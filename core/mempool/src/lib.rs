use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};

const MAX_PENDING_TXS: usize = 5000;
const MAX_SEEN_TXS: usize = 50000;
const MIN_GAS_PRICE: u128 = 1;

pub struct Mempool {
    pending_txs: VecDeque<String>,
    seen_txs: HashSet<String>,       // Deduplication
    seen_order: VecDeque<String>,    // Bounded cache tracking
    pending_nonces: HashSet<String>, // sender:sequence_number in the pending queue
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            seen_order: VecDeque::new(),
            pending_nonces: HashSet::new(),
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn add_transaction(&mut self, tx: String) -> Result<String, String> {
        // === M-04 FIX: SIZE GUARD FIRST (cheapest reject path) ===
        //
        // Hard size cap BEFORE we touch serde_json, hex decode, BCS, or any
        // signature/PQC verification. Previously the 100KB check sat after
        // Ed25519 verify (and after BCS parse), meaning an attacker could
        // burn server CPU on serde + crypto for arbitrarily large payloads
        // before being rejected. Moving it to the very first line bounds
        // the worst-case wasted work to one `.len()` call.
        const TX_BYTE_LIMIT: usize = 100 * 1024; // 100KB
        if tx.len() > TX_BYTE_LIMIT {
            return Err(format!(
                "Transaction too large ({} bytes). limit {}KB.",
                tx.len(),
                TX_BYTE_LIMIT / 1024
            ));
        }

        // === CHAIN ID VALIDATION ===
        // L5 FIX: Match mainnet genesis default to prevent unexpected rejections
        let expected_chain =
            std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());

        // Parse the transaction to enforce Chain ID early
        use executor::Transaction;
        let parsed_tx = serde_json::from_str::<Transaction>(&tx)
            .map_err(|_| "Invalid JSON format".to_string())?;
        if parsed_tx.chain_id != expected_chain {
            return Err(format!(
                "Invalid Chain ID (Expected {}, Got {})",
                expected_chain, parsed_tx.chain_id
            ));
        }

        if parsed_tx.gas_price < MIN_GAS_PRICE {
            return Err(format!(
                "Gas price too low: {} < minimum {}",
                parsed_tx.gas_price, MIN_GAS_PRICE
            ));
        }

        if parsed_tx.gas_limit == 0 {
            return Err("Gas limit must be greater than 0".to_string());
        }

        // === H-04 FIX: ZKP PROOF FAIL-CLOSED ===
        //
        // The Transaction struct carries an optional `zkp_proof` field that
        // the executor used to log-but-not-verify. Accepting transactions
        // tagged with a "ZKP proof" while doing nothing with it is worse
        // than rejecting them: it gives users a false sense of additional
        // assurance and makes future enablement risky (any naïve client
        // pinning to "ZKP enabled" semantics would have to be re-signed
        // once the verifier finally runs).
        //
        // Until the STARK verifier is wired end-to-end (proof decoding,
        // public-input binding to the tx hash, and verification result
        // gating execution), refuse any submission that carries a non-empty
        // zkp_proof. This is the fail-closed-sementara pattern: keep the
        // infra and tests around, just close the door at the entry point.
        if let Some(ref proof_hex) = parsed_tx.zkp_proof {
            if !proof_hex.is_empty() {
                return Err(
                    "ZKP proofs are not yet verified by the executor and are \
                     intentionally fail-closed at the mempool until the STARK \
                     verifier is wired. Resubmit with zkp_proof = null."
                        .to_string(),
                );
            }
        }

        let payload_bytes = hex::decode(parsed_tx.payload.trim_start_matches("0x"))
            .map_err(|_| "Invalid payload hex: expected BCS TransactionPayload".to_string())?;
        match bcs::from_bytes::<vm_move::TransactionPayload>(&payload_bytes) {
            Ok(vm_move::TransactionPayload::EntryFunction(_))
            | Ok(vm_move::TransactionPayload::PublishModule(_)) => {}
            Ok(vm_move::TransactionPayload::Script(_)) => {
                return Err("Raw script payloads are disabled".to_string());
            }
            Err(e) => {
                return Err(format!("Invalid BCS TransactionPayload: {}", e));
            }
        }

        // === H-01 FIX: PQC FAIL-CLOSED AT MEMPOOL ===
        //
        // The Dilithium5 path is verified at the VM layer (vm_move). That
        // verification is correct on its own, but the mempool used to
        // silently accept any 9254-char hex string as "PQC signature" and
        // forward it down without:
        //   - checking sender == derive_address(pubkey)
        //   - actually verifying the signature
        //
        // That turned the mempool into a free DoS surface: an attacker
        // could flood the queue with 9254-char garbage that only gets
        // rejected during block execution, after consuming mempool slots
        // and pulling executor cycles.
        //
        // Until the full Dilithium5 verification is wired at the mempool
        // entry (matching the VM-layer logic and storing the canonical
        // sender↔pqc_pubkey binding), refuse PQC submissions at this
        // gate. Existing PQC infra (CLI keygen, VM-level verification,
        // vm_move test_pqc_dilithium_detection) is intentionally NOT
        // disabled — they exercise the VM path directly without going
        // through the mempool.
        //
        // When PQC is ready for mempool acceptance, replace this branch
        // with a real Dilithium5 verification mirroring vm_move's logic.
        const PQC_DILITHIUM5_HEX_LEN: usize = 9254;
        if parsed_tx.signature.len() == PQC_DILITHIUM5_HEX_LEN {
            return Err(
                "PQC (Dilithium5) signatures are not yet accepted at the \
                 mempool layer. This path is intentionally fail-closed until \
                 full Dilithium5 verification is wired at submission time. \
                 Use Ed25519 (signature.len() == 128 hex chars) for now."
                    .to_string(),
            );
        }

        // === EARLY SIGNATURE VERIFICATION (DoS Protection) ===
        if parsed_tx.signature.len() == 128 {
            // 64 bytes hex
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            if let Ok(pk_bytes) = hex::decode(&parsed_tx.public_key) {
                match crypto::derive_address(&pk_bytes) {
                    Ok(expected_sender) if expected_sender == parsed_tx.sender => {}
                    Ok(expected_sender) => {
                        return Err(format!(
                            "Sender mismatch (expected {}, got {})",
                            expected_sender, parsed_tx.sender
                        ));
                    }
                    Err(e) => {
                        return Err(format!("Address derivation failed: {}", e));
                    }
                }
                if let Ok(vk) =
                    VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0; 32]))
                {
                    if let Ok(sig_bytes) = hex::decode(&parsed_tx.signature) {
                        if let Ok(sig) = Signature::from_slice(&sig_bytes) {
                            let message = format!(
                                "{}:{}:{}:{}",
                                parsed_tx.chain_id,
                                parsed_tx.sender,
                                parsed_tx.payload,
                                parsed_tx.sequence_number
                            );
                            if vk.verify(message.as_bytes(), &sig).is_err() {
                                return Err("Invalid Signature Verification".to_string());
                            }
                        } else {
                            return Err("Invalid signature bytes".to_string());
                        }
                    } else {
                        return Err("Invalid signature hex".to_string());
                    }
                } else {
                    return Err("Invalid public key".to_string());
                }
            } else {
                return Err("Invalid public key hex".to_string());
            }
        } else {
            // PQC (9254-char Dilithium5) is rejected earlier by the H-01
            // fail-closed gate. Any other length is unsupported.
            return Err("Unknown Signature Scheme size".to_string());
        }

        // Calculate Hash for Deduplication
        let mut hasher = Sha256::new();
        hasher.update(tx.as_bytes());
        let tx_hash = hex::encode(hasher.finalize());

        if self.seen_txs.contains(&tx_hash) {
            return Err(format!("Duplicate transaction: {}", tx_hash));
        }

        // (M-04: size guard was moved to the top of add_transaction so it
        // runs before any expensive parsing or signature verification.)

        if self.pending_txs.len() >= MAX_PENDING_TXS {
            return Err(format!(
                "Mempool full ({}/{})",
                self.pending_txs.len(),
                MAX_PENDING_TXS
            ));
        }

        let nonce_key = format!("{}:{}", parsed_tx.sender, parsed_tx.sequence_number);
        if self.pending_nonces.contains(&nonce_key) {
            return Err(format!(
                "Duplicate pending nonce for sender {} sequence {}",
                parsed_tx.sender, parsed_tx.sequence_number
            ));
        }

        // Bounded LRU-style eviction
        if self.seen_txs.len() >= MAX_SEEN_TXS {
            if let Some(old_tx) = self.seen_order.pop_front() {
                self.seen_txs.remove(&old_tx);
            }
        }

        self.seen_txs.insert(tx_hash.clone());
        self.seen_order.push_back(tx_hash.clone());
        self.pending_nonces.insert(nonce_key);
        self.pending_txs.push_back(tx.clone());

        println!(
            "📥 Added transaction to mempool: {}",
            self.pending_txs.len()
        );
        Ok(tx_hash)
    }

    pub fn get_pending_transactions(&mut self, limit: usize) -> Vec<String> {
        let mut transactions = Vec::new();
        let mut count = 0;
        while count < limit && !self.pending_txs.is_empty() {
            if let Some(tx) = self.pending_txs.pop_front() {
                self.remove_pending_nonce(&tx);
                transactions.push(tx);
                count += 1;
            }
        }
        transactions
    }

    pub fn is_empty(&self) -> bool {
        self.pending_txs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending_txs.len()
    }

    pub fn get_all_pending(&self) -> &VecDeque<String> {
        &self.pending_txs
    }

    fn remove_pending_nonce(&mut self, tx: &str) {
        if let Ok(parsed_tx) = serde_json::from_str::<executor::Transaction>(tx) {
            self.pending_nonces.remove(&format!(
                "{}:{}",
                parsed_tx.sender, parsed_tx.sequence_number
            ));
        }
    }
}

// Fungsi main bisa dihapus jika crate ini adalah library
// fn main() {
//     println!("Hello, world!");
// }
#[cfg(test)]
mod tests;
