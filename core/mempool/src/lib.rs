use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use storage::StateDB;

const MAX_PENDING_TXS: usize = 5000;
const MAX_SEEN_TXS: usize = 50000;
const MIN_GAS_PRICE: u128 = 1;

/// Dilithium5 signature length as raw bytes (NIST round-3 spec).
const PQC_DILITHIUM5_SIG_BYTES: usize = 4627;
/// Dilithium5 signature length as hex characters.
const PQC_DILITHIUM5_HEX_LEN: usize = PQC_DILITHIUM5_SIG_BYTES * 2;
/// Dilithium5 public key length as raw bytes (NIST round-3 spec).
const PQC_DILITHIUM5_PUBKEY_BYTES: usize = 2592;

pub struct Mempool {
    pending_txs: VecDeque<String>,
    seen_txs: HashSet<String>,       // Deduplication
    seen_order: VecDeque<String>,    // Bounded cache tracking
    pending_nonces: HashSet<String>, // sender:sequence_number in the pending queue
    /// Optional storage handle. When `Some`, `add_transaction` performs
    /// full Dilithium5 (PQC) verification by looking up the canonical
    /// `pqc_pubkey_{sender}` binding. When `None`, PQC submissions are
    /// fail-closed at the mempool gate (Phase 1 H-01 behaviour).
    /// Production callers should always pass storage via
    /// [`Mempool::with_storage`].
    storage: Option<Arc<StateDB>>,
}

impl Mempool {
    /// Construct a mempool without storage. PQC submissions will be
    /// fail-closed at the gate. Useful for unit tests that exercise
    /// Ed25519 paths only.
    pub fn new() -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            seen_order: VecDeque::new(),
            pending_nonces: HashSet::new(),
            storage: None,
        }
    }

    /// Construct a mempool with storage access. PQC submissions go
    /// through full Dilithium5 verification against the canonical
    /// `pqc_pubkey_{sender}` binding before being queued.
    ///
    /// Phase 2.1 (H-01): this is the constructor production node code
    /// should use — wiring real PQC verification at the mempool entry
    /// instead of leaving it as a fail-closed gate.
    pub fn with_storage(storage: Arc<StateDB>) -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            seen_order: VecDeque::new(),
            pending_nonces: HashSet::new(),
            storage: Some(storage),
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

        // === H-04 PROMOTED (Phase 2.2): WIRE THE STARK VERIFIER ===
        //
        // Phase 1 fail-closed the zkp_proof field. Phase 2.2 routes any
        // attached proof through crypto::zkp::verify_tx_attached_proof,
        // which:
        //   1. hex-decodes the envelope,
        //   2. parses it as STARKProofData (rejects structural garbage),
        //   3. asserts the proof's public inputs commit to
        //      SHA-256("{chain_id}:{sender}:{payload}:{seq}") so a
        //      detached-and-replayed proof cannot be reused on a
        //      different transaction,
        //   4. invokes STARKVerifier::verify on the dispatched proof.
        //
        // The underlying STARKVerifier is a Phase-2 placeholder today,
        // so in practice no valid proof can be constructed yet. But the
        // wiring is real: the moment a real AIR is plumbed in, valid
        // proofs flow through unchanged and invalid ones are rejected
        // with specific diagnostic categories instead of the blanket
        // "fail-closed gate" message.
        if let Some(ref proof_hex) = parsed_tx.zkp_proof {
            if !proof_hex.is_empty() {
                let canonical_msg = format!(
                    "{}:{}:{}:{}",
                    parsed_tx.chain_id,
                    parsed_tx.sender,
                    parsed_tx.payload,
                    parsed_tx.sequence_number
                );
                if let Err(e) = crypto::zkp::verify_tx_attached_proof(
                    proof_hex,
                    canonical_msg.as_bytes(),
                ) {
                    return Err(format!("ZKP proof rejected: {}", e));
                }
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

        // === H-01 PROMOTED (Phase 2.1): REAL DILITHIUM5 VERIFICATION ===
        //
        // PQC submissions used to be silently accepted (DoS surface) or
        // fail-closed (Phase 1). Phase 2.1 wires full Dilithium5
        // verification at the mempool gate by mirroring the VM-layer
        // verify_native_aa_signature path:
        //
        //   1. Look up the canonical pqc_pubkey_{sender} binding in
        //      storage (registered out-of-band during onboarding).
        //   2. Assert sender == derive_address(pqc_pubkey) — catches
        //      pubkey-spoofing-as-sender, an authentication tightening
        //      the VM-layer code does not currently perform.
        //   3. Decode the 9254-hex (4627-byte) detached signature.
        //   4. Verify the Dilithium5 signature against the canonical
        //      submission message format.
        //
        // If storage is not available to this mempool instance (Mempool
        // constructed via ::new() instead of ::with_storage(...) — only
        // used in unit tests that don't exercise PQC), fall back to the
        // Phase 1 fail-closed behaviour so an unconfigured mempool
        // doesn't accidentally accept unverified PQC.
        if parsed_tx.signature.len() == PQC_DILITHIUM5_HEX_LEN {
            let storage = match &self.storage {
                Some(s) => s,
                None => {
                    return Err(
                        "PQC (Dilithium5) signatures require a storage-backed \
                         mempool. This instance was constructed without \
                         storage; submit via the node API instead."
                            .to_string(),
                    );
                }
            };

            // 1. Look up canonical PQC public key.
            let pk_key = format!("pqc_pubkey_{}", parsed_tx.sender);
            let pk_hex = match storage.get(&pk_key) {
                Ok(Some(s)) => s,
                _ => {
                    return Err(format!(
                        "PQC public key not registered for sender {}. \
                         Register pqc_pubkey_{{sender}} before submitting \
                         Dilithium5-signed transactions.",
                        parsed_tx.sender
                    ));
                }
            };
            let pk_bytes = match hex::decode(&pk_hex) {
                Ok(b) => b,
                Err(e) => {
                    return Err(format!(
                        "Registered PQC pubkey is not valid hex: {}",
                        e
                    ));
                }
            };
            if pk_bytes.len() != PQC_DILITHIUM5_PUBKEY_BYTES {
                return Err(format!(
                    "Registered PQC pubkey has wrong size: {} (expected {})",
                    pk_bytes.len(),
                    PQC_DILITHIUM5_PUBKEY_BYTES
                ));
            }

            // 2. Sender↔pubkey binding via canonical address derivation
            // (matches `aincore-cli pqc-keygen` and the Ed25519 path:
            // hex(SHA-256(pubkey)[..16])).
            let derived = crypto::derive_address(&pk_bytes)
                .map_err(|e| format!("PQC address derivation failed: {}", e))?;
            if derived != parsed_tx.sender {
                return Err(format!(
                    "PQC sender mismatch: registered pubkey derives address \
                     {}, but transaction claims sender {}. Pubkey↔sender \
                     binding has been tampered with.",
                    derived, parsed_tx.sender
                ));
            }

            // 3. Decode detached signature.
            let sig_bytes = match hex::decode(&parsed_tx.signature) {
                Ok(s) => s,
                Err(e) => {
                    return Err(format!("PQC signature is not valid hex: {}", e));
                }
            };
            if sig_bytes.len() != PQC_DILITHIUM5_SIG_BYTES {
                return Err(format!(
                    "PQC signature has wrong size: {} (expected {})",
                    sig_bytes.len(),
                    PQC_DILITHIUM5_SIG_BYTES
                ));
            }

            // 4. Verify Dilithium5.
            use pqcrypto_dilithium::dilithium5;
            use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

            let pk = dilithium5::PublicKey::from_bytes(&pk_bytes)
                .map_err(|_| "Invalid Dilithium5 public key format".to_string())?;
            let sig = dilithium5::DetachedSignature::from_bytes(&sig_bytes)
                .map_err(|_| "Invalid Dilithium5 signature format".to_string())?;

            // Canonical submission message — must match what wallets sign.
            // We use the same shape as the Ed25519 path so wallet code can
            // share message construction between schemes.
            let message = format!(
                "{}:{}:{}:{}",
                parsed_tx.chain_id,
                parsed_tx.sender,
                parsed_tx.payload,
                parsed_tx.sequence_number
            );
            if dilithium5::verify_detached_signature(&sig, message.as_bytes(), &pk).is_err() {
                return Err("Invalid Dilithium5 signature verification".to_string());
            }

            // Verification passed — fall through to the rest of the
            // pipeline (hash dedupe, size, mempool limits, nonce dedupe)
            // by jumping past the Ed25519 branch below.
        } else if parsed_tx.signature.len() == 128 {
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
