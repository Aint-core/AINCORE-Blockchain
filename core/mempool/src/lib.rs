use std::collections::{VecDeque, HashSet};
use sha2::{Sha256, Digest};

const MAX_PENDING_TXS: usize = 5000;
const MAX_SEEN_TXS: usize = 50000;

pub struct Mempool {
    pending_txs: VecDeque<String>,
    seen_txs: HashSet<String>, // Deduplication
    seen_order: VecDeque<String>, // Bounded cache tracking
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            seen_order: VecDeque::new(),
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    pub fn add_transaction(&mut self, tx: String) {
        // === CHAIN ID VALIDATION ===
        let expected_chain = std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-TESTNET-1".to_string());
        
        // Parse the transaction to enforce Chain ID early
        use executor::Transaction;
        if let Ok(parsed_tx) = serde_json::from_str::<Transaction>(&tx) {
            if parsed_tx.chain_id != expected_chain {
                println!("❌ [Mempool] Rejected tx: Invalid Chain ID (Expected {}, Got {})", expected_chain, parsed_tx.chain_id);
                return;
            }
            
            // === EARLY SIGNATURE VERIFICATION (DoS Protection) ===
            if parsed_tx.signature.len() == 128 { // 64 bytes hex
                use ed25519_dalek::{Verifier, VerifyingKey, Signature};
                if let Ok(pk_bytes) = hex::decode(&parsed_tx.public_key) {
                    if let Ok(vk) = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0;32])) {
                        if let Ok(sig_bytes) = hex::decode(&parsed_tx.signature) {
                            if let Ok(sig) = Signature::from_slice(&sig_bytes) {
                                let message = format!("{}:{}:{}:{}", parsed_tx.chain_id, parsed_tx.sender, parsed_tx.payload, parsed_tx.sequence_number);
                                if vk.verify(message.as_bytes(), &sig).is_err() {
                                    println!("❌ [Mempool] Rejected tx: Invalid Signature Verification");
                                    return;
                                }
                            } else { return; }
                        } else { return; }
                    } else { return; }
                } else { return; }
            } else if parsed_tx.signature.len() == 9254 {
                // Pass PQC validation down to Executor for performance
            } else {
                println!("❌ [Mempool] Rejected tx: Unknown Signature Scheme size");
                return;
            }
        } else {
             println!("❌ [Mempool] Rejected tx: Invalid JSON format");
             return;
        }

        // Calculate Hash for Deduplication
        let mut hasher = Sha256::new();
        hasher.update(tx.as_bytes());
        let tx_hash = hex::encode(hasher.finalize());

        if self.seen_txs.contains(&tx_hash) {
            println!("⚠️ Ignored duplicate transaction: {}", tx_hash);
            return;
        }

        // 1. Check Transaction Size to prevent RAM DoS
        if tx.len() > 100 * 1024 { // 100KB Limit
             println!("⚠️ Transaction too large ({} bytes). limit 100KB.", tx.len());
             return;
        }

        if self.pending_txs.len() >= MAX_PENDING_TXS {
             println!("⚠️ Mempool Full ({}/{}) - Rejecting transaction {}", self.pending_txs.len(), MAX_PENDING_TXS, tx_hash);
             return;
        }

        // Bounded LRU-style eviction
        if self.seen_txs.len() >= MAX_SEEN_TXS {
            if let Some(old_tx) = self.seen_order.pop_front() {
                self.seen_txs.remove(&old_tx);
            }
        }

        self.seen_txs.insert(tx_hash.clone());
        self.seen_order.push_back(tx_hash.clone());
        self.pending_txs.push_back(tx.clone());
        
        println!("📥 Added transaction to mempool: {}", self.pending_txs.len());
    }

    pub fn get_pending_transactions(&mut self, limit: usize) -> Vec<String> {
        let mut transactions = Vec::new();
        let mut count = 0;
        while count < limit && !self.pending_txs.is_empty() {
            if let Some(tx) = self.pending_txs.pop_front() {
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
}

// Fungsi main bisa dihapus jika crate ini adalah library
// fn main() {
//     println!("Hello, world!");
// }
#[cfg(test)]
mod tests;
