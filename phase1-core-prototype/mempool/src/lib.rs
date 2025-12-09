use std::collections::{VecDeque, HashSet};
use sha2::{Sha256, Digest};

const MAX_PENDING_TXS: usize = 5000;
const MAX_SEEN_TXS: usize = 50000;

pub struct Mempool {
    pending_txs: VecDeque<String>,
    seen_txs: HashSet<String>, // Deduplication
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
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

        // Prevent memory leak in deduplication set
        if self.seen_txs.len() >= MAX_SEEN_TXS {
            println!("🧹 Clearing seen_txs cache (size limit reached)");
            self.seen_txs.clear();
        }

        self.seen_txs.insert(tx_hash);
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
