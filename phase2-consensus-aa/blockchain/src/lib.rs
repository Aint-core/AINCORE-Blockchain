use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod accumulator;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: String, // Hash dari blok sebelumnya
    pub tx_hash: String,   // Hash dari daftar transaksi dalam blok ini
    pub proposer_id: String, // ID node yang mengusulkan blok ini
    pub timestamp: u64,    // Waktu pembuatan blok
    pub hash: String,      // Hash dari header ini sendiri
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<String>, // Daftar transaksi dalam blok
}

impl Block {
    pub fn new(height: u64, prev_hash: String, transactions: Vec<String>, proposer_id: String) -> Self {
        let tx_hash = calculate_tx_hash(&transactions);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let mut header = BlockHeader {
            height,
            prev_hash,
            tx_hash,
            proposer_id,
            timestamp,
            hash: String::new(), // Akan diisi setelah semua field header siap
        };

        // Hitung hash header setelah semua field diisi
        header.hash = calculate_header_hash(&header);

        Block {
            header,
            transactions,
        }
    }
}

// Fungsi bantu untuk menghitung hash dari daftar transaksi
fn calculate_tx_hash(transactions: &[String]) -> String {
    let mut hasher = Sha256::new();
    for tx in transactions {
        hasher.update(tx.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

// Fungsi bantu untuk menghitung hash dari header blok
fn calculate_header_hash(header: &BlockHeader) -> String {
    let mut hasher = Sha256::new();
    hasher.update(header.height.to_string().as_bytes());
    hasher.update(header.prev_hash.as_bytes());
    hasher.update(header.tx_hash.as_bytes());
    hasher.update(header.proposer_id.as_bytes());
    hasher.update(header.timestamp.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vertex {
    pub round: u64,
    pub author: String,
    pub parents: Vec<String>, // Hashes of parent vertices (from round r-1)
    pub payload: Vec<String>, // Transactions (or batch IDs)
    pub timestamp: u64,
    pub hash: String,
}

impl Vertex {
    pub fn new(round: u64, author: String, parents: Vec<String>, payload: Vec<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
            
        let mut v = Vertex {
            round,
            author,
            parents,
            payload,
            timestamp,
            hash: String::new(),
        };
        v.hash = v.calculate_hash();
        v
    }

    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.round.to_string().as_bytes());
        hasher.update(self.author.as_bytes());
        for p in &self.parents {
            hasher.update(p.as_bytes());
        }
        for tx in &self.payload {
            hasher.update(tx.as_bytes());
        }
        hasher.update(self.timestamp.to_string().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}