use serde::{Deserialize, Serialize};
use crypto::hash; // Use crypto module's hash function
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: String, // Hash dari blok sebelumnya
    pub tx_hash: String,   // Hash dari daftar transaksi dalam blok ini
    pub proposer_id: String, // ID node yang mengusulkan blok ini
    #[serde(default)]
    pub round: u64,          // Consensus Round (DAG)
    pub timestamp: u64,    // Waktu pembuatan blok
    pub hash: String,      // Hash dari header ini sendiri
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<String>, // Daftar transaksi dalam blok
}

impl Block {
    pub fn new(height: u64, round: u64, prev_hash: String, transactions: Vec<String>, proposer_id: String) -> Self {
        let tx_hash = calculate_tx_hash(&transactions);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        let mut header = BlockHeader {
            height,
            prev_hash,
            tx_hash,
            proposer_id,
            round,
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
    let mut data = Vec::new();
    for tx in transactions {
        data.extend_from_slice(tx.as_bytes());
    }
    hex::encode(hash(&data))
}

// Fungsi bantu untuk menghitung hash dari header blok
fn calculate_header_hash(header: &BlockHeader) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(&header.height.to_string().as_bytes());
    data.extend_from_slice(header.prev_hash.as_bytes());
    data.extend_from_slice(header.tx_hash.as_bytes());
    data.extend_from_slice(header.proposer_id.as_bytes());
    data.extend_from_slice(&header.round.to_string().as_bytes());
    data.extend_from_slice(&header.timestamp.to_string().as_bytes());
    hex::encode(hash(&data))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vertex {
    pub round: u64,
    pub author: String,
    pub parents: Vec<String>, // Hashes of parent vertices (from round r-1)
    pub payload: Vec<String>, // Transactions (or batch IDs)
    pub timestamp: u64,
    pub hash: String,
    /// BLS signature from the author (48 bytes hex encoded)
    #[serde(default)]
    pub signature: String,
    /// Aggregated BLS signatures from validators (optional, for committed vertices)
    #[serde(default)]
    pub aggregated_signature: Option<String>,
}

impl Vertex {
    pub fn new(round: u64, author: String, parents: Vec<String>, payload: Vec<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();
            
        let mut v = Vertex {
            round,
            author,
            parents,
            payload,
            timestamp,
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
        };
        v.hash = v.calculate_hash();
        v
    }
    
    /// Sign the vertex hash with Ed25519 and set the signature field
    pub fn sign_with_ed25519(&mut self, secret_key: &ed25519_dalek::SigningKey) {
        use ed25519_dalek::Signer;
        let sig = secret_key.sign(self.hash.as_bytes());
        self.signature = hex::encode(sig.to_bytes());
    }
    
    /// Verify the Ed25519 signature
    pub fn verify_ed25519_signature(&self, public_key_hex: &str) -> bool {
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};
        if self.signature.is_empty() {
            return false;
        }
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) if b.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&b);
                arr
            },
            _ => return false,
        };
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            },
            _ => return false,
        };
        
        let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);
        
        verifying_key.verify(self.hash.as_bytes(), &signature).is_ok()
    }

    /// (DEPRECATED) Sign the vertex hash with BLS and set the signature field
    pub fn sign_with_bls(&mut self, secret_key: &[u8; 32]) {
        use crypto::bls::BLSEngine;
        let bls = BLSEngine::new(b"AINCORE_CONSENSUS_V1");
        let sig = bls.sign(self.hash.as_bytes(), secret_key);
        self.signature = hex::encode(&sig);
    }
    
    /// (DEPRECATED) Verify the BLS signature
    pub fn verify_bls_signature(&self, public_key: &[u8; 32]) -> bool {
        use crypto::bls::BLSEngine;
        if self.signature.is_empty() {
            return false;
        }
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let bls = BLSEngine::new(b"AINCORE_CONSENSUS_V1");
        let expected = bls.sign(self.hash.as_bytes(), public_key);
        sig_bytes == expected
    }

    pub fn calculate_hash(&self) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(&self.round.to_string().as_bytes());
        data.extend_from_slice(self.author.as_bytes());
        for p in &self.parents {
            data.extend_from_slice(p.as_bytes());
        }
        for tx in &self.payload {
            data.extend_from_slice(tx.as_bytes());
        }
        data.extend_from_slice(&self.timestamp.to_string().as_bytes());
        hex::encode(hash(&data))
    }
}