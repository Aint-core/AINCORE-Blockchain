use crypto::hash; // Use crypto module's hash function
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
    pub height: u64,
    pub prev_hash: String, // Hash dari blok sebelumnya
    pub tx_hash: String,   // Hash dari daftar transaksi dalam blok ini
    #[serde(default)]
    pub state_root: String, // Post-execution state root. Empty only for legacy blocks.
    #[serde(default)]
    pub receipts_root: String, // Root of per-transaction receipts. Empty only for legacy blocks.
    pub proposer_id: String, // ID node yang mengusulkan blok ini
    #[serde(default)]
    pub round: u64, // Consensus Round (DAG)
    pub timestamp: u64,    // Waktu pembuatan blok
    pub hash: String,      // Hash dari header ini sendiri
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<String>, // Daftar transaksi dalam blok
}

impl Block {
    pub fn new(
        height: u64,
        round: u64,
        prev_hash: String,
        transactions: Vec<String>,
        proposer_id: String,
    ) -> Self {
        Self::new_with_roots(
            height,
            round,
            prev_hash,
            transactions,
            proposer_id,
            String::new(),
            String::new(),
        )
    }

    pub fn new_with_roots(
        height: u64,
        round: u64,
        prev_hash: String,
        transactions: Vec<String>,
        proposer_id: String,
        state_root: String,
        receipts_root: String,
    ) -> Self {
        let tx_hash = calculate_tx_hash(&transactions);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        let mut header = BlockHeader {
            height,
            prev_hash,
            tx_hash,
            state_root,
            receipts_root,
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
pub fn calculate_tx_hash(transactions: &[String]) -> String {
    let mut data = Vec::new();
    for tx in transactions {
        data.extend_from_slice(tx.as_bytes());
    }
    hex::encode(hash(&data))
}

// Fungsi bantu untuk menghitung hash dari header blok
pub fn calculate_header_hash(header: &BlockHeader) -> String {
    let mut data = Vec::new();
    data.extend_from_slice(header.height.to_string().as_bytes());
    data.extend_from_slice(header.prev_hash.as_bytes());
    data.extend_from_slice(header.tx_hash.as_bytes());
    if !header.state_root.is_empty() || !header.receipts_root.is_empty() {
        data.extend_from_slice(header.state_root.as_bytes());
        data.extend_from_slice(header.receipts_root.as_bytes());
    }
    data.extend_from_slice(header.proposer_id.as_bytes());
    data.extend_from_slice(header.round.to_string().as_bytes());
    data.extend_from_slice(header.timestamp.to_string().as_bytes());
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
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if self.signature.is_empty() {
            return false;
        }
        let sig_bytes = match hex::decode(&self.signature) {
            Ok(b) if b.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return false,
        };
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(self.hash.as_bytes(), &signature)
            .is_ok()
    }

    // (REMOVED) sign_with_bls and verify_bls_signature have been deleted.
    // These used symmetric MAC verification (re-sign and compare) which is
    // fundamentally insecure. Per-vertex signing uses Ed25519.
    // BLS aggregate signatures for consensus quorum certificates will be
    // applied externally by DagConsensus using crypto::BLSEngine.
    pub fn calculate_hash(&self) -> String {
        let mut data = Vec::new();
        data.extend_from_slice(self.round.to_string().as_bytes());
        data.extend_from_slice(self.author.as_bytes());
        for p in &self.parents {
            data.extend_from_slice(p.as_bytes());
        }
        for tx in &self.payload {
            data.extend_from_slice(tx.as_bytes());
        }
        data.extend_from_slice(self.timestamp.to_string().as_bytes());
        hex::encode(hash(&data))
    }
}
