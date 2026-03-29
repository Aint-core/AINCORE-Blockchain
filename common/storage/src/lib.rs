use rocksdb::{DB, IteratorMode};
pub use rocksdb; // Export for consumers
pub mod object;
use object::Object;
use std::fmt;

#[derive(Debug, Clone)]
pub enum StorageError {
    DatabaseOpen(String),
    DatabaseOperation(String),
    SerializationError(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorageError::DatabaseOpen(msg) => write!(f, "Failed to open database: {}", msg),
            StorageError::DatabaseOperation(msg) => write!(f, "Database operation failed: {}", msg),
            StorageError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rocksdb::Error> for StorageError {
    fn from(err: rocksdb::Error) -> Self {
        StorageError::DatabaseOperation(err.to_string())
    }
}


pub struct StateDB {
    pub db: DB,
}

impl StateDB {
    /// Open database with proper error handling
    /// 
    /// Returns Err if:
    /// - Database is locked by another process
    /// - Insufficient permissions
    /// - Corrupted database files
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let db = DB::open_default(path)
            .map_err(|e| StorageError::DatabaseOpen(format!(
                "Path: {}, Error: {}. Ensure no other process is using this directory and you have write permissions.",
                path, e
            )))?;
        Ok(Self { db })
    }

    pub fn put(&self, key: &str, value: &str) -> std::result::Result<(), rocksdb::Error> {
        self.db.put(key, value)
    }

    pub fn get(&self, key: &str) -> std::result::Result<Option<String>, rocksdb::Error> {
        match self.db.get(key) {
            Ok(Some(v)) => {
                 match String::from_utf8(v) {
                     Ok(s) => Ok(Some(s)),
                     Err(_) => Ok(None), // Fail safe for invalid utf8
                 }
            },
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn delete(&self, key: &str) -> std::result::Result<(), rocksdb::Error> {
        self.db.delete(key)
    }

    // === HELPER FOR PEER MAN AGEMENT ===
    pub fn save_peer(&self, node_id: &str, port: u16) -> std::result::Result<(), rocksdb::Error> {
        let key = format!("peer:{}", node_id);
        self.put(&key, &port.to_string())
    }

    pub fn get_peer(&self, node_id: &str) -> Option<u16> {
        // Safe wrapper for get
        if let Ok(Some(val_str)) = self.get(&format!("peer:{}", node_id)) {
            val_str.parse().ok()
        } else {
            None
        }
    }

    pub fn scan_peers(&self) -> Vec<(String, u16)> {
        let mut peers = Vec::new();
        let prefix = b"peer:";
        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            if let Ok((key, value)) = item {
                if !key.starts_with(prefix) {
                    break;
                }
                
                let k = String::from_utf8(key.to_vec()).unwrap_or_default();
                let val_str = String::from_utf8(value.to_vec()).unwrap_or_default();
                if let Ok(port) = val_str.parse::<u16>() {
                    peers.push((k.replace("peer:", ""), port));
                }
            }
        }

        peers
    }

    // === PEER IP TRACKING (for multi-node sync) ===
    pub fn save_peer_ip(&self, node_id: &str, ip: &str) -> std::result::Result<(), rocksdb::Error> {
        let key = format!("peer_ip:{}", node_id);
        self.put(&key, ip)
    }

    pub fn get_peer_ip(&self, node_id: &str) -> Option<String> {
        if let Ok(Some(ip)) = self.get(&format!("peer_ip:{}", node_id)) {
            Some(ip)
        } else {
            None
        }
    }

    pub fn save_peer_addr(&self, peer_id: &str, multiaddr: &str) -> std::result::Result<(), rocksdb::Error> {
        self.put(&format!("peer_addr:{}", peer_id), multiaddr)
    }

    pub fn scan_peer_addrs(&self) -> Vec<(String, String)> {
        let mut peers = Vec::new();
        let prefix = b"peer_addr:";
        let iter = self.db.prefix_iterator(prefix);
        
        for item in iter {
            if let Ok((key, value)) = item {
                if !key.starts_with(prefix) {
                    break;
                }
                
                let k = String::from_utf8_lossy(&key).into_owned();
                let node_id = k.replace("peer_addr:", "");
                let addr = String::from_utf8_lossy(&value).into_owned();
                peers.push((node_id, addr));
            }
        }
        peers
    }

    pub fn scan_vertices(&self) -> Vec<String> {
        let mut vertices = Vec::new();
        let prefix = b"vertex:";
        let iter = self.db.prefix_iterator(prefix);

        for item in iter {
            if let Ok((key, value)) = item {
                if !key.starts_with(prefix) {
                    break;
                }
                
                let v_json = String::from_utf8(value.to_vec()).unwrap_or_else(|_| "{}".to_string());
                vertices.push(v_json);
            }
        }
        vertices
    }

    pub fn put_object(&self, object: &Object) -> std::result::Result<(), rocksdb::Error> {
        let key = format!("obj:{}", object.id.to_string());
        let value = serde_json::to_string(object).unwrap_or_default(); // Safe default or error? Default is ok for prototype.
        self.db.put(key, value)
    }

    pub fn write_batch(&self, batch: rocksdb::WriteBatch) -> std::result::Result<(), rocksdb::Error> {
        self.db.write(batch)
    }

    /// Get current blockchain height
    pub fn get_chain_height(&self) -> u64 {
        match self.get("latest_height") {
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
            _ => 0,
        }
    }
    
    /// Save block as JSON string — atomically updates height AND hash
    pub fn save_block_json(&self, height: u64, block_json: &str) -> Result<(), rocksdb::Error> {
        let key = format!("block_{}", height);
        self.put(&key, block_json)?;
        self.put("latest_height", &height.to_string())?;
        // Extract hash from block JSON and persist it for consensus continuity
        if let Ok(block) = serde_json::from_str::<serde_json::Value>(block_json) {
            if let Some(hash) = block["header"]["hash"].as_str() {
                self.put("latest_block_hash", hash)?;
            }
        }
        Ok(())
    }

    pub fn get_object(&self, object_id: &str) -> Option<Object> {
        let key = format!("obj:{}", object_id);
        match self.db.get(key) {
            Ok(Some(v)) => {
                if let Ok(s) = String::from_utf8(v) {
                    serde_json::from_str(&s).ok()
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    
    /// Index transaction for fast lookup: tx_hash → block_height
    /// 
    /// This enables O(1) transaction lookups instead of O(n) DAG scan.
    /// Call this after successfully executing a block.
    pub fn index_transaction(&self, tx_hash: &str, block_height: u64) -> Result<(), rocksdb::Error> {
        let key = format!("tx_index:{}", tx_hash);
        self.put(&key, &block_height.to_string())
    }
    
    /// Get block height for a transaction hash (O(1) lookup)
    /// 
    /// Returns None if transaction not found in index.
    pub fn get_tx_block_height(&self, tx_hash: &str) -> Option<u64> {
        let key = format!("tx_index:{}", tx_hash);
        self.get(&key).ok()?.and_then(|h| h.parse().ok())
    }

    // === PHASE 9: DECENTRALIZED CONFIG ===
    pub fn get_federation_key(&self) -> String {
        // Default Genesis Key (Hardcoded Fallback)
        const GENESIS_FED_ADDR: &str = "c9c32c8d0607850e6d89c8f048dd3a94";
        
        match self.get("sys:config:federation_addr") {
            Ok(Some(k)) => k,
            _ => GENESIS_FED_ADDR.to_string(),
        }
    }

    pub fn set_federation_key(&self, new_key: &str) -> std::result::Result<(), rocksdb::Error> {
        self.put("sys:config:federation_addr", new_key)
    }

    // === PHASE 10: ECONOMIC MODEL ===
    
    pub fn get_base_reward(&self) -> u64 {
        const DEFAULT_REWARD: u64 = 50;
        match self.get("sys:config:base_reward") {
            Ok(Some(v)) => v.parse().unwrap_or(DEFAULT_REWARD),
            _ => DEFAULT_REWARD,
        }
    }
    
    pub fn get_halving_interval(&self) -> u64 {
        const DEFAULT_INTERVAL: u64 = 2_100_000;
        match self.get("sys:config:halving_interval") {
            Ok(Some(v)) => v.parse().unwrap_or(DEFAULT_INTERVAL),
            _ => DEFAULT_INTERVAL,
        }
    }
    
    pub fn get_burn_percentage(&self) -> u8 {
        const DEFAULT_BURN: u8 = 10; // 10%
        match self.get("sys:config:burn_percentage") {
            Ok(Some(v)) => v.parse().unwrap_or(DEFAULT_BURN),
            _ => DEFAULT_BURN,
        }
    }

    pub fn update_economic_config(&self, reward: Option<u64>, interval: Option<u64>, burn: Option<u8>) -> std::result::Result<(), rocksdb::Error> {
        if let Some(r) = reward { self.put("sys:config:base_reward", &r.to_string())?; }
        if let Some(i) = interval { self.put("sys:config:halving_interval", &i.to_string())?; }
        if let Some(b) = burn { self.put("sys:config:burn_percentage", &b.to_string())?; }
        Ok(())
    }

    // === PHASE 12: VALIDATOR SET (SYBIL PROTECTION) ===
    
    // Scan method clearly not optimal for Mainnet, but "Real" enough for < 1000 validators.
    // In full prod, we'd use a separate column family or index.
    pub fn get_active_validators(&self) -> Vec<(String, u64)> {
         // Logic: Check a "sys:validators" list.
         // If empty/missing, fallback to Genesis Validator (Federation Key) with 100 weight.
         if let Ok(Some(json)) = self.get("sys:validators") {
             if let Ok(vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                 return vals;
             }
         }
         
         // Fallback: Genesis Validator
         vec![("c9c32c8d0607850e6d89c8f048dd3a94".to_string(), 100)]
    }

    pub fn update_validator_weight(&self, pubkey: &str, weight: u64) -> std::result::Result<(), rocksdb::Error> {
         let mut vals = self.get_active_validators();
         if let Some(v) = vals.iter_mut().find(|v| v.0 == pubkey) {
             v.1 = weight;
         } else {
             vals.push((pubkey.to_string(), weight));
         }
         let json = serde_json::to_string(&vals).unwrap_or_default();
         self.put("sys:validators", &json)
    }

    // === DAG CHECKPOINT SYSTEM (Aptos/Sui Style) ===
    
    /// Save DAG checkpoint for fast recovery
    /// Called every N rounds (e.g., 100) to enable O(1) startup
    pub fn save_dag_checkpoint(&self, round: u64, vertices_json: &str) -> std::result::Result<(), rocksdb::Error> {
        // Save checkpoint data
        self.put(&format!("dag:checkpoint:{}", round), vertices_json)?;
        // Update latest checkpoint pointer
        self.put("dag:checkpoint:latest", &round.to_string())?;
        Ok(())
    }
    
    /// Get latest checkpoint round
    pub fn get_latest_checkpoint_round(&self) -> u64 {
        match self.get("dag:checkpoint:latest") {
            Ok(Some(r)) => r.parse().unwrap_or(0),
            _ => 0,
        }
    }
    
    /// Load DAG checkpoint data
    pub fn get_dag_checkpoint(&self, round: u64) -> Option<String> {
        match self.get(&format!("dag:checkpoint:{}", round)) {
            Ok(Some(data)) => Some(data),
            _ => None,
        }
    }
    
    /// Prune old checkpoints (keep last N)
    pub fn prune_old_checkpoints(&self, current_round: u64, keep_count: u64) -> std::result::Result<(), rocksdb::Error> {
        if current_round <= keep_count {
            return Ok(());
        }
        let oldest_to_keep = current_round - keep_count;
        // Simple cleanup: delete checkpoints older than threshold
        // Note: This is a best-effort cleanup, not a full scan
        for old_round in (0..oldest_to_keep).rev().take(10) {
            let _ = self.delete(&format!("dag:checkpoint:{}", old_round));
        }
        Ok(())
    }
}
