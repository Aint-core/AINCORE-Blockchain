use rocksdb::{DB, IteratorMode};
pub use rocksdb; // Export for consumers
pub mod object;
use object::Object;


pub struct StateDB {
    pub db: DB,
}

impl StateDB {
    pub fn open(path: &str) -> Self {
        let db = DB::open_default(path).expect("Gagal membuka database RocksDB. Pastikan tidak ada proses lain yang menggunakan direktori ini dan Anda memiliki izin akses.");
        Self { db }
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
        let iter = self.db.iterator(IteratorMode::Start);

        for item in iter {
            if let Ok((key, value)) = item {
                let k = String::from_utf8(key.to_vec()).unwrap_or_default();
                
                if k.starts_with("peer:") {
                    let val_str = String::from_utf8(value.to_vec()).unwrap_or_default();
                    if let Ok(port) = val_str.parse::< u16>() {
                        peers.push((k.replace("peer:", ""), port));
                    }
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
        // Iterator is safe, but we should wrap it eventually. 
        // For now, scan is infallible in rocksdb api wrapper usually, iterator just ends.
        let mut peers = Vec::new();
        let prefix = "peer_addr:";
        let iter = self.db.prefix_iterator(prefix);
        
        for item in iter {
            if let Ok((key, value)) = item {
                let k = String::from_utf8_lossy(&key).to_string();
                if k.starts_with(prefix) {
                     let node_id = k.replace(prefix, "");
                    let addr = String::from_utf8_lossy(&value).to_string();
                    peers.push((node_id, addr));
                }
            }
        }
        peers
    }

    pub fn scan_vertices(&self) -> Vec<String> {
        let mut vertices = Vec::new();
        let iter = self.db.iterator(IteratorMode::Start);

        for item in iter {
            if let Ok((key, value)) = item {
                let k = String::from_utf8(key.to_vec()).unwrap_or_else(|_| "INVALID_UTF8".to_string());
                if k.starts_with("vertex:") {
                    let v_json = String::from_utf8(value.to_vec()).unwrap_or_else(|_| "{}".to_string());
                    vertices.push(v_json);
                }
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
    
    /// Save block as JSON string
    pub fn save_block_json(&self, height: u64, block_json: &str) -> Result<(), rocksdb::Error> {
        let key = format!("block_{}", height);
        self.put(&key, block_json)?;
        self.put("latest_height", &height.to_string())?;
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
}
