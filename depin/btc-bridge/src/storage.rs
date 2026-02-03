use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub struct Storage {
    path: String,
    processed_txs: HashSet<String>,
}

impl Storage {
    pub fn new(path: &str) -> Self {
        let mut processed_txs = HashSet::new();
        
        if Path::new(path).exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(txs) = serde_json::from_str::<HashSet<String>>(&content) {
                    processed_txs = txs;
                }
            }
        }

        Self {
            path: path.to_string(),
            processed_txs,
        }
    }

    pub fn is_processed(&self, tx_hash: &str) -> bool {
        self.processed_txs.contains(tx_hash)
    }

    pub fn mark_processed(&mut self, tx_hash: String) -> Result<()> {
        self.processed_txs.insert(tx_hash);
        self.save()
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_string(&self.processed_txs)?;
        fs::write(&self.path, json)?;
        Ok(())
    }
}
