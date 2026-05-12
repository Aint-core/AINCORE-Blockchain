#[cfg(test)]
mod tests {
    use crate::{ChainSync, SyncRequest, SyncResponse};
    use blockchain::Block;
    use std::sync::{Arc, Mutex};
    use std::collections::HashMap;
    use storage::StateDB;
    use std::fs;

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = format!("/tmp/aincore_sync_db_{}", name);
        let _ = fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("Failed to open DB"))
    }

    fn setup_sync(name: &str) -> ChainSync {
        let db = temp_db(name);
        let peers = Arc::new(Mutex::new(HashMap::new()));
        ChainSync::new("node_1".to_string(), 8080, peers, db)
    }

    #[test]
    fn test_get_height_message() {
        let sync = setup_sync("get_height");
        // DB is empty, height should be 0
        let resp = sync.handle_message("GET_HEIGHT");
        assert_eq!(resp, Some("HEIGHT:0".to_string()));

        // Set height to 42
        sync.storage.put("latest_height", "42").unwrap();
        let resp = sync.handle_message("GET_HEIGHT");
        assert_eq!(resp, Some("HEIGHT:42".to_string()));
    }

    #[test]
    fn test_handle_sync_request() {
        let sync = setup_sync("sync_req");
        
        // Create dummy blocks in DB
        for height in 1..=5 {
            let block = Block::new(height, height, "prev".to_string(), vec![], "node_1".to_string());
            let block_json = serde_json::to_string(&block).unwrap();
            sync.storage.save_block_json(height, &block_json).unwrap();
        }

        // Request blocks from height 2
        let req = SyncRequest {
            from_height: 2,
            sender_id: "node_2".to_string(),
            sender_port: 8081,
        };
        
        let resp = sync.handle_sync_request(req);
        
        // Should get blocks 3, 4, 5
        assert_eq!(resp.blocks.len(), 3);
        assert_eq!(resp.blocks[0].header.height, 3);
        assert_eq!(resp.blocks[2].header.height, 5);
    }

    #[test]
    fn test_handle_sync_request_message_parsing() {
        let sync = setup_sync("sync_req_msg");
        let block = Block::new(1, 1, "prev".to_string(), vec![], "node_1".to_string());
        let block_json = serde_json::to_string(&block).unwrap();
        sync.storage.save_block_json(1, &block_json).unwrap();

        let req = SyncRequest {
            from_height: 0,
            sender_id: "node_2".to_string(),
            sender_port: 8081,
        };
        let req_json = serde_json::to_string(&req).unwrap();
        let msg = format!("SYNC_REQ:{}", req_json);
        
        let resp_msg = sync.handle_message(&msg).unwrap();
        assert!(resp_msg.starts_with("SYNC_RESP:"));
        let resp_json = resp_msg.strip_prefix("SYNC_RESP:").unwrap();
        let resp: SyncResponse = serde_json::from_str(resp_json).unwrap();
        assert_eq!(resp.blocks.len(), 1);
    }

    #[test]
    fn test_validate_block_success() {
        let sync = setup_sync("val_success");
        let block = Block::new(2, 2, "prev_hash_1".to_string(), vec![], "node_1".to_string());
        
        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_block_future_timestamp() {
        let sync = setup_sync("val_future");
        let mut block = Block::new(2, 2, "prev_hash_1".to_string(), vec![], "node_1".to_string());
        
        // Manipulate timestamp to 60s in the future (exceeds 30s drift limit)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        block.header.timestamp = now + 60;
        
        // Recompute hash after manipulation to ensure it only fails due to timestamp
        let mut data = Vec::new();
        data.extend_from_slice(&block.header.height.to_string().as_bytes());
        data.extend_from_slice(block.header.prev_hash.as_bytes());
        data.extend_from_slice(block.header.tx_hash.as_bytes());
        data.extend_from_slice(block.header.proposer_id.as_bytes());
        data.extend_from_slice(&block.header.round.to_string().as_bytes());
        data.extend_from_slice(&block.header.timestamp.to_string().as_bytes());
        block.header.hash = hex::encode(crypto::hash(&data));

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Future timestamp rejected"));
    }

    #[test]
    fn test_validate_block_too_many_txs() {
        let sync = setup_sync("val_txs");
        // Create block with 10_001 transactions
        let txs = vec!["tx".to_string(); 10_001];
        let block = Block::new(2, 2, "prev_hash_1".to_string(), txs, "node_1".to_string());
        
        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds max 10,000"));
    }
    
    #[test]
    fn test_validate_block_hash_mismatch() {
        let sync = setup_sync("val_hash");
        let mut block = Block::new(2, 2, "prev_hash_1".to_string(), vec![], "node_1".to_string());
        
        // Manipulate hash to cause failure
        block.header.hash = "invalid_hash".to_string();
        
        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hash Mismatch"));
    }
}
