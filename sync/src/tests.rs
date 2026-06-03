#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::{ChainSync, FinalityArtifact, SyncRequest, SyncResponse};
    use blockchain::Block;
    use std::collections::HashMap;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use storage::StateDB;

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

    fn set_validators(sync: &ChainSync, validators: Vec<(&str, u64)>) {
        let vals: Vec<(String, u64)> = validators
            .into_iter()
            .map(|(addr, stake)| (addr.to_string(), stake))
            .collect();
        sync.storage
            .put("sys:validators", &serde_json::to_string(&vals).unwrap())
            .unwrap();
    }

    fn rehash_block(block: &mut Block) {
        block.header.hash = blockchain::calculate_header_hash(&block.header);
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
        sync.storage.put("consensus:finalized_round", "4").unwrap();
        sync.storage
            .put("consensus:last_anchor_round", "4")
            .unwrap();
        sync.storage
            .put("consensus:last_anchor_hash", "anchor-hash")
            .unwrap();
        sync.storage
            .put("consensus:finality_digest", "digest")
            .unwrap();

        // Create dummy blocks in DB
        for height in 1..=5 {
            let block = Block::new(
                height,
                height,
                "prev".to_string(),
                vec![],
                "node_1".to_string(),
            );
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
        let finality = resp.finality.expect("sync response includes finality");
        assert_eq!(finality.finalized_round, "4");
        assert_eq!(finality.last_anchor_hash, "anchor-hash");
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
        assert!(resp.finality.is_some());
    }

    #[test]
    fn test_get_finality_message() {
        let sync = setup_sync("get_finality");
        sync.storage.put("consensus:finalized_round", "9").unwrap();
        sync.storage
            .put("consensus:last_anchor_round", "8")
            .unwrap();
        sync.storage
            .put("consensus:last_anchor_hash", "abc")
            .unwrap();
        sync.storage
            .put("consensus:finality_digest", "def")
            .unwrap();

        let resp = sync.handle_message("GET_FINALITY").unwrap();
        let json = resp.strip_prefix("FINALITY:").unwrap();
        let artifact: FinalityArtifact = serde_json::from_str(json).unwrap();
        assert_eq!(artifact.finalized_round, "9");
        assert_eq!(artifact.last_anchor_round, "8");
        assert_eq!(artifact.finality_digest, "def");
    }

    #[test]
    fn test_apply_finality_artifact_updates_observer_storage() {
        let sync = setup_sync("apply_finality");
        sync.storage.put("latest_height", "100").unwrap();

        let artifact = FinalityArtifact {
            finalized_round: "95".to_string(),
            last_anchor_round: "95".to_string(),
            last_anchor_hash: "anchor".to_string(),
            finality_digest: "digest".to_string(),
        };

        sync.apply_finality_artifact(&artifact).unwrap();
        assert_eq!(
            sync.storage.get("consensus:finalized_round").unwrap(),
            Some("95".to_string())
        );
        assert_eq!(
            sync.storage.get("consensus:finality_digest").unwrap(),
            Some("digest".to_string())
        );
    }

    #[test]
    fn test_apply_finality_artifact_rejects_absurd_future_round() {
        let sync = setup_sync("apply_finality_future");
        sync.storage.put("latest_height", "10").unwrap();

        let artifact = FinalityArtifact {
            finalized_round: "5000".to_string(),
            last_anchor_round: "5000".to_string(),
            last_anchor_hash: "anchor".to_string(),
            finality_digest: "digest".to_string(),
        };

        let err = sync.apply_finality_artifact(&artifact).unwrap_err();
        assert!(err.contains("too far beyond local height"));
        assert_eq!(sync.storage.get("consensus:finalized_round").unwrap(), None);
    }

    #[test]
    fn test_validate_block_success() {
        let sync = setup_sync("val_success");
        let block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec![],
            "node_1".to_string(),
        );

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_block_future_timestamp() {
        let sync = setup_sync("val_future");
        let mut block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec![],
            "node_1".to_string(),
        );

        // Manipulate timestamp to 60s in the future (exceeds 30s drift limit)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        block.header.timestamp = now + 60;

        // Recompute hash after manipulation to ensure it only fails due to timestamp
        let mut data = Vec::new();
        data.extend_from_slice(block.header.height.to_string().as_bytes());
        data.extend_from_slice(block.header.prev_hash.as_bytes());
        data.extend_from_slice(block.header.tx_hash.as_bytes());
        data.extend_from_slice(block.header.proposer_id.as_bytes());
        data.extend_from_slice(block.header.round.to_string().as_bytes());
        data.extend_from_slice(block.header.timestamp.to_string().as_bytes());
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
        let mut block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec![],
            "node_1".to_string(),
        );

        // Manipulate hash to cause failure
        block.header.hash = "invalid_hash".to_string();

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hash Mismatch"));
    }

    #[test]
    fn test_validate_block_rejects_bad_tx_hash_even_if_header_hash_matches() {
        let sync = setup_sync("val_tx_hash");
        let mut block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec!["tx1".to_string()],
            "node_1".to_string(),
        );
        block.header.tx_hash = "fake_tx_hash".to_string();
        rehash_block(&mut block);

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Transaction hash mismatch"));
    }

    #[test]
    fn test_validate_block_rejects_non_validator_proposer() {
        let sync = setup_sync("val_proposer");
        set_validators(&sync, vec![("validator_1", 100)]);
        let block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec![],
            "node_1".to_string(),
        );

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in active validator set"));
    }

    #[test]
    fn test_process_blocks_rejects_height_gap() {
        let sync = setup_sync("process_gap");
        let gap_block = Block::new(3, 3, "unknown".to_string(), vec![], "node_1".to_string());

        let height = sync.process_blocks(vec![gap_block], 0);

        assert_eq!(height, 0);
        assert_eq!(sync.storage.get_chain_height(), 0);
    }

    #[test]
    fn test_validate_block_hash_commits_execution_roots() {
        let sync = setup_sync("val_roots_hash");
        let mut block = Block::new_with_roots(
            2,
            2,
            "prev_hash_1".to_string(),
            vec![],
            "node_1".to_string(),
            "state_root_a".to_string(),
            "receipts_root_a".to_string(),
        );
        let original_hash = block.header.hash.clone();
        block.header.state_root = "state_root_b".to_string();

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hash Mismatch"));
        assert_ne!(
            original_hash,
            blockchain::calculate_header_hash(&block.header)
        );
    }

    #[test]
    fn test_verify_execution_roots_rejects_state_mismatch() {
        let sync = setup_sync("root_state_mismatch");
        let block = Block::new_with_roots(
            1,
            1,
            "genesis".to_string(),
            vec![],
            "node_1".to_string(),
            "expected_state".to_string(),
            String::new(),
        );
        let summary = executor::BlockExecutionSummary {
            state_root: "actual_state".to_string(),
            receipts_root: String::new(),
            gas_charged: 0,
            tx_count: 0,
        };

        let err = sync.verify_execution_roots(&block, &summary).unwrap_err();
        assert!(err.contains("State root mismatch"));
    }

    #[test]
    fn test_process_blocks_reorg_rolls_back_non_finalized_conflict() {
        let sync = setup_sync("reorg_non_finalized");
        set_validators(&sync, vec![("node_1", 100), ("node_2", 100)]);

        let mut local_b1 = Block::new(
            1,
            1,
            "genesis".to_string(),
            vec!["a".to_string()],
            "node_1".to_string(),
        );
        rehash_block(&mut local_b1);
        sync.storage
            .save_block_json(1, &serde_json::to_string(&local_b1).unwrap())
            .unwrap();

        let mut local_b2 = Block::new(
            2,
            2,
            local_b1.header.hash.clone(),
            vec!["b".to_string()],
            "node_1".to_string(),
        );
        rehash_block(&mut local_b2);
        sync.storage
            .save_block_json(2, &serde_json::to_string(&local_b2).unwrap())
            .unwrap();

        sync.storage.put("consensus:finalized_round", "0").unwrap();

        let mut remote_b2 = Block::new(
            2,
            2,
            local_b1.header.hash.clone(),
            vec!["x".to_string()],
            "node_2".to_string(),
        );
        rehash_block(&mut remote_b2);
        let mut remote_b3 = Block::new(
            3,
            3,
            remote_b2.header.hash.clone(),
            vec!["y".to_string()],
            "node_2".to_string(),
        );
        rehash_block(&mut remote_b3);

        let new_height = sync.process_blocks(vec![remote_b2.clone(), remote_b3.clone()], 2);
        assert_eq!(new_height, 3);

        let stored_b2 = sync.storage.get("block_2").unwrap().unwrap();
        let stored_b2: Block = serde_json::from_str(&stored_b2).unwrap();
        assert_eq!(stored_b2.header.hash, remote_b2.header.hash);
    }

    #[test]
    fn test_process_blocks_reorg_rejects_finalized_conflict() {
        let sync = setup_sync("reorg_finalized");
        set_validators(&sync, vec![("node_1", 100), ("node_2", 100)]);

        let mut local_b1 = Block::new(
            1,
            1,
            "genesis".to_string(),
            vec!["a".to_string()],
            "node_1".to_string(),
        );
        rehash_block(&mut local_b1);
        sync.storage
            .save_block_json(1, &serde_json::to_string(&local_b1).unwrap())
            .unwrap();

        let mut local_b2 = Block::new(
            2,
            2,
            local_b1.header.hash.clone(),
            vec!["b".to_string()],
            "node_1".to_string(),
        );
        rehash_block(&mut local_b2);
        sync.storage
            .save_block_json(2, &serde_json::to_string(&local_b2).unwrap())
            .unwrap();
        sync.storage.put("consensus:finalized_round", "2").unwrap();

        let mut remote_b2 = Block::new(
            2,
            2,
            local_b1.header.hash.clone(),
            vec!["x".to_string()],
            "node_2".to_string(),
        );
        rehash_block(&mut remote_b2);
        let new_height = sync.process_blocks(vec![remote_b2], 2);
        assert_eq!(new_height, 2);

        let stored_b2 = sync.storage.get("block_2").unwrap().unwrap();
        let stored_b2: Block = serde_json::from_str(&stored_b2).unwrap();
        assert_eq!(stored_b2.header.hash, local_b2.header.hash);
    }
}
