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

    #[tokio::test]
    async fn sync_skips_session_only_peer_without_persisted_ip() {
        let sync = setup_sync("session_only_peer");
        sync.storage.put("latest_height", "7").unwrap();
        sync.peers
            .lock()
            .unwrap()
            .insert("session_only".to_string(), 9032);

        let height = sync.sync_from_peers().await;

        assert_eq!(height, 7);
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
    fn test_sync_request_signals_prune_horizon_when_pruned() {
        // Seed retains only blocks 1000..=1005 (1..999 pruned); a fresh node
        // requesting from height 0 gets an empty batch — the seed must signal the
        // prune horizon so the node bootstraps from a snapshot instead of looping.
        let sync = setup_sync("prune_horizon");
        for h in 1000..=1005 {
            let b = Block::new(h, h, "prev".to_string(), vec![], "node_1".to_string());
            sync.storage
                .save_block_json(h, &serde_json::to_string(&b).unwrap())
                .unwrap();
        }
        let req = SyncRequest {
            from_height: 0,
            sender_id: "node_2".to_string(),
            sender_port: 8081,
        };
        let resp = sync.handle_sync_request(req);
        assert!(resp.blocks.is_empty(), "requested range is below prune horizon");
        assert_eq!(
            resp.prune_horizon,
            Some(1000),
            "seed should report lowest available block as the horizon"
        );
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

    /// Build a valid 1-of-1 quorum certificate and store the matching trusted
    /// validator set (sys:validator_set:v1) so apply_finality_artifact can verify.
    fn build_test_qc(
        sync: &ChainSync,
        finalized_round: u64,
        anchor_round: u64,
    ) -> consensus::qc::QuorumCertificate {
        use consensus::qc::{build_qc, validator_set_hash, FinalityVote, ValidatorInfo};
        let bls = crypto::bls::BLSEngine::consensus();
        let seed = [7u8; 32];
        let validators = vec![ValidatorInfo {
            address: "validator_1".to_string(),
            stake: 1000,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&seed)),
        }];
        sync.storage
            .put(
                "sys:validator_set:v1",
                &serde_json::to_string(&validators).unwrap(),
            )
            .unwrap();
        let vote = FinalityVote {
            // Must match qc::expected_chain_id() (default AINCORE-MAINNET-1) so the
            // chain_id binding added for audit M-1 accepts this test QC.
            chain_id: "AINCORE-MAINNET-1".to_string(),
            epoch: 0,
            finalized_round,
            anchor_round,
            anchor_hash: "ab".repeat(32),
            block_height: anchor_round,
            block_hash: "cd".repeat(32),
            state_root: "ef".repeat(32),
            receipts_root: "12".repeat(32),
            finality_digest: "34".repeat(32),
            validator_set_hash: validator_set_hash(&validators),
        };
        let sig = bls.sign_raw(&vote.to_signing_bytes(), &seed);
        build_qc(&vote, &validators, &[0], &[sig]).unwrap()
    }

    // Store a local block at `height` whose header.hash == `hash` so the
    // finality binding (#6/#24) sees the certified block as held.
    fn store_block_with_hash(sync: &ChainSync, height: u64, hash: &str) {
        let mut blk = Block::new(height, height, "ab".repeat(32), vec![], "validator_1".to_string());
        blk.header.hash = hash.to_string();
        sync.storage
            .put(&format!("block_{}", height), &serde_json::to_string(&blk).unwrap())
            .unwrap();
    }

    #[test]
    fn test_apply_finality_qc_verified_advances() {
        let sync = setup_sync("finality_qc_ok");
        let qc = build_test_qc(&sync, 9000, 8990);
        // #6/#24: the node must hold the certified block (height 8990, hash cd..).
        store_block_with_hash(&sync, 8990, &"cd".repeat(32));
        let artifact = FinalityArtifact {
            finalized_round: "9000".to_string(),
            last_anchor_round: "8990".to_string(),
            last_anchor_hash: "ab".repeat(32),
            finality_digest: "34".repeat(32),
            qc: Some(qc),
        };
        sync.apply_finality_artifact(&artifact)
            .expect("a valid QC must advance finalized_round");
        assert_eq!(
            sync.storage.get("consensus:finalized_round").unwrap(),
            Some("9000".to_string())
        );
    }

    #[test]
    fn test_apply_finality_without_local_block_is_noop() {
        // SEC-#24: a valid QC for a block we don't hold yet must NOT advance
        // finality past it (no local block_8990 stored).
        let sync = setup_sync("finality_no_block");
        let qc = build_test_qc(&sync, 9000, 8990);
        let artifact = FinalityArtifact {
            finalized_round: "9000".to_string(),
            last_anchor_round: "8990".to_string(),
            last_anchor_hash: "ab".repeat(32),
            finality_digest: "34".repeat(32),
            qc: Some(qc),
        };
        sync.apply_finality_artifact(&artifact).expect("no-op, not error");
        assert_eq!(
            sync.storage.get("consensus:finalized_round").unwrap(),
            None,
            "must not advance finality past a block we don't hold"
        );
    }

    #[test]
    fn test_apply_finality_block_hash_mismatch_rejected() {
        // SEC-#6: a QC whose certified block_hash != our local block's hash at
        // that height must be REJECTED (finality must not diverge from our chain).
        let sync = setup_sync("finality_hash_mismatch");
        let qc = build_test_qc(&sync, 9000, 8990);
        store_block_with_hash(&sync, 8990, &"99".repeat(32)); // different hash
        let artifact = FinalityArtifact {
            finalized_round: "9000".to_string(),
            last_anchor_round: "8990".to_string(),
            last_anchor_hash: "ab".repeat(32),
            finality_digest: "34".repeat(32),
            qc: Some(qc),
        };
        assert!(
            sync.apply_finality_artifact(&artifact).is_err(),
            "QC block_hash != local block hash must be rejected"
        );
        assert_eq!(
            sync.storage.get("consensus:finalized_round").unwrap(),
            None
        );
    }

    #[test]
    fn test_apply_finality_without_qc_is_noop() {
        // Regression for the forgeable-guard halt (audit finding #1): an artifact
        // carrying NO QC — even with a huge finalized_round — must NOT advance
        // consensus:finalized_round. The old round-drift heuristic accepted it.
        let sync = setup_sync("finality_no_qc");
        let artifact = FinalityArtifact {
            finalized_round: "5000000".to_string(),
            last_anchor_round: "5000000".to_string(),
            last_anchor_hash: "x".to_string(),
            finality_digest: "d".to_string(),
            qc: None,
        };
        sync.apply_finality_artifact(&artifact).unwrap();
        assert_eq!(
            sync.storage.get("consensus:finalized_round").unwrap(),
            None,
            "finality without a QC must never advance"
        );
    }

    #[test]
    fn test_apply_finality_invalid_qc_rejected() {
        let sync = setup_sync("finality_bad_qc");
        let mut qc = build_test_qc(&sync, 9000, 8990);
        // Corrupt the aggregate signature -> BLS verification must fail.
        qc.aggregate_signature = vec![0u8; qc.aggregate_signature.len()];
        let artifact = FinalityArtifact {
            finalized_round: "9000".to_string(),
            last_anchor_round: "8990".to_string(),
            last_anchor_hash: "ab".repeat(32),
            finality_digest: "34".repeat(32),
            qc: Some(qc),
        };
        let err = sync.apply_finality_artifact(&artifact).unwrap_err();
        assert!(err.contains("QC verification failed"), "got: {err}");
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

    // SEC-#7 (cutover): empty execution roots are accepted by default (so the
    // running testnet is not retroactively rejected).
    #[test]
    fn verify_execution_roots_empty_ok_when_not_required() {
        let sync = setup_sync("roots_empty_default");
        let block = Block::new_with_roots(
            1,
            1,
            "genesis".to_string(),
            vec![],
            "node_1".to_string(),
            String::new(),
            String::new(),
        );
        let summary = executor::BlockExecutionSummary {
            state_root: "s".to_string(),
            receipts_root: "r".to_string(),
            gas_charged: 0,
            tx_count: 0,
        };
        assert!(sync.verify_execution_roots(&block, &summary).is_ok());
    }

    // SEC-#7 (cutover): with sys:config:require_exec_roots set, an empty-root
    // block is rejected; a non-empty matching block still passes.
    #[test]
    fn verify_execution_roots_rejects_empty_when_required() {
        let sync = setup_sync("roots_required");
        sync.storage
            .put("sys:config:require_exec_roots", "1")
            .unwrap();
        let summary = executor::BlockExecutionSummary {
            state_root: "s".to_string(),
            receipts_root: "r".to_string(),
            gas_charged: 0,
            tx_count: 0,
        };

        let empty = Block::new_with_roots(
            1,
            1,
            "genesis".to_string(),
            vec![],
            "node_1".to_string(),
            String::new(),
            String::new(),
        );
        let err = sync.verify_execution_roots(&empty, &summary).unwrap_err();
        assert!(err.contains("empty state_root"), "got: {}", err);

        let good = Block::new_with_roots(
            1,
            1,
            "genesis".to_string(),
            vec![],
            "node_1".to_string(),
            "s".to_string(),
            "r".to_string(),
        );
        assert!(sync.verify_execution_roots(&good, &summary).is_ok());
    }

    // SEC-#8: a non-finalized reorg that would orphan STATE-CHANGING blocks must
    // halt for operator re-bootstrap rather than silently roll back — rollback
    // does not revert Move/executor state, so re-executing the new fork over it
    // would diverge this node. (Empty-orphan reorgs are covered by the next test.)
    #[test]
    fn test_process_blocks_reorg_state_changing_orphan_halts() {
        let sync = setup_sync("reorg_state_changing_halts");
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
            vec!["b".to_string()], // non-empty → state-changing orphan
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
        // Reorg refused: height does not advance, local block preserved, halt latched.
        assert_eq!(new_height, 2);

        let stored_b2 = sync.storage.get("block_2").unwrap().unwrap();
        let stored_b2: Block = serde_json::from_str(&stored_b2).unwrap();
        assert_eq!(stored_b2.header.hash, local_b2.header.hash);

        let halt = sync.storage.get("sync:halt_reason").unwrap();
        assert!(
            halt.as_deref().unwrap_or("").contains("state-changing reorg"),
            "expected state-changing reorg halt to be latched, got {:?}",
            halt
        );
    }

    // SEC-#8: an empty (no-tx) orphan carries no state, so the reorg is safe to
    // roll back and re-execute as before.
    #[test]
    fn test_process_blocks_reorg_empty_orphan_rolls_back() {
        let sync = setup_sync("reorg_empty_orphan");
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
            vec![], // empty → no state to revert
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

        // No halt should be latched on the safe empty-orphan path.
        assert!(sync.storage.get("sync:halt_reason").unwrap().is_none());
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

    // ---- TASK-#29: seed-anchor / N-peer tip agreement ----

    // (1) SEED PREFERENCE: seed/validator peers must be ordered FIRST, regardless of
    // HashMap iteration order; remaining peers follow. Ordering is deterministic.
    #[test]
    fn test_order_peers_seed_first() {
        let mut peers = HashMap::new();
        peers.insert("zeta_peer".to_string(), 9001u16);
        peers.insert("validator_b".to_string(), 9002u16);
        peers.insert("alpha_peer".to_string(), 9003u16);
        peers.insert("validator_a".to_string(), 9004u16);

        let seeds = vec!["validator_a".to_string(), "validator_b".to_string()];
        let ordered = ChainSync::order_peers_seed_first(&peers, &seeds);

        let ids: Vec<&str> = ordered.iter().map(|(id, _)| id.as_str()).collect();
        // Seeds first (sorted by id), then non-seeds (sorted by id).
        assert_eq!(
            ids,
            vec!["validator_a", "validator_b", "alpha_peer", "zeta_peer"]
        );
        // Ports are carried through correctly.
        assert_eq!(ordered[0], ("validator_a".to_string(), 9004));
    }

    #[test]
    fn test_order_peers_seed_first_no_seeds_is_sorted() {
        let mut peers = HashMap::new();
        peers.insert("c".to_string(), 1u16);
        peers.insert("a".to_string(), 2u16);
        peers.insert("b".to_string(), 3u16);
        let ordered = ChainSync::order_peers_seed_first(&peers, &[]);
        let ids: Vec<&str> = ordered.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b", "c"]);
    }

    // Helper: a verified-shaped QC with a chosen finalized tip. tip_agreement_decision
    // is a PURE tally over already-verified QCs, so mutating block_height/block_hash
    // here is sound for these unit tests (no re-verification happens in the tally).
    fn qc_with_tip(sync: &ChainSync, height: u64, hash: &str) -> consensus::qc::QuorumCertificate {
        let mut qc = build_test_qc(sync, 9000, 8990);
        qc.block_height = height;
        qc.block_hash = hash.to_string();
        qc
    }

    // (2) N-PEER TIP AGREEMENT: with N=2, two seeds advertising the SAME tip agree.
    #[test]
    fn test_tip_agreement_requires_n_consistent_tips() {
        let sync = setup_sync("tip_agree_n2_ok");
        let tip_hash = "aa".repeat(32);
        let tips = vec![
            qc_with_tip(&sync, 100, &tip_hash),
            qc_with_tip(&sync, 100, &tip_hash),
        ];
        let decision = ChainSync::tip_agreement_decision(&tips, 2);
        assert_eq!(decision, Ok((100, tip_hash)));
    }

    // N=2 but only ONE seed advertised a tip -> shortfall -> refuse.
    #[test]
    fn test_tip_agreement_shortfall_refuses() {
        let sync = setup_sync("tip_agree_shortfall");
        let tips = vec![qc_with_tip(&sync, 100, &"aa".repeat(32))];
        let err = ChainSync::tip_agreement_decision(&tips, 2).unwrap_err();
        assert!(
            err.contains("only 1 seed"),
            "expected shortfall message, got: {err}"
        );
    }

    // N=2, two seeds but DIFFERENT tips -> disagreement -> refuse.
    #[test]
    fn test_tip_agreement_disagreement_refuses() {
        let sync = setup_sync("tip_agree_disagree");
        let tips = vec![
            qc_with_tip(&sync, 100, &"aa".repeat(32)),
            qc_with_tip(&sync, 101, &"bb".repeat(32)),
        ];
        let err = ChainSync::tip_agreement_decision(&tips, 2).unwrap_err();
        assert!(
            err.contains("disagree") || err.contains("no tip reached"),
            "expected disagreement message, got: {err}"
        );
    }

    // Mixed: 2 of 3 seeds agree, 1 dissents, N=2 -> the agreeing tip wins.
    #[test]
    fn test_tip_agreement_majority_with_one_dissenter() {
        let sync = setup_sync("tip_agree_majority");
        let agreed = "aa".repeat(32);
        let tips = vec![
            qc_with_tip(&sync, 100, &agreed),
            qc_with_tip(&sync, 100, &agreed),
            qc_with_tip(&sync, 200, &"cc".repeat(32)),
        ];
        let decision = ChainSync::tip_agreement_decision(&tips, 2);
        assert_eq!(decision, Ok((100, agreed)));
    }

    // N=1 PRESERVES CURRENT BEHAVIOUR: a single advertised tip is accepted.
    #[test]
    fn test_tip_agreement_n1_preserves_single_seed_behavior() {
        let sync = setup_sync("tip_agree_n1");
        let tip_hash = "aa".repeat(32);
        let tips = vec![qc_with_tip(&sync, 100, &tip_hash)];
        let decision = ChainSync::tip_agreement_decision(&tips, 1);
        assert_eq!(decision, Ok((100, tip_hash)));
    }

    // N=0 is clamped to 1 (no env, deterministic floor).
    #[test]
    fn test_tip_agreement_n_zero_clamped_to_one() {
        let sync = setup_sync("tip_agree_n0");
        let tip_hash = "aa".repeat(32);
        let tips = vec![qc_with_tip(&sync, 100, &tip_hash)];
        let decision = ChainSync::tip_agreement_decision(&tips, 0);
        assert_eq!(decision, Ok((100, tip_hash)));
        // ...and an empty set with clamped-1 still fails (need >=1).
        assert!(ChainSync::tip_agreement_decision(&[], 0).is_err());
    }

    // Config knob: default is 1 (current behaviour); a stored value overrides; bogus
    // / sub-1 values clamp to 1.
    #[test]
    fn test_tip_agreement_n_config_knob() {
        let sync = setup_sync("tip_n_config");
        assert_eq!(sync.tip_agreement_n(), 1, "default must be 1");

        sync.storage
            .put("sys:config:tip_agreement_n", "3")
            .unwrap();
        assert_eq!(sync.tip_agreement_n(), 3);

        sync.storage
            .put("sys:config:tip_agreement_n", "0")
            .unwrap();
        assert_eq!(sync.tip_agreement_n(), 1, "0 clamps to 1");

        sync.storage
            .put("sys:config:tip_agreement_n", "garbage")
            .unwrap();
        assert_eq!(sync.tip_agreement_n(), 1, "unparsable falls back to 1");
    }

    // End-to-end-ish: with N=2 configured and no reachable seeds, sync_from_peers must
    // REFUSE to advance (tip disagreement / shortfall) and return the local height.
    #[tokio::test]
    async fn test_sync_refuses_when_tip_agreement_unmet() {
        let sync = setup_sync("tip_refuse_sync");
        sync.storage.put("latest_height", "5").unwrap();
        sync.storage
            .put("sys:config:tip_agreement_n", "2")
            .unwrap();
        // Two validator seeds, but their peer_ip is never persisted -> unreachable,
        // so zero verified tips are gathered -> shortfall -> refuse.
        set_validators(&sync, vec![("validator_a", 100), ("validator_b", 100)]);
        sync.peers
            .lock()
            .unwrap()
            .insert("validator_a".to_string(), 9101);
        sync.peers
            .lock()
            .unwrap()
            .insert("validator_b".to_string(), 9102);

        let height = sync.sync_from_peers().await;
        assert_eq!(height, 5, "must not advance when tip agreement is unmet");
    }
}
