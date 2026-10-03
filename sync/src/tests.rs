#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::{ChainSync, FinalityArtifact, SyncRequest, SyncResponse};
    use blockchain::Block;
    use std::fs;
    use std::sync::{Arc, Mutex};
    use storage::StateDB;

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = format!(
            "{}/aincore_sync_db_{}",
            storage::test_dir::process_dir().display(),
            name
        );
        let _ = fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("Failed to open DB"))
    }

    /// A DB name no other call in this process gets: pid + counter, not the
    /// clock (macOS ticks in microseconds, so parallel tests could collide).
    fn unique_name(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}_{}_{n}", std::process::id())
    }

    /// RE-AUDIT CRITICAL fixture: register the proposer's Ed25519 key as its
    /// on-chain AccountData and sign the block, so validate_block's proposer
    /// authentication passes for blocks a test expects to be VALID.
    fn authenticate_block(sync: &ChainSync, block: &mut Block) {
        let _seed = sync.storage.seeding();
        use storage::object::{Object, Owner};
        let key = crypto::SigningKey::from_bytes(&[77u8; 32]);
        let pk = hex::encode(key.verifying_key().to_bytes());
        let pid = block.header.proposer_id.clone();
        let account = Object::new(
            pid.clone(),
            Owner::Address(pid),
            serde_json::json!({ "public_key": pk, "sequence_number": 0 })
                .to_string()
                .into_bytes(),
            "0x1::account::AccountData".to_string(),
        );
        sync.storage.put_object(&account).unwrap();
        let signer = block.header.proposer_id.clone();
        block.sign_proposer(&key, &signer);
    }

    fn setup_sync(name: &str) -> ChainSync {
        ChainSync::new(temp_db(name))
    }

    /// Sessions the network task lists but cannot serve (it is gone): every
    /// request on them fails.
    fn unreachable_sessions(sessions: Vec<network::SessionPeer>) -> network::SessionClient {
        let (asks, _) = tokio::sync::mpsc::channel(1);
        let (dials, _) = tokio::sync::mpsc::channel(1);
        network::SessionClient {
            asks,
            dials,
            table: Arc::new(std::sync::RwLock::new(sessions)),
        }
    }

    mod block_identity {
        include!("block_identity_tests.rs");
    }

    mod reorg_acceptance {
        include!("reorg_acceptance_tests.rs");
    }

    mod qc_import {
        include!("qc_import_tests.rs");
    }
    mod system {
        include!("system_tests.rs");
    }
    mod admission_snapshot {
        include!("admission_snapshot_tests.rs");
    }

    /// G3: genesis ends with its state committed as tree version 0 (S3). A
    /// fixture that builds headers from `current_state_root()` does the same
    /// after writing its genesis state.
    fn seed_state_tree(sync: &ChainSync) {
        let seeded = state_commit::seed_genesis(&sync.storage).expect("seed state tree v0");
        sync.storage.write_batch(seeded.batch).unwrap();
    }

    /// G5 CL-2: the state root of an empty block at `height` with BFT
    /// timestamp `timestamp`, on top of the executed chain: the executor runs
    /// it in a discarded transaction (`dry_run_empty_block_root`), so the
    /// clock write and, at a boundary, the committee record are exact. A
    /// block at a height the fixture already executed (with an empty block)
    /// gets that version's root: it is either the same block or a refused
    /// conflict.
    fn empty_block_root(sync: &ChainSync, height: u64, timestamp: u64) -> String {
        let latest = state_commit::latest_version(&sync.storage)
            .unwrap()
            .unwrap();
        if height <= latest {
            return hex::encode(state_commit::root(&sync.storage, height).unwrap().0);
        }
        crate::dry_run_empty_block_root(&sync.storage, height, timestamp)
    }

    fn set_validators(sync: &ChainSync, validators: Vec<(&str, u64)>) {
        let _seed = sync.storage.seeding();
        let vals: Vec<(String, u64)> = validators
            .into_iter()
            .map(|(addr, stake)| (addr.to_string(), stake))
            .collect();
        sync.storage
            .put("sys:validators", &serde_json::to_string(&vals).unwrap())
            .unwrap();
    }

    /// B33 witness: sessions that never answer cost a pass one short
    /// timeout, together, not a minute each one after another (three
    /// silent sessions held the old pass three minutes).
    #[tokio::test]
    async fn silent_sessions_cost_a_pass_one_short_timeout() {
        let (asks, mut queued) = tokio::sync::mpsc::channel::<network::SyncAsk>(16);
        let (dials, _) = tokio::sync::mpsc::channel(1);
        // The network task takes every ask and never answers it.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(ask) = queued.recv().await {
                held.push(ask);
            }
        });
        let session = |p: &str| network::SessionPeer {
            peer: p.into(),
            member: Some(format!("m-{p}")),
        };
        let client = network::SessionClient {
            asks,
            dials,
            table: Arc::new(std::sync::RwLock::new(vec![
                session("a"),
                session("b"),
                session("c"),
            ])),
        };
        let sync = setup_sync("silent_sessions").with_sessions(client);
        sync.storage.put("latest_height", "4").unwrap();
        let start = std::time::Instant::now();
        assert_eq!(sync.sync_from_peers().await, 4);
        let took = start.elapsed();
        assert!(
            took < std::time::Duration::from_secs(20),
            "a pass took {took:?}"
        );
        assert!(
            took >= std::time::Duration::from_secs(4),
            "positive control: the pass waited for the asks ({took:?})"
        );
    }

    /// B33 review witness: three sessions that advertise a height far above
    /// this node's and never serve a block hold the pass's three slots only
    /// once; the next pass asks the honest session for blocks. Ordered by
    /// membership and height alone, they held every slot of every pass.
    #[tokio::test]
    async fn sessions_that_never_serve_lose_their_slots() {
        let (asks, mut queued) = tokio::sync::mpsc::channel::<network::SyncAsk>(16);
        let (dials, _) = tokio::sync::mpsc::channel(1);
        let block_asks = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log = Arc::clone(&block_asks);
        tokio::spawn(async move {
            while let Some(ask) = queued.recv().await {
                let answer = match (ask.peer.as_str(), ask.wire.as_str()) {
                    ("honest", "GET_HEIGHT") => Ok("HEIGHT:5".to_string()),
                    (_, "GET_HEIGHT") => Ok("HEIGHT:1000".to_string()),
                    (peer, wire) => {
                        if wire.starts_with("SYNC_REQ:") {
                            log.lock().unwrap().push(peer.to_string());
                        }
                        Err("no".to_string())
                    }
                };
                let _ = ask.reply.send(answer);
            }
        });
        let session = |p: &str| network::SessionPeer {
            peer: p.into(),
            member: Some(format!("m-{p}")),
        };
        let client = network::SessionClient {
            asks,
            dials,
            table: Arc::new(std::sync::RwLock::new(vec![
                session("liar1"),
                session("liar2"),
                session("liar3"),
                session("honest"),
            ])),
        };
        let sync = setup_sync("never_serve").with_sessions(client);
        sync.storage.put("latest_height", "4").unwrap();
        sync.sync_from_peers().await;
        assert!(
            !block_asks.lock().unwrap().iter().any(|p| p == "honest"),
            "control: the first pass goes to the highest"
        );
        sync.sync_from_peers().await;
        assert!(
            block_asks.lock().unwrap().iter().any(|p| p == "honest"),
            "the honest session was never asked for blocks: {:?}",
            block_asks.lock().unwrap()
        );
    }

    /// G4 S6: sync goes over the network task's sessions only; without
    /// them (or when no session answers) the node stays where it is.
    #[tokio::test]
    async fn sync_without_answering_sessions_keeps_the_local_height() {
        let sync = setup_sync("no_sessions");
        sync.storage.put("latest_height", "7").unwrap();
        assert_eq!(sync.sync_from_peers().await, 7);
        let sync = setup_sync("dead_sessions").with_sessions(unreachable_sessions(vec![
            network::SessionPeer {
                peer: "12D3KooWgone".into(),
                member: None,
            },
        ]));
        sync.storage.put("latest_height", "7").unwrap();
        assert_eq!(sync.sync_from_peers().await, 7);
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
        let req = SyncRequest { from_height: 2 };

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
        let req = SyncRequest { from_height: 0 };
        let resp = sync.handle_sync_request(req);
        assert!(
            resp.blocks.is_empty(),
            "requested range is below prune horizon"
        );
        assert_eq!(
            resp.prune_horizon,
            Some(1000),
            "seed should report lowest available block as the horizon"
        );
    }

    /// G4 S1/S6: a session is served sync, boundary QCs it may have and
    /// snapshot requests (here refused by the server's setting, not by the
    /// session layer); consensus traffic is not sync.
    #[test]
    fn a_session_is_served_sync_and_snapshots() {
        let sync = setup_sync("serve_session");
        let peer = "12D3KooWsession";
        assert!(sync
            .serve_session("GET_HEIGHT", peer)
            .unwrap()
            .starts_with("HEIGHT:"));
        assert!(sync
            .serve_session("GET_FINALITY", peer)
            .unwrap()
            .starts_with("FINALITY:"));
        let chunk = format!(
            "{}{}",
            crate::state_sync::CHUNK_REQ,
            serde_json::to_string(&crate::state_sync::ChunkRequest {
                version: 0,
                after: None,
                max: 1,
            })
            .unwrap()
        );
        let answer = sync.serve_session(&chunk, peer).expect("routed");
        assert!(
            answer.starts_with(crate::state_sync::CHUNK_RESP),
            "{answer}"
        );
        assert!(answer.contains("snapshots not served here"), "{answer}");
        assert_eq!(sync.serve_session("QC_WANT:1", peer), None, "above the tip");
        assert_eq!(sync.serve_session("QC_WANT:x", peer), None);
        assert_eq!(sync.serve_session("DAG_V4:{}", peer), None, "not sync");
    }

    #[test]
    fn a_sync_answer_stops_at_its_byte_budget() {
        let sync = setup_sync("sync_req_bytes");
        // Three 3 MiB blocks: two fit the 8 MiB budget, the third does not.
        let big = "x".repeat(3 << 20);
        for height in 1..=3 {
            let block = Block::new(
                height,
                height,
                "prev".to_string(),
                vec![big.clone()],
                "node_1".to_string(),
            );
            let block_json = serde_json::to_string(&block).unwrap();
            sync.storage.save_block_json(height, &block_json).unwrap();
        }
        let req = SyncRequest { from_height: 0 };
        let resp = sync.handle_sync_request(req);
        assert_eq!(
            resp.blocks.len(),
            2,
            "B3/NI-4: the answer is bounded by bytes"
        );
        // One block over the whole budget still goes alone.
        let huge = "x".repeat(crate::SYNC_RESP_BLOCK_BYTES + 1);
        let sync = setup_sync("sync_req_one_huge");
        let block = Block::new(1, 1, "prev".into(), vec![huge], "node_1".into());
        sync.storage
            .save_block_json(1, &serde_json::to_string(&block).unwrap())
            .unwrap();
        let req = SyncRequest { from_height: 0 };
        assert_eq!(sync.handle_sync_request(req).blocks.len(), 1);
    }

    #[test]
    fn test_handle_sync_request_message_parsing() {
        let sync = setup_sync("sync_req_msg");
        let block = Block::new(1, 1, "prev".to_string(), vec![], "node_1".to_string());
        let block_json = serde_json::to_string(&block).unwrap();
        sync.storage.save_block_json(1, &block_json).unwrap();

        let req = SyncRequest { from_height: 0 };
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
        build_test_qc_for_epoch(sync, finalized_round, anchor_round, 0)
    }

    fn build_test_qc_for_epoch(
        sync: &ChainSync,
        finalized_round: u64,
        anchor_round: u64,
        epoch: u64,
    ) -> consensus::qc::QuorumCertificate {
        let _seed = sync.storage.seeding();
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
        sync.storage.put("genesis:validator_set:v1", &serde_json::to_string(&validators).unwrap()).unwrap();
        let vote = FinalityVote {
            // Must match qc::expected_chain_id() (default AINCORE-MAINNET-1) so the
            // chain_id binding added for audit M-1 accepts this test QC.
            chain_id: "AINCORE-MAINNET-1".to_string(),
            epoch,
            finalized_round,
            anchor_round,
            anchor_hash: "ab".repeat(32),
            block_height: anchor_round,
            block_hash: finality_test_block(anchor_round).header.hash,
            state_root: "ef".repeat(32),
            receipts_root: "12".repeat(32),
            finality_digest: "34".repeat(32),
            validator_set_hash: validator_set_hash(&validators),
            next_validator_set_hash: String::new(),
        };
        let sig = bls.sign_raw(&vote.to_signing_bytes(), &seed);
        build_qc(&vote, &validators, &[0], &[sig]).unwrap()
    }

    fn finality_test_block(height: u64) -> Block {
        Block::new_with_roots_at(
            height,
            height,
            "ab".repeat(32),
            vec![],
            "validator_1".into(),
            "ef".repeat(32),
            "12".repeat(32),
            1000,
            vec![],
            vec![],
            "ab".repeat(32),
            vec![],
        )
    }

    // Positive fixtures use the constructor's actual hash. The mismatch test
    // deliberately substitutes it to exercise rejection of inconsistent storage.
    fn store_block_with_hash(sync: &ChainSync, height: u64, hash: &str) {
        let mut blk = finality_test_block(height);
        blk.header.hash = hash.to_string();
        sync.storage
            .put(&format!("block_{}", height), &serde_json::to_string(&blk).unwrap())
            .unwrap();
    }

    #[test]
    fn test_apply_finality_qc_verified_advances() {
        let sync = setup_sync("finality_qc_ok");
        let qc = build_test_qc(&sync, 9000, 8990);
        // The node must hold the actual block certified by this signature.
        store_block_with_hash(&sync, 8990, &qc.block_hash);
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
    fn test_unknown_epoch_cannot_borrow_live_committee_for_finality() {
        let sync = setup_sync("finality_unknown_epoch");
        let qc = build_test_qc_for_epoch(&sync, 9000, 8990, 9);
        store_block_with_hash(&sync, 8990, &qc.block_hash);
        let _seed = sync.storage.seeding();
        sync.storage.put("consensus:epoch", "10").unwrap();
        sync.storage.put("consensus:epoch_start_height:9", "8001").unwrap();
        sync.storage.put("consensus:epoch_start_height:10", "9001").unwrap();
        let artifact = FinalityArtifact {
            finalized_round: "9000".to_string(),
            last_anchor_round: "8990".to_string(),
            last_anchor_hash: qc.anchor_hash.clone(),
            finality_digest: qc.finality_digest.clone(),
            qc: Some(qc),
        };
        let before: Vec<_> = sync.storage.db.iterator(storage::rocksdb::IteratorMode::Start)
            .map(Result::unwrap).collect();
        sync.apply_finality_artifact(&artifact).unwrap();
        let after: Vec<_> = sync.storage.db.iterator(storage::rocksdb::IteratorMode::Start)
            .map(Result::unwrap).collect();
        assert_eq!(before, after, "unknown epoch advanced finality using the live committee");

        // Positive control: an explicitly retained matching committee permits
        // the same real BLS certificate through the production receiver.
        let snapshot = sync.storage.get("sys:validator_set:v1").unwrap().unwrap();
        sync.storage.put("sys:validator_set:epoch:9", &snapshot).unwrap();
        sync.apply_finality_artifact(&artifact).unwrap();
        assert_eq!(sync.storage.get("consensus:finalized_round").unwrap().as_deref(), Some("9000"));
    }

    #[test]
    fn test_imported_qc_does_not_break_followup_aggregation() {
        let sync = setup_sync("finality_then_aggregate");
        let cert = build_test_qc(&sync, 9000, 8990);
        store_block_with_hash(&sync, cert.block_height, &cert.block_hash);
        let artifact = FinalityArtifact {
            finalized_round: "9000".into(),
            last_anchor_round: "8990".into(),
            last_anchor_hash: cert.anchor_hash.clone(),
            finality_digest: cert.finality_digest.clone(),
            qc: Some(cert),
        };
        sync.apply_finality_artifact(&artifact).unwrap();
        let next = build_test_qc(&sync, 9020, 9010);
        let msg = consensus::qc_producer::QcVoteMessage {
            vote: next.finality_vote(),
            signer_address: "validator_1".into(),
            signature: hex::encode(&next.aggregate_signature),
        };
        assert!(matches!(consensus::qc_producer::collect_vote_and_try_aggregate(
            &sync.storage, &msg, Some(&next.block_hash)),
            consensus::qc_producer::QcOutcome::Complete(_)),
            "imported finality left a QC index state that poisons subsequent aggregation");
        assert_eq!(sync.storage.get("consensus:qc:latest_height").unwrap().as_deref(), Some("9010"));
        assert!(sync.storage.get("consensus:qc:8990").unwrap().is_some());
        assert!(sync.storage.get("consensus:qc_by_round:8990").unwrap().is_some());
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
    fn test_finality_receiver_rejects_inconsistent_body_and_signed_roots() {
        use consensus::qc::{build_qc, verify_qc};
        for corrupt_body in [false, true] {
            let sync = setup_sync(if corrupt_body { "finality_body_binding" } else { "finality_root_binding" });
            let original = build_test_qc(&sync, 9000, 8990);
            store_block_with_hash(&sync, 8990, &original.block_hash);
            let mut cert = original.clone();
            if corrupt_body {
                let mut block = finality_test_block(8990);
                block.transactions.push("unexpected transaction".into());
                sync.storage.put("block_8990", &serde_json::to_string(&block).unwrap()).unwrap();
            } else {
                let mut vote = cert.finality_vote();
                vote.state_root = "98".repeat(32);
                let set = sync.trusted_validator_set(0).unwrap();
                let sig = crypto::bls::BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), &[7; 32]);
                cert = build_qc(&vote, &set, &[0], &[sig]).unwrap();
            }
            verify_qc(&cert, &sync.trusted_validator_set(0).unwrap(), &consensus::qc::expected_chain_id()).unwrap();
            let mut artifact = FinalityArtifact {
                finalized_round: "9000".into(), last_anchor_round: "8990".into(),
                last_anchor_hash: original.anchor_hash.clone(), finality_digest: original.finality_digest.clone(),
                qc: Some(cert),
            };
            let before: Vec<_> = sync.storage.db.iterator(storage::rocksdb::IteratorMode::Start).map(Result::unwrap).collect();
            assert!(sync.apply_finality_artifact(&artifact).is_err());
            let after: Vec<_> = sync.storage.db.iterator(storage::rocksdb::IteratorMode::Start).map(Result::unwrap).collect();
            assert_eq!(before, after, "rejected finality changed database rows");
            // Restore the fixture, not production recovery logic. The correct
            // pair must remain acceptable after a rejected incoming artifact.
            store_block_with_hash(&sync, 8990, &original.block_hash);
            artifact.qc = Some(original);
            sync.apply_finality_artifact(&artifact).unwrap();
            assert_eq!(sync.storage.get("consensus:finalized_round").unwrap().as_deref(), Some("9000"));
        }
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
        set_validators(&sync, vec![("node_1", 100)]);
        let mut block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec![],
            "node_1".to_string(),
        );
        authenticate_block(&sync, &mut block);

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_ok(), "Validation failed: {:?}", result.err());
    }

    #[test]
    fn test_validate_block_future_timestamp() {
        let sync = setup_sync("val_future");
        set_validators(&sync, vec![("node_1", 100)]);
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
        block.header.hash = blockchain::calculate_header_hash(&block.header);

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Future timestamp rejected"));
    }

    #[test]
    fn test_validate_block_too_many_txs() {
        let sync = setup_sync("val_txs");
        set_validators(&sync, vec![("node_1", 100)]);
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
        set_validators(&sync, vec![("node_1", 100)]);
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
        set_validators(&sync, vec![("node_1", 100)]);
        let mut block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec!["tx1".to_string()],
            "node_1".to_string(),
        );
        block.header.tx_hash = "fake_tx_hash".to_string();
        rehash_block(&mut block);
        // B41: the body is checked once a validator's signature binds the
        // header, so the block is signed to reach that check.
        authenticate_block(&sync, &mut block);

        let result = sync.validate_block(&block, 2, "prev_hash_1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Transaction hash mismatch"));
    }

    /// B41 witness: a block naming a validator as signer, without its
    /// signature, is refused for the signature before its body is checked
    /// (the DA root's encode costs up to ~0.6 s a batch).
    #[test]
    fn test_validate_block_checks_the_signature_before_the_body() {
        let sync = setup_sync("val_sig_first");
        set_validators(&sync, vec![("node_1", 100)]);
        let mut block = Block::new(
            2,
            2,
            "prev_hash_1".to_string(),
            vec!["tx1".to_string()],
            "node_1".to_string(),
        );
        block.header.tx_hash = "fake_tx_hash".to_string();
        rehash_block(&mut block);
        block.proposer_signer = "node_1".to_string();

        let err = sync.validate_block(&block, 2, "prev_hash_1").unwrap_err();
        assert!(!err.contains("Transaction hash mismatch"), "{err}");
        assert!(err.contains("signer node_1"), "{err}");
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
    fn test_process_blocks_unpersisted_execution_does_not_advance() {
        let sync = setup_sync(&unique_name("unpersisted_execution"));
        let key = crypto::SigningKey::from_bytes(&[77; 32]);
        let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        set_validators(&sync, vec![(&proposer, 100)]);
        let mut block = Block::new(1, 1, "genesis".to_string(), vec![], proposer);
        authenticate_block(&sync, &mut block);
        sync.validate_block(&block, 1, "genesis").unwrap();
        // Model a crash or in-flight producer between execution and block storage.
        sync.storage.put("sys:last_executed_height", "1").unwrap();

        let mut conflict = block.clone();
        conflict.header.round += 1;
        rehash_block(&mut conflict);
        authenticate_block(&sync, &mut conflict);
        let conflict_json = serde_json::to_string(&conflict).unwrap();
        for bad_row in [None, Some("not a block"), Some(conflict_json.as_str())] {
            if let Some(row) = bad_row {
                sync.storage.put("block_1", row).unwrap();
            }
            let before: Vec<_> = sync.storage.db
                .iterator(storage::rocksdb::IteratorMode::Start)
                .map(Result::unwrap)
                .collect();
            assert_eq!(
                sync.process_blocks(vec![block.clone()], 0), 0,
                "an executed height without a valid stored block is not synced"
            );
            let after: Vec<_> = sync.storage.db
                .iterator(storage::rocksdb::IteratorMode::Start)
                .map(Result::unwrap)
                .collect();
            assert_eq!(after, before, "sync must not alter partially committed state");
            assert_eq!(sync.storage.get_chain_height(), 0);
        }

        // Once the producer has persisted the SAME block, retry makes progress.
        sync.storage
            .save_block_json(1, &serde_json::to_string(&block).unwrap())
            .unwrap();
        assert_eq!(sync.process_blocks(vec![block.clone()], 0), 1);
        assert_eq!(sync.process_blocks(vec![block], 1), 1);
    }

    #[test]
    fn test_rejected_execution_roots_leave_state_untouched_then_valid_retry_succeeds() {
        let sync = setup_sync("rejected_execution_atomic");
        let key = crypto::SigningKey::from_bytes(&[77; 32]);
        let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        set_validators(&sync, vec![(&proposer, 100)]);
        seed_state_tree(&sync);
        let executor = executor::Executor::new(sync.storage.clone());
        let mut valid = Block::new_with_roots_at(
            1,
            1,
            "genesis".into(),
            vec![],
            proposer,
            empty_block_root(&sync, 1, 23),
            executor.receipts_root_for_block(&[]),
            23,
            Vec::new(),
            vec![],
            String::new(),
            Vec::new(),
        );
        authenticate_block(&sync, &mut valid);
        for bad_state in [true, false] {
            let mut invalid = valid.clone();
            if bad_state { invalid.header.state_root = "ff".repeat(32); }
            else { invalid.header.receipts_root = "ff".repeat(32); }
            rehash_block(&mut invalid);
            authenticate_block(&sync, &mut invalid);
            sync.validate_block(&invalid, 1, "genesis").unwrap();
            let before: Vec<_> = sync.storage.db.iterator(storage::rocksdb::IteratorMode::Start)
                .map(Result::unwrap).collect();
            assert_eq!(sync.process_blocks(vec![invalid], 0), 0);
            let after: Vec<_> = sync.storage.db.iterator(storage::rocksdb::IteratorMode::Start)
                .map(Result::unwrap).collect();
            assert!(after == before, "a rejected signed block changed persistent state");
        }
        assert_eq!(sync.process_blocks(vec![valid.clone()], 0), 1);
        assert_eq!(sync.storage.get("sys:last_executed_height").unwrap().as_deref(), Some("1"));
        let stored: Block = serde_json::from_str(&sync.storage.get("block_1").unwrap().unwrap()).unwrap();
        assert_eq!(stored.header.hash, valid.header.hash);
        assert_eq!(sync.process_blocks(vec![valid], 1), 1);
    }

    /// G3 S3: a follower's genesis commits version 0 like the producer's
    /// (here the fixture's `seed_state_tree`), so block 1 imports onto it and
    /// reaches the producer's root. The producer's root is computed apart,
    /// in memory, from the same genesis state (TA-1) plus block 1's one state
    /// change, the chain clock (G5 CL-2).
    #[test]
    fn a_follower_imports_block_one_onto_its_genesis_tree() {
        let sync = setup_sync("block_one_genesis_tree");
        let key = crypto::SigningKey::from_bytes(&[77; 32]);
        let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        set_validators(&sync, vec![(&proposer, 100)]);
        let executor = executor::Executor::new(sync.storage.clone());
        let mut block = Block::new_with_roots(
            1,
            1,
            "genesis".into(),
            vec![],
            proposer,
            String::new(),
            String::new(),
        );
        // Writes the proposer's account: genesis state on both sides.
        authenticate_block(&sync, &mut block);
        let genesis_state: std::collections::BTreeMap<String, Vec<u8>> = sync
            .storage
            .db
            .iterator(storage::rocksdb::IteratorMode::Start)
            .map(Result::unwrap)
            .filter(|(k, _)| storage::class::classify(k) == Some(storage::class::KeyClass::State))
            .map(|(k, v)| (String::from_utf8(k.to_vec()).unwrap(), v.to_vec()))
            .collect();
        let genesis_root = state_commit::genesis_root(&genesis_state).unwrap();
        seed_state_tree(&sync);
        assert_eq!(state_commit::root(&sync.storage, 0).unwrap(), genesis_root);
        let mut block_one_state = genesis_state;
        let (clock_key, clock_value) =
            executor::chain_clock_write(&sync.storage, 1, block.header.timestamp);
        block_one_state.insert(clock_key, clock_value.into_bytes());
        let producer_root = state_commit::genesis_root(&block_one_state).unwrap();
        block.header.state_root = hex::encode(producer_root.0);
        block.header.receipts_root = executor.receipts_root_for_block(&[]);
        rehash_block(&mut block);
        authenticate_block(&sync, &mut block);

        let before = sync.storage.db.state_class_stats();
        assert_eq!(sync.process_blocks(vec![block], 0), 1, "block 1 imported");
        // WG-1 runtime witness: the import wrote state only in its block.
        let after = sync.storage.db.state_class_stats();
        assert_eq!(after.state_outside_block, before.state_outside_block);
        assert_eq!(after.unclassified, before.unclassified);
        assert_eq!(
            state_commit::latest_version(&sync.storage).unwrap(),
            Some(1)
        );
        assert_eq!(state_commit::root(&sync.storage, 1).unwrap(), producer_root);
    }

    #[test]
    fn test_validate_block_hash_commits_execution_roots() {
        let sync = setup_sync("val_roots_hash");
        set_validators(&sync, vec![("node_1", 100)]);
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
            "r".to_string(),
        );
        let summary = executor::BlockExecutionSummary {
            executed_raws: Vec::new(),
            state_root: "actual_state".to_string(),
            receipts_root: "r".to_string(),
            gas_charged: 0,
            tx_count: 0,
            body: Vec::new(),
        };

        let err = sync.verify_execution_roots(&block, &summary).unwrap_err();
        assert!(err.contains("State root mismatch"));
    }

    // G3 FX-15: empty execution roots are always refused. The old
    // `sys:config:require_exec_roots` switch (and its env fallback) no longer
    // exists: even an explicit "0" cannot turn root binding off.
    #[test]
    fn empty_execution_roots_are_always_refused() {
        let sync = setup_sync("roots_empty_default");
        let _seed = sync.storage.seeding();
        sync.storage
            .put("sys:config:require_exec_roots", "0")
            .unwrap();
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
            executed_raws: Vec::new(),
            state_root: "s".to_string(),
            receipts_root: "r".to_string(),
            gas_charged: 0,
            tx_count: 0,
            body: Vec::new(),
        };
        let err = sync.verify_execution_roots(&block, &summary).unwrap_err();
        assert!(err.contains("empty state_root"), "{err}");
    }

    // SEC-#7 (cutover): with sys:config:require_exec_roots set, an empty-root
    // block is rejected; a non-empty matching block still passes.
    #[test]
    fn verify_execution_roots_rejects_empty_when_required() {
        let sync = setup_sync("roots_required");
        let _seed = sync.storage.seeding();
        sync.storage
            .put("sys:config:require_exec_roots", "1")
            .unwrap();
        let summary = executor::BlockExecutionSummary {
            executed_raws: Vec::new(),
            state_root: "s".to_string(),
            receipts_root: "r".to_string(),
            gas_charged: 0,
            tx_count: 0,
            body: Vec::new(),
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

    // Conflicting peer blocks cannot authorize rollback or a persistent halt.
    #[test]
    fn test_process_blocks_reorg_state_changing_orphan_is_rejected() {
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
        authenticate_block(&sync, &mut remote_b2);
        rehash_block(&mut remote_b2);
        let mut remote_b3 = Block::new(
            3,
            3,
            remote_b2.header.hash.clone(),
            vec!["y".to_string()],
            "node_2".to_string(),
        );
        authenticate_block(&sync, &mut remote_b3);
        rehash_block(&mut remote_b3);

        let new_height = sync.process_blocks(vec![remote_b2.clone(), remote_b3.clone()], 2);
        // Reorg refused: height does not advance, local block preserved.
        assert_eq!(new_height, 2);

        let stored_b2 = sync.storage.get("block_2").unwrap().unwrap();
        let stored_b2: Block = serde_json::from_str(&stored_b2).unwrap();
        assert_eq!(stored_b2.header.hash, local_b2.header.hash);

        // SEC (audit H-3 sibling): the unauthenticated state-changing reorg is REJECTED
        // (local chain kept intact, no rollback) but must NOT latch a persistent,
        // node-wide sync:halt_reason — that latch was a remote permanent-halt DoS a peer
        // could trigger with forged blocks. The node keeps serving; no operator
        // intervention required.
        let halt = sync.storage.get("sync:halt_reason").unwrap();
        assert!(
            halt.is_none(),
            "state-changing reorg must be rejected WITHOUT latching a persistent halt (remote DoS), got {:?}",
            halt
        );
    }

    // Stored empty blocks are not permission to delete canonical history.
    // The reorg_acceptance module also covers genuinely EXECUTED empty blocks.
    #[test]
    fn test_process_blocks_reorg_empty_orphan_is_rejected() {
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
            vec![],
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
        authenticate_block(&sync, &mut remote_b2);
        rehash_block(&mut remote_b2);
        let mut remote_b3 = Block::new(
            3,
            3,
            remote_b2.header.hash.clone(),
            vec!["y".to_string()],
            "node_2".to_string(),
        );
        authenticate_block(&sync, &mut remote_b3);
        rehash_block(&mut remote_b3);

        let new_height = sync.process_blocks(vec![remote_b2.clone(), remote_b3.clone()], 2);
        assert_eq!(new_height, 2);

        let stored_b2 = sync.storage.get("block_2").unwrap().unwrap();
        let stored_b2: Block = serde_json::from_str(&stored_b2).unwrap();
        assert_eq!(stored_b2.header.hash, local_b2.header.hash);
        assert!(sync.storage.get("block_3").unwrap().is_none());

        // Reject the peer batch, not all future sync activity.
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
        authenticate_block(&sync, &mut remote_b2);
        rehash_block(&mut remote_b2);
        let new_height = sync.process_blocks(vec![remote_b2], 2);
        assert_eq!(new_height, 2);

        let stored_b2 = sync.storage.get("block_2").unwrap().unwrap();
        let stored_b2: Block = serde_json::from_str(&stored_b2).unwrap();
        assert_eq!(stored_b2.header.hash, local_b2.header.hash);
    }

    // ---- TASK-#29: seed-anchor / N-peer tip agreement ----

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

    // N=2, two seeds certify DIFFERENT blocks at one height -> disagreement.
    #[test]
    fn test_tip_agreement_disagreement_refuses() {
        let sync = setup_sync("tip_agree_disagree");
        let tips = vec![
            qc_with_tip(&sync, 100, &"aa".repeat(32)),
            qc_with_tip(&sync, 100, &"bb".repeat(32)),
        ];
        let err = ChainSync::tip_agreement_decision(&tips, 2).unwrap_err();
        assert!(
            err.contains("disagree"),
            "expected disagreement, got: {err}"
        );
    }

    // B44: a seed one block behind agrees with the head (each tip is a
    // verified QC); before, it failed the pass.
    #[test]
    fn test_tip_agreement_a_tip_behind_agrees() {
        let sync = setup_sync("tip_agree_behind");
        let tips = vec![
            qc_with_tip(&sync, 100, &"aa".repeat(32)),
            qc_with_tip(&sync, 101, &"bb".repeat(32)),
        ];
        assert_eq!(
            ChainSync::tip_agreement_decision(&tips, 2),
            Ok((101, "bb".repeat(32)))
        );
    }

    // Three seeds, one further ahead: no two certify different blocks at one
    // height, so the head is the highest verified tip.
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
        assert_eq!(decision, Ok((200, "cc".repeat(32))));
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

        let _seed = sync.storage.seeding();
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

    // End-to-end-ish: with N=2 configured and no answering seed sessions,
    // sync_from_peers must REFUSE to advance (tip shortfall) and return the
    // local height.
    #[tokio::test]
    async fn test_sync_refuses_when_tip_agreement_unmet() {
        let member = |peer: &str, member: &str| network::SessionPeer {
            peer: peer.into(),
            member: Some(member.into()),
        };
        let sync = setup_sync("tip_refuse_sync").with_sessions(unreachable_sessions(vec![
            member("12D3KooWa", "validator_a"),
            member("12D3KooWb", "validator_b"),
        ]));
        sync.storage.put("latest_height", "5").unwrap();
        let _seed = sync.storage.seeding();
        sync.storage.put("sys:config:tip_agreement_n", "2").unwrap();
        // Two validator sessions, but neither answers, so zero verified tips
        // are gathered -> shortfall -> refuse.
        set_validators(&sync, vec![("validator_a", 100), ("validator_b", 100)]);

        let height = sync.sync_from_peers().await;
        assert_eq!(height, 5, "must not advance when tip agreement is unmet");
    }
}
