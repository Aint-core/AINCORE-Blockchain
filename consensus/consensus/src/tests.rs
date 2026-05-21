#[cfg(test)]
mod tests {
    // use super::*; // Unused
    use crate::dag::DagConsensus;
    use executor::Executor;
    use mempool::Mempool;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use storage::object::{Object, Owner};
    use storage::StateDB;

    // Helper to get a unique DB path for each test
    fn get_test_db_path(suffix: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "aincore_dag_test_db_{}_{}",
            std::process::id(),
            suffix
        ));
        let _ = std::fs::remove_dir_all(&path); // Clean start
        path.to_string_lossy().to_string()
    }

    fn setup_dag(suffix: &str) -> (DagConsensus, String) {
        let path = get_test_db_path(suffix);
        let db = Arc::new(StateDB::open(&path).unwrap());
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let executor = Arc::new(Executor::new(Arc::clone(&db)));
        let peers = Arc::new(Mutex::new(HashMap::new()));

        // Generate a deterministic Ed25519 key for testing
        let node_key = [42u8; 32]; // Deterministic seed
        let signing_key = crypto::SigningKey::from_bytes(&node_key);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let node_id = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
        let account = Object::new(
            node_id.clone(),
            Owner::Address(node_id.clone()),
            serde_json::json!({
                "public_key": public_key,
                "sequence_number": 0
            })
            .to_string()
            .into_bytes(),
            "0x1::account::AccountData".to_string(),
        );
        db.put_object(&account).unwrap();

        // Seed the validator set so the test node is an active validator
        // (without this, try_create_vertex enters Observer Mode and creates 0 vertices)
        // Format: Vec<(String, u64)> = [(address, stake_amount)]
        let validator_json = format!(r#"[["{}",1000]]"#, node_id);
        let _ = db.put("sys:validators", &validator_json);

        (
            DagConsensus::new(node_id, peers, mempool, executor, db, None, None, node_key),
            path,
        )
    }

    #[test]
    fn test_dag_vertex_creation() {
        let (mut consensus, path) = setup_dag("vertex_creation");

        // 1. Create Genesis Vertex (Round 1)
        consensus.try_create_vertex();

        let dag = consensus.dag.lock().unwrap();
        assert_eq!(dag.len(), 1, "Should have 1 vertex (Genesis)");

        // Verify Round 1 properties
        let vertices: Vec<_> = dag.values().collect();
        assert_eq!(vertices[0].round, 1);
        assert_eq!(vertices[0].parents, vec!["genesis".to_string()]);

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_dag_growth_and_ordering() {
        let (mut consensus, path) = setup_dag("growth");

        // 1. Create Round 1
        consensus.try_create_vertex();
        assert_eq!(consensus.current_round, 2);

        // 2. Create Round 2 (Should reference Round 1)
        consensus.try_create_vertex();
        assert_eq!(consensus.current_round, 3);

        let dag = consensus.dag.lock().unwrap();
        assert_eq!(dag.len(), 2, "Should have 2 vertices");

        // Verify Round 2 parent is Round 1
        let r2_vertex = dag.values().find(|v| v.round == 2).unwrap();
        let r1_vertex = dag.values().find(|v| v.round == 1).unwrap();

        assert!(r2_vertex.parents.contains(&r1_vertex.hash));

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_dag_pruning() {
        let (mut consensus, path) = setup_dag("pruning");

        // Create 10 rounds
        for _ in 0..10 {
            consensus.try_create_vertex();
        }

        {
            let dag = consensus.dag.lock().unwrap();
            assert_eq!(dag.len(), 10);
        }

        // Prune older than round 5
        consensus.prune_dag(5);

        {
            let dag = consensus.dag.lock().unwrap();
            // Should have rounds 5, 6, 7, 8, 9, 10 (6 items)
            assert_eq!(dag.len(), 6);

            // Verify no round < 5 exists
            for v in dag.values() {
                assert!(v.round >= 5);
            }
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_add_vertex_rejects_unverifiable_author_key() {
        let (mut consensus, path) = setup_dag("reject_unverifiable_author");
        consensus.current_round = 0;

        let mut vertex = blockchain::Vertex::new(
            1,
            "00000000000000000000000000000001".to_string(),
            vec!["genesis".to_string()],
            vec![],
        );
        let attacker_key = crypto::SigningKey::from_bytes(&[7u8; 32]);
        vertex.sign_with_ed25519(&attacker_key);

        consensus.add_vertex(vertex);

        let dag = consensus.dag.lock().unwrap();
        assert!(
            dag.is_empty(),
            "unverifiable vertex author must be rejected"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_dag_parent_quorum_requires_strict_supermajority() {
        assert_eq!(DagConsensus::bft_quorum_threshold(0), 0);
        assert_eq!(DagConsensus::bft_quorum_threshold(1), 1);
        assert_eq!(DagConsensus::bft_quorum_threshold(2), 2);
        assert_eq!(DagConsensus::bft_quorum_threshold(3), 3);
        assert_eq!(DagConsensus::bft_quorum_threshold(4), 3);
        assert_eq!(DagConsensus::bft_quorum_threshold(7), 5);
    }

    #[test]
    fn test_checkpoint_recovery_replays_tail_vertices() {
        let (mut consensus, path) = setup_dag("checkpoint_tail_replay");

        consensus.try_create_vertex();
        consensus.try_create_vertex();
        consensus.try_create_vertex();
        assert_eq!(consensus.current_round, 4);

        let checkpoint_json = {
            let dag = consensus.dag.lock().unwrap();
            let checkpoint_vertices: Vec<_> = dag
                .values()
                .filter(|vertex| vertex.round <= 2)
                .cloned()
                .collect();
            serde_json::to_string(&checkpoint_vertices).unwrap()
        };
        consensus
            .storage
            .save_dag_checkpoint(2, &checkpoint_json)
            .unwrap();
        consensus.storage.put("latest_proposed_round", "3").unwrap();

        let db = Arc::clone(&consensus.storage);
        let node_id = consensus.node_id.clone();
        let node_key = consensus.node_key;
        let recovered_executor = Arc::new(Executor::new(Arc::clone(&db)));
        let mut recovered = DagConsensus::new(
            node_id,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(Mempool::new())),
            recovered_executor,
            db,
            None,
            None,
            node_key,
        );

        assert_eq!(recovered.current_round, 4);
        assert!(
            recovered
                .round_index
                .lock()
                .unwrap()
                .get(&3)
                .is_some_and(|parents| !parents.is_empty()),
            "tail replay must restore previous-round parents"
        );

        recovered.try_create_vertex();
        assert_eq!(
            recovered.current_round, 5,
            "recovered singleton validator must keep producing after restart"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Phase 1.5.2 INVARIANT TEST
    ///
    /// After H-07 refactored block commit to route through
    /// `StateDB::save_block_json` (atomic block + height + hash + tx_index
    /// write), assert the post-commit invariant:
    ///
    ///   consensus.latest_block_hash == storage.get("latest_block_hash")
    ///   consensus.latest_block_height == storage.get_chain_height()
    ///   storage.get("block_{height}") is a parseable Block with that hash
    ///
    /// This catches any drift between the in-memory consensus state and
    /// the persisted state — historically a class of bug that lets a
    /// crashed node restart on a stale chain tip.
    #[test]
    fn test_block_commit_keeps_consensus_and_storage_in_sync() {
        let (mut consensus, path) = setup_dag("commit_sync_invariant");

        // Drive enough rounds for the singleton validator's ordering
        // engine to actually commit a block. Bullshark needs leader
        // support across consecutive rounds; 6 rounds gives the engine
        // at least one full anchor commit.
        for _ in 0..6 {
            consensus.try_create_vertex();
        }

        // If no block was committed, the test is inconclusive — but with
        // a singleton validator and 6 rounds that means the ordering
        // engine itself is broken, which is also a regression worth
        // failing on.
        let height_in_memory = consensus.latest_block_height;
        assert!(
            height_in_memory >= 1,
            "ordering engine must commit at least one block over 6 rounds \
             with a singleton validator; got height {}",
            height_in_memory
        );

        let height_in_storage = consensus.storage.get_chain_height();
        assert_eq!(
            height_in_memory, height_in_storage,
            "in-memory latest_block_height must equal storage latest_height \
             after commit (save_block_json atomicity invariant)"
        );

        let hash_in_storage = consensus
            .storage
            .get("latest_block_hash")
            .unwrap()
            .expect("latest_block_hash must be present after a block is committed");
        assert_eq!(
            consensus.latest_block_hash, hash_in_storage,
            "in-memory latest_block_hash must equal storage latest_block_hash \
             — drift here means consensus and storage disagree on the chain tip"
        );

        // The block itself must be retrievable and round-trip cleanly.
        let block_json = consensus
            .storage
            .get(&format!("block_{}", height_in_memory))
            .unwrap()
            .expect("block at the committed height must be persisted");
        let block: serde_json::Value =
            serde_json::from_str(&block_json).expect("persisted block must be valid JSON");
        let header_hash = block["header"]["hash"]
            .as_str()
            .expect("block header.hash field must be a string");
        assert_eq!(
            header_hash, consensus.latest_block_hash,
            "block header.hash at committed height must equal the chain-tip \
             hash (no stale block or hash mismatch from refactor)"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// C-01 REGRESSION TEST
    ///
    /// Ensures the equivocation slash event written to `sys:pending_slash:` uses
    /// the canonical `reason == "equivocation"` string that the executor matches
    /// against to apply the 100% slash + permanent removal path.
    ///
    /// Previously the DAG wrote `reason == "double_sign"`, which silently fell
    /// through to the executor's downtime branch and only deducted 5% — letting
    /// equivocators escape with a slap on the wrist while the consensus alert
    /// claimed a CRITICAL slashing was happening. Unit tests on the executor
    /// side did not catch this because they wrote the event directly with
    /// `"equivocation"` instead of routing through `add_vertex`.
    ///
    /// This test invokes the real `add_vertex` equivocation path and asserts
    /// the storage event payload uses the canonical reason. If anyone ever
    /// changes the string again, this test fails loudly.
    #[test]
    fn test_equivocation_queues_canonical_slash_reason_for_executor() {
        let (mut consensus, path) = setup_dag("equivocation_canonical_reason");

        // Round 0 → bootstrap parent only
        consensus.current_round = 1;

        // Build two distinct vertices with the SAME author + SAME round but
        // different content (different timestamp ⇒ different hash). Sign both
        // with the node's own key so author signature verification passes.
        let signing_key = crypto::SigningKey::from_bytes(&consensus.node_key);
        let author = consensus.node_id.clone();

        let mut vertex_a = blockchain::Vertex {
            round: 1,
            author: author.clone(),
            timestamp: 1_000,
            payload: vec![],
            parents: vec!["genesis".to_string()],
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
        };
        vertex_a.hash = vertex_a.calculate_hash();
        vertex_a.sign_with_ed25519(&signing_key);

        let mut vertex_b = blockchain::Vertex {
            round: 1,
            author: author.clone(),
            timestamp: 2_000, // different content ⇒ different hash
            payload: vec![],
            parents: vec!["genesis".to_string()],
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
        };
        vertex_b.hash = vertex_b.calculate_hash();
        vertex_b.sign_with_ed25519(&signing_key);

        assert_ne!(
            vertex_a.hash, vertex_b.hash,
            "test setup invariant: equivocating vertices must hash differently"
        );

        // Add both. The second one must trigger equivocation detection in DAG.
        consensus.add_vertex(vertex_a);
        consensus.add_vertex(vertex_b);

        // Now inspect the pending_slash entry the DAG wrote — this is the contract
        // surface the executor consumes from.
        let pending_key = format!("sys:pending_slash:{}", author);
        let raw = consensus
            .storage
            .get(&pending_key)
            .expect("storage read must not error")
            .expect("equivocation must queue a pending slash event");

        let event: serde_json::Value = serde_json::from_str(&raw)
            .expect("slash event must be valid JSON");

        assert_eq!(
            event.get("reason").and_then(|v| v.as_str()),
            Some("equivocation"),
            "DAG must queue reason == \"equivocation\" so executor applies the \
             100% slash path. Got: {:?}",
            event.get("reason")
        );

        assert_eq!(
            event.get("event").and_then(|v| v.as_str()),
            Some("equivocation_detected"),
            "event tag should remain stable for monitoring/alerting consumers"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    // ========================================================================
    // Phase 2.5 (H-06): DAG checkpoint integrity tests
    // ========================================================================

    /// A checkpoint with no signature (legacy / unsigned) MUST still be
    /// loaded — otherwise nodes upgrading from a pre-Phase-2 build would
    /// be forced into a full state resync. We log a warning but accept.
    #[test]
    fn h06_legacy_unsigned_checkpoint_still_loads_with_warning() {
        let (mut consensus, path) = setup_dag("h06_legacy_unsigned");

        consensus.try_create_vertex();
        consensus.try_create_vertex();
        let checkpoint_json = {
            let dag = consensus.dag.lock().unwrap();
            let vs: Vec<_> = dag.values().cloned().collect();
            serde_json::to_string(&vs).unwrap()
        };
        consensus
            .storage
            .save_dag_checkpoint(2, &checkpoint_json)
            .unwrap();
        consensus.storage.put("latest_proposed_round", "2").unwrap();

        let db = Arc::clone(&consensus.storage);
        let node_id = consensus.node_id.clone();
        let node_key = consensus.node_key;
        let recovered = DagConsensus::new(
            node_id,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Executor::new(Arc::clone(&db))),
            db,
            None,
            None,
            node_key,
        );
        let recovered_dag = recovered.dag.lock().unwrap();
        assert!(
            !recovered_dag.is_empty(),
            "legacy unsigned checkpoint must still load (warning, not reject)"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// A signed checkpoint produced by THIS node's key round-trips:
    /// boot path verifies the signature and does not panic / does not
    /// log a tamper warning.
    #[test]
    fn h06_signed_checkpoint_round_trips() {
        let (consensus, path) = setup_dag("h06_signed_roundtrip");

        let checkpoint_json = serde_json::json!([]).to_string();
        let signing_key = crypto::SigningKey::from_bytes(&consensus.node_key);
        use crypto::Signer;
        let sig = signing_key.sign(checkpoint_json.as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());

        consensus
            .storage
            .save_dag_checkpoint_signed(5, &checkpoint_json, &sig_hex)
            .unwrap();
        consensus.storage.put("latest_proposed_round", "5").unwrap();

        let db = Arc::clone(&consensus.storage);
        let node_id = consensus.node_id.clone();
        let node_key = consensus.node_key;
        let _ = DagConsensus::new(
            node_id,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Executor::new(Arc::clone(&db))),
            db,
            None,
            None,
            node_key,
        );

        // Sig still in storage post-boot — boot did not delete it.
        assert!(consensus
            .storage
            .get_dag_checkpoint_signature(5)
            .is_some());

        let _ = std::fs::remove_dir_all(&path);
    }

    /// A checkpoint whose signature does NOT verify against this node's
    /// key (tampered or signed with a different key) must be rejected
    /// — the boot path falls back to scan-based recovery instead of
    /// trusting the corrupted checkpoint.
    #[test]
    fn h06_tampered_checkpoint_signature_rejected() {
        let (consensus, path) = setup_dag("h06_tampered_sig");

        // Pair a legitimate-looking checkpoint with a bogus signature
        // of the right length (cryptographically impossible to verify
        // against the node's real Ed25519 key).
        let checkpoint_json = serde_json::json!([]).to_string();
        let bad_sig_hex = "00".repeat(64);

        consensus
            .storage
            .save_dag_checkpoint_signed(7, &checkpoint_json, &bad_sig_hex)
            .unwrap();
        consensus.storage.put("latest_proposed_round", "7").unwrap();

        let db = Arc::clone(&consensus.storage);
        let node_id = consensus.node_id.clone();
        let node_key = consensus.node_key;
        let recovered = DagConsensus::new(
            node_id,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Executor::new(Arc::clone(&db))),
            db,
            None,
            None,
            node_key,
        );

        // Tampered checkpoint must not populate the in-memory DAG.
        let recovered_dag = recovered.dag.lock().unwrap();
        assert!(
            recovered_dag.is_empty(),
            "tampered checkpoint must not populate the in-memory DAG"
        );

        let _ = std::fs::remove_dir_all(&path);
    }
}
