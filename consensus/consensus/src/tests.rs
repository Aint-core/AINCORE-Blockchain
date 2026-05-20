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
}
