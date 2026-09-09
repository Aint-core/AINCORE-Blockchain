#[cfg(test)]
#[allow(clippy::module_inception)]
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
        // B4: the DAG parent quorum is now stake-weighted via qc::stake_quorum_met
        // (strict > 2/3 of TOTAL stake), the same predicate as commit + QC verify.
        use crate::qc::stake_quorum_met;
        assert!(!stake_quorum_met(2, 3)); // exactly 2/3 fails (strict)
        assert!(stake_quorum_met(3, 4)); // 3/4 passes
        assert!(!stake_quorum_met(1, 3)); // 1/3 fails
                                          // Stake, not count: a 60/100 holder is not a quorum; 67/100 is.
        assert!(!stake_quorum_met(60, 100));
        assert!(stake_quorum_met(67, 100));
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

    /// ChainSync reload regression.
    ///
    /// A synced observer can advance `latest_height` by thousands of blocks
    /// without adding the corresponding live DAG vertices. If
    /// `reload_chain_tip()` only refreshes height/hash, `current_round` stays
    /// near genesis and the PWN-002 jump guard rejects every live peer vertex
    /// as "far future". The reload must therefore also adopt the synced block
    /// round from the persisted tip.
    ///
    /// AUDIT-B3: the adoption is now quorum-capped, because a blind
    /// `current_round = block.round + 1` wedged a live 3-node cluster (this
    /// node's DAG lacked the tip round's vertices, so it proposed at a round
    /// whose predecessor could never reach parent quorum, and stopped producing
    /// permanently). The catch-up FLOOR is what this test exercises: with a
    /// 12_345-round gap and an empty DAG, quorum_round is 0, so the node lands
    /// at `tip_next - MAX_ROUND_JUMP/2` — far enough forward that live vertices
    /// are still accepted by the jump guard, without racing past the DAG.
    #[test]
    fn test_reload_chain_tip_updates_current_round_from_synced_block() {
        let (mut consensus, path) = setup_dag("reload_round_from_synced_tip");

        let synced_block = blockchain::Block::new(
            42,
            12_345,
            "genesis".to_string(),
            vec![],
            "validator".into(),
        );
        let block_json = serde_json::to_string(&synced_block).unwrap();
        consensus.storage.save_block_json(42, &block_json).unwrap();

        assert_eq!(consensus.latest_block_height, 0);
        assert_eq!(consensus.current_round, 1);

        consensus.reload_chain_tip();

        assert_eq!(consensus.latest_block_height, 42);
        // Quorum-capped: the DAG is empty here, so the catch-up floor applies.
        let expected = 12_346u64 - (5_000u64);
        assert_eq!(
            consensus.current_round, expected,
            "reload must land on the catch-up floor, not blindly on tip+1"
        );
        assert!(
            consensus.current_round + 10_000 >= 12_346,
            "must stay inside the PWN-002 jump window so live vertices are accepted"
        );
        assert_eq!(
            consensus
                .storage
                .get("latest_proposed_round")
                .unwrap()
                .as_deref(),
            Some(expected.to_string().as_str())
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
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
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
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
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

        // RE-AUDIT HIGH (slash determinism): the DAG no longer queues a local
        // `sys:pending_slash` — that made the slash a function of WHICH node saw
        // both vertices. The contract surface is now the durable, self-contained
        // evidence row the block proposer carries (executor::collect_slash_evidence)
        // and every node verifies before applying.
        let raw = consensus
            .storage
            .get(&format!("sys:equiv_seen:{}:1", author))
            .expect("storage read must not error")
            .expect("equivocation must record a self-contained evidence row");
        let ev: serde_json::Value =
            serde_json::from_str(&raw).expect("evidence row must be valid JSON");
        assert_eq!(ev["offender"].as_str(), Some(author.as_str()));
        assert_eq!(ev["round"].as_u64(), Some(1));
        assert!(ev.get("vertex_a").is_some() && ev.get("vertex_b").is_some());
        assert_ne!(ev["vertex_a"]["hash"], ev["vertex_b"]["hash"]);
        assert!(consensus
            .storage
            .get(&format!("validator:jailed:{}", author))
            .unwrap()
            .is_some());
        assert!(
            consensus
                .storage
                .get(&format!("sys:pending_slash:{}", author))
                .unwrap()
                .is_none(),
            "no local pending_slash may be written — slashes come from block evidence"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    // ========================================================================
    // Phase 2.5 (H-06): DAG checkpoint integrity tests
    // ========================================================================

    /// Phase 4.A2 — Unsigned checkpoint MUST be rejected.
    ///
    /// The previous policy ("legacy unsigned → accept with warning") was an
    /// attack vector: an operator-level adversary with storage write access
    /// could DELETE the signature blob to forge a checkpoint. Phase 4.A2
    /// closes that loophole — a node booting against unsigned checkpoint
    /// data now falls back to scan_vertices (in-memory DAG stays empty
    /// because we never wrote individual vertex_:* rows in this test).
    #[test]
    fn h06_a2_unsigned_checkpoint_rejected() {
        let (mut consensus, path) = setup_dag("h06_a2_unsigned_rejected");

        consensus.try_create_vertex();
        consensus.try_create_vertex();
        let checkpoint_json = {
            let dag = consensus.dag.lock().unwrap();
            let vs: Vec<_> = dag.values().cloned().collect();
            serde_json::to_string(&vs).unwrap()
        };
        // Save the checkpoint but NOT the signature — simulates an attacker
        // (or a stale pre-Phase-2 install) deleting the signature blob.
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
            recovered_dag.is_empty(),
            "Phase 4.A2: unsigned checkpoint MUST be rejected — \
             in-memory DAG must NOT be populated from unsigned data"
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
        assert!(consensus.storage.get_dag_checkpoint_signature(5).is_some());

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Phase 2.8 (M-08): validator cache is populated on first read and
    /// returned for subsequent reads without re-parsing storage. After
    /// a block commit, the cache is invalidated and the next read
    /// reflects any updated validator set.
    #[test]
    fn m08_validator_cache_serves_repeated_reads_and_refreshes_on_commit() {
        let (consensus, path) = setup_dag("m08_validator_cache");

        // First read primes the cache.
        let first = consensus.get_validator_set();
        assert!(!first.is_empty(), "test setup seeded a validator");
        let seeded_node = first[0].clone();

        // Mutate storage behind the cache's back. With a naïve
        // implementation this would IMMEDIATELY change the result —
        // but the M-08 cache must keep returning the pre-mutation
        // value until the next legitimate invalidation point.
        let phantom_validator = format!(
            "{}deadbeefdeadbeefdeadbeefdeadbeef",
            &seeded_node[..0] // empty prefix; just construct a distinct 32-char hex
        );
        let mutated_json = format!(
            r#"[["{}",1000],["{}",1000]]"#,
            seeded_node, "deadbeefdeadbeefdeadbeefdeadbeef"
        );
        consensus
            .storage
            .put("sys:validators", &mutated_json)
            .unwrap();

        // Cache hit: still the original set.
        let cached_second_read = consensus.get_validator_set();
        assert_eq!(
            cached_second_read.len(),
            first.len(),
            "cache must not reflect the storage mutation until invalidation"
        );

        // Drive a commit to trigger invalidation. We can't easily
        // synthesise a block commit in this unit test, so call the
        // public invalidator directly — same code path the commit
        // takes.
        consensus.invalidate_validators_cache();

        let post_invalidation = consensus.get_validator_set();
        assert!(
            post_invalidation.len() > first.len()
                || post_invalidation.contains(&"deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
            "after invalidation, cache must re-read storage and reflect the new set"
        );

        let _ = phantom_validator;
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

    // ── Phase 5B.1 / PWN-001: Vertex hash integrity ──────────────────────

    /// Vertex whose self-declared `hash` does NOT match a freshly recomputed
    /// `calculate_hash()` must be rejected, even when the Ed25519 signature
    /// over that declared hash is valid. Without this guard a malicious
    /// validator could emit two vertices with the same `hash` + `signature`
    /// but different `payload` / `parents` / `timestamp`, splitting state
    /// across honest peers.
    #[test]
    fn pwn001_vertex_with_tampered_hash_field_is_rejected() {
        use blockchain::Vertex;
        use crypto::SigningKey;

        let (mut dag, path) = setup_dag("pwn001_tampered_hash");

        // Build a real vertex authored by THIS node so the validator-set
        // check passes (this node is registered in setup_dag).
        let signing_key = SigningKey::from_bytes(&dag.node_key);
        let mut vertex = Vertex {
            round: 1,
            author: dag.node_id.clone(),
            parents: vec![],
            payload: vec!["tx_a".to_string()],
            timestamp: 1,
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
        };
        // Tamper: set hash to garbage, then sign over the garbage hash.
        vertex.hash = "deadbeef".repeat(8);
        vertex.sign_with_ed25519(&signing_key);

        let dag_len_before = dag.dag.lock().unwrap().len();
        dag.add_vertex(vertex);
        let dag_len_after = dag.dag.lock().unwrap().len();

        assert_eq!(
            dag_len_before, dag_len_after,
            "PWN-001: vertex with tampered hash must NOT enter the DAG"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// PWN-002: a vertex with round vastly larger than current_round must
    /// be rejected, preventing u64 fast-forward + overflow halt.
    #[test]
    fn pwn002_round_overflow_attack_rejected() {
        use blockchain::Vertex;
        use crypto::SigningKey;

        let (mut dag, path) = setup_dag("pwn002_round_overflow");

        // Build a vertex with round = u64::MAX - 1 authored by this node.
        let signing_key = SigningKey::from_bytes(&dag.node_key);
        let mut vertex = Vertex {
            round: u64::MAX - 1,
            author: dag.node_id.clone(),
            parents: vec![],
            payload: vec!["malicious".to_string()],
            timestamp: 1,
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
        };
        vertex.hash = vertex.calculate_hash();
        vertex.sign_with_ed25519(&signing_key);

        let round_before = dag.current_round;
        dag.add_vertex(vertex);

        assert_eq!(
            dag.current_round, round_before,
            "PWN-002: vertex with far-future round must NOT advance current_round"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Observer nodes must not locally order and commit blocks from incoming
    /// validator DAG vertices. They are allowed to store vertices and follow
    /// rounds, but block production belongs to active validators only. This
    /// protects observer peers from creating a private fork and later failing
    /// sync with parent-hash mismatches.
    #[test]
    fn observer_add_vertex_does_not_commit_local_blocks() {
        use blockchain::Vertex;
        use crypto::{derive_address, SigningKey};

        let (mut dag, path) = setup_dag("observer_no_local_commit");

        let remote_key_bytes: [u8; 32] = [0x33; 32];
        let remote_sk = SigningKey::from_bytes(&remote_key_bytes);
        let remote_vk = remote_sk.verifying_key();
        let remote_pubkey_hex = hex::encode(remote_vk.to_bytes());
        let remote_addr = derive_address(remote_vk.as_bytes()).expect("derive remote addr");

        let remote_account = Object::new(
            remote_addr.clone(),
            Owner::Address(remote_addr.clone()),
            serde_json::json!({
                "public_key": remote_pubkey_hex,
                "sequence_number": 0
            })
            .to_string()
            .into_bytes(),
            "0x1::account::AccountData".to_string(),
        );
        dag.storage.put_object(&remote_account).unwrap();

        // Make the local node an observer by removing it from the active
        // validator set. The remote author remains a valid validator.
        let validator_json = serde_json::to_string(&vec![(remote_addr.clone(), 1000u64)]).unwrap();
        dag.storage.put("sys:validators", &validator_json).unwrap();
        dag.invalidate_validators_cache();

        let mut parents = vec!["genesis".to_string()];
        for round in 1..=4 {
            let mut vertex = Vertex::new(round, remote_addr.clone(), parents.clone(), vec![]);
            vertex.sign_with_ed25519(&remote_sk);
            parents = vec![vertex.hash.clone()];
            dag.add_vertex(vertex);
        }

        assert_eq!(
            dag.latest_block_height, 0,
            "observer must not commit local blocks from remote validator vertices"
        );
        assert!(
            dag.storage.get("latest_height").unwrap().is_none(),
            "observer must not write latest_height from local ordering"
        );
        assert_eq!(
            dag.dag.lock().unwrap().len(),
            4,
            "observer should still retain incoming vertices for visibility"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    // ── Phase 3 / H-02: Downtime attestation gossip ──────────────────────

    /// Valid remote attestation (correct sig + known validator) is stored.
    #[test]
    fn test_h02_valid_remote_attestation_stored() {
        use crypto::{derive_address, Signer, SigningKey};

        let (mut dag, path) = setup_dag("h02_valid_attest");

        // Create a fake "remote" validator key pair.
        let remote_key_bytes: [u8; 32] = [0xBB; 32];
        let remote_sk = SigningKey::from_bytes(&remote_key_bytes);
        let remote_vk = remote_sk.verifying_key();
        let remote_pubkey_hex = hex::encode(remote_vk.to_bytes());
        let remote_addr = derive_address(remote_vk.as_bytes()).expect("derive_address");

        // Register both the remote reporter AND the offender as validators
        // so the post-Phase-5B.6 checks pass (offender must be a validator
        // to be eligible for downtime slashing).
        let offender = "deadbeefdeadbeef".to_string();
        let vset: Vec<(String, u64)> =
            vec![(remote_addr.clone(), 1000u64), (offender.clone(), 1000u64)];
        dag.storage
            .put("sys:validators", &serde_json::to_string(&vset).unwrap())
            .unwrap();
        dag.invalidate_validators_cache();

        // Build and sign an attestation as the remote validator would.
        let epoch: u64 = 1;
        let round: u64 = 100;
        let canonical = format!("{}:{}:{}:{}", offender, epoch, remote_addr, round);
        let sig = remote_sk.sign(canonical.as_bytes());
        let sig_hex = hex::encode(sig.to_bytes());

        let payload = serde_json::json!({
            "offender": offender,
            "epoch": epoch,
            "reporter": remote_addr,
            "reporter_pubkey": remote_pubkey_hex,
            "round": round,
            "rounds_missed": 120u64,
            "signature": sig_hex,
        });

        let content = payload.to_string();
        dag.handle_message(&format!("DOWNTIME_ATTEST:{}", content));

        // Attestation must now be in storage.
        let key = format!(
            "sys:downtime_attestation:{}:{}:{}",
            offender, epoch, remote_addr
        );
        let stored = dag
            .storage
            .get(&key)
            .expect("db ok")
            .expect("must be stored");
        assert!(stored.contains(&offender));

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Phase 5B.6 / SEC-N03: an attestation whose `offender` is NOT in
    /// the validator set must be rejected — otherwise a single Byzantine
    /// reporter can spam attestations against arbitrary addresses and
    /// blow up `sys:downtime_attestation:` storage.
    #[test]
    fn sec_n03_offender_not_in_validator_set_rejected() {
        use crypto::{derive_address, Signer, SigningKey};

        let (mut dag, path) = setup_dag("sec_n03_unknown_offender");

        let remote_key_bytes: [u8; 32] = [0xEE; 32];
        let remote_sk = SigningKey::from_bytes(&remote_key_bytes);
        let remote_vk = remote_sk.verifying_key();
        let remote_pubkey_hex = hex::encode(remote_vk.to_bytes());
        let remote_addr = derive_address(remote_vk.as_bytes()).expect("derive");

        // Reporter IS in validator set, but offender is NOT.
        let vset: Vec<(String, u64)> = vec![(remote_addr.clone(), 1000u64)];
        dag.storage
            .put("sys:validators", &serde_json::to_string(&vset).unwrap())
            .unwrap();
        dag.invalidate_validators_cache();

        let offender = "ghost_offender_not_a_validator".to_string();
        let epoch = 1u64;
        let round = 50u64;
        let canonical = format!("{}:{}:{}:{}", offender, epoch, remote_addr, round);
        let sig = remote_sk.sign(canonical.as_bytes());

        let payload = serde_json::json!({
            "offender": offender,
            "epoch": epoch,
            "reporter": remote_addr,
            "reporter_pubkey": remote_pubkey_hex,
            "round": round,
            "rounds_missed": 130u64,
            "signature": hex::encode(sig.to_bytes()),
        });
        dag.handle_message(&format!("DOWNTIME_ATTEST:{}", payload));

        let key = format!(
            "sys:downtime_attestation:{}:{}:{}",
            offender, epoch, remote_addr
        );
        assert!(
            dag.storage.get(&key).unwrap().is_none(),
            "SEC-N03: attestation against non-validator offender must NOT be stored"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Phase 5B.6 / L-05: a reporter cannot attest its own downtime
    /// (reporter == offender). Otherwise a Byzantine validator gets a
    /// "free" attestation slot toward quorum.
    #[test]
    fn l05_self_attestation_rejected() {
        use crypto::{derive_address, Signer, SigningKey};

        let (mut dag, path) = setup_dag("l05_self_attest");

        let key_bytes: [u8; 32] = [0xAB; 32];
        let sk = SigningKey::from_bytes(&key_bytes);
        let vk = sk.verifying_key();
        let pubkey_hex = hex::encode(vk.to_bytes());
        let addr = derive_address(vk.as_bytes()).expect("derive");

        let vset: Vec<(String, u64)> = vec![(addr.clone(), 1000u64)];
        dag.storage
            .put("sys:validators", &serde_json::to_string(&vset).unwrap())
            .unwrap();
        dag.invalidate_validators_cache();

        // reporter == offender
        let epoch = 1u64;
        let round = 50u64;
        let canonical = format!("{}:{}:{}:{}", addr, epoch, addr, round);
        let sig = sk.sign(canonical.as_bytes());

        let payload = serde_json::json!({
            "offender": addr,
            "epoch": epoch,
            "reporter": addr,
            "reporter_pubkey": pubkey_hex,
            "round": round,
            "rounds_missed": 130u64,
            "signature": hex::encode(sig.to_bytes()),
        });
        dag.handle_message(&format!("DOWNTIME_ATTEST:{}", payload));

        let key = format!("sys:downtime_attestation:{}:{}:{}", addr, epoch, addr);
        assert!(
            dag.storage.get(&key).unwrap().is_none(),
            "L-05: self-attestation must NOT be stored"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Attestation with wrong signature is rejected.
    #[test]
    fn test_h02_invalid_signature_rejected() {
        use crypto::{derive_address, SigningKey};

        let (mut dag, path) = setup_dag("h02_bad_sig");

        let remote_key_bytes: [u8; 32] = [0xCC; 32];
        let remote_sk = SigningKey::from_bytes(&remote_key_bytes);
        let remote_vk = remote_sk.verifying_key();
        let remote_pubkey_hex = hex::encode(remote_vk.to_bytes());
        let remote_addr = derive_address(remote_vk.as_bytes()).expect("derive");

        let vset: Vec<(String, u64)> = vec![(remote_addr.clone(), 1000u64)];
        dag.storage
            .put("sys:validators", &serde_json::to_string(&vset).unwrap())
            .unwrap();
        dag.invalidate_validators_cache();

        // Wrong signature — 64 zeros.
        let bad_sig_hex = hex::encode([0u8; 64]);

        let payload = serde_json::json!({
            "offender": "aabbccdd",
            "epoch": 1u64,
            "reporter": remote_addr,
            "reporter_pubkey": remote_pubkey_hex,
            "round": 50u64,
            "rounds_missed": 101u64,
            "signature": bad_sig_hex,
        });

        dag.handle_message(&format!("DOWNTIME_ATTEST:{}", payload));

        // Must NOT be stored.
        let key = format!("sys:downtime_attestation:aabbccdd:1:{}", remote_addr);
        assert!(
            dag.storage.get(&key).unwrap().is_none(),
            "bad sig must be rejected"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    // ── Phase 4.B2: H-02 multi-node integration ──────────────────────────

    /// Phase 4.B2 — Logic-level simulation of cross-node attestation flow.
    ///
    /// **HONEST SCOPE OF THIS TEST:**
    ///   This is a LOGIC-LEVEL integration test, NOT a real network
    ///   integration test. It proves:
    ///     ✅ Message format, signing, signature verification, storage,
    ///        validator-set check, BFT quorum math, executor promotion
    ///        all work correctly across 3 in-process DagConsensus instances.
    ///
    ///   It does NOT prove:
    ///     ❌ libp2p Gossipsub serialization/transport
    ///     ❌ TCP fallback path
    ///     ❌ Network partition / heal scenarios
    ///     ❌ Real broadcasting via `p2p_tx` channel
    ///
    ///   For full network integration, a separate `tests/h02_libp2p_*`
    ///   harness spinning up real libp2p nodes is required (tracked as
    ///   Phase 4+ work).
    ///
    /// Scenario:
    ///   3 validators A, B, C. Offender X is offline. Each validator
    ///   independently signs an attestation. Attestations are passed
    ///   via DIRECT `handle_message()` calls (simulating successful
    ///   gossip). After exchange, every node has 3 distinct reporter
    ///   attestations → executor promotes to pending slash on quorum.
    ///
    ///   NOTE (protocol v2): this exercises a NON-LIVE path. Downtime is
    ///   attested but not slashed; promote_downtime_attestations_to_slash has
    ///   no production caller. Retained for a future deterministic protocol.
    #[test]
    fn test_h02_b2_simulated_cross_node_attestation_reaches_quorum() {
        use crypto::{derive_address, Signer, SigningKey};

        // Helper: spin up an isolated DagConsensus node with a given key seed.
        fn spawn_node(seed_byte: u8, suffix: &str) -> (DagConsensus, String, String) {
            let path = get_test_db_path(suffix);
            let db = Arc::new(StateDB::open(&path).unwrap());
            let mempool = Arc::new(Mutex::new(Mempool::new()));
            let executor = Arc::new(Executor::new(Arc::clone(&db)));
            let peers = Arc::new(Mutex::new(HashMap::new()));

            let node_key = [seed_byte; 32];
            let sk = SigningKey::from_bytes(&node_key);
            let vk = sk.verifying_key();
            let node_id = derive_address(vk.as_bytes()).unwrap();

            let consensus = DagConsensus::new(
                node_id.clone(),
                peers,
                mempool,
                executor,
                db,
                None,
                None,
                node_key,
            );
            (consensus, path, node_id)
        }

        // Build a signed DOWNTIME_ATTEST: message as if produced by
        // `broadcast_attestation` — without needing the p2p_tx channel.
        fn build_signed_attestation(
            seed_byte: u8,
            reporter_addr: &str,
            offender: &str,
            epoch: u64,
            round: u64,
        ) -> String {
            let sk = SigningKey::from_bytes(&[seed_byte; 32]);
            let vk = sk.verifying_key();
            let pubkey_hex = hex::encode(vk.to_bytes());

            let canonical = format!("{}:{}:{}:{}", offender, epoch, reporter_addr, round);
            let sig = sk.sign(canonical.as_bytes());
            let sig_hex = hex::encode(sig.to_bytes());

            let payload = serde_json::json!({
                "offender": offender,
                "epoch": epoch,
                "reporter": reporter_addr,
                "reporter_pubkey": pubkey_hex,
                "round": round,
                "rounds_missed": 120u64,
                "signature": sig_hex,
            });
            format!("DOWNTIME_ATTEST:{}", payload)
        }

        // 1. Spawn 3 validators with deterministic keys.
        let (mut node_a, path_a, addr_a) = spawn_node(0xA1, "b2_node_a");
        let (mut node_b, path_b, addr_b) = spawn_node(0xB2, "b2_node_b");
        let (mut node_c, path_c, addr_c) = spawn_node(0xC3, "b2_node_c");

        // Offender = address derived from yet another key (not a validator
        // we'll need to test it).
        let offender_sk = SigningKey::from_bytes(&[0xFF; 32]);
        let offender = derive_address(offender_sk.verifying_key().as_bytes()).unwrap();

        // 2. Register A, B, C AND the offender as the validator set on
        //    EVERY node's storage. Post-Phase-5B.6 (SEC-N03), an offender
        //    must be in the validator set to be eligible for downtime
        //    attestation — otherwise spam against random addresses would
        //    cause unbounded storage growth.
        let vset: Vec<(String, u64)> = vec![
            (addr_a.clone(), 100),
            (addr_b.clone(), 100),
            (addr_c.clone(), 100),
            (offender.clone(), 100),
        ];
        let vset_json = serde_json::to_string(&vset).unwrap();
        for node in [&node_a, &node_b, &node_c] {
            node.storage.put("sys:validators", &vset_json).unwrap();
            node.invalidate_validators_cache();
        }

        // 3. Each validator builds + "broadcasts" their attestation.
        //    Each receiving node gets the OTHER TWO attestations + already
        //    has its own (saved locally before broadcast in real code).
        let epoch = 1u64;
        let round = 100u64;

        let attest_from_a = build_signed_attestation(0xA1, &addr_a, &offender, epoch, round);
        let attest_from_b = build_signed_attestation(0xB2, &addr_b, &offender, epoch, round);
        let attest_from_c = build_signed_attestation(0xC3, &addr_c, &offender, epoch, round);

        // Each node stores its own attestation locally (simulates the
        // local write in the downtime detection path).
        for (node, reporter) in [(&node_a, &addr_a), (&node_b, &addr_b), (&node_c, &addr_c)] {
            let key = format!(
                "sys:downtime_attestation:{}:{}:{}",
                offender, epoch, reporter
            );
            let payload = serde_json::json!({
                "offender": &offender,
                "epoch": epoch,
                "reporter": reporter,
                "round": round,
                "rounds_missed": 120u64,
            });
            node.storage.put(&key, &payload.to_string()).unwrap();
        }

        // 4. Gossip: each node receives the other two attestations.
        node_a.handle_message(&attest_from_b);
        node_a.handle_message(&attest_from_c);

        node_b.handle_message(&attest_from_a);
        node_b.handle_message(&attest_from_c);

        node_c.handle_message(&attest_from_a);
        node_c.handle_message(&attest_from_b);

        // 5. Verify EACH node now has 3 distinct attestations stored for X.
        for (node, label) in [(&node_a, "A"), (&node_b, "B"), (&node_c, "C")] {
            let mut count = 0;
            for reporter in [&addr_a, &addr_b, &addr_c] {
                let key = format!(
                    "sys:downtime_attestation:{}:{}:{}",
                    offender, epoch, reporter
                );
                if node.storage.get(&key).unwrap().is_some() {
                    count += 1;
                }
            }
            assert_eq!(
                count, 3,
                "Node {} must have 3 distinct attestations after gossip",
                label
            );
        }

        // 6. Executor on node A promotes attestations → pending slash.
        //    BFT quorum = (3*2/3)+1 = 3, exactly met.
        let executor_a = Executor::new(Arc::clone(&node_a.storage));
        executor_a.promote_downtime_attestations_to_slash();

        let slash_key = format!("sys:pending_slash:{}", offender);
        assert!(
            node_a.storage.get(&slash_key).unwrap().is_some(),
            "Phase 4.B2: BFT quorum reached → executor must queue pending slash"
        );

        let _ = std::fs::remove_dir_all(&path_a);
        let _ = std::fs::remove_dir_all(&path_b);
        let _ = std::fs::remove_dir_all(&path_c);
    }

    /// Attestation from unknown validator is rejected.
    #[test]
    fn test_h02_unknown_reporter_rejected() {
        use crypto::{Signer, SigningKey};

        let (mut dag, path) = setup_dag("h02_unknown_reporter");

        // Empty validator set — no one is registered.
        let vset: Vec<(String, u64)> = vec![];
        dag.storage
            .put("sys:validators", &serde_json::to_string(&vset).unwrap())
            .unwrap();
        dag.invalidate_validators_cache();

        let key_bytes: [u8; 32] = [0xDD; 32];
        let sk = SigningKey::from_bytes(&key_bytes);
        let vk = sk.verifying_key();
        let canonical = "offender:1:fakereporter:10";
        let sig = sk.sign(canonical.as_bytes());

        let payload = serde_json::json!({
            "offender": "offender",
            "epoch": 1u64,
            "reporter": "fakereporter",
            "reporter_pubkey": hex::encode(vk.to_bytes()),
            "round": 10u64,
            "rounds_missed": 110u64,
            "signature": hex::encode(sig.to_bytes()),
        });

        dag.handle_message(&format!("DOWNTIME_ATTEST:{}", payload));

        let key = "sys:downtime_attestation:offender:1:fakereporter";
        assert!(
            dag.storage.get(key).unwrap().is_none(),
            "unknown reporter must be rejected"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    // ===== SEC-#9/#10: equivocation evidence gossip + prune retention =====

    /// Build a vertex authored + signed by the consensus node (offender == self,
    /// which is already a registered validator in `setup_dag`).
    fn signed_vertex(consensus: &DagConsensus, round: u64, timestamp: u64) -> blockchain::Vertex {
        let signing_key = crypto::SigningKey::from_bytes(&consensus.node_key);
        let mut v = blockchain::Vertex {
            round,
            author: consensus.node_id.clone(),
            timestamp,
            payload: vec![],
            parents: vec!["genesis".to_string()],
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
        };
        v.hash = v.calculate_hash();
        v.sign_with_ed25519(&signing_key);
        v
    }

    fn equiv_proof_msg(
        offender: &str,
        a: &blockchain::Vertex,
        b: &blockchain::Vertex,
    ) -> String {
        let payload = serde_json::json!({
            "offender": offender,
            "round": a.round,
            "vertex_a": a,
            "vertex_b": b,
        });
        format!("EQUIV_PROOF:{}", serde_json::to_string(&payload).unwrap())
    }

    /// Forged or non-conflicting "proofs" must NOT slash an (honest) validator.
    #[test]
    fn test_equiv_forged_evidence_rejected() {
        let (mut consensus, path) = setup_dag("equiv_forged");
        consensus.current_round = 1;
        let offender = consensus.node_id.clone();
        let pending_key = format!("sys:pending_slash:{}", offender);

        let a = signed_vertex(&consensus, 1, 1_000);
        let b = signed_vertex(&consensus, 1, 2_000);

        // (i) same vertex twice — not actually conflicting.
        consensus.handle_message(&equiv_proof_msg(&offender, &a, &a));
        assert!(consensus.storage.get(&pending_key).unwrap().is_none());

        // (ii) body tampered after signing — hash no longer binds the body.
        let mut tampered = b.clone();
        tampered.timestamp = 9_999; // hash/sig still bind ts=2000
        consensus.handle_message(&equiv_proof_msg(&offender, &a, &tampered));
        assert!(consensus.storage.get(&pending_key).unwrap().is_none());

        // (iii) second vertex signed by an ATTACKER key — sig fails against the
        // offender's pubkey, so a forger cannot frame an honest validator.
        let attacker = crypto::SigningKey::from_bytes(&[7u8; 32]);
        let mut forged = blockchain::Vertex {
            round: 1,
            author: offender.clone(),
            timestamp: 3_000,
            payload: vec![],
            parents: vec!["genesis".to_string()],
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
        };
        forged.hash = forged.calculate_hash();
        forged.sign_with_ed25519(&attacker);
        consensus.handle_message(&equiv_proof_msg(&offender, &a, &forged));

        assert!(consensus.storage.get(&pending_key).unwrap().is_none());
        assert!(consensus
            .storage
            .get(&format!("sys:equiv_seen:{}:1", offender))
            .unwrap()
            .is_none());

        let _ = std::fs::remove_dir_all(&path);
    }

    /// PROTOCOL (deterministic slashing): once an equivocation is applied, the
    /// canonical evidence item must ride in this node's NEXT vertex, prefixed
    /// with SLASH_EVIDENCE_PREFIX, so consensus orders it and every node extracts
    /// the identical set at block-build time. It must be carried exactly once.
    #[test]
    fn test_evidence_rides_in_next_vertex_exactly_once() {
        // Unique per invocation: this harness can run a test body twice in one
        // process, and RocksDB refuses to open a path whose LOCK it already holds.
        let suffix = format!(
            "evidence_carry_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let (mut consensus, path) = setup_dag(&suffix);
        consensus.current_round = 1;
        let offender = consensus.node_id.clone();
        let a = signed_vertex(&consensus, 1, 1_000);
        let b = signed_vertex(&consensus, 1, 2_000);

        // Valid proof -> applied -> queued.
        consensus.handle_message(&equiv_proof_msg(&offender, &a, &b));

        // Next vertex carries it, FIRST in the payload, with the prefix.
        consensus.try_create_vertex();
        let carried: Vec<String> = {
            let dag = consensus.dag.lock().unwrap();
            let v = dag.values().max_by_key(|v| v.round).expect("vertex created");
            v.payload.clone()
        };
        assert!(!carried.is_empty(), "vertex must carry the evidence");
        let item = carried[0]
            .strip_prefix(crate::dag::SLASH_EVIDENCE_PREFIX)
            .expect("first payload item must be prefixed evidence");
        let ev: serde_json::Value = serde_json::from_str(item).unwrap();
        assert_eq!(ev["kind"].as_str(), Some("equivocation"));
        assert_eq!(ev["offender"].as_str(), Some(offender.as_str()));
        assert_eq!(ev["round"].as_u64(), Some(1));
        assert!(ev.get("vertex_a").is_some() && ev.get("vertex_b").is_some());
        // The executor must accept exactly this item (same verifier the block
        // path uses), so a carried item is never dead weight.
        consensus
            .executor
            .verify_slash_evidence(item)
            .expect("carried item must verify on the executor");
        // The durable marker is latched only when the item lands in a BLOCK we
        // carried it into -- never at carry time -- so an orphaned or
        // cap-dropped carry can be retried. Nothing has been committed here.
        assert!(consensus
            .storage
            .get(&format!("sys:equiv_carried:{}:1", offender))
            .unwrap()
            .is_none());

        // Within the in-flight TTL a second vertex must NOT carry it again.
        consensus.current_round = 2;
        consensus.try_create_vertex();
        let again: Vec<String> = {
            let dag = consensus.dag.lock().unwrap();
            let v = dag.values().max_by_key(|v| v.round).expect("second vertex");
            assert_eq!(v.round, 2);
            v.payload.clone()
        };
        assert!(
            again.iter().all(|p| !p.starts_with(crate::dag::SLASH_EVIDENCE_PREFIX)),
            "evidence must not be re-carried while in flight"
        );

        // After the TTL with no inclusion, it is treated as orphaned and
        // carried AGAIN (liveness: evidence in a never-committed vertex is not
        // lost on this node). Exercise the carry decision directly -- vertex
        // creation itself is gated on parents/quorum and is not what is under
        // test here.
        let ttl = crate::dag::INFLIGHT_TTL_ROUNDS;
        // carried at round 1; still in flight through round ttl (1 + ttl - 1)
        for r in 3..(1 + ttl) {
            assert!(
                consensus.drain_evidence_for_vertex(r).is_empty(),
                "must not re-carry while in flight (round {})",
                r
            );
        }
        // first round where (r - 1) >= ttl -> orphaned -> re-carried
        let retried = consensus.drain_evidence_for_vertex(1 + ttl);
        assert_eq!(retried.len(), 1, "orphaned carry must be retried after INFLIGHT_TTL_ROUNDS");
        assert!(retried[0].starts_with(crate::dag::SLASH_EVIDENCE_PREFIX));
        // and it is in flight again from that round
        assert!(consensus.drain_evidence_for_vertex(1 + ttl + 1).is_empty());

        let _ = std::fs::remove_dir_all(&path);
    }

    /// PROTOCOL: canonical_block_evidence is a pure function of the committed
    /// sequence -- dedup by (offender, round) keeping the first in commit order,
    /// skip malformed items, cap at five. Two nodes feeding it the same committed
    /// payloads must get byte-identical output.
    #[test]
    fn test_canonical_block_evidence_dedup_order_cap() {
        let mk = |off: &str, round: u64, tag: &str| {
            serde_json::json!({"kind":"equivocation","offender":off,"round":round,"tag":tag}).to_string()
        };
        let input = vec![
            mk("A", 1, "first"),
            "not json".to_string(),
            mk("A", 1, "dup-later"),
            mk("B", 1, "b"),
            mk("A", 2, "a2"),
            serde_json::json!({"kind":"equivocation","offender":"C"}).to_string(), // no round
            mk("D", 1, "d"),
            mk("E", 1, "e"),
            mk("F", 1, "f"),
            mk("G", 1, "g"),
        ];
        // A permissive verifier (parses offender/round) to exercise dedup/cap.
        let parse = |it: &str| -> Option<(String, u64)> {
            let v: serde_json::Value = serde_json::from_str(it).ok()?;
            Some((v.get("offender")?.as_str()?.to_string(), v.get("round")?.as_u64()?))
        };
        let out: Vec<String> = DagConsensus::canonical_block_evidence(input.clone(), parse)
            .into_iter().map(|(it, _)| it).collect();
        // first occurrence wins, malformed skipped, cap 5
        assert_eq!(out.len(), 5);
        assert_eq!(out[0], mk("A", 1, "first"));
        assert_eq!(out[1], mk("B", 1, "b"));
        assert_eq!(out[2], mk("A", 2, "a2"));
        assert_eq!(out[3], mk("D", 1, "d"));
        assert_eq!(out[4], mk("E", 1, "e"));
        // deterministic: same input twice -> identical
        let again: Vec<String> = DagConsensus::canonical_block_evidence(input.clone(), parse)
            .into_iter().map(|(it, _)| it).collect();
        assert_eq!(out, again);
        // VERIFY-FIRST: a strict verifier that rejects offender "A" means A's
        // junk can neither occupy a slot nor shadow later real items.
        let strict = |it: &str| -> Option<(String, u64)> {
            let k = parse(it)?;
            if k.0 == "A" { None } else { Some(k) }
        };
        let strict_out: Vec<String> = DagConsensus::canonical_block_evidence(input, strict)
            .into_iter().map(|(it, _)| it).collect();
        assert_eq!(strict_out.len(), 5);
        assert_eq!(strict_out[0], mk("B", 1, "b"));
        assert!(strict_out.iter().all(|x| !x.contains("\"offender\":\"A\"")));
    }

    /// Only equivocation items may ride through the DAG. A "downtime" item
    /// would make apply_slash_evidence touch node-local attestation rows.
    #[test]
    fn test_only_equivocation_items_pass_kind_filter() {
        assert!(DagConsensus::is_equivocation_item(r#"{"kind":"equivocation","offender":"x","round":1}"#));
        assert!(!DagConsensus::is_equivocation_item(r#"{"kind":"downtime","offender":"x","epoch":1,"round":1}"#));
        assert!(!DagConsensus::is_equivocation_item(r#"{"offender":"x","round":1}"#));
        assert!(!DagConsensus::is_equivocation_item("not json"));
    }

    /// A live vertex carrying `payload_root` (the proof-only compact field) is
    /// rejected at ingress: it could otherwise pass hash recomputation with an
    /// arbitrary real payload.
    #[test]
    fn test_ingress_rejects_live_vertex_with_payload_root() {
        let (mut consensus, path) = setup_dag(&format!(
            "payload_root_ingress_{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        consensus.current_round = 1;
        let full = signed_vertex(&consensus, 1, 5_000);
        let mut compact = full.to_compact_proof(); // hash unchanged, payload stripped
        compact.payload = vec!["smuggled".to_string()]; // body != root, hash still "matches"
        let before = consensus.dag.lock().unwrap().len();
        consensus.handle_message(&format!("DAG_VERTEX:{}", serde_json::to_string(&compact).unwrap()));
        assert_eq!(consensus.dag.lock().unwrap().len(), before, "must be rejected");
        // and the honest full vertex is accepted
        consensus.handle_message(&format!("DAG_VERTEX:{}", serde_json::to_string(&full).unwrap()));
        assert_eq!(consensus.dag.lock().unwrap().len(), before + 1);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// Parents are bounded and unique at ingress; a proof-form vertex (either
    /// root set) is never admitted as live.
    #[test]
    fn test_ingress_rejects_bad_parents_and_proof_form() {
        let (mut consensus, path) = setup_dag(&format!(
            "parents_ingress_{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        consensus.current_round = 1;
        // Copy identity out so the closure does not borrow `consensus`
        // (handle_message below needs it mutably).
        let key = crypto::SigningKey::from_bytes(&consensus.node_key);
        let author = consensus.node_id.clone();
        let mk = move |parents: Vec<String>| {
            let mut v = blockchain::Vertex {
                round: 1,
                author: author.clone(),
                timestamp: 7_000,
                payload: vec![],
                parents,
                hash: String::new(),
                signature: String::new(),
                aggregated_signature: None,
                payload_root: None,
                parents_root: None,
                parent_refs: Vec::new(),
            };
            v.hash = v.calculate_hash();
            v.sign_with_ed25519(&key);
            v
        };
        let before = consensus.dag.lock().unwrap().len();
        // too many parents
        let many: Vec<String> = (0..(crate::dag::MAX_PARENTS + 1)).map(|i| format!("{:064x}", i)).collect();
        consensus.handle_message(&format!("DAG_VERTEX:{}", serde_json::to_string(&mk(many)).unwrap()));
        assert_eq!(consensus.dag.lock().unwrap().len(), before, "too many parents must be rejected");
        // duplicate parents
        consensus.handle_message(&format!("DAG_VERTEX:{}", serde_json::to_string(&mk(vec!["genesis".into(), "genesis".into()])).unwrap()));
        assert_eq!(consensus.dag.lock().unwrap().len(), before, "duplicate parents must be rejected");
        // parents_root set on a live vertex
        let mut pr = mk(vec!["genesis".into()]);
        pr.parents_root = Some(pr.parents_root());
        pr.parents = vec![];
        consensus.handle_message(&format!("DAG_VERTEX:{}", serde_json::to_string(&pr).unwrap()));
        assert_eq!(consensus.dag.lock().unwrap().len(), before, "parents_root on a live vertex must be rejected");
        // honest vertex accepted
        consensus.handle_message(&format!("DAG_VERTEX:{}", serde_json::to_string(&mk(vec!["genesis".into()])).unwrap()));
        assert_eq!(consensus.dag.lock().unwrap().len(), before + 1);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// The carry skip is ROUND-SCOPED. An earlier cut skipped whenever the
    /// offender had ANY sys:slashed row, on the assumption "slashed once => out
    /// of the validator set forever" -- nothing enforces that (join_validator_set
    /// is not blocked for a slashed address), so it handed a re-joined
    /// equivocator permanent immunity from ever being slashed again. Rows that
    /// are genuinely unverifiable are dropped by the block-side verifier, which
    /// is the deterministic gate.
    #[test]
    fn test_drain_skip_is_round_scoped_not_offender_wide() {
        let (mut consensus, path) = setup_dag(&format!(
            "drain_slashed_{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        consensus.current_round = 1;
        let offender = consensus.node_id.clone();
        let a = signed_vertex(&consensus, 1, 1_000);
        let b = signed_vertex(&consensus, 1, 2_000);
        consensus.handle_message(&equiv_proof_msg(&offender, &a, &b));

        // A slash for a DIFFERENT round must NOT suppress this round's evidence.
        consensus
            .storage
            .put(&format!("sys:slashed:{}:999", offender), "1")
            .unwrap();
        let carried = consensus.drain_evidence_for_vertex(2);
        assert_eq!(
            carried.len(),
            1,
            "a slash at another round must not grant immunity at this one"
        );

        // A slash for THIS round does suppress it (exactly-once, no re-carry).
        consensus
            .storage
            .put(&format!("sys:slashed:{}:1", offender), "1")
            .unwrap();
        assert!(
            consensus
                .drain_evidence_for_vertex(2 + crate::dag::INFLIGHT_TTL_ROUNDS)
                .is_empty(),
            "an executed slash for this exact round must stop the carry"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// An oversize DAG_VERTEX message is rejected before parsing.
    #[test]
    fn test_ingress_rejects_oversize_vertex() {
        let (mut consensus, path) = setup_dag(&format!(
            "oversize_ingress_{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let before = consensus.dag.lock().unwrap().len();
        let junk = "x".repeat(crate::dag::MAX_VERTEX_BYTES + 1);
        consensus.handle_message(&format!("DAG_VERTEX:{}", junk));
        assert_eq!(consensus.dag.lock().unwrap().len(), before);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// A valid proof received by gossip (node saw NEITHER vertex locally) slashes.
    #[test]
    fn test_equiv_valid_evidence_slashes() {
        let (mut consensus, path) = setup_dag("equiv_valid");
        consensus.current_round = 1;
        let offender = consensus.node_id.clone();
        let a = signed_vertex(&consensus, 1, 1_000);
        let b = signed_vertex(&consensus, 1, 2_000);

        consensus.handle_message(&equiv_proof_msg(&offender, &a, &b));

        let row = consensus
            .storage
            .get(&format!("sys:equiv_seen:{}:1", offender))
            .unwrap()
            .expect("valid equivocation proof must record evidence");
        let ev: serde_json::Value = serde_json::from_str(&row).unwrap();
        assert_eq!(ev["offender"].as_str(), Some(offender.as_str()));
        assert!(ev.get("vertex_a").is_some() && ev.get("vertex_b").is_some());
        assert!(consensus
            .storage
            .get(&format!("validator:jailed:{}", offender))
            .unwrap()
            .is_some());
        assert!(consensus
            .storage
            .get(&format!("sys:equiv_seen:{}:1", offender))
            .unwrap()
            .is_some());

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Re-receiving the proof AND local re-detection must slash exactly once
    /// (byte-identical event), never duplicate.
    #[test]
    fn test_equiv_double_apply_is_idempotent() {
        let (mut consensus, path) = setup_dag("equiv_idempotent");
        consensus.current_round = 1;
        let offender = consensus.node_id.clone();
        let a = signed_vertex(&consensus, 1, 1_000);
        let b = signed_vertex(&consensus, 1, 2_000);
        let msg = equiv_proof_msg(&offender, &a, &b);

        consensus.handle_message(&msg);
        let first = consensus
            .storage
            .get(&format!("sys:equiv_seen:{}:1", offender))
            .unwrap()
            .unwrap();

        // Re-deliver the gossip, then locally detect the same equivocation.
        consensus.handle_message(&msg);
        consensus.add_vertex(a.clone());
        consensus.add_vertex(b.clone());

        let second = consensus
            .storage
            .get(&format!("sys:equiv_seen:{}:1", offender))
            .unwrap()
            .unwrap();
        assert_eq!(
            first, second,
            "slash event must be byte-identical after repeated applies"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Local detection in `add_vertex` must gossip the proof to peers.
    #[tokio::test]
    async fn test_equiv_local_detection_broadcasts() {
        let path = get_test_db_path("equiv_broadcast");
        let db = Arc::new(StateDB::open(&path).unwrap());
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let executor = Arc::new(Executor::new(Arc::clone(&db)));
        let peers = Arc::new(Mutex::new(HashMap::new()));

        let node_key = [42u8; 32];
        let signing_key = crypto::SigningKey::from_bytes(&node_key);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let node_id = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
        let account = Object::new(
            node_id.clone(),
            Owner::Address(node_id.clone()),
            serde_json::json!({ "public_key": public_key, "sequence_number": 0 })
                .to_string()
                .into_bytes(),
            "0x1::account::AccountData".to_string(),
        );
        db.put_object(&account).unwrap();
        db.put("sys:validators", &format!(r#"[["{}",1000]]"#, node_id))
            .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(16);
        let mut consensus =
            DagConsensus::new(node_id, peers, mempool, executor, db, None, Some(tx), node_key);
        consensus.current_round = 1;

        let a = signed_vertex(&consensus, 1, 1_000);
        let b = signed_vertex(&consensus, 1, 2_000);
        consensus.add_vertex(a);
        consensus.add_vertex(b); // conflict → detection → broadcast

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("equivocation proof must be broadcast")
            .expect("channel open");
        assert!(got.starts_with("EQUIV_PROOF:"), "got: {}", got);

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Evidence survives DAG pruning (#10), and is GC'd only past the retention
    /// window.
    #[test]
    fn test_prune_preserves_equivocation_evidence() {
        let (mut consensus, path) = setup_dag("equiv_prune");
        consensus.current_round = 1;
        let offender = consensus.node_id.clone();
        let a = signed_vertex(&consensus, 1, 1_000);
        let b = signed_vertex(&consensus, 1, 2_000);
        consensus.handle_message(&equiv_proof_msg(&offender, &a, &b));

        let seen_key = format!("sys:equiv_seen:{}:1", offender);
        assert!(consensus.storage.get(&seen_key).unwrap().is_some());

        // Pruning well past round 1 deletes DAG vertices but NOT the evidence KV.
        consensus.prune_dag(50);
        assert!(
            consensus.storage.get(&seen_key).unwrap().is_some(),
            "equivocation evidence must survive DAG pruning (#10)"
        );

        // Only beyond the retention window is the evidence garbage-collected.
        consensus.prune_dag(crate::dag::EQUIV_EVIDENCE_RETENTION_ROUNDS + 5);
        assert!(
            consensus.storage.get(&seen_key).unwrap().is_none(),
            "evidence past the retention window must be garbage-collected"
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// AUDIT-B3: a remote vertex must NEVER be able to push this node to a round
    /// it cannot build parents for.
    ///
    /// The bug: `add_vertex` did `self.current_round = vertex.round + 1` for any
    /// strictly-ahead remote vertex, and persisted it. `try_create_vertex` then
    /// looks for parents at `current_round - 1` — a round holding only that single
    /// vertex, which can never reach the stake-weighted parent quorum. Block
    /// production stopped network-wide and survived restarts. No Byzantine intent
    /// needed: a validator with a slightly fast ticker does it.
    ///
    /// The fix advances only to `quorum_round + 1` (Narwhal's rule), so the local
    /// round can never outrun the DAG's actual parent availability.
    #[test]
    fn test_b3_remote_vertex_cannot_wedge_round_advance() {
        let (mut consensus, path) = setup_dag("b3_no_wedge");

        // Add a SECOND validator so quorum genuinely requires both (>2/3 of 2000).
        let remote_key = crypto::SigningKey::from_bytes(&[99u8; 32]);
        let remote_pub = hex::encode(remote_key.verifying_key().to_bytes());
        let remote_id = crypto::derive_address(remote_key.verifying_key().as_bytes()).unwrap();
        let remote_account = Object::new(
            remote_id.clone(),
            Owner::Address(remote_id.clone()),
            serde_json::json!({ "public_key": remote_pub, "sequence_number": 0 })
                .to_string()
                .into_bytes(),
            "0x1::account::AccountData".to_string(),
        );
        consensus.storage.put_object(&remote_account).unwrap();
        let validator_json = format!(
            r#"[["{}",1000],["{}",1000]]"#,
            consensus.node_id, remote_id
        );
        consensus.storage.put("sys:validators", &validator_json).unwrap();
        consensus.invalidate_validators_cache();

        let round_before = consensus.current_round;

        // The remote validator emits a vertex FAR ahead of us.
        let far_round = round_before + 500;
        let mut far_vertex = blockchain::Vertex {
            round: far_round,
            author: remote_id.clone(),
            timestamp: 1_000,
            payload: vec![],
            parents: vec!["genesis".to_string()],
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
        };
        far_vertex.hash = far_vertex.calculate_hash();
        far_vertex.sign_with_ed25519(&remote_key);

        consensus.add_vertex(far_vertex);

        // The vertex is STORED (it still counts toward its own round's quorum)...
        {
            let dag = consensus.dag.lock().unwrap();
            assert_eq!(dag.len(), 1, "the far-ahead vertex must still be ingested");
        }
        // ...but it must NOT have dragged our proposal clock to far_round + 1.
        assert!(
            consensus.current_round <= round_before + 1,
            "a single remote vertex must not fast-forward the local round: round went \
             {} -> {} (would wedge: parents at current_round-1 can never reach quorum)",
            round_before,
            consensus.current_round
        );
        assert_ne!(
            consensus.current_round,
            far_round + 1,
            "this is the exact wedge the audit found"
        );

        // Liveness: the round we would build on must still be one whose parents can
        // actually exist. Before the fix, current_round jumped to far_round + 1 and
        // `current_round - 1` (far_round) held exactly one vertex — permanently
        // below the stake quorum, so try_create_vertex could never succeed again.
        // (We assert the round invariant rather than calling try_create_vertex,
        // because with 2 validators and no connected peers the separate split-brain
        // guard intentionally suppresses mining — that is not what B3 is about.)
        assert!(
            consensus.current_round < far_round,
            "local round must stay far below the claimed remote round; got {} vs {}",
            consensus.current_round,
            far_round
        );

        // The persisted value must not carry the wedge across a restart either.
        let persisted = consensus
            .storage
            .get("latest_proposed_round")
            .unwrap()
            .map(|r| r.parse::<u64>().unwrap_or(0))
            .unwrap_or(0);
        assert!(
            persisted < far_round,
            "the wedge must not be persisted (was {})",
            persisted
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// AUDIT-B3 (second door) — the exact wedge that stopped a live 3-node
    /// cluster at round 85 AFTER the add_vertex quorum gate had already shipped.
    ///
    /// `reload_chain_tip` still did a blind `current_round = block.round + 1`.
    /// A committed block's round says only that the round was FINALIZED; it says
    /// nothing about whether THIS node holds that round's vertices — and those
    /// vertices are exactly what try_create_vertex needs as parents. Two of the
    /// three validators jumped to 85 without ever proposing at 84, so round 84
    /// held a single vertex, could never reach parent quorum, and the chain
    /// stopped producing permanently (the value is persisted, so it survived
    /// restarts). Closing one door was not enough.
    ///
    /// Here the gap is small (as in the real incident), so the catch-up floor
    /// does NOT apply and the cap must hold the node back.
    #[test]
    fn test_b3_reload_chain_tip_cannot_wedge_on_a_small_gap() {
        let (mut consensus, path) = setup_dag("b3_reload_small_gap");

        // Chain tip says round 84 was committed...
        let synced_block = blockchain::Block::new(
            10,
            84,
            "genesis".to_string(),
            vec![],
            "validator".into(),
        );
        consensus
            .storage
            .save_block_json(10, &serde_json::to_string(&synced_block).unwrap())
            .unwrap();

        // ...but this node's DAG has no vertices at all, so it cannot build
        // parents for round 84.
        let before = consensus.current_round;
        consensus.reload_chain_tip();

        assert!(
            consensus.current_round < 85,
            "must NOT blindly adopt tip+1 (=85) when the DAG cannot parent round \
             84 — that is the wedge: got {}",
            consensus.current_round
        );
        assert!(
            consensus.current_round >= before,
            "round must never go backwards"
        );

        let _ = std::fs::remove_dir_all(&path);
    }


    // ===================================================================
    // TIER 2 — NODE LEVEL. Real `DagConsensus`, real `StateDB`, real ingress.
    //
    // This tier is what ADJUDICATES the model layer. Tier 1 evaluates the
    // decision function over hand-built DAGs and can hand you counterexamples
    // for forks the real node cannot currently reach; tier 2 is the only thing
    // that says which is telling the truth. No code change should ship off a
    // tier-1 counterexample alone.
    //
    // It is also two to three orders of magnitude slower — ~1e3 schedules a
    // night against tier 1's ~1e4 a SECOND. Never quote the tier-1 throughput
    // as coverage for anything asserted here.
    // ===================================================================

    /// Address, public key hex, and raw key for a deterministic seed.
    fn tier2_keypair(seed: u8) -> (String, String, [u8; 32]) {
        let key = [seed; 32];
        let sk = crypto::SigningKey::from_bytes(&key);
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let addr = crypto::derive_address(sk.verifying_key().as_bytes()).unwrap();
        (addr, pubkey, key)
    }

    /// Open a node at an EXPLICIT path, seeding every author it will be asked
    /// about.
    ///
    /// Both preconditions fail SILENTLY if missed, which is why they are done
    /// here rather than per test:
    ///   * `resolve_author_pubkey` (dag.rs:998) hard-returns when the author has
    ///     no `0x1::account::AccountData` object, so an unseeded author's vertex
    ///     is dropped with nothing to distinguish it from a rejected one.
    ///   * the validator-set gate (dag.rs:1082) rejects a non-validator author —
    ///     but ONLY while `current_round > 0`, so a test that forgets to advance
    ///     the round silently skips the check it meant to exercise.
    fn tier2_open(
        seed: u8,
        path: &str,
        known: &[(String, String)],
    ) -> DagConsensus {
        let db = Arc::new(StateDB::open(path).unwrap());
        for (addr, pubkey) in known {
            let account = Object::new(
                addr.clone(),
                Owner::Address(addr.clone()),
                serde_json::json!({ "public_key": pubkey, "sequence_number": 0 })
                    .to_string()
                    .into_bytes(),
                "0x1::account::AccountData".to_string(),
            );
            db.put_object(&account).unwrap();
        }
        let vset: Vec<String> = known
            .iter()
            .map(|(a, _)| format!(r#"["{}",1000]"#, a))
            .collect();
        db.put("sys:validators", &format!("[{}]", vset.join(",")))
            .unwrap();

        let node_key = [seed; 32];
        let node_id = crypto::derive_address(
            crypto::SigningKey::from_bytes(&node_key)
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        let mut c = DagConsensus::new(
            node_id,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Executor::new(Arc::clone(&db))),
            db,
            None,
            None,
            node_key,
        );
        // Past 0, or the validator-set gate above never runs.
        c.current_round = 1;
        c
    }

    /// A vertex validly signed by `key`. Two calls with different timestamps
    /// produce a genuine equivocation: same author, same round, different hash,
    /// both signatures real.
    fn tier2_signed(key: &[u8; 32], author: &str, round: u64, ts: u64) -> blockchain::Vertex {
        let sk = crypto::SigningKey::from_bytes(key);
        let mut v = blockchain::Vertex {
            round,
            author: author.to_string(),
            timestamp: ts,
            payload: vec![],
            parents: vec!["genesis".to_string()],
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
            parent_refs: Vec::new(),
        };
        v.hash = v.calculate_hash();
        v.sign_with_ed25519(&sk);
        v
    }

    fn tier2_accepted(c: &DagConsensus) -> std::collections::BTreeSet<String> {
        c.dag.lock().unwrap().keys().cloned().collect()
    }

    /// AUDIT H1, at the node level. RED BY DESIGN — H1 is OPEN at HEAD.
    ///
    ///   cargo test -p consensus --lib test_h1_dropped_twin -- --ignored --nocapture
    ///
    /// `add_vertex` returns at dag.rs:1167 on detecting an equivocation, BEFORE
    /// the persist at :1173-1181 and the `dag.insert` / `round_idx.push` at
    /// :1183-1187. The losing twin is therefore destroyed — not quarantined, not
    /// stored as evidence, destroyed. No production DAG BFT system does this: the
    /// twin is the evidence, and a node that discards it can no longer prove what
    /// it saw.
    ///
    /// The predicate is **P_VIEW_EQ**: two honest nodes that received the same
    /// message SET hold the same accepted-vertex set. Deliberately NOT
    /// `P_CLOSURE` ("every non-genesis parent of an accepted vertex is
    /// retrievable"), which an earlier design named as the gate here and which
    /// was MEASURED to run zero checks and print green both before AND after its
    /// own mandatory fix-mutation — vacuous in exactly the scenario it was
    /// written for.
    ///
    /// GATES:
    ///   HEAD                     -> RED. X holds only the first twin it saw, Y
    ///                               only the first IT saw. Same messages,
    ///                               different final state.
    ///   hoist the persist and the dag.insert above the `return;` at dag.rs:1167
    ///                            -> GREEN, and P_RESTART_STABLE must STAY green.
    ///
    /// MEASURED RESULT — THE NAIVE HOIST IS NOT A FIX. Each leg isolated so
    /// neither short-circuits the other:
    ///
    ///                        HEAD      naive hoist
    ///   P_VIEW_EQ            RED       GREEN
    ///   P_RESTART_STABLE     GREEN     RED
    ///
    /// It trades one defect for another. The recommendation that produced this
    /// test named the hoist as the red->green flip, and two independent reviewers
    /// had built and confirmed that flip — on P_VIEW_EQ alone. Persisting both
    /// twins is only HALF a fix: something must then choose between them
    /// deterministically, and today memory chooses by arrival order while boot
    /// chooses by byte order.
    ///
    /// And the half that is missing is not local. Once a node can hold both
    /// twins, H4 opens: `direct_quorum_met` counts one author's stake toward BOTH
    /// (see `test_h2_h4_twin_...`, where the two twins together carry 200% of the
    /// validator set). H1, H2 and H4 are ONE change set with a forced order, not
    /// three fixes — exactly as the register says.
    ///
    /// P_RESTART_STABLE is not optional decoration. In memory the surviving twin
    /// is chosen by ARRIVAL order; on reboot the recovery loops (dag.rs:245-256,
    /// :318-330) refuse the second vertex from one author at one round and choose
    /// by `scan_vertices` BYTE order (`prefix_iterator`, storage/lib.rs:280).
    /// Those two orders are unrelated. At HEAD the question cannot arise — only
    /// one twin is ever persisted — so this leg is green today for a reason that
    /// the naive hoist REMOVES. A harness that goes green on the hoist without
    /// re-checking restart has measured the instance and missed the class.
    #[test]
    #[ignore = "reproduces H1, an OPEN defect: RED by design until the losing twin is persisted"]
    fn test_h1_dropped_twin_leaves_two_honest_nodes_holding_different_sets() {
        let (off_addr, off_pub, off_key) = tier2_keypair(7);
        let (x_addr, x_pub, _) = tier2_keypair(1);
        let (y_addr, y_pub, _) = tier2_keypair(2);
        let known = vec![
            (off_addr.clone(), off_pub),
            (x_addr, x_pub),
            (y_addr, y_pub),
        ];

        let xp = get_test_db_path("h1_view_eq_x");
        let yp = get_test_db_path("h1_view_eq_y");
        let mut x = tier2_open(1, &xp, &known);
        let mut y = tier2_open(2, &yp, &known);

        let a = tier2_signed(&off_key, &off_addr, 1, 1_000);
        let b = tier2_signed(&off_key, &off_addr, 1, 2_000);
        assert_ne!(a.hash, b.hash, "the twins must be distinguishable");

        // The ONLY difference between the two nodes is arrival order.
        x.add_vertex(a.clone());
        x.add_vertex(b.clone());
        y.add_vertex(b.clone());
        y.add_vertex(a.clone());

        let sx = tier2_accepted(&x);
        let sy = tier2_accepted(&y);

        // Non-vacuity: if neither node accepted anything, P_VIEW_EQ below would
        // pass trivially and this whole test would assert nothing.
        assert!(
            !sx.is_empty() && !sy.is_empty(),
            "neither node accepted any vertex — a seeding precondition failed \
             silently (AccountData for the author, or sys:validators). X={:?} Y={:?}",
            sx,
            sy
        );

        // ---- P_RESTART_STABLE, checked FIRST because P_VIEW_EQ is red at HEAD
        //      and would otherwise short-circuit it out of the run entirely.
        drop(x);
        let x2 = tier2_open(1, &xp, &known);
        assert_eq!(
            tier2_accepted(&x2),
            sx,
            "P_RESTART_STABLE VIOLATED: a node changed its own mind about which \
             twin it accepted, across nothing but a restart. In memory the winner \
             is chosen by ARRIVAL order; on reboot by scan_vertices BYTE order \
             (storage/lib.rs:280). If you have just hoisted the persist above \
             dag.rs:1167, this is the defect the hoist introduced — persisting \
             both twins is only half a fix without a deterministic choice between \
             them."
        );

        // ---- P_VIEW_EQ
        assert_eq!(
            sx, sy,
            "P_VIEW_EQ VIOLATED: two honest nodes received the SAME two vertices \
             and hold different sets.\n  X (saw A then B) accepted {:?}\n  \
             Y (saw B then A) accepted {:?}\n\
             add_vertex returns at dag.rs:1167 before the persist at :1173 and the \
             dag.insert at :1183, so the losing twin is destroyed and which one \
             survives is decided by arrival order.",
            sx,
            sy
        );

        let _ = std::fs::remove_dir_all(&xp);
        let _ = std::fs::remove_dir_all(&yp);
    }

    /// The clock seam (`now_secs`, `placement_sleep`) actually CONTROLS behaviour.
    ///
    /// Wiring a seam and never proving it is load-bearing is how a harness ends up
    /// testing a program that does not ship. Two of the three sites are asserted
    /// here by behaviour:
    ///   * the vertex timestamp, which is folded into the SIGNED hash — so a
    ///     simulation can produce reproducible vertex hashes at all
    ///   * the MAX_FUTURE_DRIFT_SECS admission gate, on both sides of the boundary
    ///
    /// The third site — the 250 ms spacing in the anchor-placement retry loop — is
    /// wired but NOT exercised here, and that is stated rather than implied.
    /// Reaching it needs a commit whose first placement attempt fails against a
    /// moving chain tip, which is the tier-2 block path. `std::thread::sleep`
    /// appears exactly once in dag.rs now, inside the default constructor, so the
    /// call site is wired by construction; it is simply not yet under test.
    #[test]
    fn test_clock_seam_controls_the_signed_timestamp_and_the_drift_gate() {
        const PINNED: u64 = 1_700_000_000;
        let (mut consensus, path) = setup_dag("clock_seam");
        consensus.now_secs = Arc::new(|| PINNED);

        // ---- site 1: the timestamp folded into the signed hash ----------------
        consensus.try_create_vertex();
        let stamps: Vec<u64> = consensus
            .dag
            .lock()
            .unwrap()
            .values()
            .map(|v| v.timestamp)
            .collect();
        assert_eq!(
            stamps,
            vec![PINNED],
            "the vertex timestamp must come from the seam. It is folded into \
             calculate_hash, so without this a simulation cannot produce the same \
             vertex hash twice and every seeded schedule is a different world."
        );

        // ---- site 2: the drift gate, on BOTH sides of the boundary ------------
        // MAX_FUTURE_DRIFT_SECS is 30. Just inside must be admitted; just outside
        // must be refused. Asserting only one side would pass on a gate that
        // rejects everything, or on one that rejects nothing.
        consensus.current_round = 1;

        // Both probes sit at round 2, and OUT-OF-BOUND goes first. That ordering
        // is deliberate: this node already authored a round-1 vertex above, so a
        // second round-1 vertex from it would be refused as an EQUIVOCATION
        // (dag.rs:1167) and the test would pass for entirely the wrong reason —
        // which is exactly what happened on the first attempt at writing it.
        // Sending the out-of-bound probe first also means that if the drift gate
        // wrongly ADMITS it, the in-bound probe then collides with it and the
        // second assertion fires too. Neither leg can pass by accident.
        let outside = signed_vertex(&consensus, 2, PINNED + 31);
        let inside = signed_vertex(&consensus, 2, PINNED + 29);
        assert_ne!(inside.hash, outside.hash);

        let before = consensus.dag.lock().unwrap().len();
        consensus.add_vertex(outside.clone());
        assert_eq!(
            consensus.dag.lock().unwrap().len(),
            before,
            "a vertex 31s ahead of the SEAM's clock must be refused (drift bound is \
             30s). If it was admitted, the gate is still reading the real wall \
             clock — which is far past PINNED, so every timestamp here looks like \
             the distant past and the bound is unreachable."
        );

        consensus.add_vertex(inside.clone());
        assert_eq!(
            consensus.dag.lock().unwrap().len(),
            before + 1,
            "a vertex 29s ahead of the SEAM's clock must be admitted. Refusal here \
             means either the gate is not reading the seam, or the out-of-bound \
             probe above was wrongly stored and this one collided with it."
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// The clock seam must not have cost DagConsensus its thread-safety: it is
    /// held in an Arc<RwLock<..>> and driven from tokio tasks in core/node.
    /// `Arc<dyn Fn>` without the `+ Send + Sync` bounds would compile here and
    /// break only at the call site in another crate.
    #[test]
    fn test_dag_consensus_is_still_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DagConsensus>();
    }

    /// AUDIT B4b. The "anchor already on chain" predicate, asserted at the
    /// BOUNDARY, because the boundary is where an off-by-one becomes a fork.
    ///
    /// This predicate existed as FIVE textually identical copies across the
    /// placement path in dag.rs. Five copies of one safety condition is the shape
    /// that drifts: a later edit fixes four and the fifth silently becomes a fork.
    /// It is one function now, and this test pins its meaning.
    ///
    /// The rule is decided by ANCHOR ROUND, never by height. The live burn-in
    /// showed what deciding by height cost: three distinct anchors (12220, 12224,
    /// 12226) were all skipped against the SAME height 5073 because
    /// reload_chain_tip had not yet seen sync\'s writes, so anchor 12226 never got
    /// a block on that node while its peers placed it at 5075.
    ///
    /// MUTATION: change `<=` to `<` and the boundary case below fails. That is not
    /// a hypothetical edit — it is exactly the "place it once more, just to be
    /// safe" change that duplicates an anchor.
    #[test]
    fn test_anchor_already_on_chain_is_decided_by_round_at_the_boundary() {
        let (mut consensus, path) = setup_dag("anchor_guard");
        consensus.latest_block_round = 10;

        assert!(
            consensus.anchor_already_on_chain(9),
            "an anchor BELOW the tip round is already on chain"
        );
        assert!(
            consensus.anchor_already_on_chain(10),
            "BOUNDARY: an anchor AT the tip round is already on chain. If this \
             fails, the placement path builds a SECOND block for an anchor that \
             already has one, and this node\'s anchor->height map diverges from \
             the network\'s — the live B4b fork."
        );
        assert!(
            !consensus.anchor_already_on_chain(11),
            "BOUNDARY: an anchor ABOVE the tip round still needs a block. If this \
             fails, every new anchor is skipped as a duplicate and the chain stops \
             producing blocks entirely — the opposite failure, equally fatal."
        );

        // Height must not enter the decision at all. That independence IS the fix
        // for the burn-in bug, so it is asserted rather than assumed.
        for h in [5_073u64, 999_999u64] {
            consensus.latest_block_height = h;
            assert!(
                consensus.anchor_already_on_chain(10),
                "height {} changed the answer — the predicate is reading height again",
                h
            );
            assert!(
                !consensus.anchor_already_on_chain(11),
                "height {} changed the answer — the predicate is reading height again",
                h
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }


    /// Feed one round of a validly-signed full mesh into `node`, returning the
    /// hashes so the next round can cite them.
    fn tier2_feed_round(
        node: &mut DagConsensus,
        keys: &[(String, String, [u8; 32])],
        round: u64,
        ts: u64,
        parents: &[String],
    ) -> Vec<String> {
        node.current_round = round;
        let mut out = Vec::new();
        for (addr, _, key) in keys {
            let sk = crypto::SigningKey::from_bytes(key);
            let mut v = blockchain::Vertex {
                round,
                author: addr.clone(),
                timestamp: ts,
                payload: vec![],
                parents: parents.to_vec(),
                hash: String::new(),
                signature: String::new(),
                aggregated_signature: None,
                payload_root: None,
                parents_root: None,
                parent_refs: Vec::new(),
            };
            v.hash = v.calculate_hash();
            v.sign_with_ed25519(&sk);
            out.push(v.hash.clone());
            node.add_vertex(v);
        }
        out
    }

    /// Every (height, anchor_round) pair this node has on disk.
    fn tier2_anchor_height_map(node: &DagConsensus) -> Vec<(u64, u64)> {
        let tip = node
            .storage
            .get("latest_height")
            .ok()
            .flatten()
            .and_then(|h| h.parse::<u64>().ok())
            .unwrap_or(0);
        (1..=tip)
            .filter_map(|h| {
                node.storage
                    .get(&format!("block_{}", h))
                    .ok()
                    .flatten()
                    .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
                    .map(|b| (h, b.header.round))
            })
            .collect()
    }

    /// AUDIT B4b — the sync-versus-local placement race, driven DELIBERATELY.
    ///
    /// This is the race behind the live block fork: one node built height 50 from
    /// round 52 while another built it from round 53. It is decided by REAL TIME
    /// — whether ChainSync's write becomes visible before or after this node
    /// finishes placing its own anchor — which is why no message-ordering harness
    /// can reach it. The `placement_sleep` seam is the hook: it fires between
    /// retry attempts, at exactly the point where sync's write would land.
    ///
    /// The scenario: this node has committed anchor round 4 and is placing its
    /// block. Mid-placement, ChainSync lands the network's block for THAT SAME
    /// ANCHOR at height 2. The node must recognise it and place nothing —
    /// producing a second block for one anchor is what makes its anchor->height
    /// map diverge from every peer's.
    ///
    /// Reaching the retry loop at all needs the first execute attempt to fail,
    /// which is arranged the way it happens live: `sys:last_executed_height` is
    /// already ahead of this node's tip, because sync executed the height before
    /// this node reloaded.
    ///
    /// MUTATION: delete `self.latest_block_round = self.latest_block_round.max(r)`
    /// from `reload_chain_tip` — the AUDIT-B4b dedup line — and this test fails:
    /// the node no longer knows the synced tip's anchor round and builds the
    /// duplicate.
    #[test]
    fn test_b4b_sync_landing_mid_placement_must_not_produce_a_duplicate_anchor() {
        const PINNED: u64 = 1_700_000_000;
        let keys: Vec<(String, String, [u8; 32])> =
            (1..=4u8).map(|i| tier2_keypair(i + 10)).collect();
        let known: Vec<(String, String)> =
            keys.iter().map(|(a, p, _)| (a.clone(), p.clone())).collect();

        let path = get_test_db_path("b4b_race");
        let mut node = tier2_open(11, &path, &known);
        node.now_secs = Arc::new(|| PINNED);

        // Rounds 1-3: anchor round 2 commits and is placed locally at height 1.
        let mut prev = vec!["genesis".to_string()];
        for r in 1..=3u64 {
            prev = tier2_feed_round(&mut node, &keys, r, PINNED, &prev);
        }
        assert_eq!(
            tier2_anchor_height_map(&node),
            vec![(1, 2)],
            "setup: anchor round 2 must be placed at height 1"
        );
        let r4_parents = tier2_feed_round(&mut node, &keys, 4, PINNED, &prev);

        // The simulated ChainSync writer: on its first firing it lands the
        // NETWORK's block for anchor round 4 at height 2 — exactly what a peer
        // would have produced — and publishes the tip the way sync does.
        let store = Arc::clone(&node.storage);
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_c = Arc::clone(&fired);
        node.placement_sleep = Arc::new(move |_d| {
            if fired_c.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let mut b = blockchain::Block::new(
                2,
                4, // the SAME anchor round this node is placing
                "prev".to_string(),
                vec![],
                "peer".to_string(),
            );
            b.header.timestamp = PINNED;
            let json = serde_json::to_string(&b).unwrap();
            let _ = store.put("block_2", &json);
            let _ = store.put("latest_height", "2");
            let _ = store.put("latest_block_hash", &b.header.hash);
        });

        // Sync already EXECUTED height 2 before this node reloaded its tip — the
        // live precondition, and what forces the placement loop past attempt 0.
        node.storage.put("sys:last_executed_height", "2").unwrap();

        // Round 5 commits anchor round 4 and enters the placement loop.
        let _ = tier2_feed_round(&mut node, &keys, 5, PINNED, &r4_parents);

        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the placement retry loop never ran, so the race was never reached and \
             this test asserted nothing. The first execute attempt must fail — check \
             that sys:last_executed_height is still ahead of the node's tip."
        );

        let map = tier2_anchor_height_map(&node);
        let placements_of_4: Vec<u64> = map
            .iter()
            .filter(|(_, r)| *r == 4)
            .map(|(h, _)| *h)
            .collect();
        assert_eq!(
            placements_of_4,
            vec![2],
            "P_ANCHOR_HEIGHT: anchor round 4 must appear at EXACTLY ONE height — \
             the one sync landed. Map was {:?}. More than one entry means this node \
             built a duplicate block for an anchor the network had already placed, \
             and its anchor->height mapping has diverged from every peer's. That is \
             the live B4b block fork.",
            map
        );

        let mut rounds: Vec<u64> = map.iter().map(|(_, r)| *r).collect();
        let unique = {
            let mut u = rounds.clone();
            u.sort_unstable();
            u.dedup();
            u
        };
        rounds.sort_unstable();
        assert_eq!(
            rounds, unique,
            "P_ANCHOR_HEIGHT (injectivity): two heights share an anchor round. Map {:?}",
            map
        );

        let _ = std::fs::remove_dir_all(&path);
    }

    /// The producer must EMIT self-describing parent refs, index-aligned with
    /// `parents`. Without them the ingress predicate has nothing to read and the
    /// whole format change is inert.
    ///
    /// FOUR validators deliberately, so round 2 cites FOUR parents. The first
    /// version of this test used `setup_dag`, which has ONE validator and
    /// therefore one parent — and a one-element list cannot exhibit
    /// misalignment, so it passed a mutation that dropped every other entry from
    /// `parents` while keeping every ref. Caught by running that mutation, which
    /// is the only reason it is known.
    #[test]
    fn test_producer_emits_aligned_parent_refs() {
        const PINNED: u64 = 1_700_000_000;
        let keys: Vec<(String, String, [u8; 32])> =
            (1..=4u8).map(|i| tier2_keypair(i + 20)).collect();
        let known: Vec<(String, String)> =
            keys.iter().map(|(a, p, _)| (a.clone(), p.clone())).collect();

        let path = get_test_db_path("parent_refs_emitted");
        // This node IS keys[0], so it can author.
        let mut node = tier2_open(21, &path, &known);
        node.now_secs = Arc::new(|| PINNED);
        // RULE 2 (dag.rs): with more than one validator the producer refuses to
        // mine while it sees no peers — split-brain prevention.
        node.peers.lock().unwrap().insert("peer".to_string(), 9999);

        // Round 1 from all four validators, so round 2 has four parents.
        let _ = tier2_feed_round(&mut node, &keys, 1, PINNED, &["genesis".to_string()]);
        node.current_round = 2;
        node.try_create_vertex();

        let dag = node.dag.lock().unwrap();
        let mine: Vec<_> = dag
            .values()
            .filter(|v| v.round == 2 && v.author == node.node_id)
            .collect();
        assert_eq!(mine.len(), 1, "this node must have authored exactly one round-2 vertex");
        let v = mine[0];

        assert!(
            v.parents.len() >= 3,
            "round 2 must cite a quorum of round-1 vertices, got {} — with fewer \
             than 3 this test cannot detect misalignment",
            v.parents.len()
        );
        assert_eq!(
            v.parent_refs.len(),
            v.parents.len(),
            "refs and parents must be the same length; the ingress predicate \
             relies on index alignment"
        );
        for (i, r) in v.parent_refs.iter().enumerate() {
            assert_eq!(
                r.digest, v.parents[i],
                "ref {} digest must equal parents[{}] — same order, not just the \
                 same set",
                i, i
            );
            assert_eq!(r.round, v.round - 1, "ref {} must declare round r-1", i);
            assert!(
                known.iter().any(|(a, _)| *a == r.author),
                "ref {} must name a real validator, got {}",
                i, r.author
            );
        }
        drop(dag);
        let _ = std::fs::remove_dir_all(&path);
    }
}
