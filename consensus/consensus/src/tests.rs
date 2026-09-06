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

}
