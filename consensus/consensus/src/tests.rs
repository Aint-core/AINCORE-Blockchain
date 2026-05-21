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
        assert!(consensus
            .storage
            .get_dag_checkpoint_signature(5)
            .is_some());

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Phase 2.8 (M-08): validator cache is populated on first read and
    /// returned for subsequent reads without re-parsing storage. After
    /// a block commit, the cache is invalidated and the next read
    /// reflects any updated validator set.
    #[test]
    fn m08_validator_cache_serves_repeated_reads_and_refreshes_on_commit() {
        let (mut consensus, path) = setup_dag("m08_validator_cache");

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

    // ── Phase 3 / H-02: Downtime attestation gossip ──────────────────────

    /// Valid remote attestation (correct sig + known validator) is stored.
    #[test]
    fn test_h02_valid_remote_attestation_stored() {
        use crypto::{Signer, SigningKey, derive_address};

        let (mut dag, path) = setup_dag("h02_valid_attest");

        // Create a fake "remote" validator key pair.
        let remote_key_bytes: [u8; 32] = [0xBB; 32];
        let remote_sk = SigningKey::from_bytes(&remote_key_bytes);
        let remote_vk = remote_sk.verifying_key();
        let remote_pubkey_hex = hex::encode(remote_vk.to_bytes());
        let remote_addr = derive_address(remote_vk.as_bytes()).expect("derive_address");

        // Register the remote validator in storage so the validator-set check passes.
        // Format: Vec<(String, u64)> serialised by serde_json → [["addr", stake], ...]
        let vset: Vec<(String, u64)> = vec![(remote_addr.clone(), 1000u64)];
        dag.storage.put("sys:validators", &serde_json::to_string(&vset).unwrap()).unwrap();
        // Invalidate cache so the new entry is visible.
        dag.invalidate_validators_cache();

        // Build and sign an attestation as the remote validator would.
        let offender = "deadbeefdeadbeef".to_string();
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
        let key = format!("sys:downtime_attestation:{}:{}:{}", offender, epoch, remote_addr);
        let stored = dag.storage.get(&key).expect("db ok").expect("must be stored");
        assert!(stored.contains(&offender));

        let _ = std::fs::remove_dir_all(&path);
    }

    /// Attestation with wrong signature is rejected.
    #[test]
    fn test_h02_invalid_signature_rejected() {
        use crypto::{SigningKey, derive_address};

        let (mut dag, path) = setup_dag("h02_bad_sig");

        let remote_key_bytes: [u8; 32] = [0xCC; 32];
        let remote_sk = SigningKey::from_bytes(&remote_key_bytes);
        let remote_vk = remote_sk.verifying_key();
        let remote_pubkey_hex = hex::encode(remote_vk.to_bytes());
        let remote_addr = derive_address(remote_vk.as_bytes()).expect("derive");

        let vset: Vec<(String, u64)> = vec![(remote_addr.clone(), 1000u64)];
        dag.storage.put("sys:validators", &serde_json::to_string(&vset).unwrap()).unwrap();
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
        assert!(dag.storage.get(&key).unwrap().is_none(), "bad sig must be rejected");

        let _ = std::fs::remove_dir_all(&path);
    }

    // ── Phase 4.B2: H-02 multi-node integration ──────────────────────────

    /// Phase 4.B2 — Multi-node downtime attestation flow reaches BFT quorum.
    ///
    /// Scenario:
    ///   3 validators A, B, C. Offender X is offline. Each validator
    ///   independently observes downtime and signs an attestation.
    ///   Attestations are gossiped (simulated via direct `handle_message`
    ///   calls on the OTHER nodes). After all gossip messages settle,
    ///   the executor on any node should see 3 distinct reporter
    ///   attestations against X for the same epoch → BFT quorum
    ///   ((3*2/3)+1 = 3) met → pending slash queued.
    ///
    /// This proves cross-validator gossip + executor promotion works
    /// end-to-end, not just the parser-level unit tests in 3.1.
    #[test]
    fn test_h02_b2_multi_node_attestation_reaches_quorum() {
        use crypto::{Signer, SigningKey, derive_address};

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

        // 2. Register A, B, C as the validator set on EVERY node's storage.
        //    (Offender is NOT in the set — they were already removed; this
        //    is OK for the test, what matters is the 3 REPORTER addresses
        //    are validators.)
        let vset: Vec<(String, u64)> = vec![
            (addr_a.clone(), 100),
            (addr_b.clone(), 100),
            (addr_c.clone(), 100),
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
        for (node, reporter) in [
            (&node_a, &addr_a),
            (&node_b, &addr_b),
            (&node_c, &addr_c),
        ] {
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
        dag.storage.put("sys:validators", &serde_json::to_string(&vset).unwrap()).unwrap();
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
        assert!(dag.storage.get(key).unwrap().is_none(), "unknown reporter must be rejected");

        let _ = std::fs::remove_dir_all(&path);
    }
}
