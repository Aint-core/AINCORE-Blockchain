use super::*;
use std::collections::BTreeMap;
use std::process::Command;

struct LocalDir(String);

impl LocalDir {
    fn seeded() -> Self {
        let (node, path) = setup_dag(&format!("local-atomic-{}", rand::random::<u64>()));
        node.storage.put("sys:epoch_interval", "1000000").unwrap();
        drop(node);
        Self(path)
    }

    fn rows(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        let db = StateDB::open(&self.0).unwrap();
        db.db
            .iterator(storage::rocksdb::IteratorMode::Start)
            .map(|row| {
                let (key, value) = row.unwrap();
                (key.to_vec(), value.to_vec())
            })
            // These producer/telemetry hints are written after add_vertex
            // returns. Recovery must instead use the already-durable vertices.
            .filter(|(key, _)| {
                key != b"latest_proposed_round" && !key.starts_with(b"validator:last_seen:")
            })
            .collect()
    }

    fn run(&self, mode: &str, code: i32) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::tests::local_acceptance_tests::local_acceptance_child",
                "--nocapture",
            ])
            .env("AINCORE_TEST_LOCAL_DB", &self.0)
            .env("AINCORE_TEST_LOCAL_MODE", mode)
            .env("AINCORE_CHAIN_ID", "AINCORE-MAINNET-1")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for LocalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn reopen(path: &str) -> DagConsensus {
    let db = Arc::new(StateDB::open(path).unwrap());
    let key = [42; 32];
    let id = crypto::derive_address(
        crypto::SigningKey::from_bytes(&key)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    let mut node = DagConsensus::new(
        id,
        Arc::new(Mutex::new(HashMap::new())),
        Arc::new(Mutex::new(Mempool::new())),
        Arc::new(Executor::new(db.clone())),
        db,
        None,
        None,
        key,
    );
    node.now_secs = Arc::new(|| 1_700_000_000);
    node.placement_sleep = Arc::new(|_| {});
    node
}

#[test]
fn local_acceptance_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_LOCAL_DB") else {
        return;
    };
    let mode = std::env::var("AINCORE_TEST_LOCAL_MODE").unwrap();
    let mut node = reopen(&path);
    if mode.starts_with("adopt_crash_") {
        assert_eq!(node.last_adopted_height, 0, "absence of adoption marker is not proof of adoption");
        node.local_acceptance_hook = Some(|boundary, view| {
            assert!(view.get("consensus:qc_pending:00000000000000000001").unwrap().is_some());
            assert_eq!(view.get("consensus:last_adopted_height").unwrap().as_deref(), Some("1"));
            let mode = std::env::var("AINCORE_TEST_LOCAL_MODE").unwrap();
            if (mode == "adopt_crash_before" && boundary == 2)
                || (mode == "adopt_crash_after" && boundary == 3)
            { std::process::exit(77); }
            Ok(())
        });
        node.reload_chain_tip();
        panic!("adoption crash boundary not reached");
    }
    if mode == "resume_qc" {
        let block_before = node.storage.get("block_1").unwrap();
        assert!(block_before.is_some());
        node.reload_chain_tip();
        assert_eq!(node.storage.get("block_1").unwrap(), block_before);
        assert_eq!(node.latest_block_height, 1);
        let raw = node.storage.get("consensus:qc:1").unwrap()
            .expect("accepted block permanently lost its QC work across crash/reopen");
        let cert: crate::qc::QuorumCertificate = serde_json::from_str(&raw).unwrap();
        let set = crate::qc_producer::load_validator_set_for_epoch(&node.storage, 0).unwrap();
        crate::qc::verify_qc(&cert, &set, &cert.chain_id).unwrap();
        return;
    }
    if mode == "resume" {
        // Replay ordering from retained DAG bodies without generating new input.
        // A subsequent round is a normal ingress trigger for pending anchors.
        if node.latest_block_height == 0 {
            node.try_create_vertex();
        }
        assert_eq!(node.latest_block_height, 1);
        assert_eq!(node.ordering_engine.lock().unwrap().finalized_round, 2);
        assert_eq!(
            node.storage
                .get("sys:last_executed_height")
                .unwrap()
                .as_deref(),
            Some("1")
        );
        assert_eq!(
            node.storage
                .get("consensus:last_adopted_height")
                .unwrap()
                .as_deref(),
            Some("1")
        );
        return;
    }
    node.local_acceptance_hook = Some(|boundary, view| {
        assert_eq!(view.get("latest_height").unwrap().as_deref(), Some("1"));
        assert_eq!(
            view.get("sys:last_executed_height").unwrap().as_deref(),
            Some("1")
        );
        assert_eq!(
            view.get("consensus:finalized_round").unwrap().as_deref(),
            Some("2")
        );
        assert!(view.get("block_1").unwrap().is_some());
        let mode = std::env::var("AINCORE_TEST_LOCAL_MODE").unwrap();
        match (mode.as_str(), boundary) {
            ("crash_before", 0) | ("crash_after", 1) => std::process::exit(77),
            ("reject", 0) | ("reject_retry", 0) => Err("injected acceptance rejection".to_string()),
            _ => Ok(()),
        }
    });
    for _ in 0..3 {
        node.try_create_vertex();
    }
    if mode.starts_with("reject") {
        assert_eq!(node.latest_block_height, 0);
        assert_eq!(node.ordering_engine.lock().unwrap().finalized_round, 0);
        assert!(node
            .storage
            .get("sys:last_executed_height")
            .unwrap()
            .is_none());
        assert!(node.storage.get("block_1").unwrap().is_none());
        assert!(node
            .storage
            .get("consensus:finalized_round")
            .unwrap()
            .is_none());
        if mode == "reject_retry" {
            node.local_acceptance_hook = None;
            node.try_create_vertex();
            assert_eq!(node.latest_block_height, 1);
            assert_eq!(node.ordering_engine.lock().unwrap().finalized_round, 2);
        }
    } else {
        assert_eq!(node.latest_block_height, 1);
        assert_eq!(node.ordering_engine.lock().unwrap().finalized_round, 2);
    }
}

#[test]
fn local_producer_crash_and_rejected_acceptance_are_atomic() {
    let clean = LocalDir::seeded();
    clean.run("clean", 0);
    let after = clean.rows();
    let rejected = LocalDir::seeded();
    let initial = rejected.rows();
    rejected.run("reject", 0);
    let before = rejected.rows();
    for (key, value) in &initial {
        assert_eq!(
            before.get(key),
            Some(value),
            "rejection changed pre-existing state"
        );
    }
    for key in before.keys().filter(|key| !initial.contains_key(*key)) {
        assert!(
            key.starts_with(b"vertex:"),
            "rejection leaked non-ingress row: {:?}",
            String::from_utf8_lossy(key)
        );
    }
    assert_ne!(before, after);

    for (mode, expected) in [("crash_before", &before), ("crash_after", &after)] {
        let dir = LocalDir::seeded();
        dir.run(mode, 77);
        let actual = dir.rows();
        let differing: Vec<_> = actual
            .keys()
            .chain(expected.keys())
            .filter(|key| actual.get(*key) != expected.get(*key))
            .map(|key| String::from_utf8_lossy(key).into_owned())
            .collect();
        assert!(
            differing.is_empty(),
            "torn local acceptance at {mode}: {differing:?}"
        );
        dir.run("resume", 0);
        // Resuming a pending anchor admits a new round, so compare the block
        // and acceptance rows, not the additional ingress vertices.
        let resumed = dir.rows();
        for (key, value) in &after {
            if key.starts_with(b"block_")
                || key.starts_with(b"consensus:")
                || key.starts_with(b"state_root")
                || key == b"sys:last_executed_height"
            {
                assert_eq!(
                    resumed.get(key),
                    Some(value),
                    "replay differs at {:?}",
                    String::from_utf8_lossy(key)
                );
            }
        }
    }
    let retry = LocalDir::seeded();
    retry.run("reject_retry", 0);
    assert_eq!(
        retry.rows().get(b"block_1".as_slice()),
        after.get(b"block_1".as_slice())
    );
}

#[test]
fn local_producer_read_only_commit_error_retains_plan_for_retry() {
    static REACHED_ACCEPTANCE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    let dir = LocalDir::seeded();
    let mut node = reopen(&dir.0);
    REACHED_ACCEPTANCE.store(false, std::sync::atomic::Ordering::SeqCst);
    node.local_acceptance_hook = Some(|boundary, view| {
        if boundary == 0 {
            assert!(view.get("block_1").unwrap().is_some());
            REACHED_ACCEPTANCE.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    });
    let read_only = Arc::new(StateDB {
        db: storage::rocksdb::DB::open_for_read_only(
            &storage::rocksdb::Options::default(),
            &dir.0,
            false,
        )
        .unwrap()
        .into(),
    });
    node.executor = Arc::new(Executor::new(read_only));
    for _ in 0..3 {
        node.try_create_vertex();
    }
    assert!(
        REACHED_ACCEPTANCE.load(std::sync::atomic::Ordering::SeqCst),
        "fixture never reached the native commit attempt"
    );
    assert_eq!(node.latest_block_height, 0);
    assert_eq!(node.ordering_engine.lock().unwrap().finalized_round, 0);
    for key in [
        "block_1",
        "sys:last_executed_height",
        "consensus:finalized_round",
        "consensus:last_adopted_height",
    ] {
        assert!(
            node.storage.get(key).unwrap().is_none(),
            "failed native write published {key}"
        );
    }
    node.executor = Arc::new(Executor::new(node.storage.clone()));
    node.try_create_vertex();
    assert_eq!(node.latest_block_height, 1);
    assert_eq!(node.ordering_engine.lock().unwrap().finalized_round, 2);
    assert!(node.storage.get("block_1").unwrap().is_some());
}

fn seed_bls_identity(node: &DagConsensus) -> Vec<crate::qc::ValidatorInfo> {
    let seed = crate::qc::derive_validator_bls_seed(&[42; 32]);
    let bls = crypto::bls::BLSEngine::consensus();
    let set = vec![crate::qc::ValidatorInfo {
        address: node.node_id.clone(),
        stake: 1000,
        ed25519_public_key: hex::encode(
            crypto::SigningKey::from_bytes(&[42; 32])
                .verifying_key()
                .as_bytes(),
        ),
        bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
        bls_pop: hex::encode(bls.prove_possession_raw(&seed)),
    }];
    let raw = serde_json::to_string(&set).unwrap();
    node.storage.put("sys:validator_set:v1", &raw).unwrap();
    node.storage.put("genesis:validator_set:v1", &raw).unwrap();
    set
}

#[test]
fn accepted_block_qc_work_survives_crash_before_attestation() {
    let control = LocalDir::seeded();
    seed_bls_identity(&reopen(&control.0));
    control.run("clean", 0);
    assert!(control.rows().contains_key(b"consensus:qc:1".as_slice()));

    let crashed = LocalDir::seeded();
    seed_bls_identity(&reopen(&crashed.0));
    crashed.run("crash_after", 77);
    let before = crashed.rows();
    assert!(before.contains_key(b"block_1".as_slice()));
    assert!(!before.contains_key(b"consensus:qc:1".as_slice()));
    crashed.run("resume_qc", 0);
    let after = crashed.rows();
    assert_eq!(after.get(b"block_1".as_slice()), before.get(b"block_1".as_slice()));
}

#[test]
fn adopted_block_qc_work_and_cursor_commit_together_across_crash() {
    let producer = LocalDir::seeded();
    seed_bls_identity(&reopen(&producer.0));
    producer.run("clean", 0);
    let producer_rows = producer.rows();
    let block = String::from_utf8(producer_rows.get(b"block_1".as_slice()).unwrap().clone()).unwrap();
    for mode in ["adopt_crash_before", "adopt_crash_after"] {
        let follower = LocalDir::seeded();
        let node = reopen(&follower.0);
        seed_bls_identity(&node);
        // Model the accepted sync store; actual producer execution supplied the
        // block. This test isolates adoption, not sync transport or execution.
        node.storage.save_block_json(1, &block).unwrap();
        node.storage.put("sys:last_executed_height", "1").unwrap();
        drop(node);
        let before = follower.rows();
        follower.run(mode, 77);
        let crashed = follower.rows();
        if mode == "adopt_crash_before" {
            assert_eq!(crashed, before);
        } else {
            assert!(crashed.contains_key(b"consensus:qc_pending:00000000000000000001".as_slice()));
            assert_eq!(crashed.get(b"consensus:last_adopted_height".as_slice()), Some(&b"1".to_vec()));
            assert!(!crashed.contains_key(b"consensus:qc:1".as_slice()));
        }
        follower.run("resume_qc", 0);
        let resumed = follower.rows();
        assert_eq!(resumed.get(b"consensus:qc:1".as_slice()), producer_rows.get(b"consensus:qc:1".as_slice()));
        assert_eq!(resumed.get(b"block_1".as_slice()), before.get(b"block_1".as_slice()));
    }
}

#[test]
fn malformed_genesis_does_not_fall_through_to_legacy_ingress_committee() {
    let control_dir = LocalDir::seeded();
    let mut control = reopen(&control_dir.0);
    control.try_create_vertex();
    assert_eq!(control.dag.lock().unwrap().len(), 1);

    let dir = LocalDir::seeded();
    let mut node = reopen(&dir.0);
    assert!(node.storage.get("sys:validator_set:v1").unwrap().is_none());
    node.storage
        .put("genesis:validator_set:v1", "invalid")
        .unwrap();
    node.try_create_vertex();
    assert!(
        node.dag.lock().unwrap().is_empty(),
        "invalid frozen genesis was bypassed via the legacy native set"
    );
    assert!(node.storage.scan_vertices().is_empty());
}

#[test]
fn producer_and_lagged_adoption_use_block_epoch_after_rotation() {
    let dir = LocalDir::seeded();
    let mut node = reopen(&dir.0);
    let set = seed_bls_identity(&node);
    // Model the executor's already-tested rotation metadata inside actual block
    // acceptance. This isolates caller timing; it does not execute Move reconfiguration.
    node.local_acceptance_hook = Some(|boundary, view| {
        if boundary == 0 && view.get("latest_height").unwrap().as_deref() == Some("1") {
            let set = view.get("sys:validator_set:v1").unwrap().unwrap();
            view.put("sys:validator_set:epoch:1", &set).unwrap();
            view.put("consensus:epoch_start_height:1", "2").unwrap();
            view.put("consensus:epoch", "1").unwrap();
        }
        Ok(())
    });
    for _ in 0..3 {
        node.try_create_vertex();
    }
    assert_eq!(node.latest_block_height, 1);
    assert_eq!(
        node.storage.get("consensus:epoch").unwrap().as_deref(),
        Some("1")
    );
    let first: crate::qc::QuorumCertificate = serde_json::from_str(
        &node
            .storage
            .get("consensus:qc:1")
            .unwrap()
            .expect("boundary QC was skipped"),
    )
    .unwrap();
    assert_eq!(
        first.epoch, 0,
        "boundary block was attributed to the new committee"
    );
    crate::qc::verify_qc(&first, &set, &first.chain_id).unwrap();
    let block = node.storage.get("block_1").unwrap().unwrap();
    for _ in 0..2 {
        node.try_create_vertex();
    }
    assert_eq!(node.latest_block_height, 2);
    let next: crate::qc::QuorumCertificate = serde_json::from_str(
        &node
            .storage
            .get("consensus:qc:2")
            .unwrap()
            .expect("successor QC was skipped"),
    )
    .unwrap();
    assert_eq!(next.epoch, 1);
    crate::qc::verify_qc(&next, &set, &next.chain_id).unwrap();

    let lagged_dir = LocalDir::seeded();
    let mut lagged = reopen(&lagged_dir.0);
    seed_bls_identity(&lagged);
    lagged.storage.put("consensus:epoch", "2").unwrap();
    lagged
        .storage
        .put("consensus:epoch_start_height:1", "2")
        .unwrap();
    lagged
        .storage
        .put("consensus:epoch_start_height:2", "3")
        .unwrap();
    lagged
        .storage
        .put(
            "sys:validator_set:epoch:2",
            &serde_json::to_string(&set).unwrap(),
        )
        .unwrap();
    // The held block came from the real producer above. Skip transport/execution
    // here to isolate reload_chain_tip's delayed ordering/QC adoption contract.
    lagged.storage.save_block_json(1, &block).unwrap();
    lagged.storage.put("sys:last_executed_height", "1").unwrap();
    lagged.reload_chain_tip();
    let adopted: crate::qc::QuorumCertificate = serde_json::from_str(
        &lagged
            .storage
            .get("consensus:qc:1")
            .unwrap()
            .expect("historical adoption QC was skipped"),
    )
    .unwrap();
    assert_eq!(adopted.epoch, 0);
    assert_eq!(adopted.block_hash, first.block_hash);
    crate::qc::verify_qc(&adopted, &set, &adopted.chain_id).unwrap();
}
