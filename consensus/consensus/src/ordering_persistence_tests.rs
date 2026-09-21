use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "aincore-anchor-atomic-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn open(&self) -> Arc<StateDB> {
        Arc::new(StateDB::open(self.0.to_str().unwrap()).unwrap())
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    rounds: BTreeSet<u64>,
    finalized: u64,
    cursor: u64,
    sequence: Vec<String>,
    dedup: BTreeSet<String>,
    digest: String,
    beacon: Vec<u8>,
    rows: BTreeMap<String, String>,
}

fn snapshot(engine: &OrderingEngine, db: &StateDB) -> Snapshot {
    let rows = db
        .db
        .prefix_iterator(b"consensus:")
        .map(|item| {
            let (key, value) = item.unwrap();
            let key = String::from_utf8(key.to_vec()).unwrap();
            let mut value = String::from_utf8(value.to_vec()).unwrap();
            if key == "consensus:committed_rounds" {
                let mut rounds: Vec<u64> = serde_json::from_str(&value).unwrap();
                rounds.sort_unstable();
                value = serde_json::to_string(&rounds).unwrap();
            }
            (key, value)
        })
        .collect();
    Snapshot {
        rounds: engine.committed_rounds.iter().copied().collect(),
        finalized: engine.finalized_round,
        cursor: engine.next_anchor_round,
        sequence: engine.committed_sequence.clone(),
        dedup: engine.committed_set.iter().cloned().collect(),
        digest: engine.finality_digest.clone(),
        beacon: engine.get_random_beacon().to_vec(),
        rows,
    }
}

fn advance(engine: &mut OrderingEngine, round: u64) -> Option<CommitInfo> {
    engine.adopt_synced_anchor(
        round,
        &format!("anchor-{round}"),
        &[format!("vertex-{round}-a"), format!("vertex-{round}-b")],
        &[("validator".to_string(), 1)],
    )
}

#[test]
fn prepared_anchor_is_invisible_until_acceptance_and_rejects_stale_reuse() {
    let dir = TestDir::new();
    let db = dir.open();
    let mut engine = OrderingEngine::new_with_storage(db.clone());
    let before = snapshot(&engine, &db);
    let plan = engine.prepare_anchor_bookkeeping(
        2, "anchor-2", "validator".to_string(), vec!["vertex-2".to_string()],
    );
    assert_eq!(snapshot(&engine, &db), before);
    let rejected: Result<(), storage::StorageError> = db.transaction(|view| {
        engine.stage_prepared_anchor(&plan, &view)
            .map_err(storage::StorageError::DatabaseOperation)?;
        assert_eq!(snapshot(&engine, &db), before);
        assert_eq!(view.get("consensus:finalized_round")?.as_deref(), Some("2"));
        Err(storage::StorageError::DatabaseOperation("reject block".to_string()))
    });
    assert!(rejected.is_err());
    assert_eq!(snapshot(&engine, &db), before);
    db.transaction(|view| {
        engine.stage_prepared_anchor(&plan, &view)
            .map_err(storage::StorageError::DatabaseOperation)?;
        assert_eq!(snapshot(&engine, &db), before);
        Ok(())
    }).unwrap();
    assert_eq!(engine.finalized_round, 0, "staging must not publish memory");
    engine.publish_prepared_anchor(&plan);
    let after = snapshot(&engine, &db);
    assert_eq!(after, snapshot(&OrderingEngine::new_with_storage(db.clone()), &db));
    assert!(!engine.prepared_is_current(&plan));
    let rejected = db.transaction(|view| {
        engine.stage_prepared_anchor(&plan, &view)
            .map_err(storage::StorageError::DatabaseOperation)
    });
    assert!(rejected.is_err());
    assert_eq!(snapshot(&engine, &db), after);
}

// The child exits without dropping RocksDB. These are process-crash tests, not
// claims about torn sectors, kernel power loss, or block-execution atomicity.
#[test]
fn anchor_metadata_crash_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_ANCHOR_DB") else {
        return;
    };
    let db = Arc::new(StateDB::open(&path).unwrap());
    let mut engine = OrderingEngine::new_with_storage(db);
    assert!(advance(&mut engine, 2).is_some());
    engine.anchor_persistence_hook = Some(|boundary| {
        let target: u8 = std::env::var("AINCORE_TEST_ANCHOR_BOUNDARY")
            .unwrap()
            .parse()
            .unwrap();
        if boundary == target {
            std::process::exit(77);
        }
    });
    // Also exercises eviction of round 2's cseq row (260 - 256 > 2).
    advance(&mut engine, 260);
    panic!("configured persistence boundary was not reached");
}

#[test]
fn anchor_metadata_survives_process_exit_at_write_boundaries() {
    let control = TestDir::new();
    let db = control.open();
    let mut engine = OrderingEngine::new_with_storage(Arc::clone(&db));
    assert!(advance(&mut engine, 2).is_some());
    let before = snapshot(&engine, &db);
    assert!(advance(&mut engine, 260).is_some());
    let live_after = snapshot(&engine, &db);
    assert_ne!(before, live_after);
    assert!(!live_after.rows.contains_key("consensus:cseq:2"));
    assert!(live_after.rows.contains_key("consensus:cseq:260"));
    // A normal reopen is the positive control, including the reconstructed beacon.
    drop(engine);
    drop(db);
    let db = control.open();
    let engine = OrderingEngine::new_with_storage(Arc::clone(&db));
    let after = snapshot(&engine, &db);
    assert_eq!(after.rows, live_after.rows);
    assert_eq!(after.digest, live_after.digest);
    assert_eq!(after.beacon, live_after.beacon);
    assert_eq!(after.finalized, 260);
    assert_eq!(after.cursor, 261);

    for boundary in [0, 1] {
        let crash_dir = TestDir::new();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ordering::persistence_tests::anchor_metadata_crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AINCORE_TEST_ANCHOR_DB", &crash_dir.0)
            .env("AINCORE_TEST_ANCHOR_BOUNDARY", boundary.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(77),
            "child did not reach boundary {boundary}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let db = crash_dir.open();
        let engine = OrderingEngine::new_with_storage(Arc::clone(&db));
        let restored = snapshot(&engine, &db);
        assert_eq!(
            &restored,
            if boundary == 0 { &before } else { &after },
            "partial anchor metadata recovered at durable boundary {boundary}"
        );
    }
}

fn advance_local(engine: &mut OrderingEngine) -> Option<CommitInfo> {
    // Storage-boundary fixture, not an ingress/signature-validity fixture.
    let mut parent = "vertex-2-a".to_string();
    let mut dag = HashMap::new();
    let mut index = HashMap::new();
    for round in 3..=5 {
        let mut vertex = Vertex::new(round, "validator".to_string(), vec![parent], vec![]);
        vertex.timestamp = round;
        vertex.hash = vertex.calculate_hash();
        parent = vertex.hash.clone();
        index.insert(round, vec![parent.clone()]);
        dag.insert(parent.clone(), vertex);
    }
    engine
        .try_commit(5, &dag, &index, &[("validator".to_string(), 1)])
        .pop()
}

fn assert_write_error_does_not_advance(local: bool) {
    let dir = TestDir::new();
    {
        let db = dir.open();
        let mut engine = OrderingEngine::new_with_storage(db);
        assert!(advance(&mut engine, 2).is_some());
    }
    let db = Arc::new(StateDB {
        db: storage::rocksdb::DB::open_for_read_only(
            &storage::rocksdb::Options::default(),
            &dir.0,
            false,
        )
        .unwrap().into(),
    });
    let mut engine = OrderingEngine::new_with_storage(Arc::clone(&db));
    let before = snapshot(&engine, &db);
    let advance_next = |engine: &mut OrderingEngine| {
        if local {
            advance_local(engine)
        } else {
            advance(engine, 260)
        }
    };
    let result = advance_next(&mut engine);
    assert!(
        result.is_none(),
        "failed persistence reported a committed anchor"
    );
    assert_eq!(
        snapshot(&engine, &db),
        before,
        "failed write advanced memory"
    );

    // Retry the same engine after replacing the read-only storage handle. A
    // failed attempt must not silently consume the anchor or fold its digest twice.
    engine.storage = None;
    drop(db);
    let db = dir.open();
    engine.storage = Some(Arc::clone(&db));
    let retried = advance_next(&mut engine).expect("retry after write recovery");
    let once = snapshot(&engine, &db);
    assert!(advance_next(&mut engine).is_none());
    assert_eq!(snapshot(&engine, &db), once);
    let mut control = OrderingEngine::new();
    advance(&mut control, 2).unwrap();
    let clean = advance_next(&mut control).unwrap();
    assert_eq!(retried.anchor_hash, clean.anchor_hash);
    assert_eq!(retried.sequence, clean.sequence);
    assert_eq!(retried.finality_digest, clean.finality_digest);
}

#[test]
fn anchor_metadata_write_error_does_not_advance_memory() {
    assert_write_error_does_not_advance(false);
}

#[test]
fn local_commit_write_error_does_not_advance_memory() {
    assert_write_error_does_not_advance(true);
}
