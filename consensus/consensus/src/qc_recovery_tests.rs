use super::*;

const PENDING: &str = "consensus:qc_pending:00000000000000000001";

// Worker unit fixture models an already executed/accepted store. The separate
// local_acceptance subprocess tests exercise actual producer execution/crash.
fn pending(db: &StateDB, height: u64) {
    let block = blockchain::Block::new_with_roots_at(
        height,
        height * 2,
        "genesis".into(),
        vec![],
        "local".into(),
        "ef".repeat(32),
        "12".repeat(32),
        1000 + height,
        vec!["ab".repeat(32)],
        "ab".repeat(32),
        vec![],
    );
    let info = crate::ordering::CommitInfo {
        anchor_round: height * 2,
        anchor_hash: block.anchor_hash.clone(),
        leader: "local".into(),
        sequence: block.committed_vertices.clone(),
        finality_digest: "34".repeat(32),
    };
    db.transaction(|view| {
        view.save_block_json(height, &serde_json::to_string(&block).unwrap())?;
        view.put("sys:last_executed_height", &height.to_string())?;
        stage_pending_qc(&view, &block, &info, qc::expected_chain_id())
            .map_err(storage::StorageError::DatabaseOperation)
    })
    .unwrap();
}

fn retry(db: &StateDB, cursor: &mut String) -> Vec<QcOutcome> {
    retry_pending_qcs(db, &[7; 32], "local", &qc::expected_chain_id(), cursor).unwrap()
}

#[test]
fn partial_replays_after_reopen_until_complete_aggregation() {
    let dir = TestDir::new();
    dir.seed(true);
    let db = dir.open();
    pending(&db, 1);
    let first = retry(&db, &mut String::new());
    let QcOutcome::Partial(message) = &first[0] else {
        panic!("expected local minority vote")
    };
    let message = message.clone();
    let after = rows(&db);
    assert!(db.get(PENDING).unwrap().is_some());
    drop(db);
    let db = dir.open();
    let replay = retry(&db, &mut String::new());
    let QcOutcome::Partial(again) = &replay[0] else {
        panic!("vote lost after reopen")
    };
    assert_eq!(again, &message);
    assert_eq!(rows(&db), after);
    let remote = signed_vote_msg(&[8; 32], "other", &message.vote);
    assert!(matches!(
        collect_vote_and_try_aggregate(&db, &remote, Some(&message.vote.block_hash)),
        QcOutcome::Complete(_)
    ));
    assert!(matches!(
        retry(&db, &mut String::new())[0],
        QcOutcome::Complete(_)
    ));
    assert!(db.get(PENDING).unwrap().is_none());
    assert!(retry(&db, &mut String::new()).is_empty());
}

#[test]
fn malformed_or_mismatched_pending_context_never_signs_or_deletes_work() {
    for case in 0..11 {
        let dir = TestDir::new();
        dir.seed(false);
        let db = dir.open();
        pending(&db, 1);
        let mut ctx: CommitContext =
            serde_json::from_str(&db.get(PENDING).unwrap().unwrap()).unwrap();
        match case {
            0 => ctx.block_hash = "99".repeat(32),
            1 => ctx.anchor_hash = "99".repeat(32),
            2 => ctx.state_root = "99".repeat(32),
            3 => ctx.receipts_root = "99".repeat(32),
            4 => ctx.epoch = 1,
            5 => ctx.chain_id = "foreign".into(),
            6 => ctx.block_height = 2,
            7 => ctx.finalized_round += 1,
            8 => ctx.anchor_round += 1,
            _ => {}
        }
        db.put(PENDING, &serde_json::to_string(&ctx).unwrap())
            .unwrap();
        if case == 9 {
            db.put(PENDING, "not-json").unwrap();
        }
        if case == 10 {
            db.put(PENDING, &"x".repeat(16 * 1024 + 1)).unwrap();
        }
        let before = rows(&db);
        assert!(
            matches!(retry(&db, &mut String::new())[0], QcOutcome::Skipped),
            "case {case}"
        );
        assert_eq!(rows(&db), before, "case {case} leaked a write");
    }
}

#[test]
fn missing_or_changed_execution_and_body_never_authorize_retry() {
    for case in 0..4 {
        let dir = TestDir::new();
        dir.seed(false);
        let db = dir.open();
        pending(&db, 1);
        match case {
            0 => db.delete("sys:last_executed_height").unwrap(),
            1 => db.put("sys:last_executed_height", "0").unwrap(),
            2 => db.delete("block_1").unwrap(),
            _ => {
                let mut block: blockchain::Block =
                    serde_json::from_str(&db.get("block_1").unwrap().unwrap()).unwrap();
                block.transactions.push("changed without rehash".into());
                db.put("block_1", &serde_json::to_string(&block).unwrap())
                    .unwrap();
            }
        }
        let before = rows(&db);
        assert!(matches!(
            retry(&db, &mut String::new())[0],
            QcOutcome::Skipped
        ));
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn bounded_retry_rotates_past_unavailable_old_work() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    for height in 1..=10 {
        pending(&db, height);
    }
    db.delete("block_1").unwrap();
    let mut cursor = String::new();
    let first = retry(&db, &mut cursor);
    assert_eq!(first.len(), 8);
    assert!(matches!(first[0], QcOutcome::Skipped));
    assert!(db.get("consensus:qc:9").unwrap().is_none());
    assert_eq!(retry(&db, &mut cursor).len(), 2);
    assert!(db.get("consensus:qc:10").unwrap().is_some());
    assert!(retry(&db, &mut cursor).is_empty());
    assert_eq!(retry(&db, &mut cursor).len(), 1);
    assert!(db.get(PENDING).unwrap().is_some());
}

#[test]
fn missing_committee_defers_and_native_failure_never_releases_outcome() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    pending(&db, 1);
    let set = db.get("genesis:validator_set:v1").unwrap().unwrap();
    db.delete("genesis:validator_set:v1").unwrap();
    let before = rows(&db);
    assert!(matches!(
        retry(&db, &mut String::new())[0],
        QcOutcome::Skipped
    ));
    assert_eq!(rows(&db), before);
    db.put("genesis:validator_set:v1", &set).unwrap();
    let before = rows(&db);
    drop(db);
    let db = StateDB {
        db: storage::rocksdb::DB::open_for_read_only(
            &storage::rocksdb::Options::default(),
            &dir.0,
            false,
        )
        .unwrap()
        .into(),
    };
    assert!(matches!(
        retry(&db, &mut String::new())[0],
        QcOutcome::Skipped
    ));
    assert_eq!(rows(&db), before);
    drop(db);
    let db = dir.open();
    assert!(matches!(
        retry(&db, &mut String::new())[0],
        QcOutcome::Complete(_)
    ));
    assert!(db.get(PENDING).unwrap().is_none());
}

#[test]
fn qc_recovery_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_QC_RECOVERY_DB") else {
        return;
    };
    let db = StateDB::open(&path).unwrap();
    let result = retry(&db, &mut String::new());
    assert_eq!(result.len(), 1);
    assert!(!matches!(result[0], QcOutcome::Skipped));
}

fn child(dir: &TestDir, boundary: Option<u8>) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "qc_producer::tests::persistence::recovery::qc_recovery_child",
            "--nocapture",
        ])
        .env("AINCORE_TEST_QC_RECOVERY_DB", &dir.0);
    command.env_remove("AINCORE_TEST_QC_BOUNDARY");
    if let Some(boundary) = boundary {
        command.env("AINCORE_TEST_QC_BOUNDARY", boundary.to_string());
    }
    let output = command.output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(if boundary.is_some() { 77 } else { 0 }),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn crash_during_retry_atomically_keeps_work_or_publishes_guarded_outcome() {
    for minority in [false, true] {
        let clean = TestDir::new();
        clean.seed(minority);
        pending(&clean.open(), 1);
        let before = rows(&clean.open());
        child(&clean, None);
        let after = rows(&clean.open());
        assert_ne!(before, after);
        for boundary in [0, 1] {
            let dir = TestDir::new();
            dir.seed(minority);
            pending(&dir.open(), 1);
            child(&dir, Some(boundary));
            assert_eq!(
                rows(&dir.open()),
                if boundary == 0 {
                    before.clone()
                } else {
                    after.clone()
                }
            );
            if boundary == 0 || minority {
                child(&dir, None);
            } else {
                assert!(retry(&dir.open(), &mut String::new()).is_empty());
            }
            assert_eq!(rows(&dir.open()), after);
        }
    }
}
