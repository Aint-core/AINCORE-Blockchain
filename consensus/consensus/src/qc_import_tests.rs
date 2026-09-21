use super::*;

fn prepare_block(db: &StateDB, height: u64) {
    let ctx = ctx_for(height);
    let block = blockchain::Block::new_with_roots_at(
        height,
        ctx.anchor_round,
        "00".repeat(32),
        vec![],
        "local".into(),
        ctx.state_root,
        ctx.receipts_root,
        1000,
        vec![],
        ctx.anchor_hash,
        vec![],
    );
    db.put(
        &format!("block_{height}"),
        &serde_json::to_string(&block).unwrap(),
    )
    .unwrap();
}

fn certificate(db: &StateDB, height: u64) -> QuorumCertificate {
    let block: blockchain::Block =
        serde_json::from_str(&db.get(&format!("block_{height}")).unwrap().unwrap()).unwrap();
    let mut ctx = ctx_for(height);
    ctx.block_hash = block.header.hash;
    let set = load_validator_set_v1(db).unwrap();
    let vote = vote_for(&ctx, &set);
    let msg = signed_vote_msg(&[7; 32], "local", &vote);
    build_qc(&vote, &set, &[0], &[hex::decode(msg.signature).unwrap()]).unwrap()
}

fn run_child(dir: &TestDir, boundary: Option<u8>) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "qc_producer::tests::persistence::imported::import_child",
            "--nocapture",
        ])
        .env("AINCORE_TEST_QC_IMPORT_DB", &dir.0)
        .env("AINCORE_CHAIN_ID", "AINCORE-MAINNET-1");
    if let Some(boundary) = boundary {
        command.env("AINCORE_TEST_QC_IMPORT_BOUNDARY", boundary.to_string());
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
fn import_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_QC_IMPORT_DB") else {
        return;
    };
    let db = StateDB::open(&path).unwrap();
    assert!(import_finality_qc(&db, &certificate(&db, 10)).unwrap());
}

#[test]
fn crash_import_publishes_all_finality_and_qc_rows_or_none() {
    let clean = TestDir::new();
    clean.seed(false);
    prepare_block(&clean.open(), 10);
    let before = rows(&clean.open());
    run_child(&clean, None);
    let after = rows(&clean.open());
    assert_eq!(
        after.len() - before.len(),
        9,
        "four finality fields and five QC indexes"
    );
    for boundary in [0, 1, 2] {
        let dir = TestDir::new();
        dir.seed(false);
        prepare_block(&dir.open(), 10);
        run_child(&dir, Some(boundary));
        let db = dir.open();
        assert_eq!(
            rows(&db),
            if boundary < 2 {
                before.clone()
            } else {
                after.clone()
            }
        );
        let cert = certificate(&db, 10);
        assert_eq!(import_finality_qc(&db, &cert).unwrap(), boundary < 2);
        assert_eq!(rows(&db), after);
        assert!(!import_finality_qc(&db, &cert).unwrap());
        assert_eq!(rows(&db), after);
    }
}

#[test]
fn native_import_write_failure_leaves_no_finality_and_retry_succeeds() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let cert = certificate(&db, 10);
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
    assert!(import_finality_qc(&db, &cert).is_err());
    assert_eq!(rows(&db), before);
    drop(db);
    let db = dir.open();
    assert!(import_finality_qc(&db, &cert).unwrap());
    assert_eq!(
        db.get("consensus:qc:latest_height").unwrap().as_deref(),
        Some("10")
    );
    assert_eq!(
        db.get("consensus:finalized_round").unwrap().as_deref(),
        Some("12")
    );
}

#[test]
fn late_index_conflict_rolls_back_staged_finality() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let cert = certificate(&db, 10);
    let mut conflicting = cert.clone();
    conflicting.state_root = "99".repeat(32);
    db.put(
        "consensus:qc:10",
        &serde_json::to_string(&conflicting).unwrap(),
    )
    .unwrap();
    let before = rows(&db);
    assert!(import_finality_qc(&db, &cert).is_err());
    assert_eq!(rows(&db), before);
    assert!(db.get("consensus:finalized_round").unwrap().is_none());
    db.delete("consensus:qc:10").unwrap();
    assert!(import_finality_qc(&db, &cert).unwrap());
}

#[test]
fn concurrent_imports_cannot_regress_finality_or_latest_indexes() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = Arc::new(dir.open());
    prepare_block(&db, 10);
    prepare_block(&db, 20);
    let certs = [certificate(&db, 10), certificate(&db, 20)];
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = certs
        .into_iter()
        .map(|cert| {
            let db = db.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                import_finality_qc(&db, &cert).unwrap()
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(outcomes.iter().any(|v| *v));
    assert_eq!(
        db.get("consensus:finalized_round").unwrap().as_deref(),
        Some("22")
    );
    assert_eq!(
        db.get("consensus:last_anchor_round").unwrap().as_deref(),
        Some("20")
    );
    assert_eq!(
        db.get("consensus:qc:latest_height").unwrap().as_deref(),
        Some("20")
    );
    assert_eq!(
        db.get("consensus:qc:latest_round").unwrap().as_deref(),
        Some("20")
    );
    assert_eq!(
        db.get("consensus:qc:latest").unwrap(),
        db.get("consensus:qc:20").unwrap()
    );
    assert_eq!(
        db.get("consensus:qc:latest").unwrap(),
        db.get("consensus:qc_by_round:20").unwrap()
    );
}

#[test]
fn malformed_local_finality_is_not_treated_as_zero() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let cert = certificate(&db, 10);
    db.put("consensus:finalized_round", "corrupted").unwrap();
    let before = rows(&db);
    assert!(import_finality_qc(&db, &cert).is_err());
    assert_eq!(rows(&db), before);
}

#[test]
fn import_rejects_valid_signature_with_contradictory_block_fields() {
    let mut accepted = vec![];
    for field in ["state_root", "receipts_root", "anchor_hash", "anchor_round"] {
        let dir = TestDir::new();
        dir.seed(false);
        let db = dir.open();
        prepare_block(&db, 10);
        let mut vote = certificate(&db, 10).finality_vote();
        match field {
            "state_root" => vote.state_root = "98".repeat(32),
            "receipts_root" => vote.receipts_root = "97".repeat(32),
            "anchor_hash" => vote.anchor_hash = "96".repeat(32),
            _ => vote.anchor_round += 1,
        }
        let set = load_validator_set_for_epoch(&db, 0).unwrap();
        let msg = signed_vote_msg(&[7; 32], "local", &vote);
        let cert = build_qc(&vote, &set, &[0], &[hex::decode(msg.signature).unwrap()]).unwrap();
        verify_qc(&cert, &set, &qc::expected_chain_id()).unwrap();
        let before = rows(&db);
        if import_finality_qc(&db, &cert).is_ok() || rows(&db) != before {
            accepted.push(field);
        }
    }
    assert!(
        accepted.is_empty(),
        "contradictory signed fields accepted or mutated rows: {accepted:?}"
    );
}

#[test]
fn import_rejects_corrupt_held_block_despite_matching_stored_hash() {
    let mut accepted = vec![];
    for field in [
        "height",
        "timestamp",
        "transactions",
        "vertices",
        "evidence",
        "anchor_hash",
    ] {
        let dir = TestDir::new();
        dir.seed(false);
        let db = dir.open();
        prepare_block(&db, 10);
        let cert = certificate(&db, 10);
        let mut block: blockchain::Block =
            serde_json::from_str(&db.get("block_10").unwrap().unwrap()).unwrap();
        match field {
            "height" => block.header.height = 11,
            "timestamp" => block.header.timestamp += 1,
            "transactions" => block.transactions.push("tampered".into()),
            "vertices" => block.committed_vertices.push("95".repeat(32)),
            "evidence" => block.slash_evidence.push("tampered".into()),
            _ => block.anchor_hash = "94".repeat(32),
        }
        db.put("block_10", &serde_json::to_string(&block).unwrap())
            .unwrap();
        let before = rows(&db);
        if import_finality_qc(&db, &cert).is_ok() || rows(&db) != before {
            accepted.push(field);
        }
    }
    assert!(
        accepted.is_empty(),
        "corrupt blocks accepted or mutated rows: {accepted:?}"
    );
}

#[test]
fn import_accepts_consistent_nonempty_body_commitments_after_reopen() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let mut block: blockchain::Block =
        serde_json::from_str(&db.get("block_10").unwrap().unwrap()).unwrap();
    block.transactions = vec!["fixture-tx".into()];
    block.committed_vertices = vec!["91".repeat(32), "92".repeat(32)];
    block.slash_evidence = vec!["fixture-evidence".into()];
    block.header.tx_hash = blockchain::calculate_tx_hash(&block.transactions);
    block.header.vertices_root = blockchain::calculate_vertices_root(&block.committed_vertices);
    block.header.evidence_root = blockchain::calculate_evidence_root(&block.slash_evidence);
    block.header.hash = blockchain::calculate_header_hash(&block.header);
    db.put("block_10", &serde_json::to_string(&block).unwrap())
        .unwrap();
    let cert = certificate(&db, 10);
    drop(db);
    let db = dir.open();
    assert!(import_finality_qc(&db, &cert).unwrap());
    let published = rows(&db);
    assert!(!import_finality_qc(&db, &cert).unwrap());
    assert_eq!(rows(&db), published);
}
