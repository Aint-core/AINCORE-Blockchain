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
        .env("AINCORE_TEST_QC_IMPORT_DB", &dir.0);
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
    block.committed_authors = vec!["c1".repeat(32), "c2".repeat(32)];
    block.slash_evidence = vec!["fixture-evidence".into()];
    block.header.tx_hash = blockchain::calculate_tx_hash(&block.transactions);
    block.header.vertices_root =
        blockchain::calculate_vertices_root(&block.committed_vertices, &block.committed_authors);
    block.header.evidence_root = blockchain::calculate_evidence_root(&block.slash_evidence);
    block.header.da_root = blockchain::calculate_da_root(
        &block.transactions,
        &block.committed_vertices,
        &block.committed_authors,
        &block.anchor_hash,
        &block.slash_evidence,
    );
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

/// B101 witness: a V4 import of a QC already stored, or of one for a height
/// this node does not hold, runs no pairing (a replayed QC_CERT cost one and
/// a synced commit each time). B443: the tip is written, as on every node
/// holding a block: `may_hold_block` is exact then, and the pairing comes
/// before the block is read.
#[test]
fn a_replayed_or_unheld_qc_costs_no_pairing() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    db.put("latest_height", "10").unwrap();
    let cert = certificate(&db, 10);
    let staged = |cert: &QuorumCertificate| {
        db.transaction(|view| {
            stage_imported_certificate(&view, cert)
                .map_err(storage::StorageError::DatabaseOperation)
        })
        .unwrap()
    };
    let pairings = || QC_PAIRINGS.with(|p| p.get());
    let before = pairings();
    assert!(staged(&cert), "the first import is stored");
    assert_eq!(pairings() - before, 1, "vacuous: nothing was verified");
    assert!(!staged(&cert));
    let mut unheld = cert.clone();
    unheld.block_height = 11;
    assert!(!staged(&unheld));
    assert_eq!(
        pairings() - before,
        1,
        "a replay or an unheld height was verified"
    );
}

/// B335 witness: a QC of a vote stored already, in another encoding (or
/// over another signer subset), runs no pairing: exact equality was the
/// only check, so each copy cost two pairings and a synced rewrite.
#[test]
fn a_qc_of_a_stored_vote_costs_no_pairing() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let cert = certificate(&db, 10);
    let staged = |cert: &QuorumCertificate| {
        db.transaction(|view| {
            stage_imported_certificate(&view, cert)
                .map_err(storage::StorageError::DatabaseOperation)
        })
        .unwrap()
    };
    assert!(staged(&cert), "vacuous: the first import was not stored");
    let pairings = || QC_PAIRINGS.with(|p| p.get());
    let before = pairings();
    let mut padded = cert.clone();
    padded.signer_bitmap.push(0);
    assert!(!staged(&padded));
    assert_eq!(pairings(), before, "a copy of a stored vote was verified");
    // Its other bytes, a valid point (another vote's signature by the same
    // key), take no pairing either: only the vote decides.
    let mut ctx = ctx_for(10);
    ctx.block_hash = "ff".repeat(32);
    let set = load_validator_set_v1(&db).unwrap();
    let other = signed_vote_msg(&[7; 32], "local", &vote_for(&ctx, &set));
    let mut resigned = cert.clone();
    resigned.aggregate_signature = hex::decode(other.signature).unwrap();
    assert_ne!(resigned.aggregate_signature, cert.aggregate_signature);
    assert!(!staged(&resigned));
    assert_eq!(
        pairings(),
        before,
        "another encoding of a stored vote was verified"
    );
}

/// B353 witness: a QC sync verified before staging it with its block is not
/// paired again (a synced block's QC was paired four times: at sync's
/// check, when stored with the block, at adoption and at its retry).
#[test]
fn a_qc_sync_verified_is_not_paired_again_when_stored() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let cert = certificate(&db, 10);
    let pairings = || QC_PAIRINGS.with(|p| p.get());
    let before = pairings();
    let stored = db
        .transaction(|view| {
            stage_block_qc(&view, &cert).map_err(storage::StorageError::DatabaseOperation)
        })
        .unwrap();
    assert!(stored, "vacuous: the QC was not stored");
    assert_eq!(pairings(), before, "a QC sync verified was paired again");
}

/// B355 witness: a QC in an encoding no producer writes (another version),
/// for a held block awaiting its QC, is refused before the block is read,
/// and charged: it read the whole block under the consensus lock and went
/// uncharged, so a member sending them was never muted.
#[test]
fn a_non_canonical_qc_is_refused_charged_before_the_block_is_read() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let mut cert = certificate(&db, 10);
    cert.version = crate::qc::QC_VERSION + 1;
    let pairings = || QC_PAIRINGS.with(|p| p.get());
    let before = pairings();
    let (result, failed) = crate::work::failed_in(|| {
        db.transaction(|view| {
            stage_imported_certificate(&view, &cert)
                .map_err(storage::StorageError::DatabaseOperation)
        })
    });
    assert!(result.is_err(), "a non-canonical QC was taken");
    assert_eq!(failed, 1, "the refusal was not charged");
    assert_eq!(pairings(), before, "it was refused past the block read");
}

/// B443 witness: a QC for a held block awaiting its QC that fails its stake
/// checks (no signer, a stake the committee does not give) or its pairing (a
/// public QC's fields over another vote, as a sync session can send), or
/// that names another epoch than its height's, is refused before the block
/// is read, charged once. Past B355's checks the block was read whole under
/// the writer gate first, and the stake and epoch refusals went uncharged,
/// so B51 never muted the member. A QC that verifies reads its block once
/// (it was read and parsed three times). On a V4 chain, where the held
/// block binds the QC (IM-3).
#[test]
fn a_qc_failing_its_signature_checks_is_refused_charged_before_the_block_is_read() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    {
        let _seed = db.seeding();
        db.put(crate::v4::VERTEX_FORMAT_KEY, "4").unwrap();
        db.put(crate::v4::epoch::EPOCH_INTERVAL_KEY, "1000")
            .unwrap();
    }
    prepare_block(&db, 10);
    db.put("latest_height", "10").unwrap();
    let cert = certificate(&db, 10);
    let staged = |cert: &QuorumCertificate| {
        crate::work::failed_in(|| {
            db.transaction(|view| {
                stage_imported_certificate(&view, cert)
                    .map_err(storage::StorageError::DatabaseOperation)
            })
        })
    };
    let reads = || HELD_BLOCK_READS.with(|n| n.get());
    let mut no_signer = cert.clone();
    no_signer.signer_bitmap.iter_mut().for_each(|b| *b = 0);
    let mut wrong_stake = cert.clone();
    wrong_stake.signed_stake += 1;
    let mut forged = cert.clone();
    forged.finality_digest = "ee".repeat(32);
    let mut other_epoch = cert.clone();
    other_epoch.epoch += 1;
    for (what, junk) in [
        ("no signer", no_signer),
        ("a wrong stake", wrong_stake),
        ("a forged signature", forged),
        ("another epoch", other_epoch),
    ] {
        let before = reads();
        let (result, failed) = staged(&junk);
        assert!(result.is_err(), "{what}: the QC was taken");
        assert_eq!(failed, 1, "{what}: not charged once");
        assert_eq!(reads(), before, "{what}: the block was read first");
    }
    let before = reads();
    let (result, failed) = staged(&cert);
    assert!(result.unwrap(), "control: the QC is stored");
    assert_eq!(failed, 0, "control: a valid QC was charged");
    assert_eq!(
        reads() - before,
        1,
        "the held block was read more than once"
    );
}

/// B443 witness: on a V4 chain a node before its first block (no tip) holds
/// none, so a QC naming any height runs no pairing. With no tip
/// `may_hold_block` holds for any height, and the pairing comes before the
/// block is read: each replayed valid QC cost such a node one (B101's cost).
#[test]
fn a_v4_node_before_its_first_block_pairs_no_qc() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    {
        let _seed = db.seeding();
        db.put(crate::v4::VERTEX_FORMAT_KEY, "4").unwrap();
        db.put(crate::v4::epoch::EPOCH_INTERVAL_KEY, "1000")
            .unwrap();
    }
    prepare_block(&db, 10);
    let cert = certificate(&db, 10);
    db.delete("block_10").unwrap();
    let staged = |cert: &QuorumCertificate| {
        db.transaction(|view| {
            stage_imported_certificate(&view, cert)
                .map_err(storage::StorageError::DatabaseOperation)
        })
        .unwrap()
    };
    let pairings = || QC_PAIRINGS.with(|p| p.get());
    let before = pairings();
    assert!(!staged(&cert), "a node holding no block stored a QC");
    assert_eq!(pairings(), before, "a node holding no block paired a QC");
    // Control: holding the block, with its tip, the QC is paired and stored.
    prepare_block(&db, 10);
    db.put("latest_height", "10").unwrap();
    assert!(staged(&cert), "control: the QC is stored");
    assert_eq!(pairings() - before, 1, "control: the QC was not paired");
}

/// B225 witness: a QC naming a height this node cannot hold (pruned, or
/// not reached) is dropped before the committee is looked up: B205 put the
/// committee first, so each parsed the record, uncharged.
#[test]
fn a_qc_for_a_height_not_held_costs_no_committee_lookup() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    prepare_block(&db, 10);
    let cert = certificate(&db, 10);
    db.put("latest_height", "10").unwrap();
    db.put(StateDB::BLOCK_PRUNE_CURSOR_KEY, "5").unwrap();
    let staged = |cert: &QuorumCertificate| {
        db.transaction(|view| {
            stage_imported_certificate(&view, cert)
                .map_err(storage::StorageError::DatabaseOperation)
        })
        .unwrap()
    };
    let lookups = || COMMITTEE_LOOKUPS.with(|n| n.get());
    let before = lookups();
    for height in [11, 4] {
        let mut unheld = cert.clone();
        unheld.block_height = height;
        assert!(!staged(&unheld), "height {height}");
    }
    assert_eq!(
        lookups(),
        before,
        "a height not held looked the committee up"
    );
    assert!(staged(&cert), "control: the held block's QC is stored");
    assert_eq!(lookups() - before, 1, "vacuous: no lookup at all");
}
