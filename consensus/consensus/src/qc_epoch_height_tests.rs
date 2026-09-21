use super::*;

fn rotated(db: &StateDB) {
    for (epoch, seed) in [(0, 7), (1, 8)] {
        let set = vec![validator_for(&[seed; 32], 100, "local")];
        db.put(
            &format!("sys:validator_set:epoch:{epoch}"),
            &serde_json::to_string(&set).unwrap(),
        )
        .unwrap();
    }
    db.put("consensus:epoch", "1").unwrap();
    db.put("genesis:validator_set:v1", &db.get("sys:validator_set:epoch:0").unwrap().unwrap()).unwrap();
    db.put("consensus:epoch_start_height:1", "21").unwrap();
}

fn context_and_vote(db: &StateDB, height: u64, epoch: u64) -> (CommitContext, QcVoteMessage) {
    let mut ctx = ctx_for(height);
    ctx.epoch = epoch;
    let block = blockchain::Block::new_with_roots_at(
        height,
        ctx.anchor_round,
        "00".repeat(32),
        vec![],
        "local".into(),
        ctx.state_root.clone(),
        ctx.receipts_root.clone(),
        1000,
        vec![],
        ctx.anchor_hash.clone(),
        vec![],
    );
    ctx.block_hash = block.header.hash.clone();
    db.put(
        &format!("block_{height}"),
        &serde_json::to_string(&block).unwrap(),
    )
    .unwrap();
    let set = load_validator_set_for_epoch(db, epoch).unwrap();
    let msg = signed_vote_msg(&[7 + epoch as u8; 32], "local", &vote_for(&ctx, &set));
    (ctx, msg)
}

#[test]
fn local_signing_rejects_committee_outside_its_height_interval() {
    for (height, epoch) in [(20, 1), (21, 0)] {
        let dir = TestDir::new();
        let db = dir.open();
        rotated(&db);
        let (ctx, _) = context_and_vote(&db, height, epoch);
        let before = rows(&db);
        assert!(
            matches!(
                produce_and_store_qc(&db, &[7 + epoch as u8; 32], "local", &ctx),
                QcOutcome::Skipped
            ),
            "signed block {height} with epoch {epoch}, whose activation range excludes it"
        );
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn aggregation_rejects_valid_signature_from_wrong_height_committee() {
    for (height, epoch) in [(20, 1), (21, 0)] {
        let dir = TestDir::new();
        let db = dir.open();
        rotated(&db);
        let (ctx, msg) = context_and_vote(&db, height, epoch);
        let before = rows(&db);
        assert!(
            matches!(
                collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash)),
                QcOutcome::Skipped
            ),
            "aggregated block {height} with wrong epoch {epoch}"
        );
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn finality_import_rejects_valid_qc_from_wrong_height_committee() {
    for (height, epoch) in [(20, 1), (21, 0)] {
        let dir = TestDir::new();
        let db = dir.open();
        rotated(&db);
        let (_, msg) = context_and_vote(&db, height, epoch);
        let set = load_validator_set_for_epoch(&db, epoch).unwrap();
        let cert = build_qc(
            &msg.vote,
            &set,
            &[0],
            &[hex::decode(msg.signature).unwrap()],
        )
        .unwrap();
        verify_qc(&cert, &set, &cert.chain_id).unwrap();
        let before = rows(&db);
        assert!(
            !import_finality_qc(&db, &cert).unwrap_or(false),
            "advanced finality for block {height} with wrong epoch {epoch}"
        );
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn boundary_and_successor_accept_only_their_respective_committees() {
    for (height, epoch) in [(20, 0), (21, 1)] {
        for mode in 0..3 {
            let dir = TestDir::new();
            let db = dir.open();
            rotated(&db);
            let (ctx, msg) = context_and_vote(&db, height, epoch);
            let set = load_validator_set_for_epoch(&db, epoch).unwrap();
            let cert = build_qc(
                &msg.vote,
                &set,
                &[0],
                &[hex::decode(&msg.signature).unwrap()],
            )
            .unwrap();
            match mode {
                0 => assert!(matches!(
                    produce_and_store_qc(&db, &[7 + epoch as u8; 32], "local", &ctx),
                    QcOutcome::Complete(_)
                )),
                1 => assert!(matches!(
                    collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash)),
                    QcOutcome::Complete(_)
                )),
                _ => assert!(import_finality_qc(&db, &cert).unwrap()),
            }
        }
    }
}

#[test]
fn resolver_uses_recorded_boundaries_across_reopen_not_current_interval() {
    let dir = TestDir::new();
    {
        let db = dir.open();
        rotated(&db);
        db.put("consensus:epoch", "3").unwrap();
        db.put("consensus:epoch_start_height:2", "38").unwrap();
        db.put("consensus:epoch_start_height:3", "101").unwrap();
        // A present-day interval cannot reconstruct historical governance changes.
        db.put("sys:config:epoch_block_interval", "9999").unwrap();
    }
    let db = dir.open();
    for (height, epoch) in [
        (1, 0),
        (20, 0),
        (21, 1),
        (37, 1),
        (38, 2),
        (100, 2),
        (101, 3),
    ] {
        assert_eq!(epoch_for_block_height(&db, height), Some(epoch));
    }
    assert_eq!(epoch_for_block_height(&db, 0), None);
    db.delete("consensus:epoch_start_height:2").unwrap();
    assert_eq!(
        epoch_for_block_height(&db, 20),
        None,
        "must not bridge a missing history interval"
    );
    assert_eq!(epoch_for_block_height(&db, 101), Some(3));
}

#[test]
fn invalid_or_missing_activation_metadata_cannot_publish_anything() {
    for invalid in [
        None,
        Some("garbage"),
        Some("0"),
        Some("1"),
        Some("-1"),
        Some("18446744073709551616"),
    ] {
        let dir = TestDir::new();
        let db = dir.open();
        rotated(&db);
        let (ctx, msg) = context_and_vote(&db, 21, 1);
        let set = load_validator_set_for_epoch(&db, 1).unwrap();
        let cert = build_qc(
            &msg.vote,
            &set,
            &[0],
            &[hex::decode(&msg.signature).unwrap()],
        )
        .unwrap();
        match invalid {
            Some(raw) => db.put("consensus:epoch_start_height:1", raw).unwrap(),
            None => db.delete("consensus:epoch_start_height:1").unwrap(),
        }
        let before = rows(&db);
        assert_eq!(epoch_for_block_height(&db, 21), None);
        assert!(matches!(
            produce_and_store_qc(&db, &[8; 32], "local", &ctx),
            QcOutcome::Skipped
        ));
        assert!(matches!(
            collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash)),
            QcOutcome::Skipped
        ));
        assert!(!import_finality_qc(&db, &cert).unwrap());
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn resolver_rejects_nonmonotonic_history_and_malformed_current_epoch() {
    let dir = TestDir::new();
    let db = dir.open();
    rotated(&db);
    db.put("consensus:epoch", "2").unwrap();
    db.put("consensus:epoch_start_height:2", "21").unwrap();
    assert_eq!(
        epoch_for_block_height(&db, 20),
        None,
        "duplicate starts are ambiguous"
    );
    db.put("consensus:epoch_start_height:1", "30").unwrap();
    assert_eq!(epoch_for_block_height(&db, 20), None, "starts regressed");
    db.put("consensus:epoch", "corrupt").unwrap();
    assert_eq!(epoch_for_block_height(&db, 20), None);
    db.put("consensus:epoch", &u64::MAX.to_string()).unwrap();
    assert_eq!(epoch_for_block_height(&db, 20), None);
}
