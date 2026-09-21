use super::*;
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{Arc, Barrier};

mod imported {
    include!("qc_import_tests.rs");
}
mod epoch_height {
    include!("qc_epoch_height_tests.rs");
}
mod genesis_committee {
    include!("qc_genesis_committee_tests.rs");
}
mod recovery {
    include!("qc_recovery_tests.rs");
}

struct TestDir(std::path::PathBuf);

impl TestDir {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "qc-durable-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        )))
    }

    fn open(&self) -> StateDB {
        StateDB::open(self.0.to_str().unwrap()).unwrap()
    }

    fn seed(&self, minority: bool) {
        let db = self.open();
        let mut set = vec![validator_for(&[7; 32], 40, "local")];
        if minority {
            set.push(validator_for(&[8; 32], 60, "other"));
        }
        db.put(
            "sys:validator_set:v1",
            &serde_json::to_string(&set).unwrap(),
        )
        .unwrap();
        db.put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap()).unwrap();
    }

    fn child(&self, mode: &str, boundary: Option<u8>, code: i32) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "qc_producer::tests::persistence::qc_publication_child",
                "--nocapture",
            ])
            .env("AINCORE_TEST_QC_DB", &self.0)
            .env("AINCORE_TEST_QC_MODE", mode)
            .env("AINCORE_CHAIN_ID", "AINCORE-MAINNET-1");
        if let Some(boundary) = boundary {
            command.env("AINCORE_TEST_QC_BOUNDARY", boundary.to_string());
        }
        let out = command.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(code),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rows(db: &StateDB) -> BTreeMap<Vec<u8>, Vec<u8>> {
    db.db
        .iterator(storage::rocksdb::IteratorMode::Start)
        .map(|row| {
            let (k, v) = row.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect()
}

#[test]
fn unknown_epoch_cannot_borrow_live_committee_to_sign() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    db.delete("genesis:validator_set:v1").unwrap();
    db.put("consensus:epoch", "10").unwrap();
    for epoch in [0, 9, 10, 11, u64::MAX] {
        let mut ctx = ctx_for(10);
        ctx.epoch = epoch;
        let before = rows(&db);
        assert!(matches!(produce_and_store_qc(&db, &[7; 32], "local", &ctx), QcOutcome::Skipped),
            "missing epoch {epoch} snapshot was replaced with the live committee");
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn invalid_epoch_snapshot_cannot_fall_back_to_live_committee() {
    for epoch in [0, 3] {
        for invalid in ["not json", "[]", "null"] {
            let dir = TestDir::new();
            dir.seed(false);
            let db = dir.open();
            db.put(&format!("sys:validator_set:epoch:{epoch}"), invalid).unwrap();
            let mut ctx = ctx_for(10);
            ctx.epoch = epoch;
            let before = rows(&db);
            assert!(matches!(produce_and_store_qc(&db, &[7; 32], "local", &ctx), QcOutcome::Skipped),
                "invalid epoch {epoch} snapshot {invalid:?} was silently substituted");
            assert_eq!(rows(&db), before);
        }
    }
}

#[test]
fn remote_vote_needs_exact_epoch_snapshot_before_any_write() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    db.put("consensus:epoch", "3").unwrap();
    db.put("consensus:epoch_start_height:3", "9").unwrap();
    let set = load_validator_set_v1(&db).unwrap();
    let mut ctx = ctx_for(10);
    ctx.epoch = 3;
    let msg = signed_vote_msg(&[7; 32], "local", &vote_for(&ctx, &set));
    let before = rows(&db);
    assert!(matches!(collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash)), QcOutcome::Skipped));
    assert_eq!(rows(&db), before);
    db.put("sys:validator_set:epoch:3", &serde_json::to_string(&set).unwrap()).unwrap();
    let QcOutcome::Complete(cert) = collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash)) else {
        panic!("valid signature and exact snapshot must complete a quorum");
    };
    verify_qc(&cert, &set, &ctx.chain_id).unwrap();
}

#[test]
fn retained_epoch_survives_live_changes_but_pruned_epoch_fails_closed() {
    let dir = TestDir::new();
    dir.seed(true);
    let db = dir.open();
    let snapshot = db.get("sys:validator_set:v1").unwrap().unwrap();
    db.put("sys:validator_set:epoch:3", &snapshot).unwrap();
    db.put("consensus:epoch", "3").unwrap();
    db.put("consensus:epoch_start_height:3", "9").unwrap();
    let mut ctx = ctx_for(10);
    ctx.epoch = 3;
    let QcOutcome::Partial(original) = produce_and_store_qc(&db, &[7; 32], "local", &ctx) else {
        panic!("historical minority fixture must sign");
    };
    let new_set = vec![validator_for(&[99; 32], 100, "replacement")];
    db.put("sys:validator_set:v1", &serde_json::to_string(&new_set).unwrap()).unwrap();
    db.put("consensus:epoch", "4").unwrap();
    db.put("consensus:epoch_start_height:4", "21").unwrap();
    drop(db);

    let db = dir.open();
    let QcOutcome::Partial(replay) = produce_and_store_qc(&db, &[7; 32], "local", &ctx) else {
        panic!("retained historical committee must remain usable after reopen");
    };
    assert_eq!(original, replay);
    db.delete("sys:validator_set:epoch:3").unwrap();
    let before = rows(&db);
    assert!(matches!(produce_and_store_qc(&db, &[7; 32], "local", &ctx), QcOutcome::Skipped));
    assert_eq!(rows(&db), before);
}

#[test]
fn live_epoch_zero_is_never_used_without_frozen_genesis() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    db.delete("genesis:validator_set:v1").unwrap();
    assert!(load_validator_set_for_epoch(&db, 0).is_none());
    db.put("consensus:epoch", "0").unwrap();
    assert!(load_validator_set_for_epoch(&db, 0).is_none());
    for current in ["1", "10", "not an epoch", "-1", "18446744073709551616"] {
        db.put("consensus:epoch", current).unwrap();
        assert!(load_validator_set_for_epoch(&db, 0).is_none(), "accepted epoch marker {current:?}");
    }
}

#[test]
fn qc_publication_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_QC_DB") else {
        return;
    };
    let db = StateDB::open(&path).unwrap();
    let ctx = ctx_for(10);
    let mode = std::env::var("AINCORE_TEST_QC_MODE").unwrap();
    let outcome = if mode == "aggregate" {
        let set = load_validator_set_v1(&db).unwrap();
        let msg = signed_vote_msg(&[8; 32], "other", &vote_for(&ctx, &set));
        collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash))
    } else {
        produce_and_store_qc(&db, &[7; 32], "local", &ctx)
    };
    assert!(!matches!(outcome, QcOutcome::Skipped));
}

#[test]
fn publication_crash_preserves_all_or_none_and_safe_retry() {
    for mode in ["complete", "partial", "aggregate"] {
        let clean = TestDir::new();
        clean.seed(mode != "complete");
        if mode == "aggregate" {
            clean.child("partial", None, 0);
        }
        let before = rows(&clean.open());
        clean.child(mode, None, 0);
        let after = rows(&clean.open());
        assert_ne!(before, after);
        for boundary in [0, 1] {
            let dir = TestDir::new();
            dir.seed(mode != "complete");
            if mode == "aggregate" {
                dir.child("partial", None, 0);
            }
            dir.child(mode, Some(boundary), 77);
            assert_eq!(
                rows(&dir.open()),
                if boundary == 0 {
                    before.clone()
                } else {
                    after.clone()
                }
            );
            if mode == "aggregate" && boundary == 1 {
                // A finished remote aggregate is already present, so replay is
                // Skipped rather than a second certificate publication.
                let db = dir.open();
                let set = load_validator_set_v1(&db).unwrap();
                let msg = signed_vote_msg(&[8; 32], "other", &vote_for(&ctx_for(10), &set));
                assert!(matches!(
                    collect_vote_and_try_aggregate(&db, &msg, Some(&msg.vote.block_hash)),
                    QcOutcome::Skipped
                ));
            } else {
                dir.child(mode, None, 0);
            }
            assert_eq!(rows(&dir.open()), after);
            if mode != "aggregate" {
                let db = dir.open();
                let mut conflict = ctx_for(10);
                conflict.state_root = "99".repeat(32);
                assert!(matches!(
                    produce_and_store_qc(&db, &[7; 32], "local", &conflict),
                    QcOutcome::Skipped
                ));
                assert_eq!(rows(&db), after);
            }
        }
    }
}

#[test]
fn every_context_field_and_either_slot_are_guarded() {
    for minority in [false, true] {
        let dir = TestDir::new();
        dir.seed(minority);
        let db = dir.open();
        // The changed-epoch case below also changes local activation metadata
        // to exercise the signing guard independently of epoch-range checks.
        let set = db.get("sys:validator_set:v1").unwrap().unwrap();
        db.put("sys:validator_set:epoch:1", &set).unwrap();
        assert!(!matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(10)),
            QcOutcome::Skipped
        ));
        let before = rows(&db);
        for field in 0..9 {
            let mut ctx = ctx_for(10);
            match field {
                0 => ctx.block_hash = "99".repeat(32),
                1 => ctx.state_root = "99".repeat(32),
                2 => ctx.receipts_root = "99".repeat(32),
                3 => ctx.finality_digest = "99".repeat(32),
                4 => ctx.anchor_hash = "99".repeat(32),
                5 => ctx.epoch += 1,
                6 => ctx.finalized_round += 1,
                7 => ctx.block_height += 1,
                _ => ctx.anchor_round += 1,
            }
            if field == 5 {
                db.put("consensus:epoch", "1").unwrap();
                db.put("consensus:epoch_start_height:1", "2").unwrap();
                assert_eq!(epoch_for_block_height(&db, ctx.block_height), Some(ctx.epoch));
            }
            let before_attempt = rows(&db);
            assert!(
                matches!(
                    produce_and_store_qc(&db, &[7; 32], "local", &ctx),
                    QcOutcome::Skipped
                ),
                "unguarded field {field}"
            );
            assert_eq!(rows(&db), before_attempt);
            if field == 5 {
                db.delete("consensus:epoch").unwrap();
                db.delete("consensus:epoch_start_height:1").unwrap();
            }
            assert_eq!(rows(&db), before);
        }
    }
}

#[test]
fn concurrent_conflicting_requests_release_only_one_vote() {
    let dir = TestDir::new();
    dir.seed(true);
    let db = Arc::new(dir.open());
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|i| {
            let db = db.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut ctx = ctx_for(10);
                ctx.block_hash = format!("{i:064x}");
                barrier.wait();
                produce_and_store_qc(&db, &[7; 32], "local", &ctx)
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, QcOutcome::Partial(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, QcOutcome::Skipped))
            .count(),
        1
    );
}

#[test]
fn older_qc_replay_cannot_regress_latest_indexes() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    for height in [10, 20, 10] {
        assert!(matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(height)),
            QcOutcome::Complete(_)
        ));
    }
    assert_eq!(
        db.get("consensus:qc:latest_height").unwrap().as_deref(),
        Some("20")
    );
    let cert: QuorumCertificate =
        serde_json::from_str(&db.get("consensus:qc:latest").unwrap().unwrap()).unwrap();
    assert_eq!(cert.block_height, 20);
    assert_eq!(
        db.get("consensus:qc:latest_round").unwrap().as_deref(),
        Some("20")
    );
}

#[test]
fn other_message_signature_does_not_poison_honest_quorum() {
    let dir = TestDir::new();
    let db = dir.open();
    let set: Vec<_> = (1..=4u8)
        .map(|i| validator_for(&[i; 32], 25, &format!("v{i}")))
        .collect();
    db.put(
        "genesis:validator_set:v1",
        &serde_json::to_string(&set).unwrap(),
    )
    .unwrap();
    let vote = vote_for(&ctx_for(10), &set);
    let mut wrong = vote.clone();
    wrong.receipts_root = "99".repeat(32);
    let byzantine = signed_vote_msg(&[4; 32], "v4", &wrong);
    assert!(matches!(
        collect_vote_and_try_aggregate(&db, &byzantine, Some(&vote.block_hash)),
        QcOutcome::Skipped
    ));
    let mut result = QcOutcome::Skipped;
    for i in 1..=3u8 {
        let msg = signed_vote_msg(&[i; 32], &format!("v{i}"), &vote);
        result = collect_vote_and_try_aggregate(&db, &msg, Some(&vote.block_hash));
    }
    let QcOutcome::Complete(cert) = result else {
        panic!("valid 75/100 quorum was poisoned by an off-message signature")
    };
    assert_eq!(cert.signed_stake, 75);
    assert_eq!(cert.finality_vote(), vote);
    verify_qc(&cert, &set, &vote.chain_id).unwrap();
}

#[test]
fn legacy_votes_remain_binding_without_new_signing_records() {
    for minority in [false, true] {
        let dir = TestDir::new();
        dir.seed(minority);
        let db = dir.open();
        let ctx = ctx_for(10);
        assert!(!matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx),
            QcOutcome::Skipped
        ));
        let pk = hex::encode(
            crypto::bls::BLSEngine::consensus().pubkey_raw(&derive_validator_bls_seed(&[7; 32])),
        );
        let vote = vote_for(&ctx, &load_validator_set_v1(&db).unwrap());
        for key in signing_guard_keys(&vote, &pk) {
            db.delete(&key).unwrap();
        }
        let before = rows(&db);
        let mut conflict = ctx_for(10);
        conflict.finality_digest = "99".repeat(32);
        assert!(matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &conflict),
            QcOutcome::Skipped
        ));
        assert_eq!(rows(&db), before);
        assert!(!matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx),
            QcOutcome::Skipped
        ));
        for key in signing_guard_keys(&vote, &pk) {
            assert!(db.get(&key).unwrap().is_some());
        }
        db.put(&signing_guard_keys(&vote, &pk)[0], "not-json")
            .unwrap();
        let corrupted = rows(&db);
        assert!(matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx),
            QcOutcome::Skipped
        ));
        assert_eq!(rows(&db), corrupted);
    }
}

#[test]
fn native_aggregate_write_error_cannot_publish_completion() {
    let dir = TestDir::new();
    dir.seed(true);
    let db = dir.open();
    let ctx = ctx_for(10);
    assert!(matches!(
        produce_and_store_qc(&db, &[7; 32], "local", &ctx),
        QcOutcome::Partial(_)
    ));
    let msg = signed_vote_msg(
        &[8; 32],
        "other",
        &vote_for(&ctx, &load_validator_set_v1(&db).unwrap()),
    );
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
        collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash)),
        QcOutcome::Skipped
    ));
    assert_eq!(rows(&db), before);
    drop(db);
    let db = dir.open();
    assert!(matches!(
        collect_vote_and_try_aggregate(&db, &msg, Some(&ctx.block_hash)),
        QcOutcome::Complete(_)
    ));
}
