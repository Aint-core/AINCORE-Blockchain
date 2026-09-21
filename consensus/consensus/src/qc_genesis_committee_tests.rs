use super::*;

#[test]
fn epoch_zero_uses_frozen_genesis_before_and_after_rotation() {
    let dir = TestDir::new();
    dir.seed(false);
    {
        let db = dir.open();
        let initial = db.get("sys:validator_set:v1").unwrap().unwrap();
        db.put("genesis:validator_set:v1", &initial).unwrap();
        let changed = vec![validator_for(&[99; 32], 100, "replacement")];
        db.put(
            "sys:validator_set:v1",
            &serde_json::to_string(&changed).unwrap(),
        )
        .unwrap();
        assert_eq!(
            load_validator_set_for_epoch(&db, 0).unwrap(),
            serde_json::from_str::<Vec<ValidatorInfo>>(&initial).unwrap()
        );
        assert!(matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(10)),
            QcOutcome::Complete(_)
        ));
        db.put("consensus:epoch", "1").unwrap();
        db.put("consensus:epoch_start_height:1", "21").unwrap();
    }
    let db = dir.open();
    assert!(
        matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(10)),
            QcOutcome::Complete(_)
        ),
        "retained frozen genesis must permit identical historical replay"
    );
    assert!(
        db.get("sys:validator_set:epoch:0").unwrap().is_none(),
        "lookup must not migrate metadata"
    );
}

#[test]
fn mutable_live_set_alone_cannot_authorize_epoch_zero() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    db.delete("genesis:validator_set:v1").unwrap();
    let before = rows(&db);
    assert!(load_validator_set_for_epoch(&db, 0).is_none());
    assert!(matches!(
        produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(10)),
        QcOutcome::Skipped
    ));
    assert_eq!(rows(&db), before);
}

#[test]
fn genesis_and_epoch_zero_snapshot_conflict_cannot_sign() {
    let dir = TestDir::new();
    dir.seed(false);
    let db = dir.open();
    let frozen = db.get("sys:validator_set:v1").unwrap().unwrap();
    db.put("genesis:validator_set:v1", &frozen).unwrap();
    let conflicting = vec![validator_for(&[7; 32], 500, "local")];
    db.put(
        "sys:validator_set:epoch:0",
        &serde_json::to_string(&conflicting).unwrap(),
    )
    .unwrap();
    let before = rows(&db);
    assert!(load_validator_set_for_epoch(&db, 0).is_none());
    assert!(matches!(
        produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(10)),
        QcOutcome::Skipped
    ));
    assert_eq!(rows(&db), before);
}

#[test]
fn missing_or_invalid_genesis_cannot_borrow_a_valid_epoch_zero_alias() {
    for invalid in [None, Some("[]"), Some("null"), Some("broken json")] {
        let dir = TestDir::new();
        dir.seed(false);
        let db = dir.open();
        let frozen = db.get("genesis:validator_set:v1").unwrap().unwrap();
        db.put("sys:validator_set:epoch:0", &frozen).unwrap();
        match invalid {
            None => db.delete("genesis:validator_set:v1").unwrap(),
            Some(raw) => db.put("genesis:validator_set:v1", raw).unwrap(),
        }
        let before = rows(&db);
        assert!(load_validator_set_for_epoch(&db, 0).is_none());
        assert!(matches!(
            produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(10)),
            QcOutcome::Skipped
        ));
        assert_eq!(rows(&db), before);
    }
}

#[test]
fn equivalent_alias_order_is_accepted_without_rewriting_genesis() {
    let dir = TestDir::new();
    dir.seed(true);
    let db = dir.open();
    let mut set = load_validator_set_for_epoch(&db, 0).unwrap();
    set.reverse();
    db.put(
        "sys:validator_set:epoch:0",
        &serde_json::to_string(&set).unwrap(),
    )
    .unwrap();
    let before = rows(&db);
    assert_eq!(
        qc::canonical_order(&load_validator_set_for_epoch(&db, 0).unwrap()),
        qc::canonical_order(&set)
    );
    assert_eq!(rows(&db), before);
}
