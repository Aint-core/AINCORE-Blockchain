use super::*;

#[test]
fn checked_eligibility_prefers_v1_and_filters_zero_stake() {
    let db = temp_db("checked_eligibility_precedence");
    db.put("sys:validators", r#"[["z",0],["b",2],["a",1]]"#)
        .unwrap();
    assert_eq!(
        db.get_active_validators_checked().unwrap(),
        vec![("a".into(), 1), ("b".into(), 2)]
    );
    db.put(
        "sys:validator_set:v1",
        r#"[{"address":"c","stake":3},{"address":"zero","stake":0}]"#,
    )
    .unwrap();
    db.put("sys:validators", "invalid legacy mirror").unwrap();
    assert_eq!(
        db.get_active_validators_checked().unwrap(),
        vec![("c".into(), 3)]
    );
}

#[test]
fn missing_empty_or_malformed_eligibility_is_an_error() {
    let db = temp_db("checked_eligibility_invalid");
    assert!(db.get_active_validators_checked().is_err());
    for json in [
        "[]",
        "null",
        "{}",
        "broken",
        r#"[["a",0]]"#,
        r#"[["a",-1]]"#,
        r#"[["a",18446744073709551616]]"#,
        r#"[["",1]]"#,
        r#"[["   ",1]]"#,
    ] {
        db.put("sys:validators", json).unwrap();
        assert!(
            db.get_active_validators_checked().is_err(),
            "accepted {json}"
        );
    }
    db.put("sys:validators", r#"[["legacy",1]]"#).unwrap();
    for json in [
        "[]",
        "null",
        "{}",
        "broken",
        r#"[{"address":"a"}]"#,
        r#"[{"address":"a","stake":0}]"#,
    ] {
        db.put("sys:validator_set:v1", json).unwrap();
        assert!(
            db.get_active_validators_checked().is_err(),
            "fell back from {json}"
        );
    }
}

#[test]
fn invalid_utf8_v1_is_not_an_absent_record() {
    let db = temp_db("checked_eligibility_utf8");
    db.put("sys:validators", r#"[["legacy",1]]"#).unwrap();
    let mut batch = rocksdb::WriteBatch::default();
    batch.put("sys:validator_set:v1", [0xff]);
    db.write_batch(batch).unwrap();
    assert!(db.get_active_validators_checked().is_err());
}

#[test]
fn duplicate_addresses_are_rejected_even_when_one_has_zero_stake() {
    let db = temp_db("checked_eligibility_duplicates");
    for json in [r#"[["a",1],["a",2]]"#, r#"[["a",0],["a",2]]"#] {
        db.put("sys:validators", json).unwrap();
        assert!(db.get_active_validators_checked().is_err());
    }
    db.put(
        "sys:validator_set:v1",
        r#"[{"address":"a","stake":0},{"address":"a","stake":2}]"#,
    )
    .unwrap();
    assert!(db.get_active_validators_checked().is_err());
}

#[test]
fn checked_eligibility_reads_the_staged_acceptance_view() {
    let db = temp_db("checked_eligibility_view");
    db.put("sys:validators", r#"[["legacy",1]]"#).unwrap();
    let result: Result<(), crate::StorageError> = db.transaction(|view| {
        view.put("sys:validator_set:v1", "[]")?;
        assert!(view.get_active_validators_checked().is_err());
        Err(crate::StorageError::DatabaseOperation(
            "discard test view".into(),
        ))
    });
    assert!(result.is_err());
    assert!(db.get("sys:validator_set:v1").unwrap().is_none());
    assert_eq!(
        db.get_active_validators_checked().unwrap(),
        vec![("legacy".into(), 1)]
    );
}
