use super::*;
use std::collections::BTreeMap;

fn fixture(name: &str) -> (ChainSync, Block, String) {
    let name = format!(
        "admission_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let sync = setup_sync(&name);
    let key = crypto::SigningKey::from_bytes(&[77; 32]);
    let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    set_validators(&sync, vec![(&proposer, 100)]);
    let executor = executor::Executor::new(sync.storage.clone());
    let mut block = Block::new_with_roots_at(
        1,
        1,
        "genesis".into(),
        vec![],
        proposer,
        executor.current_state_root(),
        executor.receipts_root_for_block(&[]),
        23,
        vec!["ab".repeat(32)],
        "ab".repeat(32),
        vec![],
    );
    authenticate_block(&sync, &mut block);
    (sync, block, format!("/tmp/aincore_sync_db_{name}"))
}

fn rows(db: &StateDB) -> BTreeMap<Vec<u8>, Vec<u8>> {
    db.db
        .iterator(storage::rocksdb::IteratorMode::Start)
        .map(|r| {
            let (k, v) = r.unwrap();
            (k.to_vec(), v.to_vec())
        })
        .collect()
}

fn revoke_author(db: &StateDB) {
    let key = crypto::SigningKey::from_bytes(&[78; 32]);
    let address = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    db.put(
        "sys:validators",
        &serde_json::to_string(&vec![(address, 100u64)]).unwrap(),
    )
    .unwrap();
}

fn replace_parent(db: &StateDB) {
    let mut parent: Block = serde_json::from_str(&db.get("block_1").unwrap().unwrap()).unwrap();
    parent.header.hash = "cd".repeat(32);
    db.save_block_json(1, &serde_json::to_string(&parent).unwrap())
        .unwrap();
}

fn replace_author_key(db: &StateDB) {
    let key = crypto::SigningKey::from_bytes(&[77; 32]);
    let address = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let mut account = db.get_object(&address).unwrap();
    account.data = serde_json::json!({
        "public_key": hex::encode(crypto::SigningKey::from_bytes(&[78; 32]).verifying_key().to_bytes()),
        "sequence_number": 0
    }).to_string().into_bytes();
    db.put_object(&account).unwrap();
}

fn remove_parent(db: &StateDB) {
    db.delete("block_1").unwrap();
}

fn publish_prepared_qc(db: &StateDB) {
    db.put(
        "consensus:qc:latest",
        &db.get("test:prepared_qc").unwrap().unwrap(),
    )
    .unwrap();
}

fn corrupt_held_qc(db: &StateDB) {
    db.put("consensus:qc:latest", "not JSON").unwrap();
}

fn expected_after(db: &StateDB, mutation: fn(&StateDB)) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let before = rows(db);
    mutation(db);
    let expected = rows(db);
    // Restore only this isolated fixture's mutated rows before exercising the hook.
    for (key, value) in &before {
        if expected.get(key) != Some(value) {
            db.put(
                std::str::from_utf8(key).unwrap(),
                std::str::from_utf8(value).unwrap(),
            )
            .unwrap();
        }
    }
    for key in expected.keys().filter(|key| !before.contains_key(*key)) {
        db.delete(std::str::from_utf8(key).unwrap()).unwrap();
    }
    expected
}

fn assert_preserved(sync: ChainSync, expected: BTreeMap<Vec<u8>, Vec<u8>>, path: String) {
    assert_eq!(rows(&sync.storage), expected);
    assert!(sync.storage.get("sync:halt_reason").unwrap().is_none());
    sync.storage.flush().unwrap();
    drop(sync);
    let reopened = StateDB::open(&path).unwrap();
    assert_eq!(
        rows(&reopened),
        expected,
        "rejection changed durable rows after reopen"
    );
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn unchanged_context_accepts_and_resumes_from_tip() {
    let (sync, block, path) = fixture("control");
    assert_eq!(sync.process_blocks(vec![block.clone()], 0), 1);
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(vec![block], 1), 1);
    assert_preserved(sync, before, path);
}

#[test]
fn revoked_author_between_precheck_and_execution_must_not_commit() {
    let (mut sync, block, path) = fixture("revoked_author");
    assert!(sync.validate_block(&block, 1, "genesis").is_ok());
    let expected = expected_after(&sync.storage, revoke_author);
    sync.before_execution_hook = Some(revoke_author);
    assert_eq!(
        sync.process_blocks(vec![block], 0),
        0,
        "stale author eligibility admitted a block"
    );
    assert_preserved(sync, expected, path);
}

#[test]
fn changed_signer_key_between_precheck_and_execution_must_not_commit() {
    let (mut sync, block, path) = fixture("changed_key");
    assert!(sync.validate_block(&block, 1, "genesis").is_ok());
    let expected = expected_after(&sync.storage, replace_author_key);
    sync.before_execution_hook = Some(replace_author_key);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, expected, path);
}

#[test]
fn replaced_parent_between_precheck_and_execution_must_not_commit() {
    let (mut sync, parent, path) = fixture("replaced_parent");
    assert_eq!(sync.process_blocks(vec![parent.clone()], 0), 1);
    let executor = executor::Executor::new(sync.storage.clone());
    let mut block = Block::new_with_roots_at(
        2,
        2,
        parent.header.hash.clone(),
        vec![],
        parent.header.proposer_id,
        executor.current_state_root(),
        executor.receipts_root_for_block(&[]),
        24,
        vec!["bc".repeat(32)],
        "bc".repeat(32),
        vec![],
    );
    authenticate_block(&sync, &mut block);
    drop(executor);
    assert!(sync.validate_block(&block, 2, &parent.header.hash).is_ok());
    let expected = expected_after(&sync.storage, replace_parent);
    sync.before_execution_hook = Some(replace_parent);
    assert_eq!(
        sync.process_blocks(vec![block], 1),
        1,
        "stale parent admitted a child on another stored parent"
    );
    assert_preserved(sync, expected, path);
}

#[test]
fn missing_parent_between_precheck_and_execution_must_not_commit() {
    let (mut sync, parent, path) = fixture("missing_parent");
    assert_eq!(sync.process_blocks(vec![parent.clone()], 0), 1);
    let executor = executor::Executor::new(sync.storage.clone());
    let mut block = Block::new_with_roots_at(
        2,
        2,
        parent.header.hash.clone(),
        vec![],
        parent.header.proposer_id,
        executor.current_state_root(),
        executor.receipts_root_for_block(&[]),
        24,
        vec!["bc".repeat(32)],
        "bc".repeat(32),
        vec![],
    );
    authenticate_block(&sync, &mut block);
    drop(executor);
    let expected = expected_after(&sync.storage, remove_parent);
    sync.before_execution_hook = Some(remove_parent);
    assert_eq!(sync.process_blocks(vec![block], 1), 1);
    assert_preserved(sync, expected, path);
}

#[test]
fn held_qc_arriving_after_precheck_is_rechecked() {
    let (mut sync, block, path) = fixture("new_qc");
    // This fixture injects a held record; it does NOT exercise QC import or prove
    // that a network peer can install such a record without a matching block.
    let mut qc = build_test_qc(&sync, 2, 1);
    let mut validators: Vec<consensus::qc::ValidatorInfo> =
        serde_json::from_str(&sync.storage.get("sys:validator_set:v1").unwrap().unwrap()).unwrap();
    validators[0].address = block.header.proposer_id.clone();
    validators[0].ed25519_public_key = hex::encode(
        crypto::SigningKey::from_bytes(&[77; 32])
            .verifying_key()
            .to_bytes(),
    );
    for key in ["sys:validator_set:v1", "genesis:validator_set:v1"] {
        sync.storage
            .put(key, &serde_json::to_string(&validators).unwrap())
            .unwrap();
    }
    let mut vote = qc.finality_vote();
    vote.validator_set_hash = consensus::qc::validator_set_hash(&validators);
    let signature =
        crypto::bls::BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), &[7; 32]);
    qc = consensus::qc::build_qc(&vote, &validators, &[0], &[signature]).unwrap();
    assert!(sync.validate_block(&block, 1, "genesis").is_ok());
    assert_ne!(qc.block_hash, block.header.hash);
    sync.storage
        .put("test:prepared_qc", &serde_json::to_string(&qc).unwrap())
        .unwrap();
    let expected = expected_after(&sync.storage, publish_prepared_qc);
    sync.before_execution_hook = Some(publish_prepared_qc);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, expected, path);
}

#[test]
fn malformed_held_qc_at_admission_fails_closed() {
    let (mut sync, block, path) = fixture("malformed_qc");
    let expected = expected_after(&sync.storage, corrupt_held_qc);
    sync.before_execution_hook = Some(corrupt_held_qc);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, expected, path);
}

#[test]
fn missing_committee_cannot_admit_a_signed_account() {
    let (sync, block, path) = fixture("missing_committee");
    sync.storage.delete("sys:validators").unwrap();
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, before, path);
}

#[test]
fn empty_preferred_committee_cannot_admit_a_signed_account() {
    let (sync, block, path) = fixture("empty_committee");
    sync.storage.put("sys:validator_set:v1", "[]").unwrap();
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, before, path);
}

#[test]
fn corrupt_preferred_committee_cannot_downgrade_to_legacy_mirror() {
    let (sync, block, path) = fixture("corrupt_committee");
    sync.storage
        .put("sys:validator_set:v1", "broken JSON")
        .unwrap();
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, before, path);
}

#[test]
fn zero_stake_author_cannot_admit_a_block() {
    let (sync, block, path) = fixture("zero_stake_author");
    set_validators(
        &sync,
        vec![(&block.header.proposer_id, 0), ("other_validator", 100)],
    );
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, before, path);
}

#[test]
fn duplicate_committee_addresses_are_not_silently_deduplicated() {
    let (sync, block, path) = fixture("duplicate_committee");
    let json = serde_json::json!([
        {"address": block.header.proposer_id, "stake": 100},
        {"address": block.header.proposer_id, "stake": 200}
    ]);
    sync.storage
        .put("sys:validator_set:v1", &json.to_string())
        .unwrap();
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, before, path);
}

fn clear_preferred_committee(db: &StateDB) {
    db.put("sys:validator_set:v1", "[]").unwrap();
}

#[test]
fn committee_cleared_after_precheck_is_rejected_in_admission_transaction() {
    let (mut sync, block, path) = fixture("committee_cleared");
    assert!(sync.validate_block(&block, 1, "genesis").is_ok());
    let expected = expected_after(&sync.storage, clear_preferred_committee);
    sync.before_execution_hook = Some(clear_preferred_committee);
    assert_eq!(sync.process_blocks(vec![block], 0), 0);
    assert_preserved(sync, expected, path);
}

#[test]
fn copy_signer_needs_positive_stake_even_with_an_eligible_leader() {
    for stake in [0, 100] {
        let (sync, mut block, path) = fixture(&format!("copy_signer_stake_{stake}"));
        let signer = block.header.proposer_id.clone();
        let leader = crypto::derive_address(
            crypto::SigningKey::from_bytes(&[78; 32])
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        set_validators(&sync, vec![(&leader, 100), (&signer, stake)]);
        block.header.proposer_id = leader;
        block.header.hash = blockchain::calculate_header_hash(&block.header);
        block.sign_proposer(&crypto::SigningKey::from_bytes(&[77; 32]), &signer);
        let before = rows(&sync.storage);
        let accepted = sync.process_blocks(vec![block], 0);
        assert_eq!(accepted, u64::from(stake > 0));
        let expected = if stake == 0 {
            before
        } else {
            rows(&sync.storage)
        };
        assert_preserved(sync, expected, path);
    }
}
