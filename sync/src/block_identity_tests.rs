use super::*;

fn fixture(name: &str) -> (ChainSync, Block) {
    let sync = setup_sync(&format!(
        "identity_{name}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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
    (sync, block)
}

#[test]
fn unchanged_signed_block_is_accepted_identically_by_two_fresh_stores() {
    let (left, block) = fixture("control_left");
    let (right, _) = fixture("control_right");
    assert_eq!(left.process_blocks(vec![block.clone()], 0), 1);
    assert_eq!(right.process_blocks(vec![block], 0), 1);
    assert_eq!(
        left.storage.get("block_1").unwrap(),
        right.storage.get("block_1").unwrap()
    );
}

#[test]
#[ignore = "OPEN block identity: round/timestamp concatenation permits signed header substitution"]
fn sync_must_reject_resegmented_round_timestamp_with_reused_signature() {
    let (left, block) = fixture("round_left");
    let (right, _) = fixture("round_right");
    let mut substituted = block.clone();
    substituted.header.round = 12;
    substituted.header.timestamp = 3;
    eprintln!(
        "resegmented header matches declared hash: {}",
        block.header.hash == blockchain::calculate_header_hash(&substituted.header)
    );
    assert_eq!(block.proposer_signature, substituted.proposer_signature);
    eprintln!(
        "reused proposer signature verifies before sync: {}",
        substituted.verify_proposer_signature(&hex::encode(
            crypto::SigningKey::from_bytes(&[77; 32])
                .verifying_key()
                .to_bytes()
        ))
    );
    assert_eq!(left.process_blocks(vec![block], 0), 1);
    let accepted = right.process_blocks(vec![substituted], 0);
    assert_eq!(accepted, 0, "a signature for (round=1,time=23) also admitted (round=12,time=3) through execution/storage");
}

#[test]
#[ignore = "OPEN block identity: anchor_hash is not covered by the proposer header signature"]
fn sync_must_reject_substituted_anchor_with_reused_signature() {
    let (left, block) = fixture("anchor_left");
    let (right, _) = fixture("anchor_right");
    let mut substituted = block.clone();
    substituted.anchor_hash = "bc".repeat(32);
    eprintln!(
        "substituted anchor matches declared hash: {}",
        block.header.hash == blockchain::calculate_header_hash(&substituted.header)
    );
    assert_eq!(block.proposer_signature, substituted.proposer_signature);
    assert_eq!(left.process_blocks(vec![block], 0), 1);
    let accepted = right.process_blocks(vec![substituted], 0);
    assert_eq!(
        accepted, 0,
        "a different unsigned anchor reached block execution/storage under the same header hash"
    );
}
