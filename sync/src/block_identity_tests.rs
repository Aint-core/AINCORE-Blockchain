use super::*;

fn fixture(name: &str) -> (ChainSync, Block) {
    fixture_with(name, vec!["ab".repeat(32)])
}

fn fixture_with(name: &str, committed_vertices: Vec<String>) -> (ChainSync, Block) {
    let anchor = committed_vertices.last().cloned().unwrap_or_default();
    let sync = setup_sync(&unique_name(&format!("identity_{name}")));
    let key = crypto::SigningKey::from_bytes(&[77; 32]);
    let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    set_validators(&sync, vec![(&proposer, 100)]);
    seed_state_tree(&sync);
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
        committed_vertices,
        anchor,
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

/// Closed by the canonical header hash (G3 FX-18); was ignored while open.
#[test]
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

/// G3 FX-18: a signed block whose header carries no vertices root cannot be
/// given a committed sequence by a peer. Sync used to compare the root only
/// when the header's was non-empty.
#[test]
fn sync_must_reject_vertices_attached_to_a_block_without_them() {
    let (left, block) = fixture_with("inject_left", vec![]);
    let (right, _) = fixture_with("inject_right", vec![]);
    assert!(block.header.vertices_root.is_empty());
    let mut injected = block.clone();
    injected.committed_vertices = vec!["cd".repeat(32)];
    assert_eq!(blockchain::calculate_header_hash(&injected.header), block.header.hash);
    assert_eq!(left.process_blocks(vec![block], 0), 1, "CONTROL: the signed block is valid");
    assert_eq!(
        right.process_blocks(vec![injected], 0),
        0,
        "a committed sequence the header does not bind reached execution/storage"
    );
}

#[test]
#[ignore = "V3 only: on V4 the anchor is bound through vertices_root (G0, Block::anchor_is_bound; witness v4_validation_refuses_an_anchor_that_is_not_the_last_committed_vertex). V3 is deleted at G1 S11"]
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
