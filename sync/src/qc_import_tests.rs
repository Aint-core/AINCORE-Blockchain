// G1 S8, IM-1 on the sync path: on a V4 chain a block is executed only
// together with a QC that verifies under its epoch's committee and binds its
// hash, anchor and roots. A proposer signature alone is not enough.

use super::*;
use consensus::qc::{
    build_qc, derive_validator_bls_seed, FinalityVote, QuorumCertificate, ValidatorInfo,
};
use crypto::bls::BLSEngine;

fn member(seed: u8) -> ValidatorInfo {
    let key = [seed; 32];
    let ed = crypto::SigningKey::from_bytes(&key)
        .verifying_key()
        .to_bytes();
    let bls = BLSEngine::consensus();
    let bls_seed = derive_validator_bls_seed(&key);
    ValidatorInfo {
        address: crypto::derive_address(&ed).unwrap(),
        stake: 100,
        ed25519_public_key: hex::encode(ed),
        bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
        bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
    }
}

const SEEDS: [u8; 4] = [11, 12, 13, 14];
/// Replaces seed 14 in the epoch-1 committee of the boundary tests.
const NEWCOMER: u8 = 15;
/// The test blocks' proposer, a member of the live set (block validation).
const PROPOSER: u8 = 77;

/// A V4 chain whose genesis committee is `SEEDS`; the proposer of the test
/// blocks is the fixture key 77 (registered by `authenticate_block`).
fn v4_sync(name: &str) -> (ChainSync, Vec<ValidatorInfo>) {
    v4_sync_with(name, 1000, None)
}

/// `v4_sync` with epoch length `interval` and, if given, the live validator
/// set every block's post-state carries (C_{E+1} derives from it).
fn v4_sync_with(
    name: &str,
    interval: u64,
    live: Option<&[ValidatorInfo]>,
) -> (ChainSync, Vec<ValidatorInfo>) {
    let name = format!("s8_{name}_{}_{}", std::process::id(), rand::random::<u64>());
    let sync = setup_sync(&name);
    let committee: Vec<ValidatorInfo> =
        consensus::qc::canonical_order(&SEEDS.iter().map(|s| member(*s)).collect::<Vec<_>>());
    let proposer = crypto::derive_address(
        crypto::SigningKey::from_bytes(&[77; 32])
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    set_validators(&sync, vec![(&proposer, 100)]);
    {
        let _seed = sync.storage.seeding();
        sync.storage
            .put(
                "genesis:validator_set:v1",
                &serde_json::to_string(&committee).unwrap(),
            )
            .unwrap();
        sync.storage
            .put(consensus::v4::VERTEX_FORMAT_KEY, "4")
            .unwrap();
        // A V4 genesis pins its epoch length (EP-1).
        sync.storage
            .put(
                consensus::v4::epoch::EPOCH_INTERVAL_KEY,
                &interval.to_string(),
            )
            .unwrap();
        sync.storage
            .put("genesis_identity", "s9b-sync-genesis")
            .unwrap();
        if let Some(live) = live {
            sync.storage
                .put(
                    "sys:validator_set:v1",
                    &serde_json::to_string(live).unwrap(),
                )
                .unwrap();
        }
    }
    seed_state_tree(&sync);
    (sync, committee)
}

fn block_at(sync: &ChainSync, height: u64, parent: &str, anchor: &str) -> Block {
    let key = crypto::SigningKey::from_bytes(&[77; 32]);
    let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let exec = executor::Executor::new(sync.storage.clone());
    let mut block = Block::new_with_roots_at(
        height,
        2 * height,
        parent.into(),
        vec![],
        proposer,
        exec.current_state_root(),
        exec.receipts_root_for_block(&[]),
        23,
        vec!["ab".repeat(32)],
        anchor.into(),
        vec![],
    );
    authenticate_block(sync, &mut block);
    block
}

/// A QC for `block` signed by the committee members at `signers`.
fn qc_for(block: &Block, committee: &[ValidatorInfo], signers: &[usize]) -> QuorumCertificate {
    qc_in(block, committee, signers, 0, String::new())
}

/// `qc_for` in epoch `epoch`, binding `next` (FinalityVote V2) if non-empty.
fn qc_in(
    block: &Block,
    committee: &[ValidatorInfo],
    signers: &[usize],
    epoch: u64,
    next: String,
) -> QuorumCertificate {
    let vote = FinalityVote {
        chain_id: consensus::qc::expected_chain_id(),
        epoch,
        finalized_round: block.header.round,
        anchor_round: block.header.round,
        anchor_hash: block.anchor_hash.clone(),
        block_height: block.header.height,
        block_hash: block.header.hash.clone(),
        state_root: block.header.state_root.clone(),
        receipts_root: block.header.receipts_root.clone(),
        finality_digest: "cd".repeat(32),
        validator_set_hash: consensus::qc::validator_set_hash(committee),
        next_validator_set_hash: next,
    };
    let by_address = |a: &str| {
        SEEDS
            .iter()
            .chain(&[NEWCOMER, PROPOSER])
            .find(|s| member(**s).address == a)
            .copied()
            .unwrap()
    };
    let signatures: Vec<Vec<u8>> = signers
        .iter()
        .map(|&i| {
            let seed = by_address(&committee[i].address);
            BLSEngine::consensus().sign_raw(
                &vote.to_signing_bytes(),
                &derive_validator_bls_seed(&[seed; 32]),
            )
        })
        .collect();
    build_qc(&vote, committee, signers, &signatures).unwrap()
}

#[test]
fn v4_a_synced_block_without_its_qc_is_not_executed() {
    let (sync, committee) = v4_sync("no_qc");
    let b1 = block_at(&sync, 1, "genesis", &"ab".repeat(32));
    assert_eq!(sync.process_blocks_with_qcs(vec![b1.clone()], &[], 0), 0);
    assert_eq!(
        executor::Executor::new(sync.storage.clone()).last_executed_height(),
        0
    );
    let qc = qc_for(&b1, &committee, &[0, 1, 2]);
    assert_eq!(sync.process_blocks_with_qcs(vec![b1], std::slice::from_ref(&qc), 0), 1);
    assert_eq!(
        consensus::qc_producer::stored_qc(&sync.storage, 1).map(|q| q.block_hash),
        Some(qc.block_hash),
        "the QC was imported with its block"
    );
}

/// The anchor hash is outside the header hash (G0 is still open), so a
/// validator can re-sign a block with another anchor. The QC binds the real
/// one: the substituted block is refused and the real one executes.
#[test]
fn v4_a_substituted_anchor_is_refused_and_the_real_block_is_executed() {
    let (sync, committee) = v4_sync("fake_anchor");
    let real = block_at(&sync, 1, "genesis", &"ab".repeat(32));
    let qc = qc_for(&real, &committee, &[0, 1, 2]);
    let mut forged = real.clone();
    forged.anchor_hash = "ef".repeat(32);
    authenticate_block(&sync, &mut forged);
    assert_eq!(
        forged.header.hash, real.header.hash,
        "same header, other anchor"
    );
    assert_eq!(
        sync.process_blocks_with_qcs(vec![forged], std::slice::from_ref(&qc), 0),
        0
    );
    assert_eq!(sync.process_blocks_with_qcs(vec![real], &[qc], 0), 1);
}

#[test]
fn v4_a_qc_below_quorum_or_for_another_block_is_refused() {
    let (sync, committee) = v4_sync("weak_qc");
    let b1 = block_at(&sync, 1, "genesis", &"ab".repeat(32));
    let weak = qc_for(&b1, &committee, &[0, 1]);
    assert_eq!(
        sync.process_blocks_with_qcs(vec![b1.clone()], &[weak], 0),
        0
    );
    let other = block_at(&sync, 1, "genesis", &"cd".repeat(32));
    let wrong = qc_for(&other, &committee, &[0, 1, 2]);
    let mut misfiled = wrong.clone();
    misfiled.block_height = 1;
    assert_eq!(
        sync.process_blocks_with_qcs(vec![b1.clone()], &[misfiled], 0),
        0
    );
    let good = qc_for(&b1, &committee, &[1, 2, 3]);
    assert_eq!(sync.process_blocks_with_qcs(vec![b1], &[good], 0), 1);
}

/// IM-4: a served batch carries the QC of every block that has one.
#[test]
fn v4_sync_responses_carry_each_blocks_qc() {
    let (sync, committee) = v4_sync("serve_qcs");
    let b1 = block_at(&sync, 1, "genesis", &"ab".repeat(32));
    let qc = qc_for(&b1, &committee, &[0, 1, 2]);
    assert_eq!(sync.process_blocks_with_qcs(vec![b1], std::slice::from_ref(&qc), 0), 1);
    let resp = sync.handle_sync_request(SyncRequest {
        from_height: 0,
        sender_id: "peer".into(),
        sender_port: 1,
    });
    assert_eq!(resp.blocks.len(), 1);
    assert_eq!(
        resp.qcs.iter().map(|q| q.block_height).collect::<Vec<_>>(),
        vec![1]
    );
}

// ------------------------------------------------------------ S9b: epochs

/// C_1 of the boundary tests: 14 leaves, 15 and the proposer join (real
/// key changes).
fn next_committee() -> Vec<ValidatorInfo> {
    consensus::qc::canonical_order(
        &[11, 12, 13, NEWCOMER, PROPOSER]
            .iter()
            .map(|s| member(*s))
            .collect::<Vec<_>>(),
    )
}

/// EP-2/EP-3/EP-4 on import (I = 2): H_0 = block 2 writes epoch 1's record
/// (C_1 from its post-state) in its own transaction; QC(H_0) binds hash(C_1);
/// block 3 is then accepted with a QC of C_1 in epoch 1, and refused with a
/// QC of C_0.
#[test]
fn v4_sync_imports_across_a_boundary_under_the_next_committee() {
    let c1 = next_committee();
    let (sync, c0) = v4_sync_with("boundary", 2, Some(&c1));
    let next = consensus::qc::validator_set_hash(&c1);
    let b1 = block_at(&sync, 1, "genesis", &"a1".repeat(32));
    assert_eq!(
        sync.process_blocks_with_qcs(vec![b1.clone()], &[qc_for(&b1, &c0, &[0, 1, 2])], 0),
        1
    );
    let b2 = block_at(&sync, 2, &b1.header.hash, &"a2".repeat(32));
    let q2 = qc_in(&b2, &c0, &[0, 1, 2], 0, next.clone());
    assert_eq!(sync.process_blocks_with_qcs(vec![b2.clone()], &[q2], 1), 2);
    let start = consensus::v4::epoch::read_start_from(&sync.storage, 1)
        .unwrap()
        .expect("H_0's transaction wrote epoch 1's record");
    assert_eq!(start.committee, c1);
    assert_eq!(start.first_round, b2.header.round + 2);
    assert_eq!(start.prev_height, 2);
    let b3 = block_at(&sync, 3, &b2.header.hash, &"a3".repeat(32));
    let stale = qc_in(&b3, &c0, &[0, 1, 2], 0, String::new());
    assert_eq!(
        sync.process_blocks_with_qcs(vec![b3.clone()], &[stale], 2),
        2,
        "a QC of the old committee certified an epoch-1 block"
    );
    let q3 = qc_in(&b3, &c1, &[0, 1, 2, 3], 1, String::new());
    assert_eq!(sync.process_blocks_with_qcs(vec![b3], &[q3], 2), 3);
}

/// EP-4 on import: QC(H_0) binding a next committee other than the one this
/// node derives from the same post-state is refused, and the node records
/// `alarm:committee_mismatch` (its consensus halts on it).
#[test]
fn v4_sync_refuses_a_boundary_qc_binding_another_committee() {
    let c1 = next_committee();
    let (sync, c0) = v4_sync_with("mismatch", 2, Some(&c1));
    let b1 = block_at(&sync, 1, "genesis", &"a1".repeat(32));
    assert_eq!(
        sync.process_blocks_with_qcs(vec![b1.clone()], &[qc_for(&b1, &c0, &[0, 1, 2])], 0),
        1
    );
    let b2 = block_at(&sync, 2, &b1.header.hash, &"a2".repeat(32));
    let wrong = qc_in(
        &b2,
        &c0,
        &[0, 1, 2],
        0,
        consensus::qc::validator_set_hash(&c0),
    );
    assert_eq!(
        sync.process_blocks_with_qcs(vec![b2.clone()], &[wrong], 1),
        1
    );
    assert!(
        consensus::v4::epoch::read_start_from(&sync.storage, 1)
            .unwrap()
            .is_none(),
        "the refused block's record was written"
    );
    assert!(sync
        .storage
        .get(&format!("alarm:committee_mismatch:{:020}", 1))
        .unwrap()
        .is_some());
}
