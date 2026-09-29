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

/// A V4 chain whose genesis committee is `SEEDS`; the proposer of the test
/// blocks is the fixture key 77 (registered by `authenticate_block`).
fn v4_sync(name: &str) -> (ChainSync, Vec<ValidatorInfo>) {
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
    let vote = FinalityVote {
        chain_id: consensus::qc::expected_chain_id(),
        epoch: 0,
        finalized_round: block.header.round,
        anchor_round: block.header.round,
        anchor_hash: block.anchor_hash.clone(),
        block_height: block.header.height,
        block_hash: block.header.hash.clone(),
        state_root: block.header.state_root.clone(),
        receipts_root: block.header.receipts_root.clone(),
        finality_digest: "cd".repeat(32),
        validator_set_hash: consensus::qc::validator_set_hash(committee),
    };
    let by_address = |a: &str| {
        SEEDS
            .iter()
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
