use super::*;
use ed25519_dalek::Signer;

pub(super) fn fixture() -> BlockIdentityV2 {
    BlockIdentityV2 {
        chain_id: "AIN-TEST".into(),
        genesis_hash: [1; 32],
        epoch: 2,
        height: 7,
        parent: Parent::Block([2; 32]),
        anchor_round: 12,
        anchor_hash: [3; 32],
        timestamp: 34,
        proposer: [4; 32],
        transactions_root: [5; 32],
        state_root: [6; 32],
        receipts_root: [7; 32],
        vertices_root: [8; 32],
        evidence_root: [9; 32],
        finality_digest: [10; 32],
    }
}

#[test]
fn fixed_vector_matches_independent_javascript_encoder() {
    let identity = fixture();
    let golden =
        hex::decode(include_str!("../../test-vectors/block_identity_v2.hex").trim()).unwrap();
    assert_eq!(identity.encode().unwrap(), golden);
    assert_eq!(BlockIdentityV2::decode(&golden).unwrap(), identity);
    assert_eq!(
        hex::encode(identity.hash().unwrap()),
        "0407086884bb9b846531bed71ef1e963c8012694c7fbafad39a22f829e5d2f78"
    );
    assert_eq!(hex::encode(identity.signing_bytes().unwrap()), "41494e434f52455f424c4f434b5f50524f504f5345525f5632000407086884bb9b846531bed71ef1e963c8012694c7fbafad39a22f829e5d2f78");
    assert_eq!(
        hex::encode(transactions_root(&[]).unwrap()),
        "8fb38df1efad444ac9c18deae026b6fd958c88be41aca777ead558f9f75c05a5"
    );
}

#[test]
fn every_identity_field_is_committed() {
    let original = fixture();
    for field in 0..15 {
        let mut other = original.clone();
        match field {
            0 => other.chain_id.push('X'),
            1 => other.genesis_hash[0] ^= 1,
            2 => other.epoch += 1,
            3 => other.height += 1,
            4 => other.parent = Parent::Block([10; 32]),
            5 => other.anchor_round += 1,
            6 => other.anchor_hash[0] ^= 1,
            7 => other.timestamp += 1,
            8 => other.proposer[0] ^= 1,
            9 => other.transactions_root[0] ^= 1,
            10 => other.state_root[0] ^= 1,
            11 => other.receipts_root[0] ^= 1,
            12 => other.vertices_root[0] ^= 1,
            13 => other.evidence_root[0] ^= 1,
            _ => other.finality_digest[0] ^= 1,
        }
        assert_ne!(
            original.encode().unwrap(),
            other.encode().unwrap(),
            "field {field}"
        );
        assert_ne!(
            original.hash().unwrap(),
            other.hash().unwrap(),
            "field {field}"
        );
        assert_ne!(
            original.signing_bytes().unwrap(),
            other.signing_bytes().unwrap(),
            "field {field}"
        );
    }
}

#[test]
fn round_timestamp_and_item_segmentation_are_unambiguous() {
    let mut first = fixture();
    first.anchor_round = 1;
    first.timestamp = 23;
    let mut second = first.clone();
    second.anchor_round = 12;
    second.timestamp = 3;
    assert_ne!(first.hash().unwrap(), second.hash().unwrap());
    let a = vec![b"a".to_vec(), b"bc".to_vec()];
    let b = vec![b"ab".to_vec(), b"c".to_vec()];
    assert_ne!(
        transactions_root(&a).unwrap(),
        transactions_root(&b).unwrap()
    );
    assert_ne!(evidence_root(&a).unwrap(), evidence_root(&b).unwrap());
    assert_ne!(transactions_root(&a).unwrap(), evidence_root(&a).unwrap());
    assert_ne!(
        transactions_root(&[]).unwrap(),
        transactions_root(&[vec![]]).unwrap()
    );
    assert_ne!(vertices_root(&[]).unwrap(), transactions_root(&[]).unwrap());
    assert_ne!(
        vertices_root(&[[1; 32], [2; 32]]).unwrap(),
        vertices_root(&[[2; 32], [1; 32]]).unwrap()
    );
}

#[test]
fn proposer_signature_is_domain_and_identity_bound() {
    let identity = fixture();
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let signature = key.sign(&identity.signing_bytes().unwrap());
    key.verifying_key()
        .verify_strict(&identity.signing_bytes().unwrap(), &signature)
        .unwrap();
    assert!(key
        .verifying_key()
        .verify_strict(&identity.hash().unwrap(), &signature)
        .is_err());
    assert!(key
        .verifying_key()
        .verify_strict(&identity.encode().unwrap(), &signature)
        .is_err());
    let mut other = identity;
    other.anchor_hash[0] ^= 1;
    assert!(key
        .verifying_key()
        .verify_strict(&other.signing_bytes().unwrap(), &signature)
        .is_err());
}

#[test]
fn decoder_rejects_unknown_version_trailing_and_noncanonical_bytes() {
    let identity = fixture();
    let wire = identity.encode().unwrap();
    assert_eq!(BlockIdentityV2::decode(&wire).unwrap(), identity);
    let mut unknown = wire.clone();
    unknown[..2].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(
        BlockIdentityV2::decode(&unknown),
        Err(CodecError::UnsupportedVersion(3))
    );
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(BlockIdentityV2::decode(&trailing).is_err());
    let mut nonminimal = wire.clone();
    nonminimal.splice(2..3, [0x88, 0x00]);
    assert!(BlockIdentityV2::decode(&nonminimal).is_err());
    let mut invalid_utf8 = wire.clone();
    invalid_utf8[3] = 0xff;
    assert!(BlockIdentityV2::decode(&invalid_utf8).is_err());
    let mut unknown_parent = wire.clone();
    assert_eq!(unknown_parent[59], 1);
    unknown_parent[59] = 2;
    assert!(BlockIdentityV2::decode(&unknown_parent).is_err());
    for end in 0..wire.len() {
        assert!(
            BlockIdentityV2::decode(&wire[..end]).is_err(),
            "truncated at {end}"
        );
    }
    assert!(BlockIdentityV2::decode(&vec![0; MAX_IDENTITY_BYTES + 1]).is_err());
}

#[test]
fn invalid_semantics_and_resource_bounds_fail_closed() {
    let mut identity = fixture();
    identity.height = 1;
    assert!(identity.encode().is_err());
    identity.parent = Parent::Genesis;
    let encoded = identity.encode().unwrap();
    assert_eq!(BlockIdentityV2::decode(&encoded).unwrap(), identity);
    identity.height = 0;
    assert!(identity.encode().is_err());
    assert!(BlockIdentityV2::decode(&bcs::to_bytes(&(VERSION, &identity)).unwrap()).is_err());
    identity = fixture();
    identity.chain_id = "x".repeat(MAX_CHAIN_ID_BYTES);
    assert!(identity.encode().is_ok());
    identity.chain_id.push('x');
    assert!(identity.encode().is_err());
    identity.chain_id.clear();
    assert!(identity.encode().is_err());
    identity.chain_id = "\u{e9}".repeat(MAX_CHAIN_ID_BYTES / 2);
    assert_eq!(
        BlockIdentityV2::decode(&identity.encode().unwrap()).unwrap(),
        identity
    );
    identity.chain_id.push('x');
    assert!(identity.encode().is_err());
    assert!(transactions_root(&vec![vec![]; MAX_ITEMS]).is_ok());
    assert!(transactions_root(&vec![vec![]; MAX_ITEMS + 1]).is_err());
    assert!(transactions_root(&[vec![0; MAX_ITEM_BYTES + 1]]).is_err());
    assert!(transactions_root(&[vec![0; MAX_ITEM_BYTES]]).is_ok());
    assert!(evidence_root(&vec![vec![0; MAX_ITEM_BYTES]; 16]).is_err());
    assert!(vertices_root(&vec![[0; 32]; MAX_ITEMS + 1]).is_err());
}
