use super::*;
use crate::identity_v2::{policy::GenesisFormatProof, MAX_ITEM_BYTES};

pub(super) struct Fixture {
    policy: VerifiedFormatPolicy,
    keys: BTreeMap<Digest, Digest>,
    key: SigningKey,
    identity: BlockIdentityV2,
    body: BodyV2,
    parent: Parent,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let key = SigningKey::from_bytes(&[77; 32]);
        let leader = SigningKey::from_bytes(&[78; 32]);
        let keys = [
            key.verifying_key().to_bytes(),
            leader.verifying_key().to_bytes(),
        ]
        .into_iter()
        .map(|pk| (address(&pk), pk))
        .collect();
        let proof = GenesisFormatProof {
            base_genesis_identity: [1; 32],
            chain_id: "AIN-TEST".into(),
            v2_from_height: 7,
        };
        let policy = VerifiedFormatPolicy::verify_against_pin(
            proof.proposed_genesis_identity().unwrap(),
            &proof.encode().unwrap(),
        )
        .unwrap();
        let body = BodyV2 {
            transactions: vec![b"a".to_vec(), b"bc".to_vec()],
            committed_vertices: vec![[11; 32], [12; 32]],
            evidence: vec![b"x".to_vec(), b"yz".to_vec()],
        };
        let mut identity = crate::identity_v2::tests::fixture();
        identity.genesis_hash = policy.genesis_identity();
        identity.proposer = address(&leader.verifying_key().to_bytes());
        identity.transactions_root = transactions_root(&body.transactions).unwrap();
        identity.vertices_root = vertices_root(&body.committed_vertices).unwrap();
        identity.evidence_root = evidence_root(&body.evidence).unwrap();
        let parent = identity.parent.clone();
        Self {
            policy,
            keys,
            key,
            identity,
            body,
            parent,
        }
    }

    pub(super) fn context(&self) -> EnvelopeContext<'_> {
        EnvelopeContext {
            policy: &self.policy,
            expected_epoch: 2,
            expected_height: 7,
            expected_parent: &self.parent,
            eligible_keys: &self.keys,
        }
    }

    pub(super) fn signed(&self) -> SignedBlockV2 {
        SignedBlockV2::sign(
            self.identity.clone(),
            self.body.clone(),
            &self.key,
            &self.context(),
        )
        .unwrap()
    }

    pub(super) fn resign(&self, block: &mut SignedBlockV2) {
        block.signature = self
            .key
            .sign(&block.identity.signing_bytes().unwrap())
            .to_bytes()
            .to_vec();
        self.key
            .verifying_key()
            .verify_strict(
                &block.identity.signing_bytes().unwrap(),
                &Signature::from_slice(&block.signature).unwrap(),
            )
            .unwrap();
    }
}

#[test]
fn nonempty_identity_and_signature_match_independent_node_crypto_vector() {
    let f = Fixture::new();
    let block = f.signed();
    assert_eq!(
        block.identity.encode().unwrap(),
        hex::decode(include_str!("../../../test-vectors/envelope_identity_v2.hex").trim()).unwrap()
    );
    assert_eq!(
        block.signature,
        hex::decode(include_str!("../../../test-vectors/envelope_signature_v2.hex").trim())
            .unwrap()
    );
    assert_eq!(
        hex::encode(f.key.verifying_key().to_bytes()),
        "62a611b472d89b0e5fc93c069b9f700b4c552d55bc0e87b56008ef17b6b2bebe"
    );
    assert_eq!(
        hex::encode(block.authenticate(&f.context()).unwrap().hash()),
        "c94897f19a1046839a356fe600bdf4c5e341ce45d6bbcdd21e740385a5a3eb23"
    );
}

#[test]
fn authorized_leader_and_other_validator_sign_the_same_identity() {
    let f = Fixture::new();
    let block = f.signed();
    assert_ne!(block.signer, block.identity.proposer);
    let checked = block.authenticate(&f.context()).unwrap();
    assert_eq!(checked.block(), &block);
    assert_eq!(checked.hash(), f.identity.hash().unwrap());
    let leader = SignedBlockV2::sign(
        f.identity.clone(),
        f.body.clone(),
        &SigningKey::from_bytes(&[78; 32]),
        &f.context(),
    )
    .unwrap();
    assert_eq!(leader.signer, leader.identity.proposer);
    assert_ne!(leader.signature, block.signature);
    assert_eq!(
        leader.authenticate(&f.context()).unwrap().hash(),
        checked.hash()
    );
}

#[test]
fn reused_signature_rejects_every_changed_identity_field() {
    let f = Fixture::new();
    let original = f.signed();
    original.authenticate(&f.context()).unwrap();
    for field in 0..15 {
        let mut other = original.clone();
        match field {
            0 => other.identity.chain_id.push('X'),
            1 => other.identity.genesis_hash[0] ^= 1,
            2 => other.identity.epoch += 1,
            3 => other.identity.height += 1,
            4 => other.identity.parent = Parent::Block([99; 32]),
            5 => other.identity.anchor_round += 1,
            6 => other.identity.anchor_hash[0] ^= 1,
            7 => other.identity.timestamp += 1,
            8 => other.identity.proposer = other.signer,
            9 => other.identity.transactions_root[0] ^= 1,
            10 => other.identity.state_root[0] ^= 1,
            11 => other.identity.receipts_root[0] ^= 1,
            12 => other.identity.vertices_root[0] ^= 1,
            13 => other.identity.evidence_root[0] ^= 1,
            _ => other.identity.finality_digest[0] ^= 1,
        }
        assert!(other.authenticate(&f.context()).is_err(), "field {field}");
    }
    let mut old_shape = original;
    old_shape.identity.anchor_round = 1;
    old_shape.identity.timestamp = 23;
    f.resign(&mut old_shape);
    old_shape.authenticate(&f.context()).unwrap();
    let mut resegmented = old_shape.clone();
    resegmented.identity.anchor_round = 12;
    resegmented.identity.timestamp = 3;
    assert_ne!(
        old_shape.identity.hash().unwrap(),
        resegmented.identity.hash().unwrap()
    );
    assert!(resegmented.authenticate(&f.context()).is_err());
}

#[test]
fn empty_body_is_valid_but_its_commitments_cannot_be_omitted() {
    let mut f = Fixture::new();
    f.body = BodyV2 {
        transactions: vec![],
        committed_vertices: vec![],
        evidence: vec![],
    };
    f.identity.transactions_root = transactions_root(&[]).unwrap();
    f.identity.vertices_root = vertices_root(&[]).unwrap();
    f.identity.evidence_root = evidence_root(&[]).unwrap();
    f.signed().authenticate(&f.context()).unwrap();
    for field in 0..3 {
        let mut other = f.signed();
        match field {
            0 => other.identity.transactions_root = [0; 32],
            1 => other.identity.vertices_root = [0; 32],
            _ => other.identity.evidence_root = [0; 32],
        }
        f.resign(&mut other);
        assert!(other.authenticate(&f.context()).is_err());
    }
}

#[test]
fn body_substitution_and_resegmentation_cannot_reuse_signature() {
    let f = Fixture::new();
    let original = f.signed();
    for field in 0..3 {
        let mut other = original.clone();
        match field {
            0 => other.body.transactions = vec![b"ab".to_vec(), b"c".to_vec()],
            1 => other.body.committed_vertices.reverse(),
            _ => other.body.evidence = vec![b"xy".to_vec(), b"z".to_vec()],
        }
        assert!(other.authenticate(&f.context()).is_err(), "body {field}");
        other.identity.transactions_root = transactions_root(&other.body.transactions).unwrap();
        other.identity.vertices_root = vertices_root(&other.body.committed_vertices).unwrap();
        other.identity.evidence_root = evidence_root(&other.body.evidence).unwrap();
        assert!(
            other.authenticate(&f.context()).is_err(),
            "rehashed body {field}"
        );
    }
}

#[test]
fn valid_signature_cannot_override_epoch_parent_height_or_chain_policy() {
    let f = Fixture::new();
    for field in 0..5 {
        let mut other = f.signed();
        match field {
            0 => other.identity.epoch += 1,
            1 => other.identity.height = 8,
            2 => other.identity.parent = Parent::Block([99; 32]),
            3 => other.identity.chain_id.push('X'),
            _ => other.identity.genesis_hash[0] ^= 1,
        }
        f.resign(&mut other);
        assert!(other.authenticate(&f.context()).is_err(), "context {field}");
    }
    let mut premature = f.signed();
    premature.identity.height = 6;
    f.resign(&mut premature);
    let mut context = f.context();
    context.expected_height = 6;
    assert!(premature.authenticate(&context).is_err());
}

#[test]
fn missing_inconsistent_and_weak_authority_keys_fail_closed() {
    let mut f = Fixture::new();
    let original = f.signed();
    let good_keys = f.keys.clone();
    for missing in [original.signer, original.identity.proposer] {
        f.keys = good_keys.clone();
        f.keys.remove(&missing);
        assert!(original.authenticate(&f.context()).is_err());
    }
    f.keys.clear();
    assert!(original.authenticate(&f.context()).is_err());
    f.keys = good_keys;
    f.keys.insert(
        original.signer,
        SigningKey::from_bytes(&[79; 32]).verifying_key().to_bytes(),
    );
    assert!(original.authenticate(&f.context()).is_err());
    let mut weak = [0; 32];
    weak[0] = 1; // Encoded Edwards identity, a low-order public key.
    assert!(VerifyingKey::from_bytes(&weak).unwrap().is_weak());
    f.keys.insert(address(&weak), weak);
    let mut other = original;
    other.identity.proposer = address(&weak);
    f.resign(&mut other);
    // Restore the legitimate signer so rejection specifically tests the proposer.
    f.keys
        .insert(other.signer, f.key.verifying_key().to_bytes());
    assert!(other.authenticate(&f.context()).is_err());
}

#[test]
fn malformed_signature_wrong_domain_and_signer_substitution_are_rejected() {
    let f = Fixture::new();
    let original = f.signed();
    for size in [0, 63, 64, 65] {
        let mut other = original.clone();
        other.signature = vec![0; size];
        assert!(other.authenticate(&f.context()).is_err());
    }
    let mut unauthenticated_body = original.clone();
    unauthenticated_body.signature = vec![0; 64];
    unauthenticated_body.body.transactions[0].push(0);
    assert_eq!(
        unauthenticated_body.authenticate(&f.context()).err(),
        Some(CodecError::Invalid("invalid block signature")),
        "signature rejection must precede body validation and hashing"
    );
    let mut other = original.clone();
    other.signature = f
        .key
        .sign(&other.identity.hash().unwrap())
        .to_bytes()
        .to_vec();
    assert!(other.authenticate(&f.context()).is_err());
    let mut other = original;
    other.signer = other.identity.proposer;
    assert!(other.authenticate(&f.context()).is_err());
}

#[test]
fn builder_rejects_invalid_content_and_combined_body_budget() {
    let f = Fixture::new();
    let mut invalid = f.body.clone();
    invalid.transactions[0].push(0);
    assert!(SignedBlockV2::sign(f.identity.clone(), invalid, &f.key, &f.context()).is_err());
    let outsider = SigningKey::from_bytes(&[99; 32]);
    assert!(
        SignedBlockV2::sign(f.identity.clone(), f.body.clone(), &outsider, &f.context()).is_err()
    );
    let mut large = f.signed();
    large.body.transactions = vec![vec![0; MAX_ITEM_BYTES]; 8];
    large.body.evidence = vec![vec![0; MAX_ITEM_BYTES]; 8];
    // Each list is individually in bounds, but the total exceeds the block budget.
    large.identity.transactions_root = transactions_root(&large.body.transactions).unwrap();
    large.identity.evidence_root = evidence_root(&large.body.evidence).unwrap();
    f.resign(&mut large);
    assert_eq!(
        large.authenticate(&f.context()).err(),
        Some(CodecError::Invalid("combined body exceeds byte bound"))
    );
    // Three list framing allowances, sixteen byte-item allowances, two digests.
    let framing = 3 * 7 + 16 * 5 + 2 * 32;
    large.body.evidence[7].truncate(MAX_ITEM_BYTES - framing);
    large.identity.evidence_root = evidence_root(&large.body.evidence).unwrap();
    f.resign(&mut large);
    large
        .authenticate(&f.context())
        .expect("exact combined budget must be accepted");
    large.body.evidence[7].push(0);
    large.identity.evidence_root = evidence_root(&large.body.evidence).unwrap();
    f.resign(&mut large);
    assert_eq!(
        large.authenticate(&f.context()).err(),
        Some(CodecError::Invalid("combined body exceeds byte bound"))
    );
    let mut excess_vertices = f.signed();
    excess_vertices.body.committed_vertices = vec![[0; 32]; MAX_ITEMS + 1];
    assert!(excess_vertices.authenticate(&f.context()).is_err());
}

#[test]
fn authentication_does_not_claim_execution_or_finality_validation() {
    let f = Fixture::new();
    let mut other = f.signed();
    other.identity.state_root = [99; 32];
    other.identity.receipts_root = [98; 32];
    other.identity.finality_digest = [97; 32];
    f.resign(&mut other);
    // These signed claims still require execution and ordering/QC validation.
    assert!(other.authenticate(&f.context()).is_ok());
}
