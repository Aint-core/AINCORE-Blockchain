use super::*;

fn proof(height: u64) -> GenesisFormatProof {
    GenesisFormatProof {
        base_genesis_identity: [11; 32],
        chain_id: "AIN-TEST".into(),
        v2_from_height: height,
    }
}

fn verified(height: u64) -> VerifiedFormatPolicy {
    let proof = proof(height);
    VerifiedFormatPolicy::verify_against_pin(
        proof.proposed_genesis_identity().unwrap(),
        &proof.encode().unwrap(),
    )
    .unwrap()
}

#[test]
fn genesis_policy_matches_independent_fixed_vector() {
    let original = proof(21);
    let bytes = hex::decode(include_str!("../../../test-vectors/genesis_format_policy.hex").trim())
        .unwrap();
    assert_eq!(original.encode().unwrap(), bytes);
    let trusted: Digest =
        hex::decode("dd4a5ea91fcaab9fa3f9282bd9c8ca8285d38ce4e3031346bd6e3c1d979ea5dd")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(original.proposed_genesis_identity().unwrap(), trusted);
    let policy = VerifiedFormatPolicy::verify_against_pin(trusted, &bytes).unwrap();
    assert_eq!(policy.chain_id(), "AIN-TEST");
    assert_eq!(policy.required_version(20).unwrap(), 1);
    assert_eq!(policy.required_version(21).unwrap(), 2);
}

#[test]
fn each_height_has_exactly_one_format_without_downgrade() {
    for activation in [1, 2, 21, u64::MAX] {
        let policy = verified(activation);
        for height in [
            1,
            activation.saturating_sub(1).max(1),
            activation,
            activation.saturating_add(1),
            u64::MAX,
        ] {
            let required = if height < activation { 1 } else { 2 };
            assert_eq!(policy.required_version(height).unwrap(), required);
            for version in [0, 1, 2, 3, u16::MAX] {
                assert_eq!(
                    policy.check_version(height, version).is_ok(),
                    version == required
                );
            }
        }
        assert!(policy.required_version(0).is_err());
    }
}

#[test]
fn policy_changes_cannot_reuse_a_trusted_pin() {
    let original = proof(21);
    let trusted = original.proposed_genesis_identity().unwrap();
    for field in 0..3 {
        let mut other = original.clone();
        match field {
            0 => other.base_genesis_identity[0] ^= 1,
            1 => other.chain_id.push('X'),
            _ => other.v2_from_height = 1,
        }
        assert_ne!(other.proposed_genesis_identity().unwrap(), trusted);
        assert!(
            VerifiedFormatPolicy::verify_against_pin(trusted, &other.encode().unwrap()).is_err()
        );
    }
    assert!(
        VerifiedFormatPolicy::verify_against_pin([0; 32], &original.encode().unwrap()).is_err()
    );
}

#[test]
fn malformed_unknown_noncanonical_and_oversized_proofs_are_rejected() {
    let original = proof(21);
    let trusted = original.proposed_genesis_identity().unwrap();
    let bytes = original.encode().unwrap();
    for end in 0..bytes.len() {
        assert!(VerifiedFormatPolicy::verify_against_pin(trusted, &bytes[..end]).is_err());
    }
    let mut unknown = bytes.clone();
    unknown[..2].copy_from_slice(&2u16.to_le_bytes());
    assert!(VerifiedFormatPolicy::verify_against_pin(trusted, &unknown).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(VerifiedFormatPolicy::verify_against_pin(trusted, &trailing).is_err());
    let mut nonminimal = bytes;
    assert_eq!(nonminimal[34], 8);
    nonminimal.splice(34..35, [0x88, 0x00]);
    assert!(VerifiedFormatPolicy::verify_against_pin(trusted, &nonminimal).is_err());
    assert!(
        VerifiedFormatPolicy::verify_against_pin(trusted, &vec![0; MAX_POLICY_BYTES + 1]).is_err()
    );
    assert!(proof(0).encode().is_err());
    let mut invalid = original;
    invalid.chain_id.clear();
    assert!(invalid.encode().is_err());
}

#[test]
fn v2_signing_requires_authorized_height_and_chain_context() {
    let policy = verified(7);
    let mut identity = crate::identity_v2::tests::fixture();
    identity.genesis_hash = policy.genesis_identity();
    assert_eq!(
        policy.signing_bytes(&identity).unwrap(),
        identity.signing_bytes().unwrap()
    );
    for mutation in 0..3 {
        let mut other = identity.clone();
        match mutation {
            0 => other.height = 6,
            1 => other.chain_id.push('X'),
            _ => other.genesis_hash[0] ^= 1,
        }
        assert!(policy.signing_bytes(&other).is_err());
    }
}
