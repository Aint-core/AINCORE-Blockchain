use super::*;

const VECTORS: &str = include_str!("../vectors/pf_vectors.json");

fn run(v: &serde_json::Value) -> Result<(), ProofError> {
    let root = parse_hash(v["root"].as_str().unwrap())?;
    let proof: WireProof = serde_json::from_value(v["proof"].clone()).unwrap();
    let value = v["value"].as_str().map(str::as_bytes);
    verify(&root, v["key"].as_str().unwrap(), value, &proof)
}

/// PF-4: every shared vector, generated from real trees by `state_commit`,
/// verifies here exactly as labelled, with no tree implementation in sight.
#[test]
fn every_shared_vector_verifies_as_labelled() {
    let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = doc["vectors"].as_array().unwrap();
    let (mut valid, mut invalid, mut empty_subtree) = (0, 0, 0);
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let result = run(v);
        if v["valid"].as_bool().unwrap() {
            assert_eq!(result, Ok(()), "{name}");
            valid += 1;
            if v["proof"]["leaf"].is_null() {
                empty_subtree += 1;
            }
        } else {
            assert!(result.is_err(), "{name} must be refused");
            invalid += 1;
        }
    }
    assert!(
        valid >= 12 && invalid >= 12,
        "positive control: {valid} / {invalid}"
    );
    assert!(empty_subtree >= 3, "both exclusion shapes are covered");
}

/// The empty tree's root is the placeholder, and every key is absent there.
#[test]
fn every_key_is_absent_from_the_empty_tree() {
    let proof = WireProof {
        leaf: None,
        siblings: vec![],
    };
    assert_eq!(verify(&PLACEHOLDER, "anything", None, &proof), Ok(()));
    assert_eq!(
        verify(&PLACEHOLDER, "anything", Some(b"x"), &proof),
        Err(ProofError::ExpectedInclusion)
    );
}

/// A one-leaf tree's root is that leaf's hash: a bottom-up check of the leaf
/// encoding that does not depend on the vector file.
#[test]
fn a_single_leaf_tree_root_is_the_leaf_hash() {
    let (key, value) = ("sys:chain_id", b"AINCORE-LOCALTEST-4V-HEAD".as_slice());
    let root = leaf_hash(&key_hash(key), &value_hash(value));
    let proof = WireProof {
        leaf: Some(WireLeaf {
            key_hash: hex::encode(key_hash(key)),
            value_hash: hex::encode(value_hash(value)),
        }),
        siblings: vec![],
    };
    assert_eq!(verify(&root, key, Some(value), &proof), Ok(()));
    assert_eq!(
        verify(&root, "other", None, &proof),
        Ok(()),
        "any other key is absent: the only leaf is on every path"
    );
}

#[test]
fn too_many_siblings_are_malformed() {
    let proof = WireProof {
        leaf: None,
        siblings: vec!["00".repeat(32); MAX_SIBLINGS + 1],
    };
    assert!(matches!(
        verify(&PLACEHOLDER, "k", None, &proof),
        Err(ProofError::Malformed(_))
    ));
}
