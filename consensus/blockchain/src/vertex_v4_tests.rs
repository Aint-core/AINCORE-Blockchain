//! G1 S2: the V4 vertex codec. The hash binds every field and the epoch; the
//! transport fields of a parent ref stay outside it; the V3 hash and V3 bytes
//! are unchanged. The goldens come from an independent encoder (Python,
//! hashlib and struct), not from this code.

use super::*;

const CHAIN: &str = "AINCORE-GOLDEN";
const GENESIS: &str = "golden-genesis";

fn golden() -> Vertex {
    let (p1, p2) = ("1".repeat(64), "2".repeat(64));
    let r = |author: String, digest: &String| ParentRef {
        round: 1233,
        author,
        digest: digest.clone(),
        proof: None,
        cert: None,
    };
    Vertex {
        epoch: 7,
        round: 1234,
        author: "a".repeat(64),
        parents: vec![p1.clone(), p2.clone()],
        parent_refs: vec![r("b".repeat(64), &p1), r("c".repeat(64), &p2)],
        payload: vec!["tx1".into(), "tx2".into()],
        timestamp: 1_790_000_000,
        hash: String::new(),
        signature: String::new(),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
    }
}

#[test]
fn the_v4_hash_matches_the_independent_encoder() {
    assert_eq!(
        golden().hash_v4_with_domain(CHAIN, GENESIS),
        "f5fcb37691138f90247b16f5ca7548ff4710f08ad5cdf2bd29ce9cbafb0811bf"
    );
    assert_eq!(
        epoch_genesis(CHAIN, GENESIS, 7, 1234, &"d".repeat(64), &"e".repeat(64)),
        "f7aeb8b6c19fb299dd1304bbdaf9dd5c68f6df82313013d9ad67b937f5730d51"
    );
    assert_eq!(epoch_genesis(CHAIN, GENESIS, 0, 1, "x", "y"), "genesis");
}

#[test]
fn the_v4_hash_binds_every_field() {
    let base = golden();
    let h = |v: &Vertex| v.hash_v4_with_domain(CHAIN, GENESIS);
    type Change = Box<dyn Fn(&mut Vertex)>;
    let changes: Vec<(&str, Change)> = vec![
        ("epoch", Box::new(|v| v.epoch += 1)),
        ("round", Box::new(|v| v.round += 1)),
        ("author", Box::new(|v| v.author = "f".repeat(64))),
        (
            "parents",
            Box::new(|v| v.parents.pop().map(|_| ()).unwrap()),
        ),
        ("ref round", Box::new(|v| v.parent_refs[0].round += 1)),
        (
            "ref author",
            Box::new(|v| v.parent_refs[1].author = "d".repeat(64)),
        ),
        (
            "absent vs empty aggregate",
            Box::new(|v| v.aggregated_signature = Some(String::new())),
        ),
        ("timestamp", Box::new(|v| v.timestamp += 1)),
        ("payload", Box::new(|v| v.payload = vec!["tx1tx2".into()])),
    ];
    for (field, change) in changes {
        let mut v = base.clone();
        change(&mut v);
        assert_ne!(h(&v), h(&base), "{field}");
    }
    assert_ne!(
        base.hash_v4_with_domain("AINCORE-GOLDEN2", GENESIS),
        h(&base),
        "chain"
    );
    assert_ne!(base.hash_v4_with_domain(CHAIN, "g"), h(&base), "genesis");
    // Length prefixes: moving a byte between chain and genesis changes it.
    assert_ne!(
        base.hash_v4_with_domain("AINCORE-GOLDENg", "olden-genesis"),
        h(&base)
    );
}

#[test]
fn transport_fields_of_a_ref_are_not_hashed() {
    let base = golden();
    let mut v = base.clone();
    v.parent_refs[0].cert = Some(CompactCert {
        signer_bitmap: vec![7],
        aggregate_signature: vec![1, 2, 3],
    });
    v.parent_refs[1].proof = Some(ParentIdentityProof {
        timestamp: 1,
        payload_root: "0".repeat(64),
        parents_root: "0".repeat(64),
        public_key: "0".repeat(64),
        signature: "0".repeat(128),
    });
    assert_eq!(
        v.hash_v4_with_domain(CHAIN, GENESIS),
        base.hash_v4_with_domain(CHAIN, GENESIS)
    );
    assert_eq!(
        v.calculate_hash_with_domain(CHAIN, GENESIS),
        base.calculate_hash_with_domain(CHAIN, GENESIS)
    );
}

#[test]
fn v3_hashes_and_bytes_are_unchanged() {
    let mut v = golden();
    let v3 = v.calculate_hash_with_domain(CHAIN, GENESIS);
    v.epoch = 0;
    // The V3 hash does not read the epoch, and the V4 hash differs from it.
    assert_eq!(v.calculate_hash_with_domain(CHAIN, GENESIS), v3);
    assert_ne!(v.hash_v4_with_domain(CHAIN, GENESIS), v3);
    assert_ne!(
        parents_root_v4_of(&v.parents, &v.parent_refs),
        parents_root_of(&v.parents, &v.parent_refs)
    );
    // A V3 vertex (epoch 0, refs without a certificate) serializes as before.
    let json = serde_json::to_string(&v).unwrap();
    assert!(
        !json.contains("\"epoch\"") && !json.contains("\"cert\""),
        "{json}"
    );
    let old: Vertex = serde_json::from_str(&json).unwrap();
    assert_eq!(old.epoch, 0);
    // A V4 vertex keeps its epoch and certificates across the wire.
    let mut v4 = golden();
    v4.parent_refs[0].cert = Some(CompactCert {
        signer_bitmap: vec![7],
        aggregate_signature: vec![9],
    });
    let back: Vertex = serde_json::from_str(&serde_json::to_string(&v4).unwrap()).unwrap();
    assert_eq!(back.epoch, 7);
    assert_eq!(back.parent_refs[0].cert, v4.parent_refs[0].cert);
}

#[test]
fn every_epoch_sentinel_field_counts() {
    let base = || epoch_genesis(CHAIN, GENESIS, 3, 100, "p", "q");
    let variants = [
        epoch_genesis("AINCORE-GOLDEN2", GENESIS, 3, 100, "p", "q"),
        epoch_genesis(CHAIN, "other", 3, 100, "p", "q"),
        epoch_genesis(CHAIN, GENESIS, 4, 100, "p", "q"),
        epoch_genesis(CHAIN, GENESIS, 3, 101, "p", "q"),
        epoch_genesis(CHAIN, GENESIS, 3, 100, "r", "q"),
        epoch_genesis(CHAIN, GENESIS, 3, 100, "p", "r"),
        // A byte moved across the block/anchor boundary.
        epoch_genesis(CHAIN, GENESIS, 3, 100, "pq", ""),
    ];
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v, &base(), "variant {i}");
    }
}
