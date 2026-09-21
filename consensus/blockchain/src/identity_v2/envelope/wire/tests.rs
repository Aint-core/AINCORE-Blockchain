use super::super::tests::Fixture;
use super::*;
use crate::identity_v2::{evidence_root, transactions_root, vertices_root};

fn prefix(block: &SignedBlockV2) -> Vec<u8> {
    bcs::to_bytes(&(
        2u16,
        block.identity.encode().unwrap(),
        block.signer,
        &block.signature,
    ))
    .unwrap()
}

fn unchecked_wire(block: &SignedBlockV2) -> Vec<u8> {
    let mut bytes = prefix(block);
    bytes.extend(
        bcs::to_bytes(&(
            &block.body.transactions,
            &block.body.committed_vertices,
            &block.body.evidence,
        ))
        .unwrap(),
    );
    bytes
}

fn uleb(mut value: usize) -> Vec<u8> {
    let mut bytes = vec![];
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value != 0 { 128 } else { 0 });
        if value == 0 {
            return bytes;
        }
    }
}

#[test]
fn canonical_wire_roundtrip_and_fixed_vector() {
    let f = Fixture::new();
    let block = f.signed();
    let wire = block.encode_wire(&f.context()).unwrap();
    assert_eq!(wire, unchecked_wire(&block));
    assert_eq!(
        wire,
        hex::decode(include_str!("../../../../test-vectors/envelope_wire_v2.hex").trim()).unwrap()
    );
    let decoded = SignedBlockV2::decode_wire(&wire, &f.context()).unwrap();
    assert_eq!(decoded, block);
    assert_eq!(decoded.encode_wire(&f.context()).unwrap(), wire);
}

#[test]
fn reject_truncations_trailing_versions_and_nonminimal_lengths() {
    let f = Fixture::new();
    let wire = f.signed().encode_wire(&f.context()).unwrap();
    for end in 0..wire.len() {
        assert!(
            SignedBlockV2::decode_wire(&wire[..end], &f.context()).is_err(),
            "accepted truncation {end}"
        );
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(SignedBlockV2::decode_wire(&trailing, &f.context()).is_err());
    for version in [0u16, 1, 3, u16::MAX] {
        let mut bad = wire.clone();
        bad[..2].copy_from_slice(&version.to_le_bytes());
        assert!(SignedBlockV2::decode_wire(&bad, &f.context()).is_err());
    }
    let mut nonminimal = wire;
    let end = (2..nonminimal.len())
        .find(|&i| nonminimal[i] < 128)
        .unwrap();
    nonminimal[end] |= 128;
    nonminimal.insert(end + 1, 0);
    assert!(SignedBlockV2::decode_wire(&nonminimal, &f.context()).is_err());
}

#[test]
fn authenticates_small_header_before_requesting_any_body() {
    let f = Fixture::new();
    let mut block = f.signed();
    block.signature[0] ^= 1;
    let error = SignedBlockV2::decode_wire(&prefix(&block), &f.context()).unwrap_err();
    assert!(
        error.to_string().contains("invalid block signature"),
        "{error}"
    );
    block = f.signed();
    block.identity.epoch += 1;
    f.resign(&mut block);
    let error = SignedBlockV2::decode_wire(&prefix(&block), &f.context()).unwrap_err();
    assert!(
        error.to_string().contains("trusted acceptance context"),
        "{error}"
    );
}

#[test]
fn reject_oversized_header_item_and_wire() {
    let f = Fixture::new();
    let oversized_identity = bcs::to_bytes(&(2u16, vec![0u8; MAX_IDENTITY_BYTES + 1])).unwrap();
    assert!(
        SignedBlockV2::decode_wire(&oversized_identity, &f.context())
            .unwrap_err()
            .to_string()
            .contains("byte item exceeds bound")
    );
    let mut block = f.signed();
    for length in [0, 63, 65] {
        block.signature = vec![0; length];
        assert!(SignedBlockV2::decode_wire(&prefix(&block), &f.context()).is_err());
    }
    let mut wire = prefix(&f.signed());
    wire.extend(uleb(1));
    wire.extend(bcs::to_bytes(&vec![0u8; MAX_ITEM_BYTES + 1]).unwrap());
    assert!(SignedBlockV2::decode_wire(&wire, &f.context())
        .unwrap_err()
        .to_string()
        .contains("byte item exceeds bound"));
    assert!(matches!(
        SignedBlockV2::decode_wire(&vec![0; MAX_WIRE_BYTES + 1], &f.context()),
        Err(CodecError::Invalid("wire exceeds byte bound"))
    ));
}

#[test]
fn reject_huge_counts_before_reading_elements_for_all_three_lists() {
    let f = Fixture::new();
    for list in 0..3 {
        let mut wire = prefix(&f.signed());
        wire.extend(vec![0; list]);
        wire.extend(uleb(MAX_ITEMS + 1));
        let error = SignedBlockV2::decode_wire(&wire, &f.context()).unwrap_err();
        assert!(error.to_string().contains("too many body items"), "{error}");
    }
}

#[test]
fn maximum_item_counts_are_accepted_in_each_list() {
    let f = Fixture::new();
    let mut block = f.signed();
    block.body.transactions = vec![vec![]; MAX_ITEMS];
    block.body.committed_vertices = vec![[11; 32]; MAX_ITEMS];
    block.body.evidence = vec![vec![]; MAX_ITEMS];
    block.identity.transactions_root = transactions_root(&block.body.transactions).unwrap();
    block.identity.vertices_root = vertices_root(&block.body.committed_vertices).unwrap();
    block.identity.evidence_root = evidence_root(&block.body.evidence).unwrap();
    f.resign(&mut block);
    let wire = block.encode_wire(&f.context()).unwrap();
    assert_eq!(
        SignedBlockV2::decode_wire(&wire, &f.context()).unwrap(),
        block
    );
}

// A post-deserialization length check would touch elements and panic here.
struct NoElements(usize);
impl<'de> SeqAccess<'de> for NoElements {
    type Error = serde::de::value::Error;
    fn size_hint(&self) -> Option<usize> {
        Some(self.0)
    }
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        _: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        panic!("must reject before requesting an element")
    }
}

#[test]
fn count_and_framing_budget_reject_before_reservation_or_element_request() {
    for count in [MAX_ITEMS + 1, usize::MAX] {
        assert!(ByteList(&mut Budget(MAX_BODY_BYTES))
            .visit_seq(NoElements(count))
            .is_err());
        assert!(Vertices(&mut Budget(MAX_BODY_BYTES))
            .visit_seq(NoElements(count))
            .is_err());
    }
    assert!(ByteList(&mut Budget(11)).visit_seq(NoElements(1)).is_err());
    assert!(Vertices(&mut Budget(38)).visit_seq(NoElements(1)).is_err());
    let bytes = [1u8; 8];
    assert!(Bytes(7)
        .visit_borrowed_bytes::<serde::de::value::Error>(&bytes)
        .is_err());
    let borrowed = Bytes(8)
        .visit_borrowed_bytes::<serde::de::value::Error>(&bytes)
        .unwrap();
    assert_eq!(borrowed.as_ptr(), bytes.as_ptr());
}

#[test]
fn aggregate_budget_exact_boundary_and_one_byte_over() {
    let f = Fixture::new();
    let mut block = f.signed();
    block.body.transactions = vec![vec![1; MAX_ITEM_BYTES]; 8];
    block.body.evidence = vec![vec![2; MAX_ITEM_BYTES]; 8];
    let framing = 3 * 7 + 16 * 5 + 2 * 32;
    block
        .body
        .evidence
        .last_mut()
        .unwrap()
        .truncate(MAX_ITEM_BYTES - framing);
    block.identity.transactions_root = transactions_root(&block.body.transactions).unwrap();
    block.identity.evidence_root = evidence_root(&block.body.evidence).unwrap();
    f.resign(&mut block);
    let wire = block.encode_wire(&f.context()).unwrap();
    assert_eq!(
        SignedBlockV2::decode_wire(&wire, &f.context()).unwrap(),
        block
    );
    block.body.evidence.last_mut().unwrap().push(2);
    block.identity.evidence_root = evidence_root(&block.body.evidence).unwrap();
    f.resign(&mut block);
    let wire = unchecked_wire(&block);
    assert!(wire.len() <= MAX_WIRE_BYTES);
    assert!(SignedBlockV2::decode_wire(&wire, &f.context()).is_err());
}

#[test]
fn valid_header_does_not_bypass_body_commitments_or_new_context() {
    let f = Fixture::new();
    let mut block = f.signed();
    block.body.transactions[0][0] ^= 1;
    assert!(
        SignedBlockV2::decode_wire(&unchecked_wire(&block), &f.context())
            .unwrap_err()
            .to_string()
            .contains("signed commitments")
    );
    let wire = f.signed().encode_wire(&f.context()).unwrap();
    let mut context = f.context();
    context.expected_height += 1;
    assert!(SignedBlockV2::decode_wire(&wire, &context).is_err());
}
