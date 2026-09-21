//! Bounded BCS transport, not wired into production networking or acceptance.
//! Layout: (2u16, identity_bytes, signer[32], signature_bytes,
//!          (transactions, vertices[32], evidence)).
//! The signed identity is authenticated before allocating body payloads.

use super::{BodyV2, EnvelopeContext, SignedBlockV2};
use crate::identity_v2::{
    BlockIdentityV2, CodecError, MAX_BODY_BYTES, MAX_IDENTITY_BYTES, MAX_ITEMS, MAX_ITEM_BYTES,
};
use serde::de::{DeserializeSeed, Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::fmt;

// Outer version, two maximum ULEB lengths, identity, signer and signature.
// MAX_BODY_BYTES already conservatively includes all body list/item framing.
pub const MAX_WIRE_BYTES: usize = 2 + 5 + MAX_IDENTITY_BYTES + 32 + 5 + 64 + MAX_BODY_BYTES;

impl SignedBlockV2 {
    pub fn encode_wire(&self, context: &EnvelopeContext<'_>) -> Result<Vec<u8>, CodecError> {
        self.authenticate(context)?;
        bcs::to_bytes(&(
            2u16,
            self.identity.encode()?,
            self.signer,
            &self.signature,
            (
                &self.body.transactions,
                &self.body.committed_vertices,
                &self.body.evidence,
            ),
        ))
        .map_err(|e| CodecError::Encoding(e.to_string()))
    }

    /// Checks canonical framing, bounds, context, signature and body commitments.
    /// The returned object is mutable, NOT an execution/finality permission.
    /// Reauthenticate against the acceptance transaction's trusted snapshot.
    /// Caller must also bound raw network frames, queues and concurrent requests.
    pub fn decode_wire(bytes: &[u8], context: &EnvelopeContext<'_>) -> Result<Self, CodecError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(CodecError::Invalid("wire exceeds byte bound"));
        }
        bcs::from_bytes_seed(Header(context), bytes)
            .map_err(|e| CodecError::Encoding(e.to_string()))
    }
}

struct Header<'a, 'b>(&'a EnvelopeContext<'b>);

impl<'de> DeserializeSeed<'de> for Header<'_, '_> {
    type Value = SignedBlockV2;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_tuple(5, self)
    }
}

impl<'de> Visitor<'de> for Header<'_, '_> {
    type Value = SignedBlockV2;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("V2 signed block transport")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let version: u16 = required(&mut seq)?;
        if version != 2 {
            return Err(A::Error::custom("unsupported wire version"));
        }
        let identity = seq
            .next_element_seed(Bytes(MAX_IDENTITY_BYTES))?
            .ok_or_else(|| A::Error::custom("missing identity"))?;
        let identity = BlockIdentityV2::decode(identity).map_err(A::Error::custom)?;
        let signer = required(&mut seq)?;
        let signature = seq
            .next_element_seed(Bytes(64))?
            .ok_or_else(|| A::Error::custom("missing signature"))?;
        let mut block = SignedBlockV2 {
            identity,
            signer,
            signature: signature.to_vec(),
            body: BodyV2 {
                transactions: vec![],
                committed_vertices: vec![],
                evidence: vec![],
            },
        };
        block
            .authenticate_header(self.0)
            .map_err(A::Error::custom)?;
        block.body = seq
            .next_element_seed(Body)?
            .ok_or_else(|| A::Error::custom("missing body"))?;
        block
            .body
            .validate(&block.identity)
            .map_err(A::Error::custom)?;
        Ok(block)
    }
}

fn required<'de, A: SeqAccess<'de>, T: Deserialize<'de>>(seq: &mut A) -> Result<T, A::Error> {
    seq.next_element()?
        .ok_or_else(|| A::Error::custom("missing wire field"))
}

// Slice-backed BCS calls visit_borrowed_bytes without allocating a Vec. Do not
// add an allocating fallback or expose this as a generic reader-based decoder.
struct Bytes(usize);
impl<'de> DeserializeSeed<'de> for Bytes {
    type Value = &'de [u8];
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_bytes(self)
    }
}
impl<'de> Visitor<'de> for Bytes {
    type Value = &'de [u8];
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded borrowed bytes")
    }
    fn visit_borrowed_bytes<E: Error>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
        if bytes.len() > self.0 {
            return Err(E::custom("byte item exceeds bound"));
        }
        Ok(bytes)
    }
}

struct Budget(usize);
impl Budget {
    fn charge<E: Error>(&mut self, size: usize) -> Result<(), E> {
        self.0 = self
            .0
            .checked_sub(size)
            .ok_or_else(|| E::custom("combined body exceeds byte bound"))?;
        Ok(())
    }
}

struct Body;
impl<'de> DeserializeSeed<'de> for Body {
    type Value = BodyV2;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_tuple(3, self)
    }
}
impl<'de> Visitor<'de> for Body {
    type Value = BodyV2;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded block body")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut budget = Budget(MAX_BODY_BYTES);
        let transactions = seq
            .next_element_seed(ByteList(&mut budget))?
            .ok_or_else(|| A::Error::custom("missing transactions"))?;
        let committed_vertices = seq
            .next_element_seed(Vertices(&mut budget))?
            .ok_or_else(|| A::Error::custom("missing vertices"))?;
        let evidence = seq
            .next_element_seed(ByteList(&mut budget))?
            .ok_or_else(|| A::Error::custom("missing evidence"))?;
        Ok(BodyV2 {
            transactions,
            committed_vertices,
            evidence,
        })
    }
}

fn bounded_count<'de, A: SeqAccess<'de>>(seq: &A) -> Result<usize, A::Error> {
    let count = seq
        .size_hint()
        .ok_or_else(|| A::Error::custom("missing BCS sequence length"))?;
    if count > MAX_ITEMS {
        return Err(A::Error::custom("too many body items"));
    }
    Ok(count)
}

struct ByteList<'a>(&'a mut Budget);
impl<'de> DeserializeSeed<'de> for ByteList<'_> {
    type Value = Vec<Vec<u8>>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for ByteList<'_> {
    type Value = Vec<Vec<u8>>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded byte-item list")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let count = bounded_count(&seq)?;
        self.0.charge::<A::Error>(7 + 5 * count)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let bytes = seq
                .next_element_seed(Bytes(MAX_ITEM_BYTES.min(self.0 .0)))?
                .ok_or_else(|| A::Error::custom("missing byte item"))?;
            self.0.charge::<A::Error>(bytes.len())?;
            items.push(bytes.to_vec());
        }
        Ok(items)
    }
}

struct Vertices<'a>(&'a mut Budget);
impl<'de> DeserializeSeed<'de> for Vertices<'_> {
    type Value = Vec<crate::identity_v2::Digest>;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Vertices<'_> {
    type Value = Vec<crate::identity_v2::Digest>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded vertex list")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let count = bounded_count(&seq)?;
        self.0.charge::<A::Error>(7 + 32 * count)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(required(&mut seq)?);
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests;
