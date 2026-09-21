//! Proposed canonical identity codec. NOT wired to block production/acceptance.
//! Activation, committee authority and execution validity belong to callers;
//! possession of these bytes alone proves none of those properties.

use serde::{Deserialize, Serialize};

pub mod envelope;
pub mod policy;

pub type Digest = [u8; 32];
pub const VERSION: u16 = 2;
pub const MAX_IDENTITY_BYTES: usize = 1024;
pub const MAX_CHAIN_ID_BYTES: usize = 128;
pub const MAX_ITEMS: usize = 10_000;
pub const MAX_ITEM_BYTES: usize = 1024 * 1024;
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const HASH_DOMAIN: &[u8] = b"AINCORE_BLOCK_ID_V2\0";
const SIGN_DOMAIN: &[u8] = b"AINCORE_BLOCK_PROPOSER_V2\0";
const TX_DOMAIN: &[u8] = b"AINCORE_BLOCK_TRANSACTIONS_V2\0";
const VERTICES_DOMAIN: &[u8] = b"AINCORE_BLOCK_VERTICES_V2\0";
const EVIDENCE_DOMAIN: &[u8] = b"AINCORE_BLOCK_EVIDENCE_V2\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Parent {
    Genesis,
    Block(Digest),
}

/// Field order is part of the proposal; no JSON or decimal-string concatenation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockIdentityV2 {
    pub chain_id: String,
    pub genesis_hash: Digest,
    pub epoch: u64,
    pub height: u64,
    pub parent: Parent,
    pub anchor_round: u64,
    pub anchor_hash: Digest,
    pub timestamp: u64,
    pub proposer: Digest,
    pub transactions_root: Digest,
    pub state_root: Digest,
    pub receipts_root: Digest,
    pub vertices_root: Digest,
    pub evidence_root: Digest,
    pub finality_digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Invalid(&'static str),
    UnsupportedVersion(u16),
    Encoding(String),
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported block identity version {version}")
            }
            Self::Encoding(reason) => write!(f, "invalid canonical encoding: {reason}"),
        }
    }
}

impl std::error::Error for CodecError {}

impl BlockIdentityV2 {
    fn validate(&self) -> Result<(), CodecError> {
        if self.chain_id.is_empty() || self.chain_id.len() > MAX_CHAIN_ID_BYTES {
            return Err(CodecError::Invalid("chain ID length outside codec bounds"));
        }
        if self.height == 0 || self.anchor_round == 0 {
            return Err(CodecError::Invalid(
                "block height and anchor round must be positive",
            ));
        }
        if (self.height == 1) != matches!(self.parent, Parent::Genesis) {
            return Err(CodecError::Invalid(
                "parent kind does not match block height",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let bytes =
            bcs::to_bytes(&(VERSION, self)).map_err(|e| CodecError::Encoding(e.to_string()))?;
        if bytes.len() > MAX_IDENTITY_BYTES {
            return Err(CodecError::Invalid("identity exceeds byte bound"));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_IDENTITY_BYTES {
            return Err(CodecError::Invalid("identity exceeds byte bound"));
        }
        let (version, identity): (u16, Self) =
            bcs::from_bytes(bytes).map_err(|e| CodecError::Encoding(e.to_string()))?;
        if version != VERSION {
            return Err(CodecError::UnsupportedVersion(version));
        }
        identity.validate()?;
        Ok(identity)
    }

    pub fn hash(&self) -> Result<Digest, CodecError> {
        Ok(domain_hash(HASH_DOMAIN, &self.encode()?))
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, CodecError> {
        let mut bytes = SIGN_DOMAIN.to_vec();
        bytes.extend_from_slice(&self.hash()?);
        Ok(bytes)
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest {
    let mut preimage = Vec::with_capacity(domain.len() + bytes.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    crypto::hash(&preimage)
        .try_into()
        .expect("SHA-256 outputs 32 bytes")
}

pub(super) fn byte_items_framed_size(items: &[Vec<u8>]) -> Result<usize, CodecError> {
    if items.len() > MAX_ITEMS {
        return Err(CodecError::Invalid("too many body items"));
    }
    // Conservative framing allowance bounds allocation BEFORE BCS serialization.
    let mut size = 7usize;
    for item in items {
        if item.len() > MAX_ITEM_BYTES {
            return Err(CodecError::Invalid("body item exceeds byte bound"));
        }
        size = size
            .checked_add(5)
            .and_then(|n| n.checked_add(item.len()))
            .ok_or(CodecError::Invalid("body size overflow"))?;
        if size > MAX_BODY_BYTES {
            return Err(CodecError::Invalid("body exceeds byte bound"));
        }
    }
    Ok(size)
}

fn byte_items_root(domain: &[u8], items: &[Vec<u8>]) -> Result<Digest, CodecError> {
    byte_items_framed_size(items)?;
    let bytes =
        bcs::to_bytes(&(VERSION, items)).map_err(|e| CodecError::Encoding(e.to_string()))?;
    Ok(domain_hash(domain, &bytes))
}

pub fn transactions_root(transactions: &[Vec<u8>]) -> Result<Digest, CodecError> {
    byte_items_root(TX_DOMAIN, transactions)
}

pub fn evidence_root(evidence: &[Vec<u8>]) -> Result<Digest, CodecError> {
    byte_items_root(EVIDENCE_DOMAIN, evidence)
}

pub fn vertices_root(vertices: &[Digest]) -> Result<Digest, CodecError> {
    if vertices.len() > MAX_ITEMS {
        return Err(CodecError::Invalid("too many vertices"));
    }
    let bytes =
        bcs::to_bytes(&(VERSION, vertices)).map_err(|e| CodecError::Encoding(e.to_string()))?;
    Ok(domain_hash(VERTICES_DOMAIN, &bytes))
}

#[cfg(test)]
mod tests;
