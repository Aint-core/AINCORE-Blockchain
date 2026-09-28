//! G3 PF: verify that a key has a value (or is absent) under a state root,
//! with no database and no Jellyfish Merkle Tree implementation.
//!
//! This is the client half of `aincore_getStateProof`. Bridges and light
//! clients use it; the JS verifier in `aincore-js` mirrors it line for line,
//! and both are tested against `vectors/pf_vectors.json` (PF-4).
//!
//! The wire format and the algorithm are frozen. They are those of `jmt`
//! 0.12 with SHA-256:
//! - `KeyHash = SHA-256(key)`, derived here from the canonical key, never
//!   taken from the server (PF-2.5);
//! - `ValueHash = SHA-256(value)`, over the exact stored bytes (KV-1);
//! - `leaf = SHA-256("JMT::LeafNode" ‖ key_hash ‖ value_hash)`;
//! - `internal = SHA-256("JMT::IntrnalNode" ‖ left ‖ right)`;
//! - an empty subtree is `"SPARSE_MERKLE_PLACEHOLDER_HASH__"`;
//! - siblings run from the bottom of the tree to the root, and sibling `i`
//!   (of `n`) sits on the side given by bit `n - 1 - i` of the key hash,
//!   counting from the most significant bit.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const LEAF_DOMAIN: &[u8] = b"JMT::LeafNode";
pub const INTERNAL_DOMAIN: &[u8] = b"JMT::IntrnalNode";
pub const PLACEHOLDER: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";
pub const MAX_SIBLINGS: usize = 256;

/// The leaf the proof ends at: the key's own leaf (inclusion), or the only
/// leaf in the subtree where the key would sit (exclusion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLeaf {
    /// 64 lowercase hex.
    pub key_hash: String,
    /// 64 lowercase hex.
    pub value_hash: String,
}

/// A sparse Merkle proof on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireProof {
    /// `None`: the key's position is an empty subtree (exclusion).
    pub leaf: Option<WireLeaf>,
    /// Sibling hashes, 64 lowercase hex each, from the bottom to the root.
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofError {
    /// A hash is not 32 bytes of hex, or there are too many siblings.
    Malformed(String),
    /// An inclusion proof for another key.
    KeyMismatch,
    /// The value's hash is not the leaf's.
    ValueMismatch,
    /// A value was claimed, but the proof shows the key absent.
    ExpectedInclusion,
    /// Absence was claimed, but the proof shows the key present.
    ExpectedExclusion,
    /// The proof's leaf could not be where the key would sit.
    NotInSubtree,
    /// The proof does not lead to the trusted root.
    RootMismatch,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::Malformed(m) => write!(f, "malformed proof: {m}"),
            ProofError::KeyMismatch => write!(f, "the proof is for another key"),
            ProofError::ValueMismatch => write!(f, "the value does not match the proof"),
            ProofError::ExpectedInclusion => write!(f, "the proof shows the key absent"),
            ProofError::ExpectedExclusion => write!(f, "the proof shows the key present"),
            ProofError::NotInSubtree => write!(f, "the proof's leaf is not on the key's path"),
            ProofError::RootMismatch => write!(f, "the proof does not reach the trusted root"),
        }
    }
}

impl std::error::Error for ProofError {}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// The key hash a client derives itself from the canonical key (PF-2.5).
pub fn key_hash(key: &str) -> [u8; 32] {
    sha256(&[key.as_bytes()])
}

pub fn value_hash(value: &[u8]) -> [u8; 32] {
    sha256(&[value])
}

pub fn leaf_hash(key_hash: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    sha256(&[LEAF_DOMAIN, key_hash, value_hash])
}

pub fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[INTERNAL_DOMAIN, left, right])
}

/// Parse 64 hex characters.
pub fn parse_hash(hex_str: &str) -> Result<[u8; 32], ProofError> {
    let bytes =
        hex::decode(hex_str).map_err(|_| ProofError::Malformed(format!("not hex: {hex_str}")))?;
    bytes
        .try_into()
        .map_err(|_| ProofError::Malformed(format!("not 32 bytes: {hex_str}")))
}

fn bit(hash: &[u8; 32], index: usize) -> bool {
    hash[index / 8] & (0x80 >> (index % 8)) != 0
}

fn common_prefix_bits(a: &[u8; 32], b: &[u8; 32]) -> usize {
    (0..256).take_while(|&i| bit(a, i) == bit(b, i)).count()
}

/// Verify that `key` has `value` (`Some`) or is absent (`None`) in the tree
/// whose root is `root`.
pub fn verify(
    root: &[u8; 32],
    key: &str,
    value: Option<&[u8]>,
    proof: &WireProof,
) -> Result<(), ProofError> {
    if proof.siblings.len() > MAX_SIBLINGS {
        return Err(ProofError::Malformed(format!(
            "{} siblings",
            proof.siblings.len()
        )));
    }
    let kh = key_hash(key);
    let leaf = match &proof.leaf {
        Some(leaf) => Some((parse_hash(&leaf.key_hash)?, parse_hash(&leaf.value_hash)?)),
        None => None,
    };
    match (value, leaf) {
        (Some(value), Some((leaf_key, leaf_value))) => {
            if leaf_key != kh {
                return Err(ProofError::KeyMismatch);
            }
            if leaf_value != value_hash(value) {
                return Err(ProofError::ValueMismatch);
            }
        }
        (Some(_), None) => return Err(ProofError::ExpectedInclusion),
        (None, Some((leaf_key, _))) => {
            if leaf_key == kh {
                return Err(ProofError::ExpectedExclusion);
            }
            // Implied by the root check below (the path follows the key's
            // own bits, so a leaf elsewhere cannot hash to the root), and
            // kept as in `jmt` for a clear refusal.
            if common_prefix_bits(&kh, &leaf_key) < proof.siblings.len() {
                return Err(ProofError::NotInSubtree);
            }
        }
        (None, None) => {}
    }
    let mut hash = match leaf {
        Some((leaf_key, leaf_value)) => leaf_hash(&leaf_key, &leaf_value),
        None => PLACEHOLDER,
    };
    let n = proof.siblings.len();
    for (i, sibling) in proof.siblings.iter().enumerate() {
        let sibling = parse_hash(sibling)?;
        hash = if bit(&kh, n - 1 - i) {
            internal_hash(&sibling, &hash)
        } else {
            internal_hash(&hash, &sibling)
        };
    }
    if &hash != root {
        return Err(ProofError::RootMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
