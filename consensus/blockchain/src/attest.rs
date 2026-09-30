//! G1 CE: what an attester signs and the vertex certificate, as plain data.
//!
//! They live here, not in `consensus::vcert` (which re-exports them), so the
//! executor can check certificate-conflict evidence (G5 SL-3) without
//! depending on consensus.

use crate::committee::{canonical_order, ValidatorInfo};
use crate::CompactCert;
use serde::{Deserialize, Serialize};

/// The attestation signing domain. Both kinds of signing bytes are
/// `domain || BCS(body)`, so equal length plus a differing prefix means the
/// two can never be byte-equal.
pub const ATTEST_DOMAIN: &[u8] = b"AINCORE_VERTEX_ATTEST_V1";
pub const CERT_VERSION: u8 = 1;

/// What an attester signs: one slot (epoch, round, author) and one digest,
/// bound to a chain, a genesis and the exact committee that counts the stake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestBody {
    pub chain_id: String,
    pub genesis_identity: String,
    pub epoch: u64,
    pub round: u64,
    pub author: String,
    pub digest: String,
    /// `validator_set_hash(C_E)`.
    pub committee_hash: String,
}

impl AttestBody {
    /// `ATTEST_DOMAIN || BCS(self)`. BCS is canonical; never sign JSON.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = ATTEST_DOMAIN.to_vec();
        out.extend_from_slice(&bcs::to_bytes(self).expect("AttestBody is BCS-serializable"));
        out
    }

    /// The same slot — (chain, genesis, epoch, round, author) — whatever the
    /// digest and whatever the committee hash. This is what a guard key and an
    /// equivocation are both about: a signer that attests two digests for one
    /// slot has equivocated even if it claimed a different committee each time.
    pub fn same_slot(&self, other: &AttestBody) -> bool {
        self.chain_id == other.chain_id
            && self.genesis_identity == other.genesis_identity
            && self.epoch == other.epoch
            && self.round == other.round
            && self.author == other.author
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VertexAttestation {
    pub body: AttestBody,
    pub signer: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VertexCertificate {
    pub version: u8,
    pub body: AttestBody,
    /// Positional bitmap over `canonical_order(C_E)`.
    pub signer_bitmap: Vec<u8>,
    pub signed_stake: u128,
    pub total_stake: u128,
    pub aggregate_signature: Vec<u8>,
}

impl VertexCertificate {
    pub fn compact(&self) -> CompactCert {
        CompactCert {
            signer_bitmap: self.signer_bitmap.clone(),
            aggregate_signature: self.aggregate_signature.clone(),
        }
    }

    /// Rebuild a full certificate from its compact form. The stakes are DERIVED
    /// from `committee` here, never taken on trust; `verify_vertex_cert` then
    /// decides whether the result is a certificate at all.
    pub fn from_compact(
        body: AttestBody,
        compact: &CompactCert,
        committee: &[ValidatorInfo],
    ) -> Self {
        let ordered = canonical_order(committee);
        let signed_stake = ordered
            .iter()
            .enumerate()
            .filter(|(i, _)| bit_set(&compact.signer_bitmap, *i))
            .map(|(_, v)| v.stake as u128)
            .sum();
        let total_stake = ordered.iter().map(|v| v.stake as u128).sum();
        Self {
            version: CERT_VERSION,
            body,
            signer_bitmap: compact.signer_bitmap.clone(),
            signed_stake,
            total_stake,
            aggregate_signature: compact.aggregate_signature.clone(),
        }
    }
}

/// Whether bit `i` of a positional bitmap is set.
pub fn bit_set(bitmap: &[u8], i: usize) -> bool {
    bitmap
        .get(i / 8)
        .is_some_and(|byte| byte & (1u8 << (i % 8)) != 0)
}
