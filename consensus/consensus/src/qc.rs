//! BLS Quorum Certificate (Phase 0 — types + verification, not yet wired into
//! consensus).
//!
//! A `QuorumCertificate` is a compact, portable cryptographic proof that
//! validators representing > 2/3 of active stake signed the same `FinalityVote`
//! over a committed anchor/checkpoint. This is the trust-minimized root that
//! enables light clients, bridge finality proofs, and trustless checkpoint
//! bootstrap — none of which are possible with the current single-node
//! Ed25519 checkpoint signature.
//!
//! See docs/BLS-QUORUM-CERT-SPEC-2026-06-10.md.
//!
//! Phase 0 scope: canonical types, deterministic encoding, stake-weighted
//! verification, and tests (including the rogue-key / PoP defense and the
//! single-validator 1-of-1 case). No node behavior change; nothing constructs a
//! QC in the live commit path yet.

use crypto::bls::BLSEngine;
use serde::{Deserialize, Serialize};

/// Domain tag mixed into every finality-vote message so a finality vote can
/// never collide with a DAG vertex signature (which uses the same consensus DST
/// at the BLS layer). Bump the suffix on any breaking change to the vote shape.
const FINALITY_VOTE_DOMAIN: &[u8] = b"AINCORE_FINALITY_VOTE_V1";

/// Per-validator finality identity. `bls_public_key` / `bls_pop` are hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: String,
    pub stake: u64,
    pub ed25519_public_key: String,
    pub bls_public_key: String,
    /// Proof-of-possession over `bls_public_key` (MANDATORY at registration).
    pub bls_pop: String,
}

/// The canonical message every validator signs for a finalized anchor. All
/// validators MUST sign byte-identical bytes for `fast_aggregate_verify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityVote {
    pub chain_id: String,
    pub epoch: u64,
    pub finalized_round: u64,
    pub anchor_round: u64,
    pub anchor_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    pub finality_digest: String,
    pub validator_set_hash: String,
}

impl FinalityVote {
    /// Deterministic signing bytes: domain tag || BCS(self). BCS is canonical
    /// (no map ordering ambiguity), and the domain prefix separates finality
    /// votes from vertex signatures. NEVER sign JSON.
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FINALITY_VOTE_DOMAIN.len() + 256);
        out.extend_from_slice(FINALITY_VOTE_DOMAIN);
        let body = bcs::to_bytes(self).expect("FinalityVote is BCS-serializable");
        out.extend_from_slice(&body);
        out
    }
}

/// A stake-weighted quorum certificate over a `FinalityVote`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    pub version: u8,
    pub chain_id: String,
    pub epoch: u64,
    pub finalized_round: u64,
    pub anchor_round: u64,
    pub anchor_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    pub finality_digest: String,
    pub validator_set_hash: String,
    /// Positional bitmap over validators in canonical (address-sorted) order.
    pub signer_bitmap: Vec<u8>,
    pub signed_stake: u128,
    pub total_stake: u128,
    /// Aggregated BLS signature (compressed bytes).
    pub aggregate_signature: Vec<u8>,
}

impl QuorumCertificate {
    /// Reconstruct the `FinalityVote` whose bytes this QC certifies.
    pub fn finality_vote(&self) -> FinalityVote {
        FinalityVote {
            chain_id: self.chain_id.clone(),
            epoch: self.epoch,
            finalized_round: self.finalized_round,
            anchor_round: self.anchor_round,
            anchor_hash: self.anchor_hash.clone(),
            block_height: self.block_height,
            block_hash: self.block_hash.clone(),
            state_root: self.state_root.clone(),
            receipts_root: self.receipts_root.clone(),
            finality_digest: self.finality_digest.clone(),
            validator_set_hash: self.validator_set_hash.clone(),
        }
    }
}

/// Precise rejection reasons (better than a bare bool for tests + diagnostics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QcError {
    SignerOutOfRange(usize),
    NoSigners,
    StakeMismatch { claimed: u128, recomputed: u128 },
    TotalStakeMismatch { claimed: u128, recomputed: u128 },
    BelowThreshold { signed: u128, total: u128 },
    BadBlsKey(String),
    VerifyFailed(String),
}

impl std::fmt::Display for QcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for QcError {}

/// Canonicalize a validator set into the deterministic order the signer bitmap
/// indexes against (sorted by address bytes). Returns a clone so callers cannot
/// accidentally pass an unsorted slice and corrupt bitmap indexing.
pub fn canonical_order(validators: &[ValidatorInfo]) -> Vec<ValidatorInfo> {
    let mut v = validators.to_vec();
    v.sort_by(|a, b| a.address.cmp(&b.address));
    v
}

/// Decode a positional bitmap into the set signer indices.
fn decode_bitmap(bitmap: &[u8], n: usize) -> Vec<usize> {
    let mut idx = Vec::new();
    for (byte_i, byte) in bitmap.iter().enumerate() {
        for bit in 0..8usize {
            if byte & (1u8 << bit) != 0 {
                let i = byte_i * 8 + bit;
                if i < n {
                    idx.push(i);
                }
            }
        }
    }
    idx
}

/// Encode signer indices into a positional bitmap.
pub fn encode_bitmap(indices: &[usize], n: usize) -> Vec<u8> {
    let mut bitmap = vec![0u8; n.div_ceil(8)];
    for &i in indices {
        if i < n {
            bitmap[i / 8] |= 1u8 << (i % 8);
        }
    }
    bitmap
}

/// Verify a quorum certificate against a trusted validator set.
///
/// `validators` is the trusted set for `qc.epoch` (any order — canonicalized
/// internally). Returns Ok(()) only if the aggregate BLS signature is valid over
/// the canonical finality-vote bytes for exactly the bitmap signers AND their
/// stake strictly exceeds 2/3 of the total.
pub fn verify_qc(qc: &QuorumCertificate, validators: &[ValidatorInfo]) -> Result<(), QcError> {
    let validators = canonical_order(validators);
    let n = validators.len();

    let signers = decode_bitmap(&qc.signer_bitmap, n);
    if signers.is_empty() {
        return Err(QcError::NoSigners);
    }
    // Any set bit beyond the validator count is a malformed/forged bitmap.
    let max_bit = qc.signer_bitmap.len() * 8;
    for bit in 0..max_bit {
        if qc.signer_bitmap[bit / 8] & (1u8 << (bit % 8)) != 0 && bit >= n {
            return Err(QcError::SignerOutOfRange(bit));
        }
    }

    // Recompute stake authoritatively from the trusted set; the QC's own stake
    // fields are only hints and must match.
    let signed_stake: u128 = signers.iter().map(|&i| validators[i].stake as u128).sum();
    let total_stake: u128 = validators.iter().map(|v| v.stake as u128).sum();

    if signed_stake != qc.signed_stake {
        return Err(QcError::StakeMismatch {
            claimed: qc.signed_stake,
            recomputed: signed_stake,
        });
    }
    if total_stake != qc.total_stake {
        return Err(QcError::TotalStakeMismatch {
            claimed: qc.total_stake,
            recomputed: total_stake,
        });
    }
    // Strict > 2/3, u128 (total_stake*2 cannot overflow realistic supplies).
    if signed_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
        return Err(QcError::BelowThreshold {
            signed: signed_stake,
            total: total_stake,
        });
    }

    // Collect signer BLS pubkeys.
    let mut pubkeys: Vec<Vec<u8>> = Vec::with_capacity(signers.len());
    for &i in &signers {
        let pk = hex::decode(&validators[i].bls_public_key)
            .map_err(|e| QcError::BadBlsKey(format!("validator {}: {}", i, e)))?;
        pubkeys.push(pk);
    }

    let vote_bytes = qc.finality_vote().to_signing_bytes();
    let bls = BLSEngine::consensus();
    match bls.fast_aggregate_verify(&vote_bytes, &pubkeys, &qc.aggregate_signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(QcError::VerifyFailed("aggregate signature invalid".into())),
        Err(e) => Err(QcError::VerifyFailed(format!("{:?}", e))),
    }
}

/// Aggregate per-signer signatures into a QC. Helper for tests and the future
/// commit-path wiring. `signer_indices` index into `canonical_order(validators)`.
pub fn build_qc(
    vote: &FinalityVote,
    validators: &[ValidatorInfo],
    signer_indices: &[usize],
    signatures: &[Vec<u8>],
) -> Result<QuorumCertificate, QcError> {
    let validators = canonical_order(validators);
    let n = validators.len();
    let bls = BLSEngine::consensus();
    let agg = bls
        .aggregate_signatures(signatures)
        .map_err(|e| QcError::VerifyFailed(format!("aggregate: {:?}", e)))?;
    let signed_stake: u128 = signer_indices
        .iter()
        .map(|&i| validators[i].stake as u128)
        .sum();
    let total_stake: u128 = validators.iter().map(|v| v.stake as u128).sum();
    Ok(QuorumCertificate {
        version: 1,
        chain_id: vote.chain_id.clone(),
        epoch: vote.epoch,
        finalized_round: vote.finalized_round,
        anchor_round: vote.anchor_round,
        anchor_hash: vote.anchor_hash.clone(),
        block_height: vote.block_height,
        block_hash: vote.block_hash.clone(),
        state_root: vote.state_root.clone(),
        receipts_root: vote.receipts_root.clone(),
        finality_digest: vote.finality_digest.clone(),
        validator_set_hash: vote.validator_set_hash.clone(),
        signer_bitmap: encode_bitmap(signer_indices, n),
        signed_stake,
        total_stake,
        aggregate_signature: agg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vote() -> FinalityVote {
        FinalityVote {
            chain_id: "AINCORE-MAINNET-1".into(),
            epoch: 1,
            finalized_round: 600,
            anchor_round: 598,
            anchor_hash: "aa".repeat(32),
            block_height: 600,
            block_hash: "bb".repeat(32),
            state_root: "cc".repeat(32),
            receipts_root: "dd".repeat(32),
            finality_digest: "ee".repeat(32),
            validator_set_hash: "ff".repeat(32),
        }
    }

    /// Build a validator with a real BLS key + PoP, deterministic from seed.
    /// Returns the raw 32-byte secret material (no blst types leak into consensus).
    fn make_validator(seed: u8, stake: u64) -> (ValidatorInfo, [u8; 32]) {
        let bls = BLSEngine::consensus();
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        ikm[31] = seed.wrapping_add(7);
        let pk = bls.pubkey_raw(&ikm);
        let pop = bls.prove_possession_raw(&ikm);
        let info = ValidatorInfo {
            address: format!("{:032x}", seed as u128),
            stake,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: hex::encode(&pk),
            bls_pop: hex::encode(&pop),
        };
        (info, ikm)
    }

    fn sign_vote(sk_bytes: &[u8; 32], vote: &FinalityVote) -> Vec<u8> {
        BLSEngine::consensus().sign_raw(&vote.to_signing_bytes(), sk_bytes)
    }

    #[test]
    fn pop_holds_for_generated_validators() {
        let bls = BLSEngine::consensus();
        let (v, _sk) = make_validator(1, 100);
        let pk = hex::decode(&v.bls_public_key).unwrap();
        let pop = hex::decode(&v.bls_pop).unwrap();
        assert!(bls.verify_possession(&pk, &pop).unwrap(), "PoP must verify");
    }

    #[test]
    fn single_validator_1_of_1_qc_verifies() {
        let vote = sample_vote();
        let (v, sk) = make_validator(1, 100);
        let validators = vec![v];
        let sig = sign_vote(&sk, &vote);
        let qc = build_qc(&vote, &validators, &[0], &[sig]).unwrap();
        // 100% stake signed -> valid 1-of-1 QC.
        assert!(verify_qc(&qc, &validators).is_ok(), "1-of-1 QC must verify");
    }

    #[test]
    fn multi_validator_supermajority_verifies_and_minority_fails() {
        let vote = sample_vote();
        // 4 validators, stakes 40/30/20/10 = 100 total. 2/3 threshold = >66.6.
        let mut set = vec![];
        let mut sks = vec![];
        for (seed, stake) in [(1u8, 40u64), (2, 30), (3, 20), (4, 10)] {
            let (v, sk) = make_validator(seed, stake);
            set.push(v);
            sks.push(sk);
        }
        let ord = canonical_order(&set);
        // Map a canonical-order validator -> its raw secret seed by matching pubkey.
        let sk_for = |info: &ValidatorInfo| -> [u8; 32] {
            let bls = BLSEngine::consensus();
            let want = hex::decode(&info.bls_public_key).unwrap();
            for sk in &sks {
                if bls.pubkey_raw(sk) == want {
                    return *sk;
                }
            }
            panic!("no secret for validator {}", info.address);
        };

        // Signers = the 40 + 30 + 20 = 90 stake holders (3 of 4) -> > 2/3.
        let signer_idx: Vec<usize> = ord
            .iter()
            .enumerate()
            .filter(|(_, v)| v.stake >= 20)
            .map(|(i, _)| i)
            .collect();
        let sigs: Vec<Vec<u8>> = signer_idx
            .iter()
            .map(|&i| sign_vote(&sk_for(&ord[i]), &vote))
            .collect();
        let qc = build_qc(&vote, &set, &signer_idx, &sigs).unwrap();
        assert!(verify_qc(&qc, &set).is_ok(), "90/100 stake QC must verify");

        // A single 40-stake validator alone is NOT > 2/3.
        let lone_idx: Vec<usize> = ord
            .iter()
            .enumerate()
            .filter(|(_, v)| v.stake == 40)
            .map(|(i, _)| i)
            .collect();
        let lone_sigs: Vec<Vec<u8>> = lone_idx
            .iter()
            .map(|&i| sign_vote(&sk_for(&ord[i]), &vote))
            .collect();
        let lone_qc = build_qc(&vote, &set, &lone_idx, &lone_sigs).unwrap();
        assert!(
            matches!(verify_qc(&lone_qc, &set), Err(QcError::BelowThreshold { .. })),
            "40/100 stake must be rejected below threshold"
        );
    }

    #[test]
    fn wrong_message_qc_fails() {
        let vote = sample_vote();
        let (v, sk) = make_validator(1, 100);
        let validators = vec![v];
        // Sign a DIFFERENT vote than the QC will claim.
        let mut other = vote.clone();
        other.state_root = "99".repeat(32);
        let sig = sign_vote(&sk, &other);
        let qc = build_qc(&vote, &validators, &[0], &[sig]).unwrap();
        assert!(
            matches!(verify_qc(&qc, &validators), Err(QcError::VerifyFailed(_))),
            "QC signed over a different message must fail BLS verify"
        );
    }

    #[test]
    fn forged_stake_field_rejected() {
        let vote = sample_vote();
        let (v, sk) = make_validator(1, 100);
        let validators = vec![v];
        let sig = sign_vote(&sk, &vote);
        let mut qc = build_qc(&vote, &validators, &[0], &[sig]).unwrap();
        // Inflate claimed signed_stake; verifier recomputes and must reject.
        qc.signed_stake = 999;
        assert!(
            matches!(verify_qc(&qc, &validators), Err(QcError::StakeMismatch { .. })),
            "forged signed_stake must be rejected"
        );
    }

    #[test]
    fn forged_bitmap_out_of_range_rejected() {
        let vote = sample_vote();
        let (v, sk) = make_validator(1, 100);
        let validators = vec![v];
        let sig = sign_vote(&sk, &vote);
        let mut qc = build_qc(&vote, &validators, &[0], &[sig]).unwrap();
        // Set a bit far beyond the single validator.
        qc.signer_bitmap = vec![0b0000_0101]; // bits 0 and 2; only index 0 exists
        assert!(
            matches!(verify_qc(&qc, &validators), Err(QcError::SignerOutOfRange(_))),
            "bitmap referencing a non-existent validator must be rejected"
        );
    }

    #[test]
    fn canonical_encoding_is_deterministic() {
        let v = sample_vote();
        assert_eq!(v.to_signing_bytes(), v.to_signing_bytes());
        // Domain prefix is present.
        assert!(v.to_signing_bytes().starts_with(FINALITY_VOTE_DOMAIN));
    }
}
