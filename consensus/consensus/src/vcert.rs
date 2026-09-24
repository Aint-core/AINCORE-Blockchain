//! G1 S1 — vertex certificates (Narwhal-style Byzantine Consistent Broadcast).
//!
//! LIBRARY ONLY. Nothing here is wired into ingress, production, ordering or
//! recovery; that is G1 S2 onward (`docs/G1_CONSENSUS_CONTRACT.md`, "Staged
//! implementation plan"). Adding this module changes no consensus decision,
//! which is why the release gate stays at 7 red / 7 green until activation.
//!
//! In contract terms it provides:
//! - the Types `AttestBody`, `VertexAttestation`, `VertexCertificate`,
//!   `CompactCert`;
//! - CE-2 `verify_vertex_cert`, which shares its stake and aggregate core with
//!   `qc::verify_qc` through `qc::verify_stake_aggregate`;
//! - AT-2 `attest_slot`, the durable one-signature-per-slot guard;
//! - CE-1 `CertCollector`, author-side collection and aggregation.
//!
//! The property all of it exists for (Lemma U): while Byzantine stake is below
//! T/3, at most one digest per slot (E, r, author) can ever be certified. Two
//! certificates need two quorums above 2T/3; any two such quorums share more
//! than T/3 of stake, which therefore contains an honest attester; and AT-2
//! stops an honest attester from signing two digests for one slot.

use crate::qc::{self, canonical_order, derive_validator_bls_seed, QcError, ValidatorInfo};
use crypto::bls::BLSEngine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use storage::{StateDB, StorageError};

/// 24 bytes: the same length as `AINCORE_FINALITY_VOTE_V1`, with different
/// content. Both kinds of signing bytes are `domain || BCS(body)`, so equal
/// length plus a differing prefix means the two can never be byte-equal.
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
    /// `qc::validator_set_hash(C_E)`.
    pub committee_hash: String,
}

impl AttestBody {
    /// `ATTEST_DOMAIN || BCS(self)`. BCS is canonical; never sign JSON.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = ATTEST_DOMAIN.to_vec();
        out.extend_from_slice(&bcs::to_bytes(self).expect("AttestBody is BCS-serializable"));
        out
    }

    /// The same slot, whatever the digest.
    pub fn same_slot(&self, other: &AttestBody) -> bool {
        self.chain_id == other.chain_id
            && self.genesis_identity == other.genesis_identity
            && self.epoch == other.epoch
            && self.round == other.round
            && self.author == other.author
            && self.committee_hash == other.committee_hash
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

/// The transport form carried in a child's `ParentRef`. The body and both
/// stakes are reconstructed from the child's epoch, the ref and C_E.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactCert {
    pub signer_bitmap: Vec<u8>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VcertError {
    UnsupportedVersion(u8),
    ChainMismatch {
        claimed: String,
        expected: String,
    },
    GenesisMismatch {
        claimed: String,
        expected: String,
    },
    EpochMismatch {
        claimed: u64,
        expected: u64,
    },
    /// A vertex author must be a committee member with positive stake (IN-1
    /// S4); a certificate or attestation for a slot that cannot exist is
    /// refused rather than processed.
    AuthorNotInCommittee(String),
    SignerNotInCommittee(String),
    /// AT-1: this node is not a committee member with positive stake.
    SelfNotInCommittee(String),
    /// AT-1: the derived BLS key is not the one the committee registered, so
    /// any signature produced could never verify.
    KeyMismatch {
        derived: String,
        registered: String,
    },
    CommitteeMismatch {
        claimed: String,
        recomputed: String,
    },
    BadSignature(String),
    /// The attestation is not for this collector's slot.
    WrongSlot,
    Aggregate(QcError),
    Storage(String),
}

impl std::fmt::Display for VcertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for VcertError {}

impl From<QcError> for VcertError {
    fn from(e: QcError) -> Self {
        VcertError::Aggregate(e)
    }
}

/// CE-2. Checks, in order: version; chain and genesis; epoch (C_E is the
/// committee of exactly one epoch); author membership; then the shared core —
/// bitmap non-empty and in range, stake recomputed from C_E, strict quorum,
/// `committee_hash` bound to C_E, and `fast_aggregate_verify`.
pub fn verify_vertex_cert(
    cert: &VertexCertificate,
    committee: &[ValidatorInfo],
    expected_chain_id: &str,
    expected_genesis_identity: &str,
    expected_epoch: u64,
) -> Result<(), VcertError> {
    if cert.version != CERT_VERSION {
        return Err(VcertError::UnsupportedVersion(cert.version));
    }
    let body = &cert.body;
    if body.chain_id != expected_chain_id {
        return Err(VcertError::ChainMismatch {
            claimed: body.chain_id.clone(),
            expected: expected_chain_id.to_string(),
        });
    }
    if body.genesis_identity != expected_genesis_identity {
        return Err(VcertError::GenesisMismatch {
            claimed: body.genesis_identity.clone(),
            expected: expected_genesis_identity.to_string(),
        });
    }
    if body.epoch != expected_epoch {
        return Err(VcertError::EpochMismatch {
            claimed: body.epoch,
            expected: expected_epoch,
        });
    }
    if !is_staked_member(committee, &body.author) {
        return Err(VcertError::AuthorNotInCommittee(body.author.clone()));
    }
    qc::verify_stake_aggregate(
        committee,
        &cert.signer_bitmap,
        cert.signed_stake,
        cert.total_stake,
        &body.committee_hash,
        &body.signing_bytes(),
        &cert.aggregate_signature,
    )?;
    Ok(())
}

/// `{cg}` in the contract's durable keys: `hex(SHA256(chain_id || 0x00 ||
/// genesis_identity))`. Scoping the guard to one chain and one genesis means a
/// key reused on another chain never finds, or is blocked by, this chain's rows.
pub fn chain_genesis_tag(chain_id: &str, genesis_identity: &str) -> String {
    let mut h = Sha256::new();
    h.update(chain_id.as_bytes());
    h.update([0u8]);
    h.update(genesis_identity.as_bytes());
    hex::encode(h.finalize())
}

/// `consensus:vattest:v1:{cg}:{bls_pk}:{E}:{author}:{r:020}`. Every field is
/// hex or decimal and the author is a committee address, so `:` never occurs
/// inside a field and the key is injective.
pub fn attest_guard_key(body: &AttestBody, bls_pk_hex: &str) -> String {
    format!(
        "consensus:vattest:v1:{}:{}:{}:{}:{:020}",
        chain_genesis_tag(&body.chain_id, &body.genesis_identity),
        bls_pk_hex,
        body.epoch,
        body.author,
        body.round
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestOutcome {
    /// A new signature. Its guard was durably committed before this returned.
    Signed(VertexAttestation),
    /// The guard already held this exact body; its persisted attestation is
    /// returned unchanged, so a retry is idempotent.
    Reused(VertexAttestation),
    /// The guard holds a DIFFERENT digest for this slot. Nothing was signed.
    /// The existing attestation is the contract's `conflict(G)` answer.
    Conflict(VertexAttestation),
}

impl AttestOutcome {
    pub fn attestation(&self) -> &VertexAttestation {
        match self {
            Self::Signed(a) | Self::Reused(a) | Self::Conflict(a) => a,
        }
    }
}

/// AT-2: sign at most one digest per slot, durably, and release a signature
/// only after its guard is committed.
///
/// Preconditions this library enforces (AT-1): `self_address` is a committee
/// member with positive stake, the author is a member, `body.committee_hash`
/// is this committee's hash, and the BLS key derived from `node_key` is the
/// one the committee registered. Preconditions the CALLER owns, because they
/// depend on node state this library does not see: E is the active epoch,
/// g < round <= cursor + LEAD, IN-1 passed including every parent certificate,
/// and guard continuity (RC-3).
///
/// The read, the decision and the write happen inside one `StateDB::transaction`,
/// which holds the single writer gate: two concurrent requests for one slot are
/// serialized, so exactly one of them can ever sign.
pub fn attest_slot(
    storage: &StateDB,
    body: &AttestBody,
    committee: &[ValidatorInfo],
    node_key: &[u8; 32],
    self_address: &str,
) -> Result<AttestOutcome, VcertError> {
    let ordered = canonical_order(committee);
    let me = ordered
        .iter()
        .find(|v| v.address == self_address && v.stake > 0)
        .ok_or_else(|| VcertError::SelfNotInCommittee(self_address.to_string()))?;
    if !is_staked_member(&ordered, &body.author) {
        return Err(VcertError::AuthorNotInCommittee(body.author.clone()));
    }
    let recomputed = qc::validator_set_hash(&ordered);
    if body.committee_hash != recomputed {
        return Err(VcertError::CommitteeMismatch {
            claimed: body.committee_hash.clone(),
            recomputed,
        });
    }
    let seed = derive_validator_bls_seed(node_key);
    let bls = BLSEngine::consensus();
    let public_key = bls.pubkey_raw(&seed);
    let pk_hex = hex::encode(&public_key);
    if pk_hex != me.bls_public_key {
        return Err(VcertError::KeyMismatch {
            derived: pk_hex,
            registered: me.bls_public_key.clone(),
        });
    }

    let key = attest_guard_key(body, &pk_hex);
    let bytes = body.signing_bytes();

    let outcome = storage
        .transaction(|view| {
            if let Some(raw) = view.get(&key)? {
                let prior: VertexAttestation = serde_json::from_str(&raw).map_err(|e| {
                    StorageError::DatabaseOperation(format!("vattest guard undecodable: {e}"))
                })?;
                // A persisted guard is trusted only if it is ours and verifies.
                // A guard that fails either check is refused, never overwritten:
                // overwriting would let corruption erase the evidence that this
                // key already signed something for the slot.
                let verifies = bls
                    .verify(&prior.body.signing_bytes(), &prior.signature, &public_key)
                    .unwrap_or(false);
                if prior.signer != self_address || !verifies {
                    return Err(StorageError::DatabaseOperation(
                        "vattest guard is not a valid attestation by this key".into(),
                    ));
                }
                return Ok(if prior.body == *body {
                    AttestOutcome::Reused(prior)
                } else {
                    AttestOutcome::Conflict(prior)
                });
            }
            let attestation = VertexAttestation {
                body: body.clone(),
                signer: self_address.to_string(),
                signature: bls.sign_raw(&bytes, &seed),
            };
            let encoded = serde_json::to_string(&attestation)
                .map_err(|e| StorageError::SerializationError(e.to_string()))?;
            view.put(&key, &encoded)?;
            // Signed and staged, NOT committed. A crash here must leave no guard
            // and must not have released the signature.
            #[cfg(test)]
            vcert_crash_boundary(0);
            Ok(AttestOutcome::Signed(attestation))
        })
        .map_err(|e| VcertError::Storage(e.to_string()))?;
    // Committed, not yet handed to the sender.
    #[cfg(test)]
    vcert_crash_boundary(1);
    Ok(outcome)
}

#[cfg(test)]
fn vcert_crash_boundary(boundary: u8) {
    if std::env::var("AINCORE_TEST_VCERT_BOUNDARY").ok().as_deref() == Some(&boundary.to_string()) {
        std::process::exit(77);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CollectOutcome {
    /// Recorded toward this body; quorum not reached yet.
    Pending { signed_stake: u128 },
    /// This signer's attestation for this body is already recorded.
    Duplicate,
    /// A verified attestation for a DIFFERENT digest of this slot. It never
    /// counts toward this certificate; it is kept as potential evidence.
    Foreign,
    /// This call reached quorum. The certificate has already passed
    /// `verify_vertex_cert`. Returned exactly once per collector.
    Certified(Box<VertexCertificate>),
    /// Recorded after the certificate formed; the certificate is unchanged.
    AfterCertified,
}

/// CE-1, the author side: verify each attestation against the signer's
/// registered BLS key, count only attestations of this exact body, and when the
/// signers reach quorum aggregate them in canonical order and run CE-2 on the
/// result before anyone else can see it.
pub struct CertCollector {
    body: AttestBody,
    committee: Vec<ValidatorInfo>,
    ours: BTreeMap<usize, Vec<u8>>,
    foreign: BTreeMap<usize, VertexAttestation>,
    evidence: Vec<(VertexAttestation, VertexAttestation)>,
    certificate: Option<VertexCertificate>,
}

impl CertCollector {
    pub fn new(body: AttestBody, committee: &[ValidatorInfo]) -> Result<Self, VcertError> {
        let committee = canonical_order(committee);
        let recomputed = qc::validator_set_hash(&committee);
        if body.committee_hash != recomputed {
            return Err(VcertError::CommitteeMismatch {
                claimed: body.committee_hash.clone(),
                recomputed,
            });
        }
        if !is_staked_member(&committee, &body.author) {
            return Err(VcertError::AuthorNotInCommittee(body.author.clone()));
        }
        Ok(Self {
            body,
            committee,
            ours: BTreeMap::new(),
            foreign: BTreeMap::new(),
            evidence: Vec::new(),
            certificate: None,
        })
    }

    pub fn certificate(&self) -> Option<&VertexCertificate> {
        self.certificate.as_ref()
    }

    /// Signers seen attesting two different digests for this slot, each pair
    /// fully verified: accountable evidence for `ATTEST_EQUIV`.
    pub fn equivocations(&self) -> &[(VertexAttestation, VertexAttestation)] {
        &self.evidence
    }

    pub fn add(&mut self, att: &VertexAttestation) -> Result<CollectOutcome, VcertError> {
        if !att.body.same_slot(&self.body) {
            return Err(VcertError::WrongSlot);
        }
        let idx = self
            .committee
            .iter()
            .position(|v| v.address == att.signer)
            .ok_or_else(|| VcertError::SignerNotInCommittee(att.signer.clone()))?;
        let pk = hex::decode(&self.committee[idx].bls_public_key)
            .map_err(|e| VcertError::BadSignature(format!("registered key undecodable: {e}")))?;
        let verifies = BLSEngine::consensus()
            .verify(&att.body.signing_bytes(), &att.signature, &pk)
            .unwrap_or(false);
        if !verifies {
            return Err(VcertError::BadSignature(att.signer.clone()));
        }

        if att.body.digest != self.body.digest {
            if let Some(sig) = self.ours.get(&idx) {
                self.note_equivocation(self.own_attestation(idx, sig), att.clone());
            }
            self.foreign.entry(idx).or_insert_with(|| att.clone());
            return Ok(CollectOutcome::Foreign);
        }

        if self.ours.contains_key(&idx) {
            return Ok(CollectOutcome::Duplicate);
        }
        if let Some(prior) = self.foreign.get(&idx).cloned() {
            self.note_equivocation(prior, att.clone());
        }
        // A signer that also attested a twin still counts here: certificates
        // count valid attestations, and Lemma U rests on honest attesters never
        // signing twice, not on excluding Byzantine ones.
        self.ours.insert(idx, att.signature.clone());
        if self.certificate.is_some() {
            return Ok(CollectOutcome::AfterCertified);
        }

        let signed_stake: u128 = self
            .ours
            .keys()
            .map(|&i| self.committee[i].stake as u128)
            .sum();
        let total_stake: u128 = self.committee.iter().map(|v| v.stake as u128).sum();
        if !qc::stake_quorum_met(signed_stake, total_stake) {
            return Ok(CollectOutcome::Pending { signed_stake });
        }

        // BTreeMap iterates in ascending index order: canonical order.
        let indices: Vec<usize> = self.ours.keys().copied().collect();
        let signatures: Vec<Vec<u8>> = self.ours.values().cloned().collect();
        let aggregate_signature = BLSEngine::consensus()
            .aggregate_signatures(&signatures)
            .map_err(|e| {
                VcertError::Aggregate(QcError::VerifyFailed(format!("aggregate: {e:?}")))
            })?;
        let cert = VertexCertificate {
            version: CERT_VERSION,
            body: self.body.clone(),
            signer_bitmap: qc::encode_bitmap(&indices, self.committee.len()),
            signed_stake,
            total_stake,
            aggregate_signature,
        };
        verify_vertex_cert(
            &cert,
            &self.committee,
            &self.body.chain_id,
            &self.body.genesis_identity,
            self.body.epoch,
        )?;
        self.certificate = Some(cert.clone());
        Ok(CollectOutcome::Certified(Box::new(cert)))
    }

    fn own_attestation(&self, idx: usize, signature: &[u8]) -> VertexAttestation {
        VertexAttestation {
            body: self.body.clone(),
            signer: self.committee[idx].address.clone(),
            signature: signature.to_vec(),
        }
    }

    /// One pair per signer. A pair is already complete evidence; recording every
    /// further digest a Byzantine signer chooses to sign for this slot would let
    /// it grow the collector without bound, one BLS signature per entry.
    fn note_equivocation(&mut self, first: VertexAttestation, second: VertexAttestation) {
        if !self.evidence.iter().any(|(a, _)| a.signer == first.signer) {
            self.evidence.push((first, second));
        }
    }
}

/// IN-1 S4's author rule, used by the verifier, the guard and the collector
/// alike so the three can never disagree about which slots exist.
fn is_staked_member(committee: &[ValidatorInfo], address: &str) -> bool {
    committee
        .iter()
        .any(|v| v.address == address && v.stake > 0)
}

fn bit_set(bitmap: &[u8], i: usize) -> bool {
    bitmap
        .get(i / 8)
        .is_some_and(|byte| byte & (1u8 << (i % 8)) != 0)
}

#[cfg(test)]
mod tests;
