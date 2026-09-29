//! G1 S2: the V4 ingress predicate, IN-1 Layers S and E of
//! `docs/G1_CONSENSUS_CONTRACT.md`. Pure and unwired: S5 puts it on the path.
//!
//! Layer S is stateless given the record of the vertex's epoch, so every node
//! that knows the epoch reaches the same verdict, and only Layer S may say
//! INVALID. Layer E depends on this node's clock, floor and certificates; it
//! only delays (PENDING, DROP) or demotes (STALE). No rule concludes that a
//! digest does not exist.

use crate::dag::{MAX_PARENTS, MAX_VERTEX_BYTES};
use crate::qc::{self, ValidatorInfo};
use crate::vcert::{self, AttestBody, VertexCertificate};
use blockchain::{CompactCert, ParentRef, Vertex};

/// Payload back-pressure (PR-1): a vertex carrying transactions more than this
/// far above this node's cursor is dropped. A payload-free vertex is not
/// dropped for its round: a hard cap on rounds deadlocks for good once every
/// round up to it is proposed and no anchor in the window can gain votes (the
/// G1 math review, b.6). Past the lead it is staged only on parents already
/// certified; otherwise it is dropped and nothing is asked for.
pub const LEAD: u64 = 200;
/// A timestamp this far ahead of this node's clock is dropped, not refused.
pub const MAX_FUTURE_DRIFT_SECS: u64 = 30;
pub const ABSOLUTE_ROUND_CEILING: u64 = u64::MAX / 2;

/// What this node holds about one epoch.
pub struct EpochRecord<'a> {
    pub epoch: u64,
    pub first_round: u64,
    /// r*: the round of the anchor that closed the epoch, once known. Above it
    /// the epoch is over (EP-5).
    pub closing_round: Option<u64>,
    /// `blockchain::epoch_genesis` of this epoch.
    pub sentinel: &'a str,
    /// C_E, frozen for the epoch.
    pub committee: &'a [ValidatorInfo],
}

/// The node-local context of a verdict.
pub struct Context<'a> {
    pub chain_id: &'a str,
    pub genesis_identity: &'a str,
    pub active: EpochRecord<'a>,
    /// The epoch before the active one, when this node holds its record.
    pub previous: Option<EpochRecord<'a>>,
    /// The epoch after the active one, once its committee is recorded (with
    /// the boundary block) and before it is activated.
    pub next: Option<EpochRecord<'a>>,
    pub now_secs: u64,
    /// The GC floor g.
    pub gc_floor: u64,
    /// This node's round cursor.
    pub cursor: u64,
}

/// A verdict is about this copy of a vertex, never about its digest: a relay
/// can alter the unhashed transport fields of an honest vertex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Drop this copy. Never feeds a ban, a score or a slash.
    Invalid(String),
    /// Timing only: the vertex can be had again.
    Drop(String),
    /// Of the next epoch, authenticated, not active yet: keep and re-evaluate
    /// on activation.
    PendingEpoch,
    /// These parent refs (indices) have no verified certificate yet: keep,
    /// ask for them, re-evaluate when one arrives.
    PendingCert(Vec<usize>),
    /// Authenticated, of a closed epoch or below the floor: evidence only.
    Stale,
    Stage,
}

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The body as it is stored and served: a ref's certificate and any V3
/// identity proof stripped, so every copy of one vertex is one byte string.
pub(crate) fn canonical_body(v: &Vertex) -> Result<String, String> {
    let mut canonical = v.clone();
    for r in &mut canonical.parent_refs {
        r.cert = None;
        r.proof = None;
    }
    serde_json::to_string(&canonical).map_err(|e| e.to_string())
}

/// The parts of Layer S that need no epoch record. The size bound is on the
/// canonical body, not on the copy received, so boot, which re-runs Layer S
/// on the stored body, measures the same bytes ingress did.
fn intrinsic(v: &Vertex) -> Result<(), String> {
    if !v.is_live_form() {
        return Err("a compact proof, not a live vertex".into());
    }
    if v.aggregated_signature.is_some() {
        return Err("an aggregated signature on a live vertex".into());
    }
    if v.parents.len() > MAX_PARENTS {
        return Err(format!("{} parents, over {MAX_PARENTS}", v.parents.len()));
    }
    let mut seen = std::collections::HashSet::new();
    if !v.parents.iter().all(|p| seen.insert(p.as_str())) {
        return Err("a parent digest twice".into());
    }
    let bytes = canonical_body(v)?.len();
    if bytes > MAX_VERTEX_BYTES {
        return Err(format!("a {bytes}-byte body, over {MAX_VERTEX_BYTES}"));
    }
    Ok(())
}

/// Layer S under the record of the vertex's own epoch: every node holding
/// that record reaches the same verdict. Boot re-runs it on staged bodies, so
/// it carries every check but the wire size.
pub(crate) fn layer_s(
    v: &Vertex,
    record: &EpochRecord<'_>,
    chain_id: &str,
    genesis_identity: &str,
) -> Result<(), String> {
    intrinsic(v)?;
    if v.hash != v.hash_v4_with_domain(chain_id, genesis_identity) {
        return Err("the hash is not the V4 hash of the body".into());
    }
    let Some(author) = record
        .committee
        .iter()
        .find(|m| m.address == v.author && m.stake > 0)
    else {
        return Err(format!("author {} is not a staked member", v.author));
    };
    // Canonical hex only: `hex::decode` takes either case, which would let a
    // relay make byte-different valid copies of one vertex.
    if !lower_hex(&v.signature, 128) || !v.verify_ed25519_signature(&author.ed25519_public_key) {
        return Err("the author's signature does not verify".into());
    }
    if v.round < record.first_round || v.round > ABSOLUTE_ROUND_CEILING {
        return Err(format!(
            "round {} outside {}..={ABSOLUTE_ROUND_CEILING}",
            v.round, record.first_round
        ));
    }
    if v.round == record.first_round {
        if v.parents != [record.sentinel] || !v.parent_refs.is_empty() {
            return Err("a first-round vertex must cite the epoch sentinel only".into());
        }
        return Ok(());
    }
    // A ref no certificate could ever satisfy is refused here rather than
    // left to wait: its author is a staked member, its digest canonical.
    let n = record.committee.len();
    for r in &v.parent_refs {
        // Transport fields bound nothing: a V3 identity proof is no V4
        // evidence, and a certificate has one shape. Refusing a padded copy
        // costs nothing: verdicts are per copy (S2 review 2, MEDIUM-A).
        if r.proof.is_some() {
            return Err("a V3 parent identity proof on a V4 ref".into());
        }
        if r.cert.as_ref().is_some_and(|c| {
            c.signer_bitmap.len() != n.div_ceil(8) || c.aggregate_signature.len() != 96
        }) {
            return Err("a parent certificate of the wrong shape".into());
        }
        if !lower_hex(&r.digest, 64) {
            return Err(format!(
                "a parent digest that is not canonical hex: {}",
                r.digest
            ));
        }
        if !record
            .committee
            .iter()
            .any(|m| m.address == r.author && m.stake > 0)
        {
            return Err(format!("a parent by {}, not a staked member", r.author));
        }
    }
    let stakes: Vec<(String, u64)> = record
        .committee
        .iter()
        .map(|m| (m.address.clone(), m.stake))
        .collect();
    qc::parent_refs_admissible_above(v, &stakes, record.first_round)
}

/// The IN-1 verdict on this copy of `v`, whose serialized form was `raw_len`
/// bytes. `local_cert` returns this node's own copy of a parent's
/// certificate, if it holds one; an embedded copy is tried first.
pub fn v4_verdict(
    raw_len: usize,
    v: &Vertex,
    ctx: &Context<'_>,
    local_cert: impl Fn(&ParentRef) -> Option<CompactCert>,
) -> Verdict {
    let active = &ctx.active;
    // Layer S, the parts that need no epoch record.
    if raw_len > MAX_VERTEX_BYTES {
        return Verdict::Invalid(format!("{raw_len} bytes, over {MAX_VERTEX_BYTES}"));
    }
    if let Err(e) = intrinsic(v) {
        return Verdict::Invalid(e);
    }
    // E1 picks the record; Layer S runs under it before anything is kept.
    // A vertex whose epoch record this node does not hold cannot be
    // authenticated, so it is dropped (timing), never buffered.
    let record = if v.epoch == active.epoch {
        active
    } else if Some(v.epoch) == active.epoch.checked_add(1) {
        match &ctx.next {
            Some(next) if next.epoch == v.epoch => next,
            _ => return Verdict::Drop("the next epoch's committee is not known yet".into()),
        }
    } else if Some(v.epoch) == active.epoch.checked_sub(1) {
        match &ctx.previous {
            Some(previous) if previous.epoch == v.epoch => previous,
            _ => return Verdict::Drop("the previous epoch's record is not held".into()),
        }
    } else {
        return Verdict::Drop(format!(
            "epoch {} is not adjacent to the active one",
            v.epoch
        ));
    };
    if let Err(e) = layer_s(v, record, ctx.chain_id, ctx.genesis_identity) {
        return Verdict::Invalid(e);
    }
    if v.epoch > active.epoch {
        return Verdict::PendingEpoch;
    }
    if v.epoch < active.epoch || active.closing_round.is_some_and(|r| v.round > r) {
        return Verdict::Stale;
    }
    // Layer E.
    if v.timestamp > ctx.now_secs.saturating_add(MAX_FUTURE_DRIFT_SECS) {
        return Verdict::Drop("timestamp ahead of this node's clock".into());
    }
    if v.round <= ctx.gc_floor {
        return Verdict::Stale;
    }
    let beyond_lead = v.round > ctx.cursor.saturating_add(LEAD);
    if beyond_lead && !v.payload.is_empty() {
        return Verdict::Drop(format!(
            "payload at round {}, beyond the cursor's lead",
            v.round
        ));
    }
    if v.round == active.first_round {
        return Verdict::Stage;
    }
    let committee_hash = qc::validator_set_hash(active.committee);
    let n = active.committee.len();
    let certified = |r: &ParentRef, compact: &CompactCert| {
        // A certificate of the wrong shape is noise a relay added: ignored.
        if compact.signer_bitmap.len() != n.div_ceil(8) || compact.aggregate_signature.len() != 96 {
            return false;
        }
        let body = AttestBody {
            chain_id: ctx.chain_id.to_string(),
            genesis_identity: ctx.genesis_identity.to_string(),
            epoch: active.epoch,
            round: r.round,
            author: r.author.clone(),
            digest: r.digest.clone(),
            committee_hash: committee_hash.clone(),
        };
        let cert = VertexCertificate::from_compact(body, compact, active.committee);
        vcert::verify_vertex_cert(
            &cert,
            active.committee,
            ctx.chain_id,
            ctx.genesis_identity,
            active.epoch,
        )
        .is_ok()
    };
    let missing: Vec<usize> = v
        .parent_refs
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            // An embedded certificate is a transport field any relay can
            // corrupt: a bad one falls back to the local copy, and neither
            // being good only makes the vertex wait.
            !(r.cert.as_ref().is_some_and(|c| certified(r, c))
                || local_cert(r).is_some_and(|c| certified(r, &c)))
        })
        .map(|(i, _)| i)
        .collect();
    if missing.is_empty() {
        Verdict::Stage
    } else if beyond_lead {
        // Past the lead a vertex is staged only on parents already certified:
        // it never makes this node wait or ask for certificates that may not
        // exist.
        Verdict::Drop(format!(
            "round {} beyond the lead on uncertified parents",
            v.round
        ))
    } else {
        Verdict::PendingCert(missing)
    }
}

#[cfg(test)]
mod tests;
