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
/// far above this node's cursor is dropped. A payload-free vertex never is:
/// a hard cap on rounds deadlocks for good once every round up to it is
/// proposed and no anchor in the window can gain votes (the G1 math review,
/// b.6). Rounds keep advancing on empty vertices; only payload is bounded.
pub const LEAD: u64 = 200;
/// A timestamp this far ahead of this node's clock is dropped, not refused.
pub const MAX_FUTURE_DRIFT_SECS: u64 = 30;
pub const ABSOLUTE_ROUND_CEILING: u64 = u64::MAX / 2;

/// What this node holds about the active epoch.
pub struct EpochRecord<'a> {
    pub epoch: u64,
    pub first_round: u64,
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
    pub now_secs: u64,
    /// The GC floor g.
    pub gc_floor: u64,
    /// This node's round cursor.
    pub cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Drop this copy. Never feeds a ban, a score or a slash.
    Invalid(String),
    /// Timing only: the vertex can be had again.
    Drop(String),
    /// Of the next epoch, not active yet: keep and re-evaluate on activation.
    PendingEpoch,
    /// These parent refs (indices) have no verified certificate yet: keep,
    /// ask for them, re-evaluate when one arrives.
    PendingCert(Vec<usize>),
    /// Evidence only.
    Stale,
    Stage,
}

/// The IN-1 verdict on `vertex`, whose serialized form was `raw_len` bytes.
/// `local_cert` returns this node's own copy of a parent's certificate, if
/// it holds one; an embedded copy is tried first.
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
    if !v.is_live_form() {
        return Verdict::Invalid("a compact proof, not a live vertex".into());
    }
    if v.aggregated_signature.is_some() {
        return Verdict::Invalid("an aggregated signature on a live vertex".into());
    }
    if v.parents.len() > MAX_PARENTS {
        return Verdict::Invalid(format!("{} parents, over {MAX_PARENTS}", v.parents.len()));
    }
    let mut seen = std::collections::HashSet::new();
    if !v.parents.iter().all(|p| seen.insert(p.as_str())) {
        return Verdict::Invalid("a parent digest twice".into());
    }
    if v.hash != v.hash_v4_with_domain(ctx.chain_id, ctx.genesis_identity) {
        return Verdict::Invalid("the hash is not the V4 hash of the body".into());
    }
    // E1 before anything round-relative: another epoch's rounds mean nothing
    // against this one's record.
    if v.epoch < active.epoch {
        return Verdict::Stale;
    }
    if v.epoch == active.epoch + 1 {
        return Verdict::PendingEpoch;
    }
    if v.epoch > active.epoch + 1 {
        return Verdict::Drop(format!("epoch {} is ahead of the next", v.epoch));
    }
    // Layer S under the active epoch's record.
    let Some(author) = active
        .committee
        .iter()
        .find(|m| m.address == v.author && m.stake > 0)
    else {
        return Verdict::Invalid(format!("author {} is not a staked member", v.author));
    };
    if !v.verify_ed25519_signature(&author.ed25519_public_key) {
        return Verdict::Invalid("the author's signature does not verify".into());
    }
    if v.round < active.first_round || v.round > ABSOLUTE_ROUND_CEILING {
        return Verdict::Invalid(format!(
            "round {} outside {}..={ABSOLUTE_ROUND_CEILING}",
            v.round, active.first_round
        ));
    }
    if v.round == active.first_round {
        if v.parents != [active.sentinel] || !v.parent_refs.is_empty() {
            return Verdict::Invalid(
                "a first-round vertex must cite the epoch sentinel only".into(),
            );
        }
    } else {
        let stakes: Vec<(String, u64)> = active
            .committee
            .iter()
            .map(|m| (m.address.clone(), m.stake))
            .collect();
        if let Err(e) = qc::parent_refs_admissible_above(v, &stakes, active.first_round) {
            return Verdict::Invalid(e);
        }
    }
    // Layer E.
    if v.timestamp > ctx.now_secs.saturating_add(MAX_FUTURE_DRIFT_SECS) {
        return Verdict::Drop("timestamp ahead of this node's clock".into());
    }
    if v.round <= ctx.gc_floor {
        return Verdict::Stale;
    }
    if v.round > ctx.cursor.saturating_add(LEAD) && !v.payload.is_empty() {
        return Verdict::Drop(format!(
            "payload at round {}, beyond the cursor's lead",
            v.round
        ));
    }
    if v.round == active.first_round {
        return Verdict::Stage;
    }
    let committee_hash = qc::validator_set_hash(active.committee);
    let certified = |r: &ParentRef, compact: &CompactCert| {
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
    } else {
        Verdict::PendingCert(missing)
    }
}

#[cfg(test)]
mod tests;
