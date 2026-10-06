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
    /// Of the next epoch while this node does not hold its record, signed by
    /// a member of the active committee: dropped, but proof that the network
    /// passed a boundary this node has not reached (it fetches the gap).
    Ahead,
    /// Authenticated, but timestamped more than `MAX_FUTURE_DRIFT_SECS`
    /// ahead of this node's clock: dropped (it can be had again). A sample
    /// for the BT-1 drift alarm: when members holding a stake quorum are all
    /// ahead, this node's clock is behind.
    Early,
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
/// The hash is the V4 hash of the body and a staked member of `record`
/// signed it (no other Layer S check: the vertex is of another epoch).
fn signed_by_member(
    v: &Vertex,
    record: &EpochRecord<'_>,
    chain_id: &str,
    genesis_identity: &str,
) -> bool {
    v.hash == v.hash_v4_with_domain(chain_id, genesis_identity)
        && lower_hex(&v.signature, 128)
        && record
            .committee
            .iter()
            .find(|m| m.address == v.author && m.stake > 0)
            .is_some_and(|m| v.verify_ed25519_signature(&m.ed25519_public_key))
}

/// B12: every payload item is either equivocation evidence or a well-formed
/// transaction for this chain, signed by its sender: the predicate the
/// mempool admits by and the executor runs first
/// (`executor::admission::check_stateless`). It needs only the item and the
/// chain id, so every node reaches the same verdict. A payload item used to
/// be accepted unread, so a member could fill each vertex with 768 KiB of
/// anything and every block body would carry it for good.
fn payload_admissible(v: &Vertex, chain_id: &str) -> Result<(), String> {
    // B95: an item twice is refused before any signature is checked (one
    // signed transaction repeated ~1,200 times filled a vertex with checks).
    let mut seen = std::collections::HashSet::with_capacity(v.payload.len());
    for (i, item) in v.payload.iter().enumerate() {
        if !seen.insert(item.as_str()) {
            return Err(format!("payload item {i} repeats an earlier one"));
        }
    }
    for (i, item) in v.payload.iter().enumerate() {
        match item.strip_prefix(crate::dag::SLASH_EVIDENCE_PREFIX) {
            Some(evidence) => {
                if !crate::DagConsensus::is_equivocation_item(evidence) {
                    return Err(format!("payload item {i} is evidence of no ordered kind"));
                }
            }
            None => {
                let checked = executor::admission::check_stateless(item, chain_id)
                    .map_err(|e| format!("payload item {i} is not a valid transaction: {e}"))?;
                // B73: in its one encoding, so no relay changed its bytes
                // (its id, its byte gas).
                if executor::admission::canonical_json(&checked.tx) != *item {
                    return Err(format!("payload item {i} is not in canonical form"));
                }
            }
        }
    }
    Ok(())
}

/// Layer S whole: what the boot re-check of staged bodies runs.
pub(crate) fn layer_s(
    v: &Vertex,
    record: &EpochRecord<'_>,
    chain_id: &str,
    genesis_identity: &str,
) -> Result<(), String> {
    layer_s_head(v, record, chain_id, genesis_identity)?;
    payload_admissible(v, chain_id)
}

/// Layer S without the payload: the hash, the author's signature, the
/// round and the refs. B95: the payload's checks (a signature or two an
/// item) run in `v4_verdict_gated` after Layer E's cheap filters.
fn layer_s_head(
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
    v4_verdict_cached(raw_len, v, ctx, local_cert, |_| false)
}

/// `v4_verdict` with E4's cache (IN-1: "results are cached"): `verified(r)`
/// says this node already holds a verified certificate for exactly `r`'s
/// (round, author, digest), so no signature is checked again for it.
pub fn v4_verdict_cached(
    raw_len: usize,
    v: &Vertex,
    ctx: &Context<'_>,
    local_cert: impl Fn(&ParentRef) -> Option<CompactCert>,
    verified: impl Fn(&ParentRef) -> bool,
) -> Verdict {
    v4_verdict_gated(raw_len, v, ctx, local_cert, verified, |_| {
        PayloadGate::Check
    })
}

/// B95: what the node does with a vertex's payload once the cheap checks
/// passed (the engine's per-slot memory, `Engine::payload_gate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadGate {
    /// Checked when this body was seen before: not again.
    Verified,
    /// Check it.
    Check,
    /// Two other bodies of this (epoch, round, author) took the check
    /// already: the author equivocated, and a third is not checked.
    Full,
}

#[cfg(test)]
thread_local! {
    /// B95 witness support: the payload checks `payload_step` ran on this
    /// thread.
    pub(crate) static PAYLOAD_CHECKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The payload step: `None` to go on.
fn payload_step(
    v: &Vertex,
    chain_id: &str,
    gate: impl FnOnce(&Vertex) -> PayloadGate,
) -> Option<Verdict> {
    match gate(v) {
        PayloadGate::Verified => None,
        PayloadGate::Full => Some(Verdict::Drop(format!(
            "round {} of {} holds two other bodies already",
            v.round, v.author
        ))),
        PayloadGate::Check => {
            #[cfg(test)]
            PAYLOAD_CHECKS.with(|n| n.set(n.get() + 1));
            payload_admissible(v, chain_id).err().map(Verdict::Invalid)
        }
    }
}

/// `v4_verdict_cached` with B95's order: Layer S without the payload, the
/// epoch and Layer E's cheap filters, and only then the payload's checks,
/// through `gate`. A vertex those filters drop or refuse as stale is not
/// staged anyway; a later copy within the window gets the payload verdict.
pub fn v4_verdict_gated(
    raw_len: usize,
    v: &Vertex,
    ctx: &Context<'_>,
    local_cert: impl Fn(&ParentRef) -> Option<CompactCert>,
    verified: impl Fn(&ParentRef) -> bool,
    gate: impl FnOnce(&Vertex) -> PayloadGate,
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
            _ if signed_by_member(v, active, ctx.chain_id, ctx.genesis_identity) => {
                return Verdict::Ahead
            }
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
    if let Err(e) = layer_s_head(v, record, ctx.chain_id, ctx.genesis_identity) {
        return Verdict::Invalid(e);
    }
    if v.epoch > active.epoch {
        // Buffered for activation: its payload is checked before it is kept.
        return payload_step(v, ctx.chain_id, gate).unwrap_or(Verdict::PendingEpoch);
    }
    if v.epoch < active.epoch || active.closing_round.is_some_and(|r| v.round > r) {
        return Verdict::Stale;
    }
    // Layer E.
    if v.timestamp > ctx.now_secs.saturating_add(MAX_FUTURE_DRIFT_SECS) {
        return Verdict::Early;
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
    // B95: the payload's signatures only now, past the cheap filters.
    if let Some(verdict) = payload_step(v, ctx.chain_id, gate) {
        return verdict;
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
            !(verified(r)
                || r.cert.as_ref().is_some_and(|c| certified(r, c))
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
