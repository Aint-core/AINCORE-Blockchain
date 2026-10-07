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
    /// The epoch after the active one, once its committee is recorded (with
    /// the boundary block) and before it is activated.
    pub next: Option<EpochRecord<'a>>,
    /// B171: the round up to which this node already wants the gap an
    /// `Ahead` vertex shows (`u64::MAX`: as far as it ever would). A
    /// next-epoch vertex at a round no higher than one past it shows nothing
    /// new, so it is dropped before it is authenticated.
    pub gap_wanted_to: u64,
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
    /// Of the closed epoch before the active one, or of the active one at or
    /// below the floor or above its closing round: dropped, told before
    /// Layer S whoever signed (B158, B171: nothing reads it, and each copy
    /// cost a hash over the body and a signature check, uncounted).
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
/// B171: its failures are charged as Layer S's are (B158): no honest node
/// sends a body whose hash fails, nor one a member of `record` signed with
/// another key (a member's key derives its address, so it is the same in
/// every epoch). An author of the next committee only is not charged: it
/// cannot be checked here.
fn signed_by_member(
    v: &Vertex,
    record: &EpochRecord<'_>,
    chain_id: &str,
    genesis_identity: &str,
) -> bool {
    #[cfg(test)]
    SIGNED_BY_MEMBER_RUNS.with(|n| n.set(n.get() + 1));
    // B181: the author before any pass over the body.
    let Some(author) = record
        .committee
        .iter()
        .find(|m| m.address == v.author && m.stake > 0)
    else {
        return false;
    };
    if !lower_hex(&v.signature, 128) || intrinsic(v).is_err() {
        crate::work::note_failed_check();
        return false;
    }
    if v.hash != v.hash_v4_with_domain(chain_id, genesis_identity) {
        crate::work::note_failed_check();
        return false;
    }
    if !v.verify_ed25519_signature(&author.ed25519_public_key) {
        crate::work::note_failed_check();
        return false;
    }
    true
}

/// B12: every payload item is either equivocation evidence or a well-formed
/// transaction for this chain, signed by its sender: the predicate the
/// mempool admits by and the executor runs first
/// (`executor::admission::check_stateless`). It needs only the item and the
/// chain id, so every node reaches the same verdict. A payload item used to
/// be accepted unread, so a member could fill each vertex with 768 KiB of
/// anything and every block body would carry it for good.
fn payload_admissible(v: &Vertex, chain_id: &str, genesis_identity: &str) -> Result<(), String> {
    // B95: an item twice is refused before any signature is checked (one
    // signed transaction repeated ~1,200 times filled a vertex with checks).
    let mut seen = std::collections::HashSet::with_capacity(v.payload.len());
    for (i, item) in v.payload.iter().enumerate() {
        if !seen.insert(item.as_str()) {
            return Err(format!("payload item {i} repeats an earlier one"));
        }
    }
    let mut evidence_items = 0usize;
    for (i, item) in v.payload.iter().enumerate() {
        match item.strip_prefix(crate::dag::SLASH_EVIDENCE_PREFIX) {
            Some(evidence) => {
                // B192: no more than a block takes from one vertex (what an
                // honest carrier puts in), each in the one form an honest
                // node builds, and bounded.
                evidence_items += 1;
                if evidence_items > crate::dag::MAX_EVIDENCE_PER_VERTEX {
                    return Err(format!(
                        "payload item {i} is evidence past {}",
                        crate::dag::MAX_EVIDENCE_PER_VERTEX
                    ));
                }
                crate::v4::evidence::admissible_item(evidence, chain_id, genesis_identity)
                    .map_err(|e| format!("payload item {i} is not admissible evidence: {e}"))?;
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
    payload_admissible(v, chain_id, genesis_identity)
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
    transport_shape(v, record)?;
    layer_s_auth(v, record, chain_id, genesis_identity)?;
    layer_s_shape(v, record)
}

/// B224: the refs' transport fields, before the author's signature: a V3
/// identity proof is no V4 evidence, and a certificate has one shape. No
/// honest V4 node adds either (authors send their own bodies, pull serves
/// staged ones, and a certificate it embeds is one of this committee's),
/// so the engine charges a refusal; refused after authentication, each copy
/// ran the hash and the signature first, uncharged and unremembered.
/// Verdicts stay per copy: a padded copy of an honest body costs its
/// author nothing (S2 review 2, MEDIUM-A).
fn transport_shape(v: &Vertex, record: &EpochRecord<'_>) -> Result<(), String> {
    let n = record.committee.len();
    for r in &v.parent_refs {
        if r.proof.is_some() {
            return Err("a V3 parent identity proof on a V4 ref".into());
        }
        if r.cert.as_ref().is_some_and(|c| {
            c.signer_bitmap.len() != n.div_ceil(8) || c.aggregate_signature.len() != 96
        }) {
            return Err("a parent certificate of the wrong shape".into());
        }
    }
    Ok(())
}

/// Layer S up to the author's signature: the author, the signature's form,
/// the round, the intrinsic form, the hash, the signature.
fn layer_s_auth(
    v: &Vertex,
    record: &EpochRecord<'_>,
    chain_id: &str,
    genesis_identity: &str,
) -> Result<(), String> {
    #[cfg(test)]
    LAYER_S_RUNS.with(|n| n.set(n.get() + 1));
    // B181: what needs no pass over the body first: the author, the
    // signature's form and the round. A body naming no staked member was
    // hashed and serialized before it was refused, uncharged, every copy.
    // Charged (B51): no honest node sends one (authors send their own, pull
    // serves staged bodies, and every node holds the same record).
    let Some(author) = record
        .committee
        .iter()
        .find(|m| m.address == v.author && m.stake > 0)
    else {
        crate::work::note_failed_check();
        return Err(format!("author {} is not a staked member", v.author));
    };
    // Canonical hex only: `hex::decode` takes either case, which would let a
    // relay make byte-different valid copies of one vertex.
    if !lower_hex(&v.signature, 128) {
        crate::work::note_failed_check();
        return Err("the author's signature does not verify".into());
    }
    if v.round < record.first_round || v.round > ABSOLUTE_ROUND_CEILING {
        return Err(format!(
            "round {} outside {}..={ABSOLUTE_ROUND_CEILING}",
            v.round, record.first_round
        ));
    }
    // B208: charged, as `signed_by_member` charges it: no honest author
    // sends a body over the bound or of the wrong form, and each copy cost a
    // clone and a serialization of up to 768 KiB.
    if let Err(e) = intrinsic(v) {
        crate::work::note_failed_check();
        return Err(e);
    }
    if v.hash != v.hash_v4_with_domain(chain_id, genesis_identity) {
        // B158: a failed costly check (B51). No honest node sends a body
        // whose hash or signature fails: authors send their own, pull
        // serves staged ones, and neither covers a transport field.
        crate::work::note_failed_check();
        return Err("the hash is not the V4 hash of the body".into());
    }
    if !v.verify_ed25519_signature(&author.ed25519_public_key) {
        crate::work::note_failed_check();
        return Err("the author's signature does not verify".into());
    }
    Ok(())
}

/// Layer S past the author's signature: the parents. Every field it refuses
/// is one its author signed (B204: no relay added it, so the digest is
/// refused for good); the transport fields a relay can add to an honest body
/// are `transport_shape`'s, before the signature (B224).
fn layer_s_shape(v: &Vertex, record: &EpochRecord<'_>) -> Result<(), String> {
    if v.round == record.first_round {
        if v.parents != [record.sentinel] || !v.parent_refs.is_empty() {
            return Err("a first-round vertex must cite the epoch sentinel only".into());
        }
        return Ok(());
    }
    // A ref no certificate could ever satisfy is refused here rather than
    // left to wait: its author is a staked member, its digest canonical.
    for r in &v.parent_refs {
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
    /// B117: refused when this body was seen before: refused again, unchecked.
    Refused,
    /// Check it.
    Check,
    /// Two other bodies of this (epoch, round, author) took the check
    /// already: the author equivocated, and a third is not checked.
    Full,
    /// B137: the author's vertices of the next epoch took as many checks
    /// before its activation as the buffer keeps of one author.
    Spent,
}

/// B117: a payload check that ran, and its outcome, so the engine remembers
/// the body either way (a refused body was checked again on every copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadChecked {
    Passed,
    Refused,
}

#[cfg(test)]
thread_local! {
    /// B95 witness support: the payload checks `payload_step` ran on this
    /// thread.
    pub(crate) static PAYLOAD_CHECKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// B148 witness support: the Layer S head checks run on this thread.
    pub(crate) static LAYER_S_RUNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// B171 witness support: the next-epoch authentications
    /// (`signed_by_member`) run on this thread.
    pub(crate) static SIGNED_BY_MEMBER_RUNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// What a verdict did besides deciding, for the engine: it remembers a
/// payload check's outcome, charges a refusal, and ingests the certificates
/// E4 verified.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Ran {
    /// The payload check that ran, and its outcome.
    pub payload: Option<PayloadChecked>,
    /// B136: the parent refs (indices) whose embedded certificate E4
    /// verified.
    pub certified: Vec<usize>,
    /// B204: refused, past its author's signature, for a field it signed.
    pub signed_refusal: bool,
    /// B224: the author's signature over this digest verified (Layer S
    /// authenticated it), whatever the verdict.
    pub authenticated: bool,
}

/// B136: what the node remembers of the payload, before anything is
/// checked: `None` to go on.
fn remembered(v: &Vertex, memo: PayloadGate) -> Option<Verdict> {
    match memo {
        PayloadGate::Verified | PayloadGate::Check => None,
        PayloadGate::Refused => Some(Verdict::Invalid(
            "its payload was refused before".to_string(),
        )),
        PayloadGate::Full => Some(Verdict::Drop(format!(
            "round {} of {} holds two other bodies already",
            v.round, v.author
        ))),
        PayloadGate::Spent => Some(Verdict::Drop(format!(
            "{}'s next-epoch checks are spent until it activates",
            v.author
        ))),
    }
}

/// The payload's check, when the memo asks for one: `None` to go on.
fn check(v: &Vertex, ctx: &Context<'_>, memo: PayloadGate, ran: &mut Ran) -> Option<Verdict> {
    if memo != PayloadGate::Check {
        return None;
    }
    #[cfg(test)]
    PAYLOAD_CHECKS.with(|n| n.set(n.get() + 1));
    let refused = payload_admissible(v, ctx.chain_id, ctx.genesis_identity).err();
    ran.payload = Some(if refused.is_some() {
        PayloadChecked::Refused
    } else {
        PayloadChecked::Passed
    });
    refused.map(Verdict::Invalid)
}

/// The payload step where no certificate is checked first: the memo, then
/// the check.
fn payload_step(
    v: &Vertex,
    ctx: &Context<'_>,
    memo: PayloadGate,
    ran: &mut Ran,
) -> Option<Verdict> {
    remembered(v, memo).or_else(|| check(v, ctx, memo, ran))
}

/// `v4_verdict_checked` without the check's outcome.
pub fn v4_verdict_gated(
    raw_len: usize,
    v: &Vertex,
    ctx: &Context<'_>,
    local_cert: impl Fn(&ParentRef) -> Option<CompactCert>,
    verified: impl Fn(&ParentRef) -> bool,
    gate: impl FnOnce(&Vertex) -> PayloadGate,
) -> Verdict {
    v4_verdict_checked(raw_len, v, ctx, local_cert, verified, gate).0
}

/// `v4_verdict_cached` with B95's order: Layer S without the payload, the
/// epoch and Layer E's cheap filters, what this node remembers of the
/// payload (B136: a body refused before is refused again, and a full slot's
/// third body dropped, before any certificate is checked), the parents'
/// certificates, and only then the payload's check, through `gate`. B117:
/// only a vertex that stages (or is buffered for the next epoch) has its
/// payload checked: one waiting on parent certificates is checked when it
/// wakes, so a vertex on invented parents never costs a check. Returns the
/// verdict and what it ran (`Ran`).
pub fn v4_verdict_checked(
    raw_len: usize,
    v: &Vertex,
    ctx: &Context<'_>,
    local_cert: impl Fn(&ParentRef) -> Option<CompactCert>,
    verified: impl Fn(&ParentRef) -> bool,
    gate: impl FnOnce(&Vertex) -> PayloadGate,
) -> (Verdict, Ran) {
    let mut ran = Ran::default();
    let verdict = v4_verdict_inner(raw_len, v, ctx, local_cert, verified, gate, &mut ran);
    (verdict, ran)
}

fn v4_verdict_inner(
    raw_len: usize,
    v: &Vertex,
    ctx: &Context<'_>,
    local_cert: impl Fn(&ParentRef) -> Option<CompactCert>,
    verified: impl Fn(&ParentRef) -> bool,
    gate: impl FnOnce(&Vertex) -> PayloadGate,
    ran: &mut Ran,
) -> Verdict {
    let active = &ctx.active;
    // Layer S, the parts that need no epoch record.
    if raw_len > MAX_VERTEX_BYTES {
        return Verdict::Invalid(format!("{raw_len} bytes, over {MAX_VERTEX_BYTES}"));
    }
    // B181: the rest of the record-free part (`intrinsic`, a serialization
    // of the body) runs in Layer S, after the cheap filters and the author.
    // E1 picks the record; Layer S runs under it before anything is kept.
    // A vertex whose epoch record this node does not hold cannot be
    // authenticated, so it is dropped (timing), never buffered.
    let record = if v.epoch == active.epoch {
        active
    } else if Some(v.epoch) == active.epoch.checked_add(1) {
        match &ctx.next {
            Some(next) if next.epoch == v.epoch => next,
            // B171: Ahead only wants the gap below it; a copy that shows no
            // more than is wanted already is not authenticated (each cost a
            // hash over the body and a signature check, uncounted).
            _ if v.round.saturating_sub(1) <= ctx.gap_wanted_to => {
                return Verdict::Drop("the gap below it is wanted already".into())
            }
            _ if signed_by_member(v, active, ctx.chain_id, ctx.genesis_identity) => {
                return Verdict::Ahead
            }
            _ => return Verdict::Drop("the next epoch's committee is not known yet".into()),
        }
    } else if Some(v.epoch) == active.epoch.checked_sub(1) {
        // B171: the closed epoch's, dropped before Layer S whoever signed
        // it: nothing reads its verdict, and its record is held for the
        // whole of the active epoch, so each copy (a replayed one, or one a
        // member of that committee signed anew at any round) cost a hash
        // over the body and a signature check, uncounted.
        return Verdict::Stale;
    } else {
        return Verdict::Drop(format!(
            "epoch {} is not adjacent to the active one",
            v.epoch
        ));
    };
    // B249: a round outside the record's range is refused first, as Layer
    // S refuses it, whatever the context: the lead filters below (B158,
    // B229) dropped such a body in some contexts, so a verdict every node
    // gives (`Invalid`) became a context's (`Drop`).
    if v.round < record.first_round || v.round > ABSOLUTE_ROUND_CEILING {
        return Verdict::Invalid(format!(
            "round {} outside {}..={ABSOLUTE_ROUND_CEILING}",
            v.round, record.first_round
        ));
    }
    // B158: the filters that need no authentication run before Layer S:
    // their outcome is the same whoever signed, and each copy they dropped
    // cost a hash over the body and a signature check, uncounted. (Early
    // waits for Layer S: its samples feed BT-1, which a forger must not.)
    let beyond_lead = v.round > ctx.cursor.saturating_add(LEAD);
    if v.epoch == active.epoch {
        if active.closing_round.is_some_and(|r| v.round > r) || v.round <= ctx.gc_floor {
            return Verdict::Stale;
        }
        if beyond_lead && !v.payload.is_empty() {
            return Verdict::Drop(format!(
                "payload at round {}, beyond the cursor's lead",
                v.round
            ));
        }
        // B229: past the lead a body stages only on parents certified here or
        // in the copy (E4 drops it otherwise): one citing a parent neither
        // certifies is dropped before its signature is checked. Each body on
        // invented parents past the lead, one a fresh slot, cost every node
        // the hash and the signature, uncharged and without end (B224
        // counts a slot's digests; each was a new slot).
        if beyond_lead
            && v.parent_refs
                .iter()
                .any(|r| r.cert.is_none() && !verified(r) && local_cert(r).is_none())
        {
            return Verdict::Drop(format!(
                "round {} beyond the lead on a parent not certified here",
                v.round
            ));
        }
    } else if v.epoch > active.epoch && v.round > record.first_round.saturating_add(LEAD) {
        // B117/B118: buffered for activation only within the next epoch's
        // lead (its parents' existence is not checked here, so an E+1
        // vertex at any round would otherwise be kept).
        return Verdict::Drop(format!("round {} beyond the next epoch's lead", v.round));
    }
    if let Err(e) = transport_shape(v, record) {
        crate::work::note_failed_check();
        return Verdict::Invalid(e);
    }
    if let Err(e) = layer_s_auth(v, record, ctx.chain_id, ctx.genesis_identity) {
        return Verdict::Invalid(e);
    }
    ran.authenticated = true;
    if let Err(e) = layer_s_shape(v, record) {
        // B204: refused for what its author signed: charged (no honest
        // author signs one), and the engine refuses its copies before Layer
        // S (each ran the hash and the signature again, uncharged).
        crate::work::note_failed_check();
        ran.signed_refusal = true;
        return Verdict::Invalid(e);
    }
    if v.epoch > active.epoch {
        // Its payload is checked before it is kept.
        return payload_step(v, ctx, gate(v), ran).unwrap_or(Verdict::PendingEpoch);
    }
    // Layer E.
    if v.timestamp > ctx.now_secs.saturating_add(MAX_FUTURE_DRIFT_SECS) {
        return Verdict::Early;
    }
    // B136: the memo before E4's pairings. A copy of a body refused before
    // used to verify the certificates it carried first, every copy.
    let memo = gate(v);
    if let Some(verdict) = remembered(v, memo) {
        return verdict;
    }
    if v.round == active.first_round {
        // B95: the payload's signatures only now, past the cheap filters.
        return check(v, ctx, memo, ran).unwrap_or(Verdict::Stage);
    }
    // B190: hashed only when a carried certificate is checked (a pairing
    // follows); every vertex reaching E4 hashed the whole committee.
    let committee_hash = std::cell::OnceCell::new();
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
            committee_hash: committee_hash
                .get_or_init(|| qc::validator_set_hash(active.committee))
                .clone(),
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
    let mut missing = Vec::new();
    // B226: once one embedded certificate fails, the copy's others are not
    // checked: no honest node embeds one that fails, and each was a pairing
    // (up to one a ref, ~0.5 s a copy at 256 members on a Pi) before the
    // failures, counted after the message, muted its sender (B51).
    let mut embedded = true;
    for (i, r) in v.parent_refs.iter().enumerate() {
        // An embedded certificate is a transport field any relay can
        // corrupt: a bad one falls back to the local copy, and neither
        // being good only makes the vertex wait.
        if verified(r) {
            continue;
        }
        if let Some(c) = r.cert.as_ref().filter(|_| embedded) {
            let (passed, failed) = crate::work::failed_in(|| certified(r, c));
            if passed {
                // B136: reported whatever the verdict, so the engine keeps it.
                ran.certified.push(i);
                continue;
            }
            // B229: charged once whatever failed (a failed pairing charged
            // itself; a bitmap below the quorum or a stake mismatch, each
            // after a committee hash and two sorts, did not): no honest node
            // embeds a certificate that fails.
            if failed == 0 {
                crate::work::note_failed_check();
            }
            embedded = false;
        }
        if !local_cert(r).is_some_and(|c| certified(r, &c)) {
            missing.push(i);
        }
    }
    if missing.is_empty() {
        // B95/B117: the payload's signatures last, for a vertex that stages.
        check(v, ctx, memo, ran).unwrap_or(Verdict::Stage)
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
