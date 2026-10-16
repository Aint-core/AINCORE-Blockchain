//! G1 S2 acceptance (`docs/G1_CONSENSUS_CONTRACT.md`, "Staged implementation
//! plan", S2): one test per IN-1 clause. Each refusal is paired with the
//! acceptance it departs from, so no test passes by refusing everything.

use super::*;
use crate::qc::derive_validator_bls_seed;
use crate::vcert::{CertCollector, CollectOutcome, VertexAttestation};
use crypto::bls::BLSEngine;

const CHAIN: &str = "AINCORE-V4-TEST";
const GENESIS: &str = "genesis-identity-v4-test";
const EPOCH: u64 = 2;
const FIRST: u64 = 1_000;
const NOW: u64 = 1_000_000;

struct Member {
    node_key: [u8; 32],
    info: ValidatorInfo,
}

fn member(seed: u8) -> Member {
    let node_key = [seed; 32];
    let ed = crypto::SigningKey::from_bytes(&node_key)
        .verifying_key()
        .to_bytes();
    let bls = BLSEngine::consensus();
    let bls_seed = derive_validator_bls_seed(&node_key);
    Member {
        node_key,
        info: ValidatorInfo {
            address: crypto::derive_address(&ed).unwrap(),
            stake: 100,
            ed25519_public_key: hex::encode(ed),
            bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed, &ed)),
        },
    }
}

/// Four equal-stake members in canonical order: a quorum is any three.
fn members() -> Vec<Member> {
    let mut m: Vec<Member> = (1..=4u8).map(member).collect();
    m.sort_by(|a, b| a.info.address.cmp(&b.info.address));
    m
}

fn committee(m: &[Member]) -> Vec<ValidatorInfo> {
    m.iter().map(|m| m.info.clone()).collect()
}

fn sentinel(epoch: u64) -> String {
    blockchain::epoch_genesis(
        CHAIN,
        GENESIS,
        epoch,
        FIRST,
        &"b".repeat(64),
        &"a".repeat(64),
    )
}

fn seal(v: &mut Vertex, m: &Member) {
    v.hash = v.hash_v4_with_domain(CHAIN, GENESIS);
    v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&m.node_key));
}

fn vertex(
    m: &Member,
    epoch: u64,
    round: u64,
    parents: Vec<String>,
    refs: Vec<ParentRef>,
) -> Vertex {
    let mut v = Vertex {
        epoch,
        round,
        author: m.info.address.clone(),
        parents,
        parent_refs: refs,
        payload: vec![crate::test_txs::tx(CHAIN, 1, 0)],
        timestamp: NOW - 5,
        hash: String::new(),
        signature: String::new(),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
    };
    seal(&mut v, m);
    v
}

fn first_round(m: &Member) -> Vertex {
    vertex(m, EPOCH, FIRST, vec![sentinel(EPOCH)], vec![])
}

/// A certificate for `parent` in `epoch`, from the signers given.
fn certify(all: &[Member], parent: &Vertex, epoch: u64, signers: &[usize]) -> CompactCert {
    let c = committee(all);
    let body = AttestBody {
        chain_id: CHAIN.into(),
        genesis_identity: GENESIS.into(),
        epoch,
        round: parent.round,
        author: parent.author.clone(),
        digest: parent.hash.clone(),
        committee_hash: qc::validator_set_hash(&c),
    };
    let mut collector = CertCollector::new(body.clone(), &c).unwrap();
    let mut out = None;
    for &i in signers {
        let att = VertexAttestation {
            body: body.clone(),
            signer: all[i].info.address.clone(),
            signature: BLSEngine::consensus().sign_raw(
                &body.signing_bytes(),
                &derive_validator_bls_seed(&all[i].node_key),
            ),
        };
        if let CollectOutcome::Certified(cert) = collector.add(&att).unwrap() {
            out = Some(cert.compact());
        }
    }
    out.expect("a quorum")
}

fn reference(parent: &Vertex, cert: Option<CompactCert>) -> ParentRef {
    ParentRef {
        round: parent.round,
        author: parent.author.clone(),
        digest: parent.hash.clone(),
        proof: None,
        cert,
    }
}

/// A round FIRST + 1 vertex by `all[by]`, citing the first-round vertices of
/// `cited`, each with an embedded certificate.
fn second_round(all: &[Member], by: usize, cited: &[usize]) -> (Vertex, Vec<Vertex>) {
    let parents: Vec<Vertex> = cited.iter().map(|&i| first_round(&all[i])).collect();
    let refs = parents
        .iter()
        .map(|p| reference(p, Some(certify(all, p, EPOCH, &[0, 1, 2]))))
        .collect();
    let digests = parents.iter().map(|p| p.hash.clone()).collect();
    (vertex(&all[by], EPOCH, FIRST + 1, digests, refs), parents)
}

fn verdict_with(
    v: &Vertex,
    committee: &[ValidatorInfo],
    local: impl Fn(&ParentRef) -> Option<CompactCert>,
) -> Verdict {
    let sentinels = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let record = |i: usize| EpochRecord {
        epoch: EPOCH - 1 + i as u64,
        first_round: FIRST,
        closing_round: None,
        sentinel: &sentinels[i],
        committee,
    };
    let ctx = Context {
        chain_id: CHAIN,
        genesis_identity: GENESIS,
        active: record(1),
        gap_wanted_to: 0,
        next: Some(record(2)),
        now_secs: NOW,
        gc_floor: 0,
        cursor: FIRST,
    };
    v4_verdict(serde_json::to_vec(v).unwrap().len(), v, &ctx, local)
}

fn verdict(v: &Vertex, committee: &[ValidatorInfo]) -> Verdict {
    verdict_with(v, committee, |_| None)
}

fn invalid(v: Verdict) -> bool {
    matches!(v, Verdict::Invalid(_))
}

#[test]
fn honest_vertices_stage() {
    let all = members();
    let c = committee(&all);
    assert_eq!(verdict(&first_round(&all[0]), &c), Verdict::Stage);
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    assert_eq!(verdict(&v, &c), Verdict::Stage);
}

#[test]
fn a_tampered_epoch_is_invalid() {
    let all = members();
    let c = committee(&all);
    let (mut v, _) = second_round(&all, 3, &[0, 1, 2]);
    assert_eq!(verdict(&v, &c), Verdict::Stage);
    v.epoch += 1;
    let v_next = v.clone();
    v.epoch -= 2;
    // The hash binds the epoch: another epoch is not the signed vertex.
    assert!(invalid(verdict(&v_next, &c)), "{:?}", verdict(&v_next, &c));
    // B171: the closed epoch's copy is dropped before Layer S.
    assert_eq!(verdict(&v, &c), Verdict::Stale);
}

#[test]
fn a_certificate_of_another_epoch_leaves_the_vertex_pending() {
    let all = members();
    let c = committee(&all);
    let (mut v, parents) = second_round(&all, 3, &[0, 1, 2]);
    // Genuine signatures, for the same slot in the previous epoch.
    v.parent_refs[1].cert = Some(certify(&all, &parents[1], EPOCH - 1, &[0, 1, 2]));
    // B226: past a failed embedded certificate, the copy's others are not
    // checked (ref 2 waits too, for its own certificate).
    assert_eq!(verdict(&v, &c), Verdict::PendingCert(vec![1, 2]));
}

#[test]
fn a_missing_certificate_leaves_the_vertex_pending() {
    let all = members();
    let c = committee(&all);
    let (mut v, _) = second_round(&all, 3, &[0, 1, 2]);
    v.parent_refs[0].cert = None;
    v.parent_refs[2].cert = None;
    assert_eq!(verdict(&v, &c), Verdict::PendingCert(vec![0, 2]));
}

#[test]
fn a_stripped_certificate_with_a_local_copy_stages() {
    let all = members();
    let c = committee(&all);
    let (mut v, parents) = second_round(&all, 3, &[0, 1, 2]);
    let held = certify(&all, &parents[0], EPOCH, &[1, 2, 3]);
    v.parent_refs[0].cert = None;
    let local = |r: &ParentRef| (r.digest == parents[0].hash).then(|| held.clone());
    assert_eq!(verdict_with(&v, &c, local), Verdict::Stage);
    // The local copy is looked up by the ref's own digest.
    let wrong = |_: &ParentRef| Some(certify(&all, &parents[1], EPOCH, &[0, 1, 2]));
    assert_eq!(verdict_with(&v, &c, wrong), Verdict::PendingCert(vec![0]));
}

#[test]
fn a_corrupted_embedded_certificate_is_never_invalid() {
    let all = members();
    let c = committee(&all);
    let (mut v, parents) = second_round(&all, 3, &[0, 1, 2]);
    let good = v.parent_refs[2].cert.clone().unwrap();
    let mut bad = good.clone();
    bad.aggregate_signature[5] ^= 1;
    v.parent_refs[2].cert = Some(bad.clone());
    // The hash does not cover the transport field: the vertex still verifies.
    assert_eq!(verdict(&v, &c), Verdict::PendingCert(vec![2]));
    let local = |r: &ParentRef| (r.digest == parents[2].hash).then(|| good.clone());
    assert_eq!(verdict_with(&v, &c, local), Verdict::Stage);
    // A bitmap below the quorum is corruption too, not invalidity.
    let mut thin = good.clone();
    thin.signer_bitmap = vec![0b0000_0001];
    v.parent_refs[2].cert = Some(thin);
    assert_eq!(verdict(&v, &c), Verdict::PendingCert(vec![2]));
}

#[test]
fn a_round_skip_or_a_thin_anchor_is_invalid() {
    let all = members();
    let c = committee(&all);
    // Citing round FIRST from round FIRST + 2 skips a round.
    let (v, parents) = second_round(&all, 3, &[0, 1, 2]);
    let refs = v.parent_refs.clone();
    let skip = vertex(
        &all[3],
        EPOCH,
        FIRST + 2,
        parents.iter().map(|p| p.hash.clone()).collect(),
        refs,
    );
    assert!(invalid(verdict(&skip, &c)), "{:?}", verdict(&skip, &c));
    // Two of four authors is not a quorum.
    let (thin, _) = second_round(&all, 3, &[0, 1]);
    assert!(invalid(verdict(&thin, &c)), "{:?}", verdict(&thin, &c));
    let (quorum, _) = second_round(&all, 3, &[0, 1, 3]);
    assert_eq!(verdict(&quorum, &c), Verdict::Stage);
}

#[test]
fn a_duplicate_parent_author_is_invalid() {
    let all = members();
    let c = committee(&all);
    // Twins: two first-round vertices by member 0.
    let a = first_round(&all[0]);
    let mut b = vertex(&all[0], EPOCH, FIRST, vec![sentinel(EPOCH)], vec![]);
    b.payload = vec![crate::test_txs::tx(CHAIN, 2, 0)];
    seal(&mut b, &all[0]);
    let p1 = first_round(&all[1]);
    let cited = [&a, &b, &p1];
    let v = vertex(
        &all[3],
        EPOCH,
        FIRST + 1,
        cited.iter().map(|p| p.hash.clone()).collect(),
        cited
            .iter()
            .map(|p| reference(p, Some(certify(&all, p, EPOCH, &[0, 1, 2]))))
            .collect(),
    );
    let verdict = verdict(&v, &c);
    assert!(
        matches!(&verdict, Verdict::Invalid(e) if e.contains("twice")),
        "{verdict:?}"
    );
}

#[test]
fn a_wrong_sentinel_is_invalid() {
    let all = members();
    let c = committee(&all);
    for wrong in [
        "genesis".to_string(),
        sentinel(EPOCH - 1),
        sentinel(EPOCH + 1),
    ] {
        let v = vertex(&all[0], EPOCH, FIRST, vec![wrong.clone()], vec![]);
        assert!(invalid(verdict(&v, &c)), "{wrong}");
    }
    // A first-round vertex with refs as well as the sentinel.
    let p = first_round(&all[1]);
    let v = vertex(
        &all[0],
        EPOCH,
        FIRST,
        vec![sentinel(EPOCH)],
        vec![reference(&p, None)],
    );
    assert!(invalid(verdict(&v, &c)));
    assert_eq!(verdict(&first_round(&all[0]), &c), Verdict::Stage);
}

#[test]
fn first_round_vertices_across_the_boundary_are_classified_by_epoch() {
    let all = members();
    let c = committee(&all);
    let at = |epoch| vertex(&all[0], epoch, FIRST, vec![sentinel(epoch)], vec![]);
    assert_eq!(verdict(&at(EPOCH), &c), Verdict::Stage);
    assert_eq!(verdict(&at(EPOCH + 1), &c), Verdict::PendingEpoch);
    assert_eq!(verdict(&at(EPOCH - 1), &c), Verdict::Stale);
    assert!(matches!(verdict(&at(EPOCH + 2), &c), Verdict::Drop(_)));
    // Another epoch's vertex is judged by that epoch's own record: round 1
    // is below its first round.
    let next = vertex(&all[0], EPOCH + 1, 1, vec![sentinel(EPOCH + 1)], vec![]);
    assert!(invalid(verdict(&next, &c)));
}

#[test]
fn layer_s_refuses_what_every_node_refuses() {
    let all = members();
    let c = committee(&all);
    let ok = first_round(&all[0]);
    assert_eq!(verdict(&ok, &c), Verdict::Stage);
    let refused = |v: &Vertex| invalid(verdict(v, &c));
    let mut v = ok.clone();
    v.payload_root = Some(v.payload_root());
    v.payload.clear();
    assert!(refused(&v), "a compact proof");
    let mut v = ok.clone();
    v.aggregated_signature = Some("00".into());
    seal(&mut v, &all[0]);
    assert!(refused(&v), "an aggregate signature");
    // B73: a valid transaction in another encoding: its keys in another
    // order, the same length, so it passes every other check (its byte gas
    // included) and only the canonical rule refuses it.
    let tx = crate::test_txs::tx(CHAIN, 1, 0);
    let reordered = serde_json::from_str::<serde_json::Value>(&tx)
        .unwrap()
        .to_string();
    assert_ne!(reordered, tx);
    assert_eq!(reordered.len(), tx.len());
    executor::admission::check_stateless(&reordered, CHAIN)
        .expect("control: the same transaction, valid in itself");
    let mut v = ok.clone();
    v.payload = vec![reordered];
    seal(&mut v, &all[0]);
    assert!(refused(&v), "a transaction in another encoding");
    // Refs that pass every other rule: three members' claims make a quorum,
    // the rest are distinct non-members, so only the parent count refuses.
    let claims = |round: u64, n: usize| -> (Vec<String>, Vec<ParentRef>) {
        let refs: Vec<ParentRef> = (0..n)
            .map(|i| ParentRef {
                round,
                author: if i < 3 {
                    all[i].info.address.clone()
                } else {
                    format!("{i:064x}")
                },
                digest: format!("{:064x}", i + 1_000),
                proof: None,
                cert: None,
            })
            .collect();
        (refs.iter().map(|r| r.digest.clone()).collect(), refs)
    };
    let (parents, refs) = claims(FIRST, MAX_PARENTS + 1);
    assert!(
        refused(&vertex(&all[3], EPOCH, FIRST + 1, parents, refs)),
        "too many parents"
    );
    // One digest cited twice, under two claimed authors: the refs alone
    // would pass (three distinct authors), so only the digest rule refuses.
    let p = first_round(&all[0]);
    let q = first_round(&all[1]);
    let r = |author: usize, parent: &Vertex| ParentRef {
        round: FIRST,
        author: all[author].info.address.clone(),
        digest: parent.hash.clone(),
        proof: None,
        cert: None,
    };
    let twice = vertex(
        &all[3],
        EPOCH,
        FIRST + 1,
        vec![p.hash.clone(), p.hash.clone(), q.hash.clone()],
        vec![r(0, &p), r(2, &p), r(1, &q)],
    );
    assert!(refused(&twice), "a parent twice: {:?}", verdict(&twice, &c));
    let mut v = ok.clone();
    v.timestamp += 1;
    assert!(refused(&v), "a hash that is not the body's");
    let v3 = {
        let mut v = ok.clone();
        v.hash = v.calculate_hash_with_domain(CHAIN, GENESIS);
        v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&all[0].node_key));
        v
    };
    assert!(refused(&v3), "a V3 hash");
    let outsider = member(9);
    assert!(refused(&first_round(&outsider)), "not a member");
    let mut v = ok.clone();
    v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&all[1].node_key));
    assert!(refused(&v), "signed by another key");
    let mut zero = c.clone();
    zero[0].stake = 0;
    assert!(invalid(verdict(&ok, &zero)), "no stake");
    let v = vertex(&all[0], EPOCH, FIRST - 1, vec![sentinel(EPOCH)], vec![]);
    assert!(refused(&v), "below the first round");
    // Payload-free: B158's lead filter drops a payload that far ahead
    // before Layer S, whatever it is.
    let past_the_lead = |round: u64| {
        let (parents, refs) = claims(round - 1, 3);
        let mut v = vertex(&all[0], EPOCH, round, parents, refs);
        v.payload.clear();
        seal(&mut v, &all[0]);
        v
    };
    // B249: over the ceiling is refused in every context, before the lead
    // filters (B229's drop of a body past the lead with uncertified parents
    // made it a context's `Drop`).
    let v = past_the_lead(ABSOLUTE_ROUND_CEILING + 1);
    assert!(refused(&v), "over the ceiling: {:?}", verdict(&v, &c));
    let v = past_the_lead(ABSOLUTE_ROUND_CEILING);
    assert!(!refused(&v), "at the ceiling: {:?}", verdict(&v, &c));
    let sentinel = sentinel(EPOCH);
    let ctx = Context {
        chain_id: CHAIN,
        genesis_identity: GENESIS,
        active: EpochRecord {
            epoch: EPOCH,
            first_round: FIRST,
            closing_round: None,
            sentinel: &sentinel,
            committee: &c,
        },
        gap_wanted_to: 0,
        next: None,
        now_secs: NOW,
        gc_floor: 0,
        cursor: FIRST,
    };
    assert!(
        invalid(v4_verdict(MAX_VERTEX_BYTES + 1, &ok, &ctx, |_| None)),
        "size"
    );
    assert_eq!(
        v4_verdict(MAX_VERTEX_BYTES, &ok, &ctx, |_| None),
        Verdict::Stage
    );
}

/// B95 witness: the payload's checks (a signature or two an item) run only
/// after Layer E's cheap filters, through the engine's gate: a copy dropped
/// past the lead, early or below the floor never reaches them, a staging
/// copy reaches them once, a third body of a slot is dropped unchecked, and
/// an item repeated is refused.
#[test]
fn the_payload_is_checked_after_the_cheap_filters() {
    let all = members();
    let c = committee(&all);
    let sentinel = sentinel(EPOCH);
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    let ctx = |now: u64, floor: u64, cursor: u64| Context {
        chain_id: CHAIN,
        genesis_identity: GENESIS,
        active: EpochRecord {
            epoch: EPOCH,
            first_round: FIRST,
            closing_round: None,
            sentinel: &sentinel,
            committee: &c,
        },
        gap_wanted_to: 0,
        next: None,
        now_secs: now,
        gc_floor: floor,
        cursor,
    };
    let gated = |cx: &Context<'_>, gate: &dyn Fn(&Vertex) -> PayloadGate| {
        v4_verdict_gated(1_000, &v, cx, |_| None, |_| false, |x| gate(x))
    };
    let untouched = |_: &Vertex| -> PayloadGate { panic!("the payload was checked") };
    let far = FIRST + 1 - LEAD - 1;
    assert!(matches!(
        gated(&ctx(NOW, 0, far), &untouched),
        Verdict::Drop(_)
    ));
    assert_eq!(
        gated(&ctx(v.timestamp - 31, 0, FIRST), &untouched),
        Verdict::Early
    );
    assert_eq!(
        gated(&ctx(NOW, FIRST + 1, FIRST), &untouched),
        Verdict::Stale
    );
    let calls = std::cell::Cell::new(0);
    let counted = |_: &Vertex| {
        calls.set(calls.get() + 1);
        PayloadGate::Check
    };
    assert_eq!(gated(&ctx(NOW, 0, FIRST), &counted), Verdict::Stage);
    assert_eq!(calls.get(), 1);
    assert!(matches!(
        gated(&ctx(NOW, 0, FIRST), &|_| PayloadGate::Full),
        Verdict::Drop(_)
    ));
    let mut twice = v.clone();
    let item = twice.payload[0].clone();
    twice.payload = vec![item.clone(), item];
    seal(&mut twice, &all[3]);
    assert!(invalid(v4_verdict(
        1_000,
        &twice,
        &ctx(NOW, 0, FIRST),
        |_| None
    )));
    // A bad payload on a copy the cheap filters drop is never looked at.
    assert!(
        matches!(
            v4_verdict_gated(
                1_000,
                &twice,
                &ctx(NOW, 0, far),
                |_| None,
                |_| false,
                |_| PayloadGate::Check
            ),
            Verdict::Drop(_)
        ),
        "the payload was checked before the cheap filters"
    );
}

/// B136 witness: what the node remembers of the payload is read before E4,
/// so a copy of a body refused before (or a full slot's third) verifies none
/// of the certificates it carries: each copy paid a pairing per carried
/// certificate the node did not hold.
#[test]
fn the_payload_memo_is_read_before_any_certificate_is_checked() {
    let all = members();
    let c = committee(&all);
    let sentinel = sentinel(EPOCH);
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    let ctx = Context {
        chain_id: CHAIN,
        genesis_identity: GENESIS,
        active: EpochRecord {
            epoch: EPOCH,
            first_round: FIRST,
            closing_round: None,
            sentinel: &sentinel,
            committee: &c,
        },
        gap_wanted_to: 0,
        next: None,
        now_secs: NOW,
        gc_floor: 0,
        cursor: FIRST,
    };
    let verifications = || crate::vcert::CERT_VERIFICATIONS.with(|n| n.get());
    for memo in [PayloadGate::Refused, PayloadGate::Full] {
        let before = verifications();
        let verdict = v4_verdict_gated(1_000, &v, &ctx, |_| None, |_| false, |_| memo);
        assert!(
            matches!(verdict, Verdict::Invalid(_) | Verdict::Drop(_)),
            "{verdict:?}"
        );
        assert_eq!(
            verifications(),
            before,
            "{memo:?}: a certificate was checked before the memo"
        );
    }
    let before = verifications();
    let (verdict, ran) =
        v4_verdict_checked(1_000, &v, &ctx, |_| None, |_| false, |_| PayloadGate::Check);
    assert_eq!(verdict, Verdict::Stage);
    assert_eq!(verifications() - before, 3, "vacuous: E4 checked nothing");
    assert_eq!(ran.certified, vec![0, 1, 2], "the verified certificates");
}

/// B158 witness: the filters that need no authentication (the floor, a
/// payload past the lead) drop a copy before Layer S; a hash or signature
/// that fails is a failed costly check (B51).
#[test]
fn the_cheap_filters_run_before_layer_s() {
    let all = members();
    let c = committee(&all);
    let sentinel = sentinel(EPOCH);
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    let ctx = |floor: u64, cursor: u64| Context {
        chain_id: CHAIN,
        genesis_identity: GENESIS,
        active: EpochRecord {
            epoch: EPOCH,
            first_round: FIRST,
            closing_round: None,
            sentinel: &sentinel,
            committee: &c,
        },
        gap_wanted_to: 0,
        next: None,
        now_secs: NOW,
        gc_floor: floor,
        cursor,
    };
    let runs = || LAYER_S_RUNS.with(|n| n.get());
    let before = runs();
    assert_eq!(
        v4_verdict(1_000, &v, &ctx(FIRST + 1, FIRST), |_| None),
        Verdict::Stale
    );
    let far = FIRST + 1 - LEAD - 1;
    assert!(matches!(
        v4_verdict(1_000, &v, &ctx(0, far), |_| None),
        Verdict::Drop(_)
    ));
    assert_eq!(runs(), before, "a copy the cheap filters drop ran Layer S");
    let mut forged = v.clone();
    forged.signature = "00".repeat(64);
    let (verdict, failed) =
        crate::work::failed_in(|| v4_verdict(1_000, &forged, &ctx(0, FIRST), |_| None));
    assert!(invalid(verdict));
    assert_eq!(failed, 1, "a failed signature check was not charged");
    // B181: a body naming no staked member is refused, charged, before it
    // is hashed (its hash is wrong too: the author is what is reported).
    let mut stranger = v.clone();
    stranger.author = member(9).info.address.clone();
    stranger.hash = "ab".repeat(32);
    let (verdict, failed) =
        crate::work::failed_in(|| v4_verdict(1_000, &stranger, &ctx(0, FIRST), |_| None));
    assert!(
        matches!(&verdict, Verdict::Invalid(why) if why.contains("staked member")),
        "{verdict:?}"
    );
    assert_eq!(failed, 1, "an unknown author was not charged");
    // B208: so is a body of the wrong form (no honest author sends one).
    let mut aggregated = v.clone();
    aggregated.aggregated_signature = Some("ab".repeat(48));
    let (verdict, failed) =
        crate::work::failed_in(|| v4_verdict(1_000, &aggregated, &ctx(0, FIRST), |_| None));
    assert!(invalid(verdict));
    assert_eq!(failed, 1, "a body of the wrong form was not charged");
}

/// B283 witness: a member waiting on finality proposes up to the floor kept
/// for its lowest block without a QC plus `MAX_KEPT_ROUNDS`, and sends that
/// newest vertex, payload and all, again while it waits. A member coming
/// back adopted the blocks before that block, so its cursor is one past
/// their anchor (the floor plus `GC_DEPTH`) and its g the floor: the vertex
/// is within its lead, and shows it the gap. At `GC_DEPTH + RETAIN_SLACK +
/// LEAD` it was past the lead and dropped before Layer S: the member never
/// learned the gap, never rebuilt the block, and with f members withholding
/// votes no QC formed again.
#[test]
fn a_waiting_members_newest_vertex_is_within_a_returning_members_lead() {
    let all = members();
    let c = committee(&all);
    let sentinel = sentinel(EPOCH);
    let floor = FIRST + 10;
    let newest = floor + crate::v4::MAX_KEPT_ROUNDS;
    let v = vertex(&all[0], EPOCH, newest, vec!["ab".repeat(32)], vec![]);
    assert!(!v.payload.is_empty(), "vacuous: no payload");
    let ctx = Context {
        chain_id: CHAIN,
        genesis_identity: GENESIS,
        active: EpochRecord {
            epoch: EPOCH,
            first_round: FIRST,
            closing_round: None,
            sentinel: &sentinel,
            committee: &c,
        },
        gap_wanted_to: 0,
        next: None,
        now_secs: NOW,
        gc_floor: floor,
        cursor: floor + crate::ordering::GC_DEPTH + 1,
    };
    let verdict = v4_verdict(1_000, &v, &ctx, |_| None);
    assert!(
        !matches!(&verdict, Verdict::Drop(why) if why.contains("lead")),
        "{verdict:?}"
    );
}

/// B171 witness: a closed epoch's copy runs no check, forged or not; a
/// next-epoch copy that shows no more gap than is wanted is not
/// authenticated; the next-epoch check charges a failed hash and an active
/// member's failed signature, but not an author of the next committee only.
#[test]
fn a_neighbouring_epochs_copy_costs_no_free_check() {
    let all = members();
    let c = committee(&all);
    let sentinels = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let at = |m: &Member, epoch| vertex(m, epoch, FIRST, vec![sentinel(epoch)], vec![]);
    let runs = || {
        (
            LAYER_S_RUNS.with(|n| n.get()),
            SIGNED_BY_MEMBER_RUNS.with(|n| n.get()),
        )
    };
    let ctx = context(&c, &sentinels, false);
    let before = runs();
    let mut old = at(&all[0], EPOCH - 1);
    old.signature = "00".repeat(64);
    let (verdict, failed) = crate::work::failed_in(|| v4_verdict(1_000, &old, &ctx, |_| None));
    assert_eq!(verdict, Verdict::Stale);
    assert_eq!(
        (runs(), failed),
        (before, 0),
        "a closed epoch's copy ran a check"
    );
    let ahead = at(&all[0], EPOCH + 1);
    let mut wanted = context(&c, &sentinels, false);
    wanted.gap_wanted_to = FIRST - 1;
    assert!(matches!(
        v4_verdict(1_000, &ahead, &wanted, |_| None),
        Verdict::Drop(_)
    ));
    assert_eq!(
        runs(),
        before,
        "a copy that shows nothing new was authenticated"
    );
    wanted.gap_wanted_to = FIRST - 2;
    assert_eq!(v4_verdict(1_000, &ahead, &wanted, |_| None), Verdict::Ahead);
    assert_eq!(runs().1, before.1 + 1, "vacuous: not authenticated");
    let mut bad_hash = ahead.clone();
    bad_hash.hash = "ab".repeat(32);
    let mut bad_signature = ahead.clone();
    bad_signature.signature = "00".repeat(64);
    for v in [&bad_hash, &bad_signature] {
        let (verdict, failed) = crate::work::failed_in(|| v4_verdict(1_000, v, &ctx, |_| None));
        assert!(matches!(verdict, Verdict::Drop(_)), "{verdict:?}");
        assert_eq!(failed, 1, "a failed next-epoch check was not charged");
    }
    let newcomer = member(5);
    let (verdict, failed) =
        crate::work::failed_in(|| v4_verdict(1_000, &at(&newcomer, EPOCH + 1), &ctx, |_| None));
    assert!(matches!(verdict, Verdict::Drop(_)), "{verdict:?}");
    assert_eq!(failed, 0, "a next committee's author was charged");
    // B181: its author is looked up before its body is hashed.
    let mut unhashed = at(&newcomer, EPOCH + 1);
    unhashed.hash = "ab".repeat(32);
    let (verdict, failed) = crate::work::failed_in(|| v4_verdict(1_000, &unhashed, &ctx, |_| None));
    assert!(matches!(verdict, Verdict::Drop(_)), "{verdict:?}");
    assert_eq!(failed, 0, "a next committee's author was hashed first");
}

#[test]
fn layer_e_delays_but_never_refuses() {
    let all = members();
    let c = committee(&all);
    let sentinel = sentinel(EPOCH);
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    let at = |now: u64, floor: u64, cursor: u64, v: &Vertex| {
        let ctx = Context {
            chain_id: CHAIN,
            genesis_identity: GENESIS,
            active: EpochRecord {
                epoch: EPOCH,
                first_round: FIRST,
                closing_round: None,
                sentinel: &sentinel,
                committee: &c,
            },
            gap_wanted_to: 0,
            next: None,
            now_secs: now,
            gc_floor: floor,
            cursor,
        };
        v4_verdict(1_000, v, &ctx, |_| None)
    };
    assert_eq!(at(NOW, 0, FIRST, &v), Verdict::Stage);
    assert_eq!(at(v.timestamp - 31, 0, FIRST, &v), Verdict::Early, "the clock");
    assert_eq!(
        at(v.timestamp - 30, 0, FIRST, &v),
        Verdict::Stage,
        "within drift"
    );
    assert_eq!(
        at(NOW, FIRST + 1, FIRST, &v),
        Verdict::Stale,
        "at the floor"
    );
    assert_eq!(at(NOW, FIRST, FIRST, &v), Verdict::Stage, "above the floor");
    let far = FIRST + 1 - LEAD - 1;
    assert!(
        matches!(at(NOW, 0, far, &v), Verdict::Drop(_)),
        "payload past the lead"
    );
    assert_eq!(at(NOW, 0, far + 1, &v), Verdict::Stage, "within the lead");
    // Rounds keep advancing past the lead on payload-free vertices: a hard
    // cap on rounds deadlocks once every round up to it is proposed.
    let mut empty = v.clone();
    empty.payload.clear();
    seal(&mut empty, &all[3]);
    assert_eq!(
        at(NOW, 0, far, &empty),
        Verdict::Stage,
        "empty, past the lead"
    );
    // Whatever the context, a vertex that passes Layer S is never invalid.
    for now in [0, NOW, u64::MAX] {
        for floor in [0, FIRST + 5, u64::MAX] {
            for cursor in [0, FIRST, u64::MAX] {
                assert!(
                    !invalid(at(now, floor, cursor, &v)),
                    "{now} {floor} {cursor}"
                );
            }
        }
    }
}

/// Layer S's verdict does not depend on the context. B158: a copy the cheap
/// filters drop (at or below the floor, a payload past the lead) never
/// reaches it, whatever it is, so the contexts here pass them.
#[test]
fn layer_s_verdicts_do_not_depend_on_the_context() {
    let all = members();
    let c = committee(&all);
    let sentinel = sentinel(EPOCH);
    let mut bad = first_round(&all[0]);
    bad.timestamp += 1;
    for (now, floor, cursor) in [
        (0, 0, FIRST),
        (NOW, FIRST - 1, u64::MAX),
        (u64::MAX, 5, FIRST - LEAD),
    ] {
        let ctx = Context {
            chain_id: CHAIN,
            genesis_identity: GENESIS,
            active: EpochRecord {
                epoch: EPOCH,
                first_round: FIRST,
                closing_round: None,
                sentinel: &sentinel,
                committee: &c,
            },
            gap_wanted_to: 0,
            next: None,
            now_secs: now,
            gc_floor: floor,
            cursor,
        };
        assert!(invalid(v4_verdict(1_000, &bad, &ctx, |_| None)));
    }
}

// ── review of S2 (733e0d8) ─────────────────────────────────────────────────

fn context<'a>(
    committee: &'a [ValidatorInfo],
    sentinels: &'a [String; 3],
    next: bool,
) -> Context<'a> {
    let record = |i: usize| EpochRecord {
        epoch: EPOCH - 1 + i as u64,
        first_round: FIRST,
        closing_round: None,
        sentinel: &sentinels[i],
        committee,
    };
    Context {
        chain_id: CHAIN,
        genesis_identity: GENESIS,
        active: record(1),
        next: next.then(|| record(2)),
        gap_wanted_to: 0,
        now_secs: NOW,
        gc_floor: 0,
        cursor: FIRST,
    }
}

/// MEDIUM-1: a vertex of the next epoch is authenticated under that
/// epoch's record before it is kept; without the record it is dropped.
/// B171: one of the closed epoch is dropped before Layer S, forged or not.
#[test]
fn adjacent_epochs_are_authenticated_before_they_are_kept() {
    let all = members();
    let c = committee(&all);
    let sentinels = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let at = |epoch| vertex(&all[0], epoch, FIRST, vec![sentinel(epoch)], vec![]);
    let forged = |epoch| {
        let mut v = at(epoch);
        v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&all[1].node_key));
        v
    };
    let judge = |v: &Vertex, next| v4_verdict(1_000, v, &context(&c, &sentinels, next), |_| None);
    assert_eq!(judge(&at(EPOCH + 1), true), Verdict::PendingEpoch);
    assert!(
        invalid(judge(&forged(EPOCH + 1), true)),
        "a forged next-epoch vertex"
    );
    // Without the next record the vertex cannot be kept, but a member's
    // signature on it proves the network is past the boundary (Ahead); a
    // forged one proves nothing.
    assert_eq!(judge(&at(EPOCH + 1), false), Verdict::Ahead);
    assert!(
        matches!(judge(&forged(EPOCH + 1), false), Verdict::Drop(_)),
        "a forged next-epoch vertex without the next record"
    );
    assert_eq!(judge(&at(EPOCH - 1), true), Verdict::Stale);
    assert_eq!(
        judge(&forged(EPOCH - 1), true),
        Verdict::Stale,
        "a forged old-epoch vertex"
    );
    assert!(matches!(judge(&at(EPOCH + 2), true), Verdict::Drop(_)));
    assert!(matches!(judge(&at(EPOCH - 2), true), Verdict::Drop(_)));
    // The active epoch at the edge of u64: no overflow, no panic.
    let edge = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let mut ctx = context(&c, &edge, false);
    ctx.active.epoch = u64::MAX;
    let mut v = at(EPOCH);
    v.epoch = u64::MAX;
    seal(&mut v, &all[0]);
    assert!(!matches!(
        v4_verdict(1_000, &v, &ctx, |_| None),
        Verdict::Drop(_)
    ));
    v.epoch = 5;
    seal(&mut v, &all[0]);
    assert!(
        matches!(v4_verdict(1_000, &v, &ctx, |_| None), Verdict::Drop(_)),
        "not adjacent to u64::MAX"
    );
    v.epoch = 0;
    seal(&mut v, &all[0]);
    ctx.active.epoch = 0;
    assert!(!matches!(
        v4_verdict(1_000, &v, &ctx, |_| None),
        Verdict::Stale
    ));
}

/// Plausible LOW: above the epoch's closing round r*, a vertex of it is stale.
#[test]
fn a_vertex_above_the_closing_round_is_stale() {
    let all = members();
    let c = committee(&all);
    let sentinels = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    let mut ctx = context(&c, &sentinels, true);
    ctx.active.closing_round = Some(FIRST + 1);
    assert_eq!(
        v4_verdict(1_000, &v, &ctx, |_| None),
        Verdict::Stage,
        "at r*"
    );
    ctx.active.closing_round = Some(FIRST);
    assert_eq!(
        v4_verdict(1_000, &v, &ctx, |_| None),
        Verdict::Stale,
        "above r*"
    );
}

/// MEDIUM-3: past the lead, a payload-free vertex is staged only on parents
/// already certified; otherwise it is dropped, and nothing is asked for.
#[test]
fn past_the_lead_only_certified_parents_are_staged() {
    let all = members();
    let c = committee(&all);
    let sentinels = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let (mut v, _) = second_round(&all, 3, &[0, 1, 2]);
    v.payload.clear();
    seal(&mut v, &all[3]);
    let mut ctx = context(&c, &sentinels, true);
    ctx.cursor = 0;
    assert_eq!(v4_verdict(1_000, &v, &ctx, |_| None), Verdict::Stage);
    v.parent_refs[1].cert = None;
    assert!(matches!(
        v4_verdict(1_000, &v, &ctx, |_| None),
        Verdict::Drop(_)
    ));
    ctx.cursor = FIRST;
    assert_eq!(
        v4_verdict(1_000, &v, &ctx, |_| None),
        Verdict::PendingCert(vec![1])
    );
}

/// LOW-1: a ref no certificate could satisfy is refused, not left waiting.
#[test]
fn refs_must_name_staked_members_and_canonical_digests() {
    let all = members();
    let c = committee(&all);
    let (v, parents) = second_round(&all, 3, &[0, 1, 2]);
    assert_eq!(verdict(&v, &c), Verdict::Stage);
    let with = |edit: &dyn Fn(&mut Vertex)| {
        let mut w = v.clone();
        edit(&mut w);
        w.parents = w.parent_refs.iter().map(|r| r.digest.clone()).collect();
        seal(&mut w, &all[3]);
        w
    };
    // A fourth ref by a non-member: the other three still make a quorum, so
    // only the membership rule refuses it.
    let outsider = member(9);
    let stray = first_round(&outsider);
    let extra = with(&|w| w.parent_refs.push(reference(&stray, None)));
    assert!(invalid(verdict(&extra, &c)), "{:?}", verdict(&extra, &c));
    let upper = parents[0].hash.to_uppercase();
    assert!(invalid(verdict(
        &with(&|w| w.parent_refs[0].digest = upper.clone()),
        &c
    )));
}

/// LOW-3: the signature must be canonical (lowercase) hex.
#[test]
fn an_upper_case_signature_is_invalid() {
    let all = members();
    let c = committee(&all);
    let mut v = first_round(&all[0]);
    assert_eq!(verdict(&v, &c), Verdict::Stage);
    v.signature = v.signature.to_uppercase();
    assert!(invalid(verdict(&v, &c)));
}

/// Review mutants: clauses the first tests did not pin.
#[test]
fn clauses_the_first_tests_did_not_pin() {
    let all = members();
    let c = committee(&all);
    // The sentinel is the ONLY parent of a first-round vertex.
    let p = first_round(&all[1]);
    let extra = vertex(
        &all[0],
        EPOCH,
        FIRST,
        vec![sentinel(EPOCH), p.hash.clone()],
        vec![],
    );
    assert!(invalid(verdict(&extra, &c)), "a sentinel and more");
    // A live vertex carries neither compact root.
    let mut rooted = first_round(&all[0]);
    rooted.parents_root = Some(rooted.parents_root_v4());
    seal(&mut rooted, &all[0]);
    assert!(
        invalid(verdict(&rooted, &c)),
        "a parents root on a live vertex"
    );
    // The author is matched exactly, not case-insensitively.
    let mut upper = first_round(&all[0]);
    upper.author = upper.author.to_uppercase();
    seal(&mut upper, &all[0]);
    assert!(invalid(verdict(&upper, &c)), "an upper-case author");
    // Stake, not a count of authors (C9): 4000/3000/2000/1000.
    let mut weighted = c.clone();
    for (m, stake) in weighted.iter_mut().zip([4000, 3000, 2000, 1000]) {
        m.stake = stake;
    }
    let claims = |authors: &[usize]| -> Vertex {
        let refs: Vec<ParentRef> = authors
            .iter()
            .map(|&i| ParentRef {
                round: FIRST,
                author: all[i].info.address.clone(),
                digest: format!("{:064x}", 5_000 + i),
                proof: None,
                cert: None,
            })
            .collect();
        vertex(
            &all[3],
            EPOCH,
            FIRST + 1,
            refs.iter().map(|r| r.digest.clone()).collect(),
            refs,
        )
    };
    assert!(
        invalid(verdict(&claims(&[1, 2, 3]), &weighted)),
        "3 of 4 authors, 60% of stake"
    );
    assert_eq!(
        verdict(&claims(&[0, 1]), &weighted),
        Verdict::PendingCert(vec![0, 1]),
        "2 of 4 authors, 70% of stake"
    );
    // V3 keeps its round-0 and round-1 exemptions.
    let v3 = |round| Vertex {
        round,
        ..first_round(&all[0])
    };
    assert!(qc::parent_refs_admissible(&v3(0), &[]).is_ok());
    assert!(qc::parent_refs_admissible(&v3(1), &[]).is_ok());
    assert!(qc::parent_refs_admissible(&v3(2), &[]).is_err());
}

// ── review 2 of S2 (fc8b6c0) ───────────────────────────────────────────────

/// MEDIUM-A: a V3 identity proof on a V4 ref, or a certificate of the wrong
/// shape, is refused for that copy.
#[test]
fn transport_padding_is_refused_per_copy() {
    let all = members();
    let c = committee(&all);
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    assert_eq!(verdict(&v, &c), Verdict::Stage);
    let mut proof = v.clone();
    proof.parent_refs[0].proof = Some(blockchain::ParentIdentityProof {
        timestamp: 1,
        payload_root: "0".repeat(64),
        parents_root: "0".repeat(64),
        public_key: "0".repeat(64),
        signature: "0".repeat(128),
    });
    assert_eq!(
        proof.hash_v4_with_domain(CHAIN, GENESIS),
        v.hash,
        "unhashed"
    );
    assert!(invalid(verdict(&proof, &c)), "a V3 proof");
    let mut wide = v.clone();
    wide.parent_refs[0]
        .cert
        .as_mut()
        .unwrap()
        .aggregate_signature
        .extend([0; 1000]);
    assert!(invalid(verdict(&wide, &c)), "an oversized certificate");
    let mut bitmap = v.clone();
    bitmap.parent_refs[1]
        .cert
        .as_mut()
        .unwrap()
        .signer_bitmap
        .push(0);
    assert!(
        invalid(verdict(&bitmap, &c)),
        "a bitmap of the wrong length"
    );
}

/// B224 witness: a transport field no honest V4 node adds (a V3 proof, a
/// certificate of the wrong shape) is refused before the author's signature
/// is checked, and charged: refused after it, each copy ran the hash and
/// the signature first, uncharged.
#[test]
fn transport_padding_is_refused_before_the_signature_and_charged() {
    let all = members();
    let c = committee(&all);
    let (v, _) = second_round(&all, 3, &[0, 1, 2]);
    let mut bitmap = v.clone();
    bitmap.parent_refs[1]
        .cert
        .as_mut()
        .unwrap()
        .signer_bitmap
        .push(0);
    let mut proof = v.clone();
    proof.parent_refs[0].proof = Some(blockchain::ParentIdentityProof {
        timestamp: 1,
        payload_root: "0".repeat(64),
        parents_root: "0".repeat(64),
        public_key: "0".repeat(64),
        signature: "0".repeat(128),
    });
    let runs = || LAYER_S_RUNS.with(|n| n.get());
    for padded in [bitmap, proof] {
        let before = runs();
        let (outcome, failed) = crate::work::failed_in(|| verdict(&padded, &c));
        assert!(invalid(outcome));
        assert_eq!(runs(), before, "a padded copy was authenticated");
        assert_eq!(failed, 1, "a padded copy was not charged");
    }
    assert_eq!(verdict(&v, &c), Verdict::Stage, "control");
}

/// B226 witness: once one embedded certificate fails, a copy's others are
/// not checked (each was a pairing, up to one a ref, before its sender was
/// muted): the copy waits on every ref, at one verification.
#[test]
fn one_failed_embedded_certificate_stops_the_rest() {
    let all = members();
    let c = committee(&all);
    let (mut v, _) = second_round(&all, 3, &[0, 1, 2]);
    for r in &mut v.parent_refs {
        r.cert.as_mut().unwrap().aggregate_signature[5] ^= 1;
    }
    let checks = || crate::vcert::CERT_VERIFICATIONS.with(|n| n.get());
    let before = checks();
    let (outcome, failed) = crate::work::failed_in(|| verdict(&v, &c));
    assert_eq!(outcome, Verdict::PendingCert(vec![0, 1, 2]));
    assert_eq!(
        checks() - before,
        1,
        "a failed copy's other certificates were checked"
    );
    assert_eq!(failed, 1);
    // B229: a certificate failing before any pairing (a bitmap below the
    // quorum, after a committee hash and two sorts) is charged once too.
    let (mut thin, _) = second_round(&all, 3, &[0, 1, 2]);
    for r in &mut thin.parent_refs {
        let cert = r.cert.as_mut().unwrap();
        cert.signer_bitmap = vec![0; cert.signer_bitmap.len()];
        cert.signer_bitmap[0] = 1;
    }
    let (outcome, failed) = crate::work::failed_in(|| verdict(&thin, &c));
    assert_eq!(outcome, Verdict::PendingCert(vec![0, 1, 2]));
    assert_eq!(
        failed, 1,
        "a certificate below the quorum was not charged once"
    );
}

/// MEDIUM-1, pinned: an adjacent epoch is judged by ITS committee and ITS
/// first round, not the active ones.
#[test]
fn an_adjacent_epoch_is_judged_by_its_own_committee_and_first_round() {
    let all = members();
    let active = committee(&all);
    let newcomer = member(5);
    // Epoch E+1: members 1..3 and the newcomer, from round FIRST + 7.
    let mut next_committee: Vec<ValidatorInfo> = all[1..].iter().map(|m| m.info.clone()).collect();
    next_committee.push(newcomer.info.clone());
    next_committee.sort_by(|a, b| a.address.cmp(&b.address));
    let sentinels = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let mut ctx = context(&active, &sentinels, true);
    if let Some(next) = ctx.next.as_mut() {
        next.committee = &next_committee;
        next.first_round = FIRST + 7;
    }
    let at = |m: &Member, round| vertex(m, EPOCH + 1, round, vec![sentinel(EPOCH + 1)], vec![]);
    let judge = |v: &Vertex| v4_verdict(1_000, v, &ctx, |_| None);
    assert_eq!(
        judge(&at(&newcomer, FIRST + 7)),
        Verdict::PendingEpoch,
        "a next-epoch member"
    );
    assert!(
        invalid(judge(&at(&all[0], FIRST + 7))),
        "an active-only member"
    );
    assert!(
        invalid(judge(&at(&newcomer, FIRST))),
        "below the next epoch's first round"
    );
}

/// S4b's clauses, each alone: a zero-stake ref author, a digest that is not
/// hex, and one of the wrong length.
#[test]
fn every_ref_clause_refuses_on_its_own() {
    let all = members();
    let mut c = committee(&all);
    let claims = |authors: &[usize], digest: &dyn Fn(usize) -> String| -> Vertex {
        let refs: Vec<ParentRef> = authors
            .iter()
            .map(|&i| ParentRef {
                round: FIRST,
                author: all[i].info.address.clone(),
                digest: digest(i),
                proof: None,
                cert: None,
            })
            .collect();
        vertex(
            &all[0],
            EPOCH,
            FIRST + 1,
            refs.iter().map(|r| r.digest.clone()).collect(),
            refs,
        )
    };
    let hexed = |i: usize| format!("{:064x}", 7_000 + i);
    // Member 3 holds no stake; members 0..2 alone are the whole quorum.
    c.iter_mut().for_each(|m| {
        if m.address == all[3].info.address {
            m.stake = 0;
        }
    });
    assert!(
        !invalid(verdict(&claims(&[0, 1, 2], &hexed), &c)),
        "positive control"
    );
    assert!(
        invalid(verdict(&claims(&[0, 1, 2, 3], &hexed), &c)),
        "a zero-stake ref author"
    );
    let letter = |i: usize| format!("{}g", &format!("{:064x}", 7_000 + i)[1..]);
    assert!(
        invalid(verdict(&claims(&[0, 1, 2], &letter), &c)),
        "not hex"
    );
    let long = |i: usize| format!("{:065x}", 7_000 + i);
    assert!(
        invalid(verdict(&claims(&[0, 1, 2], &long), &c)),
        "65 characters"
    );
}

/// The parent count at the limit passes Layer S; one over is refused.
#[test]
fn exactly_max_parents_is_admissible() {
    let all = members();
    let with_members = |n: usize| -> (Vec<ValidatorInfo>, Vertex) {
        let mut c = committee(&all);
        for i in 0..n.saturating_sub(c.len()) {
            let mut m = c[0].clone();
            m.address = format!("{:064x}", 900_000 + i);
            c.push(m);
        }
        c.sort_by(|a, b| a.address.cmp(&b.address));
        let refs: Vec<ParentRef> = c
            .iter()
            .take(n)
            .enumerate()
            .map(|(i, m)| ParentRef {
                round: FIRST,
                author: m.address.clone(),
                digest: format!("{:064x}", 1_000_000 + i),
                proof: None,
                cert: None,
            })
            .collect();
        let v = vertex(
            &all[0],
            EPOCH,
            FIRST + 1,
            refs.iter().map(|r| r.digest.clone()).collect(),
            refs,
        );
        (c, v)
    };
    let (c, v) = with_members(MAX_PARENTS);
    assert!(
        matches!(verdict(&v, &c), Verdict::PendingCert(_)),
        "{:?}",
        verdict(&v, &c)
    );
    let (c, v) = with_members(MAX_PARENTS + 1);
    assert!(invalid(verdict(&v, &c)));
}

/// The certificate bitmap holds one bit per member, rounded up to whole
/// bytes: at eight members that is one byte, not two.
#[test]
fn the_bitmap_length_is_members_rounded_up_to_bytes() {
    let mut all: Vec<Member> = (1..=8u8).map(member).collect();
    all.sort_by(|a, b| a.info.address.cmp(&b.info.address));
    let c = committee(&all);
    let s = sentinel(EPOCH);
    let record = EpochRecord {
        epoch: EPOCH,
        first_round: FIRST,
        closing_round: None,
        sentinel: &s,
        committee: &c,
    };
    let parents: Vec<Vertex> = all[..7].iter().map(first_round).collect();
    let with_bitmap = |bytes: usize| {
        let mut refs: Vec<ParentRef> = parents.iter().map(|p| reference(p, None)).collect();
        refs[0].cert = Some(CompactCert {
            signer_bitmap: vec![0; bytes],
            aggregate_signature: vec![0; 96],
        });
        let digests = parents.iter().map(|p| p.hash.clone()).collect();
        vertex(&all[0], EPOCH, FIRST + 1, digests, refs)
    };
    assert_eq!(layer_s(&with_bitmap(1), &record, CHAIN, GENESIS), Ok(()));
    assert!(layer_s(&with_bitmap(2), &record, CHAIN, GENESIS).is_err());
}

/// B192: Layer S takes an evidence item only as the bytes an honest node
/// builds from its parts, and only up to `max_item_bytes` (an item passed on
/// its kind alone, at any size, its proofs carrying their payloads, and every
/// block verified it). The largest honest items are measured here: every
/// number at its widest, a full committee's bitmap.
#[test]
fn evidence_is_admitted_only_as_its_parts_build_it() {
    use crate::v4::evidence;
    use blockchain::attest::{AttestBody, VertexCertificate};
    let proof = |digit: char, payload: Vec<String>| Vertex {
        epoch: u64::MAX,
        round: u64::MAX,
        author: "a".repeat(64),
        parents: vec![],
        parent_refs: vec![],
        payload,
        timestamp: u64::MAX,
        hash: digit.to_string().repeat(64),
        signature: "c".repeat(128),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
    };
    let twin = evidence::twin_item(&proof('d', vec![]), &proof('e', vec![])).unwrap();
    assert_eq!(twin.len(), 1_426);
    let cert = |digit: char| VertexCertificate {
        version: u8::MAX,
        body: AttestBody {
            chain_id: CHAIN.into(),
            genesis_identity: GENESIS.into(),
            epoch: u64::MAX,
            round: u64::MAX,
            author: "a".repeat(64),
            digest: digit.to_string().repeat(64),
            committee_hash: "f".repeat(64),
        },
        signer_bitmap: vec![u8::MAX; blockchain::committee::MAX_COMMITTEE.div_ceil(8)],
        signed_stake: u64::MAX.into(),
        total_stake: u64::MAX.into(),
        aggregate_signature: vec![u8::MAX; 96],
    };
    let conflict = evidence::cert_conflict_item(&cert('d'), &cert('e')).unwrap();
    // 2,221 with 39-digit stakes and empty strings: 19 digits fewer on each
    // of four stakes, and each certificate's two strings.
    assert_eq!(
        conflict.len(),
        2_221 - 4 * 19 + 2 * (CHAIN.len() + GENESIS.len())
    );
    for item in [&twin, &conflict] {
        assert!(item.len() <= evidence::max_item_bytes(CHAIN, GENESIS));
        assert_eq!(evidence::admissible_item(item, CHAIN, GENESIS), Ok(()));
    }
    let refused = |item: &str| evidence::admissible_item(item, CHAIN, GENESIS).is_err();
    // The same parts in another encoding, order or form.
    assert!(refused(&format!(" {twin}")));
    assert!(refused(&twin.replacen(':', ": ", 1)));
    let (d, e) = (
        proof('d', vec![]).to_compact_proof_v4(),
        proof('e', vec![]).to_compact_proof_v4(),
    );
    let envelope = |a: &Vertex, b: &Vertex| evidence::twin_json(a, b).unwrap();
    assert_eq!(envelope(&d, &e), twin, "vacuous: the envelope differs");
    // B210: one encoding, the fields in their declared order (a `json!`
    // object's order follows serde_json's `preserve_order` feature).
    assert!(
        twin.starts_with(r#"{"kind":"equivocation_v4","offender":"#),
        "{twin}"
    );
    assert!(conflict.starts_with(r#"{"kind":"certificate_conflict","offender":"#));
    assert!(refused(&envelope(&e, &d)), "out of hash order");
    let (full_d, full_e) = (
        proof('d', vec!["x".repeat(100)]),
        proof('e', vec!["x".repeat(100)]),
    );
    // Refused as such, before a payload is hashed.
    let why = |item: &str| evidence::admissible_item(item, CHAIN, GENESIS).unwrap_err();
    let full = why(&envelope(&full_d, &full_e));
    assert!(full.contains("compact"), "proofs with payloads: {full}");
    let mut with_payload = d.clone();
    with_payload.payload = vec!["x".repeat(100)];
    let both = why(&envelope(&with_payload, &e));
    assert!(both.contains("compact"), "a root and a payload: {both}");
    // Bounded before it is parsed.
    let most = evidence::max_item_bytes(CHAIN, GENESIS);
    let huge = why(&format!("{twin}{}", " ".repeat(most)));
    assert!(huge.contains("over"), "{huge}");
    // The kind alone, or no ordered kind.
    assert!(refused(
        r#"{"kind":"equivocation_v4","offender":"x","epoch":2,"round":1}"#
    ));
    assert!(refused(&twin.replace(evidence::KIND, "downtime")));
    // Layer S refuses the vertex that carries one, and takes the honest one.
    let carrying = |item: &str| {
        let mut v = proof('d', vec![]);
        v.payload = vec![format!("{}{item}", crate::dag::SLASH_EVIDENCE_PREFIX)];
        payload_admissible(&v, CHAIN, GENESIS)
    };
    assert_eq!(carrying(&twin), Ok(()));
    assert_eq!(carrying(&conflict), Ok(()));
    assert!(carrying(&format!(" {twin}")).is_err());
    assert!(carrying(&envelope(&full_d, &full_e)).is_err());
    // No more items than a block takes from one vertex.
    let digits: Vec<char> = "0123456789ab".chars().collect();
    let items: Vec<String> = digits
        .chunks(2)
        .map(|p| {
            let item = evidence::twin_item(&proof(p[0], vec![]), &proof(p[1], vec![])).unwrap();
            format!("{}{item}", crate::dag::SLASH_EVIDENCE_PREFIX)
        })
        .collect();
    assert_eq!(items.len(), crate::dag::MAX_EVIDENCE_PER_VERTEX + 1);
    let mut v = proof('d', vec![]);
    v.payload = items[1..].to_vec();
    assert_eq!(payload_admissible(&v, CHAIN, GENESIS), Ok(()));
    v.payload = items;
    assert!(payload_admissible(&v, CHAIN, GENESIS).is_err());
}
