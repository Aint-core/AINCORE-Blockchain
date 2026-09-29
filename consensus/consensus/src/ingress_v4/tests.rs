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
            bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
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
        payload: vec!["tx".into()],
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
        previous: Some(record(0)),
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
    assert!(invalid(verdict(&v, &c)));
}

#[test]
fn a_certificate_of_another_epoch_leaves_the_vertex_pending() {
    let all = members();
    let c = committee(&all);
    let (mut v, parents) = second_round(&all, 3, &[0, 1, 2]);
    // Genuine signatures, for the same slot in the previous epoch.
    v.parent_refs[1].cert = Some(certify(&all, &parents[1], EPOCH - 1, &[0, 1, 2]));
    assert_eq!(verdict(&v, &c), Verdict::PendingCert(vec![1]));
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
    b.payload = vec!["other".into()];
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
    let (parents, refs) = claims(ABSOLUTE_ROUND_CEILING, 3);
    let v = vertex(&all[0], EPOCH, ABSOLUTE_ROUND_CEILING + 1, parents, refs);
    assert!(refused(&v), "over the ceiling: {:?}", verdict(&v, &c));
    let (parents, refs) = claims(ABSOLUTE_ROUND_CEILING - 1, 3);
    let v = vertex(&all[0], EPOCH, ABSOLUTE_ROUND_CEILING, parents, refs);
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
        previous: None,
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
            previous: None,
            next: None,
            now_secs: now,
            gc_floor: floor,
            cursor,
        };
        v4_verdict(1_000, v, &ctx, |_| None)
    };
    assert_eq!(at(NOW, 0, FIRST, &v), Verdict::Stage);
    assert!(
        matches!(at(v.timestamp - 31, 0, FIRST, &v), Verdict::Drop(_)),
        "the clock"
    );
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

#[test]
fn layer_s_verdicts_do_not_depend_on_the_context() {
    let all = members();
    let c = committee(&all);
    let sentinel = sentinel(EPOCH);
    let mut bad = first_round(&all[0]);
    bad.timestamp += 1;
    for (now, floor, cursor) in [(0, 0, 0), (NOW, u64::MAX, u64::MAX), (u64::MAX, 5, FIRST)] {
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
            previous: None,
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
    previous: bool,
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
        previous: previous.then(|| record(0)),
        next: next.then(|| record(2)),
        now_secs: NOW,
        gc_floor: 0,
        cursor: FIRST,
    }
}

/// MEDIUM-1: a vertex of an adjacent epoch is authenticated under that
/// epoch's record before it is kept; without the record it is dropped.
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
    let judge = |v: &Vertex, previous, next| {
        v4_verdict(1_000, v, &context(&c, &sentinels, previous, next), |_| None)
    };
    assert_eq!(judge(&at(EPOCH + 1), true, true), Verdict::PendingEpoch);
    assert!(
        invalid(judge(&forged(EPOCH + 1), true, true)),
        "a forged next-epoch vertex"
    );
    assert!(
        matches!(judge(&at(EPOCH + 1), true, false), Verdict::Drop(_)),
        "no next record"
    );
    assert_eq!(judge(&at(EPOCH - 1), true, true), Verdict::Stale);
    assert!(
        invalid(judge(&forged(EPOCH - 1), true, true)),
        "a forged old-epoch vertex"
    );
    assert!(
        matches!(judge(&at(EPOCH - 1), false, true), Verdict::Drop(_)),
        "no previous record"
    );
    assert!(matches!(
        judge(&at(EPOCH + 2), true, true),
        Verdict::Drop(_)
    ));
    assert!(matches!(
        judge(&at(EPOCH - 2), true, true),
        Verdict::Drop(_)
    ));
    // The active epoch at the edge of u64: no overflow, no panic.
    let edge = [sentinel(EPOCH - 1), sentinel(EPOCH), sentinel(EPOCH + 1)];
    let mut ctx = context(&c, &edge, false, false);
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
    let mut ctx = context(&c, &sentinels, true, true);
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
    let mut ctx = context(&c, &sentinels, true, true);
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
    let mut ctx = context(&active, &sentinels, true, true);
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
