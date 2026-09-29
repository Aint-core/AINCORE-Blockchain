//! G1 S3 acceptance (`docs/G1_CONSENSUS_CONTRACT.md`, "Staged implementation
//! plan", S3): twins staged equally in every arrival order, restart-stable,
//! the third twin evidence only, the certified reservation, the plain-body
//! budget, and atomicity under a crash mid-stage.

use super::*;
use crate::ingress_v4::EpochRecord;
use crate::qc::{self, derive_validator_bls_seed, ValidatorInfo};
use crate::vcert::{AttestBody, CertCollector, CollectOutcome, VertexAttestation};
use crypto::bls::BLSEngine;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const CHAIN: &str = "AINCORE-S3-TEST";
const GENESIS: &str = "genesis-identity-s3-test";
const EPOCH: u64 = 1;
const FIRST: u64 = 100;

struct Member {
    node_key: [u8; 32],
    info: ValidatorInfo,
}

fn members() -> Vec<Member> {
    let mut m: Vec<Member> = (1..=4u8)
        .map(|seed| {
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
        })
        .collect();
    m.sort_by(|a, b| a.info.address.cmp(&b.info.address));
    m
}

fn committee(m: &[Member]) -> Vec<ValidatorInfo> {
    m.iter().map(|m| m.info.clone()).collect()
}

fn sentinel() -> String {
    blockchain::epoch_genesis(CHAIN, GENESIS, EPOCH, FIRST, "b", "a")
}

/// A first-round vertex by `m`; `tag` makes twins.
fn twin(m: &Member, round: u64, tag: &str) -> Vertex {
    let mut v = Vertex {
        epoch: EPOCH,
        round,
        author: m.info.address.clone(),
        parents: vec![sentinel()],
        parent_refs: vec![],
        payload: vec![tag.to_string()],
        timestamp: 1_000,
        hash: String::new(),
        signature: String::new(),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
    };
    v.hash = v.hash_v4_with_domain(CHAIN, GENESIS);
    v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&m.node_key));
    v
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "aincore-s3-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
    fn open(&self) -> StateDB {
        StateDB::open(self.0.to_str().unwrap()).unwrap()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn slot(db: &StateDB, v: &Vertex) -> Vec<SlotEntry> {
    read_slot(db, &vslot_key(v.epoch, v.round, &v.author)).unwrap()
}

fn digests(db: &StateDB, v: &Vertex) -> Vec<String> {
    let mut d: Vec<String> = slot(db, v).into_iter().map(|e| e.digest).collect();
    d.sort();
    d
}

fn body_held(db: &StateDB, v: &Vertex) -> bool {
    db.get(&format!("vertex:{}", v.hash)).unwrap().is_some()
}

fn plain(db: &StateDB, v: &Vertex) -> u64 {
    read_bytes(db, &vbytes_key(v.epoch, &v.author)).unwrap()
}

fn record<'a>(committee: &'a [ValidatorInfo], sentinel: &'a str) -> EpochRecord<'a> {
    EpochRecord {
        epoch: EPOCH,
        first_round: FIRST,
        closing_round: None,
        sentinel,
        committee,
    }
}

#[test]
fn twins_are_staged_equally_whatever_the_arrival_order() {
    let all = members();
    let (a, b) = (twin(&all[0], FIRST, "a"), twin(&all[0], FIRST, "b"));
    let mut seen = Vec::new();
    for order in [[&a, &b], [&b, &a]] {
        let dir = TempDb::new("twins");
        let db = dir.open();
        for v in order {
            assert_eq!(
                stage(&db, v, Role::Staged, None, B_AUTH),
                Ok(StageOutcome::Staged)
            );
        }
        assert!(body_held(&db, &a) && body_held(&db, &b));
        seen.push(digests(&db, &a));
        // A repeat is a no-op.
        assert_eq!(
            stage(&db, &a, Role::Staged, None, B_AUTH),
            Ok(StageOutcome::Held)
        );
    }
    assert_eq!(seen[0], seen[1], "the same slot in both orders");
    assert_eq!(seen[0].len(), 2);
}

#[test]
fn a_restarted_store_loads_both_twins() {
    let all = members();
    let c = committee(&all);
    let s = sentinel();
    let (a, b) = (twin(&all[0], FIRST, "a"), twin(&all[0], FIRST, "b"));
    let other = twin(&all[1], FIRST, "x");
    let mut loaded = Vec::new();
    for order in [[&a, &b, &other], [&other, &b, &a]] {
        let dir = TempDb::new("restart");
        {
            let db = dir.open();
            for v in order {
                stage(&db, v, Role::Staged, None, B_AUTH).unwrap();
            }
        }
        let got = load(&dir.open(), &record(&c, &s), CHAIN, GENESIS, 0).unwrap();
        let mut hashes: Vec<String> = got.bodies.iter().map(|(_, v)| v.hash.clone()).collect();
        hashes.sort();
        assert!(got.refused.is_empty());
        loaded.push(hashes);
    }
    assert_eq!(
        loaded[0], loaded[1],
        "load does not depend on arrival order"
    );
    assert_eq!(
        loaded[0].len(),
        3,
        "both twins, and the other author's vertex"
    );
}

#[test]
fn a_third_twin_is_evidence_only() {
    let all = members();
    let dir = TempDb::new("third");
    let db = dir.open();
    let [a, b, c] = ["a", "b", "c"].map(|t| twin(&all[0], FIRST, t));
    stage(&db, &a, Role::Staged, None, B_AUTH).unwrap();
    stage(&db, &b, Role::Staged, None, B_AUTH).unwrap();
    assert!(matches!(
        stage(&db, &c, Role::Staged, None, B_AUTH),
        Ok(StageOutcome::EvidenceOnly(_))
    ));
    assert!(!body_held(&db, &c), "no body stored");
    assert_eq!(slot(&db, &a).len(), 2);
}

/// The 3-twin witness: a certified third twin evicts a plain member, never
/// the self-attested one, and is always installable.
#[test]
fn a_certified_third_twin_evicts_a_plain_member() {
    let all = members();
    let [a, b, c] = ["a", "b", "c"].map(|t| twin(&all[0], FIRST, t));
    // A self-attested and B plain: B goes.
    let dir = TempDb::new("evict-self");
    let db = dir.open();
    stage(&db, &a, Role::SelfAttested, None, B_AUTH).unwrap();
    stage(&db, &b, Role::Staged, None, B_AUTH).unwrap();
    assert_eq!(
        stage(&db, &c, Role::Staged, Some(&c.hash), B_AUTH),
        Ok(StageOutcome::Evicted(b.hash.clone()))
    );
    assert!(body_held(&db, &a) && body_held(&db, &c) && !body_held(&db, &b));
    let roles: Vec<Role> = slot(&db, &a).into_iter().map(|e| e.role).collect();
    assert_eq!(roles, vec![Role::SelfAttested, Role::Certified]);
    assert_eq!(
        plain(&db, &a),
        0,
        "the evicted plain body's bytes are released"
    );
    // Two plain members: the greater digest goes, the same every time.
    let dir = TempDb::new("evict-plain");
    let db = dir.open();
    stage(&db, &a, Role::Staged, None, B_AUTH).unwrap();
    stage(&db, &b, Role::Staged, None, B_AUTH).unwrap();
    let greater = a.hash.clone().max(b.hash.clone());
    assert_eq!(
        stage(&db, &c, Role::Staged, Some(&c.hash), B_AUTH),
        Ok(StageOutcome::Evicted(greater))
    );
}

#[test]
fn the_certified_digest_is_installable_in_every_arrival_order() {
    let all = members();
    let [a, b, c] = ["a", "b", "c"].map(|t| twin(&all[0], FIRST, t));
    let orders = [
        [&a, &b, &c],
        [&a, &c, &b],
        [&b, &a, &c],
        [&b, &c, &a],
        [&c, &a, &b],
        [&c, &b, &a],
    ];
    for order in orders {
        let dir = TempDb::new("orders");
        let db = dir.open();
        for v in order {
            stage(&db, v, Role::Staged, Some(&c.hash), B_AUTH).unwrap();
        }
        let s = slot(&db, &c);
        assert!(
            s.iter()
                .any(|e| e.digest == c.hash && e.role == Role::Certified),
            "{:?}",
            s
        );
        assert!(s.len() <= MAX_STAGED_PER_SLOT && body_held(&db, &c));
    }
}

#[test]
fn a_second_certified_digest_is_evidence_only() {
    let all = members();
    let [a, b, c] = ["a", "b", "c"].map(|t| twin(&all[0], FIRST, t));
    let dir = TempDb::new("two-certs");
    let db = dir.open();
    stage(&db, &a, Role::Staged, Some(&a.hash), B_AUTH).unwrap();
    stage(&db, &b, Role::Staged, None, B_AUTH).unwrap();
    assert!(matches!(
        stage(&db, &c, Role::Staged, Some(&c.hash), B_AUTH),
        Ok(StageOutcome::EvidenceOnly(_))
    ));
    assert!(!body_held(&db, &c));
}

#[test]
fn the_plain_body_budget_spares_certified_and_self_bodies() {
    let all = members();
    let m = &all[0];
    let v1 = twin(m, FIRST, "a");
    let size = serde_json::to_string(&v1).unwrap().len() as u64;
    let budget = size + size / 2;
    let dir = TempDb::new("budget");
    let db = dir.open();
    assert_eq!(
        stage(&db, &v1, Role::Staged, None, budget),
        Ok(StageOutcome::Staged)
    );
    let v2 = twin(m, FIRST + 1, "a");
    assert!(matches!(
        stage(&db, &v2, Role::Staged, None, budget),
        Ok(StageOutcome::EvidenceOnly(_))
    ));
    assert!(!body_held(&db, &v2));
    // Certified and self-attested bodies do not count.
    let v3 = twin(m, FIRST + 2, "a");
    let v4 = twin(m, FIRST + 3, "a");
    assert_eq!(
        stage(&db, &v3, Role::Staged, Some(&v3.hash), budget),
        Ok(StageOutcome::Staged)
    );
    assert_eq!(
        stage(&db, &v4, Role::SelfAttested, None, budget),
        Ok(StageOutcome::Staged)
    );
    // Another author has its own budget.
    let other = twin(&all[1], FIRST + 1, "a");
    assert_eq!(
        stage(&db, &other, Role::Staged, None, budget),
        Ok(StageOutcome::Staged)
    );
    // A plain body later certified frees its bytes.
    assert_eq!(plain(&db, &v1), size);
    assert_eq!(
        stage(&db, &v1, Role::Staged, Some(&v1.hash), budget),
        Ok(StageOutcome::Held)
    );
    assert_eq!(plain(&db, &v1), 0);
    assert_eq!(slot(&db, &v1)[0].role, Role::Certified);
    assert_eq!(
        stage(&db, &v2, Role::Staged, None, budget),
        Ok(StageOutcome::Staged)
    );
}

#[test]
fn boot_reruns_layer_s_and_respects_the_floor() {
    let all = members();
    let c = committee(&all);
    let s = sentinel();
    let dir = TempDb::new("boot");
    let low = twin(&all[0], FIRST, "low");
    let high = twin(&all[1], FIRST + 60, "high");
    let tampered = twin(&all[2], FIRST + 60, "t");
    {
        let db = dir.open();
        for v in [&low, &high, &tampered] {
            // Staged directly (the rounds are not all first rounds, so a real
            // node would not have admitted `high`; the load re-checks anyway).
            stage(&db, v, Role::Staged, None, B_AUTH).unwrap();
        }
        let mut body = tampered.clone();
        body.payload = vec!["changed".into()];
        db.put(
            &format!("vertex:{}", tampered.hash),
            &serde_json::to_string(&body).unwrap(),
        )
        .unwrap();
    }
    let db = dir.open();
    let got = load(&db, &record(&c, &s), CHAIN, GENESIS, 0).unwrap();
    let hashes: Vec<&str> = got.bodies.iter().map(|(_, v)| v.hash.as_str()).collect();
    assert!(hashes.contains(&low.hash.as_str()));
    assert!(
        got.refused.contains(&tampered.hash),
        "a body that no longer hashes"
    );
    assert!(
        got.refused.contains(&high.hash),
        "Layer S: not a first round, no sentinel rule"
    );
    // Rounds at or below g − RETAIN_SLACK are not loaded.
    let floor = FIRST + RETAIN_SLACK + 1;
    let got = load(&db, &record(&c, &s), CHAIN, GENESIS, floor).unwrap();
    assert!(got
        .bodies
        .iter()
        .all(|(_, v)| v.round >= floor - RETAIN_SLACK));
    assert!(!got.bodies.iter().any(|(_, v)| v.hash == low.hash));
}

fn certificate(all: &[Member], v: &Vertex, epoch: u64) -> VertexCertificate {
    let c = committee(all);
    let body = AttestBody {
        chain_id: CHAIN.into(),
        genesis_identity: GENESIS.into(),
        epoch,
        round: v.round,
        author: v.author.clone(),
        digest: v.hash.clone(),
        committee_hash: qc::validator_set_hash(&c),
    };
    let mut collector = CertCollector::new(body.clone(), &c).unwrap();
    let mut out = None;
    for m in &all[..3] {
        let att = VertexAttestation {
            body: body.clone(),
            signer: m.info.address.clone(),
            signature: BLSEngine::consensus().sign_raw(
                &body.signing_bytes(),
                &derive_validator_bls_seed(&m.node_key),
            ),
        };
        if let CollectOutcome::Certified(cert) = collector.add(&att).unwrap() {
            out = Some(*cert);
        }
    }
    out.unwrap()
}

#[test]
fn boot_loads_only_certificates_that_verify() {
    let all = members();
    let c = committee(&all);
    let s = sentinel();
    let v = twin(&all[0], FIRST, "a");
    let w = twin(&all[1], FIRST, "b");
    let dir = TempDb::new("certs");
    let db = dir.open();
    let good = certificate(&all, &v, EPOCH);
    let other_epoch = certificate(&all, &w, EPOCH + 1);
    for (cert, x) in [(&good, &v), (&other_epoch, &w)] {
        db.put(
            &vcert_key(EPOCH, x.round, &x.author),
            &serde_json::to_string(cert).unwrap(),
        )
        .unwrap();
    }
    let got = load(&db, &record(&c, &s), CHAIN, GENESIS, 0).unwrap();
    assert_eq!(got.certs, vec![good]);
}

const CHILD_DB: &str = "AINCORE_TEST_STAGING_DB";

/// Subprocess body for the crash test: stage one vertex. A no-op unless the
/// parent sets `AINCORE_TEST_STAGING_DB`.
#[test]
fn staging_crash_child() {
    let Ok(path) = std::env::var(CHILD_DB) else {
        return;
    };
    let all = members();
    let db = StateDB::open(&path).unwrap();
    stage(&db, &twin(&all[0], FIRST, "a"), Role::Staged, None, B_AUTH).unwrap();
}

/// RC-2: a crash after every write of a stage, before its commit, leaves
/// neither the body nor the slot entry nor the budget; a clean run leaves all
/// three.
#[test]
fn a_crash_mid_stage_leaves_nothing_behind() {
    let all = members();
    let v = twin(&all[0], FIRST, "a");
    for crash in [false, true] {
        let dir = TempDb::new("crash");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "staging::tests::staging_crash_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_DB, &dir.0)
            .env_remove("AINCORE_TEST_STAGING_CRASH");
        if crash {
            command.env("AINCORE_TEST_STAGING_CRASH", "1");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(if crash { 77 } else { 0 }));
        let db = dir.open();
        let held = [
            body_held(&db, &v),
            !slot(&db, &v).is_empty(),
            plain(&db, &v) > 0,
        ];
        assert_eq!(held, [!crash; 3], "crash {crash}: {held:?}");
    }
}

#[test]
fn the_pending_buffer_evicts_the_highest_round() {
    let all = members();
    let mut buffer = PendingBuffer::default();
    for r in 0..PENDING_MAX_PER_AUTHOR as u64 {
        assert!(buffer.push(twin(&all[0], FIRST + r, "p")).is_none());
    }
    let evicted = buffer.push(twin(&all[0], FIRST - 1, "p")).unwrap();
    assert_eq!(evicted.round, FIRST + PENDING_MAX_PER_AUTHOR as u64 - 1);
    let high = buffer.push(twin(&all[0], FIRST + 999, "p")).unwrap();
    assert_eq!(
        high.round,
        FIRST + 999,
        "the newcomer itself when it is highest"
    );
    assert_eq!(buffer.len(), PENDING_MAX_PER_AUTHOR);
    // Another author has its own bound.
    assert!(buffer.push(twin(&all[1], FIRST, "p")).is_none());
    let low = twin(&all[0], FIRST - 1, "p");
    assert!(buffer
        .remove(&all[0].info.address, low.round, &low.hash)
        .is_some());
}

/// S2 review 2: the stored body is canonical, without transport fields, so
/// the first copy to arrive cannot pad what is stored and served.
#[test]
fn the_stored_body_carries_no_transport_fields() {
    let all = members();
    let mut v = twin(&all[0], FIRST + 1, "a");
    v.parent_refs = vec![blockchain::ParentRef {
        round: FIRST,
        author: all[1].info.address.clone(),
        digest: "1".repeat(64),
        proof: blockchain::ParentRef::authenticated(
            &twin(&all[1], FIRST, "p"),
            all[1].info.ed25519_public_key.clone(),
        )
        .proof,
        cert: Some(blockchain::CompactCert {
            signer_bitmap: vec![7],
            aggregate_signature: vec![9; 96],
        }),
    }];
    let dir = TempDb::new("canonical");
    let db = dir.open();
    stage(&db, &v, Role::Staged, None, B_AUTH).unwrap();
    let stored: Vertex =
        serde_json::from_str(&db.get(&format!("vertex:{}", v.hash)).unwrap().unwrap()).unwrap();
    assert_eq!(stored.parent_refs.len(), 1);
    assert_eq!(stored.parent_refs[0].cert, None);
    assert!(stored.parent_refs[0].proof.is_none());
    assert_eq!(stored.parent_refs[0].digest, v.parent_refs[0].digest);
}

/// Writes `v`'s body and a slot row naming `digest` under `epoch`, bypassing
/// `stage`: what a corrupted or tampered store could hold.
fn plant(db: &StateDB, epoch: u64, digest: &str, v: &Vertex) {
    let row = vec![SlotEntry {
        digest: digest.to_string(),
        role: Role::Staged,
        bytes: 1,
    }];
    db.put(
        &vslot_key(epoch, v.round, &v.author),
        &serde_json::to_string(&row).unwrap(),
    )
    .unwrap();
    db.put(
        &format!("vertex:{digest}"),
        &serde_json::to_string(v).unwrap(),
    )
    .unwrap();
}

/// S3/S4 review L-1: boot loads rounds strictly above g − RETAIN_SLACK, and
/// every round while that is negative.
#[test]
fn boot_loads_exactly_the_rounds_above_g_minus_slack() {
    let all = members();
    let c = committee(&all);
    let s = sentinel();
    let dir = TempDb::new("boundary");
    let v = twin(&all[0], FIRST, "edge");
    {
        let db = dir.open();
        stage(&db, &v, Role::Staged, None, B_AUTH).unwrap();
    }
    let db = dir.open();
    let loaded = |g| {
        load(&db, &record(&c, &s), CHAIN, GENESIS, g)
            .unwrap()
            .bodies
            .iter()
            .any(|(_, b)| b.hash == v.hash)
    };
    assert!(loaded(0));
    assert!(loaded(RETAIN_SLACK - 1));
    assert!(
        loaded(FIRST - 1 + RETAIN_SLACK),
        "round g − RETAIN_SLACK + 1"
    );
    assert!(!loaded(FIRST + RETAIN_SLACK), "round g − RETAIN_SLACK");
}

/// S3/S4 review L-2: boot re-runs S1 and S2 too. A compact-form body under a
/// real digest hashes, but its payload is not the one signed for.
#[test]
fn boot_refuses_a_proof_form_body() {
    let all = members();
    let c = committee(&all);
    let s = sentinel();
    let dir = TempDb::new("proofform");
    let v = twin(&all[0], FIRST, "real");
    let mut w = v.clone();
    w.payload_root = Some(v.payload_root());
    w.payload = vec!["FOREIGN".to_string()];
    assert_eq!(w.hash_v4_with_domain(CHAIN, GENESIS), v.hash);
    let db = dir.open();
    plant(&db, EPOCH, &v.hash, &w);
    let got = load(&db, &record(&c, &s), CHAIN, GENESIS, 0).unwrap();
    assert!(got.bodies.is_empty());
    assert_eq!(got.refused, vec![v.hash.clone()]);
}

#[test]
fn boot_refuses_an_oversized_body() {
    let all = members();
    let c = committee(&all);
    let s = sentinel();
    let dir = TempDb::new("oversize");
    let big = twin(&all[0], FIRST, &"x".repeat(crate::dag::MAX_VERTEX_BYTES));
    let db = dir.open();
    plant(&db, EPOCH, &big.hash, &big);
    let got = load(&db, &record(&c, &s), CHAIN, GENESIS, 0).unwrap();
    assert!(got.bodies.is_empty());
    assert_eq!(got.refused, vec![big.hash.clone()]);
}

/// A slot entry is loaded only with the body its digest names, of the
/// record's epoch, even when the body under that key is itself valid.
#[test]
fn boot_refuses_a_body_under_another_digest_or_epoch() {
    let all = members();
    let c = committee(&all);
    let s = sentinel();
    let dir = TempDb::new("foreign");
    let db = dir.open();
    let v = twin(&all[0], FIRST, "named");
    let w = twin(&all[0], FIRST, "other");
    plant(&db, EPOCH, &v.hash, &w);
    let got = load(&db, &record(&c, &s), CHAIN, GENESIS, 0).unwrap();
    assert!(got.bodies.is_empty(), "the body of another digest");
    // An epoch-2 vertex that cites epoch 1's sentinel passes Layer S under
    // epoch 1's record; only the epoch check keeps it out of that epoch.
    let mut e2 = twin(&all[1], FIRST, "e2");
    e2.epoch = EPOCH + 1;
    e2.hash = e2.hash_v4_with_domain(CHAIN, GENESIS);
    e2.sign_with_ed25519(&crypto::SigningKey::from_bytes(&all[1].node_key));
    assert!(crate::ingress_v4::layer_s(&e2, &record(&c, &s), CHAIN, GENESIS).is_ok());
    plant(&db, EPOCH, &e2.hash, &e2);
    let got = load(&db, &record(&c, &s), CHAIN, GENESIS, 0).unwrap();
    assert!(got.bodies.is_empty(), "a body of another epoch");
    assert_eq!(got.refused.len(), 2);
}

/// A held body is never demoted: re-staging a certified body as plain leaves
/// it certified, so it stays unevictable and off the budget.
#[test]
fn a_held_body_is_never_demoted() {
    let all = members();
    let v = twin(&all[0], FIRST, "a");
    let dir = TempDb::new("demote");
    let db = dir.open();
    stage(&db, &v, Role::Staged, Some(&v.hash), B_AUTH).unwrap();
    assert_eq!(
        stage(&db, &v, Role::Staged, None, B_AUTH),
        Ok(StageOutcome::Held)
    );
    assert_eq!(slot(&db, &v)[0].role, Role::Certified);
    assert_eq!(plain(&db, &v), 0);
}

#[test]
fn a_body_that_exactly_fits_the_budget_is_staged() {
    let all = members();
    let v = twin(&all[0], FIRST, "a");
    let size = serde_json::to_string(&v).unwrap().len() as u64;
    let dir = TempDb::new("exact");
    let db = dir.open();
    assert_eq!(
        stage(&db, &v, Role::Staged, None, size),
        Ok(StageOutcome::Staged)
    );
    assert_eq!(plain(&db, &v), size);
}

/// ST-3: the plain-body budget is per author AND epoch.
#[test]
fn each_epoch_has_its_own_plain_body_budget() {
    let all = members();
    let m = &all[0];
    let v1 = twin(m, FIRST, "a");
    let size = serde_json::to_string(&v1).unwrap().len() as u64;
    let budget = size + size / 2;
    let dir = TempDb::new("epoch_budget");
    let db = dir.open();
    stage(&db, &v1, Role::Staged, None, budget).unwrap();
    assert!(matches!(
        stage(&db, &twin(m, FIRST + 1, "a"), Role::Staged, None, budget),
        Ok(StageOutcome::EvidenceOnly(_))
    ));
    let mut e2 = twin(m, FIRST + 1, "a");
    e2.epoch = EPOCH + 1;
    e2.hash = e2.hash_v4_with_domain(CHAIN, GENESIS);
    assert_eq!(
        stage(&db, &e2, Role::Staged, None, budget),
        Ok(StageOutcome::Staged)
    );
}

/// S3/S4 review L-5: a body this node attests must be held (AT-3), so
/// attesting a third digest for a full slot is an error, and writes nothing.
#[test]
fn attesting_a_third_digest_for_a_full_slot_is_an_error() {
    let all = members();
    let (a, b, c) = (
        twin(&all[0], FIRST, "a"),
        twin(&all[0], FIRST, "b"),
        twin(&all[0], FIRST, "c"),
    );
    let dir = TempDb::new("self_third");
    let db = dir.open();
    stage(&db, &a, Role::Staged, None, B_AUTH).unwrap();
    stage(&db, &b, Role::Staged, None, B_AUTH).unwrap();
    let before = plain(&db, &a);
    assert!(stage(&db, &c, Role::SelfAttested, None, B_AUTH).is_err());
    assert!(!body_held(&db, &c));
    assert_eq!(digests(&db, &a).len(), 2);
    assert_eq!(plain(&db, &a), before);
}

/// Of two pending vertices at the top round, the greater digest goes: the
/// same choice whatever order they arrived in.
#[test]
fn the_pending_buffer_breaks_a_top_round_tie_by_digest() {
    let all = members();
    let top = FIRST + 500;
    let (x, y) = (twin(&all[0], top, "x"), twin(&all[0], top, "y"));
    let greater = x.hash.clone().max(y.hash.clone());
    for order in [[&x, &y], [&y, &x]] {
        let mut buffer = PendingBuffer::default();
        for r in 0..PENDING_MAX_PER_AUTHOR as u64 - 1 {
            assert!(buffer.push(twin(&all[0], FIRST + r, "p")).is_none());
        }
        assert!(buffer.push(order[0].clone()).is_none());
        assert_eq!(buffer.push(order[1].clone()).unwrap().hash, greater);
    }
}
