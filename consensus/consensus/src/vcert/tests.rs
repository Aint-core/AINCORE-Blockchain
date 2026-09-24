//! G1 S1 acceptance, one test per criterion in `docs/G1_CONSENSUS_CONTRACT.md`
//! ("Staged implementation plan", S1). Every test that asserts a refusal also
//! asserts the matching acceptance, so none of them can pass by refusing
//! everything.

use super::*;
use crate::qc::FinalityVote;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

const CHAIN: &str = "AINCORE-VCERT-TEST";
const GENESIS: &str = "genesis-identity-vcert-test";
const STAKE: u64 = 100;

// ── fixtures ────────────────────────────────────────────────────────────────

struct Member {
    node_key: [u8; 32],
    info: ValidatorInfo,
}

fn member(seed: u8, stake: u64) -> Member {
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
            stake,
            ed25519_public_key: hex::encode(ed),
            bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
        },
    }
}

/// Four equal-stake members, returned in canonical (address) order so an index
/// here is an index into the signer bitmap. Quorum is 3 of 4.
fn committee4() -> Vec<Member> {
    let mut m: Vec<Member> = (1..=4u8).map(|s| member(s, STAKE)).collect();
    m.sort_by(|a, b| a.info.address.cmp(&b.info.address));
    m
}

fn infos(members: &[Member]) -> Vec<ValidatorInfo> {
    members.iter().map(|m| m.info.clone()).collect()
}

fn body(
    committee: &[ValidatorInfo],
    epoch: u64,
    round: u64,
    author: &str,
    digest: &str,
) -> AttestBody {
    AttestBody {
        chain_id: CHAIN.into(),
        genesis_identity: GENESIS.into(),
        epoch,
        round,
        author: author.into(),
        digest: digest.into(),
        committee_hash: qc::validator_set_hash(committee),
    }
}

/// A Byzantine attester: signs whatever it is shown, with no guard.
fn byzantine_attest(m: &Member, b: &AttestBody) -> VertexAttestation {
    VertexAttestation {
        body: b.clone(),
        signer: m.info.address.clone(),
        signature: BLSEngine::consensus()
            .sign_raw(&b.signing_bytes(), &derive_validator_bls_seed(&m.node_key)),
    }
}

static DB_SEQ: AtomicUsize = AtomicUsize::new(0);

struct TempDb(PathBuf);

impl TempDb {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "aincore-vcert-{tag}-{}-{}",
            std::process::id(),
            DB_SEQ.fetch_add(1, Ordering::Relaxed)
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

fn digest(c: char) -> String {
    std::iter::repeat_n(c, 64).collect()
}

/// Build a genuine certificate from the given signer indices.
fn certify(members: &[Member], b: &AttestBody, signers: &[usize]) -> VertexCertificate {
    let committee = infos(members);
    let mut collector = CertCollector::new(b.clone(), &committee).unwrap();
    let mut out = None;
    for &i in signers {
        if let CollectOutcome::Certified(c) =
            collector.add(&byzantine_attest(&members[i], b)).unwrap()
        {
            out = Some(*c);
        }
    }
    out.expect("signers did not reach quorum")
}

// ── 1. domain separation ────────────────────────────────────────────────────

#[test]
fn attestation_bytes_never_cross_verify_with_a_finality_vote() {
    let members = committee4();
    let committee = infos(&members);
    let b = body(&committee, 0, 2, &members[0].info.address, &digest('a'));
    let vote = FinalityVote {
        chain_id: CHAIN.into(),
        epoch: 0,
        finalized_round: 2,
        anchor_round: 2,
        anchor_hash: digest('a'),
        block_height: 1,
        block_hash: digest('a'),
        state_root: digest('a'),
        receipts_root: digest('a'),
        finality_digest: digest('a'),
        validator_set_hash: qc::validator_set_hash(&committee),
    };
    let attest_bytes = b.signing_bytes();
    let vote_bytes = vote.to_signing_bytes();
    let vote_domain = &vote_bytes[..ATTEST_DOMAIN.len()];

    // Equal length and a differing prefix: the two families of signing bytes are
    // disjoint for EVERY input, not just this one.
    assert_eq!(ATTEST_DOMAIN.len(), 24);
    assert!(attest_bytes.starts_with(ATTEST_DOMAIN));
    assert_ne!(
        vote_domain, ATTEST_DOMAIN,
        "attestations and finality votes share a domain: a crafted body of one could be the bytes of the other"
    );

    let bls = BLSEngine::consensus();
    let seed = derive_validator_bls_seed(&members[0].node_key);
    let pk = hex::decode(&members[0].info.bls_public_key).unwrap();
    let on_attest = bls.sign_raw(&attest_bytes, &seed);
    let on_vote = bls.sign_raw(&vote_bytes, &seed);
    // Positive controls: each signature verifies over its own bytes.
    assert!(bls.verify(&attest_bytes, &on_attest, &pk).unwrap());
    assert!(bls.verify(&vote_bytes, &on_vote, &pk).unwrap());
    assert!(!bls.verify(&vote_bytes, &on_attest, &pk).unwrap_or(false));
    assert!(!bls.verify(&attest_bytes, &on_vote, &pk).unwrap_or(false));
}

// ── 2. the verifier ─────────────────────────────────────────────────────────

#[test]
fn verifier_rejects_wrong_chain_genesis_committee_epoch_stake_or_bitmap() {
    let members = committee4();
    let committee = infos(&members);
    let b = body(&committee, 3, 8, &members[1].info.address, &digest('a'));
    let good = certify(&members, &b, &[0, 1, 2]);
    let verify = |c: &VertexCertificate, com: &[ValidatorInfo], chain: &str, gen: &str, e: u64| {
        verify_vertex_cert(c, com, chain, gen, e)
    };

    // Positive control: the untouched certificate verifies, and so does its
    // compact round trip.
    assert_eq!(verify(&good, &committee, CHAIN, GENESIS, 3), Ok(()));
    let rebuilt = VertexCertificate::from_compact(b.clone(), &good.compact(), &committee);
    assert_eq!(rebuilt, good);
    assert_eq!(verify(&rebuilt, &committee, CHAIN, GENESIS, 3), Ok(()));

    assert!(matches!(
        verify(&good, &committee, "OTHER-CHAIN", GENESIS, 3),
        Err(VcertError::ChainMismatch { .. })
    ));
    assert!(matches!(
        verify(&good, &committee, CHAIN, "other-genesis", 3),
        Err(VcertError::GenesisMismatch { .. })
    ));
    assert!(matches!(
        verify(&good, &committee, CHAIN, GENESIS, 4),
        Err(VcertError::EpochMismatch {
            claimed: 3,
            expected: 4
        })
    ));

    // A different committee with IDENTICAL addresses and stakes, so no stake
    // check can fire first: only the committee binding can catch it.
    let mut other = committee.clone();
    other[2].ed25519_public_key = "00".repeat(32);
    assert!(matches!(
        verify(&good, &other, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::ValidatorSetMismatch { .. }))
    ));

    let mut c = good.clone();
    c.signed_stake += 1;
    assert!(matches!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::StakeMismatch { .. }))
    ));
    let mut c = good.clone();
    c.total_stake += 1;
    assert!(matches!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::TotalStakeMismatch { .. }))
    ));

    let mut c = good.clone();
    c.signer_bitmap = vec![0];
    assert!(matches!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::NoSigners))
    ));
    let mut c = good.clone();
    c.signer_bitmap[0] |= 1 << 5;
    assert!(matches!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::SignerOutOfRange(5)))
    ));
    // The bitmap names a member who did not sign; stakes are consistent with the
    // bitmap, so only the aggregate check stands between this and acceptance.
    let mut c = good.clone();
    c.signer_bitmap = qc::encode_bitmap(&[0, 1, 3], 4);
    assert!(matches!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::VerifyFailed(_)))
    ));
    // Two genuine signatures, honestly aggregated: below quorum.
    let two = {
        let sigs: Vec<Vec<u8>> = [0, 1]
            .iter()
            .map(|&i| byzantine_attest(&members[i], &b).signature)
            .collect();
        VertexCertificate {
            version: CERT_VERSION,
            body: b.clone(),
            signer_bitmap: qc::encode_bitmap(&[0, 1], 4),
            signed_stake: 2 * STAKE as u128,
            total_stake: 4 * STAKE as u128,
            aggregate_signature: BLSEngine::consensus().aggregate_signatures(&sigs).unwrap(),
        }
    };
    assert!(matches!(
        verify(&two, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::BelowThreshold { .. }))
    ));
    // The whole point: the signature binds the digest.
    let mut c = good.clone();
    c.body.digest = digest('b');
    assert!(matches!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::Aggregate(QcError::VerifyFailed(_)))
    ));
    let mut c = good.clone();
    c.version = 2;
    assert_eq!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::UnsupportedVersion(2))
    );
    let mut c = good.clone();
    c.body.author = digest('f');
    assert!(matches!(
        verify(&c, &committee, CHAIN, GENESIS, 3),
        Err(VcertError::AuthorNotInCommittee(_))
    ));
}

// ── 3–6. the attestation guard ──────────────────────────────────────────────

#[test]
fn guard_refuses_a_conflicting_digest_across_reopen() {
    let members = committee4();
    let committee = infos(&members);
    let me = &members[0];
    let author = &members[1].info.address;
    let a = body(&committee, 0, 4, author, &digest('a'));
    let b = body(&committee, 0, 4, author, &digest('b'));
    let dir = TempDb::new("reopen");

    let first = {
        let db = dir.open();
        attest_slot(&db, &a, &committee, &me.node_key, &me.info.address).unwrap()
    };
    assert!(matches!(first, AttestOutcome::Signed(_)));

    let db = dir.open();
    let second = attest_slot(&db, &b, &committee, &me.node_key, &me.info.address).unwrap();
    assert_eq!(
        second,
        AttestOutcome::Conflict(first.attestation().clone()),
        "after a restart the guard let this key sign a second digest for one slot"
    );
}

#[test]
fn identical_retry_is_idempotent_including_across_reopen() {
    let members = committee4();
    let committee = infos(&members);
    let me = &members[2];
    let a = body(&committee, 0, 6, &members[0].info.address, &digest('a'));
    let dir = TempDb::new("retry");

    let db = dir.open();
    let first = attest_slot(&db, &a, &committee, &me.node_key, &me.info.address).unwrap();
    let again = attest_slot(&db, &a, &committee, &me.node_key, &me.info.address).unwrap();
    drop(db);
    let reopened =
        attest_slot(&dir.open(), &a, &committee, &me.node_key, &me.info.address).unwrap();

    let AttestOutcome::Signed(signed) = first else {
        panic!("first request did not sign")
    };
    assert_eq!(again, AttestOutcome::Reused(signed.clone()));
    assert_eq!(reopened, AttestOutcome::Reused(signed));
}

#[test]
fn the_same_author_and_round_in_adjacent_epochs_are_both_attestable() {
    let members = committee4();
    let committee = infos(&members);
    let me = &members[0];
    let author = &members[3].info.address;
    let dir = TempDb::new("epochs");
    let db = dir.open();
    for epoch in [7, 8] {
        let b = body(&committee, epoch, 10, author, &digest('a'));
        assert!(
            matches!(
                attest_slot(&db, &b, &committee, &me.node_key, &me.info.address).unwrap(),
                AttestOutcome::Signed(_)
            ),
            "epoch {epoch} was blocked by a guard written in another epoch"
        );
    }
}

#[test]
fn different_authors_at_one_round_never_collide() {
    let members = committee4();
    let committee = infos(&members);
    let me = &members[0];
    let dir = TempDb::new("authors");
    let db = dir.open();
    for (i, author) in members.iter().enumerate() {
        let b = body(&committee, 0, 12, &author.info.address, &digest('a'));
        assert!(
            matches!(
                attest_slot(&db, &b, &committee, &me.node_key, &me.info.address).unwrap(),
                AttestOutcome::Signed(_)
            ),
            "author {i} was blocked by another author's guard"
        );
    }
}

// ── 7. concurrency ──────────────────────────────────────────────────────────

#[test]
fn concurrent_conflicting_requests_yield_exactly_one_attestation() {
    let members = Arc::new(committee4());
    let committee = Arc::new(infos(&members));
    const THREADS: usize = 8;
    for iteration in 0..20 {
        let dir = TempDb::new("race");
        let db = Arc::new(dir.open());
        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let (db, barrier, members, committee) = (
                    db.clone(),
                    barrier.clone(),
                    members.clone(),
                    committee.clone(),
                );
                std::thread::spawn(move || {
                    let d = if t % 2 == 0 { digest('a') } else { digest('b') };
                    let b = body(&committee, 0, 14, &members[1].info.address, &d);
                    barrier.wait();
                    attest_slot(
                        &db,
                        &b,
                        &committee,
                        &members[0].node_key,
                        &members[0].info.address,
                    )
                    .unwrap()
                })
            })
            .collect();
        let outcomes: Vec<AttestOutcome> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let signed: Vec<_> = outcomes
            .iter()
            .filter(|o| matches!(o, AttestOutcome::Signed(_)))
            .collect();
        assert_eq!(
            signed.len(),
            1,
            "iteration {iteration}: {} signatures for one slot",
            signed.len()
        );
        let winner = signed[0].attestation().clone();
        for o in &outcomes {
            assert_eq!(
                o.attestation(),
                &winner,
                "iteration {iteration}: a request saw an attestation other than the one guarded"
            );
        }
        // Both digests were really requested, so the refusals are not vacuous.
        assert!(outcomes
            .iter()
            .any(|o| matches!(o, AttestOutcome::Conflict(_))));
    }
}

// ── 8. crash safety ─────────────────────────────────────────────────────────

const CHILD_DB: &str = "AINCORE_TEST_VCERT_DB";
const PUBLISHED: &str = "VCERT_PUBLISHED:";

/// Subprocess body for the crash test. A no-op unless the parent sets
/// `AINCORE_TEST_VCERT_DB`. "Publishing" is printing the signature, which the
/// real sender would do only after `attest_slot` returns.
#[test]
fn vcert_attest_child() {
    let Ok(path) = std::env::var(CHILD_DB) else {
        return;
    };
    let members = committee4();
    let committee = infos(&members);
    let a = body(&committee, 0, 16, &members[1].info.address, &digest('a'));
    let db = StateDB::open(&path).unwrap();
    let out = attest_slot(
        &db,
        &a,
        &committee,
        &members[0].node_key,
        &members[0].info.address,
    )
    .unwrap();
    println!("{PUBLISHED}{}", hex::encode(&out.attestation().signature));
}

fn run_child(dir: &TempDb, boundary: Option<u8>) -> String {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "vcert::tests::vcert_attest_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DB, &dir.0)
        .env_remove("AINCORE_TEST_VCERT_BOUNDARY");
    if let Some(b) = boundary {
        command.env("AINCORE_TEST_VCERT_BOUNDARY", b.to_string());
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_eq!(
        output.status.code(),
        Some(if boundary.is_some() { 77 } else { 0 }),
        "boundary {boundary:?}\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

#[test]
fn a_crash_before_or_after_commit_never_publishes_an_unguarded_signature() {
    let members = committee4();
    let committee = infos(&members);
    let me = &members[0];
    let author = &members[1].info.address;
    let a = body(&committee, 0, 16, author, &digest('a'));
    let b = body(&committee, 0, 16, author, &digest('b'));
    let pk = me.info.bls_public_key.clone();
    let guard_present = |dir: &TempDb| {
        dir.open()
            .get(&attest_guard_key(&a, &pk))
            .unwrap()
            .is_some()
    };

    // Control: an uninterrupted child publishes, and what it published is guarded.
    let clean = TempDb::new("crash-clean");
    let out = run_child(&clean, None);
    assert!(
        out.contains(PUBLISHED),
        "the clean child never published: the harness is not exercising attest_slot"
    );
    assert!(guard_present(&clean));

    // Crash after signing, before commit: nothing published, nothing guarded —
    // so signing a different digest after restart equivocates to nobody.
    let before = TempDb::new("crash-0");
    assert!(!run_child(&before, Some(0)).contains(PUBLISHED));
    assert!(!guard_present(&before));
    assert!(matches!(
        attest_slot(
            &before.open(),
            &b,
            &committee,
            &me.node_key,
            &me.info.address
        )
        .unwrap(),
        AttestOutcome::Signed(_)
    ));

    // Crash after commit, before sending: nothing published, but guarded — so
    // the restarted node must refuse the other digest.
    let after = TempDb::new("crash-1");
    assert!(!run_child(&after, Some(1)).contains(PUBLISHED));
    assert!(guard_present(&after));
    assert!(matches!(
        attest_slot(
            &after.open(),
            &b,
            &committee,
            &me.node_key,
            &me.info.address
        )
        .unwrap(),
        AttestOutcome::Conflict(_)
    ));
}

// ── 9–10. Lemma U, exhaustively at n = 4 ────────────────────────────────────

/// One equivocating author proposes twins A and B for slot (0, 2, author).
/// Each honest member stages whichever twin reaches it first and attests
/// through the REAL guard; each Byzantine member attests both, unguarded. Every
/// attestation is offered to BOTH collectors. Returns the certificates that
/// pass CE-2.
fn twin_schedule(byzantine: &[usize], order_mask: u32) -> Vec<VertexCertificate> {
    let members = committee4();
    let committee = infos(&members);
    let author = members[byzantine[0]].info.address.clone();
    let twin_a = body(&committee, 0, 2, &author, &digest('a'));
    let twin_b = body(&committee, 0, 2, &author, &digest('b'));

    let mut attestations = Vec::new();
    let honest: Vec<usize> = (0..4).filter(|i| !byzantine.contains(i)).collect();
    let dirs: Vec<TempDb> = honest.iter().map(|_| TempDb::new("lemma-u")).collect();
    for (k, (&h, dir)) in honest.iter().zip(&dirs).enumerate() {
        let (first, second) = if order_mask & (1 << k) == 0 {
            (&twin_a, &twin_b)
        } else {
            (&twin_b, &twin_a)
        };
        let db = dir.open();
        let m = &members[h];
        let signed = attest_slot(&db, first, &committee, &m.node_key, &m.info.address).unwrap();
        assert!(
            matches!(signed, AttestOutcome::Signed(_)),
            "honest member {h} could not attest the first twin"
        );
        assert!(
            matches!(
                attest_slot(&db, second, &committee, &m.node_key, &m.info.address).unwrap(),
                AttestOutcome::Conflict(_)
            ),
            "honest member {h} attested BOTH twins: the guard failed"
        );
        attestations.push(signed.attestation().clone());
    }
    for &b in byzantine {
        attestations.push(byzantine_attest(&members[b], &twin_a));
        attestations.push(byzantine_attest(&members[b], &twin_b));
    }

    let mut certs = Vec::new();
    for twin in [&twin_a, &twin_b] {
        let mut collector = CertCollector::new(twin.clone(), &committee).unwrap();
        for att in &attestations {
            collector.add(att).unwrap();
        }
        if let Some(c) = collector.certificate() {
            verify_vertex_cert(c, &committee, CHAIN, GENESIS, 0).unwrap();
            certs.push(c.clone());
        }
    }
    certs
}

#[test]
fn exhaustive_n4_one_byzantine_attester_yields_at_most_one_certificate() {
    let mut counts = Vec::new();
    for mask in 0..8u32 {
        let certs = twin_schedule(&[0], mask);
        assert!(
            certs.len() <= 1,
            "delivery order {mask:03b}: {} certificates for one slot — Lemma U is broken",
            certs.len()
        );
        counts.push(certs.len());
    }
    // Non-vacuity, and certification liveness: three honest attesters always
    // split 2-1 or 3-0, and the majority twin plus the Byzantine attester reaches
    // 3 of 4. A bound of "at most one" met by forming none would prove nothing.
    assert_eq!(
        counts,
        vec![1; 8],
        "some delivery order formed no certificate at all"
    );
}

#[test]
fn negative_control_two_byzantine_attesters_do_certify_both_twins() {
    let doubled = (0..4u32)
        .filter(|&mask| twin_schedule(&[0, 1], mask).len() == 2)
        .count();
    // Two Byzantine of four is half the stake, past the T/3 bound. When the two
    // honest attesters split 1-1 (orders 01 and 10) each twin reaches 3 of 4.
    // If this harness could not produce two certificates, the "at most one"
    // result above would say nothing about the guard.
    assert_eq!(doubled, 2);
}

// ── collector evidence and refusals ─────────────────────────────────────────

#[test]
fn collector_records_a_signer_who_attests_two_digests() {
    let members = committee4();
    let committee = infos(&members);
    let author = &members[1].info.address;
    let a = body(&committee, 0, 20, author, &digest('a'));
    let b = body(&committee, 0, 20, author, &digest('b'));
    let mut collector = CertCollector::new(a.clone(), &committee).unwrap();

    // An honest attester of A alone produces no evidence.
    assert!(matches!(
        collector.add(&byzantine_attest(&members[0], &a)).unwrap(),
        CollectOutcome::Pending { .. }
    ));
    assert!(collector.equivocations().is_empty());

    let twin_first = byzantine_attest(&members[3], &b);
    let then_ours = byzantine_attest(&members[3], &a);
    assert_eq!(collector.add(&twin_first).unwrap(), CollectOutcome::Foreign);
    assert!(matches!(
        collector.add(&then_ours).unwrap(),
        CollectOutcome::Pending { .. }
    ));
    assert_eq!(collector.equivocations(), &[(twin_first, then_ours)][..]);
}

#[test]
fn collector_refuses_forged_foreign_and_wrong_slot_attestations() {
    let members = committee4();
    let committee = infos(&members);
    let author = &members[1].info.address;
    let a = body(&committee, 0, 22, author, &digest('a'));
    let mut collector = CertCollector::new(a.clone(), &committee).unwrap();

    let mut forged = byzantine_attest(&members[0], &a);
    forged.signer = members[2].info.address.clone();
    assert!(matches!(
        collector.add(&forged),
        Err(VcertError::BadSignature(_))
    ));

    let outsider = member(99, STAKE);
    assert!(matches!(
        collector.add(&byzantine_attest(&outsider, &a)),
        Err(VcertError::SignerNotInCommittee(_))
    ));
    let other_round = body(&committee, 0, 24, author, &digest('a'));
    assert_eq!(
        collector.add(&byzantine_attest(&members[0], &other_round)),
        Err(VcertError::WrongSlot)
    );
    // Control: the genuine attestation is accepted, and counted once.
    let genuine = byzantine_attest(&members[0], &a);
    assert!(matches!(
        collector.add(&genuine).unwrap(),
        CollectOutcome::Pending { .. }
    ));
    assert_eq!(collector.add(&genuine).unwrap(), CollectOutcome::Duplicate);
}

#[test]
fn attest_refuses_a_non_member_and_a_key_the_committee_did_not_register() {
    let members = committee4();
    let committee = infos(&members);
    let a = body(&committee, 0, 26, &members[1].info.address, &digest('a'));
    let dir = TempDb::new("preconditions");
    let db = dir.open();

    let outsider = member(99, STAKE);
    assert!(matches!(
        attest_slot(
            &db,
            &a,
            &committee,
            &outsider.node_key,
            &outsider.info.address
        ),
        Err(VcertError::SelfNotInCommittee(_))
    ));
    // Member 0's address, member 3's node key: a signature that could never
    // verify under the registered key.
    assert!(matches!(
        attest_slot(
            &db,
            &a,
            &committee,
            &members[3].node_key,
            &members[0].info.address
        ),
        Err(VcertError::KeyMismatch { .. })
    ));
    let mut stale = a.clone();
    stale.committee_hash = "00".repeat(32);
    assert!(matches!(
        attest_slot(
            &db,
            &stale,
            &committee,
            &members[0].node_key,
            &members[0].info.address
        ),
        Err(VcertError::CommitteeMismatch { .. })
    ));
    let guard = attest_guard_key(&a, &members[0].info.bls_public_key);
    assert!(
        db.get(&guard).unwrap().is_none(),
        "a refused request left a guard row"
    );
    // Control: the genuine member signs.
    assert!(matches!(
        attest_slot(
            &db,
            &a,
            &committee,
            &members[0].node_key,
            &members[0].info.address
        )
        .unwrap(),
        AttestOutcome::Signed(_)
    ));
}

#[test]
fn a_corrupted_guard_is_refused_and_never_overwritten() {
    let members = committee4();
    let committee = infos(&members);
    let me = &members[0];
    let a = body(&committee, 0, 28, &members[1].info.address, &digest('a'));
    let dir = TempDb::new("corrupt");
    let db = dir.open();
    let signed = attest_slot(&db, &a, &committee, &me.node_key, &me.info.address).unwrap();

    let key = attest_guard_key(&a, &me.info.bls_public_key);
    let mut tampered = signed.attestation().clone();
    tampered.signature[10] ^= 0xff;
    let tampered_row = serde_json::to_string(&tampered).unwrap();
    db.put(&key, &tampered_row).unwrap();

    assert!(matches!(
        attest_slot(&db, &a, &committee, &me.node_key, &me.info.address),
        Err(VcertError::Storage(_))
    ));
    assert_eq!(
        db.get(&key).unwrap().as_deref(),
        Some(tampered_row.as_str())
    );
}

// ── review findings (2026-09-24) ────────────────────────────────────────────

#[test]
fn a_byzantine_signer_cannot_grow_the_evidence_without_bound() {
    let members = committee4();
    let committee = infos(&members);
    let author = &members[1].info.address;
    let ours = body(&committee, 0, 30, author, &digest('a'));
    let mut collector = CertCollector::new(ours.clone(), &committee).unwrap();

    collector
        .add(&byzantine_attest(&members[3], &ours))
        .unwrap();
    // Fifty further digests for the same slot, every one validly signed.
    for i in 0..50u32 {
        let twin = body(&committee, 0, 30, author, &format!("{:064x}", i + 1));
        assert_eq!(
            collector
                .add(&byzantine_attest(&members[3], &twin))
                .unwrap(),
            CollectOutcome::Foreign
        );
    }
    assert_eq!(
        collector.equivocations().len(),
        1,
        "one Byzantine signer grew the evidence list by one entry per digest it chose to sign"
    );
    // The bound is per signer, not global: a second equivocator is still recorded.
    collector
        .add(&byzantine_attest(&members[2], &ours))
        .unwrap();
    let twin = body(&committee, 0, 30, author, &digest('b'));
    collector
        .add(&byzantine_attest(&members[2], &twin))
        .unwrap();
    assert_eq!(collector.equivocations().len(), 2);
}

#[test]
fn a_zero_stake_author_has_no_slot_anywhere() {
    // Seeds 1..=4 with the last at zero stake, then canonical order.
    let mut members: Vec<Member> = [(1u8, STAKE), (2, STAKE), (3, STAKE), (4, 0)]
        .into_iter()
        .map(|(s, st)| member(s, st))
        .collect();
    members.sort_by(|a, b| a.info.address.cmp(&b.info.address));
    let committee = infos(&members);
    let zero = members.iter().position(|m| m.info.stake == 0).unwrap();
    let staked: Vec<usize> = (0..4).filter(|&i| i != zero).collect();
    let signer = &members[staked[0]];

    let at = |author: &str| body(&committee, 0, 32, author, &digest('a'));
    // A certificate with genuine signatures from all three staked members.
    let cert_for = |b: &AttestBody| {
        let sigs: Vec<Vec<u8>> = staked
            .iter()
            .map(|&i| byzantine_attest(&members[i], b).signature)
            .collect();
        VertexCertificate {
            version: CERT_VERSION,
            body: b.clone(),
            signer_bitmap: qc::encode_bitmap(&staked, 4),
            signed_stake: 3 * STAKE as u128,
            total_stake: 3 * STAKE as u128,
            aggregate_signature: BLSEngine::consensus().aggregate_signatures(&sigs).unwrap(),
        }
    };

    let zero_body = at(&members[zero].info.address);
    let dir = TempDb::new("zero-stake");
    let db = dir.open();
    assert!(matches!(
        attest_slot(
            &db,
            &zero_body,
            &committee,
            &signer.node_key,
            &signer.info.address
        ),
        Err(VcertError::AuthorNotInCommittee(_))
    ));
    assert!(matches!(
        CertCollector::new(zero_body.clone(), &committee),
        Err(VcertError::AuthorNotInCommittee(_))
    ));
    assert!(matches!(
        verify_vertex_cert(&cert_for(&zero_body), &committee, CHAIN, GENESIS, 0),
        Err(VcertError::AuthorNotInCommittee(_))
    ));

    // Control: the same committee, a staked author, the same signers.
    let live = at(&members[staked[1]].info.address);
    assert!(matches!(
        attest_slot(
            &db,
            &live,
            &committee,
            &signer.node_key,
            &signer.info.address
        )
        .unwrap(),
        AttestOutcome::Signed(_)
    ));
    assert!(CertCollector::new(live.clone(), &committee).is_ok());
    assert_eq!(
        verify_vertex_cert(&cert_for(&live), &committee, CHAIN, GENESIS, 0),
        Ok(())
    );
}
