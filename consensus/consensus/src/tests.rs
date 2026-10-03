#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    // G5 S4c: the V3 DAG and its tests are deleted. What stays here is pure
    // (the parent-ref predicate, evidence canonicalisation, BFT time) or runs
    // on an inert node; the V4 node tests are included below, the V4 engine
    // tests live in `v4::tests`.
    mod v4_node_tests {
        include!("v4_node_tests.rs");
    }
    use crate::dag::DagConsensus;
    use executor::Executor;
    use mempool::Mempool;
    use std::sync::{Arc, Mutex};
    use storage::object::{Object, Owner};
    use storage::StateDB;

    // Helper to get a unique DB path for each call. The counter keeps two
    // calls apart even with the same suffix; the clock cannot (macOS ticks in
    // microseconds).
    fn get_test_db_path(suffix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "aincore_dag_test_db_{}_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            suffix
        ));
        let _ = std::fs::remove_dir_all(&path); // Clean start
        path.to_string_lossy().to_string()
    }

    /// G3 S3: genesis commits version 0 of the state tree. A fixture that
    /// writes its own genesis state ends the same way; like genesis, it is a
    /// no-op on a database that already has one (a reopened node).
    pub(crate) fn seed_state_tree(db: &Arc<StateDB>) {
        if state_commit::latest_version(db).unwrap().is_some() {
            return;
        }
        let seeded = state_commit::seed_genesis(db).expect("seed state tree v0");
        db.write_batch(seeded.batch).unwrap();
    }

    /// A node on a bare database (no V4 genesis): inert since G5 S4c. Only
    /// what does not need consensus is tested on it.
    fn setup_dag(suffix: &str) -> (DagConsensus, String) {
        let path = get_test_db_path(suffix);
        let db = Arc::new(StateDB::open(&path).unwrap());
        let _seed = db.seeding();
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let executor = Arc::new(Executor::new(Arc::clone(&db)));

        // Generate a deterministic Ed25519 key for testing
        let node_key = [42u8; 32]; // Deterministic seed
        let signing_key = crypto::SigningKey::from_bytes(&node_key);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let node_id = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
        let account = Object::new(
            node_id.clone(),
            Owner::Address(node_id.clone()),
            serde_json::json!({
                "public_key": public_key,
                "sequence_number": 0
            })
            .to_string()
            .into_bytes(),
            "0x1::account::AccountData".to_string(),
        );
        db.put_object(&account).unwrap();

        // Seed the validator set so the test node is an active validator
        // (without this, try_create_vertex enters Observer Mode and creates 0 vertices)
        // Format: Vec<(String, u64)> = [(address, stake_amount)]
        let validator_json = format!(r#"[["{}",1000]]"#, node_id);
        let _ = db.put("sys:validators", &validator_json);
        seed_state_tree(&db);

        (
            DagConsensus::new(node_id, mempool, executor, db, None, node_key),
            path,
        )
    }

    #[test]
    fn test_dag_parent_quorum_requires_strict_supermajority() {
        // B4: the DAG parent quorum is now stake-weighted via qc::stake_quorum_met
        // (strict > 2/3 of TOTAL stake), the same predicate as commit + QC verify.
        use crate::qc::stake_quorum_met;
        assert!(!stake_quorum_met(2, 3)); // exactly 2/3 fails (strict)
        assert!(stake_quorum_met(3, 4)); // 3/4 passes
        assert!(!stake_quorum_met(1, 3)); // 1/3 fails
                                          // Stake, not count: a 60/100 holder is not a quorum; 67/100 is.
        assert!(!stake_quorum_met(60, 100));
        assert!(stake_quorum_met(67, 100));
    }

    /// Phase 2.8 (M-08): validator cache is populated on first read and
    /// returned for subsequent reads without re-parsing storage. After
    /// a block commit, the cache is invalidated and the next read
    /// reflects any updated validator set.
    #[test]
    fn m08_validator_cache_serves_repeated_reads_and_refreshes_on_commit() {
        let (consensus, path) = setup_dag("m08_validator_cache");

        // First read primes the cache.
        let first = consensus.get_validator_set();
        assert!(!first.is_empty(), "test setup seeded a validator");
        let seeded_node = first[0].clone();

        // Mutate storage behind the cache's back. With a naïve
        // implementation this would IMMEDIATELY change the result —
        // but the M-08 cache must keep returning the pre-mutation
        // value until the next legitimate invalidation point.
        let phantom_validator = format!(
            "{}deadbeefdeadbeefdeadbeefdeadbeef",
            &seeded_node[..0] // empty prefix; just construct a distinct 32-char hex
        );
        let mutated_json = format!(
            r#"[["{}",1000],["{}",1000]]"#,
            seeded_node, "deadbeefdeadbeefdeadbeefdeadbeef"
        );
        let _seed = consensus.storage.seeding();
        consensus
            .storage
            .put("sys:validators", &mutated_json)
            .unwrap();

        // Cache hit: still the original set.
        let cached_second_read = consensus.get_validator_set();
        assert_eq!(
            cached_second_read.len(),
            first.len(),
            "cache must not reflect the storage mutation until invalidation"
        );

        // Drive a commit to trigger invalidation. We can't easily
        // synthesise a block commit in this unit test, so call the
        // public invalidator directly — same code path the commit
        // takes.
        consensus.invalidate_validators_cache();

        let post_invalidation = consensus.get_validator_set();
        assert!(
            post_invalidation.len() > first.len()
                || post_invalidation.contains(&"deadbeefdeadbeefdeadbeefdeadbeef".to_string()),
            "after invalidation, cache must re-read storage and reflect the new set"
        );

        let _ = phantom_validator;
        let _ = std::fs::remove_dir_all(&path);
    }

    /// PROTOCOL: canonical_block_evidence is a pure function of the committed
    /// sequence -- dedup by (offender, round) keeping the first in commit order,
    /// skip malformed items, cap at five. Two nodes feeding it the same committed
    /// payloads must get byte-identical output.
    #[test]
    fn test_canonical_block_evidence_dedup_order_cap() {
        let mk = |off: &str, round: u64, tag: &str| {
            serde_json::json!({"kind":"equivocation","offender":off,"round":round,"tag":tag})
                .to_string()
        };
        let input = vec![
            mk("A", 1, "first"),
            "not json".to_string(),
            mk("A", 1, "dup-later"),
            mk("B", 1, "b"),
            mk("A", 2, "a2"),
            serde_json::json!({"kind":"equivocation","offender":"C"}).to_string(), // no round
            mk("D", 1, "d"),
            mk("E", 1, "e"),
            mk("F", 1, "f"),
            mk("G", 1, "g"),
        ];
        // A permissive verifier (parses offender/round) to exercise dedup/cap.
        let parse = |it: &str| -> Option<(String, u64)> {
            let v: serde_json::Value = serde_json::from_str(it).ok()?;
            Some((
                v.get("offender")?.as_str()?.to_string(),
                v.get("round")?.as_u64()?,
            ))
        };
        let out: Vec<String> = DagConsensus::canonical_block_evidence(input.clone(), parse)
            .into_iter()
            .map(|(it, _)| it)
            .collect();
        // first occurrence wins, malformed skipped, cap 5
        assert_eq!(out.len(), 5);
        assert_eq!(out[0], mk("A", 1, "first"));
        assert_eq!(out[1], mk("B", 1, "b"));
        assert_eq!(out[2], mk("A", 2, "a2"));
        assert_eq!(out[3], mk("D", 1, "d"));
        assert_eq!(out[4], mk("E", 1, "e"));
        // deterministic: same input twice -> identical
        let again: Vec<String> = DagConsensus::canonical_block_evidence(input.clone(), parse)
            .into_iter()
            .map(|(it, _)| it)
            .collect();
        assert_eq!(out, again);
        // VERIFY-FIRST: a strict verifier that rejects offender "A" means A's
        // junk can neither occupy a slot nor shadow later real items.
        let strict = |it: &str| -> Option<(String, u64)> {
            let k = parse(it)?;
            if k.0 == "A" {
                None
            } else {
                Some(k)
            }
        };
        let strict_out: Vec<String> = DagConsensus::canonical_block_evidence(input, strict)
            .into_iter()
            .map(|(it, _)| it)
            .collect();
        assert_eq!(strict_out.len(), 5);
        assert_eq!(strict_out[0], mk("B", 1, "b"));
        assert!(strict_out.iter().all(|x| !x.contains("\"offender\":\"A\"")));
    }

    /// Only equivocation items may ride through the DAG. A "downtime" item
    /// would make apply_slash_evidence touch node-local attestation rows.
    #[test]
    fn test_only_equivocation_items_pass_kind_filter() {
        // G5 S4c: the V3 kind went with the V3 DAG.
        assert!(!DagConsensus::is_equivocation_item(
            r#"{"kind":"equivocation","offender":"x","round":1}"#
        ));
        assert!(DagConsensus::is_equivocation_item(
            r#"{"kind":"equivocation_v4","offender":"x","epoch":2,"round":1}"#
        ));
        assert!(DagConsensus::is_equivocation_item(&format!(
            r#"{{"kind":"{}","offender":"x","epoch":2,"round":1}}"#,
            crate::v4::evidence::CERT_KIND
        )));
        assert!(!DagConsensus::is_equivocation_item(
            r#"{"kind":"downtime","offender":"x","epoch":1,"round":1}"#
        ));
        assert!(!DagConsensus::is_equivocation_item(
            r#"{"offender":"x","round":1}"#
        ));
        assert!(!DagConsensus::is_equivocation_item("not json"));
    }

    /// Address, public key hex, and raw key for a deterministic seed.
    fn tier2_keypair(seed: u8) -> (String, String, [u8; 32]) {
        let key = [seed; 32];
        let sk = crypto::SigningKey::from_bytes(&key);
        let pubkey = hex::encode(sk.verifying_key().to_bytes());
        let addr = crypto::derive_address(sk.verifying_key().as_bytes()).unwrap();
        (addr, pubkey, key)
    }

    /// The clock seam must not have cost DagConsensus its thread-safety: it is
    /// held in an Arc<RwLock<..>> and driven from tokio tasks in core/node.
    /// `Arc<dyn Fn>` without the `+ Send + Sync` bounds would compile here and
    /// break only at the call site in another crate.
    #[test]
    fn test_dag_consensus_is_still_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DagConsensus>();
    }

    /// AUDIT B4b. The "anchor already on chain" predicate, asserted at the
    /// BOUNDARY, because the boundary is where an off-by-one becomes a fork.
    ///
    /// This predicate existed as FIVE textually identical copies across the
    /// placement path in dag.rs. Five copies of one safety condition is the shape
    /// that drifts: a later edit fixes four and the fifth silently becomes a fork.
    /// It is one function now, and this test pins its meaning.
    ///
    /// The rule is decided by ANCHOR ROUND, never by height. The live burn-in
    /// showed what deciding by height cost: three distinct anchors (12220, 12224,
    /// 12226) were all skipped against the SAME height 5073 because
    /// reload_chain_tip had not yet seen sync\'s writes, so anchor 12226 never got
    /// a block on that node while its peers placed it at 5075.
    ///
    /// MUTATION: change `<=` to `<` and the boundary case below fails. That is not
    /// a hypothetical edit — it is exactly the "place it once more, just to be
    /// safe" change that duplicates an anchor.
    #[test]
    fn test_anchor_already_on_chain_is_decided_by_round_at_the_boundary() {
        let (mut consensus, path) = setup_dag("anchor_guard");
        consensus.latest_block_round = 10;

        assert!(
            consensus.anchor_already_on_chain(9),
            "an anchor BELOW the tip round is already on chain"
        );
        assert!(
            consensus.anchor_already_on_chain(10),
            "BOUNDARY: an anchor AT the tip round is already on chain. If this \
             fails, the placement path builds a SECOND block for an anchor that \
             already has one, and this node\'s anchor->height map diverges from \
             the network\'s — the live B4b fork."
        );
        assert!(
            !consensus.anchor_already_on_chain(11),
            "BOUNDARY: an anchor ABOVE the tip round still needs a block. If this \
             fails, every new anchor is skipped as a duplicate and the chain stops \
             producing blocks entirely — the opposite failure, equally fatal."
        );

        // Height must not enter the decision at all. That independence IS the fix
        // for the burn-in bug, so it is asserted rather than assumed.
        for h in [5_073u64, 999_999u64] {
            consensus.latest_block_height = h;
            assert!(
                consensus.anchor_already_on_chain(10),
                "height {} changed the answer — the predicate is reading height again",
                h
            );
            assert!(
                !consensus.anchor_already_on_chain(11),
                "height {} changed the answer — the predicate is reading height again",
                h
            );
        }

        let _ = std::fs::remove_dir_all(&path);
    }

    /// A parent as (digest, round, author, V3 identity proof), for building
    /// refs without a DAG.
    type TestParent = (String, u64, String, Option<blockchain::ParentIdentityProof>);

    fn test_parent(v: &blockchain::Vertex, key: &[u8; 32]) -> TestParent {
        let reference = blockchain::ParentRef::authenticated(v,
            hex::encode(crypto::SigningKey::from_bytes(key).verifying_key().to_bytes()));
        (reference.digest, reference.round, reference.author, reference.proof)
    }

    fn tier2_vertex(
        key: &[u8; 32],
        author: &str,
        round: u64,
        ts: u64,
        parents: &[TestParent],
    ) -> blockchain::Vertex {
        let sk = crypto::SigningKey::from_bytes(key);
        // Round 1 cites the genesis sentinel with no refs, as the producer
        // builds it; `&[]` or the sentinel alone asks for that shape.
        let sentinel = [("genesis".to_string(), 0, String::new(), None)];
        let parents: &[TestParent] =
            if round == 1 && parents.iter().all(|(d, _, _, _)| d == "genesis") {
                &sentinel
            } else {
                parents
            };
        let mut v = blockchain::Vertex {
            epoch: 0,
            round,
            author: author.to_string(),
            timestamp: ts,
            payload: vec![],
            parents: parents.iter().map(|(d, _, _, _)| d.clone()).collect(),
            parent_refs: parents
                .iter()
                .filter(|(d, _, _, _)| d != "genesis")
                .map(|(d, r, a, proof)| blockchain::ParentRef {
                    cert: None,
                    round: *r,
                    author: a.clone(),
                    digest: d.clone(),
                    proof: proof.clone(),
                })
                .collect(),
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
        };
        v.hash = v.calculate_hash();
        v.sign_with_ed25519(&sk);
        v
    }

    /// THE DISCRIMINATOR: the gate must reject ZERO honest vertices, at any level
    /// of packet loss.
    ///
    /// This is the counter the two refuted ingress attempts did not have. A
    /// genuine structural rule reads only the vertex's bytes and the committee,
    /// so it CANNOT reject an honest emission no matter what the receiver is
    /// missing — DAG-Rider Claim 2. One rejection means a DAG lookup leaked back
    /// in and the rule has degenerated into the possession rule that measured
    /// 0.3914 against a 0.42 floor.
    ///
    /// The strongest evidence is in the SIGNATURE, not the assertions:
    /// `qc::parent_refs_admissible(&Vertex, &[(String, u64)])` takes no DAG, no
    /// storage and no `&self`. What a node holds is not in scope, so it cannot
    /// influence the verdict. The loop below is the behavioural confirmation of
    /// what the type already guarantees.
    #[test]
    fn test_stateless_gate_rejects_zero_honest_vertices() {
        const PINNED: u64 = 1_700_000_000;
        let keys: Vec<(String, String, [u8; 32])> =
            (1..=4u8).map(|i| tier2_keypair(i + 50)).collect();
        let mut validators: Vec<(String, u64)> =
            keys.iter().map(|(a, _, _)| (a.clone(), 1000u64)).collect();
        validators.sort_by(|a, b| a.0.cmp(&b.0));

        let mut prev: Vec<TestParent> =
            vec![("genesis".to_string(), 0, String::new(), None)];
        let mut checked = 0usize;
        for r in 1..=12u64 {
            let mut this = Vec::new();
            for (addr, _, key) in &keys {
                let v = tier2_vertex(key, addr, r, PINNED, &prev);
                assert!(
                    crate::qc::parent_refs_admissible(&v, &validators).is_ok(),
                    "the gate REJECTED an honest vertex at round {} from {}: {:?}\n\
                     A stateless rule cannot do this. If it fires, a possession \
                     test has leaked back into the predicate and it will halt the \
                     chain on ordinary packet loss.",
                    r,
                    addr,
                    crate::qc::parent_refs_admissible(&v, &validators)
                );
                checked += 1;
                this.push(test_parent(&v, key));
            }
            prev = this;
        }
        assert_eq!(checked, 48, "non-vacuity: 4 validators x 12 rounds");

        // And the converse, so the test cannot pass on a predicate that accepts
        // everything: a thin anchor IS refused, from the same bytes.
        let thin = tier2_vertex(
            &keys[0].2,
            &keys[0].0,
            13,
            PINNED,
            &prev[..1],
        );
        assert!(
            crate::qc::parent_refs_admissible(&thin, &validators).is_err(),
            "CONTROL: a one-parent anchor must still be refused, or this test \
             passes on a predicate that accepts everything"
        );
    }

    /// C1 — a vertex may not name the same parent AUTHOR twice.
    ///
    /// Sui's `DuplicatedAncestorsAuthority`. Stateless: the predicate takes no
    /// DAG, no storage, no `&self`, so the verdict is identical on every honest
    /// node at any packet-loss level.
    ///
    /// What it stops: citing BOTH twins of an equivocating author. The
    /// duplicate-DIGEST check already in `add_vertex` cannot catch that — twin A
    /// and twin B are different digests — and without C1 that one vertex is
    /// counted toward BOTH twins by `direct_quorum_met`, which is evaluated once
    /// per candidate.
    ///
    /// MEASURED on the corpus, 20,000 schedules, with the universe made C1-legal
    /// (validated separately: 0 duplicate-author citations, twins still present):
    ///   before  1,737 breaches, ALL Commit-vs-Commit
    ///   after     807 breaches, ZERO Commit-vs-Commit, all Commit-vs-Skip
    /// So C1 closes the two-nodes-finalise-different-hashes shape completely, and
    /// closes NOTHING of the Commit-vs-Skip residual, which is H1+H2 and needs a
    /// vertex-fetch client. Claiming more than that would be a false report.
    #[test]
    fn test_c1_duplicate_parent_author_is_refused() {
        let keys: Vec<(String, String, [u8; 32])> =
            (1..=4u8).map(|i| tier2_keypair(i + 60)).collect();
        let mut validators: Vec<(String, u64)> =
            keys.iter().map(|(a, _, _)| (a.clone(), 1000u64)).collect();
        validators.sort_by(|a, b| a.0.cmp(&b.0));

        // Round-1 vertices, then a round-2 vertex citing all four — legal.
        let r1: Vec<TestParent> = keys
            .iter()
            .map(|(addr, _, key)| {
                let v = tier2_vertex(key, addr, 1, 1_000, &[("genesis".into(), 0, String::new(), None)]);
                test_parent(&v, key)
            })
            .collect();
        let legal = tier2_vertex(&keys[0].2, &keys[0].0, 2, 1_000, &r1);
        assert!(
            crate::qc::parent_refs_admissible(&legal, &validators).is_ok(),
            "CONTROL: a vertex citing one vertex per author must be admitted, or \
             this test passes on a predicate that rejects everything"
        );

        // Now duplicate ONE author, with a DISTINCT digest — the twin shape. The
        // author list is 4 distinct + 1 repeat, so the stake clause is still
        // satisfied and only C1 can catch it.
        let mut twins = r1.clone();
        twins.push((format!("{}#twin", r1[0].0), 1, r1[0].2.clone(), r1[0].3.clone()));
        let dup = tier2_vertex(&keys[0].2, &keys[0].0, 2, 1_000, &twins);
        assert_eq!(dup.parent_refs.len(), 5);
        assert_ne!(
            dup.parents[0], dup.parents[4],
            "the two entries must be DISTINCT digests, or the pre-existing \
             duplicate-digest check would catch this and C1 would be unproven"
        );
        let verdict = crate::qc::parent_refs_admissible(&dup, &validators);
        assert!(
            verdict.is_err(),
            "a vertex naming author {} twice must be refused",
            r1[0].2
        );
        assert!(
            format!("{:?}", verdict).contains("twice"),
            "refused for the wrong reason: {:?} — it must be the duplicate-author \
             clause, not the stake or round clause",
            verdict
        );
    }

    /// The V3 opening rule, exactly: nothing at round 0, and round 1 cites the
    /// genesis sentinel alone, with no refs, as the producer builds it.
    #[test]
    fn round_one_cites_the_genesis_sentinel_alone() {
        let (addr, _, key) = tier2_keypair(70);
        let shaped = |round: u64, parents: &[&str], refs: usize| {
            let mut v = tier2_vertex(&key, &addr, round, 1_000, &[]);
            v.parents = parents.iter().map(|p| p.to_string()).collect();
            v.parent_refs = (0..refs)
                .map(|_| blockchain::ParentRef {
                    cert: None,
                    round: 0,
                    author: String::new(),
                    digest: "genesis".to_string(),
                    proof: None,
                })
                .collect();
            v
        };
        let other = "a".repeat(64);
        assert!(shaped(1, &["genesis"], 0).verify_parent_identities());
        assert!(!shaped(1, &["genesis"], 1).verify_parent_identities());
        assert!(!shaped(1, &[&other], 0).verify_parent_identities());
        assert!(!shaped(1, &["genesis", &other], 0).verify_parent_identities());
        assert!(!shaped(1, &[], 0).verify_parent_identities());
        assert!(!shaped(0, &[], 0).verify_parent_identities());
        assert!(!shaped(0, &["genesis"], 0).verify_parent_identities());
    }

    /// G5 BT-1 at the call site: the quorum is measured against the whole
    /// committee's stake, and a non-member's vote carries no weight. Two of
    /// four members cannot move time; three can; an outsider adds nothing.
    #[test]
    fn a_block_timestamp_needs_a_quorum_of_the_committee() {
        use crate::dag::committee_block_timestamp;
        let committee: Vec<(String, u64)> = ["a", "b", "c", "d"]
            .iter()
            .map(|m| (m.to_string(), 100))
            .collect();
        let sample = |authors: &[&str]| -> Vec<(String, u64)> {
            authors.iter().map(|a| (a.to_string(), 5_000)).collect()
        };
        assert_eq!(
            committee_block_timestamp(&sample(&["a", "b"]), &committee, 777),
            777
        );
        assert_eq!(
            committee_block_timestamp(&sample(&["a", "b", "outsider"]), &committee, 777),
            777,
            "a non-member does not complete a quorum"
        );
        assert_eq!(
            committee_block_timestamp(&sample(&["a", "b", "c"]), &committee, 777),
            5_000
        );
    }
}
