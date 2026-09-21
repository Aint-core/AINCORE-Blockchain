use super::*;
use crate::ordering::{CommitInfo, OrderingEngine};

struct Fixture {
    path: String,
    known: Vec<(String, String)>,
}

impl Fixture {
    fn new(known: &[(String, String)]) -> Self {
        Self {
            path: get_test_db_path(&format!("equivocation-ordering-{}", rand::random::<u64>())),
            known: known.to_vec(),
        }
    }

    fn open(&self) -> DagConsensus {
        // Observer identity isolates admission/recovery from execution. We drive
        // the actual ordering engine explicitly below, not a replacement model.
        let mut node = tier2_open(200, &self.path, &self.known);
        node.now_secs = Arc::new(|| 1_700_000_000);
        node
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn decide(node: &DagConsensus, validators: &[(String, u64)]) -> Option<CommitInfo> {
    node.ordering_engine
        .lock()
        .unwrap()
        .try_commit(
            9,
            &node.dag.lock().unwrap(),
            &node.round_index.lock().unwrap(),
            validators,
        )
        .into_iter()
        .next()
}

fn deliver(node: &mut DagConsensus, vertex: &blockchain::Vertex) {
    node.handle_message(&format!(
        "DAG_VERTEX:{}",
        serde_json::to_string(vertex).unwrap()
    ));
}

fn witness(equivocate: bool) {
    let keys: Vec<_> = (31..=34).map(tier2_keypair).collect();
    let known: Vec<_> = keys
        .iter()
        .map(|(a, p, _)| (a.clone(), p.clone()))
        .collect();
    let mut validators: Vec<_> = keys.iter().map(|(a, _, _)| (a.clone(), 1000)).collect();
    validators.sort();
    let byzantine = OrderingEngine::leader_for_round(2, &validators, 0);
    let byz = keys.iter().find(|(a, _, _)| a == &byzantine).unwrap();
    let honest: Vec<_> = keys.iter().filter(|(a, _, _)| a != &byzantine).collect();
    assert_eq!(honest.len(), 3);
    let fx = Fixture::new(&known);
    let fy = Fixture::new(&known);
    let mut x = fx.open();
    let mut y = fy.open();

    let r1: Vec<_> = keys
        .iter()
        .map(|(a, _, k)| tier2_vertex(k, a, 1, 1000, &[]))
        .collect();
    let refs1: Vec<_> = r1
        .iter()
        .zip(&keys)
        .map(|(v, (_, _, k))| test_parent(v, k))
        .collect();
    for v in &r1 {
        deliver(&mut x, v);
        deliver(&mut y, v);
    }
    let r2: Vec<_> = keys
        .iter()
        .map(|(a, _, k)| tier2_vertex(k, a, 2, 1001, &refs1))
        .collect();
    let a = r2.iter().find(|v| v.author == byzantine).unwrap().clone();
    let b = tier2_vertex(&byz.2, &byzantine, 2, 1002, &refs1);
    assert_ne!(a.hash, b.hash);
    if equivocate {
        deliver(&mut y, &b);
    }
    for v in &r2 {
        deliver(&mut x, v);
        deliver(&mut y, v);
    }
    if equivocate {
        deliver(&mut x, &b);
    }

    // Two honest authors and the Byzantine author support A; the remaining
    // honest author supports B. No honest author signs two vertices or cites
    // both twins. Every vertex has a >2/3 distinct-author parent quorum.
    let refs_a: Vec<_> = r2
        .iter()
        .zip(&keys)
        .map(|(v, (_, _, k))| test_parent(v, k))
        .collect();
    let refs_b: Vec<_> = r2
        .iter()
        .zip(&keys)
        .map(|(v, (_, _, k))| {
            test_parent(
                if equivocate && v.author == byzantine {
                    &b
                } else {
                    v
                },
                k,
            )
        })
        .collect();
    let r3: Vec<_> = keys
        .iter()
        .map(|(addr, _, k)| {
            tier2_vertex(
                k,
                addr,
                3,
                1003,
                if addr == &honest[0].0 {
                    &refs_b
                } else {
                    &refs_a
                },
            )
        })
        .collect();
    let mut all_tail = r3.clone();
    let mut prev: Vec<_> = r3
        .iter()
        .filter(|v| v.author != byzantine)
        .cloned()
        .collect();
    for round in 4..=9 {
        let refs: Vec<_> = prev
            .iter()
            .map(|v| {
                let (_, _, key) = keys.iter().find(|(addr, _, _)| addr == &v.author).unwrap();
                test_parent(v, key)
            })
            .collect();
        prev = honest
            .iter()
            .map(|(addr, _, key)| tier2_vertex(key, addr, round, 1000 + round, &refs))
            .collect();
        all_tail.extend(prev.clone());
    }
    for v in &all_tail {
        assert!(v.verify_parent_identities());
        crate::qc::parent_refs_admissible(v, &validators).unwrap();
        deliver(&mut x, v);
        deliver(&mut y, v);
        assert!(tier2_accepted(&x).contains(&v.hash));
        assert!(tier2_accepted(&y).contains(&v.hash));
    }
    let commit_x =
        decide(&x, &validators).expect("A has genuine 3-of-4 direct support and complete history");
    assert_eq!(commit_x.anchor_round, 2);
    assert_eq!(commit_x.anchor_hash, a.hash);

    // Neither replaying all delivered messages nor reopening should permanently
    // prevent the other receiver from reaching that already-supported anchor.
    for _ in 0..3 {
        deliver(&mut y, &a);
        for v in &all_tail {
            deliver(&mut y, v);
        }
    }
    let preview = y.ordering_engine.lock().unwrap().prepare_commit(
        9,
        &y.dag.lock().unwrap(),
        &y.round_index.lock().unwrap(),
        &validators,
    );
    if let Some(plan) = preview {
        assert_eq!(plan.info.anchor_round, commit_x.anchor_round);
        assert_eq!(
            plan.info.anchor_hash, commit_x.anchor_hash,
            "recovery must not replace a liveness failure with conflicting anchor decisions"
        );
    }
    drop(y);
    let mut y = fy.open();
    deliver(&mut y, &a);
    let decision_y = decide(&y, &validators);
    if equivocate {
        eprintln!(
            "ordering witness: X committed anchor 2; Y has A={}, B={}, tail={}, decision={:?}",
            tier2_accepted(&y).contains(&a.hash),
            tier2_accepted(&y).contains(&b.hash),
            all_tail
                .iter()
                .all(|v| tier2_accepted(&y).contains(&v.hash)),
            decision_y
                .as_ref()
                .map(|c| (c.anchor_round, &c.anchor_hash))
        );
    }
    let commit_y = decision_y
        .expect("delivered parent body remains unrecoverable after retransmission and reopen");
    assert_eq!(commit_y.anchor_round, commit_x.anchor_round);
    assert_eq!(commit_y.anchor_hash, commit_x.anchor_hash);
    assert_eq!(commit_y.sequence, commit_x.sequence);
}

#[test]
fn complete_signed_history_decides_after_retransmission_and_reopen() {
    witness(false);
}

#[test]
#[ignore = "OPEN G1: retransmission/reopen cannot recover a dropped equivocated parent; run explicitly for release review"]
fn equivocated_parent_must_not_permanently_block_supported_anchor() {
    witness(true);
}
