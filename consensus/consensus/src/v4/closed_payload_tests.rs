use super::*;

fn closed_frontier(tag: &str) -> (Cluster, usize, Vertex) {
    let mut c = Cluster::new(tag, 4, 0);
    let slow = c.validators().find(|i| *i != c.leader(2)).unwrap();
    let net = c.net(slow);
    let tx = crate::test_txs::tagged(CHAIN, "closed-payload");
    c.engines[slow].as_mut().unwrap().on_tick(vec![tx], &net);
    for i in c.validators().filter(|i| *i != slow) { c.tick(i); }
    let first = c.engine(slow).own_proposal(1).unwrap().clone();
    let delay = |env: &Envelope, _: usize| {
        matches!(&env.msg, Msg::Vertex(v) if v.hash == first.hash)
    };
    c.deliver(&delay);
    for i in c.validators().filter(|i| *i != slow) { c.tick(i); }
    c.deliver(&delay);
    assert!(c.engine(slow).current_round() >= 3);
    c.release();
    c.deliver(&|_, _| false);
    c.tick(slow);
    c.deliver(&|_, _| false);
    let e = c.engine(slow);
    assert!(e.certs.contains_key(&(1, first.author.clone())));
    assert!(!e.own.contains_key(&2));
    assert!(e.own.last_key_value().unwrap().0 > &2);
    assert!(!lock(&e.ordering).is_committed(&first.hash));
    assert_eq!(e.gc_floor(), 0);
    for member in &c.committee {
        if member.address == first.author { continue; }
        let cert = &e.certs[&(2, member.address.clone())];
        assert!(!lock(&e.dag)[&cert.body.digest].parents.contains(&first.hash));
    }
    (c, slow, first)
}

#[test]
fn closed_payload_returns_once_without_changing_certification_or_ordering() {
    let (mut c, slow, first) = closed_frontier("closed-once");
    let e = c.engines[slow].as_mut().unwrap();
    let certs = e.certs.len();
    let dag = lock(&e.dag).len();
    let round = e.current_round();
    let committed = lock(&e.ordering).committed_digests();
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
    assert!(e.take_closed_frontier_payload().is_empty());
    assert_eq!((e.certs.len(), lock(&e.dag).len(), e.current_round()), (certs, dag, round));
    assert_eq!(lock(&e.ordering).committed_digests(), committed);
}

#[test]
fn closed_payload_requires_own_certificate() {
    let (mut c, slow, first) = closed_frontier("closed-own-cert");
    let e = c.engines[slow].as_mut().unwrap();
    let key = (1, first.author.clone());
    let cert = e.certs.remove(&key).unwrap();
    assert!(e.take_closed_frontier_payload().is_empty());
    e.certs.insert(key, cert);
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
}

#[test]
fn closed_payload_requires_every_other_child_certificate_and_body() {
    let (mut c, slow, first) = closed_frontier("closed-child-cert");
    let other = c.committee.iter().find(|m| m.address != first.author).unwrap().address.clone();
    let e = c.engines[slow].as_mut().unwrap();
    let key = (2, other);
    let cert = e.certs.remove(&key).unwrap();
    assert!(e.take_closed_frontier_payload().is_empty());
    e.certs.insert(key, cert.clone());
    let child = lock(&e.dag).remove(&cert.body.digest).unwrap();
    assert!(e.take_closed_frontier_payload().is_empty());
    lock(&e.dag).insert(cert.body.digest, child);
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
}

#[test]
fn closed_payload_keeps_a_vertex_with_a_possible_child_path() {
    let (mut c, slow, first) = closed_frontier("closed-viable-child");
    let other = c.committee.iter().find(|m| m.address != first.author).unwrap().address.clone();
    let e = c.engines[slow].as_mut().unwrap();
    let digest = e.certs[&(2, other)].body.digest.clone();
    // Fault-inject the materialized view to exercise the conservative guard.
    lock(&e.dag).get_mut(&digest).unwrap().parents.push(first.hash.clone());
    assert!(e.take_closed_frontier_payload().is_empty());
    lock(&e.dag).get_mut(&digest).unwrap().parents.pop();
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
}

#[test]
fn closed_payload_requires_a_permanently_skipped_own_child_slot() {
    let (mut c, slow, first) = closed_frontier("closed-own-slot");
    let e = c.engines[slow].as_mut().unwrap();
    let (round, higher) = e.own.pop_last().unwrap();
    assert!(e.take_closed_frontier_payload().is_empty());
    e.own.insert(round, higher.clone());
    e.own.insert(2, higher);
    assert!(e.take_closed_frontier_payload().is_empty());
    e.own.remove(&2);
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
}

#[test]
fn closed_payload_does_not_recall_a_newer_payloads_loan() {
    let (mut c, slow, first) = closed_frontier("closed-newer-loan");
    let e = c.engines[slow].as_mut().unwrap();
    let round = *e.own.last_key_value().unwrap().0;
    assert!(e.own[&round].payload.is_empty());
    e.own.get_mut(&round).unwrap().payload = first.payload.clone();
    assert!(e.take_closed_frontier_payload().is_empty());
    e.own.get_mut(&round).unwrap().payload.clear();
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
}

#[test]
fn closed_payload_stays_closed_during_halt_or_epoch_closing() {
    let (mut c, slow, first) = closed_frontier("closed-halted");
    let e = c.engines[slow].as_mut().unwrap();
    e.halted = Some("injected test halt".into());
    assert!(e.take_closed_frontier_payload().is_empty());
    e.halted = None;
    e.closing_round = Some(2);
    assert!(e.take_closed_frontier_payload().is_empty());
    e.closing_round = None;
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
}

#[test]
fn closed_payload_does_not_recall_history_below_gc_floor() {
    let (mut c, slow, _) = closed_frontier("closed-gc-floor");
    let e = c.engines[slow].as_mut().unwrap();
    lock(&e.ordering).begin_epoch(3, "test-epoch-sentinel").unwrap();
    assert_eq!(e.gc_floor(), 2);
    assert!(e.take_closed_frontier_payload().is_empty());
}

#[test]
fn closed_payload_restart_rebuilds_the_proof_without_reopening_the_child_slot() {
    let (mut c, slow, first) = closed_frontier("closed-restart");
    c.reopen(slow);
    let e = c.engines[slow].as_mut().unwrap();
    assert!(!e.own.contains_key(&2));
    assert_eq!(e.take_closed_frontier_payload(), first.payload);
    assert!(e.take_closed_frontier_payload().is_empty());
}
