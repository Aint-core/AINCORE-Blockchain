use super::*;

fn signed_tx(seed: u8, seq: u64) -> String {
    signed_tx_priced(seed, seq, 1)
}

/// `signed_tx` at `gas_price` (B453: a fee-bumped replacement of it).
fn signed_tx_priced(seed: u8, seq: u64, gas_price: u64) -> String {
    signed_publish(seed, seq, gas_price, vec![seed, seq as u8])
}

/// The canonical transaction of `seed`'s key at `seq` and `gas_price`
/// publishing `module`, its gas limit covering its bytes and at least
/// 100,000 gas of execution (B462: its publish floor, for large ones).
fn signed_publish(seed: u8, seq: u64, gas_price: u64, module: Vec<u8>) -> String {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let modules = vec![module];
    let execution = executor::admission::publish_floor(&modules).max(100_000);
    let payload = vm_move::TransactionPayload::PublishModule(modules);
    let mut tx = serde_json::json!({
        "chain_id": blockchain::chain_id(),
        "sender": sender,
        "input_objects": [],
        "payload": hex::encode(bcs::to_bytes(&payload).unwrap()),
        "args": [],
        "gas_price": gas_price,
        "sequence_number": seq,
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "gas_limit": 0,
        "signature": "00".repeat(64),
    });
    let unsized_len = tx.to_string().len();
    tx["gas_limit"] = serde_json::json!(executor::admission::gas_limit_covering(
        unsized_len,
        execution
    ));
    let parsed: executor::Transaction = serde_json::from_value(tx.clone()).unwrap();
    let message = executor::admission::signing_message(&parsed);
    tx["signature"] = serde_json::json!(hex::encode(key.sign(message.as_bytes()).to_bytes()));
    // B73: the canonical encoding, the one a mempool keeps and forwards.
    executor::admission::canonicalize(&tx.to_string()).unwrap()
}

fn submit(txs: &[String]) -> String {
    format!("{TX_SUBMIT}{}", serde_json::to_string(txs).unwrap())
}

fn verdicts(reply: &str) -> Vec<Verdict> {
    serde_json::from_str(reply.strip_prefix(TX_RESULT).unwrap()).unwrap()
}

/// B173 witness: a copy of a transaction the mempool holds, or of one
/// earlier in the batch, is refused before its signature is checked; a
/// batch of 64 copies of one transaction cost 64 checks.
#[test]
fn a_copy_costs_no_signature_check() {
    let member = Mutex::new(Mempool::new());
    let tx = signed_tx(4, 0);
    let checks = || OUTSIDE_CHECKS.with(|n| n.get());
    let before = checks();
    let copies = submit(&vec![tx.clone(); FORWARD_BATCH]);
    let v = verdicts(&serve_tx_submit(&member, &copies).unwrap());
    assert!(matches!(v[0], Verdict::Accepted(_)), "vacuous: {v:?}");
    assert!(
        v[1..]
            .iter()
            .all(|v| matches!(v, Verdict::Refused(r) if r.contains("Duplicate"))),
        "{v:?}"
    );
    assert_eq!(checks() - before, 1, "each copy in the batch was checked");
    let v = verdicts(&serve_tx_submit(&member, &submit(&[tx])).unwrap());
    assert!(
        matches!(&v[0], Verdict::Refused(r) if r.contains("Duplicate")),
        "{v:?}"
    );
    assert_eq!(checks() - before, 1, "a held transaction was checked again");
}

/// B21, member side: each forwarded transaction gets its own mempool
/// verdict, in order; a batch that is not one is refused whole.
#[test]
fn a_member_answers_each_transaction_with_its_mempool_verdict() {
    let member = Mutex::new(Mempool::new());
    let tx = signed_tx(1, 0);
    let reply = serve_tx_submit(&member, &submit(&[tx.clone(), "nope".into(), tx])).unwrap();
    let v = verdicts(&reply);
    assert!(matches!(v[0], Verdict::Accepted(_)), "{v:?}");
    assert!(
        matches!(&v[1], Verdict::Refused(r) if r.contains("JSON")),
        "{v:?}"
    );
    assert!(
        matches!(&v[2], Verdict::Refused(r) if r.contains("Duplicate")),
        "{v:?}"
    );
    assert_eq!(member.lock().unwrap().len(), 1);
    let many: Vec<String> = (0..=FORWARD_BATCH as u64)
        .map(|s| signed_tx(2, s))
        .collect();
    for wire in [
        submit(&[]),
        submit(&many),
        "TX_SUBMIT:{".into(),
        "SYNC_REQ:{}".into(),
    ] {
        assert_eq!(
            serve_tx_submit(&member, &wire),
            None,
            "{}",
            &wire[..20.min(wire.len())]
        );
    }
    assert_eq!(
        member.lock().unwrap().len(),
        1,
        "nothing from a refused batch"
    );
}

fn session(peer: &str, member: bool) -> network::SessionPeer {
    network::SessionPeer {
        peer: peer.into(),
        member: member.then(|| format!("addr-{peer}")),
    }
}

/// One sender's transactions go to one member, the next members in a fixed
/// order behind it; senders spread over the members; non-members never.
#[test]
fn a_sender_maps_to_one_member_and_fails_over_in_order() {
    let sessions = [
        session("p3", true),
        session("p1", true),
        session("x", false),
        session("p2", true),
        session("p4", true),
    ];
    let order = members_for("alice", &sessions);
    assert_eq!(order.len(), 4);
    assert!(!order.contains(&"x".to_string()));
    assert_eq!(order, members_for("alice", &sessions), "deterministic");
    let mut sorted = order.clone();
    sorted.sort();
    assert_eq!(sorted, ["p1", "p2", "p3", "p4"]);
    let start = sorted.iter().position(|p| *p == order[0]).unwrap();
    sorted.rotate_left(start);
    assert_eq!(order, sorted, "a rotation of the address order");
    let firsts: std::collections::BTreeSet<String> = (0..64)
        .map(|i| members_for(&format!("sender-{i}"), &sessions)[0].clone())
        .collect();
    assert_eq!(firsts.len(), 4, "senders spread over every member");
    assert!(members_for("alice", &[session("x", false)]).is_empty());
}

#[test]
fn batches_stop_at_their_count_and_their_bytes() {
    let small: Vec<String> = (0..FORWARD_BATCH * 2 + 1)
        .map(|i| format!("t{i}"))
        .collect();
    let b = batches(small.clone(), 1 << 20);
    assert_eq!(
        b.iter().map(Vec::len).collect::<Vec<_>>(),
        [FORWARD_BATCH, FORWARD_BATCH, 1]
    );
    assert_eq!(b.concat(), small, "order kept");
    let big: Vec<String> = (0..3).map(|i| format!("{i}{}", "y".repeat(400))).collect();
    let b = batches(big.clone(), 900);
    assert!(
        b.iter().all(|x| x.len() <= 2),
        "{:?}",
        b.iter().map(Vec::len).collect::<Vec<_>>()
    );
    for batch in &b {
        if batch.len() > 1 {
            assert!(submit(batch).len() <= 900);
        }
    }
    assert_eq!(b.concat(), big);
}

/// `answer`'s way of saying nothing at all: the request is held unanswered
/// (the asker's timeout runs out).
const SILENCE: &str = "silence";

/// A fake network task: every request to `peer` is answered by `answer`.
fn fake_network(
    sessions: Vec<network::SessionPeer>,
    mut answer: impl FnMut(&str, &str) -> Result<String, String> + Send + 'static,
) -> network::SessionClient {
    let (asks_tx, mut asks) = tokio::sync::mpsc::channel::<network::SyncAsk>(8);
    let (dials_tx, _dials) = tokio::sync::mpsc::channel::<network::SyncDial>(8);
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(ask) = asks.recv().await {
            match answer(&ask.peer, &ask.wire) {
                Err(e) if e == SILENCE => held.push(ask.reply),
                result => {
                    let _ = ask.reply.send(result);
                }
            }
        }
    });
    network::SessionClient {
        asks: asks_tx,
        dials: dials_tx,
        table: Arc::new(std::sync::RwLock::new(sessions)),
    }
}

/// B21 witness: what an observer's RPC accepted reaches a member's mempool,
/// past a member that is down; a transaction two members refuse (both hold
/// it already) is dropped (B39: one refusal is not enough).
#[tokio::test]
async fn an_observer_forwards_its_mempool_to_a_member() {
    let observer = Arc::new(Mutex::new(Mempool::new()));
    let txs = [signed_tx(7, 0), signed_tx(7, 1), signed_tx(8, 0)];
    for tx in &txs {
        observer
            .lock()
            .unwrap()
            .add_transaction(tx.clone())
            .unwrap();
    }
    let (up, up2) = (
        Arc::new(Mutex::new(Mempool::new())),
        Arc::new(Mutex::new(Mempool::new())),
    );
    // Both answering members hold the third already: both refuse it.
    up.lock().unwrap().add_transaction(txs[2].clone()).unwrap();
    up2.lock().unwrap().add_transaction(txs[2].clone()).unwrap();
    let sessions = vec![
        session("down", true),
        session("up", true),
        session("up2", true),
        session("obs", false),
    ];
    let (s1, s2) = (Arc::clone(&up), Arc::clone(&up2));
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&asked);
    let client = fake_network(sessions, move |peer, wire| {
        log.lock().unwrap().push(peer.to_string());
        match peer {
            "up" => serve_tx_submit(&s1, wire).ok_or_else(|| "refused".into()),
            "up2" => serve_tx_submit(&s2, wire).ok_or_else(|| "refused".into()),
            _ => Err("connection reset".into()),
        }
    });
    assert_eq!(
        forward_once(&observer, &client, &ForwardState::default()).await,
        2
    );
    {
        let held = |m: &Arc<Mutex<Mempool>>, t: &String| {
            m.lock().unwrap().get_all_pending().iter().any(|p| p == t)
        };
        for t in &txs[..2] {
            assert!(held(&up, t) || held(&up2, t), "accepted by a member");
        }
    }
    {
        let o = observer.lock().unwrap();
        assert!(o.is_empty(), "everything settled or on loan");
        let raw = |t: &str| storage::StateDB::raw_tx_hash(t);
        assert!(
            o.any_pending(|t| raw(t) == raw(&txs[0])),
            "accepted: on loan until a block"
        );
        assert!(
            !o.any_pending(|t| raw(t) == raw(&txs[2])),
            "refused by two members: dropped"
        );
        assert!(
            !asked.lock().unwrap().iter().any(|p| p == "obs"),
            "never a non-member"
        );
    }
    // B452: refused for good by members, it never ran here: the same bytes
    // are taken again.
    observer
        .lock()
        .unwrap()
        .add_transaction(txs[2].clone())
        .expect("refused again after its drop");

    // Nobody answers: the batch returns to the front of the queue, in order.
    let lonely = Arc::new(Mutex::new(Mempool::new()));
    for tx in &txs {
        lonely.lock().unwrap().add_transaction(tx.clone()).unwrap();
    }
    let before: Vec<String> = lonely.lock().unwrap().get_all_pending();
    let dead = fake_network(vec![session("down", true)], |_, _| Err("timeout".into()));
    assert_eq!(
        forward_once(&lonely, &dead, &ForwardState::default()).await,
        0
    );
    let after: Vec<String> = lonely.lock().unwrap().get_all_pending();
    assert_eq!(after, before);
}

/// B39 witness: one member refusing everything cannot censor a sender: the
/// refused transactions go to the next member, which accepts them.
#[tokio::test]
async fn one_refusing_member_cannot_censor() {
    let observer = Arc::new(Mutex::new(Mempool::new()));
    let members = [session("liar", true), session("honest", true)];
    // A sender whose transactions go to the liar first.
    let tx = (9..=255)
        .map(|seed| signed_tx(seed, 0))
        .find(|t| members_for(&sender_of(t), &members)[0] == "liar")
        .unwrap();
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let client = fake_network(members.to_vec(), move |peer, wire| match peer {
        "liar" => {
            let n = serde_json::from_str::<Vec<String>>(wire.strip_prefix(TX_SUBMIT).unwrap())
                .unwrap()
                .len();
            let no = vec![Verdict::Refused("no".into()); n];
            Ok(format!(
                "{TX_RESULT}{}",
                serde_json::to_string(&no).unwrap()
            ))
        }
        _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
    });
    assert_eq!(
        forward_once(&observer, &client, &ForwardState::default()).await,
        1
    );
    assert!(honest.lock().unwrap().get_all_pending().contains(&tx));
}

/// B39 review and B133 witness: a transaction one member refuses in every
/// pass, its other member silent, is not dropped by how many passes it took
/// (a Byzantine minority drove that count), but it is not forwarded forever
/// either: it leaves at its TTL.
#[tokio::test]
async fn a_transaction_never_taken_leaves_at_its_ttl() {
    let observer = Arc::new(Mutex::new(Mempool::new()));
    let tx = signed_tx(9, 0);
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let members = vec![session("liar", true), session("silent", true)];
    let client = fake_network(members, move |peer, wire| match peer {
        "liar" => {
            let n = serde_json::from_str::<Vec<String>>(wire.strip_prefix(TX_SUBMIT).unwrap())
                .unwrap()
                .len();
            let no = vec![Verdict::Refused("no".into()); n];
            Ok(format!(
                "{TX_RESULT}{}",
                serde_json::to_string(&no).unwrap()
            ))
        }
        _ => Err("timeout".into()),
    });
    let raw = storage::StateDB::raw_tx_hash(&tx);
    let waiting = |m: &Arc<Mutex<Mempool>>| {
        m.lock()
            .unwrap()
            .any_pending(|t| storage::StateDB::raw_tx_hash(t) == raw)
    };
    let state = ForwardState::default();
    let t0 = 1_000_000;
    for pass in 0..10 {
        forward_once_at(&observer, &client, &state, t0 + pass).await;
        assert!(waiting(&observer), "dropped after {} passes", pass + 1);
    }
    forward_once_at(&observer, &client, &state, t0 + FORWARD_TTL_SECS).await;
    assert!(!waiting(&observer), "still forwarded past its TTL");
    // B452: it never ran, so the same bytes are taken again.
    observer
        .lock()
        .unwrap()
        .add_transaction(tx)
        .expect("refused again after its TTL");
}

/// B53/B134 witness: a member that answers Accepted and drops the
/// transaction cannot censor its sender: once the loan goes stale, the
/// transaction is forwarded again to the members that have not answered for
/// it first, and the next keeps it. Before, every re-forward went to the
/// same first member. (The forwarder's state lives across passes, as
/// `run_forwarder` keeps it: B134 moved what a re-forward skips from the
/// mempool's loan count into it.)
#[tokio::test]
async fn an_accept_and_drop_member_cannot_censor() {
    let observer = Arc::new(Mutex::new(Mempool::new()));
    let members = [session("dropper", true), session("honest", true)];
    let tx = (9..=255)
        .map(|seed| signed_tx(seed, 0))
        .find(|t| members_for(&sender_of(t), &members)[0] == "dropper")
        .unwrap();
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let client = fake_network(members.to_vec(), move |peer, wire| match peer {
        "dropper" => {
            let n = serde_json::from_str::<Vec<String>>(wire.strip_prefix(TX_SUBMIT).unwrap())
                .unwrap()
                .len();
            let yes = vec![Verdict::Accepted("dropped".into()); n];
            Ok(format!(
                "{TX_RESULT}{}",
                serde_json::to_string(&yes).unwrap()
            ))
        }
        _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
    });
    let held = |m: &Arc<Mutex<Mempool>>| m.lock().unwrap().get_all_pending().contains(&tx);
    let state = ForwardState::default();
    assert_eq!(forward_once(&observer, &client, &state).await, 1);
    assert!(
        !held(&honest),
        "control: the first forward went to the dropper"
    );
    // No block settled it: the loan goes stale and returns to the queue.
    observer.lock().unwrap().requeue_stale_at(0, u64::MAX / 2);
    forward_once(&observer, &client, &state).await;
    assert!(held(&honest), "the re-forward went to the same member");
}

/// B232 witness: a member first in a sender's order that refuses every
/// transaction for now cannot censor it: the transaction goes on to the next
/// member in the same pass (B216 left it on loan at the first, so the same
/// member was asked first at every re-forward until the TTL dropped it).
#[tokio::test]
async fn a_member_refusing_for_now_cannot_censor() {
    let observer = Arc::new(Mutex::new(Mempool::new()));
    let members = [session("stalling", true), session("honest", true)];
    let tx = (9..=255)
        .map(|seed| signed_tx(seed, 0))
        .find(|t| members_for(&sender_of(t), &members)[0] == "stalling")
        .unwrap();
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let client = fake_network(members.to_vec(), move |peer, wire| match peer {
        "stalling" => answer_all(wire, Verdict::Later("Mempool full".into())),
        _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
    });
    let state = ForwardState::default();
    assert_eq!(forward_once(&observer, &client, &state).await, 1);
    assert!(
        honest.lock().unwrap().get_all_pending().contains(&tx),
        "the first member's refusals for now held the transaction"
    );
}

/// B247 witness: a transaction one member refused for now while another
/// was resting goes back to the queue (it stayed on loan 30 s), and the next
/// pass asks the member that did not answer, not again the one that refused
/// it for now.
#[tokio::test]
async fn a_refusal_for_now_with_a_member_unasked_holds_nothing() {
    let observer = Arc::new(Mutex::new(Mempool::new()));
    let members = [session("stalling", true), session("resting", true)];
    let tx = (9..=255)
        .map(|seed| signed_tx(seed, 0))
        .find(|t| members_for(&sender_of(t), &members)[0] == "stalling")
        .unwrap();
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let asks = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let counted = Arc::clone(&asks);
    let client = fake_network(members.to_vec(), move |peer, wire| {
        *counted.lock().unwrap().entry(peer.to_string()).or_default() += 1;
        match peer {
            "stalling" => answer_all(wire, Verdict::Later("Mempool full".into())),
            _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
        }
    });
    let state = ForwardState::default();
    let t0 = 2_000_000;
    state.rest("resting", t0);
    forward_once_at(&observer, &client, &state, t0).await;
    assert!(
        observer.lock().unwrap().get_all_pending().contains(&tx),
        "held on loan though a member was not asked"
    );
    forward_once_at(&observer, &client, &state, t0 + 1).await;
    assert!(
        honest.lock().unwrap().get_all_pending().contains(&tx),
        "the member that did not answer was not asked"
    );
    let asks = asks.lock().unwrap();
    assert_eq!(
        asks.get("stalling"),
        Some(&1),
        "asked again within its loan period: {asks:?}"
    );
}

/// A member answering every transaction of a batch with `verdict`.
fn answer_all(wire: &str, verdict: Verdict) -> Result<String, String> {
    let n = serde_json::from_str::<Vec<String>>(wire.strip_prefix(TX_SUBMIT).unwrap())
        .unwrap()
        .len();
    Ok(format!(
        "{TX_RESULT}{}",
        serde_json::to_string(&vec![verdict; n]).unwrap()
    ))
}

/// B122 witness: in a committee of seven, two refusing members next to each
/// other in a sender's rotation hold less than a third of the stake: the
/// transaction goes on to an honest member. Two refusals used to drop it.
#[tokio::test]
async fn a_byzantine_minority_cannot_drop_a_transaction_by_refusing() {
    let names = ["a1", "a2", "b1", "b2", "b3", "b4", "b5"];
    let members: Vec<network::SessionPeer> = names.iter().map(|n| session(n, true)).collect();
    let tx = (9..=255)
        .map(|seed| signed_tx(seed, 0))
        .find(|t| members_for(&sender_of(t), &members)[..2] == ["a1", "a2"])
        .expect("a sender whose rotation starts at the two liars");
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let client = fake_network(members.clone(), move |peer, wire| match peer {
        "a1" | "a2" => answer_all(wire, Verdict::Refused("no".into())),
        _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
    });
    let state = ForwardState::with_stakes(
        members
            .iter()
            .map(|s| (s.member.clone().unwrap(), 100))
            .collect(),
    );
    assert_eq!(forward_once(&observer, &client, &state).await, 1);
    assert!(honest.lock().unwrap().get_all_pending().contains(&tx));
}

/// B122 witness: a member that does not answer is skipped for a while, not
/// asked (and waited for) again in every pass.
#[tokio::test]
async fn a_silent_member_is_skipped_for_a_while() {
    let members = vec![session("silent", true), session("honest", true)];
    let txs: Vec<String> = (9..=255)
        .map(|seed| signed_tx(seed, 0))
        .filter(|t| members_for(&sender_of(t), &members)[0] == "silent")
        .take(2)
        .collect();
    let observer = Arc::new(Mutex::new(Mempool::new()));
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let asked = Arc::new(Mutex::new(0usize));
    let count = Arc::clone(&asked);
    let client = fake_network(members, move |peer, wire| match peer {
        "silent" => {
            *count.lock().unwrap() += 1;
            Err(SILENCE.into())
        }
        _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
    });
    let state = ForwardState::default().with_timeout(std::time::Duration::from_millis(50));
    for tx in &txs {
        observer
            .lock()
            .unwrap()
            .add_transaction(tx.clone())
            .unwrap();
        assert_eq!(forward_once(&observer, &client, &state).await, 1);
    }
    assert_eq!(
        *asked.lock().unwrap(),
        1,
        "the silent member was asked again"
    );
}

/// B133 witness: a busy member says so and is asked again next pass (it
/// used to be benched like a silent one), as is one whose ask failed at once
/// (only a timeout benches); and a minority's refusals, carried over every
/// pass, never drop a transaction while the rest are busy.
#[tokio::test]
async fn busy_members_are_asked_again_and_a_minority_cannot_drop() {
    let names = ["a1", "a2", "b1", "b2", "b3", "b4", "b5"];
    let members: Vec<network::SessionPeer> = names.iter().map(|n| session(n, true)).collect();
    let tx = signed_tx(9, 0);
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let busy = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let still_busy = Arc::clone(&busy);
    let asked: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
    let log = Arc::clone(&asked);
    let client = fake_network(members.clone(), move |peer, wire| {
        *log.lock().unwrap().entry(peer.to_string()).or_insert(0) += 1;
        match peer {
            "a1" | "a2" => answer_all(wire, Verdict::Refused("no".into())),
            "b1" if still_busy.load(std::sync::atomic::Ordering::SeqCst) => Err("gone".into()),
            _ if still_busy.load(std::sync::atomic::Ordering::SeqCst) => Ok(TX_BUSY.into()),
            _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
        }
    });
    let state = ForwardState::with_stakes(
        members
            .iter()
            .map(|s| (s.member.clone().unwrap(), 100))
            .collect(),
    );
    let raw = storage::StateDB::raw_tx_hash(&tx);
    let waiting = |m: &Arc<Mutex<Mempool>>| {
        m.lock()
            .unwrap()
            .any_pending(|t| storage::StateDB::raw_tx_hash(t) == raw)
    };
    let t0 = 2_000_000;
    for pass in 0..5 {
        assert_eq!(
            forward_once_at(&observer, &client, &state, t0 + pass).await,
            0
        );
        assert!(waiting(&observer), "a minority's refusals dropped it");
    }
    // One lock per assertion: a message locking the same mutex again
    // deadlocked a failing one.
    let counts = asked.lock().unwrap().clone();
    assert!(counts["b5"] >= 5, "a busy member was benched: {counts:?}");
    assert!(
        counts["b1"] >= 5,
        "a member whose ask failed at once was benched: {counts:?}"
    );
    busy.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(forward_once_at(&observer, &client, &state, t0 + 5).await, 1);
    assert!(honest.lock().unwrap().get_all_pending().contains(&tx));
}

/// B154 witness: a record lives as long as the mempool holds its
/// transaction: a full table drops the records of transactions no longer
/// held, never a held one, however long since it was loaned (a full table
/// evicted the longest-pending live record, and an idle bound forgot a held
/// one across a long gap between loans, restarting its TTL and members).
#[test]
fn a_held_transactions_record_outlives_a_full_table() {
    let state = ForwardState::default();
    let t0 = 5_000_000;
    let live = "live".to_string();
    state.record(&live, t0 - 10_000);
    for i in 0..MAX_FORWARD_RECORDS - 1 {
        state.record(&format!("settled-{i}"), t0);
    }
    let held: HashSet<String> = [storage::StateDB::raw_tx_hash(&live)].into_iter().collect();
    state.make_room(1, || held.clone());
    state.record("new", t0 + 1);
    assert_eq!(
        state.record(&live, t0 + 2).first_secs,
        t0 - 10_000,
        "a held transaction's record was forgotten"
    );
    assert_eq!(
        state.forwarded.lock().unwrap().by_tx.len(),
        2,
        "the records of transactions no longer held were kept"
    );
}

/// B156 witness: a member that said it was busy rests a second (of the pass
/// clock) before it is asked again; each pass, 250 ms apart, asked it anew
/// and spent the forwarder's quota at it.
#[tokio::test]
async fn a_busy_member_rests_a_second() {
    let members = vec![session("b1", true), session("b2", true)];
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(signed_tx(9, 0))
        .unwrap();
    let asked: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
    let log = Arc::clone(&asked);
    let client = fake_network(members, move |peer, _| {
        *log.lock().unwrap().entry(peer.to_string()).or_insert(0) += 1;
        Ok(TX_BUSY.into())
    });
    let state = ForwardState::default();
    let t0 = 4_000_000;
    for now in [t0, t0, t0 + 1] {
        forward_once_at(&observer, &client, &state, now).await;
    }
    // One lock: the message's own lock of the same mutex deadlocked a
    // failing assertion.
    let asked = asked.lock().unwrap().clone();
    assert_eq!(
        asked.get("b1"),
        Some(&2),
        "a busy member was asked again within its second: {asked:?}"
    );
}

/// B151 witness: a member answering just inside the timeout holds only the
/// batch it was asked; the next passes go on without it. Each pass waited
/// for its slowest batch, and every pass for the one before.
#[tokio::test]
async fn a_slow_member_holds_no_other_pass() {
    let members = vec![session("slow", true), session("honest", true)];
    let first_at = |name: &str| {
        (9..=255)
            .map(|seed| signed_tx(seed, 0))
            .find(|t| members_for(&sender_of(t), &members)[0] == name)
            .unwrap()
    };
    let (held_up, other) = (first_at("slow"), first_at("honest"));
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(held_up.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    // "slow" answers every batch three seconds late, inside the timeout.
    let (asks_tx, mut asks) = tokio::sync::mpsc::channel::<network::SyncAsk>(8);
    let (dials_tx, _dials) = tokio::sync::mpsc::channel::<network::SyncDial>(8);
    tokio::spawn(async move {
        while let Some(ask) = asks.recv().await {
            if ask.peer == "slow" {
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let _ = ask
                        .reply
                        .send(answer_all(&ask.wire, Verdict::Accepted("late".into())));
                });
            } else {
                let _ = ask
                    .reply
                    .send(serve_tx_submit(&served, &ask.wire).ok_or_else(|| "refused".into()));
            }
        }
    });
    let client = network::SessionClient {
        asks: asks_tx,
        dials: dials_tx,
        table: Arc::new(std::sync::RwLock::new(members.clone())),
    };
    let shutdown = Arc::new(AtomicBool::new(false));
    tokio::spawn(run_forwarder(
        Arc::clone(&observer),
        client,
        Arc::new(std::sync::RwLock::new(crate::sessions::PeerBook::default())),
        Arc::new(AtomicBool::new(false)),
        Arc::clone(&shutdown),
    ));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    observer
        .lock()
        .unwrap()
        .add_transaction(other.clone())
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let reached = honest.lock().unwrap().get_all_pending().contains(&other);
    shutdown.store(true, Ordering::SeqCst);
    assert!(reached, "a slow member's batch held the next pass");
}

/// B134/B154 witness: a run of accept-and-drop members, adjacent in a
/// sender's rotation and holding less than a third of the stake, cannot hold
/// a transaction: its first re-forward goes on through the members not
/// tried yet until those that took it hold more than a third. Each
/// re-forward used to reach one member, so the run held it past its TTL.
#[tokio::test]
async fn adjacent_accept_and_drop_members_cannot_censor() {
    let names = ["d1", "d2", "d3", "h1", "h2", "h3", "h4", "h5", "h6", "h7"];
    let members: Vec<network::SessionPeer> = names.iter().map(|n| session(n, true)).collect();
    let tx = (9..=255)
        .map(|seed| signed_tx(seed, 0))
        .find(|t| members_for(&sender_of(t), &members)[..3] == ["d1", "d2", "d3"])
        .expect("a sender whose rotation starts at the three droppers");
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let honest = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&honest);
    let client = fake_network(members.clone(), move |peer, wire| match peer {
        "d1" | "d2" | "d3" => answer_all(wire, Verdict::Accepted("dropped".into())),
        _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
    });
    let state = ForwardState::default();
    let held = |m: &Arc<Mutex<Mempool>>| m.lock().unwrap().get_all_pending().contains(&tx);
    let now = 3_000_000;
    assert_eq!(forward_once_at(&observer, &client, &state, now).await, 1);
    assert!(!held(&honest), "control: a dropper took it");
    forward_once_at(&observer, &client, &state, now + FORWARD_RETRY_SECS).await;
    assert!(held(&honest), "the re-forward stopped at the droppers");
}

/// B183 witness: the smallest transaction whose two signatures a member
/// checks (sponsored: the sender's, which verifies, then the paymaster's)
/// takes two checks' worth of `MIN_WIRE_PER_CHECK` as a batch element, built
/// at its shortest: a one-byte chain id, an empty module bundle, the
/// sequence number left out, the gas limit just covering its canonical
/// bytes. The bound was 408 bytes a transaction, so a sponsored one bought
/// its second check free.
#[test]
fn the_smallest_sponsored_transaction_pays_for_both_checks() {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let payload =
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![])).unwrap());
    assert_eq!(payload.len(), 4, "not the shortest payload");
    let build = |gas_limit: u64, sponsored: bool| {
        let mut tx = executor::Transaction {
            chain_id: "X".into(),
            sender: sender.clone(),
            input_objects: vec![],
            payload: payload.clone(),
            args: vec![],
            gas_limit,
            gas_price: 1,
            sequence_number: 0,
            public_key: public_key.clone(),
            signature: String::new(),
            paymaster: sponsored.then(|| public_key.clone()),
            paymaster_signature: sponsored.then(|| "0".repeat(128)),
            zkp_proof: None,
        };
        let message = executor::admission::signing_message(&tx);
        tx.signature = hex::encode(key.sign(message.as_bytes()).to_bytes());
        let mut raw = format!(
            r#"{{"chain_id":"X","sender":"{}","input_objects":[],"payload":"{}","gas_limit":{},"gas_price":1,"public_key":"{}","signature":"{}""#,
            tx.sender, tx.payload, tx.gas_limit, tx.public_key, tx.signature
        );
        if sponsored {
            raw.push_str(&format!(
                r#","paymaster":"{public_key}","paymaster_signature":"{}""#,
                "0".repeat(128)
            ));
        }
        raw.push('}');
        raw
    };
    // What `check_admissible` runs, under a one-byte chain id.
    let admit = |raw: &str| {
        let canonical = executor::admission::canonicalize(raw)?;
        executor::admission::check_stateless(&canonical, "X").map(|_| ())
    };
    let smallest = |sponsored: bool| {
        let mut gas = 1;
        loop {
            let raw = build(gas, sponsored);
            let canonical = executor::admission::canonicalize(&raw).unwrap();
            let need = executor::admission::intrinsic_gas(canonical.len());
            if gas >= need {
                return raw;
            }
            gas = need;
        }
    };
    let element = |raw: &str| serde_json::to_string(raw).unwrap().len() + 1;
    let (one, two) = (smallest(false), smallest(true));
    assert_eq!(admit(&one), Ok(()), "one check: admitted");
    let why = admit(&two).unwrap_err();
    assert!(why.contains("Invalid paymaster signature"), "{why}");
    assert_eq!((element(&one), element(&two)), (413, 653));
    assert!(element(&one) >= MIN_WIRE_PER_CHECK);
    assert!(
        element(&two) >= 2 * MIN_WIRE_PER_CHECK,
        "a sponsored transaction's second check is free"
    );
}

/// B201/B216/B232 witness: refusals for now (the fee, the pool's room, a
/// nonce gap, the payer's balance) never drop a transaction (two from members
/// over a third of the stake dropped it for good, after the RPC had answered
/// "sent"); each member is asked once a pass, and again only once the loan
/// is stale, not every pass. The same members' refusals for good still drop
/// it.
#[tokio::test]
async fn a_refusal_for_now_drops_nothing() {
    let members: Vec<network::SessionPeer> = ["l1", "l2", "l3"]
        .iter()
        .map(|n| session(n, true))
        .collect();
    let tx = signed_tx(61, 0);
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    let state = ForwardState::with_stakes(
        members
            .iter()
            .map(|s| (s.member.clone().unwrap(), 100))
            .collect(),
    );
    let held = |observer: &Arc<Mutex<Mempool>>| {
        let mp = observer.lock().unwrap();
        mp.any_pending(|p| *p == tx)
    };
    let asks = Arc::new(Mutex::new(0usize));
    let counted = Arc::clone(&asks);
    let later = fake_network(members.clone(), move |_, wire| {
        *counted.lock().unwrap() += 1;
        answer_all(wire, Verdict::Later("Mempool full".into()))
    });
    let t0 = 1_000_000;
    assert_eq!(forward_once_at(&observer, &later, &state, t0).await, 0);
    assert_eq!(
        *asks.lock().unwrap(),
        3,
        "not asked of each member once in the pass"
    );
    forward_once_at(&observer, &later, &state, t0 + 1).await;
    assert_eq!(
        *asks.lock().unwrap(),
        3,
        "asked again before its loan was stale"
    );
    forward_once_at(&observer, &later, &state, t0 + FORWARD_RETRY_SECS + 1).await;
    assert_eq!(*asks.lock().unwrap(), 6, "never asked again");
    assert!(held(&observer), "refusals for now dropped it");
    let refused = fake_network(members.clone(), |_, wire| {
        answer_all(wire, Verdict::Refused("used".into()))
    });
    forward_once_at(&observer, &refused, &state, t0 + 3 * FORWARD_RETRY_SECS).await;
    assert!(!held(&observer), "vacuous: refusals for good kept it");
}

/// B453 witness: a fee-bumped replacement whose original every member holds
/// on loan to a vertex is refused for now, not for good: the observer keeps
/// it, and once the original comes back unrun at a member, the replacement
/// asked again replaces it there. The refusal was for good, so members over
/// a third of the stake holding the original on loan dropped the
/// replacement after the RPC had answered "sent".
#[tokio::test]
async fn a_replacement_of_a_transaction_on_loan_is_kept() {
    let original = signed_tx_priced(62, 0, 1);
    let bump = signed_tx_priced(62, 0, 2);
    let names = ["l1", "l2"];
    let members: Vec<network::SessionPeer> = names.iter().map(|n| session(n, true)).collect();
    // Each member holds the original on loan to a vertex.
    let pools: Vec<Arc<Mutex<Mempool>>> = names
        .iter()
        .map(|_| {
            let mut mp = Mempool::new();
            mp.add_transaction(original.clone()).unwrap();
            assert_eq!(
                mp.get_pending_transactions_at(1, 100),
                std::slice::from_ref(&original),
                "vacuous: the original is not on loan"
            );
            Arc::new(Mutex::new(mp))
        })
        .collect();
    let asked = submit(std::slice::from_ref(&bump));
    let v = verdicts(&serve_tx_submit(&pools[0], &asked).unwrap());
    assert!(
        matches!(&v[0], Verdict::Later(r) if r.contains("on loan")),
        "{v:?}"
    );
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(bump.clone())
        .unwrap();
    let (s1, s2) = (Arc::clone(&pools[0]), Arc::clone(&pools[1]));
    let client = fake_network(members, move |peer, wire| {
        let pool = if peer == "l1" { &s1 } else { &s2 };
        serve_tx_submit(pool, wire).ok_or_else(|| "refused".into())
    });
    let state = ForwardState::default();
    let t0 = 1_000_000;
    assert_eq!(forward_once_at(&observer, &client, &state, t0).await, 0);
    assert!(
        observer.lock().unwrap().any_pending(|p| *p == bump),
        "refused while its original was on loan: dropped"
    );
    // No block settled the original: back from its loan at every member.
    for pool in &pools {
        assert_eq!(pool.lock().unwrap().requeue_stale_at(30, 130), 1);
    }
    let stale = t0 + FORWARD_RETRY_SECS + 1;
    assert_eq!(
        forward_once_at(&observer, &client, &state, stale).await,
        1,
        "not asked again once its loan was stale"
    );
    let replaced = |pool: &Arc<Mutex<Mempool>>| {
        pool.lock().unwrap().get_all_pending() == std::slice::from_ref(&bump)
    };
    assert!(
        pools.iter().any(replaced),
        "the replacement did not replace the original"
    );
}

/// B251 witness: a forwarder that named `MAX_MEMBER_IDS` members over its
/// life still records a new member's verdicts once the records naming the
/// old ones are gone (ids were given for good, and from then on a new
/// member's refusals counted toward no drop), and an id a live record still
/// names is not given again.
#[test]
fn member_ids_no_record_names_are_given_again() {
    let state = ForwardState::default();
    let tx = |i: usize| format!("tx-{i}");
    state.record(&tx(0), 1);
    let (_, kept) = state.note(&tx(0), "member-0", false);
    assert!(state.names(&kept, "member-0"));
    for i in 1..MAX_MEMBER_IDS {
        state.record(&tx(i), 1);
        state.note(&tx(i), &format!("member-{i}"), false);
    }
    let gone: Vec<String> = (1..MAX_MEMBER_IDS).map(tx).collect();
    state.forget(&gone);
    state.record(&tx(MAX_MEMBER_IDS), 2);
    let (_, refused) = state.note(&tx(MAX_MEMBER_IDS), "newcomer", false);
    assert!(
        state.names(&refused, "newcomer"),
        "a new member's refusal was recorded nowhere"
    );
    assert!(
        !state.names(&refused, "member-0"),
        "an id a live record names was given again"
    );
    let (_, still) = state.note(&tx(0), "member-0", false);
    assert!(state.names(&still, "member-0"));
    assert!(!state.names(&still, "newcomer"));
}

/// B259 witness: a submit batch lets a waiting consensus thread take the
/// pool's lock before each admission (`std::sync::Mutex` is not fair: the
/// batch took the lock again at once, and the proposal, under the consensus
/// lock, waited for the whole batch).
#[test]
fn a_submit_batch_yields_to_a_waiting_consensus_thread() {
    let member = Mutex::new(Mempool::new());
    let wire = submit(&[signed_tx(9, 0)]);
    let done = AtomicBool::new(false);
    let waiting = mempool::ConsensusWaiting::begin();
    std::thread::scope(|s| {
        let served = s.spawn(|| {
            let reply = serve_tx_submit(&member, &wire);
            done.store(true, Ordering::SeqCst);
            reply
        });
        std::thread::sleep(Duration::from_millis(100));
        let early = done.load(Ordering::SeqCst);
        drop(waiting);
        let reply = served.join().unwrap().expect("an answer");
        assert!(!early, "a submit went before a waiting consensus thread");
        assert!(
            matches!(verdicts(&reply)[0], Verdict::Accepted(_)),
            "vacuous: {reply}"
        );
    });
}

/// B475 witness: the checks of transactions from outside (an RPC send's, a
/// submit batch's) let a waiting consensus thread take the pool's lock
/// before their dedup lookups, as an admission does (B259): every RPC send
/// took it at once.
#[test]
fn outside_checks_yield_to_a_waiting_consensus_thread() {
    let pool = Mutex::new(Mempool::new());
    let tx = signed_tx(9, 1);
    let done = AtomicBool::new(false);
    let waiting = mempool::ConsensusWaiting::begin();
    std::thread::scope(|s| {
        let checking = s.spawn(|| {
            let checked = check_from_outside(&pool, vec![tx.clone()]);
            done.store(true, Ordering::SeqCst);
            checked
        });
        std::thread::sleep(Duration::from_millis(100));
        let early = done.load(Ordering::SeqCst);
        drop(waiting);
        let checked = checking.join().unwrap();
        assert!(
            !early,
            "outside checks went before a waiting consensus thread"
        );
        assert!(
            checked[0].is_ok(),
            "vacuous: {:?}",
            checked[0].as_ref().err()
        );
    });
}

/// B462: a pool on a database of its own in which the keys of `seeds` hold
/// an account and plenty of AIN, so its gates and its evictions run.
fn funded_pool(seeds: &[u8]) -> Arc<Mutex<Mempool>> {
    let db = Arc::new(
        storage::StateDB::open(&storage::test_dir::test_dir_str("forward_pool"))
            .expect("a test database"),
    );
    for &seed in seeds {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        executor::test_support::set_sequence_number(
            &db,
            &sender,
            &hex::encode(key.verifying_key().to_bytes()),
            0,
        );
        executor::test_support::set_ain_balance(&db, &sender, 10u128.pow(30));
    }
    Arc::new(Mutex::new(Mempool::with_storage(db)))
}

/// B462 witness: what members over a third of the stake refused for now
/// holds no room at an observer: deferred, a ready transaction evicts it
/// from a pool full by its bytes, though a member was down and the
/// transaction went back to the queue to ask it (B247); a minority's
/// refusals for now defer nothing; taken by a member, it holds its room
/// again. Kept to their TTL and never evicted, transactions the members
/// refused only for now (their payer short there, by a transaction only
/// they held) filled an observer's pool, and its RPC answered every user
/// "Mempool full".
#[tokio::test]
async fn what_members_refused_for_now_holds_no_room() {
    let (filler, first, second) = (63u8, 64u8, 66u8);
    let observer = funded_pool(&[filler, first, second]);
    let admit = |tx: &String| observer.lock().unwrap().add_transaction(tx.clone());
    let mut held = 0;
    for seq in 0..mempool::MAX_NONCE_AHEAD - 1 {
        if admit(&signed_publish(filler, seq, 1, vec![seq as u8; 45 * 1024])).is_err() {
            break;
        }
        held += 1;
    }
    // A KiB more than a filler, so neither fits the room a filler left.
    let newcomer = |seed: u8| signed_publish(seed, 0, 1, vec![seed; 46 * 1024]);
    let (one, two) = (newcomer(first), newcomer(second));
    let full = admit(&one).unwrap_err();
    assert!(full.contains("bytes held"), "vacuous: {full} ({held} held)");
    let members = vec![session("m1", true), session("m2", true), session("m3", true)];
    let state = ForwardState::default();
    let t0 = 1_000_000;
    // One member refuses for now, the others are down: a minority.
    let minority = fake_network(members.clone(), |peer, wire| match peer {
        "m1" => answer_all(wire, Verdict::Later("Insufficient balance".into())),
        _ => Err("gone".into()),
    });
    forward_once_at(&observer, &minority, &state, t0).await;
    let full = admit(&one).unwrap_err();
    assert!(
        full.contains("bytes held"),
        "one member's refusal for now deferred it: {full}"
    );
    // Two of the three refuse for now, the third is down.
    let refusing = fake_network(members.clone(), |peer, wire| match peer {
        "m3" => Err("gone".into()),
        _ => answer_all(wire, Verdict::Later("Insufficient balance".into())),
    });
    forward_once_at(&observer, &refusing, &state, t0 + FORWARD_RETRY_SECS).await;
    admit(&one).expect("refused for room held by what members refused for now");
    // The members take them: they hold their room again.
    let taking = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&taking);
    let accepting = fake_network(members, move |peer, wire| match peer {
        "m3" => Err("gone".into()),
        _ => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
    });
    forward_once_at(&observer, &accepting, &state, t0 + 2 * FORWARD_RETRY_SECS).await;
    let full = admit(&two).unwrap_err();
    assert!(
        full.contains("bytes held"),
        "what the members took stayed deferred: {full}"
    );
}

/// B476 witness: through an observer, a fee-bumped replacement takes the
/// place of an original the observer is forwarding, and replaces it at the
/// member that took it. The observer refused it while the original was on
/// loan (to its forwarder, in no vertex) and re-queued and loaned the
/// original again in one lock hold every `FORWARD_RETRY_SECS`, so no
/// replacement got in until the original ran, was refused for good or
/// reached its TTL.
#[tokio::test]
async fn a_replacement_takes_the_place_of_an_original_being_forwarded() {
    let original = signed_tx_priced(65, 0, 1);
    let bump = signed_tx_priced(65, 0, 2);
    let observer = Arc::new(Mutex::new(Mempool::new()));
    observer
        .lock()
        .unwrap()
        .add_transaction(original.clone())
        .unwrap();
    let member = Arc::new(Mutex::new(Mempool::new()));
    let served = Arc::clone(&member);
    let client = fake_network(vec![session("m", true)], move |_, wire| {
        serve_tx_submit(&served, wire).ok_or_else(|| "refused".into())
    });
    let state = ForwardState::default();
    let t0 = 1_000_000;
    assert_eq!(forward_once_at(&observer, &client, &state, t0).await, 1);
    assert!(
        observer.lock().unwrap().any_pending(|p| *p == original),
        "vacuous: the original is not on loan"
    );
    observer
        .lock()
        .unwrap()
        .add_transaction(bump.clone())
        .expect("a fee bump of an original being forwarded");
    {
        let o = observer.lock().unwrap();
        assert!(
            !o.any_pending(|p| *p == original),
            "the original stayed beside its replacement"
        );
        assert_eq!(o.get_all_pending(), std::slice::from_ref(&bump));
    }
    assert_eq!(forward_once_at(&observer, &client, &state, t0 + 1).await, 1);
    assert_eq!(
        member.lock().unwrap().get_all_pending(),
        std::slice::from_ref(&bump),
        "the member kept the original"
    );
}
