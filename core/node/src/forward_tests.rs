use super::*;

fn signed_tx(seed: u8, seq: u64) -> String {
    use ed25519_dalek::Signer;
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let payload = vm_move::TransactionPayload::PublishModule(vec![vec![seed, seq as u8]]);
    let mut tx = serde_json::json!({
        "chain_id": blockchain::chain_id(),
        "sender": sender,
        "input_objects": [],
        "payload": hex::encode(bcs::to_bytes(&payload).unwrap()),
        "args": [],
        "gas_price": 1,
        "sequence_number": seq,
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "gas_limit": 0,
        "signature": "00".repeat(64),
    });
    let unsized_len = tx.to_string().len();
    tx["gas_limit"] = serde_json::json!(executor::admission::gas_limit_covering(
        unsized_len,
        100_000
    ));
    let parsed: executor::Transaction = serde_json::from_value(tx.clone()).unwrap();
    let message = executor::admission::signing_message(&parsed);
    tx["signature"] = serde_json::json!(hex::encode(key.sign(message.as_bytes()).to_bytes()));
    tx.to_string()
}

fn submit(txs: &[String]) -> String {
    format!("{TX_SUBMIT}{}", serde_json::to_string(txs).unwrap())
}

fn verdicts(reply: &str) -> Vec<Verdict> {
    serde_json::from_str(reply.strip_prefix(TX_RESULT).unwrap()).unwrap()
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

/// A fake network task: every request to `peer` is answered by `answer`.
fn fake_network(
    sessions: Vec<network::SessionPeer>,
    mut answer: impl FnMut(&str, &str) -> Result<String, String> + Send + 'static,
) -> network::SessionClient {
    let (asks_tx, mut asks) = tokio::sync::mpsc::channel::<network::SyncAsk>(8);
    let (dials_tx, _dials) = tokio::sync::mpsc::channel::<network::SyncDial>(8);
    tokio::spawn(async move {
        while let Some(ask) = asks.recv().await {
            let _ = ask.reply.send(answer(&ask.peer, &ask.wire));
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
    assert_eq!(forward_once(&observer, &client).await, 2);
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

    // Nobody answers: the batch returns to the front of the queue, in order.
    let lonely = Arc::new(Mutex::new(Mempool::new()));
    for tx in &txs {
        lonely.lock().unwrap().add_transaction(tx.clone()).unwrap();
    }
    let before: Vec<String> = lonely
        .lock()
        .unwrap()
        .get_all_pending()
        .iter()
        .cloned()
        .collect();
    let dead = fake_network(vec![session("down", true)], |_, _| Err("timeout".into()));
    assert_eq!(forward_once(&lonely, &dead).await, 0);
    let after: Vec<String> = lonely
        .lock()
        .unwrap()
        .get_all_pending()
        .iter()
        .cloned()
        .collect();
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
    assert_eq!(forward_once(&observer, &client).await, 1);
    assert!(honest
        .lock()
        .unwrap()
        .get_all_pending()
        .iter()
        .any(|p| *p == tx));
}

/// B39 review witness: a transaction one member refuses in every pass,
/// its other member silent, is dropped after the mempool's requeue cap.
/// Returned as unshipped, it was forwarded every pass forever.
#[tokio::test]
async fn a_transaction_refused_in_every_pass_is_dropped_at_the_requeue_cap() {
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
    assert_eq!(forward_once(&observer, &client).await, 0);
    assert!(waiting(&observer), "one refusal does not drop it");
    let mut passes = 1;
    while waiting(&observer) {
        assert!(passes < 10, "still forwarded after {passes} passes");
        forward_once(&observer, &client).await;
        passes += 1;
    }
}
