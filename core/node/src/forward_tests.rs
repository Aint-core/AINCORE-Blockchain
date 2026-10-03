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
/// past a member that is down; a transaction the member refuses is dropped;
/// with no member answering, everything goes back to the queue in order.
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
    let member = Arc::new(Mutex::new(Mempool::new()));
    // The member already holds the third: it refuses it as a duplicate.
    member
        .lock()
        .unwrap()
        .add_transaction(txs[2].clone())
        .unwrap();
    let sessions = vec![
        session("down", true),
        session("up", true),
        session("obs", false),
    ];
    let served = Arc::clone(&member);
    let asked = Arc::new(Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&asked);
    let client = fake_network(sessions, move |peer, wire| {
        log.lock().unwrap().push(peer.to_string());
        match peer {
            "up" => serve_tx_submit(&served, wire).ok_or_else(|| "refused".into()),
            _ => Err("connection reset".into()),
        }
    });
    assert_eq!(forward_once(&observer, &client).await, 2);
    {
        let m = member.lock().unwrap();
        let held: Vec<&String> = m.get_all_pending().iter().collect();
        assert_eq!(held.len(), 3, "{held:?}");
        assert!(txs.iter().all(|t| held.contains(&t)));
    }
    {
        let o = observer.lock().unwrap();
        assert!(o.is_empty(), "everything was loaned out");
        let raw = |t: &str| storage::StateDB::raw_tx_hash(t);
        assert!(
            o.any_pending(|t| raw(t) == raw(&txs[0])),
            "accepted: on loan until a block"
        );
        assert!(
            !o.any_pending(|t| raw(t) == raw(&txs[2])),
            "refused: dropped"
        );
        assert!(
            asked.lock().unwrap().iter().any(|p| p == "up"),
            "the member that answered was asked"
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
