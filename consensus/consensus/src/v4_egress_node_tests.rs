use super::*;
use network::Outbound;
use std::time::Duration;
use tokio::sync::mpsc;

async fn receive(rx: &mut mpsc::Receiver<Outbound>) -> Outbound {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn r35_verified_conflict_pair_reaches_other_nodes_after_saturation() {
    let mut c = Cluster::new("r35-conflict", &[131, 132, 133, 134], true);
    c.run(6);
    let author = c.known[1].0.clone();
    let forged = forge_cert(&c, 1, &author, &"cd".repeat(32), &[131, 132, 133]);
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(Outbound::Broadcast("blocked-network".into()))
        .unwrap();
    c.node_mut(0).v4_outbox = None;
    c.node_mut(0).p2p_tx = Some(tx.clone());
    let wire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Cert(forged)).unwrap()
    );
    c.node_mut(0).handle_message(&wire);
    assert!(c.node(0).ordering_halted().is_some());
    for _ in 0..64 {
        c.node_mut(0).handle_message(&wire);
    }
    assert!(
        tx.strong_count() <= 3,
        "conflict relay spawned unbounded workers"
    );
    assert_eq!(receive(&mut rx).await.wire(), "blocked-network");
    let pair = [receive(&mut rx).await, receive(&mut rx).await];
    for out in &pair {
        assert!(matches!(out, Outbound::Broadcast(_)));
        assert!(matches!(
            serde_json::from_str::<crate::v4::Msg>(
                out.wire().strip_prefix(crate::v4::WIRE_PREFIX).unwrap()
            )
            .unwrap(),
            crate::v4::Msg::Cert(_)
        ));
        for i in 1..4 {
            c.node_mut(i).handle_message(out.wire());
        }
    }
    for i in 0..4 {
        assert!(
            c.node(i).ordering_halted().is_some(),
            "recipient {i} missed alarm"
        );
        let row = crate::v4::evidence::cert_seen_key(&author, 0, 1);
        let item = c.node(i).storage.get(&row).unwrap().unwrap();
        c.node(i).executor.verify_slash_evidence(&item).unwrap();
    }
}

#[tokio::test(flavor = "current_thread")]
async fn r35_real_channel_qc_answer_preserves_slow_requester() {
    let mut c = Cluster::with_interval("r35-qc-fair", &[75, 76, 77, 78], true, 4);
    c.run_until(400, |c| c.node(1).latest_block_height >= 4);
    assert!(c.node(1).latest_block_height >= 4);
    for h in 1..=4 {
        c.node(1)
            .storage
            .put(&format!("consensus:qc:{h}"), "{\"stand_in_for_qc\":1}")
            .unwrap();
    }
    for _ in 0..6 {
        c.node_mut(1).try_create_vertex();
    }
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(Outbound::Broadcast("blocked-network".into()))
        .unwrap();
    let node = c.node_mut(1);
    node.v4_outbox = None;
    node.p2p_tx = Some(tx);
    for _ in 0..32 {
        for h in 1..=4 {
            node.handle_message_from("greedy", &format!("{}{h}", crate::dag::QC_WANT_PREFIX));
        }
    }
    node.handle_message_from("slow", &format!("{}1", crate::dag::QC_WANT_PREFIX));
    assert_eq!(receive(&mut rx).await.wire(), "blocked-network");
    let mut greedy = 0;
    let mut slow = 0;
    for index in 0..5 {
        match receive(&mut rx).await {
            Outbound::To { address, wire } => {
                assert!(wire.starts_with(crate::dag::QC_CERT_PREFIX));
                match address.as_str() {
                    "greedy" => greedy += 1,
                    "slow" => {
                        slow += 1;
                        assert!(index <= 2, "slow answer starved");
                    }
                    _ => panic!("wrong recipient"),
                }
            }
            _ => panic!("addressed QC response was broadcast"),
        }
    }
    assert_eq!((greedy, slow), (4, 1));
}

async fn drain(c: &mut Cluster, receivers: &mut [mpsc::Receiver<Outbound>]) {
    for _ in 0..256 {
        tokio::task::yield_now().await;
        let mut batch = Vec::new();
        for (source, rx) in receivers.iter_mut().enumerate() {
            while let Ok(out) = rx.try_recv() {
                batch.push((source, out));
            }
        }
        if batch.is_empty() {
            return;
        }
        for (source, out) in batch {
            let from = c.known[source].0.clone();
            for dest in 0..4 {
                if dest == source {
                    continue;
                }
                let deliver = match &out {
                    Outbound::Broadcast(_) => true,
                    Outbound::To { address, .. } => address == &c.known[dest].0,
                };
                if deliver {
                    c.node_mut(dest).handle_message_from(&from, out.wire());
                }
            }
        }
    }
    panic!("bounded real-channel drain failed to settle");
}

#[tokio::test(flavor = "current_thread")]
async fn r35_real_channel_recovers_after_stall_and_lost_messages() {
    let mut c = Cluster::new("r35-recovery", &[141, 142, 143, 144], true);
    c.run(6);
    let before = (0..4).map(|i| c.node(i).latest_block_height).max().unwrap();
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    for i in 0..4 {
        let (tx, rx) = mpsc::channel(1);
        tx.try_send(Outbound::Broadcast("blocked-network".into()))
            .unwrap();
        c.node_mut(i).v4_outbox = None;
        c.node_mut(i).p2p_tx = Some(tx.clone());
        receivers.push(rx);
        senders.push(tx);
    }
    for _ in 0..12 {
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        tokio::task::yield_now().await;
    }
    for tx in &senders {
        assert!(tx.strong_count() <= 3);
    }
    // Lose already-buffered traffic, then restore delivery. No retry settings change.
    for rx in &mut receivers {
        while rx.try_recv().is_ok() {}
    }
    for _ in 0..120 {
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        drain(&mut c, &mut receivers).await;
        if (0..4).all(|i| c.node(i).latest_block_height >= before + 3) {
            break;
        }
    }
    c.assert_same_blocks(before + 3);
    for (i, tx) in senders.iter().enumerate() {
        let height = c.node(i).latest_block_height;
        let qc = c.qc(i, height).expect("missing stored QC after recovery");
        crate::qc::verify_qc(&qc, &c.committee, &crate::qc::expected_chain_id()).unwrap();
        assert!(c.node(i).ordering_halted().is_none());
        assert!(tx.strong_count() <= 3);
    }
}
