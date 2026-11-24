use super::*;
use crypto::Signer;
use network::Outbound;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

const FUNDS: u128 = 1_000_000_000_000;
const RECIPIENT_FUNDS: u128 = 123;
const AMOUNT: u128 = 12_345;
const FILLER: &str = "r39-synthetic-backlog";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    Transfer,
    CoinAbort,
    WriteGasAbort,
}

impl Case {
    fn gas_limit(self) -> u64 {
        match self {
            Self::Transfer => 2_000_000,
            Self::CoinAbort | Self::WriteGasAbort => 1_000_000,
        }
    }
}

fn signed_transfer(sender: &str, recipient: &str, case: Case) -> String {
    let key = crypto::SigningKey::from_bytes(&[77; 32]);
    let mut tx = executor::Transaction {
        chain_id: blockchain::chain_id(),
        sender: sender.to_string(),
        input_objects: vec![],
        payload: executor::test_support::ain_transfer_payload(
            sender,
            recipient,
            if case == Case::CoinAbort {
                FUNDS + 1
            } else {
                AMOUNT
            },
        ),
        args: vec![],
        gas_limit: case.gas_limit(),
        gas_price: 1,
        sequence_number: 0,
        public_key: hex::encode(key.verifying_key().to_bytes()),
        signature: String::new(),
        paymaster: None,
        paymaster_signature: None,
        zkp_proof: None,
    };
    tx.signature = hex::encode(
        key.sign(executor::admission::signing_message(&tx).as_bytes())
            .to_bytes(),
    );
    executor::admission::canonical_json(&tx)
}

fn receipt(c: &Cluster, i: usize, id: &str) -> Option<serde_json::Value> {
    c.node(i)
        .storage
        .get(&format!("tx_receipt:{id}"))
        .unwrap()
        .map(|raw| serde_json::from_str(&raw).unwrap())
}

fn carrying(c: &Cluster, i: usize, tx: &str) -> Vec<u64> {
    (1..=c.node(i).latest_block_height)
        .filter(|h| {
            let raw = c
                .node(i)
                .storage
                .get(&format!("block_{h}"))
                .unwrap()
                .unwrap();
            let block: blockchain::Block = serde_json::from_str(&raw).unwrap();
            block.transactions.iter().any(|item| item == tx)
        })
        .collect()
}

async fn drain(c: &mut Cluster, receivers: &mut [mpsc::Receiver<Outbound>]) {
    // Yielding twice avoids mistaking a just-woken sender for a drained queue.
    let mut empty = 0;
    for _ in 0..256 {
        tokio::task::yield_now().await;
        let mut batch = Vec::new();
        for (from, rx) in receivers.iter_mut().enumerate() {
            while let Ok(out) = rx.try_recv() {
                batch.push((from, out));
            }
        }
        if batch.is_empty() {
            empty += 1;
            if empty == 2 {
                return;
            }
            continue;
        }
        empty = 0;
        for (from, out) in batch {
            if out.wire() == FILLER {
                continue;
            }
            let source = c.known[from].0.clone();
            for to in 0..4 {
                if to == from {
                    continue;
                }
                let deliver = match &out {
                    Outbound::Broadcast(_) => true,
                    Outbound::To { address, .. } => address == &c.known[to].0,
                };
                if deliver {
                    c.node_mut(to).handle_message_from(&source, out.wire());
                }
            }
        }
    }
    panic!("real-channel delivery did not settle within the original 256 turns");
}

fn assert_accounting(c: &Cluster, tx: &str, sender: &str, recipient: &str, case: Case) -> u64 {
    let id = hex::encode(crypto::hash(tx.as_bytes()));
    let places = carrying(c, 0, tx);
    assert_eq!(places.len(), 1, "transaction must be in exactly one block");
    let height = places[0];
    c.assert_same_blocks(height);
    let first = receipt(c, 0, &id).expect("stored receipt");
    assert_eq!(
        first["status"],
        if case == Case::Transfer {
            "success"
        } else {
            "aborted"
        },
        "case {case:?}: {first}"
    );
    assert_eq!(first["gas_charged"], case.gas_limit().to_string());
    match case {
        Case::Transfer => assert!(first["error"].is_null()),
        Case::CoinAbort => {
            let error = first["error"].as_str().expect("Move abort explanation");
            assert!(
                error.contains("status ABORTED with sub status 65537")
                    && error.contains("Identifier(\"coin\")"),
                "wrong abort: {error}"
            );
        }
        Case::WriteGasAbort => {
            let error = first["error"].as_str().expect("write gas explanation");
            assert!(
                error.contains("out of gas: execution used")
                    && error.contains("the writes cost")
                    && error.contains("the limit leaves 684400"),
                "wrong under-gas path: {error}"
            );
        }
    }
    let transferred = if case == Case::Transfer { AMOUNT } else { 0 };
    for i in 0..4 {
        assert_eq!(carrying(c, i, tx), places, "node {i} duplicate placement");
        assert_eq!(receipt(c, i, &id), Some(first.clone()), "node {i} receipt");
        assert_eq!(
            executor::test_support::ain_balance(&c.node(i).storage, sender),
            Some(FUNDS - transferred - case.gas_limit() as u128),
            "node {i} sender"
        );
        assert_eq!(
            executor::test_support::ain_balance(&c.node(i).storage, recipient),
            Some(RECIPIENT_FUNDS + transferred),
            "node {i} recipient"
        );
        assert_eq!(
            executor::committed_sequence_number(&c.node(i).storage, sender),
            1
        );
        let qc = c.qc(i, height).expect("stored QC at transaction height");
        crate::qc::verify_qc(&qc, &c.committee, &crate::qc::expected_chain_id()).unwrap();
        assert!(c.node(i).ordering_halted().is_none());
    }
    height
}

async fn exercise(case: Case, saturated: bool) {
    let sender = tier2_keypair(77).0;
    let recipient = tier2_keypair(78).0;
    let tag = format!("r39-transactions-{case:?}-{saturated}");
    let mut c = Cluster::with_funded(
        &tag,
        &[141, 142, 143, 144],
        true,
        1000,
        vec![
            (sender.clone(), FUNDS),
            (recipient.clone(), RECIPIENT_FUNDS),
        ],
    );
    c.run(6);
    let now = Arc::new(AtomicU64::new(PINNED));
    let tx = signed_transfer(&sender, &recipient, case);
    executor::admission::check_stateless(&tx, &blockchain::chain_id()).unwrap();
    let id = hex::encode(crypto::hash(tx.as_bytes()));
    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for i in 0..4 {
        assert!(c
            .node(i)
            .v4_outbox
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .is_empty());
        let clock = now.clone();
        c.node_mut(i)
            .set_now_secs(Arc::new(move || clock.load(Ordering::SeqCst)));
        let (sender, receiver) = mpsc::channel(1);
        c.node_mut(i).v4_outbox = None;
        c.node_mut(i).p2p_tx = Some(sender.clone());
        if saturated {
            sender.try_send(Outbound::Broadcast(FILLER.into())).unwrap();
            // No await: the only worker cannot drain before the actual proposal.
            let mut accepted = 0;
            while c
                .node(i)
                .test_admit_v4_outbound(Outbound::Broadcast(FILLER.into()))
            {
                accepted += 1;
                assert!(accepted <= 64, "ordinary queue bound changed");
            }
            assert_eq!(accepted, 64, "must hit actual per-route overflow");
            assert_eq!(sender.capacity(), 0);
        }
        senders.push(sender);
        receivers.push(receiver);
    }
    c.node(0)
        .mempool
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .unwrap();
    for i in 0..4 {
        c.node_mut(i).try_create_vertex();
    }
    let proposal = c
        .node(0)
        .dag
        .lock()
        .unwrap()
        .values()
        .find(|v| v.author == c.known[0].0 && v.payload.contains(&tx))
        .cloned()
        .expect("the transaction was actually proposed during the stall");
    for (i, channel) in senders.iter().enumerate() {
        assert!(receipt(&c, i, &id).is_none());
        assert_eq!(
            executor::committed_sequence_number(&c.node(i).storage, &sender),
            0
        );
        assert_eq!(
            executor::test_support::ain_balance(&c.node(i).storage, &sender),
            Some(FUNDS)
        );
        assert!(channel.strong_count() <= 3, "per-emission waiting tasks");
    }
    if saturated {
        assert!(!c
            .node(0)
            .test_admit_v4_outbound(Outbound::Broadcast(FILLER.into())));
        // Let the blocked worker poll, then release only synthetic backlog. The
        // lost payload is never re-injected before ordinary recovery commits it.
        tokio::task::yield_now().await;
        for rx in &mut receivers {
            assert_eq!(rx.try_recv().unwrap().wire(), FILLER);
        }
    }
    let mut inclusion = None;
    for tick in 1..=20 {
        now.store(PINNED + tick * 3, Ordering::SeqCst);
        drain(&mut c, &mut receivers).await;
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        drain(&mut c, &mut receivers).await;
        if (0..4).all(|i| {
            receipt(&c, i, &id).is_some()
                && carrying(&c, i, &tx)
                    .first()
                    .is_some_and(|h| c.qc(i, *h).is_some())
        }) {
            inclusion = Some(tick * 3);
            break;
        }
    }
    let elapsed = inclusion.expect("transaction/QCs did not recover within 60 virtual seconds");
    let height = assert_accounting(&c, &tx, &sender, &recipient, case);
    let saved: Vec<_> = (0..4).map(|i| receipt(&c, i, &id)).collect();
    let replay = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Vertex(proposal)).unwrap()
    );
    for i in 0..4 {
        // Direct mempool insertion intentionally bypasses the RPC admission
        // rejection to exercise the final execution/replay guard as well.
        let _ = c
            .node(i)
            .mempool
            .lock()
            .unwrap()
            .add_transaction(tx.clone());
        let author = c.known[0].0.clone();
        c.node_mut(i).handle_message_from(&author, &replay);
    }
    for tick in 1..=12 {
        now.store(PINNED + elapsed + tick * 3, Ordering::SeqCst);
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        drain(&mut c, &mut receivers).await;
    }
    assert_eq!(
        assert_accounting(&c, &tx, &sender, &recipient, case),
        height
    );
    c.assert_same_blocks(height + 2);
    for (i, sender) in senders.iter().enumerate() {
        assert_eq!(receipt(&c, i, &id), saved[i], "replay rewrote receipt");
        assert!(sender.strong_count() <= 3);
    }
    eprintln!("R39 case={case:?} saturated={saturated} inclusion_virtual_seconds={elapsed} height={height} accounting=exactly_once");
    drop(c);
    drop(receivers);
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        senders.iter().all(|s| s.strong_count() == 1),
        "sender worker survived cleanup"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn r39_native_transfer_loss_free_control() {
    exercise(Case::Transfer, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r39_charged_abort_loss_free_control() {
    exercise(Case::CoinAbort, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r39_native_transfer_recovers_after_full_egress() {
    exercise(Case::Transfer, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r39_charged_abort_recovers_after_full_egress() {
    exercise(Case::CoinAbort, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r39_write_gas_abort_loss_free_control() {
    exercise(Case::WriteGasAbort, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r39_write_gas_abort_recovers_after_full_egress() {
    exercise(Case::WriteGasAbort, true).await;
}
