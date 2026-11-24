use super::*;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};

/// R5's retained DAG had a certified payload with no child, and its author
/// skipped the child round. Recreate that shape without any real network.
#[test]
fn closed_child_frontier_recovers_certified_payload_before_stale_timer() {
    use crypto::Signer;
    let key = crypto::SigningKey::from_bytes(&[77u8; 32]);
    let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    const FUNDS: u128 = 1_000_000_000_000;
    let mut c = Cluster::with_funded("closed-child-frontier", &[93, 94, 95, 96],
        true, 1000, vec![(sender.clone(), FUNDS)]);
    let stakes: Vec<_> = c.committee.iter().map(|m| (m.address.clone(), m.stake)).collect();
    let leader = crate::ordering::OrderingEngine::leader_for_round(2, &stakes, 0);
    let slow = c.committee.iter().position(|m| m.address != leader).unwrap();
    let now = Arc::new(AtomicU64::new(PINNED));
    for i in 0..4 {
        let clock = now.clone();
        c.node_mut(i).set_now_secs(Arc::new(move || clock.load(Ordering::SeqCst)));
    }
    let chain_id = blockchain::chain_id();
    let payload = hex::encode([2u8, 1, 2, 7, 7]);
    let (seq, gas_limit, gas_price) = (0u64, 1_000_000u64, 1u128);
    let message = format!("{chain_id}:{sender}:{payload}:{seq}:{gas_limit}:{gas_price}:");
    let raw = serde_json::json!({
        "chain_id": chain_id, "sender": sender, "input_objects": [],
        "payload": payload, "args": [], "gas_limit": gas_limit,
        "gas_price": gas_price, "sequence_number": seq,
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "signature": hex::encode(key.sign(message.as_bytes()).to_bytes()),
    }).to_string();
    let tx = executor::admission::canonicalize(&raw).unwrap();
    c.node(slow).mempool.lock().unwrap().add_transaction(tx.clone()).unwrap();
    let held = RefCell::new(None::<String>);
    let delay = |from: usize, _to: usize, wire: &str| {
        if from != slow { return false; }
        let Some(body) = wire.strip_prefix(crate::v4::WIRE_PREFIX) else { return false; };
        let Ok(crate::v4::Msg::Vertex(v)) = serde_json::from_str(body) else { return false; };
        if v.round != 1 || !v.payload.contains(&tx) { return false; }
        held.borrow_mut().get_or_insert_with(|| wire.to_string());
        true
    };
    for i in 0..4 { c.node_mut(i).try_create_vertex(); }
    c.deliver_filtered(&delay);
    now.store(PINNED + 3, Ordering::SeqCst);
    for i in (0..4).filter(|i| *i != slow) { c.node_mut(i).try_create_vertex(); }
    c.deliver_filtered(&delay);
    assert!(c.node(slow).v4.as_ref().unwrap().current_round() >= 3);
    let wire = held.into_inner().expect("first payload was actually withheld");
    let crate::v4::Msg::Vertex(first) = serde_json::from_str(
        wire.strip_prefix(crate::v4::WIRE_PREFIX).unwrap()).unwrap() else { panic!("not a vertex"); };
    now.store(PINNED + 6, Ordering::SeqCst);
    for i in (0..4).filter(|i| *i != slow) { c.node_mut(i).handle_message(&wire); }
    c.deliver();
    let cert_key = format!("consensus:vcert:v1:{:020}:{:020}:{}", 0, 1, first.author);
    assert!(c.node(slow).storage.get(&cert_key).unwrap().is_some(), "must be certified, not merely lost");
    c.node_mut(slow).try_create_vertex();
    c.deliver();
    {
        let dag = c.node(slow).dag.lock().unwrap();
        let children: Vec<_> = dag.values().filter(|v| v.round == 2).collect();
        assert_eq!(children.len(), 3, "the author skipped the child round");
        assert!(children.iter().all(|v| !v.parents.contains(&first.hash)));
        assert!(dag.values().any(|v| v.author == first.author && v.round > 2));
    }
    let carrying = |c: &Cluster, i: usize| -> Vec<u64> {
        (1..=c.node(i).latest_block_height).filter(|h| {
            c.node(i).storage.get(&format!("block_{h}")).unwrap()
                .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
                .is_some_and(|b| b.transactions.contains(&tx))
        }).collect()
    };
    let mut included = None;
    for tick in 3..=40 {
        let seconds = tick * 3;
        now.store(PINNED + seconds, Ordering::SeqCst);
        c.run(1);
        if included.is_none() && (0..4).all(|i| !carrying(&c, i).is_empty()) {
            included = Some(seconds);
        }
        if included.is_some_and(|at| seconds >= at + 18) { break; }
    }
    let elapsed = included.expect("the payload did not recover");
    let height = carrying(&c, 0)[0];
    c.assert_same_blocks(height);
    for i in 0..4 {
        assert_eq!(carrying(&c, i), vec![height]);
        assert_eq!(executor::test_support::ain_balance(&c.node(i).storage, &sender),
            Some(FUNDS - gas_limit as u128 * gas_price));
        assert!(c.qc(i, height).is_some());
    }
    eprintln!("CERTIFIED_ORPHAN_DIAGNOSTIC inclusion_virtual_seconds={elapsed} height={height}");
    assert!(elapsed < 30, "closed-child proof was available before the stale timer, inclusion waited {elapsed}s");
}
