use super::*;
use std::time::Duration;
use tokio::sync::mpsc;

fn message(i: usize) -> Outbound {
    Outbound::Broadcast(format!("r35-{i}"))
}
fn to(who: &str, i: usize) -> Outbound {
    Outbound::To {
        address: who.into(),
        wire: format!("r35-{i}"),
    }
}
async fn recv(rx: &mut mpsc::Receiver<Outbound>) -> Outbound {
    tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap()
}
async fn idle(egress: &Egress, tx: &Sender<Outbound>, owners: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while tx.strong_count() != owners || egress.0.lock().unwrap().running {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker did not release ownership");
}

#[tokio::test(flavor = "current_thread")]
async fn r35_original_real_channel_bound_is_preserved() {
    let (tx, mut rx) = mpsc::channel(1);
    let network = crate::dag::V4Net {
        p2p_tx: Some(tx.clone()),
        outbox: None,
        egress: Egress::default(),
    };
    tx.try_send(message(0)).unwrap();
    let owners = tx.strong_count();
    assert_eq!(owners, 2);
    for i in 1..=64 {
        network.emit(message(i));
    }
    tokio::task::yield_now().await;
    let first = tx.strong_count();
    for i in 65..=128 {
        network.emit(message(i));
    }
    tokio::task::yield_now().await;
    let second = tx.strong_count();
    assert_eq!(tx.capacity(), 0);
    assert_eq!(rx.try_recv().unwrap(), message(0));
    eprintln!("R35 owners={owners} after_64={first} after_128={second}");
    assert!(
        first <= owners + 1 && second <= owners + 1,
        "unbounded producer waiters: owners={owners}, first={first}, second={second}"
    );
    drop(rx);
    idle(&network.egress, &tx, owners).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r35_admitted_messages_drain_in_route_order() {
    let (tx, mut rx) = mpsc::channel(1);
    let e = Egress::default();
    tx.try_send(message(0)).unwrap();
    for i in 1..=MAX_PER_ROUTE {
        assert!(e.emit(&tx, message(i)));
    }
    assert!(!e.emit(&tx, message(999)));
    for i in 0..=MAX_PER_ROUTE {
        assert_eq!(recv(&mut rx).await, message(i));
    }
    idle(&e, &tx, 1).await;
    assert_eq!(e.0.lock().unwrap().bytes, 0);
    assert!(rx.try_recv().is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn r35_receiver_close_releases_all_pending_work() {
    let (tx, rx) = mpsc::channel(1);
    let e = Egress::default();
    tx.try_send(message(0)).unwrap();
    for i in 0..128 {
        e.emit(&tx, to("a", i));
    }
    e.relay_conflict(&tx, [message(900), message(901)]);
    drop(rx);
    idle(&e, &tx, 1).await;
    let state = e.0.lock().unwrap();
    assert!(state.routes.is_empty() && state.conflict.is_empty());
    assert_eq!(state.bytes, 0);
    drop(state);
    assert!(!e.emit(&tx, message(1)));
}

#[test]
fn r35_runtime_cancel_before_first_poll_releases_worker() {
    let e = Egress::default();
    let (tx, _rx) = mpsc::channel(1);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    {
        let _entered = rt.enter();
        assert!(e.emit(&tx, message(1)));
        assert_eq!(tx.strong_count(), 2);
    }
    drop(rt);
    assert_eq!(tx.strong_count(), 1);
    let state = e.0.lock().unwrap();
    assert!(!state.running && state.routes.is_empty() && state.bytes == 0);
}

#[tokio::test(flavor = "current_thread")]
async fn r35_admitted_slow_route_is_not_starved_by_busy_route() {
    let (tx, mut rx) = mpsc::channel(1);
    let e = Egress::default();
    tx.try_send(message(0)).unwrap();
    for i in 0..1024 {
        e.emit(&tx, to("greedy", i));
    }
    assert!(e.emit(&tx, to("slow", 99)));
    assert_eq!(recv(&mut rx).await, message(0));
    let mut slow = false;
    for _ in 0..3 {
        let out = recv(&mut rx).await;
        if out == to("slow", 99) {
            slow = true;
            break;
        }
        for i in 0..1024 {
            e.emit(&tx, to("greedy", i));
        }
    }
    assert!(slow, "busy route starved an admitted slow recipient");
    drop(rx);
    idle(&e, &tx, 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r35_conflict_pair_survives_full_queue_and_is_bounded() {
    let (tx, mut rx) = mpsc::channel(1);
    let e = Egress::default();
    tx.try_send(message(0)).unwrap();
    for i in 1..=MAX_PER_ROUTE {
        assert!(e.emit(&tx, message(i)));
    }
    tokio::task::yield_now().await;
    let owners = tx.strong_count();
    for i in 0..128 {
        e.relay_conflict(&tx, [message(900 + 2 * i), message(901 + 2 * i)]);
    }
    assert_eq!(owners, 2);
    assert_eq!(tx.strong_count(), owners);
    assert_eq!(e.0.lock().unwrap().conflict.len(), 2);
    assert_eq!(recv(&mut rx).await, message(0));
    // One ordinary message was already waiting in send before the alarm.
    assert_eq!(recv(&mut rx).await, message(1));
    assert_eq!(recv(&mut rx).await, message(900));
    assert_eq!(recv(&mut rx).await, message(901));
    for i in 2..=MAX_PER_ROUTE {
        assert_eq!(recv(&mut rx).await, message(i));
    }
    idle(&e, &tx, 1).await;
    assert!(rx.try_recv().is_err());
}

#[test]
fn r35_route_count_and_global_byte_bounds() {
    let mut state = State::default();
    for i in 0..MAX_ROUTES {
        assert!(state.push(to(&i.to_string(), i)));
    }
    assert!(!state.push(to("one-too-many", 0)));
    assert_eq!(state.routes.len(), MAX_ROUTES);
    let mut large = State::default();
    for i in 0..1024 {
        large.push(Outbound::To {
            address: (i % 64).to_string(),
            wire: "x".repeat(MAX_WIRE),
        });
        assert!(large.bytes <= MAX_BYTES);
        assert!(large
            .routes
            .iter()
            .all(|r| r.bytes <= MAX_ROUTE_BYTES && r.messages.len() <= MAX_PER_ROUTE));
    }
    assert!(
        large.bytes > MAX_BYTES - MAX_WIRE * 2,
        "vacuous byte limit test"
    );
    let admitted = large.bytes;
    let mut drained = 0;
    while let Some(out) = large.next() {
        drained += bytes(&out);
    }
    assert_eq!(drained, admitted);
    assert_eq!(large.bytes, 0);
}

#[test]
fn r35_oversized_wire_and_address_refused_without_empty_routes() {
    let mut state = State::default();
    assert!(!state.push(Outbound::Broadcast("x".repeat(MAX_WIRE + 1))));
    assert!(!state.push(to(&"a".repeat(129), 1)));
    assert!(state.routes.is_empty() && state.bytes == 0);
}

#[test]
fn r35_without_runtime_keeps_original_bounded_behavior() {
    let (tx, mut rx) = mpsc::channel(1);
    let e = Egress::default();
    tx.try_send(message(0)).unwrap();
    for i in 1..=128 {
        assert!(!e.emit(&tx, message(i)));
    }
    assert_eq!(tx.strong_count(), 1);
    assert_eq!(rx.try_recv().unwrap(), message(0));
    assert!(rx.try_recv().is_err());
}

#[test]
fn r36_shutdown_runtime_drops_worker_without_relocking_held_mutex() {
    let (done, result) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let handle = rt.handle().clone();
        drop(rt);
        let _entered = handle.enter();
        let (tx, _rx) = mpsc::channel(1);
        let e = Egress::default();
        e.emit(&tx, message(1));
        e.relay_conflict(&tx, [message(2), message(3)]);
        assert_eq!(tx.strong_count(), 1);
        let state = e.0.lock().unwrap();
        assert!(!state.running && state.routes.is_empty() && state.conflict.is_empty());
        assert_eq!(state.bytes, 0);
        done.send(()).unwrap();
    });
    result
        .recv_timeout(Duration::from_secs(2))
        .expect("spawn into closed runtime deadlocked");
    thread.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r36_concurrent_producers_keep_one_worker_and_recover_idle() {
    let (tx, mut rx) = mpsc::channel(1);
    let e = Egress::default();
    tx.try_send(message(0)).unwrap();
    let accepted = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let handle = tokio::runtime::Handle::current();
        for i in 0..8 {
            let handle = handle.clone();
            let e = &e;
            let tx = &tx;
            let accepted = &accepted;
            scope.spawn(move || {
                let _entered = handle.enter();
                for n in 0..128 {
                    if e.emit(tx, to(&i.to_string(), n)) {
                        accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        }
    });
    assert_eq!(tx.strong_count(), 2);
    assert_eq!(recv(&mut rx).await, message(0));
    let mut delivered = std::collections::BTreeSet::new();
    for _ in 0..accepted.load(std::sync::atomic::Ordering::Relaxed) {
        let out = recv(&mut rx).await;
        if let Outbound::To { address, .. } = out {
            delivered.insert(address);
        }
    }
    idle(&e, &tx, 1).await;
    assert_eq!(delivered.len(), 8);
    assert!(e.emit(&tx, message(9999)));
    assert_eq!(recv(&mut rx).await, message(9999));
    idle(&e, &tx, 1).await;
}

#[tokio::test(flavor = "current_thread")]
async fn r36_later_conflict_pair_is_not_suppressed_after_drain() {
    let (tx, mut rx) = mpsc::channel(1);
    let e = Egress::default();
    for i in 0..3 {
        e.relay_conflict(&tx, [message(100 + 2 * i), message(101 + 2 * i)]);
        assert_eq!(recv(&mut rx).await, message(100 + 2 * i));
        assert_eq!(recv(&mut rx).await, message(101 + 2 * i));
        idle(&e, &tx, 1).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn r37_idle_handoff_delivers_every_admitted_message_once() {
    let (tx, mut rx) = mpsc::channel(1);
    let e = Egress::default();
    let mut producers = Vec::new();
    for i in 0..8 {
        let e = e.clone();
        let tx = tx.clone();
        producers.push(tokio::spawn(async move {
            let mut accepted = 0;
            for n in 0..256 {
                if e.emit(&tx, to(&i.to_string(), n)) {
                    accepted += 1;
                }
                tokio::task::yield_now().await;
            }
            accepted
        }));
    }
    drop(tx);
    let delivered = tokio::time::timeout(Duration::from_secs(10), async {
        let mut seen = std::collections::BTreeSet::new();
        while let Some(out) = rx.recv().await {
            match out {
                Outbound::To { address, wire } => {
                    assert!(seen.insert((address, wire)), "duplicate delivery")
                }
                _ => panic!("unexpected broadcast"),
            }
        }
        seen.len()
    })
    .await
    .expect("worker leaked, hung or failed to close after producer completion");
    let mut accepted = 0;
    for producer in producers {
        accepted += producer.await.unwrap();
    }
    assert!(accepted > 0);
    assert_eq!(
        delivered, accepted,
        "an accepted message was lost during idle handoff"
    );
    let state = e.0.lock().unwrap();
    assert!(!state.running && state.routes.is_empty() && state.bytes == 0);
}
