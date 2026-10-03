//! G4 S7: a flood harness. It opens `--identities` libp2p sessions to one
//! node, each under a fresh key (none is a committee member), and drives
//! one kind of abuse per session, round-robin over `--mix`:
//!
//!   hold       connect and keep the connection (the non-member cap)
//!   consensus  member-only consensus requests (refused: not a member)
//!   sync       GET_HEIGHT as fast as `--rate` (the per-session sync budget)
//!   gossip     junk DAG_V4 and TX gossip (rejected, the sender graylisted)
//!   big        sync requests over the request cap (refused before read)
//!
//!   flood --target /ip4/H/tcp/P --identities 60 --seconds 180 --rate 50
//!         [--mix hold,consensus,sync,gossip,big]
//!
//! `--target` is the node's libp2p address (base port + 100). Every 10 s and
//! at the end it prints one JSON line of counts per kind. Run it against a
//! rehearsal node only, never a live validator.

use libp2p::futures::StreamExt;
use libp2p::{
    core::upgrade,
    gossipsub, identity, noise, request_response,
    swarm::{dial_opts::DialOpts, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Swarm, Transport,
};
use node::sessions::{self, FramedCodec};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(libp2p::swarm::NetworkBehaviour)]
struct Flood {
    gossipsub: gossipsub::Behaviour,
    consensus: request_response::Behaviour<FramedCodec>,
    sync: request_response::Behaviour<FramedCodec>,
}

const KINDS: [&str; 5] = ["hold", "consensus", "sync", "gossip", "big"];

#[derive(Default)]
struct Count {
    sessions: AtomicU64,
    closed: AtomicU64,
    dial_failed: AtomicU64,
    sent: AtomicU64,
    answered: AtomicU64,
    refused: AtomicU64,
}

fn flags() -> HashMap<String, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = HashMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        match (k.strip_prefix("--"), it.next()) {
            (Some(name), Some(v)) => {
                out.insert(name.to_string(), v.clone());
            }
            _ => {
                eprintln!("usage: flood --target MULTIADDR [--identities N] [--seconds S] [--rate R] [--mix k,k]");
                std::process::exit(2)
            }
        }
    }
    out
}

fn report(counts: &[Count], elapsed: Duration) {
    let mut line = serde_json::Map::new();
    line.insert("secs".into(), elapsed.as_secs().into());
    for (kind, c) in KINDS.iter().zip(counts) {
        line.insert(
            (*kind).into(),
            serde_json::json!({
                "sessions": c.sessions.load(Ordering::Relaxed),
                "closed": c.closed.load(Ordering::Relaxed),
                "dial_failed": c.dial_failed.load(Ordering::Relaxed),
                "sent": c.sent.load(Ordering::Relaxed),
                "answered": c.answered.load(Ordering::Relaxed),
                "refused": c.refused.load(Ordering::Relaxed),
            }),
        );
    }
    println!("{}", serde_json::Value::Object(line));
}

fn swarm(key: identity::Keypair) -> Swarm<Flood> {
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::Config::new(&key).expect("noise"))
        .multiplex(yamux::Config::default())
        .boxed();
    // Requests up to 4 MiB may be written, so `big` can exceed the node's caps.
    let big_codec = |response_cap| FramedCodec::new(4 << 20, response_cap);
    let behaviour = Flood {
        gossipsub: sessions::gossip_behaviour(&key).expect("gossipsub"),
        consensus: request_response::Behaviour::with_codec(
            big_codec(sessions::CONSENSUS_ACK.len()),
            [(
                libp2p::StreamProtocol::new(sessions::CONSENSUS_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(10)),
        ),
        sync: request_response::Behaviour::with_codec(
            big_codec(sessions::SYNC_RESPONSE_CAP),
            [(
                libp2p::StreamProtocol::new(sessions::SYNC_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default().with_request_timeout(Duration::from_secs(10)),
        ),
    };
    let peer = key.public().to_peer_id();
    Swarm::new(
        transport,
        behaviour,
        peer,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(120)),
    )
}

async fn run(
    kind: usize,
    target: Multiaddr,
    rate: u64,
    until: tokio::time::Instant,
    c: Arc<Vec<Count>>,
) {
    let c = &c[kind];
    let mut swarm = swarm(identity::Keypair::generate_ed25519());
    let topic = gossipsub::IdentTopic::new(sessions::GOSSIP_TOPIC);
    let _ = swarm.dial(DialOpts::unknown_peer_id().address(target.clone()).build());
    let (mut peer, mut dialing): (Option<PeerId>, bool) = (None, true);
    let every = match KINDS[kind] {
        "big" => Duration::from_millis(500),
        _ => Duration::from_micros(1_000_000 / rate.max(1)),
    };
    let mut tick = tokio::time::interval(every);
    let mut n = 0u64;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(until) => break,
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    c.sessions.fetch_add(1, Ordering::Relaxed);
                    (peer, dialing) = (Some(peer_id), false);
                }
                SwarmEvent::ConnectionClosed { num_established: 0, .. } => {
                    c.closed.fetch_add(1, Ordering::Relaxed);
                    peer = None;
                }
                SwarmEvent::OutgoingConnectionError { .. } => {
                    c.dial_failed.fetch_add(1, Ordering::Relaxed);
                    dialing = false;
                }
                SwarmEvent::Behaviour(FloodEvent::Consensus(request_response::Event::Message {
                    message: request_response::Message::Response { .. }, ..
                }))
                | SwarmEvent::Behaviour(FloodEvent::Sync(request_response::Event::Message {
                    message: request_response::Message::Response { .. }, ..
                })) => {
                    c.answered.fetch_add(1, Ordering::Relaxed);
                }
                SwarmEvent::Behaviour(FloodEvent::Consensus(request_response::Event::OutboundFailure { .. }))
                | SwarmEvent::Behaviour(FloodEvent::Sync(request_response::Event::OutboundFailure { .. })) => {
                    c.refused.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            },
            _ = tick.tick() => {
                let Some(p) = peer else {
                    // Keep the pressure on: redial a closed session.
                    if !dialing {
                        dialing = swarm
                            .dial(DialOpts::unknown_peer_id().address(target.clone()).build())
                            .is_ok();
                    }
                    continue;
                };
                n += 1;
                let sent = match KINDS[kind] {
                    "consensus" => {
                        swarm.behaviour_mut().consensus.send_request(&p, format!("DAG_V4:flood-{n}"));
                        true
                    }
                    "sync" => {
                        swarm.behaviour_mut().sync.send_request(&p, "GET_HEIGHT".into());
                        true
                    }
                    "gossip" => {
                        let junk = if n.is_multiple_of(2) { "DAG_V4" } else { "TX" };
                        let wire = format!("{junk}:flood-{}-{n}", swarm.local_peer_id());
                        swarm.behaviour_mut().gossipsub.publish(topic.clone(), wire.into_bytes()).is_ok()
                    }
                    "big" => {
                        let wire = format!("SYNC_REQ:{}", "x".repeat(sessions::SYNC_REQUEST_CAP + 1));
                        swarm.behaviour_mut().sync.send_request(&p, wire);
                        true
                    }
                    _ => false,
                };
                if sent {
                    c.sent.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let f = flags();
    let target: Multiaddr = f
        .get("target")
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| {
            eprintln!("--target MULTIADDR is required (the node's libp2p address)");
            std::process::exit(2)
        });
    let num = |k: &str, d: u64| f.get(k).and_then(|v| v.parse().ok()).unwrap_or(d);
    let (identities, seconds, rate) = (num("identities", 60), num("seconds", 180), num("rate", 50));
    let mix: Vec<usize> = f
        .get("mix")
        .map(String::as_str)
        .unwrap_or("hold,consensus,sync,gossip,big")
        .split(',')
        .filter_map(|k| KINDS.iter().position(|x| *x == k))
        .collect();
    assert!(!mix.is_empty(), "--mix names none of {KINDS:?}");
    let counts: Arc<Vec<Count>> = Arc::new(KINDS.iter().map(|_| Count::default()).collect());
    let start = tokio::time::Instant::now();
    let until = start + Duration::from_secs(seconds);
    let mut tasks = Vec::new();
    for i in 0..identities as usize {
        let kind = mix[i % mix.len()];
        tasks.push(tokio::spawn(run(
            kind,
            target.clone(),
            rate,
            until,
            Arc::clone(&counts),
        )));
    }
    let mut every = tokio::time::interval(Duration::from_secs(10));
    every.tick().await;
    while tokio::time::Instant::now() < until {
        every.tick().await;
        report(&counts, start.elapsed());
    }
    for t in tasks {
        let _ = t.await;
    }
    report(&counts, start.elapsed());
}
