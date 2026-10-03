use crate::sessions::{self, PeerBook, SessionWiring};
use libp2p::futures::StreamExt;
use libp2p::{
    autonat,
    core::upgrade,
    dcutr,
    gossipsub::{
        Behaviour as GossipsubBehaviour, Event as GossipsubEvent, IdentTopic, MessageAcceptance,
    },
    identify,
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent,
    },
    mdns::{tokio::Behaviour as Mdns, Config as MdnsConfig, Event as MdnsEvent},
    multiaddr::Protocol,
    noise, relay, request_response,
    swarm::{dial_opts::DialOpts, dial_opts::PeerCondition, Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use network::Outbound;
use std::error::Error;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use storage::StateDB;
use tokio::sync::mpsc;

// === START P2P ===
use libp2p::swarm::behaviour::toggle::Toggle;

const MAX_LIBP2P_CONNECTIONS_PER_PEER: u32 = 2;
const MAX_INBOUND_LIBP2P_CONNECTIONS_PER_HOST: u32 = 2;

fn multiaddr_host(addr: &Multiaddr) -> Option<String> {
    addr.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => Some(ip.to_string()),
        Protocol::Ip6(ip) => Some(ip.to_string()),
        Protocol::Dns(host) | Protocol::Dns4(host) | Protocol::Dns6(host) => Some(host.to_string()),
        _ => None,
    })
}

// === START P2P ===
// Returns: (Sender to broadcast, Receiver for incoming messages)
/// How often the network task dials the committee members it is not
/// connected to (gossipsub's own explicit-peer redial is 300 heartbeats).
const COMMITTEE_DIAL_EVERY: Duration = Duration::from_secs(5);

#[allow(clippy::too_many_arguments)] // the node's network inputs
pub async fn start_p2p(
    port: u16,
    bootnodes: Vec<String>,
    storage: Arc<StateDB>,
    enable_mdns: bool,
    enable_nat: bool,
    // G4 S1: the node key (the session identity), and the committee book,
    // session table and sync channels shared with the node.
    node_key: [u8; 32],
    wiring: SessionWiring,
) -> Result<(mpsc::Sender<Outbound>, mpsc::Receiver<String>), Box<dyn Error>> {
    let SessionWiring {
        book,
        table: session_table,
        asks: mut sync_asks,
        dials: mut sync_dials,
        serves: sync_serves,
    } = wiring;
    let (tx_out, mut rx_in) = mpsc::channel::<Outbound>(64); // Main -> P2P
    let (tx_in, rx_out) = mpsc::channel::<String>(64); // P2P -> Main

    // === The session identity: the node key (G4 S1, NI-1) ===
    let local_key = sessions::local_keypair(&node_key);
    let local_peer_id = PeerId::from(local_key.public());
    println!("🛰️ Local peer id: {:?}", local_peer_id);

    // === Build Noise encryption (v0.45 style) ===
    let noise_config = noise::Config::new(&local_key)?;

    // === Relay Client (Hole Punching) ===
    let (relay_transport, relay_behaviour_inner) = relay::client::new(local_peer_id);

    // === Build transport (TCP + Noise + Yamux) ===
    let tcp_config = tcp::Config::default();
    // tcp_config.port_reuse(true); // Deprecated
    let tcp_transport = tcp::tokio::Transport::new(tcp_config);

    let transport = tcp_transport
        .or_transport(relay_transport)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(yamux::Config::default())
        // B24: a connection that does not finish its handshake is dropped.
        .timeout(sessions::HANDSHAKE_TIMEOUT)
        .boxed();

    // === Gossipsub (M-05 config; G4 S5: validated before forwarding, peers
    // scored, explicit peering for committee members only) ===
    let gossipsub = sessions::gossip_behaviour(&local_key)
        .map_err(|e| -> Box<dyn Error> { e.into() })?;
    let topic = IdentTopic::new(sessions::GOSSIP_TOPIC);

    // === mDNS behaviour (Optional) ===
    let mdns = if enable_mdns {
        println!("👀 mDNS Discovery Enabled");
        Some(Mdns::new(MdnsConfig::default(), local_peer_id)?)
    } else {
        println!("🚫 mDNS Discovery Disabled (Kademlia Only)");
        None
    };

    // === Kademlia behaviour ===
    let store = MemoryStore::new(local_peer_id);
    #[allow(deprecated)]
    let mut kad_config = KademliaConfig::default();
    kad_config.set_query_timeout(Duration::from_secs(60));
    let kademlia = Kademlia::with_config(local_peer_id, store, kad_config);

    // === AutoNAT ===
    let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());

    // === Identify ===
    let identify = identify::Behaviour::new(identify::Config::new(
        "/aincore/1.0.0".to_string(),
        local_key.public(),
    ));

    let relay_behaviour = if enable_nat {
        Some(relay_behaviour_inner)
    } else {
        None
    };

    let dcutr_behaviour = if enable_nat {
        println!("🔓 NAT Traversal Enabled (Relay + DCUTR)");
        Some(dcutr::Behaviour::new(local_peer_id))
    } else {
        println!("🔒 NAT Traversal Disabled");
        None
    };

    // === Combine behaviours ===
    #[derive(libp2p::swarm::NetworkBehaviour)]
    struct P2PBehaviour {
        gossipsub: GossipsubBehaviour,
        mdns: Toggle<Mdns>,
        kademlia: Kademlia<MemoryStore>,
        autonat: autonat::Behaviour,
        identify: identify::Behaviour,
        pub dcutr: Toggle<dcutr::Behaviour>,
        pub relay: Toggle<relay::client::Behaviour>,
        consensus: request_response::Behaviour<sessions::FramedCodec>,
        sync: request_response::Behaviour<sessions::FramedCodec>,
        // B24: admission before the handshake, per IP and in all.
        gate: sessions::InboundGate,
        limits: libp2p::connection_limits::Behaviour,
    }

    let behaviour = P2PBehaviour {
        gossipsub,
        mdns: Toggle::from(mdns),
        kademlia,
        autonat,
        identify,
        consensus: sessions::consensus_behaviour(),
        sync: sessions::sync_behaviour(),
        dcutr: Toggle::from(dcutr_behaviour),
        relay: Toggle::from(relay_behaviour),
        gate: sessions::InboundGate::default(),
        limits: libp2p::connection_limits::Behaviour::new(
            libp2p::connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(sessions::MAX_PENDING_INBOUND)),
        ),
    };

    // === Swarm ===
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(20)),
    );

    // B22: bootnodes given without a PeerId are dialled again until reached.
    let mut unresolved = sessions::Unresolved::new(&bootnodes, std::time::Instant::now());
    // Add bootnodes
    for peer_addr in bootnodes {
        if let Ok(multiaddr) = peer_addr.parse::<Multiaddr>() {
            println!("🔗 Adding bootnode: {:?}", multiaddr);
            if let Some(Protocol::P2p(peer_id)) = multiaddr.iter().last() {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, multiaddr.clone());
            }
            // Force dial
            if let Err(e) = swarm.dial(multiaddr) {
                eprintln!("❌ Failed to dial bootnode: {:?}", e);
            }
        }
    }

    // === Listen on the libp2p port: base port + 100 (the operators' bootnode convention) ===
    //
    // Lightweight observer nodes (e.g. Raspberry Pi) can run outbound-only by
    // setting AINCORE_P2P_LISTEN=0. They still dial bootnodes and receive
    // gossip/sync over outbound connections, but they do not accept inbound
    // libp2p sessions. This prevents a non-validator observer from becoming a
    // socket sink if a bootnode repeatedly redials it over multiple observed
    // addresses.
    let p2p_listen = std::env::var("AINCORE_P2P_LISTEN")
        .map(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    if p2p_listen {
        let libp2p_port = port + 100;
        let addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", libp2p_port).parse()?;
        Swarm::listen_on(&mut swarm, addr)?;
    } else {
        println!("🚫 P2P listening disabled (AINCORE_P2P_LISTEN=0); outbound-only observer mode");
    }

    // === LiDAR DDoS Protection ===
    let mut lidar_tracker: std::collections::HashMap<PeerId, (std::time::Instant, u32)> =
        std::collections::HashMap::new();

    // GATE-HIGH: keying ONLY on the authenticated publisher removed the
    // per-connection bound entirely. Gossipsub relays messages authored by peers
    // we are not connected to, and Strict mode validates a signature against the
    // key embedded in the message — it does not require that identity to be known
    // or connected. So an attacker mints N identities offline, signs one message
    // each, and pushes them all down ONE connection: every `publisher` is
    // distinct, every count stays at 1, and the limiter never fires. Both budgets
    // are needed — the publisher counter to attribute and ban, and this
    // per-connection counter to bound total inbound traffic regardless of author.
    let mut conn_tracker: std::collections::HashMap<PeerId, (std::time::Instant, u32)> =
        std::collections::HashMap::new();
    const MAX_MSG_PER_SEC: u32 = 100; // Production Grade Limit
    /// Cap on distinct publishers tracked at once. The key space is chosen by
    /// whoever signs the messages, so this map must be swept.
    const MAX_TRACKED_PUBLISHERS: usize = 10_000;
    /// Aggregate inbound budget for ONE connection, across all publishers whose
    /// traffic that peer relays. Sized well above a single publisher's limit
    /// because a relay legitimately carries the whole mesh's traffic. Exceeding
    /// it drops messages; it never bans, because the peer being measured is the
    /// messenger, not necessarily the author.
    const MAX_CONN_MSG_PER_SEC: u32 = 2_000;

    // === Event Loop ===
    tokio::spawn(async move {
        let mut inbound_connections_by_host: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        // The inbound connections counted against their host, so a close
        // gives back exactly what was taken (members are not counted).
        let mut counted_inbound: std::collections::HashMap<libp2p::swarm::ConnectionId, String> =
            std::collections::HashMap::new();
        let mut committee_dial = tokio::time::interval(COMMITTEE_DIAL_EVERY);
        // G4 S1: sync requests this node asked, and those it is answering.
        let mut pending_asks: std::collections::HashMap<
            request_response::OutboundRequestId,
            tokio::sync::oneshot::Sender<Result<String, String>>,
        > = std::collections::HashMap::new();
        let mut pending_serves: std::collections::HashMap<
            request_response::InboundRequestId,
            request_response::ResponseChannel<String>,
        > = std::collections::HashMap::new();
        let (served_tx, mut served_rx) =
            mpsc::channel::<(request_response::InboundRequestId, Option<String>)>(64);
        // G4 S6: sessions the node asked for by address, until they open.
        let mut pending_dials: std::collections::HashMap<
            libp2p::swarm::ConnectionId,
            tokio::sync::oneshot::Sender<Result<String, String>>,
        > = std::collections::HashMap::new();
        // G4 NI-3: per-member consensus budget, per-session sync quota.
        let mut member_budget: sessions::Budget<String> =
            sessions::Budget::new(sessions::MEMBER_MSGS_PER_SEC, sessions::MEMBER_MSG_BURST);
        let mut sync_budget: sessions::Budget<PeerId> = sessions::Budget::new(
            sessions::SYNC_REQUESTS_PER_SEC,
            sessions::SYNC_REQUEST_BURST,
        );
        // G4 NI-3: messages bound for the node; the swarm never waits on it.
        let mut inbox = sessions::Inbox::default();
        // G4 NI-2: inbound connections from non-members, all together.
        let mut non_member_inbound: std::collections::HashSet<libp2p::swarm::ConnectionId> =
            std::collections::HashSet::new();
        // G4 S5: the explicit gossip peers, kept equal to the members.
        let mut explicit: std::collections::HashSet<PeerId> = std::collections::HashSet::new();
        let members = |book: &Arc<RwLock<PeerBook>>| -> Vec<PeerId> {
            book.read()
                .map(|b| b.peers().copied().filter(|p| *p != local_peer_id).collect())
                .unwrap_or_default()
        };

        loop {
            tokio::select! {
                Some(out) = rx_in.recv() => match out {
                    // G4 S1: a broadcast floods over gossip and is pushed on
                    // every connected member session; gossip alone drops a
                    // repeat of the same payload for a minute.
                    Outbound::Broadcast(wire) => {
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), wire.as_bytes());
                        if sessions::is_consensus_message(&wire) {
                            for peer in members(&book) {
                                if swarm.is_connected(&peer) {
                                    swarm.behaviour_mut().consensus.send_request(&peer, wire.clone());
                                }
                            }
                        }
                    }
                    // An addressed message goes on its member's session only;
                    // an address the book does not name is flooded instead.
                    Outbound::To { address, wire } => {
                        let peer = book.read().ok().and_then(|b| b.peer_of(&address));
                        match peer {
                            Some(peer) if peer != local_peer_id => {
                                swarm.behaviour_mut().consensus.send_request(&peer, wire);
                            }
                            _ => {
                                let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), wire.as_bytes());
                            }
                        }
                    }
                },
                // Hand the node what it can take now; the rest waits here.
                permit = tx_in.reserve(), if !inbox.is_empty() => {
                    match permit {
                        Ok(permit) => {
                            if let Some(msg) = inbox.pop() {
                                permit.send(msg);
                            }
                        }
                        Err(_) => {
                            eprintln!("❌ The main loop is gone; dropping {} queued bytes", inbox.bytes());
                            while inbox.pop().is_some() {}
                        }
                    }
                }
                Some(dial) = sync_dials.recv() => {
                    match dial.addr.parse::<Multiaddr>() {
                        Ok(addr) => {
                            let opts = match addr.iter().last() {
                                Some(Protocol::P2p(peer)) => {
                                    DialOpts::peer_id(peer).addresses(vec![addr]).build()
                                }
                                _ => DialOpts::unknown_peer_id().address(addr).build(),
                            };
                            let id = opts.connection_id();
                            match swarm.dial(opts) {
                                Ok(()) => {
                                    pending_dials.insert(id, dial.reply);
                                }
                                Err(e) => {
                                    let _ = dial.reply.send(Err(e.to_string()));
                                }
                            }
                        }
                        Err(e) => {
                            let _ = dial.reply.send(Err(format!("not a multiaddr: {e}")));
                        }
                    }
                }
                Some(ask) = sync_asks.recv() => {
                    match ask.peer.parse::<PeerId>() {
                        Ok(peer) => {
                            let id = swarm.behaviour_mut().sync.send_request(&peer, ask.wire);
                            pending_asks.insert(id, ask.reply);
                        }
                        Err(e) => {
                            let _ = ask.reply.send(Err(format!("not a PeerId: {e}")));
                        }
                    }
                }
                Some((id, answer)) = served_rx.recv() => {
                    if let Some(channel) = pending_serves.remove(&id) {
                        match answer {
                            Some(answer) => {
                                let _ = swarm.behaviour_mut().sync.send_response(channel, answer);
                            }
                            None => drop(channel),
                        }
                    }
                }
                _ = committee_dial.tick() => {
                    // The session table names members by the current book.
                    if let (Ok(b), Ok(mut table)) = (book.read(), session_table.write()) {
                        for entry in table.iter_mut() {
                            entry.member = entry
                                .peer
                                .parse::<PeerId>()
                                .ok()
                                .and_then(|p| b.member_of(&p).map(str::to_string));
                        }
                    }
                    // Keep a session to every member (NI-1); a member is
                    // dialled at the addresses identify and Kademlia learned.
                    // G4 S5: the members, and only they, are explicit gossip
                    // peers (always sent to, never scored out of the mesh).
                    let current: std::collections::HashSet<PeerId> =
                        members(&book).into_iter().collect();
                    for gone in explicit.difference(&current) {
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(gone);
                    }
                    for peer in current.difference(&explicit) {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(peer);
                    }
                    explicit = current;
                    // B22: bootnodes not reached yet (they may boot after us).
                    for addr in unresolved.due(std::time::Instant::now()) {
                        let _ = swarm.dial(DialOpts::unknown_peer_id().address(addr).build());
                    }
                    for peer in members(&book) {
                        if !swarm.is_connected(&peer) {
                            let _ = swarm.dial(
                                DialOpts::peer_id(peer)
                                    .condition(PeerCondition::DisconnectedAndNotDialing)
                                    .build(),
                            );
                        }
                    }
                }
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Consensus(request_response::Event::Message {
                        peer,
                        message: request_response::Message::Request { request, channel, .. },
                    })) => {
                        // NI-1: only a session whose key names a member is heard;
                        // anyone else's channel is dropped (it sees a failure).
                        let member = book
                            .read()
                            .ok()
                            .and_then(|b| sessions::admit_consensus_request(&b, &peer).map(str::to_string));
                        let within_budget = member
                            .as_ref()
                            .is_some_and(|m| member_budget.spend(m, std::time::Instant::now()));
                        if within_budget && sessions::is_consensus_message(&request) {
                            let _ = swarm.behaviour_mut().consensus.send_response(channel, sessions::CONSENSUS_ACK.to_string());
                            inbox.push(request);
                        } else {
                            drop(channel);
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Consensus(_)) => {}
                    // G4 S1: a sync request from any session, attributed to
                    // the key it authenticated; the node answers it off the
                    // swarm task.
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(request_response::Event::Message {
                        peer,
                        message: request_response::Message::Request { request_id, request, channel },
                    })) => {
                        if !sync_budget.spend(&peer, std::time::Instant::now()) {
                            // NI-3: over its sync quota. A snapshot part is told
                            // "busy" (its client waits it out without losing
                            // its place); anything else is refused.
                            match chain_sync::state_sync::busy_reply(&request) {
                                Some(busy) => {
                                    let _ = swarm.behaviour_mut().sync.send_response(channel, busy);
                                }
                                None => drop(channel),
                            }
                            continue;
                        }
                        let member = book
                            .read()
                            .ok()
                            .and_then(|b| b.member_of(&peer).map(str::to_string));
                        let (reply, answer) = tokio::sync::oneshot::channel();
                        let serve = network::SyncServe {
                            peer: peer.to_string(),
                            member,
                            wire: request,
                            reply,
                        };
                        if sync_serves.try_send(serve).is_ok() {
                            pending_serves.insert(request_id, channel);
                            let served_tx = served_tx.clone();
                            tokio::spawn(async move {
                                let answer = answer.await.ok().flatten();
                                let _ = served_tx.send((request_id, answer)).await;
                            });
                        } else {
                            drop(channel); // the node is saturated: refuse
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(request_response::Event::Message {
                        message: request_response::Message::Response { request_id, response },
                        ..
                    })) => {
                        if let Some(reply) = pending_asks.remove(&request_id) {
                            let _ = reply.send(Ok(response));
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(request_response::Event::OutboundFailure {
                        request_id, error, ..
                    })) => {
                        if let Some(reply) = pending_asks.remove(&request_id) {
                            let _ = reply.send(Err(error.to_string()));
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(request_response::Event::InboundFailure {
                        request_id, ..
                    })) => {
                        pending_serves.remove(&request_id);
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(_)) => {}
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(MdnsEvent::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            println!("👀 mDNS discovered a new peer: {:?}", peer_id);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr.clone());
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(MdnsEvent::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("👋 mDNS peer expired: {:?}", peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Kademlia(KademliaEvent::RoutingUpdated { peer, addresses, .. })) => {
                        println!("🕸️  Kademlia Routing Updated: peer={:?} addrs={:?}", peer, addresses);
                        // B22: nothing is saved from here. Kademlia reports back the
                        // addresses it was given, wrong ones included (a saved 9612
                        // came back on every boot); only an address a dial reached
                        // is saved (ConnectionEstablished, Dialer).
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(GossipsubEvent::Message { propagation_source: peer_id, message_id, message })) => {
                        // G4 S5: every message gets a verdict; only an accepted
                        // one reaches the node or is forwarded.
                        let verdict = 'judge: {
                        // 🛡️ LiDAR PROTECTION LOGIC
                        let now = std::time::Instant::now();

                        // AUDIT-CRITICAL (pre-mainnet B6): rate-limit the PUBLISHER,
                        // not `propagation_source`. `propagation_source` is the
                        // neighbour that RELAYED the message, which in a gossip mesh
                        // is an honest validator forwarding someone else's traffic.
                        // Keying the limiter on it let any unauthenticated stranger
                        // publish >MAX_MSG_PER_SEC and make honest validators
                        // permanently blacklist EACH OTHER — a remote, unauthenticated
                        // partition of the validator set. Gossipsub runs with
                        // MessageAuthenticity::Signed + ValidationMode::Strict, so
                        // `message.source` is the authenticated publisher; fall back to
                        // the relay only if it is somehow absent.
                        // Per-CONNECTION budget: bounds how much one peer can push
                        // at us regardless of who authored it, closing the
                        // identity-rotation bypass of the publisher counter.
                        //
                        // GATE-CRITICAL: this must only DROP. `peer_id` here is
                        // `propagation_source` — the neighbour that RELAYED the
                        // message — so banning on it re-creates the very B6
                        // partition the publisher counter was introduced to fix:
                        // a stranger publishing from throwaway identities makes
                        // honest relays exceed the budget and get blacklisted by
                        // their own peers. Only the authenticated publisher below
                        // may earn a ban. The budget is also an AGGREGATE, not the
                        // per-publisher constant: legitimate relayed traffic is
                        // n_validators * their rate, and the bootstrap re-gossip
                        // loop alone sends 4 rounds x n authors in a tick.
                        {
                            let (c_last, c_count) =
                                conn_tracker.entry(peer_id).or_insert((now, 0));
                            if now.duration_since(*c_last) > std::time::Duration::from_secs(1) {
                                *c_last = now;
                                *c_count = 0;
                            }
                            *c_count += 1;
                            if *c_count > MAX_CONN_MSG_PER_SEC {
                                if c_count.is_multiple_of(500) {
                                    println!(
                                        "⚠️  LiDAR: connection {:?} over aggregate budget ({}/s) — dropping excess",
                                        peer_id, *c_count
                                    );
                                }
                                break 'judge sessions::GossipVerdict::Ignore; // drop this message only; never ban a relay
                            }
                        }

                        // GATE-CRITICAL: this limiter NEVER bans. Four review
                        // rounds produced a ban-the-wrong-peer bug every time the
                        // ban existed:
                        //   * keyed on propagation_source it banned honest RELAYS
                        //     (B6), partitioning the validator set;
                        //   * keyed on message.source it banned the VICTIM, because
                        //     gossipsub messages are self-authenticating and an
                        //     attacker can replay a validator's own old signed
                        //     messages back at its peers;
                        //   * either way a node's own honest recovery burst (the
                        //     re-gossip loop sends 4 rounds x n authors per tick)
                        //     trips it once the validator set grows.
                        // Attribution is not reliable enough here to justify a
                        // punishment that can partition consensus. Dropping the
                        // excess already bounds the work an attacker can impose,
                        // and gossipsub's own peer scoring handles persistent
                        // misbehaviour without the risk of removing an honest
                        // validator from the mesh.
                        let publisher = message.source.unwrap_or(peer_id);
                        if lidar_tracker.len() > MAX_TRACKED_PUBLISHERS {
                            lidar_tracker.retain(|_, (t, _)| {
                                now.duration_since(*t) <= std::time::Duration::from_secs(1)
                            });
                        }
                        if conn_tracker.len() > MAX_TRACKED_PUBLISHERS {
                            conn_tracker.retain(|_, (t, _)| {
                                now.duration_since(*t) <= std::time::Duration::from_secs(1)
                            });
                        }
                        let (last_time, count) = lidar_tracker.entry(publisher).or_insert((now, 0));
                        if now.duration_since(*last_time) > std::time::Duration::from_secs(1) {
                            *last_time = now;
                            *count = 0;
                        }
                        *count += 1;
                        if *count > MAX_MSG_PER_SEC {
                            if count.is_multiple_of(500) {
                                println!(
                                    "⚠️  LiDAR: publisher {:?} over budget ({}/s) — dropping excess",
                                    publisher, *count
                                );
                            }
                            break 'judge sessions::GossipVerdict::Ignore; // drop only
                        }

                        let Ok(wire) = std::str::from_utf8(&message.data) else {
                            break 'judge sessions::GossipVerdict::Reject;
                        };
                        // NI-1: consensus gossip only from a member publisher;
                        // nothing a node never gossips (G4 S5).
                        book.read()
                            .map(|b| sessions::judge_gossip(&b, message.source.as_ref(), &peer_id, wire))
                            .unwrap_or(sessions::GossipVerdict::Ignore)
                        };
                        let acceptance = match verdict {
                            sessions::GossipVerdict::Accept => MessageAcceptance::Accept,
                            sessions::GossipVerdict::Reject => MessageAcceptance::Reject,
                            sessions::GossipVerdict::Ignore => MessageAcceptance::Ignore,
                        };
                        let _ = swarm.behaviour_mut().gossipsub.report_message_validation_result(
                            &message_id,
                            &peer_id,
                            acceptance,
                        );
                        if verdict == sessions::GossipVerdict::Accept {
                            inbox.push(String::from_utf8_lossy(&message.data).into_owned());
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("🌐 P2P Listening on {:?}", address);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, .. } => {
                        // G4 S6: a session the node asked for is open (answered
                        // before any duplicate connection is closed below).
                        if let Some(reply) = pending_dials.remove(&connection_id) {
                            let _ = reply.send(Ok(peer_id.to_string()));
                        }
                        // B22: an address this node dialled is reachable: route
                        // to it by PeerId from now on, and stop redialling it as
                        // an unresolved bootnode.
                        if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                            unresolved.resolved(address);
                            swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, sessions::without_peer(address));
                        }
                        if num_established.get() > MAX_LIBP2P_CONNECTIONS_PER_PEER {
                            eprintln!(
                                "⚠️ Closing duplicate libp2p connection to {:?}: established={} limit={}",
                                peer_id,
                                num_established,
                                MAX_LIBP2P_CONNECTIONS_PER_PEER
                            );
                            let _ = swarm.close_connection(connection_id);
                            continue;
                        }

                        println!("🤝 Connection established with {:?}", peer_id);
                        if num_established.get() == 1 {
                            let member = book
                                .read()
                                .ok()
                                .and_then(|b| b.member_of(&peer_id).map(str::to_string));
                            if let Ok(mut table) = session_table.write() {
                                table.push(network::SessionPeer { peer: peer_id.to_string(), member });
                            }
                        }
                        // G4 S5: only committee members are explicit gossip
                        // peers (committee dial); every other peer meets the
                        // mesh and its score.
                        match endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                if sessions::routable_for_others(&address) {
                                    let _ = storage.save_peer_addr(&peer_id.to_string(), &address.to_string());
                                }
                            }
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                // NI-2: a committee member never counts against the
                                // per-host cap (one host may run several members).
                                let is_member = book
                                    .read()
                                    .map(|b| b.member_of(&peer_id).is_some())
                                    .unwrap_or(false);
                                if !is_member {
                                    // NI-2: the non-members share one cap.
                                    if non_member_inbound.len() >= sessions::MAX_NON_MEMBER_INBOUND {
                                        let _ = swarm.close_connection(connection_id);
                                        continue;
                                    }
                                    non_member_inbound.insert(connection_id);
                                }
                                if let (false, Some(host)) = (is_member, multiaddr_host(&send_back_addr)) {
                                    let count = inbound_connections_by_host.entry(host.clone()).or_insert(0);
                                    *count = count.saturating_add(1);
                                    counted_inbound.insert(connection_id, host.clone());
                                    if *count > MAX_INBOUND_LIBP2P_CONNECTIONS_PER_HOST {
                                        eprintln!(
                                            "⚠️ Closing excess inbound libp2p connection from {}: established={} limit={}",
                                            host,
                                            count,
                                            MAX_INBOUND_LIBP2P_CONNECTIONS_PER_HOST
                                        );
                                        let _ = swarm.close_connection(connection_id);
                                        continue;
                                    }
                                }
                                // Do not persist inbound send-back addresses: they are usually
                                // ephemeral source ports, not stable listen addresses. Persisting
                                // them poisons the next boot's bootnode list and can trigger a
                                // connection storm against stale ports.
                                println!("🤝 Inbound libp2p connection from {:?} via {}", peer_id, send_back_addr);
                            }
                        }
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established, .. } => {
                        non_member_inbound.remove(&connection_id);
                        if num_established == 0 {
                            if let Ok(mut table) = session_table.write() {
                                let peer = peer_id.to_string();
                                table.retain(|s| s.peer != peer);
                            }
                        }
                        if let Some(host) = counted_inbound.remove(&connection_id) {
                            if let Some(count) = inbound_connections_by_host.get_mut(&host) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    inbound_connections_by_host.remove(&host);
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new })) => {
                        println!("🔄 AutoNAT Status Changed: {:?} -> {:?}", old, new);
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        println!("🆔 Identify Received from {:?}: Agent={:?}, Addrs={:?}", peer_id, info.agent_version, info.listen_addrs);
                        // B22: a peer reached over the network is routed only at
                        // addresses another host can dial (its loopback is its
                        // own); a peer on this host keeps them all.
                        let local_peer = !sessions::routable_for_others(&info.observed_addr);
                        for addr in info.listen_addrs {
                            unresolved.resolved(&addr);
                            if !local_peer && !sessions::routable_for_others(&addr) {
                                continue;
                            }
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, connection_id, error, .. } => {
                        if let Some(reply) = pending_dials.remove(&connection_id) {
                            let _ = reply.send(Err(error.to_string()));
                        }
                        eprintln!("❌ P2P Outgoing Connection Error to {:?}: {:?}", peer_id, error);
                    }
                    SwarmEvent::Dialing { peer_id, .. } => {
                        println!("📞 Dialing peer: {:?}", peer_id);
                    }
                    _ => {}
                }
            }
        }
    });

    Ok((tx_out, rx_out))
}
