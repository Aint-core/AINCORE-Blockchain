use crate::sessions::{self, PeerBook, SessionWiring};
use libp2p::futures::StreamExt;
use libp2p::{
    autonat,
    core::upgrade,
    dcutr, identify,
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
/// A dial by PeerId tries the peer's addresses at once; the dialer keeps
/// the first that opens and drops the rest, and the listener sees several
/// open for a moment. Closing the extras the moment they opened raced with
/// the dialer's choice: it could close the one kept, and the dialer then
/// redialled in a loop (rehearsal, 2026-10-03: ~150 closes a node in five
/// minutes). Extras above `MAX_LIBP2P_CONNECTIONS_PER_PEER` are closed once
/// they outlive this grace, the newest first; only past
/// `MAX_LIBP2P_CONNECTIONS_HARD` at once (libp2p's default dial
/// concurrency, 8, from each side).
const DUPLICATE_GRACE: Duration = Duration::from_secs(5);
const MAX_LIBP2P_CONNECTIONS_HARD: u32 = 16;
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
/// A non-member's sync request being answered: the busy reply its kind has
/// (B30) and the budget key its answer is charged to (B60).
struct OpenServe {
    busy: Option<String>,
    key: String,
}

/// How often the network task dials the committee members it is not
/// connected to.
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
) -> Result<(mpsc::Sender<Outbound>, mpsc::Receiver<(String, String)>), Box<dyn Error>> {
    let SessionWiring {
        book,
        table: session_table,
        asks: mut sync_asks,
        dials: mut sync_dials,
        serves: sync_serves,
        held_open_bytes,
    } = wiring;
    // Main -> P2P.
    let (tx_out, mut rx_in) = mpsc::channel::<Outbound>(64);
    // P2P -> Main: (source, message); B51 holds a source to account.
    let (tx_in, rx_out) = mpsc::channel::<(String, String)>(64);

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
        // B24: admission before the handshake, per IP and in all. First: a
        // behaviour asked after one that denies a connection has already
        // set up state for it (the derive asks the fields in this order).
        gate: sessions::InboundGate,
        limits: libp2p::connection_limits::Behaviour,
        mdns: Toggle<Mdns>,
        kademlia: Kademlia<MemoryStore>,
        autonat: autonat::Behaviour,
        identify: identify::Behaviour,
        pub dcutr: Toggle<dcutr::Behaviour>,
        pub relay: Toggle<relay::client::Behaviour>,
        // B30: the protocol exists on members' connections only.
        consensus: sessions::MembersOnly,
        sync: request_response::Behaviour<sessions::FramedCodec>,
    }

    // B56: the IPs members connected from; the gate keeps slots for them.
    let member_ips: sessions::MemberIps = Arc::default();
    let behaviour = P2PBehaviour {
        mdns: Toggle::from(mdns),
        kademlia,
        autonat,
        identify,
        consensus: sessions::MembersOnly::new(Arc::clone(&book)),
        sync: sessions::sync_behaviour(),
        dcutr: Toggle::from(dcutr_behaviour),
        relay: Toggle::from(relay_behaviour),
        gate: sessions::InboundGate::with_member_ips(Arc::clone(&member_ips)),
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
    // setting AINCORE_P2P_LISTEN=0. They still dial bootnodes and sync
    // over outbound connections, but they do not accept inbound
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
        // The channel, and for a non-member its busy reply if the request
        // has one (B30: the held-answer bound refuses with it) and the key
        // its answer is charged to (B60).
        let mut pending_serves: std::collections::HashMap<
            request_response::InboundRequestId,
            (request_response::ResponseChannel<String>, Option<OpenServe>),
        > = std::collections::HashMap::new();
        let mut held_answers: sessions::HeldAnswers<request_response::InboundRequestId> =
            sessions::HeldAnswers::new(held_open_bytes);
        let (served_tx, mut served_rx) =
            mpsc::channel::<(request_response::InboundRequestId, Option<String>)>(64);
        // B25: boundary-QC asks this node made over sync for itself; their
        // answers go to the node like a member's push.
        let mut inbox_asks: std::collections::HashSet<request_response::OutboundRequestId> =
            std::collections::HashSet::new();
        // G4 S6: sessions the node asked for by address, until they open.
        let mut pending_dials: std::collections::HashMap<
            libp2p::swarm::ConnectionId,
            tokio::sync::oneshot::Sender<Result<String, String>>,
        > = std::collections::HashMap::new();
        // G4 NI-3: per-member consensus budget, per-session sync quota.
        let mut member_budget: sessions::Budget<String> =
            sessions::Budget::new(sessions::MEMBER_MSGS_PER_SEC, sessions::MEMBER_MSG_BURST);
        // B34: members by key, everyone else by host (a host's free
        // identities share one budget).
        let mut sync_budget: sessions::Budget<String> = sessions::Budget::new(
            sessions::SYNC_REQUESTS_PER_SEC,
            sessions::SYNC_REQUEST_BURST,
        );
        // G4 NI-3: messages bound for the node; the swarm never waits on it.
        let mut inbox = sessions::Inbox::default();
        // The open connections to each peer, with when each opened.
        let mut peer_connections: std::collections::HashMap<
            PeerId,
            Vec<(libp2p::swarm::ConnectionId, std::time::Instant)>,
        > = std::collections::HashMap::new();
        // Every connection opened and closed, for diagnosis
        // (`AINCORE_P2P_TRACE=1`).
        let trace_connections = std::env::var("AINCORE_P2P_TRACE").as_deref() == Ok("1");
        // Consensus pushes that failed (logged at powers of two).
        let mut consensus_failures: u64 = 0;
        // G4 NI-2: inbound connections from non-members, all together.
        // B34: the host each connected peer reached this node from (or at).
        let mut peer_hosts: std::collections::HashMap<PeerId, String> =
            std::collections::HashMap::new();
        // B40: and outbound to non-members.
        let mut non_member_outbound: std::collections::HashSet<libp2p::swarm::ConnectionId> =
            std::collections::HashSet::new();
        let mut non_member_inbound: std::collections::HashSet<libp2p::swarm::ConnectionId> =
            std::collections::HashSet::new();
        let members = |book: &Arc<RwLock<PeerBook>>| -> Vec<PeerId> {
            book.read()
                .map(|b| b.peers().copied().filter(|p| *p != local_peer_id).collect())
                .unwrap_or_default()
        };

        loop {
            tokio::select! {
                Some(out) = rx_in.recv() => match out {
                    // B25: a node outside the committee asks members for a
                    // boundary QC over sync and takes the answer as if a
                    // member had pushed it.
                    Outbound::Broadcast(wire)
                        if wire.starts_with(consensus::dag::QC_WANT_PREFIX)
                            && book.read().is_ok_and(|b| b.member_of(&local_peer_id).is_none()) =>
                    {
                        let asked: Vec<PeerId> = members(&book)
                            .into_iter()
                            .filter(|p| swarm.is_connected(p))
                            .take(2)
                            .collect();
                        for peer in asked {
                            let id = swarm.behaviour_mut().sync.send_request(&peer, wire.clone());
                            inbox_asks.insert(id);
                        }
                    }
                    // B48: pushed on every connected member session, and
                    // nothing else (gossip is gone: a member that stopped
                    // reading made every node queue gossip for it without
                    // bound). A member missing one asks for it (V4 pulls) or
                    // gets the next rebroadcast.
                    Outbound::Broadcast(wire) => {
                        if sessions::is_consensus_message(&wire) {
                            for peer in members(&book) {
                                if swarm.is_connected(&peer) {
                                    swarm.behaviour_mut().consensus.send_request(&peer, wire.clone());
                                }
                            }
                        }
                    }
                    // An addressed message goes on its member's session only;
                    // one for an address the book does not name is dropped
                    // (B48: it used to be flooded over gossip).
                    Outbound::To { address, wire } => {
                        let peer = book.read().ok().and_then(|b| b.peer_of(&address));
                        if let Some(peer) = peer.filter(|p| *p != local_peer_id) {
                            swarm.behaviour_mut().consensus.send_request(&peer, wire);
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
                    if let Some((channel, open)) = pending_serves.remove(&id) {
                        match answer {
                            Some(answer) => {
                                // B30: when non-members already hold too many
                                // unread answers, a snapshot part is told busy
                                // and anything else is refused.
                                let refused = open.is_some() && !held_answers.admit(id, answer.len());
                                if refused {
                                    match open.and_then(|o| o.busy) {
                                        Some(busy) => {
                                            let _ = swarm.behaviour_mut().sync.send_response(channel, busy);
                                        }
                                        None => drop(channel),
                                    }
                                } else {
                                    // B60: and by its bytes.
                                    if let Some(open) = &open {
                                        sync_budget.charge(
                                            &open.key,
                                            sessions::answer_tokens(answer.len()),
                                            std::time::Instant::now(),
                                        );
                                    }
                                    if swarm.behaviour_mut().sync.send_response(channel, answer).is_err() {
                                        held_answers.release(&id);
                                    }
                                }
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
                    // B30: a connection opened under an older book carries the
                    // wrong consensus handler: close it; once it is closed, the
                    // committee dial below dials a member again (a dial at once
                    // opened a second session beside the closing one).
                    for (peer, id) in swarm.behaviour().consensus.misfiled() {
                        println!("🔐 [P2P] reconnecting {peer}: its session opened under another committee");
                        swarm.close_connection(id);
                    }
                    // Extra connections to one peer that outlived the grace:
                    // the dialer kept them; the newest go.
                    let now = std::time::Instant::now();
                    for (peer, open) in &peer_connections {
                        let mut open = open.clone();
                        open.sort_by_key(|(_, at)| *at);
                        for (id, at) in open.into_iter().skip(MAX_LIBP2P_CONNECTIONS_PER_PEER as usize) {
                            if now.duration_since(at) >= DUPLICATE_GRACE {
                                eprintln!(
                                    "⚠️ Closing duplicate libp2p connection to {peer:?}: limit={MAX_LIBP2P_CONNECTIONS_PER_PEER}"
                                );
                                swarm.close_connection(id);
                            }
                        }
                    }
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
                        // B26: acknowledged only once queued; a push the full
                        // inbox drops fails at its sender, which sends it again.
                        // B55: each member's pushes queue apart.
                        let queued = match &member {
                            Some(m) if within_budget && sessions::is_consensus_message(&request) => {
                                inbox.push(m, request)
                            }
                            _ => false,
                        };
                        if queued {
                            let _ = swarm.behaviour_mut().consensus.send_response(channel, sessions::CONSENSUS_ACK.to_string());
                        } else {
                            drop(channel);
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Consensus(request_response::Event::OutboundFailure {
                        peer, error, ..
                    })) => {
                        consensus_failures += 1;
                        if consensus_failures.is_power_of_two() {
                            eprintln!(
                                "⚠️ [P2P] consensus push to {peer} failed: {error} ({consensus_failures} so far)"
                            );
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
                        let member = book
                            .read()
                            .ok()
                            .and_then(|b| b.member_of(&peer).map(str::to_string));
                        let budget_key = match (&member, peer_hosts.get(&peer)) {
                            (None, Some(host)) => format!("host:{host}"),
                            _ => peer.to_string(),
                        };
                        if !sync_budget.spend(&budget_key, std::time::Instant::now()) {
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
                        let (reply, answer) = tokio::sync::oneshot::channel();
                        let open = member.is_none().then(|| OpenServe {
                            busy: chain_sync::state_sync::busy_reply(&request),
                            key: budget_key.clone(),
                        });
                        let serve = network::SyncServe {
                            peer: peer.to_string(),
                            member,
                            wire: request,
                            reply,
                        };
                        if sync_serves.try_send(serve).is_ok() {
                            pending_serves.insert(request_id, (channel, open));
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
                        peer,
                        message: request_response::Message::Response { request_id, response },
                        ..
                    })) => {
                        if inbox_asks.remove(&request_id) {
                            if response.starts_with(consensus::dag::QC_CERT_PREFIX) {
                                inbox.push(&peer.to_string(), response);
                            }
                        } else if let Some(reply) = pending_asks.remove(&request_id) {
                            let _ = reply.send(Ok(response));
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(request_response::Event::OutboundFailure {
                        request_id, error, ..
                    })) => {
                        inbox_asks.remove(&request_id);
                        if let Some(reply) = pending_asks.remove(&request_id) {
                            let _ = reply.send(Err(error.to_string()));
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(request_response::Event::InboundFailure {
                        request_id, ..
                    })) => {
                        pending_serves.remove(&request_id);
                        held_answers.release(&request_id);
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Sync(request_response::Event::ResponseSent {
                        request_id, ..
                    })) => {
                        held_answers.release(&request_id);
                    }
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
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("🌐 P2P Listening on {:?}", address);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, .. } => {
                        if trace_connections {
                            eprintln!("[P2P-TRACE] up {peer_id} {connection_id:?} n={num_established} {endpoint:?}");
                        }
                        // G4 S6: a session the node asked for is open (answered
                        // before any duplicate connection is closed below).
                        if let Some(reply) = pending_dials.remove(&connection_id) {
                            let _ = reply.send(Ok(peer_id.to_string()));
                        }
                        // B22: an address this node dialled is reachable: route
                        // to it by PeerId from now on, and stop redialling it as
                        // an unresolved bootnode.
                        let mut was_bootnode = false;
                        if let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint {
                            was_bootnode = unresolved.resolved(address);
                            swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, sessions::without_peer(address));
                        }
                        if num_established.get() > MAX_LIBP2P_CONNECTIONS_HARD {
                            eprintln!(
                                "⚠️ Closing duplicate libp2p connection to {:?}: established={} limit={}",
                                peer_id,
                                num_established,
                                MAX_LIBP2P_CONNECTIONS_HARD
                            );
                            let _ = swarm.close_connection(connection_id);
                            continue;
                        }
                        peer_connections
                            .entry(peer_id)
                            .or_default()
                            .push((connection_id, std::time::Instant::now()));

                        println!("🤝 Connection established with {:?}", peer_id);
                        let host = match &endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => multiaddr_host(address),
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => multiaddr_host(send_back_addr),
                        };
                        if let Some(host) = host {
                            // B56: a member's IP gets the gate's kept slots.
                            if book.read().is_ok_and(|b| b.member_of(&peer_id).is_some()) {
                                if let (Ok(ip), Ok(mut ips)) =
                                    (host.parse::<std::net::IpAddr>(), member_ips.write())
                                {
                                    if ips.len() < sessions::MAX_MEMBER_IPS {
                                        ips.insert(ip);
                                    }
                                }
                            }
                            peer_hosts.insert(peer_id, host);
                        }
                        if num_established.get() == 1 {
                            let member = book
                                .read()
                                .ok()
                                .and_then(|b| b.member_of(&peer_id).map(str::to_string));
                            if let Ok(mut table) = session_table.write() {
                                table.push(network::SessionPeer { peer: peer_id.to_string(), member });
                            }
                        }
                        match endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                let is_member = book
                                    .read()
                                    .map(|b| b.member_of(&peer_id).is_some())
                                    .unwrap_or(false);
                                // B40: outbound non-member connections share a cap.
                                if !is_member {
                                    if non_member_outbound.len() >= sessions::MAX_NON_MEMBER_OUTBOUND {
                                        let _ = swarm.close_connection(connection_id);
                                        continue;
                                    }
                                    non_member_outbound.insert(connection_id);
                                }
                                // B43: only a member's or a bootnode's address is
                                // saved for the next boot (rows grew with every
                                // peer Kademlia ever dialled).
                                if (is_member || was_bootnode) && sessions::routable_for_others(&address) {
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
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, num_established, cause, .. } => {
                        if let Some(open) = peer_connections.get_mut(&peer_id) {
                            open.retain(|(id, _)| *id != connection_id);
                            if open.is_empty() {
                                peer_connections.remove(&peer_id);
                            }
                        }
                        if trace_connections {
                            eprintln!("[P2P-TRACE] down {peer_id} {connection_id:?} n={num_established} cause={cause:?}");
                        }
                        non_member_inbound.remove(&connection_id);
                        non_member_outbound.remove(&connection_id);
                        if num_established == 0 {
                            peer_hosts.remove(&peer_id);
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
