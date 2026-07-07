use libp2p::futures::StreamExt;
use libp2p::{
    autonat,
    core::upgrade,
    dcutr,
    gossipsub::{
        Behaviour as GossipsubBehaviour, ConfigBuilder as GossipsubConfigBuilder,
        Event as GossipsubEvent, IdentTopic, MessageAuthenticity, ValidationMode,
    },
    identify, identity,
    kad::{
        store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent,
    },
    mdns::{tokio::Behaviour as Mdns, Config as MdnsConfig, Event as MdnsEvent},
    multiaddr::Protocol,
    noise, relay,
    swarm::{Swarm, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId, Transport,
};
use std::error::Error;
use std::sync::Arc;
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

fn is_docker_bridge_addr(addr: &Multiaddr) -> bool {
    addr.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => {
            let octets = ip.octets();
            octets[0] == 172 && (16..=31).contains(&octets[1])
        }
        _ => false,
    })
}

// === START P2P ===
// Returns: (Sender to broadcast, Receiver for incoming messages)
pub async fn start_p2p(
    port: u16,
    bootnodes: Vec<String>,
    storage: Arc<StateDB>,
    enable_mdns: bool,
    enable_nat: bool,
) -> Result<(mpsc::Sender<String>, mpsc::Receiver<String>), Box<dyn Error>> {
    let (tx_out, mut rx_in) = mpsc::channel::<String>(64); // Main -> P2P
    let (tx_in, rx_out) = mpsc::channel::<String>(64); // P2P -> Main

    // === Generate keypair ===
    let local_key = identity::Keypair::generate_ed25519();
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
        .boxed();

    // === Gossipsub behaviour (Phase 2.7 / M-05 hardened config) ===
    //
    // Default libp2p Gossipsub config is tuned for general use, not for a
    // BFT L1 with adversarial validators. M-05 tightens the params:
    //
    //   * validation_mode = Strict
    //       Reject malformed messages immediately instead of forwarding,
    //       so a Byzantine peer cannot waste mesh bandwidth flooding
    //       garbage to its neighbours.
    //   * max_transmit_size = 1 MiB
    //       Bounds per-message work and aligns with the mempool's 100KB
    //       tx limit + headroom for batched DAG vertices. Default is
    //       much larger and lets a single peer push memory pressure.
    //   * mesh params (D, D_lo, D_hi)
    //       Default D=6 is fine for typical p2p; we keep it but pin the
    //       low/high watermarks so adversarial churn cannot drift the
    //       mesh into degenerate fan-out.
    //   * heartbeat_interval = 1 s (default), but documented here so the
    //       cadence is explicit when reading the config.
    //   * duplicate_cache_time = 60 s
    //       Suppresses replayed messages for a full minute. The default
    //       (30 s) is on the low side for a chain with 5 s round times
    //       under load.
    //   * message_id_fn = sha256 of payload
    //       Deduplication keys are cryptographic, not pointer-based, so
    //       semantically-equal messages from different peers collapse.
    let gossipsub_config = GossipsubConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .max_transmit_size(1 << 20) // 1 MiB
        .mesh_n(6)
        .mesh_n_low(4)
        .mesh_n_high(12)
        .heartbeat_interval(Duration::from_secs(1))
        .duplicate_cache_time(Duration::from_secs(60))
        .message_id_fn(|msg| {
            use sha2::{Digest, Sha256};
            libp2p::gossipsub::MessageId::from(Sha256::digest(&msg.data).to_vec())
        })
        .build()
        .map_err(|e| -> Box<dyn Error> { format!("gossipsub config: {}", e).into() })?;
    let mut gossipsub = GossipsubBehaviour::new(
        MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )?;
    let topic = IdentTopic::new("aincore-gossip");
    gossipsub.subscribe(&topic)?;

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
    }

    let behaviour = P2PBehaviour {
        gossipsub,
        mdns: Toggle::from(mdns),
        kademlia,
        autonat,
        identify,
        dcutr: Toggle::from(dcutr_behaviour),
        relay: Toggle::from(relay_behaviour),
    };

    // === Swarm ===
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(Duration::from_secs(20)),
    );

    // Add bootnodes
    for peer_addr in bootnodes {
        if let Ok(multiaddr) = peer_addr.parse::<Multiaddr>() {
            println!("🔗 Adding bootnode: {:?}", multiaddr);
            if let Some(Protocol::P2p(peer_id)) = multiaddr.iter().last() {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, multiaddr.clone());
                swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
            }
            // Force dial
            if let Err(e) = swarm.dial(multiaddr) {
                eprintln!("❌ Failed to dial bootnode: {:?}", e);
            }
        }
    }

    // === Listen on configured libp2p port (port + 100 to avoid conflict with legacy TCP) ===
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
    const MAX_MSG_PER_SEC: u32 = 100; // Production Grade Limit

    // === Event Loop ===
    tokio::spawn(async move {
        let mut inbound_connections_by_host: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();

        loop {
            tokio::select! {
                Some(msg) = rx_in.recv() => {
                    // println!("📤 Broadcasting TX via P2P: {}", msg);
                    let _ = swarm.behaviour_mut().gossipsub.publish(IdentTopic::new("aincore-gossip"), msg.as_bytes());
                }
                event = swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(MdnsEvent::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            println!("👀 mDNS discovered a new peer: {:?}", peer_id);
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr.clone());

                            // Persist peer
                            let _ = storage.save_peer_addr(&peer_id.to_string(), &multiaddr.to_string());
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(MdnsEvent::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("👋 mDNS peer expired: {:?}", peer_id);
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Kademlia(KademliaEvent::RoutingUpdated { peer, addresses, .. })) => {
                        println!("🕸️  Kademlia Routing Updated: peer={:?} addrs={:?}", peer, addresses);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);

                        // Persist the first routable address. Docker bridge addresses
                        // (172.16.0.0/12) leak through Identify/Kademlia when nodes run
                        // in containers, but remote peers cannot dial them. Persisting
                        // those addresses poisons the next boot's bootnode list and
                        // causes repeated TCP connect timeouts.
                        if let Some(addr) = addresses.iter().find(|addr| !is_docker_bridge_addr(addr)) {
                             let _ = storage.save_peer_addr(&peer.to_string(), &addr.to_string());
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Gossipsub(GossipsubEvent::Message { propagation_source: peer_id, message_id: _, message })) => {
                        // 🛡️ LiDAR PROTECTION LOGIC
                        let now = std::time::Instant::now();
                        let (last_time, count) = lidar_tracker.entry(peer_id).or_insert((now, 0));

                        if now.duration_since(*last_time) > std::time::Duration::from_secs(1) {
                            // Reset window
                            *last_time = now;
                            *count = 0;
                        }

                        *count += 1;

                        if *count > MAX_MSG_PER_SEC {
                            println!("⛔ LiDAR DETECTED ATTACK: Banning Peer {:?} (Rate: {}/s)", peer_id, *count);
                            // Ban action: Disconnect
                            let _ = swarm.disconnect_peer_id(peer_id);
                            // Optional: Blacklist in Gossipsub to prevent reconnect
                            swarm.behaviour_mut().gossipsub.blacklist_peer(&peer_id);
                            continue; // DROP MESSAGE
                        }

                        let msg_content = String::from_utf8_lossy(&message.data).to_string();
                        // println!("📨 Received P2P message from {:?}: {}", peer_id, msg_content);
                        if let Err(e) = tx_in.send(msg_content).await {
                            eprintln!("❌ Failed to send P2P msg to main loop: {}", e);
                        }
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        println!("🌐 P2P Listening on {:?}", address);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, .. } => {
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
                        // FIX (mesh propagation): register every established libp2p connection as
                        // an explicit gossipsub peer, keyed on the peer id learned from the live
                        // connection. Bootnodes are dialed as bare /ip4/<ip>/tcp/<port> (no
                        // /p2p/<peerid> suffix) and the libp2p identity is ephemeral per boot, so
                        // the bootnode loop never learns peer ids up-front and never calls
                        // add_explicit_peer. In a small validator set (n=3) that left connected
                        // validators OUT of each other's gossipsub mesh, so DAG vertices never
                        // propagated and Parents stayed below quorum (chain stuck). Grafting on the
                        // live peer id forces reliable forwarding regardless of how we dialed.
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        match endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => {
                                let _ = storage.save_peer_addr(&peer_id.to_string(), &address.to_string());
                            }
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => {
                                if let Some(host) = multiaddr_host(&send_back_addr) {
                                    let count = inbound_connections_by_host.entry(host.clone()).or_insert(0);
                                    *count = count.saturating_add(1);
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
                    SwarmEvent::ConnectionClosed { endpoint, .. } => {
                        // pre-existing nesting; kept explicit for clarity over collapsing
                        #[allow(clippy::collapsible_match)]
                        if let libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } = endpoint {
                            if let Some(host) = multiaddr_host(&send_back_addr) {
                                if let Some(count) = inbound_connections_by_host.get_mut(&host) {
                                    *count = count.saturating_sub(1);
                                    if *count == 0 {
                                        inbound_connections_by_host.remove(&host);
                                    }
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new })) => {
                        println!("🔄 AutoNAT Status Changed: {:?} -> {:?}", old, new);
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        println!("🆔 Identify Received from {:?}: Agent={:?}, Addrs={:?}", peer_id, info.agent_version, info.listen_addrs);
                        for addr in info.listen_addrs {
                            if is_docker_bridge_addr(&addr) {
                                println!("🧹 Ignoring Docker bridge peer address from Identify: {}", addr);
                                continue;
                            }
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
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
