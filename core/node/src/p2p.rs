use libp2p::{
    core::upgrade,
    identity,
    noise,
    yamux,
    gossipsub::{Behaviour as GossipsubBehaviour, Config as GossipsubConfig, IdentTopic, MessageAuthenticity, Event as GossipsubEvent},
    mdns::{tokio::Behaviour as Mdns, Event as MdnsEvent, Config as MdnsConfig},
    kad::{store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Event as KademliaEvent},
    swarm::{Swarm, SwarmEvent},
    Multiaddr, PeerId, Transport,
    multiaddr::Protocol,
    tcp,
    autonat,
    identify,
    dcutr,
    relay,
};
use libp2p::futures::StreamExt;
use tokio::sync::mpsc;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use storage::StateDB;

// === START P2P ===
use libp2p::swarm::behaviour::toggle::Toggle;

// === START P2P ===
// Returns: (Sender to broadcast, Receiver for incoming messages)
pub async fn start_p2p(port: u16, bootnodes: Vec<String>, storage: Arc<StateDB>, enable_mdns: bool, enable_nat: bool) -> Result<(mpsc::Sender<String>, mpsc::Receiver<String>), Box<dyn Error>> {
    let (tx_out, mut rx_in) = mpsc::channel::<String>(64); // Main -> P2P
    let (tx_in, rx_out) = mpsc::channel::<String>(64);     // P2P -> Main

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

    // === Gossipsub behaviour ===
    let gossipsub_config = GossipsubConfig::default();
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
    let autonat = autonat::Behaviour::new(
        local_peer_id,
        autonat::Config::default(),
    );

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
        libp2p::swarm::Config::with_tokio_executor(),
    );

    // Add bootnodes
    for peer_addr in bootnodes {
        if let Ok(multiaddr) = peer_addr.parse::<Multiaddr>() {
            println!("🔗 Adding bootnode: {:?}", multiaddr);
    if let Some(Protocol::P2p(peer_id)) = multiaddr.iter().last() {
        swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr.clone());
        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
    }
            // Force dial
            if let Err(e) = swarm.dial(multiaddr) {
                eprintln!("❌ Failed to dial bootnode: {:?}", e);
            }
        }
    }

    // === Listen on configured libp2p port (port + 100 to avoid conflict with legacy TCP) ===
    let libp2p_port = port + 100;
    let addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", libp2p_port).parse()?;
    Swarm::listen_on(&mut swarm, addr)?;

    // === LiDAR DDoS Protection ===
    let mut lidar_tracker: std::collections::HashMap<PeerId, (std::time::Instant, u32)> = std::collections::HashMap::new();
    const MAX_MSG_PER_SEC: u32 = 100; // Production Grade Limit

    // === Event Loop ===
    tokio::spawn(async move {
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
                            let _ = swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr.clone());
                            
                            // Persist peer
                            let _ = storage.save_peer_addr(&peer_id.to_string(), &multiaddr.to_string());
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Mdns(MdnsEvent::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            println!("👋 mDNS peer expired: {:?}", peer_id);
                            let _ = swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Kademlia(KademliaEvent::RoutingUpdated { peer, addresses, .. })) => {
                        println!("🕸️  Kademlia Routing Updated: peer={:?} addrs={:?}", peer, addresses);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                        
                        // Persist peer (save first known address)
                        if let Some(addr) = addresses.iter().next() {
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
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                        println!("🤝 Connection established with {:?}", peer_id);
                        let addr = match endpoint {
                            libp2p::core::ConnectedPoint::Dialer { address, .. } => address,
                            libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
                        };
                        let _ = storage.save_peer_addr(&peer_id.to_string(), &addr.to_string());
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Autonat(autonat::Event::StatusChanged { old, new })) => {
                        println!("🔄 AutoNAT Status Changed: {:?} -> {:?}", old, new);
                    }
                    SwarmEvent::Behaviour(P2PBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        println!("🆔 Identify Received from {:?}: Agent={:?}, Addrs={:?}", peer_id, info.agent_version, info.listen_addrs);
                        for addr in info.listen_addrs {
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
