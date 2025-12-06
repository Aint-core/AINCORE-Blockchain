// === --- IMPORT FASE 1 --- ===
use storage::StateDB;
// use network::{start_server, handshake}; // start_server unused
use network::handshake;
use std::env;
use std::sync::{Arc, Mutex};
use std::{thread, time::Duration};

// === --- IMPORT FASE 2 --- ===
use executor::Executor;
use mempool::Mempool;
use consensus::DagConsensus;

// === --- IMPORT FASE 3 (Chain Sync) --- ===
use chain_sync::{ChainSync, SyncRequest, SyncResponse};

// === --- IMPORT FASE 4 (DA Sequencer) --- ===
use da_sequencer::DASequencer;

// === --- IMPORT FASE 5 (P2P Network) --- ===
// === --- IMPORT FASE 5 (P2P Network) --- ===
use node::p2p::start_p2p;
use node::genesis;
// use node::api; // Bypass library issue
mod api_local;
use api_local as api;

#[tokio::main]
async fn main() {
    // === ARGUMENT PARSER ===
    let args: Vec<String> = env::args().collect();
    let mut port: u16 = 9001;
    let mut api_port: u16 = 8001;
    let mut datadir = "data".to_string();
    let mut initial_peers: Vec<u16> = Vec::new();
    let mut bootnodes: Vec<String> = Vec::new();
    let mut enable_mdns = false;
    let mut enable_nat = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(9001);
                    api_port = port - 1000;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--datadir" => {
                if i + 1 < args.len() {
                    datadir = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--peers" => {
                if i + 1 < args.len() {
                    initial_peers = args[i + 1]
                        .split(',')
                        .filter_map(|s| s.trim().parse::<u16>().ok())
                        .collect();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--bootnodes" => {
                if i + 1 < args.len() {
                    bootnodes = args[i + 1]
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--enable-mdns" => {
                enable_mdns = true;
                i += 1;
            }
            "--enable-nat" => {
                enable_nat = true;
                i += 1;
            }
            "--rpc-port" => {
                if i + 1 < args.len() {
                    api_port = args[i + 1].parse().unwrap_or(8001);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    // === INISIALISASI NODE IDENTITY ===
    use ed25519_dalek::{SigningKey};
    // Load or Generate Keypair
    let _ = std::fs::create_dir_all(&datadir); // Ensure data dir exists
    let key_path_buf = std::path::Path::new(&datadir).join("node_identity.key");
    let key_path = key_path_buf.to_str().expect("Invalid path");
    
    let signing_key = if key_path_buf.exists() {
        println!("🔑 Loading node identity from {}", key_path);
        let bytes = std::fs::read(key_path).expect("Failed to read node key");
        SigningKey::from_bytes(bytes.as_slice().try_into().expect("Invalid key length"))
    } else {
        println!("🔑 Generating new node identity and saving to {}", key_path);
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        std::fs::write(key_path, key.to_bytes()).expect("Failed to save node key");
        key
    };

    let verifying_key = signing_key.verifying_key();
    let pub_key_hex = hex::encode(verifying_key.to_bytes());
    // Use first 16 bytes (32 hex chars) as address for Move compatibility
    let node_addr_hex = pub_key_hex[0..32].to_string();
    let node_id = node_addr_hex.clone(); // Use address as node_id for consensus matching

    let db_path = format!("{}/validator_{}.db", datadir, port);
    let storage = Arc::new(StateDB::open(&db_path));
    let peers = Arc::new(Mutex::new(std::collections::HashMap::<String, u16>::new()));

    println!("🚀 AINCORE node {} running on port {}", node_id, port);
    println!("🚀 DEBUG: I AM THE NEW CODE (Step 830)");
    println!("🌐 Listening on TCP port {}", port);

    // === LOAD PERSISTED PEERS ===
    let saved_peer_addrs = storage.scan_peer_addrs();
    if !saved_peer_addrs.is_empty() {
        println!("📚 Found {} saved peer addresses in database", saved_peer_addrs.len());
        for (_, addr) in saved_peer_addrs {
            if !bootnodes.contains(&addr) {
                bootnodes.push(addr);
            }
        }
    }

    // === NORMALIZE BOOTNODES ===
    let normalized_bootnodes: Vec<String> = bootnodes.iter().map(|s| {
        if s.starts_with("/") {
            s.clone()
        } else {
            // Try IP:PORT
            if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
                 format!("/ip4/{}/tcp/{}", addr.ip(), addr.port())
            } else {
                // Try DOMAIN:PORT (e.g. ngrok)
                let parts: Vec<&str> = s.split(':').collect();
                if parts.len() == 2 {
                    if let Ok(p) = parts[1].parse::<u16>() {
                        format!("/dns4/{}/tcp/{}", parts[0], p)
                    } else {
                        s.clone()
                    }
                } else {
                    s.clone()
                }
            }
        }
    }).collect();
    
    // === INISIALISASI P2P NETWORK (Start early to bind port) ===
    let (_p2p_tx, mut p2p_rx) = match start_p2p(normalized_bootnodes, Arc::clone(&storage), enable_mdns, enable_nat).await {
        Ok((tx, rx)) => {
            println!("🌐 P2P gossip network started (libp2p running in background)");
            (tx, rx)
        }
        Err(e) => {
            eprintln!("❌ Failed to start P2P: {:?}", e);
            return;
        }
    };

    // === HANDSHAKE KE PEERS (legacy - optional now) ===
    if !initial_peers.is_empty() {
        println!("🔗 Connecting to {} initial peers (legacy TCP): {:?}", initial_peers.len(), initial_peers);
        for peer_port in &initial_peers {
            // FIXED: Now accepts peer_ip parameter (localhost for legacy peers)
            handshake(&node_id, "127.0.0.1", *peer_port, port, Arc::clone(&peers), Arc::clone(&storage));
            thread::sleep(Duration::from_millis(100));
        }
    } else {
        println!("📍 No initial legacy peers provided.");
    }

    // === INISIALISASI MODUL INTI ===
    // Pass node_addr_hex as genesis address
    // Fix path to point to phase1-core-prototype/vm_move/stdlib/bytecode
    let stdlib_path = if std::path::Path::new("phase1-core-prototype/vm_move/stdlib/bytecode").exists() {
        "phase1-core-prototype/vm_move/stdlib/bytecode"
    } else {
        "vm_move/stdlib/bytecode" // Fallback if running from phase1 dir
    };
    genesis::initialize_genesis(&storage, stdlib_path, &node_addr_hex);

    let executor = Arc::new(Executor::new(Arc::clone(&storage)));
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    
    let da_sequencer = Arc::new(Mutex::new(
        DASequencer::new(node_id.clone(), Arc::clone(&storage), Arc::clone(&peers)),
    ));

    let consensus = Arc::new(Mutex::new(DagConsensus::new(
        node_id.clone(),
        Arc::clone(&peers),
        Arc::clone(&mempool),
        Arc::clone(&executor),
        Arc::clone(&storage),
        Some(Arc::clone(&da_sequencer)), // Wired DA Sequencer!
    )));

    let chain_sync = Arc::new(ChainSync::new(
        node_id.clone(),
        port,
        Arc::clone(&peers),
        Arc::clone(&storage),
    ));

    // === INITIALIZE DA PUBLISHER (REAL) ===
    // We use the aincore-da crate.
    // In production, this URL should come from config/args.
    let _da_publisher = match aincore_da::DAPublisher::new("http://localhost:26658").await {
        Ok(p) => {
            println!("🌌 Connected to Celestia Node at http://localhost:26658");
            Some(Arc::new(p))
        },
        Err(e) => {
            println!("⚠️ Failed to connect to Celestia: {}. DA will be disabled.", e);
            None
        }
    };

    println!("⚙️ DagConsensus initialized (Narwhal-lite)");
    println!("🧩 DA Sequencer initialized.");

    // === DECOUPLE CONSENSUS TO BACKGROUND TASK ===
    // We use a channel to signal when consensus creates a new vertex/block
    // Ideally, consensus should push to a 'committed_blocks' channel.
    // For this prototype, we'll keep the lock-based access but run the ticker in a separate task.
    
    let consensus_clone = Arc::clone(&consensus);
    tokio::spawn(async move {
        loop {
            // Run consensus round every 100ms (faster than 5s)
            {
                if let Ok(mut c) = consensus_clone.lock() {
                    c.try_create_vertex();
                }
            }
            tokio::time::sleep(Duration::from_millis(3000)).await;
        }
    });

    // === Handle Incoming P2P Messages (Now that consensus is ready) ===
    {
        let node_consensus = Arc::clone(&consensus);
        let da_seq_clone = Arc::clone(&da_sequencer);
        
        tokio::spawn(async move {
            while let Some(msg) = p2p_rx.recv().await {
                // println!("📨 Main loop received P2P msg: {}", msg);
                if msg.starts_with("TX:") || msg.starts_with('{') {
                    if let Ok(guard) = node_consensus.lock() {
                        if let Ok(mut mp) = guard.mempool.lock() {
                            mp.add_transaction(msg);
                        }
                    }
                } else if msg.starts_with("DAG_VERTEX:") {
                    if let Ok(mut guard) = node_consensus.lock() {
                        guard.handle_message(&msg);
                    }
                } else if let Some(stripped) = msg.strip_prefix("DA_COMMIT:") {
                    if let Ok(guard) = da_seq_clone.lock() {
                        guard.handle_incoming_batch(stripped);
                    }
                }
            }
        });
    }

    // === START TCP SERVER (legacy transport) ===
    {
        let node_peers = Arc::clone(&peers);
        let node_storage = Arc::clone(&storage);
        let node_consensus = Arc::clone(&consensus);
        let da_seq_clone = Arc::clone(&da_sequencer);
        let node_chain_sync = Arc::clone(&chain_sync);
        let server_node_id = node_id.clone();

        tokio::spawn(async move {
            network::start_server(
                port,
                server_node_id,
                node_peers,
                Arc::clone(&node_storage),
                move |msg: String| {
                    println!("📨 [Server] Received msg: {:.50}...", msg);
                    if msg.starts_with("TX:") {
                        if let Ok(guard) = node_consensus.lock() {
                            if let Ok(mut mp) = guard.mempool.lock() {
                                mp.add_transaction(msg);
                            }
                        }
                    } else if msg.starts_with("DAG_VERTEX:") {
                        if let Ok(mut guard) = node_consensus.lock() {
                            guard.handle_message(&msg);
                        }
                    } else if let Some(stripped) = msg.strip_prefix("DA_COMMIT:") {
                        if let Ok(guard) = da_seq_clone.lock() {
                            guard.handle_incoming_batch(stripped);
                        }
                    } else if let Some(content) = msg.strip_prefix("SYNC_REQUEST:") {
                        if let Ok(req) = serde_json::from_str::<SyncRequest>(content) {
                            let resp = node_chain_sync.handle_sync_request(req.clone());
                            if let Ok(resp_str) = serde_json::to_string(&resp) {
                                let reply_msg = format!("SYNC_RESPONSE:{}", resp_str);
                                let target_addr = format!("127.0.0.1:{}", req.sender_port);
                                let _ = network::send_message(&target_addr, &reply_msg);
                            }
                        }
                    } else if let Some(content) = msg.strip_prefix("SYNC_RESPONSE:") {
                        match serde_json::from_str::<SyncResponse>(content) {
                            Ok(resp) => node_chain_sync.handle_sync_response(resp),
                            Err(e) => eprintln!("❌ [Server] Failed to parse SYNC_RESPONSE: {}", e),
                        }
                    }
                },
            ).await;
        });
    }

    // === INITIALIZE GOVERNANCE ===
    let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(&storage))));
    
     // === START REST API SERVER ===
    {
        let api_consensus = Arc::clone(&consensus);
        let api_peers = Arc::clone(&peers);
        let api_mempool = Arc::clone(&mempool);
        let api_storage = Arc::clone(&storage);
        let api_governance = Arc::clone(&governance);
        
        std::thread::spawn(move || {
            println!("🌍 [Reference] Initializing API Thread for port {}...", api_port);
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build() 
            {
                Ok(rt) => {
                    println!("🌍 [Reference] Runtime built. Blocking on API...");
                    rt.block_on(async {
                        println!("🌍 [Reference] Calling start_api_server...");
                        if let Err(e) = api::start_api_server(api_port, api_consensus, api_peers, api_mempool, api_storage, api_governance).await {
                            eprintln!("❌ API Server CRASHED: {}", e);
                        } else {
                            println!("🌍 API Server exited normally (Unexpected).");
                        }
                    });
                },
                Err(e) => eprintln!("❌ Failed to build endpoint runtime: {}", e),
            }
        });
    }

    // === MAIN LOOP (EXECUTION & DA ONLY) ===
    // Consensus is now running in background!
    
    // Trigger initial sync
    println!("🔄 Starting initial chain sync...");
    chain_sync.sync_from_peers();

    println!("\n🎬 Main Execution Loop started (Consensus running in background)...\n");
    println!("👤 Node Identity: {}", node_addr_hex);

    loop {
        // === PARALLEL EXECUTION & DA INTEGRATION ===
        // Execution is now handled by DagConsensus::add_vertex upon commit.
        // DA Batch creation is triggered automatically by Consensus.

        // Update Metrics
        let peer_count = if let Ok(p) = peers.lock() { p.len() } else { 0 };
        node::metrics::PEER_COUNT.set(peer_count as i64);
        
        if let Ok(Some(height_str)) = storage.get("latest_height") {
            if let Ok(h) = height_str.parse::<i64>() {
                node::metrics::BLOCK_HEIGHT.set(h);
            }
        }
        
        // Increment transaction count
        /*
        if !txs_to_execute.is_empty() {
             node::metrics::TRANSACTION_COUNT.inc_by(txs_to_execute.len() as f64);
        }
        */

        // println!("✅ Node {} ticked. Peers: {}", port, peer_count);
        thread::sleep(Duration::from_millis(1000)); // Lower tick rate for efficiency
    }
}

