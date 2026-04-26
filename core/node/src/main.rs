// === --- IMPORT FASE 1 --- ===
use storage::StateDB;
// use network::{start_server, handshake}; // start_server unused
use network::handshake;
// use std::env;
use std::sync::{Arc, Mutex, RwLock};
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
    let config = config::NodeConfig::parse();
    
    // Unpack config for backward compatibility
    let port = config.port;
    let api_port = config.api_port;
    let datadir = config.datadir;
    let initial_peers = config.initial_peers;
    let mut bootnodes = config.bootnodes;
    let enable_mdns = config.enable_mdns;
    let enable_nat = config.enable_nat;


    // === INISIALISASI NODE IDENTITY ===
    use ed25519_dalek::{SigningKey};
    
    // Load or Generate Keypair
    let _ = std::fs::create_dir_all(&datadir);
    let datadir_path = std::path::PathBuf::from(&datadir);
    // Load or generate node key with error handling
    let key_path_buf = datadir_path.join("node.key");
    let key_path = match key_path_buf.to_str() {
        Some(p) => p,
        None => {
            eprintln!("❌ FATAL: Invalid key path (non-UTF8)");
            std::process::exit(1);
        }
    };
    
    let signing_key = if std::path::Path::new(key_path).exists() {
        match std::fs::read(key_path) {
            Ok(bytes) => {
                match bytes.as_slice().try_into() {
                    Ok(key_bytes) => SigningKey::from_bytes(key_bytes),
                    Err(_) => {
                        eprintln!("❌ FATAL: Invalid key length in {}", key_path);
                        eprintln!("   Expected 32 bytes, got {}", bytes.len());
                        eprintln!("   Try deleting the key file to regenerate.");
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("❌ FATAL: Failed to read node key from {}: {}", key_path, e);
                std::process::exit(1);
            }
        }
    } else {
        // Auto-generate key for testnet (key persists via Docker volume)
        println!("⚠️  node.key not found in {} — generating new keypair...", datadir);
        let mut csprng = rand::rngs::OsRng;
        let new_key = SigningKey::generate(&mut csprng);
        match std::fs::write(key_path, new_key.to_bytes()) {
            Ok(_) => {
                println!("✅ Generated new node key: {}", key_path);
                println!("🔑 Public Key: {}", hex::encode(new_key.verifying_key().to_bytes()));
            }
            Err(e) => {
                eprintln!("❌ FATAL: Failed to save generated key: {}", e);
                std::process::exit(1);
            }
        }
        new_key
    };

    let verifying_key = signing_key.verifying_key();
    let pub_key_hex = hex::encode(verifying_key.to_bytes());
    // Use first 16 bytes (32 hex chars) as address for Move compatibility
    let node_addr_hex = pub_key_hex[0..32].to_string();
    let node_id = node_addr_hex.clone(); // Use address as node_id for consensus matching

    let db_path = format!("{}/validator_{}.db", datadir, port);
    // Open Database with error handling
    let storage = match StateDB::open(&db_path) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("❌ FATAL: Failed to open database at '{}'", db_path);
            eprintln!("   Error: {}", e);
            eprintln!("   ");
            eprintln!("   Possible solutions:");
            eprintln!("   1. Ensure no other AINCORE node is running");
            eprintln!("   2. Check file permissions on the data directory");
            eprintln!("   3. Try removing the database: rm -rf {}", db_path);
            std::process::exit(1);
        }
    };
    let peers = Arc::new(Mutex::new(std::collections::HashMap::<String, u16>::new()));

    println!("🚀 AINCORE node {} running on port {}", node_id, port);
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

    if bootnodes.is_empty() {
        println!("🌐 No bootnodes provided. Using default AINCORE public seed node...");
        bootnodes.push("/dns4/seed.aincore.network/tcp/9000".to_string());
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
    
    // === LIBP2P BOOTNODES (Port + 100) ===
    let libp2p_bootnodes: Vec<String> = normalized_bootnodes.iter().map(|s| {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() >= 5 && parts[3] == "tcp" {
            if let Ok(p) = parts[4].parse::<u16>() {
                let new_port = p + 100;
                let mut new_parts = parts.clone();
                let port_str = new_port.to_string();
                new_parts[4] = &port_str;
                return new_parts.join("/");
            }
        }
        s.clone()
    }).collect();

    println!("🕸️  Kademlia DHT: Feeding {} bootnodes to Routing Table", libp2p_bootnodes.len());
    if !libp2p_bootnodes.is_empty() {
         println!("   - Example Libp2p: {}", libp2p_bootnodes[0]);
         if let Some(first_legacy) = normalized_bootnodes.first() {
             println!("   - Example Legacy: {}", first_legacy);
         }
    }
    
    // === INISIALISASI P2P NETWORK (Start early to bind port) ===
    let (_p2p_tx, mut p2p_rx) = match start_p2p(port, libp2p_bootnodes, Arc::clone(&storage), enable_mdns, enable_nat).await {
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
    let node_signing_key = Arc::new(signing_key.clone());
    
    // CRITICAL FIX: Parse bootnodes to extract IP and port for legacy TCP handshake
    if !normalized_bootnodes.is_empty() {
        println!("🔗 Attempting legacy TCP handshake with {} bootnodes", normalized_bootnodes.len());
        for bootnode in &normalized_bootnodes {
            // Parse bootnode address: /ip4/192.168.18.90/tcp/9000 or /dns4/example.com/tcp/9000
            let parts: Vec<&str> = bootnode.split('/').collect();
            if parts.len() >= 5 {
                let ip_or_dns = parts[2]; // "192.168.18.90" or "example.com"
                if let Ok(port) = parts[4].parse::<u16>() {
                    println!("🔗 Trying legacy TCP handshake to {}:{}", ip_or_dns, port);
                    handshake(&node_id, ip_or_dns, port, port, Arc::clone(&peers), Arc::clone(&storage), Arc::clone(&node_signing_key));
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }
    
    if !initial_peers.is_empty() {
        println!("🔗 Connecting to {} initial peers (legacy TCP): {:?}", initial_peers.len(), initial_peers);
        for peer_port in &initial_peers {
            // FIXED: Now accepts peer_ip parameter (localhost for legacy peers)
            handshake(&node_id, "127.0.0.1", *peer_port, port, Arc::clone(&peers), Arc::clone(&storage), Arc::clone(&node_signing_key));
            thread::sleep(Duration::from_millis(100));
        }
    } else if normalized_bootnodes.is_empty() {
        println!("📍 No initial legacy peers provided.");
    }

    // === INISIALISASI MODUL INTI ===
    // Pass node_addr_hex as genesis address
    // Fix path to point to phase1-core-prototype/vm_move/stdlib/bytecode
    let stdlib_path = if std::path::Path::new("core/vm_move/stdlib/bytecode").exists() {
        "core/vm_move/stdlib/bytecode"
    } else if std::path::Path::new("vm_move/stdlib/bytecode").exists() {
        "vm_move/stdlib/bytecode"
    } else if std::path::Path::new("/root/.aincore/vm_move/stdlib/bytecode").exists() {
        "/root/.aincore/vm_move/stdlib/bytecode" // Docker container path
    } else {
        "core/vm_move/stdlib/bytecode" // Default, will error with clear message if missing
    };
    // Initialize Genesis with error handling
    if let Err(e) = genesis::initialize_genesis(&storage, stdlib_path, &node_addr_hex) {
        eprintln!("❌ FATAL: Genesis initialization failed: {}", e);
        eprintln!("   This usually means:");
        eprintln!("   1. Stdlib bytecode is missing or corrupted");
        eprintln!("   2. Database write permissions issue");
        eprintln!("   3. Invalid genesis configuration");
        std::process::exit(1);
    }

    let executor = Arc::new(Executor::new(Arc::clone(&storage)));
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    
    let da_sequencer = Arc::new(Mutex::new(
        DASequencer::new(node_id.clone(), Arc::clone(&storage), Arc::clone(&peers)),
    ));

    // CRITICAL: Use RwLock for DAG Consensus
    let p2p_tx_clone = Some(_p2p_tx.clone()); // Pass the libp2p transmitter
    
    let consensus = Arc::new(RwLock::new(DagConsensus::new(
        node_id.clone(),
        Arc::clone(&peers),
        Arc::clone(&mempool),
        Arc::clone(&executor),
        Arc::clone(&storage),
        Some(Arc::clone(&da_sequencer)), // Wired DA Sequencer!
        p2p_tx_clone, // Add Libp2p gossip channel
    )));

    let chain_sync = Arc::new(ChainSync::new(
        node_id.clone(),
        port,
        Arc::clone(&peers),
        Arc::clone(&storage),
    ));

    // === DA PLAYER (SOVEREIGN ONLY) ===
    // Celestia integration removed per user request for Sovereign DA (privacy).
    // The internal DASequencer (initialized above) handles all DA duties via Erasure Coding + P2P.
    println!("🛡️ Running in SOVEREIGN DA mode (No external DA dependency)");

    println!("⚙️ DagConsensus initialized (Narwhal-lite) [RwLock Enabled]");
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
                // WRITE LOCK FOR MINING
                if let Ok(mut c) = consensus_clone.write() {
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
                    // READ LOCK usually sufficient if mempool is internally mutexed, 
                    // BUT Mempool is stored as Arc<Mutex> inside DagConsensus struct in Main?
                    // Actually DagConsensus struct definition: pub mempool: Arc<Mutex<Mempool>>
                    // So we only need READ access to DagConsensus to get the Mempool Arc.
                    if let Ok(guard) = node_consensus.read() {
                        if let Ok(mut mp) = guard.mempool.lock() {
                            mp.add_transaction(msg);
                        }
                    }
                } else if msg.starts_with("DAG_VERTEX:") {
                    // WRITE LOCK required to update DAG
                    if let Ok(mut guard) = node_consensus.write() {
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
        let handler_storage = Arc::clone(&storage);
        let node_signing_key_server = Arc::clone(&node_signing_key);

        tokio::spawn(async move {
            network::start_server(
                port,
                server_node_id,
                node_peers,
                Arc::clone(&node_storage),
                node_signing_key_server,
                move |msg: String| {
                    let storage_clone = Arc::clone(&handler_storage);
                    println!("📨 [Server] Received msg: {:.50}...", msg);
                    if msg.starts_with("TX:") {
                        if let Ok(guard) = node_consensus.read() {
                            if let Ok(mut mp) = guard.mempool.lock() {
                                mp.add_transaction(msg);
                            }
                        }
                    } else if msg.starts_with("DAG_VERTEX:") {
                        if let Ok(mut guard) = node_consensus.write() {
                            guard.handle_message(&msg);
                        }
                    } else if let Some(stripped) = msg.strip_prefix("DA_COMMIT:") {
                        if let Ok(guard) = da_seq_clone.lock() {
                            guard.handle_incoming_batch(stripped);
                        }
                    } else if let Some(content) = msg.strip_prefix("SYNC_REQUEST:") {
                        // println!("🔍 [DEBUG] SYNC_REQUEST handler triggered!");
                        if let Ok(req) = serde_json::from_str::<SyncRequest>(content) {
                            // println!("🔍 [DEBUG] Parsed SYNC_REQUEST from {}", req.sender_id);
                            let resp = node_chain_sync.handle_sync_request(req.clone());
                            // println!("🔍 [DEBUG] Got {} blocks from handle_sync_request", resp.blocks.len());
                            
                            let resp_json = serde_json::to_string(&resp).unwrap_or_default();
                            let response_msg = format!("SYNC_RESPONSE:{}", resp_json);
                            
                            let requester_ip = storage_clone.get_peer_ip(&req.sender_id).unwrap_or_else(|| "127.0.0.1".to_string());
                            let requester_addr = format!("{}:{}", requester_ip, req.sender_port);
                            
                            if let Err(e) = network::send_message(&requester_addr, &response_msg) {
                                eprintln!("❌ Failed to send sync response error: {}", e);
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

    // === PERSISTENT P2P MAINTENANCE (AUTO-RECONNECT) ===
    {
        let peers_clone_reconnect = Arc::clone(&peers);
        let storage_clone_reconnect = Arc::clone(&storage);
        let node_id_reconnect = node_id.clone();
        let bootnodes_clone = bootnodes.clone();
        let my_port = port;
        let signing_key_reconnect = Arc::clone(&node_signing_key);

        tokio::spawn(async move {
            println!("🛡️ P2P Maintenance Service started (Auto-Reconnect every 15s)");
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                
                // 1. Reconnect to Bootnodes
                for bootnode_str in &bootnodes_clone {
                     let parts: Vec<&str> = bootnode_str.split('/').collect();
                     if parts.len() >= 5 {
                         let ip = parts[2];
                         let port_str = parts[4];
                         if let Ok(p) = port_str.parse::<u16>() {
                             if p != my_port {
                                 network::handshake(
                                     &node_id_reconnect,
                                     ip,
                                     p,
                                     my_port,
                                     Arc::clone(&peers_clone_reconnect),
                                     Arc::clone(&storage_clone_reconnect),
                                     Arc::clone(&signing_key_reconnect)
                                 );
                             }
                         }
                     }
                }
                
                // 2. Reconnect to Saved Peers (from Storage)
                // FIXED: Use scan_peers() which stores valid (peer_id, port) pairs,
                // NOT scan_peer_addrs() which stores libp2p multiaddrs with ephemeral ports
                let saved_peers = storage_clone_reconnect.scan_peers();
                for (peer_id, peer_port) in saved_peers {
                    if peer_port != 0 && peer_port != my_port {
                        let ip = storage_clone_reconnect.get_peer_ip(&peer_id)
                            .unwrap_or_else(|| "127.0.0.1".to_string());
                        network::handshake(
                             &node_id_reconnect,
                             &ip,
                             peer_port,
                             my_port,
                             Arc::clone(&peers_clone_reconnect),
                             Arc::clone(&storage_clone_reconnect),
                             Arc::clone(&signing_key_reconnect)
                         );
                    }
                }
            }
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
    
    // === INITIAL SYNC + AUTO-REGISTRATION ===
    println!("🔄 Starting initial chain sync...");
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Spawn initial sync as task — then register as validator if needed
    let chain_sync_initial = Arc::clone(&chain_sync);
    let consensus_post_sync = Arc::clone(&consensus);
    let storage_post_sync = Arc::clone(&storage);
    let node_id_post_sync = node_id.clone();
    tokio::spawn(async move {
        let synced_height = chain_sync_initial.sync_from_peers().await;
        
        // Reload consensus chain tip to prevent fork
        if synced_height > 0 {
            if let Ok(mut c) = consensus_post_sync.write() {
                c.reload_chain_tip();
            }
        }
        
        // Auto-register as validator if not already in the set
        let already_validator = {
            if let Ok(Some(json)) = storage_post_sync.get("sys:validators") {
                if let Ok(vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                    vals.iter().any(|(addr, _)| addr == &node_id_post_sync)
                } else { false }
            } else { false }
        };
        
        if !already_validator {
            // DISABLED: AutoReg was creating phantom validators that broke BFT quorum.
            // Validators must be defined in genesis.json or added via governance/staking.
            println!("⚠️  [AutoReg] Node {} is NOT in validator set. Use genesis.json or staking to register.", node_id_post_sync);
            println!("   Current node will run in Observer mode until registered.");
        } else {
            println!("✅ [AutoReg] Already a validator in the set");
        }
    });
    
    // === PERIODIC BACKGROUND SYNC ===
    let chain_sync_periodic = Arc::clone(&chain_sync);
    let consensus_periodic = Arc::clone(&consensus);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let synced_height = chain_sync_periodic.sync_from_peers().await;
            // Reload consensus chain tip after every sync
            if synced_height > 0 {
                if let Ok(mut c) = consensus_periodic.write() {
                    c.reload_chain_tip();
                }
            }
        }
    });

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
        
        thread::sleep(Duration::from_millis(1000)); // Lower tick rate for efficiency
    }
}
