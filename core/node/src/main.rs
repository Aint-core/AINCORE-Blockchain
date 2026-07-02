// === --- IMPORT FASE 1 --- ===
use storage::StateDB;
// use network::{start_server, handshake}; // start_server unused
use network::handshake;
// use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::{thread, time::Duration};

// === --- IMPORT FASE 2 --- ===
use consensus::DagConsensus;
use executor::Executor;
use mempool::Mempool;

// === --- IMPORT FASE 3 (Chain Sync) --- ===
use chain_sync::ChainSync;

// === --- IMPORT FASE 4 (DA Sequencer) --- ===
use da_sequencer::DASequencer;

// === --- IMPORT FASE 5 (P2P Network) --- ===
// === --- IMPORT FASE 5 (P2P Network) --- ===
use node::genesis;
use node::p2p::start_p2p;
// use node::api; // Bypass library issue
mod api_local;
use api_local as api;

fn is_docker_bridge_host(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>()
        .map(|ip| {
            let octets = ip.octets();
            octets[0] == 172 && (16..=31).contains(&octets[1])
        })
        .unwrap_or(false)
}

fn bootnode_host(addr: &str) -> Option<&str> {
    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() >= 5 && (parts[1] == "ip4" || parts[1] == "dns4") {
        Some(parts[2])
    } else {
        None
    }
}

/// Automated state-sync bootstrap (public-testnet onboarding).
///
/// A fresh node cannot replay from genesis — the seed prunes old blocks. If the
/// datadir is EMPTY and `AINCORE_BOOTSTRAP_SNAPSHOT` is set (a local path or an
/// http(s) URL to a `validator_*.db` tarball), load that snapshot so the node
/// starts near the current height and ChainSyncs only the small delta.
///
/// Safety: acts ONLY when `db_path` does not yet exist — it never touches or
/// overwrites an existing chain DB. Returns true if a snapshot was installed
/// (the caller then sanitises per-identity keys via the storage API).
fn maybe_extract_bootstrap_snapshot(datadir: &str, db_path: &str, port: u16) -> bool {
    if std::path::Path::new(db_path).exists() {
        return false; // existing data — never overwrite
    }
    let snap = match std::env::var("AINCORE_BOOTSTRAP_SNAPSHOT") {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => return false,
    };
    println!("📦 [bootstrap] fresh datadir + AINCORE_BOOTSTRAP_SNAPSHOT set → bootstrapping from {snap}");

    let local = if snap.starts_with("https://") {
        // Audit #6: https-only, NO redirects (blocks SSRF via redirect to
        // internal/metadata endpoints) and no protocol downgrade.
        let dest = format!("{datadir}/.bootstrap-snapshot.tar.gz");
        let ok = matches!(
            std::process::Command::new("curl")
                .args([
                    "-fsS", "--proto", "=https", "--max-redirs", "0", "--retry", "2", "-o", &dest,
                    &snap,
                ])
                .status(),
            Ok(s) if s.success()
        );
        if !ok {
            eprintln!("⚠️ [bootstrap] snapshot download failed — starting fresh");
            return false;
        }
        // Optional integrity check against AINCORE_BOOTSTRAP_SHA256 (supply-chain).
        if let Ok(expected) = std::env::var("AINCORE_BOOTSTRAP_SHA256") {
            let expected = expected.trim().to_lowercase();
            if !expected.is_empty() {
                let got = std::process::Command::new("sha256sum")
                    .arg(&dest)
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .and_then(|s| s.split_whitespace().next().map(|x| x.to_lowercase()));
                if got.as_deref() != Some(expected.as_str()) {
                    eprintln!(
                        "🚨 [bootstrap] snapshot SHA256 mismatch (expected {expected}, got {got:?}) — refusing"
                    );
                    let _ = std::fs::remove_file(&dest);
                    return false;
                }
                println!("🔒 [bootstrap] snapshot SHA256 verified");
            }
        }
        dest
    } else if snap.starts_with("http://") {
        eprintln!("🚨 [bootstrap] refusing insecure http:// snapshot URL (use https://) — starting fresh");
        return false;
    } else {
        snap.clone() // local filesystem path
    };

    // Audit #10: extract into a staging subdir so we move ONLY the snapshot's DB,
    // never a pre-existing sibling validator_*.db already in the datadir.
    let staging = format!("{datadir}/.bootstrap-staging");
    let _ = std::fs::remove_dir_all(&staging);
    if std::fs::create_dir_all(&staging).is_err() {
        eprintln!("⚠️ [bootstrap] could not create staging dir — starting fresh");
        return false;
    }
    let extracted = matches!(
        std::process::Command::new("tar").args(["xzf", &local, "-C", &staging]).status(),
        Ok(s) if s.success()
    );
    if !extracted {
        eprintln!("⚠️ [bootstrap] snapshot extract failed — starting fresh");
        let _ = std::fs::remove_dir_all(&staging);
        return false;
    }

    // Move the single validator_*.db from staging to THIS node's port.
    let want = format!("validator_{port}.db");
    let mut moved = false;
    if let Ok(entries) = std::fs::read_dir(&staging) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("validator_") && name.ends_with(".db") {
                let to = std::path::Path::new(datadir).join(&want);
                if std::fs::rename(e.path(), &to).is_ok() {
                    println!("📦 [bootstrap] loaded snapshot state → {}", to.display());
                    moved = true;
                }
                break;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&staging);
    if !moved {
        eprintln!("⚠️ [bootstrap] no validator_*.db inside snapshot — starting fresh");
    }
    moved
}

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
    use ed25519_dalek::SigningKey;

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
                let key_bytes = if bytes.len() == 32 {
                    bytes
                } else if let Ok(text) = std::str::from_utf8(&bytes) {
                    let trimmed = text.trim();
                    if trimmed.len() == 64 {
                        match hex::decode(trimmed) {
                            Ok(decoded) => decoded,
                            Err(e) => {
                                eprintln!("❌ FATAL: Invalid hex node key in {}", key_path);
                                eprintln!("   Error: {}", e);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        bytes
                    }
                } else {
                    bytes
                };

                match key_bytes.as_slice().try_into() {
                    Ok(key_bytes) => SigningKey::from_bytes(key_bytes),
                    Err(_) => {
                        eprintln!("❌ FATAL: Invalid key length in {}", key_path);
                        eprintln!(
                            "   Expected raw 32 bytes or 64 hex chars, got {} bytes",
                            key_bytes.len()
                        );
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
        println!(
            "⚠️  node.key not found in {} — generating new keypair...",
            datadir
        );
        let mut csprng = rand::rngs::OsRng;
        let new_key = SigningKey::generate(&mut csprng);
        match std::fs::write(key_path, new_key.to_bytes()) {
            Ok(_) => {
                // node.key is the root secret: it re-derives the Ed25519 consensus
                // identity, the validator BLS finality seed, and the DA at-rest key.
                // Restrict to owner-only (0600) so it is never world-readable.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        key_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                println!("✅ Generated new node key: {}", key_path);
                println!(
                    "🔑 Public Key: {}",
                    hex::encode(new_key.verifying_key().to_bytes())
                );
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
    let node_addr_hex = match crypto::derive_address(verifying_key.as_bytes()) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("❌ FATAL: Failed to derive node address: {}", e);
            std::process::exit(1);
        }
    };
    let node_id = node_addr_hex.clone(); // Use address as node_id for consensus matching

    let db_path = format!("{}/validator_{}.db", datadir, port);

    // Automated state-sync bootstrap: on a fresh datadir, optionally load a
    // published snapshot so a new public-testnet node starts near the tip
    // instead of stalling at height 0 (the seed prunes old blocks). No-op if the
    // DB already exists.
    let bootstrapped_from_snapshot = maybe_extract_bootstrap_snapshot(&datadir, &db_path, port);

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

    // Sanitise a freshly-bootstrapped snapshot: it carries the SEED's per-identity
    // DA signing key (which this node cannot decrypt → boot panic) and the seed's
    // peer table (dead peers this node would hammer). Drop both so this node
    // generates its own DA key and discovers peers via its own bootnode. This is
    // why joiners need no ldb / manual key surgery.
    if bootstrapped_from_snapshot {
        let _ = storage.delete("sys:da:signing_key_enc_v1");
        let _ = storage.delete("sys:da:signing_key");
        let inherited = storage.scan_peers();
        for (peer_id, _) in &inherited {
            let _ = storage.remove_peer(peer_id);
        }
        println!(
            "🧼 [bootstrap] sanitised snapshot: DA key reset (regenerates) + cleared {} inherited peer(s)",
            inherited.len()
        );
    }

    // === H-07 MIGRATION: one-shot tx_index backfill ===
    //
    // Before the H-07 fix, `save_block_json` did not write `tx_index:`
    // entries. Any block that landed before this build is invisible to
    // `aincore_getTransaction`, which would silently return `null` for
    // historical receipts. The backfill walks existing `block_*` rows
    // and populates the index for them. It is idempotent (sentinel-
    // gated) so subsequent restarts are no-ops.
    //
    // Failure here is non-fatal: we log and continue, because the
    // index is a query convenience, not a consensus invariant. New
    // blocks are still indexed correctly by `save_block_json`.
    match storage.backfill_tx_index() {
        Ok(0) => {
            // Either already done in a previous boot, or no blocks yet.
        }
        Ok(n) => {
            println!(
                "🛠️  tx_index migration: backfilled {} historical transactions",
                n
            );
        }
        Err(e) => {
            eprintln!(
                "⚠️  tx_index backfill failed (non-fatal, getTransaction may \
                 return null for old txs until rerun): {}",
                e
            );
        }
    }

    let peers = Arc::new(Mutex::new(std::collections::HashMap::<String, u16>::new()));

    println!("🚀 AINCORE node {} running on port {}", node_id, port);
    println!("🌐 Listening on TCP port {}", port);

    // === LOAD PERSISTED PEERS ===
    let saved_peer_addrs = storage.scan_peer_addrs();
    if !saved_peer_addrs.is_empty() {
        println!(
            "📚 Found {} saved peer addresses in database",
            saved_peer_addrs.len()
        );
        for (_, addr) in saved_peer_addrs {
            if bootnode_host(&addr).is_some_and(is_docker_bridge_host) {
                println!("🧹 Skipping stale Docker bridge peer address: {}", addr);
                continue;
            }
            if !bootnodes.contains(&addr) {
                bootnodes.push(addr);
            }
        }
    }

    if bootnodes.is_empty() {
        match std::env::var("AINCORE_PUBLIC_SEED_BOOTNODE") {
            Ok(seed) if !seed.trim().is_empty() => {
                println!(
                    "🌐 Using explicit public seed bootnode from AINCORE_PUBLIC_SEED_BOOTNODE"
                );
                bootnodes.push(seed);
            }
            _ => {
                println!("🌐 No bootnodes provided. Starting isolated/sovereign node with no public seed.");
            }
        }
    }

    // === NORMALIZE BOOTNODES ===
    let normalized_bootnodes: Vec<String> = bootnodes
        .iter()
        .map(|s| {
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
        })
        .collect();

    // === LIBP2P BOOTNODES (Port + 100) ===
    let libp2p_bootnodes: Vec<String> = normalized_bootnodes
        .iter()
        .map(|s| {
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
        })
        .collect();

    println!(
        "🕸️  Kademlia DHT: Feeding {} bootnodes to Routing Table",
        libp2p_bootnodes.len()
    );
    if !libp2p_bootnodes.is_empty() {
        println!("   - Example Libp2p: {}", libp2p_bootnodes[0]);
        if let Some(first_legacy) = normalized_bootnodes.first() {
            println!("   - Example Legacy: {}", first_legacy);
        }
    }

    // === INISIALISASI P2P NETWORK (Start early to bind port) ===
    let (_p2p_tx, mut p2p_rx) = match start_p2p(
        port,
        libp2p_bootnodes,
        Arc::clone(&storage),
        enable_mdns,
        enable_nat,
    )
    .await
    {
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
        println!(
            "🔗 Attempting legacy TCP handshake with {} bootnodes",
            normalized_bootnodes.len()
        );
        for bootnode in &normalized_bootnodes {
            // Parse bootnode address: /ip4/192.168.18.90/tcp/9000 or /dns4/example.com/tcp/9000
            let parts: Vec<&str> = bootnode.split('/').collect();
            if parts.len() >= 5 {
                let ip_or_dns = parts[2]; // "192.168.18.90" or "example.com"
                if let Ok(port) = parts[4].parse::<u16>() {
                    println!("🔗 Trying legacy TCP handshake to {}:{}", ip_or_dns, port);
                    handshake(
                        &node_id,
                        ip_or_dns,
                        port,
                        port,
                        Arc::clone(&peers),
                        Arc::clone(&storage),
                        Arc::clone(&node_signing_key),
                    );
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }
    }

    if !initial_peers.is_empty() {
        println!(
            "🔗 Connecting to {} initial peers (legacy TCP): {:?}",
            initial_peers.len(),
            initial_peers
        );
        for peer_port in &initial_peers {
            // FIXED: Now accepts peer_ip parameter (localhost for legacy peers)
            handshake(
                &node_id,
                "127.0.0.1",
                *peer_port,
                port,
                Arc::clone(&peers),
                Arc::clone(&storage),
                Arc::clone(&node_signing_key),
            );
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
    // Pass the node identity (Ed25519 seed bytes) so the validator BLS key +
    // PoP can be derived deterministically for the local/single-node fallback.
    let genesis_node_identity = signing_key.to_bytes();
    if let Err(e) = genesis::initialize_genesis(
        &storage,
        stdlib_path,
        &node_addr_hex,
        &pub_key_hex,
        &genesis_node_identity,
    ) {
        eprintln!("❌ FATAL: Genesis initialization failed: {}", e);
        eprintln!("   This usually means:");
        eprintln!("   1. Stdlib bytecode is missing or corrupted");
        eprintln!("   2. Database write permissions issue");
        eprintln!("   3. Invalid genesis configuration");
        std::process::exit(1);
    }

    let executor = Arc::new(Executor::new(Arc::clone(&storage)));
    // Phase 2.1 (H-01): use with_storage so PQC (Dilithium5) submissions
    // are verified at the mempool gate against the canonical
    // pqc_pubkey_{sender} binding, instead of being silently accepted
    // (pre-Phase-1) or fail-closed (Phase 1 mitigation).
    let mempool = Arc::new(Mutex::new(Mempool::with_storage(Arc::clone(&storage))));

    // Phase 2.9 (M-09): pass the node's persistent Ed25519 key bytes
    // so the DA signing key is encrypted at rest with a key derived
    // from the node identity. Reading the RocksDB directory is no
    // longer sufficient to extract the DA signing key — an attacker
    // also needs `node.key`.
    let node_identity_bytes = signing_key.to_bytes();
    let da_sequencer = Arc::new(Mutex::new(DASequencer::new_encrypted(
        node_id.clone(),
        Arc::clone(&storage),
        Arc::clone(&peers),
        &node_identity_bytes,
    )));

    // CRITICAL: Use RwLock for DAG Consensus
    let p2p_tx_clone = Some(_p2p_tx.clone()); // Pass the libp2p transmitter

    let consensus = Arc::new(RwLock::new(DagConsensus::new(
        node_id.clone(),
        Arc::clone(&peers),
        Arc::clone(&mempool),
        Arc::clone(&executor),
        Arc::clone(&storage),
        Some(Arc::clone(&da_sequencer)), // Wired DA Sequencer!
        p2p_tx_clone,                    // Add Libp2p gossip channel
        signing_key.to_bytes(), // H4 FIX: Pass the persistent Ed25519 key for BLS derivation
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

    let consensus_tick_ms = std::env::var("AINCORE_CONSENSUS_TICK_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 100)
        .unwrap_or(3_000);
    println!("⏱️ Consensus ticker interval: {}ms", consensus_tick_ms);

    // #10 Graceful shutdown: a shared flag flipped on SIGTERM/SIGINT. Background
    // loops check it and stop creating new work so the final flush is not racing
    // an in-flight commit.
    let shutdown = Arc::new(AtomicBool::new(false));

    // Signal listener: docker stop sends SIGTERM (then SIGKILL after the grace
    // period); Ctrl-C sends SIGINT. Either flips the shutdown flag.
    {
        let shutdown_signal = Arc::clone(&shutdown);
        tokio::spawn(async move {
            let mut sigterm =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("⚠️ Failed to install SIGTERM handler: {e}");
                        return;
                    }
                };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\n🛑 SIGINT received — initiating graceful shutdown...");
                }
                _ = sigterm.recv() => {
                    println!("\n🛑 SIGTERM received — initiating graceful shutdown...");
                }
            }
            shutdown_signal.store(true, Ordering::SeqCst);
        });
    }

    let consensus_clone = Arc::clone(&consensus);
    let shutdown_consensus = Arc::clone(&shutdown);
    tokio::spawn(async move {
        loop {
            // Stop mining the moment shutdown is requested so we never start a
            // new vertex/commit while the main loop is draining + flushing.
            if shutdown_consensus.load(Ordering::SeqCst) {
                break;
            }
            // Run one consensus attempt per configured ticker interval.
            {
                // WRITE LOCK FOR MINING
                if let Ok(mut c) = consensus_clone.write() {
                    c.try_create_vertex();
                }
            }
            tokio::time::sleep(Duration::from_millis(consensus_tick_ms)).await;
        }
    });

    // === Handle Incoming P2P Messages (Now that consensus is ready) ===
    {
        let node_consensus = Arc::clone(&consensus);
        let da_seq_clone = Arc::clone(&da_sequencer);
        let shutdown_p2p_rx = Arc::clone(&shutdown);

        tokio::spawn(async move {
            while let Some(msg) = p2p_rx.recv().await {
                if shutdown_p2p_rx.load(Ordering::SeqCst) {
                    break;
                }
                // println!("📨 Main loop received P2P msg: {}", msg);
                if msg.starts_with("TX:") || msg.starts_with('{') {
                    // READ LOCK usually sufficient if mempool is internally mutexed,
                    // BUT Mempool is stored as Arc<Mutex> inside DagConsensus struct in Main?
                    // Actually DagConsensus struct definition: pub mempool: Arc<Mutex<Mempool>>
                    // So we only need READ access to DagConsensus to get the Mempool Arc.
                    if let Ok(guard) = node_consensus.read() {
                        if let Ok(mut mp) = guard.mempool.lock() {
                            let tx_msg = msg.strip_prefix("TX:").unwrap_or(&msg).to_string();
                            if let Err(reason) = mp.add_transaction(tx_msg) {
                                println!("❌ [P2P] Rejected transaction: {}", reason);
                            }
                        }
                    }
                } else if msg.starts_with("DAG_VERTEX:")
                    || msg.starts_with("DOWNTIME_ATTEST:")
                    || msg.starts_with("EQUIV_PROOF:")
                    || msg.starts_with("QC_VOTE:")
                {
                    // WRITE LOCK required to update DAG / store remote attestation /
                    // slash equivocator / collect+aggregate QC finality votes
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
        let node_signing_key_server = Arc::clone(&node_signing_key);

        tokio::spawn(async move {
            network::start_server(
                port,
                server_node_id,
                node_peers,
                Arc::clone(&node_storage),
                node_signing_key_server,
                move |msg: String| -> Option<String> {
                    println!("📨 [Server] Received msg: {:.50}...", msg);
                    if msg.starts_with("TX:") {
                        if let Ok(guard) = node_consensus.read() {
                            if let Ok(mut mp) = guard.mempool.lock() {
                                let tx_msg = msg.strip_prefix("TX:").unwrap_or(&msg).to_string();
                                if let Err(reason) = mp.add_transaction(tx_msg) {
                                    println!("❌ [P2P] Rejected transaction: {}", reason);
                                }
                            }
                        }
                        None
                    } else if msg.starts_with("DAG_VERTEX:")
                        || msg.starts_with("DOWNTIME_ATTEST:")
                        || msg.starts_with("EQUIV_PROOF:")
                        || msg.starts_with("QC_VOTE:")
                    {
                        if let Ok(mut guard) = node_consensus.write() {
                            guard.handle_message(&msg);
                        }
                        None
                    } else if let Some(stripped) = msg.strip_prefix("DA_COMMIT:") {
                        if let Ok(guard) = da_seq_clone.lock() {
                            guard.handle_incoming_batch(stripped);
                        }
                        None
                    } else if msg.starts_with("DA_SHARD:") {
                        // TASK #3 Stage-2 SERVE: route shard requests to the DA
                        // sequencer. handle_p2p_message builds the ShardResponse
                        // (DA_SHARD:{json}) which start_server writes back over the
                        // same encrypted socket. Side-effect-only: serving shards
                        // touches no consensus state, so it is determinism-safe.
                        if let Ok(guard) = da_seq_clone.lock() {
                            guard.handle_p2p_message(&msg)
                        } else {
                            None
                        }
                    } else if msg == "GET_HEIGHT"
                        || msg == "GET_FINALITY"
                        || msg.starts_with("SYNC_REQ:")
                    {
                        // Single serving implementation: chain_sync owns GET_HEIGHT,
                        // GET_FINALITY (with the quorum certificate) and SYNC_REQ (blocks +
                        // finality QC + prune_horizon). The returned response is sent back
                        // over the same encrypted socket by network::start_server. Keeping
                        // this here — instead of reimplementing it inline in the transport —
                        // is what stops serving-side fixes from silently landing on dead code.
                        node_chain_sync.handle_message(&msg)
                    } else {
                        None
                    }
                },
            )
            .await;
        });
    }

    // === PERSISTENT P2P MAINTENANCE (AUTO-RECONNECT) ===
    {
        let peers_clone_reconnect = Arc::clone(&peers);
        let storage_clone_reconnect = Arc::clone(&storage);
        let node_id_reconnect = node_id.clone();
        // Use the NORMALIZED bootnodes (`/ip4/<ip>/tcp/<port>`): the reconnect loop
        // parses each entry with `split('/')` expecting a multiaddr (parts>=5). The raw
        // `bootnodes` list is `<ip>:<port>` → split('/') yields 1 part → every bootnode is
        // silently skipped → the auto-reconnect NEVER re-handshakes. On a real multi-machine
        // cluster the boot-time handshakes race (peer TCP servers not up yet) and fail, and
        // with the reconnect dead the peer mesh never recovers → no quorum → no finality.
        // (Localhost hides this: boot handshakes succeed instantly.)
        let bootnodes_clone = normalized_bootnodes.clone();
        let my_port = port;
        let signing_key_reconnect = Arc::clone(&node_signing_key);
        let shutdown_reconnect = Arc::clone(&shutdown);

        tokio::spawn(async move {
            println!("🛡️ P2P Maintenance Service started (Auto-Reconnect every 15s)");
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
                if shutdown_reconnect.load(Ordering::SeqCst) {
                    break;
                }

                // 1. Reconnect to Bootnodes
                for bootnode_str in &bootnodes_clone {
                    if shutdown_reconnect.load(Ordering::SeqCst) {
                        break;
                    }
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
                                    Arc::clone(&signing_key_reconnect),
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
                    if shutdown_reconnect.load(Ordering::SeqCst) {
                        break;
                    }
                    if peer_port == 0 || peer_port == my_port {
                        continue;
                    }
                    let ip = storage_clone_reconnect
                        .get_peer_ip(&peer_id)
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    // Peer hygiene: a saved peer whose IP is an ephemeral
                    // Docker-bridge address (172.16–31.x — e.g. the 172.23.0.1
                    // gateway left behind by a stopped sibling container / old
                    // lineage) is never a reachable node. Prune it instead of
                    // re-handshaking it every 15s (which spams timeout noise).
                    // Consistent with the boot-time skip already applied to
                    // peer_addr entries.
                    if is_docker_bridge_host(&ip) {
                        match storage_clone_reconnect.remove_peer(&peer_id) {
                            Ok(()) => {
                                println!(
                                    "🧹 Pruned stale Docker-bridge peer {} ({}:{})",
                                    peer_id, ip, peer_port
                                );
                                if let Ok(mut p) = peers_clone_reconnect.lock() {
                                    p.remove(&peer_id);
                                }
                            }
                            Err(e) => {
                                eprintln!("⚠️ Failed to prune stale peer {}: {}", peer_id, e)
                            }
                        }
                        continue;
                    }
                    network::handshake(
                        &node_id_reconnect,
                        &ip,
                        peer_port,
                        my_port,
                        Arc::clone(&peers_clone_reconnect),
                        Arc::clone(&storage_clone_reconnect),
                        Arc::clone(&signing_key_reconnect),
                    );
                }
            }
        });
    }

    // === INITIALIZE GOVERNANCE ===
    let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(
        &storage,
    ))));

    // === START REST API SERVER ===
    {
        let api_consensus = Arc::clone(&consensus);
        let api_peers = Arc::clone(&peers);
        let api_mempool = Arc::clone(&mempool);
        let api_storage = Arc::clone(&storage);
        let api_governance = Arc::clone(&governance);

        std::thread::spawn(move || {
            println!(
                "🌍 [Reference] Initializing API Thread for port {}...",
                api_port
            );
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    println!("🌍 [Reference] Runtime built. Blocking on API...");
                    rt.block_on(async {
                        println!("🌍 [Reference] Calling start_api_server...");
                        if let Err(e) = api::start_api_server(
                            api_port,
                            api_consensus,
                            api_peers,
                            api_mempool,
                            api_storage,
                            api_governance,
                        )
                        .await
                        {
                            eprintln!("❌ API Server CRASHED: {}", e);
                        } else {
                            println!("🌍 API Server exited normally (Unexpected).");
                        }
                    });
                }
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
    let shutdown_initial_sync = Arc::clone(&shutdown);
    tokio::spawn(async move {
        if shutdown_initial_sync.load(Ordering::SeqCst) {
            return;
        }
        let synced_height = chain_sync_initial.sync_from_peers().await;
        if shutdown_initial_sync.load(Ordering::SeqCst) {
            return;
        }

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
                } else {
                    false
                }
            } else {
                false
            }
        };

        if !already_validator {
            // SECURITY: AutoReg disabled to prevent Sybil attacks.
            // Testnet: Add node address to genesis.json validators array.
            // Mainnet: Use staking transaction to register with locked stake.
            println!("⚠️  [AutoReg] Node {} is NOT in validator set. Use genesis.json or staking to register.", node_id_post_sync);
            println!("   Current node will run in Observer mode until registered.");
        } else {
            println!("✅ [AutoReg] Already a validator in the set");
        }
    });

    // === PERIODIC BACKGROUND SYNC ===
    // Pull-sync cadence. Observers pull committed blocks + the finality QC on this
    // interval, so in steady state they trail the validator's tip by roughly
    // (interval / block_time) blocks. Default 3s ≈ the block time, keeping observers
    // within ~1 block of the tip (near-realtime) instead of the old fixed 30s lag.
    // Tunable via AINCORE_SYNC_INTERVAL_MS (floored at 500ms to bound RPC load).
    let sync_interval_ms = std::env::var("AINCORE_SYNC_INTERVAL_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 500)
        .unwrap_or(3_000);
    println!("⏱️ Periodic pull-sync interval: {}ms", sync_interval_ms);
    let chain_sync_periodic = Arc::clone(&chain_sync);
    let consensus_periodic = Arc::clone(&consensus);
    let shutdown_periodic_sync = Arc::clone(&shutdown);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(sync_interval_ms)).await;
            if shutdown_periodic_sync.load(Ordering::SeqCst) {
                break;
            }
            let synced_height = chain_sync_periodic.sync_from_peers().await;
            if shutdown_periodic_sync.load(Ordering::SeqCst) {
                break;
            }
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
        // #10 Graceful shutdown: on SIGTERM/SIGINT, drain any in-flight commit
        // and flush the DB before exiting, so a rolling deploy never relies on
        // crash recovery.
        if shutdown.load(Ordering::SeqCst) {
            println!("🧹 Graceful shutdown: draining in-flight consensus work...");
            // Acquiring the consensus write lock blocks until the current
            // try_create_vertex/commit (if any) has finished — the ticker has
            // already stopped starting new ones via the same flag.
            {
                let _drain = consensus.write();
            }
            match storage.flush() {
                Ok(()) => println!("💾 Graceful shutdown: storage flushed to disk."),
                Err(e) => eprintln!("⚠️ Graceful shutdown: storage flush failed: {e}"),
            }
            println!("👋 Node exited cleanly.");
            break;
        }

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

        thread::sleep(Duration::from_millis(250)); // Poll shutdown ~4x/sec; metrics tick
    }
}
