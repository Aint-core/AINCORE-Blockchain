// === --- IMPORT FASE 1 --- ===
use storage::StateDB;
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

// === --- IMPORT FASE 5 (P2P Network) --- ===
// === --- IMPORT FASE 5 (P2P Network) --- ===
use node::genesis;
use node::p2p::start_p2p;
mod api_local;
use api_local as api;

/// G3 RC-2 and RC-3, at boot after RC-1.
/// - RC-2: every flat consensus-state key equals its tree leaf, and the
///   reverse. This catches an out-of-band edit of the database.
/// - RC-3: when the node holds a QC for a height the tree still has, the tree
///   root there is the QC's `state_root`. This catches a self-consistent but
///   foreign database, such as a restored backup or a copied datadir.
fn state_boot_audit(storage: &std::sync::Arc<StateDB>) -> Result<(), String> {
    let divergent = state_commit::audit_flat_vs_tree(storage)
        .map_err(|e| format!("state audit (RC-2) failed: {e}"))?;
    if !divergent.is_empty() {
        let shown: Vec<_> = divergent.iter().take(20).collect();
        return Err(format!(
            "{} consensus-state keys disagree with the state tree (RC-2), first: {:?}",
            divergent.len(),
            shown
        ));
    }
    let qc_height = storage
        .get("consensus:qc:latest_height")
        .ok()
        .flatten()
        .and_then(|h| h.parse::<u64>().ok());
    let Some(height) = qc_height else {
        return Ok(());
    };
    let floor = state_commit::floor(storage).map_err(|e| e.to_string())?;
    let latest = state_commit::latest_version(storage)
        .map_err(|e| e.to_string())?
        .unwrap_or(0);
    if height < floor || height > latest {
        return Ok(());
    }
    let Some(qc_json) = storage
        .get(&format!("consensus:qc:{height}"))
        .ok()
        .flatten()
    else {
        return Ok(());
    };
    let qc: consensus::qc::QuorumCertificate = serde_json::from_str(&qc_json)
        .map_err(|e| format!("stored QC at {height} is unreadable: {e}"))?;
    // The QC comes from this same database, so its root is evidence only once
    // it verifies: a quorum of the committee this node records for its epoch
    // signed it, under this chain id. That committee record is itself local;
    // binding it to the network is TA (S5), until then this is the limit.
    match node::qc_rpc::verify(storage, &qc, Some(height)) {
        Ok(()) => {}
        Err(node::qc_rpc::VerificationError::Unavailable(why)) => {
            eprintln!(
                "⚠️ G3 RC-3 skipped at boot: the stored QC at {height} cannot be verified ({why})"
            );
            return Ok(());
        }
        Err(e) => {
            return Err(format!(
                "the stored QC at {height} does not verify (RC-3): {e}"
            ))
        }
    }
    state_commit::audit_root_against_qc(storage, height, &qc.state_root)
        .map_err(|e| format!("this database is not the network's (RC-3): {e}"))
}

/// G3 SN-5: `AINCORE_BOOTSTRAP_SNAPSHOT` installed a downloaded database
/// without verifying its state. It is removed, and a node that still sets it
/// refuses to start rather than silently ignoring it.
fn refuse_removed_snapshot_install(env: Option<String>) -> Result<(), String> {
    match env {
        Some(v) if !v.trim().is_empty() => Err(
            "AINCORE_BOOTSTRAP_SNAPSHOT was removed (G3 SN-5): it installed unverified state. \
             Unset it and sync from genesis; verified snapshot restore is G3 S6."
                .to_string(),
        ),
        _ => Ok(()),
    }
}

/// G4 S6: `--peers` dialled the legacy TCP channel, which is gone.
fn refuse_removed_legacy_peers(initial_peers: &[u16]) -> Result<(), String> {
    if initial_peers.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "--peers {initial_peers:?} dialled the legacy TCP channel, removed in G4 S6: \
             give the peers as --bootnodes"
        ))
    }
}

/// G3 S6: where and from whom to restore state before booting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StateSyncSettings {
    checkpoint: chain_sync::state_sync::Checkpoint,
    /// The peers' libp2p addresses (G4 S6: `host:port` is their base port,
    /// as bootnodes are; a multiaddr may pin a key).
    peers: Vec<String>,
    /// Replace an older chain this datadir holds.
    replace_existing: bool,
}

/// A restore takes its trust from the checkpoint and from the network's
/// genesis identity, which the operator pins alongside it (TA-1).
const GENESIS_PIN: &str = "AINCORE_EXPECTED_GENESIS_HASH";

impl StateSyncSettings {
    /// `AINCORE_STATE_SYNC_CHECKPOINT=height:block_hash:state_root`,
    /// `AINCORE_STATE_SYNC_PEERS=host:port,...` (or multiaddrs) and, to
    /// replace an older chain,
    /// `AINCORE_STATE_SYNC_REPLACE=1`. `None` without a checkpoint.
    fn parse(
        checkpoint: Option<String>,
        peers: Option<String>,
        replace: Option<String>,
        genesis_pin: Option<String>,
    ) -> Result<Option<Self>, String> {
        let Some(checkpoint) = checkpoint.filter(|c| !c.trim().is_empty()) else {
            return Ok(None);
        };
        let checkpoint = checkpoint.parse()?;
        if genesis_pin.filter(|p| !p.trim().is_empty()).is_none() {
            return Err(format!(
                "a state restore needs {GENESIS_PIN}: the checkpoint pins the state, the genesis \
                 hash pins which chain it belongs to"
            ));
        }
        let peers = peers
            .filter(|p| !p.trim().is_empty())
            .ok_or("AINCORE_STATE_SYNC_PEERS is required with a checkpoint")?;
        let peers = peers
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(|p| {
                node::sessions::sync_peer_multiaddr(p)
                    .map_err(|e| format!("state sync peer {p:?}: {e}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let replace_existing = match replace.as_deref().map(str::trim) {
            None | Some("") | Some("0") => false,
            Some("1") => true,
            Some(other) => return Err(format!("AINCORE_STATE_SYNC_REPLACE={other}: use 1 or 0")),
        };
        Ok(Some(Self {
            checkpoint,
            peers,
            replace_existing,
        }))
    }

    fn from_env() -> Result<Option<Self>, String> {
        Self::parse(
            std::env::var("AINCORE_STATE_SYNC_CHECKPOINT").ok(),
            std::env::var("AINCORE_STATE_SYNC_PEERS").ok(),
            std::env::var("AINCORE_STATE_SYNC_REPLACE").ok(),
            std::env::var(GENESIS_PIN).ok(),
        )
    }
}

/// G3 S6 (SN-1, SN-2): restore this node's state at an operator-pinned
/// checkpoint from peers, before genesis handling; genesis then reopens the
/// restored datadir. The checkpoint is the trust anchor, so it must come from
/// a source the operator trusts (TA-0, TA-4).
///
/// Nothing is restored on a datadir already restored from this checkpoint,
/// or one past it on the checkpoint's own chain, so the settings may stay
/// set. A datadir past it on another chain (its block at the checkpoint
/// height differs) is refused unless `AINCORE_STATE_SYNC_REPLACE=1`.
async fn restore_from_checkpoint(
    storage: &Arc<StateDB>,
    settings: &StateSyncSettings,
    genesis: impl FnOnce() -> Result<genesis::GenesisState, String>,
    sessions: &network::SessionClient,
    local_signer: &str,
) -> Result<Option<chain_sync::state_sync::Restored>, String> {
    let cp = &settings.checkpoint;
    let read = |key: &str| storage.try_get(key).map_err(|e| e.to_string());
    if read(storage::RESTORE_MARKER)?.is_none() {
        let height = read("latest_height")?
            .map(|raw| raw.parse::<u64>())
            .transpose()
            .map_err(|e| format!("invalid local height: {e}"))?;
        let restored_here =
            read(chain_sync::state_sync::RESTORED_CHECKPOINT)? == Some(cp.to_string());
        if restored_here || height.is_some_and(|h| h >= cp.height) {
            match cp.matches_retained(storage)? {
                Some(true) => {
                    println!(
                        "ℹ️ [STATE_SYNC] local history matches checkpoint {cp}; not restoring"
                    );
                    return Ok(None);
                }
                Some(false) if !settings.replace_existing => {
                    return Err(format!(
                        "local block or QC disagrees with checkpoint {cp}: another chain or a different state root. Set AINCORE_STATE_SYNC_REPLACE=1 to replace it"
                    ));
                }
                None if !settings.replace_existing => {
                    return Err(format!(
                        "this datadir holds neither the block nor the QC at {}, so whether it is on the checkpoint's chain cannot be told. Set AINCORE_STATE_SYNC_REPLACE=1 to replace it, or unset the checkpoint",
                        cp.height
                    ));
                }
                _ => {}
            }
        }
    }
    let genesis = genesis()?;
    let plan = chain_sync::state_sync::RestorePlan {
        checkpoint: cp,
        genesis: &genesis.writes,
        genesis_identity: &genesis.identity,
        replace_existing: settings.replace_existing,
        local_signer: Some(local_signer),
        patience: chain_sync::state_sync::Patience::default(),
    };
    println!(
        "🔄 [STATE_SYNC] restoring height {} from {} peer(s)",
        settings.checkpoint.height,
        settings.peers.len()
    );
    let restored =
        chain_sync::state_sync::restore_over_sessions(storage, &plan, sessions, &settings.peers)
            .await?;
    println!(
        "✅ [STATE_SYNC] restored height {} ({} leaves, {} restarts)",
        restored.height, restored.leaves, restored.restarts
    );
    Ok(Some(restored))
}

/// G3 SN-6 at every boot: a datadir restored with one key may not run as a
/// validator with another. A validator key moved onto a restored datadir can
/// sign a slot its old instance already signed, and the abstention that
/// prevents that (G1 RC-3) does not exist yet. The restoring key itself may
/// become a validator later: it had to be none when the restore ran.
fn check_restored_signer(storage: &StateDB, my_address: &str) -> Result<(), String> {
    let Some(restored_by) = storage
        .try_get(chain_sync::state_sync::RESTORED_BY)
        .map_err(|e| e.to_string())?
    else {
        return Ok(());
    };
    if restored_by != my_address && chain_sync::state_sync::recorded_validator(storage, my_address)?
    {
        return Err(format!(
            "this datadir was restored with key {restored_by}, and this node's key \
             {my_address} is a validator: a validator key moved onto a restored datadir can \
             sign a slot its old instance already signed (SN-6)"
        ));
    }
    Ok(())
}

/// G3 FX-6: the chain id comes only from `sys:chain_id`, which genesis
/// writes. The `AINCORE_CHAIN_ID` env may repeat it, for tools that still
/// read it, but it may not name another chain.
fn resolve_boot_chain_id(stored: Option<String>, env: Option<String>) -> Result<String, String> {
    let chain_id = stored
        .filter(|c| !c.trim().is_empty())
        .ok_or("sys:chain_id is missing: genesis did not complete")?;
    if let Some(env) = env.filter(|e| !e.trim().is_empty()) {
        if env.trim() != chain_id {
            return Err(format!(
                "AINCORE_CHAIN_ID={} but this chain is {}; the env is not a source, \
                 fix or remove it",
                env, chain_id
            ));
        }
    }
    Ok(chain_id)
}

/// G3 FX-6: the epoch interval comes only from the genesis pin
/// `sys:config:epoch_block_interval`. A database without the pin refuses to
/// start instead of falling back to the env, and an env that disagrees with
/// the pin is refused rather than silently ignored.
fn check_epoch_interval_pinned(stored: Option<String>, env: Option<String>) -> Result<u64, String> {
    let pinned = stored
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .ok_or("sys:config:epoch_block_interval is missing or invalid: genesis did not pin it")?;
    if let Some(env) = env.filter(|e| !e.trim().is_empty()) {
        if env.trim().parse::<u64>().ok() != Some(pinned) {
            return Err(format!(
                "AINCORE_EPOCH_BLOCK_INTERVAL={} but the chain pins {}; the env is not a \
                 source, fix or remove it",
                env, pinned
            ));
        }
    }
    Ok(pinned)
}

/// B384: every boot list entry the node cannot dial, with why: an empty
/// entry, or one `sessions::libp2p_bootnode` (the parser `boot_dial_list`
/// dials with) refuses. `boot_dial_list` dropped such an entry with one log
/// line, so a mistyped list booted the node isolated.
fn bad_bootnodes(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|given| {
            if given.trim().is_empty() {
                return Some("an empty entry".to_string());
            }
            node::sessions::libp2p_bootnode(given).err()
        })
        .collect()
}

/// B384: `--bootnodes` and `AINCORE_PUBLIC_SEED_BOOTNODE` (unset or blank:
/// none), checked at boot as strictly as every other flag (B331): every
/// entry the node cannot dial is named. A list of only bad entries was
/// also non-empty, so the public seed was skipped too.
fn check_bootnodes(bootnodes: &[String], public_seed: Option<String>) -> Result<(), String> {
    let mut problems: Vec<String> = bad_bootnodes(bootnodes)
        .into_iter()
        .map(|e| format!("--bootnodes: {e}"))
        .collect();
    if let Some(seed) = public_seed.filter(|s| !s.trim().is_empty()) {
        problems.extend(
            bad_bootnodes(&[seed])
                .into_iter()
                .map(|e| format!("AINCORE_PUBLIC_SEED_BOOTNODE: {e}")),
        );
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "bootnodes the node cannot dial: {}",
            problems.join("; ")
        ))
    }
}

/// B112: `path` (a secret) readable and writable by its owner only.
fn owner_only(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode != 0o600 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn load_or_create_node_key(path: &std::path::Path) -> std::io::Result<ed25519_dalek::SigningKey> {
    let read_key = || {
        owner_only(path)?;
        crypto::key_file::read_ed25519(path)
    };
    match read_key() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let candidate = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            match crypto::key_file::publish_new(path, &candidate.to_bytes()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            read_key()
        }
        result => result,
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // B77: a panic ends the process (systemd restarts it) instead of
    // poisoning a lock every loop then skips.
    node::abort_on_panic();
    // === ARGUMENT PARSER ===
    let config = config::NodeConfig::parse();
    // B349: and the environment, as strictly as the flags.
    if let Err(why) = node::env_check::check() {
        eprintln!("❌ {why}");
        std::process::exit(2);
    }
    // B384: and the boot list, with the parser it is dialled with.
    if let Err(why) = check_bootnodes(
        &config.bootnodes,
        std::env::var("AINCORE_PUBLIC_SEED_BOOTNODE").ok(),
    ) {
        eprintln!("❌ {why}");
        std::process::exit(2);
    }

    // Unpack config for backward compatibility
    let port = config.port;
    let api_port = config.api_port;
    let datadir = config.datadir;
    let initial_peers = config.initial_peers;
    let mut bootnodes = config.bootnodes;
    let enable_mdns = config.enable_mdns;
    let enable_nat = config.enable_nat;

    // === INISIALISASI NODE IDENTITY ===
    let datadir_path = std::path::PathBuf::from(&datadir);
    let key_path = datadir_path.join("node.key");
    let signing_key = match std::fs::create_dir_all(&datadir_path)
        .and_then(|_| load_or_create_node_key(&key_path))
    {
        Ok(key) => key,
        Err(e) => {
            eprintln!(
                "❌ FATAL: cannot load or initialize {}: {e}",
                key_path.display()
            );
            std::process::exit(1);
        }
    };

    let verifying_key = signing_key.verifying_key();
    let node_addr_hex = match crypto::derive_address(verifying_key.as_bytes()) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("❌ FATAL: Failed to derive node address: {}", e);
            std::process::exit(1);
        }
    };
    let node_id = node_addr_hex.clone(); // Use address as node_id for consensus matching

    let db_path = format!("{}/validator_{}.db", datadir, port);
    // B326: never an empty chain beside this node's own under another port.
    if let Some(other) = node::other_validator_db(&datadir_path, port) {
        eprintln!(
            "❌ FATAL: {datadir}/{other} is this node's database under another port, and port {port} has none: run with that --port"
        );
        std::process::exit(1);
    }

    // Automated state-sync bootstrap: on a fresh datadir, optionally load a
    // published snapshot so a new public-testnet node starts near the tip
    // instead of stalling at height 0 (the seed prunes old blocks). No-op if the
    // DB already exists.
    // G3 SN-5: the snapshot install extracted a downloaded database and
    // trusted it: no state root, no consensus signature, only an optional
    // tarball hash. It is gone. Verified snapshot restore is G3 S6. Until
    // then a node syncs from genesis. Refuse the old variable rather than
    // silently ignore it.
    if let Err(e) =
        refuse_removed_snapshot_install(std::env::var("AINCORE_BOOTSTRAP_SNAPSHOT").ok())
    {
        eprintln!("❌ FATAL: {}", e);
        std::process::exit(1);
    }

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

    println!("🚀 AINCORE node {} running on port {}", node_id, port);

    // === LOAD PERSISTED PEERS ===
    // B22: libp2p addresses saved from earlier sessions; dialled as they are.
    // B43: the newest few; older rows are deleted.
    let saved_peer_addrs: Vec<String> =
        storage.keep_newest_peer_addrs(node::sessions::MAX_SAVED_PEERS);
    if !saved_peer_addrs.is_empty() {
        println!(
            "📚 Found {} saved peer addresses in database",
            saved_peer_addrs.len()
        );
    }

    if bootnodes.is_empty() && saved_peer_addrs.is_empty() {
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

    // === LIBP2P DIAL LIST (B22) ===
    // The operator's bootnodes are base ports (dialled at base + 100); the
    // saved addresses are libp2p addresses already, kept when routable.
    let libp2p_bootnodes = node::sessions::boot_dial_list(&bootnodes, &saved_peer_addrs);

    println!(
        "🕸️  Kademlia DHT: Feeding {} bootnodes to Routing Table",
        libp2p_bootnodes.len()
    );
    if !libp2p_bootnodes.is_empty() {
        println!("   - Example Libp2p: {}", libp2p_bootnodes[0]);
        if let Some(first) = bootnodes.first() {
            println!(
                "   - Given as: {} (base port; libp2p dials base + 100)",
                first
            );
        }
    }

    // === INISIALISASI P2P NETWORK (Start early to bind port) ===
    let state_sync_settings = match StateSyncSettings::from_env() {
        Ok(settings) => settings,
        Err(e) => {
            eprintln!("[STATE_SYNC] invalid boot settings: {e}; refusing to boot");
            return std::process::ExitCode::FAILURE;
        }
    };
    // The empty book permits sync bootstrap, not consensus. Normal boots
    // publish the validated engine's committee before sessions may open.
    let session_book = Arc::new(RwLock::new(node::sessions::PeerBook::default()));
    // Sync asks over the sessions through `session_client`; the requests
    // sessions send arrive on `sync_serves`.
    let (mut session_wiring, session_client, mut sync_serves) =
        node::sessions::SessionWiring::new(Arc::clone(&session_book));
    let network_ready = if state_sync_settings.is_none() {
        let (ready, wait) = tokio::sync::oneshot::channel();
        session_wiring.startup_ready = Some(wait);
        Some(ready)
    } else {
        // Restoring a checkpoint needs sync sessions before the local state
        // and its committee exist. Member-only admission remains closed.
        None
    };
    let (_p2p_tx, mut p2p_rx) = match start_p2p(
        port,
        libp2p_bootnodes,
        Arc::clone(&storage),
        enable_mdns,
        enable_nat,
        signing_key.to_bytes(),
        session_wiring,
    )
    .await
    {
        Ok((tx, rx)) => {
            println!("🌐 P2P gossip network started (libp2p running in background)");
            (tx, rx)
        }
        Err(e) => {
            eprintln!("❌ Failed to start P2P: {:?}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    // G4 S6: the legacy TCP channel is gone. `--peers` dialled it; libp2p
    // sessions come from `--bootnodes` (and identify, Kademlia, mDNS).
    if let Err(e) = refuse_removed_legacy_peers(&initial_peers) {
        eprintln!("❌ FATAL: {e}");
        std::process::exit(1);
    }

    // === INISIALISASI MODUL INTI ===
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
    // G3 S6: restore from a checkpoint first, when one is configured.
    match state_sync_settings {
        None => {
            // B35: no checkpoint, no pinned height.
            let _ = storage.delete(storage::CHECKPOINT_PIN);
        }
        Some(settings) => {
            // B35: pruning keeps the checkpoint's block and QC, which the
            // check below reads at every boot.
            if let Err(e) = storage.put(
                storage::CHECKPOINT_PIN,
                &settings.checkpoint.height.to_string(),
            ) {
                eprintln!("❌ [STATE_SYNC] the checkpoint pin was not written: {e}");
                std::process::exit(1);
            }
            let local_genesis =
                || genesis::build_local_genesis(stdlib_path).map_err(|e| e.to_string());
            let restore = restore_from_checkpoint(
                &storage,
                &settings,
                local_genesis,
                &session_client,
                &node_id,
            );
            tokio::pin!(restore);
            // G4 S6: the restore runs over sessions while the network task
            // keeps going. What it hands the node meanwhile is dropped (no
            // consensus yet, the state is being rebuilt), and every sync
            // request is refused.
            let restored = loop {
                tokio::select! {
                    result = &mut restore => break result,
                    Some(_) = p2p_rx.recv() => {}
                    Some(request) = sync_serves.recv() => {
                        let _ = request.reply.send(None);
                    }
                }
            };
            if let Err(e) = restored {
                eprintln!("❌ FATAL: state restore failed: {e}; refusing to boot");
                std::process::exit(1);
            }
        }
    }
    // G3 FX-7: genesis depends on genesis.json and the stdlib only, never on
    // this node's key, so every node builds the same state and identity.
    if let Err(e) = genesis::initialize_genesis(&storage, stdlib_path) {
        eprintln!("❌ FATAL: Genesis initialization failed: {}", e);
        eprintln!("   This usually means:");
        eprintln!("   1. Stdlib bytecode is missing or corrupted");
        eprintln!("   2. Database write permissions issue");
        eprintln!("   3. Invalid genesis configuration");
        std::process::exit(1);
    }

    // VERTEX HASH V2 domain: chain_id + genesis identity, installed once,
    // BEFORE any vertex is created or verified. Both are identical on every
    // node of this chain (chain_id from config, identity from genesis state).
    {
        // G3 FX-6: `sys:chain_id`, written by genesis, is the only source of
        // the chain id. Every validity rule reads it through
        // `blockchain::chain_id()`, installed here with the domain. The env
        // is checked, never used: a node whose env names another chain would
        // otherwise admit transactions the rest of the cluster refuses.
        let chain_id = match resolve_boot_chain_id(
            storage.get("sys:chain_id").ok().flatten(),
            std::env::var("AINCORE_CHAIN_ID").ok(),
        ) {
            Ok(chain_id) => chain_id,
            Err(e) => {
                eprintln!("❌ FATAL: {}; refusing to boot", e);
                std::process::exit(1);
            }
        };
        if let Err(e) = check_epoch_interval_pinned(
            storage
                .get("sys:config:epoch_block_interval")
                .ok()
                .flatten(),
            std::env::var("AINCORE_EPOCH_BLOCK_INTERVAL").ok(),
        ) {
            eprintln!("❌ FATAL: {}; refusing to boot", e);
            std::process::exit(1);
        }
        let genesis_identity = storage
            .get("genesis_identity")
            .ok()
            .flatten()
            .unwrap_or_default();
        if genesis_identity.is_empty() {
            eprintln!("❌ FATAL: genesis_identity missing after genesis init; refusing to boot");
            std::process::exit(1);
        }
        blockchain::set_vertex_domain(&chain_id, &genesis_identity);
        println!("🔏 Vertex hash domain installed: chain={} genesis={}", chain_id, &genesis_identity[..16]);
    }

    // G3 RC-1: the state tree, the executed height and the chain height are
    // written together by every block. If they disagree, this database is not
    // one this node produced; refuse to start rather than guess.
    if let Err(e) = state_commit::boot_check(&storage) {
        eprintln!("❌ FATAL: state tree boot check failed: {e}; refusing to boot");
        std::process::exit(1);
    }
    if let Err(e) = state_boot_audit(&storage) {
        eprintln!("❌ FATAL: {e}; refusing to boot");
        std::process::exit(1);
    }
    if let Err(e) = check_restored_signer(&storage, &node_id) {
        eprintln!("❌ FATAL: {e}; refusing to boot");
        std::process::exit(1);
    }

    let executor = Arc::new(Executor::new(Arc::clone(&storage)));
    // with_storage: the admission gate checks the gas payer's committed balance.
    let mempool = Arc::new(Mutex::new(Mempool::with_storage(Arc::clone(&storage))));

    // CRITICAL: Use RwLock for DAG Consensus
    let p2p_tx_clone = Some(_p2p_tx.clone()); // Pass the libp2p transmitter

    let consensus = DagConsensus::new(
        node_id.clone(),
        Arc::clone(&mempool),
        Arc::clone(&executor),
        Arc::clone(&storage),
        p2p_tx_clone,           // Add Libp2p gossip channel
        signing_key.to_bytes(), // H4 FIX: Pass the persistent Ed25519 key for BLS derivation
    );
    if let Some((epoch, current, next)) = consensus.session_committees() {
        let mut committees = vec![current.as_slice()];
        if let Some(next) = &next {
            committees.push(next.as_slice());
        }
        match session_book.write() {
            Ok(mut book) => {
                *book = node::sessions::PeerBook::new(epoch, &committees);
                println!("[P2P] boot committee ready for epoch {epoch}: {} members", book.len());
            }
            Err(e) => {
                eprintln!("[P2P] cannot publish boot committee: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }
    if let Some(ready) = network_ready {
        if ready.send(()).is_err() {
            eprintln!("[P2P] network task ended before boot completed");
            return std::process::ExitCode::FAILURE;
        }
    }
    let consensus = Arc::new(RwLock::new(consensus));

    let chain_sync = Arc::new(
        ChainSync::new(Arc::clone(&storage))
            // G4 S1: block sync over the libp2p sessions, not a connection of
            // its own.
            .with_sessions(session_client.clone()),
    );

    // G4 S6: the RPC counts the sessions the network task holds.
    let session_table = Arc::clone(&session_client.table);

    // G4 S1: answer the sync requests sessions send, off the network task,
    // at most SYNC_SERVE_CONCURRENCY at once (the rest are refused).
    // B21: whether this node is in the current committee (set by the
    // consensus ticker). Members serve forwarded transactions; the rest
    // forward theirs.
    let in_committee = Arc::new(AtomicBool::new(false));
    {
        // B34: serving slots. Members keep their own (free identities used
        // to take all eight); forwarded transactions have theirs (B31).
        // Counts are choices.
        const MEMBER_SERVES: usize = 4;
        const OPEN_SERVES: usize = 4;
        const TX_SUBMIT_SERVES: usize = 2;
        // B114: the operator's reserved peers (its RPC nodes) forward on
        // slots of their own; B187: and sync on slots of their own (they
        // shared the open ones with every stranger).
        const RESERVED_TX_SUBMIT_SERVES: usize = 2;
        const RESERVED_SERVES: usize = 2;
        let serve_sync = Arc::clone(&chain_sync);
        let serve_mempool = Arc::clone(&mempool);
        let serve_member = Arc::clone(&in_committee);
        let member_permits = Arc::new(tokio::sync::Semaphore::new(MEMBER_SERVES));
        let open_permits = Arc::new(tokio::sync::Semaphore::new(OPEN_SERVES));
        let tx_permits = Arc::new(tokio::sync::Semaphore::new(TX_SUBMIT_SERVES));
        let reserved_tx_permits = Arc::new(tokio::sync::Semaphore::new(RESERVED_TX_SUBMIT_SERVES));
        let reserved_permits = Arc::new(tokio::sync::Semaphore::new(RESERVED_SERVES));
        tokio::spawn(async move {
            while let Some(request) = sync_serves.recv().await {
                // B88: members keep to their own slots (taking the open ones
                // too, one member could hold all eight with 8 MiB answers and
                // starve every observer).
                let pool = node::sessions::serve_pool(
                    request.wire.starts_with(node::forward::TX_SUBMIT),
                    request.member.is_some(),
                    request.reserved,
                );
                let permit = match pool {
                    node::sessions::ServePool::ReservedTxSubmit => {
                        Arc::clone(&reserved_tx_permits).try_acquire_owned()
                    }
                    node::sessions::ServePool::TxSubmit => {
                        Arc::clone(&tx_permits).try_acquire_owned()
                    }
                    node::sessions::ServePool::Member => {
                        Arc::clone(&member_permits).try_acquire_owned()
                    }
                    node::sessions::ServePool::Reserved => {
                        Arc::clone(&reserved_permits).try_acquire_owned()
                    }
                    node::sessions::ServePool::Open => {
                        Arc::clone(&open_permits).try_acquire_owned()
                    }
                };
                let Ok(permit) = permit else {
                    // A snapshot part waits a busy answer out; anything
                    // else is refused.
                    let _ = request.reply.send(node::forward::busy_reply(&request.wire));
                    continue;
                };
                let serve_sync = Arc::clone(&serve_sync);
                let serve_mempool = Arc::clone(&serve_mempool);
                let member = serve_member.load(Ordering::SeqCst);
                tokio::task::spawn_blocking(move || {
                    let answer = if request.wire.starts_with(node::forward::TX_SUBMIT) {
                        member
                            .then(|| node::forward::serve_tx_submit(&serve_mempool, &request.wire))
                            .flatten()
                    } else {
                        // B131/B178: who the request is charged to, and
                        // whether it may take the kept snapshot slot.
                        let (client, kept) = node::sessions::snapshot_client(
                            &request.peer,
                            request.member.is_some(),
                            request.reserved,
                            request.group.as_deref(),
                        );
                        serve_sync.serve_session_from(&request.wire, &client, kept)
                    };
                    let _ = request.reply.send(answer);
                    drop(permit);
                });
            }
        });
    }

    // Data availability (B1): each block header carries a DA root over the
    // block body; nodes serve samples against it (aincore_sampleDA). There
    // is no separate DA service, key or message.

    println!("⚙️ DagConsensus initialized (Narwhal-lite) [RwLock Enabled]");

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

    // B21: outside the committee, forward what this node's RPC accepted to
    // a member (members put their own mempool into vertices).
    tokio::spawn(node::forward::run_forwarder(
        Arc::clone(&mempool),
        session_client.clone(),
        Arc::clone(&session_book),
        Arc::clone(&in_committee),
        Arc::clone(&shutdown),
    ));

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
    let ticker_book = Arc::clone(&session_book);
    let ticker_member = Arc::clone(&in_committee);
    let ticker_node_id = node_id.clone();
    tokio::spawn(async move {
        // (epoch, whether C_{E+1} is known) of the book's last refresh.
        let mut book_key: Option<(u64, bool)> = None;
        loop {
            // Stop mining the moment shutdown is requested so we never start a
            // new vertex/commit while the main loop is draining + flushing.
            if shutdown_consensus.load(Ordering::SeqCst) {
                break;
            }
            // Run one consensus attempt per configured ticker interval.
            // B77: off the async workers (the lock is a std one and a block
            // holds it for seconds): the swarm task keeps running.
            tokio::task::block_in_place(|| {
                // WRITE LOCK FOR MINING
                if let Ok(mut c) = consensus_clone.write() {
                    c.try_create_vertex();
                    // G4 S1: the sessions admit C_E and C_{E+1}.
                    if let Some((epoch, current, next)) = c.session_committees() {
                        // B405: a member that abstains (RC-3) proposes
                        // nothing: it forwards like a node outside.
                        ticker_member.store(
                            current.iter().any(|m| m.address == ticker_node_id) && c.v4_signs(),
                            Ordering::SeqCst,
                        );
                        let key = (epoch, next.is_some());
                        if book_key != Some(key) {
                            let mut committees: Vec<&[blockchain::committee::ValidatorInfo]> =
                                vec![&current];
                            if let Some(next) = &next {
                                committees.push(next);
                            }
                            if let Ok(mut book) = ticker_book.write() {
                                *book = node::sessions::PeerBook::new(epoch, &committees);
                                println!(
                                    "🔐 Committee sessions for epoch {epoch}: {} members",
                                    book.len()
                                );
                            }
                            book_key = Some(key);
                        }
                    }
                }
            });
            tokio::time::sleep(Duration::from_millis(consensus_tick_ms)).await;
        }
    });

    // === Handle Incoming P2P Messages (Now that consensus is ready) ===
    {
        let node_consensus = Arc::clone(&consensus);
        let shutdown_p2p_rx = Arc::clone(&shutdown);

        tokio::spawn(async move {
            while let Some((source, msg)) = p2p_rx.recv().await {
                if shutdown_p2p_rx.load(Ordering::SeqCst) {
                    break;
                }
                // Only consensus messages reach here (members' pushes and the
                // boundary QCs this node asked for; transactions travel by
                // forwarding, B21, and gossip is gone, B48).
                if msg.starts_with(consensus::v4::WIRE_PREFIX)
                    || msg.starts_with("QC_VOTE:")
                    || msg.starts_with(consensus::dag::QC_WANT_PREFIX)
                    || msg.starts_with(consensus::dag::QC_CERT_PREFIX)
                {
                    // WRITE LOCK required to update the DAG and collect or
                    // aggregate QC finality votes. B51: the source is held to
                    // account for checks its messages fail. B77: off the
                    // async workers.
                    tokio::task::block_in_place(|| {
                        if let Ok(mut guard) = node_consensus.write() {
                            guard.handle_message_from(&source, &msg);
                        }
                    });
                }
            }
        });
    }

    // === START REST API SERVER ===
    let api_thread = {
        let api_consensus = Arc::clone(&consensus);
        let api_sessions = Arc::clone(&session_table);
        let api_mempool = Arc::clone(&mempool);
        let api_storage = Arc::clone(&storage);
        let api_shutdown = Arc::clone(&shutdown);

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
                            api_sessions,
                            api_mempool,
                            api_storage,
                            Arc::clone(&api_shutdown),
                        )
                        .await
                        {
                            // B305: a node whose RPC cannot listen (its port
                            // taken) stops: it ran on with no RPC, and every
                            // tool reading it saw nothing or another node.
                            eprintln!("❌ FATAL: the API server on port {api_port} failed: {e}");
                            api_shutdown.store(true, Ordering::SeqCst);
                            return Err(e);
                        } else {
                            api_shutdown.store(true, Ordering::SeqCst);
                        }
                        Ok(())
                    })
                }
                Err(e) => {
                    api_shutdown.store(true, Ordering::SeqCst);
                    Err(e)
                }
            }
        })
    };
    let mut api_thread = Some(api_thread);

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
            tokio::task::block_in_place(|| {
                if let Ok(mut c) = consensus_post_sync.write() {
                    c.reload_chain_tip();
                }
            });
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
                tokio::task::block_in_place(|| {
                    if let Ok(mut c) = consensus_periodic.write() {
                        c.reload_chain_tip();
                    }
                });
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
            // The API owns DB references on a separate OS thread. Join it
            // before process teardown can destroy RocksDB's global scheduler.
            api_thread.take().expect("API thread exists").join()
                .expect("API thread panicked").expect("API server failed");
            println!("🧹 Graceful shutdown: draining in-flight consensus work...");
            // Acquiring the consensus write lock blocks until the current
            // try_create_vertex/commit (if any) has finished — the ticker has
            // already stopped starting new ones via the same flag.
            {
                let _drain = consensus.write();
            }
            match storage.flush() {
                Ok(()) => println!("💾 Graceful shutdown: storage flushed to disk."),
                Err(e) => {
                    eprintln!("⚠️ Graceful shutdown: storage flush failed: {e}");
                    // Return through runtime teardown; do not report a clean stop.
                    return std::process::ExitCode::FAILURE;
                }
            }
            println!("👋 Shutdown drain completed; runtime teardown follows.");
            break;
        }

        // === PARALLEL EXECUTION & DA INTEGRATION ===
        // Execution is handled by the consensus commit loop (V4 ticks).
        // DA Batch creation is triggered automatically by Consensus.

        // Update Metrics
        let peer_count = session_table.read().map(|t| t.len()).unwrap_or(0);
        node::metrics::PEER_COUNT.set(peer_count as i64);

        if let Ok(Some(height_str)) = storage.get("latest_height") {
            if let Ok(h) = height_str.parse::<i64>() {
                node::metrics::BLOCK_HEIGHT.set(h);
            }
        }

        thread::sleep(Duration::from_millis(250)); // Poll shutdown ~4x/sec; metrics tick
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod boot_identity_tests {
    use super::{
        check_epoch_interval_pinned, refuse_removed_snapshot_install, resolve_boot_chain_id,
    };

    /// G3 RC-2 / RC-3 at boot (witness C1′'s second half, C2′'s database half).
    #[test]
    fn the_boot_audit_refuses_a_tampered_or_foreign_database() {
        use consensus::qc::{
            build_qc, expected_chain_id, validator_set_hash, FinalityVote, ValidatorInfo,
        };
        use std::sync::Arc;
        let path =
            storage::test_dir::process_dir().join(format!("boot_audit_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let db = Arc::new(storage::StateDB::open(path.to_str().unwrap()).unwrap());
        let committee = vec![ValidatorInfo {
            address: "local".into(),
            stake: 100,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: hex::encode(crypto::bls::BLSEngine::consensus().pubkey_raw(&[7; 32])),
            bls_pop: hex::encode(
                crypto::bls::BLSEngine::consensus().prove_possession_raw(&[7; 32], &[0u8; 32]),
            ),
        }];
        let second = format!("obj:{}", "cd".repeat(32));
        {
            let _seed = db.seeding();
            db.put("sys:chain_id", "AINCORE-TEST").unwrap();
            db.put(&format!("obj:{}", "ab".repeat(32)), "{}").unwrap();
            db.put(
                "genesis:validator_set:v1",
                &serde_json::to_string(&committee).unwrap(),
            )
            .unwrap();
        }
        let v0 = state_commit::seed_genesis(&db).unwrap();
        db.write_batch(v0.batch).unwrap();
        {
            let _seed = db.seeding();
            db.put(&second, "{}").unwrap();
        }
        let v1 = state_commit::apply(&db, 1, vec![(second, Some(b"{}".to_vec()))]).unwrap();
        db.write_batch(v1.batch).unwrap();
        assert_eq!(super::state_boot_audit(&db), Ok(()), "consistent");

        let bls = crypto::bls::BLSEngine::consensus();
        let member = [7u8; 32];
        let quorum_cert = |state_root: String, signer: [u8; 32]| {
            let vote = FinalityVote {
                chain_id: expected_chain_id(),
                epoch: 0,
                finalized_round: 2,
                anchor_round: 2,
                anchor_hash: "01".repeat(32),
                block_height: 1,
                block_hash: "02".repeat(32),
                state_root,
                receipts_root: "04".repeat(32),
                finality_digest: "05".repeat(32),
                validator_set_hash: validator_set_hash(&committee),
                next_validator_set_hash: String::new(),
            };
            let signature = bls.sign_raw(&vote.to_signing_bytes(), &signer);
            serde_json::to_string(&build_qc(&vote, &committee, &[0], &[signature]).unwrap())
                .unwrap()
        };
        let root = hex::encode(state_commit::root(&db, 1).unwrap().0);
        db.put("consensus:qc:latest_height", "1").unwrap();
        db.put("consensus:qc:1", &quorum_cert("00".repeat(32), member))
            .unwrap();
        let err = super::state_boot_audit(&db).expect_err("a foreign root");
        assert!(
            err.contains("RC-3") && err.contains("not the network"),
            "{err}"
        );
        db.put("consensus:qc:1", &quorum_cert(root.clone(), [9; 32]))
            .unwrap();
        let err = super::state_boot_audit(&db).expect_err("signed outside the committee");
        assert!(err.contains("does not verify"), "{err}");
        db.put("consensus:qc:1", &quorum_cert(root.clone(), member))
            .unwrap();
        assert_eq!(super::state_boot_audit(&db), Ok(()), "the network's root");
        db.put("consensus:qc:latest_height", "0").unwrap();
        db.put("consensus:qc:0", &quorum_cert(root, member))
            .unwrap();
        let err = super::state_boot_audit(&db).expect_err("filed under another height");
        assert!(err.contains("does not verify"), "{err}");
        db.put("consensus:qc:latest_height", "1").unwrap();

        {
            let _seed = db.seeding();
            db.put("sys:chain_id", "TAMPERED").unwrap();
        }
        let err = super::state_boot_audit(&db).expect_err("an edited flat key");
        assert!(
            err.contains("RC-2") && err.contains("sys:chain_id"),
            "{err}"
        );
    }

    /// G3 S6: the restore settings parse strictly, are off without a
    /// checkpoint, and need the genesis pin with one.
    #[test]
    fn state_sync_settings_parse_strictly() {
        use super::StateSyncSettings;
        let some = |s: &str| Some(s.to_string());
        let pin = some(&"ee".repeat(32));
        let cp = format!("7:{}:{}", "ab".repeat(32), "cd".repeat(32));
        assert_eq!(
            StateSyncSettings::parse(None, some("1.2.3.4:9"), None, None),
            Ok(None)
        );
        assert_eq!(
            StateSyncSettings::parse(some(" "), None, None, None),
            Ok(None)
        );
        let parsed = StateSyncSettings::parse(
            some(&cp),
            some("192.168.18.202:9022, 192.168.18.66:9032"),
            some("1"),
            pin.clone(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.checkpoint.height, 7);
        assert_eq!(
            parsed.peers,
            vec![
                "/ip4/192.168.18.202/tcp/9122".to_string(),
                "/ip4/192.168.18.66/tcp/9132".to_string()
            ]
        );
        assert!(parsed.replace_existing);
        for (peers, replace, genesis_pin) in [
            (None, None, pin.clone()),
            (some(""), None, pin.clone()),
            (some("192.168.18.202"), None, pin.clone()),
            (some(":9022"), None, pin.clone()),
            (some("host:99999"), None, pin.clone()),
            (some("host:9022"), some("yes"), pin.clone()),
            (some("host:9022"), None, None),
            (some("host:9022"), None, some(" ")),
        ] {
            assert!(
                StateSyncSettings::parse(
                    some(&cp),
                    peers.clone(),
                    replace.clone(),
                    genesis_pin.clone()
                )
                .is_err(),
                "{peers:?} {replace:?} {genesis_pin:?}"
            );
        }
        assert!(StateSyncSettings::parse(some("7:x:y"), some("h:1"), None, pin).is_err());
    }

    fn settings(replace: bool) -> super::StateSyncSettings {
        super::StateSyncSettings::parse(
            Some(format!("7:{}:{}", "ab".repeat(32), "cd".repeat(32))),
            Some("127.0.0.1:1".into()),
            replace.then(|| "1".into()),
            Some("ee".repeat(32)),
        )
        .unwrap()
        .unwrap()
    }

    fn skip_db(name: &str) -> std::sync::Arc<storage::StateDB> {
        let path = storage::test_dir::process_dir().join(format!(
            "s6b_{name}_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::sync::Arc::new(storage::StateDB::open(path.to_str().unwrap()).unwrap())
    }

    fn block_at_7(hash: &str) -> String {
        let mut block = blockchain::Block::new_with_roots(
            7,
            14,
            "00".repeat(32),
            vec![],
            "p".into(),
            String::new(),
            String::new(),
        );
        block.header.hash = hash.to_string();
        block.header.state_root = "cd".repeat(32);
        serde_json::to_string(&block).unwrap()
    }

    /// A restore must not run: no genesis is built.
    fn untouched() -> Result<node::genesis::GenesisState, String> {
        panic!("no genesis is built when nothing is restored")
    }

    /// A restore runs: it asks for the genesis, which here fails.
    fn no_genesis() -> Result<node::genesis::GenesisState, String> {
        Err("no genesis".into())
    }

    /// A session client whose network task is gone: these restores stop
    /// before asking any peer.
    fn closed_sessions() -> network::SessionClient {
        let book = std::sync::Arc::new(std::sync::RwLock::new(node::sessions::PeerBook::default()));
        node::sessions::SessionWiring::new(book).1
    }

    /// G3 S6: a datadir restored from this checkpoint, or past it on its
    /// chain, is left alone, so the settings may stay set across restarts.
    #[tokio::test]
    async fn a_datadir_at_the_checkpoint_is_not_restored_again() {
        use super::restore_from_checkpoint;
        let me = "ff".repeat(32);
        let on_chain = skip_db("on_chain");
        on_chain.put("latest_height", "9").unwrap();
        on_chain
            .put("block_7", &block_at_7(&"ab".repeat(32)))
            .unwrap();
        for replace in [false, true] {
            assert_eq!(
                restore_from_checkpoint(
                    &on_chain,
                    &settings(replace),
                    untouched,
                    &closed_sessions(),
                    &me
                )
                .await,
                Ok(None),
                "on the checkpoint's chain (replace: {replace})"
            );
        }
        let restored = skip_db("restored");
        restored
            .put("block_7", &block_at_7(&"ab".repeat(32)))
            .unwrap();
        restored
            .put(
                chain_sync::state_sync::RESTORED_CHECKPOINT,
                &settings(true).checkpoint.to_string(),
            )
            .unwrap();
        assert_eq!(
            restore_from_checkpoint(
                &restored,
                &settings(true),
                untouched,
                &closed_sessions(),
                &me
            )
            .await,
            Ok(None),
            "restored from it already"
        );
        // Mid-restore, it restores.
        on_chain.put(storage::RESTORE_MARKER, "{}").unwrap();
        assert_eq!(
            restore_from_checkpoint(
                &on_chain,
                &settings(false),
                no_genesis,
                &closed_sessions(),
                &me
            )
            .await,
            Err("no genesis".into())
        );
    }

    /// Review M2: a datadir past the checkpoint on another chain (its block at
    /// the checkpoint height differs: a fork) is refused, or replaced when
    /// asked. With the block pruned the QC at that height, never pruned,
    /// decides; with neither, it is refused (post-fix review MEDIUM 4).
    #[tokio::test]
    async fn a_forked_datadir_past_the_checkpoint_is_refused_or_replaced() {
        use super::restore_from_checkpoint;
        let me = "ff".repeat(32);
        let forked = skip_db("forked");
        forked.put("latest_height", "100").unwrap();
        forked
            .put("block_7", &block_at_7(&"99".repeat(32)))
            .unwrap();
        let err = restore_from_checkpoint(
            &forked,
            &settings(false),
            untouched,
            &closed_sessions(),
            &me,
        )
        .await
        .unwrap_err();
        assert!(
            err.contains("another chain") && err.contains("REPLACE"),
            "{err}"
        );
        assert_eq!(
            restore_from_checkpoint(
                &forked,
                &settings(true),
                no_genesis,
                &closed_sessions(),
                &me
            )
            .await,
            Err("no genesis".into()),
            "replaced when asked"
        );
        // Block pruned: the QC at the checkpoint height decides.
        let qc_at_7 = |hash: &str| {
            let mut qc: consensus::qc::QuorumCertificate =
                serde_json::from_value(serde_json::json!({
                    "version": 1, "chain_id": "C", "epoch": 0, "finalized_round": 16,
                    "anchor_round": 14, "anchor_hash": "", "block_height": 7, "block_hash": "",
                    "state_root": "", "receipts_root": "", "finality_digest": "",
                    "validator_set_hash": "", "signer_bitmap": [], "signed_stake": 0,
                    "total_stake": 0, "aggregate_signature": [],
                }))
                .unwrap();
            qc.block_hash = hash.to_string();
            qc.state_root = "cd".repeat(32);
            serde_json::to_string(&qc).unwrap()
        };
        let pruned_on_chain = skip_db("pruned_on_chain");
        pruned_on_chain.put("latest_height", "100").unwrap();
        pruned_on_chain
            .put("consensus:qc:7", &qc_at_7(&"ab".repeat(32)))
            .unwrap();
        assert_eq!(
            restore_from_checkpoint(
                &pruned_on_chain,
                &settings(false),
                untouched,
                &closed_sessions(),
                &me
            )
            .await,
            Ok(None),
            "the QC says: the checkpoint's chain"
        );
        let pruned_forked = skip_db("pruned_forked");
        pruned_forked.put("latest_height", "100").unwrap();
        pruned_forked
            .put("consensus:qc:7", &qc_at_7(&"99".repeat(32)))
            .unwrap();
        let err = restore_from_checkpoint(
            &pruned_forked,
            &settings(false),
            untouched,
            &closed_sessions(),
            &me,
        )
        .await
        .unwrap_err();
        assert!(err.contains("another chain"), "{err}");
        let mut wrong_root = settings(false);
        wrong_root.checkpoint.state_root = "ee".repeat(32);
        let block_only = skip_db("pinned_root");
        block_only.put("latest_height", "100").unwrap();
        block_only
            .put("block_7", &block_at_7(&"ab".repeat(32)))
            .unwrap();
        for db in [&pruned_on_chain, &block_only] {
            assert!(
                restore_from_checkpoint(db, &wrong_root, untouched, &closed_sessions(), &me)
                    .await
                    .is_err()
            );
        }
        // A retained block and QC must describe a consistent history.
        pruned_on_chain
            .put("block_7", &block_at_7(&"99".repeat(32)))
            .unwrap();
        assert!(restore_from_checkpoint(
            &pruned_on_chain,
            &settings(false),
            untouched,
            &closed_sessions(),
            &me
        )
        .await
        .is_err());
        // Neither block nor QC: cannot tell, so refused unless replacing.
        let unknown = skip_db("unknown");
        unknown.put("latest_height", "100").unwrap();
        let err = restore_from_checkpoint(
            &unknown,
            &settings(false),
            untouched,
            &closed_sessions(),
            &me,
        )
        .await
        .unwrap_err();
        assert!(err.contains("cannot be told"), "{err}");
        assert_eq!(
            restore_from_checkpoint(
                &unknown,
                &settings(true),
                no_genesis,
                &closed_sessions(),
                &me
            )
            .await,
            Err("no genesis".into())
        );
        // Exactly at the checkpoint height counts as past it; one below
        // restores.
        let at = skip_db("at_height");
        at.put("latest_height", "7").unwrap();
        at.put("block_7", &block_at_7(&"ab".repeat(32))).unwrap();
        assert_eq!(
            restore_from_checkpoint(&at, &settings(false), untouched, &closed_sessions(), &me)
                .await,
            Ok(None)
        );
        at.put("latest_height", "6").unwrap();
        assert_eq!(
            restore_from_checkpoint(&at, &settings(true), no_genesis, &closed_sessions(), &me)
                .await,
            Err("no genesis".into())
        );
    }

    /// SN-6 at every boot: a datadir restored with one key refuses to run
    /// with another that the chain records as a validator, in any epoch it
    /// retains or in the active set; the restoring key itself may join.
    #[test]
    fn a_restored_datadir_refuses_a_different_validator_key() {
        use super::check_restored_signer;
        let observer = "aa".repeat(32);
        let old = "bb".repeat(32);
        let current = "cc".repeat(32);
        let pending = "dd".repeat(32);
        let member = |address: &str| consensus::qc::ValidatorInfo {
            address: address.to_string(),
            stake: 100,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: "00".repeat(48),
            bls_pop: "00".repeat(96),
        };
        let set = |who: &str| serde_json::to_string(&vec![member(who)]).unwrap();
        // Genesis: `old`. Epoch 2, the current one: `current`. The active
        // set: `pending`, and the observer that restored, which joined.
        let db = skip_db("restored_signer");
        {
            let _seed = db.seeding();
            db.put("genesis:validator_set:v1", &set(&old)).unwrap();
            db.put("sys:validator_set:epoch:2", &set(&current)).unwrap();
            db.put("consensus:epoch", "2").unwrap();
            db.put(
                "sys:validators",
                &serde_json::to_string(&vec![(pending.clone(), 100u64), (observer.clone(), 100)])
                    .unwrap(),
            )
            .unwrap();
        }
        let ok = |key: &str| check_restored_signer(&db, key).is_ok();
        assert!(
            [&observer, &old, &current, &pending].iter().all(|k| ok(k)),
            "not restored"
        );
        db.put(chain_sync::state_sync::RESTORED_BY, &observer)
            .unwrap();
        assert!(ok(&observer), "the restoring key, a validator since");
        assert!(ok(&"ee".repeat(32)), "another key that is no validator");
        for key in [&old, &current, &pending] {
            let err = check_restored_signer(&db, key).unwrap_err();
            assert!(err.contains("SN-6") && err.contains(&observer), "{err}");
        }
    }

    #[test]
    fn the_removed_snapshot_install_refuses_to_start() {
        assert!(refuse_removed_snapshot_install(None).is_ok());
        assert!(refuse_removed_snapshot_install(Some("  ".into())).is_ok());
        let err = refuse_removed_snapshot_install(Some("https://x/snap.tar.gz".into()))
            .expect_err("a set snapshot variable refuses");
        assert!(err.contains("SN-5"), "{err}");
    }

    fn some(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn the_chain_id_comes_from_storage_and_the_env_may_only_repeat_it() {
        assert_eq!(
            resolve_boot_chain_id(some("CHAIN-A"), None).unwrap(),
            "CHAIN-A"
        );
        assert_eq!(
            resolve_boot_chain_id(some("CHAIN-A"), some("CHAIN-A")).unwrap(),
            "CHAIN-A"
        );
        assert_eq!(
            resolve_boot_chain_id(some("CHAIN-A"), some("")).unwrap(),
            "CHAIN-A"
        );
        let err = resolve_boot_chain_id(some("CHAIN-A"), some("CHAIN-B")).unwrap_err();
        assert!(err.contains("CHAIN-B") && err.contains("CHAIN-A"), "{err}");
        // No stored id: the env cannot stand in for it.
        assert!(resolve_boot_chain_id(None, some("CHAIN-A")).is_err());
        assert!(resolve_boot_chain_id(some("  "), some("CHAIN-A")).is_err());
    }

    #[test]
    fn the_epoch_interval_comes_from_the_genesis_pin_only() {
        assert_eq!(check_epoch_interval_pinned(some("20"), None).unwrap(), 20);
        assert_eq!(
            check_epoch_interval_pinned(some("20"), some("20")).unwrap(),
            20
        );
        assert!(check_epoch_interval_pinned(some("20"), some("7")).is_err());
        assert!(check_epoch_interval_pinned(some("20"), some("x")).is_err());
        // No pin: the env cannot stand in for it.
        assert!(check_epoch_interval_pinned(None, some("20")).is_err());
        assert!(check_epoch_interval_pinned(some("0"), None).is_err());
        assert!(check_epoch_interval_pinned(some("abc"), None).is_err());
    }
}

#[cfg(test)]
mod secret_file_tests {
    use super::{load_or_create_node_key, owner_only};
    use crypto::key_file::publish_new;

    #[test]
    fn concurrent_node_initializers_read_the_same_key() {
        let dir = storage::test_dir::process_dir()
            .join(format!("init-key-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        let barrier = std::sync::Barrier::new(2);
        let initialize = || {
            barrier.wait();
            load_or_create_node_key(&path).unwrap().verifying_key()
        };
        let (a, b) = std::thread::scope(|s| {
            let first = s.spawn(initialize);
            let second = initialize();
            (first.join().unwrap(), second)
        });
        assert_eq!(a, b);
        assert_eq!(a, load_or_create_node_key(&path).unwrap().verifying_key());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// B87: node.key is owner-only from the first byte, under any umask,
    /// and later initializers cannot replace it.
    #[test]
    fn a_secret_file_is_created_owner_only() {
        let dir = storage::test_dir::process_dir().join(format!("secret_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.key");
        publish_new(&path, &[7u8; 32]).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), vec![7u8; 32]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "node.key must be owner-only, is {mode:o}");
        }
        let second = publish_new(&path, &[9u8; 32]).unwrap_err();
        assert_eq!(second.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), vec![7u8; 32]);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        // B112: a key an older build left world-readable is narrowed.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            owner_only(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "narrowed to {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod bootnode_tests {
    use super::{bad_bootnodes, check_bootnodes};

    fn list(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|e| e.to_string()).collect()
    }

    /// B384 witness: a boot list entry the node cannot dial is refused at
    /// boot, every one named. `boot_dial_list` dropped it with one log line
    /// and the node booted isolated (a list of only bad entries also
    /// skipped `AINCORE_PUBLIC_SEED_BOOTNODE`); a bad public seed is
    /// refused the same way.
    #[test]
    fn a_bootnode_the_node_cannot_dial_is_refused() {
        let good = list(&[
            "127.0.0.1:9001",
            "[::1]:9001",
            "seed.example.org:9001",
            "/ip4/10.0.0.1/tcp/9001",
        ]);
        assert_eq!(bad_bootnodes(&good), Vec::<String>::new());
        assert!(check_bootnodes(&good, Some("/ip4/10.0.0.2/tcp/9001".into())).is_ok());
        assert!(check_bootnodes(&[], None).is_ok());
        assert!(
            check_bootnodes(&[], Some(" ".into())).is_ok(),
            "blank is unset"
        );

        let bad = bad_bootnodes(&list(&[
            "127.0.0.1",
            "127.0.0.1:9001",
            "/ip4/10.0.0.1",
            "",
            "localhost:99999",
        ]));
        assert_eq!(bad.len(), 4, "{bad:?}");

        let err = check_bootnodes(&list(&["nohost", "10.0.0.1:65500"]), None).unwrap_err();
        assert!(err.contains("nohost") && err.contains("65500"), "{err}");
        let err = check_bootnodes(&good, Some("/dns4/seed.example.org".into())).unwrap_err();
        assert!(err.contains("AINCORE_PUBLIC_SEED_BOOTNODE"), "{err}");
        assert!(!err.contains("--bootnodes"), "{err}");
    }
}
