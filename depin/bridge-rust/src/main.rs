mod aincore_client;
mod evm_client;
mod nonce_store;
mod validator_set;

use aincore_client::AincoreClient;
use dotenv::dotenv;
use ethers::signers::LocalWallet;
use evm_client::EvmClient;
use log::{error, info, warn};
use nonce_store::BridgeState;
use std::env;
use std::time::Duration;

/// B332: the bridge cannot see a lock (it reads a raw `bridge_lock:` payload
/// that admission refuses, and no stdlib module escrows AIN), its mint would
/// revert (it signs `abi.encode`, the contract recovers `abi.encodePacked`),
/// and its signature binds neither the EVM chain nor the contract. It runs
/// only when its operator says it is an experiment.
fn refuse_unless_experimental(flag: Option<String>) -> Result<(), String> {
    if flag.as_deref() == Some("1") {
        Ok(())
    } else {
        Err(
            "the EVM bridge is not part of the launch (no lock it can see, mints that \
             revert): set AINCORE_BRIDGE_EXPERIMENTAL=1 to run it against a test chain"
                .to_string(),
        )
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::init();
    if let Err(why) = refuse_unless_experimental(env::var("AINCORE_BRIDGE_EXPERIMENTAL").ok()) {
        error!("❌ {why}");
        std::process::exit(1);
    }

    info!("🌉 AINCORE Bridge Service (Rust) Starting...");

    // Configuration
    // B258: the node's API port is 8002 (the default was 8001).
    let aincore_rpc =
        env::var("AINCORE_RPC").unwrap_or_else(|_| "http://localhost:8002/rpc".to_string());
    // B258: the chain is named, never assumed (the default was mainnet).
    let Some(chain_id) = aincore_client::configured_chain_id() else {
        error!(
            "❌ AINCORE_CHAIN_ID is not set: name the chain whose certificates this bridge accepts"
        );
        std::process::exit(1);
    };
    // B320: a finality vote binds the genesis too, so the one this bridge
    // follows is installed before any certificate is verified.
    let Some(genesis_identity) = aincore_client::configured_genesis_identity() else {
        error!(
            "❌ AINCORE_GENESIS_IDENTITY is not set: name the genesis whose certificates this bridge accepts"
        );
        std::process::exit(1);
    };
    blockchain::set_vertex_domain(&chain_id, &genesis_identity);
    let evm_rpc = env::var("EVM_RPC").unwrap_or_else(|_| "https://rpc.sepolia.org".to_string());
    let contract_addr = env::var("CONTRACT_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    // Phase 5B.3 / SEC-N01: parse ONE OR MORE `--keystore <path>` flags.
    // EvmClient requires 3 distinct signers (MULTISIG_THRESHOLD = 3). The
    // previous code accepted exactly one keystore and silently padded the
    // signer set with two `LocalWallet::new(&mut rand::thread_rng())`
    // ephemeral keys — fake multisig that collapsed to single-key trust
    // and broke on every restart (regenerated keys would not match any
    // on-chain registration). Bridge now hard-fails boot unless at least
    // MULTISIG_THRESHOLD real keystores are supplied.
    let args: Vec<String> = env::args().collect();
    let mut keystore_paths: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--keystore" && i + 1 < args.len() {
            keystore_paths.push(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }

    const REQUIRED_KEYSTORES: usize = 3;
    if keystore_paths.len() < REQUIRED_KEYSTORES {
        error!(
            "🚨 CRITICAL [SEC-N01]: bridge requires {} real keystores; got {}.",
            REQUIRED_KEYSTORES,
            keystore_paths.len()
        );
        error!("🚨 The previous build silently padded with ephemeral random wallets —");
        error!("🚨 that collapsed the security to single-key trust and is now BLOCKED.");
        error!("");
        error!("Usage:");
        error!("  bridge-rust --keystore /path/to/key1.json \\");
        error!("              --keystore /path/to/key2.json \\");
        error!("              --keystore /path/to/key3.json");
        std::process::exit(1);
    }

    // Decrypt each keystore (separate password prompt per file). All
    // keystores must succeed before the bridge starts.
    let mut wallets: Vec<LocalWallet> = Vec::with_capacity(keystore_paths.len());
    for (idx, path) in keystore_paths.iter().enumerate() {
        info!(
            "🔐 Loading keystore {}/{}: {}",
            idx + 1,
            keystore_paths.len(),
            path
        );
        let password = rpassword::prompt_password(format!(
            "Enter password for keystore {} ({}): ",
            idx + 1,
            path
        ))
        .expect("Failed to read password");
        let pk =
            keystore::KeyManager::decrypt(path, &password).expect("Failed to decrypt keystore");
        let w: LocalWallet = pk
            .parse()
            .expect("Failed to parse private key from keystore");
        wallets.push(w);
    }

    // Refuse to start if any two keystores resolved to the same address —
    // that defeats the multisig requirement just as effectively as
    // ephemeral random wallets did.
    let mut addrs: Vec<_> = wallets
        .iter()
        .map(|w| {
            use ethers::signers::Signer;
            w.address()
        })
        .collect();
    addrs.sort();
    let unique_before = addrs.len();
    addrs.dedup();
    if addrs.len() != unique_before {
        error!(
            "🚨 CRITICAL [SEC-N01]: keystores resolve to duplicate addresses; refusing to start."
        );
        std::process::exit(1);
    }

    let mut aincore = AincoreClient::new(aincore_rpc.clone());

    let evm = match EvmClient::new(evm_rpc.clone(), contract_addr.clone(), wallets) {
        Ok(c) => Some(c),
        Err(e) => {
            error!("⚠️ Failed to initialize EVM Client: {}", e);
            None
        }
    };

    // Phase 3 / H-03: Load persisted bridge state.
    // - last_processed_height: resume from where we left off (no block re-scan)
    // - nonce_counter: continue EVM nonce sequence (no collision)
    // - processed_events: tombstones for replay protection
    let mut bridge_state = BridgeState::load();

    // Sync AincoreClient's internal height cursor to the persisted value so
    // it doesn't re-scan blocks already processed before restart.
    aincore.set_last_processed_height(bridge_state.last_processed_height);

    info!(
        "🚀 Bridge Service Running (nonce={}, resume_height={}). Polling...",
        bridge_state.nonce_counter, bridge_state.last_processed_height
    );

    loop {
        match aincore.fetch_bridge_events().await {
            Ok(events) => {
                let cursor_after_fetch = aincore.get_last_processed_height();
                let mut batch_processed = 0u64;

                // Phase 3.5 fix: events now carry block_height + tx_index so
                // the dedup key is GLOBALLY unique. Two identical (sender,
                // amount, eth_addr) transactions in the same finalized batch
                // no longer collide because their (block_height, tx_index)
                // differ.
                for (sender, amount, eth_addr, block_height, tx_index) in events {
                    let event_key =
                        BridgeState::event_key(&sender, amount, &eth_addr, block_height, tx_index);

                    if bridge_state.is_seen(&event_key) {
                        warn!(
                            "⚠️  [H-03] REPLAY DETECTED — skipping duplicate event: {}",
                            event_key
                        );
                        continue;
                    }

                    info!(
                        "🔒 Lock @ block {} tx#{}: {} AIN from {}",
                        block_height, tx_index, amount, sender
                    );

                    if let Some(evm_client) = &evm {
                        // H-03: Get next nonce from persisted state (never resets).
                        let nonce = bridge_state.mark_processed(event_key);

                        match evm_client
                            .mint_tokens(&eth_addr, amount.into(), nonce)
                            .await
                        {
                            Ok(tx_hash) => {
                                info!("✅ Minted on EVM (nonce={}): {}", nonce, tx_hash);
                                batch_processed += 1;
                            }
                            Err(e) => {
                                error!("❌ Failed to mint on EVM: {}", e);
                                // Nonce already incremented; operator resolves manually.
                            }
                        }
                    } else {
                        info!("⚠️ EVM Client not ready. Skipping mint for {}", eth_addr);
                    }
                }

                // Persist cursor + any new tombstones.
                bridge_state.last_processed_height = cursor_after_fetch;
                if batch_processed > 0 || cursor_after_fetch > 0 {
                    bridge_state.save();
                }
            }
            Err(e) => error!("❌ Error fetching AINCORE events: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    /// B332 witness: the bridge does not run unless its operator says it is
    /// an experiment (it cannot see a lock, and its mints revert).
    #[test]
    fn the_bridge_runs_only_as_an_experiment() {
        assert!(super::refuse_unless_experimental(None).is_err());
        assert!(super::refuse_unless_experimental(Some("yes".into())).is_err());
        assert!(super::refuse_unless_experimental(Some("1".into())).is_ok());
    }
}
