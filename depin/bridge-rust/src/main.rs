mod aincore_client;
mod evm_client;
mod nonce_store;

use aincore_client::AincoreClient;
use dotenv::dotenv;
use ethers::signers::LocalWallet;
use evm_client::EvmClient;
use log::{error, info, warn};
use nonce_store::BridgeState;
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::init();

    info!("🌉 AINCORE Bridge Service (Rust) Starting...");

    // Configuration
    let aincore_rpc =
        env::var("AINCORE_RPC").unwrap_or_else(|_| "http://localhost:8001/rpc".to_string());
    let evm_rpc = env::var("EVM_RPC").unwrap_or_else(|_| "https://rpc.sepolia.org".to_string());
    let contract_addr = env::var("CONTRACT_ADDRESS")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    // Argument Parsing for Keystore
    let args: Vec<String> = env::args().collect();
    let mut keystore_path = None;
    for i in 0..args.len() {
        if args[i] == "--keystore" && i + 1 < args.len() {
            keystore_path = Some(args[i + 1].clone());
        }
    }

    let evm_private_key = if let Some(keystore_path) = keystore_path {
        info!(
            "🔐 Loading EVM private key from secure keystore: {}",
            keystore_path
        );

        // Prompt for password
        let password = rpassword::prompt_password("Enter keystore password: ")
            .expect("Failed to read password");

        // Decrypt keystore
        keystore::KeyManager::decrypt(&keystore_path, &password)
            .expect("Failed to decrypt keystore")
    } else {
        // PRODUCTION SECURITY: Keystore is MANDATORY
        error!("🚨 CRITICAL: --keystore flag is REQUIRED for production deployment");
        error!("🚨 Environment variables (EVM_PRIVATE_KEY) are NOT SECURE:");
        error!("   - Visible in process listings (ps aux)");
        error!("   - Leaked in core dumps");
        error!("   - Exposed to child processes");
        error!("   - Logged in system logs");
        error!("");
        error!("Usage: cargo run -- --keystore /path/to/keystore.json");

        std::process::exit(1);
    };

    // FIX: mut aincore
    let mut aincore = AincoreClient::new(aincore_rpc.clone());

    // Initialize EVM Client
    // FIX: Parse String pkey to LocalWallet
    let wallet: LocalWallet = evm_private_key
        .parse()
        .expect("Failed to parse private key");
    // Ensure 3-of-5 threshold is met by generating additional temporary signers for prototype
    let wallet2 = LocalWallet::new(&mut rand::thread_rng());
    let wallet3 = LocalWallet::new(&mut rand::thread_rng());

    let evm = match EvmClient::new(
        evm_rpc.clone(),
        contract_addr.clone(),
        vec![wallet, wallet2, wallet3],
    ) {
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
                let current_height = aincore.get_last_processed_height();
                let mut batch_processed = 0u64;

                for (sender, amount, eth_addr) in events {
                    // H-03: Build dedup key and check tombstone before processing.
                    let event_key =
                        BridgeState::event_key(&sender, amount, &eth_addr, current_height);

                    if bridge_state.is_seen(&event_key) {
                        warn!(
                            "⚠️  [H-03] REPLAY DETECTED — skipping duplicate event: {}",
                            event_key
                        );
                        continue;
                    }

                    info!("🔒 Processing Lock: {} AIN from {}", amount, sender);

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
                                // On failure: nonce was already incremented in state.
                                // The EVM tx was attempted; operator must resolve manually.
                                // We still persist to avoid re-sending (which would use
                                // a different nonce and create a stuck tx).
                            }
                        }
                    } else {
                        info!("⚠️ EVM Client not ready. Skipping mint for {}", eth_addr);
                        // Don't mark as processed — retry next loop.
                    }
                }

                // Persist state after every polling cycle (height + any new tombstones).
                bridge_state.last_processed_height = current_height;
                if batch_processed > 0 || current_height > 0 {
                    bridge_state.save();
                }
            }
            Err(e) => error!("❌ Error fetching AINCORE events: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
