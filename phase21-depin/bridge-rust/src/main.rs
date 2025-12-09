mod aincore_client;
mod evm_client;

use aincore_client::AincoreClient;
use evm_client::EvmClient;
use std::env;
use dotenv::dotenv;
use log::{info, error};
use std::time::Duration;

#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::init();

    info!("🌉 AINCORE Bridge Service (Rust) Starting...");

    // Configuration
    let aincore_rpc = env::var("AINCORE_RPC").unwrap_or_else(|_| "http://localhost:8001/rpc".to_string());
    let evm_rpc = env::var("EVM_RPC").unwrap_or_else(|_| "https://rpc.sepolia.org".to_string());
    let contract_addr = env::var("CONTRACT_ADDRESS").unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".to_string());

    // Argument Parsing for Keystore
    let args: Vec<String> = env::args().collect();
    let mut keystore_path = None;
    for i in 0..args.len() {
        if args[i] == "--keystore" && i + 1 < args.len() {
            keystore_path = Some(args[i+1].clone());
        }
    }

    let evm_private_key = if let Some(path) = keystore_path {
        info!("🔐 Loading key from keystore: {}", path);
        print!("🔑 Enter keystore password: ");
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        let password = rpassword::read_password().expect("Failed to read password");
        match keystore::KeyManager::decrypt(&path, &password) {
            Ok(k) => k,
            Err(e) => {
                error!("❌ Failed to decrypt key: {}", e);
                return;
            }
        }
    } else {
        // Fallback to Env Var (Legacy/Unsafe)
        match env::var("EVM_PRIVATE_KEY") {
            Ok(k) => {
                info!("🚨 CRITICAL SECURITY WARNING: Using EVM_PRIVATE_KEY from environment variables.");
                info!("🚨 IN PRODUCTION, THIS KEY WILL BE LEAKED IN PROCESS DUMPS.");
                info!("🚨 USE --keystore INSTEAD.");
                // sleep to make them read it
                tokio::time::sleep(Duration::from_secs(3)).await;
                k
            }
            Err(_) => {
                error!("❌ No private key provided! Use --keystore <path> or set EVM_PRIVATE_KEY.");
                return;
            }
        }
    };

    let aincore = AincoreClient::new(aincore_rpc);
    
    // Initialize EVM Client
    let evm = match EvmClient::new(&evm_rpc, &evm_private_key, &contract_addr) {
        Ok(c) => Some(c),
        Err(e) => {
            error!("⚠️ Failed to initialize EVM Client: {}", e);
            None
        }
    };

    info!("🚀 Bridge Service Running. Polling for events...");

    loop {
        match aincore.fetch_bridge_events().await {
            Ok(events) => {
                for (sender, amount, eth_addr) in events {
                    info!("🔒 Processing Lock: {} AIN from {}", amount, sender);
                    
                    if let Some(evm_client) = &evm {
                        match evm_client.mint_tokens(&eth_addr, amount).await {
                            Ok(tx_hash) => info!("✅ Minted on EVM: {}", tx_hash),
                            Err(e) => error!("❌ Failed to mint on EVM: {}", e),
                        }
                    } else {
                        info!("⚠️ EVM Client not ready. Skipping mint for {}", eth_addr);
                    }
                }
            }
            Err(e) => error!("❌ Error fetching AINCORE events: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
