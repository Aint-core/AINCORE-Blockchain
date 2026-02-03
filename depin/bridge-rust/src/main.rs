mod aincore_client;
mod evm_client;

use aincore_client::AincoreClient;
use evm_client::EvmClient;
use std::env;
use dotenv::dotenv;
use log::{info, error};
use std::time::Duration;
use ethers::signers::LocalWallet;

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


    let evm_private_key = if let Some(keystore_path) = keystore_path {
        info!("🔐 Loading EVM private key from secure keystore: {}", keystore_path);
        
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
    let wallet: LocalWallet = evm_private_key.parse().expect("Failed to parse private key");
    
    let evm = match EvmClient::new(evm_rpc.clone(), contract_addr.clone(), vec![wallet]) {
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
                        // FIX: Cast amount to u128 and pass eth_addr string
                        match evm_client.mint_tokens(&eth_addr, amount.into()).await {
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
