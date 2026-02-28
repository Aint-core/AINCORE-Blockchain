mod btc_client;
mod aincore_client;
mod storage;

use tokio::time::{sleep, Duration};
use btc_client::BtcClient;
use aincore_client::AincoreClient;
use storage::Storage;
use std::env;

const CONFIRMATIONS: u64 = 6;

#[tokio::main]
async fn main() {
    // SECURITY: Load all sensitive config from environment variables
    let multisig_address = env::var("BTC_MULTISIG_ADDRESS")
        .expect("BTC_MULTISIG_ADDRESS env var is required");
    let aincore_rpc = env::var("AINCORE_RPC")
        .unwrap_or_else(|_| "http://localhost:8002".to_string());
    let bridge_key = env::var("BRIDGE_KEY")
        .expect("BRIDGE_KEY env var is required. Never hardcode private keys!");

    println!("🌉 BTC Bridge Service Starting...");
    println!("👀 Monitoring BTC Address: {}", multisig_address);
    println!("🔐 Required Confirmations: {}", CONFIRMATIONS);

    let btc = BtcClient::new(multisig_address);
    let aincore = AincoreClient::new(aincore_rpc, bridge_key);
    let mut db = Storage::new("processed_txs.json");

    loop {
        match btc.get_deposits(CONFIRMATIONS).await {
            Ok(deposits) => {
                for (tx_hash, amount, user) in deposits {
                    if !db.is_processed(&tx_hash) {
                        println!("💰 New Deposit Detected: {} sats from tx {}", amount, tx_hash);
                        
                        // Mint wBTC
                        match aincore.mint_wbtc(&user, amount).await {
                            Ok(_) => {
                                println!("✅ Minted successfully!");
                                if let Err(e) = db.mark_processed(tx_hash.clone()) {
                                    eprintln!("❌ Failed to save state: {}", e);
                                }
                            },
                            Err(e) => eprintln!("❌ Minting failed: {}", e),
                        }
                    }
                }
            },
            Err(e) => eprintln!("⚠️ Error checking deposits: {}", e),
        }

        // Wait 60 seconds before next check
        sleep(Duration::from_secs(60)).await;
    }
}
