mod btc_client;
mod aincore_client;
mod storage;

use tokio::time::{sleep, Duration};
use btc_client::BtcClient;
use aincore_client::AincoreClient;
use storage::Storage;

// Configuration (Hardcoded for prototype phase)
// Configuration (Updated for Deployment)
const MULTISIG_ADDRESS: &str = "bc1q5d40e477b2bb3cc9d9f5508de1fb0456aincore"; // Generated Multisig
const AINCORE_RPC: &str = "http://localhost:8002"; // Updated Port
const BRIDGE_KEY: &str = "03a768d1830ddb64823af79c3017f7a9e21da2de39eee3d7444203d014a156ea"; // Generated Key
const CONFIRMATIONS: u64 = 6;

#[tokio::main]
async fn main() {
    println!("🌉 BTC Bridge Service Starting...");
    println!("👀 Monitoring BTC Address: {}", MULTISIG_ADDRESS);
    println!("🔐 Required Confirmations: {}", CONFIRMATIONS);

    let btc = BtcClient::new(MULTISIG_ADDRESS.to_string());
    let aincore = AincoreClient::new(AINCORE_RPC.to_string(), BRIDGE_KEY.to_string());
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
