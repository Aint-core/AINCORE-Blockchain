mod aincore_client;
mod btc_client;
mod storage;

use aincore_client::AincoreClient;
use btc_client::BtcClient;
use std::env;
use storage::Storage;
use tokio::time::{sleep, Duration};

const CONFIRMATIONS: u64 = 6;

#[tokio::main]
async fn main() {
    // SECURITY: Load all sensitive config from environment variables
    let multisig_address =
        env::var("BTC_MULTISIG_ADDRESS").expect("BTC_MULTISIG_ADDRESS env var is required");
    let aincore_rpc =
        env::var("AINCORE_RPC").unwrap_or_else(|_| "http://localhost:8002".to_string());
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
                    // H-03 (BTC port): is_seen() now also covers in-progress
                    // tombstones from a crashed prior run — those entries
                    // must NOT be retried automatically.
                    if db.is_seen(&tx_hash) {
                        continue;
                    }

                    println!(
                        "💰 New Deposit Detected: {} sats from tx {}",
                        amount, tx_hash
                    );

                    // H-03 fix: tombstone BEFORE mint. If save() fails we
                    // abort the mint attempt entirely — better to be late
                    // than to double-mint after a crash between mint and
                    // mark_completed.
                    if let Err(e) = db.mark_in_progress(tx_hash.clone()) {
                        eprintln!(
                            "❌ [H-03] Failed to tombstone tx {} before mint; \
                             ABORTING mint to prevent double-mint risk: {}",
                            tx_hash, e
                        );
                        continue;
                    }

                    // Attempt the mint. On success: promote tombstone to
                    // Completed. On failure: leave as InProgress so the
                    // operator can investigate; automatic retry is blocked.
                    match aincore.mint_wbtc(&user, amount).await {
                        Ok(_) => {
                            println!("✅ Minted successfully!");
                            if let Err(e) = db.mark_completed(&tx_hash) {
                                eprintln!(
                                    "⚠️  Mint succeeded but mark_completed failed: {} \
                                     (tx remains in InProgress; operator must verify)",
                                    e
                                );
                            }
                        }
                        Err(e) => eprintln!(
                            "❌ Minting failed for tx {}: {} \
                             (left as InProgress; operator-manual resolution)",
                            tx_hash, e
                        ),
                    }
                }
            }
            Err(e) => eprintln!("⚠️ Error checking deposits: {}", e),
        }

        // Wait 60 seconds before next check
        sleep(Duration::from_secs(60)).await;
    }
}
