mod aincore_client;
mod btc_client;
mod custody;
mod storage;

use aincore_client::AincoreClient;
use btc_client::BtcClient;
use custody::{Custody, CustodyType, Network};
use log::{error, info};
use std::env;
use storage::Storage;
use tokio::time::{sleep, Duration};

const CONFIRMATIONS: u64 = 6;

#[tokio::main]
async fn main() {
    env_logger::init();

    // SECURITY: Load all sensitive config from environment variables
    let multisig_address =
        env::var("BTC_MULTISIG_ADDRESS").expect("BTC_MULTISIG_ADDRESS env var is required");
    let aincore_rpc =
        env::var("AINCORE_RPC").unwrap_or_else(|_| "http://localhost:8002".to_string());

    // Audit #33: CUSTODY verification. Derive the canonical custody
    // scriptPubKey/address from a configured redeem/witness script the
    // operator controls, then assert it equals BTC_MULTISIG_ADDRESS. This
    // closes the trust gap of relying on an indexer's `addr` label.
    let custody_script = env::var("BTC_CUSTODY_SCRIPT").unwrap_or_else(|_| {
        error!("🚨 CRITICAL [#33]: BTC_CUSTODY_SCRIPT (hex redeem/witness script) is REQUIRED.");
        error!("   The custody scriptPubKey is derived from this script and must");
        error!("   match BTC_MULTISIG_ADDRESS, so deposits are verified against the");
        error!("   script we control — not a trusted indexer address label.");
        std::process::exit(1);
    });
    let custody_type_str = env::var("BTC_CUSTODY_TYPE").unwrap_or_else(|_| "p2wsh".to_string());
    let network_str = env::var("BTC_NETWORK").unwrap_or_else(|_| "mainnet".to_string());

    let custody_type = match CustodyType::parse(&custody_type_str) {
        Ok(t) => t,
        Err(e) => {
            error!("🚨 [#33] Invalid BTC_CUSTODY_TYPE: {}", e);
            std::process::exit(1);
        }
    };
    let network = match Network::parse(&network_str) {
        Ok(n) => n,
        Err(e) => {
            error!("🚨 [#33] Invalid BTC_NETWORK: {}", e);
            std::process::exit(1);
        }
    };
    let custody = match Custody::from_hex_script(&custody_script, custody_type, network) {
        Ok(c) => c,
        Err(e) => {
            error!("🚨 [#33] Failed to build custody from BTC_CUSTODY_SCRIPT: {}", e);
            std::process::exit(1);
        }
    };

    // Boot-time invariant: the address derived from the custody script MUST
    // equal the configured custody address. Refuse to boot on mismatch.
    match custody.derived_address() {
        Ok(derived) => {
            if derived != multisig_address {
                error!("🚨 [#33] CUSTODY MISMATCH — refusing to boot.");
                error!("   BTC_MULTISIG_ADDRESS = {}", multisig_address);
                error!("   derived from script  = {} ({:?}/{:?})", derived, custody_type, network);
                error!("   The configured address is NOT the one this script controls.");
                std::process::exit(1);
            }
            info!(
                "🔒 [#33] Custody verified: {} ({:?}/{:?}), scriptPubKey={}",
                derived,
                custody_type,
                network,
                custody.expected_script_pubkey_hex()
            );
        }
        Err(e) => {
            error!("🚨 [#33] Failed to derive custody address: {}", e);
            std::process::exit(1);
        }
    }

    // Phase 5B.5 / SEC-N02: bridge key MUST come from an encrypted
    // keystore file with an interactive password prompt — never from
    // an env var. Env var private keys are visible in `ps aux`, core
    // dumps, child processes, and system logs. This matches the
    // policy the EVM bridge has enforced since Phase 2.
    let args: Vec<String> = env::args().collect();
    let mut keystore_path: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--keystore" && i + 1 < args.len() {
            keystore_path = Some(args[i + 1].clone());
            i += 2;
        } else {
            i += 1;
        }
    }
    let bridge_key = match keystore_path {
        Some(path) => {
            info!("🔐 Loading BTC bridge key from keystore: {}", path);
            let password = rpassword::prompt_password("Enter BTC bridge keystore password: ")
                .expect("Failed to read password");
            keystore::KeyManager::decrypt(&path, &password)
                .expect("Failed to decrypt BTC bridge keystore")
        }
        None => {
            error!("🚨 CRITICAL [SEC-N02]: --keystore <path> is REQUIRED for BTC bridge.");
            error!("🚨 The previous env-var path (BRIDGE_KEY) is removed because:");
            error!("   - visible in `ps aux`");
            error!("   - leaked via core dumps");
            error!("   - exposed to child processes");
            error!("   - logged in system logs");
            error!("");
            error!("Usage:");
            error!("  btc-bridge --keystore /path/to/bridge-keystore.json");
            std::process::exit(1);
        }
    };

    println!("🌉 BTC Bridge Service Starting...");
    println!("👀 Monitoring BTC Address: {}", multisig_address);
    println!("🔐 Required Confirmations: {}", CONFIRMATIONS);

    let btc = BtcClient::new(multisig_address);
    let aincore = AincoreClient::new(aincore_rpc, bridge_key.to_string());
    let mut db = Storage::new("processed_txs.json");

    loop {
        match btc.get_deposits(CONFIRMATIONS, &custody).await {
            Ok(deposits) => {
                for deposit in deposits {
                    // Audit #33: dedup is PER-OUTPUT ("{txid}:{vout}") so two
                    // custody outputs in one BTC tx are minted independently.
                    let key = deposit.dedup_key();

                    // H-03 (BTC port): is_seen() also covers in-progress
                    // tombstones from a crashed prior run — those entries
                    // must NOT be retried automatically.
                    if db.is_seen(&key) {
                        continue;
                    }

                    println!(
                        "💰 New Deposit Detected: {} sats from output {}",
                        deposit.amount_sats, key
                    );

                    // H-03 fix: tombstone BEFORE mint. If save() fails we
                    // abort the mint attempt entirely — better to be late
                    // than to double-mint after a crash between mint and
                    // mark_completed.
                    if let Err(e) = db.mark_in_progress(key.clone()) {
                        eprintln!(
                            "❌ [H-03] Failed to tombstone output {} before mint; \
                             ABORTING mint to prevent double-mint risk: {}",
                            key, e
                        );
                        continue;
                    }

                    // Attempt the mint. On success: promote tombstone to
                    // Completed. On failure: leave as InProgress so the
                    // operator can investigate; automatic retry is blocked.
                    match aincore
                        .mint_wbtc(&deposit.aincore_address, deposit.amount_sats)
                        .await
                    {
                        Ok(_) => {
                            println!("✅ Minted successfully!");
                            if let Err(e) = db.mark_completed(&key) {
                                eprintln!(
                                    "⚠️  Mint succeeded but mark_completed failed: {} \
                                     (output remains in InProgress; operator must verify)",
                                    e
                                );
                            }
                        }
                        Err(e) => eprintln!(
                            "❌ Minting failed for output {}: {} \
                             (left as InProgress; operator-manual resolution)",
                            key, e
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
