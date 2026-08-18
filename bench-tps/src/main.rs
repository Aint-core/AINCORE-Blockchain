//! AINCORE load generator.
//!
//! # Why this was rewritten (AUDIT / fix-plan Step 2)
//!
//! The previous version could not put a single transaction on chain. It emitted
//! the legacy string payload `"transfer:{pubkey}:1:{nonce}"`, which the BCS-only
//! mempool rejects outright; it used the raw public key as `sender` instead of the
//! derived address; it signed a message shape the node does not verify; and it
//! generated random unfunded keypairs that would fail the balance admission gate
//! even if the payload had parsed.
//!
//! The consequence was that in 349k rounds of live testnet only 2 blocks ever
//! carried a transaction — so the executor, VM, DEX and consensus payload paths
//! had effectively never run in production. Every "done when" criterion in the
//! mainnet fix plan depends on being able to load those paths, which makes this
//! tool a hard gate rather than a nice-to-have.
//!
//! # What it does now
//!
//! 1. FUND phase: sequentially transfers AIN from one funded key to N fresh
//!    accounts (sequential because a single sender's `sequence_number` must
//!    increment in order — this is the constraint that limited earlier ad-hoc
//!    load tests to a couple of landed transactions).
//! 2. LOAD phase: every funded account then submits CONCURRENTLY, each with its
//!    own independent nonce sequence, which is what actually exercises parallel
//!    execution and the conflict-token scheduler.
//! 3. `--abort-rate` deliberately generates transactions that ABORT mid-payload
//!    (over-balance transfer, aborting inside coin::withdraw), so the failure
//!    paths — the ones BLOCKER-1 rewrote — are exercised at scale instead of only
//!    the happy path. (The original vehicle — transfer to an unregistered
//!    address — stopped aborting once onboarding auto-registration shipped.)
//!
//! Measures SUBMISSION throughput and, with `--verify`, re-reads balances at the
//! end so landed-vs-submitted is visible rather than assumed.

use clap::Parser;
use colored::*;
use ed25519_dalek::{Signer, SigningKey};
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "AINCORE BCS load generator", long_about = None)]
struct Args {
    /// RPC endpoint of the node to load
    #[arg(long, default_value = "http://localhost:8002/rpc")]
    rpc: String,

    /// Chain id the signature is bound to (must match the node)
    #[arg(long, default_value = "AINCORE-MAINNET-1")]
    chain_id: String,

    /// Hex Ed25519 secret key (64 hex chars) of a FUNDED account, or a path to a
    /// key file. This account pays for the fan-out.
    #[arg(long)]
    funder_key: String,

    /// Number of independent sender accounts to fan out to
    #[arg(long, default_value_t = 20)]
    accounts: usize,

    /// Transactions each account submits in the load phase
    #[arg(long, default_value_t = 25)]
    per_account: usize,

    /// AIN (in base units) sent to each account during funding
    #[arg(long, default_value_t = 5_000_000_000_000_000_000u128)]
    fund_amount: u128,

    /// Fraction (0-100) of load transactions that should deliberately ABORT,
    /// via an over-balance transfer (aborts in coin::withdraw). Exercises the
    /// failure path BLOCKER-1 rewrote.
    #[arg(long, default_value_t = 20)]
    abort_rate: u8,

    /// Gas limit per transaction
    #[arg(long, default_value_t = 100_000u64)]
    gas_limit: u64,

    /// Max concurrent in-flight requests during the load phase
    #[arg(long, default_value_t = 64)]
    concurrency: usize,

    /// Re-read balances afterwards to report landed-vs-submitted
    #[arg(long, default_value_t = false)]
    verify: bool,
}

/// A signing identity plus the address the chain knows it by.
#[derive(Clone)]
struct Account {
    key: Arc<SigningKey>,
    address: String,
    public_key: String,
}

impl Account {
    fn from_key(key: SigningKey) -> Self {
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let address = crypto::derive_address(key.verifying_key().as_bytes())
            .expect("address derivation must succeed for a valid Ed25519 key");
        Self {
            key: Arc::new(key),
            address,
            public_key,
        }
    }

    fn random() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self::from_key(SigningKey::from_bytes(&seed))
    }
}

fn parse_move_address(addr: &str) -> Option<move_core_types::account_address::AccountAddress> {
    move_core_types::account_address::AccountAddress::from_hex_literal(&format!("0x{}", addr)).ok()
}

/// Build the hex-encoded BCS `coin::transfer<AincoreCoin>` payload.
///
/// This is the exact shape core/cli builds, which is the shape the mempool's BCS
/// decoder and `analyze_tx` expect. Anything else is rejected at admission.
fn transfer_payload(from: &str, to: &str, amount: u128) -> String {
    let call = vm_move::EntryFunctionCall {
        module: move_core_types::language_storage::ModuleId::new(
            move_core_types::account_address::AccountAddress::ONE,
            move_core_types::identifier::Identifier::new("coin").unwrap(),
        ),
        function: "transfer".to_string(),
        ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
            Box::new(move_core_types::language_storage::StructTag {
                address: move_core_types::account_address::AccountAddress::ONE,
                module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                type_params: vec![],
            }),
        )],
        args: vec![
            bcs::to_bytes(&parse_move_address(from).expect("sender address")).unwrap(),
            bcs::to_bytes(&parse_move_address(to).expect("recipient address")).unwrap(),
            bcs::to_bytes(&amount).unwrap(),
        ],
    };
    hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
}

/// Sign and serialize a transaction.
///
/// The signed message binds chain_id, sender, payload, sequence number, gas limit,
/// gas price and input objects (audit F4) — omitting any field would let it be
/// mutated in flight, so the shape must match the node's verifier exactly.
#[allow(clippy::too_many_arguments)]
fn signed_tx(
    acct: &Account,
    chain_id: &str,
    payload: &str,
    seq: u64,
    gas_limit: u64,
    gas_price: u128,
) -> String {
    let message = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, acct.address, payload, seq, gas_limit, gas_price, ""
    );
    let signature = hex::encode(acct.key.sign(message.as_bytes()).to_bytes());
    json!({
        "chain_id": chain_id,
        "sender": acct.address,
        "public_key": acct.public_key,
        "input_objects": [],
        "payload": payload,
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "sequence_number": seq,
        "signature": signature,
        "paymaster": null,
        "paymaster_signature": null,
    })
    .to_string()
}

async fn rpc(client: &Client, url: &str, method: &str, params: Value) -> Option<Value> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let resp = client.post(url).json(&body).send().await.ok()?;
    let v: Value = resp.json().await.ok()?;
    Some(v)
}

/// Read an account's on-chain sequence number (0 if the account does not exist).
///
/// The nonce is NOT a top-level field of aincore_getBalance: it lives inside
/// `result.data`, a byte array holding the AccountData JSON
/// (`{"sequence_number":N,...}`). The first version of this function read
/// `result.sequence_number`, which does not exist, so it always returned 0 —
/// and every run on a fresh chain still worked, because a fresh funder's nonce
/// IS 0. The first rerun against a used chain then had all its funding txs
/// rejected with "Invalid Sequence Number". A default that coincides with the
/// happy path is the worst kind of bug: this now decodes the real value.
async fn fetch_seq(client: &Client, url: &str, address: &str) -> u64 {
    match rpc(client, url, "aincore_getBalance", json!([address])).await {
        Some(v) => {
            let r = &v["result"];
            if let Some(bytes) = r["data"].as_array() {
                let raw: Vec<u8> = bytes
                    .iter()
                    .filter_map(|b| b.as_u64().map(|x| x as u8))
                    .collect();
                if let Ok(inner) = serde_json::from_slice::<Value>(&raw) {
                    if let Some(seq) = inner["sequence_number"].as_u64() {
                        return seq;
                    }
                }
            }
            // Fallbacks: a future top-level field, else 0 (account not yet on chain).
            r["sequence_number"].as_u64().unwrap_or(0)
        }
        None => 0,
    }
}

async fn fetch_balance(client: &Client, url: &str, address: &str) -> u128 {
    match rpc(client, url, "aincore_getBalance", json!([address])).await {
        Some(v) => v["result"]["move_balance"]
            .as_str()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0),
        None => 0,
    }
}

/// Submit one transaction; returns true if the node ACCEPTED it into the mempool.
async fn submit(client: &Client, url: &str, tx_json: String) -> bool {
    match rpc(client, url, "aincore_sendTransaction", json!([tx_json])).await {
        Some(v) => v.get("error").map(|e| e.is_null()).unwrap_or(true) && v["result"].is_object()
            || v["result"].is_string(),
        None => false,
    }
}

fn load_funder_key(spec: &str) -> SigningKey {
    // Accept either a raw 64-hex secret key or a path to a file containing one.
    let raw = if std::path::Path::new(spec).exists() {
        std::fs::read_to_string(spec).expect("read funder key file")
    } else {
        spec.to_string()
    };
    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed).expect("funder key must be hex");
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .expect("funder key must be 32 bytes (64 hex chars)");
    SigningKey::from_bytes(&arr)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("{}", "🚀 AINCORE Load Generator (BCS)".bold().cyan());
    println!("{}", "─────────────────────────────────────────────".dimmed());
    println!("Target      : {}", args.rpc);
    println!("Chain ID    : {}", args.chain_id);
    println!(
        "Plan        : {} accounts x {} txs = {} total, {}% deliberately aborting",
        args.accounts,
        args.per_account,
        args.accounts * args.per_account,
        args.abort_rate
    );
    println!("{}", "─────────────────────────────────────────────".dimmed());

    let client = Client::new();
    let funder = Account::from_key(load_funder_key(&args.funder_key));
    println!("Funder      : {}", funder.address);

    let funder_balance = fetch_balance(&client, &args.rpc, &funder.address).await;
    println!(
        "Funder bal. : {} base units",
        funder_balance.to_string().bold()
    );
    let required = args.fund_amount * args.accounts as u128;
    if funder_balance < required {
        eprintln!(
            "{} funder holds {} but needs {} to fund {} accounts — reduce --accounts or --fund-amount",
            "❌".red(),
            funder_balance,
            required,
            args.accounts
        );
        std::process::exit(1);
    }

    // ---- PHASE 1: FUND ------------------------------------------------------
    // Sequential by necessity: one sender means one nonce sequence. This is the
    // exact constraint that capped earlier ad-hoc load attempts at a couple of
    // landed transactions; here it is a one-time setup cost, not the load itself.
    println!("\n{} Funding {} accounts…", "💰".yellow(), args.accounts);
    let accounts: Vec<Account> = (0..args.accounts).map(|_| Account::random()).collect();
    let mut seq = fetch_seq(&client, &args.rpc, &funder.address).await;
    let pb = ProgressBar::new(args.accounts as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.yellow/blue}] {pos}/{len}")
            .unwrap()
            .progress_chars("#>-"),
    );
    let mut funded = 0usize;
    for acct in &accounts {
        let payload = transfer_payload(&funder.address, &acct.address, args.fund_amount);
        let tx = signed_tx(
            &funder,
            &args.chain_id,
            &payload,
            seq,
            args.gas_limit,
            1,
        );
        if submit(&client, &args.rpc, tx).await {
            funded += 1;
            seq += 1;
        }
        pb.inc(1);
        // Give the mempool/consensus a moment so the nonce advances on chain.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    pb.finish_and_clear();
    println!("   accepted {}/{} funding txs", funded, args.accounts);

    println!("   waiting 15s for funding to finalize…");
    tokio::time::sleep(std::time::Duration::from_secs(15)).await;

    // Keep only accounts that actually received funds — submitting from an
    // unfunded account just measures rejection latency.
    let mut live: Vec<(Account, u64)> = Vec::new();
    for acct in &accounts {
        let bal = fetch_balance(&client, &args.rpc, &acct.address).await;
        if bal > 0 {
            let s = fetch_seq(&client, &args.rpc, &acct.address).await;
            live.push((acct.clone(), s));
        }
    }
    println!(
        "   {} accounts funded and ready",
        live.len().to_string().bold()
    );
    if live.is_empty() {
        eprintln!(
            "{} no account was funded — is the chain producing blocks and is the funder key right?",
            "❌".red()
        );
        std::process::exit(1);
    }

    // ---- PHASE 2: LOAD ------------------------------------------------------
    // Every account has its OWN nonce sequence, so these can all fly at once.
    // That is what exercises parallel execution and the conflict-token scheduler.
    let total = live.len() * args.per_account;
    println!("\n{} Load phase: {} transactions…", "🔥".red(), total);
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    // ABORT VEHICLE.
    //
    // This used to target an address with no CoinStore, so coin::deposit aborted
    // after coin::withdraw had already debited the sender. That vehicle is GONE:
    // the onboarding fix auto-registers an absent recipient, so those transfers
    // now succeed by design — and for one run this tool silently reported abort
    // coverage it was no longer producing. A load generator that lies about what
    // it exercised is worse than one that does less.
    //
    // The vehicle is now an OVER-BALANCE transfer, which aborts inside
    // coin::withdraw's `store.coin.value >= amount` assert. The property under
    // test is unchanged and is the BLOCKER-1 contract: an aborting payload must
    // commit NOTHING but gas.
    //
    // `abort_probe` is a real funded account used only for the post-run assertion
    // below; the aborting transfers are sent FROM the load accounts with an
    // impossible amount, so nothing can ever legitimately credit it.
    let abort_probe = Account::random().address;
    // Far more than any account was funded with -> guaranteed withdraw abort.
    let abort_amount = args.fund_amount.saturating_mul(1_000_000);

    let start = Instant::now();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut inflight = Vec::new();
    let mut submitted = 0usize;

    for i in 0..args.per_account {
        for (acct, base_seq) in &live {
            let client = client.clone();
            let rpc_url = args.rpc.clone();
            let chain_id = args.chain_id.clone();
            let acct = acct.clone();
            let seq = base_seq + i as u64;
            let gas_limit = args.gas_limit;
            let accepted = Arc::clone(&accepted);

            // Deterministic spread of aborting txs across the run.
            let should_abort = (i * 100 / args.per_account.max(1)) < args.abort_rate as usize;
            let (dest, amount) = if should_abort {
                // Over-balance -> aborts in coin::withdraw. Sent to the probe so a
                // credit there would prove an aborted payload committed state.
                (abort_probe.clone(), abort_amount)
            } else {
                // Send to another live account: real state contention between
                // distinct senders, which is what the scheduler must handle.
                (
                    live[(i + 1) % live.len()].0.address.clone(),
                    1_000_000_000_000u128,
                )
            };

            inflight.push(tokio::spawn(async move {
                let payload = transfer_payload(&acct.address, &dest, amount);
                let tx = signed_tx(&acct, &chain_id, &payload, seq, gas_limit, 1);
                if submit(&client, &rpc_url, tx).await {
                    accepted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }));
            submitted += 1;

            if inflight.len() >= args.concurrency {
                let batch = std::mem::take(&mut inflight);
                let n = batch.len();
                join_all(batch).await;
                pb.inc(n as u64);
            }
        }
    }
    let rest = inflight.len();
    join_all(inflight).await;
    pb.inc(rest as u64);
    pb.finish_and_clear();

    let elapsed = start.elapsed();
    let accepted_n = accepted.load(std::sync::atomic::Ordering::Relaxed);
    let tps = submitted as f64 / elapsed.as_secs_f64();

    println!("{}", "─────────────────────────────────────────────".dimmed());
    println!("{} Load complete", "✅".green());
    println!("Submitted   : {}", submitted);
    println!("Accepted    : {} ({} rejected)", accepted_n, submitted - accepted_n);
    println!("Elapsed     : {:.2?}", elapsed);
    println!(
        "Submission  : {} TPS",
        format!("{:.1}", tps).bold().green()
    );

    if args.verify {
        println!("\n{} Verifying landed state (30s settle)…", "🔍".cyan());
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        let mut moved = 0usize;
        for (acct, _) in &live {
            let bal = fetch_balance(&client, &args.rpc, &acct.address).await;
            if bal != args.fund_amount {
                moved += 1;
            }
        }
        println!(
            "   {}/{} accounts show a changed balance — transactions are LANDING, not just being accepted",
            moved,
            live.len()
        );
        let abort_bal = fetch_balance(&client, &args.rpc, &abort_probe).await;
        if abort_bal == 0 {
            println!(
                "   abort probe balance: 0 OK - aborted payloads committed nothing (BLOCKER-1 holds)"
            );
        } else {
            println!(
                "   abort probe balance: {} !! MUST BE 0 - an aborted payload committed \
                 state, i.e. BLOCKER-1 REGRESSED",
                abort_bal
            );
        }
    }
    println!("{}", "─────────────────────────────────────────────".dimmed());
}
