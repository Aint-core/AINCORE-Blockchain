use colored::*;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use rand::rngs::OsRng;
use reqwest::Client;
use serde_json::json;
use std::time::Instant;
use tokio::time::{sleep, Duration};

const RPC_URL: &str = "http://localhost:8002/rpc"; // Target Node 2
const TOTAL_TXS: usize = 1000; // Number of transactions to spam
const BATCH_SIZE: usize = 50; // Parallel requests per batch

#[tokio::main]
async fn main() {
    println!("{}", "🚀 AINCORE TPS Benchmark Tool".bold().cyan());
    println!("{}", "─────────────────────────────────────────────".dimmed());
    println!("Target: {}", RPC_URL);
    println!("Total Transactions: {}", TOTAL_TXS);
    println!("Batch Size: {}", BATCH_SIZE);
    println!("{}", "─────────────────────────────────────────────".dimmed());

    let client = Client::new();

    // 1. Generate Accounts (Parallel Execution needs distinct accounts/objects)
    println!("{} Generating {} keypairs...", "⚙️".yellow(), TOTAL_TXS);
    let mut keypairs = Vec::new();
    for _ in 0..TOTAL_TXS {
        let mut csprng = OsRng;
        let keypair = SigningKey::generate(&mut csprng);
        keypairs.push(keypair);
    }

    // 2. Spam Transactions
    println!("{} Starting Benchmark...", "🔥".red());
    let start_time = Instant::now();
    let pb = ProgressBar::new(TOTAL_TXS as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("#>-"));

    let mut handles = Vec::new();
    
    for (i, kp) in keypairs.iter().enumerate() {
        let client = client.clone();
        // Mock Transaction: Transfer 1 unit to self (or random)
        // In a real scenario, we need a valid signature and nonce.
        // For this benchmark, we assume the node accepts signed payloads.
        
        let pubkey = hex::encode(kp.verifying_key().as_bytes());
        // Simple payload: "transfer:TO_ADDRESS:AMOUNT:NONCE"
        let payload = format!("transfer:{}:1:{}", pubkey, i); 
        let signature = kp.sign(payload.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        let body = json!({
            "jsonrpc": "2.0",
            "method": "send_transaction",
            "params": [{
                "sender": pubkey,
                "input_objects": [],
                "payload": payload,
                "gas_limit": 1000,
                "gas_price": 1,
                "sequence_number": i as u64,
                "signature": sig_hex,
                "paymaster": null, // Optional
                "paymaster_signature": null // Optional
            }],
            "id": i
        });

        let handle = tokio::spawn(async move {
            let _ = client.post(RPC_URL).json(&body).send().await;
        });
        handles.push(handle);

        if handles.len() >= BATCH_SIZE {
            join_all(handles.drain(..)).await;
            pb.inc(BATCH_SIZE as u64);
        }
    }

    // Wait for remaining
    join_all(handles).await;
    pb.finish_with_message("Done");

    let duration = start_time.elapsed();
    let tps = TOTAL_TXS as f64 / duration.as_secs_f64();

    println!("{}", "─────────────────────────────────────────────".dimmed());
    println!("{} Benchmark Complete!", "✅".green());
    println!("Time Elapsed: {:.2?}", duration);
    println!("Throughput: {} TPS", format!("{:.2}", tps).bold().green());
    println!("{}", "─────────────────────────────────────────────".dimmed());
    
    // Note: This measures SUBMISSION TPS. Confirmation TPS requires polling.
    // For "Parallel Execution" verification, high submission acceptance is the first step.
}
