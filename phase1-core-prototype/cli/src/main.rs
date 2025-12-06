mod wallet;
mod client;
mod keys;

use clap::{Parser, Subcommand};
use std::path::Path;
use wallet::Wallet;
use client::RpcClient;
use keys::KeysCmd;
use serde_json::json;
use anyhow::Context;

#[derive(Parser)]
#[command(name = "aincore-cli")]
#[command(about = "AINCORE Blockchain CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// RPC URL of the node
    #[arg(short, long, default_value = "http://127.0.0.1:8001/rpc")]
    rpc: String,

    /// Path to wallet key file
    #[arg(short, long, default_value = "wallet.key")]
    keyfile: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Keygen,
    /// Get node status
    Info,
    /// Submit a DePIN Mining Proof
    SubmitProof {
        /// Device ID
        #[arg(long)]
        device: String,
        /// Breath Quality Index (0-100)
        #[arg(long)]
        quality: u64,
    },
    /// Get account balance/object
    Balance {
        address: Option<String>,
    },
    /// Transfer funds (Real Transaction)
    Transfer {
        to: String,
        amount: u64,
        #[arg(long, default_value = "10000")]
        gas_limit: u64,
    },
    /// Publish a Move module
    Publish {
        path: String,
    },
    /// Manage keys (Encrypted Keystores)
    Keys {
        #[command(subcommand)]
        command: KeysSubcommand,
    },
    /// Register as a Validator (Stakes 1000 AIN)
    RegisterValidator,
}

#[derive(Subcommand)]
enum KeysSubcommand {
    /// Generate a new encrypted keypair
    Generate {
        #[arg(long, default_value = "./keys")]
        out: String,
    },
    /// Import a private key
    Import {
        #[arg(long)]
        priv_key: String,
        #[arg(long, default_value = "./keys")]
        out: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = RpcClient::new(&cli.rpc);

    match cli.command {
        Commands::Keygen => {
            let path = Path::new(&cli.keyfile);
            let wallet = Wallet::load_or_create(path)?;
            println!("🔑 Wallet loaded/created at {:?}", path);
            println!("👤 Address: {}", wallet.address());
        }
        Commands::Info => {
            let res = client.call("aincore_getStatus", json!([]))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Commands::SubmitProof { device, quality } => {
            let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
            let sender = wallet.address();
            
            // Get Seq Number
            let balance_res = client.call("aincore_getBalance", json!([sender]))?;
            let mut sequence_number = 0;
            if let Some(obj) = balance_res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }
            
            println!("📡 Submitting Proof for Device: {} (BQI: {})", device, quality);
            
            let payload = format!("submit_proof:{}:{}", device, quality);
            let seq_num = sequence_number;
            let message = format!("{}:{}", payload, seq_num);
            let signature = wallet.sign(message.as_bytes());
            
            let tx_json = json!({
                "chain_id": "AINCORE-MAINNET-1",
                "sender": sender,
                "public_key": wallet.public_key(),
                "input_objects": [], 
                "payload": payload,
                "gas_limit": 5000,
                "gas_price": 1,
                "sequence_number": seq_num, 
                "signature": signature
            });
            
            let res = client.call("aincore_sendTransaction", json!([tx_json.to_string()]))?;
            println!("✅ Proof Submitted: {}", res);
        }
        Commands::Balance { address } => {
            let addr = if let Some(a) = address {
                a
            } else {
                let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
                wallet.address()
            };
            
            println!("🔍 Checking balance for: {}", addr);
            let res = client.call("aincore_getBalance", json!([addr]))?;
            // println!("{}", serde_json::to_string_pretty(&res)?); // Raw output bad

            let mut balance = 0;
            let mut btc_balance = 0;
            if let Some(obj) = res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect();
                    // Attempt to decode as generic Value first to find "balance" fields
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(b) = account_data.get("balance").and_then(|v| v.as_u64()) {
                            balance = b;
                        }
                        if let Some(btc) = account_data.get("btc_balance").and_then(|v| v.as_u64()) {
                            btc_balance = btc;
                        }
                    }
                }
            }
            
            // Print in a grep-friendly format for the script
            println!("{{ \"balance\": {}, \"btc_balance\": {} }}", balance, btc_balance);
        }
        Commands::Transfer { to, amount, gas_limit } => {
            let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
            let sender = wallet.address();
            
            println!("🔍 Checking balance for sender: {}", sender);
            let balance_res = client.call("aincore_getBalance", json!([sender]))?;
            
            let mut current_balance = 0;
            let mut sequence_number = 0;

            if let Some(obj) = balance_res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        current_balance = account_data["balance"].as_u64().unwrap_or(0);
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }

            let gas_price = 1;
            let total_cost = amount + (gas_limit * gas_price);

            if current_balance < total_cost {
                anyhow::bail!("❌ Insufficient balance! Have: {}, Need: {} (Amount: {} + Gas: {})", 
                    current_balance, total_cost, amount, gas_limit * gas_price);
            }

            println!("✅ Balance verified: {} (Seq: {})", current_balance, sequence_number);
            println!("💸 Sending {} from {} to {} (Gas Limit: {})", amount, sender, to, gas_limit);
            
            // Construct payload
            let payload = format!("transfer:{}:{}", to, amount);
            let seq_num = sequence_number; // Use current seq number (Executor expects match)
            let message = format!("{}:{}", payload, seq_num);
            let signature = wallet.sign(message.as_bytes());
            
            // Construct Transaction JSON
            // Note: In Account-Based model, input_objects is empty for native coin transfers.
            // The dependency is implied by the sender address.
            let tx_json = json!({
                "chain_id": "AINCORE-MAINNET-1",
                "sender": sender,
                "public_key": wallet.public_key(),
                "input_objects": [], 
                "payload": payload,
                "gas_limit": gas_limit,
                "gas_price": gas_price,
                "sequence_number": seq_num, 
                "signature": signature
            });
            
            let tx_str = tx_json.to_string();
            let res = client.call("aincore_sendTransaction", json!([tx_str]))?;
            println!("✅ Transaction submitted: {}", res);
        }
        Commands::Publish { path } => {
            let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
            let sender = wallet.address();
            let source_path = Path::new(&path);
            
            println!("📦 Publishing module from: {:?}", source_path);

            // 1. Compile using move_compiler_tool
            // We assume the tool is in the same target dir or accessible via PATH
            // For dev environment, we look in ../../target/debug/
            let compiler_tool = "../../target/debug/move_compiler_tool";
            let output_dir = "temp_build";
            
            // Path to Stdlib sources (Hardcoded for dev environment)
            let stdlib_path = "../vm_move/stdlib/sources";
            
            // Clean/Create temp dir
            if Path::new(output_dir).exists() {
                std::fs::remove_dir_all(output_dir)?;
            }
            std::fs::create_dir(output_dir)?;

            println!("   Compiling...");
            
            // Collect all .move files from stdlib
            let mut cmd = std::process::Command::new(compiler_tool);
            cmd.arg("--sources").arg(path);
            
            // Add stdlib files
            if let Ok(entries) = std::fs::read_dir(stdlib_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("move") {
                        cmd.arg(path);
                    }
                }
            }

            let status = cmd
                .arg("--output")
                .arg(output_dir)
                .status()
                .context("Failed to execute move_compiler_tool. Make sure it is built.")?;

            if !status.success() {
                anyhow::bail!("Compilation failed.");
            }

            // 2. Read compiled bytecode
            // Find the .mv file in output_dir
            let mut bytecode = Vec::new();
            for entry in std::fs::read_dir(output_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("mv") {
                    println!("   Found compiled module: {:?}", path);
                    bytecode = std::fs::read(path)?;
                    break; // Only support single module publish for now
                }
            }

            if bytecode.is_empty() {
                anyhow::bail!("No compiled module found in output directory.");
            }

            // 3. Construct Payload
            let bytecode_hex = hex::encode(bytecode);
            let payload = format!("publish:{}", bytecode_hex);
            let signature = wallet.sign(payload.as_bytes());

            // 4. Send Transaction
            let tx_json = json!({
                "chain_id": "AINCORE-MAINNET-1",
                "sender": sender,
                "public_key": wallet.public_key(),
                "input_objects": [],
                "payload": payload,
                "gas_limit": 50000, // Higher limit for publish
                "gas_price": 1,
                "signature": signature
            });
            
            let tx_str = tx_json.to_string();
            let res = client.call("aincore_sendTransaction", json!([tx_str]))?;
            println!("✅ Publish Transaction submitted: {}", res);
            
            // Cleanup
            std::fs::remove_dir_all(output_dir)?;
        }
        Commands::Keys { command } => match command {
            KeysSubcommand::Generate { out } => {
                KeysCmd::generate(&out)?;
            }
            KeysSubcommand::Import { priv_key, out } => {
                KeysCmd::import(&priv_key, &out)?;
            }
        }
        Commands::RegisterValidator => {
            let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
            let sender = wallet.address();
            
            println!("🔒 Registering Validator for address: {}", sender);
            
            // Check Balance
            let res = client.call("aincore_getBalance", json!([sender]))?;
            let mut current_balance = 0;
            let mut sequence_number = 0;
            if let Some(obj) = res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        current_balance = account_data["balance"].as_u64().unwrap_or(0);
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }
            
            let required_stake: u128 = 1000 * 1_000_000_000_000_000_000;
            if u128::from(current_balance) < required_stake {
                anyhow::bail!("❌ Insufficient Balance! Need 1000 AIN. You have: {}", current_balance);
            }
            
            let payload = "register_validator".to_string();
            let message = format!("{}:{}", payload, sequence_number);
            let signature = wallet.sign(message.as_bytes());
            
            let tx_json = json!({
                "chain_id": "AINCORE-MAINNET-1",
                "sender": sender,
                "public_key": wallet.public_key(),
                "input_objects": [],
                "payload": payload,
                "gas_limit": 50000,
                "gas_price": 1,
                "sequence_number": sequence_number,
                "signature": signature
            });
            
            let res = client.call("aincore_sendTransaction", json!([tx_json.to_string()]))?;
            println!("✅ Validator Registration Submitted: {}", res);
        }
    }

    Ok(())
}
