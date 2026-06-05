fn parse_move_address(hex_str: &str) -> Option<move_core_types::account_address::AccountAddress> {
    let hex_str = hex_str.trim_start_matches("0x");
    let mut bytes = [0u8; 16];
    if hex_str.len() != 32 {
        return None;
    }
    match hex::decode_to_slice(hex_str, &mut bytes) {
        Ok(_) => Some(move_core_types::account_address::AccountAddress::new(bytes)),
        Err(_) => None,
    }
}

mod client;
mod keys;
mod wallet;

use anyhow::Context;
use clap::{Parser, Subcommand};
use client::RpcClient;
use keys::KeysCmd;
use serde_json::json;
use sha2::Digest;
use std::path::Path;
use wallet::Wallet;

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
    /// Generate a post-quantum keypair (Dilithium5)
    PqcKeygen {
        /// Output directory for keys
        #[arg(long, default_value = "./pqc_keys")]
        out: String,
    },
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
    Balance { address: Option<String> },
    /// Transfer funds (Real Transaction)
    Transfer {
        to: String,
        amount: u64,
        #[arg(long, default_value = "10000")]
        gas_limit: u64,
    },
    /// Publish a Move module
    Publish { path: String },
    /// Manage keys (Encrypted Keystores)
    Keys {
        #[command(subcommand)]
        command: KeysSubcommand,
    },
    /// Register as a Validator (Stakes 1000 AIN)
    RegisterValidator,
    /// Distribute AIN from Genesis (Testnet Faucet)
    Faucet {
        /// Recipient address
        to: String,
        /// Amount in AIN (whole units)
        amount: u64,
    },
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
            println!("Wallet loaded/created at {:?}", path);
            println!("Address: {}", wallet.address());
            println!("Public Key: {}", wallet.public_key());
        }
        Commands::PqcKeygen { out } => {
            use pqcrypto_dilithium::dilithium5;
            use pqcrypto_traits::sign::{PublicKey, SecretKey};

            // Create output directory
            std::fs::create_dir_all(&out)?;

            // Generate Dilithium5 keypair
            let (pk, sk) = dilithium5::keypair();

            // Get bytes
            let pk_bytes = pk.as_bytes();
            let sk_bytes = sk.as_bytes();

            // Derive address (first 16 bytes of SHA256 hash of public key)
            let pk_hash = sha2::Sha256::digest(pk_bytes);
            let address = hex::encode(&pk_hash[..16]);

            // Save files
            let pk_path = format!("{}/pqc_pubkey.bin", out);
            let sk_path = format!("{}/pqc_privkey.bin", out);
            let addr_path = format!("{}/pqc_address.txt", out);

            std::fs::write(&pk_path, pk_bytes)?;
            std::fs::write(&sk_path, sk_bytes)?;
            std::fs::write(&addr_path, &address)?;

            println!("Post-Quantum Keypair Generated (Dilithium5)");
            println!("Public Key:  {} ({} bytes)", pk_path, pk_bytes.len());
            println!("Private Key: {} ({} bytes)", sk_path, sk_bytes.len());
            println!("Address:     {}", address);
            println!();
            println!("SECURITY: Keep pqc_privkey.bin secure!");
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
                    let bytes: Vec<u8> = data_bytes
                        .iter()
                        .map(|b| b.as_u64().unwrap_or(0) as u8)
                        .collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }

            println!(
                "📡 Submitting Proof for Device: {} (BQI: {})",
                device, quality
            );

            let device_bytes = hex::decode(&device).unwrap_or_else(|_| device.as_bytes().to_vec());
            let call = vm_move::EntryFunctionCall {
                module: move_core_types::language_storage::ModuleId::new(
                    move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    move_core_types::identifier::Identifier::new("universal_mining").unwrap(),
                ),
                function: "submit_mining_proof".to_string(),
                ty_args: vec![],
                args: vec![
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&device_bytes).unwrap(),
                    bcs::to_bytes(&{ quality }).unwrap(),
                ],
            };
            let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            let seq_num = sequence_number;
            // PROTOCOL UPDATE: Chain Binding
            // F4: signature must cover gas_limit, gas_price, input_objects.
            // input_objects=[] here, gas_limit=5000, gas_price=1 (must match tx_json below).
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                "AINCORE-MAINNET-1", sender, payload, seq_num, 5000u64, 1u128, ""
            );
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

            let mut balance = "0".to_string();
            let mut btc_balance = 0;
            if let Some(obj) = res.as_object() {
                if let Some(move_balance) = obj.get("move_balance").and_then(|v| v.as_str()) {
                    balance = move_balance.to_string();
                }
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes
                        .iter()
                        .map(|b| b.as_u64().unwrap_or(0) as u8)
                        .collect();
                    // AccountData now stores metadata; keep btc_balance read for bridge tooling.
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(btc) = account_data.get("btc_balance").and_then(|v| v.as_u64())
                        {
                            btc_balance = btc;
                        }
                    }
                }
            }

            // Print in a grep-friendly format for the script
            println!(
                "{{ \"balance\": \"{}\", \"btc_balance\": {} }}",
                balance, btc_balance
            );
        }
        Commands::Transfer {
            to,
            amount,
            gas_limit,
        } => {
            let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
            let sender = wallet.address();

            println!("🔍 Loading sender metadata: {}", sender);
            let balance_res = client.call("aincore_getBalance", json!([sender]))?;

            let mut sequence_number = 0;

            if let Some(obj) = balance_res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes
                        .iter()
                        .map(|b| b.as_u64().unwrap_or(0) as u8)
                        .collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }

            println!("✅ Sender metadata loaded (Seq: {})", sequence_number);
            println!(
                "💸 Sending {} from {} to {} (Gas Limit: {})",
                amount, sender, to, gas_limit
            );

            // Construct payload
            let call = vm_move::EntryFunctionCall {
                module: move_core_types::language_storage::ModuleId::new(
                    move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    move_core_types::identifier::Identifier::new("coin").unwrap(),
                ),
                function: "transfer".to_string(),
                ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                    Box::new(move_core_types::language_storage::StructTag {
                        address: move_core_types::account_address::AccountAddress::new([
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ]),
                        module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                        name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                        type_params: vec![],
                    }),
                )],
                args: vec![
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&parse_move_address(&to).unwrap()).unwrap(),
                    bcs::to_bytes(&(amount as u128)).unwrap(),
                ],
            };
            let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            let seq_num = sequence_number; // Use current seq number (Executor expects match)
            let gas_price = 1;
            // PROTOCOL UPDATE: Chain Binding
            // F4: bind gas_limit/gas_price/input_objects. input_objects=[] for native transfer.
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                "AINCORE-MAINNET-1", sender, payload, seq_num, gas_limit, gas_price, ""
            );
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

            let bytes = hex::decode(&bytecode_hex).expect("invalid hex in publish command");
            let payload_struct = vm_move::TransactionPayload::PublishModule(vec![bytes]);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            let balance_res = client.call("aincore_getBalance", json!([sender]))?;
            let mut sequence_number = 0;
            if let Some(obj) = balance_res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes
                        .iter()
                        .map(|b| b.as_u64().unwrap_or(0) as u8)
                        .collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }
            // F4: bind gas_limit/gas_price/input_objects (publish uses gas_limit 50000).
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                "AINCORE-MAINNET-1", sender, payload, sequence_number, 50000u64, 1u128, ""
            );
            let signature = wallet.sign(message.as_bytes());

            // 4. Send Transaction
            let tx_json = json!({
                "chain_id": "AINCORE-MAINNET-1",
                "sender": sender,
                "public_key": wallet.public_key(),
                "input_objects": [],
                "payload": payload,
                "gas_limit": 50000, // Higher limit for publish
                "gas_price": 1,
                "sequence_number": sequence_number,
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
        },
        Commands::RegisterValidator => {
            let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
            let sender = wallet.address();

            println!("🔒 Registering Validator for address: {}", sender);

            // Check Balance
            let res = client.call("aincore_getBalance", json!([sender]))?;
            let mut sequence_number = 0;
            if let Some(obj) = res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes
                        .iter()
                        .map(|b| b.as_u64().unwrap_or(0) as u8)
                        .collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }

            // Skipping client-side balance check due to u64 parsing limitations in CLI for u128 balances

            let pk_bytes = hex::decode(wallet.public_key()).unwrap_or_default();
            let min_stake: u128 = 1_000_000_000_000_000_000_000; // 1000 AIN in quanta (smallest unit, 10^18)
            let call = vm_move::EntryFunctionCall {
                module: move_core_types::language_storage::ModuleId::new(
                    move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    move_core_types::identifier::Identifier::new("staking").unwrap(),
                ),
                function: "join_validator_set".to_string(),
                ty_args: vec![],
                args: vec![
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&min_stake).unwrap(),
                    bcs::to_bytes(&pk_bytes).unwrap(),
                ],
            };
            let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            // PROTOCOL UPDATE: Chain Binding
            // F4: bind gas_limit/gas_price/input_objects (register uses gas_limit 50000).
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                "AINCORE-MAINNET-1", sender, payload, sequence_number, 50000u64, 1u128, ""
            );
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
        Commands::Faucet { to, amount } => {
            let wallet = Wallet::load_or_create(Path::new(&cli.keyfile))?;
            let sender = wallet.address();

            println!("🚰 Faucet: Sending {} AIN to {}", amount, to);

            // Get sequence number
            let res = client.call("aincore_getBalance", json!([sender]))?;
            let mut sequence_number = 0;
            if let Some(obj) = res.as_object() {
                if let Some(data_bytes) = obj.get("data").and_then(|v| v.as_array()) {
                    let bytes: Vec<u8> = data_bytes
                        .iter()
                        .map(|b| b.as_u64().unwrap_or(0) as u8)
                        .collect();
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        sequence_number = account_data["sequence_number"].as_u64().unwrap_or(0);
                    }
                }
            }

            // Convert AIN to quanta (AINCORE smallest unit, 18 decimals).
            // 1 AIN = 10^18 quanta.
            let amount_quanta: u128 = amount as u128 * 1_000_000_000_000_000_000;
            let call = vm_move::EntryFunctionCall {
                module: move_core_types::language_storage::ModuleId::new(
                    move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    move_core_types::identifier::Identifier::new("coin").unwrap(),
                ),
                function: "transfer".to_string(),
                ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                    Box::new(move_core_types::language_storage::StructTag {
                        address: move_core_types::account_address::AccountAddress::new([
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                        ]),
                        module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                        name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                        type_params: vec![],
                    }),
                )],
                args: vec![
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&parse_move_address(&to).unwrap()).unwrap(),
                    bcs::to_bytes(&amount_quanta).unwrap(),
                ],
            };
            let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            // F4: bind gas_limit/gas_price/input_objects (faucet uses gas_limit 50000).
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                "AINCORE-MAINNET-1", sender, payload, sequence_number, 50000u64, 1u128, ""
            );
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
            println!("✅ Faucet Transaction Submitted: {}", res);
        }
    }

    Ok(())
}
