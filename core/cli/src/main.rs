/// Accepts `A1n…` (checksum enforced), 64-hex or `0x` + 64-hex.
fn parse_move_address(input: &str) -> Option<move_core_types::account_address::AccountAddress> {
    crypto::parse_address(input)
        .ok()
        .map(move_core_types::account_address::AccountAddress::new)
}

/// Like `parse_move_address`, but says why an address was refused (a typo in
/// an `A1n` address fails its checksum instead of paying a stranger).
fn require_address_hex(input: &str) -> anyhow::Result<String> {
    crypto::canonical_address_hex(input)
        .map_err(|e| anyhow::anyhow!("invalid address {:?}: {}", input.trim(), e))
}

fn a1n(hex_address: &str) -> String {
    crypto::hex_to_a1n(hex_address).unwrap_or_else(|_| hex_address.to_string())
}

fn derive_validator_bls_identity(wallet: &Wallet) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"AINCORE_VALIDATOR_BLS_V1");
    hasher.update(wallet.ed25519_secret()?);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    let bls = crypto::bls::BLSEngine::consensus();
    Ok((bls.pubkey_raw(&seed), bls.prove_possession_raw(&seed)))
}

/// The spending wallet: the ML-DSA-65 seed given with `--pqc-seed`, or else
/// the Ed25519 key file.
fn load_wallet(pqc_seed: &Option<String>, keyfile: &str) -> anyhow::Result<Wallet> {
    match pqc_seed {
        Some(seed) => Wallet::load_ml_dsa_65(Path::new(seed)),
        None => Wallet::load_or_create(Path::new(keyfile)),
    }
}

/// A signed transaction carrying `payload`: priced at the node's base fee
/// (B15), with `execution` gas on top of the intrinsic byte gas its own size
/// owes (B14), signed over the seven fields (F4) by `wallet`. B65: without
/// `execution`, the node runs the transaction and answers what it would use,
/// the state its writes add included (`aincore_estimateGas`).
fn signed_tx_json(
    client: &RpcClient,
    wallet: &Wallet,
    chain_id: &str,
    payload: String,
    sequence_number: u64,
    execution: Option<u64>,
) -> anyhow::Result<String> {
    let price = client.call("aincore_getGasPrice", json!([]))?;
    let gas_price: u128 = match &price {
        serde_json::Value::String(s) => s.parse()?,
        serde_json::Value::Number(n) => n.as_u64().map(u128::from).unwrap_or(1),
        _ => anyhow::bail!("unexpected aincore_getGasPrice answer: {price}"),
    };
    let mut tx = executor::Transaction {
        chain_id: chain_id.to_string(),
        sender: wallet.address(),
        input_objects: vec![],
        payload,
        args: vec![],
        gas_limit: 0,
        gas_price,
        sequence_number,
        public_key: wallet.public_key(),
        // The signature's own size counts: a placeholder of the same length.
        signature: wallet.sign(b"size"),
        paymaster: None,
        paymaster_signature: None,
        zkp_proof: None,
    };
    let unsized_len = serde_json::to_string(&tx)?.len();
    let execution = match execution {
        Some(gas) => gas,
        None => {
            let answer = client.call("aincore_estimateGas", json!([serde_json::to_value(&tx)?]))?;
            answer["execution_gas"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("unexpected aincore_estimateGas answer: {answer}"))?
        }
    };
    tx.gas_limit = executor::admission::gas_limit_covering(unsized_len, execution);
    tx.signature = wallet.sign(executor::admission::signing_message(&tx).as_bytes());
    Ok(serde_json::to_string(&tx)?)
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

    /// Sign with this ML-DSA-65 seed file (from `pqc-keygen`) instead of the
    /// Ed25519 key file
    #[arg(long)]
    pqc_seed: Option<String>,

    /// Chain ID used in signed transactions (or AINCORE_CHAIN_ID env)
    #[arg(long, default_value = "AINCORE-MAINNET-1")]
    chain_id: String,

    /// Execution gas for every signed transaction; the node's estimate
    /// (`aincore_estimateGas`) when not given (B65)
    #[arg(long, global = true)]
    execution_gas: Option<u64>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Keygen,
    /// Generate a post-quantum key (ML-DSA-65, FIPS 204)
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
        /// Execution gas; the node's estimate when not given (B65).
        #[arg(long)]
        gas_limit: Option<u64>,
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
    /// Import a private key (entered at a hidden prompt — never via CLI arg)
    Import {
        #[arg(long, default_value = "./keys")]
        out: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = RpcClient::new(&cli.rpc);
    let chain_id = if cli.chain_id == "AINCORE-MAINNET-1" {
        std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| cli.chain_id.clone())
    } else {
        cli.chain_id.clone()
    };

    match cli.command {
        Commands::Keygen => {
            let path = Path::new(&cli.keyfile);
            let wallet = Wallet::load_or_create(path)?;
            println!("Wallet loaded/created at {:?}", path);
            println!("Address: {}", a1n(&wallet.address()));
            println!("Address (hex): {}", wallet.address());
            println!("Public Key: {}", wallet.public_key());
        }
        Commands::PqcKeygen { out } => {
            use rand::RngCore;

            std::fs::create_dir_all(&out)?;
            // ML-DSA.KeyGen_internal(ξ) (FIPS 204): the 32-byte seed is the
            // whole secret; the key pair is recomputed from it.
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let key = crypto::MlDsa65Key::from_seed(&seed);
            let public_key = key.public_key();
            let address = crypto::derive_address(&public_key)
                .map_err(|e| anyhow::anyhow!("failed to derive the address: {e}"))?;

            let seed_path = format!("{}/mldsa65.seed", out);
            let pk_path = format!("{}/mldsa65.pub", out);
            let addr_path = format!("{}/mldsa65_address.txt", out);
            std::fs::write(&pk_path, hex::encode(&public_key))?;
            // The seed is a spendable signing identity: owner-only (0600) from
            // creation, like node.key (audit H-5).
            {
                #[cfg(unix)]
                {
                    use std::io::Write as _;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&seed_path)?;
                    f.write_all(hex::encode(seed).as_bytes())?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::write(&seed_path, hex::encode(seed))?;
                }
            }
            std::fs::write(&addr_path, &address)?;

            println!("Post-quantum key generated (ML-DSA-65, FIPS 204)");
            println!("Public key:  {} ({} bytes)", pk_path, public_key.len());
            println!("Seed:        {} (32 bytes, mode 0600)", seed_path);
            println!("Address:     {}", a1n(&address));
            println!("Address hex: {}", address);
            println!();
            println!(
                "Sign with it: aincore-cli --pqc-seed {} <command>",
                seed_path
            );
            println!("SECURITY: the seed is the key; keep it secret (stored unencrypted, 0600).");
        }
        Commands::Info => {
            let res = client.call("aincore_getStatus", json!([]))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Commands::SubmitProof { device, quality } => {
            let wallet = load_wallet(&cli.pqc_seed, &cli.keyfile)?;
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
                    move_core_types::account_address::AccountAddress::ONE,
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
            let tx_json = signed_tx_json(
                &client,
                &wallet,
                &chain_id,
                payload,
                seq_num,
                cli.execution_gas,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_json]))?;
            println!("✅ Proof Submitted: {}", res);
        }
        Commands::Balance { address } => {
            let addr = if let Some(a) = address {
                require_address_hex(&a)?
            } else {
                let wallet = load_wallet(&cli.pqc_seed, &cli.keyfile)?;
                wallet.address()
            };

            println!("🔍 Checking balance for: {}", a1n(&addr));
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
            let to = require_address_hex(&to)?;
            let wallet = load_wallet(&cli.pqc_seed, &cli.keyfile)?;
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
                "💸 Sending {} from {} to {} (execution gas: {})",
                amount,
                sender,
                to,
                gas_limit.map_or_else(|| "estimated".to_string(), |g| g.to_string())
            );

            // Construct payload
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
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&parse_move_address(&to).unwrap()).unwrap(),
                    bcs::to_bytes(&(amount as u128)).unwrap(),
                ],
            };
            let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            let seq_num = sequence_number; // Use current seq number (Executor expects match)
                                           // `gas_limit` is the gas for execution; the byte gas is added.
            let tx_str = signed_tx_json(
                &client,
                &wallet,
                &chain_id,
                payload,
                seq_num,
                gas_limit.or(cli.execution_gas),
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_str]))?;
            println!("✅ Transaction submitted: {}", res);
        }
        Commands::Publish { path } => {
            let wallet = load_wallet(&cli.pqc_seed, &cli.keyfile)?;
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
            // F4: bind gas_limit/gas_price/input_objects.
            let tx_str = signed_tx_json(
                &client,
                &wallet,
                &chain_id,
                payload,
                sequence_number,
                cli.execution_gas,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_str]))?;
            println!("✅ Publish Transaction submitted: {}", res);

            // Cleanup
            std::fs::remove_dir_all(output_dir)?;
        }
        Commands::Keys { command } => match command {
            KeysSubcommand::Generate { out } => {
                KeysCmd::generate(&out)?;
            }
            KeysSubcommand::Import { out } => {
                KeysCmd::import(&out)?;
            }
        },
        Commands::RegisterValidator => {
            let wallet = load_wallet(&cli.pqc_seed, &cli.keyfile)?;
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
            let (bls_public_key, bls_pop) = derive_validator_bls_identity(&wallet)?;
            let min_stake: u128 = 1_000_000_000_000_000_000_000; // 1000 AIN in quanta (smallest unit, 10^18)
            let call = vm_move::EntryFunctionCall {
                module: move_core_types::language_storage::ModuleId::new(
                    move_core_types::account_address::AccountAddress::ONE,
                    move_core_types::identifier::Identifier::new("staking").unwrap(),
                ),
                function: "join_validator_set".to_string(),
                ty_args: vec![],
                args: vec![
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&min_stake).unwrap(),
                    bcs::to_bytes(&pk_bytes).unwrap(),
                    bcs::to_bytes(&bls_public_key).unwrap(),
                    bcs::to_bytes(&bls_pop).unwrap(),
                ],
            };
            let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            let tx_json = signed_tx_json(
                &client,
                &wallet,
                &chain_id,
                payload,
                sequence_number,
                cli.execution_gas,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_json]))?;
            println!("✅ Validator Registration Submitted: {}", res);
        }
        Commands::Faucet { to, amount } => {
            let to = require_address_hex(&to)?;
            let wallet = load_wallet(&cli.pqc_seed, &cli.keyfile)?;
            let sender = wallet.address();

            println!("🚰 Faucet: Sending {} AIN to {}", amount, a1n(&to));

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
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&parse_move_address(&to).unwrap()).unwrap(),
                    bcs::to_bytes(&amount_quanta).unwrap(),
                ],
            };
            let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            let tx_json = signed_tx_json(
                &client,
                &wallet,
                &chain_id,
                payload,
                sequence_number,
                cli.execution_gas,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_json]))?;
            println!("✅ Faucet Transaction Submitted: {}", res);
        }
    }

    Ok(())
}

#[cfg(test)]
mod address_tests {
    use super::*;

    const HEX: &str = "dd48891f6d6799d5aa71e17b150ba3a8c30cbfbfb02544f546801f057aa65d42";
    const A1N: &str = "A1nB31ipYCNJJR7Gcsat1oE8J6kFPdEbJP5pAkq7u2ZLjdokxA3nH";

    #[test]
    fn recipient_accepts_a1n_and_hex_and_refuses_a_typo() {
        assert_eq!(require_address_hex(A1N).unwrap(), HEX);
        assert_eq!(require_address_hex(HEX).unwrap(), HEX);
        assert_eq!(require_address_hex(&format!("0x{}", HEX)).unwrap(), HEX);
        assert_eq!(
            parse_move_address(A1N).unwrap(),
            parse_move_address(HEX).unwrap()
        );

        let typo = A1N.replacen("YCNJ", "YCNK", 1);
        assert_ne!(typo, A1N, "positive control: the typo was applied");
        let err = require_address_hex(&typo).unwrap_err().to_string();
        assert!(err.contains("checksum"), "{}", err);
        assert!(parse_move_address(&typo).is_none());
    }

    #[test]
    fn display_uses_a1n() {
        assert_eq!(a1n(HEX), A1N);
    }
}
