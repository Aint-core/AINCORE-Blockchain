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
    // B354: the proof of possession binds the validator's Ed25519 key.
    let owner = hex::decode(wallet.public_key())?;
    Ok((
        bls.pubkey_raw(&seed),
        bls.prove_possession_raw(&seed, &owner),
    ))
}

/// The spending wallet: the ML-DSA-65 seed given with `--pqc-seed`, or else
/// the Ed25519 key file.
/// The signing wallet: an ML-DSA-65 seed, (B350) an encrypted keystore from
/// `keys generate|import` (its password asked at a hidden prompt), or the
/// plaintext key file.
fn load_wallet(
    pqc_seed: &Option<String>,
    keystore: &Option<String>,
    keyfile: &str,
) -> anyhow::Result<Wallet> {
    if let Some(seed) = pqc_seed {
        return Wallet::load_ml_dsa_65(Path::new(seed));
    }
    if let Some(keystore) = keystore {
        let password = rpassword::prompt_password("🔑 Keystore password: ")
            .context("Failed to read the keystore password")?;
        let key = keystore::KeyManager::decrypt(keystore, &password)
            .map_err(|e| anyhow::anyhow!("cannot open the keystore {keystore}: {e}"))?;
        return Wallet::from_ed25519_hex(&key);
    }
    Wallet::load_or_create(Path::new(keyfile))
}

/// A signed transaction carrying `payload`: priced at the node's base fee
/// (B15), with `execution` gas on top of the intrinsic byte gas its own size
/// owes (B14), signed over the seven fields (F4) by `wallet`. B65: without
/// `execution`, the node runs the transaction and answers what it would use,
/// the state its writes add included (`aincore_estimateGas`).
fn signed_tx_json(
    client: &RpcClient,
    wallet: &Wallet,
    chain_id: &Option<String>,
    payload: String,
    sequence_number: u64,
    execution: Option<u64>,
    fees: &FeePolicy,
) -> anyhow::Result<String> {
    let chain_id = signing_chain(chain_id, &client.network()?)?;
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
    fees.check(execution, gas_price)?;
    tx.gas_limit = executor::admission::gas_limit_covering(unsized_len, execution);
    fees.confirm(tx.gas_limit, gas_price)?;
    tx.signature = wallet.sign(executor::admission::signing_message(&tx).as_bytes());
    Ok(serde_json::to_string(&tx)?)
}

/// The sequence number `address`'s next transaction must carry.
fn account_nonce(client: &RpcClient, address: &str) -> anyhow::Result<u64> {
    let answer = client.call("aincore_getAccountNonce", json!([address]))?;
    answer["sequence_number"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("unexpected aincore_getAccountNonce answer: {answer}"))
}

/// An object's `data` as the node serves it: its text (B66), or the array
/// of its bytes.
fn object_data(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::String(text) => Some(text.as_bytes().to_vec()),
        serde_json::Value::Array(bytes) => bytes
            .iter()
            .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
            .collect(),
        _ => None,
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

    /// RPC URL of the node (B243: the node's default API port is 8002)
    #[arg(short, long, default_value = "http://127.0.0.1:8002/rpc")]
    rpc: String,

    /// Path to wallet key file
    #[arg(short, long, default_value = "wallet.key")]
    keyfile: String,

    /// Sign with this ML-DSA-65 seed file (from `pqc-keygen`) instead of the
    /// Ed25519 key file
    #[arg(long)]
    pqc_seed: Option<String>,

    /// B350: sign with this encrypted keystore (from `keys generate` or
    /// `keys import`) instead of the plaintext key file; its password is
    /// asked at a hidden prompt
    #[arg(long)]
    keystore: Option<String>,

    /// Chain ID used in signed transactions (or AINCORE_CHAIN_ID env). B243:
    /// required to sign, and it must be the chain the node runs: a default
    /// of AINCORE-MAINNET-1 signed mainnet-valid transactions for a user who
    /// forgot the flag on a testnet.
    #[arg(long)]
    chain_id: Option<String>,

    /// Execution gas for every signed transaction; the node's estimate
    /// (`aincore_estimateGas`) when not given (B65)
    #[arg(long, global = true)]
    execution_gas: Option<u64>,

    /// B362: refuse to sign at a gas price above this (quanta a gas); the
    /// node's price is otherwise shown with the fee it makes and confirmed
    #[arg(long, global = true)]
    max_gas_price: Option<u128>,

    /// B362: sign without asking to confirm the fee (for scripts)
    #[arg(long, global = true)]
    assume_yes: bool,
}

/// B362: what a signer takes from the node's price and estimate.
struct FeePolicy {
    max_gas_price: Option<u128>,
    assume_yes: bool,
}

impl FeePolicy {
    /// The node's estimate and price, refused past a transaction's gas limit
    /// or `--max-gas-price` (both are the RPC's word: a hostile one named a
    /// price that spent the whole balance on one transfer's fee).
    fn check(&self, execution: u64, gas_price: u128) -> anyhow::Result<()> {
        if execution > executor::MAX_GAS_LIMIT {
            anyhow::bail!(
                "the node's estimate, {execution} gas, is past a transaction's {} \
                 (give --execution-gas)",
                executor::MAX_GAS_LIMIT
            );
        }
        if let Some(max) = self.max_gas_price {
            if gas_price > max {
                anyhow::bail!("the node's gas price, {gas_price}, is above --max-gas-price {max}");
            }
        }
        Ok(())
    }

    /// The most the transaction pays, shown, and signed only once confirmed
    /// (or with `--assume-yes`), as Aptos's CLI asks.
    fn confirm(&self, gas_limit: u64, gas_price: u128) -> anyhow::Result<()> {
        let fee = u128::from(gas_limit).saturating_mul(gas_price);
        println!(
            "Fee: at most {} AIN ({fee} quanta): {gas_limit} gas at {gas_price} quanta a gas",
            ain_text(fee)
        );
        if self.assume_yes {
            return Ok(());
        }
        print!("Sign and submit? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if confirmed(&answer) {
            Ok(())
        } else {
            anyhow::bail!("not submitted")
        }
    }
}

/// B362: a yes to the fee's question.
fn confirmed(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair
    Keygen,
    /// Generate a post-quantum key (ML-DSA-65, FIPS 204)
    PqcKeygen {
        /// Output directory for keys (B307: `$HOME/.aincore/pqc_keys` when
        /// not given; it was `./pqc_keys`, inside whatever checkout the
        /// command ran in, where `git add -A` published the spending seed)
        #[arg(long)]
        out: Option<String>,
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
        /// Amount in AIN, up to 18 decimals (B296: it was taken as quanta,
        /// so `transfer <addr> 1010` sent 1,010 quanta, and no more than
        /// about 18.4 AIN could be sent).
        amount: String,
        /// The amount is in quanta (10^-18 AIN), a whole number.
        #[arg(long)]
        quanta: bool,
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
    /// Generate a new encrypted keypair (B328: in `$HOME/.aincore/keys` by
    /// default, never the working directory)
    Generate {
        #[arg(long)]
        out: Option<String>,
    },
    /// Import a private key (entered at a hidden prompt — never via CLI arg)
    Import {
        #[arg(long)]
        out: Option<String>,
    },
}

/// B243: the chain id to sign for: the one named (`--chain-id` or
/// `AINCORE_CHAIN_ID`), and only if it is the chain the node runs. Nothing
/// is signed without one: a default signed for mainnet.
fn signing_chain<'a>(named: &'a Option<String>, node: &str) -> anyhow::Result<&'a str> {
    let Some(named) = named.as_deref() else {
        anyhow::bail!(
            "name the chain to sign for: --chain-id or AINCORE_CHAIN_ID (the node runs {node})"
        );
    };
    if named != node {
        anyhow::bail!("the node runs {node}, not {named}: refusing to sign");
    }
    Ok(named)
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let client = RpcClient::new(&cli.rpc);
    let fees = FeePolicy {
        max_gas_price: cli.max_gas_price,
        assume_yes: cli.assume_yes,
    };
    let chain_id = cli
        .chain_id
        .clone()
        .or_else(|| std::env::var("AINCORE_CHAIN_ID").ok())
        .filter(|id| !id.is_empty());

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

            let out = match out {
                Some(out) => out,
                None => {
                    let home = std::env::var("HOME")
                        .map_err(|_| anyhow::anyhow!("no HOME: name the directory with --out"))?;
                    format!("{home}/.aincore/pqc_keys")
                }
            };
            std::fs::create_dir_all(&out)?;
            // ML-DSA.KeyGen_internal(ξ) (FIPS 204): the 32-byte seed is the
            // whole secret; the key pair is recomputed from it.
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            let key = crypto::MlDsa65Key::from_seed(&seed);
            let public_key = key.public_key();
            let address = crypto::derive_address(&public_key)
                .map_err(|e| anyhow::anyhow!("failed to derive the address: {e}"))?;

            let (seed_path, pk_path) = save_pqc_key(Path::new(&out), &seed, &public_key, &address)?;

            println!("Post-quantum key generated (ML-DSA-65, FIPS 204)");
            println!(
                "Public key:  {} ({} bytes)",
                pk_path.display(),
                public_key.len()
            );
            println!("Seed:        {} (32 bytes, mode 0600)", seed_path.display());
            println!("Address:     {}", a1n(&address));
            println!("Address hex: {}", address);
            println!();
            println!(
                "Sign with it: aincore-cli --pqc-seed {} <command>",
                seed_path.display()
            );
            println!("SECURITY: the seed is the key; keep it secret (stored unencrypted, 0600).");
        }
        Commands::Info => {
            let res = client.call("aincore_getStatus", json!([]))?;
            println!("{}", serde_json::to_string_pretty(&res)?);
        }
        Commands::SubmitProof { device, quality } => {
            let wallet = load_wallet(&cli.pqc_seed, &cli.keystore, &cli.keyfile)?;
            let sender = wallet.address();

            // Get Seq Number
            let sequence_number = account_nonce(&client, &sender)?;

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
                &fees,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_json]))?;
            println!("✅ Proof Submitted: {}", res);
        }
        Commands::Balance { address } => {
            let addr = if let Some(a) = address {
                require_address_hex(&a)?
            } else {
                let wallet = load_wallet(&cli.pqc_seed, &cli.keystore, &cli.keyfile)?;
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
                if let Some(bytes) = obj.get("data").and_then(object_data) {
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
            quanta,
            gas_limit,
        } => {
            let to = require_address_hex(&to)?;
            let amount_quanta = if quanta {
                amount
                    .trim()
                    .parse::<u128>()
                    .map_err(|e| anyhow::anyhow!("an amount in quanta: {e}"))?
            } else {
                parse_ain(&amount)?
            };
            let amount = if quanta {
                format!("{amount} quanta")
            } else {
                format!("{amount} AIN")
            };
            let wallet = load_wallet(&cli.pqc_seed, &cli.keystore, &cli.keyfile)?;
            let sender = wallet.address();

            println!("🔍 Loading sender metadata: {}", sender);
            let sequence_number = account_nonce(&client, &sender)?;

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
                    bcs::to_bytes(&amount_quanta).unwrap(),
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
                &fees,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_str]))?;
            println!("✅ Transaction submitted: {}", res);
        }
        Commands::Publish { path } => {
            let wallet = load_wallet(&cli.pqc_seed, &cli.keystore, &cli.keyfile)?;
            let sender = wallet.address();
            let source_path = Path::new(&path);

            println!("📦 Publishing module from: {:?}", source_path);

            // 1. Compile with move_compiler_tool: the stdlib as dependencies
            // (B363: given after `--sources`, every stdlib module was a
            // target, and the first `.mv` the directory listed, often
            // `ascii.mv`, was the one signed and sent), into a directory of
            // this run's own (`./temp_build` was removed whatever it held).
            let compiler_tool = std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|dir| dir.join("move_compiler_tool")))
                .filter(|tool| tool.exists())
                .unwrap_or_else(|| {
                    Path::new("../../target/debug/move_compiler_tool").to_path_buf()
                });
            // Path to Stdlib sources (Hardcoded for dev environment)
            let stdlib_path = "../vm_move/stdlib/sources";
            let stdlib: Vec<std::path::PathBuf> = std::fs::read_dir(stdlib_path)
                .with_context(|| format!("the stdlib sources are not at {stdlib_path}"))?
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("move"))
                .collect();
            let output_dir = private_build_dir()?;

            println!("   Compiling...");
            let status = compile_command(&compiler_tool, &path, &stdlib, &output_dir)
                .status()
                .context("Failed to execute move_compiler_tool. Make sure it is built.")?;

            if !status.success() {
                let _ = std::fs::remove_dir_all(&output_dir);
                anyhow::bail!("Compilation failed.");
            }

            // 2. The one module the source compiled to.
            let compiled: Vec<std::path::PathBuf> = std::fs::read_dir(&output_dir)?
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("mv"))
                .collect();
            let bytecode = match compiled.as_slice() {
                [module] => {
                    println!("   Found compiled module: {:?}", module);
                    std::fs::read(module)?
                }
                other => {
                    let _ = std::fs::remove_dir_all(&output_dir);
                    anyhow::bail!(
                        "the source compiled to {} modules: publish one module a file",
                        other.len()
                    );
                }
            };
            std::fs::remove_dir_all(&output_dir)?;

            // 3. Construct Payload
            let bytecode_hex = hex::encode(bytecode);

            let bytes = hex::decode(&bytecode_hex).expect("invalid hex in publish command");
            let payload_struct = vm_move::TransactionPayload::PublishModule(vec![bytes]);
            let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
            let sequence_number = account_nonce(&client, &sender)?;
            // F4: bind gas_limit/gas_price/input_objects.
            let tx_str = signed_tx_json(
                &client,
                &wallet,
                &chain_id,
                payload,
                sequence_number,
                cli.execution_gas,
                &fees,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_str]))?;
            println!("✅ Publish Transaction submitted: {}", res);
        }
        Commands::Keys { command } => match command {
            KeysSubcommand::Generate { out } => {
                KeysCmd::generate(&keys::out_dir(out)?)?;
            }
            KeysSubcommand::Import { out } => {
                KeysCmd::import(&keys::out_dir(out)?)?;
            }
        },
        Commands::RegisterValidator => {
            let wallet = load_wallet(&cli.pqc_seed, &cli.keystore, &cli.keyfile)?;
            let sender = wallet.address();

            println!("🔒 Registering Validator for address: {}", sender);

            // Check Balance
            let sequence_number = account_nonce(&client, &sender)?;

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
                &fees,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_json]))?;
            println!("✅ Validator Registration Submitted: {}", res);
        }
        Commands::Faucet { to, amount } => {
            let to = require_address_hex(&to)?;
            let wallet = load_wallet(&cli.pqc_seed, &cli.keystore, &cli.keyfile)?;
            let sender = wallet.address();

            println!("🚰 Faucet: Sending {} AIN to {}", amount, a1n(&to));

            // Get sequence number
            let sequence_number = account_nonce(&client, &sender)?;

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
                &fees,
            )?;
            let res = client.call("aincore_sendTransaction", json!([tx_json]))?;
            println!("✅ Faucet Transaction Submitted: {}", res);
        }
    }

    Ok(())
}

/// One AIN in quanta (the coin's 18 decimals).
const QUANTA_PER_AIN: u128 = 1_000_000_000_000_000_000;

/// B364: an ML-DSA-65 key's three files in `out`: its seed first (owner-only,
/// 0600, as node.key: audit H-5), then its public key and address, none over
/// a file that exists. A second run wrote a new public key over the old one,
/// then failed on the seed's `create_new`: a public key without its seed,
/// whose address could receive and never spend.
fn save_pqc_key(
    out: &Path,
    seed: &[u8; 32],
    public_key: &[u8],
    address: &str,
) -> anyhow::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let seed_path = out.join("mldsa65.seed");
    let pk_path = out.join("mldsa65.pub");
    let addr_path = out.join("mldsa65_address.txt");
    for path in [&seed_path, &pk_path, &addr_path] {
        if path.exists() {
            anyhow::bail!(
                "{} exists: a key is never written over (move it, or name another --out)",
                path.display()
            );
        }
    }
    let write_new = |path: &Path, contents: &[u8], private: bool| -> std::io::Result<()> {
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            if private {
                std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            }
        }
        #[cfg(not(unix))]
        let _ = private;
        options.open(path)?.write_all(contents)
    };
    write_new(&seed_path, hex::encode(seed).as_bytes(), true)?;
    write_new(&pk_path, hex::encode(public_key).as_bytes(), false)?;
    write_new(&addr_path, address.as_bytes(), false)?;
    Ok((seed_path, pk_path))
}

/// B363: the compiler's command: the user's source its only target, the
/// stdlib its dependencies (compiled, not emitted), into `out`.
fn compile_command(
    tool: &Path,
    source: &str,
    stdlib: &[std::path::PathBuf],
    out: &Path,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(tool);
    cmd.arg("--sources")
        .arg(source)
        .arg("--deps")
        .args(stdlib)
        .arg("--output")
        .arg(out);
    cmd
}

/// B363: a new directory of this run's own for the compiler's output, under
/// the system's temporary directory (never one that exists).
fn private_build_dir() -> anyhow::Result<std::path::PathBuf> {
    use rand::RngCore;
    let dir = std::env::temp_dir().join(format!(
        "aincore-publish-{}-{:016x}",
        std::process::id(),
        rand::rngs::OsRng.next_u64()
    ));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    }
    builder
        .create(&dir)
        .with_context(|| format!("could not create {}", dir.display()))?;
    Ok(dir)
}

/// B362: quanta in AIN, its 18 decimals without trailing zeros.
fn ain_text(quanta: u128) -> String {
    let (whole, frac) = (quanta / QUANTA_PER_AIN, quanta % QUANTA_PER_AIN);
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:018}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

/// B296: an amount in AIN with up to 18 decimals ("1010", "0.25"), in quanta.
fn parse_ain(text: &str) -> anyhow::Result<u128> {
    let text = text.trim();
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if (whole.is_empty() && frac.is_empty()) || !digits(whole) || !digits(frac) || frac.len() > 18 {
        anyhow::bail!("{text:?} is not an amount of AIN (up to 18 decimals)");
    }
    let whole: u128 = if whole.is_empty() { 0 } else { whole.parse()? };
    let frac: u128 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<18}").parse()?
    };
    whole
        .checked_mul(QUANTA_PER_AIN)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| anyhow::anyhow!("{text} AIN is past what a u128 of quanta holds"))
}

#[cfg(test)]
mod amount_tests {
    /// B296 witness: a transfer's amount is in AIN, as the faucet's and the
    /// funding script's are (it was taken as quanta).
    #[test]
    fn a_transfer_amount_is_in_ain() {
        let ain = super::QUANTA_PER_AIN;
        assert_eq!(super::parse_ain("1010").unwrap(), 1010 * ain);
        assert_eq!(super::parse_ain("0.5").unwrap(), ain / 2);
        assert_eq!(super::parse_ain("1.000000000000000001").unwrap(), ain + 1);
        assert!(
            super::parse_ain("1.0000000000000000001").is_err(),
            "19 decimals"
        );
        assert!(super::parse_ain("").is_err());
        assert!(super::parse_ain("-1").is_err());
        assert!(super::parse_ain("1e3").is_err());
    }
}

#[cfg(test)]
mod fee_tests {
    use super::*;

    /// B362 witness: the node's price and estimate are a stranger's word: a
    /// price above `--max-gas-price` and an estimate past a transaction's gas
    /// limit are refused, and only a yes signs the fee shown (a hostile RPC
    /// named a price that spent the whole balance on one transfer's fee).
    #[test]
    fn the_nodes_price_is_bounded_and_its_fee_confirmed() {
        let fees = FeePolicy {
            max_gas_price: Some(100),
            assume_yes: false,
        };
        assert!(fees.check(1_000, 100).is_ok());
        assert!(fees.check(1_000, 101).is_err(), "a price past the bound");
        assert!(
            fees.check(executor::MAX_GAS_LIMIT + 1, 1).is_err(),
            "an estimate past a transaction's limit"
        );
        assert!(confirmed("y\n") && confirmed(" YES "));
        assert!(!confirmed("") && !confirmed("n") && !confirmed("yes please"));
        assert_eq!(ain_text(QUANTA_PER_AIN * 3 / 2), "1.5");
        assert_eq!(ain_text(7), "0.000000000000000007");
        assert_eq!(ain_text(0), "0");
    }

    /// B363 witness: the stdlib compiles as the source's dependencies only,
    /// into a new directory of the run's own (given after `--sources`, every
    /// stdlib module was a target, and the first `.mv` listed was the one
    /// signed and sent; `./temp_build` was removed whatever it held).
    #[test]
    fn the_stdlib_compiles_as_dependencies_only() {
        let stdlib = [std::path::PathBuf::from("std/ascii.move")];
        let cmd = compile_command(Path::new("tool"), "mine.move", &stdlib, Path::new("out"));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                "--sources",
                "mine.move",
                "--deps",
                "std/ascii.move",
                "--output",
                "out"
            ]
        );
        let (a, b) = (private_build_dir().unwrap(), private_build_dir().unwrap());
        assert_ne!(a, b);
        assert!(a.starts_with(std::env::temp_dir()));
        std::fs::remove_dir(&a).unwrap();
        std::fs::remove_dir(&b).unwrap();
    }

    /// B364 witness: a key is never written over: a second key in the same
    /// directory is refused before any file is touched (it wrote its public
    /// key over the first one's, then failed on the seed). A public key
    /// alone is refused too, and the seed is written first: one that cannot
    /// be written leaves no public key.
    #[test]
    fn a_second_pqc_key_writes_over_nothing() {
        let out = std::env::temp_dir().join(format!(
            "aincore-b364-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&out).unwrap();
        save_pqc_key(&out, &[1; 32], b"first", "addr1").unwrap();
        let read = |name: &str| std::fs::read_to_string(out.join(name)).unwrap();
        let before = (
            read("mldsa65.seed"),
            read("mldsa65.pub"),
            read("mldsa65_address.txt"),
        );
        assert!(save_pqc_key(&out, &[2; 32], b"second", "addr2").is_err());
        let after = (
            read("mldsa65.seed"),
            read("mldsa65.pub"),
            read("mldsa65_address.txt"),
        );
        assert_eq!(before, after, "a file was written over");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(out.join("mldsa65.seed"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A public key alone (its seed moved away): refused, the public key
        // kept, no seed or address written beside it (a new key pair over
        // the old public key otherwise).
        std::fs::remove_file(out.join("mldsa65.seed")).unwrap();
        std::fs::remove_file(out.join("mldsa65_address.txt")).unwrap();
        assert!(save_pqc_key(&out, &[3; 32], b"third", "addr3").is_err());
        assert_eq!(read("mldsa65.pub"), before.1, "the public key written over");
        assert!(!out.join("mldsa65.seed").exists(), "a seed written");
        assert!(
            !out.join("mldsa65_address.txt").exists(),
            "an address written"
        );

        // The seed first: a seed that cannot be written leaves no public key
        // (a dangling link passes `exists`, and `create_new` refuses it).
        #[cfg(unix)]
        {
            std::fs::remove_file(out.join("mldsa65.pub")).unwrap();
            std::os::unix::fs::symlink(out.join("nowhere"), out.join("mldsa65.seed")).unwrap();
            assert!(save_pqc_key(&out, &[4; 32], b"fourth", "addr4").is_err());
            assert!(
                std::fs::symlink_metadata(out.join("mldsa65.pub")).is_err(),
                "a public key written before its seed"
            );
            assert!(!out.join("mldsa65_address.txt").exists());
            assert!(!out.join("nowhere").exists());
        }
        std::fs::remove_dir_all(&out).unwrap();
    }
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

#[cfg(test)]
mod chain_tests {
    use super::*;

    /// B243 witness: a transaction is signed only for the chain named, and
    /// only if the node runs that chain (with nothing named it was signed
    /// for mainnet, whatever chain the node ran).
    #[test]
    fn a_transaction_is_signed_only_for_the_named_chain_the_node_runs() {
        let named = Some("AINCORE-TESTNET-V4".to_string());
        assert_eq!(
            signing_chain(&named, "AINCORE-TESTNET-V4").unwrap(),
            "AINCORE-TESTNET-V4"
        );
        assert!(signing_chain(&named, "AINCORE-MAINNET-1").is_err());
        assert!(signing_chain(&None, "AINCORE-MAINNET-1").is_err());
    }
}
