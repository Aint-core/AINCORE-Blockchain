use clap::{Parser, Subcommand};
use node::genesis;
use std::sync::Arc;
use storage::StateDB;

mod multi_genesis;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    // === Legacy single-node `init` flags (kept at top level so existing
    // invocations `genesis-tool --db-path ...` keep working unchanged). ===
    /// Path to the database directory (e.g., "data/validator_9000.db")
    #[arg(short, long)]
    db_path: Option<String>,

    /// Path to the Move Stdlib bytecode directory
    #[arg(short, long, default_value = "vm_move/stdlib/bytecode")]
    stdlib_path: String,

    /// Genesis Validator Address (Hex, 32 bytes = 64 hex chars)
    #[arg(
        short,
        long,
        default_value = "0000000000000000000000000000000000000000000000000000000000000001"
    )]
    genesis_addr: String,

    /// Genesis Validator Public Key (Hex). Defaults to genesis_addr for legacy tooling.
    #[arg(long)]
    genesis_pubkey: Option<String>,

    /// Node identity seed (32-byte hex) used to derive the validator BLS key for
    /// the single-node fallback path. Ignored when genesis.json supplies explicit
    /// per-validator BLS keys. Defaults to a deterministic all-zero seed.
    #[arg(long)]
    node_identity: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize genesis state into a RocksDB datadir (legacy single-node path).
    Init {
        /// Path to the database directory (e.g., "data/validator_9000.db")
        #[arg(short, long)]
        db_path: String,
        /// Path to the Move Stdlib bytecode directory
        #[arg(short, long, default_value = "vm_move/stdlib/bytecode")]
        stdlib_path: String,
        /// Genesis Validator Address (Hex, 32 bytes = 64 hex chars)
        #[arg(
            short,
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000001"
        )]
        genesis_addr: String,
        /// Genesis Validator Public Key (Hex). Defaults to genesis_addr.
        #[arg(long)]
        genesis_pubkey: Option<String>,
        /// Node identity seed (32-byte hex) for single-node BLS fallback.
        #[arg(long)]
        node_identity: Option<String>,
    },

    /// Generate a multi-validator genesis.json from N node-key seeds + stakes.
    ///
    /// For each validator, the tool derives the EXACT fields a multi-validator
    /// genesis requires — address, ed25519 public_key, and the embedded BLS
    /// finality identity (bls_public_key + bls_pop) — so every booting node
    /// agrees on the same `sys:validator_set:v1` and their QCs verify against
    /// each other. Without embedded BLS keys a multi-validator genesis is
    /// rejected (a node cannot self-derive another node's BLS key).
    GenMulti(multi_genesis::GenMultiArgs),
}

fn run_init(
    db_path: &str,
    stdlib_path: &str,
    genesis_addr: &str,
    genesis_pubkey: Option<&str>,
    node_identity_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🛠️  AINCORE Genesis Tool");
    println!("📂 Database Path: {}", db_path);
    println!("📚 Stdlib Path: {}", stdlib_path);
    println!("👤 Genesis Address: {}", genesis_addr);

    let storage = Arc::new(StateDB::open(db_path).expect("Failed to open DB"));
    let genesis_pubkey = genesis_pubkey.unwrap_or(genesis_addr);

    // B1: node identity (32-byte hex) drives the deterministic single-node BLS
    // key + PoP fallback when genesis.json does not supply explicit per-validator
    // BLS keys. Defaults to an all-zero seed if not provided.
    let mut node_identity = [0u8; 32];
    if let Some(ni_hex) = node_identity_hex {
        let bytes = hex::decode(ni_hex.trim()).expect("--node-identity must be valid hex");
        assert_eq!(
            bytes.len(),
            32,
            "--node-identity must be exactly 32 bytes (64 hex chars)"
        );
        node_identity.copy_from_slice(&bytes);
    }

    genesis::initialize_genesis(
        &storage,
        stdlib_path,
        genesis_addr,
        genesis_pubkey,
        &node_identity,
    )?;

    println!("✅ Genesis initialization complete!");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Some(Command::Init {
            db_path,
            stdlib_path,
            genesis_addr,
            genesis_pubkey,
            node_identity,
        }) => run_init(
            &db_path,
            &stdlib_path,
            &genesis_addr,
            genesis_pubkey.as_deref(),
            node_identity.as_deref(),
        ),
        Some(Command::GenMulti(gen_args)) => multi_genesis::run(gen_args),
        None => {
            // Backwards-compatible default: behave like the legacy `init` path
            // when invoked with top-level flags (`genesis-tool --db-path ...`).
            let db_path = args.db_path.clone().ok_or_else(|| {
                "no subcommand given and --db-path missing; use `gen-multi` to build a \
                 multi-validator genesis.json, or `init`/--db-path to initialize a datadir"
                    .to_string()
            })?;
            run_init(
                &db_path,
                &args.stdlib_path,
                &args.genesis_addr,
                args.genesis_pubkey.as_deref(),
                args.node_identity.as_deref(),
            )
        }
    }
}
