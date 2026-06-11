use clap::Parser;
use node::genesis;
use std::sync::Arc;
use storage::StateDB;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the database directory (e.g., "data/validator_9000.db")
    #[arg(short, long)]
    db_path: String,

    /// Path to the Move Stdlib bytecode directory
    #[arg(short, long, default_value = "vm_move/stdlib/bytecode")]
    stdlib_path: String,

    /// Genesis Validator Address (Hex)
    #[arg(short, long, default_value = "00000000000000000000000000000001")]
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("🛠️  AINCORE Genesis Tool");
    println!("📂 Database Path: {}", args.db_path);
    println!("📚 Stdlib Path: {}", args.stdlib_path);
    println!("👤 Genesis Address: {}", args.genesis_addr);

    // Open (or create) the database
    let storage = Arc::new(StateDB::open(&args.db_path).expect("Failed to open DB"));

    // Initialize Genesis
    let genesis_pubkey = args.genesis_pubkey.as_deref().unwrap_or(&args.genesis_addr);

    // B1: node identity (32-byte hex) drives the deterministic single-node BLS
    // key + PoP fallback when genesis.json does not supply explicit per-validator
    // BLS keys. Defaults to an all-zero seed if not provided.
    let mut node_identity = [0u8; 32];
    if let Some(ni_hex) = args.node_identity.as_deref() {
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
        &args.stdlib_path,
        &args.genesis_addr,
        genesis_pubkey,
        &node_identity,
    )?;

    println!("✅ Genesis initialization complete!");
    Ok(())
}
