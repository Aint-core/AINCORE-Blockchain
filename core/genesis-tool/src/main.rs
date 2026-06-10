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
    genesis::initialize_genesis(
        &storage,
        &args.stdlib_path,
        &args.genesis_addr,
        genesis_pubkey,
    )?;

    println!("✅ Genesis initialization complete!");
    Ok(())
}
