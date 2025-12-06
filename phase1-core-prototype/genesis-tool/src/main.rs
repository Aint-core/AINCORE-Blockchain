use clap::Parser;
use std::sync::Arc;
use storage::StateDB;
use node::genesis;

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
}

fn main() {
    let args = Args::parse();

    println!("🛠️  AINCORE Genesis Tool");
    println!("📂 Database Path: {}", args.db_path);
    println!("📚 Stdlib Path: {}", args.stdlib_path);
    println!("👤 Genesis Address: {}", args.genesis_addr);

    // Open (or create) the database
    let storage = Arc::new(StateDB::open(&args.db_path));

    // Initialize Genesis
    genesis::initialize_genesis(&storage, &args.stdlib_path, &args.genesis_addr);

    println!("✅ Genesis initialization complete!");
}
