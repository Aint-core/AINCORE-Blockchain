use clap::{Parser, Subcommand};
use node::genesis;
use std::sync::Arc;
use storage::StateDB;

mod multi_genesis;
mod score;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    // === `init` flags (also accepted at top level so existing
    // invocations `genesis-tool --db-path ...` keep working unchanged). ===
    /// Path to the database directory (e.g., "data/validator_9000.db")
    #[arg(short, long)]
    db_path: Option<String>,

    /// Path to the Move Stdlib bytecode directory
    #[arg(short, long, default_value = "vm_move/stdlib/bytecode")]
    stdlib_path: String,

    /// The genesis.json to initialize from (G3 FX-7: genesis depends on this
    /// file and the stdlib only; `gen-multi` writes it).
    #[arg(long, default_value = "genesis.json")]
    genesis: String,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize genesis state into a RocksDB datadir from a genesis.json.
    Init {
        /// Path to the database directory (e.g., "data/validator_9000.db")
        #[arg(short, long)]
        db_path: String,
        /// Path to the Move Stdlib bytecode directory
        #[arg(short, long, default_value = "vm_move/stdlib/bytecode")]
        stdlib_path: String,
        /// The genesis.json to initialize from.
        #[arg(long, default_value = "genesis.json")]
        genesis: String,
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

    /// Print this validator's public genesis entry from its node.key: the
    /// address, keys, BLS proof of possession and a node-key signature. Each
    /// operator runs it on its own machine and sends the output to the
    /// genesis coordinator (`gen-multi --entries-file`); no seed leaves the
    /// validator.
    ValidatorEntry(multi_genesis::EntryArgs),

    /// Derive the measured block time and the consensus-time cap C_tau from
    /// the release candidate's block intervals (G5 P-1): the inputs of
    /// `gen-multi`.
    ClockCap(multi_genesis::ClockCapArgs),

    /// Score the incentivized testnet's window from a stopped node's datadir
    /// and write the mainnet genesis inputs: allocations.json (for
    /// `gen-multi --allocations-file`), accounts.json (for `--accounts-file`)
    /// and report.json (G5 A4-S6).
    ScoreTestnet(score::ScoreArgs),
}

fn run_init(
    db_path: &str,
    stdlib_path: &str,
    genesis_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🛠️  AINCORE Genesis Tool");
    println!("📂 Database Path: {}", db_path);
    println!("📚 Stdlib Path: {}", stdlib_path);
    println!("📄 Genesis: {}", genesis_path);

    let storage = Arc::new(StateDB::open(db_path).expect("Failed to open DB"));
    genesis::initialize_genesis_from(&storage, stdlib_path, std::path::Path::new(genesis_path))?;

    println!("✅ Genesis initialization complete!");
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Some(Command::Init {
            db_path,
            stdlib_path,
            genesis,
        }) => run_init(&db_path, &stdlib_path, &genesis),
        Some(Command::GenMulti(gen_args)) => multi_genesis::run(gen_args),
        Some(Command::ValidatorEntry(entry_args)) => multi_genesis::run_entry(entry_args),
        Some(Command::ClockCap(cap_args)) => multi_genesis::run_clock_cap(cap_args),
        Some(Command::ScoreTestnet(score_args)) => score::run(score_args),
        None => {
            // Backwards-compatible default: behave like the legacy `init` path
            // when invoked with top-level flags (`genesis-tool --db-path ...`).
            let db_path = args.db_path.clone().ok_or_else(|| {
                "no subcommand given and --db-path missing; use `gen-multi` to build a \
                 multi-validator genesis.json, or `init`/--db-path to initialize a datadir"
                    .to_string()
            })?;
            run_init(&db_path, &args.stdlib_path, &args.genesis)
        }
    }
}
