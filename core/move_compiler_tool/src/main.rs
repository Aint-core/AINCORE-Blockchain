use clap::Parser;
use move_compiler::{compiled_unit::CompiledUnitEnum, Compiler};

use anyhow::Result;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the Move source files
    #[arg(short, long, num_args = 1..)]
    sources: Vec<PathBuf>,

    /// Output directory for compiled bytecode
    #[arg(short, long, default_value = "./build")]
    output: PathBuf,

    /// Dependency sources compiled but not emitted (e.g. the 0x1 stdlib).
    /// Required to compile a module that `use`s 0x1::coin, 0x1::staking, etc.
    #[arg(short, long, num_args = 0..)]
    deps: Vec<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("🔨 Compiling {} Move files...", args.sources.len());
    let targets: Vec<String> = args
        .sources
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    let deps: Vec<String> = args
        .deps
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    if !deps.is_empty() {
        println!("   with {} dependency source(s)", deps.len());
    }

    // Compiler::from_files expects <Paths, NamedAddress>
    // Paths must implement Into<Symbol> (String does)
    // NamedAddress must implement Into<Symbol> (String does)

    let mut address_map = BTreeMap::new();
    address_map.insert(
        "std".to_string(),
        move_compiler::shared::NumericalAddress::parse_str("0x1").unwrap(),
    );

    let (files, units_res) =
        Compiler::from_files::<String, String>(targets, deps, address_map).build()?;

    match units_res {
        Ok((units, _)) => {
            fs::create_dir_all(&args.output)?;

            for unit in units {
                if let CompiledUnitEnum::Module(named_module) = unit {
                    let module = named_module.named_module.module;

                    let mut bytes = vec![];
                    module.serialize(&mut bytes)?;

                    let filename = format!("{}.mv", module.self_id().name());
                    let output_path = args.output.join(filename);
                    fs::write(&output_path, &bytes)?;

                    println!("✅ Compiled: {:?} ({} bytes)", output_path, bytes.len());
                    println!("   Hex: {}", hex::encode(&bytes));
                }
            }
        }
        Err(errors) => {
            eprintln!("❌ Compilation failed with errors");
            move_compiler::diagnostics::report_diagnostics(&files, errors);
        }
    }

    Ok(())
}
