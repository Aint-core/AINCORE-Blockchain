//! Move unit tests for the stdlib, run on the production VM.
//!
//! `move-unit-test` is not used: it enables `move-stdlib/testing`, which adds a
//! field to `move_stdlib::natives::GasParameters`, so Cargo feature unification
//! would break `AINCOREVM::native_gas_params`. Instead this compiles the Move
//! test modules under `stdlib/tests/` in test mode with `move-compiler`, and
//! runs every `#[test]` through `AINCOREVM`'s own `MoveVM`: the production
//! natives and gas meter, over the COMMITTED stdlib bytecode in a fresh
//! StateDB. The test modules never become part of the stdlib.

use crate::{gas::AINCOREGasMeter, AINCOREVM};
use move_binary_format::errors::VMError;
use move_compiler::{
    compiled_unit::AnnotatedCompiledUnit,
    diagnostics::{self, codes::Severity, Diagnostics, FilesSourceText},
    shared::{Flags, NumericalAddress},
    unit_test::{plan_builder::construct_test_plan, ExpectedFailure, ModuleTestPlan, TestCase},
    Compiler, PASS_CFGIR,
};
use move_core_types::{identifier::IdentStr, language_storage::ModuleId, vm_status::StatusCode};
use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};
use storage::StateDB;

/// Gas for one test: executor::MAX_GAS_LIMIT, the most a transaction may use.
const TEST_GAS_LIMIT: u64 = 10_000_000;

fn stdlib_dir(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("stdlib")
        .join(sub)
}

fn move_files(sub: &str) -> Vec<String> {
    let mut files: Vec<String> = fs::read_dir(stdlib_dir(sub))
        .expect("stdlib directory exists")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("move"))
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    files.sort();
    files
}

fn named_addresses() -> BTreeMap<String, NumericalAddress> {
    BTreeMap::from([(
        "std".to_string(),
        NumericalAddress::parse_str("0x1").expect("0x1 parses"),
    )])
}

fn report(files: &FilesSourceText, diags: Diagnostics) -> String {
    String::from_utf8_lossy(&diagnostics::report_diagnostics_to_buffer(files, diags)).into_owned()
}

fn modules_of(units: Vec<AnnotatedCompiledUnit>) -> Vec<(ModuleId, Vec<u8>)> {
    units
        .into_iter()
        .filter_map(|unit| match unit.into_compiled_unit() {
            move_compiler::compiled_unit::CompiledUnitEnum::Module(named) => {
                let module = named.module;
                let mut bytes = vec![];
                module.serialize(&mut bytes).expect("module serializes");
                Some((module.self_id(), bytes))
            }
            move_compiler::compiled_unit::CompiledUnitEnum::Script(_) => None,
        })
        .collect()
}

/// Test mode links every module to `std::unit_test::create_signers_for_testing`
/// (a "poison" so test code cannot run on a real chain). That function is a
/// native the production VM does not register, so the tests get this
/// non-native stand-in, compiled in normal mode. Nothing calls it.
const UNIT_TEST_STAND_IN: &str = "
module std::unit_test {
    public fun create_signers_for_testing(_num_signers: u64): vector<signer> {
        abort 0
    }
}
";

fn compile_unit_test_stand_in() -> (ModuleId, Vec<u8>) {
    let file = std::env::temp_dir().join(format!(
        "aincore_move_unit_stand_in_{}.move",
        std::process::id()
    ));
    fs::write(&file, UNIT_TEST_STAND_IN).expect("stand-in written");
    let (files, result) = Compiler::from_files(
        vec![file.to_string_lossy().into_owned()],
        vec![],
        named_addresses(),
    )
    .build()
    .expect("stand-in readable");
    let _ = fs::remove_file(&file);
    let (units, _warnings) = result.unwrap_or_else(|diags| panic!("{}", report(&files, diags)));
    modules_of(units).pop().expect("one stand-in module")
}

/// Compiles `targets` against the stdlib sources in test mode and returns the
/// modules to install next to the stdlib (the targets plus the unit_test
/// stand-in) and the targets' test plans.
fn compile_tests(targets: Vec<String>) -> (Vec<(ModuleId, Vec<u8>)>, Vec<ModuleTestPlan>) {
    let (files, result) = Compiler::from_files(targets, move_files("sources"), named_addresses())
        .set_flags(Flags::testing())
        .run::<PASS_CFGIR>()
        .expect("Move sources readable");
    let (_, compiler) = result.unwrap_or_else(|diags| panic!("{}", report(&files, diags)));
    let (mut compiler, cfgir) = compiler.into_ast();
    let plans = construct_test_plan(compiler.compilation_env(), None, &cfgir)
        .expect("test mode builds a plan");
    // A malformed #[test] or #[expected_failure] is a diagnostic, not a
    // missing test; refuse it rather than silently running fewer tests.
    if let Err(diags) = compiler
        .compilation_env()
        .check_diags_at_or_above_severity(Severity::NonblockingError)
    {
        panic!("{}", report(&files, diags));
    }
    let (units, _warnings) = compiler
        .at_cfgir(cfgir)
        .build()
        .unwrap_or_else(|diags| panic!("{}", report(&files, diags)));
    let mut modules = modules_of(units);
    let plans = plans
        .into_iter()
        .filter(|plan| modules.iter().any(|(id, _)| *id == plan.module_id))
        .collect();
    modules.push(compile_unit_test_stand_in());
    (modules, plans)
}

/// A fresh StateDB holding the committed stdlib bytecode and `extra` modules.
fn fresh_db(name: &str, extra: &[(ModuleId, Vec<u8>)]) -> (Arc<StateDB>, PathBuf) {
    let path =
        std::env::temp_dir().join(format!("aincore_move_unit_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&path);
    let db = Arc::new(StateDB::open(path.to_str().expect("utf-8 path")).expect("test DB opens"));
    let _seed = db.seeding();
    let mut modules: Vec<(ModuleId, Vec<u8>)> = fs::read_dir(stdlib_dir("bytecode"))
        .expect("stdlib bytecode exists")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("mv"))
        .map(|path| {
            let bytes = fs::read(&path).expect("module readable");
            let module = move_binary_format::CompiledModule::deserialize(&bytes)
                .expect("module deserializes");
            (module.self_id(), bytes)
        })
        .collect();
    modules.extend(extra.iter().cloned());
    for (id, bytes) in modules {
        let key = crate::state_keys::module_key(id.address(), id.name().as_str());
        db.put(&key, &hex::encode(bytes)).expect("module stored");
    }
    (db, path)
}

/// Why `outcome` does not match `case`, or None when it does.
fn mismatch(case: &TestCase, outcome: &Result<(), VMError>) -> Option<String> {
    match (&case.expected_failure, outcome) {
        (None, Ok(())) => None,
        (None, Err(err)) => Some(format!("failed: {:?}", err)),
        (Some(expected), Ok(())) => Some(format!("expected {:?} but succeeded", expected)),
        // A bare #[expected_failure] would also pass on out-of-gas or a wrong
        // abort, which is how a test comes to prove nothing.
        (Some(ExpectedFailure::Expected), Err(_)) => {
            Some("#[expected_failure] must name an abort_code and a location".to_string())
        }
        (Some(ExpectedFailure::ExpectedWithCodeDEPRECATED(code)), Err(err)) => {
            if err.major_status() == StatusCode::ABORTED && err.sub_status() == Some(*code) {
                None
            } else {
                Some(format!("expected abort {:#x}, got {:?}", code, err))
            }
        }
        (Some(ExpectedFailure::ExpectedWithError(expected)), Err(err)) => {
            if err.major_status() == expected.0
                && err.sub_status() == expected.1
                && *err.location() == expected.2
            {
                None
            } else {
                Some(format!("expected {:?}, got {:?}", expected, err))
            }
        }
    }
}

/// Runs every test in `plans`, each in its own fresh state; returns the
/// number run and the failures.
fn run_plans(modules: &[(ModuleId, Vec<u8>)], plans: &[ModuleTestPlan]) -> (usize, Vec<String>) {
    let mut ran = 0;
    let mut failures = Vec::new();
    for plan in plans {
        for (name, case) in &plan.tests {
            let (db, path) = fresh_db(name, modules);
            let vm = AINCOREVM::new(db);
            let args: Vec<Vec<u8>> = case
                .arguments
                .iter()
                .map(|arg| arg.simple_serialize().expect("test argument serializes"))
                .collect();
            let mut gas = AINCOREGasMeter::new(TEST_GAS_LIMIT);
            let mut session = vm.vm.new_session(&vm.storage);
            let outcome = session
                .execute_function_bypass_visibility(
                    &plan.module_id,
                    IdentStr::new(name).expect("test name is an identifier"),
                    vec![],
                    args,
                    &mut gas,
                )
                .map(|_| ());
            drop(session);
            let verdict = mismatch(case, &outcome);
            println!(
                "{} {}::{} ({} gas)",
                if verdict.is_none() { "PASS" } else { "FAIL" },
                plan.module_id,
                name,
                gas.gas_used()
            );
            if let Some(why) = verdict {
                failures.push(format!("{}::{}: {}", plan.module_id, name, why));
            }
            ran += 1;
            let _ = fs::remove_dir_all(&path);
        }
    }
    (ran, failures)
}

#[test]
fn stdlib_move_unit_tests_pass_on_the_production_vm() {
    let (modules, plans) = compile_tests(move_files("tests"));
    let (ran, failures) = run_plans(&modules, &plans);
    // The count is pinned so a test that stops being discovered (a broken
    // attribute, a file that no longer loads) fails here instead of vanishing.
    assert_eq!(ran, 21, "Move unit tests discovered");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The harness must fail a test whose expectation does not hold. Without this,
/// a runner that treated every outcome as a pass would look exactly like a
/// green suite.
#[test]
fn the_move_test_runner_reports_wrong_outcomes() {
    let dir = std::env::temp_dir().join(format!("aincore_move_unit_meta_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("meta.move");
    fs::write(
        &file,
        r#"
        #[test_only]
        module 0xcafe::runner_meta {
            use 0x1::universal_mining;
            #[test] fun passes() {}
            #[test] fun aborts() { abort 7 }
            #[test]
            #[expected_failure(abort_code = 7, location = Self)]
            fun succeeds_but_should_abort() {}
            #[test]
            #[expected_failure(abort_code = 8, location = Self)]
            fun aborts_with_the_wrong_code() { abort 7 }
            #[test]
            #[expected_failure(abort_code = 0x10005, location = 0x1::universal_mining)]
            fun aborts_in_the_wrong_module() { abort 0x10005 }
            #[test(owner = @0xa11ce)]
            #[expected_failure(abort_code = 0x10005, location = 0x1::universal_mining)]
            fun aborts_where_expected(owner: signer) {
                universal_mining::register_device(&owner, x"00", 1);
            }
        }
        "#,
    )
    .expect("meta test written");
    let (modules, plans) = compile_tests(vec![file.to_string_lossy().into_owned()]);
    let (ran, failures) = run_plans(&modules, &plans);
    let _ = fs::remove_dir_all(&dir);
    assert_eq!(ran, 6);
    let failed: Vec<&str> = failures
        .iter()
        .map(|f| {
            f.split("::")
                .nth(2)
                .and_then(|s| s.split(':').next())
                .unwrap_or("")
        })
        .collect();
    assert_eq!(
        failed,
        vec![
            "aborts",
            "aborts_in_the_wrong_module",
            "aborts_with_the_wrong_code",
            "succeeds_but_should_abort",
        ],
        "{failures:#?}"
    );
}

/// G5 P-1 and CL-2: in the committed bytecode, the genesis-pinned `Params`
/// and the executor-written `Clock` have one Move writer, `chain::initialize`,
/// which refuses a second call (the chain_tests above). Move lets only the
/// declaring module write its resources, so no other module, governance
/// included, can change a parameter or move the clock.
#[test]
fn the_chain_parameters_and_clock_have_no_move_writer_but_initialize() {
    use move_binary_format::{access::ModuleAccess, file_format::Bytecode, CompiledModule};
    let bytes = fs::read(stdlib_dir("bytecode").join("chain.mv")).expect("chain.mv committed");
    let module = CompiledModule::deserialize(&bytes).expect("chain.mv deserializes");
    let mut writes = std::collections::BTreeSet::new();
    for def in module.function_defs() {
        let function = module
            .identifier_at(module.function_handle_at(def.function).name)
            .to_string();
        for instruction in def.code.iter().flat_map(|unit| unit.code.iter()) {
            let target = match instruction {
                Bytecode::MoveTo(i) | Bytecode::MoveFrom(i) | Bytecode::MutBorrowGlobal(i) => *i,
                Bytecode::MoveToGeneric(_)
                | Bytecode::MoveFromGeneric(_)
                | Bytecode::MutBorrowGlobalGeneric(_) => panic!("chain has no generic resource"),
                _ => continue,
            };
            let handle = module.struct_handle_at(module.struct_def_at(target).struct_handle);
            writes.insert((
                function.clone(),
                module.identifier_at(handle.name).to_string(),
            ));
        }
    }
    let expected = [("initialize", "Clock"), ("initialize", "Params")]
        .map(|(f, r)| (f.to_string(), r.to_string()));
    assert_eq!(writes, expected.into_iter().collect());
}

/// G5 CL-1: no stdlib module has a wall clock. Every deadline reads
/// `chain::height`, so a halted chain ages nothing; a `timestamp` module, or
/// a field or function named for seconds, time or a duration, is how a
/// second clock would come back. Identifiers, not source text, so comments
/// that explain the old clock do not count.
#[test]
fn no_stdlib_module_has_a_wall_clock() {
    use move_binary_format::{access::ModuleAccess, CompiledModule};
    let mut found = Vec::new();
    for entry in fs::read_dir(stdlib_dir("bytecode"))
        .expect("stdlib bytecode exists")
        .flatten()
    {
        let bytes = fs::read(entry.path()).expect("module readable");
        let module = CompiledModule::deserialize(&bytes).expect("module deserializes");
        for ident in module.identifiers() {
            let ident = ident.as_str().to_ascii_lowercase();
            if ["time", "second", "duration", "clock_secs"]
                .iter()
                .any(|w| ident.contains(w))
            {
                found.push(format!("{}: {}", module.self_id().name(), ident));
            }
        }
    }
    assert!(found.is_empty(), "wall-clock identifiers: {found:?}");
}

/// The committed bytecode is what genesis installs and what the tests above
/// run, but the Dockerfile rebuilds it from the sources. Both must agree, or
/// the stdlib_hash pinned in genesis.json names code no image runs.
#[test]
fn committed_stdlib_bytecode_matches_its_sources() {
    let (files, result) = Compiler::from_files(move_files("sources"), vec![], named_addresses())
        .build()
        .expect("Move sources readable");
    let (units, _warnings) = result.unwrap_or_else(|diags| panic!("{}", report(&files, diags)));
    let compiled = modules_of(units);
    let mut committed: Vec<String> = fs::read_dir(stdlib_dir("bytecode"))
        .expect("stdlib bytecode exists")
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.ends_with(".mv"))
        .collect();
    committed.sort();
    let mut expected: Vec<String> = compiled
        .iter()
        .map(|(id, _)| format!("{}.mv", id.name()))
        .collect();
    expected.sort();
    assert_eq!(committed, expected, "one committed .mv per compiled module");
    for (id, bytes) in compiled {
        let on_disk = fs::read(stdlib_dir("bytecode").join(format!("{}.mv", id.name())))
            .expect("committed module readable");
        assert!(
            on_disk == bytes,
            "stdlib/bytecode/{}.mv is stale: recompile with move_compiler_tool",
            id.name()
        );
    }
}
