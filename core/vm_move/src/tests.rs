#![allow(clippy::module_inception)]
#[cfg(test)]
mod tests {
    use crate::{EntryFunctionCall, TransactionPayload};
    use move_core_types::account_address::AccountAddress;
    use move_core_types::identifier::Identifier;
    use move_core_types::language_storage::{ModuleId, StructTag, TypeTag};

    fn system_address() -> AccountAddress {
        AccountAddress::from_hex_literal("0x1").unwrap()
    }

    fn parse_addr(hex_addr: &str) -> AccountAddress {
        AccountAddress::from_hex_literal(&format!("0x{}", hex_addr)).unwrap()
    }

    fn aincore_coin_type() -> TypeTag {
        TypeTag::Struct(Box::new(StructTag {
            address: system_address(),
            module: Identifier::new("staking").unwrap(),
            name: Identifier::new("AincoreCoin").unwrap(),
            type_params: vec![],
        }))
    }

    /// Golden BCS vectors for the canonical transaction payloads. Updated for
    /// #35: AINCORE addresses are 32 bytes (`address32`), so every embedded
    /// AccountAddress now serializes as 32 raw bytes (and address-typed `args`
    /// carry a 0x20 length prefix). The JS SDK must be regenerated to match.
    #[test]
    fn test_bcs_payload_golden_vectors_match_js_sdk() {
        let sender = "fe812c12f3ab4ce6ac5db69ac352f906";
        let recipient = "5c29b78f10a35a49a6231d08ee840a04";

        let transfer = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("coin").unwrap()),
            function: "transfer".to_string(),
            ty_args: vec![aincore_coin_type()],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes(&parse_addr(recipient)).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&transfer).unwrap()),
            "01000000000000000000000000000000000000000000000000000000000000000104636f696e087472616e7366657201070000000000000000000000000000000000000000000000000000000000000001077374616b696e670b41696e636f7265436f696e00032000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f90620000000000000000000000000000000005c29b78f10a35a49a6231d08ee840a041064000000000000000000000000000000"
        );

        let publish = TransactionPayload::PublishModule(vec![vec![0xca, 0xfe, 0xba, 0xbe]]);
        assert_eq!(
            hex::encode(bcs::to_bytes(&publish).unwrap()),
            "020104cafebabe"
        );

        let register_validator = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("staking").unwrap()),
            function: "join_validator_set".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes(&123456789u128).unwrap(),
                bcs::to_bytes(
                    &hex::decode(
                        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
                    )
                    .unwrap(),
                )
                .unwrap(),
                bcs::to_bytes(&vec![0x11u8; 48]).unwrap(),
                bcs::to_bytes(&vec![0x22u8; 96]).unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&register_validator).unwrap()),
            "010000000000000000000000000000000000000000000000000000000000000001077374616b696e67126a6f696e5f76616c696461746f725f73657400052000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f9061015cd5b070000000000000000000000002120ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c31301111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111116160222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
        );

        let create_token = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("token_factory").unwrap()),
            function: "create_token".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes("Ain Token").unwrap(),
                bcs::to_bytes("AINX").unwrap(),
                bcs::to_bytes(&8u8).unwrap(),
                bcs::to_bytes(&1_000_000_000_000u128).unwrap(),
                bcs::to_bytes(&12_345u128).unwrap(),
                bcs::to_bytes("ipfs://icon").unwrap(),
                bcs::to_bytes("https://aincore.test").unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&create_token).unwrap()),
            "0100000000000000000000000000000000000000000000000000000000000000010d746f6b656e5f666163746f72790c6372656174655f746f6b656e00082000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f9060a0941696e20546f6b656e050441494e580108100010a5d4e8000000000000000000000010393000000000000000000000000000000c0b697066733a2f2f69636f6e151468747470733a2f2f61696e636f72652e74657374"
        );

        let delegate = TransactionPayload::EntryFunction(EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("delegation").unwrap()),
            function: "delegate".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_addr(sender)).unwrap(),
                bcs::to_bytes(&parse_addr(recipient)).unwrap(),
                bcs::to_bytes(&555u128).unwrap(),
            ],
        });
        assert_eq!(
            hex::encode(bcs::to_bytes(&delegate).unwrap()),
            "0100000000000000000000000000000000000000000000000000000000000000010a64656c65676174696f6e0864656c656761746500032000000000000000000000000000000000fe812c12f3ab4ce6ac5db69ac352f90620000000000000000000000000000000005c29b78f10a35a49a6231d08ee840a04102b020000000000000000000000000000"
        );
    }

    #[test]
    fn test_account_address_is_32_bytes() {
        assert_eq!(AccountAddress::LENGTH, 32);

        // A full 64-hex literal must parse to a 32-byte address.
        let hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let addr = AccountAddress::from_hex_literal(&format!("0x{}", hex64))
            .expect("64-hex literal must parse with address32");
        assert_eq!(addr.to_vec().len(), 32);
        assert_eq!(addr.to_string(), hex64);

        // System address 0x1 left-pads to 32 bytes.
        let one = AccountAddress::from_hex_literal("0x1").unwrap();
        assert_eq!(one, AccountAddress::ONE);
        assert_eq!(one.to_vec().len(), 32);
    }

    /// B69: the VM runs with Aptos's production module limits, not move's
    /// unbounded defaults. B93: and no dependency depth of its own (it
    /// depended on the module cache); the executor bounds it from storage.
    #[test]
    fn the_vm_runs_with_the_production_verifier_limits() {
        let config = crate::AINCOREVM::vm_config().verifier;
        assert_eq!(config.max_dependency_depth, None);
        assert_eq!(config.max_loop_depth, Some(5));
        assert_eq!(config.max_generic_instantiation_length, Some(32));
        assert_eq!(config.max_function_parameters, Some(128));
        assert_eq!(config.max_basic_blocks, Some(1024));
        assert_eq!(config.max_type_nodes, Some(256));
        assert_eq!(config.max_push_size, Some(10_000));
        assert_eq!(config.max_struct_definitions, Some(200));
        assert_eq!(config.max_fields_in_struct, Some(64));
        assert_eq!(config.max_function_definitions, Some(1000));
        assert!(
            config.max_per_mod_meter_units.is_some(),
            "verification is metered"
        );
    }

    /// B211, B212, B214: the runtime checks Aptos runs in production: a
    /// type check at every instruction (a type confusion the verifier let
    /// through panicked outside move's unwinding guard), the bound on a
    /// call's type-argument size, and the bytecode version pinned at the
    /// stdlib's own (6), not a future move's maximum.
    #[test]
    fn the_vm_runs_with_the_production_runtime_checks() {
        let config = crate::AINCOREVM::vm_config();
        assert!(config.paranoid_type_checks, "no type check at run time");
        assert!(config.type_size_limit, "no type-argument size bound");
        assert_eq!(config.max_binary_format_version, 6);
        assert!(config.enable_invariant_violation_check_in_swap_loc);
    }

    /// B430 witness: every Move session runs on the VM's own threads
    /// (`move-vm-*`, `VM_STACK_BYTES` of stack each), whatever thread asks:
    /// here one with 64 KiB, which a session on its caller's stack overflows
    /// in a debug build. Sessions ran on their caller's thread, a 2 MiB
    /// tokio or rayon worker, where a value at B343's depth bound did not
    /// fit.
    #[test]
    fn every_session_runs_on_the_vm_stack() {
        let path =
            storage::test_dir::process_dir().join(format!("vm_stack_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let db = std::sync::Arc::new(storage::StateDB::open(path.to_str().unwrap()).unwrap());
        let vm = crate::AINCOREVM::new(db);
        let sender = parse_addr("ab");
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .stack_size(64 << 10)
                .spawn_scoped(scope, || {
                    let _ =
                        vm.publish_modules(vec![vec![0xa1, 0x1c, 0xeb, 0x0b]], sender, 1_000_000);
                    let call = crate::MoveAction::CallEntryFunction(EntryFunctionCall {
                        module: ModuleId::new(system_address(), Identifier::new("coin").unwrap()),
                        function: "no_such_function".to_string(),
                        ty_args: vec![],
                        args: vec![],
                    });
                    // A user stage alone (no prologue) opens its own session.
                    let _ = vm.execute_transaction_actions(
                        vec![(call.clone(), false, sender)],
                        sender,
                        1_000_000,
                    );
                    let pay = crate::MoveAction::CallEntryFunction(EntryFunctionCall {
                        module: ModuleId::new(system_address(), Identifier::new("coin").unwrap()),
                        function: "no_such_function".to_string(),
                        ty_args: vec![],
                        args: vec![],
                    });
                    let _ = vm.execute_transaction_actions(
                        vec![(pay, true, sender), (call, false, sender)],
                        sender,
                        1_000_000,
                    );
                })
                .unwrap()
                .join()
                .unwrap();
        });
        let threads = crate::SESSION_THREADS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert!(threads.len() >= 3, "vacuous: sessions opened {threads:?}");
        assert!(
            threads.iter().all(|t| t.starts_with("move-vm-")),
            "a session ran off the VM's stack: {threads:?}"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    /// B434 witness: a worker of another rayon pool (one thread, 256 KiB of
    /// stack) asking 200 sessions in a parallel loop hands each to a thread
    /// of its own and nests nothing. On `VM_POOL.install` such a worker ran
    /// the loop's other items on its own stack while it waited, nesting
    /// them until it overflowed.
    #[test]
    fn a_foreign_pool_worker_hands_its_sessions_off() {
        use rayon::prelude::*;
        let path =
            storage::test_dir::process_dir().join(format!("vm_foreign_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let db = std::sync::Arc::new(storage::StateDB::open(path.to_str().unwrap()).unwrap());
        let vm = crate::AINCOREVM::new(db);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .stack_size(256 << 10)
            .build()
            .unwrap();
        let before = crate::FOREIGN_POOL_HANDOFFS.load(std::sync::atomic::Ordering::SeqCst);
        let sender = parse_addr("ab");
        let ran = pool.install(|| {
            (0..200u32)
                .into_par_iter()
                .map(|_| {
                    vm.publish_modules(vec![vec![0xa1, 0x1c, 0xeb, 0x0b]], sender, 1_000_000)
                        .is_err()
                })
                .filter(|refused| *refused)
                .count()
        });
        assert_eq!(ran, 200, "vacuous: a module was published");
        let handed =
            crate::FOREIGN_POOL_HANDOFFS.load(std::sync::atomic::Ordering::SeqCst) - before;
        assert!(handed >= 200, "sessions were not handed off: {handed}");
        let _ = std::fs::remove_dir_all(&path);
    }

    /// B447 witness: dry runs whose sessions never end hold none of the
    /// VM's threads: a block's work still runs on them at once. Here as many
    /// dry runs as the VM has threads each hold a session until released;
    /// on `VM_POOL` (B430) they took every thread, and a block's batch (its
    /// `on_vm_threads`) waited behind them.
    #[test]
    fn dry_runs_never_hold_the_block_threads() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Condvar, Mutex};
        use std::time::{Duration, Instant};
        let vm_threads = crate::on_vm_threads(rayon::current_num_threads);
        let released = (Mutex::new(false), Condvar::new());
        let started = AtomicUsize::new(0);
        let release = || {
            *released.0.lock().unwrap_or_else(|e| e.into_inner()) = true;
            released.1.notify_all();
        };
        let (all_started, block) = std::thread::scope(|scope| {
            for _ in 0..vm_threads {
                scope.spawn(|| {
                    crate::on_dry_run_thread(|| {
                        crate::on_vm_stack(|| {
                            started.fetch_add(1, Ordering::SeqCst);
                            let mut done = released.0.lock().unwrap_or_else(|e| e.into_inner());
                            while !*done {
                                done = released.1.wait(done).unwrap_or_else(|e| e.into_inner());
                            }
                        })
                    })
                    .expect("a dry run's thread")
                });
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            while started.load(Ordering::SeqCst) < vm_threads && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let all_started = started.load(Ordering::SeqCst) == vm_threads;
            let (sender, receiver) = std::sync::mpsc::channel();
            scope.spawn(move || {
                let _ = sender.send(crate::on_vm_threads(|| 7));
            });
            let block = receiver.recv_timeout(Duration::from_secs(20));
            // Released before anything is asserted: a failure holds nothing.
            release();
            (all_started, block)
        });
        assert!(all_started, "vacuous: the dry runs did not all start");
        assert_eq!(block, Ok(7), "a block's work waited for the dry runs");
    }

    /// B473 witness: every call a Move session runs goes through
    /// `run_action`, which binds every signer to the authenticated principal
    /// (`bind_signer_args`) and admits only primitive argument types. The
    /// public `execute_script` ran a script in a session of its own, and
    /// move-vm builds a script's signers from the caller's bytes, so the
    /// bytes of @0x1 made a signer that mints. The crate's sources are read,
    /// so a new way to run code in a session is caught without editing this
    /// test.
    #[test]
    fn every_move_call_runs_through_the_signer_binding() {
        let sources = [
            include_str!("lib.rs"),
            include_str!("gas.rs"),
            include_str!("overlay.rs"),
            include_str!("state_keys.rs"),
        ];
        let calls = |name: &str| {
            let mut found = 0;
            for source in sources {
                found += source.matches(name).count();
            }
            found
        };
        assert_eq!(
            calls(".execute_script("),
            0,
            "a session runs a script, its signers built from the caller's bytes"
        );
        assert_eq!(
            calls(".execute_function_bypass_visibility("),
            0,
            "a session runs a function past the entry checks"
        );
        assert_eq!(
            calls(".execute_entry_function("),
            1,
            "an entry function runs outside run_action"
        );
        let lib = sources[0];
        let start = lib.find("fn run_action<").expect("run_action is defined");
        let end = start
            + lib[start..]
                .find("\n    fn ")
                .expect("a function follows run_action");
        let body = &lib[start..end];
        let bind = body
            .find("Self::bind_signer_args(")
            .expect("run_action binds the signers");
        let entry = body
            .find(".execute_entry_function(")
            .expect("the entry call is in run_action");
        assert!(
            bind < entry,
            "the entry function runs before its signers are bound"
        );
        assert!(
            body[entry..].contains("bound_args,"),
            "the entry function runs on the caller's own bytes"
        );
    }
}
