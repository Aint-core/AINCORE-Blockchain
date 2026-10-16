// B65 witnesses: a transaction pays for its writes. Included in `tests`.
use super::*;
use crate::state_gas::{
    history_gas, next_state_byte_gas, write_cost, WriteCost, BODY_BLOCKS_KEPT, GAS_PER_HISTORY_ROW,
    HISTORY_BLOCKS_HELD, HISTORY_GAS_PER_KEY, HISTORY_GAS_PER_OLD_BYTE, IO_BYTES_PER_GAS,
    IO_GAS_PER_WRITE, MIN_STATE_BYTE_GAS, NEW_KEY_BYTES, STATE_BYTE_GAS_KEY, TARGET_STATE_BYTES,
};
use move_core_types::account_address::AccountAddress;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;

/// tests/fixtures/blob.move: `store`, `resize` and `remove` a resource of a
/// chosen size, and `spin` until the gas runs out.
const BLOB: &[u8] = include_bytes!("../tests/fixtures/blob.mv");

fn blob_address() -> AccountAddress {
    AccountAddress::from_hex_literal("0xcafe").expect("an address")
}

/// The stdlib, the blob module at 0xcafe, and a sender (account and coins)
/// from `seed`.
fn blob_chain(name: &str, seed: u8) -> (Arc<StateDB>, SigningKey, String) {
    let db = temp_db(name);
    load_stdlib(&db);
    let key = SigningKey::from_bytes(&[seed; 32]);
    let sender = create_account(&db, &key);
    {
        let _seed = db.seeding();
        let module = CompiledModule::deserialize(BLOB).expect("the fixture deserializes");
        let id = module.self_id();
        db.put(
            &format!("module_{}_{}", id.address(), id.name()),
            &hex::encode(BLOB),
        )
        .expect("module stored");
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
    }
    set_coin_store(&db, &sender, 1_000_000_000_000);
    (db, key, sender)
}

/// A call of `0xcafe::blob::{function}`; a signer slot first when `signer`.
fn blob_call(function: &str, signer: Option<&str>, n: Option<u64>) -> String {
    let mut args = Vec::new();
    if let Some(sender) = signer {
        args.push(bcs::to_bytes(&parse_move_address(sender).unwrap()).unwrap());
    }
    if let Some(n) = n {
        args.push(bcs::to_bytes(&n).unwrap());
    }
    let call = EntryFunctionCall {
        module: ModuleId::new(blob_address(), Identifier::new("blob").unwrap()),
        function: function.to_string(),
        ty_args: vec![],
        args,
    };
    hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
}

fn blob_key(sender: &str) -> String {
    vm_move::state_keys::resource_key_str(
        &parse_move_address(sender).unwrap(),
        "0xcafe::blob::Blob",
    )
}

fn receipt_status(db: &StateDB, tx_json: &str) -> String {
    let receipt = db
        .get(&format!("tx_receipt:{}", tx_hash_hex(tx_json)))
        .unwrap()
        .expect("receipt stored");
    let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
    receipt["status"].as_str().unwrap().to_string()
}

/// Executes `tx_json` alone and applies what it wrote; `None` if it did not
/// execute.
fn run(db: &StateDB, executor: &Executor, tx_json: &str) -> Option<()> {
    let (updates, _) = executor.execute_transaction(tx_json)?;
    let _seed = db.seeding();
    apply_updates(db, updates);
    Some(())
}

/// B150 witness: a module named `<SELF>` (Move accepts the name; the
/// state's classifier does not) aborts its own publish, charged. Its key
/// reached the block's write batch, which the gate refused whole, and every
/// validator panicked at that block for good.
#[test]
fn a_module_the_state_cannot_hold_aborts_its_publish() {
    let (db, key, sender) = blob_chain("b150_self", 62);
    let executor = Executor::new(db.clone());
    let mut module = CompiledModule::deserialize(BLOB).expect("the fixture deserializes");
    let handle = module.module_handles[module.self_module_handle_idx.0 as usize].clone();
    module.identifiers[handle.name.0 as usize] =
        Identifier::new("<SELF>").expect("Move accepts the name");
    module.address_identifiers[handle.address.0 as usize] = parse_move_address(&sender).unwrap();
    let mut bytes = Vec::new();
    module.serialize(&mut bytes).expect("it serializes");
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![bytes])).unwrap(),
    );
    let tx = signed_tx(&key, &sender, &payload, 0, 1_000_000, 1);
    let balance = coin_balance(&db, &sender);
    let (updates, _) = executor
        .execute_transaction(&tx)
        .expect("executed, charged");
    let unheld: Vec<&String> = updates
        .iter()
        .map(|(k, _)| k)
        .filter(|k| storage::class::classify(k.as_bytes()).is_none())
        .collect();
    assert!(
        unheld.is_empty(),
        "a write the state cannot hold: {unheld:?}"
    );
    run_updates(&db, updates);
    assert_eq!(receipt_status(&db, &tx), "aborted");
    let receipt: serde_json::Value = serde_json::from_str(
        &db.get(&format!("tx_receipt:{}", tx_hash_hex(&tx)))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(
        receipt["error"]
            .as_str()
            .is_some_and(|e| e.contains("cannot hold")),
        "vacuous: aborted for another reason: {receipt}"
    );
    assert!(
        coin_balance(&db, &sender) < balance,
        "the publish was not charged"
    );
}

/// B340: a module at 0xcafe (`nv`) whose entry `native_push` calls
/// `0x1::vector::push_back<u64>` as a function, and whose `opcode_push` uses
/// the `VecPushBack` opcode the compiler emits for that call.
fn vector_native_module() -> Vec<u8> {
    use move_binary_format::file_format::{
        empty_module, AbilitySet, AddressIdentifierIndex, Bytecode, CodeUnit, FunctionDefinition,
        FunctionHandle, FunctionHandleIndex, FunctionInstantiation, FunctionInstantiationIndex,
        IdentifierIndex, ModuleHandle, ModuleHandleIndex, Signature, SignatureIndex,
        SignatureToken, Visibility,
    };
    let mut m = empty_module();
    m.address_identifiers = vec![blob_address(), AccountAddress::ONE];
    m.identifiers = ["nv", "vector", "push_back", "native_push", "opcode_push"]
        .iter()
        .map(|name| Identifier::new(*name).unwrap())
        .collect();
    m.module_handles.push(ModuleHandle {
        address: AddressIdentifierIndex(1),
        name: IdentifierIndex(1),
    });
    m.signatures = vec![
        Signature(vec![]),
        Signature(vec![
            SignatureToken::MutableReference(Box::new(SignatureToken::Vector(Box::new(
                SignatureToken::TypeParameter(0),
            )))),
            SignatureToken::TypeParameter(0),
        ]),
        Signature(vec![SignatureToken::U64]),
        Signature(vec![SignatureToken::Vector(Box::new(SignatureToken::U64))]),
    ];
    let handle = |module: u16, name: u16, parameters: u16, type_parameters: Vec<AbilitySet>| {
        FunctionHandle {
            module: ModuleHandleIndex(module),
            name: IdentifierIndex(name),
            parameters: SignatureIndex(parameters),
            return_: SignatureIndex(0),
            type_parameters,
        }
    };
    m.function_handles = vec![
        handle(1, 2, 1, vec![AbilitySet::EMPTY]),
        handle(0, 3, 0, vec![]),
        handle(0, 4, 0, vec![]),
    ];
    m.function_instantiations = vec![FunctionInstantiation {
        handle: FunctionHandleIndex(0),
        type_parameters: SignatureIndex(2),
    }];
    let entry = |function: u16, push: Bytecode| FunctionDefinition {
        function: FunctionHandleIndex(function),
        visibility: Visibility::Public,
        is_entry: true,
        acquires_global_resources: vec![],
        code: Some(CodeUnit {
            locals: SignatureIndex(3),
            code: vec![
                Bytecode::VecPack(SignatureIndex(2), 0),
                Bytecode::StLoc(0),
                Bytecode::MutBorrowLoc(0),
                Bytecode::LdU64(7),
                push,
                Bytecode::Ret,
            ],
        }),
    };
    m.function_defs = vec![
        entry(1, Bytecode::CallGeneric(FunctionInstantiationIndex(0))),
        entry(2, Bytecode::VecPushBack(SignatureIndex(2))),
    ];
    let mut bytes = vec![];
    m.serialize(&mut bytes).unwrap();
    bytes
}

/// B340 witness: a `std::vector` native called as a function aborts,
/// charged (its `push_back` took the pushed value off the memory quota while
/// the vector kept it, so the quota stopped bounding memory); the opcode
/// the compiler emits for the same call runs.
#[test]
fn a_vector_native_called_as_a_function_aborts() {
    let (db, key, sender) = blob_chain("b340_natives", 61);
    {
        let _seed = db.seeding();
        db.put(
            &vm_move::state_keys::module_key(&blob_address(), "nv"),
            &hex::encode(vector_native_module()),
        )
        .unwrap();
    }
    let executor = Executor::new(db.clone());
    let call = |function: &str| {
        let call = EntryFunctionCall {
            module: ModuleId::new(blob_address(), Identifier::new("nv").unwrap()),
            function: function.to_string(),
            ty_args: vec![],
            args: vec![],
        };
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
    };
    let opcode = signed_tx(&key, &sender, &call("opcode_push"), 0, 1_000_000, 1);
    run(&db, &executor, &opcode).expect("executed");
    assert_eq!(
        receipt_status(&db, &opcode),
        "success",
        "vacuous: the module does not run"
    );
    let native = signed_tx(&key, &sender, &call("native_push"), 1, 1_000_000, 1);
    let balance = coin_balance(&db, &sender);
    run(&db, &executor, &native).expect("executed, charged");
    assert_eq!(receipt_status(&db, &native), "aborted");
    let receipt: serde_json::Value = serde_json::from_str(
        &db.get(&format!("tx_receipt:{}", tx_hash_hex(&native)))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let code = vm_move::BYTECODE_ONLY_NATIVE.to_string();
    assert!(
        receipt["error"].as_str().is_some_and(|e| e.contains(&code)),
        "vacuous: aborted for another reason: {receipt}"
    );
    assert!(
        coin_balance(&db, &sender) < balance,
        "the abort was not charged"
    );
}

/// B343 witness: a publish defining a struct that nests past 128 levels is
/// a charged abort, before the VM loads it (a chain packed in memory nested
/// ~20,000 deep, and the stack overflowed on every node).
#[test]
fn a_publish_nesting_too_deep_aborts_charged() {
    let (db, key, sender) = blob_chain("b343_publish", 60);
    let executor = Executor::new(db.clone());
    let at = parse_move_address(&sender).unwrap();
    let module = crate::deps::tests::deep_module(at, 128, 0, 0);
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![module])).unwrap(),
    );
    let balance = coin_balance(&db, &sender);
    let tx = signed_tx(&key, &sender, &payload, 0, 1_000_000, 1);
    run(&db, &executor, &tx).expect("executed, charged");
    assert_eq!(receipt_status(&db, &tx), "aborted");
    let receipt: serde_json::Value = serde_json::from_str(
        &db.get(&format!("tx_receipt:{}", tx_hash_hex(&tx)))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(
        receipt["error"]
            .as_str()
            .is_some_and(|e| e.contains("nests 129 deep")),
        "vacuous: aborted for another reason: {receipt}"
    );
    assert!(
        coin_balance(&db, &sender) < balance,
        "the abort was not charged"
    );
}

/// B170 witness: a republish pays for the version it replaces and that
/// version's closure (its compatibility check loads them), and a module
/// republished earlier in the block is refused to anything that loads it.
#[test]
fn a_republish_pays_for_what_it_replaces() {
    let (db, _key, _sender) = blob_chain("b170_roots", 63);
    let index = deps::ModuleIndex::default();
    let blob = CompiledModule::deserialize(BLOB)
        .expect("the fixture deserializes")
        .self_id();
    let roots = deps::bundle_roots(&[BLOB.to_vec()]).expect("it parses");
    assert!(roots.contains(&blob), "the replaced module is not paid for");
    let stored = index.closure(&db, roots.clone()).expect("a closure");
    assert_eq!(stored.modules, 2, "blob as stored and the signer it loads");
    let key = vm_move::state_keys::module_key(blob.address(), blob.name().as_str());
    let upgraded: std::collections::HashSet<String> = [key].into_iter().collect();
    let refused = index
        .closure_in_block(&db, roots, &upgraded)
        .expect_err("an upgraded module was loaded");
    assert!(refused.contains("upgraded in this block"), "{refused}");
}

/// Applies `updates` as a block would (seeding: a test outside the block).
fn run_updates(db: &StateDB, updates: Vec<(String, Option<String>)>) {
    let _seed = db.seeding();
    apply_updates(db, updates);
}

#[test]
fn an_estimate_counts_payer_history_once_when_the_payload_changes_it() {
    let (db, key, sender) = blob_chain("estimate_payer_history_once", 73);
    let recipient = create_account(&db, &SigningKey::from_bytes(&[74; 32]));
    set_coin_store(&db, &recipient, 0);
    let executor = Executor::new(db.clone());
    let payload = coin_transfer_payload(&sender, &recipient, 100);
    let before = coin_balance(&db, &sender);
    let estimate = executor
        .estimate_gas(&signed_tx(&key, &sender, &payload, 0, 0, 1))
        .unwrap();
    assert_eq!(estimate.aborted, None);
    let raw = signed_tx(&key, &sender, &payload, 0, estimate.execution_gas(), 1);
    let (updates, _) = executor.execute_transaction(&raw).expect("transfer admitted");
    assert_eq!(estimate.writes, write_cost(&db, &updates), "history counted once");
    assert_eq!(coin_balance(&db, &sender), before, "simulation does not write");
    run_updates(&db, updates);
    assert_eq!(receipt_status(&db, &raw), "success");
    assert_eq!(coin_balance(&db, &recipient), 100);
    assert_eq!(coin_balance(&db, &sender), before - gas_of(&raw) as u128 - 100);
}

/// B65 witness: a new resource costs its key, its value and the tree's rows
/// at the state byte gas, on top of execution. A limit one gas short of the
/// estimate aborts, charged, and stores nothing; the estimate itself runs.
#[test]
fn a_transaction_pays_for_the_state_bytes_it_adds() {
    let (db, key, sender) = blob_chain("b65_new_state", 61);
    let executor = Executor::new(db.clone());
    let store = blob_call("store", Some(&sender), Some(1_000));
    let estimate = executor
        .estimate_gas(&signed_tx(&key, &sender, &store, 0, 0, 1))
        .expect("the estimate runs");
    assert_eq!(estimate.aborted, None);
    assert_eq!(estimate.state_byte_gas, MIN_STATE_BYTE_GAS);
    // The resource's value is the hex of its BCS: a 2-byte length and 1,000
    // bytes. Every other write rewrites a value of the same length.
    let value_len = 2 * (2 + 1_000);
    assert_eq!(
        estimate.writes.new_bytes,
        (blob_key(&sender).len() + value_len) as u64 + NEW_KEY_BYTES
    );
    let larger = executor
        .estimate_gas(&signed_tx(
            &key,
            &sender,
            &blob_call("store", Some(&sender), Some(2_000)),
            0,
            0,
            1,
        ))
        .unwrap();
    assert_eq!(larger.writes.new_bytes - estimate.writes.new_bytes, 2_000);
    let needed = estimate.execution_gas();

    // Execution and I/O paid, the new bytes not: aborted, charged.
    let unpriced = estimate.vm_gas + estimate.writes.io_gas;
    assert!(unpriced + estimate.writes.new_bytes * MIN_STATE_BYTE_GAS <= needed);
    let no_bytes = signed_tx(&key, &sender, &store, 0, unpriced, 1);
    run(&db, &executor, &no_bytes).expect("charged");
    assert_eq!(receipt_status(&db, &no_bytes), "aborted");

    let short = signed_tx(&key, &sender, &store, 1, needed - 1, 1);
    run(&db, &executor, &short).expect("charged");
    assert_eq!(receipt_status(&db, &short), "aborted");
    assert_eq!(db.get(&blob_key(&sender)).unwrap(), None, "nothing stored");

    let enough = signed_tx(&key, &sender, &store, 2, needed, 1);
    run(&db, &executor, &enough).expect("executes");
    assert_eq!(receipt_status(&db, &enough), "success");
    assert_eq!(
        db.get(&blob_key(&sender)).unwrap().map(|v| v.len()),
        Some(value_len)
    );

    // An estimate runs whatever the base fee: it is asked before the price.
    {
        let _seed = db.seeding();
        db.put(BASE_FEE_KEY, "1000").unwrap();
    }
    let resize = blob_call("resize", Some(&sender), Some(1_500));
    let grown = executor
        .estimate_gas(&signed_tx(&key, &sender, &resize, 3, 0, 1))
        .expect("an estimate under a higher base fee");
    assert_eq!(grown.writes.new_bytes, 1_000, "500 bytes more, in hex");
}

/// B65 witness: what a set of writes costs. Growth counts, a shrink or a
/// delete adds nothing (no refunds), a key written twice counts once at its
/// last value, history keys are not state, and every state write pays I/O
/// (and, B460, each change the tree history it leaves).
#[test]
fn only_added_state_bytes_are_charged_and_nothing_is_refunded() {
    let db = temp_db("b65_write_cost");
    let account = format!("obj:{}", "aa".repeat(32));
    let fresh = format!("obj:{}", "bb".repeat(32));
    let old = "x".repeat(100);
    {
        let _seed = db.seeding();
        db.put(&account, &old).unwrap();
    }
    let cost = |writes: &[(&str, Option<&str>)]| {
        let writes: Vec<(String, Option<String>)> = writes
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
            .collect();
        write_cost(&db, &writes)
    };
    let grown = "x".repeat(130);
    assert_eq!(cost(&[(&account, Some(&grown))]).new_bytes, 30);
    assert_eq!(cost(&[(&account, Some("x"))]).new_bytes, 0);
    assert_eq!(cost(&[(&account, None)]).new_bytes, 0);
    assert_eq!(
        cost(&[(&fresh, Some("yy"))]).new_bytes,
        (fresh.len() + 2) as u64 + NEW_KEY_BYTES
    );
    let long = "y".repeat(50);
    assert_eq!(
        cost(&[(&fresh, Some(&long)), (&fresh, Some("yy"))]),
        cost(&[(&fresh, Some("yy"))])
    );
    let receipt = format!("tx_receipt:{}", "cd".repeat(32));
    assert_eq!(cost(&[(&receipt, Some("a receipt"))]), WriteCost::default());
    assert_eq!(
        cost(&[(&account, Some(&grown))]).io_gas,
        IO_GAS_PER_WRITE
            + ((account.len() + 130) as u64).div_ceil(IO_BYTES_PER_GAS)
            + history_gas(Some(old.as_str()))
    );
    assert_eq!(
        cost(&[(&account, None)]).io_gas,
        IO_GAS_PER_WRITE
            + (account.len() as u64).div_ceil(IO_BYTES_PER_GAS)
            + history_gas(Some(old.as_str()))
    );
}

/// B460 witness: every change to a state key pays for the tree history it
/// leaves, even one that adds no state: a rewrite of the same length, a
/// delete (its old value row and path), a new key (its path's nodes, no
/// old value). The same bytes, or a delete of an absent key, change nothing
/// and pay I/O only. Before B460 each paid I/O only.
#[test]
fn a_changed_key_pays_for_the_history_it_leaves() {
    let db = temp_db("b460_history");
    let account = format!("obj:{}", "aa".repeat(32));
    let fresh = format!("obj:{}", "bb".repeat(32));
    let old = "x".repeat(100);
    {
        let _seed = db.seeding();
        db.put(&account, &old).unwrap();
    }
    let cost = |key: &str, value: Option<&str>| {
        write_cost(&db, &[(key.to_string(), value.map(str::to_string))])
    };
    let io = |key: &str, value: Option<&str>| {
        let written = (key.len() + value.map_or(0, str::len)) as u64;
        IO_GAS_PER_WRITE + written.div_ceil(IO_BYTES_PER_GAS)
    };
    let kept = HISTORY_GAS_PER_KEY + 100 * HISTORY_GAS_PER_OLD_BYTE;
    assert_eq!(history_gas(Some(old.as_str())), kept);
    let same_length = "y".repeat(100);
    let rewrite = cost(&account, Some(same_length.as_str()));
    assert_eq!(rewrite.new_bytes, 0, "a rewrite adds no state");
    assert_eq!(
        rewrite.io_gas,
        io(&account, Some(same_length.as_str())) + kept
    );
    assert_eq!(cost(&account, None).io_gas, io(&account, None) + kept);
    assert_eq!(
        cost(&fresh, Some("yy")).io_gas,
        io(&fresh, Some("yy")) + HISTORY_GAS_PER_KEY
    );
    assert_eq!(
        cost(&account, Some(old.as_str())).io_gas,
        io(&account, Some(old.as_str())),
        "the same bytes change nothing"
    );
    assert_eq!(cost(&fresh, None).io_gas, io(&fresh, None));
}

/// B460: the history price's derivation. A block at the gas target leaves
/// no more tree rows than the default pruner removes per block, and a gas
/// unit spent on history holds no more disk over its window than one spent
/// on body bytes over theirs (research note, section 2: `BYTE_GAS` a byte,
/// stored about twice, kept 100,000 blocks): the history window and the
/// pruner's rate are what the price pays for.
#[test]
fn the_history_price_fits_the_pruner_and_the_disk() {
    let changed = TARGET_BLOCK_GAS / HISTORY_GAS_PER_KEY;
    assert!(
        changed * state_commit::HISTORY_ROWS_PER_KEY <= state_commit::PRUNE_ROWS_PER_BLOCK,
        "{changed} changed keys a target block"
    );
    // Disk byte-blocks one gas buys as body bytes, times BYTE_GAS.
    let body = 2 * BODY_BLOCKS_KEPT;
    let rows = state_commit::HISTORY_ROWS_PER_KEY * state_commit::MAX_HISTORY_ROW_BYTES;
    assert!(
        rows * HISTORY_BLOCKS_HELD * admission::BYTE_GAS <= body * HISTORY_GAS_PER_KEY,
        "a changed key's rows"
    );
    assert!(
        2 * HISTORY_BLOCKS_HELD * admission::BYTE_GAS <= body * HISTORY_GAS_PER_OLD_BYTE,
        "an old value's row, in hex"
    );
}

/// B460 witness: a block's transactions pay for the tree rows the block
/// leaves for the pruner, at the rate the pruner sustains at the gas target
/// (the block's own writes included). Each transfer changes three keys: its
/// sender's account and two coin stores. Before B460 their writes paid I/O
/// only, ~180 gas a key, and the rows cost 10,000 each.
#[test]
fn a_block_pays_for_the_tree_rows_it_leaves() {
    let db = temp_db("b460_block_rows");
    load_stdlib(&db);
    {
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
    }
    let proposer = create_account(&db, &SigningKey::from_bytes(&[99u8; 32]));
    set_coin_store(&db, &proposer, 0);
    let executor = Executor::new(db.clone());
    let (mut txs, mut paid) = (Vec::new(), 0u64);
    for i in 0..20u8 {
        let key = SigningKey::from_bytes(&[100 + i; 32]);
        let sender = create_account(&db, &key);
        set_coin_store(&db, &sender, 1_000_000_000_000_000);
        let to = SigningKey::from_bytes(&[150 + i; 32]);
        let recipient = crypto::derive_address(to.verifying_key().as_bytes()).unwrap();
        set_coin_store(&db, &recipient, 0);
        let payload = coin_transfer_payload(&sender, &recipient, 1);
        let estimate = executor
            .estimate_gas(&signed_tx(&key, &sender, &payload, 0, 0, 1))
            .expect("the estimate runs");
        assert_eq!(estimate.aborted, None);
        paid += estimate.writes.io_gas;
        let execution = estimate.execution_gas();
        txs.push(signed_tx(&key, &sender, &payload, 0, execution, 1));
    }
    seed_genesis_tree(&db);
    let Ok(BlockExecOutcome::Executed(summary)) = executor.execute_block_checked_at(
        txs,
        &proposer,
        1,
        block_time(1),
        0,
        &[],
        &[],
        |_, _| Ok(()),
    ) else {
        panic!("block must execute");
    };
    assert_eq!(
        summary.body.len(),
        20,
        "positive control: every transfer ran"
    );
    let rows = state_commit::history_rows(&db, 1).unwrap();
    assert!(rows >= 20 * 3 * 2, "positive control: {rows} rows");
    assert!(
        rows * GAS_PER_HISTORY_ROW <= paid,
        "{rows} rows left, {paid} gas paid for the writes"
    );
}

/// B65 witness: the state byte gas moves as EIP-1559's base fee does,
/// at most 1/8 a block however far a block overshoots, never below the
/// floor.
#[test]
fn the_state_byte_gas_follows_demand() {
    let (min, target) = (MIN_STATE_BYTE_GAS, TARGET_STATE_BYTES);
    assert_eq!(next_state_byte_gas(min, target), min);
    assert_eq!(next_state_byte_gas(min, 0), min);
    assert!(next_state_byte_gas(min, target + 1) > min);
    assert_eq!(next_state_byte_gas(8 * min, 0), 7 * min);
    assert_eq!(next_state_byte_gas(8 * min, 2 * target), 9 * min);
    assert_eq!(next_state_byte_gas(8 * min, 100 * target), 9 * min);
    assert_eq!(next_state_byte_gas(8 * min, target / 2), 8 * min - min / 2);
}

/// B65 witness: a block that adds more state bytes than the target raises
/// the next block's byte gas by the rule, and an empty block lowers it.
#[test]
fn a_block_over_the_state_target_raises_the_byte_gas() {
    let (db, key, sender) = blob_chain("b65_block_price", 62);
    let n = TARGET_STATE_BYTES;
    let store = blob_call("store", Some(&sender), Some(n));
    let estimate = Executor::new(db.clone())
        .estimate_gas(&signed_tx(&key, &sender, &store, 0, 0, 1))
        .unwrap();
    assert!(estimate.writes.new_bytes > TARGET_STATE_BYTES);
    let tx = signed_tx(&key, &sender, &store, 0, estimate.execution_gas(), 1);
    seed_genesis_tree(&db);
    let Ok(BlockExecOutcome::Executed(summary)) = Executor::new(db.clone())
        .execute_block_checked_at(vec![tx], &sender, 1, block_time(1), 0, &[], &[], |_, _| {
            Ok(())
        })
    else {
        panic!("block must execute");
    };
    assert_eq!(summary.body.len(), 1);
    let raised = next_state_byte_gas(MIN_STATE_BYTE_GAS, estimate.writes.new_bytes);
    assert!(raised > MIN_STATE_BYTE_GAS);
    assert_eq!(
        db.get(STATE_BYTE_GAS_KEY).unwrap(),
        Some(raised.to_string())
    );
    assert_eq!(state_gas::committed_state_byte_gas(&db), raised);
    let Ok(BlockExecOutcome::Executed(_)) = Executor::new(db.clone()).execute_block_checked_at(
        vec![],
        &sender,
        2,
        block_time(2),
        0,
        &[],
        &[],
        |_, _| Ok(()),
    ) else {
        panic!("block must execute");
    };
    assert_eq!(
        state_gas::committed_state_byte_gas(&db),
        next_state_byte_gas(raised, 0)
    );
}

/// B65 witness: Move execution stops at MAX_GAS_LIMIT whatever the limit,
/// while the writes may use the rest of it (EIP-8037's split): a resource
/// whose bytes cost more than MAX_GAS_LIMIT is admitted and stored, and a
/// loop given 50M stops at 10M.
#[test]
fn move_execution_is_capped_apart_from_the_writes() {
    let (db, key, sender) = blob_chain("b65_split", 63);
    let executor = Executor::new(db.clone());
    let store = blob_call("store", Some(&sender), Some(12_000));
    let estimate = executor
        .estimate_gas(&signed_tx(&key, &sender, &store, 0, 0, 1))
        .unwrap();
    assert!(estimate.writes.gas(estimate.state_byte_gas) > MAX_GAS_LIMIT);
    assert!(estimate.vm_gas < MAX_GAS_LIMIT);
    let tx = signed_tx(&key, &sender, &store, 0, estimate.execution_gas(), 1);
    admission::check_stateless(&tx, &expected_chain_id()).expect("admitted");
    run(&db, &executor, &tx).expect("executes");
    assert_eq!(receipt_status(&db, &tx), "success");

    let spin = blob_call("spin", None, None);
    let looped = executor
        .estimate_gas(&signed_tx(&key, &sender, &spin, 1, 0, 1))
        .unwrap();
    assert!(looped.aborted.is_some(), "the loop runs out of gas");
    assert!(
        looped.vm_gas <= MAX_GAS_LIMIT && looped.vm_gas > MAX_GAS_LIMIT - 1_000,
        "{}",
        looped.vm_gas
    );
    let tx = signed_tx(&key, &sender, &spin, 1, 50_000_000, 1);
    run(&db, &executor, &tx).expect("charged");
    assert_eq!(receipt_status(&db, &tx), "aborted");
}

/// B65 witness: a sender's first transaction creates its account. A limit
/// that cannot pay for that (with its object loads) is refused before the VM
/// runs, and `can_pay` refuses it too, so no block reserves space for it:
/// no account, no charge. A limit that covers it but not the payload is
/// charged once the VM has run (no free execution), and so is the same limit
/// from an existing account.
#[test]
fn the_charges_own_writes_are_priced_before_anything_runs() {
    let (db, key, sender) = blob_chain("b65_charge_writes", 64);
    let newcomer_key = SigningKey::from_bytes(&[65u8; 32]);
    let newcomer = crypto::derive_address(newcomer_key.verifying_key().as_bytes()).unwrap();
    let balance = 1_000_000_000_000u128;
    set_coin_store(&db, &newcomer, balance);
    let executor = Executor::new(db.clone());
    let store = |who: &str| blob_call("store", Some(who), Some(1_000));
    let first = executor
        .estimate_gas(&signed_tx(
            &newcomer_key,
            &newcomer,
            &store(&newcomer),
            0,
            0,
            1,
        ))
        .unwrap();
    let existing = executor
        .estimate_gas(&signed_tx(&key, &sender, &store(&sender), 0, 0, 1))
        .unwrap();
    assert!(
        first.writes.new_bytes > existing.writes.new_bytes,
        "the first transaction pays for its account"
    );
    let parse = |raw: &str| serde_json::from_str::<Transaction>(raw).unwrap();
    let probe = signed_tx(&newcomer_key, &newcomer, &store(&newcomer), 0, 0, 1);
    let account_writes = executor
        .charge_account_writes(&parse(&probe), &newcomer)
        .expect("nonce 0");
    let charge = executor.charge_gas(&parse(&probe), &account_writes);
    assert!(charge > MIN_STATE_BYTE_GAS * NEW_KEY_BYTES, "{charge}");

    let short = signed_tx(
        &newcomer_key,
        &newcomer,
        &store(&newcomer),
        0,
        charge - 1,
        1,
    );
    assert!(
        !executor.can_pay(&parse(&short), &short),
        "no block reserves it"
    );
    assert_eq!(executor.execute_transaction(&short), None);
    assert!(db.get_object(&newcomer).is_none(), "no account created");
    assert_eq!(coin_balance(&db, &newcomer), balance, "nothing charged");

    let covered = signed_tx(
        &newcomer_key,
        &newcomer,
        &store(&newcomer),
        0,
        charge + 20_000,
        1,
    );
    assert!(executor.can_pay(&parse(&covered), &covered));
    run(&db, &executor, &covered).expect("charged");
    assert_eq!(
        receipt_status(&db, &covered),
        "aborted",
        "the blob's bytes are not paid"
    );
    assert_eq!(
        committed_sequence_number(&db, &newcomer),
        1,
        "the account exists"
    );
    assert_eq!(
        coin_balance(&db, &newcomer),
        balance - gas_of(&covered) as u128,
        "charged in full"
    );

    // B460: an existing account's charge is its nonce bump, with the tree
    // history that leaves.
    let probe = signed_tx(&key, &sender, &store(&sender), 0, 0, 1);
    let account_writes = executor
        .charge_account_writes(&parse(&probe), &sender)
        .expect("nonce 0");
    let limit = executor.charge_gas(&parse(&probe), &account_writes) + 20_000;
    let tx = signed_tx(&key, &sender, &store(&sender), 0, limit, 1);
    assert!(executor.can_pay(&parse(&tx), &tx));
    run(&db, &executor, &tx).expect("charged");
    assert_eq!(receipt_status(&db, &tx), "aborted");
}

/// B69: a module at 0xd0d named `name` that pulls in `dep` (if any) and
/// carries `padding` bytes of extra identifiers. Parsed, never verified: the
/// dependency charge reads only the module's handles.
fn chained_module(name: &str, dep: Option<&str>, padding: usize) -> Vec<u8> {
    use move_binary_format::file_format::{
        empty_module, AddressIdentifierIndex, IdentifierIndex, ModuleHandle,
    };
    let mut m = empty_module();
    m.address_identifiers = vec![AccountAddress::from_hex_literal("0xd0d").unwrap()];
    m.identifiers = vec![Identifier::new(name).unwrap()];
    if let Some(dep) = dep {
        m.identifiers.push(Identifier::new(dep).unwrap());
        m.module_handles.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
    }
    let mut left = padding;
    let mut i = 0;
    while left > 0 {
        let len = left.min(4_000);
        m.identifiers
            .push(Identifier::new(format!("p{i}{}", "x".repeat(len))).unwrap());
        left -= len;
        i += 1;
    }
    let mut bytes = vec![];
    m.serialize(&mut bytes).unwrap();
    bytes
}

/// Seeds `count` chained modules m0 <- m1 <- ... and returns the call of the
/// last one's `run`.
fn seed_chain(db: &StateDB, sender: &str, count: usize, padding: usize) -> String {
    let _seed = db.seeding();
    for i in 0..count {
        let name = format!("m{i}");
        let dep = (i > 0).then(|| format!("m{}", i - 1));
        let bytes = chained_module(&name, dep.as_deref(), padding);
        let key = vm_move::state_keys::module_key(
            &AccountAddress::from_hex_literal("0xd0d").unwrap(),
            &name,
        );
        db.put(&key, &hex::encode(bytes)).unwrap();
    }
    let call = EntryFunctionCall {
        module: ModuleId::new(
            AccountAddress::from_hex_literal("0xd0d").unwrap(),
            Identifier::new(format!("m{}", count - 1)).unwrap(),
        ),
        function: "run".to_string(),
        ty_args: vec![],
        args: vec![bcs::to_bytes(&parse_move_address(sender).unwrap()).unwrap()],
    };
    hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
}

/// B69 witness: a call pays for the modules it loads (each module and its
/// bytes, over the whole closure), before the VM runs: the closure of the
/// blob module is itself and `signer` (its `vector` calls compile to vector
/// instructions, so it does not depend on `vector`: 389 + 130 bytes on
/// disk), and a limit that covers everything but that is charged and
/// aborts.
#[test]
fn a_call_pays_for_the_modules_it_loads() {
    let (db, key, sender) = blob_chain("b69_closure", 66);
    let executor = Executor::new(db.clone());
    let size = |module: &str, address: &str| {
        let key = vm_move::state_keys::module_key(
            &AccountAddress::from_hex_literal(address).unwrap(),
            module,
        );
        (db.get(&key).unwrap().unwrap().len() / 2) as u64
    };
    let blob = ModuleId::new(blob_address(), Identifier::new("blob").unwrap());
    let closure = executor.modules.closure(&db, [blob]).unwrap();
    assert_eq!(
        closure,
        deps::Closure {
            modules: 2,
            bytes: size("blob", "0xcafe") + size("signer", "0x1"),
        }
    );
    assert_eq!(
        closure.bytes,
        389 + 130,
        "the fixture's and signer.mv's sizes"
    );
    assert_eq!(
        closure.gas(),
        2 * deps::GAS_PER_DEPENDENCY + closure.bytes.div_ceil(deps::DEPENDENCY_BYTES_PER_GAS)
    );
    let store = blob_call("store", Some(&sender), Some(100));
    let estimate = executor
        .estimate_gas(&signed_tx(&key, &sender, &store, 0, 0, 1))
        .unwrap();
    assert!(
        estimate.vm_gas > closure.gas(),
        "the estimate counts the closure"
    );
    let short = estimate.execution_gas() - closure.gas();
    let tx = signed_tx(&key, &sender, &store, 0, short, 1);
    run(&db, &executor, &tx).expect("charged");
    assert_eq!(
        receipt_status(&db, &tx),
        "aborted",
        "the modules' load was not paid"
    );
    let tx = signed_tx(&key, &sender, &store, 1, estimate.execution_gas(), 1);
    run(&db, &executor, &tx).expect("executes");
    assert_eq!(receipt_status(&db, &tx), "success");
}

/// B93 witness: the loader's recursion depth is bounded from storage before
/// the VM runs (the VM's own check depended on its module cache): a chain of
/// 100 modules loads, one of 101 is refused, the same way on every call; the
/// stdlib's friend cycles (`coin` and its friends) count once and load.
#[test]
fn the_dependency_depth_is_bounded_from_storage() {
    let (db, _key, sender) = blob_chain("b93_depth", 70);
    let index = deps::ModuleIndex::default();
    let top = |n: usize| {
        ModuleId::new(
            AccountAddress::from_hex_literal("0xd0d").unwrap(),
            Identifier::new(format!("m{}", n - 1)).unwrap(),
        )
    };
    seed_chain(&db, &sender, 101, 0);
    for _ in 0..2 {
        let deep = index.closure(&db, [top(101)]).unwrap_err();
        assert!(deep.contains("a chain of 101 modules"), "{deep}");
        let fits = index.closure(&db, [top(100)]).expect("100 deep fits");
        assert_eq!(fits.modules, 100);
    }
    let coin = ModuleId::new(AccountAddress::ONE, Identifier::new("coin").unwrap());
    let stdlib = index
        .closure(&db, [coin])
        .expect("the stdlib's friend cycles load");
    assert!(stdlib.modules > 3, "vacuous: {stdlib:?}");
}

/// B69 witness: a call whose closure is past Aptos's limits (768 modules,
/// 1.8 MB) is charged and aborted before the VM loads any of it.
#[test]
fn a_closure_past_the_limits_is_refused_before_the_vm() {
    let (db, key, sender) = blob_chain("b69_limits", 67);
    let executor = Executor::new(db.clone());
    let reason = |db: &StateDB, raw: &str| {
        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(raw)))
            .unwrap()
            .expect("receipt");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "aborted");
        receipt["error"].as_str().unwrap_or_default().to_string()
    };
    let deep = seed_chain(&db, &sender, deps::MAX_DEPENDENCIES as usize + 1, 0);
    let tx = signed_tx(&key, &sender, &deep, 0, 5_000_000, 1);
    run(&db, &executor, &tx).expect("charged");
    assert!(
        reason(&db, &tx).contains("dependency limits"),
        "{}",
        reason(&db, &tx)
    );

    let (db, key, sender) = blob_chain("b69_bytes", 68);
    let executor = Executor::new(db.clone());
    let heavy = seed_chain(&db, &sender, 10, 200_000);
    let tx = signed_tx(&key, &sender, &heavy, 0, 5_000_000, 1);
    run(&db, &executor, &tx).expect("charged");
    assert!(
        reason(&db, &tx).contains("dependency limits"),
        "{}",
        reason(&db, &tx)
    );

    let (db, key, sender) = blob_chain("b69_within", 69);
    let executor = Executor::new(db.clone());
    let fine = seed_chain(&db, &sender, 9, 200_000);
    // Within the limits, the closure (~1.8 MB) is paid before the VM loads
    // it: a limit under its cost is charged and aborts on the charge.
    let tx = signed_tx(&key, &sender, &fine, 0, 100_000, 1);
    run(&db, &executor, &tx).expect("charged");
    let why = reason(&db, &tx);
    assert!(
        !why.contains("dependency limits"),
        "control: 1.8 MB fits: {why}"
    );
    assert!(why.contains("loading its modules costs"), "{why}");
}
