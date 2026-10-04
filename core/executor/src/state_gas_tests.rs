// B65 witnesses: a transaction pays for its writes. Included in `tests`.
use super::*;
use crate::state_gas::{
    next_state_byte_gas, write_cost, WriteCost, IO_BYTES_PER_GAS, IO_GAS_PER_WRITE,
    MIN_STATE_BYTE_GAS, NEW_KEY_BYTES, STATE_BYTE_GAS_KEY, TARGET_STATE_BYTES,
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
/// last value, history keys are not state, and every state write pays I/O.
#[test]
fn only_added_state_bytes_are_charged_and_nothing_is_refunded() {
    let db = temp_db("b65_write_cost");
    let account = format!("obj:{}", "aa".repeat(32));
    let fresh = format!("obj:{}", "bb".repeat(32));
    {
        let _seed = db.seeding();
        db.put(&account, &"x".repeat(100)).unwrap();
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
        IO_GAS_PER_WRITE + ((account.len() + 130) as u64).div_ceil(IO_BYTES_PER_GAS)
    );
    assert_eq!(
        cost(&[(&account, None)]).io_gas,
        IO_GAS_PER_WRITE + (account.len() as u64).div_ceil(IO_BYTES_PER_GAS)
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

    let limit = 20_000;
    let tx = signed_tx(&key, &sender, &store(&sender), 0, limit, 1);
    assert!(executor.can_pay(&parse(&tx), &tx));
    run(&db, &executor, &tx).expect("charged");
    assert_eq!(receipt_status(&db, &tx), "aborted");
}
