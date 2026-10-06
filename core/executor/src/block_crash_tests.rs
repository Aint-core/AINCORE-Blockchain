use super::*;
use std::collections::BTreeMap;
use std::process::Command;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        // A counter, not the clock: macOS clocks tick in microseconds, so two
        // parallel tests (or two dirs made back to back) could share a name.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = storage::test_dir::process_dir().join(format!(
            "aincore-block-crash-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn open(&self) -> Arc<StateDB> {
        Arc::new(StateDB::open(self.0.to_str().unwrap()).unwrap())
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(db: &StateDB, initialize: bool) -> (Vec<String>, String, String) {
    let sender_key = SigningKey::from_bytes(&[71; 32]);
    let recipient_key = SigningKey::from_bytes(&[72; 32]);
    let proposer_key = SigningKey::from_bytes(&[73; 32]);
    let addr = |key: &SigningKey| crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let sender = addr(&sender_key);
    let recipient = addr(&recipient_key);
    let proposer = addr(&proposer_key);
    if initialize {
        load_stdlib(db);
        for key in [&sender_key, &recipient_key, &proposer_key] {
            create_account(db, key);
        }
        set_coin_store(db, &sender, 1_000_000);
        set_coin_store(db, &recipient, 0);
        set_coin_store(db, &proposer, 0);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        db.put("sys:config:epoch_block_interval", "1000000")
            .unwrap();
    }
    let txs = [100, 200]
        .into_iter()
        .enumerate()
        .map(|(nonce, amount)| {
            signed_tx(
                &sender_key,
                &sender,
                &coin_transfer_payload(&sender, &recipient, amount),
                nonce as u64,
                100_000,
                1,
            )
        })
        .collect();
    (txs, proposer, recipient)
}

/// The fixture's genesis, ending as genesis does: with state-tree version 0
/// committed (G3 S3). Like genesis, it is idempotent: a crash child reruns it
/// on a database its parent already initialized.
fn genesis_fixture(db: &Arc<StateDB>) -> (Vec<String>, String, String) {
    let fixture = fixture(db, true);
    if state_commit::latest_version(db).unwrap().is_none() {
        super::seed_genesis_tree(db);
    }
    fixture
}

fn rows(db: &StateDB) -> BTreeMap<Vec<u8>, Vec<u8>> {
    db.db
        .iterator(storage::rocksdb::IteratorMode::Start)
        .map(|entry| {
            let (key, value) = entry.unwrap();
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

#[test]
fn rejected_admission_never_enters_execution_and_preserves_reopened_rows() {
    let dir = TestDir::new();
    let db = dir.open();
    let (txs, proposer, _) = genesis_fixture(&db);
    let before = rows(&db);
    let mut executor = Executor::new(db.clone());
    executor.block_boundary_hook =
        Some(|_, _| panic!("execution entered after admission rejection"));
    let error = executor
        .execute_block_admitted_at(
            txs,
            &proposer,
            1,
            block_time(1),
            0,
            &[],
            &[],
            |view| {
                assert!(view.get("sys:last_executed_height").unwrap().is_none());
                Err("admission revoked".into())
            },
            |_, _| panic!("acceptance entered after admission rejection"),
        )
        .unwrap_err();
    assert!(error.contains("admission revoked"));
    assert_eq!(rows(&db), before);
    db.flush().unwrap();
    drop(executor);
    drop(db);
    assert_eq!(rows(&dir.open()), before);
}

#[test]
fn admission_sees_parent_state_and_rejected_execution_remains_retryable() {
    let dir = TestDir::new();
    let db = dir.open();
    let (txs, proposer, _) = genesis_fixture(&db);
    let before = rows(&db);
    let executor = Executor::new(db.clone());
    let admitted = std::cell::Cell::new(false);
    let error = executor
        .execute_block_admitted_at(
            txs.clone(),
            &proposer,
            1,
            block_time(1),
            0,
            &[],
            &[],
            |view| {
                assert_eq!(rows(view), before);
                admitted.set(true);
                Ok(())
            },
            |summary, view| {
                assert!(admitted.get());
                assert_eq!(summary.tx_count, 2);
                assert_eq!(
                    view.get("sys:last_executed_height").unwrap().as_deref(),
                    Some("1")
                );
                view.put("consensus:last_adopted_height", "staged").unwrap();
                Err("reject staged result".into())
            },
        )
        .unwrap_err();
    assert!(error.contains("reject staged result"));
    assert_eq!(rows(&db), before);
    let outcome = executor
        .execute_block_admitted_at(
            txs,
            &proposer,
            1,
            block_time(1),
            0,
            &[],
            &[],
            |view| {
                assert_eq!(rows(view), before);
                Ok(())
            },
            |summary, view| {
                assert_eq!(summary.tx_count, 2);
                view.put("consensus:last_adopted_height", "committed")
                    .map_err(|e| e.to_string())
            },
        )
        .unwrap();
    assert!(matches!(outcome, BlockExecOutcome::Executed(_)));
    let after = rows(&db);
    assert_ne!(after, before);
    assert_eq!(
        db.get("consensus:last_adopted_height").unwrap().as_deref(),
        Some("committed")
    );
    db.flush().unwrap();
    drop(executor);
    drop(db);
    assert_eq!(rows(&dir.open()), after);
}

fn run_child(dir: &TestDir, boundary: Option<u8>, replay: bool) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::block_crash_tests::block_crash_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("AINCORE_TEST_BLOCK_CRASH_DB", &dir.0)
        .env(
            "AINCORE_TEST_BLOCK_CRASH_POINT",
            boundary.map(|p| p.to_string()).unwrap_or_default(),
        )
        .env(
            "AINCORE_TEST_BLOCK_CRASH_REPLAY",
            if replay { "1" } else { "0" },
        )
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(if boundary.is_some() { 77 } else { 0 }),
        "child did not reach intended boundary: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn block_crash_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_BLOCK_CRASH_DB") else {
        return;
    };
    let db = Arc::new(StateDB::open(&path).unwrap());
    let replay = std::env::var("AINCORE_TEST_BLOCK_CRASH_REPLAY").unwrap() == "1";
    let (txs, proposer, recipient) = if replay {
        fixture(&db, false)
    } else {
        genesis_fixture(&db)
    };
    let mut executor = Executor::new(Arc::clone(&db));
    executor.block_boundary_hook = Some(|point, _db| {
        if std::env::var("AINCORE_TEST_BLOCK_CRASH_POINT")
            .ok()
            .and_then(|p| p.parse::<u8>().ok())
            == Some(point)
        {
            std::process::exit(77); // no destructors or graceful RocksDB close
        }
    });
    match executor.execute_block_parallel_at(txs, &proposer, 1, block_time(1), 0, &[], &[]) {
        BlockExecOutcome::Executed(summary) if !replay => {
            assert_eq!(
                summary.executed_raws.len(),
                2,
                "both transfers must execute"
            );
            assert_eq!(coin_balance(&db, &recipient), 300);
            assert_eq!(
                summary.state_root,
                // G3: the Jellyfish Merkle root of this fixture after block 1.
                // It replaced the old hash-chain value 0b19b72b...; what the
                // crash tests prove is that every replay equals this clean root.
                // The fixture state holds the stdlib bytecode, so the root
                // moves with it: 40051153... became bfd42aa6... when
                // universal_mining bounded device registration, and G5 S1 moved
                // it in three proven steps (each alone, from bfd42aa6...): the
                // height-clock stdlib 1ea8e128..., the genesis chain Params and
                // Clock 94c32abd..., the per-block clock write af45a2f3....
                // G5 amendment A1 moved it the same way, each step proven from
                // af45a2f3...: the consensus-time stdlib 405a1f99..., the new
                // Params and Clock layout 35d1e242..., the tau clock write (the
                // block at timestamp 7) 3208d836.... G5 S2 moved it through
                // the stdlib alone (per-period emission): with A1's bytecode the
                // S2 executor reproduces 3208d836... exactly. G5 S3 moved it
                // through the stdlib alone (delegation pools, the emission
                // hot potato, math): with S2's bytecode the S3 executor
                // reproduces e8953244... exactly. G5 S4a moved it through the
                // stdlib alone (the offense ledger, W and D): with S3's
                // bytecode the S4a executor reproduces 726ce81d... exactly. G5
                // S4d moved it through the stdlib alone (join refuses a shared
                // BLS key): with S4b's bytecode the S4d executor reproduces
                // c5038a3d... exactly. The G5 review (A3, A3b) moved it
                // through the stdlib alone (staking entries `entry` only,
                // linear settlement, frozen payouts, conviction in full,
                // eviction from a full set): with S4c's bytecode the
                // reviewed executor reproduces c5be08d5... exactly. G5 CH-1
                // moved it through the stdlib alone (ChurnState and
                // admit_increase): with the A3/A3b bytecode the CH-1 executor
                // reproduces 247c3a72... exactly. G5 A4 (revised after review)
                // moved it through the stdlib alone (BootstrapProtected and
                // the protected eviction, rewards by weight, the offense split
                // up to the weight): with 31c631e's bytecode the A4 executor
                // reproduces 73137b35... exactly. The second A4 review moved
                // it through the stdlib alone (pay_rewards against at least
                // s_min): with 854f1ae's bytecode the reviewed executor
                // reproduces 7172c9b7... exactly. B14/B15 moved it through the
                // executor (byte gas; the base fee burned, the fee written
                // only when it moves): with 419b9a0's bytecode the new
                // executor gives e7e2ff0b.... B7 then moved it through the
                // stdlib alone (0x1::treasury deleted, coin.mv without the
                // friend): ba90d7a8.... B66 moved it through the object
                // encoding alone (an account's data stored as its text): with
                // data stored as a byte array again, the B66 executor
                // reproduces ba90d7a8... exactly. B65 did not move it (the
                // block adds less than the state target: no byte gas write).
                // Round 3 moved it through the stdlib alone, each step proven
                // from 9e6887ef...: with the old governance.mv and dex.mv and
                // no dependency charge the round-3 executor reproduces
                // 9e6887ef... exactly, and so it does with the B69 charge;
                // B71's governance.mv gives 1a91a159..., then B85's dex.mv
                // a1f25c44.... Round 4 moved it through the stdlib alone: with
                // round 3's dex.mv and token_factory.mv the round-4 executor
                // reproduces a1f25c44... exactly; B99's token_factory.mv gives
                // 480958b3..., then B100's dex.mv 913b381f....
                "913b381f244537461cb0945b93e33978256011204c9673caed4e02367518fbb0",
                "clean execution must preserve the pre-staging fixture root"
            );
        }
        BlockExecOutcome::Executed(_) | BlockExecOutcome::AlreadyExecuted { .. } if replay => {}
        other => panic!("unexpected execution: {other:?}"),
    }
}

fn assert_crash_atomic(boundary: u8, retry: bool) {
    let clean = TestDir::new();
    run_child(&clean, None, false);
    let after = rows(&clean.open());
    let interrupted = TestDir::new();
    let before = {
        let db = interrupted.open();
        genesis_fixture(&db);
        rows(&db)
    };
    assert_ne!(before, after, "control must change state");
    run_child(&interrupted, Some(boundary), false);
    if retry {
        run_child(&interrupted, None, true);
    }
    let db = interrupted.open();
    let recovered = rows(&db);
    let valid = if retry || boundary == 4 {
        recovered == after
    } else if boundary == 0 {
        recovered == before
    } else {
        recovered == before || recovered == after
    };
    assert!(valid,
        "partial state at boundary {boundary}, retry={retry}: executed_height={:?}, root={:?}; expected complete pre-state or clean post-state",
        db.get("sys:last_executed_height").unwrap(), db.get("sys:state_root").unwrap());
}

#[test]
fn block_crash_before_and_after_execution_controls() {
    assert_crash_atomic(0, false);
    assert_crash_atomic(4, false);
}

#[test]
fn block_crash_after_staged_height_before_commit_is_atomic() {
    assert_crash_atomic(3, false);
    assert_crash_atomic(3, true);
}

#[test]
fn block_crash_after_first_transaction_batch_is_atomic() {
    assert_crash_atomic(1, false);
}

#[test]
fn block_crash_after_root_before_height_is_atomic() {
    assert_crash_atomic(2, false);
}

#[test]
fn block_crash_replay_after_transaction_matches_clean_execution() {
    assert_crash_atomic(1, true);
}

#[test]
fn block_crash_replay_after_root_matches_clean_execution() {
    assert_crash_atomic(2, true);
}

#[test]
fn block_panic_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_BLOCK_PANIC_DB") else {
        return;
    };
    let db = Arc::new(StateDB::open(&path).unwrap());
    let (txs, proposer, _) = genesis_fixture(&db);
    let before = rows(&db);
    let mut executor = Executor::new(Arc::clone(&db));
    executor.block_boundary_hook = Some(|point, view| {
        if point == 1 {
            let (_, _, recipient) = fixture(view, false);
            assert_eq!(
                coin_balance(view, &recipient),
                100,
                "the first real transfer must be visible inside the transaction"
            );
            panic!("injected panic after first transaction batch");
        }
    });
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        executor.execute_block_parallel_at(txs.clone(), &proposer, 1, block_time(1), 0, &[], &[])
    }));
    assert!(interrupted.is_err(), "injection must unwind execution");
    let partial = rows(&db);
    assert!(
        partial == before,
        "panic must discard all speculative writes"
    );
    assert_eq!(db.get("sys:last_executed_height").unwrap(), None);

    // A new Executor must not bypass a poisoned process-wide execution lock.
    let retry_executor = Executor::new(Arc::clone(&db));
    let retry = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        retry_executor.execute_block_parallel_at(txs, &proposer, 1, block_time(1), 0, &[], &[])
    }));
    assert!(
        retry.is_err(),
        "execution resumed over partially written state: {retry:?}"
    );
    assert!(rows(&db) == partial, "retry must not write any more state");
}

#[test]
fn block_panic_poison_refuses_retry() {
    let dir = TestDir::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::block_crash_tests::block_panic_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("AINCORE_TEST_BLOCK_PANIC_DB", &dir.0)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_checked_child(dir: &TestDir, mode: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tests::block_crash_tests::checked_block_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("AINCORE_TEST_CHECKED_DB", &dir.0)
        .env("AINCORE_TEST_CHECKED_MODE", mode)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(if mode.starts_with("crash") { 77 } else { 0 }),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn checked_block_child() {
    let Ok(path) = std::env::var("AINCORE_TEST_CHECKED_DB") else {
        return;
    };
    let mode = std::env::var("AINCORE_TEST_CHECKED_MODE").unwrap();
    let db = Arc::new(StateDB::open(&path).unwrap());
    let (txs, proposer, recipient) = if mode == "resume" {
        fixture(&db, false)
    } else {
        genesis_fixture(&db)
    };
    let before = rows(&db);
    let mut executor = Executor::new(db.clone());
    executor.block_boundary_hook = Some(|point, _| {
        if point == 4 && std::env::var("AINCORE_TEST_CHECKED_MODE").unwrap() == "crash_after" {
            std::process::exit(77);
        }
    });
    let accept = |summary: &BlockExecutionSummary, view: &StateDB, reject: bool| {
        assert_eq!(coin_balance(view, &recipient), 300);
        assert_eq!(summary.executed_raws.len(), 2);
        let mut block = blockchain::Block::new_with_roots_at(
            1,
            1,
            "genesis".into(),
            txs.clone(),
            proposer.clone(),
            summary.state_root.clone(),
            summary.receipts_root.clone(),
            1000,
            vec![],
            vec![],
            "anchor-test".into(),
            vec![],
        );
        block.sign_proposer(&SigningKey::from_bytes(&[73; 32]), &proposer);
        view.save_block_json(1, &serde_json::to_string(&block).unwrap())
            .map_err(|e| e.to_string())?;
        assert_eq!(view.get_chain_height(), 1);
        assert_eq!(db.get_chain_height(), 0, "acceptance leaked before commit");
        if mode == "crash_before" {
            std::process::exit(77);
        }
        if reject {
            return Err("injected rejection after metadata staging".into());
        }
        Ok(())
    };
    if mode == "reject_then_retry" {
        assert!(executor
            .execute_block_checked_at(
                txs.clone(),
                &proposer,
                1,
                block_time(1),
                0,
                &[],
                &[],
                |s, v| accept(s, v, true)
            )
            .is_err());
        assert!(
            rows(&db) == before,
            "rejected real transfers or metadata leaked"
        );
    }
    let result = executor
        .execute_block_checked_at(
            txs.clone(),
            &proposer,
            1,
            block_time(1),
            0,
            &[],
            &[],
            |s, v| accept(s, v, false),
        )
        .unwrap();
    assert!(matches!(
        result,
        BlockExecOutcome::Executed(_) | BlockExecOutcome::AlreadyExecuted { last_executed: 1 }
    ));
    assert_eq!(coin_balance(&db, &recipient), 300);
    let block: blockchain::Block =
        serde_json::from_str(&db.get("block_1").unwrap().unwrap()).unwrap();
    assert_eq!(block.header.state_root, executor.current_state_root());
    assert_eq!(db.get_chain_height(), 1);
    assert_eq!(executor.last_executed_height(), 1);
    for tx in txs {
        use sha2::Digest;
        let hash = hex::encode(sha2::Sha256::digest(tx.as_bytes()));
        assert_eq!(db.get_tx_block_height(&hash), Some(1));
    }
}

#[test]
fn checked_block_crash_and_rejected_metadata_are_atomic() {
    let clean = TestDir::new();
    run_checked_child(&clean, "clean");
    let after = rows(&clean.open());
    for mode in ["crash_before", "crash_after", "reject_then_retry"] {
        let dir = TestDir::new();
        let before = {
            let db = dir.open();
            genesis_fixture(&db);
            rows(&db)
        };
        run_checked_child(&dir, mode);
        let expected = if mode == "crash_before" {
            &before
        } else {
            &after
        };
        assert!(
            &rows(&dir.open()) == expected,
            "torn state/block/index at {mode}"
        );
        run_checked_child(&dir, "resume");
        assert!(rows(&dir.open()) == after, "replay differed after {mode}");
    }
}
