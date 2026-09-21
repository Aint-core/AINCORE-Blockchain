use super::*;

type Rows = Vec<(Box<[u8]>, Box<[u8]>)>;

fn rows(db: &StateDB) -> Rows {
    db.db
        .iterator(storage::rocksdb::IteratorMode::Start)
        .map(Result::unwrap)
        .collect()
}

fn signed_empty(sync: &ChainSync, height: u64, parent: &str, timestamp: u64) -> Block {
    let key = crypto::SigningKey::from_bytes(&[77; 32]);
    let proposer = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let exec = executor::Executor::new(sync.storage.clone());
    let mut block = Block::new_with_roots_at(
        height,
        height,
        parent.into(),
        vec![],
        proposer,
        exec.current_state_root(),
        exec.receipts_root_for_block(&[]),
        timestamp,
        vec!["ab".repeat(32)],
        "ab".repeat(32),
        vec![],
    );
    authenticate_block(sync, &mut block);
    block
}

fn fixture(name: &str, height: u64) -> (ChainSync, Vec<Block>, String) {
    let name = format!(
        "reorg_{name}_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    );
    let sync = setup_sync(&name);
    let proposer = crypto::derive_address(
        crypto::SigningKey::from_bytes(&[77; 32])
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    set_validators(&sync, vec![(&proposer, 100)]);
    let mut blocks = vec![];
    let mut parent = "genesis".to_string();
    for h in 1..=height {
        let block = signed_empty(&sync, h, &parent, 23);
        assert_eq!(sync.process_blocks(vec![block.clone()], h - 1), h);
        parent = block.header.hash.clone();
        blocks.push(block);
    }
    assert_eq!(sync.storage.get_chain_height(), height);
    assert_eq!(
        executor::Executor::new(sync.storage.clone()).last_executed_height(),
        height,
        "even empty blocks carry durable execution progress"
    );
    (sync, blocks, format!("/tmp/aincore_sync_db_{name}"))
}

fn assert_preserved(sync: ChainSync, before: Rows, path: String) {
    assert_eq!(
        rows(&sync.storage),
        before,
        "a peer conflict cannot change any stored row"
    );
    assert!(sync.storage.get("sync:halt_reason").unwrap().is_none());
    sync.storage.flush().unwrap();
    drop(sync);
    let reopened = StateDB::open(&path).unwrap();
    assert_eq!(
        rows(&reopened),
        before,
        "rejection must remain unchanged after reopen"
    );
    drop(reopened);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn duplicate_empty_chain_is_read_only_and_its_successor_still_executes() {
    let (sync, blocks, path) = fixture("control", 2);
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(blocks.clone(), 2), 2);
    assert_eq!(rows(&sync.storage), before);
    let next = signed_empty(&sync, 3, &blocks[1].header.hash, 24);
    assert_eq!(sync.process_blocks(vec![next], 2), 3);
    assert_eq!(
        executor::Executor::new(sync.storage.clone()).last_executed_height(),
        3
    );
    let after = rows(&sync.storage);
    assert_preserved(sync, after, path);
}

#[test]
fn unsigned_conflict_cannot_delete_executed_empty_tip() {
    let (sync, blocks, path) = fixture("unsigned", 2);
    let mut forged = blocks[1].clone();
    forged.header.hash = "ff".repeat(32);
    forged.proposer_signature.clear();
    assert!(sync
        .validate_block(&forged, 2, &blocks[0].header.hash)
        .is_err());
    let before = rows(&sync.storage);
    let result = sync.process_blocks(vec![forged], 2);
    eprintln!(
        "unsigned conflict: result={result}, stored_tip={}, executed={}, block_2_exists={}",
        sync.storage.get_chain_height(),
        executor::Executor::new(sync.storage.clone()).last_executed_height(),
        sync.storage.get("block_2").unwrap().is_some()
    );
    assert_eq!(
        result, 2,
        "invalid peer block must not rewind accepted progress"
    );
    assert_preserved(sync, before, path);
}

#[test]
fn signed_conflict_cannot_rewind_executed_state_without_undo() {
    let (sync, blocks, path) = fixture("signed", 2);
    let other = signed_empty(&sync, 2, &blocks[0].header.hash, 24);
    assert_ne!(other.header.hash, blocks[1].header.hash);
    sync.validate_block(&other, 2, &blocks[0].header.hash)
        .unwrap();
    let before = rows(&sync.storage);
    let result = sync.process_blocks(vec![other], 2);
    eprintln!(
        "signed conflict: result={result}, stored_tip={}, executed={}, block_2_exists={}",
        sync.storage.get_chain_height(),
        executor::Executor::new(sync.storage.clone()).last_executed_height(),
        sync.storage.get("block_2").unwrap().is_some()
    );
    assert_eq!(
        result, 2,
        "a validator signature alone does not authorize state rollback"
    );
    assert_preserved(sync, before, path);
}

#[test]
fn longer_signed_fork_cannot_delete_an_executed_empty_suffix() {
    let (sync, blocks, path) = fixture("longer", 3);
    let mut fork = vec![];
    let mut parent = blocks[0].header.hash.clone();
    for h in 2..=4 {
        let block = signed_empty(&sync, h, &parent, 24);
        parent = block.header.hash.clone();
        fork.push(block);
    }
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(fork, 3), 3);
    assert_preserved(sync, before, path);
}

#[test]
fn rejected_conflict_does_not_block_the_matching_successor() {
    let (sync, blocks, path) = fixture("recovery_control", 2);
    let conflict = signed_empty(&sync, 2, &blocks[0].header.hash, 24);
    let before = rows(&sync.storage);
    assert_eq!(sync.process_blocks(vec![conflict], 2), 2);
    assert_eq!(rows(&sync.storage), before);
    let next = signed_empty(&sync, 3, &blocks[1].header.hash, 24);
    assert_eq!(sync.process_blocks(vec![next.clone()], 2), 3);
    assert_eq!(sync.storage.get_chain_height(), 3);
    assert_eq!(
        executor::Executor::new(sync.storage.clone()).last_executed_height(),
        3
    );
    assert_eq!(
        sync.storage.get("latest_block_hash").unwrap(),
        Some(next.header.hash)
    );
    let after = rows(&sync.storage);
    assert_preserved(sync, after, path);
}
