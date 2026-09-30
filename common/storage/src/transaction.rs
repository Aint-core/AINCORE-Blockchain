//! Serialized, write-behind views over the existing RocksDB format.
//!
//! The raw database is private: all writers share the same gate. A transaction
//! holds that gate while its callback runs, so base reads and prefix scans cannot
//! race a writer. Only staged writes are copied; the database is not materialized.
use crate::class::{classify, KeyClass, Observer, StateClassStats, WriteContext};
use crate::{StateDB, StorageError, RESTORE_MARKER};
use rocksdb::{Direction, IteratorMode, WriteBatch, WriteBatchIterator, DB};
use std::collections::BTreeMap;
use std::iter::Peekable;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

type Changes = BTreeMap<Vec<u8>, Option<Arc<[u8]>>>;
type OverlayEntry = (Vec<u8>, Option<Arc<[u8]>>);
type Row = (Box<[u8]>, Box<[u8]>);
type ReadResult = Result<Row, rocksdb::Error>;

struct Shared {
    raw: DB,
    writers: Mutex<()>,
    /// G3 S0: counts unclassified keys and state written outside the block
    /// transaction. The refusal itself is `ReadStore::write` (WG-1, S3).
    observer: Observer,
    /// Live `SeedingGuard`s (tests only): while nonzero, a base write of a
    /// state key is allowed, so a fixture can write its own genesis state.
    seeding: Arc<std::sync::atomic::AtomicUsize>,
    /// Declared after `raw` on purpose: fields drop in declaration order, so the
    /// directory becomes claimable again only after RocksDB has closed it.
    _claim: Option<crate::DirectoryClaim>,
}

struct Stage {
    changes: Mutex<Changes>,
    active: AtomicBool,
    read_failed: AtomicBool,
    /// True only for the executor's block transaction (G3 WG-1).
    block: bool,
    /// True only for a snapshot restore's transaction (G3 SN-2).
    restore: bool,
    /// G3 CM-2: set once the block's state root is computed. From then on a
    /// consensus-state write would escape the root, so it fails the whole
    /// block at commit (`seal_violated`).
    sealed: AtomicBool,
    seal_violated: AtomicBool,
}

impl Stage {
    fn check_active(&self) {
        assert!(
            self.active.load(Ordering::Acquire),
            "transaction view has closed"
        );
    }
}

struct CloseStage(Arc<Stage>);

impl Drop for CloseStage {
    fn drop(&mut self) {
        self.0.active.store(false, Ordering::Release);
    }
}

/// Read-only public handle. Writes must use StateDB, never a raw RocksDB handle.
pub struct ReadStore {
    shared: Arc<Shared>,
    stage: Option<Arc<Stage>>,
}

impl From<DB> for ReadStore {
    fn from(raw: DB) -> Self {
        Self {
            shared: Arc::new(Shared {
                raw,
                writers: Mutex::new(()),
                observer: Observer::default(),
                seeding: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                _claim: None,
            }),
            stage: None,
        }
    }
}

impl ReadStore {
    /// A store that holds the process-wide claim on its directory until the
    /// last handle to it, transaction views included, is dropped.
    pub(crate) fn claimed(raw: DB, claim: crate::DirectoryClaim) -> Self {
        Self {
            shared: Arc::new(Shared {
                raw,
                writers: Mutex::new(()),
                observer: Observer::default(),
                seeding: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                _claim: Some(claim),
            }),
            stage: None,
        }
    }
}

impl ReadStore {
    pub(crate) fn invalid_read(&self) {
        if let Some(stage) = &self.stage {
            stage.read_failed.store(true, Ordering::Release);
        }
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, rocksdb::Error> {
        if let Some(stage) = &self.stage {
            let changes = stage.changes.lock().expect("transaction changes poisoned");
            stage.check_active();
            if let Some(value) = changes.get(key.as_ref()) {
                return Ok(value.as_ref().map(|value| value.to_vec()));
            }
        }
        let value = self.shared.raw.get(key);
        if value.is_err() {
            if let Some(stage) = &self.stage {
                stage.read_failed.store(true, Ordering::Release);
            }
        }
        value
    }

    pub fn iterator(&self, mode: IteratorMode<'_>) -> StoreIterator<'_> {
        let reverse = matches!(
            mode,
            IteratorMode::End | IteratorMode::From(_, Direction::Reverse)
        );
        let mut overlay = Vec::new();
        if let Some(stage) = &self.stage {
            let changes = stage.changes.lock().expect("transaction changes poisoned");
            stage.check_active();
            overlay.extend(
                changes
                    .iter()
                    .filter(|(key, _)| match mode {
                        IteratorMode::From(start, Direction::Forward) => key.as_slice() >= start,
                        IteratorMode::From(start, Direction::Reverse) => key.as_slice() <= start,
                        _ => true,
                    })
                    .map(|(k, v)| (k.clone(), v.clone())),
            );
        }
        if reverse {
            overlay.reverse();
        }
        StoreIterator {
            base: self.shared.raw.iterator(mode).peekable(),
            overlay: overlay.into_iter().peekable(),
            reverse,
            stage: self.stage.clone(),
        }
    }

    pub fn prefix_iterator(&self, prefix: impl AsRef<[u8]>) -> StoreIterator<'_> {
        self.iterator(IteratorMode::From(prefix.as_ref(), Direction::Forward))
    }

    /// The write gate, enforced from G3 S3.
    /// - CL-1: every key must be classified, in every context.
    /// - WG-1: consensus state is written only inside the block transaction.
    /// - Only plain puts and deletes pass. A range delete names no keys the
    ///   gate could check, so it is refused.
    ///
    /// A refused batch is refused whole: nothing in it is written.
    fn gate<'k>(
        &self,
        ctx: WriteContext,
        keys: impl Iterator<Item = &'k [u8]>,
        visited: usize,
        batch_len: usize,
    ) -> Result<(), StorageError> {
        // Refused even while seeding: the binding would not stage it.
        if visited != batch_len {
            return Err(StorageError::WriteGate(format!(
                "a batch with {} operations other than put or delete (range delete?)",
                batch_len - visited
            )));
        }
        if self.shared.seeding.load(Ordering::Acquire) > 0 {
            return Ok(());
        }
        for key in keys {
            match classify(key) {
                None => {
                    return Err(StorageError::WriteGate(format!(
                        "unclassified key {} (CL-1)",
                        crate::class::mask(key)
                    )))
                }
                Some(KeyClass::State) if !ctx.may_write_state() => {
                    return Err(StorageError::WriteGate(format!(
                        "state key {} written outside the block transaction ({} context)",
                        crate::class::mask(key),
                        ctx.as_str()
                    )))
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    pub(crate) fn write(&self, batch: WriteBatch) -> Result<(), StorageError> {
        let ctx = match &self.stage {
            None => WriteContext::Base,
            Some(stage) if stage.block => WriteContext::Block,
            Some(stage) if stage.restore => WriteContext::Restore,
            Some(_) => WriteContext::Transaction,
        };
        if let Some(stage) = &self.stage {
            let mut collected = BatchChanges::default();
            batch.iterate(&mut collected);
            for key in collected.changes.keys() {
                self.shared.observer.observe(key, ctx);
            }
            self.gate(
                ctx,
                collected.changes.keys().map(Vec::as_slice),
                collected.count,
                batch.len(),
            )?;
            if stage.sealed.load(Ordering::Acquire)
                && collected
                    .changes
                    .keys()
                    .any(|key| classify(key) == Some(KeyClass::State))
            {
                stage.seal_violated.store(true, Ordering::Release);
            }
            let mut changes = stage.changes.lock().expect("transaction changes poisoned");
            stage.check_active();
            changes.extend(collected.changes);
            Ok(())
        } else {
            // Only the keys are kept. The rocksdb binding still copies each
            // value to call `put`, then this collector drops it at once: one
            // transient copy per base write, which the observer accepts.
            let mut keys = BatchKeys::default();
            batch.iterate(&mut keys);
            for key in &keys.keys {
                self.shared.observer.observe(key, ctx);
            }
            self.gate(
                ctx,
                keys.keys.iter().map(|key| &key[..]),
                keys.keys.len(),
                batch.len(),
            )?;

            let _guard = self
                .shared
                .writers
                .lock()
                .expect("storage writer gate poisoned");
            Ok(self.write_durable(batch)?)
        }
    }

    /// Tests only: see `StateDB::seeding`.
    #[cfg(any(test, feature = "test-seeding"))]
    pub(crate) fn seeding(&self) -> SeedingGuard {
        self.shared.seeding.fetch_add(1, Ordering::AcqRel);
        SeedingGuard(Arc::clone(&self.shared.seeding))
    }

    /// G3 CM-1: the consensus-state writes staged so far in this block
    /// transaction, last write per key (`None` = delete). `None` outside a
    /// transaction view.
    pub fn staged_state_changes(&self) -> Option<Vec<(String, Option<Vec<u8>>)>> {
        let stage = self.stage.as_ref()?;
        let changes = stage.changes.lock().expect("transaction changes poisoned");
        stage.check_active();
        Some(
            changes
                .iter()
                .filter(|(key, _)| classify(key) == Some(KeyClass::State))
                .filter_map(|(key, value)| {
                    let key = String::from_utf8(key.clone()).ok()?;
                    Some((key, value.as_ref().map(|v| v.to_vec())))
                })
                .collect(),
        )
    }

    /// A value staged in THIS transaction only, never the base database:
    /// `Some(Some(v))` written, `Some(None)` deleted, `None` untouched (or no
    /// transaction). Used for data a block must derive from its own writes.
    pub fn staged_get(&self, key: &[u8]) -> Option<Option<Vec<u8>>> {
        let stage = self.stage.as_ref()?;
        let changes = stage.changes.lock().expect("transaction changes poisoned");
        stage.check_active();
        changes.get(key).map(|v| v.as_ref().map(|v| v.to_vec()))
    }

    /// G3 CM-2: seal consensus state once the root is computed. Returns false
    /// outside the block transaction, where sealing has no meaning.
    pub fn seal_state(&self) -> bool {
        match &self.stage {
            Some(stage) if stage.block => {
                stage.sealed.store(true, Ordering::Release);
                true
            }
            _ => false,
        }
    }

    /// G3 S0 counters for this database.
    pub fn state_class_stats(&self) -> StateClassStats {
        self.shared.observer.stats()
    }

    fn write_durable(&self, batch: WriteBatch) -> Result<(), rocksdb::Error> {
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        self.shared.raw.write_opt(batch, &options)
    }

    pub(crate) fn flush(&self) -> Result<(), rocksdb::Error> {
        assert!(
            self.stage.is_none(),
            "cannot flush a speculative transaction"
        );
        let _guard = self
            .shared
            .writers
            .lock()
            .expect("storage writer gate poisoned");
        self.shared.raw.flush_wal(true)?;
        self.shared.raw.flush()
    }
}

/// The keys of a batch, without copying its values.
/// The keys of a base batch's plain puts and deletes. Any other operation
/// is not visited, so `keys.len() < batch.len()` reveals it.
#[derive(Default)]
struct BatchKeys {
    keys: Vec<Box<[u8]>>,
}

impl WriteBatchIterator for BatchKeys {
    fn put(&mut self, key: Box<[u8]>, _value: Box<[u8]>) {
        self.keys.push(key);
    }

    fn delete(&mut self, key: Box<[u8]>) {
        self.keys.push(key);
    }
}

#[derive(Default)]
struct BatchChanges {
    changes: Changes,
    count: usize,
}

impl WriteBatchIterator for BatchChanges {
    fn put(&mut self, key: Box<[u8]>, value: Box<[u8]>) {
        self.count += 1;
        self.changes.insert(key.into_vec(), Some(Arc::from(value)));
    }

    fn delete(&mut self, key: Box<[u8]>) {
        self.count += 1;
        self.changes.insert(key.into_vec(), None);
    }
}

/// Merge a native snapshot iterator with staged overrides, without reading the
/// whole underlying prefix into memory. Tombstones suppress base entries.
pub struct StoreIterator<'a> {
    base: Peekable<rocksdb::DBIterator<'a>>,
    overlay: Peekable<std::vec::IntoIter<OverlayEntry>>,
    reverse: bool,
    stage: Option<Arc<Stage>>,
}

impl Iterator for StoreIterator<'_> {
    type Item = ReadResult;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(stage) = &self.stage {
            stage.check_active();
        }
        loop {
            if matches!(self.base.peek(), Some(Err(_))) {
                if let Some(stage) = &self.stage {
                    stage.read_failed.store(true, Ordering::Release);
                }
                return self.base.next();
            }
            let take_overlay = match (self.base.peek(), self.overlay.peek()) {
                (_, None) => false,
                (None, Some(_)) => true,
                (Some(Ok((base_key, _))), Some((key, _))) => {
                    let cmp = key.as_slice().cmp(base_key.as_ref());
                    if cmp.is_eq() {
                        self.base.next();
                    }
                    if self.reverse {
                        !cmp.is_lt()
                    } else {
                        !cmp.is_gt()
                    }
                }
                _ => unreachable!(),
            };
            if !take_overlay {
                return self.base.next();
            }
            let (key, value) = self.overlay.next().unwrap();
            if let Some(value) = value {
                return Some(Ok((
                    key.into_boxed_slice(),
                    value.to_vec().into_boxed_slice(),
                )));
            }
        }
    }
}

impl StateDB {
    /// G3 CM-1: consensus-state writes staged in this transaction view.
    pub fn staged_state_changes(&self) -> Option<Vec<(String, Option<Vec<u8>>)>> {
        self.db.staged_state_changes()
    }

    /// G3 CM-2: seal consensus state in the block transaction.
    pub fn seal_state(&self) -> bool {
        self.db.seal_state()
    }

    /// A value staged in this transaction only (see `ReadStore::staged_get`).
    pub fn staged_get(&self, key: &str) -> Option<Option<Vec<u8>>> {
        self.db.staged_get(key.as_bytes())
    }

    /// Execute against a private write-behind view; publish one synced batch only
    /// on success. ALL callback DB access must use the supplied view. Re-entering
    /// a base writer from this callback would deadlock on the non-reentrant gate.
    /// Views must not escape; any use after closure completion panics.
    pub fn transaction<T>(
        &self,
        work: impl FnOnce(Arc<StateDB>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.transaction_with(false, false, work)
    }

    /// The executor's block transaction, and genesis's: the only place
    /// consensus state may be written (G3 WG-1, enforced since S3).
    /// Everywhere else such a write is refused. Otherwise it has the same
    /// semantics as `transaction`.
    pub fn block_transaction<T>(
        &self,
        work: impl FnOnce(Arc<StateDB>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        self.transaction_with(true, false, work)
    }

    /// A snapshot restore's transaction (G3 SN-2): it may write consensus
    /// state, like the block transaction, and opens only while the database
    /// carries the restore marker `sys:restore_in_progress`. Everything it
    /// writes came out of a chunk verified against the trusted root.
    pub fn restore_transaction<T>(
        &self,
        work: impl FnOnce(Arc<StateDB>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        if self.get(RESTORE_MARKER)?.is_none() {
            return Err(StorageError::WriteGate(
                "a restore transaction needs the restore marker".into(),
            ));
        }
        self.transaction_with(false, true, work)
    }

    fn transaction_with<T>(
        &self,
        block: bool,
        restore: bool,
        work: impl FnOnce(Arc<StateDB>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        if self.db.stage.is_some() {
            return Err(StorageError::DatabaseOperation(
                "nested transaction refused".into(),
            ));
        }
        let _guard =
            self.db.shared.writers.lock().map_err(|_| {
                StorageError::DatabaseOperation("storage writer gate poisoned".into())
            })?;
        let stage = Arc::new(Stage {
            changes: Mutex::new(BTreeMap::new()),
            active: AtomicBool::new(true),
            read_failed: AtomicBool::new(false),
            block,
            restore,
            sealed: AtomicBool::new(false),
            seal_violated: AtomicBool::new(false),
        });
        let _close = CloseStage(stage.clone());
        let view = Arc::new(StateDB {
            db: ReadStore {
                shared: self.db.shared.clone(),
                stage: Some(stage.clone()),
            },
        });
        let result = work(view)?;
        let changes = stage
            .changes
            .lock()
            .map_err(|_| StorageError::DatabaseOperation("transaction changes poisoned".into()))?;
        stage.active.store(false, Ordering::Release);
        if stage.read_failed.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseOperation(
                "transaction encountered a storage read error".into(),
            ));
        }
        if stage.seal_violated.load(Ordering::Acquire) {
            return Err(StorageError::DatabaseOperation(
                "consensus state was written after the block's state root was sealed".into(),
            ));
        }
        let mut batch = WriteBatch::default();
        for (key, value) in changes.iter() {
            match value {
                Some(value) => batch.put(key, value.as_ref()),
                None => batch.delete(key),
            }
        }
        self.db.write_durable(batch)?;
        Ok(result)
    }
}

/// Tests only (G3 WG-1): while it lives, base writes of state keys are allowed
/// on its database. Never compiled into a production binary: it exists only
/// for this crate's tests and the `test-seeding` feature, which other crates
/// enable in `[dev-dependencies]` only.
#[cfg(any(test, feature = "test-seeding"))]
/// It holds only the counter, so it never keeps the database open.
pub struct SeedingGuard(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(any(test, feature = "test-seeding"))]
impl Drop for SeedingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            // A counter, not the clock: macOS clocks tick in microseconds, so
            // two parallel tests could build the same name.
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "aincore-tx-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn open(&self) -> StateDB {
            StateDB::open(self.0.to_str().unwrap()).unwrap()
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rows(db: &StateDB) -> Vec<Row> {
        db.db
            .iterator(IteratorMode::Start)
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn staged_reads_scans_and_batches_commit_together() {
        let dir = TempDir::new();
        let db = dir.open();
        let _seed = db.seeding();
        db.put("p:a", "old").unwrap();
        db.put("p:c", "keep").unwrap();
        db.put("q:a", "other").unwrap();
        db.transaction(|view| {
            let mut batch = WriteBatch::default();
            batch.put("p:b", "first");
            batch.put("p:b", "last");
            batch.delete("p:a");
            view.write_batch(batch)?;
            assert_eq!(view.get("p:b")?, Some("last".into()));
            assert_eq!(view.get("p:a")?, None);
            assert_eq!(db.get("p:a")?, Some("old".into()));
            assert_eq!(db.get("p:b")?, None, "uncommitted data leaked");
            assert_eq!(
                view.scan_prefix_limited("p:", 1),
                vec![("p:b".into(), "last".into())]
            );
            assert_eq!(
                view.scan_prefix("p:"),
                vec![("p:b".into(), "last".into()), ("p:c".into(), "keep".into())]
            );
            let expected = rows(&view);
            let backwards: Vec<_> = view
                .db
                .iterator(IteratorMode::End)
                .map(Result::unwrap)
                .collect();
            assert_eq!(backwards, expected.into_iter().rev().collect::<Vec<_>>());
            let keys: Vec<_> = view
                .db
                .iterator(IteratorMode::From(b"p:b", Direction::Reverse))
                .map(|row| row.unwrap().0)
                .collect();
            assert_eq!(keys, vec![b"p:b".to_vec().into_boxed_slice()]);
            Ok(())
        })
        .unwrap();
        assert_eq!(db.get("p:a").unwrap(), None);
        assert_eq!(db.get("p:b").unwrap().as_deref(), Some("last"));
        let expected = rows(&db);
        drop(db);
        assert_eq!(rows(&dir.open()), expected);
    }

    #[test]
    fn rejected_transaction_discards_writes_and_seals_escaped_view() {
        let dir = TempDir::new();
        let db = dir.open();
        let _seed = db.seeding();
        db.put("key", "old").unwrap();
        let before = rows(&db);
        let mut escaped = None;
        let result: Result<(), _> = db.transaction(|view| {
            view.put("key", "unaccepted")?;
            escaped = Some(view);
            Err(StorageError::DatabaseOperation(
                "rejected block root".into(),
            ))
        });
        assert!(result.is_err());
        assert_eq!(rows(&db), before);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            escaped.unwrap().put("key", "late write").unwrap();
        }))
        .is_err());
        // Rejection is not poisoning: a later valid transaction may commit.
        db.transaction(|view| {
            view.put("key", "accepted")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(db.get("key").unwrap().as_deref(), Some("accepted"));
    }

    #[test]
    fn iterator_retains_staged_snapshot_while_view_changes() {
        let dir = TempDir::new();
        let db = dir.open();
        // Mechanics only: generic keys, written under the test guard.
        let _seed = db.seeding();
        db.transaction(|view| {
            view.put("key", "first")?;
            let iter = view.db.iterator(IteratorMode::Start);
            view.put("key", "second")?;
            view.put("later", "new")?;
            let snapshot: Vec<_> = iter.map(Result::unwrap).collect();
            assert_eq!(
                snapshot,
                vec![(
                    b"key".to_vec().into_boxed_slice(),
                    b"first".to_vec().into_boxed_slice()
                )]
            );
            assert_eq!(view.get("key")?.as_deref(), Some("second"));
            Ok(())
        })
        .unwrap();
        assert_eq!(db.get("key").unwrap().as_deref(), Some("second"));
    }

    #[test]
    fn real_read_only_commit_error_publishes_nothing() {
        let dir = TempDir::new();
        {
            let db = dir.open();
            let _seed = db.seeding();
            db.put("key", "old").unwrap();
        }
        let db = StateDB {
            db: DB::open_for_read_only(&rocksdb::Options::default(), &dir.0, false)
                .unwrap()
                .into(),
        };
        let before = rows(&db);
        assert!(db
            .transaction(|view| {
                view.put("key", "new")?;
                view.put("extra", "new")?;
                Ok(())
            })
            .is_err());
        assert_eq!(rows(&db), before);
    }

    #[test]
    fn ignored_decode_error_still_refuses_transaction_commit() {
        let dir = TempDir::new();
        let db = dir.open();
        let mut batch = WriteBatch::default();
        batch.put("bad_utf8", [0xff]);
        batch.put("obj:bad_object", "not json");
        let _seed = db.seeding();
        db.write_batch(batch).unwrap();
        for object in [false, true] {
            let before = rows(&db);
            let result = db.transaction(|view| {
                if object {
                    assert!(view.get_object("bad_object").is_none());
                } else {
                    assert!(view.get("bad_utf8")?.is_none());
                }
                view.put("must_not_commit", "value")?;
                Ok(())
            });
            assert!(
                result.is_err(),
                "swallowed storage corruption must not authorize commit"
            );
            assert_eq!(rows(&db), before);
        }
    }

    #[test]
    fn outside_write_is_ordered_after_transaction() {
        let dir = TempDir::new();
        let db = Arc::new(dir.open());
        let _seed = db.seeding();
        db.put("key", "old").unwrap();
        let mut writer = None;
        db.transaction(|view| {
            assert!(db.db.shared.writers.try_lock().is_err());
            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let outside = db.clone();
            writer = Some(std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                outside.put("key", "outside").unwrap();
                done_tx.send(()).unwrap();
            }));
            started_rx.recv().unwrap();
            assert!(done_rx
                .recv_timeout(std::time::Duration::from_millis(30))
                .is_err());
            view.put("key", "transaction")?;
            assert_eq!(view.get("key")?.as_deref(), Some("transaction"));
            // Keep the receiver alive until the writer returns.
            Ok(done_rx)
        })
        .unwrap()
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
        writer.unwrap().join().unwrap();
        assert_eq!(db.get("key").unwrap().as_deref(), Some("outside"));
    }
}
