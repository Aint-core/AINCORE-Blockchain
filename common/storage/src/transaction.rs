//! Serialized, write-behind views over the existing RocksDB format.
//!
//! The raw database is private: all writers share the same gate. A transaction
//! holds that gate while its callback runs, so base reads and prefix scans cannot
//! race a writer. Only staged writes are copied; the database is not materialized.
use crate::{StateDB, StorageError};
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
}

struct Stage {
    changes: Mutex<Changes>,
    active: AtomicBool,
    read_failed: AtomicBool,
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

    pub(crate) fn write(&self, batch: WriteBatch) -> Result<(), rocksdb::Error> {
        if let Some(stage) = &self.stage {
            let mut collected = BatchChanges::default();
            batch.iterate(&mut collected);
            // The binding only visits default-column puts/deletes. Never silently
            // omit other operation kinds from a transaction's commit.
            assert_eq!(
                collected.count,
                batch.len(),
                "unsupported staged batch operation"
            );
            let mut changes = stage.changes.lock().expect("transaction changes poisoned");
            stage.check_active();
            changes.extend(collected.changes);
            Ok(())
        } else {
            let _guard = self
                .shared
                .writers
                .lock()
                .expect("storage writer gate poisoned");
            self.write_durable(batch)
        }
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
    /// Execute against a private write-behind view; publish one synced batch only
    /// on success. ALL callback DB access must use the supplied view. Re-entering
    /// a base writer from this callback would deadlock on the non-reentrant gate.
    /// Views must not escape; any use after closure completion panics.
    pub fn transaction<T>(
        &self,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aincore-tx-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
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
