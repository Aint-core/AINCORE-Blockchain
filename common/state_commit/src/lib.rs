//! G3 state commitment: a Jellyfish Merkle Tree over the consensus-state keys
//! (class `State`), stored in the node's RocksDB under `jmt:*` (class `Tree`).
//! Contract: `docs/G3_STATE_AUTHENTICATION_CONTRACT.md` (CM-1, CM-7, CM-8,
//! PF, SN-2).
//!
//! The `jmt` crate computes roots and proofs, but it does not:
//! - sequence versions (applying `v` without `v-1` silently yields a root over
//!   the change set alone: probes P4/P5);
//! - refuse re-applying a version (P9);
//! - reject an incomplete restore (`finish` accepts it: P6);
//! - survive restoring over an older tree (it panics: P7).
//!
//! This wrapper enforces every one of those, and diffs each change against
//! the previous version, so a same-bytes rewrite or a delete of an absent key
//! is not a change (CM-1).

use anyhow::{bail, ensure, Context, Result};
use jmt::restore::{JellyfishMerkleRestore, StateSnapshotReceiver};
use jmt::storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter};
use jmt::{JellyfishMerkleIterator, KeyHash, OwnedValue, RootHash, Sha256Jmt, Version};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Arc;
use storage::class::{classify, KeyClass};
use storage::rocksdb::{Direction, IteratorMode, WriteBatch};
use storage::StateDB;

pub use jmt::proof::{SparseMerkleProof, SparseMerkleRangeProof};

/// Flat `(key, value)` pairs of one restore chunk.
pub type Entries = Vec<(String, Vec<u8>)>;

/// Largest chunk `chunk` will serve.
pub const MAX_CHUNK: usize = 10_000;

/// `jmt` unwraps reader results in places (`node_type.rs:533-542`), and its
/// restore asserts on internal state (`node_type.rs:411`, `restore.rs:668`),
/// so a missing or malformed row, or a hostile peer's input, can panic inside
/// it. Every call into `jmt` goes through here and becomes an error instead.
/// This relies on `panic = "unwind"`, the workspace default: a profile that
/// sets `panic = "abort"` would turn these back into crashes.
fn no_panic<T>(what: &str, f: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(result) => result,
        Err(_) => bail!("{what}: the state tree panicked (missing, corrupt or hostile tree data)"),
    }
}

/// The seam behind which the tree can later be swapped (NOMT, QMDB, a
/// binary tree for ZK) without touching the executor (contract: route
/// decision).
pub trait StateCommitment {
    fn apply(&self, version: Version, changes: Vec<(String, Option<Vec<u8>>)>) -> Result<Applied>;
    fn root(&self, version: Version) -> Result<RootHash>;
    fn prove(
        &self,
        key: &str,
        version: Version,
    ) -> Result<(Option<OwnedValue>, SparseMerkleProof<Sha256>)>;
}

/// The Jellyfish Merkle Tree backend.
pub struct Jmt {
    db: Arc<StateDB>,
}

impl Jmt {
    pub fn new(db: Arc<StateDB>) -> Self {
        Self { db }
    }
}

impl StateCommitment for Jmt {
    fn apply(&self, version: Version, changes: Vec<(String, Option<Vec<u8>>)>) -> Result<Applied> {
        apply(&self.db, version, changes)
    }
    fn root(&self, version: Version) -> Result<RootHash> {
        root(&self.db, version)
    }
    fn prove(
        &self,
        key: &str,
        version: Version,
    ) -> Result<(Option<OwnedValue>, SparseMerkleProof<Sha256>)> {
        prove(&self.db, key, version)
    }
}

/// Tree nodes: `jmt:node:{hex(borsh(NodeKey))}` → `hex(borsh(Node))`.
const NODE: &str = "jmt:node:";
/// Value history: `jmt:val:{keyhash}:{version:020}` → `v{hex}` or `d` (deleted).
const VAL: &str = "jmt:val:";
/// Stale-node index for pruning: `jmt:stale:{since:020}:{hex(borsh(NodeKey))}`.
const STALE: &str = "jmt:stale:";
/// Key preimages: `jmt:pre:{keyhash}` → the flat key.
const PRE: &str = "jmt:pre:";
/// The latest applied version.
pub const LATEST: &str = "jmt:latest";

/// The hash a state key is stored under. Clients derive it themselves from
/// the canonical key (PF-2); a server-supplied key hash is never trusted.
pub fn key_hash(key: &str) -> KeyHash {
    KeyHash::with::<Sha256>(key.as_bytes())
}

fn node_key(k: &NodeKey) -> Result<String> {
    Ok(format!("{NODE}{}", hex::encode(borsh::to_vec(k)?)))
}

fn val_key(kh: &KeyHash, version: Version) -> String {
    format!("{VAL}{}:{:020}", hex::encode(kh.0), version)
}

fn val_prefix(kh: &KeyHash) -> String {
    format!("{VAL}{}:", hex::encode(kh.0))
}

fn stale_key(since: Version, k: &NodeKey) -> Result<String> {
    Ok(format!(
        "{STALE}{:020}:{}",
        since,
        hex::encode(borsh::to_vec(k)?)
    ))
}

fn pre_key(kh: &KeyHash) -> String {
    format!("{PRE}{}", hex::encode(kh.0))
}

/// `v{hex}` for a value (empty values stay distinct from deletions), `d` for
/// a deletion.
fn encode_value(value: Option<&[u8]>) -> String {
    match value {
        Some(v) => format!("v{}", hex::encode(v)),
        None => "d".to_string(),
    }
}

fn decode_value(raw: &[u8]) -> Result<Option<OwnedValue>> {
    match raw.split_first() {
        Some((b'v', hex_bytes)) => Ok(Some(hex::decode(hex_bytes)?)),
        Some((b'd', [])) => Ok(None),
        _ => bail!("malformed tree value row"),
    }
}

/// The tree's reader and writer over the node database. Reads and writes go
/// through `StateDB`, so inside a transaction view they are staged like any
/// other write.
pub struct JmtStore {
    db: Arc<StateDB>,
}

impl JmtStore {
    pub fn new(db: Arc<StateDB>) -> Self {
        Self { db }
    }
}

impl TreeReader for JmtStore {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        match self.db.get(&node_key(key)?)? {
            None => Ok(None),
            Some(raw) => Ok(Some(borsh::from_slice(&hex::decode(raw)?)?)),
        }
    }

    /// Newest value at or below `max_version`: a reverse seek over the
    /// zero-padded version suffix.
    fn get_value_option(&self, max_version: Version, kh: KeyHash) -> Result<Option<OwnedValue>> {
        let prefix = val_prefix(&kh);
        let start = val_key(&kh, max_version);
        let mut it = self
            .db
            .db
            .iterator(IteratorMode::From(start.as_bytes(), Direction::Reverse));
        match it.next() {
            Some(Ok((k, v))) if k.starts_with(prefix.as_bytes()) => decode_value(&v),
            Some(Err(e)) => Err(e.into()),
            _ => Ok(None),
        }
    }

    /// Only a restore resumes from here, and `Restore::begin` requires an
    /// empty namespace, so a full scan is acceptable.
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let mut best: Option<(NodeKey, LeafNode)> = None;
        for row in self.db.db.prefix_iterator(NODE.as_bytes()) {
            let (k, v) = row?;
            if !k.starts_with(NODE.as_bytes()) {
                break;
            }
            let key: NodeKey = borsh::from_slice(&hex::decode(&k[NODE.len()..])?)?;
            if let Node::Leaf(leaf) = borsh::from_slice::<Node>(&hex::decode(&v)?)? {
                if best
                    .as_ref()
                    .is_none_or(|(_, b)| leaf.key_hash() > b.key_hash())
                {
                    best = Some((key, leaf));
                }
            }
        }
        Ok(best)
    }
}

impl TreeWriter for JmtStore {
    /// Used by restore only; block commits build their batch in `apply`.
    /// Like `apply`, it never overwrites an existing node (CM-7).
    fn write_node_batch(&self, batch: &NodeBatch) -> Result<()> {
        let mut wb = WriteBatch::default();
        for (k, node) in batch.nodes() {
            let key = node_key(k)?;
            ensure!(
                self.db.get(&key)?.is_none(),
                "refusing to overwrite tree node {key}"
            );
            wb.put(key, hex::encode(borsh::to_vec(node)?));
        }
        for ((version, kh), value) in batch.values() {
            wb.put(val_key(kh, *version), encode_value(value.as_deref()));
        }
        self.db.write_batch(wb)?;
        Ok(())
    }
}

/// The latest applied version, if any.
pub fn latest_version(db: &StateDB) -> Result<Option<Version>> {
    db.get(LATEST)?
        .map(|s| s.parse::<Version>().context("malformed jmt:latest"))
        .transpose()
}

/// The result of applying one version: the new root, plus every tree row to
/// write in the SAME atomic batch as the block (CM-3). Nothing is written by
/// `apply` itself.
pub struct Applied {
    pub root: RootHash,
    pub batch: WriteBatch,
    /// State keys whose value actually changed.
    pub changed: usize,
}

/// Apply version `version` (CM-2, CM-7).
///
/// - Sequencing: version 0 needs an empty tree; any later version needs
///   `jmt:latest == version - 1` and that version's root node present.
/// - Diff (CM-1): each change is compared with the value at `version - 1`,
///   and an unchanged value or a delete of an absent key is dropped.
/// - Overwrite refusal: an existing tree node is never overwritten.
/// - Only `State` keys may be committed.
pub fn apply(
    db: &Arc<StateDB>,
    version: Version,
    changes: impl IntoIterator<Item = (String, Option<Vec<u8>>)>,
) -> Result<Applied> {
    apply_checked(db, version, changes, true)
}

/// `apply`, with the state-key check switchable only so tests can build the
/// tree a malicious server would serve.
fn apply_checked(
    db: &Arc<StateDB>,
    version: Version,
    changes: impl IntoIterator<Item = (String, Option<Vec<u8>>)>,
    state_keys_only: bool,
) -> Result<Applied> {
    let store = JmtStore::new(db.clone());
    match (latest_version(db)?, version) {
        (None, 0) => ensure!(
            tree_namespace_empty(db)?,
            "version 0 needs an empty tree namespace (leftover rows from a failed restore?)"
        ),
        (Some(prev), v) if Some(v) == prev.checked_add(1) => {
            ensure!(
                Sha256Jmt::new(&store).get_root_hash_option(prev)?.is_some(),
                "root node of version {prev} is missing"
            );
        }
        (latest, v) => bail!("state tree out of sequence: latest {latest:?}, applying {v}"),
    }

    let mut set: BTreeMap<KeyHash, Option<Vec<u8>>> = BTreeMap::new();
    let mut preimages: BTreeMap<KeyHash, String> = BTreeMap::new();
    for (key, value) in changes {
        ensure!(
            !state_keys_only || classify(key.as_bytes()) == Some(KeyClass::State),
            "not a state key: {key:?}"
        );
        let kh = key_hash(&key);
        ensure!(
            set.insert(kh, value).is_none(),
            "duplicate key in one change set: {key:?}"
        );
        preimages.insert(kh, key);
    }
    if version > 0 {
        let mut unchanged = Vec::new();
        for (kh, value) in &set {
            if store.get_value_option(version - 1, *kh)? == *value {
                unchanged.push(*kh);
            }
        }
        for kh in unchanged {
            set.remove(&kh);
            preimages.remove(&kh);
        }
    } else {
        set.retain(|_, v| v.is_some());
        preimages.retain(|kh, _| set.contains_key(kh));
    }
    let changed = set.len();

    let (root, update) = no_panic("apply", || {
        Sha256Jmt::new(&store).put_value_set(set, version)
    })?;

    let mut batch = WriteBatch::default();
    for (k, node) in update.node_batch.nodes() {
        let key = node_key(k)?;
        ensure!(
            db.get(&key)?.is_none(),
            "refusing to overwrite tree node {key}"
        );
        batch.put(key, hex::encode(borsh::to_vec(node)?));
    }
    for ((v, kh), value) in update.node_batch.values() {
        batch.put(val_key(kh, *v), encode_value(value.as_deref()));
    }
    for stale in &update.stale_node_index_batch {
        batch.put(stale_key(stale.stale_since_version, &stale.node_key)?, "");
    }
    for (kh, key) in preimages {
        let pk = pre_key(&kh);
        if db.get(&pk)?.is_none() {
            batch.put(pk, key);
        }
    }
    batch.put(LATEST, version.to_string());
    Ok(Applied {
        root,
        batch,
        changed,
    })
}

/// The root at `version`.
pub fn root(db: &Arc<StateDB>, version: Version) -> Result<RootHash> {
    no_panic("root", || {
        Sha256Jmt::new(&JmtStore::new(db.clone())).get_root_hash(version)
    })
}

/// Value and proof for `key` at `version`. An absent key yields `None` plus
/// an exclusion proof.
pub fn prove(
    db: &Arc<StateDB>,
    key: &str,
    version: Version,
) -> Result<(Option<OwnedValue>, SparseMerkleProof<Sha256>)> {
    no_panic("prove", || {
        Sha256Jmt::new(&JmtStore::new(db.clone())).get_with_proof(key_hash(key), version)
    })
}

/// Verify `key` → `value` (or its absence, for `None`) against `root`. The
/// key hash is computed here, never taken from the prover.
pub fn verify(
    root: RootHash,
    key: &str,
    value: Option<&[u8]>,
    proof: &SparseMerkleProof<Sha256>,
) -> Result<()> {
    proof.verify(root, key_hash(key), value)
}

/// Serve one restore chunk at `version`: up to `max` leaves after `after`,
/// with their flat keys and a range proof up to the last one. `Ok(None)`
/// means the stream is complete; `Err` always means a failure.
pub fn chunk(
    db: &Arc<StateDB>,
    version: Version,
    after: Option<KeyHash>,
    max: usize,
) -> Result<Option<(Entries, SparseMerkleRangeProof<Sha256>)>> {
    ensure!(
        (1..=MAX_CHUNK).contains(&max),
        "chunk size must be 1..={MAX_CHUNK}"
    );
    no_panic("chunk", || {
        let store = Arc::new(JmtStore::new(db.clone()));
        let start = after.unwrap_or(KeyHash([0u8; 32]));
        let mut out = Vec::new();
        let mut last = None;
        for item in JellyfishMerkleIterator::new(store.clone(), version, start)? {
            let (kh, value) = item?;
            if Some(kh) == after {
                continue;
            }
            let key = db
                .get(&pre_key(&kh))?
                .with_context(|| format!("missing preimage for {}", hex::encode(kh.0)))?;
            // Never serve a preimage that does not hash to its leaf: every
            // client would refuse the chunk and lose its restore.
            ensure!(
                key_hash(&key) == kh,
                "corrupt preimage for {}",
                hex::encode(kh.0)
            );
            out.push((key, value));
            last = Some(kh);
            if out.len() == max {
                break;
            }
        }
        let Some(last) = last else {
            return Ok(None);
        };
        let proof = Sha256Jmt::new(store.as_ref()).get_range_proof(last, version)?;
        Ok(Some((out, proof)))
    })
}

/// Delete every tree row (`jmt:*`), so a failed restore can start over
/// (SN-2 "wipe and restart"). The caller commits the batch, together with
/// the deletion of the flat state keys the restore installed.
pub fn wipe_tree(db: &StateDB) -> Result<WriteBatch> {
    let mut batch = WriteBatch::default();
    for row in db.db.prefix_iterator(b"jmt:") {
        let (key, _) = row?;
        if !key.starts_with(b"jmt:") {
            break;
        }
        batch.delete(&*key);
    }
    Ok(batch)
}

/// True when no `jmt:*` row exists.
fn tree_namespace_empty(db: &StateDB) -> Result<bool> {
    match db.db.prefix_iterator(b"jmt:").next() {
        None => Ok(true),
        Some(Ok((k, _))) => Ok(!k.starts_with(b"jmt:")),
        Some(Err(e)) => Err(e.into()),
    }
}

/// A snapshot restore of `version` against a trusted `expected_root` (SN-2).
pub struct Restore {
    inner: JellyfishMerkleRestore<Sha256>,
    db: Arc<StateDB>,
    version: Version,
    expected: RootHash,
    last: Option<KeyHash>,
    accepted: usize,
    /// `jmt` mutates its restore state before it verifies a chunk and never
    /// rolls back, so after any refused chunk this session is unusable: wipe
    /// (`wipe_tree`) and begin again.
    poisoned: bool,
}

impl Restore {
    /// Refuses a non-empty tree namespace: `jmt` panics restoring over an
    /// older tree (P7).
    pub fn begin(db: Arc<StateDB>, version: Version, expected_root: RootHash) -> Result<Self> {
        ensure!(
            tree_namespace_empty(&db)?,
            "restore needs an empty tree namespace"
        );
        let store = Arc::new(JmtStore::new(db.clone()));
        let inner = no_panic("restore begin", || {
            JellyfishMerkleRestore::new(store, version, expected_root)
        })?;
        Ok(Self {
            inner,
            db,
            version,
            expected: expected_root,
            last: None,
            accepted: 0,
            poisoned: false,
        })
    }

    /// Accept one chunk from an untrusted peer. Every key must be a state key.
    /// Key hashes are computed locally and must strictly increase across
    /// chunks, and `jmt` verifies the range proof against the expected root.
    /// Returns the verified `(key, value)` pairs for the caller to install as
    /// flat keys.
    pub fn add_chunk(
        &mut self,
        entries: Entries,
        proof: SparseMerkleRangeProof<Sha256>,
    ) -> Result<Entries> {
        ensure!(
            !self.poisoned,
            "restore is poisoned by an earlier refused chunk; wipe and begin again"
        );
        let result = self.add_chunk_inner(entries, proof);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn add_chunk_inner(
        &mut self,
        entries: Entries,
        proof: SparseMerkleRangeProof<Sha256>,
    ) -> Result<Entries> {
        ensure!(!entries.is_empty(), "empty chunk");
        let mut chunk = Vec::with_capacity(entries.len());
        let mut last = self.last;
        for (key, value) in &entries {
            ensure!(
                classify(key.as_bytes()) == Some(KeyClass::State),
                "non-state key in snapshot: {key:?}"
            );
            let kh = key_hash(key);
            ensure!(last.is_none_or(|p| kh > p), "snapshot chunk out of order");
            last = Some(kh);
            chunk.push((kh, value.clone()));
        }
        let inner = &mut self.inner;
        no_panic("restore chunk", || inner.add_chunk(chunk, proof))?;
        self.last = last;
        self.accepted += entries.len();
        let mut batch = WriteBatch::default();
        for (key, _) in &entries {
            batch.put(pre_key(&key_hash(key)), key);
        }
        self.db.write_batch(batch)?;
        Ok(entries)
    }

    /// Finish, then require the restored root to equal the expected one.
    /// `jmt`'s own `finish` accepts a partial restore (P6), so this check is
    /// what makes a restore complete.
    ///
    /// Returns the batch that marks the tree complete (`jmt:latest`). The
    /// caller commits it atomically with the bootstrap record (SN-1b). On
    /// any error the tree rows already written must be wiped (`wipe_tree`).
    pub fn finish(self) -> Result<WriteBatch> {
        let Restore {
            inner,
            db,
            version,
            expected,
            accepted,
            poisoned,
            ..
        } = self;
        ensure!(
            !poisoned,
            "restore is poisoned by an earlier refused chunk; wipe and begin again"
        );
        // A consensus state is never empty (genesis seeds it), and finishing
        // with nothing accepted trips an assertion inside `jmt`.
        ensure!(accepted > 0, "no snapshot chunk was accepted");
        no_panic("restore finish", || inner.finish())?;
        let got = no_panic("restore root", || {
            Sha256Jmt::new(&JmtStore::new(db.clone())).get_root_hash_option(version)
        })?;
        ensure!(
            got == Some(expected),
            "restored root {:?} != expected {} (incomplete or forged restore)",
            got.map(|r| hex::encode(r.0)),
            hex::encode(expected.0)
        );
        let mut batch = WriteBatch::default();
        batch.put(LATEST, version.to_string());
        Ok(batch)
    }
}

#[cfg(test)]
mod tests;
