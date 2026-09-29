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
pub use jmt::RootHash;
use jmt::{JellyfishMerkleIterator, KeyHash, OwnedValue, Sha256Jmt, Version};
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
/// Value-stale index (GC-1): `jmt:vstale:{v:020}:{kh}:{prev:020}` says the
/// value row of `kh` at `prev` was superseded at `v`. `jmt`'s own stale index
/// covers nodes only.
const VSTALE: &str = "jmt:vstale:";
/// Deletion index (GC-1): `jmt:vdead:{v:020}:{kh}` says `kh` was deleted at
/// `v`. Once nothing older survives, its deletion row (and, with nothing
/// newer, its preimage) can go too: absence is the default.
const VDEAD: &str = "jmt:vdead:";
/// PF-3 / GC-1: versions below this are pruned and never served.
pub const FLOOR: &str = "jmt:floor";
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

fn vstale_key(since: Version, kh: &KeyHash, prev: Version) -> String {
    format!("{VSTALE}{:020}:{}:{:020}", since, hex::encode(kh.0), prev)
}

/// The version of `kh`'s newest value row at or below `max_version`.
fn latest_value_version(
    db: &StateDB,
    kh: &KeyHash,
    max_version: Version,
) -> Result<Option<Version>> {
    let prefix = val_prefix(kh);
    let start = val_key(kh, max_version);
    let mut it = db
        .db
        .iterator(IteratorMode::From(start.as_bytes(), Direction::Reverse));
    match it.next() {
        Some(Ok((k, _))) if k.starts_with(prefix.as_bytes()) => {
            let version = std::str::from_utf8(&k[prefix.len()..])?.parse::<Version>()?;
            Ok(Some(version))
        }
        Some(Err(e)) => Err(e.into()),
        _ => Ok(None),
    }
}

fn vdead_key(since: Version, kh: &KeyHash) -> String {
    format!("{VDEAD}{:020}:{}", since, hex::encode(kh.0))
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

fn read_node(db: &StateDB, key: &NodeKey) -> Result<Option<Node>> {
    match db.get(&node_key(key)?)? {
        None => Ok(None),
        Some(raw) => Ok(Some(borsh::from_slice(&hex::decode(raw)?)?)),
    }
}

/// Node reads over a borrowed `StateDB`, a transaction view included. A root
/// lookup reads nothing else.
struct RootReader<'a>(&'a StateDB);

impl TreeReader for RootReader<'_> {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        read_node(self.0, key)
    }

    fn get_value_option(&self, _: Version, _: KeyHash) -> Result<Option<OwnedValue>> {
        bail!("a root lookup reads no values")
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        bail!("a root lookup reads no leaves")
    }
}

impl TreeReader for JmtStore {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        read_node(&self.db, key)
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
        // GC-1 value rule: the previous row is superseded at `v`.
        if *v > 0 {
            if let Some(prev) = latest_value_version(db, kh, v - 1)? {
                batch.put(vstale_key(*v, kh, prev), "");
            }
        }
        batch.put(val_key(kh, *v), encode_value(value.as_deref()));
        if value.is_none() {
            batch.put(vdead_key(*v, kh), "");
        }
    }
    let mut old_root_marked = false;
    for stale in &update.stale_node_index_batch {
        if version > 0
            && stale.node_key.version() == version - 1
            && stale.node_key.nibble_path().is_empty()
        {
            old_root_marked = true;
        }
        batch.put(stale_key(stale.stale_since_version, &stale.node_key)?, "");
    }
    // GC-1: an empty block carries the root forward as a new node at this
    // version, but `jmt` does not mark the previous root stale
    // (`tree_cache.rs:316-323`). Mark it, or it would never be pruned.
    if version > 0 && !old_root_marked {
        if let Some(new_root) = update
            .node_batch
            .nodes()
            .keys()
            .find(|nk| nk.version() == version && nk.nibble_path().is_empty())
        {
            // The same key at version - 1: borsh is the version (u64 LE)
            // followed by the empty path.
            let mut bytes = borsh::to_vec(new_root)?;
            bytes[..8].copy_from_slice(&(version - 1).to_le_bytes());
            let old_root: NodeKey = borsh::from_slice(&bytes)?;
            if db.get(&node_key(&old_root)?)?.is_some() {
                batch.put(stale_key(version, &old_root)?, "");
            }
        }
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

/// A tree with no nodes. Version 0 of an empty tree reads nothing from its
/// store, so its root needs no database.
struct EmptyTree;

impl TreeReader for EmptyTree {
    fn get_node_option(&self, _: &NodeKey) -> Result<Option<Node>> {
        Ok(None)
    }
    fn get_value_option(&self, _: Version, _: KeyHash) -> Result<Option<OwnedValue>> {
        Ok(None)
    }
    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        Ok(None)
    }
}

/// TA-1 / FX-7: the root of version 0 over the genesis state, computed in
/// memory from that state alone. The genesis identity binds this root. The
/// tree on disk, which may later be pruned or restored, is never consulted
/// for it.
pub fn genesis_root(state: &BTreeMap<String, Vec<u8>>) -> Result<RootHash> {
    let mut set = Vec::with_capacity(state.len());
    for (key, value) in state {
        ensure!(
            classify(key.as_bytes()) == Some(KeyClass::State),
            "not a state key: {key:?}"
        );
        set.push((key_hash(key), Some(value.clone())));
    }
    no_panic("genesis_root", || {
        Ok(Sha256Jmt::new(&EmptyTree).put_value_set(set, 0)?.0)
    })
}

/// Version 0 of an EMPTY tree from every consensus-state key in the flat
/// store, i.e. the genesis state. It must run before block 1 executes: its
/// scan reads whatever is staged, so running it later would fold block 1's
/// writes into genesis.
pub fn seed_genesis(db: &Arc<StateDB>) -> Result<Applied> {
    let mut changes = Vec::new();
    for row in db.db.iterator(IteratorMode::Start) {
        let (key, value) = row?;
        if classify(&key) == Some(KeyClass::State) {
            changes.push((String::from_utf8(key.to_vec())?, Some(value.to_vec())));
        }
    }
    apply(db, 0, changes)
}

/// RC-1: at boot, after genesis, the tree's latest version, the executed
/// height and the stored chain height must agree, and no snapshot restore may
/// be half done.
/// The block transaction writes all three together, so a mismatch means the
/// database is not something this node produced; it must refuse to start,
/// never guess.
pub fn boot_check(db: &Arc<StateDB>) -> Result<()> {
    ensure!(
        db.get(storage::RESTORE_MARKER)?.is_none(),
        "a snapshot restore is incomplete; wipe the tree and restore again"
    );
    let executed: Version = db
        .get("sys:last_executed_height")?
        .map(|s| s.parse::<Version>())
        .transpose()
        .context("malformed sys:last_executed_height")?
        .unwrap_or(0);
    // S3: genesis commits version 0, and this runs after genesis, so a
    // database with no tree predates S3 or lost its tree.
    match (executed, latest_version(db)?) {
        (_, None) => bail!("no state tree: genesis did not commit version 0"),
        (height, Some(version)) if version == height => {}
        (height, Some(version)) => {
            bail!("state tree is at version {version} but the executed height is {height}")
        }
    }
    match db
        .get("latest_height")?
        .map(|s| s.parse::<Version>())
        .transpose()
        .context("malformed latest_height")?
    {
        Some(latest) => ensure!(
            latest == executed,
            "latest_height {latest} != executed height {executed}"
        ),
        None => ensure!(
            executed == 0,
            "the executed height is {executed} but latest_height is missing"
        ),
    }
    // The next block reads the latest root. A missing root node would only
    // surface then, inside the block transaction.
    if let Some(version) = latest_version(db)? {
        root(db, version)
            .with_context(|| format!("the root node of tree version {version} is missing"))?;
    }
    Ok(())
}

/// The retention floor: versions below it may be pruned and are not served.
pub fn floor(db: &StateDB) -> Result<Version> {
    Ok(db
        .get(FLOOR)?
        .map(|s| s.parse::<Version>())
        .transpose()
        .context("malformed jmt:floor")?
        .unwrap_or(0))
}

/// What one `prune` call removed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PruneStats {
    pub nodes: usize,
    pub values: usize,
    /// True when rows at or below the floor remain (the call hit its limit).
    pub more: bool,
}

/// GC-1: prune the tree below `target_floor`, at most `max_rows` rows per
/// call. Node-local and root-neutral (GC-2): only `jmt:*` rows go.
///
/// - The floor is raised first, in its own write, so a version about to lose
///   rows is refused (PF-3) before any row goes. A crash mid-prune leaves
///   nothing servable half-deleted.
/// - Tree nodes go through `jmt`'s stale index: a node stale since `s` is
///   needed only by versions below `s`.
/// - Values follow the value rule: a row superseded at `v` is needed only by
///   versions below `v`, so each key keeps its newest row at or below the
///   floor plus every newer one.
/// - A pinned version (SN-4) keeps every node and value row it needs.
pub fn prune(
    db: &Arc<StateDB>,
    target_floor: Version,
    pinned: &std::collections::BTreeSet<Version>,
    max_rows: usize,
) -> Result<PruneStats> {
    let latest = latest_version(db)?.context("no state tree")?;
    let target = target_floor.min(latest);
    let current = floor(db)?;
    if target > current {
        db.put(FLOOR, &target.to_string())?;
    }
    let floor = target.max(current);
    // A row live over [created, superseded) is kept if a pin falls in it.
    let pinned_in = |from: Version, until: Version| pinned.range(from..until).next().is_some();
    let mut stats = PruneStats::default();
    let mut batch = WriteBatch::default();
    let mut rows = 0usize;
    for row in db.db.prefix_iterator(STALE.as_bytes()) {
        let (k, _) = row?;
        if !k.starts_with(STALE.as_bytes()) {
            break;
        }
        let rest = std::str::from_utf8(&k[STALE.len()..])?;
        let (since, node_hex) = rest.split_once(':').context("malformed stale row")?;
        let since: Version = since.parse()?;
        if since > floor {
            break;
        }
        if rows >= max_rows {
            stats.more = true;
            break;
        }
        let nk: NodeKey = borsh::from_slice(&hex::decode(node_hex)?)?;
        if pinned_in(nk.version(), since) {
            continue;
        }
        batch.delete(node_key(&nk)?);
        batch.delete(&k);
        stats.nodes += 1;
        rows += 1;
    }
    for row in db.db.prefix_iterator(VSTALE.as_bytes()) {
        let (k, _) = row?;
        if !k.starts_with(VSTALE.as_bytes()) {
            break;
        }
        let rest = std::str::from_utf8(&k[VSTALE.len()..])?;
        let mut parts = rest.splitn(3, ':');
        let since: Version = parts.next().context("malformed vstale row")?.parse()?;
        if since > floor {
            break;
        }
        if rows >= max_rows {
            stats.more = true;
            break;
        }
        let kh = KeyHash(
            hex::decode(parts.next().context("malformed vstale row")?)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("malformed vstale key hash"))?,
        );
        let prev: Version = parts.next().context("malformed vstale row")?.parse()?;
        if pinned_in(prev, since) {
            continue;
        }
        batch.delete(val_key(&kh, prev));
        batch.delete(&k);
        stats.values += 1;
        rows += 1;
    }
    if !batch.is_empty() {
        db.write_batch(batch)?;
    }
    // Deleted keys: once no older row survives (a pin may still hold one),
    // the deletion row goes, and with nothing newer, the preimage too. The
    // checks and the deletes are one transaction, which holds the writer gate
    // block execution takes: a key re-created in between cannot lose its
    // preimage to a check that no longer holds.
    let budget = max_rows.saturating_sub(rows);
    let dead = db
        .transaction(|view| {
            prune_deleted(&view, floor, budget)
                .map_err(|e| storage::StorageError::DatabaseOperation(e.to_string()))
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    stats.values += dead.values;
    stats.more |= dead.more;
    Ok(stats)
}

#[cfg(test)]
thread_local! {
    /// Tests only: runs in `prune_deleted` after its checks, before its writes.
    pub(crate) static BEFORE_DEAD_WRITE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// The deletion pass of `prune`, over a transaction view.
fn prune_deleted(view: &StateDB, floor: Version, budget: usize) -> Result<PruneStats> {
    let mut stats = PruneStats::default();
    let mut batch = WriteBatch::default();
    for row in view.db.prefix_iterator(VDEAD.as_bytes()) {
        let (k, _) = row?;
        if !k.starts_with(VDEAD.as_bytes()) {
            break;
        }
        let rest = std::str::from_utf8(&k[VDEAD.len()..])?;
        let (since, kh_hex) = rest.split_once(':').context("malformed vdead row")?;
        let since: Version = since.parse()?;
        if since > floor {
            break;
        }
        if stats.values >= budget {
            stats.more = true;
            break;
        }
        let kh = KeyHash(
            hex::decode(kh_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("malformed vdead key hash"))?,
        );
        if since > 0 && latest_value_version(view, &kh, since - 1)?.is_some() {
            continue;
        }
        batch.delete(val_key(&kh, since));
        batch.delete(&k);
        if latest_value_version(view, &kh, Version::MAX)? == Some(since) {
            batch.delete(pre_key(&kh));
        }
        stats.values += 1;
    }
    #[cfg(test)]
    if let Some(hook) = BEFORE_DEAD_WRITE.with(|h| h.borrow_mut().take()) {
        hook();
    }
    if !batch.is_empty() {
        view.write_batch(batch)?;
    }
    Ok(stats)
}

/// SN-4: the pinned versions for a tip. They are epoch boundaries (multiples
/// of `epoch_interval`), spaced about a quarter of the retention window
/// apart, and kept for two windows. That is a handful of versions, not every
/// boundary. Pure arithmetic, so a joiner and every server agree on it
/// without reading any rows.
pub fn pin_schedule(
    tip: Version,
    keep: Version,
    epoch_interval: Version,
) -> std::collections::BTreeSet<Version> {
    let interval = epoch_interval.max(1);
    let spacing = interval * (keep / 4 / interval).max(1);
    let from = tip.saturating_sub(keep.saturating_mul(2));
    let first = from.div_ceil(spacing) * spacing;
    (first..=tip)
        .step_by(spacing as usize)
        .filter(|v| *v > 0)
        .collect()
}

/// The epoch interval genesis pinned (FX-6); pins are its multiples. Boot
/// refuses a database without the pin, so a running node never sees the
/// default.
pub fn epoch_interval(db: &StateDB) -> Version {
    db.get("sys:config:epoch_block_interval")
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<Version>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(20)
}

/// SN-4: whether this node may serve `version` to a restoring peer: every
/// version from the floor to the latest, plus the pins of the current
/// window. `keep` is this node's retention window; `None` is an archive
/// node, which never prunes. Pruning keeps exactly this set.
pub fn servable(db: &StateDB, version: Version, keep: Option<Version>) -> Result<bool> {
    let Some(latest) = latest_version(db)? else {
        return Ok(false);
    };
    if version > latest {
        return Ok(false);
    }
    if version >= floor(db)? {
        return Ok(true);
    }
    Ok(keep.is_some_and(|keep| pin_schedule(latest, keep, epoch_interval(db)).contains(&version)))
}

/// RC-2: at boot, the flat consensus-state keys and the tree's leaves at the
/// latest version must agree exactly. Returns every divergent key (empty:
/// consistent). It detects an out-of-band edit of a flat state key and a
/// stale value row, but not a self-consistent foreign database (RC-3).
/// Cost: O(|S|), since it walks the tree's leaves and the state templates,
/// never the whole database.
pub fn audit_flat_vs_tree(db: &Arc<StateDB>) -> Result<Vec<String>> {
    let Some(version) = latest_version(db)? else {
        return Ok(Vec::new());
    };
    let mut divergent = Vec::new();
    // 1. Every leaf equals its flat key.
    let mut in_tree = std::collections::BTreeSet::new();
    no_panic("audit", || {
        let store = Arc::new(JmtStore::new(db.clone()));
        for item in JellyfishMerkleIterator::new(store, version, KeyHash([0u8; 32]))? {
            let (kh, value) = item?;
            match db.get(&pre_key(&kh))? {
                None => divergent.push(format!("leaf {} has no preimage", hex::encode(kh.0))),
                Some(key) => {
                    if db.db.get(&key)?.as_deref() != Some(value.as_slice()) {
                        divergent.push(key.clone());
                    }
                    in_tree.insert(key);
                }
            }
        }
        Ok(())
    })?;
    // 2. Every flat state key is a leaf.
    let mut flat_keys: Vec<Vec<u8>> = storage::class::STATE_EXACT
        .iter()
        .filter_map(|key| {
            db.db
                .get(key)
                .ok()
                .flatten()
                .map(|_| key.as_bytes().to_vec())
        })
        .collect();
    for prefix in storage::class::STATE_PREFIXES {
        for row in db.db.prefix_iterator(prefix.as_bytes()) {
            let (k, _) = row?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            flat_keys.push(k.to_vec());
        }
    }
    for key in flat_keys {
        if classify(&key) != Some(KeyClass::State) {
            continue;
        }
        let key = String::from_utf8(key)?;
        if !in_tree.contains(&key) {
            divergent.push(key);
        }
    }
    Ok(divergent)
}

/// RC-3: the tree root at `version` must equal the network's
/// `qc.state_root` for it. This catches a self-consistent but foreign
/// database (a restored backup, a copied datadir) that RC-2 cannot see.
pub fn audit_root_against_qc(db: &StateDB, version: Version, qc_state_root: &str) -> Result<()> {
    let root = hex::encode(root(db, version)?.0);
    ensure!(
        root.eq_ignore_ascii_case(qc_state_root),
        "tree root {root} at version {version} is not the network's {qc_state_root}"
    );
    Ok(())
}

/// The root at `version`. Takes any `StateDB`, so a transaction view can
/// check a root inside the write that depends on it.
pub fn root(db: &StateDB, version: Version) -> Result<RootHash> {
    no_panic("root", || {
        Sha256Jmt::new(&RootReader(db)).get_root_hash(version)
    })
}

/// The value of `key` at `version`, read through the tree: `None` when the
/// key is absent there.
pub fn value_at(db: &Arc<StateDB>, key: &str, version: Version) -> Result<Option<OwnedValue>> {
    no_panic("value", || {
        Sha256Jmt::new(&JmtStore::new(db.clone())).get(key_hash(key), version)
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

/// G3 PF-1: value and proof for `key` at `version`, in the wire format that
/// clients verify with `state_proof::verify` (and its JS mirror). The proof
/// is checked by that independent verifier against the tree's own root
/// before it leaves the node, so a divergence between `jmt` and the client
/// algorithm fails here, not at the client.
pub fn wire_proof(
    db: &Arc<StateDB>,
    key: &str,
    version: Version,
) -> Result<(Option<OwnedValue>, state_proof::WireProof)> {
    let (value, proof) = prove(db, key, version)?;
    let wire = to_wire(&proof)?;
    let root = root(db, version)?;
    state_proof::verify(&root.0, key, value.as_deref(), &wire)
        .map_err(|e| anyhow::anyhow!("wire proof fails the client check: {e}"))?;
    Ok((value, wire))
}

/// `jmt` keeps the proof's siblings private; its borsh encoding is public and
/// fixed: `leaf: Option<(key_hash, value_hash)>`, then a `u32` little-endian
/// count of siblings, each tagged `0` null, `1` internal `(left, right)` or
/// `2` leaf `(key_hash, value_hash)`. Each sibling becomes its hash.
fn to_wire(proof: &SparseMerkleProof<Sha256>) -> Result<state_proof::WireProof> {
    let bytes = borsh::to_vec(proof)?;
    let mut rest = bytes.as_slice();
    let mut take = |n: usize| -> Result<&[u8]> {
        ensure!(rest.len() >= n, "truncated proof encoding");
        let (head, tail) = rest.split_at(n);
        rest = tail;
        Ok(head)
    };
    let hash32 = |b: &[u8]| -> [u8; 32] { b.try_into().expect("32 bytes") };
    let leaf = match take(1)?[0] {
        0 => None,
        1 => Some(state_proof::WireLeaf {
            key_hash: hex::encode(take(32)?),
            value_hash: hex::encode(take(32)?),
        }),
        tag => bail!("unknown leaf tag {tag}"),
    };
    let count = u32::from_le_bytes(take(4)?.try_into().expect("4 bytes")) as usize;
    ensure!(count <= state_proof::MAX_SIBLINGS, "{count} siblings");
    let mut siblings = Vec::with_capacity(count);
    for _ in 0..count {
        let hash = match take(1)?[0] {
            0 => state_proof::PLACEHOLDER,
            1 => {
                let left = hash32(take(32)?);
                state_proof::internal_hash(&left, &hash32(take(32)?))
            }
            2 => {
                let key = hash32(take(32)?);
                state_proof::leaf_hash(&key, &hash32(take(32)?))
            }
            tag => bail!("unknown sibling tag {tag}"),
        };
        siblings.push(hex::encode(hash));
    }
    ensure!(rest.is_empty(), "trailing proof bytes");
    Ok(state_proof::WireProof { leaf, siblings })
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
    let mut out = Vec::new();
    let proof = chunk_with(db, version, after, max, |key, value| {
        out.push((key, value));
        true
    })?;
    Ok(proof.map(|proof| (out, proof)))
}

/// Walk up to `max` leaves after `after`, in order, handing each to `take`,
/// which keeps it (true) or ends the chunk before it (false). So a server can
/// stop at a byte budget, having read at most one leaf past it, and need not
/// hold values it only measures. Returns the range proof up to the last leaf
/// taken; `Ok(None)` when none was: the stream is complete, or `take` refused
/// the first leaf (its caller knows which).
pub fn chunk_with(
    db: &Arc<StateDB>,
    version: Version,
    after: Option<KeyHash>,
    max: usize,
    mut take: impl FnMut(String, Vec<u8>) -> bool,
) -> Result<Option<SparseMerkleRangeProof<Sha256>>> {
    ensure!(
        (1..=MAX_CHUNK).contains(&max),
        "chunk size must be 1..={MAX_CHUNK}"
    );
    no_panic("chunk", || {
        let store = Arc::new(JmtStore::new(db.clone()));
        let start = after.unwrap_or(KeyHash([0u8; 32]));
        let mut taken = 0;
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
            if !take(key, value) {
                break;
            }
            taken += 1;
            last = Some(kh);
            if taken == max {
                break;
            }
        }
        let Some(last) = last else {
            return Ok(None);
        };
        Ok(Some(
            Sha256Jmt::new(store.as_ref()).get_range_proof(last, version)?,
        ))
    })
}

/// Largest wire range proof: a count, then at most 256 tagged siblings of
/// up to 64 bytes each.
pub const MAX_RANGE_PROOF_BYTES: usize = 4 + 256 * 65;

/// `chunk` for the wire: the range proof borsh-encoded, so peers never
/// handle `jmt` types. `after` is the key hash the previous chunk ended on.
pub fn wire_chunk(
    db: &Arc<StateDB>,
    version: Version,
    after: Option<[u8; 32]>,
    max: usize,
) -> Result<Option<(Entries, Vec<u8>)>> {
    match chunk(db, version, after.map(KeyHash), max)? {
        None => Ok(None),
        Some((entries, proof)) => Ok(Some((entries, borsh::to_vec(&proof)?))),
    }
}

/// `chunk_with` for the wire: the proof borsh-encoded.
pub fn wire_chunk_with(
    db: &Arc<StateDB>,
    version: Version,
    after: Option<[u8; 32]>,
    max: usize,
    take: impl FnMut(String, Vec<u8>) -> bool,
) -> Result<Option<Vec<u8>>> {
    match chunk_with(db, version, after.map(KeyHash), max, take)? {
        None => Ok(None),
        Some(proof) => Ok(Some(borsh::to_vec(&proof)?)),
    }
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

    /// The key hash of the last accepted leaf, where the next chunk starts.
    pub fn cursor(&self) -> Option<[u8; 32]> {
        self.last.map(|k| k.0)
    }

    /// `add_chunk` with the proof in its wire encoding (`wire_chunk`). A
    /// proof that does not decode is a refused chunk like any other.
    pub fn add_wire_chunk(&mut self, entries: Entries, proof: &[u8]) -> Result<Entries> {
        let decoded = if proof.len() > MAX_RANGE_PROOF_BYTES {
            Err(anyhow::anyhow!("a range proof of {} bytes", proof.len()))
        } else {
            borsh::from_slice::<SparseMerkleRangeProof<Sha256>>(proof)
                .map_err(|e| anyhow::anyhow!("malformed range proof: {e}"))
        };
        match decoded {
            Ok(proof) => self.add_chunk(entries, proof),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
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
