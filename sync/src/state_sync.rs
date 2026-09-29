//! G3 S6: restore a node's consensus state from untrusted peers at a
//! checkpoint the operator trusts (SN-1, SN-2, SN-1b).
//!
//! Trust. Until the transition log (TA, S5) exists, the anchor is a
//! weak-subjectivity checkpoint `(height, block hash, state root)` that the
//! operator pins (TA-0, TA-4), next to the network's genesis identity
//! (`AINCORE_EXPECTED_GENESIS_HASH`). Every chunk is proven against the
//! checkpoint root, and nothing a peer sends is written unproven. The block
//! and quorum certificate at the checkpoint also come from peers, as a pair
//! that must match it. The QC is then verified under the committee the
//! restored state records for its epoch. That is a consistency check, not
//! trust: the committee comes from the same state the checkpoint pins.

use crate::ChainSync;
use blockchain::Block;
use consensus::qc::QuorumCertificate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use storage::class::{classify, KeyClass};
use storage::rocksdb::{Direction, IteratorMode, WriteBatch};
use storage::{StateDB, RESTORE_MARKER};

pub const ANCHOR_REQ: &str = "STATE_ANCHOR_REQ:";
pub const ANCHOR_RESP: &str = "STATE_ANCHOR_RESP:";
pub const CHUNK_REQ: &str = "STATE_CHUNK_REQ:";
pub const CHUNK_RESP: &str = "STATE_CHUNK_RESP:";
pub const VALUE_REQ: &str = "STATE_VALUE_REQ:";
pub const VALUE_RESP: &str = "STATE_VALUE_RESP:";

/// The most leaves a server sends in one chunk.
pub const MAX_CHUNK_ENTRIES: usize = 2_000;
/// Encoded chunk budget, well under the transport's 10 MiB frame.
const MAX_CHUNK_BYTES: usize = 6 * 1024 * 1024;
/// A value longer than this travels in parts (`STATE_VALUE_REQ`), so no
/// single leaf can make a chunk unservable.
pub const INLINE_VALUE_BYTES: usize = 256 * 1024;
/// The bytes of one value part (twice that as hex, under the frame).
pub const VALUE_PART_BYTES: usize = 2 * 1024 * 1024;
/// The largest leaf a client accepts, and the most bytes one chunk may
/// assemble to: what a hostile peer can make a restoring node allocate.
pub const MAX_LEAF_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CHUNK_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
/// Snapshot serving: concurrent requests, and leaves (or value parts) per
/// second. Apart from vertex serving's budget.
pub const STATE_SERVE_IN_FLIGHT: usize = 2;
pub const STATE_SERVE_LEAVES_PER_SEC: f64 = 4_000.0;
/// Rows deleted per batch while clearing a datadir.
const CLEAR_BATCH: usize = 10_000;
/// Where a restored node records the checkpoint it restored (N).
pub const RESTORED_CHECKPOINT: &str = "sys:restored_checkpoint";

/// Genesis state keys no transaction changes. The restored state must hold
/// this node's own genesis values for them. With the genesis identity pinned
/// by the operator, that ties the checkpoint to the network's genesis.
pub const GENESIS_FIXED: [&str; 3] = [
    "sys:chain_id",
    "genesis:validator_set:v1",
    "sys:config:epoch_block_interval",
];

/// A weak-subjectivity checkpoint (TA-0): the trust anchor of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

impl std::str::FromStr for Checkpoint {
    type Err = String;

    /// `{height}:{block hash}:{state root}`, each hash 64 hex characters.
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.trim().split(':').collect();
        let [height, block_hash, state_root] = parts.as_slice() else {
            return Err("a checkpoint is height:block_hash:state_root".into());
        };
        let height: u64 = height
            .parse()
            .map_err(|_| format!("checkpoint height {height:?} is not a number"))?;
        if height == 0 {
            return Err("a checkpoint at genesis: sync from genesis instead".into());
        }
        for (what, hash) in [("block hash", block_hash), ("state root", state_root)] {
            if hex32(hash).is_none() {
                return Err(format!("checkpoint {what} is not 64 hex characters"));
            }
        }
        Ok(Self {
            height,
            block_hash: block_hash.to_ascii_lowercase(),
            state_root: state_root.to_ascii_lowercase(),
        })
    }
}

impl std::fmt::Display for Checkpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.height, self.block_hash, self.state_root)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRequest {
    pub height: u64,
}

/// The block and QC a server holds at the requested height. Unverified.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnchorResponse {
    pub block: Option<Block>,
    pub quorum_certificate: Option<QuorumCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub version: u64,
    /// Hex key hash of the last leaf already received; none for the first.
    pub after: Option<String>,
    pub max: usize,
}

/// One leaf of a chunk.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireEntry {
    pub key: String,
    /// Hex of the whole value, or empty when it travels in parts.
    pub value: String,
    /// The value's length in bytes.
    pub len: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChunkResponse {
    /// Leaves in key-hash order, after the cursor.
    pub entries: Vec<WireEntry>,
    /// Hex of the borsh range proof up to the last entry.
    pub proof: String,
    /// No leaf follows the cursor.
    pub done: bool,
    /// Why nothing was served. Never trusted; the client asks elsewhere.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueRequest {
    pub version: u64,
    pub key: String,
    pub offset: u64,
}

/// Up to `VALUE_PART_BYTES` of a value, from `offset`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueResponse {
    /// Hex of the part.
    pub data: String,
    /// The whole value's length.
    pub len: u64,
    pub error: Option<String>,
}

/// Run `f`, which reads RocksDB synchronously, without holding a tokio worker
/// that consensus tasks wait on: on a multi-thread runtime the worker first
/// hands its other tasks off.
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

impl ChainSync {
    /// Serve the block and QC at a height, straight from storage.
    pub fn handle_state_anchor(&self, req: AnchorRequest) -> AnchorResponse {
        let read = |key: String| self.storage.get(&key).ok().flatten();
        AnchorResponse {
            block: read(format!("block_{}", req.height))
                .and_then(|json| serde_json::from_str(&json).ok()),
            quorum_certificate: read(format!("consensus:qc:{}", req.height))
                .and_then(|json| serde_json::from_str(&json).ok()),
        }
    }

    /// Judged under the retention this node prunes with, so it serves
    /// exactly what its pruning keeps.
    fn state_servable(&self, version: u64) -> Result<(), &'static str> {
        let keep = self.retention.map(|(keep, _)| keep);
        match state_commit::servable(&self.storage, version, keep) {
            Ok(true) => Ok(()),
            Ok(false) => Err("version not retained"),
            Err(_) => Err("state tree unreadable"),
        }
    }

    /// Serve one restore chunk (SN-2) of a version this node retains
    /// (`state_commit::servable`). Bounded apart from vertex serving: a slot of
    /// `STATE_SERVE_IN_FLIGHT`, leaves from a `STATE_SERVE_LEAVES_PER_SEC`
    /// bucket, `MAX_CHUNK_BYTES` per answer, and the reads off the shared
    /// tokio workers.
    pub fn handle_state_chunk(&self, req: ChunkRequest) -> ChunkResponse {
        let refuse = |why: &str| ChunkResponse {
            error: Some(why.to_string()),
            ..Default::default()
        };
        let Some(_slot) = self.state_budget.try_enter() else {
            return refuse("busy");
        };
        let after = match req.after.as_deref() {
            None => None,
            Some(hex) => match hex32(hex) {
                Some(hash) => Some(hash),
                None => return refuse("malformed cursor"),
            },
        };
        // A few point reads: before any leaves are charged.
        if let Err(why) = self.state_servable(req.version) {
            return refuse(why);
        }
        let granted = self
            .state_budget
            .take_lookups(req.max.clamp(1, MAX_CHUNK_ENTRIES));
        if granted == 0 {
            return refuse("busy");
        }
        blocking(|| {
            let mut max = granted;
            loop {
                let (entries, proof) =
                    match state_commit::wire_chunk(&self.storage, req.version, after, max) {
                        Ok(None) => {
                            return ChunkResponse {
                                done: true,
                                ..Default::default()
                            }
                        }
                        Ok(Some(chunk)) => chunk,
                        Err(_) => return refuse("version not whole here"),
                    };
                let entries: Vec<WireEntry> = entries
                    .into_iter()
                    .map(|(key, value)| WireEntry {
                        len: value.len() as u64,
                        value: if value.len() > INLINE_VALUE_BYTES {
                            String::new()
                        } else {
                            hex::encode(&value)
                        },
                        key,
                    })
                    .collect();
                let size: usize = entries
                    .iter()
                    .map(|e| e.key.len() + e.value.len() + 32)
                    .sum();
                if size + 2 * proof.len() <= MAX_CHUNK_BYTES {
                    return ChunkResponse {
                        entries,
                        proof: hex::encode(proof),
                        done: false,
                        error: None,
                    };
                }
                if max == 1 {
                    return refuse("one leaf exceeds the chunk budget");
                }
                max /= 2;
            }
        })
    }

    /// Serve up to `VALUE_PART_BYTES` of one leaf's value, for a value too
    /// large to travel inline. Bounded like chunks; the last value read is
    /// cached, so the parts of one value cost one read.
    pub fn handle_state_value(&self, req: ValueRequest) -> ValueResponse {
        let refuse = |why: &str| ValueResponse {
            error: Some(why.to_string()),
            ..Default::default()
        };
        let Some(_slot) = self.state_budget.try_enter() else {
            return refuse("busy");
        };
        if let Err(why) = self.state_servable(req.version) {
            return refuse(why);
        }
        if self.state_budget.take_lookups(1) == 0 {
            return refuse("busy");
        }
        blocking(|| {
            let cached = {
                let cache = self
                    .state_value_cache
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                cache
                    .as_ref()
                    .filter(|(v, k, _)| *v == req.version && *k == req.key)
                    .map(|(_, _, value)| Arc::clone(value))
            };
            let value = match cached {
                Some(value) => value,
                None => match state_commit::value_at(&self.storage, &req.key, req.version) {
                    Ok(Some(value)) => {
                        let value = Arc::new(value);
                        *self
                            .state_value_cache
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()) =
                            Some((req.version, req.key.clone(), Arc::clone(&value)));
                        value
                    }
                    Ok(None) => return refuse("no such leaf"),
                    Err(_) => return refuse("version not whole here"),
                },
            };
            let len = value.len() as u64;
            if req.offset >= len {
                return refuse("offset past the value");
            }
            let start = req.offset as usize;
            let end = value.len().min(start + VALUE_PART_BYTES);
            ValueResponse {
                data: hex::encode(&value[start..end]),
                len,
                error: None,
            }
        })
    }
}

/// How hard a restore tries before it gives up.
#[derive(Debug, Clone)]
pub struct Patience {
    /// Unanswered requests in a row, across all peers, before giving up.
    pub max_failures: usize,
    /// The wait after an unanswered request, doubling each round of the
    /// peers up to `backoff_max`.
    pub backoff_start: Duration,
    pub backoff_max: Duration,
}

impl Default for Patience {
    fn default() -> Self {
        Self {
            max_failures: 60,
            backoff_start: Duration::from_millis(50),
            backoff_max: Duration::from_secs(5),
        }
    }
}

impl Patience {
    fn backoff(&self, failures: usize, live_peers: usize) -> Duration {
        let rounds = (failures / live_peers.max(1)).min(16) as u32;
        self.backoff_start
            .saturating_mul(1u32 << rounds)
            .min(self.backoff_max)
    }
}

/// What the joining node brings from its own configuration.
pub struct RestorePlan<'a> {
    pub checkpoint: &'a Checkpoint,
    /// Every row this node's own genesis writes, built in memory from its
    /// genesis.json (TA-1). The restored state must agree on the
    /// `GENESIS_FIXED` keys, and the rows outside the state are written with
    /// the bootstrap record.
    pub genesis: &'a BTreeMap<String, String>,
    /// This node's genesis identity, from the same build.
    pub genesis_identity: &'a str,
    /// Replace the chain this datadir already holds (a node offline past
    /// block retention, SN-4). Without it a restore only runs on a fresh
    /// datadir, or one an interrupted restore left marked.
    pub replace_existing: bool,
    /// This node's own address. A restore refuses a chain where it is a
    /// validator (SN-6).
    pub local_signer: Option<&'a str>,
    pub patience: Patience,
}

/// A finished restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    pub height: u64,
    pub leaves: usize,
    pub restarts: usize,
}

/// Rows a restore removes before it starts. Consensus state and the tree go
/// (SN-2 step 2: a stale flat key would fork the node at `h + 1`), and so
/// does the chain data and consensus view of the old chain. The signing
/// guards and the proposal round stay (SN-6), and so do node-local rows and
/// the transition log.
fn cleared_by_restore(key: &[u8]) -> bool {
    match classify(key) {
        Some(KeyClass::State | KeyClass::Chain | KeyClass::Tree | KeyClass::Dead) => true,
        Some(KeyClass::Local) => {
            !(key.starts_with(b"consensus:qc_signing:")
                || key.starts_with(b"consensus:vattest:")
                || key == b"latest_proposed_round")
        }
        _ => false,
    }
}

fn clear(storage: &Arc<StateDB>) -> Result<(), String> {
    let mut from: Vec<u8> = Vec::new();
    loop {
        let mut doomed = Vec::new();
        let mut finished = true;
        for row in storage
            .db
            .iterator(IteratorMode::From(&from, Direction::Forward))
        {
            let (key, _) = row.map_err(|e| e.to_string())?;
            if key.as_ref() == RESTORE_MARKER.as_bytes() || !cleared_by_restore(&key) {
                continue;
            }
            doomed.push(key.to_vec());
            if doomed.len() == CLEAR_BATCH {
                from = key.to_vec();
                from.push(0);
                finished = false;
                break;
            }
        }
        if !doomed.is_empty() {
            storage
                .restore_transaction(|view| {
                    let mut batch = WriteBatch::default();
                    for key in &doomed {
                        batch.delete(key);
                    }
                    view.write_batch(batch)
                })
                .map_err(|e| e.to_string())?;
        }
        if finished {
            return Ok(());
        }
    }
}

/// The block and QC match the checkpoint, and each other, and the block is
/// internally whole. The QC's signature is checked after the restore.
fn check_anchor(cp: &Checkpoint, block: &Block, qc: &QuorumCertificate) -> Result<(), String> {
    let h = &block.header;
    if h.height != cp.height
        || !h.hash.eq_ignore_ascii_case(&cp.block_hash)
        || !h.state_root.eq_ignore_ascii_case(&cp.state_root)
    {
        return Err("the block is not the checkpoint's".into());
    }
    if blockchain::calculate_header_hash(h) != h.hash
        || blockchain::calculate_tx_hash(&block.transactions) != h.tx_hash
        || blockchain::calculate_vertices_root(&block.committed_vertices) != h.vertices_root
        || blockchain::calculate_evidence_root(&block.slash_evidence) != h.evidence_root
    {
        return Err("the block's header does not commit to its body".into());
    }
    if qc.block_height != h.height
        || qc.block_hash != h.hash
        || qc.state_root != h.state_root
        || qc.receipts_root != h.receipts_root
        || qc.anchor_round != h.round
        || qc.anchor_hash != block.anchor_hash
    {
        return Err("the QC is not for the checkpoint's block".into());
    }
    Ok(())
}

/// Every (block, QC) pair the peers hold for the checkpoint. A pair stays
/// together: the block stored is the one whose own QC verifies.
async fn fetch_anchor<F, Fut>(
    cp: &Checkpoint,
    peers: usize,
    ask: &mut F,
) -> Result<Vec<(Block, QuorumCertificate)>, String>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let request =
        serde_json::to_string(&AnchorRequest { height: cp.height }).map_err(|e| e.to_string())?;
    let mut pairs: Vec<(Block, QuorumCertificate)> = Vec::new();
    for peer in 0..peers {
        let Ok(reply) = ask(peer, format!("{ANCHOR_REQ}{request}")).await else {
            continue;
        };
        let Some(anchor) = reply
            .strip_prefix(ANCHOR_RESP)
            .and_then(|json| serde_json::from_str::<AnchorResponse>(json).ok())
        else {
            continue;
        };
        let (Some(block), Some(qc)) = (anchor.block, anchor.quorum_certificate) else {
            continue;
        };
        if let Err(e) = check_anchor(cp, &block, &qc) {
            eprintln!("⚠️ [STATE_SYNC] peer {peer}: {e}");
            continue;
        }
        if !pairs.iter().any(|(_, known)| *known == qc) {
            pairs.push((block, qc));
        }
    }
    if pairs.is_empty() {
        return Err(format!(
            "no peer holds block {} and its QC as the checkpoint names them",
            cp.height
        ));
    }
    Ok(pairs)
}

fn short(value: &str) -> &str {
    value.get(..48).unwrap_or(value)
}

/// The restored state is of this node's genesis (`GENESIS_FIXED`). Returns
/// the chain id.
fn check_genesis(storage: &StateDB, plan: &RestorePlan<'_>) -> Result<String, String> {
    for key in GENESIS_FIXED {
        let local = plan
            .genesis
            .get(key)
            .ok_or_else(|| format!("this node's genesis has no {key}"))?;
        let restored = storage
            .get(key)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        if &restored != local {
            return Err(format!(
                "the checkpoint's {key} is {:?}, this node's genesis has {:?}",
                short(&restored),
                short(local)
            ));
        }
    }
    Ok(plan.genesis["sys:chain_id"].clone())
}

/// The restored state is of this node's genesis, its own committee signed
/// one of the QCs under this node's chain id, and this node is not one of
/// its validators. Returns the verified pair.
fn verify_restored(
    storage: &StateDB,
    plan: &RestorePlan<'_>,
    pairs: &[(Block, QuorumCertificate)],
) -> Result<(Block, QuorumCertificate), String> {
    let chain_id = check_genesis(storage, plan)?;
    let height = plan.checkpoint.height;
    let epoch = consensus::qc_producer::epoch_for_block_height(storage, height)
        .ok_or("the restored state has no epoch for the checkpoint height")?;
    let committee = consensus::qc_producer::load_validator_set_for_epoch(storage, epoch)
        .ok_or("the restored state has no committee for the checkpoint's epoch")?;
    if let Some(me) = plan.local_signer {
        let signs = committee.iter().any(|v| v.address == me)
            || storage
                .get_active_validators()
                .iter()
                .any(|(address, _)| address == me);
        if signs {
            return Err(format!(
                "this node's key {me} is a validator of the restored chain. A validator key \
                 restored onto a new datadir can sign a slot its old instance already signed, \
                 and the abstention that prevents that (G1 RC-3) does not exist yet (SN-6). \
                 Restore with a new node key, as an observer"
            ));
        }
    }
    let mut last_error = String::from("no QC");
    for (block, qc) in pairs {
        if qc.epoch != epoch {
            last_error = format!("QC epoch {} is not the restored epoch {epoch}", qc.epoch);
            continue;
        }
        match consensus::qc::verify_qc(qc, &committee, &chain_id) {
            Ok(()) => return Ok((block.clone(), qc.clone())),
            Err(e) => last_error = format!("{e:?}"),
        }
    }
    Err(format!(
        "no QC for the checkpoint verifies under the restored committee: {last_error}"
    ))
}

/// SN-1b: the consensus bootstrap record, in the batch that also completes
/// the tree and removes the restore marker. The chain rows come from the
/// checkpoint's block and its verified QC, never from a peer's database.
fn bootstrap_record(
    mut batch: WriteBatch,
    plan: &RestorePlan<'_>,
    block: &Block,
    qc: &QuorumCertificate,
) -> Result<WriteBatch, String> {
    let h = block.header.height.to_string();
    let block_json = serde_json::to_string(block).map_err(|e| e.to_string())?;
    let qc_json = serde_json::to_string(qc).map_err(|e| e.to_string())?;
    let anchor_round = qc.anchor_round.to_string();
    let finalized_round = qc.finalized_round.to_string();
    let checkpoint = plan.checkpoint.to_string();
    let rows: Vec<(String, &str)> = vec![
        ("jmt:floor".into(), &h),
        (format!("block_{h}"), &block_json),
        ("latest_height".into(), &h),
        ("latest_block_hash".into(), &block.header.hash),
        ("sys:last_executed_height".into(), &h),
        ("consensus:last_adopted_height".into(), &h),
        ("consensus:finality_digest".into(), &qc.finality_digest),
        ("consensus:last_anchor_round".into(), &anchor_round),
        ("consensus:last_anchor_hash".into(), &qc.anchor_hash),
        ("consensus:finalized_round".into(), &finalized_round),
        (format!("consensus:qc:{h}"), &qc_json),
        (format!("consensus:qc_by_round:{anchor_round}"), &qc_json),
        ("consensus:qc:latest".into(), &qc_json),
        ("consensus:qc:latest_height".into(), &h),
        ("consensus:qc:latest_round".into(), &anchor_round),
        ("genesis_identity".into(), plan.genesis_identity),
        ("genesis_initialized".into(), "true"),
        // Node-local rows that described the replaced chain: nothing below
        // `h` exists now, and a sync halt was about the old state.
        (StateDB::BLOCK_PRUNE_CURSOR_KEY.into(), &h),
        (RESTORED_CHECKPOINT.into(), &checkpoint),
    ];
    for (key, value) in rows {
        batch.put(key.as_bytes(), value.as_bytes());
    }
    batch.delete(b"sync:halt_reason");
    // Genesis rows outside the state (stdlib pins, version), from this
    // node's own build; the state rows came with the restore.
    for (key, value) in plan.genesis {
        if classify(key.as_bytes()) != Some(KeyClass::State) {
            batch.put(key.as_bytes(), value.as_bytes());
        }
    }
    batch.delete(RESTORE_MARKER.as_bytes());
    Ok(batch)
}

/// Refuse to overwrite a chain unless asked (`replace_existing`). A fresh
/// datadir, or one an interrupted restore marked, is always fine.
fn check_datadir(storage: &StateDB, replace_existing: bool) -> Result<(), String> {
    let marked = storage
        .get(RESTORE_MARKER)
        .map_err(|e| e.to_string())?
        .is_some();
    let holds_chain = storage
        .get("genesis_initialized")
        .map_err(|e| e.to_string())?
        .is_some()
        || storage
            .get("latest_height")
            .map_err(|e| e.to_string())?
            .is_some();
    if holds_chain && !marked && !replace_existing {
        return Err(
            "this datadir already holds a chain; restoring replaces it, so it must be asked for"
                .into(),
        );
    }
    Ok(())
}

/// Round robin over the peers, less the ones caught sending a bad stream.
struct PeerSet {
    excluded: Vec<bool>,
    next: usize,
}

impl PeerSet {
    fn new(peers: usize) -> Self {
        Self {
            excluded: vec![false; peers],
            next: 0,
        }
    }

    fn pick(&mut self) -> Option<usize> {
        let n = self.excluded.len();
        for _ in 0..n {
            let peer = self.next % n;
            self.next = self.next.wrapping_add(1);
            if !self.excluded[peer] {
                return Some(peer);
            }
        }
        None
    }

    fn exclude(&mut self, peer: usize) {
        self.excluded[peer] = true;
    }

    fn live(&self) -> usize {
        self.excluded.iter().filter(|e| !**e).count()
    }
}

enum Reply {
    Chunk(state_commit::Entries, Vec<u8>),
    Done,
    /// No usable answer. Not proof of lying: a busy or pruning peer, a dead
    /// connection, or a leaf too large to take.
    Unanswered(String),
}

/// One chunk from `peer`, with every value too large to travel inline
/// fetched in parts from the same peer. Nothing here is verified yet.
async fn ask_chunk<F, Fut>(ask: &mut F, peer: usize, version: u64, after: Option<[u8; 32]>) -> Reply
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let request = ChunkRequest {
        version,
        after: after.map(hex::encode),
        max: MAX_CHUNK_ENTRIES,
    };
    let Ok(message) = serde_json::to_string(&request) else {
        return Reply::Unanswered("cannot encode the request".into());
    };
    let response = match ask(peer, format!("{CHUNK_REQ}{message}")).await {
        Ok(reply) => reply
            .strip_prefix(CHUNK_RESP)
            .and_then(|json| serde_json::from_str::<ChunkResponse>(json).ok()),
        Err(e) => return Reply::Unanswered(e),
    };
    let Some(response) = response else {
        return Reply::Unanswered("a garbled answer".into());
    };
    if let Some(error) = response.error {
        return Reply::Unanswered(error);
    }
    if response.done {
        return Reply::Done;
    }
    let Ok(proof) = hex::decode(&response.proof) else {
        return Reply::Unanswered("a garbled proof".into());
    };
    let mut total = 0u64;
    let mut entries = Vec::with_capacity(response.entries.len());
    for entry in response.entries {
        let Ok(mut value) = hex::decode(&entry.value) else {
            return Reply::Unanswered("a garbled value".into());
        };
        total = total.saturating_add(entry.len);
        if entry.len > MAX_LEAF_BYTES || total > MAX_CHUNK_TOTAL_BYTES {
            return Reply::Unanswered(format!(
                "a leaf of {} bytes is too large to take",
                entry.len
            ));
        }
        if (value.len() as u64) > entry.len {
            return Reply::Unanswered("a value longer than its length".into());
        }
        while (value.len() as u64) < entry.len {
            let part = ValueRequest {
                version,
                key: entry.key.clone(),
                offset: value.len() as u64,
            };
            let Ok(message) = serde_json::to_string(&part) else {
                return Reply::Unanswered("cannot encode the request".into());
            };
            let part = match ask(peer, format!("{VALUE_REQ}{message}")).await {
                Ok(reply) => reply
                    .strip_prefix(VALUE_RESP)
                    .and_then(|json| serde_json::from_str::<ValueResponse>(json).ok()),
                Err(e) => return Reply::Unanswered(e),
            };
            let Some(part) = part.filter(|p| p.error.is_none() && p.len == entry.len) else {
                return Reply::Unanswered("a value part was refused".into());
            };
            match hex::decode(&part.data) {
                Ok(data)
                    if !data.is_empty() && value.len() as u64 + data.len() as u64 <= entry.len =>
                {
                    value.extend_from_slice(&data)
                }
                _ => return Reply::Unanswered("a garbled value part".into()),
            }
        }
        entries.push((entry.key, value));
    }
    Reply::Chunk(entries, proof)
}

/// SN-2: restore the state at `plan.checkpoint` from `peers` peers, asking
/// peer `i` with `ask(i, message)`, then write the bootstrap record (SN-1b).
///
/// Requests go round robin, so no one peer holds the restore. A peer that
/// sends a refused chunk, or ends the stream early, is shut out and the
/// partial restore starts over with the others. An unanswered request is
/// retried with the next peer, from the same cursor, after a backoff. The
/// datadir carries the restore marker from the first write to the last, and
/// keeps it when the restore fails: a failed or interrupted restore refuses
/// to boot (RC-1) until a restore completes.
pub async fn restore_state<F, Fut>(
    storage: &Arc<StateDB>,
    plan: &RestorePlan<'_>,
    peers: usize,
    mut ask: F,
) -> Result<Restored, String>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    if peers == 0 {
        return Err("no peers to restore from".into());
    }
    check_datadir(storage, plan.replace_existing)?;
    let cp = plan.checkpoint;
    let root = hex32(&cp.state_root).ok_or("malformed checkpoint root")?;
    let pairs = fetch_anchor(cp, peers, &mut ask).await?;

    let marker = serde_json::json!({"height": cp.height, "state_root": cp.state_root});
    storage
        .put(RESTORE_MARKER, &marker.to_string())
        .map_err(|e| e.to_string())?;

    let mut set = PeerSet::new(peers);
    let mut restarts = 0usize;
    let mut failures = 0usize;
    'restore: loop {
        clear(storage)?;
        let mut restore = state_commit::Restore::begin(
            Arc::clone(storage),
            cp.height,
            state_commit::RootHash(root),
        )
        .map_err(|e| e.to_string())?;
        let mut leaves = 0usize;
        let ended_by = loop {
            let Some(peer) = set.pick() else {
                return Err(format!(
                    "every peer sent a bad state stream ({restarts} restarts)"
                ));
            };
            match ask_chunk(&mut ask, peer, cp.height, restore.cursor()).await {
                Reply::Unanswered(why) => {
                    failures += 1;
                    if failures >= plan.patience.max_failures {
                        return Err(format!(
                            "no peer serves the checkpoint's state (last: {why})"
                        ));
                    }
                    tokio::time::sleep(plan.patience.backoff(failures, set.live())).await;
                }
                Reply::Done => {
                    failures = 0;
                    break peer;
                }
                Reply::Chunk(entries, proof) => {
                    failures = 0;
                    match restore.add_wire_chunk(entries, &proof) {
                        Ok(verified) => {
                            leaves += verified.len();
                            storage
                                .restore_transaction(|view| {
                                    let mut batch = WriteBatch::default();
                                    for (key, value) in &verified {
                                        batch.put(key.as_bytes(), value);
                                    }
                                    view.write_batch(batch)
                                })
                                .map_err(|e| e.to_string())?;
                        }
                        Err(e) => {
                            eprintln!(
                                "⚠️ [STATE_SYNC] peer {peer} sent a refused chunk, shut out: {e}"
                            );
                            set.exclude(peer);
                            restarts += 1;
                            continue 'restore;
                        }
                    }
                }
            }
        };
        let tree = match restore.finish() {
            Ok(batch) => batch,
            Err(e) => {
                eprintln!("⚠️ [STATE_SYNC] peer {ended_by} ended the stream early, shut out: {e}");
                set.exclude(ended_by);
                restarts += 1;
                continue 'restore;
            }
        };
        // The tree is whole at `root` but `jmt:latest` is not written yet;
        // the checks read only flat state. On failure the marker stays.
        let (block, qc) = verify_restored(storage, plan, &pairs)
            .map_err(|e| format!("the checkpoint is inconsistent: {e}"))?;
        let record = bootstrap_record(tree, plan, &block, &qc)?;
        storage.write_batch(record).map_err(|e| e.to_string())?;
        return Ok(Restored {
            height: cp.height,
            leaves,
            restarts,
        });
    }
}

type Connections =
    tokio::sync::Mutex<std::collections::HashMap<usize, (tokio::net::TcpStream, [u8; 32])>>;

/// How long one request over TCP may take before it counts as unanswered.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `restore_state` over the node's encrypted TCP transport, to the peers'
/// sync ports. One connection per peer, kept across requests and reopened
/// after a failure or a timeout.
pub async fn restore_over_tcp(
    storage: &Arc<StateDB>,
    plan: &RestorePlan<'_>,
    peers: &[(String, u16)],
    my_port: u16,
) -> Result<Restored, String> {
    let key = crypto::SigningKey::generate(&mut rand::rngs::OsRng);
    let connections: Arc<Connections> = Arc::default();
    restore_state(storage, plan, peers.len(), |peer, msg| {
        let connections = Arc::clone(&connections);
        let (ip, port) = peers[peer].clone();
        let key = key.clone();
        async move {
            let asked = ask_over_tcp(&connections, peer, &ip, port, my_port, &key, &msg);
            match tokio::time::timeout(REQUEST_TIMEOUT, asked).await {
                Ok(reply) => reply,
                Err(_) => {
                    // The connection may be mid-frame: never reuse it.
                    connections.lock().await.remove(&peer);
                    Err(format!("{ip}:{port}: no answer in {REQUEST_TIMEOUT:?}"))
                }
            }
        }
    })
    .await
}

async fn ask_over_tcp(
    connections: &Connections,
    peer: usize,
    ip: &str,
    port: u16,
    my_port: u16,
    key: &crypto::SigningKey,
    msg: &str,
) -> Result<String, String> {
    let mut open = connections.lock().await;
    if let std::collections::hash_map::Entry::Vacant(slot) = open.entry(peer) {
        let (stream, shared, _) =
            network::secure_connect(ip, port, "__state_sync__", my_port, None, key)
                .await
                .map_err(|e| format!("{ip}:{port}: {e}"))?;
        slot.insert((stream, shared));
    }
    let (stream, shared) = open.get_mut(&peer).ok_or("no connection")?;
    let reply = match network::send_encrypted_msg(stream, shared, msg).await {
        Ok(()) => network::read_encrypted_msg(stream, shared).await,
        Err(e) => Err(e),
    };
    reply.map_err(|e| {
        open.remove(&peer);
        format!("{ip}:{port}: {e}")
    })
}

#[cfg(test)]
mod tests;
