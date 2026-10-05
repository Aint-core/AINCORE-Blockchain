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
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
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
const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// A value longer than this travels in parts (`STATE_VALUE_REQ`), so no
/// single leaf can make a chunk unservable.
pub const INLINE_VALUE_BYTES: usize = 256 * 1024;
/// The bytes of one value part. Every part but a value's last is exactly
/// this long, so a peer that sends less is caught at once.
pub const VALUE_PART_BYTES: usize = 1024 * 1024;
/// The largest leaf the protocol carries, and the most bytes one chunk may
/// add up to. A server never sends past them; a client that is sent past
/// them has met a liar.
pub const MAX_LEAF_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_CHUNK_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
/// Snapshot serving, apart from vertex serving: requests in flight and cost
/// units per second (a leaf, or `UNIT_BYTES` read), globally and per client,
/// so no one client takes more than its share. A client is the key its
/// session authenticated (G4 S6).
pub const STATE_SERVE_IN_FLIGHT: usize = 4;
pub const STATE_SERVE_IN_FLIGHT_PER_CLIENT: usize = 1;
pub const STATE_SERVE_UNITS_PER_SEC: f64 = 8_000.0;
pub const STATE_SERVE_UNITS_PER_SEC_PER_CLIENT: f64 = 2_000.0;
pub const UNIT_BYTES: u64 = 4 * 1024;
/// Clients remembered at once; idle ones are forgotten first.
const MAX_TRACKED_CLIENTS: usize = 1_024;
/// Rows deleted per batch while clearing a datadir.
const CLEAR_BATCH: usize = 10_000;
/// The longest wait between "busy" answers to a value part: a server's
/// budget refills within a second.
const PART_BUSY_WAIT: Duration = Duration::from_secs(1);
/// What a turn longer than `Patience::slow_turn` must deliver, or its peer
/// sits out turns. An honest server delivers at its budget, several times
/// this.
const MIN_TURN_UNITS_PER_SEC: f64 = STATE_SERVE_UNITS_PER_SEC_PER_CLIENT / 8.0;
/// Where a restored node records the checkpoint it restored, and the key it
/// restored with (N).
pub const RESTORED_CHECKPOINT: &str = "sys:restored_checkpoint";
pub const RESTORED_BY: &str = "sys:restored_by";

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

/// `VALUE_PART_BYTES` of a value from `offset`, or what is left of it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueResponse {
    /// Hex of the part.
    pub data: String,
    /// The whole value's length.
    pub len: u64,
    pub error: Option<String>,
}

const BUSY: &str = "busy";
const NOT_SERVED: &str = "snapshots not served here";
/// The units a value part costs: a request and its bytes.
const PART_UNITS: usize = 1 + VALUE_PART_BYTES / UNIT_BYTES as usize;
/// The values kept for serving parts: at most this many, and this many
/// bytes in all.
const VALUE_CACHE_ENTRIES: usize = 4;
const VALUE_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// The values last served in parts, the least recently used out first, so
/// the parts of one value cost one read even while others are served.
#[derive(Default)]
pub struct ValueCache {
    /// Most recently used last.
    entries: Vec<(u64, String, Arc<Vec<u8>>)>,
}

impl ValueCache {
    fn get(&mut self, version: u64, key: &str) -> Option<Arc<Vec<u8>>> {
        let at = self
            .entries
            .iter()
            .position(|(v, k, _)| *v == version && k == key)?;
        let entry = self.entries.remove(at);
        let value = Arc::clone(&entry.2);
        self.entries.push(entry);
        Some(value)
    }

    fn put(&mut self, version: u64, key: &str, value: Arc<Vec<u8>>) {
        self.entries
            .retain(|(v, k, _)| !(*v == version && k == key));
        self.entries.push((version, key.to_string(), value));
        while self.entries.len() > VALUE_CACHE_ENTRIES
            || (self.entries.len() > 1
                && self.entries.iter().map(|e| e.2.len()).sum::<usize>() > VALUE_CACHE_BYTES)
        {
            self.entries.remove(0);
        }
    }
}

/// The protocol's limits on one chunk, counted leaf by leaf: no leaf over
/// `MAX_LEAF_BYTES`; at most `MAX_CHUNK_BYTES` inline (key, hex value and
/// framing per leaf, and the proof in hex); at most `MAX_CHUNK_TOTAL_BYTES`
/// in parts.
struct ChunkBudget {
    inline: usize,
    parted: u64,
}

impl ChunkBudget {
    /// Room kept for a proof of `proof` bytes.
    fn new(proof: usize) -> Self {
        Self {
            inline: 2 * proof,
            parted: 0,
        }
    }

    /// Whether the chunk may also carry a leaf of `len` bytes under `key`:
    /// inline up to `INLINE_VALUE_BYTES`, in parts above.
    fn take(&mut self, key: &str, len: u64) -> bool {
        self.inline += key.len() + 32;
        if len > INLINE_VALUE_BYTES as u64 {
            self.parted = self.parted.saturating_add(len);
        } else {
            self.inline += 2 * len as usize;
        }
        len <= MAX_LEAF_BYTES
            && self.inline <= MAX_CHUNK_BYTES
            && self.parted <= MAX_CHUNK_TOTAL_BYTES
    }
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

struct Bucket {
    tokens: f64,
    last: Instant,
    in_flight: usize,
}

impl Bucket {
    fn full(burst: f64) -> Self {
        Self {
            tokens: burst,
            last: Instant::now(),
            in_flight: 0,
        }
    }

    fn refill(&mut self, rate: f64, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * rate).min(rate);
    }
}

struct Buckets {
    global: Bucket,
    per_client: HashMap<String, Bucket>,
}

/// Snapshot serving's budget: slots in flight and cost units, globally and
/// per client IP. A burst is one second's worth. Bytes read are charged
/// after the fact and may leave a bucket in debt, which later requests wait
/// out.
pub struct StateBudget {
    buckets: Mutex<Buckets>,
}

impl Default for StateBudget {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(Buckets {
                global: Bucket::full(STATE_SERVE_UNITS_PER_SEC),
                per_client: HashMap::new(),
            }),
        }
    }
}

/// A request let in: `granted` units, and a slot released on drop.
pub struct Admission<'a> {
    budget: &'a StateBudget,
    client: Option<String>,
    pub granted: usize,
}

impl StateBudget {
    /// Plain counters: recovering from a poisoned lock is safe.
    fn lock(&self) -> MutexGuard<'_, Buckets> {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Let a request from `client` in (`None`: in process, global limits
    /// only), with up to `want` units both buckets hold. `None` when busy.
    pub fn admit(&self, client: Option<&str>, want: usize) -> Option<Admission<'_>> {
        self.admit_at_least(client, want, 1)
    }

    /// `admit`, only when both buckets hold all `units`.
    pub fn admit_all(&self, client: Option<&str>, units: usize) -> Option<Admission<'_>> {
        self.admit_at_least(client, units, units)
    }

    fn admit_at_least(
        &self,
        client: Option<&str>,
        want: usize,
        least: usize,
    ) -> Option<Admission<'_>> {
        let mut st = self.lock();
        let now = Instant::now();
        st.global.refill(STATE_SERVE_UNITS_PER_SEC, now);
        if st.global.in_flight >= STATE_SERVE_IN_FLIGHT {
            return None;
        }
        let mut cap = st.global.tokens;
        if let Some(client) = client {
            if !st.per_client.contains_key(client) && st.per_client.len() >= MAX_TRACKED_CLIENTS {
                // A bucket that has refilled and is idle is the same as a
                // new one.
                st.per_client.retain(|_, b| {
                    let refilled = b.tokens
                        + now.saturating_duration_since(b.last).as_secs_f64()
                            * STATE_SERVE_UNITS_PER_SEC_PER_CLIENT;
                    b.in_flight > 0 || refilled < STATE_SERVE_UNITS_PER_SEC_PER_CLIENT
                });
                if st.per_client.len() >= MAX_TRACKED_CLIENTS {
                    return None;
                }
            }
            let bucket = st
                .per_client
                .entry(client.to_string())
                .or_insert_with(|| Bucket::full(STATE_SERVE_UNITS_PER_SEC_PER_CLIENT));
            bucket.refill(STATE_SERVE_UNITS_PER_SEC_PER_CLIENT, now);
            if bucket.in_flight >= STATE_SERVE_IN_FLIGHT_PER_CLIENT {
                return None;
            }
            cap = cap.min(bucket.tokens);
        }
        let granted = (want as f64).min(cap).floor();
        if granted < least.max(1) as f64 {
            return None;
        }
        st.global.tokens -= granted;
        st.global.in_flight += 1;
        if let Some(bucket) = client.and_then(|c| st.per_client.get_mut(c)) {
            bucket.tokens -= granted;
            bucket.in_flight += 1;
        }
        Some(Admission {
            budget: self,
            client: client.map(str::to_string),
            granted: granted as usize,
        })
    }
}

impl StateBudget {
    /// Tests only: the units a bucket holds now, before any refill.
    #[cfg(test)]
    fn balance(&self, client: Option<&str>) -> f64 {
        let st = self.lock();
        match client {
            None => st.global.tokens,
            Some(c) => st.per_client.get(c).map_or(f64::NAN, |b| b.tokens),
        }
    }
}

impl Admission<'_> {
    /// Charge `bytes` sent or read, on top of what was granted, but never
    /// more than one second's worth for a client: a bucket in debt waits a
    /// second at most, so one costly request cannot lock a client out.
    fn charge(&self, bytes: u64) {
        let units = (bytes.div_ceil(UNIT_BYTES) as f64).min(STATE_SERVE_UNITS_PER_SEC_PER_CLIENT);
        let mut st = self.budget.lock();
        st.global.tokens -= units;
        if let Some(bucket) = self
            .client
            .as_deref()
            .and_then(|c| st.per_client.get_mut(c))
        {
            bucket.tokens -= units;
        }
    }

    /// Give back `units` of the grant that went unused.
    fn refund(&self, units: usize) {
        let units = units as f64;
        let mut st = self.budget.lock();
        st.global.tokens = (st.global.tokens + units).min(STATE_SERVE_UNITS_PER_SEC);
        if let Some(bucket) = self
            .client
            .as_deref()
            .and_then(|c| st.per_client.get_mut(c))
        {
            bucket.tokens = (bucket.tokens + units).min(STATE_SERVE_UNITS_PER_SEC_PER_CLIENT);
        }
    }
}

impl Drop for Admission<'_> {
    fn drop(&mut self) {
        let mut st = self.budget.lock();
        st.global.in_flight = st.global.in_flight.saturating_sub(1);
        if let Some(bucket) = self
            .client
            .as_deref()
            .and_then(|c| st.per_client.get_mut(c))
        {
            bucket.in_flight = bucket.in_flight.saturating_sub(1);
        }
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

    /// `serve_state_chunk` for an in-process caller.
    pub fn handle_state_chunk(&self, req: ChunkRequest) -> ChunkResponse {
        self.serve_state_chunk(req, None)
    }

    /// Serve one restore chunk (SN-2) of a version this node retains, to
    /// `peer`, within the protocol's limits (`ChunkBudget`): the leaves are
    /// read once, up to the first that does not fit. Charged a unit per leaf
    /// served and per `UNIT_BYTES` read (at most one second's worth), under
    /// the global and the per-IP budget; the reads off the shared workers.
    pub fn serve_state_chunk(&self, req: ChunkRequest, peer: Option<&str>) -> ChunkResponse {
        let refuse = |why: &str| ChunkResponse {
            error: Some(why.to_string()),
            ..Default::default()
        };
        if !self.serves_snapshots {
            return refuse(NOT_SERVED);
        }
        let after = match req.after.as_deref() {
            None => None,
            Some(hex) => match hex32(hex) {
                Some(hash) => Some(hash),
                None => return refuse("malformed cursor"),
            },
        };
        // A few point reads: before anything is charged.
        if let Err(why) = self.state_servable(req.version) {
            return refuse(why);
        }
        let Some(admission) = self
            .state_budget
            .admit(peer, req.max.clamp(1, MAX_CHUNK_ENTRIES))
        else {
            return refuse(BUSY);
        };
        blocking(|| {
            let mut budget = ChunkBudget::new(state_commit::MAX_RANGE_PROOF_BYTES);
            let (mut read, mut refused) = (0u64, false);
            // A value too large to travel inline is only measured: its bytes
            // are not held while the chunk is built.
            let mut entries = Vec::new();
            let chunk = state_commit::wire_chunk_with(
                &self.storage,
                req.version,
                after,
                admission.granted,
                |key, value| {
                    let len = value.len() as u64;
                    read += len;
                    refused = !budget.take(&key, len);
                    if !refused {
                        entries.push(WireEntry {
                            len,
                            value: if value.len() > INLINE_VALUE_BYTES {
                                String::new()
                            } else {
                                hex::encode(&value)
                            },
                            key,
                        });
                    }
                    !refused
                },
            );
            admission.charge(read);
            let proof = match chunk {
                Ok(Some(proof)) => proof,
                Ok(None) if refused => return refuse("a leaf over the protocol's limit"),
                Ok(None) => {
                    admission.refund(admission.granted);
                    return ChunkResponse {
                        done: true,
                        ..Default::default()
                    };
                }
                Err(_) => return refuse("version not whole here"),
            };
            admission.refund(admission.granted.saturating_sub(entries.len()));
            ChunkResponse {
                entries,
                proof: hex::encode(proof),
                done: false,
                error: None,
            }
        })
    }

    /// `serve_state_value` for an in-process caller.
    pub fn handle_state_value(&self, req: ValueRequest) -> ValueResponse {
        self.serve_state_value(req, None)
    }

    /// Serve `VALUE_PART_BYTES` of one leaf's value from `offset` to
    /// `peer`, for a value too large to travel inline. A part is let in only
    /// when its whole cost fits; reading a value that is not cached costs at
    /// most one more second's worth.
    pub fn serve_state_value(&self, req: ValueRequest, peer: Option<&str>) -> ValueResponse {
        let refuse = |why: &str| ValueResponse {
            error: Some(why.to_string()),
            ..Default::default()
        };
        if !self.serves_snapshots {
            return refuse(NOT_SERVED);
        }
        if let Err(why) = self.state_servable(req.version) {
            return refuse(why);
        }
        let Some(admission) = self.state_budget.admit_all(peer, PART_UNITS) else {
            return refuse(BUSY);
        };
        blocking(|| {
            let cached = self
                .state_value_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(req.version, &req.key);
            let value = match cached {
                Some(value) => value,
                None => match state_commit::value_at(&self.storage, &req.key, req.version) {
                    Ok(Some(value)) => {
                        admission.charge(value.len() as u64);
                        let value = Arc::new(value);
                        self.state_value_cache
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .put(req.version, &req.key, Arc::clone(&value));
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
    /// Requests in a row, across all peers, that got no usable answer (a
    /// dead or silent peer, a refusal other than busy) before giving up.
    /// Busy answers wait instead, within `deadline`.
    pub max_failures: usize,
    /// The wait after a request that got no usable answer, doubling each
    /// round of the peers up to `backoff_max`.
    pub backoff_start: Duration,
    pub backoff_max: Duration,
    /// One request's limit over TCP.
    pub request_timeout: Duration,
    /// The slowest a peer may send a value's parts before it counts as not
    /// answering: this many bytes a second, after `request_timeout`.
    pub min_bytes_per_sec: u64,
    /// A turn that takes longer than this must deliver at least
    /// `MIN_TURN_UNITS_PER_SEC`, or its peer sits out turns: a peer that
    /// trickles valid chunks, or stalls before saying busy, loses its turns.
    pub slow_turn: Duration,
    /// The whole restore's limit.
    pub deadline: Duration,
}

impl Default for Patience {
    fn default() -> Self {
        Self {
            max_failures: 60,
            backoff_start: Duration::from_millis(50),
            backoff_max: Duration::from_secs(5),
            request_timeout: Duration::from_secs(60),
            min_bytes_per_sec: 256 * 1024,
            slow_turn: Duration::from_secs(2),
            deadline: Duration::from_secs(24 * 60 * 60),
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
    /// validator (SN-6), and records it.
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
/// internally whole. The QC's signature and the block's proposer signature
/// are checked after the restore.
fn check_anchor(cp: &Checkpoint, block: &Block, qc: &QuorumCertificate) -> Result<(), String> {
    let h = &block.header;
    if h.height != cp.height
        || !h.hash.eq_ignore_ascii_case(&cp.block_hash)
        || !h.state_root.eq_ignore_ascii_case(&cp.state_root)
    {
        return Err("the block is not the checkpoint's".into());
    }
    block
        .check_commitments()
        .map_err(|e| format!("the block's header does not commit to its body: {e}"))?;
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

type Pair = (Block, QuorumCertificate);

/// Every distinct (block, QC) pair the peers hold for the checkpoint, asked
/// again, round after round, until one is found. A pair stays together: the
/// block stored is the one whose own QC verifies.
async fn fetch_anchor<F, Fut>(
    cp: &Checkpoint,
    peers: usize,
    ask: &mut F,
    patience: &Patience,
) -> Result<Vec<Pair>, String>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let request =
        serde_json::to_string(&AnchorRequest { height: cp.height }).map_err(|e| e.to_string())?;
    for round in 0..patience.max_failures.max(1) {
        let mut pairs: Vec<Pair> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
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
            let id = serde_json::to_string(&(&block, &qc)).map_err(|e| e.to_string())?;
            if !seen.contains(&id) {
                seen.push(id);
                pairs.push((block, qc));
            }
        }
        if !pairs.is_empty() {
            return Ok(pairs);
        }
        tokio::time::sleep(patience.backoff(round + 1, 1)).await;
    }
    Err(format!(
        "no peer holds block {} and its QC as the checkpoint names them",
        cp.height
    ))
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

fn sn6_refusal(me: &str) -> String {
    format!(
        "this node's key {me} is a validator of the chain. A validator key restored onto a \
         new datadir can sign a slot its old instance already signed, and the abstention that \
         prevents that (G1 RC-3) does not exist yet (SN-6). Restore with a new node key, as an \
         observer"
    )
}

/// The checkpoint epoch's committee, as the restored state records it; and
/// SN-6: this node's key is no validator the restored state records.
fn restored_committee(
    storage: &StateDB,
    plan: &RestorePlan<'_>,
) -> Result<(u64, Vec<consensus::qc::ValidatorInfo>), String> {
    let height = plan.checkpoint.height;
    let epoch = consensus::qc_producer::epoch_for_block_height(storage, height)
        .ok_or("the restored state has no epoch for the checkpoint height")?;
    // B50: on V4, C_E as the restored state records it (E's own record is
    // not state). Past epoch 0 only a boundary block can be restored: E+1's
    // record is rebuilt from it, and E's, which an inner checkpoint would
    // need, cannot be (it is derived from H_{E-1}, which a restore lacks).
    let committee = if consensus::v4::is_v4_chain(storage) {
        let interval = consensus::v4::epoch::epoch_interval(storage)
            .ok_or("a V4 chain needs its epoch interval")?;
        if epoch > 0 && !height.is_multiple_of(interval) {
            return Err(format!(
                "a V4 checkpoint past epoch 0 must be an epoch boundary (every {interval} blocks), not {height}"
            ));
        }
        consensus::v4::epoch::recorded_committee(storage, epoch)
    } else {
        consensus::qc_producer::load_validator_set_for_epoch(storage, epoch)
    }
    .ok_or("the restored state has no committee for the checkpoint's epoch")?;
    if let Some(me) = plan.local_signer {
        if recorded_validator(storage, me) {
            return Err(sn6_refusal(me));
        }
    }
    Ok((epoch, committee))
}

/// SN-6: whether `storage` records `key` as a validator: in the committee of
/// any epoch it retains, or in the active set. It cannot tell about a chain
/// it has not seen: a key that joined after the checkpoint is not in a
/// restored state (G1 RC-3 covers that case; see the contract).
pub fn recorded_validator(storage: &StateDB, key: &str) -> bool {
    let current = storage
        .get("consensus:epoch")
        .ok()
        .flatten()
        .and_then(|e| e.parse::<u64>().ok())
        .unwrap_or(0);
    (0..=current).rev().take(64).any(|epoch| {
        consensus::qc_producer::load_validator_set_for_epoch(storage, epoch)
            .is_some_and(|set| set.iter().any(|v| v.address == key))
    }) || storage
        .get_active_validators()
        .iter()
        .any(|(address, _)| address == key)
}

/// Whether `signer` may sign the checkpoint's block: a validator of the
/// checkpoint epoch's committee, or of the restored active set.
fn signed_by_a_validator(
    storage: &StateDB,
    committee: &[consensus::qc::ValidatorInfo],
    signer: &str,
) -> bool {
    committee.iter().any(|v| v.address == signer)
        || storage
            .get_active_validators()
            .iter()
            .any(|(address, _)| address == signer)
}

/// The first pair whose QC the committee signed under this chain id, and
/// whose block one of that committee's validators signed, under the key the
/// restored state records for it.
fn verified_pair(
    storage: &StateDB,
    chain_id: &str,
    epoch: u64,
    committee: &[consensus::qc::ValidatorInfo],
    pairs: &[Pair],
) -> Result<Pair, String> {
    let mut last_error = String::from("no QC");
    for (block, qc) in pairs {
        let signer = &block.proposer_signer;
        if !signed_by_a_validator(storage, committee, signer) {
            last_error = format!("block signer {signer} is not a validator");
            continue;
        }
        if qc.epoch != epoch {
            last_error = format!("QC epoch {} is not the restored epoch {epoch}", qc.epoch);
            continue;
        }
        if let Err(e) = consensus::qc::verify_qc(qc, committee, chain_id) {
            last_error = format!("{e:?}");
            continue;
        }
        match ChainSync::verify_proposer_signature_in(storage, block) {
            Ok(()) => return Ok((block.clone(), qc.clone())),
            Err(e) => last_error = e,
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
    storage: &StateDB,
    mut batch: WriteBatch,
    plan: &RestorePlan<'_>,
    block: &Block,
    qc: &QuorumCertificate,
    next: Option<&consensus::v4::epoch::EpochStart>,
) -> Result<WriteBatch, String> {
    let h = block.header.height.to_string();
    let block_json = serde_json::to_string(block).map_err(|e| e.to_string())?;
    let qc_json = serde_json::to_string(qc).map_err(|e| e.to_string())?;
    // B82: a restored node only adopts (SN-6, checked again here); its
    // ordering cursors are written, not left to derivation: nothing at or
    // below the restored anchor is ordered again (the GC floor), and the
    // next anchor is scanned above the finalized round.
    if let Some(me) = plan.local_signer {
        if recorded_validator(storage, me) {
            return Err(sn6_refusal(me));
        }
    }
    let anchor_round = qc.anchor_round.to_string();
    let finalized_round = qc.finalized_round.to_string();
    let next_anchor_round = qc.finalized_round.saturating_add(1).to_string();
    let checkpoint = plan.checkpoint.to_string();
    let mut rows: Vec<(String, &str)> = vec![
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
        ("consensus:gc_floor".into(), &anchor_round),
        ("consensus:next_anchor_round".into(), &next_anchor_round),
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
        (StateDB::KEPT_PIN_BLOCKS_KEY.into(), "[]"),
        // B61: and the finality rows' pruning starts here too.
        (consensus::qc_producer::FINALITY_PRUNE_CURSOR_KEY.into(), &h),
        (RESTORED_CHECKPOINT.into(), &checkpoint),
    ];
    let next_json = next
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| e.to_string())?;
    let next_epoch = next.map(|n| n.epoch.to_string());
    if let (Some(n), Some(json), Some(epoch)) = (next, &next_json, &next_epoch) {
        rows.push((
            consensus::v4::epoch::epoch_start_key(n.epoch),
            json.as_str(),
        ));
        rows.push((
            consensus::v4::epoch::EPOCH_ACTIVE_KEY.into(),
            epoch.as_str(),
        ));
    }
    if let Some(me) = plan.local_signer {
        rows.push((RESTORED_BY.into(), me));
    }
    for (key, value) in rows {
        batch.put(key.as_bytes(), value.as_bytes());
    }
    batch.delete(b"sync:halt_reason");
    // B61: alarms described the replaced chain; kept, they halted ordering
    // on the restored one.
    for (key, _) in storage.scan_prefix("alarm:") {
        batch.delete(key.as_bytes());
    }
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

/// Refuse to overwrite a chain unless asked (`replace_existing`), and a
/// replace of a chain where this node is a validator (SN-6), before anything
/// is cleared. A fresh datadir, or one an interrupted restore marked, is
/// always fine.
fn check_datadir(storage: &StateDB, plan: &RestorePlan<'_>) -> Result<(), String> {
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
    if holds_chain && !marked && !plan.replace_existing {
        return Err(
            "this datadir already holds a chain; restoring replaces it, so it must be asked for"
                .into(),
        );
    }
    if let Some(me) = plan.local_signer {
        if recorded_validator(storage, me) {
            return Err(sn6_refusal(me));
        }
    }
    Ok(())
}

/// Whether a turn that took `took` and delivered `units` was too slow: past
/// `slow_turn`, under `MIN_TURN_UNITS_PER_SEC`. A short turn never is, so a
/// small last chunk costs nothing.
fn too_slow(took: Duration, units: f64, slow_turn: Duration) -> bool {
    took > slow_turn && units / took.as_secs_f64() < MIN_TURN_UNITS_PER_SEC
}

/// The longest a struck peer sits out, in turns.
const MAX_SIT_OUT: u32 = 256;

/// Picks peers for the next request, round robin. A peer that fails to
/// deliver sits out turns, twice as many at each failure in a row, so a
/// slow, silent or stalling peer loses its turns to the ones that deliver
/// while one that stumbled once is soon back. A peer caught lying is shut
/// out for good.
struct PeerSet {
    excluded: Vec<bool>,
    penalty: Vec<u32>,
    sit_out: Vec<u32>,
    next: usize,
}

impl PeerSet {
    fn new(peers: usize) -> Self {
        Self {
            excluded: vec![false; peers],
            penalty: vec![0; peers],
            sit_out: vec![0; peers],
            next: 0,
        }
    }

    fn pick(&mut self) -> Option<usize> {
        let n = self.excluded.len();
        for _ in 0..n {
            let peer = self.next % n;
            self.next = self.next.wrapping_add(1);
            if self.excluded[peer] {
                continue;
            }
            if self.sit_out[peer] > 0 {
                self.sit_out[peer] -= 1;
                continue;
            }
            return Some(peer);
        }
        // Every live peer is sitting out: the one closest to its turn.
        let peer = (0..n)
            .filter(|p| !self.excluded[*p])
            .min_by_key(|p| self.sit_out[*p])?;
        self.sit_out[peer] = 0;
        Some(peer)
    }

    fn delivered(&mut self, peer: usize) {
        self.penalty[peer] = 0;
        self.sit_out[peer] = 0;
    }

    fn strike(&mut self, peer: usize) {
        self.penalty[peer] = self.penalty[peer].saturating_mul(2).clamp(1, MAX_SIT_OUT);
        self.sit_out[peer] = self.penalty[peer];
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
    /// The peer is up but loaded: wait, it is no failure.
    Busy,
    /// No usable answer, which proves nothing: a dead connection, a pruned
    /// version, a peer too slow.
    Unanswered(String),
    /// An answer no honest server gives.
    Lied(String),
}

/// One value, in parts, from `peer`. Every part but the last must be exactly
/// `VALUE_PART_BYTES`, and all of it must arrive at `min_bytes_per_sec`.
async fn ask_parts<F, Fut>(
    ask: &mut F,
    peer: usize,
    version: u64,
    key: &str,
    len: u64,
    patience: &Patience,
) -> Result<Vec<u8>, Reply>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let deadline = Instant::now()
        + patience.request_timeout
        + Duration::from_secs(len / patience.min_bytes_per_sec.max(1));
    let mut value = Vec::with_capacity(len as usize);
    let mut busy = 0usize;
    // A busy server is waited for, with no part lost, as long as parts keep
    // coming: one per request timeout at least, at the minimum rate overall.
    let mut progress = Instant::now();
    while (value.len() as u64) < len {
        if Instant::now() > deadline || progress.elapsed() > patience.request_timeout {
            return Err(Reply::Unanswered("value parts too slow".into()));
        }
        let request = ValueRequest {
            version,
            key: key.to_string(),
            offset: value.len() as u64,
        };
        let message =
            serde_json::to_string(&request).map_err(|e| Reply::Unanswered(e.to_string()))?;
        let part = match ask(peer, format!("{VALUE_REQ}{message}")).await {
            Ok(reply) => reply
                .strip_prefix(VALUE_RESP)
                .and_then(|json| serde_json::from_str::<ValueResponse>(json).ok()),
            Err(e) => return Err(Reply::Unanswered(e)),
        };
        let Some(part) = part else {
            return Err(Reply::Unanswered("a garbled value part".into()));
        };
        match part.error.as_deref() {
            Some(BUSY) => {
                busy += 1;
                tokio::time::sleep(patience.backoff(busy, 1).min(PART_BUSY_WAIT)).await;
                continue;
            }
            Some(error) => return Err(Reply::Unanswered(error.to_string())),
            None => {}
        }
        busy = 0;
        progress = Instant::now();
        let expected = (len - value.len() as u64).min(VALUE_PART_BYTES as u64);
        match hex::decode(&part.data) {
            Ok(data) if part.len == len && data.len() as u64 == expected => {
                value.extend_from_slice(&data)
            }
            Ok(data) => {
                return Err(Reply::Lied(format!(
                    "a value part of {} bytes of {}, where {expected} of {len} were due",
                    data.len(),
                    part.len
                )))
            }
            Err(_) => return Err(Reply::Lied("a value part that is not hex".into())),
        }
    }
    Ok(value)
}

/// One chunk from `peer`, with every value too large to travel inline
/// fetched in parts from the same peer. Nothing here is verified against the
/// root yet; what is checked are the protocol's own limits.
async fn ask_chunk<F, Fut>(
    ask: &mut F,
    peer: usize,
    version: u64,
    after: Option<[u8; 32]>,
    patience: &Patience,
) -> Reply
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
    match response.error.as_deref() {
        Some(BUSY) => return Reply::Busy,
        Some(error) => return Reply::Unanswered(error.to_string()),
        None => {}
    }
    if response.done {
        return Reply::Done;
    }
    let Ok(proof) = hex::decode(&response.proof) else {
        return Reply::Lied("a proof that is not hex".into());
    };
    // Every entry is checked against the protocol's limits, as the server
    // counts them (`ChunkBudget`), before any part is fetched. A value is
    // inline up to `INLINE_VALUE_BYTES` and in parts above.
    let mut budget = ChunkBudget::new(proof.len());
    let mut decoded = Vec::with_capacity(response.entries.len());
    for entry in response.entries {
        let Ok(value) = hex::decode(&entry.value) else {
            return Reply::Lied("a value that is not hex".into());
        };
        let inline = entry.len <= INLINE_VALUE_BYTES as u64;
        let whole = inline && value.len() as u64 == entry.len;
        let parted = !inline && value.is_empty();
        if !whole && !parted {
            return Reply::Lied("a value neither whole nor in parts".into());
        }
        if !budget.take(&entry.key, entry.len) {
            return Reply::Lied(format!(
                "a chunk past the protocol's limits at {}",
                entry.key
            ));
        }
        decoded.push((entry.key, value, parted.then_some(entry.len)));
    }
    let mut entries = Vec::with_capacity(decoded.len());
    for (key, value, parted) in decoded {
        let Some(len) = parted else {
            entries.push((key, value));
            continue;
        };
        match ask_parts(ask, peer, version, &key, len, patience).await {
            Ok(value) => entries.push((key, value)),
            Err(reply) => return reply,
        }
    }
    Reply::Chunk(entries, proof)
}

/// SN-2: restore the state at `plan.checkpoint` from `peers` peers, asking
/// peer `i` with `ask(i, message)`, then write the bootstrap record (SN-1b).
///
/// Requests go round robin, a failing peer sitting out turns (`PeerSet`). A peer
/// that sends a refused chunk, or ends the stream early, is shut out and the
/// partial restore starts over with the others; one that breaks the protocol
/// is shut out with no restart. A busy peer is waited for, within the
/// deadline; a peer that does not answer is retried after a backoff, from
/// the same cursor. The datadir carries the restore marker from the first
/// write to the last, and keeps it when the restore fails: a failed or
/// interrupted restore refuses to boot (RC-1) until a restore completes.
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
    let started = Instant::now();
    let patience = &plan.patience;
    check_datadir(storage, plan)?;
    let cp = plan.checkpoint;
    let root = hex32(&cp.state_root).ok_or("malformed checkpoint root")?;
    let pairs = fetch_anchor(cp, peers, &mut ask, patience).await?;

    let marker = serde_json::json!({"height": cp.height, "state_root": cp.state_root});
    storage
        .put(RESTORE_MARKER, &marker.to_string())
        .map_err(|e| e.to_string())?;

    let mut set = PeerSet::new(peers);
    let mut restarts = 0usize;
    let mut failures = 0usize;
    let mut busy = 0usize;
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
            if started.elapsed() > patience.deadline {
                return Err(format!(
                    "the restore ran out of time ({:?})",
                    patience.deadline
                ));
            }
            let Some(peer) = set.pick() else {
                return Err(format!(
                    "every peer sent a bad state stream ({restarts} restarts)"
                ));
            };
            // The peer's time, not this node's own checking.
            let asked = Instant::now();
            let reply = ask_chunk(&mut ask, peer, cp.height, restore.cursor(), patience).await;
            let took = asked.elapsed();
            match reply {
                Reply::Chunk(entries, proof) => match restore.add_wire_chunk(entries, &proof) {
                    Ok(verified) => {
                        // Judged by what it delivered for the time it took:
                        // valid data sent too slowly still costs turns.
                        let units = verified.len() as f64
                            + verified.iter().map(|(_, v)| v.len() as f64).sum::<f64>()
                                / UNIT_BYTES as f64;
                        if too_slow(took, units, patience.slow_turn) {
                            set.strike(peer);
                        } else {
                            set.delivered(peer);
                        }
                        failures = 0;
                        busy = 0;
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
                },
                Reply::Done => break peer,
                Reply::Busy => {
                    // An honest server says busy at once, before reading
                    // anything; one that takes its time to say it stalls.
                    if took >= patience.slow_turn {
                        set.strike(peer);
                    }
                    busy += 1;
                    tokio::time::sleep(patience.backoff(busy, set.live())).await;
                }
                Reply::Unanswered(why) => {
                    set.strike(peer);
                    failures += 1;
                    if failures >= patience.max_failures {
                        return Err(format!(
                            "no peer serves the checkpoint's state (last: {why})"
                        ));
                    }
                    tokio::time::sleep(patience.backoff(failures, set.live())).await;
                }
                Reply::Lied(why) => {
                    eprintln!("⚠️ [STATE_SYNC] peer {peer} broke the protocol, shut out: {why}");
                    set.exclude(peer);
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
        let inconsistent = |e: String| format!("the checkpoint is inconsistent: {e}");
        let chain_id = check_genesis(storage, plan).map_err(inconsistent)?;
        let (epoch, committee) = restored_committee(storage, plan).map_err(inconsistent)?;
        // B42: the anchor pairs gathered before the download may all be a
        // liar's (honest peers that missed that round): keep asking, within
        // the deadline, until a pair verifies against the restored state.
        let mut candidates = pairs;
        let mut asked = 1u32;
        let (block, qc) = loop {
            match verified_pair(storage, &chain_id, epoch, &committee, &candidates) {
                Ok(pair) => break pair,
                Err(e) if started.elapsed() > patience.deadline => {
                    return Err(inconsistent(e));
                }
                Err(_) => {
                    tokio::time::sleep(patience.backoff(asked as usize, peers)).await;
                    asked = asked.saturating_add(1);
                    // Rounds that found no pair count against the deadline
                    // only: giving up here would throw the download away.
                    candidates = fetch_anchor(cp, peers, &mut ask, patience)
                        .await
                        .unwrap_or_default();
                }
            }
        };
        // B50: at a V4 boundary, E+1's record, which QC(H_E) must bind (the
        // EP-4 check activation runs), and E+1 becomes the active epoch.
        let interval = consensus::v4::epoch::epoch_interval(storage).unwrap_or(0);
        let next = if consensus::v4::is_v4_chain(storage)
            && interval > 0
            && cp.height.is_multiple_of(interval)
        {
            let next = consensus::v4::epoch::restored_next_start(
                storage,
                &block,
                &chain_id,
                plan.genesis_identity,
            )
            .map_err(inconsistent)?;
            let derived = consensus::qc::validator_set_hash(&next.committee);
            if qc.next_validator_set_hash != derived {
                return Err(inconsistent(format!(
                    "QC({}) binds next committee {:?}, the restored state gives {derived}",
                    cp.height, qc.next_validator_set_hash
                )));
            }
            Some(next)
        } else {
            None
        };
        let record = bootstrap_record(storage, tree, plan, &block, &qc, next.as_ref())?;
        storage.write_batch(record).map_err(|e| e.to_string())?;
        return Ok(Restored {
            height: cp.height,
            leaves,
            restarts,
        });
    }
}

/// G4 S6: the answer to a chunk or value-part request a server cannot take
/// now (its quota or its serving slots are spent): "busy", which a client
/// waits out without losing its place. Constant size, reads no storage.
/// `None` for any other request, which is simply refused.
pub fn busy_reply(wire: &str) -> Option<String> {
    if wire.starts_with(CHUNK_REQ) {
        let busy = ChunkResponse {
            error: Some(BUSY.into()),
            ..Default::default()
        };
        return Some(format!(
            "{CHUNK_RESP}{}",
            serde_json::to_string(&busy).ok()?
        ));
    }
    if wire.starts_with(VALUE_REQ) {
        let busy = ValueResponse {
            error: Some(BUSY.into()),
            ..Default::default()
        };
        return Some(format!(
            "{VALUE_RESP}{}",
            serde_json::to_string(&busy).ok()?
        ));
    }
    None
}

/// G4 S6: `restore_state` over the network task's sessions. Peer `i` is
/// dialled at `addrs[i]` (a multiaddr) on first use and again after a
/// failed request; each request runs on its own stream of the session, so
/// a timed-out request cannot poison the next.
pub async fn restore_over_sessions(
    storage: &Arc<StateDB>,
    plan: &RestorePlan<'_>,
    client: &network::SessionClient,
    addrs: &[String],
) -> Result<Restored, String> {
    const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
    let known: Arc<tokio::sync::Mutex<HashMap<usize, String>>> = Arc::default();
    let timeout = plan.patience.request_timeout;
    restore_state(storage, plan, addrs.len(), |peer, msg| {
        let known = Arc::clone(&known);
        let client = client.clone();
        let addr = addrs[peer].clone();
        async move {
            let cached = known.lock().await.get(&peer).cloned();
            let id = match cached {
                Some(id) => id,
                None => {
                    let id = client.connect(&addr, DIAL_TIMEOUT).await?;
                    known.lock().await.insert(peer, id.clone());
                    id
                }
            };
            match client.ask(&id, &msg, timeout).await {
                Ok(reply) => Ok(reply),
                Err(e) => {
                    known.lock().await.remove(&peer);
                    Err(format!("{addr}: {e}"))
                }
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests;
