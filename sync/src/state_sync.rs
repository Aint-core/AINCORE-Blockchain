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
/// so no one client takes more than its share. B131: a kept client is the
/// key its session authenticated (G4 S6); anyone else is its network group
/// (`net_group`), so one host's many keys share one client's budget, and
/// `STATE_SERVE_IN_FLIGHT_KEPT` of the slots are theirs alone, so outsiders
/// cannot keep their restores answered "busy". B178: the node keeps its
/// reserved peers (`node::sessions::snapshot_client`); members were kept
/// too, but a node whose key a committee records never restores (SN-6).
pub const STATE_SERVE_IN_FLIGHT: usize = 4;
/// B131: in-flight slots only kept clients take (a choice).
pub const STATE_SERVE_IN_FLIGHT_KEPT: usize = 1;
pub const STATE_SERVE_IN_FLIGHT_PER_CLIENT: usize = 1;
pub const STATE_SERVE_UNITS_PER_SEC: f64 = 8_000.0;
/// B145: of those, the units only kept clients draw on (a choice: a
/// quarter), so a kept client's value part (`PART_UNITS` at once) is
/// admitted within a second however hard outsiders pull: one shared bucket,
/// charged after the fact, was drained into debt by five outsider groups.
pub const STATE_SERVE_UNITS_PER_SEC_KEPT: f64 = STATE_SERVE_UNITS_PER_SEC / 4.0;
/// B159: the most of the kept units one request takes, granted and charged
/// after the fact (a choice: a quarter, above a value part's `PART_UNITS`):
/// a kept client's own rate equals the kept rate, so one member pulling at
/// it held the kept units in debt and another's value part was busy.
pub const STATE_SERVE_KEPT_PER_REQUEST: f64 = STATE_SERVE_UNITS_PER_SEC_KEPT / 4.0;
/// B145: the units everyone draws on.
pub const STATE_SERVE_UNITS_PER_SEC_SHARED: f64 =
    STATE_SERVE_UNITS_PER_SEC - STATE_SERVE_UNITS_PER_SEC_KEPT;
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
    /// B397: the block, when no answer can hold it: its header and proposer's
    /// signature, its body fetched in shards (`SYNC_SHARD`). `None` from
    /// older servers.
    #[serde(default)]
    pub oversized: Option<crate::OversizedBlock>,
    /// B418: `BUSY` when the server cannot take the request now (its
    /// snapshot budget or serving slots are spent), which the client waits
    /// out within its deadline. `None` from older servers.
    #[serde(default)]
    pub error: Option<String>,
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

pub(crate) const BUSY: &str = "busy";
const NOT_SERVED: &str = "snapshots not served here";
/// The units a value part costs: a request and its bytes.
pub(crate) const PART_UNITS: usize = 1 + VALUE_PART_BYTES / UNIT_BYTES as usize;
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
    pub(crate) fn get(&mut self, version: u64, key: &str) -> Option<Arc<Vec<u8>>> {
        let at = self
            .entries
            .iter()
            .position(|(v, k, _)| *v == version && k == key)?;
        let entry = self.entries.remove(at);
        let value = Arc::clone(&entry.2);
        self.entries.push(entry);
        Some(value)
    }

    pub(crate) fn put(&mut self, version: u64, key: &str, value: Arc<Vec<u8>>) {
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
    /// The shared units (`STATE_SERVE_UNITS_PER_SEC_SHARED`) and every slot
    /// in flight.
    global: Bucket,
    /// B145: kept clients' own units.
    kept: Bucket,
    per_client: HashMap<String, Bucket>,
}

/// Snapshot serving's budget: slots in flight and cost units, globally and
/// per client (see `STATE_SERVE_IN_FLIGHT`). A burst is one second's worth. Bytes read are charged
/// after the fact and may leave a bucket in debt, which later requests wait
/// out.
pub struct StateBudget {
    buckets: Mutex<Buckets>,
}

impl Default for StateBudget {
    fn default() -> Self {
        Self {
            buckets: Mutex::new(Buckets {
                global: Bucket::full(STATE_SERVE_UNITS_PER_SEC_SHARED),
                kept: Bucket::full(STATE_SERVE_UNITS_PER_SEC_KEPT),
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
    /// B145: drawn on the kept units, where its charges go too.
    from_kept: bool,
}

impl StateBudget {
    /// Plain counters: recovering from a poisoned lock is safe.
    fn lock(&self) -> MutexGuard<'_, Buckets> {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Let a request from `client` in (`None`: in process, global limits
    /// only), with up to `want` units both buckets hold. `None` when busy.
    /// `kept`: a kept client (B178: a reserved peer), which may take the
    /// kept slots.
    pub fn admit(&self, client: Option<&str>, want: usize, kept: bool) -> Option<Admission<'_>> {
        self.admit_at_least(client, want, 1, kept)
    }

    /// `admit`, only when both buckets hold all `units`.
    pub fn admit_all(
        &self,
        client: Option<&str>,
        units: usize,
        kept: bool,
    ) -> Option<Admission<'_>> {
        self.admit_at_least(client, units, units, kept)
    }

    fn admit_at_least(
        &self,
        client: Option<&str>,
        want: usize,
        least: usize,
        kept: bool,
    ) -> Option<Admission<'_>> {
        let mut st = self.lock();
        let now = Instant::now();
        st.global.refill(STATE_SERVE_UNITS_PER_SEC_SHARED, now);
        st.kept.refill(STATE_SERVE_UNITS_PER_SEC_KEPT, now);
        let slots = if kept {
            STATE_SERVE_IN_FLIGHT
        } else {
            STATE_SERVE_IN_FLIGHT - STATE_SERVE_IN_FLIGHT_KEPT
        };
        if st.global.in_flight >= slots {
            return None;
        }
        // B145: a kept client draws on whichever of its two
        // pools holds more; anyone else on the shared one only.
        let from_kept = kept && st.kept.tokens > st.global.tokens;
        let mut cap = if from_kept {
            st.kept.tokens.min(STATE_SERVE_KEPT_PER_REQUEST)
        } else {
            st.global.tokens
        };
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
        if from_kept {
            st.kept.tokens -= granted;
        } else {
            st.global.tokens -= granted;
        }
        st.global.in_flight += 1;
        if let Some(bucket) = client.and_then(|c| st.per_client.get_mut(c)) {
            bucket.tokens -= granted;
            bucket.in_flight += 1;
        }
        Some(Admission {
            budget: self,
            client: client.map(str::to_string),
            granted: granted as usize,
            from_kept,
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
    pub(crate) fn charge(&self, bytes: u64) {
        let units = (bytes.div_ceil(UNIT_BYTES) as f64).min(STATE_SERVE_UNITS_PER_SEC_PER_CLIENT);
        let mut st = self.budget.lock();
        if self.from_kept {
            // B159: the rest of it falls on the client's own bucket.
            st.kept.tokens -= units.min(STATE_SERVE_KEPT_PER_REQUEST);
        } else {
            st.global.tokens -= units;
        }
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
        if self.from_kept {
            st.kept.tokens = (st.kept.tokens + units).min(STATE_SERVE_UNITS_PER_SEC_KEPT);
        } else {
            st.global.tokens = (st.global.tokens + units).min(STATE_SERVE_UNITS_PER_SEC_SHARED);
        }
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
    /// `serve_state_anchor_as` for an in-process caller.
    pub fn handle_state_anchor(&self, req: AnchorRequest) -> AnchorResponse {
        self.serve_state_anchor_as(req, None, false)
    }

    /// Serve the block and QC at a height, straight from storage, to `peer`.
    /// B299: answered only by a node that serves snapshots, for a version
    /// it retains (what a restore anchors on), and a block a batch could not
    /// hold is not parsed for it. Every node read, parsed and re-serialized
    /// any height's block for anyone, a missed instance of B275's class.
    /// B324: a block known to be served in parts is not read, and any other
    /// read is admitted on the snapshot budget and charged its bytes (it read
    /// a whole block, up to 512 MiB, for about one token); one found too
    /// large for a batch is known from then on.
    /// B397: such a block is named with its QC (`AnchorResponse::oversized`),
    /// and its body served in shards. It was answered with nothing, so no
    /// node could restore at a checkpoint whose block was over a batch.
    pub fn serve_state_anchor_as(
        &self,
        req: AnchorRequest,
        peer: Option<&str>,
        kept: bool,
    ) -> AnchorResponse {
        if !self.serves_snapshots || self.state_servable(req.height).is_err() {
            return AnchorResponse::default();
        }
        // B470: known only while this node may still hold it.
        let known = self.known_oversized(req.height, true);
        // A block known to be parted is not read: only its QC is.
        let units = if known.is_some() { 1 } else { PART_UNITS };
        // B418: a refusal for budget or slots is busy, not an empty answer
        // (which the client counts against `max_failures`, ~4.5 minutes).
        let Some(admission) = self.state_budget.admit_all(peer, units, kept) else {
            return AnchorResponse {
                error: Some(BUSY.into()),
                ..Default::default()
            };
        };
        blocking(|| {
            let read = |key: String| self.storage.get(&key).ok().flatten();
            let qc = read(format!("consensus:qc:{}", req.height));
            admission.charge(qc.as_ref().map_or(0, |json| json.len() as u64));
            let quorum_certificate = qc.and_then(|json| serde_json::from_str(&json).ok());
            if let Some(big) = known {
                return AnchorResponse {
                    block: None,
                    quorum_certificate,
                    oversized: Some(big),
                    error: None,
                };
            }
            let block = read(format!("block_{}", req.height));
            admission.charge(block.as_ref().map_or(0, |json| json.len() as u64));
            let (block, oversized) = match block {
                Some(json) if json.len() > self.batch_bytes => {
                    (None, self.learn_oversized(req.height, json))
                }
                json => (json.and_then(|json| serde_json::from_str(&json).ok()), None),
            };
            AnchorResponse {
                block,
                quorum_certificate,
                oversized,
                error: None,
            }
        })
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

    /// `serve_state_chunk` for a client outside the kept slots.
    pub fn serve_state_chunk(&self, req: ChunkRequest, peer: Option<&str>) -> ChunkResponse {
        self.serve_state_chunk_as(req, peer, false)
    }

    /// Serve one restore chunk (SN-2) of a version this node retains, to
    /// `peer`, within the protocol's limits (`ChunkBudget`): the leaves are
    /// read once, up to the first that does not fit. Charged a unit per leaf
    /// served and per `UNIT_BYTES` read (at most one second's worth), under
    /// the global and the client's budget; the reads off the shared workers.
    /// B471: no more bytes are read than the grant pays for, but one leaf.
    /// `kept`: a kept client (B131, B178: a reserved peer).
    pub fn serve_state_chunk_as(
        &self,
        req: ChunkRequest,
        peer: Option<&str>,
        kept: bool,
    ) -> ChunkResponse {
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
            .admit(peer, req.max.clamp(1, MAX_CHUNK_ENTRIES), kept)
        else {
            return refuse(BUSY);
        };
        blocking(|| {
            let mut budget = ChunkBudget::new(state_commit::MAX_RANGE_PROOF_BYTES);
            let (mut read, mut refused) = (0u64, false);
            // B471: the bytes the grant pays for, at `UNIT_BYTES` a unit.
            let readable = (admission.granted as u64).saturating_mul(UNIT_BYTES);
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
                    // B471: the chunk ends before a leaf whose value takes
                    // the bytes read past what the grant pays for (the first
                    // leaf is always taken). Each value is read whole, a
                    // parted one only measured, and a read is charged at
                    // most one client-second (`Admission::charge`), so one
                    // chunk read up to 512 MiB and one more leaf for 8 MiB's
                    // charge: about 64 times the client's share of the disk.
                    if !entries.is_empty() && read > readable {
                        return false;
                    }
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

    /// `serve_state_value` for a client outside the kept slots.
    pub fn serve_state_value(&self, req: ValueRequest, peer: Option<&str>) -> ValueResponse {
        self.serve_state_value_as(req, peer, false)
    }

    /// Serve `VALUE_PART_BYTES` of one leaf's value from `offset` to
    /// `peer`, for a value too large to travel inline. A part is let in only
    /// when its whole cost fits; reading a value that is not cached costs at
    /// most one more second's worth. `kept`: a kept client (a reserved peer).
    pub fn serve_state_value_as(
        &self,
        req: ValueRequest,
        peer: Option<&str>,
        kept: bool,
    ) -> ValueResponse {
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
        let Some(admission) = self.state_budget.admit_all(peer, PART_UNITS, kept) else {
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
    /// answering: this many bytes a second, after `request_timeout` (B463:
    /// of the bytes its turn brought, over the whole turn, `Pace`).
    pub min_bytes_per_sec: u64,
    /// A turn that takes longer than this must deliver at least
    /// `MIN_TURN_UNITS_PER_SEC`, or its peer sits out turns: a peer that
    /// trickles valid chunks, or stalls before saying busy, loses its turns.
    /// B463: and owes its time past what it delivered, a turn sat out for
    /// each `slow_turn` of it (`PeerSet`).
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
/// B395: a restore is a guard loss (G1 RC-3): `consensus:guard_origin` and
/// the resume point go, so the next boot abstains from a fresh resume point
/// until an epoch that begins after it. The origin stayed while the V4
/// producer guards (`consensus:vproposed*`, B282) went, so a node restored
/// under a validator key the restored state does not record (SN-6 cannot
/// see it) booted with continuous guards and none of its proposals. Those
/// guards now stay, like the attestation and QC signing guards.
fn cleared_by_restore(key: &[u8]) -> bool {
    match classify(key) {
        Some(KeyClass::State | KeyClass::Chain | KeyClass::Tree | KeyClass::Dead) => true,
        Some(KeyClass::Local) => {
            !(key.starts_with(b"consensus:qc_signing:")
                || key.starts_with(b"consensus:vattest:")
                || key.starts_with(b"consensus:vproposed:")
                || key.starts_with(b"consensus:vproposed_high:")
                || key == b"latest_proposed_round")
        }
        Some(KeyClass::Node) => {
            key == b"consensus:guard_origin"
                || key == consensus::v4::epoch::GUARD_RESUME_KEY.as_bytes()
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

#[cfg(test)]
thread_local! {
    /// B398 witness support: the bodies `check_anchor` checked against
    /// their header (a Reed-Solomon extension each) on this thread.
    static COMMITMENT_CHECKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The header and QC match the checkpoint, and each other, except for the
/// anchor, which the body carries.
fn check_anchor_header(
    cp: &Checkpoint,
    h: &blockchain::BlockHeader,
    qc: &QuorumCertificate,
) -> Result<(), String> {
    if h.height != cp.height
        || !h.hash.eq_ignore_ascii_case(&cp.block_hash)
        || !h.state_root.eq_ignore_ascii_case(&cp.state_root)
    {
        return Err("the block is not the checkpoint's".into());
    }
    if qc.block_height != h.height
        || qc.block_hash != h.hash
        || qc.state_root != h.state_root
        || qc.receipts_root != h.receipts_root
        || qc.anchor_round != h.round
    {
        return Err("the QC is not for the checkpoint's block".into());
    }
    Ok(())
}

/// The block and QC match the checkpoint, and each other, and the block is
/// internally whole. The QC's signature and the block's proposer signature
/// are checked after the restore.
/// B398: the cheap comparisons and the anchor binding (G0) first, the body's
/// roots last. Only the DA root covers `anchor_hash`, and it ran first: a
/// peer padding the anchor (and its QC's) cost a whole extension a round
/// (B275's class).
fn check_anchor(cp: &Checkpoint, block: &Block, qc: &QuorumCertificate) -> Result<(), String> {
    check_anchor_header(cp, &block.header, qc)?;
    if qc.anchor_hash != block.anchor_hash {
        return Err("the QC is not for the checkpoint's block".into());
    }
    check_body(block)
}

/// `check_anchor`'s checks of the block alone: its anchor is bound (G0) and
/// its header commits to its body.
/// B401: a parted block's body runs them once, when its last shard proves,
/// not once for each answer that names it.
fn check_body(block: &Block) -> Result<(), String> {
    if !block.anchor_is_bound() {
        return Err(format!(
            "the block's anchor {} is not its last committed vertex",
            block.anchor_hash.chars().take(80).collect::<String>()
        ));
    }
    #[cfg(test)]
    COMMITMENT_CHECKS.with(|n| n.set(n.get() + 1));
    block
        .check_commitments()
        .map_err(|e| format!("the block's header does not commit to its body: {e}"))
}

/// A candidate anchor: the checkpoint's block as one answer signed it, and
/// that answer's QC. A pair stays together: the block stored is the one
/// whose own QC verifies.
/// B401: every pair's header and body are the checkpoint's (its hash pins
/// the one, the header's roots the other), so the pairs share one copy
/// (`body`), each with its own signature beside it, and the whole block is
/// built only for the pair that verifies. Each pair held a whole copy, up to
/// 512 MiB of text for a parted block, for the whole download: a copy for
/// every answering peer, and one more.
#[derive(Debug, Clone)]
struct Pair {
    /// The checkpoint's block. Its own signature is not this pair's.
    body: Arc<Block>,
    proposer_signature: String,
    proposer_signer: String,
    qc: QuorumCertificate,
}

impl Pair {
    /// What this pair's signature covers (the header's hash), with no body.
    fn signed_header(&self) -> Block {
        Block {
            header: self.body.header.clone(),
            transactions: Vec::new(),
            committed_vertices: Vec::new(),
            committed_authors: Vec::new(),
            anchor_hash: String::new(),
            proposer_signature: self.proposer_signature.clone(),
            proposer_signer: self.proposer_signer.clone(),
            slash_evidence: Vec::new(),
        }
    }

    /// The whole block under this pair's signature, and its QC. The body is
    /// taken over when nothing else holds it, and copied otherwise.
    fn into_block(self) -> (Block, QuorumCertificate) {
        let body = Arc::try_unwrap(self.body).unwrap_or_else(|body| Block::clone(&body));
        let block = Block {
            proposer_signature: self.proposer_signature,
            proposer_signer: self.proposer_signer,
            ..body
        };
        (block, self.qc)
    }
}

/// B401: the anchor block's body for the whole restore: the one shard fetch
/// every peer's turn extends, round after round (a proved shard is valid
/// whoever served it), then the one copy every pair shares. The fetch was
/// one `fetch_anchor_body` call's own: an ask error, or a busy answer past
/// one request timeout, threw away every shard it had proved.
#[derive(Default)]
struct AnchorBody {
    fetch: Option<crate::ShardFetch>,
    body: Option<Arc<Block>>,
}

impl AnchorBody {
    /// The body every pair shares: the one held, else `block`'s, checked
    /// whole (`check_body`). The fetch's shards go.
    fn share(&mut self, block: Block) -> Arc<Block> {
        self.fetch = None;
        Arc::clone(self.body.get_or_insert_with(|| Arc::new(block)))
    }
}

/// B401: how one peer's turn at the anchor body went.
#[derive(Default)]
struct BodyTurn {
    /// It proved a shard.
    proved: bool,
    /// Its peer was still busy when the turn's time ran out.
    busy: bool,
    /// Why it ended before the body was whole.
    why: Option<String>,
}

/// B397: an anchor block too large for one answer may be fetched: its
/// header hashes to itself (so its DA root is the one the checkpoint's hash
/// pins) and, with its QC, is the checkpoint's.
fn check_named_anchor(
    cp: &Checkpoint,
    big: &crate::OversizedBlock,
    qc: &QuorumCertificate,
) -> Result<(), String> {
    if big.height != cp.height {
        return Err(format!(
            "a parted block #{} named for #{}",
            big.height, cp.height
        ));
    }
    if blockchain::calculate_header_hash(&big.header) != big.header.hash {
        return Err("a parted block's header that does not hash to its hash".into());
    }
    check_anchor_header(cp, &big.header, qc)
}

/// B397: the body of the anchor block `big` names, as its DA data shards
/// from `peer` (`SYNC_SHARD`, the path a parted block takes in sync, B319),
/// each verified under the header's DA root when its last piece arrives.
/// The checkpoint's block hash pins that root, so no other body proves.
/// B401: one turn of the restore's one fetch (`anchor`). A turn that ends
/// short (no answer, a refusal, a peer too slow or still busy, a lie) keeps
/// every shard proved for any peer's next turn, and its peer's unfinished
/// shard unless the peer lied (B387). The body's own checks (`check_body`)
/// run once, when its last shard proves. `Err` only when they fail: no other
/// body proves under the checkpoint, so none can be fetched.
async fn fetch_anchor_body<F, Fut>(
    ask: &mut F,
    peer: usize,
    big: &crate::OversizedBlock,
    patience: &Patience,
    anchor: &mut AnchorBody,
) -> Result<BodyTurn, String>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let fetch = anchor
        .fetch
        .get_or_insert_with(|| crate::ShardFetch::new(big.clone()));
    let mut turn = BodyTurn::default();
    let Some(block) = shard_turn(ask, peer, fetch, patience, &mut turn).await else {
        return Ok(turn);
    };
    let block = block
        .and_then(|block| check_body(&block).map(|()| block))
        .map_err(|e| format!("the checkpoint's block, as its shards prove it: {e}"))?;
    anchor.share(block);
    Ok(turn)
}

/// B401: `peer`'s turn at the shards `fetch` still misses. Busy answers are
/// waited out while pieces keep coming: one per request timeout, and past
/// the first request timeout at `min_bytes_per_sec` of the bytes received
/// (not of the length claimed, which a liar could inflate). `Some` once
/// every data shard is in: the body they make. `None`: the turn ended
/// short, as `turn` says.
async fn shard_turn<F, Fut>(
    ask: &mut F,
    peer: usize,
    fetch: &mut crate::ShardFetch,
    patience: &Patience,
    turn: &mut BodyTurn,
) -> Option<Result<Block, String>>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let budget = crate::parted_body_budget(crate::MAX_PARTED_BLOCK_BYTES);
    let key = peer.to_string();
    let height = fetch.big.height;
    let da_root = fetch.big.header.da_root.clone();
    let started = Instant::now();
    let mut received = 0u64;
    let mut progress = Instant::now();
    let mut busy = 0usize;
    'shards: loop {
        if let Some(block) = fetch.block() {
            return Some(block);
        }
        // B401: this peer's unfinished shard from its last turn (B387), else
        // (B415) a shard no other peer's unfinished one covers (B423: shard 0
        // until a shard proves the length).
        let (index, mut shard, mut claimed) = fetch.turn_shard(&key);
        // Why the turn ends short, and whether the peer's unfinished shard
        // is kept for its next turn (not after a lie).
        let (why, keep): (String, bool) = loop {
            let paced = patience.request_timeout
                + Duration::from_secs(received / patience.min_bytes_per_sec.max(1));
            if progress.elapsed() > patience.request_timeout || started.elapsed() > paced {
                // B401: a peer still busy ends its turn, not the fetch.
                turn.busy = busy > 0;
                let why = if turn.busy {
                    "busy past a request timeout"
                } else {
                    "shard pieces too slow"
                };
                break (why.into(), true);
            }
            let request = match serde_json::to_string(&crate::ShardRequest {
                height,
                index,
                offset: shard.len() as u64,
            }) {
                Ok(request) => request,
                Err(e) => break (e.to_string(), true),
            };
            let answer = match ask(peer, format!("{}{request}", crate::SHARD_REQ)).await {
                Ok(answer) => answer,
                Err(e) => break (e, true),
            };
            let Some(piece) = answer
                .strip_prefix(crate::SHARD_RESP)
                .and_then(|json| serde_json::from_str::<crate::ShardResponse>(json).ok())
            else {
                break ("a garbled shard piece".into(), false);
            };
            match piece.error.as_deref() {
                Some(BUSY) => {
                    busy += 1;
                    tokio::time::sleep(patience.backoff(busy, 1).min(PART_BUSY_WAIT)).await;
                    continue;
                }
                Some(e) => break (format!("a shard refused: {e}"), true),
                None => {}
            }
            busy = 0;
            progress = Instant::now();
            // As `fetch_sharded_block` takes them: a piece of any length up
            // to its shard's end, of a body no larger than a fetch holds and
            // of the length a verified shard proved.
            let layout = da::Layout::of(piece.body_len);
            let due = layout.shard_size.saturating_sub(shard.len() as u64);
            let data = hex::decode(&piece.data)
                .ok()
                .filter(|d| !d.is_empty() && d.len() as u64 <= due);
            let fits = piece.index == index
                && piece.offset == shard.len() as u64
                && piece.body_len > 0
                && piece.body_len <= budget
                && index < layout.data_shards
                && claimed.is_none_or(|len| len == piece.body_len);
            let (true, Some(data)) = (fits, data) else {
                break (
                    format!(
                        "a piece of shard {} at {} of a {}-byte body, where up to {due} bytes of shard {index} at {} were due",
                        piece.index,
                        piece.offset,
                        piece.body_len,
                        shard.len()
                    ),
                    false,
                );
            };
            claimed = Some(piece.body_len);
            received = received.saturating_add(data.len() as u64);
            shard.extend_from_slice(&data);
            if (shard.len() as u64) < layout.shard_size {
                continue;
            }
            let sample = da::Sample {
                body_len: piece.body_len,
                index,
                shard: hex::encode(&shard),
                proof: piece.proof,
            };
            if let Err(e) = da::verify_sample(&da_root, index, &sample) {
                break (
                    format!(
                        "data shard {index} does not prove under the checkpoint's DA root: {e:?}"
                    ),
                    false,
                );
            }
            fetch.accept(layout, index, shard);
            turn.proved = true;
            continue 'shards;
        };
        if keep {
            fetch.keep_partial(&key, index, shard, claimed);
        }
        turn.why = Some(why);
        return None;
    }
}

/// Every distinct (block, QC) pair the peers hold for the checkpoint, asked
/// again, round after round, until one is found. A pair stays together: the
/// block stored is the one whose own QC verifies.
/// B397: an anchor block too large for one answer comes with its header,
/// proposer's signature and QC; its body is fetched in shards.
/// B401: the body is fetched once for the whole restore and held in
/// `anchor`, which every pair shares. A round whose turns proved a shard, or
/// found a peer still busy (B418: or a peer answering the anchor busy), is
/// waited out within the restore's deadline (counted from `started`), not
/// against `max_failures`: such a turn ended in an error, and its shards were
/// lost with it.
async fn fetch_anchor<F, Fut>(
    cp: &Checkpoint,
    peers: usize,
    ask: &mut F,
    patience: &Patience,
    anchor: &mut AnchorBody,
    started: Instant,
) -> Result<Vec<Pair>, String>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let request =
        serde_json::to_string(&AnchorRequest { height: cp.height }).map_err(|e| e.to_string())?;
    let (mut failures, mut waits) = (0usize, 0usize);
    loop {
        let mut pairs: Vec<Pair> = Vec::new();
        // B401: the answers that name a parted block (peer, signature,
        // signer, QC), a pair each once its body is whole, even when a later
        // peer's turn completes it.
        let mut named: Vec<(usize, String, String, QuorumCertificate)> = Vec::new();
        let (mut proved, mut waited) = (false, false);
        for peer in 0..peers {
            let Ok(reply) = ask(peer, format!("{ANCHOR_REQ}{request}")).await else {
                continue;
            };
            let Some(answer) = reply
                .strip_prefix(ANCHOR_RESP)
                .and_then(|json| serde_json::from_str::<AnchorResponse>(json).ok())
            else {
                continue;
            };
            // B418: a peer busy now is waited out within the deadline, as a
            // busy shard server is (B401): taken for no answer, a server's
            // spent quota ended the restore after `max_failures` rounds.
            if answer.error.as_deref() == Some(BUSY) {
                waited = true;
                continue;
            }
            match (answer.block, answer.oversized, answer.quorum_certificate) {
                (Some(block), _, Some(qc)) => {
                    if let Err(e) = check_anchor(cp, &block, &qc) {
                        // B466: cut, as every refusal of a peer's text.
                        crate::log_line(format!(
                            "⚠️ [STATE_SYNC] peer {peer}: {}",
                            crate::loggable(&e)
                        ));
                        continue;
                    }
                    // B401: its body is the checkpoint's: the one held, if
                    // any, is shared instead.
                    let proposer_signature = block.proposer_signature.clone();
                    let proposer_signer = block.proposer_signer.clone();
                    pairs.push(Pair {
                        body: anchor.share(block),
                        proposer_signature,
                        proposer_signer,
                        qc,
                    });
                }
                (None, Some(big), Some(qc)) => {
                    if let Err(e) = check_named_anchor(cp, &big, &qc) {
                        crate::log_line(format!(
                            "⚠️ [STATE_SYNC] peer {peer}: {}",
                            crate::loggable(&e)
                        ));
                        continue;
                    }
                    if anchor.body.is_none() {
                        let turn =
                            fetch_anchor_body(&mut *ask, peer, &big, patience, anchor).await?;
                        proved |= turn.proved;
                        waited |= turn.proved || turn.busy;
                        // B466: a shard refusal carries the peer's own text.
                        if let Some(why) = turn.why {
                            crate::log_line(format!(
                                "⚠️ [STATE_SYNC] peer {peer}: the anchor block's shards: {}",
                                crate::loggable(&why)
                            ));
                        }
                    }
                    named.push((peer, big.proposer_signature, big.proposer_signer, qc));
                }
                _ => continue,
            }
        }
        if let Some(body) = &anchor.body {
            for (peer, proposer_signature, proposer_signer, qc) in named {
                // The rest of `check_anchor`: the header and QC were checked
                // with the name, the body once, when it was whole.
                if qc.anchor_hash != body.anchor_hash {
                    eprintln!(
                        "⚠️ [STATE_SYNC] peer {peer}: the QC is not for the checkpoint's block"
                    );
                    continue;
                }
                pairs.push(Pair {
                    body: Arc::clone(body),
                    proposer_signature,
                    proposer_signer,
                    qc,
                });
            }
        }
        // B397: past the checks every pair holds the checkpoint's header and
        // body (each root checked under the pinned hash), so a pair is its
        // signature and QC: a block of up to 512 MiB was serialized to
        // compare each answer.
        let mut seen: Vec<String> = Vec::new();
        let mut distinct: Vec<Pair> = Vec::new();
        for pair in pairs {
            let id =
                serde_json::to_string(&(&pair.proposer_signature, &pair.proposer_signer, &pair.qc))
                    .map_err(|e| e.to_string())?;
            if !seen.contains(&id) {
                seen.push(id);
                distinct.push(pair);
            }
        }
        if !distinct.is_empty() {
            return Ok(distinct);
        }
        if proved {
            failures = 0;
        }
        if waited && started.elapsed() <= patience.deadline {
            waits += 1;
            tokio::time::sleep(patience.backoff(waits, 1).min(PART_BUSY_WAIT)).await;
            continue;
        }
        failures += 1;
        if failures >= patience.max_failures.max(1) {
            return Err(format!(
                "no peer holds block {} and its QC as the checkpoint names them",
                cp.height
            ));
        }
        tokio::time::sleep(patience.backoff(failures, 1)).await;
    }
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
/// B395: on V4, C_E past epoch 0 is E's own record, which is no state: a
/// restored state holds none, so only the genesis committee and the active
/// set were seen. The executor's record of C_E (`recorded_committee`) is
/// state, and is read too.
pub fn recorded_validator(storage: &StateDB, key: &str) -> bool {
    let current = storage
        .get("consensus:epoch")
        .ok()
        .flatten()
        .and_then(|e| e.parse::<u64>().ok())
        .unwrap_or(0);
    let v4 = consensus::v4::is_v4_chain(storage);
    let holds = |set: Option<Vec<consensus::qc::ValidatorInfo>>| {
        set.is_some_and(|set| set.iter().any(|v| v.address == key))
    };
    (0..=current).rev().take(64).any(|epoch| {
        let set = consensus::qc_producer::load_validator_set_for_epoch(storage, epoch);
        holds(set) || (v4 && holds(consensus::v4::epoch::recorded_committee(storage, epoch)))
    }) || storage
        .get_active_validators()
        .iter()
        .any(|(address, _)| address == key)
}

/// Whether `signer` may sign the checkpoint's block, by the rule sync checks
/// a block's signer by (`ChainSync::eligible_proposers`): on V4 a member of
/// the checkpoint epoch's committee C_E(h) (G1 DE-7); on V3 a validator of
/// that committee or of the restored active set.
/// B472: on V4 the restored active set was accepted too (up to 1,000 keys,
/// against a committee of at most 256): a pair one of its keys outside C_E
/// signed was stored, and the restored node could never serve its block to
/// a block-syncing client, which refuses that signer.
fn signed_by_a_validator(
    storage: &StateDB,
    committee: &[consensus::qc::ValidatorInfo],
    signer: &str,
) -> bool {
    committee.iter().any(|v| v.address == signer)
        || (!consensus::v4::is_v4_chain(storage)
            && storage
                .get_active_validators()
                .iter()
                .any(|(address, _)| address == signer))
}

/// The first pair whose QC the committee signed under this chain id, and
/// whose block one of that committee's validators signed, under the key the
/// restored state records for it.
fn verified_pair(
    storage: &StateDB,
    chain_id: &str,
    genesis_identity: &str,
    epoch: u64,
    committee: &[consensus::qc::ValidatorInfo],
    pairs: &[Pair],
) -> Result<Pair, String> {
    let mut last_error = String::from("no QC");
    for pair in pairs {
        let (signer, qc) = (&pair.proposer_signer, &pair.qc);
        if !signed_by_a_validator(storage, committee, signer) {
            last_error = format!("block signer {signer} is not a validator");
            continue;
        }
        if qc.epoch != epoch {
            last_error = format!("QC epoch {} is not the restored epoch {epoch}", qc.epoch);
            continue;
        }
        // B345: under the genesis the checkpoint names (boot installs the
        // domain only after the restore).
        if let Err(e) = consensus::qc::verify_qc_under(qc, committee, chain_id, genesis_identity) {
            last_error = format!("{e:?}");
            continue;
        }
        // B401: the signature covers the header's hash, checked with no
        // body: the whole block is built for the pair that verifies only.
        match ChainSync::verify_proposer_signature_in(storage, &pair.signed_header()) {
            Ok(()) => return Ok(pair.clone()),
            Err(e) => last_error = e,
        }
    }
    // B466: the last refusal echoes what a peer sent (its signer, its QC's
    // fields), and boot prints it.
    Err(format!(
        "no QC for the checkpoint verifies under the restored committee: {}",
        crate::loggable(&last_error)
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

/// B395: what the restore marker keeps of a restore's first attempt, for
/// every attempt that resumes it: the key it ran under, and whether it
/// replaced a chain (whose rows its first clear deleted).
struct FirstAttempt {
    signer: Option<String>,
    replaced: bool,
}

/// Refuse to overwrite a chain unless asked (`replace_existing`), and a
/// replace of a chain where this node is a validator (SN-6), before anything
/// is cleared. A fresh datadir, or one an interrupted restore marked, is
/// always fine.
/// B395: a resume of a restore that replaced a chain runs under the key its
/// first attempt ran under. That chain's rows were cleared, so SN-6 had
/// nothing left to check another key against: a resume under a validator
/// key after a first attempt under a new key restored it.
fn check_datadir(storage: &StateDB, plan: &RestorePlan<'_>) -> Result<FirstAttempt, String> {
    let marker = storage.get(RESTORE_MARKER).map_err(|e| e.to_string())?;
    let holds_chain = storage
        .get("genesis_initialized")
        .map_err(|e| e.to_string())?
        .is_some()
        || storage
            .get("latest_height")
            .map_err(|e| e.to_string())?
            .is_some();
    if holds_chain && marker.is_none() && !plan.replace_existing {
        return Err(
            "this datadir already holds a chain; restoring replaces it, so it must be asked for"
                .into(),
        );
    }
    let first = match marker {
        None => FirstAttempt {
            signer: plan.local_signer.map(str::to_string),
            replaced: holds_chain,
        },
        // A marker that does not say (an older node's) may have replaced one.
        Some(raw) => {
            let marker: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
            FirstAttempt {
                signer: marker["signer"].as_str().map(str::to_string),
                replaced: marker["replaced"].as_bool().unwrap_or(true),
            }
        }
    };
    if first.replaced && first.signer.as_deref() != plan.local_signer {
        return Err(format!(
            "this restore began under key {} and cleared the chain this datadir held, so \
             whether key {} is a validator of that chain can no longer be told (SN-6). Resume \
             it under key {0}, or restore onto a new datadir",
            first.signer.as_deref().unwrap_or("(none)"),
            plan.local_signer.unwrap_or("(none)")
        ));
    }
    if let Some(me) = plan.local_signer {
        if recorded_validator(storage, me) {
            return Err(sn6_refusal(me));
        }
    }
    Ok(first)
}

/// B396: a V4 checkpoint past epoch 0 must be an epoch boundary (see
/// `restored_committee`), told from this node's own genesis before anything
/// is asked or cleared. It was refused only after the whole download, and a
/// replace restore had cleared the old chain by then.
fn check_checkpoint_epoch(plan: &RestorePlan<'_>) -> Result<(), String> {
    if plan
        .genesis
        .get(consensus::v4::VERTEX_FORMAT_KEY)
        .map(String::as_str)
        != Some("4")
    {
        return Ok(());
    }
    let interval = plan
        .genesis
        .get(consensus::v4::epoch::EPOCH_INTERVAL_KEY)
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
        .ok_or("this node's V4 genesis has no epoch interval")?;
    let height = plan.checkpoint.height;
    if consensus::v4::epoch::epoch_of_height(height, interval) > 0
        && !height.is_multiple_of(interval)
    {
        return Err(format!(
            "a V4 checkpoint past epoch 0 must be an epoch boundary (every {interval} blocks), not {height}"
        ));
    }
    Ok(())
}

/// Whether a turn that took `took` and delivered `units` was too slow: past
/// `slow_turn`, under `MIN_TURN_UNITS_PER_SEC`. A short turn never is, so a
/// small last chunk costs nothing.
fn too_slow(took: Duration, units: f64, slow_turn: Duration) -> bool {
    took > slow_turn && units / took.as_secs_f64() < MIN_TURN_UNITS_PER_SEC
}

/// The longest a struck peer sits out for its failures in a row, in turns
/// (B463: its debt may sit out longer).
const MAX_SIT_OUT: u32 = 256;

/// Picks peers for the next request, round robin. A peer that fails to
/// deliver sits out turns, twice as many at each failure in a row, so a
/// slow, silent or stalling peer loses its turns to the ones that deliver
/// while one that stumbled once is soon back. A peer caught lying is shut
/// out for good.
/// B463: and a peer owes the time its turns held the restore beyond what
/// they delivered (`charge`): it sits out a turn for each `slow_turn` of
/// that debt, and a delivery forgives it only once the debt is paid, at
/// `MIN_TURN_UNITS_PER_SEC`. Any delivery forgave a peer, so one that
/// alternated an 18-minute failed turn with a quick one-leaf chunk sat out
/// one turn a cycle and slowed a restore up to about 360 times, past its
/// deadline for a state over about 475,000 leaves.
struct PeerSet {
    excluded: Vec<bool>,
    penalty: Vec<u32>,
    sit_out: Vec<u32>,
    /// B463: each peer's debt, in seconds.
    owed: Vec<f64>,
    /// `Patience::slow_turn`: a turn within it adds no debt, and a debt
    /// sits out a turn for each of it.
    slow_turn: Duration,
    next: usize,
}

impl PeerSet {
    fn new(peers: usize, slow_turn: Duration) -> Self {
        Self {
            excluded: vec![false; peers],
            penalty: vec![0; peers],
            sit_out: vec![0; peers],
            owed: vec![0.0; peers],
            slow_turn,
            next: 0,
        }
    }

    /// B463: what `peer`'s turn cost the restore: `took`, less what its
    /// verified `units` pay for at `MIN_TURN_UNITS_PER_SEC`, added to its
    /// debt (never below none). A turn within `slow_turn` adds nothing, as
    /// `too_slow` never judges one, but pays.
    fn charge(&mut self, peer: usize, took: Duration, units: f64) {
        let mut cost = took.as_secs_f64() - units / MIN_TURN_UNITS_PER_SEC;
        if took <= self.slow_turn {
            cost = cost.min(0.0);
        }
        self.owed[peer] = (self.owed[peer] + cost).max(0.0);
    }

    /// B463: the turns `peer`'s debt sits out: one for each `slow_turn` of
    /// it, the longest an honest turn takes unjudged, so the time it held
    /// the restore goes to the others' turns.
    fn debt_turns(&self, peer: usize) -> u32 {
        (self.owed[peer] / self.slow_turn.as_secs_f64().max(1e-3)).ceil() as u32
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

    /// A turn that delivered: its peer is forgiven, once (B463) its debt is
    /// paid; until then it keeps its penalty and sits out its debt.
    fn delivered(&mut self, peer: usize) {
        if self.owed[peer] > 0.0 {
            self.sit_out[peer] = self.penalty[peer].max(self.debt_turns(peer));
        } else {
            self.penalty[peer] = 0;
            self.sit_out[peer] = 0;
        }
    }

    fn strike(&mut self, peer: usize) {
        self.penalty[peer] = self.penalty[peer].saturating_mul(2).clamp(1, MAX_SIT_OUT);
        self.sit_out[peer] = self.penalty[peer].max(self.debt_turns(peer));
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

/// B463: a chunk turn's pace. Past the first request timeout the value
/// bytes the turn brought must keep up with `min_bytes_per_sec`, counted
/// over the whole turn from its chunk's ask (as B401 paces a shard turn).
/// Each value's parts were paced by the length its chunk claimed, each from
/// its own start: one claim of 256 MiB held a turn about 18 minutes for a
/// junk part every request timeout, and a chunk of 2,047 values claimed one
/// part long held it about 33 hours.
struct Pace {
    started: Instant,
    received: u64,
}

impl Pace {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            received: 0,
        }
    }

    /// Whether the turn has run past what the bytes it brought pay for.
    fn spent(&self, patience: &Patience) -> bool {
        let paid = Duration::from_secs(self.received / patience.min_bytes_per_sec.max(1));
        self.started.elapsed() > patience.request_timeout.saturating_add(paid)
    }
}

/// One value, in parts, from `peer`. Every part but the last must be exactly
/// `VALUE_PART_BYTES`, and the turn's parts must keep its `pace`.
async fn ask_parts<F, Fut>(
    ask: &mut F,
    peer: usize,
    version: u64,
    key: &str,
    len: u64,
    patience: &Patience,
    pace: &mut Pace,
) -> Result<Vec<u8>, Reply>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let mut value = Vec::with_capacity(len as usize);
    let mut busy = 0usize;
    // A busy server is waited for, with no part lost, as long as parts keep
    // coming: one per request timeout at least, at the minimum rate overall
    // (B463: of the bytes received, never of the length claimed).
    let mut progress = Instant::now();
    while (value.len() as u64) < len {
        if pace.spent(patience) || progress.elapsed() > patience.request_timeout {
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
                pace.received = pace.received.saturating_add(expected);
                value.extend_from_slice(&data);
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
    // B463: the whole turn's pace, every value's parts together.
    let mut pace = Pace::new();
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
        match ask_parts(ask, peer, version, &key, len, patience, &mut pace).await {
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
    check_checkpoint_epoch(plan)?;
    let first = check_datadir(storage, plan)?;
    let cp = plan.checkpoint;
    let root = hex32(&cp.state_root).ok_or("malformed checkpoint root")?;
    // B397: the anchor block's body, when it is fetched in shards.
    // B401: one fetch and one body for the whole restore, which every pair
    // shares.
    let mut anchor_body = AnchorBody::default();
    let pairs = fetch_anchor(cp, peers, &mut ask, patience, &mut anchor_body, started).await?;

    // B395: with the first attempt's key, and whether it replaced a chain.
    let marker = serde_json::json!({
        "height": cp.height,
        "state_root": cp.state_root,
        "signer": first.signer,
        "replaced": first.replaced,
    });
    storage
        .put(RESTORE_MARKER, &marker.to_string())
        .map_err(|e| e.to_string())?;

    let mut set = PeerSet::new(peers, patience.slow_turn);
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
                        // B463: and its peer's debt, which it pays toward.
                        set.charge(peer, took, units);
                        if too_slow(took, units, patience.slow_turn) {
                            set.strike(peer);
                            eprintln!(
                                "⚠️ [STATE_SYNC] peer {peer} delivered too slowly ({took:?}), \
                                 sits out {} turns",
                                set.sit_out[peer]
                            );
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
                        crate::log_line(format!(
                            "⚠️ [STATE_SYNC] peer {peer} sent a refused chunk, shut out: {}",
                            crate::loggable(&e.to_string())
                        ));
                        set.exclude(peer);
                        restarts += 1;
                        continue 'restore;
                    }
                },
                Reply::Done => break peer,
                Reply::Busy => {
                    // An honest server says busy at once, before reading
                    // anything; one that takes its time to say it stalls.
                    // B463: and owes that time.
                    set.charge(peer, took, 0.0);
                    if took >= patience.slow_turn {
                        set.strike(peer);
                        eprintln!(
                            "⚠️ [STATE_SYNC] peer {peer} said busy after {took:?}, sits out {} \
                             turns",
                            set.sit_out[peer]
                        );
                    }
                    busy += 1;
                    tokio::time::sleep(patience.backoff(busy, set.live())).await;
                }
                Reply::Unanswered(why) => {
                    // B463: it owes the time it held the restore, and is named:
                    // no failed turn was logged, so an operator could not
                    // tell which listed peer stalled the restore.
                    set.charge(peer, took, 0.0);
                    set.strike(peer);
                    crate::log_line(format!(
                        "⚠️ [STATE_SYNC] peer {peer} gave no answer after {took:?} ({}), sits \
                         out {} turns",
                        crate::loggable(&why),
                        set.sit_out[peer]
                    ));
                    failures += 1;
                    if failures >= patience.max_failures {
                        // B466: boot prints it, and a peer chose its text.
                        return Err(format!(
                            "no peer serves the checkpoint's state (last: {})",
                            crate::loggable(&why)
                        ));
                    }
                    tokio::time::sleep(patience.backoff(failures, set.live())).await;
                }
                Reply::Lied(why) => {
                    crate::log_line(format!(
                        "⚠️ [STATE_SYNC] peer {peer} broke the protocol, shut out: {}",
                        crate::loggable(&why)
                    ));
                    set.exclude(peer);
                }
            }
        };
        let tree = match restore.finish() {
            Ok(batch) => batch,
            Err(e) => {
                crate::log_line(format!(
                    "⚠️ [STATE_SYNC] peer {ended_by} ended the stream early, shut out: {}",
                    crate::loggable(&e.to_string())
                ));
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
        let pair = loop {
            match verified_pair(
                storage,
                &chain_id,
                plan.genesis_identity,
                epoch,
                &committee,
                &candidates,
            ) {
                Ok(pair) => break pair,
                Err(e) if started.elapsed() > patience.deadline => {
                    return Err(inconsistent(e));
                }
                Err(_) => {
                    tokio::time::sleep(patience.backoff(asked as usize, peers)).await;
                    asked = asked.saturating_add(1);
                    // Rounds that found no pair count against the deadline
                    // only: giving up here would throw the download away.
                    candidates =
                        fetch_anchor(cp, peers, &mut ask, patience, &mut anchor_body, started)
                            .await
                            .unwrap_or_default();
                }
            }
        };
        // B401: the whole block, for the pair that verified only, once the
        // other pairs and the held body have let go of the body: it is taken
        // over, not copied.
        drop(candidates);
        drop(anchor_body);
        let (block, qc) = pair.into_block();
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
    // B418: a checkpoint's anchor too: it was dropped unanswered, so a
    // restore ended after `max_failures` rounds of a server's spent quota.
    if wire.starts_with(ANCHOR_REQ) {
        let busy = AnchorResponse {
            error: Some(BUSY.into()),
            ..Default::default()
        };
        return Some(format!(
            "{ANCHOR_RESP}{}",
            serde_json::to_string(&busy).ok()?
        ));
    }
    // B275: a block's shard piece too (B319; it was dropped, so a client's
    // next piece was lost whenever the server's answer budget was spent,
    // which each piece spends: no block over a batch could be fetched).
    if wire.starts_with(crate::SHARD_REQ) {
        let busy = crate::ShardResponse {
            error: Some(BUSY.into()),
            ..Default::default()
        };
        return Some(format!(
            "{}{}",
            crate::SHARD_RESP,
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
