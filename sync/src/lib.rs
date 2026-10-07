use blockchain::Block;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use storage::StateDB;

/// G3 S6: snapshot restore from peers (SN-2).
pub mod state_sync;

/// `SYNC_REQ`: the blocks from `from_height` on. The requester is the
/// session that sent it (G4); the request names no one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub from_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
    #[serde(default)]
    pub finality: Option<FinalityArtifact>,
    /// Set when the requested range is below the seed's prune horizon (the
    /// requested blocks no longer exist). Carries the lowest block height the
    /// seed can still serve, so the requester knows block-replay can't bridge
    /// the gap and it must bootstrap from a state snapshot instead of looping on
    /// empty responses. `None` from older peers (serde default).
    #[serde(default)]
    pub prune_horizon: Option<u64>,
    /// G1 IM-4: the QC of each served block that has one. A V4 chain imports a
    /// block only together with its QC (IM-1). Empty from older peers.
    #[serde(default)]
    pub qcs: Vec<consensus::qc::QuorumCertificate>,
    /// B264: the next block, when no batch can hold it (its encoded bytes
    /// pass `SYNC_RESP_BLOCK_BYTES`: the vertices a block commits are not
    /// bounded). The answer then carries no block; this one travels in
    /// `SYNC_PART`s, and its QC, when held, is in `qcs`. `None` from older
    /// peers.
    #[serde(default)]
    pub oversized: Option<OversizedBlock>,
}

/// B264: a block too large for a batch, as a `SYNC_RESP` names it. B275:
/// with its header, which the client checks against the block's QC before
/// it asks for any part (any block's height was enough to start a fetch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OversizedBlock {
    pub height: u64,
    /// Its encoded bytes.
    pub len: u64,
    pub header: blockchain::BlockHeader,
}

/// `SYNC_PART` (B264): `BLOCK_PART_BYTES` of the stored block at `height`,
/// from `offset`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPartRequest {
    pub height: u64,
    pub offset: u64,
}

/// `SYNC_PART_RESP` (B264): one part, or why none was served.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockPartResponse {
    /// B275: the part, the block's stored text from `offset`, cut at a
    /// character boundary (hex doubled it, and the server's answer budget,
    /// a token each 64 KiB, held block parts to about 0.4 MiB/s).
    pub data: String,
    /// The whole block's encoded length.
    pub len: u64,
    pub error: Option<String>,
}

/// B264: the wire prefixes of a block part's request and answer.
pub const PART_REQ: &str = "SYNC_PART:";
pub const PART_RESP: &str = "SYNC_PART_RESP:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalityArtifact {
    pub finalized_round: String,
    pub last_anchor_round: String,
    pub last_anchor_hash: String,
    pub finality_digest: String,
    /// The quorum certificate that cryptographically proves this finality (>2/3
    /// stake BLS signature). This is the ONLY thing that authorises advancing
    /// `consensus:finalized_round` on a syncing node — the legacy string fields
    /// above are unauthenticated hints. `None` from pre-QC peers (serde default),
    /// in which case finality is NOT advanced.
    #[serde(default)]
    pub qc: Option<consensus::qc::QuorumCertificate>,
}

pub struct ChainSync {
    storage: Arc<StateDB>,
    /// G3 S6: snapshot serving's own budget, global and per client IP.
    state_budget: state_sync::StateBudget,
    /// The values last served in parts.
    state_value_cache: Mutex<state_sync::ValueCache>,
    /// G3 S6: whether this node serves state snapshots at all
    /// (`AINCORE_SERVE_SNAPSHOTS=1`). Off by default: a snapshot read load
    /// on a validator's disk competes with consensus.
    serves_snapshots: bool,
    /// Block retention (`StateDB::block_pruning_policy_from_env`), read once.
    /// Imported blocks prune under it like built ones (G3 GC-1).
    retention: Option<(u64, u64)>,
    /// G4 S1: the sessions the network task holds; sync talks to peers over
    /// them only (the legacy TCP channel is gone, S6). None in tests that
    /// only serve.
    sessions: Option<network::SessionClient>,
    /// B33 review: passes in which each session advertised a height above
    /// this node's and delivered nothing (B256/B263: struck turns), and
    /// when the last was (B263: they expire). Those sessions are asked
    /// after the others, so peers that advertise a height they never serve
    /// cannot hold every one of a pass's slots.
    stalls: Mutex<HashMap<String, (u32, std::time::Instant)>>,
    /// B263: the blocks each session's last turn that asked for blocks
    /// brought, and when; sessions that brought more are asked first.
    /// B274: kept across a session's reconnects (it was dropped with the
    /// session, so a reconnect made a struck server a fresh one), for
    /// `STRIKE_TTL`, at most `MAX_STANDINGS` sessions.
    yields: Mutex<HashMap<String, (u64, std::time::Instant)>>,
    /// B274: when each session last had a turn; among equals the one that
    /// waited longest goes first (the height a session advertised ordered
    /// them, and it is the session's own unauthenticated claim).
    turns: Mutex<HashMap<String, std::time::Instant>>,
    /// B264: the blocks last served in parts, so a block's parts cost one
    /// read. Only blocks too large for a batch are kept.
    parted_blocks: Mutex<state_sync::ValueCache>,
    /// B275: the blocks known to be too large for a batch, by height, and
    /// (B288) when each was last asked for: the least recently asked goes
    /// first (the lowest height went, the one a lagging client fetches).
    oversized_known: Mutex<std::collections::BTreeMap<u64, (OversizedBlock, std::time::Instant)>>,
    /// B275: the parted blocks being fetched, kept across turns. B285: one
    /// per session (each session's copy of a block differs in its
    /// signature, so a second session's turn threw the first's away, and no
    /// block much over two turns' worth arrived with two sessions serving
    /// it), within `MAX_PARTED_BLOCK_BYTES` in all.
    parted: Mutex<HashMap<String, PartialBlock>>,
    /// B275: when a part may next need its block read from storage (B291:
    /// later the more bytes the last read took).
    parted_read_due: Mutex<Option<std::time::Instant>>,
    /// B286: when each session was first and last seen above this node.
    seen: Mutex<HashMap<String, (std::time::Instant, std::time::Instant)>>,
    /// B286: this node's key for ordering sessions alike in every other
    /// respect (their PeerIds, which a Sybil grinds, ordered them).
    turn_salt: [u8; 16],
    /// B311: held for a whole pass (`sync_from_peers`).
    pass: tokio::sync::Mutex<()>,
    /// The encoded bytes a batch's blocks stop at (`SYNC_RESP_BLOCK_BYTES`;
    /// tests make it small, so real blocks are parted).
    batch_bytes: usize,
    /// B285: the bytes all parted fetches may hold together
    /// (`MAX_PARTED_BLOCK_BYTES`; tests make it small).
    parted_budget: u64,
    #[cfg(test)]
    before_execution_hook: Option<fn(&StateDB)>,
}

/// G4 S1: how long one sync request on a session may take.
const SYNC_ASK_TIMEOUT: Duration = Duration::from_secs(60);
/// B33: how long a height or finality answer may take (a few bytes; a
/// choice far above a round trip).
const QUICK_ASK_TIMEOUT: Duration = Duration::from_secs(5);
/// B33: the sessions a pass takes blocks from, the highest first (a choice).
const SYNC_PEERS_PER_PASS: usize = 3;

/// B256: how long one session's turn of a pass may take (a choice: a sync
/// request's timeout). A session kept its turn while each batch made any
/// progress, so one serving a block a batch just inside the request timeout
/// held every pass of every catching-up node at about a block a minute, and
/// the other sessions were never asked.
#[cfg(not(test))]
const SYNC_TURN: Duration = Duration::from_secs(60);
#[cfg(test)]
const SYNC_TURN: Duration = Duration::from_secs(2);

/// B256: a full batch in blocks (`handle_sync_request` answers up to 500
/// blocks or `SYNC_RESP_BLOCK_BYTES` of them). A turn that brought one is
/// never struck, however it ended.
const SYNC_TURN_BLOCKS: u64 = 500;

/// B263: a full batch in the server's unit, its blocks' encoded bytes
/// (half the server's cut: a batch the bytes cut holds more, or its next
/// block is larger than this and fills the following one). B256 counted the
/// transactions' bytes, so a full batch of real blocks was never full.
const FULL_BATCH_BYTES: usize = SYNC_RESP_BLOCK_BYTES / 2;

/// B263: an answer that took longer than this and carried less than a full
/// batch is slow, and strikes its session (a choice: well above a round
/// trip and the reading of a small batch; a full batch over a slow link
/// takes longer, and is never slow).
#[cfg(not(test))]
const SLOW_ANSWER: Duration = Duration::from_secs(20);
#[cfg(test)]
const SLOW_ANSWER: Duration = Duration::from_millis(500);

/// B263: how long a strike counts (a choice): strikes never expired, so a
/// member struck once (an answer lost, its tip without a QC) sat behind any
/// session never struck, Sybils advertising this node's height included.
const STRIKE_TTL: Duration = Duration::from_secs(600);

/// B274: the most sessions whose standing (strikes, yield, last turn) is
/// kept; past it the one updated longest ago goes (a choice: well above any
/// node's sessions, a few hundred KB).
const MAX_STANDINGS: usize = 1024;

/// B274: a session's standing for block turns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Standing {
    member: bool,
    /// Strikes still counting (`STRIKE_TTL`).
    strikes: u32,
    /// Blocks its last turn that asked for blocks brought (0 if none).
    brought: u64,
    /// B286: since when it waits for a turn: its last turn, or, never given
    /// one (or not within `STRIKE_TTL`), when this node first saw it.
    waited_since: std::time::Instant,
    /// B286: its PeerId hashed under this node's `turn_salt`.
    salted: u64,
}

/// B274: the order block turns go in: members, whatever their strikes;
/// then the fewest strikes still counting; then the most blocks brought at
/// the last turn; then (B286) the one that has waited longest, a session
/// never given a turn since this node first saw it; then by `salted`.
/// Nothing a session merely claims (its height) orders it. B286: "never
/// given a turn" went first and ties went by PeerId, so three fresh
/// identities a pass, ground to sort low, took every turn from honest
/// non-members (an observer's only sources). B309: a parted fetch's session
/// gets no turn before its turn comes (B275 put it first; B287 first within
/// its class; a server naming a real header at the largest length, its
/// parts unchecked until the whole arrives, then held every pass's first
/// turn): each session's fetch waits for its turn, kept (B285).
fn turn_order(a: &(String, Standing), b: &(String, Standing)) -> std::cmp::Ordering {
    let ((_, sa), (_, sb)) = (a, b);
    sb.member
        .cmp(&sa.member)
        .then(sa.strikes.cmp(&sb.strikes))
        .then(sb.brought.cmp(&sa.brought))
        .then(sa.waited_since.cmp(&sb.waited_since))
        .then(sa.salted.cmp(&sb.salted))
}

/// B286: `peer` hashed under `salt`.
fn salted_with(salt: &[u8; 16], peer: &str) -> u64 {
    let mut input = salt.to_vec();
    input.extend_from_slice(peer.as_bytes());
    let digest = crypto::hash(&input);
    u64::from_le_bytes(<[u8; 8]>::try_from(&digest[..8]).unwrap_or_default())
}

/// B274: insert `value` under `key`, the entry updated longest ago (`at`)
/// going first when `MAX_STANDINGS` are kept.
fn keep_standing<V>(
    map: &mut HashMap<String, V>,
    key: String,
    value: V,
    at: impl Fn(&V) -> std::time::Instant,
) {
    if !map.contains_key(&key) && map.len() >= MAX_STANDINGS {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, v)| at(v))
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
    }
    map.insert(key, value);
}

/// B263: what a session's turn did, to judge it by.
struct Turn {
    /// The height this node reached.
    reached: u64,
    /// The blocks this node took, and their encoded bytes.
    brought: u64,
    bytes: usize,
    /// An answer took over `SLOW_ANSWER` and carried less than a full batch.
    slow: bool,
    /// The turn ended at the session's height, or at the block it offered
    /// without its QC (an honest server's newest), rather than on an error,
    /// an empty, refused or junk answer, or the turn's time.
    ended_well: bool,
    /// B274: the turn asked for blocks (it did not find this node already
    /// at the session's height).
    asked: bool,
    /// B275: the session sent what no honest server sends (a parted block
    /// that does not check, or does not import).
    refused: bool,
    /// The turn says nothing either way; bringing no whole block, it neither
    /// strikes its session nor clears its strikes. B287: it added to a parted
    /// fetch it left under way (a part's bytes made it full, so one junk part
    /// a turn kept a session clear while its fetch never ended). B302: it
    /// ended at a block without its QC further below the claimed height than
    /// `qcless_tip` allows (a direct commit after a stall builds a block for
    /// every anchor it decides, so an honest server can hold any number
    /// without their QCs, and B289's bound struck it every pass).
    unjudged: bool,
}

impl Turn {
    /// B263: whether the turn strikes its session: a slow answer, or an end
    /// short of the session's certified blocks without a full batch. B256
    /// judged only a turn the clock ended, so one that brought a block
    /// slowly and then answered empty cleared its strike.
    fn struck(&self) -> bool {
        let full = self.brought >= SYNC_TURN_BLOCKS || self.bytes >= FULL_BATCH_BYTES;
        self.slow || self.refused || !(self.ended_well || full)
    }
}

/// B274: whether a block offered without its QC, at `height`, can be its
/// server's newest work. A server claiming far more ended its turn on its
/// own word, and was never struck. B289: members stop proposing once they
/// hold `MAX_UNFINALIZED_BLOCKS` blocks above their lowest without a QC
/// (so an honest server in a stall holds that many, not fewer), and the
/// anchors already supported then still commit: twice that is allowed.
/// Under `MAX_UNFINALIZED_BLOCKS` every honest member was struck on every
/// pass of a stall.
fn qcless_tip(height: u64, claimed: u64) -> bool {
    claimed.saturating_sub(height) <= QCLESS_TIP_BLOCKS
}

/// B302: judge a turn that ends at its server's block `height` offered
/// without its QC, the server claiming `claimed`: well when that block can
/// be its newest work (`qcless_tip`), else unjudged (`Turn::unjudged`).
fn judge_qcless_tip(turn: &mut Turn, height: u64, claimed: u64) {
    if qcless_tip(height, claimed) {
        turn.ended_well = true;
    } else {
        turn.unjudged = true;
    }
}

/// B289: how far above a block offered without its QC its server's claimed
/// height may be for the block to be its newest work.
const QCLESS_TIP_BLOCKS: u64 = 2 * consensus::v4::MAX_UNFINALIZED_BLOCKS;

/// NI-4: the blocks of one SYNC_RESP stop at this many bytes, so the answer
/// stays under the 10 MiB a client reads. B264: a block larger than this is
/// never in a batch; it is named (`SyncResponse::oversized`) and sent in
/// parts.
pub const SYNC_RESP_BLOCK_BYTES: usize = 8 << 20;

/// B264: the bytes of one block part (B275: of a batch's cut, half, as text
/// with its escapes it fits the frame as a batch does). Every part but a
/// block's last is this long but for the bytes of a character cut short
/// (at most 3), so a server that sends less is caught at once.
pub const BLOCK_PART_BYTES: usize = SYNC_RESP_BLOCK_BYTES / 2;

/// B264: the largest block a client fetches in parts. An import holds about
/// six copies of a block's bytes at once (the parts, the parsed block, its
/// body bytes and their Reed-Solomon extension, the stored row), so 512 MiB
/// keeps one within half the documented 8 GB minimum. A block this large
/// lists about four million committed vertices at 134 bytes each, and every
/// node that built it held each of them in its DAG at a kilobyte or more:
/// half that minimum as well.
pub const MAX_PARTED_BLOCK_BYTES: u64 = 512 << 20;

/// B264: the key a block is kept under for its parts (the cache's version
/// is its height).
const PARTED_KEY: &str = "block";

/// B275: the blocks a server knows are too large for a batch, by height,
/// at most this many (a choice; such blocks are rare, an entry is a
/// header): a request beside one is answered from what is known, not by
/// reading the block again.
const MAX_OVERSIZED_KNOWN: usize = 256;

/// B275: how long a client waits after a busy part answer (the server's
/// answer budget refills 12.8 tokens a second, a part's text about 74).
const PART_BUSY_WAIT: Duration = Duration::from_secs(1);

/// B275: a part that needs its block read from storage (not kept) waits
/// this long after the last such read, answered busy meanwhile: clients
/// fetching two large blocks at once made every part a whole block's read.
const PARTED_READ_EVERY: Duration = Duration::from_secs(1);

/// B291: and longer after a large read, at this many bytes a second (a
/// choice, under a spinning disk's rate): one read a second of up to
/// 512 MiB each was a disk's whole rate.
const PARTED_READ_BYTES_PER_SEC: u64 = 64 << 20;

/// B291: how long after reading a block of `len` bytes for its parts the
/// next such read waits.
fn parted_read_wait(len: u64) -> Duration {
    PARTED_READ_EVERY.max(Duration::from_millis(
        len.saturating_mul(1000) / PARTED_READ_BYTES_PER_SEC,
    ))
}

/// B275: why a parted fetch stopped short.
enum PartFailure {
    /// No answer (a timeout, a lost session), or (B288) a refusal an honest
    /// server can give (a block it no longer indexes or holds): proves
    /// nothing; what came is kept for the session's next turn.
    Lost(String),
    /// An answer no honest server sends: its session is struck.
    Lied(String),
    /// B285: larger fetches hold the bytes all fetches share; this one gave
    /// way. Nothing against its server.
    Crowded,
}

/// B275: a parted block's bytes so far, from one session, kept across that
/// session's turns (a part waits on the server's answer budget, so a large
/// block takes more than a turn). Only that session resumes it: each node's
/// copy of a block carries its own proposer signature. B287: dropped once
/// this node holds its height, or after `STRIKE_TTL` without a byte.
struct PartialBlock {
    peer: String,
    height: u64,
    hash: String,
    len: u64,
    bytes: Vec<u8>,
    progressed: std::time::Instant,
    /// B301: when it began (`parted_deadline`).
    started: std::time::Instant,
}

/// B301: an honest server's slowest pace for parts, to a client that gives
/// it a turn a pass, with room to spare (its answer budget sends about
/// 0.8 MiB/s; a pass gives a session about a third of the time).
const PARTED_MIN_BYTES_PER_SEC: u64 = 128 << 10;

/// B301: how long a parted fetch of `len` bytes may run: at the slowest
/// honest pace, at least `STRIKE_TTL`. Past it the fetch goes: one kept
/// large and fed a part a turn held the bytes every other fetch needed, so
/// no fetch of a block over half the budget finished.
fn parted_deadline(len: u64) -> Duration {
    STRIKE_TTL.max(Duration::from_secs(len / PARTED_MIN_BYTES_PER_SEC))
}

/// B287/B301: whether a parted fetch is kept at `now` for a later turn:
/// above `final_height` (this node holds that height otherwise), given a
/// byte within `STRIKE_TTL`, and within its deadline.
fn parted_kept(p: &PartialBlock, final_height: u64, now: std::time::Instant) -> bool {
    p.height > final_height
        && now.duration_since(p.progressed) < STRIKE_TTL
        && now.duration_since(p.started) < parted_deadline(p.len)
}

/// B275: the header a block's stored text starts with (`{"header":{..}`),
/// read without the rest.
fn header_of(json: &str) -> Option<blockchain::BlockHeader> {
    let rest = json.strip_prefix("{\"header\":")?;
    serde_json::Deserializer::from_str(rest)
        .into_iter::<blockchain::BlockHeader>()
        .next()?
        .ok()
}

/// A seed's finality tip as this node can judge it.
enum Tip {
    /// Its QC verifies under its epoch's committee.
    Verified(Box<consensus::qc::QuorumCertificate>),
    /// B57: its QC is in an epoch whose committee this node does not hold
    /// yet, above this node's tip.
    Ahead,
    /// No answer, or a QC that does not verify.
    None,
}

/// The peer a sync client talks to: a session the network task holds (G4
/// S1).
enum SyncLink {
    Session {
        client: network::SessionClient,
        peer: String,
    },
}

impl SyncLink {
    async fn ask_within(&mut self, msg: &str, timeout: Duration) -> Result<String, String> {
        match self {
            Self::Session { client, peer } => client.ask(peer, msg, timeout).await,
        }
    }
}

impl ChainSync {
    pub fn new(storage: Arc<StateDB>) -> Self {
        Self {
            storage,
            state_budget: state_sync::StateBudget::default(),
            state_value_cache: Mutex::new(state_sync::ValueCache::default()),
            serves_snapshots: std::env::var("AINCORE_SERVE_SNAPSHOTS").as_deref() == Ok("1"),
            retention: StateDB::block_pruning_policy_from_env(),
            sessions: None,
            stalls: Mutex::default(),
            yields: Mutex::default(),
            turns: Mutex::default(),
            parted_blocks: Mutex::default(),
            oversized_known: Mutex::default(),
            parted: Mutex::default(),
            parted_read_due: Mutex::default(),
            seen: Mutex::default(),
            turn_salt: rand::random(),
            pass: tokio::sync::Mutex::new(()),
            batch_bytes: SYNC_RESP_BLOCK_BYTES,
            parted_budget: MAX_PARTED_BLOCK_BYTES,
            #[cfg(test)]
            before_execution_hook: None,
        }
    }

    /// Tests only: a retention policy other than the environment's.
    #[cfg(test)]
    pub(crate) fn with_retention(mut self, retention: Option<(u64, u64)>) -> Self {
        self.retention = retention;
        self
    }

    /// Tests only: a batch's byte cut other than `SYNC_RESP_BLOCK_BYTES`.
    #[cfg(test)]
    pub(crate) fn with_batch_bytes(mut self, bytes: usize) -> Self {
        self.batch_bytes = bytes;
        self
    }

    /// Tests only: a parted-fetch budget other than `MAX_PARTED_BLOCK_BYTES`.
    #[cfg(test)]
    pub(crate) fn with_parted_budget(mut self, bytes: u64) -> Self {
        self.parted_budget = bytes;
        self
    }

    /// Tests only: a turn salt other than a random one.
    #[cfg(test)]
    pub(crate) fn with_turn_salt(mut self, salt: [u8; 16]) -> Self {
        self.turn_salt = salt;
        self
    }

    /// B286: `peer` hashed under this node's `turn_salt`.
    fn salted(&self, peer: &str) -> u64 {
        salted_with(&self.turn_salt, peer)
    }

    /// The bytes of one block part (`BLOCK_PART_BYTES` at the default cut).
    fn part_bytes(&self) -> usize {
        self.batch_bytes / 2
    }

    /// B288: the bytes a parted block's text may run past its encoding here
    /// (1 MiB at the default cut): fields a newer release adds, which this
    /// one drops. Exact equality refused every block a newer server sent
    /// during a rolling upgrade, and struck the server; past this it is
    /// padding.
    fn text_slack(&self) -> u64 {
        self.batch_bytes as u64 / 8
    }

    /// Serve state snapshots (G3 S6), whatever `AINCORE_SERVE_SNAPSHOTS` says.
    pub fn with_snapshot_serving(mut self, serve: bool) -> Self {
        self.serves_snapshots = serve;
        self
    }

    /// G4 S1: sync over the network task's sessions.
    pub fn with_sessions(mut self, client: network::SessionClient) -> Self {
        self.sessions = Some(client);
        self
    }

    fn verify_block_hash(block: &Block) -> Result<bool, String> {
        let computed_hash = blockchain::calculate_header_hash(&block.header);

        if computed_hash == block.header.hash {
            Ok(true)
        } else {
            Err(format!(
                "Hash Mismatch. Expected: {}, Computed: {}",
                block.header.hash, computed_hash
            ))
        }
    }

    #[cfg(test)]
    fn verify_execution_roots(
        &self,
        block: &Block,
        summary: &executor::BlockExecutionSummary,
    ) -> Result<(), String> {
        Self::verify_execution_roots_in(block, summary)
    }

    fn verify_execution_roots_in(
        block: &Block,
        summary: &executor::BlockExecutionSummary,
    ) -> Result<(), String> {
        // G3 FX-15: every block binds to the state it executes, always. There
        // is no switch and no env fallback: an empty root used to skip the
        // comparison entirely, letting a producer ship blocks bound to nothing.
        if block.header.state_root.is_empty() {
            return Err(format!(
                "block {} has an empty state_root; execution roots are required",
                block.header.height
            ));
        }
        if block.header.receipts_root.is_empty() {
            return Err(format!(
                "block {} has an empty receipts_root; execution roots are required",
                block.header.height
            ));
        }
        if block.header.state_root != summary.state_root {
            return Err(format!(
                "State root mismatch at block {}: header={}, executed={}",
                block.header.height, block.header.state_root, summary.state_root
            ));
        }
        if block.header.receipts_root != summary.receipts_root {
            return Err(format!(
                "Receipts root mismatch at block {}: header={}, executed={}",
                block.header.height, block.header.receipts_root, summary.receipts_root
            ));
        }
        // B14: a body is what executed and paid. A transaction in it that does
        // not execute here was stored for nothing on the producer.
        if block.transactions != summary.body {
            return Err(format!(
                "block {} carries {} transactions, {} of which execute",
                block.header.height,
                block.transactions.len(),
                summary.body.len()
            ));
        }
        Ok(())
    }

    fn active_validator_addresses(&self) -> Vec<String> {
        self.storage
            .get_active_validators()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect()
    }

    /// TASK-#29: number of distinct seed peers that must advertise a CONSISTENT
    /// finalized tip before this node will accept it as the head to sync past.
    ///
    /// Resolved from the genesis-pinned `sys:config:tip_agreement_n` so it is
    /// deterministic and identical across nodes (NO env var, NO wall-clock — this
    /// path runs during sync and must not fork). Default 1 preserves the current
    /// single-seed behaviour. A value below 1 is clamped to 1.
    fn tip_agreement_n(&self) -> usize {
        self.storage
            .get("sys:config:tip_agreement_n")
            .ok()
            .flatten()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .max(1)
    }

    /// TASK-#29 (pure, unit-testable): decide whether a set of seed-advertised
    /// finalized tips agree well enough to advance past.
    ///
    /// `tips` are the QCs gathered from DISTINCT seed peers (one entry per peer).
    /// Each QC has ALREADY been cryptographically verified by the caller (the QC
    /// crypto backstop in `apply_finality_artifact` is NOT weakened — this is an
    /// additional N-of-seed agreement gate on top of it). We require at least `n`
    /// of them to advertise the SAME `(block_height, block_hash)` finalized tip.
    ///
    /// Returns the agreed `(block_height, block_hash)` on success, or an `Err`
    /// describing the disagreement/shortfall so the caller can refuse to advance
    /// and log `🚨 [SECURITY][TIP_DISAGREEMENT]`.
    fn tip_agreement_decision(
        tips: &[consensus::qc::QuorumCertificate],
        n: usize,
    ) -> Result<(u64, String), String> {
        let n = n.max(1);
        if tips.len() < n {
            return Err(format!(
                "need {} agreeing seed tips but only {} seed(s) advertised a verifiable tip",
                n,
                tips.len()
            ));
        }
        // B44: each tip is a verified QC, so a tip that is merely behind
        // agrees with the head; only two different blocks certified at one
        // height disagree (a member one block behind used to fail the pass).
        let mut at: HashMap<u64, &str> = HashMap::new();
        for qc in tips {
            match at.get(&qc.block_height) {
                Some(hash) if *hash != qc.block_hash => {
                    return Err(format!(
                        "seeds disagree on the finalized head: two blocks certified at height {}",
                        qc.block_height
                    ))
                }
                _ => {
                    at.insert(qc.block_height, &qc.block_hash);
                }
            }
        }
        let head = tips
            .iter()
            .max_by(|a, b| a.block_height.cmp(&b.block_height))
            .map(|qc| (qc.block_height, qc.block_hash.clone()));
        head.ok_or_else(|| "no seed advertised a verifiable finalized tip".to_string())
    }

    fn validate_block(
        &self,
        block: &Block,
        expected_height: u64,
        prev_hash: &str,
    ) -> Result<(), String> {
        Self::validate_block_in(&self.storage, block, expected_height, prev_hash)
    }

    fn validate_block_in(
        storage: &StateDB,
        block: &Block,
        expected_height: u64,
        prev_hash: &str,
    ) -> Result<(), String> {
        if block.header.height != expected_height {
            return Err(format!(
                "Height mismatch: expected {}, got {}",
                expected_height, block.header.height
            ));
        }
        if expected_height == 1 && block.header.prev_hash != "genesis" {
            return Err(format!(
                "Genesis parent mismatch: expected genesis, got {}",
                block.header.prev_hash
            ));
        }
        if expected_height > 1 && block.header.prev_hash != prev_hash {
            return Err(format!(
                "Parent hash mismatch at {}: exp {}, got {}",
                expected_height, prev_hash, block.header.prev_hash
            ));
        }

        let validators = Self::eligible_proposers(storage, block.header.height)?;
        if !validators.contains(&block.header.proposer_id) {
            return Err(format!(
                "Proposer {} is not in active validator set",
                block.header.proposer_id
            ));
        }

        // Consumer-side invariant: only equivocation evidence is ordered
        // through the DAG. Reject a block carrying any other kind outright.
        if let Some(bad) = block
            .slash_evidence
            .iter()
            .find(|it| !consensus::DagConsensus::is_equivocation_item(it))
        {
            return Err(format!(
                "block {} carries non-equivocation slash evidence kind: {}",
                block.header.height,
                bad.chars().take(80).collect::<String>()
            ));
        }

        // S3-4a: Reject blocks with future timestamps (30s drift tolerance)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();
        if block.header.timestamp > now + 30 {
            return Err(format!(
                "Future timestamp rejected: block={}, now={}",
                block.header.timestamp, now
            ));
        }

        // S3-4b: Reject blocks with excessive transaction count (DoS prevention)
        if block.transactions.len() > 10_000 {
            return Err(format!(
                "Transaction count {} exceeds max 10,000",
                block.transactions.len()
            ));
        }

        Self::verify_block_hash(block)?;
        // RE-AUDIT CRITICAL: a synced block must PROVE it was produced by a
        // validator. Followers adopt its committed sequence and BLS-vote for it,
        // so any peer able to forge a block could harvest votes on a fork. The
        // signer is the validator that BUILT this copy (`proposer_signer`) — every
        // validator builds every block deterministically, so binding to the anchor
        // leader's key instead made blocks syncable only from the leader itself
        // (98 rejections in one catch-up; a dead leader's blocks unsyncable).
        let signer = block.proposer_signer.clone();
        if signer.is_empty() {
            return Err(format!("Block #{} carries no proposer signer", block.header.height));
        }
        if !validators.contains(&signer) {
            return Err(format!(
                "Block #{} signer {} is not an active validator",
                block.header.height, signer
            ));
        }
        Self::verify_proposer_signature_in(storage, block)?;
        // G0 (V4): the anchor is the sequence's last vertex, which the header
        // binds; a substituted anchor under a reused signature stops here.
        // B275: before the roots: only the DA root covers `anchor_hash`, so
        // one padded to megabytes cost a whole Reed-Solomon encode first.
        if consensus::v4::is_v4_chain(storage) && !block.anchor_is_bound() {
            return Err(format!(
                "block {}'s anchor {} is not its last committed vertex",
                block.header.height,
                block.anchor_hash.chars().take(80).collect::<String>()
            ));
        }
        // B41: the costly checks last, once a validator's signature binds the
        // header (the DA root's encode costs up to ~0.6 s a batch).
        // Every header root against the body: transactions, the committed
        // vertex sequence a follower adopts, slash evidence, and the DA root
        // a light client samples against. Unconditional (G3 FX-18): an empty
        // root must mean an empty list, or a peer could attach vertices to a
        // block that has none.
        block.check_commitments()?;
        Ok(())
    }

    /// Who may lead or sign block `height`. On V4 (G1 DE-7) the frozen
    /// committee of the height's epoch, C_E(h): a member that leaves or is
    /// slashed mid-epoch still leads its anchors, and the QC is the authority
    /// anyway (final review HIGH: gating on the live set made its blocks
    /// unsyncable). On V3 the live set, as before.
    fn eligible_proposers(storage: &StateDB, height: u64) -> Result<Vec<String>, String> {
        if consensus::v4::is_v4_chain(storage) {
            let epoch = consensus::qc_producer::epoch_for_block_height(storage, height)
                .ok_or("no epoch for this height")?;
            let committee = consensus::v4::epoch::committee_of(storage, epoch)
                .ok_or_else(|| format!("no committee for epoch {epoch}"))?;
            return Ok(committee.into_iter().map(|m| m.address).collect());
        }
        Ok(storage
            .get_active_validators_checked()
            .map_err(|e| format!("cannot resolve validator eligibility: {e}"))?
            .into_iter()
            .map(|(address, _)| address)
            .collect())
    }

    /// The block's proposer signature, under the public key its signer's
    /// account records in `storage`.
    pub(crate) fn verify_proposer_signature_in(
        storage: &StateDB,
        block: &Block,
    ) -> Result<(), String> {
        let signer = &block.proposer_signer;
        let signer_pk = storage
            .get_object(signer)
            .and_then(|obj| serde_json::from_slice::<serde_json::Value>(&obj.data).ok())
            .and_then(|v| v.get("public_key").and_then(|k| k.as_str()).map(String::from));
        match signer_pk {
            Some(pk) if block.verify_proposer_signature(&pk) => Ok(()),
            Some(_) => Err(format!(
                "Proposer signature invalid or missing on block #{} (signer {})",
                block.header.height, signer
            )),
            None => Err(format!(
                "Cannot resolve signer {} public key to authenticate block #{}",
                signer, block.header.height
            )),
        }
    }

    // Run before execution while holding the storage writer gate. In particular,
    // do not reuse parent/key/QC reads from the unlocked network precheck.
    fn validate_admission_in(storage: &StateDB, block: &Block) -> Result<(), String> {
        let height = block.header.height;
        if height == 0 {
            return Err("cannot admit block height zero".into());
        }
        let parent_hash = if height == 1 {
            "genesis".to_owned()
        } else {
            let parent_json = storage.get(&format!("block_{}", height - 1))
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "missing parent at admission".to_owned())?;
            let parent: Block = serde_json::from_str(&parent_json)
                .map_err(|e| format!("invalid parent at admission: {e}"))?;
            if parent.header.height != height - 1 {
                return Err("stored parent height mismatch at admission".into());
            }
            parent.header.hash
        };
        if let Some(json) = storage.get("consensus:qc:latest").map_err(|e| e.to_string())? {
            let qc: consensus::qc::QuorumCertificate = serde_json::from_str(&json)
                .map_err(|e| format!("invalid held QC at admission: {e}"))?;
            if qc.block_height == height && qc.block_hash != block.header.hash {
                return Err("held QC conflicts with block at admission".into());
            }
        }
        Self::validate_block_in(storage, block, height, &parent_hash)
    }

    fn get_local_height(&self) -> u64 {
        self.storage.get_chain_height()
    }

    fn finalized_round_boundary(&self) -> u64 {
        self.storage
            .get("consensus:finalized_round")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    }

    fn collect_finality_artifact(&self) -> FinalityArtifact {
        FinalityArtifact {
            finalized_round: self
                .storage
                .get("consensus:finalized_round")
                .ok()
                .flatten()
                .unwrap_or_else(|| "0".to_string()),
            last_anchor_round: self
                .storage
                .get("consensus:last_anchor_round")
                .ok()
                .flatten()
                .unwrap_or_else(|| "0".to_string()),
            last_anchor_hash: self
                .storage
                .get("consensus:last_anchor_hash")
                .ok()
                .flatten()
                .unwrap_or_default(),
            finality_digest: self
                .storage
                .get("consensus:finality_digest")
                .ok()
                .flatten()
                .unwrap_or_default(),
            // Serve the quorum certificate so peers can cryptographically VERIFY
            // (not trust) the finality we advertise.
            qc: self
                .storage
                .get("consensus:qc:latest")
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<consensus::qc::QuorumCertificate>(&j).ok()),
        }
    }

    /// The trusted validator set that a finality QC is verified against. SEC-#16:
    /// resolved by the QC's epoch (`sys:validator_set:epoch:{epoch}`, the snapshot
    /// frozen at that epoch's start) so a QC produced in an earlier epoch still
    /// verifies against the set that produced it. Missing historical snapshots
    /// cannot be substituted with the live set (legacy epoch-0 bootstrap aside).
    fn trusted_validator_set(&self, epoch: u64) -> Option<Vec<consensus::qc::ValidatorInfo>> {
        consensus::qc_producer::load_validator_set_for_epoch(&self.storage, epoch)
    }

    /// Apply a finality artifact — QC-GATED.
    ///
    /// SECURITY: only a quorum certificate that verifies (>2/3-stake aggregate
    /// BLS signature over the canonical FinalityVote) against our trusted
    /// validator set may advance `consensus:finalized_round`. The previous
    /// round-drift heuristic was forgeable: an unsigned `block.header.round`
    /// (blocks carry no proposer signature) could inflate the accepted round and
    /// poison `consensus:finalized_round`, halting a validator. With QC-gating a
    /// peer cannot move our finalized round without the validators' aggregate
    /// signature; a peer that supplies no/invalid QC simply does not advance our
    /// finality (a no-op, not a failure).
    fn apply_finality_artifact(&self, artifact: &FinalityArtifact) -> Result<(), String> {
        let Some(qc) = artifact.qc.as_ref() else {
            return Ok(()); // pre-QC peer: cannot move our finality, harmless
        };
        // Membership, local-block binding, monotonicity, finality metadata and
        // every QC index share one writer-gated transaction. Never publish just
        // the latest body: the producer consumes its height/round indexes too.
        if consensus::qc_producer::import_finality_qc(&self.storage, qc)? {
            println!(
                "✅ [ChainSync] Applied durable QC-verified finality: round={} (signed_stake={}/{})",
                qc.finalized_round, qc.signed_stake, qc.total_stake
            );
        }
        Ok(())
    }

    /// Sync over the network sessions (G4 S1).
    /// Returns the final synced height (0 if no sync happened)
    pub async fn sync_from_peers(&self) -> u64 {
        // B311: one pass at a time. A lagging node's boot sync and its
        // periodic loop ran together: each took the same top session's block,
        // and each held a parted fetch outside `parted`, so neither counted
        // the other's against the budget (twice the bytes).
        let Ok(_pass) = self.pass.try_lock() else {
            return self.get_local_height();
        };
        println!("🔄 [ChainSync] Starting sync over network sessions...");

        // Audit #3: `sync:halt_reason` stops syncing while it is present. No
        // code writes it any more (a block whose roots differ is refused on
        // its own, B45); an operator may set it to hold a node, and deletes
        // it to resume.
        if let Ok(Some(reason)) = self.storage.get("sync:halt_reason") {
            eprintln!(
                "🛑 [ChainSync] HALTED after a state divergence: {reason} — not syncing. \
                 Investigate, then clear `sync:halt_reason` to resume."
            );
            return self.get_local_height();
        }

        match self.sessions.clone() {
            Some(client) => self.sync_over_sessions(&client).await,
            None => {
                println!("📡 [ChainSync] No network sessions to sync over.");
                self.get_local_height()
            }
        }
    }

    /// G4 S1: sync over the sessions the network task holds, committee
    /// members first. The tip-agreement gate counts a member only by the key
    /// its session authenticated, never by an id a peer claims.
    async fn sync_over_sessions(&self, client: &network::SessionClient) -> u64 {
        let sessions = client.sessions();
        let mut final_height = self.get_local_height();
        if sessions.is_empty() {
            println!("📡 [ChainSync] No sessions available.");
            return final_height;
        }
        let tip_n = self.tip_agreement_n();
        if tip_n > 1 {
            let seed_set = self.active_validator_addresses();
            let mut tips = Vec::new();
            let mut ahead = 0usize;
            for session in &sessions {
                if !session
                    .member
                    .as_ref()
                    .is_some_and(|m| seed_set.contains(m))
                {
                    continue;
                }
                let mut link = SyncLink::Session {
                    client: client.clone(),
                    peer: session.peer.clone(),
                };
                match self.verified_tip_over(&mut link).await {
                    Tip::Verified(qc) => {
                        tips.push(*qc);
                        if tips.len() >= tip_n {
                            break;
                        }
                    }
                    Tip::Ahead => ahead += 1,
                    Tip::None => {}
                }
            }
            // B57: seeds whose tips lie in an epoch this node cannot verify
            // yet (it has not imported the boundary block) are ahead of it;
            // with too few verifiable tips then, the pass goes on, and every
            // block it imports still needs its own QC. Refusing left a
            // follower one boundary behind stalled for good. B72: an "ahead"
            // claim is unverified, so it counts as one seed's answer, never
            // as the agreement of N: the pass goes on only when verified
            // tips and ahead claims together reach N, and the verified tips
            // still agree among themselves. One seed naming an epoch the
            // node does not know used to waive the gate.
            if tips.len() < tip_n && tips.len() + ahead >= tip_n {
                // The verified tips, if any, must agree (with none, the
                // ahead claims alone reach N: B57's follower).
                let disagree = if tips.is_empty() {
                    Ok(())
                } else {
                    Self::tip_agreement_decision(&tips, tips.len()).map(|_| ())
                };
                if let Err(e) = disagree {
                    eprintln!(
                        "🚨 [SECURITY][TIP_DISAGREEMENT] {} — refusing to advance",
                        e
                    );
                    return final_height;
                }
                println!(
                    "📡 [ChainSync] {ahead} seed(s) are past an epoch this node has not reached; syncing toward them"
                );
            } else if let Err(e) = Self::tip_agreement_decision(&tips, tip_n) {
                eprintln!(
                    "🚨 [SECURITY][TIP_DISAGREEMENT] {} — refusing to advance",
                    e
                );
                return final_height;
            }
        }
        // B33: every session's height at once, each within
        // QUICK_ASK_TIMEOUT; then blocks from the highest few, members first.
        // Asked one after another with 60 s timeouts, one stalling peer cost
        // every pass about two minutes.
        let mut asks = tokio::task::JoinSet::new();
        for session in sessions {
            let client = client.clone();
            asks.spawn(async move {
                let height = client
                    .ask(&session.peer, "GET_HEIGHT", QUICK_ASK_TIMEOUT)
                    .await
                    .ok()
                    .and_then(|r| {
                        r.strip_prefix("HEIGHT:")
                            .and_then(|h| h.trim().parse::<u64>().ok())
                    });
                (session, height)
            });
        }
        // B263: block turns go to sessions above this node's height only; a
        // session at it has no block to give, and is asked for its finality
        // artifact alone (the tip's QC), outside the turns. It took a turn
        // and was never struck, so Sybils advertising this node's height
        // held every turn once the members had a strike.
        let mut above = Vec::new();
        let mut level = Vec::new();
        while let Some(joined) = asks.join_next().await {
            if let Ok((session, Some(height))) = joined {
                if height > final_height {
                    above.push((session, height));
                } else if height == final_height {
                    level.push(session);
                }
            }
        }
        // B286: members first, then by this node's salt, not the PeerId.
        let salted = |peer: &str| self.salted(peer);
        level.sort_by(|a, b| {
            b.member
                .is_some()
                .cmp(&a.member.is_some())
                .then(salted(&a.peer).cmp(&salted(&b.peer)))
        });
        let mut finality = tokio::task::JoinSet::new();
        for session in level.into_iter().take(SYNC_PEERS_PER_PASS) {
            let client = client.clone();
            finality.spawn(async move {
                client
                    .ask(&session.peer, "GET_FINALITY", QUICK_ASK_TIMEOUT)
                    .await
                    .ok()
            });
        }
        while let Some(joined) = finality.join_next().await {
            let artifact = joined
                .ok()
                .flatten()
                .and_then(|r| r.strip_prefix("FINALITY:").map(str::to_string))
                .and_then(|json| serde_json::from_str::<FinalityArtifact>(&json).ok());
            if let Some(artifact) = artifact {
                if let Err(e) = self.apply_finality_artifact(&artifact) {
                    eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                }
            }
        }
        // B263/B274: the order of `turn_order`, from standings that expire
        // after `STRIKE_TTL` and outlive a session's reconnects.
        let now = std::time::Instant::now();
        let fresh = |at: &std::time::Instant| now.duration_since(*at) < STRIKE_TTL;
        let stalls = self
            .stalls
            .lock()
            .map(|mut s| {
                s.retain(|_, (_, at)| fresh(at));
                s.clone()
            })
            .unwrap_or_default();
        let yields = self
            .yields
            .lock()
            .map(|mut y| {
                y.retain(|_, (_, at)| fresh(at));
                y.clone()
            })
            .unwrap_or_default();
        let turns = self
            .turns
            .lock()
            .map(|mut t| {
                t.retain(|_, at| fresh(at));
                t.clone()
            })
            .unwrap_or_default();
        // B286: when each session above was first seen (kept while it is
        // seen again within `STRIKE_TTL`).
        let seen = self
            .seen
            .lock()
            .map(|mut seen| {
                seen.retain(|_, (_, last)| fresh(last));
                for (session, _) in &above {
                    match seen.get_mut(&session.peer) {
                        Some((_, last)) => *last = now,
                        None => keep_standing(
                            &mut seen,
                            session.peer.clone(),
                            (now, now),
                            |(_, last)| *last,
                        ),
                    }
                }
                seen.clone()
            })
            .unwrap_or_default();
        // B287/B301: fetches this node holds the height of, that took no
        // byte within `STRIKE_TTL`, or that ran past their deadline, are
        // dropped.
        if let Ok(mut parted) = self.parted.lock() {
            parted.retain(|_, p| parted_kept(p, final_height, now));
        }
        let mut ranked: Vec<((String, Standing), (network::SessionPeer, u64))> = above
            .into_iter()
            .map(|(session, advertised)| {
                let first_seen = seen.get(&session.peer).map_or(now, |(first, _)| *first);
                let standing = Standing {
                    member: session.member.is_some(),
                    strikes: stalls.get(&session.peer).map_or(0, |(n, _)| *n),
                    brought: yields.get(&session.peer).map_or(0, |(n, _)| *n),
                    waited_since: turns.get(&session.peer).copied().unwrap_or(first_seen),
                    salted: self.salted(&session.peer),
                };
                ((session.peer.clone(), standing), (session, advertised))
            })
            .collect();
        ranked.sort_by(|(a, _), (b, _)| turn_order(a, b));
        for (_, (session, advertised)) in ranked.into_iter().take(SYNC_PEERS_PER_PASS) {
            let label = session
                .member
                .clone()
                .unwrap_or_else(|| session.peer.clone());
            let peer = session.peer.clone();
            let mut link = SyncLink::Session {
                client: client.clone(),
                peer: session.peer,
            };
            let before = self.get_local_height();
            let turn = self.sync_over(&mut link, &label, before, advertised).await;
            final_height = final_height.max(turn.reached);
            let at = std::time::Instant::now();
            if let Ok(mut turns) = self.turns.lock() {
                keep_standing(&mut turns, peer.clone(), at, |t| *t);
            }
            // B274: a turn that found this node already at the session's
            // height asked for nothing, and says nothing of its yield.
            if turn.asked {
                if let Ok(mut yields) = self.yields.lock() {
                    keep_standing(&mut yields, peer.clone(), (turn.brought, at), |(_, t)| *t);
                }
            }
            if let Ok(mut stalls) = self.stalls.lock() {
                if turn.unjudged && turn.brought == 0 {
                    // B287/B302: nothing to judge the session by.
                } else if turn.struck() {
                    let n = stalls.get(&peer).map_or(0, |(n, _)| *n);
                    keep_standing(&mut stalls, peer, (n.saturating_add(1), at), |(_, t)| *t);
                } else {
                    stalls.remove(&peer);
                }
            }
        }
        final_height
    }

    /// One peer's blocks over `link`: its height, then batches up to it
    /// (B256: within `SYNC_TURN`), then its finality artifact. B263: what
    /// the turn did, to judge the session by (`Turn::struck`). B274:
    /// `advertised` is the height the session claimed for this pass; a turn
    /// ends well on its word only when that claim is borne out or plausible
    /// (`qcless_tip`).
    async fn sync_over(
        &self,
        link: &mut SyncLink,
        peer_id: &str,
        my_height: u64,
        advertised: u64,
    ) -> Turn {
        let mut turn = Turn {
            reached: my_height,
            brought: 0,
            bytes: 0,
            slow: false,
            ended_well: false,
            asked: false,
            refused: false,
            unjudged: false,
        };
        let turn_ends = tokio::time::Instant::now() + SYNC_TURN;
        // 2. Request Chain Height
        let Ok(resp) = link.ask_within("GET_HEIGHT", QUICK_ASK_TIMEOUT).await else {
            return turn;
        };
        // Parse Height response e.g. "HEIGHT:100"
        let Some(peer_height) = resp
            .strip_prefix("HEIGHT:")
            .and_then(|h| h.trim().parse::<u64>().ok())
        else {
            return turn;
        };
        println!("📊 [ChainSync] Peer Height: {}", peer_height);

        if peer_height > my_height {
            // 3. Request Blocks — loop in batches until caught up
            let mut current = my_height;
            while current < peer_height {
                let sync_req = SyncRequest {
                    from_height: current,
                };
                let req_json = match serde_json::to_string(&sync_req) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("❌ [ChainSync] Failed to serialize sync request: {}", e);
                        break;
                    }
                };
                // 4. Receive Blocks Batch, within the turn (B256).
                let asked_at = tokio::time::Instant::now();
                let left = turn_ends.saturating_duration_since(asked_at);
                if left.is_zero() {
                    break;
                }
                turn.asked = true;
                let asked = link
                    .ask_within(
                        &format!("SYNC_REQ:{}", req_json),
                        left.min(SYNC_ASK_TIMEOUT),
                    )
                    .await;
                let data_resp = match asked {
                    Ok(data_resp) => data_resp,
                    Err(e) => {
                        eprintln!(
                            "❌ [ChainSync] Failed to read SYNC_RESP from {}: {}",
                            peer_id, e
                        );
                        break;
                    }
                };
                let took = asked_at.elapsed();
                let Some(json_data) = data_resp.strip_prefix("SYNC_RESP:") else {
                    eprintln!(
                        "❌ [ChainSync] Unexpected sync response prefix: {}",
                        data_resp.chars().take(80).collect::<String>()
                    );
                    break;
                };
                let Ok(sync_resp) = serde_json::from_str::<SyncResponse>(json_data) else {
                    eprintln!(
                        "❌ [ChainSync] Failed to parse SYNC_RESP JSON ({} bytes)",
                        json_data.len()
                    );
                    break;
                };
                let finality = sync_resp.finality.clone();
                // B264: the next block is too large for a batch: it comes in
                // parts, then through the import like any other block. B275:
                // its header and QC are checked first, the parts wait out the
                // server's answer budget, and what the turn could not fetch is
                // fetched at this session's next turn.
                if let Some(big) = sync_resp.oversized {
                    turn.slow |= took > SLOW_ANSWER;
                    if big.height != current + 1 {
                        break;
                    }
                    let qc = sync_resp.qcs.iter().find(|q| q.block_height == big.height);
                    if consensus::v4::is_v4_chain(&self.storage) && qc.is_none() {
                        // Its server's newest block, without its QC yet.
                        judge_qcless_tip(&mut turn, big.height, peer_height.max(advertised));
                        break;
                    }
                    if let Err(e) = self.check_named(&big, qc) {
                        eprintln!(
                            "❌ [ChainSync] Block #{} named in parts by {}: {}",
                            big.height, peer_id, e
                        );
                        turn.refused = true;
                        break;
                    }
                    let block = match self
                        .fetch_parted_block(link, peer_id, &big, turn_ends, &mut turn)
                        .await
                    {
                        Ok(Some(block)) => block,
                        // The turn ended; the next resumes it.
                        Ok(None) => break,
                        Err(PartFailure::Lost(e)) => {
                            eprintln!(
                                "❌ [ChainSync] Block #{} in parts from {}: {}",
                                big.height, peer_id, e
                            );
                            break;
                        }
                        Err(PartFailure::Lied(e)) => {
                            eprintln!(
                                "🚨 [ChainSync] Block #{} in parts from {}: {}",
                                big.height, peer_id, e
                            );
                            turn.refused = true;
                            break;
                        }
                        Err(PartFailure::Crowded) => {
                            turn.ended_well = true;
                            break;
                        }
                    };
                    let synced = self.process_blocks_with_qcs(vec![block], &sync_resp.qcs, current);
                    if synced <= current {
                        turn.refused = true;
                        break;
                    }
                    turn.brought += 1;
                    current = synced;
                    turn.reached = synced;
                    if let Some(finality) = finality {
                        if let Err(e) = self.apply_finality_artifact(&finality) {
                            eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                        }
                    }
                    continue;
                }
                if sync_resp.blocks.is_empty() {
                    if let Some(finality) = finality {
                        if let Err(e) = self.apply_finality_artifact(&finality) {
                            eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                        }
                    }
                    // Below the peer's prune horizon: block-replay
                    // cannot bridge this gap. Surface it clearly
                    // instead of looping silently on empty replies.
                    if let Some(horizon) = sync_resp.prune_horizon {
                        let local_now = self.get_local_height();
                        if horizon > local_now + 1 {
                            eprintln!(
                                "🛑 [ChainSync] peer pruned below us: earliest block #{} but we are at #{}. \
                                 Block-replay cannot bridge this: restore from a checkpoint \
                                 (AINCORE_STATE_SYNC_CHECKPOINT) or sync from a peer that keeps history.",
                                horizon, local_now
                            );
                        }
                    }
                    break; // No more blocks
                }
                // B256/B263: what the answer brought, in the server's unit
                // (each block's encoded bytes), and whether its next block
                // came without its QC (an honest server's newest block).
                let sizes: Vec<(u64, usize)> = sync_resp
                    .blocks
                    .iter()
                    .filter(|b| b.header.height > current)
                    .map(|b| {
                        (
                            b.header.height,
                            serde_json::to_string(b).map_or(0, |j| j.len()),
                        )
                    })
                    .collect();
                let offered: Vec<u64> = sync_resp.blocks.iter().map(|b| b.header.height).collect();
                let certified: Vec<u64> = sync_resp.qcs.iter().map(|q| q.block_height).collect();
                let synced =
                    self.process_blocks_with_qcs(sync_resp.blocks, &sync_resp.qcs, current);
                let (got, got_bytes) = sizes
                    .iter()
                    .filter(|(h, _)| *h <= synced)
                    .fold((0u64, 0usize), |(n, b), (_, len)| {
                        (n + 1, b.saturating_add(*len))
                    });
                turn.brought += got;
                turn.bytes = turn.bytes.saturating_add(got_bytes);
                if took > SLOW_ANSWER && got < SYNC_TURN_BLOCKS && got_bytes < FULL_BATCH_BYTES {
                    turn.slow = true;
                }
                if synced <= current {
                    // The server's next block has no QC yet: what it could
                    // certify, this node holds.
                    if offered.contains(&(synced + 1)) && !certified.contains(&(synced + 1)) {
                        judge_qcless_tip(&mut turn, synced + 1, peer_height.max(advertised));
                    }
                    eprintln!(
                        "⚠️ [ChainSync] Batch made no progress from height {}",
                        current
                    );
                    break; // No progress made
                }
                current = synced;
                turn.reached = synced;
                if let Some(finality) = finality {
                    if let Err(e) = self.apply_finality_artifact(&finality) {
                        eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                    }
                }
                if current < peer_height
                    && offered.contains(&(current + 1))
                    && !certified.contains(&(current + 1))
                {
                    judge_qcless_tip(&mut turn, current + 1, peer_height.max(advertised));
                    break;
                }
            }
            turn.ended_well |= turn.reached >= peer_height;
        } else {
            println!("✅ [ChainSync] Already caught up with peer {}", peer_id);
            // B274: borne out only if this node reached the height the
            // session claimed for the pass (another session brought it); a
            // session that claimed more and now claims less ends badly.
            turn.ended_well = my_height >= advertised;
        }

        if let Ok(finality_resp) = link.ask_within("GET_FINALITY", QUICK_ASK_TIMEOUT).await {
            if let Some(json) = finality_resp.strip_prefix("FINALITY:") {
                if let Ok(artifact) = serde_json::from_str::<FinalityArtifact>(json) {
                    if let Err(e) = self.apply_finality_artifact(&artifact) {
                        eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                    }
                }
            }
        }
        turn
    }

    /// B275: whether `big` may be fetched: a length no batch holds and no
    /// more than a client imports, its header's own hash at its height, and
    /// (on V4) a QC that verifies under the height's committee and binds the
    /// header. Checked before any part is asked for: a fetch started on any
    /// QC that merely named the height.
    fn check_named(
        &self,
        big: &OversizedBlock,
        qc: Option<&consensus::qc::QuorumCertificate>,
    ) -> Result<(), String> {
        if big.len <= self.batch_bytes as u64 || big.len > MAX_PARTED_BLOCK_BYTES {
            return Err(format!("a parted block of {} bytes", big.len));
        }
        if big.header.height != big.height {
            return Err(format!(
                "a header of #{} named #{}",
                big.header.height, big.height
            ));
        }
        if blockchain::calculate_header_hash(&big.header) != big.header.hash {
            return Err("a header that does not hash to its hash".into());
        }
        match qc {
            Some(qc) => consensus::qc_producer::verify_header_qc(&self.storage, &big.header, qc),
            None => Ok(()),
        }
    }

    /// B264/B275: the block `big` names, in parts over `link`, within the
    /// turn (`turn_ends`): resumed from what this session sent at its last
    /// turns, a busy answer waited out, each part but the last `part_bytes`
    /// long but for a character cut short. `None`: the turn ended first.
    /// The whole must be the text the server stores for the header checked
    /// (`check_named`): padding is refused.
    async fn fetch_parted_block(
        &self,
        link: &mut SyncLink,
        peer: &str,
        big: &OversizedBlock,
        turn_ends: tokio::time::Instant,
        turn: &mut Turn,
    ) -> Result<Option<Block>, PartFailure> {
        let part_bytes = self.part_bytes() as u64;
        let lied = PartFailure::Lied;
        // B285: this session's own fetch. B287: the block it named before at
        // another length is a lie (a renamed length restarted the fetch, at
        // no cost).
        let held = self
            .parted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(peer)
            .filter(|p| p.height == big.height && p.hash == big.header.hash);
        if let Some(p) = &held {
            if p.len != big.len {
                return Err(lied(format!(
                    "block #{} named at {} bytes, then at {}",
                    big.height, p.len, big.len
                )));
            }
        }
        let mut partial = held.unwrap_or_else(|| PartialBlock {
            peer: peer.to_string(),
            height: big.height,
            hash: big.header.hash.clone(),
            len: big.len,
            bytes: Vec::new(),
            progressed: std::time::Instant::now(),
            started: std::time::Instant::now(),
        });
        let start = partial.bytes.len();
        // What came is kept for the session's next turn; a turn that added
        // to it is under way (B287).
        let keep = |partial: PartialBlock, turn: &mut Turn| {
            turn.unjudged |= partial.bytes.len() > start;
            if let Ok(mut parted) = self.parted.lock() {
                parted.insert(partial.peer.clone(), partial);
            }
        };
        while (partial.bytes.len() as u64) < big.len {
            let left = turn_ends.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                keep(partial, turn);
                return Ok(None);
            }
            let req = serde_json::to_string(&BlockPartRequest {
                height: big.height,
                offset: partial.bytes.len() as u64,
            })
            .map_err(|e| PartFailure::Lost(e.to_string()))?;
            // No answer proves nothing: what came is kept for the next turn.
            let answer = match link
                .ask_within(&format!("{PART_REQ}{req}"), left.min(SYNC_ASK_TIMEOUT))
                .await
            {
                Ok(answer) => answer,
                Err(e) => {
                    keep(partial, turn);
                    return Err(PartFailure::Lost(e));
                }
            };
            let part = answer
                .strip_prefix(PART_RESP)
                .and_then(|json| serde_json::from_str::<BlockPartResponse>(json).ok())
                .ok_or_else(|| lied("a garbled block part".into()))?;
            match part.error.as_deref() {
                Some(state_sync::BUSY) => {
                    tokio::time::sleep(PART_BUSY_WAIT.min(left)).await;
                    continue;
                }
                // B288: an honest server refuses a block it no longer
                // indexes (its index is bounded) or holds (pruned): not a
                // lie (it was struck as one).
                Some(e) => {
                    let why = format!("a part refused: {e}");
                    keep(partial, turn);
                    return Err(PartFailure::Lost(why));
                }
                None => {}
            }
            let due = big.len - partial.bytes.len() as u64;
            let n = part.data.len() as u64;
            let whole = n > 0 && n <= due.min(part_bytes) && (n == due || n + 3 >= part_bytes);
            if part.len != big.len || !whole {
                return Err(lied(format!(
                    "a block part of {n} bytes of {}, where up to {} of {} were due",
                    part.len,
                    due.min(part_bytes),
                    big.len
                )));
            }
            // B285: within the bytes all fetches share; the smallest gives
            // way, so the largest (an honest server's, at its full rate)
            // completes.
            if !self.make_room(peer, partial.bytes.len() as u64 + n) {
                // B301: what it holds is kept (within the budget as it
                // stands): it was dropped, so a fetch kept largest by a part
                // a turn held every other one below the budget less its own
                // bytes, for good.
                keep(partial, turn);
                return Err(PartFailure::Crowded);
            }
            partial.bytes.extend_from_slice(part.data.as_bytes());
            partial.progressed = std::time::Instant::now();
            turn.bytes = turn.bytes.saturating_add(n as usize);
        }
        let block = serde_json::from_slice::<Block>(&partial.bytes)
            .map_err(|e| lied(format!("a parted block that does not parse: {e}")))?;
        if block.header.hash != big.header.hash {
            return Err(lied(format!(
                "parts of block {}, not {}",
                block.header.hash, big.header.hash
            )));
        }
        let encoded = serde_json::to_vec(&block)
            .map_err(|e| lied(e.to_string()))?
            .len() as u64;
        if big.len > encoded.saturating_add(self.text_slack()) {
            return Err(lied(format!(
                "a parted block of {} bytes whose encoding is {encoded}: padded",
                big.len
            )));
        }
        Ok(Some(block))
    }

    /// B285: room for a fetch under way (out of `parted` while it runs) to
    /// hold `want` bytes, within `parted_budget` with every other session's
    /// fetch: the smallest fetch gives way, this one included (false: this
    /// one).
    fn make_room(&self, peer: &str, want: u64) -> bool {
        let mut parted = self.parted.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            let others: u64 = parted.values().map(|p| p.bytes.len() as u64).sum();
            if others.saturating_add(want) <= self.parted_budget {
                return true;
            }
            let Some((smallest, held)) = parted
                .iter()
                .filter(|(other, _)| other.as_str() != peer)
                .map(|(other, p)| (other.clone(), p.bytes.len() as u64))
                .min_by_key(|(other, held)| (*held, other.clone()))
            else {
                return true;
            };
            if held >= want {
                return false;
            }
            parted.remove(&smallest);
        }
    }

    /// A peer's finalized tip over `link`, iff its QC verifies against the
    /// trusted validator set of its epoch.
    async fn verified_tip_over(&self, link: &mut SyncLink) -> Tip {
        let Ok(resp) = link.ask_within("GET_FINALITY", QUICK_ASK_TIMEOUT).await else {
            return Tip::None;
        };
        let Some(qc) = resp
            .strip_prefix("FINALITY:")
            .and_then(|json| serde_json::from_str::<FinalityArtifact>(json).ok())
            .and_then(|artifact| artifact.qc)
        else {
            return Tip::None;
        };
        let Some(validators) = self.trusted_validator_set(qc.epoch) else {
            // B57: no committee yet for its epoch, past this node's tip.
            return if qc.block_height > self.get_local_height() {
                Tip::Ahead
            } else {
                Tip::None
            };
        };
        match consensus::qc::verify_qc(&qc, &validators, &consensus::qc::expected_chain_id()) {
            Ok(()) => Tip::Verified(Box::new(qc)),
            Err(_) => Tip::None,
        }
    }

    /// Process synced blocks — returns the final height reached
    #[cfg(test)]
    fn process_blocks(&self, blocks: Vec<Block>, current_height: u64) -> u64 {
        self.process_blocks_with_qcs(blocks, &[], current_height)
    }

    /// `process_blocks` with the peer's per-height QCs. On a V4 chain (G1
    /// IM-1) a block is executed only together with a QC that verifies under
    /// its epoch's committee and binds its hash, anchor and roots; the QC is
    /// imported with it. A proposer signature alone is not enough.
    fn process_blocks_with_qcs(
        &self,
        blocks: Vec<Block>,
        qcs: &[consensus::qc::QuorumCertificate],
        current_height: u64,
    ) -> u64 {
        let v4 = consensus::v4::is_v4_chain(&self.storage);
        let qc_of = |b: &Block| -> Option<&consensus::qc::QuorumCertificate> {
            qcs.iter().find(|q| q.block_height == b.header.height)
        };
        let mut last_processed = current_height;
        let executor = executor::Executor::new(std::sync::Arc::clone(&self.storage));
        let total_blocks = blocks.len();
        let finalized_round = self.finalized_round_boundary();

        // AUDIT-H2 (verify-before-execute, QC pin): `consensus:qc:latest` is only
        // ever written AFTER apply_finality_artifact has cryptographically
        // verified a quorum certificate (chain-id + trusted-validator-set bound)
        // — so its (block_height, block_hash) is an AUTHENTICATED pin. If this
        // downloaded batch claims to contain the certified height, its block
        // there MUST carry the certified hash; a mismatch proves the peer is
        // serving a fabricated chain, and the ENTIRE batch is rejected BEFORE a
        // single transaction of it executes. Blocks above the pin (not yet
        // certified) keep today's defense (execute + re-derived-root check +
        // reject), and the executor's own signature/nonce gates bound what an
        // unauthenticated block can do. This closes H-2's "forged block executes
        // first, gets rejected after" window for everything at or below the
        // latest certified height.
        if let Ok(Some(qc_json)) = self.storage.get("consensus:qc:latest") {
            if let Ok(qc) = serde_json::from_str::<consensus::qc::QuorumCertificate>(&qc_json) {
                if let Some(b) = blocks.iter().find(|b| b.header.height == qc.block_height) {
                    if b.header.hash != qc.block_hash {
                        // G1 IM-3 (V4): the peer's block has its own verified
                        // QC. Two certified blocks at one height is a conflict.
                        if v4 {
                            if let Some(q) = qc_of(b) {
                                if consensus::qc_producer::verify_block_qc(&self.storage, b, q)
                                    .is_ok()
                                {
                                    consensus::qc_producer::record_decision_conflict(
                                        &self.storage,
                                        b.header.height,
                                        &format!(
                                            "{}: two QCs at height {}: {} and {}",
                                            consensus::ordering::DECISION_CONFLICT,
                                            b.header.height,
                                            qc.block_hash,
                                            b.header.hash
                                        ),
                                    );
                                }
                            }
                        }
                        eprintln!(
                            "🚨 [SECURITY][SYNC_QC_PIN_REJECT] peer's block #{} hash {} does not \
                             match the QC-certified hash {} — rejecting the whole batch before \
                             execution (fabricated chain)",
                            qc.block_height, b.header.hash, qc.block_hash
                        );
                        return last_processed;
                    }
                }
            }
        }

        for (i, block) in blocks.iter().enumerate() {
            if block.header.height <= last_processed {
                let key = format!("block_{}", block.header.height);
                if let Ok(Some(existing_json)) = self.storage.get(&key) {
                    if let Ok(existing) = serde_json::from_str::<Block>(&existing_json) {
                        if existing.header.hash == block.header.hash {
                            // A held block's missing QC (a crash lost it, or it
                            // never formed here) is imported from the peer's.
                            if v4
                                && consensus::qc_producer::stored_qc(
                                    &self.storage,
                                    block.header.height,
                                )
                                .is_none()
                            {
                                if let Some(q) = qc_of(block) {
                                    self.import_block_qc(q);
                                }
                            }
                            continue;
                        }
                        if existing.header.round <= finalized_round
                            || block.header.round <= finalized_round
                        {
                            eprintln!(
                                "🚨 [SECURITY][SYNC_REORG_REJECT] conflict at finalized boundary height={} local_round={} remote_round={} finalized_round={}",
                                block.header.height,
                                existing.header.round,
                                block.header.round,
                                finalized_round
                            );
                            break;
                        }
                        // G1 IM-3 (V4): a verified QC for this other block
                        // proves the local chain is not the certified one.
                        // Halt with the alarm; never serve or build on it.
                        if v4 {
                            if let Some(q) = qc_of(block) {
                                if consensus::qc_producer::verify_block_qc(&self.storage, block, q)
                                    .is_ok()
                                {
                                    let why = format!(
                                        "{}: a QC certifies block {} at height {}, this node holds {}",
                                        consensus::ordering::DECISION_CONFLICT,
                                        block.header.hash,
                                        block.header.height,
                                        existing.header.hash
                                    );
                                    consensus::qc_producer::record_decision_conflict(
                                        &self.storage,
                                        block.header.height,
                                        &why,
                                    );
                                    break;
                                }
                            }
                        }
                        // A proposer signature or a longer peer chain is not a
                        // fork-choice proof. Even zero-TX blocks advance execution
                        // and may sweep fees or advance epochs. Deleting block rows
                        // cannot undo that state, QC indexes or ordering history.
                        // Until authenticated fork adoption and atomic state recovery
                        // exist, reject every conflict without writes or a halt latch.
                        eprintln!(
                            "[SECURITY][SYNC_REORG_REJECT] conflict at height {} requires authenticated fork choice and complete state recovery; preserving local chain",
                            block.header.height
                        );
                        break;
                    } else {
                        eprintln!(
                            "🚨 [SECURITY][SYNC_REORG_REJECT] corrupt local block json at height {}",
                            block.header.height
                        );
                        break;
                    }
                } else {
                    continue;
                }
            }

            let expected_height = last_processed + 1;
            let prev_hash = if expected_height > 1 {
                let prev_key = format!("block_{}", last_processed);
                match self
                    .storage
                    .get(&prev_key)
                    .ok()
                    .flatten()
                    .and_then(|json| serde_json::from_str::<Block>(&json).ok())
                    .map(|b| b.header.hash)
                {
                    Some(hash) => hash,
                    None => {
                        eprintln!(
                            "🚨 [SECURITY] Cannot verify parent for block #{}: missing local block #{}",
                            expected_height, last_processed
                        );
                        break;
                    }
                }
            } else {
                "genesis".to_string()
            };

            if let Err(e) = self.validate_block(block, expected_height, &prev_hash) {
                eprintln!(
                    "🚨 [SECURITY] Block #{} validation FAILED: {}",
                    block.header.height, e
                );
                break;
            }
            let qc = if v4 {
                let checked = qc_of(block).map(|q| {
                    consensus::qc_producer::verify_block_qc(&self.storage, block, q).map(|()| q)
                });
                match checked {
                    Some(Ok(q)) => Some(q.clone()),
                    Some(Err(e)) => {
                        eprintln!(
                            "🚨 [SECURITY][SYNC_QC_REJECT] block #{}: {e}",
                            block.header.height
                        );
                        break;
                    }
                    None => {
                        eprintln!(
                            "[ChainSync] block #{} came without its QC; not executed (V4)",
                            block.header.height
                        );
                        break;
                    }
                }
            } else {
                None
            };

            // Validate roots and stage block/index storage in the SAME transaction
            // as execution. Rejection must not consume a nonce or execution height.
            #[cfg(test)]
            if let Some(hook) = self.before_execution_hook {
                hook(&self.storage);
            }
            // B23: only an alarm this block's import raises can halt.
            consensus::alarm::clear();
            match executor.execute_block_admitted_at(
                block.transactions.clone(),
                &block.header.proposer_id,
                // The synced block's own height (epoch determinism — see
                // executor::execute_block_parallel_at).
                block.header.height,
                // G5 CL-2: its certified BFT timestamp drives consensus time.
                block.header.timestamp,
                // G5 BW-6: its certified anchor round.
                block.header.round,
                // RE-AUDIT HIGH: the block's own slash evidence, verified by
                // the executor — identical on every node.
                &block.slash_evidence,
                &block.committed_authors,
                |view| Self::validate_admission_in(view, block),
                |summary, view| {
                    Self::verify_execution_roots_in(block, summary)?;
                    let json = serde_json::to_string(block).map_err(|e| e.to_string())?;
                    view.save_block_json(block.header.height, &json).map_err(|e| e.to_string())?;
                    // G1 EP-2/EP-3: an imported boundary block closes its epoch
                    // in its own transaction, so H_E + 1's QC verifies under
                    // C_{E+1}. EP-4: QC(H_E) must bind the committee derived.
                    // G1 IM-2 (V4): the block's QC is stored in the block's own
                    // transaction; a crash between them used to leave the
                    // block without its QC, and adoption waiting forever.
                    if let Some(q) = &qc {
                        consensus::qc_producer::stage_block_qc(view, q)?;
                    }
                    if let Some(start) = consensus::v4::epoch::stage_boundary(view, block)? {
                        let derived = consensus::qc::validator_set_hash(&start.committee);
                        if let Some(q) = &qc {
                            if q.next_validator_set_hash != derived {
                                return Err(consensus::alarm::raise(
                                    consensus::alarm::Alarm::CommitteeMismatch,
                                    format!(
                                        "{}: QC(H_{}) binds next committee {:?}, this node derived {derived}",
                                        consensus::v4::epoch::COMMITTEE_MISMATCH,
                                        start.epoch - 1,
                                        q.next_validator_set_hash
                                    ),
                                ));
                            }
                        }
                    }
                    Ok(())
                },
            ) {
                Ok(executor::BlockExecOutcome::Executed(_)) => {
                    // (its QC was stored in the same transaction)
                    last_processed = block.header.height;
                    consensus::dag::prune_history(&self.storage, last_processed, self.retention);
                }
                Ok(executor::BlockExecOutcome::AlreadyExecuted { last_executed }) => {
                    // Execution completion alone does not identify the block.
                    // Missing storage may mean an in-flight producer OR a crash
                    // between execution and save_block_json. Wait for a matching
                    // persisted block; never infer identity from the height.
                    let stored = self
                        .storage
                        .get(&format!("block_{}", block.header.height))
                        .ok()
                        .flatten()
                        .and_then(|j| serde_json::from_str::<Block>(&j).ok())
                        .map(|b| b.header.hash);
                    match stored {
                        Some(h) if h != block.header.hash => {
                            eprintln!(
                                "🚨 [SECURITY][SYNC_HEIGHT_ALREADY_EXECUTED] peer's block #{} hash {} \
                                 conflicts with our stored {} at an executed height (last_executed={}) \
                                 — rejecting this peer's batch",
                                block.header.height, block.header.hash, h, last_executed
                            );
                            break;
                        }
                        Some(_) => {
                            last_processed = last_processed.max(block.header.height);
                            if let Some(q) = &qc {
                                self.import_block_qc(q);
                            }
                            continue;
                        }
                        None => {
                            eprintln!(
                                "[ChainSync][EXECUTION_WITHOUT_BLOCK] height {} was executed \
                                 (last_executed={}) but its stored block is missing or unreadable; \
                                 stopping this batch without advancing sync",
                                block.header.height, last_executed
                            );
                            break;
                        }
                    }
                }
                // Executing out of order would corrupt the state-root chain.
                Ok(executor::BlockExecOutcome::Gap { expected, got }) => {
                    eprintln!(
                        "⏸️  [ChainSync] execution gap: expected height {}, peer offered {} — stopping this batch",
                        expected, got
                    );
                    break;
                }
                Err(error) => {
                    // The error can be invalid roots OR local storage failure.
                    // Neither authorizes progress or a permanent peer-triggered halt.
                    eprintln!(
                        "[ChainSync][BLOCK_ACCEPTANCE_FAILED] block #{} was not accepted: {}",
                        block.header.height, error
                    );
                    // Except EP-4's: a verified QC(H_E) (>2/3 of C_E) certifies
                    // a next committee this node did not derive from the same
                    // post-state. That is not a peer's fault: the node halts.
                    if consensus::alarm::take() == Some(consensus::alarm::Alarm::CommitteeMismatch) {
                        if let Some(interval) = consensus::v4::epoch::epoch_interval(&self.storage) {
                            let next = consensus::v4::epoch::epoch_of_height(
                                block.header.height,
                                interval,
                            ) + 1;
                            let _ = self.storage.put(
                                &format!("alarm:committee_mismatch:{next:020}"),
                                &error,
                            );
                        }
                    }
                    break;
                }
            }

            // Progress logging for large syncs
            if total_blocks > 10 && (i + 1) % 50 == 0 {
                println!(
                    "📦 [ChainSync] Progress: {}/{} blocks processed",
                    i + 1,
                    total_blocks
                );
            }
        }
        if last_processed > current_height {
            println!(
                "✅ [ChainSync] Synced up to block #{} (+{} blocks)",
                last_processed,
                last_processed - current_height
            );
        }
        last_processed
    }

    /// Store a verified block QC (IM-1/IM-4). Idempotent; a failure only
    /// delays adoption, which waits for a stored QC.
    fn import_block_qc(&self, q: &consensus::qc::QuorumCertificate) {
        if let Err(e) = consensus::qc_producer::import_finality_qc(&self.storage, q) {
            eprintln!(
                "[ChainSync] QC of block #{} not stored ({e}); adoption waits",
                q.block_height
            );
        }
    }

    /// The requests `handle_message` answers. The node's session layer routes
    /// exactly these here, so a request type is added in one place.
    pub fn serves(msg: &str) -> bool {
        msg == "GET_HEIGHT"
            || msg == "GET_FINALITY"
            || [
                "SYNC_REQ:",
                PART_REQ,
                state_sync::ANCHOR_REQ,
                state_sync::CHUNK_REQ,
                state_sync::VALUE_REQ,
            ]
            .iter()
            .any(|prefix| msg.starts_with(prefix))
    }

    /// G4 S1/S6: a request a libp2p session sent: what `serves` lists
    /// (snapshot serving charged to `peer`, the key the session
    /// authenticated), and a boundary QC (`QC_WANT:h`, answered
    /// `QC_CERT:{qc}` for a held height, so an observer can activate an
    /// epoch).
    pub fn serve_session(&self, msg: &str, peer: &str) -> Option<String> {
        self.serve_session_from(msg, peer, false)
    }

    /// `serve_session` charged to `client` (B131: a member's or a reserved
    /// peer's key, or another peer's network group); `kept`: a reserved
    /// peer (B178).
    pub fn serve_session_from(&self, msg: &str, client: &str, kept: bool) -> Option<String> {
        let peer = client;
        if let Some(height) = msg.strip_prefix(consensus::dag::QC_WANT_PREFIX) {
            let height = height.parse::<u64>().ok()?;
            if height > self.get_local_height() {
                return None;
            }
            let qc = consensus::qc_producer::stored_qc(&self.storage, height)?;
            return Some(format!(
                "{}{}",
                consensus::dag::QC_CERT_PREFIX,
                serde_json::to_string(&qc).ok()?
            ));
        }
        if Self::serves(msg) {
            self.handle_request(msg, Some(peer), kept)
        } else {
            None
        }
    }

    /// A request from an in-process caller (global limits only).
    pub fn handle_message(&self, msg: &str) -> Option<String> {
        self.handle_request(msg, None, false)
    }

    /// A request charged to `client` (`None` is an in-process caller,
    /// global limits only); `kept`: a kept client (B131, B178: a reserved
    /// peer).
    fn handle_request(&self, msg: &str, client: Option<&str>, kept: bool) -> Option<String> {
        // Handle Request Logic
        if msg == "GET_HEIGHT" {
            let h = self.get_local_height();
            return Some(format!("HEIGHT:{}", h));
        }

        if msg == "GET_FINALITY" {
            if let Ok(json) = serde_json::to_string(&self.collect_finality_artifact()) {
                return Some(format!("FINALITY:{}", json));
            }
            return None;
        }

        if let Some(req_json) = msg.strip_prefix(state_sync::CHUNK_REQ) {
            let req = serde_json::from_str::<state_sync::ChunkRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.serve_state_chunk_as(req, client, kept)).ok()?;
            return Some(format!("{}{}", state_sync::CHUNK_RESP, resp));
        }
        if let Some(req_json) = msg.strip_prefix(state_sync::VALUE_REQ) {
            let req = serde_json::from_str::<state_sync::ValueRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.serve_state_value_as(req, client, kept)).ok()?;
            return Some(format!("{}{}", state_sync::VALUE_RESP, resp));
        }
        if let Some(req_json) = msg.strip_prefix(state_sync::ANCHOR_REQ) {
            let req = serde_json::from_str::<state_sync::AnchorRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.handle_state_anchor(req)).ok()?;
            return Some(format!("{}{}", state_sync::ANCHOR_RESP, resp));
        }
        if let Some(req_json) = msg.strip_prefix("SYNC_REQ:") {
            if let Ok(req) = serde_json::from_str::<SyncRequest>(req_json) {
                let resp = self.handle_sync_request(req);
                if let Ok(resp_json) = serde_json::to_string(&resp) {
                    return Some(format!("SYNC_RESP:{}", resp_json));
                }
            }
        }
        if let Some(req_json) = msg.strip_prefix(PART_REQ) {
            let req = serde_json::from_str::<BlockPartRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.handle_block_part(req)).ok()?;
            return Some(format!("{PART_RESP}{resp}"));
        }
        None
    }

    /// `SYNC_PART` (B264): `part_bytes` of the stored block at `height`
    /// from `offset`. B275: only a block known to be too large for a batch
    /// (a batch answer named it) is served in parts, and nothing is read
    /// for any other (a request for any height read its whole block); it is
    /// read once for all its parts (kept in `parted_blocks`). The part is the
    /// block's text, cut at a character boundary.
    pub fn handle_block_part(&self, req: BlockPartRequest) -> BlockPartResponse {
        let refuse = |why: &str| BlockPartResponse {
            error: Some(why.to_string()),
            ..Default::default()
        };
        let Some(big) = self
            .oversized_known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_mut(&req.height)
            .map(|(big, used)| {
                *used = std::time::Instant::now();
                big.clone()
            })
        else {
            return refuse("not a block served in parts");
        };
        if req.offset >= big.len {
            return refuse("offset past the block");
        }
        let kept = self
            .parted_blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(req.height, PARTED_KEY);
        let block = match kept {
            Some(block) => block,
            None => {
                {
                    let mut due = self
                        .parted_read_due
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let now = std::time::Instant::now();
                    if due.is_some_and(|at| now < at) {
                        return refuse(state_sync::BUSY);
                    }
                    *due = Some(now + parted_read_wait(big.len));
                }
                match self.storage.get(&format!("block_{}", req.height)) {
                    Ok(Some(json)) if json.len() as u64 == big.len => {
                        self.keep_parted(req.height, json.into_bytes())
                    }
                    _ => return refuse("no such block"),
                }
            }
        };
        // A continuation byte (10xxxxxx) starts no character.
        let boundary = |i: usize| i >= block.len() || block[i] & 0xC0 != 0x80;
        let start = req.offset as usize;
        if !boundary(start) {
            return refuse("offset inside a character");
        }
        let mut end = block.len().min(start + self.part_bytes());
        while !boundary(end) {
            end -= 1;
        }
        match std::str::from_utf8(&block[start..end]) {
            Ok(data) if end > start => BlockPartResponse {
                data: data.to_string(),
                len: big.len,
                error: None,
            },
            _ => refuse("no whole character to send"),
        }
    }

    /// B264: keep a block's bytes for its parts.
    fn keep_parted(&self, height: u64, block: Vec<u8>) -> Arc<Vec<u8>> {
        let block = Arc::new(block);
        self.parted_blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(height, PARTED_KEY, Arc::clone(&block));
        block
    }

    /// B275: a block at `height`, read as `json`, is too large for a batch:
    /// known from now on by its length and header, and kept for its parts.
    fn learn_oversized(&self, height: u64, json: String) -> Option<OversizedBlock> {
        let header = header_of(&json).filter(|h| h.height == height)?;
        let big = OversizedBlock {
            height,
            len: json.len() as u64,
            header,
        };
        {
            let mut known = self
                .oversized_known
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            // B288: the one asked for longest ago goes (the lowest height
            // went: the very block a lagging client was fetching).
            if !known.contains_key(&height) && known.len() >= MAX_OVERSIZED_KNOWN {
                if let Some(stale) = known
                    .iter()
                    .min_by_key(|(_, (_, used))| *used)
                    .map(|(height, _)| *height)
                {
                    known.remove(&stale);
                }
            }
            known.insert(height, (big.clone(), std::time::Instant::now()));
        }
        self.keep_parted(height, json.into_bytes());
        Some(big)
    }

    pub fn handle_sync_request(&self, req: SyncRequest) -> SyncResponse {
        let mut blocks_to_send = Vec::new();
        let local_height = self.get_local_height();

        // Limit batch size to avoid huge messages (Optimized to 500 for Production Performance)
        // B144: saturating, as the height is the peer's: near u64::MAX it
        // wrapped (a release build served from 0) or panicked (overflow
        // checks).
        let end_height = std::cmp::min(local_height, req.from_height.saturating_add(500));
        // NI-4: and by bytes, so the answer fits what a client reads (500
        // full blocks would be far over it).
        let mut bytes = 0usize;
        let mut oversized = None;

        for height in req.from_height.saturating_add(1)..=end_height {
            // B275: a block known to be too large is named without a read
            // (each request beside one read it whole, for a few bytes).
            let known = self
                .oversized_known
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&height)
                .map(|(big, _)| big.clone());
            if let Some(big) = known {
                if blocks_to_send.is_empty() {
                    oversized = Some(big);
                }
                break;
            }
            let key = format!("block_{}", height);
            if let Ok(Some(block_data)) = self.storage.get(&key) {
                // B264: a block no batch holds is never in one (it went
                // alone, over the frame, and no client could read it): the
                // answer names it, and it is kept for the parts asked next.
                if block_data.len() > self.batch_bytes {
                    let big = self.learn_oversized(height, block_data);
                    if blocks_to_send.is_empty() {
                        oversized = big;
                    }
                    break;
                }
                if bytes + block_data.len() > self.batch_bytes {
                    break;
                }
                if let Ok(block) = serde_json::from_str::<Block>(&block_data) {
                    bytes += block_data.len();
                    blocks_to_send.push(block);
                }
            }
        }
        // Prune-horizon signal (audit #9): trigger whenever the FIRST requested
        // block is missing — not only when the whole batch is empty. Otherwise a
        // request whose start is pruned but whose tail (e.g. from_height+50)
        // still exists returns non-empty blocks the requester cannot apply (height
        // gap) AND no signal, so it never learns it must state-sync.
        let first_block_pruned = req.from_height < local_height
            && self
                .storage
                .get(&format!("block_{}", req.from_height + 1))
                .ok()
                .flatten()
                .is_none();
        let prune_horizon = if first_block_pruned {
            Some(self.earliest_available_block(req.from_height + 1, local_height))
        } else {
            None
        };
        let qcs = blocks_to_send
            .iter()
            .map(|b| b.header.height)
            .chain(oversized.as_ref().map(|big| big.height))
            .filter_map(|height| consensus::qc_producer::stored_qc(&self.storage, height))
            .collect();
        SyncResponse {
            blocks: blocks_to_send,
            finality: Some(self.collect_finality_artifact()),
            prune_horizon,
            qcs,
            oversized,
        }
    }

    /// Lowest block height still present, searched within `[lo, hi]`. After
    /// prefix-pruning, block existence is monotonic (absent below the horizon,
    /// present from it to the tip), so a binary search finds the horizon.
    fn earliest_available_block(&self, lo: u64, hi: u64) -> u64 {
        let exists = |h: u64| {
            self.storage
                .get(&format!("block_{}", h))
                .ok()
                .flatten()
                .is_some()
        };
        if exists(lo) {
            return lo;
        }
        let (mut lo, mut hi) = (lo, hi);
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if exists(mid) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    }
}

#[cfg(test)]
mod tests;

/// Test helper: the state root an empty block at `height` with BFT timestamp
/// `timestamp` would have on top of the executed chain, found by executing it
/// in a block transaction that is then discarded (nothing is written). It is
/// exact at any height, including boundary blocks, whose committee record and
/// epoch writes a fixture would otherwise have to predict.
#[cfg(test)]
pub(crate) fn dry_run_empty_block_root(storage: &Arc<StateDB>, height: u64, timestamp: u64) -> String {
    let executor = executor::Executor::new(Arc::clone(storage));
    let mut root = None;
    let outcome = executor.execute_block_admitted_at(
        vec![],
        "dry-run",
        height,
        timestamp,
        0,
        &[],
        &[],
        |_| Ok(()),
        |summary, _| {
            root = Some(summary.state_root.clone());
            Err("dry run".into())
        },
    );
    assert!(outcome.is_err(), "the dry run must not commit");
    root.expect("the parent height is executed")
}
