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
/// it asks for any shard (any block's height was enough to start a fetch).
/// B319: and its proposer's signature, which the import checks and no shard
/// carries (the body is all the DA root commits to).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OversizedBlock {
    pub height: u64,
    /// Its stored text's bytes (what made it too large for a batch).
    pub len: u64,
    pub header: blockchain::BlockHeader,
    pub proposer_signature: String,
    pub proposer_signer: String,
}

/// B319 (`SYNC_SHARD`): a piece of the block at `height`'s data shard
/// `index`, from `offset` into the shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRequest {
    pub height: u64,
    pub index: u64,
    pub offset: u64,
}

/// B319 (`SYNC_SHARD_RESP`): one piece of a data shard, or why none was
/// served. The piece that ends its shard carries the shard's inclusion proof
/// under the header's DA root.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ShardResponse {
    /// The body's length (the DA root binds it; a shard that verifies proves it).
    pub body_len: u64,
    pub index: u64,
    pub offset: u64,
    /// The piece, hex.
    pub data: String,
    /// The shard's proof (sibling hashes, hex), with the shard's last piece.
    pub proof: Vec<String>,
    pub error: Option<String>,
}

/// B319: the wire prefixes of a shard piece's request and answer.
pub const SHARD_REQ: &str = "SYNC_SHARD:";
pub const SHARD_RESP: &str = "SYNC_SHARD_RESP:";

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
    /// B417: the data shards each session's last turn that asked for blocks
    /// proved, and when; kept as `yields` is.
    shard_yields: Mutex<HashMap<String, (u64, std::time::Instant)>>,
    /// B424: the sessions whose last silent turn (`Turn::silent`) no piece or
    /// block has followed, and when it was; kept as `stalls` is. B439: with
    /// the height of the block it was silent on.
    silences: Mutex<HashMap<String, (u64, std::time::Instant)>>,
    /// B274: when each session last had a turn; among equals the one that
    /// waited longest goes first (the height a session advertised ordered
    /// them, and it is the session's own unauthenticated claim).
    turns: Mutex<HashMap<String, std::time::Instant>>,
    /// B319: the body and shard proofs of the block last served in shards,
    /// so its pieces cost one read and one extension.
    shard_source: Mutex<Option<(u64, Arc<ShardSource>)>>,
    /// B347: held while a shard source is built: one build at a time.
    shard_build: Mutex<()>,
    /// B275: the blocks known to be too large for a batch, by height, and
    /// (B288) when each was last asked for: the least recently asked goes
    /// first (the lowest height went, the one a lagging client fetches).
    oversized_known: Mutex<std::collections::BTreeMap<u64, (OversizedBlock, std::time::Instant)>>,
    /// B319: the block being fetched in shards, kept across turns and
    /// extended by any session's (`ShardFetch`).
    sharded: Mutex<Option<ShardFetch>>,
    /// B275: when a shard may next need its block read from storage (B291:
    /// later the more bytes the last read took).
    parted_read_due: Mutex<Option<std::time::Instant>>,
    /// B286: when each session was first and last seen above this node.
    seen: Mutex<HashMap<String, (std::time::Instant, std::time::Instant)>>,
    /// B388: the lowest block each session showed it can serve, when that
    /// was above this node's next (it pruned below), and when it showed it.
    pruned: Mutex<HashMap<String, (u64, std::time::Instant)>>,
    /// B286: this node's key for ordering sessions alike in every other
    /// respect (their PeerIds, which a Sybil grinds, ordered them).
    turn_salt: [u8; 16],
    /// B311: held for a whole pass (`sync_from_peers`).
    pass: tokio::sync::Mutex<()>,
    /// The encoded bytes a batch's blocks stop at (`SYNC_RESP_BLOCK_BYTES`;
    /// tests make it small, so real blocks are parted).
    batch_bytes: usize,
    /// B319: the largest stored text of a block fetched in shards
    /// (`MAX_PARTED_BLOCK_BYTES`); B365: its body is held up to
    /// `parted_body_budget` of it.
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

/// B466: the most characters of a peer's text one log line keeps (B342,
/// B448 and B443's cut).
const MAX_LOGGED_CHARS: usize = 200;

/// B466: `text`, which a peer chose in whole or in part (an error that
/// echoes a field it sent, its own refusal), for a log line: its first
/// `MAX_LOGGED_CHARS` characters, control characters escaped. B443 cut only
/// the gossip path's refused QC (`dag.rs`); sync printed the same refusals
/// whole, up to a 10 MiB answer a line, line breaks included (a forged log
/// line), and the restore returned them whole to the boot's FATAL line.
pub(crate) fn loggable(text: &str) -> String {
    text.escape_debug().take(MAX_LOGGED_CHARS).collect()
}

#[cfg(test)]
thread_local! {
    /// B466 witness support: the lines `log_line` wrote on this thread.
    static LOGGED: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// B466: a log line that carries a peer's text, cut (`loggable`).
pub(crate) fn log_line(line: String) {
    #[cfg(test)]
    LOGGED.with(|logged| logged.borrow_mut().push(line.clone()));
    eprintln!("{line}");
}

/// B466 witness support: the lines `log_line` wrote on this thread since
/// the last call.
#[cfg(test)]
pub(crate) fn take_logged() -> Vec<String> {
    LOGGED.with(|logged| std::mem::take(&mut *logged.borrow_mut()))
}

/// B433: whether `blocks` could be an honest answer to a request from
/// `current`: every block above it, each above the last, at most a batch
/// (`SYNC_TURN_BLOCKS`). A pruned server's answer may start past
/// `current + 1` (B388) and skip heights it does not hold; it never repeats
/// one, goes back, or answers at or below the requester's height.
fn honest_batch_shape(blocks: &[Block], current: u64) -> bool {
    blocks.len() as u64 <= SYNC_TURN_BLOCKS
        && blocks.first().is_none_or(|b| b.header.height > current)
        && blocks
            .windows(2)
            .all(|w| w[1].header.height > w[0].header.height)
}

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
    /// B388: its last answer (within `STRIKE_TTL`) showed it no longer
    /// holds this node's next block.
    cannot_serve: bool,
    member: bool,
    /// Strikes still counting (`STRIKE_TTL`).
    strikes: u32,
    /// Blocks its last turn that asked for blocks brought (0 if none).
    brought: u64,
    /// B417: the data shards its last turn that asked for blocks proved
    /// (0 if none). A parted fetch's turns bring no whole block, so an
    /// honest shard server tied with a session that names the block and
    /// answers busy, and rotated with every such stranger.
    shards: u64,
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
/// turn): each session's fetch waits for its turn, kept (B285). B417: after
/// the blocks brought, the data shards proved (what a parted fetch's turn
/// delivers, verified under the header's DA root).
fn turn_order(a: &(String, Standing), b: &(String, Standing)) -> std::cmp::Ordering {
    let ((_, sa), (_, sb)) = (a, b);
    sa.cannot_serve
        .cmp(&sb.cannot_serve)
        .then(sb.member.cmp(&sa.member))
        .then(sa.strikes.cmp(&sb.strikes))
        .then(sb.brought.cmp(&sa.brought))
        .then(sb.shards.cmp(&sa.shards))
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
    /// B417: the data shards of a parted block the turn proved.
    shards: u64,
    /// An answer took over `SLOW_ANSWER` and carried less than a full batch.
    slow: bool,
    /// The turn ended at the session's height, or at the block it offered
    /// without its QC (an honest server's newest; B445: a member's, that
    /// checks but for its QC), rather than on an error, an empty, refused or
    /// junk answer, or the turn's time.
    ended_well: bool,
    /// B274: the turn asked for blocks (it did not find this node already
    /// at the session's height).
    asked: bool,
    /// B275: the session sent what no honest server sends (a parted block
    /// that does not check, or does not import; B443: a finality QC that
    /// fails a check).
    refused: bool,
    /// The turn says nothing either way; bringing no whole block, it neither
    /// strikes its session nor clears its strikes. B287/B319: it added pieces
    /// to a shard fetch but proved no shard (a part's bytes made it full, so
    /// one junk part a turn kept a session clear while its fetch never
    /// ended; a proved shard ends the turn well). B302: it
    /// ended at a block without its QC further below the claimed height than
    /// `qcless_tip` allows (a direct commit after a stall builds a block for
    /// every anchor it decides, so an honest server can hold any number
    /// without their QCs, and B289's bound struck it every pass).
    unjudged: bool,
    /// B424: a parted fetch's server named the block, then sent no piece and
    /// no busy answer: an ask it left unanswered past `SLOW_ANSWER`, or a
    /// refusal. Unjudged once (an honest server builds the block's source
    /// inside the first ask, past its timeout); struck the next time it
    /// comes before a piece (`silence_verdict`). B439: the height of the
    /// block it was silent on.
    silent: Option<u64>,
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

    /// B323: the turn's verdict on its session: `Some(true)` a strike,
    /// `Some(false)` its strikes cleared, `None` neither. A slow or refused
    /// answer strikes whatever else the turn did: an unjudged turn was never
    /// struck, so a session answering each request at the turn's edge,
    /// behind a QC-less block far below its claim, stayed clear for good.
    /// An unjudged turn that brought whole blocks clears (an honest server
    /// reaching its QC-less backlog after a few certified blocks was struck);
    /// one that brought none says nothing.
    fn verdict(&self) -> Option<bool> {
        if self.slow || self.refused {
            Some(true)
        } else if self.unjudged {
            (self.brought > 0).then_some(false)
        } else {
            Some(self.struck())
        }
    }
}

/// B424: `turn`'s verdict on `peer` (`Turn::verdict`), its silence counted
/// in `silences`: a silent turn nothing else judged is struck when the
/// session's last silent turn (within `STRIKE_TTL`) had no piece or block
/// after it, else noted. B416 left every turn without a piece unjudged, so
/// a session naming the real block and then never answering kept no strike
/// for good, ahead of every honest server holding one. An honest server is
/// silent once: it builds the block's source inside the first ask, past
/// its timeout, keeps it, and serves the next ask from it (or answers busy
/// while another block's build holds it, which says nothing). B439: silent
/// once a block: a session's silence counts against it only on the block
/// its last silence was on. Any silence counted, so an honest server was
/// struck at the second block it had to build for this node (the fetch
/// moved on to the next oversized block before it served a piece of the
/// first). Silent twice on one block is still struck, even when its source
/// was replaced between the two asks (another client's block, built after
/// its gate): this node cannot tell that from a server that never answers.
fn silence_verdict(
    silences: &mut HashMap<String, (u64, std::time::Instant)>,
    peer: &str,
    turn: &Turn,
    at: std::time::Instant,
) -> Option<bool> {
    let verdict = turn.verdict();
    silences.retain(|_, (_, since)| at.saturating_duration_since(*since) < STRIKE_TTL);
    if turn.brought > 0 || turn.bytes > 0 {
        silences.remove(peer);
    } else if let (Some(height), None) = (turn.silent, verdict) {
        let again = silences.get(peer).is_some_and(|(on, _)| *on == height);
        keep_standing(silences, peer.to_string(), (height, at), |(_, since)| {
            *since
        });
        if again {
            return Some(true);
        }
    }
    verdict
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

/// B445: what a batch's import reached, and the block it stopped at for
/// want of its QC alone (V4), if it did: one that passed every check a block
/// needs no QC for (`validate_header_in`). Any other stop (a block that does
/// not check, a QC that does not verify, an execution that fails) names
/// none: such a block is no server's newest work.
struct Imported {
    reached: u64,
    qcless: Option<u64>,
}

/// NI-4: the blocks of one SYNC_RESP stop at this many bytes, so the answer
/// stays under the 10 MiB a client reads. B264: a block larger than this is
/// never in a batch; it is named (`SyncResponse::oversized`) and sent in
/// parts.
pub const SYNC_RESP_BLOCK_BYTES: usize = 8 << 20;

/// B319: the raw bytes of one shard piece: a quarter of a batch's cut, so
/// as hex it fits the frame a batch's half did as text.
pub const SHARD_PIECE_BYTES: usize = SYNC_RESP_BLOCK_BYTES / 4;

/// B264: the largest block a client fetches in shards. An import holds about
/// six copies of a block's bytes at once (the shards, the parsed block, its
/// body bytes and their Reed-Solomon extension, the stored row), so 512 MiB
/// keeps one within half the documented 8 GB minimum. A block this large
/// lists about four million committed vertices at 134 bytes each, and every
/// node that built it held each of them in its DAG at a kilobyte or more:
/// half that minimum as well.
pub const MAX_PARTED_BLOCK_BYTES: u64 = 512 << 20;

/// B365: the largest body a block of at most `text` bytes of stored text
/// has. An honest body field costs no more bytes than its text, but a
/// committed vertex's: two 64-hex strings, 134 bytes of text (quotes and a
/// comma each) and 144 of body (an 8-byte length each); the rest is the
/// domain and a few lengths, which a page covers. One number bounded both
/// the text and the body: a block of 476-512 MiB of text has a body past
/// 512 MiB, so it never arrived, and every honest server serving it was
/// struck.
pub(crate) fn parted_body_budget(text: u64) -> u64 {
    text.saturating_mul(144) / 134 + 4096
}

/// B275: the blocks a server knows are too large for a batch, by height,
/// at most this many (a choice; such blocks are rare, an entry is a
/// header): a request beside one is answered from what is known, not by
/// reading the block again.
const MAX_OVERSIZED_KNOWN: usize = 256;

/// B356: an honest server's slowest pace for shard pieces (B301's bound:
/// its answer budget sends about 0.8 MiB/s to a client); a turn of pieces
/// slower than this that proved no shard is slow. Tests cut blocks into
/// pieces of a few hundred bytes.
#[cfg(not(test))]
const MIN_PIECE_BYTES_PER_SEC: u64 = 128 << 10;
#[cfg(test)]
const MIN_PIECE_BYTES_PER_SEC: u64 = 64;

/// B275: a shard that needs its block read from storage (not kept) waits
/// this long after the last such read, answered busy meanwhile: clients
/// fetching two large blocks at once made every piece a whole block's read.
const PARTED_READ_EVERY: Duration = Duration::from_secs(1);

/// B291: and longer after a large read, at this many bytes a second (a
/// choice, under a spinning disk's rate): one read a second of up to
/// 512 MiB each was a disk's whole rate.
const PARTED_READ_BYTES_PER_SEC: u64 = 64 << 20;

/// B291: how long after reading a block of `len` bytes for its shards the
/// next such read waits.
fn parted_read_wait(len: u64) -> Duration {
    PARTED_READ_EVERY.max(Duration::from_millis(
        len.saturating_mul(1000) / PARTED_READ_BYTES_PER_SEC,
    ))
}

/// B275: why a shard fetch stopped short.
enum PartFailure {
    /// No answer (a timeout, a lost session), or (B288) a refusal an honest
    /// server can give (a block it no longer indexes or holds): proves
    /// nothing; the shards verified are kept for any session's next turn.
    Lost(String),
    /// An answer no honest server sends (B319: a shard that does not prove
    /// under the header's DA root): its session is struck.
    Lied(String),
}

/// B319: a block too large for a batch, fetched as its DA data shards, each
/// verified against the QC-bound header's `da_root` when it completes, from
/// whichever sessions serve them: one fetch for the block. B309/B301: parts
/// of the stored text could be checked only once the whole arrived, and each
/// node's text differs (its proposer's signature), so a fetch was a
/// session's own: one session naming a real header at 512 MiB fed junk and
/// pinned the budget, and past about seven members above a node no fetch
/// kept pace with its deadline. A lie now costs at most a shard, and every
/// session's turn extends the one fetch.
struct ShardFetch {
    big: OversizedBlock,
    /// The body's length: the one the first verified shard proved.
    body_len: Option<u64>,
    /// The data shards verified so far (as many as the layout has, once the
    /// length is known).
    shards: Vec<Option<Vec<u8>>>,
    /// B387: each session's unfinished shard (its index, the bytes so far,
    /// the length it claimed), resumed at its next turn only: a liar spoils
    /// only its own. `MAX_PARTIALS` at most. B415: kept until it proves,
    /// its shard proves from another session, or its session lies; B423:
    /// or, the store full, it is the one kept longest ago. In the order
    /// kept.
    partials: Vec<(String, u64, Vec<u8>, Option<u64>)>,
}

/// B387: sessions' unfinished shards kept at once. B415: as many as a body
/// has data shards (a shard is at most 1/128 of a body within the fetch's
/// budget, so they hold at most one more body). Eight, the oldest evicted
/// first, were all pushed between two turns of a session when nine or more
/// took turns in rotation, so a shard of two turns or more never finished.
const MAX_PARTIALS: usize = da::MAX_DATA_SHARDS as usize;

impl ShardFetch {
    fn new(big: OversizedBlock) -> Self {
        Self {
            big,
            body_len: None,
            shards: Vec::new(),
            partials: Vec::new(),
        }
    }

    /// B387/B415: the data shard `peer`'s turn asks for, with its bytes so
    /// far and the length claimed for them: `peer`'s unfinished shard (taken
    /// out) while it is still missing and agrees with the proved length;
    /// else the first missing shard no other session's unfinished one
    /// covers, from its start (the first missing when every one is covered).
    /// Every session restarted the first missing shard, the same one. B423:
    /// before a shard proves the length, shard 0 (`next_missing`): B415
    /// spread sessions over the fewest shards the unfinished shards' claimed
    /// lengths gave, so when every unfinished shard was a stranger's, the
    /// spread was theirs to choose, unchecked.
    fn turn_shard(&mut self, peer: &str) -> (u64, Vec<u8>, Option<u64>) {
        if let Some(at) = self.partials.iter().position(|(p, ..)| p == peer) {
            let (_, index, bytes, claimed) = self.partials.remove(at);
            let agrees = self.body_len.is_none() || claimed == self.body_len;
            if agrees && self.missing(index) {
                return (index, bytes, claimed.or(self.body_len));
            }
        }
        if self.body_len.is_none() {
            return (self.next_missing(), Vec::new(), None);
        }
        let index = (0..self.shards.len() as u64)
            .find(|i| self.missing(*i) && !self.partials.iter().any(|(_, held, ..)| held == i))
            .unwrap_or_else(|| self.next_missing());
        (index, Vec::new(), self.body_len)
    }

    /// B415: whether data shard `index` is still to prove.
    fn missing(&self, index: u64) -> bool {
        self.shards.get(index as usize).is_none_or(Option::is_none)
    }

    /// B387: `peer`'s unfinished shard kept for its next turn. A busy answer
    /// ends a turn (B376), and the bytes were dropped with it: under the
    /// server's answer budget (about 65 tokens a 2 MiB piece, 12.8 a second)
    /// a shard of two pieces or more never finished. B423: with
    /// `MAX_PARTIALS` held, the one whose session's turn ended longest ago
    /// goes (first in the list: each is pushed at its session's turn's end).
    /// B415 kept none for a session holding none, so strangers' unfinished
    /// shards, never proved and never lied about, held the store for good
    /// and no honest session's shard of two turns could finish. A session in
    /// rotation now loses its own only when more than `MAX_PARTIALS` other
    /// turns came between two of its own: at `SYNC_PEERS_PER_PASS` (3) a
    /// pass, over 42 passes.
    fn keep_partial(&mut self, peer: &str, index: u64, bytes: Vec<u8>, claimed: Option<u64>) {
        self.partials.retain(|(p, ..)| p != peer);
        if bytes.is_empty() {
            return;
        }
        if self.partials.len() >= MAX_PARTIALS {
            self.partials.remove(0);
        }
        self.partials
            .push((peer.to_string(), index, bytes, claimed));
    }

    /// The next data shard to ask for (0 before the length is known).
    fn next_missing(&self) -> u64 {
        self.shards.iter().position(Option::is_none).unwrap_or(0) as u64
    }

    /// A shard that verified under the header's DA root, for a body of
    /// `layout`.
    fn accept(&mut self, layout: da::Layout, index: u64, shard: Vec<u8>) {
        if self.body_len.is_none() {
            self.body_len = Some(layout.body_len);
            self.shards = vec![None; layout.data_shards as usize];
        }
        if let Some(slot) = self.shards.get_mut(index as usize) {
            *slot = Some(shard);
        }
        // B415: the unfinished shards this one or the proved length ends.
        let body_len = self.body_len;
        self.partials
            .retain(|(_, held, _, claimed)| *held != index && *claimed == body_len);
    }

    /// The block, once every data shard is in: the body the shards make,
    /// under the header and the proposer's signature named. `Err`: the body
    /// a QC-bound DA root commits to is no body (no honest chain makes one).
    fn block(&self) -> Option<Result<Block, String>> {
        let len = usize::try_from(self.body_len?).ok()?;
        // Asked after every shard: nothing is copied until all are in.
        if self.shards.iter().any(Option::is_none) {
            return None;
        }
        let mut body = Vec::with_capacity(self.shards.iter().flatten().map(Vec::len).sum());
        for shard in self.shards.iter().flatten() {
            body.extend_from_slice(shard);
        }
        body.truncate(len);
        Some(blockchain::body_from_bytes(&body).map(|parts| Block {
            header: self.big.header.clone(),
            transactions: parts.transactions,
            committed_vertices: parts.committed_vertices,
            committed_authors: parts.committed_authors,
            anchor_hash: parts.anchor_hash,
            proposer_signature: self.big.proposer_signature.clone(),
            proposer_signer: self.big.proposer_signer.clone(),
            slash_evidence: parts.slash_evidence,
        }))
    }
}

/// B319: what a server keeps to serve a block's data shards: its body, and
/// every shard's proof (the parity shards dropped once hashed).
struct ShardSource {
    body: Vec<u8>,
    proofs: da::ShardProofs,
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
            shard_yields: Mutex::default(),
            silences: Mutex::default(),
            turns: Mutex::default(),
            shard_source: Mutex::default(),
            shard_build: Mutex::default(),
            oversized_known: Mutex::default(),
            sharded: Mutex::default(),
            parted_read_due: Mutex::default(),
            seen: Mutex::default(),
            pruned: Mutex::default(),
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

    /// Tests only: a shard-fetch budget other than `MAX_PARTED_BLOCK_BYTES`.
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

    /// B319: the raw bytes of one shard piece (`SHARD_PIECE_BYTES` at the
    /// default cut; hex doubles them on the wire).
    fn piece_bytes(&self) -> usize {
        (self.batch_bytes / 4).max(1)
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

    /// Tests only: the whole check, roots included (B444: the import checks
    /// the roots apart, after the QC).
    #[cfg(test)]
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
        Self::validate_header_in(storage, block, expected_height, prev_hash)?;
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

    /// B444: every check of `validate_block_in` but the body's roots
    /// (`check_commitments`, whose DA root costs a Reed-Solomon extension):
    /// height and parent, eligible proposer and signer, the signature, and
    /// the anchor binding. Sync runs it before a block's QC, and the roots
    /// only under a QC that verifies (`import_blocks`). Of the body it reads
    /// each slash-evidence item's kind, the transaction count and the last
    /// committed vertex (the anchor), never a root.
    fn validate_header_in(
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
            // B443: the parent's header only (`header_of`), as the import's
            // precheck reads it (B433): its whole body (up to 512 MiB parted)
            // was parsed for every block imported, under the writer gate.
            let parent = blockchain::header_of(&parent_json)
                .ok_or("invalid parent at admission: no header")?;
            if parent.height != height - 1 {
                return Err("stored parent height mismatch at admission".into());
            }
            parent.hash
        };
        if let Some(json) = storage
            .get("consensus:qc:latest")
            .map_err(|e| e.to_string())?
        {
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

    /// B443: `artifact`, which a session sent, applied
    /// (`apply_finality_artifact`): whether its QC failed a check that no
    /// honest node's QC fails, counted as B51 counts them (`consensus::work`:
    /// an epoch that is not its height's, another committee, a non-canonical
    /// encoding, a stake check, the pairing). Such a QC is its session's
    /// lie. Sync logged the refusal and struck nobody, so any session it
    /// asked for finality could send a public QC's fields over another vote,
    /// with any signature, every pass.
    fn finality_lied(&self, artifact: &FinalityArtifact) -> bool {
        let (applied, failed) =
            consensus::work::failed_in(|| self.apply_finality_artifact(artifact));
        if let Err(e) = applied {
            // B466: the refusal echoes fields the session chose.
            log_line(format!(
                "🚨 [SECURITY][SYNC_FINALITY_REJECT] {}",
                loggable(&e)
            ));
        }
        failed > 0
    }

    /// B443: `finality`, which `turn`'s session sent, applied: a lie
    /// (`finality_lied`) refuses the turn, so its session is struck whatever
    /// else the turn did. The caller ends the turn on it: a session that
    /// lied in every answer cost a forged QC a batch.
    fn turn_finality(&self, turn: &mut Turn, finality: Option<FinalityArtifact>) -> bool {
        let lied = finality.is_some_and(|finality| self.finality_lied(&finality));
        turn.refused |= lied;
        lied
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
        self.drop_reached_fetch();
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
        // B390: nor while a consensus conflict halts ordering. Adoption has
        // stopped, so pruning keeps every block above it (B371), and sync
        // went on importing and executing blocks: the disk grew without end
        // on a node an operator has to look at anyway.
        if let Some(conflict) = consensus::dag::recorded_conflict(&self.storage) {
            eprintln!(
                "🛑 [ChainSync] not syncing: ordering is halted by a recorded conflict \
                 ({conflict}). Investigate, then clear it to resume."
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

    /// B319: a shard fetch of a height this node holds goes (its proved
    /// shards and unfinished ones, up to about a body and a half). It needs
    /// no deadline: a lie costs at most a shard, and any session extends it.
    /// B438: dropped at every pass's start, before anything can end the
    /// pass: it was dropped only past the halt checks, the session list and
    /// the tip gate, so a node that reached the block another way and then
    /// halted, lost its sessions or met a tip disagreement kept it until the
    /// next oversized block or a restart.
    fn drop_reached_fetch(&self) {
        let local = self.get_local_height();
        let mut sharded = self.sharded.lock().unwrap_or_else(|e| e.into_inner());
        if sharded.as_ref().is_some_and(|f| f.big.height <= local) {
            *sharded = None;
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
        // B446: not on V4, where every block sync imports needs its own QC
        // (IM-1) and finality moves only by a verified QC, so the gate adds
        // nothing a pass does not check anyway, and cost liveness alone: N
        // above the member sessions that answer (with N = 3 at n = 4, one
        // member silent or sending a QC that fails) refused every pass, so a
        // member that fell behind never caught up, and each silent member
        // added a 5 s ask to every pass.
        if tip_n > 1 && !consensus::v4::is_v4_chain(&self.storage) {
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
                let answer = client
                    .ask(&session.peer, "GET_FINALITY", QUICK_ASK_TIMEOUT)
                    .await
                    .ok();
                (session.peer, answer)
            });
        }
        while let Some(joined) = finality.join_next().await {
            let Ok((peer, answer)) = joined else {
                continue;
            };
            let artifact = answer
                .and_then(|r| r.strip_prefix("FINALITY:").map(str::to_string))
                .and_then(|json| serde_json::from_str::<FinalityArtifact>(&json).ok());
            // B443: a QC that fails a check strikes its session, as a lie in
            // a turn does: a level session takes no turn, so nothing else
            // judges it.
            if artifact.is_some_and(|artifact| self.finality_lied(&artifact)) {
                if let Ok(mut stalls) = self.stalls.lock() {
                    let n = stalls.get(&peer).map_or(0, |(n, _)| *n);
                    let at = std::time::Instant::now();
                    keep_standing(&mut stalls, peer, (n.saturating_add(1), at), |(_, t)| *t);
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
        let shard_yields = self
            .shard_yields
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
        // B388: sessions that showed they pruned below this node's next
        // block go after every other: members went first whatever they
        // held, so a node behind the members' retention never asked the
        // archive peer that held its blocks.
        let local = self.get_local_height();
        let pruned = self
            .pruned
            .lock()
            .map(|mut p| {
                p.retain(|_, (_, at)| fresh(at));
                p.clone()
            })
            .unwrap_or_default();
        let mut ranked: Vec<((String, Standing), (network::SessionPeer, u64))> = above
            .into_iter()
            .map(|(session, advertised)| {
                let first_seen = seen.get(&session.peer).map_or(now, |(first, _)| *first);
                let standing = Standing {
                    cannot_serve: pruned
                        .get(&session.peer)
                        .is_some_and(|(lowest, _)| *lowest > local + 1),
                    member: session.member.is_some(),
                    strikes: stalls.get(&session.peer).map_or(0, |(n, _)| *n),
                    brought: yields.get(&session.peer).map_or(0, |(n, _)| *n),
                    shards: shard_yields.get(&session.peer).map_or(0, |(n, _)| *n),
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
            let member = session.member.is_some();
            let mut link = SyncLink::Session {
                client: client.clone(),
                peer: session.peer,
            };
            let before = self.get_local_height();
            let turn = self
                .sync_over(&mut link, &label, member, before, advertised)
                .await;
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
                if let Ok(mut shard_yields) = self.shard_yields.lock() {
                    keep_standing(
                        &mut shard_yields,
                        peer.clone(),
                        (turn.shards, at),
                        |(_, t)| *t,
                    );
                }
            }
            let verdict = match self.silences.lock() {
                Ok(mut silences) => silence_verdict(&mut silences, &peer, &turn, at),
                Err(_) => turn.verdict(),
            };
            if let Ok(mut stalls) = self.stalls.lock() {
                match verdict {
                    // B287/B302: nothing to judge the session by.
                    None => {}
                    Some(true) => {
                        let n = stalls.get(&peer).map_or(0, |(n, _)| *n);
                        keep_standing(&mut stalls, peer, (n.saturating_add(1), at), |(_, t)| *t);
                    }
                    Some(false) => {
                        stalls.remove(&peer);
                    }
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
    /// B388: `link`'s session showed the lowest block it serves is `lowest`.
    fn note_pruned(&self, link: &SyncLink, lowest: u64) {
        let SyncLink::Session { peer, .. } = link;
        if let Ok(mut pruned) = self.pruned.lock() {
            keep_standing(
                &mut pruned,
                peer.clone(),
                (lowest, std::time::Instant::now()),
                |(_, at)| *at,
            );
        }
    }

    /// B445: `member`: `link`'s session authenticated a committee member's
    /// key. A block offered without its QC ends a turn well (`qcless_tip`)
    /// only as a member's, and only once it passed every check but the QC:
    /// a block that does not check is nobody's work, and an honest
    /// non-member holds a block without its QC only as its own copy, which
    /// no eligible key signed (every block it synced came with its QC,
    /// stored in the block's transaction). Any such block ended a turn well,
    /// so a stranger answering junk, or the real block relayed without its
    /// QC, was never struck, and outranked every struck honest server.
    /// Residual: a member answering every turn with a block it signed itself
    /// at this node's next height, and no QC, is never struck and goes
    /// before struck honest members; nothing tells that block from an honest
    /// member's newest (a member can sign any header).
    async fn sync_over(
        &self,
        link: &mut SyncLink,
        peer_id: &str,
        member: bool,
        my_height: u64,
        advertised: u64,
    ) -> Turn {
        // B445: a block at `height` the import stopped at for want of its QC
        // alone, offered by a member: what its server could certify, this
        // node holds.
        let at_qcless_tip =
            |imported: &Imported, height: u64| member && imported.qcless == Some(height);
        let mut turn = Turn {
            reached: my_height,
            brought: 0,
            bytes: 0,
            shards: 0,
            slow: false,
            ended_well: false,
            asked: false,
            refused: false,
            unjudged: false,
            silent: None,
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
                        log_line(format!(
                            "❌ [ChainSync] Failed to read SYNC_RESP from {}: {}",
                            peer_id,
                            loggable(&e)
                        ));
                        break;
                    }
                };
                let took = asked_at.elapsed();
                let Some(json_data) = data_resp.strip_prefix("SYNC_RESP:") else {
                    // B466: escaped too: an 80-character cut kept line breaks.
                    log_line(format!(
                        "❌ [ChainSync] Unexpected sync response prefix: {}",
                        loggable(&data_resp)
                    ));
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
                // B470: a prune horizon above this node's next block is noted
                // (B388) whatever else the answer carries, and no later note
                // of this answer goes below it. Only an empty answer noted
                // it, so a member that pruned a block but still named it
                // oversized (a stale index entry) at this node's next was
                // never noted, and kept every turn an archive peer needed.
                let horizon = sync_resp.prune_horizon.filter(|h| *h > current + 1);
                if let Some(horizon) = horizon {
                    self.note_pruned(link, horizon);
                }
                let lowest = |first: u64| horizon.map_or(first, |h| h.max(first));
                // B264: the next block is too large for a batch: it comes in
                // shards (B319), then through the import like any other block.
                // B275: its header and QC are checked first, the shards wait
                // out the server's answer budget, and what the turn could not
                // fetch any session's next turn fetches.
                if let Some(big) = sync_resp.oversized {
                    turn.slow |= took > SLOW_ANSWER;
                    if big.height != current + 1 {
                        // B399: a block named past this node's next is the
                        // first its server holds (it pruned below): B388's
                        // note, which this branch skipped.
                        if big.height > current + 1 {
                            self.note_pruned(link, lowest(big.height));
                        }
                        break;
                    }
                    let qc = sync_resp.qcs.iter().find(|q| q.block_height == big.height);
                    if consensus::v4::is_v4_chain(&self.storage) && qc.is_none() {
                        // Its server's newest block, without its QC yet. B445:
                        // only a member's, its header checked but for the QC
                        // (`check_named`); any other name ends the turn as an
                        // empty answer does (a stub with any header ended it
                        // well, before a check).
                        if member && self.check_named(&big, None).is_ok() {
                            judge_qcless_tip(&mut turn, big.height, peer_height.max(advertised));
                        }
                        break;
                    }
                    if let Err(e) = self.check_named(&big, qc) {
                        log_line(format!(
                            "❌ [ChainSync] Block #{} named in shards by {}: {}",
                            big.height,
                            peer_id,
                            loggable(&e)
                        ));
                        turn.refused = true;
                        break;
                    }
                    let block = match self
                        .fetch_sharded_block(link, &big, turn_ends, &mut turn)
                        .await
                    {
                        Ok(Some(block)) => block,
                        // The turn ended; the next resumes it.
                        Ok(None) => break,
                        // B466: a shard refusal carries the server's own text.
                        Err(PartFailure::Lost(e)) => {
                            log_line(format!(
                                "❌ [ChainSync] Block #{} in shards from {}: {}",
                                big.height,
                                peer_id,
                                loggable(&e)
                            ));
                            break;
                        }
                        Err(PartFailure::Lied(e)) => {
                            log_line(format!(
                                "🚨 [ChainSync] Block #{} in shards from {}: {}",
                                big.height,
                                peer_id,
                                loggable(&e)
                            ));
                            turn.refused = true;
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
                    // B443: a lie in the answer's finality ends the turn.
                    if self.turn_finality(&mut turn, finality) {
                        break;
                    }
                    continue;
                }
                if sync_resp.blocks.is_empty() {
                    // B443: a lie in its finality refuses the turn, struck
                    // even after a full batch.
                    self.turn_finality(&mut turn, finality);
                    // Below the peer's prune horizon: block-replay
                    // cannot bridge this gap. Surface it clearly
                    // instead of looping silently on empty replies.
                    // (B470: noted with the answer, above.)
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
                // B433: an honest server answers blocks above this node's
                // height, each above the last, at most a batch of them
                // (`handle_sync_request`). Any other answer is a lie, refused
                // before a block is read: stubs naming held heights made this
                // node read and parse a held block whole, once a stub, inside
                // its sync pass (~70,000 stubs fit an answer).
                if !honest_batch_shape(&sync_resp.blocks, current) {
                    eprintln!(
                        "🚨 [ChainSync] {peer_id}: an answer no honest server sends \
                         (blocks not above #{current}, out of order or over a batch)"
                    );
                    turn.refused = true;
                    break;
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
                // B388: an answer starting above this node's next block.
                if let Some(first) = offered.first().filter(|first| **first > current + 1) {
                    self.note_pruned(link, lowest(*first));
                }
                let imported = self.import_blocks(sync_resp.blocks, &sync_resp.qcs, current);
                let synced = imported.reached;
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
                    // certify, this node holds. B445: a member's block that
                    // checks but for its QC (any block offered without one
                    // ended the turn well).
                    if at_qcless_tip(&imported, synced + 1) {
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
                // B443: a lie in the answer's finality ends the turn: the next
                // batch's answer could carry another.
                if self.turn_finality(&mut turn, finality) {
                    break;
                }
                if current < peer_height && at_qcless_tip(&imported, current + 1) {
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
                    // B443: a lie strikes the session, however its turn ended.
                    self.turn_finality(&mut turn, Some(artifact));
                }
            }
        }
        turn
    }

    /// B275: whether `big` may be fetched: a length no batch holds and no
    /// more than a client imports, its header's own hash at its height, and
    /// (on V4) a QC that verifies under the height's committee and binds the
    /// header. Checked before any shard is asked for: a fetch started on any
    /// QC that merely named the height.
    fn check_named(
        &self,
        big: &OversizedBlock,
        qc: Option<&consensus::qc::QuorumCertificate>,
    ) -> Result<(), String> {
        if big.len <= self.batch_bytes as u64 || big.len > self.parted_budget {
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
        if let Some(qc) = qc {
            consensus::qc_producer::verify_header_qc(&self.storage, &big.header, qc)?;
        }
        // B319: the proposer's signature the import checks (it signs the
        // header's hash), before any shard: the shards carry none, so a junk
        // one named here was found only once the whole block had arrived.
        if !Self::eligible_proposers(&self.storage, big.height)?.contains(&big.proposer_signer) {
            return Err(format!(
                "its signer {:.16} is not an eligible proposer",
                big.proposer_signer
            ));
        }
        let signed = Block {
            header: big.header.clone(),
            transactions: Vec::new(),
            committed_vertices: Vec::new(),
            committed_authors: Vec::new(),
            anchor_hash: String::new(),
            proposer_signature: big.proposer_signature.clone(),
            proposer_signer: big.proposer_signer.clone(),
            slash_evidence: Vec::new(),
        };
        Self::verify_proposer_signature_in(&self.storage, &signed)
    }

    /// B319: the block `big` names, as its DA data shards over `link`, within
    /// the turn (`turn_ends`): the one fetch of this block, which any
    /// session's turn extends, a shard at a time, each verified under the
    /// header's DA root when its last piece arrives (a lie costs at most that
    /// shard: its pieces are dropped and its session struck). `None`: the
    /// turn ended first.
    async fn fetch_sharded_block(
        &self,
        link: &mut SyncLink,
        big: &OversizedBlock,
        turn_ends: tokio::time::Instant,
        turn: &mut Turn,
    ) -> Result<Option<Block>, PartFailure> {
        let lied = PartFailure::Lied;
        let started = std::time::Instant::now();
        let peer = match &*link {
            SyncLink::Session { peer, .. } => peer.clone(),
        };
        let mut fetch = match self
            .sharded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            Some(fetch)
                if fetch.big.height == big.height && fetch.big.header.hash == big.header.hash =>
            {
                fetch
            }
            _ => ShardFetch::new(big.clone()),
        };
        // B323: a turn that proved a shard ended well; one whose pieces did
        // not yet make a shard says nothing, but (B356) one whose pieces came
        // slower than an honest server's slowest pace is slow: a session
        // answering each piece just under the ask timeout never completed a
        // shard, so its turns were never judged. B376: a busy answer ends
        // the turn (below), so the pace is over time the session served.
        // B416: a turn that got no piece and no lie says nothing (a server
        // building a block's source answers its first piece only after the
        // build, ~70 s at 512 MiB on a Pi, past the ask's timeout; a block
        // it pruned or no longer indexes is refused), and the first answer's
        // wait (that build) is no part of the pace: both struck honest
        // servers. B424: such a turn without even a busy answer is silent,
        // struck when it comes again before a piece (`silence_verdict`).
        let mut proved = false;
        let mut pieces = 0u64;
        let mut first_wait: Option<Duration> = None;
        let judge = |turn: &mut Turn, proved: bool, pieces: u64, first_wait: Option<Duration>| {
            if proved {
                turn.ended_well = true;
            } else if pieces == 0 {
                turn.unjudged = true;
            } else {
                let served = started
                    .elapsed()
                    .saturating_sub(first_wait.unwrap_or_default());
                let floor = MIN_PIECE_BYTES_PER_SEC as f64 * served.as_secs_f64();
                if (pieces as f64) < floor {
                    turn.slow = true;
                } else {
                    turn.unjudged = true;
                }
            }
        };
        loop {
            if let Some(block) = fetch.block() {
                judge(turn, proved, pieces, first_wait);
                return block.map(Some).map_err(PartFailure::Lost);
            }
            // B387/B415: this session's unfinished shard, resumed, else a
            // shard no other session's unfinished one covers (B423: shard 0
            // until a shard proves the length).
            let (index, mut shard, mut claimed) = fetch.turn_shard(&peer);
            loop {
                let left = turn_ends.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    judge(turn, proved, pieces, first_wait);
                    fetch.keep_partial(&peer, index, shard, claimed);
                    self.keep_fetch(fetch);
                    return Ok(None);
                }
                let req = serde_json::to_string(&ShardRequest {
                    height: big.height,
                    index,
                    offset: shard.len() as u64,
                })
                .map_err(|e| PartFailure::Lost(e.to_string()))?;
                let asked_at = std::time::Instant::now();
                let answer = match link
                    .ask_within(&format!("{SHARD_REQ}{req}"), left.min(SYNC_ASK_TIMEOUT))
                    .await
                {
                    Ok(answer) => {
                        first_wait.get_or_insert_with(|| asked_at.elapsed());
                        answer
                    }
                    Err(e) => {
                        judge(turn, proved, pieces, first_wait);
                        // B424: no answer at all, past an honest answer's time.
                        if !proved && pieces == 0 && asked_at.elapsed() >= SLOW_ANSWER {
                            turn.silent = Some(big.height);
                        }
                        fetch.keep_partial(&peer, index, shard, claimed);
                        self.keep_fetch(fetch);
                        return Err(PartFailure::Lost(e));
                    }
                };
                let piece = answer
                    .strip_prefix(SHARD_RESP)
                    .and_then(|json| serde_json::from_str::<ShardResponse>(json).ok());
                let Some(piece) = piece else {
                    self.keep_fetch(fetch);
                    return Err(lied("a garbled shard piece".into()));
                };
                match piece.error.as_deref() {
                    // B376: a busy answer ends the turn, judged by its pieces
                    // or else neither way, and the fetch waits for the next
                    // turn. It was waited out inside the turn: an honest
                    // server rebuilding for another block (B347: three times
                    // a build) was struck for its turn's empty pace, and
                    // B360's pace without the waits let a session hold every
                    // turn's time by answering busy, unstruck.
                    Some(state_sync::BUSY) => {
                        judge(turn, proved, pieces, first_wait);
                        fetch.keep_partial(&peer, index, shard, claimed);
                        self.keep_fetch(fetch);
                        return Ok(None);
                    }
                    // B288: an honest server refuses a block it no longer
                    // indexes (its index is bounded) or holds (pruned).
                    Some(e) => {
                        judge(turn, proved, pieces, first_wait);
                        // B424: the block it named, refused before a piece.
                        if !proved && pieces == 0 {
                            turn.silent = Some(big.height);
                        }
                        fetch.keep_partial(&peer, index, shard, claimed);
                        self.keep_fetch(fetch);
                        return Err(PartFailure::Lost(format!("a shard refused: {e}")));
                    }
                    None => {}
                }
                // The length a verified shard proved, else this server's own
                // claim, held for its shard; the shard's proof decides. B356:
                // a piece of any length that does not pass its shard's end
                // (a piece's length is the server's cut, which a rolling
                // upgrade may change: an exact length struck honest servers).
                let layout = da::Layout::of(piece.body_len);
                let due = layout.shard_size.saturating_sub(shard.len() as u64);
                let data = hex::decode(&piece.data)
                    .ok()
                    .filter(|d| !d.is_empty() && d.len() as u64 <= due);
                let fits = piece.index == index
                    && piece.offset == shard.len() as u64
                    && piece.body_len > 0
                    && piece.body_len <= parted_body_budget(self.parted_budget)
                    && index < layout.data_shards
                    && claimed.is_none_or(|len| len == piece.body_len);
                let (true, Some(data)) = (fits, data) else {
                    self.keep_fetch(fetch);
                    return Err(lied(format!(
                        "a piece of shard {} at {} of a {}-byte body, where up to {} bytes of shard {index} were due",
                        piece.index, piece.offset, piece.body_len, due
                    )));
                };
                claimed = Some(piece.body_len);
                pieces = pieces.saturating_add(data.len() as u64);
                turn.bytes = turn.bytes.saturating_add(data.len());
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
                if let Err(e) = da::verify_sample(&big.header.da_root, index, &sample) {
                    self.keep_fetch(fetch);
                    return Err(lied(format!(
                        "data shard {index} does not prove under the header's DA root: {e:?}"
                    )));
                }
                fetch.accept(layout, index, shard);
                proved = true;
                turn.shards += 1;
                break;
            }
        }
    }

    /// B319: the shard fetch, kept for any session's next turn.
    fn keep_fetch(&self, fetch: ShardFetch) {
        *self.sharded.lock().unwrap_or_else(|e| e.into_inner()) = Some(fetch);
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
        self.import_blocks(blocks, qcs, current_height).reached
    }

    /// `process_blocks_with_qcs`, and (B445) the block it stopped at for want
    /// of its QC alone, if it did (`Imported`).
    fn import_blocks(
        &self,
        blocks: Vec<Block>,
        qcs: &[consensus::qc::QuorumCertificate],
        current_height: u64,
    ) -> Imported {
        let v4 = consensus::v4::is_v4_chain(&self.storage);
        let qc_of = |b: &Block| -> Option<&consensus::qc::QuorumCertificate> {
            qcs.iter().find(|q| q.block_height == b.header.height)
        };
        let mut last_processed = current_height;
        let mut qcless = None;
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
                        // B466: the peer's hash is any text it chose here.
                        log_line(format!(
                            "🚨 [SECURITY][SYNC_QC_PIN_REJECT] peer's block #{} hash {} does not \
                             match the QC-certified hash {} — rejecting the whole batch before \
                             execution (fabricated chain)",
                            qc.block_height,
                            loggable(&b.header.hash),
                            qc.block_hash
                        ));
                        return Imported {
                            reached: last_processed,
                            qcless,
                        };
                    }
                }
            }
        }

        for (i, block) in blocks.iter().enumerate() {
            if block.header.height <= last_processed {
                let key = format!("block_{}", block.header.height);
                if let Ok(Some(existing_json)) = self.storage.get(&key) {
                    // B433: only the held block's header is read (`header_of`),
                    // never the whole block, on a peer's word.
                    if let Some(existing) = blockchain::header_of(&existing_json) {
                        if existing.hash == block.header.hash {
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
                        if existing.round <= finalized_round
                            || block.header.round <= finalized_round
                        {
                            eprintln!(
                                "🚨 [SECURITY][SYNC_REORG_REJECT] conflict at finalized boundary height={} local_round={} remote_round={} finalized_round={}",
                                block.header.height,
                                existing.round,
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
                                        existing.hash
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
                    // B433: the parent's header only; its whole body (up to
                    // 512 MiB parted) was parsed for every batch's first block.
                    .and_then(|json| blockchain::header_of(&json))
                    .map(|header| header.hash)
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

            // B444: the checks a block needs no QC for first (B41: its
            // signature before its body); then, on V4, its QC; its body's
            // roots (the DA root's Reed-Solomon extension) only once that QC
            // verified. A member signing a ~9 MiB block, sent without a QC,
            // cost every node a whole extension a pass: B41 moved only the
            // signature ahead of the roots, and a member's own costs it
            // nothing.
            // B466: these refusals echo fields the block and its QC carry
            // (a parent hash, a proposer, a claimed chain id), whole.
            if let Err(e) =
                Self::validate_header_in(&self.storage, block, expected_height, &prev_hash)
            {
                log_line(format!(
                    "🚨 [SECURITY] Block #{} validation FAILED: {}",
                    block.header.height,
                    loggable(&e)
                ));
                break;
            }
            let qc = if v4 {
                let checked = qc_of(block).map(|q| {
                    consensus::qc_producer::verify_block_qc(&self.storage, block, q).map(|()| q)
                });
                match checked {
                    Some(Ok(q)) => Some(q.clone()),
                    Some(Err(e)) => {
                        log_line(format!(
                            "🚨 [SECURITY][SYNC_QC_REJECT] block #{}: {}",
                            block.header.height,
                            loggable(&e)
                        ));
                        break;
                    }
                    None => {
                        eprintln!(
                            "[ChainSync] block #{} came without its QC; not executed (V4)",
                            block.header.height
                        );
                        // B445: it checks but for its QC.
                        qcless = Some(block.header.height);
                        break;
                    }
                }
            } else {
                None
            };
            if let Err(e) = block.check_commitments() {
                log_line(format!(
                    "🚨 [SECURITY] Block #{}'s body does not match its header: {}",
                    block.header.height,
                    loggable(&e)
                ));
                break;
            }

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
                    // B443: its header only (`header_of`): the whole stored
                    // block was parsed for its hash.
                    let stored = self
                        .storage
                        .get(&format!("block_{}", block.header.height))
                        .ok()
                        .flatten()
                        .and_then(|row| blockchain::header_of(&row))
                        .map(|header| header.hash);
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
                    // B466: cut, as it may quote what the block carries.
                    log_line(format!(
                        "[ChainSync][BLOCK_ACCEPTANCE_FAILED] block #{} was not accepted: {}",
                        block.header.height,
                        loggable(&error)
                    ));
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
        Imported {
            reached: last_processed,
            qcless,
        }
    }

    /// Store a verified block QC (IM-1/IM-4). Idempotent; a failure only
    /// delays adoption, which waits for a stored QC.
    fn import_block_qc(&self, q: &consensus::qc::QuorumCertificate) {
        if let Err(e) = consensus::qc_producer::import_finality_qc(&self.storage, q) {
            // B466: a peer's QC, its refusal echoing its fields (B443).
            log_line(format!(
                "[ChainSync] QC of block #{} not stored ({}); adoption waits",
                q.block_height,
                loggable(&e)
            ));
        }
    }

    /// The requests `handle_message` answers. The node's session layer routes
    /// exactly these here, so a request type is added in one place.
    pub fn serves(msg: &str) -> bool {
        msg == "GET_HEIGHT"
            || msg == "GET_FINALITY"
            || [
                "SYNC_REQ:",
                SHARD_REQ,
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
            let resp =
                serde_json::to_string(&self.serve_state_anchor_as(req, client, kept)).ok()?;
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
        if let Some(req_json) = msg.strip_prefix(SHARD_REQ) {
            let req = serde_json::from_str::<ShardRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.serve_block_shard_as(req, client, kept)).ok()?;
            return Some(format!("{SHARD_RESP}{resp}"));
        }
        None
    }

    /// B319 (`SYNC_SHARD`): a piece of data shard `index` of the block at
    /// `height`, from `offset` into the shard, with the shard's proof when
    /// the piece ends it. B275: only a block known to be too large for a
    /// batch (a batch answer named it) is served, and nothing is read for any
    /// other; its body and shard proofs are made once (`shard_source`).
    pub fn handle_block_shard(&self, req: ShardRequest) -> ShardResponse {
        self.serve_block_shard_as(req, None, false)
    }

    /// `handle_block_shard` for `client` (`None`: in process; `kept`: a
    /// reserved peer), whose snapshot budget a source's build is charged to
    /// (B347).
    pub fn serve_block_shard_as(
        &self,
        req: ShardRequest,
        client: Option<&str>,
        kept: bool,
    ) -> ShardResponse {
        let refuse = |why: &str| ShardResponse {
            error: Some(why.to_string()),
            ..Default::default()
        };
        let known = self.known_oversized(req.height, true).map(|big| big.len);
        let Some(len) = known else {
            return refuse("not a block served in shards");
        };
        let source = match self.shard_source(req.height, len, client, kept) {
            Ok(source) => source,
            Err(why) => return refuse(why),
        };
        let layout = source.proofs.layout();
        if req.index >= layout.data_shards {
            return refuse("no such data shard");
        }
        let size = layout.shard_size;
        if req.offset >= size {
            return refuse("offset past the shard");
        }
        let piece = (size - req.offset).min(self.piece_bytes() as u64);
        // The body's bytes from here, zeros past its end (the last shard's
        // padding, as the extension pads it).
        let start = req.index * size + req.offset;
        let mut data = vec![0u8; piece as usize];
        let body = &source.body;
        if let Some(rest) = usize::try_from(start).ok().and_then(|s| body.get(s..)) {
            let n = rest.len().min(data.len());
            data[..n].copy_from_slice(&rest[..n]);
        }
        let last = req.offset + piece == size;
        ShardResponse {
            body_len: layout.body_len,
            index: req.index,
            offset: req.offset,
            data: hex::encode(&data),
            proof: if last {
                source.proofs.proof(req.index).unwrap_or_default()
            } else {
                Vec::new()
            },
            error: None,
        }
    }

    /// B319: the body of the block at `height` (its stored text `len` bytes)
    /// and its shard proofs, kept for its pieces: one block at a time (the
    /// clients behind fetch the same next block). B347: one build at a
    /// time, admitted on `client`'s snapshot budget and charged the bytes it
    /// read; the next waits for `parted_read_wait` (B291) and for three times
    /// this build's measured cost, answered busy meanwhile. A build (a read,
    /// a parse, a Reed-Solomon extension) took up to ~70 s of a Pi's cores at
    /// 512 MiB against a gate paced at disk speed and set when it started,
    /// so a stranger alternating two heights kept the cores busy and several
    /// builds at once held gigabytes.
    fn shard_source(
        &self,
        height: u64,
        len: u64,
        client: Option<&str>,
        kept: bool,
    ) -> Result<Arc<ShardSource>, &'static str> {
        let held = || {
            self.shard_source
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .filter(|(at, _)| *at == height)
                .map(|(_, source)| Arc::clone(source))
        };
        if let Some(source) = held() {
            return Ok(source);
        }
        let Ok(_building) = self.shard_build.try_lock() else {
            return Err(state_sync::BUSY);
        };
        if let Some(source) = held() {
            return Ok(source);
        }
        let now = std::time::Instant::now();
        if self
            .parted_read_due
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|at| now < at)
        {
            return Err(state_sync::BUSY);
        }
        let Some(admission) = self
            .state_budget
            .admit_all(client, state_sync::PART_UNITS, kept)
        else {
            return Err(state_sync::BUSY);
        };
        let built = (|| {
            let json = match self.storage.get(&format!("block_{height}")) {
                Ok(Some(json)) => json,
                _ => return Err("no such block"),
            };
            admission.charge(json.len() as u64);
            let block: Block =
                serde_json::from_str(&json).map_err(|_| "a stored block that does not parse")?;
            drop(json);
            let body = block.body_bytes();
            drop(block);
            let proofs = da::Extended::new(&body).into_proofs();
            Ok(Arc::new(ShardSource { body, proofs }))
        })();
        let took = now.elapsed();
        *self
            .parted_read_due
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            Some(std::time::Instant::now() + parted_read_wait(len).max(took * 3));
        let source = built?;
        *self.shard_source.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((height, Arc::clone(&source)));
        Ok(source)
    }

    /// B275: the block at `height` known to be too large for a batch, and
    /// (B288) its last ask now, if `touch`. B470: only while this node may
    /// still hold it (`StateDB::may_hold_block`, exact when false); an entry
    /// for a block pruned since goes. Pruning never touched the index (in
    /// memory, bounded, least recently asked out first), so a member that
    /// pruned a block went on naming it at a requester's next height, with
    /// no QC and a prune horizon above it: the requester never noted that
    /// it pruned (B388, B399), and its members kept every turn an archive
    /// peer needed. Each shard asked for it began a build that found no
    /// block, and held the next build back (`parted_read_wait`).
    fn known_oversized(&self, height: u64, touch: bool) -> Option<OversizedBlock> {
        let index = || {
            self.oversized_known
                .lock()
                .unwrap_or_else(|e| e.into_inner())
        };
        let big = {
            let mut known = index();
            let (big, used) = known.get_mut(&height)?;
            if touch {
                *used = std::time::Instant::now();
            }
            big.clone()
        };
        if self.storage.may_hold_block(height) {
            return Some(big);
        }
        index().remove(&height);
        None
    }

    /// B275: a block at `height`, read as `json`, is too large for a batch:
    /// known from now on by its length, header and (B319) proposer's
    /// signature, the rest of the text skipped.
    fn learn_oversized(&self, height: u64, json: String) -> Option<OversizedBlock> {
        #[derive(Deserialize)]
        struct Signed {
            #[serde(default)]
            proposer_signature: String,
            #[serde(default)]
            proposer_signer: String,
        }
        let header = blockchain::header_of(&json).filter(|h| h.height == height)?;
        let signed: Signed = serde_json::from_str(&json).ok()?;
        let big = OversizedBlock {
            height,
            len: json.len() as u64,
            header,
            proposer_signature: signed.proposer_signature,
            proposer_signer: signed.proposer_signer,
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
            // B470: only while this node may still hold it.
            if let Some(big) = self.known_oversized(height, false) {
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
        let horizon = self.earliest_held_block();
        let first_block_pruned = req.from_height < local_height && req.from_height + 1 < horizon;
        let prune_horizon = first_block_pruned.then_some(horizon);
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

    /// B324: the lowest height from which this node holds every block: the
    /// block prune cursor (pruning moves it, a restore sets it to its anchor;
    /// 1 when neither ran). A binary search for it read whole blocks (up to
    /// 512 MiB each, about log2 of the height of them) for a request's
    /// few-byte answer, and a block kept for a pin below it read as the
    /// horizon, so the requester got that block and then a gap.
    fn earliest_held_block(&self) -> u64 {
        self.storage
            .get(StateDB::BLOCK_PRUNE_CURSOR_KEY)
            .ok()
            .flatten()
            .and_then(|cursor| cursor.parse::<u64>().ok())
            .unwrap_or(1)
            .max(1)
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
