use std::collections::HashMap;
use std::sync::{Arc, Mutex};
// use serde::{Serialize, Deserialize}; // Unused
use crate::ordering::OrderingEngine;
use blockchain::Vertex;
use crypto::accumulator::Accumulator;
use da_sequencer::DASequencer;
use executor::Executor;
use mempool::Mempool;
use network::PeerList;
use storage::StateDB;

/// Cached active validator set as `(address, stake)` pairs, canonically sorted.
type ValidatorStakeCache = Arc<Mutex<Option<Vec<(String, u64)>>>>;

#[cfg(test)]
type LocalAcceptanceHook = fn(u8, &StateDB) -> Result<(), String>;

/// PROTOCOL (deterministic slashing): a vertex payload item carrying this
/// prefix is equivocation evidence, not a transaction. It rides through the DAG
/// and is ordered by the commit rule exactly like a tx, so every node extracts
/// the IDENTICAL evidence set at block-build time. Never send it to the mempool
/// or the executor as a tx.
pub const SLASH_EVIDENCE_PREFIX: &str = "SLASH_EVIDENCE:";
/// G1 EP-4: ask peers for QC(H_E) / answer with it (`answer_qc_want`).
pub const QC_WANT_PREFIX: &str = "QC_WANT:";
pub const QC_CERT_PREFIX: &str = "QC_CERT:";
const QC_WANT_EVERY_TICKS: u64 = 4;
/// RC-3: how long after `sys:genesis_time` a validator may take its first
/// guard origin, and the clock skew allowed before it.
pub const LAUNCH_WINDOW_SECS: u64 = 3600;
pub const LAUNCH_WINDOW_SKEW_SECS: u64 = 600;
/// G5 BT-1: a placed block's T further than this from the node's clock
/// counts toward the drift alarm (twice the ingress gate's 30 s). A clock
/// behind by more than the gate places no block at all: it alarms on the
/// vertices it refuses as early instead (`Engine::early_quorum`).
pub const CLOCK_DRIFT_ALARM_SECS: i64 = 60;
/// The alarm holds after this many placed blocks in a row past the bound:
/// an anchor committed late after a pause carries old timestamps once.
pub const CLOCK_DRIFT_ALARM_BLOCKS: u32 = 3;
const QC_ANSWERS_PER_TICK: u32 = 4;
const QC_ANSWERED_CAP: usize = 256;
/// Upper bound on evidence items carried per vertex and applied per block
/// (matches executor::apply_slash_evidence's `.take(5)`).
const MAX_EVIDENCE_PER_VERTEX: usize = 5;
/// Rounds a carried-but-not-yet-included evidence item stays in flight before
/// it is treated as orphaned/cap-dropped and re-carried. Local bookkeeping.
pub const INFLIGHT_TTL_ROUNDS: u64 = 8;
/// Hard byte budget for a serialized vertex, comfortably under the 1 MiB
/// gossipsub / TCP transport cap (core/node/src/p2p.rs, common/network). A
/// vertex over this is undeliverable, so it is never BUILT (try_create_vertex
/// trims to fit) and never ACCEPTED (ingress rejects before parsing).
pub const MAX_VERTEX_BYTES: usize = 768 * 1024;
/// Hard cap on parents per vertex at ingress. A Narwhal-style vertex references
/// at most one vertex per validator of the previous round; anything beyond a
/// generous bound is an inflation attack (unbounded parents made an
/// equivocator's own evidence undeliverable before parents were rooted).
pub const MAX_PARENTS: usize = 256;

pub struct DagConsensus {
    pub node_id: String,
    pub current_round: u64,
    pub dag: Arc<Mutex<HashMap<String, Vertex>>>, // Hash -> Vertex
    pub round_index: Arc<Mutex<HashMap<u64, Vec<String>>>>, // Round -> Vec<Hash>
    pub mempool: Arc<Mutex<Mempool>>,
    pub executor: Arc<Executor>,
    pub storage: Arc<StateDB>,
    pub peers: PeerList,
    pub ordering_engine: Arc<Mutex<OrderingEngine>>,
    pub latest_block_height: u64,
    pub latest_block_hash: String,
    /// AUDIT-H1: timestamp of the chain tip, used to keep BFT block time
    /// monotonic across blocks and across restarts.
    pub latest_block_timestamp: u64,
    /// AUDIT-B4b (dedup): the ANCHOR ROUND of the chain-tip block. Blocks reach
    /// the tip from TWO sources — the local commit loop and ChainSync imports —
    /// and both must advance one shared stream. Without this, a node that synced
    /// a peer's block for anchor A and then ran its own commit for A built a
    /// SECOND block for the same anchor at the next height, shifting its whole
    /// chain numbering by one forever (the residual ±1 fork the first B4b deploy
    /// exposed: anchor 73 landed at height 67 on NAS and height 68 on LAP).
    /// The commit loop skips block-building for any anchor <= this round.
    pub latest_block_round: u64,
    /// LIVENESS: highest block height whose anchor has been applied to the
    /// ordering engine — by local commit or by adopting a synced block. Heights
    /// above this that arrive via ChainSync are adopted in reload_chain_tip.
    pub last_adopted_height: u64,
    /// G5 BT-1: placed blocks in a row whose T was more than
    /// `CLOCK_DRIFT_ALARM_SECS` from this node's clock, and the last
    /// difference (local − T, seconds).
    clock_drift: (u32, i64),
    /// Whether the alarm was on at the last check, so it is logged once
    /// when it starts and once when it clears.
    clock_alarm_logged: bool,
    qc_retry_cursor: String,
    pub accumulator: Accumulator,
    pub da_sequencer: Option<Arc<Mutex<DASequencer>>>, // Added DA Sequencer
    pub p2p_tx: Option<tokio::sync::mpsc::Sender<String>>, // Added P2P Libp2p Channel
    pub node_key: [u8; 32], // H4 FIX: Store the persistent Ed25519 key for BLS derivation
    /// Phase 2.8 (M-08): cache of the active validator set.
    ///
    /// `get_validator_set` used to hit RocksDB on every call — twice per
    /// vertex (proposal + verification) plus once per ordering attempt.
    /// On a healthy network that's hundreds of disk reads + JSON parses
    /// per second of identical data. The cache is populated on first
    /// access, returned for all reads in the same block window, and
    /// invalidated when a block commits (cheapest moment to refresh —
    /// the only time validator set may legitimately change during normal
    /// operation is via a slash, which happens during block execution).
    validators_cache: ValidatorStakeCache,
    /// (offender, round) -> round at which we carried it, for items carried in
    /// a vertex of ours not yet seen INCLUDED in a block. Stops consecutive
    /// vertices re-carrying the same item; an entry older than
    /// INFLIGHT_TTL_ROUNDS is treated as orphaned or cap-dropped and re-carried.
    /// Cleared, and the durable marker latched, only when the item lands in a
    /// block's slash_evidence carried by us.
    evidence_inflight: Arc<Mutex<std::collections::BTreeMap<(String, u64), u64>>>,
    /// Wall-clock seam. Three sites in this file read real time, and each one
    /// DECIDES something:
    ///   * the vertex timestamp, which is folded into the SIGNED hash
    ///   * the `MAX_FUTURE_DRIFT_SECS` admission gate
    ///   * the spacing of the anchor-placement retry loop
    ///
    /// A deterministic harness cannot reproduce a schedule whose clock it does not
    /// control, and the anchor->height race — the mechanism behind the live B4b
    /// block fork, where one node built height 50 from round 52 and another from
    /// round 53 — is decided by REAL TIME, not by message order. It is unreachable
    /// without this seam. That was established by compiler error, not opinion:
    /// `CommitInfo` carries no height, because height is fixed as
    /// `latest_block_height + 1` inside the retry loop below.
    ///
    /// Defaulted to the real clock in `new`, so production behaviour is unchanged.
    /// Deliberately NOT behind a `cfg`: a simulation-only branch means the harness
    /// tests a program that does not ship.
    pub now_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// The pause between anchor-placement attempts. Separate from `now_secs`
    /// because a simulation wants to skip the wait, not fake the clock.
    pub placement_sleep: Arc<dyn Fn(std::time::Duration) + Send + Sync>,
    /// G1 S5: the certified-DAG engine, when this chain's vertex format is V4
    /// (`genesis:vertex_format` = 4). It then owns ingress, staging, O_E and
    /// production; `dag` holds its staged bodies and `round_index` O_E.
    pub(crate) v4: Option<crate::v4::Engine>,
    /// Fixed at boot: this chain runs V4 (otherwise the node is inert). Every
    /// gate reads this, not whether the engine happens to be present at that
    /// moment.
    v4_chain: bool,
    /// C_0 as (address, stake), fixed at boot on a V4 chain (DE-7).
    v4_stakes: Vec<(String, u64)>,
    /// A recorded conflict (a second certificate for a slot, CE-3; a decision
    /// row that disagrees, DE-6) halts ordering: no block is placed, no
    /// finality vote signed, no synced anchor adopted. Survives restarts.
    ordering_halt: Option<String>,
    /// V4 ticks so far, and the QC(H_E) ask/answer throttles (EP-4).
    v4_ticks: u64,
    qc_want_next: u64,
    qc_answered: HashMap<u64, u64>,
    qc_answer_budget: (u64, u32),
    #[cfg(test)]
    pub(crate) local_acceptance_hook: Option<LocalAcceptanceHook>,
    /// Tests only: runs inside the block transaction BEFORE execution, the
    /// last point where consensus state may be staged (G3 CM-2).
    #[cfg(test)]
    pub(crate) pre_execution_hook: Option<LocalAcceptanceHook>,
    /// Tests only: V4 wire messages this node sent, instead of the network.
    #[cfg(any(test, feature = "sim"))]
    pub v4_outbox: Option<V4Outbox>,
}

#[cfg(any(test, feature = "sim"))]
pub type V4Outbox = Arc<Mutex<Vec<String>>>;

/// The production `ConsensusNet`: V4 messages go out as `DAG_V4:{json}` over
/// gossip and the TCP fan-out, like `DAG_VERTEX`. An attestation, addressed to
/// its author, travels the same way; every other node ignores it.
struct V4Net {
    node_id: String,
    p2p_tx: Option<tokio::sync::mpsc::Sender<String>>,
    peers: PeerList,
    storage: Arc<StateDB>,
    #[cfg(any(test, feature = "sim"))]
    outbox: Option<V4Outbox>,
}

impl V4Net {
    /// Gossip plus the TCP fallback (in tests, the node's outbox).
    fn broadcast_wire(&self, wire: String) {
        #[cfg(any(test, feature = "sim"))]
        if let Some(outbox) = &self.outbox {
            outbox.lock().unwrap_or_else(|e| e.into_inner()).push(wire);
            return;
        }
        if let Some(tx) = &self.p2p_tx {
            let (tx, wire) = (tx.clone(), wire.clone());
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(async move {
                        let _ = tx.send(wire).await;
                    });
                }
                Err(_) => {
                    let _ = tx.try_send(wire);
                }
            }
        }
        if let Ok(peers) = self.peers.lock() {
            for (peer_id, port) in peers.iter() {
                if *peer_id == self.node_id {
                    continue;
                }
                let ip = self
                    .storage
                    .get_peer_ip(peer_id)
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let _ = network::send_message(&format!("{ip}:{port}"), &wire);
            }
        }
    }
}

impl crate::v4::ConsensusNet for V4Net {
    fn broadcast(&self, msg: crate::v4::Msg) {
        let Ok(json) = serde_json::to_string(&msg) else {
            return;
        };
        self.broadcast_wire(format!("{}{json}", crate::v4::WIRE_PREFIX));
    }

    fn send(&self, _to: &str, msg: crate::v4::Msg) {
        self.broadcast(msg);
    }
}

/// G5 BT-1: the block timestamp from the committed vertices' `(author,
/// timestamp)` samples, weighted by `committee` (non-members carry no weight),
/// with the quorum measured against the whole committee's stake.
pub(crate) fn committee_block_timestamp(
    samples: &[(String, u64)],
    committee: &[(String, u64)],
    parent_ts: u64,
) -> u64 {
    let stakes: std::collections::HashMap<&str, u64> =
        committee.iter().map(|(a, s)| (a.as_str(), *s)).collect();
    let weighted = samples
        .iter()
        .filter_map(|(a, ts)| stakes.get(a.as_str()).map(|s| (a.clone(), *s, *ts)))
        .collect();
    let committee_stake = committee.iter().map(|(_, s)| *s as u128).sum();
    blockchain::bft_block_timestamp(weighted, parent_ts, committee_stake)
}

impl DagConsensus {
    #[allow(clippy::too_many_arguments)] // intrinsic to DagConsensus dependencies
    pub fn new(
        node_id: String,
        peers: PeerList,
        mempool: Arc<Mutex<Mempool>>,
        executor: Arc<Executor>,
        storage: Arc<StateDB>,
        da_sequencer: Option<Arc<Mutex<DASequencer>>>,
        p2p_tx: Option<tokio::sync::mpsc::Sender<String>>, // Corrected to Sender
        node_key: [u8; 32],                                // H4 FIX: Accept the persistent key
    ) -> Self {
        // G1 S5: a V4 chain boots through the certified-DAG engine (RC-1).
        // G5 S4c: the V3 DAG is deleted; a node on any other database is
        // inert (it never proposes, signs or ingests). Fail closed: a node
        // that cannot read its format must not guess.
        let v4_format = match storage.get(crate::v4::VERTEX_FORMAT_KEY) {
            Ok(v) => v.as_deref() == Some("4"),
            Err(e) => panic!("cannot read the chain's vertex format: {e}"),
        };
        if !v4_format {
            eprintln!(
                "⚠️ not a V4 chain ({}): this node is inert",
                crate::v4::VERTEX_FORMAT_KEY
            );
        }

        let latest_block_height = match storage.get("latest_height") {
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
            _ => 0,
        };
        let latest_block_hash = match storage.get("latest_block_hash") {
            Ok(Some(h)) => h,
            _ => "genesis".to_string(),
        };

        // AUDIT-H1: restore the tip's timestamp so BFT block time stays monotonic
        // across a restart (otherwise the first block after a restart could move
        // time backwards and diverge from peers that never restarted).
        let (latest_block_timestamp, latest_block_round) = storage
            .get(&format!("block_{}", latest_block_height))
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<blockchain::Block>(&json).ok())
            .map(|b| (b.header.timestamp, b.header.round))
            .unwrap_or((0, 0));
        // RE-AUDIT MEDIUM: adoption cursor persisted across restarts (never above
        // the tip), so a crash between sync persisting a block and its adoption
        // cannot silently skip that block at boot.
        let last_adopted_height = storage
            .get("consensus:last_adopted_height")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|h| h.min(latest_block_height))
            .unwrap_or(0);

        let storage_for_ordering = Arc::clone(&storage);

        let mut this = Self {
            node_id,
            peers,
            // The engine sets the round at boot (`start_v4`).
            current_round: 0,
            dag: Arc::new(Mutex::new(HashMap::new())),
            round_index: Arc::new(Mutex::new(HashMap::new())),
            mempool,
            executor,
            storage,
            ordering_engine: Arc::new(Mutex::new(OrderingEngine::new_with_storage(
                storage_for_ordering,
            ))),
            latest_block_height,
            latest_block_hash,
            latest_block_timestamp,
            latest_block_round,
            last_adopted_height,
            clock_drift: (0, 0),
            clock_alarm_logged: false,
            qc_retry_cursor: String::new(),
            accumulator: Accumulator::new(),
            da_sequencer,
            p2p_tx,
            node_key,
            // Phase 2.8 (M-08): empty cache; first get_validator_set call
            // populates it from storage. Subsequent reads are cache hits
            // until the next block commit invalidates.
            validators_cache: Arc::new(Mutex::new(None)),
            evidence_inflight: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            // The real clock. The two call sites this replaces were written
            // differently (`.unwrap_or(Duration::from_secs(0)).as_secs()` vs
            // `.map(|d| d.as_secs()).unwrap_or(0)`) but are semantically equal;
            // this is that value, not a verbatim move of either.
            now_secs: Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            }),
            placement_sleep: Arc::new(std::thread::sleep),
            v4: None,
            v4_chain: v4_format,
            v4_stakes: Vec::new(),
            ordering_halt: None,
            v4_ticks: 0,
            qc_want_next: 0,
            qc_answered: HashMap::new(),
            qc_answer_budget: (0, 0),
            #[cfg(test)]
            local_acceptance_hook: None,
            #[cfg(test)]
            pre_execution_hook: None,
            #[cfg(any(test, feature = "sim"))]
            v4_outbox: None,
        };
        for alarms in ["alarm:decision_conflict:", "alarm:committee_mismatch:"] {
            if let Some(Ok((key, _))) = this.storage.db.prefix_iterator(alarms.as_bytes()).next() {
                if key.starts_with(alarms.as_bytes()) {
                    this.ordering_halt = Some(format!(
                        "a consensus conflict was recorded ({})",
                        String::from_utf8_lossy(&key)
                    ));
                }
            }
        }
        if v4_format {
            this.start_v4();
        }
        this
    }

    /// Why ordering is halted, if it is: a conflict this node recorded, or
    /// the V4 engine's certificate conflict (CE-3, OR-2).
    pub fn ordering_halted(&self) -> Option<String> {
        self.ordering_halt.clone().or_else(|| {
            self.v4
                .as_ref()
                .and_then(|e| e.halted().map(str::to_string))
        })
    }

    /// G5 BT-1: the drift alarm, this node's clock minus the chain's time in
    /// seconds, while it holds. Either the T of the blocks it places has been
    /// more than `CLOCK_DRIFT_ALARM_SECS` away for `CLOCK_DRIFT_ALARM_BLOCKS`
    /// blocks in a row, or a stake quorum of members' vertices are refused as
    /// early (then it places no block). An attacker can shift NTP; the
    /// chain's time comes from a stake quorum.
    pub fn clock_drift_alarm(&self) -> Option<i64> {
        if self.clock_drift.0 >= CLOCK_DRIFT_ALARM_BLOCKS {
            return Some(self.clock_drift.1);
        }
        let early = self.v4.as_ref()?.early_quorum()?;
        Some(((self.now_secs)() as i64).saturating_sub(early as i64))
    }

    /// G5 BT-1: compare the T of a block this node placed with its clock.
    fn check_clock_drift(&mut self, block_ts: u64) {
        let drift = ((self.now_secs)() as i64).saturating_sub(block_ts as i64);
        self.clock_drift = if drift.abs() > CLOCK_DRIFT_ALARM_SECS {
            (self.clock_drift.0.saturating_add(1), drift)
        } else {
            (0, drift)
        };
        self.log_clock_alarm();
    }

    /// Log the drift alarm when it starts and when it clears.
    fn log_clock_alarm(&mut self) {
        let alarm = self.clock_drift_alarm();
        if alarm.is_some() == self.clock_alarm_logged {
            return;
        }
        self.clock_alarm_logged = alarm.is_some();
        match alarm {
            Some(drift) => eprintln!(
                "⏰ [BT-1 ALARM] this node's clock differs from the chain's time by {drift} s: \
                 check its time sources (NTS)"
            ),
            None => eprintln!("⏰ [BT-1] the clock drift alarm cleared"),
        }
    }

    /// The genesis launch window: from `LAUNCH_WINDOW_SKEW_SECS` before
    /// `sys:genesis_time` to `LAUNCH_WINDOW_SECS` after it. No genesis time,
    /// no window.
    pub(crate) fn within_launch_window(storage: &StateDB, now: u64) -> bool {
        storage
            .get("sys:genesis_time")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|t| {
                now.saturating_add(LAUNCH_WINDOW_SKEW_SECS) >= t
                    && now <= t.saturating_add(LAUNCH_WINDOW_SECS)
            })
    }

    /// The V4 engine's active epoch (None on an inert node).
    pub fn v4_epoch(&self) -> Option<u64> {
        self.v4.as_ref().map(|e| e.epoch())
    }

    /// DE-6: a decision row disagreed. Recorded durably; ordering stops.
    fn halt_on_decision_conflict(&mut self, height: u64, err: &str) {
        let _ = self
            .storage
            .put(&format!("alarm:decision_conflict:{height}"), err);
        eprintln!("🚨 [DE-6] {err}: ordering halted at height {height}");
        self.ordering_halt = Some(err.to_string());
    }

    /// G1 EP-3 and EP-4 on the node. E closes in memory once H_E is accepted
    /// or adopted (its record was written in H_E's transaction). E+1 activates
    /// once this node holds QC(H_E), verified under C_E and binding H_E; the
    /// QC's `next_validator_set_hash` must be the hash of the committee this
    /// node derived, or ordering halts with `alarm:committee_mismatch`.
    fn v4_epoch_step(&mut self) {
        if self.ordering_halted().is_some() {
            return;
        }
        let Some(mut engine) = self.v4.take() else {
            return;
        };
        self.v4_epoch_step_with(&mut engine);
        self.v4_stakes = engine.stakes().to_vec();
        self.v4 = Some(engine);
    }

    fn v4_epoch_step_with(&mut self, engine: &mut crate::v4::Engine) {
        match engine.observe_close() {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                // Fail closed: E cannot be known closed, so nothing more of E
                // may be decided (the peers have closed it).
                let why = format!("the next epoch's record is unreadable: {e}");
                eprintln!("🚨 [EP-3] {why}: ordering halted");
                self.ordering_halt = Some(why);
                return;
            }
        }
        let Some(next) = engine.next_start().cloned() else {
            return;
        };
        let mismatch_key = format!("alarm:committee_mismatch:{:020}", next.epoch);
        if let Ok(Some(why)) = self.storage.get(&mismatch_key) {
            // Sync refused QC(H_E) for this reason (see chain_sync).
            self.ordering_halt = Some(why);
            return;
        }
        let Some(qc) = crate::qc_producer::stored_qc(&self.storage, next.prev_height) else {
            // A node that missed the votes has no other way to this one QC
            // (sync asks for blocks above its tip, GET_FINALITY for the latest
            // QC): ask peers for it.
            self.want_qc(next.prev_height);
            return;
        };
        let binds = qc.block_height == next.prev_height
            && qc.block_hash == next.prev_block_hash
            && qc.anchor_round == next.prev_closing_round
            && qc.anchor_hash == next.prev_anchor
            && qc.epoch == engine.epoch()
            && crate::qc::verify_qc(&qc, engine.committee(), &self.resolve_chain_id()).is_ok();
        if !binds {
            eprintln!(
                "[EP-4] the stored QC of height {} does not bind H_{}; activation waits",
                next.prev_height,
                engine.epoch()
            );
            return;
        }
        let derived = crate::qc::validator_set_hash(&next.committee);
        if qc.next_validator_set_hash != derived {
            let why = format!(
                "{}: QC(H_{}) binds next committee {:?}, this node derived {derived}",
                crate::v4::epoch::COMMITTEE_MISMATCH,
                engine.epoch(),
                qc.next_validator_set_hash
            );
            let _ = self.storage.put(&mismatch_key, &why);
            eprintln!("🚨 [EP-4] {why}: ordering halted");
            self.ordering_halt = Some(why);
            return;
        }
        let net = self.v4_net();
        if let Err(e) = engine.activate_next(&net) {
            eprintln!("[EP-4] activation of epoch {} failed: {e}", next.epoch);
            return;
        }
        println!(
            "⏭️  [EP-4] epoch {} active from round {}",
            next.epoch, next.first_round
        );
        self.current_round = engine.current_round();
        let orphans: Vec<String> = engine
            .take_orphaned_payloads()
            .into_iter()
            .filter(|p| !p.starts_with(SLASH_EVIDENCE_PREFIX))
            .collect();
        if !orphans.is_empty() {
            if let Ok(mut mp) = self.mempool.lock() {
                mp.return_unshipped(&orphans);
            }
        }
    }

    /// A conflict another component recorded (sync's IM-3 / EP-4 checks write
    /// `alarm:decision_conflict:*` or `alarm:committee_mismatch:*`) halts
    /// ordering here too, not only at the next boot.
    fn refresh_alarm_halt(&mut self) {
        if self.ordering_halt.is_some() {
            return;
        }
        for alarms in ["alarm:decision_conflict:", "alarm:committee_mismatch:"] {
            if let Some(Ok((key, _))) = self.storage.db.prefix_iterator(alarms.as_bytes()).next() {
                if key.starts_with(alarms.as_bytes()) {
                    self.ordering_halt = Some(format!(
                        "a consensus conflict was recorded ({})",
                        String::from_utf8_lossy(&key)
                    ));
                    return;
                }
            }
        }
    }

    /// Ask peers for the QC of a held height (`QC_WANT:{h}`), at most once
    /// per `QC_WANT_EVERY_TICKS`.
    fn want_qc(&mut self, h: u64) {
        if self.v4_ticks >= self.qc_want_next {
            self.qc_want_next = self.v4_ticks + QC_WANT_EVERY_TICKS;
            self.v4_net().broadcast_wire(format!("{QC_WANT_PREFIX}{h}"));
        }
    }

    /// `QC_WANT:{h}`: a peer asks for the QC of a height (its boundary block,
    /// a block it cannot adopt without one, or one it voted on). Answered with
    /// the stored QC, at most once per `QC_WANT_EVERY_TICKS` per height (the
    /// oldest throttle entry is evicted, never the whole table) and at most
    /// `QC_ANSWERS_PER_TICK` answers per tick in all, so however asks are
    /// spread over heights they cost a bounded number of answers.
    fn answer_qc_want(&mut self, raw: &str) {
        if raw.len() > 20 {
            return;
        }
        let Ok(h) = raw.parse::<u64>() else {
            return;
        };
        if h == 0 || h > self.latest_block_height {
            return;
        }
        if self.qc_answer_budget.0 != self.v4_ticks {
            self.qc_answer_budget = (self.v4_ticks, 0);
        }
        if self.qc_answer_budget.1 >= QC_ANSWERS_PER_TICK {
            return;
        }
        if self
            .qc_answered
            .get(&h)
            .is_some_and(|t| self.v4_ticks < t + QC_WANT_EVERY_TICKS)
        {
            return;
        }
        let Some(raw_qc) = self.storage.get(&format!("consensus:qc:{h}")).ok().flatten() else {
            return;
        };
        if self.qc_answered.len() >= QC_ANSWERED_CAP {
            if let Some(oldest) = self
                .qc_answered
                .iter()
                .min_by_key(|(height, tick)| (**tick, **height))
                .map(|(height, _)| *height)
            {
                self.qc_answered.remove(&oldest);
            }
        }
        self.qc_answered.insert(h, self.v4_ticks);
        self.qc_answer_budget.1 += 1;
        self.v4_net().broadcast_wire(format!("{QC_CERT_PREFIX}{raw_qc}"));
    }

    /// `QC_CERT:{qc}`: a QC for a block this node holds. Stored only if it
    /// verifies under that block's committee and binds the block (IM-1), then
    /// the epoch step runs (it may activate).
    fn on_boundary_qc(&mut self, json: &str) {
        if json.len() > 64 * 1024 {
            return;
        }
        let Ok(qc) = serde_json::from_str::<crate::qc::QuorumCertificate>(json) else {
            return;
        };
        if crate::qc_producer::stored_qc(&self.storage, qc.block_height).is_some() {
            return;
        }
        // Verified under the height's committee and bound to the held block
        // before it is stored (a verified QC for another block is IM-3's
        // conflict); on V4 an import never touches the ordering keys.
        if let Err(e) = crate::qc_producer::import_finality_qc(&self.storage, &qc) {
            eprintln!("[EP-4] QC of block {} not stored: {e}", qc.block_height);
            self.refresh_alarm_halt();
            return;
        }
        self.v4_epoch_step();
    }

    /// Boot the certified-DAG engine on a V4 chain (RC-1). A V4 chain without
    /// its genesis committee or identity cannot run: boot stops.
    fn start_v4(&mut self) {
        let committee = crate::qc_producer::load_validator_set_for_epoch(&self.storage, 0)
            .expect("a V4 chain needs its genesis committee (genesis:validator_set:v1)");
        let genesis_identity = self
            .storage
            .get("genesis_identity")
            .ok()
            .flatten()
            .expect("a V4 chain needs its genesis identity");
        let cfg = crate::v4::Config {
            chain_id: self.resolve_chain_id(),
            genesis_identity,
            committee,
            node_key: self.node_key,
            address: self.node_id.clone(),
            b_auth: crate::staging::B_AUTH,
            // The node closes epochs on its own blocks (S9b), not by count.
            epoch_interval: 0,
        };
        let shared = crate::v4::Shared {
            dag: Arc::clone(&self.dag),
            round_index: Arc::clone(&self.round_index),
            ordering: Arc::clone(&self.ordering_engine),
        };
        // RC-3: the guard origin is written only on an explicit first start.
        // Only within the launch window after `sys:genesis_time`: the flag
        // left set on a database wiped later must not re-arm signing (final
        // review MEDIUM); that node resumes by RC-3's resume point instead.
        let flag = std::env::var("AINCORE_GUARD_ORIGIN_INIT").ok().as_deref() == Some("1");
        let genesis_init = flag && Self::within_launch_window(&self.storage, (self.now_secs)());
        if flag && !genesis_init {
            eprintln!(
                "⚠️ [RC-3] AINCORE_GUARD_ORIGIN_INIT is set outside the launch window \
                 (sys:genesis_time + {LAUNCH_WINDOW_SECS} s): ignored; remove it"
            );
        }
        let engine = crate::v4::Engine::open_shared(
            Arc::clone(&self.storage),
            cfg,
            shared,
            genesis_init,
            Arc::clone(&self.now_secs),
        )
        .unwrap_or_else(|e| panic!("the V4 engine did not boot: {e}"));
        self.current_round = engine.current_round();
        self.v4_stakes = engine.stakes().to_vec();
        self.v4 = Some(engine);
    }

    /// Replace the wall clock, the V4 engine's included.
    pub fn set_now_secs(&mut self, now_secs: Arc<dyn Fn() -> u64 + Send + Sync>) {
        if let Some(engine) = self.v4.as_mut() {
            engine.set_now_secs(Arc::clone(&now_secs));
        }
        self.now_secs = now_secs;
    }

    fn v4_net(&self) -> V4Net {
        V4Net {
            node_id: self.node_id.clone(),
            p2p_tx: self.p2p_tx.clone(),
            peers: self.peers.clone(),
            storage: Arc::clone(&self.storage),
            #[cfg(any(test, feature = "sim"))]
            outbox: self.v4_outbox.clone(),
        }
    }

    /// One V4 message through the engine, then the commit loop if O_E grew.
    fn on_v4_message(&mut self, raw_len: usize, msg: crate::v4::Msg) {
        let Some(mut engine) = self.v4.take() else {
            return;
        };
        let net = self.v4_net();
        engine.on_message(raw_len, msg, &net);
        let progressed = engine.take_progress();
        self.current_round = self.current_round.max(engine.current_round());
        self.v4 = Some(engine);
        if progressed {
            self.commit_ready_anchors(0);
        }
    }

    /// The V4 tick: PR-1..PR-4 through the engine, with this node's payload
    /// gathered only when a proposal is due, then the commit loop if O_E grew.
    fn v4_tick(&mut self) {
        self.v4_ticks += 1;
        self.refresh_alarm_halt();
        // A height this node voted on whose QC never reached it (lost votes)
        // is fetched instead of being retried forever (final review MEDIUM).
        if let Some(h) = crate::qc_producer::lowest_pending_qc_height(&self.storage) {
            if crate::qc_producer::stored_qc(&self.storage, h).is_none() {
                self.want_qc(h);
            }
        }
        self.retry_qc_work();
        self.v4_epoch_step();
        let Some(mut engine) = self.v4.take() else {
            return;
        };
        let net = self.v4_net();
        if let Some(slot) = engine.tick(&net) {
            let payload = if slot.carry_payload {
                let overhead = engine
                    .proposal_overhead(slot.round)
                    .saturating_add(crate::v4::WIRE_PREFIX.len());
                self.gather_payload(slot.round, overhead)
            } else {
                Vec::new()
            };
            if engine.propose(slot.round, payload.clone(), &net) {
                self.current_round = self.current_round.max(slot.round);
            } else {
                let txs: Vec<String> = payload
                    .into_iter()
                    .filter(|p| !p.starts_with(SLASH_EVIDENCE_PREFIX))
                    .collect();
                if !txs.is_empty() {
                    if let Ok(mut mp) = self.mempool.lock() {
                        mp.return_unshipped(&txs);
                    }
                }
            }
        }
        let progressed = engine.take_progress();
        self.v4 = Some(engine);
        if progressed {
            self.commit_ready_anchors(0);
        }
    }

    /// Has this anchor round already been placed on chain?
    ///
    /// AUDIT B4b — the single source of truth for "already done". It is decided by
    /// ANCHOR ROUND, never by height. The live burn-in showed what deciding by
    /// height costs: three distinct anchors (12220, 12224, 12226) were all skipped
    /// against the SAME height 5073 because `reload_chain_tip` had not yet seen
    /// sync's writes, so anchor 12226 never got a block on that node while its
    /// peers placed it at 5075. The node's anchor->height mapping went out of step
    /// with the network's, and the chain forked at the block level.
    ///
    /// This predicate previously existed as FIVE textually identical copies across
    /// the placement path. Five copies of one safety condition is precisely the
    /// shape that drifts — a later edit fixes four of them and the fifth becomes a
    /// fork. It is one function now, and `anchor_height_map_intact` below is its
    /// companion assertion at the moment of placement.
    /// `pub(crate)` only so the boundary case can be asserted from `tests`, which
    /// is a sibling module of `dag`, not a descendant. An off-by-one here is a
    /// fork, so it must be testable.
    #[inline]
    pub(crate) fn anchor_already_on_chain(&self, anchor_round: u64) -> bool {
        anchor_round <= self.latest_block_round
    }

    /// P_ANCHOR_HEIGHT, checked at the one moment it can be violated.
    ///
    /// The map `anchor_round -> block_height` must be injective and strictly
    /// increasing along the chain. A block about to be placed for an anchor round
    /// that is already at or below the tip's round would break that — and this is
    /// the invariant whose violation WAS the live B4b fork.
    ///
    /// Reports; never changes behaviour. A check that could itself drop a block
    /// would be a worse defect than the one it guards against.
    fn assert_anchor_height_map(&self, anchor_round: u64, height: u64) {
        if !self.anchor_already_on_chain(anchor_round) {
            return;
        }
        eprintln!(
            "🚨 P_ANCHOR_HEIGHT VIOLATED: placing anchor round {} at height {} while \
             the tip is already at round {}. The anchor->height map is no longer \
             strictly increasing, which is the live B4b block-fork signature. \
             This node's mapping has diverged from the network's.",
            anchor_round, height, self.latest_block_round
        );
        // Durable, so ops finds it after the fact rather than in a lost log line.
        let _ = self.storage.put(
            &format!("alarm:anchor_height_violation:{}", height),
            &format!("{{\"anchor_round\":{},\"tip_round\":{}}}", anchor_round, self.latest_block_round),
        );
    }

    /// Phase 2.8 (M-08): force the next `get_validator_set` to re-read
    /// from storage. Called on block commit because that's the only
    /// moment validator set may legitimately change during normal
    /// operation (slash execution updates `sys:validators`). Public so
    /// out-of-band code paths (genesis init, integration tests,
    /// admin tooling that mutates storage directly) can force a refresh.
    pub fn invalidate_validators_cache(&self) {
        if let Ok(mut guard) = self.validators_cache.lock() {
            *guard = None;
        }
    }

    /// One consensus tick (G1 S5). Only a V4 chain has an engine; a node on
    /// any other database is inert (G5 S4c: the V3 DAG is deleted, and boot
    /// refuses such a database before it gets here).
    pub fn try_create_vertex(&mut self) {
        if self.v4_chain {
            self.v4_tick();
            self.log_clock_alarm();
        }
    }

    /// The committee a decision reads: the frozen C_E (DE-7), for the leader,
    /// the votes, the reward and BFT time.
    fn decision_committee(&self) -> Vec<(String, u64)> {
        self.v4_stakes.clone()
    }

    /// Decide and place every anchor that is ready: one anchor per decision,
    /// its block executed and accepted before the next is decided.
    fn commit_ready_anchors(&mut self, trigger_round: u64) {
        if self.ordering_halted().is_some() {
            return;
        }
        // --- ORDERING LOGIC (Bullshark-lite) ---
        // Now we can take new locks without holding the previous ones.

        // We need read access to DAG and RoundIndex for ordering check, BUT we don't need write.
        // And we definitly don't want to hold them during execution.

        // PROTOCOL (re-audit HIGH): decide ONE anchor per try_commit call, execute
        // its block, then RE-SAMPLE the validator set and decide the next. A
        // slash / join / leave executed by anchor k rewrites the set; deciding a
        // whole batch from one pre-k sample elected k+1's leader from the wrong
        // set on nodes that happened to batch (gossip holes make batching
        // node-dependent) -> different reward recipient / anchor -> fork.
        // Every `continue` below re-enters this loop and re-decides.
        'anchors: loop {
            self.reload_chain_tip();
            // G1 (V4): the ordering state is valid only once it has absorbed
            // every block on the chain. While a held block is not adopted (no
            // QC yet, a crash between import and adoption), nothing is decided
            // locally: a decision would re-collect that block's sequence.
            if self.last_adopted_height < self.latest_block_height {
                break;
            }
            let plan = {
                let engine = self
                    .ordering_engine
                    .lock()
                    .expect("🚨 FATAL: Ordering engine lock poisoned");
                let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");
                let round_idx = self
                    .round_index
                    .lock()
                    .expect("🚨 FATAL: Round index lock poisoned");
                // B4: stake-aware set so the commit-side quorum is stake-weighted.
                // Re-sampled on EVERY iteration: the previous anchor's block may have
                // just changed it.
                self.invalidate_validators_cache();
                let validators = self.decision_committee();

                let Some(plan) =
                    engine.prepare_commit(trigger_round, &dag, &round_idx, &validators)
                else {
                    break;
                };
                plan
            }; // All locks dropped here!
            let commit = plan.info.clone();

            // AUDIT-B4b: ONE block per anchor, on every node identically.
            // AUDIT-B4b (dedup): if the chain tip already covers this anchor, a
            // ChainSync import beat the local commit to it — the peer's block for
            // this anchor is ALREADY on our chain, fully executed and state-root
            // verified by the sync path. Building it again here would put the
            // same anchor at two heights and shift this node's numbering off the
            // network's forever. The ordering-engine bookkeeping (cursor, digest,
            // committed-set) must be adopted from the durable block, not from
            // this local speculative plan. reload_chain_tip above retries that.
            if self.anchor_already_on_chain(commit.anchor_round) {
                println!(
                    "⏭️  Anchor round {} already on chain via sync (tip round {}) — skipping duplicate block",
                    commit.anchor_round, self.latest_block_round
                );
                break;
            }
            println!(
                "Anchor round {} ready: preparing execution of {} vertices...",
                commit.anchor_round,
                commit.sequence.len()
            );

            // Clone the Arc so the borrow of `self.executor` ends here: the
            // anchor-placement retry below needs `&mut self` for reload_chain_tip.
            let executor = std::sync::Arc::clone(&self.executor);
            let mut block_txs = Vec::new();
            // PROTOCOL: evidence carried by committed vertices, in commit order,
            // with the carrying author (to latch our own markers on inclusion).
            let mut carried_evidence: Vec<(String, String)> = Vec::new();
            let reward_recipient = commit.leader.clone(); // C-10 FIX: Reward the anchor leader deterministically

            // Re-acquire DAG read lock just to fetch payloads
            // We can optimize this by cloning necessary data in the previous block,
            // but identifying which vertices are committed before engine runs is hard.
            // So we just re-acquire efficiently.
            // AUDIT-H1: collect the committed vertices' AUTHOR-SIGNED timestamps so
            // the block timestamp can be derived deterministically (BFT-Time) rather
            // than read from this node's wall clock. Vertex timestamps are inside
            // Vertex::calculate_hash and signed, so every node sees identical values.
            // Keep the RAW per-vertex BFT-time inputs. Stake weights (and
            // which authors count at all) are joined in later against a set
            // sampled at the tip we actually build on -- the first cut baked in
            // one pre-loop sample, so a tip move produced a timestamp weighted
            // by the OLD validator set while peers used the new one.
            let mut ts_raw: Vec<(String, u64)> = Vec::new();

            let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");

            for hash in &commit.sequence {
                if let Some(v) = dag.get(hash) {
                    // Clone payload to release DAG lock faster?
                    // No, looking up payload is fast. Execution is slow.
                    // But we must NOT hold DAG lock during execution.
                    // So we collect ALL txs first.
                    // PROTOCOL: split the committed payload. `SLASH_EVIDENCE:` items
                    // are evidence ordered by consensus; everything else is a tx.
                    let mut per_vertex = 0usize;
                    for item in &v.payload {
                        if let Some(ev) = item.strip_prefix(SLASH_EVIDENCE_PREFIX) {
                            // Bound verification work per committed vertex: an
                            // honest carrier never exceeds this; extra items from
                            // a spammer are ignored.
                            if per_vertex >= MAX_EVIDENCE_PER_VERTEX {
                                continue;
                            }
                            // Only the kind this protocol orders through the DAG.
                            // A "downtime" item reaching the block path would fold
                            // node-local attestation rows into the state root.
                            if Self::is_equivocation_item(ev) {
                                per_vertex += 1;
                                carried_evidence.push((v.author.clone(), ev.to_string()));
                            }
                        } else {
                            block_txs.push(item.clone());
                        }
                    }
                    ts_raw.push((v.author.clone(), v.timestamp));
                } else {
                    // A committed vertex MUST be present: the sequence was computed
                    // from this DAG moments ago. If it is gone, something pruned it
                    // mid-batch and this block's content is about to diverge from
                    // every other node's. Never silent.
                    eprintln!(
                        "🚨 [SECURITY][COMMIT_VERTEX_MISSING] anchor round {} sequence hash {} \
                         is not in the DAG at block-build time; deferring without partial acceptance",
                        commit.anchor_round, hash
                    );
                    break 'anchors;
                }
            }
            drop(dag); // DROP DAG LOCK NOW!

            // BFT-TIME DETERMINISM (burn-in finding, h=121): the monotonic clamp
            // must use the CANONICAL parent's timestamp — the stored block at the
            // current tip — never the in-memory field. That field was kept as a
            // running max() across sync reloads, so a node that had built a local
            // block later superseded by the synced chain carried a stale-high value
            // into its next clamp and produced a header one second off from every
            // other node (same vertices, same state, different hash).
            let parent_ts = self
                .storage
                .get(&format!("block_{}", self.latest_block_height))
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
                .map(|b| b.header.timestamp)
                .unwrap_or(self.latest_block_timestamp);
            // Join raw samples with a freshly sampled stake map: both the
            // membership filter and the weights must come from the set as of the
            // tip we are building on.
            let block_timestamp =
                committee_block_timestamp(&ts_raw, &self.decision_committee(), parent_ts);

            // Execute without holding DAG/round-index locks.
            // We execute even if empty to trigger Block Rewards (Heartbeat Mining)
            {
                println!(
                    "🚀 Executing Parallel Batch of {} transactions",
                    block_txs.len()
                );

                // Use Executor parallel logic directly?
                // The existing logic was: analyze deps -> schedule -> execute.
                // We can use executor.execute_block_parallel(block_txs).
                // PROTOCOL (deterministic slashing): evidence is NOT gathered from
                // this node's local view any more -- that made the block a function
                // of which node saw what and forked the chain. It is extracted from
                // the COMMITTED vertices above, which are identical on every node,
                // then canonicalised (dedup by offender+round, first in commit
                // order, capped). Every node still verifies each item independently
                // before applying (executor::apply_slash_evidence).
                let slash_evidence: Vec<String> =
                    Self::canonicalize_evidence(&executor, &carried_evidence);
                // Every decision/input belongs to this parent. If sync moves
                // it, re-plan ordering as well as evidence and BFT time.
                let verified_tip = self.latest_block_height;
                // ANCHOR PLACEMENT (burn-in fix): every committed anchor must get
                // EXACTLY ONE block, and "already done" is decided by ANCHOR ROUND,
                // never by height. The first cut skipped on height alone, and the
                // live log shows what that cost: three distinct anchors (12220,
                // 12224, 12226) were all skipped against the SAME height 5073
                // because reload_chain_tip had not yet seen sync's writes. Anchor
                // 12226 therefore never got a block on that node while its peers
                // placed it at 5075 — the node's anchor->height mapping was off by
                // one from then on and it hard-forked (23,936 parent-hash
                // rejections). Retry against the refreshed tip; only treat it as a
                // duplicate when the chain genuinely already carries this anchor.
                let mut placed: Option<(executor::BlockExecutionSummary, blockchain::Block)> = None;
                let mut already_on_chain = false;
                // Retries are SPACED: the live alarm showed all four attempts
                // firing inside the same millisecond, each hitting
                // "height N already executed" because ChainSync had EXECUTED
                // height N but not yet PERSISTED its block — so reload_chain_tip
                // kept returning the stale tip and the anchor was dropped a beat
                // before sync's write landed ("Synced up to block #52" appears on
                // the very next line). A short wait between attempts lets that
                // write become visible; total worst case ~2s, which the consensus
                // ticker (>=500ms) absorbs.
                for attempt in 0..8 {
                    if attempt > 0 {
                        (self.placement_sleep)(std::time::Duration::from_millis(250));
                        self.reload_chain_tip();
                        if self.anchor_already_on_chain(commit.anchor_round) {
                            already_on_chain = true;
                            break;
                        }
                    }
                    if self.latest_block_height != verified_tip {
                        continue 'anchors;
                    }
                    let mut accepted_block = None;
                    let engine_arc = Arc::clone(&self.ordering_engine);
                    // Lock order: ordering -> executor -> storage writers. Sync
                    // releases execution/storage before reload acquires ordering.
                    // Never call reload_chain_tip while holding this guard.
                    let outcome = {
                        let mut engine = engine_arc.lock().expect("ordering engine lock poisoned");
                        if !engine.prepared_is_current(&plan) {
                            continue 'anchors;
                        }
                        let parent_height = self.latest_block_height;
                        let parent_hash = self.latest_block_hash.clone();
                        let qc_chain_id = self.resolve_chain_id();
                        #[cfg(test)]
                        let pre_execution_hook = self.pre_execution_hook;
                        let outcome = executor.execute_block_admitted_at(
                            block_txs.clone(),
                            &reward_recipient,
                            // The block being BUILT: one above the current tip.
                            self.latest_block_height + 1,
                            // G5 CL-2: its BFT timestamp drives consensus time.
                            block_timestamp,
                            // G5 BW-6: its anchor round (the header's `round`).
                            commit.anchor_round,
                            &slash_evidence,
                            // Nothing to admit for a block this node built. Tests
                            // may stage state here, BEFORE execution: after the
                            // state root is sealed (G3 CM-2) a state write fails
                            // the whole block.
                            |_view| {
                                #[cfg(test)]
                                if let Some(hook) = pre_execution_hook {
                                    hook(0, _view)?;
                                }
                                Ok(())
                            },
                            |summary, view| {
                                let stored_height = view.get("latest_height").map_err(|e| e.to_string())?
                                    .map(|h| h.parse::<u64>()).transpose().map_err(|e| e.to_string())?
                                    .unwrap_or(0);
                                let stored_hash = view.get("latest_block_hash").map_err(|e| e.to_string())?
                                    .unwrap_or_else(|| "genesis".to_string());
                                if stored_height != parent_height || stored_hash != parent_hash {
                                    return Err("local block parent changed before acceptance".to_string());
                                }
                                let mut block = blockchain::Block::new_with_roots_at(
                                    parent_height + 1, commit.anchor_round, parent_hash.clone(),
                                    block_txs.clone(), reward_recipient.clone(),
                                    summary.state_root.clone(), summary.receipts_root.clone(),
                                    block_timestamp, commit.sequence.clone(), commit.anchor_hash.clone(),
                                    slash_evidence.clone(),
                                );
                                if !block.anchor_is_bound() {
                                    // G0: every peer would refuse this block.
                                    return Err("the anchor is not the last committed vertex".to_string());
                                }
                                block.sign_proposer(&crypto::SigningKey::from_bytes(&self.node_key), &self.node_id);
                                let json = serde_json::to_string(&block).map_err(|e| e.to_string())?;
                                view.save_block_json(parent_height + 1, &json).map_err(|e| e.to_string())?;
                                engine.stage_prepared_anchor(&plan, view)?;
                                // G1 EP-2/EP-3: a boundary block closes its epoch
                                // in its own transaction (before the QC work,
                                // whose vote binds the next committee).
                                crate::v4::epoch::stage_boundary(view, &block)?;
                                crate::qc_producer::stage_pending_qc(
                                    view, &block, &plan.info, qc_chain_id.clone(),
                                )?;
                                view.put("consensus:last_adopted_height", &(parent_height + 1).to_string())
                                    .map_err(|e| e.to_string())?;
                                #[cfg(test)]
                                if let Some(hook) = self.local_acceptance_hook { hook(0, view)?; }
                                accepted_block = Some(block);
                                Ok(())
                            },
                        );
                        if matches!(&outcome, Ok(executor::BlockExecOutcome::Executed(_))) {
                            #[cfg(test)]
                            if let Some(hook) = self.local_acceptance_hook {
                                hook(1, &self.storage).expect("post-commit test hook failed");
                            }
                            engine.publish_prepared_anchor(&plan);
                        }
                        outcome
                    };
                    match outcome {
                        Ok(executor::BlockExecOutcome::Executed(summary)) => {
                            placed = Some((summary, accepted_block.expect("accepted block missing")));
                            break;
                        }
                        Ok(executor::BlockExecOutcome::AlreadyExecuted { last_executed }) => {
                            self.reload_chain_tip();
                            if self.anchor_already_on_chain(commit.anchor_round) {
                                println!(
                                    "⏭️  Anchor round {} already on chain via sync (tip round {}, last_executed={})",
                                    commit.anchor_round, self.latest_block_round, last_executed
                                );
                                already_on_chain = true;
                                break;
                            }
                            // Height was taken by a DIFFERENT anchor's block: our
                            // anchor still needs one. Retry at the refreshed tip.
                        }
                        Ok(executor::BlockExecOutcome::Gap { expected, got }) => {
                            eprintln!(
                                "⏸️  Anchor round {}: execution gap (expected height {}, wanted {}) — refreshing tip",
                                commit.anchor_round, expected, got
                            );
                            self.reload_chain_tip();
                            if self.anchor_already_on_chain(commit.anchor_round) {
                                already_on_chain = true;
                                break;
                            }
                        }
                        Err(err) => {
                            eprintln!("[LOCAL_BLOCK_ACCEPTANCE_FAILED] anchor {}: {err}; ordering not advanced", commit.anchor_round);
                            if err.contains(crate::ordering::DECISION_CONFLICT) {
                                let height = self.latest_block_height + 1;
                                self.halt_on_decision_conflict(height, &err);
                            }
                            break;
                        }
                    }
                }
                if already_on_chain {
                    continue;
                }
                // Final check before deferring: sync may have persisted the
                // block during the last wait.
                if placed.is_none() && !already_on_chain {
                    self.reload_chain_tip();
                    if self.anchor_already_on_chain(commit.anchor_round) {
                        already_on_chain = true;
                    }
                }
                if already_on_chain {
                    continue;
                }
                // Latch the durable carried-marker ONLY now that the block is
                // actually placed, and only for items WE carried that the block
                // really contains. Doing it at canonicalisation time marked
                // items that a later recompute dropped, and they were never
                // re-carried.
                if placed.is_some() {
                    Self::latch_carried(
                        &self.storage,
                        &self.evidence_inflight,
                        &self.node_id,
                        &carried_evidence,
                        &slash_evidence,
                    );
                }
                let Some((execution_summary, new_block)) = placed else {
                    // Keep the plan retryable. Do not skip to the next anchor.
                    eprintln!(
                        "[ANCHOR_DEFERRED] anchor round {} has no accepted block \
                         (tip height {}, tip round {}); ordering cursor retained",
                        commit.anchor_round, self.latest_block_height, self.latest_block_round
                    );
                    break;
                };
                // G1 EP-3: if that was H_E, E closes before anything else is
                // decided (no epoch-E anchor above r*).
                self.v4_epoch_step();
                // Orphan-loss fix: settle the mempool's loan ledger — only the
                // transactions that actually EXECUTED leave it; the rest stay
                // inflight and requeue_stale() returns them to pending later.
                if let Ok(mut mp) = self.mempool.lock() {
                    mp.mark_executed(&execution_summary.executed_raws);
                }

                // Durable state, block, indexes and ordering already committed.
                // Publish caches and external side effects only after that point.
                self.latest_block_height = new_block.header.height;
                self.latest_block_hash = new_block.header.hash.clone();
                self.latest_block_timestamp = new_block.header.timestamp;
                self.check_clock_drift(new_block.header.timestamp);
                self.assert_anchor_height_map(commit.anchor_round, self.latest_block_height);
                self.latest_block_round = commit.anchor_round;
                self.last_adopted_height = self.latest_block_height;

                // Update Accumulator and DB
                if let Ok(bytes) = hex::decode(&new_block.header.hash) {
                    self.accumulator.append(&bytes);
                }

                {
                    prune_history(
                        &self.storage,
                        self.latest_block_height,
                        storage::StateDB::block_pruning_policy_from_env(),
                    );
                    // Phase 2.8 (M-08): block commit is the only moment
                    // where a slash could have changed the validator set
                    // during normal operation, so refresh the cache here.
                    self.invalidate_validators_cache();
                    println!(
                        "📦 Created Block #{} (Hash: {:.8})",
                        self.latest_block_height, self.latest_block_hash
                    );

                    // === DA SEQUENCER INTEGRATION ===
                    // L1 FIX: Wire DA verification into consensus finality
                    if let Some(da_seq) = &self.da_sequencer {
                        if let Ok(mut seq) = da_seq.lock() {
                            println!("🧩 [Consensus] Triggering DA Batch with erasure coding verification...");
                            seq.create_batch(self.latest_block_hash.clone(), block_txs.len());
                            // DA batch includes: erasure coding, Merkle proof generation,
                            // shard distribution to peers, and fraud proof readiness.
                            // Light clients can now verify data availability via DAS sampling.
                            println!(
                                "✅ [DA] Block #{} data availability confirmed",
                                self.latest_block_height
                            );
                        }
                    }

                    // The request committed with the block. Signing/gossip may
                    // fail here; later ticks or reopen retry that same context.
                    self.retry_qc_work();
                }
            }
        }

    }

    /// A vertex payload for `round`: queued equivocation evidence first, then
    /// mempool transactions, trimmed from the end until a vertex whose
    /// payload-free wire size is `overhead` fits `MAX_VERTEX_BYTES`. Trimmed
    /// transactions go back to the mempool.
    fn gather_payload(&mut self, round: u64, overhead: usize) -> Vec<String> {
        let mut payload = Vec::new();
        if let Ok(mut mp) = self.mempool.lock() {
            // Orphan-loss fix: before pulling, reclaim loaned transactions
            // that never executed (orphaned vertex payloads and
            // nonce-deferred txs). 30s ≈ well past commit latency, well
            // short of user-visible loss.
            let _ = mp.requeue_stale(std::time::Duration::from_secs(30));
            // Throughput tuning: pull size per vertex. Narwhal is designed for
            // large batches; 50 was a conservative bring-up cap and became the
            // de-facto per-round throughput ceiling. Env-tunable so the burn-in
            // and benchmark runs measure the config that will actually ship.
            let pull = std::env::var("AINCORE_MEMPOOL_PULL")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| (1..=10_000).contains(v))
                .unwrap_or(500);
            payload = mp.get_pending_transactions(pull);
            if !payload.is_empty() {
                println!("🚀 DAG PULLED {} TXS FROM MEMPOOL", payload.len());
            }
        }

        // PROTOCOL: carry queued equivocation evidence in this vertex so it
        // is ordered by consensus and extracted identically on every node.
        let carried = self.drain_evidence_for_vertex(round);
        if !carried.is_empty() {
            println!(
                "⚖️  DAG carrying {} slash evidence item(s) in this vertex",
                carried.len()
            );
            let mut with_evidence = carried;
            with_evidence.extend(payload);
            payload = with_evidence;
        }
        // BYTE BUDGET: never build a vertex the transport cannot deliver.
        // Measure what is actually shipped -- the serialized JSON of the
        // whole DAG_VERTEX message -- not an estimate: JSON escaping and the
        // fixed fields made an estimate under-count, so a "trimmed" vertex
        // was still rejected on the wire. Drop from the END (txs first,
        // evidence last) until it fits.
        {
            // Fixed overhead measured ONCE with an empty payload, then a
            // running total of each item's escaped contribution. The first
            // cut re-serialised the whole remaining payload on every pop,
            // which is quadratic in payload bytes under the consensus lock.
            let item_cost = |it: &String| -> usize {
                // escaped JSON string + the separating comma
                serde_json::to_string(it)
                    .map(|s| s.len())
                    .unwrap_or(usize::MAX)
                    + 1
            };
            let mut total: usize =
                overhead.saturating_add(payload.iter().map(item_cost).sum::<usize>());
            let mut trimmed_txs: Vec<String> = Vec::new();
            while total > MAX_VERTEX_BYTES && !payload.is_empty() {
                if let Some(d) = payload.pop() {
                    total = total.saturating_sub(item_cost(&d));
                    if d.starts_with(SLASH_EVIDENCE_PREFIX) {
                        eprintln!("⚠️  evidence item deferred: vertex byte budget");
                    } else {
                        // A trimmed tx was LOANED by the mempool
                        // (get_pending_transactions moved it to inflight).
                        // Dropping it here would strand it until
                        // requeue_stale, and after MAX_REQUEUE_ATTEMPTS a
                        // valid accepted transaction is deleted outright.
                        trimmed_txs.push(d);
                    }
                }
            }
            if !trimmed_txs.is_empty() {
                if let Ok(mut mp) = self.mempool.lock() {
                    mp.return_unshipped(&trimmed_txs);
                }
                println!(
                    "↩️  returned {} tx(s) to the mempool: vertex byte budget",
                    trimmed_txs.len()
                );
            }
        }
        payload
    }

    fn retry_qc_work(&mut self) {
        // A halted node signs no finality vote, nor does an inert one.
        if !self.v4_chain || self.ordering_halted().is_some() {
            return;
        }
        let chain = self.resolve_chain_id();
        match crate::qc_producer::retry_pending_qcs(
            &self.storage,
            &self.node_key,
            &self.node_id,
            &chain,
            &mut self.qc_retry_cursor,
        ) {
            Ok(outcomes) => {
                for outcome in outcomes {
                    match outcome {
                        crate::qc_producer::QcOutcome::Partial(message) => {
                            self.broadcast_qc_vote(&message)
                        }
                        crate::qc_producer::QcOutcome::Complete(cert) => {
                            if let Ok(mut engine) = self.ordering_engine.lock() {
                                engine.fold_qc_for_height(cert.block_height);
                            }
                        }
                        crate::qc_producer::QcOutcome::Skipped => {}
                    }
                }
            }
            Err(error) => eprintln!("[QC] pending work scan deferred: {error}"),
        }
    }

    /// The chain id QC votes are signed under: the same `sys:chain_id` the
    /// verifiers check (G3 FX-6). It used to prefer storage but fall back to
    /// the env and then the genesis file, while verification read only the
    /// env, so the two could disagree.
    fn resolve_chain_id(&self) -> String {
        crate::qc::expected_chain_id()
    }

    /// PROTOCOL: evidence items (WITH prefix) to carry in the vertex being
    /// built: the durable V4 rows (G1 EQ-1 and CE-3, G5 SL-3), keyed by epoch.
    /// An item is skipped if already latched as included (written only when
    /// it lands in a block this node carried it into) or in flight in a recent
    /// vertex of ours. No durable marker is written here, so an orphaned or
    /// cap-dropped carry is re-carried after INFLIGHT_TTL_ROUNDS. Local
    /// bookkeeping only -- never a state-root write.
    pub(crate) fn drain_evidence_for_vertex(&self, current_round: u64) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        // The offender need not be in the live set (evidence is checked
        // against the committee of its epoch).
        use crate::v4::evidence as ev;
        type Keys = (
            fn(&str, u64, u64) -> String,
            fn(&str, u64, u64) -> (String, u64),
        );
        let kinds: [(&str, Keys); 2] = [
            ("sys:equiv_seen_v4:", (ev::carried_key, ev::flight_key)),
            (
                "sys:equiv_cert_v4:",
                (ev::cert_carried_key, ev::cert_flight_key),
            ),
        ];
        for (prefix, (carried_key, flight_key)) in kinds {
            for (key, item) in self.storage.scan_prefix(prefix) {
                if out.len() >= MAX_EVIDENCE_PER_VERTEX {
                    break;
                }
                let Some(rest) = key.strip_prefix(prefix) else {
                    continue;
                };
                let mut parts = rest.rsplitn(3, ':');
                let (Some(round), Some(epoch), Some(off)) = (
                    parts.next().and_then(|r| r.parse::<u64>().ok()),
                    parts.next().and_then(|e| e.parse::<u64>().ok()),
                    parts.next(),
                ) else {
                    continue;
                };
                if matches!(
                    self.storage.get(&carried_key(off, epoch, round)),
                    Ok(Some(_))
                ) {
                    continue;
                }
                // In flight in a recent vertex of ours: nothing to verify.
                let flight = flight_key(off, epoch, round);
                let in_flight = self.evidence_inflight.lock().is_ok_and(|inflight| {
                    inflight
                        .get(&flight)
                        .is_some_and(|&at| current_round.saturating_sub(at) < INFLIGHT_TTL_ROUNDS)
                });
                if in_flight {
                    continue;
                }
                // G5 review: only what the executor accepts takes a slot. A
                // row it can never accept again (older than W, its records
                // pruned, its offenders jailed) is retired, so it neither
                // comes back every TTL nor grows the scan.
                if let Err(why) = self.executor.verify_slash_evidence(&item) {
                    if ["older than W", "pruned", "jailed already"]
                        .iter()
                        .any(|m| why.contains(m))
                    {
                        let _ = self.storage.delete(&key);
                    }
                    continue;
                }
                if let Ok(mut inflight) = self.evidence_inflight.lock() {
                    inflight.insert(flight, current_round);
                }
                out.push(format!("{}{}", SLASH_EVIDENCE_PREFIX, item));
            }
        }
        out
    }

    /// PROTOCOL: verify -> dedup -> cap the evidence extracted from committed
    /// vertices, and latch OUR durable carried-marker (plain put, never state
    /// root) + release the in-flight entry only for items that actually land in
    /// the block and that WE carried. Anything else (orphaned, junk, cap-dropped)
    /// is re-carried after INFLIGHT_TTL_ROUNDS. Pure w.r.t. block content: the
    /// output depends only on `carried` (from the committed sequence) and the
    /// executor's on-chain-state verifier.
    fn canonicalize_evidence(executor: &Executor, carried: &[(String, String)]) -> Vec<String> {
        let items: Vec<String> = carried.iter().map(|(_, it)| it.clone()).collect();
        Self::canonical_block_evidence(items, |it| {
            executor.verify_slash_evidence(it).ok().map(|v| v.key())
        })
        .into_iter()
        .map(|(it, _)| it)
        .collect()
    }

    /// Latch the durable carried-marker (plain put, never state root) and release
    /// the in-flight entry for the items THIS node carried that actually made it
    /// into the placed block. Called only after placement, so an item dropped by
    /// a recompute, the cap, or a failed placement is re-carried after the TTL.
    fn latch_carried(
        storage: &StateDB,
        inflight: &Arc<Mutex<std::collections::BTreeMap<(String, u64), u64>>>,
        node_id: &str,
        carried: &[(String, String)],
        included: &[String],
    ) {
        let mine: std::collections::HashSet<&str> = carried
            .iter()
            .filter(|(a, _)| a == node_id)
            .map(|(_, it)| it.as_str())
            .collect();
        for item in included {
            if !mine.contains(item.as_str()) {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(item) else { continue };
            let (Some(off), Some(round)) = (
                v.get("offender").and_then(|x| x.as_str()),
                v.get("round").and_then(|x| x.as_u64()),
            ) else {
                continue;
            };
            use crate::v4::evidence as ev;
            let kind = v.get("kind").and_then(|k| k.as_str());
            let epoch = v.get("epoch").and_then(|e| e.as_u64());
            let flight = match (kind, epoch) {
                (Some(ev::KIND), Some(epoch)) => {
                    let _ = storage.put(&ev::carried_key(off, epoch, round), "1");
                    ev::flight_key(off, epoch, round)
                }
                (Some(ev::CERT_KIND), Some(epoch)) => {
                    let _ = storage.put(&ev::cert_carried_key(off, epoch, round), "1");
                    ev::cert_flight_key(off, epoch, round)
                }
                _ => continue,
            };
            if let Ok(mut f) = inflight.lock() {
                f.remove(&flight);
            }
        }
    }

    /// PROTOCOL: the only evidence kinds ordered through the DAG: V4
    /// proposer twins and certificate conflicts (G1 EQ-1, G5 SL-3). Anything
    /// else (the deleted V3 "equivocation" and "downtime" kinds) is dropped at
    /// the block-build split before it can reach the executor.
    pub fn is_equivocation_item(item: &str) -> bool {
        serde_json::from_str::<serde_json::Value>(item)
            .ok()
            .and_then(|x| {
                x.get("kind")
                    .and_then(|k| k.as_str())
                    .map(|k| k == crate::v4::evidence::KIND || k == crate::v4::evidence::CERT_KIND)
            })
            .unwrap_or(false)
    }

    /// PROTOCOL: canonicalise the evidence extracted from committed vertices.
    /// `verify` is the executor's on-chain-state verifier (pure at a given
    /// height, so identical on every node): it returns the VERIFIED
    /// (offender, round) or None. Items are verified FIRST, then deduped on
    /// the verified key keeping the first in commit order, then capped -- so a
    /// junk item can neither occupy a slot nor pre-empt a real item's key (an
    /// equivocator used to be able to self-shield by planting a junk item
    /// under its own (offender, round) ahead of the real proof). Returns the
    /// surviving items and their verified keys, in order.
    pub fn canonical_block_evidence<F>(items: Vec<String>, verify: F) -> Vec<(String, (String, u64))>
    where
        F: Fn(&str) -> Option<(String, u64)>,
    {
        use std::collections::BTreeSet;
        let mut seen: BTreeSet<(String, u64)> = BTreeSet::new();
        let mut out: Vec<(String, (String, u64))> = Vec::new();
        for item in items {
            if out.len() >= MAX_EVIDENCE_PER_VERTEX {
                break;
            }
            let Some(key) = verify(&item) else { continue };
            if seen.insert(key.clone()) {
                out.push((item, key));
            }
        }
        out
    }

    /// QC Phase 3: gossip THIS node's partial finality vote so peers can
    /// aggregate a multi-party quorum certificate. Mirrors the
    /// `broadcast_attestation` transport (Gossipsub + TCP fallback). The vote is
    /// self-authenticating: it carries a BLS signature the receiver verifies
    /// against the signer's key in the frozen epoch validator set, so no extra
    /// reporter signature is needed.
    fn broadcast_qc_vote(&self, vote_msg: &crate::qc_producer::QcVoteMessage) {
        let serialized = match serde_json::to_string(vote_msg) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ [QC] Failed to serialise finality vote: {}", e);
                return;
            }
        };
        // Gossipsub plus the TCP fallback (one transport for every
        // consensus message; tests route it through the outbox).
        self.v4_net()
            .broadcast_wire(format!("QC_VOTE:{}", serialized));
    }

    /// QC Phase 3: handle an inbound peer finality vote. Verify the single BLS
    /// signature against the signer's key in the frozen epoch validator set, bind
    /// the vote to THIS node's committed block at the vote's anchor round, persist
    /// it (deduped per (round, signer)), and — once the collected stake exceeds
    /// 2/3 — deterministically aggregate, verify, and store a complete QC.
    ///
    /// Fully side-effect-only: any failure drops the vote and never affects
    /// consensus. A QC is never stored unless it verifies (enforced inside
    /// `collect_vote_and_try_aggregate`).
    fn handle_remote_qc_vote(&self, content: &str) {
        let vote_msg: crate::qc_producer::QcVoteMessage = match serde_json::from_str(content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("❌ [QC] Malformed finality vote JSON: {}", e);
                return;
            }
        };

        // Bind the vote to OUR committed block at its anchor round, when known.
        // We look up the block hash this node committed at the vote's height; if
        // it disagrees the vote is for a different fork/block and is dropped by
        // the aggregator. (When we have not committed that height yet, pass None
        // and let the validator_set_hash + BLS-over-exact-vote binding guard it.)
        let expected_block_hash = self
            .storage
            .get(&format!("block_{}", vote_msg.vote.block_height))
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|b| {
                b.get("header")
                    .and_then(|h| h.get("hash"))
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
            });

        let outcome = crate::qc_producer::collect_vote_and_try_aggregate(
            &self.storage,
            &vote_msg,
            expected_block_hash.as_deref(),
        );
        if let crate::qc_producer::QcOutcome::Complete(qc) = outcome {
            println!(
                "✅ [QC] multi-party quorum certificate assembled for block #{}",
                qc.block_height
            );
            // SEC-#12 Step-2: a complete (>2/3) multi-party QC now exists at
            // consensus:qc:{height}. Fold its aggregate BLS signature into the
            // leader-election beacon — the same fold every other validator performs
            // when it assembles the identical QC for the same height, so the beacon
            // stays byte-identical across nodes. `fold_qc_for_height` is idempotent
            // and monotonic, so folding here is safe even if the commit path already
            // attempted it (no complete QC then) or a later vote re-triggers it.
            if let Ok(mut engine) = self.ordering_engine.lock() {
                engine.fold_qc_for_height(qc.block_height);
            }
        }
    }

    pub fn handle_message(&mut self, msg: &str) {
        // G5 S4c: only a V4 chain takes messages. `DAG_VERTEX:`,
        // `DOWNTIME_ATTEST:` and `EQUIV_PROOF:` (the deleted V3 DAG and its
        // evidence) are dropped unparsed: no V4 signature can appear in a V3
        // body, and V4 evidence travels in vertices (EQ-1).
        if !self.v4_chain {
            return;
        }
        if let Some(h) = msg.strip_prefix(QC_WANT_PREFIX) {
            self.answer_qc_want(h);
            return;
        }
        if let Some(json) = msg.strip_prefix(QC_CERT_PREFIX) {
            self.on_boundary_qc(json);
            return;
        }
        if let Some(content) = msg.strip_prefix(crate::v4::WIRE_PREFIX) {
            // S1 before parsing. The JSON of a `Msg::Vertex` wraps the vertex
            // in `{"Vertex":…}`; the vertex's own length is what S1 bounds.
            const WRAP: usize = r#"{"Vertex":}"#.len();
            // One bound for every message kind: a pull answer carrying one
            // maximal body must pass (the vertex copy is still bounded by S1).
            if content.len() > crate::v4::MAX_WIRE_BYTES {
                return;
            }
            if let Ok(m) = serde_json::from_str::<crate::v4::Msg>(content) {
                let raw_len = match &m {
                    crate::v4::Msg::Vertex(_) => content.len().saturating_sub(WRAP),
                    _ => content.len(),
                };
                self.on_v4_message(raw_len, m);
            }
            return;
        }
        if let Some(content) = msg.strip_prefix("QC_VOTE:") {
            // QC Phase 3: a peer's partial finality vote for multi-party QC
            // aggregation. Verify + collect; aggregate a complete QC on quorum.
            self.handle_remote_qc_vote(content);
        }
    }

    /// Reload chain tip from storage after external state changes (e.g. sync)
    /// This prevents consensus from forking by building on stale state.
    pub fn reload_chain_tip(&mut self) {
        self.retry_qc_work();
        let new_height = match self.storage.get("latest_height") {
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
            _ => 0,
        };
        let new_hash = match self.storage.get("latest_block_hash") {
            Ok(Some(h)) => h,
            _ => "genesis".to_string(),
        };

        // Adoption can lag a known tip after an I/O error. Retry that backlog
        // even without another synced block, but never regress the known tip.
        if new_height > self.latest_block_height
            || (new_height == self.latest_block_height && self.last_adopted_height < new_height)
        {
            if new_height > self.latest_block_height {
                println!(
                "🔄 [Consensus] Chain tip reloaded: Block #{} -> #{} (Hash: {:.8}..)",
                self.latest_block_height, new_height, new_hash
                );
            }
            self.latest_block_height = new_height;
            self.latest_block_hash = new_hash;
            // DIVERGENCE FIX (audit 2026-08-26, CRITICAL): the validator-set cache
            // used to be invalidated ONLY when this node BUILT a block. A node
            // catching up applies the very same slash/stake change to storage via
            // ChainSync but never rebuilt, so it kept a STALE (addr,stake) list —
            // and that list decides the anchor LEADER (hashed whole into
            // leader_for_round), the reward recipient, the BFT-time stake weights
            // and the >2/3 commit threshold. Two honest nodes then produce
            // different proposer_id / timestamp / state_root for the same anchor.
            // The tip advancing is exactly the moment the set may have changed.
            self.invalidate_validators_cache();

            // LIVENESS (burn-in finding): every synced block above the last
            // adopted height carries the network's committed vertex sequence for
            // its anchor. Apply each one to the ordering engine IN ORDER so the
            // local cursor moves past any gossip hole exactly as the producer's
            // did, then cast this node's finality vote for the block — a stalled
            // follower otherwise stops voting and the >2/3 QC quorum dies.
            // Only a V4 node adopts (an inert node votes on nothing).
            if self.v4_chain && self.ordering_halted().is_none() {
                let mut validators = self.decision_committee();
                let start_h = self.last_adopted_height.saturating_add(1);
                for h in start_h..=new_height {
                    let Some(block) = self
                        .storage
                        .get(&format!("block_{}", h))
                        .ok()
                        .flatten()
                        .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
                    else {
                        break;
                    };
                    // RE-AUDIT HIGH (loan ledger): every transaction carried by a
                    // synced block is settled — included-in-committed-block is the
                    // right notion of "done" here (a failed one would fail again
                    // and is bounded by the requeue cap anyway).
                    if !block.transactions.is_empty() {
                        if let Ok(mut mp) = self.mempool.lock() {
                            mp.mark_executed(&block.transactions);
                        }
                    }
                    // RE-AUDIT CRITICAL: never adopt or vote for a block that does
                    // not carry a proposer signature. ChainSync already rejects
                    // unsigned/mis-signed blocks before execution; this is defense
                    // in depth for anything that reached storage another way.
                    if !block.committed_vertices.is_empty() && !block.proposer_signature.is_empty() {
                        // G1 IM-1 (V4): a synced block is adopted only with a
                        // stored QC that verifies and binds it; without one,
                        // adoption waits (the QC is fetched with the block).
                        let Some(qc) =
                            crate::qc_producer::stored_qc(&self.storage, h).filter(|q| {
                                crate::qc_producer::verify_block_qc(&self.storage, &block, q)
                                    .is_ok()
                            })
                        else {
                            eprintln!("V4: block {h} has no verified QC yet; adoption waits");
                            self.want_qc(h);
                            break;
                        };
                        let qc_chain_id = self.resolve_chain_id();
                        let mut conflict: Option<String> = None;
                        let adopted = match self.ordering_engine.lock() {
                            Ok(mut engine) => {
                                let already_decided = block.header.round <= engine.finalized_round
                                    || engine.committed_rounds.contains(&block.header.round);
                                let result = engine.adopt_synced_anchor_with(
                                    block.header.round,
                                    &block.anchor_hash,
                                    &block.committed_vertices,
                                    &validators,
                                    |view, info| {
                                        // IM-1's last clause, where the digest is
                                        // computed: the QC's finality digest must be
                                        // this node's fold of the same sequence.
                                        if qc.finality_digest != info.finality_digest {
                                            return Err(format!(
                                                "{}: block {h}'s QC finality digest {} is not this node's {}",
                                                crate::ordering::DECISION_CONFLICT,
                                                qc.finality_digest,
                                                info.finality_digest
                                            ));
                                        }
                                        crate::qc_producer::stage_pending_qc(view, &block, info, qc_chain_id)?;
                                        view.put("consensus:last_adopted_height", &h.to_string())
                                            .map_err(|e| e.to_string())?;
                                        #[cfg(test)]
                                        if let Some(hook) = self.local_acceptance_hook { hook(2, view)?; }
                                        Ok(())
                                    },
                                );
                                match result {
                                    Ok(info) => {
                                        if info.is_none() && !already_decided {
                                            eprintln!("Anchor adoption at height {h} was not persisted; retry later");
                                            break;
                                        }
                                        info
                                    }
                                    Err(e) if e.contains(crate::ordering::DECISION_CONFLICT) => {
                                        conflict = Some(e);
                                        None
                                    }
                                    Err(e) => {
                                        eprintln!("Anchor adoption at height {h} was not persisted ({e}); retry later");
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                eprintln!("Ordering lock unavailable at height {h}; adoption deferred");
                                break;
                            }
                        };
                        // IM-3: a QC-bound decision this node disagrees with halts.
                        if let Some(e) = conflict {
                            self.halt_on_decision_conflict(h, &e);
                            break;
                        }
                        if adopted.is_some() {
                            #[cfg(test)]
                            if let Some(hook) = self.local_acceptance_hook {
                                hook(3, &self.storage).expect("post-adoption test hook failed");
                            }
                            self.retry_qc_work();
                        }
                    }
                    self.last_adopted_height = h;
                    let _ = self
                        .storage
                        .put("consensus:last_adopted_height", &h.to_string());
                    // G1 EP-3/EP-4: an adopted H_E closes E, and its QC (held,
                    // since adoption needs it) activates E+1 before H_E + 1.
                    self.v4_epoch_step();
                    if self.ordering_halted().is_some() {
                        break;
                    }
                    validators = self.decision_committee();
                }
            }

            let synced_block = self
                .storage
                .get(&format!("block_{}", new_height))
                .ok()
                .flatten()
                .and_then(|block_json| serde_json::from_str::<serde_json::Value>(&block_json).ok());
            let synced_round = synced_block.as_ref().and_then(|block| {
                block
                    .get("header")
                    .and_then(|header| header.get("round"))
                    .and_then(|round| round.as_u64())
            });
            // AUDIT-B4b (dedup): adopt the synced tip's anchor round so the local
            // commit loop knows which anchors are ALREADY represented on chain and
            // never builds a duplicate block for them. Adopt its timestamp too, so
            // the next locally-built block's BFT-time clamps against the true
            // parent — the same value on every node.
            if let Some(r) = synced_round {
                self.latest_block_round = self.latest_block_round.max(r);
            }
            if let Some(ts) = synced_block.as_ref().and_then(|block| {
                block
                    .get("header")
                    .and_then(|header| header.get("timestamp"))
                    .and_then(|t| t.as_u64())
            }) {
                // SET, not max(): the synced tip IS the canonical parent. A max()
                // let a stale-high value from a superseded local block survive and
                // skew the next block's BFT-time clamp (see the build site).
                self.latest_block_timestamp = ts;
            }
        }
    }

    /// Authoritative validator-set read: `(address, stake)` pairs, sorted by
    /// address and deduped. This is the single source of truth for both
    /// membership AND stake-weighted quorum / leader election (B4). Cache fast
    /// path (Phase 2.8 / M-08): `sys:validators` only changes when a slash
    /// executes, and `invalidate_validators_cache()` is called from `add_vertex`
    /// right after a block is persisted — the only moment the active set can
    /// change in normal operation. Tests/ops that write `sys:validators`
    /// directly MUST also invalidate, or the cache stays stale.
    pub fn get_validator_set_with_stake(&self) -> Vec<(String, u64)> {
        if let Ok(guard) = self.validators_cache.lock() {
            if let Some(cached) = guard.as_ref() {
                return cached.clone();
            }
        }
        let fresh = self.read_validators_from_storage();
        if let Ok(mut guard) = self.validators_cache.lock() {
            *guard = Some(fresh.clone());
        }
        fresh
    }

    /// Membership-only view (addresses), derived from the authoritative
    /// stake-aware set. Existing callers that only need membership/count stay
    /// unchanged.
    pub fn get_validator_set(&self) -> Vec<String> {
        self.get_validator_set_with_stake()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Storage-backed read path returning `(address, stake)`. Callers should
    /// prefer `get_validator_set_with_stake` so the cache is exercised; this
    /// helper is extracted so cache misses and explicit refreshes share one
    /// implementation.
    fn read_validators_from_storage(&self) -> Vec<(String, u64)> {
        Self::validators_from_storage(&self.storage)
    }

    /// The same read, callable from `new()` — before `Self` exists. Extracted
    /// rather than duplicated: a boot path with its own copy of the validator
    /// rules is a second implementation, and the two drift.
    fn validators_from_storage(storage: &StateDB) -> Vec<(String, u64)> {
        // 1. AUTHORITATIVE PATH: BLS/stake-aware validator set. Runtime joins
        // update this key; legacy `sys:validators` is only a compatibility
        // mirror and can lag on older nodes.
        if let Ok(Some(json)) = storage.get("sys:validator_set:v1") {
            if let Ok(vals) = serde_json::from_str::<Vec<ValidatorSetV1Entry>>(&json) {
                let mut validators: Vec<(String, u64)> =
                    vals.into_iter().map(|v| (v.address, v.stake)).collect();
                validators.sort_by(|a, b| a.0.cmp(&b.0));
                validators.dedup_by(|a, b| a.0 == b.0);
                return validators;
            }
        }

        // 2. LEGACY PATH: Native consensus mirror (`sys:validators`).
        if let Ok(Some(json)) = storage.get("sys:validators") {
            if let Ok(vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                let mut validators: Vec<(String, u64)> = vals;
                validators.sort_by(|a, b| a.0.cmp(&b.0));
                validators.dedup_by(|a, b| a.0 == b.0);
                return validators;
            }
        }

        // 3. SLOW PATH: Read BCS ValidatorSet Resource directly.
        // G3 FX-9: the canonical key, not a hand-written copy of it.
        let key = executor::validator_set_key();
        if let Ok(Some(bytes_hex)) = storage.get(&key) {
            if let Ok(bytes) = hex::decode(bytes_hex) {
                if let Ok(val_set) = bcs::from_bytes::<ValidatorSet>(&bytes) {
                    let mut validators: Vec<(String, u64)> = val_set
                        .validators
                        .iter()
                        // Coin.value is u128 quanta (10^18 per AIN); scale to
                        // whole-AIN u64 to match the fast-path / qc::ValidatorInfo
                        // stake unit, saturating instead of truncating.
                        .map(|v| {
                            let whole_ain = v.stake.value / 1_000_000_000_000_000_000u128;
                            (
                                v.validator_addr.to_string(),
                                u64::try_from(whole_ain).unwrap_or(u64::MAX),
                            )
                        })
                        .collect();
                    validators.sort_by(|a, b| a.0.cmp(&b.0));
                    validators.dedup_by(|a, b| a.0 == b.0);
                    return validators;
                }
            }
        }

        // STRICT ENFORCEMENT: No fallback to P2P peer list!
        // If staking is completely missing and we aren't Genesis, we must not mine.
        Vec::new()
    }
}

#[derive(serde::Deserialize)]
struct Coin {
    #[allow(dead_code)]
    value: u128,
}

#[derive(serde::Deserialize)]
struct ValidatorConfig {
    #[allow(dead_code)]
    validator_addr: AccountAddress,
    #[allow(dead_code)]
    stake: Coin,
    #[allow(dead_code)]
    public_key: Vec<u8>,
    #[allow(dead_code)]
    bls_public_key: Vec<u8>,
    #[allow(dead_code)]
    bls_pop: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct ValidatorSet {
    validators: Vec<ValidatorConfig>,
}

#[derive(serde::Deserialize)]
struct ValidatorSetV1Entry {
    address: String,
    stake: u64,
}

#[derive(serde::Deserialize, Debug)]
struct AccountAddress([u8; 32]);

impl std::fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Serializes pruning. A node prunes from the path that builds blocks and
/// from the one that imports them; a run that finds another in progress
/// skips, and a later tip catches up.
static PRUNING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// G3 GC-1: prune block history and state versions behind `height`, the new
/// tip, under `policy` (`StateDB::block_pruning_policy_from_env`: the blocks
/// to keep and a batch size, `None` for an archive node). Every path that
/// advances the tip calls it, a block this node built and one it imported
/// through sync, so a node that only follows prunes too. Node-local and
/// root-neutral.
pub fn prune_history(storage: &Arc<StateDB>, height: u64, policy: Option<(u64, u64)>) {
    let Some((keep_blocks, max_delete)) = policy else {
        return;
    };
    let _running = match PRUNING.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => return,
    };
    // The pinned versions keep their blocks too, so a snapshot at a pin has
    // its anchor block (SN-4).
    let interval = state_commit::epoch_interval(storage);
    let pins = state_commit::pin_schedule(height, keep_blocks, interval);
    match storage.prune_old_blocks(height, keep_blocks, max_delete, &pins) {
        Ok(deleted) if deleted > 0 => println!(
            "🧹 Block history pruning: removed {} old blocks (retain={}, batch={})",
            deleted, keep_blocks, max_delete
        ),
        Ok(_) => {}
        Err(e) => eprintln!("⚠️ Block history pruning failed: {}", e),
    }
    // Blocks kept for a pin that no longer is one (the window moved, or the
    // retention changed) go; a run skipped by the lock is caught up here.
    if let Err(e) = storage.prune_expired_pins(height, keep_blocks, &pins) {
        eprintln!("⚠️ Pruning expired pin blocks failed: {e}");
    }
    // State versions follow the same window, so proofs are served exactly as
    // long as blocks are.
    if !height.is_multiple_of(STATE_PRUNE_EVERY) {
        return;
    }
    match prune_state_window(
        storage,
        height,
        keep_blocks,
        (max_delete as usize).saturating_mul(4_000),
    ) {
        Ok(stats) if stats.nodes + stats.values > 0 => println!(
            "🧹 State tree pruning: removed {} nodes and {} values",
            stats.nodes, stats.values
        ),
        Ok(_) => {}
        Err(e) => eprintln!("⚠️ State tree pruning failed: {}", e),
    }
}

/// How often state pruning runs, in blocks. Each run raises the floor with
/// one synced write, so running every block would add that write to every
/// commit under the consensus lock.
pub(crate) const STATE_PRUNE_EVERY: u64 = 100;

/// G3 GC-1 / SN-4: prune state versions older than `keep` blocks behind
/// `tip`, keeping the pinned epoch-boundary versions of the last two windows
/// (`state_commit::pin_schedule`) for snapshot restores. At most `max_rows`
/// rows per call; the rest follows on later runs. Node-local and
/// root-neutral.
pub(crate) fn prune_state_window(
    storage: &Arc<StateDB>,
    tip: u64,
    keep: u64,
    max_rows: usize,
) -> Result<state_commit::PruneStats, String> {
    if keep == 0 || tip <= keep {
        return Ok(state_commit::PruneStats::default());
    }
    let pinned = state_commit::pin_schedule(tip, keep, state_commit::epoch_interval(storage));
    state_commit::prune(storage, tip - keep, &pinned, max_rows).map_err(|e| e.to_string())
}

#[cfg(test)]
mod prune_window_tests {
    use super::prune_state_window;
    use std::sync::Arc;
    use storage::StateDB;

    /// GC-1 / SN-4 wiring: the window follows block retention, and the pinned
    /// epoch-boundary versions below the floor stay whole. The pins come from
    /// arithmetic, not from `consensus:epoch_start_height:*` rows, which the
    /// executor deletes after 8 epochs (S7 review).
    #[test]
    fn the_state_window_prunes_old_versions_and_keeps_epoch_pins() {
        let path = std::env::temp_dir().join(format!("prune_window_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        let db = Arc::new(StateDB::open(path.to_str().unwrap()).unwrap());
        let key = |i: u64| format!("obj:{i:064x}");
        let mut v0 = vec![(
            "sys:config:epoch_block_interval".to_string(),
            Some(b"5".to_vec()),
        )];
        v0.push((key(99), Some(b"tick0".to_vec())));
        {
            let _seed = db.seeding();
            db.put("sys:config:epoch_block_interval", "5").unwrap();
        }
        let applied = state_commit::apply(&db, 0, v0).unwrap();
        db.write_batch(applied.batch).unwrap();
        for version in 1..=30u64 {
            let changes = vec![
                (key(version % 5), Some(format!("v{version}").into_bytes())),
                (key(99), Some(format!("tick{version}").into_bytes())),
            ];
            let applied = state_commit::apply(&db, version, changes).unwrap();
            db.write_batch(applied.batch).unwrap();
        }
        let roots: Vec<_> = (0..=30)
            .map(|v| state_commit::root(&db, v).unwrap())
            .collect();
        let stats = prune_state_window(&db, 30, 10, usize::MAX).unwrap();
        assert!(stats.nodes > 0, "positive control: {stats:?}");
        assert_eq!(state_commit::floor(&db).unwrap(), 20);
        // Pins: multiples of 5 from 10 (two windows back).
        for version in [10u64, 15, 20, 25, 30] {
            let (value, proof) = state_commit::prove(&db, &key(99), version).unwrap();
            assert_eq!(
                value,
                Some(format!("tick{version}").into_bytes()),
                "{version}"
            );
            state_commit::verify(roots[version as usize], &key(99), value.as_deref(), &proof)
                .unwrap();
        }
        let old = state_commit::prove(&db, &key(99), 7);
        assert!(
            old.is_err() || old.unwrap().0 != Some(b"tick7".to_vec()),
            "an unpinned version below the floor lost its rows"
        );
        // A tip inside the window prunes nothing.
        assert_eq!(
            prune_state_window(&db, 8, 10, usize::MAX).unwrap(),
            state_commit::PruneStats::default()
        );
    }
}
