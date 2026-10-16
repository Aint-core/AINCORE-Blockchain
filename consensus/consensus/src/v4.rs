//! G1 S5: the V4 pipeline of `docs/G1_CONSENSUS_CONTRACT.md` as one engine
//! driven by messages and ticks: ingress and staging (IN, ST), attestation
//! (AT), certificates (CE), the orderable index (OR), production (PR), the
//! decision over O_E (DE) and boot (RC). Transport is a seam
//! (`ConsensusNet`); the node wires the engine in at S5e, behind the V4 flag.
//!
//! Scope at S5: one epoch with a frozen committee C_0 (DE-7); epochs are S9.
//! Bodies, attestations and certificates are pushed; pull (fetch, CERT_REQ,
//! ATTEST_REQ) is S6. There is no GC yet (g = 0, S7), so OR-1 has no
//! settled-by-floor arm: it returns with S7's sequence builder (review C-1).

use crate::ingress_v4::{self, Context, EpochRecord, Verdict};
use crate::ordering::{CommitInfo, OrderingEngine};
use crate::qc::{self, ValidatorInfo};
use crate::staging::{self, PendingBuffer, Role, StageOutcome};
use crate::vcert::{
    self, AttestBody, AttestOutcome, CertCollector, CollectOutcome, VertexAttestation,
    VertexCertificate,
};
use blockchain::{ParentRef, Vertex};
use crypto::bls::BLSEngine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use storage::{StateDB, StorageError};

/// The single epoch of S5, its first round and its sentinel (EP-1).
pub const EPOCH: u64 = 0;
pub const FIRST_ROUND: u64 = 1;
pub const SENTINEL: &str = "genesis";
/// PR-3: how many ticks a round waits for the previous anchor's leader.
pub const T_LEADER_TICKS: u64 = 2;
/// The genesis-pinned vertex format (`VERTEX_FORMAT`): "4" selects V4.
pub const VERTEX_FORMAT_KEY: &str = "genesis:vertex_format";
/// The node-side wire prefix of a V4 message.
pub const WIRE_PREFIX: &str = "DAG_V4:";
/// The largest `DAG_V4:` message content a node parses: one maximal vertex
/// body plus an envelope. Pull answers are packed to fit it (`pull.rs`).
pub const MAX_WIRE_BYTES: usize = crate::dag::MAX_VERTEX_BYTES + 8 * 1024;

/// The `consensus:guard_origin` row of RC-3: the chain, the genesis and this
/// node's two keys. A database whose row differs (or is missing) did not sign
/// under these keys from genesis on.
pub fn guard_origin(chain_id: &str, genesis_identity: &str, node_key: &[u8; 32]) -> String {
    let ed25519 = hex::encode(
        crypto::SigningKey::from_bytes(node_key)
            .verifying_key()
            .to_bytes(),
    );
    let bls =
        hex::encode(BLSEngine::consensus().pubkey_raw(&qc::derive_validator_bls_seed(node_key)));
    serde_json::json!({
        "cg": vcert::chain_genesis_tag(chain_id, genesis_identity),
        "ed25519": ed25519,
        "bls": bls,
    })
    .to_string()
}

/// Whether this chain's genesis pins the V4 vertex format. One DAG format per
/// chain: a node never runs both.
///
/// Fail closed (G5 review): a read error must not route a V4 chain down a
/// path meant for another format.
pub fn is_v4_chain(storage: &StateDB) -> bool {
    storage
        .get(VERTEX_FORMAT_KEY)
        .expect("CRITICAL: the chain's vertex format could not be read")
        .as_deref()
        == Some("4")
}

/// The V4 wire messages the engine exchanges (the push half of the contract's
/// message table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Msg {
    /// `DAG_VERTEX`: author to all.
    Vertex(Vertex),
    /// `DAG_ATTEST`: attester to author.
    Attest(VertexAttestation),
    /// `DAG_CERT`: author to all.
    Cert(VertexCertificate),
    /// RE-3: a signed pull request for one target, answered to its sender.
    /// Only `to` answers, whatever the transport delivers it to.
    Req(pull::SignedRequest),
    /// RE-5: the answer, addressed to the requester.
    Resp { to: String, resp: pull::Response },
}

/// The transport seam. Production sends over gossip and TCP; tests use a
/// simulated network.
pub trait ConsensusNet {
    fn broadcast(&self, msg: Msg);
    fn send(&self, to: &str, msg: Msg);
}

pub struct Config {
    pub chain_id: String,
    pub genesis_identity: String,
    /// C_0, frozen for the epoch.
    pub committee: Vec<ValidatorInfo>,
    pub node_key: [u8; 32],
    pub address: String,
    /// ST-3's plain-body budget per author (`staging::B_AUTH`).
    pub b_auth: u64,
    /// Standalone engines (tests) close an epoch every this many blocks
    /// (decided anchors); 0 for none. A node closes epochs on its blocks.
    pub epoch_interval: u64,
}

/// What the engine shares with its host node (the contract's derived state):
/// `dag` holds the staged bodies, `round_index` holds O_E (OR-1 is its only
/// writer), and the ordering engine the host decides with.
#[derive(Clone)]
pub struct Shared {
    pub dag: Arc<Mutex<HashMap<String, Vertex>>>,
    pub round_index: Arc<Mutex<HashMap<u64, Vec<String>>>>,
    pub ordering: Arc<Mutex<OrderingEngine>>,
}

/// A proposal PR-2 and PR-3 allow at this tick. Above the cursor's lead the
/// vertex carries no payload (PR-1, Correction C1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub round: u64,
    pub carry_payload: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// B229: a costly check that failed is charged once (B51), whether or not
/// it charged itself (a failed pairing does; a cheaper refusal of a peer's
/// certificate did not). No honest node sends a certificate that fails.
fn charged_once(check: impl FnOnce() -> bool) -> bool {
    let (passed, failed) = crate::work::failed_in(check);
    if !passed && failed == 0 {
        crate::work::note_failed_check();
    }
    passed
}

#[cfg(test)]
thread_local! {
    /// B442 witness support: the PENDING vertices woken on this thread.
    pub(crate) static WAKES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// B95/B117: the bodies of one (epoch, round, author) whose payload was
/// checked.
#[derive(Debug, Default)]
struct PayloadSlot {
    passed: Vec<String>,
    refused: Vec<String>,
    /// B155: bodies that passed every check and could not be staged (a full
    /// slot's third, or past the author's plain-body budget), at most
    /// `UNSTAGED_PER_SLOT`.
    unstaged: Vec<String>,
    /// B224: the digests Layer S authenticated, at most
    /// `AUTHENTICATED_PER_SLOT`: an honest author signs one body a slot, so
    /// a second is twin evidence, and a third is not authenticated unless it
    /// is certified here.
    authenticated: Vec<String>,
    /// B202/B224: those the pending buffer evicted: a copy runs Layer S
    /// again only once it could be kept or staged (`evicted_again`).
    evicted: Vec<String>,
}

/// B155: unstageable bodies remembered per slot (a choice: an author has two
/// staged bodies a slot; more twins than this are evidence enough).
const UNSTAGED_PER_SLOT: usize = 4;

/// B224: authenticated digests remembered per slot (`PayloadSlot`).
const AUTHENTICATED_PER_SLOT: usize = 2;

/// B224: bodies dropped after Layer S remembered in one tick (a choice;
/// past it a copy is evaluated, as every copy was before B190).
const DROPPED_CAP: usize = 1_024;

/// B204: early digests remembered (a choice, as `DROPPED_CAP`).
const EARLY_DIGESTS_CAP: usize = 1_024;

impl PayloadSlot {
    fn checks(&self) -> usize {
        self.passed.len() + self.refused.len()
    }
}

/// B118: payload slots kept at most. The active epoch's window (GC_DEPTH
/// below the cursor to LEAD above it) and the next epoch's lead hold about
/// 450 rounds x n slots, so a choice: 2^16 (~20 MB) covers committees up to
/// ~145 members; past the cap the map is pruned, and a forgotten slot only
/// costs its checks again.
const PAYLOAD_SLOTS_CAP: usize = 1 << 16;

/// B255: the blocks this node may hold above its lowest block without a QC
/// before it proposes nothing more (a choice), so a lagging member has few
/// blocks to rebuild and vote on from what is kept for it
/// (`retention_floor`). GC deleted what a member cut off past the window
/// needed, and with f members withholding their votes every QC needed that
/// member's: no QC formed again, and the next epoch never activated.
pub const MAX_UNFINALIZED_BLOCKS: u64 = 50;

/// B262: the rounds this node may run above the floor kept for its lowest
/// block without a QC (while that floor is below g) before it proposes
/// nothing more. Bounded in blocks alone, it kept every round for as long
/// as f members let one anchor commit every few hundred rounds (rounds per
/// block are unbounded, contract correction C1): their payloads, attested
/// and so outside the plain-body budget, grew memory without bound.
///
/// B283: the GC window and the lead, so the newest vertex a waiting member
/// sends again stays within the lead of a member coming back. That floor is
/// the g before the block's anchor, the anchor before it less `GC_DEPTH`;
/// a member that adopted the blocks before has its cursor one past that
/// anchor, so its lead reaches floor + `GC_DEPTH` + 1 + `LEAD`. With
/// `RETAIN_SLACK` added the newest vertex, payload and all, was past that
/// lead and dropped before Layer S: the member never learned the gap, never
/// rebuilt the block, and with f members withholding votes no QC formed.
pub const MAX_KEPT_ROUNDS: u64 = crate::ordering::GC_DEPTH + ingress_v4::LEAD;

/// B262: how often a member waiting on finality sends its newest vertex
/// again (ticks): nothing new is pushed while proposals wait, so a member
/// coming back learned how far the DAG got one round at a time.
const FINALITY_REBROADCAST_TICKS: u64 = 4;

/// The V4 engine of one node.
pub struct Engine {
    cfg: Config,
    storage: Arc<StateDB>,
    /// C_0 as (address, stake), canonical order: the decision's committee.
    stakes: Vec<(String, u64)>,
    committee_hash: String,
    ed25519_pk: String,
    /// This node's BLS public key (hex), derived once (B205).
    bls_pk: String,
    /// AT-1: a staked member whose derived BLS key is the registered one.
    can_sign: bool,
    /// RC-3: guard continuity held at boot.
    guards_continuous: bool,
    /// The staged bodies (canonical form), shared with the host as `dag`.
    dag: Arc<Mutex<HashMap<String, Vertex>>>,
    /// The certificate index: (round, author) → certificate.
    certs: HashMap<(u64, String), VertexCertificate>,
    /// Signed stake of the certificates held per round (PR-1).
    cert_stake: BTreeMap<u64, u128>,
    /// PR-3: the tick at which a quorum of certificates at a round was first held.
    quorum_since: HashMap<u64, u64>,
    /// B5: the tick at which this node proposed an anchor it owed (it leads
    /// it, and the round reached quorum before its tick). Its own wait for
    /// that anchor's certificate starts there, not at the older quorum.
    owed_at: HashMap<u64, u64>,
    /// O_E: round → orderable digests (one per author, OR-2), shared with the
    /// host as `round_index`, and its membership.
    round_index: Arc<Mutex<HashMap<u64, Vec<String>>>>,
    orderable: HashSet<String>,
    /// OR-1: a parent digest → the certified children waiting on it.
    waiting: HashMap<String, HashSet<String>>,
    pending: PendingBuffer,
    /// B224: the bodies Layer S authenticated this tick and dropped (past
    /// the lead on parents not certified here, a full slot's third, an
    /// author's spent next-epoch checks): their copies this tick are dropped
    /// before Layer S (each ran the hash and the signature again,
    /// unremembered). A later tick's copy is evaluated again: the cursor and
    /// the certificates move. Cleared every tick; at most `DROPPED_CAP`.
    /// (The buffer's evictions are remembered in their slots, B202.)
    dropped: HashSet<String>,
    /// B204: bodies Layer S authenticated and Layer E found early, by
    /// digest, with their timestamps: their copies are dropped before Layer
    /// S until they are due (each ran the hash and the signature again).
    /// At most `EARLY_DIGESTS_CAP`; the due ones leave at the next tick.
    early_digests: HashMap<String, u64>,
    /// B95/B117: per (epoch, round, author), the bodies whose payload was
    /// checked, passed or refused (at most two checks a slot, a third only
    /// for a certified body: a third plain body is an equivocation and is
    /// not checked).
    payload_slots: HashMap<(u64, u64, String), PayloadSlot>,
    /// B137: per author, the payload checks its next-epoch vertices took
    /// since the last activation. At most `PENDING_MAX_PER_AUTHOR`, what the
    /// buffer keeps of one author: an author sending lower rounds first had
    /// every one checked and kept (up to two bodies a round over the lead).
    next_checks: HashMap<String, usize>,
    /// G5 BT-1: per member, the timestamp of its latest vertex refused as
    /// ahead of this node's clock (`Verdict::Early`); cleared when one of
    /// its vertices stages.
    early: HashMap<String, u64>,
    /// This node's proposals, as broadcast (parent certificates embedded).
    own: BTreeMap<u64, Vertex>,
    /// CE-1 for this node's proposals not yet certified.
    collectors: BTreeMap<u64, CertCollector>,
    ordering: Arc<Mutex<OrderingEngine>>,
    /// Standalone (tests): decide on every O_E insertion. Hosted: the host's
    /// commit loop decides, told by `take_progress`.
    self_decide: bool,
    /// O_E grew since the last `take_progress`.
    progressed: bool,
    decided: Vec<CommitInfo>,
    halted: Option<String>,
    tick: u64,
    now_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// RE-1 (a, b): certified bodies this node lacks, and who to ask.
    body_wants: BTreeMap<String, pull::Want>,
    /// RE-1 (b, c, d): certificates this node lacks, by slot.
    cert_wants: BTreeMap<(u64, String), pull::Want>,
    /// B51: certificates an answer may still bring per wanted slot, one per
    /// request this node sent for it (answers are unauthenticated); B248:
    /// per member asked; B250: the last `pull::MAX_ASKED_PER_SLOT` asked.
    cert_answers: HashMap<(u64, String), Vec<(String, u8)>>,
    /// The tick at which a certificate last arrived (RE-1 d).
    last_cert_tick: u64,
    /// This node's last request number and the durable reservation above it.
    pull_seq: u64,
    pull_seq_reserved: u64,
    /// RE-6 on the serving side.
    budget: pull::Budget,
    /// The GC floor this engine last acted on (OR-3, GC-3).
    last_floor: u64,
    /// B255: the anchor round of the lowest block this node holds without a
    /// QC, less GC_DEPTH (`u64::MAX`: none), refreshed every tick.
    finality_floor: u64,
    /// B318: the cursor that block's decision started from (`u64::MAX`: no
    /// block, or one staged before it was recorded), read with the floor.
    finality_cursor: u64,
    /// B273: the g at which `finality_floor` was last read.
    floor_read_at: u64,
    /// The active epoch E (EP-1): its number, first round and sentinel, and
    /// r* once it has closed (EP-3). `cfg.committee` is C_E.
    epoch: u64,
    first_round: u64,
    sentinel: String,
    closing_round: Option<u64>,
    /// E+1's record once E has closed and until activation (EP-2, EP-4).
    next: Option<epoch::EpochStart>,
    /// B230: `validator_set_hash` of `next`'s committee while it is held.
    next_committee_hash: String,
    /// E−1 and its closing round, for classifying its late messages (EP-5).
    previous: Option<epoch::EpochStart>,
    previous_closing: u64,
    /// Epoch 0's record (the genesis committee).
    genesis: epoch::EpochStart,
    /// Verified certificates of E+1 that arrived before activation.
    early_certs: Vec<VertexCertificate>,
    /// Payloads of this node's proposals that an epoch boundary orphaned.
    orphaned: Vec<String>,
    /// Standalone only: blocks decided, scheduled committees, and an
    /// activation waiting for the end of the call.
    blocks: u64,
    scheduled: BTreeMap<u64, Vec<ValidatorInfo>>,
    activation_due: bool,
    /// The highest round a gap fetch already covers (`want_gap`).
    gap_high: u64,
    /// The tail of the epoch just closed, served to nodes still finishing it.
    closed: Option<epoch::ClosedEpoch>,
    /// Requests sent this tick (client pacing), by tick.
    sent: (u64, usize),
    /// The committee's peers, shared by every certificate want.
    peer_list: Option<(String, Arc<[String]>)>,
    /// Slots whose attestation was re-sent this tick (one re-send per slot
    /// per tick, however often a copy is replayed).
    resent: (u64, HashSet<(u64, String)>),
    /// The early E+1 certificates held, by (round, author, digest).
    early_keys: HashSet<(u64, String, String)>,
}

fn storage_err(e: impl ToString) -> StorageError {
    StorageError::DatabaseOperation(e.to_string())
}

/// The canonical body: transport fields stripped (as staged and served).
fn canonical(v: &Vertex) -> Vertex {
    let mut c = v.clone();
    for r in &mut c.parent_refs {
        r.cert = None;
        r.proof = None;
    }
    c
}

impl Engine {
    /// RC-1 boot of the V4 engine over `storage`. `genesis_init` is true only
    /// when this database is being initialised at genesis: that is the one
    /// moment the guard origin may be written (RC-3). Otherwise a missing or
    /// mismatched origin under a committee key means a fresh, wiped or resynced
    /// database, and the node abstains from signing for the epoch.
    ///
    /// Standalone: the engine decides by itself on every O_E insertion, and a
    /// decision is persisted before anything is built from it. That is not
    /// atomic with a block (RC-2), so this form exists for tests only; a node
    /// uses `open_shared`, whose decisions its block-acceptance transaction
    /// stages (review of S5 part 1, HIGH-2).
    #[cfg(test)]
    pub fn open(
        storage: Arc<StateDB>,
        cfg: Config,
        genesis_init: bool,
        now_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, String> {
        let shared = Shared {
            dag: Arc::new(Mutex::new(HashMap::new())),
            round_index: Arc::new(Mutex::new(HashMap::new())),
            ordering: Arc::new(Mutex::new(OrderingEngine::new_with_storage(Arc::clone(
                &storage,
            )))),
        };
        Self::open_with(storage, cfg, shared, true, genesis_init, now_secs)
    }

    /// The engine inside a node: it fills the node's `dag` and `round_index`
    /// and leaves deciding to the node's commit loop (`take_progress`).
    pub fn open_shared(
        storage: Arc<StateDB>,
        cfg: Config,
        shared: Shared,
        genesis_init: bool,
        now_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, String> {
        Self::open_with(storage, cfg, shared, false, genesis_init, now_secs)
    }

    fn open_with(
        storage: Arc<StateDB>,
        cfg: Config,
        shared: Shared,
        self_decide: bool,
        genesis_init: bool,
        now_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, String> {
        let committee = qc::canonical_order(&cfg.committee);
        let stakes: Vec<(String, u64)> = committee
            .iter()
            .map(|m| (m.address.clone(), m.stake))
            .collect();
        let committee_hash = qc::validator_set_hash(&committee);
        let ed25519_pk = hex::encode(
            crypto::SigningKey::from_bytes(&cfg.node_key)
                .verifying_key()
                .to_bytes(),
        );
        let bls_pk = hex::encode(
            BLSEngine::consensus().pubkey_raw(&qc::derive_validator_bls_seed(&cfg.node_key)),
        );
        let me = committee
            .iter()
            .find(|m| m.address == cfg.address && m.stake > 0);
        let can_sign = me.is_some_and(|m| m.bls_public_key == bls_pk);
        let origin = guard_origin(&cfg.chain_id, &cfg.genesis_identity, &cfg.node_key);
        let held = storage
            .get("consensus:guard_origin")
            .map_err(|e| e.to_string())?;
        let guards_continuous = match held {
            Some(h) => h == origin,
            // Only a database that has never signed or placed anything may
            // take a first origin; the flag left set on a wiped or restored
            // store must not re-arm signing (review LOW-3).
            None if genesis_init && Self::never_signed(&storage) => {
                storage
                    .put("consensus:guard_origin", &origin)
                    .map_err(|e| e.to_string())?;
                true
            }
            None => false,
        };
        // B405: a node without continuous guards abstains until a block
        // carrying one of its proof-of-boot transactions is seen in this run
        // (`epoch::note_boot_proof`); a boot took a resume time from its clock
        // alone, and a clock an hour behind (a Pi on fake-hwclock before NTP)
        // re-armed a wiped validator inside an epoch it had signed in. A node
        // whose guards are continuous drops a row left from an abstention.
        if guards_continuous {
            storage
                .delete(epoch::GUARD_RESUME_KEY)
                .map_err(|e| e.to_string())?;
        } else {
            epoch::begin_abstaining(&storage)?;
        }
        let genesis = epoch::EpochStart {
            epoch: EPOCH,
            first_round: FIRST_ROUND,
            sentinel: SENTINEL.to_string(),
            committee: committee.clone(),
            prev_closing_round: 0,
            prev_anchor: String::new(),
            prev_block_hash: String::new(),
            prev_height: 0,
            prev_timestamp: 0,
        };
        let cfg = Config { committee, ..cfg };
        let seq = Self::load_seq(&storage, (now_secs)());
        let mut engine = Self {
            ordering: shared.ordering,
            self_decide,
            progressed: false,
            storage,
            stakes,
            committee_hash,
            ed25519_pk,
            bls_pk,
            can_sign,
            guards_continuous,
            dag: shared.dag,
            certs: HashMap::new(),
            cert_stake: BTreeMap::new(),
            quorum_since: HashMap::new(),
            owed_at: HashMap::new(),
            round_index: shared.round_index,
            orderable: HashSet::new(),
            waiting: HashMap::new(),
            pending: PendingBuffer::default(),
            dropped: HashSet::new(),
            early_digests: HashMap::new(),
            payload_slots: HashMap::new(),
            next_checks: HashMap::new(),
            early: HashMap::new(),
            own: BTreeMap::new(),
            collectors: BTreeMap::new(),
            decided: Vec::new(),
            halted: None,
            tick: 0,
            now_secs,
            body_wants: BTreeMap::new(),
            cert_wants: BTreeMap::new(),
            cert_answers: HashMap::new(),
            last_cert_tick: 0,
            pull_seq: seq,
            pull_seq_reserved: seq,
            budget: pull::Budget::default(),
            last_floor: 0,
            finality_floor: u64::MAX,
            finality_cursor: u64::MAX,
            floor_read_at: u64::MAX,
            gap_high: 0,
            closed: None,
            sent: (0, 0),
            peer_list: None,
            resent: (0, HashSet::new()),
            early_keys: HashSet::new(),
            epoch: EPOCH,
            first_round: FIRST_ROUND,
            sentinel: SENTINEL.to_string(),
            closing_round: None,
            next: None,
            next_committee_hash: String::new(),
            previous: None,
            previous_closing: 0,
            genesis,
            early_certs: Vec::new(),
            orphaned: Vec::new(),
            blocks: 0,
            scheduled: BTreeMap::new(),
            activation_due: false,
            cfg,
        };
        engine.boot()?;
        Ok(engine)
    }

    fn never_signed(storage: &StateDB) -> bool {
        let fresh_tip = storage
            .get("latest_height")
            .ok()
            .flatten()
            .is_none_or(|h| h == "0");
        let no_rows = [
            "consensus:vproposed:",
            "consensus:vproposed_high:",
            "consensus:vattest:",
            "consensus:vslot:",
        ]
        .iter()
        .all(|p| {
            storage
                .db
                .prefix_iterator(p.as_bytes())
                .next()
                .is_none_or(|row| row.is_ok_and(|(k, _)| !k.starts_with(p.as_bytes())))
        });
        fresh_tip && no_rows
    }

    /// RC-1 steps 2 to 6.
    fn boot(&mut self) -> Result<(), String> {
        self.load_epoch_state()?;
        // B255: what GC kept for a block without a QC is loaded back.
        self.refresh_finality_floor();
        self.load_closed()?;
        let floor = self.retention_floor();
        let loaded = {
            let record = self.record();
            staging::load(
                &self.storage,
                &record,
                &self.cfg.chain_id,
                &self.cfg.genesis_identity,
                floor,
            )?
        };
        {
            let mut dag = lock(&self.dag);
            for (_, v) in loaded.bodies {
                dag.insert(v.hash.clone(), v);
            }
        }
        // CE-3's halt survives a restart: a recorded certificate conflict is
        // never forgotten, and the node orders and signs nothing more.
        let alarms = format!("alarm:vcert_conflict:{:020}:", self.epoch);
        if let Some(row) = self.storage.db.prefix_iterator(alarms.as_bytes()).next() {
            let (key, _) = row.map_err(|e| e.to_string())?;
            if key.starts_with(alarms.as_bytes()) {
                self.halted = Some(format!(
                    "a certificate conflict was recorded ({})",
                    String::from_utf8_lossy(&key)
                ));
            }
        }
        let mut certs = loaded.certs;
        certs.sort_by_key(|c| c.body.round);
        for cert in certs {
            // A crash between the certificate row and the promotion leaves
            // the body in a plain role: promote it again (idempotent).
            let held = lock(&self.dag).get(&cert.body.digest).cloned();
            if let Some(v) = held {
                staging::stage(
                    &self.storage,
                    &v,
                    Role::Staged,
                    Some(&cert.body.digest),
                    self.cfg.b_auth,
                )?;
            }
            self.index_cert(cert);
        }
        // Step 4: O_E through OR-1, in increasing round.
        let mut digests: Vec<(u64, String)> = self
            .certs
            .values()
            .map(|c| (c.body.round, c.body.digest.clone()))
            .collect();
        digests.sort();
        for (_, d) in digests {
            self.try_orderable(d);
        }
        // Step 6: this node's own proposals, rebuilt with their parents'
        // certificates, so the first tick rebroadcasts exactly those bodies.
        let prefix = self.proposed_prefix();
        let mut proposed: Vec<(u64, String)> = Vec::new();
        for row in self.storage.db.prefix_iterator(prefix.as_bytes()) {
            let (key, value) = row.map_err(|e| e.to_string())?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            let round = std::str::from_utf8(&key[prefix.len()..])
                .ok()
                .and_then(|r| r.parse::<u64>().ok())
                .ok_or("an unreadable producer guard row")?;
            proposed.push((round, String::from_utf8_lossy(&value).into_owned()));
        }
        for (round, digest) in proposed {
            let held = lock(&self.dag).get(&digest).cloned();
            let Some(body) = held else {
                continue;
            };
            let mut full = body;
            for r in &mut full.parent_refs {
                r.cert = self
                    .certs
                    .get(&(r.round, r.author.clone()))
                    .filter(|c| c.body.digest == r.digest)
                    .map(|c| c.compact());
            }
            if !self.certs.contains_key(&(round, self.cfg.address.clone())) {
                let body = self.attest_body(round, &self.cfg.address, &digest);
                if let Ok(mut collector) = CertCollector::new(body.clone(), &self.cfg.committee) {
                    if let Some(own) = self.read_own_attestation(&body)? {
                        let _ = collector.add(&own);
                    }
                    self.collectors.insert(round, collector);
                }
            }
            self.own.insert(round, full);
        }
        self.progressed = !self.orderable.is_empty();
        if self.self_decide {
            self.decide();
        }
        Ok(())
    }

    fn record(&self) -> EpochRecord<'_> {
        EpochRecord {
            epoch: self.epoch,
            first_round: self.first_round,
            closing_round: self.closing_round,
            sentinel: &self.sentinel,
            committee: &self.cfg.committee,
        }
    }

    /// g: the ordering engine's GC floor (B131: it advances with the
    /// decided anchors, `ordering::gc_floor`).
    fn gc_floor(&self) -> u64 {
        lock(&self.ordering).gc_floor()
    }

    /// B255: the floor GC-3 deletes and forgets below (less RETAIN_SLACK):
    /// g, but never above `finality_floor`, so the rounds a member needs to
    /// rebuild a block that has no QC yet, and vote on it, are kept and
    /// served until its QC forms. g itself (the decision's) is unchanged.
    /// B273: `finality_floor` is read again whenever g has moved since it was
    /// read. A block's pending row is written as its anchor raises g, and
    /// the first message after that cut with the floor of the last tick:
    /// the rounds that block's decision walked were deleted everywhere.
    fn retention_floor(&mut self) -> u64 {
        let g = self.gc_floor();
        if g != self.floor_read_at {
            self.refresh_finality_floor();
        }
        g.min(self.finality_floor)
    }

    /// GC-3's cut: rounds at or below it are deleted and forgotten.
    fn retention_cut(&mut self) -> u64 {
        self.retention_floor().saturating_sub(staging::RETAIN_SLACK)
    }

    /// B255: `finality_floor` from this node's pending QC work. B262: the
    /// floor that block's decision walked down to (its anchor less GC_DEPTH
    /// was too high after skipped anchors: a member rebuilding it found the
    /// rounds below deleted everywhere).
    fn refresh_finality_floor(&mut self) {
        self.floor_read_at = self.gc_floor();
        // B419: unreadable pending work holds retention (floor and cursor
        // 0) and is read again later; as "none" it released everything.
        // B469: its key and its row both (a row that could not be read or
        // parse still read as none).
        let lowest = crate::qc_producer::try_lowest_pending_qc_height(&self.storage)
            .and_then(|low| match low {
                Some(h) => crate::qc_producer::pending_context(&self.storage, h),
                None => Ok(None),
            });
        let lowest = match lowest {
            Ok(lowest) => lowest,
            Err(e) => {
                eprintln!("⚠️ [B255] pending QC work is unreadable ({e}); retention held");
                self.finality_floor = 0;
                self.finality_cursor = 0;
                return;
            }
        };
        self.finality_floor = lowest.as_ref().map_or(u64::MAX, |ctx| {
            ctx.decision_floor
                .unwrap_or_else(|| ctx.anchor_round.saturating_sub(crate::ordering::GC_DEPTH))
        });
        self.finality_cursor = lowest
            .and_then(|ctx| ctx.decision_cursor)
            .unwrap_or(u64::MAX);
    }

    /// B255: whether this node holds `MAX_UNFINALIZED_BLOCKS` blocks above
    /// its lowest block without a QC, or (B262) runs `MAX_KEPT_ROUNDS`
    /// rounds above the floor kept for it while that floor is below g, or
    /// (B318) runs past `LEAD` rounds above the cursor that block's decision
    /// started from. A member coming back stands at that cursor and drops
    /// every copy with a payload past its lead. At an epoch's first rounds
    /// the cursor is the first round and the floor just below it, so the
    /// floor rule (which takes a cursor `GC_DEPTH` above the floor) let the
    /// frontier run 50 rounds past that lead: the member never learned the
    /// gap, and with f members withholding votes no QC formed again.
    fn finality_lags(&self) -> bool {
        let Some(low) = crate::qc_producer::lowest_pending_qc_height(&self.storage) else {
            return false;
        };
        // B456: a tip that cannot be read lags (this node proposes nothing
        // until it reads again). Read as 0, it never lagged, and the node
        // proposed on past the bound.
        let tip_lags = match self.storage.try_chain_height() {
            Ok(tip) => tip.saturating_sub(low) >= MAX_UNFINALIZED_BLOCKS,
            Err(_) => true,
        };
        tip_lags
            || self.current_round() > self.finality_cursor.saturating_add(ingress_v4::LEAD)
            || (self.finality_floor < self.gc_floor()
                && self.current_round().saturating_sub(self.finality_floor) > MAX_KEPT_ROUNDS)
    }

    fn attest_body(&self, round: u64, author: &str, digest: &str) -> AttestBody {
        AttestBody {
            chain_id: self.cfg.chain_id.clone(),
            genesis_identity: self.cfg.genesis_identity.clone(),
            epoch: self.epoch,
            round,
            author: author.to_string(),
            digest: digest.to_string(),
            committee_hash: self.committee_hash.clone(),
        }
    }

    fn proposed_prefix(&self) -> String {
        format!(
            "consensus:vproposed:v1:{}:{}:{}:",
            vcert::chain_genesis_tag(&self.cfg.chain_id, &self.cfg.genesis_identity),
            self.ed25519_pk,
            self.epoch
        )
    }

    fn proposed_key(&self, round: u64) -> String {
        format!("{}{round:020}", self.proposed_prefix())
    }

    /// B282: the highest round this node proposed in its epoch, kept for the
    /// whole epoch (GC-3 deletes the per-round guards at or below its cut).
    fn proposed_high_key(&self) -> String {
        format!(
            "consensus:vproposed_high:v1:{}:{}:{}",
            vcert::chain_genesis_tag(&self.cfg.chain_id, &self.cfg.genesis_identity),
            self.ed25519_pk,
            self.epoch
        )
    }

    /// B282: whether this node may sign a body for its slot at `round`: above
    /// g (a body at or below it is stale everywhere), above every round it
    /// proposed in this epoch, and not proposed. GC-3 deletes the per-round
    /// guards at or below its cut and forgets the certificates there, and
    /// `current_round` falls back to the epoch's first round while no quorum
    /// round is held: a member coming back past the GC window signed a
    /// second body for its first slot, a twin any member holding the first
    /// could carry as evidence (slashed in full, jailed). A read error
    /// refuses.
    fn may_propose(&self, round: u64) -> bool {
        let high = match self.storage.get(&self.proposed_high_key()) {
            Ok(None) => 0,
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(u64::MAX),
            Err(_) => u64::MAX,
        };
        round > self.gc_floor()
            && round > high
            && !self.own.contains_key(&round)
            && matches!(self.storage.get(&self.proposed_key(round)), Ok(None))
    }

    fn read_own_attestation(&self, body: &AttestBody) -> Result<Option<VertexAttestation>, String> {
        // B205: the key derived once, at construction.
        let row = self
            .storage
            .get(&vcert::attest_guard_key(body, &self.bls_pk))
            .map_err(|e| e.to_string())?;
        Ok(row
            .and_then(|r| serde_json::from_str::<VertexAttestation>(&r).ok())
            .filter(|a| a.body == *body))
    }

    /// Signing is allowed: AT-1's membership and key, and RC-3.
    fn may_sign(&self) -> bool {
        self.can_sign && self.guards_continuous && self.halted.is_none()
    }

    // ----------------------------------------------------------------- ingress

    pub fn on_message(&mut self, raw_len: usize, msg: Msg, net: &dyn ConsensusNet) {
        self.on_message_from(None, raw_len, msg, net);
    }

    /// `on_message` from `source`, the member the transport names (`None`
    /// in process). B248: a pull answer brings certificates only for what
    /// was asked of its source.
    pub fn on_message_from(
        &mut self,
        source: Option<&str>,
        raw_len: usize,
        msg: Msg,
        net: &dyn ConsensusNet,
    ) {
        self.dispatch(source, raw_len, msg, net);
        self.observe_floor(net);
        self.finish_call(net);
    }

    fn dispatch(&mut self, source: Option<&str>, raw_len: usize, msg: Msg, net: &dyn ConsensusNet) {
        match msg {
            Msg::Vertex(v) => self.on_vertex(raw_len, v, net),
            Msg::Attest(a) => self.on_attestation(a, net),
            Msg::Cert(c) => self.on_cert(c, net),
            Msg::Req(signed) => self.on_request(signed, net),
            Msg::Resp { to, resp } => {
                if to == self.cfg.address {
                    self.on_response(resp, source, net);
                }
            }
        }
    }

    /// B95/B117: whether `v`'s payload must be checked: not when this body
    /// was checked before (it passed, or it is refused again unchecked), and
    /// not once two bodies of its (epoch, round, author) were checked,
    /// whatever their outcome. A body this node holds a certificate for is
    /// checked whatever the slot holds: a certified twin evicts a plain one,
    /// and a slot has at most one certified body (Lemma U).
    fn payload_gate(
        slots: &HashMap<(u64, u64, String), PayloadSlot>,
        v: &Vertex,
        certified: bool,
    ) -> ingress_v4::PayloadGate {
        match slots.get(&(v.epoch, v.round, v.author.clone())) {
            Some(slot) if slot.passed.contains(&v.hash) => ingress_v4::PayloadGate::Verified,
            Some(slot) if slot.refused.contains(&v.hash) => ingress_v4::PayloadGate::Refused,
            Some(slot) if slot.checks() >= 2 && !certified => ingress_v4::PayloadGate::Full,
            _ => ingress_v4::PayloadGate::Check,
        }
    }

    /// B95/B117: remember the outcome of `v`'s payload check. The map holds
    /// at most `PAYLOAD_SLOTS_CAP` slots: past it, those at or below the
    /// floor of the active epoch (or of an older one) are forgotten, and if
    /// that is not enough, all (B118: E+1 slots are bounded by its lead, but
    /// a cap must not rest on that; a forgotten slot only costs its checks
    /// again).
    fn remember_payload(&mut self, v: &Vertex, outcome: ingress_v4::PayloadChecked) {
        let slot = self.payload_slot(v);
        // Two checks, and a third only of a certified body (the gate lets
        // no other third through).
        if slot.checks() < 3 && !slot.passed.contains(&v.hash) && !slot.refused.contains(&v.hash) {
            match outcome {
                ingress_v4::PayloadChecked::Passed => slot.passed.push(v.hash.clone()),
                ingress_v4::PayloadChecked::Refused => slot.refused.push(v.hash.clone()),
            }
        }
    }

    /// `v`'s slot in `payload_slots`, made if missing. The map holds at most
    /// `PAYLOAD_SLOTS_CAP` slots (see `remember_payload`).
    fn payload_slot(&mut self, v: &Vertex) -> &mut PayloadSlot {
        if self.payload_slots.len() >= PAYLOAD_SLOTS_CAP {
            let (epoch, floor) = (self.epoch, self.gc_floor());
            self.payload_slots
                .retain(|(e, r, _), _| *e > epoch || (*e == epoch && *r > floor));
            if self.payload_slots.len() >= PAYLOAD_SLOTS_CAP {
                self.payload_slots.clear();
            }
        }
        self.payload_slots
            .entry((v.epoch, v.round, v.author.clone()))
            .or_default()
    }

    /// `v` waits in the pending buffer, on the certificates of its parent
    /// refs `missing` (indices; none for a next-epoch vertex, judged again at
    /// activation). B202/B224: a body the buffer evicts (an author's past
    /// `PENDING_MAX_PER_AUTHOR`) is remembered in its slot, and its copies
    /// skip Layer S while they would be evicted again (`evicted_again`).
    /// B202 cleared the memory every tick, so an author's bodies past its
    /// share, re-sent every tick, ran the hash and the signature again each
    /// tick.
    fn keep_pending(&mut self, v: Vertex, missing: &[usize]) {
        if let Some(evicted) = self.pending.push_waiting(v, missing) {
            let slot = self.payload_slot(&evicted);
            if slot.evicted.len() < AUTHENTICATED_PER_SLOT && !slot.evicted.contains(&evicted.hash)
            {
                slot.evicted.push(evicted.hash);
            }
        }
    }

    /// B224: whether a copy of `v`, a body the buffer evicted, would be
    /// evicted again: it waits (a next-epoch body, or a parent it cites
    /// certified neither here nor in the copy), and its author's share of
    /// the buffer would evict it at once (full, and it its last). A
    /// certificate that arrives, or room the buffer makes, lets the next
    /// copy through (B202: a body whose certificate needs this node's
    /// attestation must be kept once it can be).
    fn evicted_again(&self, v: &Vertex) -> bool {
        self.pending.evicts(&v.author, v.round, &v.hash)
            && (v.epoch > self.epoch
                || v.parent_refs.iter().any(|r| {
                    r.cert.is_none()
                        && self
                            .certs
                            .get(&(r.round, r.author.clone()))
                            .is_none_or(|c| c.body.digest != r.digest)
                }))
    }

    /// B224: Layer S authenticated `v`'s digest. It is counted for its slot
    /// (at most `AUTHENTICATED_PER_SLOT`), and a second digest is
    /// proposer-twin evidence (G1 EQ-1) against the first, wherever this
    /// node holds it, staged or pending: twins were recorded only when both
    /// staged, so an author whose bodies waited on invented parents signed
    /// any number of them for one slot, each authenticated by every node,
    /// and was never slashed.
    fn note_authenticated(&mut self, v: &Vertex) {
        let slot = self.payload_slot(v);
        if slot.authenticated.contains(&v.hash) {
            return;
        }
        let first = slot.authenticated.first().cloned();
        if slot.authenticated.len() < AUTHENTICATED_PER_SLOT {
            slot.authenticated.push(v.hash.clone());
        }
        let Some(first) = first else {
            return;
        };
        let held = self
            .pending
            .get(&v.author, v.round, &first)
            .cloned()
            .or_else(|| {
                let raw = self
                    .storage
                    .get(&format!("vertex:{first}"))
                    .ok()
                    .flatten()?;
                serde_json::from_str::<Vertex>(&raw).ok()
            });
        if let Some(other) = held {
            evidence::record_twin(&self.storage, &other, v);
        }
    }

    /// B155: `v` passed every check and could not be staged.
    fn remember_unstaged(&mut self, v: &Vertex) {
        let slot = self.payload_slot(v);
        if slot.unstaged.len() < UNSTAGED_PER_SLOT && !slot.unstaged.contains(&v.hash) {
            slot.unstaged.push(v.hash.clone());
        }
    }

    /// IN-1, then ST and AT for a vertex that stages.
    pub fn on_vertex(&mut self, raw_len: usize, v: Vertex, net: &dyn ConsensusNet) {
        self.judge_vertex(raw_len, v, false, net);
    }

    /// B68, B442: `v`, kept PENDING, has every parent it waited on
    /// certified here now: judged once more, on behalf of no sender (B68:
    /// whoever sent the last certificate did not deliver `v`), and without
    /// Layer S, which passed it when it was kept (`v4_verdict_judged`). S1
    /// bounded it when it arrived: it is not serialized again for a length.
    fn wake(&mut self, v: Vertex, net: &dyn ConsensusNet) {
        #[cfg(test)]
        WAKES.with(|n| n.set(n.get() + 1));
        crate::work::uncounted(|| self.judge_vertex(0, v, true, net));
    }

    /// `on_vertex`; `woken`: `v` is a body this node kept PENDING (`wake`).
    fn judge_vertex(&mut self, raw_len: usize, v: Vertex, woken: bool, net: &dyn ConsensusNet) {
        // A copy of a body already staged: nothing to verify or stage again,
        // and nothing to harvest (every ref of a staged body had a verified
        // certificate when it staged; a relay-padded copy is not verified, so
        // its refs are never looked at). Its author may be retrying for this
        // node's attestation (AT-2 reuses the guard).
        if self.is_staged(&v.hash) {
            self.resend_attestation(&v, net);
            return;
        }
        // B148: nor one held pending, or whose payload was refused, before
        // Layer S (each copy re-ran the hash, two serializations and the
        // signature check, uncounted). Both sets hold only authenticated
        // digests (Layer S passed for each), so a copy that claims one is
        // that body or a lie; a refused one is still charged (B136). A
        // later copy of a pending body may carry certificates the first did
        // not: they come by pull (RE-1) like any other.
        if self.pending.contains(&v.hash) {
            return;
        }
        // B224: nor a copy of a body dropped after Layer S this tick.
        if self.dropped.contains(&v.hash) {
            return;
        }
        // B229: nor a next-epoch body whose author's checks are spent until
        // activation, unless its payload was checked: Layer S, then the
        // payload gate, dropped it as spent, and each copy ran Layer S again
        // every tick until E+1 activated.
        if v.epoch > self.epoch
            && self.next_checks.get(&v.author).copied().unwrap_or(0)
                >= staging::PENDING_MAX_PER_AUTHOR
            && Self::payload_gate(&self.payload_slots, &v, false) == ingress_v4::PayloadGate::Check
        {
            return;
        }
        // B204: nor one that was early, while it still is (not charged: its
        // author's clock may run ahead).
        if let Some(&at) = self.early_digests.get(&v.hash) {
            let due = (self.now_secs)().saturating_add(ingress_v4::MAX_FUTURE_DRIFT_SECS);
            if at > due {
                return;
            }
            self.early_digests.remove(&v.hash);
        }
        if self
            .payload_slots
            .get(&(v.epoch, v.round, v.author.clone()))
            .is_some_and(|slot| slot.refused.contains(&v.hash))
        {
            crate::work::note_failed_check();
            return;
        }
        // B155: nor a copy of a body that passed every check and could not
        // be staged, unless it is certified here now (a certified body
        // takes its slot): each copy ran Layer S again, read the slot's
        // other bodies and checked this node's guard (a pairing), uncounted.
        // Not charged: its sender may be its honest author retrying.
        let certified_here = self
            .certs
            .get(&(v.round, v.author.clone()))
            .is_some_and(|c| c.body.digest == v.hash);
        if let Some(slot) = self
            .payload_slots
            .get(&(v.epoch, v.round, v.author.clone()))
        {
            if !certified_here && slot.unstaged.contains(&v.hash) {
                return;
            }
            // B224: nor a third digest for the slot, unless it is certified
            // here: its author signed two others (twin evidence already),
            // and each cost every node the hash and the signature,
            // uncharged. Not charged: a node that staged it may serve it.
            if !certified_here
                && slot.authenticated.len() >= AUTHENTICATED_PER_SLOT
                && !slot.authenticated.contains(&v.hash)
            {
                return;
            }
            // B224: nor a copy of an evicted body while it would be
            // evicted again.
            if slot.evicted.contains(&v.hash) && self.evicted_again(&v) {
                return;
            }
        }
        let verdict = {
            let ctx = Context {
                chain_id: &self.cfg.chain_id,
                genesis_identity: &self.cfg.genesis_identity,
                active: self.record(),
                next: self.next_record(),
                // Read only for a next-epoch vertex while E+1's record is
                // not held (it scans the round index).
                gap_wanted_to: if Some(v.epoch) == self.epoch.checked_add(1) && self.next.is_none()
                {
                    self.gap_wanted_to()
                } else {
                    u64::MAX
                },
                now_secs: (self.now_secs)(),
                gc_floor: self.gc_floor(),
                cursor: lock(&self.ordering).next_anchor_round,
            };
            let certs = &self.certs;
            let slots = &self.payload_slots;
            let next_checks = &self.next_checks;
            let epoch = self.epoch;
            // E4's cache: a ref whose certificate is already in the index was
            // verified when it got there (CE-3 ingests only verified ones).
            ingress_v4::v4_verdict_judged(
                woken,
                raw_len,
                &v,
                &ctx,
                |_| None,
                |r: &ParentRef| {
                    certs
                        .get(&(r.round, r.author.clone()))
                        .is_some_and(|c| c.body.digest == r.digest)
                },
                |v: &Vertex| {
                    let certified = v.epoch == epoch
                        && certs
                            .get(&(v.round, v.author.clone()))
                            .is_some_and(|c| c.body.digest == v.hash);
                    match Self::payload_gate(slots, v, certified) {
                        ingress_v4::PayloadGate::Check
                            if v.epoch > epoch
                                && next_checks.get(&v.author).copied().unwrap_or(0)
                                    >= staging::PENDING_MAX_PER_AUTHOR =>
                        {
                            ingress_v4::PayloadGate::Spent
                        }
                        gate => gate,
                    }
                },
            )
        };
        let (verdict, ran) = verdict;
        // B224: an authenticated digest counts for its slot (a second is
        // twin evidence), whatever the verdict; one dropped after Layer S is
        // remembered for the tick.
        if ran.authenticated {
            self.note_authenticated(&v);
            if matches!(verdict, Verdict::Drop(_)) && self.dropped.len() < DROPPED_CAP {
                self.dropped.insert(v.hash.clone());
            }
        }
        // B95/B117: a body whose payload was checked is remembered for its
        // slot, passed or refused. Its author signed it (the payload is
        // checked only after the author's signature), so only the author can
        // fill its own slot, and a refused payload is a failed costly check
        // charged to whoever delivered it (B51): no honest node stages or
        // serves one, as the checks are stateless (and so is each copy of
        // it after, above, B136/B148).
        // B204: refused, past its author's signature, for a field it signed:
        // its copies are refused before Layer S, charged, as a refused
        // payload's are (the digest is authenticated).
        if ran.signed_refusal {
            self.remember_payload(&v, ingress_v4::PayloadChecked::Refused);
        }
        if let Some(outcome) = ran.payload {
            self.remember_payload(&v, outcome);
            if v.epoch > self.epoch {
                *self.next_checks.entry(v.author.clone()).or_default() += 1;
            }
            if outcome == ingress_v4::PayloadChecked::Refused {
                crate::work::note_failed_check();
            }
        }
        // B126/B136: the embedded certificates E4 verified are ingested
        // whatever the verdict, and not verified again: a copy refused or
        // dropped after E4 threw them away, so each replay paid their
        // pairings again.
        self.ingest_carried(&v, &ran.certified, net);
        match verdict {
            Verdict::Stage => {
                self.early.remove(&v.author);
                self.stage_and_attest(v, net);
            }
            Verdict::PendingCert(missing) => {
                // Past the clock check: its author is not early any more.
                self.early.remove(&v.author);
                // RE-1 (c): ask for the certificates it waits on, and for the
                // whole gap below them when this node is far behind.
                for &i in &missing {
                    if let Some(r) = v.parent_refs.get(i) {
                        self.want_cert(r.round, &r.author);
                    }
                }
                self.want_gap(v.round.saturating_sub(1));
                // B68/B126: the buffered vertex keeps no embedded
                // certificate: those that verified are ingested above, and
                // those that failed were charged to whoever delivered it and
                // must not be checked (and charged) again at a wake. A
                // transport field: the digest does not cover them.
                let mut v = v;
                for r in &mut v.parent_refs {
                    r.cert = None;
                }
                // B442: woken once, by the last of these certificates.
                self.keep_pending(v, &missing);
            }
            Verdict::PendingEpoch => {
                // B119: its embedded certificates are not checked before the
                // next epoch is active, and activation re-evaluates what was
                // buffered uncounted: they are dropped (E+1's certificates
                // arrive as early certificates or by pull).
                let mut v = v;
                for r in &mut v.parent_refs {
                    r.cert = None;
                }
                self.keep_pending(v, &[]);
            }
            Verdict::Ahead => {
                // The network activated E+1 and this node has not closed E:
                // the rest of E is fetched (served from peers' closed tail).
                self.want_gap(v.round.saturating_sub(1));
            }
            Verdict::Early => {
                let ts = self.early.entry(v.author.clone()).or_insert(v.timestamp);
                *ts = (*ts).max(v.timestamp);
                if self.early_digests.len() < EARLY_DIGESTS_CAP {
                    self.early_digests.insert(v.hash.clone(), v.timestamp);
                }
            }
            Verdict::Invalid(_) | Verdict::Drop(_) | Verdict::Stale => {}
        }
    }

    /// CE-3 for the parent certificates a vertex carried that E4 verified
    /// (`refs`, indices), so a lost `DAG_CERT` never leaves this node unable
    /// to order a parent it can see certified in its children. E4 verified
    /// each against the body `attest_body` builds and the active committee,
    /// so it is not verified again (B136: it was, once per certificate).
    fn ingest_carried(&mut self, v: &Vertex, refs: &[usize], net: &dyn ConsensusNet) {
        for &i in refs {
            let Some(r) = v.parent_refs.get(i) else {
                continue;
            };
            let Some(compact) = &r.cert else {
                continue;
            };
            // B120: nothing at or below GC's cut is kept (B255: the
            // retention cut).
            if r.round <= self.retention_cut() {
                continue;
            }
            let body = self.attest_body(r.round, &r.author, &r.digest);
            let cert = VertexCertificate::from_compact(body, compact, &self.cfg.committee);
            self.ingest_cert(cert, net);
        }
    }

    /// Answer a retried vertex with this node's existing attestation, if it
    /// signed one: AT-2's reuse, without a transaction.
    fn resend_attestation(&mut self, v: &Vertex, net: &dyn ConsensusNet) {
        if !self.may_sign() {
            return;
        }
        // Once per slot per tick: each replayed copy used to trigger a
        // broadcast (final review MEDIUM).
        if self.resent.0 != self.tick {
            self.resent = (self.tick, HashSet::new());
        }
        // B205: the slot of the staged body, not the copy's claim (a copy is
        // matched by its digest alone, so each invented (round, author) cost
        // a key derivation and a guard read a tick).
        let Some((round, author)) = lock(&self.dag)
            .get(&v.hash)
            .map(|staged| (staged.round, staged.author.clone()))
        else {
            return;
        };
        if !self.resent.1.insert((round, author.clone())) {
            return;
        }
        let body = self.attest_body(round, &author, &v.hash);
        let Ok(Some(a)) = self.read_own_attestation(&body) else {
            return;
        };
        if author == self.cfg.address {
            self.on_attestation(a, net);
        } else {
            net.send(&author, Msg::Attest(a));
        }
    }

    /// ST-1..3 and AT-2/AT-3 in one transaction (RC-2): the node attests the
    /// first digest it stages for a slot, and a signature is released only
    /// with its body durably staged.
    fn stage_and_attest(&mut self, v: Vertex, net: &dyn ConsensusNet) {
        let certified = self
            .certs
            .get(&(v.round, v.author.clone()))
            .map(|c| c.body.digest.clone());
        let body = self.attest_body(v.round, &v.author, &v.hash);
        // Never sign a digest the slot is certified against: under Lemma U
        // it cannot be certified, and beyond f it would help a second one.
        // EP-3: nothing of E is attested once E has closed (its anchors are
        // decided; what is still staged is kept for serving only).
        // B155: and not a twin of the digest this node attested for the
        // slot (its guard would refuse it, after a pairing on each copy).
        let sign = self.may_sign()
            && self.closing_round.is_none()
            && certified.as_deref().is_none_or(|d| d == v.hash)
            && staging::self_attested_digest(&self.storage, v.epoch, v.round, &v.author)
                .is_none_or(|d| d == v.hash);
        // G1 EQ-1 / G5 SL-3: a second digest for the slot is proposer-twin
        // evidence. Read the slot's other bodies first: staging may evict one.
        let twins = evidence::other_bodies(&self.storage, &v);
        let (committee, key, address, budget) = (
            &self.cfg.committee,
            &self.cfg.node_key,
            &self.cfg.address,
            self.cfg.b_auth,
        );
        let result = self.storage.transaction(|view| {
            let attestation = if sign {
                Some(
                    vcert::attest_slot_in(&view, &body, committee, key, address)
                        .map_err(storage_err)?,
                )
            } else {
                None
            };
            let role = match attestation {
                Some(AttestOutcome::Signed(_) | AttestOutcome::Reused(_)) => Role::SelfAttested,
                _ => Role::Staged,
            };
            let staged = staging::stage_in(&view, &v, role, certified.as_deref(), budget)
                .map_err(storage_err)?;
            if role == Role::SelfAttested && matches!(staged, StageOutcome::EvidenceOnly(_)) {
                // Never sign a body this node does not hold (AT-3, Lemma A).
                return Err(storage_err("an attested body that was not staged"));
            }
            // In the same transaction (G5 review): a crash after staging
            // must not lose the pair, since the staged body is never
            // processed again.
            for other in &twins {
                evidence::record_twin(&view, other, &v);
            }
            Ok((attestation, staged))
        });
        let Ok((attestation, staged)) = result else {
            return;
        };
        if matches!(staged, StageOutcome::EvidenceOnly(_)) {
            self.remember_unstaged(&v);
        }
        {
            let mut dag = lock(&self.dag);
            match staged {
                StageOutcome::EvidenceOnly(_) => return,
                StageOutcome::Evicted(gone) => {
                    dag.remove(&gone);
                }
                StageOutcome::Staged | StageOutcome::Held => {}
            }
            dag.insert(v.hash.clone(), canonical(&v));
        }
        if let Some(AttestOutcome::Signed(a) | AttestOutcome::Reused(a)) = attestation {
            if v.author == self.cfg.address {
                self.on_attestation(a, net);
            } else {
                net.send(&v.author, Msg::Attest(a));
            }
        }
        self.try_orderable(v.hash);
    }

    /// CE-1 on the author's side.
    pub fn on_attestation(&mut self, att: VertexAttestation, net: &dyn ConsensusNet) {
        if att.body.author != self.cfg.address || att.body.epoch != self.epoch {
            return;
        }
        let Some(collector) = self.collectors.get_mut(&att.body.round) else {
            return;
        };
        if let Ok(CollectOutcome::Certified(cert)) = collector.add(&att) {
            self.collectors.remove(&att.body.round);
            net.broadcast(Msg::Cert((*cert).clone()));
            self.ingest_cert(*cert, net);
        }
    }

    /// CE-2 then CE-3.
    pub fn on_cert(&mut self, cert: VertexCertificate, net: &dyn ConsensusNet) {
        if cert.body.epoch != self.epoch {
            // EP-5: a certificate of E+1 before activation is kept, verified
            // under C_{E+1}, and ingested at activation. Any other epoch's is
            // inert.
            const EARLY_CERT_CAP: usize = 4096;
            // Replays of one certificate cost one verification and one slot
            // (they used to fill the cap and crowd out the rest).
            let key = (
                cert.body.round,
                cert.body.author.clone(),
                cert.body.digest.clone(),
            );
            if self.early_keys.contains(&key) || self.early_certs.len() >= EARLY_CERT_CAP {
                return;
            }
            let Some(next) = self.next.as_ref().filter(|n| n.epoch == cert.body.epoch) else {
                return;
            };
            // B230: as B205 for E's: bound to another committee, refused
            // before C_{E+1} is sorted and hashed, and a failed check
            // charged (no honest member sends one that fails under C_{E+1});
            // each replay of one cost both sorts and the hash, uncharged.
            if cert.body.committee_hash != self.next_committee_hash {
                crate::work::note_failed_check();
                return;
            }
            let verified = charged_once(|| {
                vcert::verify_vertex_cert(
                    &cert,
                    &next.committee,
                    &self.cfg.chain_id,
                    &self.cfg.genesis_identity,
                    next.epoch,
                )
                .is_ok()
            });
            if verified {
                self.early_keys.insert(key);
                self.early_certs.push(cert);
            }
            return;
        }
        // B120: a certificate at or below GC's cut (g - RETAIN_SLACK, where
        // GC-3 forgets certificates) is forgotten as soon as it is ingested:
        // a replay of one cost a pairing, a synced write and a body request.
        // Between the cut and g certificates are still held, so a second
        // digest for a held slot there is still verified (a conflict).
        if cert.body.round <= self.retention_cut() {
            return;
        }
        // B51: a copy of a certificate already held costs nothing (each
        // replay used to cost a pairing). Another digest for a held slot is
        // verified: a valid one is a conflict `ingest_cert` reports.
        if self
            .certs
            .get(&(cert.body.round, cert.body.author.clone()))
            .is_some_and(|held| held.body.digest == cert.body.digest)
        {
            return;
        }
        // B205: bound to another committee, refused before the committee is
        // sorted and hashed again (`verify_stake_aggregate`), and charged: an
        // honest certificate of E names C_E's hash.
        if cert.body.committee_hash != self.committee_hash {
            crate::work::note_failed_check();
            return;
        }
        // B229: any failure charged once (a failed pairing charged itself;
        // a bitmap below the quorum or a stake mismatch, after a sort of the
        // committee, did not).
        let verified = charged_once(|| {
            vcert::verify_vertex_cert(
                &cert,
                &self.cfg.committee,
                &self.cfg.chain_id,
                &self.cfg.genesis_identity,
                self.epoch,
            )
            .is_ok()
        });
        if !verified {
            return;
        }
        self.ingest_cert(cert, net);
    }

    /// Record a verified certificate in memory (no conflict check).
    fn index_cert(&mut self, cert: VertexCertificate) {
        let round = cert.body.round;
        let key = (round, cert.body.author.clone());
        if self.certs.contains_key(&key) {
            return;
        }
        let signer_stake = self
            .stakes
            .iter()
            .find(|(a, _)| *a == cert.body.author)
            .map_or(0, |(_, s)| *s as u128);
        // RE-1 (a): a certificate whose body is not held.
        if !self.is_staged(&cert.body.digest) {
            self.want_body(&cert);
        }
        // B5 trace: an anchor leader's certificate that arrives after its
        // round reached quorum, with how many ticks later and whether this
        // node had already moved on without it.
        if round >= 2 && round.is_multiple_of(2) {
            if let Some(since) = self.quorum_since.get(&round).copied() {
                if OrderingEngine::leader_for_round(round, &self.stakes, 0) == cert.body.author {
                    println!(
                        "⏱️ [B5] anchor {round}: leader certificate {} ticks after quorum{}",
                        self.tick - since,
                        if self.own.contains_key(&(round + 1)) {
                            ", after this node proposed without it"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
        self.certs.insert(key, cert);
        self.last_cert_tick = self.tick;
        let total: u128 = self.stakes.iter().map(|(_, s)| *s as u128).sum();
        let held = self.cert_stake.entry(round).or_insert(0);
        *held += signer_stake;
        if qc::stake_quorum_met(*held, total) {
            self.quorum_since.entry(round).or_insert(self.tick);
        }
    }

    /// CE-3: a verified certificate. A second digest for a slot halts ordering
    /// and keeps both as evidence; the node never chooses between them.
    fn ingest_cert(&mut self, cert: VertexCertificate, net: &dyn ConsensusNet) {
        let key = (cert.body.round, cert.body.author.clone());
        if let Some(held) = self.certs.get(&key) {
            if held.body.digest != cert.body.digest {
                let alarm =
                    recovery::alarm_key(cert.body.epoch, cert.body.round, &cert.body.author);
                let evidence = serde_json::json!({ "held": held, "other": cert }).to_string();
                let first = matches!(self.storage.get(&alarm), Ok(None));
                // G5 SL-3: every attester in both signed both digests. The
                // alarm and the evidence row commit together.
                let _ = self.storage.transaction(|view| {
                    view.put(&alarm, &evidence)?;
                    evidence::record_cert_conflict(&view, held, &cert);
                    Ok(())
                });
                self.halted = Some(format!(
                    "two certificates for round {} author {}",
                    cert.body.round, cert.body.author
                ));
                // G5 review: relayed once, so every honest node holding
                // either certificate halts too and keeps the evidence (a
                // coalition able to make two could halt the chain anyway).
                // It is carried once operators recover the chain.
                if first {
                    net.broadcast(Msg::Cert(held.clone()));
                    net.broadcast(Msg::Cert(cert.clone()));
                }
            }
            return;
        }
        let row = format!(
            "consensus:vcert:v1:{:020}:{:020}:{}",
            cert.body.epoch, cert.body.round, cert.body.author
        );
        if let Ok(json) = serde_json::to_string(&cert) {
            // May be unsynced: a certificate can be obtained again (RC-2).
            let _ = self.storage.put(&row, &json);
        }
        let digest = cert.body.digest.clone();
        self.index_cert(cert);
        // A held body of the certified digest takes the certified role.
        let held = lock(&self.dag).get(&digest).cloned();
        if let Some(v) = held {
            let _ = staging::stage(
                &self.storage,
                &v,
                Role::Staged,
                Some(&digest),
                self.cfg.b_auth,
            );
        }
        self.try_orderable(digest.clone());
        // B442: the vertices that waited on this slot's certificate last are
        // judged again, each once (`wake`); the others keep waiting. Every
        // certificate took the whole buffer out and scanned each held
        // vertex's refs, and each one naming the slot ran Layer S again over
        // up to 768 KiB, uncounted: f members cost every honest node
        // f·(n−f) runs a round, with bodies citing parents not certified yet.
        let (round, author) = key;
        for v in self.pending.certified(round, &author, &digest) {
            self.wake(v, net);
        }
    }

    // --------------------------------------------------------- orderable (OR)

    /// OR-1, the single writer of O_E: a digest is orderable when it is its
    /// slot's certified digest, its body is staged, and it is at the first
    /// round or every parent is orderable. Inserting it wakes the children
    /// waiting on it, then runs the decision.
    fn try_orderable(&mut self, digest: String) {
        let floor = self.gc_floor();
        let mut work = vec![digest];
        let mut inserted = false;
        while let Some(d) = work.pop() {
            if self.orderable.contains(&d) {
                continue;
            }
            let held = lock(&self.dag).get(&d).cloned();
            let Some(v) = held else {
                continue;
            };
            let certified = self
                .certs
                .get(&(v.round, v.author.clone()))
                .is_some_and(|c| c.body.digest == d);
            if !certified {
                continue;
            }
            // OR-1 with GC-2's settled arm: a parent whose ref declares a round
            // at or below g is settled, as in the decision's walk (one
            // predicate; Layer S aligns refs with parents and checks the round).
            let missing: Vec<String> = if v.round == self.first_round {
                Vec::new()
            } else {
                v.parent_refs
                    .iter()
                    .filter(|r| r.round > floor && !self.orderable.contains(&r.digest))
                    .map(|r| r.digest.clone())
                    .collect()
            };
            if !missing.is_empty() {
                for p in missing {
                    // RE-1 (b): a waiting child's parent. Its body is wanted
                    // once its certificate is held; the certificate first.
                    if let Some(r) = v.parent_refs.iter().find(|r| r.digest == p) {
                        if !self.certs.contains_key(&(r.round, r.author.clone())) {
                            let (round, author) = (r.round, r.author.clone());
                            self.want_cert(round, &author);
                        }
                    }
                    self.waiting.entry(p).or_default().insert(d.clone());
                }
                continue;
            }
            // OR-2: one digest per author per round. CE-3 keeps one
            // certificate per slot, so this cannot fire; it is checked anyway.
            {
                let dag = lock(&self.dag);
                let mut index = lock(&self.round_index);
                let row = index.entry(v.round).or_default();
                if row
                    .iter()
                    .any(|h| dag.get(h).is_some_and(|u| u.author == v.author))
                {
                    self.halted = Some(format!(
                        "OR-2: author {} twice at round {}",
                        v.author, v.round
                    ));
                    return;
                }
                row.push(d.clone());
            }
            self.orderable.insert(d.clone());
            inserted = true;
            if let Some(children) = self.waiting.remove(&d) {
                work.extend(children);
            }
        }
        if inserted {
            self.progressed = true;
            if self.self_decide {
                self.decide();
            }
        }
    }

    // ----------------------------------------------------------- decision (DE)

    /// DE over O_E with the frozen committee, one anchor per call until none
    /// is decidable. Halted ordering decides nothing.
    fn decide(&mut self) {
        while self.halted.is_none() {
            let out = {
                let mut ordering = lock(&self.ordering);
                let dag = lock(&self.dag);
                let index = lock(&self.round_index);
                ordering.try_commit(0, &dag, &index, &self.stakes)
            };
            if out.is_empty() {
                break;
            }
            for info in &out {
                self.standalone_block(info);
            }
            self.decided.extend(out);
            if self.activation_due {
                break;
            }
        }
    }

    /// The end of every call: a standalone epoch boundary activates here,
    /// where a network is at hand (EP-4).
    fn finish_call(&mut self, net: &dyn ConsensusNet) {
        while self.activation_due {
            self.activation_due = false;
            let _ = self.activate_next(net);
        }
    }

    // --------------------------------------------------------- production (PR)

    /// PR-1: one above the highest round whose held certificates come from a
    /// quorum of authors.
    pub fn current_round(&self) -> u64 {
        let total: u128 = self.stakes.iter().map(|(_, s)| *s as u128).sum();
        let top = self
            .cert_stake
            .iter()
            .rev()
            .find(|(_, s)| qc::stake_quorum_met(**s, total))
            .map(|(r, _)| *r);
        top.map_or(self.first_round, |r| (r + 1).max(self.first_round))
    }

    /// One tick: send this node's uncertified proposals of the last two
    /// rounds again (T_RETRY is one tick), then return the round PR-2 and
    /// PR-3 allow this node to propose now, if any. The caller gathers a
    /// payload only then, and calls `propose`.
    pub fn tick(&mut self, net: &dyn ConsensusNet) -> Option<Slot> {
        self.tick += 1;
        self.dropped.clear();
        self.refresh_finality_floor();
        let due = (self.now_secs)().saturating_add(ingress_v4::MAX_FUTURE_DRIFT_SECS);
        self.early_digests.retain(|_, at| *at > due);
        if self.halted.is_some() {
            return None;
        }
        // PR-4 and RC-1 step 6 (B359): an uncertified proposal of the last
        // two rounds goes again, to the members whose attestation it lacks.
        // Each one went whole to every member every tick until GC: a member
        // nobody attests (f members withholding, an honest one away) pushed
        // ~100 bodies of up to 768 KiB a tick past its byte budget, and its
        // new vertices were dropped with them. An older one is past being
        // cited (the rounds above it formed their quorums without it), and
        // its transactions return to the mempool.
        let recent = self.current_round().saturating_sub(1);
        for (round, collector) in self.collectors.range(recent..) {
            if let Some(v) = self.own.get(round) {
                for member in collector.missing() {
                    net.send(member, Msg::Vertex(v.clone()));
                }
            }
        }
        self.observe_floor(net);
        self.finish_call(net);
        self.fetch(net);
        // B262: the newest own vertex goes out again now and then while a
        // block of this node's waits on its QC, so a member coming back sees
        // how far the DAG got and wants the whole gap (B300). B300: whether
        // or not this node may still propose: the boundary block closed the
        // epoch (EP-3) before its QC formed, nothing was sent again, and a
        // member coming back learned nothing. B322: only while this node
        // proposes nothing (the epoch closed, or finality lags): a proposal
        // pushes the frontier anyway, and every block waits on its QC for a
        // while, so the newest vertex (up to 768 KiB) went to every member
        // every fourth tick in steady state.
        if self.tick.is_multiple_of(FINALITY_REBROADCAST_TICKS)
            && crate::qc_producer::lowest_pending_qc_height(&self.storage).is_some()
            && (self.closing_round.is_some() || self.finality_lags())
        {
            if let Some(v) = self.own.values().next_back() {
                net.broadcast(Msg::Vertex(v.clone()));
            }
        }
        // EP-3: after its boundary block, epoch E proposes nothing more.
        if !self.may_sign() || self.closing_round.is_some() {
            return None;
        }
        // B255: nor with `MAX_UNFINALIZED_BLOCKS` blocks above this node's
        // lowest block without a QC (B262: or `MAX_KEPT_ROUNDS` rounds above
        // its floor): what a lagging member needs to rebuild and vote on is
        // kept (`retention_floor`), and proposing on would grow it without
        // bound.
        if self.finality_lags() {
            return None;
        }
        let owed = self.anchor_owed();
        let round = owed.unwrap_or_else(|| self.current_round());
        if !self.may_propose(round) {
            return None;
        }
        let prev = round - 1;
        if round > self.first_round && prev >= 2 && prev.is_multiple_of(2) {
            let leader = OrderingEngine::leader_for_round(prev, &self.stakes, 0);
            let since = self.quorum_since.get(&prev).copied().unwrap_or(self.tick);
            // B5: an anchor this node proposed late is waited for from then.
            let since = since.max(self.owed_at.get(&prev).copied().unwrap_or(0));
            if !self.certs.contains_key(&(prev, leader.clone())) {
                if self.tick < since + T_LEADER_TICKS {
                    return None;
                }
                // B5 trace: the wait ran out; this vertex cannot support
                // the anchor.
                println!(
                    "⏱️ [B5] round {round}: no certificate from anchor {prev}'s leader {:.8} after {} ticks",
                    leader,
                    self.tick - since
                );
            }
        }
        if let Some(anchor) = owed {
            self.owed_at.insert(anchor, self.tick);
        }
        let cursor = lock(&self.ordering).next_anchor_round;
        Some(Slot {
            round,
            carry_payload: round <= cursor.saturating_add(ingress_v4::LEAD),
        })
    }

    /// B5: the anchor round this node leads and still owes a vertex: the
    /// round below `current_round`, when the other members certified a
    /// quorum of it before this node's tick came (ticks are not aligned
    /// across nodes). Proposing `current_round` instead skipped the anchor
    /// for good: it was never certified and its round committed nothing
    /// (every missed anchor of the S7a rehearsal, 8 of 138, was its own
    /// leader's skip). The vertex still reaches the next round in time:
    /// its proposals wait `T_LEADER_TICKS` for exactly this certificate.
    ///
    /// Never after this node proposed the round above (a vertex nothing
    /// would cite, review LOW-1). An epoch's first round is an anchor too;
    /// it cites the sentinel, so no quorum below it is needed (LOW-2).
    fn anchor_owed(&self) -> Option<u64> {
        let anchor = self.current_round().checked_sub(1)?;
        let unproposed = |round: u64| {
            !self.own.contains_key(&round)
                && matches!(self.storage.get(&self.proposed_key(round)), Ok(None))
        };
        let parents_held = anchor == self.first_round
            || (anchor > self.first_round && self.quorum_held(anchor - 1));
        let owed = anchor >= 2
            && anchor.is_multiple_of(2)
            && parents_held
            && OrderingEngine::leader_for_round(anchor, &self.stakes, 0) == self.cfg.address
            && unproposed(anchor)
            && unproposed(anchor + 1);
        owed.then_some(anchor)
    }

    /// Whether this node holds certificates of a stake quorum for `round`.
    fn quorum_held(&self, round: u64) -> bool {
        let total: u128 = self.stakes.iter().map(|(_, s)| *s as u128).sum();
        self.cert_stake
            .get(&round)
            .is_some_and(|held| qc::stake_quorum_met(*held, total))
    }

    /// `tick`, then `propose` with `payload` when a slot is open.
    pub fn on_tick(&mut self, payload: Vec<String>, net: &dyn ConsensusNet) {
        if let Some(slot) = self.tick(net) {
            let payload = if slot.carry_payload {
                payload
            } else {
                Vec::new()
            };
            self.propose(slot.round, payload, net);
        }
    }

    /// PR-4's parents for `round`: every certificate held for the previous
    /// round, one per author, sorted by author, each carried with its
    /// certificate. The first round cites the sentinel.
    fn parents_for(&self, round: u64) -> (Vec<String>, Vec<ParentRef>) {
        if round == self.first_round {
            return (vec![self.sentinel.clone()], Vec::new());
        }
        let mut held: Vec<&VertexCertificate> = self
            .certs
            .iter()
            .filter(|((r, _), _)| *r == round - 1)
            .map(|(_, c)| c)
            .collect();
        held.sort_by(|a, b| a.body.author.cmp(&b.body.author));
        let refs: Vec<ParentRef> = held
            .iter()
            .map(|c| ParentRef {
                round: c.body.round,
                author: c.body.author.clone(),
                digest: c.body.digest.clone(),
                proof: None,
                cert: Some(c.compact()),
            })
            .collect();
        (refs.iter().map(|r| r.digest.clone()).collect(), refs)
    }

    /// The wire size of this node's round-`round` proposal with no payload,
    /// so the caller can fit its payload under `MAX_VERTEX_BYTES`.
    pub fn proposal_overhead(&self, round: u64) -> usize {
        let (parents, parent_refs) = self.parents_for(round);
        let probe = Vertex {
            epoch: self.epoch,
            round,
            author: self.cfg.address.clone(),
            parents,
            parent_refs,
            payload: Vec::new(),
            timestamp: u64::MAX,
            hash: "0".repeat(64),
            signature: "0".repeat(128),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
        };
        serde_json::to_string(&Msg::Vertex(probe)).map_or(usize::MAX, |s| s.len())
    }

    /// PR-4: one transaction stages the body, writes the producer guard and
    /// the node's own attestation guard; only then is the vertex broadcast.
    /// Returns false when nothing was proposed, so the caller keeps its
    /// payload.
    pub fn propose(&mut self, round: u64, payload: Vec<String>, net: &dyn ConsensusNet) -> bool {
        // B282: never at or below g, whatever the caller asked.
        if round <= self.gc_floor() {
            return false;
        }
        let (parents, parent_refs) = self.parents_for(round);
        let mut v = Vertex {
            epoch: self.epoch,
            round,
            author: self.cfg.address.clone(),
            parents,
            parent_refs,
            payload,
            timestamp: (self.now_secs)(),
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
        };
        v.hash = v.hash_v4_with_domain(&self.cfg.chain_id, &self.cfg.genesis_identity);
        v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&self.cfg.node_key));
        // S1 bounds the copy received, certificates included, and Layer S the
        // canonical body; a proposal over either could never be staged.
        if serde_json::to_string(&v).map_or(true, |b| b.len() > crate::dag::MAX_VERTEX_BYTES) {
            return false;
        }
        let body = self.attest_body(round, &self.cfg.address, &v.hash);
        let guard = self.proposed_key(round);
        let high = self.proposed_high_key();
        let (committee, key, address, budget) = (
            &self.cfg.committee,
            &self.cfg.node_key,
            &self.cfg.address,
            self.cfg.b_auth,
        );
        let result = self.storage.transaction(|view| {
            if view.get(&guard).map_err(storage_err)?.is_some() {
                return Err(storage_err("this round was already proposed"));
            }
            // B282: and never at or below a round proposed before in this
            // epoch (its guard may be gone), in the guard's transaction.
            let proposed_above = view
                .get(&high)
                .map_err(storage_err)?
                .is_some_and(|h| h.parse::<u64>().map_or(true, |h| round <= h));
            if proposed_above {
                return Err(storage_err("a round at or above it was proposed"));
            }
            let staged = staging::stage_in(&view, &v, Role::SelfAttested, None, budget)
                .map_err(storage_err)?;
            if matches!(staged, StageOutcome::EvidenceOnly(_)) {
                return Err(storage_err("the node's own body was not staged"));
            }
            view.put(&guard, &v.hash).map_err(storage_err)?;
            view.put(&high, &round.to_string()).map_err(storage_err)?;
            match vcert::attest_slot_in(&view, &body, committee, key, address)
                .map_err(storage_err)?
            {
                AttestOutcome::Signed(a) | AttestOutcome::Reused(a) => Ok(a),
                AttestOutcome::Conflict(_) => Err(storage_err("the slot is attested already")),
            }
        });
        let Ok(own_attestation) = result else {
            return false;
        };
        lock(&self.dag).insert(v.hash.clone(), canonical(&v));
        if let Ok(collector) = CertCollector::new(body, &self.cfg.committee) {
            self.collectors.insert(round, collector);
        }
        self.own.insert(round, v.clone());
        net.broadcast(Msg::Vertex(v));
        self.on_attestation(own_attestation, net);
        true
    }

    // ----------------------------------------------------------------- reads

    /// Decisions made since the last call, in order.
    pub fn take_decided(&mut self) -> Vec<CommitInfo> {
        std::mem::take(&mut self.decided)
    }

    pub fn halted(&self) -> Option<&str> {
        self.halted.as_deref()
    }

    /// B405: whether this node signs now: a staked member whose BLS key is
    /// the registered one (AT-1), with continuous guards (RC-3). A member
    /// that abstains forwards its transactions instead of holding them.
    pub fn signs(&self) -> bool {
        self.can_sign && self.guards_continuous
    }

    /// B405: whether this node's guards are not continuous (RC-3): it signs
    /// nothing until the activation of an epoch whose boundary is above its
    /// proof of boot.
    pub fn lacks_guards(&self) -> bool {
        !self.guards_continuous
    }

    /// B405, B441: whether this node seeks its proof of boot: it lacks
    /// continuous guards and its key is registered in C_E or in the live
    /// set, which C_{E+1} is derived from at H_E. A joiner proves during
    /// the epoch it joined in, so the boundary that admits it is above its
    /// proof and E+1's activation re-arms it. Asked of C_E's members alone,
    /// every joiner (no origin is written at a first key use) abstained its
    /// whole first member epoch, and a wave of joiners cut the committee's
    /// fault margin by their stake (G5 CH-1 bounds it near 10%) for that
    /// epoch.
    pub fn seeks_boot_proof(&self) -> bool {
        !self.guards_continuous
            && (self.can_sign
                || crate::qc_producer::load_validator_set_v1(&self.storage).is_some_and(|live| {
                    live.iter().any(|m| {
                        m.address == self.cfg.address
                            && m.stake > 0
                            && m.bls_public_key == self.bls_pk
                    })
                }))
    }

    /// G5 BT-1: when the members whose latest vertex was refused as ahead of
    /// this node's clock hold a stake quorum of the committee, their
    /// stake-weighted median timestamp: this node's clock is behind theirs.
    /// A Byzantine minority cannot raise it alone.
    pub fn early_quorum(&self) -> Option<u64> {
        let samples: Vec<(String, u64)> = self.early.iter().map(|(a, t)| (a.clone(), *t)).collect();
        let t = crate::dag::committee_block_timestamp(&samples, &self.stakes, 0);
        (t > 0).then_some(t)
    }

    pub fn is_staged(&self, digest: &str) -> bool {
        lock(&self.dag).contains_key(digest)
    }

    pub fn is_orderable(&self, digest: &str) -> bool {
        self.orderable.contains(digest)
    }

    /// The certified digest of a slot, if this node holds its certificate.
    pub fn certified(&self, round: u64, author: &str) -> Option<&str> {
        self.certs
            .get(&(round, author.to_string()))
            .map(|c| c.body.digest.as_str())
    }

    pub fn own_proposal(&self, round: u64) -> Option<&Vertex> {
        self.own.get(&round)
    }

    pub fn address(&self) -> &str {
        &self.cfg.address
    }

    pub fn finality_digest(&self) -> String {
        lock(&self.ordering).current_finality_digest().to_string()
    }

    /// GC-1's g, as the ordering engine holds it.
    pub fn floor(&self) -> u64 {
        self.gc_floor()
    }

    /// B262: the floor kept for this node's lowest block without a QC
    /// (`u64::MAX`: none), as of the last tick.
    pub fn finality_floor(&self) -> u64 {
        self.finality_floor
    }

    pub fn cursor(&self) -> u64 {
        lock(&self.ordering).next_anchor_round
    }

    /// Replace the wall clock (a deterministic harness pins it).
    pub fn set_now_secs(&mut self, now_secs: Arc<dyn Fn() -> u64 + Send + Sync>) {
        self.now_secs = now_secs;
    }

    /// C_0 as (address, stake), canonical order: what the host decides with
    /// (DE-7), never the live set.
    pub fn stakes(&self) -> &[(String, u64)] {
        &self.stakes
    }

    /// Whether O_E grew since the last call: the host's cue to run its
    /// commit loop.
    pub fn take_progress(&mut self) -> bool {
        std::mem::take(&mut self.progressed)
    }
}

pub mod epoch;
pub mod evidence;
mod gc;
pub mod pull;
pub mod recovery;

#[cfg(test)]
mod tests;
