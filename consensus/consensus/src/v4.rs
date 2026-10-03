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

/// The V4 engine of one node.
pub struct Engine {
    cfg: Config,
    storage: Arc<StateDB>,
    /// C_0 as (address, stake), canonical order: the decision's committee.
    stakes: Vec<(String, u64)>,
    committee_hash: String,
    ed25519_pk: String,
    /// AT-1: a staked member whose derived BLS key is the registered one.
    can_sign: bool,
    /// RC-3: guard continuity held at boot.
    guards_continuous: bool,
    /// RC-3: a node that booted without continuous guards re-arms only at the
    /// activation of an epoch whose boundary block is later than this (its
    /// boot time plus the clock-skew margin), i.e. an epoch that began after
    /// its guards were lost. Persisted in `consensus:guard_resume_after`.
    resume_after: Option<u64>,
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
    /// request this node sent for it (answers are unauthenticated).
    cert_answers: HashMap<(u64, String), u8>,
    /// The tick at which a certificate last arrived (RE-1 d).
    last_cert_tick: u64,
    /// This node's last request number and the durable reservation above it.
    pull_seq: u64,
    pull_seq_reserved: u64,
    /// RE-6 on the serving side.
    budget: pull::Budget,
    /// The GC floor this engine last acted on (OR-3, GC-3).
    last_floor: u64,
    /// The active epoch E (EP-1): its number, first round and sentinel, and
    /// r* once it has closed (EP-3). `cfg.committee` is C_E.
    epoch: u64,
    first_round: u64,
    sentinel: String,
    closing_round: Option<u64>,
    /// E+1's record once E has closed and until activation (EP-2, EP-4).
    next: Option<epoch::EpochStart>,
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
        let resume_after = if guards_continuous {
            None
        } else {
            Some(epoch::resume_point(&storage, (now_secs)())?)
        };
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
        let seq = Self::load_seq(&storage);
        let mut engine = Self {
            ordering: shared.ordering,
            self_decide,
            progressed: false,
            storage,
            stakes,
            committee_hash,
            ed25519_pk,
            can_sign,
            guards_continuous,
            resume_after,
            dag: shared.dag,
            certs: HashMap::new(),
            cert_stake: BTreeMap::new(),
            quorum_since: HashMap::new(),
            owed_at: HashMap::new(),
            round_index: shared.round_index,
            orderable: HashSet::new(),
            waiting: HashMap::new(),
            pending: PendingBuffer::default(),
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
        self.load_closed()?;
        let loaded = {
            let record = self.record();
            staging::load(
                &self.storage,
                &record,
                &self.cfg.chain_id,
                &self.cfg.genesis_identity,
                self.gc_floor(),
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

    /// g. Always 0 until GC lands (S7).
    fn gc_floor(&self) -> u64 {
        lock(&self.ordering).gc_floor()
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

    fn read_own_attestation(&self, body: &AttestBody) -> Result<Option<VertexAttestation>, String> {
        let bls_pk = hex::encode(
            BLSEngine::consensus().pubkey_raw(&qc::derive_validator_bls_seed(&self.cfg.node_key)),
        );
        let row = self
            .storage
            .get(&vcert::attest_guard_key(body, &bls_pk))
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
        self.dispatch(raw_len, msg, net);
        self.observe_floor(net);
        self.finish_call(net);
    }

    fn dispatch(&mut self, raw_len: usize, msg: Msg, net: &dyn ConsensusNet) {
        match msg {
            Msg::Vertex(v) => self.on_vertex(raw_len, v, net),
            Msg::Attest(a) => self.on_attestation(a, net),
            Msg::Cert(c) => self.on_cert(c, net),
            Msg::Req(signed) => self.on_request(signed, net),
            Msg::Resp { to, resp } => {
                if to == self.cfg.address {
                    self.on_response(resp, net);
                }
            }
        }
    }

    /// IN-1, then ST and AT for a vertex that stages.
    pub fn on_vertex(&mut self, raw_len: usize, v: Vertex, net: &dyn ConsensusNet) {
        // A copy of a body already staged: nothing to verify or stage again,
        // and nothing to harvest (every ref of a staged body had a verified
        // certificate when it staged; a relay-padded copy is not verified, so
        // its refs are never looked at). Its author may be retrying for this
        // node's attestation (AT-2 reuses the guard).
        if self.is_staged(&v.hash) {
            self.resend_attestation(&v, net);
            return;
        }
        let verdict = {
            let ctx = Context {
                chain_id: &self.cfg.chain_id,
                genesis_identity: &self.cfg.genesis_identity,
                active: self.record(),
                previous: self.previous_record(),
                next: self.next_record(),
                now_secs: (self.now_secs)(),
                gc_floor: self.gc_floor(),
                cursor: lock(&self.ordering).next_anchor_round,
            };
            let certs = &self.certs;
            // E4's cache: a ref whose certificate is already in the index was
            // verified when it got there (CE-3 ingests only verified ones).
            ingress_v4::v4_verdict_cached(
                raw_len,
                &v,
                &ctx,
                |_| None,
                |r: &ParentRef| {
                    certs
                        .get(&(r.round, r.author.clone()))
                        .is_some_and(|c| c.body.digest == r.digest)
                },
            )
        };
        match verdict {
            Verdict::Stage => {
                self.early.remove(&v.author);
                self.harvest_certs(&v, net);
                self.stage_and_attest(v, net);
            }
            Verdict::PendingCert(missing) => {
                // Past the clock check: its author is not early any more.
                self.early.remove(&v.author);
                // RE-1 (c): ask for the certificates it waits on, and for the
                // whole gap below them when this node is far behind.
                for i in missing {
                    if let Some(r) = v.parent_refs.get(i) {
                        self.want_cert(r.round, &r.author);
                    }
                }
                self.want_gap(v.round.saturating_sub(1));
                self.pending.push(v);
            }
            Verdict::PendingEpoch => {
                self.pending.push(v);
            }
            Verdict::Ahead => {
                // The network activated E+1 and this node has not closed E:
                // the rest of E is fetched (served from peers' closed tail).
                self.want_gap(v.round.saturating_sub(1));
            }
            Verdict::Early => {
                let ts = self.early.entry(v.author.clone()).or_insert(v.timestamp);
                *ts = (*ts).max(v.timestamp);
            }
            Verdict::Invalid(_) | Verdict::Drop(_) | Verdict::Stale => {}
        }
    }

    /// CE-3 for the parent certificates a vertex carries: each one that
    /// verifies and is not yet in the index is ingested (with the conflict
    /// check), so a lost `DAG_CERT` never leaves this node unable to order a
    /// parent it can see certified in its children.
    fn harvest_certs(&mut self, v: &Vertex, net: &dyn ConsensusNet) {
        for r in &v.parent_refs {
            let Some(compact) = &r.cert else {
                continue;
            };
            let known = self
                .certs
                .get(&(r.round, r.author.clone()))
                .is_some_and(|c| c.body.digest == r.digest);
            if known {
                continue;
            }
            let body = self.attest_body(r.round, &r.author, &r.digest);
            let cert = VertexCertificate::from_compact(body, compact, &self.cfg.committee);
            self.on_cert(cert, net);
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
        if !self.resent.1.insert((v.round, v.author.clone())) {
            return;
        }
        let body = self.attest_body(v.round, &v.author, &v.hash);
        let Ok(Some(a)) = self.read_own_attestation(&body) else {
            return;
        };
        if v.author == self.cfg.address {
            self.on_attestation(a, net);
        } else {
            net.send(&v.author, Msg::Attest(a));
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
        let sign = self.may_sign()
            && self.closing_round.is_none()
            && certified.as_deref().is_none_or(|d| d == v.hash);
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
            let keep = self.next.as_ref().is_some_and(|next| {
                cert.body.epoch == next.epoch
                    && vcert::verify_vertex_cert(
                        &cert,
                        &next.committee,
                        &self.cfg.chain_id,
                        &self.cfg.genesis_identity,
                        next.epoch,
                    )
                    .is_ok()
            });
            if keep {
                self.early_keys.insert(key);
                self.early_certs.push(cert);
            }
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
        if vcert::verify_vertex_cert(
            &cert,
            &self.cfg.committee,
            &self.cfg.chain_id,
            &self.cfg.genesis_identity,
            self.epoch,
        )
        .is_err()
        {
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
        // Vertices waiting on this slot's certificate are re-evaluated; the
        // others keep waiting.
        if !self.pending.is_empty() {
            let (round, author) = key;
            let (wake, wait): (Vec<Vertex>, Vec<Vertex>) =
                self.pending.take_all().into_iter().partition(|p| {
                    p.parent_refs
                        .iter()
                        .any(|r| r.round == round && r.author == author && r.digest == digest)
                });
            for v in wait {
                self.pending.push(v);
            }
            for v in wake {
                let len = ingress_v4::canonical_body(&v).map_or(usize::MAX, |b| b.len());
                self.on_vertex(len, v, net);
            }
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

    /// One tick: rebroadcast this node's uncertified proposals (T_RETRY is one
    /// tick), then return the round PR-2 and PR-3 allow this node to propose
    /// now, if any. The caller gathers a payload only then, and calls
    /// `propose`.
    pub fn tick(&mut self, net: &dyn ConsensusNet) -> Option<Slot> {
        self.tick += 1;
        if self.halted.is_some() {
            return None;
        }
        for round in self.collectors.keys() {
            if let Some(v) = self.own.get(round) {
                net.broadcast(Msg::Vertex(v.clone()));
            }
        }
        self.observe_floor(net);
        self.finish_call(net);
        self.fetch(net);
        // EP-3: after its boundary block, epoch E proposes nothing more.
        if !self.may_sign() || self.closing_round.is_some() {
            return None;
        }
        let owed = self.anchor_owed();
        let round = owed.unwrap_or_else(|| self.current_round());
        if self.own.contains_key(&round) {
            return None;
        }
        match self.storage.get(&self.proposed_key(round)) {
            Ok(None) => {}
            _ => return None,
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
            let staged = staging::stage_in(&view, &v, Role::SelfAttested, None, budget)
                .map_err(storage_err)?;
            if matches!(staged, StageOutcome::EvidenceOnly(_)) {
                return Err(storage_err("the node's own body was not staged"));
            }
            view.put(&guard, &v.hash).map_err(storage_err)?;
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
