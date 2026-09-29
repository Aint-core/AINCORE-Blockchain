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
use std::sync::Arc;
use storage::{StateDB, StorageError};

/// The single epoch of S5, its first round and its sentinel (EP-1).
pub const EPOCH: u64 = 0;
pub const FIRST_ROUND: u64 = 1;
pub const SENTINEL: &str = "genesis";
/// PR-3: how many ticks a round waits for the previous anchor's leader.
pub const T_LEADER_TICKS: u64 = 2;

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
    /// The staged bodies (canonical form).
    bodies: HashMap<String, Vertex>,
    /// The certificate index: (round, author) → certificate.
    certs: HashMap<(u64, String), VertexCertificate>,
    /// Signed stake of the certificates held per round (PR-1).
    cert_stake: BTreeMap<u64, u128>,
    /// PR-3: the tick at which a quorum of certificates at a round was first held.
    quorum_since: HashMap<u64, u64>,
    /// O_E: round → orderable digests (one per author, OR-2), and their bodies.
    orderable_index: HashMap<u64, Vec<String>>,
    orderable: HashMap<String, Vertex>,
    /// OR-1: a parent digest → the certified children waiting on it.
    waiting: HashMap<String, HashSet<String>>,
    pending: PendingBuffer,
    /// This node's proposals, as broadcast (parent certificates embedded).
    own: BTreeMap<u64, Vertex>,
    /// CE-1 for this node's proposals not yet certified.
    collectors: BTreeMap<u64, CertCollector>,
    ordering: OrderingEngine,
    decided: Vec<CommitInfo>,
    halted: Option<String>,
    tick: u64,
    now_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
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
    pub fn open(
        storage: Arc<StateDB>,
        cfg: Config,
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
        let origin = serde_json::json!({
            "cg": vcert::chain_genesis_tag(&cfg.chain_id, &cfg.genesis_identity),
            "ed25519": ed25519_pk,
            "bls": bls_pk,
        })
        .to_string();
        let held = storage
            .get("consensus:guard_origin")
            .map_err(|e| e.to_string())?;
        let guards_continuous = match held {
            Some(h) => h == origin,
            None if genesis_init => {
                storage
                    .put("consensus:guard_origin", &origin)
                    .map_err(|e| e.to_string())?;
                true
            }
            None => false,
        };
        let cfg = Config { committee, ..cfg };
        let mut engine = Self {
            ordering: OrderingEngine::new_with_storage(Arc::clone(&storage)),
            storage,
            stakes,
            committee_hash,
            ed25519_pk,
            can_sign,
            guards_continuous,
            bodies: HashMap::new(),
            certs: HashMap::new(),
            cert_stake: BTreeMap::new(),
            quorum_since: HashMap::new(),
            orderable_index: HashMap::new(),
            orderable: HashMap::new(),
            waiting: HashMap::new(),
            pending: PendingBuffer::default(),
            own: BTreeMap::new(),
            collectors: BTreeMap::new(),
            decided: Vec::new(),
            halted: None,
            tick: 0,
            now_secs,
            cfg,
        };
        engine.boot()?;
        Ok(engine)
    }

    /// RC-1 steps 2 to 6.
    fn boot(&mut self) -> Result<(), String> {
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
        for (_, v) in loaded.bodies {
            self.bodies.insert(v.hash.clone(), v);
        }
        let mut certs = loaded.certs;
        certs.sort_by_key(|c| c.body.round);
        for cert in certs {
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
            let Some(body) = self.bodies.get(&digest).cloned() else {
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
        self.decide();
        Ok(())
    }

    fn record(&self) -> EpochRecord<'_> {
        EpochRecord {
            epoch: EPOCH,
            first_round: FIRST_ROUND,
            closing_round: None,
            sentinel: SENTINEL,
            committee: &self.cfg.committee,
        }
    }

    /// g. Always 0 until GC lands (S7).
    fn gc_floor(&self) -> u64 {
        0
    }

    fn attest_body(&self, round: u64, author: &str, digest: &str) -> AttestBody {
        AttestBody {
            chain_id: self.cfg.chain_id.clone(),
            genesis_identity: self.cfg.genesis_identity.clone(),
            epoch: EPOCH,
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
            EPOCH
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
        match msg {
            Msg::Vertex(v) => self.on_vertex(raw_len, v, net),
            Msg::Attest(a) => self.on_attestation(a, net),
            Msg::Cert(c) => self.on_cert(c, net),
        }
    }

    /// IN-1, then ST and AT for a vertex that stages.
    pub fn on_vertex(&mut self, raw_len: usize, v: Vertex, net: &dyn ConsensusNet) {
        let verdict = {
            let ctx = Context {
                chain_id: &self.cfg.chain_id,
                genesis_identity: &self.cfg.genesis_identity,
                active: self.record(),
                previous: None,
                next: None,
                now_secs: (self.now_secs)(),
                gc_floor: self.gc_floor(),
                cursor: self.ordering.next_anchor_round,
            };
            let certs = &self.certs;
            ingress_v4::v4_verdict(raw_len, &v, &ctx, |r: &ParentRef| {
                certs
                    .get(&(r.round, r.author.clone()))
                    .filter(|c| c.body.digest == r.digest)
                    .map(|c| c.compact())
            })
        };
        match verdict {
            Verdict::Stage => self.stage_and_attest(v, net),
            Verdict::PendingCert(_) | Verdict::PendingEpoch => {
                self.pending.push(v);
            }
            Verdict::Invalid(_) | Verdict::Drop(_) | Verdict::Stale => {}
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
        let sign = self.may_sign();
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
            Ok((attestation, staged))
        });
        let Ok((attestation, staged)) = result else {
            return;
        };
        match staged {
            StageOutcome::EvidenceOnly(_) => return,
            StageOutcome::Evicted(gone) => {
                self.bodies.remove(&gone);
            }
            StageOutcome::Staged | StageOutcome::Held => {}
        }
        self.bodies.insert(v.hash.clone(), canonical(&v));
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
        if att.body.author != self.cfg.address || att.body.epoch != EPOCH {
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
        if vcert::verify_vertex_cert(
            &cert,
            &self.cfg.committee,
            &self.cfg.chain_id,
            &self.cfg.genesis_identity,
            EPOCH,
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
        self.certs.insert(key, cert);
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
                let alarm = format!(
                    "alarm:vcert_conflict:{EPOCH:020}:{:020}:{}",
                    cert.body.round, cert.body.author
                );
                let evidence = serde_json::json!({ "held": held, "other": cert }).to_string();
                let _ = self.storage.put(&alarm, &evidence);
                self.halted = Some(format!(
                    "two certificates for round {} author {}",
                    cert.body.round, cert.body.author
                ));
            }
            return;
        }
        let row = format!(
            "consensus:vcert:v1:{EPOCH:020}:{:020}:{}",
            cert.body.round, cert.body.author
        );
        if let Ok(json) = serde_json::to_string(&cert) {
            // May be unsynced: a certificate can be obtained again (RC-2).
            let _ = self.storage.put(&row, &json);
        }
        let digest = cert.body.digest.clone();
        self.index_cert(cert);
        // A held body of the certified digest takes the certified role.
        if let Some(v) = self.bodies.get(&digest).cloned() {
            let _ = staging::stage(
                &self.storage,
                &v,
                Role::Staged,
                Some(&digest),
                self.cfg.b_auth,
            );
        }
        self.try_orderable(digest);
        // Vertices waiting on a parent certificate are re-evaluated.
        if !self.pending.is_empty() {
            for v in self.pending.take_all() {
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
        let mut work = vec![digest];
        let mut inserted = false;
        while let Some(d) = work.pop() {
            if self.orderable.contains_key(&d) {
                continue;
            }
            let Some(v) = self.bodies.get(&d) else {
                continue;
            };
            let certified = self
                .certs
                .get(&(v.round, v.author.clone()))
                .is_some_and(|c| c.body.digest == d);
            if !certified {
                continue;
            }
            let missing: Vec<String> = if v.round == FIRST_ROUND {
                Vec::new()
            } else {
                v.parents
                    .iter()
                    .filter(|p| !self.orderable.contains_key(*p))
                    .cloned()
                    .collect()
            };
            if !missing.is_empty() {
                for p in missing {
                    self.waiting.entry(p).or_default().insert(d.clone());
                }
                continue;
            }
            let v = v.clone();
            // OR-2: one digest per author per round. CE-3 keeps one
            // certificate per slot, so this cannot fire; it is checked anyway.
            let row = self.orderable_index.entry(v.round).or_default();
            if row
                .iter()
                .any(|h| self.orderable.get(h).is_some_and(|u| u.author == v.author))
            {
                self.halted = Some(format!(
                    "OR-2: author {} twice at round {}",
                    v.author, v.round
                ));
                return;
            }
            row.push(d.clone());
            self.orderable.insert(d.clone(), v);
            inserted = true;
            if let Some(children) = self.waiting.remove(&d) {
                work.extend(children);
            }
        }
        if inserted {
            self.decide();
        }
    }

    // ----------------------------------------------------------- decision (DE)

    /// DE over O_E with the frozen committee, one anchor per call until none
    /// is decidable. Halted ordering decides nothing.
    fn decide(&mut self) {
        while self.halted.is_none() {
            let out =
                self.ordering
                    .try_commit(0, &self.orderable, &self.orderable_index, &self.stakes);
            if out.is_empty() {
                break;
            }
            self.decided.extend(out);
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
        top.map_or(FIRST_ROUND, |r| (r + 1).max(FIRST_ROUND))
    }

    /// One tick: rebroadcast this node's uncertified proposals (T_RETRY is one
    /// tick), then propose the current round if PR-2 and PR-3 allow. `payload`
    /// is what this node would carry; above the lead it proposes without it.
    pub fn on_tick(&mut self, payload: Vec<String>, net: &dyn ConsensusNet) {
        self.tick += 1;
        if self.halted.is_some() {
            return;
        }
        for round in self.collectors.keys() {
            if let Some(v) = self.own.get(round) {
                net.broadcast(Msg::Vertex(v.clone()));
            }
        }
        if !self.may_sign() {
            return;
        }
        let round = self.current_round();
        if self.own.contains_key(&round) {
            return;
        }
        match self.storage.get(&self.proposed_key(round)) {
            Ok(None) => {}
            _ => return,
        }
        let prev = round - 1;
        if round > FIRST_ROUND && prev >= 2 && prev.is_multiple_of(2) {
            let leader = OrderingEngine::leader_for_round(prev, &self.stakes, 0);
            let since = self.quorum_since.get(&prev).copied().unwrap_or(self.tick);
            if !self.certs.contains_key(&(prev, leader)) && self.tick < since + T_LEADER_TICKS {
                return;
            }
        }
        let beyond_lead = round
            > self
                .ordering
                .next_anchor_round
                .saturating_add(ingress_v4::LEAD);
        let payload = if beyond_lead { Vec::new() } else { payload };
        self.propose(round, payload, net);
    }

    /// PR-4: parents are all certificates held for the previous round, one per
    /// author, sorted by author, each carried with its certificate. One
    /// transaction stages the body, writes the producer guard and the node's
    /// own attestation guard; only then is the vertex broadcast.
    fn propose(&mut self, round: u64, payload: Vec<String>, net: &dyn ConsensusNet) {
        let (parents, parent_refs) = if round == FIRST_ROUND {
            (vec![SENTINEL.to_string()], Vec::new())
        } else {
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
        };
        let mut v = Vertex {
            epoch: EPOCH,
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
            return;
        };
        self.bodies.insert(v.hash.clone(), canonical(&v));
        if let Ok(collector) = CertCollector::new(body, &self.cfg.committee) {
            self.collectors.insert(round, collector);
        }
        self.own.insert(round, v.clone());
        net.broadcast(Msg::Vertex(v));
        self.on_attestation(own_attestation, net);
    }

    // ----------------------------------------------------------------- reads

    /// Decisions made since the last call, in order.
    pub fn take_decided(&mut self) -> Vec<CommitInfo> {
        std::mem::take(&mut self.decided)
    }

    pub fn halted(&self) -> Option<&str> {
        self.halted.as_deref()
    }

    pub fn is_staged(&self, digest: &str) -> bool {
        self.bodies.contains_key(digest)
    }

    pub fn is_orderable(&self, digest: &str) -> bool {
        self.orderable.contains_key(digest)
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

    pub fn finality_digest(&self) -> &str {
        self.ordering.current_finality_digest()
    }

    pub fn cursor(&self) -> u64 {
        self.ordering.next_anchor_round
    }
}

#[cfg(test)]
mod tests;
