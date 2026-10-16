//! G1 S6: retrieval (RE-1..RE-5 of `docs/G1_CONSENSUS_CONTRACT.md`). Push
//! delivery is never relied upon: every certified body and every
//! certificate this node lacks becomes a want, asked of those who must hold
//! it, retried with backoff, and retired only when satisfied (an `unknown`
//! answer never retires a want). The serving side reads only.
//!
//! The transport is the engine's `send`: a request goes to one target and the
//! answer comes back to `from`. Until sessions carry an authenticated identity
//! (G4), a request is signed by its sender's committee key (the contract's
//! interim), so RE-6's per-member budget is keyed on an identity a flood
//! cannot forge or replay.

use super::*;

/// RE-3: digests per `VERTEX_REQ`.
pub const MAX_REQ_DIGESTS: usize = 32;
/// Rounds `want_gap` wants at once, from one past the highest round held.
const MAX_GAP_ROUNDS: u64 = 256;
/// Slots per `CERT_REQ`.
pub const MAX_REQ_SLOTS: usize = 64;
/// RE-5: bytes of bodies per answer. The whole answer (bodies, `unknown`
/// and the `Msg::Resp` envelope, at most `RESP_ENVELOPE_BYTES`) fits the
/// node's pre-parse bound `v4::MAX_WIRE_BYTES`, and one maximal body always
/// fits (final review HIGH: answers of 900 KiB were dropped unparsed by
/// every node, so a near-maximal body could never be pulled).
pub const MAX_RESP_BYTES: usize = MAX_WIRE_BYTES - RESP_ENVELOPE_BYTES;
/// The `Msg::Resp` envelope and a full `unknown` list.
pub const RESP_ENVELOPE_BYTES: usize = 4 * 1024;
/// Requests this node sends per tick in all (client side): a far-behind node
/// paces its fetch instead of bursting every due want at once.
pub const CLIENT_REQS_PER_TICK: usize = 8;
/// RE-6: a member's request numbers are accepted once each, in any order,
/// within this distance of the highest seen (transports reorder).
pub const SEQ_WINDOW: u64 = 1024;
/// RE-3: `T_FETCH` doubles up to this many ticks.
pub const T_FETCH_MAX: u64 = 8;
/// RE-6: requests served per committee member per tick (its reservation).
pub const MEMBER_REQS_PER_TICK: u32 = 4;
/// RE-6: requests served per tick to everyone outside the committee, together.
pub const RESIDUAL_REQS_PER_TICK: u32 = 2;
/// B191: the body bytes a member's answers carry per tick (outsiders', all
/// together, as much): one maximal answer (a choice). Each of a member's
/// four requests a tick could take 768 KiB of bodies, read and serialized
/// under the consensus lock and uploaded, at about 2 KB to the asker.
pub const RESP_BYTES_PER_TICK: usize = MAX_RESP_BYTES;
/// The signing domain of a pull request.
pub const PULL_DOMAIN: &[u8] = b"AINCORE_V4_PULL_V1";
/// Request sequence numbers are reserved in blocks this size (`next_seq`).
const SEQ_BLOCK: u64 = 1024;

/// B125: the lowest request number a node starts at, from its clock: 2^30 a
/// second, far more than a node sends, so a member whose database was lost
/// (RC-3: it abstains, then resumes with its key) starts above every number
/// it used before, which servers remember (`SeqWindow`) until they restart.
pub(crate) fn seq_floor(now_secs: u64) -> u64 {
    now_secs.saturating_mul(1 << 30)
}
const SEQ_KEY: &str = "consensus:pull_seq";
/// B51: certificates answers may bring for one slot before this node asks
/// for it again (a choice: the requests of a few ticks in flight at once).
pub const MAX_ANSWERS_PER_SLOT: u8 = 4;
/// B250: the members whose answers a wanted slot still takes: the last this
/// many asked (a choice: an answer later than four more asks of its slot is
/// dropped, and the slot asked again).
pub const MAX_ASKED_PER_SLOT: usize = 4;
/// RE-1 (d): ticks without a new certificate before this node asks everyone
/// for the certificates of its current and previous rounds.
pub const STALL_TICKS: u64 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// `VERTEX_REQ`: staged bodies by digest.
    Vertices(Vec<String>),
    /// `CERT_REQ`: certificates by (round, author) of one epoch (the active
    /// one, or the one just closed while a lagging node finishes it).
    Certs {
        epoch: u64,
        slots: Vec<(u64, String)>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Vertices {
        bodies: Vec<Vertex>,
        unknown: Vec<String>,
    },
    Certs {
        certs: Vec<VertexCertificate>,
        unknown: Vec<(u64, String)>,
    },
}

/// A request signed by its sender: `seq` increases strictly per sender, so a
/// copy cannot be replayed against the sender's budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRequest {
    pub from: String,
    pub to: String,
    pub seq: u64,
    pub req: Request,
    pub signature: String,
}

impl SignedRequest {
    /// `PULL_DOMAIN ‖ put(chain) ‖ put(genesis) ‖ put(from) ‖ put(to) ‖ seq ‖ BCS(req)`.
    pub fn signing_bytes(&self, chain_id: &str, genesis_identity: &str) -> Vec<u8> {
        let mut out = PULL_DOMAIN.to_vec();
        for field in [chain_id, genesis_identity, &self.from, &self.to] {
            out.extend_from_slice(&(field.len() as u64).to_be_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&bcs::to_bytes(&self.req).expect("a request is BCS-serializable"));
        out
    }

    pub fn sign(
        chain_id: &str,
        genesis_identity: &str,
        key: &[u8; 32],
        from: &str,
        to: &str,
        seq: u64,
        req: Request,
    ) -> Self {
        use crypto::Signer;
        let mut signed = Self {
            from: from.to_string(),
            to: to.to_string(),
            seq,
            req,
            signature: String::new(),
        };
        let bytes = signed.signing_bytes(chain_id, genesis_identity);
        signed.signature = hex::encode(crypto::SigningKey::from_bytes(key).sign(&bytes).to_bytes());
        signed
    }

    fn verifies(&self, chain_id: &str, genesis_identity: &str, public_key_hex: &str) -> bool {
        let (Ok(pk), Ok(sig)) = (hex::decode(public_key_hex), hex::decode(&self.signature)) else {
            return false;
        };
        crypto::verify_signature(&pk, &self.signing_bytes(chain_id, genesis_identity), &sig)
            .unwrap_or(false)
    }
}

/// RE-6's accounting on the serving side, reset every tick.
#[derive(Debug, Default)]
pub(crate) struct Budget {
    tick: u64,
    /// Per member: the request numbers seen, and requests served this tick.
    members: HashMap<String, (SeqWindow, u32)>,
    residual: u32,
    /// B191: body bytes served this tick, per member (`None`: outsiders).
    bytes: HashMap<Option<String>, usize>,
}

impl Budget {
    /// B191: the body bytes `who` (`None`: outsiders, together) may still
    /// be sent this tick.
    pub(crate) fn bytes_left(&self, who: &Option<String>) -> usize {
        RESP_BYTES_PER_TICK.saturating_sub(self.bytes.get(who).copied().unwrap_or(0))
    }

    pub(crate) fn spend_bytes(&mut self, who: Option<String>, n: usize) {
        let used = self.bytes.entry(who).or_default();
        *used = used.saturating_add(n);
    }
}

/// Anti-replay for one member's signed requests: each `seq` is accepted once,
/// in any order, if it is within `SEQ_WINDOW` of the highest seen (a single
/// high-water mark dropped every request a transport reordered, and a node
/// behind never caught up; final review HIGH).
#[derive(Debug, Default)]
pub(crate) struct SeqWindow {
    high: u64,
    seen: std::collections::BTreeSet<u64>,
}

impl SeqWindow {
    fn admit(&mut self, seq: u64) -> bool {
        if seq == 0 || seq.saturating_add(SEQ_WINDOW) <= self.high || !self.seen.insert(seq) {
            return false;
        }
        self.high = self.high.max(seq);
        let floor = self.high.saturating_sub(SEQ_WINDOW);
        while self.seen.first().is_some_and(|s| *s <= floor) {
            self.seen.pop_first();
        }
        true
    }
}

/// One outstanding want: who to ask, in rotation, and when next.
#[derive(Debug, Clone)]
pub struct Want {
    /// The round of what is wanted: at or below g, it retires (RE-4).
    pub(super) round: u64,
    targets: Arc<[String]>,
    next: usize,
    due: u64,
    backoff: u64,
}

impl Want {
    /// `start` spreads the rotation: wants made in one tick do not all ask
    /// the same peer first.
    pub(super) fn new(round: u64, targets: Arc<[String]>, start: usize, now: u64) -> Self {
        Self {
            round,
            targets,
            next: start,
            due: now,
            backoff: 1,
        }
    }

    /// The target `take_turn` would ask now, without taking the turn.
    fn peek(&self, now: u64) -> Option<&str> {
        if self.due > now || self.targets.is_empty() {
            return None;
        }
        Some(&self.targets[self.next % self.targets.len()])
    }

    /// The target to ask now, advancing the rotation and the backoff.
    fn take_turn(&mut self, now: u64) -> Option<String> {
        if self.due > now || self.targets.is_empty() {
            return None;
        }
        let target = self.targets[self.next % self.targets.len()].clone();
        self.next += 1;
        self.due = now + self.backoff;
        self.backoff = (self.backoff * 2).min(T_FETCH_MAX);
        Some(target)
    }
}

/// A rotation start derived from what is wanted.
fn spread(key: &str) -> usize {
    let digest = crypto::hash(key.as_bytes());
    usize::from(digest[0]) | (usize::from(digest[1]) << 8)
}

impl Engine {
    /// RE-2: a body is asked of its certificate's signers, never of this node.
    pub(super) fn want_body(&mut self, cert: &VertexCertificate) {
        if self.body_wants.contains_key(&cert.body.digest) {
            return;
        }
        let signers: Vec<String> = self
            .cfg
            .committee
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                cert.signer_bitmap
                    .get(i / 8)
                    .is_some_and(|b| b & (1 << (i % 8)) != 0)
            })
            .map(|(_, m)| m.address.clone())
            .filter(|a| *a != self.cfg.address)
            .collect();
        let start = spread(&cert.body.digest);
        self.body_wants.insert(
            cert.body.digest.clone(),
            Want::new(cert.body.round, signers.into(), start, self.tick),
        );
    }

    /// RE-2: a certificate is asked of every member.
    pub(super) fn want_cert(&mut self, round: u64, author: &str) {
        let slot = (round, author.to_string());
        if self.certs.contains_key(&slot) || self.cert_wants.contains_key(&slot) {
            return;
        }
        // One shared peer list per committee (a per-want copy made one Ahead
        // vertex cost 257·n·(n−1) strings; final review MEDIUM).
        if self.peer_list.as_ref().is_none_or(|(hash, _)| *hash != self.committee_hash) {
            let peers: Vec<String> = self
                .cfg
                .committee
                .iter()
                .map(|m| m.address.clone())
                .filter(|a| *a != self.cfg.address)
                .collect();
            self.peer_list = Some((self.committee_hash.clone(), peers.into()));
        }
        let peers = Arc::clone(&self.peer_list.as_ref().expect("just set").1);
        let start = spread(&format!("{round}:{author}"));
        self.cert_wants
            .insert(slot, Want::new(round, peers, start, self.tick));
    }

    /// One fetch step: retire what is satisfied, then ask for what is due.
    pub(super) fn fetch(&mut self, net: &dyn ConsensusNet) {
        let now = self.tick;
        // RE-1 (d): no certificate for a while, so this node may be below the
        // round quorum without knowing what it misses.
        if now >= self.last_cert_tick + STALL_TICKS {
            // B300: never below g: once GC forgot every certificate held,
            // `current_round` fell back to the epoch's first round, and the
            // rounds asked for were deleted everywhere.
            let round = self.current_round().max(self.gc_floor() + 1);
            let authors: Vec<String> = self.stakes.iter().map(|(a, _)| a.clone()).collect();
            for r in [round.saturating_sub(1), round] {
                if r >= self.first_round {
                    for a in &authors {
                        self.want_cert(r, a);
                    }
                }
            }
            self.last_cert_tick = now;
        }
        // B300: certificates of a quorum held above the rounds this node
        // holds bodies for prove the rounds between exist: the whole gap is
        // wanted, window by window, whatever the lead. A frontier vertex past
        // the lead staged on its carried certificates, RE-1 (d) then asked
        // only for the top two rounds, and their bodies, past the lead on
        // parents not certified here, were dropped: a member coming back
        // never fetched what a block without its QC needs, and with f
        // members withholding votes no QC formed again (B283 assumed the
        // newest vertex came within the lead).
        let round = self.current_round();
        if round > self.gap_bounds().0 + 1 {
            self.want_gap(round - 1);
        }
        // RE-4: a want retires only when satisfied.
        let staged: HashSet<String> = {
            let dag = lock(&self.dag);
            self.body_wants
                .keys()
                .filter(|d| dag.contains_key(*d))
                .cloned()
                .collect()
        };
        self.body_wants.retain(|d, _| !staged.contains(d));
        let certs = &self.certs;
        self.cert_wants.retain(|slot, _| !certs.contains_key(slot));

        self.send_due(net);
    }

    /// Ask for every want that is due, in batches: never more than a batch
    /// per request, and never a turn used without being sent.
    pub(super) fn send_due(&mut self, net: &dyn ConsensusNet) {
        let now = self.tick;
        if self.sent.0 != now {
            self.sent = (now, 0);
        }
        // At most `CLIENT_REQS_PER_TICK` requests this tick. A want is taken
        // only if it joins a batch already open for its target, or a new
        // request is still allowed; otherwise it stays due for the next tick.
        let mut requests_left = CLIENT_REQS_PER_TICK.saturating_sub(self.sent.1);
        // B318: bodies take at most half the requests while a certificate
        // is due. Bodies came first and took every request: a member coming
        // back whose due body wants named eight targets (f members minted
        // certificates for their unused slots past its lead) asked for no
        // certificate again. B344: a body past this node's lead is asked
        // for like any other: after a long run of skipped anchors, the
        // payload-free bodies past the lead are what a member coming back
        // needs to decide the block waiting on its vote (B318 skipped them,
        // and with f members withholding votes no QC formed again). One
        // with a payload is dropped on arrival before any check, and its
        // want backs off to `T_FETCH_MAX`.
        let certs_due = self.cert_wants.values().any(|w| w.peek(now).is_some());
        let mut body_requests = if certs_due {
            requests_left / 2
        } else {
            requests_left
        };
        let mut bodies: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (digest, want) in self.body_wants.iter_mut() {
            let Some(target) = want.peek(now) else {
                continue;
            };
            // A body already received and waiting on its parents' certificates
            // is not asked for again. B257: asked of due wants only.
            if self.pending.contains(digest) {
                continue;
            }
            let open = bodies.get(target).map_or(0, Vec::len);
            if open.is_multiple_of(MAX_REQ_DIGESTS) {
                if body_requests == 0 {
                    continue;
                }
                body_requests -= 1;
                requests_left -= 1;
            }
            let target = want.take_turn(now).expect("peeked");
            bodies.entry(target).or_default().push(digest.clone());
        }
        let mut slots: BTreeMap<String, Vec<(u64, String)>> = BTreeMap::new();
        for (slot, want) in self.cert_wants.iter_mut() {
            let Some(target) = want.peek(now) else {
                continue;
            };
            let open = slots.get(target).map_or(0, Vec::len);
            if open.is_multiple_of(MAX_REQ_SLOTS) {
                if requests_left == 0 {
                    continue;
                }
                requests_left -= 1;
            }
            let target = want.take_turn(now).expect("peeked");
            slots.entry(target).or_default().push(slot.clone());
        }
        for (target, digests) in bodies {
            for batch in digests.chunks(MAX_REQ_DIGESTS) {
                self.request(&target, Request::Vertices(batch.to_vec()), net);
            }
        }
        for (target, slots) in slots {
            for batch in slots.chunks(MAX_REQ_SLOTS) {
                // B51: each request lets one answer bring one certificate
                // per slot asked (at most `MAX_ANSWERS_PER_SLOT` owed). B248:
                // from the member asked. B250: of the last
                // `MAX_ASKED_PER_SLOT` members asked only: kept per member,
                // the map grew to every member asked for every slot of a
                // stuck node's gap (n times its wants).
                for slot in batch {
                    let asked = self.cert_answers.entry(slot.clone()).or_default();
                    match asked.iter_mut().find(|(member, _)| *member == target) {
                        Some((_, owed)) => {
                            *owed = owed.saturating_add(1).min(MAX_ANSWERS_PER_SLOT);
                        }
                        None => {
                            if asked.len() >= MAX_ASKED_PER_SLOT {
                                asked.remove(0);
                            }
                            asked.push((target.clone(), 1));
                        }
                    }
                }
                let req = Request::Certs {
                    epoch: self.epoch,
                    slots: batch.to_vec(),
                };
                self.request(&target, req, net);
            }
        }
        let wants = &self.cert_wants;
        self.cert_answers.retain(|slot, _| wants.contains_key(slot));
    }

    /// `want_gap`'s first round (one past the highest round held, or the
    /// floor), and the round through which it wants nothing more: what it
    /// wanted already, or `u64::MAX` once that reaches `MAX_GAP_ROUNDS`.
    fn gap_bounds(&self) -> (u64, u64) {
        let top = lock(&self.round_index)
            .keys()
            .max()
            .copied()
            .unwrap_or(0)
            .max(self.gc_floor());
        let from = top + 1;
        let wanted = self.gap_high.max(from);
        let wanted_to = if from + MAX_GAP_ROUNDS <= wanted {
            u64::MAX
        } else {
            wanted
        };
        (from, wanted_to)
    }

    /// B171: the round through which `want_gap` wants nothing new (an
    /// `Ahead` vertex at a round no higher than one past it shows nothing).
    pub(super) fn gap_wanted_to(&self) -> u64 {
        self.gap_bounds().1
    }

    /// A node far behind learns what it misses one level at a time through
    /// PENDING, which can be slower than the chain grows. So when a vertex
    /// waits on certificates at `upto` far above O_E, the certificates of
    /// every author for the whole gap are wanted at once (bounded), and their
    /// bodies follow through RE-1 (a).
    pub(super) fn want_gap(&mut self, upto: u64) {
        let (from, wanted_to) = self.gap_bounds();
        let upto = upto.min(from + MAX_GAP_ROUNDS);
        if upto <= wanted_to {
            return;
        }
        let authors: Vec<String> = self.stakes.iter().map(|(a, _)| a.clone()).collect();
        for r in from.max(self.gap_high + 1)..=upto {
            for a in &authors {
                self.want_cert(r, a);
            }
        }
        self.gap_high = upto;
    }

    /// A strictly increasing request number, across restarts: numbers are
    /// reserved durably in blocks, and a restart starts past the last block
    /// and past the clock (`seq_floor`), so a member that lost its database
    /// still starts above every number it used (B125).
    pub(super) fn next_seq(&mut self) -> u64 {
        if self.pull_seq >= self.pull_seq_reserved {
            let reserve = self.pull_seq + SEQ_BLOCK;
            if self.storage.put(SEQ_KEY, &reserve.to_string()).is_err() {
                return self.pull_seq;
            }
            self.pull_seq_reserved = reserve;
        }
        self.pull_seq += 1;
        self.pull_seq
    }

    /// Where a reopened node's request numbers start: past its last durable
    /// reservation and past `seq_floor(now_secs)`.
    pub(super) fn load_seq(storage: &StateDB, now_secs: u64) -> u64 {
        storage
            .get(SEQ_KEY)
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
            .max(seq_floor(now_secs))
    }

    fn request(&mut self, target: &str, req: Request, net: &dyn ConsensusNet) {
        if self.sent.0 != self.tick {
            self.sent = (self.tick, 0);
        }
        self.sent.1 += 1;
        let seq = self.next_seq();
        let signed = SignedRequest::sign(
            &self.cfg.chain_id,
            &self.cfg.genesis_identity,
            &self.cfg.node_key,
            &self.cfg.address,
            target,
            seq,
            req,
        );
        net.send(target, Msg::Req(signed));
    }

    /// RE-5 and RE-6: answer a request addressed to this node, within the
    /// sender's budget. A member is known by its signature and gets its own
    /// reservation; a request claiming a member without its signature, or
    /// replaying an old number, is dropped; everyone else shares a residual.
    pub(super) fn on_request(&mut self, signed: SignedRequest, net: &dyn ConsensusNet) {
        if signed.to != self.cfg.address {
            return;
        }
        if self.budget.tick != self.tick {
            self.budget.tick = self.tick;
            self.budget.residual = 0;
            self.budget.bytes.clear();
            for (_, used) in self.budget.members.values_mut() {
                *used = 0;
            }
        }
        let member = self
            .cfg
            .committee
            .iter()
            .find(|m| m.address == signed.from)
            .map(|m| m.ed25519_public_key.clone());
        let is_member = member.is_some();
        match member {
            Some(pk) => {
                // B224: charged (B51): a member signs its own requests, and
                // no one relays them.
                if !signed.verifies(&self.cfg.chain_id, &self.cfg.genesis_identity, &pk) {
                    crate::work::note_failed_check();
                    return;
                }
                let (window, used) = self.budget.members.entry(signed.from.clone()).or_default();
                if !window.admit(signed.seq) {
                    return;
                }
                if *used >= MEMBER_REQS_PER_TICK {
                    return;
                }
                *used += 1;
            }
            None => {
                if self.budget.residual >= RESIDUAL_REQS_PER_TICK {
                    return;
                }
                self.budget.residual += 1;
            }
        }
        // B191: within its bytes this tick.
        let who = is_member.then(|| signed.from.clone());
        let left = self.budget.bytes_left(&who);
        if left == 0 {
            return;
        }
        let (resp, bytes) = self.serve_within(&signed.req, left);
        self.budget.spend_bytes(who, bytes);
        net.send(
            &signed.from,
            Msg::Resp {
                to: signed.from.clone(),
                resp,
            },
        );
    }

    /// RE-5: read-only answers. Bodies are the staged canonical bodies; a
    /// digest not held, or over the byte budget, is `unknown`.
    pub fn serve(&self, req: &Request) -> Response {
        self.serve_within(req, MAX_RESP_BYTES).0
    }

    /// `serve` with at most `cap` bytes of bodies (and `MAX_RESP_BYTES`), and
    /// the body bytes it sent (B191).
    pub fn serve_within(&self, req: &Request, cap: usize) -> (Response, usize) {
        let cap = cap.min(MAX_RESP_BYTES);
        match req {
            Request::Vertices(digests) => {
                let dag = lock(&self.dag);
                let closed = self.closed.as_ref().map(|c| &c.bodies);
                let (mut bodies, mut unknown, mut bytes) = (Vec::new(), Vec::new(), 0usize);
                // B110: each digest served once, and nothing serialized once
                // a held body did not fit (a member asking one 768 KiB body 32
                // times a request had it serialized 32 times under the lock):
                // at most the bodies sent and one more are measured.
                let mut asked = std::collections::HashSet::new();
                let mut full = false;
                for d in digests.iter().take(MAX_REQ_DIGESTS) {
                    if !asked.insert(d) {
                        continue;
                    }
                    if full {
                        unknown.push(d.clone());
                        continue;
                    }
                    let held = dag.get(d).or_else(|| closed.and_then(|c| c.get(d)));
                    let size = held
                        .and_then(|v| serde_json::to_string(v).ok())
                        .map(|j| j.len());
                    match (held, size) {
                        (Some(v), Some(n)) if bytes + n <= cap => {
                            bytes += n;
                            bodies.push(v.clone());
                        }
                        (Some(_), Some(_)) => {
                            full = true;
                            unknown.push(d.clone());
                        }
                        _ => unknown.push(d.clone()),
                    }
                }
                (Response::Vertices { bodies, unknown }, bytes)
            }
            Request::Certs { epoch, slots } => {
                // The closed epoch's tail stays servable until the next
                // activation, so a node behind the boundary can finish it.
                let index = if *epoch == self.epoch {
                    Some(&self.certs)
                } else {
                    self.closed
                        .as_ref()
                        .filter(|c| c.epoch == *epoch)
                        .map(|c| &c.certs)
                };
                let (mut certs, mut unknown) = (Vec::new(), Vec::new());
                for slot in slots.iter().take(MAX_REQ_SLOTS) {
                    match index.and_then(|i| i.get(slot)) {
                        Some(c) => certs.push(c.clone()),
                        None => unknown.push(slot.clone()),
                    }
                }
                (Response::Certs { certs, unknown }, 0)
            }
        }
    }

    /// RE-4: a returned body is taken only if it was wanted, and then goes
    /// through the same IN-1 path as a gossiped one (its hash is the digest).
    /// Certificates are verified by CE-2 on ingest. `unknown` changes nothing.
    pub(super) fn on_response(
        &mut self,
        resp: Response,
        source: Option<&str>,
        net: &dyn ConsensusNet,
    ) {
        match resp {
            Response::Vertices { bodies, .. } => {
                for v in bodies {
                    if !self.body_wants.contains_key(&v.hash) {
                        continue;
                    }
                    let len = serde_json::to_string(&v).map_or(usize::MAX, |j| j.len());
                    self.on_vertex(len, v, net);
                }
            }
            Response::Certs { certs, .. } => {
                // Only what this node asked for and does not hold, at most a
                // request's worth: an answer is unauthenticated, and each
                // certificate costs a pairing (final review MEDIUM). B51: and
                // one certificate per request sent for the slot, so junk
                // answers cost at most what this node asked for.
                for c in certs.into_iter().take(MAX_REQ_SLOTS) {
                    let slot = (c.body.round, c.body.author.clone());
                    if !self.cert_wants.contains_key(&slot) || self.certs.contains_key(&slot) {
                        continue;
                    }
                    // B248: a certificate of another epoch than the one
                    // asked (`on_cert` drops it for free) takes no turn, and
                    // a turn is the asked member's: the budget was the
                    // slot's, so any member's unsolicited answers used it up
                    // and the asked member's honest answer was dropped; a
                    // node that missed rounds never got their certificates.
                    // In process (no source) any asked member's turn serves.
                    if c.body.epoch != self.epoch {
                        continue;
                    }
                    let turn = self.cert_answers.get_mut(&slot).and_then(|asked| {
                        asked.iter_mut().find(|(member, owed)| {
                            *owed > 0 && source.is_none_or(|s| member.as_str() == s)
                        })
                    });
                    match turn {
                        Some((_, owed)) => *owed -= 1,
                        None => continue,
                    }
                    self.on_cert(c, net);
                }
            }
        }
        // What this answer revealed is asked for now, not a tick later.
        self.send_due(net);
    }

    /// The digests this node is fetching (tests and diagnostics).
    pub fn wanted_bodies(&self) -> Vec<String> {
        self.body_wants.keys().cloned().collect()
    }
}
