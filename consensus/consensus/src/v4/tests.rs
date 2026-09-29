//! G1 S5 acceptance (`docs/G1_CONSENSUS_CONTRACT.md`, "Staged implementation
//! plan", S5): four validators on real RocksDB guards over a simulated
//! network. Each witness is paired with the schedule it departs from, so none
//! passes by deciding nothing.

use super::*;
use crate::qc::derive_validator_bls_seed;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

const CHAIN: &str = "AINCORE-S5-TEST";
const GENESIS: &str = "genesis-identity-s5-test";
const NOW: u64 = 1_000_000;

struct Member {
    node_key: [u8; 32],
    info: ValidatorInfo,
}

fn member(seed: u8) -> Member {
    let node_key = [seed; 32];
    let ed = crypto::SigningKey::from_bytes(&node_key)
        .verifying_key()
        .to_bytes();
    let bls = BLSEngine::consensus();
    let bls_seed = derive_validator_bls_seed(&node_key);
    Member {
        node_key,
        info: ValidatorInfo {
            address: crypto::derive_address(&ed).unwrap(),
            stake: 100,
            ed25519_public_key: hex::encode(ed),
            bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
        },
    }
}

#[derive(Clone, Debug)]
enum To {
    All,
    One(String),
}

#[derive(Clone, Debug)]
struct Envelope {
    from: String,
    to: To,
    msg: Msg,
}

type Queue = Rc<RefCell<VecDeque<Envelope>>>;

struct Net {
    from: String,
    q: Queue,
}

impl ConsensusNet for Net {
    fn broadcast(&self, msg: Msg) {
        self.q.borrow_mut().push_back(Envelope {
            from: self.from.clone(),
            to: To::All,
            msg,
        });
    }
    fn send(&self, to: &str, msg: Msg) {
        self.q.borrow_mut().push_back(Envelope {
            from: self.from.clone(),
            to: To::One(to.to_string()),
            msg,
        });
    }
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "aincore-s5-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        Self(path)
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A decision as every node must see it: (anchor round, anchor digest,
/// sequence, finality digest).
type Decision = (u64, String, Vec<String>, String);

struct Cluster {
    members: Vec<Member>,
    committee: Vec<ValidatorInfo>,
    dirs: Vec<TempDb>,
    engines: Vec<Option<Engine>>,
    decisions: Vec<Vec<Decision>>,
    q: Queue,
    /// Envelopes held back by a delivery rule, released later.
    held: Vec<Envelope>,
    /// Blocks per epoch (0: one epoch forever).
    epoch_interval: u64,
}

impl Cluster {
    /// `n` validators, plus `observers` nodes outside the committee.
    fn new(tag: &str, n: u8, observers: u8) -> Self {
        Self::with_epochs(tag, n, observers, 0)
    }

    /// Standalone epochs: every node closes and activates an epoch every
    /// `interval` blocks (decided anchors).
    fn with_epochs(tag: &str, n: u8, observers: u8, interval: u64) -> Self {
        let mut members: Vec<Member> = (1..=n).map(member).collect();
        members.sort_by(|a, b| a.info.address.cmp(&b.info.address));
        let committee: Vec<ValidatorInfo> = members.iter().map(|m| m.info.clone()).collect();
        for seed in 0..observers {
            members.push(member(200 + seed));
        }
        let dirs: Vec<TempDb> = (0..members.len())
            .map(|i| TempDb::new(&format!("{tag}-{i}")))
            .collect();
        let mut cluster = Self {
            decisions: vec![Vec::new(); members.len()],
            engines: (0..members.len()).map(|_| None).collect(),
            members,
            committee,
            dirs,
            q: Rc::new(RefCell::new(VecDeque::new())),
            held: Vec::new(),
            epoch_interval: interval,
        };
        for i in 0..cluster.members.len() {
            cluster.open(i, true);
        }
        cluster
    }

    fn open(&mut self, i: usize, genesis_init: bool) {
        let storage = Arc::new(StateDB::open(self.dirs[i].0.to_str().unwrap()).unwrap());
        let cfg = Config {
            chain_id: CHAIN.into(),
            genesis_identity: GENESIS.into(),
            committee: self.committee.clone(),
            node_key: self.members[i].node_key,
            address: self.members[i].info.address.clone(),
            b_auth: staging::B_AUTH,
            epoch_interval: self.epoch_interval,
        };
        self.engines[i] = Some(Engine::open(storage, cfg, genesis_init, Arc::new(|| NOW)).unwrap());
    }

    /// Close and reopen node `i` on its database (a crash between messages).
    fn reopen(&mut self, i: usize) {
        self.engines[i] = None;
        self.open(i, false);
    }

    fn engine(&self, i: usize) -> &Engine {
        self.engines[i].as_ref().unwrap()
    }

    fn net(&self, i: usize) -> Net {
        Net {
            from: self.members[i].info.address.clone(),
            q: Rc::clone(&self.q),
        }
    }

    fn index_of(&self, address: &str) -> usize {
        self.members
            .iter()
            .position(|m| m.info.address == address)
            .unwrap()
    }

    fn collect(&mut self, i: usize) {
        let out = self.engines[i].as_mut().unwrap().take_decided();
        for c in out {
            self.decisions[i].push((c.anchor_round, c.anchor_hash, c.sequence, c.finality_digest));
        }
    }

    fn tick(&mut self, i: usize) {
        let net = self.net(i);
        self.engines[i].as_mut().unwrap().on_tick(vec![], &net);
        self.collect(i);
    }

    fn tick_all(&mut self) {
        for i in 0..self.members.len() {
            self.tick(i);
        }
    }

    fn receive(&mut self, i: usize, msg: Msg) {
        let len = match &msg {
            Msg::Vertex(v) => serde_json::to_string(v).unwrap().len(),
            _ => 0,
        };
        let net = self.net(i);
        self.engines[i].as_mut().unwrap().on_message(len, msg, &net);
        self.collect(i);
    }

    /// Deliver until the network is quiet. `hold` keeps an envelope back for
    /// one receiver (it is released by `release`).
    fn deliver(&mut self, hold: &dyn Fn(&Envelope, usize) -> bool) {
        loop {
            let Some(env) = self.q.borrow_mut().pop_front() else {
                break;
            };
            let receivers: Vec<usize> = match &env.to {
                To::All => (0..self.members.len())
                    .filter(|&i| self.members[i].info.address != env.from)
                    .collect(),
                To::One(a) => vec![self.index_of(a)],
            };
            for i in receivers {
                if hold(&env, i) {
                    self.held.push(Envelope {
                        from: env.from.clone(),
                        to: To::One(self.members[i].info.address.clone()),
                        msg: env.msg.clone(),
                    });
                } else {
                    self.receive(i, env.msg.clone());
                }
            }
        }
    }

    /// Deliver until quiet, letting `map` drop (None) or rewrite each
    /// envelope for each receiver: a Byzantine relay or server.
    fn deliver_map(&mut self, map: &dyn Fn(&Envelope, usize) -> Option<Msg>) {
        loop {
            let Some(env) = self.q.borrow_mut().pop_front() else {
                break;
            };
            let receivers: Vec<usize> = match &env.to {
                To::All => (0..self.members.len())
                    .filter(|&i| self.members[i].info.address != env.from)
                    .collect(),
                To::One(a) => vec![self.index_of(a)],
            };
            for i in receivers {
                if let Some(msg) = map(&env, i) {
                    self.receive(i, msg);
                }
            }
        }
    }

    fn release(&mut self) {
        let held = std::mem::take(&mut self.held);
        self.q.borrow_mut().extend(held);
    }

    fn run(&mut self, ticks: usize) {
        for _ in 0..ticks {
            self.tick_all();
            self.deliver(&|_, _| false);
        }
    }

    /// Run until `done` holds, at most `ticks` ticks.
    fn run_until(&mut self, ticks: usize, done: impl Fn(&Cluster) -> bool) {
        for _ in 0..ticks {
            if done(self) {
                return;
            }
            self.tick_all();
            self.deliver(&|_, _| false);
        }
    }

    fn validators(&self) -> std::ops::Range<usize> {
        0..self.committee.len()
    }

    fn leader(&self, round: u64) -> usize {
        let stakes: Vec<(String, u64)> = self
            .committee
            .iter()
            .map(|m| (m.address.clone(), m.stake))
            .collect();
        self.index_of(&OrderingEngine::leader_for_round(round, &stakes, 0))
    }

    /// Every node's decisions agree on their common prefix, and none is empty.
    fn assert_agree(&self) {
        self.assert_agree_except(None);
    }

    /// The same, over every node but a Byzantine one, whose own engine was
    /// bypassed and whose state means nothing.
    fn assert_agree_except(&self, byzantine: Option<usize>) {
        let honest: Vec<usize> = (0..self.members.len())
            .filter(|&i| Some(i) != byzantine)
            .collect();
        let longest = honest
            .iter()
            .map(|&i| &self.decisions[i])
            .max_by_key(|d| d.len())
            .unwrap();
        for &i in &honest {
            let d = &self.decisions[i];
            assert!(!d.is_empty(), "node {i} decided nothing");
            assert_eq!(d[..], longest[..d.len()], "node {i} disagrees");
        }
    }

    fn anchor(&self, i: usize, round: u64) -> Option<&Decision> {
        self.decisions[i].iter().find(|d| d.0 == round)
    }
}

/// A second vertex for the same slot as `v`: a different payload, the same
/// parents, signed by the same key.
fn twin_of(v: &Vertex, key: &[u8; 32], tag: &str) -> Vertex {
    let mut w = v.clone();
    w.payload = vec![tag.to_string()];
    w.hash = w.hash_v4_with_domain(CHAIN, GENESIS);
    w.sign_with_ed25519(&crypto::SigningKey::from_bytes(key));
    w
}

#[test]
fn four_honest_validators_certify_every_round_and_agree() {
    let mut c = Cluster::new("honest", 4, 1);
    c.run(12);
    c.assert_agree();
    assert!(c.engine(0).current_round() >= 10);
    assert!(c.anchor(0, 2).is_some(), "anchor 2 is committed directly");
    // The observer decides the same sequence without ever signing.
    let observer = c.members.len() - 1;
    assert_eq!(
        c.engine(observer).own_proposal(1).map(|v| v.hash.clone()),
        None
    );
    assert_eq!(
        c.decisions[observer][..],
        c.decisions[0][..c.decisions[observer].len()]
    );
}

/// Round 2's leader proposes A and hands a twin B to h0 first. h0 attests
/// B; the leader and h1, h2 certify A. Everyone commits 2/A with one sequence
/// and one finality digest, before and after every node reopens; h0 still
/// holds B, and B is never orderable.
#[test]
fn a3c_push_the_certified_twin_commits_and_the_other_stays_staged() {
    let mut c = Cluster::new("a3c", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    let h0 = c.validators().find(|&i| i != byz).unwrap();
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    c.q.borrow_mut().push_front(Envelope {
        from: c.members[byz].info.address.clone(),
        to: To::One(c.members[h0].info.address.clone()),
        msg: Msg::Vertex(b.clone()),
    });
    c.deliver(&|_, _| false);
    for i in c.validators() {
        assert_eq!(c.engine(i).certified(2, &a.author), Some(a.hash.as_str()));
    }
    assert!(
        c.engine(h0).is_staged(&b.hash),
        "h0 holds its attested twin"
    );
    // CE-3: h0's plain copy of A took the certified role (never evictable,
    // off the plain-body budget).
    let row = c
        .engine(h0)
        .storage
        .get(&staging::vslot_key(EPOCH, 2, &a.author))
        .unwrap()
        .unwrap();
    let slot: Vec<staging::SlotEntry> = serde_json::from_str(&row).unwrap();
    let role = |d: &str| slot.iter().find(|e| e.digest == d).map(|e| e.role);
    assert_eq!(role(&a.hash), Some(Role::Certified));
    assert_eq!(role(&b.hash), Some(Role::SelfAttested));
    c.run(6);
    c.assert_agree_except(Some(byz));
    for i in c.validators().filter(|&i| i != byz) {
        let d = c.anchor(i, 2).expect("anchor 2 is decided");
        assert_eq!(d.1, a.hash, "node {i} committed the certified twin");
        assert!(!d.2.contains(&b.hash));
    }
    let before: Vec<String> = c
        .validators()
        .map(|i| c.engine(i).finality_digest().to_string())
        .collect();
    for i in c.validators() {
        c.reopen(i);
    }
    let after: Vec<String> = c
        .validators()
        .map(|i| c.engine(i).finality_digest().to_string())
        .collect();
    assert_eq!(before, after);
    assert!(c.engine(h0).is_staged(&b.hash), "B survives the restart");
    assert!(!c.engine(h0).is_orderable(&b.hash));
    c.run(6);
    c.assert_agree();
}

/// A2c: the equivocating leader of round 2 sends both twins to all three
/// honest validators, in each of the 8 orders, and (being Byzantine) signs
/// and aggregates both. Each honest validator attests only the twin it staged
/// first, so exactly one twin reaches a quorum in every order (2 + 2 > 3
/// honest), and every node commits that twin at round 2.
#[test]
fn a2c_certified_twin_decisions_agree_in_all_eight_delivery_orders() {
    let mut committed = 0;
    for order in 0..8u8 {
        let mut c = Cluster::new(&format!("a2c{order}"), 4, 0);
        c.run(1);
        let byz = c.leader(2);
        c.tick_all();
        let a = c.engine(byz).own_proposal(2).unwrap().clone();
        let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
        // Drop the leader's own broadcast of A; deliver the twins per order.
        c.q.borrow_mut()
            .retain(|e| !matches!(&e.msg, Msg::Vertex(v) if v.hash == a.hash));
        let honest: Vec<usize> = c.validators().filter(|&i| i != byz).collect();
        let mut first_b = Vec::new();
        for (k, &h) in honest.iter().enumerate() {
            let b_first = order & (1 << k) != 0;
            if b_first {
                first_b.push(h);
            }
            let (x, y) = if b_first { (&b, &a) } else { (&a, &b) };
            for v in [x, y] {
                c.q.borrow_mut().push_back(Envelope {
                    from: c.members[byz].info.address.clone(),
                    to: To::One(c.members[h].info.address.clone()),
                    msg: Msg::Vertex(v.clone()),
                });
            }
        }
        c.deliver(&|_, _| false);
        // The leader aggregates B from the honest attestations of B plus its
        // own (its engine already aggregates A).
        if first_b.len() >= 2 {
            let mut signers = vec![byz];
            signers.extend(&first_b);
            let cert_b = forged_cert(&c, 2, &a.author, &b.hash, &signers);
            c.q.borrow_mut().push_back(Envelope {
                from: c.members[byz].info.address.clone(),
                to: To::All,
                msg: Msg::Cert(cert_b),
            });
            c.deliver(&|_, _| false);
        }
        let certified: HashSet<String> = c
            .validators()
            .filter_map(|i| c.engine(i).certified(2, &a.author).map(str::to_string))
            .collect();
        assert_eq!(certified.len(), 1, "order {order}: {certified:?}");
        let expected = if first_b.len() >= 2 { &b.hash } else { &a.hash };
        assert!(certified.contains(expected), "order {order}");
        c.run(8);
        c.assert_agree_except(Some(byz));
        for i in c.validators().filter(|&i| i != byz) {
            assert!(c.engine(i).halted().is_none());
            assert_eq!(
                c.anchor(i, 2).map(|x| &x.1),
                Some(expected),
                "order {order}: node {i} did not commit the certified twin"
            );
        }
        committed += 1;
    }
    assert_eq!(committed, 8);
}

/// Builds a certificate for (round, author, digest) signed by `signers`,
/// bypassing every guard: what colluding keys can produce.
fn forged_cert(
    c: &Cluster,
    round: u64,
    author: &str,
    digest: &str,
    signers: &[usize],
) -> VertexCertificate {
    let body = AttestBody {
        chain_id: CHAIN.into(),
        genesis_identity: GENESIS.into(),
        epoch: EPOCH,
        round,
        author: author.to_string(),
        digest: digest.to_string(),
        committee_hash: qc::validator_set_hash(&c.committee),
    };
    let mut collector = CertCollector::new(body.clone(), &c.committee).unwrap();
    let mut out = None;
    for &s in signers {
        let att = VertexAttestation {
            body: body.clone(),
            signer: c.members[s].info.address.clone(),
            signature: BLSEngine::consensus().sign_raw(
                &body.signing_bytes(),
                &derive_validator_bls_seed(&c.members[s].node_key),
            ),
        };
        if let CollectOutcome::Certified(cert) = collector.add(&att).unwrap() {
            out = Some(*cert);
        }
    }
    out.expect("a quorum of signers")
}

/// The negative control of A2c: with TWO Byzantine validators both twins can
/// be certified. Every node that sees both certificates halts ordering and
/// records the conflict; none commits either twin at round 2.
#[test]
fn v4_cert_conflict_halts_ordering() {
    let mut c = Cluster::new("conflict", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    let byz2 = c.validators().find(|&i| i != byz).unwrap();
    let honest: Vec<usize> = c.validators().filter(|&i| i != byz && i != byz2).collect();
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    let cert_a = forged_cert(&c, 2, &a.author, &a.hash, &[byz, byz2, honest[0]]);
    let cert_b = forged_cert(&c, 2, &a.author, &b.hash, &[byz, byz2, honest[1]]);
    for cert in [cert_a, cert_b] {
        c.q.borrow_mut().push_front(Envelope {
            from: c.members[byz].info.address.clone(),
            to: To::All,
            msg: Msg::Cert(cert),
        });
    }
    // The certificates arrive first: from then on a halted node signs
    // nothing, not even the round-2 vertices still in flight.
    let byz_addr = c.members[byz].info.address.clone();
    let attested = Cell::new(0);
    let count = |e: &Envelope, _: usize| {
        if e.from != byz_addr && matches!(e.msg, Msg::Attest(_)) {
            attested.set(attested.get() + 1);
        }
        false
    };
    c.deliver(&count);
    for _ in 0..6 {
        c.tick_all();
        c.deliver(&count);
    }
    assert_eq!(attested.get(), 0, "a halted node attested");
    for i in c.validators().filter(|&i| i != byz) {
        assert!(c.engine(i).halted().is_some(), "node {i} did not halt");
        let alarm = format!("alarm:vcert_conflict:{EPOCH:020}:{:020}:{}", 2, a.author);
        let db = &c.engine(i).storage;
        assert!(db.get(&alarm).unwrap().is_some(), "node {i}: no alarm row");
        assert!(c.anchor(i, 2).is_none());
    }
}

/// Twin flood: an equivocating leader sends both twins to everyone. The
/// honest producers' next vertices cite one certified digest per author, so
/// they pass the stateless parent gate (C1) and no plan commits the other
/// twin.
#[test]
fn a_twin_flood_leaves_every_next_vertex_citing_one_digest_per_author() {
    let mut c = Cluster::new("flood", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    c.q.borrow_mut().push_front(Envelope {
        from: c.members[byz].info.address.clone(),
        to: To::All,
        msg: Msg::Vertex(b.clone()),
    });
    c.deliver(&|_, _| false);
    c.run(8);
    let stakes: Vec<(String, u64)> = c
        .committee
        .iter()
        .map(|m| (m.address.clone(), m.stake))
        .collect();
    for i in c.validators().filter(|&i| i != byz) {
        let v = c.engine(i).own_proposal(3).expect("round 3 proposed");
        qc::parent_refs_admissible(v, &stakes).unwrap();
        assert!(!v.parents.contains(&b.hash) || !v.parents.contains(&a.hash));
    }
    c.assert_agree_except(Some(byz));
    for i in c.validators().filter(|&i| i != byz) {
        let d = c.anchor(i, 2).map(|x| x.1.clone());
        let certified = c.engine(i).certified(2, &a.author).map(str::to_string);
        assert_eq!(d, certified, "node {i}: the decision is the certified twin");
        assert!(
            c.decisions[i].iter().any(|d| d.0 > 2),
            "node {i} made no progress"
        );
    }
}

/// PR-3, the slow-leader witness: round 2's honest leader is one tick late.
/// The others wait for its certificate before proposing round 3, so anchor 2
/// is still committed directly rather than skipped.
#[test]
fn a_slow_honest_leader_is_still_committed() {
    let mut c = Cluster::new("slow", 4, 0);
    c.run(1);
    let leader = c.leader(2);
    let slow = c.members[leader].info.address.clone();
    let late = move |e: &Envelope, _: usize| {
        e.from == slow && matches!(&e.msg, Msg::Vertex(v) if v.round == 2)
    };
    c.tick_all();
    c.deliver(&late);
    // One tick without the leader's vertex.
    c.tick_all();
    c.deliver(&late);
    for i in c.validators().filter(|&i| i != leader) {
        assert!(
            c.engine(i).own_proposal(3).is_none(),
            "node {i} did not wait"
        );
    }
    c.release();
    c.deliver(&|_, _| false);
    c.run(6);
    c.assert_agree();
    let leader_vertex = c.engine(leader).own_proposal(2).unwrap().hash.clone();
    for i in c.validators() {
        assert_eq!(c.anchor(i, 2).map(|d| &d.1), Some(&leader_vertex));
    }
}

/// A leader that never shows up is waited for only T_LEADER ticks: its round
/// is skipped and the chain goes on.
#[test]
fn an_absent_leader_is_skipped_after_the_wait() {
    let mut c = Cluster::new("absent", 4, 0);
    c.run(1);
    let leader = c.leader(2);
    let gone = c.members[leader].info.address.clone();
    let mute = move |e: &Envelope, _: usize| e.from == gone;
    for _ in 0..12 {
        c.tick_all();
        c.deliver(&mute);
    }
    for i in c.validators().filter(|&i| i != leader) {
        assert!(c.anchor(i, 2).is_none());
        assert!(
            c.decisions[i].iter().any(|d| d.0 > 2),
            "node {i} made no progress"
        );
    }
}

/// RC-1: every node reopens mid-run; nothing is proposed twice for a slot,
/// and decisions go on agreeing.
#[test]
fn reopening_every_node_mid_run_keeps_one_body_per_slot_and_agreement() {
    let mut c = Cluster::new("reopen", 4, 0);
    c.run(4);
    let proposed: Vec<Option<String>> = c
        .validators()
        .map(|i| c.engine(i).own_proposal(4).map(|v| v.hash.clone()))
        .collect();
    for i in c.validators() {
        c.reopen(i);
    }
    for i in c.validators() {
        assert_eq!(
            c.engine(i).own_proposal(4).map(|v| v.hash.clone()),
            proposed[i],
            "node {i} lost or changed its round-4 proposal"
        );
    }
    c.run(8);
    c.assert_agree();
    assert!(c.decisions[0].iter().any(|d| d.0 >= 8));
}

/// RC-3: a validator whose database lost its guard origin (a wiped or
/// resynced store under a live key) abstains from signing; it still stages
/// and decides.
#[test]
fn a_node_without_guard_origin_abstains_from_signing() {
    let mut c = Cluster::new("origin", 4, 0);
    c.run(2);
    let i = 0;
    c.engine(i)
        .storage
        .delete("consensus:guard_origin")
        .unwrap();
    c.reopen(i);
    let me = c.members[i].info.address.clone();
    let signed = Cell::new(0);
    for _ in 0..6 {
        c.tick_all();
        c.deliver(&|e, _| {
            if e.from == me && matches!(e.msg, Msg::Attest(_)) {
                signed.set(signed.get() + 1);
            }
            false
        });
    }
    assert_eq!(signed.get(), 0, "an abstaining node attested");
    assert!(
        c.engine(i).own_proposal(3).is_none() && c.engine(i).own_proposal(4).is_none(),
        "an abstaining node proposed"
    );
    c.assert_agree();
}

/// DE reads O_E only. Round-3 attestations flow, so each author certifies
/// its own round-3 vertex (one orderable vote, which runs the decision), but
/// the certificates are held: the other three round-3 vertices are staged,
/// uncertified, and must cast no vote. Anchor 2 is decided only once they
/// are certified.
#[test]
fn the_decision_counts_only_orderable_votes() {
    let mut c = Cluster::new("orderable-votes", 4, 0);
    c.run(2);
    let no_certs = |e: &Envelope, _: usize| matches!(&e.msg, Msg::Cert(x) if x.body.round == 3);
    c.tick_all();
    c.deliver(&no_certs);
    for i in c.validators() {
        let own = c.engine(i).own_proposal(3).unwrap().hash.clone();
        assert!(
            c.engine(i).is_orderable(&own),
            "node {i} certified its own vertex"
        );
        for j in c.validators().filter(|&j| j != i) {
            let v = c.engine(j).own_proposal(3).unwrap();
            assert!(c.engine(i).is_staged(&v.hash), "round 3 staged everywhere");
            assert!(!c.engine(i).is_orderable(&v.hash));
        }
        assert!(
            c.anchor(i, 2).is_none(),
            "node {i} counted an uncertified vote"
        );
    }
    c.release();
    c.deliver(&|_, _| false);
    for i in c.validators() {
        assert!(c.anchor(i, 2).is_some(), "node {i}: anchor 2 not decided");
    }
    c.assert_agree();
}

/// IN-1 E4 + ST: a relay strips the embedded parent certificates, and the
/// certificates themselves reach node 0 late. The stripped vertices wait
/// PENDING, and are staged (and attested) once the certificates arrive.
#[test]
fn a_vertex_ahead_of_its_parent_certificates_is_staged_when_they_arrive() {
    let mut c = Cluster::new("pending", 4, 0);
    let me = c.members[0].info.address.clone();
    let late_certs = move |e: &Envelope, to: usize| {
        to == 0 && e.from != me && matches!(&e.msg, Msg::Cert(x) if x.body.round == 1)
    };
    c.tick_all();
    c.deliver(&late_certs);
    c.tick_all();
    // Round 2 reaches node 0 only as stripped copies.
    let mut stripped = Vec::new();
    c.q.borrow_mut().retain(|e| match &e.msg {
        Msg::Vertex(v) if v.round == 2 && matches!(e.to, To::All) => {
            let mut w = v.clone();
            for r in &mut w.parent_refs {
                r.cert = None;
            }
            stripped.push((e.from.clone(), w));
            true
        }
        _ => true,
    });
    let to_zero =
        |e: &Envelope, to: usize| to == 0 && matches!(&e.msg, Msg::Vertex(v) if v.round == 2);
    for (from, w) in &stripped {
        c.q.borrow_mut().push_front(Envelope {
            from: from.clone(),
            to: To::One(c.members[0].info.address.clone()),
            msg: Msg::Vertex(w.clone()),
        });
    }
    let first = stripped.len();
    // Deliver the stripped copies (queued first), then hold every other
    // round-2 vertex and round-1 certificate for node 0.
    for _ in 0..first {
        let env = c.q.borrow_mut().pop_front().unwrap();
        let Msg::Vertex(v) = env.msg else {
            unreachable!()
        };
        c.receive(0, Msg::Vertex(v));
    }
    let hold = move |e: &Envelope, to: usize| late_certs(e, to) || to_zero(e, to);
    c.deliver(&hold);
    let others: Vec<String> = stripped
        .iter()
        .filter(|(from, _)| *from != c.members[0].info.address)
        .map(|(_, w)| w.hash.clone())
        .collect();
    assert_eq!(others.len(), 3);
    for h in &others {
        assert!(
            !c.engine(0).is_staged(h),
            "staged without its parent certificates"
        );
    }
    // Only the certificates are released: the stripped copies must stage.
    c.held.retain(|e| matches!(e.msg, Msg::Cert(_)));
    c.release();
    c.deliver(&|_, _| false);
    for h in &others {
        assert!(
            c.engine(0).is_staged(h),
            "not staged after the certificates came"
        );
    }
    c.run(6);
    c.assert_agree();
}

/// OR-1: a certified vertex is orderable only once every parent is. Node 0
/// holds round 2 certified but not the body of one round-1 parent.
#[test]
fn a_certified_vertex_waits_for_its_parents_to_be_orderable() {
    let mut c = Cluster::new("down-closed", 4, 0);
    let absent = c.members[1].info.address.clone();
    // The parent's body is hidden from node 0, pushed or pulled.
    let hide = move |e: &Envelope, to: usize| {
        to == 0
            && ((e.from == absent && matches!(&e.msg, Msg::Vertex(v) if v.round == 1))
                || matches!(e.msg, Msg::Resp { .. }))
    };
    c.tick_all();
    c.deliver(&hide);
    c.tick_all();
    c.deliver(&hide);
    let parent = c.engine(1).own_proposal(1).unwrap().hash.clone();
    assert!(c.engine(0).certified(1, c.engine(1).address()).is_some());
    assert!(!c.engine(0).is_staged(&parent));
    for j in c.validators() {
        let child = c.engine(j).own_proposal(2).unwrap().hash.clone();
        if c.engine(0).is_staged(&child) {
            assert!(
                !c.engine(0).is_orderable(&child),
                "orderable over a missing parent"
            );
        }
    }
    c.release();
    c.deliver(&|_, _| false);
    for j in c.validators() {
        let child = c.engine(j).own_proposal(2).unwrap().hash.clone();
        assert!(c.engine(0).is_orderable(&child));
    }
}

/// ST-2 through the engine: h0 attested twin B; twin A reached it too as a
/// plain body; the leader then certifies a third twin C with h1 and h2. h0
/// must evict A (never its attested B) to install C, and commit C.
#[test]
fn a_certified_third_twin_evicts_the_plain_one_on_a_node_that_attested_another() {
    let mut c = Cluster::new("third-twin", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    let honest: Vec<usize> = c.validators().filter(|&i| i != byz).collect();
    let h0 = honest[0];
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    let cc = twin_of(&a, &c.members[byz].node_key, "twin-c");
    c.q.borrow_mut()
        .retain(|e| !matches!(&e.msg, Msg::Vertex(v) if v.hash == a.hash));
    let addrs: Vec<String> = c.members.iter().map(|m| m.info.address.clone()).collect();
    let byz_addr = addrs[byz].clone();
    let to = |h: usize, v: &Vertex| Envelope {
        from: byz_addr.clone(),
        to: To::One(addrs[h].clone()),
        msg: Msg::Vertex(v.clone()),
    };
    let envs = vec![
        to(h0, &b),
        to(h0, &a),
        to(honest[1], &cc),
        to(honest[2], &cc),
    ];
    c.q.borrow_mut().extend(envs);
    c.deliver(&|_, _| false);
    let cert_c = forged_cert(&c, 2, &a.author, &cc.hash, &[byz, honest[1], honest[2]]);
    c.q.borrow_mut().push_back(Envelope {
        from: c.members[byz].info.address.clone(),
        to: To::All,
        msg: Msg::Cert(cert_c),
    });
    c.q.borrow_mut().push_back(to(h0, &cc));
    c.deliver(&|_, _| false);
    assert!(
        c.engine(h0).is_staged(&b.hash),
        "the attested twin is never evicted"
    );
    assert!(
        !c.engine(h0).is_staged(&a.hash),
        "the plain twin was evicted"
    );
    assert!(c.engine(h0).is_orderable(&cc.hash));
    c.run(6);
    c.assert_agree_except(Some(byz));
    assert_eq!(c.anchor(h0, 2).map(|d| &d.1), Some(&cc.hash));
}

/// Review of S5 part 1, HIGH-1: an author's `DAG_CERT` for round 1 reaches
/// only h1. The others see that certificate embedded in h1's round-2 vertex;
/// they ingest it from there (CE-3) and keep ordering and deciding.
#[test]
fn a_lost_dag_cert_is_recovered_from_the_children_that_embed_it() {
    let mut c = Cluster::new("harvest", 4, 0);
    let (byz, h1) = (0usize, 1usize);
    let byz_addr = c.members[byz].info.address.clone();
    let withhold = move |e: &Envelope, to: usize| {
        e.from == byz_addr && to != h1 && matches!(&e.msg, Msg::Cert(x) if x.body.round == 1)
    };
    for _ in 0..20 {
        c.tick_all();
        c.deliver(&withhold);
        c.held.clear(); // never delivered
    }
    let b1 = c.engine(byz).own_proposal(1).unwrap().hash.clone();
    for v in [2usize, 3] {
        assert_eq!(
            c.engine(v).certified(1, c.engine(byz).address()),
            Some(b1.as_str()),
            "node {v} ingested the embedded certificate"
        );
        assert!(c.engine(v).is_orderable(&b1));
        assert!(
            c.decisions[v].iter().any(|d| d.0 >= 14),
            "node {v} kept deciding"
        );
    }
    c.assert_agree();
}

/// Review of S5 part 1, MEDIUM-1: CE-3's halt is persisted. After a restart
/// the node is still halted: it orders nothing and signs nothing.
#[test]
fn the_cert_conflict_halt_survives_a_restart() {
    let mut c = Cluster::new("halt-restart", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    let byz2 = c.validators().find(|&i| i != byz).unwrap();
    let honest: Vec<usize> = c.validators().filter(|&i| i != byz && i != byz2).collect();
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    let cert_a = forged_cert(&c, 2, &a.author, &a.hash, &[byz, byz2, honest[0]]);
    let cert_b = forged_cert(&c, 2, &a.author, &b.hash, &[byz, byz2, honest[1]]);
    for cert in [cert_a, cert_b] {
        c.q.borrow_mut().push_front(Envelope {
            from: c.members[byz].info.address.clone(),
            to: To::All,
            msg: Msg::Cert(cert),
        });
    }
    c.q.borrow_mut().push_back(Envelope {
        from: c.members[byz].info.address.clone(),
        to: To::All,
        msg: Msg::Vertex(b.clone()),
    });
    c.deliver(&|_, _| false);
    for &h in &honest {
        assert!(c.engine(h).halted().is_some());
        c.reopen(h);
        assert!(
            c.engine(h).halted().is_some(),
            "node {h}: the halt was forgotten"
        );
    }
    let gone = c.members[byz].info.address.clone();
    let signed = Cell::new(0);
    let honest_addrs: Vec<String> = honest
        .iter()
        .map(|&h| c.members[h].info.address.clone())
        .collect();
    for _ in 0..10 {
        c.tick_all();
        c.deliver(&|e, _| {
            if honest_addrs.contains(&e.from) && matches!(e.msg, Msg::Attest(_)) {
                signed.set(signed.get() + 1);
            }
            e.from == gone
        });
        c.held.clear();
    }
    assert_eq!(signed.get(), 0, "a halted node attested");
    for &h in &honest {
        assert!(
            c.anchor(h, 2).is_none(),
            "node {h} ordered past the conflict"
        );
    }
}

/// Review of S5 part 1, LOW-1: a node that holds the slot's certificate for
/// twin B never signs twin A, even when A is the first body it stages.
#[test]
fn a_node_holding_one_twins_certificate_never_signs_the_other() {
    let mut c = Cluster::new("no-attest-twin", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    let honest: Vec<usize> = c.validators().filter(|&i| i != byz).collect();
    let h0 = honest[0];
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    c.q.borrow_mut()
        .retain(|e| !matches!(&e.msg, Msg::Vertex(v) if v.hash == a.hash));
    let cert_b = forged_cert(&c, 2, &a.author, &b.hash, &[byz, honest[1], honest[2]]);
    c.receive(h0, Msg::Cert(cert_b));
    c.receive(h0, Msg::Vertex(a.clone()));
    assert!(c.engine(h0).is_staged(&a.hash), "A is still staged");
    let e = c.engine(h0);
    let body = e.attest_body(2, &a.author, &a.hash);
    assert!(
        e.read_own_attestation(&body).unwrap().is_none(),
        "h0 signed A"
    );
}

/// RC-1 step 6 and CE-1 across a restart: a node restarts while its own
/// proposal is still collecting attestations; the collector is rebuilt, the
/// attestations answering its rebroadcast are counted, and it is certified.
#[test]
fn a_proposal_collecting_attestations_across_a_restart_is_certified() {
    let mut c = Cluster::new("collector-restart", 4, 0);
    c.run(1);
    let me = c.members[0].info.address.clone();
    let to_me = move |e: &Envelope, to: usize| to == 0 && matches!(e.msg, Msg::Attest(_));
    c.tick_all();
    c.deliver(&to_me);
    c.held.clear(); // the attestations are lost with the crash
    let mine = c.engine(0).own_proposal(2).unwrap().hash.clone();
    assert!(c.engine(0).certified(2, &me).is_none());
    c.reopen(0);
    c.run(2);
    for i in c.validators() {
        assert_eq!(
            c.engine(i).certified(2, &me),
            Some(mine.as_str()),
            "node {i}"
        );
    }
}

/// T_RETRY: a proposal whose broadcast is lost is sent again at the next
/// tick and certified.
#[test]
fn a_lost_proposal_is_rebroadcast_and_certified() {
    let mut c = Cluster::new("retry", 4, 0);
    c.run(1);
    let me = c.members[0].info.address.clone();
    let from_me = me.clone();
    let lose = move |e: &Envelope, _: usize| {
        e.from == from_me && matches!(&e.msg, Msg::Vertex(v) if v.round == 2)
    };
    c.tick_all();
    c.deliver(&lose);
    c.held.clear();
    let mine = c.engine(0).own_proposal(2).unwrap().hash.clone();
    for i in 1..4 {
        assert!(!c.engine(i).is_staged(&mine));
    }
    c.run(1);
    for i in c.validators() {
        assert_eq!(
            c.engine(i).certified(2, &me),
            Some(mine.as_str()),
            "node {i}"
        );
    }
}

fn decision_row(c: &Cluster, i: usize, round: u64) -> Option<String> {
    c.engine(i)
        .storage
        .get(&crate::ordering::anchor_decision_key(EPOCH, round))
        .unwrap()
}

/// DE-6: every anchor round the cursor passes gets exactly one written
/// decision, a skip included, and it matches what was committed.
#[test]
fn every_anchor_round_gets_one_written_decision() {
    let mut c = Cluster::new("decision-rows", 4, 0);
    c.run(1);
    let leader = c.leader(2);
    let gone = c.members[leader].info.address.clone();
    let mute = move |e: &Envelope, _: usize| e.from == gone;
    for _ in 0..12 {
        c.tick_all();
        c.deliver(&mute);
        c.held.clear();
    }
    for i in c.validators().filter(|&i| i != leader) {
        assert_eq!(decision_row(&c, i, 2).as_deref(), Some("S"), "node {i}");
        let top = c.decisions[i].last().expect("decided").0;
        for r in (4..=top).step_by(2) {
            let row = decision_row(&c, i, r).unwrap_or_else(|| panic!("node {i}: no row {r}"));
            match c.anchor(i, r) {
                Some(d) => assert_eq!(row, format!("C:{}", d.1)),
                None => assert_eq!(row, "S"),
            }
        }
        assert!(decision_row(&c, i, top + 2).is_none());
    }
}

/// DE-6: a decision row that already says otherwise refuses the decision,
/// and the node orders nothing past it.
#[test]
fn a_conflicting_decision_row_refuses_the_decision() {
    let mut c = Cluster::new("decision-conflict", 4, 0);
    c.engine(0)
        .storage
        .put(&crate::ordering::anchor_decision_key(EPOCH, 2), "S")
        .unwrap();
    c.run(8);
    assert!(
        c.decisions[0].is_empty(),
        "node 0 decided past a conflicting row"
    );
    for i in 1..4 {
        let d = c.anchor(i, 2).expect("the others commit anchor 2");
        assert_eq!(decision_row(&c, i, 2), Some(format!("C:{}", d.1)));
    }
}

/// Review of S5 part 1, LOW-3: a crash between a certificate's row and the
/// promotion of its body leaves the body in a plain role. Boot promotes it
/// again.
#[test]
fn boot_restores_the_certified_role_of_a_held_body() {
    let mut c = Cluster::new("repromote", 4, 0);
    c.run(3);
    let author = c.members[1].info.address.clone();
    let digest = c.engine(0).certified(2, &author).unwrap().to_string();
    let key = staging::vslot_key(EPOCH, 2, &author);
    let db = &c.engine(0).storage;
    let mut slot: Vec<staging::SlotEntry> =
        serde_json::from_str(&db.get(&key).unwrap().unwrap()).unwrap();
    for e in &mut slot {
        if e.digest == digest {
            e.role = Role::Staged;
        }
    }
    db.put(&key, &serde_json::to_string(&slot).unwrap())
        .unwrap();
    c.reopen(0);
    let slot: Vec<staging::SlotEntry> =
        serde_json::from_str(&c.engine(0).storage.get(&key).unwrap().unwrap()).unwrap();
    assert_eq!(
        slot.iter().find(|e| e.digest == digest).map(|e| e.role),
        Some(Role::Certified)
    );
}

/// The fixture of the pull witnesses: round 2's leader never shows its
/// vertex A to h0 and never answers a request. Returns (leader, h0, A).
fn withheld_from(c: &mut Cluster) -> (usize, usize, Vertex) {
    c.run(1);
    let byz = c.leader(2);
    let h0 = c.validators().find(|&i| i != byz).unwrap();
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    (byz, h0, a)
}

fn withholding(c: &Cluster, byz: usize, h0: usize) -> impl Fn(&Envelope, usize) -> bool {
    let byz_addr = c.members[byz].info.address.clone();
    move |e: &Envelope, to: usize| {
        e.from == byz_addr
            && ((to == h0 && matches!(&e.msg, Msg::Vertex(v) if v.round == 2))
                || matches!(e.msg, Msg::Resp { .. }))
    }
}

/// A3c-pull: A's body is withheld from h0 and its author refuses to serve.
/// h0 holds A's certificate, fetches the body from A's other signers, and
/// commits 2/A with everyone, a restart mid-fetch included.
#[test]
fn a3c_pull_a_withheld_body_is_fetched_from_its_signers() {
    let mut c = Cluster::new("pull-a3c", 4, 0);
    let (byz, h0, a) = withheld_from(&mut c);
    let rule = withholding(&c, byz, h0);
    // First delivery: h0 gets A's certificate, not A.
    c.deliver(&|e, to| rule(e, to) || (to == h0 && matches!(e.msg, Msg::Resp { .. })));
    c.held.clear();
    assert_eq!(c.engine(h0).certified(2, &a.author), Some(a.hash.as_str()));
    assert!(!c.engine(h0).is_staged(&a.hash));
    // A restart before the fetch completes: the want is rebuilt at boot.
    c.reopen(h0);
    assert!(c.engine(h0).wanted_bodies().contains(&a.hash));
    for _ in 0..8 {
        c.tick_all();
        c.deliver(&rule);
        c.held.clear();
    }
    assert!(c.engine(h0).is_staged(&a.hash), "h0 fetched A");
    c.assert_agree();
    assert_eq!(c.anchor(h0, 2).map(|d| &d.1), Some(&a.hash));
}

/// RE-4: a signer that answers with a body under another digest (here A's
/// twin) is ignored, the body is not staged, and the next signer is asked.
#[test]
fn a_wrong_body_is_refused_and_the_next_signer_is_asked() {
    let mut c = Cluster::new("pull-wrong", 4, 0);
    let (byz, h0, a) = withheld_from(&mut c);
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    let rule = withholding(&c, byz, h0);
    let liar = c.validators().find(|&i| i != byz && i != h0).unwrap();
    let liar_addr = c.members[liar].info.address.clone();
    let forged = b.clone();
    let map = move |e: &Envelope, to: usize| -> Option<Msg> {
        if rule(e, to) {
            return None;
        }
        match &e.msg {
            Msg::Resp {
                to: requester,
                resp: pull::Response::Vertices { .. },
            } if e.from == liar_addr => Some(Msg::Resp {
                to: requester.clone(),
                resp: pull::Response::Vertices {
                    bodies: vec![forged.clone()],
                    unknown: vec![],
                },
            }),
            _ => Some(e.msg.clone()),
        }
    };
    for _ in 0..10 {
        c.tick_all();
        c.deliver_map(&map);
    }
    assert!(
        c.engine(h0).is_staged(&a.hash),
        "h0 fetched A from an honest signer"
    );
    assert!(
        !c.engine(h0).is_staged(&b.hash),
        "h0 staged the liar's body"
    );
    c.assert_agree();
    assert_eq!(c.anchor(h0, 2).map(|d| &d.1), Some(&a.hash));
}

/// RE-4: `unknown` never retires a want. Every signer answers `unknown` for
/// a while; h0 keeps asking and fetches A once one of them serves it.
#[test]
fn an_unknown_answer_never_ends_the_search() {
    let mut c = Cluster::new("pull-unknown", 4, 0);
    let (byz, h0, a) = withheld_from(&mut c);
    let rule = withholding(&c, byz, h0);
    let silent = Cell::new(true);
    let map = |e: &Envelope, to: usize| -> Option<Msg> {
        if rule(e, to) {
            return None;
        }
        match &e.msg {
            Msg::Resp {
                to: requester,
                resp: pull::Response::Vertices { bodies, unknown },
            } if silent.get() => Some(Msg::Resp {
                to: requester.clone(),
                resp: pull::Response::Vertices {
                    bodies: vec![],
                    unknown: unknown
                        .iter()
                        .cloned()
                        .chain(bodies.iter().map(|v| v.hash.clone()))
                        .collect(),
                },
            }),
            _ => Some(e.msg.clone()),
        }
    };
    for _ in 0..8 {
        c.tick_all();
        c.deliver_map(&map);
    }
    assert!(!c.engine(h0).is_staged(&a.hash));
    assert!(
        c.engine(h0).wanted_bodies().contains(&a.hash),
        "the want retired"
    );
    silent.set(false);
    for _ in 0..12 {
        c.tick_all();
        c.deliver_map(&map);
    }
    assert!(c.engine(h0).is_staged(&a.hash));
    c.assert_agree();
}

/// RE-1 end to end: a node cut off for several rounds catches up by pull
/// alone (no push is replayed to it) and decides the same anchors.
#[test]
fn a_node_cut_off_for_several_rounds_catches_up_by_pull() {
    let mut c = Cluster::new("pull-catchup", 4, 0);
    c.run(2);
    let cut = c.members[0].info.address.clone();
    let isolate = move |e: &Envelope, to: usize| to == 0 || e.from == cut;
    for _ in 0..6 {
        c.tick_all();
        c.deliver(&isolate);
        c.held.clear();
    }
    let behind = c.decisions[0].len();
    let ahead = c.decisions[1].len();
    assert!(
        ahead > behind + 1,
        "the others moved on ({behind} vs {ahead})"
    );
    c.run(16);
    c.assert_agree();
    assert!(c.decisions[0].len() > ahead, "node 0 caught up and went on");
}

/// RE-1 (d): a node that receives no push at all (no vertex, attestation or
/// certificate reaches it) learns everything by pull: stalled, it asks for
/// the certificates of its rounds, then for their bodies, and decides the
/// same anchors.
#[test]
fn a_node_without_any_push_keeps_up_by_pull_alone() {
    let mut c = Cluster::new("pull-only", 4, 0);
    let no_push = |e: &Envelope, to: usize| {
        to == 0 && matches!(e.msg, Msg::Vertex(_) | Msg::Attest(_) | Msg::Cert(_))
    };
    for _ in 0..40 {
        c.tick_all();
        c.deliver(&no_push);
        c.held.clear();
    }
    assert!(!c.decisions[0].is_empty(), "node 0 decided nothing");
    c.assert_agree();
}

/// RE-1 (b): a crash lost an (unsynced) certificate row of an old round.
/// After the restart that parent is not orderable, so its children wait;
/// the node asks for the certificate and orders again.
#[test]
fn a_lost_certificate_row_is_fetched_after_a_restart() {
    let mut c = Cluster::new("pull-lost-cert", 4, 0);
    c.run(4);
    let author = c.members[1].info.address.clone();
    let row = format!("consensus:vcert:v1:{EPOCH:020}:{:020}:{author}", 1);
    c.engine(0).storage.delete(&row).unwrap();
    c.reopen(0);
    assert!(c.engine(0).certified(1, &author).is_none());
    let before = c.decisions[0].len();
    c.run(6);
    assert!(
        c.engine(0).certified(1, &author).is_some(),
        "the certificate was fetched"
    );
    assert!(c.decisions[0].len() > before, "node 0 orders again");
    c.assert_agree();
}

/// RE-6, the flood witness. Every tick, ahead of the honest requests, each
/// server receives 20 validly signed requests from a Byzantine member, 20
/// requests claiming the honest fetcher's identity under the wrong key, 20
/// from a node outside the committee, and 20 replays of every request the
/// honest fetcher has sent so far. The honest fetch still completes: its
/// reservation is its own, a forged identity or a replay charges no one, and
/// outsiders share only the residual. The flood asks for an unknown digest,
/// so no answer to it can help the victim.
#[test]
fn a_flood_cannot_starve_an_honest_members_fetch() {
    let mut c = Cluster::new("pull-flood", 4, 1);
    let (byz, h0, a) = withheld_from(&mut c);
    let rule = withholding(&c, byz, h0);
    let outsider = c.members.len() - 1;
    let addr = |i: usize| c.members[i].info.address.clone();
    let (byz_addr, h0_addr, out_addr) = (addr(byz), addr(h0), addr(outsider));
    let (byz_key, out_key) = (c.members[byz].node_key, c.members[outsider].node_key);
    let servers: Vec<String> = c
        .validators()
        .filter(|&i| i != byz && i != h0)
        .map(addr)
        .collect();
    let addrs: Vec<String> = c.members.iter().map(|m| m.info.address.clone()).collect();
    let captured: RefCell<Vec<(String, pull::SignedRequest)>> = RefCell::new(Vec::new());
    let mut seq = 1_000_000u64;
    for _ in 0..12 {
        c.tick_all();
        // Every request the victim ever sent is replayed, every tick.
        let replays: Vec<(String, pull::SignedRequest)> = captured.borrow().clone();
        for to in &servers {
            for _ in 0..20 {
                seq += 1;
                let req = pull::Request::Vertices(vec!["f".repeat(64)]);
                let flood = [
                    (byz_addr.clone(), &byz_key, byz_addr.clone()),
                    (byz_addr.clone(), &byz_key, h0_addr.clone()),
                    (out_addr.clone(), &out_key, out_addr.clone()),
                ];
                for (sender, key, claimed) in flood {
                    let signed = pull::SignedRequest::sign(
                        CHAIN,
                        GENESIS,
                        key,
                        &claimed,
                        to,
                        seq,
                        req.clone(),
                    );
                    c.q.borrow_mut().push_front(Envelope {
                        from: sender,
                        to: To::One(to.clone()),
                        msg: Msg::Req(signed),
                    });
                }
                for (target, old) in replays.iter().filter(|(t, _)| t == to) {
                    c.q.borrow_mut().push_front(Envelope {
                        from: byz_addr.clone(),
                        to: To::One(target.clone()),
                        msg: Msg::Req(old.clone()),
                    });
                }
            }
        }
        c.deliver(&|e, to| {
            if let Msg::Req(r) = &e.msg {
                if r.from == h0_addr && e.from == h0_addr {
                    captured.borrow_mut().push((addrs[to].clone(), r.clone()));
                }
            }
            rule(e, to)
        });
        c.held.clear();
    }
    assert!(
        c.engine(h0).is_staged(&a.hash),
        "the honest fetch was starved"
    );
    c.assert_agree();
}

/// RE-6: a replayed request is not answered and charges nothing, so the
/// member it came from still gets its whole reservation in that tick; a
/// request claiming a member under another key is not answered either.
#[test]
fn a_replay_or_a_forged_identity_charges_no_ones_budget() {
    let mut c = Cluster::new("replay", 4, 0);
    c.run(2);
    let (me, server) = (0usize, 1usize);
    let from = c.members[me].info.address.clone();
    let to = c.members[server].info.address.clone();
    let key = c.members[me].node_key;
    let other_key = c.members[2].node_key;
    let req = |seq: u64, key: &[u8; 32]| {
        Msg::Req(pull::SignedRequest::sign(
            CHAIN,
            GENESIS,
            key,
            &from,
            &to,
            seq,
            pull::Request::Certs {
                epoch: 0,
                slots: vec![(1, from.clone())],
            },
        ))
    };
    let answers = |c: &Cluster| {
        c.q.borrow()
            .iter()
            .filter(|e| matches!(&e.msg, Msg::Resp { to: t, .. } if *t == from))
            .count()
    };
    c.receive(server, req(10, &key));
    assert_eq!(answers(&c), 1);
    for _ in 0..10 {
        c.receive(server, req(10, &key)); // replays
        c.receive(server, req(11 + 100, &other_key)); // forged identity
    }
    assert_eq!(answers(&c), 1, "a replay or a forgery was answered");
    for seq in 11..20 {
        c.receive(server, req(seq, &key));
    }
    assert_eq!(
        answers(&c),
        pull::MEMBER_REQS_PER_TICK as usize,
        "the member's reservation was charged by others"
    );
}

/// Second review of S5, MEDIUM-1: a copy of a staged body is neither
/// verified nor harvested, so a relay padding a public digest with refs (here
/// carrying a valid but conflicting certificate) costs nothing and changes
/// nothing.
#[test]
fn a_padded_copy_of_a_staged_body_is_not_harvested() {
    let mut c = Cluster::new("no-harvest", 4, 0);
    c.run(3);
    let author = c.members[1].info.address.clone();
    let staged = c.engine(0).certified(2, &author).unwrap().to_string();
    let mut copy = lock(&c.engine(0).dag).get(&staged).cloned().unwrap();
    let fake = "ab".repeat(32);
    let conflicting = forged_cert(&c, 1, &author, &fake, &[0, 2, 3]);
    copy.parent_refs.push(ParentRef {
        round: 1,
        author: author.clone(),
        digest: fake,
        proof: None,
        cert: Some(conflicting.compact()),
    });
    c.receive(0, Msg::Vertex(copy));
    assert!(
        c.engine(0).halted().is_none(),
        "the padded copy was harvested"
    );
}

/// Second review of S5, LOW-3: the guard-origin flag left set does not re-arm
/// signing on a database that has already signed.
#[test]
fn a_used_database_never_takes_a_new_guard_origin() {
    let mut c = Cluster::new("origin-rearm", 4, 0);
    c.run(3);
    c.engine(0)
        .storage
        .delete("consensus:guard_origin")
        .unwrap();
    // `open` with genesis_init = true, as a node started with the flag set.
    c.engines[0] = None;
    c.open(0, true);
    assert!(c
        .engine(0)
        .storage
        .get("consensus:guard_origin")
        .unwrap()
        .is_none());
    c.run(4);
    assert!(
        c.engine(0).own_proposal(5).is_none(),
        "the node signed again"
    );
}

/// S7: 200 rounds. Every node restarts at a different time, and one is cut
/// off for 40 rounds (inside the retention window) and rejoins by fetch. All
/// decide the same sequences; GC deleted the rows at or below g − slack;
/// memory stays bounded; nodes at one cursor hold the same committed set.
#[test]
fn two_hundred_rounds_with_restarts_at_different_times_agree() {
    let mut c = Cluster::new("s7-long", 4, 0);
    let cut = c.members[3].info.address.clone();
    for tick in 0..200usize {
        if tick >= 40 && (tick - 40) % 35 == 0 && (tick - 40) / 35 < 4 {
            c.reopen((tick - 40) / 35);
        }
        c.tick_all();
        if (100..140).contains(&tick) {
            let off = cut.clone();
            c.deliver(&move |e, to| to == 3 || e.from == off);
            c.held.clear();
        } else {
            c.deliver(&|_, _| false);
        }
    }
    c.run(10);
    c.assert_agree();
    for i in c.validators() {
        let e = c.engine(i);
        let g = e.floor();
        assert!(g > 100, "node {i}: g = {g}");
        let cut_round = g - staging::RETAIN_SLACK;
        let old = staging::vslot_key(EPOCH, cut_round, &c.members[0].info.address);
        assert!(
            e.storage.get(&old).unwrap().is_none(),
            "node {i} kept row {old}"
        );
        let held = lock(&e.dag).len();
        let bound = 4 * (crate::ordering::GC_DEPTH + staging::RETAIN_SLACK + 20) as usize;
        assert!(held <= bound, "node {i} holds {held} bodies");
        assert!(lock(&e.dag).values().all(|v| v.round > cut_round));
    }
    let cursors: Vec<u64> = c.validators().map(|i| c.engine(i).cursor()).collect();
    for i in c.validators().skip(1) {
        if cursors[i] == cursors[0] {
            assert_eq!(
                lock(&c.engine(i).ordering).committed_digests(),
                lock(&c.engine(0).ordering).committed_digests(),
                "node {i}"
            );
        }
    }
}

/// OR-3, the floor-rise witness: node 0 can never obtain one round-3 body,
/// so its children wait. When g passes that round (here node 0 adopts the
/// others' decisions, as block sync would), the waiting children are
/// released and node 0 orders and decides again.
#[test]
fn a_waiting_child_is_released_when_the_floor_passes_its_parent() {
    let mut c = Cluster::new("s7-floor", 4, 0);
    c.run(2);
    c.tick_all();
    let lost = c.engine(1).own_proposal(3).unwrap().hash.clone();
    let gone = lost.clone();
    let hide = move |e: &Envelope, to: usize| {
        to == 0
            && match &e.msg {
                Msg::Vertex(v) => v.hash == gone,
                Msg::Resp {
                    resp: pull::Response::Vertices { bodies, .. },
                    ..
                } => bodies.iter().any(|v| v.hash == gone),
                _ => false,
            }
    };
    for _ in 0..70 {
        c.deliver(&hide);
        c.held.clear();
        c.tick_all();
    }
    c.deliver(&hide);
    c.held.clear();
    assert!(!c.engine(0).is_staged(&lost));
    let stuck = c.decisions[0].len();
    let ahead: Vec<Decision> = c.decisions[1].clone();
    assert!(ahead.iter().any(|d| d.0 > 3 + crate::ordering::GC_DEPTH));
    // Adopt the others' decisions until g passes round 3.
    let stakes = c.engine(0).stakes().to_vec();
    for d in ahead.iter().skip(stuck) {
        let mut ord = lock(&c.engine(0).ordering);
        if ord.gc_floor() >= 3 {
            break;
        }
        assert!(ord.adopt_synced_anchor(d.0, &d.1, &d.2, &stakes).is_some());
    }
    assert!(c.engine(0).floor() >= 3);
    c.tick(0);
    assert!(
        !c.engine(0).wanted_bodies().contains(&lost),
        "a want at or below g did not retire"
    );
    let adopted = lock(&c.engine(0).ordering).next_anchor_round;
    c.run(8);
    assert!(
        c.engine(0).cursor() > adopted,
        "node 0 decided nothing after the floor rose"
    );
}

/// GC-3: deleting guards below g cannot enable a second signature. A twin of
/// a vertex just above g is refused (its guard survives GC); an old vertex at
/// or below g is STALE and never signed again.
#[test]
fn guards_are_deleted_only_where_ingress_refuses_everything() {
    let mut c = Cluster::new("s7-guards", 4, 0);
    c.run(2);
    let old = c.engine(1).own_proposal(2).unwrap().clone();
    c.run(130);
    let g = c.engine(0).floor();
    assert!(g > staging::RETAIN_SLACK + 2, "g = {g}");
    let me = c.members[0].info.address.clone();
    let signed = Cell::new(0);
    let count = |e: &Envelope, _: usize| {
        if e.from == me && matches!(e.msg, Msg::Attest(_)) {
            signed.set(signed.get() + 1);
        }
        false
    };
    // Old: at or below g, its guard long deleted.
    c.q.borrow_mut().push_back(Envelope {
        from: c.members[1].info.address.clone(),
        to: To::One(me.clone()),
        msg: Msg::Vertex(old.clone()),
    });
    c.deliver(&count);
    assert_eq!(signed.get(), 0, "an old vertex was signed again");
    // Just above g: a twin of what node 0 already attested.
    let author = c.members[1].info.address.clone();
    let r = (g + 1..g + 20)
        .find(|r| c.engine(1).own_proposal(*r).is_some())
        .expect("a round above g");
    let above = c.engine(1).own_proposal(r).unwrap().clone();
    let twin = twin_of(&above, &c.members[1].node_key, "late-twin");
    c.q.borrow_mut().push_back(Envelope {
        from: author,
        to: To::One(me.clone()),
        msg: Msg::Vertex(twin),
    });
    c.deliver(&count);
    assert_eq!(signed.get(), 0, "a twin above g was signed");
}

/// ST-3 after GC-3: a Byzantine leader's uncertified twin is staged as a
/// plain body and counts against its author's budget; once g passes its
/// round, GC deletes it and gives the bytes back.
#[test]
fn gc_gives_the_plain_body_budget_back() {
    let mut c = Cluster::new("s7-vbytes", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    c.q.borrow_mut().push_back(Envelope {
        from: c.members[byz].info.address.clone(),
        to: To::All,
        msg: Msg::Vertex(b.clone()),
    });
    c.deliver(&|_, _| false);
    let h = c.validators().find(|&i| i != byz).unwrap();
    let counted = |c: &Cluster| -> u64 {
        c.engine(h)
            .storage
            .get(&staging::vbytes_key(EPOCH, &a.author))
            .unwrap()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    assert!(c.engine(h).is_staged(&b.hash));
    assert!(counted(&c) > 0, "vacuous: the twin is not a plain body");
    c.run(130);
    assert!(c.engine(h).floor() > 2 + staging::RETAIN_SLACK);
    assert!(!c.engine(h).is_staged(&b.hash), "GC kept the twin");
    assert_eq!(counted(&c), 0, "GC did not give the twin's bytes back");
}

// ------------------------------------------------------------ S9: epochs

/// The epoch a node is in, and its first round.
fn epoch_of(c: &Cluster, i: usize) -> (u64, u64) {
    let e = c.engine(i);
    (e.epoch, e.first_round)
}

/// EP-1..EP-4: every 3 blocks an epoch closes at its last anchor r* and the
/// next begins at r* + 2 with its own sentinel. Nodes agree across several
/// boundaries, and each boundary's first round follows its closing anchor.
#[test]
fn epochs_rotate_and_every_node_agrees_across_boundaries() {
    let mut c = Cluster::with_epochs("s9-rotate", 4, 0, 3);
    c.run(40);
    c.assert_agree();
    for i in c.validators() {
        let (epoch, first) = epoch_of(&c, i);
        assert!(epoch >= 3, "node {i} is in epoch {epoch}");
        let start: epoch::EpochStart = serde_json::from_str(
            &c.engine(i)
                .storage
                .get(&epoch::epoch_start_key(epoch))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(first, start.prev_closing_round + 2);
        assert_ne!(start.sentinel, SENTINEL);
        // The boundary anchor is the epoch's last decision (EP-3).
        let boundary = c.decisions[i]
            .iter()
            .find(|d| d.1 == start.prev_anchor)
            .expect("the boundary anchor was decided");
        assert_eq!(boundary.0, start.prev_closing_round);
        // EP-5 (i): the in-memory index holds the active epoch only; an entry
        // of E surviving activation would sit at E+1's round numbers.
        {
            let e = c.engine(i);
            let dag = lock(&e.dag);
            for (round, digests) in lock(&e.round_index).iter() {
                for d in digests {
                    assert!(
                        dag.get(d)
                            .is_some_and(|v| v.epoch == epoch && v.round == *round),
                        "node {i}: round {round} indexes {d}, not an epoch-{epoch} body"
                    );
                }
            }
        }
        // GC-3 by epoch: two epochs back, nothing of epoch 0 is left.
        let old = format!("consensus:vslot:v1:{:020}:", 0);
        let e = c.engine(i);
        assert!(
            e.storage
                .db
                .prefix_iterator(old.as_bytes())
                .next()
                .is_none_or(|r| !r.unwrap().0.starts_with(old.as_bytes())),
            "node {i} kept epoch 0's slots"
        );
    }
}

/// EP-2, (e): epoch 1's committee drops one member, adds a newcomer with its
/// own keys, and weights stake unequally. In epoch 1 the newcomer's vertices
/// are ordered and the leaver's are not, the leaver follows as an observer,
/// and every node agrees throughout.
#[test]
fn a_committee_change_with_a_new_key_and_unequal_stake_rotates_cleanly() {
    let mut c = Cluster::with_epochs("s9-change", 4, 1, 6);
    let newcomer = c.members.len() - 1;
    let leaver = 3;
    let mut next: Vec<ValidatorInfo> = c.committee[..3].to_vec();
    next[0].stake = 300;
    next.push(c.members[newcomer].info.clone());
    for i in 0..c.members.len() {
        c.engines[i]
            .as_mut()
            .unwrap()
            .schedule_committee(1, next.clone());
    }
    let e1_decisions = |c: &Cluster| {
        let first = c.engine(0).first_round;
        c.decisions[0].iter().filter(|d| d.0 >= first).count()
    };
    c.run_until(80, |c| {
        (0..c.members.len()).all(|i| epoch_of(c, i).0 == 1) && e1_decisions(c) >= 3
    });
    assert!(e1_decisions(&c) >= 3, "vacuous: epoch 1 decided too little");
    c.assert_agree();
    let e1: epoch::EpochStart = serde_json::from_str(
        &c.engine(0)
            .storage
            .get(&epoch::epoch_start_key(1))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(e1.committee, qc::canonical_order(&next));
    let authors: Vec<String> = {
        let dag = lock(&c.engine(0).dag);
        c.decisions[0]
            .iter()
            .filter(|d| d.0 >= e1.first_round)
            .flat_map(|d| d.2.clone())
            .map(|h| dag.get(&h).expect("an epoch-1 body is held").author.clone())
            .collect()
    };
    assert!(authors.contains(&c.members[newcomer].info.address));
    assert!(!authors.contains(&c.members[leaver].info.address));
    assert!(c.engine(leaver).own.is_empty(), "the leaver proposed");
}

/// EP-2, (j): a proposed member whose BLS proof of possession fails makes the
/// whole proposal invalid: epoch 1 carries epoch 0's committee over, with an
/// alarm, on every node alike.
#[test]
fn an_invalid_pop_carries_the_committee_over_with_an_alarm() {
    let mut c = Cluster::with_epochs("s9-pop", 4, 0, 3);
    let mut next = c.committee.clone();
    next[1].bls_pop = hex::encode([7u8; 96]);
    for i in c.validators() {
        c.engines[i]
            .as_mut()
            .unwrap()
            .schedule_committee(1, next.clone());
    }
    c.run(20);
    c.assert_agree();
    for i in c.validators() {
        let e = c.engine(i);
        let e1: epoch::EpochStart =
            serde_json::from_str(&e.storage.get(&epoch::epoch_start_key(1)).unwrap().unwrap())
                .unwrap();
        assert_eq!(e1.committee, qc::canonical_order(&c.committee), "node {i}");
        assert!(e
            .storage
            .get(&format!("alarm:committee_invalid:{:020}", 1))
            .unwrap()
            .is_some());
    }
}

/// EP-5 (a), (d), (i): after a boundary, an epoch-E vertex at the new
/// epoch's round numbers is inert, and an epoch-(E+1) first-round vertex
/// citing a wrong sentinel is invalid; neither is staged, and O_{E+1} does
/// not change.
#[test]
fn stale_and_wrong_sentinel_vertices_change_nothing_after_a_boundary() {
    let mut c = Cluster::with_epochs("s9-stale", 4, 0, 3);
    c.run(14);
    let (epoch, first) = epoch_of(&c, 0);
    assert!(epoch >= 1);
    let m = &c.members[1];
    let mk = |epoch: u64, round: u64, parents: Vec<String>| {
        let mut v = Vertex {
            epoch,
            round,
            author: m.info.address.clone(),
            parents,
            parent_refs: vec![],
            payload: vec!["x".into()],
            timestamp: NOW,
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
        };
        v.hash = v.hash_v4_with_domain(CHAIN, GENESIS);
        v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&m.node_key));
        v
    };
    let stale = mk(epoch - 1, first, vec!["genesis".into()]);
    let wrong = mk(epoch, first, vec!["f".repeat(64)]);
    let before = lock(&c.engine(0).round_index).clone();
    c.receive(0, Msg::Vertex(stale.clone()));
    c.receive(0, Msg::Vertex(wrong.clone()));
    assert!(!c.engine(0).is_staged(&stale.hash));
    assert!(!c.engine(0).is_staged(&wrong.hash));
    assert_eq!(*lock(&c.engine(0).round_index), before);
}

/// LA-6 across a boundary: a node cut off just before the others close
/// epoch 0 (it is behind by less than the retention window) finishes epoch 0
/// from the others' closed tail, activates epoch 1 and agrees. Without the
/// closed tail, or without the Ahead trigger, it stays in epoch 0 forever.
#[test]
fn a_node_behind_at_a_boundary_catches_up_into_the_next_epoch() {
    let mut c = Cluster::with_epochs("s9-behind", 4, 0, 6);
    c.run_until(40, |c| c.decisions[1].len() >= 4);
    let cut = c.members[0].info.address.clone();
    let quiet = move |e: &Envelope, to: usize| to == 0 || e.from == cut;
    for _ in 0..40 {
        if epoch_of(&c, 1).0 == 1 && c.engine(1).current_round() > c.engine(1).first_round + 2 {
            break;
        }
        c.tick_all();
        c.deliver(&quiet);
        c.held.clear();
    }
    assert_eq!(epoch_of(&c, 0).0, 0, "vacuous: node 0 kept up");
    assert_eq!(epoch_of(&c, 1).0, 1, "vacuous: the others never closed");
    c.run_until(80, |c| {
        epoch_of(c, 0).0 == 1 && c.decisions[0].len() >= c.decisions[1].len()
    });
    assert_eq!(epoch_of(&c, 0).0, 1, "node 0 never finished epoch 0");
    c.run(6);
    c.assert_agree();
    assert!(c.decisions[0].len() > 6);
}

/// RC-3, (k): a node whose guard database was wiped abstains for the rest of
/// the epoch and resumes at the next activation.
#[test]
fn a_wiped_guard_database_abstains_until_the_next_epoch() {
    let mut c = Cluster::with_epochs("s9-wiped", 4, 0, 4);
    c.run(2);
    c.engine(0)
        .storage
        .delete("consensus:guard_origin")
        .unwrap();
    c.reopen(0);
    let e0 = epoch_of(&c, 0).0;
    c.run(3);
    assert!(
        c.engine(0).own.keys().all(|r| *r < 3),
        "node 0 proposed while abstaining"
    );
    c.run(30);
    let (e, first) = epoch_of(&c, 0);
    assert!(e > e0, "no activation happened");
    assert!(
        c.engine(0).own.keys().any(|r| *r >= first),
        "node 0 did not resume at activation"
    );
    c.assert_agree();
}

/// RC-3: a guard database whose origin is another key's (a copied or
/// swapped store) is not continuous either: the node abstains until the next
/// activation, exactly as with a wiped one.
#[test]
fn a_guard_database_of_another_key_abstains_until_the_next_epoch() {
    let mut c = Cluster::with_epochs("s9-foreign", 4, 0, 4);
    c.run(2);
    let foreign = guard_origin(CHAIN, GENESIS, &c.members[1].node_key);
    c.engine(0)
        .storage
        .put("consensus:guard_origin", &foreign)
        .unwrap();
    c.reopen(0);
    let e0 = epoch_of(&c, 0).0;
    c.run(3);
    assert!(
        c.engine(0).own.keys().all(|r| *r < 3),
        "node 0 proposed under another key's guards"
    );
    c.run(30);
    let (e, first) = epoch_of(&c, 0);
    assert!(e > e0, "no activation happened");
    assert!(
        c.engine(0).own.keys().any(|r| *r >= first),
        "node 0 did not resume at activation"
    );
    c.assert_agree();
}

/// EP-4, (f): a node cut off across a boundary carried a payload in a
/// proposal that never got certified. At activation that payload is handed
/// back for the mempool.
#[test]
fn an_orphaned_payload_is_handed_back_at_activation() {
    let mut c = Cluster::with_epochs("s9-orphan", 4, 0, 6);
    c.run_until(40, |c| c.decisions[1].len() >= 3);
    // A payload that does get committed in epoch 0, above its floor: it must
    // not come back.
    let net = c.net(0);
    c.engines[0]
        .as_mut()
        .unwrap()
        .on_tick(vec!["kept-tx".into()], &net);
    let kept = c
        .engine(0)
        .own
        .values()
        .find(|v| v.payload == ["kept-tx"])
        .map(|v| v.hash.clone());
    let kept = kept.expect("node 0 proposed kept-tx");
    c.deliver(&|_, _| false);
    c.run_until(20, |c| lock(&c.engine(0).ordering).is_committed(&kept));
    assert!(
        lock(&c.engine(0).ordering).is_committed(&kept),
        "kept-tx never committed"
    );
    assert_eq!(
        epoch_of(&c, 0).0,
        0,
        "vacuous: the boundary came before the cut"
    );
    let net = c.net(0);
    c.engines[0]
        .as_mut()
        .unwrap()
        .on_tick(vec!["orphan-tx".into()], &net);
    let lost = c.members[0].info.address.clone();
    let quiet = move |e: &Envelope, to: usize| e.from == lost || to == 0;
    for _ in 0..40 {
        if epoch_of(&c, 1).0 == 1 {
            break;
        }
        c.tick_all();
        c.deliver(&quiet);
        c.held.clear();
    }
    assert_eq!(epoch_of(&c, 0).0, 0, "vacuous: node 0 kept up");
    c.run_until(80, |c| epoch_of(c, 0).0 == 1);
    c.assert_agree();
    assert_eq!(epoch_of(&c, 0).0, 1);
    let back = c.engines[0].as_mut().unwrap().take_orphaned_payloads();
    assert!(back.contains(&"orphan-tx".to_string()), "{back:?}");
    assert!(
        !back.contains(&"kept-tx".to_string()),
        "a committed payload came back"
    );
}

/// RC-1 across a boundary: the servers restart after activating epoch 1 and
/// still serve epoch 0's tail (rebuilt from their rows) to a node that was
/// cut off before the boundary.
#[test]
fn restarted_servers_still_serve_the_closed_tail() {
    let mut c = Cluster::with_epochs("s9-reopen-tail", 4, 0, 6);
    c.run_until(40, |c| c.decisions[1].len() >= 4);
    let cut = c.members[0].info.address.clone();
    let quiet = move |e: &Envelope, to: usize| to == 0 || e.from == cut;
    for _ in 0..40 {
        if epoch_of(&c, 1).0 == 1 && c.engine(1).current_round() > c.engine(1).first_round + 2 {
            break;
        }
        c.tick_all();
        c.deliver(&quiet);
        c.held.clear();
    }
    assert_eq!(epoch_of(&c, 0).0, 0, "vacuous: node 0 kept up");
    for i in 1..4 {
        c.reopen(i);
        assert_eq!(epoch_of(&c, i).0, 1);
        assert!(c
            .engine(i)
            .closed
            .as_ref()
            .is_some_and(|t| t.epoch == 0 && !t.certs.is_empty()));
    }
    c.run_until(80, |c| {
        epoch_of(c, 0).0 == 1 && c.decisions[0].len() >= c.decisions[1].len()
    });
    assert_eq!(epoch_of(&c, 0).0, 1, "node 0 never finished epoch 0");
    c.run(4);
    c.assert_agree();
}

/// RC-1 between close and activation: a node whose activation write was lost
/// (it holds E+1's record but not `epoch_active`) activates on its first call
/// and keeps agreeing; it never stays in a closed epoch.
#[test]
fn a_crash_between_close_and_activation_still_activates() {
    let mut c = Cluster::with_epochs("s9-crash-close", 4, 0, 4);
    for _ in 0..60 {
        if epoch_of(&c, 0).0 == 1 {
            break;
        }
        c.tick_all();
        c.deliver(&|_, _| false);
    }
    assert_eq!(epoch_of(&c, 0).0, 1);
    c.engine(0).storage.delete(epoch::EPOCH_ACTIVE_KEY).unwrap();
    c.reopen(0);
    assert_eq!(epoch_of(&c, 0).0, 0, "the lost write was not simulated");
    assert!(c.engine(0).closing_round.is_some());
    // EP-5 (c): an E+1 certificate that arrives before activation is kept
    // and ingested at activation (the end of this very call), not dropped to
    // be fetched again.
    for _ in 0..10 {
        if c.engine(1).certs.values().any(|cert| cert.body.epoch == 1) {
            break;
        }
        for i in 1..4 {
            c.tick(i);
        }
        c.deliver(&|_, to| to == 0);
        c.held.clear();
    }
    let early = c
        .engine(1)
        .certs
        .values()
        .find(|cert| cert.body.epoch == 1)
        .cloned()
        .expect("node 1 holds an epoch-1 certificate");
    let slot = (early.body.round, early.body.author.clone());
    c.receive(0, Msg::Cert(early.clone()));
    assert_eq!(epoch_of(&c, 0).0, 1, "the first call did not activate");
    assert_eq!(
        c.engine(0).certs.get(&slot).map(|k| k.body.digest.clone()),
        Some(early.body.digest.clone()),
        "the early certificate was not ingested at activation"
    );
    c.run(20);
    assert!(epoch_of(&c, 0).0 >= 1, "node 0 stayed in the closed epoch");
    c.assert_agree();
}

// ------------------------------------------------------------ S10: rates

/// Decided anchors over the anchor rounds they span, on node `i`.
fn decided_rate(c: &Cluster, i: usize) -> f64 {
    let d = &c.decisions[i];
    let (Some(first), Some(last)) = (d.first(), d.last()) else {
        return 0.0;
    };
    let span = (last.0 - first.0) / 2 + 1;
    d.len() as f64 / span as f64
}

/// S10's liveness floor: the V4 decided-rate stays at or above 0.42 with
/// four honest validators, and with one Byzantine member that proposes but
/// never attests (its certificates must come from the three honest ones).
#[test]
fn the_decided_rate_stays_above_the_floor_with_a_non_attesting_member() {
    let mut honest = Cluster::new("rate-honest", 4, 0);
    honest.run(120);
    honest.assert_agree();
    let r_honest = decided_rate(&honest, 0);

    let mut c = Cluster::new("rate-silent", 4, 0);
    let byz = c.members[3].info.address.clone();
    for _ in 0..120 {
        c.tick_all();
        let b = byz.clone();
        c.deliver(&move |e, _| e.from == b && matches!(e.msg, Msg::Attest(_)));
        c.held.clear();
    }
    c.assert_agree();
    let r_byz = decided_rate(&c, 0);
    eprintln!("S10 decided-rate: honest {r_honest:.3}, one non-attesting member {r_byz:.3}");
    assert!(
        c.decisions[0].len() >= 20,
        "vacuous: {} decisions",
        c.decisions[0].len()
    );
    assert!(r_honest >= 0.42, "honest decided-rate {r_honest:.3}");
    assert!(
        r_byz >= 0.42,
        "decided-rate {r_byz:.3} with a non-attesting member"
    );
}

/// The same floor under delay and a harder adversary: a quarter of all
/// messages arrive a tick late, and the Byzantine member never attests and
/// shows each of its vertices to one honest node only (the others must pull
/// it or decide without it).
#[test]
fn the_decided_rate_stays_above_the_floor_under_delay_and_a_withholding_member() {
    use rand::{Rng, SeedableRng};
    let mut c = Cluster::new("rate-delay", 4, 0);
    let byz = c.members[3].info.address.clone();
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x42);
    let late: Vec<bool> = (0..20_000).map(|_| rng.gen_range(0..100) < 25).collect();
    let counter = std::rc::Rc::new(std::cell::Cell::new(0usize));
    for _ in 0..160 {
        c.release();
        c.tick_all();
        let (b, late, n) = (byz.clone(), late.clone(), std::rc::Rc::clone(&counter));
        c.deliver(&move |e, to| {
            if e.from == b {
                if matches!(e.msg, Msg::Attest(_)) {
                    return true;
                }
                if matches!(e.msg, Msg::Vertex(_)) && to != 0 {
                    return true;
                }
            }
            let k = n.get();
            n.set(k + 1);
            late[k % late.len()]
        });
        // The Byzantine member's withheld copies are dropped for good; the
        // late honest ones are released at the next tick.
        let b = byz.clone();
        c.held
            .retain(|e| !(e.from == b && matches!(e.msg, Msg::Attest(_) | Msg::Vertex(_))));
    }
    c.run(10);
    c.assert_agree_except(Some(3));
    let r = decided_rate(&c, 0);
    eprintln!(
        "S10 decided-rate under delay and withholding: {r:.3} ({} decisions)",
        c.decisions[0].len()
    );
    assert!(
        c.decisions[0].len() >= 20,
        "vacuous: {} decisions",
        c.decisions[0].len()
    );
    assert!(r >= 0.42, "decided-rate {r:.3}");
}

/// EP-3: E+1's record is written once. Writing the same record again is a
/// no-op; a different one is a decision conflict and changes nothing.
#[test]
fn an_epoch_record_is_written_once() {
    let c = Cluster::new("s9-write-once", 4, 0);
    let db = &c.engine(0).storage;
    let boundary = epoch::Boundary {
        epoch: 0,
        current: &c.committee,
        closing_round: 10,
        anchor: "aa",
        block_hash: "bb",
        height: 4,
    };
    let (start, invalid) = epoch::next_start(CHAIN, GENESIS, &boundary, &c.committee);
    assert!(invalid.is_none());
    epoch::write_next(db, &start, None).unwrap();
    epoch::write_next(db, &start, None).unwrap();
    let mut other = start.clone();
    other.first_round += 2;
    let err = epoch::write_next(db, &other, None).unwrap_err();
    assert!(err.contains(crate::ordering::DECISION_CONFLICT), "{err}");
    assert_eq!(epoch::read_start_from(db, 1).unwrap(), Some(start));
}
