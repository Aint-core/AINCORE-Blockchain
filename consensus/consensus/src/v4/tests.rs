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
        let path = storage::test_dir::process_dir().join(format!(
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
    /// Every engine's wall clock (seconds); NOW unless a test moves it.
    clock: Arc<std::sync::atomic::AtomicU64>,
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
            clock: Arc::new(std::sync::atomic::AtomicU64::new(NOW)),
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
        let clock = Arc::clone(&self.clock);
        let now = Arc::new(move || clock.load(AtomicOrdering::SeqCst));
        self.engines[i] = Some(Engine::open(storage, cfg, genesis_init, now).unwrap());
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
    w.payload = vec![crate::test_txs::tagged(CHAIN, tag)];
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
    forged_cert_in(c, EPOCH, &c.committee, round, author, digest, signers)
}

/// `forged_cert` for `epoch` under `committee`.
fn forged_cert_in(
    c: &Cluster,
    epoch: u64,
    committee: &[ValidatorInfo],
    round: u64,
    author: &str,
    digest: &str,
    signers: &[usize],
) -> VertexCertificate {
    let body = AttestBody {
        chain_id: CHAIN.into(),
        genesis_identity: GENESIS.into(),
        epoch,
        round,
        author: author.to_string(),
        digest: digest.to_string(),
        committee_hash: qc::validator_set_hash(committee),
    };
    let mut collector = CertCollector::new(body.clone(), committee).unwrap();
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

/// Twin flood: an equivocating leader sends both twins to everyone, B first,
/// and (being Byzantine) aggregates the honest attestations of B into a
/// certificate. The honest producers' next vertices cite exactly one digest
/// for the leader's slot, the certified one, so they pass the stateless
/// parent gate (C1); no node ever cites or commits A. (Final review: the old
/// version certified neither twin, so its checks held trivially.)
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
    let honest: Vec<usize> = c.validators().filter(|&i| i != byz).collect();
    let mut signers = vec![byz];
    signers.extend(&honest);
    let cert_b = forged_cert(&c, 2, &a.author, &b.hash, &signers);
    c.q.borrow_mut().push_back(Envelope {
        from: c.members[byz].info.address.clone(),
        to: To::All,
        msg: Msg::Cert(cert_b),
    });
    c.deliver(&|_, _| false);
    for &i in &honest {
        assert_eq!(
            c.engine(i).certified(2, &a.author),
            Some(b.hash.as_str()),
            "vacuous: node {i} does not hold B's certificate"
        );
    }
    c.run(8);
    let stakes: Vec<(String, u64)> = c
        .committee
        .iter()
        .map(|m| (m.address.clone(), m.stake))
        .collect();
    for &i in &honest {
        let v = c.engine(i).own_proposal(3).expect("round 3 proposed");
        qc::parent_refs_admissible(v, &stakes).unwrap();
        assert!(v.parents.contains(&b.hash), "node {i} does not cite the certified twin");
        assert!(!v.parents.contains(&a.hash), "node {i} cites the uncertified twin");
    }
    c.assert_agree_except(Some(byz));
    for &i in &honest {
        let d = c.anchor(i, 2).map(|x| x.1.clone());
        assert_eq!(d.as_deref(), Some(b.hash.as_str()), "node {i}: anchor 2 is B");
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

/// B5 witness, the rehearsal's missed anchors: the other three members
/// propose and certify the anchor round before the leader's tick comes, so
/// the leader's current round is already the next one. It still proposes
/// its anchor, the others' next proposals wait for its certificate, and the
/// anchor commits on every node. Before the fix the leader went straight to
/// the next round and the anchor was never certified.
#[test]
fn a_leader_whose_tick_comes_after_its_anchor_quorum_still_proposes_it() {
    let mut c = Cluster::new("late_tick", 4, 0);
    c.run(1);
    let leader = c.leader(2);
    for i in c.validators().filter(|&i| i != leader) {
        c.tick(i);
    }
    c.deliver(&|_, _| false);
    assert_eq!(
        c.engine(leader).current_round(),
        3,
        "positive control: round 2 reached quorum without the leader"
    );
    c.tick(leader);
    c.deliver(&|_, _| false);
    let leader_vertex = c
        .engine(leader)
        .own_proposal(2)
        .expect("the leader proposed its anchor round")
        .hash
        .clone();
    c.run(8);
    c.assert_agree();
    for i in c.validators() {
        assert_eq!(
            c.anchor(i, 2).map(|d| &d.1),
            Some(&leader_vertex),
            "node {i}"
        );
    }
}

/// B5 review (a): one tick after the anchor's quorum the others are still
/// waiting for the leader's certificate; the late anchor reaches them in
/// time and their next round cites it.
#[test]
fn the_others_wait_for_a_late_owed_anchor_and_cite_it() {
    let mut c = Cluster::new("late_wait", 4, 0);
    c.run(1);
    let leader = c.leader(2);
    let others: Vec<usize> = c.validators().filter(|&i| i != leader).collect();
    for &i in &others {
        c.tick(i);
    }
    c.deliver(&|_, _| false);
    for &i in &others {
        c.tick(i);
    }
    c.deliver(&|_, _| false);
    for &i in &others {
        assert!(
            c.engine(i).own_proposal(3).is_none(),
            "node {i} did not wait"
        );
    }
    c.tick(leader);
    c.deliver(&|_, _| false);
    let anchor = c.engine(leader).own_proposal(2).unwrap().hash.clone();
    for &i in &others {
        c.tick(i);
    }
    c.deliver(&|_, _| false);
    for &i in &others {
        let v = c.engine(i).own_proposal(3).expect("round 3 proposed");
        assert!(
            v.parent_refs
                .iter()
                .any(|r| r.round == 2 && r.digest == anchor),
            "node {i} did not cite the anchor"
        );
    }
}

/// B5 review LOW-3: a leader that proposed its anchor late waits for that
/// anchor's certificate from when it proposed it, not from the older
/// quorum, so its own next round cites it.
#[test]
fn a_leader_waits_for_its_own_late_anchor_from_when_it_proposed_it() {
    let mut c = Cluster::new("late_own", 4, 0);
    c.run(1);
    let leader = c.leader(2);
    for i in c.validators().filter(|&i| i != leader) {
        c.tick(i);
    }
    c.deliver(&|_, _| false);
    c.tick(leader);
    let slow = move |e: &Envelope, i: usize| i == leader && matches!(e.msg, Msg::Attest(_));
    c.deliver(&slow);
    let anchor = c.engine(leader).own_proposal(2).unwrap().hash.clone();
    c.tick(leader);
    c.deliver(&slow);
    assert!(
        c.engine(leader).own_proposal(3).is_none(),
        "the leader moved on before its own anchor was certified"
    );
    c.release();
    c.deliver(&|_, _| false);
    c.tick(leader);
    c.deliver(&|_, _| false);
    let v = c.engine(leader).own_proposal(3).expect("round 3 proposed");
    assert!(v
        .parent_refs
        .iter()
        .any(|r| r.round == 2 && r.digest == anchor));
}

/// B5 review LOW-1: an anchor is never owed once this node proposed the
/// round above it (nothing would cite it).
#[test]
fn an_anchor_is_not_owed_after_the_round_above_it() {
    let mut c = Cluster::new("owed_above", 4, 0);
    c.run(1);
    let leader = c.leader(2);
    let other = c.validators().find(|&i| i != leader).unwrap();
    for i in c.validators().filter(|&i| i != leader) {
        c.tick(i);
    }
    c.deliver(&|_, _| false);
    assert_eq!(c.engine(leader).anchor_owed(), Some(2), "positive control");
    let any = c.engine(other).own_proposal(2).unwrap().clone();
    c.engines[leader].as_mut().unwrap().own.insert(3, any);
    assert_eq!(c.engine(leader).anchor_owed(), None);
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

/// B68 witness: failed checks are charged only to the message that carried
/// what failed. A Byzantine member signs a round-2 vertex that waits on an
/// honest member's round-1 certificate and cites the other round-1 slots by
/// fake digests with junk certificates of the right shape. The junk is
/// charged to the Byzantine sender once, when it arrives; the honest
/// certificate that wakes the vertex costs its sender nothing.
#[test]
fn a_waking_certificate_is_not_charged_for_the_vertex_it_wakes() {
    let mut c = Cluster::new("wake-charge", 4, 0);
    let me = c.members[0].info.address.clone();
    let late_certs = move |e: &Envelope, to: usize| {
        to == 0 && e.from != me && matches!(&e.msg, Msg::Cert(x) if x.body.round == 1)
    };
    c.tick_all();
    c.deliver(&late_certs);
    c.tick_all();
    let byzantine = 1;
    let honest = c.members[2].info.address.clone();
    let mut forged =
        c.q.borrow()
            .iter()
            .find_map(|e| match &e.msg {
                Msg::Vertex(v) if v.round == 2 && e.from == c.members[byzantine].info.address => {
                    Some(v.clone())
                }
                _ => None,
            })
            .expect("the Byzantine member's round-2 vertex");
    let shape = c
        .held
        .iter()
        .find_map(|e| match &e.msg {
            Msg::Cert(x) => Some(x.compact()),
            _ => None,
        })
        .expect("a held certificate");
    let junk = blockchain::CompactCert {
        signer_bitmap: shape.signer_bitmap.clone(),
        aggregate_signature: vec![7u8; shape.aggregate_signature.len()],
    };
    let mut faked = 0;
    for (i, r) in forged.parent_refs.iter_mut().enumerate() {
        if r.author == honest {
            r.cert = None;
            continue;
        }
        r.digest = format!("{:064x}", 0xfa4e_u64 + i as u64);
        forged.parents[i] = r.digest.clone();
        r.cert = Some(junk.clone());
        faked += 1;
    }
    assert!(faked >= 2, "vacuous: no junk refs");
    forged.hash = forged.hash_v4_with_domain(CHAIN, GENESIS);
    forged.sign_with_ed25519(&crypto::SigningKey::from_bytes(
        &c.members[byzantine].node_key,
    ));
    let ((), charged) = crate::work::failed_in(|| c.receive(0, Msg::Vertex(forged.clone())));
    assert_eq!(
        charged, faked,
        "the junk is charged to the sender that carried it"
    );
    assert!(!c.engine(0).is_staged(&forged.hash));
    let pending = &mut c.engines[0].as_mut().unwrap().pending;
    let held = pending
        .remove(&forged.author, forged.round, &forged.hash)
        .expect("the vertex waits");
    pending.push(held.clone());
    assert!(
        held.parent_refs.iter().all(|r| r.cert.is_none()),
        "the junk that failed is kept for a later wake to check again"
    );

    let wake = c
        .held
        .iter()
        .find(|e| e.from == honest && matches!(&e.msg, Msg::Cert(x) if x.body.round == 1))
        .map(|e| e.msg.clone())
        .expect("the honest member's held round-1 certificate");
    let ((), charged) = crate::work::failed_in(|| c.receive(0, wake));
    assert_eq!(
        charged, 0,
        "the honest certificate was charged for the vertex it woke"
    );
}

/// B68 witness at an epoch boundary: a vertex of E+1 buffered before
/// activation was never checked; it is checked at activation, on behalf of
/// whoever delivered it, so its junk certificates are not charged to the
/// message that completed the epoch. Node 0's epoch is closed by hand (a
/// standalone engine closes and activates in one call, so E+1's record
/// would never be seen without activation).
#[test]
fn junk_buffered_for_the_next_epoch_is_not_charged_at_activation() {
    let mut c = Cluster::new("wake-epoch", 4, 0);
    c.run_until(40, |c| c.decisions[0].len() >= 2);
    let (closing_round, anchor, _, _) = c.decisions[0]
        .last()
        .cloned()
        .expect("vacuous: nothing decided");
    let epoch_before = c.engine(0).epoch;
    let committee = c.committee.clone();
    c.engines[0]
        .as_mut()
        .unwrap()
        .close_epoch(closing_round, &anchor, &"ab".repeat(32), &committee)
        .unwrap();
    let next = c.engine(0).next.clone().expect("E+1 scheduled");
    let shape = c
        .engine(0)
        .certs
        .values()
        .next()
        .expect("a held certificate")
        .compact();
    let junk = blockchain::CompactCert {
        signer_bitmap: shape.signer_bitmap.clone(),
        aggregate_signature: vec![7u8; shape.aggregate_signature.len()],
    };
    let byzantine = 1;
    let author = c.members[byzantine].info.address.clone();
    let template = lock(&c.engine(byzantine).dag)
        .values()
        .find(|v| v.author == author)
        .expect("a vertex of the Byzantine member")
        .clone();
    let mut forged = template;
    forged.epoch = next.epoch;
    forged.round = next.first_round + 1;
    forged.payload = vec![];
    forged.parent_refs = next
        .committee
        .iter()
        .enumerate()
        .map(|(i, m)| blockchain::ParentRef {
            round: next.first_round,
            author: m.address.clone(),
            digest: format!("{:064x}", 0xe4b0_u64 + i as u64),
            proof: None,
            cert: Some(junk.clone()),
        })
        .collect();
    forged.parents = forged
        .parent_refs
        .iter()
        .map(|r| r.digest.clone())
        .collect();
    forged.hash = forged.hash_v4_with_domain(CHAIN, GENESIS);
    forged.sign_with_ed25519(&crypto::SigningKey::from_bytes(
        &c.members[byzantine].node_key,
    ));
    let (forged_author, forged_round, forged_hash) =
        (forged.author.clone(), forged.round, forged.hash.clone());
    c.engines[0].as_mut().unwrap().pending.push(forged);
    let net = c.net(0);
    let (activated, charged) =
        crate::work::failed_in(|| c.engines[0].as_mut().unwrap().activate_next(&net));
    activated.unwrap();
    assert!(
        c.engine(0).epoch > epoch_before,
        "vacuous: node 0 never activated"
    );
    let held = c.engines[0]
        .as_mut()
        .unwrap()
        .pending
        .remove(&forged_author, forged_round, &forged_hash)
        .expect("vacuous: the forged vertex was not checked into waiting on its parents");
    assert!(
        held.parent_refs.iter().all(|r| r.cert.is_none()),
        "vacuous: its junk certificates were not checked at activation"
    );
    assert_eq!(
        charged, 0,
        "junk buffered for E+1 was charged at activation"
    );
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
    let mk = |epoch: u64, round: u64, parents: Vec<String>, refs: Vec<ParentRef>| {
        let mut v = Vertex {
            epoch,
            round,
            author: m.info.address.clone(),
            parents,
            parent_refs: refs,
            payload: vec![crate::test_txs::tx(CHAIN, 9, 0)],
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
    // An epoch-(E−1) vertex at E's first round, well formed: it cites a
    // quorum of round r−1 parents, so Layer S under E−1's record accepts it
    // and only EP-5's STALE rule can refuse it (final review: the old copy
    // was malformed and refused by Layer S instead).
    let refs: Vec<ParentRef> = (0..3)
        .map(|k| ParentRef {
            round: first - 1,
            author: c.members[k].info.address.clone(),
            digest: format!("{:064x}", k + 1),
            proof: None,
            cert: None,
        })
        .collect();
    let parents: Vec<String> = refs.iter().map(|r| r.digest.clone()).collect();
    let stale = mk(epoch - 1, first, parents, refs);
    {
        let e = c.engine(0);
        let previous = e.previous_record().expect("E−1's record is held");
        ingress_v4::layer_s(&stale, &previous, CHAIN, GENESIS)
            .expect("vacuous: the stale vertex fails Layer S");
    }
    let wrong = mk(epoch, first, vec!["f".repeat(64)], vec![]);
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
    // Time passes beyond the resume point (boot + the skew margin): the
    // next boundary opens an epoch that began after the guards were lost.
    c.clock.store(
        NOW + 3 * ingress_v4::MAX_FUTURE_DRIFT_SECS,
        AtomicOrdering::SeqCst,
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
    // Time passes beyond the resume point (boot + the skew margin): the
    // next boundary opens an epoch that began after the guards were lost.
    c.clock.store(
        NOW + 3 * ingress_v4::MAX_FUTURE_DRIFT_SECS,
        AtomicOrdering::SeqCst,
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
    let kept_tx = crate::test_txs::tx(CHAIN, 11, 0);
    let orphan_tx = crate::test_txs::tx(CHAIN, 12, 0);
    let net = c.net(0);
    c.engines[0]
        .as_mut()
        .unwrap()
        .on_tick(vec![kept_tx.clone()], &net);
    let kept = c
        .engine(0)
        .own
        .values()
        .find(|v| v.payload == [kept_tx.clone()])
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
        .on_tick(vec![orphan_tx.clone()], &net);
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
    assert!(back.contains(&orphan_tx), "{back:?}");
    assert!(!back.contains(&kept_tx), "a committed payload came back");
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
        timestamp: NOW,
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

// ------------------------------------------------ final review (ingress)

/// Node 0's own attestation row for (epoch, round, author, digest), if any.
fn rev_own_attestation(
    c: &Cluster,
    i: usize,
    epoch: u64,
    round: u64,
    author: &str,
    digest: &str,
) -> Option<VertexAttestation> {
    let body = AttestBody {
        chain_id: CHAIN.into(),
        genesis_identity: GENESIS.into(),
        epoch,
        round,
        author: author.to_string(),
        digest: digest.to_string(),
        committee_hash: qc::validator_set_hash(&c.engine(i).cfg.committee),
    };
    c.engine(i).read_own_attestation(&body).unwrap()
}

/// RC-3 (final review, HIGH): a validator whose database is wiped in epoch 1
/// and that re-syncs from genesis must NOT be re-armed by the activations it
/// performs while catching up: epoch 1 began before the wipe, and the key
/// already signed in it. (It was, and a Byzantine author then got a second
/// attestation from the honest key for a slot it had attested.)
#[test]
fn a_resyncing_wiped_validator_is_not_rearmed_in_an_epoch_it_signed_in() {
    let mut c = Cluster::with_epochs("rev-wipe-resync", 4, 0, 10);
    // Everyone in epoch 1, a few rounds in.
    c.run_until(120, |c| {
        c.validators().all(|i| epoch_of(c, i).0 == 1)
            && c.engine(1).current_round() > c.engine(1).first_round + 2
    });
    assert!(c.validators().all(|i| epoch_of(&c, i).0 == 1), "no epoch 1");
    let byz = 3usize;
    let byz_addr = c.members[byz].info.address.clone();
    let byz_key = c.members[byz].node_key;
    // Byzantine node 3 shows its next vertex V to node 0 only.
    c.tick_all();
    let (r, v) = {
        let e = c.engine(byz);
        let (r, v) = e
            .own
            .iter()
            .next_back()
            .map(|(r, v)| (*r, v.clone()))
            .unwrap();
        (r, v)
    };
    assert_eq!(v.epoch, 1);
    let vh = v.hash.clone();
    let hide_v =
        move |e: &Envelope, to: usize| matches!(&e.msg, Msg::Vertex(x) if x.hash == vh) && to != 0;
    c.deliver(&hide_v);
    c.held.clear();
    for _ in 0..3 {
        c.tick_all();
        c.deliver(&hide_v);
        c.held.clear();
    }
    let before = rev_own_attestation(&c, 0, 1, r, &byz_addr, &v.hash)
        .expect("node 0 attested V before the wipe");
    assert!(c.engine(1).certified(r, &byz_addr).is_none());

    // Wipe node 0's database; restart without the init flag (correct ops).
    c.engines[0] = None;
    c.dirs[0] = TempDb::new("rev-wiped-0");
    c.open(0, false);
    assert!(!c.engine(0).guards_continuous, "RC-3 should abstain");
    assert_eq!(epoch_of(&c, 0).0, 0);

    // Node 0 catches up epoch 0 from the others' closed tail (only node 0
    // ticks, so the others stay in epoch 1). An epoch-1 vertex is its cue.
    let cue = c.engine(1).own.values().next_back().cloned().unwrap();
    c.receive(0, Msg::Vertex(cue));
    let vh2 = v.hash.clone();
    let hide_all =
        move |e: &Envelope, _to: usize| matches!(&e.msg, Msg::Vertex(x) if x.hash == vh2);
    for _ in 0..200 {
        if epoch_of(&c, 0).0 == 1 {
            break;
        }
        c.tick(0);
        c.deliver(&hide_all);
        c.held.clear();
    }
    assert_eq!(epoch_of(&c, 0).0, 1, "node 0 never activated epoch 1");
    assert!(
        !c.engine(0).guards_continuous,
        "re-armed inside an epoch that began before the wipe"
    );
    // The Byzantine author shows node 0 a twin of V for the same slot.
    let twin = twin_of(&v, &byz_key, "rev-twin");
    c.receive(0, Msg::Vertex(twin.clone()));
    assert!(
        rev_own_attestation(&c, 0, 1, r, &byz_addr, &twin.hash).is_none(),
        "the honest key attested a second digest for slot (1, {r})"
    );
    let _ = before;
}

// ------------------------------------------------ final review (dos) regressions

/// The node transport's size check (dag.rs handle_message): a `DAG_V4:`
/// message whose JSON exceeds MAX_VERTEX_BYTES + WRAP is dropped before
/// parsing, whatever its kind.
fn dos_node_wire_accepts(msg: &Msg) -> bool {
    const WRAP: usize = r#"{"Vertex":}"#.len();
    serde_json::to_string(msg).is_ok_and(|c| c.len() <= crate::dag::MAX_VERTEX_BYTES + WRAP)
}

/// One tick where every validator proposes `payload_bytes` of payload, then a
/// delivery that (optionally) applies the node's wire bound and isolates
/// `cut`.
fn dos_tick(c: &mut Cluster, payload_bytes: usize, wire: bool, cut: Option<usize>) {
    for i in c.validators() {
        let net = c.net(i);
        let payload = if payload_bytes == 0 {
            vec![]
        } else {
            crate::test_txs::payload_of_size(CHAIN, i as u8 + 1, payload_bytes)
        };
        c.engines[i].as_mut().unwrap().on_tick(payload, &net);
        c.collect(i);
    }
    let cut_addr = cut.map(|k| c.members[k].info.address.clone());
    let dropped = Cell::new(0usize);
    c.deliver_map(&|e, to| {
        if let (Some(k), Some(a)) = (cut, cut_addr.as_ref()) {
            if to == k || e.from == *a {
                return None;
            }
        }
        if wire && !dos_node_wire_accepts(&e.msg) {
            dropped.set(dropped.get() + 1);
            return None;
        }
        Some(e.msg.clone())
    });
}

/// DOS-1: `serve` packs up to MAX_RESP_BYTES (900 KiB) of bodies, but every
/// node drops a `DAG_V4:` message over MAX_VERTEX_BYTES + 11 (768 KiB) before
/// parsing it. A lagging node whose wanted bodies of one batch exceed 768 KiB
/// never receives them; its wants retry in lockstep (same due tick, same
/// rotation), so the same oversize answer is produced forever.
#[test]
fn dos_a_pull_answer_over_the_node_wire_bound_never_arrives() {
    const PAYLOAD: usize = 60 * 1024;
    let run = |wire: bool| -> (usize, usize, usize) {
        let mut c = Cluster::new(if wire { "dos-wire-f" } else { "dos-wire-c" }, 4, 0);
        for _ in 0..2 {
            dos_tick(&mut c, PAYLOAD, wire, None);
        }
        for _ in 0..8 {
            dos_tick(&mut c, PAYLOAD, wire, Some(0));
        }
        let ahead = c.decisions[1].len();
        for _ in 0..40 {
            dos_tick(&mut c, PAYLOAD, wire, None);
        }
        (c.decisions[0].len(), ahead, c.engine(0).wanted_bodies().len())
    };
    let (d0, ahead, _) = run(false);
    assert!(d0 > ahead, "control: without the wire bound node 0 catches up ({d0} vs {ahead})");
    let (d0, ahead, wants) = run(true);
    assert!(
        d0 > ahead,
        "with the node's wire bound node 0 never catches up: {d0} decisions vs {ahead} before \
         the rejoin, {wants} bodies still wanted after 40 ticks"
    );
}

/// DOS-1 at the byte level: one ordinary answer to one request is over the
/// node's bound.
#[test]
fn dos_one_serve_answer_exceeds_the_node_wire_bound() {
    let mut c = Cluster::new("dos-wire-unit", 4, 0);
    for _ in 0..6 {
        dos_tick(&mut c, 60 * 1024, false, None);
    }
    let digests: Vec<String> = lock(&c.engine(1).dag).keys().take(32).cloned().collect();
    let resp = c.engine(1).serve(&pull::Request::Vertices(digests.clone()));
    let n = match &resp {
        pull::Response::Vertices { bodies, .. } => bodies.len(),
        _ => 0,
    };
    let msg = Msg::Resp {
        to: c.members[0].info.address.clone(),
        resp,
    };
    let len = serde_json::to_string(&msg).unwrap().len();
    eprintln!("answer with {n} bodies of {} asked: {len} bytes, bound {}", digests.len(), crate::dag::MAX_VERTEX_BYTES + 11);
    assert!(dos_node_wire_accepts(&msg), "serve built a {len}-byte answer the node transport drops");
}

/// B110 witness: a digest asked many times in one request is served once.
#[test]
fn a_digest_asked_twice_is_served_once() {
    let mut c = Cluster::new("b110-dedup", 4, 0);
    c.run(3);
    let d = lock(&c.engine(1).dag)
        .keys()
        .next()
        .cloned()
        .expect("a held body");
    let pull::Response::Vertices { bodies, unknown } = c
        .engine(1)
        .serve(&pull::Request::Vertices(vec![d.clone(); 32]))
    else {
        panic!("a vertices answer");
    };
    assert_eq!(bodies.len(), 1, "one body for one digest");
    assert!(unknown.is_empty(), "{unknown:?}");
}

/// Deliver until quiet, pass by pass. In each pass the requests of one sender
/// to one target are delivered highest `seq` first: what the node transport
/// (one spawned TCP connection per message plus gossip) does at random, and
/// what any gossip peer can force by racing a sender's last request of a tick
/// to its target. `cut` isolates a node.
fn dos_deliver_reordered(c: &mut Cluster, reorder: bool, cut: Option<usize>) -> (usize, usize) {
    let (mut sent, mut answered) = (0usize, 0usize);
    let cut_addr = cut.map(|k| c.members[k].info.address.clone());
    loop {
        let mut pass: Vec<Envelope> = c.q.borrow_mut().drain(..).collect();
        if pass.is_empty() {
            break;
        }
        if reorder {
            pass.sort_by_key(|e| match &e.msg {
                Msg::Req(r) => (1u8, r.from.clone(), r.to.clone(), u64::MAX - r.seq),
                _ => (0u8, String::new(), String::new(), 0),
            });
        }
        for env in pass {
            let receivers: Vec<usize> = match &env.to {
                To::All => (0..c.members.len())
                    .filter(|&i| c.members[i].info.address != env.from)
                    .collect(),
                To::One(a) => vec![c.index_of(a)],
            };
            for i in receivers {
                if let (Some(k), Some(a)) = (cut, cut_addr.as_ref()) {
                    if i == k || env.from == *a {
                        continue;
                    }
                }
                if let Msg::Req(r) = &env.msg {
                    if r.from == c.members[0].info.address {
                        sent += 1;
                    }
                }
                let before = c.q.borrow().len();
                c.receive(i, env.msg.clone());
                if let Msg::Req(r) = &env.msg {
                    if r.from == c.members[0].info.address {
                        answered += c.q.borrow().iter().skip(before).filter(|e| matches!(e.msg, Msg::Resp { .. })).count();
                    }
                }
            }
        }
    }
    (sent, answered)
}

/// DOS-2: RE-6's strictly increasing `seq` drops every request of a sender
/// that arrives after a later one. A lagging node sends its whole gap in one
/// tick, many requests per target; delivered out of order, all but the last
/// are dropped as replays (the budget charged nothing, but nothing is
/// answered), the dropped wants back off in lockstep, and the catch-up falls
/// behind the chain.
#[test]
fn dos_reordered_requests_are_dropped_as_replays() {
    let run = |reorder: bool| -> (usize, usize, usize, usize) {
        let mut c = Cluster::new(if reorder { "dos-seq-r" } else { "dos-seq-f" }, 4, 0);
        c.run(2);
        for _ in 0..40 {
            c.tick_all();
            dos_deliver_reordered(&mut c, false, Some(0));
        }
        let ahead = c.decisions[1].len();
        let (mut sent, mut answered) = (0, 0);
        for _ in 0..30 {
            c.tick_all();
            let (s, a) = dos_deliver_reordered(&mut c, reorder, None);
            sent += s;
            answered += a;
        }
        (c.decisions[0].len(), ahead, sent, answered)
    };
    let (d0, ahead, sent, answered) = run(false);
    eprintln!("in order: node 0 {d0} decisions (others had {ahead}), {answered}/{sent} requests answered");
    assert!(d0 > ahead, "control: in order node 0 catches up");
    let (d0, ahead, sent, answered) = run(true);
    eprintln!("reordered: node 0 {d0} decisions (others had {ahead}), {answered}/{sent} requests answered");
    assert!(d0 > ahead, "reordered: node 0 never caught up ({d0} vs {ahead}); {answered}/{sent} answered");
}


/// DOS-5: an unsolicited `Resp` (anyone can send one: it is not signed and
/// not matched to a request) carrying certificates this node ALREADY holds
/// costs one full BLS aggregate verification per certificate: `on_response`
/// takes every certificate (no cap, no want check) and `on_cert` verifies
/// before looking at the index. One message under the node's 768 KiB bound
/// carries ~1,000 of them.
#[test]
fn dos_an_unsolicited_answer_of_held_certificates_costs_a_pairing_each() {
    // (Deterministic since the fix: a timing assertion failed under load.)
    let mut c = Cluster::new("dos-cert-replay", 4, 0);
    c.run(30);
    let cert = c.engine(0).certs.values().next().cloned().unwrap();
    let slot = (cert.body.round, cert.body.author.clone());
    // Unheld and unwanted: an unsolicited answer carrying it is ignored.
    c.engines[0].as_mut().unwrap().certs.remove(&slot);
    let me = c.members[0].info.address.clone();
    let answer = |cert: &VertexCertificate| Msg::Resp {
        to: me.clone(),
        resp: pull::Response::Certs {
            certs: vec![cert.clone()],
            unknown: vec![],
        },
    };
    let msg = answer(&cert);
    c.receive(0, msg);
    assert!(
        !c.engine(0).certs.contains_key(&slot),
        "an unsolicited certificate was taken"
    );
    // Wanted and asked for: the same answer is taken (the control; B51: an
    // answer is taken only for a request this node sent).
    c.engines[0].as_mut().unwrap().want_cert(slot.0, &slot.1);
    let net = c.net(0);
    c.engines[0].as_mut().unwrap().send_due(&net);
    let msg = answer(&cert);
    c.receive(0, msg);
    assert!(
        c.engine(0).certs.contains_key(&slot),
        "vacuous: a wanted certificate was not taken"
    );
}

/// B51 witness: an answer brings at most one certificate per request this
/// node sent for the slot. A member's junk answer of 64 certificates (a real
/// signature over another body) costs nothing before this node asked, one
/// failed check once it asked, and the slot still certifies from honest
/// answers. Before, every one of the 64 was checked.
#[test]
fn junk_answers_cost_one_check_per_request_sent() {
    let mut c = Cluster::new("junk-answers", 4, 0);
    c.run(30);
    let mut held = c.engine(0).certs.values().cloned();
    let cert = held.next().unwrap();
    let other = held.next().unwrap();
    let slot = (cert.body.round, cert.body.author.clone());
    c.engines[0].as_mut().unwrap().certs.remove(&slot);
    let mut junk = cert.clone();
    junk.aggregate_signature = other.aggregate_signature.clone();
    let answer = Msg::Resp {
        to: c.members[0].info.address.clone(),
        resp: pull::Response::Certs {
            certs: vec![junk; 64],
            unknown: vec![],
        },
    };
    c.engines[0].as_mut().unwrap().want_cert(slot.0, &slot.1);
    let ((), failed) = crate::work::failed_in(|| c.receive(0, answer.clone()));
    assert_eq!(failed, 0, "checked before this node asked");
    let net = c.net(0);
    c.engines[0].as_mut().unwrap().send_due(&net);
    let ((), failed) = crate::work::failed_in(|| c.receive(0, answer.clone()));
    assert_eq!(failed, 1, "one check for the one request sent");
    c.run_until(30, |c| c.engine(0).certs.contains_key(&slot));
    assert!(
        c.engine(0).certs.contains_key(&slot),
        "the slot never certified from honest answers"
    );
}

/// DOS-6: one Byzantine member's signed E+1 vertex (verdict `Ahead`) makes
/// every honest node want every author's certificate for 257 rounds, each
/// want holding its own copy of the n−1 member addresses; all of them are
/// due at once, to the same first target. Measured at n = 64.
#[test]
fn dos_one_ahead_vertex_creates_n_squared_want_state_and_a_request_burst() {
    let n: u8 = 64;
    let mut members: Vec<Member> = (1..=n).map(member).collect();
    members.sort_by(|a, b| a.info.address.cmp(&b.info.address));
    let committee: Vec<ValidatorInfo> = members.iter().map(|m| m.info.clone()).collect();
    let db = TempDb::new("dos-ahead");
    let storage = Arc::new(StateDB::open(db.0.to_str().unwrap()).unwrap());
    let cfg = Config {
        chain_id: CHAIN.into(),
        genesis_identity: GENESIS.into(),
        committee: committee.clone(),
        node_key: members[0].node_key,
        address: members[0].info.address.clone(),
        b_auth: staging::B_AUTH,
        epoch_interval: 0,
    };
    let mut engine = Engine::open(storage, cfg, true, Arc::new(|| NOW)).unwrap();
    let byz = &members[1];
    let mut v = Vertex {
        epoch: 1,
        round: 1_000_000,
        author: byz.info.address.clone(),
        parents: vec!["a".repeat(64)],
        parent_refs: vec![],
        payload: vec![],
        timestamp: NOW,
        hash: String::new(),
        signature: String::new(),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
    };
    v.hash = v.hash_v4_with_domain(CHAIN, GENESIS);
    v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&byz.node_key));
    let q: Queue = Rc::new(RefCell::new(VecDeque::new()));
    let net = Net {
        from: members[0].info.address.clone(),
        q: Rc::clone(&q),
    };
    let len = serde_json::to_string(&v).unwrap().len();
    engine.on_message(len, Msg::Vertex(v), &net);
    let wants = engine.cert_wants.len();
    let target_strings = wants * (n as usize - 1);
    let t = std::time::Instant::now();
    engine.tick(&net);
    let tick_time = t.elapsed();
    let reqs: Vec<String> = q
        .borrow()
        .iter()
        .filter_map(|e| match (&e.msg, &e.to) {
            (Msg::Req(_), To::One(to)) => Some(to.clone()),
            _ => None,
        })
        .collect();
    let distinct: HashSet<&String> = reqs.iter().collect();
    eprintln!(
        "n={n}: one Ahead vertex -> {wants} certificate wants holding {target_strings} address strings \
         (~{} MiB), first tick {tick_time:?}: {} signed requests to {} target(s); each request is a \
         broadcast to n-1 peers in the node",
        target_strings * 88 / (1 << 20),
        reqs.len(),
        distinct.len()
    );
    // The wants share one peer list (memory is per want, not per want and
    // peer), the first tick sends a paced batch, not a burst, and the
    // rotation spreads it over several peers.
    assert!(wants > 0, "vacuous: the Ahead vertex made no wants");
    assert!(
        reqs.len() <= pull::CLIENT_REQS_PER_TICK,
        "{} requests in one tick",
        reqs.len()
    );
    assert!(distinct.len() > 1, "every request went to one peer");
}

/// DOS-7: `early_certs` (EP-5) has no dedup. Replays of ONE valid E+1
/// certificate (public: it was gossiped) fill the 4096 cap, every copy costing
/// a pairing now and again at activation, and every genuine early certificate
/// after that is dropped.
#[test]
fn dos_replays_of_one_early_certificate_fill_the_cap_and_drop_the_rest() {
    let mut c = Cluster::with_epochs("dos-early", 4, 0, 4);
    c.run_until(80, |c| {
        (0..4).all(|i| epoch_of(c, i).0 == 1)
            && c.engine(1).certs.values().filter(|k| k.body.epoch == 1).count() >= 2
    });
    let mut e1: Vec<VertexCertificate> = c
        .engine(1)
        .certs
        .values()
        .filter(|k| k.body.epoch == 1)
        .cloned()
        .collect();
    e1.sort_by_key(|k| (k.body.round, k.body.author.clone()));
    assert!(e1.len() >= 2, "vacuous: no epoch-1 certificates");
    // Node 0 closed epoch 0 but has not activated epoch 1 (a host waiting for QC(H_0)).
    c.engine(0).storage.delete(epoch::EPOCH_ACTIVE_KEY).unwrap();
    c.epoch_interval = 0;
    c.reopen(0);
    assert_eq!(epoch_of(&c, 0).0, 0);
    assert!(c.engine(0).next_start().is_some());
    for _ in 0..5000 {
        c.receive(0, Msg::Cert(e1[0].clone()));
    }
    c.receive(0, Msg::Cert(e1[1].clone()));
    let kept = c.engine(0).early_certs.len();
    let distinct: HashSet<(u64, String)> = c
        .engine(0)
        .early_certs
        .iter()
        .map(|k| (k.body.round, k.body.author.clone()))
        .collect();
    eprintln!("{kept} early certificates kept, {} distinct", distinct.len());
    assert!(
        distinct.contains(&(e1[1].body.round, e1[1].body.author.clone())),
        "a genuine early certificate was dropped: {kept} kept, {} distinct",
        distinct.len()
    );
}

// ---------------------------------------- final review (test quality): kill tests

// ------------------------------------------------ review probes (rev_tests)





// ------------------------------------------- review kill tests (rev_tests)

/// KILL(M01), AT-1/IN-1 E4: an honest node never stages or attests a vertex
/// whose parent ref names a digest other than the slot's certified one, even
/// though it holds a certificate for that slot. A Byzantine author's round-3
/// vertex cites its own uncertified round-2 twin B while A is certified.
#[test]
fn kill_m01_a_ref_to_an_uncertified_twin_is_never_attested() {
    let mut c = Cluster::new("kill-m01", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    c.tick_all();
    c.deliver(&|_, _| false);
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    let honest: Vec<usize> = c.validators().filter(|&i| i != byz).collect();
    let h = honest[0];
    assert_eq!(
        c.engine(h).certified(2, &a.author),
        Some(a.hash.as_str()),
        "vacuous: A is not certified at h"
    );
    let mut refs: Vec<ParentRef> = Vec::new();
    for m in &c.committee {
        let cert = c
            .engine(h)
            .certs
            .get(&(2, m.address.clone()))
            .expect("vacuous: round 2 is not certified")
            .clone();
        let twin = m.address == a.author;
        refs.push(ParentRef {
            round: 2,
            author: m.address.clone(),
            digest: if twin { b.hash.clone() } else { cert.body.digest.clone() },
            proof: None,
            cert: if twin { None } else { Some(cert.compact()) },
        });
    }
    let mut w = Vertex {
        epoch: EPOCH,
        round: 3,
        author: a.author.clone(),
        parents: refs.iter().map(|r| r.digest.clone()).collect(),
        parent_refs: refs,
        payload: vec![],
        timestamp: NOW,
        hash: String::new(),
        signature: String::new(),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
    };
    w.hash = w.hash_v4_with_domain(CHAIN, GENESIS);
    w.sign_with_ed25519(&crypto::SigningKey::from_bytes(&c.members[byz].node_key));
    for &i in &honest {
        c.receive(i, Msg::Vertex(w.clone()));
    }
    let attested = c
        .q
        .borrow()
        .iter()
        .filter(|e| matches!(&e.msg, Msg::Attest(att) if att.body.digest == w.hash))
        .count();
    assert_eq!(attested, 0, "an honest node attested a vertex citing an uncertified twin");
    for &i in &honest {
        assert!(!c.engine(i).is_staged(&w.hash), "node {i} staged it");
    }
}

/// KILL(M60), GC-3: GC deletes a node's attestation guards only at or below
/// g − RETAIN_SLACK; every guard above the cut survives (the existing guard
/// witness is masked by the slot's certificate, which also refuses a twin).
#[test]
fn kill_m60_guards_above_the_cut_survive_gc() {
    let mut c = Cluster::new("kill-m60", 4, 0);
    c.run(130);
    let e0 = c.engine(0);
    let g = e0.floor();
    assert!(g > staging::RETAIN_SLACK + 2, "vacuous: g = {g}");
    let cut = g - staging::RETAIN_SLACK;
    let author = c.members[1].info.address.clone();
    let mut checked = 0;
    for r in (cut + 1)..=g {
        if let Some(v) = c.engine(1).own_proposal(r) {
            let body = e0.attest_body(r, &author, &v.hash);
            assert!(
                e0.read_own_attestation(&body).unwrap().is_some(),
                "node 0's guard for round {r} (cut {cut}) is gone"
            );
            checked += 1;
        }
    }
    assert!(checked > 10, "vacuous: {checked} guards checked");
}

/// KILL(M60), the unmasked guard witness: node 0 attested X at a round above
/// g (so ingress does not refuse it as STALE) before the last GC, and does not
/// hold X's certificate. A twin of X must still be refused by the guard alone.
#[test]
fn kill_m60_a_twin_above_the_cut_is_refused_by_the_guard_alone() {
    let mut c = Cluster::new("kill-m60b", 4, 0);
    c.run(130);
    let g = c.engine(0).floor();
    let author = c.members[1].info.address.clone();
    let r = (g + 1..=g + 10)
        .find(|r| c.engine(1).own_proposal(*r).is_some())
        .expect("a round above g");
    let x = c.engine(1).own_proposal(r).unwrap().clone();
    // Simulate "the certificate never reached node 0": drop it from node 0's
    // index (as a node that attested X and then lost every copy of the
    // certificate would be); the guard row must still refuse the twin.
    c.engines[0].as_mut().unwrap().certs.remove(&(r, author.clone()));
    let twin = twin_of(&x, &c.members[1].node_key, "late-twin");
    c.receive(0, Msg::Vertex(twin.clone()));
    let signed = c
        .q
        .borrow()
        .iter()
        .filter(|e| matches!(&e.msg, Msg::Attest(att) if att.body.digest == twin.hash))
        .count();
    assert_eq!(signed, 0, "a twin above the cut was attested after GC");
}


/// KILL(M12..M15), EP-2 clause by clause: each malformed proposal alone is
/// refused (so it carries C_E over), and zero-stake entries are dropped.
#[test]
fn kill_ep2_each_committee_clause_is_enforced() {
    let good: Vec<ValidatorInfo> = (1..=4).map(|s| member(s).info).collect();
    assert!(epoch::validate_committee(&good).is_ok(), "vacuous: the base set fails");
    // M12: one address twice.
    let mut dup = good.clone();
    dup.push(good[0].clone());
    assert!(epoch::validate_committee(&dup).is_err(), "a duplicated member was admitted");
    // M13: an Ed25519 key that does not derive its address (the BLS key and
    // PoP are the member's own, so only the derivation clause can refuse it).
    let mut swapped = good.clone();
    swapped[1].ed25519_public_key = good[2].ed25519_public_key.clone();
    assert!(epoch::validate_committee(&swapped).is_err(), "a non-deriving key was admitted");
    // M14: more than 256 members.
    let mut over: Vec<ValidatorInfo> = (0..=255u8).map(|s| member(s).info).collect();
    // 256 distinct seeds exist (0..=255); a 257th entry needs a new key.
    let k257: [u8; 32] = {
        let mut k = [9u8; 32];
        k[0] = 1;
        k[1] = 2;
        k
    };
    let ed = crypto::SigningKey::from_bytes(&k257).verifying_key().to_bytes();
    let bls = BLSEngine::consensus();
    let bls_seed = derive_validator_bls_seed(&k257);
    over.push(ValidatorInfo {
        address: crypto::derive_address(&ed).unwrap(),
        stake: 100,
        ed25519_public_key: hex::encode(ed),
        bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
        bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
    });
    assert_eq!(over.len(), 257);
    assert!(epoch::validate_committee(&over[..256]).is_ok(), "vacuous: 256 is refused");
    assert!(epoch::validate_committee(&over).is_err(), "257 members were admitted");
    // M15: a zero-stake entry is dropped, not kept.
    let mut zero = good.clone();
    let mut z = member(9).info;
    z.stake = 0;
    zero.push(z.clone());
    let out = epoch::validate_committee(&zero).unwrap();
    assert!(out.iter().all(|m| m.address != z.address), "a zero-stake member was kept");
}

/// KILL(M05), PR-1 with unequal stake: a node holding round-1 certificates
/// from three authors that carry less than 2/3 of the stake has no round
/// quorum and proposes no round-2 vertex (which every peer would refuse at
/// Layer S, burning the slot).
#[test]
fn kill_m05_the_round_quorum_is_by_stake_not_by_count() {
    let mut c = Cluster::new("kill-m05", 4, 0);
    let stakes = [4000u64, 3000, 2000, 1000];
    for (m, s) in c.committee.iter_mut().zip(stakes) {
        m.stake = s;
    }
    for i in c.validators() {
        c.reopen(i);
    }
    let heavy = c.members[0].info.address.clone();
    let x = 3; // stake 1000
    c.tick_all();
    let h = heavy.clone();
    c.deliver(&move |e, to| to == x && e.from == h && matches!(&e.msg, Msg::Cert(_)));
    assert!(c.engine(x).certified(1, &heavy).is_none(), "vacuous: x holds the heavy cert");
    let light: usize = (1..4)
        .filter(|&i| c.engine(x).certified(1, &c.members[i].info.address).is_some())
        .count();
    assert_eq!(light, 3, "vacuous: x lacks a light certificate");
    c.tick(x);
    assert!(
        c.engine(x).own_proposal(2).is_none(),
        "x proposed round 2 on 6000 of 10000 stake"
    );
}

/// KILL(M07), EP-3: once E has closed (H_E accepted) and before E+1 is
/// active, the node proposes no epoch-E vertex.
#[test]
fn kill_m07_no_proposal_between_close_and_activation() {
    let mut c = Cluster::new("kill-m07", 4, 0);
    c.run(6);
    let d = c.decisions[0].last().expect("vacuous: nothing decided").clone();
    let committee = c.committee.clone();
    c.engines[0]
        .as_mut()
        .unwrap()
        .close_epoch(d.0, &d.1, "boundary-block", &committee)
        .unwrap();
    let next = c.engine(0).current_round();
    assert!(c.engine(0).own_proposal(next).is_none(), "vacuous: already proposed");
    c.tick(0);
    assert!(
        c.engine(0).own.keys().all(|r| *r < next),
        "an epoch-E vertex was proposed after the close"
    );
}

/// KILL(M79), RC-3: a guard database whose origin row was written for another
/// chain (same keys) is not continuous for this one: the node abstains.
#[test]
fn kill_m79_a_guard_origin_of_another_chain_abstains() {
    let mut c = Cluster::new("kill-m79", 4, 0);
    let other = guard_origin("ANOTHER-CHAIN", GENESIS, &c.members[0].node_key);
    c.engine(0).storage.put("consensus:guard_origin", &other).unwrap();
    c.reopen(0);
    let me = c.members[0].info.address.clone();
    let signed = Cell::new(0);
    for _ in 0..4 {
        c.tick_all();
        c.deliver(&|e, _| {
            if e.from == me && matches!(e.msg, Msg::Attest(_)) {
                signed.set(signed.get() + 1);
            }
            false
        });
    }
    assert_eq!(signed.get(), 0, "a node under another chain's guard origin attested");
    assert!(c.engine(0).own.is_empty(), "it proposed");
}

/// KILL(M80), RC-3: a database that holds blocks (a resynced store) but no
/// guard rows never takes a first origin, even with the init flag set.
#[test]
fn kill_m80_a_synced_database_never_takes_a_guard_origin() {
    let mut c = Cluster::new("kill-m80", 4, 0);
    c.engine(0).storage.delete("consensus:guard_origin").unwrap();
    c.engine(0).storage.put("latest_height", "5").unwrap();
    c.engines[0] = None;
    c.open(0, true);
    assert!(
        c.engine(0).storage.get("consensus:guard_origin").unwrap().is_none(),
        "a store with 5 blocks took a first guard origin"
    );
}

/// KILL(M19), EP-3: E+1's sentinel is EPOCH_GENESIS over the chain, E+1, its
/// first round, H_E's hash and A*, exactly.
#[test]
fn kill_m19_the_sentinel_binds_the_boundary_block_and_anchor() {
    let mut c = Cluster::with_epochs("kill-m19", 4, 0, 3);
    c.run_until(40, |c| c.engine(0).epoch >= 1);
    let start: epoch::EpochStart = serde_json::from_str(
        &c.engine(0).storage.get(&epoch::epoch_start_key(1)).unwrap().unwrap(),
    )
    .unwrap();
    assert!(!start.prev_block_hash.is_empty() && !start.prev_anchor.is_empty());
    assert_eq!(
        start.sentinel,
        blockchain::epoch_genesis(
            CHAIN,
            GENESIS,
            1,
            start.first_round,
            &start.prev_block_hash,
            &start.prev_anchor
        )
    );
}

/// KILL(M25), RE-5: only the addressee answers a request (in the node every
/// request is gossiped to everyone).
#[test]
fn kill_m25_only_the_addressee_answers() {
    let mut c = Cluster::new("kill-m25", 4, 0);
    c.run(2);
    let from = c.members[0].info.address.clone();
    let to = c.members[1].info.address.clone();
    let req = pull::SignedRequest::sign(
        CHAIN,
        GENESIS,
        &c.members[0].node_key,
        &from,
        &to,
        1,
        pull::Request::Certs { epoch: 0, slots: vec![(1, to.clone())] },
    );
    c.receive(2, Msg::Req(req));
    let answers = c
        .q
        .borrow()
        .iter()
        .filter(|e| matches!(&e.msg, Msg::Resp { .. }))
        .count();
    assert_eq!(answers, 0, "a node answered a request addressed to another");
}

/// KILL(M27), RE-5: a VERTEX_RESP carries at most MAX_RESP_BYTES of bodies;
/// the rest is `unknown` (asked again).
#[test]
fn kill_m27_a_vertex_answer_respects_the_byte_cap() {
    let c = Cluster::new("kill-m27", 4, 0);
    let e = c.engine(0);
    let mut digests = Vec::new();
    // 31 bodies of 100 KiB and, last, a small one: MAX_REQ_DIGESTS (32) in
    // all, so every digest is looked at.
    for k in 0..31u64 {
        let mut v = Vertex {
            epoch: EPOCH,
            round: 1,
            author: c.members[1].info.address.clone(),
            parents: vec![SENTINEL.into()],
            parent_refs: vec![],
            payload: vec!["x".repeat(100 * 1024)],
            timestamp: NOW + k,
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
        };
        v.hash = v.hash_v4_with_domain(CHAIN, GENESIS);
        digests.push(v.hash.clone());
        lock(&e.dag).insert(v.hash.clone(), v);
    }
    // B110: past the first body that does not fit nothing more is measured,
    // so a small body asked after it is not served either.
    let mut small = Vertex {
        epoch: EPOCH,
        round: 1,
        author: c.members[2].info.address.clone(),
        parents: vec![SENTINEL.into()],
        parent_refs: vec![],
        payload: vec![],
        timestamp: NOW,
        hash: String::new(),
        signature: String::new(),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
    };
    small.hash = small.hash_v4_with_domain(CHAIN, GENESIS);
    digests.push(small.hash.clone());
    lock(&e.dag).insert(small.hash.clone(), small.clone());
    let pull::Response::Vertices { bodies, unknown } = e.serve(&pull::Request::Vertices(digests))
    else {
        panic!("wrong answer kind")
    };
    let bytes: usize = bodies.iter().map(|v| serde_json::to_string(v).unwrap().len()).sum();
    assert!(bytes <= pull::MAX_RESP_BYTES, "{bytes} bytes answered");
    assert!(!unknown.is_empty(), "vacuous: everything fit");
    assert!(unknown.contains(&small.hash), "measured past a full answer");
}

// ---------------------------------------- final review: remaining witnesses

/// EP-3: once E has closed, this node signs nothing of E. White-box: the
/// slot's attestation guard row is removed, so only the close can stop it.
#[test]
fn a_closed_epoch_is_never_attested() {
    let mut c = Cluster::with_epochs("s9-closed-attest", 4, 0, 4);
    for _ in 0..60 {
        if epoch_of(&c, 0).0 == 1 {
            break;
        }
        c.tick_all();
        c.deliver(&|_, _| false);
    }
    assert_eq!(epoch_of(&c, 0).0, 1);
    // Back to "epoch 0 closed, epoch 1 not active" (the lost activation write).
    c.engine(0).storage.delete(epoch::EPOCH_ACTIVE_KEY).unwrap();
    c.reopen(0);
    let me = c.members[0].info.address.clone();
    let (v, body) = {
        let e = c.engine(0);
        let closing = e.closing_round.expect("epoch 0 is closed");
        let v = lock(&e.dag)
            .values()
            .filter(|v| v.epoch == 0 && v.round <= closing && v.author != me)
            .max_by_key(|v| v.round)
            .cloned()
            .expect("an epoch-0 body is held");
        let body = e.attest_body(v.round, &v.author, &v.hash);
        (v, body)
    };
    let bls_pk = hex::encode(
        BLSEngine::consensus().pubkey_raw(&derive_validator_bls_seed(&c.members[0].node_key)),
    );
    c.engine(0)
        .storage
        .delete(&vcert::attest_guard_key(&body, &bls_pk))
        .unwrap();
    assert!(c.engine(0).read_own_attestation(&body).unwrap().is_none());
    let net = c.net(0);
    c.engines[0].as_mut().unwrap().stage_and_attest(v, &net);
    assert!(
        c.engine(0).read_own_attestation(&body).unwrap().is_none(),
        "a slot of the closed epoch was attested"
    );
}

/// Client pacing covers body fetches too: however many bodies are due, one
/// tick sends at most `CLIENT_REQS_PER_TICK` requests.
#[test]
fn body_fetches_are_paced_per_tick() {
    let mut c = Cluster::new("pace-bodies", 4, 0);
    c.run(6);
    let cert = c.engine(0).certs.values().next().cloned().unwrap();
    {
        let e = c.engines[0].as_mut().unwrap();
        for k in 0..(pull::CLIENT_REQS_PER_TICK * pull::MAX_REQ_DIGESTS * 3) {
            let mut fake = cert.clone();
            fake.body.digest = format!("{:064x}", 0xabc000 + k);
            e.want_body(&fake);
        }
    }
    c.q.borrow_mut().clear();
    let net = c.net(0);
    c.engines[0].as_mut().unwrap().send_due(&net);
    let reqs = c
        .q
        .borrow()
        .iter()
        .filter(|x| matches!(x.msg, Msg::Req(_)))
        .count();
    assert!(
        reqs > 0 && reqs <= pull::CLIENT_REQS_PER_TICK,
        "{reqs} requests in one tick"
    );
}

// ---------------------------------------------------------------------------
// G5 S4c: the V4 twins of the three V3 consensus controls deleted with V3
// (`test_h3_tier2_*` and `complete_signed_history_*`). Same schedules, with
// certificates; same assertions.

/// `v` re-cited: `refs` replace its parents, re-hashed and re-signed by `key`.
fn recite(v: &Vertex, refs: Vec<ParentRef>, key: &[u8; 32]) -> Vertex {
    let mut w = v.clone();
    w.parents = refs.iter().map(|r| r.digest.clone()).collect();
    w.parent_refs = refs;
    w.hash = w.hash_v4_with_domain(CHAIN, GENESIS);
    w.sign_with_ed25519(&crypto::SigningKey::from_bytes(key));
    w
}

/// `node`'s certified ref to (round, author), embedded certificate included.
fn cert_ref(c: &Cluster, node: usize, round: u64, author: &str) -> ParentRef {
    let cert = c
        .engine(node)
        .certs
        .get(&(round, author.to_string()))
        .expect("the parent is certified");
    ParentRef {
        round,
        author: author.to_string(),
        digest: cert.body.digest.clone(),
        proof: None,
        cert: Some(cert.compact()),
    }
}

/// Every honest node and observer refuses `v`: none holds it in any role.
fn refused_everywhere(c: &Cluster, byz: usize, v: &Vertex) {
    for i in (0..c.members.len()).filter(|&i| i != byz) {
        assert!(
            !c.engine(i).is_staged(&v.hash),
            "node {i} admitted {}",
            v.hash
        );
    }
}

/// The first anchor round whose leader differs from the next anchor round's:
/// the H3 schedules need an honest leader at `r` and a Byzantine one at `r + 2`.
fn h3_rounds(c: &Cluster) -> (u64, usize, usize) {
    let r = (1..8u64)
        .map(|k| 2 * k)
        .find(|&r| c.leader(r) != c.leader(r + 2))
        .expect("two consecutive anchor rounds with distinct leaders");
    (r, c.leader(r), c.leader(r + 2))
}

/// The twin of `test_h3_tier2_stateless_gate_prevents_the_ancestry_fork`.
/// The leader of anchor round r+2 is Byzantine: at rounds r+1 and r+2 it
/// sends one-parent vertices whose history excludes round r's leader, each
/// parent certified (so no missing certificate can be what holds them).
/// Observer X gets every push; observer Y loses the two other honest
/// round-(r+1) bodies (it pulls them later). Every node refuses both thin
/// vertices from their bytes alone (Layer S), so no node can anchor on them,
/// and every node commits round r's leader in one sequence.
///
/// MUTATION: drop `parent_refs_admissible_above` from Layer S → red.
#[test]
fn v4_thin_byzantine_vertices_are_refused_alike_and_the_leader_commits() {
    let mut c = Cluster::new("h3-thin", 4, 2);
    let (r, l, byz) = h3_rounds(&c);
    let (x, y) = (4, 5);
    let byz_addr = c.members[byz].info.address.clone();
    let l_addr = c.members[l].info.address.clone();
    let lossy: Vec<String> = c
        .validators()
        .filter(|&i| i != l && i != byz)
        .map(|i| c.members[i].info.address.clone())
        .collect();
    assert_eq!(lossy.len(), 2, "the scenario needs exactly two omissions");
    let lossy_first = c.index_of(&lossy[0]);
    // The Byzantine author's own bodies at rounds r+1 and r+2 never leave it
    // (it sends the crafted ones instead), and it serves no pull.
    let lost = Cell::new(0);
    let map = |e: &Envelope, to: usize| -> Option<Msg> {
        let from_byz = e.from == byz_addr;
        match &e.msg {
            Msg::Vertex(v)
                if from_byz && v.author == byz_addr && (v.round == r + 1 || v.round == r + 2) =>
            {
                None
            }
            Msg::Req(_) | Msg::Resp { .. } if from_byz => None,
            Msg::Vertex(v)
                if v.round == r + 1
                    && lossy.contains(&v.author)
                    && to == y
                    && e.from == v.author =>
            {
                lost.set(lost.get() + 1);
                None
            }
            m => Some(m.clone()),
        }
    };
    let (mut thin1, mut thin2): (Option<Vertex>, Option<Vertex>) = (None, None);
    let key = c.members[byz].node_key;
    for _ in 0..(24 + 2 * r as usize) {
        c.tick_all();
        c.deliver_map(&map);
        if thin1.is_none() {
            if let Some(own) = c.engine(byz).own_proposal(r + 1).cloned() {
                // ONE parent, and not round r's leader.
                let p = own
                    .parent_refs
                    .iter()
                    .find(|p| p.author != l_addr)
                    .expect("a non-leader parent")
                    .clone();
                let v = recite(&own, vec![p], &key);
                c.q.borrow_mut().push_back(Envelope {
                    from: byz_addr.clone(),
                    to: To::All,
                    msg: Msg::Vertex(v.clone()),
                });
                thin1 = Some(v);
            }
        }
        if let (Some(_), None) = (&thin1, &thin2) {
            if let Some(own) = c.engine(byz).own_proposal(r + 2).cloned() {
                // ONE certified parent (an honest one): only Layer S's stake
                // clause can refuse it, never a missing certificate.
                let honest = c.members[lossy_first].info.address.clone();
                let p = cert_ref(&c, byz, r + 1, &honest);
                let v = recite(&own, vec![p], &key);
                c.q.borrow_mut().push_back(Envelope {
                    from: byz_addr.clone(),
                    to: To::All,
                    msg: Msg::Vertex(v.clone()),
                });
                thin2 = Some(v);
            }
        }
        c.deliver_map(&map);
    }
    let thin1 = thin1.expect("the Byzantine author reached round r+1");
    let thin2 = thin2.expect("the Byzantine author reached round r+2");
    assert_eq!(thin1.parent_refs.len(), 1);
    assert_eq!(thin2.parent_refs.len(), 1);
    assert!(thin1.parent_refs[0].cert.is_some() && thin2.parent_refs[0].cert.is_some());
    assert_ne!(thin1.parent_refs[0].author, l_addr);
    refused_everywhere(&c, byz, &thin1);
    refused_everywhere(&c, byz, &thin2);
    c.assert_agree_except(Some(byz));
    let a = c.engine(l).own_proposal(r).unwrap().hash.clone();
    for i in (0..c.members.len()).filter(|&i| i != byz) {
        assert_eq!(
            c.anchor(i, r).map(|d| d.1.as_str()),
            Some(a.as_str()),
            "node {i} did not commit round {r}'s leader"
        );
        assert!(
            c.decisions[i].iter().any(|d| d.0 > r + 2),
            "node {i} made no progress past the Byzantine round"
        );
    }
    // X (every push) and Y (two lost) both decided it.
    assert!(c.anchor(x, r).is_some() && c.anchor(y, r).is_some());
    assert!(lost.get() >= 2, "Y lost no push");
}

/// The twin of `test_h3_tier2_round_skipping_anchor_is_refused`. The leader
/// of anchor round r+2 is Byzantine and cites, at round r+2, the three
/// round-r vertices other than round r's leader, each with its genuine
/// certificate: 3 of 4 stake, so the stake clause admits it, and its history
/// skips round r+1 and round r's leader. The round clause refuses it on
/// every node, while every honest round-(r+2) vertex is admitted.
///
/// MUTATION: drop the round clause of `parent_refs_admissible_above` → red.
#[test]
fn v4_a_round_skipping_anchor_is_refused_and_honest_vertices_are_not() {
    let mut c = Cluster::new("h3-skip", 4, 1);
    let (r, l, byz) = h3_rounds(&c);
    let byz_addr = c.members[byz].info.address.clone();
    let map = |e: &Envelope, _: usize| -> Option<Msg> {
        match &e.msg {
            Msg::Vertex(v) if e.from == byz_addr && v.author == byz_addr && v.round == r + 2 => {
                None
            }
            m => Some(m.clone()),
        }
    };
    let mut skip: Option<Vertex> = None;
    for _ in 0..(24 + 2 * r as usize) {
        c.tick_all();
        c.deliver_map(&map);
        if skip.is_none() {
            if let Some(own) = c.engine(byz).own_proposal(r + 2).cloned() {
                let refs: Vec<ParentRef> = c
                    .validators()
                    .filter(|&i| i != l)
                    .map(|i| cert_ref(&c, byz, r, &c.members[i].info.address))
                    .collect();
                let v = recite(&own, refs, &c.members[byz].node_key);
                c.q.borrow_mut().push_back(Envelope {
                    from: byz_addr.clone(),
                    to: To::All,
                    msg: Msg::Vertex(v.clone()),
                });
                skip = Some(v);
            }
        }
        c.deliver_map(&map);
    }
    let skip = skip.expect("the Byzantine author reached round r+2");
    // The stake clause is not what refuses it.
    assert_eq!(skip.parent_refs.len(), 3);
    assert!(skip
        .parent_refs
        .iter()
        .all(|p| p.round == r && p.cert.is_some()));
    let authors: std::collections::HashSet<&str> =
        skip.parent_refs.iter().map(|p| p.author.as_str()).collect();
    assert_eq!(authors.len(), 3);
    assert!(!authors.contains(c.members[l].info.address.as_str()));
    assert!(qc::stake_quorum_met(300, 400));
    refused_everywhere(&c, byz, &skip);
    // Non-vacuity: every honest round-(r+2) vertex is admitted everywhere.
    for author in c.validators().filter(|&i| i != byz) {
        let v = c
            .engine(author)
            .own_proposal(r + 2)
            .expect("proposed")
            .hash
            .clone();
        for i in (0..c.members.len()).filter(|&i| i != byz) {
            assert!(
                c.engine(i).is_staged(&v),
                "node {i} refused an honest vertex"
            );
        }
    }
    c.assert_agree_except(Some(byz));
    for i in (0..c.members.len()).filter(|&i| i != byz) {
        assert!(
            c.anchor(i, r).is_some(),
            "node {i} did not decide round {r}"
        );
        assert!(
            c.decisions[i].iter().any(|d| d.0 > r + 2),
            "node {i} stalled"
        );
    }
}

/// The twin of `complete_signed_history_decides_after_retransmission_and_reopen`.
/// Round 2's leader takes part through round 3 and is silent after. Observer
/// X gets every message once; observer Y gets every message, then all of them
/// three more times, then reopens. Y's decisions match X's (anchor round and
/// digest, sequence, finality digest), the replays change nothing, each one
/// is a durable decision row, and the reopened Y goes on agreeing. Observer
/// Z, offline throughout, then gets Y's whole history in reverse order three
/// times and reopens: it decides what X decided (G5 review: an order other
/// than the live one, so the test is not idempotence alone).
#[test]
fn v4_complete_signed_history_decides_after_retransmission_and_reopen() {
    let mut c = Cluster::new("history", 4, 3);
    let (x, y, z) = (4, 5, 6);
    let quiet = c.leader(2);
    let quiet_addr = c.members[quiet].info.address.clone();
    let z_addr = c.members[z].info.address.clone();
    let log: RefCell<Vec<Msg>> = RefCell::new(Vec::new());
    let round_of = |m: &Msg| match m {
        Msg::Vertex(v) => Some(v.round),
        Msg::Attest(a) => Some(a.body.round),
        Msg::Cert(cert) => Some(cert.body.round),
        _ => None,
    };
    let map = |e: &Envelope, to: usize| -> Option<Msg> {
        if e.from == quiet_addr && round_of(&e.msg).is_none_or(|r| r > 3) {
            return None;
        }
        if to == z || e.from == z_addr {
            return None;
        }
        if to == y {
            log.borrow_mut().push(e.msg.clone());
        }
        Some(e.msg.clone())
    };
    for _ in 0..16 {
        c.tick_all();
        c.deliver_map(&map);
    }
    let a = c.engine(quiet).own_proposal(2).unwrap().hash.clone();
    let dx = c.anchor(x, 2).expect("X decided round 2").clone();
    assert_eq!(dx.1, a, "round 2 commits its leader's vertex");
    assert!(
        c.decisions[x].iter().any(|d| d.0 > 4),
        "X stalled after the leader went quiet"
    );
    assert_eq!(c.decisions[y], c.decisions[x], "Y decided differently");
    let decided = c.decisions[y].clone();
    let digest = c.engine(y).finality_digest();
    let messages = log.borrow().clone();
    assert!(!messages.is_empty());
    for _ in 0..3 {
        for m in &messages {
            c.receive(y, m.clone());
        }
    }
    assert_eq!(c.decisions[y], decided, "a replay decided again");
    assert_eq!(c.engine(y).finality_digest(), digest);
    c.reopen(y);
    assert_eq!(
        c.engine(y).finality_digest(),
        digest,
        "the reopen lost decisions"
    );
    for m in &messages {
        c.receive(y, m.clone());
    }
    assert_eq!(
        c.decisions[y], decided,
        "a replay after the reopen decided again"
    );
    for _ in 0..8 {
        c.tick_all();
        c.deliver_map(&map);
    }
    assert!(
        c.decisions[y].len() > decided.len(),
        "Y stopped deciding after the reopen"
    );
    for d in &decided {
        assert_eq!(
            decision_row(&c, y, d.0),
            Some(format!("C:{}", d.1)),
            "Y's decision at round {} is not durable",
            d.0
        );
    }

    // Z: the same history, reversed, three times, then a reopen.
    assert!(c.decisions[z].is_empty(), "Z was not offline");
    let mut reversed = messages.clone();
    reversed.reverse();
    for _ in 0..3 {
        for m in &reversed {
            c.receive(z, m.clone());
        }
    }
    c.reopen(z);
    for m in &reversed {
        c.receive(z, m.clone());
    }
    c.deliver_map(&map);
    let dz = c.decisions[z].clone();
    assert!(
        dz.iter().any(|d| d == &dx),
        "Z did not decide round 2 as X did: {:?}",
        dz.iter().map(|d| d.0).collect::<Vec<_>>()
    );
    assert_eq!(
        dz[..],
        c.decisions[x][..dz.len()],
        "Z decided differently from X"
    );
    for d in &dz {
        assert_eq!(decision_row(&c, z, d.0), Some(format!("C:{}", d.1)));
    }
    c.assert_agree_except(Some(quiet));
}

/// B95 witness, end to end: the engine remembers each body whose payload it
/// checked, so of three plain twins of one slot it checks two and drops the
/// third unchecked.
#[test]
fn an_engine_checks_two_plain_twins_of_a_slot_and_not_a_third() {
    let mut c = Cluster::new("payload-slots", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    let h0 = c.validators().find(|&i| i != byz).unwrap();
    c.tick_all();
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let b = twin_of(&a, &c.members[byz].node_key, "twin-b");
    let cc = twin_of(&a, &c.members[byz].node_key, "twin-c");
    let net = c.net(h0);
    let checks = || ingress_v4::PAYLOAD_CHECKS.with(|n| n.get());
    let before = checks();
    for v in [&a, &b, &cc] {
        let len = serde_json::to_string(v).unwrap().len();
        c.engines[h0]
            .as_mut()
            .unwrap()
            .on_vertex(len, v.clone(), &net);
    }
    assert!(c.engine(h0).is_staged(&a.hash), "vacuous: a did not stage");
    assert_eq!(
        checks() - before,
        2,
        "the third plain body's payload was checked"
    );
}

/// B95 witness: the engine checks at most two bodies' payloads per (epoch,
/// round, author), a third only when it is certified (a certified twin evicts
/// a plain one), and a body checked before is not checked again (a wake).
#[test]
fn a_third_body_of_one_slot_is_not_checked() {
    let v = Vertex::new(5, "author".into(), vec![], vec![]);
    let key = (v.epoch, v.round, v.author.clone());
    let mut slots: HashMap<(u64, u64, String), PayloadSlot> = HashMap::new();
    let gate =
        |slots: &HashMap<(u64, u64, String), PayloadSlot>| Engine::payload_gate(slots, &v, false);
    assert_eq!(gate(&slots), ingress_v4::PayloadGate::Check);
    slots.insert(
        key.clone(),
        PayloadSlot {
            passed: vec!["x".into()],
            refused: vec!["y".into()],
        },
    );
    // B117: two checks fill a slot whatever their outcome.
    assert_eq!(gate(&slots), ingress_v4::PayloadGate::Full);
    assert_eq!(
        Engine::payload_gate(&slots, &v, true),
        ingress_v4::PayloadGate::Check,
        "a certified third body is checked"
    );
    slots.get_mut(&key).unwrap().refused[0] = v.hash.clone();
    assert_eq!(gate(&slots), ingress_v4::PayloadGate::Refused);
    slots.get_mut(&key).unwrap().refused.clear();
    slots.get_mut(&key).unwrap().passed[0] = v.hash.clone();
    assert_eq!(gate(&slots), ingress_v4::PayloadGate::Verified);
}

/// `v` with its payload replaced, re-hashed and re-signed by `key`.
fn with_payload(v: &Vertex, payload: Vec<String>, key: &[u8; 32]) -> Vertex {
    let mut w = v.clone();
    w.payload = payload;
    w.hash = w.hash_v4_with_domain(CHAIN, GENESIS);
    w.sign_with_ed25519(&crypto::SigningKey::from_bytes(key));
    w
}

/// B117 witness: a refused payload is remembered, so its copies are not
/// checked again, and the refusal is charged to whoever delivered it (B51);
/// a vertex waiting on parent certificates (here, invented parents) has its
/// payload checked only when it wakes, which never happens.
#[test]
fn a_refused_payload_is_checked_once_and_a_waiting_one_not_at_all() {
    let mut c = Cluster::new("b117-refused", 4, 0);
    c.run(1);
    let byz = c.leader(2);
    let h0 = c.validators().find(|&i| i != byz).unwrap();
    c.tick_all();
    let key = c.members[byz].node_key;
    let a = c.engine(byz).own_proposal(2).unwrap().clone();
    let bad = with_payload(&a, vec!["not a transaction".to_string()], &key);
    let net = c.net(h0);
    let checks = || ingress_v4::PAYLOAD_CHECKS.with(|n| n.get());
    let before = checks();
    let ((), failed) = crate::work::failed_in(|| {
        for _ in 0..3 {
            let len = serde_json::to_string(&bad).unwrap().len();
            c.engines[h0]
                .as_mut()
                .unwrap()
                .on_vertex(len, bad.clone(), &net);
        }
    });
    assert_eq!(checks() - before, 1, "a refused payload was checked again");
    assert_eq!(failed, 1, "the refusal was not charged once");

    let invented: Vec<ParentRef> = (0..3)
        .map(|i| ParentRef {
            round: 1,
            author: c.members[i].info.address.clone(),
            digest: format!("{:064x}", 0xb117_u64 + i as u64),
            proof: None,
            cert: None,
        })
        .collect();
    let waiting = recite(
        &with_payload(&a, vec!["also not a transaction".to_string()], &key),
        invented,
        &key,
    );
    let before = checks();
    let len = serde_json::to_string(&waiting).unwrap().len();
    c.engines[h0]
        .as_mut()
        .unwrap()
        .on_vertex(len, waiting.clone(), &net);
    assert_eq!(
        checks(),
        before,
        "a vertex on invented parents was payload-checked"
    );
    assert!(
        c.engines[h0]
            .as_mut()
            .unwrap()
            .pending
            .remove(&waiting.author, waiting.round, &waiting.hash)
            .is_some(),
        "vacuous: the vertex does not wait on its parents"
    );
}

/// B119 witness: a vertex buffered for E+1 keeps none of its embedded
/// certificates, and activation ingests the early certificates without
/// verifying them again: activating checks no certificate at all.
#[test]
fn activation_checks_no_certificate_twice_and_none_a_buffered_vertex_carried() {
    let mut c = Cluster::new("b119-activation", 4, 0);
    c.run_until(40, |c| c.decisions[0].len() >= 2);
    let (closing_round, anchor, _, _) = c.decisions[0]
        .last()
        .cloned()
        .expect("vacuous: nothing decided");
    let epoch_before = c.engine(0).epoch;
    let committee = c.committee.clone();
    c.engines[0]
        .as_mut()
        .unwrap()
        .close_epoch(closing_round, &anchor, &"ab".repeat(32), &committee)
        .unwrap();
    let next = c.engine(0).next.clone().expect("E+1 scheduled");
    let shape = c
        .engine(0)
        .certs
        .values()
        .next()
        .expect("a held certificate")
        .compact();
    let junk = blockchain::CompactCert {
        signer_bitmap: shape.signer_bitmap.clone(),
        aggregate_signature: vec![7u8; shape.aggregate_signature.len()],
    };
    let byzantine = 1;
    let author = c.members[byzantine].info.address.clone();
    let mut forged = lock(&c.engine(byzantine).dag)
        .values()
        .find(|v| v.author == author)
        .expect("a vertex of the Byzantine member")
        .clone();
    forged.epoch = next.epoch;
    forged.round = next.first_round + 1;
    forged.payload = vec![];
    forged.parent_refs = next
        .committee
        .iter()
        .enumerate()
        .map(|(i, m)| blockchain::ParentRef {
            round: next.first_round,
            author: m.address.clone(),
            digest: format!("{:064x}", 0xb119_u64 + i as u64),
            proof: None,
            cert: Some(junk.clone()),
        })
        .collect();
    forged.parents = forged
        .parent_refs
        .iter()
        .map(|r| r.digest.clone())
        .collect();
    forged.hash = forged.hash_v4_with_domain(CHAIN, GENESIS);
    forged.sign_with_ed25519(&crypto::SigningKey::from_bytes(
        &c.members[byzantine].node_key,
    ));
    let early = forged_cert_in(
        &c,
        next.epoch,
        &next.committee,
        next.first_round,
        &c.members[2].info.address,
        &"cd".repeat(32),
        &[0, 1, 2],
    );
    // B118: an E+1 vertex past the next epoch's lead is not buffered (its
    // parents' existence is not checked before activation, so any round
    // was kept, and remembered for good).
    let far_round = next.first_round + ingress_v4::LEAD + 1;
    let mut far = forged.clone();
    far.round = far_round;
    for r in &mut far.parent_refs {
        r.round = far_round - 1;
    }
    far.hash = far.hash_v4_with_domain(CHAIN, GENESIS);
    far.sign_with_ed25519(&crypto::SigningKey::from_bytes(
        &c.members[byzantine].node_key,
    ));
    let net = c.net(0);
    {
        let e = c.engines[0].as_mut().unwrap();
        e.on_cert(early, &net);
        let len = serde_json::to_string(&forged).unwrap().len();
        e.on_vertex(len, forged.clone(), &net);
        let len = serde_json::to_string(&far).unwrap().len();
        e.on_vertex(len, far.clone(), &net);
        assert!(
            e.pending
                .remove(&far.author, far.round, &far.hash)
                .is_none(),
            "an E+1 vertex past the lead was buffered"
        );
    }
    let verifications = || crate::vcert::CERT_VERIFICATIONS.with(|n| n.get());
    let before = verifications();
    c.engines[0].as_mut().unwrap().activate_next(&net).unwrap();
    assert!(
        c.engine(0).epoch > epoch_before,
        "vacuous: node 0 never activated"
    );
    assert!(
        c.engine(0)
            .certs
            .contains_key(&(next.first_round, c.members[2].info.address.clone())),
        "vacuous: the early certificate was not ingested"
    );
    assert_eq!(
        verifications(),
        before,
        "activation verified a certificate again or one a buffered vertex carried"
    );
}

/// B120 witness: a certificate GC has forgotten (at or below g minus the
/// retention slack) is not verified (a replay of one cost a pairing and a
/// synced write).
#[test]
fn a_certificate_below_the_floor_is_not_verified() {
    let mut c = Cluster::new("b120-floor", 4, 0);
    c.run(3);
    let old = c
        .engine(0)
        .certs
        .values()
        .find(|x| x.body.round == 2)
        .cloned()
        .expect("a round-2 certificate");
    let past = 2 + staging::RETAIN_SLACK;
    c.run_until(400, |c| c.engine(0).gc_floor() > past);
    assert!(
        c.engine(0).gc_floor() > past,
        "vacuous: the floor never passed the old round's cut"
    );
    assert!(
        !c.engine(0)
            .certs
            .contains_key(&(old.body.round, old.body.author.clone())),
        "vacuous: the old certificate is still held"
    );
    let net = c.net(0);
    let verifications = || crate::vcert::CERT_VERIFICATIONS.with(|n| n.get());
    let before = verifications();
    c.engines[0].as_mut().unwrap().on_cert(old, &net);
    assert_eq!(
        verifications(),
        before,
        "a forgotten certificate was verified"
    );
    // Between the cut and g certificates are still held: a second digest
    // for a held slot there is verified, and is a conflict.
    let g = c.engine(0).gc_floor();
    let held = c
        .engine(0)
        .certs
        .values()
        .find(|x| x.body.round <= g && x.body.round > g - staging::RETAIN_SLACK)
        .cloned()
        .expect("a certificate between the cut and g");
    let twin = forged_cert(
        &c,
        held.body.round,
        &held.body.author,
        &"ee".repeat(32),
        &[0, 1, 2],
    );
    c.engines[0].as_mut().unwrap().on_cert(twin, &net);
    assert!(
        c.engine(0).halted.is_some(),
        "a conflict between the cut and g went unseen"
    );
}

/// B125 witness: a member that lost its database starts its pull request
/// numbers above every number it used before (servers remember each
/// member's highest and refused everything below it).
#[test]
fn a_member_that_lost_its_database_starts_above_its_old_request_numbers() {
    let mut c = Cluster::new("b125-seq", 4, 0);
    c.run(3);
    let before = c.engines[1].as_mut().unwrap().next_seq();
    c.engines[1] = None;
    let _lost = std::mem::replace(&mut c.dirs[1], TempDb::new("b125-seq-lost"));
    c.clock.fetch_add(1, AtomicOrdering::SeqCst);
    c.open(1, true);
    let after = c.engines[1].as_mut().unwrap().next_seq();
    assert!(
        after > before,
        "{after} after a lost database, {before} before it"
    );
}

/// B126 witness: the embedded certificates a waiting vertex carries that
/// verify are ingested at once (each copy verified them again).
#[test]
fn a_waiting_vertex_hands_over_the_certificates_it_carries() {
    let mut c = Cluster::new("b126-harvest", 4, 0);
    c.run(3);
    let byz = c.leader(4);
    let h0 = c.validators().find(|&i| i != byz).unwrap();
    let key = c.members[byz].node_key;
    let template = c.engine(byz).own_proposal(2).unwrap().clone();
    let held = cert_ref(&c, byz, 1, &c.members[byz].info.address.clone());
    let mut refs = vec![held.clone()];
    for i in (0..4).filter(|&i| i != byz).take(2) {
        refs.push(ParentRef {
            round: 1,
            author: c.members[i].info.address.clone(),
            digest: format!("{:064x}", 0xb126_u64 + i as u64),
            proof: None,
            cert: None,
        });
    }
    let waiting = recite(&template, refs, &key);
    let slot = (1, c.members[byz].info.address.clone());
    c.engines[h0].as_mut().unwrap().certs.remove(&slot);
    let net = c.net(h0);
    let len = serde_json::to_string(&waiting).unwrap().len();
    c.engines[h0]
        .as_mut()
        .unwrap()
        .on_vertex(len, waiting.clone(), &net);
    assert!(
        c.engines[h0]
            .as_mut()
            .unwrap()
            .pending
            .remove(&waiting.author, waiting.round, &waiting.hash)
            .is_some(),
        "vacuous: the vertex does not wait"
    );
    assert!(
        c.engine(h0).certs.contains_key(&slot),
        "the certificate it carried was not ingested"
    );
}
