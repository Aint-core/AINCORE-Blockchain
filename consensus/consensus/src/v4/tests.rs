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
}

impl Cluster {
    /// `n` validators, plus `observers` nodes outside the committee.
    fn new(tag: &str, n: u8, observers: u8) -> Self {
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
    let hide = move |e: &Envelope, to: usize| {
        to == 0 && e.from == absent && matches!(&e.msg, Msg::Vertex(v) if v.round == 1)
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
