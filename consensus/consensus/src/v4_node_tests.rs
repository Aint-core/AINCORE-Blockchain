// G1 S5 part 2: the V4 engine inside real `DagConsensus` nodes. Four
// validators on a V4 genesis exchange `DAG_V4:` wire messages through their
// test outboxes; the V3 commit loop (block building, execution, acceptance)
// runs over O_E with C_0. Every node must place the same blocks.

use super::{seed_state_tree, tier2_keypair};
use crate::dag::DagConsensus;
use crate::qc::{derive_validator_bls_seed, ValidatorInfo};
use crypto::bls::BLSEngine;
use executor::Executor;
use mempool::Mempool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use storage::object::{Object, Owner};
use storage::StateDB;

const PINNED: u64 = 1_700_000_000;
const GENESIS_IDENTITY: &str = "v4-node-test-genesis-identity";

struct Node {
    c: Option<DagConsensus>,
    path: String,
    seed: u8,
}

struct Cluster {
    nodes: Vec<Node>,
    committee: Vec<ValidatorInfo>,
    known: Vec<(String, String)>,
    /// I, pinned in the seeded genesis (EP-1).
    epoch_interval: u64,
    /// B14: accounts given AIN at genesis, with the stdlib installed, so a
    /// transaction can execute. Empty: no stdlib, as before.
    funded: Vec<(String, u128)>,
}

fn validator_info(seed: u8) -> ValidatorInfo {
    let (address, ed25519_public_key, key) = tier2_keypair(seed);
    let bls = BLSEngine::consensus();
    let bls_seed = derive_validator_bls_seed(&key);
    ValidatorInfo {
        address,
        stake: 1000,
        ed25519_public_key,
        bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
        bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
    }
}

/// A node of seed `seed` on the database at `path`.
fn open_node(path: &str, seed: u8) -> DagConsensus {
    let db = Arc::new(StateDB::open(path).unwrap());
    let key = [seed; 32];
    let node_id = crypto::derive_address(
        crypto::SigningKey::from_bytes(&key)
            .verifying_key()
            .as_bytes(),
    )
    .unwrap();
    let mut c = DagConsensus::new(
        node_id,
        Arc::new(Mutex::new(Mempool::new())),
        Arc::new(Executor::new(Arc::clone(&db))),
        db,
        None,
        key,
    );
    c.set_now_secs(Arc::new(|| PINNED));
    c.placement_sleep = Arc::new(|_| {});
    c.v4_outbox = Some(Arc::new(Mutex::new(Vec::new())));
    c
}

impl Cluster {
    fn new(tag: &str, seeds: &[u8], v4: bool) -> Self {
        Self::with_interval(tag, seeds, v4, 1000)
    }

    fn with_interval(tag: &str, seeds: &[u8], v4: bool, epoch_interval: u64) -> Self {
        Self::with_funded(tag, seeds, v4, epoch_interval, Vec::new())
    }

    /// A cluster whose genesis installs the stdlib and gives `funded` AIN.
    fn with_funded(
        tag: &str,
        seeds: &[u8],
        v4: bool,
        epoch_interval: u64,
        funded: Vec<(String, u128)>,
    ) -> Self {
        let mut cluster = Self::unopened(seeds, epoch_interval);
        cluster.funded = funded;
        for (i, seed) in seeds.iter().enumerate() {
            let path = std::env::temp_dir()
                .join(format!("aincore_v4_node_{}_{tag}_{i}", std::process::id()))
                .to_string_lossy()
                .to_string();
            let _ = std::fs::remove_dir_all(&path);
            cluster.seed_db(&path, *seed, v4);
            cluster.nodes.push(Node {
                c: None,
                path,
                seed: *seed,
            });
            cluster.open(i);
        }
        cluster
    }

    /// The committee of `seeds`, with no node open yet.
    fn unopened(seeds: &[u8], epoch_interval: u64) -> Self {
        let committee: Vec<ValidatorInfo> = seeds.iter().map(|s| validator_info(*s)).collect();
        let known: Vec<(String, String)> = committee
            .iter()
            .map(|m| (m.address.clone(), m.ed25519_public_key.clone()))
            .collect();
        Self {
            nodes: Vec::new(),
            committee,
            known,
            epoch_interval,
            funded: Vec::new(),
        }
    }

    fn seed_db(&self, path: &str, seed: u8, v4: bool) {
        let db = Arc::new(StateDB::open(path).unwrap());
        let _seeding = db.seeding();
        for (addr, pubkey) in &self.known {
            let account = Object::new(
                addr.clone(),
                Owner::Address(addr.clone()),
                serde_json::json!({ "public_key": pubkey, "sequence_number": 0 })
                    .to_string()
                    .into_bytes(),
                "0x1::account::AccountData".to_string(),
            );
            db.put_object(&account).unwrap();
        }
        let vset: Vec<String> = self
            .known
            .iter()
            .map(|(a, _)| format!(r#"["{a}",1000]"#))
            .collect();
        db.put("sys:validators", &format!("[{}]", vset.join(",")))
            .unwrap();
        db.put(
            "genesis:validator_set:v1",
            &serde_json::to_string(&self.committee).unwrap(),
        )
        .unwrap();
        db.put("genesis_identity", GENESIS_IDENTITY).unwrap();
        db.put(
            crate::v4::epoch::EPOCH_INTERVAL_KEY,
            &self.epoch_interval.to_string(),
        )
        .unwrap();
        if v4 {
            db.put(crate::v4::VERTEX_FORMAT_KEY, "4").unwrap();
            // The live set genesis writes: C_{E+1} derives from it (EP-2).
            db.put(
                "sys:validator_set:v1",
                &serde_json::to_string(&self.committee).unwrap(),
            )
            .unwrap();
            db.put(
                "consensus:guard_origin",
                &crate::v4::guard_origin(
                    &crate::qc::expected_chain_id(),
                    GENESIS_IDENTITY,
                    &[seed; 32],
                ),
            )
            .unwrap();
        }
        if !self.funded.is_empty() {
            executor::test_support::load_stdlib(&db);
            for (address, amount) in &self.funded {
                executor::test_support::set_ain_balance(&db, address, *amount);
            }
        }
        seed_state_tree(&db);
    }

    fn open(&mut self, i: usize) {
        let node = &self.nodes[i];
        let c = open_node(&node.path, node.seed);
        self.nodes[i].c = Some(c);
    }

    /// Close and reopen node `i` on its database.
    fn reopen(&mut self, i: usize) {
        self.nodes[i].c = None;
        self.open(i);
    }

    fn node(&self, i: usize) -> &DagConsensus {
        self.nodes[i].c.as_ref().unwrap()
    }

    fn node_mut(&mut self, i: usize) -> &mut DagConsensus {
        self.nodes[i].c.as_mut().unwrap()
    }

    /// Deliver every queued wire message to every other node, until quiet.
    fn deliver(&mut self) {
        loop {
            let mut batch: Vec<(usize, String)> = Vec::new();
            for i in 0..self.nodes.len() {
                let outbox = self.node(i).v4_outbox.clone().unwrap();
                batch.extend(outbox.lock().unwrap().drain(..).map(|w| (i, w)));
            }
            if batch.is_empty() {
                break;
            }
            for (from, wire) in batch {
                for j in (0..self.nodes.len()).filter(|&j| j != from) {
                    self.node_mut(j).handle_message(&wire);
                }
            }
        }
    }

    /// `deliver`, except that `lost(from, to)` messages never arrive.
    fn deliver_lossy(&mut self, lost: &dyn Fn(usize, usize) -> bool) {
        loop {
            let mut batch: Vec<(usize, String)> = Vec::new();
            for i in 0..self.nodes.len() {
                let outbox = self.node(i).v4_outbox.clone().unwrap();
                batch.extend(outbox.lock().unwrap().drain(..).map(|w| (i, w)));
            }
            if batch.is_empty() {
                break;
            }
            for (from, wire) in batch {
                for j in (0..self.nodes.len()).filter(|&j| j != from && !lost(from, j)) {
                    self.node_mut(j).handle_message(&wire);
                }
            }
        }
    }

    /// `deliver`, except that `lost(from, to, wire)` messages never arrive.
    fn deliver_filtered(&mut self, lost: &dyn Fn(usize, usize, &str) -> bool) {
        loop {
            let mut batch: Vec<(usize, String)> = Vec::new();
            for i in 0..self.nodes.len() {
                let outbox = self.node(i).v4_outbox.clone().unwrap();
                batch.extend(outbox.lock().unwrap().drain(..).map(|w| (i, w)));
            }
            if batch.is_empty() {
                break;
            }
            for (from, wire) in batch {
                for j in (0..self.nodes.len()).filter(|&j| j != from && !lost(from, j, &wire)) {
                    self.node_mut(j).handle_message(&wire);
                }
            }
        }
    }

    /// Run until `done` holds, at most `ticks` ticks.
    fn run_until(&mut self, ticks: usize, done: impl Fn(&Cluster) -> bool) {
        for _ in 0..ticks {
            if done(self) {
                return;
            }
            self.run(1);
        }
    }

    /// The active epoch of node `i`'s engine.
    fn epoch(&self, i: usize) -> u64 {
        self.node(i).v4.as_ref().unwrap().epoch()
    }

    fn qc(&self, i: usize, h: u64) -> Option<crate::qc::QuorumCertificate> {
        crate::qc_producer::stored_qc(&self.node(i).storage, h)
    }

    fn run(&mut self, ticks: usize) {
        for _ in 0..ticks {
            for i in 0..self.nodes.len() {
                self.node_mut(i).try_create_vertex();
            }
            self.deliver();
        }
    }

    fn block(&self, i: usize, h: u64) -> Option<(u64, String)> {
        self.node(i)
            .storage
            .get(&format!("block_{h}"))
            .unwrap()
            .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
            .map(|b| (b.header.round, b.header.hash))
    }

    /// Every node placed the same blocks, at least `min` of them.
    fn assert_same_blocks(&self, min: u64) -> u64 {
        let heights: Vec<u64> = (0..self.nodes.len())
            .map(|i| self.node(i).latest_block_height)
            .collect();
        let common = *heights.iter().min().unwrap();
        assert!(common >= min, "heights {heights:?}, wanted at least {min}");
        for h in 1..=common {
            let first = self.block(0, h);
            assert!(first.is_some(), "no block {h}");
            for i in 1..self.nodes.len() {
                assert_eq!(self.block(i, h), first, "node {i} differs at height {h}");
            }
        }
        common
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        for n in &mut self.nodes {
            n.c = None;
            let _ = std::fs::remove_dir_all(&n.path);
        }
    }
}

#[test]
fn four_v4_nodes_place_the_same_blocks() {
    let mut c = Cluster::new("blocks", &[81, 82, 83, 84], true);
    for i in 0..4 {
        assert!(c.node(i).v4.is_some(), "node {i} did not start V4");
    }
    c.run(14);
    let placed = c.assert_same_blocks(3);
    // The anchor rounds are even and increasing (one block per anchor).
    let rounds: Vec<u64> = (1..=placed).map(|h| c.block(0, h).unwrap().0).collect();
    assert!(rounds.windows(2).all(|w| w[0] < w[1]), "{rounds:?}");
    assert!(rounds.iter().all(|r| r % 2 == 0), "{rounds:?}");
    // DE-6 in the acceptance transaction: each block's anchor is recorded.
    for i in 0..4 {
        for h in 1..=placed {
            let b: blockchain::Block = serde_json::from_str(
                &c.node(i)
                    .storage
                    .get(&format!("block_{h}"))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            let row = c
                .node(i)
                .storage
                .get(&crate::ordering::anchor_decision_key(0, b.header.round))
                .unwrap();
            assert_eq!(
                row,
                Some(format!("C:{}", b.anchor_hash)),
                "node {i} height {h}"
            );
        }
    }
}

/// RC-1 through the node: every node restarts mid-run and the chain goes on,
/// identically everywhere.
#[test]
fn v4_nodes_restart_and_keep_placing_the_same_blocks() {
    let mut c = Cluster::new("restart", &[85, 86, 87, 88], true);
    c.run(8);
    let before = c.assert_same_blocks(1);
    for i in 0..4 {
        c.reopen(i);
        assert!(c.node(i).v4.is_some());
    }
    c.run(10);
    let after = c.assert_same_blocks(before + 2);
    assert!(after > before);
}

/// One DAG format per chain: a V4 node ignores V3 vertices, and a node
/// without the V4 format (inert since G5 S4c deleted V3) ignores V4 messages.
#[test]
fn a_node_never_mixes_dag_formats() {
    let mut v4 = Cluster::new("mix4", &[89, 90, 91, 92], true);
    let mut v3 = Cluster::new("mix3", &[89, 90, 91, 92], false);
    assert!(v3.node(0).v4.is_none());
    // A V4 message reaches the inert node: nothing is staged.
    let outbox = v4.node(0).v4_outbox.clone().unwrap();
    v4.node_mut(0).try_create_vertex();
    let wire = outbox
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the V4 node proposed round 1");
    assert!(wire.starts_with(crate::v4::WIRE_PREFIX));
    v3.node_mut(0).handle_message(&wire);
    assert!(v3.node(0).dag.lock().unwrap().is_empty());
    v4.deliver();
    // A V3 vertex reaches a V4 node: refused, and it is no evidence either.
    // Its author (node 2) has proposed nothing yet, so only the format rule
    // can refuse it.
    let (addr, _, key) = tier2_keypair(91);
    let mut v = blockchain::Vertex {
        epoch: 0,
        round: 1,
        author: addr,
        timestamp: PINNED,
        payload: vec![],
        parents: vec!["genesis".to_string()],
        hash: String::new(),
        signature: String::new(),
        aggregated_signature: None,
        payload_root: None,
        parents_root: None,
        parent_refs: Vec::new(),
    };
    v.hash = v.calculate_hash();
    v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&key));
    let staged = v4.node(1).dag.lock().unwrap().len();
    v4.node_mut(1).handle_message(&format!(
        "DAG_VERTEX:{}",
        serde_json::to_string(&v).unwrap()
    ));
    assert_eq!(v4.node(1).dag.lock().unwrap().len(), staged);
    assert!(!v4.node(1).dag.lock().unwrap().contains_key(&v.hash));
    assert!(v4
        .node(1)
        .storage
        .get(&format!("sys:equiv_seen:{}:1", v.author))
        .unwrap()
        .is_none());
}

/// A signed transaction in one node's mempool rides that node's next V4
/// vertex and lands in the same block, at the same height, on every node.
#[test]
fn a_transaction_travels_through_a_v4_vertex_into_every_nodes_block() {
    use crypto::Signer;
    let key = crypto::SigningKey::from_bytes(&[77u8; 32]);
    let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    // B14: the body is what executed and paid, so the sender has AIN.
    const FUNDS: u128 = 1_000_000_000_000;
    let mut c = Cluster::with_funded(
        "tx",
        &[93, 94, 95, 96],
        true,
        1000,
        vec![(sender.clone(), FUNDS)],
    );
    let chain_id = blockchain::chain_id();
    // BCS of `TransactionPayload::PublishModule(vec![vec![7, 7]])`: variant 2,
    // one module of two bytes. Not a module: it aborts, after paying gas.
    let payload = hex::encode([2u8, 1, 2, 7, 7]);
    // A limit that covers the transaction's bytes (B14) with room to run.
    let (seq, gas_limit, gas_price) = (0u64, 1_000_000u64, 1u128);
    let message = format!("{chain_id}:{sender}:{payload}:{seq}:{gas_limit}:{gas_price}:");
    let tx = serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "sequence_number": seq,
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "signature": hex::encode(key.sign(message.as_bytes()).to_bytes()),
    })
    .to_string();
    c.node(0)
        .mempool
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .expect("a signed transaction is admitted");
    c.run(10);
    let placed = c.assert_same_blocks(2);
    let carrying: Vec<u64> = (1..=placed)
        .filter(|h| {
            c.node(0)
                .storage
                .get(&format!("block_{h}"))
                .unwrap()
                .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
                .is_some_and(|b| b.transactions.contains(&tx))
        })
        .collect();
    assert_eq!(carrying.len(), 1, "the transaction is in exactly one block");
    // Every node charged it the same, and every node holds the same base fee.
    for i in 0..4 {
        assert_eq!(
            executor::test_support::ain_balance(&c.node(i).storage, &sender),
            Some(FUNDS - gas_limit as u128 * gas_price),
            "node {i}"
        );
        assert_eq!(
            executor::committed_base_fee(&c.node(i).storage),
            executor::committed_base_fee(&c.node(0).storage),
            "node {i}"
        );
    }
}

/// B14: a transaction that cannot pay is ordered, executes nowhere, and is
/// stored nowhere: every node builds the same blocks without it.
#[test]
fn an_unfunded_transaction_is_ordered_but_never_stored() {
    use crypto::Signer;
    let mut c = Cluster::new("unpaid", &[93, 94, 95, 96], true);
    let key = crypto::SigningKey::from_bytes(&[78u8; 32]);
    let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let chain_id = blockchain::chain_id();
    let payload = hex::encode([2u8, 1, 2, 7, 8]);
    let (seq, gas_limit, gas_price) = (0u64, 1_000_000u64, 1u128);
    let message = format!("{chain_id}:{sender}:{payload}:{seq}:{gas_limit}:{gas_price}:");
    let tx = serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "sequence_number": seq,
        "public_key": hex::encode(key.verifying_key().to_bytes()),
        "signature": hex::encode(key.sign(message.as_bytes()).to_bytes()),
    })
    .to_string();
    c.node(0)
        .mempool
        .lock()
        .unwrap()
        .add_transaction(tx.clone())
        .expect("a signed transaction is admitted (no balance gate here)");
    c.run(10);
    let placed = c.assert_same_blocks(2);
    let ordered = c
        .node(0)
        .dag
        .lock()
        .unwrap()
        .values()
        .any(|v| v.payload.contains(&tx));
    assert!(ordered, "vacuous: the transaction never rode a vertex");
    for h in 1..=placed {
        let block: blockchain::Block = serde_json::from_str(
            &c.node(0)
                .storage
                .get(&format!("block_{h}"))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert!(
            !block.transactions.contains(&tx),
            "block {h} stored an unpaid transaction"
        );
    }
}

/// DE-7 through the node: the live validator set changes on one node mid-run
/// (a join, a leave and a stake change). The leader, the votes, the reward and
/// BFT time come from the frozen C_0, so every node still places the same
/// blocks.
#[test]
fn v4_leader_uses_frozen_committee() {
    let mut c = Cluster::new("frozen", &[97, 98, 99, 100], true);
    c.run(4);
    let (stranger, _, _) = tier2_keypair(150);
    let live = format!(
        r#"[["{}",5000],["{}",1],["{stranger}",9000]]"#,
        c.known[0].0, c.known[1].0
    );
    {
        let node = c.node(2);
        let _seeding = node.storage.seeding();
        node.storage.put("sys:validators", &live).unwrap();
        node.invalidate_validators_cache();
    }
    c.run(10);
    c.assert_same_blocks(4);
}

/// Past the point where V3 prunes (round 50, a height divisible by 10), a V4
/// node keeps every staged body (its GC is S7): after a restart the whole
/// certified history reloads and the chain goes on, identically everywhere.
#[test]
fn a_long_v4_run_survives_a_restart_past_the_v3_prune_point() {
    let mut c = Cluster::new("long", &[101, 102, 103, 104], true);
    c.run(70);
    assert!(
        c.node(0).current_round > 60,
        "round {}",
        c.node(0).current_round
    );
    let before = c.assert_same_blocks(25);
    for i in 0..4 {
        c.reopen(i);
    }
    c.run(10);
    let after = c.assert_same_blocks(before + 3);
    assert!(after > before);
}

/// S6 through the node: node 0 hears nothing for six ticks, then pulls what
/// it missed (requests and answers travel as `DAG_V4:` messages) and places
/// the same blocks as everyone.
#[test]
fn a_v4_node_that_missed_rounds_catches_up_by_pull() {
    let mut c = Cluster::new("pull", &[105, 106, 107, 108], true);
    c.run(3);
    for _ in 0..6 {
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        c.deliver_lossy(&|_, to| to == 0);
    }
    let behind = c.node(0).latest_block_height;
    let ahead = c.node(1).latest_block_height;
    assert!(ahead > behind, "the others moved on ({behind} vs {ahead})");
    c.run(12);
    let common = c.assert_same_blocks(ahead);
    assert!(common >= ahead);
}

/// A certificate for (round, author, digest) signed by `signer_seeds`: what
/// more than f colluding keys can produce.
fn forge_cert(
    c: &Cluster,
    round: u64,
    author: &str,
    digest: &str,
    signer_seeds: &[u8],
) -> crate::vcert::VertexCertificate {
    let body = crate::vcert::AttestBody {
        chain_id: crate::qc::expected_chain_id(),
        genesis_identity: GENESIS_IDENTITY.to_string(),
        epoch: 0,
        round,
        author: author.to_string(),
        digest: digest.to_string(),
        committee_hash: crate::qc::validator_set_hash(&c.committee),
    };
    let mut collector = crate::vcert::CertCollector::new(body.clone(), &c.committee).unwrap();
    let mut out = None;
    for &s in signer_seeds {
        let att = crate::vcert::VertexAttestation {
            body: body.clone(),
            signer: validator_info(s).address,
            signature: BLSEngine::consensus()
                .sign_raw(&body.signing_bytes(), &derive_validator_bls_seed(&[s; 32])),
        };
        if let Ok(crate::vcert::CollectOutcome::Certified(cert)) = collector.add(&att) {
            out = Some(*cert);
        }
    }
    out.expect("a quorum of signers")
}

/// CE-3 through the node (second review of S5, HIGH-1): a node that sees two
/// certificates for one slot places no further block, signs no further
/// finality vote, before and after a restart.
#[test]
fn a_ce3_halted_node_places_no_more_blocks() {
    let mut c = Cluster::new("halt", &[111, 112, 113, 114], true);
    c.run(6);
    let author = c.known[1].0.clone();
    let fake = "ab".repeat(32);
    let cert = forge_cert(&c, 1, &author, &fake, &[111, 112, 113]);
    let wire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Cert(cert)).unwrap()
    );
    c.node_mut(0).handle_message(&wire);
    assert!(c.node(0).ordering_halted().is_some(), "not halted");
    // Its relay of the two certificates (G5 A3) is dropped here, so the
    // others keep going as the control: this witness is about the halted
    // node itself. The relay has its own witness,
    // `a_certificate_conflict_is_recorded_as_evidence_against_both_signers`.
    c.node(0).v4_outbox.as_ref().unwrap().lock().unwrap().clear();
    let at_halt = c.node(0).latest_block_height;
    c.run(10);
    assert_eq!(
        c.node(0).latest_block_height,
        at_halt,
        "a halted node placed blocks"
    );
    assert!(
        c.node(1).latest_block_height > at_halt,
        "vacuous: the others stopped too"
    );
    c.reopen(0);
    assert!(
        c.node(0).ordering_halted().is_some(),
        "the halt was forgotten"
    );
    c.run(6);
    assert_eq!(c.node(0).latest_block_height, at_halt);
}

static EXECUTIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// DE-6 through the node (second review of S5, LOW-1): a decision row that
/// disagrees refuses the acceptance, records an alarm and halts ordering; the
/// refused block is executed once, not on every progress, and the halt
/// survives a restart.
#[test]
fn a_decision_conflict_halts_the_node_with_an_alarm() {
    let mut c = Cluster::new("de6-halt", &[119, 120, 121, 122], true);
    c.node(0)
        .storage
        .put(&crate::ordering::anchor_decision_key(0, 2), "S")
        .unwrap();
    c.node_mut(0).pre_execution_hook = Some(|_, _| {
        EXECUTIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    });
    c.run(20);
    assert_eq!(c.node(0).latest_block_height, 0);
    assert!(
        c.node(1).latest_block_height > 2,
        "vacuous: the others stopped too"
    );
    assert!(c.node(0).ordering_halted().is_some());
    assert!(EXECUTIONS.load(std::sync::atomic::Ordering::SeqCst) <= 1);
    let alarm = c
        .node(0)
        .storage
        .db
        .prefix_iterator(b"alarm:decision_conflict:")
        .next()
        .and_then(|r| r.ok())
        .map(|(k, _)| k.starts_with(b"alarm:decision_conflict:"));
    assert_eq!(alarm, Some(true), "no alarm row");
    c.reopen(0);
    assert!(
        c.node(0).ordering_halted().is_some(),
        "the halt was forgotten"
    );
}

// ------------------------------------------------------------ S9b: epochs

/// EP-1..EP-4 on real nodes (I = 4 blocks): every boundary block H_E writes
/// E+1's record in its own transaction, the nodes form QC(H_E) binding
/// `next_validator_set_hash` (FinalityVote V2), activate E+1 on it, and keep
/// placing the same blocks, whose QCs verify under the epoch's committee.
/// (g): this harness has no Move stdlib, so `advance_epoch` fails at every
/// boundary; the epochs advance regardless, and the executor still records
/// each committee (G5 EM-2), equal to the one consensus derived.
#[test]
fn v4_nodes_rotate_epochs_on_the_qc_of_each_boundary_block() {
    let mut c = Cluster::with_interval("epochs", &[91, 92, 93, 94], true, 4);
    c.run_until(200, |c| {
        (0..4).all(|i| c.epoch(i) >= 3 && c.node(i).latest_block_height >= 14)
    });
    let placed = c.assert_same_blocks(14);
    for i in 0..4 {
        assert!(c.epoch(i) >= 3, "node {i} is in epoch {}", c.epoch(i));
        let db = &c.node(i).storage;
        assert!(
            db.get("resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::epoch::Epoch")
                .unwrap()
                .is_none(),
            "(g) is vacuous: Move's advance_epoch could run here"
        );
        for e in 1..=3u64 {
            let start = crate::v4::epoch::read_start_from(db, e).unwrap().unwrap();
            let boundary = 4 * e;
            let (round, hash) = c.block(i, boundary).unwrap();
            assert_eq!(start.prev_height, boundary);
            assert_eq!(start.prev_block_hash, hash);
            assert_eq!(start.prev_closing_round, round);
            assert_eq!(start.first_round, round + 2);
            assert_eq!(start.committee, crate::qc::canonical_order(&c.committee));
            let recorded: Vec<crate::qc::ValidatorInfo> = serde_json::from_str(
                &db.get(&format!("sys:validator_set:epoch:{e}"))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(recorded, start.committee, "the executor's record");
            // FinalityVote V2 on the boundary block only.
            let q = c.qc(i, boundary).expect("QC(H_E) is held");
            assert_eq!(
                q.next_validator_set_hash,
                crate::qc::validator_set_hash(&start.committee)
            );
            assert_eq!(q.epoch, e - 1);
            // The first block of E+1 is certified by C_{E+1} in epoch E+1,
            // with an anchor at or above E+1's first round.
            let (first, _) = c.block(i, boundary + 1).unwrap();
            assert!(
                first >= start.first_round,
                "block {} at round {first}",
                boundary + 1
            );
            let q = c
                .qc(i, boundary + 1)
                .expect("the first block of E+1 has its QC");
            assert_eq!(q.epoch, e);
            assert!(q.next_validator_set_hash.is_empty());
            crate::qc::verify_qc(&q, &start.committee, &crate::qc::expected_chain_id()).unwrap();
        }
    }
    assert!(placed >= 14);
}

/// EP-2 (e) on real nodes: the live set in H_0's post-state weights one
/// member ten times (staged by every node's executor alike). Epoch 1's
/// committee is that set, the boundary QC binds its hash, and the nodes keep
/// agreeing under the new stake.
#[test]
fn a_stake_change_in_the_boundary_post_state_becomes_the_next_committee() {
    let mut c = Cluster::with_interval("epoch-stake", &[95, 96, 97, 98], true, 4);
    fn reweigh(_: u8, view: &StateDB) -> Result<(), String> {
        let raw = view
            .get("genesis:validator_set:v1")
            .map_err(|e| e.to_string())?
            .unwrap();
        let mut set: Vec<ValidatorInfo> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        set = crate::qc::canonical_order(&set);
        set[0].stake = 10_000;
        view.put(
            "sys:validator_set:v1",
            &serde_json::to_string(&set).unwrap(),
        )
        .map_err(|e| e.to_string())
    }
    for i in 0..4 {
        c.node_mut(i).pre_execution_hook = Some(reweigh);
    }
    c.run_until(200, |c| {
        (0..4).all(|i| c.epoch(i) >= 1 && c.node(i).latest_block_height >= 9)
    });
    c.assert_same_blocks(9);
    for i in 0..4 {
        assert!(c.epoch(i) >= 1);
        let start = crate::v4::epoch::read_start_from(&c.node(i).storage, 1)
            .unwrap()
            .unwrap();
        assert_eq!(start.committee.iter().map(|m| m.stake).max(), Some(10_000));
        assert_eq!(
            c.qc(i, 4).unwrap().next_validator_set_hash,
            crate::qc::validator_set_hash(&start.committee)
        );
        let engine = c.node(i).v4.as_ref().unwrap();
        assert!(
            engine.stakes().iter().any(|(_, s)| *s == 10_000),
            "node {i}"
        );
    }
}

/// EP-3/EP-4 (h): a node restarted right after accepting H_E (E+1's record
/// written, E+1 not active) closes on boot and activates once it holds the
/// QC, like the others.
#[test]
fn a_node_restarted_at_the_boundary_block_activates_like_the_others() {
    let mut c = Cluster::with_interval("epoch-crash", &[71, 72, 73, 74], true, 4);
    c.run_until(80, |c| c.node(0).latest_block_height >= 4);
    assert!(c.node(0).latest_block_height >= 4, "no boundary block");
    c.reopen(0);
    let engine = c.node(0).v4.as_ref().unwrap();
    assert!(
        engine.next_start().is_some() || engine.epoch() >= 1,
        "the boundary record was lost across the restart"
    );
    c.run_until(200, |c| {
        (0..4).all(|i| c.epoch(i) >= 2 && c.node(i).latest_block_height >= 10)
    });
    c.assert_same_blocks(10);
    assert!(c.epoch(0) >= 2);
}

/// EP-4 and EP-5 (c): a node that closed E but never saw the votes for
/// QC(H_E) asks for the QC (QC_WANT), gets it (QC_CERT), activates, and
/// catches up with the others' E+1 blocks; its E+1 messages held before
/// activation change nothing.
#[test]
fn a_node_that_missed_the_boundary_votes_fetches_the_qc_and_activates() {
    let mut c = Cluster::with_interval("epoch-qcwant", &[61, 62, 63, 64], true, 4);
    c.run_until(80, |c| (0..4).all(|i| c.node(i).latest_block_height >= 3));
    // Node 0 hears no finality vote and no QC answer for a while.
    for _ in 0..40 {
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        c.deliver_filtered(&|_, to, wire| {
            to == 0
                && (wire.starts_with("QC_VOTE:") || wire.starts_with(crate::dag::QC_CERT_PREFIX))
        });
        if (1..4).all(|i| c.epoch(i) >= 1) && c.node(1).latest_block_height >= 6 {
            break;
        }
    }
    assert_eq!(c.epoch(0), 0, "vacuous: node 0 activated without the QC");
    assert!(
        c.node(0).v4.as_ref().unwrap().next_start().is_some(),
        "node 0 did not close"
    );
    assert!(c.qc(0, 4).is_none());
    // A forged QC(H_0) (one flipped signature byte) is never stored.
    let mut forged = c.qc(1, 4).expect("node 1 holds QC(H_0)");
    forged.aggregate_signature[10] ^= 1;
    let wire = format!(
        "{}{}",
        crate::dag::QC_CERT_PREFIX,
        serde_json::to_string(&forged).unwrap()
    );
    c.node_mut(0).handle_message(&wire);
    assert!(c.qc(0, 4).is_none(), "a forged QC was stored");
    assert_eq!(c.epoch(0), 0);
    // QC_WANT is answered only for a boundary height, once per throttle
    // window however often it is asked.
    let answers = |c: &mut Cluster, ask: &str| {
        let outbox = c.node(1).v4_outbox.clone().unwrap();
        outbox.lock().unwrap().clear();
        for _ in 0..5 {
            c.node_mut(1).handle_message(ask);
        }
        let sent = outbox
            .lock()
            .unwrap()
            .iter()
            .filter(|w| w.starts_with(crate::dag::QC_CERT_PREFIX))
            .count();
        sent
    };
    // Any held height is answered (adoption and lost votes need them too),
    // never one above the tip.
    let above = format!("QC_WANT:{}", c.node(1).latest_block_height + 1);
    assert_eq!(answers(&mut c, &above), 0, "a height above the tip was answered");
    assert!(
        answers(&mut c, "QC_WANT:4") <= 1,
        "the answer is not throttled"
    );
    c.run_until(200, |c| {
        c.epoch(0) >= 1 && c.node(0).latest_block_height >= c.node(1).latest_block_height
    });
    assert!(
        c.epoch(0) >= 1,
        "node 0 never activated: height {}, closed {:?}, qc4 {}, halted {:?}",
        c.node(0).latest_block_height,
        c.node(0)
            .v4
            .as_ref()
            .unwrap()
            .next_start()
            .map(|n| (n.epoch, n.prev_height)),
        c.qc(0, 4).is_some(),
        c.node(0).ordering_halted()
    );
    assert!(c.qc(0, 4).is_some());
    c.run(8);
    c.assert_same_blocks(8);
}

/// EP-4: a QC(H_E) whose next committee differs from the one this node
/// derived halts ordering with `alarm:committee_mismatch`, durably. (Node 0's
/// record is rewritten as a divergent derivation would have left it.)
#[test]
fn a_boundary_qc_binding_another_committee_halts_the_node() {
    let mut c = Cluster::with_interval("epoch-mismatch", &[51, 52, 53, 54], true, 4);
    c.run_until(80, |c| (0..4).all(|i| c.node(i).latest_block_height >= 3));
    for _ in 0..40 {
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        c.deliver_filtered(&|_, to, wire| {
            to == 0
                && (wire.starts_with("QC_VOTE:") || wire.starts_with(crate::dag::QC_CERT_PREFIX))
        });
        if c.node(0).latest_block_height >= 4 && (1..4).all(|i| c.qc(i, 4).is_some()) {
            break;
        }
    }
    assert_eq!(c.epoch(0), 0, "vacuous: node 0 activated");
    assert!(c.qc(0, 4).is_none(), "vacuous: node 0 holds the QC");
    {
        let db = &c.node(0).storage;
        let mut start = crate::v4::epoch::read_start_from(db, 1).unwrap().unwrap();
        start.committee.pop();
        db.put(
            &crate::v4::epoch::epoch_start_key(1),
            &serde_json::to_string(&start).unwrap(),
        )
        .unwrap();
    }
    c.reopen(0);
    c.run(20);
    assert_eq!(
        c.epoch(0),
        0,
        "node 0 activated a committee it did not derive"
    );
    assert!(c.node(0).ordering_halted().is_some(), "node 0 did not halt");
    assert!(
        c.node(0)
            .storage
            .get(&format!("alarm:committee_mismatch:{:020}", 1))
            .unwrap()
            .is_some(),
        "no alarm row"
    );
    c.reopen(0);
    assert!(
        c.node(0).ordering_halted().is_some(),
        "the halt was forgotten"
    );
}

/// EP-3 in one commit loop: a node cut off across H_0 learns several
/// anchors at once when it heals, so a single commit loop crosses the
/// boundary. E closes right after H_0 is placed, so no epoch-0 anchor above
/// r* becomes a block: every node places the same blocks.
#[test]
fn a_node_deciding_a_batch_across_the_boundary_places_the_same_blocks() {
    let mut c = Cluster::with_interval("epoch-batch", &[41, 42, 43, 44], true, 4);
    c.run_until(80, |c| (0..4).all(|i| c.node(i).latest_block_height >= 2));
    let cut_at = c.node(0).latest_block_height;
    for _ in 0..60 {
        for i in 0..4 {
            c.node_mut(i).try_create_vertex();
        }
        c.deliver_lossy(&|from, to| from == 0 || to == 0);
        if (1..4).all(|i| c.epoch(i) >= 1 && c.node(i).latest_block_height >= 7) {
            break;
        }
    }
    assert!(
        c.node(0).latest_block_height <= cut_at + 1,
        "vacuous: node 0 kept up"
    );
    assert!(
        (1..4).all(|i| c.epoch(i) >= 1),
        "vacuous: no boundary passed"
    );
    c.run_until(300, |c| {
        c.epoch(0) >= 1 && c.node(0).latest_block_height >= c.node(1).latest_block_height
    });
    c.run(4);
    let placed = c.assert_same_blocks(8);
    for h in 1..=placed {
        let start = crate::v4::epoch::read_start_from(&c.node(0).storage, 1)
            .unwrap()
            .unwrap();
        let (round, _) = c.block(0, h).unwrap();
        if h <= 4 {
            assert!(
                round <= start.prev_closing_round,
                "block {h} at round {round}"
            );
        } else {
            assert!(round >= start.first_round, "block {h} at round {round}");
        }
    }
}

/// EP-3 against lagging placement: every node's block placement stalls
/// (execution fails) while rounds go on past H_0's anchor, so epoch-0 anchors
/// above r* become decidable before anyone closes. When placement resumes,
/// one commit loop places H_0 and must stop there: every block after it
/// anchors an epoch-1 vertex, never an epoch-0 one above r*.
#[test]
fn a_commit_loop_stops_at_the_boundary_even_when_later_anchors_are_ready() {
    static BLOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    fn gate(_: u8, _: &StateDB) -> Result<(), String> {
        if BLOCKED.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("placement stalled (test)".into());
        }
        Ok(())
    }
    let mut c = Cluster::with_interval("epoch-stall", &[35, 36, 37, 38], true, 4);
    for i in 0..4 {
        c.node_mut(i).pre_execution_hook = Some(gate);
    }
    c.run_until(80, |c| (0..4).all(|i| c.node(i).latest_block_height >= 3));
    BLOCKED.store(true, std::sync::atomic::Ordering::SeqCst);
    let stalled_at = c.node(0).latest_block_height;
    c.run(14);
    assert_eq!(
        c.node(0).latest_block_height,
        stalled_at,
        "placement was not stalled"
    );
    BLOCKED.store(false, std::sync::atomic::Ordering::SeqCst);
    c.run_until(300, |c| {
        (0..4).all(|i| c.epoch(i) >= 1 && c.node(i).latest_block_height >= 8)
    });
    let placed = c.assert_same_blocks(8);
    let db = &c.node(0).storage;
    let start = crate::v4::epoch::read_start_from(db, 1).unwrap().unwrap();
    for h in 5..=placed {
        let block: blockchain::Block =
            serde_json::from_str(&db.get(&format!("block_{h}")).unwrap().unwrap()).unwrap();
        let anchor: blockchain::Vertex = serde_json::from_str(
            &db.get(&format!("vertex:{}", block.anchor_hash))
                .unwrap()
                .expect("the anchor body is held"),
        )
        .unwrap();
        assert!(
            anchor.epoch >= 1,
            "block {h} anchors an epoch-{} vertex at round {} (r* = {})",
            anchor.epoch,
            anchor.round,
            start.prev_closing_round
        );
    }
}

// ------------------------------------------------ final review (dos) regressions

/// DOS-3: `QC_WANT` is "answered at most once per throttle window per
/// height", but the window map is cleared whenever it holds 16 heights. With
/// 17 boundary heights holding a QC (17 epochs), asking them in rotation gets
/// every ask answered, each answer a broadcast (gossip plus one fresh TCP
/// connection per peer).
#[test]
fn dos_qc_want_throttle_is_bypassed_by_rotating_17_heights() {
    let mut c = Cluster::with_interval("dos-qcwant", &[71, 72, 73, 74], true, 4);
    c.run_until(200, |c| c.node(1).latest_block_height >= 17);
    assert!(c.node(1).latest_block_height >= 17, "vacuous: too few blocks");
    let heights: Vec<u64> = (1..=17).collect();
    for h in &heights {
        c.node(1)
            .storage
            .put(&format!("consensus:qc:{h}"), &format!("{{\"stand_in_for_qc\":{h}}}"))
            .unwrap();
    }
    let outbox = c.node(1).v4_outbox.clone().unwrap();
    outbox.lock().unwrap().clear();
    let rounds = 3;
    for _ in 0..rounds {
        for h in &heights {
            c.node_mut(1).handle_message(&format!("{}{h}", crate::dag::QC_WANT_PREFIX));
        }
    }
    let answers = outbox
        .lock()
        .unwrap()
        .iter()
        .filter(|w| w.starts_with(crate::dag::QC_CERT_PREFIX))
        .count();
    // However the asks are spread over heights, one tick answers at most
    // QC_ANSWERS_PER_TICK of them (and does answer).
    assert!(answers > 0, "vacuous: nothing was answered");
    assert!(
        answers <= 4,
        "{answers} answers to {} asks in one tick",
        rounds * heights.len()
    );
}

/// DOS-4: every copy of a staged body makes the node re-send its attestation
/// (`resend_attestation`), and `V4Net::send` is a broadcast (gossip plus one
/// fresh TCP connection per peer). No throttle: N copies from anyone, N
/// broadcasts.
#[test]
fn dos_each_replayed_vertex_copy_triggers_an_attestation_broadcast() {
    let mut c = Cluster::new("dos-reattest", &[91, 92, 93, 94], true);
    c.run(6);
    let author = c.node(1).v4.as_ref().unwrap();
    let v = (1..40)
        .filter_map(|r| author.own_proposal(r).cloned())
        .find(|v| c.node(0).v4.as_ref().unwrap().is_staged(&v.hash))
        .expect("a proposal of node 1 staged at node 0");
    let wire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Vertex(v)).unwrap()
    );
    let outbox = c.node(0).v4_outbox.clone().unwrap();
    outbox.lock().unwrap().clear();
    let copies = 50;
    for _ in 0..copies {
        c.node_mut(0).handle_message(&wire);
    }
    let attests = outbox
        .lock()
        .unwrap()
        .iter()
        .filter(|w| w.starts_with(&format!("{}{{\"Attest\"", crate::v4::WIRE_PREFIX)))
        .count();
    eprintln!("{copies} replayed copies of one staged body: {attests} attestation broadcasts");
    assert!(attests <= 1, "{attests} attestation broadcasts for {copies} copies of one body");
}

// ------------------------------------------------ final review (ingress) regressions

/// Byzantine node 3 (offline otherwise) signs a round-r vertex whose
/// canonical body is `MAX_VERTEX_BYTES - margin` bytes, shows it to nodes 1
/// and 2 only, and certifies it with them. Node 0 must pull it. Returns
/// (node 0 height before, after; node 1 height before, after; still wanted).
fn rev_withheld_body(tag: &str, seeds: [u8; 4], margin: usize) -> (u64, u64, u64, u64, bool) {
    let mut c = Cluster::new(tag, &seeds, true);
    c.run(4);
    let offline = |from: usize, to: usize, _w: &str| from == 3 || to == 3;
    let run3 = |c: &mut Cluster, ticks: usize| {
        for _ in 0..ticks {
            for i in 0..3 {
                c.node_mut(i).try_create_vertex();
            }
            c.deliver_filtered(&offline);
        }
    };
    run3(&mut c, 3);
    let byz_addr = c.known[3].0.clone();
    let r = c.node(1).v4.as_ref().unwrap().current_round();
    let mut refs: Vec<blockchain::ParentRef> = Vec::new();
    for (a, _) in &c.known {
        if let Some(d) = c.node(1).v4.as_ref().unwrap().certified(r - 1, a) {
            refs.push(blockchain::ParentRef {
                round: r - 1,
                author: a.clone(),
                digest: d.to_string(),
                proof: None,
                cert: None,
            });
        }
    }
    refs.sort_by(|a, b| a.author.cmp(&b.author));
    assert!(refs.len() >= 3, "no quorum at r-1");
    let chain = crate::qc::expected_chain_id();
    let key = crypto::SigningKey::from_bytes(&[seeds[3]; 32]);
    let build = |payload: Vec<String>| {
        let mut v = blockchain::Vertex {
            epoch: 0,
            round: r,
            author: byz_addr.clone(),
            parents: refs.iter().map(|x| x.digest.clone()).collect(),
            parent_refs: refs.clone(),
            payload,
            timestamp: PINNED,
            hash: String::new(),
            signature: String::new(),
            aggregated_signature: None,
            payload_root: None,
            parents_root: None,
        };
        v.hash = v.hash_v4_with_domain(&chain, GENESIS_IDENTITY);
        v.sign_with_ed25519(&key);
        v
    };
    let base = serde_json::to_string(&build(vec![])).unwrap().len();
    let v = build(crate::test_txs::payload_of_size(
        &chain,
        seeds[3],
        crate::dag::MAX_VERTEX_BYTES - margin - base,
    ));
    let canonical = serde_json::to_string(&v).unwrap().len();
    assert_eq!(canonical, crate::dag::MAX_VERTEX_BYTES - margin);
    let wire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Vertex(v.clone())).unwrap()
    );
    c.node_mut(1).handle_message(&wire);
    c.node_mut(2).handle_message(&wire);
    assert!(c.node(1).v4.as_ref().unwrap().is_staged(&v.hash), "1 did not stage");
    assert!(c.node(2).v4.as_ref().unwrap().is_staged(&v.hash), "2 did not stage");
    // Nodes 1 and 2 attested it (deterministic BLS: forge_cert's signatures
    // are the ones they produced); the Byzantine author aggregates.
    let cert = forge_cert(&c, r, &byz_addr, &v.hash, &[seeds[1], seeds[2], seeds[3]]);
    let cwire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Cert(cert)).unwrap()
    );
    for i in 0..3 {
        c.node_mut(i).handle_message(&cwire);
    }
    c.deliver_filtered(&offline);
    let (h0, h1) = (c.node(0).latest_block_height, c.node(1).latest_block_height);
    run3(&mut c, 30);
    let wanted = c
        .node(0)
        .v4
        .as_ref()
        .unwrap()
        .wanted_bodies()
        .contains(&v.hash);
    let top_qc = (1..=c.node(1).latest_block_height)
        .filter(|h| c.qc(1, *h).is_some())
        .max()
        .unwrap_or(0);
    eprintln!("REV-QC {tag}: node 1 highest QC'd height {top_qc} of {}", c.node(1).latest_block_height);
    (
        h0,
        c.node(0).latest_block_height,
        h1,
        c.node(1).latest_block_height,
        wanted,
    )
}

/// Control: a large withheld body (MAX - 2000) is pulled and node 0 keeps up.
#[test]
fn rev_control_a_large_withheld_body_is_pulled() {
    let (h0, h0b, h1, h1b, wanted) = rev_withheld_body("rev-body-ctl", [211, 212, 213, 214], 2000);
    assert!(h1b > h1, "vacuous: nodes 1/2 placed nothing ({h1} -> {h1b})");
    assert!(!wanted, "control: body still wanted");
    assert!(h0b > h0 + 3, "control: node 0 stalled ({h0} -> {h0b})");
}

/// REVIEW PoC: a withheld body within ~90 bytes of MAX_VERTEX_BYTES is
/// served (MAX_RESP_BYTES = 900 KiB) but every RESP carrying it exceeds the
/// node's pre-parse cap (MAX_VERTEX_BYTES + 11), so node 0 can never pull it
/// and stops ordering for good.
#[test]
fn rev_a_near_max_withheld_body_can_never_be_pulled() {
    let (h0, h0b, h1, h1b, wanted) = rev_withheld_body("rev-body-max", [221, 222, 223, 224], 20);
    assert!(h1b > h1, "vacuous: nodes 1/2 placed nothing ({h1} -> {h1b})");
    assert!(
        h0b + 1 >= h1b && !wanted,
        "node0 height {h0} -> {h0b}; node1 {h1} -> {h1b}; body still wanted by node 0: {wanted}"
    );
}

// ---------------------------------------- final review (test quality): kill tests

/// KILL(M55), DE-7 after an epoch change: the node's own decisions in E+1
/// (leader and reward recipient) use C_{E+1}'s stakes, not C_E's. The
/// existing stake-change witness checks only the engine's stake table.
#[test]
fn kill_m55_blocks_of_the_next_epoch_are_led_by_its_committee() {
    let mut c = Cluster::with_interval("kill-m55", &[95, 96, 97, 98], true, 4);
    fn reweigh(_: u8, view: &StateDB) -> Result<(), String> {
        let raw = view
            .get("genesis:validator_set:v1")
            .map_err(|e| e.to_string())?
            .unwrap();
        let mut set: Vec<ValidatorInfo> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        set = crate::qc::canonical_order(&set);
        set[0].stake = 10_000;
        view.put("sys:validator_set:v1", &serde_json::to_string(&set).unwrap())
            .map_err(|e| e.to_string())
    }
    for i in 0..4 {
        c.node_mut(i).pre_execution_hook = Some(reweigh);
    }
    c.run_until(300, |c| (0..4).all(|i| c.epoch(i) >= 1 && c.node(i).latest_block_height >= 12));
    let top = c.assert_same_blocks(12);
    let start = crate::v4::epoch::read_start_from(&c.node(0).storage, 1).unwrap().unwrap();
    let c1: Vec<(String, u64)> = start.committee.iter().map(|m| (m.address.clone(), m.stake)).collect();
    let c0: Vec<(String, u64)> = crate::qc::canonical_order(&c.committee)
        .iter()
        .map(|m| (m.address.clone(), m.stake))
        .collect();
    let mut differs = 0;
    for h in 5..=top.min(8) {
        let b: blockchain::Block =
            serde_json::from_str(&c.node(0).storage.get(&format!("block_{h}")).unwrap().unwrap()).unwrap();
        let want = crate::ordering::OrderingEngine::leader_for_round(b.header.round, &c1, 0);
        if want != crate::ordering::OrderingEngine::leader_for_round(b.header.round, &c0, 0) {
            differs += 1;
        }
        assert_eq!(b.header.proposer_id, want, "block {h} (round {}) led by the wrong committee", b.header.round);
    }
    assert!(differs > 0, "vacuous: C_0 and C_1 elect the same leaders here");
}

/// RC-3 (S11): the guard-origin flag is honored only from ten minutes before
/// `sys:genesis_time` to an hour after it, and never without a genesis time.
#[test]
fn the_guard_origin_flag_is_honored_only_in_the_launch_window() {
    let path = std::env::temp_dir()
        .join(format!("aincore_launch_window_{}", std::process::id()))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_dir_all(&path);
    let db = StateDB::open(&path).unwrap();
    assert!(!DagConsensus::within_launch_window(&db, 1_000_000));
    {
        let _seed = db.seeding();
        db.put("sys:genesis_time", "1000000").unwrap();
    }
    let t = 1_000_000u64;
    let w = crate::dag::LAUNCH_WINDOW_SECS;
    let skew = crate::dag::LAUNCH_WINDOW_SKEW_SECS;
    assert!(DagConsensus::within_launch_window(&db, t));
    assert!(DagConsensus::within_launch_window(&db, t + w));
    assert!(!DagConsensus::within_launch_window(&db, t + w + 1));
    assert!(DagConsensus::within_launch_window(&db, t - skew));
    assert!(!DagConsensus::within_launch_window(&db, t - skew - 1));
    drop(db);
    let _ = std::fs::remove_dir_all(&path);
}

/// S11b: a V4 node takes no V3 evidence. A valid V3 equivocation proof by a
/// committee member (two V3-hashed vertices of one round, both signed by its
/// key) and a downtime attestation change nothing: no evidence row, no gossip
/// mark, no attestation row.
#[test]
fn a_v4_node_takes_no_v3_evidence() {
    let mut c = Cluster::new("v3-evidence", &[45, 46, 47, 48], true);
    c.run(4);
    let (addr, _, key) = tier2_keypair(46);
    let mk = |payload: &str| {
        let mut v = blockchain::Vertex::new(5, addr.clone(), vec!["genesis".into()], vec![payload.into()]);
        v.sign_with_ed25519(&crypto::SigningKey::from_bytes(&key));
        v
    };
    let (a, b) = (mk("a"), mk("b"));
    assert_ne!(a.hash, b.hash);
    let proof = serde_json::json!({ "vertex_a": a, "vertex_b": b }).to_string();
    let rows = |c: &Cluster| -> usize {
        ["sys:equiv_seen:", "sys:equiv_gossiped:", "sys:downtime", "sys:pending_slash:"]
            .iter()
            .map(|p| {
                c.node(0)
                    .storage
                    .db
                    .prefix_iterator(p.as_bytes())
                    .take_while(|r| r.as_ref().is_ok_and(|(k, _)| k.starts_with(p.as_bytes())))
                    .count()
            })
            .sum()
    };
    let before = rows(&c);
    c.node_mut(0).handle_message(&format!("EQUIV_PROOF:{proof}"));
    let attest = serde_json::json!({ "offender": addr, "reporter": addr, "round": 5 }).to_string();
    c.node_mut(0).handle_message(&format!("DOWNTIME_ATTEST:{attest}"));
    assert_eq!(rows(&c), before, "a V4 node recorded V3 evidence");
}

/// G1 EQ-1, G5 SL-3 on real V4 nodes: an author that sends a second body
/// for its slot to one node is caught there. That node keeps the pair in an
/// epoch-keyed row and carries it through the DAG; every node's chain holds
/// it in the same block.
#[test]
fn a_v4_twin_is_recorded_and_carried_in_every_nodes_block() {
    let mut c = Cluster::new("twin-evidence", &[51, 52, 53, 54], true);
    c.run(3);
    let (author, _, key) = tier2_keypair(52);
    // Node 1 (seed 52) proposes; hold its messages to find the vertex.
    c.node_mut(1).try_create_vertex();
    let outbox = c.node(1).v4_outbox.clone().unwrap();
    let original = outbox
        .lock()
        .unwrap()
        .iter()
        .filter_map(|w| w.strip_prefix(crate::v4::WIRE_PREFIX))
        .filter_map(|json| serde_json::from_str::<crate::v4::Msg>(json).ok())
        .find_map(|m| match m {
            crate::v4::Msg::Vertex(v) if v.author == author => Some(v),
            _ => None,
        })
        .expect("node 1 proposed a vertex");
    let mut twin = original.clone();
    twin.payload
        .push(crate::test_txs::tx(&crate::qc::expected_chain_id(), 77, 0));
    twin.payload_root = None;
    twin.hash = twin.hash_v4_with_domain(&crate::qc::expected_chain_id(), GENESIS_IDENTITY);
    twin.sign_with_ed25519(&crypto::SigningKey::from_bytes(&key));
    assert_ne!(twin.hash, original.hash);
    c.deliver();
    let wire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Vertex(twin.clone())).unwrap()
    );
    c.node_mut(0).handle_message(&wire);
    let row = crate::v4::evidence::seen_key(&author, original.epoch, original.round);
    assert!(
        c.node(0).storage.get(&row).unwrap().is_some(),
        "the node that saw both bodies keeps the pair"
    );
    let item = c.node(0).storage.get(&row).unwrap().unwrap();
    c.run_until(60, |c| (0..4).all(|i| carried_at(c, i, &item).is_some()));
    // Every node's chain carries the item at the same height, in the same
    // blocks. (Conviction needs the Move stdlib, which these fixtures do not
    // load: executor `g5_v4_twin_evidence_is_checked_against_its_committee_and_age`
    // witnesses it on the same item shape.)
    let at = carried_at(&c, 0, &item).expect("a block carries the V4 evidence");
    for i in 1..4 {
        assert_eq!(carried_at(&c, i, &item), Some(at), "node {i}");
    }
    c.assert_same_blocks(at);
    // The bytes consensus built are the bytes the executor convicts on.
    let verified = c.node(0).executor.verify_slash_evidence(&item).unwrap();
    assert_eq!(verified.offenders, vec![author.clone()]);
    assert_eq!(
        (verified.epoch, verified.round),
        (original.epoch, original.round)
    );
}

/// The height of the first block on node `i` that carries `item`.
fn carried_at(c: &Cluster, i: usize, item: &str) -> Option<u64> {
    (1..=c.node(i).latest_block_height).find(|h| {
        c.node(i)
            .storage
            .get(&format!("block_{h}"))
            .unwrap()
            .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
            .is_some_and(|b| b.slash_evidence.iter().any(|e| e == item))
    })
}

/// G1 CE-3, G5 SL-3 on real V4 nodes: a node that sees two certificates for
/// one slot halts ordering (CE-3) and keeps the pair in an epoch-keyed row.
/// The item verifies on the executor and convicts exactly the members whose
/// bit is set in both certificates. A conflict means safety was attacked, so
/// the chain halts where it is seen, and the node relays both certificates
/// once so every honest node halts and keeps the pair. After recovery (the
/// operators clear the halt) the row is carried like any evidence row, in
/// the same block on every node.
#[test]
fn a_certificate_conflict_is_recorded_as_evidence_against_both_signers() {
    let mut c = Cluster::new("cert-conflict", &[131, 132, 133, 134], true);
    c.run(6);
    let author = c.known[1].0.clone();
    let fake = "cd".repeat(32);
    let forged = forge_cert(&c, 1, &author, &fake, &[131, 132, 133]);
    let wire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Cert(forged.clone())).unwrap()
    );
    c.node_mut(0).handle_message(&wire);
    assert!(c.node(0).ordering_halted().is_some(), "not halted");
    let row = crate::v4::evidence::cert_seen_key(&author, 0, 1);
    let item = c
        .node(0)
        .storage
        .get(&row)
        .unwrap()
        .expect("the halted node keeps the pair");
    let verified = c
        .node(0)
        .executor
        .verify_slash_evidence(&item)
        .expect("the pair verifies on the executor");
    let ordered = crate::qc::canonical_order(&c.committee);
    let pair: serde_json::Value = serde_json::from_str(&item).unwrap();
    let bitmap = |field: &str| -> Vec<u8> {
        serde_json::from_value(pair[field]["signer_bitmap"].clone()).unwrap()
    };
    let (a, b) = (bitmap("cert_a"), bitmap("cert_b"));
    let both: Vec<String> = ordered
        .iter()
        .enumerate()
        .filter(|(i, _)| blockchain::attest::bit_set(&a, *i) && blockchain::attest::bit_set(&b, *i))
        .map(|(_, m)| m.address.clone())
        .collect();
    assert!(!both.is_empty(), "two quorums of four always overlap");
    assert_eq!(verified.offenders, both);
    assert_eq!((verified.epoch, verified.round), (0, 1));

    // G5 review: the halted node relays both certificates once, so every
    // honest node halts too and keeps the pair (it was the only holder).
    c.deliver();
    for i in 0..4 {
        assert!(
            c.node(i).ordering_halted().is_some(),
            "node {i} did not halt"
        );
        assert!(
            c.node(i).storage.get(&row).unwrap().is_some(),
            "node {i} does not hold the pair"
        );
    }
    // Recovery, an operator action on every node (runbook step 5): the
    // canonical certificate is pinned, which clears the halt, and the node
    // restarts. The evidence row stays and is carried.
    let real = held_cert(&c, 0, 1, &author);
    for i in 0..4 {
        let pinned = pin(&c, i, &real).expect("the real certificate pins");
        assert!(pinned.alarm_cleared, "node {i} had no halt to clear");
        assert!(c.node(i).storage.get(&row).unwrap().is_some(), "node {i} lost the pair");
        c.reopen(i);
        assert!(
            c.node(i).ordering_halted().is_none(),
            "node {i} is still halted"
        );
    }
    c.run_until(40, |c| (0..4).all(|i| carried_at(c, i, &item).is_some()));
    // Every node's chain carries the pair at the same height, in the same
    // blocks; each verifies it to the same offenders. (Conviction needs the
    // Move stdlib, which these fixtures do not load: executor
    // `g5_a_certificate_conflict_convicts_every_attester_in_both` witnesses
    // it on the same item shape.)
    let at = carried_at(&c, 0, &item).expect("a block carries the pair after recovery");
    for i in 0..4 {
        assert_eq!(carried_at(&c, i, &item), Some(at), "node {i}");
    }
    c.assert_same_blocks(at);
}

/// The certificate row node `i` holds for slot (epoch 0, round, author).
fn held_cert(c: &Cluster, i: usize, round: u64, author: &str) -> crate::vcert::VertexCertificate {
    let raw = c
        .node(i)
        .storage
        .get(&crate::staging::vcert_key(0, round, author))
        .unwrap()
        .expect("a certificate row");
    serde_json::from_str(&raw).unwrap()
}

fn pin(
    c: &Cluster,
    i: usize,
    cert: &crate::vcert::VertexCertificate,
) -> Result<crate::v4::recovery::Pinned, String> {
    crate::v4::recovery::pin_canonical(
        &c.node(i).storage,
        cert,
        &c.committee,
        &crate::qc::expected_chain_id(),
        GENESIS_IDENTITY,
    )
}

/// The recovery tool (runbook step 5) on a node whose certificate row holds
/// the other digest: the canonical certificate replaces it, the other digest
/// loses the certified role, and the restarted cluster places the same
/// blocks. It refuses a certificate that does not verify, and a node that
/// ordered the other digest, writing nothing in either case.
#[test]
fn the_recovery_tool_pins_the_canonical_certificate_on_every_node() {
    let mut c = Cluster::new("cert-pin", &[141, 142, 143, 144], true);
    c.run(6);
    let author = c.known[1].0.clone();
    let real = held_cert(&c, 0, 1, &author);
    let fake = "ef".repeat(32);
    let forged = forge_cert(&c, 1, &author, &fake, &[141, 142, 143]);
    // Node 2 holds the forged certificate, as if it had arrived first: its
    // slot row gives the forged digest the certified role, and the real
    // body only the role of its own attestation.
    let cert_row = crate::staging::vcert_key(0, 1, &author);
    let slot_row = crate::staging::vslot_key(0, 1, &author);
    let bytes_row = crate::staging::vbytes_key(0, &author);
    let plain = |s: &StateDB| -> u64 {
        s.get(&bytes_row).unwrap().map_or(0, |v| v.parse().unwrap())
    };
    let plain_before = {
        let store = &c.node(2).storage;
        store
            .put(&cert_row, &serde_json::to_string(&forged).unwrap())
            .unwrap();
        let mut slot: Vec<crate::staging::SlotEntry> =
            serde_json::from_str(&store.get(&slot_row).unwrap().unwrap()).unwrap();
        for e in slot.iter_mut() {
            e.role = crate::staging::Role::SelfAttested;
        }
        slot.push(crate::staging::SlotEntry {
            digest: fake.clone(),
            role: crate::staging::Role::Certified,
            bytes: 100,
        });
        store.put(&slot_row, &serde_json::to_string(&slot).unwrap()).unwrap();
        plain(store)
    };
    c.reopen(2);
    // The real certificate reaches it: CE-3 halts it, and its relay halts
    // the others.
    let wire = format!(
        "{}{}",
        crate::v4::WIRE_PREFIX,
        serde_json::to_string(&crate::v4::Msg::Cert(real.clone())).unwrap()
    );
    c.node_mut(2).handle_message(&wire);
    c.deliver();
    for i in 0..4 {
        assert!(c.node(i).ordering_halted().is_some(), "node {i} did not halt");
    }
    // Step 4: every node ordered the real vertex, so it is canonical.
    let states: Vec<_> = (0..4)
        .map(|i| crate::v4::recovery::slot_state(&c.node(i).storage, 0, 1, &author).unwrap())
        .collect();
    let ordered: Vec<&str> = states
        .iter()
        .flat_map(|s| s.ordered.iter().map(String::as_str))
        .collect();
    assert!(!ordered.is_empty(), "vacuous: no node ordered the slot");
    let pair = states[2].alarm_digests.clone().expect("node 2 holds the alarm");
    let chosen =
        crate::v4::recovery::choose_canonical((pair.0.as_str(), pair.1.as_str()), ordered).unwrap();
    assert_eq!(chosen, real.body.digest);

    // A certificate below quorum does not verify: nothing is written.
    let thin = thin_cert(&c, 1, &author, &real.body.digest, &[141, 142, 143], 141);
    let alarm = crate::v4::recovery::alarm_key(0, 1, &author);
    assert!(pin(&c, 2, &thin).unwrap_err().contains("does not verify"));
    assert!(
        c.node(2).storage.get(&alarm).unwrap().is_some(),
        "a refused pin cleared the alarm"
    );
    // A node that ordered the other digest is refused: nothing is written.
    let cseq = "consensus:cseq:999999999";
    c.node(3)
        .storage
        .put(cseq, &serde_json::to_string(&vec![fake.clone()]).unwrap())
        .unwrap();
    let refused = pin(&c, 3, &real).unwrap_err();
    assert!(refused.contains("ordered"), "{refused}");
    assert!(c.node(3).storage.get(&alarm).unwrap().is_some());
    c.node(3).storage.delete(cseq).unwrap();

    for i in 0..4 {
        let pinned = pin(&c, i, &real).unwrap();
        assert!(pinned.alarm_cleared, "node {i}");
        if i == 2 {
            assert_eq!(pinned.replaced.as_deref(), Some(fake.as_str()));
            assert_eq!(pinned.demoted, vec![fake.clone()]);
        } else {
            assert_eq!(pinned.replaced, None, "node {i}");
        }
    }
    assert_eq!(held_cert(&c, 2, 1, &author), real);
    let slot: Vec<crate::staging::SlotEntry> =
        serde_json::from_str(&c.node(2).storage.get(&slot_row).unwrap().unwrap()).unwrap();
    let roles: HashMap<String, crate::staging::Role> =
        slot.into_iter().map(|e| (e.digest, e.role)).collect();
    assert_eq!(roles[&fake], crate::staging::Role::Staged);
    assert_eq!(roles[&real.body.digest], crate::staging::Role::SelfAttested);
    assert_eq!(plain(&c.node(2).storage), plain_before + 100);
    for i in 0..4 {
        c.reopen(i);
        assert!(c.node(i).ordering_halted().is_none(), "node {i} is still halted");
    }
    let before = c.node(0).latest_block_height;
    c.run_until(40, |c| (0..4).all(|i| c.node(i).latest_block_height > before + 2));
    c.assert_same_blocks(before + 3);
}

/// A certificate of `signers` (a quorum) whose bitmap keeps only `keep`:
/// below quorum, so it must not verify.
fn thin_cert(
    c: &Cluster,
    round: u64,
    author: &str,
    digest: &str,
    signers: &[u8],
    keep: u8,
) -> crate::vcert::VertexCertificate {
    let mut cert = forge_cert(c, round, author, digest, signers);
    let ordered = crate::qc::canonical_order(&c.committee);
    let keep = validator_info(keep).address;
    let mut bitmap = vec![0u8; cert.signer_bitmap.len()];
    for (idx, m) in ordered.iter().enumerate() {
        if m.address == keep {
            bitmap[idx / 8] |= 1 << (idx % 8);
        }
    }
    cert.signer_bitmap = bitmap;
    cert
}

// ---------------------------------------------------------------------------
// G5 S4c: the local-acceptance crash witnesses on a V4 genesis. They replace
// `local_acceptance_tests` (V3 fixtures, deleted with V3) and keep its
// schedule: a crash is a real process exit (77) at a test hook boundary, and
// the rows on disk are compared across it. The committee is the producer
// alone, so it certifies its own vertices and its block's QC.

const PRODUCER: u8 = 91;
const FOLLOWER: u8 = 92;
const LOCAL_DB: &str = "AINCORE_TEST_V4_LOCAL_DB";
const LOCAL_MODE: &str = "AINCORE_TEST_V4_LOCAL_MODE";
const LOCAL_SEED: &str = "AINCORE_TEST_V4_LOCAL_SEED";
const PENDING_1: &[u8] = b"consensus:qc_pending:00000000000000000001";

struct LocalDir(String);

impl LocalDir {
    /// A V4 genesis whose committee is the producer alone, keyed for `seed`.
    fn seeded(tag: &str, seed: u8) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir()
            .join(format!(
                "aincore_v4_local_{}_{}_{tag}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
            .to_string_lossy()
            .to_string();
        let _ = std::fs::remove_dir_all(&path);
        Cluster::unopened(&[PRODUCER], 1000).seed_db(&path, seed, true);
        Self(path)
    }

    fn rows(&self) -> std::collections::BTreeMap<Vec<u8>, Vec<u8>> {
        let db = StateDB::open(&self.0).unwrap();
        db.db
            .iterator(storage::rocksdb::IteratorMode::Start)
            .map(|row| {
                let (key, value) = row.unwrap();
                (key.to_vec(), value.to_vec())
            })
            // Producer and telemetry hints, written outside acceptance.
            .filter(|(key, _)| {
                key != b"latest_proposed_round" && !key.starts_with(b"validator:last_seen:")
            })
            .collect()
    }

    fn run(&self, mode: &str, seed: u8, code: i32) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::tests::v4_node_tests::v4_local_acceptance_child",
                "--nocapture",
            ])
            .env(LOCAL_DB, &self.0)
            .env(LOCAL_MODE, mode)
            .env(LOCAL_SEED, seed.to_string())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "mode {mode}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

impl Drop for LocalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Tick the lone producer until block 1 is placed (at most 20 ticks).
fn produce_block_1(node: &mut DagConsensus) {
    for _ in 0..20 {
        if node.latest_block_height >= 1 {
            return;
        }
        node.try_create_vertex();
        node.v4_outbox.as_ref().unwrap().lock().unwrap().clear();
    }
}

/// QC 1, verified under the epoch-0 committee.
fn verified_qc_1(node: &DagConsensus) -> crate::qc::QuorumCertificate {
    let cert = crate::qc_producer::stored_qc(&node.storage, 1)
        .expect("block 1 lost its QC work across the crash");
    let set = crate::qc_producer::load_validator_set_for_epoch(&node.storage, 0).unwrap();
    crate::qc::verify_qc(&cert, &set, &cert.chain_id).unwrap();
    cert
}

#[test]
fn v4_local_acceptance_child() {
    let Ok(path) = std::env::var(LOCAL_DB) else {
        return;
    };
    let mode = std::env::var(LOCAL_MODE).unwrap();
    let seed: u8 = std::env::var(LOCAL_SEED).unwrap().parse().unwrap();
    let mut node = open_node(&path, seed);
    assert!(node.v4.is_some(), "the fixture is not a V4 genesis");
    match mode.as_str() {
        "produce" => {
            produce_block_1(&mut node);
            assert_eq!(node.latest_block_height, 1);
            verified_qc_1(&node);
        }
        "crash_after_acceptance" => {
            node.local_acceptance_hook = Some(|boundary, view| {
                // Block, execution marker and QC work commit together.
                assert!(view.get("block_1").unwrap().is_some());
                assert_eq!(
                    view.get("sys:last_executed_height").unwrap().as_deref(),
                    Some("1")
                );
                assert!(view
                    .get(std::str::from_utf8(PENDING_1).unwrap())
                    .unwrap()
                    .is_some());
                assert!(view.get("consensus:qc:1").unwrap().is_none());
                if boundary == 1 {
                    std::process::exit(77);
                }
                Ok(())
            });
            produce_block_1(&mut node);
            panic!("the acceptance crash boundary was not reached");
        }
        "adopt_crash_before" | "adopt_crash_after" => {
            assert_eq!(
                node.last_adopted_height, 0,
                "absence of the adoption marker is not proof of adoption"
            );
            node.local_acceptance_hook = Some(|boundary, view| {
                // Cursor, decision rows and QC work, all in one transaction.
                for row in [
                    "consensus:finalized_round",
                    "consensus:next_anchor_round",
                    "consensus:finality_digest",
                    "consensus:last_anchor_hash",
                ] {
                    assert!(view.get(row).unwrap().is_some(), "{row} is not staged");
                }
                let block: blockchain::Block =
                    serde_json::from_str(&view.get("block_1").unwrap().unwrap()).unwrap();
                assert_eq!(
                    view.get(&crate::ordering::anchor_decision_key(0, block.header.round))
                        .unwrap(),
                    Some(format!("C:{}", block.anchor_hash)),
                    "the decision row is not staged"
                );
                assert!(view
                    .get(std::str::from_utf8(PENDING_1).unwrap())
                    .unwrap()
                    .is_some());
                assert_eq!(
                    view.get("consensus:last_adopted_height")
                        .unwrap()
                        .as_deref(),
                    Some("1")
                );
                let mode = std::env::var(LOCAL_MODE).unwrap();
                if (mode == "adopt_crash_before" && boundary == 2)
                    || (mode == "adopt_crash_after" && boundary == 3)
                {
                    std::process::exit(77);
                }
                Ok(())
            });
            node.reload_chain_tip();
            panic!("the adoption crash boundary was not reached");
        }
        "resume" => {
            let block = node.storage.get("block_1").unwrap();
            assert!(block.is_some());
            node.reload_chain_tip();
            assert_eq!(node.storage.get("block_1").unwrap(), block);
            assert_eq!(node.latest_block_height, 1);
            assert_eq!(node.last_adopted_height, 1);
            verified_qc_1(&node);
            let round: blockchain::Block = serde_json::from_str(block.as_deref().unwrap()).unwrap();
            assert_eq!(
                node.ordering_engine.lock().unwrap().finalized_round,
                round.header.round
            );
        }
        other => panic!("unknown mode {other}"),
    }
}

/// A block accepted just before a crash keeps its QC work: block, execution
/// marker and pending QC row commit in one transaction (boundary 0), the
/// process dies after that commit and before any vote (boundary 1), and the
/// reopened node certifies the same block.
#[test]
fn v4_accepted_block_qc_work_survives_crash_before_attestation() {
    let control = LocalDir::seeded("control", PRODUCER);
    control.run("produce", PRODUCER, 0);
    let control_rows = control.rows();
    assert!(control_rows.contains_key(b"consensus:qc:1".as_slice()));
    assert!(
        !control_rows.contains_key(PENDING_1),
        "a placed QC retires its work"
    );

    let crashed = LocalDir::seeded("crashed", PRODUCER);
    crashed.run("crash_after_acceptance", PRODUCER, 77);
    let before = crashed.rows();
    assert!(before.contains_key(b"block_1".as_slice()));
    assert!(before.contains_key(PENDING_1));
    assert!(!before.contains_key(b"consensus:qc:1".as_slice()));
    crashed.run("resume", PRODUCER, 0);
    let after = crashed.rows();
    assert_eq!(
        after.get(b"block_1".as_slice()),
        before.get(b"block_1".as_slice())
    );
    assert!(after.contains_key(b"consensus:qc:1".as_slice()));
    assert!(
        !after.contains_key(PENDING_1),
        "the QC retires the pending work"
    );
}

/// A follower holding block 1 and its QC (IM-1: adoption needs both, and the
/// QC's finality digest must be the follower's own fold) adopts it in one
/// transaction: ordering cursor, decision rows, pending QC row and adoption
/// height commit together. A crash inside that transaction (boundary 2)
/// leaves the rows unchanged; a crash after it (boundary 3) leaves them all.
/// Either way the reopened follower adopts or keeps block 1 and retires the
/// pending row (it is outside the committee: it has no vote to sign), the
/// QC unchanged.
#[test]
fn v4_adopted_block_qc_work_and_cursor_commit_together_across_crash() {
    let producer = LocalDir::seeded("producer", PRODUCER);
    producer.run("produce", PRODUCER, 0);
    let producer_rows = producer.rows();
    let block = producer_rows.get(b"block_1".as_slice()).unwrap().clone();
    let qc = producer_rows
        .get(b"consensus:qc:1".as_slice())
        .unwrap()
        .clone();
    for mode in ["adopt_crash_before", "adopt_crash_after"] {
        let follower = LocalDir::seeded("follower", FOLLOWER);
        {
            // The accepted sync store: block and QC as sync imports them, and
            // the execution marker (this witness isolates adoption).
            let db = StateDB::open(&follower.0).unwrap();
            let _seeding = db.seeding();
            db.save_block_json(1, std::str::from_utf8(&block).unwrap())
                .unwrap();
            db.put("consensus:qc:1", std::str::from_utf8(&qc).unwrap())
                .unwrap();
            db.put("sys:last_executed_height", "1").unwrap();
        }
        let before = follower.rows();
        follower.run(mode, FOLLOWER, 77);
        let crashed = follower.rows();
        if mode == "adopt_crash_before" {
            assert_eq!(crashed, before, "a crash inside adoption commits nothing");
        } else {
            assert!(crashed.contains_key(PENDING_1));
            assert_eq!(
                crashed.get(b"consensus:last_adopted_height".as_slice()),
                Some(&b"1".to_vec())
            );
            assert_eq!(
                crashed.get(b"consensus:finality_digest".as_slice()),
                producer_rows.get(b"consensus:finality_digest".as_slice()),
                "the adopted cursor is the producer's"
            );
            assert_ne!(crashed, before, "the adoption committed");
        }
        follower.run("resume", FOLLOWER, 0);
        let resumed = follower.rows();
        assert_eq!(resumed.get(b"consensus:qc:1".as_slice()), Some(&qc));
        assert_eq!(resumed.get(b"block_1".as_slice()), Some(&block));
        assert!(
            !resumed.contains_key(PENDING_1),
            "{mode}: the work is retired"
        );
    }
}

/// The pending QC row a producer staged with block 1, read at boundary 1.
static PENDING_ROW: Mutex<Option<String>> = Mutex::new(None);

/// G5 S4c (review): a node on a database without the V4 vertex format (boot
/// refuses one in production) is inert, gate by gate. Its database holds a
/// real block 1, the QC over it and the pending QC work a producer staged
/// with it, so each gate has something to act on: it proposes nothing,
/// answers no QC ask, adopts no block, signs no vote, and writes nothing.
#[test]
fn a_node_without_the_v4_format_is_inert() {
    let producer = LocalDir::seeded("inert-producer", PRODUCER);
    {
        let mut node = open_node(&producer.0, PRODUCER);
        node.local_acceptance_hook = Some(|boundary, view| {
            if boundary == 1 {
                *PENDING_ROW.lock().unwrap() =
                    view.get(std::str::from_utf8(PENDING_1).unwrap()).unwrap();
            }
            Ok(())
        });
        produce_block_1(&mut node);
    }
    let pending = PENDING_ROW
        .lock()
        .unwrap()
        .clone()
        .expect("block 1 staged QC work");
    let produced = producer.rows();
    let row = |k: &str| String::from_utf8(produced[k.as_bytes()].clone()).unwrap();
    // The same rows on a V4 database and on one without the format.
    let seed = |tag: &str, v4: bool| {
        let dir = LocalDir::seeded(tag, FOLLOWER);
        let db = StateDB::open(&dir.0).unwrap();
        let _seeding = db.seeding();
        if !v4 {
            db.delete(crate::v4::VERTEX_FORMAT_KEY).unwrap();
        }
        db.save_block_json(1, &row("block_1")).unwrap();
        db.put("consensus:qc:1", &row("consensus:qc:1")).unwrap();
        db.put(std::str::from_utf8(PENDING_1).unwrap(), &pending)
            .unwrap();
        db.put("sys:last_executed_height", "1").unwrap();
        drop(db);
        dir
    };
    // Control: on the V4 database each gate has work. The node adopts block
    // 1 and answers a QC ask.
    let control = seed("inert-control", true);
    {
        let mut node = open_node(&control.0, FOLLOWER);
        node.reload_chain_tip();
        assert_eq!(node.last_adopted_height, 1, "the control did not adopt");
        node.handle_message(&format!("{}1", crate::dag::QC_WANT_PREFIX));
        assert!(
            !node.v4_outbox.as_ref().unwrap().lock().unwrap().is_empty(),
            "the control did not answer the QC ask"
        );
    }
    let inert = seed("inert", false);
    let before = inert.rows();
    let mut node = open_node(&inert.0, FOLLOWER);
    assert!(node.v4.is_none(), "the inert node started an engine");
    for _ in 0..3 {
        node.try_create_vertex();
    }
    node.reload_chain_tip();
    let vertex = produced
        .iter()
        .find(|(k, _)| k.starts_with(b"vertex:"))
        .map(|(_, v)| String::from_utf8(v.clone()).unwrap())
        .expect("the producer stored a vertex");
    for wire in [
        format!("{}1", crate::dag::QC_WANT_PREFIX),
        format!("{}{}", crate::dag::QC_CERT_PREFIX, row("consensus:qc:1")),
        format!("{}{{\"Vertex\":{vertex}}}", crate::v4::WIRE_PREFIX),
        format!("DAG_VERTEX:{vertex}"),
        "EQUIV_PROOF:{}".to_string(),
        "DOWNTIME_ATTEST:{}".to_string(),
    ] {
        node.handle_message(&wire);
    }
    assert_eq!(
        node.last_adopted_height, 0,
        "the inert node adopted block 1"
    );
    assert!(
        node.v4_outbox.as_ref().unwrap().lock().unwrap().is_empty(),
        "the inert node sent something"
    );
    drop(node);
    assert_eq!(inert.rows(), before, "the inert node wrote to its database");
}

/// G5 BT-1, both directions on one node, the others as the control. Behind
/// by 120 s it refuses every other member's vertices as early and places
/// nothing: their stake quorum is the alarm. Ahead by 120 s the others refuse
/// its vertices, but it orders theirs and places blocks whose T is 120 s
/// behind its clock: `CLOCK_DRIFT_ALARM_BLOCKS` of them in a row are the
/// alarm. Each clears with the clock, and no other node alarms (one member's
/// early vertices are not a quorum).
#[test]
fn a_node_whose_clock_drifts_from_the_chain_alarms() {
    use crate::dag::{CLOCK_DRIFT_ALARM_BLOCKS, CLOCK_DRIFT_ALARM_SECS};
    let mut c = Cluster::new("clock-drift", &[151, 152, 153, 154], true);
    c.run(6);
    assert!(c.node(0).latest_block_height > 0, "vacuous: no block yet");
    assert_eq!(c.node(0).clock_drift_alarm(), None);
    let others_quiet = |c: &Cluster| {
        for i in 1..4 {
            assert_eq!(c.node(i).clock_drift_alarm(), None, "node {i}");
        }
    };

    c.node_mut(0).set_now_secs(Arc::new(|| PINNED - 120));
    let at = c.node(0).latest_block_height;
    c.run(4);
    assert_eq!(c.node(0).latest_block_height, at, "a node 120 s behind placed a block");
    let drift = c.node(0).clock_drift_alarm().expect("no alarm when behind");
    assert!(drift < -CLOCK_DRIFT_ALARM_SECS, "drift {drift}");
    others_quiet(&c);

    c.node_mut(0).set_now_secs(Arc::new(|| PINNED));
    let at = c.node(0).latest_block_height;
    c.run_until(60, |c| c.node(0).latest_block_height > at);
    assert!(c.node(0).latest_block_height > at, "vacuous: no block after the fix");
    assert_eq!(c.node(0).clock_drift_alarm(), None, "the behind alarm did not clear");

    c.node_mut(0).set_now_secs(Arc::new(|| PINNED + 120));
    let needed = CLOCK_DRIFT_ALARM_BLOCKS as u64;
    let at = c.node(0).latest_block_height;
    c.run_until(60, |c| c.node(0).latest_block_height >= at + needed);
    assert!(
        c.node(0).latest_block_height >= at + needed,
        "vacuous: node 0 placed {} blocks ahead",
        c.node(0).latest_block_height - at
    );
    let drift = c.node(0).clock_drift_alarm().expect("no alarm when ahead");
    assert!(drift > CLOCK_DRIFT_ALARM_SECS, "drift {drift}");
    others_quiet(&c);

    c.node_mut(0).set_now_secs(Arc::new(|| PINNED));
    let at = c.node(0).latest_block_height;
    c.run_until(60, |c| c.node(0).latest_block_height > at);
    assert!(c.node(0).latest_block_height > at, "vacuous: no block after the fix");
    assert_eq!(c.node(0).clock_drift_alarm(), None, "the ahead alarm did not clear");
}

/// The family a storage key belongs to: its leading words, with ids,
/// heights and hashes cut off.
fn key_family(key: &str) -> String {
    let words: Vec<&str> = key.split(':').collect();
    let is_id = |w: &str| {
        !w.is_empty()
            && (w.bytes().all(|b| b.is_ascii_digit())
                || (w.len() >= 32 && w.bytes().all(|b| b.is_ascii_hexdigit())))
    };
    if words.len() > 1 {
        let kept: Vec<&str> = words.iter().take_while(|w| !is_id(w)).copied().collect();
        return format!("{}:", kept.join(":"));
    }
    // `_`-separated families: block_12, resource_<addr>_<tag>, module_<addr>_<name>.
    match key.split_once('_') {
        Some((head, _)) => format!("{head}_"),
        None => key.to_string(),
    }
}

/// Per family: (keys, bytes of key + value).
fn family_sizes(db: &StateDB) -> std::collections::BTreeMap<String, (i64, i64)> {
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in db.scan_prefix("") {
        let e = out.entry(key_family(&k)).or_insert((0i64, 0i64));
        e.0 += 1;
        e.1 += (k.len() + v.len()) as i64;
    }
    out
}

/// B6 measurement: what a validator keeps per block, by key family, on a
/// four-node cluster whose blocks are empty. The net growth over a run, so
/// rows pruned during it count against their family.
/// `cargo test -p consensus --lib -- --ignored --nocapture b6_storage`.
#[test]
#[ignore = "a measurement, not a check"]
fn b6_storage_per_empty_block_by_key_family() {
    let mut c = Cluster::new("b6", &[101, 102, 103, 104], true);
    // Past the GC horizon (GC_DEPTH + RETAIN_SLACK = 100 rounds), so the
    // DAG rows GC deletes are counted at their steady state.
    c.run(260);
    let before = family_sizes(&c.node(0).storage);
    let h0 = c.node(0).latest_block_height;
    c.run(200);
    let h1 = c.node(0).latest_block_height;
    let after = family_sizes(&c.node(0).storage);
    let blocks = (h1 - h0).max(1) as i64;
    let mut rows: Vec<(String, i64, i64)> = after
        .iter()
        .map(|(f, (n, b))| {
            let (n0, b0) = before.get(f).copied().unwrap_or((0, 0));
            (f.clone(), (n - n0), (b - b0))
        })
        .filter(|(_, n, b)| *n != 0 || *b != 0)
        .collect();
    rows.sort_by_key(|(_, _, b)| -b);
    let total: i64 = rows.iter().map(|(_, _, b)| b).sum();
    println!(
        "b6: {blocks} blocks (height {h0} to {h1}); net logical bytes per block {}",
        total / blocks
    );
    for (family, n, b) in rows {
        println!(
            "b6: {family:<48} keys/block {:>7.2}  bytes/block {:>8}",
            n as f64 / blocks as f64,
            b / blocks
        );
    }
}

/// B6: pruning a block takes every row it left: the block, its QC under both
/// keys, the vote and aggregation rows of its anchor round, the signing
/// guards at its height and round, and the anchor decisions up to its round.
/// The rows of the blocks kept stay.
#[test]
fn pruning_a_block_takes_its_finality_rows() {
    let mut c = Cluster::new("b6-prune", &[111, 112, 113, 114], true);
    c.run_until(400, |c| c.qc(0, 12).is_some());
    let s = Arc::clone(&c.node(0).storage);
    let tip = c.node(0).latest_block_height;
    assert!(c.qc(0, 12).is_some(), "vacuous: no QC at height 12");
    let rows = |prefix: &str| -> Vec<String> {
        s.db.prefix_iterator(prefix.as_bytes())
            .filter_map(Result::ok)
            .take_while(|(k, _)| k.starts_with(prefix.as_bytes()))
            .map(|(k, _)| String::from_utf8(k.to_vec()).unwrap())
            .collect()
    };
    let guards = |suffix: &str| {
        rows("consensus:qc_signing:v1:")
            .into_iter()
            .filter(|k| k.ends_with(suffix))
            .count()
    };
    let round_of = |h: u64| c.qc(0, h).unwrap().anchor_round;
    let (floor, kept) = (5u64, 8u64);
    // A pinned height keeps its block and QC (SN-4); the rest go.
    let pins = state_commit::pin_schedule(tip, tip - floor, state_commit::epoch_interval(&s));
    let pruned: Vec<u64> = (1..floor).filter(|h| !pins.contains(h)).collect();
    assert!(!pruned.is_empty() && !pins.contains(&kept));
    let pruned_rounds: Vec<u64> = pruned.iter().map(|&h| round_of(h)).collect();
    let kept_round = round_of(kept);
    for (&h, r) in pruned.iter().zip(&pruned_rounds) {
        assert!(
            guards(&format!(":height:{h}")) > 0,
            "vacuous: no guard at {h}"
        );
        assert!(
            guards(&format!(":round:{r}")) > 0,
            "vacuous: no guard at round {r}"
        );
    }
    assert!(
        !rows("consensus:anchor_decision:").is_empty(),
        "vacuous: no decisions"
    );

    crate::dag::prune_history(&s, tip, Some((tip - floor, 1_000)));

    for (&h, r) in pruned.iter().zip(&pruned_rounds) {
        assert!(s.get(&format!("block_{h}")).unwrap().is_none(), "block {h}");
        assert!(c.qc(0, h).is_none(), "qc {h}");
        assert!(s
            .get(&format!("consensus:qc_by_round:{r}"))
            .unwrap()
            .is_none());
        assert!(
            rows(&format!("consensus:qc_vote:{r}:")).is_empty(),
            "votes {r}"
        );
        assert!(
            rows(&format!("consensus:qc_vote_agg:{r}:")).is_empty(),
            "agg {r}"
        );
        assert_eq!(guards(&format!(":height:{h}")), 0, "guard at {h}");
        assert_eq!(guards(&format!(":round:{r}")), 0, "guard at round {r}");
    }
    let last_pruned = *pruned_rounds.last().unwrap();
    for key in rows("consensus:anchor_decision:") {
        let round: u64 = key.rsplit(':').next().unwrap().parse().unwrap();
        assert!(round > last_pruned, "decision {key} survived");
    }
    // What is kept stays.
    assert!(s.get(&format!("block_{kept}")).unwrap().is_some());
    assert!(c.qc(0, kept).is_some());
    assert!(guards(&format!(":height:{kept}")) > 0);
    assert!(s
        .get(&format!("consensus:qc_by_round:{kept_round}"))
        .unwrap()
        .is_some());
}
