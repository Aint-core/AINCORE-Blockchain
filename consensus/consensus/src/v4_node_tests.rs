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

impl Cluster {
    fn new(tag: &str, seeds: &[u8], v4: bool) -> Self {
        let committee: Vec<ValidatorInfo> = seeds.iter().map(|s| validator_info(*s)).collect();
        let known: Vec<(String, String)> = committee
            .iter()
            .map(|m| (m.address.clone(), m.ed25519_public_key.clone()))
            .collect();
        let mut cluster = Self {
            nodes: Vec::new(),
            committee,
            known,
        };
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
        if v4 {
            db.put(crate::v4::VERTEX_FORMAT_KEY, "4").unwrap();
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
        seed_state_tree(&db);
    }

    fn open(&mut self, i: usize) {
        let node = &self.nodes[i];
        let db = Arc::new(StateDB::open(&node.path).unwrap());
        let key = [node.seed; 32];
        let node_id = crypto::derive_address(
            crypto::SigningKey::from_bytes(&key)
                .verifying_key()
                .as_bytes(),
        )
        .unwrap();
        let mut c = DagConsensus::new(
            node_id,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Executor::new(Arc::clone(&db))),
            db,
            None,
            None,
            key,
        );
        c.set_now_secs(Arc::new(|| PINNED));
        c.placement_sleep = Arc::new(|_| {});
        c.v4_outbox = Some(Arc::new(Mutex::new(Vec::new())));
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

/// One DAG format per chain: a V4 node ignores V3 vertices, and a V3 node
/// ignores V4 messages.
#[test]
fn a_node_never_mixes_dag_formats() {
    let mut v4 = Cluster::new("mix4", &[89, 90, 91, 92], true);
    let mut v3 = Cluster::new("mix3", &[89, 90, 91, 92], false);
    assert!(v3.node(0).v4.is_none());
    // A V4 message reaches a V3 node: nothing is staged.
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
    let mut c = Cluster::new("tx", &[93, 94, 95, 96], true);
    let key = crypto::SigningKey::from_bytes(&[77u8; 32]);
    let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
    let chain_id = blockchain::chain_id();
    // BCS of `TransactionPayload::PublishModule(vec![vec![7, 7]])`: variant 2,
    // one module of two bytes.
    let payload = hex::encode([2u8, 1, 2, 7, 7]);
    let (seq, gas_limit, gas_price) = (0u64, 100_000u64, 1u128);
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
