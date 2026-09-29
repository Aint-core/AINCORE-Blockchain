// G1 S10: the system suite. Real `DagConsensus` nodes on a V4 genesis, each
// with its own `ChainSync` on the same database. Consensus messages (DAG_V4,
// QC votes, QC_WANT/QC_CERT) travel through the nodes' outboxes; block sync
// is a direct SYNC_REQ/SYNC_RESP exchange followed by the node's adoption
// (`reload_chain_tip`). A node can be offline (it neither sends nor hears),
// partitioned, or restarted on its database.

use super::*;
use consensus::dag::DagConsensus;
use consensus::qc::{derive_validator_bls_seed, ValidatorInfo};
use crypto::bls::BLSEngine;
use storage::object::{Object, Owner};

const PINNED: u64 = 1_700_000_000;
const GENESIS_IDENTITY: &str = "g1-s10-system-genesis";

fn keypair(seed: u8) -> (String, String, [u8; 32]) {
    let key = [seed; 32];
    let sk = crypto::SigningKey::from_bytes(&key);
    let pubkey = hex::encode(sk.verifying_key().to_bytes());
    let addr = crypto::derive_address(sk.verifying_key().as_bytes()).unwrap();
    (addr, pubkey, key)
}

fn validator_with(seed: u8, stake: u64) -> ValidatorInfo {
    let (address, ed25519_public_key, key) = keypair(seed);
    let bls = BLSEngine::consensus();
    let bls_seed = derive_validator_bls_seed(&key);
    ValidatorInfo {
        address,
        stake,
        ed25519_public_key,
        bls_public_key: hex::encode(bls.pubkey_raw(&bls_seed)),
        bls_pop: hex::encode(bls.prove_possession_raw(&bls_seed)),
    }
}

struct SimNode {
    c: Option<DagConsensus>,
    sync: Option<ChainSync>,
    path: String,
    seed: u8,
}

struct Sim {
    nodes: Vec<SimNode>,
    committee: Vec<ValidatorInfo>,
    /// Who hears whom this tick: `link(from, to)`.
    online: Vec<bool>,
    groups: Vec<u8>,
    /// Network faults: loss, delay (in ticks) and reordering, seeded.
    chaos: Option<Chaos>,
    delayed: Vec<(u64, usize, usize, String)>,
    ticks: u64,
    /// A slow node ticks only every `slow.1` steps.
    slow: Option<(usize, u64)>,
}

struct Chaos {
    rng: rand::rngs::StdRng,
    drop_pct: u32,
    delay_pct: u32,
    max_delay: u64,
}

impl Sim {
    fn new(tag: &str, seeds: &[u8], interval: u64) -> Self {
        Self::with_stakes(tag, seeds, &vec![1000; seeds.len()], interval)
    }

    fn with_stakes(tag: &str, seeds: &[u8], stakes: &[u64], interval: u64) -> Self {
        let committee: Vec<ValidatorInfo> = seeds
            .iter()
            .zip(stakes)
            .map(|(s, stake)| validator_with(*s, *stake))
            .collect();
        let mut sim = Self {
            nodes: Vec::new(),
            committee,
            online: vec![true; seeds.len()],
            groups: vec![0; seeds.len()],
            chaos: None,
            delayed: Vec::new(),
            ticks: 0,
            slow: None,
        };
        for (i, seed) in seeds.iter().enumerate() {
            let path = std::env::temp_dir()
                .join(format!(
                    "aincore_s10_{}_{}_{tag}_{i}",
                    std::process::id(),
                    rand::random::<u32>()
                ))
                .to_string_lossy()
                .to_string();
            let _ = fs::remove_dir_all(&path);
            sim.seed_db(&path, *seed, interval);
            sim.nodes.push(SimNode {
                c: None,
                sync: None,
                path,
                seed: *seed,
            });
            sim.open(i);
        }
        sim
    }

    /// The genesis every node derives alike (what `genesis.rs` writes).
    fn seed_db(&self, path: &str, seed: u8, interval: u64) {
        let db = Arc::new(StateDB::open(path).unwrap());
        let _seeding = db.seeding();
        for m in &self.committee {
            let account = Object::new(
                m.address.clone(),
                Owner::Address(m.address.clone()),
                serde_json::json!({ "public_key": m.ed25519_public_key, "sequence_number": 0 })
                    .to_string()
                    .into_bytes(),
                "0x1::account::AccountData".to_string(),
            );
            db.put_object(&account).unwrap();
        }
        let vset: Vec<(String, u64)> = self
            .committee
            .iter()
            .map(|m| (m.address.clone(), m.stake))
            .collect();
        // (the genesis committee's stakes are whole AIN, as genesis.rs writes)
        db.put("sys:validators", &serde_json::to_string(&vset).unwrap())
            .unwrap();
        let set = serde_json::to_string(&self.committee).unwrap();
        db.put("genesis:validator_set:v1", &set).unwrap();
        db.put("sys:validator_set:v1", &set).unwrap();
        db.put("genesis_identity", GENESIS_IDENTITY).unwrap();
        db.put(consensus::v4::VERTEX_FORMAT_KEY, "4").unwrap();
        db.put(
            consensus::v4::epoch::EPOCH_INTERVAL_KEY,
            &interval.to_string(),
        )
        .unwrap();
        db.put(
            "consensus:guard_origin",
            &consensus::v4::guard_origin(
                &consensus::qc::expected_chain_id(),
                GENESIS_IDENTITY,
                &[seed; 32],
            ),
        )
        .unwrap();
        drop(_seeding);
        let seeded = state_commit::seed_genesis(&db).expect("seed state tree v0");
        db.write_batch(seeded.batch).unwrap();
    }

    fn open(&mut self, i: usize) {
        let node = &self.nodes[i];
        let db = Arc::new(StateDB::open(&node.path).unwrap());
        let (node_id, _, key) = keypair(node.seed);
        let mut c = DagConsensus::new(
            node_id.clone(),
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::new(executor::Executor::new(Arc::clone(&db))),
            Arc::clone(&db),
            None,
            None,
            key,
        );
        c.set_now_secs(Arc::new(|| PINNED));
        c.placement_sleep = Arc::new(|_| {});
        c.v4_outbox = Some(Arc::new(Mutex::new(Vec::new())));
        let sync = ChainSync::new(
            node_id,
            9000 + i as u16,
            Arc::new(Mutex::new(HashMap::new())),
            db,
        );
        self.nodes[i].c = Some(c);
        self.nodes[i].sync = Some(sync);
    }

    /// Crash and restart node `i` on its database.
    fn reopen(&mut self, i: usize) {
        self.nodes[i].c = None;
        self.nodes[i].sync = None;
        self.open(i);
    }

    fn node(&self, i: usize) -> &DagConsensus {
        self.nodes[i].c.as_ref().unwrap()
    }

    fn node_mut(&mut self, i: usize) -> &mut DagConsensus {
        self.nodes[i].c.as_mut().unwrap()
    }

    fn linked(&self, from: usize, to: usize) -> bool {
        self.online[from] && self.online[to] && self.groups[from] == self.groups[to]
    }

    /// Deliver queued consensus messages over the current links, until quiet.
    /// What an offline or partitioned-away node would have heard is lost.
    /// Under chaos a copy may be dropped, held for a few ticks, and every
    /// batch is delivered in a shuffled order.
    fn deliver(&mut self) {
        use rand::seq::SliceRandom;
        use rand::Rng;
        let now = self.ticks;
        let due: Vec<(usize, usize, String)> = {
            let (ready, later): (Vec<_>, Vec<_>) =
                std::mem::take(&mut self.delayed).into_iter().partition(|d| d.0 <= now);
            self.delayed = later;
            ready.into_iter().map(|(_, f, t, w)| (f, t, w)).collect()
        };
        for (from, to, wire) in due {
            if self.linked(from, to) {
                self.node_mut(to).handle_message(&wire);
            }
        }
        loop {
            let mut batch: Vec<(usize, usize, String)> = Vec::new();
            for i in 0..self.nodes.len() {
                let outbox = self.node(i).v4_outbox.clone().unwrap();
                let sent: Vec<String> = outbox.lock().unwrap().drain(..).collect();
                for w in sent {
                    for to in 0..self.nodes.len() {
                        if to != i {
                            batch.push((i, to, w.clone()));
                        }
                    }
                }
            }
            if batch.is_empty() {
                break;
            }
            if let Some(chaos) = self.chaos.as_mut() {
                batch.shuffle(&mut chaos.rng);
            }
            for (from, to, wire) in batch {
                if !self.linked(from, to) {
                    continue;
                }
                if let Some(chaos) = self.chaos.as_mut() {
                    let roll = chaos.rng.gen_range(0..100);
                    if roll < chaos.drop_pct {
                        continue;
                    }
                    if roll < chaos.drop_pct + chaos.delay_pct {
                        let wait = chaos.rng.gen_range(1..=chaos.max_delay);
                        self.delayed.push((now + wait, from, to, wire));
                        continue;
                    }
                }
                self.node_mut(to).handle_message(&wire);
            }
        }
    }

    /// One tick for every online node (a slow one only every few steps),
    /// then delivery.
    fn step(&mut self) {
        self.ticks += 1;
        for i in 0..self.nodes.len() {
            let slowed = self
                .slow
                .is_some_and(|(n, every)| n == i && !self.ticks.is_multiple_of(every));
            if self.online[i] && !slowed {
                self.node_mut(i).try_create_vertex();
            }
        }
        self.deliver();
    }

    fn run(&mut self, ticks: usize) {
        for _ in 0..ticks {
            self.step();
        }
    }

    fn run_until(&mut self, ticks: usize, done: impl Fn(&Sim) -> bool) -> bool {
        for _ in 0..ticks {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    fn height(&self, i: usize) -> u64 {
        self.node(i).latest_block_height
    }

    fn epoch(&self, i: usize) -> u64 {
        self.node(i).v4_epoch().unwrap()
    }

    /// One SYNC_REQ from `i` to `j`, the import, then `i`'s adoption.
    fn sync_from(&mut self, i: usize, j: usize) -> u64 {
        let from = self.height(i);
        let resp = self.nodes[j]
            .sync
            .as_ref()
            .unwrap()
            .handle_sync_request(SyncRequest {
                from_height: from,
                sender_id: "sim".into(),
                sender_port: 1,
            });
        let got = self.nodes[i]
            .sync
            .as_ref()
            .unwrap()
            .process_blocks_with_qcs(resp.blocks, &resp.qcs, from);
        self.node_mut(i).reload_chain_tip();
        got
    }

    /// Sync `i` from `j` until it holds `j`'s tip (bounded).
    fn catch_up(&mut self, i: usize, j: usize) {
        for _ in 0..200 {
            if self.height(i) >= self.height(j) {
                return;
            }
            let before = self.height(i);
            self.sync_from(i, j);
            if self.height(i) == before {
                return;
            }
        }
    }

    fn block(&self, i: usize, h: u64) -> Option<String> {
        self.node(i)
            .storage
            .get(&format!("block_{h}"))
            .unwrap()
            .and_then(|j| serde_json::from_str::<Block>(&j).ok())
            .map(|b| b.header.hash)
    }

    /// The nodes in `who` hold identical blocks up to the lowest of their
    /// tips, which is at least `min`. Returns that height.
    fn assert_same_blocks(&self, who: &[usize], min: u64) -> u64 {
        let common = who.iter().map(|&i| self.height(i)).min().unwrap();
        let heights: Vec<u64> = who.iter().map(|&i| self.height(i)).collect();
        assert!(common >= min, "heights {heights:?}, wanted at least {min}");
        for h in 1..=common {
            let first = self.block(who[0], h);
            assert!(first.is_some(), "no block {h}");
            for &i in &who[1..] {
                assert_eq!(self.block(i, h), first, "node {i} differs at height {h}");
            }
            // At most one QC per height, and it certifies that block (the
            // block hash binds the state and receipts roots).
            for i in 0..self.nodes.len() {
                if let Some(q) = self.qc(i, h) {
                    assert_eq!(Some(q.block_hash), first, "node {i}'s QC at {h}");
                }
            }
        }
        common
    }

    fn qc(&self, i: usize, h: u64) -> Option<consensus::qc::QuorumCertificate> {
        consensus::qc_producer::stored_qc(&self.node(i).storage, h)
    }
}

impl Drop for Sim {
    fn drop(&mut self) {
        for n in &mut self.nodes {
            n.c = None;
            n.sync = None;
            let _ = fs::remove_dir_all(&n.path);
        }
    }
}

/// S8's outage witness. Y is offline far past the pull window (GC_DEPTH +
/// RETAIN_SLACK rounds), so it can only come back by IM-1 block sync with
/// per-height QCs. Then W crashes for good: X, Z and Y must form new QCs
/// together, which needs Y's vote (3 of 4 equal stakes).
#[test]
fn a_node_offline_past_the_window_syncs_back_and_its_votes_form_new_qcs() {
    let (x, z, w, y) = (0, 1, 2, 3);
    let mut sim = Sim::new("outage", &[21, 22, 23, 24], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    let far = consensus::ordering::GC_DEPTH + consensus::staging::RETAIN_SLACK;
    let start_round = sim.node(y).latest_block_round;
    assert!(sim.run_until(600, |s| s.node(x).latest_block_round
        > start_round + far + 20));
    let gap = sim.height(x) - sim.height(y);
    assert!(gap > 20, "vacuous: Y is only {gap} blocks behind");
    sim.online[y] = true;
    sim.catch_up(y, x);
    assert_eq!(sim.height(y), sim.height(x), "Y did not sync back");
    for h in 1..=sim.height(y) {
        assert!(
            sim.qc(y, h).is_some() || h > sim.height(x),
            "Y imported block {h} without its QC"
        );
    }
    // W crashes for good. Progress now needs Y's votes.
    sim.online[w] = false;
    let tip = sim.height(x);
    assert!(sim.run_until(300, |s| s.height(x) >= tip + 6 && s.height(y) >= tip + 6));
    let common = sim.assert_same_blocks(&[x, z, y], tip + 6);
    for h in tip + 1..=common {
        let q = sim
            .qc(y, h)
            .or_else(|| sim.qc(x, h))
            .unwrap_or_else(|| panic!("no QC for block {h} without W"));
        let ordered = consensus::qc::canonical_order(&sim.committee);
        let k = ordered
            .iter()
            .position(|m| m.address == sim.node(y).node_id)
            .unwrap();
        assert!(
            q.signer_bitmap[k / 8] & (1 << (k % 8)) != 0,
            "block {h}'s QC was formed without Y"
        );
    }
}

/// Adoption across a boundary (I = 4): Y is offline while the others pass
/// two epoch boundaries; it syncs back through them (each H_E's import writes
/// E+1's record; adoption closes and activates between heights), ends in the
/// others' epoch, and its votes then form QCs with X and Z.
#[test]
fn a_node_syncs_back_across_epoch_boundaries_and_votes_in_the_new_epoch() {
    let (x, z, w, y) = (0, 1, 2, 3);
    let mut sim = Sim::new("across", &[31, 32, 33, 34], 4);
    assert!(sim.run_until(60, |s| s.height(y) >= 2));
    sim.online[y] = false;
    assert!(sim.run_until(400, |s| s.epoch(x) >= 2 && s.height(x) >= 10));
    assert_eq!(sim.epoch(y), 0, "vacuous: Y kept up");
    sim.online[y] = true;
    sim.catch_up(y, x);
    assert_eq!(sim.height(y), sim.height(x));
    assert_eq!(
        sim.epoch(y),
        sim.epoch(x),
        "Y did not activate the epochs it synced through"
    );
    sim.online[w] = false;
    let tip = sim.height(x);
    assert!(sim.run_until(300, |s| s.height(x) >= tip + 5 && s.height(y) >= tip + 5));
    sim.assert_same_blocks(&[x, z, y], tip + 5);
}

/// A 2|2 partition has no quorum anywhere: no block is placed on either side.
/// Healed, the nodes place blocks again and agree.
#[test]
fn a_two_two_partition_places_nothing_and_heals() {
    let mut sim = Sim::new("partition", &[41, 42, 43, 44], 1000);
    assert!(sim.run_until(60, |s| (0..4).all(|i| s.height(i) >= 3)));
    sim.groups = vec![0, 0, 1, 1];
    let before: Vec<u64> = (0..4).map(|i| sim.height(i)).collect();
    sim.run(40);
    // At most the blocks already decided in flight are placed.
    for (i, was) in before.iter().enumerate() {
        assert!(
            sim.height(i) <= was + 1,
            "node {i} progressed without a quorum"
        );
    }
    sim.groups = vec![0; 4];
    let tip = (0..4).map(|i| sim.height(i)).max().unwrap();
    assert!(sim.run_until(300, |s| (0..4).all(|i| s.height(i) >= tip + 5)));
    sim.assert_same_blocks(&[0, 1, 2, 3], tip + 5);
}

/// Crashes during the run: every few ticks one node restarts on its
/// database (a different one each time). The nodes keep agreeing.
#[test]
fn restarts_during_the_run_keep_every_node_agreeing() {
    let mut sim = Sim::new("crashes", &[45, 46, 47, 48], 4);
    for k in 0..12 {
        sim.run(5);
        sim.reopen(k % 4);
    }
    assert!(sim.run_until(300, |s| (0..4).all(|i| s.height(i) >= 14)));
    sim.assert_same_blocks(&[0, 1, 2, 3], 14);
}

/// IM-3 on adoption: Y holds a decision row for an anchor round that the
/// QC'd chain decided differently. Syncing that block halts Y with an alarm;
/// the blocks before it are adopted.
#[test]
fn a_synced_block_that_conflicts_with_a_local_decision_halts_the_node() {
    let (x, y) = (0, 3);
    let mut sim = Sim::new("conflict", &[25, 26, 27, 28], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 2));
    sim.online[y] = false;
    let base = sim.height(y);
    assert!(sim.run_until(200, |s| s.height(x) >= base + 4));
    let target = base + 2;
    let round = serde_json::from_str::<Block>(
        &sim.node(x)
            .storage
            .get(&format!("block_{target}"))
            .unwrap()
            .unwrap(),
    )
    .unwrap()
    .header
    .round;
    sim.node(y)
        .storage
        .put(&consensus::ordering::anchor_decision_key(0, round), "S")
        .unwrap();
    sim.online[y] = true;
    sim.catch_up(y, x);
    assert!(sim.node(y).ordering_halted().is_some(), "Y did not halt");
    assert!(
        sim.node(y).last_adopted_height < target,
        "the conflicting block was adopted"
    );
    let alarm = sim
        .node(y)
        .storage
        .db
        .prefix_iterator(b"alarm:decision_conflict:")
        .next()
        .and_then(|r| r.ok())
        .is_some_and(|(k, _)| k.starts_with(b"alarm:decision_conflict:"));
    assert!(alarm, "no alarm row");
}

/// Loss (10%), delay of up to 3 ticks (15%) and reordering of every batch,
/// with epoch boundaries (I = 5): every node keeps an identical prefix and the
/// chain keeps growing.
#[test]
fn loss_delay_and_reordering_keep_one_prefix() {
    use rand::SeedableRng;
    let mut sim = Sim::new("chaos", &[101, 102, 103, 104], 5);
    sim.chaos = Some(Chaos {
        rng: rand::rngs::StdRng::seed_from_u64(0x5107),
        drop_pct: 10,
        delay_pct: 15,
        max_delay: 3,
    });
    assert!(
        sim.run_until(600, |s| (0..4).all(|i| s.height(i) >= 16)),
        "heights {:?}",
        (0..4).map(|i| sim.height(i)).collect::<Vec<_>>()
    );
    sim.assert_same_blocks(&[0, 1, 2, 3], 16);
    assert!((0..4).all(|i| sim.epoch(i) >= 2));
}

/// A 1|3 partition: the three keep deciding (3 of 4 equal stakes is a
/// quorum), the isolated one decides nothing, and after healing it catches
/// up (pull within the window, else sync) and agrees.
#[test]
fn a_one_three_partition_leaves_the_three_deciding() {
    let mut sim = Sim::new("partition13", &[111, 112, 113, 114], 1000);
    assert!(sim.run_until(60, |s| (0..4).all(|i| s.height(i) >= 3)));
    sim.groups = vec![1, 0, 0, 0];
    let alone = sim.height(0);
    let three = sim.height(1);
    sim.run(30);
    assert!(sim.height(0) <= alone + 1, "the isolated node decided alone");
    assert!(sim.height(1) >= three + 4, "the three stopped");
    sim.groups = vec![0; 4];
    let tip = sim.height(1);
    assert!(sim.run_until(300, |s| s.height(0) >= tip + 2));
    sim.assert_same_blocks(&[0, 1, 2, 3], tip + 2);
}

/// The contract's stake profiles: unequal stake decides and agrees.
#[test]
fn every_stake_profile_decides_and_agrees() {
    for (k, stakes) in [
        [4000, 3000, 2000, 1000],
        [3300, 2300, 2200, 2200],
        [2000, 1000, 1000, 1000],
    ]
    .iter()
    .enumerate()
    {
        let seeds = [120 + 4 * k as u8, 121 + 4 * k as u8, 122 + 4 * k as u8, 123 + 4 * k as u8];
        let mut sim = Sim::with_stakes(&format!("stakes{k}"), &seeds, stakes, 6);
        assert!(
            sim.run_until(300, |s| (0..4).all(|i| s.height(i) >= 14)),
            "profile {stakes:?}: heights {:?}",
            (0..4).map(|i| sim.height(i)).collect::<Vec<_>>()
        );
        sim.assert_same_blocks(&[0, 1, 2, 3], 14);
    }
}

/// A slow node (it ticks one step in four) neither stalls nor forks the
/// others, and keeps the same prefix.
#[test]
fn a_slow_node_neither_stalls_nor_forks_the_others() {
    let mut sim = Sim::new("slow", &[141, 142, 143, 144], 5);
    sim.slow = Some((2, 4));
    assert!(sim.run_until(400, |s| (0..4).all(|i| s.height(i) >= 12)));
    sim.assert_same_blocks(&[0, 1, 2, 3], 12);
}
