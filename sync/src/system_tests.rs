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
            let mut certified = false;
            for i in 0..self.nodes.len() {
                if let Some(q) = self.qc(i, h) {
                    assert_eq!(Some(q.block_hash), first, "node {i}'s QC at {h}");
                    certified = true;
                }
            }
            // ...and some node holds it (the newest heights may still be
            // collecting votes).
            assert!(certified || h + 2 > common, "no node holds a QC for height {h}");
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

// ---------------------------------------------------------------------------
// G1 final review (safety): the crash between import and adoption (CRITICAL),
// kept as regressions.

impl Sim {
    /// ChainSync's half of IM-2 only: import `j`'s blocks above `i`'s tip
    /// with their QCs, WITHOUT `i`'s adoption (`reload_chain_tip`).
    fn import_only(&mut self, i: usize, j: usize) -> u64 {
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
        self.nodes[i]
            .sync
            .as_ref()
            .unwrap()
            .process_blocks_with_qcs(resp.blocks, &resp.qcs, from)
    }

    fn ordering_state(&self, i: usize) -> (u64, u64, u64, usize) {
        let e = self.node(i).ordering_engine.lock().unwrap();
        (
            e.finalized_round,
            e.next_anchor_round,
            e.gc_floor(),
            e.committed_digests().len(),
        )
    }
}

fn rs_import_then_restart(tag: &str, seeds: &[u8], adopt_before_crash: bool) {
    let (x, y) = (0, 3);
    let mut sim = Sim::new(tag, seeds, 1000);
    assert!(sim.run_until(60, |s| (0..4).all(|i| s.height(i) >= 3)));
    sim.online[y] = false;
    let base = sim.height(y);
    assert!(sim.run_until(200, |s| s.height(x) >= base + 4));
    sim.online[y] = true;
    let got = sim.import_only(y, x);
    assert!(got >= base + 4, "vacuous: nothing imported ({got})");
    if adopt_before_crash {
        sim.node_mut(y).reload_chain_tip();
    }
    // A crash between ChainSync's import transaction and adoption.
    sim.reopen(y);
    let yo = sim.ordering_state(y);
    let xo = sim.ordering_state(x);
    eprintln!("after restart: Y (finalized, cursor, g, |committed|) = {yo:?}; X = {xo:?}");
    let tip = (0..4).map(|i| sim.height(i)).max().unwrap();
    let reached = sim.run_until(300, |s| (0..4).all(|i| s.height(i) >= tip + 4));
    let heights: Vec<u64> = (0..4).map(|i| sim.height(i)).collect();
    eprintln!("reached={reached} heights={heights:?} tip={tip} halted(Y)={:?}", sim.node(y).ordering_halted());
    for h in 1..=heights.iter().copied().min().unwrap() {
        let bx = sim.block(x, h);
        let by = sim.block(y, h);
        if bx != by {
            let seq = |i: usize| {
                sim.node(i)
                    .storage
                    .get(&format!("block_{h}"))
                    .unwrap()
                    .and_then(|j| serde_json::from_str::<Block>(&j).ok())
                    .map(|b| (b.header.round, b.committed_vertices.len()))
            };
            eprintln!("FORK at height {h}: X (round, |seq|) = {:?}, Y = {:?}", seq(x), seq(y));
            break;
        }
    }
    if !adopt_before_crash {
        // IM-3 / DE-6: does anything notice? Y asks X for X's chain from the
        // fork point, as ChainSync would.
        let fork_from = base;
        let resp = sim.nodes[x].sync.as_ref().unwrap().handle_sync_request(SyncRequest {
            from_height: fork_from,
            sender_id: "sim".into(),
            sender_port: 1,
        });
        let yh = sim.height(y);
        let got = sim.nodes[y].sync.as_ref().unwrap().process_blocks_with_qcs(resp.blocks, &resp.qcs, yh);
        sim.node_mut(y).reload_chain_tip();
        let alarm = sim.node(y).storage.db.prefix_iterator(b"alarm:").next()
            .and_then(|r| r.ok()).map(|(k, _)| String::from_utf8_lossy(&k).to_string())
            .filter(|k| k.starts_with("alarm:"));
        let own_qcs: Vec<u64> = (base + 1..=yh).filter(|h| sim.qc(y, *h)
            .is_some_and(|q| Some(q.block_hash) == sim.block(y, *h))).collect();
        let foreign_qcs: Vec<u64> = (base + 1..=yh).filter(|h| sim.qc(y, *h)
            .is_some_and(|q| Some(q.block_hash) != sim.block(y, *h))).collect();
        eprintln!("after re-sync: got={got} Y halted={:?} alarm={alarm:?} Y-heights-with-QC-binding-Y's-own-block={own_qcs:?} Y-heights-whose-stored-QC-certifies-ANOTHER-block={foreign_qcs:?}",
            sim.node(y).ordering_halted());
    }
    sim.assert_same_blocks(&[0, 1, 2, 3], tip + 4);
}

/// Control: adoption runs before the crash. Must pass.
#[test]
fn rs_import_adopt_then_restart_agrees() {
    rs_import_then_restart("rs-ctrl", &[161, 162, 163, 164], true);
}

/// PoC: a crash between ChainSync's import (which writes the ordering
/// engine's `consensus:finalized_round` / `consensus:finality_digest`) and
/// adoption. At boot the ordering cursor jumps past the imported blocks, the
/// adoption loop skips them as `already_decided`, and `committed_set` / g
/// never receive their sequences.
#[test]
fn rs_import_then_crash_before_adoption_keeps_agreement() {
    rs_import_then_restart("rs-poc", &[165, 166, 167, 168], false);
}


/// The same crash window across an epoch boundary (I = 4): Y imports H_0 and
/// epoch-1 blocks, crashes before adoption, then activates epoch 1 at boot.
#[test]
fn rs_import_across_a_boundary_then_crash_keeps_agreement() {
    let (x, y) = (0, 3);
    let mut sim = Sim::new("rs-epoch", &[181, 182, 183, 184], 4);
    assert!(sim.run_until(60, |s| (0..4).all(|i| s.height(i) >= 2)));
    sim.online[y] = false;
    assert!(sim.run_until(300, |s| s.epoch(x) >= 1 && s.height(x) >= 6));
    assert_eq!(sim.epoch(y), 0);
    sim.online[y] = true;
    let got = sim.import_only(y, x);
    eprintln!("Y imported to {got}; X at {} epoch {}", sim.height(x), sim.epoch(x));
    sim.reopen(y);
    let tip = (0..4).map(|i| sim.height(i)).max().unwrap();
    let _ = sim.run_until(300, |s| (0..4).all(|i| s.height(i) >= tip + 4));
    let heights: Vec<u64> = (0..4).map(|i| sim.height(i)).collect();
    eprintln!("heights {heights:?} epochs {:?} halted(Y)={:?}",
        (0..4).map(|i| sim.epoch(i)).collect::<Vec<_>>(), sim.node(y).ordering_halted());
    for h in 1..=heights.iter().copied().min().unwrap() {
        if sim.block(x, h) != sim.block(y, h) {
            eprintln!("FORK at height {h}");
            break;
        }
    }
    sim.assert_same_blocks(&[0, 1, 2, 3], tip + 4);
}

/// IM-3 at runtime: an alarm row another component wrote (sync's conflict
/// check) halts a running node at its next tick; it places nothing more.
#[test]
fn an_alarm_written_by_sync_halts_the_running_node() {
    let y = 3;
    let mut sim = Sim::new("alarm-runtime", &[191, 192, 193, 194], 1000);
    assert!(sim.run_until(60, |s| (0..4).all(|i| s.height(i) >= 3)));
    consensus::qc_producer::record_decision_conflict(
        &sim.node(y).storage,
        2,
        &format!("{}: test", consensus::ordering::DECISION_CONFLICT),
    );
    sim.step();
    assert!(sim.node(y).ordering_halted().is_some(), "the alarm did not halt the node");
    let at = sim.height(y);
    sim.run(20);
    assert_eq!(sim.height(y), at, "a halted node placed blocks");
    assert!(sim.height(0) > at, "vacuous: the others stopped too");
}

// G1 final review (node): regressions.

/// PoC-3: IM-2's deviation says a crash between a synced block's execution
/// and its QC import "only delays adoption". For a non-boundary height the QC
/// is never obtained again (sync asks above the tip; QC_WANT answers only
/// boundary heights; peers stop re-sending votes once they hold the QC), so
/// adoption waits forever and the node never votes again. With one other node
/// down, the chain stops.
#[test]
fn a_block_held_without_its_qc_is_adopted_after_fetching_it() {
    let (x, z, w, y) = (0, 1, 2, 3);
    let mut sim = Sim::new("poc_qcloss", &[171, 172, 173, 174], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(200, |s| s.height(x) >= s.height(y) + 6));
    sim.online[y] = true;
    let from = sim.height(y);
    let resp = sim.nodes[x]
        .sync
        .as_ref()
        .unwrap()
        .handle_sync_request(SyncRequest {
            from_height: from,
            sender_id: "sim".into(),
            sender_port: 1,
        });
    // Import up to h - 1 normally.
    let h = from + 2;
    let first: Vec<Block> = resp.blocks.iter().filter(|b| b.header.height < h).cloned().collect();
    let got = sim.nodes[y].sync.as_ref().unwrap().process_blocks_with_qcs(first, &resp.qcs, from);
    assert_eq!(got, h - 1);
    // Block h: its execution transaction commits, then the process dies before
    // `import_block_qc` (modelled by restoring every row the import writes).
    let keys = {
        let q = resp.qcs.iter().find(|q| q.block_height == h).unwrap();
        vec![
            format!("consensus:qc:{h}"),
            format!("consensus:qc_by_round:{}", q.anchor_round),
            "consensus:qc:latest".to_string(),
            "consensus:qc:latest_height".to_string(),
            "consensus:qc:latest_round".to_string(),
            "consensus:finalized_round".to_string(),
            "consensus:last_anchor_round".to_string(),
            "consensus:last_anchor_hash".to_string(),
            "consensus:finality_digest".to_string(),
        ]
    };
    let before: Vec<Option<String>> = keys.iter().map(|k| sim.node(y).storage.get(k).unwrap()).collect();
    let only_h: Vec<Block> = resp.blocks.iter().filter(|b| b.header.height == h).cloned().collect();
    let got = sim.nodes[y].sync.as_ref().unwrap().process_blocks_with_qcs(only_h, &resp.qcs, h - 1);
    assert_eq!(got, h);
    for (k, v) in keys.iter().zip(before) {
        match v {
            Some(v) => sim.node(y).storage.put(k, &v).unwrap(),
            None => sim.node(y).storage.delete(k).unwrap(),
        }
    }
    assert!(sim.qc(y, h).is_none());
    sim.reopen(y);
    // The node comes back and syncs the rest as usual.
    for _ in 0..3 {
        sim.catch_up(y, x);
        sim.run(5);
    }
    eprintln!(
        "POC3: Y height {} adopted {} (crash at {h}); X height {}",
        sim.height(y),
        sim.node(y).last_adopted_height,
        sim.height(x)
    );
    let stuck = sim.node(y).last_adopted_height < h;
    // W crashes for good: X, Z, Y must keep deciding (3 of 4 equal stakes).
    sim.online[w] = false;
    let tip = sim.height(x);
    let live = sim.run_until(300, |s| s.qc(x, tip + 3).is_some());
    eprintln!(
        "POC3: after W left: X height {} (tip was {tip}), latest QC at X {:?}, Y adopted {}",
        sim.height(x),
        (1..=sim.height(x)).rev().find(|k| sim.qc(x, *k).is_some()),
        sim.node(y).last_adopted_height
    );
    assert!(!stuck, "adoption is stuck below {h}");
    assert!(live, "no QC after W left: Y never votes again");
    let _ = z;
}

/// A member of the frozen C_E that leaves the live set mid-epoch (what the
/// executor's leave/slash path does to `sys:validator_set:v1`) still leads
/// anchors on V4 (DE-7), so it is the `proposer_id` of blocks every live node
/// places. Sync used to gate on the LIVE set, so no node could sync
/// those blocks from anyone: a node behind them never catches up.
#[test]
fn a_block_led_by_a_member_that_left_mid_epoch_still_syncs() {
    let (x, w, y) = (0, 2, 3);
    let mut sim = Sim::new("poc_left", &[161, 162, 163, 164], 1000);
    assert!(sim.run_until(60, |s| (0..4).all(|i| s.height(i) >= 2)));
    let w_addr = sim.node(w).node_id.clone();
    for i in 0..4 {
        let db = &sim.node(i).storage;
        let _seed = db.seeding();
        let raw = db.get("sys:validator_set:v1").unwrap().unwrap();
        let mut set: Vec<ValidatorInfo> = serde_json::from_str(&raw).unwrap();
        set.retain(|m| m.address != w_addr);
        db.put("sys:validator_set:v1", &serde_json::to_string(&set).unwrap())
            .unwrap();
    }
    sim.online[y] = false;
    let base = sim.height(y);
    let led_by_w = |s: &Sim| {
        (base + 1..=s.height(x)).find(|h| proposer_at(s, x, *h).as_deref() == Some(w_addr.as_str()))
    };
    assert!(sim.run_until(300, |s| led_by_w(s).is_some_and(|h| s.height(x) > h + 1)));
    let hw = led_by_w(&sim).unwrap();
    eprintln!("POC2: block {hw} is led by W, who left the live set; X is at {}", sim.height(x));
    sim.online[y] = true;
    for _ in 0..5 {
        sim.catch_up(y, x);
    }
    assert!(
        sim.height(y) >= hw,
        "Y is stuck at {} below block {hw} (led by W)",
        sim.height(y)
    );
}

fn proposer_at(sim: &Sim, i: usize, h: u64) -> Option<String> {
    sim.node(i)
        .storage
        .get(&format!("block_{h}"))
        .unwrap()
        .and_then(|j| serde_json::from_str::<Block>(&j).ok())
        .map(|b| b.header.proposer_id)
}

// ---------------------------------------- final review (test quality): kill tests

/// PoC (review, IM-2 deviation): "a crash between [import and adoption] only
/// delays adoption". Y syncs a batch (execution + per-height QC import, which
/// writes consensus:finalized_round / finality_digest), then crashes before
/// its consensus adopts the batch. After the restart the ordering engine
/// starts past the imported anchors (finalized_round came from the import),
/// so adoption of those heights is skipped: their sequences never enter
/// `cseq` / the committed set and g stays at the pre-outage value.
#[test]
fn poc_restart_between_import_and_adoption() {
    let (x, z, w, y) = (0, 1, 2, 3);
    let mut sim = Sim::new("imp-adopt", &[51, 52, 53, 54], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(300, |s| s.height(x) >= s.height(y) + 8));
    sim.online[y] = true;
    let from = sim.height(y);
    let resp = sim.nodes[x]
        .sync
        .as_ref()
        .unwrap()
        .handle_sync_request(SyncRequest {
            from_height: from,
            sender_id: "sim".into(),
            sender_port: 1,
        });
    let got = sim.nodes[y]
        .sync
        .as_ref()
        .unwrap()
        .process_blocks_with_qcs(resp.blocks, &resp.qcs, from);
    assert!(got >= from + 8, "vacuous: imported only up to {got} from {from}");
    // Crash before the consensus task's reload_chain_tip adopts the batch.
    sim.reopen(y);
    sim.node_mut(y).reload_chain_tip();
    let ord = |s: &Sim, i: usize| {
        let e = s.node(i).ordering_engine.lock().unwrap();
        let d = s.node(i).storage.get("consensus:finality_digest").unwrap().unwrap_or_default();
        (e.next_anchor_round, e.gc_floor(), e.committed_digests().len(), d[..8.min(d.len())].to_string())
    };
    eprintln!(
        "POC after restart: heights x={} y={} last_adopted y={}; ordering x={:?} y={:?}",
        sim.height(x), sim.height(y), sim.node(y).last_adopted_height, ord(&sim, x), ord(&sim, y)
    );
    let cseq_rows = |s: &Sim, i: usize| {
        s.node(i).storage.db.prefix_iterator(b"consensus:cseq:")
            .filter_map(|r| r.ok())
            .take_while(|(k, _)| k.starts_with(b"consensus:cseq:"))
            .count()
    };
    eprintln!("POC cseq rows x={} y={}", cseq_rows(&sim, x), cseq_rows(&sim, y));
    let tip = sim.height(x);
    let ok = sim.run_until(300, |s| s.height(x) >= tip + 6 && s.height(y) >= tip + 6);
    eprintln!(
        "POC after run: ok={ok} heights {:?}; ordering x={:?} y={:?}",
        (0..4).map(|i| sim.height(i)).collect::<Vec<_>>(), ord(&sim, x), ord(&sim, y)
    );
    let _ = (z, w);
    sim.assert_same_blocks(&[x, z, w, y], tip + 6);
}

/// PoC (review, IM-2/IM-4): a crash after a synced block's execution
/// transaction and before its QC-import transaction. The block is held
/// without `consensus:qc:{h}`; nothing ever fetches that QC again (sync asks
/// above the tip, GET_FINALITY serves the latest, QC_WANT only boundaries),
/// so adoption waits at h forever.
#[test]
fn poc_crash_between_block_execution_and_qc_import_stalls_adoption() {
    let (x, z, w, y) = (0, 1, 2, 3);
    let mut sim = Sim::new("exec-qc", &[61, 62, 63, 64], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(300, |s| s.height(x) >= s.height(y) + 8));
    sim.online[y] = true;
    let from = sim.height(y);
    let resp = sim.nodes[x].sync.as_ref().unwrap().handle_sync_request(SyncRequest {
        from_height: from,
        sender_id: "sim".into(),
        sender_port: 1,
    });
    let first = resp.blocks.iter().find(|b| b.header.height == from + 1).unwrap().clone();
    // The state the QC-import transaction would have found: snapshot it,
    // import block from+1 (execution txn + QC txn), then undo the QC txn.
    let keys = [
        "consensus:finalized_round",
        "consensus:last_anchor_round",
        "consensus:last_anchor_hash",
        "consensus:finality_digest",
        "consensus:qc:latest",
        "consensus:qc:latest_height",
        "consensus:qc:latest_round",
    ];
    let db = sim.node(y).storage.clone();
    let before: Vec<Option<String>> = keys.iter().map(|k| db.get(k).unwrap()).collect();
    let got = sim.nodes[y].sync.as_ref().unwrap()
        .process_blocks_with_qcs(vec![first.clone()], &resp.qcs, from);
    assert_eq!(got, from + 1, "vacuous: the block was not imported");
    for (k, v) in keys.iter().zip(&before) {
        match v {
            Some(v) => db.put(k, v).unwrap(),
            None => db.delete(k).unwrap(),
        }
    }
    db.delete(&format!("consensus:qc:{}", from + 1)).unwrap();
    db.delete(&format!("consensus:qc_by_round:{}", first.header.round)).unwrap();
    drop(db);
    sim.reopen(y);
    sim.node_mut(y).reload_chain_tip();
    sim.catch_up(y, x);
    eprintln!(
        "POC2 after catch-up: heights {:?}, y last_adopted {} (stuck at {}?)",
        (0..4).map(|i| sim.height(i)).collect::<Vec<_>>(),
        sim.node(y).last_adopted_height,
        from
    );
    sim.online[w] = false;
    let tip = sim.height(x);
    let ok = sim.run_until(200, |s| s.height(x) >= tip + 4 && s.height(y) >= tip + 4);
    eprintln!(
        "POC2 after run: ok={ok} heights {:?}, y last_adopted {}",
        (0..4).map(|i| sim.height(i)).collect::<Vec<_>>(),
        sim.node(y).last_adopted_height
    );
    let _ = z;
    assert!(sim.node(y).last_adopted_height > from, "Y never adopted past height {from}");
    assert!(ok, "the chain stalled once W left (Y cannot vote)");
}

/// KILL(M36), IM-1's last clause at adoption: Y's own fold of the committed
/// sequences differs from the QC-bound finality digest (here its persisted
/// digest was corrupted while it was offline). Adopting the next synced
/// block is a decision conflict: Y halts with the alarm instead of adopting.
#[test]
fn kill_m36_a_finality_digest_mismatch_at_adoption_halts() {
    let (x, y) = (0, 3);
    let mut sim = Sim::new("kill-m36", &[71, 72, 73, 74], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(300, |s| s.height(x) >= s.height(y) + 4));
    sim.node(y)
        .storage
        .put("consensus:finality_digest", &"ab".repeat(32))
        .unwrap();
    sim.reopen(y);
    sim.online[y] = true;
    let before = sim.node(y).last_adopted_height;
    sim.catch_up(y, x);
    assert!(sim.height(y) > before, "vacuous: nothing was synced");
    assert!(
        sim.node(y).ordering_halted().is_some(),
        "Y adopted blocks whose QC binds another finality digest"
    );
    assert_eq!(sim.node(y).last_adopted_height, before);
}

/// KILL(M37), IM-1 at adoption: a V4 block held without its QC (here: the
/// QC-import transaction after its execution never committed) is not adopted.
#[test]
fn kill_m37_a_held_block_without_its_qc_is_not_adopted() {
    let (x, y) = (0, 3);
    let mut sim = Sim::new("kill-m37", &[81, 82, 83, 84], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(300, |s| s.height(x) >= s.height(y) + 4));
    sim.online[y] = true;
    let from = sim.height(y);
    let resp = sim.nodes[x].sync.as_ref().unwrap().handle_sync_request(SyncRequest {
        from_height: from,
        sender_id: "sim".into(),
        sender_port: 1,
    });
    let first = resp.blocks.iter().find(|b| b.header.height == from + 1).unwrap().clone();
    let keys = [
        "consensus:finalized_round",
        "consensus:last_anchor_round",
        "consensus:last_anchor_hash",
        "consensus:finality_digest",
        "consensus:qc:latest",
        "consensus:qc:latest_height",
        "consensus:qc:latest_round",
    ];
    let db = sim.node(y).storage.clone();
    let before: Vec<Option<String>> = keys.iter().map(|k| db.get(k).unwrap()).collect();
    assert_eq!(
        sim.nodes[y].sync.as_ref().unwrap().process_blocks_with_qcs(vec![first.clone()], &resp.qcs, from),
        from + 1
    );
    for (k, v) in keys.iter().zip(&before) {
        match v {
            Some(v) => db.put(k, v).unwrap(),
            None => db.delete(k).unwrap(),
        }
    }
    db.delete(&format!("consensus:qc:{}", from + 1)).unwrap();
    db.delete(&format!("consensus:qc_by_round:{}", first.header.round)).unwrap();
    drop(db);
    sim.reopen(y);
    sim.node_mut(y).reload_chain_tip();
    assert_eq!(
        sim.node(y).last_adopted_height,
        from,
        "a block without a stored QC was adopted"
    );
}
