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
            let path = storage::test_dir::process_dir()
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
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::new(executor::Executor::new(Arc::clone(&db))),
            Arc::clone(&db),
            None,
            key,
        );
        c.set_now_secs(Arc::new(|| PINNED));
        c.placement_sleep = Arc::new(|_| {});
        c.v4_outbox = Some(Arc::new(Mutex::new(Vec::new())));
        let sync = ChainSync::new(db);
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
            .handle_sync_request(SyncRequest { from_height: from });
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
            .handle_sync_request(SyncRequest { from_height: from });
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
        let resp = sim.nodes[x]
            .sync
            .as_ref()
            .unwrap()
            .handle_sync_request(SyncRequest {
                from_height: fork_from,
            });
        let yh = sim.height(y);
        let got =
            sim.nodes[y]
                .sync
                .as_ref()
                .unwrap()
                .process_blocks_with_qcs(resp.blocks, &resp.qcs, yh);
        sim.node_mut(y).reload_chain_tip();
        let alarm = sim
            .node(y)
            .storage
            .db
            .prefix_iterator(b"alarm:")
            .next()
            .and_then(|r| r.ok())
            .map(|(k, _)| String::from_utf8_lossy(&k).to_string())
            .filter(|k| k.starts_with("alarm:"));
        let own_qcs: Vec<u64> = (base + 1..=yh)
            .filter(|h| {
                sim.qc(y, *h)
                    .is_some_and(|q| Some(q.block_hash) == sim.block(y, *h))
            })
            .collect();
        let foreign_qcs: Vec<u64> = (base + 1..=yh)
            .filter(|h| {
                sim.qc(y, *h)
                    .is_some_and(|q| Some(q.block_hash) != sim.block(y, *h))
            })
            .collect();
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
        .handle_sync_request(SyncRequest { from_height: from });
    // Import up to h - 1 normally.
    let h = from + 2;
    let first: Vec<Block> = resp
        .blocks
        .iter()
        .filter(|b| b.header.height < h)
        .cloned()
        .collect();
    let got = sim.nodes[y]
        .sync
        .as_ref()
        .unwrap()
        .process_blocks_with_qcs(first, &resp.qcs, from);
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
        .handle_sync_request(SyncRequest { from_height: from });
    let got =
        sim.nodes[y]
            .sync
            .as_ref()
            .unwrap()
            .process_blocks_with_qcs(resp.blocks, &resp.qcs, from);
    assert!(
        got >= from + 8,
        "vacuous: imported only up to {got} from {from}"
    );
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
    let resp = sim.nodes[x]
        .sync
        .as_ref()
        .unwrap()
        .handle_sync_request(SyncRequest { from_height: from });
    let first = resp
        .blocks
        .iter()
        .find(|b| b.header.height == from + 1)
        .unwrap()
        .clone();
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
    let resp = sim.nodes[x]
        .sync
        .as_ref()
        .unwrap()
        .handle_sync_request(SyncRequest { from_height: from });
    let first = resp
        .blocks
        .iter()
        .find(|b| b.header.height == from + 1)
        .unwrap()
        .clone();
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

/// B80 witness: a server that lacks one block's QC stops this node's batch
/// at the block before it; the pass goes on to the next session (B33: up to
/// `SYNC_PEERS_PER_PASS`), which has the QC, and the node reaches the
/// certified tip in that one pass.
#[test]
fn a_server_without_a_blocks_qc_does_not_stall_the_pass() {
    let (x, y) = (0, 3);
    let mut sim = Sim::new("b80_qcless_server", &[181, 182, 183, 184], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(200, |s| s.height(x) >= s.height(y) + 6));
    let from = sim.height(y);
    let full = sim.nodes[x]
        .sync
        .as_ref()
        .unwrap()
        .handle_sync_request(SyncRequest { from_height: from });
    // The certified tip of the answer: blocks in a row that carry their QC.
    let mut tip = from;
    while full.blocks.iter().any(|b| b.header.height == tip + 1)
        && full.qcs.iter().any(|q| q.block_height == tip + 1)
    {
        tip += 1;
    }
    let gap = from + 2;
    assert!(
        tip > gap,
        "vacuous: the answer is not certified past the gap"
    );
    let (blocks, qcs) = (full.blocks.clone(), full.qcs.clone());
    let (asks, mut queued) = tokio::sync::mpsc::channel::<network::SyncAsk>(64);
    let (dials, _) = tokio::sync::mpsc::channel(1);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.spawn(async move {
        while let Some(ask) = queued.recv().await {
            let answer = if ask.wire == "GET_HEIGHT" {
                Ok(format!("HEIGHT:{tip}"))
            } else if let Some(req) = ask.wire.strip_prefix("SYNC_REQ:") {
                let req: SyncRequest = serde_json::from_str(req).unwrap();
                // The first session's server never got block `gap`'s QC.
                let lacks = ask.peer == "12D3KooWa";
                let resp = SyncResponse {
                    blocks: blocks
                        .iter()
                        .filter(|b| b.header.height > req.from_height && b.header.height <= tip)
                        .cloned()
                        .collect(),
                    finality: None,
                    prune_horizon: None,
                    qcs: qcs
                        .iter()
                        .filter(|q| !(lacks && q.block_height == gap))
                        .cloned()
                        .collect(),
                    oversized: None,
                };
                Ok(format!(
                    "SYNC_RESP:{}",
                    serde_json::to_string(&resp).unwrap()
                ))
            } else {
                Err("no".to_string())
            };
            let _ = ask.reply.send(answer);
        }
    });
    let member = |peer: &str, member: &str| network::SessionPeer {
        peer: peer.into(),
        member: Some(member.into()),
    };
    let client = network::SessionClient {
        asks,
        dials,
        table: Arc::new(std::sync::RwLock::new(vec![
            member("12D3KooWa", &sim.committee[0].address),
            member("12D3KooWb", &sim.committee[1].address),
        ])),
    };
    let sync = ChainSync::new(Arc::clone(&sim.node(y).storage)).with_sessions(client);
    let reached = rt.block_on(sync.sync_from_peers());
    assert_eq!(
        reached, tip,
        "the pass stopped at the server without block {gap}'s QC"
    );
}

/// B256 witness: a session that serves a block a batch, slowly, holds a
/// pass for one turn (`SYNC_TURN`), not for as long as it brings a block
/// (one just inside the request timeout held every pass, at a block a
/// minute, and no other session was asked): the next session is asked in
/// that pass and brings the node to the certified tip, and the slow one is
/// asked after the others from then on.
#[test]
fn a_slow_server_holds_a_pass_for_one_turn() {
    let (x, y) = (0, 3);
    let mut sim = Sim::new("b256_slow_server", &[191, 192, 193, 194], 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(400, |s| s.height(x) >= s.height(y) + 12));
    let from = sim.height(y);
    let full = sim.nodes[x]
        .sync
        .as_ref()
        .unwrap()
        .handle_sync_request(SyncRequest { from_height: from });
    let mut tip = from;
    while full.blocks.iter().any(|b| b.header.height == tip + 1)
        && full.qcs.iter().any(|q| q.block_height == tip + 1)
    {
        tip += 1;
    }
    assert!(tip >= from + 6, "vacuous: few certified blocks to serve");
    let (blocks, qcs) = (full.blocks.clone(), full.qcs.clone());
    let block_asks = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&block_asks);
    let (asks, mut queued) = tokio::sync::mpsc::channel::<network::SyncAsk>(64);
    let (dials, _) = tokio::sync::mpsc::channel(1);
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.spawn(async move {
        while let Some(ask) = queued.recv().await {
            let slow = ask.peer == "12D3KooWslow";
            let (blocks, qcs) = (blocks.clone(), qcs.clone());
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let answer = if ask.wire == "GET_HEIGHT" {
                    Ok(format!("HEIGHT:{}", if slow { u64::MAX / 2 } else { tip }))
                } else if let Some(req) = ask.wire.strip_prefix("SYNC_REQ:") {
                    log.lock().unwrap().push(ask.peer.clone());
                    let req: SyncRequest = serde_json::from_str(req).unwrap();
                    // The slow one: a single block a batch, after most of a
                    // turn's time.
                    let last = if slow { req.from_height + 1 } else { tip };
                    if slow {
                        tokio::time::sleep(crate::SYNC_TURN / 3).await;
                    }
                    let resp = SyncResponse {
                        blocks: blocks
                            .iter()
                            .filter(|b| {
                                b.header.height > req.from_height && b.header.height <= last
                            })
                            .cloned()
                            .collect(),
                        finality: None,
                        prune_horizon: None,
                        qcs: qcs.clone(),
                        oversized: None,
                    };
                    Ok(format!(
                        "SYNC_RESP:{}",
                        serde_json::to_string(&resp).unwrap()
                    ))
                } else {
                    Err("no".to_string())
                };
                let _ = ask.reply.send(answer);
            });
        }
    });
    let member = |peer: &str, member: &str| network::SessionPeer {
        peer: peer.into(),
        member: Some(member.into()),
    };
    let client = network::SessionClient {
        asks,
        dials,
        table: Arc::new(std::sync::RwLock::new(vec![
            member("12D3KooWslow", &sim.committee[1].address),
            member("12D3KooWfast", &sim.committee[2].address),
        ])),
    };
    let sync = ChainSync::new(Arc::clone(&sim.node(y).storage)).with_sessions(client);
    let reached = rt.block_on(sync.sync_from_peers());
    assert_eq!(reached, tip, "the pass did not reach the certified tip");
    let asked = block_asks.lock().unwrap().clone();
    assert!(
        asked.iter().any(|p| p == "12D3KooWfast"),
        "the slow session held the pass: {asked:?}"
    );
    assert!(
        sync.stalls
            .lock()
            .unwrap()
            .get("12D3KooWslow")
            .map_or(0, |(n, _)| *n)
            > 0,
        "the slow session was not struck"
    );
}

/// B263 witness support: node `y` of a four-node `Sim` left behind the
/// others' certified blocks by at least `gap`, with `x`'s answer to it:
/// (sim, y, its height, the certified tip above it, the blocks, their QCs).
fn left_behind(
    tag: &str,
    seeds: &[u8],
    gap: u64,
) -> (
    Sim,
    usize,
    u64,
    u64,
    Vec<Block>,
    Vec<consensus::qc::QuorumCertificate>,
) {
    let (x, y) = (0, 3);
    let mut sim = Sim::new(tag, seeds, 1000);
    assert!(sim.run_until(60, |s| s.height(y) >= 3));
    sim.online[y] = false;
    assert!(sim.run_until(400, |s| s.height(x) >= s.height(y) + gap + 2));
    let from = sim.height(y);
    let full = sim.nodes[x]
        .sync
        .as_ref()
        .unwrap()
        .handle_sync_request(SyncRequest { from_height: from });
    let mut tip = from;
    while full.blocks.iter().any(|b| b.header.height == tip + 1)
        && full.qcs.iter().any(|q| q.block_height == tip + 1)
    {
        tip += 1;
    }
    assert!(tip >= from + gap, "vacuous: few certified blocks to serve");
    (sim, y, from, tip, full.blocks.clone(), full.qcs.clone())
}

/// B263 witness support: sessions answering as `serve` says, each answer
/// on its own task; the peers asked for blocks, in order, are logged.
fn sessions_serving(
    rt: &tokio::runtime::Runtime,
    table: Vec<network::SessionPeer>,
    serve: impl Fn(&str, &str) -> Option<(std::time::Duration, String)> + Send + Sync + 'static,
) -> (network::SessionClient, Arc<std::sync::Mutex<Vec<String>>>) {
    let block_asks = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&block_asks);
    let serve = Arc::new(serve);
    let (asks, mut queued) = tokio::sync::mpsc::channel::<network::SyncAsk>(64);
    let (dials, _) = tokio::sync::mpsc::channel(1);
    rt.spawn(async move {
        while let Some(ask) = queued.recv().await {
            if ask.wire.starts_with("SYNC_REQ:") {
                log.lock().unwrap().push(ask.peer.clone());
            }
            let serve = Arc::clone(&serve);
            tokio::spawn(async move {
                let answer = match serve(&ask.peer, &ask.wire) {
                    Some((wait, answer)) => {
                        tokio::time::sleep(wait).await;
                        Ok(answer)
                    }
                    None => Err("no".to_string()),
                };
                let _ = ask.reply.send(answer);
            });
        }
    });
    let client = network::SessionClient {
        asks,
        dials,
        table: Arc::new(std::sync::RwLock::new(table)),
    };
    (client, block_asks)
}

/// The `SYNC_RESP` of `blocks` above `from` up to `last`, with `qcs`.
fn sync_answer(
    blocks: &[Block],
    qcs: &[consensus::qc::QuorumCertificate],
    from: u64,
    last: u64,
) -> String {
    let resp = SyncResponse {
        blocks: blocks
            .iter()
            .filter(|b| b.header.height > from && b.header.height <= last)
            .cloned()
            .collect(),
        finality: None,
        prune_horizon: None,
        qcs: qcs.to_vec(),
        oversized: None,
    };
    format!("SYNC_RESP:{}", serde_json::to_string(&resp).unwrap())
}

/// B263 witness: a session that brought one block slowly and then answered
/// empty at once keeps its strike (B256 judged only a turn the clock ended,
/// so ending it early cleared the strike, and the session kept the first
/// turn of every pass).
#[test]
fn a_session_ending_its_turn_early_is_struck() {
    let (sim, y, from, tip, blocks, qcs) = left_behind("b263_early_end", &[201, 202, 203, 204], 6);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = Arc::clone(&served);
    let (client, _) = sessions_serving(
        &rt,
        vec![network::SessionPeer {
            peer: "12D3KooWslow".into(),
            member: Some(sim.committee[1].address.clone()),
        }],
        move |_, wire| {
            if wire == "GET_HEIGHT" {
                return Some((std::time::Duration::ZERO, format!("HEIGHT:{}", tip + 1_000)));
            }
            let req: SyncRequest = serde_json::from_str(wire.strip_prefix("SYNC_REQ:")?).ok()?;
            if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                // One real block, slowly.
                let last = req.from_height + 1;
                return Some((
                    crate::SLOW_ANSWER * 2,
                    sync_answer(&blocks, &qcs, req.from_height, last),
                ));
            }
            // Then nothing, at once.
            Some((std::time::Duration::ZERO, sync_answer(&blocks, &qcs, 0, 0)))
        },
    );
    let sync = ChainSync::new(Arc::clone(&sim.node(y).storage)).with_sessions(client);
    let reached = rt.block_on(sync.sync_from_peers());
    assert_eq!(reached, from + 1, "vacuous: the block was not taken");
    assert!(
        sync.stalls
            .lock()
            .unwrap()
            .get("12D3KooWslow")
            .is_some_and(|(n, _)| *n > 0),
        "a session that ended its turn early cleared its strike"
    );
}

/// B263 witness: sessions advertising this node's own height take no block
/// turn, and a member with strikes is asked before them (they took a turn
/// each and were never struck, so three of them held every turn once the
/// members had a strike: the node never synced).
#[test]
fn sessions_at_this_nodes_height_take_no_turn() {
    let (sim, y, from, tip, blocks, qcs) = left_behind("b263_level", &[211, 212, 213, 214], 6);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let sybil = |p: &str| network::SessionPeer {
        peer: p.into(),
        member: None,
    };
    let (client, block_asks) = sessions_serving(
        &rt,
        vec![
            sybil("12D3KooWsybil1"),
            sybil("12D3KooWsybil2"),
            sybil("12D3KooWsybil3"),
            network::SessionPeer {
                peer: "12D3KooWmember".into(),
                member: Some(sim.committee[1].address.clone()),
            },
        ],
        move |peer, wire| {
            let height = if peer == "12D3KooWmember" { tip } else { from };
            if wire == "GET_HEIGHT" {
                return Some((std::time::Duration::ZERO, format!("HEIGHT:{height}")));
            }
            let req: SyncRequest = serde_json::from_str(wire.strip_prefix("SYNC_REQ:")?).ok()?;
            Some((
                std::time::Duration::ZERO,
                sync_answer(&blocks, &qcs, req.from_height, height),
            ))
        },
    );
    let sync = ChainSync::new(Arc::clone(&sim.node(y).storage)).with_sessions(client);
    sync.stalls
        .lock()
        .unwrap()
        .insert("12D3KooWmember".into(), (3, std::time::Instant::now()));
    let reached = rt.block_on(sync.sync_from_peers());
    let asked = block_asks.lock().unwrap().clone();
    assert!(
        asked.iter().all(|p| p == "12D3KooWmember"),
        "a session at this node's height took a turn: {asked:?}"
    );
    assert_eq!(reached, tip, "the member was not asked");
}

/// B263 witness: a member whose newest block has no QC yet is not struck
/// for it: this node takes what it certified and stops there (it was struck
/// whenever its tip lacked a QC, and sat behind sessions never struck).
#[test]
fn a_member_at_its_tip_without_a_qc_is_not_struck() {
    let (sim, y, from, tip, blocks, qcs) = left_behind("b263_tip", &[221, 222, 223, 224], 6);
    // This node holds everything but the tip already.
    let below: Vec<Block> = blocks
        .iter()
        .filter(|b| b.header.height < tip)
        .cloned()
        .collect();
    let held = sim.nodes[y]
        .sync
        .as_ref()
        .unwrap()
        .process_blocks_with_qcs(below, &qcs, from);
    assert_eq!(
        held,
        tip - 1,
        "vacuous: the blocks below the tip were not taken"
    );
    // The member's newest block, `tip`, comes without its QC.
    let uncertified: Vec<consensus::qc::QuorumCertificate> = qcs
        .iter()
        .filter(|q| q.block_height != tip)
        .cloned()
        .collect();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (client, _) = sessions_serving(
        &rt,
        vec![network::SessionPeer {
            peer: "12D3KooWmember".into(),
            member: Some(sim.committee[1].address.clone()),
        }],
        move |_, wire| {
            if wire == "GET_HEIGHT" {
                return Some((std::time::Duration::ZERO, format!("HEIGHT:{tip}")));
            }
            let req: SyncRequest = serde_json::from_str(wire.strip_prefix("SYNC_REQ:")?).ok()?;
            Some((
                std::time::Duration::ZERO,
                sync_answer(&blocks, &uncertified, req.from_height, tip),
            ))
        },
    );
    let sync = ChainSync::new(Arc::clone(&sim.node(y).storage)).with_sessions(client);
    let reached = rt.block_on(sync.sync_from_peers());
    assert_eq!(reached, tip - 1);
    assert!(
        !sync.stalls.lock().unwrap().contains_key("12D3KooWmember"),
        "a member was struck for a newest block without a QC"
    );
}

/// B264/B275 witness support: the byte cut at which node x's server and
/// node y's client part blocks (a Sim block is a few KB: every block is
/// parted, in parts of half this).
const CUT: usize = 640;

/// B264/B275 witness support: how one member session, serving node `y` from
/// node `x`'s real blocks parted at `CUT`, misbehaves.
#[derive(Clone, Copy, Default)]
struct Parted {
    /// Each part but a block's last, ten bytes short (past the three a
    /// server's cut at a character boundary may leave).
    short: bool,
    /// The oversized answer without its block's QC.
    no_qc: bool,
    /// Its QC with another block hash.
    junk_qc: bool,
    /// The length named, when not the block's.
    len: Option<u64>,
    /// One space after the block's text (every length raised to match).
    pad: bool,
    /// The second part asked answered busy (a fetch under way).
    busy_once: bool,
    /// Each part answered after this many milliseconds.
    part_delay_ms: u64,
    /// The passes run (fewer once the certified tip is reached).
    passes: usize,
}

/// What `sync_past_oversized` saw.
struct PartedRun {
    reached: u64,
    /// The (height, offset) of each part asked for, in order.
    offsets: Vec<(u64, u64)>,
    strikes: u32,
}

/// B264/B275 witness support: node `y` of a `left_behind` cluster syncing
/// to the certified tip from one member session that serves node 0's blocks
/// in parts, as `how` says.
fn sync_past_oversized(sim: &Sim, y: usize, tip: u64, how: Parted) -> PartedRun {
    let server = Arc::new(ChainSync::new(Arc::clone(&sim.node(0).storage)).with_batch_bytes(CUT));
    let offsets = Arc::new(std::sync::Mutex::new(Vec::<(u64, u64)>::new()));
    let asked = Arc::clone(&offsets);
    let parts_asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (client, _) = sessions_serving(
        &rt,
        vec![network::SessionPeer {
            peer: "12D3KooWbig".into(),
            member: Some(sim.committee[1].address.clone()),
        }],
        move |_, wire| {
            let now = std::time::Duration::ZERO;
            if wire == "GET_HEIGHT" {
                return Some((now, format!("HEIGHT:{tip}")));
            }
            if let Some(req) = wire.strip_prefix(crate::PART_REQ) {
                let req: crate::BlockPartRequest = serde_json::from_str(req).ok()?;
                asked.lock().unwrap().push((req.height, req.offset));
                let wait = std::time::Duration::from_millis(how.part_delay_ms);
                let nth = parts_asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if how.busy_once && nth == 1 {
                    return Some((wait, crate::state_sync::busy_reply(wire)?));
                }
                let answer = server.handle_message(wire)?;
                let mut part: crate::BlockPartResponse =
                    serde_json::from_str(answer.strip_prefix(crate::PART_RESP)?).ok()?;
                let last = req.offset + part.data.len() as u64 >= part.len;
                if how.short && !last {
                    let mut cut = part.data.len().saturating_sub(10);
                    while !part.data.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    part.data.truncate(cut);
                }
                if how.pad {
                    if last {
                        part.data.push(' ');
                    }
                    part.len += 1;
                }
                let json = serde_json::to_string(&part).unwrap();
                return Some((wait, format!("{}{json}", crate::PART_RESP)));
            }
            let answer = server.handle_message(wire)?;
            let Some(json) = answer.strip_prefix("SYNC_RESP:") else {
                return Some((now, answer));
            };
            let mut resp: SyncResponse = serde_json::from_str(json).ok()?;
            if let Some(big) = resp.oversized.as_mut() {
                if how.no_qc {
                    resp.qcs.retain(|q| q.block_height != big.height);
                }
                if how.junk_qc {
                    for q in resp.qcs.iter_mut().filter(|q| q.block_height == big.height) {
                        q.block_hash = "ab".repeat(32);
                    }
                }
                if let Some(len) = how.len {
                    big.len = len;
                }
                if how.pad {
                    big.len += 1;
                }
            }
            Some((
                now,
                format!("SYNC_RESP:{}", serde_json::to_string(&resp).unwrap()),
            ))
        },
    );
    let sync = ChainSync::new(Arc::clone(&sim.node(y).storage))
        .with_batch_bytes(CUT)
        .with_sessions(client);
    let mut reached = 0;
    for _ in 0..how.passes.max(1) {
        reached = rt.block_on(sync.sync_from_peers());
        if reached >= tip {
            break;
        }
    }
    let strikes = sync
        .stalls
        .lock()
        .unwrap()
        .get("12D3KooWbig")
        .map_or(0, |(n, _)| *n);
    let offsets = offsets.lock().unwrap().clone();
    PartedRun {
        reached,
        offsets,
        strikes,
    }
}

/// B264/B275 witness: blocks a server names as too large for a batch are
/// fetched in parts, each checked against its QC first, and imported, to
/// the certified tip. The server sent such a block alone, over the frame no
/// client reads past, so no node could block-sync beyond it.
#[test]
fn a_block_named_oversized_is_fetched_in_parts() {
    let (sim, y, from, tip, _, _) = left_behind("b264_fetch", &[231, 232, 233, 234], 4);
    let how = Parted {
        passes: 8,
        ..Parted::default()
    };
    let run = sync_past_oversized(&sim, y, tip, how);
    assert!(
        run.offsets.len() > 2,
        "vacuous: {} parts",
        run.offsets.len()
    );
    assert_eq!(
        run.reached, tip,
        "syncing did not go past the parted blocks"
    );
    assert_eq!(run.strikes, 0);
    assert!(run.offsets.iter().any(|(h, _)| *h == from + 1));
}

/// B264 witness: a part shorter than due ends the fetch at once: nothing is
/// imported, and the session is struck.
#[test]
fn a_short_block_part_ends_the_fetch() {
    let (sim, y, from, tip, _, _) = left_behind("b264_short", &[241, 242, 243, 244], 4);
    let how = Parted {
        short: true,
        passes: 1,
        ..Parted::default()
    };
    let run = sync_past_oversized(&sim, y, tip, how);
    assert_eq!(
        run.offsets,
        vec![(from + 1, 0)],
        "a short part did not end the fetch"
    );
    assert_eq!(run.reached, from);
    assert!(
        run.strikes > 0,
        "a session sending short parts was not struck"
    );
}

/// B264 witness: a block named too large for a batch without its QC is its
/// server's newest: no part is asked for, and the session is not struck.
#[test]
fn an_oversized_block_without_its_qc_is_not_fetched() {
    let (sim, y, from, tip, _, _) = left_behind("b264_noqc", &[251, 252, 253, 254], 4);
    let how = Parted {
        no_qc: true,
        passes: 1,
        ..Parted::default()
    };
    let run = sync_past_oversized(&sim, y, tip, how);
    assert!(run.offsets.is_empty(), "a block without its QC was fetched");
    assert_eq!(run.reached, from);
    assert_eq!(run.strikes, 0, "a server was struck for its newest block");
}

/// B275 witness: a block named with a QC that does not bind its header, or
/// with a length no server parts (one a batch holds, one past what a client
/// imports), is refused before any part is asked for, and its server is
/// struck (any QC naming the height started a fetch of up to 512 MiB).
#[test]
fn a_parted_block_is_checked_before_any_part() {
    let (sim, y, from, tip, _, _) = left_behind("b275_named", &[5, 6, 7, 8], 4);
    for how in [
        Parted {
            junk_qc: true,
            ..Parted::default()
        },
        Parted {
            len: Some(CUT as u64),
            ..Parted::default()
        },
        Parted {
            len: Some(crate::MAX_PARTED_BLOCK_BYTES + 1),
            ..Parted::default()
        },
    ] {
        let run = sync_past_oversized(&sim, y, tip, how);
        assert!(
            run.offsets.is_empty(),
            "a part was asked for: {:?}",
            run.offsets
        );
        assert_eq!(run.reached, from);
        assert!(run.strikes > 0);
    }
}

/// B275 witness: a parted block must be the text its server stores: one
/// padded (it still parses to the block, and filled a turn's bytes) is
/// refused, and its server struck.
#[test]
fn a_padded_parted_block_is_refused() {
    let (sim, y, from, tip, _, _) = left_behind("b264_padded", &[15, 16, 17, 18], 4);
    let how = Parted {
        pad: true,
        passes: 1,
        ..Parted::default()
    };
    let run = sync_past_oversized(&sim, y, tip, how);
    assert!(run.offsets.len() > 1, "vacuous: the block was not fetched");
    assert_eq!(run.reached, from, "a padded block was imported");
    assert!(run.strikes > 0, "padding was not struck");
}

/// B275 witness: a busy part answer is waited out, and the fetch goes on
/// from that part (the server's answer budget refused the next part, and
/// the fetch failed), and a block that outlasts a turn is resumed at the
/// next from where it stopped (it began again from 0, so no block longer
/// than a turn could arrive).
#[test]
fn a_parted_fetch_waits_out_busy_and_resumes_across_turns() {
    let (sim, y, from, tip, _, _) = left_behind("b275_resume", &[35, 36, 37, 38], 4);
    let how = Parted {
        busy_once: true,
        part_delay_ms: crate::SYNC_TURN.as_millis() as u64 / 3,
        passes: 40,
        ..Parted::default()
    };
    let run = sync_past_oversized(&sim, y, tip, how);
    // Every block here takes more parts than a turn's time holds, so one
    // fetched at all was resumed.
    assert!(run.reached > from, "nothing was fetched");
    // A part in flight when a turn ends is asked again at the next; a
    // block once begun is never begun again.
    let mut at = std::collections::HashMap::new();
    for &(height, offset) in &run.offsets {
        let before = at.insert(height, offset).unwrap_or(0);
        assert!(
            offset >= before,
            "block {height} began again at {offset} after {before}: {:?}",
            run.offsets
        );
    }
    assert!(
        run.offsets.iter().any(|(h, o)| *h == from + 1 && *o > 0),
        "vacuous: no block took more than one part"
    );
}

/// B263/B274 witness: block turns go by standing: members first whatever
/// their strikes, then the fewest strikes still counting (they expire after
/// `STRIKE_TTL`), then the most blocks brought, then the session that waited
/// longest; three take a turn, and every turn is recorded.
#[test]
fn turns_go_to_members_then_live_strikes_then_yield() {
    let path = format!(
        "{}/b263_order_{}",
        storage::test_dir::process_dir().display(),
        std::process::id()
    );
    let _ = std::fs::remove_dir_all(&path);
    let db = Arc::new(StateDB::open(&path).unwrap());
    let rt = tokio::runtime::Runtime::new().unwrap();
    let session = |peer: &str, member: Option<&str>| network::SessionPeer {
        peer: peer.into(),
        member: member.map(str::to_string),
    };
    let (client, block_asks) = sessions_serving(
        &rt,
        vec![
            session("12D3KooWa", None),
            session("12D3KooWb", None),
            session("12D3KooWc", None),
            session("12D3KooWd", None),
            session("12D3KooWm", Some(&"ee".repeat(32))),
        ],
        |_, wire| {
            if wire == "GET_HEIGHT" {
                return Some((std::time::Duration::ZERO, "HEIGHT:100".to_string()));
            }
            wire.strip_prefix("SYNC_REQ:")?;
            Some((std::time::Duration::ZERO, sync_answer(&[], &[], 0, 0)))
        },
    );
    let sync = ChainSync::new(db).with_sessions(client);
    let now = std::time::Instant::now();
    let long_ago = now.checked_sub(crate::STRIKE_TTL * 2).unwrap();
    {
        let mut stalls = sync.stalls.lock().unwrap();
        // a's strikes expired; b's count.
        stalls.insert("12D3KooWa".into(), (5, long_ago));
        stalls.insert("12D3KooWb".into(), (1, now));
        stalls.insert("12D3KooWm".into(), (2, now));
        let mut yields = sync.yields.lock().unwrap();
        yields.insert("12D3KooWa".into(), (9, now));
        yields.insert("12D3KooWc".into(), (7, now));
    }
    rt.block_on(sync.sync_from_peers());
    let asked = block_asks.lock().unwrap().clone();
    // m (a member, struck); a (its strikes expired, most brought); c.
    assert_eq!(asked, vec!["12D3KooWm", "12D3KooWa", "12D3KooWc"]);
    assert!(
        sync.turns.lock().unwrap().contains_key("12D3KooWc"),
        "a turn was not recorded"
    );
}

/// B263 witness: a session at this node's height takes no block turn but is
/// asked for its finality artifact (it was asked at the end of a turn, and
/// such a session no longer gets one, so a node level with its peers never
/// imported their QCs).
#[test]
fn a_session_at_this_nodes_height_gives_its_finality() {
    let (sim, y, from, _tip, _blocks, _qcs) = left_behind("b263_finality", &[25, 26, 27, 28], 4);
    let asked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let log = Arc::clone(&asked);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let (client, block_asks) = sessions_serving(
        &rt,
        vec![network::SessionPeer {
            peer: "12D3KooWlevel".into(),
            member: Some(sim.committee[1].address.clone()),
        }],
        move |_, wire| {
            log.lock().unwrap().push(wire.to_string());
            let now = std::time::Duration::ZERO;
            (wire == "GET_HEIGHT").then(|| (now, format!("HEIGHT:{from}")))
        },
    );
    let sync = ChainSync::new(Arc::clone(&sim.node(y).storage)).with_sessions(client);
    rt.block_on(sync.sync_from_peers());
    assert!(
        block_asks.lock().unwrap().is_empty(),
        "a level session took a block turn"
    );
    let asked = asked.lock().unwrap().clone();
    assert!(
        asked.iter().any(|w| w == "GET_FINALITY"),
        "a level session was not asked for its finality: {asked:?}"
    );
}
