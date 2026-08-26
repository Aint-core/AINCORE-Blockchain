use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
// use serde::{Serialize, Deserialize}; // Unused
use crate::ordering::OrderingEngine;
use blockchain::Vertex;
use crypto::accumulator::Accumulator;
use da_sequencer::DASequencer;
use executor::Executor;
use mempool::Mempool;
use network::PeerList;
use storage::StateDB;

/// Cached active validator set as `(address, stake)` pairs, canonically sorted.
type ValidatorStakeCache = Arc<Mutex<Option<Vec<(String, u64)>>>>;

/// SEC-#10: how long equivocation evidence (`sys:equiv_seen:{offender}:{round}`)
/// is retained past the DAG prune horizon before garbage collection. Set well
/// beyond any realistic forensic/governance window; the slash is applied and
/// finalized long before this, so older records are safe to discard.
pub(crate) const EQUIV_EVIDENCE_RETENTION_ROUNDS: u64 = 100_000;

pub struct DagConsensus {
    pub node_id: String,
    pub current_round: u64,
    pub dag: Arc<Mutex<HashMap<String, Vertex>>>, // Hash -> Vertex
    pub round_index: Arc<Mutex<HashMap<u64, Vec<String>>>>, // Round -> Vec<Hash>
    pub mempool: Arc<Mutex<Mempool>>,
    pub executor: Arc<Executor>,
    pub storage: Arc<StateDB>,
    pub peers: PeerList,
    pub ordering_engine: Arc<Mutex<OrderingEngine>>,
    pub latest_block_height: u64,
    pub latest_block_hash: String,
    /// AUDIT-H1: timestamp of the chain tip, used to keep BFT block time
    /// monotonic across blocks and across restarts.
    pub latest_block_timestamp: u64,
    /// AUDIT-B4b (dedup): the ANCHOR ROUND of the chain-tip block. Blocks reach
    /// the tip from TWO sources — the local commit loop and ChainSync imports —
    /// and both must advance one shared stream. Without this, a node that synced
    /// a peer's block for anchor A and then ran its own commit for A built a
    /// SECOND block for the same anchor at the next height, shifting its whole
    /// chain numbering by one forever (the residual ±1 fork the first B4b deploy
    /// exposed: anchor 73 landed at height 67 on NAS and height 68 on LAP).
    /// The commit loop skips block-building for any anchor <= this round.
    pub latest_block_round: u64,
    /// LIVENESS: highest block height whose anchor has been applied to the
    /// ordering engine — by local commit or by adopting a synced block. Heights
    /// above this that arrive via ChainSync are adopted in reload_chain_tip.
    pub last_adopted_height: u64,
    pub accumulator: Accumulator,
    pub da_sequencer: Option<Arc<Mutex<DASequencer>>>, // Added DA Sequencer
    pub p2p_tx: Option<tokio::sync::mpsc::Sender<String>>, // Added P2P Libp2p Channel
    pub node_key: [u8; 32], // H4 FIX: Store the persistent Ed25519 key for BLS derivation
    /// Phase 2.8 (M-08): cache of the active validator set.
    ///
    /// `get_validator_set` used to hit RocksDB on every call — twice per
    /// vertex (proposal + verification) plus once per ordering attempt.
    /// On a healthy network that's hundreds of disk reads + JSON parses
    /// per second of identical data. The cache is populated on first
    /// access, returned for all reads in the same block window, and
    /// invalidated when a block commits (cheapest moment to refresh —
    /// the only time validator set may legitimately change during normal
    /// operation is via a slash, which happens during block execution).
    validators_cache: ValidatorStakeCache,
}

impl DagConsensus {
    #[allow(clippy::too_many_arguments)] // intrinsic to DagConsensus dependencies
    pub fn new(
        node_id: String,
        peers: PeerList,
        mempool: Arc<Mutex<Mempool>>,
        executor: Arc<Executor>,
        storage: Arc<StateDB>,
        da_sequencer: Option<Arc<Mutex<DASequencer>>>,
        p2p_tx: Option<tokio::sync::mpsc::Sender<String>>, // Corrected to Sender
        node_key: [u8; 32],                                // H4 FIX: Accept the persistent key
    ) -> Self {
        let mut dag_map = HashMap::new();
        let mut round_idx_map: HashMap<u64, Vec<String>> = HashMap::new();
        let mut max_round = 0;

        // OPTIMIZED RECOVERY: Use checkpoint instead of full scan (Aptos/Sui style)
        let checkpoint_round = storage.get_latest_checkpoint_round();

        if checkpoint_round > 0 {
            // Fast path: Load from checkpoint with H-06 integrity verification.
            //
            // Pre-Phase-2 code loaded checkpoints blindly. An attacker with
            // write access to the storage layer could inject a fake
            // checkpoint and the node would happily restore from it on
            // boot — silent rollback / arbitrary-state attack.
            //
            // Phase 2.5 → Phase 4.A2: production checkpoints are signed with
            // the node's Ed25519 key. On load we re-verify the signature:
            //   - signature present + valid  → fast recovery from checkpoint
            //   - signature present + invalid → REJECT fast recovery, fall
            //     back to full scan_vertices replay (safety over speed)
            //   - signature absent           → REJECT fast recovery, fall
            //     back to full scan_vertices replay (Phase 4.A2)
            //
            // ⚠️  PRECISE SCOPE OF A2 FIX:
            //   "Reject unsigned checkpoint" here means "do not use it for
            //   fast recovery"; it does NOT mean the node fails-fast on boot.
            //   The node still boots successfully via the slower
            //   scan_vertices replay path. This closes the legacy-bypass
            //   attack vector (operator-level adversary deleting the
            //   signature blob to forge a checkpoint) while preserving
            //   one-time recovery for operators upgrading from pre-Phase-2
            //   installs — they incur a single longer boot until their
            //   node produces a fresh signed checkpoint.
            let checkpoint_accepted: bool;
            if let Some(checkpoint_data) = storage.get_dag_checkpoint(checkpoint_round) {
                checkpoint_accepted = match storage.get_dag_checkpoint_signature(checkpoint_round) {
                    Some(sig_hex) => {
                        let signing_key = crypto::SigningKey::from_bytes(&node_key);
                        let verifying_key = signing_key.verifying_key();
                        let pubkey_bytes = verifying_key.to_bytes();
                        match hex::decode(&sig_hex) {
                            Ok(sig_bytes) if sig_bytes.len() == 64 => {
                                match crypto::verify_signature(
                                    &pubkey_bytes,
                                    checkpoint_data.as_bytes(),
                                    &sig_bytes,
                                ) {
                                    Ok(true) => true,
                                    _ => {
                                        eprintln!(
                                            "🚨 [H-06] Checkpoint signature INVALID for round {} — \
                                             refusing fast recovery; falling back to scan. \
                                             Possible storage tampering.",
                                            checkpoint_round
                                        );
                                        false
                                    }
                                }
                            }
                            _ => {
                                eprintln!(
                                    "🚨 [H-06] Checkpoint signature malformed for round {} — \
                                     refusing fast recovery; falling back to scan.",
                                    checkpoint_round
                                );
                                false
                            }
                        }
                    }
                    None => {
                        // Phase 4.A2: REJECT FAST RECOVERY from unsigned
                        // checkpoint (not a hard boot reject — node falls
                        // back to scan replay below).
                        eprintln!(
                            "🚨 [H-06/A2] Checkpoint at round {} has NO signature — \
                             REJECTING fast recovery path; falling back to \
                             scan_vertices replay (legacy-bypass attack vector closed).",
                            checkpoint_round
                        );
                        false
                    }
                };

                if checkpoint_accepted {
                    if let Ok(vertices) = serde_json::from_str::<Vec<Vertex>>(&checkpoint_data) {
                        // Phase 5C.1 / NEW-001: enforce PWN-001 also at boot.
                        // The checkpoint signature covers the JSON blob as a
                        // whole, but each Vertex.hash inside MUST still match
                        // a freshly computed hash of its body. Otherwise a
                        // disk-write attacker could mutate vertices inside an
                        // otherwise-valid checkpoint and bypass PWN-001 on
                        // the recovery path.
                        let mut accepted = 0usize;
                        let mut rejected = 0usize;
                        for vertex in vertices {
                            if vertex.calculate_hash() != vertex.hash {
                                eprintln!(
                                    "🚨 [NEW-001/boot] checkpoint vertex hash tampered, \
                                     dropping (hash={})",
                                    vertex.hash
                                );
                                rejected += 1;
                                continue;
                            }
                            if vertex.round > max_round {
                                max_round = vertex.round;
                            }
                            round_idx_map
                                .entry(vertex.round)
                                .or_default()
                                .push(vertex.hash.clone());
                            dag_map.insert(vertex.hash.clone(), vertex);
                            accepted += 1;
                        }
                        println!(
                            "⚡ Fast recovery from checkpoint: {} accepted / {} tampered-dropped, Round {}",
                            accepted, rejected, checkpoint_round
                        );
                    }
                }
                // Whether or not checkpoint was accepted, the tail-replay
                // loop below still runs to fill in vertices written after
                // the checkpoint. If the checkpoint was rejected, the
                // tail replay alone reconstructs as much of the DAG as
                // honest on-disk data permits.
            }

            // Checkpoints are saved periodically, while every proposed vertex is persisted
            // individually. On cold restart we must replay the tail after the latest checkpoint;
            // otherwise latest_proposed_round can advance past the in-memory round index and
            // the node gets stuck with zero parents.
            let mut replayed_tail = 0usize;
            let mut tail_rejected = 0usize;
            for v_json in storage.scan_vertices() {
                if let Ok(vertex) = serde_json::from_str::<Vertex>(&v_json) {
                    if vertex.round <= checkpoint_round || dag_map.contains_key(&vertex.hash) {
                        continue;
                    }
                    // Phase 5C.1 / NEW-001: hash-integrity check on tail replay.
                    if vertex.calculate_hash() != vertex.hash {
                        eprintln!(
                            "🚨 [NEW-001/tail] tail vertex hash tampered, dropping (hash={})",
                            vertex.hash
                        );
                        tail_rejected += 1;
                        continue;
                    }
                    if vertex.round > max_round {
                        max_round = vertex.round;
                    }
                    round_idx_map
                        .entry(vertex.round)
                        .or_default()
                        .push(vertex.hash.clone());
                    dag_map.insert(vertex.hash.clone(), vertex);
                    replayed_tail += 1;
                }
            }
            if replayed_tail > 0 || tail_rejected > 0 {
                println!(
                    "🔄 Replayed {} DAG vertices after checkpoint round {} ({} tampered-dropped)",
                    replayed_tail, checkpoint_round, tail_rejected
                );
            }
        } else {
            // Fallback: Scan for legacy data (only on first run or migration)
            let vertices_json = storage.scan_vertices();
            let mut legacy_rejected = 0usize;
            for v_json in vertices_json {
                if let Ok(vertex) = serde_json::from_str::<Vertex>(&v_json) {
                    // Phase 5C.1 / NEW-001: hash-integrity check on legacy scan.
                    if vertex.calculate_hash() != vertex.hash {
                        eprintln!(
                            "🚨 [NEW-001/legacy] legacy vertex hash tampered, dropping (hash={})",
                            vertex.hash
                        );
                        legacy_rejected += 1;
                        continue;
                    }
                    if vertex.round > max_round {
                        max_round = vertex.round;
                    }
                    round_idx_map
                        .entry(vertex.round)
                        .or_default()
                        .push(vertex.hash.clone());
                    dag_map.insert(vertex.hash.clone(), vertex);
                }
            }
            if !dag_map.is_empty() {
                println!(
                    "♻️  Legacy recovery (scan): {} vertices ({} tampered-dropped), Max Round {}",
                    dag_map.len(),
                    legacy_rejected,
                    max_round
                );
            }
        }

        println!(
            "✅ DAG Initialized: {} vertices, Starting Round {}",
            dag_map.len(),
            max_round + 1
        );

        let latest_block_height = match storage.get("latest_height") {
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
            _ => 0,
        };
        let latest_block_hash = match storage.get("latest_block_hash") {
            Ok(Some(h)) => h,
            _ => "genesis".to_string(),
        };

        // AUDIT-H1: restore the tip's timestamp so BFT block time stays monotonic
        // across a restart (otherwise the first block after a restart could move
        // time backwards and diverge from peers that never restarted).
        let (latest_block_timestamp, latest_block_round) = storage
            .get(&format!("block_{}", latest_block_height))
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<blockchain::Block>(&json).ok())
            .map(|b| (b.header.timestamp, b.header.round))
            .unwrap_or((0, 0));
        // RE-AUDIT MEDIUM: adoption cursor persisted across restarts (never above
        // the tip), so a crash between sync persisting a block and its adoption
        // cannot silently skip that block at boot.
        let last_adopted_height = storage
            .get("consensus:last_adopted_height")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .map(|h| h.min(latest_block_height))
            .unwrap_or(latest_block_height);


        let explicit_max_round = match storage.get("latest_proposed_round") {
            Ok(Some(r)) => r.parse::<u64>().unwrap_or(0),
            _ => 0,
        };

        let mut final_start_round = std::cmp::max(1, max_round + 1);
        if explicit_max_round >= final_start_round {
            println!(
                "🔄 Restoring from explicitly saved proposed round: {}",
                explicit_max_round
            );
            final_start_round = explicit_max_round + 1;
        }

        let storage_for_ordering = Arc::clone(&storage);

        Self {
            node_id,
            peers,
            current_round: final_start_round,
            dag: Arc::new(Mutex::new(dag_map)),
            round_index: Arc::new(Mutex::new(round_idx_map)),
            mempool,
            executor,
            storage,
            ordering_engine: Arc::new(Mutex::new(OrderingEngine::new_with_storage(
                storage_for_ordering,
            ))),
            latest_block_height,
            latest_block_hash,
            latest_block_timestamp,
            latest_block_round,
            last_adopted_height,
            accumulator: Accumulator::new(),
            da_sequencer,
            p2p_tx,
            node_key,
            // Phase 2.8 (M-08): empty cache; first get_validator_set call
            // populates it from storage. Subsequent reads are cache hits
            // until the next block commit invalidates.
            validators_cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Phase 2.8 (M-08): force the next `get_validator_set` to re-read
    /// from storage. Called on block commit because that's the only
    /// moment validator set may legitimately change during normal
    /// operation (slash execution updates `sys:validators`). Public so
    /// out-of-band code paths (genesis init, integration tests,
    /// admin tooling that mutates storage directly) can force a refresh.
    pub fn invalidate_validators_cache(&self) {
        if let Ok(mut guard) = self.validators_cache.lock() {
            *guard = None;
        }
    }

    /// Highest round for which this node already holds a STAKE QUORUM of vertices.
    ///
    /// AUDIT-B3. This is the Narwhal round-advance predicate: a validator moves to
    /// round r+1 only once it has collected vertices from >2/3 of stake at round r,
    /// because those vertices are exactly the parents its next vertex must
    /// reference. Deriving the local round from this — instead of from whatever
    /// round a single remote vertex happens to claim — makes the wedge
    /// unrepresentable: we can never sit at a round whose predecessor lacks the
    /// parents we need.
    ///
    /// Pure function of (round_index, dag, validators) so it is identical on every
    /// node given the same DAG contents, and it takes the already-held guards
    /// rather than `&self` so it can run inside the ingest critical section.
    fn quorum_round(
        round_index: &HashMap<u64, Vec<String>>,
        dag: &HashMap<String, Vertex>,
        validators: &[(String, u64)],
    ) -> u64 {
        let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();
        if total_stake == 0 {
            return 0;
        }
        let stake_by_addr: HashMap<&str, u64> =
            validators.iter().map(|(a, s)| (a.as_str(), *s)).collect();

        let mut best = 0u64;
        for (round, hashes) in round_index.iter() {
            if *round <= best {
                continue; // cannot improve the maximum
            }
            let mut authors: HashSet<&str> = HashSet::new();
            for h in hashes {
                if let Some(v) = dag.get(h) {
                    authors.insert(v.author.as_str());
                }
            }
            let round_stake: u128 = authors
                .iter()
                .filter_map(|a| stake_by_addr.get(a).map(|s| *s as u128))
                .sum();
            if crate::qc::stake_quorum_met(round_stake, total_stake) {
                best = *round;
            }
        }
        best
    }

    pub fn try_create_vertex(&mut self) {
        // 1. Check if we have enough parents from previous round
        let prev_round = self.current_round - 1;
        let mut parents = {
            let round_idx = self
                .round_index
                .lock()
                .expect("🚨 FATAL: Round index lock poisoned");
            round_idx.get(&prev_round).cloned().unwrap_or_default()
        };

        // Ensure Round 1 links to genesis
        if prev_round == 0 && parents.is_empty() {
            parents.push("genesis".to_string());
        }

        // DYNAMIC CHECK: stake-aware validator set FIRST (B4).
        let validators = self.get_validator_set_with_stake();
        let is_active_validator = validators.iter().any(|(a, _)| a == &self.node_id);
        let n = validators.len();
        if n == 0 {
            println!("⚠️ [Consensus] No validators found! Defaulting to Singleton Quorum.");
        }
        let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();

        // B4: parent quorum is STAKE-weighted. A new vertex must reference parents
        // whose DISTINCT authors represent strict > 2/3 of total stake (genesis
        // round bootstraps with no parents). This is the liveness/connectivity
        // gate; the BFT SAFETY gate is the stake-weighted COMMIT quorum in
        // try_commit. Same `qc::stake_quorum_met` predicate as QC verification.
        let parent_quorum_met = if prev_round == 0 {
            true
        } else {
            let stake_by_addr: HashMap<&str, u64> =
                validators.iter().map(|(a, s)| (a.as_str(), *s)).collect();
            let parent_stake: u128 = {
                let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");
                let mut authors: HashSet<&str> = HashSet::new();
                for ph in &parents {
                    if let Some(v) = dag.get(ph) {
                        authors.insert(v.author.as_str());
                    }
                }
                authors
                    .iter()
                    .filter_map(|a| stake_by_addr.get(a).map(|s| *s as u128))
                    .sum()
            };
            crate::qc::stake_quorum_met(parent_stake, total_stake)
        };

        println!(
            "🔒 [Consensus] Round {}: Validators={}, Parents={}, StakeQuorum={}",
            self.current_round,
            n,
            parents.len(),
            parent_quorum_met
        );

        // SPLIT-BRAIN PREVENTION & OBSERVER MODE:
        // Dynamic singleton detection: if exactly 1 validator and it's us, we are the genesis/bootstrap node
        let is_singleton = validators.len() == 1 && is_active_validator;

        let has_peers = {
            if let Ok(p) = self.peers.lock() {
                !p.is_empty()
            } else {
                false
            }
        };

        // RULE 1: If I am NOT a validator, I am an Observer. Observers CANNOT mine.
        if !is_active_validator {
            if self.current_round.is_multiple_of(10) || self.current_round < 5 {
                println!("⚠️  [Consensus] Observer Mode: I am not in Validator Set. Waiting to sync/register... (Round {})", self.current_round);
            }
            return;
        }
        // RULE 2: If I AM a validator, but I have NO peers (and not Singleton), I must stop to avoid Split-Brain.
        else if !has_peers && !is_singleton {
            println!("⚠️  [Consensus] Validator Isolated! Stopping mining to prevent fork. Waiting for peers...");
            return;
        }

        // Standard logic for Genesis or Connected Nodes
        if parent_quorum_met {
            // 2. Create Payload (Fetch from Mempool)
            let mut payload = Vec::new();
            if let Ok(mut mp) = self.mempool.lock() {
                // Orphan-loss fix: before pulling, reclaim loaned transactions
                // that never executed (orphaned vertex payloads and
                // nonce-deferred txs). 30s ≈ well past commit latency, well
                // short of user-visible loss.
                let _ = mp.requeue_stale(std::time::Duration::from_secs(30));
                // Throughput tuning: pull size per vertex. Narwhal is designed for
                // large batches; 50 was a conservative bring-up cap and became the
                // de-facto per-round throughput ceiling. Env-tunable so the burn-in
                // and benchmark runs measure the config that will actually ship.
                let pull = std::env::var("AINCORE_MEMPOOL_PULL")
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
                    .filter(|v| (1..=10_000).contains(v))
                    .unwrap_or(500);
                payload = mp.get_pending_transactions(pull);
                if !payload.is_empty() {
                    println!("🚀 DAG PULLED {} TXS FROM MEMPOOL", payload.len());
                }
            }

            // 3. Create Vertex
            let mut vertex = Vertex {
                round: self.current_round,
                author: self.node_id.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::from_secs(0))
                    .as_secs(),
                payload,
                parents,
                hash: String::new(),
                signature: String::new(),
                aggregated_signature: None,
            };

            vertex.hash = vertex.calculate_hash();

            // C-2 FIX: Use Ed25519 signing (BLS was actually symmetric MAC)
            let signing_key = crypto::SigningKey::from_bytes(&self.node_key);
            vertex.sign_with_ed25519(&signing_key);

            // 4. Add & Broadcast
            self.add_vertex(vertex.clone());
            self.broadcast_vertex(&vertex);

            // Explicitly save the round we just proposed to prevent Double-Sign on restart
            let _ = self
                .storage
                .put("latest_proposed_round", &self.current_round.to_string());

            // === DOWNTIME DETECTION (Jail System Trigger) ===
            // Track which validators participated in this round.
            // If a validator misses 100+ consecutive rounds (~100 minutes), mark for slashing.
            // DOWNTIME TOLERANCE IS TIME-BASED, NOT ROUND-BASED.
            //
            // The old constant (100 rounds) silently coupled the jail window to
            // the consensus tick: at the original 3s tick it meant ~5 minutes of
            // tolerance, but when the tick was tuned to 500ms it became FIFTY
            // SECONDS — and the live 4-validator cluster promptly jailed its two
            // slowest validators for ordinary lag, shrinking the set to 3. A
            // liveness knob must not silently change meaning when a performance
            // knob is turned. The window is now ~5 minutes of wall time,
            // converted to rounds using the SAME tick env the round ticker uses
            // (deterministic enough: per-node detection only feeds the
            // BFT-quorum downtime attestation, which is what actually jails).
            // Overridable directly via AINCORE_DOWNTIME_THRESHOLD_ROUNDS.
            let downtime_threshold: u64 = std::env::var("AINCORE_DOWNTIME_THRESHOLD_ROUNDS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v >= 10)
                .unwrap_or_else(|| {
                    let tick_ms = std::env::var("AINCORE_CONSENSUS_TICK_MS")
                        .ok()
                        .and_then(|v| v.parse::<u64>().ok())
                        .filter(|v| *v >= 100)
                        .unwrap_or(3_000);
                    (300_000 / tick_ms).max(100) // ~5 minutes of rounds, floor 100
                });

            // Record our participation
            let _ = self.storage.put(
                &format!("validator:last_seen:{}", self.node_id),
                &self.current_round.to_string(),
            );

            // Check all validators for downtime (only every 10 rounds to save CPU)
            if self.current_round.is_multiple_of(10) {
                for (validator_id, _stake) in &validators {
                    if validator_id == &self.node_id {
                        continue;
                    } // Skip self

                    let last_seen = match self
                        .storage
                        .get(&format!("validator:last_seen:{}", validator_id))
                    {
                        Ok(Some(r)) => r.parse::<u64>().unwrap_or(0),
                        _ => 0,
                    };

                    let rounds_missed = self.current_round.saturating_sub(last_seen);

                    if rounds_missed >= downtime_threshold && last_seen > 0 {
                        // Check if already jailed (prevent double-slash)
                        let jail_key = format!("validator:jailed:{}", validator_id);
                        if let Ok(Some(_)) = self.storage.get(&jail_key) {
                            continue; // Already jailed, skip
                        }

                        // === H-02 PROMOTED (Phase 2.3): BFT ATTESTATION, NOT UNILATERAL SLASH ===
                        //
                        // The pre-Phase-2 path wrote `sys:pending_slash:{addr}`
                        // directly from this single node's local observation.
                        // That meant any single validator could trigger a 5%
                        // slash + 21-day unbonding against any other validator,
                        // which is unsafe during network partitions (an
                        // isolated node sees everyone else as "down") and
                        // open to griefing (a Byzantine validator slashing
                        // honest peers).
                        //
                        // Phase 2.3 replaces the direct slash queue with an
                        // attestation: this node records *its own* downtime
                        // observation for (offender, epoch). The executor
                        // promotes the attestation set to a real pending
                        // slash only when distinct reporters reach BFT
                        // quorum.
                        //
                        // Without cross-validator gossip of attestations
                        // (Phase 3 work) only THIS node's attestations exist
                        // locally; BFT quorum cannot be reached and no
                        // downtime slash will fire. That is the intended
                        // safety stance until the gossip protocol lands —
                        // false positives stop NOW; real offenders are
                        // punished AFTER gossip is wired. Equivocation
                        // slashing (provable from local data) is unaffected
                        // and continues to apply.
                        const DOWNTIME_EPOCH_ROUNDS: u64 = 50;
                        let epoch = self.current_round / DOWNTIME_EPOCH_ROUNDS;

                        println!(
                            "🚨 DOWNTIME OBSERVED: Validator {} missed {} rounds (this node only)",
                            validator_id, rounds_missed
                        );
                        println!(
                            "⚖️  Recording BFT attestation for offender={}, epoch={}, reporter={}",
                            validator_id, epoch, self.node_id
                        );

                        // Attestation key: distinct per (offender, epoch, reporter)
                        // so the same node cannot inflate the count by
                        // re-attesting within the same epoch.
                        let attestation_key = format!(
                            "sys:downtime_attestation:{}:{}:{}",
                            validator_id, epoch, self.node_id
                        );
                        let attestation = serde_json::json!({
                            "offender": validator_id,
                            "epoch": epoch,
                            "reporter": self.node_id,
                            "round": self.current_round,
                            "rounds_missed": rounds_missed,
                        });

                        // Phase 3 / H-02: Broadcast to peers so they can add
                        // their own view and collectively reach BFT quorum.
                        self.broadcast_attestation(&attestation);

                        let _ = self.storage.put(&attestation_key, &attestation.to_string());

                        // Log the local observation in the audit trail. The
                        // executor will scan attestations and queue a real
                        // slash once BFT quorum is reached.
                        let _ = self.storage.put(
                            &format!("slash_event:{}", self.current_round),
                            &attestation.to_string(),
                        );
                    }
                }
            }

            // Advance round
            self.current_round += 1;
            println!(
                "⚡ Created Vertex {} (Round {}) [BLS Signed]",
                vertex.hash, vertex.round
            );
        } else {
            // === BOOTSTRAP/PARTITION RECOVERY: RE-GOSSIP RECENT VERTICES ===
            //
            // Vertices are normally broadcast exactly once, at creation
            // (above). On a multi-machine bootstrap a validator that was not
            // yet connected — or whose peer_ip was not yet persisted, so the
            // TCP fallback fell back to loopback — permanently misses that
            // one-shot delivery. With a strict >2/3 stake quorum a small
            // validator set (n=3 needs ALL three vertices per round) then
            // deadlocks below parent quorum forever: no quorum → no new
            // vertex → no new broadcast → no quorum. This is the
            // multi-machine bootstrap deadlock noted in add_vertex's
            // fast-forward comment; localhost never hits it because the
            // loopback default address is actually correct there.
            //
            // Recovery: while stuck below parent quorum, re-gossip every
            // vertex we hold from the recent round window — including peers'
            // vertices, so delivery becomes transitive (A can relay B's
            // vertex to C). By the time this fires, peer_ip entries are
            // persisted and the TCP fallback reaches real LAN addresses.
            // Duplicates are safe: add_vertex drops same-hash vertices
            // before the equivocation check, so re-sending our own signed
            // vertex can never read as a double-sign.
            //
            // Bounded: fires once per consensus tick and only while stuck;
            // window is 4 rounds × n authors, trivially under the LiDAR
            // per-peer rate limit for any realistic validator set.
            let resend: Vec<Vertex> = {
                let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");
                let min_round = self.current_round.saturating_sub(3);
                dag.values()
                    .filter(|v| v.round >= min_round)
                    .cloned()
                    .collect()
            }; // DAG lock dropped before broadcasting.
            if !resend.is_empty() {
                println!(
                    "🔁 [Consensus] Parent quorum not met at round {}; re-gossiping {} recent vertices (bootstrap/partition recovery)",
                    self.current_round,
                    resend.len()
                );
                for v in &resend {
                    self.broadcast_vertex(v);
                }
            }
        }
    }

    /// Phase 5B.2 + 5C.2 — round-bound limits:
    ///
    /// * `ABSOLUTE_ROUND_CEILING` is the hard upper bound on any vertex
    ///   round. Set well below `u64::MAX` so `current_round += 1` and
    ///   `vertex.round + 1` never wrap. Practically unreachable: at one
    ///   block per second a chain would need ~300 quadrillion years to
    ///   approach this. Defends PWN-002 anti-overflow attack.
    ///
    /// * `MAX_ROUND_JUMP` is the soft cap on a single-vertex round jump
    ///   from the node's CURRENT view. Phase 5B.2 set this to 50, which
    ///   the Phase 5C.2 re-audit revealed wedges legitimate long-partition
    ///   recovery: a node offline for >50 rounds rejects every catch-up
    ///   vertex and never re-syncs via P2P. Raised to 10_000 (~hours of
    ///   downtime on a 1-block-per-second chain). Still rejects the
    ///   "jump to u64::MAX" griefing attack because that lands above
    ///   ABSOLUTE_ROUND_CEILING anyway.
    const ABSOLUTE_ROUND_CEILING: u64 = u64::MAX / 2;
    const MAX_ROUND_JUMP: u64 = 10_000;

    pub fn add_vertex(&mut self, vertex: Vertex) {
        // Anti-overflow: any vertex above ABSOLUTE_ROUND_CEILING is malicious
        // — the chain cannot legitimately reach this magnitude.
        if vertex.round > Self::ABSOLUTE_ROUND_CEILING {
            println!(
                "🚨 REJECTED [PWN-002/abs]: vertex round {} exceeds absolute ceiling {}",
                vertex.round,
                Self::ABSOLUTE_ROUND_CEILING
            );
            return;
        }

        // Anti-grief: reject "one giant jump" that an attacker could use to
        // fast-forward `current_round` past honest progress. Legitimate
        // catch-up is a STREAM of vertices, not one big-round vertex.
        if vertex.round > self.current_round.saturating_add(Self::MAX_ROUND_JUMP) {
            println!(
                "🚨 REJECTED [PWN-002/jump]: vertex round {} exceeds local round {} + {} cap",
                vertex.round,
                self.current_round,
                Self::MAX_ROUND_JUMP
            );
            return;
        }

        // PWN-003: bound vertex timestamp drift. The timestamp is folded into the
        // signed vertex hash but its VALUE was never range-checked. Reject vertices
        // dated too far in the future (clock-skew abuse / hash-grinding surface).
        // Future-bound ONLY — a past/monotonic bound would reject legitimately
        // delayed honest vertices and harm liveness.
        {
            const MAX_FUTURE_DRIFT_SECS: u64 = 30;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            if vertex.timestamp > now.saturating_add(MAX_FUTURE_DRIFT_SECS) {
                println!(
                    "🚨 REJECTED [PWN-003/ts]: vertex timestamp {} exceeds now {} + {}s drift",
                    vertex.timestamp, now, MAX_FUTURE_DRIFT_SECS
                );
                return;
            }
        }

        // C-10 FIX (#35): Resolve the FULL Ed25519 public key from the account object in storage.
        // vertex.author is the 32-byte AINCORE address (64 hex chars) = hex(SHA256(pubkey)), but
        // Ed25519 verification requires the full 32-byte public key (also 64 hex chars). The
        // address cannot be expanded back into a key, so it is looked up and verified to derive
        // the claimed author.
        let author_pubkey_hex = match self.resolve_author_pubkey(&vertex.author) {
            Some(pk) => pk,
            None => return,
        };

        if !vertex.verify_ed25519_signature(&author_pubkey_hex) {
            println!(
                "🚨 REJECTED: Invalid Ed25519 signature from author {}",
                vertex.author
            );
            return;
        }

        // Phase 5B.1 / PWN-001 CRITICAL: vertex.hash MUST equal a fresh
        // calculate_hash(). Without this check, the signature only binds
        // the attacker-controlled `hash` field to the author, NOT to the
        // vertex body — letting one malicious validator emit two vertices
        // with the same hash + signature but different `payload` / `parents`
        // / `timestamp`, splitting state across honest peers.
        let recomputed = vertex.calculate_hash();
        if recomputed != vertex.hash {
            println!(
                "🚨 REJECTED [PWN-001]: vertex.hash {} does not match \
                 recomputed hash {} — body tampered after signing",
                vertex.hash, recomputed
            );
            return;
        }

        // C-2 FIX: Cross-check against the active ValidatorSet.
        // AUDIT-B3: fetch the STAKE-weighted set once, here, before any lock is
        // taken — the quorum-gated round advance below needs stake weights, and
        // it runs while the DAG/round-index guards are held, so it cannot call
        // back into &self at that point.
        let validators_with_stake = self.get_validator_set_with_stake();
        let validators: Vec<String> = validators_with_stake
            .iter()
            .map(|(a, _)| a.clone())
            .collect();
        if !validators.contains(&vertex.author) && self.current_round > 0 {
            println!(
                "🚨 REJECTED: Vertex author {} is not in the active validator set",
                vertex.author
            );
            return;
        }

        // 1. Scope for DAG and RoundIndex modification
        {
            let mut dag = self.dag.lock().expect(
                "🚨 FATAL: DAG lock poisoned - consensus integrity compromised. Node must restart.",
            );
            println!(
                "DEBUG: add_vertex: Hash='{}', Round={}",
                vertex.hash, vertex.round
            );
            if dag.contains_key(&vertex.hash) {
                println!("DEBUG: add_vertex: Duplicate hash! Skipping.");
                return;
            }

            // Persist to DB
            if let Ok(v_json) = serde_json::to_string(&vertex) {
                if let Err(e) = self
                    .storage
                    .put(&format!("vertex:{}", vertex.hash), &v_json)
                {
                    println!("❌ Failed to persist DAG vertex: {}", e);
                }
            }

            // === SLASHING DETECTION (Double-Sign) ===
            let mut round_idx = self.round_index.lock()
                .expect("🚨 FATAL: Round index lock poisoned - consensus integrity compromised. Node must restart.");
            if let Some(hashes) = round_idx.get(&vertex.round) {
                for existing_hash in hashes {
                    if let Some(v_exist) = dag.get(existing_hash) {
                        // Same Author, Same Round, Different Hash => EQUIVOCATION!
                        if v_exist.author == vertex.author && existing_hash != &vertex.hash {
                            println!("🚨🚨 CRITICAL SLASHING ALERT 🚨🚨");
                            println!("⚔️  MALICIOUS BEHAVIOR DETECTED (Equivocation/Double-Sign)");
                            println!("   Offender: {}", vertex.author);
                            println!("   Round: {}", vertex.round);
                            println!("   Proof A: {}", existing_hash);
                            println!("   Proof B: {}", vertex.hash);
                            println!("🔥 SLASHING STAKE OF {}", vertex.author);

                            // SEC-#9/#10: route the slash through the shared
                            // `apply_equivocation_slash` (idempotent + durable evidence) and
                            // gossip the self-authenticating proof so every honest node
                            // independently verifies and slashes — instead of slashing only
                            // on whichever node happened to receive both conflicting vertices.
                            // `proof_a` = the already-stored vertex, `proof_b` = the incoming
                            // conflicting one (preserves the prior event field order).
                            let proof_a = v_exist.clone();
                            let proof_b = vertex.clone();
                            self.apply_equivocation_slash(&proof_a, &proof_b);
                            self.broadcast_equivocation_proof(&proof_a, &proof_b);
                            return;
                        }
                    }
                }
            }

            dag.insert(vertex.hash.clone(), vertex.clone());
            round_idx
                .entry(vertex.round)
                .or_default()
                .push(vertex.hash.clone());
            println!(
                "📥 Added Vertex to DAG: {} (Round {})",
                vertex.hash, vertex.round
            );

            // C-04 FIX: Record peer activity to prevent false-positive downtime slashes
            if vertex.author != self.node_id {
                let current_last_seen = match self
                    .storage
                    .get(&format!("validator:last_seen:{}", vertex.author))
                {
                    Ok(Some(r)) => r.parse::<u64>().unwrap_or(0),
                    _ => 0,
                };
                if vertex.round > current_last_seen {
                    let _ = self.storage.put(
                        &format!("validator:last_seen:{}", vertex.author),
                        &vertex.round.to_string(),
                    );
                }
            }

            // Fast-forward local round to match the network (Amnesia Recovery),
            // ONLY for remote vertices — try_create_vertex already increments for
            // local ones.
            //
            // AUDIT-B3: this used to be `self.current_round = vertex.round + 1`,
            // driven by a SINGLE remote vertex. That is a permanent chain wedge and
            // it needs no Byzantine intent — a validator whose ticker runs slightly
            // fast emits a vertex one round ahead, every node adopts round+1, and
            // then `try_create_vertex` looks for parents at `current_round - 1`,
            // a round that holds only that one vertex and can therefore NEVER reach
            // the stake-weighted parent quorum. Block production stops network-wide,
            // and because the value was persisted as `latest_proposed_round` it
            // survived restarts.
            //
            // Narwhal's actual rule: a node advances to round r+1 only once it holds
            // a stake quorum of round-r vertices. So we advance to
            // `quorum_round + 1` — the highest round we can genuinely build parents
            // for — and never to an arbitrary round some peer claims. A vertex far
            // ahead is still stored and still counts toward its own round's quorum;
            // it just cannot drag our proposal clock past what the DAG supports.
            if vertex.author != self.node_id && vertex.round > self.current_round {
                let target =
                    Self::quorum_round(&round_idx, &dag, &validators_with_stake).saturating_add(1);
                if target > self.current_round {
                    self.current_round = target;
                    let _ = self
                        .storage
                        .put("latest_proposed_round", &self.current_round.to_string());
                }
            }
        } // Locks dropped here!

        // Observer nodes may ingest and persist validator vertices so chain
        // sync has visibility into the live network, but only active
        // validators are allowed to run local ordering and commit blocks.
        // Without this guard a non-validator observer can manufacture a
        // private fork from incoming DAG traffic, then later fail sequential
        // sync with parent-hash mismatches.
        if !validators.contains(&self.node_id) {
            if self.current_round.is_multiple_of(10) {
                println!(
                    "⚠️  [Consensus] Observer Mode: skipping local ordering/commit at round {}",
                    self.current_round
                );
            }
            return;
        }

        // --- ORDERING LOGIC (Bullshark-lite) ---
        // Now we can take new locks without holding the previous ones.

        // We need read access to DAG and RoundIndex for ordering check, BUT we don't need write.
        // And we definitly don't want to hold them during execution.

        let committed_result = {
            let mut engine = self
                .ordering_engine
                .lock()
                .expect("🚨 FATAL: Ordering engine lock poisoned");
            let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");
            let round_idx = self
                .round_index
                .lock()
                .expect("🚨 FATAL: Round index lock poisoned");
            // B4: stake-aware set so the commit-side quorum is stake-weighted.
            // Belt-and-braces with reload_chain_tip above: never decide an anchor
            // from a validator set that a synced block may have just changed.
            self.invalidate_validators_cache();
            let validators = self.get_validator_set_with_stake();

            engine.try_commit(vertex.round, &dag, &round_idx, &validators)
        }; // All locks dropped here!

        // AUDIT-B4b: try_commit now returns the anchors decided since the last
        // call, in deterministic round order — ONE block per anchor, on every
        // node identically. Iterating (instead of the old single-Option) is what
        // aligns the height<->anchor mapping across nodes.
        for commit in committed_result {
            // AUDIT-B4b (dedup): if the chain tip already covers this anchor, a
            // ChainSync import beat the local commit to it — the peer's block for
            // this anchor is ALREADY on our chain, fully executed and state-root
            // verified by the sync path. Building it again here would put the
            // same anchor at two heights and shift this node's numbering off the
            // network's forever. The ordering-engine bookkeeping (cursor, digest,
            // committed-set) already happened inside try_commit and must happen;
            // only the duplicate block build is skipped.
            if commit.anchor_round <= self.latest_block_round {
                println!(
                    "⏭️  Anchor round {} already on chain via sync (tip round {}) — skipping duplicate block",
                    commit.anchor_round, self.latest_block_round
                );
                continue;
            }
            println!(
                "⛓️  Consensus Reached! Anchor round {}: executing {} vertices...",
                commit.anchor_round,
                commit.sequence.len()
            );

            // Clone the Arc so the borrow of `self.executor` ends here: the
            // anchor-placement retry below needs `&mut self` for reload_chain_tip.
            let executor = std::sync::Arc::clone(&self.executor);
            let mut block_txs = Vec::new();
            let reward_recipient = commit.leader.clone(); // C-10 FIX: Reward the anchor leader deterministically

            // Re-acquire DAG read lock just to fetch payloads
            // We can optimize this by cloning necessary data in the previous block,
            // but identifying which vertices are committed before engine runs is hard.
            // So we just re-acquire efficiently.
            // AUDIT-H1: collect the committed vertices' AUTHOR-SIGNED timestamps so
            // the block timestamp can be derived deterministically (BFT-Time) rather
            // than read from this node's wall clock. Vertex timestamps are inside
            // Vertex::calculate_hash and signed, so every node sees identical values.
            let stake_by_addr: std::collections::HashMap<String, u64> =
                self.get_validator_set_with_stake().into_iter().collect();
            let mut ts_samples: Vec<(String, u64, u64)> = Vec::new();

            let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");

            for hash in &commit.sequence {
                if let Some(v) = dag.get(hash) {
                    // Clone payload to release DAG lock faster?
                    // No, looking up payload is fast. Execution is slow.
                    // But we must NOT hold DAG lock during execution.
                    // So we collect ALL txs first.
                    block_txs.extend(v.payload.clone());
                    if let Some(stake) = stake_by_addr.get(&v.author) {
                        ts_samples.push((v.author.clone(), *stake, v.timestamp));
                    }
                } else {
                    // A committed vertex MUST be present: the sequence was computed
                    // from this DAG moments ago. If it is gone, something pruned it
                    // mid-batch and this block's content is about to diverge from
                    // every other node's. Never silent.
                    eprintln!(
                        "🚨 [SECURITY][COMMIT_VERTEX_MISSING] anchor round {} sequence hash {} \
                         is not in the DAG at block-build time — block content will diverge",
                        commit.anchor_round, hash
                    );
                }
            }
            drop(dag); // DROP DAG LOCK NOW!

            // BFT-TIME DETERMINISM (burn-in finding, h=121): the monotonic clamp
            // must use the CANONICAL parent's timestamp — the stored block at the
            // current tip — never the in-memory field. That field was kept as a
            // running max() across sync reloads, so a node that had built a local
            // block later superseded by the synced chain carried a stale-high value
            // into its next clamp and produced a header one second off from every
            // other node (same vertices, same state, different hash).
            let parent_ts = self
                .storage
                .get(&format!("block_{}", self.latest_block_height))
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
                .map(|b| b.header.timestamp)
                .unwrap_or(self.latest_block_timestamp);
            let block_timestamp = blockchain::bft_block_timestamp(ts_samples, parent_ts);

            // NOW EXECUTE (Lock Free!)
            // We execute even if empty to trigger Block Rewards (Heartbeat Mining)
            {
                println!(
                    "🚀 Executing Parallel Batch of {} transactions",
                    block_txs.len()
                );

                // Use Executor parallel logic directly?
                // The existing logic was: analyze deps -> schedule -> execute.
                // We can use executor.execute_block_parallel(block_txs).
                // RE-AUDIT HIGH: slash evidence is gathered by the PROPOSER from its
                // local view and carried by the block; every node verifies it
                // independently before applying (executor::apply_slash_evidence).
                let slash_evidence = executor.collect_slash_evidence();
                // ANCHOR PLACEMENT (burn-in fix): every committed anchor must get
                // EXACTLY ONE block, and "already done" is decided by ANCHOR ROUND,
                // never by height. The first cut skipped on height alone, and the
                // live log shows what that cost: three distinct anchors (12220,
                // 12224, 12226) were all skipped against the SAME height 5073
                // because reload_chain_tip had not yet seen sync's writes. Anchor
                // 12226 therefore never got a block on that node while its peers
                // placed it at 5075 — the node's anchor->height mapping was off by
                // one from then on and it hard-forked (23,936 parent-hash
                // rejections). Retry against the refreshed tip; only treat it as a
                // duplicate when the chain genuinely already carries this anchor.
                let mut placed: Option<executor::BlockExecutionSummary> = None;
                let mut already_on_chain = false;
                for _attempt in 0..4 {
                    match executor.execute_block_parallel_at(
                        block_txs.clone(),
                        &reward_recipient,
                        // The block being BUILT: one above the current tip.
                        self.latest_block_height + 1,
                        &slash_evidence,
                    ) {
                        executor::BlockExecOutcome::Executed(summary) => {
                            placed = Some(summary);
                            break;
                        }
                        executor::BlockExecOutcome::AlreadyExecuted { last_executed } => {
                            self.reload_chain_tip();
                            if commit.anchor_round <= self.latest_block_round {
                                println!(
                                    "⏭️  Anchor round {} already on chain via sync (tip round {}, last_executed={})",
                                    commit.anchor_round, self.latest_block_round, last_executed
                                );
                                already_on_chain = true;
                                break;
                            }
                            // Height was taken by a DIFFERENT anchor's block: our
                            // anchor still needs one. Retry at the refreshed tip.
                        }
                        executor::BlockExecOutcome::Gap { expected, got } => {
                            eprintln!(
                                "⏸️  Anchor round {}: execution gap (expected height {}, wanted {}) — refreshing tip",
                                commit.anchor_round, expected, got
                            );
                            self.reload_chain_tip();
                            if commit.anchor_round <= self.latest_block_round {
                                already_on_chain = true;
                                break;
                            }
                        }
                    }
                }
                if already_on_chain {
                    continue;
                }
                let Some(execution_summary) = placed else {
                    // The anchor could not be placed. It is committed in the
                    // ordering engine but has no block, so this node's
                    // anchor->height mapping is about to diverge from the
                    // network's. Never silent: this alarm is what turns a
                    // multi-hour undetected fork into an immediate signal.
                    eprintln!(
                        "🚨 [SECURITY][ANCHOR_DROPPED] anchor round {} committed but no block could be \
                         placed (tip height {}, tip round {}) — this node will diverge",
                        commit.anchor_round, self.latest_block_height, self.latest_block_round
                    );
                    continue;
                };
                // Orphan-loss fix: settle the mempool's loan ledger — only the
                // transactions that actually EXECUTED leave it; the rest stay
                // inflight and requeue_stale() returns them to pending later.
                if let Ok(mut mp) = self.mempool.lock() {
                    mp.mark_executed(&execution_summary.executed_raws);
                }

                // QC Phase 2: capture the executed roots before they are moved
                // into the Block (used to build the FinalityVote below).
                let qc_state_root = execution_summary.state_root.clone();
                let qc_receipts_root = execution_summary.receipts_root.clone();

                // Create Block (Post-Execution)
                use blockchain::Block;
                self.latest_block_height += 1;
                // AUDIT-H1: new_with_roots_at, NOT new_with_roots — the latter reads
                // the local clock, which made every node derive a different header
                // hash for identical content and chained that divergence forward
                // through prev_hash.
                let new_block = Block::new_with_roots_at(
                    self.latest_block_height,
                    // AUDIT-B4b: the block's round is the ANCHOR round — a pure
                    // function of the commit sequence. It was `vertex.round`, the
                    // round of whichever vertex happened to trigger this commit
                    // locally, which differed per node (the live fork showed
                    // height 50 built from round 52 on one node and 53 on
                    // another) and poisoned the header hash.
                    commit.anchor_round,
                    self.latest_block_hash.clone(),
                    block_txs.clone(), // This duplicates data, effectively block contains processed txs
                    reward_recipient.clone(),
                    execution_summary.state_root,
                    execution_summary.receipts_root,
                    block_timestamp,
                    // LIVENESS: the block carries the committed vertex sequence
                    // so a follower can adopt this anchor into its own ordering
                    // engine in exact parity (see OrderingEngine::adopt_synced_anchor).
                    commit.sequence.clone(),
                    commit.anchor_hash.clone(),
                    slash_evidence,
                );
                // RE-AUDIT CRITICAL: authenticate the block to its proposer so
                // followers only ever adopt/vote for validator-produced blocks.
                let mut new_block = new_block;
                new_block.sign_proposer(&crypto::SigningKey::from_bytes(&self.node_key), &self.node_id);
                self.latest_block_hash = new_block.header.hash.clone();
                self.latest_block_timestamp = new_block.header.timestamp;
                self.latest_block_round = commit.anchor_round;
                self.last_adopted_height = self.latest_block_height;
                // RE-AUDIT MEDIUM: persist the adoption cursor so a crash between
                // sync persisting a block and its adoption cannot skip it at boot.
                let _ = self.storage.put(
                    "consensus:last_adopted_height",
                    &self.last_adopted_height.to_string(),
                );

                // Update Accumulator and DB
                if let Ok(bytes) = hex::decode(&new_block.header.hash) {
                    self.accumulator.append(&bytes);
                }

                if let Ok(block_json) = serde_json::to_string(&new_block) {
                    // H-07 FIX: route through save_block_json so block,
                    // latest_height, latest_block_hash, and the per-tx
                    // index are all written in a single atomic batch.
                    // Previously these were three separate put() calls,
                    // which (a) was not crash-safe — a sync between
                    // height and hash updates could leave the chain
                    // pointing at the wrong block — and (b) skipped the
                    // tx index entirely, forcing aincore_getTransaction
                    // to scan the whole DAG under lock.
                    if let Err(e) = self
                        .storage
                        .save_block_json(self.latest_block_height, &block_json)
                    {
                        eprintln!(
                            "❌ Failed to persist block #{}: {}",
                            self.latest_block_height, e
                        );
                    }
                    if let Some((keep_blocks, max_delete)) =
                        storage::StateDB::block_pruning_policy_from_env()
                    {
                        match self.storage.prune_old_blocks(
                            self.latest_block_height,
                            keep_blocks,
                            max_delete,
                        ) {
                            Ok(deleted) if deleted > 0 => {
                                println!(
                                    "🧹 Block history pruning: removed {} old blocks (retain={}, batch={})",
                                    deleted, keep_blocks, max_delete
                                );
                            }
                            Ok(_) => {}
                            Err(e) => eprintln!("⚠️ Block history pruning failed: {}", e),
                        }
                    }
                    // Phase 2.8 (M-08): block commit is the only moment
                    // where a slash could have changed the validator set
                    // during normal operation, so refresh the cache here.
                    self.invalidate_validators_cache();
                    println!(
                        "📦 Created Block #{} (Hash: {:.8})",
                        self.latest_block_height, self.latest_block_hash
                    );

                    // === DA SEQUENCER INTEGRATION ===
                    // L1 FIX: Wire DA verification into consensus finality
                    if let Some(da_seq) = &self.da_sequencer {
                        if let Ok(mut seq) = da_seq.lock() {
                            println!("🧩 [Consensus] Triggering DA Batch with erasure coding verification...");
                            seq.create_batch(self.latest_block_hash.clone(), block_txs.len());
                            // DA batch includes: erasure coding, Merkle proof generation,
                            // shard distribution to peers, and fraud proof readiness.
                            // Light clients can now verify data availability via DAS sampling.
                            println!(
                                "✅ [DA] Block #{} data availability confirmed",
                                self.latest_block_height
                            );
                        }
                    }

                    // === QC PHASE 2: quorum-certificate production ===
                    // ADDITIVE & SIDE-EFFECT-ONLY: this contributes THIS node's
                    // BLS signature over the committed block and, when this node's
                    // stake alone meets the strict >2/3 quorum (the live
                    // single-validator / supermajority topology), stores a
                    // complete, externally-verifiable quorum certificate. It is
                    // NOT a precondition for commit — any failure just skips the
                    // attestation; consensus is unaffected. Multi-party vote
                    // aggregation is Phase 3.
                    {
                        let epoch = self
                            .storage
                            .get("consensus:epoch")
                            .ok()
                            .flatten()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(0);
                        let ctx = crate::qc_producer::CommitContext {
                            chain_id: self.resolve_chain_id(),
                            epoch,
                            finalized_round: commit.anchor_round,
                            anchor_round: commit.anchor_round,
                            anchor_hash: commit.anchor_hash.clone(),
                            block_height: self.latest_block_height,
                            block_hash: self.latest_block_hash.clone(),
                            state_root: qc_state_root.clone(),
                            receipts_root: qc_receipts_root.clone(),
                            finality_digest: commit.finality_digest.clone(),
                        };
                        // Phase 3: if this node alone cannot finalize, broadcast
                        // its partial finality vote so peers can aggregate a
                        // multi-party QC. Side-effect-only; a send failure just
                        // skips the gossip and consensus is unaffected.
                        match crate::qc_producer::produce_and_store_qc(
                            &self.storage,
                            &self.node_key,
                            &self.node_id,
                            &ctx,
                        ) {
                            crate::qc_producer::QcOutcome::Partial(vote_msg) => {
                                self.broadcast_qc_vote(&vote_msg);
                            }
                            crate::qc_producer::QcOutcome::Complete(_)
                            | crate::qc_producer::QcOutcome::Skipped => {}
                        }

                        // SEC-#12 Step-2: fold the COMPLETE QC's aggregate BLS
                        // signature into the leader-election beacon for true
                        // unbiasability. This runs ONLY when a complete (>2/3) QC
                        // exists at consensus:qc:{height} — i.e. the single-
                        // validator / supermajority case where produce_and_store_qc
                        // just stored one. In the multi-party case no complete QC
                        // exists here yet, so this is a no-op and the fold happens
                        // later from handle_remote_qc_vote when aggregation
                        // completes. Step-1's digest-bound beacon (set in
                        // try_commit) is the base in both cases. Side-effect-only,
                        // additive: a missing QC never alters consensus.
                        if let Ok(mut engine) = self.ordering_engine.lock() {
                            engine.fold_qc_for_height(self.latest_block_height);
                        }
                    }
                }
            }

            // Garbage Collection (Pruning)
            // We can do this in background or here.
            // Since we dropped locks, it's safe to call prune_dag (which takes locks).
            // Logic for max frame...
            // We need to know max round of committed hashes.
            // We lost reference to 'dag' map, but we have hashes.
            // We can't look up round without DAG lock.
            // Let's Skip intricate pruning update for this hotfix.
            // Or re-acquire lock.
            if !commit.sequence.is_empty() {
                // H-5 FIX: Prune only FINALIZED rounds (check ordering engine)
                // M3 FIX: Derive the prune watermark from the MONOTONIC finality
                // high-water mark, not committed_rounds.iter().min(). The old
                // min() was permanently pinned to the earliest committed round,
                // so the watermark never advanced and pruning was a no-op
                // (unbounded DAG growth). The high-water mark advances every
                // commit, so the watermark now tracks finality forward.
                if self.latest_block_height.is_multiple_of(10) && self.current_round > 50 {
                    let finalized_round = {
                        if let Ok(engine) = self.ordering_engine.lock() {
                            engine.finalized_round
                        } else {
                            0 // Don't prune if we can't verify finality
                        }
                    };
                    // CATCH-UP FORK FIX: one try_commit call can yield MANY anchors
                    // (a node catching up after a restart commits dozens at once).
                    // The engine's finalized_round then already points at the LAST
                    // anchor of the batch while this loop is still building blocks
                    // for the earlier ones — pruning off finalized_round here
                    // deleted vertices those later-built blocks still needed, so
                    // `dag.get(hash)` silently returned None for them: fewer
                    // BFT-time samples (a header that differed from every other
                    // node by a few seconds — the live PI-only fork) and, under
                    // load, DROPPED TRANSACTIONS. The horizon is therefore bounded
                    // by the round of the block just BUILT, which is always the
                    // lowest round still being assembled.
                    let horizon = finalized_round.min(self.latest_block_round);
                    if horizon > 10 {
                        self.prune_dag(horizon - 10);
                    }
                }

                // CHECKPOINT SAVE: Save checkpoint every 100 rounds for fast
                // recovery. Phase 2.5 (H-06): we now sign the checkpoint JSON
                // with the node's Ed25519 key and route through
                // `save_dag_checkpoint_signed` so the boot-time loader can
                // detect tampering. A node booting against a checkpoint that
                // doesn't verify against its OWN key will refuse to fast-
                // recover from it and fall back to a full scan replay.
                if self.current_round.is_multiple_of(100) {
                    if let Ok(dag) = self.dag.lock() {
                        // Phase 5B.10 / L-04: HashMap::values() yields
                        // vertices in non-deterministic order, so two nodes
                        // with identical state produced byte-different
                        // checkpoint blobs (signature still verifies, but
                        // checkpoints were not byte-reproducible across
                        // peers / restarts). Sort by vertex hash to make
                        // the on-disk representation canonical.
                        let mut vertices: Vec<&Vertex> = dag.values().collect();
                        vertices.sort_by(|a, b| a.hash.cmp(&b.hash));
                        if let Ok(json) = serde_json::to_string(&vertices) {
                            let signing_key = crypto::SigningKey::from_bytes(&self.node_key);
                            use crypto::Signer;
                            let sig = signing_key.sign(json.as_bytes());
                            let sig_hex = hex::encode(sig.to_bytes());

                            if let Err(e) = self.storage.save_dag_checkpoint_signed(
                                self.current_round,
                                &json,
                                &sig_hex,
                            ) {
                                eprintln!("⚠️ Failed to save signed checkpoint: {}", e);
                            } else {
                                println!(
                                    "💾 Signed checkpoint saved at Round {} ({}B sig)",
                                    self.current_round,
                                    sig_hex.len() / 2
                                );
                                // Prune old checkpoints (keep last 5)
                                let _ = self.storage.prune_old_checkpoints(self.current_round, 500);
                            }
                        }
                    }
                }
            }
        }
    }

    fn resolve_chain_id(&self) -> String {
        if let Ok(Some(chain_id)) = self.storage.get("sys:chain_id") {
            if !chain_id.trim().is_empty() {
                return chain_id;
            }
        }
        if let Ok(chain_id) = std::env::var("AINCORE_CHAIN_ID") {
            if !chain_id.trim().is_empty() {
                return chain_id;
            }
        }
        if let Ok(path) = std::env::var("AINCORE_GENESIS_PATH") {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&contents) {
                    if let Some(chain_id) = json.get("chain_id").and_then(|v| v.as_str()) {
                        if !chain_id.trim().is_empty() {
                            return chain_id.to_string();
                        }
                    }
                }
            }
        }
        "AINCORE-MAINNET-1".to_string()
    }

    fn broadcast_vertex(&self, vertex: &Vertex) {
        let serialized = match serde_json::to_string(vertex) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ Failed to serialize vertex: {}", e);
                return;
            }
        };
        let msg = format!("DAG_VERTEX:{}", serialized);

        // 1. Broadccast via Libp2p Gossipsub (Preferred Method)
        if let Some(tx) = &self.p2p_tx {
            let msg_clone = msg.clone();
            let tx_clone = tx.clone();
            // Important: Use spawn because Sender::send is async
            tokio::spawn(async move {
                let _ = tx_clone.send(msg_clone).await;
            });
        }

        // 2. Broadcast via Legacy TCP (Fallback/Syncing Nodes without Libp2p connected)
        use network::send_message;
        if let Ok(peers) = self.peers.lock() {
            for (peer_id, port) in peers.iter() {
                // FIXED: Resolve valid IP from storage instead of hardcoded localhost
                let ip = self
                    .storage
                    .get_peer_ip(peer_id)
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let addr = format!("{}:{}", ip, port);

                // Don't send to self (redundant check but safe)
                if *peer_id != self.node_id {
                    let _ = send_message(&addr, &msg);
                }
            }
        }
    }

    /// Phase 3 / H-02: Broadcast a downtime attestation to all peers via
    /// Gossipsub + TCP so that BFT quorum can be reached across the validator
    /// set.  The attestation JSON is signed with this node's Ed25519 key;
    /// the reporter's raw public-key bytes are embedded so receivers can
    /// independently verify authenticity without a PKI lookup.
    fn broadcast_attestation(&self, attestation: &serde_json::Value) {
        use crypto::Signer;
        // Build the canonical payload that will be signed:
        // strip "signature" + "reporter_pubkey" fields first, then sign.
        let signing_key = crypto::SigningKey::from_bytes(&self.node_key);
        let verifying_key = signing_key.verifying_key();
        let pubkey_hex = hex::encode(verifying_key.to_bytes());

        // Canonical message = deterministic JSON with known fields only.
        let canonical = format!(
            "{}:{}:{}:{}",
            attestation["offender"].as_str().unwrap_or(""),
            attestation["epoch"],
            attestation["reporter"].as_str().unwrap_or(""),
            attestation["round"],
        );
        let sig_bytes = signing_key.sign(canonical.as_bytes());
        let sig_hex = hex::encode(sig_bytes.to_bytes());

        let mut full = attestation.clone();
        full["reporter_pubkey"] = serde_json::Value::String(pubkey_hex);
        full["signature"] = serde_json::Value::String(sig_hex);

        let serialized = match serde_json::to_string(&full) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ [H-02] Failed to serialise attestation: {}", e);
                return;
            }
        };
        let msg = format!("DOWNTIME_ATTEST:{}", serialized);

        // 1. Gossipsub
        if let Some(tx) = &self.p2p_tx {
            let tx_clone = tx.clone();
            let msg_clone = msg.clone();
            tokio::spawn(async move {
                let _ = tx_clone.send(msg_clone).await;
            });
        }

        // 2. TCP fallback
        use network::send_message;
        if let Ok(peers) = self.peers.lock() {
            for (peer_id, port) in peers.iter() {
                if *peer_id != self.node_id {
                    let ip = self
                        .storage
                        .get_peer_ip(peer_id)
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    let addr = format!("{}:{}", ip, port);
                    let _ = send_message(&addr, &msg);
                }
            }
        }
    }

    /// Resolve the FULL 64-hex Ed25519 public key for a vertex author.
    ///
    /// (C-10 / #35) `vertex.author` is the 32-byte AINCORE address (64 hex
    /// chars) = hex(SHA256(pubkey)). Ed25519 verification needs the full 32-byte
    /// public key (also 64 hex chars), so we resolve it from the account object
    /// in storage and confirm it actually derives the claimed author via
    /// `crypto::derive_address` — never via a hex-length heuristic, since address
    /// and pubkey are now the same width. Returns `None` (with a diagnostic) when
    /// the key cannot be resolved or does not derive the author. Shared by
    /// `add_vertex` and equivocation-proof verification.
    fn resolve_author_pubkey(&self, author: &str) -> Option<String> {
        if let Some(account_obj) = self.storage.get_object(author) {
            if let Ok(account_data) =
                serde_json::from_slice::<serde_json::Value>(&account_obj.data)
            {
                if let Some(pk) = account_data.get("public_key").and_then(|v| v.as_str()) {
                    // A valid Ed25519 public key is exactly 32 bytes (64 hex).
                    // Resolution succeeds ONLY when the stored key derives the
                    // claimed author address; an explicit derive-and-compare,
                    // not a length test on `author`.
                    let resolved = hex::decode(pk)
                        .ok()
                        .filter(|bytes| bytes.len() == 32)
                        .and_then(|bytes| crypto::derive_address(&bytes).ok())
                        .map(|addr| addr == author)
                        .unwrap_or(false);
                    if resolved {
                        Some(pk.to_string())
                    } else {
                        println!(
                            "🚨 REJECTED: Stored public key does not derive author {}",
                            author
                        );
                        None
                    }
                } else {
                    println!("🚨 REJECTED: Account object for {} has no public_key", author);
                    None
                }
            } else {
                println!("🚨 REJECTED: Account object for {} is not valid JSON", author);
                None
            }
        } else if author == self.node_id {
            let signing_key = crypto::SigningKey::from_bytes(&self.node_key);
            let public_key = signing_key.verifying_key();
            match crypto::derive_address(public_key.as_bytes()) {
                Ok(addr) if addr == author => Some(hex::encode(public_key.as_bytes())),
                _ => {
                    println!("🚨 REJECTED: Local node key does not derive author {}", author);
                    None
                }
            }
        } else {
            println!("🚨 REJECTED: No public key available for vertex author {}", author);
            None
        }
    }

    /// SEC-#9: independently verify a self-authenticating equivocation proof.
    ///
    /// Returns `Some(offender)` only if BOTH vertices are signed by the same
    /// author over the same round with distinct, body-bound hashes, and the
    /// offender is a current validator. A forged proof cannot pass: producing
    /// two distinct valid signatures over two distinct bodies at one round
    /// requires the offender's own secret key.
    fn verify_equivocation_proof(&self, a: &Vertex, b: &Vertex) -> Option<String> {
        // 1. same author, same round, genuinely conflicting.
        if a.author != b.author || a.round != b.round || a.hash == b.hash {
            return None;
        }
        // 2. each hash must bind its body (PWN-001) — stops pairing a real
        //    vertex with a body-tampered twin.
        if a.hash != a.calculate_hash() || b.hash != b.calculate_hash() {
            return None;
        }
        // 3. resolve the offender's full pubkey and verify BOTH signatures.
        let pubkey_hex = self.resolve_author_pubkey(&a.author)?;
        if !a.verify_ed25519_signature(&pubkey_hex) || !b.verify_ed25519_signature(&pubkey_hex) {
            return None;
        }
        // 4. offender must be a current validator (SEC-N03: no slashing /
        //    storage growth against arbitrary non-validators).
        if !self.get_validator_set().contains(&a.author) {
            return None;
        }
        Some(a.author.clone())
    }

    /// SEC-#9/#10: idempotent, deterministic single-apply of an equivocation
    /// slash. Both the local detector and inbound gossip funnel through here.
    /// The first writer latches the dedup/evidence key; later duplicates (same
    /// offender+round, whether re-received or locally re-detected) short-circuit.
    fn apply_equivocation_slash(&self, proof_a: &Vertex, proof_b: &Vertex) {
        let offender = &proof_a.author;
        let round = proof_a.round;

        let seen_key = format!("sys:equiv_seen:{}:{}", offender, round);
        if matches!(self.storage.get(&seen_key), Ok(Some(_))) {
            return; // already handled — exactly-once.
        }

        // Durable, self-contained evidence (plain KV — never a `vertex:{hash}`
        // row, so DAG pruning cannot destroy it: closes #10).
        // CANONICAL ORDER (audit 2026-08-26): record the pair ordered by vertex
        // hash, never by arrival. Two nodes that both witness the same
        // equivocation otherwise store byte-different proofs — harmless while
        // the row is node-local, a fork the moment evidence is block-carried.
        let (first, second) = if proof_a.hash <= proof_b.hash {
            (proof_a, proof_b)
        } else {
            (proof_b, proof_a)
        };
        let evidence = serde_json::json!({
            "offender": offender,
            "round": round,
            "vertex_a": first,
            "vertex_b": second,
        });
        let _ = self.storage.put(&seen_key, &evidence.to_string());

        // Canonical slash event — byte-stable across nodes (no timestamps /
        // node-local fields) and matched by the executor's 100% equivocation path.
        let slash_event = serde_json::json!({
            "event": "equivocation_detected",
            "validator": offender,
            "round": round,
            "proof_a": proof_a.hash,
            "proof_b": proof_b.hash,
            "reason": "equivocation",
            "penalty": "100% slash + permanent removal"
        });
        // RE-AUDIT HIGH: no direct `sys:pending_slash` write any more — that made
        // the slash a function of WHICH node saw both vertices. The durable
        // `sys:equiv_seen` evidence row above is what the block proposer carries
        // (executor::collect_slash_evidence) and every node verifies+applies.
        let _ = slash_event;
        let _ = self.storage.put(
            &format!("validator:jailed:{}", offender),
            &round.to_string(),
        );
    }

    /// SEC-#9: gossip a self-authenticating equivocation proof (both signed
    /// vertices) to all peers via Gossipsub + TCP fallback. Mirrors the
    /// `broadcast_attestation` transport. No reporter signature is needed: the
    /// embedded vertex signatures ARE the proof.
    fn broadcast_equivocation_proof(&self, proof_a: &Vertex, proof_b: &Vertex) {
        let payload = serde_json::json!({
            "offender": proof_a.author,
            "round": proof_a.round,
            "vertex_a": proof_a,
            "vertex_b": proof_b,
        });
        let serialized = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ [SEC-#9] Failed to serialise equivocation proof: {}", e);
                return;
            }
        };
        let msg = format!("EQUIV_PROOF:{}", serialized);

        // 1. Gossipsub.
        if let Some(tx) = &self.p2p_tx {
            let tx_clone = tx.clone();
            let msg_clone = msg.clone();
            tokio::spawn(async move {
                let _ = tx_clone.send(msg_clone).await;
            });
        }

        // 2. TCP fallback.
        use network::send_message;
        if let Ok(peers) = self.peers.lock() {
            for (peer_id, port) in peers.iter() {
                if *peer_id != self.node_id {
                    let ip = self
                        .storage
                        .get_peer_ip(peer_id)
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    let addr = format!("{}:{}", ip, port);
                    let _ = send_message(&addr, &msg);
                }
            }
        }
    }

    /// SEC-#9: handle an inbound equivocation proof. Verify independently, then
    /// — only on the FIRST valid receipt for this (offender, round) — apply the
    /// slash and re-gossip once so the proof reaches nodes that saw only one of
    /// the two conflicting vertices.
    fn handle_remote_equivocation(&self, content: &str) {
        let v: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("❌ [SEC-#9] Malformed equivocation proof JSON: {}", e);
                return;
            }
        };
        let a: Vertex = match serde_json::from_value(v["vertex_a"].clone()) {
            Ok(x) => x,
            Err(_) => {
                eprintln!("❌ [SEC-#9] equivocation proof missing/invalid vertex_a");
                return;
            }
        };
        let b: Vertex = match serde_json::from_value(v["vertex_b"].clone()) {
            Ok(x) => x,
            Err(_) => {
                eprintln!("❌ [SEC-#9] equivocation proof missing/invalid vertex_b");
                return;
            }
        };

        let offender = match self.verify_equivocation_proof(&a, &b) {
            Some(o) => o,
            None => {
                eprintln!("❌ [SEC-#9] equivocation proof failed verification — dropping");
                return;
            }
        };

        // Re-gossip only on the FIRST application (dedup guards a broadcast storm).
        let seen_key = format!("sys:equiv_seen:{}:{}", offender, a.round);
        if matches!(self.storage.get(&seen_key), Ok(Some(_))) {
            return;
        }
        self.apply_equivocation_slash(&a, &b);
        self.broadcast_equivocation_proof(&a, &b);
    }

    /// QC Phase 3: gossip THIS node's partial finality vote so peers can
    /// aggregate a multi-party quorum certificate. Mirrors the
    /// `broadcast_attestation` transport (Gossipsub + TCP fallback). The vote is
    /// self-authenticating: it carries a BLS signature the receiver verifies
    /// against the signer's key in the frozen epoch validator set, so no extra
    /// reporter signature is needed.
    fn broadcast_qc_vote(&self, vote_msg: &crate::qc_producer::QcVoteMessage) {
        let serialized = match serde_json::to_string(vote_msg) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ [QC] Failed to serialise finality vote: {}", e);
                return;
            }
        };
        let msg = format!("QC_VOTE:{}", serialized);

        // 1. Gossipsub.
        if let Some(tx) = &self.p2p_tx {
            let tx_clone = tx.clone();
            let msg_clone = msg.clone();
            tokio::spawn(async move {
                let _ = tx_clone.send(msg_clone).await;
            });
        }

        // 2. TCP fallback.
        use network::send_message;
        if let Ok(peers) = self.peers.lock() {
            for (peer_id, port) in peers.iter() {
                if *peer_id != self.node_id {
                    let ip = self
                        .storage
                        .get_peer_ip(peer_id)
                        .unwrap_or_else(|| "127.0.0.1".to_string());
                    let addr = format!("{}:{}", ip, port);
                    let _ = send_message(&addr, &msg);
                }
            }
        }
    }

    /// QC Phase 3: handle an inbound peer finality vote. Verify the single BLS
    /// signature against the signer's key in the frozen epoch validator set, bind
    /// the vote to THIS node's committed block at the vote's anchor round, persist
    /// it (deduped per (round, signer)), and — once the collected stake exceeds
    /// 2/3 — deterministically aggregate, verify, and store a complete QC.
    ///
    /// Fully side-effect-only: any failure drops the vote and never affects
    /// consensus. A QC is never stored unless it verifies (enforced inside
    /// `collect_vote_and_try_aggregate`).
    fn handle_remote_qc_vote(&self, content: &str) {
        let vote_msg: crate::qc_producer::QcVoteMessage = match serde_json::from_str(content) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("❌ [QC] Malformed finality vote JSON: {}", e);
                return;
            }
        };

        // Bind the vote to OUR committed block at its anchor round, when known.
        // We look up the block hash this node committed at the vote's height; if
        // it disagrees the vote is for a different fork/block and is dropped by
        // the aggregator. (When we have not committed that height yet, pass None
        // and let the validator_set_hash + BLS-over-exact-vote binding guard it.)
        let expected_block_hash = self
            .storage
            .get(&format!("block_{}", vote_msg.vote.block_height))
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
            .and_then(|b| {
                b.get("header")
                    .and_then(|h| h.get("hash"))
                    .and_then(|h| h.as_str())
                    .map(|s| s.to_string())
            });

        let outcome = crate::qc_producer::collect_vote_and_try_aggregate(
            &self.storage,
            &vote_msg,
            expected_block_hash.as_deref(),
        );
        if let crate::qc_producer::QcOutcome::Complete(qc) = outcome {
            println!(
                "✅ [QC] multi-party quorum certificate assembled for block #{}",
                qc.block_height
            );
            // SEC-#12 Step-2: a complete (>2/3) multi-party QC now exists at
            // consensus:qc:{height}. Fold its aggregate BLS signature into the
            // leader-election beacon — the same fold every other validator performs
            // when it assembles the identical QC for the same height, so the beacon
            // stays byte-identical across nodes. `fold_qc_for_height` is idempotent
            // and monotonic, so folding here is safe even if the commit path already
            // attempted it (no complete QC then) or a later vote re-triggers it.
            if let Ok(mut engine) = self.ordering_engine.lock() {
                engine.fold_qc_for_height(qc.block_height);
            }
        }
    }

    pub fn handle_message(&mut self, msg: &str) {
        if let Some(content) = msg.strip_prefix("DAG_VERTEX:") {
            if let Ok(vertex) = serde_json::from_str::<Vertex>(content) {
                self.add_vertex(vertex);
            }
        } else if let Some(content) = msg.strip_prefix("DOWNTIME_ATTEST:") {
            // Phase 3 / H-02: Remote downtime attestation received from a peer.
            // Validate → store so executor can count towards BFT quorum.
            self.handle_remote_attestation(content);
        } else if let Some(content) = msg.strip_prefix("EQUIV_PROOF:") {
            // SEC-#9: a self-authenticating equivocation proof received from a
            // peer. Independently verify (both vertices signed by the offender,
            // same round, distinct bodies) before slashing, then re-gossip once.
            self.handle_remote_equivocation(content);
        } else if let Some(content) = msg.strip_prefix("QC_VOTE:") {
            // QC Phase 3: a peer's partial finality vote for multi-party QC
            // aggregation. Verify + collect; aggregate a complete QC on quorum.
            self.handle_remote_qc_vote(content);
        }
    }

    /// Validate and store a remote downtime attestation.
    ///
    /// Checks:
    ///  1. JSON parses correctly and has all required fields.
    ///  2. `reporter` is a known validator (in current validator set).
    ///  3. `reporter_pubkey` derives to the claimed `reporter` address.
    ///  4. Ed25519 signature over canonical payload is valid.
    ///  5. Not a duplicate (storage key already guards this).
    fn handle_remote_attestation(&mut self, content: &str) {
        let attest: serde_json::Value = match serde_json::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("❌ [H-02] Malformed attestation JSON: {}", e);
                return;
            }
        };

        let offender = match attest["offender"].as_str() {
            Some(s) => s.to_string(),
            None => {
                eprintln!("❌ [H-02] Missing offender field");
                return;
            }
        };
        let epoch = match attest["epoch"].as_u64() {
            Some(e) => e,
            None => {
                eprintln!("❌ [H-02] Missing epoch field");
                return;
            }
        };
        let reporter = match attest["reporter"].as_str() {
            Some(s) => s.to_string(),
            None => {
                eprintln!("❌ [H-02] Missing reporter field");
                return;
            }
        };
        let round = attest["round"].as_u64().unwrap_or(0);
        let reporter_pubkey_hex = match attest["reporter_pubkey"].as_str() {
            Some(s) => s.to_string(),
            None => {
                eprintln!("❌ [H-02] Missing reporter_pubkey");
                return;
            }
        };
        let sig_hex = match attest["signature"].as_str() {
            Some(s) => s.to_string(),
            None => {
                eprintln!("❌ [H-02] Missing signature");
                return;
            }
        };

        // Don't re-process our own attestation broadcast back to us.
        if reporter == self.node_id {
            return;
        }

        // Phase 5B.6 / L-05: a reporter must not be able to attest its
        // own downtime. Self-attestations cannot reach quorum alone but
        // they inflate the attestation-set surface and complicate
        // forensic review.
        if reporter == offender {
            eprintln!(
                "❌ [L-05] Attestation rejected: reporter == offender ({})",
                reporter
            );
            return;
        }

        // 1. Reporter must be a known validator.
        let validators = self.get_validator_set();
        if !validators.contains(&reporter) {
            eprintln!(
                "❌ [H-02] Attestation from unknown validator {}, dropping",
                reporter
            );
            return;
        }

        // Phase 5B.6 / SEC-N03: offender must ALSO be a known validator.
        // Without this check a single Byzantine reporter could write
        // attestations against arbitrary addresses, producing unbounded
        // `sys:downtime_attestation:` storage growth (bounded only by
        // the scan-prefix cap). Even though such attestations cannot
        // reach BFT quorum (no other reporter would echo a non-validator
        // offender), the disk write itself is a DoS amplifier.
        if !validators.contains(&offender) {
            eprintln!(
                "❌ [SEC-N03] Attestation rejected: offender {} is not in validator set",
                offender
            );
            return;
        }

        // 2. Verify pubkey → address derivation matches claimed reporter.
        let pubkey_bytes = match hex::decode(&reporter_pubkey_hex) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("❌ [H-02] reporter_pubkey not valid hex");
                return;
            }
        };
        let derived_addr = match crypto::derive_address(&pubkey_bytes) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("❌ [H-02] derive_address failed: {}", e);
                return;
            }
        };
        if derived_addr != reporter {
            eprintln!(
                "❌ [H-02] reporter_pubkey derives to {} but reporter claims {}",
                derived_addr, reporter
            );
            return;
        }

        // 3. Verify Ed25519 signature over canonical payload.
        let canonical = format!("{}:{}:{}:{}", offender, epoch, reporter, round);
        let sig_bytes = match hex::decode(&sig_hex) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("❌ [H-02] signature not valid hex");
                return;
            }
        };
        match crypto::verify_signature(&pubkey_bytes, canonical.as_bytes(), &sig_bytes) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("❌ [H-02] Attestation signature INVALID from {}", reporter);
                return;
            }
            Err(e) => {
                eprintln!("❌ [H-02] Attestation signature verify error: {}", e);
                return;
            }
        }

        // 4. Store — key is unique per (offender, epoch, reporter) so this is
        //    idempotent; the executor counts distinct reporters for BFT quorum.
        let key = format!(
            "sys:downtime_attestation:{}:{}:{}",
            offender, epoch, reporter
        );
        // Only store if not already present (idempotency).
        if let Ok(Some(_)) = self.storage.get(&key) {
            return; // Already have this attestation, skip.
        }

        let payload = serde_json::json!({
            "offender": offender,
            "epoch": epoch,
            "reporter": reporter,
            "round": round,
            "rounds_missed": attest["rounds_missed"].as_u64().unwrap_or(0),
        });
        match self.storage.put(&key, &payload.to_string()) {
            Ok(_) => println!(
                "✅ [H-02] Stored remote attestation: offender={} epoch={} reporter={}",
                offender, epoch, reporter
            ),
            Err(e) => eprintln!("❌ [H-02] Failed to store remote attestation: {}", e),
        }
    }

    pub fn prune_dag(&self, min_round: u64) {
        let mut dag = match self.dag.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let mut round_idx = match self.round_index.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        let initial_size = dag.len();

        // Identify vertices to remove
        let mut to_remove = Vec::new();
        for (hash, vertex) in dag.iter() {
            if vertex.round < min_round {
                to_remove.push(hash.clone());
            }
        }

        // Remove from DB and Memory
        for hash in &to_remove {
            let _ = self.storage.delete(&format!("vertex:{}", hash));
            dag.remove(hash);
        }

        // Remove old entries from Round Index
        round_idx.retain(|r, _| *r >= min_round);

        let removed_count = initial_size - dag.len();
        if removed_count > 0 {
            println!(
                "🧹 Garbage Collection: Pruned {} vertices older than round {} from Disk & Memory",
                removed_count, min_round
            );
        }

        // SEC-#10: equivocation evidence (`sys:equiv_seen:{offender}:{round}`) is
        // a plain KV row, never a `vertex:{hash}`, so it already survives the DAG
        // prune above — this only bounds its growth long after the slash is
        // finalized. Records are kept for a large retention window past the prune
        // horizon; older ones are safe to discard (the slash is long applied).
        let gc_below = min_round.saturating_sub(EQUIV_EVIDENCE_RETENTION_ROUNDS);
        if gc_below > 0 {
            for (key, _) in self.storage.scan_prefix("sys:equiv_seen:") {
                // key = sys:equiv_seen:{offender}:{round}
                if let Some(round_str) = key.rsplit(':').next() {
                    if let Ok(r) = round_str.parse::<u64>() {
                        if r < gc_below {
                            let _ = self.storage.delete(&key);
                        }
                    }
                }
            }
        }
    }

    /// Reload chain tip from storage after external state changes (e.g. sync)
    /// This prevents consensus from forking by building on stale state.
    pub fn reload_chain_tip(&mut self) {
        let new_height = match self.storage.get("latest_height") {
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
            _ => 0,
        };
        let new_hash = match self.storage.get("latest_block_hash") {
            Ok(Some(h)) => h,
            _ => "genesis".to_string(),
        };

        if new_height > self.latest_block_height {
            println!(
                "🔄 [Consensus] Chain tip reloaded: Block #{} -> #{} (Hash: {:.8}..)",
                self.latest_block_height, new_height, new_hash
            );
            self.latest_block_height = new_height;
            self.latest_block_hash = new_hash;
            // DIVERGENCE FIX (audit 2026-08-26, CRITICAL): the validator-set cache
            // used to be invalidated ONLY when this node BUILT a block. A node
            // catching up applies the very same slash/stake change to storage via
            // ChainSync but never rebuilt, so it kept a STALE (addr,stake) list —
            // and that list decides the anchor LEADER (hashed whole into
            // leader_for_round), the reward recipient, the BFT-time stake weights
            // and the >2/3 commit threshold. Two honest nodes then produce
            // different proposer_id / timestamp / state_root for the same anchor.
            // The tip advancing is exactly the moment the set may have changed.
            self.invalidate_validators_cache();

            // LIVENESS (burn-in finding): every synced block above the last
            // adopted height carries the network's committed vertex sequence for
            // its anchor. Apply each one to the ordering engine IN ORDER so the
            // local cursor moves past any gossip hole exactly as the producer's
            // did, then cast this node's finality vote for the block — a stalled
            // follower otherwise stops voting and the >2/3 QC quorum dies.
            {
                let validators = self.get_validator_set_with_stake();
                let start_h = self.last_adopted_height.saturating_add(1);
                for h in start_h..=new_height {
                    let Some(block) = self
                        .storage
                        .get(&format!("block_{}", h))
                        .ok()
                        .flatten()
                        .and_then(|j| serde_json::from_str::<blockchain::Block>(&j).ok())
                    else {
                        break;
                    };
                    // RE-AUDIT HIGH (loan ledger): every transaction carried by a
                    // synced block is settled — included-in-committed-block is the
                    // right notion of "done" here (a failed one would fail again
                    // and is bounded by the requeue cap anyway).
                    if !block.transactions.is_empty() {
                        if let Ok(mut mp) = self.mempool.lock() {
                            mp.mark_executed(&block.transactions);
                        }
                    }
                    // RE-AUDIT CRITICAL: never adopt or vote for a block that does
                    // not carry a proposer signature. ChainSync already rejects
                    // unsigned/mis-signed blocks before execution; this is defense
                    // in depth for anything that reached storage another way.
                    if !block.committed_vertices.is_empty() && !block.proposer_signature.is_empty() {
                        let adopted = match self.ordering_engine.lock() {
                            Ok(mut engine) => engine.adopt_synced_anchor(
                                block.header.round,
                                &block.anchor_hash,
                                &block.committed_vertices,
                                &validators,
                            ),
                            Err(_) => None,
                        };
                        if let Some(info) = adopted {
                            let epoch = self
                                .storage
                                .get("consensus:epoch")
                                .ok()
                                .flatten()
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(0);
                            let ctx = crate::qc_producer::CommitContext {
                                chain_id: self.resolve_chain_id(),
                                epoch,
                                finalized_round: info.anchor_round,
                                anchor_round: info.anchor_round,
                                anchor_hash: info.anchor_hash.clone(),
                                block_height: h,
                                block_hash: block.header.hash.clone(),
                                state_root: block.header.state_root.clone(),
                                receipts_root: block.header.receipts_root.clone(),
                                finality_digest: info.finality_digest.clone(),
                            };
                            if let crate::qc_producer::QcOutcome::Partial(vote_msg) =
                                crate::qc_producer::produce_and_store_qc(
                                    &self.storage,
                                    &self.node_key,
                                    &self.node_id,
                                    &ctx,
                                )
                            {
                                self.broadcast_qc_vote(&vote_msg);
                            }
                            if let Ok(mut engine) = self.ordering_engine.lock() {
                                engine.fold_qc_for_height(h);
                            }
                        }
                    }
                    self.last_adopted_height = h;
                    let _ = self
                        .storage
                        .put("consensus:last_adopted_height", &h.to_string());
                }
            }

            let synced_block = self
                .storage
                .get(&format!("block_{}", new_height))
                .ok()
                .flatten()
                .and_then(|block_json| serde_json::from_str::<serde_json::Value>(&block_json).ok());
            let synced_round = synced_block.as_ref().and_then(|block| {
                block
                    .get("header")
                    .and_then(|header| header.get("round"))
                    .and_then(|round| round.as_u64())
            });
            // AUDIT-B4b (dedup): adopt the synced tip's anchor round so the local
            // commit loop knows which anchors are ALREADY represented on chain and
            // never builds a duplicate block for them. Adopt its timestamp too, so
            // the next locally-built block's BFT-time clamps against the true
            // parent — the same value on every node.
            if let Some(r) = synced_round {
                self.latest_block_round = self.latest_block_round.max(r);
            }
            if let Some(ts) = synced_block.as_ref().and_then(|block| {
                block
                    .get("header")
                    .and_then(|header| header.get("timestamp"))
                    .and_then(|t| t.as_u64())
            }) {
                // SET, not max(): the synced tip IS the canonical parent. A max()
                // let a stale-high value from a superseded local block survive and
                // skew the next block's BFT-time clamp (see the build site).
                self.latest_block_timestamp = ts;
            }

            if let Some(round) = synced_round {
                // AUDIT-B3 (second door): this used to be a BLIND
                // `self.current_round = block.round + 1`, the exact same defect
                // that was fixed in `add_vertex` — and it wedged a live 3-node
                // cluster at round 85 even after that fix, because closing one
                // door is not enough. A committed block's round says only that
                // the round was FINALIZED; it says nothing about whether this
                // node holds the round's vertices, and those vertices are what
                // `try_create_vertex` needs as parents. Jumping past them leaves
                // the node proposing at a round whose predecessor can never reach
                // parent quorum, so it stops producing — permanently, since the
                // value is persisted.
                //
                // Same Narwhal rule as the ingest path: advance only to
                // `quorum_round + 1`, the highest round we can genuinely build
                // parents for. A node that synced blocks ahead of its DAG simply
                // waits for gossip to deliver the vertices instead of racing past
                // them.
                // Validators fetched BEFORE the locks: quorum_round runs while the
                // DAG/round-index guards are held and cannot call back into &self.
                let validators = self.get_validator_set_with_stake();
                let quorum_target = {
                    let round_idx = self
                        .round_index
                        .lock()
                        .expect("🚨 FATAL: Round index lock poisoned");
                    let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");
                    Self::quorum_round(&round_idx, &dag, &validators).saturating_add(1)
                };
                // ...but a node that synced thousands of blocks must not be left
                // so far behind that the PWN-002 jump guard rejects every live
                // vertex as "far future" — that is the catch-up deadlock this
                // reload exists to prevent, and it is why the blind jump was here
                // in the first place. So the quorum cap has a floor: never sit
                // more than half the jump allowance below the synced tip. Normal
                // operation (a gap of a few rounds, like the round-85 wedge) is
                // fully quorum-gated; only a genuinely stranded node uses the
                // floor, and it lands inside the guard's window so gossip can
                // refill the DAG and quorum_round takes over again.
                let tip_next = round.saturating_add(1);
                let catchup_floor = tip_next.saturating_sub(Self::MAX_ROUND_JUMP / 2);
                let next_round = tip_next.min(quorum_target.max(catchup_floor));
                if next_round > self.current_round {
                    println!(
                        "🔄 [Consensus] Round reloaded from synced tip: {} -> {} \
                         (tip round {}, quorum cap {}, catch-up floor {})",
                        self.current_round, next_round, round, quorum_target, catchup_floor
                    );
                    self.current_round = next_round;
                    let _ = self
                        .storage
                        .put("latest_proposed_round", &self.current_round.to_string());
                }
            }
        }
    }

    /// Authoritative validator-set read: `(address, stake)` pairs, sorted by
    /// address and deduped. This is the single source of truth for both
    /// membership AND stake-weighted quorum / leader election (B4). Cache fast
    /// path (Phase 2.8 / M-08): `sys:validators` only changes when a slash
    /// executes, and `invalidate_validators_cache()` is called from `add_vertex`
    /// right after a block is persisted — the only moment the active set can
    /// change in normal operation. Tests/ops that write `sys:validators`
    /// directly MUST also invalidate, or the cache stays stale.
    pub fn get_validator_set_with_stake(&self) -> Vec<(String, u64)> {
        if let Ok(guard) = self.validators_cache.lock() {
            if let Some(cached) = guard.as_ref() {
                return cached.clone();
            }
        }
        let fresh = self.read_validators_from_storage();
        if let Ok(mut guard) = self.validators_cache.lock() {
            *guard = Some(fresh.clone());
        }
        fresh
    }

    /// Membership-only view (addresses), derived from the authoritative
    /// stake-aware set. Existing callers that only need membership/count stay
    /// unchanged.
    pub fn get_validator_set(&self) -> Vec<String> {
        self.get_validator_set_with_stake()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect()
    }

    /// Storage-backed read path returning `(address, stake)`. Callers should
    /// prefer `get_validator_set_with_stake` so the cache is exercised; this
    /// helper is extracted so cache misses and explicit refreshes share one
    /// implementation.
    fn read_validators_from_storage(&self) -> Vec<(String, u64)> {
        // 1. AUTHORITATIVE PATH: BLS/stake-aware validator set. Runtime joins
        // update this key; legacy `sys:validators` is only a compatibility
        // mirror and can lag on older nodes.
        if let Ok(Some(json)) = self.storage.get("sys:validator_set:v1") {
            if let Ok(vals) = serde_json::from_str::<Vec<ValidatorSetV1Entry>>(&json) {
                let mut validators: Vec<(String, u64)> =
                    vals.into_iter().map(|v| (v.address, v.stake)).collect();
                validators.sort_by(|a, b| a.0.cmp(&b.0));
                validators.dedup_by(|a, b| a.0 == b.0);
                return validators;
            }
        }

        // 2. LEGACY PATH: Native consensus mirror (`sys:validators`).
        if let Ok(Some(json)) = self.storage.get("sys:validators") {
            if let Ok(vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                let mut validators: Vec<(String, u64)> = vals;
                validators.sort_by(|a, b| a.0.cmp(&b.0));
                validators.dedup_by(|a, b| a.0 == b.0);
                return validators;
            }
        }

        // 3. SLOW PATH: Read BCS ValidatorSet Resource directly.
        let key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::staking::ValidatorSet";
        if let Ok(Some(bytes_hex)) = self.storage.get(key) {
            if let Ok(bytes) = hex::decode(bytes_hex) {
                if let Ok(val_set) = bcs::from_bytes::<ValidatorSet>(&bytes) {
                    let mut validators: Vec<(String, u64)> = val_set
                        .validators
                        .iter()
                        // Coin.value is u128 quanta (10^18 per AIN); scale to
                        // whole-AIN u64 to match the fast-path / qc::ValidatorInfo
                        // stake unit, saturating instead of truncating.
                        .map(|v| {
                            let whole_ain = v.stake.value / 1_000_000_000_000_000_000u128;
                            (
                                v.validator_addr.to_string(),
                                u64::try_from(whole_ain).unwrap_or(u64::MAX),
                            )
                        })
                        .collect();
                    validators.sort_by(|a, b| a.0.cmp(&b.0));
                    validators.dedup_by(|a, b| a.0 == b.0);
                    return validators;
                }
            }
        }

        // STRICT ENFORCEMENT: No fallback to P2P peer list!
        // If staking is completely missing and we aren't Genesis, we must not mine.
        Vec::new()
    }
}

#[derive(serde::Deserialize)]
struct Coin {
    #[allow(dead_code)]
    value: u128,
}

#[derive(serde::Deserialize)]
struct ValidatorConfig {
    #[allow(dead_code)]
    validator_addr: AccountAddress,
    #[allow(dead_code)]
    stake: Coin,
    #[allow(dead_code)]
    public_key: Vec<u8>,
    #[allow(dead_code)]
    bls_public_key: Vec<u8>,
    #[allow(dead_code)]
    bls_pop: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct ValidatorSet {
    validators: Vec<ValidatorConfig>,
}

#[derive(serde::Deserialize)]
struct ValidatorSetV1Entry {
    address: String,
    stake: u64,
}

#[derive(serde::Deserialize, Debug)]
struct AccountAddress([u8; 32]);

impl std::fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
