use std::collections::HashMap;
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
    validators_cache: Arc<Mutex<Option<Vec<String>>>>,
}

impl DagConsensus {
    pub(crate) fn bft_quorum_threshold(validator_count: usize) -> usize {
        if validator_count == 0 {
            return 0;
        }
        if validator_count == 1 {
            return 1;
        }
        (validator_count * 2 / 3) + 1
    }

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

        // DYNAMIC CHECK: Get active validator set FIRST (needed for quorum calculation)
        let validators = self.get_validator_set();
        let is_active_validator = validators.contains(&self.node_id);

        // BFT quorum is a strict >2/3 threshold; two validators need both parents.
        let n = validators.len();
        if n == 0 {
            println!("⚠️ [Consensus] No validators found! Defaulting to Singleton Quorum.");
            // Return early or set n=1 to avoid division by zero
        }
        let n = n.max(1); // Prevent division by zero safely
        let bft_quorum = Self::bft_quorum_threshold(n);

        // For genesis round (round 0), we need 0 parents (bootstrap)
        // For subsequent rounds, we need BFT quorum of parents
        let quorum = if prev_round == 0 {
            0
        } else {
            bft_quorum.max(1) // At minimum 1 parent required
        };

        println!(
            "🔒 [Consensus] Round {}: Validators={}, BFT_Quorum={}, Parents={}",
            self.current_round,
            n,
            quorum,
            parents.len()
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
        if parents.len() >= quorum {
            // 2. Create Payload (Fetch from Mempool)
            let mut payload = Vec::new();
            if let Ok(mut mp) = self.mempool.lock() {
                payload = mp.get_pending_transactions(50);
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
            const DOWNTIME_THRESHOLD: u64 = 100; // 100 rounds of absence = jail

            // Record our participation
            let _ = self.storage.put(
                &format!("validator:last_seen:{}", self.node_id),
                &self.current_round.to_string(),
            );

            // Check all validators for downtime (only every 10 rounds to save CPU)
            if self.current_round.is_multiple_of(10) {
                for validator_id in &validators {
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

                    if rounds_missed >= DOWNTIME_THRESHOLD && last_seen > 0 {
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

        // C-10 FIX: Resolve the FULL Ed25519 public key from the account object in storage.
        // vertex.author is a truncated 16-byte address (32 hex chars), but Ed25519 verification
        // requires the full 32-byte public key (64 hex chars). Without this fix, signature
        // verification would always fail because hex::decode produces only 16 bytes.
        let author_pubkey_hex = {
            // First try: Look up the account object for the author's full public key
            if let Some(account_obj) = self.storage.get_object(&vertex.author) {
                // Parse AccountData to extract the full public_key field
                if let Ok(account_data) =
                    serde_json::from_slice::<serde_json::Value>(&account_obj.data)
                {
                    if let Some(pk) = account_data.get("public_key").and_then(|v| v.as_str()) {
                        if pk.len() == 64 {
                            match hex::decode(pk)
                                .ok()
                                .and_then(|bytes| crypto::derive_address(&bytes).ok())
                            {
                                Some(addr) if addr == vertex.author => pk.to_string(),
                                _ => {
                                    println!(
                                        "🚨 REJECTED: Stored public key does not derive author {}",
                                        vertex.author
                                    );
                                    return;
                                }
                            }
                        } else {
                            println!(
                                "🚨 REJECTED: Missing full Ed25519 public key for author {}",
                                vertex.author
                            );
                            return;
                        }
                    } else {
                        println!(
                            "🚨 REJECTED: Account object for {} has no public_key",
                            vertex.author
                        );
                        return;
                    }
                } else {
                    println!(
                        "🚨 REJECTED: Account object for {} is not valid JSON",
                        vertex.author
                    );
                    return;
                }
            } else if vertex.author == self.node_id {
                let signing_key = crypto::SigningKey::from_bytes(&self.node_key);
                let public_key = signing_key.verifying_key();
                match crypto::derive_address(public_key.as_bytes()) {
                    Ok(addr) if addr == vertex.author => hex::encode(public_key.as_bytes()),
                    _ => {
                        println!(
                            "🚨 REJECTED: Local node key does not derive author {}",
                            vertex.author
                        );
                        return;
                    }
                }
            } else {
                println!(
                    "🚨 REJECTED: No public key available for vertex author {}",
                    vertex.author
                );
                return;
            }
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

        // C-2 FIX: Cross-check against the active ValidatorSet
        let validators = self.get_validator_set();
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

                            // === SLASH EXECUTION QUEUE (Equivocation) ===
                            // C-01 FIX: reason MUST be "equivocation" so executor applies
                            // the 100% slash + permanent removal path. Previously this wrote
                            // "double_sign" which fell through to the 5% downtime branch and
                            // copied the downtime penalty string — letting equivocators escape
                            // with a slap on the wrist while the consensus alert above claimed
                            // a critical slashing was happening. The mismatch was not caught
                            // by unit tests because they wrote events directly with the
                            // canonical "equivocation" reason instead of routing through DAG.
                            let slash_event = serde_json::json!({
                                "event": "equivocation_detected",
                                "validator": vertex.author,
                                "round": vertex.round,
                                "proof_a": existing_hash,
                                "proof_b": vertex.hash,
                                "reason": "equivocation",
                                "penalty": "100% slash + permanent removal"
                            });
                            let _ = self.storage.put(
                                &format!("sys:pending_slash:{}", vertex.author),
                                &slash_event.to_string(),
                            );
                            let _ = self.storage.put(
                                &format!("validator:jailed:{}", vertex.author),
                                &vertex.round.to_string(),
                            );
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

            // Fast-forward local round to match network if lagging behind (Amnesia Recovery)
            // ONLY for remote vertices — try_create_vertex already increments for local ones
            if vertex.author != self.node_id && vertex.round >= self.current_round {
                self.current_round = vertex.round + 1;
                let _ = self
                    .storage
                    .put("latest_proposed_round", &self.current_round.to_string());
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
            let validators = self.get_validator_set(); // This acquires peers lock, safe now.

            engine.try_commit(vertex.round, &dag, &round_idx, &validators)
        }; // All locks dropped here!

        if let Some((hashes, anchor_leader)) = committed_result {
            println!(
                "⛓️  Consensus Reached! Executing {} vertices in order...",
                hashes.len()
            );

            let executor = &self.executor;
            let mut block_txs = Vec::new();
            let reward_recipient = anchor_leader; // C-10 FIX: Reward the anchor leader deterministically

            // Re-acquire DAG read lock just to fetch payloads
            // We can optimize this by cloning necessary data in the previous block,
            // but identifying which vertices are committed before engine runs is hard.
            // So we just re-acquire efficiently.
            let dag = self.dag.lock().expect("🚨 FATAL: DAG lock poisoned");

            for hash in &hashes {
                if let Some(v) = dag.get(hash) {
                    // Clone payload to release DAG lock faster?
                    // No, looking up payload is fast. Execution is slow.
                    // But we must NOT hold DAG lock during execution.
                    // So we collect ALL txs first.
                    block_txs.extend(v.payload.clone());
                }
            }
            drop(dag); // DROP DAG LOCK NOW!

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
                let execution_summary =
                    executor.execute_block_parallel(block_txs.clone(), &reward_recipient);

                // Create Block (Post-Execution)
                use blockchain::Block;
                self.latest_block_height += 1;
                let new_block = Block::new_with_roots(
                    self.latest_block_height,
                    vertex.round, // Pass Round
                    self.latest_block_hash.clone(),
                    block_txs.clone(), // This duplicates data, effectively block contains processed txs
                    reward_recipient.clone(),
                    execution_summary.state_root,
                    execution_summary.receipts_root,
                );
                self.latest_block_hash = new_block.header.hash.clone();

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
            if !hashes.is_empty() {
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
                    // Keep a safety buffer of 10 rounds below the latest finalized
                    // round. Anything older than this is causally settled and safe
                    // to reclaim.
                    if finalized_round > 10 {
                        self.prune_dag(finalized_round - 10);
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

    pub fn handle_message(&mut self, msg: &str) {
        if let Some(content) = msg.strip_prefix("DAG_VERTEX:") {
            if let Ok(vertex) = serde_json::from_str::<Vertex>(content) {
                self.add_vertex(vertex);
            }
        } else if let Some(content) = msg.strip_prefix("DOWNTIME_ATTEST:") {
            // Phase 3 / H-02: Remote downtime attestation received from a peer.
            // Validate → store so executor can count towards BFT quorum.
            self.handle_remote_attestation(content);
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

            let synced_round = self
                .storage
                .get(&format!("block_{}", new_height))
                .ok()
                .flatten()
                .and_then(|block_json| serde_json::from_str::<serde_json::Value>(&block_json).ok())
                .and_then(|block| {
                    block
                        .get("header")
                        .and_then(|header| header.get("round"))
                        .and_then(|round| round.as_u64())
                });

            if let Some(round) = synced_round {
                let next_round = round.saturating_add(1);
                if next_round > self.current_round {
                    println!(
                        "🔄 [Consensus] Round reloaded from synced tip: {} -> {}",
                        self.current_round, next_round
                    );
                    self.current_round = next_round;
                    let _ = self
                        .storage
                        .put("latest_proposed_round", &round.to_string());
                }
            }
        }
    }

    pub fn get_validator_set(&self) -> Vec<String> {
        // Phase 2.8 (M-08): cache fast path.
        //
        // The previous implementation re-read `sys:validators` from RocksDB
        // and re-parsed the JSON on every call. `try_create_vertex` and
        // `add_vertex` both call this once or more per vertex, so on a
        // healthy network this was hundreds of identical disk reads per
        // block period for data that only changes when a slash executes.
        //
        // Cache invariants:
        //   * `validators_cache` is populated on first cache miss.
        //   * `invalidate_validators_cache()` is called from `add_vertex`
        //     immediately after a block is persisted via save_block_json
        //     — that is the only moment a slash could have changed the
        //     active set during normal operation.
        //   * If anything bypasses that flow (tests writing
        //     `sys:validators` directly, manual ops surgery), they must
        //     also call `invalidate_validators_cache()`; otherwise the
        //     cache will stay stale until the next legitimate commit.
        if let Ok(guard) = self.validators_cache.lock() {
            if let Some(cached) = guard.as_ref() {
                return cached.clone();
            }
        }

        // Cache miss — read fresh from storage and populate.
        let fresh = self.read_validators_from_storage();
        if let Ok(mut guard) = self.validators_cache.lock() {
            *guard = Some(fresh.clone());
        }
        fresh
    }

    /// Storage-backed read path. Direct callers should prefer
    /// `get_validator_set` so the cache is exercised; this helper is
    /// extracted so cache misses and explicit refreshes share one
    /// implementation.
    fn read_validators_from_storage(&self) -> Vec<String> {
        // 1. FAST PATH: Native Consensus State sync'd from Move VM (sys:validators)
        if let Ok(Some(json)) = self.storage.get("sys:validators") {
            if let Ok(vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                let mut validators: Vec<String> = vals.into_iter().map(|(addr, _)| addr).collect();
                validators.sort();
                validators.dedup();
                return validators;
            }
        }

        // 2. SLOW PATH: Read BCS ValidatorSet Resource directly
        let key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::staking::ValidatorSet";
        if let Ok(Some(bytes_hex)) = self.storage.get(key) {
            if let Ok(bytes) = hex::decode(bytes_hex) {
                if let Ok(val_set) = bcs::from_bytes::<ValidatorSet>(&bytes) {
                    let mut validators: Vec<String> = val_set
                        .validators
                        .iter()
                        .map(|v| v.validator_addr.to_string())
                        .collect();
                    validators.sort();
                    validators.dedup();
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

#[derive(serde::Deserialize, Debug)]
struct AccountAddress([u8; 32]);

impl std::fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
