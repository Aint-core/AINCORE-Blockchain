use blockchain::Block;
use network::{read_encrypted_msg, secure_connect, send_encrypted_msg};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use storage::StateDB;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub from_height: u64,
    pub sender_id: String,
    pub sender_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
    #[serde(default)]
    pub finality: Option<FinalityArtifact>,
    /// Set when the requested range is below the seed's prune horizon (the
    /// requested blocks no longer exist). Carries the lowest block height the
    /// seed can still serve, so the requester knows block-replay can't bridge
    /// the gap and it must bootstrap from a state snapshot instead of looping on
    /// empty responses. `None` from older peers (serde default).
    #[serde(default)]
    pub prune_horizon: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalityArtifact {
    pub finalized_round: String,
    pub last_anchor_round: String,
    pub last_anchor_hash: String,
    pub finality_digest: String,
    /// The quorum certificate that cryptographically proves this finality (>2/3
    /// stake BLS signature). This is the ONLY thing that authorises advancing
    /// `consensus:finalized_round` on a syncing node — the legacy string fields
    /// above are unauthenticated hints. `None` from pre-QC peers (serde default),
    /// in which case finality is NOT advanced.
    #[serde(default)]
    pub qc: Option<consensus::qc::QuorumCertificate>,
}

pub struct ChainSync {
    node_id: String,
    my_port: u16,
    peers: Arc<Mutex<HashMap<String, u16>>>,
    storage: Arc<StateDB>,
}

impl ChainSync {
    /// SEC-#7 (cutover): whether blocks must commit to non-empty execution roots.
    /// Resolved from the genesis-pinned `sys:config:require_exec_roots` (so it is
    /// deterministic + identical across nodes — unlike a per-node env var), with
    /// `AINCORE_REQUIRE_EXEC_ROOTS` as a dev fallback. Off by default: the running
    /// testnet may hold empty-root blocks, so this is enabled only at the
    /// fresh-genesis mainnet cutover.
    fn require_exec_roots(&self) -> bool {
        if let Ok(Some(v)) = self.storage.get("sys:config:require_exec_roots") {
            return v == "1" || v.eq_ignore_ascii_case("true");
        }
        std::env::var("AINCORE_REQUIRE_EXEC_ROOTS")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    pub fn new(
        node_id: String,
        my_port: u16,
        peers: Arc<Mutex<HashMap<String, u16>>>,
        storage: Arc<StateDB>,
    ) -> Self {
        Self {
            node_id,
            my_port,
            peers,
            storage,
        }
    }

    fn verify_block_hash(&self, block: &Block) -> Result<bool, String> {
        let computed_hash = blockchain::calculate_header_hash(&block.header);

        if computed_hash == block.header.hash {
            Ok(true)
        } else {
            Err(format!(
                "Hash Mismatch. Expected: {}, Computed: {}",
                block.header.hash, computed_hash
            ))
        }
    }

    fn verify_execution_roots(
        &self,
        block: &Block,
        summary: &executor::BlockExecutionSummary,
    ) -> Result<(), String> {
        // SEC-#7 (cutover): when AINCORE_REQUIRE_EXEC_ROOTS is set, a block MUST
        // commit to NON-EMPTY execution roots. Otherwise the empty-root bypass
        // below lets a producer ship blocks that don't bind to executed state
        // (the header just omits the roots and the mismatch checks are skipped).
        // Opt-in / off by default so the running testnet (which may hold
        // empty-root blocks) is not retroactively rejected; enable at the
        // fresh-genesis mainnet cutover.
        if self.require_exec_roots() {
            if block.header.state_root.is_empty() {
                return Err(format!(
                    "block {} has empty state_root but execution roots are required (cutover)",
                    block.header.height
                ));
            }
            if block.header.receipts_root.is_empty() {
                return Err(format!(
                    "block {} has empty receipts_root but execution roots are required (cutover)",
                    block.header.height
                ));
            }
        }
        if !block.header.state_root.is_empty() && block.header.state_root != summary.state_root {
            return Err(format!(
                "State root mismatch at block {}: header={}, executed={}",
                block.header.height, block.header.state_root, summary.state_root
            ));
        }
        if !block.header.receipts_root.is_empty()
            && block.header.receipts_root != summary.receipts_root
        {
            return Err(format!(
                "Receipts root mismatch at block {}: header={}, executed={}",
                block.header.height, block.header.receipts_root, summary.receipts_root
            ));
        }
        Ok(())
    }

    fn calculate_tx_hash(transactions: &[String]) -> String {
        let mut data = Vec::new();
        for tx in transactions {
            data.extend_from_slice(tx.as_bytes());
        }
        hex::encode(crypto::hash(&data))
    }

    fn active_validator_addresses(&self) -> Vec<String> {
        self.storage
            .get_active_validators()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect()
    }

    /// TASK-#29: number of distinct seed peers that must advertise a CONSISTENT
    /// finalized tip before this node will accept it as the head to sync past.
    ///
    /// Resolved from the genesis-pinned `sys:config:tip_agreement_n` so it is
    /// deterministic and identical across nodes (NO env var, NO wall-clock — this
    /// path runs during sync and must not fork). Default 1 preserves the current
    /// single-seed behaviour. A value below 1 is clamped to 1.
    fn tip_agreement_n(&self) -> usize {
        self.storage
            .get("sys:config:tip_agreement_n")
            .ok()
            .flatten()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .max(1)
    }

    /// TASK-#29 (pure, unit-testable): order peers so trusted seed/validator peers
    /// are tried FIRST, then everyone else. HashMap iteration order is arbitrary;
    /// seeding the sync from a validator peer (the trusted fallback-seed set) before
    /// an unknown peer reduces the chance of being fed a bogus tip by a random peer.
    ///
    /// Ordering within each group, and the relative order of the two groups, is
    /// stable/deterministic: peers are sorted by id, seeds (those whose id is in
    /// `seed_set`) first. This keeps the iteration reproducible across nodes.
    fn order_peers_seed_first(
        peers: &HashMap<String, u16>,
        seed_set: &[String],
    ) -> Vec<(String, u16)> {
        let is_seed = |id: &str| seed_set.iter().any(|s| s == id);
        let mut ordered: Vec<(String, u16)> =
            peers.iter().map(|(id, p)| (id.clone(), *p)).collect();
        // Sort: seeds before non-seeds; then by peer id for determinism.
        ordered.sort_by(|a, b| {
            let (a_seed, b_seed) = (is_seed(&a.0), is_seed(&b.0));
            b_seed.cmp(&a_seed).then_with(|| a.0.cmp(&b.0))
        });
        ordered
    }

    /// TASK-#29 (pure, unit-testable): decide whether a set of seed-advertised
    /// finalized tips agree well enough to advance past.
    ///
    /// `tips` are the QCs gathered from DISTINCT seed peers (one entry per peer).
    /// Each QC has ALREADY been cryptographically verified by the caller (the QC
    /// crypto backstop in `apply_finality_artifact` is NOT weakened — this is an
    /// additional N-of-seed agreement gate on top of it). We require at least `n`
    /// of them to advertise the SAME `(block_height, block_hash)` finalized tip.
    ///
    /// Returns the agreed `(block_height, block_hash)` on success, or an `Err`
    /// describing the disagreement/shortfall so the caller can refuse to advance
    /// and log `🚨 [SECURITY][TIP_DISAGREEMENT]`.
    fn tip_agreement_decision(
        tips: &[consensus::qc::QuorumCertificate],
        n: usize,
    ) -> Result<(u64, String), String> {
        let n = n.max(1);
        if tips.len() < n {
            return Err(format!(
                "need {} agreeing seed tips but only {} seed(s) advertised a verifiable tip",
                n,
                tips.len()
            ));
        }
        // Tally distinct (height, hash) tips.
        let mut counts: HashMap<(u64, String), usize> = HashMap::new();
        for qc in tips {
            *counts
                .entry((qc.block_height, qc.block_hash.clone()))
                .or_insert(0) += 1;
        }
        // Pick the most-advertised tip (deterministic tie-break by height then hash).
        let best = counts
            .iter()
            .max_by(|a, b| {
                a.1.cmp(b.1)
                    .then_with(|| a.0 .0.cmp(&b.0 .0))
                    .then_with(|| a.0 .1.cmp(&b.0 .1))
            })
            .map(|((h, hash), c)| ((*h, hash.clone()), *c));

        match best {
            Some(((height, hash), count)) if count >= n => Ok((height, hash)),
            Some((_, count)) => Err(format!(
                "no tip reached {} agreeing seeds (best had {} of {}); seeds disagree on the finalized head",
                n,
                count,
                tips.len()
            )),
            None => Err("no seed advertised a verifiable finalized tip".to_string()),
        }
    }

    fn validate_block(
        &self,
        block: &Block,
        expected_height: u64,
        prev_hash: &str,
    ) -> Result<(), String> {
        if block.header.height != expected_height {
            return Err(format!(
                "Height mismatch: expected {}, got {}",
                expected_height, block.header.height
            ));
        }
        if expected_height == 1 && block.header.prev_hash != "genesis" {
            return Err(format!(
                "Genesis parent mismatch: expected genesis, got {}",
                block.header.prev_hash
            ));
        }
        if expected_height > 1 && block.header.prev_hash != prev_hash {
            return Err(format!(
                "Parent hash mismatch at {}: exp {}, got {}",
                expected_height, prev_hash, block.header.prev_hash
            ));
        }

        let validators = self.active_validator_addresses();
        if !validators.is_empty() && !validators.contains(&block.header.proposer_id) {
            return Err(format!(
                "Proposer {} is not in active validator set",
                block.header.proposer_id
            ));
        }

        let computed_tx_hash = Self::calculate_tx_hash(&block.transactions);
        if block.header.tx_hash != computed_tx_hash {
            return Err(format!(
                "Transaction hash mismatch: expected {}, computed {}",
                block.header.tx_hash, computed_tx_hash
            ));
        }

        // LIVENESS/INTEGRITY: the block's committed vertex sequence is what a
        // follower adopts into its ordering engine; bind it to the header so a
        // peer cannot hand us a sequence that does not belong to this block.
        if !block.header.vertices_root.is_empty() {
            let computed = blockchain::calculate_vertices_root(&block.committed_vertices);
            if computed != block.header.vertices_root {
                return Err(format!(
                    "Vertices root mismatch: expected {}, computed {}",
                    block.header.vertices_root, computed
                ));
            }
        }

        // S3-4a: Reject blocks with future timestamps (30s drift tolerance)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();
        if block.header.timestamp > now + 30 {
            return Err(format!(
                "Future timestamp rejected: block={}, now={}",
                block.header.timestamp, now
            ));
        }

        // S3-4b: Reject blocks with excessive transaction count (DoS prevention)
        if block.transactions.len() > 10_000 {
            return Err(format!(
                "Transaction count {} exceeds max 10,000",
                block.transactions.len()
            ));
        }

        self.verify_block_hash(block)?;
        // RE-AUDIT CRITICAL: a synced block must PROVE it was produced by its
        // proposer. Followers adopt its committed sequence into their ordering
        // engine and cast a BLS finality vote for it (see
        // OrderingEngine::adopt_synced_anchor / DagConsensus::reload_chain_tip);
        // without this check any peer could hand honest followers a fabricated
        // block with a self-consistent vertices_root and collect their votes on a
        // fork. The proposer's Ed25519 key is the one registered in its on-chain
        // AccountData (the same resolution the DAG uses for vertex signatures).
        let proposer_pk = self
            .storage
            .get_object(&block.header.proposer_id)
            .and_then(|obj| serde_json::from_slice::<serde_json::Value>(&obj.data).ok())
            .and_then(|v| v.get("public_key").and_then(|k| k.as_str()).map(String::from));
        match proposer_pk {
            Some(pk) if block.verify_proposer_signature(&pk) => {}
            Some(_) => {
                return Err(format!(
                    "Proposer signature invalid or missing on block #{} from {}",
                    block.header.height, block.header.proposer_id
                ));
            }
            None => {
                return Err(format!(
                    "Cannot resolve proposer {} public key to authenticate block #{}",
                    block.header.proposer_id, block.header.height
                ));
            }
        }

        Ok(())
    }

    fn get_local_height(&self) -> u64 {
        self.storage.get_chain_height()
    }

    fn finalized_round_boundary(&self) -> u64 {
        self.storage
            .get("consensus:finalized_round")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    }

    fn collect_finality_artifact(&self) -> FinalityArtifact {
        FinalityArtifact {
            finalized_round: self
                .storage
                .get("consensus:finalized_round")
                .ok()
                .flatten()
                .unwrap_or_else(|| "0".to_string()),
            last_anchor_round: self
                .storage
                .get("consensus:last_anchor_round")
                .ok()
                .flatten()
                .unwrap_or_else(|| "0".to_string()),
            last_anchor_hash: self
                .storage
                .get("consensus:last_anchor_hash")
                .ok()
                .flatten()
                .unwrap_or_default(),
            finality_digest: self
                .storage
                .get("consensus:finality_digest")
                .ok()
                .flatten()
                .unwrap_or_default(),
            // Serve the quorum certificate so peers can cryptographically VERIFY
            // (not trust) the finality we advertise.
            qc: self
                .storage
                .get("consensus:qc:latest")
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<consensus::qc::QuorumCertificate>(&j).ok()),
        }
    }

    /// The trusted validator set that a finality QC is verified against. SEC-#16:
    /// resolved by the QC's epoch (`sys:validator_set:epoch:{epoch}`, the snapshot
    /// frozen at that epoch's start) so a QC produced in an earlier epoch still
    /// verifies against the set that produced it; falls back to the live set.
    fn trusted_validator_set(&self, epoch: u64) -> Option<Vec<consensus::qc::ValidatorInfo>> {
        consensus::qc_producer::load_validator_set_for_epoch(&self.storage, epoch)
    }

    /// Apply a finality artifact — QC-GATED.
    ///
    /// SECURITY: only a quorum certificate that verifies (>2/3-stake aggregate
    /// BLS signature over the canonical FinalityVote) against our trusted
    /// validator set may advance `consensus:finalized_round`. The previous
    /// round-drift heuristic was forgeable: an unsigned `block.header.round`
    /// (blocks carry no proposer signature) could inflate the accepted round and
    /// poison `consensus:finalized_round`, halting a validator. With QC-gating a
    /// peer cannot move our finalized round without the validators' aggregate
    /// signature; a peer that supplies no/invalid QC simply does not advance our
    /// finality (a no-op, not a failure).
    fn apply_finality_artifact(&self, artifact: &FinalityArtifact) -> Result<(), String> {
        let Some(qc) = artifact.qc.as_ref() else {
            return Ok(()); // pre-QC peer: cannot move our finality, harmless
        };
        let validators = match self.trusted_validator_set(qc.epoch) {
            Some(v) => v,
            None => return Ok(()), // no trusted set to verify against — skip
        };
        consensus::qc::verify_qc(qc, &validators, &consensus::qc::expected_chain_id())
            .map_err(|e| format!("finality QC verification failed: {:?}", e))?;

        let remote_finalized = qc.finalized_round;
        if remote_finalized == 0 || remote_finalized <= self.finalized_round_boundary() {
            return Ok(()); // not newer than what we already hold
        }
        if qc.anchor_round > remote_finalized {
            return Err(format!(
                "QC anchor round {} exceeds finalized round {}",
                qc.anchor_round, remote_finalized
            ));
        }

        // SEC-#6/#24: bind finality to the block this node actually holds. The QC
        // certifies (block_height, block_hash); only advance finality if we have
        // that EXACT block locally. Otherwise the finalized marker could outrun or
        // diverge from our canonical chain — precisely what light clients/bridges
        // trust the QC to prevent. (qc.block_hash == the committed block's
        // header.hash; see dag.rs CommitContext.)
        let local_block_key = format!("block_{}", qc.block_height);
        match self.storage.get(&local_block_key).ok().flatten() {
            Some(json) => match serde_json::from_str::<Block>(&json) {
                Ok(b) if b.header.hash == qc.block_hash => { /* certified block held — ok */ }
                Ok(b) => {
                    return Err(format!(
                        "🚨 [SECURITY] finality QC block_hash {} != local block_{} hash {} — refusing to advance",
                        qc.block_hash, qc.block_height, b.header.hash
                    ));
                }
                Err(e) => {
                    return Err(format!("local block_{} unparsable: {}", qc.block_height, e));
                }
            },
            None => {
                // We do not yet hold the certified block (still catching up).
                // Do NOT advance finality past a block we don't have (#24);
                // this re-runs after block sync delivers it.
                return Ok(());
            }
        }

        self.storage
            .put("consensus:finalized_round", &remote_finalized.to_string())
            .map_err(|e| format!("persist finalized_round failed: {}", e))?;
        self.storage
            .put("consensus:last_anchor_round", &qc.anchor_round.to_string())
            .map_err(|e| format!("persist last_anchor_round failed: {}", e))?;
        self.storage
            .put("consensus:last_anchor_hash", &qc.anchor_hash)
            .map_err(|e| format!("persist last_anchor_hash failed: {}", e))?;
        self.storage
            .put("consensus:finality_digest", &qc.finality_digest)
            .map_err(|e| format!("persist finality_digest failed: {}", e))?;
        // Persist the verified QC so this node can serve the proof onward.
        if let Ok(j) = serde_json::to_string(qc) {
            let _ = self.storage.put("consensus:qc:latest", &j);
        }

        println!(
            "✅ [ChainSync] Applied QC-verified finality: round={} (signed_stake={}/{})",
            remote_finalized, qc.signed_stake, qc.total_stake
        );
        Ok(())
    }

    fn rollback_to_height(&self, target_height: u64) -> Result<(), String> {
        let current_height = self.storage.get_chain_height();
        if target_height >= current_height {
            return Ok(());
        }

        for h in ((target_height + 1)..=current_height).rev() {
            let key = format!("block_{}", h);
            self.storage
                .delete(&key)
                .map_err(|e| format!("rollback delete failed at {}: {}", h, e))?;
        }

        let (new_hash, new_height) = if target_height == 0 {
            ("genesis".to_string(), 0u64)
        } else {
            let key = format!("block_{}", target_height);
            let hash = self
                .storage
                .get(&key)
                .ok()
                .flatten()
                .and_then(|json| serde_json::from_str::<Block>(&json).ok())
                .map(|b| b.header.hash)
                .ok_or_else(|| format!("rollback target block {} missing", target_height))?;
            (hash, target_height)
        };

        self.storage
            .put("latest_height", &new_height.to_string())
            .map_err(|e| format!("rollback latest_height update failed: {}", e))?;
        self.storage
            .put("latest_block_hash", &new_hash)
            .map_err(|e| format!("rollback latest_block_hash update failed: {}", e))?;
        Ok(())
    }

    /// Unified Sync: Uses Persistent Encrypted Connection
    /// Returns the final synced height (0 if no sync happened)
    pub async fn sync_from_peers(&self) -> u64 {
        println!("🔄 [ChainSync] Starting Encrypted P2P Sync...");

        // Audit #3: a prior state-root divergence must ACTUALLY stop syncing —
        // otherwise the node loops, re-executing onto already-divergent state.
        // `sync:halt_reason` is set by process_blocks on a state-root mismatch;
        // refuse to sync while it is present. The operator clears it (deletes the
        // key) after investigating (a state divergence is usually a node-binary
        // mismatch against the seed).
        if let Ok(Some(reason)) = self.storage.get("sync:halt_reason") {
            eprintln!(
                "🛑 [ChainSync] HALTED after a state divergence: {reason} — not syncing. \
                 Investigate, then clear `sync:halt_reason` to resume."
            );
            return self.get_local_height();
        }

        let peers_map = self.peers.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if peers_map.is_empty() {
            println!("📡 [ChainSync] No peers available.");
            return 0;
        }

        let my_height = self.get_local_height();
        println!("📊 [ChainSync] Local Height: {}", my_height);
        let mut final_height = my_height;

        // TASK-#29 (1) SEED PREFERENCE: the trusted fallback-seed set is the active
        // validator set. Try seed/validator peers FIRST so the sync is anchored on a
        // trusted source rather than whichever peer HashMap iteration happened to
        // surface first.
        let seed_set = self.active_validator_addresses();
        let ordered_peers = Self::order_peers_seed_first(&peers_map, &seed_set);

        // TASK-#29 (2) N-PEER TIP AGREEMENT: when configured to require more than one
        // seed (sys:config:tip_agreement_n > 1), demand that >= N distinct seed peers
        // advertise a CONSISTENT, individually-verifiable finalized tip before we sync
        // past it. On disagreement we refuse to advance. This is an ADDITIONAL gate on
        // top of the per-artifact QC crypto backstop in apply_finality_artifact — it is
        // not a replacement for it.
        let tip_n = self.tip_agreement_n();
        if tip_n > 1 {
            match self
                .gather_and_check_seed_tips(&ordered_peers, &seed_set, tip_n)
                .await
            {
                Ok((height, hash)) => {
                    println!(
                        "✅ [ChainSync] Tip agreement reached: {} seeds agree on finalized tip height={} hash={}",
                        tip_n, height, hash
                    );
                }
                Err(e) => {
                    eprintln!("🚨 [SECURITY][TIP_DISAGREEMENT] {} — refusing to advance", e);
                    return final_height;
                }
            }
        }

        for (peer_id, peer_port) in ordered_peers.iter() {
            let Some(peer_ip) = self.storage.get_peer_ip(peer_id) else {
                // Inbound peers behind Docker/NAT are useful as live sessions, but
                // their accepted socket source is not a routable sync target. Only
                // outbound handshakes persist peer_ip; skip session-only peers here
                // instead of trying 127.0.0.1:<peer_port> and spamming refused logs.
                continue;
            };

            // Skip self-dials and bogus loopback entries. A stale peer record
            // pointing at our own port (e.g. 127.0.0.1:<my_port>) just wastes a
            // connect + handshake cycle and spams the log; it can never sync us.
            let is_loopback = peer_ip == "127.0.0.1" || peer_ip == "localhost" || peer_ip == "::1";
            if is_loopback && *peer_port == self.my_port {
                continue;
            }

            println!(
                "🌐 [ChainSync] Connecting to {} ({}:{})...",
                peer_id, peer_ip, peer_port
            );

            // 1. Establish Secure Connection (With MitM Check)
            use rand::rngs::OsRng;
            let mut csprng = OsRng;
            let ephemeral_signing_key = crypto::SigningKey::generate(&mut csprng);

            match secure_connect(
                &peer_ip,
                *peer_port,
                "__sync__",
                self.my_port,
                Some(peer_id),
                &ephemeral_signing_key,
            )
            .await
            {
                Ok((mut stream, shared_key, _peer_node_id)) => {
                    println!("🔐 Secure Channel Established with {}", peer_id);

                    // 2. Request Chain Height
                    let req_msg = "GET_HEIGHT".to_string();
                    if send_encrypted_msg(&mut stream, &shared_key, &req_msg)
                        .await
                        .is_err()
                    {
                        continue;
                    }

                    if let Ok(resp) = read_encrypted_msg(&mut stream, &shared_key).await {
                        // Parse Height response e.g. "HEIGHT:100"
                        if let Some(h_str) = resp.strip_prefix("HEIGHT:") {
                            if let Ok(peer_height) = h_str.trim().parse::<u64>() {
                                println!("📊 [ChainSync] Peer Height: {}", peer_height);

                                if peer_height > my_height {
                                    // 3. Request Blocks — loop in batches until caught up
                                    let mut current = my_height;
                                    while current < peer_height {
                                        let sync_req = SyncRequest {
                                            from_height: current,
                                            sender_id: self.node_id.clone(),
                                            sender_port: self.my_port,
                                        };
                                        let req_json = match serde_json::to_string(&sync_req) {
                                            Ok(j) => j,
                                            Err(e) => {
                                                eprintln!(
                                                    "❌ [ChainSync] Failed to serialize sync request: {}",
                                                    e
                                                );
                                                break;
                                            }
                                        };
                                        let msg = format!("SYNC_REQ:{}", req_json);

                                        if send_encrypted_msg(&mut stream, &shared_key, &msg)
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }

                                        // 4. Receive Blocks Batch
                                        match read_encrypted_msg(&mut stream, &shared_key).await {
                                            Ok(data_resp) => {
                                                if let Some(json_data) =
                                                    data_resp.strip_prefix("SYNC_RESP:")
                                                {
                                                    if let Ok(sync_resp) =
                                                        serde_json::from_str::<SyncResponse>(
                                                            json_data,
                                                        )
                                                    {
                                                        let finality = sync_resp.finality.clone();
                                                        if sync_resp.blocks.is_empty() {
                                                            if let Some(finality) = finality {
                                                                if let Err(e) = self
                                                                    .apply_finality_artifact(
                                                                        &finality,
                                                                    )
                                                                {
                                                                    eprintln!(
                                                                        "🚨 [SECURITY][SYNC_FINALITY_REJECT] {}",
                                                                        e
                                                                    );
                                                                }
                                                            }
                                                            // Below the peer's prune horizon: block-replay
                                                            // cannot bridge this gap. Surface it clearly
                                                            // instead of looping silently on empty replies.
                                                            if let Some(horizon) = sync_resp.prune_horizon {
                                                                let local_now = self.get_local_height();
                                                                if horizon > local_now + 1 {
                                                                    eprintln!(
                                                                        "🛑 [ChainSync] peer pruned below us: earliest block #{} but we are at #{}. \
                                                                         Block-replay cannot bridge this — bootstrap from a state snapshot \
                                                                         (set AINCORE_BOOTSTRAP_SNAPSHOT on a fresh datadir, or run testnet-join.sh).",
                                                                        horizon, local_now
                                                                    );
                                                                }
                                                            }
                                                            break; // No more blocks
                                                        }
                                                        let synced = self.process_blocks(
                                                            sync_resp.blocks,
                                                            current,
                                                        );
                                                        if synced <= current {
                                                            eprintln!(
                                                                "⚠️ [ChainSync] Batch made no progress from height {}",
                                                                current
                                                            );
                                                            break; // No progress made
                                                        }
                                                        current = synced;
                                                        final_height = synced;
                                                        if let Some(finality) = finality {
                                                            if let Err(e) = self
                                                                .apply_finality_artifact(&finality)
                                                            {
                                                                eprintln!(
                                                                    "🚨 [SECURITY][SYNC_FINALITY_REJECT] {}",
                                                                    e
                                                                );
                                                            }
                                                        }
                                                    } else {
                                                        eprintln!(
                                                            "❌ [ChainSync] Failed to parse SYNC_RESP JSON ({} bytes)",
                                                            json_data.len()
                                                        );
                                                        break;
                                                    }
                                                } else {
                                                    eprintln!(
                                                        "❌ [ChainSync] Unexpected sync response prefix: {}",
                                                        data_resp
                                                            .chars()
                                                            .take(80)
                                                            .collect::<String>()
                                                    );
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "❌ [ChainSync] Failed to read SYNC_RESP from {}: {}",
                                                    peer_id, e
                                                );
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    println!(
                                        "✅ [ChainSync] Already caught up with peer {}",
                                        peer_id
                                    );
                                }

                                if send_encrypted_msg(&mut stream, &shared_key, "GET_FINALITY")
                                    .await
                                    .is_ok()
                                {
                                    if let Ok(finality_resp) =
                                        read_encrypted_msg(&mut stream, &shared_key).await
                                    {
                                        if let Some(json) = finality_resp.strip_prefix("FINALITY:")
                                        {
                                            if let Ok(artifact) =
                                                serde_json::from_str::<FinalityArtifact>(json)
                                            {
                                                if let Err(e) =
                                                    self.apply_finality_artifact(&artifact)
                                                {
                                                    eprintln!(
                                                        "🚨 [SECURITY][SYNC_FINALITY_REJECT] {}",
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ Connection Failed to {}: {}", peer_id, e);
                }
            }
        }
        final_height
    }

    /// TASK-#29: fetch one peer's advertised finalized tip and return its QC iff the
    /// QC is cryptographically verifiable against our trusted validator set for the
    /// QC's epoch (the SAME crypto backstop used by apply_finality_artifact). A peer
    /// that supplies no QC, an unverifiable QC, or no reachable channel contributes
    /// nothing to tip agreement (returns None) — it cannot dilute the gate.
    async fn fetch_verified_tip(
        &self,
        peer_id: &str,
        peer_ip: &str,
        peer_port: u16,
    ) -> Option<consensus::qc::QuorumCertificate> {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let ephemeral_signing_key = crypto::SigningKey::generate(&mut csprng);

        let (mut stream, shared_key, _peer_node_id) = secure_connect(
            peer_ip,
            peer_port,
            "__sync__",
            self.my_port,
            Some(peer_id),
            &ephemeral_signing_key,
        )
        .await
        .ok()?;

        send_encrypted_msg(&mut stream, &shared_key, "GET_FINALITY")
            .await
            .ok()?;
        let resp = read_encrypted_msg(&mut stream, &shared_key).await.ok()?;
        let json = resp.strip_prefix("FINALITY:")?;
        let artifact = serde_json::from_str::<FinalityArtifact>(json).ok()?;
        let qc = artifact.qc?;

        // Verify the QC against the trusted validator set for its epoch. Only a
        // verifiable QC counts toward agreement (the crypto backstop is preserved).
        let validators = self.trusted_validator_set(qc.epoch)?;
        match consensus::qc::verify_qc(&qc, &validators, &consensus::qc::expected_chain_id()) {
            Ok(()) => Some(qc),
            Err(_) => None,
        }
    }

    /// TASK-#29 (2): poll seed peers for their finalized tips and require >= `n`
    /// distinct seed peers to advertise a CONSISTENT, individually-verifiable tip.
    /// Returns the agreed `(block_height, block_hash)` or an `Err` the caller turns
    /// into a `🚨 [SECURITY][TIP_DISAGREEMENT]` refusal. Only peers in `seed_set`
    /// (the trusted validator set) are polled — a random peer cannot vote on the tip.
    async fn gather_and_check_seed_tips(
        &self,
        ordered_peers: &[(String, u16)],
        seed_set: &[String],
        n: usize,
    ) -> Result<(u64, String), String> {
        let is_seed = |id: &str| seed_set.iter().any(|s| s == id);
        let mut tips: Vec<consensus::qc::QuorumCertificate> = Vec::new();

        for (peer_id, peer_port) in ordered_peers.iter() {
            if !is_seed(peer_id) {
                continue;
            }
            let Some(peer_ip) = self.storage.get_peer_ip(peer_id) else {
                continue; // session-only peer without a routable IP
            };
            let is_loopback =
                peer_ip == "127.0.0.1" || peer_ip == "localhost" || peer_ip == "::1";
            if is_loopback && *peer_port == self.my_port {
                continue; // self-dial
            }
            if let Some(qc) = self.fetch_verified_tip(peer_id, &peer_ip, *peer_port).await {
                tips.push(qc);
                // Enough verified tips collected to satisfy the gate even in the
                // unanimous case — stop polling (no point hammering more seeds).
                if tips.len() >= n {
                    // Keep going only if we still might not agree; but a quick exit
                    // once we have n verified tips is fine because the decision below
                    // tolerates extra entries. Break to bound network work.
                    break;
                }
            }
        }

        Self::tip_agreement_decision(&tips, n)
    }

    /// Process synced blocks — returns the final height reached
    fn process_blocks(&self, blocks: Vec<Block>, current_height: u64) -> u64 {
        let mut last_processed = current_height;
        let executor = executor::Executor::new(std::sync::Arc::clone(&self.storage));
        let total_blocks = blocks.len();
        let finalized_round = self.finalized_round_boundary();

        // AUDIT-H2 (verify-before-execute, QC pin): `consensus:qc:latest` is only
        // ever written AFTER apply_finality_artifact has cryptographically
        // verified a quorum certificate (chain-id + trusted-validator-set bound)
        // — so its (block_height, block_hash) is an AUTHENTICATED pin. If this
        // downloaded batch claims to contain the certified height, its block
        // there MUST carry the certified hash; a mismatch proves the peer is
        // serving a fabricated chain, and the ENTIRE batch is rejected BEFORE a
        // single transaction of it executes. Blocks above the pin (not yet
        // certified) keep today's defense (execute + re-derived-root check +
        // reject), and the executor's own signature/nonce gates bound what an
        // unauthenticated block can do. This closes H-2's "forged block executes
        // first, gets rejected after" window for everything at or below the
        // latest certified height.
        if let Ok(Some(qc_json)) = self.storage.get("consensus:qc:latest") {
            if let Ok(qc) = serde_json::from_str::<consensus::qc::QuorumCertificate>(&qc_json) {
                if let Some(b) = blocks.iter().find(|b| b.header.height == qc.block_height) {
                    if b.header.hash != qc.block_hash {
                        eprintln!(
                            "🚨 [SECURITY][SYNC_QC_PIN_REJECT] peer's block #{} hash {} does not \
                             match the QC-certified hash {} — rejecting the whole batch before \
                             execution (fabricated chain)",
                            qc.block_height, b.header.hash, qc.block_hash
                        );
                        return last_processed;
                    }
                }
            }
        }

        for (i, block) in blocks.iter().enumerate() {
            if block.header.height <= last_processed {
                let key = format!("block_{}", block.header.height);
                if let Ok(Some(existing_json)) = self.storage.get(&key) {
                    if let Ok(existing) = serde_json::from_str::<Block>(&existing_json) {
                        if existing.header.hash == block.header.hash {
                            continue;
                        }
                        if existing.header.round <= finalized_round
                            || block.header.round <= finalized_round
                        {
                            eprintln!(
                                "🚨 [SECURITY][SYNC_REORG_REJECT] conflict at finalized boundary height={} local_round={} remote_round={} finalized_round={}",
                                block.header.height,
                                existing.header.round,
                                block.header.round,
                                finalized_round
                            );
                            break;
                        }
                        let rollback_target = block.header.height.saturating_sub(1);
                        // SEC-#8: `rollback_to_height` only deletes block records and resets the
                        // height/hash pointers — it does NOT revert the Move/executor state writes
                        // (CoinStore balances, staking, arbitrary resources) made by the orphaned
                        // blocks. Re-executing the new fork over that un-reverted state silently
                        // diverges this node from one that never saw the orphan (last-write-wins
                        // leaves orphan-only resources behind). Until a full per-height state-undo
                        // log exists, refuse to silently reorg across state-changing blocks: halt
                        // for operator re-bootstrap from a snapshot. Empty (no-tx) orphans carry no
                        // state and are safe to roll back + re-execute.
                        let stored_tip = self.storage.get_chain_height();
                        let mut state_changing_orphan = false;
                        for h in (rollback_target + 1)..=stored_tip {
                            let k = format!("block_{}", h);
                            if let Ok(Some(j)) = self.storage.get(&k) {
                                if let Ok(b) = serde_json::from_str::<Block>(&j) {
                                    if !b.transactions.is_empty() {
                                        state_changing_orphan = true;
                                        break;
                                    }
                                }
                            }
                        }
                        if state_changing_orphan {
                            // SEC (audit C-2/H-3 sibling): the competing chain that would
                            // orphan state-changing committed blocks arrived over the
                            // UNAUTHENTICATED sync path (forgeable by any peer). Do NOT
                            // latch a persistent, node-wide `sync:halt_reason` — that is
                            // the same remote permanent-halt DoS the H-3 exec-root fix
                            // removed, just reachable through the reorg branch. REJECT the
                            // reorg (never roll back to an unauthenticated fork) and stop
                            // consuming this peer's batch; the node keeps its current
                            // QC-finality-backed chain intact (no state corruption, since
                            // we do NOT roll back). A genuine reorg above the finalized
                            // boundary cannot occur for a node following QC-gated finality.
                            eprintln!(
                                "🚨 [SECURITY][SYNC_REORG_REJECT] refusing unauthenticated state-changing reorg at height {} (orphaning {}..={}) from this peer (not halting)",
                                block.header.height,
                                rollback_target + 1,
                                stored_tip
                            );
                            break;
                        }
                        if let Err(err) = self.rollback_to_height(rollback_target) {
                            eprintln!("🚨 [SECURITY][SYNC_ROLLBACK_FAIL] {}", err);
                            break;
                        }
                        last_processed = rollback_target;
                    } else {
                        eprintln!(
                            "🚨 [SECURITY][SYNC_REORG_REJECT] corrupt local block json at height {}",
                            block.header.height
                        );
                        break;
                    }
                } else {
                    continue;
                }
            }

            let expected_height = last_processed + 1;
            let prev_hash = if expected_height > 1 {
                let prev_key = format!("block_{}", last_processed);
                match self
                    .storage
                    .get(&prev_key)
                    .ok()
                    .flatten()
                    .and_then(|json| serde_json::from_str::<Block>(&json).ok())
                    .map(|b| b.header.hash)
                {
                    Some(hash) => hash,
                    None => {
                        eprintln!(
                            "🚨 [SECURITY] Cannot verify parent for block #{}: missing local block #{}",
                            expected_height, last_processed
                        );
                        break;
                    }
                }
            } else {
                "genesis".to_string()
            };

            if let Err(e) = self.validate_block(block, expected_height, &prev_hash) {
                eprintln!(
                    "🚨 [SECURITY] Block #{} validation FAILED: {}",
                    block.header.height, e
                );
                break;
            }

            // Execute transactions through the VM/Executor
            let execution_summary = executor
                .execute_block_parallel_at(
                    block.transactions.clone(),
                    &block.header.proposer_id,
                    // The synced block's own height (epoch determinism — see
                    // executor::execute_block_parallel_at).
                    block.header.height,
                );
            if let Err(e) = self.verify_execution_roots(block, &execution_summary) {
                // SEC (audit H-3): synced blocks are UNAUTHENTICATED (no proposer
                // signature — only a self-referential header hash + a public proposer_id
                // string). A re-execution-root mismatch is EXPECTED adversarial input
                // from a malicious peer, NOT proof of local divergence — so it must NOT
                // latch a persistent, node-wide `sync:halt_reason` that survives restart
                // and needs manual operator intervention. A single forged block from any
                // peer could otherwise permanently halt the node (remote DoS). Reject
                // this block and stop consuming THIS peer's batch; the QC-gated finality
                // path (apply_finality_artifact + chain_id/set-bound verify_qc) remains
                // the authenticated crypto backstop.
                //
                // RESIDUAL (tracked): the complete remediation authenticates blocks
                // BEFORE execution (a verifiable QC covering the block, or a proposer
                // vertex signature) so a forged block never executes at all — a block-
                // format change, out of scope here.
                eprintln!(
                    "🚨 [SECURITY][SYNC_EXECUTION_ROOT_REJECT] rejecting divergent/forged block #{} from this peer (not halting): {}",
                    block.header.height, e
                );
                break;
            }

            if let Ok(json) = serde_json::to_string(&block) {
                // save_block_json now atomically updates height + hash
                if let Err(e) = self.storage.save_block_json(block.header.height, &json) {
                    eprintln!("❌ DB Error: {}", e);
                } else {
                    last_processed = block.header.height;
                }
            }

            // Progress logging for large syncs
            if total_blocks > 10 && (i + 1) % 50 == 0 {
                println!(
                    "📦 [ChainSync] Progress: {}/{} blocks processed",
                    i + 1,
                    total_blocks
                );
            }
        }
        if last_processed > current_height {
            println!(
                "✅ [ChainSync] Synced up to block #{} (+{} blocks)",
                last_processed,
                last_processed - current_height
            );
        }
        last_processed
    }

    /// Handle incoming encrypted message (called by Network Server Handler)
    pub fn handle_message(&self, msg: &str) -> Option<String> {
        // Handle Request Logic
        if msg == "GET_HEIGHT" {
            let h = self.get_local_height();
            return Some(format!("HEIGHT:{}", h));
        }

        if msg == "GET_FINALITY" {
            if let Ok(json) = serde_json::to_string(&self.collect_finality_artifact()) {
                return Some(format!("FINALITY:{}", json));
            }
            return None;
        }

        if let Some(req_json) = msg.strip_prefix("SYNC_REQ:") {
            if let Ok(req) = serde_json::from_str::<SyncRequest>(req_json) {
                let resp = self.handle_sync_request(req);
                if let Ok(resp_json) = serde_json::to_string(&resp) {
                    return Some(format!("SYNC_RESP:{}", resp_json));
                }
            }
        }
        None
    }

    pub fn handle_sync_request(&self, req: SyncRequest) -> SyncResponse {
        let mut blocks_to_send = Vec::new();
        let local_height = self.get_local_height();

        // Limit batch size to avoid huge messages (Optimized to 500 for Production Performance)
        let end_height = std::cmp::min(local_height, req.from_height + 500);

        for height in (req.from_height + 1)..=end_height {
            let key = format!("block_{}", height);
            if let Ok(Some(block_data)) = self.storage.get(&key) {
                if let Ok(block) = serde_json::from_str::<Block>(&block_data) {
                    blocks_to_send.push(block);
                }
            }
        }
        // Prune-horizon signal (audit #9): trigger whenever the FIRST requested
        // block is missing — not only when the whole batch is empty. Otherwise a
        // request whose start is pruned but whose tail (e.g. from_height+50)
        // still exists returns non-empty blocks the requester cannot apply (height
        // gap) AND no signal, so it never learns it must state-sync.
        let first_block_pruned = req.from_height < local_height
            && self
                .storage
                .get(&format!("block_{}", req.from_height + 1))
                .ok()
                .flatten()
                .is_none();
        let prune_horizon = if first_block_pruned {
            Some(self.earliest_available_block(req.from_height + 1, local_height))
        } else {
            None
        };
        SyncResponse {
            blocks: blocks_to_send,
            finality: Some(self.collect_finality_artifact()),
            prune_horizon,
        }
    }

    /// Lowest block height still present, searched within `[lo, hi]`. After
    /// prefix-pruning, block existence is monotonic (absent below the horizon,
    /// present from it to the tip), so a binary search finds the horizon.
    fn earliest_available_block(&self, lo: u64, hi: u64) -> u64 {
        let exists = |h: u64| {
            self.storage
                .get(&format!("block_{}", h))
                .ok()
                .flatten()
                .is_some()
        };
        if exists(lo) {
            return lo;
        }
        let (mut lo, mut hi) = (lo, hi);
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if exists(mid) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    }

    // Legacy Handler for compatibility if needed
    pub fn handle_sync_response(&self, _resp: SyncResponse) {
        // No-op in new pull model
    }
}

#[cfg(test)]
mod tests;
