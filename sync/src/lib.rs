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
}

pub struct ChainSync {
    node_id: String,
    my_port: u16,
    peers: Arc<Mutex<HashMap<String, u16>>>,
    storage: Arc<StateDB>,
}

impl ChainSync {
    const FINALITY_ROUND_DRIFT_LIMIT: u64 = 1_000;

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
        Ok(())
    }

    fn get_local_height(&self) -> u64 {
        self.storage.get_chain_height()
    }

    /// Round of the latest locally-synced block (0 if none).
    ///
    /// Finality is measured in ROUNDS, not block height. The drift guard in
    /// `apply_finality_artifact` must compare a remote finalized ROUND against
    /// our latest synced ROUND — comparing it against block HEIGHT was a bug:
    /// rounds outrun height on a live chain (empty/skipped rounds produce no
    /// block), so once the round−height gap exceeded the limit the guard
    /// rejected EVERY finality artifact, freezing observers'
    /// `consensus:finalized_round` forever.
    fn local_latest_round(&self) -> u64 {
        let h = self.get_local_height();
        if h == 0 {
            return 0;
        }
        self.storage
            .get(&format!("block_{}", h))
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<Block>(&json).ok())
            .map(|b| b.header.round)
            .unwrap_or(0)
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
        }
    }

    fn apply_finality_artifact(&self, artifact: &FinalityArtifact) -> Result<(), String> {
        let remote_finalized = artifact
            .finalized_round
            .parse::<u64>()
            .map_err(|_| "remote finalized_round is not numeric".to_string())?;
        let remote_anchor = artifact
            .last_anchor_round
            .parse::<u64>()
            .map_err(|_| "remote last_anchor_round is not numeric".to_string())?;

        if remote_finalized == 0 {
            return Ok(());
        }
        if remote_anchor > remote_finalized {
            return Err(format!(
                "remote finality anchor {} exceeds finalized round {}",
                remote_anchor, remote_finalized
            ));
        }
        if artifact.finality_digest.is_empty() {
            return Err("remote finality digest is empty".to_string());
        }

        let local_finalized = self.finalized_round_boundary();
        if remote_finalized <= local_finalized {
            return Ok(());
        }

        // Compare ROUND↔ROUND (not round↔height): only accept finality within
        // FINALITY_ROUND_DRIFT_LIMIT of the latest ROUND we have actually synced.
        // This still blocks a peer from fast-forwarding us to an unsynced round,
        // but no longer spuriously rejects legitimate finality once the chain's
        // round−height gap grows.
        let local_round = self.local_latest_round();
        if remote_finalized > local_round + Self::FINALITY_ROUND_DRIFT_LIMIT {
            return Err(format!(
                "remote finality round {} is too far beyond local synced round {}",
                remote_finalized, local_round
            ));
        }

        self.storage
            .put("consensus:finalized_round", &artifact.finalized_round)
            .map_err(|e| format!("persist finalized_round failed: {}", e))?;
        self.storage
            .put("consensus:last_anchor_round", &artifact.last_anchor_round)
            .map_err(|e| format!("persist last_anchor_round failed: {}", e))?;
        self.storage
            .put("consensus:last_anchor_hash", &artifact.last_anchor_hash)
            .map_err(|e| format!("persist last_anchor_hash failed: {}", e))?;
        self.storage
            .put("consensus:finality_digest", &artifact.finality_digest)
            .map_err(|e| format!("persist finality_digest failed: {}", e))?;

        println!(
            "✅ [ChainSync] Applied finality artifact: finalized_round={} anchor_round={}",
            artifact.finalized_round, artifact.last_anchor_round
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

        let peers_map = self.peers.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if peers_map.is_empty() {
            println!("📡 [ChainSync] No peers available.");
            return 0;
        }

        let my_height = self.get_local_height();
        println!("📊 [ChainSync] Local Height: {}", my_height);
        let mut final_height = my_height;

        for (peer_id, peer_port) in peers_map.iter() {
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
                                                                if horizon > my_height + 1 {
                                                                    eprintln!(
                                                                        "🛑 [ChainSync] peer pruned below us: earliest block #{} but we are at #{}. \
                                                                         Block-replay cannot bridge this — bootstrap from a state snapshot \
                                                                         (set AINCORE_BOOTSTRAP_SNAPSHOT on a fresh datadir, or run testnet-join.sh).",
                                                                        horizon, my_height
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

    /// Process synced blocks — returns the final height reached
    fn process_blocks(&self, blocks: Vec<Block>, current_height: u64) -> u64 {
        let mut last_processed = current_height;
        let executor = executor::Executor::new(std::sync::Arc::clone(&self.storage));
        let total_blocks = blocks.len();
        let finalized_round = self.finalized_round_boundary();

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
                .execute_block_parallel(block.transactions.clone(), &block.header.proposer_id);
            if let Err(e) = self.verify_execution_roots(block, &execution_summary) {
                eprintln!("🚨 [SECURITY][SYNC_EXECUTION_ROOT_REJECT] {}", e);
                let _ = self.storage.put("sync:halt_reason", &e);
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
        // Prune-horizon signal: the requester asked for a range we should have
        // (from_height < local_height) but we returned nothing — those blocks
        // were pruned. Tell it the lowest height we can still serve so it
        // bootstraps from a state snapshot rather than looping on empty replies.
        let prune_horizon = if blocks_to_send.is_empty() && req.from_height < local_height {
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
