use log::{error, info, warn};
use reqwest::Client;
use serde::Deserialize;
use std::error::Error;

// CRITICAL-5 FIX: Finality depth to prevent reorg attacks
const FINALITY_DEPTH: u64 = 100; // Wait for 100 block confirmations (~20 minutes)

#[derive(Debug, Clone)]
pub struct AincoreClient {
    rpc_url: String,
    client: Client,
    last_processed_height: u64, // Track last processed finalized block
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Default, Deserialize)]
pub struct BlockHeader {
    // SEC-#18: bind bridge events to the block's hash so they can be checked
    // against a quorum certificate (by scan height) before the bridge acts.
    #[serde(default)]
    pub hash: String,
}

#[derive(Debug, Deserialize)]
pub struct Block {
    #[serde(default)]
    pub header: BlockHeader,
    pub transactions: Vec<String>, // Simplified: Txs are JSON strings in payload
}

/// SEC-#18: pure decision for whether a `aincore_getQuorumCertificate` response
/// proves the given block is finalized. The block is accepted ONLY if the node
/// reports the QC available AND independently verified (>2/3-stake aggregate BLS),
/// AND the QC binds to exactly this `(height, hash)`. Extracted so the gate logic
/// is unit-testable without a live RPC.
fn qc_response_confirms(result: &serde_json::Value, height: u64, expected_hash: &str) -> bool {
    if expected_hash.is_empty() {
        return false;
    }
    if !result.get("available").and_then(|v| v.as_bool()).unwrap_or(false) {
        return false;
    }
    if !result.get("verified").and_then(|v| v.as_bool()).unwrap_or(false) {
        return false;
    }
    let Some(qc) = result.get("quorum_certificate") else {
        return false;
    };
    let qc_height = qc.get("block_height").and_then(|v| v.as_u64());
    let qc_hash = qc.get("block_hash").and_then(|v| v.as_str());
    qc_height == Some(height) && qc_hash == Some(expected_hash)
}

#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub payload: String,
    #[allow(dead_code)]
    pub signature: String,
}

/// Phase 3.5 fix: Bridge event with full context for dedup uniqueness.
/// `(sender, amount, eth_addr, block_height, tx_index_in_block)`
pub type BridgeEvent = (String, u64, String, u64, usize);

impl AincoreClient {
    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_url,
            client: Client::new(),
            last_processed_height: 0,
        }
    }

    /// Phase 3 / H-03: Restore height cursor from persisted BridgeState so
    /// the client does not re-scan blocks already processed before a restart.
    pub fn set_last_processed_height(&mut self, height: u64) {
        self.last_processed_height = height;
    }

    /// Return the cursor after the latest fetch_bridge_events call.
    pub fn get_last_processed_height(&self) -> u64 {
        self.last_processed_height
    }

    /// Legacy "latest N blocks" fetch. After Phase 3.5 the bridge uses
    /// `get_blocks_range()` exclusively (range-based to avoid backlog skip),
    /// but this remains for ad-hoc operator queries and explorer integrations.
    #[allow(dead_code)]
    pub async fn get_latest_blocks(&self, limit: u64) -> Result<Vec<Block>, Box<dyn Error>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "aincore_getBlocks",
            "params": [limit],
            "id": 1
        });

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?;

        let rpc_resp: RpcResponse<Vec<Block>> = resp.json().await?;

        if let Some(err) = rpc_resp.error {
            error!("RPC Error: {:?}", err);
            return Ok(vec![]);
        }

        Ok(rpc_resp.result.unwrap_or_default())
    }

    /// Phase 3.5 / H-03 fix: fetch a specific range of blocks (ascending order).
    /// This is the correct primitive for catching up on bridge backlog without
    /// losing blocks. `start_height` is inclusive; up to `limit` blocks returned.
    pub async fn get_blocks_range(
        &self,
        start_height: u64,
        limit: u64,
    ) -> Result<Vec<Block>, Box<dyn Error>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "aincore_getBlocks",
            "params": [limit, start_height],
            "id": 1
        });

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?;

        let rpc_resp: RpcResponse<Vec<Block>> = resp.json().await?;

        if let Some(err) = rpc_resp.error {
            error!("RPC Error (range): {:?}", err);
            return Ok(vec![]);
        }

        Ok(rpc_resp.result.unwrap_or_default())
    }

    /// Get latest block height from node
    pub async fn get_latest_height(&self) -> Result<u64, Box<dyn Error>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "aincore_getStatus",
            "params": [],
            "id": 1
        });

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?;

        let rpc_resp: RpcResponse<serde_json::Value> = resp.json().await?;

        if let Some(result) = rpc_resp.result
            && let Some(height) = result.get("block_height").and_then(|h| h.as_u64())
        {
            return Ok(height);
        }

        Ok(0)
    }

    /// Get finalized block height (latest - FINALITY_DEPTH)
    /// CRITICAL-5 FIX: Only process events from finalized blocks to prevent reorg attacks
    pub async fn get_finalized_height(&self) -> Result<u64, Box<dyn Error>> {
        let latest = self.get_latest_height().await?;

        let finalized = latest.saturating_sub(FINALITY_DEPTH);

        info!(
            "📊 Latest: {}, Finalized: {} (depth: {})",
            latest, finalized, FINALITY_DEPTH
        );
        Ok(finalized)
    }

    /// SEC-#18: verify that block `height` is finalized by a verified quorum
    /// certificate bound to `expected_hash`. Queries `aincore_getQuorumCertificate`
    /// and applies [`qc_response_confirms`]. Any RPC/parse failure → `false`
    /// (fail-closed: the bridge must not act on state it cannot prove final).
    pub async fn verify_block_finalized(&self, height: u64, expected_hash: &str) -> bool {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "aincore_getQuorumCertificate",
            "params": [height],
            "id": 1
        });
        let resp = match self.client.post(&self.rpc_url).json(&payload).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("⚠️ [SEC-#18] QC query failed for block {}: {}", height, e);
                return false;
            }
        };
        let rpc_resp: RpcResponse<serde_json::Value> = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!("⚠️ [SEC-#18] QC response parse failed for block {}: {}", height, e);
                return false;
            }
        };
        match rpc_resp.result {
            Some(result) => qc_response_confirms(&result, height, expected_hash),
            None => false,
        }
    }

    /// Fetch bridge events from FINALIZED blocks only.
    ///
    /// Phase 3.5 / H-03 critical fix:
    ///   1. Use range-based `get_blocks_range(start, limit)` so old blocks
    ///      are NEVER skipped on backlog. Cursor only advances by the number
    ///      of blocks actually fetched in this batch.
    ///   2. Return tuple includes `block_height` + `tx_index` so the bridge
    ///      can build a globally-unique event key (no in-batch collisions).
    ///
    /// CRITICAL-5: only processes FINALIZED blocks (no reorg risk).
    pub async fn fetch_bridge_events(&mut self) -> Result<Vec<BridgeEvent>, Box<dyn Error>> {
        let finalized_height = self.get_finalized_height().await?;

        if finalized_height <= self.last_processed_height {
            info!(
                "⏸️  No new finalized blocks (last: {}, finalized: {})",
                self.last_processed_height, finalized_height
            );
            return Ok(vec![]);
        }

        // Calculate scan window. Process in chunks of up to 100 blocks per
        // RPC call; the rest will be picked up in the next polling cycle.
        let scan_start = self.last_processed_height + 1;
        let backlog = finalized_height - self.last_processed_height;
        let chunk_size = std::cmp::min(backlog, 100);
        let scan_end = scan_start + chunk_size - 1;

        info!(
            "🔍 Scanning finalized blocks {}..={} (backlog={}, chunk={})",
            scan_start, scan_end, backlog, chunk_size
        );

        // FIX: range-based fetch — no more "latest N" silent skip.
        let blocks = self.get_blocks_range(scan_start, chunk_size).await?;

        let mut events = Vec::new();
        let mut blocks_actually_returned: u64 = 0;

        // RPC returns blocks in ASCENDING order when start_height is given.
        // Map them back to absolute heights: scan_start, scan_start+1, ...
        for (block_offset, block) in blocks.iter().enumerate() {
            let block_height = scan_start + block_offset as u64;

            // SEC-#18: require a verified QC binding this block's (height, hash) to
            // >2/3-stake finality before emitting ANY lock event from it. A node
            // that cannot prove finality cannot make the bridge mint on the far
            // chain. Stop the scan at the first unprovable block and do NOT advance
            // the cursor past it (it is retried next cycle once its QC is queryable).
            if !self.verify_block_finalized(block_height, &block.header.hash).await {
                warn!(
                    "⚠️ [SEC-#18] block {} is not QC-finalized (or hash mismatch) — halting scan; bridge will retry",
                    block_height
                );
                break;
            }
            blocks_actually_returned += 1;

            for (tx_index, tx_str) in block.transactions.iter().enumerate() {
                let tx: Transaction = match serde_json::from_str(tx_str) {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                if !tx.payload.starts_with("bridge_lock:") {
                    continue;
                }
                let parts: Vec<&str> = tx.payload.split(':').collect();
                if parts.len() != 3 {
                    continue;
                }

                let eth_addr = parts[2].to_string();
                if !eth_addr.starts_with("0x") || eth_addr.len() != 42 {
                    warn!("⚠️  Invalid Ethereum address format: {}", eth_addr);
                    continue;
                }

                let amount = match parts[1].parse::<u64>() {
                    Ok(a) => a,
                    Err(_) => continue,
                };

                info!(
                    "🌉 Bridge Lock @ block {}, tx#{}: {} AIN from {} -> {}",
                    block_height, tx_index, amount, tx.sender, eth_addr
                );
                events.push((tx.sender, amount, eth_addr, block_height, tx_index));
            }
        }

        // FIX: advance cursor by what we actually consumed, NOT to
        // finalized_height. If RPC returned fewer blocks than requested
        // we still want correct progress next call.
        if blocks_actually_returned > 0 {
            self.last_processed_height = scan_start + blocks_actually_returned - 1;
        }
        info!(
            "✅ Processed up to finalized block {} ({} events found)",
            self.last_processed_height,
            events.len()
        );

        Ok(events)
    }
}

#[cfg(test)]
mod qc_gate_tests {
    use super::qc_response_confirms;
    use serde_json::json;

    fn qc_resp(available: bool, verified: bool, h: u64, hash: &str) -> serde_json::Value {
        json!({
            "available": available,
            "verified": verified,
            "quorum_certificate": { "block_height": h, "block_hash": hash }
        })
    }

    // SEC-#18: the bridge accepts a block ONLY when the QC is available, verified,
    // and bound to exactly this (height, hash).
    #[test]
    fn qc_confirms_only_when_available_verified_and_bound() {
        let h = 42u64;
        let hash = "ab".repeat(32);

        assert!(qc_response_confirms(&qc_resp(true, true, h, &hash), h, &hash));

        // Not verified / not available -> reject (forged or unfinalized state).
        assert!(!qc_response_confirms(&qc_resp(true, false, h, &hash), h, &hash));
        assert!(!qc_response_confirms(&qc_resp(false, true, h, &hash), h, &hash));

        // Wrong height or hash -> reject (QC for a different block).
        assert!(!qc_response_confirms(&qc_resp(true, true, h + 1, &hash), h, &hash));
        assert!(!qc_response_confirms(&qc_resp(true, true, h, &"cd".repeat(32)), h, &hash));

        // Empty expected hash cannot be bound -> reject.
        assert!(!qc_response_confirms(&qc_resp(true, true, h, ""), h, ""));

        // Missing quorum_certificate object -> reject.
        assert!(!qc_response_confirms(
            &json!({"available": true, "verified": true}),
            h,
            &hash
        ));
    }
}
