use crate::validator_set::TrustedValidatorSet;
use consensus::qc::{self, QuorumCertificate};
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
    // SEC-#18 Tier-B: the operator-shipped TRUSTED validator set, loaded
    // independently of the RPC. Used to verify QC aggregate BLS signatures
    // CLIENT-SIDE so the bridge never trusts the RPC node's `verified` flag.
    // `None` => no trusted set configured => fail-closed (refuse every block).
    trusted_validators: Option<TrustedValidatorSet>,
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

/// SEC-#18 Tier-B: pure decision for whether a `aincore_getQuorumCertificate`
/// response proves the given block is finalized — verified CLIENT-SIDE.
///
/// The block is accepted ONLY if:
///   1. the node says the QC is `available` (no QC -> nothing to verify),
///   2. the embedded `quorum_certificate` deserializes into a
///      [`consensus::qc::QuorumCertificate`],
///   3. it binds to exactly this `(height, hash)`,
///   4. and — crucially — the QC's aggregate BLS signature VERIFIES against the
///      bridge's own TRUSTED validator set for `qc.epoch` via
///      [`consensus::qc::verify_qc`] (> 2/3 stake, correct set hash, valid agg).
///
/// The node's own `verified` flag is now **advisory only**: a malicious RPC can
/// set `verified: true` over a forged QC, so we recompute the result ourselves
/// and merely log when the two disagree. Any parse/verify failure, or a missing
/// trusted set, yields `false` (fail-closed). Extracted so the gate logic is
/// unit-testable without a live RPC.
fn qc_response_confirms(
    result: &serde_json::Value,
    height: u64,
    expected_hash: &str,
    trusted: Option<&TrustedValidatorSet>,
) -> bool {
    if expected_hash.is_empty() {
        return false;
    }
    if !result
        .get("available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return false;
    }

    // The server's `verified` flag is advisory only — we re-verify below. Keep it
    // for an operator-visible warning if the RPC disagrees with our verdict.
    let server_verified = result
        .get("verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let Some(qc_json) = result.get("quorum_certificate") else {
        return false;
    };

    // Deserialize the QC into the canonical consensus type. A forged/garbled QC
    // that does not match the type fails closed here.
    let qc: QuorumCertificate = match serde_json::from_value(qc_json.clone()) {
        Ok(q) => q,
        Err(e) => {
            warn!("⚠️ [SEC-#18-B] QC for block {} failed to deserialize: {}", height, e);
            return false;
        }
    };

    // Bind to exactly the block we are gating on BEFORE the (more expensive) BLS
    // check. Wrong height/hash -> reject (QC is for a different block).
    if qc.block_height != height || qc.block_hash != expected_hash {
        warn!(
            "⚠️ [SEC-#18-B] QC binds to ({}, {}) but expected ({}, {}) — reject",
            qc.block_height, qc.block_hash, height, expected_hash
        );
        return false;
    }

    // CLIENT-SIDE cryptographic verification against the operator's trusted set.
    let Some(trusted) = trusted else {
        error!(
            "🚨 [SEC-#18-B] no trusted validator set configured ({} unset?) — cannot verify QC for block {}; fail-closed",
            crate::validator_set::VALIDATOR_SET_PATH_ENV,
            height
        );
        return false;
    };

    // Resolve the trusted set for the QC's epoch (per-epoch sets supported; a
    // single pinned set is used for every epoch). No set for this epoch ->
    // fail-closed.
    let Some(set) = trusted.resolve_for_epoch(qc.epoch) else {
        error!(
            "🚨 [SEC-#18-B] no trusted validator set for epoch {} (block {}) — fail-closed",
            qc.epoch, height
        );
        return false;
    };

    match qc::verify_qc(&qc, set, &qc::expected_chain_id()) {
        Ok(()) => {
            if !server_verified {
                warn!(
                    "⚠️ [SEC-#18-B] RPC reported verified=false for block {} but client-side verify_qc PASSED — trusting our own verification",
                    height
                );
            }
            true
        }
        Err(e) => {
            // If the RPC claimed verified=true but the QC does NOT verify against
            // our trusted set, the RPC is lying or compromised — this is exactly
            // the attack Tier-B closes. Surface it loudly.
            error!(
                "🚨 [SEC-#18-B] CLIENT-SIDE QC verification FAILED for block {} (server_verified={}): {} — rejecting (bridge will not act)",
                height, server_verified, e
            );
            false
        }
    }
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
    /// Construct a client and load the TRUSTED validator set from
    /// `AINCORE_VALIDATOR_SET_PATH` (SEC-#18 Tier-B). If the env is unset or the
    /// file is unreadable/invalid, the trusted set stays `None` and every QC
    /// verification fails closed (the bridge refuses to act). The error is logged
    /// loudly at construction so operators notice the misconfiguration at boot.
    pub fn new(rpc_url: String) -> Self {
        let trusted_validators = match TrustedValidatorSet::from_env() {
            Ok(set) => {
                info!("🔐 [SEC-#18-B] loaded trusted validator set for client-side QC verification");
                Some(set)
            }
            Err(e) => {
                error!(
                    "🚨 [SEC-#18-B] could not load trusted validator set: {} — bridge will FAIL-CLOSED on every block until {} points to a valid validator-set file",
                    e,
                    crate::validator_set::VALIDATOR_SET_PATH_ENV
                );
                None
            }
        };
        Self {
            rpc_url,
            client: Client::new(),
            last_processed_height: 0,
            trusted_validators,
        }
    }

    /// Test/embedding constructor: supply the trusted validator set explicitly
    /// instead of reading the environment.
    #[allow(dead_code)]
    pub fn with_trusted_validators(rpc_url: String, trusted: TrustedValidatorSet) -> Self {
        Self {
            rpc_url,
            client: Client::new(),
            last_processed_height: 0,
            trusted_validators: Some(trusted),
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

    /// SEC-#18 Tier-B: verify that block `height` is finalized by a quorum
    /// certificate bound to `expected_hash`, verified CLIENT-SIDE against the
    /// bridge's own trusted validator set. Queries `aincore_getQuorumCertificate`
    /// and applies [`qc_response_confirms`] with `self.trusted_validators`. Any
    /// RPC/parse/verify failure → `false` (fail-closed: the bridge must not act
    /// on state it cannot itself prove final — it does NOT trust the RPC's flag).
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
            Some(result) => qc_response_confirms(
                &result,
                height,
                expected_hash,
                self.trusted_validators.as_ref(),
            ),
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
    use crate::validator_set::TrustedValidatorSet;
    use consensus::qc::{build_qc, validator_set_hash, FinalityVote, ValidatorInfo};
    use crypto::bls::BLSEngine;
    use serde_json::json;

    // ---- helpers to build a REAL, BLS-valid QC the bridge can verify client-side ----

    /// Build `n` validators with real deterministic BLS keys + PoP, plus their
    /// raw secret seeds (so we can sign).
    fn make_validators(specs: &[(u8, u64)]) -> (Vec<ValidatorInfo>, Vec<[u8; 32]>) {
        let bls = BLSEngine::consensus();
        let mut infos = Vec::new();
        let mut sks = Vec::new();
        for &(seed, stake) in specs {
            let mut ikm = [0u8; 32];
            ikm[0] = seed;
            ikm[31] = seed.wrapping_add(7);
            let pk = bls.pubkey_raw(&ikm);
            let pop = bls.prove_possession_raw(&ikm);
            infos.push(ValidatorInfo {
                address: format!("{:032x}", seed as u128),
                stake,
                ed25519_public_key: "00".repeat(32),
                bls_public_key: hex::encode(&pk),
                bls_pop: hex::encode(&pop),
            });
            sks.push(ikm);
        }
        (infos, sks)
    }

    fn vote_for(height: u64, hash: &str, set_hash: &str) -> FinalityVote {
        FinalityVote {
            chain_id: "AINCORE-MAINNET-1".into(),
            epoch: 0,
            finalized_round: height,
            anchor_round: height,
            anchor_hash: "aa".repeat(32),
            block_height: height,
            block_hash: hash.to_string(),
            state_root: "cc".repeat(32),
            receipts_root: "dd".repeat(32),
            finality_digest: "ee".repeat(32),
            validator_set_hash: set_hash.to_string(),
        }
    }

    /// Produce a QC JSON value the way the RPC would embed it, signed by all
    /// validators in `sks` (canonical-order indices).
    fn signed_qc_json(
        height: u64,
        hash: &str,
        validators: &[ValidatorInfo],
        sks: &[[u8; 32]],
    ) -> serde_json::Value {
        let bls = BLSEngine::consensus();
        let set_hash = validator_set_hash(validators);
        let vote = vote_for(height, hash, &set_hash);

        // canonical order = address-sorted. Our addresses sort by seed, and we
        // build specs in seed order, so indices line up; but be robust: sort.
        let mut order: Vec<usize> = (0..validators.len()).collect();
        order.sort_by(|&a, &b| validators[a].address.cmp(&validators[b].address));

        let signer_indices: Vec<usize> = (0..order.len()).collect();
        let sigs: Vec<Vec<u8>> = order
            .iter()
            .map(|&orig| bls.sign_raw(&vote.to_signing_bytes(), &sks[orig]))
            .collect();

        let qc = build_qc(&vote, validators, &signer_indices, &sigs).expect("build_qc");
        serde_json::to_value(&qc).unwrap()
    }

    fn rpc_response(available: bool, verified: bool, qc: serde_json::Value) -> serde_json::Value {
        json!({
            "available": available,
            "verified": verified,
            "quorum_certificate": qc
        })
    }

    fn single_set(validators: Vec<ValidatorInfo>) -> TrustedValidatorSet {
        let json = serde_json::to_string(&validators).unwrap();
        TrustedValidatorSet::from_json_str(&json).unwrap()
    }

    // ---- tests ----

    // SEC-#18 Tier-B: a QC that VERIFIES against the trusted set is accepted.
    #[test]
    fn valid_qc_accepted_client_side() {
        let h = 600u64;
        let hash = "bb".repeat(32);
        let (validators, sks) = make_validators(&[(1, 40), (2, 30), (3, 20)]); // 90 stake, 1-of-1 set
        let qc = signed_qc_json(h, &hash, &validators, &sks);
        let trusted = single_set(validators);
        // 100% of the trusted set signed -> > 2/3 -> accepted.
        assert!(qc_response_confirms(
            &rpc_response(true, true, qc),
            h,
            &hash,
            Some(&trusted)
        ));
    }

    // Even if the RPC LIES (verified=false), a cryptographically valid QC is still
    // accepted — Tier-B trusts our own verification, not the RPC flag.
    #[test]
    fn valid_qc_accepted_even_if_rpc_says_unverified() {
        let h = 7u64;
        let hash = "cd".repeat(32);
        let (validators, sks) = make_validators(&[(5, 100)]);
        let qc = signed_qc_json(h, &hash, &validators, &sks);
        let trusted = single_set(validators);
        assert!(qc_response_confirms(
            &rpc_response(true, false, qc),
            h,
            &hash,
            Some(&trusted)
        ));
    }

    // A tampered QC (mutated block_hash inside the QC) is rejected: the binding
    // check fails (and the BLS signature would not match either).
    #[test]
    fn tampered_qc_rejected() {
        let h = 600u64;
        let hash = "bb".repeat(32);
        let (validators, sks) = make_validators(&[(1, 60), (2, 40)]);
        let mut qc = signed_qc_json(h, &hash, &validators, &sks);
        // Attacker flips the block_hash but leaves the (now-invalid) signature.
        qc["block_hash"] = json!("ff".repeat(32));
        let trusted = single_set(validators);
        // expected_hash still the original -> binding mismatch -> reject. And even
        // if it matched, the signature is over the original hash -> BLS fail.
        assert!(!qc_response_confirms(
            &rpc_response(true, true, qc),
            h,
            &hash,
            Some(&trusted)
        ));
    }

    // A QC verified against the WRONG validator set is rejected (validator_set_hash
    // binding + BLS keys differ).
    #[test]
    fn wrong_validator_set_rejected() {
        let h = 600u64;
        let hash = "bb".repeat(32);
        let (real, sks) = make_validators(&[(1, 60), (2, 40)]);
        let qc = signed_qc_json(h, &hash, &real, &sks);
        // Operator's trusted set is a DIFFERENT validator set.
        let (other, _) = make_validators(&[(9, 60), (8, 40)]);
        let trusted = single_set(other);
        assert!(!qc_response_confirms(
            &rpc_response(true, true, qc),
            h,
            &hash,
            Some(&trusted)
        ));
    }

    // Wrong height or wrong expected hash -> reject (QC for a different block).
    #[test]
    fn wrong_height_or_hash_rejected() {
        let h = 600u64;
        let hash = "bb".repeat(32);
        let (validators, sks) = make_validators(&[(1, 100)]);
        let qc = signed_qc_json(h, &hash, &validators, &sks);
        let trusted = single_set(validators);

        // Same QC, but gating a different height.
        assert!(!qc_response_confirms(
            &rpc_response(true, true, qc.clone()),
            h + 1,
            &hash,
            Some(&trusted)
        ));
        // Same QC, but gating a different expected hash.
        assert!(!qc_response_confirms(
            &rpc_response(true, true, qc),
            h,
            &"cd".repeat(32),
            Some(&trusted)
        ));
    }

    // Missing trusted-set config -> fail-closed regardless of how good the QC is.
    #[test]
    fn missing_trusted_set_fails_closed() {
        let h = 600u64;
        let hash = "bb".repeat(32);
        let (validators, sks) = make_validators(&[(1, 100)]);
        let qc = signed_qc_json(h, &hash, &validators, &sks);
        assert!(!qc_response_confirms(
            &rpc_response(true, true, qc),
            h,
            &hash,
            None
        ));
    }

    // available=false / missing QC / empty expected hash -> reject (unchanged
    // Tier-A guards, still enforced before any crypto).
    #[test]
    fn unavailable_or_malformed_rejected() {
        let h = 600u64;
        let hash = "bb".repeat(32);
        let (validators, sks) = make_validators(&[(1, 100)]);
        let qc = signed_qc_json(h, &hash, &validators, &sks);
        let trusted = single_set(validators);

        // available=false -> reject even with a valid QC.
        assert!(!qc_response_confirms(
            &rpc_response(false, true, qc.clone()),
            h,
            &hash,
            Some(&trusted)
        ));
        // empty expected hash -> reject.
        assert!(!qc_response_confirms(
            &rpc_response(true, true, qc),
            h,
            "",
            Some(&trusted)
        ));
        // missing quorum_certificate -> reject.
        assert!(!qc_response_confirms(
            &json!({"available": true, "verified": true}),
            h,
            &hash,
            Some(&trusted)
        ));
        // garbage quorum_certificate (wrong type) -> reject (deserialize fails).
        assert!(!qc_response_confirms(
            &json!({"available": true, "verified": true, "quorum_certificate": "nope"}),
            h,
            &hash,
            Some(&trusted)
        ));
    }
}
