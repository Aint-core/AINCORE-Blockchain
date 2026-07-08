use blockchain::Vertex;
use crypto::vdf::VDFEngine;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use storage::StateDB;

use std::collections::{HashMap, HashSet};

/// OrderingEngine bertanggung jawab untuk mengubah DAG menjadi urutan linear (Blockchain).
/// Kita menggunakan pendekatan simplified Bullshark:
/// 1. Setiap ronde ganjil punya "Leader".
/// 2. Jika Leader punya cukup dukungan (votes) dari ronde sebelumnya, dia jadi "Anchor".
/// 3. Semua vertex yang terhubung ke Anchor tersebut akan diurutkan (Committed).
pub struct OrderingEngine {
    /// Bounded recent de-dup window of committed anchor rounds. This is NO LONGER
    /// an unbounded finality log: it is trimmed to the most recent
    /// `COMMITTED_ROUNDS_WINDOW` rounds and is used purely to reject
    /// double-committing a just-seen anchor. Authoritative finality progress is
    /// tracked by `finalized_round` (monotonic high-water mark).
    pub committed_rounds: HashSet<u64>,
    /// Monotonic high-water mark of the highest committed anchor round. Never
    /// decreases. Used to (a) gate re-committing old anchors that have already
    /// fallen out of `committed_rounds`, and (b) derive the DAG prune watermark.
    pub finalized_round: u64,
    pub committed_sequence: Vec<String>, // List of Vertex Hashes in order
    /// Rolling cumulative finality digest: `H(prev_digest_hex || new_hashes…)`,
    /// chained on every commit and persisted as `consensus:finality_digest`. On
    /// restart it CONTINUES from that persisted value, so it is a pure function of
    /// the FULL committed history and stays identical across nodes regardless of
    /// restarts. The old approach re-hashed the in-memory `committed_sequence`,
    /// which is persisted truncated (last 10k) AND reversed — so after any restart
    /// its digest diverged from long-running peers even though the chain agreed.
    /// This value seeds the leader-election beacon, so the divergence was a latent
    /// agreement hazard, not just a cosmetic reporting bug.
    finality_digest: String,
    /// VDF engine for random beacon (unpredictable leader election)
    vdf_engine: Option<VDFEngine>,
    /// SEC-#12 Step-1 base beacon: the digest-bound VDF output BEFORE any QC fold.
    /// Recomputed on every commit (`update_random_beacon`) and on restart. Kept
    /// separately so a Step-2 QC fold always re-derives from this exact base
    /// instead of chaining onto an already-folded value — that makes the post-fold
    /// beacon a pure function of (Step-1 base, folded QC) and therefore identical
    /// across nodes regardless of WHEN each node's complete QC arrives (commit-time
    /// for a supermajority holder vs. later for multi-party aggregation).
    step1_beacon: Vec<u8>,
    /// Last VDF output for randomness (Step-1 base folded with the latest complete
    /// QC's aggregate signature, when one exists).
    last_vdf_output: Vec<u8>,
    /// Block height of the QC currently folded into `last_vdf_output`, if any.
    /// Monotonic; mirrors the persisted `consensus:beacon_folded_qc_height`.
    folded_qc_height: Option<u64>,
    /// Storage reference for persisting committed state
    storage: Option<Arc<StateDB>>,
}

/// Number of most-recent committed anchor rounds retained in `committed_rounds`
/// for de-dup. Anchors older than `finalized_round - COMMITTED_ROUNDS_WINDOW`
/// are rejected via the high-water comparison instead of set membership.
const COMMITTED_ROUNDS_WINDOW: u64 = 256;

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub sequence: Vec<String>,
    pub leader: String,
    pub anchor_round: u64,
    pub anchor_hash: String,
    pub finality_digest: String,
}

impl Default for OrderingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderingEngine {
    pub fn new() -> Self {
        // Initialize VDF with moderate difficulty (adjustable for faster/slower)
        let vdf = VDFEngine::new(50).ok();

        Self {
            committed_rounds: HashSet::new(),
            finalized_round: 0,
            committed_sequence: Vec::new(),
            finality_digest: String::new(),
            vdf_engine: vdf,
            step1_beacon: vec![0u8; 32],
            last_vdf_output: vec![0u8; 32],
            folded_qc_height: None,
            storage: None,
        }
    }

    /// Create with storage for persistence (production mode)
    pub fn new_with_storage(storage: Arc<StateDB>) -> Self {
        let vdf = VDFEngine::new(50).ok();

        // Load committed_rounds from DB (backward-compatible: old data may be a
        // huge unbounded Vec<u64>; we derive the high-water mark from it and
        // then keep only the most recent window in memory).
        let mut committed_rounds: HashSet<u64> = HashSet::new();
        let mut finalized_round: u64 = 0;
        if let Ok(Some(json)) = storage.get("consensus:committed_rounds") {
            if let Ok(rounds) = serde_json::from_str::<Vec<u64>>(&json) {
                println!("🔄 Restored {} committed rounds from DB", rounds.len());
                finalized_round = rounds.iter().copied().max().unwrap_or(0);
                let cutoff = finalized_round.saturating_sub(COMMITTED_ROUNDS_WINDOW);
                committed_rounds = rounds.into_iter().filter(|r| *r >= cutoff).collect();
            }
        }
        // Prefer the explicit persisted high-water mark when present (newer nodes
        // persist it); fall back to the value derived from the set above.
        if let Ok(Some(s)) = storage.get("consensus:finalized_round") {
            if let Ok(persisted) = s.parse::<u64>() {
                finalized_round = finalized_round.max(persisted);
            }
        }

        // Load committed_sequence from DB
        let mut committed_sequence = Vec::new();
        if let Ok(Some(json)) = storage.get("consensus:committed_sequence") {
            if let Ok(seq) = serde_json::from_str::<Vec<String>>(&json) {
                println!("🔄 Restored {} committed vertex hashes from DB", seq.len());
                committed_sequence = seq;
            }
        }

        // Continue the rolling finality digest from its persisted value — the
        // authoritative digest over the FULL committed history. Re-hashing the
        // reloaded (truncated + reversed) committed_sequence would diverge from
        // peers that never restarted, so we chain from the stored value instead.
        let finality_digest = storage
            .get("consensus:finality_digest")
            .ok()
            .flatten()
            .unwrap_or_default();

        // SEC-#22/#12: restore the leader-election beacon on restart. The beacon is
        // a pure function of (last anchor round, cumulative finality digest) — both
        // persisted every commit (consensus:last_anchor_round / consensus:finality_
        // _digest) — so it recomputes deterministically and identically on every
        // node without persisting the beacon itself. A fresh restart that left it at
        // zeros would select leaders off a different beacon than long-running peers
        // (agreement/liveness hazard until re-sync), so reconstruct it here.
        let mut step1_beacon = vec![0u8; 32];
        let mut last_vdf_output = vec![0u8; 32];
        let mut folded_qc_height: Option<u64> = None;
        if let Some(ref v) = vdf {
            let last_anchor_round = storage
                .get("consensus:last_anchor_round")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok());
            let digest = storage.get("consensus:finality_digest").ok().flatten();
            if let (Some(ar), Some(d)) = (last_anchor_round, digest.as_ref()) {
                if let Ok((output, _proof)) = v.compute(&Self::beacon_challenge(ar, d)) {
                    step1_beacon = output;
                }
            }
            // The post-fold beacon starts equal to the Step-1 base; a QC fold below
            // overrides it.
            last_vdf_output = step1_beacon.clone();

            // SEC-#12 Step-2: re-apply the QC aggregate-signature fold on restart.
            // The Step-1 base above is the pre-fold value; if a complete QC was
            // folded before shutdown we persisted the folded block height +
            // anchor round (consensus:beacon_folded_qc_height /
            // consensus:beacon_folded_anchor_round). Re-folding that QC's aggregate
            // signature onto the SAME Step-1 base with the SAME deterministic mix
            // reproduces the exact post-fold beacon a live engine holds — no beacon
            // bytes are persisted. The anchor-round guard ensures we ONLY re-fold
            // when the marker matches the current Step-1 base (i.e. the latest
            // committed anchor still carries that fold); a stale marker from an
            // earlier base — whose later heights had no complete QC — is ignored, so
            // restart matches the live unfolded beacon in that case. A missing QC
            // (pruned) likewise falls back to the Step-1 base.
            let folded_h = storage
                .get("consensus:beacon_folded_qc_height")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok());
            let folded_ar = storage
                .get("consensus:beacon_folded_anchor_round")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok());
            if let (Some(h), Some(far), Some(lar)) = (folded_h, folded_ar, last_anchor_round) {
                if far == lar {
                    if let Some(agg) = Self::load_qc_aggregate_signature(&storage, h) {
                        if let Some(mixed) = Self::compute_qc_mix(v, &step1_beacon, &agg) {
                            last_vdf_output = mixed;
                            folded_qc_height = Some(h);
                        }
                    }
                }
            }
        }

        Self {
            committed_rounds,
            finalized_round,
            committed_sequence,
            finality_digest,
            vdf_engine: vdf,
            step1_beacon,
            last_vdf_output,
            folded_qc_height,
            storage: Some(storage),
        }
    }

    /// SEC-#12: domain-separated leader-election beacon challenge.
    ///
    /// The beacon is seeded from `(anchor_round, finality_digest)` rather than the
    /// bare proposer-chosen anchor-vertex hash. `finality_digest` is a cumulative
    /// hash over the ENTIRE committed sequence, so the seed is bound to the whole
    /// committed prefix — a single proposer can no longer grind one vertex (the old
    /// cheap two-hash trial) to steer the next leader; it would have to control the
    /// cumulative digest. (Full unbiasability needs the multi-party QC aggregate
    /// signature — Step 2 — and a real delay-VDF is the longer-term roadmap; the
    /// hash-chain VDF here provides determinism, not delay.)
    fn beacon_challenge(anchor_round: u64, finality_digest: &str) -> Vec<u8> {
        let mut c = Vec::with_capacity(17 + 8 + finality_digest.len());
        c.extend_from_slice(b"AINCORE_BEACON_V1");
        c.extend_from_slice(&anchor_round.to_le_bytes());
        c.extend_from_slice(finality_digest.as_bytes());
        c
    }

    /// Update random beacon using VDF (called after each commit). Deterministic
    /// across nodes: same (anchor_round, finality_digest) → same Step-1 base.
    ///
    /// This sets the Step-1 base (`step1_beacon`) and resets the live beacon to it.
    /// Any QC fold (Step-2) for the newly committed height is layered on top
    /// afterwards via [`fold_qc_for_height`], always re-derived from this base so
    /// the post-fold beacon is timing-independent across nodes.
    pub fn update_random_beacon(&mut self, anchor_round: u64, finality_digest: &str) {
        if let Some(ref vdf) = self.vdf_engine {
            if let Ok((output, _proof)) =
                vdf.compute(&Self::beacon_challenge(anchor_round, finality_digest))
            {
                self.step1_beacon = output.clone();
                self.last_vdf_output = output;
                // A fresh Step-1 base supersedes any prior fold; the next
                // fold_qc_for_height re-applies the current height's QC on top.
                self.folded_qc_height = None;
            }
        }
    }

    /// Get random bytes from beacon for leader selection
    pub fn get_random_beacon(&self) -> &[u8] {
        &self.last_vdf_output
    }

    /// SEC-#12 Step-2: domain-separated challenge folding a finalized block's QC
    /// aggregate BLS signature into the running beacon.
    ///
    /// The aggregate signature is a >2/3 BLS aggregate over the canonical
    /// `FinalityVote` — it is deterministic given the signer set + message and
    /// cannot be forged or predicted by any sub-quorum, so no single proposer can
    /// grind the next leader. Folding `prev_beacon` keeps the chain dependent on
    /// the entire prior history (Step-1's digest binding remains the base).
    fn qc_mix_challenge(prev_beacon: &[u8], aggregate_signature: &[u8]) -> Vec<u8> {
        let mut c =
            Vec::with_capacity(20 + prev_beacon.len() + aggregate_signature.len());
        c.extend_from_slice(b"AINCORE_BEACON_QC_V1");
        c.extend_from_slice(prev_beacon);
        c.extend_from_slice(aggregate_signature);
        c
    }

    /// Deterministically compute the post-fold beacon from a previous beacon and a
    /// QC aggregate signature. Pure (no `self`/storage) so the restart path and the
    /// live path share one definition. Returns `None` only if the VDF errors.
    fn compute_qc_mix(
        vdf: &VDFEngine,
        prev_beacon: &[u8],
        aggregate_signature: &[u8],
    ) -> Option<Vec<u8>> {
        vdf.compute(&Self::qc_mix_challenge(prev_beacon, aggregate_signature))
            .ok()
            .map(|(output, _proof)| output)
    }

    /// SEC-#12 Step-2: fold a QC aggregate signature into the beacon, deriving from
    /// the Step-1 base: `last_vdf_output = VDF(domain || step1_beacon || aggregate_
    /// signature)`. Folding from the immutable Step-1 base (rather than chaining
    /// onto whatever `last_vdf_output` currently is) makes the result a pure
    /// function of (Step-1 base, aggregate signature) — identical across nodes no
    /// matter when each node's complete QC arrives. No-op if the VDF is unavailable.
    pub fn mix_qc_into_beacon(&mut self, aggregate_signature: &[u8]) {
        if let Some(ref vdf) = self.vdf_engine {
            if let Some(mixed) =
                Self::compute_qc_mix(vdf, &self.step1_beacon, aggregate_signature)
            {
                self.last_vdf_output = mixed;
            }
        }
    }

    /// Load a COMPLETE QC stored at `consensus:qc:{height}`. Returns `None` when no
    /// complete QC exists for that height (the common case until a >2/3 quorum is
    /// assembled) or it cannot be decoded.
    fn load_qc(storage: &StateDB, height: u64) -> Option<crate::qc::QuorumCertificate> {
        let raw = storage.get(&format!("consensus:qc:{}", height)).ok()??;
        serde_json::from_str(&raw).ok()
    }

    /// Load just the `aggregate_signature` of a COMPLETE QC at `height`.
    fn load_qc_aggregate_signature(storage: &StateDB, height: u64) -> Option<Vec<u8>> {
        Self::load_qc(storage, height).map(|qc| qc.aggregate_signature)
    }

    /// SEC-#12 Step-2 entry point: if a COMPLETE QC exists for `height` and it has
    /// not already been folded, fold its aggregate signature onto the CURRENT
    /// Step-1 base beacon and persist the fold marker so restart reproduces the
    /// exact beacon.
    ///
    /// DETERMINISM: every node folds the SAME complete QC (the aggregate signature
    /// is identical given the signer set + message) for the SAME height onto the
    /// SAME Step-1 base, so the post-fold beacon is byte-identical everywhere
    /// regardless of WHEN each node assembles its complete QC. The monotonic
    /// `height <= prev → skip` guard makes this idempotent (commit path then a late
    /// QC_VOTE for the same height folds at most once) and prevents folding a stale
    /// older-height QC onto a newer Step-1 base after the commit moved on.
    ///
    /// The persisted marker records BOTH the folded height and the QC's anchor
    /// round; on restart the fold is re-applied ONLY when that anchor round matches
    /// the Step-1 base's `last_anchor_round`, so a marker left over from an earlier
    /// base (whose later heights had no complete QC) is not mis-folded.
    ///
    /// Returns `true` iff a fold actually happened.
    pub fn fold_qc_for_height(&mut self, height: u64) -> bool {
        let storage = match self.storage {
            Some(ref s) => Arc::clone(s),
            None => return false,
        };
        // Monotonic: never re-fold a height already folded and never fold an older
        // height than the last folded one (out-of-order arrival would diverge).
        let already = storage
            .get("consensus:beacon_folded_qc_height")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u64>().ok());
        if let Some(prev) = already {
            if height <= prev {
                return false;
            }
        }
        let qc = match Self::load_qc(&storage, height) {
            Some(q) => q,
            None => return false, // no complete QC yet — Step-1 beacon still applies
        };
        self.mix_qc_into_beacon(&qc.aggregate_signature);
        self.folded_qc_height = Some(height);
        let _ = storage.put("consensus:beacon_folded_qc_height", &height.to_string());
        // Bind the marker to the Step-1 base this fold sits on (the QC's anchor
        // round == the commit's anchor round), so restart only re-folds when the
        // base still corresponds to this fold.
        let _ = storage.put(
            "consensus:beacon_folded_anchor_round",
            &qc.anchor_round.to_string(),
        );
        true
    }

    /// Fold newly committed vertex hashes into the rolling finality digest:
    /// `H(prev_digest_hex || h1 || h2 || …)`. Chaining from the previous digest
    /// (persisted + reloaded on restart) makes the result a pure function of the
    /// full committed history in commit order, identical on every node no matter
    /// how much of `committed_sequence` is kept in memory or how many times a node
    /// restarted. `prev` is the empty string at genesis.
    fn fold_finality_digest(prev: &str, new_hashes: &[String]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev.as_bytes());
        for hash in new_hashes {
            hasher.update(hash.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Mencoba melakukan commit pada ronde tertentu
    pub fn try_commit(
        &mut self,
        current_round: u64,
        dag: &HashMap<String, Vertex>,
        round_index: &HashMap<u64, Vec<String>>,
        // B4: (address, stake) pairs, canonically sorted by address (the order
        // get_validator_set_with_stake guarantees) so leader election is
        // deterministic across honest nodes.
        validators: &[(String, u64)],
    ) -> Option<CommitInfo> {
        if current_round < 4 {
            return None;
        }

        // 1. Tentukan Anchor Round (current - 2)
        // Bullshark: We commit an anchor from round r-2 using votes from r-1.
        // But here we are at current_round, so we look at current_round - 1 to see if it votes for current_round - 2?
        // Let's stick to the plan: Commit round - 2.
        // To commit Anchor at R, we need f+1 votes from R+1.
        // So if we are at R+2 (current_round), we can check if R+1 voted for R.

        let anchor_round = current_round - 2;
        // Anti-double-commit invariant: reject if this anchor round was already
        // committed. `committed_rounds` only retains a recent window, so we also
        // reject anything at or below the monotonic high-water mark that is no
        // longer in the set (those are definitively already finalized).
        // `finalized_round` starts at 0 and round 0 is never a valid anchor here
        // (current_round >= 4 implies anchor_round >= 2), so the `> 0` guard only
        // skips the genesis no-op case.
        if self.committed_rounds.contains(&anchor_round)
            || (self.finalized_round > 0 && anchor_round <= self.finalized_round)
        {
            return None;
        }

        // CRITICAL-1 FIX: View Change Mechanism
        // Try all validators if necessary (continuous round-robin fallback)
        let max_attempts = if validators.is_empty() {
            3
        } else {
            validators.len() as u32
        };

        let mut anchor_vertex_hash: Option<&String> = None;
        let mut successful_leader = String::new();

        for attempt in 0..max_attempts {
            let leader_id = self.get_leader_with_fallback(anchor_round, validators, attempt);

            // Try to find this leader's vertex in anchor round
            if let Some(hashes) = round_index.get(&anchor_round) {
                let found = hashes.iter().find(|h| {
                    if let Some(v) = dag.get(*h) {
                        v.author == leader_id
                    } else {
                        false
                    }
                });

                if let Some(hash) = found {
                    anchor_vertex_hash = Some(hash);
                    successful_leader = leader_id.clone();
                    if attempt > 0 {
                        println!(
                            "🔄 View Change: Backup leader {} selected (attempt {})",
                            leader_id,
                            attempt + 1
                        );
                    }
                    break;
                }
            }

            if attempt < max_attempts - 1 {
                println!(
                    "⚠️  Leader {} not found in anchor round {}, trying backup...",
                    leader_id, anchor_round
                );
            }
        }

        let anchor_vertex_hash = if let Some(h) = anchor_vertex_hash {
            h
        } else {
            println!("🚨 CRITICAL: All {} leader attempts failed for anchor round {} - possible network partition", 
                max_attempts, anchor_round);
            return None;
        };

        // 4. Cek Dukungan (Votes) dari Round R+1 (current_round - 1)
        let vote_round = current_round - 1;
        let votes = round_index.get(&vote_round)?;

        // B4: stake-weighted commit quorum. Sum the stake of DISTINCT voter
        // AUTHORS (one validator counts once even if it produced multiple
        // vertices) that are in the active validator set, then require strict
        // > 2/3 of TOTAL stake — the same predicate as qc::verify_qc and the DAG
        // parent quorum.
        let validator_stakes: HashMap<&str, u64> =
            validators.iter().map(|(a, s)| (a.as_str(), *s)).collect();
        let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();

        let mut voted_authors: HashSet<&str> = HashSet::new();
        for voter_hash in votes {
            if let Some(voter) = dag.get(voter_hash) {
                if voter.parents.contains(anchor_vertex_hash) {
                    voted_authors.insert(voter.author.as_str());
                }
            }
        }
        let signed_stake: u128 = voted_authors
            .iter()
            .filter_map(|a| validator_stakes.get(a).map(|s| *s as u128))
            .sum();

        if !crate::qc::stake_quorum_met(signed_stake, total_stake) {
            println!(
                "⚠️ Anchor Round {} (Leader {}) not committed. Stake {}/{} (need >2/3)",
                anchor_round, successful_leader, signed_stake, total_stake
            );
            return None;
        }

        println!(
            "⚓ Committing Anchor Round {} (Leader {}) with stake {}/{} (>2/3)",
            anchor_round, successful_leader, signed_stake, total_stake
        );

        // 5. Commit Causal History
        let mut sequence = self.find_causal_history(anchor_vertex_hash, dag);

        // Filter yang sudah committed
        sequence.retain(|h| !self.committed_sequence.contains(h));

        // Update state
        self.committed_rounds.insert(anchor_round);
        // Advance the monotonic finality high-water mark.
        self.finalized_round = self.finalized_round.max(anchor_round);
        // Trim the de-dup window so `committed_rounds` stays bounded regardless of
        // how many rounds are committed (this is the leak fix). Rounds below the
        // cutoff are still rejected by the high-water comparison in the guard.
        let cutoff = self.finalized_round.saturating_sub(COMMITTED_ROUNDS_WINDOW);
        if cutoff > 0 {
            self.committed_rounds.retain(|r| *r >= cutoff);
        }
        self.committed_sequence.extend(sequence.clone());

        // Fold this commit's newly-ordered vertex hashes into the rolling finality
        // digest, chained from the previous (persisted) value — see the field doc.
        // Bound to the full committed history, so every node derives the identical
        // value for persistence, the leader-election beacon (SEC-#12) and the
        // returned CommitInfo, and it survives restarts (unlike a re-hash over the
        // truncated in-memory committed_sequence). `sequence` is already deduped
        // against committed_sequence above, so no hash is folded twice.
        self.finality_digest = Self::fold_finality_digest(&self.finality_digest, &sequence);
        let digest = self.finality_digest.clone();

        // PERSIST committed state to DB (BUG #1 FIX)
        if let Some(ref storage) = self.storage {
            // committed_rounds is now bounded (<= COMMITTED_ROUNDS_WINDOW + 1
            // entries), so this write is O(window), not O(history).
            if let Ok(json) =
                serde_json::to_string(&self.committed_rounds.iter().collect::<Vec<_>>())
            {
                let _ = storage.put("consensus:committed_rounds", &json);
            }
            // Only persist last 10000 committed hashes to prevent unbounded growth
            let seq_to_save: Vec<&String> =
                self.committed_sequence.iter().rev().take(10000).collect();
            if let Ok(json) = serde_json::to_string(&seq_to_save) {
                let _ = storage.put("consensus:committed_sequence", &json);
            }
            // Persist the monotonic high-water mark directly (no longer derived
            // from the now-trimmed set).
            let _ = storage.put(
                "consensus:finalized_round",
                &self.finalized_round.to_string(),
            );
            let _ = storage.put("consensus:last_anchor_round", &anchor_round.to_string());
            let _ = storage.put("consensus:last_anchor_hash", anchor_vertex_hash);
            let _ = storage.put("consensus:finality_digest", &digest);
        }

        // 6. Update the VDF leader-election beacon from (anchor_round, finality
        // digest). SEC-#12: binding to the cumulative digest (not the bare
        // proposer-chosen anchor hash) removes the cheap single-vertex grind.
        self.update_random_beacon(anchor_round, &digest);

        Some(CommitInfo {
            sequence,
            leader: successful_leader,
            anchor_round,
            anchor_hash: anchor_vertex_hash.clone(),
            finality_digest: digest,
        })
    }

    /// H5 + M6 FIX: Leader selection now uses VDF random beacon for unpredictability.
    /// Previously this was pure deterministic round-robin (idx = round % n),
    /// making leader election fully predictable by any observer.
    /// Now the VDF beacon output is mixed into the selection to add randomness.
    /// Also removed the hardcoded "node_9009" dev fallback (M6 fix).
    fn get_leader_with_fallback(
        &self,
        round: u64,
        validators: &[(String, u64)],
        attempt: u32,
    ) -> String {
        if validators.is_empty() {
            // M6 FIX: Instead of hardcoded "node_9009", return empty string
            // The caller already handles the "no leader found" case properly
            return String::new();
        }

        // SEC (audit H-1): elect from the DETERMINISTIC Step-1 base `step1_beacon`
        // (VDF over anchor_round + cumulative finality_digest), NOT from
        // `last_vdf_output`. `last_vdf_output` is `step1_beacon` optionally folded with
        // a COMPLETE multi-party QC aggregate signature, and that fold happens per node
        // at a different moment (as each node assembles the complete QC from gossiped
        // QC_VOTEs). Electing off `last_vdf_output` therefore let a node that had folded
        // height H elect a DIFFERENT anchor leader than a node that had not yet folded
        // it — a finality-safety FORK reachable with no Byzantine participant. The
        // Step-1 base is a pure function of already-committed state, identical on every
        // honest node at commit time, so leader selection is deterministic.
        // NOTE: the Step-1 base is still proposer-biasable via chosen content (audit
        // H-2) — closing that needs a real delay-VDF (or a QC fold bound to a height
        // buried below a fixed finality lag so all nodes fold before electing); tracked
        // as deferred. The QC-folded `last_vdf_output` remains available via
        // get_random_beacon() for NON-consensus randomness only.
        let election_beacon = &self.step1_beacon;
        let vdf_seed: u64 = if election_beacon.len() >= 8 {
            let bytes: [u8; 8] = [
                election_beacon[0],
                election_beacon[1],
                election_beacon[2],
                election_beacon[3],
                election_beacon[4],
                election_beacon[5],
                election_beacon[6],
                election_beacon[7],
            ];
            u64::from_le_bytes(bytes)
        } else {
            0 // Fallback to deterministic if VDF not initialized yet (first few rounds)
        };

        // B4: STAKE-WEIGHTED leader election. The seed mixes round + VDF beacon +
        // fallback attempt (VDF changes every committed anchor -> unpredictable).
        // A validator's chance of being leader is proportional to its stake.
        // Deterministic across honest nodes: `validators` is canonically sorted
        // by address, so the cumulative-stake walk picks the same leader for the
        // same seed everywhere.
        let seed = round.wrapping_add(vdf_seed).wrapping_add(attempt as u64);
        let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();

        if total_stake == 0 {
            // Degenerate (no stake info): fall back to uniform round-robin so the
            // chain never stalls on a divide-by-zero.
            let idx = (seed % validators.len() as u64) as usize;
            return validators[idx].0.clone();
        }

        let draw = (seed as u128) % total_stake;
        let mut cumulative: u128 = 0;
        for (addr, stake) in validators {
            cumulative += *stake as u128;
            if draw < cumulative {
                return addr.clone();
            }
        }
        // Unreachable: draw < total_stake guarantees a hit above. Safe fallback.
        validators[validators.len() - 1].0.clone()
    }

    fn find_causal_history(&self, anchor_hash: &str, dag: &HashMap<String, Vertex>) -> Vec<String> {
        let mut history = Vec::new();
        let mut stack = vec![anchor_hash.to_string()];
        let mut visited = HashSet::new();

        while let Some(hash) = stack.pop() {
            if visited.contains(&hash) {
                continue;
            }
            visited.insert(hash.clone());

            if let Some(vertex) = dag.get(&hash) {
                history.push(hash.clone());
                for parent in &vertex.parents {
                    if !self.committed_sequence.contains(parent) {
                        // Optimization: Stop if already committed
                        stack.push(parent.clone());
                    }
                }
            }
        }

        // Sort by Round (ASC) then Hash (ASC) for deterministic order
        // CRITICAL FIX: Remove expect() panics, use safe error handling
        history.sort_by(|a, b| {
            // Safe retrieval with fallback
            let va_opt = dag.get(a);
            let vb_opt = dag.get(b);

            match (va_opt, vb_opt) {
                (Some(va), Some(vb)) => {
                    if va.round != vb.round {
                        va.round.cmp(&vb.round)
                    } else {
                        // FORK CHOICE RULE: Lowest hash wins (deterministic tie-breaking)
                        a.cmp(b)
                    }
                }
                (Some(_), None) => std::cmp::Ordering::Less, // A exists, B missing → A first
                (None, Some(_)) => std::cmp::Ordering::Greater, // B exists, A missing → B first
                (None, None) => std::cmp::Ordering::Equal,   // Both missing → equal
            }
        });

        history
    }
}

#[cfg(test)]
mod tests {
    use super::{OrderingEngine, COMMITTED_ROUNDS_WINDOW};
    use std::sync::Arc;
    use storage::StateDB;

    fn temp_db(suffix: &str) -> Arc<StateDB> {
        let path = format!(
            "/tmp/aincore_ordering_test_{}_{}",
            std::process::id(),
            suffix
        );
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).unwrap())
    }

    #[test]
    fn stake_quorum_requires_strict_supermajority() {
        use crate::qc::stake_quorum_met;
        // Exactly 2/3 must FAIL (strict greater-than).
        assert!(!stake_quorum_met(2, 3));
        assert!(!stake_quorum_met(20, 30));
        // Just over 2/3 passes.
        assert!(stake_quorum_met(21, 30));
        // Full stake passes; zero stake never does.
        assert!(stake_quorum_met(100, 100));
        assert!(!stake_quorum_met(0, 100));
        // Stake-weighting (not count): a 60/100-stake holder alone is NOT a
        // quorum; 67/100 is. This is the property count-based thresholds missed.
        assert!(!stake_quorum_met(60, 100));
        assert!(stake_quorum_met(67, 100));
    }

    /// B4: leader election must be STAKE-WEIGHTED (a high-stake validator leads
    /// far more often) AND deterministic (same inputs -> same leader on every
    /// honest node, or the DAG forks).
    #[test]
    fn leader_election_is_stake_weighted_and_deterministic() {
        let db = temp_db("leader_stake");
        let engine = OrderingEngine::new_with_storage(db);
        // B holds 99% of stake; canonically sorted by address.
        let validators = vec![("aaaa".to_string(), 1u64), ("bbbb".to_string(), 99u64)];

        let (mut a, mut b) = (0u32, 0u32);
        for round in 0..1000u64 {
            match engine
                .get_leader_with_fallback(round, &validators, 0)
                .as_str()
            {
                "aaaa" => a += 1,
                "bbbb" => b += 1,
                _ => {}
            }
        }
        assert!(
            b > a * 5,
            "99%-stake validator must lead far more often: a={a} b={b}"
        );
        assert!(a > 0, "low-stake validator should still occasionally lead");

        // Determinism: identical (round, attempt, set) -> identical leader.
        assert_eq!(
            engine.get_leader_with_fallback(42, &validators, 0),
            engine.get_leader_with_fallback(42, &validators, 0),
        );
        // total_stake==0 must not panic (uniform fallback).
        let zero = vec![("aaaa".to_string(), 0u64), ("bbbb".to_string(), 0u64)];
        let _ = engine.get_leader_with_fallback(1, &zero, 0);
    }

    /// SEC-#12: the leader-election beacon is deterministic across nodes and
    /// bound to the cumulative finality digest (committed history) — not a single
    /// proposer-chosen value.
    #[test]
    fn beacon_is_deterministic_and_history_dependent() {
        let mut e1 = OrderingEngine::new_with_storage(temp_db("beacon_det1"));
        let mut e2 = OrderingEngine::new_with_storage(temp_db("beacon_det2"));

        // Same (anchor_round, finality_digest) → identical beacon on independent
        // engines (consensus-critical: a divergent beacon forks leader election).
        e1.update_random_beacon(7, "digest-AAAA");
        e2.update_random_beacon(7, "digest-AAAA");
        assert_eq!(e1.get_random_beacon(), e2.get_random_beacon());
        assert_ne!(
            e1.get_random_beacon(),
            &[0u8; 32][..],
            "beacon must actually be derived (VDF present)"
        );

        // A different finality digest → different beacon: the seed tracks the whole
        // committed history, so an attacker must control the cumulative digest
        // rather than cheaply grinding one anchor vertex.
        let before = e1.get_random_beacon().to_vec();
        e1.update_random_beacon(7, "digest-BBBB");
        assert_ne!(e1.get_random_beacon(), &before[..]);

        // A different anchor round → different beacon too.
        let mut e3 = OrderingEngine::new_with_storage(temp_db("beacon_det3"));
        e3.update_random_beacon(8, "digest-AAAA");
        assert_ne!(e3.get_random_beacon(), e2.get_random_beacon());
    }

    /// SEC-#12/#22: on restart the beacon is reconstructed EXACTLY from the
    /// persisted (last_anchor_round, finality_digest) — matching what a live
    /// engine holds — without persisting the beacon itself.
    #[test]
    fn beacon_reconstructs_from_persisted_state_on_restart() {
        let path = format!(
            "/tmp/aincore_ordering_test_{}_beacon_restart",
            std::process::id()
        );
        let _ = std::fs::remove_dir_all(&path);
        let db = Arc::new(StateDB::open(&path).unwrap());
        db.put("consensus:last_anchor_round", "5").unwrap();
        db.put("consensus:finality_digest", "deadbeef-digest").unwrap();

        // Fresh engine reconstructs the beacon from persisted state...
        let restored = OrderingEngine::new_with_storage(Arc::clone(&db));
        // ...and it equals what a live engine derives from the same inputs.
        let mut live = OrderingEngine::new_with_storage(temp_db("beacon_restart_live"));
        live.update_random_beacon(5, "deadbeef-digest");

        assert_eq!(
            restored.get_random_beacon(),
            live.get_random_beacon(),
            "restart must reconstruct the exact beacon from persisted (round, digest)"
        );
        assert_ne!(restored.get_random_beacon(), &[0u8; 32][..]);
        let _ = std::fs::remove_dir_all(&path);
    }

    /// SEC (audit H-1): leader election must read the DETERMINISTIC Step-1 beacon,
    /// NOT the QC-folded `last_vdf_output` (folded per node at different moments as
    /// each assembles the complete QC from gossiped votes). Two engines that agree
    /// on the Step-1 base but DISAGREE on the folded value must still elect identical
    /// leaders every round — otherwise honest nodes fork finalized state with no
    /// Byzantine participant. This test would fail on the pre-fix code (which seeded
    /// election from `last_vdf_output`).
    #[test]
    fn leader_election_ignores_qc_fold_divergence() {
        let mut e1 = OrderingEngine::new_with_storage(temp_db("h1_fold_a"));
        let mut e2 = OrderingEngine::new_with_storage(temp_db("h1_fold_b"));
        // Same committed state -> identical Step-1 base on both engines.
        e1.update_random_beacon(11, "digest-COMMON");
        e2.update_random_beacon(11, "digest-COMMON");
        assert_eq!(
            e1.step1_beacon, e2.step1_beacon,
            "Step-1 base must match for identical committed state"
        );
        // Simulate a complete-QC fold that has landed on e1 but not yet on e2 (the
        // real cross-node timing skew): their folded beacons now diverge...
        e1.last_vdf_output = vec![0xABu8; 32];
        e2.last_vdf_output = vec![0xCDu8; 32];
        assert_ne!(e1.last_vdf_output, e2.last_vdf_output);
        // ...yet leader election (now seeded from step1_beacon) must agree EVERY round.
        let validators = vec![
            ("aaaa".to_string(), 30u64),
            ("bbbb".to_string(), 30u64),
            ("cccc".to_string(), 40u64),
        ];
        for round in 0..500u64 {
            assert_eq!(
                e1.get_leader_with_fallback(round, &validators, 0),
                e2.get_leader_with_fallback(round, &validators, 0),
                "leader must be identical despite QC-fold divergence at round {round}"
            );
        }
    }

    /// M3: a legacy node persisted committed_rounds as a huge unbounded Vec.
    /// On boot the engine must (a) bound the in-memory de-dup set to the recent
    /// window (the leak fix), and (b) recover the finality high-water mark from
    /// the max of the old data so DAG pruning has a correct watermark.
    #[test]
    fn m3_legacy_unbounded_committed_rounds_loads_bounded_with_watermark() {
        let db = temp_db("legacy_unbounded");
        // Simulate the old format: every round 0..5000 ever committed.
        let legacy: Vec<u64> = (0..5000).collect();
        db.put(
            "consensus:committed_rounds",
            &serde_json::to_string(&legacy).unwrap(),
        )
        .unwrap();

        let engine = OrderingEngine::new_with_storage(db);
        // Leak fixed: the in-memory set is bounded by the window, NOT 5000.
        assert!(
            engine.committed_rounds.len() as u64 <= COMMITTED_ROUNDS_WINDOW + 1,
            "committed_rounds must be trimmed to the recent window, got {}",
            engine.committed_rounds.len()
        );
        // Watermark recovered from the max of the legacy data.
        assert_eq!(
            engine.finalized_round, 4999,
            "high-water mark = max(rounds)"
        );
        // The oldest rounds were dropped from the set but remain rejected via the
        // high-water comparison (they are <= finalized_round).
        assert!(!engine.committed_rounds.contains(&0));
        assert!(engine.committed_rounds.contains(&4999));
    }

    /// M3: when an explicit persisted high-water mark exists it is preferred /
    /// max-merged, so the prune watermark never regresses even if the set was
    /// trimmed below it.
    #[test]
    fn m3_prefers_persisted_finalized_round_high_water() {
        let db = temp_db("persisted_hw");
        db.put(
            "consensus:committed_rounds",
            &serde_json::to_string(&vec![10u64, 11, 12]).unwrap(),
        )
        .unwrap();
        db.put("consensus:finalized_round", "9000").unwrap();

        let engine = OrderingEngine::new_with_storage(db);
        assert_eq!(
            engine.finalized_round, 9000,
            "explicit persisted high-water mark must win over the set max"
        );
    }

    // ===== SEC-#12 Step-2: QC aggregate-signature fold into the beacon =====

    use crate::qc::QuorumCertificate;

    /// Store a synthetic COMPLETE QC at `consensus:qc:{height}` with the given
    /// aggregate signature + anchor round. Only the fields the beacon fold reads
    /// (aggregate_signature, anchor_round, block_height) need be meaningful.
    fn store_qc(db: &Arc<StateDB>, height: u64, anchor_round: u64, agg: &[u8]) {
        let qc = QuorumCertificate {
            version: 1,
            chain_id: "AINCORE-TEST-1".into(),
            epoch: 0,
            finalized_round: anchor_round,
            anchor_round,
            anchor_hash: "ab".repeat(32),
            block_height: height,
            block_hash: "cd".repeat(32),
            state_root: "ef".repeat(32),
            receipts_root: "12".repeat(32),
            finality_digest: "34".repeat(32),
            validator_set_hash: "ff".repeat(32),
            signer_bitmap: vec![0xff],
            signed_stake: 100,
            total_stake: 100,
            aggregate_signature: agg.to_vec(),
        };
        db.put(
            &format!("consensus:qc:{}", height),
            &serde_json::to_string(&qc).unwrap(),
        )
        .unwrap();
    }

    /// Folding the SAME complete QC onto the SAME Step-1 base on two independent
    /// engines yields the SAME beacon (consensus-critical: divergence forks leader
    /// election). A DIFFERENT aggregate signature yields a DIFFERENT beacon.
    #[test]
    fn qc_fold_is_deterministic_and_signature_dependent() {
        let db1 = temp_db("qcfold_det1");
        let db2 = temp_db("qcfold_det2");
        store_qc(&db1, 10, 8, b"AGGREGATE-SIG-AAAA");
        store_qc(&db2, 10, 8, b"AGGREGATE-SIG-AAAA");

        let mut e1 = OrderingEngine::new_with_storage(Arc::clone(&db1));
        let mut e2 = OrderingEngine::new_with_storage(Arc::clone(&db2));
        // Identical Step-1 base on both.
        e1.update_random_beacon(8, "digest-X");
        e2.update_random_beacon(8, "digest-X");
        let step1 = e1.get_random_beacon().to_vec();
        assert_eq!(e1.get_random_beacon(), e2.get_random_beacon());

        // Fold the (identical) complete QC: both engines move to the same beacon...
        assert!(e1.fold_qc_for_height(10));
        assert!(e2.fold_qc_for_height(10));
        assert_eq!(
            e1.get_random_beacon(),
            e2.get_random_beacon(),
            "same QC + same Step-1 base must yield identical folded beacon"
        );
        // ...and the fold actually changed the beacon away from the Step-1 base.
        assert_ne!(
            e1.get_random_beacon(),
            &step1[..],
            "folding a QC must move the beacon off the Step-1 base"
        );

        // A different aggregate signature → different folded beacon.
        let db3 = temp_db("qcfold_det3");
        store_qc(&db3, 10, 8, b"AGGREGATE-SIG-BBBB");
        let mut e3 = OrderingEngine::new_with_storage(Arc::clone(&db3));
        e3.update_random_beacon(8, "digest-X");
        assert!(e3.fold_qc_for_height(10));
        assert_ne!(
            e3.get_random_beacon(),
            e1.get_random_beacon(),
            "different aggregate signature must yield a different beacon"
        );
    }

    /// Folding is idempotent + monotonic: re-folding the same height is a no-op,
    /// and folding an older height after a newer one is rejected (prevents a late
    /// out-of-order QC_VOTE from folding a stale QC onto a newer base).
    #[test]
    fn qc_fold_is_idempotent_and_monotonic() {
        let db = temp_db("qcfold_idem");
        store_qc(&db, 9, 7, b"SIG-9");
        store_qc(&db, 10, 8, b"SIG-10");
        let mut e = OrderingEngine::new_with_storage(Arc::clone(&db));
        e.update_random_beacon(8, "d");

        assert!(e.fold_qc_for_height(10), "first fold of height 10 applies");
        let after = e.get_random_beacon().to_vec();
        // Re-folding the same height: no-op (idempotent).
        assert!(!e.fold_qc_for_height(10), "re-fold of same height is a no-op");
        assert_eq!(e.get_random_beacon(), &after[..]);
        // Folding an OLDER height than the last folded one is rejected.
        assert!(
            !e.fold_qc_for_height(9),
            "older-height fold after a newer one must be rejected"
        );
        assert_eq!(e.get_random_beacon(), &after[..]);
    }

    /// No complete QC for the height → fold is a no-op and the Step-1 (digest-bound)
    /// beacon still applies (Step-1 remains the base).
    #[test]
    fn qc_fold_noop_without_complete_qc() {
        let db = temp_db("qcfold_noqc");
        let mut e = OrderingEngine::new_with_storage(Arc::clone(&db));
        e.update_random_beacon(8, "digest-Z");
        let step1 = e.get_random_beacon().to_vec();
        assert!(
            !e.fold_qc_for_height(10),
            "no QC stored → nothing to fold"
        );
        assert_eq!(
            e.get_random_beacon(),
            &step1[..],
            "without a complete QC the Step-1 beacon is unchanged"
        );
    }

    /// Restart reproduces the EXACT folded beacon from persisted state: a fresh
    /// engine re-derives the Step-1 base and re-applies the folded QC, matching a
    /// live engine that committed + folded.
    #[test]
    fn qc_fold_reproduces_on_restart() {
        let path = format!(
            "/tmp/aincore_ordering_test_{}_qcfold_restart",
            std::process::id()
        );
        let _ = std::fs::remove_dir_all(&path);
        let db = Arc::new(StateDB::open(&path).unwrap());
        store_qc(&db, 10, 8, b"RESTART-AGG-SIG");
        // Persist the Step-1 inputs exactly as the commit path does.
        db.put("consensus:last_anchor_round", "8").unwrap();
        db.put("consensus:finality_digest", "restart-digest").unwrap();

        // Live engine: derive Step-1 base, then fold the complete QC for height 10.
        let mut live = OrderingEngine::new_with_storage(Arc::clone(&db));
        live.update_random_beacon(8, "restart-digest");
        assert!(live.fold_qc_for_height(10));
        let live_beacon = live.get_random_beacon().to_vec();

        // Fresh restart from the SAME db must reconstruct the identical folded beacon
        // (anchor-round marker == last_anchor_round → fold re-applied).
        let restored = OrderingEngine::new_with_storage(Arc::clone(&db));
        assert_eq!(
            restored.get_random_beacon(),
            &live_beacon[..],
            "restart must reproduce the exact folded beacon from persisted state"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    /// A stale fold marker from an EARLIER Step-1 base (whose later heights had no
    /// complete QC, so the live beacon advanced to a newer unfolded Step-1 base) is
    /// NOT mis-applied on restart: the anchor-round guard keeps restart equal to the
    /// live unfolded beacon.
    #[test]
    fn stale_fold_marker_not_reapplied_on_restart() {
        let path = format!(
            "/tmp/aincore_ordering_test_{}_qcfold_stale",
            std::process::id()
        );
        let _ = std::fs::remove_dir_all(&path);
        let db = Arc::new(StateDB::open(&path).unwrap());
        // A QC was folded at an OLD anchor round 8 / height 10...
        store_qc(&db, 10, 8, b"OLD-AGG-SIG");
        db.put("consensus:beacon_folded_qc_height", "10").unwrap();
        db.put("consensus:beacon_folded_anchor_round", "8").unwrap();
        // ...but the chain has since committed up to a NEWER anchor round 20 with no
        // complete QC folded onto it (Step-1 base only).
        db.put("consensus:last_anchor_round", "20").unwrap();
        db.put("consensus:finality_digest", "newer-digest").unwrap();

        let restored = OrderingEngine::new_with_storage(Arc::clone(&db));

        // Expected: the pure Step-1 base for (20, "newer-digest") — NO fold applied.
        let mut step1_only = OrderingEngine::new_with_storage(temp_db("qcfold_stale_ref"));
        step1_only.update_random_beacon(20, "newer-digest");
        assert_eq!(
            restored.get_random_beacon(),
            step1_only.get_random_beacon(),
            "a stale fold marker for an earlier base must NOT be re-applied"
        );
        let _ = std::fs::remove_dir_all(&path);
    }
}
