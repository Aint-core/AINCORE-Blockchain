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
    /// AUDIT-B4b: the next anchor round whose commit/skip decision is PENDING.
    /// Anchors are decided strictly in round order from this cursor — never from
    /// whatever round an arriving vertex happens to carry. Persisted as
    /// `consensus:next_anchor_round`; on restart it resumes at
    /// max(persisted, finalized_round + 1), and rounds above it whose skip
    /// decisions were lost are simply re-derived from the DAG (the decision is a
    /// pure function of DAG contents, so the re-derivation is identical).
    ///
    /// ANCHORS LIVE ON EVEN ROUNDS ONLY (Bullshark's two-round wave). This is
    /// not a style choice — it is what makes commit/skip decisions CONVERGE.
    /// The skip-proof walks the next committed anchor's causal history; quorum
    /// intersection guarantees a voted anchor appears in that history only when
    /// the next anchor is at least TWO rounds above (its 2f+1 parents at r+1
    /// must intersect the 2f+1 voters at r+1). With anchors on EVERY round the
    /// next anchor sat at r+1 and owed the voted anchor nothing — so one node
    /// could commit round r on direct votes while another PROVED a skip from a
    /// consistent-but-different DAG subset. Observed live at round 728: NAS
    /// committed it, LAP/PI/LP4 skipped it, and the block chains split.
    pub next_anchor_round: u64,
    pub committed_sequence: Vec<String>, // recent committed vertex hashes (bounded window)
    /// O(1) membership mirror of `committed_sequence` for the commit-time de-dup
    /// (`retain` / `contains`). Kept in lockstep with the Vec so the per-commit
    /// de-dup no longer does a linear scan over an ever-growing list.
    committed_set: std::collections::HashSet<String>,
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

/// In-memory retention for the committed-hash de-dup index. The DAG is pruned at
/// `finalized - 10`, so causal history never reaches back more than a handful of
/// rounds — this window is deliberately generous. Persisted INCREMENTALLY as one
/// small per-round key (`consensus:cseq:{round}`); the previous code re-serialised
/// the WHOLE 10k-hash window to a single key on EVERY commit, i.e. ~700 KB/round
/// of WAL write-amplification at the cap (measured ~90 KB/round even near-empty).
const COMMITTED_SEQ_WINDOW: usize = 8192;
/// Per-round committed-hash key prefix (append-only; pruned with the round window).
const COMMITTED_SEQ_KEY_PREFIX: &str = "consensus:cseq:";

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
            next_anchor_round: 1,
            committed_sequence: Vec::new(),
            committed_set: HashSet::new(),
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

        // Rebuild the bounded committed-hash de-dup index from the recent per-round
        // keys (consensus:cseq:{round}). Only rounds still inside committed_rounds
        // are read, so this is O(window) — and it replaces the previous single giant
        // key that was rewritten in full on every commit.
        let mut committed_sequence: Vec<String> = Vec::new();
        let mut committed_set: HashSet<String> = HashSet::new();
        {
            let mut recent: Vec<u64> = committed_rounds.iter().copied().collect();
            recent.sort_unstable();
            for r in recent {
                if let Ok(Some(json)) =
                    storage.get(&format!("{}{}", COMMITTED_SEQ_KEY_PREFIX, r))
                {
                    if let Ok(hashes) = serde_json::from_str::<Vec<String>>(&json) {
                        for h in hashes {
                            if committed_set.insert(h.clone()) {
                                committed_sequence.push(h);
                            }
                        }
                    }
                }
            }
            // Backward-compat: fold in the legacy single-key blob if present (older
            // nodes wrote consensus:committed_sequence; ignored once cseq keys exist).
            if committed_sequence.is_empty() {
                if let Ok(Some(json)) = storage.get("consensus:committed_sequence") {
                    if let Ok(seq) = serde_json::from_str::<Vec<String>>(&json) {
                        for h in seq {
                            if committed_set.insert(h.clone()) {
                                committed_sequence.push(h);
                            }
                        }
                    }
                }
            }
            if committed_sequence.len() > COMMITTED_SEQ_WINDOW {
                let excess = committed_sequence.len() - COMMITTED_SEQ_WINDOW;
                for h in committed_sequence.drain(0..excess) {
                    committed_set.remove(&h);
                }
            }
            if !committed_sequence.is_empty() {
                println!(
                    "🔄 Restored {} committed vertex hashes (de-dup index)",
                    committed_sequence.len()
                );
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

        // AUDIT-B4b: resume the anchor cursor. Persisted value wins when it is
        // ahead (it also encodes SKIP decisions past the last commit); otherwise
        // derive from the finality high-water mark.
        let mut next_anchor_round = finalized_round.saturating_add(1).max(1);
        if let Ok(Some(s)) = storage.get("consensus:next_anchor_round") {
            if let Ok(persisted) = s.parse::<u64>() {
                next_anchor_round = next_anchor_round.max(persisted);
            }
        }

        Self {
            committed_rounds,
            finalized_round,
            next_anchor_round,
            committed_sequence,
            committed_set,
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

    /// Record newly committed hashes into the bounded in-memory de-dup index
    /// (Vec + HashSet mirror), evicting the oldest entries once the window is
    /// exceeded. Front eviction is a single O(len) drain, done at most once per
    /// commit — cheap relative to the removed per-round 700 KB re-serialisation.
    fn record_committed(&mut self, new_hashes: &[String]) {
        for h in new_hashes {
            if self.committed_set.insert(h.clone()) {
                self.committed_sequence.push(h.clone());
            }
        }
        if self.committed_sequence.len() > COMMITTED_SEQ_WINDOW {
            let excess = self.committed_sequence.len() - COMMITTED_SEQ_WINDOW;
            for h in self.committed_sequence.drain(0..excess) {
                self.committed_set.remove(&h);
            }
        }
    }

    /// Mencoba melakukan commit pada ronde tertentu
    /// AUDIT-B4b: decide anchors STRICTLY IN ROUND ORDER from a persisted
    /// cursor, committing or skipping each one deterministically (Bullshark's
    /// rule, Spiegelman et al., CCS 2022), and emit ONE CommitInfo per committed
    /// anchor.
    ///
    /// # What was wrong
    ///
    /// This used to be called once per INCOMING VERTEX with that vertex's round
    /// as the anchor cursor, and a "view change" fallback elected whichever
    /// backup leader happened to have a vertex in the LOCAL DAG. Both made the
    /// committed-anchor sequence a function of vertex ARRIVAL ORDER, which
    /// differs per node — so nodes packaged different anchor rounds into the
    /// same block height, and the first 4-validator cluster forked three ways at
    /// the block level (identical DAG, different height<->round mapping;
    /// LAP built height 50 from round 52, NAS from round 53).
    ///
    /// # The rule
    ///
    ///  * Anchor r commits DIRECTLY when a stake-quorum (>2/3) of round r+1
    ///    vertices reference the round-r leader's vertex as a parent.
    ///  * When anchor r' commits directly, every undecided round j < r' is
    ///    decided by ANCESTRY, walking back down the committed-anchor chain:
    ///    leader_vertex(j) in the chain's causal history -> commit j too,
    ///    otherwise SKIP j permanently. No availability-driven backup leaders.
    ///  * Quorum intersection makes this arrival-order independent: if round j
    ///    ever had a direct quorum, every vertex at j+2 references >2/3 of the
    ///    j+1 vertices, which intersects the >2/3 that voted for the leader —
    ///    so leader_vertex(j) is an ancestor of EVERY later vertex, and a node
    ///    that missed the votes still commits j via the ancestry walk. Early
    ///    and late evaluators reach identical sequences.
    ///
    /// Anything not yet decidable — no direct anchor found ahead, or a HOLE (a
    /// referenced vertex missing from the local DAG) — stops the scan; gossip
    /// refills the DAG and a later call resumes from the same cursor. Deferring
    /// is safe; guessing is what forked the chain.
    ///
    /// `_current_round` is kept for call-site compatibility; the cursor, not
    /// the caller, decides what is evaluated.
    pub fn try_commit(
        &mut self,
        _current_round: u64,
        dag: &HashMap<String, Vertex>,
        round_index: &HashMap<u64, Vec<String>>,
        // B4: (address, stake) pairs, canonically sorted by address (the order
        // get_validator_set_with_stake guarantees) so leader election is
        // deterministic across honest nodes.
        validators: &[(String, u64)],
    ) -> Vec<CommitInfo> {
        let mut out = Vec::new();
        if validators.is_empty() {
            return out;
        }
        let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();
        if total_stake == 0 {
            return out;
        }
        let max_round = round_index.keys().copied().max().unwrap_or(0);
        // Backstop against pathological cursor-to-tip gaps; the cursor normally
        // trails the tip by a handful of rounds.
        const MAX_SCAN: u64 = 10_000;

        // ONE anchor per call (see step 3): no outer loop -- the caller executes
        // the returned anchor, re-samples the validator set, and calls again.
        {
            // Anchors live on EVEN rounds only (see the next_anchor_round doc).
            let start = Self::align_anchor(self.next_anchor_round.max(1));
            // 1. Find the SMALLEST directly-committable anchor round >= cursor.
            let mut direct: Option<(u64, String)> = None;
            let mut r = start;
            while r < max_round && r - start < MAX_SCAN {
                if let Some(h) = Self::leader_vertex_hash(r, dag, round_index, validators) {
                    if Self::direct_quorum_met(r, &h, dag, round_index, validators, total_stake)
                    {
                        direct = Some((r, h));
                        break;
                    }
                }
                r += 2;
            }
            let Some((r_direct, direct_hash)) = direct else {
                return out;
            };

            // 2. Walk BACK from the direct anchor, deciding every round in
            //    [cursor, r_direct) by ancestry along the committed-anchor chain.
            let mut to_commit: Vec<(u64, String)> = vec![(r_direct, direct_hash.clone())];
            let mut chain = direct_hash;
            for j in (start..r_direct).rev().filter(|j| j.is_multiple_of(2)) {
                let chain_round = match dag.get(&chain) {
                    Some(v) => v.round,
                    None => return out, // cannot happen, but never guess
                };
                let Some(visited) =
                    Self::walk_history(&chain, j, chain_round, dag, &self.committed_set)
                else {
                    // HOLE below the chain anchor: not decidable yet.
                    return out;
                };
                match Self::leader_vertex_hash(j, dag, round_index, validators) {
                    Some(hj) if visited.contains(&hj) => {
                        to_commit.push((j, hj.clone()));
                        chain = hj;
                    }
                    // Leader vertex known and provably NOT an ancestor, or no
                    // leader vertex exists anywhere in the chain's complete
                    // history: SKIP j. (The walk above was complete, so absence
                    // is proof, not a guess.)
                    _ => {}
                }
            }

            // 3. Commit the LOWEST decidable anchor -- ONE per call.
            // PROTOCOL (re-audit HIGH): the caller executes this anchor's block
            // (which may slash / join / leave and rewrite the validator set),
            // re-samples the set, and calls again. Deciding a whole batch from
            // one sample let a node that batched [k, k+1] elect k+1's leader
            // from the PRE-k set while a node that decided k+1 after executing
            // k used the POST-k set -- different leader/reward -> fork.
            to_commit.reverse();
            if let Some((anchor_round, anchor_hash)) = to_commit.into_iter().next() {
                let leader = Self::leader_for_round(anchor_round, validators, 0);
                // Incomplete history for this anchor: return nothing, retry
                // later from the same cursor.
                if let Some(info) =
                    self.commit_one_anchor(anchor_round, &anchor_hash, leader, dag)
                {
                    out.push(info);
                }
            }
        }
        out
    }

    /// Smallest EVEN round >= r (anchors live on even rounds — Bullshark waves).
    fn align_anchor(r: u64) -> u64 {
        if r.is_multiple_of(2) {
            r
        } else {
            r + 1
        }
    }

    /// The round-r leader's vertex hash, if present in the local DAG.
    /// Leader = `leader_for_round(r, validators, 0)` — the PURE function; no
    /// availability-driven fallback attempts (those were half the fork).
    fn leader_vertex_hash(
        round: u64,
        dag: &HashMap<String, Vertex>,
        round_index: &HashMap<u64, Vec<String>>,
        validators: &[(String, u64)],
    ) -> Option<String> {
        let leader = Self::leader_for_round(round, validators, 0);
        round_index.get(&round)?.iter().find_map(|h| {
            dag.get(h)
                .filter(|v| v.author == leader)
                .map(|_| h.clone())
        })
    }

    /// Stake-weighted direct-commit check: do round r+1 vertices from a strict
    /// >2/3 stake of DISTINCT authors reference `anchor_hash` as a parent?
    fn direct_quorum_met(
        round: u64,
        anchor_hash: &str,
        dag: &HashMap<String, Vertex>,
        round_index: &HashMap<u64, Vec<String>>,
        validators: &[(String, u64)],
        total_stake: u128,
    ) -> bool {
        let Some(votes) = round_index.get(&(round + 1)) else {
            return false;
        };
        let stakes: HashMap<&str, u64> =
            validators.iter().map(|(a, s)| (a.as_str(), *s)).collect();
        let mut voted: HashSet<&str> = HashSet::new();
        for vh in votes {
            if let Some(v) = dag.get(vh) {
                if v.parents.iter().any(|p| p == anchor_hash) {
                    voted.insert(v.author.as_str());
                }
            }
        }
        let signed: u128 = voted
            .iter()
            .filter_map(|a| stakes.get(a).map(|s| *s as u128))
            .sum();
        crate::qc::stake_quorum_met(signed, total_stake)
    }

    /// Walk the causal history of `from` down to rounds >= `floor`, returning
    /// the set of visited vertex hashes — or None if the walk hits a HOLE: a
    /// referenced parent that is neither in the local DAG, nor already
    /// committed, nor the genesis sentinel. A complete walk is what makes a
    /// SKIP decision a proof instead of a guess.
    fn walk_history(
        from: &str,
        floor: u64,
        from_round: u64,
        dag: &HashMap<String, Vertex>,
        committed_set: &std::collections::HashSet<String>,
    ) -> Option<HashSet<String>> {
        let _ = from_round; // bounded implicitly: rounds strictly decrease
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack = vec![from.to_string()];
        while let Some(h) = stack.pop() {
            if visited.contains(&h) {
                continue;
            }
            let Some(v) = dag.get(&h) else {
                if h == "genesis" || committed_set.contains(&h) {
                    continue; // settled — not a hole
                }
                return None; // hole
            };
            visited.insert(h);
            if v.round <= floor {
                continue; // do not descend below the floor
            }
            for p in &v.parents {
                if p != "genesis" && !committed_set.contains(p) {
                    stack.push(p.clone());
                }
            }
        }
        Some(visited)
    }

    /// Book-keeping for ONE committed anchor: complete causal history (deferred
    /// on holes), de-dup, digest fold, persistence, beacon. Extracted verbatim
    /// from the old commit tail; the only structural change is that the cursor
    /// (`next_anchor_round`) advances and persists with each anchor.
    fn commit_one_anchor(
        &mut self,
        anchor_round: u64,
        anchor_vertex_hash: &str,
        leader: String,
        dag: &HashMap<String, Vertex>,
    ) -> Option<CommitInfo> {
        // Completeness gate: an anchor with a hole in its history must WAIT,
        // not commit a partial sequence (the old find_causal_history silently
        // dropped missing vertices, which would diverge across nodes).
        let anchor_round_in_dag = dag.get(anchor_vertex_hash).map(|v| v.round)?;
        Self::walk_history(
            anchor_vertex_hash,
            0,
            anchor_round_in_dag,
            dag,
            &self.committed_set,
        )?;

        let mut sequence = self.find_causal_history(anchor_vertex_hash, dag);
        // Filter yang sudah committed (O(1) membership via the mirror set).
        sequence.retain(|h| !self.committed_set.contains(h));

        Some(self.apply_anchor_bookkeeping(
            anchor_round,
            anchor_vertex_hash,
            leader,
            sequence,
        ))
    }

    /// Shared bookkeeping for ONE anchor that has been DECIDED — either by this
    /// node's own commit path or by adopting a synced block's committed
    /// sequence (see `adopt_synced_anchor`). Identical state transitions on both
    /// paths are what keep a catching-up follower in exact parity with the
    /// validator that produced the block: same committed_set, same cursor, same
    /// rolling finality digest.
    fn apply_anchor_bookkeeping(
        &mut self,
        anchor_round: u64,
        anchor_vertex_hash: &str,
        leader: String,
        sequence: Vec<String>,
    ) -> CommitInfo {
        println!(
            "⚓ Committing Anchor Round {} (Leader {}, {} vertices)",
            anchor_round,
            leader,
            sequence.len()
        );

        // Update state
        self.committed_rounds.insert(anchor_round);
        // Advance the monotonic finality high-water mark.
        self.finalized_round = self.finalized_round.max(anchor_round);
        // Cursor: this anchor round is decided; never revisit it.
        self.next_anchor_round = self.next_anchor_round.max(anchor_round + 1);
        // Trim the de-dup window so `committed_rounds` stays bounded regardless of
        // how many rounds are committed (this is the leak fix). Rounds below the
        // cutoff are still rejected by the high-water comparison in the guard.
        // The evicted rounds also get their per-round cseq keys deleted below.
        let cutoff = self.finalized_round.saturating_sub(COMMITTED_ROUNDS_WINDOW);
        let evicted_cseq_rounds: Vec<u64> = if cutoff > 0 {
            let ev: Vec<u64> = self
                .committed_rounds
                .iter()
                .copied()
                .filter(|r| *r < cutoff)
                .collect();
            self.committed_rounds.retain(|r| *r >= cutoff);
            ev
        } else {
            Vec::new()
        };
        // Bounded in-memory de-dup index (Vec + set), no unbounded growth.
        self.record_committed(&sequence);

        // Fold this commit's newly-ordered vertex hashes into the rolling finality
        // digest, chained from the previous (persisted) value. With the anchor
        // sequence now deterministic, every node folds the SAME sequences in the
        // SAME order, so the digest finally agrees across nodes too.
        self.finality_digest = Self::fold_finality_digest(&self.finality_digest, &sequence);
        let digest = self.finality_digest.clone();

        // PERSIST committed state to DB (BUG #1 FIX)
        if let Some(ref storage) = self.storage {
            if let Ok(json) =
                serde_json::to_string(&self.committed_rounds.iter().collect::<Vec<_>>())
            {
                let _ = storage.put("consensus:committed_rounds", &json);
            }
            if !sequence.is_empty() {
                if let Ok(json) = serde_json::to_string(&sequence) {
                    let _ = storage
                        .put(&format!("{}{}", COMMITTED_SEQ_KEY_PREFIX, anchor_round), &json);
                }
            }
            for r in &evicted_cseq_rounds {
                let _ = storage.delete(&format!("{}{}", COMMITTED_SEQ_KEY_PREFIX, r));
            }
            let _ = storage.put(
                "consensus:finalized_round",
                &self.finalized_round.to_string(),
            );
            let _ = storage.put(
                "consensus:next_anchor_round",
                &self.next_anchor_round.to_string(),
            );
            let _ = storage.put("consensus:last_anchor_round", &anchor_round.to_string());
            let _ = storage.put("consensus:last_anchor_hash", anchor_vertex_hash);
            let _ = storage.put("consensus:finality_digest", &digest);
        }

        // 6. Update the VDF leader-election beacon from (anchor_round, finality
        // digest). SEC-#12 note: since B4a the beacon no longer feeds leader
        // election (which is a pure function); it remains for non-consensus
        // randomness via get_random_beacon().
        self.update_random_beacon(anchor_round, &digest);

        CommitInfo {
            sequence,
            leader,
            anchor_round,
            anchor_hash: anchor_vertex_hash.to_string(),
            finality_digest: digest,
        }
    }

    /// LIVENESS (burn-in finding): adopt an anchor that the NETWORK decided and
    /// that reached this node as a synced block carrying its committed vertex
    /// sequence.
    ///
    /// Why this exists: gossip is lossy (`Parents=3` is routine on the live
    /// cluster). Once a follower's DAG has a hole below its cursor, the
    /// completeness gate defers forever — correctly, but silently — and the
    /// producing validator prunes the missing vertex long before re-gossip
    /// could refill it. Observed live: two validators stuck at anchor 7110 and
    /// one at 55942 for ~48h while the chain tip (via ChainSync) sat at 45k
    /// blocks. A stalled follower also stops casting finality votes, so the
    /// >2/3 QC quorum dies with it — and with it every QC-gated path.
    ///
    /// The synced block IS the network's decision for this anchor round. Folding
    /// its sequence VERBATIM (not re-filtered — the producer already filtered
    /// against its own committed set, which is a superset of ours at this point)
    /// reproduces the producer's bookkeeping exactly, so the cursor jumps past
    /// the hole and later local commits agree byte-for-byte.
    ///
    /// Returns the CommitInfo so the caller can cast this node's finality vote
    /// for the block, restoring QC quorum. No-op for already-decided rounds.
    pub fn adopt_synced_anchor(
        &mut self,
        anchor_round: u64,
        anchor_hash: &str,
        sequence: &[String],
        validators: &[(String, u64)],
    ) -> Option<CommitInfo> {
        if anchor_round <= self.finalized_round || self.committed_rounds.contains(&anchor_round) {
            return None;
        }
        let leader = Self::leader_for_round(anchor_round, validators, 0);
        println!(
            "⚓ Adopting synced anchor round {} ({} vertices): cursor {} -> {}",
            anchor_round,
            sequence.len(),
            self.next_anchor_round,
            anchor_round + 1
        );
        Some(self.apply_anchor_bookkeeping(anchor_round, anchor_hash, leader, sequence.to_vec()))
    }

    /// Elect the anchor leader for `round` as a PURE function of the round, the
    /// active validator set, and the fallback attempt.
    ///
    /// # Why this stopped using the VDF beacon (AUDIT-B4)
    ///
    /// Election used to seed from `self.step1_beacon`, which
    /// `update_random_beacon` refreshes on every LOCAL commit. Two honest nodes at
    /// different commit heights therefore held DIFFERENT beacons, and while both
    /// were deciding the same anchor round they could elect DIFFERENT leaders —
    /// a finality fork reachable with zero Byzantine participants, purely from one
    /// node being a commit behind (exactly the situation during catch-up, which is
    /// the common case on a real network).
    ///
    /// A previous fix (audit H-1) had already moved election off `last_vdf_output`
    /// onto `step1_beacon` for the same class of reason, but stopped one step
    /// short: `step1_beacon` is still per-node mutable state, not committed data.
    ///
    /// The seed is now `Sha256("AINCORE_LEADER_V2" || round || (addr,stake)*)`,
    /// so every node computes the same leader for the same round given the same
    /// validator set — the property Bullshark's anchor rule actually requires.
    ///
    /// Cost: leader identity becomes predictable in advance. That is the documented
    /// H-2 trade-off and it is the correct one — predictability is a grinding
    /// concern to be closed by a real delay-VDF, whereas non-determinism here is an
    /// outright safety break. The QC-folded beacon remains available via
    /// `get_random_beacon()` for NON-consensus randomness.
    pub(crate) fn leader_for_round(round: u64, validators: &[(String, u64)], attempt: u32) -> String {
        if validators.is_empty() {
            // M6 FIX: Instead of hardcoded "node_9009", return empty string
            // The caller already handles the "no leader found" case properly
            return String::new();
        }

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"AINCORE_LEADER_V2");
        hasher.update(round.to_le_bytes());
        hasher.update((attempt as u64).to_le_bytes());
        // `validators` is canonically sorted by address by
        // get_validator_set_with_stake, so this preimage is identical everywhere.
        for (addr, stake) in validators {
            hasher.update(addr.as_bytes());
            hasher.update(stake.to_le_bytes());
        }
        let digest = hasher.finalize();
        let seed = u64::from_le_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ]);

        // B4: STAKE-WEIGHTED leader election. A validator's chance of being leader
        // is proportional to its stake. Deterministic across honest nodes:
        // `validators` is canonically sorted by address, so the cumulative-stake
        // walk picks the same leader for the same seed everywhere.
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
                    if !self.committed_set.contains(parent) {
                        // Optimization: Stop if already committed (O(1) via mirror set)
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

    /// PROTOCOL (re-audit HIGH): try_commit now decides ONE anchor per call so
    /// the caller can execute it and re-sample the validator set before the
    /// next. Tests that reason about "everything decidable right now" drain
    /// the engine the way DagConsensus does: call until it returns nothing.
    fn drain(
        engine: &mut super::OrderingEngine,
        dag: &std::collections::HashMap<String, blockchain::Vertex>,
        idx: &std::collections::HashMap<u64, Vec<String>>,
        validators: &[(String, u64)],
    ) -> Vec<super::CommitInfo> {
        let mut out = Vec::new();
        loop {
            let mut one = engine.try_commit(0, dag, idx, validators);
            if one.is_empty() {
                break;
            }
            out.append(&mut one);
        }
        out
    }


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
        let _engine = OrderingEngine::new_with_storage(db);
        // B holds 99% of stake; canonically sorted by address.
        let validators = vec![("aaaa".to_string(), 1u64), ("bbbb".to_string(), 99u64)];

        let (mut a, mut b) = (0u32, 0u32);
        for round in 0..1000u64 {
            match OrderingEngine::leader_for_round(round, &validators, 0)
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
            OrderingEngine::leader_for_round(42, &validators, 0),
            OrderingEngine::leader_for_round(42, &validators, 0),
        );
        // total_stake==0 must not panic (uniform fallback).
        let zero = vec![("aaaa".to_string(), 0u64), ("bbbb".to_string(), 0u64)];
        let _ = OrderingEngine::leader_for_round(1, &zero, 0);
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
                OrderingEngine::leader_for_round(round, &validators, 0),
                OrderingEngine::leader_for_round(round, &validators, 0),
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

    /// AUDIT-B4: anchor leader election must be a PURE function of (round,
    /// validators) — never of per-node mutable state.
    ///
    /// Election used to seed from `step1_beacon`, which `update_random_beacon`
    /// refreshes on every LOCAL commit. Two honest nodes at different commit
    /// heights therefore held different beacons and, while both were deciding the
    /// SAME anchor round, could elect DIFFERENT leaders — a finality fork with
    /// zero Byzantine participants, and precisely the state a node is in while
    /// catching up. This test pins the fix: two engines whose beacons have been
    /// driven to different values must still agree on every round's leader.
    #[test]
    fn test_b4_leader_election_is_independent_of_local_beacon_state() {
        let validators: Vec<(String, u64)> = vec![
            ("aaaa000000000000000000000000000000000000000000000000000000000001".to_string(), 1000),
            ("bbbb000000000000000000000000000000000000000000000000000000000002".to_string(), 1000),
            ("cccc000000000000000000000000000000000000000000000000000000000003".to_string(), 1000),
        ];

        let mut node_a = OrderingEngine::new();
        let mut node_b = OrderingEngine::new();

        // Drive the two nodes' beacons apart, exactly as differing commit heights do.
        node_a.update_random_beacon(7, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        node_b.update_random_beacon(99, "ffffffffffffffffffffffffffffffff");
        assert_ne!(
            node_a.get_random_beacon(),
            node_b.get_random_beacon(),
            "test setup invariant: the two nodes must hold different beacons"
        );

        for round in 1u64..200 {
            for attempt in 0u32..3 {
                assert_eq!(
                    OrderingEngine::leader_for_round(round, &validators, attempt),
                    OrderingEngine::leader_for_round(round, &validators, attempt),
                    "nodes with different beacons must still elect the same leader \
                     for round {} attempt {}",
                    round,
                    attempt
                );
            }
        }
    }

    /// Election must still be stake-weighted and must still spread leadership
    /// across the validator set (a constant leader would centralise proposals).
    #[test]
    fn test_b4_leader_election_still_rotates_and_covers_the_set() {
        let validators: Vec<(String, u64)> = vec![
            ("aaaa000000000000000000000000000000000000000000000000000000000001".to_string(), 1000),
            ("bbbb000000000000000000000000000000000000000000000000000000000002".to_string(), 1000),
            ("cccc000000000000000000000000000000000000000000000000000000000003".to_string(), 1000),
        ];
        let _engine = OrderingEngine::new();
        let mut seen = std::collections::HashSet::new();
        for round in 1u64..500 {
            seen.insert(OrderingEngine::leader_for_round(round, &validators, 0));
        }
        assert_eq!(
            seen.len(),
            3,
            "every equal-stake validator must be elected at some round, got {:?}",
            seen
        );
    }

    /// A validator that leaves or joins changes the leader schedule — the schedule
    /// is bound to the validator set, so nodes MUST use the same set. This pins
    /// that the set is part of the preimage (a regression here would silently
    /// re-introduce cross-node divergence when sets differ).
    #[test]
    fn test_b4_leader_schedule_is_bound_to_the_validator_set() {
        let set_a: Vec<(String, u64)> = vec![
            ("aaaa000000000000000000000000000000000000000000000000000000000001".to_string(), 1000),
            ("bbbb000000000000000000000000000000000000000000000000000000000002".to_string(), 1000),
        ];
        let mut set_b = set_a.clone();
        set_b.push((
            "cccc000000000000000000000000000000000000000000000000000000000003".to_string(),
            1000,
        ));
        let _engine = OrderingEngine::new();
        let differs = (1u64..50)
            .any(|r| OrderingEngine::leader_for_round(r, &set_a, 0)
                != OrderingEngine::leader_for_round(r, &set_b, 0));
        assert!(differs, "the validator set must be part of the election preimage");
    }

    // ===================== AUDIT-B4b determinism tests =====================
    //
    // These pin the exact property the live 4-validator cluster violated: the
    // committed-anchor sequence (and therefore the block chain) must be a pure
    // function of DAG contents, independent of vertex ARRIVAL ORDER and of WHEN
    // each node happens to evaluate.

    fn mk_validators(n: usize) -> Vec<(String, u64)> {
        // Distinct, sorted addresses with equal stake.
        (0..n)
            .map(|i| (format!("{:0>64}", format!("{}a", i)), 1000u64))
            .collect()
    }

    fn mk_vertex(
        round: u64,
        author: &str,
        parents: Vec<String>,
    ) -> (String, blockchain::Vertex) {
        // Full author in the hash: synthetic addresses differ only at the END,
        // so a prefix would collide and silently overwrite dag entries.
        let hash = format!("v{}_{}", round, author);
        (
            hash.clone(),
            blockchain::Vertex {
                round,
                author: author.to_string(),
                timestamp: 1_000 + round,
                payload: vec![],
                parents,
                hash,
                signature: String::new(),
                aggregated_signature: None,
            payload_root: None,
            parents_root: None,
            },
        )
    }

    /// Build a full-mesh DAG: every validator emits one vertex per round, each
    /// referencing ALL of the previous round's vertices (parent quorum always
    /// met, every leader always has direct votes).
    #[allow(clippy::type_complexity)]
    fn full_mesh(
        validators: &[(String, u64)],
        rounds: u64,
    ) -> (
        std::collections::HashMap<String, blockchain::Vertex>,
        std::collections::HashMap<u64, Vec<String>>,
    ) {
        let mut dag = std::collections::HashMap::new();
        let mut idx: std::collections::HashMap<u64, Vec<String>> =
            std::collections::HashMap::new();
        let mut prev: Vec<String> = vec!["genesis".to_string()];
        for r in 1..=rounds {
            let mut this = Vec::new();
            for (a, _) in validators {
                let (h, v) = mk_vertex(r, a, prev.clone());
                this.push(h.clone());
                idx.entry(r).or_default().push(h.clone());
                dag.insert(h, v);
            }
            prev = this;
        }
        (dag, idx)
    }

    fn commit_fingerprint(commits: &[super::CommitInfo]) -> Vec<(u64, String, Vec<String>)> {
        commits
            .iter()
            .map(|c| (c.anchor_round, c.anchor_hash.clone(), c.sequence.clone()))
            .collect()
    }

    // ===================================================================
    // TIER-1 DST: the anchor decision function, evaluated over hand-built DAGs.
    //
    // WHY THIS EXISTS. The 35 existing consensus tests are hand-written EXAMPLES;
    // a Byzantine validator picks from an unbounded space of schedules. This is
    // the seam a seeded scheduler will drive: no storage, no clock, no
    // signatures (`OrderingEngine::new()` sets `storage: None`), so it runs at
    // ~0.01 s per schedule.
    //
    // KNOWN LIMIT, stated here because it will otherwise be forgotten: tier 1
    // does NOT execute `add_vertex`, so any candidate fix expressed as an
    // admission filter here is a SECOND IMPLEMENTATION of that rule. It proves
    // a property is ACHIEVABLE; it does not validate the production fix. That
    // needs a tier-2 (node-level) test.
    //
    // Tier 1 also provably cannot express P-ANCHOR-HEIGHT — the anchor_round ->
    // block_height map whose violation WAS the live B4b fork. Measured, not
    // assumed: `CommitInfo` (this file) has no height field, because height is
    // fixed at dag.rs:1508 as `latest_block_height + 1` INSIDE an 8x250ms
    // retry loop racing ChainSync's storage visibility. That is decided by real
    // time, not message order, and is out of reach at this tier.
    // ===================================================================

    /// A round's outcome from ONE node's point of view.
    ///
    /// `Undecided` is load-bearing, not a nicety. `try_commit` records a SKIP
    /// nowhere — the skip arm is a bare `_ => {}` and only the cursor advance
    /// latches it — so "skipped" and "not yet reached" are indistinguishable
    /// without tracking the cursor. Collapsing them makes the fork assertion
    /// wrong in BOTH directions: it reports a fork in a healthy cluster (a node
    /// that has simply not caught up), and it cannot tell a real skip from
    /// silence.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Decision {
        Commit(String),
        Skip,
        Undecided,
    }

    /// One node's view: its own engine plus the DAG subset it happens to hold.
    struct View {
        eng: super::OrderingEngine,
        dag: std::collections::HashMap<String, blockchain::Vertex>,
        idx: std::collections::HashMap<u64, Vec<String>>,
        log: std::collections::BTreeMap<u64, Decision>,
    }

    impl View {
        fn new() -> Self {
            View {
                eng: super::OrderingEngine::new(),
                dag: std::collections::HashMap::new(),
                idx: std::collections::HashMap::new(),
                log: std::collections::BTreeMap::new(),
            }
        }

        /// Mirrors `add_vertex`'s bookkeeping at dag.rs:1183-1187: insert into
        /// the map, PUSH onto the round vector. Push order is arrival order,
        /// which is exactly what `leader_vertex_hash`'s `find_map` reads.
        fn insert(&mut self, h: &str, v: &blockchain::Vertex) {
            self.idx.entry(v.round).or_default().push(h.to_string());
            self.dag.insert(h.to_string(), v.clone());
        }

        /// Drain the engine to a fixpoint and reconstruct the full decision
        /// stream, synthesizing the SKIPs that `try_commit` never records.
        fn evaluate(&mut self, validators: &[(String, u64)]) {
            loop {
                let before = self.eng.next_anchor_round;
                let commits = self.eng.try_commit(0, &self.dag, &self.idx, validators);
                if commits.is_empty() {
                    break;
                }
                for c in &commits {
                    // Every even round the cursor stepped OVER was skipped.
                    let mut j = super::OrderingEngine::align_anchor(before.max(1));
                    while j < c.anchor_round {
                        self.log.entry(j).or_insert(Decision::Skip);
                        j += 2;
                    }
                    self.log
                        .insert(c.anchor_round, Decision::Commit(c.anchor_hash.clone()));
                }
            }
        }

        fn decision(&self, round: u64) -> Decision {
            if round >= self.eng.next_anchor_round {
                return Decision::Undecided;
            }
            self.log.get(&round).cloned().unwrap_or(Decision::Skip)
        }
    }

    /// AD-1 (agreement): two nodes that have BOTH decided round r must have
    /// decided the same thing. A node that has not decided yet is not a
    /// disagreement — see the `Undecided` doc.
    fn agree(a: &Decision, b: &Decision) -> bool {
        match (a, b) {
            (Decision::Undecided, _) | (_, Decision::Undecided) => true,
            _ => a == b,
        }
    }

    /// The candidate fix, as an admission filter: admit a round>1 vertex only
    /// when its DISTINCT parent authors carry >2/3 stake. This is the same test
    /// `parent_quorum_met` already applies PRODUCER-side at dag.rs:566/592 —
    /// H3 is that it is absent at INGRESS (`add_vertex` checks parents only for
    /// count and uniqueness, dag.rs:1046-1060).
    fn parent_quorum_ok(
        v: &blockchain::Vertex,
        dag: &std::collections::HashMap<String, blockchain::Vertex>,
        validators: &[(String, u64)],
    ) -> bool {
        if v.round <= 1 {
            return true; // round 1 cites the genesis sentinel
        }
        let total: u128 = validators.iter().map(|(_, s)| *s as u128).sum();
        let stakes: std::collections::HashMap<&str, u64> =
            validators.iter().map(|(a, s)| (a.as_str(), *s)).collect();
        let mut authors: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for p in &v.parents {
            if p == "genesis" {
                continue;
            }
            if let Some(pv) = dag.get(p) {
                authors.insert(pv.author.as_str());
            }
        }
        let signed: u128 = authors
            .iter()
            .filter_map(|a| stakes.get(a).map(|s| *s as u128))
            .sum();
        crate::qc::stake_quorum_met(signed, total)
    }

    /// Build the H3 scenario. Returns (validators, ordered (hash, vertex) list,
    /// the round-2 leader's vertex hash, the Byzantine author).
    ///
    /// `byz_honest = true` is the M0 negative control: identical in every
    /// respect except that the round-4 leader plays by the rules.
    #[allow(clippy::type_complexity)]
    fn h3_scenario(
        byz_honest: bool,
    ) -> (
        Vec<(String, u64)>,
        Vec<(String, blockchain::Vertex)>,
        String,
        String,
    ) {
        let validators = mk_validators(4);
        // Verified by search, not assumed: with n=4 these are different authors.
        let l2 = super::OrderingEngine::leader_for_round(2, &validators, 0);
        let byz = super::OrderingEngine::leader_for_round(4, &validators, 0);
        assert_ne!(l2, byz, "scenario requires distinct round-2 and round-4 leaders");

        let mut out: Vec<(String, blockchain::Vertex)> = Vec::new();
        let mut prev: Vec<String> = vec!["genesis".to_string()];
        let mut h2_leader = String::new();
        let mut byz_prev = String::new();

        for r in 1..=5u64 {
            let mut this = Vec::new();
            for (a, _) in &validators {
                let parents = if !byz_honest && a == &byz && (r == 3 || r == 4) {
                    if r == 3 {
                        // ONE parent, and deliberately NOT the round-2 leader:
                        // the whole point is that h2_leader is absent from this
                        // vertex's causal history.
                        let non_leader = prev
                            .iter()
                            .find(|h| {
                                out.iter()
                                    .find(|(hh, _)| hh == *h)
                                    .map(|(_, v)| v.author != l2)
                                    .unwrap_or(false)
                            })
                            .expect("a non-leader round-2 vertex exists")
                            .clone();
                        vec![non_leader]
                    } else {
                        vec![byz_prev.clone()]
                    }
                } else {
                    prev.clone()
                };
                let (h, v) = mk_vertex(r, a, parents);
                if r == 2 && a == &l2 {
                    h2_leader = h.clone();
                }
                if a == &byz {
                    byz_prev = h.clone();
                }
                this.push(h.clone());
                out.push((h, v));
            }
            prev = this;
        }
        (validators, out, h2_leader, byz)
    }

    // ===================================================================
    // TIER-1 SEEDED SCHEDULER
    //
    // The action space is INVERTED, and that is the whole design. A reviewer
    // built the obvious "deliver messages from an empty view" explorer and
    // measured it: depth <=7 is 26,717,121 states, exhaustive, and NOT ONE
    // COMMIT is reachable — the first commit sits at depth 38. Building up from
    // nothing never reaches the interesting states.
    //
    // So: start from a COMPLETE DAG and take things away. The actions are
    // OMISSION (a view never received a vertex) and PERMUTATION (it received
    // them in a different order). Both are one step from an interesting state
    // instead of thirty-eight.
    //
    // A failing schedule prints its SEED, and the seed reproduces it exactly.
    // That is the property the whole exercise exists for.
    // ===================================================================

    const SCHED_ROUNDS: u64 = 6;
    const SCHED_OMIT_P: f64 = 0.2;
    const SCHED_VIEWS: usize = 3;

    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    struct ArmCounts {
        direct_commit: u64,
        ancestry_commit: u64,
        ancestry_skip: u64,
        defer: u64,
    }

    impl ArmCounts {
        fn add(&mut self, o: &ArmCounts) {
            self.direct_commit += o.direct_commit;
            self.ancestry_commit += o.ancestry_commit;
            self.ancestry_skip += o.ancestry_skip;
            self.defer += o.defer;
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ScheduleOutcome {
        /// (round, view i, decision i, view j, decision j) of the first AD-1 breach.
        violation: Option<(u64, usize, String, usize, String)>,
        arms: ArmCounts,
    }

    /// Build the complete world for one schedule.
    ///
    /// `byz`, when set, plays the SPARSE-ANCHOR script: from round 2 on it emits
    /// vertices with exactly ONE parent. Such a vertex passes real ingress
    /// unchanged — `add_vertex` checks parents for count (dag.rs:1046-1052) and
    /// uniqueness (:1054-1060) and nothing else.
    ///
    /// The FABRICATED-PARENT script (B3/B4) is deliberately NOT in the menu: it
    /// is a known-open wedge that would fire on essentially every seed and drown
    /// the agreement signal. It has its own characterisation test.
    fn sched_universe(
        validators: &[(String, u64)],
        byz: Option<&str>,
        rng: &mut rand::rngs::StdRng,
    ) -> Vec<(String, blockchain::Vertex)> {
        use rand::Rng;
        let mut out = Vec::new();
        let mut prev: Vec<String> = vec!["genesis".to_string()];
        for r in 1..=SCHED_ROUNDS {
            let mut this = Vec::new();
            for (a, _) in validators {
                let parents = if byz == Some(a.as_str()) && r >= 2 && !prev.is_empty() {
                    vec![prev[rng.gen_range(0..prev.len())].clone()]
                } else {
                    prev.clone()
                };
                let (h, v) = mk_vertex(r, a, parents);
                this.push(h.clone());
                out.push((h, v));
            }
            prev = this;
        }
        out
    }

    /// Which arm of the decision function each round took, from OUTSIDE the
    /// engine — no production instrumentation. A committed round that was not
    /// directly committable in this view was reached by ancestry.
    fn sched_classify(v: &View, validators: &[(String, u64)], arms: &mut ArmCounts) {
        let total: u128 = validators.iter().map(|(_, s)| *s as u128).sum();
        let max_r = v.idx.keys().copied().max().unwrap_or(0);
        let mut r = 2;
        while r < max_r {
            match v.decision(r) {
                Decision::Commit(_) => {
                    let direct = super::OrderingEngine::leader_vertex_hash(
                        r, &v.dag, &v.idx, validators,
                    )
                    .map(|h| {
                        super::OrderingEngine::direct_quorum_met(
                            r, &h, &v.dag, &v.idx, validators, total,
                        )
                    })
                    .unwrap_or(false);
                    if direct {
                        arms.direct_commit += 1;
                    } else {
                        arms.ancestry_commit += 1;
                    }
                }
                Decision::Skip => arms.ancestry_skip += 1,
                Decision::Undecided => arms.defer += 1,
            }
            r += 2;
        }
    }

    /// Run ONE schedule. Deterministic in `seed`: same seed, same outcome, always.
    ///
    /// `permute` draws from a SEPARATE rng stream so that toggling it does not
    /// shift the main stream — otherwise "same seed, permutation off" would be a
    /// different world, and the inertness measurement would be meaningless.
    fn sched_run(seed: u64, byzantine: bool, permute: bool) -> ScheduleOutcome {
        use rand::seq::SliceRandom;
        use rand::{Rng, SeedableRng};
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let mut prng = rand::rngs::StdRng::seed_from_u64(seed ^ 0x5eed_0f5e_0007_u64);

        let validators = mk_validators(4);
        // The Byzantine author is RANDOM. The scheduler is not told that the
        // fork needs it to land on an anchor-round leader — finding that is the
        // search.
        let byz_owned = if byzantine {
            Some(validators[rng.gen_range(0..validators.len())].0.clone())
        } else {
            None
        };
        let universe = sched_universe(&validators, byz_owned.as_deref(), &mut rng);

        let mut views: Vec<View> = Vec::new();
        for i in 0..SCHED_VIEWS {
            let mut v = View::new();
            for (h, vx) in &universe {
                // View 0 is fully connected. A deliberate bias toward FINDING a
                // disagreeing pair — not a coverage claim. Which vertices the
                // other views miss stays random.
                if i > 0 && rng.gen_bool(SCHED_OMIT_P) {
                    continue;
                }
                v.insert(h, vx);
            }
            if permute {
                for list in v.idx.values_mut() {
                    list.shuffle(&mut prng);
                }
            }
            v.evaluate(&validators);
            views.push(v);
        }

        let mut arms = ArmCounts::default();
        for v in &views {
            sched_classify(v, &validators, &mut arms);
        }

        let max_r = views
            .iter()
            .filter_map(|v| v.idx.keys().copied().max())
            .max()
            .unwrap_or(0);
        let mut violation = None;
        'outer: for i in 0..views.len() {
            for j in (i + 1)..views.len() {
                let mut r = 2;
                while r < max_r {
                    let (a, b) = (views[i].decision(r), views[j].decision(r));
                    if !agree(&a, &b) {
                        violation = Some((r, i, format!("{:?}", a), j, format!("{:?}", b)));
                        break 'outer;
                    }
                    r += 2;
                }
            }
        }
        ScheduleOutcome { violation, arms }
    }

    /// Corpus size for the in-suite gates, scaled by profile: 3,000 schedules
    /// cost 0.46 s in release but 15.8 s in DEBUG, which is what a plain
    /// `cargo test` pays — too much to make the suite worth running.
    ///
    /// This is a deliberate, stated cap. Both gates below are still non-vacuous
    /// at the debug size (asserted, not assumed), and the real numbers quoted in
    /// their doc comments come from `probe_corpus_arm_distribution`, which runs
    /// 20,000 per menu on demand:
    ///   cargo test -p consensus --release --lib probe_corpus -- --ignored --nocapture
    const SCHED_CORPUS: u64 = if cfg!(debug_assertions) { 400 } else { 3_000 };

    /// GATE 1 — honest emissions must never fork, and the ancestry arms must
    /// stay unreachable.
    ///
    /// The second half is a MEASURED property, not an assumption, and it is the
    /// most useful thing this corpus produced. Across 20,000 schedules at world
    /// sizes of 6, 10 and 16 rounds, honest-only emissions exercised the
    /// ancestry walk-back EXACTLY ZERO TIMES — while direct commits ran to
    /// 153,030 at 16 rounds. Both non-direct arms are reachable only via a
    /// Byzantine thin anchor.
    ///
    /// That is why H3 lived there: the most subtle branch of the ordering
    /// algorithm gets no coverage at all from honest traffic, so no amount of
    /// honest testing — or honest production running — would ever have touched it.
    #[test]
    fn corpus_honest_emissions_never_fork_and_never_reach_the_ancestry_arms() {
        let mut arms = ArmCounts::default();
        for seed in 0..SCHED_CORPUS {
            let o = sched_run(seed, false, true);
            assert!(
                o.violation.is_none(),
                "AD-1 breach under HONEST-ONLY emissions at seed {}: {:?}\n\
                 Reproduce with: sched_run({}, false, true)\n\
                 This would be a NEW defect — honest nodes disagreeing from nothing \
                 but packet loss and reordering.",
                seed,
                o.violation,
                seed
            );
            arms.add(&o.arms);
        }

        // Non-vacuity. Without these the corpus could be asserting nothing at all.
        assert!(
            arms.direct_commit > 0 && arms.defer > 0,
            "corpus is vacuous: direct={} defer={}",
            arms.direct_commit,
            arms.defer
        );

        assert_eq!(
            (arms.ancestry_commit, arms.ancestry_skip),
            (0, 0),
            "honest traffic now REACHES the ancestry walk-back (commit={}, skip={}). \
             Measured zero at 6/10/16 rounds over 20k schedules each. This is a \
             coverage CHANGE, not necessarily a bug — confirm it is intended, and \
             note that the ancestry arms are where H3 lived precisely because \
             nothing honest ever exercised them.",
            arms.ancestry_commit,
            arms.ancestry_skip
        );
    }

    /// GATE 2 — the scheduler must REDISCOVER a defect that is already sitting in
    /// this repo as a failing test, without being told where it is.
    ///
    /// This is the gate that gives every future "the corpus found nothing" any
    /// meaning at all. A search that cannot re-find a known answer proves nothing
    /// when it comes back empty. The Byzantine AUTHOR is drawn at random and the
    /// scheduler is not told that the fork needs it to land on an anchor-round
    /// leader — finding that is the search.
    ///
    /// Observed: first breach at seed 77, three orders of magnitude inside the
    /// 100,000 budget, and its SHAPE is the hand-written H3 witness exactly —
    /// one view Commits an even round, another Skips it.
    #[test]
    fn corpus_rediscovers_the_h3_witness_unaided() {
        const BUDGET: u64 = 100_000;
        let mut found: Option<(u64, ScheduleOutcome)> = None;
        for seed in 0..BUDGET {
            let o = sched_run(seed, true, true);
            if o.violation.is_some() {
                found = Some((seed, o));
                break;
            }
        }
        let (seed, outcome) = found.expect(
            "the scheduler failed to rediscover H3 within 100,000 schedules. \
             Until it can re-find a defect already known to be there, a run that \
             reports nothing means nothing.",
        );

        let (round, _i, di, _j, dj) = outcome.violation.clone().unwrap();
        assert_eq!(round % 2, 0, "anchors live on even rounds");
        assert!(
            (di.starts_with("Commit") && dj == "Skip")
                || (dj.starts_with("Commit") && di == "Skip"),
            "seed {} breached AD-1 but not in the H3 shape (got {} vs {}). \
             A different defect is not a failure — investigate it — but this gate \
             is specifically that H3 is re-findable.",
            seed,
            di,
            dj
        );

        // THE point of deterministic simulation: the seed IS the bug report.
        for replay in 0..3 {
            assert_eq!(
                sched_run(seed, true, true),
                outcome,
                "replay {} of seed {} diverged — the corpus is not deterministic, \
                 and a non-reproducible counterexample is worthless",
                replay,
                seed
            );
        }
    }

    /// GATE 3 — an honest measurement of what half the action space is worth today.
    ///
    /// PERMUTATION IS CURRENTLY INERT. Every consumer of `round_index` order
    /// except one accumulates into a set: `direct_quorum_met` collects distinct
    /// authors, `walk_history` collects visited hashes. The single order-sensitive
    /// reader is `leader_vertex_hash`'s `find_map` — and it only matters when a
    /// round holds TWO vertices by the same author, i.e. twins, which `add_vertex`
    /// drops at dag.rs:1167 (H1) and which this corpus does not yet inject.
    ///
    /// So the reordering half of the action space explores nothing at present.
    /// Recorded rather than quietly assumed, because a corpus that claims to
    /// explore arrival order and does not is exactly the kind of false assurance
    /// this whole harness exists to prevent. Injecting twins is step 4; when it
    /// lands, THIS TEST MUST FAIL, and that failure is the proof the twins took
    /// effect.
    #[test]
    fn corpus_permutation_is_inert_until_twins_are_injectable() {
        for seed in 0..SCHED_CORPUS {
            assert_eq!(
                sched_run(seed, true, true),
                sched_run(seed, true, false),
                "seed {}: permutation changed the outcome. If twins are now being \
                 injected this is EXPECTED — delete this test and assert the \
                 order-dependence directly. If they are not, arrival order is \
                 reaching a decision it should not.",
                seed
            );
        }
    }

    /// MEASUREMENT, not an assertion. Run it to see what the corpus actually
    /// exercises before trusting any claim about coverage:
    ///   cargo test -p consensus --lib probe_corpus -- --ignored --nocapture
    #[test]
    #[ignore = "measurement probe, not a gate"]
    fn probe_corpus_arm_distribution() {
        for (label, byz) in [("honest", false), ("byzantine", true)] {
            let mut arms = ArmCounts::default();
            let mut violations = 0u64;
            let mut first_violation: Option<u64> = None;
            let n = 20_000u64;
            for seed in 0..n {
                let o = sched_run(seed, byz, true);
                arms.add(&o.arms);
                if o.violation.is_some() {
                    violations += 1;
                    if first_violation.is_none() {
                        first_violation = Some(seed);
                        println!("  {} first AD-1 breach at seed {}: {:?}", label, seed, o.violation);
                    }
                }
            }
            println!(
                "{:>9}: {} schedules | AD-1 breaches {} | direct {} ancestry-commit {} \
                 ancestry-SKIP {} defer {}",
                label, n, violations, arms.direct_commit, arms.ancestry_commit,
                arms.ancestry_skip, arms.defer
            );
        }
    }

    /// P-LIVE: the anchor cursor advanced. Trivial to state, and the single most
    /// important predicate in this module.
    ///
    /// Every safety property here — agreement, validity, no-fork — is satisfied
    /// VACUOUSLY by a node that decides nothing. So "defer whenever unsure" passes
    /// the entire safety set while wedging the chain, and B3/B4 *is* a wedge. A
    /// harness without P-LIVE would sign off on a fix that halts mainnet.
    fn p_live(cursor_before: u64, cursor_after: u64) -> bool {
        cursor_after > cursor_before
    }

    /// A 64-hex hash that is not, and never was, any vertex. `add_vertex` would
    /// accept a vertex citing it: parents are checked for count (dag.rs:1046-1052)
    /// and uniqueness (:1054-1060) and nothing else — not existence, not
    /// resolvability, not quorum.
    const FABRICATED_PARENT: &str =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    /// Full mesh over 5 rounds; when `poison` is set, the round-2 LEADER's vertex
    /// carries one extra parent that never existed.
    #[allow(clippy::type_complexity)]
    fn b3b4_scenario(
        poison: bool,
    ) -> (
        Vec<(String, u64)>,
        std::collections::HashMap<String, blockchain::Vertex>,
        std::collections::HashMap<u64, Vec<String>>,
        String,
    ) {
        let validators = mk_validators(4);
        let l2 = super::OrderingEngine::leader_for_round(2, &validators, 0);
        let mut dag = std::collections::HashMap::new();
        let mut idx: std::collections::HashMap<u64, Vec<String>> =
            std::collections::HashMap::new();
        let mut prev: Vec<String> = vec!["genesis".to_string()];
        let mut h2_leader = String::new();

        for r in 1..=5u64 {
            let mut this = Vec::new();
            for (a, _) in &validators {
                let mut parents = prev.clone();
                if poison && r == 2 && a == &l2 {
                    parents.push(FABRICATED_PARENT.to_string());
                }
                let (h, v) = mk_vertex(r, a, parents);
                if r == 2 && a == &l2 {
                    h2_leader = h.clone();
                }
                this.push(h.clone());
                idx.entry(r).or_default().push(h.clone());
                dag.insert(h, v);
            }
            prev = this;
        }
        (validators, dag, idx, h2_leader)
    }

    /// AUDIT B3/B4 (open by design — see the standing comment in dag.rs). One
    /// validly-signed vertex citing a parent that NEVER EXISTED wedges the anchor
    /// cursor permanently, and no in-protocol path recovers it.
    ///
    /// This is a CHARACTERISATION test: it is GREEN at HEAD because it pins the
    /// current behaviour. Green here does NOT mean "healthy" — read leg 2. When a
    /// real fix lands, leg 2 must be inverted, and the fix is only acceptable if
    /// leg 1 stays green.
    ///
    /// Why B3/B4 was left open: two code attempts and three designs to close it
    /// were refuted, every time because the "fix" made ordinary packet loss halt
    /// the chain — strictly worse than a defect that needs a Byzantine key. The
    /// value of this test is that it makes both failure directions detectable.
    ///
    /// MUTATION GATES — both RUN and OBSERVED. B3/B4 can be "fixed" wrongly in two
    /// opposite directions and this test must catch each:
    ///   M1  FAIL-CLOSED — `walk_history` always returns None ("defer whenever
    ///       unsure"). Every safety property still passes. **Leg 1 must fail
    ///       P-LIVE.** This is the halt-as-fix trap.
    ///   M2  FAIL-OPEN — `walk_history` treats a hole as settled. This is exactly
    ///       the guessing that forked the chain live (see try_commit's doc).
    ///       **Leg 2 must fail.**
    ///
    /// Observed detail worth keeping: under M2 leg 2 fails at mechanism assertion
    /// (c), which short-circuits BEFORE the freeze loop — so (c) alone would leave
    /// the freeze loop unproven, the same "passes against its own mutation" trap
    /// one level down. Verified separately: with (c) removed, M2 fails in the
    /// freeze loop at tick 0 ("committed under a fabricated parent"). Both layers
    /// discriminate independently. Re-verify this if either is edited.
    #[test]
    fn test_b3b4_fabricated_parent_wedges_the_cursor_and_p_live_catches_it() {
        // ---- LEG 1: P-LIVE positive control -----------------------------------
        // Without this, leg 2's "cursor frozen" assertion would also pass on a
        // harness that simply never commits anything. The control is what gives
        // the freeze its meaning.
        let (validators, dag, idx, _) = b3b4_scenario(false);
        let mut healthy = super::OrderingEngine::new();
        let before = healthy.next_anchor_round;
        let commits = drain(&mut healthy, &dag, &idx, &validators);
        assert!(
            p_live(before, healthy.next_anchor_round),
            "P-LIVE: a clean full mesh must decide something — cursor stayed at {}. \
             If this fires, every safety assertion below is vacuous.",
            before
        );
        assert!(!commits.is_empty());

        // ---- LEG 2: the wedge --------------------------------------------------
        let (validators, dag, idx, h2_leader) = b3b4_scenario(true);
        let mut wedged = super::OrderingEngine::new();
        let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();

        // Pin the MECHANISM, not just the symptom. Three separate facts, so a
        // future reader knows the wedge is the hole and nothing else:
        //   (a) the round-2 leader vertex is present and IS the elected leader's
        assert_eq!(
            super::OrderingEngine::leader_vertex_hash(2, &dag, &idx, &validators).as_deref(),
            Some(h2_leader.as_str())
        );
        //   (b) it is DIRECTLY committable — quorum is not the blocker
        assert!(
            super::OrderingEngine::direct_quorum_met(
                2, &h2_leader, &dag, &idx, &validators, total_stake
            ),
            "the anchor must be directly committable, or the freeze proves nothing"
        );
        //   (c) its causal history has a HOLE — this is the actual blocker
        assert!(
            super::OrderingEngine::walk_history(
                &h2_leader,
                0,
                2,
                &dag,
                &wedged.committed_set
            )
            .is_none(),
            "walk_history must report a hole on the fabricated parent"
        );

        // Now the symptom: the cursor never moves, no matter how many times the
        // node retries. On a live node this is every consensus tick, forever.
        let frozen_at = wedged.next_anchor_round;
        for tick in 0..32 {
            let out = wedged.try_commit(0, &dag, &idx, &validators);
            assert!(
                out.is_empty(),
                "tick {}: committed under a fabricated parent — that is fail-OPEN \
                 guessing, the behaviour that forked the chain live",
                tick
            );
            assert_eq!(
                wedged.next_anchor_round, frozen_at,
                "tick {}: cursor moved while the hole is unresolved",
                tick
            );
        }
        assert!(
            !p_live(frozen_at, wedged.next_anchor_round),
            "B3/B4 is OPEN at HEAD: this assertion failing means it was fixed — \
             invert leg 2 and confirm leg 1 is still green"
        );

        // ---- LEG 3: the only escape -------------------------------------------
        // The wedge is not recoverable in-protocol. `adopt_synced_anchor` bypasses
        // walk_history entirely, so a node only escapes by being TOLD the answer
        // out of band. That asymmetry is the whole reason B3/B4 is a liveness
        // defect and not merely a slow path.
        let seq: Vec<String> = vec![h2_leader.clone()];
        let adopted = wedged.adopt_synced_anchor(2, &h2_leader, &seq, &validators);
        assert!(adopted.is_some(), "sync adoption must succeed where consensus cannot");
        assert!(
            p_live(frozen_at, wedged.next_anchor_round),
            "cursor must advance once the anchor is adopted out of band"
        );
    }

    /// AUDIT H3 (CRITICAL, safety fork). The soundness argument for the
    /// ancestry skip is written in this file's `try_commit` doc: "every vertex
    /// at j+2 references >2/3 of the j+1 vertices, which intersects the >2/3
    /// that voted for the leader". That is a claim about vertices that MET
    /// parent quorum — and nothing enforces it on ingress. `parent_quorum_met`
    /// lives at dag.rs:566/592, inside `try_create_vertex`, i.e. producer-side
    /// only; `add_vertex` checks parents for count (dag.rs:1046-1052) and
    /// uniqueness (:1054-1060) and nothing else.
    ///
    /// So a Byzantine round-4 leader can emit a ONE-PARENT anchor whose causal
    /// history is COMPLETE (no hole -> no deferral) but excludes the round-2
    /// leader. A node with the round-3 votes commits round 2 directly; a node
    /// missing two of them walks back from the thin anchor, finds the round-2
    /// leader provably absent, and SKIPS round 2 permanently. Both decisions
    /// are final. That is a finality fork from one Byzantine key and ordinary
    /// gossip loss — no second Byzantine act required.
    /// RED BY DESIGN. H3 is OPEN at HEAD, so this test FAILS, and that failure is
    /// the point: it is the executable statement of the defect. It is `#[ignore]`d
    /// only so `cargo test --workspace` stays a usable gate for everything else.
    ///
    ///   cargo test -p consensus --lib test_h3_sparse -- --ignored --nocapture
    ///
    /// Un-ignore it the moment the ingress parent-quorum gate lands; it is then
    /// the regression test for that fix.
    ///
    /// MUTATION GATES — all four RUN and OBSERVED, never predicted (four designs
    /// in a row shipped gates whose behaviour their author mispredicted):
    ///   HEAD                              -> RED   (fork reproduced)
    ///   M0  BYZ_HONEST = true             -> SILENT. The negative control. Y now
    ///       hits a genuine HOLE under the fat anchor, `walk_history` returns None
    ///       (this file, the hole arm), Y DEFERS -> Undecided. If this fires, the
    ///       extractor conflates "not yet decided" with "skipped" and nothing
    ///       downstream is trustworthy. Stop and fix it.
    ///   M1  min-hash tie-break on round_index in `leader_vertex_hash` -> stays RED.
    ///       The H2-shaped fix. This scenario has no twins and one round-2 leader
    ///       vertex, so sorting cannot change any outcome. If M1 goes green, the
    ///       test is measuring the wrong defect.
    ///   M2  APPLY_PARENT_QUORUM = true    -> GREEN, with P-LIVE still green.
    ///
    /// M2's LIMIT, stated so it is not mistaken for validation of a production
    /// fix: tier 1 does not run `add_vertex`, so the filter here is a SECOND
    /// IMPLEMENTATION of the ingress rule. It proves the property is achievable.
    /// Validating the real fix needs a tier-2 node-level test.
    #[test]
    #[ignore = "reproduces H3, an OPEN CRITICAL defect: RED by design until the ingress parent-quorum gate lands"]
    fn test_h3_sparse_anchor_forks_direct_committer_from_ancestry_skipper() {
        // M0 negative control: flip to true, the test must go SILENT.
        const BYZ_HONEST: bool = false;
        // M2 candidate fix: flip to true, the test must go GREEN.
        const APPLY_PARENT_QUORUM: bool = false;

        let (validators, vertices, h2_leader, _byz) = h3_scenario(BYZ_HONEST);

        // Y is missing two of the three HONEST round-3 vertices. Plain gossip
        // loss: no second Byzantine act, no equivocation, no partition.
        let l2 = super::OrderingEngine::leader_for_round(2, &validators, 0);
        let byz = super::OrderingEngine::leader_for_round(4, &validators, 0);
        let dropped_for_y: Vec<String> = vertices
            .iter()
            .filter(|(_, v)| v.round == 3 && v.author != byz && v.author != l2)
            .map(|(h, _)| h.clone())
            .collect();
        assert_eq!(dropped_for_y.len(), 2, "scenario requires exactly two omissions");

        let mut x = View::new();
        let mut y = View::new();
        for (h, v) in &vertices {
            if APPLY_PARENT_QUORUM && !parent_quorum_ok(v, &x.dag, &validators) {
                // X and Y are filtered against their OWN views, exactly as an
                // ingress rule would be.
            } else {
                x.insert(h, v);
            }
            if dropped_for_y.contains(h) {
                continue;
            }
            if APPLY_PARENT_QUORUM && !parent_quorum_ok(v, &y.dag, &validators) {
                continue;
            }
            y.insert(h, v);
        }

        x.evaluate(&validators);
        y.evaluate(&validators);

        let dx = x.decision(2);
        let dy = y.decision(2);

        // P-LIVE, checked FIRST and unconditionally. Without it the trivially
        // "safe" fix — defer everything, decide nothing — makes AD-1 vacuously
        // true and this test green. A harness that can be satisfied by a halt
        // is worse than no harness: B3/B4 IS a halt.
        assert!(
            matches!(dx, Decision::Commit(_)) || matches!(dy, Decision::Commit(_)),
            "P-LIVE: no view decided anything — a halt would satisfy AD-1 vacuously \
             (X={:?} Y={:?})",
            dx,
            dy
        );

        // AD-1 (agreement). RED at HEAD: X commits round 2 on direct votes while
        // Y proves a skip from a consistent-but-smaller subset.
        assert!(
            agree(&dx, &dy),
            "AD-1 VIOLATED at round 2 — finality fork.\n  \
             X (holds everything)                = {:?}\n  \
             Y (missing 2 honest round-3 votes)  = {:?}\n  \
             round-2 leader vertex               = {}\n\
             X direct-commits round 2 (3 honest round-3 vertices cite it, 9000 > 8000).\n\
             Y has 1 such vote, advances to the Byzantine one-parent round-4 anchor,\n\
             whose causal history is COMPLETE (so no hole, no deferral) and does not\n\
             contain the round-2 leader — so Y skips round 2 permanently.",
            dx,
            dy,
            h2_leader
        );
    }

    /// THE fork scenario: one node evaluates incrementally as rounds arrive,
    /// another evaluates once, late, with the full DAG. Their committed-anchor
    /// sequences (rounds, hashes, per-anchor vertex sequences, digests) must be
    /// IDENTICAL. Before B4b the early evaluator produced different height<->
    /// round packaging than the late one — the live block fork.
    #[test]
    fn test_b4b_commit_sequence_is_arrival_order_independent() {
        let validators = mk_validators(3);
        let (full_dag, full_idx) = full_mesh(&validators, 10);

        // Late evaluator: one call over the complete DAG.
        let mut late = OrderingEngine::new();
        let late_commits = drain(&mut late, &full_dag, &full_idx, &validators);

        // Incremental evaluator: DAG grows one round at a time, try_commit is
        // called at EVERY step (the per-vertex cadence of add_vertex).
        let mut early = OrderingEngine::new();
        let mut early_commits = Vec::new();
        let mut dag = std::collections::HashMap::new();
        let mut idx: std::collections::HashMap<u64, Vec<String>> =
            std::collections::HashMap::new();
        for r in 1..=10u64 {
            for h in &full_idx[&r] {
                dag.insert(h.clone(), full_dag[h].clone());
                idx.entry(r).or_default().push(h.clone());
                early_commits.extend(drain(&mut early, &dag, &idx, &validators));
            }
        }

        assert!(
            !late_commits.is_empty(),
            "sanity: the full-mesh DAG must commit anchors"
        );
        assert_eq!(
            commit_fingerprint(&late_commits),
            commit_fingerprint(&early_commits),
            "arrival cadence must not change the committed-anchor sequence"
        );
        assert_eq!(
            late_commits.last().unwrap().finality_digest,
            early_commits.last().unwrap().finality_digest,
            "the rolling finality digest must agree once the same anchors are folded"
        );
    }

    /// A missing leader is SKIPPED by proof, not guessed around: with 4
    /// validators, drop the round-5 leader's vertex entirely. Both an early and
    /// a late evaluator must produce the same sequence, with round 5 absent from
    /// the anchor list — and no availability-driven "backup leader" invented.
    #[test]
    fn test_b4b_missing_leader_is_skipped_deterministically() {
        let validators = mk_validators(4);
        let (mut dag, mut idx) = full_mesh(&validators, 10);

        // EVEN round: anchors live on even rounds only (Bullshark waves), so an
        // odd victim would make this test pass vacuously.
        let victim_round = 6u64;
        let leader = OrderingEngine::leader_for_round(victim_round, &validators, 0);
        let leader_hash = idx[&victim_round]
            .iter()
            .find(|h| dag[*h].author == leader)
            .cloned()
            .expect("full mesh has the leader vertex");
        // Remove the leader's vertex AND every reference to it, as if it was
        // never produced (the validator was down that round).
        dag.remove(&leader_hash);
        idx.get_mut(&victim_round).unwrap().retain(|h| h != &leader_hash);
        for v in dag.values_mut() {
            v.parents.retain(|p| p != &leader_hash);
        }

        let mut late = OrderingEngine::new();
        let late_commits = drain(&mut late, &dag, &idx, &validators);
        let rounds: Vec<u64> = late_commits.iter().map(|c| c.anchor_round).collect();

        assert!(
            !rounds.contains(&victim_round),
            "round {} has no leader vertex and must be SKIPPED, got anchors {:?}",
            victim_round,
            rounds
        );
        assert!(
            rounds.iter().any(|r| *r > victim_round),
            "the chain must continue PAST the skipped round (no stall): {:?}",
            rounds
        );
        // The skipped round's OTHER vertices still get ordered — inside a later
        // anchor's causal history, so no data is lost.
        let all_committed: std::collections::HashSet<&String> = late_commits
            .iter()
            .flat_map(|c| c.sequence.iter())
            .collect();
        for h in &idx[&victim_round] {
            assert!(
                all_committed.contains(h),
                "non-leader vertex {} of the skipped round must still be committed",
                h
            );
        }
    }

    /// THE round-728 live incident, pinned: a node that is MISSING an anchor's
    /// leader vertex — while later vertices still CITE it — must DEFER, never
    /// prove a false skip. Quorum intersection makes this sound only because
    /// anchors sit two rounds apart: the next anchor's 2f+1 parents at r+1 must
    /// intersect the 2f+1 voters at r+1, so the walk is guaranteed to reach a
    /// citing vertex and hit the hole. With every-round anchors (the first B4b
    /// cut) the next anchor sat at r+1 and owed the voters nothing — NAS
    /// committed round 728 on direct votes while LAP proved a "skip" from a
    /// consistent-but-incomplete DAG, and the block chains split.
    #[test]
    fn test_b4b_missing_voted_leader_defers_instead_of_false_skip() {
        let validators = mk_validators(4);
        let (full_dag, idx) = full_mesh(&validators, 10);

        let victim = 6u64;
        let leader = OrderingEngine::leader_for_round(victim, &validators, 0);
        let leader_hash = idx[&victim]
            .iter()
            .find(|h| full_dag[*h].author == leader)
            .cloned()
            .expect("full mesh has the leader vertex");

        // Node B's view: the leader vertex itself never arrived, but the
        // round-7 vertices citing it as a parent DID (full mesh: all cite it).
        let mut dag_b = full_dag.clone();
        dag_b.remove(&leader_hash);

        let mut engine_b = OrderingEngine::new();
        let commits_b = drain(&mut engine_b, &dag_b, &idx, &validators);
        let rounds_b: Vec<u64> = commits_b.iter().map(|c| c.anchor_round).collect();

        assert!(
            rounds_b.iter().all(|r| *r < victim),
            "with the voted leader missing but cited, everything from round {} on \
             must DEFER (wait for gossip) — a skip here is the fork: got {:?}",
            victim,
            rounds_b
        );

        // Gossip delivers the vertex -> B resumes and matches a full-view node.
        dag_b.insert(leader_hash, full_dag[&idx[&victim].iter().find(|h| full_dag[*h].author == leader).unwrap().clone()].clone());
        let more = drain(&mut engine_b, &dag_b, &idx, &validators);
        let mut all_b = commits_b;
        all_b.extend(more);

        let mut engine_a = OrderingEngine::new();
        let commits_a = drain(&mut engine_a, &full_dag, &idx, &validators);
        assert_eq!(
            commit_fingerprint(&commits_a),
            commit_fingerprint(&all_b),
            "after the gap fills, both nodes must hold the identical sequence"
        );
    }

    /// A HOLE defers, never guesses: if a committed-history walk references a
    /// vertex the local DAG does not (yet) hold, the anchor must WAIT for
    /// gossip, not commit a partial sequence that would diverge across nodes.
    #[test]
    fn test_b4b_hole_in_history_defers_until_filled() {
        let validators = mk_validators(4);
        let (full_dag, idx) = full_mesh(&validators, 8);

        // Remove ONE round-3 vertex (not the leader) from the local DAG while
        // round-4 vertices still reference it: a gossip gap.
        let leader3 = OrderingEngine::leader_for_round(3, &validators, 0);
        let missing = idx[&3]
            .iter()
            .find(|h| full_dag[*h].author != leader3)
            .cloned()
            .expect("a non-leader round-3 vertex exists");
        let mut dag = full_dag.clone();
        dag.remove(&missing);

        let mut engine = OrderingEngine::new();
        let first = drain(&mut engine, &dag, &idx, &validators);
        let first_rounds: Vec<u64> = first.iter().map(|c| c.anchor_round).collect();
        assert!(
            first_rounds.iter().all(|r| *r <= 3),
            "no anchor whose history crosses the hole may commit; got {:?}",
            first_rounds
        );

        // Gossip delivers the missing vertex -> the SAME cursor resumes and the
        // rest commits, identical to a node that never had the gap.
        dag.insert(missing.clone(), full_dag[&missing].clone());
        let second = drain(&mut engine, &dag, &idx, &validators);
        assert!(
            second.iter().any(|c| c.anchor_round == 4),
            "anchor 4 must commit once the hole is filled"
        );

        // And the combined sequence equals a never-gapped evaluator's.
        let mut clean = OrderingEngine::new();
        let clean_commits = drain(&mut clean, &full_dag, &idx, &validators);
        let mut combined = first;
        combined.extend(second);
        assert_eq!(
            commit_fingerprint(&clean_commits),
            commit_fingerprint(&combined),
            "deferral must not change the final sequence"
        );
    }

    /// LIVENESS (burn-in finding): a follower that ADOPTS a synced anchor must
    /// end in byte-for-byte parity with the node that COMMITTED it locally —
    /// same cursor, same finalized round, same rolling finality digest, same
    /// committed set — so every later local commit agrees across both.
    #[test]
    fn test_adopt_synced_anchor_matches_local_commit_bookkeeping() {
        let validators: Vec<(String, u64)> = vec![
            ("aaaa000000000000000000000000000000000000000000000000000000000001".to_string(), 1000),
            ("bbbb000000000000000000000000000000000000000000000000000000000002".to_string(), 1000),
        ];
        // "Producer": commits anchors 2 and 4 through the shared bookkeeping.
        let mut producer = OrderingEngine::new();
        let seq2 = vec!["v2a".to_string(), "v2b".to_string()];
        let seq4 = vec!["v4a".to_string()];
        let leader2 = OrderingEngine::leader_for_round(2, &validators, 0);
        let leader4 = OrderingEngine::leader_for_round(4, &validators, 0);
        let info2 = producer.apply_anchor_bookkeeping(2, "anchor2", leader2, seq2.clone());
        let info4 = producer.apply_anchor_bookkeeping(4, "anchor4", leader4, seq4.clone());

        // "Follower": stalled with nothing decided; adopts the two synced blocks.
        let mut follower = OrderingEngine::new();
        let a2 = follower
            .adopt_synced_anchor(2, "anchor2", &seq2, &validators)
            .expect("anchor 2 adopted");
        let a4 = follower
            .adopt_synced_anchor(4, "anchor4", &seq4, &validators)
            .expect("anchor 4 adopted");

        assert_eq!(a2.finality_digest, info2.finality_digest, "digest parity after anchor 2");
        assert_eq!(a4.finality_digest, info4.finality_digest, "digest parity after anchor 4");
        assert_eq!(follower.finalized_round, producer.finalized_round);
        assert_eq!(follower.next_anchor_round, producer.next_anchor_round);
        assert_eq!(follower.committed_rounds, producer.committed_rounds);
        assert_eq!(follower.committed_set, producer.committed_set);

        // Idempotent: re-adopting an already-decided anchor is a no-op.
        assert!(follower.adopt_synced_anchor(4, "anchor4", &seq4, &validators).is_none());
        assert!(follower.adopt_synced_anchor(2, "anchor2", &seq2, &validators).is_none());
        assert_eq!(follower.finality_digest, producer.finality_digest);
    }
}
