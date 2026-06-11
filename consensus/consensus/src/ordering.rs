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
    /// VDF engine for random beacon (unpredictable leader election)
    vdf_engine: Option<VDFEngine>,
    /// Last VDF output for randomness
    last_vdf_output: Vec<u8>,
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
            vdf_engine: vdf,
            last_vdf_output: vec![0u8; 32],
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

        Self {
            committed_rounds,
            finalized_round,
            committed_sequence,
            vdf_engine: vdf,
            last_vdf_output: vec![0u8; 32],
            storage: Some(storage),
        }
    }

    /// Update random beacon using VDF (called after each commit)
    pub fn update_random_beacon(&mut self, seed: &[u8]) {
        if let Some(ref vdf) = self.vdf_engine {
            if let Ok((output, _proof)) = vdf.compute(seed) {
                self.last_vdf_output = output;
            }
        }
    }

    /// Get random bytes from beacon for leader selection
    pub fn get_random_beacon(&self) -> &[u8] {
        &self.last_vdf_output
    }

    fn finality_digest(sequence: &[String]) -> String {
        let mut hasher = Sha256::new();
        for hash in sequence {
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
            let digest = Self::finality_digest(&self.committed_sequence);
            let _ = storage.put("consensus:finality_digest", &digest);
        }

        // 6. Update VDF random beacon with committed anchor hash
        // This ensures unpredictable randomness for future leader selection
        self.update_random_beacon(anchor_vertex_hash.as_bytes());

        Some(CommitInfo {
            sequence,
            leader: successful_leader,
            anchor_round,
            anchor_hash: anchor_vertex_hash.clone(),
            finality_digest: Self::finality_digest(&self.committed_sequence),
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

        // H5 FIX: Mix VDF beacon randomness into leader selection
        // Convert VDF output bytes to a u64 seed for index calculation
        let vdf_seed: u64 = if self.last_vdf_output.len() >= 8 {
            let bytes: [u8; 8] = [
                self.last_vdf_output[0],
                self.last_vdf_output[1],
                self.last_vdf_output[2],
                self.last_vdf_output[3],
                self.last_vdf_output[4],
                self.last_vdf_output[5],
                self.last_vdf_output[6],
                self.last_vdf_output[7],
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
}
