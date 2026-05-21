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
    pub committed_rounds: HashSet<u64>,
    pub committed_sequence: Vec<String>, // List of Vertex Hashes in order
    /// VDF engine for random beacon (unpredictable leader election)
    vdf_engine: Option<VDFEngine>,
    /// Last VDF output for randomness
    last_vdf_output: Vec<u8>,
    /// Storage reference for persisting committed state
    storage: Option<Arc<StateDB>>,
}

impl OrderingEngine {
    pub fn new() -> Self {
        // Initialize VDF with moderate difficulty (adjustable for faster/slower)
        let vdf = VDFEngine::new(50).ok();

        Self {
            committed_rounds: HashSet::new(),
            committed_sequence: Vec::new(),
            vdf_engine: vdf,
            last_vdf_output: vec![0u8; 32],
            storage: None,
        }
    }

    /// Create with storage for persistence (production mode)
    pub fn new_with_storage(storage: Arc<StateDB>) -> Self {
        let vdf = VDFEngine::new(50).ok();

        // Load committed_rounds from DB
        let mut committed_rounds = HashSet::new();
        if let Ok(Some(json)) = storage.get("consensus:committed_rounds") {
            if let Ok(rounds) = serde_json::from_str::<Vec<u64>>(&json) {
                println!("🔄 Restored {} committed rounds from DB", rounds.len());
                committed_rounds = rounds.into_iter().collect();
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

    fn bft_commit_threshold(validator_count: usize) -> usize {
        if validator_count == 0 {
            return 0;
        }
        if validator_count == 1 {
            return 1;
        }
        (validator_count * 2 / 3) + 1
    }

    /// Mencoba melakukan commit pada ronde tertentu
    pub fn try_commit(
        &mut self,
        current_round: u64,
        dag: &HashMap<String, Vertex>,
        round_index: &HashMap<u64, Vec<String>>,
        validators: &[String],
    ) -> Option<(Vec<String>, String)> {
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
        if self.committed_rounds.contains(&anchor_round) {
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

        let mut vote_count = 0;
        for voter_hash in votes {
            if let Some(voter) = dag.get(voter_hash) {
                if voter.parents.contains(anchor_vertex_hash) {
                    vote_count += 1;
                }
            }
        }

        // Commit only with a strict >2/3 quorum. A two-validator network therefore
        // needs both votes; one validator must not be able to finalize alone.
        let threshold = Self::bft_commit_threshold(validators.len());

        if vote_count < threshold {
            println!(
                "⚠️ Anchor Round {} (Leader {}) not committed. Votes: {}/{}",
                anchor_round, successful_leader, vote_count, threshold
            );
            return None;
        }

        println!(
            "⚓ Committing Anchor Round {} (Leader {}) with {} votes",
            anchor_round, successful_leader, vote_count
        );

        // 5. Commit Causal History
        let mut sequence = self.find_causal_history(anchor_vertex_hash, dag);

        // Filter yang sudah committed
        sequence.retain(|h| !self.committed_sequence.contains(h));

        // Update state
        self.committed_rounds.insert(anchor_round);
        self.committed_sequence.extend(sequence.clone());

        // PERSIST committed state to DB (BUG #1 FIX)
        if let Some(ref storage) = self.storage {
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
            let finalized_round = self.committed_rounds.iter().copied().max().unwrap_or(0);
            let _ = storage.put("consensus:finalized_round", &finalized_round.to_string());
            let _ = storage.put("consensus:last_anchor_round", &anchor_round.to_string());
            let _ = storage.put("consensus:last_anchor_hash", anchor_vertex_hash);
            let digest = Self::finality_digest(&self.committed_sequence);
            let _ = storage.put("consensus:finality_digest", &digest);
        }

        // 6. Update VDF random beacon with committed anchor hash
        // This ensures unpredictable randomness for future leader selection
        self.update_random_beacon(anchor_vertex_hash.as_bytes());

        Some((sequence, successful_leader))
    }

    /// H5 + M6 FIX: Leader selection now uses VDF random beacon for unpredictability.
    /// Previously this was pure deterministic round-robin (idx = round % n),
    /// making leader election fully predictable by any observer.
    /// Now the VDF beacon output is mixed into the selection to add randomness.
    /// Also removed the hardcoded "node_9009" dev fallback (M6 fix).
    fn get_leader_with_fallback(&self, round: u64, validators: &[String], attempt: u32) -> String {
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

        // Leader index = (round + vdf_randomness + attempt) mod n
        // The VDF seed changes after every committed anchor, making future leaders unpredictable
        let idx = ((round.wrapping_add(vdf_seed).wrapping_add(attempt as u64))
            % validators.len() as u64) as usize;
        validators[idx].clone()
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
    use super::OrderingEngine;

    #[test]
    fn bft_threshold_requires_strict_supermajority() {
        assert_eq!(OrderingEngine::bft_commit_threshold(0), 0);
        assert_eq!(OrderingEngine::bft_commit_threshold(1), 1);
        assert_eq!(OrderingEngine::bft_commit_threshold(2), 2);
        assert_eq!(OrderingEngine::bft_commit_threshold(3), 3);
        assert_eq!(OrderingEngine::bft_commit_threshold(4), 3);
        assert_eq!(OrderingEngine::bft_commit_threshold(7), 5);
    }
}
