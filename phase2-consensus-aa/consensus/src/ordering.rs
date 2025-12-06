use blockchain::Vertex;

use std::collections::{HashMap, HashSet};

/// OrderingEngine bertanggung jawab untuk mengubah DAG menjadi urutan linear (Blockchain).
/// Kita menggunakan pendekatan simplified Bullshark:
/// 1. Setiap ronde ganjil punya "Leader".
/// 2. Jika Leader punya cukup dukungan (votes) dari ronde sebelumnya, dia jadi "Anchor".
/// 3. Semua vertex yang terhubung ke Anchor tersebut akan diurutkan (Committed).
pub struct OrderingEngine {
    pub committed_rounds: HashSet<u64>,
    pub committed_sequence: Vec<String>, // List of Vertex Hashes in order
}

impl OrderingEngine {
    pub fn new() -> Self {
        Self {
            committed_rounds: HashSet::new(),
            committed_sequence: Vec::new(),
        }
    }

    /// Mencoba melakukan commit pada ronde tertentu
    pub fn try_commit(
        &mut self,
        current_round: u64,
        dag: &HashMap<String, Vertex>,
        round_index: &HashMap<u64, Vec<String>>,
        validators: &[String],
    ) -> Option<Vec<String>> {
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

        // 2. Tentukan Leader untuk Anchor Round
        let leader_id = self.get_leader(anchor_round, validators);
        
        // 3. Cari Vertex Leader di Anchor Round
        let anchor_vertex_hash = if let Some(hashes) = round_index.get(&anchor_round) {
             hashes.iter().find(|h| {
                if let Some(v) = dag.get(*h) {
                    v.author == leader_id
                } else {
                    false
                }
            })
        } else {
            println!("DEBUG: Anchor round {} not found in round_index", anchor_round);
            return None;
        };

        let anchor_vertex_hash = if let Some(h) = anchor_vertex_hash {
            h
        } else {
            println!("DEBUG: Leader {} not found in anchor round {}", leader_id, anchor_round);
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

        // Threshold: For prototype with 1 node, need 1 vote.
        // Real BFT: 2f + 1.
        let threshold = if validators.is_empty() { 1 } else { (validators.len() * 2 / 3) + 1 };
        
        if vote_count < threshold {
            println!("⚠️ Anchor Round {} (Leader {}) not committed. Votes: {}/{}", anchor_round, leader_id, vote_count, threshold);
            return None;
        }

        println!("⚓ Committing Anchor Round {} (Leader {}) with {} votes", anchor_round, leader_id, vote_count);

        // 5. Commit Causal History
        let mut sequence = self.find_causal_history(anchor_vertex_hash, dag);
        
        // Filter yang sudah committed
        sequence.retain(|h| !self.committed_sequence.contains(h));
        
        // Update state
        self.committed_rounds.insert(anchor_round);
        self.committed_sequence.extend(sequence.clone());
        
        Some(sequence)
    }

    fn get_leader(&self, round: u64, validators: &[String]) -> String {
        if validators.is_empty() {
            return "node_9009".to_string(); // Fallback for dev
        }
        // Simple Round-Robin
        let idx = (round % validators.len() as u64) as usize;
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
                    if !self.committed_sequence.contains(parent) { // Optimization: Stop if already committed
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
                },
                (Some(_), None) => std::cmp::Ordering::Less,    // A exists, B missing → A first
                (None, Some(_)) => std::cmp::Ordering::Greater, // B exists, A missing → B first
                (None, None) => std::cmp::Ordering::Equal,      // Both missing → equal
            }
        });

        history
    }
}
