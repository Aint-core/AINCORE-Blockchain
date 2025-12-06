use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use blockchain::Vertex;
use blockchain::accumulator::Accumulator;
use storage::StateDB;
use mempool::Mempool;
use executor::Executor;
use network::PeerList;
use crate::ordering::OrderingEngine;
use da_sequencer::DASequencer;

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
}

impl DagConsensus {
    pub fn new(
        node_id: String,
        peers: PeerList,
        mempool: Arc<Mutex<Mempool>>,
        executor: Arc<Executor>,
        storage: Arc<StateDB>,
        da_sequencer: Option<Arc<Mutex<DASequencer>>>, // Added arg
    ) -> Self {
        let mut dag_map = HashMap::new();
        let mut round_idx_map: HashMap<u64, Vec<String>> = HashMap::new();
        let mut max_round = 0;

        // Recovery: Load vertices from DB
        let vertices_json = storage.scan_vertices();
        for v_json in vertices_json {
            if let Ok(vertex) = serde_json::from_str::<Vertex>(&v_json) {
                if vertex.round > max_round {
                    max_round = vertex.round;
                }
                round_idx_map.entry(vertex.round).or_insert_with(Vec::new).push(vertex.hash.clone());
                dag_map.insert(vertex.hash.clone(), vertex);
            }
        }
        
        println!("♻️  Restored DAG state: {} vertices, Max Round {}", dag_map.len(), max_round);

        let latest_block_height = match storage.get("latest_height") {
             Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
             _ => 0,
        };
        let latest_block_hash = match storage.get("latest_block_hash") {
            Ok(Some(h)) => h,
            _ => "genesis".to_string(),
        };

        Self {
            node_id,
            peers,
            current_round: std::cmp::max(1, max_round + 1),
            dag: Arc::new(Mutex::new(dag_map)),
            round_index: Arc::new(Mutex::new(round_idx_map)),
            mempool,
            executor,
            storage,
            ordering_engine: Arc::new(Mutex::new(OrderingEngine::new())),
            latest_block_height,
            latest_block_hash,
            accumulator: Accumulator::new(),
            da_sequencer,
        }
    }

    pub fn try_create_vertex(&mut self) {
        // 1. Check if we have enough parents from previous round
        let prev_round = self.current_round - 1;
        let mut parents = {
            let round_idx = self.round_index.lock().unwrap_or_else(|e| e.into_inner());
            round_idx.get(&prev_round).cloned().unwrap_or_default()
        };

        // Ensure Round 1 links to genesis
        if prev_round == 0 && parents.is_empty() {
            parents.push("genesis".to_string());
        }

        // DYNAMIC CHECK: Get active validator set FIRST (needed for quorum calculation)
        let validators = self.get_validator_set();
        let is_active_validator = validators.contains(&self.node_id);
        
        // BFT QUORUM CALCULATION: 2f+1 where f = (n-1)/3
        // This ensures we can tolerate f Byzantine nodes
        let n = validators.len().max(1); // Prevent division by zero
        let f = (n - 1) / 3; // Byzantine tolerance
        let bft_quorum = (2 * f) + 1;
        
        // For genesis round (round 0), we need 0 parents (bootstrap)
        // For subsequent rounds, we need BFT quorum of parents
        let mut quorum = if prev_round == 0 { 
            0 
        } else { 
            bft_quorum.max(1) // At minimum 1 parent required
        };
        
        println!("🔒 [Consensus] Round {}: Validators={}, BFT_Quorum={}, Parents={}", 
                 self.current_round, n, quorum, parents.len());

        // SPLIT-BRAIN PREVENTION & OBSERVER MODE:
        let genesis_id = "8f7d00f56518177823e32849fa9e5f83"; 
        let is_genesis_id = self.node_id == genesis_id;

        let has_peers = {
             if let Ok(p) = self.peers.lock() {
                 !p.is_empty()
             } else {
                 false
             }
        };

        // RULE 1: If I am NOT a validator, I am an Observer. Observers CANNOT mine.
        if !is_active_validator {
             if self.current_round % 10 == 0 || self.current_round < 5 {
                 println!("⚠️  [Consensus] Observer Mode: I am not in Validator Set. Waiting to sync/register... (Round {})", self.current_round);
             }
             quorum = 9999; // Block mining
        } 
        // RULE 2: If I AM a validator, but I have NO peers (and not Singleton/Genesis), I must stop to avoid Split-Brain.
        else if !has_peers && !is_genesis_id {
             // Check if we are really the only validator in the set
             let is_singleton = validators.len() == 1; 
             
             if !is_singleton {
                  println!("⚠️  [Consensus] Validator Isolated! Stopping mining to prevent fork. Waiting for peers...");
                  quorum = 9999; // Block mining
             }
        }

        // Standard logic for Genesis or Connected Nodes
        if parents.len() >= quorum {
            // 2. Create Payload (Fetch from Mempool)
            let mut payload = Vec::new();
            if let Ok(mut mp) = self.mempool.lock() {
                payload = mp.get_pending_transactions(50); 
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
            };
            
            vertex.hash = vertex.calculate_hash(); 
            
            // 4. Add & Broadcast
            self.add_vertex(vertex.clone());
            self.broadcast_vertex(&vertex);
            
            // Advance round
            self.current_round += 1;
            println!("⚡ Created Vertex {} (Round {})", vertex.hash, vertex.round);
        }
    }

    pub fn add_vertex(&mut self, vertex: Vertex) {
        // 1. Scope for DAG and RoundIndex modification
        {
            let mut dag = self.dag.lock().unwrap_or_else(|e| e.into_inner());
            println!("DEBUG: add_vertex: Hash='{}', Round={}", vertex.hash, vertex.round);
            if dag.contains_key(&vertex.hash) {
                println!("DEBUG: add_vertex: Duplicate hash! Skipping.");
                return;
            }
            
            // Persist to DB
            if let Ok(v_json) = serde_json::to_string(&vertex) {
                if let Err(e) = self.storage.put(&format!("vertex:{}", vertex.hash), &v_json) {
                    println!("❌ Failed to persist DAG vertex: {}", e);
                }
            }

            dag.insert(vertex.hash.clone(), vertex.clone());
            
            let mut round_idx = self.round_index.lock().unwrap_or_else(|e| e.into_inner());
            round_idx.entry(vertex.round).or_default().push(vertex.hash.clone());
            println!("📥 Added Vertex to DAG: {} (Round {})", vertex.hash, vertex.round);
        } // Locks dropped here!

        // --- ORDERING LOGIC (Bullshark-lite) ---
        // Now we can take new locks without holding the previous ones.
        
        // We need read access to DAG and RoundIndex for ordering check, BUT we don't need write.
        // And we definitly don't want to hold them during execution.
        
        let committed_hashes = {
            let mut engine = self.ordering_engine.lock().unwrap_or_else(|e| e.into_inner());
            let dag = self.dag.lock().unwrap_or_else(|e| e.into_inner()); 
            let round_idx = self.round_index.lock().unwrap_or_else(|e| e.into_inner());
            let validators = self.get_validator_set(); // This acquires peers lock, safe now.
            
            engine.try_commit(vertex.round, &dag, &round_idx, &validators)
        }; // All locks dropped here!

        if let Some(hashes) = committed_hashes {
             println!("⛓️  Consensus Reached! Executing {} vertices in order...", hashes.len());
             
             let executor = &self.executor;
             let mut block_txs = Vec::new();
             let mut reward_recipient = self.node_id.clone(); // Default fallback

             // Re-acquire DAG read lock just to fetch payloads
             // We can optimize this by cloning necessary data in the previous block, 
             // but identifying which vertices are committed before engine runs is hard.
             // So we just re-acquire efficiently.
             let dag = self.dag.lock().unwrap_or_else(|e| e.into_inner());

             // Identify Reward Recipient (Author of the last vertex in the batch)
             // This ensures all nodes agree on who gets the reward.
             if let Some(last_hash) = hashes.last() {
                 if let Some(v) = dag.get(last_hash) {
                     reward_recipient = v.author.clone();
                 }
             }

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
                 println!("🚀 Executing Parallel Batch of {} transactions", block_txs.len());
                 
                 // Use Executor parallel logic directly? 
                 // The existing logic was: analyze deps -> schedule -> execute.
                 // We can use executor.execute_block_parallel(block_txs).
                 executor.execute_block_parallel(block_txs.clone(), &reward_recipient);
                 
                 // Create Block (Post-Execution)
                 use blockchain::Block;
                 self.latest_block_height += 1;
                 let new_block = Block::new(
                     self.latest_block_height,
                     self.latest_block_hash.clone(),
                     block_txs.clone(), // This duplicates data, effectively block contains processed txs
                     reward_recipient.clone()
                 );
                 self.latest_block_hash = new_block.header.hash.clone();
                 
                 // Update Accumulator and DB
                 if let Ok(bytes) = hex::decode(&new_block.header.hash) {
                    self.accumulator.append(bytes);
                 }

                 if let Ok(block_json) = serde_json::to_string(&new_block) {
                     let _ = self.storage.put(&format!("block_{}", self.latest_block_height), &block_json);
                     let _ = self.storage.put("latest_height", &self.latest_block_height.to_string());
                     let _ = self.storage.put("latest_block_hash", &self.latest_block_hash);
                     println!("📦 Created Block #{} (Hash: {:.8})", self.latest_block_height, self.latest_block_hash);
                     
                     // === DA SEQUENCER INTEGRATION ===
                     if let Some(da_seq) = &self.da_sequencer {
                         if let Ok(mut seq) = da_seq.lock() {
                             println!("🧩 [Consensus] Triggering DA Batch creation...");
                             seq.create_batch(self.latest_block_hash.clone(), block_txs.len());
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
             if hashes.len() > 0 {
                  // Simplified trigger: just prune every 10 blocks
                  if self.latest_block_height % 10 == 0 && self.current_round > 50 {
                       self.prune_dag(self.current_round - 50);
                  }
             }
        }
    }

    fn broadcast_vertex(&self, vertex: &Vertex) {
        use network::send_message;
        let serialized = match serde_json::to_string(vertex) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ Failed to serialize vertex: {}", e);
                return;
            }
        };
        let msg = format!("DAG_VERTEX:{}", serialized);
        
        if let Ok(peers) = self.peers.lock() {
            for (_, port) in peers.iter() {
                let addr = format!("127.0.0.1:{}", port);
                let _ = send_message(&addr, &msg);
            }
        }
    }
    
    pub fn handle_message(&mut self, msg: &str) {
        if let Some(content) = msg.strip_prefix("DAG_VERTEX:") {
            if let Ok(vertex) = serde_json::from_str::<Vertex>(content) {
                self.add_vertex(vertex);
            }
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
            println!("🧹 Garbage Collection: Pruned {} vertices older than round {} from Disk & Memory", removed_count, min_round);
        }
    }

    pub fn get_validator_set(&self) -> Vec<String> {
        // Key for ValidatorSet at 0x1
        // Address: 0000000000000000000000000000000000000000000000000000000000000001
        // StructTag: 0x1::staking::ValidatorSet
        let key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::staking::ValidatorSet";
        
        if let Ok(Some(bytes_hex)) = self.storage.get(key) {
            if let Ok(bytes) = hex::decode(bytes_hex) {
                if let Ok(val_set) = bcs::from_bytes::<ValidatorSet>(&bytes) {
                    // Convert addresses to strings (hex without 0x)
                    return val_set.validators.iter()
                        .map(|v| v.validator_addr.to_string()) 
                        .collect();
                }
            }
        }
        
        // Fallback to peers list if staking not initialized or empty
        let mut validators = Vec::new();
        if let Ok(peers) = self.peers.lock() {
            validators = peers.keys().cloned().collect();
        }
        validators.push(self.node_id.clone());
        validators.sort();
        validators.dedup();
        validators
    }
}

#[derive(serde::Deserialize)]
struct Coin {
    #[allow(dead_code)]
    value: u64,
}

#[derive(serde::Deserialize)]
struct ValidatorConfig {
    #[allow(dead_code)]
    validator_addr: move_core_types::account_address::AccountAddress,
    #[allow(dead_code)]
    stake: Coin,
    #[allow(dead_code)]
    public_key: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct ValidatorSet {
    validators: Vec<ValidatorConfig>,
}
