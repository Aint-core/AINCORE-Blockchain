use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use serde::{Deserialize, Serialize};
use storage::StateDB;
use mempool::Mempool;
use executor::{Executor};
// Use crypto crate for everything
use crypto::{hash_hex, Signer, Verifier, SigningKey, VerifyingKey, Signature}; 
use rand::rngs::OsRng;
use rand::RngCore;

pub mod dag;
pub mod ordering;

#[cfg(test)]
mod tests;
pub use dag::DagConsensus;

// === Consensus Structs ===

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BlockHeader {
    pub parent_hash: String,
    pub height: u64,
    pub timestamp: u64,
    pub proposer: String,
    pub hash: String, // Self-hash
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<String>, // simplified as list of tx strings/hashes
}

impl Block {
    pub fn new(height: u64, parent_hash: String, transactions: Vec<String>, proposer: String) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();

        // Simple hash calculation (SHA256)
        // CRITICAL FIX: Use deterministic inputs for hash (including timestamp, but timestamp MUST be fixed by proposer)
        let input = format!("{}{}{}", parent_hash, height, proposer);
        // Use crypto::hash_hex instead of sha256::digest
        let hash = hash_hex(input.as_bytes());

        Block {
            header: BlockHeader {
                parent_hash,
                height,
                timestamp,
                proposer,
                hash,
            },
            transactions,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vote {
    pub block_hash: String,
    pub voter_id: String, // Public Key (Hex)
    pub round: u64,
    pub signature: String, // Hex Signature
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Proposal {
    pub block: Block,
    pub proposer_id: String, // Public Key (Hex)
    pub round: u64,
    pub signature: String, // Hex Signature
}

// === Consensus Engine ===

pub struct SimpleConsensus {
    node_id: String, // Friendly ID
    keypair: SigningKey, // The Node's Private Key
    peers: Arc<Mutex<HashMap<String, u16>>>, // PeerID -> Port
    mempool: Arc<Mutex<Mempool>>,
    db: Arc<StateDB>, // Active DB access for PoS
    executor: Arc<Executor>,
    
    // State
    current_round: u64,
    votes: Arc<Mutex<HashMap<String, Vec<Vote>>>>, // BlockHash -> Votes
    pending_proposals: Arc<Mutex<HashMap<String, Proposal>>>,
    committed_blocks: Arc<Mutex<Vec<Block>>>,
}

impl SimpleConsensus {
    pub fn new(
        node_id: String,
        peers: Arc<Mutex<HashMap<String, u16>>>,
        mempool: Arc<Mutex<Mempool>>,
        db: Arc<StateDB>,
    ) -> Self {
        // Generate a fresh keypair for this session using RngCore
        let mut csprng = OsRng;
        let mut key_bytes = [0u8; 32];
        csprng.fill_bytes(&mut key_bytes);
        let keypair = SigningKey::from_bytes(&key_bytes);
        
        let public_key_bytes = VerifyingKey::from(&keypair).to_bytes();
        let public_key_hex = hex::encode(public_key_bytes);

        println!("🔑 [Node {}] Generated Session Keypair. Public Key: {}...", node_id, &public_key_hex[0..8]);

        Self {
            node_id,
            keypair,
            peers,
            mempool,
            db: db.clone(),
            executor: Arc::new(Executor::new(db)),
            current_round: 0,
            votes: Arc::new(Mutex::new(HashMap::new())),
            pending_proposals: Arc::new(Mutex::new(HashMap::new())),
            committed_blocks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn start(&mut self) {
        println!("🚀 Consensus Engine Started for Node {}", self.node_id);
    }

    pub fn propose_block(&mut self) {
        println!("🔨 [Node {}] Attempting to propose block...", self.node_id);

        // 1. Get transactions (dropping lock immediately)
        let transactions = {
            let mut mempool_lock = match self.mempool.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!("❌ Mempool lock poisoned: {}", e);
                    return;
                }
            };
            let txs = mempool_lock.get_pending_transactions(50);
            txs // return txs, lock drops
        };

        // ALLOW EMPTY BLOCKS (Heartbeat / Reward Mining)
        if transactions.is_empty() {
            // Optional: Add a check to only produce empty blocks every N seconds
            // For now, we allow it to ensure mining rewards flow.
            // println!("zzz [Node {}] No transactions, but proposing Empty Block (Heartbeat).", self.node_id);
        }

        // 2. Determine Height/Parent (dropping lock immediately)
        let (height, prev_hash) = {
            let blocks = match self.committed_blocks.lock() {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("❌ Committed blocks lock poisoned: {}", e);
                    return;
                }
            };
            let h = blocks.len() as u64;
            let ph = blocks.last()
                .map(|b| b.header.hash.clone())
                .unwrap_or_else(|| "0".to_string());
            (h, ph)
        };

        let pk_bytes = VerifyingKey::from(&self.keypair).to_bytes();
        let my_public_key = hex::encode(pk_bytes);

        let block = Block::new(height, prev_hash, transactions.clone(), my_public_key.clone());
        let block_hash = block.header.hash.clone();

        let message = format!("{}{}", block_hash, self.current_round);
        let signature = self.keypair.sign(message.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        let proposal = Proposal {
            block: block.clone(),
            proposer_id: my_public_key.clone(),
            round: self.current_round,
            signature: signature_hex,
        };

        // Cache own proposal
        {
            let mut proposals_lock = match self.pending_proposals.lock() {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("❌ Proposals lock poisoned: {}", e);
                    return;
                }
            };
            proposals_lock.insert(block_hash.clone(), proposal.clone());
        }

        println!("✅ [Node {}] Proposed Block #{} ({}) [Txs: {}]", self.node_id, height, block_hash, transactions.len());

        if let Ok(msg) = serde_json::to_string(&proposal) {
            self.broadcast_message(&format!("PROPOSAL:{}", msg));
        }
        
        self.vote_on_proposal(&block_hash);
    }
    
    pub fn vote_on_proposal(&mut self, block_hash: &str) {
         let pk_bytes = VerifyingKey::from(&self.keypair).to_bytes();
         let my_public_key = hex::encode(pk_bytes);
         
         let message = format!("{}{}{}", block_hash, self.current_round, "VOTE");
         let signature = self.keypair.sign(message.as_bytes());
         
         let vote = Vote {
             block_hash: block_hash.to_string(),
             voter_id: my_public_key,
             round: self.current_round,
             signature: hex::encode(signature.to_bytes()), 
         };
         
         self.handle_vote(vote.clone());
         
         if let Ok(msg) = serde_json::to_string(&vote) {
             self.broadcast_message(&format!("VOTE:{}", msg));
         }
    }

    pub fn handle_message(&mut self, message: String) {
        if message.starts_with("PROPOSAL:") {
            let content = &message[9..];
            if let Ok(proposal) = serde_json::from_str::<Proposal>(content) {
                self.handle_proposal(proposal);
            } else {
                 eprintln!("❌ Failed to parse PROPOSAL");
            }
        } else if message.starts_with("VOTE:") {
            let content = &message[5..];
             if let Ok(vote) = serde_json::from_str::<Vote>(content) {
                self.handle_vote(vote);
            } else {
                 eprintln!("❌ Failed to parse VOTE");
            }
        }
    }

    fn handle_proposal(&mut self, proposal: Proposal) {
        println!("📨 [Node {}] Received PROPOSAL for {} from {}", self.node_id, proposal.block.header.hash, proposal.proposer_id);
        
        if !self.verify_signature(&proposal.proposer_id, &proposal.signature, &format!("{}{}", proposal.block.header.hash, proposal.round)) {
             println!("⛔ [Node {}] INVALID SIGNATURE on Proposal from {}", self.node_id, proposal.proposer_id);
             return;
        }

        // === TIMESTAMP VERIFICATION (Future Block Protection) ===
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or(std::time::Duration::from_secs(0)).as_secs();
        if proposal.block.header.timestamp > now + 5 {
             println!("⚠️ [Node {}] REJECTED Future Block (Ts: {}, Now: {})", self.node_id, proposal.block.header.timestamp, now);
             return;
        }

        // === REAL MODE: VALIDATOR CHECK ===
        let validators = self.db.get_active_validators();
        if !validators.iter().any(|(pk, _)| pk == &proposal.proposer_id) {
             println!("⚠️ [Node {}] Ignored PROPOSAL from non-validator: {}", self.node_id, proposal.proposer_id);
             return;
        }

        {
            let mut proposals_lock = self.pending_proposals.lock().unwrap();
            proposals_lock.insert(proposal.block.header.hash.clone(), proposal.clone());
        }

        self.vote_on_proposal(&proposal.block.header.hash);
    }

    fn handle_vote(&mut self, vote: Vote) {
        if !self.verify_signature(&vote.voter_id, &vote.signature, &format!("{}{}{}", vote.block_hash, vote.round, "VOTE")) {
             println!("⛔ [Node {}] INVALID SIGNATURE on Vote from {}", self.node_id, vote.voter_id);
             return; 
        }

        // === REAL MODE: VALIDATOR SET CHECK ===
        // Fetch active validators from StateDB
        let validators = self.db.get_active_validators();
        
        // 1. Check if voter is a validator
        let _voter_weight = match validators.iter().find(|(pk, _)| pk == &vote.voter_id) {
            Some((_, weight)) => *weight,
            None => {
                println!("⚠️ [Node {}] Ignored vote from non-validator: {}", self.node_id, vote.voter_id);
                return;
            }
        };

        let block_hash = vote.block_hash.clone();
        let mut should_commit = false;

        {
            let mut votes_lock = match self.votes.lock() {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("❌ Votes lock poisoned: {}", e);
                    return;
                }
            };
            let current_votes = votes_lock.entry(block_hash.clone()).or_insert(Vec::new());
            
            if !current_votes.iter().any(|v| v.voter_id == vote.voter_id) {
                 current_votes.push(vote);
                 
                 // 2. Calculate Stake-Based Quorum
                 let total_stake: u64 = validators.iter().map(|(_, w)| w).sum();
                 let current_stake_weight: u64 = current_votes.iter()
                    .filter_map(|v| validators.iter().find(|(pk, _)| pk == &v.voter_id).map(|(_, w)| *w))
                    .sum();

                 // BFT Quorum: 2/3 + 1
                 let quorum_threshold = (total_stake * 2) / 3 + 1;

                 if current_stake_weight >= quorum_threshold {
                      println!("🎉 [Node {}] BFT Quorum Reached ({}/{} Stake) for Block {}", self.node_id, current_stake_weight, total_stake, block_hash);
                      should_commit = true;
                 }
            }
        } // votes_lock dropped here

        if should_commit {
             // Check if already committed to avoid double commit
             let is_committed = {
                 let blocks = match self.committed_blocks.lock() {
                     Ok(g) => g,
                     Err(_) => return, // Fail silently if poisoned
                 };
                 blocks.iter().any(|b| b.header.hash == block_hash)
             }; // lock drops

             if !is_committed {
                  self.commit_block(block_hash);
             }
        }
    }

    fn commit_block(&mut self, block_hash: String) {
         let proposal_opt = {
            let proposals = match self.pending_proposals.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            proposals.get(&block_hash).cloned()
        }; // lock drops

        if let Some(proposal) = proposal_opt {
             println!("💾 [Node {}] Committing Block {} (Height {})", self.node_id, block_hash, proposal.block.header.height);
             
             if let Ok(mut blocks) = self.committed_blocks.lock() {
                 blocks.push(proposal.block.clone());
             }
             
             println!("⚙️ [Node {}] Executing Transactions...", self.node_id);
             // PASS PROPOSER TO EXECUTOR FOR REWARDS
             self.executor.execute_block_parallel(proposal.block.transactions.clone(), &proposal.block.header.proposer);
        } else {
             eprintln!("❌ [Node {}] Cannot commit block {}: Proposal data missing!", self.node_id, block_hash);
        }
    }

    fn broadcast_message(&self, message: &str) {
        let peers = match self.peers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("❌ Lock poisoned on peers: {}", poisoned);
                return;
            }
        };
        for (_peer_id, port) in peers.iter() {
             let msg_clone = message.to_string();
             let port_clone = *port;
             thread::spawn(move || {
                 if let Ok(mut stream) = std::net::TcpStream::connect(format!("127.0.0.1:{}", port_clone)) {
                     use std::io::Write;
                     let _ = stream.write_all(msg_clone.as_bytes());
                 }
             });
        }
    }
    
    fn verify_signature(&self, public_key_hex: &str, signature_hex: &str, message: &str) -> bool {
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            },
            _ => return false,
        };
        
        let sig_bytes = match hex::decode(signature_hex) {
            Ok(b) if b.len() == 64 => {
                 let mut arr = [0u8; 64];
                 arr.copy_from_slice(&b);
                 arr
            },
            _ => return false,
        };
        
        let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        
        let signature = Signature::from_bytes(&sig_bytes);
        
        verifying_key.verify(message.as_bytes(), &signature).is_ok()
    }
}
