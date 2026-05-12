use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use blockchain::Block;
use storage::StateDB;
use network::{secure_connect, send_encrypted_msg, read_encrypted_msg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub from_height: u64,
    pub sender_id: String,
    pub sender_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
}

pub struct ChainSync {
    node_id: String,
    my_port: u16,
    peers: Arc<Mutex<HashMap<String, u16>>>,
    storage: Arc<StateDB>,
}

impl ChainSync {
    pub fn new(node_id: String, my_port: u16, peers: Arc<Mutex<HashMap<String, u16>>>, storage: Arc<StateDB>) -> Self {
        Self { node_id, my_port, peers, storage }
    }
    
    fn verify_block_hash(&self, block: &Block) -> Result<bool, String> {
        // Must match blockchain::calculate_header_hash exactly:
        // height + prev_hash + tx_hash + proposer_id + round + timestamp
        let mut data = Vec::new();
        data.extend_from_slice(block.header.height.to_string().as_bytes());
        data.extend_from_slice(block.header.prev_hash.as_bytes());
        data.extend_from_slice(block.header.tx_hash.as_bytes());
        data.extend_from_slice(block.header.proposer_id.as_bytes());
        data.extend_from_slice(block.header.round.to_string().as_bytes());
        data.extend_from_slice(block.header.timestamp.to_string().as_bytes());
        
        let computed_hash = hex::encode(crypto::hash(&data));
        
        if computed_hash == block.header.hash {
            Ok(true)
        } else {
            Err(format!("Hash Mismatch. Expected: {}, Computed: {}", block.header.hash, computed_hash))
        }
    }
    
    fn validate_block(&self, block: &Block, expected_height: u64, prev_hash: &str) -> Result<(), String> {
        if block.header.height != expected_height {
            return Err(format!("Height mismatch: expected {}, got {}", expected_height, block.header.height));
        }
        if expected_height > 1 && block.header.prev_hash != prev_hash {
            return Err(format!("Parent hash mismatch at {}: exp {}, got {}", expected_height, prev_hash, block.header.prev_hash));
        }
        
        // S3-4a: Reject blocks with future timestamps (30s drift tolerance)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();
        if block.header.timestamp > now + 30 {
            return Err(format!("Future timestamp rejected: block={}, now={}", block.header.timestamp, now));
        }
        
        // S3-4b: Reject blocks with excessive transaction count (DoS prevention)
        if block.transactions.len() > 10_000 {
            return Err(format!("Transaction count {} exceeds max 10,000", block.transactions.len()));
        }
        
        self.verify_block_hash(block)?;
        Ok(())
    }

    fn get_local_height(&self) -> u64 {
        self.storage.get_chain_height()
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
            let peer_ip = self.storage.get_peer_ip(peer_id).unwrap_or_else(|| "127.0.0.1".to_string());
            println!("🌐 [ChainSync] Connecting to {} ({}:{})...", peer_id, peer_ip, peer_port);
            
            // 1. Establish Secure Connection (With MitM Check)
            use rand::rngs::OsRng;
            let mut csprng = OsRng;
            let ephemeral_signing_key = crypto::SigningKey::generate(&mut csprng);

            match secure_connect(&peer_ip, *peer_port, "__sync__", self.my_port, Some(peer_id), &ephemeral_signing_key).await {
                Ok((mut stream, shared_key, _peer_node_id)) => {
                    println!("🔐 Secure Channel Established with {}", peer_id);
                    
                    // 2. Request Chain Height
                    let req_msg = "GET_HEIGHT".to_string();
                    if send_encrypted_msg(&mut stream, &shared_key, &req_msg).await.is_err() { continue; }
                    
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
                                                 eprintln!("❌ [ChainSync] Failed to serialize sync request: {}", e);
                                                 break;
                                             }
                                         };
                                         let msg = format!("SYNC_REQ:{}", req_json);
                                         
                                         if send_encrypted_msg(&mut stream, &shared_key, &msg).await.is_err() { break; }
                                         
                                         // 4. Receive Blocks Batch
                                         if let Ok(data_resp) = read_encrypted_msg(&mut stream, &shared_key).await {
                                             if let Some(json_data) = data_resp.strip_prefix("SYNC_RESP:") {
                                                 if let Ok(sync_resp) = serde_json::from_str::<SyncResponse>(json_data) {
                                                     if sync_resp.blocks.is_empty() {
                                                         break; // No more blocks
                                                     }
                                                     let synced = self.process_blocks(sync_resp.blocks, current);
                                                     if synced <= current {
                                                         break; // No progress made
                                                     }
                                                     current = synced;
                                                     final_height = synced;
                                                 } else { break; }
                                             } else { break; }
                                         } else { break; }
                                     }
                                 } else {
                                     println!("✅ [ChainSync] Already caught up with peer {}", peer_id);
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
        
        for (i, block) in blocks.iter().enumerate() {
             // Skip blocks we already have
             if block.header.height <= current_height {
                 continue;
             }
             
             // SECURITY: Validate block before processing
             let prev_hash = if block.header.height > 1 {
                 let prev_key = format!("block_{}", block.header.height - 1);
                 self.storage.get(&prev_key).ok().flatten()
                     .and_then(|json| serde_json::from_str::<Block>(&json).ok())
                     .map(|b| b.header.hash)
                     .unwrap_or_else(|| "unknown".to_string())
             } else {
                 "genesis".to_string()
             };
             
             if let Err(e) = self.validate_block(block, block.header.height, &prev_hash) {
                 eprintln!("🚨 [SECURITY] Block #{} validation FAILED: {}", block.header.height, e);
                 break;
             }
             
             // Execute transactions through the VM/Executor
             executor.execute_block_parallel(block.transactions.clone(), &block.header.proposer_id);
             
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
                 println!("📦 [ChainSync] Progress: {}/{} blocks processed", i + 1, total_blocks);
             }
        }
        if last_processed > current_height {
            println!("✅ [ChainSync] Synced up to block #{} (+{} blocks)", last_processed, last_processed - current_height);
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
        SyncResponse { blocks: blocks_to_send }
    }
    
    // Legacy Handler for compatibility if needed
    pub fn handle_sync_response(&self, _resp: SyncResponse) {
        // No-op in new pull model
    }
}

#[cfg(test)]
mod tests;
