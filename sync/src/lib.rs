use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use blockchain::Block;
use storage::StateDB;
use crypto::hash_hex;
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
        let mut hash_input = String::new();
        hash_input.push_str(&block.header.height.to_string());
        hash_input.push_str(&block.header.prev_hash);
        hash_input.push_str(&block.header.timestamp.to_string());
        hash_input.push_str(&block.header.proposer_id);
        
        for tx in &block.transactions {
            hash_input.push_str(tx);
        }
        
        let computed_hash = hash_hex(hash_input.as_bytes());
        
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
        self.verify_block_hash(block)?;
        Ok(())
    }

    fn get_local_height(&self) -> u64 {
        self.storage.get_chain_height()
    }

    /// Unified Sync: Uses Persistent Encrypted Connection
    pub async fn sync_from_peers(&self) {
        println!("🔄 [ChainSync] Starting Encrypted P2P Sync...");
        
        let peers_map = self.peers.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if peers_map.is_empty() {
            println!("📡 [ChainSync] No peers available.");
            return;
        }

        let my_height = self.get_local_height();
        println!("📊 [ChainSync] Local Height: {}", my_height);

        for (peer_id, peer_port) in peers_map.iter() {
            let peer_ip = self.storage.get_peer_ip(peer_id).unwrap_or_else(|| "127.0.0.1".to_string());
            println!("🌐 [ChainSync] Connecting to {} ({}:{})...", peer_id, peer_ip, peer_port);
            
            // 1. Establish Secure Connection (With MitM Check)
            match secure_connect(&peer_ip, *peer_port, &self.node_id, self.my_port, Some(peer_id)).await {
                Ok((mut stream, shared_key)) => {
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
                                     // 3. Request Blocks Batch
                                     let sync_req = SyncRequest {
                                         from_height: my_height,
                                         sender_id: self.node_id.clone(),
                                         sender_port: self.my_port,
                                     };
                                     let req_json = serde_json::to_string(&sync_req).unwrap();
                                     let msg = format!("SYNC_REQ:{}", req_json);
                                     
                                     if send_encrypted_msg(&mut stream, &shared_key, &msg).await.is_err() { continue; }
                                     
                                     // 4. Receive Blocks Stream (simplified as single batch response for now)
                                     if let Ok(data_resp) = read_encrypted_msg(&mut stream, &shared_key).await {
                                         if let Some(json_data) = data_resp.strip_prefix("SYNC_RESP:") {
                                             if let Ok(sync_resp) = serde_json::from_str::<SyncResponse>(json_data) {
                                                 self.process_blocks(sync_resp.blocks, my_height);
                                             }
                                         }
                                     }
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
    }
    
    fn process_blocks(&self, blocks: Vec<Block>, current_height: u64) {
        let mut last_processed = current_height;
        for block in blocks {
             // 5. SECURITY: Validate block before processing
             // In real impl, we fetch prev block hash from DB to validate chain link
             let prev_hash = if block.header.height > 1 {
                 let prev_key = format!("block_{}", block.header.height - 1);
                 self.storage.get(&prev_key).ok().flatten()
                     .and_then(|json| serde_json::from_str::<Block>(&json).ok())
                     .map(|b| b.header.hash)
                     .unwrap_or_else(|| "unknown".to_string())
             } else {
                 "genesis".to_string()
             };
             
             if let Err(e) = self.validate_block(&block, block.header.height, &prev_hash) {
                 eprintln!("🚨 [SECURITY] Block #{} validation FAILED: {}", block.header.height, e);
                 break; // Stop processing batch on first failure
             }
             
             if let Ok(json) = serde_json::to_string(&block) {
                 if let Err(e) = self.storage.save_block_json(block.header.height, &json) {
                     eprintln!("❌ DB Error: {}", e);
                 } else {
                     last_processed = block.header.height;
                 }
             }
        }
        if last_processed > current_height {
            println!("✅ [ChainSync] Synced up to block {}", last_processed);
        }
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
