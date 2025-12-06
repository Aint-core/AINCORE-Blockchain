use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use blockchain::Block;
use network::send_message;
use storage::StateDB;

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

    /// Mendapatkan tinggi block lokal terakhir
    fn get_local_height(&self) -> u64 {
        match self.storage.get("latest_height") {
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
            _ => 0,
        }
    }

    /// Sinkronisasi awal dengan peers
    pub fn sync_from_peers(&self) {
        println!("🔄 [ChainSync] Starting RPC-based blockchain sync...");
        
        let peers_map = self.peers.lock().unwrap();
        if peers_map.is_empty() {
            println!("📡 [ChainSync] No peers available for sync.");
            return;
        }

        let my_height = self.storage.get_chain_height();
        println!("📊 [ChainSync] My chain height: {}", my_height);

        for (peer_id, peer_port) in peers_map.iter() {
            // Get peer IP from storage
            let peer_ip = self.storage.get_peer_ip(peer_id)
                .unwrap_or_else(|| "127.0.0.1".to_string());
            
            // Calculate RPC port (P2P port - 1000)
            // 9000 -> 8000, 9001 -> 8001
            let rpc_port = if *peer_port >= 9000 { peer_port - 1000 } else { 8000 };
            let rpc_url = format!("http://{}:{}", peer_ip, rpc_port);
            
            println!("🌐 [ChainSync] Syncing from peer {} ({}:{})", peer_id, peer_ip, rpc_port);
            
            // Get peer's chain height via RPC
            match reqwest::blocking::get(&format!("{}/get_chain_height", rpc_url)) {
                Ok(resp) => {
                    if let Ok(text) = resp.text() {
                        if let Ok(peer_height) = text.trim().parse::<u64>() {
                            println!("📊 [ChainSync] Peer height: {}, downloading {} blocks...", 
                                peer_height, peer_height.saturating_sub(my_height));
                            
                            // Download missing blocks
                            let mut synced_count = 0;
                            for h in (my_height + 1)..=peer_height {
                                match reqwest::blocking::get(&format!("{}/get_block?height={}", rpc_url, h)) {
                                    Ok(block_resp) => {
                                        if let Ok(block_json) = block_resp.text() {
                                            // Save block to storage
                                            if let Err(e) = self.storage.save_block_json(h, &block_json) {
                                                eprintln!("❌ Failed to save block #{}: {}", h, e);
                                            } else {
                                                synced_count += 1;
                                                if synced_count % 100 == 0 {
                                                    println!("📦 [ChainSync] Synced {} blocks...", synced_count);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("❌ Failed to fetch block #{}: {}", h, e);
                                        break;
                                    }
                                }
                            }
                            
                            if synced_count > 0 {
                                println!("✅ [ChainSync] Successfully synced {} blocks from {}", synced_count, peer_ip);
                            }
                            return; // Successfully synced from this peer
                        }
                    }
                }
                Err(e) => {
                    eprintln!("❌ [ChainSync] Failed to get height from {}: {}", peer_ip, e);
                }
            }
        }
    }

    /// Menangani permintaan sinkronisasi dari peer lain
    pub fn handle_sync_request(&self, req: SyncRequest) -> SyncResponse {
        let mut blocks_to_send = Vec::new();
        let local_height = self.get_local_height();
        println!("🔍 [ChainSync] Handling request from {} (port {}). Local Height: {}, Remote From: {}", req.sender_id, req.sender_port, local_height, req.from_height);

        if local_height <= req.from_height {
            println!("🟢 [ChainSync] Peer already up-to-date (from_height={})", req.from_height);
            return SyncResponse { blocks: vec![] };
        }

        println!(
            "📤 [ChainSync] Sending blocks {}..{} to requester",
            req.from_height + 1,
            local_height
        );

        for height in (req.from_height + 1)..=local_height {
            let key = format!("block_{}", height);
            if let Ok(Some(block_data)) = self.storage.get(&key) {
                if let Ok(block) = serde_json::from_str::<Block>(&block_data) {
                    blocks_to_send.push(block);
                }
            }
        }

        SyncResponse { blocks: blocks_to_send }
    }

    /// Menangani response sync yang diterima dari peer
    pub fn handle_sync_response(&self, resp: SyncResponse) {
        if resp.blocks.is_empty() {
            println!("✅ [ChainSync] No new blocks received (already up-to-date)");
            return;
        }

        println!("📦 [ChainSync] Received {} new blocks from peer", resp.blocks.len());
        for block in resp.blocks {
            let key = format!("block_{}", block.header.height);
            if let Ok(val) = serde_json::to_string(&block) {
                let _ = self.storage.put(&key, &val);
                let _ = self.storage.put("latest_height", &block.header.height.to_string());
            }
        }

        println!("✅ [ChainSync] Chain updated successfully to latest height");
    }
}
