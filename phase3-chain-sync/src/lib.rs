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
        let peers_map = match self.peers.lock() {
            Ok(p) => p,
            Err(e) => e.into_inner(), // Poison recovery
        };
        if peers_map.is_empty() {
            println!("⚠️ [ChainSync] No peers available for sync.");
            return;
        }

        let from_height = self.get_local_height();
        let request = SyncRequest { 
            from_height,
            sender_id: self.node_id.clone(),
            sender_port: self.my_port,
        };
        let serialized = serde_json::to_string(&request).unwrap_or_default();
        if serialized.is_empty() { return; }
        let msg = format!("SYNC_REQUEST:{}", serialized);

        for (peer_id, peer_port) in peers_map.iter() {
            println!("📡 [ChainSync] Requesting missing blocks from peer {} (port {})", peer_id, peer_port);
            let addr = format!("127.0.0.1:{}", peer_port);
            if let Err(e) = send_message(&addr, &msg) {
                println!("❌ [ChainSync] Failed to send request to {}: {}", addr, e);
            } else {
                println!("✅ [ChainSync] Request sent to {}", addr);
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
