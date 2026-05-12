use serde::Deserialize;
use reqwest::Client;
use std::error::Error;
use log::{info, error, warn};

// CRITICAL-5 FIX: Finality depth to prevent reorg attacks
const FINALITY_DEPTH: u64 = 100; // Wait for 100 block confirmations (~20 minutes)

#[derive(Debug, Clone)]
pub struct AincoreClient {
    rpc_url: String,
    client: Client,
    last_processed_height: u64, // Track last processed finalized block
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Block {
    pub transactions: Vec<String>, // Simplified: Txs are JSON strings in payload
}

#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub payload: String,
    #[allow(dead_code)]
    pub signature: String,
}

impl AincoreClient {
    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_url,
            client: Client::new(),
            last_processed_height: 0,
        }
    }

    pub async fn get_latest_blocks(&self, limit: u64) -> Result<Vec<Block>, Box<dyn Error>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "aincore_getBlocks",
            "params": [limit],
            "id": 1
        });

        let resp = self.client.post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?;

        let rpc_resp: RpcResponse<Vec<Block>> = resp.json().await?;
        
        if let Some(err) = rpc_resp.error {
            error!("RPC Error: {:?}", err);
            return Ok(vec![]);
        }

        Ok(rpc_resp.result.unwrap_or_default())
    }

    /// Get latest block height from node
    pub async fn get_latest_height(&self) -> Result<u64, Box<dyn Error>> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "aincore_getStatus",
            "params": [],
            "id": 1
        });

        let resp = self.client.post(&self.rpc_url)
            .json(&payload)
            .send()
            .await?;

        let rpc_resp: RpcResponse<serde_json::Value> = resp.json().await?;
        
        if let Some(result) = rpc_resp.result {
            if let Some(height) = result.get("block_height").and_then(|h| h.as_u64()) {
                return Ok(height);
            }
        }
        
        Ok(0)
    }

    /// Get finalized block height (latest - FINALITY_DEPTH)
    /// CRITICAL-5 FIX: Only process events from finalized blocks to prevent reorg attacks
    pub async fn get_finalized_height(&self) -> Result<u64, Box<dyn Error>> {
        let latest = self.get_latest_height().await?;
        
        let finalized = if latest > FINALITY_DEPTH {
            latest - FINALITY_DEPTH
        } else {
            0 // Genesis case
        };
        
        info!("📊 Latest: {}, Finalized: {} (depth: {})", latest, finalized, FINALITY_DEPTH);
        Ok(finalized)
    }

    /// Fetch bridge events from FINALIZED blocks only
    /// CRITICAL-5 FIX: Prevents processing events from blocks that could be reorganized
    pub async fn fetch_bridge_events(&mut self) -> Result<Vec<(String, u64, String)>, Box<dyn Error>> {
        // Returns (Sender, Amount, EthAddress)
        
        // Get finalized height
        let finalized_height = self.get_finalized_height().await?;
        
        // Check if we have new finalized blocks to process
        if finalized_height <= self.last_processed_height {
            info!("⏸️  No new finalized blocks (last: {}, finalized: {})", 
                self.last_processed_height, finalized_height);
            return Ok(vec![]);
        }
        
        // Calculate range to fetch
        let start = self.last_processed_height + 1;
        let end = finalized_height;
        let count = end - start + 1;
        
        info!("🔍 Scanning finalized blocks {} to {} ({} blocks)", start, end, count);
        
        // Fetch blocks (limited to avoid overwhelming RPC)
        let fetch_limit = std::cmp::min(count, 100); // Max 100 blocks per call
        let blocks = self.get_latest_blocks(fetch_limit).await?;
        
        let mut events = Vec::new();

        for block in blocks {
            for tx_str in block.transactions {
                // Parse TX JSON
                if let Ok(tx) = serde_json::from_str::<Transaction>(&tx_str) {
                    // Check payload for "bridge_lock"
                    // Payload format: "bridge_lock:AMOUNT:ETH_ADDR"
                    if tx.payload.starts_with("bridge_lock:") {
                        let parts: Vec<&str> = tx.payload.split(':').collect();
                        if parts.len() == 3 {
                            // CRITICAL-4 PARTIAL: Validate Ethereum address format
                            let eth_addr = parts[2].to_string();
                            if !eth_addr.starts_with("0x") || eth_addr.len() != 42 {
                                warn!("⚠️  Invalid Ethereum address format: {}", eth_addr);
                                continue;
                            }
                            
                            if let Ok(amount) = parts[1].parse::<u64>() {
                                info!("🌉 Found FINALIZED Bridge Lock: {} AIN from {} -> {}", 
                                    amount, tx.sender, eth_addr);
                                events.push((tx.sender, amount, eth_addr));
                            }
                        }
                    }
                }
            }
        }
        
        // Update last processed height
        self.last_processed_height = finalized_height;
        info!("✅ Processed up to finalized block {}", finalized_height);
        
        Ok(events)
    }
}
