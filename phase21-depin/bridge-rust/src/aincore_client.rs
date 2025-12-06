use serde::Deserialize;
use reqwest::Client;
use std::error::Error;
use log::{info, error};

#[derive(Debug, Clone)]
pub struct AincoreClient {
    rpc_url: String,
    client: Client,
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
    pub signature: String,
}

impl AincoreClient {
    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_url,
            client: Client::new(),
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

    pub async fn fetch_bridge_events(&self) -> Result<Vec<(String, u64, String)>, Box<dyn Error>> {
        // Returns (Sender, Amount, EthAddress)
        let blocks = self.get_latest_blocks(5).await?;
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
                            if let Ok(amount) = parts[1].parse::<u64>() {
                                let eth_addr = parts[2].to_string();
                                info!("🌉 Found Bridge Lock: {} AIN from {} -> {}", amount, tx.sender, eth_addr);
                                events.push((tx.sender, amount, eth_addr));
                            }
                        }
                    }
                }
            }
        }
        Ok(events)
    }
}
