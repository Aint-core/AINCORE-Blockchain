use reqwest::Client;
use serde_json::json;
use crate::signer::FederationSigner;

use std::sync::atomic::{AtomicU64, Ordering};

pub struct Dispatcher {
    client: Client,
    aincore_url: String,
    last_sequence: AtomicU64,
}

impl Dispatcher {
    pub fn new(url: &str) -> Self {
        Self {
            client: Client::new(),
            aincore_url: url.to_string(),
            last_sequence: AtomicU64::new(0),
        }
    }

    pub async fn get_sequence_number(&self, addr: &str) -> u64 {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "aincore_getObject",
            "params": [addr],
            "id": 1
        });

        if let Ok(resp) = self.client.post(&self.aincore_url).json(&body).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                // println!("🔍 [DEBUG] getObject Response: {}", json); // Redacted
                if let Some(result) = json.get("result") {
                     if !result.is_null() {
                         if let Some(data_bytes) = result.get("data").and_then(|d| d.as_array()) {
                             let bytes: Vec<u8> = data_bytes.iter().map(|v| v.as_u64().unwrap() as u8).collect();
                             #[derive(serde::Deserialize)]
                             struct PartialAccountData {
                                 sequence_number: u64,
                             }
                             if let Ok(acc) = serde_json::from_slice::<PartialAccountData>(&bytes) {
                                 return acc.sequence_number;
                             }
                         }
                     }
                }
            }
        }
        0 
    }

    pub async fn submit_mint(&self, signer: &FederationSigner, amount: u64, recipient: &str) {
        let fed_addr = signer.get_public_key_hex()[0..32].to_string(); 
        let payload = format!("mint_btc:{}:{}", amount, recipient);
        
        let node_seq = self.get_sequence_number(&fed_addr).await;
        let last_known = self.last_sequence.load(Ordering::SeqCst);
        
        // Ensure monotonically increasing
        let mut seq = node_seq;
        if seq <= last_known {
            seq = last_known + 1;
        } else {
             // If node_seq jumped ahead (e.g. manual txs), allow it?
             // But usually it means we are catching up.
             // If node_seq > last_known, it is fine.
        }
        
        // Update local tracker
        self.last_sequence.store(seq, Ordering::SeqCst);
        
        println!("🔢 Federation Seq: {} (Node: {}, Local: {})", seq, node_seq, last_known);
        
        let signature = signer.sign_transaction(&payload, seq);
        
        // Construct Transaction JSON
        let tx = json!({
            "chain_id": "AINCORE-MAINNET-1",
            "sender": fed_addr,
            "input_objects": [],
            "payload": payload,
            "gas_limit": 5000,
            "gas_price": 1,
            "sequence_number": seq,
            "public_key": signer.get_public_key_hex(),
            "signature": signature
        });

        println!("🚀 Dispatching Transaction: {} Sats -> {}", amount, recipient);

        // Send
        let body = json!({
            "jsonrpc": "2.0",
            "method": "aincore_sendTransaction",
            "params": [tx], 
            "id": 2
        });
        
        match self.client.post(&self.aincore_url).json(&body).send().await {
            Ok(resp) => {
                let txt = resp.text().await.unwrap_or_default();
                println!("✅ Response: {}", txt);
            },
            Err(e) => println!("❌ Failed to send transaction: {}", e),
        }
    }
}
