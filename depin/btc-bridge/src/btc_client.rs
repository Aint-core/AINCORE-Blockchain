use anyhow::Result;
use reqwest::Client;

/// BTC client for monitoring deposits to the multisig address.
/// Uses blockchain.info API for lightweight monitoring.
pub struct BtcClient {
    client: Client,
    address: String,
}

impl BtcClient {
    pub fn new(address: String) -> Self {
        Self {
            client: Client::new(),
            address,
        }
    }

    pub async fn get_deposits(&self, min_confirmations: u64) -> Result<Vec<(String, u64, String)>> {
        // Using blockchain.info API as agreed for lightweight monitoring
        let url = format!("https://blockchain.info/rawaddr/{}", self.address);
        let resp = self
            .client
            .get(&url)
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;

        let current_height = self.get_current_block_height().await?;
        let mut deposits = Vec::new();

        if let Some(txs) = resp["txs"].as_array() {
            for tx in txs {
                let hash = tx["hash"].as_str().unwrap_or_default().to_string();
                let tx_height = tx["block_height"].as_u64();

                if let Some(height) = tx_height {
                    let confirmations = current_height.saturating_sub(height) + 1;

                    if confirmations >= min_confirmations {
                        // Check for output to our multisig
                        let mut btc_amount = 0;
                        for out in tx["out"].as_array().unwrap_or(&vec![]) {
                            if let Some(addr) = out["addr"].as_str() {
                                if addr == self.address {
                                    btc_amount = out["value"].as_u64().unwrap_or(0);
                                }
                            }
                        }

                        // Check for OP_RETURN with AIN address
                        let aincore_address = self.extract_op_return(tx);

                        if btc_amount > 0 {
                            if let Some(ain_addr) = aincore_address {
                                deposits.push((hash, btc_amount, ain_addr));
                            } else {
                                println!(
                                    "⚠️ Deposit found but no AIN address in OP_RETURN: {}",
                                    hash
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(deposits)
    }

    async fn get_current_block_height(&self) -> Result<u64> {
        let resp = self
            .client
            .get("https://blockchain.info/q/getblockcount")
            .send()
            .await?
            .text()
            .await?;
        Ok(resp.trim().parse::<u64>().unwrap_or(0))
    }

    fn extract_op_return(&self, tx: &serde_json::Value) -> Option<String> {
        if let Some(outs) = tx["out"].as_array() {
            for out in outs {
                if let Some(script) = out["script"].as_str() {
                    // Simple check for OP_RETURN (6a)
                    // Strict OP_RETURN Parsing
                    if script.starts_with("6a") {
                        // Format: 6a [1-byte length] [data]
                        // e.g. 6a 14 [20 bytes data]
                        if script.len() < 4 {
                            continue;
                        }

                        // Parse length from next 2 chars (1 byte)
                        if let Ok(len_byte) = u8::from_str_radix(&script[2..4], 16) {
                            let expected_char_len = (len_byte as usize) * 2;
                            if script.len() < 4 + expected_char_len {
                                continue;
                            }

                            let payload_hex = &script[4..4 + expected_char_len];
                            if let Ok(data) = hex::decode(payload_hex) {
                                if let Ok(addr_str) = String::from_utf8(data) {
                                    // SECURITY: Validate AINCORE address format (0x + 64 hex chars typically)
                                    // Minimal check: starts with 0x and length > 10
                                    if addr_str.starts_with("0x") && addr_str.len() > 10 {
                                        return Some(addr_str);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
