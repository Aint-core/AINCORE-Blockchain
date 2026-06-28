use crate::custody::{self, Custody};
use anyhow::Result;
use reqwest::Client;

/// A single finalized deposit to a custody output.
///
/// Audit #33: one BTC tx may pay the custody script in more than one output
/// (e.g. two OP_RETURN-tagged custody outputs), so a deposit is identified by
/// `(txid, vout)` — NOT by txid alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub txid: String,
    /// Output index within the tx that pays the custody script.
    pub vout: u64,
    pub amount_sats: u64,
    pub aincore_address: String,
}

impl Deposit {
    /// Per-output dedup key: `"{txid}:{vout}"`. Mirrors the EVM bridge's
    /// `(block_height, tx_index)` uniqueness (see `bridge-rust/src/nonce_store.rs`).
    pub fn dedup_key(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }
}

/// BTC client for monitoring deposits to the custody script.
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

    /// Scan the custody address history and return every finalized output that
    /// actually pays the custody script.
    ///
    /// Audit #33 changes:
    ///   - returns one `Deposit` per custody OUTPUT (carries `vout`), so a tx
    ///     with two custody outputs yields two distinct deposits;
    ///   - each output's raw `scriptPubKey` is verified to pay the custody
    ///     script via `custody.output_pays_custody()` — not a trust of the
    ///     indexer's `addr` label;
    ///   - finality uses the pure `custody::is_finalized()` helper.
    pub async fn get_deposits(
        &self,
        min_confirmations: u64,
        custody: &Custody,
    ) -> Result<Vec<Deposit>> {
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
                let tx_height = match tx["block_height"].as_u64() {
                    Some(h) => h,
                    None => continue, // unconfirmed (mempool) — skip
                };

                if !custody::is_finalized(tx_height, current_height, min_confirmations) {
                    continue;
                }

                // Extract the AIN destination from the tx OP_RETURN tag once.
                let aincore_address = match self.extract_op_return(tx) {
                    Some(addr) => addr,
                    None => {
                        println!("⚠️ Deposit found but no AIN address in OP_RETURN: {}", hash);
                        continue;
                    }
                };

                // PER-OUTPUT scan: every output that pays the custody script is
                // its own deposit, keyed by (txid, vout).
                if let Some(outs) = tx["out"].as_array() {
                    for out in outs {
                        let vout = match out["n"].as_u64() {
                            Some(n) => n,
                            None => continue,
                        };
                        let script_hex = match out["script"].as_str() {
                            Some(s) => s,
                            None => continue,
                        };

                        // CUSTODY verification: the output's raw scriptPubKey
                        // must pay the custody script. We do NOT trust the
                        // indexer's `addr` string here.
                        if !custody.output_pays_custody(script_hex) {
                            continue;
                        }

                        let amount = out["value"].as_u64().unwrap_or(0);
                        if amount == 0 {
                            continue;
                        }

                        deposits.push(Deposit {
                            txid: hash.clone(),
                            vout,
                            amount_sats: amount,
                            aincore_address: aincore_address.clone(),
                        });
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
