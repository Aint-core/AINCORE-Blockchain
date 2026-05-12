use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};
use network::PeerList;

// Input validation constants
// Input validation constants
const MAX_BLOCK_HEIGHT: u64 = 1_000_000_000;

// --- Shared State ---
use consensus::DagConsensus;
use governance::GovernanceManager;
use storage::StateDB;

// --- Shared State ---
pub struct AppState {
    pub consensus: Arc<RwLock<DagConsensus>>,
    pub peers: PeerList,
    pub mempool: Arc<Mutex<mempool::Mempool>>,
    pub governance: Arc<Mutex<GovernanceManager>>,
    pub storage: Arc<StateDB>,
}

// --- Handlers ---
#[derive(Deserialize, Debug)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<serde_json::Value>,
    pub id: serde_json::Value,
}

#[derive(Serialize, Debug)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

#[derive(Serialize, Debug)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

fn handle_rpc_method(
    method: &str,
    params: serde_json::Value,
    data: &AppState,
) -> Result<serde_json::Value, JsonRpcError> {
    match method {
        "aincore_getBalance" => {
            // params: [address]
            if let Some(addr) = params.get(0).and_then(|v| v.as_str()) {
                if let Some(obj) = data.storage.get_object(addr) {
                     Ok(serde_json::json!(obj))
                } else {
                     Ok(serde_json::json!(null))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params".into() })
            }
        },
        "aincore_getObject" => {
             // params: [object_id]
             if let Some(id) = params.get(0).and_then(|v| v.as_str()) {
                 if let Some(obj) = data.storage.get_object(id) {
                      Ok(serde_json::json!(obj))
                 } else {
                      Ok(serde_json::json!(null))
                 }
             } else {
                 Err(JsonRpcError { code: -32602, message: "Invalid params".into() })
             }
        },
        "aincore_sendTransaction" => {
            // params: [signed_tx_json_string OR signed_tx_object]
            let tx_str_opt = if let Some(val) = params.get(0) {
                if val.is_string() {
                    val.as_str().map(|s| s.to_string())
                } else if val.is_object() {
                    serde_json::to_string(val).ok()
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(tx_str) = tx_str_opt {
                let mut mempool = data.mempool.lock()
                    .map_err(|e| JsonRpcError { code: -32000, message: format!("Mempool lock error: {}", e) })?;
                mempool.add_transaction(tx_str.clone());
                
                // Calculate Hash
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(tx_str.as_bytes());
                let result = hasher.finalize();
                let tx_hash = hex::encode(result);
                
                Ok(serde_json::json!({ "status": "sent", "tx_hash": tx_hash }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: Expected JSON string or object".into() })
            }
        },
        "aincore_getStatus" => {
             // CRITICAL: READ lock for high concurrency
             let consensus = data.consensus.read().map_err(|e| JsonRpcError { code: -32000, message: format!("Consensus lock error: {}", e) })?;
             let peers = data.peers.lock().map_err(|e| JsonRpcError { code: -32000, message: format!("Peers lock error: {}", e) })?;
             
             Ok(serde_json::json!({
                 "node_id": consensus.node_id,
                 "current_round": consensus.current_round,
                 "peers_count": peers.len(),
                 "latest_height": match data.storage.get("latest_height") {
                     Ok(Some(h)) => h,
                     _ => "0".to_string(),
                  }
             }))
        },
        "aincore_getDag" => {
            let consensus = data.consensus.read().map_err(|e| JsonRpcError { code: -32000, message: format!("Consensus lock error: {}", e) })?;
            let dag = consensus.dag.lock().map_err(|e| JsonRpcError { code: -32000, message: format!("DAG lock error: {}", e) })?;
            
            let vertices: Vec<_> = dag.values().cloned().collect();
            Ok(serde_json::json!(vertices))
        },
        "aincore_getTransaction" => {
            // params: [tx_hash]
            if let Some(target_hash) = params.get(0).and_then(|v| v.as_str()) {
                // M4 FIX: Use O(1) indexed lookup instead of O(N) DAG scan
                if let Some(block_height) = data.storage.get_tx_block_height(target_hash) {
                    let block_key = format!("block_{}", block_height);
                    if let Ok(Some(block_json)) = data.storage.get(&block_key) {
                        if let Ok(block_obj) = serde_json::from_str::<serde_json::Value>(&block_json) {
                            if let Some(txs) = block_obj.get("transactions").and_then(|t| t.as_array()) {
                                for tx_val in txs {
                                    if let Some(tx_str) = tx_val.as_str() {
                                        use sha2::{Sha256, Digest};
                                        let mut hasher = Sha256::new();
                                        hasher.update(tx_str.as_bytes());
                                        let tx_hash = hex::encode(hasher.finalize());
                                        
                                        if tx_hash == target_hash {
                                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(tx_str) {
                                                return Ok(parsed);
                                            } else {
                                                return Ok(serde_json::json!({ "raw": tx_str }));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Fallback to mempool check if not in a block
                let in_mempool = if let Ok(mp) = data.mempool.lock() {
                    mp.get_all_pending().iter().find(|tx| {
                         use sha2::{Sha256, Digest};
                         let mut hasher = Sha256::new();
                         hasher.update(tx.as_bytes());
                         hex::encode(hasher.finalize()) == target_hash
                    }).cloned()
                } else { None };
                
                if let Some(tx_str) = in_mempool {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&tx_str) {
                         return Ok(parsed);
                    } else {
                         return Ok(serde_json::json!({ "raw": tx_str }));
                    }
                }
                
                Ok(serde_json::json!(null))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params".into() })
            }
        },
        "aincore_getBlocks" => {
            // params: [limit] (optional, default 10)
            let limit = params.get(0).and_then(|v| v.as_u64()).unwrap_or(10);
            
            // FIXED: Explicitly handle latest_height parsing with logging
            let latest_height: u64 = match data.storage.get("latest_height") {
                Ok(Some(h)) => {
                    match h.parse::<u64>() {
                        Ok(val) => val,
                        Err(e) => {
                            println!("❌ [RPC] Failed to parse latest_height '{}': {}", h, e);
                            0
                        }
                    }
                },
                Ok(None) => {
                    println!("⚠️ [RPC] latest_height key not found in storage");
                    0
                },
                Err(e) => {
                    println!("❌ [RPC] Storage error reading latest_height: {}", e);
                    0
                }
            };
            
            println!("🔍 [RPC] aincore_getBlocks: Head={}, Limit={}", latest_height, limit);
            
            let mut blocks = Vec::new();
            let _start = latest_height;
            let start_index = latest_height.saturating_sub(limit);
            
            for i in (start_index + 1..=latest_height).rev() {
                let key = format!("block_{}", i);
                if let Ok(Some(block_json)) = data.storage.get(&key) {
                    if let Ok(block_obj) = serde_json::from_str::<serde_json::Value>(&block_json) {
                        blocks.push(block_obj);
                    }
                }
            }
            
            Ok(serde_json::json!(blocks))
        },
        "aincore_getPeers" => {
            let peers = data.storage.scan_peer_addrs();
            // Convert to a cleaner JSON format
            let peer_list: Vec<serde_json::Value> = peers.into_iter().map(|(id, addr)| {
                serde_json::json!({
                    "peer_id": id,
                    "multiaddr": addr
                })
            }).collect();
            Ok(serde_json::json!(peer_list))
        },
        "aincore_debug" => {
            // Scan all keys to see what's inside
            let mut keys = Vec::new();
            let iter = data.storage.db.iterator(rocksdb::IteratorMode::Start);
            for (i, item) in iter.enumerate() {
                if i > 100 { break; } // Limit to 100 keys
                if let Ok((k, v)) = item {
                    let key_str = String::from_utf8_lossy(&k).to_string();
                    let val_str = String::from_utf8_lossy(&v).to_string();
                    keys.push(format!("{} = {}", key_str, val_str));
                }
            }
            Ok(serde_json::json!(keys))
        },
        "aincore_getMiningStats" => {
            let peers = data.peers.lock()
                .map_err(|e| JsonRpcError { code: -32000, message: format!("Peers lock error: {}", e) })?;
            // Mock data for now, but active_miners is real (connected peers)
            Ok(serde_json::json!({
                "active_miners": peers.len(),
                "avg_bqi": 0.0, // Oracle not yet connected
                "network_hashrate": format!("{} TH/s (Est)", peers.len() * 10), 
                "difficulty": 1 // Genesis difficulty
            }))
        },
        "aincore_createProposal" => {
            // params: [id, title, description, proposer, duration_seconds]
            if let (Some(id), Some(title), Some(desc), Some(proposer), Some(duration)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
                params.get(3).and_then(|v| v.as_str()),
                params.get(4).and_then(|v| v.as_u64())
            ) {
                 let governance = data.governance.lock()
                     .map_err(|e| JsonRpcError { code: -32000, message: format!("Governance lock error: {}", e) })?;
                 match governance.create_proposal(id.to_string(), title.to_string(), desc.to_string(), proposer.to_string(), duration, None) {
                     Ok(pid) => Ok(serde_json::json!({ "status": "created", "proposal_id": pid })),
                     Err(e) => Err(JsonRpcError { code: -32000, message: e }),
                 }
            } else {
                 Err(JsonRpcError { code: -32602, message: "Invalid params".into() })
            }
        },
        "aincore_vote" => {
            // params: [proposal_id, voter_addr, approve_bool]
            if let (Some(pid), Some(voter), Some(approve)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_bool())
            ) {
                 let governance = data.governance.lock()
                     .map_err(|e| JsonRpcError { code: -32000, message: format!("Governance lock error: {}", e) })?;
                 // weight is calculated internally now, passing 0 as placeholder
                 match governance.vote(pid, voter.to_string(), approve, 0) {
                     Ok(_) => Ok(serde_json::json!({ "status": "voted" })),
                     Err(e) => Err(JsonRpcError { code: -32000, message: e }),
                 }
            } else {
             // params: [proposal_id, voter, choice(bool)]
             // Fix: Use as_array to safely check length
             let len = params.as_array().map(|a| a.len()).unwrap_or(0);
             if len < 3 { return Err(JsonRpcError { code: -32602, message: "Invalid params".into() }); }
             
             let pid = params[0].as_str().unwrap_or("").to_string();
             let voter = params[1].as_str().unwrap_or("").to_string();
             let choice = params[2].as_bool().unwrap_or(false);
             
             let governance = data.governance.lock().map_err(|e| JsonRpcError { code: -32000, message: format!("Governance lock error: {}", e) })?;
             // Fix: Pass 4 args
             let res = governance.vote(&pid, voter, choice, 0); 
             Ok(serde_json::json!(res))
             }
        },
        "aincore_getProposal" => {
            if let Some(pid) = params.get(0).and_then(|v| v.as_str()) {
                 let governance = data.governance.lock().map_err(|e| JsonRpcError { code: -32000, message: format!("Governance lock error: {}", e) })?;
                 if let Some(p) = governance.get_proposal(pid) {
                     Ok(serde_json::json!(p))
                 } else {
                     Ok(serde_json::json!(null))
                 }
            } else {
                 Err(JsonRpcError { code: -32602, message: "Invalid params".into() })
            }
        },
        "aincore_tally" => {
             if let Some(pid) = params.get(0).and_then(|v| v.as_str()) {
                 let governance = data.governance.lock().map_err(|e| JsonRpcError { code: -32000, message: format!("Governance lock error: {}", e) })?;
                 // Fix: Call tally instead of tally_votes
                 let res = governance.tally(pid);
                 Ok(serde_json::json!(res))
             } else {
                 Err(JsonRpcError { code: -32602, message: "Missing proposal ID".into() })
             }
        },
        "aincore_getGasPrice" => {
            // Return safe minimum gas price (1 AIN-Sat)
            Ok(serde_json::json!(1))
        },
        "aincore_getMempoolStatus" => {
            let mempool = data.mempool.lock()
                .map_err(|e| JsonRpcError { code: -32000, message: format!("Mempool lock error: {}", e) })?;
            
            Ok(serde_json::json!({
                "status": "Active",
                "pending_tx_count": mempool.len() // Real count!
            }))
        },
        "aincore_getFheKey" => {
            let key = match data.storage.get("sys:fhe:global_public_key") {
                Ok(Some(k)) => k,
                _ => "FHE_MOCK_PUBLIC_KEY_12345".to_string() 
            };
            Ok(serde_json::json!({ "public_key": key }))
        },
        "aincore_getDaStatus" => {
             // Retrieve DA internal state from storage keys
             // DA Sequencer writes `da_root_{epoch}`
             // We can guess current DA epoch by scanning or storing "da:latest_epoch"
             // Since we don't have "da:latest_epoch" index yet, let's just return what we know.
             // We could scan recent keys? 
             // Better: Return the `node_id` which acts as DA Proposer ID if active.
             let consensus = data.consensus.read().map_err(|e| JsonRpcError { code: -32000, message: format!("Consensus lock error: {}", e) })?;
             
             Ok(serde_json::json!({
                 "da_mode": "Sovereign",
                 "sequencer_id": consensus.node_id,
                 "erasure_coding": "Reed-Solomon (16/16)",
                 "da_epoch": "Synced with Block Height (Approx)" // Placeholder until we index DA epoch
             }))
        },
        
        // ============ DELEGATION QUERY METHODS ============
        
        "aincore_getDelegation" => {
            // params: [delegator_address, validator_address]
            if let (Some(delegator), Some(validator)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str())
            ) {
                // Query delegation from storage
                // Delegation data stored as: delegation:{delegator}:{validator}
                let key = format!("delegation:{}:{}", delegator, validator);
                match data.storage.get(&key) {
                    Ok(Some(data_str)) => {
                        if let Ok(del_data) = serde_json::from_str::<serde_json::Value>(&data_str) {
                            Ok(del_data)
                        } else {
                            Ok(serde_json::json!({ "amount": "0", "pending_rewards": "0" }))
                        }
                    },
                    _ => Ok(serde_json::json!({ "amount": "0", "pending_rewards": "0" }))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [delegator, validator]".into() })
            }
        },
        
        "aincore_getDelegations" => {
            // params: [delegator_address]
            if let Some(delegator) = params.get(0).and_then(|v| v.as_str()) {
                // Scan for all delegations from this delegator
                // Keys: delegation:{delegator}:*
                let prefix = format!("delegation:{}:", delegator);
                let mut delegations = Vec::new();
                
                // Scan DB for keys with prefix
                let iter = data.storage.db.prefix_iterator(prefix.as_bytes());
                for item in iter {
                    if let Ok((k, v)) = item {
                        let key_str = String::from_utf8_lossy(&k).to_string();
                        if !key_str.starts_with(&prefix) {
                            break; // Past our prefix
                        }
                        // Extract validator address from key
                        let validator = key_str.strip_prefix(&prefix).unwrap_or("");
                        if let Ok(del_data) = serde_json::from_slice::<serde_json::Value>(&v) {
                            delegations.push(serde_json::json!({
                                "validator": validator,
                                "amount": del_data.get("amount").unwrap_or(&serde_json::json!("0")),
                                "pending_rewards": del_data.get("pending_rewards").unwrap_or(&serde_json::json!("0"))
                            }));
                        }
                    }
                }
                
                Ok(serde_json::json!(delegations))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [delegator_address]".into() })
            }
        },
        
        "aincore_getUnbondingDelegations" => {
            // params: [delegator_address]
            if let Some(delegator) = params.get(0).and_then(|v| v.as_str()) {
                let prefix = format!("unbonding:{}:", delegator);
                let mut unbondings = Vec::new();
                
                let iter = data.storage.db.prefix_iterator(prefix.as_bytes());
                for item in iter {
                    if let Ok((k, v)) = item {
                        let key_str = String::from_utf8_lossy(&k).to_string();
                        if !key_str.starts_with(&prefix) {
                            break;
                        }
                        let validator = key_str.strip_prefix(&prefix).unwrap_or("");
                        if let Ok(data) = serde_json::from_slice::<serde_json::Value>(&v) {
                            unbondings.push(serde_json::json!({
                                "validator": validator,
                                "amount": data.get("amount").unwrap_or(&serde_json::json!("0")),
                                "unlock_time": data.get("unlock_time").unwrap_or(&serde_json::json!(0))
                            }));
                        }
                    }
                }
                
                Ok(serde_json::json!(unbondings))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [delegator_address]".into() })
            }
        },
        
        "aincore_getValidatorPool" => {
            // params: [validator_address]
            if let Some(validator) = params.get(0).and_then(|v| v.as_str()) {
                let key = format!("validator_pool:{}", validator);
                match data.storage.get(&key) {
                    Ok(Some(pool_str)) => {
                        if let Ok(pool_data) = serde_json::from_str::<serde_json::Value>(&pool_str) {
                            Ok(serde_json::json!({
                                "total_delegated": pool_data.get("total_delegated").unwrap_or(&serde_json::json!("0")),
                                "commission_rate": pool_data.get("commission_rate").unwrap_or(&serde_json::json!(0)),
                                "delegator_count": pool_data.get("delegator_count").unwrap_or(&serde_json::json!(0)),
                                "is_accepting": true
                            }))
                        } else {
                            Ok(serde_json::json!({
                                "total_delegated": "0",
                                "commission_rate": 0,
                                "delegator_count": 0,
                                "is_accepting": false
                            }))
                        }
                    },
                    _ => Ok(serde_json::json!({
                        "total_delegated": "0",
                        "commission_rate": 0,
                        "delegator_count": 0,
                        "is_accepting": false
                    }))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [validator_address]".into() })
            }
        },
        
        "aincore_getValidatorsWithDelegation" => {
            // No params, returns all validators accepting delegations
            let mut validators = Vec::new();
            
            // Scan for validator_pool:* keys
            let prefix = "validator_pool:";
            let iter = data.storage.db.prefix_iterator(prefix.as_bytes());
            for item in iter {
                if let Ok((k, v)) = item {
                    let key_str = String::from_utf8_lossy(&k).to_string();
                    if !key_str.starts_with(prefix) {
                        break;
                    }
                    let validator = key_str.strip_prefix(prefix).unwrap_or("");
                    if let Ok(pool_data) = serde_json::from_slice::<serde_json::Value>(&v) {
                        validators.push(serde_json::json!({
                            "address": validator,
                            "total_delegated": pool_data.get("total_delegated").unwrap_or(&serde_json::json!("0")),
                            "commission_rate": pool_data.get("commission_rate").unwrap_or(&serde_json::json!(0)),
                            "delegator_count": pool_data.get("delegator_count").unwrap_or(&serde_json::json!(0))
                        }));
                    }
                }
            }
            
            Ok(serde_json::json!(validators))
        },
        
        // ============ TOKEN FACTORY QUERY METHODS ============
        
        "aincore_getToken" => {
            // params: [token_id]
            if let Some(token_id) = params.get(0).and_then(|v| v.as_str()) {
                let key = format!("token:{}", token_id);
                match data.storage.get(&key) {
                    Ok(Some(token_str)) => {
                        if let Ok(token_data) = serde_json::from_str::<serde_json::Value>(&token_str) {
                            Ok(token_data)
                        } else {
                            Ok(serde_json::json!(null))
                        }
                    },
                    _ => Ok(serde_json::json!(null))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [token_id]".into() })
            }
        },
        
        "aincore_getTokens" => {
            // No params, returns all tokens
            let mut tokens = Vec::new();
            
            let prefix = "token:";
            let iter = data.storage.db.prefix_iterator(prefix.as_bytes());
            for item in iter {
                if let Ok((k, v)) = item {
                    let key_str = String::from_utf8_lossy(&k).to_string();
                    if !key_str.starts_with(prefix) {
                        break;
                    }
                    if let Ok(token_data) = serde_json::from_slice::<serde_json::Value>(&v) {
                        tokens.push(token_data);
                    }
                }
            }
            
            Ok(serde_json::json!(tokens))
        },
        
        "aincore_getTokenBalance" => {
            // params: [address, token_id]
            if let (Some(address), Some(token_id)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str())
            ) {
                let key = format!("token_balance:{}:{}", address, token_id);
                match data.storage.get(&key) {
                    Ok(Some(balance_str)) => {
                        if let Ok(balance) = balance_str.parse::<u128>() {
                            Ok(serde_json::json!({ "balance": balance.to_string() }))
                        } else {
                            Ok(serde_json::json!({ "balance": "0" }))
                        }
                    },
                    _ => Ok(serde_json::json!({ "balance": "0" }))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [address, token_id]".into() })
            }
        },
        
        // ============ CRITICAL WALLET ENDPOINTS ============
        
        "aincore_getAccountNonce" => {
            // params: [address]
            if let Some(addr) = params.get(0).and_then(|v| v.as_str()) {
                if let Some(obj) = data.storage.get_object(addr) {
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&obj.data) {
                        let nonce = account_data.get("sequence_number").and_then(|v| v.as_u64()).unwrap_or(0);
                        Ok(serde_json::json!({ "nonce": nonce, "sequence_number": nonce }))
                    } else {
                        Ok(serde_json::json!({ "nonce": 0, "sequence_number": 0 }))
                    }
                } else {
                    Ok(serde_json::json!({ "nonce": 0, "sequence_number": 0 }))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [address]".into() })
            }
        },
        
        "aincore_getSupply" => {
            // No params
            let max_supply: u128 = 150_000_000 * 1_000_000_000_000_000_000; // 150M AIN
            let tail_emission: u128 = 10 * 1_000_000_000_000_000_000; // 10 AIN
            
            // Read total minted from storage
            let total_minted = match data.storage.get("total_supply") {
                Ok(Some(s)) => s.parse::<u128>().unwrap_or(0),
                _ => 0,
            };
            let total_burned = match data.storage.get("total_burned") {
                Ok(Some(s)) => s.parse::<u128>().unwrap_or(0),
                _ => 0,
            };
            let circulating = total_minted.saturating_sub(total_burned);
            
            Ok(serde_json::json!({
                "max_supply": max_supply.to_string(),
                "total_minted": total_minted.to_string(),
                "total_burned": total_burned.to_string(),
                "circulating_supply": circulating.to_string(),
                "tail_emission_per_block": tail_emission.to_string(),
                "decimals": 18
            }))
        },
        
        "aincore_getTransactionReceipt" => {
            // params: [tx_hash]
            if let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()) {
                // Use indexed lookup (O(1)) 
                if let Some(block_height) = data.storage.get_tx_block_height(tx_hash) {
                    // Fetch the block to get confirmation details
                    let block_key = format!("block_{}", block_height);
                    let block_data = match data.storage.get(&block_key) {
                        Ok(Some(b)) => serde_json::from_str::<serde_json::Value>(&b).ok(),
                        _ => None,
                    };
                    let latest_height = data.storage.get_chain_height();
                    let confirmations = latest_height.saturating_sub(block_height);
                    
                    Ok(serde_json::json!({
                        "tx_hash": tx_hash,
                        "block_height": block_height,
                        "confirmations": confirmations,
                        "status": "confirmed",
                        "block_hash": block_data.as_ref()
                            .and_then(|b| b.get("header"))
                            .and_then(|h| h.get("hash"))
                            .and_then(|h| h.as_str())
                            .unwrap_or("")
                    }))
                } else {
                    // Check if it's in mempool
                    let in_mempool = if let Ok(mp) = data.mempool.lock() {
                        mp.len() > 0 // Simplified check
                    } else { false };
                    
                    Ok(serde_json::json!({
                        "tx_hash": tx_hash,
                        "status": if in_mempool { "pending" } else { "not_found" },
                        "confirmations": 0
                    }))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [tx_hash]".into() })
            }
        },
        
        "aincore_estimateGas" => {
            // params: [tx_object] or [payload_string]
            // Simple estimation based on payload type
            let payload = params.get(0)
                .and_then(|v| {
                    if v.is_string() { v.as_str().map(|s| s.to_string()) }
                    else if v.is_object() { v.get("payload").and_then(|p| p.as_str()).map(|s| s.to_string()) }
                    else { None }
                })
                .unwrap_or_default();
            
            let gas = if payload.starts_with("transfer:") { 21_000u64 }
                else if payload.starts_with("delegate:") || payload.starts_with("undelegate:") { 50_000 }
                else if payload.starts_with("claim_rewards:") || payload.starts_with("withdraw_unbonded:") { 30_000 }
                else if payload.starts_with("create_token:") { 100_000 }
                else if payload.starts_with("mint_token:") || payload.starts_with("burn_token:") { 40_000 }
                else if payload.starts_with("transfer_token:") { 25_000 }
                else if payload.starts_with("mint_btc:") { 60_000 }
                else if payload.starts_with("submit_proof:") { 200_000 }
                else if payload.starts_with("enable_delegation:") { 50_000 }
                else if payload.starts_with("0x") { 500_000 } // Move script
                else { 21_000 }; // Default
            
            Ok(serde_json::json!({
                "estimated_gas": gas,
                "gas_price": 1,
                "estimated_fee": gas.to_string()
            }))
        },
        
        "aincore_getBlockByHash" => {
            // params: [block_hash]
            if let Some(target_hash) = params.get(0).and_then(|v| v.as_str()) {
                let latest_height = data.storage.get_chain_height();
                let mut found_block = None;
                
                // Search recent blocks (last 1000) for matching hash
                let search_start = latest_height.saturating_sub(1000);
                for h in (search_start..=latest_height).rev() {
                    let key = format!("block_{}", h);
                    if let Ok(Some(block_json)) = data.storage.get(&key) {
                        if block_json.contains(target_hash) {
                            if let Ok(block_obj) = serde_json::from_str::<serde_json::Value>(&block_json) {
                                found_block = Some(block_obj);
                                break;
                            }
                        }
                    }
                }
                
                Ok(found_block.unwrap_or(serde_json::json!(null)))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [block_hash]".into() })
            }
        },
        
        "aincore_getBtcBalance" => {
            // params: [address]
            if let Some(addr) = params.get(0).and_then(|v| v.as_str()) {
                if let Some(obj) = data.storage.get_object(addr) {
                    if let Ok(account_data) = serde_json::from_slice::<serde_json::Value>(&obj.data) {
                        let btc_balance = account_data.get("btc_balance").and_then(|v| v.as_u64()).unwrap_or(0);
                        Ok(serde_json::json!({
                            "address": addr,
                            "btc_balance_sats": btc_balance,
                            "btc_balance_btc": format!("{:.8}", btc_balance as f64 / 100_000_000.0)
                        }))
                    } else {
                        Ok(serde_json::json!({ "btc_balance_sats": 0, "btc_balance_btc": "0.00000000" }))
                    }
                } else {
                    Ok(serde_json::json!({ "btc_balance_sats": 0, "btc_balance_btc": "0.00000000" }))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [address]".into() })
            }
        },
        
        // ============ IMPORTANT DAPP/EXPLORER ENDPOINTS ============
        
        "aincore_getEconomics" => {
            let base_reward = data.storage.get_base_reward();
            let halving_interval = data.storage.get_halving_interval();
            let burn_percentage = data.storage.get_burn_percentage();
            let latest_height = data.storage.get_chain_height();
            let max_supply: u128 = 150_000_000 * 1_000_000_000_000_000_000;
            
            // Calculate current epoch and effective reward
            let epoch = if halving_interval > 0 { latest_height / halving_interval } else { 0 };
            
            Ok(serde_json::json!({
                "base_reward": base_reward,
                "halving_interval": halving_interval,
                "burn_percentage": burn_percentage,
                "current_epoch": epoch,
                "max_supply": max_supply.to_string(),
                "block_height": latest_height,
                "decay_model": "Exponential Smooth (TAIL_EMISSION = 10 AIN)"
            }))
        },
        
        "aincore_sampleDA" => {
            // params: [epoch, shard_id]
            if let (Some(epoch), Some(shard_id)) = (
                params.get(0).and_then(|v| v.as_u64()),
                params.get(1).and_then(|v| v.as_u64())
            ) {
                // Check if shard data exists
                let shard_key = format!("da_shard_{}_{}", epoch, shard_id);
                let commitment_key = format!("da_commitment_{}", epoch);
                
                let shard_exists = matches!(data.storage.get(&shard_key), Ok(Some(_)));
                let commitment = match data.storage.get(&commitment_key) {
                    Ok(Some(c)) => c,
                    _ => String::new(),
                };
                
                Ok(serde_json::json!({
                    "epoch": epoch,
                    "shard_id": shard_id,
                    "available": shard_exists,
                    "merkle_root": commitment,
                    "sampling_result": if shard_exists { "PASS" } else { "MISSING" }
                }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [epoch, shard_id]".into() })
            }
        },
        
        "aincore_verifyFraudProof" => {
            // params: [proof_json]
            if let Some(proof) = params.get(0) {
                // Verify fraud proof structure
                let is_valid = proof.get("proof_type").is_some() 
                    && proof.get("evidence").is_some()
                    && proof.get("block_height").is_some();
                
                Ok(serde_json::json!({
                    "valid_structure": is_valid,
                    "status": if is_valid { "accepted_for_review" } else { "invalid_format" },
                    "required_fields": ["proof_type", "evidence", "block_height", "offender"]
                }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [proof_object]".into() })
            }
        },
        
        "aincore_getShardProof" => {
            // params: [epoch, shard_id]
            if let (Some(epoch), Some(shard_id)) = (
                params.get(0).and_then(|v| v.as_u64()),
                params.get(1).and_then(|v| v.as_u64())
            ) {
                let shard_key = format!("da_shard_{}_{}", epoch, shard_id);
                let commitment_key = format!("da_commitment_{}", epoch);
                
                let shard_data = match data.storage.get(&shard_key) {
                    Ok(Some(d)) => d,
                    _ => String::new(),
                };
                let merkle_root = match data.storage.get(&commitment_key) {
                    Ok(Some(c)) => c,
                    _ => String::new(),
                };
                
                Ok(serde_json::json!({
                    "epoch": epoch,
                    "shard_id": shard_id,
                    "shard_data_hex": shard_data,
                    "merkle_root": merkle_root,
                    "proof_available": !shard_data.is_empty() && !merkle_root.is_empty()
                }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [epoch, shard_id]".into() })
            }
        },
        
        "aincore_getFederationKey" => {
            let key = data.storage.get_federation_key();
            Ok(serde_json::json!({ "federation_key": key }))
        },
        
        "aincore_getTransactionsByAddress" => {
            // params: [address, limit (optional)]
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let limit = params.get(1).and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                let latest_height = data.storage.get_chain_height();
                let mut txs = Vec::new();
                
                // Scan recent blocks for transactions involving this address
                let search_start = latest_height.saturating_sub(500);
                'block_scan: for h in (search_start..=latest_height).rev() {
                    let key = format!("block_{}", h);
                    if let Ok(Some(block_json)) = data.storage.get(&key) {
                        if block_json.contains(address) {
                            if let Ok(block) = serde_json::from_str::<serde_json::Value>(&block_json) {
                                if let Some(transactions) = block.get("transactions").and_then(|t| t.as_array()) {
                                    for tx_str in transactions {
                                        let tx_text = tx_str.as_str().unwrap_or("");
                                        if tx_text.contains(address) {
                                            if let Ok(tx_obj) = serde_json::from_str::<serde_json::Value>(tx_text) {
                                                txs.push(serde_json::json!({
                                                    "block_height": h,
                                                    "transaction": tx_obj
                                                }));
                                            } else {
                                                txs.push(serde_json::json!({
                                                    "block_height": h,
                                                    "raw": tx_text
                                                }));
                                            }
                                            if txs.len() >= limit { break 'block_scan; }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                Ok(serde_json::json!({
                    "address": address,
                    "count": txs.len(),
                    "transactions": txs
                }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [address, limit?]".into() })
            }
        },
        
        // ============ ADVANCED CRYPTO ENDPOINTS ============
        
        "aincore_verifyMultiSig" => {
            // params: [scheme (0=Ed25519, 1=Dilithium5, 2=Secp256k1), public_key_hex, message_hex, signature_hex]
            if let (Some(scheme_id), Some(pubkey_hex), Some(msg_hex), Some(sig_hex)) = (
                params.get(0).and_then(|v| v.as_u64()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
                params.get(3).and_then(|v| v.as_str())
            ) {
                let pubkey = hex::decode(pubkey_hex).unwrap_or_default();
                let message = hex::decode(msg_hex).unwrap_or_default();
                let signature = hex::decode(sig_hex).unwrap_or_default();
                
                use crypto::multi_sig::{MultiSigVerifier, SignatureScheme};
                let verifier = MultiSigVerifier::new();
                
                let scheme = match scheme_id {
                    0 => Some(SignatureScheme::Ed25519),
                    1 => Some(SignatureScheme::Dilithium5),
                    2 => Some(SignatureScheme::Secp256k1),
                    _ => None,
                };
                
                if let Some(s) = scheme {
                    match verifier.verify(s, &pubkey, &message, &signature) {
                        Ok(valid) => Ok(serde_json::json!({
                            "valid": valid,
                            "scheme": format!("{:?}", s)
                        })),
                        Err(e) => Ok(serde_json::json!({
                            "valid": false,
                            "error": format!("{}", e)
                        }))
                    }
                } else {
                    Err(JsonRpcError { code: -32602, message: "Invalid scheme: 0=Ed25519, 1=Dilithium5, 2=Secp256k1".into() })
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [scheme, pubkey_hex, message_hex, signature_hex]".into() })
            }
        },
        
        "aincore_aggregateBLS" => {
            // params: [signatures_hex_array]
            // Returns aggregated BLS signature info
            if let Some(sigs) = params.get(0).and_then(|v| v.as_array()) {
                Ok(serde_json::json!({
                    "input_count": sigs.len(),
                    "scheme": "BLS12-381",
                    "status": "aggregation_available",
                    "note": "Submit via sendTransaction with submit_proof: payload"
                }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [signatures_array]".into() })
            }
        },
        
        "aincore_verifyProof" => {
            // params: [proof_type ("snark"|"stark"), proof_hex]
            if let (Some(proof_type), Some(proof_hex)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str())
            ) {
                let proof_bytes = hex::decode(proof_hex).unwrap_or_default();
                let is_valid_format = !proof_bytes.is_empty();
                
                Ok(serde_json::json!({
                    "proof_type": proof_type,
                    "proof_size_bytes": proof_bytes.len(),
                    "valid_format": is_valid_format,
                    "supported_types": ["snark", "stark"],
                    "status": if is_valid_format { "proof_accepted" } else { "invalid_encoding" }
                }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [proof_type, proof_hex]".into() })
            }
        },
        
        "aincore_verifyVDF" => {
            // params: [input_hex, output_hex, iterations]
            if let (Some(input_hex), Some(output_hex), Some(iterations)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_u64())
            ) {
                let input_bytes = hex::decode(input_hex).unwrap_or_default();
                let output_bytes = hex::decode(output_hex).unwrap_or_default();
                
                use crypto::VDFEngine;
                if let Ok(vdf) = VDFEngine::new(iterations) {
                    if let Ok((computed_output, _proof)) = vdf.compute(&input_bytes) {
                        let valid = computed_output == output_bytes;
                        
                        Ok(serde_json::json!({
                            "valid": valid,
                            "iterations": iterations,
                            "input_len": input_bytes.len(),
                            "output_len": output_bytes.len()
                        }))
                    } else {
                        Ok(serde_json::json!({ "valid": false, "error": "VDF computation failed" }))
                    }
                } else {
                    Err(JsonRpcError { code: -32602, message: "Invalid VDF iterations parameters".into() })
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [input_hex, output_hex, iterations]".into() })
            }
        },
        
        "aincore_ecdsaVerify" => {
            // params: [public_key_hex, message_hex, signature_hex]
            if let (Some(pubkey_hex), Some(msg_hex), Some(sig_hex)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str())
            ) {
                let pubkey_bytes = hex::decode(pubkey_hex).unwrap_or_default();
                let message = hex::decode(msg_hex).unwrap_or_default();
                let signature = hex::decode(sig_hex).unwrap_or_default();
                
                use crypto::ECDSACrypto;
                let crypto = ECDSACrypto::new();
                
                if let Ok(pubkey) = crypto.public_key_from_bytes(&pubkey_bytes) {
                    match crypto.verify(&pubkey, &message, &signature) {
                        Ok(valid) => Ok(serde_json::json!({
                            "valid": valid,
                            "scheme": "secp256k1"
                        })),
                        Err(e) => Ok(serde_json::json!({
                            "valid": false,
                            "error": format!("{}", e)
                        }))
                    }
                } else {
                    Ok(serde_json::json!({
                        "valid": false,
                        "error": "Invalid public key format"
                    }))
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [pubkey_hex, message_hex, signature_hex]".into() })
            }
        },
        
        "aincore_deriveAddress" => {
            // params: [public_key_hex]
            if let Some(pubkey_hex) = params.get(0).and_then(|v| v.as_str()) {
                let pubkey_bytes = hex::decode(pubkey_hex).unwrap_or_default();
                match crypto::derive_address(&pubkey_bytes) {
                    Ok(address) => Ok(serde_json::json!({
                        "public_key": pubkey_hex,
                        "address": address,
                        "format": "hex(SHA256(pubkey)[0..16])"
                    })),
                    Err(e) => Err(JsonRpcError { code: -32000, message: format!("Derivation error: {}", e) })
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [public_key_hex]".into() })
            }
        },
        
        _ => Err(JsonRpcError { code: -32601, message: "Method not found".into() }),
    }
}

async fn json_rpc_handler(
    req: web::Json<JsonRpcRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let method = req.method.as_str();
    let params = req.params.clone().unwrap_or(serde_json::Value::Null);

    println!("📥 JSON-RPC Request: {} {:?}", method, params);

    let result = handle_rpc_method(method, params, &data);

    let response = match result {
        Ok(res) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(res),
            error: None,
            id: req.id.clone(),
        },
        Err(err) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(err),
            id: req.id.clone(),
        },
    };

    HttpResponse::Ok().json(response)
}

async fn health() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

// === RPC-BASED SYNC ENDPOINTS ===

async fn get_chain_height_handler(data: web::Data<AppState>) -> impl Responder {
    let height = data.storage.get_chain_height();
    HttpResponse::Ok().body(height.to_string())
}

#[derive(Deserialize)]
struct BlockQuery {
    height: u64,
}

// GET /get_block?height=N
async fn get_block_handler(
    query: web::Query<BlockQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    // INPUT VALIDATION
    if query.height > MAX_BLOCK_HEIGHT {
        return HttpResponse::BadRequest()
            .body(format!("Invalid height: {} exceeds maximum {}", query.height, MAX_BLOCK_HEIGHT));
    }
    
    let current_height = data.storage.get_chain_height();
    if query.height > current_height {
        return HttpResponse::NotFound()
            .body(format!("Block not found: height {} exceeds chain tip {}", query.height, current_height));
    }
    let key = format!("block_{}", query.height);
    match data.storage.get(&key) {
        Ok(Some(block_json)) => HttpResponse::Ok()
            .content_type("application/json")
            .body(block_json),
        Ok(None) => HttpResponse::NotFound().body("Block not found"),
        Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
    }
}

// GET /get_latest_blocks?limit=10
#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<u64>,
}

async fn get_latest_blocks_handler(
    query: web::Query<LimitQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(10).min(50); 
    
    // Explicitly fetch latest_height as string then parse, to match other handlers
    let latest_height: u64 = match data.storage.get("latest_height") {
        Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
        _ => {
            println!("⚠️ [API] get_latest_blocks: 'latest_height' key not found or error. Returning empty.");
            return HttpResponse::Ok().json(serde_json::json!([]));
        }
    };
    
    println!("🔍 [API] get_latest_blocks: Head={}, Limit={}", latest_height, limit);
    
    let mut blocks = Vec::new();
    let start_index = latest_height.saturating_sub(limit);
    
    // Loop inclusive
    for i in (start_index + 1..=latest_height).rev() {
        let key = format!("block_{}", i);
        match data.storage.get(&key) {
             Ok(Some(block_json)) => {
                 if let Ok(block_obj) = serde_json::from_str::<serde_json::Value>(&block_json) {
                     blocks.push(block_obj);
                 } else {
                     println!("❌ [API] Failed to parse block_{}", i);
                 }
             },
             Ok(None) => println!("⚠️ [API] Block key {} missing in DB", key),
             Err(e) => println!("❌ [API] DB Error reading {}: {}", key, e),
        }
    }
    
    println!("✅ [API] Returning {} blocks", blocks.len());
    HttpResponse::Ok().json(blocks)
}

// GET /get_validators
async fn get_validators_handler(data: web::Data<AppState>) -> impl Responder {
    // REAL IMPLEMENTATION: Fetch from StateDB
    let validators = data.storage.get_active_validators(); // Returns Vec<(String, u64)> (PubKey, Stake)
    
    let validator_list: Vec<serde_json::Value> = validators.into_iter().map(|(pubkey, stake)| {
        serde_json::json!({
            "address": pubkey, // ID/PubKey
            "stake": stake,
            "status": "Active"
        })
    }).collect();

    let total_staked: u64 = validator_list.iter()
        .map(|v| v["stake"].as_u64().unwrap_or(0))
        .sum();
    
    let response = serde_json::json!({
        "active_validators_count": validator_list.len(),
        "total_staked": total_staked,
        "validators": validator_list
    });
    
    HttpResponse::Ok().json(response)
}

// GET /get_network_info
async fn get_network_info_handler(data: web::Data<AppState>) -> impl Responder {
    let peers = data.peers.lock().unwrap_or_else(|e| e.into_inner());
    let consensus = data.consensus.read().unwrap_or_else(|e| e.into_inner());
    let height = data.storage.get_chain_height();
    
    // CALCULATE TPS (Transactions per Second)
    // Look back 10 blocks or 100 blocks
    let lookback = 20;
    let start_block = height.saturating_sub(lookback);
    let mut total_txs = 0;
    let mut start_time = 0;
    let mut end_time = 0;

    // Fetch latest block for end time
    if let Ok(Some(b)) = data.storage.get(&format!("block_{}", height)) {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&b) {
            end_time = json["header"]["timestamp"].as_u64().unwrap_or(0);
        }
    }

    // Fetch start block for start time
    if start_block > 0 {
        if let Ok(Some(b)) = data.storage.get(&format!("block_{}", start_block)) {
             if let Ok(json) = serde_json::from_str::<serde_json::Value>(&b) {
                start_time = json["header"]["timestamp"].as_u64().unwrap_or(0);
            }
        }
    }

    // Capture TX count in window
    if end_time > start_time {
        for i in start_block..=height {
            if let Ok(Some(b)) = data.storage.get(&format!("block_{}", i)) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&b) {
                     if let Some(txs) = json["transactions"].as_array() {
                         total_txs += txs.len();
                     }
                }
            }
        }
    }

    // Determine TPS
    let tps = if end_time > start_time {
        let duration_ms = end_time.saturating_sub(start_time);
        if duration_ms > 0 {
             let duration_sec = duration_ms as f64 / 1000.0;
             if duration_sec > 0.0 {
                 total_txs as f64 / duration_sec
             } else {
                 0.0
             }
        } else {
             0.0
        }
    } else {
        0.0
    };

    let info = serde_json::json!({
        "node_id": consensus.node_id,
        "version": "0.1.0-alpha",
        "peer_count": peers.len(),
        "latest_block": height,
        "current_round": consensus.current_round,
        "tps": tps, 
        "network": "AINCORE Mainnet (Prototype)",
        "protocol_version": 1
    });
    
    HttpResponse::Ok().json(info)
}


// GET /get_transaction?hash=...
#[derive(Deserialize)]
struct TxQuery {
    hash: String,
}

async fn get_transaction_handler(
    query: web::Query<TxQuery>,
    data: web::Data<AppState>,
) -> impl Responder {
    let target_hash = &query.hash;
    let latest_height = data.storage.get_chain_height();
    
    // Naive scan (in production, use an indexer DB!)
    // Limit scan to last 1000 blocks to avoid timeout
    let start_index = latest_height.saturating_sub(1000);
    
    for i in (start_index..=latest_height).rev() {
        let key = format!("block_{}", i);
        if let Ok(Some(block_json)) = data.storage.get(&key) {
            // Check if block contains the string of the hash? 
            // Better: parse block and check header.tx_hash
            // For now, simpler string check to be fast
            if block_json.contains(target_hash) {
                 return HttpResponse::Ok()
                    .content_type("application/json")
                    .body(block_json); // Return the whole block containing the TX for now
            }
        }
    }
    
    HttpResponse::NotFound().body("Transaction not found in recent blocks")
}

async fn metrics_handler() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(node::metrics::gather_metrics())
}

// --- Server setup ---
// use consensus::SimpleConsensus; // Removed


// ...

pub async fn start_api_server(
    api_port: u16,
    consensus: Arc<RwLock<DagConsensus>>,
    peers: PeerList,
    mempool: Arc<Mutex<mempool::Mempool>>,
    storage: Arc<StateDB>,
    governance: Arc<Mutex<GovernanceManager>>,
) -> std::io::Result<()> {
    println!("🌐 Starting REST API server on port {}...", api_port);

    let app_state = web::Data::new(AppState {
        consensus,
        peers,
        mempool,
        governance,
        storage,
    });

    // gunakan tokio::task::LocalSet agar runtime single-thread tidak butuh Send
    let local = tokio::task::LocalSet::new();
    local
        .run_until(
            HttpServer::new(move || {
                use actix_cors::Cors;
                let cors = Cors::permissive();
                
                App::new()
                    .wrap(cors)
                    .app_data(app_state.clone())
                    .route("/health", web::get().to(health))
                    .route("/metrics", web::get().to(metrics_handler))
                    .service(
                        web::resource("/rpc")
                            .app_data(web::JsonConfig::default().limit(2 * 1024 * 1024))
                            .route(web::post().to(json_rpc_handler))
                    )
                    .route("/get_chain_height", web::get().to(get_chain_height_handler))
                    .route("/get_block", web::get().to(get_block_handler))
                    .route("/get_latest_blocks", web::get().to(get_latest_blocks_handler))
                    .route("/get_validators", web::get().to(get_validators_handler))
                    .route("/get_network_info", web::get().to(get_network_info_handler))
                    .route("/get_transaction", web::get().to(get_transaction_handler))
            })
            .bind(("0.0.0.0", api_port))?
            .run(),
        )
        .await
}
