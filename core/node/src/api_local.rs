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
                let consensus = data.consensus.read().map_err(|e| JsonRpcError { code: -32000, message: format!("Consensus lock error: {}", e) })?;
                let dag = consensus.dag.lock().map_err(|e| JsonRpcError { code: -32000, message: format!("DAG lock error: {}", e) })?;
                
                let mut found_tx = None;
                
                // Scan all vertices (inefficient but works for prototype)
                'outer: for vertex in dag.values() {
                    for tx_str in &vertex.payload {
                        use sha2::{Sha256, Digest};
                        let mut hasher = Sha256::new();
                        hasher.update(tx_str.as_bytes());
                        let result = hasher.finalize();
                        let tx_hash = hex::encode(result);
                        
                        if tx_hash == target_hash {
                            // Parse JSON to return structured data
                            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(tx_str) {
                                found_tx = Some(parsed);
                            } else {
                                found_tx = Some(serde_json::json!({ "raw": tx_str }));
                            }
                            break 'outer;
                        }
                    }
                }
                
                if let Some(tx) = found_tx {
                    Ok(tx)
                } else {
                    Ok(serde_json::json!(null))
                }
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
