use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use network::PeerList;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};

fn permissive_cors_enabled() -> bool {
    std::env::var("AINCORE_PERMISSIVE_CORS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::middleware::Logger;

// Input validation constants
const MAX_LIMIT: u64 = 1000;

// --- Shared State ---
use consensus::DagConsensus;
use storage::StateDB;

#[derive(Deserialize)]
struct MoveCoin {
    value: u128,
}

fn move_coin_store_key(addr: move_core_types::account_address::AccountAddress) -> String {
    use move_core_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{StructTag, TypeTag},
    };
    let system = AccountAddress::from_hex_literal("0x1").expect("valid system address");
    let coin_type = TypeTag::Struct(Box::new(StructTag {
        address: system,
        module: Identifier::new("staking").expect("valid module"),
        name: Identifier::new("AincoreCoin").expect("valid coin"),
        type_params: vec![],
    }));
    let store = StructTag {
        address: system,
        module: Identifier::new("coin").expect("valid module"),
        name: Identifier::new("CoinStore").expect("valid store"),
        type_params: vec![coin_type],
    };
    format!("resource_{}_{}", addr, store)
}

fn move_balance(storage: &Arc<StateDB>, addr: &str) -> String {
    let move_addr = match move_core_types::account_address::AccountAddress::from_hex_literal(
        &format!("0x{}", addr),
    ) {
        Ok(addr) => addr,
        Err(_) => return "0".to_string(),
    };
    let key = move_coin_store_key(move_addr);
    storage
        .get(&key)
        .ok()
        .flatten()
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<MoveCoin>(&bytes).ok())
        .map(|coin| coin.value.to_string())
        .unwrap_or_else(|| "0".to_string())
}

fn stored_tx_receipt(storage: &Arc<StateDB>, tx_hash: &str) -> Option<serde_json::Value> {
    storage
        .get(&format!("tx_receipt:{}", tx_hash))
        .ok()
        .flatten()
        .and_then(|receipt| serde_json::from_str(&receipt).ok())
}

// --- Shared State ---
pub struct AppState {
    pub consensus: Arc<RwLock<DagConsensus>>,
    pub peers: PeerList,
    pub mempool: Arc<Mutex<mempool::Mempool>>,
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

async fn json_rpc_handler(
    req: web::Json<JsonRpcRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let method = req.method.as_str();
    let params = req.params.clone().unwrap_or(serde_json::Value::Null);

    println!("📥 JSON-RPC Request: {} {:?}", method, params);

    let result = match method {
        "aincore_getBalance" => {
            // params: [address]
            if let Some(addr) = params.get(0).and_then(|v| v.as_str()) {
                if let Some(obj) = data.storage.get_object(addr) {
                     let mut value = serde_json::json!(obj);
                     if let Some(map) = value.as_object_mut() {
                         map.insert("move_balance".to_string(), serde_json::json!(move_balance(&data.storage, addr)));
                         map.insert("balance_source".to_string(), serde_json::json!("move_coin_store"));
                     }
                     Ok(value)
                } else {
                     Ok(serde_json::json!({
                         "id": addr,
                         "move_balance": move_balance(&data.storage, addr),
                         "balance_source": "move_coin_store"
                     }))
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
                let mut mempool = data.mempool.lock().unwrap_or_else(|e| e.into_inner());
                match mempool.add_transaction(tx_str) {
                    Ok(tx_hash) => Ok(serde_json::json!({ "status": "sent", "tx_hash": tx_hash })),
                    Err(reason) => Err(JsonRpcError {
                        code: -32010,
                        message: format!("Transaction rejected by mempool: {}", reason),
                    }),
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: Expected JSON string or object".into() })
            }
        },
        "submit_transaction_with_key" => {
            Err(JsonRpcError {
                code: -32040,
                message: "submit_transaction_with_key disabled in secure mode; submit signed transaction via aincore_sendTransaction".into(),
            })
        },
        "aincore_nodeStatus" => {
             let consensus = data.consensus.read().unwrap_or_else(|e| e.into_inner());
             let peers = data.peers.lock().unwrap_or_else(|e| e.into_inner());
             Ok(serde_json::json!({
                 "node_id": consensus.node_id,
                 "current_round": consensus.current_round,
                 "peers_count": peers.len(),
                 "latest_height": match data.storage.get("latest_height") {
                     Ok(Some(h)) => h,
                     _ => "0".to_string(),
                 },
                 "finalized_round": match data.storage.get("consensus:finalized_round") {
                     Ok(Some(v)) => v,
                     _ => "0".to_string(),
                 },
                 "last_anchor_round": match data.storage.get("consensus:last_anchor_round") {
                     Ok(Some(v)) => v,
                     _ => "0".to_string(),
                 },
                 "finality_digest": match data.storage.get("consensus:finality_digest") {
                     Ok(Some(v)) => v,
                     _ => String::new(),
                 },
             }))
        },
        "aincore_getFinalityStatus" => {
            Ok(serde_json::json!({
                "finalized_round": match data.storage.get("consensus:finalized_round") {
                    Ok(Some(v)) => v,
                    _ => "0".to_string(),
                },
                "last_anchor_round": match data.storage.get("consensus:last_anchor_round") {
                    Ok(Some(v)) => v,
                    _ => "0".to_string(),
                },
                "last_anchor_hash": match data.storage.get("consensus:last_anchor_hash") {
                    Ok(Some(v)) => v,
                    _ => String::new(),
                },
                "finality_digest": match data.storage.get("consensus:finality_digest") {
                    Ok(Some(v)) => v,
                    _ => String::new(),
                }
            }))
        },
        "aincore_getQuorumCert" | "aincore_getLatestQuorumCertificate" | "aincore_getQuorumCertificate" => {
            // QC Phase 2: return the stored quorum certificate (optionally for a
            // specific [height]; default = latest) AND independently re-verify it
            // against the trusted validator set so callers get a trust verdict,
            // not just bytes.
            let height = params.get(0).and_then(|v| v.as_u64()).or_else(|| {
                data.storage
                    .get("consensus:qc:latest_height")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<u64>().ok())
            });
            match height {
                None => Ok(serde_json::json!({
                    "available": false,
                    "reason": "no quorum certificate produced yet"
                })),
                Some(h) => match data.storage.get(&format!("consensus:qc:{}", h)) {
                    Ok(Some(qc_json)) => {
                        match serde_json::from_str::<consensus::qc::QuorumCertificate>(&qc_json) {
                            Ok(qc) => {
                                let (verified, verify_error) =
                                    match consensus::qc_producer::load_validator_set_v1(
                                        &data.storage,
                                    ) {
                                        Some(vset) => match consensus::qc::verify_qc(&qc, &vset) {
                                            Ok(()) => (true, String::new()),
                                            Err(e) => (false, e.to_string()),
                                        },
                                        None => (false, "validator set unavailable".to_string()),
                                    };
                                Ok(serde_json::json!({
                                    "available": true,
                                    "height": h,
                                    "verified": verified,
                                    "verify_error": verify_error,
                                    "quorum_certificate": qc,
                                }))
                            }
                            Err(e) => Ok(serde_json::json!({
                                "available": false,
                                "height": h,
                                "reason": format!("corrupt QC at height: {e}")
                            })),
                        }
                    }
                    _ => Ok(serde_json::json!({
                        "available": false,
                        "height": h,
                        "reason": "no quorum certificate at height"
                    })),
                },
            }
        },
        "aincore_verifyQuorumCertificate" => {
            let qc_value = params.get(0).ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Invalid params: [quorum_certificate]".into(),
            })?;
            let qc: consensus::qc::QuorumCertificate =
                serde_json::from_value(qc_value.clone()).map_err(|e| JsonRpcError {
                    code: -32602,
                    message: format!("Invalid quorum certificate: {e}"),
                })?;
            let validators = consensus::qc_producer::load_validator_set_v1(&data.storage)
                .ok_or_else(|| JsonRpcError {
                    code: -32000,
                    message: "validator set unavailable".into(),
                })?;
            match consensus::qc::verify_qc(&qc, &validators) {
                Ok(()) => Ok(serde_json::json!({ "valid": true })),
                Err(e) => Ok(serde_json::json!({ "valid": false, "error": e.to_string() })),
            }
        },
        "aincore_getDag" => {
            let consensus = data.consensus.read().unwrap_or_else(|e| e.into_inner());
            let dag = consensus.dag.lock().unwrap_or_else(|e| e.into_inner());
            let vertices: Vec<_> = dag.values().cloned().collect();
            Ok(serde_json::json!(vertices))
        },
        "aincore_getTransactionReceipt" => {
            if let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()) {
                let execution_receipt = stored_tx_receipt(&data.storage, tx_hash);
                if let Some(block_height) = data.storage.get_tx_block_height(tx_hash) {
                    let block_key = format!("block_{}", block_height);
                    let block_data = match data.storage.get(&block_key) {
                        Ok(Some(b)) => serde_json::from_str::<serde_json::Value>(&b).ok(),
                        _ => None,
                    };
                    let latest_height = data.storage.get_chain_height();
                    let confirmations = latest_height.saturating_sub(block_height);
                    let status = execution_receipt
                        .as_ref()
                        .and_then(|receipt| receipt.get("status"))
                        .and_then(|status| status.as_str())
                        .unwrap_or("confirmed");
                    Ok(serde_json::json!({
                        "tx_hash": tx_hash,
                        "block_height": block_height,
                        "confirmations": confirmations,
                        "status": status,
                        "execution_receipt": execution_receipt,
                        "block_hash": block_data.as_ref()
                            .and_then(|b| b.get("header"))
                            .and_then(|h| h.get("hash"))
                            .and_then(|h| h.as_str())
                            .unwrap_or("")
                    }))
                } else if let Some(receipt) = execution_receipt {
                    let status = receipt
                        .get("status")
                        .and_then(|status| status.as_str())
                        .unwrap_or("executed");
                    Ok(serde_json::json!({
                        "tx_hash": tx_hash,
                        "status": status,
                        "confirmations": 0,
                        "execution_receipt": receipt
                    }))
                } else {
                    let in_mempool = data
                        .mempool
                        .lock()
                        .map(|mempool| !mempool.is_empty())
                        .unwrap_or(false);
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
        "aincore_getTransaction" => {
            // params: [tx_hash]
            //
            // H-07 FIX: previously this acquired the consensus read lock,
            // then the DAG lock, then scanned every vertex hashing every
            // payload tx — O(N·M) under lock, which stalled block
            // production whenever a wallet polled for tx status.
            //
            // Block commit now writes `tx_index:{tx_hash} -> block_height`
            // atomically with the block (see StateDB::save_block_json),
            // so we can do O(1) → O(M_block) lookup with no consensus
            // locks held. We deliberately do NOT fall back to a full DAG
            // scan if the index miss: the index is authoritative once
            // a block is committed, so a miss means the tx is either
            // still pending (mempool path elsewhere) or genuinely
            // unknown. Forcing a scan-on-miss would let attackers
            // restore the original DoS by spamming unknown-hash queries.
            //
            // Wrapped in a closure so `?`-style early exits do not escape
            // the outer json_rpc_handler function signature.
            let lookup = || -> Option<serde_json::Value> {
                let target_hash = params.get(0).and_then(|v| v.as_str())?;
                let block_height = data.storage.get_tx_block_height(target_hash)?;
                let block_json = data
                    .storage
                    .get(&format!("block_{}", block_height))
                    .ok()
                    .flatten()?;
                let block: serde_json::Value = serde_json::from_str(&block_json).ok()?;
                let txs = block.get("transactions").and_then(|v| v.as_array())?;

                use sha2::{Digest, Sha256};
                for tx in txs {
                    let tx_str_owned: String;
                    let tx_bytes: &[u8] = if let Some(s) = tx.as_str() {
                        s.as_bytes()
                    } else {
                        tx_str_owned = tx.to_string();
                        tx_str_owned.as_bytes()
                    };
                    let mut hasher = Sha256::new();
                    hasher.update(tx_bytes);
                    let tx_hash = hex::encode(hasher.finalize());
                    if tx_hash == target_hash {
                        if let Some(s) = tx.as_str() {
                            return serde_json::from_str::<serde_json::Value>(s)
                                .ok()
                                .or_else(|| Some(serde_json::json!({ "raw": s })));
                        }
                        return Some(tx.clone());
                    }
                }
                None
            };

            if params.get(0).and_then(|v| v.as_str()).is_none() {
                Err(JsonRpcError { code: -32602, message: "Invalid params".into() })
            } else {
                Ok(lookup().unwrap_or(serde_json::Value::Null))
            }
        },
        "aincore_getBlocks" => {
            // params: [limit]  OR  [limit, start_height]
            //
            // Phase 3.5 / H-03 fix: bridge backlog could silently skip older
            // finalized blocks. Optional `start_height` lets callers request
            // a specific range. Backward compatible.
            let limit = params.get(0).and_then(|v| v.as_u64()).unwrap_or(10);

            if limit > MAX_LIMIT {
                return HttpResponse::BadRequest().json(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: format!("Limit too large: {} exceeds maximum {}", limit, MAX_LIMIT),
                    }),
                    id: req.id.clone(),
                });
            }

            let start_height_param = params.get(1).and_then(|v| v.as_u64());

            let latest_height: u64 = match data.storage.get("latest_height") {
                Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
                _ => 0,
            };

            let mut blocks = Vec::new();
            match start_height_param {
                Some(start_height) if start_height > 0 && start_height <= latest_height => {
                    let end_height = std::cmp::min(
                        start_height.saturating_add(limit).saturating_sub(1),
                        latest_height,
                    );
                    println!(
                        "🔍 [API] getBlocks range: {}..={} (latest={})",
                        start_height, end_height, latest_height
                    );
                    for i in start_height..=end_height {
                        let key = format!("block_{}", i);
                        if let Ok(Some(block_json)) = data.storage.get(&key) {
                            if let Ok(block_obj) =
                                serde_json::from_str::<serde_json::Value>(&block_json)
                            {
                                blocks.push(block_obj);
                            }
                        }
                    }
                }
                _ => {
                    println!("🔍 [API] getBlocks latest: head={} limit={}", latest_height, limit);
                    let start_index = latest_height.saturating_sub(limit);
                    for i in (start_index..=latest_height).rev() {
                        let key = format!("block_{}", i);
                        if let Ok(Some(block_json)) = data.storage.get(&key) {
                            if let Ok(block_obj) =
                                serde_json::from_str::<serde_json::Value>(&block_json)
                            {
                                blocks.push(block_obj);
                            }
                        }
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
        _ => Err(JsonRpcError { code: -32601, message: "Method not found".into() }),
    };

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

async fn metrics_handler() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(crate::metrics::gather_metrics())
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
) -> std::io::Result<()> {
    println!("🌐 Starting REST API server on port {}...", api_port);

    let app_state = web::Data::new(AppState {
        consensus,
        peers,
        mempool,
        storage,
    });

    // Rate limiter: 100 requests per second per IP
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(100)
        .burst_size(200)
        .finish()
        .unwrap();

    // gunakan tokio::task::LocalSet agar runtime single-thread tidak butuh Send
    let local = tokio::task::LocalSet::new();
    local
        .run_until(
            HttpServer::new(move || {
                use actix_cors::Cors;
                let cors = if permissive_cors_enabled() {
                    Cors::permissive()
                } else {
                    Cors::default()
                        .allowed_origin("http://localhost:3000")
                        .allowed_origin("http://127.0.0.1:3000")
                        .allowed_origin("http://localhost:5173")
                        .allowed_origin("http://127.0.0.1:5173")
                        .allow_any_header()
                        .allowed_methods(vec!["POST", "GET"])
                };

                App::new()
                    .wrap(cors)
                    .wrap(Governor::new(&governor_conf))
                    .wrap(Logger::default())
                    .app_data(app_state.clone())
                    .route("/health", web::get().to(health))
                    .route("/metrics", web::get().to(metrics_handler))
                    .route("/rpc", web::post().to(json_rpc_handler))
            })
            .bind(("0.0.0.0", api_port))?
            .run(),
        )
        .await
}
