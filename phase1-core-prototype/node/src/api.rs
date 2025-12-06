use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use network::PeerList;

// --- Shared State ---
use consensus::DagConsensus;
use storage::StateDB;

// --- Shared State ---
pub struct AppState {
    pub consensus: Arc<Mutex<DagConsensus>>,
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
                let mut mempool = data.mempool.lock().unwrap();
                mempool.add_transaction(tx_str.clone());
                // std::fs::write("debug_api.log", format!("Received TX: {}\n", tx_str)).ok();
                
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
        "aincore_nodeStatus" => {
             let consensus = data.consensus.lock().unwrap();
             let peers = data.peers.lock().unwrap();
             Ok(serde_json::json!({
                 "node_id": consensus.node_id,
                 "current_round": consensus.current_round,
                 "peers_count": peers.len(),
                 "latest_height": match data.storage.get("latest_height") {
                     Ok(Some(h)) => h,
                     _ => "0".to_string(),
                 },
             }))
        },
        "aincore_getDag" => {
            let consensus = data.consensus.lock().unwrap();
            let dag = consensus.dag.lock().unwrap();
            let vertices: Vec<_> = dag.values().cloned().collect();
            Ok(serde_json::json!(vertices))
        },
        "aincore_getTransaction" => {
            // params: [tx_hash]
            if let Some(target_hash) = params.get(0).and_then(|v| v.as_str()) {
                let consensus = data.consensus.lock().unwrap();
                let dag = consensus.dag.lock().unwrap();
                
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
            
            let latest_height: u64 = match data.storage.get("latest_height") {
                Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
                _ => 0,
            };
            
            println!("🔍 [API] aincore_getBlocks: latest_height = {}", latest_height);
            
            let mut blocks = Vec::new();
            let start = latest_height;
            let start_index = latest_height.saturating_sub(limit);
            
            for i in (start_index..=start).rev() {
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
    consensus: Arc<Mutex<DagConsensus>>,
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
                    .route("/rpc", web::post().to(json_rpc_handler))
            })
            .bind(("0.0.0.0", api_port))?
            .run(),
        )
        .await
}
