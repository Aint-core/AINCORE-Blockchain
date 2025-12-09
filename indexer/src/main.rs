use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

use log::{info, error};
use std::env;

fn get_rpc_url() -> String {
    env::var("NODE_RPC_URL").unwrap_or_else(|_| "http://localhost:8002/rpc".to_string())
}
const DB_PATH: &str = "indexer.db";

// --- Database Setup ---
fn init_db() -> Result<Connection, Box<dyn std::error::Error>> {
    let conn = Connection::open(DB_PATH)?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS transactions (
            hash TEXT PRIMARY KEY,
            sender TEXT NOT NULL,
            receiver TEXT,
            amount INTEGER,
            payload TEXT,
            block_height INTEGER,
            timestamp INTEGER
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT
        )",
        [],
    )?;

    Ok(conn)
}

fn get_last_indexed_height(conn: &Connection) -> u64 {
    let stmt = conn.prepare("SELECT value FROM state WHERE key = 'last_height'").ok();
    if let Some(mut s) = stmt {
        let mut rows = s.query([]).ok();
        if let Some(rows) = rows.as_mut() {
            if let Ok(Some(row)) = rows.next() {
                let s: String = row.get(0).unwrap_or("0".to_string());
                return s.parse::<u64>().unwrap_or(0);
            }
        }
    }
    0
}

fn set_last_indexed_height(conn: &Connection, height: u64) {
    if let Err(e) = conn.execute(
        "INSERT OR REPLACE INTO state (key, value) VALUES ('last_height', ?1)",
        params![height.to_string()],
    ) {
        error!("Failed to update last indexed height: {}", e);
    }
}

// --- RPC Client ---
#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: String,
    method: String,
    params: Vec<serde_json::Value>,
    id: u64,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
}

async fn fetch_blocks(_start: u64, limit: u64) -> Option<Vec<serde_json::Value>> {
    let client = reqwest::Client::new();
    // Note: aincore_getBlocks currently returns blocks in reverse order (latest first)
    // We might need to fetch one by one or handle the range logic carefully.
    // For simplicity, let's just fetch latest blocks and filter.
    // Ideally, we add `aincore_getBlockByHeight` to the node.
    // But for now, let's use `aincore_getBlocks` with a large limit and filter locally, 
    // or just rely on the fact that we are catching up.
    
    // Actually, let's just implement a loop that tries to get block N.
    // But we don't have getBlockByHeight exposed nicely yet (only getBlocks range).
    // Let's assume we fetch latest 10 and see if we missed any.
    // Better strategy for this MVP:
    // Just fetch `aincore_getBlocks` with limit 50.
    // Process them. If we see a block height > last_indexed, we process it.
    // Since blocks are immutable, we can just process any block we haven't seen.
    
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "aincore_getBlocks".to_string(),
        params: vec![serde_json::json!(limit)], // Fetch last N blocks
        id: 1,
    };

    let res = client.post(&get_rpc_url()).json(&req).send().await.ok()?;
    let json: RpcResponse<Vec<serde_json::Value>> = res.json().await.ok()?;
    json.result
}

// --- Indexing Logic ---
async fn indexer_loop(db: Arc<Mutex<Connection>>) {
    println!("🕵️ Indexer started...");
    loop {
        let last_height = {
            match db.lock() {
                Ok(conn) => get_last_indexed_height(&conn),
                Err(_) => {
                    eprintln!("❌ DB Lock Poisoned");
                    0 
                }
            }
        };

        // Fetch latest 20 blocks
        if let Some(blocks) = fetch_blocks(0, 20).await {
            // Blocks are returned latest first. Reverse to process in order.
            let mut blocks_rev = blocks;
            blocks_rev.reverse();

            for block in blocks_rev {
                let height = block["header"]["height"].as_u64().unwrap_or(0);
                if height > last_height {
                    println!("📥 Indexing Block #{}", height);
                    
                    // Process Transactions
                    if let Some(txs) = block["transactions"].as_array() {
                        let conn = match db.lock() {
                            Ok(c) => c,
                            Err(_) => continue,
                        };
                        for tx in txs {
                            let _hash = tx["hash"].as_str().unwrap_or("").to_string(); // We need hash in tx object
                            // Wait, the node returns raw tx strings in some endpoints, or objects in others.
                            // aincore_getBlocks returns block object with transactions list.
                            // In `main.rs`, `Block` struct has `transactions: Vec<String>`.
                            // So it's a list of JSON strings.
                            
                            if let Some(tx_str) = tx.as_str() {
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(tx_str) {
                                    let sender = parsed["sender"].as_str().unwrap_or("");
                                    let payload = parsed["payload"].as_str().unwrap_or("");
                                    
                                    // Calculate Hash (Naive)
                                    // use sha2::{Sha256, Digest}; // Unused for now
                                    
                                    let hash = format!("{}_{}", height, sender); // Temporary ID
                                    
                                    let mut receiver = None;
                                    let mut amount = 0;
                                    
                                    if payload.starts_with("transfer:") {
                                        let parts: Vec<&str> = payload.split(':').collect();
                                        if parts.len() == 3 {
                                            receiver = Some(parts[1].to_string());
                                            amount = parts[2].parse().unwrap_or(0);
                                        }
                                    }
                                    
                                    conn.execute(
                                        "INSERT OR IGNORE INTO transactions (hash, sender, receiver, amount, payload, block_height, timestamp)
                                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                                        params![hash, sender, receiver, amount, payload, height, 0],
                                    ).ok();
                                }
                            }
                        }
                        set_last_indexed_height(&conn, height);
                    }
                }
            }
        }

        sleep(Duration::from_secs(2)).await;
    }
}

// --- API Handlers ---
struct AppState {
    db: Arc<Mutex<Connection>>,
}

#[derive(Serialize)]
struct TxRecord {
    hash: String,
    sender: String,
    receiver: Option<String>,
    amount: Option<u64>,
    payload: String,
    block_height: u64,
}

async fn get_history(data: web::Data<AppState>, path: web::Path<String>) -> impl Responder {
    let address = path.into_inner();
    let conn = match data.db.lock() {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().body("DB Lock Error"),
    };
    
    let mut stmt = match conn.prepare(
        "SELECT hash, sender, receiver, amount, payload, block_height FROM transactions 
         WHERE sender = ?1 OR receiver = ?1 
         ORDER BY block_height DESC LIMIT 50"
    ) {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError().body("DB Query Error"),
    };
    
    let rows = match stmt.query_map(params![address], |row| {
        Ok(TxRecord {
            hash: row.get(0)?,
            sender: row.get(1)?,
            receiver: row.get(2)?,
            amount: row.get(3)?,
            payload: row.get(4)?,
            block_height: row.get(5)?,
        })
    }) {
        Ok(r) => r,
        Err(_) => return HttpResponse::InternalServerError().body("DB Fetch Error"),
    };

    let mut txs = Vec::new();
    for tx in rows {
        if let Ok(t) = tx {
            txs.push(t);
        }
    }

    HttpResponse::Ok().json(txs)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    info!("Starting AINCORE Indexer...");

    let db = match init_db() {
        Ok(c) => Arc::new(Mutex::new(c)),
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            return Ok(());
        }
    };
    
    // Spawn Indexer
    let db_clone = db.clone();
    tokio::spawn(async move {
        indexer_loop(db_clone).await;
    });

    println!("🚀 Indexer API running on port 3001");
    
    let app_state = web::Data::new(AppState { db });

    HttpServer::new(move || {
        let cors = Cors::permissive();
        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .route("/history/{address}", web::get().to(get_history))
    })
    .bind(("0.0.0.0", 3001))?
    .run()
    .await
}
