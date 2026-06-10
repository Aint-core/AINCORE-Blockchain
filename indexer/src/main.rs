use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, sleep};

use log::{error, info};
use move_core_types::account_address::AccountAddress;
use std::env;

fn get_rpc_url() -> String {
    env::var("NODE_RPC_URL").unwrap_or_else(|_| "http://localhost:8002/rpc".to_string())
}
const DB_PATH: &str = "indexer.db";
const DEFAULT_INDEXER_BATCH_SIZE: u64 = 500;
const MAX_INDEXER_BATCH_SIZE: u64 = 2_000;
const DEFAULT_INDEXER_BOOTSTRAP_BACKFILL: u64 = 5_000;

fn indexer_batch_size() -> u64 {
    env::var("AINCORE_INDEXER_BATCH_SIZE")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(1, MAX_INDEXER_BATCH_SIZE))
        .unwrap_or(DEFAULT_INDEXER_BATCH_SIZE)
}

fn indexer_bootstrap_backfill() -> Option<u64> {
    env::var("AINCORE_INDEXER_BOOTSTRAP_BACKFILL")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.min(1_000_000))
}

fn permissive_cors_enabled() -> bool {
    env::var("AINCORE_PERMISSIVE_CORS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn decode_transfer(payload: &str) -> (Option<String>, u64) {
    let hex_payload = payload.trim_start_matches("0x");
    let bytes = match hex::decode(hex_payload) {
        Ok(bytes) => bytes,
        Err(_) => return (None, 0),
    };

    let tx_payload = match bcs::from_bytes::<vm_move::TransactionPayload>(&bytes) {
        Ok(payload) => payload,
        Err(_) => return (None, 0),
    };

    let vm_move::TransactionPayload::EntryFunction(call) = tx_payload else {
        return (None, 0);
    };

    let system_address = AccountAddress::from_hex_literal("0x1").expect("valid system address");
    if call.module.address() != &system_address
        || call.module.name().as_str() != "coin"
        || call.function != "transfer"
        || call.args.len() < 3
    {
        return (None, 0);
    }

    let receiver =
        bcs::from_bytes::<move_core_types::account_address::AccountAddress>(&call.args[1])
            .ok()
            .map(|addr| addr.to_string());
    let amount_u128 = bcs::from_bytes::<u128>(&call.args[2]).unwrap_or(0);
    let amount = u64::try_from(amount_u128).unwrap_or(u64::MAX);
    (receiver, amount)
}

fn tx_hash_hex(raw_tx: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(raw_tx.as_bytes());
    hex::encode(hasher.finalize())
}

fn canonical_asset_id(asset: &str) -> String {
    match asset.trim().to_ascii_uppercase().as_str() {
        "AIN" => "0x1::staking::AincoreCoin".to_string(),
        "WBTC" => "0x1::wbtc::WBTC".to_string(),
        other => {
            if other.starts_with("0X") {
                asset.trim().replacen("0X", "0x", 1)
            } else {
                asset.trim().to_string()
            }
        }
    }
}

fn token_decimals(token: &str) -> i32 {
    let canonical = canonical_asset_id(token);
    match canonical.as_str() {
        "0x1::staking::AincoreCoin" => 18,
        "0x1::wbtc::WBTC" => 8,
        _ => 0,
    }
}

fn amount_to_display_units(raw_amount: &str, token: &str) -> Option<f64> {
    let amount = raw_amount.parse::<f64>().ok()?;
    if amount < 0.0 {
        return None;
    }
    Some(amount / 10_f64.powi(token_decimals(token)))
}

fn clean_market_float(value: f64) -> f64 {
    if !value.is_finite() || value.abs() < f64::EPSILON {
        0.0
    } else {
        value
    }
}

fn normalize_timestamp_secs(timestamp: u64) -> u64 {
    if timestamp >= 1_000_000_000_000 {
        timestamp / 1000
    } else {
        timestamp
    }
}

fn value_to_u64(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
}

fn value_to_text(value: Option<&serde_json::Value>) -> Option<String> {
    value.and_then(|v| v.as_str().map(|text| text.to_string()))
}

#[derive(Clone, Debug)]
struct DexTradeRecord {
    tx_hash: String,
    pool_addr: String,
    function: String,
    token_x: String,
    token_y: String,
    token_in: String,
    token_out: String,
    amount_in: String,
    amount_out: String,
    block_height: u64,
    timestamp: u64,
    sender: String,
}

#[derive(Clone, Debug)]
struct TradePoint {
    timestamp: u64,
    price: f64,
    volume_base: f64,
    volume_quote: f64,
}

#[derive(Serialize)]
struct OhlcCandle {
    time: u64,
    open: f64,
    high: f64,
    low: f64,
    close: f64,
    volume: f64,
}

#[derive(Serialize)]
struct DexPairSummary {
    base_token: String,
    quote_token: String,
    last_price: f64,
    price_change_24h_pct: f64,
    volume_base_24h: f64,
    volume_quote_24h: f64,
    trades_24h: u64,
    high_24h: f64,
    low_24h: f64,
    first_trade_at: u64,
    last_trade_at: u64,
}

#[derive(Serialize)]
struct DexMarketSummary {
    token_x: String,
    token_y: String,
    pool_addr: String,
    last_price: f64,
    price_change_24h_pct: f64,
    volume_x_24h: f64,
    volume_y_24h: f64,
    trades_24h: u64,
    last_trade_at: u64,
}

fn dex_trade_from_receipt(
    tx_hash: &str,
    block_height: u64,
    timestamp: u64,
    sender: &str,
    receipt: &serde_json::Value,
) -> Option<DexTradeRecord> {
    let execution_receipt = receipt.get("execution_receipt")?;
    if execution_receipt.get("status")?.as_str()? != "success" {
        return None;
    }
    let metadata = execution_receipt.get("metadata")?;
    if metadata.get("kind")?.as_str()? != "dex" {
        return None;
    }

    let function = metadata.get("function")?.as_str()?.to_string();
    if function != "swap_x_to_y" && function != "swap_y_to_x" {
        return None;
    }

    let type_args = metadata.get("type_args")?.as_array()?;
    let token_x = value_to_text(type_args.first()).unwrap_or_default();
    let token_y = value_to_text(type_args.get(1)).unwrap_or_default();
    let token_in = value_to_text(metadata.get("token_in"))?;
    let token_out = value_to_text(metadata.get("token_out"))?;
    let amount_in = value_to_text(metadata.get("amount_in"))?;
    let amount_out = value_to_text(metadata.get("actual_amount_out"))?;
    let pool_addr = value_to_text(metadata.get("pool_addr"))?;

    Some(DexTradeRecord {
        tx_hash: tx_hash.to_string(),
        pool_addr,
        function,
        token_x,
        token_y,
        token_in,
        token_out,
        amount_in,
        amount_out,
        block_height,
        timestamp: normalize_timestamp_secs(timestamp),
        sender: sender.to_string(),
    })
}

fn trade_point_for_pair(
    trade: &DexTradeRecord,
    base_token: &str,
    quote_token: &str,
) -> Option<TradePoint> {
    let amount_in = amount_to_display_units(&trade.amount_in, &trade.token_in)?;
    let amount_out = amount_to_display_units(&trade.amount_out, &trade.token_out)?;
    if amount_in <= 0.0 || amount_out <= 0.0 {
        return None;
    }

    if trade.token_in == base_token && trade.token_out == quote_token {
        Some(TradePoint {
            timestamp: trade.timestamp,
            price: amount_out / amount_in,
            volume_base: amount_in,
            volume_quote: amount_out,
        })
    } else if trade.token_in == quote_token && trade.token_out == base_token {
        Some(TradePoint {
            timestamp: trade.timestamp,
            price: amount_in / amount_out,
            volume_base: amount_out,
            volume_quote: amount_in,
        })
    } else {
        None
    }
}

fn build_ohlc(points: &[TradePoint], resolution_minutes: u64) -> Vec<OhlcCandle> {
    if points.is_empty() || resolution_minutes == 0 {
        return Vec::new();
    }

    let bucket_size = resolution_minutes * 60;
    let mut candles = Vec::new();
    let mut current_bucket = 0u64;
    let mut current: Option<OhlcCandle> = None;

    for point in points {
        let bucket = (point.timestamp / bucket_size) * bucket_size;
        match &mut current {
            Some(candle) if bucket == current_bucket => {
                candle.high = candle.high.max(point.price);
                candle.low = candle.low.min(point.price);
                candle.close = point.price;
                candle.volume += point.volume_base;
            }
            Some(_) => {
                if let Some(finished) = current.take() {
                    candles.push(finished);
                }
                current_bucket = bucket;
                current = Some(OhlcCandle {
                    time: bucket,
                    open: clean_market_float(point.price),
                    high: clean_market_float(point.price),
                    low: clean_market_float(point.price),
                    close: clean_market_float(point.price),
                    volume: clean_market_float(point.volume_base),
                });
            }
            None => {
                current_bucket = bucket;
                current = Some(OhlcCandle {
                    time: bucket,
                    open: clean_market_float(point.price),
                    high: clean_market_float(point.price),
                    low: clean_market_float(point.price),
                    close: clean_market_float(point.price),
                    volume: clean_market_float(point.volume_base),
                });
            }
        }
    }

    if let Some(finished) = current {
        candles.push(finished);
    }

    candles
}

fn build_pair_summary(
    base_token: &str,
    quote_token: &str,
    points: &[TradePoint],
    now_ts: u64,
) -> Option<DexPairSummary> {
    let first = points.first()?;
    let last = points.last()?;
    let cutoff = now_ts.saturating_sub(24 * 60 * 60);
    let recent: Vec<&TradePoint> = points
        .iter()
        .filter(|point| point.timestamp >= cutoff)
        .collect();
    let recent_first = recent.first().copied().unwrap_or(last);
    let recent_last = recent.last().copied().unwrap_or(last);
    let volume_base_24h = recent.iter().map(|point| point.volume_base).sum::<f64>();
    let volume_quote_24h = recent.iter().map(|point| point.volume_quote).sum::<f64>();
    let trades_24h = recent.len() as u64;
    let high_24h = recent
        .iter()
        .map(|point| point.price)
        .reduce(f64::max)
        .unwrap_or(last.price);
    let low_24h = recent
        .iter()
        .map(|point| point.price)
        .reduce(f64::min)
        .unwrap_or(last.price);
    let price_change_24h_pct = if recent_first.price > 0.0 {
        ((recent_last.price - recent_first.price) / recent_first.price) * 100.0
    } else {
        0.0
    };

    Some(DexPairSummary {
        base_token: base_token.to_string(),
        quote_token: quote_token.to_string(),
        last_price: clean_market_float(last.price),
        price_change_24h_pct: clean_market_float(price_change_24h_pct),
        volume_base_24h: clean_market_float(volume_base_24h),
        volume_quote_24h: clean_market_float(volume_quote_24h),
        trades_24h,
        high_24h: clean_market_float(high_24h),
        low_24h: clean_market_float(low_24h),
        first_trade_at: first.timestamp,
        last_trade_at: last.timestamp,
    })
}

fn market_summary_for_trades(
    token_x: &str,
    token_y: &str,
    pool_addr: &str,
    trades: &[DexTradeRecord],
    now_ts: u64,
) -> Option<DexMarketSummary> {
    let points: Vec<TradePoint> = trades
        .iter()
        .filter_map(|trade| trade_point_for_pair(trade, token_x, token_y))
        .collect();
    let summary = build_pair_summary(token_x, token_y, &points, now_ts)?;

    Some(DexMarketSummary {
        token_x: token_x.to_string(),
        token_y: token_y.to_string(),
        pool_addr: pool_addr.to_string(),
        last_price: clean_market_float(summary.last_price),
        price_change_24h_pct: clean_market_float(summary.price_change_24h_pct),
        volume_x_24h: clean_market_float(summary.volume_base_24h),
        volume_y_24h: clean_market_float(summary.volume_quote_24h),
        trades_24h: summary.trades_24h,
        last_trade_at: summary.last_trade_at,
    })
}

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

    conn.execute(
        "CREATE TABLE IF NOT EXISTS dex_trades (
            tx_hash TEXT PRIMARY KEY,
            pool_addr TEXT NOT NULL,
            function TEXT NOT NULL,
            token_x TEXT NOT NULL,
            token_y TEXT NOT NULL,
            token_in TEXT NOT NULL,
            token_out TEXT NOT NULL,
            amount_in TEXT NOT NULL,
            amount_out TEXT NOT NULL,
            block_height INTEGER NOT NULL,
            timestamp INTEGER NOT NULL,
            sender TEXT NOT NULL DEFAULT ''
        )",
        [],
    )?;

    // Migration: add sender column to existing dex_trades tables that pre-date
    // this column. SQLite ALTER TABLE ADD COLUMN is idempotent-via-error: we
    // ignore the "duplicate column" error path.
    let _ = conn.execute(
        "ALTER TABLE dex_trades ADD COLUMN sender TEXT NOT NULL DEFAULT ''",
        [],
    );

    // Backfill sender from transactions.sender for any historical dex_trades
    // rows that landed before the column existed. Cheap one-pass join.
    let _ = conn.execute(
        "UPDATE dex_trades \
         SET sender = (SELECT sender FROM transactions WHERE transactions.hash = dex_trades.tx_hash) \
         WHERE sender = '' AND EXISTS (SELECT 1 FROM transactions WHERE transactions.hash = dex_trades.tx_hash)",
        [],
    );

    // Index for fast sender filtering
    let _ = conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_dex_trades_sender ON dex_trades(sender)",
        [],
    );

    Ok(conn)
}

fn get_last_indexed_height(conn: &Connection) -> u64 {
    let stmt = conn
        .prepare("SELECT value FROM state WHERE key = 'last_height'")
        .ok();
    if let Some(mut s) = stmt {
        let mut rows = s.query([]).ok();
        if let Some(rows) = rows.as_mut()
            && let Ok(Some(row)) = rows.next()
        {
            let s: String = row.get(0).unwrap_or("0".to_string());
            return s.parse::<u64>().unwrap_or(0);
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

async fn fetch_blocks(start: u64, limit: u64) -> Option<Vec<serde_json::Value>> {
    let client = reqwest::Client::new();
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "aincore_getBlocks".to_string(),
        params: vec![serde_json::json!(limit), serde_json::json!(start)],
        id: 1,
    };

    let res = client.post(get_rpc_url()).json(&req).send().await.ok()?;
    let json: RpcResponse<Vec<serde_json::Value>> = res.json().await.ok()?;
    json.result
}

async fn fetch_transaction_receipt(tx_hash: &str) -> Option<serde_json::Value> {
    let client = reqwest::Client::new();
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "aincore_getTransactionReceipt".to_string(),
        params: vec![serde_json::json!(tx_hash)],
        id: 1,
    };

    let res = client.post(get_rpc_url()).json(&req).send().await.ok()?;
    let json: RpcResponse<serde_json::Value> = res.json().await.ok()?;
    json.result
}

async fn fetch_latest_height() -> Option<u64> {
    let client = reqwest::Client::new();
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "aincore_getStatus".to_string(),
        params: vec![],
        id: 1,
    };

    let res = client.post(get_rpc_url()).json(&req).send().await.ok()?;
    let json: RpcResponse<serde_json::Value> = res.json().await.ok()?;
    let status = json.result?;
    value_to_u64(
        status
            .get("latest_height")
            .unwrap_or(&serde_json::Value::Null),
    )
}

fn index_transaction_row(conn: &Connection, tx_str: &str, height: u64, timestamp: u64) {
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(tx_str) {
        let sender = parsed["sender"].as_str().unwrap_or("");
        let payload = parsed["payload"].as_str().unwrap_or("");
        let hash = tx_hash_hex(tx_str);
        let (receiver, amount) = decode_transfer(payload);

        let _ = conn.execute(
            "INSERT OR IGNORE INTO transactions (hash, sender, receiver, amount, payload, block_height, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![hash, sender, receiver, amount, payload, height, normalize_timestamp_secs(timestamp)],
        );
    }
}

fn index_dex_trade_row(conn: &Connection, trade: &DexTradeRecord) {
    let _ = conn.execute(
        "INSERT OR REPLACE INTO dex_trades
         (tx_hash, pool_addr, function, token_x, token_y, token_in, token_out, amount_in, amount_out, block_height, timestamp, sender)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            trade.tx_hash,
            trade.pool_addr,
            trade.function,
            trade.token_x,
            trade.token_y,
            trade.token_in,
            trade.token_out,
            trade.amount_in,
            trade.amount_out,
            trade.block_height,
            trade.timestamp,
            trade.sender,
        ],
    );
}

// --- Indexing Logic ---
async fn indexer_loop(db: Arc<Mutex<Connection>>) {
    println!("🕵️ Indexer started...");
    let batch_size = indexer_batch_size();
    let bootstrap_backfill =
        indexer_bootstrap_backfill().unwrap_or(DEFAULT_INDEXER_BOOTSTRAP_BACKFILL);
    if bootstrap_backfill > 0
        && let Some(latest_height) = fetch_latest_height().await
    {
        let last_height = db
            .lock()
            .map(|conn| get_last_indexed_height(&conn))
            .unwrap_or(0);
        if last_height == 0 && latest_height > bootstrap_backfill {
            let bootstrap_height = latest_height.saturating_sub(bootstrap_backfill);
            if let Ok(conn) = db.lock() {
                set_last_indexed_height(&conn, bootstrap_height);
                println!(
                    "⚡ Indexer bootstrap tail mode: latest={} backfill={} start={}",
                    latest_height,
                    bootstrap_backfill,
                    bootstrap_height.saturating_add(1)
                );
            }
        }
    }

    // Concurrency for receipt fetches inside a batch. RPC node tolerates 32 in-flight
    // without backpressure; raise if your node has more headroom.
    const RECEIPT_CONCURRENCY: usize = 32;

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

        let start_height = last_height.saturating_add(1);
        let mut indexed_any = false;

        // Pull lag metric for observability
        let latest_height_for_log = fetch_latest_height().await;

        if let Some(blocks) = fetch_blocks(start_height, batch_size).await {
            // Phase 1 — collect ALL (height, timestamp, hash, tx_str) tuples across the batch.
            //          This lets us fan-out receipt fetches in parallel below.
            #[derive(Clone)]
            struct PendingTx {
                height: u64,
                timestamp: u64,
                hash: String,
                tx_str: String,
            }
            let mut pending: Vec<PendingTx> = Vec::new();
            let mut max_height_in_batch = last_height;

            for block in &blocks {
                let height = block["header"]["height"].as_u64().unwrap_or(0);
                if height == 0 || height < start_height {
                    continue;
                }
                indexed_any = true;
                if height > max_height_in_batch {
                    max_height_in_batch = height;
                }
                let timestamp = value_to_u64(&block["header"]["timestamp"]).unwrap_or(0);
                if let Some(txs) = block["transactions"].as_array() {
                    for tx in txs {
                        if let Some(tx_str) = tx.as_str() {
                            pending.push(PendingTx {
                                height,
                                timestamp,
                                hash: tx_hash_hex(tx_str),
                                tx_str: tx_str.to_string(),
                            });
                        }
                    }
                }
            }

            if let Some(latest) = latest_height_for_log {
                let lag = latest.saturating_sub(last_height);
                if lag > 100 || pending.len() > 50 {
                    println!(
                        "📥 Indexing batch: start={} end={} txs={} lag={}",
                        start_height,
                        max_height_in_batch,
                        pending.len(),
                        lag
                    );
                }
            }

            // Phase 2 — fan-out receipt fetches with bounded concurrency.
            use futures::stream::{self, StreamExt};
            let receipts: Vec<(PendingTx, Option<serde_json::Value>)> =
                stream::iter(pending.into_iter().map(|tx| {
                    let hash = tx.hash.clone();
                    async move {
                        let receipt = fetch_transaction_receipt(&hash).await;
                        (tx, receipt)
                    }
                }))
                .buffer_unordered(RECEIPT_CONCURRENCY)
                .collect()
                .await;

            // Phase 3 — single DB lock per batch, drain all writes serially.
            if let Ok(conn) = db.lock() {
                for (tx, receipt) in &receipts {
                    let sender = serde_json::from_str::<serde_json::Value>(&tx.tx_str)
                        .ok()
                        .and_then(|v| v.get("sender").and_then(|s| s.as_str()).map(String::from))
                        .unwrap_or_default();
                    index_transaction_row(&conn, &tx.tx_str, tx.height, tx.timestamp);
                    if let Some(receipt) = receipt
                        && let Some(trade) = dex_trade_from_receipt(
                            &tx.hash,
                            tx.height,
                            tx.timestamp,
                            &sender,
                            receipt,
                        )
                    {
                        index_dex_trade_row(&conn, &trade);
                    }
                }
                if max_height_in_batch > last_height {
                    set_last_indexed_height(&conn, max_height_in_batch);
                }
            }
        }

        if !indexed_any {
            sleep(Duration::from_secs(2)).await;
        }
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

#[derive(Serialize)]
struct DexTradeResponse {
    tx_hash: String,
    pool_addr: String,
    function: String,
    token_x: String,
    token_y: String,
    token_in: String,
    token_out: String,
    amount_in: String,
    amount_out: String,
    block_height: u64,
    timestamp: u64,
    sender: String,
}

#[derive(Deserialize)]
struct OhlcQuery {
    base: String,
    quote: String,
    resolution: Option<u64>,
    limit: Option<u64>,
}

#[derive(Deserialize)]
struct TradesQuery {
    base: String,
    quote: String,
    limit: Option<u64>,
    sender: Option<String>,
}

#[derive(Deserialize)]
struct PairSummaryQuery {
    base: String,
    quote: String,
}

#[derive(Deserialize)]
struct MarketsQuery {
    limit: Option<u64>,
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
         ORDER BY block_height DESC LIMIT 50",
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
    for t in rows.flatten() {
        txs.push(t);
    }

    HttpResponse::Ok().json(txs)
}

async fn get_dex_trades(
    data: web::Data<AppState>,
    query: web::Query<TradesQuery>,
) -> impl Responder {
    let base = canonical_asset_id(&query.base);
    let quote = canonical_asset_id(&query.quote);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let sender_filter = query.sender.as_ref().map(|s| s.trim().to_string());
    let conn = match data.db.lock() {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().body("DB Lock Error"),
    };

    let row_mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<DexTradeResponse> {
        Ok(DexTradeResponse {
            tx_hash: row.get(0)?,
            pool_addr: row.get(1)?,
            function: row.get(2)?,
            token_x: row.get(3)?,
            token_y: row.get(4)?,
            token_in: row.get(5)?,
            token_out: row.get(6)?,
            amount_in: row.get(7)?,
            amount_out: row.get(8)?,
            block_height: row.get(9)?,
            timestamp: row.get(10)?,
            sender: row.get::<_, String>(11).unwrap_or_default(),
        })
    };

    let trades_result: rusqlite::Result<Vec<DexTradeResponse>> = if let Some(sender) = sender_filter
    {
        let mut stmt = match conn.prepare(
            "SELECT tx_hash, pool_addr, function, token_x, token_y, token_in, token_out, amount_in, amount_out, block_height, timestamp, sender
             FROM dex_trades
             WHERE ((token_in = ?1 AND token_out = ?2) OR (token_in = ?2 AND token_out = ?1))
               AND sender = ?3
             ORDER BY timestamp DESC
             LIMIT ?4",
        ) {
            Ok(s) => s,
            Err(_) => return HttpResponse::InternalServerError().body("DB Query Error"),
        };
        let rows = stmt.query_map(params![base, quote, sender, limit], row_mapper);
        rows.map(|iter| iter.flatten().collect())
    } else {
        let mut stmt = match conn.prepare(
            "SELECT tx_hash, pool_addr, function, token_x, token_y, token_in, token_out, amount_in, amount_out, block_height, timestamp, sender
             FROM dex_trades
             WHERE (token_in = ?1 AND token_out = ?2) OR (token_in = ?2 AND token_out = ?1)
             ORDER BY timestamp DESC
             LIMIT ?3",
        ) {
            Ok(s) => s,
            Err(_) => return HttpResponse::InternalServerError().body("DB Query Error"),
        };
        let rows = stmt.query_map(params![base, quote, limit], row_mapper);
        rows.map(|iter| iter.flatten().collect())
    };

    match trades_result {
        Ok(trades) => HttpResponse::Ok().json(trades),
        Err(_) => HttpResponse::InternalServerError().body("DB Fetch Error"),
    }
}

async fn get_ohlc(data: web::Data<AppState>, query: web::Query<OhlcQuery>) -> impl Responder {
    let base = canonical_asset_id(&query.base);
    let quote = canonical_asset_id(&query.quote);
    let resolution = query.resolution.unwrap_or(15).clamp(1, 1440);
    let limit = query.limit.unwrap_or(5000).clamp(1, 20_000);
    let conn = match data.db.lock() {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().body("DB Lock Error"),
    };

    let mut stmt = match conn.prepare(
        "SELECT tx_hash, pool_addr, function, token_x, token_y, token_in, token_out, amount_in, amount_out, block_height, timestamp
         FROM dex_trades
         WHERE (token_in = ?1 AND token_out = ?2) OR (token_in = ?2 AND token_out = ?1)
         ORDER BY timestamp ASC
         LIMIT ?3",
    ) {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError().body("DB Query Error"),
    };

    let rows = match stmt.query_map(params![base, quote, limit], |row| {
        Ok(DexTradeRecord {
            tx_hash: row.get(0)?,
            pool_addr: row.get(1)?,
            function: row.get(2)?,
            token_x: row.get(3)?,
            token_y: row.get(4)?,
            token_in: row.get(5)?,
            token_out: row.get(6)?,
            amount_in: row.get(7)?,
            amount_out: row.get(8)?,
            block_height: row.get(9)?,
            timestamp: row.get(10)?,
            sender: String::new(),
        })
    }) {
        Ok(rows) => rows,
        Err(_) => return HttpResponse::InternalServerError().body("DB Fetch Error"),
    };

    let mut points = Vec::new();
    for row in rows.flatten() {
        if let Some(point) = trade_point_for_pair(&row, &base, &quote) {
            points.push(point);
        }
    }

    HttpResponse::Ok().json(build_ohlc(&points, resolution))
}

async fn get_pair_summary(
    data: web::Data<AppState>,
    query: web::Query<PairSummaryQuery>,
) -> impl Responder {
    let base = canonical_asset_id(&query.base);
    let quote = canonical_asset_id(&query.quote);
    let conn = match data.db.lock() {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().body("DB Lock Error"),
    };

    let mut stmt = match conn.prepare(
        "SELECT tx_hash, pool_addr, function, token_x, token_y, token_in, token_out, amount_in, amount_out, block_height, timestamp
         FROM dex_trades
         WHERE (token_in = ?1 AND token_out = ?2) OR (token_in = ?2 AND token_out = ?1)
         ORDER BY timestamp ASC",
    ) {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError().body("DB Query Error"),
    };

    let rows = match stmt.query_map(params![base, quote], |row| {
        Ok(DexTradeRecord {
            tx_hash: row.get(0)?,
            pool_addr: row.get(1)?,
            function: row.get(2)?,
            token_x: row.get(3)?,
            token_y: row.get(4)?,
            token_in: row.get(5)?,
            token_out: row.get(6)?,
            amount_in: row.get(7)?,
            amount_out: row.get(8)?,
            block_height: row.get(9)?,
            timestamp: row.get(10)?,
            sender: String::new(),
        })
    }) {
        Ok(rows) => rows,
        Err(_) => return HttpResponse::InternalServerError().body("DB Fetch Error"),
    };

    let points: Vec<TradePoint> = rows
        .flatten()
        .filter_map(|row| trade_point_for_pair(&row, &base, &quote))
        .collect();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    match build_pair_summary(&base, &quote, &points, now_ts) {
        Some(summary) => HttpResponse::Ok().json(summary),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "pair_not_found",
            "base_token": base,
            "quote_token": quote,
        })),
    }
}

async fn get_markets(data: web::Data<AppState>, query: web::Query<MarketsQuery>) -> impl Responder {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    let conn = match data.db.lock() {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().body("DB Lock Error"),
    };

    let mut stmt = match conn.prepare(
        "SELECT tx_hash, pool_addr, function, token_x, token_y, token_in, token_out, amount_in, amount_out, block_height, timestamp
         FROM dex_trades
         ORDER BY timestamp ASC",
    ) {
        Ok(s) => s,
        Err(_) => return HttpResponse::InternalServerError().body("DB Query Error"),
    };

    let rows = match stmt.query_map([], |row| {
        Ok(DexTradeRecord {
            tx_hash: row.get(0)?,
            pool_addr: row.get(1)?,
            function: row.get(2)?,
            token_x: row.get(3)?,
            token_y: row.get(4)?,
            token_in: row.get(5)?,
            token_out: row.get(6)?,
            amount_in: row.get(7)?,
            amount_out: row.get(8)?,
            block_height: row.get(9)?,
            timestamp: row.get(10)?,
            sender: String::new(),
        })
    }) {
        Ok(rows) => rows,
        Err(_) => return HttpResponse::InternalServerError().body("DB Fetch Error"),
    };

    let mut grouped: std::collections::BTreeMap<(String, String, String), Vec<DexTradeRecord>> =
        std::collections::BTreeMap::new();
    for row in rows.flatten() {
        grouped
            .entry((
                row.token_x.clone(),
                row.token_y.clone(),
                row.pool_addr.clone(),
            ))
            .or_default()
            .push(row);
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let mut markets: Vec<DexMarketSummary> = grouped
        .into_iter()
        .filter_map(|((token_x, token_y, pool_addr), trades)| {
            market_summary_for_trades(&token_x, &token_y, &pool_addr, &trades, now_ts)
        })
        .collect();

    markets.sort_by(|a, b| b.last_trade_at.cmp(&a.last_trade_at));
    markets.truncate(limit as usize);

    HttpResponse::Ok().json(markets)
}

async fn health() -> impl Responder {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    HttpResponse::Ok().json(serde_json::json!({
        "status": "OK",
        "timestamp": timestamp,
    }))
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
        let cors = if permissive_cors_enabled() {
            Cors::permissive()
        } else {
            Cors::default()
                .allowed_origin("http://localhost:3000")
                .allowed_origin("http://127.0.0.1:3000")
                .allowed_origin("http://localhost:5173")
                .allowed_origin("http://127.0.0.1:5173")
                .allow_any_header()
                .allowed_methods(vec!["GET"])
        };
        App::new()
            .wrap(cors)
            .app_data(app_state.clone())
            .route("/health", web::get().to(health))
            .route("/history/{address}", web::get().to(get_history))
            .route("/api/v1/trades", web::get().to(get_dex_trades))
            .route("/api/v1/ohlc", web::get().to(get_ohlc))
            .route("/api/v1/pair_summary", web::get().to(get_pair_summary))
            .route("/api/v1/markets", web::get().to(get_markets))
    })
    .bind(("0.0.0.0", 3001))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::{
        DexMarketSummary, DexTradeRecord, TradePoint, build_ohlc, build_pair_summary,
        decode_transfer, dex_trade_from_receipt, market_summary_for_trades, trade_point_for_pair,
    };
    use move_core_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{ModuleId, StructTag, TypeTag},
    };

    fn system_address() -> AccountAddress {
        AccountAddress::from_hex_literal("0x1").expect("valid system address")
    }

    fn aincore_coin_type() -> TypeTag {
        TypeTag::Struct(Box::new(StructTag {
            address: system_address(),
            module: Identifier::new("staking").expect("valid module"),
            name: Identifier::new("AincoreCoin").expect("valid coin"),
            type_params: vec![],
        }))
    }

    #[test]
    fn decode_transfer_reads_bcs_entry_function_payload() {
        let sender =
            AccountAddress::from_hex_literal("0x11111111111111111111111111111111").unwrap();
        let receiver =
            AccountAddress::from_hex_literal("0x22222222222222222222222222222222").unwrap();
        let payload = vm_move::TransactionPayload::EntryFunction(vm_move::EntryFunctionCall {
            module: ModuleId::new(system_address(), Identifier::new("coin").unwrap()),
            function: "transfer".to_string(),
            ty_args: vec![aincore_coin_type()],
            args: vec![
                bcs::to_bytes(&sender).unwrap(),
                bcs::to_bytes(&receiver).unwrap(),
                bcs::to_bytes(&1234u128).unwrap(),
            ],
        });

        let encoded = hex::encode(bcs::to_bytes(&payload).unwrap());
        let (decoded_receiver, decoded_amount) = decode_transfer(&encoded);

        assert_eq!(
            decoded_receiver.as_deref(),
            Some("22222222222222222222222222222222")
        );
        assert_eq!(decoded_amount, 1234);
    }

    #[test]
    fn decode_transfer_rejects_non_transfer_payloads() {
        let payload = vm_move::TransactionPayload::PublishModule(vec![vec![0xCA, 0xFE]]);
        let encoded = hex::encode(bcs::to_bytes(&payload).unwrap());

        let (decoded_receiver, decoded_amount) = decode_transfer(&encoded);

        assert!(decoded_receiver.is_none());
        assert_eq!(decoded_amount, 0);
    }

    #[test]
    fn dex_trade_from_receipt_reads_native_swap_metadata() {
        let receipt = serde_json::json!({
            "execution_receipt": {
                "status": "success",
                "metadata": {
                    "kind": "dex",
                    "function": "swap_x_to_y",
                    "pool_addr": "11111111111111111111111111111111",
                    "type_args": ["0x1::staking::AincoreCoin", "0x1::wbtc::WBTC"],
                    "token_in": "0x1::staking::AincoreCoin",
                    "token_out": "0x1::wbtc::WBTC",
                    "amount_in": "1000",
                    "actual_amount_out": "906"
                }
            }
        });

        let trade = dex_trade_from_receipt("tx1", 12, 1_715_000_000, "test-sender", &receipt)
            .expect("dex trade parsed");
        assert_eq!(trade.tx_hash, "tx1");
        assert_eq!(trade.function, "swap_x_to_y");
        assert_eq!(trade.token_in, "0x1::staking::AincoreCoin");
        assert_eq!(trade.token_out, "0x1::wbtc::WBTC");
        assert_eq!(trade.amount_in, "1000");
        assert_eq!(trade.amount_out, "906");
    }

    #[test]
    fn build_ohlc_aggregates_forward_and_reverse_trades() {
        let points = vec![
            TradePoint {
                timestamp: 1_715_000_000,
                price: 0.90,
                volume_base: 10.0,
                volume_quote: 9.0,
            },
            TradePoint {
                timestamp: 1_715_000_100,
                price: 0.95,
                volume_base: 5.0,
                volume_quote: 4.75,
            },
            TradePoint {
                timestamp: 1_715_000_950,
                price: 0.85,
                volume_base: 8.0,
                volume_quote: 6.8,
            },
        ];

        let candles = build_ohlc(&points, 15);
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].open, 0.90);
        assert_eq!(candles[0].high, 0.95);
        assert_eq!(candles[0].low, 0.90);
        assert_eq!(candles[0].close, 0.95);
        assert!((candles[0].volume - 15.0).abs() < f64::EPSILON);
        assert_eq!(candles[1].open, 0.85);
        assert_eq!(candles[1].close, 0.85);
    }

    #[test]
    fn build_pair_summary_tracks_last_price_and_24h_change() {
        let now_ts = 1_715_086_400;
        let points = vec![
            TradePoint {
                timestamp: now_ts - 23 * 60 * 60,
                price: 0.90,
                volume_base: 10.0,
                volume_quote: 9.0,
            },
            TradePoint {
                timestamp: now_ts - 60,
                price: 1.05,
                volume_base: 5.0,
                volume_quote: 5.25,
            },
        ];

        let summary = build_pair_summary(
            "0x1::staking::AincoreCoin",
            "0x1::wbtc::WBTC",
            &points,
            now_ts,
        )
        .expect("summary exists");
        assert_eq!(summary.last_price, 1.05);
        assert_eq!(summary.trades_24h, 2);
        assert!((summary.volume_base_24h - 15.0).abs() < f64::EPSILON);
        assert!((summary.volume_quote_24h - 14.25).abs() < f64::EPSILON);
        assert!(summary.price_change_24h_pct > 16.0 && summary.price_change_24h_pct < 17.0);
    }

    #[test]
    fn market_summary_uses_canonical_trade_direction() {
        let now_ts = 1_715_086_400;
        let trades = vec![
            DexTradeRecord {
                tx_hash: "tx1".into(),
                pool_addr: "pool1".into(),
                function: "swap_x_to_y".into(),
                token_x: "0x1::staking::AincoreCoin".into(),
                token_y: "0x1::wbtc::WBTC".into(),
                token_in: "0x1::staking::AincoreCoin".into(),
                token_out: "0x1::wbtc::WBTC".into(),
                amount_in: "10000000000000000000".into(),
                amount_out: "900000000".into(),
                block_height: 1,
                timestamp: now_ts - 3600,
                sender: "test-sender".into(),
            },
            DexTradeRecord {
                tx_hash: "tx2".into(),
                pool_addr: "pool1".into(),
                function: "swap_y_to_x".into(),
                token_x: "0x1::staking::AincoreCoin".into(),
                token_y: "0x1::wbtc::WBTC".into(),
                token_in: "0x1::wbtc::WBTC".into(),
                token_out: "0x1::staking::AincoreCoin".into(),
                amount_in: "400000000".into(),
                amount_out: "5000000000000000000".into(),
                block_height: 2,
                timestamp: now_ts - 60,
                sender: "test-sender".into(),
            },
        ];

        let market = market_summary_for_trades(
            "0x1::staking::AincoreCoin",
            "0x1::wbtc::WBTC",
            "pool1",
            &trades,
            now_ts,
        )
        .expect("market summary");
        assert_eq!(market.pool_addr, "pool1");
        assert_eq!(market.trades_24h, 2);
        assert!((market.last_price - 0.8).abs() < f64::EPSILON);
        assert!((market.volume_x_24h - 15.0).abs() < f64::EPSILON);
        assert!((market.volume_y_24h - 13.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dex_market_math_scales_native_token_decimals() {
        let now_ts = 1_715_086_400;
        let trade = DexTradeRecord {
            tx_hash: "tx-scaled".into(),
            pool_addr: "pool1".into(),
            function: "swap_x_to_y".into(),
            token_x: "0x1::staking::AincoreCoin".into(),
            token_y: "0x1::wbtc::WBTC".into(),
            token_in: "0x1::staking::AincoreCoin".into(),
            token_out: "0x1::wbtc::WBTC".into(),
            amount_in: "100000000000000000000".into(),
            amount_out: "9871580".into(),
            block_height: 1,
            timestamp: now_ts,
            sender: "test-sender".into(),
        };

        let point = trade_point_for_pair(&trade, "0x1::staking::AincoreCoin", "0x1::wbtc::WBTC")
            .expect("scaled trade point");
        assert!((point.volume_base - 100.0).abs() < 0.000001);
        assert!((point.volume_quote - 0.0987158).abs() < 0.00000001);
        assert!((point.price - 0.000987158).abs() < 0.000000001);

        let summary = build_pair_summary(
            "0x1::staking::AincoreCoin",
            "0x1::wbtc::WBTC",
            &[point],
            now_ts,
        )
        .expect("summary exists");
        assert!((summary.volume_base_24h - 100.0).abs() < 0.000001);
        assert!((summary.volume_quote_24h - 0.0987158).abs() < 0.00000001);
        assert!((summary.last_price - 0.000987158).abs() < 0.000000001);
    }

    #[test]
    fn dex_market_summary_never_emits_negative_zero() {
        let now_ts = 1_715_086_400;
        let points = vec![TradePoint {
            timestamp: now_ts - 25 * 60 * 60,
            price: 0.00098412,
            volume_base: 100.0,
            volume_quote: 0.098412,
        }];

        let summary = build_pair_summary(
            "0x1::staking::AincoreCoin",
            "0x1::wbtc::WBTC",
            &points,
            now_ts,
        )
        .expect("summary exists");
        assert_eq!(summary.trades_24h, 0);
        assert_eq!(summary.volume_base_24h.to_bits(), 0.0f64.to_bits());
        assert_eq!(summary.volume_quote_24h.to_bits(), 0.0f64.to_bits());
        assert_eq!(summary.price_change_24h_pct.to_bits(), 0.0f64.to_bits());

        let market = DexMarketSummary {
            token_x: "0x1::staking::AincoreCoin".into(),
            token_y: "0x1::wbtc::WBTC".into(),
            pool_addr: "pool1".into(),
            last_price: summary.last_price,
            price_change_24h_pct: summary.price_change_24h_pct,
            volume_x_24h: summary.volume_base_24h,
            volume_y_24h: summary.volume_quote_24h,
            trades_24h: summary.trades_24h,
            last_trade_at: summary.last_trade_at,
        };
        let json = serde_json::to_string(&market).expect("serializes");
        assert!(!json.contains("-0.0"));
    }
}
