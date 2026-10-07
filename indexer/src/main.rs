use actix_cors::Cors;
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, web};
use rusqlite::{Connection, Result, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::time::{Duration, sleep};

use log::{error, info};
use move_core_types::account_address::AccountAddress;
use std::env;

fn get_rpc_url() -> String {
    env::var("NODE_RPC_URL").unwrap_or_else(|_| "http://localhost:8002/rpc".to_string())
}
const DB_PATH: &str = "indexer.db";

/// B265: the API's read connections, and so the most queries it runs at
/// once. In WAL mode a reader never waits on the indexing writer, nor the
/// writer on readers (one connection, behind one mutex, served both: a
/// client looping on a scan stalled the API and the indexed height).
const READERS: usize = 4;
/// B265: how long a request waits for its network group's turn and a
/// reader before it is answered busy.
const QUERY_WAIT: Duration = Duration::from_secs(2);
/// B265: network groups tracked for turns; idle ones are dropped past it.
const MAX_GATES: usize = 4096;
/// B265: how long a market summary is served from the cache: under a
/// block's 6.65 s, so it is never more than a block behind.
const SUMMARY_TTL: Duration = Duration::from_secs(5);
/// B265: the most summaries cached (the keys are request parameters).
const MAX_SUMMARIES: usize = 1024;
/// B265: the trailing window of a market summary.
const DAY_SECS: u64 = 24 * 60 * 60;
/// The most markets one request lists.
const MAX_MARKETS: u64 = 500;
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

fn build_pair_summary<P: std::borrow::Borrow<TradePoint>>(
    base_token: &str,
    quote_token: &str,
    points: impl IntoIterator<Item = P>,
    now_ts: u64,
) -> Option<DexPairSummary> {
    // B265: one pass that keeps only the sums, so the points can be
    // streamed from the database (every trade was loaded at once).
    let cutoff = now_ts.saturating_sub(DAY_SECS);
    let mut first: Option<TradePoint> = None;
    let mut last: Option<TradePoint> = None;
    let mut recent_first: Option<TradePoint> = None;
    let mut recent_last: Option<TradePoint> = None;
    let mut volume_base_24h = 0.0;
    let mut volume_quote_24h = 0.0;
    let mut trades_24h = 0u64;
    let mut high_24h: Option<f64> = None;
    let mut low_24h: Option<f64> = None;
    for point in points {
        let point = point.borrow();
        if first.is_none() {
            first = Some(point.clone());
        }
        if point.timestamp >= cutoff {
            if recent_first.is_none() {
                recent_first = Some(point.clone());
            }
            recent_last = Some(point.clone());
            volume_base_24h += point.volume_base;
            volume_quote_24h += point.volume_quote;
            trades_24h += 1;
            high_24h = Some(high_24h.map_or(point.price, |high| high.max(point.price)));
            low_24h = Some(low_24h.map_or(point.price, |low| low.min(point.price)));
        }
        last = Some(point.clone());
    }
    let first = first?;
    let last = last?;
    let recent_first = recent_first.unwrap_or_else(|| last.clone());
    let recent_last = recent_last.unwrap_or_else(|| last.clone());
    let high_24h = high_24h.unwrap_or(last.price);
    let low_24h = low_24h.unwrap_or(last.price);
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

fn market_summary<P: std::borrow::Borrow<TradePoint>>(
    token_x: &str,
    token_y: &str,
    pool_addr: &str,
    points: impl IntoIterator<Item = P>,
    now_ts: u64,
) -> Option<DexMarketSummary> {
    let summary = build_pair_summary(token_x, token_y, points, now_ts)?;

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

/// B265: the points a summary reads, for the summary every point gives:
/// the first (when it is before the window), the window's, and the last
/// (when the window is empty).
fn day_points(
    first: Option<TradePoint>,
    window: impl Iterator<Item = TradePoint>,
    mut last: impl Iterator<Item = TradePoint>,
    cutoff: u64,
) -> impl Iterator<Item = TradePoint> {
    let mut window = window.peekable();
    let tail = if window.peek().is_none() {
        last.next()
    } else {
        None
    };
    first
        .filter(|point| point.timestamp < cutoff)
        .into_iter()
        .chain(window)
        .chain(tail)
}

// --- Database Setup ---
fn init_db() -> Result<Connection, Box<dyn std::error::Error>> {
    let conn = Connection::open(DB_PATH)?;
    prepare_db(&conn)?;
    Ok(conn)
}

/// The schema, its indexes and its journal (B265).
fn prepare_db(conn: &Connection) -> rusqlite::Result<()> {
    // B265: WAL, so the API's readers and the indexing writer never wait
    // on each other.
    conn.query_row("PRAGMA journal_mode = WAL", [], |row| {
        row.get::<_, String>(0)
    })?;
    conn.busy_timeout(Duration::from_secs(5))?;

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

    // B265: every API query is a search of one of these (none had an
    // index but the sender's, so each request scanned a whole table).
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_tx_sender_height ON transactions(sender, block_height);
         CREATE INDEX IF NOT EXISTS idx_tx_receiver_height ON transactions(receiver, block_height);
         CREATE INDEX IF NOT EXISTS idx_dex_pair_time ON dex_trades(token_in, token_out, timestamp);
         CREATE INDEX IF NOT EXISTS idx_dex_sender_time ON dex_trades(sender, timestamp);
         CREATE INDEX IF NOT EXISTS idx_dex_pool_time ON dex_trades(pool_addr, token_x, token_y, timestamp);
         DROP INDEX IF EXISTS idx_dex_trades_sender;
         CREATE TABLE IF NOT EXISTS dex_pools (
             token_x TEXT NOT NULL,
             token_y TEXT NOT NULL,
             pool_addr TEXT NOT NULL,
             last_trade_at INTEGER NOT NULL,
             PRIMARY KEY (token_x, token_y, pool_addr)
         );
         CREATE INDEX IF NOT EXISTS idx_dex_pools_last ON dex_pools(last_trade_at);",
    )?;
    // B265: the pools of a database that predates `dex_pools`, once.
    let has_pools: bool = conn.query_row("SELECT EXISTS (SELECT 1 FROM dex_pools)", [], |row| {
        row.get(0)
    })?;
    if !has_pools {
        conn.execute(
            "INSERT INTO dex_pools (token_x, token_y, pool_addr, last_trade_at)
             SELECT token_x, token_y, pool_addr, MAX(timestamp) FROM dex_trades
             GROUP BY token_x, token_y, pool_addr",
            [],
        )?;
    }

    Ok(())
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
    /// B233: the node's error, if it answered one (a busy heavy read).
    #[serde(default)]
    error: Option<serde_json::Value>,
}

/// B270: `Err` when the node did not answer (no connection, the call's time
/// out, an answer that is not JSON-RPC); `Ok(None)` when it answered an
/// error.
async fn fetch_blocks(
    start: u64,
    limit: u64,
) -> std::result::Result<Option<Vec<serde_json::Value>>, ()> {
    let client = http_client();
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "aincore_getBlocks".to_string(),
        params: vec![serde_json::json!(limit), serde_json::json!(start)],
        id: 1,
    };

    let res = client
        .post(get_rpc_url())
        .json(&req)
        .send()
        .await
        .map_err(|_| ())?;
    let json: RpcResponse<Vec<serde_json::Value>> = res.json().await.map_err(|_| ())?;
    Ok(json.result)
}

/// B270: the blocks the next read asks for: half as many after a read the
/// node did not answer (a batch's answer, up to 8 MiB, outlasts the call's
/// 30 s over a link under about 2.2 Mbit/s, and the same batch was asked
/// again whole for good), twice as many after one it answered, within
/// `1..=most`.
fn next_batch(current: u64, answered: bool, most: u64) -> u64 {
    if answered {
        current.saturating_mul(2).min(most)
    } else {
        (current / 2).max(1)
    }
}

/// A transaction of a fetched batch, waiting for its receipt.
#[derive(Clone)]
struct PendingTx {
    height: u64,
    timestamp: u64,
    hash: String,
    tx_str: String,
}

/// B242: what a batch indexes when the receipt of a transaction of block
/// `unread_at` could not be read: the rows of the blocks before it, and the
/// height to advance to (the block before it; the batch's last block when
/// every receipt was read).
fn complete_blocks<T>(
    receipts: &mut Vec<(PendingTx, T)>,
    unread_at: Option<u64>,
    max_height: u64,
) -> u64 {
    match unread_at {
        Some(height) => {
            receipts.retain(|(tx, _)| tx.height < height);
            height.saturating_sub(1)
        }
        None => max_height,
    }
}

/// B260: how long a call to the node may take before it is an error (a
/// choice: a heavy call waits up to 2 s for its turn, and a batch of blocks
/// is up to 8 MiB). The client had no timeout, so one half-open connection
/// stalled the indexer's one-at-a-time loop for good.
const NODE_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// B260: a client whose connects and calls end after `timeout`.
fn client_with_timeout(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(timeout)
        .timeout(timeout)
        .build()
        .expect("the HTTP client")
}

/// B242: one HTTP client for every call (a client a call opened a
/// connection a receipt).
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| client_with_timeout(NODE_CALL_TIMEOUT))
}

/// B233: a transaction's receipt (`None`: the node holds none), or why it
/// could not be read (a refused or busy call, the network). An error was
/// read as "no receipt", so the batch's DEX trades were skipped for good.
async fn fetch_transaction_receipt(tx_hash: &str) -> Result<Option<serde_json::Value>, String> {
    let client = http_client();
    let req = RpcRequest {
        jsonrpc: "2.0".to_string(),
        method: "aincore_getTransactionReceipt".to_string(),
        params: vec![serde_json::json!(tx_hash)],
        id: 1,
    };
    let res = client
        .post(get_rpc_url())
        .json(&req)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let json: RpcResponse<serde_json::Value> = res.json().await.map_err(|e| e.to_string())?;
    receipt_of(json)
}

/// B233: a receipt answer read: an error object is an error, a null result
/// is no receipt.
fn receipt_of(answer: RpcResponse<serde_json::Value>) -> Result<Option<serde_json::Value>, String> {
    match answer.error {
        Some(error) => Err(error.to_string()),
        None => Ok(answer.result.filter(|r| !r.is_null())),
    }
}

/// B233: tries of one receipt read before its batch is left for the next
/// loop, and the pause between them (choices: the node waits a heavy call
/// up to 2 s for a slot before it answers busy, B220).
const RECEIPT_TRIES: u32 = 3;
const RECEIPT_RETRY: Duration = Duration::from_millis(500);

/// `fetch_transaction_receipt`, tried `RECEIPT_TRIES` times.
async fn fetch_receipt_retried(tx_hash: &str) -> Result<Option<serde_json::Value>, String> {
    let mut last = String::new();
    for attempt in 0..RECEIPT_TRIES {
        if attempt > 0 {
            sleep(RECEIPT_RETRY).await;
        }
        match fetch_transaction_receipt(tx_hash).await {
            Ok(receipt) => return Ok(receipt),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn fetch_latest_height() -> Option<u64> {
    let client = http_client();
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
    // B265: the pool's newest trade, so the markets list reads pools, not
    // trades.
    let _ = conn.execute(
        "INSERT INTO dex_pools (token_x, token_y, pool_addr, last_trade_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (token_x, token_y, pool_addr)
         DO UPDATE SET last_trade_at = MAX(last_trade_at, excluded.last_trade_at)",
        params![
            trade.token_x,
            trade.token_y,
            trade.pool_addr,
            trade.timestamp
        ],
    );
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

    // B270: the blocks a read asks for (`next_batch`).
    let mut batch = batch_size;
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

        let fetched = fetch_blocks(start_height, batch).await;
        batch = next_batch(batch, fetched.is_ok(), batch_size);
        if let Ok(Some(blocks)) = fetched {
            // Phase 1 — collect ALL (height, timestamp, hash, tx_str) tuples across the batch.
            //          This lets us fan-out receipt fetches in parallel below.
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

            // Phase 2 — the receipts, one at a time, in block order (B233:
            // the node serves one heavy call per client). B242: the first
            // that cannot be read ends the batch there: the blocks before
            // its block are written and the height advances to the last of
            // them; its block is read again next loop (all-or-nothing, a
            // 500-block batch failed whole on one busy answer, and kept
            // failing under steady load).
            let mut receipts: Vec<(PendingTx, Option<serde_json::Value>)> = Vec::new();
            let mut unread_at: Option<u64> = None;
            for tx in pending {
                match fetch_receipt_retried(&tx.hash).await {
                    Ok(receipt) => receipts.push((tx, receipt)),
                    Err(e) => {
                        eprintln!(
                            "⚠️ Indexer: the receipt of {} (block {}) could not be read: {e}; indexing resumes at its block",
                            tx.hash, tx.height
                        );
                        unread_at = Some(tx.height);
                        break;
                    }
                }
            }
            let indexed_to = complete_blocks(&mut receipts, unread_at, max_height_in_batch);

            // Phase 3 — single DB lock per batch, drain all writes serially,
            // in one transaction with the height (B265).
            if let Ok(mut conn) = db.lock()
                && let Ok(conn) = conn.transaction()
            {
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
                if indexed_to > last_height {
                    set_last_indexed_height(&conn, indexed_to);
                }
                if let Err(e) = conn.commit() {
                    error!("Failed to commit the indexed batch: {}", e);
                }
            }
            if unread_at.is_some() {
                sleep(Duration::from_secs(2)).await;
            }
        }

        if !indexed_any {
            sleep(Duration::from_secs(2)).await;
        }
    }
}

// --- API Handlers ---

/// B265: the API's side of the database: read connections, the most
/// queries at once, one query in flight per network group, and summaries
/// cached for `SUMMARY_TTL`.
struct Reads {
    readers: Vec<Mutex<Connection>>,
    slots: Arc<Semaphore>,
    gates: Mutex<HashMap<IpAddr, Arc<Semaphore>>>,
    summaries: Mutex<HashMap<String, (Instant, u16, serde_json::Value)>>,
}

impl Reads {
    fn open(path: &str, readers: usize) -> rusqlite::Result<Self> {
        let readers = (0..readers)
            .map(|_| {
                let conn = Connection::open(path)?;
                conn.busy_timeout(Duration::from_secs(5))?;
                conn.pragma_update(None, "query_only", true)?;
                Ok(Mutex::new(conn))
            })
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(readers.len())),
            readers,
            gates: Mutex::default(),
            summaries: Mutex::default(),
        })
    }

    /// The turn of `group`: one query at a time.
    fn gate(&self, group: IpAddr) -> Arc<Semaphore> {
        let mut gates = self.gates.lock().unwrap_or_else(|e| e.into_inner());
        if !gates.contains_key(&group) && gates.len() >= MAX_GATES {
            gates.retain(|_, gate| Arc::strong_count(gate) > 1);
        }
        Arc::clone(
            gates
                .entry(group)
                .or_insert_with(|| Arc::new(Semaphore::new(1))),
        )
    }

    fn cached(&self, key: &str) -> Option<HttpResponse> {
        let (status, body) = self.fresh(key)?;
        Some(summary_response(status, body))
    }

    /// A summary cached under `key` less than `SUMMARY_TTL` ago.
    fn fresh(&self, key: &str) -> Option<(u16, serde_json::Value)> {
        let summaries = self.summaries.lock().unwrap_or_else(|e| e.into_inner());
        let (at, status, body) = summaries.get(key)?;
        (at.elapsed() < SUMMARY_TTL).then(|| (*status, body.clone()))
    }

    fn remember(&self, key: String, status: u16, body: &serde_json::Value) {
        let mut summaries = self.summaries.lock().unwrap_or_else(|e| e.into_inner());
        if summaries.len() >= MAX_SUMMARIES {
            summaries.retain(|_, (at, _, _)| at.elapsed() < SUMMARY_TTL);
        }
        if summaries.len() < MAX_SUMMARIES {
            summaries.insert(key, (Instant::now(), status, body.clone()));
        }
    }
}

fn summary_response(status: u16, body: serde_json::Value) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    HttpResponse::build(status).json(body)
}

/// B279: whose client-address header is believed: the proxies named in
/// `AINCORE_INDEXER_TRUSTED_PROXIES` (comma-separated addresses), for the
/// header named in `AINCORE_INDEXER_CLIENT_IP_HEADER` (e.g.
/// `X-Forwarded-For`). Behind a proxy every client was the proxy's group,
/// one query at a time for the whole public. The node's rule (B74, B266):
/// the last element of the header's last line, peers compared canonical.
#[derive(Clone, Default)]
struct ClientIp {
    header: Option<String>,
    trusted: Vec<IpAddr>,
}

impl ClientIp {
    fn from_env() -> Self {
        let header = env::var("AINCORE_INDEXER_CLIENT_IP_HEADER")
            .ok()
            .filter(|h| !h.trim().is_empty());
        let trusted = env::var("AINCORE_INDEXER_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|a| a.trim().parse::<IpAddr>().ok())
            .map(|a| a.to_canonical())
            .collect();
        Self { header, trusted }
    }

    /// The client of a request from `peer` with `headers`.
    fn address(&self, peer: IpAddr, headers: &actix_web::http::header::HeaderMap) -> IpAddr {
        let peer = peer.to_canonical();
        if !self.trusted.contains(&peer) {
            return peer;
        }
        self.header
            .as_deref()
            .and_then(|name| headers.get_all(name).last()?.to_str().ok())
            .and_then(|line| line.rsplit(',').next()?.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .unwrap_or(peer)
    }
}

/// B265: the network group a client is charged to: its /24 (IPv4) or /48
/// (IPv6), as the node groups heavy calls (B253).
fn net_group(client: IpAddr) -> IpAddr {
    match client.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            IpAddr::from([a, b, c, 0])
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            IpAddr::from([s[0], s[1], s[2], 0, 0, 0, 0, 0])
        }
    }
}

/// B265/B279: the group a request is charged to (`ClientIp`, `net_group`).
fn client_group(data: &AppState, req: &HttpRequest) -> IpAddr {
    let peer = req
        .peer_addr()
        .map_or(IpAddr::from([0u8, 0, 0, 0]), |addr| addr.ip());
    net_group(data.client_ip.address(peer, req.headers()))
}

/// B265: run `query` on a reader on `group`'s turn, off the server's
/// workers: one query in flight per group and `READERS` in all; a request
/// that gets neither within `QUERY_WAIT` is answered busy.
async fn read<T: Send + 'static>(
    reads: &Arc<Reads>,
    group: IpAddr,
    query: impl FnOnce(&Connection) -> T + Send + 'static,
) -> std::result::Result<T, HttpResponse> {
    let busy =
        || HttpResponse::ServiceUnavailable().json(serde_json::json!({ "error": "busy; retry" }));
    let deadline = tokio::time::Instant::now() + QUERY_WAIT;
    let gate = reads.gate(group);
    let Ok(Ok(turn)) = tokio::time::timeout_at(deadline, gate.acquire_owned()).await else {
        return Err(busy());
    };
    let slots = Arc::clone(&reads.slots);
    let Ok(Ok(slot)) = tokio::time::timeout_at(deadline, slots.acquire_owned()).await else {
        return Err(busy());
    };
    let reads = Arc::clone(reads);
    web::block(move || {
        let _held = (turn, slot);
        // A slot is held, so a reader is free.
        let conn = reads
            .readers
            .iter()
            .find_map(|reader| reader.try_lock().ok())
            .unwrap_or_else(|| reads.readers[0].lock().unwrap_or_else(|e| e.into_inner()));
        query(&conn)
    })
    .await
    .map_err(|_| HttpResponse::InternalServerError().body("DB Error"))
}

fn respond<T>(
    outcome: std::result::Result<rusqlite::Result<T>, HttpResponse>,
    ok: impl FnOnce(T) -> HttpResponse,
) -> HttpResponse {
    match outcome {
        Ok(Ok(value)) => ok(value),
        Ok(Err(_)) => HttpResponse::InternalServerError().body("DB Query Error"),
        Err(busy) => busy,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// B265: the columns a trade is read with (`trade_row`).
macro_rules! trade_cols {
    () => {
        "tx_hash, pool_addr, function, token_x, token_y, token_in, token_out, \
         amount_in, amount_out, block_height, timestamp, sender"
    };
}

/// B265: a pair's trades in both directions, merged by time: each direction
/// is a search of `idx_dex_pair_time` (an OR over the two scanned every
/// trade).
macro_rules! pair_trades {
    ($cond:literal, $order:literal) => {
        concat!(
            "SELECT ",
            trade_cols!(),
            " FROM dex_trades WHERE token_in = ?1 AND token_out = ?2",
            $cond,
            " UNION ALL SELECT ",
            trade_cols!(),
            " FROM dex_trades WHERE token_in = ?2 AND token_out = ?1",
            $cond,
            " ORDER BY timestamp ",
            $order
        )
    };
}

/// B265: one pool's trades by time, a search of `idx_dex_pool_time`.
macro_rules! pool_trades {
    ($cond:literal, $order:literal) => {
        concat!(
            "SELECT ",
            trade_cols!(),
            " FROM dex_trades WHERE pool_addr = ?1 AND token_x = ?2 AND token_y = ?3",
            $cond,
            " ORDER BY timestamp ",
            $order
        )
    };
}

const PAIR_FIRST_SQL: &str = pair_trades!("", "ASC");
const PAIR_WINDOW_SQL: &str = pair_trades!(" AND timestamp >= ?3", "ASC");
const PAIR_LAST_SQL: &str = pair_trades!("", "DESC");
const PAIR_LATEST_SQL: &str = concat!(pair_trades!("", "DESC"), " LIMIT ?3");
const SENDER_TRADES_SQL: &str = concat!(
    "SELECT ",
    trade_cols!(),
    " FROM dex_trades INDEXED BY idx_dex_sender_time WHERE sender = ?3 \
     AND ((token_in = ?1 AND token_out = ?2) OR (token_in = ?2 AND token_out = ?1)) \
     ORDER BY timestamp DESC LIMIT ?4"
);
const POOLS_SQL: &str =
    "SELECT token_x, token_y, pool_addr FROM dex_pools ORDER BY last_trade_at DESC LIMIT ?1";
const POOL_FIRST_SQL: &str = pool_trades!("", "ASC");
const POOL_WINDOW_SQL: &str = pool_trades!(" AND timestamp >= ?4", "ASC");
const POOL_LAST_SQL: &str = pool_trades!("", "DESC");
/// B265: an address's latest transactions, sent then received (the
/// received side leaves out what it sent itself), each a search of its
/// index (an OR over the two scanned every transaction).
const HISTORY_SQL: &str = "SELECT hash, sender, receiver, amount, payload, block_height \
     FROM transactions WHERE sender = ?1 \
     UNION ALL SELECT hash, sender, receiver, amount, payload, block_height \
     FROM transactions WHERE receiver = ?1 AND sender <> ?1 \
     ORDER BY block_height DESC LIMIT 50";

fn trade_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DexTradeRecord> {
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
        sender: row.get::<_, String>(11).unwrap_or_default(),
    })
}

fn history(conn: &Connection, address: &str) -> rusqlite::Result<Vec<TxRecord>> {
    let mut stmt = conn.prepare(HISTORY_SQL)?;
    let rows = stmt.query_map(params![address], |row| {
        Ok(TxRecord {
            hash: row.get(0)?,
            sender: row.get(1)?,
            receiver: row.get(2)?,
            amount: row.get(3)?,
            payload: row.get(4)?,
            block_height: row.get(5)?,
        })
    })?;
    Ok(rows.flatten().collect())
}

/// B265: a pair's summary from its first trade, its last day's, and its
/// last, in one read transaction: the summary every trade gave, from the
/// rows of one day.
fn pair_summary(
    conn: &Connection,
    base: &str,
    quote: &str,
    now_ts: u64,
) -> rusqlite::Result<Option<DexPairSummary>> {
    let cutoff = now_ts.saturating_sub(DAY_SECS);
    let snapshot = conn.unchecked_transaction()?;
    let point = |trade: DexTradeRecord| trade_point_for_pair(&trade, base, quote);
    let mut first = snapshot.prepare(PAIR_FIRST_SQL)?;
    let mut window = snapshot.prepare(PAIR_WINDOW_SQL)?;
    let mut last = snapshot.prepare(PAIR_LAST_SQL)?;
    let first = first
        .query_map(params![base, quote], trade_row)?
        .flatten()
        .find_map(point);
    let window = window
        .query_map(params![base, quote, cutoff], trade_row)?
        .flatten()
        .filter_map(point);
    let last = last
        .query_map(params![base, quote], trade_row)?
        .flatten()
        .filter_map(point);
    Ok(build_pair_summary(
        base,
        quote,
        day_points(first, window, last, cutoff),
        now_ts,
    ))
}

/// B265: the `limit` pools traded last, each summarized as `pair_summary`
/// does, from `dex_pools` and each pool's last day (every trade was read).
fn markets(conn: &Connection, limit: u64, now_ts: u64) -> rusqlite::Result<Vec<DexMarketSummary>> {
    let cutoff = now_ts.saturating_sub(DAY_SECS);
    let snapshot = conn.unchecked_transaction()?;
    let pools: Vec<(String, String, String)> = snapshot
        .prepare(POOLS_SQL)?
        .query_map(params![limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .flatten()
        .collect();
    let mut first = snapshot.prepare(POOL_FIRST_SQL)?;
    let mut window = snapshot.prepare(POOL_WINDOW_SQL)?;
    let mut last = snapshot.prepare(POOL_LAST_SQL)?;
    let mut markets = Vec::new();
    for (token_x, token_y, pool_addr) in pools {
        let point = |trade: DexTradeRecord| trade_point_for_pair(&trade, &token_x, &token_y);
        let at = params![pool_addr, token_x, token_y];
        let first = first.query_map(at, trade_row)?.flatten().find_map(point);
        let window = window
            .query_map(params![pool_addr, token_x, token_y, cutoff], trade_row)?
            .flatten()
            .filter_map(point);
        let last = last.query_map(at, trade_row)?.flatten().filter_map(point);
        if let Some(market) = market_summary(
            &token_x,
            &token_y,
            &pool_addr,
            day_points(first, window, last, cutoff),
            now_ts,
        ) {
            markets.push(market);
        }
    }
    markets.sort_by_key(|m| std::cmp::Reverse(m.last_trade_at));
    Ok(markets)
}

struct AppState {
    reads: Arc<Reads>,
    client_ip: ClientIp,
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

impl From<DexTradeRecord> for DexTradeResponse {
    fn from(trade: DexTradeRecord) -> Self {
        Self {
            tx_hash: trade.tx_hash,
            pool_addr: trade.pool_addr,
            function: trade.function,
            token_x: trade.token_x,
            token_y: trade.token_y,
            token_in: trade.token_in,
            token_out: trade.token_out,
            amount_in: trade.amount_in,
            amount_out: trade.amount_out,
            block_height: trade.block_height,
            timestamp: trade.timestamp,
            sender: trade.sender,
        }
    }
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

async fn get_history(
    data: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    let address = path.into_inner();
    let outcome = read(&data.reads, client_group(&data, &req), move |conn| {
        history(conn, &address)
    })
    .await;
    respond(outcome, |txs| HttpResponse::Ok().json(txs))
}

async fn get_dex_trades(
    data: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<TradesQuery>,
) -> impl Responder {
    let base = canonical_asset_id(&query.base);
    let quote = canonical_asset_id(&query.quote);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let sender_filter = query.sender.as_ref().map(|s| s.trim().to_string());
    let outcome = read(
        &data.reads,
        client_group(&data, &req),
        move |conn| -> rusqlite::Result<Vec<DexTradeResponse>> {
            let trades: Vec<DexTradeRecord> = match &sender_filter {
                Some(sender) => conn
                    .prepare(SENDER_TRADES_SQL)?
                    .query_map(params![base, quote, sender, limit], trade_row)?
                    .flatten()
                    .collect(),
                None => conn
                    .prepare(PAIR_LATEST_SQL)?
                    .query_map(params![base, quote, limit], trade_row)?
                    .flatten()
                    .collect(),
            };
            Ok(trades.into_iter().map(DexTradeResponse::from).collect())
        },
    )
    .await;
    respond(outcome, |trades| HttpResponse::Ok().json(trades))
}

async fn get_ohlc(
    data: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<OhlcQuery>,
) -> impl Responder {
    let base = canonical_asset_id(&query.base);
    let quote = canonical_asset_id(&query.quote);
    let resolution = query.resolution.unwrap_or(15).clamp(1, 1440);
    let limit = query.limit.unwrap_or(5000).clamp(1, 20_000);
    let outcome = read(
        &data.reads,
        client_group(&data, &req),
        move |conn| -> rusqlite::Result<Vec<OhlcCandle>> {
            // B265: the latest `limit` trades, oldest first (the earliest were
            // read, so a chart stopped at its first `limit` trades for good).
            let mut points: Vec<TradePoint> = conn
                .prepare(PAIR_LATEST_SQL)?
                .query_map(params![base, quote, limit], trade_row)?
                .flatten()
                .filter_map(|trade| trade_point_for_pair(&trade, &base, &quote))
                .collect();
            points.reverse();
            Ok(build_ohlc(&points, resolution))
        },
    )
    .await;
    respond(outcome, |candles| HttpResponse::Ok().json(candles))
}

async fn get_pair_summary(
    data: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<PairSummaryQuery>,
) -> impl Responder {
    let base = canonical_asset_id(&query.base);
    let quote = canonical_asset_id(&query.quote);
    let key = format!("pair\u{0}{base}\u{0}{quote}");
    if let Some(cached) = data.reads.cached(&key) {
        return cached;
    }
    let outcome = read(
        &data.reads,
        client_group(&data, &req),
        move |conn| -> rusqlite::Result<(u16, serde_json::Value)> {
            let summary = pair_summary(conn, &base, &quote, now_secs())?;
            Ok(match summary {
                Some(summary) => (200, serde_json::to_value(summary).unwrap_or_default()),
                None => (
                    404,
                    serde_json::json!({
                        "error": "pair_not_found",
                        "base_token": base,
                        "quote_token": quote,
                    }),
                ),
            })
        },
    )
    .await;
    respond(outcome, |(status, body)| {
        data.reads.remember(key, status, &body);
        summary_response(status, body)
    })
}

async fn get_markets(
    data: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<MarketsQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(50).clamp(1, MAX_MARKETS);
    // B280: one list, of the most markets any request may ask for, sliced
    // for each (a key per `limit` gave 500 keys: varying it skipped the
    // cache, and every request read a day of trades a pool).
    let key = "markets".to_string();
    let first = |body: serde_json::Value| match body {
        serde_json::Value::Array(all) => {
            serde_json::Value::Array(all.into_iter().take(limit as usize).collect())
        }
        other => other,
    };
    if let Some((status, body)) = data.reads.fresh(&key) {
        return summary_response(status, first(body));
    }
    let outcome = read(
        &data.reads,
        client_group(&data, &req),
        move |conn| -> rusqlite::Result<serde_json::Value> {
            let markets = markets(conn, MAX_MARKETS, now_secs())?;
            Ok(serde_json::to_value(markets).unwrap_or_default())
        },
    )
    .await;
    respond(outcome, |body| {
        data.reads.remember(key, 200, &body);
        summary_response(200, first(body))
    })
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
    // B265: the API reads on its own connections; `db` is the writer's.
    let reads = match Reads::open(DB_PATH, READERS) {
        Ok(reads) => Arc::new(reads),
        Err(e) => {
            error!("Failed to open the database for reading: {}", e);
            return Ok(());
        }
    };

    // Spawn Indexer
    let db_clone = db.clone();
    tokio::spawn(async move {
        indexer_loop(db_clone).await;
    });

    println!("🚀 Indexer API running on port 3001");

    let app_state = web::Data::new(AppState {
        reads,
        client_ip: ClientIp::from_env(),
    });

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
        PendingTx, RpcResponse, client_with_timeout, complete_blocks, next_batch, receipt_of,
    };

    /// B270 witness: a read the node did not answer halves the next batch,
    /// down to one block; one it answered doubles it back, up to the most
    /// (an 8 MiB answer that outlasted the call was asked again whole).
    #[test]
    fn a_batch_the_node_did_not_answer_is_halved() {
        assert_eq!(next_batch(500, false, 500), 250);
        assert_eq!(next_batch(1, false, 500), 1);
        assert_eq!(next_batch(250, true, 500), 500);
        assert_eq!(next_batch(400, true, 500), 500);
    }

    /// B260 witness: a call to a node that takes the connection and never
    /// answers ends in an error (the client had no timeout: one half-open
    /// connection stalled the one-at-a-time loop for good).
    #[tokio::test]
    async fn a_silent_node_is_an_error_not_a_stall() {
        let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = silent.local_addr().unwrap();
        let client = client_with_timeout(std::time::Duration::from_millis(200));
        let call = client.get(format!("http://{addr}/get_chain_height")).send();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), call).await;
        assert!(
            matches!(outcome, Ok(Err(_))),
            "a silent node stalled the call"
        );
    }

    /// B242 witness: a batch with a receipt it could not read writes the
    /// blocks before that one's and advances to the block before it (all or
    /// nothing, a 500-block batch failed whole on one busy answer).
    #[test]
    fn a_batch_keeps_the_blocks_before_an_unread_receipt() {
        let tx = |height: u64| PendingTx {
            height,
            timestamp: 0,
            hash: format!("{height}"),
            tx_str: String::new(),
        };
        let mut receipts = vec![(tx(10), ()), (tx(11), ()), (tx(12), ())];
        assert_eq!(complete_blocks(&mut receipts, Some(12), 20), 11);
        assert_eq!(receipts.len(), 2);
        let mut all = vec![(tx(10), ())];
        assert_eq!(complete_blocks(&mut all, None, 20), 20);
        assert_eq!(all.len(), 1);
        let mut first = vec![(tx(10), ())];
        assert_eq!(complete_blocks(&mut first, Some(10), 20), 9);
        assert!(first.is_empty());
    }

    /// B233 witness: an error answered for a receipt is an error, not "no
    /// receipt" (the batch's height advanced past a busy answer and its DEX
    /// trades were lost); a null result is no receipt.
    #[test]
    fn a_busy_receipt_answer_is_an_error() {
        let read = |json: &str| {
            receipt_of(serde_json::from_str::<RpcResponse<serde_json::Value>>(json).unwrap())
        };
        assert!(read(r#"{"error":{"code":-32005,"message":"busy; retry"}}"#).is_err());
        assert_eq!(read(r#"{"result":null}"#), Ok(None));
        assert_eq!(
            read(r#"{"result":{"status":"success"}}"#),
            Ok(Some(serde_json::json!({"status":"success"})))
        );
    }

    use super::{
        DexMarketSummary, DexTradeRecord, TradePoint, build_ohlc, build_pair_summary,
        decode_transfer, dex_trade_from_receipt, market_summary, trade_point_for_pair,
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
            Some("0000000000000000000000000000000022222222222222222222222222222222")
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
        let trades = [
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

        let (x, y) = ("0x1::staking::AincoreCoin", "0x1::wbtc::WBTC");
        let points = trades
            .iter()
            .filter_map(|trade| trade_point_for_pair(trade, x, y));
        let market = market_summary(x, y, "pool1", points, now_ts).expect("market summary");
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

    // B265 witnesses.
    use super::{
        Connection, DAY_SECS, Duration, HISTORY_SQL, Instant, IpAddr, PAIR_FIRST_SQL,
        PAIR_LAST_SQL, PAIR_LATEST_SQL, PAIR_WINDOW_SQL, POOL_FIRST_SQL, POOL_LAST_SQL,
        POOL_WINDOW_SQL, POOLS_SQL, READERS, Reads, SENDER_TRADES_SQL, history,
        index_dex_trade_row, markets, pair_summary, prepare_db, read, trade_row,
    };
    use std::sync::Arc;

    /// A database file of its own, removed on drop (the name carries the
    /// pid and a counter: a clock-based name collided between tests).
    struct TempDb {
        path: String,
    }

    impl TempDb {
        fn new(tag: &str) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let path = std::env::temp_dir()
                .join(format!(
                    "aincore_indexer_{tag}_{}_{n}.db",
                    std::process::id()
                ))
                .to_string_lossy()
                .into_owned();
            prepare_db(&Connection::open(&path).unwrap()).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.path));
            }
        }
    }

    /// B265 witness: every query the API runs is a search of an index (each
    /// scanned a whole table, holding the one connection the indexing loop
    /// writes on), and none sorts what it found.
    #[test]
    fn every_api_query_searches_an_index() {
        let db = TempDb::new("b265_plans");
        let conn = Connection::open(&db.path).unwrap();
        let queries = [
            ("history", HISTORY_SQL),
            ("pair first", PAIR_FIRST_SQL),
            ("pair window", PAIR_WINDOW_SQL),
            ("pair last", PAIR_LAST_SQL),
            ("pair latest", PAIR_LATEST_SQL),
            ("sender trades", SENDER_TRADES_SQL),
            ("pools", POOLS_SQL),
            ("pool first", POOL_FIRST_SQL),
            ("pool window", POOL_WINDOW_SQL),
            ("pool last", POOL_LAST_SQL),
        ];
        for (name, sql) in queries {
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let params = stmt.parameter_count();
            let args: Vec<String> = (0..params).map(|_| "1".to_string()).collect();
            let plan: Vec<String> = stmt
                .query_map(rusqlite::params_from_iter(args.iter()), |row| {
                    row.get::<_, String>(3)
                })
                .unwrap()
                .flatten()
                .collect();
            assert!(!plan.is_empty(), "{name}: no plan");
            for step in &plan {
                assert!(
                    !step.starts_with("SCAN transactions") && !step.starts_with("SCAN dex_trades"),
                    "{name} scans a table: {plan:?}"
                );
                assert!(!step.contains("TEMP B-TREE"), "{name} sorts: {plan:?}");
            }
        }
    }

    /// B265 witness: the indexing writer commits while an API reader holds
    /// a read transaction (one connection behind one mutex served both, and
    /// a rollback journal would refuse the commit until the reader ended).
    #[test]
    fn the_writer_commits_while_a_reader_holds_a_snapshot() {
        let db = TempDb::new("b265_wal");
        let writer = Connection::open(&db.path).unwrap();
        let reader = Connection::open(&db.path).unwrap();
        reader.execute_batch("BEGIN").unwrap();
        let held: i64 = reader
            .query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))
            .unwrap();
        writer.busy_timeout(Duration::ZERO).unwrap();
        writer
            .execute(
                "INSERT INTO transactions (hash, sender) VALUES ('h', 's')",
                [],
            )
            .expect("the writer waited on a reader");
        let still: i64 = reader
            .query_row("SELECT COUNT(*) FROM transactions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(held, still, "the reader's snapshot moved");
        reader.execute_batch("COMMIT").unwrap();
    }

    fn trade(i: u64, now: u64, forward: bool) -> DexTradeRecord {
        let (x, y) = ("0x1::staking::AincoreCoin", "0x1::wbtc::WBTC");
        let ain = ((10 + i) as u128 * 10u128.pow(18)).to_string();
        let btc = ((9 + i % 5) as u128 * 10u128.pow(7)).to_string();
        let (token_in, token_out, amount_in, amount_out) = if forward {
            (x, y, ain, btc)
        } else {
            (y, x, btc, ain)
        };
        DexTradeRecord {
            tx_hash: format!("tx{i}"),
            pool_addr: "pool1".into(),
            function: if forward {
                "swap_x_to_y"
            } else {
                "swap_y_to_x"
            }
            .into(),
            token_x: x.into(),
            token_y: y.into(),
            token_in: token_in.into(),
            token_out: token_out.into(),
            amount_in,
            amount_out,
            block_height: 1_000 - i,
            timestamp: now - i * 3_600 - 7,
            sender: format!("sender{}", i % 4),
        }
    }

    /// B265 witness: a pair's and a pool's summaries read from their first
    /// trade, their last day's and their last are the summaries of every
    /// trade (which were all loaded per request), both ways round; and the
    /// latest trades are the newest (OHLC read the oldest).
    #[test]
    fn a_summary_from_a_days_rows_is_every_trades_summary() {
        let db = TempDb::new("b265_summary");
        let conn = Connection::open(&db.path).unwrap();
        let now = 1_715_086_400;
        let (x, y) = ("0x1::staking::AincoreCoin", "0x1::wbtc::WBTC");
        let trades: Vec<DexTradeRecord> = (0..40).map(|i| trade(i, now, i % 3 != 0)).collect();
        for t in &trades {
            index_dex_trade_row(&conn, t);
        }
        let mut oldest_first = trades.clone();
        oldest_first.sort_by_key(|t| t.timestamp);
        assert!(
            oldest_first[0].timestamp < now - DAY_SECS
                && oldest_first[39].timestamp >= now - DAY_SECS,
            "vacuous: the trades do not straddle the window"
        );
        for (base, quote) in [(x, y), (y, x)] {
            let every = build_pair_summary(
                base,
                quote,
                oldest_first
                    .iter()
                    .filter_map(|t| trade_point_for_pair(t, base, quote)),
                now,
            );
            let read = pair_summary(&conn, base, quote, now).unwrap();
            assert_eq!(
                serde_json::to_value(read).unwrap(),
                serde_json::to_value(every).unwrap(),
                "{base}/{quote}"
            );
        }
        let every = market_summary(
            x,
            y,
            "pool1",
            oldest_first
                .iter()
                .filter_map(|t| trade_point_for_pair(t, x, y)),
            now,
        );
        assert_eq!(
            serde_json::to_value(markets(&conn, 50, now).unwrap()).unwrap(),
            serde_json::json!([serde_json::to_value(every).unwrap()])
        );
        // A day with no trade: the first and last trades still give the
        // summary every trade gives.
        let later = now + 3 * DAY_SECS;
        let every = build_pair_summary(
            x,
            y,
            oldest_first
                .iter()
                .filter_map(|t| trade_point_for_pair(t, x, y)),
            later,
        );
        assert_eq!(
            serde_json::to_value(pair_summary(&conn, x, y, later).unwrap()).unwrap(),
            serde_json::to_value(every).unwrap()
        );
        let latest: Vec<u64> = conn
            .prepare(PAIR_LATEST_SQL)
            .unwrap()
            .query_map(rusqlite::params![x, y, 5u64], trade_row)
            .unwrap()
            .flatten()
            .map(|t| t.timestamp)
            .collect();
        let newest: Vec<u64> = oldest_first
            .iter()
            .rev()
            .take(5)
            .map(|t| t.timestamp)
            .collect();
        assert_eq!(latest, newest);
    }

    /// B265 witness: an address's history is the latest 50 of what it sent
    /// and received, a transfer to itself once.
    #[test]
    fn history_is_both_sides_latest() {
        let db = TempDb::new("b265_history");
        let conn = Connection::open(&db.path).unwrap();
        let put = |hash: String, sender: &str, receiver: &str, height: u64| {
            conn.execute(
                "INSERT INTO transactions (hash, sender, receiver, amount, payload, block_height, timestamp)
                 VALUES (?1, ?2, ?3, 1, '', ?4, 0)",
                rusqlite::params![hash, sender, receiver, height],
            )
            .unwrap();
        };
        for h in 1..=60u64 {
            put(format!("sent{h}"), "a", "b", h);
            put(format!("got{h}"), "b", "a", 60 + h);
            put(format!("other{h}"), "b", "c", 200 + h);
        }
        put("self".into(), "a", "a", 150);
        let got = history(&conn, "a").unwrap();
        let heights: Vec<u64> = got.iter().map(|t| t.block_height).collect();
        let want: Vec<u64> = std::iter::once(150)
            .chain((71..=120).rev())
            .take(50)
            .collect();
        assert_eq!(heights, want);
    }

    /// B279 witness: behind a trusted proxy a client is the last address of
    /// the header's last line, a mapped peer as IPv4; from any other peer
    /// the header is ignored (every client was the proxy's group).
    #[test]
    fn a_client_behind_a_trusted_proxy_is_its_own() {
        let proxy: IpAddr = "10.0.0.1".parse().unwrap();
        let client_ip = super::ClientIp {
            header: Some("X-Forwarded-For".into()),
            trusted: vec![proxy],
        };
        let mut headers = actix_web::http::header::HeaderMap::new();
        for line in ["198.18.0.1", "1.2.3.4, 203.0.113.7"] {
            headers.append(
                actix_web::http::header::HeaderName::from_static("x-forwarded-for"),
                actix_web::http::header::HeaderValue::from_static(line),
            );
        }
        let at = |peer: &str| {
            client_ip
                .address(peer.parse().unwrap(), &headers)
                .to_string()
        };
        assert_eq!(at("10.0.0.1"), "203.0.113.7");
        assert_eq!(at("::ffff:10.0.0.1"), "203.0.113.7");
        assert_eq!(at("10.0.0.2"), "10.0.0.2", "an untrusted peer's header");
        assert_eq!(
            super::net_group("203.0.113.7".parse().unwrap()).to_string(),
            "203.0.113.0"
        );
    }

    /// B280 witness: one cached markets list serves every `limit` (a list
    /// per limit let a client skip the cache by varying it).
    #[actix_web::test]
    async fn one_markets_list_serves_every_limit() {
        let db = TempDb::new("b280_markets");
        let conn = Connection::open(&db.path).unwrap();
        index_dex_trade_row(&conn, &trade(0, super::now_secs(), true));
        let state = actix_web::web::Data::new(super::AppState {
            reads: Arc::new(Reads::open(&db.path, READERS).unwrap()),
            client_ip: super::ClientIp::default(),
        });
        let app =
            actix_web::test::init_service(actix_web::App::new().app_data(state.clone()).route(
                "/api/v1/markets",
                actix_web::web::get().to(super::get_markets),
            ))
            .await;
        for limit in [1, 2, 7] {
            let req = actix_web::test::TestRequest::get()
                .uri(&format!("/api/v1/markets?limit={limit}"))
                .peer_addr("127.0.0.1:5000".parse().unwrap())
                .to_request();
            let body: serde_json::Value = actix_web::test::call_and_read_body_json(&app, req).await;
            assert_eq!(body.as_array().map(Vec::len), Some(1), "limit {limit}");
        }
        assert_eq!(
            state.reads.summaries.lock().unwrap().len(),
            1,
            "a markets list per limit"
        );
    }

    /// B265 witness: a summary is answered from the cache while it is fresh,
    /// and the cache holds at most `MAX_SUMMARIES` (its keys are request
    /// parameters).
    #[test]
    fn a_summary_is_served_from_the_cache_while_fresh() {
        let db = TempDb::new("b265_cache");
        let reads = Reads::open(&db.path, 1).unwrap();
        assert!(reads.cached("pair").is_none());
        reads.remember(
            "pair".into(),
            404,
            &serde_json::json!({"error": "pair_not_found"}),
        );
        let hit = reads.cached("pair").expect("a fresh summary is cached");
        assert_eq!(hit.status().as_u16(), 404);
        for i in 0..super::MAX_SUMMARIES + 10 {
            reads.remember(format!("k{i}"), 200, &serde_json::json!(i));
        }
        assert!(reads.summaries.lock().unwrap().len() <= super::MAX_SUMMARIES);
    }

    /// B265 witness: a network group's second query waits for its first,
    /// while another group's runs beside it (one client looping on the API
    /// held the only connection).
    #[actix_web::test]
    async fn a_network_group_waits_for_its_own_query() {
        let db = TempDb::new("b265_turns");
        let reads = Arc::new(Reads::open(&db.path, READERS).unwrap());
        let call = |group: IpAddr| {
            let reads = Arc::clone(&reads);
            async move {
                read(&reads, group, |_| {
                    let start = Instant::now();
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    (start, Instant::now())
                })
                .await
                .unwrap_or_else(|_| panic!("a query was answered busy"))
            }
        };
        let (a, b) = (IpAddr::from([10, 0, 0, 0]), IpAddr::from([10, 0, 1, 0]));
        let (a1, a2, b1) = tokio::join!(call(a), call(a), call(b));
        let (first, second) = if a1.0 <= a2.0 { (a1, a2) } else { (a2, a1) };
        assert!(second.0 >= first.1, "one group ran two queries at once");
        assert!(b1.0 < first.1, "another group waited for this one's");
    }
}
