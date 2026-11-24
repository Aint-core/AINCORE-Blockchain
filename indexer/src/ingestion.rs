use super::*;
use rusqlite::TransactionBehavior;
use serde::de::DeserializeOwned;

pub(super) const BLOCK_RESPONSE_BYTES: usize = 32 << 20;
const STATUS_BYTES: usize = 64 << 10;
const POLL: Duration = Duration::from_secs(2);
const FRESHNESS: Duration = Duration::from_secs(65);
const ANCHOR_RECHECK: Duration = Duration::from_secs(30);

pub(super) async fn rpc<T: DeserializeOwned>(
    method: &str,
    params: Vec<serde_json::Value>,
    max_bytes: usize,
) -> Result<RpcResponse<T>, String> {
    let req = RpcRequest {
        jsonrpc: "2.0".into(),
        method: method.into(),
        params,
        id: 1,
    };
    let mut response = http_client()
        .post(get_rpc_url())
        .json(&req)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| format!("{method}: upstream HTTP error"))?;
    if response
        .content_length()
        .is_some_and(|n| n > max_bytes as u64)
    {
        return Err(format!("{method}: response exceeds byte limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| format!("{method}: incomplete response"))?
    {
        if chunk.len() > max_bytes - body.len() {
            return Err(format!("{method}: response exceeds byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    decode_response(&body).map_err(|why| format!("{method}: {why}"))
}

fn decode_response<T: DeserializeOwned>(body: &[u8]) -> Result<RpcResponse<T>, &'static str> {
    let envelope: serde_json::Value = serde_json::from_slice(body).map_err(|_| "invalid JSON")?;
    if envelope["jsonrpc"].as_str() != Some("2.0") || envelope["id"].as_u64() != Some(1) {
        return Err("invalid response version or id");
    }
    if !envelope["error"].is_null() {
        return Err("upstream RPC error");
    }
    if envelope.get("result").is_none() {
        return Err("missing result");
    }
    serde_json::from_value(envelope).map_err(|_| "invalid result type")
}

fn is_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Cursor {
    chain_id: String,
    genesis_identity: String,
    height: u64,
    block_hash: Option<String>,
}

impl Cursor {
    fn validate(&self) -> Result<(), String> {
        if self.chain_id.trim().is_empty()
            || !is_hash(&self.genesis_identity)
            || !match (&self.block_hash, self.height) {
                (None, 0) => true,
                (Some(h), 1..) => is_hash(h),
                _ => false,
            }
        {
            return Err("invalid chain identity or checkpoint hash".into());
        }
        Ok(())
    }
}

fn stored_cursor(db: &Connection) -> Result<Option<Cursor>, String> {
    let raw: Option<String> = db
        .query_row(
            "SELECT value FROM state WHERE key='index_cursor_v1'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let cursor: Cursor = serde_json::from_str(&raw).map_err(|_| "invalid database checkpoint")?;
    cursor.validate()?;
    if cursor.height != get_last_indexed_height(db).map_err(|e| e.to_string())? {
        return Err("inconsistent database height and checkpoint".into());
    }
    Ok(Some(cursor))
}

fn table_exists(db: &Connection, table: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |r| r.get(0),
    )
}

fn has_history(db: &Connection) -> rusqlite::Result<bool> {
    for sql in [
        ("transactions", "SELECT EXISTS(SELECT 1 FROM transactions)"),
        ("dex_trades", "SELECT EXISTS(SELECT 1 FROM dex_trades)"),
        ("dex_pools", "SELECT EXISTS(SELECT 1 FROM dex_pools)"),
    ] {
        if table_exists(db, sql.0)? && db.query_row(sql.1, [], |r| r.get::<_, bool>(0))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check provenance before prepare_db can migrate any historical rows.
pub(super) fn legacy_checkpoint(db: &Connection) -> Result<Option<Cursor>, String> {
    let has_state = table_exists(db, "state").map_err(|e| e.to_string())?;
    if has_state && stored_cursor(db)?.is_some() {
        return Ok(None);
    }
    let height = if has_state {
        get_last_indexed_height(db).map_err(|e| e.to_string())?
    } else {
        0
    };
    if height == 0 && !has_history(db).map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let first_schema: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('transactions') WHERE name='amount' AND upper(type)='INTEGER')",
        [], |r| r.get(0)).map_err(|e| e.to_string())?;
    if first_schema || height == 0 {
        return Err("legacy index has no verifiable cursor or uses the retired integer schema; preserve it and rebuild at a new AINCORE_INDEXER_DB_PATH".into());
    }
    let path = env::var_os("AINCORE_INDEXER_LEGACY_CHECKPOINT").ok_or(
        "unbound legacy index; supply its independently recorded checkpoint file in AINCORE_INDEXER_LEGACY_CHECKPOINT or rebuild at a new AINCORE_INDEXER_DB_PATH")?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let checkpoint: Cursor =
        serde_json::from_slice(&bytes).map_err(|_| "invalid legacy checkpoint file")?;
    checkpoint.validate()?;
    if checkpoint.height != height {
        return Err("legacy checkpoint height differs from database".into());
    }
    Ok(Some(checkpoint))
}

/// Compare and write in one writer transaction. Concurrent processes must refetch after a race.
fn save(
    db: &mut Connection,
    before: Option<&Cursor>,
    next: &Cursor,
    legacy: Option<&Cursor>,
    receipts: &[(PendingTx, Option<serde_json::Value>)],
) -> Result<(), String> {
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    if stored_cursor(&tx)?.as_ref() != before {
        return Err("checkpoint changed while fetching".into());
    }
    let old_height = get_last_indexed_height(&tx).map_err(|e| e.to_string())?;
    if before.is_none()
        && legacy.is_none()
        && (old_height != 0 || has_history(&tx).map_err(|e| e.to_string())?)
    {
        return Err("database acquired unbound history while fetching".into());
    }
    if let Some(checkpoint) = legacy
        && before.is_none()
        && (old_height != checkpoint.height || checkpoint != next)
    {
        return Err("legacy checkpoint changed while fetching".into());
    }
    write_batch(&tx, receipts, next.height, old_height).map_err(|e| e.to_string())?;
    let encoded = serde_json::to_string(next).map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT OR REPLACE INTO state(key,value) VALUES('index_cursor_v1',?1)",
        [encoded],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

struct Upstream {
    identity: Cursor,
    latest: u64,
}
async fn upstream() -> Result<Upstream, String> {
    let status = rpc::<serde_json::Value>("aincore_getStatus", vec![], STATUS_BYTES)
        .await?
        .result
        .ok_or("missing node status")?;
    let identity = Cursor {
        chain_id: status["chain_id"].as_str().unwrap_or_default().to_owned(),
        genesis_identity: status["genesis_identity"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        height: 0,
        block_hash: None,
    };
    identity.validate()?;
    if let Ok(pin) = env::var("AINCORE_EXPECTED_GENESIS_HASH")
        && !pin.eq_ignore_ascii_case(&identity.genesis_identity)
    {
        return Err("configured genesis pin differs from upstream".into());
    }
    let latest = value_to_u64(&status["latest_height"]).ok_or("missing upstream height")?;
    Ok(Upstream { identity, latest })
}

#[derive(Deserialize)]
struct Header {
    height: u64,
    hash: String,
    prev_hash: String,
    timestamp: u64,
}
#[derive(Deserialize)]
struct Block {
    header: Header,
    transactions: Vec<String>,
}

fn checked_block(value: serde_json::Value, cursor: &Cursor, latest: u64) -> Result<Block, String> {
    let block: Block = serde_json::from_value(value)
        .map_err(|_| format!("invalid block envelope after {}", cursor.height))?;
    let h = &block.header;
    if cursor.height.checked_add(1) != Some(h.height)
        || h.height > latest
        || !is_hash(&h.hash)
        || h.prev_hash != cursor.block_hash.as_deref().unwrap_or("genesis")
    {
        return Err(format!("invalid block linkage at {}", h.height));
    }
    for raw in &block.transactions {
        let valid = serde_json::from_str::<serde_json::Value>(raw)
            .is_ok_and(|tx| tx["sender"].is_string() && tx["payload"].is_string());
        if !valid {
            return Err(format!("invalid transaction envelope at {}", h.height));
        }
    }
    Ok(block)
}

async fn header_at(height: u64) -> Result<Header, String> {
    let block = fetch_blocks(height, 1)
        .await?
        .into_iter()
        .next()
        .ok_or("checkpoint block unavailable")?;
    let header: Header =
        serde_json::from_value(block["header"].clone()).map_err(|_| "invalid checkpoint header")?;
    if header.height != height || !is_hash(&header.hash) {
        return Err("invalid checkpoint block".into());
    }
    Ok(header)
}

fn check_chain(cursor: &Cursor, up: &Upstream) -> Result<(), String> {
    if cursor.chain_id != up.identity.chain_id
        || cursor.genesis_identity != up.identity.genesis_identity
    {
        return Err("upstream chain or genesis differs from database checkpoint".into());
    }
    if up.latest < cursor.height {
        return Err("upstream is behind the database checkpoint".into());
    }
    Ok(())
}

#[derive(Default, Clone)]
pub(super) struct Progress(Arc<Mutex<Reading>>);

#[derive(Default)]
struct Reading {
    caught_up: bool,
    height: Option<u64>,
    latest: Option<u64>,
    last_commit: Option<u64>,
    last_check: Option<Instant>,
    problem: Option<String>,
}

impl Reading {
    fn reason(&self) -> Option<&str> {
        if let Some(reason) = &self.problem {
            return Some(reason);
        }
        let Some(at) = self.last_check else {
            return Some("starting");
        };
        if at.elapsed() > FRESHNESS {
            return Some("upstream observation expired");
        }
        if !self.caught_up || self.height.is_none() || self.height != self.latest {
            return Some("catching up");
        }
        None
    }
}

impl Progress {
    fn update(&self, f: impl FnOnce(&mut Reading)) {
        f(&mut self.0.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

pub(super) async fn readiness(data: web::Data<AppState>) -> HttpResponse {
    let p = data.progress.0.lock().unwrap_or_else(|e| e.into_inner());
    let reason = p.reason();
    let response = serde_json::json!({"ready":reason.is_none(), "reason":reason, "indexed_height":p.height,
        "upstream_height":p.latest, "last_commit_unix":p.last_commit,
        "observation_age_secs":p.last_check.map(|at| at.elapsed().as_secs())});
    if reason.is_none() {
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::ServiceUnavailable().json(response)
    }
}

struct PollState {
    batch: u64,
    batch_limit: u64,
    backfill: u64,
    anchor_checked: Option<(Cursor, Instant)>,
}

async fn poll(
    db: &mut Connection,
    state: &mut PollState,
    progress: &Progress,
    legacy: Option<&Cursor>,
) -> Result<bool, String> {
    let local = stored_cursor(db)?;
    progress.update(|p| p.height = local.as_ref().map(|c| c.height));
    let up = upstream().await?;
    progress.update(|p| {
        p.latest = Some(up.latest);
        p.last_check = Some(Instant::now());
    });
    let Some(cursor) = local else {
        let mut first = up.identity.clone();
        if let Some(existing) = legacy {
            check_chain(existing, &up)?;
            if Some(header_at(existing.height).await?.hash) != existing.block_hash {
                return Err("legacy checkpoint block hash differs".into());
            }
            first = existing.clone();
        } else if state.backfill > 0 && up.latest > state.backfill {
            first.height = up.latest - state.backfill;
            let next = header_at(first.height + 1).await?;
            if !is_hash(&next.prev_hash) {
                return Err("invalid parent at bootstrap boundary".into());
            }
            first.block_hash = Some(next.prev_hash);
            log::warn!(
                "Tail bootstrap starts at height {}; earlier history is excluded",
                first.height + 1
            );
        }
        if first.height > 0 {
            check_chain(&first, &upstream().await?)?;
        }
        save(db, None, &first, legacy, &[])?;
        return Ok(true);
    };
    check_chain(&cursor, &up)?;
    if up.latest == cursor.height {
        if let Some(hash) = &cursor.block_hash
            && !state
                .anchor_checked
                .as_ref()
                .is_some_and(|(c, t)| c == &cursor && t.elapsed() < ANCHOR_RECHECK)
        {
            if header_at(cursor.height).await?.hash != *hash {
                return Err("upstream tip hash differs from database checkpoint".into());
            }
            state.anchor_checked = Some((cursor.clone(), Instant::now()));
        }
        progress.update(|p| {
            p.problem = None;
            p.caught_up = true;
        });
        return Ok(false);
    }
    progress.update(|p| p.caught_up = false);
    let start = cursor.height + 1;
    let result = fetch_blocks(start, state.batch.min(up.latest - cursor.height)).await;
    state.batch = next_batch(state.batch, result.is_ok(), state.batch_limit);
    let blocks = result?;
    let run = leading_run(&blocks, start);
    if missing_height(run, blocks.len(), start, Some(up.latest)).is_some() {
        return Err(format!("block {start} missing, pruned or unreadable"));
    }
    let mut issue =
        (run != blocks.len()).then(|| "upstream block heights are discontinuous".to_string());
    let mut next = cursor.clone();
    let mut receipts = Vec::new();
    'blocks: for value in blocks.into_iter().take(run) {
        let block = match checked_block(value, &next, up.latest) {
            Ok(block) => block,
            Err(e) => {
                issue = Some(e);
                break;
            }
        };
        let header = block.header;
        for raw in block.transactions {
            let hash = tx_hash_hex(&raw);
            match fetch_receipt_retried(&hash).await {
                Ok(receipt) => receipts.push((
                    PendingTx {
                        height: header.height,
                        timestamp: header.timestamp,
                        hash,
                        tx_str: raw,
                    },
                    receipt,
                )),
                Err(_) => {
                    issue = Some(format!("receipt unavailable at {}", header.height));
                    complete_blocks(&mut receipts, Some(header.height), header.height);
                    break 'blocks;
                }
            }
        }
        next.height = header.height;
        next.block_hash = Some(header.hash);
    }
    if next.height > cursor.height {
        check_chain(&next, &upstream().await?)?;
        save(db, Some(&cursor), &next, None, &receipts)?;
        progress.update(|p| {
            p.height = Some(next.height);
            p.last_commit = Some(now_secs());
        });
        state.anchor_checked = None;
    }
    if let Some(error) = issue {
        return Err(error);
    }
    progress.update(|p| p.problem = None);
    Ok(true)
}

pub(super) async fn indexer_loop(db: &mut Connection, progress: Progress, legacy: Option<Cursor>) {
    let limit = indexer_batch_size();
    let mut state = PollState {
        batch: limit,
        batch_limit: limit,
        backfill: indexer_bootstrap_backfill().unwrap_or(DEFAULT_INDEXER_BOOTSTRAP_BACKFILL),
        anchor_checked: None,
    };
    let mut logged: Option<(String, Instant)> = None;
    loop {
        match poll(db, &mut state, &progress, legacy.as_ref()).await {
            Ok(true) => {
                logged = None;
                continue;
            }
            Ok(false) => logged = None,
            Err(e) => {
                if logged
                    .as_ref()
                    .is_none_or(|(msg, at)| msg != &e || at.elapsed() >= MISSING_REPORT_EVERY)
                {
                    log::error!("Indexing paused: {e}");
                    logged = Some((e.clone(), Instant::now()));
                }
                progress.update(|p| {
                    p.problem = Some(e);
                    p.caught_up = false;
                });
            }
        }
        sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cursor(height: u64, byte: &str) -> Cursor {
        Cursor {
            chain_id: "network".into(),
            genesis_identity: "12".repeat(32),
            height,
            block_hash: (height > 0).then(|| byte.repeat(32)),
        }
    }

    #[test]
    fn response_requires_an_explicit_matching_rpc_result() {
        let decode = |s: serde_json::Value| {
            decode_response::<serde_json::Value>(&serde_json::to_vec(&s).unwrap()).is_ok()
        };
        assert!(decode(
            json!({"jsonrpc":"2.0","id":1,"result":null,"error":null})
        ));
        assert!(!decode(json!({"jsonrpc":"2.0","id":1})));
        assert!(!decode(json!({"jsonrpc":"2.0","id":2,"result":[]})));
        assert!(!decode(
            json!({"jsonrpc":"2.0","id":1,"result":null,"error":{"code":-1}})
        ));
    }

    #[test]
    fn indexing_requires_an_intact_block_envelope_and_parent() {
        let checkpoint = cursor(4, "aa");
        let header =
            json!({"height":5,"hash":"bb".repeat(32),"prev_hash":"aa".repeat(32),"timestamp":123});
        let good = json!({"header":header,"transactions":[r#"{"sender":"s","payload":""}"#]});
        assert!(checked_block(good.clone(), &checkpoint, 5).is_ok());
        assert!(checked_block(json!({"header":header,"transactions":[]}), &checkpoint, 5).is_ok());
        assert!(checked_block(json!({"header":header}), &checkpoint, 5).is_err());
        assert!(
            checked_block(
                json!({"header":header,"transactions":[null]}),
                &checkpoint,
                5
            )
            .is_err()
        );
        assert!(
            checked_block(
                json!({"header":header,"transactions":["{}"]}),
                &checkpoint,
                5
            )
            .is_err()
        );
        assert!(checked_block(good.clone(), &cursor(4, "cc"), 5).is_err());
        assert!(checked_block(good, &checkpoint, 4).is_err());
    }

    #[test]
    fn cursor_rows_and_checkpoint_share_a_transaction_and_compare_the_old_tip() {
        let mut db = Connection::open_in_memory().unwrap();
        prepare_db(&db).unwrap();
        let initial = cursor(0, "");
        let one = cursor(1, "aa");
        let two = cursor(2, "bb");
        save(&mut db, None, &initial, None, &[]).unwrap();
        save(&mut db, Some(&initial), &one, None, &[]).unwrap();
        assert!(save(&mut db, Some(&initial), &two, None, &[]).is_err());
        db.execute_batch(
            "CREATE TRIGGER reject_checkpoint BEFORE INSERT ON state WHEN NEW.key='index_cursor_v1'
                          BEGIN SELECT RAISE(ABORT,'injected test error'); END;",
        )
        .unwrap();
        let row = PendingTx {
            height: 2,
            timestamp: 3,
            hash: "h".into(),
            tx_str: r#"{"sender":"s","payload":""}"#.into(),
        };
        assert!(save(&mut db, Some(&one), &two, None, &[(row, None)]).is_err());
        assert_eq!(stored_cursor(&db).unwrap(), Some(one));
        assert_eq!(get_last_indexed_height(&db).unwrap(), 1);
        assert!(!has_history(&db).unwrap());
    }

    #[test]
    fn historical_database_requires_matching_checkpoint_before_binding() {
        let mut db = Connection::open_in_memory().unwrap();
        prepare_db(&db).unwrap();
        let old = cursor(7, "aa");
        set_last_indexed_height(&db, 7).unwrap();
        assert!(save(&mut db, None, &old, None, &[]).is_err());
        assert!(save(&mut db, None, &cursor(8, "bb"), Some(&old), &[]).is_err());
        save(&mut db, None, &old, Some(&old), &[]).unwrap();
        let mut up = Upstream {
            identity: cursor(0, ""),
            latest: 9,
        };
        assert!(check_chain(&old, &up).is_ok());
        up.identity.genesis_identity = "34".repeat(32);
        assert!(check_chain(&old, &up).is_err());
        up.identity = cursor(0, "");
        up.latest = 6;
        assert!(check_chain(&old, &up).is_err());
    }

    #[test]
    fn readiness_requires_recent_validated_upstream_and_matching_height() {
        let mut p = Reading::default();
        assert_eq!(p.reason(), Some("starting"));
        p.problem = Some("upstream unavailable".into());
        assert_eq!(p.reason(), Some("upstream unavailable"));
        p.problem = None;
        p.last_check = Some(Instant::now());
        p.height = Some(7);
        p.latest = Some(8);
        assert_eq!(p.reason(), Some("catching up"));
        p.latest = Some(7);
        assert!(p.reason().is_some());
        p.caught_up = true;
        assert_eq!(p.reason(), None);
        p.last_check = Some(Instant::now() - FRESHNESS - Duration::from_secs(1));
        assert_eq!(p.reason(), Some("upstream observation expired"));
    }
}
