use actix_governor::{Governor, GovernorConfigBuilder, KeyExtractor, SimpleKeyExtractionError};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

// Input validation constants
const MAX_BLOCK_HEIGHT: u64 = 1_000_000_000;
const MAX_QUERY_LIMIT: u64 = 1000;
/// B54: the bytes of blocks one `aincore_getBlocks` answer carries (a choice:
/// the sync answer's 8 MiB, `SYNC_RESP_BLOCK_BYTES`); at least one block.
const MAX_BLOCKS_BYTES: usize = 8 << 20;
/// B54: the vertices `aincore_getDag` returns, newest first (a choice: a few
/// rounds of a full committee).
const MAX_DAG_VERTICES: usize = 256;
/// B76: the payload bytes one `aincore_getDag` answer carries (a choice: the
/// same 8 MiB as `MAX_BLOCKS_BYTES`; the payload is the part of a vertex that
/// grows to 768 KiB, the rest is bounded by the committee); at least one
/// vertex.
const MAX_DAG_BYTES: usize = MAX_BLOCKS_BYTES;

// --- Shared State ---
use consensus::DagConsensus;
use governance::GovernanceManager;
use storage::StateDB;

fn permissive_cors_enabled() -> bool {
    std::env::var("AINCORE_PERMISSIVE_CORS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[derive(Deserialize, Serialize)]
struct MoveCoin {
    value: u128,
}

#[derive(Deserialize, Serialize, Clone)]
struct DexPoolInfo {
    pool_key: Vec<u8>,
    pool_addr: move_core_types::account_address::AccountAddress,
    token_x_name: Vec<u8>,
    token_y_name: Vec<u8>,
    fee_bp: u64,
    creator: move_core_types::account_address::AccountAddress,
    active: bool,
}

#[derive(Deserialize, Serialize)]
struct DexPoolRegistry {
    pools: Vec<DexPoolInfo>,
}

#[derive(Deserialize, Serialize)]
struct DexLiquidityPool {
    coin_x: MoveCoin,
    coin_y: MoveCoin,
    lp_supply: u128,
    fee_bp: u64,
}

#[derive(Deserialize, Serialize)]
struct DexLPToken {
    balance: u128,
}

fn move_coin_store_key(addr: move_core_types::account_address::AccountAddress) -> String {
    move_coin_store_key_for(addr, "staking", "AincoreCoin")
}

fn move_coin_store_key_for(
    addr: move_core_types::account_address::AccountAddress,
    module: &str,
    name: &str,
) -> String {
    use move_core_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{StructTag, TypeTag},
    };
    let system = AccountAddress::from_hex_literal("0x1").expect("valid system address");
    let coin_type = TypeTag::Struct(Box::new(StructTag {
        address: system,
        module: Identifier::new(module).expect("valid module"),
        name: Identifier::new(name).expect("valid coin"),
        type_params: vec![],
    }));
    let store = StructTag {
        address: system,
        module: Identifier::new("coin").expect("valid module"),
        name: Identifier::new("CoinStore").expect("valid store"),
        type_params: vec![coin_type],
    };
    vm_move::state_keys::resource_key(&addr, &store)
}

fn wbtc_coin_store_key(addr: move_core_types::account_address::AccountAddress) -> String {
    move_coin_store_key_for(addr, "wbtc", "WBTC")
}

fn dex_registry_key() -> String {
    let system = move_core_types::account_address::AccountAddress::from_hex_literal("0x1")
        .expect("valid system address");
    vm_move::state_keys::resource_key_str(&system, "0x1::dex::PoolRegistry")
}

fn normalize_type_name(value: &str) -> String {
    let value = value.trim();
    match value.to_ascii_uppercase().as_str() {
        "AIN" => return "0000000000000000000000000000000000000000000000000000000000000001::staking::AincoreCoin".to_string(),
        "WBTC" => return "0000000000000000000000000000000000000000000000000000000000000001::wbtc::WBTC".to_string(),
        _ => {}
    }

    let trimmed = value.trim_start_matches("0x");
    let mut parts: Vec<String> = trimmed.split("::").map(|part| part.to_string()).collect();
    if let Some(addr) = parts.get_mut(0) {
        *addr = addr.to_ascii_lowercase();
        if addr.len() < crypto::ADDRESS_HEX_LEN {
            *addr = format!("{:0>width$}", addr, width = crypto::ADDRESS_HEX_LEN);
        }
    }
    parts.join("::")
}

fn canonical_pool_key(left: &str, right: &str) -> Option<String> {
    let left = normalize_type_name(left);
    let right = normalize_type_name(right);
    if left == right {
        return None;
    }
    if left < right {
        Some(format!("{}::{}", left, right))
    } else {
        Some(format!("{}::{}", right, left))
    }
}

fn normalize_pool_key(value: &str) -> String {
    let parts: Vec<&str> = value.trim().split("::").collect();
    if parts.len() == 6 {
        let left = format!("{}::{}::{}", parts[0], parts[1], parts[2]);
        let right = format!("{}::{}::{}", parts[3], parts[4], parts[5]);
        canonical_pool_key(&left, &right).unwrap_or_else(|| value.to_string())
    } else {
        normalize_type_name(value)
    }
}

fn type_tag_from_name(value: &str) -> Option<move_core_types::language_storage::TypeTag> {
    use move_core_types::{
        account_address::AccountAddress,
        identifier::Identifier,
        language_storage::{StructTag, TypeTag},
    };
    let normalized = normalize_type_name(value);
    let mut parts = normalized.split("::");
    let address = parts.next()?;
    let module = parts.next()?;
    let name = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(TypeTag::Struct(Box::new(StructTag {
        address: AccountAddress::from_hex_literal(&format!("0x{}", address)).ok()?,
        module: Identifier::new(module).ok()?,
        name: Identifier::new(name).ok()?,
        type_params: vec![],
    })))
}

fn dex_pool_key(
    pool_addr: move_core_types::account_address::AccountAddress,
    token_x_name: &str,
    token_y_name: &str,
) -> Option<String> {
    use move_core_types::{
        account_address::AccountAddress, identifier::Identifier, language_storage::StructTag,
    };
    let system = AccountAddress::from_hex_literal("0x1").ok()?;
    let x = type_tag_from_name(token_x_name)?;
    let y = type_tag_from_name(token_y_name)?;
    let tag = StructTag {
        address: system,
        module: Identifier::new("dex").ok()?,
        name: Identifier::new("LiquidityPool").ok()?,
        type_params: vec![x, y],
    };
    Some(vm_move::state_keys::resource_key(&pool_addr, &tag))
}

fn dex_lp_key(
    owner: move_core_types::account_address::AccountAddress,
    token_x_name: &str,
    token_y_name: &str,
) -> Option<String> {
    use move_core_types::{
        account_address::AccountAddress, identifier::Identifier, language_storage::StructTag,
    };
    let system = AccountAddress::from_hex_literal("0x1").ok()?;
    let x = type_tag_from_name(token_x_name)?;
    let y = type_tag_from_name(token_y_name)?;
    let tag = StructTag {
        address: system,
        module: Identifier::new("dex").ok()?,
        name: Identifier::new("LPToken").ok()?,
        type_params: vec![x, y],
    };
    Some(vm_move::state_keys::resource_key(&owner, &tag))
}

fn decode_dex_registry(storage: &Arc<StateDB>) -> DexPoolRegistry {
    storage
        .get(&dex_registry_key())
        .ok()
        .flatten()
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<DexPoolRegistry>(&bytes).ok())
        .unwrap_or(DexPoolRegistry { pools: vec![] })
}

fn dex_pool_json(storage: &Arc<StateDB>, info: &DexPoolInfo) -> serde_json::Value {
    let token_x_name = String::from_utf8_lossy(&info.token_x_name).to_string();
    let token_y_name = String::from_utf8_lossy(&info.token_y_name).to_string();
    let pool_key = String::from_utf8_lossy(&info.pool_key).to_string();
    let pool = dex_pool_key(info.pool_addr, &token_x_name, &token_y_name)
        .and_then(|key| storage.get(&key).ok().flatten())
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<DexLiquidityPool>(&bytes).ok());

    serde_json::json!({
        "pool_key": pool_key,
        "pool_addr": info.pool_addr.to_string(),
        "token_x": token_x_name,
        "token_y": token_y_name,
        "fee_bp": info.fee_bp,
        "creator": info.creator.to_string(),
        "active": info.active,
        "reserve_x": pool.as_ref().map(|p| p.coin_x.value.to_string()).unwrap_or_else(|| "0".to_string()),
        "reserve_y": pool.as_ref().map(|p| p.coin_y.value.to_string()).unwrap_or_else(|| "0".to_string()),
        "lp_supply": pool.as_ref().map(|p| p.lp_supply.to_string()).unwrap_or_else(|| "0".to_string()),
    })
}

fn find_dex_pool_info<'a>(
    registry: &'a DexPoolRegistry,
    selector: Option<&str>,
    token_y: Option<&str>,
) -> Option<&'a DexPoolInfo> {
    match (selector, token_y) {
        (Some(left), Some(right)) => {
            let target_key = canonical_pool_key(left, right)?;
            registry
                .pools
                .iter()
                .find(|info| String::from_utf8_lossy(&info.pool_key) == target_key)
        }
        (Some(value), None) => {
            let normalized_value = value.trim_start_matches("0x").to_ascii_lowercase();
            if normalized_value.len() == crypto::ADDRESS_HEX_LEN
                && normalized_value.chars().all(|ch| ch.is_ascii_hexdigit())
            {
                registry.pools.iter().find(|info| {
                    info.pool_addr
                        .to_string()
                        .trim_start_matches("0x")
                        .eq_ignore_ascii_case(&normalized_value)
                })
            } else {
                let target_key = normalize_pool_key(value);
                registry
                    .pools
                    .iter()
                    .find(|info| String::from_utf8_lossy(&info.pool_key) == target_key)
            }
        }
        (None, None) => {
            let target_key = canonical_pool_key("AIN", "WBTC")?;
            registry
                .pools
                .iter()
                .find(|info| String::from_utf8_lossy(&info.pool_key) == target_key)
        }
        (None, Some(_)) => None,
    }
}

fn dex_lp_balance_json(
    storage: &Arc<StateDB>,
    owner: &str,
    selector: Option<&str>,
    token_y: Option<&str>,
) -> Result<serde_json::Value, JsonRpcError> {
    let owner_addr = move_core_types::account_address::AccountAddress::from_hex_literal(&format!(
        "0x{}",
        owner.trim_start_matches("0x")
    ))
    .map_err(|_| JsonRpcError {
        code: -32602,
        message: "Invalid address".into(),
    })?;

    let registry = decode_dex_registry(storage);
    let Some(info) = find_dex_pool_info(&registry, selector, token_y) else {
        return Ok(serde_json::json!({
            "address": owner.trim_start_matches("0x"),
            "status": "pool_not_found",
            "balance": "0",
            "lp_supply": "0",
            "share_bps": 0.0,
        }));
    };

    let token_x_name = String::from_utf8_lossy(&info.token_x_name).to_string();
    let token_y_name = String::from_utf8_lossy(&info.token_y_name).to_string();
    let pool = dex_pool_key(info.pool_addr, &token_x_name, &token_y_name)
        .and_then(|key| storage.get(&key).ok().flatten())
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<DexLiquidityPool>(&bytes).ok());

    let lp_balance = dex_lp_key(owner_addr, &token_x_name, &token_y_name)
        .and_then(|key| storage.get(&key).ok().flatten())
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<DexLPToken>(&bytes).ok())
        .map(|lp| lp.balance)
        .unwrap_or(0);
    let lp_supply = pool.as_ref().map(|pool| pool.lp_supply).unwrap_or(0);
    let share_bps = if lp_supply == 0 {
        0.0
    } else {
        (lp_balance as f64 / lp_supply as f64) * 10_000.0
    };

    Ok(serde_json::json!({
        "address": owner.trim_start_matches("0x"),
        "status": "ok",
        "pool_key": String::from_utf8_lossy(&info.pool_key).to_string(),
        "pool_addr": info.pool_addr.to_string(),
        "token_x": token_x_name,
        "token_y": token_y_name,
        "balance": lp_balance.to_string(),
        "lp_supply": lp_supply.to_string(),
        "share_bps": share_bps,
        "balance_source": "move_dex_lp_token",
    }))
}

fn dex_quote(amount_in: u128, reserve_in: u128, reserve_out: u128, fee_bp: u64) -> Option<u128> {
    if amount_in == 0 || reserve_in == 0 || reserve_out == 0 || fee_bp >= 10_000 {
        return None;
    }
    let fee_multiplier = 10_000u128.checked_sub(fee_bp as u128)?;
    let amount_in_with_fee = amount_in.checked_mul(fee_multiplier)?;
    let numerator = amount_in_with_fee.checked_mul(reserve_out)?;
    let denominator = reserve_in
        .checked_mul(10_000)?
        .checked_add(amount_in_with_fee)?;
    Some(numerator / denominator)
}

fn dex_spot_price_json(
    token_in: &str,
    token_out: &str,
    unit_amount_in: u128,
    quote: serde_json::Value,
) -> serde_json::Value {
    let amount_out = quote
        .get("amount_out")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    let approx_price = amount_out
        .as_ref()
        .and_then(|value| value.parse::<f64>().ok())
        .and_then(|amount_out| {
            if unit_amount_in == 0 {
                None
            } else {
                Some(amount_out / unit_amount_in as f64)
            }
        });

    serde_json::json!({
        "status": quote.get("status").cloned().unwrap_or_else(|| serde_json::json!("unavailable")),
        "token_in": token_in,
        "token_out": token_out,
        "unit_amount_in": unit_amount_in.to_string(),
        "amount_out": amount_out,
        "approx_price": approx_price,
        "quote": quote,
    })
}

fn move_balance(storage: &Arc<StateDB>, addr: &str) -> String {
    let move_addr = match move_core_types::account_address::AccountAddress::from_hex_literal(
        &format!("0x{}", addr.trim_start_matches("0x")),
    ) {
        Ok(addr) => addr,
        Err(_) => return "0".to_string(),
    };
    coin_store_balance(storage, move_coin_store_key(move_addr))
}

/// G5 EM-1: the emission rate, of the remaining reserve per year.
const EMISSION_RATE_PER_YEAR: &str = "0.019";

/// G5 DOC-1: how the emission works, in one sentence.
const EMISSION_MODEL: &str =
    "1.90 % per year of the remaining reserve (the 150M cap minus everything minted), \
     paid to the committee every reward period by consensus time";

/// G5 DL-2: a pool as the RPC reports it. `active`: its validator is in the
/// live set, so the pool takes delegations (unless a slash closed it).
fn validator_pool_json(
    pool: &executor::DelegationPool,
    now: u64,
    active: bool,
) -> serde_json::Value {
    serde_json::json!({
        "total_delegated": pool.active_coins.to_string(),
        "commission_rate": pool.commission_at(now),
        "pending_commission": pool.pending_commission,
        "commission_effective_time": pool.commission_effective_time,
        "delegator_count": pool.position_count,
        "unbonding": pool.unbonding_coins.to_string(),
        "rewards_held": pool.rewards.to_string(),
        "slashed": pool.closed,
        "is_accepting": active && !pool.closed
    })
}

/// The live validator set's addresses (`sys:validator_set:v1`).
fn live_validator_addresses(storage: &Arc<StateDB>) -> std::collections::BTreeSet<String> {
    storage
        .get("sys:validator_set:v1")
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Vec<serde_json::Value>>(&raw).ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|v| {
            v.get("address")
                .and_then(|a| a.as_str())
                .map(str::to_string)
        })
        .collect()
}

fn coin_store_balance(storage: &Arc<StateDB>, key: String) -> String {
    storage
        .get(&key)
        .ok()
        .flatten()
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<MoveCoin>(&bytes).ok())
        .map(|coin| coin.value.to_string())
        .unwrap_or_else(|| "0".to_string())
}

fn coin_balance(
    storage: &Arc<StateDB>,
    addr: &str,
    token: &str,
) -> Result<serde_json::Value, JsonRpcError> {
    let move_addr = move_core_types::account_address::AccountAddress::from_hex_literal(&format!(
        "0x{}",
        addr.trim_start_matches("0x")
    ))
    .map_err(|_| JsonRpcError {
        code: -32602,
        message: "Invalid address".into(),
    })?;

    let token = token.trim().to_ascii_uppercase();
    let (canonical_token, key) = match token.as_str() {
        "AIN" | "AINCORE" => ("AIN", move_coin_store_key(move_addr)),
        "WBTC" | "SYNTHETIC_WBTC" | "SYNTHETIC WBTC" => ("WBTC", wbtc_coin_store_key(move_addr)),
        _ => {
            return Err(JsonRpcError {
                code: -32602,
                message: "Unsupported token alias. Supported tokens: AIN, WBTC".into(),
            });
        }
    };

    Ok(serde_json::json!({
        "address": addr.trim_start_matches("0x"),
        "token": canonical_token,
        "balance": coin_store_balance(storage, key),
        "decimals": if canonical_token == "AIN" { 18 } else { 8 },
        "balance_source": "move_coin_store",
        "market_mode": if canonical_token == "WBTC" { "synthetic_test_asset_not_btc_backed" } else { "native_ain" }
    }))
}

fn estimate_payload_gas(payload: &str) -> u64 {
    let bytes = match hex::decode(payload.trim_start_matches("0x")) {
        Ok(bytes) => bytes,
        Err(_) => return 21_000,
    };
    match bcs::from_bytes::<vm_move::TransactionPayload>(&bytes) {
        Ok(vm_move::TransactionPayload::PublishModule(_)) => 500_000,
        Ok(vm_move::TransactionPayload::Script(_)) => 0,
        Ok(vm_move::TransactionPayload::EntryFunction(call)) => {
            let module = call.module.name().as_str();
            let function = call.function.as_str();
            match (module, function) {
                ("coin", "transfer") => 21_000,
                ("delegation", "delegate") | ("delegation", "undelegate") => 50_000,
                ("delegation", "claim_rewards") | ("delegation", "withdraw_unbonded") => 30_000,
                ("delegation", "enable_delegation") => 50_000,
                ("token_factory", "create_token") => 100_000,
                ("token_factory", "mint") | ("token_factory", "burn") => 40_000,
                ("token_factory", "transfer") => 25_000,
                ("dex", "create_pool") => 120_000,
                ("dex", "add_liquidity") | ("dex", "remove_liquidity") => 150_000,
                ("dex", "swap_x_to_y") | ("dex", "swap_y_to_x") => 120_000,
                ("universal_mining", "submit_mining_proof") => 200_000,
                _ => 100_000,
            }
        }
        Err(_) => 21_000,
    }
}

/// Net tracked supply. `sys:total_supply` is already NET of burns (it mirrors
/// the Move ValidatorSet.total_supply — mints added — and is decremented by
/// `burn_supply_trackers`). Despite the name, this is NOT gross minted.
fn total_minted_supply(storage: &Arc<StateDB>) -> u128 {
    storage
        .get("sys:total_supply")
        .ok()
        .flatten()
        .or_else(|| storage.get("total_supply").ok().flatten())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0)
}

/// SEC-#15: derive the public supply view from the NET tracked supply + the
/// cumulative burned total. Because the net supply already has burns removed,
/// `circulating == net` and gross `total_minted == net + burned`. The previous
/// RPC computed `circulating = net - burned`, subtracting burns a SECOND time
/// and under-reporting circulating supply by exactly `total_burned`.
/// Returns `(total_minted_gross, circulating)`.
fn supply_view(net_supply: u128, total_burned: u128) -> (u128, u128) {
    let total_minted = net_supply.saturating_add(total_burned);
    let circulating = net_supply;
    (total_minted, circulating)
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
    /// G4 S6: the sessions the network task holds.
    pub sessions: network::SessionTable,
    pub mempool: Arc<Mutex<mempool::Mempool>>,
    pub governance: Arc<Mutex<GovernanceManager>>,
    pub storage: Arc<StateDB>,
    /// B65: dry runs executing now (`DRY_RUNS_AT_ONCE` at most).
    pub dry_runs: Arc<AtomicUsize>,
}

/// B65: dry runs (`aincore_estimateGas`) executing at once. One executes
/// Move up to MAX_GAS_LIMIT; two at most leave the node's other cores to
/// consensus whatever the request rate (geth bounds `eth_estimateGas` by a
/// gas cap and a timeout for the same reason).
const DRY_RUNS_AT_ONCE: usize = 2;

/// A dry run's slot, given back when dropped.
struct DryRun(Arc<AtomicUsize>);

impl DryRun {
    fn begin(running: &Arc<AtomicUsize>) -> Option<Self> {
        let before = running.fetch_add(1, Ordering::SeqCst);
        let slot = DryRun(Arc::clone(running));
        (before < DRY_RUNS_AT_ONCE).then_some(slot)
    }
}

impl Drop for DryRun {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
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

/// Read the consensus state WITHOUT waiting for it.
///
/// The consensus loop holds this lock for whole block commits, measured at
/// ~2 s per block on the NAS's spinning disk. An RPC that WAITS for it parks an
/// actix worker for that long; the NAS runs 4 workers, so a handful of
/// concurrent calls froze the entire public RPC (`aincore_getStatus` was seen
/// hanging for 20-30 s). And a reader that holds the lock while doing slow work
/// blocks the consensus loop from taking it. So handlers take what they need
/// with `try_read`, drop the guard at once, and answer from storage or say
/// "busy" when the lock is held.
/// The block held at `height`, or an RPC error if it is not held (unknown,
/// or pruned).
fn held_block(storage: &StateDB, height: u64) -> Result<blockchain::Block, JsonRpcError> {
    let json = storage
        .get(&format!("block_{}", height))
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("storage error: {e}"),
        })?
        .ok_or_else(|| JsonRpcError {
            code: -32004,
            message: format!("block {height} is not held (unknown or pruned)"),
        })?;
    serde_json::from_str(&json).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("stored block {height} is unreadable: {e}"),
    })
}

/// The body extension of a held block. A client samples a few indices of one
/// block in a row, so the last few extensions are kept: an extension costs a
/// Reed-Solomon encode of the whole body.
fn extended_body(block: &blockchain::Block) -> Result<Arc<da::Extended>, JsonRpcError> {
    const KEEP: usize = 4;
    type Recent = Mutex<std::collections::VecDeque<(String, Arc<da::Extended>)>>;
    static RECENT: std::sync::OnceLock<Recent> = std::sync::OnceLock::new();
    let recent = RECENT.get_or_init(Default::default);
    let hash = &block.header.hash;
    if let Some((_, ext)) = recent
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .find(|(h, _)| h == hash)
    {
        return Ok(Arc::clone(ext));
    }
    let ext = Arc::new(da::Extended::new(&block.body_bytes()));
    // A held block passed check_commitments; a mismatch is local corruption,
    // and samples from it would not verify. Refuse rather than serve them.
    if ext.root() != block.header.da_root {
        return Err(JsonRpcError {
            code: -32000,
            message: format!(
                "held block {} does not match its DA root",
                block.header.height
            ),
        });
    }
    let mut recent = recent.lock().unwrap_or_else(|p| p.into_inner());
    if recent.len() == KEEP {
        recent.pop_front();
    }
    recent.push_back((hash.clone(), Arc::clone(&ext)));
    Ok(ext)
}

fn try_consensus(
    data: &AppState,
) -> Result<Option<std::sync::RwLockReadGuard<'_, DagConsensus>>, JsonRpcError> {
    match data.consensus.try_read() {
        Ok(guard) => Ok(Some(guard)),
        Err(std::sync::TryLockError::WouldBlock) => Ok(None),
        Err(std::sync::TryLockError::Poisoned(e)) => Err(JsonRpcError {
            code: -32000,
            message: format!("Consensus lock error: {}", e),
        }),
    }
}

fn consensus_busy() -> JsonRpcError {
    JsonRpcError {
        code: -32005,
        message: "Consensus is busy committing a block; retry shortly.".into(),
    }
}

/// Parameter positions that carry an account address, per method.
fn address_param_positions(method: &str) -> &'static [usize] {
    match method {
        "aincore_getBalance"
        | "aincore_getObject"
        | "aincore_getCoinBalance"
        | "aincore_getAccountNonce"
        | "aincore_getBtcBalance"
        | "aincore_getTransactionsByAddress"
        | "aincore_getDexLpBalance"
        | "aincore_getTokenBalance"
        | "aincore_getDelegations"
        | "aincore_getUnbondingDelegations"
        | "aincore_getValidatorPool" => &[0],
        "aincore_getDelegation" => &[0, 1],
        _ => &[],
    }
}

/// Accept `A1n…` wherever an address is taken. An `A1n` string must decode
/// with a valid checksum, so a typo is refused instead of silently reading an
/// empty account. Full 64-hex (optionally `0x`, any case) becomes the
/// canonical lowercase hex every storage key uses. Anything else passes
/// through unchanged, so existing callers see no difference.
fn normalize_address_params(
    method: &str,
    mut params: serde_json::Value,
) -> Result<serde_json::Value, JsonRpcError> {
    let positions = address_param_positions(method);
    if let Some(list) = params.as_array_mut() {
        for &i in positions {
            if let Some(serde_json::Value::String(s)) = list.get_mut(i) {
                let trimmed = s.trim();
                if trimmed.starts_with(crypto::A1N_PREFIX) {
                    *s = crypto::canonical_address_hex(trimmed).map_err(|e| JsonRpcError {
                        code: -32602,
                        message: format!("Invalid address: {}", e),
                    })?;
                } else if let Ok(hex) = crypto::canonical_address_hex(trimmed) {
                    *s = hex;
                }
            }
        }
    }
    Ok(params)
}

fn handle_rpc_method(
    method: &str,
    params: serde_json::Value,
    data: &AppState,
) -> Result<serde_json::Value, JsonRpcError> {
    let params = normalize_address_params(method, params)?;
    match method {
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
            //
            // Phase 5B.11 / PWN-007: canonicalization moved to the mempool
            // layer (Mempool::canonical_tx_hash) so dedup is consistent
            // across ALL entry points (this RPC, api.rs, P2P TX inbound).
            // The API layer just forwards a serialised string; correctness
            // does not depend on whether the encoding was already canonical.
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
                // B54: the signature and proof checks run before the mempool
                // lock (the consensus tick needs it); under it, only the
                // stateful gates.
                let checked = mempool::Mempool::check_admissible(&tx_str).map_err(|reason| JsonRpcError {
                    code: -32010,
                    message: format!("Transaction rejected by mempool: {}", reason),
                })?;
                let mut mempool = data.mempool.lock()
                    .map_err(|e| JsonRpcError { code: -32000, message: format!("Mempool lock error: {}", e) })?;
                // `tx_hash` is the key this transaction can be LOOKED UP by: blocks
                // index a transaction under `StateDB::raw_tx_hash` of the exact
                // string submitted. The mempool's own hash covers the signed
                // fields -- right for deduplication, but nothing is stored under
                // it, so returning it meant a client's receipt lookup said
                // "pending" forever. It is still returned, as `canonical_hash`.
                // B73: of the canonical encoding, the one the mempool keeps and
                // blocks carry.
                let lookup_hash =
                    StateDB::raw_tx_hash(&executor::admission::canonical_json(&checked.tx));
                match mempool.add_checked(tx_str, checked) {
                    Ok(canonical_hash) => Ok(serde_json::json!({
                        "status": "sent",
                        "tx_hash": lookup_hash,
                        "canonical_hash": canonical_hash,
                    })),
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
        // G3 FX-8: both wrote balances straight into this node's database,
        // outside consensus. That forks a multi-node network and would be an
        // unlimited mint on any chain that enabled it. Fund an account with a
        // signed transfer from a funded one instead.
        "aincore_faucet" | "aincore_testMintWbtc" => Err(JsonRpcError {
            code: -32030,
            message: format!(
                "{} was removed: it wrote balances outside consensus. Fund the account \
                 with a signed transfer (aincore_sendTransaction) from a funded account.",
                method
            ),
        }),
        "aincore_getCoinBalance" => {
            // params: [address, token]
            //
            // Reads the exact Move CoinStore balance for native AIN or the
            // Phase DEX synthetic WBTC test asset. This is intentionally
            // separate from legacy AccountData.balance.
            if let (Some(addr), Some(token)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            ) {
                coin_balance(&data.storage, addr, token)
            } else {
                Err(JsonRpcError {
                    code: -32602,
                    message: "Invalid params: [address, token]".into(),
                })
            }
        },
        "aincore_getStatus" => {
             // Never waits on the consensus lock (see `try_consensus`). While a
             // block is being committed the two in-memory fields come from
             // storage (or are null) and `consensus_busy` says so.
             let (node_id, current_round, consensus_busy, clock_drift_alarm) = match try_consensus(data)? {
                 Some(c) => (
                     serde_json::json!(c.node_id),
                     serde_json::json!(c.current_round),
                     false,
                     serde_json::json!(c.clock_drift_alarm()),
                 ),
                 None => (
                     serde_json::Value::Null,
                     match data.storage.get("latest_proposed_round") {
                         Ok(Some(r)) => r.parse::<u64>().map(|r| serde_json::json!(r)).unwrap_or(serde_json::Value::Null),
                         _ => serde_json::Value::Null,
                     },
                     true,
                     serde_json::Value::Null,
                 ),
             };
             // G4 S6: sessions, and how many of them name a committee member.
             let (peers_count, committee_sessions) = session_counts(&data.sessions);

             Ok(serde_json::json!({
                 "node_id": node_id,
                 "current_round": current_round,
                 "consensus_busy": consensus_busy,
                 // G5 BT-1: local clock − the chain's block time, in seconds,
                 // while this node's drift alarm holds; null otherwise.
                 "clock_drift_alarm_secs": clock_drift_alarm,
                 "peers_count": peers_count,
                 "committee_sessions": committee_sessions,
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
                 }
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
            // Verify the stored certificate against local epoch/committee
            // metadata. This is not a proof of execution or epoch transitions.
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
                                    match node::qc_rpc::verify(&data.storage, &qc, Some(h)) {
                                        Ok(()) => (true, String::new()),
                                        Err(e) => (false, e.to_string()),
                                    };
                                Ok(serde_json::json!({
                                    "available": true,
                                    "height": h,
                                    "verified": verified,
                                    "verification_scope": node::qc_rpc::VERIFICATION_SCOPE,
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
        "aincore_getStateProof" => {
            // G3 PF-1: params [key, height?]. The value of a consensus-state
            // key (or its absence) with a proof against the state root at
            // `height`, plus that block's header and quorum certificate. A
            // client verifies the proof against `quorum_certificate.state_root`
            // after verifying the QC itself (PF-2); `state_root` here is
            // informational. The default height is the latest one with a QC.
            let key = params.get(0).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Invalid params: [key, height?]".into(),
            })?;
            if storage::class::classify(key.as_bytes()) != Some(storage::class::KeyClass::State) {
                return Err(JsonRpcError {
                    code: -32602,
                    message: format!("{key} is not a consensus-state key; only those are proven"),
                });
            }
            let stored_u64 = |k: &str| {
                data.storage.get(k).ok().flatten().and_then(|s| s.parse::<u64>().ok())
            };
            let latest = state_commit::latest_version(&data.storage)
                .ok()
                .flatten()
                .ok_or_else(|| JsonRpcError { code: -32000, message: "no state tree yet".into() })?;
            // PF-3: nothing below the retention floor (S7 prunes under it).
            let floor = stored_u64("jmt:floor").unwrap_or(0);
            // A height that is present but not a u64 is refused, never
            // silently replaced by the latest one (PF-2.6).
            let height = match params.get(1) {
                None | Some(serde_json::Value::Null) => {
                    stored_u64("consensus:qc:latest_height").unwrap_or(latest)
                },
                Some(v) => v.as_u64().ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: format!("Invalid height {v}: expected an unsigned integer"),
                })?,
            };
            if height < floor || height > latest {
                return Err(JsonRpcError {
                    code: -32602,
                    message: format!("height {height} is outside the proven range {floor}..={latest}"),
                });
            }
            let (value, proof) = state_commit::wire_proof(&data.storage, key, height)
                .map_err(|e| JsonRpcError { code: -32000, message: format!("proof failed: {e}") })?;
            let state_root = state_commit::root(&data.storage, height)
                .map(|r| hex::encode(r.0))
                .map_err(|e| JsonRpcError { code: -32000, message: format!("root failed: {e}") })?;
            let header = data
                .storage
                .get(&format!("block_{height}"))
                .ok()
                .flatten()
                .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                .map(|block| block["header"].clone());
            let qc = data
                .storage
                .get(&format!("consensus:qc:{height}"))
                .ok()
                .flatten()
                .and_then(|json| serde_json::from_str::<consensus::qc::QuorumCertificate>(&json).ok());
            Ok(serde_json::json!({
                "key": key,
                "value": value.map(|v| String::from_utf8_lossy(&v).into_owned()),
                "height": height,
                "state_root": state_root,
                "proof": proof,
                "header": header,
                "quorum_certificate": qc,
            }))
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
            match node::qc_rpc::verify(&data.storage, &qc, None) {
                Err(node::qc_rpc::VerificationError::Unavailable(message)) => Err(JsonRpcError {
                    code: -32000,
                    message: message.into(),
                }),
                Ok(()) => Ok(serde_json::json!({
                    "valid": true,
                    "verification_scope": node::qc_rpc::VERIFICATION_SCOPE
                })),
                Err(e) => Ok(serde_json::json!({
                    "valid": false,
                    "error": e.to_string(),
                    "verification_scope": node::qc_rpc::VERIFICATION_SCOPE
                })),
            }
        },
        "aincore_getDag" => {
            let consensus = try_consensus(data)?.ok_or_else(consensus_busy)?;
            let dag = consensus.dag.lock().map_err(|e| JsonRpcError { code: -32000, message: format!("DAG lock error: {}", e) })?;

            // B54: the newest `MAX_DAG_VERTICES`, not the whole DAG cloned
            // under the consensus lock. B76: and at most `MAX_DAG_BYTES` of
            // payload (one vertex at least), copied under the locks and
            // serialized after them, so consensus writers do not wait on it.
            let mut newest: Vec<(u64, &String)> = dag.iter().map(|(h, v)| (v.round, h)).collect();
            newest.sort_unstable_by(|a, b| b.cmp(a));
            let mut vertices = Vec::new();
            let mut bytes = 0usize;
            for (_, h) in newest.into_iter().take(MAX_DAG_VERTICES) {
                let Some(v) = dag.get(h) else { continue };
                bytes = bytes.saturating_add(v.payload.iter().map(String::len).sum::<usize>());
                if bytes > MAX_DAG_BYTES && !vertices.is_empty() {
                    break;
                }
                vertices.push(v.clone());
            }
            drop(dag);
            drop(consensus);
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

                // Fallback to mempool check if not in a block (B54: by the
                // hash each transaction got at admission, nothing hashed under
                // the lock).
                let in_mempool = data
                    .mempool
                    .lock()
                    .ok()
                    .and_then(|mp| mp.pending_with_raw_hash(target_hash).map(str::to_string));

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
            // params: [limit]  OR  [limit, start_height]
            //
            // Phase 3.5 / H-03 fix: bridge backlog >100 blocks could silently skip
            // older finalized blocks because the original RPC only returned
            // "latest N". An optional `start_height` lets callers request a
            // specific block range. Backward compatible: if start_height
            // is missing, the old "latest N" behaviour is preserved.
            let limit = params.get(0).and_then(|v| v.as_u64()).unwrap_or(10);
            let limit = std::cmp::min(limit, MAX_QUERY_LIMIT); // S3: DoS prevention

            // Optional start_height parameter for range queries.
            let start_height_param = params.get(1).and_then(|v| v.as_u64());

            let latest_height: u64 = match data.storage.get("latest_height") {
                Ok(Some(h)) => h.parse::<u64>().unwrap_or_else(|e| {
                    println!("❌ [RPC] Failed to parse latest_height '{}': {}", h, e);
                    0
                }),
                Ok(None) => {
                    println!("⚠️ [RPC] latest_height key not found in storage");
                    0
                }
                Err(e) => {
                    println!("❌ [RPC] Storage error reading latest_height: {}", e);
                    0
                }
            };

            // Compute scan window.
            //   - If start_height provided: scan blocks `start_height ..= min(start_height+limit-1, latest_height)`.
            //     Returned in ASCENDING order (so callers can iterate forward).
            //   - Else (legacy): scan latest N blocks, DESCENDING (latest first).
            let mut blocks = Vec::new();
            match start_height_param {
                Some(start_height) => {
                    if start_height == 0 || start_height > latest_height {
                        println!(
                            "🔍 [RPC] getBlocks range: start={} out of range (latest={})",
                            start_height, latest_height
                        );
                        return Ok(serde_json::json!(blocks));
                    }
                    let end_height = std::cmp::min(
                        start_height.saturating_add(limit).saturating_sub(1),
                        latest_height,
                    );
                    println!(
                        "🔍 [RPC] getBlocks range: {}..={} (latest={})",
                        start_height, end_height, latest_height
                    );
                    let mut bytes = 0usize;
                    for i in start_height..=end_height {
                        let key = format!("block_{}", i);
                        if let Ok(Some(block_json)) = data.storage.get(&key) {
                            // B54: the answer stops at MAX_BLOCKS_BYTES (at
                            // least one block); the caller asks again from
                            // the next height.
                            bytes += block_json.len();
                            if bytes > MAX_BLOCKS_BYTES && !blocks.is_empty() {
                                break;
                            }
                            if let Ok(block_obj) =
                                serde_json::from_str::<serde_json::Value>(&block_json)
                            {
                                blocks.push(block_obj);
                            }
                        }
                    }
                }
                None => {
                    println!("🔍 [RPC] getBlocks latest: head={} limit={}", latest_height, limit);
                    let start_index = latest_height.saturating_sub(limit);
                    let mut bytes = 0usize;
                    for i in (start_index + 1..=latest_height).rev() {
                        let key = format!("block_{}", i);
                        if let Ok(Some(block_json)) = data.storage.get(&key) {
                            bytes += block_json.len();
                            if bytes > MAX_BLOCKS_BYTES && !blocks.is_empty() {
                                break;
                            }
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
            // B90: the sessions held, by PeerId and whether a committee key
            // names them; never an address (this answered any client with
            // the saved validators' addresses, a map for whoever wants to
            // flood them).
            let table = data.sessions.read().unwrap_or_else(|e| e.into_inner());
            let peer_list: Vec<serde_json::Value> = table
                .iter()
                .map(|s| serde_json::json!({ "peer_id": s.peer, "member": s.member.is_some() }))
                .collect();
            Ok(serde_json::json!(peer_list))
        },
        // S3: aincore_debug REMOVED — raw DB key scanner is a data exfiltration vector on mainnet
        "aincore_createProposal" => {
            // SECURITY (FIX-3): This handler previously mutated governance state
            // directly from an UNAUTHENTICATED `proposer` string param, bypassing
            // the Move VM, escrow and fee-burn in 0x1::governance. Disabled.
            // Governance must be driven by a signed transaction submitted via
            // aincore_sendTransaction, calling 0x1::governance::create_proposal,
            // so the mempool enforces Ed25519 signature + sender==derive_address(pubkey).
            Err(JsonRpcError {
                code: -32040,
                message: "aincore_createProposal disabled: submit a signed transaction calling 0x1::governance::create_proposal via aincore_sendTransaction".into(),
            })
        },
        "aincore_vote" => {
            // SECURITY (FIX-3): This handler previously cast a vote using an
            // UNAUTHENTICATED `voter` string param and derived the vote weight
            // from that CLAIMED address's on-chain balance, with no proof of key
            // ownership. An attacker could vote with any whale's full stake weight.
            // Disabled. Votes must be cast via a signed transaction submitted
            // through aincore_sendTransaction, calling 0x1::governance::vote, so
            // the mempool enforces Ed25519 signature + sender==derive_address(pubkey).
            Err(JsonRpcError {
                code: -32040,
                message: "aincore_vote disabled: submit a signed transaction calling 0x1::governance::vote via aincore_sendTransaction".into(),
            })
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
                 // SEC-#32: READ-ONLY. Previously this called the mutating tally(),
                 // letting any unauthenticated caller flip a proposal Active->Queued/
                 // Rejected and persist it. The status transition must be driven
                 // deterministically on-chain (epoch tick) — see governance-execution
                 // task. Here we only REPORT the current persisted status.
                 match governance.get_proposal(pid) {
                     Some(p) => Ok(serde_json::json!({ "id": pid, "status": p.status })),
                     None => Err(JsonRpcError { code: -32602, message: "Unknown proposal".into() }),
                 }
             } else {
                 Err(JsonRpcError { code: -32602, message: "Missing proposal ID".into() })
             }
        },
        "aincore_getGasPrice" => {
            // B15: the committed base fee, quanta per gas, as a string (it can
            // pass 2^53). A transaction needs at least this price.
            Ok(serde_json::json!(executor::committed_base_fee(&data.storage).to_string()))
        },
        "aincore_getMempoolStatus" => {
            let mempool = data.mempool.lock()
                .map_err(|e| JsonRpcError { code: -32000, message: format!("Mempool lock error: {}", e) })?;

            Ok(serde_json::json!({
                "status": "Active",
                "pending_tx_count": mempool.len() // Real count!
            }))
        },
        "aincore_getDaStatus" => {
            // params: [height?] (default: the tip). B1: the block's DA root and
            // the shard layout a light client samples within. A client checks
            // samples against the da_root of a header it holds under a QC,
            // never against this response.
            let height = match params.get(0) {
                Some(v) => v.as_u64().ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "Invalid params: [height?]".into(),
                })?,
                None => data.storage.get_chain_height(),
            };
            let block = held_block(&data.storage, height)?;
            let layout = da::Layout::of(block.body_bytes().len() as u64);
            Ok(serde_json::json!({
                "height": height,
                "block_hash": block.header.hash,
                "da_root": block.header.da_root,
                "body_len": layout.body_len,
                "data_shards": layout.data_shards,
                "total_shards": layout.total_shards(),
                "shard_size": layout.shard_size,
            }))
        },

        // ============ DELEGATION QUERY METHODS ============

        // G5 DL-2, DL-3: delegation lives in Move state (`0x1::delegation::Pool`
        // at the validator, `0x1::delegation::Book` at the delegator). Amounts
        // are base-unit strings; a ticket's amount is nominal (a slash of its
        // pool is applied when it is withdrawn).
        "aincore_getDelegation" => {
            // params: [delegator_address, validator_address]
            if let (Some(delegator), Some(validator)) = (
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str())
            ) {
                let position = executor::delegation_book(&data.storage, delegator).and_then(|book| {
                    book.positions
                        .into_iter()
                        .find(|p| p.validator.to_string() == validator)
                });
                let pool = executor::delegation_pool(&data.storage, validator);
                let (amount, pending, points) = match (pool, position) {
                    (Some(pool), Some(position)) => {
                        let (value, owed) = pool.position_value(&position);
                        (value, owed, position.points)
                    }
                    _ => (0, 0, 0),
                };
                Ok(serde_json::json!({
                    "amount": amount.to_string(),
                    "pending_rewards": pending.to_string(),
                    "points": points.to_string()
                }))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [delegator, validator]".into() })
            }
        },

        "aincore_getDelegations" => {
            // params: [delegator_address]; at most 8 positions (DL-3).
            if let Some(delegator) = params.get(0).and_then(|v| v.as_str()) {
                let positions = executor::delegation_book(&data.storage, delegator)
                    .map(|book| book.positions)
                    .unwrap_or_default();
                let delegations: Vec<serde_json::Value> = positions
                    .iter()
                    .map(|position| {
                        let validator = position.validator.to_string();
                        let (amount, pending) = executor::delegation_pool(&data.storage, &validator)
                            .map(|pool| pool.position_value(position))
                            .unwrap_or((0, 0));
                        serde_json::json!({
                            "validator": validator,
                            "amount": amount.to_string(),
                            "pending_rewards": pending.to_string()
                        })
                    })
                    .collect();
                Ok(serde_json::json!(delegations))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [delegator_address]".into() })
            }
        },

        "aincore_getUnbondingDelegations" => {
            // params: [delegator_address]; at most 16 tickets (DL-3).
            if let Some(delegator) = params.get(0).and_then(|v| v.as_str()) {
                let tickets = executor::delegation_book(&data.storage, delegator)
                    .map(|book| book.tickets)
                    .unwrap_or_default();
                let unbondings: Vec<serde_json::Value> = tickets
                    .iter()
                    .map(|ticket| {
                        let validator = ticket.validator.to_string();
                        let pool_slashed = executor::delegation_pool(&data.storage, &validator)
                            .map(|pool| pool.closed)
                            .unwrap_or(false);
                        serde_json::json!({
                            "validator": validator,
                            "amount": ticket.amount.to_string(),
                            "unlock_time": ticket.unlock_time,
                            "created_epoch": ticket.created_epoch,
                            "pool_slashed": pool_slashed
                        })
                    })
                    .collect();
                Ok(serde_json::json!(unbondings))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [delegator_address]".into() })
            }
        },

        "aincore_getValidatorPool" => {
            // params: [validator_address]
            if let Some(validator) = params.get(0).and_then(|v| v.as_str()) {
                let now = executor::committed_chain_clock(&data.storage).time;
                let active = live_validator_addresses(&data.storage).contains(validator);
                Ok(match executor::delegation_pool(&data.storage, validator) {
                    Some(pool) => validator_pool_json(&pool, now, active),
                    None => serde_json::json!({
                        "total_delegated": "0",
                        "commission_rate": 0,
                        "delegator_count": 0,
                        "is_accepting": false
                    }),
                })
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [validator_address]".into() })
            }
        },

        "aincore_getValidatorsWithDelegation" => {
            // No params: the live validators with an open pool.
            let now = executor::committed_chain_clock(&data.storage).time;
            let validators: Vec<serde_json::Value> = live_validator_addresses(&data.storage)
                .into_iter()
                .filter_map(|address| {
                    let pool = executor::delegation_pool(&data.storage, &address)?;
                    let mut entry = validator_pool_json(&pool, now, true);
                    entry["address"] = serde_json::json!(address);
                    Some(entry)
                })
                .collect();
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
            // No params, returns all tokens.
            // Phase 2.11: bounded scan, see aincore_getDelegations.
            let mut tokens = Vec::new();
            let prefix = "token:";
            const API_PREFIX_CAP: usize = 1000;
            for (_key_str, raw_value) in
                data.storage.scan_prefix_limited(prefix, API_PREFIX_CAP)
            {
                if let Ok(token_data) =
                    serde_json::from_str::<serde_json::Value>(&raw_value)
                {
                    tokens.push(token_data);
                }
            }

            Ok(serde_json::json!(tokens))
        },

        "aincore_getDexPools" => {
            let registry = decode_dex_registry(&data.storage);
            let pools: Vec<serde_json::Value> = registry
                .pools
                .iter()
                .map(|info| dex_pool_json(&data.storage, info))
                .collect();
            Ok(serde_json::json!(pools))
        },

        "aincore_getDexPool" => {
            let registry = decode_dex_registry(&data.storage);
            let pool = find_dex_pool_info(
                &registry,
                params.get(0).and_then(|v| v.as_str()),
                params.get(1).and_then(|v| v.as_str()),
            );
            Ok(pool
                .map(|info| dex_pool_json(&data.storage, info))
                .unwrap_or_else(|| serde_json::json!(null)))
        },

        "aincore_getDexLpBalance" => {
            // params: [address, pool_addr?] or [address, token_x, token_y].
            // With only address, defaults to the canonical Phase DEX AIN/WBTC
            // test market. Balance source is the Move LPToken<X,Y> resource.
            let Some(address) = params.get(0).and_then(|v| v.as_str()) else {
                return Err(JsonRpcError { code: -32602, message: "Invalid params: [address, pool_addr?] or [address, token_x, token_y]".into() });
            };
            dex_lp_balance_json(
                &data.storage,
                address,
                params.get(1).and_then(|v| v.as_str()),
                params.get(2).and_then(|v| v.as_str()),
            )
        },

        "aincore_getDexQuote" => {
            let token_in = params.get(0).and_then(|v| v.as_str());
            let token_out = params.get(1).and_then(|v| v.as_str());
            let amount_in = params.get(2).and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<u128>().ok())
                    .or_else(|| v.as_u64().map(|n| n as u128))
            });
            let (Some(token_in), Some(token_out), Some(amount_in)) = (token_in, token_out, amount_in) else {
                return Err(JsonRpcError { code: -32602, message: "Invalid params: [token_in, token_out, amount_in]".into() });
            };
            let Some(pool_key) = canonical_pool_key(token_in, token_out) else {
                return Err(JsonRpcError { code: -32602, message: "Invalid token pair".into() });
            };

            let registry = decode_dex_registry(&data.storage);
            let Some(info) = registry.pools.iter().find(|info| {
                String::from_utf8_lossy(&info.pool_key) == pool_key
            }) else {
                return Ok(serde_json::json!({ "status": "pool_not_found" }));
            };

            let token_x_name = String::from_utf8_lossy(&info.token_x_name).to_string();
            let token_y_name = String::from_utf8_lossy(&info.token_y_name).to_string();
            let pool = dex_pool_key(info.pool_addr, &token_x_name, &token_y_name)
                .and_then(|key| data.storage.get(&key).ok().flatten())
                .and_then(|hex_value| hex::decode(hex_value).ok())
                .and_then(|bytes| bcs::from_bytes::<DexLiquidityPool>(&bytes).ok());
            let Some(pool) = pool else {
                return Ok(serde_json::json!({ "status": "pool_state_missing" }));
            };

            let normalized_in = normalize_type_name(token_in);
            let normalized_x = normalize_type_name(&token_x_name);
            let (reserve_in, reserve_out, direction) = if normalized_in == normalized_x {
                (pool.coin_x.value, pool.coin_y.value, "x_to_y")
            } else {
                (pool.coin_y.value, pool.coin_x.value, "y_to_x")
            };
            let amount_out = dex_quote(amount_in, reserve_in, reserve_out, pool.fee_bp);
            Ok(serde_json::json!({
                "status": if amount_out.is_some() { "ok" } else { "unavailable" },
                "pool_key": pool_key,
                "pool_addr": info.pool_addr.to_string(),
                "direction": direction,
                "amount_in": amount_in.to_string(),
                "amount_out": amount_out.map(|v| v.to_string()),
                "fee_bp": pool.fee_bp,
                "reserve_in": reserve_in.to_string(),
                "reserve_out": reserve_out.to_string()
            }))
        },

        "aincore_getDexSpotPrice" => {
            let token_in = params.get(0).and_then(|v| v.as_str());
            let token_out = params.get(1).and_then(|v| v.as_str());
            let unit_amount_in = params.get(2).and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse::<u128>().ok())
                    .or_else(|| v.as_u64().map(|n| n as u128))
            })
            .unwrap_or(1_000_000_000_000_000_000u128);

            let (Some(token_in), Some(token_out)) = (token_in, token_out) else {
                return Err(JsonRpcError { code: -32602, message: "Invalid params: [token_in, token_out, unit_amount_in?]".into() });
            };

            let quote = handle_rpc_method(
                "aincore_getDexQuote",
                serde_json::json!([token_in, token_out, unit_amount_in.to_string()]),
                data,
            )?;
            Ok(dex_spot_price_json(token_in, token_out, unit_amount_in, quote))
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

            // Genesis writes sys:total_supply; keep total_supply as a legacy fallback only.
            // SEC-#15: sys:total_supply is already NET of burns, so circulating == net
            // and gross total_minted == net + burned. Do NOT subtract burns again.
            let net_supply = total_minted_supply(&data.storage);
            let total_burned = match data.storage.get("total_burned") {
                Ok(Some(s)) => s.parse::<u128>().unwrap_or(0),
                _ => 0,
            };
            let (total_minted, circulating) = supply_view(net_supply, total_burned);
            // G5 DOC-1: the emission draws 1.90 %/yr of what remains of the
            // cap, by consensus time; there is no per-block reward.
            let emission = executor::emission_view(&data.storage);

            Ok(serde_json::json!({
                "max_supply": max_supply.to_string(),
                "total_minted": total_minted.to_string(),
                "total_burned": total_burned.to_string(),
                "circulating_supply": circulating.to_string(),
                "remaining_reserve": emission.remaining.to_string(),
                "emission_rate_per_year": EMISSION_RATE_PER_YEAR,
                "last_reward_time": emission.last_reward_time,
                "decimals": 18
            }))
        },

        "aincore_getTransactionReceipt" => {
            // params: [tx_hash]
            if let Some(tx_hash) = params.get(0).and_then(|v| v.as_str()) {
                let execution_receipt = stored_tx_receipt(&data.storage, tx_hash);
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
                    // Pending only if THIS transaction is still waiting. The old
                    // check was "is the mempool non-empty", which reported every
                    // unknown hash as pending whenever anyone had a tx queued.
                    let in_mempool = data
                        .mempool
                        .lock()
                        .map(|mp| mp.pending_with_raw_hash(tx_hash).is_some())
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

        "aincore_estimateGas" => {
            // params: [tx_object] or [payload_string].
            // B65: a whole transaction (its signature zero-filled at the
            // scheme's length) runs against the current state, and the answer
            // is what it would use: Move execution, its writes' I/O, the state
            // bytes it adds priced at the most the byte gas can reach two
            // blocks on (x 81/64: a transaction usually executes in the next
            // block or the one after), and its own bytes (B14). A payload
            // alone cannot run (no sender), so it gets the per-function table
            // and no write cost.
            let price = executor::committed_base_fee(&data.storage);
            if let Some(object) = params.get(0).filter(|v| v.is_object()) {
                let Some(_slot) = DryRun::begin(&data.dry_runs) else {
                    return Err(JsonRpcError {
                        code: -32005,
                        message: "estimates are busy; retry".into(),
                    });
                };
                // B84: on a fresh VM, as a block runs (`execute_block_parallel`),
                // so it runs the code on chain now: a VM that lived as long as
                // the node kept its module cache across upgrades, and grew
                // with every module estimated.
                let estimate = executor::Executor::new(Arc::clone(&data.storage))
                    .estimate_gas(&object.to_string())
                    .map_err(|e| JsonRpcError { code: -32602, message: format!("Invalid params: {e}") })?;
                if let Some(reason) = &estimate.aborted {
                    return Err(JsonRpcError {
                        code: -32000,
                        message: format!("the transaction would abort: {reason}"),
                    });
                }
                let byte_gas = estimate.state_byte_gas;
                let execution =
                    estimate.execution_gas_at(byte_gas.saturating_mul(81).div_ceil(64));
                let mut zero_limit = object.clone();
                zero_limit["gas_limit"] = serde_json::json!(0);
                let gas = executor::admission::gas_limit_covering(zero_limit.to_string().len(), execution);
                return Ok(serde_json::json!({
                    "estimated_gas": gas,
                    "execution_gas": execution,
                    "intrinsic_gas": gas.saturating_sub(execution),
                    "vm_gas": estimate.vm_gas,
                    "io_gas": estimate.writes.io_gas,
                    "new_state_bytes": estimate.writes.new_bytes,
                    "state_byte_gas": byte_gas,
                    "includes_writes": true,
                    "gas_price": price.to_string(),
                    "estimated_fee": (gas as u128).saturating_mul(price).to_string()
                }));
            }
            let payload = params.get(0).and_then(|v| v.as_str()).unwrap_or_default().to_string();
            // A signed Ed25519 transfer's JSON without its payload: ~420 bytes.
            const ENVELOPE_BYTES: usize = 420;
            let execution = estimate_payload_gas(&payload);
            let intrinsic = executor::admission::intrinsic_gas(payload.len() + ENVELOPE_BYTES);
            let gas = execution.saturating_add(intrinsic);
            Ok(serde_json::json!({
                "estimated_gas": gas,
                "execution_gas": execution,
                "intrinsic_gas": intrinsic,
                "includes_writes": false,
                "gas_price": price.to_string(),
                "estimated_fee": (gas as u128).saturating_mul(price).to_string()
            }))
        },

        "aincore_getBlockByHash" => {
            // params: [block_hash]
            if let Some(target_hash) = params.get(0).and_then(|v| v.as_str()) {
                // B58: the block whose own header hash this is. A substring
                // test matched the child too (its `prev_hash`), and any
                // fragment matched every block.
                let target = target_hash.trim().trim_start_matches("0x").to_ascii_lowercase();
                if target.len() != 64 || !target.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(JsonRpcError { code: -32602, message: "Invalid params: block_hash must be 64 hex characters".into() });
                }
                let needle = format!("\"hash\":\"{target}\"");
                let latest_height = data.storage.get_chain_height();
                let mut found_block = None;

                // Search recent blocks (last 1000) for matching hash
                let search_start = latest_height.saturating_sub(1000);
                for h in (search_start..=latest_height).rev() {
                    let key = format!("block_{}", h);
                    if let Ok(Some(block_json)) = data.storage.get(&key) {
                        if block_json.contains(&needle) {
                            if let Ok(block_obj) = serde_json::from_str::<serde_json::Value>(&block_json) {
                                let own = block_obj["header"]["hash"].as_str().unwrap_or_default();
                                if own.eq_ignore_ascii_case(&target) {
                                    found_block = Some(block_obj);
                                    break;
                                }
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

        "aincore_getBootstrap" => {
            // G5 A4 BW-10: the bootstrap weight as the chain holds it, with
            // the owned stake P and the target the next boundary would compute
            // now (the executor's own functions). Whole AIN throughout.
            let Some(report) = executor::bootstrap_report(&data.storage) else {
                return Ok(serde_json::json!({ "active": false }));
            };
            let whole = |v: u128| u64::try_from(v).unwrap_or(u64::MAX);
            Ok(serde_json::json!({
                "active": !report.state.operators.is_empty(),
                "s_min_ain": report.state.s_min,
                "bootstrap_ain": report.state.total(),
                "ceiling_ain": report.state.ceilings(),
                "owned_stake_ain": whole(report.owned_stake),
                "target_ain": whole(report.target),
                "operators": report.state.operators,
            }))
        },
        "aincore_getEconomics" => {
            // G5 DOC-1: the economics as the chain runs them, from Move state.
            let burn_percentage = data.storage.get_burn_percentage();
            let latest_height = data.storage.get_chain_height();
            let max_supply: u128 = 150_000_000 * 1_000_000_000_000_000_000;
            let emission = executor::emission_view(&data.storage);
            let clock = executor::committed_chain_clock(&data.storage);
            let (epoch_blocks, reward_period, max_block_interval_secs) =
                executor::pinned_chain_params(&data.storage).unwrap_or((0, 0, 0));

            Ok(serde_json::json!({
                "emission_model": EMISSION_MODEL,
                "emission_rate_per_year": EMISSION_RATE_PER_YEAR,
                "max_supply": max_supply.to_string(),
                "total_minted": emission.minted.to_string(),
                "remaining_reserve": emission.remaining.to_string(),
                "last_reward_time": emission.last_reward_time,
                "consensus_time": clock.time,
                "reward_period_blocks": reward_period,
                "epoch_blocks": epoch_blocks,
                "max_block_interval_secs": max_block_interval_secs,
                "burn_percentage": burn_percentage,
                "block_height": latest_height
            }))
        },

        "aincore_sampleDA" => {
            // params: [height, index]. B1: shard `index` of the block's body
            // extension with its inclusion proof (`da::verify_sample`). The
            // client picks the indices itself, uniformly at random.
            let (Some(height), Some(index)) = (
                params.get(0).and_then(|v| v.as_u64()),
                params.get(1).and_then(|v| v.as_u64()),
            ) else {
                return Err(JsonRpcError { code: -32602, message: "Invalid params: [height, index]".into() });
            };
            let block = held_block(&data.storage, height)?;
            let extended = extended_body(&block)?;
            let sample = extended.sample(index).ok_or_else(|| JsonRpcError {
                code: -32602,
                message: format!(
                    "index {index} is past the last shard ({} shards)",
                    extended.layout().total_shards()
                ),
            })?;
            Ok(serde_json::json!({
                "height": height,
                "block_hash": block.header.hash,
                "da_root": block.header.da_root,
                "sample": sample,
            }))
        },

        "aincore_getFederationKey" => {
            let key = data.storage.get_federation_key();
            Ok(serde_json::json!({ "federation_key": key }))
        },

        "aincore_getTransactionsByAddress" => {
            // params: [address, limit (optional)]
            if let Some(address) = params.get(0).and_then(|v| v.as_str()) {
                let limit = std::cmp::min(params.get(1).and_then(|v| v.as_u64()).unwrap_or(20), MAX_QUERY_LIMIT) as usize;
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
                    1 => Some(SignatureScheme::MlDsa65),
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
                    Err(JsonRpcError { code: -32602, message: "Invalid scheme: 0=Ed25519, 1=ML-DSA-65, 2=Secp256k1".into() })
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [scheme, pubkey_hex, message_hex, signature_hex]".into() })
            }
        },

        // B47: `aincore_verifyVDF` (client-sized work: 2^64 - 1 iterations
        // aborted the node), `aincore_verifyProof` (answered "proof_accepted"
        // for any bytes) and `aincore_aggregateBLS` (a placeholder) are gone:
        // nothing on chain uses them.
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
                        "address_a1n": crypto::hex_to_a1n(&address).ok(),
                        "format": "hex(SHA256(pubkey))"
                    })),
                    Err(e) => Err(JsonRpcError { code: -32000, message: format!("Derivation error: {}", e) })
                }
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [public_key_hex]".into() })
            }
        },

        "aincore_getStateClassStats" => {
            // G3 WG-1 is enforced (S3): `state_outside_block` counts the
            // consensus-state writes the gate refused.
            let stats = data.storage.db.state_class_stats();
            Ok(serde_json::json!({
                "mode": "enforce",
                "writes": stats.writes,
                "unclassified": stats.unclassified,
                "state_outside_block": stats.state_outside_block,
                "samples": stats.samples.iter().map(|x| serde_json::json!({
                    "pattern": x.pattern,
                    "violation": x.violation,
                    "context": x.context,
                    "count": x.count,
                })).collect::<Vec<_>>(),
            }))
        },

        "aincore_formatAddress" => {
            // params: [address in any accepted form] → both display forms.
            let Some(input) = params.get(0).and_then(|v| v.as_str()) else {
                return Err(JsonRpcError { code: -32602, message: "Invalid params: [address]".into() });
            };
            match crypto::parse_address(input) {
                Ok(bytes) => Ok(serde_json::json!({
                    "hex": hex::encode(bytes),
                    "a1n": crypto::to_a1n(&bytes),
                })),
                Err(e) => Err(JsonRpcError { code: -32602, message: format!("Invalid address: {}", e) }),
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

    // B59: a bounded prefix (a request may carry 2 MiB of params).
    let shown: String = params.to_string().chars().take(256).collect();
    println!("📥 JSON-RPC Request: {} {}", method, shown);

    // B65: a dry run executes Move, so it runs on the blocking pool, not on
    // this worker (`DRY_RUNS_AT_ONCE` bounds how many).
    let result = if method == "aincore_estimateGas" {
        let state = data.clone();
        match web::block(move || handle_rpc_method("aincore_estimateGas", params, &state)).await {
            Ok(result) => result,
            Err(_) => Err(JsonRpcError {
                code: -32603,
                message: "the estimate failed".into(),
            }),
        }
    } else {
        handle_rpc_method(method, params, &data)
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
        return HttpResponse::BadRequest().body(format!(
            "Invalid height: {} exceeds maximum {}",
            query.height, MAX_BLOCK_HEIGHT
        ));
    }

    let current_height = data.storage.get_chain_height();
    if query.height > current_height {
        return HttpResponse::NotFound().body(format!(
            "Block not found: height {} exceeds chain tip {}",
            query.height, current_height
        ));
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
            println!(
                "⚠️ [API] get_latest_blocks: 'latest_height' key not found or error. Returning empty."
            );
            return HttpResponse::Ok().json(serde_json::json!([]));
        }
    };

    println!(
        "🔍 [API] get_latest_blocks: Head={}, Limit={}",
        latest_height, limit
    );

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
            }
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

    let validator_list: Vec<serde_json::Value> = validators
        .into_iter()
        .map(|(pubkey, stake)| {
            serde_json::json!({
                "address": pubkey, // ID/PubKey
                "stake": stake,
                "status": "Active"
            })
        })
        .collect();

    let total_staked: u64 = validator_list
        .iter()
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
    // Copy what is needed and release both locks BEFORE the storage scan below:
    // holding the consensus read lock across 20 block reads blocked the
    // consensus loop from taking its write lock, from a public endpoint.
    let (peer_count, committee_sessions) = session_counts(&data.sessions);
    let (node_id, current_round) = match data.consensus.try_read() {
        Ok(c) => (
            serde_json::json!(c.node_id),
            serde_json::json!(c.current_round),
        ),
        Err(std::sync::TryLockError::Poisoned(e)) => {
            let c = e.into_inner();
            (
                serde_json::json!(c.node_id),
                serde_json::json!(c.current_round),
            )
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            (serde_json::Value::Null, serde_json::Value::Null)
        }
    };
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
    // Block timestamps are unix SECONDS (the BFT median of vertex timestamps).
    // This used to divide by 1000 as if they were milliseconds, reporting a TPS
    // a thousand times too high.
    let tps = if end_time > start_time {
        total_txs as f64 / end_time.saturating_sub(start_time) as f64
    } else {
        0.0
    };

    let info = serde_json::json!({
        "node_id": node_id,
        "version": "0.1.0-alpha",
        "peer_count": peer_count,
        "committee_sessions": committee_sessions,
        "latest_block": height,
        "current_round": current_round,
        "tps": tps,
        // The chain this node actually runs. It used to say "AINCORE Mainnet
        // (Prototype)" on every network, including the public testnet.
        "network": blockchain::chain_id(),
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

/// G4 S6: the sessions held, and how many name a committee member.
fn session_counts(sessions: &network::SessionTable) -> (usize, usize) {
    let table = sessions.read().unwrap_or_else(|e| e.into_inner());
    (
        table.len(),
        table.iter().filter(|s| s.member.is_some()).count(),
    )
}

/// B59: the key the RPC rate limit counts a request against. Behind a local
/// proxy every client is 127.0.0.1, so one client spent everyone's budget.
/// When the operator names the header its proxy sets
/// (`AINCORE_RPC_CLIENT_IP_HEADER`, e.g. `CF-Connecting-IP` behind a
/// Cloudflare tunnel), a request counts under that header's address.
///
/// B74: only from a proxy the operator names (`AINCORE_RPC_TRUSTED_PROXIES`,
/// comma-separated addresses): any loopback peer used to be trusted, and a
/// socket proxy on loopback passes the client's own header through. The
/// header's last element is taken (the hop the proxy appended; a client
/// writes the first). An IPv6 client counts by its /64 (one host holds
/// 2^64 addresses), and keys fall into `RATE_LIMIT_BUCKETS` buckets by a
/// per-process random hash, so the limiter's map, which actix-governor never
/// shrinks, holds at most that many entries.
#[derive(Clone)]
struct ClientIp {
    header: Option<String>,
    trusted: Vec<std::net::IpAddr>,
    buckets: std::collections::hash_map::RandomState,
}

/// B74: the rate limiter's keys at most (a choice: a few MB of state; two
/// clients share a budget with probability 1 / 65,536, not one an attacker
/// can aim, the hash key being random).
const RATE_LIMIT_BUCKETS: u32 = 1 << 16;

/// B74: the address a request counts under: the trusted proxy's last
/// forwarded hop, else the peer; an IPv6 address by its /64.
fn client_address(
    peer: std::net::IpAddr,
    header: Option<&str>,
    trusted: &[std::net::IpAddr],
) -> std::net::IpAddr {
    use std::net::{IpAddr, Ipv6Addr};
    let client = if trusted.contains(&peer) {
        header
            .and_then(|h| h.rsplit(',').next()?.trim().parse().ok())
            .unwrap_or(peer)
    } else {
        peer
    };
    match client {
        IpAddr::V4(_) => client,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

impl ClientIp {
    fn from_env() -> Self {
        let header = std::env::var("AINCORE_RPC_CLIENT_IP_HEADER")
            .ok()
            .filter(|h| !h.trim().is_empty());
        let trusted: Vec<std::net::IpAddr> = std::env::var("AINCORE_RPC_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|a| a.trim().parse().ok())
            .collect();
        if header.is_some() && trusted.is_empty() {
            eprintln!(
                "⚠️ AINCORE_RPC_CLIENT_IP_HEADER is ignored: name the proxy that sets it \
                 in AINCORE_RPC_TRUSTED_PROXIES"
            );
        }
        Self {
            header,
            trusted,
            buckets: Default::default(),
        }
    }

    fn address(&self, req: &actix_web::dev::ServiceRequest) -> Option<std::net::IpAddr> {
        let peer = req.peer_addr()?.ip();
        let header = self
            .header
            .as_deref()
            .and_then(|name| req.headers().get(name)?.to_str().ok());
        Some(client_address(peer, header, &self.trusted))
    }
}

impl KeyExtractor for ClientIp {
    type Key = u32;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(
        &self,
        req: &actix_web::dev::ServiceRequest,
    ) -> Result<Self::Key, Self::KeyExtractionError> {
        use std::hash::BuildHasher;
        let address = self
            .address(req)
            .ok_or_else(|| SimpleKeyExtractionError::new("no peer address"))?;
        Ok((self.buckets.hash_one(address) % u64::from(RATE_LIMIT_BUCKETS)) as u32)
    }
}

pub async fn start_api_server(
    api_port: u16,
    consensus: Arc<RwLock<DagConsensus>>,
    sessions: network::SessionTable,
    mempool: Arc<Mutex<mempool::Mempool>>,
    storage: Arc<StateDB>,
    governance: Arc<Mutex<GovernanceManager>>,
) -> std::io::Result<()> {
    println!("🌐 Starting REST API server on port {}...", api_port);

    let app_state = web::Data::new(AppState {
        consensus,
        sessions,
        mempool,
        governance,
        storage,
        dry_runs: Arc::default(),
    });

    // M1: Rate limiter — 100 requests/second per IP, burst up to 200.
    // Mirrors the config in api.rs so the LIVE server is throttled.
    // NOTE: actix-governor 0.4 `per_second(n)` = replenish one cell every n
    // SECONDS, so per_second(100) throttled every IP to ~1 req/100s after a 200
    // burst — a frontend-bricking bug. per_millisecond(10) = true 100 req/s.
    let client_ip = ClientIp::from_env();
    let governor_conf = GovernorConfigBuilder::default()
        .key_extractor(client_ip)
        .per_millisecond(10)
        .burst_size(200)
        .finish()
        .expect("governor config is valid");

    // M1: Bind address — default to loopback only; operators must opt into a
    // wider interface (e.g. 0.0.0.0) explicitly via AINCORE_RPC_BIND.
    let bind_host = std::env::var("AINCORE_RPC_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    println!(
        "🔒 RPC bind host: {} (override with AINCORE_RPC_BIND), rate limit: 100 req/s burst 200",
        bind_host
    );

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
                    .app_data(app_state.clone())
                    .route("/health", web::get().to(health))
                    .route("/metrics", web::get().to(metrics_handler))
                    .service(
                        web::resource("/rpc")
                            .app_data(web::JsonConfig::default().limit(2 * 1024 * 1024))
                            .route(web::post().to(json_rpc_handler)),
                    )
                    .route("/get_chain_height", web::get().to(get_chain_height_handler))
                    .route("/get_block", web::get().to(get_block_handler))
                    .route(
                        "/get_latest_blocks",
                        web::get().to(get_latest_blocks_handler),
                    )
                    .route("/get_validators", web::get().to(get_validators_handler))
                    .route("/get_network_info", web::get().to(get_network_info_handler))
                    .route("/get_transaction", web::get().to(get_transaction_handler))
            })
            .bind((bind_host.as_str(), api_port))?
            .run(),
        )
        .await
}

#[cfg(test)]
mod qc_rpc_tests {
    use super::*;
    fn state(db: Arc<StateDB>) -> AppState {
        super::tests::test_state(db)
    }
    include!("qc_rpc_tests.rs");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::Mutex;

    /// Writes a CoinStore balance straight into the test database.
    fn seed_coin(db: &StateDB, key: String, value: u128) {
        let coin = bcs::to_bytes(&MoveCoin { value }).unwrap();
        let _seed = db.seeding();
        db.put(&key, &hex::encode(coin)).expect("seed a balance");
    }

    fn move_address(address: &str) -> move_core_types::account_address::AccountAddress {
        move_core_types::account_address::AccountAddress::from_hex_literal(&format!(
            "0x{}",
            address
        ))
        .unwrap()
    }

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = storage::test_dir::process_dir().join(format!(
            "aincore_phase05_api_{}_{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(path.to_str().expect("utf8 temp path")).expect("test DB opens"))
    }

    pub(super) fn test_state(db: Arc<StateDB>) -> AppState {
        let executor = Arc::new(executor::Executor::new(Arc::clone(&db)));
        let consensus = Arc::new(RwLock::new(consensus::DagConsensus::new(
            "node_test".to_string(),
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::clone(&executor),
            Arc::clone(&db),
            None,
            [3u8; 32],
        )));
        let sessions: network::SessionTable = Arc::default();
        let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(
            &db,
        ))));
        AppState {
            consensus,
            sessions,
            mempool: Arc::new(Mutex::new(mempool::Mempool::new())),
            governance,
            storage: db,
            dry_runs: Arc::default(),
        }
    }

    /// B65 witness: at most DRY_RUNS_AT_ONCE estimates execute at once; the
    /// next is told to retry, and a finished one frees its slot.
    #[test]
    fn dry_runs_are_bounded() {
        let state = test_state(temp_db("b65_dry_runs"));
        let held: Vec<_> = (0..DRY_RUNS_AT_ONCE)
            .map(|_| DryRun::begin(&state.dry_runs).expect("a free slot"))
            .collect();
        let tx = serde_json::json!({ "sender": "ab" });
        let err = handle_rpc_method("aincore_estimateGas", serde_json::json!([tx]), &state)
            .expect_err("busy");
        assert_eq!(err.code, -32005);
        drop(held);
        let err = handle_rpc_method("aincore_estimateGas", serde_json::json!([tx]), &state)
            .expect_err("a malformed transaction");
        assert_eq!(err.code, -32602, "{}", err.message);
        assert_eq!(state.dry_runs.load(Ordering::SeqCst), 0);
    }

    /// B65 witness: `aincore_estimateGas` on a whole transaction runs it, so a
    /// transfer to an address with no coins is estimated with the CoinStore
    /// it creates, and the transaction signed with the estimate executes.
    #[test]
    fn the_gas_estimate_covers_the_writes_a_transaction_makes() {
        use ed25519_dalek::Signer;
        let db = temp_db("b65_estimate");
        executor::test_support::load_stdlib(&db);
        let key = SigningKey::from_bytes(&[71u8; 32]);
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        executor::test_support::set_ain_balance(&db, &sender, 10u128.pow(21));
        {
            // An account that has sent before, so the new state is the
            // recipient's CoinStore alone (the negative control below).
            let _seed = db.seeding();
            db.put_object(&aa::AccountManager::create_account(
                sender.clone(),
                public_key.clone(),
            ))
            .unwrap();
        }
        let recipient = "ab".repeat(32);
        let state = test_state(Arc::clone(&db));
        let ain = move_core_types::language_storage::TypeTag::Struct(Box::new(
            move_core_types::language_storage::StructTag {
                address: move_core_types::account_address::AccountAddress::ONE,
                module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                type_params: vec![],
            },
        ));
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![ain],
            args: vec![
                bcs::to_bytes(&move_address(&sender)).unwrap(),
                bcs::to_bytes(&move_address(&recipient)).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        };
        let payload =
            hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap());
        let chain_id = blockchain::chain_id();
        let tx = serde_json::json!({
            "chain_id": chain_id,
            "sender": sender,
            "input_objects": [],
            "payload": payload,
            "args": [],
            "gas_limit": 0,
            "gas_price": 1,
            "sequence_number": 0,
            "public_key": public_key,
            "signature": "00".repeat(64),
        });
        let answer = handle_rpc_method("aincore_estimateGas", serde_json::json!([tx]), &state)
            .expect("an estimate");
        assert_eq!(answer["includes_writes"], true);
        assert!(
            answer["new_state_bytes"].as_u64().unwrap() > 0,
            "the recipient's CoinStore is new state"
        );
        let field = |name: &str| answer[name].as_u64().unwrap();
        let byte_gas = field("state_byte_gas");
        assert_eq!(
            field("execution_gas"),
            field("vm_gas")
                + field("io_gas")
                + field("new_state_bytes") * (byte_gas * 81).div_ceil(64),
            "the new bytes at the byte gas two blocks on"
        );
        let gas = answer["estimated_gas"].as_u64().unwrap();
        let sign = |gas: u64| {
            let mut tx = tx.clone();
            tx["gas_limit"] = serde_json::json!(gas);
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                chain_id, sender, payload, 0, gas, 1, ""
            );
            tx["signature"] =
                serde_json::json!(hex::encode(key.sign(message.as_bytes()).to_bytes()));
            tx.to_string()
        };
        let status = |raw: &str| {
            let (updates, _) = executor::Executor::new(Arc::clone(&db))
                .execute_transaction(raw)
                .expect("executes");
            let receipt = updates
                .iter()
                .find(|(k, _)| k.starts_with("tx_receipt:"))
                .and_then(|(_, v)| v.clone())
                .expect("a receipt");
            serde_json::from_str::<serde_json::Value>(&receipt).unwrap()["status"].clone()
        };
        // Control: the estimate less the new bytes' share is not enough.
        let state_part = answer["new_state_bytes"].as_u64().unwrap()
            * answer["state_byte_gas"].as_u64().unwrap();
        assert_eq!(status(&sign(gas - state_part)), "aborted");
        let raw = sign(gas);
        let checked = executor::admission::check_stateless(&raw, &chain_id).expect("admitted");
        assert_eq!(
            checked.execution_gas,
            answer["execution_gas"].as_u64().unwrap(),
            "the estimate is the limit's execution part exactly"
        );
        assert_eq!(status(&raw), "success");

        // B84: each estimate runs the code on chain now: once `coin` is gone
        // the estimate fails (a VM living as long as the node ran its cached
        // copy).
        {
            let _seed = db.seeding();
            db.delete(&vm_move::state_keys::module_key(
                &move_core_types::account_address::AccountAddress::ONE,
                "coin",
            ))
            .unwrap();
        }
        let err = handle_rpc_method("aincore_estimateGas", serde_json::json!([tx]), &state)
            .expect_err("coin is no longer on chain");
        assert_ne!(err.code, -32005, "{}", err.message);
    }

    /// B58 witness: a block's hash finds that block, not its child (whose
    /// `prev_hash` holds it), and a fragment of a hash finds nothing.
    #[test]
    fn a_block_hash_finds_its_own_block() {
        let db = temp_db("block_by_hash");
        let (parent, child) = ("ab".repeat(32), "cd".repeat(32));
        let mut first = blockchain::Block::new(1, 1, "genesis".into(), vec![], "n".into());
        first.header.hash = parent.clone();
        let mut second = blockchain::Block::new(2, 2, parent.clone(), vec![], "n".into());
        second.header.hash = child;
        let seed = db.seeding();
        db.put("block_1", &serde_json::to_string(&first).unwrap())
            .unwrap();
        db.put("block_2", &serde_json::to_string(&second).unwrap())
            .unwrap();
        db.put("latest_height", "2").unwrap();
        drop(seed);
        let state = test_state(db);
        let found = handle_rpc_method(
            "aincore_getBlockByHash",
            serde_json::json!([parent]),
            &state,
        )
        .unwrap();
        assert_eq!(found["header"]["height"], 1);
        assert!(
            handle_rpc_method("aincore_getBlockByHash", serde_json::json!(["ab"]), &state).is_err()
        );
    }

    /// B54 witness: `getDag` returns the newest `MAX_DAG_VERTICES`, not the
    /// whole DAG cloned under the consensus lock; `getBlocks` stops at
    /// `MAX_BLOCKS_BYTES` (one block at least).
    #[test]
    fn dag_and_block_answers_are_bounded() {
        let db = temp_db("bounded_answers");
        let state = test_state(Arc::clone(&db));
        {
            let consensus = state.consensus.read().unwrap();
            let mut dag = consensus.dag.lock().unwrap();
            for round in 1..=(MAX_DAG_VERTICES as u64 + 44) {
                let v = blockchain::Vertex::new(round, "a".into(), vec![], vec![]);
                dag.insert(format!("{round:064x}"), v);
            }
        }
        let dag = handle_rpc_method("aincore_getDag", serde_json::json!([]), &state).unwrap();
        let rounds: Vec<u64> = dag
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["round"].as_u64().unwrap())
            .collect();
        assert_eq!(rounds.len(), MAX_DAG_VERTICES);
        assert_eq!(rounds[0], MAX_DAG_VERTICES as u64 + 44, "the newest first");

        // B76: three newer vertices of 3 MiB payload each pass 8 MiB at the
        // third: two come back, the newest first.
        {
            let consensus = state.consensus.read().unwrap();
            let mut dag = consensus.dag.lock().unwrap();
            for round in 1000..1003u64 {
                let v =
                    blockchain::Vertex::new(round, "a".into(), vec![], vec!["x".repeat(3 << 20)]);
                dag.insert(format!("{round:064x}"), v);
            }
        }
        let dag = handle_rpc_method("aincore_getDag", serde_json::json!([]), &state).unwrap();
        let rounds: Vec<u64> = dag
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["round"].as_u64().unwrap())
            .collect();
        assert_eq!(
            rounds,
            vec![1002, 1001],
            "the payload bytes stop the answer"
        );

        let big = "x".repeat(3 << 20);
        let seed = db.seeding();
        for h in 1..=3u64 {
            let block = serde_json::json!({ "header": { "height": h }, "transactions": [big] });
            db.put(&format!("block_{h}"), &block.to_string()).unwrap();
        }
        db.put("latest_height", "3").unwrap();
        drop(seed);
        let blocks =
            handle_rpc_method("aincore_getBlocks", serde_json::json!([10, 1]), &state).unwrap();
        assert_eq!(
            blocks.as_array().unwrap().len(),
            2,
            "three 3 MiB blocks pass 8 MiB at the third"
        );
    }

    /// B59 witness: behind the operator's proxy, with its header named, each
    /// client is counted under its own address; a header from any other
    /// peer is ignored (it is the client's to forge), as it is with no header
    /// named. B74: a loopback peer the operator did not name is such a peer
    /// (a socket proxy passes the client's header through); the last hop is
    /// taken; an IPv6 client counts by its /64; the keys are bounded.
    #[test]
    fn the_rate_limit_counts_each_client_behind_a_proxy() {
        let request = |peer: &str, header: Option<&str>| {
            let mut req = actix_web::test::TestRequest::default().peer_addr(peer.parse().unwrap());
            if let Some(ip) = header {
                req = req.insert_header(("CF-Connecting-IP", ip));
            }
            req.to_srv_request()
        };
        let proxy: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let named = ClientIp {
            header: Some("CF-Connecting-IP".into()),
            trusted: vec![proxy],
            buckets: Default::default(),
        };
        let untrusted = ClientIp {
            trusted: vec![],
            ..named.clone()
        };
        let unnamed = ClientIp {
            header: None,
            ..named.clone()
        };
        let addr = |x: &ClientIp, req| x.address(&req).unwrap().to_string();
        assert_eq!(
            addr(&named, request("127.0.0.1:5000", Some("203.0.113.7"))),
            "203.0.113.7"
        );
        assert_eq!(addr(&named, request("127.0.0.1:5000", None)), "127.0.0.1");
        assert_eq!(
            addr(&named, request("198.51.100.9:5000", Some("203.0.113.7"))),
            "198.51.100.9"
        );
        assert_eq!(
            addr(&unnamed, request("127.0.0.1:5000", Some("203.0.113.7"))),
            "127.0.0.1"
        );
        // B74: a loopback peer that is not the named proxy is not trusted.
        assert_eq!(
            addr(&untrusted, request("127.0.0.1:5000", Some("203.0.113.7"))),
            "127.0.0.1"
        );
        // B74: the hop the proxy appended, not the client's first element.
        assert_eq!(
            addr(
                &named,
                request("127.0.0.1:5000", Some("1.2.3.4, 203.0.113.7"))
            ),
            "203.0.113.7"
        );
        // B74: an IPv6 client by its /64, a mapped IPv4 as IPv4.
        let v6 = |ip: &str| client_address(ip.parse().unwrap(), None, &[]).to_string();
        assert_eq!(v6("2001:db8:1:2:aaaa::1"), v6("2001:db8:1:2:ffff::9"));
        assert_ne!(v6("2001:db8:1:2::1"), v6("2001:db8:1:3::1"));
        assert_eq!(v6("::ffff:203.0.113.7"), "203.0.113.7");
        // B74: keys fall in RATE_LIMIT_BUCKETS buckets, one per address.
        let key = |req| named.extract(&req).unwrap();
        let a = key(request("127.0.0.1:5000", Some("203.0.113.7")));
        assert_eq!(a, key(request("127.0.0.1:6000", Some("203.0.113.7"))));
        let keys: std::collections::HashSet<u32> = (0..5_000u32)
            .map(|i| {
                let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i).to_string();
                key(request("127.0.0.1:5000", Some(&ip)))
            })
            .collect();
        assert!(keys.iter().all(|k| *k < RATE_LIMIT_BUCKETS));
        assert!(
            keys.len() > 4_500,
            "distinct clients mostly get distinct keys"
        );
    }

    /// B90 witness: `aincore_getPeers` names the sessions, never an address,
    /// though saved peer addresses exist.
    #[test]
    fn get_peers_gives_no_addresses() {
        let db = temp_db("get_peers");
        {
            let _seed = db.seeding();
            db.save_peer_addr("12D3KooWsaved", "/ip4/192.0.2.1/tcp/9101")
                .unwrap();
        }
        let state = test_state(Arc::clone(&db));
        state.sessions.write().unwrap().push(network::SessionPeer {
            peer: "12D3KooWlive".into(),
            member: Some("ab".repeat(32)),
        });
        let peers = handle_rpc_method("aincore_getPeers", serde_json::json!([]), &state).unwrap();
        assert_eq!(
            peers,
            serde_json::json!([{ "peer_id": "12D3KooWlive", "member": true }])
        );
        assert!(!peers.to_string().contains("192.0.2.1"));
    }

    /// B47 witness: the demonstration crypto methods are gone (the VDF one
    /// ran a client-chosen number of iterations; the proof one accepted any
    /// bytes).
    #[test]
    fn demo_crypto_methods_are_not_served() {
        let state = test_state(temp_db("demo_crypto"));
        for (method, params) in [
            ("aincore_verifyVDF", serde_json::json!(["00", "00", 1])),
            ("aincore_verifyProof", serde_json::json!(["snark", "00"])),
            ("aincore_aggregateBLS", serde_json::json!([["00"]])),
        ] {
            let answer = handle_rpc_method(method, params, &state);
            assert_eq!(answer.err().map(|e| e.code), Some(-32601), "{method}");
        }
    }

    /// The consensus loop holds its lock for whole block commits (~2 s on the
    /// NAS). An RPC must never wait for it: a few concurrent waiters froze the
    /// whole public RPC. Here another thread holds the write lock for 2 s,
    /// exactly as during a commit; the old code waited out all 2 s.
    #[test]
    fn rpc_never_waits_on_a_held_consensus_lock() {
        let db = temp_db("consensus_busy");
        db.put("latest_proposed_round", "42").unwrap();
        let state = test_state(db);

        // Control: lock free -> the live fields, and not flagged busy.
        let free = handle_rpc_method("aincore_getStatus", serde_json::json!([]), &state).unwrap();
        assert_eq!(free["consensus_busy"], false);
        assert_eq!(free["node_id"], "node_test");

        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let consensus = Arc::clone(&state.consensus);
        let holder = std::thread::spawn(move || {
            let _commit = consensus.write().unwrap();
            held_tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_secs(2));
        });
        held_rx.recv().unwrap();
        let t0 = std::time::Instant::now();
        let busy = handle_rpc_method("aincore_getStatus", serde_json::json!([]), &state).unwrap();
        let dag = handle_rpc_method("aincore_getDag", serde_json::json!([]), &state);
        let elapsed = t0.elapsed();
        holder.join().unwrap();

        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "an RPC waited {elapsed:?} on the consensus lock"
        );
        assert_eq!(busy["consensus_busy"], true);
        assert_eq!(
            busy["current_round"], 42,
            "a busy status must still answer from storage"
        );
        assert_eq!(dag.unwrap_err().code, -32005);
    }

    /// The contract a tester relies on end to end: the hash
    /// `aincore_sendTransaction` returns is the hash `aincore_getTransactionReceipt`
    /// finds -- "pending" while queued, and at its block once included. It used
    /// to return a hash over the signed fields, under which nothing is stored,
    /// so the receipt said "pending" forever.
    #[test]
    fn the_hash_send_returns_is_the_hash_the_receipt_is_found_under() {
        let db = temp_db("send_lookup");
        let state = test_state(Arc::clone(&db));

        use ed25519_dalek::Signer;
        let key = SigningKey::from_bytes(&[91u8; 32]);
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let chain_id = blockchain::chain_id();
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![
                9, 1,
            ]]))
            .unwrap(),
        );
        // A limit that covers the transaction's bytes (B14) with room to run.
        let (seq, gas_limit, gas_price) = (0u64, 1_000_000u64, 1u128);
        let message = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            chain_id, sender, payload, seq, gas_limit, gas_price, ""
        );
        let tx = serde_json::json!({
            "chain_id": chain_id,
            "sender": sender,
            "input_objects": [],
            "payload": payload,
            "args": [],
            "gas_limit": gas_limit,
            "gas_price": gas_price,
            "sequence_number": seq,
            "public_key": public_key,
            "signature": hex::encode(key.sign(message.as_bytes()).to_bytes()),
        })
        .to_string();

        let sent = handle_rpc_method("aincore_sendTransaction", serde_json::json!([tx]), &state)
            .expect("a signed transaction is admitted");
        let hash = sent["tx_hash"].as_str().unwrap().to_string();
        let receipt = |h: &str| {
            handle_rpc_method(
                "aincore_getTransactionReceipt",
                serde_json::json!([h]),
                &state,
            )
            .unwrap()
        };
        assert_eq!(
            receipt(&hash)["status"],
            "pending",
            "the returned hash is not the one it is pending under"
        );
        // Control: an unknown hash is not "pending" merely because this tx is queued.
        assert_eq!(receipt(&"00".repeat(32))["status"], "not_found");

        // B73: a block carries the canonical encoding the mempool kept.
        let kept = executor::admission::canonicalize(&tx).unwrap();
        let block = serde_json::json!({ "header": {}, "transactions": [kept] }).to_string();
        db.save_block_json(1, &block).unwrap();
        assert_eq!(
            receipt(&hash)["block_height"],
            1,
            "once included, the returned hash does not find its block"
        );
    }

    /// G3 FX-8: the faucet and the test WBTC mint wrote balances straight
    /// into this node's database, outside consensus. Both are gone: the RPC
    /// names answer with an explanation, and nothing is written.
    #[test]
    fn the_direct_write_faucets_are_removed_and_write_nothing() {
        let db = temp_db("faucet_removed");
        let state = test_state(Arc::clone(&db));
        let signing_key = SigningKey::from_bytes(&[34u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let address = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
        for method in ["aincore_faucet", "aincore_testMintWbtc"] {
            let err = handle_rpc_method(
                method,
                serde_json::json!([address, "1000", public_key]),
                &state,
            )
            .expect_err("the direct-write RPC is removed");
            assert_eq!(err.code, -32030, "{method}");
            assert!(
                err.message.contains("was removed"),
                "{method}: {}",
                err.message
            );
        }
        let key = |k: String| db.get(&k).unwrap();
        assert_eq!(key(move_coin_store_key(move_address(&address))), None);
        assert_eq!(key(wbtc_coin_store_key(move_address(&address))), None);
        assert!(db.get_object(&address).is_none(), "no account was created");
    }

    /// G5 DL-2, DL-3: the delegation RPCs read the Move state, the pool at
    /// the validator and the book at the delegator. They used to read keys
    /// nothing wrote, and always answered zero.
    #[test]
    fn the_delegation_rpcs_read_the_move_pool_and_book() {
        let db = temp_db("s3_delegation_rpc");
        let (validator, delegator) = (format!("{:064x}", 0xa1), format!("{:064x}", 0xd1));
        let ain: u128 = 1_000_000_000_000_000_000;
        let pool = executor::DelegationPool {
            active_coins: 2 * ain,
            active_points: 2 * ain,
            reward_counter: ain / 2,
            reward_carry: 0,
            unbonding_coins: 3 * ain,
            principal: 5 * ain,
            rewards: ain,
            commission_rate: 1_000,
            pending_commission: 1_500,
            commission_effective_time: 100,
            closed: false,
            slash_count: 0,
            ticket_count: 1,
            position_count: 1,
            slash_events: vec![],
        };
        let book = executor::DelegationBook {
            positions: vec![executor::DelegationPosition {
                validator: move_address(&validator),
                points: 2 * ain,
                reward_snapshot: 0,
            }],
            tickets: vec![executor::DelegationTicket {
                validator: move_address(&validator),
                amount: 3 * ain,
                created_epoch: 4,
                slash_seq: 0,
                unlock_time: 9_000,
            }],
        };
        let clock = executor::ChainClock {
            height: 10,
            time: 200,
            block_timestamp: 1_000,
        };
        {
            let _seed = db.seeding();
            let put = |address: &str, tag: &str, bytes: Vec<u8>| {
                db.put(
                    &vm_move::state_keys::resource_key_str(&move_address(address), tag),
                    &hex::encode(bytes),
                )
                .unwrap();
            };
            put(
                &validator,
                "0x1::delegation::Pool",
                bcs::to_bytes(&pool).unwrap(),
            );
            put(
                &delegator,
                "0x1::delegation::Book",
                bcs::to_bytes(&book).unwrap(),
            );
            put(
                &format!("{:064x}", 1),
                "0x1::chain::Clock",
                bcs::to_bytes(&clock).unwrap(),
            );
            db.put(
                "sys:validator_set:v1",
                &serde_json::json!([{ "address": validator, "stake": 1_002 }]).to_string(),
            )
            .unwrap();
        }
        let state = test_state(Arc::clone(&db));
        let rpc = |method: &str, params: serde_json::Value| {
            handle_rpc_method(method, params, &state).expect(method)
        };

        // The pending raise took effect at 100; the clock reads 200.
        let pool_json = rpc("aincore_getValidatorPool", serde_json::json!([validator]));
        assert_eq!(pool_json["total_delegated"], "2000000000000000000");
        assert_eq!(pool_json["commission_rate"], 1_500);
        assert_eq!(pool_json["delegator_count"], 1);
        assert_eq!(pool_json["unbonding"], "3000000000000000000");
        assert_eq!(pool_json["rewards_held"], "1000000000000000000");
        assert_eq!(pool_json["is_accepting"], true);
        // Owed: 2e18 points x 0.5e18 / 1e18 = 1e18.
        let one = rpc(
            "aincore_getDelegation",
            serde_json::json!([delegator, validator]),
        );
        assert_eq!(one["amount"], "2000000000000000000");
        assert_eq!(one["pending_rewards"], "1000000000000000000");
        let all = rpc("aincore_getDelegations", serde_json::json!([delegator]));
        assert_eq!(all[0]["validator"], validator);
        assert_eq!(all[0]["amount"], "2000000000000000000");
        let unbonding = rpc(
            "aincore_getUnbondingDelegations",
            serde_json::json!([delegator]),
        );
        assert_eq!(unbonding[0]["amount"], "3000000000000000000");
        assert_eq!(unbonding[0]["unlock_time"], 9_000);
        assert_eq!(unbonding[0]["pool_slashed"], false);
        let listed = rpc("aincore_getValidatorsWithDelegation", serde_json::json!([]));
        assert_eq!(listed[0]["address"], validator);
        // A stranger has nothing.
        let none = rpc(
            "aincore_getDelegation",
            serde_json::json!([format!("{:064x}", 0xee), validator]),
        );
        assert_eq!(none["amount"], "0");
    }

    /// G5 A4 BW-10: getBootstrap reports what the state holds: s_min, the
    /// bootstrap weight, owned stake (live weight minus bootstrap weight),
    /// the target and each operator; a chain without bootstrap says so.
    #[test]
    fn get_bootstrap_reports_the_state() {
        #[derive(serde::Serialize)]
        struct Config {
            validator_addr: [u8; 32],
            stake: u128,
            public_key: Vec<u8>,
            bls_public_key: Vec<u8>,
            bls_pop: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        struct Set {
            validators: Vec<Config>,
            unbonding_queue: Vec<u8>,
            total_supply: u128,
            current_epoch: u64,
        }
        let db = temp_db("rpc_bootstrap");
        let state = test_state(Arc::clone(&db));
        let none =
            handle_rpc_method("aincore_getBootstrap", serde_json::json!([]), &state).unwrap();
        assert_eq!(none, serde_json::json!({ "active": false }));
        let (a, b, c) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        let ain: u128 = 1_000_000_000_000_000_000;
        {
            let _seed = db.seeding();
            db.put(
                executor::BOOTSTRAP_KEY,
                &serde_json::to_string(&executor::BootstrapState {
                    s_min: 10_000,
                    genesis_ceilings: 3_000,
                    full_since: None,
                    operators: vec![executor::BootstrapOperator {
                        address: a.clone(),
                        entity: a.clone(),
                        ceiling: 3_000,
                        weight: 2_500,
                        score: 900_000,
                    }],
                })
                .unwrap(),
            )
            .unwrap();
            // The live set: a owns 1,000 with its bootstrap weight, b owns
            // 6,000, c holds a seat the Move set no longer has.
            db.put(
                "sys:validator_set:v1",
                &serde_json::json!([
                    { "address": a, "stake": 3_500, "ed25519_public_key": "",
                      "bls_public_key": "", "bls_pop": "" },
                    { "address": b, "stake": 6_000, "ed25519_public_key": "",
                      "bls_public_key": "", "bls_pop": "" },
                    { "address": c, "stake": 9_000, "ed25519_public_key": "",
                      "bls_public_key": "", "bls_pop": "" },
                ])
                .to_string(),
            )
            .unwrap();
            let config = |who: &str, stake_ain: u128| Config {
                validator_addr: hex::decode(who).unwrap().try_into().unwrap(),
                stake: stake_ain * ain,
                public_key: vec![],
                bls_public_key: vec![],
                bls_pop: vec![],
            };
            db.put(
                &vm_move::state_keys::resource_key_str(
                    &move_address(&format!("{:064x}", 1)),
                    "0x1::staking::ValidatorSet",
                ),
                &hex::encode(
                    bcs::to_bytes(&Set {
                        validators: vec![config(&a, 1_000), config(&b, 6_000)],
                        unbonding_queue: vec![],
                        total_supply: 7_000 * ain,
                        current_epoch: 0,
                    })
                    .unwrap(),
                ),
            )
            .unwrap();
        }
        let r = handle_rpc_method("aincore_getBootstrap", serde_json::json!([]), &state).unwrap();
        assert_eq!(r["active"], true);
        assert_eq!(r["s_min_ain"], 10_000);
        assert_eq!(r["bootstrap_ain"], 2_500);
        assert_eq!(r["ceiling_ain"], 3_000);
        // P is owned stake in the Move set (1,000 + 6,000), not the live
        // weights less bootstrap weight (c's 9,000 has no Move stake).
        assert_eq!(r["owned_stake_ain"], 7_000);
        assert_eq!(
            r["target_ain"], 3_000,
            "the next boundary refills to the ceiling"
        );
        assert_eq!(r["operators"][0]["score"], 900_000);
    }

    /// G5 DOC-1: the supply and economics RPCs report the Move emission
    /// state: the remaining reserve (the cap minus net supply and burns),
    /// the last payout's consensus time, the rate and the pinned parameters,
    /// and nothing of a halving.
    #[test]
    fn the_economics_rpcs_report_the_move_emission_state() {
        #[derive(serde::Serialize)]
        struct Set {
            validators: Vec<u8>,
            unbonding_queue: Vec<u8>,
            total_supply: u128,
            current_epoch: u64,
        }
        let db = temp_db("doc1_economics");
        let ain: u128 = 1_000_000_000_000_000_000;
        {
            let _seed = db.seeding();
            let put = |tag: &str, bytes: Vec<u8>| {
                db.put(
                    &vm_move::state_keys::resource_key_str(
                        &move_address(&format!("{:064x}", 1)),
                        tag,
                    ),
                    &hex::encode(bytes),
                )
                .unwrap();
            };
            put(
                "0x1::staking::ValidatorSet",
                bcs::to_bytes(&Set {
                    validators: vec![],
                    unbonding_queue: vec![],
                    total_supply: 2_000_000 * ain,
                    current_epoch: 3,
                })
                .unwrap(),
            );
            put(
                "0x1::staking::SupplyStats",
                bcs::to_bytes(&(500 * ain)).unwrap(),
            );
            put(
                "0x1::staking::EmissionState",
                bcs::to_bytes(&4_242u64).unwrap(),
            );
            put(
                "0x1::chain::Params",
                bcs::to_bytes(&(1_000u64, 20u64, 14u64)).unwrap(),
            );
            put(
                "0x1::chain::Clock",
                bcs::to_bytes(&(77u64, 4_300u64, 9_000u64)).unwrap(),
            );
        }
        let state = test_state(Arc::clone(&db));
        let remaining = (150_000_000 * ain - 2_000_500 * ain).to_string();
        let supply = handle_rpc_method("aincore_getSupply", serde_json::json!([]), &state).unwrap();
        assert_eq!(supply["remaining_reserve"], remaining);
        assert_eq!(supply["last_reward_time"], 4_242);
        assert_eq!(supply["emission_rate_per_year"], "0.019");
        let economics =
            handle_rpc_method("aincore_getEconomics", serde_json::json!([]), &state).unwrap();
        assert_eq!(economics["remaining_reserve"], remaining);
        assert_eq!(economics["total_minted"], (2_000_500 * ain).to_string());
        assert_eq!(economics["consensus_time"], 4_300);
        assert_eq!(
            (
                economics["epoch_blocks"].clone(),
                economics["reward_period_blocks"].clone()
            ),
            (serde_json::json!(1_000), serde_json::json!(20))
        );
        for reply in [supply, economics] {
            assert!(
                !reply.to_string().to_lowercase().contains("halving"),
                "{reply}"
            );
        }
    }

    /// Every address form reads the same account; a mistyped `A1n` is refused
    /// instead of silently reading an empty one.
    #[test]
    fn a1n_and_hex_addresses_read_the_same_account() {
        let db = temp_db("a1n_address");
        let signing_key = SigningKey::from_bytes(&[44u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let address = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
        let move_addr = move_core_types::account_address::AccountAddress::from_hex_literal(
            &format!("0x{}", address),
        )
        .unwrap();
        let coin = bcs::to_bytes(&MoveCoin {
            value: 7_000_000_000_000_000_000,
        })
        .unwrap();
        let _seed = db.seeding();
        db.put(&move_coin_store_key(move_addr), &hex::encode(coin))
            .expect("seed a balance");
        let state = test_state(Arc::clone(&db));
        let a1n = crypto::hex_to_a1n(&address).unwrap();

        let balance = |addr: &str| {
            handle_rpc_method(
                "aincore_getCoinBalance",
                serde_json::json!([addr, "AIN"]),
                &state,
            )
            .map(|v| v["balance"].clone())
        };
        let expected = serde_json::json!("7000000000000000000");
        assert_eq!(balance(&address).unwrap(), expected, "control: plain hex");
        assert_eq!(balance(&a1n).unwrap(), expected, "A1n");
        assert_eq!(
            balance(&format!(" {} ", a1n)).unwrap(),
            expected,
            "pasted with spaces"
        );
        assert_eq!(
            balance(&address.to_uppercase()).unwrap(),
            expected,
            "upper-case hex"
        );
        assert_eq!(
            balance(&format!("0x{}", address)).unwrap(),
            expected,
            "0x hex"
        );

        let by_a1n = handle_rpc_method("aincore_getBalance", serde_json::json!([a1n]), &state)
            .expect("getBalance by A1n");
        assert_eq!(by_a1n["move_balance"], expected);

        // One wrong character: refused, never an empty account.
        let mut typo: Vec<char> = a1n.chars().collect();
        typo[10] = if typo[10] == 'x' { 'y' } else { 'x' };
        let typo: String = typo.into_iter().collect();
        let err = balance(&typo).expect_err("typo refused");
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("Invalid address"), "{}", err.message);
        // getBalance answers any unknown string with an empty account, so only
        // the A1n gate stands between a typo and a false "balance: 0".
        let err = handle_rpc_method("aincore_getBalance", serde_json::json!([typo]), &state)
            .expect_err("typo must not read as an empty account");
        assert_eq!(err.code, -32602);
        assert!(err.message.contains("checksum"), "{}", err.message);

        // Non-address object ids still pass through unchanged.
        let obj = handle_rpc_method(
            "aincore_getObject",
            serde_json::json!(["proposal-7"]),
            &state,
        )
        .expect("legacy id passes through");
        assert!(obj.is_null());

        let derived = handle_rpc_method(
            "aincore_deriveAddress",
            serde_json::json!([public_key]),
            &state,
        )
        .expect("derive");
        assert_eq!(derived["address"], serde_json::json!(address));
        assert_eq!(derived["address_a1n"], serde_json::json!(a1n));

        let formatted =
            handle_rpc_method("aincore_formatAddress", serde_json::json!([a1n]), &state)
                .expect("format");
        assert_eq!(formatted["hex"], serde_json::json!(address));
        assert_eq!(formatted["a1n"], serde_json::json!(a1n));
        assert_eq!(
            handle_rpc_method("aincore_formatAddress", serde_json::json!(["0x1"]), &state)
                .expect_err("short hex is not an account address")
                .code,
            -32602
        );
    }

    /// G3 WG-1 runtime witness (S3b review): every RPC method, called with a
    /// spread of parameter shapes, writes no consensus state and no
    /// unclassified key. The method list is read from this file, so a new RPC
    /// is covered without editing this test.
    #[test]
    fn no_rpc_method_writes_consensus_state() {
        let source = include_str!("api_local.rs");
        let start = source.find("fn handle_rpc_method(").unwrap();
        let end = start + source[start..].find("\n}\n").unwrap();
        let mut methods = std::collections::BTreeSet::new();
        for line in source[start..end].lines().map(str::trim) {
            if !line.starts_with('"') {
                continue;
            }
            let Some(arrow) = line.find("=>") else {
                continue;
            };
            for token in line[..arrow].split('|') {
                let name = token.trim().trim_matches('"');
                if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    methods.insert(name.to_string());
                }
            }
        }
        assert!(
            methods.len() > 40,
            "positive control: {} methods",
            methods.len()
        );
        let db = temp_db("rpc_wg1");
        {
            let _seed = db.seeding();
            db.put("sys:chain_id", "AINCORE-TEST").unwrap();
            db.put(&format!("obj:{}", "ab".repeat(32)), "{}").unwrap();
        }
        let v0 = state_commit::seed_genesis(&db).unwrap();
        db.write_batch(v0.batch).unwrap();
        let state = test_state(Arc::clone(&db));
        let before = db.db.state_class_stats();
        let addr = "ab".repeat(32);
        for method in &methods {
            for params in [
                serde_json::json!([]),
                serde_json::json!([addr]),
                serde_json::json!([addr, "AIN"]),
                serde_json::json!([1]),
                serde_json::json!(["sys:chain_id"]),
                serde_json::json!([{}]),
            ] {
                let _ = handle_rpc_method(method, params, &state);
            }
        }
        let after = db.db.state_class_stats();
        assert_eq!(after.state_outside_block, before.state_outside_block);
        assert_eq!(after.unclassified, before.unclassified);
    }

    /// G3 PF-1: the proof RPC answers a present and an absent key with
    /// proofs the client verifier accepts against the root, and refuses
    /// non-state keys and heights outside the proven range.
    #[test]
    fn the_state_proof_rpc_answers_with_verifiable_proofs() {
        let db = temp_db("state_proof_rpc");
        {
            let _seed = db.seeding();
            db.put("sys:chain_id", "AINCORE-TEST").unwrap();
            db.put(&format!("obj:{}", "ab".repeat(32)), "{}").unwrap();
        }
        let v0 = state_commit::seed_genesis(&db).unwrap();
        db.write_batch(v0.batch).unwrap();
        let state = test_state(Arc::clone(&db));
        let call = |params| handle_rpc_method("aincore_getStateProof", params, &state);
        let check = |answer: &serde_json::Value, key: &str, value: Option<&[u8]>| {
            let root = state_proof::parse_hash(answer["state_root"].as_str().unwrap()).unwrap();
            let proof: state_proof::WireProof =
                serde_json::from_value(answer["proof"].clone()).unwrap();
            state_proof::verify(&root, key, value, &proof)
        };

        let present = call(serde_json::json!(["sys:chain_id"])).unwrap();
        assert_eq!(present["value"], "AINCORE-TEST");
        assert_eq!(present["height"], 0);
        assert_eq!(
            check(&present, "sys:chain_id", Some(b"AINCORE-TEST")),
            Ok(())
        );
        assert!(check(&present, "sys:chain_id", Some(b"forged")).is_err());

        let absent = call(serde_json::json!(["sys:config:burn_percentage", 0])).unwrap();
        assert!(absent["value"].is_null());
        assert_eq!(check(&absent, "sys:config:burn_percentage", None), Ok(()));

        assert!(
            call(serde_json::json!(["latest_height"])).is_err(),
            "not a state key"
        );
        assert!(
            call(serde_json::json!(["sys:chain_id", 5])).is_err(),
            "above the tree"
        );
        // PF-2.6: a malformed height is refused, never read as "latest".
        for bad in [
            serde_json::json!("0"),
            serde_json::json!(-1),
            serde_json::json!(0.5),
            serde_json::json!([0]),
        ] {
            let err = call(serde_json::json!(["sys:chain_id", bad])).unwrap_err();
            assert_eq!(err.code, -32602, "{bad}");
        }
        assert_eq!(
            call(serde_json::json!(["sys:chain_id", null])).unwrap()["height"],
            0
        );
        db.put("jmt:floor", "1").unwrap();
        assert!(
            call(serde_json::json!(["sys:chain_id", 0])).is_err(),
            "below the floor"
        );
    }

    /// G3 S0: the observe-mode counters are readable over RPC.
    #[test]
    fn state_class_stats_rpc_reports_out_of_block_state_writes() {
        let db = temp_db("state_class_rpc");
        let state = test_state(Arc::clone(&db));
        let read = |state: &AppState| {
            handle_rpc_method("aincore_getStateClassStats", serde_json::json!([]), state)
                .expect("stats")
        };
        let before = read(&state);
        assert_eq!(before["mode"], "enforce");
        assert!(
            db.put("sys:chain_id", "X").is_err(),
            "state outside any block is refused"
        );
        assert!(
            db.put("no:such:template:rpc", "x").is_err(),
            "an unclassified key is refused (CL-1)"
        );
        let after = read(&state);
        assert_eq!(
            after["state_outside_block"].as_u64().unwrap(),
            before["state_outside_block"].as_u64().unwrap() + 1
        );
        assert_eq!(
            after["unclassified"].as_u64().unwrap(),
            before["unclassified"].as_u64().unwrap() + 1
        );
        assert!(after["samples"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["pattern"] == "sys:chain_id" && x["context"] == "base"));
    }

    #[test]
    fn test_coin_balance_endpoint_reads_ain_and_synthetic_wbtc_coinstores() {
        let db = temp_db("coin_balance");
        let signing_key = SigningKey::from_bytes(&[33u8; 32]);
        let address = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
        seed_coin(
            &db,
            move_coin_store_key(move_address(&address)),
            123_000_000_000_000_000_000,
        );
        seed_coin(&db, wbtc_coin_store_key(move_address(&address)), 42_000_000);
        let state = test_state(Arc::clone(&db));

        let ain = handle_rpc_method(
            "aincore_getCoinBalance",
            serde_json::json!([address, "AIN"]),
            &state,
        )
        .expect("AIN balance response");
        assert_eq!(ain["token"], "AIN");
        assert_eq!(ain["balance"], "123000000000000000000");
        assert_eq!(ain["decimals"], 18);
        assert_eq!(ain["balance_source"], "move_coin_store");

        let wbtc = handle_rpc_method(
            "aincore_getCoinBalance",
            serde_json::json!([address, "synthetic_wbtc"]),
            &state,
        )
        .expect("WBTC balance response");
        assert_eq!(wbtc["token"], "WBTC");
        assert_eq!(wbtc["balance"], "42000000");
        assert_eq!(wbtc["decimals"], 8);
        assert_eq!(wbtc["market_mode"], "synthetic_test_asset_not_btc_backed");

        let err = handle_rpc_method(
            "aincore_getCoinBalance",
            serde_json::json!([address, "USDT"]),
            &state,
        )
        .expect_err("unsupported token rejected");
        assert!(err.message.contains("Supported tokens"));
    }

    #[test]
    fn test_supply_reads_genesis_total_supply_key() {
        let db = temp_db("supply");
        let _seed = db.seeding();
        db.put("sys:total_supply", "42").expect("write sys supply");
        db.put("total_supply", "7").expect("write legacy supply");

        assert_eq!(total_minted_supply(&db), 42);
    }

    #[test]
    fn test_finality_status_endpoint_fields() {
        let db = temp_db("finality_status");
        db.put("consensus:finalized_round", "7")
            .expect("write finalized round");
        db.put("consensus:last_anchor_round", "7")
            .expect("write anchor round");
        db.put("consensus:last_anchor_hash", "abc123")
            .expect("write anchor hash");
        db.put("consensus:finality_digest", "deadbeef")
            .expect("write digest");

        let executor = Arc::new(executor::Executor::new(Arc::clone(&db)));
        let consensus = Arc::new(RwLock::new(consensus::DagConsensus::new(
            "node_test".to_string(),
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::clone(&executor),
            Arc::clone(&db),
            None,
            [1u8; 32],
        )));
        let sessions: network::SessionTable = Arc::default();
        let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(
            &db,
        ))));
        let state = AppState {
            consensus,
            sessions,
            mempool: Arc::new(Mutex::new(mempool::Mempool::new())),
            governance,
            storage: Arc::clone(&db),
            dry_runs: Arc::default(),
        };

        let status = handle_rpc_method("aincore_getFinalityStatus", serde_json::json!([]), &state)
            .expect("finality status response");
        assert_eq!(status["finalized_round"], "7");
        assert_eq!(status["last_anchor_round"], "7");
        assert_eq!(status["last_anchor_hash"], "abc123");
        assert_eq!(status["finality_digest"], "deadbeef");
    }

    #[test]
    fn test_transaction_receipt_endpoint_reads_executor_receipt() {
        let db = temp_db("tx_receipt");
        let tx_hash = "abc123".repeat(10) + "abcd";
        db.put(
            &format!("tx_receipt:{}", tx_hash),
            &serde_json::json!({
                "status": "aborted",
                "gas_charged": "100000",
                "error": "Move abort"
            })
            .to_string(),
        )
        .expect("receipt stored");
        let state = test_state(Arc::clone(&db));

        let receipt = handle_rpc_method(
            "aincore_getTransactionReceipt",
            serde_json::json!([tx_hash]),
            &state,
        )
        .expect("receipt response");

        assert_eq!(receipt["tx_hash"], tx_hash);
        assert_eq!(receipt["status"], "aborted");
        assert_eq!(receipt["confirmations"], 0);
        assert_eq!(receipt["execution_receipt"]["gas_charged"], "100000");
        assert_eq!(receipt["execution_receipt"]["error"], "Move abort");
    }

    #[test]
    fn test_dex_pool_and_quote_endpoints_read_move_registry() {
        let db = temp_db("dex_rpc");
        let pool_addr = move_core_types::account_address::AccountAddress::from_hex_literal(
            "0x11111111111111111111111111111111",
        )
        .unwrap();
        let token_x = "0000000000000000000000000000000000000000000000000000000000000001::staking::AincoreCoin";
        let token_y = "0000000000000000000000000000000000000000000000000000000000000001::wbtc::WBTC";
        let pool_key = format!("{}::{}", token_x, token_y);
        let registry = DexPoolRegistry {
            pools: vec![DexPoolInfo {
                pool_key: pool_key.as_bytes().to_vec(),
                pool_addr,
                token_x_name: token_x.as_bytes().to_vec(),
                token_y_name: token_y.as_bytes().to_vec(),
                fee_bp: 30,
                creator: pool_addr,
                active: true,
            }],
        };
        let _seed = db.seeding();
        db.put(
            &dex_registry_key(),
            &hex::encode(bcs::to_bytes(&registry).unwrap()),
        )
        .unwrap();
        let pool = DexLiquidityPool {
            coin_x: MoveCoin { value: 10_000 },
            coin_y: MoveCoin { value: 10_000 },
            lp_supply: 10_000,
            fee_bp: 30,
        };
        let pool_resource_key = dex_pool_key(pool_addr, token_x, token_y).unwrap();
        db.put(
            &pool_resource_key,
            &hex::encode(bcs::to_bytes(&pool).unwrap()),
        )
        .unwrap();
        let owner = move_core_types::account_address::AccountAddress::from_hex_literal(
            "0x22222222222222222222222222222222",
        )
        .unwrap();
        let lp_key = dex_lp_key(owner, token_x, token_y).unwrap();
        db.put(
            &lp_key,
            &hex::encode(bcs::to_bytes(&DexLPToken { balance: 2_500 }).unwrap()),
        )
        .unwrap();
        let state = test_state(Arc::clone(&db));

        let pools = handle_rpc_method("aincore_getDexPools", serde_json::json!([]), &state)
            .expect("dex pools response");
        assert_eq!(pools.as_array().unwrap().len(), 1);
        assert_eq!(pools[0]["reserve_x"], "10000");
        assert_eq!(pools[0]["reserve_y"], "10000");

        let quote = handle_rpc_method(
            "aincore_getDexQuote",
            serde_json::json!([token_x, token_y, "1000"]),
            &state,
        )
        .expect("dex quote response");
        assert_eq!(quote["status"], "ok");
        assert_eq!(quote["amount_out"], "906");
        assert_eq!(quote["direction"], "x_to_y");

        let alias_quote = handle_rpc_method(
            "aincore_getDexQuote",
            serde_json::json!(["AIN", "WBTC", "1000"]),
            &state,
        )
        .expect("dex alias quote response");
        assert_eq!(alias_quote["status"], "ok");
        assert_eq!(alias_quote["amount_out"], "906");
        assert_eq!(alias_quote["direction"], "x_to_y");

        let spot = handle_rpc_method(
            "aincore_getDexSpotPrice",
            serde_json::json!([token_x, token_y, "1000"]),
            &state,
        )
        .expect("dex spot response");
        assert_eq!(spot["status"], "ok");
        assert_eq!(spot["amount_out"], "906");
        assert_eq!(spot["approx_price"], 0.906);
        assert_eq!(spot["quote"]["pool_key"], pool_key);

        let lp_balance = handle_rpc_method(
            "aincore_getDexLpBalance",
            serde_json::json!([owner.to_string(), pool_addr.to_string()]),
            &state,
        )
        .expect("dex LP balance response");
        assert_eq!(lp_balance["status"], "ok");
        assert_eq!(lp_balance["balance"], "2500");
        assert_eq!(lp_balance["lp_supply"], "10000");
        assert_eq!(lp_balance["pool_addr"], pool_addr.to_string());
        assert_eq!(lp_balance["share_bps"], 2500.0);

        let default_lp_balance = handle_rpc_method(
            "aincore_getDexLpBalance",
            serde_json::json!([owner.to_string()]),
            &state,
        )
        .expect("default dex LP balance response");
        assert_eq!(default_lp_balance["balance"], "2500");
    }

    #[test]
    fn test_submit_transaction_with_key_is_disabled() {
        let db = temp_db("legacy_rpc_disabled");
        let executor = Arc::new(executor::Executor::new(Arc::clone(&db)));
        let consensus = Arc::new(RwLock::new(consensus::DagConsensus::new(
            "node_test".to_string(),
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::clone(&executor),
            Arc::clone(&db),
            None,
            [2u8; 32],
        )));
        let sessions: network::SessionTable = Arc::default();
        let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(
            &db,
        ))));
        let state = AppState {
            consensus,
            sessions,
            mempool: Arc::new(Mutex::new(mempool::Mempool::new())),
            governance,
            storage: db,
            dry_runs: Arc::default(),
        };

        let err = handle_rpc_method("submit_transaction_with_key", serde_json::json!([]), &state)
            .expect_err("legacy rpc must be disabled");
        assert_eq!(err.code, -32040);
        assert!(err.message.contains("disabled in secure mode"));
    }

    /// SEC-#15: circulating supply must NOT have burns subtracted twice.
    #[test]
    fn supply_view_does_not_double_subtract_burns() {
        // Net = gross issued (1000) − burned (150) = 850.
        let (total_minted, circulating) = supply_view(850, 150);
        assert_eq!(total_minted, 1000, "gross minted = net + burned");
        assert_eq!(circulating, 850, "circulating = net (NOT net - burned)");
        // Self-consistent: circulating == total_minted − total_burned.
        assert_eq!(circulating, total_minted - 150);

        // No burns: minted == circulating == net.
        let (m, c) = supply_view(500, 0);
        assert_eq!((m, c), (500, 500));
    }
}
