use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use network::PeerList;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};

// Input validation constants
const MAX_BLOCK_HEIGHT: u64 = 1_000_000_000;
const MAX_QUERY_LIMIT: u64 = 1000;

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
    format!("resource_{}_{}", addr, store)
}

fn wbtc_coin_store_key(addr: move_core_types::account_address::AccountAddress) -> String {
    move_coin_store_key_for(addr, "wbtc", "WBTC")
}

fn dex_registry_key() -> String {
    let system = move_core_types::account_address::AccountAddress::from_hex_literal("0x1")
        .expect("valid system address");
    format!("resource_{}_{}", system, "0x1::dex::PoolRegistry")
}

fn normalize_type_name(value: &str) -> String {
    let value = value.trim();
    match value.to_ascii_uppercase().as_str() {
        "AIN" => return "00000000000000000000000000000001::staking::AincoreCoin".to_string(),
        "WBTC" => return "00000000000000000000000000000001::wbtc::WBTC".to_string(),
        _ => {}
    }

    let trimmed = value.trim_start_matches("0x");
    let mut parts: Vec<String> = trimmed.split("::").map(|part| part.to_string()).collect();
    if let Some(addr) = parts.get_mut(0) {
        *addr = addr.to_ascii_lowercase();
        if addr.len() < 32 {
            *addr = format!("{:0>32}", addr);
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
    Some(format!("resource_{}_{}", pool_addr, tag))
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
    Some(format!("resource_{}_{}", owner, tag))
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
            if normalized_value.len() == 32
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

/// Canonical mainnet chain id. Mirrors the default used by the mempool
/// (`core/mempool/src/lib.rs`) and genesis (`core/node/src/genesis.rs`).
const MAINNET_CHAIN_ID: &str = "AINCORE-MAINNET-1";

/// Resolve the node's chain id using the same env contract as the mempool:
/// `AINCORE_CHAIN_ID`, defaulting to the mainnet id when unset.
fn resolve_chain_id() -> String {
    std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| MAINNET_CHAIN_ID.to_string())
}

/// M2: Hard safety gate for ALL direct-write faucet/test-mint paths.
///
/// The faucet writes balances straight into RocksDB CoinStore keys, bypassing
/// the executor, supply accounting and `BLOCK_EXECUTION_LOCK`. On mainnet that
/// would be an unlimited-mint + state-root-race + supply-desync hole, so we
/// refuse unconditionally when the resolved chain id is the mainnet id --
/// EVEN IF `AINCORE_ENABLE_FAUCET` is set. Dev/testnet nodes (any other
/// `AINCORE_CHAIN_ID`) are unaffected.
fn faucet_chain_guard() -> Result<(), JsonRpcError> {
    let chain_id = resolve_chain_id();
    if chain_id == MAINNET_CHAIN_ID {
        eprintln!(
            "[SECURITY] Faucet/test-mint RPC refused: chain_id={} is mainnet. \
             Direct-write faucet is permanently disabled on mainnet regardless of \
             AINCORE_ENABLE_FAUCET. Set AINCORE_CHAIN_ID to a testnet id to use it.",
            chain_id
        );
        return Err(JsonRpcError {
            code: -32041,
            message: "Faucet permanently disabled on mainnet (AINCORE-MAINNET-1).".into(),
        });
    }
    Ok(())
}

fn faucet_enabled() -> bool {
    std::env::var("AINCORE_ENABLE_FAUCET")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn credit_testnet_faucet(
    storage: &Arc<StateDB>,
    addr: &str,
    amount: u128,
    public_key_hex: Option<&str>,
) -> Result<serde_json::Value, JsonRpcError> {
    // M2: Mainnet refusal FIRST — never mints on AINCORE-MAINNET-1 even if the
    // enable flag is set. Dev/testnet continues past this.
    faucet_chain_guard()?;
    if !faucet_enabled() {
        return Err(JsonRpcError {
            code: -32030,
            message: "Faucet disabled. Set AINCORE_ENABLE_FAUCET=1 for local/testnet smoke tests."
                .into(),
        });
    }

    let move_addr =
        move_core_types::account_address::AccountAddress::from_hex_literal(&format!("0x{}", addr))
            .map_err(|_| JsonRpcError {
                code: -32602,
                message: "Invalid address".into(),
            })?;

    if let Some(public_key) = public_key_hex {
        let public_key_bytes = hex::decode(public_key).map_err(|_| JsonRpcError {
            code: -32602,
            message: "Invalid public key hex".into(),
        })?;
        let expected_addr =
            crypto::derive_address(&public_key_bytes).map_err(|e| JsonRpcError {
                code: -32602,
                message: format!("Address derivation failed: {}", e),
            })?;
        if expected_addr != addr {
            return Err(JsonRpcError {
                code: -32602,
                message: format!("Public key/address mismatch: expected {}", expected_addr),
            });
        }
        if storage.get_object(addr).is_none() {
            let account =
                aa::AccountManager::create_account(addr.to_string(), public_key.to_string());
            storage.put_object(&account).map_err(|e| JsonRpcError {
                code: -32000,
                message: format!("Failed to create faucet account: {}", e),
            })?;
        }
    }

    let key = move_coin_store_key(move_addr);
    let current = storage
        .get(&key)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("Failed to read CoinStore: {}", e),
        })?
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<MoveCoin>(&bytes).ok())
        .map(|coin| coin.value)
        .unwrap_or(0);
    let new_balance = current.checked_add(amount).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Faucet amount overflows balance".into(),
    })?;
    let bytes = bcs::to_bytes(&MoveCoin { value: new_balance }).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("Failed to encode CoinStore: {}", e),
    })?;
    storage
        .put(&key, &hex::encode(bytes))
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("Failed to write CoinStore: {}", e),
        })?;

    Ok(serde_json::json!({
        "address": addr,
        "amount": amount.to_string(),
        "move_balance": new_balance.to_string(),
        "balance_source": "move_coin_store",
        "faucet_mode": "local_testnet_only"
    }))
}

fn credit_testnet_wbtc(
    storage: &Arc<StateDB>,
    addr: &str,
    amount: u128,
    public_key_hex: Option<&str>,
) -> Result<serde_json::Value, JsonRpcError> {
    // M2: Mainnet refusal FIRST — never mints on AINCORE-MAINNET-1 even if the
    // enable flag is set. Dev/testnet continues past this.
    faucet_chain_guard()?;
    if !faucet_enabled() {
        return Err(JsonRpcError {
            code: -32030,
            message: "Test WBTC mint disabled. Set AINCORE_ENABLE_FAUCET=1 for local/testnet smoke tests."
                .into(),
        });
    }

    let move_addr =
        move_core_types::account_address::AccountAddress::from_hex_literal(&format!("0x{}", addr))
            .map_err(|_| JsonRpcError {
                code: -32602,
                message: "Invalid address".into(),
            })?;

    if let Some(public_key) = public_key_hex {
        let public_key_bytes = hex::decode(public_key).map_err(|_| JsonRpcError {
            code: -32602,
            message: "Invalid public key hex".into(),
        })?;
        let expected_addr =
            crypto::derive_address(&public_key_bytes).map_err(|e| JsonRpcError {
                code: -32602,
                message: format!("Address derivation failed: {}", e),
            })?;
        if expected_addr != addr {
            return Err(JsonRpcError {
                code: -32602,
                message: format!("Public key/address mismatch: expected {}", expected_addr),
            });
        }
        if storage.get_object(addr).is_none() {
            let account =
                aa::AccountManager::create_account(addr.to_string(), public_key.to_string());
            storage.put_object(&account).map_err(|e| JsonRpcError {
                code: -32000,
                message: format!("Failed to create faucet account: {}", e),
            })?;
        }
    }

    let key = wbtc_coin_store_key(move_addr);
    let current = storage
        .get(&key)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("Failed to read WBTC CoinStore: {}", e),
        })?
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<MoveCoin>(&bytes).ok())
        .map(|coin| coin.value)
        .unwrap_or(0);
    let new_balance = current.checked_add(amount).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Test WBTC amount overflows balance".into(),
    })?;
    let bytes = bcs::to_bytes(&MoveCoin { value: new_balance }).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("Failed to encode WBTC CoinStore: {}", e),
    })?;
    storage
        .put(&key, &hex::encode(bytes))
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("Failed to write WBTC CoinStore: {}", e),
        })?;

    Ok(serde_json::json!({
        "address": addr,
        "amount": amount.to_string(),
        "wbtc_balance": new_balance.to_string(),
        "balance_source": "move_coin_store",
        "faucet_mode": "local_testnet_only"
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

fn total_minted_supply(storage: &Arc<StateDB>) -> u128 {
    storage
        .get("sys:total_supply")
        .ok()
        .flatten()
        .or_else(|| storage.get("total_supply").ok().flatten())
        .and_then(|s| s.parse::<u128>().ok())
        .unwrap_or(0)
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
                let mut mempool = data.mempool.lock()
                    .map_err(|e| JsonRpcError { code: -32000, message: format!("Mempool lock error: {}", e) })?;
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
        "aincore_faucet" => {
            // params: [address, amount?, public_key?]
            if let Some(addr) = params.get(0).and_then(|v| v.as_str()) {
                let amount = params.get(1)
                    .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok()).or_else(|| v.as_u64().map(|n| n as u128)))
                    .unwrap_or(1_000_000_000_000_000_000);
                let public_key = params.get(2).and_then(|v| v.as_str());
                credit_testnet_faucet(&data.storage, addr, amount, public_key)
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [address, amount?, public_key?]".into() })
            }
        },
        "aincore_testMintWbtc" => {
            // params: [address, amount, public_key?]
            //
            // Local/testnet-only helper for DEX market seeding. This never
            // represents real BTC custody; production WBTC minting must go
            // through the bridge authority path.
            if let Some(addr) = params.get(0).and_then(|v| v.as_str()) {
                let amount = params.get(1)
                    .and_then(|v| v.as_str().and_then(|s| s.parse::<u128>().ok()).or_else(|| v.as_u64().map(|n| n as u128)))
                    .ok_or_else(|| JsonRpcError {
                        code: -32602,
                        message: "Invalid params: [address, amount, public_key?]".into(),
                    })?;
                let public_key = params.get(2).and_then(|v| v.as_str());
                credit_testnet_wbtc(&data.storage, addr, amount, public_key)
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [address, amount, public_key?]".into() })
            }
        },
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
            // QC Phase 2: return the stored quorum certificate (optionally for a
            // specific [height]; default = latest) and independently verify it
            // against the trusted validator set.
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
                None => {
                    println!("🔍 [RPC] getBlocks latest: head={} limit={}", latest_height, limit);
                    let start_index = latest_height.saturating_sub(limit);
                    for i in (start_index + 1..=latest_height).rev() {
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
        // S3: aincore_debug REMOVED — raw DB key scanner is a data exfiltration vector on mainnet
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
            //
            // Phase 2.11 (scope creep): bounded scan to prevent
            // unbounded-iterator DoS through the API. Cap of 1000
            // mirrors MAX_LIMIT used elsewhere in the API and is
            // comfortably above realistic per-delegator delegation
            // counts.
            if let Some(delegator) = params.get(0).and_then(|v| v.as_str()) {
                let prefix = format!("delegation:{}:", delegator);
                let mut delegations = Vec::new();
                const API_PREFIX_CAP: usize = 1000;

                for (key_str, raw_value) in
                    data.storage.scan_prefix_limited(&prefix, API_PREFIX_CAP)
                {
                    let validator = key_str.strip_prefix(&prefix).unwrap_or("");
                    if let Ok(del_data) =
                        serde_json::from_str::<serde_json::Value>(&raw_value)
                    {
                        delegations.push(serde_json::json!({
                            "validator": validator,
                            "amount": del_data.get("amount").unwrap_or(&serde_json::json!("0")),
                            "pending_rewards": del_data.get("pending_rewards").unwrap_or(&serde_json::json!("0"))
                        }));
                    }
                }

                Ok(serde_json::json!(delegations))
            } else {
                Err(JsonRpcError { code: -32602, message: "Invalid params: [delegator_address]".into() })
            }
        },

        "aincore_getUnbondingDelegations" => {
            // params: [delegator_address]
            //
            // Phase 2.11: bounded scan, see aincore_getDelegations.
            if let Some(delegator) = params.get(0).and_then(|v| v.as_str()) {
                let prefix = format!("unbonding:{}:", delegator);
                let mut unbondings = Vec::new();
                const API_PREFIX_CAP: usize = 1000;

                for (key_str, raw_value) in
                    data.storage.scan_prefix_limited(&prefix, API_PREFIX_CAP)
                {
                    let validator = key_str.strip_prefix(&prefix).unwrap_or("");
                    if let Ok(data) =
                        serde_json::from_str::<serde_json::Value>(&raw_value)
                    {
                        unbondings.push(serde_json::json!({
                            "validator": validator,
                            "amount": data.get("amount").unwrap_or(&serde_json::json!("0")),
                            "unlock_time": data.get("unlock_time").unwrap_or(&serde_json::json!(0))
                        }));
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

            // Phase 2.11: bounded scan, see aincore_getDelegations.
            let prefix = "validator_pool:";
            const API_PREFIX_CAP: usize = 1000;
            for (key_str, raw_value) in
                data.storage.scan_prefix_limited(prefix, API_PREFIX_CAP)
            {
                let validator = key_str.strip_prefix(prefix).unwrap_or("");
                if let Ok(pool_data) =
                    serde_json::from_str::<serde_json::Value>(&raw_value)
                {
                    validators.push(serde_json::json!({
                        "address": validator,
                        "total_delegated": pool_data.get("total_delegated").unwrap_or(&serde_json::json!("0")),
                        "commission_rate": pool_data.get("commission_rate").unwrap_or(&serde_json::json!(0)),
                        "delegator_count": pool_data.get("delegator_count").unwrap_or(&serde_json::json!(0))
                    }));
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
            let total_minted = total_minted_supply(&data.storage);
            let total_burned = match data.storage.get("total_burned") {
                Ok(Some(s)) => s.parse::<u128>().unwrap_or(0),
                _ => 0,
            };
            let circulating = total_minted.saturating_sub(total_burned);

            // S3: Calculate current reward from halving model (36 AIN base, halves every 2.1M blocks)
            let latest_height = data.storage.get_chain_height();
            let halving_interval: u64 = 2_102_400;
            let halvings = latest_height / halving_interval;
            let base_reward: u128 = 36_000_000_000_000_000_000; // 36 AIN
            let current_reward = if halvings >= 128 { 0 } else { base_reward >> halvings };

            Ok(serde_json::json!({
                "max_supply": max_supply.to_string(),
                "total_minted": total_minted.to_string(),
                "total_burned": total_burned.to_string(),
                "circulating_supply": circulating.to_string(),
                "current_block_reward": current_reward.to_string(),
                "halving_epoch": halvings,
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
                    // Check if it's in mempool
                    let in_mempool = if let Ok(mp) = data.mempool.lock() {
                        !mp.is_empty() // Simplified check
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

            let gas = estimate_payload_gas(&payload);

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
                "decay_model": "Halving (36 AIN base, halves every 2,102,400 blocks)"
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
                    "note": "Submit via sendTransaction with a hex-encoded BCS TransactionPayload"
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

    // M1: Rate limiter — 100 requests/second per IP, burst up to 200.
    // Mirrors the (previously dead) config in api.rs so the LIVE server is throttled.
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(100)
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
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::{Mutex, OnceLock};

    fn faucet_env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = std::env::temp_dir().join(format!(
            "aincore_phase05_api_{}_{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(path.to_str().expect("utf8 temp path")).expect("test DB opens"))
    }

    fn test_state(db: Arc<StateDB>) -> AppState {
        let consensus = Arc::new(RwLock::new(consensus::DagConsensus::new(
            "node_test".to_string(),
            Arc::new(Mutex::new(std::collections::HashMap::new())),
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::new(executor::Executor::new(Arc::clone(&db))),
            Arc::clone(&db),
            None,
            None,
            [3u8; 32],
        )));
        let peers = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(
            &db,
        ))));
        AppState {
            consensus,
            peers,
            mempool: Arc::new(Mutex::new(mempool::Mempool::new())),
            governance,
            storage: db,
        }
    }

    #[test]
    fn test_faucet_disabled_by_default() {
        let _guard = faucet_env_lock().lock().unwrap();
        std::env::remove_var("AINCORE_ENABLE_FAUCET");
        // Testnet chain id so the M2 mainnet guard passes and we reach the
        // "disabled" (-32030) path this test asserts.
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-TESTNET-1");
        let db = temp_db("disabled");
        let err = credit_testnet_faucet(&db, "00000000000000000000000000000001", 1, None)
            .expect_err("faucet must be disabled by default");
        assert_eq!(err.code, -32030);
        std::env::remove_var("AINCORE_CHAIN_ID");
    }

    #[test]
    fn test_faucet_creates_account_and_credits_move_coinstore() {
        let _guard = faucet_env_lock().lock().unwrap();
        std::env::set_var("AINCORE_ENABLE_FAUCET", "1");
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-TESTNET-1");
        let db = temp_db("credit");
        let signing_key = SigningKey::from_bytes(&[31u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let address = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();

        let result = credit_testnet_faucet(&db, &address, 123, Some(&public_key))
            .expect("faucet credits account");
        assert_eq!(result["move_balance"], "123");
        assert!(db.get_object(&address).is_some());
        assert_eq!(move_balance(&db, &address), "123");

        let result = credit_testnet_faucet(&db, &address, 7, Some(&public_key))
            .expect("faucet increments account balance");
        assert_eq!(result["move_balance"], "130");
        assert_eq!(move_balance(&db, &address), "130");
        std::env::remove_var("AINCORE_ENABLE_FAUCET");
        std::env::remove_var("AINCORE_CHAIN_ID");
    }

    #[test]
    fn test_faucet_refused_on_mainnet_even_when_enabled() {
        let _guard = faucet_env_lock().lock().unwrap();
        std::env::set_var("AINCORE_ENABLE_FAUCET", "1");
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-MAINNET-1");
        let db = temp_db("mainnet_refused");
        let signing_key = SigningKey::from_bytes(&[34u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let address = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();

        let err = credit_testnet_faucet(&db, &address, 1, Some(&public_key))
            .expect_err("faucet must refuse on mainnet even when enabled");
        assert_eq!(err.code, -32041);
        // No CoinStore must have been written.
        assert_eq!(move_balance(&db, &address), "0");

        let err = credit_testnet_wbtc(&db, &address, 1, Some(&public_key))
            .expect_err("wbtc mint must refuse on mainnet even when enabled");
        assert_eq!(err.code, -32041);

        std::env::remove_var("AINCORE_ENABLE_FAUCET");
        std::env::remove_var("AINCORE_CHAIN_ID");
    }

    #[test]
    fn test_faucet_rejects_public_key_address_mismatch() {
        let _guard = faucet_env_lock().lock().unwrap();
        std::env::set_var("AINCORE_ENABLE_FAUCET", "1");
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-TESTNET-1");
        let db = temp_db("mismatch");
        let signing_key = SigningKey::from_bytes(&[32u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let err = credit_testnet_faucet(
            &db,
            "00000000000000000000000000000001",
            1,
            Some(&public_key),
        )
        .expect_err("faucet rejects mismatched public key");

        assert_eq!(err.code, -32602);
        assert!(err.message.contains("Public key/address mismatch"));
        std::env::remove_var("AINCORE_ENABLE_FAUCET");
        std::env::remove_var("AINCORE_CHAIN_ID");
    }

    #[test]
    fn test_coin_balance_endpoint_reads_ain_and_synthetic_wbtc_coinstores() {
        let _guard = faucet_env_lock().lock().unwrap();
        std::env::set_var("AINCORE_ENABLE_FAUCET", "1");
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-TESTNET-1");
        let db = temp_db("coin_balance");
        let signing_key = SigningKey::from_bytes(&[33u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let address = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();

        credit_testnet_faucet(
            &db,
            &address,
            123_000_000_000_000_000_000,
            Some(&public_key),
        )
        .expect("AIN faucet credits CoinStore");
        credit_testnet_wbtc(&db, &address, 42_000_000, Some(&public_key))
            .expect("synthetic WBTC mint credits CoinStore");
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
        std::env::remove_var("AINCORE_ENABLE_FAUCET");
    }

    #[test]
    fn test_supply_reads_genesis_total_supply_key() {
        let db = temp_db("supply");
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

        let consensus = Arc::new(RwLock::new(consensus::DagConsensus::new(
            "node_test".to_string(),
            Arc::new(Mutex::new(std::collections::HashMap::new())),
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::new(executor::Executor::new(Arc::clone(&db))),
            Arc::clone(&db),
            None,
            None,
            [1u8; 32],
        )));
        let peers = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(
            &db,
        ))));
        let state = AppState {
            consensus,
            peers,
            mempool: Arc::new(Mutex::new(mempool::Mempool::new())),
            governance,
            storage: Arc::clone(&db),
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
        let tx_hash = "abc123";
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
        let token_x = "00000000000000000000000000000001::staking::AincoreCoin";
        let token_y = "00000000000000000000000000000001::wbtc::WBTC";
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
        let consensus = Arc::new(RwLock::new(consensus::DagConsensus::new(
            "node_test".to_string(),
            Arc::new(Mutex::new(std::collections::HashMap::new())),
            Arc::new(Mutex::new(mempool::Mempool::new())),
            Arc::new(executor::Executor::new(Arc::clone(&db))),
            Arc::clone(&db),
            None,
            None,
            [2u8; 32],
        )));
        let peers = Arc::new(Mutex::new(std::collections::HashMap::new()));
        let governance = Arc::new(Mutex::new(governance::GovernanceManager::new(Arc::clone(
            &db,
        ))));
        let state = AppState {
            consensus,
            peers,
            mempool: Arc::new(Mutex::new(mempool::Mempool::new())),
            governance,
            storage: db,
        };

        let err = handle_rpc_method("submit_transaction_with_key", serde_json::json!([]), &state)
            .expect_err("legacy rpc must be disabled");
        assert_eq!(err.code, -32040);
        assert!(err.message.contains("disabled in secure mode"));
    }
}
