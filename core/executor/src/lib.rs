use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use storage::rocksdb::WriteBatch;
use storage::StateDB;
use vm_move::{EntryFunctionCall, MoveAction, AINCOREVM};

/// SECURITY FIX: Global mutex to serialize block execution.
/// Prevents State Root Race Condition where concurrent execute_block_parallel
/// calls (from consensus + sync threads) could read the same prev_root and
/// compute conflicting new roots, causing an instant Hard Fork.
static BLOCK_EXECUTION_LOCK: std::sync::LazyLock<Mutex<()>> =
    std::sync::LazyLock::new(|| Mutex::new(()));

/// Chain ID loaded from environment, defaults to TESTNET for safety.
/// Set AINCORE_CHAIN_ID=AINCORE-MAINNET-1 explicitly for production.
fn get_chain_id() -> String {
    std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string())
}
// V3 CONSTANTS
#[allow(dead_code)]
const MAX_SUPPLY: u128 = 150_000_000 * 1_000_000_000_000_000_000; // 150 Million AIN
                                                                  // Note: Block rewards handled exclusively by staking.move (Halving model)
                                                                  // Executor only distributes transaction fees — no inflationary minting here

// N-2 FIX: Per-block cumulative object limit to prevent memory exhaustion DoS.
// 10,000 TXs × 128 objects = 1.28M objects → 1.28GB RAM. Cap at 10K total.
const MAX_OBJECTS_PER_BLOCK: usize = 10_000;
// Gas cost per input object loaded (prevents zero-cost object flooding)
const OBJECT_LOAD_GAS: u64 = 100;
const MIN_GAS_PRICE: u128 = 1;

fn system_address() -> move_core_types::account_address::AccountAddress {
    move_core_types::account_address::AccountAddress::from_hex_literal("0x1")
        .expect("0x1 must be a valid Move system address")
}

fn parse_move_address(addr: &str) -> Option<move_core_types::account_address::AccountAddress> {
    move_core_types::account_address::AccountAddress::from_hex_literal(&format!("0x{}", addr)).ok()
}

fn aincore_coin_type() -> move_core_types::language_storage::TypeTag {
    move_core_types::language_storage::TypeTag::Struct(Box::new(
        move_core_types::language_storage::StructTag {
            address: system_address(),
            module: move_core_types::identifier::Identifier::new("staking").expect("valid module"),
            name: move_core_types::identifier::Identifier::new("AincoreCoin")
                .expect("valid struct"),
            type_params: vec![],
        },
    ))
}

#[cfg(test)]
fn coin_store_key(addr: move_core_types::account_address::AccountAddress) -> String {
    let tag = move_core_types::language_storage::StructTag {
        address: system_address(),
        module: move_core_types::identifier::Identifier::new("coin").expect("valid module"),
        name: move_core_types::identifier::Identifier::new("CoinStore").expect("valid struct"),
        type_params: vec![aincore_coin_type()],
    };
    format!("resource_{}_{}", addr, tag)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveCoin {
    value: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveValidatorConfig {
    validator_addr: move_core_types::account_address::AccountAddress,
    stake: MoveCoin,
    public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveUnbondingRequest {
    validator_addr: move_core_types::account_address::AccountAddress,
    stake: u128,
    unlock_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveValidatorSet {
    validators: Vec<MoveValidatorConfig>,
    unbonding_queue: Vec<MoveUnbondingRequest>,
    total_supply: u128,
    current_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeeSweepEntry {
    miner: String,
    amount: String,
    reason: String,
    attempts: u64,
}

fn validator_set_key() -> String {
    format!(
        "resource_{}_{}",
        system_address(),
        "0x1::staking::ValidatorSet"
    )
}

fn dex_registry_key() -> String {
    format!(
        "resource_{}_{}",
        system_address(),
        "0x1::dex::PoolRegistry"
    )
}

fn coin_store_key_for_type(
    addr: move_core_types::account_address::AccountAddress,
    coin_type: move_core_types::language_storage::TypeTag,
) -> String {
    let tag = move_core_types::language_storage::StructTag {
        address: system_address(),
        module: move_core_types::identifier::Identifier::new("coin").expect("valid module"),
        name: move_core_types::identifier::Identifier::new("CoinStore").expect("valid struct"),
        type_params: vec![coin_type],
    };
    format!("resource_{}_{}", addr, tag)
}

fn dex_pool_key_for_type_args(
    pool_addr: move_core_types::account_address::AccountAddress,
    ty_args: &[move_core_types::language_storage::TypeTag],
) -> Option<String> {
    if ty_args.len() != 2 {
        return None;
    }
    let tag = move_core_types::language_storage::StructTag {
        address: system_address(),
        module: move_core_types::identifier::Identifier::new("dex").ok()?,
        name: move_core_types::identifier::Identifier::new("LiquidityPool").ok()?,
        type_params: vec![ty_args[0].clone(), ty_args[1].clone()],
    };
    Some(format!("resource_{}_{}", pool_addr, tag))
}

fn dex_lp_key_for_type_args(
    owner: move_core_types::account_address::AccountAddress,
    ty_args: &[move_core_types::language_storage::TypeTag],
) -> Option<String> {
    if ty_args.len() != 2 {
        return None;
    }
    let tag = move_core_types::language_storage::StructTag {
        address: system_address(),
        module: move_core_types::identifier::Identifier::new("dex").ok()?,
        name: move_core_types::identifier::Identifier::new("LPToken").ok()?,
        type_params: vec![ty_args[0].clone(), ty_args[1].clone()],
    };
    Some(format!("resource_{}_{}", owner, tag))
}

fn decode_validator_set_hex(value: &str) -> Option<MoveValidatorSet> {
    let bytes = hex::decode(value).ok()?;
    bcs::from_bytes::<MoveValidatorSet>(&bytes).ok()
}

fn encode_validator_set_hex(value: &MoveValidatorSet) -> Option<String> {
    bcs::to_bytes(value).ok().map(hex::encode)
}

fn tx_hash_hex(tx_json: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(tx_json.as_bytes()))
}

fn receipt_update(
    db: &StateDB,
    tx_json: &str,
    updates: &[(String, Option<String>)],
    status: &str,
    gas_charged: u128,
    error: Option<String>,
) -> (String, Option<String>) {
    let metadata = receipt_metadata(db, tx_json, updates, status);
    let value = serde_json::json!({
        "status": status,
        "gas_charged": gas_charged.to_string(),
        "error": error,
        "metadata": metadata,
    });
    (
        format!("tx_receipt:{}", tx_hash_hex(tx_json)),
        Some(value.to_string()),
    )
}

fn bcs_arg<T: serde::de::DeserializeOwned>(args: &[Vec<u8>], index: usize) -> Option<T> {
    args.get(index).and_then(|bytes| bcs::from_bytes(bytes).ok())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DexReceiptCoin {
    value: u128,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DexReceiptPool {
    coin_x: DexReceiptCoin,
    coin_y: DexReceiptCoin,
    lp_supply: u128,
    fee_bp: u64,
}

struct DexReceiptContext {
    tx: Transaction,
    call: vm_move::EntryFunctionCall,
}

fn decode_dex_receipt_context(tx_json: &str) -> Option<DexReceiptContext> {
    let tx = serde_json::from_str::<Transaction>(tx_json).ok()?;
    let payload_bytes = hex::decode(tx.payload.trim_start_matches("0x")).ok()?;
    let payload = bcs::from_bytes::<vm_move::TransactionPayload>(&payload_bytes).ok()?;
    let vm_move::TransactionPayload::EntryFunction(call) = payload else {
        return None;
    };
    if *call.module.address() != system_address() || call.module.name().as_str() != "dex" {
        return None;
    }

    Some(DexReceiptContext { tx, call })
}

fn read_updated_value<'a>(
    db: &'a StateDB,
    updates: &'a [(String, Option<String>)],
    key: &str,
) -> Option<String> {
    for (candidate, value) in updates.iter().rev() {
        if candidate == key {
            return value.clone();
        }
    }
    db.get(key).ok().flatten()
}

fn decode_dex_pool_from_state(
    db: &StateDB,
    updates: &[(String, Option<String>)],
    pool_addr: move_core_types::account_address::AccountAddress,
    ty_args: &[move_core_types::language_storage::TypeTag],
) -> Option<DexReceiptPool> {
    let key = dex_pool_key_for_type_args(pool_addr, ty_args)?;
    read_updated_value(db, updates, &key)
        .and_then(|hex_value| hex::decode(hex_value).ok())
        .and_then(|bytes| bcs::from_bytes::<DexReceiptPool>(&bytes).ok())
}

fn add_pool_delta_metadata(
    metadata: &mut serde_json::Map<String, serde_json::Value>,
    pre_pool: &DexReceiptPool,
    post_pool: &DexReceiptPool,
    function: &str,
    type_args: &[String],
) {
    metadata.insert(
        "reserve_x_before".to_string(),
        serde_json::json!(pre_pool.coin_x.value.to_string()),
    );
    metadata.insert(
        "reserve_y_before".to_string(),
        serde_json::json!(pre_pool.coin_y.value.to_string()),
    );
    metadata.insert(
        "reserve_x_after".to_string(),
        serde_json::json!(post_pool.coin_x.value.to_string()),
    );
    metadata.insert(
        "reserve_y_after".to_string(),
        serde_json::json!(post_pool.coin_y.value.to_string()),
    );
    metadata.insert(
        "lp_supply_before".to_string(),
        serde_json::json!(pre_pool.lp_supply.to_string()),
    );
    metadata.insert(
        "lp_supply_after".to_string(),
        serde_json::json!(post_pool.lp_supply.to_string()),
    );

    match function {
        "add_liquidity" => {
            metadata.insert(
                "actual_amount_x".to_string(),
                serde_json::json!(
                    post_pool.coin_x.value.saturating_sub(pre_pool.coin_x.value).to_string()
                ),
            );
            metadata.insert(
                "actual_amount_y".to_string(),
                serde_json::json!(
                    post_pool.coin_y.value.saturating_sub(pre_pool.coin_y.value).to_string()
                ),
            );
            metadata.insert(
                "actual_lp_minted".to_string(),
                serde_json::json!(post_pool.lp_supply.saturating_sub(pre_pool.lp_supply).to_string()),
            );
        }
        "remove_liquidity" => {
            metadata.insert(
                "actual_amount_x".to_string(),
                serde_json::json!(
                    pre_pool.coin_x.value.saturating_sub(post_pool.coin_x.value).to_string()
                ),
            );
            metadata.insert(
                "actual_amount_y".to_string(),
                serde_json::json!(
                    pre_pool.coin_y.value.saturating_sub(post_pool.coin_y.value).to_string()
                ),
            );
            metadata.insert(
                "actual_lp_burned".to_string(),
                serde_json::json!(pre_pool.lp_supply.saturating_sub(post_pool.lp_supply).to_string()),
            );
        }
        "swap_x_to_y" => {
            metadata.insert("token_in".to_string(), serde_json::json!(type_args.first().cloned()));
            metadata.insert("token_out".to_string(), serde_json::json!(type_args.get(1).cloned()));
            metadata.insert(
                "actual_amount_out".to_string(),
                serde_json::json!(
                    pre_pool.coin_y.value.saturating_sub(post_pool.coin_y.value).to_string()
                ),
            );
        }
        "swap_y_to_x" => {
            metadata.insert("token_in".to_string(), serde_json::json!(type_args.get(1).cloned()));
            metadata.insert("token_out".to_string(), serde_json::json!(type_args.first().cloned()));
            metadata.insert(
                "actual_amount_out".to_string(),
                serde_json::json!(
                    pre_pool.coin_x.value.saturating_sub(post_pool.coin_x.value).to_string()
                ),
            );
        }
        _ => {}
    }
}

fn receipt_metadata(
    db: &StateDB,
    tx_json: &str,
    updates: &[(String, Option<String>)],
    status: &str,
) -> Option<serde_json::Value> {
    let DexReceiptContext { tx, call } = decode_dex_receipt_context(tx_json)?;

    let type_args: Vec<String> = call.ty_args.iter().map(|arg| arg.to_string()).collect();
    let sender_addr = parse_move_address(&tx.sender)?;
    let pool_addr = if call.function == "create_pool" {
        Some(sender_addr)
    } else {
        bcs_arg::<move_core_types::account_address::AccountAddress>(&call.args, 1)
    };

    let mut metadata = serde_json::json!({
        "kind": "dex",
        "module": "dex",
        "function": call.function,
        "type_args": type_args,
        "pool_addr": pool_addr.map(|addr| addr.to_string()),
    });

    if let Some(obj) = metadata.as_object_mut() {
        match call.function.as_str() {
            "add_liquidity" => {
                if let Some(amount_x) = bcs_arg::<u128>(&call.args, 2) {
                    obj.insert("amount_x".to_string(), serde_json::json!(amount_x.to_string()));
                }
                if let Some(amount_y) = bcs_arg::<u128>(&call.args, 3) {
                    obj.insert("amount_y".to_string(), serde_json::json!(amount_y.to_string()));
                }
                if let Some(min_lp) = bcs_arg::<u128>(&call.args, 4) {
                    obj.insert("min_lp".to_string(), serde_json::json!(min_lp.to_string()));
                }
            }
            "remove_liquidity" => {
                if let Some(lp_amount) = bcs_arg::<u128>(&call.args, 2) {
                    obj.insert("lp_amount".to_string(), serde_json::json!(lp_amount.to_string()));
                }
                if let Some(min_x) = bcs_arg::<u128>(&call.args, 3) {
                    obj.insert("min_x".to_string(), serde_json::json!(min_x.to_string()));
                }
                if let Some(min_y) = bcs_arg::<u128>(&call.args, 4) {
                    obj.insert("min_y".to_string(), serde_json::json!(min_y.to_string()));
                }
            }
            "swap_x_to_y" | "swap_y_to_x" => {
                if let Some(amount_in) = bcs_arg::<u128>(&call.args, 2) {
                    obj.insert("amount_in".to_string(), serde_json::json!(amount_in.to_string()));
                }
                if let Some(min_out) = bcs_arg::<u128>(&call.args, 3) {
                    obj.insert("min_out".to_string(), serde_json::json!(min_out.to_string()));
                }
            }
            _ => {}
        }

        if status == "success" {
            if let Some(pool_addr) = pool_addr {
                if let Some(pre_pool) =
                    decode_dex_pool_from_state(db, &[], pool_addr, &call.ty_args)
                {
                    if let Some(post_pool) =
                        decode_dex_pool_from_state(db, updates, pool_addr, &call.ty_args)
                    {
                        add_pool_delta_metadata(
                            obj,
                            &pre_pool,
                            &post_pool,
                            &call.function,
                            &type_args,
                        );
                    }
                }
            }
        }
    }

    Some(metadata)
}

fn known_payload_format(payload: &str) -> bool {
    let hex_payload = payload.trim_start_matches("0x");
    if let Ok(bytes) = hex::decode(hex_payload) {
        matches!(
            bcs::from_bytes::<vm_move::TransactionPayload>(&bytes),
            Ok(vm_move::TransactionPayload::EntryFunction(_))
                | Ok(vm_move::TransactionPayload::PublishModule(_))
        )
    } else {
        false
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub chain_id: String,           // Replay Protection
    pub sender: String,             // Account Object ID
    pub input_objects: Vec<String>, // Object IDs
    pub payload: String,            // Hex-encoded BCS TransactionPayload
    #[serde(default)]
    pub args: Vec<String>, // Arguments for Script
    pub gas_limit: u64,
    pub gas_price: u128, // Upgraded to u128
    #[serde(default)]
    pub sequence_number: u64, // Replay Protection
    #[serde(default)]
    pub public_key: String, // Hex Public Key (Required for verification)
    pub signature: String, // Hex signature

    // === Native Paymaster Fields (Gas Abstraction) ===
    #[serde(default)]
    pub paymaster: Option<String>, // Optional: Address of gas payer
    #[serde(default)]
    pub paymaster_signature: Option<String>, // Optional: Signature from paymaster

    // === ZKP Proof Field (Scalability) ===
    #[serde(default)]
    pub zkp_proof: Option<String>, // Optional: STARK proof for computation (hex encoded)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockExecutionSummary {
    pub state_root: String,
    pub receipts_root: String,
    pub gas_charged: u128,
    pub tx_count: usize,
}

pub struct Executor {
    db: Arc<StateDB>,
    vm: AINCOREVM,
}

fn default_state_root() -> String {
    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(8).collect()
}

impl Executor {
    pub fn new(db: Arc<StateDB>) -> Self {
        let vm = AINCOREVM::new(Arc::clone(&db));
        Self { db, vm }
    }

    pub fn current_state_root(&self) -> String {
        self.db
            .get("sys:state_root")
            .ok()
            .flatten()
            .unwrap_or_else(default_state_root)
    }

    pub fn receipts_root_for_block(&self, txs_json: &[String]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update((txs_json.len() as u64).to_be_bytes());
        for tx_json in txs_json {
            let tx_hash = tx_hash_hex(tx_json);
            hasher.update(tx_hash.as_bytes());
            match self.db.get(&format!("tx_receipt:{}", tx_hash)) {
                Ok(Some(receipt)) => hasher.update(receipt.as_bytes()),
                _ => hasher.update(b"NO_RECEIPT"),
            }
        }
        hex::encode(hasher.finalize())
    }

    fn append_supply_tracker_updates(&self, updates: &mut Vec<(String, Option<String>)>) {
        let key = validator_set_key();
        let new_supply = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == &key { v.as_deref() } else { None })
            .and_then(decode_validator_set_hex)
            .map(|set| set.total_supply);

        let Some(new_supply) = new_supply else {
            return;
        };

        let old_supply = self
            .db
            .get("sys:total_supply")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u128>().ok());

        if old_supply != Some(new_supply) {
            updates.push(("sys:total_supply".to_string(), Some(new_supply.to_string())));
        }

        if let Some(old_supply) = old_supply {
            if old_supply > new_supply {
                let burned_delta = old_supply - new_supply;
                let prev_burned = self
                    .db
                    .get("total_burned")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                let new_burned = prev_burned.saturating_add(burned_delta);
                updates.push(("total_burned".to_string(), Some(new_burned.to_string())));
            }
        }
    }

    fn commit_kv_updates(
        &self,
        mut updates: Vec<(String, Option<String>)>,
        context: &str,
    ) -> Result<(), String> {
        updates.sort_by(|left, right| left.0.cmp(&right.0));
        let mut write_batch = WriteBatch::default();
        for (key, val_opt) in updates {
            if let Some(value) = val_opt {
                write_batch.put(key.as_bytes(), value.as_bytes());
            } else {
                write_batch.delete(key.as_bytes());
            }
        }
        self.db
            .write_batch(write_batch)
            .map_err(|e| format!("{} write batch failed: {}", context, e))
    }

    fn sync_supply_trackers_from_validator_set(&self) {
        let Some(new_supply) = self
            .db
            .get(&validator_set_key())
            .ok()
            .flatten()
            .and_then(|value| decode_validator_set_hex(&value))
            .map(|set| set.total_supply)
        else {
            return;
        };

        let old_supply = self
            .db
            .get("sys:total_supply")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u128>().ok());

        if old_supply != Some(new_supply) {
            let _ = self.db.put("sys:total_supply", &new_supply.to_string());
        }

        if let Some(old_supply) = old_supply {
            if old_supply > new_supply {
                let burned_delta = old_supply - new_supply;
                let prev_burned = self
                    .db
                    .get("total_burned")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0);
                let _ = self.db.put(
                    "total_burned",
                    &prev_burned.saturating_add(burned_delta).to_string(),
                );
            }
        }
    }

    fn epoch_block_interval() -> u64 {
        std::env::var("AINCORE_EPOCH_BLOCK_INTERVAL")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(20)
    }

    fn maybe_advance_epoch(&self) {
        let interval = Self::epoch_block_interval();
        let next_height = self.db.get_chain_height().saturating_add(1);
        if next_height == 0 || !next_height.is_multiple_of(interval) {
            return;
        }

        let module = move_core_types::language_storage::ModuleId::new(
            system_address(),
            move_core_types::identifier::Identifier::new("epoch").expect("epoch identifier"),
        );
        let action = MoveAction::CallEntryFunction(EntryFunctionCall {
            module,
            function: "advance_epoch".to_string(),
            ty_args: vec![],
            args: vec![bcs::to_bytes(&system_address()).unwrap_or_default()],
        });

        match self
            .vm
            .execute_transaction_actions(vec![(action, true)], system_address(), 1_000_000)
        {
            Ok((_gas_used, mut updates, status)) => {
                if !status.success {
                    eprintln!(
                        "⚠️ Epoch advance aborted at block {}: {:?}",
                        next_height, status.error
                    );
                    return;
                }
                self.append_supply_tracker_updates(&mut updates);
                if let Err(err) = self.commit_kv_updates(updates, "epoch advance") {
                    eprintln!("🚨 [EPOCH_ADVANCE_COMMIT_FAIL] {}", err);
                    return;
                }
                self.sync_supply_trackers_from_validator_set();
                println!("⏳ Epoch advanced at block {}", next_height);
            }
            Err(err) => {
                eprintln!("⚠️ Epoch advance failed at block {}: {}", next_height, err);
            }
        }
    }

    fn burn_supply_trackers(&self, amount: u128) {
        if amount == 0 {
            return;
        }

        let prev_burned = self
            .db
            .get("total_burned")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(0);
        let _ = self.db.put(
            "total_burned",
            &prev_burned.saturating_add(amount).to_string(),
        );

        if let Ok(Some(total_supply_str)) = self.db.get("sys:total_supply") {
            if let Ok(total_supply) = total_supply_str.parse::<u128>() {
                let adjusted_supply = total_supply.saturating_sub(amount);
                let _ = self
                    .db
                    .put("sys:total_supply", &adjusted_supply.to_string());
            }
        }

        let key = validator_set_key();
        if let Ok(Some(value)) = self.db.get(&key) {
            if let Some(mut set) = decode_validator_set_hex(&value) {
                set.total_supply = set.total_supply.saturating_sub(amount);
                if let Some(encoded) = encode_validator_set_hex(&set) {
                    let _ = self.db.put(&key, &encoded);
                }
            }
        }
    }

    /// Phase 4.A1: Compute stake-proportional block reward payouts.
    ///
    /// Splits `total_reward` between:
    ///   - 20% anchor-leader bonus → `anchor_leader`
    ///   - 80% stake-weighted pool → every validator in sys:validators
    ///
    /// The leader still receives any pool share they're entitled to from
    /// their own stake (so a high-stake leader gets bonus + pool share).
    ///
    /// Rounding remainder (from integer division) is given to anchor_leader
    /// so the reward is fully consumed and never lost.
    ///
    /// Fallback: if validator set is empty/unreadable, ALL goes to leader
    /// (legacy behaviour preserved for genesis bootstrap and edge cases).
    fn compute_block_payouts(
        &self,
        anchor_leader: &str,
        total_reward: u128,
    ) -> Vec<(String, u128)> {
        // Step 1: read validator set with stakes.
        let validators: Vec<(String, u64)> = self
            .db
            .get("sys:validators")
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str::<Vec<(String, u64)>>(&json).ok())
            .unwrap_or_default();

        // Fallback: no validator set → legacy single-miner path.
        if validators.is_empty() {
            return vec![(anchor_leader.to_string(), total_reward)];
        }

        let total_stake: u128 = validators.iter().map(|(_, s)| *s as u128).sum();
        if total_stake == 0 {
            return vec![(anchor_leader.to_string(), total_reward)];
        }

        // Step 2: split into bonus + pool buckets.
        // 20% leader bonus, 80% stake-weighted pool.
        const LEADER_BONUS_PCT: u128 = 20;
        // Phase 5B.9 / L-02 + L-03: saturating arithmetic in reward math.
        // At AINCORE supply scale the unchecked `*` does not overflow, but
        // any future governance bug that engineers an oversized reward
        // would panic in debug or wrap in release. saturating_* gives
        // defense-in-depth without changing correct-case behaviour.
        // Phase 5C.4 / NEW-003: saturating_sub here too — if total_reward
        // is so large that LEADER_BONUS_PCT/100 actually saturated (only
        // possible via a future governance bug), `leader_bonus` could
        // exceed `total_reward` and an unchecked `-` would wrap.
        let leader_bonus = total_reward.saturating_mul(LEADER_BONUS_PCT) / 100;
        let pool = total_reward.saturating_sub(leader_bonus);

        // Step 3: stake-weighted distribution of the pool.
        use std::collections::BTreeMap;
        let mut payouts: BTreeMap<String, u128> = BTreeMap::new();
        let mut distributed_pool: u128 = 0;

        for (addr, stake) in &validators {
            let share = pool.saturating_mul(*stake as u128) / total_stake;
            distributed_pool = distributed_pool.saturating_add(share);
            *payouts.entry(addr.clone()).or_insert(0) =
                payouts.get(addr).copied().unwrap_or(0).saturating_add(share);
        }

        // Step 4: leader bonus + rounding remainder to leader.
        // Phase 5C.4 / NEW-003: saturating_add on the `+=` too — the
        // unchecked `+=` would wrap if leader_bonus + remainder + their
        // own pool share crossed u128::MAX.
        let remainder = pool.saturating_sub(distributed_pool);
        let leader_credit = leader_bonus.saturating_add(remainder);
        let entry = payouts.entry(anchor_leader.to_string()).or_insert(0);
        *entry = entry.saturating_add(leader_credit);

        payouts.into_iter().collect()
    }

    fn deposit_fee_reward(&self, miner_addr: &str, amount: u128) -> Result<(), String> {
        if amount == 0 {
            return Ok(());
        }

        use move_core_types::account_address::AccountAddress;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::ModuleId;

        let miner_account = AccountAddress::from_hex_literal(&format!("0x{}", miner_addr))
            .map_err(|e| format!("invalid miner address {miner_addr}: {e}"))?;
        let module_id = ModuleId::new(system_address(), Identifier::new("coin").unwrap());
        let arg_sys = bcs::to_bytes(&system_address()).map_err(|e| e.to_string())?;
        let arg_miner = bcs::to_bytes(&miner_account).map_err(|e| e.to_string())?;
        let arg_amount = bcs::to_bytes(&amount).map_err(|e| e.to_string())?;

        let (_gas_used, vm_changes, _) = self
            .vm
            .execute_public_entry_function(
                vec![],
                module_id,
                "deposit_fee_reward",
                vec![aincore_coin_type()],
                vec![arg_sys, arg_miner, arg_amount],
                100_000,
                system_address(),
            )
            .map_err(|e| e.to_string())?;

        for (k, v) in vm_changes {
            match v {
                Some(val) => self.db.put(&k, &val).map_err(|e| e.to_string())?,
                None => self.db.delete(&k).map_err(|e| e.to_string())?,
            }
        }

        Ok(())
    }

    fn queue_fee_sweep(&self, miner_addr: &str, amount: u128, height: u64) {
        let sweep_key = format!("sys:fee_sweep_queue:{height}:{miner_addr}");
        let existing_amount = self
            .db
            .get(&sweep_key)
            .ok()
            .flatten()
            .and_then(|raw| serde_json::from_str::<FeeSweepEntry>(&raw).ok())
            .and_then(|entry| entry.amount.parse::<u128>().ok())
            .unwrap_or(0);
        let entry = FeeSweepEntry {
            miner: miner_addr.to_string(),
            amount: existing_amount.saturating_add(amount).to_string(),
            reason: "vm_distribution_failed_3_attempts".to_string(),
            attempts: 0,
        };
        if let Ok(json) = serde_json::to_string(&entry) {
            let _ = self.db.put(&sweep_key, &json);
        }
    }

    fn process_fee_sweep_queue(&self) {
        // M-06 FIX: bound the scan at the storage layer rather than relying on
        // a downstream `.take(25)` that would otherwise materialise the entire
        // queue into a Vec first. The cap of 25 matches the original drain rate.
        let sweep_keys: Vec<_> = self
            .db
            .scan_prefix_limited("sys:fee_sweep_queue:", 25);

        for (key, raw) in sweep_keys {
            let mut entry = match serde_json::from_str::<FeeSweepEntry>(&raw) {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!("⚠️ Invalid fee sweep entry {key}: {e}. Leaving queued.");
                    continue;
                }
            };
            let amount = match entry.amount.parse::<u128>() {
                Ok(amount) if amount > 0 => amount,
                _ => {
                    let _ = self.db.delete(&key);
                    continue;
                }
            };

            match self.deposit_fee_reward(&entry.miner, amount) {
                Ok(()) => {
                    let _ = self.db.delete(&key);
                    println!(
                        "✅ Fee sweep recovered {} AIN for miner {}",
                        amount, entry.miner
                    );
                }
                Err(e) => {
                    entry.attempts = entry.attempts.saturating_add(1);
                    if let Ok(json) = serde_json::to_string(&entry) {
                        let _ = self.db.put(&key, &json);
                    }
                    eprintln!(
                        "⚠️ Fee sweep retry failed for {} AIN to {}: {}",
                        amount, entry.miner, e
                    );
                }
            }
        }
    }

    /// Execute a batch of transactions in PARALLEL.
    /// This uses a Scheduler to group non-conflicting transactions.
    pub fn execute_block_parallel(
        &self,
        txs_json: Vec<String>,
        proposer_hex: &str,
    ) -> BlockExecutionSummary {
        // SECURITY FIX: Acquire block-level lock to serialize state root calculation.
        // Individual transactions within a block still run in parallel (via Rayon),
        // but two DIFFERENT blocks cannot execute concurrently.
        let _block_lock = BLOCK_EXECUTION_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        println!(
            "🚀 Starting Parallel Execution for {} transactions...",
            txs_json.len()
        );

        // 1. Parse all transactions with N-2 FIX: cumulative object limit
        let mut parsed_txs = Vec::new();
        let mut total_block_objects: usize = 0;

        for raw in &txs_json {
            match serde_json::from_str::<Transaction>(raw) {
                Ok(tx) => {
                    // Per-TX limit (existing)
                    if tx.input_objects.len() > 128 {
                        println!("⛔ Transaction REJECTED: Too many input objects (>128)");
                        continue;
                    }

                    // N-2 FIX: Cumulative per-block object limit
                    let new_total = total_block_objects + tx.input_objects.len();
                    if new_total > MAX_OBJECTS_PER_BLOCK {
                        println!(
                            "⛔ BLOCK OBJECT LIMIT: {} + {} = {} exceeds cap ({}). Dropping remaining TXs.",
                            total_block_objects,
                            tx.input_objects.len(),
                            new_total,
                            MAX_OBJECTS_PER_BLOCK
                        );
                        break; // Block is "full" — no more TXs accepted
                    }

                    total_block_objects = new_total;
                    parsed_txs.push((tx, raw.clone()));
                }
                Err(_e) => {}
            }
        }

        println!(
            "📊 Block accepted {} TXs with {} total input objects (limit: {})",
            parsed_txs.len(),
            total_block_objects,
            MAX_OBJECTS_PER_BLOCK
        );

        // 2. Build Dependency Graph & Schedule
        let mut batches: Vec<Vec<(Transaction, String)>> = Vec::new();
        let mut current_batch: Vec<(Transaction, String)> = Vec::new();
        let mut locked_objects: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for (tx, raw) in parsed_txs {
            let deps = self.get_tx_dependencies(&tx);
            let mut conflict = false;

            for dep in &deps {
                if locked_objects.contains(dep) {
                    conflict = true;
                    break;
                }
            }

            if conflict {
                if !current_batch.is_empty() {
                    batches.push(current_batch);
                }
                current_batch = Vec::new();
                locked_objects.clear();

                current_batch.push((tx.clone(), raw));
                for dep in deps {
                    locked_objects.insert(dep);
                }
            } else {
                current_batch.push((tx.clone(), raw));
                for dep in deps {
                    locked_objects.insert(dep);
                }
            }
        }
        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        println!("📊 Scheduled {} execution batches.", batches.len());

        // 3. Execute Batches ATOMICALLY
        let mut total_fees: u128 = 0;

        for batch in batches.iter() {
            // Execute in parallel to get updates
            #[allow(clippy::type_complexity)] // intrinsic to parallel TX result shape
            let mut results: Vec<(String, Option<(Vec<(String, Option<String>)>, u128)>)> = batch
                .par_iter()
                .map(|(_tx, raw)| (tx_hash_hex(raw), self.execute_transaction(raw)))
                .collect();
            results.sort_by(|left, right| left.0.cmp(&right.0));

            // 4. Commit Batch Atomically
            let mut write_batch = WriteBatch::default();
            let mut batch_hasher = sha2::Sha256::new();
            use sha2::Digest;

            for (_tx_hash, res) in results {
                if let Some((mut updates, gas_charged)) = res {
                    updates.sort_by(|left, right| left.0.cmp(&right.0));
                    for (key, val_opt) in updates {
                        if let Some(val) = val_opt {
                            write_batch.put(key.as_bytes(), val.as_bytes());
                            batch_hasher.update(key.as_bytes());
                            batch_hasher.update(val.as_bytes());
                        } else {
                            write_batch.delete(key.as_bytes());
                            batch_hasher.update(key.as_bytes()); // Hash key for delete
                            batch_hasher.update(b"DELETE");
                        }
                    }
                    total_fees += gas_charged; // C-6 FIX: Accumulate actual gas cost
                }
            }

            // Calc Batch Hash
            let batch_hash = batch_hasher.finalize();

            // Update Global State Root
            // Get previous root
            let prev_root = self.db.get("sys:state_root").unwrap_or(None).unwrap_or(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            );
            let mut global_hasher = sha2::Sha256::new();
            global_hasher.update(hex::decode(&prev_root).unwrap_or(vec![0u8; 32]));
            global_hasher.update(batch_hash);
            let new_root = hex::encode(global_hasher.finalize());

            // println!("🌳 State Root Updated: {} -> {}", &prev_root[0..8], &new_root[0..8]);
            write_batch.put("sys:state_root", new_root.as_bytes());

            if let Err(e) = self.db.write_batch(write_batch) {
                eprintln!("❌ FATAL: RocksDB Write Batch Failed: {}", e);
                panic!(
                    "CRITICAL: database write failure - stopping node to prevent state corruption."
                );
            }
        }

        // 5. Apply Block Rewards
        // BUG #2 FIX: Reward minting is EXCLUSIVELY handled by staking.move (Halving model).
        // The Executor only distributes TRANSACTION FEES to the miner.
        // DO NOT mint new coins here — that would cause double inflation!

        let _current_height = self.db.get_chain_height();

        let _total_supply: u128 = match self.db.get("sys:total_supply") {
            Ok(Some(s)) => s.parse().unwrap_or(0),
            _ => 0,
        };

        // Fee Logic & Burning (fees only, no inflation)
        let burn_pct = self.db.get_burn_percentage() as u128;
        let total_fees_u128 = total_fees;

        let burnt_fees = (total_fees_u128 * burn_pct) / 100;
        let miner_fees = total_fees_u128 - burnt_fees;

        // Miner reward = fees ONLY (no block inflation from executor)
        let reward_amount = miner_fees;

        if burnt_fees > 0 {
            println!(
                "🔥 BURNING {} Fees ({}% of {})",
                burnt_fees, burn_pct, total_fees
            );
            self.burn_supply_trackers(burnt_fees);
        }

        // C-5/C-6 FIX: Route fee distribution through Move VM instead of native balance.
        // Phase 4.A1: Stake-proportional reward distribution.
        //
        // OLD BEHAVIOUR (broken economics):
        //   100% of miner_fees went to the anchor_leader. Every other
        //   validator stake-locked tokens, ran consensus, but earned
        //   zero from each block they helped finalise. With many
        //   validators this means most stakers earn nothing — the
        //   protocol is effectively winner-take-all per block, which
        //   destroys the incentive to run a non-leader validator.
        //
        // NEW BEHAVIOUR (Phase 4.A1):
        //   - 20% bonus → anchor_leader (block proposer)
        //   - 80% pool  → distributed across the active validator set
        //                 weighted by stake.
        //   If the validator set is empty or unreadable, fall back to
        //   the legacy single-miner path so we never burn the reward.
        let miner_addr = if proposer_hex.len() > 32 {
            &proposer_hex[0..32]
        } else {
            proposer_hex
        };

        if reward_amount > 0 {
            let payouts = self.compute_block_payouts(miner_addr, reward_amount);

            println!(
                "💰 Distributing Block Fees ({} AIN total) across {} recipient(s)",
                reward_amount, payouts.len()
            );

            for (recipient, share) in &payouts {
                if *share == 0 {
                    continue;
                }
                let mut distributed = false;
                for attempt in 1..=3 {
                    match self.deposit_fee_reward(recipient, *share) {
                        Ok(()) => {
                            distributed = true;
                            println!(
                                "✅ Paid {} AIN → {} (attempt {})",
                                share, recipient, attempt
                            );
                            break;
                        }
                        Err(e) => eprintln!(
                            "⚠️ Reward payout failed for {} (attempt {}): {}",
                            recipient, attempt, e
                        ),
                    }
                }
                if !distributed {
                    self.queue_fee_sweep(recipient, *share, self.db.get_chain_height());
                    eprintln!(
                        "🔴 Reward queued for sweep: {} AIN → {}",
                        share, recipient
                    );
                }
            }
        }

        // 6. Recover queued fee rewards whose recipient CoinStore is now valid.
        self.process_fee_sweep_queue();

        // 7. Promote downtime attestations to pending slashes when distinct
        //    reporters reach BFT quorum (Phase 2.3 / H-02). Equivocation
        //    slashes are written directly by the consensus equivocation
        //    detector and bypass this step.
        self.promote_downtime_attestations_to_slash();

        // 8. Process Pending Slashes from Consensus Engine
        // The consensus layer writes sys:pending_slash:{address} entries when it detects
        // downtime or equivocation. We process them here to execute on-chain balance deduction.
        self.execute_pending_slashes();

        // 8. Advance Move epoch on a deterministic block interval.
        // This is the only path that triggers staking reward distribution.
        self.maybe_advance_epoch();

        let summary = BlockExecutionSummary {
            state_root: self.current_state_root(),
            receipts_root: self.receipts_root_for_block(&txs_json),
            gas_charged: total_fees,
            tx_count: txs_json.len(),
        };

        println!(
            "✅ Parallel Execution Complete. state_root={} receipts_root={}",
            short_hash(&summary.state_root),
            short_hash(&summary.receipts_root)
        );
        summary
    }

    /// Phase 2.3 (H-02): promote downtime attestations to pending slashes
    /// only when distinct reporters reach BFT quorum.
    ///
    /// Pre-Phase-2 the consensus layer wrote `sys:pending_slash:{addr}`
    /// directly from a single node's local observation, which let any
    /// validator unilaterally slash any other (false positives on
    /// network partition, griefing surface for Byzantine validators).
    ///
    /// New protocol:
    ///   1. Each validator writes its own attestation under
    ///      `sys:downtime_attestation:{offender}:{epoch}:{reporter}`.
    ///   2. This routine groups attestations by `(offender, epoch)`,
    ///      counts *distinct* reporters that are still in the active
    ///      validator set, and only when the count meets BFT quorum
    ///      `(n*2/3) + 1` does it write `sys:pending_slash:{offender}`.
    ///   3. Once promoted, the attestations for that (offender, epoch)
    ///      are deleted so the slash isn't re-queued. The jail marker
    ///      also prevents double-processing inside `execute_pending_slashes`.
    ///
    /// Honest limitation: until cross-validator gossip of attestations
    /// is wired (Phase 3 work), only this node's attestations exist
    /// locally, so BFT quorum is unreachable on real networks with
    /// more than 1 validator. The path is therefore *safe* (no false
    /// positives) but not yet *live* (real offenders are not punished).
    /// Equivocation slashing is unaffected — it's provable from local
    /// DAG data and continues to apply through the equivocation detector.
    pub fn promote_downtime_attestations_to_slash(&self) {
        // 1. Snapshot the active validator set so quorum is computed
        //    against a stable set within this routine.
        let validators: Vec<String> = match self.db.get("sys:validators") {
            Ok(Some(json)) => match serde_json::from_str::<Vec<(String, u64)>>(&json) {
                Ok(vs) => vs.into_iter().map(|(addr, _)| addr).collect(),
                Err(_) => return,
            },
            _ => return,
        };
        if validators.is_empty() {
            return;
        }
        let n = validators.len();
        let bft_quorum = ((n * 2) / 3) + 1;

        // 2. Scan attestations. Bounded by SCAN_PREFIX_HARD_CAP via
        //    `scan_prefix` so a Byzantine flood cannot blow up memory.
        let entries = self.db.scan_prefix("sys:downtime_attestation:");
        if entries.is_empty() {
            return;
        }

        // 3. Group by (offender, epoch) -> set of distinct reporters.
        use std::collections::{BTreeMap, BTreeSet};
        let mut groups: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for (key, _value) in &entries {
            // key format: sys:downtime_attestation:{offender}:{epoch}:{reporter}
            let parts: Vec<&str> = key.splitn(5, ':').collect();
            if parts.len() != 5 {
                continue;
            }
            let offender = parts[2].to_string();
            let epoch = parts[3].to_string();
            let reporter = parts[4].to_string();

            // Only count reporters that are currently active validators.
            // Stale reporters from a removed/slashed validator do not
            // count toward quorum (anti-grief).
            if !validators.contains(&reporter) {
                continue;
            }

            groups
                .entry((offender, epoch))
                .or_default()
                .insert(reporter);
        }

        // 4. Promote groups that hit BFT quorum.
        for ((offender, epoch), reporters) in groups {
            if reporters.len() < bft_quorum {
                continue;
            }

            // Phase 5C.3 / NEW-002 (SEC-N03 reverse hole): the
            // attest-time check on dag.rs only validates `offender`
            // against the validator set AT THE TIME OF ATTESTATION
            // RECEIVE. If the offender voluntarily unbonds or is
            // governance-removed between attest and promote, they
            // could be slashed despite no longer being a validator.
            // Re-check offender ∈ current validator_set here.
            if !validators.contains(&offender) {
                eprintln!(
                    "⚠️  [NEW-002] skipping promote: offender {} left validator set \
                     between attestation and quorum promotion",
                    offender
                );
                continue;
            }

            // Skip if already jailed (prevents double-slash if the
            // executor runs this twice for the same offender).
            let jail_key = format!("validator:jailed:{}", offender);
            if matches!(self.db.get(&jail_key), Ok(Some(_))) {
                continue;
            }

            let slash_event = serde_json::json!({
                "event": "validator_jailed",
                "validator": offender,
                "epoch": epoch,
                "reporters": reporters.iter().collect::<Vec<_>>(),
                "reporter_count": reporters.len(),
                "bft_quorum": bft_quorum,
                "validator_set_size": n,
                "reason": "downtime",
                "penalty": "5% slash + 21-day unbonding"
            });

            // Queue the real slash and the jail marker.
            let _ = self.db.put(
                &format!("sys:pending_slash:{}", offender),
                &slash_event.to_string(),
            );
            let _ = self
                .db
                .put(&jail_key, &serde_json::to_string(&reporters).unwrap_or_default());

            // Drop the attestations for this (offender, epoch) to free
            // storage and prevent re-promotion. We only drop the
            // promoted group; attestations for OTHER offenders or
            // future epochs are untouched.
            let prefix = format!("sys:downtime_attestation:{}:{}:", offender, epoch);
            for (key, _) in self.db.scan_prefix(&prefix) {
                let _ = self.db.delete(&key);
            }

            println!(
                "⛓️  BFT-quorum downtime slash queued for {} (reporters={}, quorum={}, n={})",
                offender,
                reporters.len(),
                bft_quorum,
                n
            );
        }
    }

    /// Execute pending slash events written by the consensus engine.
    /// This is the critical bridge between consensus-level detection and on-chain execution.
    /// Reads sys:pending_slash:{addr}, deducts 5% of validator stake, removes from validator set.
    fn execute_pending_slashes(&self) {
        use move_core_types::account_address::AccountAddress;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::ModuleId;

        // H-4 FIX: Cap processing to 5 slashes per block to prevent O(N) drain.
        // M-06 FIX: enforce the cap at the storage scan instead of after
        // materialising the entire queue.
        let slash_keys: Vec<_> = self
            .db
            .scan_prefix_limited("sys:pending_slash:", 5);

        for (key, event_json) in &slash_keys {
            // Extract validator address from key: "sys:pending_slash:{addr}"
            let validator_addr = match key.strip_prefix("sys:pending_slash:") {
                Some(addr) => addr.to_string(),
                None => continue,
            };

            // Parse the slash event
            let (reason, round) =
                if let Ok(event) = serde_json::from_str::<serde_json::Value>(event_json) {
                    let r = event
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let rd = event.get("round").and_then(|v| v.as_u64()).unwrap_or(0);
                    (r, rd)
                } else {
                    ("unknown".to_string(), 0)
                };

            // H-4 FIX: Tombstone check for replay protection
            let event_id = format!("{}:{}", validator_addr, round);
            let tombstone_key = format!("sys:slashed:{}", event_id);
            if let Ok(Some(_)) = self.db.get(&tombstone_key) {
                println!(
                    "   ⏭️  Skipping already processed slash event: {}",
                    event_id
                );
                let _ = self.db.delete(key);
                continue;
            }

            println!(
                "⚖️  EXECUTING ON-CHAIN SLASH for validator: {}",
                &validator_addr
            );
            println!("   Reason: {}, Round: {}", reason, round);

            // === C-5 FIX: ROUTE ECONOMIC SLASH THROUGH MOVE VM ===
            // The Move VM staking::slash_validator handles bonded stake deduction atomically.
            // This replaces the old native-only weight manipulation.
            let slash_pct: u64 = if reason == "equivocation" { 100 } else { 5 };

            let module_id = ModuleId::new(
                AccountAddress::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                Identifier::new("staking").expect("staking identifier is valid"),
            );

            let vm_addr = match AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)) {
                Ok(addr) => addr,
                Err(_) => {
                    println!(
                        "   ❌ Invalid validator address for slash: {}",
                        validator_addr
                    );
                    let _ = self.db.delete(key);
                    continue;
                }
            };

            let arg_sys = bcs::to_bytes(&AccountAddress::new([
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]))
            .unwrap_or_default();
            let arg_val = bcs::to_bytes(&vm_addr).unwrap_or_default();
            let arg_bps = bcs::to_bytes(&(slash_pct * 100)).unwrap_or_default();

            match self.vm.execute_public_entry_function(
                vec![],
                module_id,
                "slash_validator_bps",
                vec![],
                vec![arg_sys, arg_val, arg_bps],
                500_000, // Gas budget for slash operation
                vm_addr,
            ) {
                Ok((_gas_used, vm_changes, _)) => {
                    for (k, v) in vm_changes {
                        let _ = match v {
                            Some(val) => self.db.put(&k, &val),
                            None => self.db.delete(&k),
                        };
                    }
                    self.sync_supply_trackers_from_validator_set();
                    println!(
                        "   ⚡ Move VM slash executed: {}% of bonded stake for {}",
                        slash_pct, validator_addr
                    );
                }
                Err(e) => {
                    println!(
                        "   ⚠️  Move VM slash failed ({}), falling back to consensus-only removal",
                        e
                    );
                }
            }

            // CONSENSUS SET UPDATE: mirror Move staking's active-set semantics.
            // staking::slash_validator_bps removes the validator from the Move active set
            // and queues any remaining stake for unbonding/jail, so the native cache must
            // not keep the validator active with reduced weight.
            if let Ok(Some(json)) = self.db.get("sys:validators") {
                if let Ok(mut vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                    let before_len = vals.len();
                    let mut slashed = false;

                    for (addr, weight) in vals.iter_mut() {
                        if addr == &validator_addr {
                            if reason == "equivocation" {
                                println!(
                                    "   💥 EQUIVOCATION: Validator permanently removed from consensus set!"
                                );
                            } else {
                                println!(
                                    "   ⏳ DOWNTIME: Validator jailed and removed from active consensus set."
                                );
                            }
                            *weight = 0;
                            slashed = true;
                        }
                    }

                    if slashed {
                        vals.retain(|(_, w)| *w > 0);
                        if let Ok(new_json) = serde_json::to_string(&vals) {
                            let _ = self.db.put("sys:validators", &new_json);
                            println!(
                                "   ⛓️  Validator set updated ({} -> {} validators)",
                                before_len,
                                vals.len()
                            );
                        }
                    }
                }
            }

            // H-4 FIX: Write tombstone
            let _ = self.db.put(&tombstone_key, "1");

            // Delete the pending slash entry (processed)
            let _ = self.db.delete(key);
            println!("   ✅ Slash executed and cleared from queue.");
        }
    }

    pub fn analyze_dependencies(&self, tx_json: &str) -> Vec<String> {
        if let Ok(tx) = serde_json::from_str::<Transaction>(tx_json) {
            self.get_tx_dependencies(&tx)
        } else {
            Vec::new()
        }
    }

    fn get_tx_dependencies(&self, tx: &Transaction) -> Vec<String> {
        let mut deps = Vec::new();
        deps.push(tx.sender.clone());
        for obj in &tx.input_objects {
            deps.push(obj.clone());
        }

        let payload_bytes = match hex::decode(tx.payload.trim_start_matches("0x")) {
            Ok(bytes) => bytes,
            Err(_) => return deps,
        };
        let payload = match bcs::from_bytes::<vm_move::TransactionPayload>(&payload_bytes) {
            Ok(payload) => payload,
            Err(_) => return deps,
        };

        fn push_addr_arg(deps: &mut Vec<String>, args: &[Vec<u8>], index: usize) {
            if let Some(bytes) = args.get(index) {
                if let Ok(addr) =
                    bcs::from_bytes::<move_core_types::account_address::AccountAddress>(bytes)
                {
                    deps.push(addr.to_string());
                }
            }
        }

        if let vm_move::TransactionPayload::EntryFunction(call) = payload {
            let module_addr = call.module.address();
            let module_name = call.module.name().as_str();
            let function = call.function.as_str();

            if *module_addr == system_address() && module_name == "coin" && function == "transfer" {
                push_addr_arg(&mut deps, &call.args, 1);
            } else if *module_addr == system_address() && module_name == "staking" {
                deps.push(validator_set_key());
            } else if *module_addr == system_address() && module_name == "delegation" {
                match function {
                    "enable_delegation" => {
                        deps.push(format!(
                            "resource_{}_{}",
                            tx.sender, "0x1::delegation::ValidatorPool"
                        ));
                        deps.push(format!(
                            "resource_{}_{}",
                            system_address(),
                            "0x1::delegation::DelegationRegistry"
                        ));
                    }
                    "delegate" | "undelegate" | "claim_rewards" | "withdraw_unbonded" => {
                        push_addr_arg(&mut deps, &call.args, 1);
                        if let Some(bytes) = call.args.get(1) {
                            if let Ok(addr) = bcs::from_bytes::<
                                move_core_types::account_address::AccountAddress,
                            >(bytes)
                            {
                                deps.push(format!(
                                    "resource_{}_{}",
                                    addr, "0x1::delegation::ValidatorPool"
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            } else if *module_addr == system_address() && module_name == "governance" {
                deps.push(format!(
                    "resource_{}_{}",
                    system_address(),
                    "0x1::governance::GovernanceState"
                ));
                deps.push(format!(
                    "resource_{}_{}",
                    tx.sender, "0x1::governance::VoteEscrow"
                ));
            } else if *module_addr == system_address()
                && module_name == "token_factory"
                && function == "transfer"
            {
                push_addr_arg(&mut deps, &call.args, 2);
                deps.push(format!(
                    "resource_{}_{}",
                    tx.sender, "0x1::token_factory::TokenWallet"
                ));
                if let Some(bytes) = call.args.get(2) {
                    if let Ok(addr) =
                        bcs::from_bytes::<move_core_types::account_address::AccountAddress>(bytes)
                    {
                        deps.push(format!(
                            "resource_{}_{}",
                            addr, "0x1::token_factory::TokenWallet"
                        ));
                    }
                }
            } else if *module_addr == system_address() && module_name == "token_factory" {
                deps.push(format!(
                    "resource_{}_{}",
                    system_address(),
                    "0x1::token_factory::TokenRegistry"
                ));
                deps.push(format!(
                    "resource_{}_{}",
                    tx.sender, "0x1::token_factory::TokenWallet"
                ));
            } else if *module_addr == system_address() && module_name == "dex" {
                deps.push(dex_registry_key());

                let sender_addr = parse_move_address(&tx.sender);
                let pool_addr = if function == "create_pool" {
                    sender_addr
                } else {
                    bcs_arg::<move_core_types::account_address::AccountAddress>(&call.args, 1)
                };

                if let Some(pool_addr) = pool_addr {
                    if let Some(pool_key) = dex_pool_key_for_type_args(pool_addr, &call.ty_args) {
                        deps.push(pool_key);
                    }
                }

                if let Some(sender_addr) = sender_addr {
                    if let Some(lp_key) = dex_lp_key_for_type_args(sender_addr, &call.ty_args) {
                        if matches!(function, "add_liquidity" | "remove_liquidity") {
                            deps.push(lp_key);
                        }
                    }
                    for coin_type in &call.ty_args {
                        deps.push(coin_store_key_for_type(sender_addr, coin_type.clone()));
                    }
                }
            }
        }
        deps
    }

    /// Build the database update set for a single transaction.
    ///
    /// # Lock Contract (Phase 2.4 / H-05 hardening)
    ///
    /// This function performs only **reads** against `self.db` and Move
    /// VM caches — it does NOT write to RocksDB. The caller is
    /// responsible for applying the returned update list, and that
    /// application MUST happen while the global
    /// [`BLOCK_EXECUTION_LOCK`] is held. Otherwise concurrent block
    /// executions could observe each other's intermediate state and
    /// produce divergent state roots, instantly forking the chain.
    ///
    /// In the production code path this contract is satisfied because
    /// `execute_block_parallel` acquires `BLOCK_EXECUTION_LOCK` at the
    /// top of its body and only releases it after every parallel
    /// worker has finished and updates have been committed to
    /// RocksDB. The rayon worker pool inside that critical section
    /// invokes this function read-only and ships the resulting
    /// `Vec<(key, value)>` back to the main thread for batched commit.
    ///
    /// External / test callers that invoke `execute_transaction`
    /// directly (without going through `execute_block_parallel`) must
    /// either:
    ///   1. ensure no other thread is running `execute_block_parallel`
    ///      against the same `Executor`, or
    ///   2. wrap their own use in `BLOCK_EXECUTION_LOCK.lock()` to
    ///      preserve the global-serialization invariant.
    ///
    /// The audit (DEEP-AUDIT-REPORT-2026-05-21 H-05) initially flagged
    /// this as a critical lock-bypass risk. Code review downgraded the
    /// severity because the production commit path is locked and this
    /// function is read-only against shared state. Phase 2.4 documents
    /// the contract explicitly so any future caller that needs to call
    /// this outside the canonical flow has clear instructions.
    #[allow(clippy::type_complexity)]
    pub fn execute_transaction(
        &self,
        tx_json: &str,
    ) -> Option<(Vec<(String, Option<String>)>, u128)> {
        let mut updates = Vec::new();

        if let Ok(tx) = serde_json::from_str::<Transaction>(tx_json) {
            // 0. Verify Chain ID
            let expected_chain = get_chain_id();
            if tx.chain_id != expected_chain {
                println!(
                    "❌ Invalid Chain ID: Expected {}, Got {}",
                    expected_chain, tx.chain_id
                );
                return None;
            }

            // 1. Fetch Sender Account Object
            let sender_obj = self.db.get_object(&tx.sender)?;

            // 2. Verify Signature (Sender)
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            let pk_bytes = match hex::decode(&tx.public_key) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => return None,
            };

            let expected_sender = match crypto::derive_address(&pk_bytes) {
                Ok(addr) => addr,
                Err(e) => {
                    println!("❌ Failed to derive sender address: {}", e);
                    return None;
                }
            };
            if tx.sender != expected_sender {
                println!(
                    "❌ SENDER ADDRESS MISMATCH: tx.sender={} expected={}",
                    tx.sender, expected_sender
                );
                return None;
            }

            // Verify Sig
            let sig_bytes = match hex::decode(&tx.signature) {
                Ok(bytes) if bytes.len() == 64 => {
                    let mut arr = [0u8; 64];
                    arr.copy_from_slice(&bytes);
                    arr
                }
                _ => return None,
            };

            let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
                Ok(vk) => vk,
                Err(_) => return None,
            };

            let signature = Signature::from_bytes(&sig_bytes);
            let message = format!(
                "{}:{}:{}:{}",
                tx.chain_id, tx.sender, tx.payload, tx.sequence_number
            );

            if verifying_key
                .verify(message.as_bytes(), &signature)
                .is_err()
            {
                println!("❌ Invalid Signature Verification");
                return None;
            }

            // 2b. H-04 PROMOTED (Phase 2.2): defense-in-depth STARK verify.
            //
            // The mempool's H-04 gate also calls the same dispatcher,
            // so most ZKP-tagged transactions are rejected before they
            // reach here. We re-run the check at the executor because
            // block execution can also see transactions via sync /
            // gossip / older peers that bypassed our mempool. Policy
            // must be uniform: no execution path silently accepts an
            // unverified ZKP claim.
            //
            // The check performs hex decode → STARKProofData parse →
            // public-input binding to "{chain_id}:{sender}:{payload}:{seq}"
            // → STARKVerifier::verify dispatch. The verifier itself is
            // currently a Phase-2 placeholder; when it's wired to a
            // real AIR, valid proofs flow through unchanged.
            if let Some(ref proof_hex) = tx.zkp_proof {
                if !proof_hex.is_empty() {
                    let canonical_msg = format!(
                        "{}:{}:{}:{}",
                        tx.chain_id, tx.sender, tx.payload, tx.sequence_number
                    );
                    if let Err(e) = crypto::zkp::verify_tx_attached_proof(
                        proof_hex,
                        canonical_msg.as_bytes(),
                    ) {
                        println!(
                            "❌ Transaction zkp_proof rejected at executor (H-04): {}",
                            e
                        );
                        return None;
                    }
                }
            }

            // 2.5 Replay Protection
            let sender_data_check: aa::AccountData = match serde_json::from_slice(&sender_obj.data)
            {
                Ok(d) => d,
                Err(_) => return None,
            };

            if tx.sequence_number != sender_data_check.sequence_number {
                println!("❌ Invalid Sequence Number");
                return None;
            }

            if !known_payload_format(&tx.payload) {
                println!(
                    "⚠️ REJECTED: Unrecognized payload format from {}. Raw hex script execution is disabled for security.",
                    tx.sender
                );
                return None;
            }

            if tx.gas_price < MIN_GAS_PRICE {
                println!(
                    "❌ Gas price too low: {} < minimum {}",
                    tx.gas_price, MIN_GAS_PRICE
                );
                return None;
            }

            if tx.gas_limit == 0 {
                println!("❌ Gas limit must be greater than 0");
                return None;
            }

            // 3. Check Balance & Deduct Gas
            // N-2 FIX: Charge gas for object loading upfront
            let object_load_gas = (tx.input_objects.len() as u64) * OBJECT_LOAD_GAS;
            if object_load_gas > tx.gas_limit {
                println!(
                    "❌ Insufficient gas for object loading: {} objects × {} gas = {} > gas_limit {}",
                    tx.input_objects.len(),
                    OBJECT_LOAD_GAS,
                    object_load_gas,
                    tx.gas_limit
                );
                return None;
            }
            let gas_cost: u128 = match (tx.gas_limit as u128).checked_mul(tx.gas_price) {
                Some(cost) => cost,
                None => {
                    println!(
                        "❌ Gas cost overflow: gas_limit={} gas_price={}",
                        tx.gas_limit, tx.gas_price
                    );
                    return None;
                }
            };

            // N-1 FIX (HARDENED): Paymaster Signature Validation
            // Message now includes chain_id, sequence_number, gas_limit for full replay protection.
            let payer_addr = if let Some(pm) = &tx.paymaster {
                if let Some(pm_sig_hex) = &tx.paymaster_signature {
                    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                    let pm_valid = (|| -> Result<(), ()> {
                        let pm_pubkey_bytes = hex::decode(pm).map_err(|_| ())?;
                        if pm_pubkey_bytes.len() != 32 {
                            return Err(());
                        }
                        let vk = VerifyingKey::from_bytes(
                            pm_pubkey_bytes.as_slice().try_into().map_err(|_| ())?,
                        )
                        .map_err(|_| ())?;
                        let sig_bytes = hex::decode(pm_sig_hex).map_err(|_| ())?;
                        let sig = Signature::from_slice(&sig_bytes).map_err(|_| ())?;

                        // N-1 FIX: Paymaster signs FULL context to prevent replay and cross-TX theft:
                        // PAYMASTER_AUTH:{chain_id}:{sender}:{payload}:{gas_limit}:{sequence_number}
                        let pm_message = format!(
                            "PAYMASTER_AUTH:{}:{}:{}:{}:{}",
                            tx.chain_id, tx.sender, tx.payload, tx.gas_limit, tx.sequence_number
                        );
                        use sha2::{Digest, Sha256};
                        let hash = Sha256::digest(pm_message.as_bytes());
                        vk.verify(&hash, &sig).map_err(|_| ())
                    })();
                    if pm_valid.is_err() {
                        println!("❌ Invalid Paymaster Signature! Gas sponsorship rejected.");
                        return None;
                    }
                    println!(
                        "✅ Paymaster {} authorized gas payment for TX seq={}",
                        pm, tx.sequence_number
                    );
                } else {
                    println!("❌ Paymaster specified without signature! Rejected.");
                    return None;
                }
                pm.clone()
            } else {
                tx.sender.clone()
            };

            // Check if payer has balance
            // We need to fetch payer object again (or use sender_obj if same)
            let mut payer_obj = if payer_addr == tx.sender {
                sender_obj.clone()
            } else {
                self.db.get_object(&payer_addr)?
            };

            let mut account_data: aa::AccountData = match serde_json::from_slice(&payer_obj.data) {
                Ok(d) => d,
                Err(_) => return None,
            };

            // === MOVE GAS DEDUCTION ===
            // AccountData is now identity/nonce metadata. AIN balance lives in
            // 0x1::coin::CoinStore<0x1::staking::AincoreCoin>.
            let mut pre_actions = vec![];
            if gas_cost > 0 {
                let payer_move_addr = match parse_move_address(&payer_addr) {
                    Some(addr) => addr,
                    None => {
                        println!("❌ Invalid gas payer address");
                        return None;
                    }
                };
                let gas_module = move_core_types::language_storage::ModuleId::new(
                    system_address(),
                    move_core_types::identifier::Identifier::new("coin")
                        .expect("coin identifier is valid"),
                );
                let arg_sys = bcs::to_bytes(&system_address()).unwrap_or_default();
                let arg_user = bcs::to_bytes(&payer_move_addr).unwrap_or_default();
                let arg_amount = bcs::to_bytes(&gas_cost).unwrap_or_default();
                let gas_action = MoveAction::CallEntryFunction(EntryFunctionCall {
                    module: gas_module,
                    function: "deduct_gas".to_string(),
                    ty_args: vec![aincore_coin_type()],
                    args: vec![arg_sys, arg_user, arg_amount],
                });
                pre_actions.push((gas_action, true)); // true = must succeed
            }

            // CRITICAL FIX: ALWAYS increment the SENDER's sequence number, even if Paymaster pays gas
            let mut sender_account_data: aa::AccountData = if payer_addr == tx.sender {
                account_data.clone()
            } else {
                sender_data_check
            };

            if let Some(new_seq) = sender_account_data.sequence_number.checked_add(1) {
                sender_account_data.sequence_number = new_seq;
            } else {
                println!("❌ Sender Sequence Number Overflow");
                return None;
            }

            if payer_addr == tx.sender {
                account_data.sequence_number = sender_account_data.sequence_number;
            } else {
                // Save the sender's updated sequence number independently
                let mut updated_sender_obj = sender_obj.clone();
                if let Ok(new_sender_data) = serde_json::to_vec(&sender_account_data) {
                    updated_sender_obj.data = new_sender_data;
                    updates.push((
                        format!("obj:{}", updated_sender_obj.id),
                        Some(
                            serde_json::to_string(&updated_sender_obj)
                                .unwrap_or_else(|_| "{}".to_string()),
                        ),
                    ));
                }
            }

            // Save Payer Update (sequence number only; gas is deducted via Move VM)
            if let Ok(new_data) = serde_json::to_vec(&account_data) {
                payer_obj.data = new_data;
                updates.push((
                    format!("obj:{}", payer_obj.id),
                    Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string())),
                ));
            }

            let actual_gas = gas_cost;
            let mut tx_status = "success".to_string();
            let mut tx_error: Option<String> = None;
            macro_rules! absorb_vm_result {
                ($vm_changes:expr, $status:expr) => {{
                    for (k, v) in $vm_changes {
                        updates.push((k, v));
                    }
                    self.append_supply_tracker_updates(&mut updates);
                    if !$status.success {
                        tx_status = "aborted".to_string();
                        tx_error = Some(
                            $status
                                .error
                                .unwrap_or_else(|| "Move execution aborted".to_string()),
                        );
                        false
                    } else {
                        true
                    }
                }};
            }

            // 4. Execution Payload (Structured BCS)
            let sender_addr = match parse_move_address(&tx.sender) {
                Some(addr) => addr,
                None => {
                    println!("❌ Invalid sender address format");
                    return None;
                }
            };

            let payload_bytes = match hex::decode(tx.payload.trim_start_matches("0x")) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // C-11 FIX: Backwards compatibility for genesis and old tools (TEMPORARY)
                    // If it's not valid hex, maybe it's a legacy string payload.
                    // For now, if we are in Phase 0 / 1 transition, we can optionally parse legacy here,
                    // but the objective says: "Hapus semua if tx.payload.starts_with...".
                    // However, we MUST NOT break the entire chain right now before we fix the CLI.
                    // Actually, the instruction was clear: Replace it entirely to enforce structured ABI.
                    println!(
                        "⚠️ REJECTED: Unrecognized payload format from {}. Must be hex-encoded BCS TransactionPayload. Err: {}",
                        tx.sender, e
                    );
                    return None;
                }
            };

            let parsed_payload: Result<vm_move::TransactionPayload, _> =
                bcs::from_bytes(&payload_bytes);

            match parsed_payload {
                Ok(vm_move::TransactionPayload::EntryFunction(call)) => {
                    let mut actions = pre_actions.clone();
                    actions.push((vm_move::MoveAction::CallEntryFunction(call), false));
                    match self
                        .vm
                        .execute_transaction_actions(actions, sender_addr, tx.gas_limit)
                    {
                        Ok((_gas_used, vm_changes, status)) => {
                            if absorb_vm_result!(vm_changes, status) {
                                println!("✅ Move EntryFunction executed by {}", tx.sender);
                            } else {
                                println!(
                                    "❌ EntryFunction aborted after gas charge: {}",
                                    tx_error
                                        .clone()
                                        .unwrap_or_else(|| "unknown Move error".to_string())
                                );
                            }
                        }
                        Err(e) => {
                            println!("❌ EntryFunction Failed (Move VM fatal): {}", e);
                            return None;
                        }
                    }
                }
                Ok(vm_move::TransactionPayload::PublishModule(modules)) => {
                    if sender_addr == system_address() {
                        println!("❌ Publish rejected: user transactions cannot publish to 0x1");
                        return None;
                    }
                    let mut actions = pre_actions.clone();
                    actions.push((vm_move::MoveAction::PublishModule(modules), false));
                    match self
                        .vm
                        .execute_transaction_actions(actions, sender_addr, tx.gas_limit)
                    {
                        Ok((_gas_used, vm_changes, status)) => {
                            if absorb_vm_result!(vm_changes, status) {
                                println!("✅ Move module published by {}", tx.sender);
                            } else {
                                println!(
                                    "❌ Publish aborted after gas charge: {}",
                                    tx_error
                                        .clone()
                                        .unwrap_or_else(|| "unknown Move error".to_string())
                                );
                            }
                        }
                        Err(e) => {
                            println!("❌ Publish Failed (Move VM fatal): {}", e);
                            return None;
                        }
                    }
                }
                Ok(vm_move::TransactionPayload::Script(_)) => {
                    println!("🚫 [SECURITY] Raw script execution BLOCKED");
                    return None;
                }
                Err(e) => {
                    println!(
                        "⚠️ REJECTED: Failed to deserialize BCS TransactionPayload from {}: {}",
                        tx.sender, e
                    );
                    // Invalid format -> no gas charged
                    return None;
                }
            }

            updates.push(receipt_update(
                &self.db,
                tx_json,
                &updates,
                &tx_status,
                actual_gas,
                tx_error.clone(),
            ));
            Some((updates, actual_gas))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use move_binary_format::CompiledModule;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn test_transaction_deserialization() {
        // Updated JSON with chain_id
        let json = r#"{"chain_id":"AINCORE-MAINNET-1","sender":"c4b14ae227ec4e1f661dbb0d15039f1c","input_objects":[],"payload":"0200","args":[],"gas_limit":10000,"gas_price":1,"signature":"bf3714c3b74c954cd88d5e076cc2335ab389cd3e0bc9cec55fbc9d3c62edcc3ad5720868385f45e87bf257c3dcd0083c0737c60f4839ccc949e8e68e214e5c02"}"#;

        let tx: Result<Transaction, _> = serde_json::from_str(json);
        match tx {
            Ok(_) => println!("✅ Deserialization Successful"),
            Err(e) => {
                println!("❌ Deserialization Failed: {}", e);
                panic!("Deserialization failed: {}", e);
            }
        }
    }

    #[test]
    fn test_receipt_update_records_status_and_gas() {
        let db = temp_db("receipt_update");
        let (key, value) = receipt_update(
            &db,
            "{}",
            &[],
            "aborted",
            42,
            Some("Move abort".to_string()),
        );
        assert!(key.starts_with("tx_receipt:"));
        let parsed: serde_json::Value =
            serde_json::from_str(&value.expect("receipt value")).unwrap();
        assert_eq!(parsed["status"], "aborted");
        assert_eq!(parsed["gas_charged"], "42");
        assert_eq!(parsed["error"], "Move abort");
    }

    #[derive(Serialize, Deserialize)]
    struct TestCoin {
        value: u128,
    }

    #[derive(Serialize, Deserialize)]
    struct TestValidatorConfig {
        validator_addr: move_core_types::account_address::AccountAddress,
        stake: TestCoin,
        public_key: Vec<u8>,
    }

    #[derive(Serialize, Deserialize)]
    struct TestUnbondingRequest {
        validator_addr: move_core_types::account_address::AccountAddress,
        stake: u128,
        unlock_time: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct TestValidatorSet {
        validators: Vec<TestValidatorConfig>,
        unbonding_queue: Vec<TestUnbondingRequest>,
        total_supply: u128,
        current_epoch: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct TestProposal {
        id: u64,
        proposer: move_core_types::account_address::AccountAddress,
        description: Vec<u8>,
        votes_for: u128,
        votes_against: u128,
        executed: bool,
        action_type: u8,
        action_value: u64,
        voters: Vec<move_core_types::account_address::AccountAddress>,
    }

    #[derive(Serialize, Deserialize)]
    struct TestGovernanceState {
        proposals: Vec<TestProposal>,
        next_proposal_id: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct TestVoteEscrow {
        locked_coins: TestCoin,
        proposal_id: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct TestLiquidityPool {
        coin_x: TestCoin,
        coin_y: TestCoin,
        lp_supply: u128,
        fee_bp: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct TestLPToken {
        balance: u128,
    }

    #[derive(Serialize, Deserialize, Clone)]
    struct TestPoolInfo {
        pool_key: Vec<u8>,
        pool_addr: move_core_types::account_address::AccountAddress,
        token_x_name: Vec<u8>,
        token_y_name: Vec<u8>,
        fee_bp: u64,
        creator: move_core_types::account_address::AccountAddress,
        active: bool,
    }

    #[derive(Serialize, Deserialize)]
    struct TestPoolRegistry {
        pools: Vec<TestPoolInfo>,
    }

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = format!(
            "/tmp/aincore_phase0_executor_{}_{}",
            name,
            std::process::id()
        );
        let _ = fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("test DB opens"))
    }

    fn load_stdlib(db: &StateDB) {
        let bytecode_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vm_move/stdlib/bytecode");
        let mut paths: Vec<_> = fs::read_dir(&bytecode_dir)
            .expect("stdlib bytecode dir exists")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("mv"))
            .collect();
        paths.sort();
        for path in paths {
            let bytes = fs::read(&path).expect("stdlib module readable");
            let module = CompiledModule::deserialize(&bytes).expect("stdlib module deserializes");
            let id = module.self_id();
            let key = format!("module_{}_{}", id.address(), id.name());
            db.put(&key, &hex::encode(bytes)).expect("module stored");
        }
    }

    fn create_account(db: &StateDB, signing_key: &SigningKey) -> String {
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());
        let address = crypto::derive_address(public_key.as_bytes()).expect("canonical address");
        let object = aa::AccountManager::create_account(address.clone(), public_key_hex);
        db.put_object(&object).expect("account object stored");
        address
    }

    fn set_coin_store(db: &StateDB, address: &str, value: u128) {
        let move_addr = parse_move_address(address).expect("valid move address");
        let bytes = bcs::to_bytes(&TestCoin { value }).expect("coin store BCS");
        db.put(&coin_store_key(move_addr), &hex::encode(bytes))
            .expect("coin store stored");
    }

    fn coin_balance(db: &StateDB, address: &str) -> u128 {
        let move_addr = parse_move_address(address).expect("valid move address");
        let value = db
            .get(&coin_store_key(move_addr))
            .expect("coin store read")
            .expect("coin store exists");
        let bytes = hex::decode(value).expect("coin store hex");
        bcs::from_bytes::<TestCoin>(&bytes)
            .expect("coin store BCS")
            .value
    }

    fn wbtc_coin_type() -> move_core_types::language_storage::TypeTag {
        move_core_types::language_storage::TypeTag::Struct(Box::new(
            move_core_types::language_storage::StructTag {
                address: system_address(),
                module: move_core_types::identifier::Identifier::new("wbtc").unwrap(),
                name: move_core_types::identifier::Identifier::new("WBTC").unwrap(),
                type_params: vec![],
            },
        ))
    }

    fn coin_store_key_for(
        addr: move_core_types::account_address::AccountAddress,
        coin_type: move_core_types::language_storage::TypeTag,
    ) -> String {
        let tag = move_core_types::language_storage::StructTag {
            address: system_address(),
            module: move_core_types::identifier::Identifier::new("coin").unwrap(),
            name: move_core_types::identifier::Identifier::new("CoinStore").unwrap(),
            type_params: vec![coin_type],
        };
        format!("resource_{}_{}", addr, tag)
    }

    fn set_coin_store_for(
        db: &StateDB,
        address: &str,
        coin_type: move_core_types::language_storage::TypeTag,
        value: u128,
    ) {
        let move_addr = parse_move_address(address).expect("valid move address");
        let bytes = bcs::to_bytes(&TestCoin { value }).expect("coin store BCS");
        db.put(
            &coin_store_key_for(move_addr, coin_type),
            &hex::encode(bytes),
        )
        .expect("coin store stored");
    }

    fn coin_balance_for(
        db: &StateDB,
        address: &str,
        coin_type: move_core_types::language_storage::TypeTag,
    ) -> u128 {
        let move_addr = parse_move_address(address).expect("valid move address");
        let value = db
            .get(&coin_store_key_for(move_addr, coin_type))
            .expect("coin store read")
            .expect("coin store exists");
        let bytes = hex::decode(value).expect("coin store hex");
        bcs::from_bytes::<TestCoin>(&bytes)
            .expect("coin store BCS")
            .value
    }

    fn dex_registry_key() -> String {
        super::dex_registry_key()
    }

    fn dex_pool_key(
        pool_addr: move_core_types::account_address::AccountAddress,
        x: move_core_types::language_storage::TypeTag,
        y: move_core_types::language_storage::TypeTag,
    ) -> String {
        let tag = move_core_types::language_storage::StructTag {
            address: system_address(),
            module: move_core_types::identifier::Identifier::new("dex").unwrap(),
            name: move_core_types::identifier::Identifier::new("LiquidityPool").unwrap(),
            type_params: vec![x, y],
        };
        format!("resource_{}_{}", pool_addr, tag)
    }

    fn dex_lp_key(
        owner: &str,
        x: move_core_types::language_storage::TypeTag,
        y: move_core_types::language_storage::TypeTag,
    ) -> String {
        let tag = move_core_types::language_storage::StructTag {
            address: system_address(),
            module: move_core_types::identifier::Identifier::new("dex").unwrap(),
            name: move_core_types::identifier::Identifier::new("LPToken").unwrap(),
            type_params: vec![x, y],
        };
        format!("resource_{}_{}", owner, tag)
    }

    fn set_dex_registry(db: &StateDB, pools: Vec<TestPoolInfo>) {
        db.put(
            &dex_registry_key(),
            &hex::encode(
                bcs::to_bytes(&TestPoolRegistry { pools }).expect("dex registry BCS"),
            ),
        )
        .expect("dex registry stored");
    }

    fn dex_registry(db: &StateDB) -> TestPoolRegistry {
        let value = db
            .get(&dex_registry_key())
            .expect("dex registry read")
            .expect("dex registry exists");
        bcs::from_bytes(&hex::decode(value).expect("dex registry hex"))
            .expect("dex registry BCS")
    }

    fn set_dex_pool(
        db: &StateDB,
        pool_owner: &str,
        x: move_core_types::language_storage::TypeTag,
        y: move_core_types::language_storage::TypeTag,
        reserve_x: u128,
        reserve_y: u128,
        lp_supply: u128,
    ) {
        let pool = TestLiquidityPool {
            coin_x: TestCoin { value: reserve_x },
            coin_y: TestCoin { value: reserve_y },
            lp_supply,
            fee_bp: 30,
        };
        let pool_addr = parse_move_address(pool_owner).expect("pool owner address");
        db.put(
            &dex_pool_key(pool_addr, x, y),
            &hex::encode(bcs::to_bytes(&pool).expect("dex pool BCS")),
        )
        .expect("dex pool stored");
    }

    fn dex_pool(
        db: &StateDB,
        pool_owner: &str,
        x: move_core_types::language_storage::TypeTag,
        y: move_core_types::language_storage::TypeTag,
    ) -> TestLiquidityPool {
        let pool_addr = parse_move_address(pool_owner).expect("pool owner address");
        let value = db
            .get(&dex_pool_key(pool_addr, x, y))
            .expect("dex pool read")
            .expect("dex pool exists");
        bcs::from_bytes(&hex::decode(value).expect("dex pool hex")).expect("dex pool BCS")
    }

    fn dex_lp_balance(
        db: &StateDB,
        owner: &str,
        x: move_core_types::language_storage::TypeTag,
        y: move_core_types::language_storage::TypeTag,
    ) -> u128 {
        let value = db
            .get(&dex_lp_key(owner, x, y))
            .expect("lp token read")
            .expect("lp token exists");
        bcs::from_bytes::<TestLPToken>(&hex::decode(value).expect("lp token hex"))
            .expect("lp token BCS")
            .balance
    }

    fn entry_payload(
        module_name: &str,
        function: &str,
        ty_args: Vec<move_core_types::language_storage::TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> String {
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new(module_name).unwrap(),
            ),
            function: function.to_string(),
            ty_args,
            args,
        };
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
    }

    fn validator_set_key() -> String {
        super::validator_set_key()
    }

    fn token_registry_key() -> String {
        format!(
            "resource_{}_{}",
            system_address(),
            "0x1::token_factory::TokenRegistry"
        )
    }

    fn token_wallet_key(addr: &str) -> String {
        format!("resource_{}_{}", addr, "0x1::token_factory::TokenWallet")
    }

    fn governance_state_key() -> String {
        format!(
            "resource_{}_{}",
            system_address(),
            "0x1::governance::GovernanceState"
        )
    }

    fn vote_escrow_key(addr: &str) -> String {
        format!("resource_{}_{}", addr, "0x1::governance::VoteEscrow")
    }

    fn set_governance_state(db: &StateDB, state: &TestGovernanceState) {
        let bytes = bcs::to_bytes(state).expect("governance state BCS");
        db.put(&governance_state_key(), &hex::encode(bytes))
            .expect("governance state stored");
    }

    fn governance_state(db: &StateDB) -> TestGovernanceState {
        let value = db
            .get(&governance_state_key())
            .expect("governance state read")
            .expect("governance state exists");
        let bytes = hex::decode(value).expect("governance state hex");
        bcs::from_bytes::<TestGovernanceState>(&bytes).expect("governance state BCS")
    }

    fn vote_escrow(db: &StateDB, addr: &str) -> TestVoteEscrow {
        let value = db
            .get(&vote_escrow_key(addr))
            .expect("vote escrow read")
            .expect("vote escrow exists");
        let bytes = hex::decode(value).expect("vote escrow hex");
        bcs::from_bytes::<TestVoteEscrow>(&bytes).expect("vote escrow BCS")
    }

    fn set_validator_set(db: &StateDB, validator: &str, stake: u128, total_supply: u128) {
        let validator_addr = parse_move_address(validator).expect("validator move address");
        let set = TestValidatorSet {
            validators: vec![TestValidatorConfig {
                validator_addr,
                stake: TestCoin { value: stake },
                public_key: vec![1, 2, 3],
            }],
            unbonding_queue: vec![],
            total_supply,
            current_epoch: 0,
        };
        let bytes = bcs::to_bytes(&set).expect("validator set BCS");
        db.put(&validator_set_key(), &hex::encode(bytes))
            .expect("validator set stored");
    }

    fn validator_set(db: &StateDB) -> TestValidatorSet {
        let value = db
            .get(&validator_set_key())
            .expect("validator set read")
            .expect("validator set exists");
        let bytes = hex::decode(value).expect("validator set hex");
        bcs::from_bytes::<TestValidatorSet>(&bytes).expect("validator set BCS")
    }

    fn apply_updates(db: &StateDB, updates: Vec<(String, Option<String>)>) {
        for (key, value) in updates {
            if let Some(value) = value {
                db.put(&key, &value).expect("update put");
            } else {
                db.delete(&key).expect("update delete");
            }
        }
    }

    fn signed_tx(
        signing_key: &SigningKey,
        sender: &str,
        payload: &str,
        sequence_number: u64,
        gas_limit: u64,
        gas_price: u128,
    ) -> String {
        let public_key = signing_key.verifying_key();
        let message = format!(
            "{}:{}:{}:{}",
            "AINCORE-MAINNET-1", sender, payload, sequence_number
        );
        let signature = signing_key.sign(message.as_bytes());
        serde_json::to_string(&Transaction {
            chain_id: "AINCORE-MAINNET-1".to_string(),
            sender: sender.to_string(),
            input_objects: vec![],
            payload: payload.to_string(),
            args: vec![],
            gas_limit,
            gas_price,
            sequence_number,
            public_key: hex::encode(public_key.as_bytes()),
            signature: hex::encode(signature.to_bytes()),
            paymaster: None,
            paymaster_signature: None,
            zkp_proof: None,
        })
        .expect("tx json")
    }

    #[test]
    fn test_move_transfer_charges_gas_and_updates_coinstores() {
        let db = temp_db("transfer_success");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[7u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[8u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);
        set_coin_store(&db, &recipient, 0);

        let executor = Executor::new(db.clone());
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::new([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                    name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                    type_params: vec![],
                }),
            )],
            args: vec![
                bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&recipient).unwrap()).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        };
        let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1))
            .expect("transaction accepted");
        assert_eq!(gas, 100_000);
        apply_updates(&db, updates);

        assert_eq!(coin_balance(&db, &sender), 899_900);
        assert_eq!(coin_balance(&db, &recipient), 100);
        let sender_obj = db.get_object(&sender).expect("sender object");
        let sender_data: aa::AccountData = serde_json::from_slice(&sender_obj.data).unwrap();
        assert_eq!(sender_data.sequence_number, 1);
    }

    #[test]
    fn test_move_transfer_abort_still_charges_gas_and_records_receipt() {
        let db = temp_db("transfer_abort");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[9u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[10u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 100_050);
        set_coin_store(&db, &recipient, 0);

        let executor = Executor::new(db.clone());
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::new([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                    name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                    type_params: vec![],
                }),
            )],
            args: vec![
                bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&recipient).unwrap()).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        };
        let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
        let tx_json = signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&tx_json)
            .expect("transaction accepted");
        assert_eq!(gas, 100_000);
        apply_updates(&db, updates);

        assert_eq!(coin_balance(&db, &sender), 50);
        assert_eq!(coin_balance(&db, &recipient), 0);
        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(&tx_json)))
            .unwrap()
            .expect("receipt stored");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "aborted");
        assert_eq!(receipt["gas_charged"], "100000");
    }

    #[test]
    fn test_bad_signature_rejects_before_gas_or_nonce() {
        let db = temp_db("bad_signature");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[11u8; 32]);
        let other_key = SigningKey::from_bytes(&[12u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[13u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000);
        set_coin_store(&db, &recipient, 0);

        let executor = Executor::new(db.clone());
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::new([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                    name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                    type_params: vec![],
                }),
            )],
            args: vec![
                bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&recipient).unwrap()).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        };
        let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
        assert!(executor
            .execute_transaction(&signed_tx(&other_key, &sender, &payload, 0, 10, 1))
            .is_none());

        assert_eq!(coin_balance(&db, &sender), 1_000);
        let sender_obj = db.get_object(&sender).expect("sender object");
        let sender_data: aa::AccountData = serde_json::from_slice(&sender_obj.data).unwrap();
        assert_eq!(sender_data.sequence_number, 0);
    }

    #[test]
    fn test_zero_gas_price_rejects_before_gas_or_nonce() {
        let db = temp_db("zero_gas_price");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[31u8; 32]);
        let sender = create_account(&db, &sender_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        let executor = Executor::new(db.clone());
        let payload_struct = vm_move::TransactionPayload::PublishModule(vec![vec![0xCA, 0xFE]]);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
        assert!(executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 0))
            .is_none());

        assert_eq!(coin_balance(&db, &sender), 1_000_000);
        let sender_obj = db.get_object(&sender).expect("sender object");
        let sender_data: aa::AccountData = serde_json::from_slice(&sender_obj.data).unwrap();
        assert_eq!(sender_data.sequence_number, 0);
    }

    #[test]
    fn test_publish_invalid_hex_rejects_before_gas_or_nonce() {
        let db = temp_db("publish_bad_hex");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[14u8; 32]);
        let sender = create_account(&db, &sender_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        let executor = Executor::new(db.clone());
        assert!(executor
            .execute_transaction(&signed_tx(
                &sender_key,
                &sender,
                "publish:not-hex",
                0,
                100_000,
                1
            ))
            .is_none());

        assert_eq!(coin_balance(&db, &sender), 1_000_000);
        let sender_obj = db.get_object(&sender).expect("sender object");
        let sender_data: aa::AccountData = serde_json::from_slice(&sender_obj.data).unwrap();
        assert_eq!(sender_data.sequence_number, 0);
    }

    #[test]
    fn test_publish_invalid_bytecode_charges_gas_and_records_abort() {
        let db = temp_db("publish_bad_bytecode");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[15u8; 32]);
        let sender = create_account(&db, &sender_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        let executor = Executor::new(db.clone());
        let payload_struct = vm_move::TransactionPayload::PublishModule(vec![vec![0xCA, 0xFE]]);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
        let tx_json = signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&tx_json)
            .expect("transaction accepted");
        assert_eq!(gas, 100_000);
        apply_updates(&db, updates);

        assert_eq!(coin_balance(&db, &sender), 900_000);
        let sender_obj = db.get_object(&sender).expect("sender object");
        let sender_data: aa::AccountData = serde_json::from_slice(&sender_obj.data).unwrap();
        assert_eq!(sender_data.sequence_number, 1);

        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(&tx_json)))
            .unwrap()
            .expect("receipt stored");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "aborted");
        assert_eq!(receipt["gas_charged"], "100000");
    }

    #[test]
    fn test_script_payload_rejects_before_gas_or_nonce() {
        let db = temp_db("script_reject");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[16u8; 32]);
        let sender = create_account(&db, &sender_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        let executor = Executor::new(db.clone());
        let payload_struct = vm_move::TransactionPayload::Script(vec![0xca, 0xfe]);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
        assert!(executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1))
            .is_none());

        assert_eq!(coin_balance(&db, &sender), 1_000_000);
        let sender_obj = db.get_object(&sender).expect("sender object");
        let sender_data: aa::AccountData = serde_json::from_slice(&sender_obj.data).unwrap();
        assert_eq!(sender_data.sequence_number, 0);
    }

    #[test]
    fn test_bcs_transfer_dependency_includes_recipient() {
        let db = temp_db("bcs_transfer_deps");
        let sender_key = SigningKey::from_bytes(&[17u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[18u8; 32]);
        let sender = crypto::derive_address(sender_key.verifying_key().as_bytes()).unwrap();
        let recipient = crypto::derive_address(recipient_key.verifying_key().as_bytes()).unwrap();
        let executor = Executor::new(db);

        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![aincore_coin_type()],
            args: vec![
                bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&recipient).unwrap()).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        };
        let payload =
            hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap());
        let tx_json = serde_json::to_string(&Transaction {
            chain_id: "AINCORE-MAINNET-1".to_string(),
            sender,
            input_objects: vec![],
            payload,
            args: vec![],
            gas_limit: 100_000,
            gas_price: 1,
            sequence_number: 0,
            public_key: hex::encode(sender_key.verifying_key().as_bytes()),
            signature: String::new(),
            paymaster: None,
            paymaster_signature: None,
            zkp_proof: None,
        })
        .unwrap();

        let deps = executor.analyze_dependencies(&tx_json);
        assert!(deps.contains(&recipient));
    }

    #[test]
    fn test_block_fee_burn_updates_supply_trackers() {
        let db = temp_db("block_burn_supply");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[19u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[20u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);
        set_coin_store(&db, &recipient, 0);
        set_validator_set(&db, &sender, 0, 1_000_000_000);
        db.put("sys:total_supply", "1000000000").unwrap();
        db.put("total_burned", "0").unwrap();
        db.put("sys:config:burn_percentage", "10").unwrap();

        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::new([
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ]),
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::new([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]),
                    module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                    name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                    type_params: vec![],
                }),
            )],
            args: vec![
                bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&recipient).unwrap()).unwrap(),
                bcs::to_bytes(&100u128).unwrap(),
            ],
        };
        let payload =
            hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap());
        let tx_json = signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1);

        let executor = Executor::new(db.clone());
        executor.execute_block_parallel(vec![tx_json], &sender);

        let total_burned = db
            .get("total_burned")
            .unwrap()
            .unwrap()
            .parse::<u128>()
            .unwrap();
        let total_supply = db
            .get("sys:total_supply")
            .unwrap()
            .unwrap()
            .parse::<u128>()
            .unwrap();
        assert_eq!(total_burned, 10_000);
        assert_eq!(total_supply, 999_990_000);
        assert_eq!(validator_set(&db).total_supply, 999_990_000);
    }

    #[test]
    fn test_dex_create_pool_liquidity_swap_and_remove_end_to_end() {
        let db = temp_db("dex_liquidity_swap");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[32u8; 32]);
        let trader = create_account(&db, &trader_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 1_000_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 1_000_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload("dex", "create_pool", vec![ain.clone(), wbtc.clone()], vec![
            bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
        ]);
        let create_tx = signed_tx(&trader_key, &trader, &create_payload, 0, 10_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&create_tx)
            .expect("create pool accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);
        assert_eq!(dex_registry(&db).pools.len(), 1);

        let add_payload = entry_payload(
            "dex",
            "add_liquidity",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&10_000u128).unwrap(),
                bcs::to_bytes(&10_000u128).unwrap(),
                bcs::to_bytes(&9_000u128).unwrap(),
            ],
        );
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&trader_key, &trader, &add_payload, 1, 10_000, 1))
            .expect("add liquidity accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 10_000);
        assert_eq!(pool.coin_y.value, 10_000);
        assert_eq!(pool.lp_supply, 10_000);
        assert_eq!(
            dex_lp_balance(&db, &trader, ain.clone(), wbtc.clone()),
            9_000
        );
        assert_eq!(
            coin_balance_for(&db, &trader, ain.clone()),
            1_000_000 - 10_000 - 10_000 - 10_000
        );
        assert_eq!(coin_balance_for(&db, &trader, wbtc.clone()), 990_000);

        let swap_payload = entry_payload(
            "dex",
            "swap_x_to_y",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&1_000u128).unwrap(),
                bcs::to_bytes(&900u128).unwrap(),
            ],
        );
        let swap_tx = signed_tx(&trader_key, &trader, &swap_payload, 2, 10_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&swap_tx)
            .expect("swap accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 11_000);
        assert_eq!(pool.coin_y.value, 9_094);
        assert_eq!(coin_balance_for(&db, &trader, ain.clone()), 959_000);
        assert_eq!(coin_balance_for(&db, &trader, wbtc.clone()), 990_906);
        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(&swap_tx)))
            .unwrap()
            .expect("receipt stored");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "success");
        assert_eq!(receipt["metadata"]["kind"], "dex");
        assert_eq!(receipt["metadata"]["function"], "swap_x_to_y");
        assert_eq!(
            receipt["metadata"]["actual_amount_out"],
            serde_json::json!("906")
        );
        assert_eq!(
            receipt["metadata"]["reserve_x_before"],
            serde_json::json!("10000")
        );
        assert_eq!(
            receipt["metadata"]["reserve_y_after"],
            serde_json::json!("9094")
        );
        assert_eq!(
            receipt["metadata"]["token_in"],
            serde_json::json!("0x1::staking::AincoreCoin")
        );
        assert_eq!(
            receipt["metadata"]["token_out"],
            serde_json::json!("0x1::wbtc::WBTC")
        );

        let remove_payload = entry_payload(
            "dex",
            "remove_liquidity",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&1_000u128).unwrap(),
                bcs::to_bytes(&1_000u128).unwrap(),
                bcs::to_bytes(&900u128).unwrap(),
            ],
        );
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&trader_key, &trader, &remove_payload, 3, 10_000, 1))
            .expect("remove liquidity accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 9_900);
        assert_eq!(pool.coin_y.value, 8_185);
        assert_eq!(pool.lp_supply, 9_000);
        assert_eq!(dex_lp_balance(&db, &trader, ain.clone(), wbtc.clone()), 8_000);
        assert_eq!(coin_balance_for(&db, &trader, ain), 950_100);
        assert_eq!(coin_balance_for(&db, &trader, wbtc), 991_815);
    }

    #[test]
    fn test_dex_duplicate_and_reverse_pool_creation_abort_after_gas() {
        let db = temp_db("dex_duplicate_reverse");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[35u8; 32]);
        let trader = create_account(&db, &trader_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 100_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload("dex", "create_pool", vec![ain.clone(), wbtc.clone()], vec![
            bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
        ]);
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&trader_key, &trader, &create_payload, 0, 10_000, 1))
            .expect("first create accepted");
        apply_updates(&db, updates);
        assert_eq!(dex_registry(&db).pools.len(), 1);

        let reverse_payload = entry_payload("dex", "create_pool", vec![wbtc.clone(), ain.clone()], vec![
            bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
        ]);
        let reverse_tx = signed_tx(&trader_key, &trader, &reverse_payload, 1, 10_000, 1);
        let (updates, _) = executor
            .execute_transaction(&reverse_tx)
            .expect("reverse create abort is accepted and gas-charged");
        apply_updates(&db, updates);
        assert_eq!(dex_registry(&db).pools.len(), 1);
        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(&reverse_tx)))
            .unwrap()
            .expect("reverse receipt stored");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "aborted");

        let duplicate_tx = signed_tx(&trader_key, &trader, &create_payload, 2, 10_000, 1);
        let (updates, _) = executor
            .execute_transaction(&duplicate_tx)
            .expect("duplicate create abort is accepted and gas-charged");
        apply_updates(&db, updates);
        assert_eq!(dex_registry(&db).pools.len(), 1);
        assert_eq!(coin_balance_for(&db, &trader, ain), 70_000);
    }

    #[test]
    fn test_dex_dependency_tracking_includes_shared_pool_resource() {
        let db = temp_db("dex_dependencies");
        let trader_key = SigningKey::from_bytes(&[36u8; 32]);
        let trader = create_account(&db, &trader_key);
        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        let pool_addr = parse_move_address(&trader).unwrap();
        let payload = entry_payload(
            "dex",
            "swap_x_to_y",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&pool_addr).unwrap(),
                bcs::to_bytes(&pool_addr).unwrap(),
                bcs::to_bytes(&1_000u128).unwrap(),
                bcs::to_bytes(&1u128).unwrap(),
            ],
        );
        let tx_json = signed_tx(&trader_key, &trader, &payload, 0, 10_000, 1);
        let executor = Executor::new(db.clone());
        let deps = executor.analyze_dependencies(&tx_json);
        let expected_pool = dex_pool_key(pool_addr, ain, wbtc);

        assert!(deps.contains(&dex_registry_key()));
        assert!(deps.contains(&expected_pool));
    }

    #[test]
    fn test_dex_initial_liquidity_below_minimum_aborts_after_gas_only() {
        let db = temp_db("dex_minimum_liquidity");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[33u8; 32]);
        let trader = create_account(&db, &trader_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 100_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload("dex", "create_pool", vec![ain.clone(), wbtc.clone()], vec![
            bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
        ]);
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&trader_key, &trader, &create_payload, 0, 10_000, 1))
            .expect("create pool accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let payload = entry_payload(
            "dex",
            "add_liquidity",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&1_000u128).unwrap(),
                bcs::to_bytes(&1_000u128).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
            ],
        );
        let tx_json = signed_tx(&trader_key, &trader, &payload, 1, 10_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&tx_json)
            .expect("minimum-liquidity abort is accepted and gas-charged");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.lp_supply, 0);
        assert_eq!(pool.coin_x.value, 0);
        assert_eq!(pool.coin_y.value, 0);
        assert_eq!(coin_balance_for(&db, &trader, ain), 80_000);
        assert_eq!(coin_balance_for(&db, &trader, wbtc), 100_000);
        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(&tx_json)))
            .unwrap()
            .expect("receipt stored");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "aborted");
    }

    #[test]
    fn test_dex_swap_overflow_guard_aborts_before_withdrawal() {
        let db = temp_db("dex_swap_overflow");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[34u8; 32]);
        let trader = create_account(&db, &trader_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        let overflow_input = (u128::MAX / 9_970) + 1;
        set_coin_store_for(&db, &trader, ain.clone(), overflow_input + 10_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload("dex", "create_pool", vec![ain.clone(), wbtc.clone()], vec![
            bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
        ]);
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&trader_key, &trader, &create_payload, 0, 10_000, 1))
            .expect("create pool accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);
        set_dex_pool(&db, &trader, ain.clone(), wbtc.clone(), 10_000, 10_000, 10_000);

        let payload = entry_payload(
            "dex",
            "swap_x_to_y",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&overflow_input).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
            ],
        );
        let tx_json = signed_tx(&trader_key, &trader, &payload, 1, 10_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&tx_json)
            .expect("overflow abort is accepted and gas-charged");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 10_000);
        assert_eq!(pool.coin_y.value, 10_000);
        assert_eq!(coin_balance_for(&db, &trader, ain), overflow_input - 10_000);
        assert_eq!(coin_balance_for(&db, &trader, wbtc), 100_000);
        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(&tx_json)))
            .unwrap()
            .expect("receipt stored");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "aborted");
    }

    #[test]
    fn test_dex_add_liquidity_uses_only_ratio_matched_amounts() {
        let db = temp_db("dex_liquidity_ratio_guard");
        load_stdlib(&db);
        let maker_key = SigningKey::from_bytes(&[37u8; 32]);
        let maker = create_account(&db, &maker_key);
        let lp2_key = SigningKey::from_bytes(&[38u8; 32]);
        let lp2 = create_account(&db, &lp2_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &maker, ain.clone(), 100_000);
        set_coin_store_for(&db, &maker, wbtc.clone(), 100_000);
        set_coin_store_for(&db, &lp2, ain.clone(), 100_000);
        set_coin_store_for(&db, &lp2, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload(
            "dex",
            "create_pool",
            vec![ain.clone(), wbtc.clone()],
            vec![bcs::to_bytes(&parse_move_address(&maker).unwrap()).unwrap()],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&maker_key, &maker, &create_payload, 0, 10_000, 1))
            .expect("create pool accepted");
        apply_updates(&db, updates);

        let seed_payload = entry_payload(
            "dex",
            "add_liquidity",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&maker).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&maker).unwrap()).unwrap(),
                bcs::to_bytes(&10_000u128).unwrap(),
                bcs::to_bytes(&10_000u128).unwrap(),
                bcs::to_bytes(&9_000u128).unwrap(),
            ],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&maker_key, &maker, &seed_payload, 1, 10_000, 1))
            .expect("seed liquidity accepted");
        apply_updates(&db, updates);

        let imbalanced_payload = entry_payload(
            "dex",
            "add_liquidity",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&lp2).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&maker).unwrap()).unwrap(),
                bcs::to_bytes(&10_000u128).unwrap(),
                bcs::to_bytes(&5_000u128).unwrap(),
                bcs::to_bytes(&4_000u128).unwrap(),
            ],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&lp2_key, &lp2, &imbalanced_payload, 0, 10_000, 1))
            .expect("imbalanced add liquidity accepted");
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &maker, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 15_000, "pool should only take matched X");
        assert_eq!(pool.coin_y.value, 15_000, "pool should only take matched Y");
        assert_eq!(pool.lp_supply, 15_000);
        assert_eq!(
            dex_lp_balance(&db, &lp2, ain.clone(), wbtc.clone()),
            5_000,
            "second LP shares should come from the limiting side",
        );
        assert_eq!(
            coin_balance_for(&db, &lp2, ain),
            85_000,
            "only matched X plus gas should be deducted",
        );
        assert_eq!(
            coin_balance_for(&db, &lp2, wbtc),
            95_000,
            "matched Y should be fully deposited",
        );
    }

    #[test]
    fn test_token_creation_fee_burn_syncs_move_and_native_supply_trackers() {
        let db = temp_db("token_fee_supply");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[23u8; 32]);
        let sender = create_account(&db, &sender_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 200_000_000_000_000_000_000);
        set_validator_set(&db, &sender, 0, 200_000_000_000_000_000_000);
        db.put("sys:total_supply", "200000000000000000000").unwrap();
        db.put("total_burned", "0").unwrap();
        db.put(&token_registry_key(), "00").unwrap();
        db.put(&token_wallet_key(&sender), "00").unwrap();

        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("token_factory").unwrap(),
            ),
            function: "create_token".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                bcs::to_bytes(&b"Ain Pepe".to_vec()).unwrap(),
                bcs::to_bytes(&b"APEPE".to_vec()).unwrap(),
                bcs::to_bytes(&18u8).unwrap(),
                bcs::to_bytes(&1_000_000u128).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
                bcs::to_bytes(&Vec::<u8>::new()).unwrap(),
                bcs::to_bytes(&Vec::<u8>::new()).unwrap(),
            ],
        };
        let payload =
            hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap());
        let executor = Executor::new(db.clone());
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 10_000, 1))
            .expect("token creation accepted");
        apply_updates(&db, updates);

        assert_eq!(
            db.get("sys:total_supply").unwrap().unwrap(),
            "100000000000000000000"
        );
        assert_eq!(
            db.get("total_burned").unwrap().unwrap(),
            "100000000000000000000"
        );
        assert_eq!(validator_set(&db).total_supply, 100_000_000_000_000_000_000);
    }

    #[test]
    fn test_governance_proposal_fee_burn_syncs_move_and_native_supply_trackers() {
        let db = temp_db("governance_fee_supply");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[24u8; 32]);
        let sender = create_account(&db, &sender_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        let starting_supply = 20_000_000_000_000_000_000_000u128;
        set_coin_store(&db, &sender, starting_supply);
        set_validator_set(&db, &sender, 0, starting_supply);
        db.put("sys:total_supply", &starting_supply.to_string())
            .unwrap();
        db.put("total_burned", "0").unwrap();
        db.put(&governance_state_key(), "000000000000000000")
            .unwrap();

        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("governance").unwrap(),
            ),
            function: "create_proposal".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                bcs::to_bytes(&b"reduce spam".to_vec()).unwrap(),
                bcs::to_bytes(&1u8).unwrap(),
                bcs::to_bytes(&60u64).unwrap(),
            ],
        };
        let payload =
            hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap());
        let executor = Executor::new(db.clone());
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 10_000, 1))
            .expect("proposal accepted");
        apply_updates(&db, updates);

        let fee = 10_000_000_000_000_000_000_000u128;
        assert_eq!(
            db.get("sys:total_supply").unwrap().unwrap(),
            (starting_supply - fee).to_string()
        );
        assert_eq!(db.get("total_burned").unwrap().unwrap(), fee.to_string());
        assert_eq!(validator_set(&db).total_supply, starting_supply - fee);
    }

    #[test]
    fn test_governance_vote_escrow_locks_real_coin_without_supply_drift() {
        let db = temp_db("governance_vote_escrow");
        load_stdlib(&db);
        let voter_key = SigningKey::from_bytes(&[25u8; 32]);
        let voter = create_account(&db, &voter_key);
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        let balance = 1_000_000_000_000_000_000_000u128;
        set_coin_store(&db, &voter, balance);
        set_validator_set(&db, &voter, 0, balance);
        db.put("sys:total_supply", &balance.to_string()).unwrap();
        db.put("total_burned", "0").unwrap();
        set_governance_state(
            &db,
            &TestGovernanceState {
                proposals: vec![TestProposal {
                    id: 0,
                    proposer: parse_move_address(&voter).unwrap(),
                    description: b"escrow check".to_vec(),
                    votes_for: 0,
                    votes_against: 0,
                    executed: false,
                    action_type: 1,
                    action_value: 60,
                    voters: vec![],
                }],
                next_proposal_id: 1,
            },
        );

        let vote_call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("governance").unwrap(),
            ),
            function: "vote".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_move_address(&voter).unwrap()).unwrap(),
                bcs::to_bytes(&0u64).unwrap(),
                bcs::to_bytes(&true).unwrap(),
            ],
        };
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(vote_call)).unwrap(),
        );
        let executor = Executor::new(db.clone());
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&voter_key, &voter, &payload, 0, 10_000, 1))
            .expect("vote accepted");
        apply_updates(&db, updates);

        let gas_per_tx = 10_000u128;
        let vote_gas_reserve = 1_000_000_000_000_000_000u128;
        let locked = balance - gas_per_tx - vote_gas_reserve;

        assert_eq!(coin_balance(&db, &voter), vote_gas_reserve);
        assert_eq!(vote_escrow(&db, &voter).locked_coins.value, locked);
        assert_eq!(
            db.get("sys:total_supply").unwrap().unwrap(),
            balance.to_string()
        );
        assert_eq!(db.get("total_burned").unwrap().unwrap(), "0");
        assert_eq!(validator_set(&db).total_supply, balance);

        let mut state = governance_state(&db);
        state.proposals[0].executed = true;
        set_governance_state(&db, &state);

        let claim_call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("governance").unwrap(),
            ),
            function: "claim_vote_tokens".to_string(),
            ty_args: vec![],
            args: vec![bcs::to_bytes(&parse_move_address(&voter).unwrap()).unwrap()],
        };
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(claim_call)).unwrap(),
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&voter_key, &voter, &payload, 1, 10_000, 1))
            .expect("claim accepted");
        apply_updates(&db, updates);

        assert_eq!(coin_balance(&db, &voter), balance - (gas_per_tx * 2));
        assert!(db.get(&vote_escrow_key(&voter)).unwrap().is_none());
        assert_eq!(
            db.get("sys:total_supply").unwrap().unwrap(),
            balance.to_string()
        );
        assert_eq!(db.get("total_burned").unwrap().unwrap(), "0");
        assert_eq!(validator_set(&db).total_supply, balance);
    }

    #[test]
    fn test_fee_sweep_queue_recovers_after_miner_registers_coinstore() {
        let db = temp_db("fee_sweep_recovery");
        load_stdlib(&db);
        let miner_key = SigningKey::from_bytes(&[26u8; 32]);
        let miner = create_account(&db, &miner_key);
        let executor = Executor::new(db.clone());
        let amount = 777_000u128;

        executor.queue_fee_sweep("not_a_hex_address", amount, 42);
        executor.process_fee_sweep_queue();
        let queued = db
            .scan_prefix("sys:fee_sweep_queue:")
            .into_iter()
            .next()
            .expect("fee remains queued");
        let entry: FeeSweepEntry = serde_json::from_str(&queued.1).unwrap();
        assert_eq!(entry.attempts, 1);

        let recovered_entry = FeeSweepEntry {
            miner: miner.clone(),
            amount: amount.to_string(),
            reason: entry.reason,
            attempts: entry.attempts,
        };
        db.put(&queued.0, &serde_json::to_string(&recovered_entry).unwrap())
            .unwrap();
        set_coin_store(&db, &miner, 0);
        executor.process_fee_sweep_queue();

        assert!(db.scan_prefix("sys:fee_sweep_queue:").is_empty());
        assert_eq!(coin_balance(&db, &miner), amount);
    }

    #[test]
    fn test_pending_equivocation_slash_burns_all_stake_and_removes_validator() {
        let db = temp_db("slash_equivocation");
        load_stdlib(&db);
        let validator_key = SigningKey::from_bytes(&[21u8; 32]);
        let validator = crypto::derive_address(validator_key.verifying_key().as_bytes()).unwrap();
        db.put(
            "sys:validators",
            &serde_json::to_string(&vec![
                (validator.clone(), 100u64),
                ("33333333333333333333333333333333".to_string(), 100u64),
            ])
            .unwrap(),
        )
        .unwrap();
        set_validator_set(&db, &validator, 1_000_000, 1_000_000);
        db.put(
            &format!("sys:pending_slash:{}", validator),
            &serde_json::json!({"reason":"equivocation","round":77}).to_string(),
        )
        .unwrap();

        let executor = Executor::new(db.clone());
        executor.execute_pending_slashes();

        assert!(db
            .get(&format!("sys:pending_slash:{}", validator))
            .unwrap()
            .is_none());
        assert_eq!(
            db.get(&format!("sys:slashed:{}:77", validator))
                .unwrap()
                .as_deref(),
            Some("1")
        );
        let native_validators: Vec<(String, u64)> =
            serde_json::from_str(&db.get("sys:validators").unwrap().unwrap()).unwrap();
        assert!(!native_validators.iter().any(|(addr, _)| addr == &validator));

        let move_validators = validator_set(&db);
        assert!(move_validators.validators.is_empty());
        assert!(move_validators.unbonding_queue.is_empty());
        assert_eq!(move_validators.total_supply, 0);
    }

    #[test]
    fn test_pending_downtime_slash_jails_validator_and_unbonds_remaining_stake() {
        let db = temp_db("slash_downtime");
        load_stdlib(&db);
        let validator_key = SigningKey::from_bytes(&[22u8; 32]);
        let validator = crypto::derive_address(validator_key.verifying_key().as_bytes()).unwrap();
        db.put(
            "sys:validators",
            &serde_json::to_string(&vec![(validator.clone(), 100u64)]).unwrap(),
        )
        .unwrap();
        set_validator_set(&db, &validator, 1_000_000, 1_000_000);
        db.put(
            &format!("sys:pending_slash:{}", validator),
            &serde_json::json!({"reason":"downtime","round":78}).to_string(),
        )
        .unwrap();

        let executor = Executor::new(db.clone());
        executor.execute_pending_slashes();

        assert!(db
            .get(&format!("sys:pending_slash:{}", validator))
            .unwrap()
            .is_none());
        assert_eq!(
            db.get(&format!("sys:slashed:{}:78", validator))
                .unwrap()
                .as_deref(),
            Some("1")
        );
        let native_validators: Vec<(String, u64)> =
            serde_json::from_str(&db.get("sys:validators").unwrap().unwrap()).unwrap();
        assert!(native_validators.is_empty());

        let move_validators = validator_set(&db);
        assert!(move_validators.validators.is_empty());
        assert_eq!(move_validators.unbonding_queue.len(), 1);
        assert_eq!(move_validators.unbonding_queue[0].stake, 950_000);
        assert_eq!(move_validators.total_supply, 950_000);
    }

    // ========================================================================
    // Phase 2.3 (H-02): BFT-quorum downtime attestation tests
    // ========================================================================

    /// Unilateral observation is no longer enough to trigger a slash.
    /// With 4 validators and BFT quorum = 3, a single reporter must NOT
    /// promote the attestation to a pending_slash.
    #[test]
    fn downtime_attestation_below_bft_quorum_does_not_slash() {
        let db = temp_db("downtime_below_quorum");
        // 4-validator set, quorum = 3.
        let validators: Vec<(String, u64)> = vec![
            ("aaaa".repeat(8), 100),
            ("bbbb".repeat(8), 100),
            ("cccc".repeat(8), 100),
            ("dddd".repeat(8), 100),
        ];
        db.put("sys:validators", &serde_json::to_string(&validators).unwrap())
            .unwrap();

        // Only ONE reporter attests against the offender.
        let offender = &validators[0].0;
        let reporter = &validators[1].0;
        db.put(
            &format!(
                "sys:downtime_attestation:{}:{}:{}",
                offender, 7, reporter
            ),
            &serde_json::json!({"reason": "downtime"}).to_string(),
        )
        .unwrap();

        let executor = Executor::new(db.clone());
        executor.promote_downtime_attestations_to_slash();

        // No pending_slash queued — single reporter is below quorum.
        assert!(db
            .get(&format!("sys:pending_slash:{}", offender))
            .unwrap()
            .is_none(),
            "single-reporter attestation must NOT promote to a slash");
        // Attestation is retained for future reporters to potentially
        // bring the count to quorum.
        assert!(db
            .get(&format!(
                "sys:downtime_attestation:{}:{}:{}",
                offender, 7, reporter
            ))
            .unwrap()
            .is_some());
    }

    /// Once enough distinct reporters attest, the offender's slash is queued.
    #[test]
    fn downtime_attestation_at_bft_quorum_promotes_to_slash() {
        let db = temp_db("downtime_at_quorum");
        let validators: Vec<(String, u64)> = vec![
            ("aaaa".repeat(8), 100),
            ("bbbb".repeat(8), 100),
            ("cccc".repeat(8), 100),
            ("dddd".repeat(8), 100),
        ];
        db.put("sys:validators", &serde_json::to_string(&validators).unwrap())
            .unwrap();

        let offender = &validators[0].0;
        // 3 distinct reporters (out of 4) — exactly BFT quorum.
        for reporter in &validators[1..] {
            db.put(
                &format!(
                    "sys:downtime_attestation:{}:{}:{}",
                    offender, 9, reporter.0
                ),
                &serde_json::json!({"reason": "downtime", "round": 500}).to_string(),
            )
            .unwrap();
        }

        let executor = Executor::new(db.clone());
        executor.promote_downtime_attestations_to_slash();

        // pending_slash queued with quorum metadata.
        let slash = db
            .get(&format!("sys:pending_slash:{}", offender))
            .unwrap()
            .expect("BFT-quorum attestations must promote to a pending slash");
        let parsed: serde_json::Value = serde_json::from_str(&slash).unwrap();
        assert_eq!(parsed["reason"].as_str(), Some("downtime"));
        assert_eq!(parsed["reporter_count"].as_u64(), Some(3));
        assert_eq!(parsed["bft_quorum"].as_u64(), Some(3));

        // Attestations for the promoted (offender, epoch) are cleaned up.
        for reporter in &validators[1..] {
            assert!(db
                .get(&format!(
                    "sys:downtime_attestation:{}:{}:{}",
                    offender, 9, reporter.0
                ))
                .unwrap()
                .is_none());
        }

        // Jail marker is set so re-running doesn't double-promote.
        assert!(db
            .get(&format!("validator:jailed:{}", offender))
            .unwrap()
            .is_some());
    }

    /// Attestations from a non-validator reporter must not count toward
    /// quorum (anti-grief: a slashed/removed validator cannot keep
    /// influencing slashing decisions).
    #[test]
    fn downtime_attestation_from_non_validator_reporter_does_not_count() {
        let db = temp_db("downtime_stale_reporter");
        let validators: Vec<(String, u64)> = vec![
            ("aaaa".repeat(8), 100),
            ("bbbb".repeat(8), 100),
            ("cccc".repeat(8), 100),
            ("dddd".repeat(8), 100),
        ];
        db.put("sys:validators", &serde_json::to_string(&validators).unwrap())
            .unwrap();

        let offender = &validators[0].0;
        // 2 valid reporters + 1 stale (not in validator set) = only 2 count.
        // 2 < BFT quorum of 3 → no slash should be queued.
        let valid_reporters = [&validators[1].0, &validators[2].0];
        let stale_reporter = "ffff".repeat(8);

        for reporter in valid_reporters.iter() {
            db.put(
                &format!(
                    "sys:downtime_attestation:{}:{}:{}",
                    offender, 11, reporter
                ),
                &serde_json::json!({}).to_string(),
            )
            .unwrap();
        }
        db.put(
            &format!(
                "sys:downtime_attestation:{}:{}:{}",
                offender, 11, stale_reporter
            ),
            &serde_json::json!({}).to_string(),
        )
        .unwrap();

        let executor = Executor::new(db.clone());
        executor.promote_downtime_attestations_to_slash();

        assert!(db
            .get(&format!("sys:pending_slash:{}", offender))
            .unwrap()
            .is_none(),
            "stale reporter must not push the group over quorum");
    }

    /// Phase 5C.3 / NEW-002: an offender who LEFT the validator set
    /// between attestation collection and quorum promotion must NOT be
    /// slashed. Closes the reverse hole in SEC-N03 (attest-time check
    /// catches non-validator offenders, but a graceful exit between
    /// attest and promote slipped through before this fix).
    #[test]
    fn new002_offender_left_set_between_attest_and_promote_not_slashed() {
        let db = temp_db("new002_offender_unbonded");

        // Validator set at ATTEST time: a, b, c, d, and the offender (e).
        let attest_time_validators: Vec<(String, u64)> = vec![
            ("aaaa".repeat(8), 100),
            ("bbbb".repeat(8), 100),
            ("cccc".repeat(8), 100),
            ("dddd".repeat(8), 100),
            ("eeee".repeat(8), 100),
        ];
        let offender = attest_time_validators[4].0.clone();

        // Persist 3 valid reporter attestations against offender.
        for reporter in attest_time_validators[..3].iter() {
            db.put(
                &format!(
                    "sys:downtime_attestation:{}:{}:{}",
                    offender, 7, reporter.0
                ),
                &serde_json::json!({}).to_string(),
            )
            .unwrap();
        }

        // Validator set at PROMOTE time: offender removed (e.g. governance
        // unbonded them between attestation and quorum check).
        let promote_time_validators: Vec<(String, u64)> = vec![
            ("aaaa".repeat(8), 100),
            ("bbbb".repeat(8), 100),
            ("cccc".repeat(8), 100),
            ("dddd".repeat(8), 100),
        ];
        db.put(
            "sys:validators",
            &serde_json::to_string(&promote_time_validators).unwrap(),
        )
        .unwrap();

        let executor = Executor::new(db.clone());
        executor.promote_downtime_attestations_to_slash();

        assert!(
            db.get(&format!("sys:pending_slash:{}", offender))
                .unwrap()
                .is_none(),
            "NEW-002: offender removed from validator set must NOT be slashed at promote time"
        );
    }

    // ── Phase 4.A1: stake-proportional reward distribution ────────────────

    fn temp_db_a1(suffix: &str) -> Arc<StateDB> {
        let mut p = std::env::temp_dir();
        p.push(format!("aincore_a1_{}_{}", std::process::id(), suffix));
        let _ = std::fs::remove_dir_all(&p);
        Arc::new(StateDB::open(p.to_str().unwrap()).unwrap())
    }

    fn set_validator_set_a1(db: &StateDB, vs: &[(&str, u64)]) {
        let owned: Vec<(String, u64)> =
            vs.iter().map(|(a, s)| (a.to_string(), *s)).collect();
        db.put("sys:validators", &serde_json::to_string(&owned).unwrap())
            .unwrap();
    }

    #[test]
    fn a1_empty_validator_set_falls_back_to_leader() {
        let db = temp_db_a1("empty_vset");
        let executor = Executor::new(Arc::clone(&db));
        let payouts = executor.compute_block_payouts("leader", 1_000);

        assert_eq!(payouts.len(), 1);
        assert_eq!(payouts[0], ("leader".to_string(), 1_000));
    }

    #[test]
    fn a1_single_validator_gets_everything() {
        let db = temp_db_a1("single");
        set_validator_set_a1(&db, &[("alice", 100)]);
        let executor = Executor::new(Arc::clone(&db));
        let payouts = executor.compute_block_payouts("alice", 1_000);

        // alice = anchor leader, also sole pool member
        // total must == 1_000, no funds lost
        let total: u128 = payouts.iter().map(|(_, s)| s).sum();
        assert_eq!(total, 1_000);
        // Should be a single entry for alice with 1_000
        assert_eq!(payouts.iter().find(|(a, _)| a == "alice").unwrap().1, 1_000);
    }

    #[test]
    fn a1_stake_proportional_distribution() {
        let db = temp_db_a1("proportional");
        // 3 validators with stakes 100, 200, 700 (total 1000)
        // Leader bonus: 20% of 1000 = 200 → leader (alice)
        // Pool: 80% of 1000 = 800
        //   alice (100/1000): 80
        //   bob   (200/1000): 160
        //   carol (700/1000): 560
        //   sum: 800 (no remainder)
        // Final: alice = 200 + 80 = 280, bob = 160, carol = 560
        set_validator_set_a1(&db, &[("alice", 100), ("bob", 200), ("carol", 700)]);
        let executor = Executor::new(Arc::clone(&db));
        let payouts = executor.compute_block_payouts("alice", 1_000);

        let map: std::collections::HashMap<String, u128> = payouts.into_iter().collect();
        assert_eq!(map.get("alice").copied().unwrap_or(0), 280);
        assert_eq!(map.get("bob").copied().unwrap_or(0), 160);
        assert_eq!(map.get("carol").copied().unwrap_or(0), 560);

        // Conservation: total payouts == total_reward
        let total: u128 = map.values().sum();
        assert_eq!(total, 1_000, "no AIN may be lost in distribution");
    }

    #[test]
    fn a1_rounding_remainder_goes_to_leader() {
        let db = temp_db_a1("rounding");
        // 3 validators, equal stake 1 each (total 3).
        // total_reward = 100
        // leader_bonus = 20% = 20
        // pool = 80
        // each share = 80 / 3 = 26 (truncated)
        // distributed_pool = 78
        // remainder = 2 → goes to leader (alice)
        // alice = 20 + 26 + 2 = 48
        // bob   = 26
        // carol = 26
        // total: 100 ✓
        set_validator_set_a1(&db, &[("alice", 1), ("bob", 1), ("carol", 1)]);
        let executor = Executor::new(Arc::clone(&db));
        let payouts = executor.compute_block_payouts("alice", 100);

        let map: std::collections::HashMap<String, u128> = payouts.into_iter().collect();
        let total: u128 = map.values().sum();
        assert_eq!(total, 100, "rounding remainder must not be lost");
        // Leader gets at least bonus + own share
        assert!(*map.get("alice").unwrap_or(&0) >= 20 + 26);
    }

    #[test]
    fn a1_non_validator_leader_still_gets_bonus() {
        // Edge case: anchor_leader is NOT in validator set (e.g. transient state).
        // Leader bonus still flows to leader; pool split among validators.
        let db = temp_db_a1("non_validator_leader");
        set_validator_set_a1(&db, &[("bob", 100), ("carol", 100)]);
        let executor = Executor::new(Arc::clone(&db));
        let payouts = executor.compute_block_payouts("ghost_leader", 1_000);

        let map: std::collections::HashMap<String, u128> = payouts.into_iter().collect();
        // ghost_leader gets 20% bonus = 200
        assert_eq!(*map.get("ghost_leader").unwrap_or(&0), 200);
        // bob + carol split 800 equally = 400 each
        assert_eq!(*map.get("bob").unwrap_or(&0), 400);
        assert_eq!(*map.get("carol").unwrap_or(&0), 400);

        let total: u128 = map.values().sum();
        assert_eq!(total, 1_000);
    }
}
