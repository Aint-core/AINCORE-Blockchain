use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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

/// The chain id transactions must carry: `sys:chain_id`, installed at boot
/// (G3 FX-6). The `AINCORE_CHAIN_ID` env is not a source.
pub fn expected_chain_id() -> String {
    blockchain::chain_id()
}
// V3 CONSTANTS
// SEC-#14: 150M AIN hard cap (in quanta). Minting is cap-clamped in
// staking.move (distribute_rewards); this constant backs the executor-side
// defense-in-depth tripwire in `append_supply_tracker_updates`.
const MAX_SUPPLY: u128 = 150_000_000 * 1_000_000_000_000_000_000; // 150 Million AIN
                                                                  // Note: Block rewards handled exclusively by staking.move (Halving model)
                                                                  // Executor only distributes transaction fees — no inflationary minting here

// N-2 FIX: Per-block cumulative object limit to prevent memory exhaustion DoS.
// 10,000 TXs × 128 objects = 1.28M objects → 1.28GB RAM. Cap at 10K total.
const MAX_OBJECTS_PER_BLOCK: usize = 10_000;
// Gas cost per input object loaded (prevents zero-cost object flooding)
/// Protocol ceiling on a single transaction's `gas_limit`.
///
/// AUDIT-CRITICAL (pre-mainnet B5). Real transactions here use 1_000..100_000
/// gas, so this leaves ~100x headroom while bounding the work one transaction
/// can force every validator to perform. Without it `gas_limit` was unbounded
/// and a ~0.001 AIN transaction could run an unbounded Move loop on every node
/// at once (there is no wall-clock timeout on execution). Enforced in BOTH the
/// executor (consensus path, authoritative) and the mempool (admission).
pub const MAX_GAS_LIMIT: u64 = 10_000_000;

/// Protocol ceiling on the SUM of `gas_limit` across one block.
///
/// GATE-CRITICAL (pre-mainnet). MAX_GAS_LIMIT alone bounds a single
/// transaction, so a block packed with transactions at that ceiling reaches the
/// same unbounded-execution halt by volume. 200M is 20 transactions at the
/// per-tx maximum, or ~2000 ordinary ones, while capping the work any single
/// block can force on every validator.
pub const MAX_BLOCK_GAS_LIMIT: u64 = 200_000_000;

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
    vm_move::state_keys::resource_key(&addr, &tag)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveCoin {
    value: u128,
}

/// SEC-#27: best-effort read of an address's committed AIN balance from its
/// `0x1::coin::CoinStore<0x1::staking::AincoreCoin>` resource.
///
/// Returns `None` when the address is unparseable, the CoinStore is absent, or
/// the stored bytes don't decode. Callers MUST treat `None` as **unknown**
/// (fail-open), never as zero: an account can be funded by an earlier
/// transaction in the same block, so a missing/uninitialised store at admission
/// time must not cause a false rejection. Mirrors the production read in
/// `core/node/src/api_local.rs::coin_store_balance` byte-for-byte.
pub fn committed_ain_balance(db: &StateDB, address: &str) -> Option<u128> {
    let move_addr = parse_move_address(address)?;
    let tag = move_core_types::language_storage::StructTag {
        address: system_address(),
        module: move_core_types::identifier::Identifier::new("coin").ok()?,
        name: move_core_types::identifier::Identifier::new("CoinStore").ok()?,
        type_params: vec![aincore_coin_type()],
    };
    let key = vm_move::state_keys::resource_key(&move_addr, &tag);
    let hex_value = db.get(&key).ok().flatten()?;
    let bytes = hex::decode(hex_value).ok()?;
    bcs::from_bytes::<MoveCoin>(&bytes).ok().map(|c| c.value)
}

/// Local mirror of `consensus::qc::ValidatorInfo` for `sys:validator_set:v1`.
///
/// The executor cannot depend on the `consensus` crate (consensus depends on
/// executor — a dep here would be circular), so this struct reproduces the
/// exact serde JSON field layout of `consensus::qc::ValidatorInfo`. Field names
/// MUST match byte-for-byte so the JSON written here round-trips through
/// `consensus::qc::ValidatorInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ValidatorSetV1Entry {
    address: String,
    stake: u64,
    ed25519_public_key: String,
    bls_public_key: String,
    bls_pop: String,
}

/// Extract the `sys:validator_set:v1` entry for a `join_validator_set` call, or
/// `None` if this is not such a call. Mirrors the genesis `crypto_qc_validator_info`
/// scaling (stake in 10^18 quanta -> whole-AIN u64). The PoP has already been
/// verified by `verify_join_validator_pop` before dispatch.
fn extract_join_validator_v1(
    call: &vm_move::EntryFunctionCall,
    sender: &str,
) -> Option<ValidatorSetV1Entry> {
    if *call.module.address() != system_address()
        || call.module.name().as_str() != "staking"
        || call.function != "join_validator_set"
        || call.args.len() < 5
    {
        return None;
    }
    let stake_quanta: u128 = bcs::from_bytes(&call.args[1]).ok()?;
    let public_key: Vec<u8> = bcs::from_bytes(&call.args[2]).ok()?;
    let bls_public_key: Vec<u8> = bcs::from_bytes(&call.args[3]).ok()?;
    let bls_pop: Vec<u8> = bcs::from_bytes(&call.args[4]).ok()?;
    const COIN_SCALE: u128 = 1_000_000_000_000_000_000;
    let stake = u64::try_from(stake_quanta / COIN_SCALE).ok()?;
    Some(ValidatorSetV1Entry {
        address: sender.to_string(),
        stake,
        ed25519_public_key: hex::encode(&public_key),
        bls_public_key: hex::encode(&bls_public_key),
        bls_pop: hex::encode(&bls_pop),
    })
}

/// AUDIT-#1: detect a `0x1::staking::leave_validator_set` entry call so the
/// executor can prune the departing validator from the QC trust root
/// (`sys:validator_set:v1`) and the `sys:validators` reward mirror after a
/// successful execution. Move's `leave_validator_set` removes the validator from
/// its live set and burns bonded stake into the 21-day unbonding queue, but the
/// Rust-side mirrors were pruned ONLY on slash — so a departed (once-supermajority)
/// coalition kept full QC stake weight forever and could forge a >2/3 QC at zero
/// stake-at-risk (nothing-at-stake double-finality). Returns the leaving address.
fn extract_leave_validator(call: &vm_move::EntryFunctionCall, sender: &str) -> Option<String> {
    if *call.module.address() != system_address()
        || call.module.name().as_str() != "staking"
        || call.function != "leave_validator_set"
    {
        return None;
    }
    Some(sender.to_string())
}

/// AUDIT-#5: detect a `0x1::staking::add_stake(account, amount)` entry call so
/// the executor can RESYNC the staker's weight in the QC trust root
/// (`sys:validator_set:v1`) and the `sys:validators` reward mirror from the
/// authoritative Move ValidatorSet after the stake grows. Without this, a
/// validator's real stake increases but its QC quorum weight stays frozen at the
/// join-time value — the >2/3 finality math drifts from actual stake-at-risk.
/// Returns the staker address (an add_stake by a non-validator is a harmless
/// no-op in the resync).
fn extract_add_stake(call: &vm_move::EntryFunctionCall, sender: &str) -> Option<String> {
    if *call.module.address() != system_address()
        || call.module.name().as_str() != "staking"
        || call.function != "add_stake"
    {
        return None;
    }
    Some(sender.to_string())
}

/// Authoritative pre-dispatch gate for `0x1::staking::join_validator_set`.
///
/// Move cannot run the BLS pairing check, so the proof-of-possession binding
/// (the rogue-key defense for QC aggregation) MUST be enforced in Rust BEFORE
/// the entry function is dispatched. The Move entry only enforces structural
/// length invariants (pk=48, pop=96). Returns Ok(()) when this is NOT a
/// join_validator_set call (nothing to check) or when the supplied PoP verifies.
///
/// `join_validator_set(account: &signer, stake_amount: u128, public_key,
/// bls_public_key, bls_pop)` — so `call.args` layout is:
///   [0]=signer placeholder, [1]=stake_amount, [2]=public_key,
///   [3]=bls_public_key, [4]=bls_pop  (each vector<u8> is BCS-encoded).
fn verify_join_validator_pop(
    call: &vm_move::EntryFunctionCall,
    tx_public_key_hex: &str,
) -> Result<(), String> {
    if *call.module.address() != system_address()
        || call.module.name().as_str() != "staking"
        || call.function != "join_validator_set"
    {
        return Ok(());
    }

    if call.args.len() < 5 {
        return Err(format!(
            "join_validator_set: expected 5 args, got {}",
            call.args.len()
        ));
    }

    let public_key: Vec<u8> = bcs::from_bytes(&call.args[2])
        .map_err(|e| format!("join_validator_set: malformed public_key arg: {}", e))?;
    let bls_public_key: Vec<u8> = bcs::from_bytes(&call.args[3])
        .map_err(|e| format!("join_validator_set: malformed bls_public_key arg: {}", e))?;
    let bls_pop: Vec<u8> = bcs::from_bytes(&call.args[4])
        .map_err(|e| format!("join_validator_set: malformed bls_pop arg: {}", e))?;

    let tx_public_key = hex::decode(tx_public_key_hex.trim_start_matches("0x"))
        .map_err(|e| format!("join_validator_set: malformed tx public_key hex: {}", e))?;
    if public_key.len() != 32 {
        return Err(format!(
            "join_validator_set: public_key must be 32 bytes, got {}",
            public_key.len()
        ));
    }
    if public_key != tx_public_key {
        return Err("join_validator_set: public_key arg must equal tx.public_key".into());
    }
    if bls_public_key.len() != 48 {
        return Err(format!(
            "join_validator_set: bls_public_key must be 48 bytes, got {}",
            bls_public_key.len()
        ));
    }
    if bls_pop.len() != 96 {
        return Err(format!(
            "join_validator_set: bls_pop must be 96 bytes, got {}",
            bls_pop.len()
        ));
    }

    match crypto::bls::BLSEngine::consensus().verify_possession(&bls_public_key, &bls_pop) {
        Ok(true) => Ok(()),
        Ok(false) => Err("join_validator_set: BLS proof-of-possession failed verification".into()),
        Err(e) => Err(format!(
            "join_validator_set: BLS PoP verification error: {:?}",
            e
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveValidatorConfig {
    validator_addr: move_core_types::account_address::AccountAddress,
    stake: MoveCoin,
    public_key: Vec<u8>,
    bls_public_key: Vec<u8>,
    bls_pop: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveUnbondingRequest {
    validator_addr: move_core_types::account_address::AccountAddress,
    stake: u128,
    start_height: u64,
    unlock_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveValidatorSet {
    validators: Vec<MoveValidatorConfig>,
    unbonding_queue: Vec<MoveUnbondingRequest>,
    total_supply: u128,
    current_epoch: u64,
}

/// AUDIT-#8 mirror of the Move `0x1::staking::SupplyStats` resource. Independent
/// of ValidatorSet (its byte layout is untouched), so this adds no BCS-mirror
/// coupling to the on-chain validator set. Holds the monotonic cumulative-burn
/// ledger the emission anchor keys off (minted = ValidatorSet.total_supply +
/// SupplyStats.cumulative_burned).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MoveSupplyStats {
    cumulative_burned: u128,
}

/// Mirror of the Move `0x1::delegation::SlashEvent` (G5 SL-1), BCS field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationSlashEvent {
    pub seq: u64,
    pub infraction_epoch: u64,
    pub bps: u64,
    pub pending_tickets: u64,
}

/// Mirror of the Move `0x1::delegation::Pool` (G5 DL-2), BCS field order. A
/// `Coin` is a struct of one u128, so its BCS bytes are that u128's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPool {
    pub active_coins: u128,
    pub active_points: u128,
    pub reward_counter: u128,
    pub reward_carry: u128,
    pub unbonding_coins: u128,
    pub principal: u128,
    pub rewards: u128,
    pub commission_rate: u64,
    pub pending_commission: u64,
    pub commission_effective_time: u64,
    pub closed: bool,
    pub slash_count: u64,
    pub ticket_count: u64,
    pub position_count: u64,
    pub slash_events: Vec<DelegationSlashEvent>,
}

/// Mirror of the Move `0x1::delegation::Position`, BCS field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationPosition {
    pub validator: move_core_types::account_address::AccountAddress,
    pub points: u128,
    pub reward_snapshot: u128,
}

/// Mirror of the Move `0x1::delegation::Ticket` (G5 DL-3), BCS field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationTicket {
    pub validator: move_core_types::account_address::AccountAddress,
    pub amount: u128,
    pub created_epoch: u64,
    pub slash_seq: u64,
    pub unlock_time: u64,
}

/// Mirror of the Move `0x1::delegation::Book` (G5 DL-3), BCS field order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationBook {
    pub positions: Vec<DelegationPosition>,
    pub tickets: Vec<DelegationTicket>,
}

/// A committed `0x1::delegation` resource at `address`: `Ok(None)` when the
/// address is unparseable or holds none, `Err` when the stored value does not
/// decode (corrupt state).
fn delegation_resource<T: serde::de::DeserializeOwned>(
    db: &StateDB,
    address: &str,
    tag: &str,
) -> Result<Option<T>, String> {
    let Some(address) = parse_move_address(address) else {
        return Ok(None);
    };
    let Some(stored) = db
        .get(&vm_move::state_keys::resource_key_str(&address, tag))
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    let bytes = hex::decode(stored).map_err(|e| format!("{tag} is not hex: {e}"))?;
    bcs::from_bytes(&bytes)
        .map(Some)
        .map_err(|e| format!("{tag} is corrupt: {e}"))
}

/// The delegation pool of `validator` (G5 DL-2), if it opened one. For
/// readers (the RPC): unreadable state reads as none.
pub fn delegation_pool(db: &StateDB, validator: &str) -> Option<DelegationPool> {
    delegation_resource(db, validator, "0x1::delegation::Pool")
        .ok()
        .flatten()
}

/// The positions and unbonding tickets of `delegator` (G5 DL-3). For
/// readers (the RPC): unreadable state reads as none.
pub fn delegation_book(db: &StateDB, delegator: &str) -> Option<DelegationBook> {
    delegation_resource(db, delegator, "0x1::delegation::Book")
        .ok()
        .flatten()
}

impl DelegationPool {
    /// G5 CM-1: the commission in force at consensus time `time`, in basis
    /// points (Move's `commission_at`).
    pub fn commission_at(&self, time: u64) -> u64 {
        if self.pending_commission != self.commission_rate && time >= self.commission_effective_time
        {
            self.pending_commission
        } else {
            self.commission_rate
        }
    }

    /// G5 DL-2, DL-3: what `position` is worth, floor(p x C / P), and what it
    /// can claim, floor(p x (rho - snapshot) / S) clamped to the reward
    /// escrow (Move's `get_delegation`).
    pub fn position_value(&self, position: &DelegationPosition) -> (u128, u128) {
        use move_core_types::u256::U256;
        // Move's `math::mul_div_floor`, in u256; a quotient past u128 (not
        // reachable from valid state) saturates.
        let mul_div = |a: u128, b: u128, c: u128| -> u128 {
            if c == 0 {
                return 0;
            }
            let quotient = U256::from(a) * U256::from(b) / U256::from(c);
            if quotient > U256::from(u128::MAX) {
                u128::MAX
            } else {
                quotient.unchecked_as_u128()
            }
        };
        let value = mul_div(position.points, self.active_coins, self.active_points);
        let owed = mul_div(
            position.points,
            self.reward_counter.saturating_sub(position.reward_snapshot),
            COIN_SCALE,
        );
        (value, owed.min(self.rewards))
    }
}

/// G5 DL-1: the committee weight `validator`'s pool adds, in whole AIN: its
/// bonded delegated principal, or 0 without an open pool (a slashed pool
/// weighs nothing). Corrupt pool state stops the node: this feeds the
/// committee.
pub fn delegated_weight(db: &StateDB, validator: &str) -> u64 {
    delegation_resource::<DelegationPool>(db, validator, "0x1::delegation::Pool")
        .unwrap_or_else(|e| panic!("CRITICAL: {e}"))
        .filter(|pool| !pool.closed)
        .map(|pool| u64::try_from(pool.active_coins / COIN_SCALE).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// 1 AIN in base units.
const COIN_SCALE: u128 = 1_000_000_000_000_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FeeSweepEntry {
    miner: String,
    amount: String,
    reason: String,
    attempts: u64,
}

/// Storage key of the Move `0x1::staking::ValidatorSet` resource. Pinned to
/// the canonical encoder (`vm_move::state_keys`) by a golden test.
/// Mirror of the Move `0x1::chain::Clock` resource (BCS field order).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainClock {
    pub height: u64,
    /// tau, consensus time in seconds.
    pub time: u64,
    /// The block's BFT timestamp, seconds.
    pub block_timestamp: u64,
}

/// Mirror of the Move `0x1::chain::Params` resource (BCS field order).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct ChainParamsResource {
    epoch_blocks: u64,
    reward_period: u64,
    max_block_interval_secs: u64,
}

/// The genesis-pinned `0x1::chain::Params`, if the chain has them (a test
/// fixture may not; boot refuses such a database).
fn chain_params(db: &StateDB) -> Option<ChainParamsResource> {
    let key = vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Params");
    db.get(&key)
        .expect("CRITICAL: the chain parameters could not be read")
        .map(|hex_value| {
            bcs::from_bytes(&hex::decode(hex_value).expect("CRITICAL: chain state is not hex"))
                .expect("CRITICAL: 0x1::chain::Params is corrupt")
        })
}

/// G5 CL-1/CL-2 (amendment A1): the `0x1::chain::Clock` for block `height`
/// whose BFT timestamp is `block_timestamp`, given the chain's state before
/// it. tau grows by the timestamp's growth since the previous block, capped
/// at the genesis-pinned `max_block_interval_secs`: it follows real time at
/// any block speed, and a halt or a corrupted timestamp moves it by at most
/// the cap per block. A timestamp that goes back adds nothing. Without
/// `Params` (only a test fixture: boot refuses such a database) the cap is 0,
/// so the clock is frozen.
pub fn next_chain_clock(db: &StateDB, height: u64, block_timestamp: u64) -> ChainClock {
    let read = |resource: &str| {
        db.get(&vm_move::state_keys::resource_key_str(
            &system_address(),
            resource,
        ))
        .expect("CRITICAL: the chain clock state could not be read")
        .map(|hex_value| hex::decode(hex_value).expect("CRITICAL: chain state is not hex"))
    };
    let previous: ChainClock = read("0x1::chain::Clock")
        .map(|bytes| bcs::from_bytes(&bytes).expect("CRITICAL: 0x1::chain::Clock is corrupt"))
        .unwrap_or_default();
    let cap = chain_params(db)
        .map(|p| p.max_block_interval_secs)
        .unwrap_or(0);
    let growth = block_timestamp.saturating_sub(previous.block_timestamp);
    ChainClock {
        height,
        time: previous.time.saturating_add(growth.min(cap)),
        block_timestamp: block_timestamp.max(previous.block_timestamp),
    }
}

/// The committed `0x1::chain::Clock` (G5 CL-2), for readers (the RPC):
/// before the first block, or unreadable, it reads as zero.
pub fn committed_chain_clock(db: &StateDB) -> ChainClock {
    db.get(&vm_move::state_keys::resource_key_str(
        &system_address(),
        "0x1::chain::Clock",
    ))
    .ok()
    .flatten()
    .and_then(|raw| hex::decode(raw).ok())
    .and_then(|bytes| bcs::from_bytes(&bytes).ok())
    .unwrap_or_default()
}

/// G5 CL-2: the state write every block makes before its transactions,
/// `0x1::chain::Clock` (see [`next_chain_clock`]), as (key, stored value). It
/// is the only state change an empty block makes.
pub fn chain_clock_write(db: &StateDB, height: u64, block_timestamp: u64) -> (String, String) {
    let clock = next_chain_clock(db, height, block_timestamp);
    (
        vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock"),
        hex::encode(bcs::to_bytes(&clock).expect("the clock is BCS-serializable")),
    )
}

pub fn validator_set_key() -> String {
    vm_move::state_keys::resource_key_str(&system_address(), "0x1::staking::ValidatorSet")
}

fn validator_set_v1_key() -> &'static str {
    "sys:validator_set:v1"
}

/// G5 DL-1: the delegated part of each member's weight in the committee of
/// `epoch`, written with the committee record.
fn delegated_split_key(epoch: u64) -> String {
    format!("sys:validator_set:epoch_delegated:{epoch}")
}

/// G5 SL-3: the consensus time committee epoch `epoch` began, written at its
/// boundary with the committee record.
fn epoch_time_key(epoch: u64) -> String {
    format!("sys:validator_set:epoch_time:{epoch}")
}

/// G5 SL-3: the oldest epoch whose committee records are still kept.
const RETAINED_FROM_KEY: &str = "sys:validator_set:retained_from";

/// W, `0x1::chain::EVIDENCE_MAX_AGE_SECS` (G5 SL-3): an epoch's records are
/// kept while evidence of it can still be accepted.
const EVIDENCE_MAX_AGE_SECS: u64 = 604_800;

/// G5 SL-3: a verified evidence item: the offender and the slot it
/// equivocated in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidence {
    pub offender: String,
    pub kind: String,
    /// The committee epoch of the slot. A V3 proof binds none: the executing
    /// block's stands in (the V3 path is deleted in G5 S4c).
    pub epoch: u64,
    pub round: u64,
}

/// G5 SL-5: an offense's weights from the records of its epoch.
struct OffenseRecord {
    began: u64,
    weight: u64,
    committee_weight: u64,
    delegated: u64,
}

fn dex_registry_key() -> String {
    vm_move::state_keys::resource_key_str(&system_address(), "0x1::dex::PoolRegistry")
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
    vm_move::state_keys::resource_key(&addr, &tag)
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
    Some(vm_move::state_keys::resource_key(&pool_addr, &tag))
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
    Some(vm_move::state_keys::resource_key(&owner, &tag))
}

fn decode_validator_set_hex(value: &str) -> Option<MoveValidatorSet> {
    let bytes = hex::decode(value).ok()?;
    bcs::from_bytes::<MoveValidatorSet>(&bytes).ok()
}

fn encode_validator_set_hex(value: &MoveValidatorSet) -> Option<String> {
    bcs::to_bytes(value).ok().map(hex::encode)
}

/// AUDIT-#8: db key of the Move `0x1::staking::SupplyStats` resource. Built
/// identically to `validator_set_key()` so the Rust fee-burn writes the exact
/// resource the Move VM reads via `borrow_global<SupplyStats>(@0x1)`.
fn supply_stats_key() -> String {
    vm_move::state_keys::resource_key_str(&system_address(), "0x1::staking::SupplyStats")
}

fn decode_supply_stats_hex(value: &str) -> Option<MoveSupplyStats> {
    let bytes = hex::decode(value).ok()?;
    bcs::from_bytes::<MoveSupplyStats>(&bytes).ok()
}

fn encode_supply_stats_hex(value: &MoveSupplyStats) -> Option<String> {
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
    args.get(index)
        .and_then(|bytes| bcs::from_bytes(bytes).ok())
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
                serde_json::json!(post_pool
                    .coin_x
                    .value
                    .saturating_sub(pre_pool.coin_x.value)
                    .to_string()),
            );
            metadata.insert(
                "actual_amount_y".to_string(),
                serde_json::json!(post_pool
                    .coin_y
                    .value
                    .saturating_sub(pre_pool.coin_y.value)
                    .to_string()),
            );
            metadata.insert(
                "actual_lp_minted".to_string(),
                serde_json::json!(post_pool
                    .lp_supply
                    .saturating_sub(pre_pool.lp_supply)
                    .to_string()),
            );
        }
        "remove_liquidity" => {
            metadata.insert(
                "actual_amount_x".to_string(),
                serde_json::json!(pre_pool
                    .coin_x
                    .value
                    .saturating_sub(post_pool.coin_x.value)
                    .to_string()),
            );
            metadata.insert(
                "actual_amount_y".to_string(),
                serde_json::json!(pre_pool
                    .coin_y
                    .value
                    .saturating_sub(post_pool.coin_y.value)
                    .to_string()),
            );
            metadata.insert(
                "actual_lp_burned".to_string(),
                serde_json::json!(pre_pool
                    .lp_supply
                    .saturating_sub(post_pool.lp_supply)
                    .to_string()),
            );
        }
        "swap_x_to_y" => {
            metadata.insert(
                "token_in".to_string(),
                serde_json::json!(type_args.first().cloned()),
            );
            metadata.insert(
                "token_out".to_string(),
                serde_json::json!(type_args.get(1).cloned()),
            );
            metadata.insert(
                "actual_amount_out".to_string(),
                serde_json::json!(pre_pool
                    .coin_y
                    .value
                    .saturating_sub(post_pool.coin_y.value)
                    .to_string()),
            );
        }
        "swap_y_to_x" => {
            metadata.insert(
                "token_in".to_string(),
                serde_json::json!(type_args.get(1).cloned()),
            );
            metadata.insert(
                "token_out".to_string(),
                serde_json::json!(type_args.first().cloned()),
            );
            metadata.insert(
                "actual_amount_out".to_string(),
                serde_json::json!(pre_pool
                    .coin_x
                    .value
                    .saturating_sub(post_pool.coin_x.value)
                    .to_string()),
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
                    obj.insert(
                        "amount_x".to_string(),
                        serde_json::json!(amount_x.to_string()),
                    );
                }
                if let Some(amount_y) = bcs_arg::<u128>(&call.args, 3) {
                    obj.insert(
                        "amount_y".to_string(),
                        serde_json::json!(amount_y.to_string()),
                    );
                }
                if let Some(min_lp) = bcs_arg::<u128>(&call.args, 4) {
                    obj.insert("min_lp".to_string(), serde_json::json!(min_lp.to_string()));
                }
            }
            "remove_liquidity" => {
                if let Some(lp_amount) = bcs_arg::<u128>(&call.args, 2) {
                    obj.insert(
                        "lp_amount".to_string(),
                        serde_json::json!(lp_amount.to_string()),
                    );
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
                    obj.insert(
                        "amount_in".to_string(),
                        serde_json::json!(amount_in.to_string()),
                    );
                }
                if let Some(min_out) = bcs_arg::<u128>(&call.args, 3) {
                    obj.insert(
                        "min_out".to_string(),
                        serde_json::json!(min_out.to_string()),
                    );
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

/// Result of asking the executor to execute a block AT a height.
///
/// ROOT-CAUSE FIX (2026-08-25 burn-in): `sys:state_root` is a CHAIN —
/// `H(prev_root || writes)` — and TWO paths execute blocks into it: ChainSync's
/// import and the local commit loop. The block lock only covered execution, so
/// when a node fell behind, sync could execute height H while the local loop was
/// still building H-1; the local block's header then captured a root that
/// already contained H's work. Observed live: the epoch advance for height 6640
/// landed inside the block stored as 6639, permanently offsetting that node's
/// prev_hash chain (51k "Parent hash mismatch" rejections, chain split 3 ways
/// with zero transactions). Heights are now executed strictly one at a time, in
/// order, enforced INSIDE the lock — so double execution is unrepresentable
/// rather than merely unlikely.
#[derive(Debug)]
pub enum BlockExecOutcome {
    /// The height was executed by this call; state root advanced.
    Executed(BlockExecutionSummary),
    /// Another path already executed this height. The caller must NOT build or
    /// persist a block for it.
    AlreadyExecuted { last_executed: u64 },
    /// The chain state is behind the requested height; executing would skip a
    /// block. The caller must let sync fill the gap first.
    Gap { expected: u64, got: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockExecutionSummary {
    pub state_root: String,
    pub receipts_root: String,
    pub gas_charged: u128,
    pub tx_count: usize,
    /// Orphan-loss fix: the RAW transactions that actually EXECUTED in this
    /// block (accepted by the nonce/signature gates and committed their
    /// writes). The consensus layer reports these to the mempool's loan ledger
    /// (`mark_executed`); anything pulled but NOT in this list stays inflight
    /// and is re-queued by `requeue_stale` — so an orphaned vertex or a
    /// nonce-deferred transaction is a delay, never a permanent loss.
    pub executed_raws: Vec<String>,
}

pub struct Executor {
    db: Arc<StateDB>,
    vm: AINCOREVM,
    #[cfg(test)]
    block_boundary_hook: Option<fn(u8, &StateDB)>,
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
        Self {
            db,
            vm,
            #[cfg(test)]
            block_boundary_hook: None,
        }
    }

    /// B1: keep `sys:validator_set:v1` live when a validator joins at runtime.
    /// Appends (or replaces by address) the new validator's finality identity and
    /// stages it in the transaction update set. Also stages the legacy
    /// `sys:validators` mirror because older consensus/tooling still reads the
    /// `(address, stake)` list. This MUST NOT write directly to RocksDB: the
    /// production path commits updates atomically inside
    /// `execute_block_parallel`, and the state-root hash is derived from that same
    /// update list.
    fn append_validator_set_v1_update(
        &self,
        updates: &mut Vec<(String, Option<String>)>,
        entry: ValidatorSetV1Entry,
    ) -> Result<(), String> {
        let legacy_entry = (entry.address.clone(), entry.stake);
        let key = validator_set_v1_key();
        let existing_json = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == key { v.as_deref() } else { None })
            .map(str::to_string)
            .or_else(|| self.db.get(key).ok().flatten());

        let mut set: Vec<ValidatorSetV1Entry> = existing_json
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();
        set.retain(|v| v.address != entry.address);
        set.push(entry);
        let json = serde_json::to_string(&set)
            .map_err(|e| format!("serialize sys:validator_set:v1 failed: {e}"))?;
        updates.push((key.to_string(), Some(json)));

        let legacy_key = "sys:validators";
        let existing_legacy_json = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == legacy_key { v.as_deref() } else { None })
            .map(str::to_string)
            .or_else(|| self.db.get(legacy_key).ok().flatten());

        let mut legacy_set: Vec<(String, u64)> = existing_legacy_json
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();
        legacy_set.retain(|(addr, _)| addr != &legacy_entry.0);
        legacy_set.push(legacy_entry);
        legacy_set.sort_by(|a, b| a.0.cmp(&b.0));
        legacy_set.dedup_by(|a, b| a.0 == b.0);
        let legacy_json = serde_json::to_string(&legacy_set)
            .map_err(|e| format!("serialize sys:validators failed: {e}"))?;
        updates.push((legacy_key.to_string(), Some(legacy_json)));
        Ok(())
    }

    /// AUDIT-#1: prune a validator from BOTH the QC trust root
    /// (`sys:validator_set:v1`) and the `sys:validators` reward mirror, staged
    /// into the block's update batch. The slash path already prunes both; this
    /// mirrors it for a VOLUNTARY `leave_validator_set` so a departed validator
    /// cannot retain QC quorum weight (nothing-at-stake) or keep drawing fee
    /// payouts. Reads the latest staged-or-committed value so it composes with a
    /// same-block join.
    fn append_validator_removal(
        &self,
        updates: &mut Vec<(String, Option<String>)>,
        addr: &str,
    ) -> Result<(), String> {
        let key = validator_set_v1_key();
        let existing = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == key { v.as_deref() } else { None })
            .map(str::to_string)
            .or_else(|| self.db.get(key).ok().flatten());
        if let Some(json) = existing {
            if let Ok(mut set) = serde_json::from_str::<Vec<ValidatorSetV1Entry>>(&json) {
                let before = set.len();
                set.retain(|v| v.address != addr);
                if set.len() != before {
                    let nj = serde_json::to_string(&set)
                        .map_err(|e| format!("serialize sys:validator_set:v1 failed: {e}"))?;
                    updates.push((key.to_string(), Some(nj)));
                }
            }
        }
        let legacy_key = "sys:validators";
        let existing_legacy = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == legacy_key { v.as_deref() } else { None })
            .map(str::to_string)
            .or_else(|| self.db.get(legacy_key).ok().flatten());
        if let Some(json) = existing_legacy {
            if let Ok(mut legacy) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                let before = legacy.len();
                legacy.retain(|(a, _)| a != addr);
                if legacy.len() != before {
                    let nj = serde_json::to_string(&legacy)
                        .map_err(|e| format!("serialize sys:validators failed: {e}"))?;
                    updates.push((legacy_key.to_string(), Some(nj)));
                }
            }
        }
        Ok(())
    }

    /// AUDIT-#5: resync one validator's stake in the QC trust root
    /// (`sys:validator_set:v1`) and the `sys:validators` reward mirror from the
    /// AUTHORITATIVE Move `ValidatorSet` after `add_stake`. Reads the latest
    /// staged-or-committed Move set so it composes with same-block changes, and
    /// derives the whole-AIN u64 weight exactly as the join path does
    /// (`stake_quanta / 10^18`). No-op if the address is not an active validator
    /// or has no v1 entry (e.g. a non-validator top-up), so it is always safe to
    /// call. Staged into the block update batch — never a direct RocksDB write —
    /// so it is covered by the state-root hash.
    fn refresh_validator_set_v1_stake(
        &self,
        updates: &mut Vec<(String, Option<String>)>,
        addr: &str,
    ) -> Result<(), String> {
        let want = match parse_move_address(addr) {
            Some(a) => a,
            None => return Ok(()),
        };
        // New authoritative stake (whole AIN, u64) from the Move ValidatorSet.
        let vs_key = validator_set_key();
        let move_set_hex = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == &vs_key { v.as_deref() } else { None })
            .map(str::to_string)
            .or_else(|| self.db.get(&vs_key).ok().flatten());
        let Some(move_set) = move_set_hex.as_deref().and_then(decode_validator_set_hex) else {
            return Ok(());
        };
        let Some(cfg) = move_set
            .validators
            .iter()
            .find(|c| c.validator_addr == want)
        else {
            return Ok(()); // not an active validator — nothing to resync
        };
        // G5 DL-1: the bonded weight, its own stake plus its open pool's.
        let new_stake = match u64::try_from(cfg.stake.value / COIN_SCALE) {
            Ok(s) => s.saturating_add(delegated_weight(&self.db, addr)),
            Err(_) => return Ok(()),
        };

        // Update the v1 QC-trust-root entry's stake (matched by address).
        let key = validator_set_v1_key();
        let existing = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == key { v.as_deref() } else { None })
            .map(str::to_string)
            .or_else(|| self.db.get(key).ok().flatten());
        if let Some(json) = existing {
            if let Ok(mut set) = serde_json::from_str::<Vec<ValidatorSetV1Entry>>(&json) {
                let mut changed = false;
                for e in set.iter_mut() {
                    if e.address == addr && e.stake != new_stake {
                        e.stake = new_stake;
                        changed = true;
                    }
                }
                if changed {
                    let nj = serde_json::to_string(&set)
                        .map_err(|e| format!("serialize sys:validator_set:v1 failed: {e}"))?;
                    updates.push((key.to_string(), Some(nj)));
                }
            }
        }

        // Update the sys:validators reward mirror's stake.
        let legacy_key = "sys:validators";
        let existing_legacy = updates
            .iter()
            .rev()
            .find_map(|(k, v)| if k == legacy_key { v.as_deref() } else { None })
            .map(str::to_string)
            .or_else(|| self.db.get(legacy_key).ok().flatten());
        if let Some(json) = existing_legacy {
            if let Ok(mut legacy) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                let mut changed = false;
                for (a, s) in legacy.iter_mut() {
                    if a == addr && *s != new_stake {
                        *s = new_stake;
                        changed = true;
                    }
                }
                if changed {
                    let nj = serde_json::to_string(&legacy)
                        .map_err(|e| format!("serialize sys:validators failed: {e}"))?;
                    updates.push((legacy_key.to_string(), Some(nj)));
                }
            }
        }
        Ok(())
    }

    /// The Jellyfish Merkle root at the latest committed version (G3), or
    /// all zeros before genesis seeded the tree.
    pub fn current_state_root(&self) -> String {
        match state_commit::latest_version(&self.db) {
            Ok(Some(version)) => state_commit::root(&self.db, version)
                .map(|root| hex::encode(root.0))
                .unwrap_or_else(|_| default_state_root()),
            _ => default_state_root(),
        }
    }

    /// The receipts root of a block, from the receipts THIS block wrote.
    ///
    /// G3 FX-5: it used to read `tx_receipt:*` from the database, so a
    /// transaction refused in this block but byte-identical to one executed
    /// earlier hashed the STALE earlier receipt, and a node restored without
    /// receipt history computed a different root. Only the block's own staged
    /// receipts count now; outside a block transaction every transaction is
    /// `NO_RECEIPT`.
    pub fn receipts_root_for_block(&self, txs_json: &[String]) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update((txs_json.len() as u64).to_be_bytes());
        for tx_json in txs_json {
            let tx_hash = tx_hash_hex(tx_json);
            hasher.update(tx_hash.as_bytes());
            match self.db.staged_get(&format!("tx_receipt:{}", tx_hash)) {
                Some(Some(receipt)) => hasher.update(&receipt),
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

        // SEC-#14: defense-in-depth cap tripwire. Net supply is mirrored from the
        // Move ValidatorSet.total_supply, whose minting is cap-clamped in
        // staking.move (distribute_rewards), so it must never exceed MAX_SUPPLY
        // here. If it ever does, a mint path has regressed past the 150M cap —
        // surface it loudly for monitoring/forensics. This is a read-only alert:
        // the executor must NOT abort an in-flight committed block (that would
        // itself diverge state); the alarm is the actionable signal.
        if new_supply > MAX_SUPPLY {
            eprintln!(
                "🚨 [SECURITY][SUPPLY_CAP] tracked supply {} exceeds MAX_SUPPLY {} — a mint path breached the 150M cap",
                new_supply, MAX_SUPPLY
            );
        }

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

    /// A plain staged write. Since G3 the state root covers every
    /// consensus-state write staged in the block transaction, logged or not,
    /// so there is no separate write log to feed.
    fn logged_put(&self, key: &str, val: &str) -> Result<(), String> {
        self.db.put(key, val).map_err(|e| e.to_string())
    }

    /// A plain staged delete (see `logged_put`).
    fn logged_delete(&self, key: &str) -> Result<(), String> {
        self.db.delete(key).map_err(|e| e.to_string())
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
            // Through the write log: this key feeds a later epoch block's
            // logged update, so leaving it outside the root means a divergence
            // here is invisible until it resurfaces in a block that cannot
            // explain it.
            let _ = self.logged_put("sys:total_supply", &new_supply.to_string());
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
                let _ = self.logged_put(
                    "total_burned",
                    &prev_burned.saturating_add(burned_delta).to_string(),
                );
            }
        }
    }

    /// SEC-#13: canonical, genesis-pinned default for the epoch-block interval.
    /// Used only when neither the on-chain config key nor a dev override is set
    /// (e.g. a fresh DB before genesis, or a legacy DB predating the pin).
    const DEFAULT_EPOCH_BLOCK_INTERVAL: u64 = 20;

    /// SEC-#13 (mainnet fork hazard): the epoch-block interval drives
    /// `maybe_advance_epoch` (boundary check), `rotate_validator_epoch`
    /// (`new_epoch = height / interval`), governance driving, and reward/halving
    /// timing. If two nodes used different values they would advance epochs at
    /// different heights → divergent validator-set snapshots + reward timing →
    /// FORK. To make this deterministic and identical across nodes, the canonical
    /// interval is written to `sys:config:epoch_block_interval` at genesis and
    /// folded into the genesis identity hash (forge-proof).
    ///
    /// The only source is `sys:config:epoch_block_interval` (G3 FX-6). The
    /// `AINCORE_EPOCH_BLOCK_INTERVAL` env used to stand in when the pin was
    /// absent. Now a node refuses to boot without the pin, or with an env that
    /// disagrees with it, so `DEFAULT_EPOCH_BLOCK_INTERVAL` only serves
    /// databases that never ran genesis (unit tests).
    fn epoch_block_interval(&self) -> u64 {
        self.db
            .get("sys:config:epoch_block_interval")
            .ok()
            .flatten()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(Self::DEFAULT_EPOCH_BLOCK_INTERVAL)
    }

    /// G5 CL-2: `0x1::chain::Clock` holds the executing block's height and
    /// consensus time. It is a state write inside the block transaction (so
    /// the root covers it).
    fn write_chain_clock(&self, height: u64, block_timestamp: u64) {
        let (key, value) = chain_clock_write(&self.db, height, block_timestamp);
        self.db
            .put(&key, &value)
            .expect("CRITICAL: the chain clock write failed inside the block transaction");
    }

    /// The committee epoch boundary H_E (G1 EP-1): Move's `advance_epoch`
    /// (the epoch counter, matured unbonding payouts), then the committee
    /// record for E+1. The record does not depend on Move succeeding: consensus
    /// derives the same committee at the same block whatever Move did (FX-14).
    fn maybe_advance_epoch(&self, next_height: u64) {
        let interval = self.epoch_block_interval();
        if next_height == 0 || !next_height.is_multiple_of(interval) {
            return;
        }
        // Exactly-once guard: a sync import and a local build racing on the same
        // height must not BOTH fire the boundary. The marker is written in the
        // same block transaction as the epoch state below.
        let already = self
            .db
            .get("sys:last_epoch_boundary")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if next_height <= already {
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

        match self.vm.execute_transaction_actions(
            vec![(action, true, system_address())],
            system_address(),
            // AUDIT-#2: bounded loops (matured payouts, MAX_PAYOUTS_PER_BOUNDARY)
            // fit well inside this budget.
            20_000_000,
        ) {
            Ok((_gas_used, mut updates, status)) if status.success => {
                self.append_supply_tracker_updates(&mut updates);
                if let Err(err) = self.commit_kv_updates(updates, "epoch advance") {
                    eprintln!("🚨 [EPOCH_ADVANCE_COMMIT_FAIL] {}", err);
                } else {
                    self.sync_supply_trackers_from_validator_set();
                }
            }
            Ok((_gas_used, _updates, status)) => eprintln!(
                "⚠️ Epoch advance aborted at block {}: {:?}",
                next_height, status.error
            ),
            Err(err) => eprintln!("⚠️ Epoch advance failed at block {}: {}", next_height, err),
        }
        self.db
            .put("sys:last_epoch_boundary", &next_height.to_string())
            .expect("CRITICAL: the epoch boundary marker write failed");
        self.rotate_validator_epoch(next_height);
        println!("⏳ Epoch advanced at block {}", next_height);
    }

    /// G5 EM-1, EM-2, DL-2: at every reward-period height (h mod R = 0) pay
    /// the emission for the consensus time since the last payout to the
    /// committee of h's epoch, jailed members excluded, each member's weight
    /// split into its own and its pool's part as recorded with the committee.
    /// A payout that aborts is caught up by the next one (Move keeps the time
    /// of the last payout).
    fn maybe_pay_rewards(&self, height: u64) {
        let Some(params) = chain_params(&self.db) else {
            return;
        };
        if height == 0 || !height.is_multiple_of(params.reward_period) {
            return;
        }
        let split =
            self.delegated_split_of_epoch(height.saturating_sub(1) / self.epoch_block_interval());
        let mut members = Vec::new();
        let mut self_weights = Vec::new();
        let mut delegated_weights = Vec::new();
        for (address, stake) in self.paid_committee(height) {
            let Some(member) = parse_move_address(&address) else {
                continue;
            };
            let delegated = split.get(&address).copied().unwrap_or(0).min(stake);
            members.push(member);
            self_weights.push(stake - delegated);
            delegated_weights.push(delegated);
        }
        let action = MoveAction::CallEntryFunction(EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("delegation")
                    .expect("delegation identifier"),
            ),
            function: "pay_rewards".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&system_address()).expect("an address is BCS"),
                bcs::to_bytes(&members).expect("addresses are BCS"),
                bcs::to_bytes(&self_weights).expect("weights are BCS"),
                bcs::to_bytes(&delegated_weights).expect("weights are BCS"),
            ],
        });
        match self.vm.execute_transaction_actions(
            vec![(action, true, system_address())],
            system_address(),
            // At most 256 members (G1 EP-2): a bounded loop.
            20_000_000,
        ) {
            Ok((_gas_used, mut updates, status)) if status.success => {
                self.append_supply_tracker_updates(&mut updates);
                if let Err(err) = self.commit_kv_updates(updates, "reward payout") {
                    eprintln!("🚨 [REWARD_PAYOUT_COMMIT_FAIL] {}", err);
                } else {
                    self.sync_supply_trackers_from_validator_set();
                }
            }
            Ok((_gas_used, _updates, status)) => eprintln!(
                "⚠️ Reward payout aborted at block {}: {:?}",
                height, status.error
            ),
            Err(err) => eprintln!("⚠️ Reward payout failed at block {}: {}", height, err),
        }
        self.settle_offenses(height);
    }

    /// G5 SL-5: every reward period, settle the offenses whose slash fraction
    /// is final (Move `delegation::settle_offenses`).
    fn settle_offenses(&self, height: u64) {
        let action = MoveAction::CallEntryFunction(EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("delegation")
                    .expect("delegation identifier"),
            ),
            function: "settle_offenses".to_string(),
            ty_args: vec![],
            args: vec![bcs::to_bytes(&system_address()).expect("an address is BCS")],
        });
        match self.vm.execute_transaction_actions(
            vec![(action, true, system_address())],
            system_address(),
            // Linear in the offense ledger, which holds each offender once.
            20_000_000,
        ) {
            Ok((_gas_used, mut updates, status)) if status.success => {
                self.append_supply_tracker_updates(&mut updates);
                if let Err(err) = self.commit_kv_updates(updates, "offense settlement") {
                    eprintln!("🚨 [OFFENSE_SETTLEMENT_COMMIT_FAIL] {}", err);
                } else {
                    self.sync_supply_trackers_from_validator_set();
                }
            }
            Ok((_gas_used, _updates, status)) => eprintln!(
                "⚠️ Offense settlement aborted at block {}: {:?}",
                height, status.error
            ),
            Err(err) => eprintln!("⚠️ Offense settlement failed at block {}: {}", height, err),
        }
    }

    /// The committee of epoch E (G1 EP-2): the genesis committee for epoch 0,
    /// the record written at H_{E-1} after. Empty when the chain has none (a
    /// test fixture).
    fn committee_of_epoch(&self, epoch: u64) -> Vec<blockchain::committee::ValidatorInfo> {
        let key = if epoch == 0 {
            "genesis:validator_set:v1".to_string()
        } else {
            format!("sys:validator_set:epoch:{epoch}")
        };
        self.db
            .get(&key)
            .expect("CRITICAL: the committee record could not be read")
            .map(|raw| serde_json::from_str(&raw).expect("CRITICAL: a committee record is corrupt"))
            .unwrap_or_default()
    }

    /// G5 SL-5: what an offense by `validator` in `epoch` weighs, from the
    /// records of that epoch: its weight and delegated part in C_{epoch}, the
    /// committee's total weight and the consensus time the epoch began. None
    /// when the records are gone (older than W, SL-3) or do not hold it.
    fn offense_record(&self, validator: &str, epoch: u64) -> Option<OffenseRecord> {
        let committee = self.committee_of_epoch(epoch);
        let weight = committee.iter().find(|m| m.address == validator)?.stake;
        let committee_weight = committee
            .iter()
            .map(|m| m.stake)
            .fold(0u64, u64::saturating_add);
        let delegated = self
            .delegated_split_of_epoch(epoch)
            .get(validator)
            .copied()
            .unwrap_or(0)
            .min(weight);
        Some(OffenseRecord {
            began: self.epoch_began(epoch)?,
            weight,
            committee_weight,
            delegated,
        })
    }

    /// The consensus time committee epoch `epoch` began: 0 for the genesis
    /// epoch, the tau of its boundary block H_{E-1} after (recorded at
    /// rotation). None once pruned.
    fn epoch_began(&self, epoch: u64) -> Option<u64> {
        if epoch == 0 {
            return Some(0);
        }
        self.db
            .get(&epoch_time_key(epoch))
            .expect("CRITICAL: the epoch time record could not be read")
            .map(|raw| {
                raw.parse()
                    .expect("CRITICAL: an epoch time record is corrupt")
            })
    }

    /// The committee epoch of the executing block, E(h) = (h - 1) / I, from
    /// the clock written before its slashes and transactions (G5 CL-2).
    fn executing_epoch(&self) -> u64 {
        let key = vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock");
        let height = self
            .db
            .get(&key)
            .expect("CRITICAL: the chain clock could not be read")
            .map(|raw| {
                bcs::from_bytes::<ChainClock>(
                    &hex::decode(raw).expect("CRITICAL: chain state is not hex"),
                )
                .expect("CRITICAL: 0x1::chain::Clock is corrupt")
                .height
            })
            .unwrap_or(0);
        height.saturating_sub(1) / self.epoch_block_interval()
    }

    /// G5 DL-1: the delegated part of each member's weight in the committee
    /// of `epoch`, recorded with it (`sys:validator_set:epoch_delegated:{E}`).
    /// Absent (epoch 0, or no member had an open pool): none.
    fn delegated_split_of_epoch(&self, epoch: u64) -> BTreeMap<String, u64> {
        self.db
            .get(&delegated_split_key(epoch))
            .expect("CRITICAL: the delegated-weight record could not be read")
            .map(|raw| {
                serde_json::from_str(&raw).expect("CRITICAL: a delegated-weight record is corrupt")
            })
            .unwrap_or_default()
    }

    /// G5 DL-1: at the boundary, before the next committee is derived, set
    /// every live member's weight in `sys:validator_set:v1` (and the
    /// `sys:validators` mirror) to its bonded stake: its own stake in the
    /// Move ValidatorSet plus its open pool's active principal, in whole AIN.
    /// A delegation therefore weighs the committee from the next epoch, never
    /// inside one. Returns the delegated part per member. A member the Move
    /// set does not hold (only a test fixture) keeps its weight and adds no
    /// delegation.
    fn refresh_bonded_weights(&self) -> BTreeMap<String, u64> {
        let mut delegated = BTreeMap::new();
        let Some(mut live) = self
            .db
            .get(validator_set_v1_key())
            .expect("CRITICAL: the live validator set could not be read")
            .and_then(|raw| serde_json::from_str::<Vec<ValidatorSetV1Entry>>(&raw).ok())
        else {
            return delegated;
        };
        let own: BTreeMap<move_core_types::account_address::AccountAddress, u128> = self
            .db
            .get(&validator_set_key())
            .expect("CRITICAL: the Move validator set could not be read")
            .and_then(|raw| decode_validator_set_hex(&raw))
            .map(|set| {
                set.validators
                    .into_iter()
                    .map(|v| (v.validator_addr, v.stake.value))
                    .collect()
            })
            .unwrap_or_default();
        let mut bonded = BTreeMap::new();
        for entry in live.iter_mut() {
            let Some(own_stake) = parse_move_address(&entry.address).and_then(|a| own.get(&a))
            else {
                continue;
            };
            let pool = delegated_weight(&self.db, &entry.address);
            if pool > 0 {
                delegated.insert(entry.address.clone(), pool);
            }
            let weight = u64::try_from(own_stake / COIN_SCALE)
                .unwrap_or(u64::MAX)
                .saturating_add(pool);
            if entry.stake != weight {
                entry.stake = weight;
                bonded.insert(entry.address.clone(), weight);
            }
        }
        if bonded.is_empty() {
            return delegated;
        }
        self.db
            .put(
                validator_set_v1_key(),
                &serde_json::to_string(&live).expect("the live set is JSON"),
            )
            .expect("CRITICAL: the live validator set write failed");
        if let Some(mut mirror) = self
            .db
            .get("sys:validators")
            .expect("CRITICAL: the validator mirror could not be read")
            .and_then(|raw| serde_json::from_str::<Vec<(String, u64)>>(&raw).ok())
        {
            let mut changed = false;
            for (address, stake) in mirror.iter_mut() {
                if let Some(weight) = bonded.get(address) {
                    *stake = *weight;
                    changed = true;
                }
            }
            if changed {
                self.db
                    .put(
                        "sys:validators",
                        &serde_json::to_string(&mirror).expect("the mirror is JSON"),
                    )
                    .expect("CRITICAL: the validator mirror write failed");
            }
        }
        delegated
    }

    /// G5 EM-2: who is paid for block `height`: the members of the committee
    /// C_{E(height)} with their committee stake, never the live set; jailed
    /// members and zero stake excluded.
    fn paid_committee(&self, height: u64) -> Vec<(String, u64)> {
        let epoch = height.saturating_sub(1) / self.epoch_block_interval();
        self.committee_of_epoch(epoch)
            .into_iter()
            .filter(|m| m.stake > 0)
            .filter(|m| {
                self.db
                    .get(&format!("validator:jailed:{}", m.address))
                    .expect("CRITICAL: the jail record could not be read")
                    .is_none()
            })
            .map(|m| (m.address, m.stake))
            .collect()
    }

    /// G1 EP-2 / G5 EM-2: at the boundary H_E, record the committee of E+1 as
    /// `sys:validator_set:epoch:{E+1}`: the live set (`sys:validator_set:v1`,
    /// this block's post-state) if it is a valid committee, C_E otherwise.
    /// Consensus derives its committee with the same function from the same
    /// inputs and refuses a boundary block whose record differs; rewards and
    /// fees pay this record. Runs on both the consensus and the sync
    /// block-apply paths, inside the block transaction.
    fn rotate_validator_epoch(&self, boundary_height: u64) {
        let interval = self.epoch_block_interval();
        if interval == 0 {
            return;
        }
        let new_epoch = boundary_height / interval;

        let delegated = self.refresh_bonded_weights();
        let current = self.committee_of_epoch(new_epoch.saturating_sub(1));
        let proposed: Vec<blockchain::committee::ValidatorInfo> = self
            .db
            .get("sys:validator_set:v1")
            .expect("CRITICAL: the live validator set could not be read")
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        let (next, invalid) = blockchain::committee::next_committee(&current, &proposed);
        if let Some(why) = &invalid {
            eprintln!(
                "🚨 [COMMITTEE_INVALID] epoch {new_epoch} keeps the previous committee: {why}"
            );
        }
        self.db
            .put(
                &format!("sys:validator_set:epoch:{}", new_epoch),
                &serde_json::to_string(&next).expect("a committee is JSON"),
            )
            .expect("CRITICAL: the committee record write failed");
        // G5 DL-1: the delegated part of each member's weight, recorded with
        // the committee for its payouts. A kept committee keeps its split.
        let split: BTreeMap<String, u64> = if invalid.is_some() {
            self.delegated_split_of_epoch(new_epoch.saturating_sub(1))
        } else {
            next.iter()
                .filter_map(|m| {
                    delegated
                        .get(&m.address)
                        .map(|d| (m.address.clone(), (*d).min(m.stake)))
                })
                .collect()
        };
        if !split.is_empty() {
            self.db
                .put(
                    &delegated_split_key(new_epoch),
                    &serde_json::to_string(&split).expect("a split is JSON"),
                )
                .expect("CRITICAL: the delegated-weight record write failed");
        }
        let _ = self.db.put("consensus:epoch", &new_epoch.to_string());
        let _ = self.db.put(
            &format!("consensus:epoch_start_height:{}", new_epoch),
            &boundary_height.saturating_add(1).to_string(),
        );
        let now = committed_chain_clock(&self.db).time;
        self.db
            .put(&epoch_time_key(new_epoch), &now.to_string())
            .expect("CRITICAL: the epoch time record write failed");

        // G5 SL-3: keep an epoch's committee, split and start time while
        // evidence of it can still be accepted (tau <= tau_start(E+1) + W), and
        // at least the last 8 epochs, so slightly-behind nodes can still verify
        // QCs from recent epochs. The walk is bounded per boundary.
        const EPOCH_SNAPSHOT_RETENTION: u64 = 8;
        const MAX_PRUNED_PER_BOUNDARY: u64 = 64;
        let mut oldest = self
            .db
            .get(RETAINED_FROM_KEY)
            .expect("CRITICAL: the retention record could not be read")
            .map(|raw| {
                raw.parse::<u64>()
                    .expect("CRITICAL: the retention record is corrupt")
            })
            .unwrap_or(0);
        let from = oldest;
        while oldest + EPOCH_SNAPSHOT_RETENTION < new_epoch
            && oldest - from < MAX_PRUNED_PER_BOUNDARY
            && self
                .epoch_began(oldest + 1)
                .is_some_and(|next| next.saturating_add(EVIDENCE_MAX_AGE_SECS) < now)
        {
            let _ = self
                .db
                .delete(&format!("sys:validator_set:epoch:{}", oldest));
            let _ = self.db.delete(&delegated_split_key(oldest));
            let _ = self.db.delete(&epoch_time_key(oldest));
            let _ = self
                .db
                .delete(&format!("consensus:epoch_start_height:{}", oldest));
            oldest += 1;
        }
        if oldest != from {
            self.db
                .put(RETAINED_FROM_KEY, &oldest.to_string())
                .expect("CRITICAL: the retention record write failed");
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
        let _ = self.logged_put(
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
                    let _ = self.logged_put(&key, &encoded);
                }
            }
        }

        // AUDIT-#8 (BTC mint-cap): the Move emission anchor now keys off
        // cumulative MINTED = ValidatorSet.total_supply + SupplyStats.cumulative_burned
        // (staking.move::distribute_rewards). This Rust-native fee burn just
        // decremented total_supply by `amount`; credit the SAME `amount` into the
        // Move SupplyStats resource (lazy-create if absent) so `minted` stays
        // invariant and burnt fees can NEVER be re-minted as fresh emission.
        // WITHOUT this, the fee-burn path silently re-opens finding #8 — exactly
        // the hole the adversarial verifiers caught in the "minimal" hybrid.
        // `amount` matches the convention used for `total_burned` above (both use
        // the requested amount; total_supply's saturating_sub only differs in the
        // impossible case total_supply < a single block's burnt fees).
        let stats_key = supply_stats_key();
        let prev_move_burned = self
            .db
            .get(&stats_key)
            .ok()
            .flatten()
            .and_then(|v| decode_supply_stats_hex(&v))
            .map(|s| s.cumulative_burned)
            .unwrap_or(0);
        let updated_stats = MoveSupplyStats {
            cumulative_burned: prev_move_burned.saturating_add(amount),
        };
        if let Some(encoded) = encode_supply_stats_hex(&updated_stats) {
            let _ = self.logged_put(&stats_key, &encoded);
        }
    }

    /// Phase 4.A1: Compute stake-proportional block reward payouts.
    ///
    /// Splits `total_reward` between:
    ///   - 20% anchor-leader bonus → `anchor_leader`
    ///   - 80% stake-weighted pool → every member of `committee`, the block's
    ///     paid committee (G5 EM-2: C_{E(h)} without jailed members, never
    ///     the live set)
    ///
    /// The leader still receives any pool share they're entitled to from
    /// their own stake (so a high-stake leader gets bonus + pool share).
    ///
    /// Rounding remainder (from integer division) is given to anchor_leader
    /// so the reward is fully consumed and never lost.
    ///
    /// Fallback: if the committee is empty, ALL goes to the leader.
    fn compute_block_payouts(
        anchor_leader: &str,
        total_reward: u128,
        validators: &[(String, u64)],
    ) -> Vec<(String, u128)> {
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

        for (addr, stake) in validators {
            let share = pool.saturating_mul(*stake as u128) / total_stake;
            distributed_pool = distributed_pool.saturating_add(share);
            *payouts.entry(addr.clone()).or_insert(0) = payouts
                .get(addr)
                .copied()
                .unwrap_or(0)
                .saturating_add(share);
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
                system_address(), // auth_signer: deposit_fee_reward asserts @0x1
            )
            .map_err(|e| e.to_string())?;

        for (k, v) in vm_changes {
            match v {
                Some(val) => self.logged_put(&k, &val).map_err(|e| e.to_string())?,
                None => self.logged_delete(&k).map_err(|e| e.to_string())?,
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
            let _ = self.logged_put(&sweep_key, &json);
        }
    }

    fn process_fee_sweep_queue(&self) {
        // M-06 FIX: bound the scan at the storage layer rather than relying on
        // a downstream `.take(25)` that would otherwise materialise the entire
        // queue into a Vec first. The cap of 25 matches the original drain rate.
        let sweep_keys: Vec<_> = self.db.scan_prefix_limited("sys:fee_sweep_queue:", 25);

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
                    let _ = self.logged_delete(&key);
                    continue;
                }
            };

            match self.deposit_fee_reward(&entry.miner, amount) {
                Ok(()) => {
                    let _ = self.logged_delete(&key);
                    println!(
                        "✅ Fee sweep recovered {} AIN for miner {}",
                        amount, entry.miner
                    );
                }
                Err(e) => {
                    entry.attempts = entry.attempts.saturating_add(1);
                    if let Ok(json) = serde_json::to_string(&entry) {
                        let _ = self.logged_put(&key, &json);
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
    /// Back-compat wrapper: derives the height from storage. Production block
    /// paths (dag commit loop, chain sync) must use
    /// [`Self::execute_block_parallel_at`] with the EXPLICIT height of the block
    /// being executed — see that method's doc for why.
    /// Highest height whose execution has been consumed. Falls back to the
    /// chain height for a chain that predates the marker.
    pub fn last_executed_height(&self) -> u64 {
        self.db
            .get("sys:last_executed_height")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or_else(|| self.db.get_chain_height())
    }

    /// Test convenience: execute the next height in order, at the previous
    /// block's timestamp (no consensus time passes). Production
    /// consensus/sync paths call [`Self::execute_block_admitted_at`] with the
    /// block's own height and timestamp.
    #[cfg(test)]
    pub fn execute_block_parallel(
        &self,
        txs_json: Vec<String>,
        proposer_hex: &str,
    ) -> BlockExecutionSummary {
        let height = self.last_executed_height().saturating_add(1);
        let timestamp = next_chain_clock(&self.db, height, 0).block_timestamp;
        match self.execute_block_parallel_at(txs_json, proposer_hex, height, timestamp, &[]) {
            BlockExecOutcome::Executed(summary) => summary,
            other => {
                eprintln!("⚠️ execute_block_parallel: {:?} — returning current roots", other);
                BlockExecutionSummary {
                    state_root: self.current_state_root(),
                    receipts_root: self.receipts_root_for_block(&[]),
                    gas_charged: 0,
                    executed_raws: Vec::new(),
                    tx_count: 0,
                }
            }
        }
    }

    /// AUDIT-B4b (epoch determinism): execute a block's transactions AS the
    /// given height. The height must be the height of the block being
    /// executed/built — NOT re-read from storage at execution time.
    ///
    /// Why: the epoch boundary (staking emission, validator rotation,
    /// governance) fires as a function of the executing block's height. It used
    /// to be derived from `get_chain_height()+1` INSIDE execution, i.e. from
    /// mutable global state — so when a ChainSync import and a local commit
    /// interleaved, a node could fire a boundary twice or skip it entirely.
    /// Observed live on the 4-validator harness: epoch counts of 12 / 11 / 14
    /// on three nodes over the SAME deterministic block sequence, minting
    /// different rewards and diverging every state root from the first
    /// tx-bearing block onward. Height-as-parameter makes the boundary a pure
    /// function of the block, and the persisted `sys:last_epoch_boundary`
    /// marker makes each boundary fire exactly once per node.
    ///
    /// G5 CL-2: `block_timestamp` is the block's BFT timestamp (its header),
    /// which drives consensus time.
    pub fn execute_block_parallel_at(
        &self,
        txs_json: Vec<String>,
        proposer_hex: &str,
        block_height: u64,
        block_timestamp: u64,
        // RE-AUDIT HIGH: slash evidence CARRIED BY THE BLOCK (see apply_slash_evidence).
        slash_evidence: &[String],
    ) -> BlockExecOutcome {
        self.execute_block_checked_at(
            txs_json,
            proposer_hex,
            block_height,
            block_timestamp,
            slash_evidence,
            |_, _| Ok(()),
        )
        .expect("block state transaction failed; no execution result may be published")
    }

    /// Stage execution, validate its result, and stage acceptance metadata before
    /// ONE durable write. `accept` must use only its supplied view for DB writes.
    /// Returning Err discards state, receipts, height, and acceptance writes.
    /// Callers remain responsible for authenticating the block and its parent.
    pub fn execute_block_checked_at(
        &self,
        txs_json: Vec<String>,
        proposer_hex: &str,
        block_height: u64,
        block_timestamp: u64,
        slash_evidence: &[String],
        accept: impl FnOnce(&BlockExecutionSummary, &StateDB) -> Result<(), String>,
    ) -> Result<BlockExecOutcome, String> {
        self.execute_block_admitted_at(
            txs_json,
            proposer_hex,
            block_height,
            block_timestamp,
            slash_evidence,
            |_| Ok(()),
            accept,
        )
    }

    /// Revalidate admission on the writer-gated PRE-execution view, then stage
    /// execution and acceptance in that same transaction. `admit` must only read
    /// its supplied view; it must not use a captured base DB or mutate state.
    /// Neither callback may write through a captured base DB (writer deadlock).
    /// A prior network precheck is only an optimization, not admission authority.
    #[allow(clippy::too_many_arguments)] // the block (content, height, timestamp, evidence) and its two checks are intrinsic
    pub fn execute_block_admitted_at(
        &self,
        txs_json: Vec<String>,
        proposer_hex: &str,
        block_height: u64,
        block_timestamp: u64,
        slash_evidence: &[String],
        admit: impl FnOnce(&StateDB) -> Result<(), String>,
        accept: impl FnOnce(&BlockExecutionSummary, &StateDB) -> Result<(), String>,
    ) -> Result<BlockExecOutcome, String> {
        // SECURITY FIX: Acquire block-level lock to serialize state root calculation.
        // Individual transactions within a block still run in parallel (via Rayon),
        // but two DIFFERENT blocks cannot execute concurrently.
        // Keep poison detection fail-closed. Staging now discards execution writes
        // on unwind, but this is not an automatic repair of pre-existing torn DBs.
        let _block_lock = BLOCK_EXECUTION_LOCK
            .lock()
            .expect("block execution lock poisoned; partial state requires recovery");

        // Rebuild the VM on the private view, so module caches and ALL helper
        // reads/writes (including governance) belong to this speculative block.
        // The block transaction is the only place consensus state may be
        // written (G3 WG-1); in S0 the mark only feeds the storage observer.
        let outcome = self
            .db
            .block_transaction(|view| {
                admit(&view).map_err(storage::StorageError::DatabaseOperation)?;
                let executor = Executor::new(view.clone());
                #[cfg(test)]
                let executor = Executor {
                    block_boundary_hook: self.block_boundary_hook,
                    ..executor
                };
                let outcome = executor.execute_block_staged_at(
                    txs_json,
                    proposer_hex,
                    block_height,
                    block_timestamp,
                    slash_evidence,
                );
                if let BlockExecOutcome::Executed(summary) = &outcome {
                    accept(summary, &view).map_err(storage::StorageError::DatabaseOperation)?;
                }
                Ok(outcome)
            })
            .map_err(|error| error.to_string())?;
        #[cfg(test)]
        if let Some(hook) = self.block_boundary_hook {
            hook(4, &self.db);
        }
        if matches!(outcome, BlockExecOutcome::Executed(_)) {
            println!("Execution state committed at height {}", block_height);
        }
        Ok(outcome)
    }

    // Only called with BLOCK_EXECUTION_LOCK and the storage writer gate held.
    // This function sees its own staged writes; none are durable until the
    // transaction driver publishes the complete result with one synced batch.
    fn execute_block_staged_at(
        &self,
        txs_json: Vec<String>,
        proposer_hex: &str,
        block_height: u64,
        block_timestamp: u64,
        slash_evidence: &[String],
    ) -> BlockExecOutcome {

        // STRICT HEIGHT ORDER (see BlockExecOutcome). Checked INSIDE the lock and
        // paired with the marker write at the end of this function, so the
        // check-then-execute is atomic against the other execution path.
        let last_executed = self.last_executed_height();
        if block_height <= last_executed {
            println!(
                "⏭️  Height {} already executed (last_executed={}) — refusing to execute twice",
                block_height, last_executed
            );
            return BlockExecOutcome::AlreadyExecuted { last_executed };
        }
        if block_height > last_executed.saturating_add(1) {
            eprintln!(
                "🚨 [SECURITY][EXEC_GAP] refusing to execute height {} with last_executed={} \
                 — executing out of order would corrupt the state-root chain",
                block_height, last_executed
            );
            return BlockExecOutcome::Gap {
                expected: last_executed.saturating_add(1),
                got: block_height,
            };
        }

        println!(
            "🚀 Starting Parallel Execution for {} transactions...",
            txs_json.len()
        );

        // 0. PROTOCOL: apply block-carried slash evidence FIRST, before any
        //    transaction, so apply-time verification sees the SAME parent-state
        //    snapshot the block builder verified against. It used to run after
        //    the tx loop, where a leave_validator_set tx in the same block could
        //    remove the offender and let the slash silently fail while the block
        //    still committed to the item.
        //
        //    Every write it makes is staged in the block transaction, and the
        //    state root at the end covers all of them (G3 CM-1).
        //
        // G3 S3: version 0 of the state tree is written by genesis itself
        // (`commit_genesis`), so block 1 applies on top of it like any block.
        #[cfg(test)]
        if let Some(hook) = self.block_boundary_hook {
            hook(0, &self.db);
        }
        // G5 CL-2: the height and consensus time of this block, before
        // anything of it runs, so every deadline a transaction or a system
        // call checks is this block's.
        self.write_chain_clock(block_height, block_timestamp);
        self.apply_slash_evidence(slash_evidence);

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

        // GATE-CRITICAL (pre-mainnet): MAX_GAS_LIMIT bounds ONE transaction;
        // nothing bounded a BLOCK. A proposer (or an attacker filling the
        // mempool) could pack a block with transactions each at the per-tx
        // ceiling, and every validator would execute the sum deterministically,
        // with no wall-clock timeout — the same halt, reached by volume instead
        // of by a single huge transaction.
        //
        // The trim is deterministic: it walks the block's transactions in their
        // fixed order and stops at the first one that would cross the ceiling,
        // so every node keeps byte-identical prefix and computes the same state
        // root. Trimming (rather than rejecting the whole block) keeps a
        // malicious proposer from halting the chain by making blocks nobody can
        // execute.
        let parsed_txs = {
            let mut kept = Vec::with_capacity(parsed_txs.len());
            let mut budget: u64 = 0;
            let mut dropped = 0usize;
            for tx in parsed_txs.into_iter() {
                let cost = tx.0.gas_limit;
                // GATE-CRITICAL: budget on a VALIDATED gas_limit. `gas_limit` is
                // an attacker-declared field, and the per-tx ceiling is enforced
                // later, inside execution. Budgeting on the raw value let one
                // transaction declaring an absurd gas_limit consume the entire
                // block budget and push every honest transaction out — free,
                // deterministic censorship, and free block-space reservation,
                // since the transaction is then rejected and never pays. A
                // transaction over the per-tx ceiling cannot execute at all, so
                // it is skipped here without charging the block for it.
                if cost > MAX_GAS_LIMIT {
                    dropped += 1;
                    continue;
                }
                if budget.saturating_add(cost) > MAX_BLOCK_GAS_LIMIT {
                    dropped += 1;
                    continue;
                }
                budget = budget.saturating_add(cost);
                kept.push(tx);
            }
            if dropped > 0 {
                println!(
                    "✂️  block gas ceiling: kept {} tx ({} gas), dropped {} over MAX_BLOCK_GAS_LIMIT {}",
                    kept.len(),
                    budget,
                    dropped,
                    MAX_BLOCK_GAS_LIMIT
                );
            }
            kept
        };

        // 2. Build Dependency Graph & Schedule (see schedule_batches — unknown
        //    write sets are serialized into singleton batches, #1).
        let batches = self.schedule_batches(parsed_txs);
        println!("📊 Scheduled {} execution batches.", batches.len());

        // 3. Execute Batches ATOMICALLY
        let mut total_fees: u128 = 0;

        let mut executed_raws: Vec<String> = Vec::new();
        // (write log already armed at step 0, before apply_slash_evidence)
        // AUDIT-B4b (root determinism): the state root used to be chained ONCE
        // PER EXECUTION BATCH, which made it a function of how the conflict
        // scheduler happened to PARTITION the block — and that partitioning is
        // not canonical across nodes. Observed live: identical blocks, identical
        // final balances on every node, different "state roots" (NAS f7d88fef vs
        // PI 4de15e88 at height 69). The root now folds ONCE PER BLOCK over the
        // block's EFFECTIVE writes (last-write-wins across batches), sorted by
        // key — a pure function of the block's outcome, immune to partitioning.
        // Seeded with the step-0 slash writes so a later tx write to the same
        // key correctly wins (matching RocksDB's actual ordering).

        for batch in batches.iter() {
            // Execute in parallel to get updates
            #[allow(clippy::type_complexity)] // intrinsic to parallel TX result shape
            let mut results: Vec<(
                String,
                String,
                Option<(Vec<(String, Option<String>)>, u128)>,
            )> = batch
                .par_iter()
                .map(|(_tx, raw)| (tx_hash_hex(raw), raw.clone(), self.execute_transaction(raw)))
                .collect();
            results.sort_by(|left, right| left.0.cmp(&right.0));

            // 4. Commit Batch Atomically
            let mut write_batch = WriteBatch::default();

            // AUDIT-B2 safety net: two transactions in ONE parallel batch writing
            // the same key is, by construction, a conflict-token miss — both read
            // pre-batch state, and this loop's last-write-wins silently erases one
            // of them. That is exactly how the unbounded-mint bug worked. The
            // scheduler is supposed to make this impossible; if it ever happens
            // again (a new stdlib call path, a moved function), surface it loudly
            // instead of silently corrupting state. Keyed by tx_hash so a single
            // tx overwriting its own key across staged sessions is not flagged.
            let mut writer_of_key: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            for (tx_hash, raw_tx, res) in results {
                if let Some((mut updates, gas_charged)) = res {
                    executed_raws.push(raw_tx);
                    updates.sort_by(|left, right| left.0.cmp(&right.0));
                    for (key, val_opt) in updates {
                        if let Some(prev_writer) = writer_of_key.get(&key) {
                            if prev_writer != &tx_hash {
                                eprintln!(
                                    "🚨 [SECURITY][BATCH_CONFLICT] key {} written by two txs in one \
                                     parallel batch ({} and {}) — analyze_tx is missing a conflict \
                                     token for this path; one write is being lost",
                                    key, prev_writer, tx_hash
                                );
                            }
                        } else {
                            writer_of_key.insert(key.clone(), tx_hash.clone());
                        }
                        if let Some(val) = val_opt {
                            write_batch.put(key.as_bytes(), val.as_bytes());
                        } else {
                            write_batch.delete(key.as_bytes());
                        }
                    }
                    total_fees = total_fees.saturating_add(gas_charged); // C-6 FIX: accumulate gas (saturating — defense-in-depth)
                }
            }

            // Later batches read these staged writes through the same view.
            if let Err(e) = self.db.write_batch(write_batch) {
                eprintln!("❌ FATAL: RocksDB Write Batch Failed: {}", e);
                panic!(
                    "CRITICAL: database write failure - stopping node to prevent state corruption."
                );
            }
            #[cfg(test)]
            if let Some(hook) = self.block_boundary_hook {
                hook(1, &self.db);
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

        let burnt_fees = total_fees_u128.saturating_mul(burn_pct) / 100;
        let miner_fees = total_fees_u128.saturating_sub(burnt_fees);

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
        let miner_addr = if proposer_hex.len() > crypto::ADDRESS_HEX_LEN {
            &proposer_hex[0..crypto::ADDRESS_HEX_LEN]
        } else {
            proposer_hex
        };

        if reward_amount > 0 {
            let payouts = Self::compute_block_payouts(
                miner_addr,
                reward_amount,
                &self.paid_committee(block_height),
            );

            println!(
                "💰 Distributing Block Fees ({} AIN total) across {} recipient(s)",
                reward_amount,
                payouts.len()
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
                    // G3 FX-4: keyed by the EXECUTING height, not `latest_height`
                    // (chain data read into a state key name).
                    self.queue_fee_sweep(recipient, *share, block_height);
                    eprintln!("🔴 Reward queued for sweep: {} AIN → {}", share, recipient);
                }
            }
        }

        // 6. Recover queued fee rewards whose recipient CoinStore is now valid.
        self.process_fee_sweep_queue();

        // 7. Promote downtime attestations to pending slashes when distinct
        //    reporters reach BFT quorum (Phase 2.3 / H-02). Equivocation
        //    slashes are written directly by the consensus equivocation
        //    detector and bypass this step.
        // 7. Slash evidence was applied at step 0 (parent-state snapshot).

        // 8. Advance Move epoch on a deterministic block interval, AS the block
        // being executed (see execute_block_parallel_at doc).
        // G5 EM-3: the reward payout for (h - R, h] pays C_{E(h)} before a
        // boundary block records C_{E+1}.
        self.maybe_pay_rewards(block_height);
        self.maybe_advance_epoch(block_height);

        // G3 CM-1/CM-2: the state root is the Jellyfish Merkle root over EVERY
        // consensus-state key. The change set is whatever this block staged,
        // including writes that never went through a log (epoch rotation,
        // governance, the burn path), diffed against version h-1. After the
        // root is computed the stage is sealed: a later state write would
        // escape the root, so it fails the whole block at commit.
        let changes = self
            .db
            .staged_state_changes()
            .expect("CRITICAL: a block must execute inside its block transaction");
        let applied = state_commit::apply(&self.db, block_height, changes).unwrap_or_else(|e| {
            panic!("CRITICAL: state tree apply failed at height {block_height}: {e}")
        });
        if let Err(e) = self.db.write_batch(applied.batch) {
            panic!("CRITICAL: state tree write failed at height {block_height}: {e}");
        }
        assert!(
            self.db.seal_state(),
            "CRITICAL: state root computed outside the block transaction"
        );
        let state_root = hex::encode(applied.root.0);
        #[cfg(test)]
        if let Some(hook) = self.block_boundary_hook {
            hook(2, &self.db);
        }
        // Staged with the root and all state writes, not a separate durable put.
        if let Err(e) = self
            .db
            .put("sys:last_executed_height", &block_height.to_string())
        {
            eprintln!("❌ FATAL: last_executed_height persist failed: {}", e);
            panic!("CRITICAL: database write failure - stopping node to prevent state corruption.");
        }
        #[cfg(test)]
        if let Some(hook) = self.block_boundary_hook {
            hook(3, &self.db);
        }

        let summary = BlockExecutionSummary {
            state_root,
            receipts_root: self.receipts_root_for_block(&txs_json),
            gas_charged: total_fees,
            executed_raws,
            tx_count: txs_json.len(),
        };

        println!(
            "Parallel Execution Prepared. state_root={} receipts_root={}",
            short_hash(&summary.state_root),
            short_hash(&summary.receipts_root)
        );
        BlockExecOutcome::Executed(summary)
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
    ///
    /// NOT LIVE (protocol v2): nothing on the block path calls this. Downtime
    /// slashing has no deterministic DAG producer and is filtered out of
    /// block-carried evidence (only "equivocation" is ordered through the DAG).
    /// Retained, with its tests, for a future deterministic downtime protocol.
    pub fn promote_downtime_attestations_to_slash(&self) {
        // 1. Snapshot the active validator set so quorum is computed
        //    against a stable set within this routine.
        let validator_stakes: Vec<(String, u64)> = match self.db.get("sys:validators") {
            Ok(Some(json)) => match serde_json::from_str::<Vec<(String, u64)>>(&json) {
                Ok(vs) => vs,
                Err(_) => return,
            },
            _ => return,
        };
        if validator_stakes.is_empty() {
            return;
        }
        // SEC-#17: gate on STAKE-weighted quorum (the chain-wide >2/3-stake
        // threshold used by QC / DAG-parent / commit) — NOT validator COUNT — so a
        // swarm of tiny-stake validators cannot reach quorum to slash a large
        // honest one. (Predicate inlined: executor cannot depend on `consensus`.)
        use std::collections::HashMap;
        let stake_by_addr: HashMap<&str, u64> = validator_stakes
            .iter()
            .map(|(a, s)| (a.as_str(), *s))
            .collect();
        let total_stake: u128 = validator_stakes.iter().map(|(_, s)| *s as u128).sum();

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
            if !stake_by_addr.contains_key(reporter.as_str()) {
                continue;
            }

            groups
                .entry((offender, epoch))
                .or_default()
                .insert(reporter);
        }

        // 4. Promote groups that hit BFT quorum.
        for ((offender, epoch), reporters) in groups {
            // Sum distinct in-set reporter stake; require >2/3 of total stake
            // (mirrors consensus::qc::stake_quorum_met: signed*3 > total*2).
            let reporter_stake: u128 = reporters
                .iter()
                .map(|r| *stake_by_addr.get(r.as_str()).unwrap_or(&0) as u128)
                .sum();
            if reporter_stake.saturating_mul(3) <= total_stake.saturating_mul(2) {
                continue;
            }

            // Phase 5C.3 / NEW-002 (SEC-N03 reverse hole): the
            // attest-time check on dag.rs only validates `offender`
            // against the validator set AT THE TIME OF ATTESTATION
            // RECEIVE. If the offender voluntarily unbonds or is
            // governance-removed between attest and promote, they
            // could be slashed despite no longer being a validator.
            // Re-check offender ∈ current validator_set here.
            if !stake_by_addr.contains_key(offender.as_str()) {
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
                "reporter_stake": reporter_stake.to_string(),
                "total_stake": total_stake.to_string(),
                "reason": "downtime",
                "penalty": "5% slash + 21-day unbonding"
            });

            // Queue the real slash and the jail marker.
            let _ = self.logged_put(
                &format!("sys:pending_slash:{}", offender),
                &slash_event.to_string(),
            );
            let _ = self.logged_put(
                &jail_key,
                &serde_json::to_string(&reporters).unwrap_or_default(),
            );

            // Drop the attestations for this (offender, epoch) to free
            // storage and prevent re-promotion. We only drop the
            // promoted group; attestations for OTHER offenders or
            // future epochs are untouched.
            let prefix = format!("sys:downtime_attestation:{}:{}:", offender, epoch);
            for (key, _) in self.db.scan_prefix(&prefix) {
                let _ = self.logged_delete(&key);
            }

            println!(
                "⛓️  Stake-quorum downtime slash queued for {} (reporters={}, reporter_stake={}/{} total)",
                offender,
                reporters.len(),
                reporter_stake,
                total_stake
            );
        }
    }

    /// Verify ONE evidence item against on-chain data only. Returns
    /// (offender, reason, round_or_epoch) on success. Pure.
    pub fn verify_slash_evidence(&self, item: &str) -> Result<VerifiedEvidence, String> {
        use std::collections::{BTreeMap, BTreeSet};
        let ev: serde_json::Value =
            serde_json::from_str(item).map_err(|e| format!("bad json: {e}"))?;
        if ev.get("kind").and_then(|k| k.as_str()) == Some("equivocation_v4") {
            return self.verify_v4_twins(&ev);
        }
        let validators: Vec<(String, u64)> = self
            .db
            .get("sys:validators")
            .ok()
            .flatten()
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();
        let stake: BTreeMap<&str, u64> = validators.iter().map(|(a, s)| (a.as_str(), *s)).collect();
        let total: u128 = validators.iter().map(|(_, s)| *s as u128).sum();
        let offender = ev.get("offender").and_then(|v| v.as_str()).ok_or("missing offender")?.to_string();
        if !stake.contains_key(offender.as_str()) {
            return Err(format!("offender {offender} not in validator set"));
        }
        let pubkey_of = |addr: &str| -> Option<String> {
            self.db.get_object(addr)
                .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.data).ok())
                .and_then(|v| v.get("public_key").and_then(|k| k.as_str()).map(String::from))
        };
        match ev.get("kind").and_then(|v| v.as_str()) {
            Some("equivocation") => {
                let round = ev
                    .get("round")
                    .and_then(|v| v.as_u64())
                    .ok_or("missing round")?;
                let a: blockchain::Vertex =
                    serde_json::from_value(ev.get("vertex_a").cloned().unwrap_or_default())
                        .map_err(|e| format!("vertex_a: {e}"))?;
                let b: blockchain::Vertex =
                    serde_json::from_value(ev.get("vertex_b").cloned().unwrap_or_default())
                        .map_err(|e| format!("vertex_b: {e}"))?;
                if a.author != offender || b.author != offender {
                    return Err("author != offender".into());
                }
                if a.round != round || b.round != round {
                    return Err("round mismatch".into());
                }
                if a.hash == b.hash {
                    return Err("identical vertices are not equivocation".into());
                }
                // A V3 proof carries no epoch: the V3 hash does not bind one.
                if a.epoch != 0 || b.epoch != 0 {
                    return Err("a V3 proof carrying an epoch".into());
                }
                if a.calculate_hash() != a.hash || b.calculate_hash() != b.hash {
                    return Err("vertex hash does not match body".into());
                }
                let pk = pubkey_of(&offender).ok_or("offender pubkey unresolvable")?;
                if !a.verify_ed25519_signature(&pk) || !b.verify_ed25519_signature(&pk) {
                    return Err("vertex signature invalid".into());
                }
                Ok(VerifiedEvidence {
                    offender,
                    kind: "equivocation".into(),
                    epoch: self.executing_epoch(),
                    round,
                })
            }
            Some("downtime") => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let epoch = ev.get("epoch").and_then(|v| v.as_u64()).ok_or("missing epoch")?;
                let atts = ev.get("attestations").and_then(|v| v.as_array()).ok_or("missing attestations")?;
                let mut reporters: BTreeSet<String> = BTreeSet::new();
                for a in atts {
                    let off = a.get("offender").and_then(|v| v.as_str()).ok_or("att: offender")?;
                    let ep = a.get("epoch").and_then(|v| v.as_u64()).ok_or("att: epoch")?;
                    let rep = a.get("reporter").and_then(|v| v.as_str()).ok_or("att: reporter")?;
                    let round = a.get("round").and_then(|v| v.as_u64()).ok_or("att: round")?;
                    let pk_hex = a.get("reporter_pubkey").and_then(|v| v.as_str()).ok_or("att: pubkey")?;
                    let sig_hex = a.get("signature").and_then(|v| v.as_str()).ok_or("att: signature")?;
                    if off != offender || ep != epoch { return Err("attestation does not match item".into()); }
                    if !stake.contains_key(rep) { continue; } // not a validator: does not count
                    let pk_bytes = hex::decode(pk_hex).map_err(|_| "att: pubkey hex")?;
                    let derived = crypto::derive_address(&pk_bytes).map_err(|e| format!("att: derive: {e}"))?;
                    if derived != rep { return Err("att: pubkey does not derive to reporter".into()); }
                    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| "att: pubkey len")?;
                    let vk = VerifyingKey::from_bytes(&pk_arr).map_err(|_| "att: pubkey")?;
                    let sig_bytes = hex::decode(sig_hex).map_err(|_| "att: sig hex")?;
                    let sig = Signature::from_slice(&sig_bytes).map_err(|_| "att: sig")?;
                    // Same canonical preimage as DagConsensus::broadcast_attestation.
                    let canonical = format!("{}:{}:{}:{}", off, ep, rep, round);
                    vk.verify(canonical.as_bytes(), &sig).map_err(|_| "att: signature invalid")?;
                    reporters.insert(rep.to_string());
                }
                let rs: u128 = reporters.iter().filter_map(|r| stake.get(r.as_str()).map(|s| *s as u128)).sum();
                if rs.saturating_mul(3) <= total.saturating_mul(2) {
                    return Err(format!("downtime quorum not met: {rs}/{total}"));
                }
                Ok(VerifiedEvidence {
                    offender,
                    kind: "downtime".into(),
                    epoch,
                    round: epoch,
                })
            }
            _ => Err("unknown evidence kind".into()),
        }
    }

    /// G1 EQ-1, G5 SL-3: a V4 proposer-twin pair. Two vertices of one slot
    /// (E, round, author) with different hashes, each hash its own `hash_v4`
    /// under this chain's domain, each signed with the author's key in C_E
    /// (never the live set). Refused once tau > tau_start(E+1) + W, or once
    /// C_E's record is gone.
    fn verify_v4_twins(&self, ev: &serde_json::Value) -> Result<VerifiedEvidence, String> {
        let offender = ev
            .get("offender")
            .and_then(|v| v.as_str())
            .ok_or("missing offender")?
            .to_string();
        let epoch = ev
            .get("epoch")
            .and_then(|v| v.as_u64())
            .ok_or("missing epoch")?;
        let round = ev
            .get("round")
            .and_then(|v| v.as_u64())
            .ok_or("missing round")?;
        let vertex = |field: &str| -> Result<blockchain::Vertex, String> {
            serde_json::from_value(ev.get(field).cloned().unwrap_or_default())
                .map_err(|e| format!("{field}: {e}"))
        };
        let (a, b) = (vertex("vertex_a")?, vertex("vertex_b")?);
        for v in [&a, &b] {
            if v.author != offender || v.epoch != epoch || v.round != round {
                return Err("the pair is not one slot of the offender".into());
            }
        }
        if a.hash == b.hash {
            return Err("identical vertices are not equivocation".into());
        }
        let genesis_identity = self
            .db
            .get("genesis_identity")
            .map_err(|e| e.to_string())?
            .ok_or("no genesis identity")?;
        let chain_id = blockchain::chain_id();
        for v in [&a, &b] {
            if v.hash_v4_with_domain(&chain_id, &genesis_identity) != v.hash {
                return Err("a vertex hash is not its V4 hash".into());
            }
        }
        let member = self
            .committee_of_epoch(epoch)
            .into_iter()
            .find(|m| m.address == offender)
            .ok_or_else(|| format!("{offender} is not in the committee of epoch {epoch}"))?;
        if !a.verify_ed25519_signature(&member.ed25519_public_key)
            || !b.verify_ed25519_signature(&member.ed25519_public_key)
        {
            return Err("vertex signature invalid".into());
        }
        if let Some(next) = self.epoch_began(epoch + 1) {
            if committed_chain_clock(&self.db).time > next.saturating_add(EVIDENCE_MAX_AGE_SECS) {
                return Err(format!("evidence of epoch {epoch} is older than W"));
            }
        }
        Ok(VerifiedEvidence {
            offender,
            kind: "equivocation_v4".into(),
            epoch,
            round,
        })
    }

    /// Apply the block's slash evidence: verify each item independently, then
    /// execute. Invalid items are ignored (logged) — a proposer cannot slash
    /// anyone without evidence every node can check.
    fn apply_slash_evidence(&self, items: &[String]) {
        for item in items.iter().take(5) {
            // Consumer-side invariant (defense in depth, mirrors the producer's
            // split filter): only equivocation is ordered through the DAG. A
            // "downtime" item's apply path touched node-local rows.
            let is_equiv = serde_json::from_str::<serde_json::Value>(item)
                .ok()
                .and_then(|v| {
                    v.get("kind")
                        .and_then(|k| k.as_str())
                        .map(|k| k == "equivocation" || k == "equivocation_v4")
                })
                .unwrap_or(false);
            if !is_equiv {
                eprintln!("⚠️  [SLASH] rejecting non-equivocation evidence kind in block");
                continue;
            }
            match self.verify_slash_evidence(item) {
                Ok(VerifiedEvidence {
                    offender,
                    kind,
                    epoch,
                    round,
                }) => {
                    self.execute_one_slash(&offender, epoch, round);
                    if kind == "downtime" {
                        // These attestation rows are NODE-LOCAL bookkeeping (written
                        // with plain put by the local detector and by whatever gossip
                        // this node happened to receive). They were never state-root
                        // writes, so their deletion must not be either: logged_delete
                        // here folded a per-node key set into the state root and forked
                        // honest nodes on identical blocks. Plain delete.
                        let prefix = format!("sys:downtime_attestation:{}:{}:", offender, round);
                        for (k, _) in self.db.scan_prefix(&prefix) {
                            let _ = self.db.delete(&k);
                        }
                    }
                }
                Err(e) => eprintln!("⚠️  [SLASH] rejecting block-carried evidence: {e}"),
            }
        }
    }

    /// TEST-ONLY compatibility shim for the pre-evidence unit tests: drain
    /// locally queued `sys:pending_slash:*` entries through `execute_one_slash`.
    /// The production block path never scans local state (see
    /// apply_slash_evidence) — that scan was the determinism bug.
    #[cfg(test)]
    fn execute_pending_slashes(&self) {
        let slash_keys: Vec<_> = self.db.scan_prefix_limited("sys:pending_slash:", 5);
        for (key, event_json) in &slash_keys {
            let Some(addr) = key.strip_prefix("sys:pending_slash:") else { continue };
            let ev: serde_json::Value = serde_json::from_str(event_json).unwrap_or_default();
            let round = ev.get("round").and_then(|v| v.as_u64()).unwrap_or(0);
            let epoch = ev
                .get("epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| self.executing_epoch());
            self.execute_one_slash(addr, epoch, round);
        }
    }

    /// Execute ONE verified slash (the body of the former pending-slash scan,
    /// now driven exclusively by block-carried evidence). `round` is the
    /// evidence round (equivocation) or epoch (downtime) used for the tombstone.
    fn execute_one_slash(&self, validator_addr: &str, epoch: u64, round: u64) {
        use move_core_types::account_address::AccountAddress;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::ModuleId;

        let validator_addr = validator_addr.to_string();
        let key = &format!("sys:pending_slash:{}", validator_addr);
        {
            // H-4 FIX: Tombstone check for replay protection. G5 SL-3: a
            // jailed validator's first offense is its only one.
            let event_id = format!("{}:{}", validator_addr, round);
            let tombstone_key = format!("sys:slashed:{}", event_id);
            let jailed = self
                .db
                .get(&format!("validator:jailed:{}", validator_addr))
                .ok()
                .flatten()
                .is_some();
            if jailed || matches!(self.db.get(&tombstone_key), Ok(Some(_))) {
                println!(
                    "   ⏭️  Skipping already processed slash event: {}",
                    event_id
                );
                let _ = self.logged_delete(key);
                return;
            }

            println!(
                "⚖️  ACCEPTING EQUIVOCATION by {} in epoch {} (round {})",
                &validator_addr, epoch, round
            );

            // G5 SL-5: Move records the offense with its weight, its
            // committee's weight and its frozen split, all from C_{epoch}, and
            // takes the offender's stake into unbonding; the fraction settles
            // later (SL-4..SL-6), at `delegation::settle_offenses`.
            let Some(record) = self.offense_record(&validator_addr, epoch) else {
                println!(
                    "   ❌ No committee record places {} in epoch {}: refused",
                    validator_addr, epoch
                );
                let _ = self.logged_delete(key);
                return;
            };
            let vm_addr = match AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)) {
                Ok(addr) => addr,
                Err(_) => {
                    println!(
                        "   ❌ Invalid validator address for slash: {}",
                        validator_addr
                    );
                    let _ = self.logged_delete(key);
                    return;
                }
            };
            let args = vec![
                bcs::to_bytes(&AccountAddress::ONE).expect("an address is BCS"),
                bcs::to_bytes(&vm_addr).expect("an address is BCS"),
                bcs::to_bytes(&epoch).expect("a u64 is BCS"),
                bcs::to_bytes(&record.began).expect("a u64 is BCS"),
                bcs::to_bytes(&record.weight).expect("a u64 is BCS"),
                bcs::to_bytes(&record.committee_weight).expect("a u64 is BCS"),
                bcs::to_bytes(&(record.weight - record.delegated)).expect("a u64 is BCS"),
                bcs::to_bytes(&record.delegated).expect("a u64 is BCS"),
            ];
            match self.vm.execute_public_entry_function(
                vec![],
                ModuleId::new(
                    AccountAddress::ONE,
                    Identifier::new("delegation").expect("delegation identifier is valid"),
                ),
                "report_equivocation",
                vec![],
                args,
                // Bounded: the offense ledger holds each offender once, and the
                // settlement it runs is linear in it.
                10_000_000,
                // auth_signer: report_equivocation asserts signer==@0x1. With
                // FIX #1 binding the signer slot to auth_signer, this MUST be
                // system_address() (the offender is carried separately).
                system_address(),
            ) {
                Ok((_gas_used, vm_changes, status)) if status.success => {
                    for (k, v) in vm_changes {
                        let _ = match v {
                            Some(val) => self.logged_put(&k, &val),
                            None => self.logged_delete(&k),
                        };
                    }
                    self.sync_supply_trackers_from_validator_set();
                    println!("   ⚡ Offense recorded; the fraction settles by G5 SL-5");
                }
                Ok((_gas_used, _changes, status)) => {
                    println!(
                        "   ⚠️  Move VM offense record aborted ({:?}), falling back to consensus-only removal",
                        status.error
                    );
                }
                Err(e) => {
                    println!(
                        "   ⚠️  Move VM offense record failed ({}), falling back to consensus-only removal",
                        e
                    );
                }
            }

            // CONSENSUS SET UPDATE: mirror Move staking's active-set semantics.
            // staking::remove_offender takes the validator out of the Move active
            // set, so the native cache must not keep it with any weight.
            if let Ok(Some(json)) = self.db.get("sys:validators") {
                if let Ok(mut vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                    let before_len = vals.len();
                    let mut slashed = false;

                    for (addr, weight) in vals.iter_mut() {
                        if addr == &validator_addr {
                            println!(
                                "   💥 EQUIVOCATION: Validator permanently removed from consensus set!"
                            );
                            *weight = 0;
                            slashed = true;
                        }
                    }

                    if slashed {
                        vals.retain(|(_, w)| *w > 0);
                        if let Ok(new_json) = serde_json::to_string(&vals) {
                            let _ = self.logged_put("sys:validators", &new_json);
                            println!(
                                "   ⛓️  Validator set updated ({} -> {} validators)",
                                before_len,
                                vals.len()
                            );
                        }
                    }
                }
            }

            // SEC (audit C-2): also prune the slashed validator from the AUTHORITATIVE
            // QC trust root `sys:validator_set:v1`. verify_qc resolves its set (stake +
            // BLS key) from v1, but v1 was previously only upserted on join and NEVER
            // pruned on slash/leave — so a slashed (even proven-equivocating) validator
            // kept full QC stake weight forever, letting a departed/ghost set forge a
            // >2/3 QC with no honest supermajority. Prune here to match the Move active
            // set + the sys:validators mirror above.
            if let Ok(Some(v1_json)) = self.db.get(validator_set_v1_key()) {
                if let Ok(mut v1) = serde_json::from_str::<Vec<ValidatorSetV1Entry>>(&v1_json) {
                    let v1_before = v1.len();
                    v1.retain(|v| v.address != validator_addr);
                    if v1.len() != v1_before {
                        if let Ok(nj) = serde_json::to_string(&v1) {
                            let _ = self.logged_put(validator_set_v1_key(), &nj);
                            println!(
                                "   🔻 Removed slashed validator from sys:validator_set:v1 ({} -> {})",
                                v1_before,
                                v1.len()
                            );
                        }
                    }
                }
            }

            // G5 SL-3: the offender is jailed for good (no payouts, no
            // committee, no rejoin). H-4 FIX: the tombstone stops a replay.
            let _ = self.logged_put(
                &format!("validator:jailed:{}", validator_addr),
                &round.to_string(),
            );
            let _ = self.logged_put(&tombstone_key, "1");

            // Delete the pending slash entry (processed)
            let _ = self.logged_delete(key);
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
        self.analyze_tx(tx).0
    }

    /// Analyze a tx: its conflict-dependency tokens AND whether its write set was
    /// statically RECOGNIZED. An UNRECOGNIZED call (PublishModule, an unlisted
    /// module/function, or an undecodable payload) has an unknown write set and
    /// MUST be serialized (run alone) by the scheduler — otherwise two such calls
    /// mutating the same global resource would race in one parallel batch and
    /// fork the state root (#1). The allowlist below is a fast PATH for known
    /// calls, NEVER the safety boundary.
    /// Conflict tokens for the `0x1::staking` global singletons.
    ///
    /// AUDIT-B2: `analyze_tx` declares dependencies per MODULE, but a module can
    /// mutate resources it never names — Move calls into `0x1::staking` from
    /// `governance`, `token_factory` and `delegation`, and those calls
    /// `borrow_global_mut` the staking singletons:
    ///
    /// * `staking::burn_ain` (governance::create_proposal, token_factory::create_token,
    ///   delegation's ticket payout) writes `ValidatorSet` AND `SupplyStats`.
    /// * `staking::mint_depin_reward` and the emission draw write `EmissionPools`.
    ///
    /// Any branch that can reach those MUST declare these keys, or the scheduler
    /// puts it in the same parallel batch as a `staking` tx; both execute against
    /// pre-batch state and the last-write-wins commit silently erases one of the
    /// two `ValidatorSet` blobs. That is the unbounded-mint bug: pair a
    /// `withdraw_unbonded` (which removes the unbonding entry from `ValidatorSet`
    /// but mints into a separate `CoinStore` key) with a hash-ground
    /// `token_factory` tx and the payout survives while the queue entry is
    /// restored — repeatable every block, and the `MAX_SUPPLY` tripwire never
    /// fires because `withdraw_unbonded` does not touch `total_supply`.
    fn staking_global_keys() -> [String; 3] {
        [
            validator_set_key(),
            supply_stats_key(),
            vm_move::state_keys::resource_key_str(&system_address(), "0x1::staking::EmissionPools"),
        ]
    }

    /// Pre-staged state writes that let a transaction reach an address which has
    /// never held AIN.
    ///
    /// # The deadlock this breaks
    ///
    /// `coin::deposit` aborts unless the recipient already holds a
    /// `CoinStore<AincoreCoin>` (coin.move:53). The only way to create one is
    /// `coin::register`, which needs a transaction signed by that account — and
    /// every transaction pays gas through `coin::deduct_gas`, which itself asserts
    /// the payer already has a `CoinStore` (coin.move:104). So a brand-new address
    /// could neither be paid nor pay to register itself: only genesis-seeded
    /// addresses could ever hold AIN. That silently breaks the entire launch model
    /// (buy on the DEX, then stake), and it is invisible to code review — it only
    /// shows up when real transfers actually run, which is how the load generator
    /// surfaced it.
    ///
    /// Move cannot fix this itself: creating a resource at another address requires
    /// that address's `signer`, and this VM exposes no `create_signer` native.
    /// So the adapter does it, using the same staged-write mechanism the abort
    /// atomicity fix introduced: the empty store is materialized before execution
    /// and made visible through `OverlayStorage`, then returned in the normal write
    /// set so it lands in the same WriteBatch and the same state root as everything
    /// else. It is therefore deterministic on every node, not a side channel.
    ///
    /// Deliberately narrow: only `0x1::coin::transfer`, only the declared recipient,
    /// only when the store is genuinely absent, and only ever creating a ZERO
    /// balance. It grants nothing — it just removes an impossible precondition.
    fn auto_register_writes(
        &self,
        call: &vm_move::EntryFunctionCall,
    ) -> Vec<(String, Option<String>)> {
        if *call.module.address() != system_address()
            || call.module.name().as_str() != "coin"
            || call.function != "transfer"
        {
            return Vec::new();
        }
        // coin::transfer(from, to, amount) — arg 1 is the recipient.
        let Some(recipient) = bcs_arg::<move_core_types::account_address::AccountAddress>(
            &call.args, 1,
        ) else {
            return Vec::new();
        };
        // RE-AUDIT MEDIUM: onboarding is for AIN only. Allowing any type arg let
        // anyone force-create CoinStore<T> for arbitrary T at arbitrary addresses
        // (storage griefing; the pre-staged write survives the payload abort by
        // design). Other coin types keep the explicit coin::register flow.
        let coin_type = match call.ty_args.first() {
            Some(t) if *t == aincore_coin_type() => t.clone(),
            Some(_) => return Vec::new(),
            None => aincore_coin_type(),
        };
        let key = coin_store_key_for_type(recipient, coin_type);
        // RE-AUDIT LOW: fail CLOSED on a storage read error. Treating Err as
        // "absent" would overwrite a real balance with zero.
        match self.db.get(&key) {
            Ok(None) => {}
            Ok(Some(_)) => return Vec::new(), // already registered — never overwrite
            Err(_) => return Vec::new(),
        }
        // CoinStore<T> { coin: Coin<T> { value: u128 } } — BCS is the bare u128.
        let Ok(empty) = bcs::to_bytes(&0u128) else {
            return Vec::new();
        };
        println!("🪪 Auto-registering CoinStore for new recipient {}", recipient);
        vec![(key, Some(hex::encode(empty)))]
    }

    fn analyze_tx(&self, tx: &Transaction) -> (Vec<String>, bool) {
        let mut deps = Vec::new();
        let mut recognized = false;
        // H2 FIX: Canonicalize the sender into the SAME representation used for
        // recipients (Move `AccountAddress` Display, i.e. fully zero-padded
        // lowercase hex). `tx.sender` is the raw client-supplied string, which
        // may differ in case / padding / `0x` prefix from the canonical form
        // that `push_addr_arg` and every `resource_{addr}_...` state key uses.
        // If we left it raw, a transfer FROM A and a transfer TO A could yield
        // two DIFFERENT conflict tokens for the same account, so the scheduler
        // would place both in the same parallel batch, both would read A's
        // pre-batch balance, and the atomic last-write-wins commit on
        // `resource_{A}_CoinStore` would silently corrupt the balance and make
        // the state root non-deterministic (consensus-split risk).
        let sender_move_addr = parse_move_address(&tx.sender);
        let sender_token = sender_move_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| tx.sender.clone());
        // G3 KV-2: conflict tokens name the exact state keys, through the one
        // encoder. An unparseable sender cannot execute; its token only has
        // to be distinct.
        let sender_resource = |tag: &str| match &sender_move_addr {
            Some(addr) => vm_move::state_keys::resource_key_str(addr, tag),
            None => format!("resource_{}_{}", tx.sender, tag),
        };
        deps.push(sender_token.clone());
        // SEC (audit C-1): a paymaster-sponsored tx has `deduct_gas` DEBIT the
        // PAYMASTER's CoinStore (`resource_{paymaster}_CoinStore`), not the sender's —
        // but without a covering conflict token, two same-paymaster / different-sender
        // txs land in the SAME parallel batch, both read the pre-batch paymaster
        // balance B, both emit `resource_{P}_CoinStore = B - G`, and the last-write-wins
        // atomic commit collapses N gas deductions into ONE while `total_fees` counts
        // all N → the proposer is minted fees that were never actually burned (AIN
        // created from nothing, breaching the supply cap). Tokenize the paymaster
        // address (identical mechanism to `sender_token`) so same-paymaster txs — and
        // a normal transfer FROM the paymaster racing a sponsored tx — serialize into
        // separate batches and each observes the updated balance.
        if let Some(pm) = &tx.paymaster {
            let pm_token = parse_move_address(pm)
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| pm.clone());
            deps.push(pm_token);
        }
        for obj in &tx.input_objects {
            deps.push(obj.clone());
        }

        let payload_bytes = match hex::decode(tx.payload.trim_start_matches("0x")) {
            Ok(bytes) => bytes,
            Err(_) => return (deps, recognized), // undecodable -> unknown -> serialize
        };
        let payload = match bcs::from_bytes::<vm_move::TransactionPayload>(&payload_bytes) {
            Ok(payload) => payload,
            Err(_) => return (deps, recognized), // undecodable -> unknown -> serialize
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
                recognized = true;
                push_addr_arg(&mut deps, &call.args, 1);
            } else if *module_addr == system_address() && module_name == "staking" {
                // staking locks the validator-set keys, serializing all staking txs.
                recognized = true;
                deps.extend(Self::staking_global_keys());
                deps.push(validator_set_v1_key().to_string());
            } else if *module_addr == system_address() && module_name == "delegation" {
                // AUDIT-B2: delegation reads the active set (staking::is_validator)
                // and burns slashed tickets (staking::burn_ain: ValidatorSet +
                // SupplyStats). G5 DL-3: a user call writes only the named pool
                // and the sender's own Book and coin store.
                deps.extend(Self::staking_global_keys());
                deps.push(sender_resource("0x1::delegation::Book"));
                match function {
                    "enable_delegation" | "update_commission" => {
                        recognized = true;
                        deps.push(sender_resource("0x1::delegation::Pool"));
                    }
                    "delegate" | "undelegate" | "claim_rewards" | "withdraw_unbonded" => {
                        recognized = true;
                        push_addr_arg(&mut deps, &call.args, 1);
                        if let Some(bytes) = call.args.get(1) {
                            if let Ok(addr) = bcs::from_bytes::<
                                move_core_types::account_address::AccountAddress,
                            >(bytes)
                            {
                                deps.push(vm_move::state_keys::resource_key_str(
                                    &addr,
                                    "0x1::delegation::Pool",
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            } else if *module_addr == system_address() && module_name == "governance" {
                recognized = true;
                // AUDIT-B2: governance::create_proposal burns the proposal fee via
                // staking::burn_ain, mutating ValidatorSet + SupplyStats.
                deps.extend(Self::staking_global_keys());
                deps.push(vm_move::state_keys::resource_key_str(
                    &system_address(),
                    "0x1::governance::GovernanceState",
                ));
                deps.push(sender_resource("0x1::governance::VoteEscrow"));
            } else if *module_addr == system_address()
                && module_name == "token_factory"
                && function == "transfer"
            {
                recognized = true;
                // AUDIT-B2: token_factory reaches staking::burn_ain (create_token
                // burns the listing fee). Declared on BOTH token_factory branches
                // so a future function moved between them cannot silently lose the
                // dependency.
                deps.extend(Self::staking_global_keys());
                push_addr_arg(&mut deps, &call.args, 2);
                deps.push(sender_resource("0x1::token_factory::TokenWallet"));
                if let Some(bytes) = call.args.get(2) {
                    if let Ok(addr) =
                        bcs::from_bytes::<move_core_types::account_address::AccountAddress>(bytes)
                    {
                        deps.push(vm_move::state_keys::resource_key_str(
                            &addr,
                            "0x1::token_factory::TokenWallet",
                        ));
                    }
                }
            } else if *module_addr == system_address() && module_name == "token_factory" {
                recognized = true;
                // AUDIT-B2: create_token burns the listing fee via staking::burn_ain.
                deps.extend(Self::staking_global_keys());
                deps.push(vm_move::state_keys::resource_key_str(
                    &system_address(),
                    "0x1::token_factory::TokenRegistry",
                ));
                deps.push(sender_resource("0x1::token_factory::TokenWallet"));
            } else if *module_addr == system_address() && module_name == "dex" {
                recognized = true;
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
        (deps, recognized)
    }

    /// Group block txs into execution batches. Txs WITHIN a batch run in parallel
    /// and have disjoint conflict tokens; txs sharing a token go in later
    /// (sequential) batches. A tx whose write set is NOT statically recognized
    /// (`analyze_tx` -> recognized=false: PublishModule, unlisted module/function,
    /// undecodable payload) is run ALONE in its own batch, fully serialized — we
    /// cannot prove it conflict-free, and two such calls racing a shared global in
    /// one parallel batch would fork the state root (#1).
    fn schedule_batches(
        &self,
        parsed_txs: Vec<(Transaction, String)>,
    ) -> Vec<Vec<(Transaction, String)>> {
        let mut batches: Vec<Vec<(Transaction, String)>> = Vec::new();
        let mut current_batch: Vec<(Transaction, String)> = Vec::new();
        let mut locked_objects: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        for (tx, raw) in parsed_txs {
            let (deps, recognized) = self.analyze_tx(&tx);

            if !recognized {
                // Unknown write set -> run alone (flush current, singleton, reset).
                if !current_batch.is_empty() {
                    batches.push(std::mem::take(&mut current_batch));
                }
                locked_objects.clear();
                batches.push(vec![(tx, raw)]);
                continue;
            }

            let conflict = deps.iter().any(|d| locked_objects.contains(d));
            if conflict {
                if !current_batch.is_empty() {
                    batches.push(std::mem::take(&mut current_batch));
                }
                locked_objects.clear();
            }
            for dep in &deps {
                locked_objects.insert(dep.clone());
            }
            current_batch.push((tx, raw));
        }
        if !current_batch.is_empty() {
            batches.push(current_batch);
        }
        batches
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
            let expected_chain = expected_chain_id();
            if tx.chain_id != expected_chain {
                println!(
                    "❌ Invalid Chain ID: Expected {}, Got {}",
                    expected_chain, tx.chain_id
                );
                return None;
            }

            // 1. Fetch Sender Account Object.
            //
            // ONBOARDING (second layer): a first-time sender has no AccountData
            // object, and `get_object(...)?` used to drop its transaction SILENTLY
            // — no log, no receipt, nothing. Combined with the CoinStore deadlock
            // this meant a new account could neither receive NOR send; after the
            // CoinStore fix it could receive but still never spend, which is the
            // same launch-blocking dead end one step further in. Caught on the live
            // cluster: 6 funded accounts each held exactly their 1 AIN and every one
            // of their 60 outgoing transactions vanished without a trace.
            //
            // Accounts are therefore created IMPLICITLY on first send, the same way
            // Aptos does it. This is safe because the address is not a free
            // parameter: it is derived from the public key
            // (`derive_address(pk) == tx.sender` is asserted a few lines below, and
            // again in the mempool), and the signature is verified against that
            // same key. So only the holder of the matching private key can produce
            // a transaction for this address, and the synthesized account starts at
            // sequence_number 0 — meaning the replay check below still forces the
            // very first transaction to be nonce 0, exactly as for a pre-existing
            // account. Nothing is granted here; an impossible precondition is
            // removed.
            let sender_obj = match self.db.get_object(&tx.sender) {
                Some(obj) => obj,
                None => {
                    println!(
                        "🆕 Implicitly creating account {} on its first transaction",
                        tx.sender
                    );
                    // G3 FX-10: the ONE account constructor genesis uses too,
                    // so a logical account has one encoding in the state tree
                    // whichever path created it.
                    // KV-2: one spelling of the key, whatever case the client sent.
                    aa::AccountManager::create_account(
                        tx.sender.clone(),
                        tx.public_key.to_ascii_lowercase(),
                    )
                }
            };

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
            // F4: signature binds gas_limit, gas_price, input_objects so a
            // network-mutated gas field or rewritten input_objects fails verify
            // here too (defense-in-depth; sync/gossip txs bypass the mempool).
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                tx.chain_id,
                tx.sender,
                tx.payload,
                tx.sequence_number,
                tx.gas_limit,
                tx.gas_price,
                tx.input_objects.join(",")
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
                    if let Err(e) =
                        crypto::zkp::verify_tx_attached_proof(proof_hex, canonical_msg.as_bytes())
                    {
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

            // AUDIT-CRITICAL (pre-mainnet B5): gas_limit had NO upper bound. The
            // sender pre-pays gas_limit * gas_price, but with MIN_GAS_PRICE = 1 a
            // gas_limit of 1e15 costs ~0.001 AIN and buys 1e15 units of Move
            // execution that EVERY validator performs deterministically, on both
            // the consensus and the sync path. There is no wall-clock timeout on
            // Move execution, so one cheap transaction halts the whole chain.
            // This gate lives in the executor, not only the mempool, because a
            // malicious validator can place a transaction straight into a vertex
            // and never offer it for admission.
            if tx.gas_limit > MAX_GAS_LIMIT {
                println!(
                    "❌ REJECTED: gas_limit {} exceeds MAX_GAS_LIMIT {}",
                    tx.gas_limit, MAX_GAS_LIMIT
                );
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
                // G3 FX-9: one canonical spelling, so case variants of the
                // same key cannot address different account objects.
                pm.to_ascii_lowercase()
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
                // deduct_gas asserts signer::address_of(sys)==@0x1, so the
                // authenticated signer for this system pre-action is @0x1, NOT the
                // tx sender. This is why auth_signer must be per-action (FIX #1).
                pre_actions.push((gas_action, true, system_address())); // must succeed
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
                    // SECURITY (B1): authoritative PoP gate. Move cannot run the
                    // BLS pairing check, so reject a join_validator_set whose
                    // proof-of-possession does not verify BEFORE dispatch.
                    if let Err(reason) = verify_join_validator_pop(&call, &tx.public_key) {
                        println!(
                            "❌ REJECTED join_validator_set from {}: {}",
                            tx.sender, reason
                        );
                        return None;
                    }
                    // G5 SL-3 (tombstone): a validator with an accepted
                    // offense never re-enters a committee.
                    if extract_join_validator_v1(&call, &tx.sender).is_some()
                        && self
                            .db
                            .get(&format!("validator:jailed:{}", tx.sender))
                            .expect("CRITICAL: the jail record could not be read")
                            .is_some()
                    {
                        println!(
                            "❌ REJECTED join_validator_set from {}: tombstoned for equivocation",
                            tx.sender
                        );
                        return None;
                    }
                    // B1: capture join_validator_set identity BEFORE the call is
                    // moved into the action, so we can append it to the live
                    // sys:validator_set:v1 after a successful execution.
                    let join_v1_entry = extract_join_validator_v1(&call, &tx.sender);
                    // AUDIT-#1: capture a leave_validator_set BEFORE the call is
                    // moved, so we can prune the departing validator from the QC
                    // trust root + reward mirror after a successful execution.
                    let leave_addr = extract_leave_validator(&call, &tx.sender);
                    // AUDIT-#5: capture an add_stake BEFORE the call is moved, so we
                    // can resync the staker's QC weight from the Move ValidatorSet
                    // after a successful stake increase.
                    let add_stake_addr = extract_add_stake(&call, &tx.sender);
                    // ONBOARDING: a coin::transfer to an address that has never held
                    // AIN would abort inside coin::deposit, and that address can never
                    // fix it itself (registering costs gas, and gas is only taken from
                    // an existing CoinStore). Pre-stage the empty store so the deposit
                    // lands. See auto_register_writes.
                    let prestaged = self.auto_register_writes(&call);
                    let mut actions = pre_actions.clone();
                    // SECURITY (FIX #1): the user's entry call may only act as the
                    // authenticated tx sender. bind_signer_args overwrites the
                    // leading &signer slots with sender_addr, so a forged @0x1 (or
                    // any other principal) embedded in the payload is discarded.
                    actions.push((
                        vm_move::MoveAction::CallEntryFunction(call),
                        false,
                        sender_addr,
                    ));
                    match self.vm.execute_transaction_actions_with_prestaged(
                        actions,
                        sender_addr,
                        tx.gas_limit,
                        prestaged,
                    ) {
                        Ok((_gas_used, vm_changes, status)) => {
                            if absorb_vm_result!(vm_changes, status) {
                                println!("✅ Move EntryFunction executed by {}", tx.sender);
                                // B1: keep sys:validator_set:v1 live on runtime join.
                                if let Some(info) = join_v1_entry {
                                    if let Err(e) =
                                        self.append_validator_set_v1_update(&mut updates, info)
                                    {
                                        println!(
                                            "❌ Failed to stage sys:validator_set:v1 update: {}",
                                            e
                                        );
                                        return None;
                                    }
                                }
                                // AUDIT-#1: prune the departing validator from the
                                // QC trust root + reward mirror on a successful leave.
                                if let Some(addr) = leave_addr {
                                    if let Err(e) =
                                        self.append_validator_removal(&mut updates, &addr)
                                    {
                                        println!(
                                            "❌ Failed to stage validator removal on leave: {}",
                                            e
                                        );
                                        return None;
                                    }
                                    println!("   🔻 Pruned departed validator {} from QC trust root", addr);
                                }
                                // AUDIT-#5: resync QC weight after a stake increase.
                                if let Some(addr) = add_stake_addr {
                                    if let Err(e) =
                                        self.refresh_validator_set_v1_stake(&mut updates, &addr)
                                    {
                                        println!(
                                            "❌ Failed to resync sys:validator_set:v1 stake on add_stake: {}",
                                            e
                                        );
                                        return None;
                                    }
                                }
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
                    // SEC (audit M-5): module publishing runs full bytecode verification
                    // (deserialize + verify_module_bundle_for_publication + dependency
                    // checks) with the move-vm gas meter ignored, and the executor charges
                    // a flat gas_limit upfront (ignoring VM gas_used). A large adversarial
                    // bundle could therefore force superlinear verification work on every
                    // validator for a near-minimal fee (cheap chain-halt-grade DoS).
                    // Require the declared gas_limit to cover a size-proportional floor so
                    // the fee scales with the verification cost imposed on the network.
                    const PUBLISH_GAS_PER_BYTE: u64 = 10;
                    const PUBLISH_GAS_PER_MODULE: u64 = 5_000;
                    let publish_bytes: u64 =
                        modules.iter().map(|m| m.len() as u64).sum::<u64>();
                    let publish_floor = publish_bytes
                        .saturating_mul(PUBLISH_GAS_PER_BYTE)
                        .saturating_add(
                            (modules.len() as u64).saturating_mul(PUBLISH_GAS_PER_MODULE),
                        );
                    if tx.gas_limit < publish_floor {
                        println!(
                            "❌ Publish rejected: gas_limit {} below size-derived floor {} ({} bytes, {} modules)",
                            tx.gas_limit,
                            publish_floor,
                            publish_bytes,
                            modules.len()
                        );
                        return None;
                    }
                    let mut actions = pre_actions.clone();
                    // 3-tuple arity (FIX #1). PublishModule ignores auth_signer
                    // (it uses the fn `sender` param for the 0x1 reservation check),
                    // but the tuple must carry an address; pass sender_addr.
                    actions.push((
                        vm_move::MoveAction::PublishModule(modules),
                        false,
                        sender_addr,
                    ));
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
    mod block_crash_tests {
        include!("block_crash_tests.rs");
    }
    use ed25519_dalek::{Signer, SigningKey};
    use move_binary_format::CompiledModule;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;

    #[test]
    fn test_validator_set_bcs_roundtrip_preserves_bls() {
        // B1 lockstep guard: the live commit path decodes the FULL MoveValidatorSet,
        // mutates total_supply, and re-encodes it (encode_validator_set_hex). If
        // MoveValidatorConfig were missing the two trailing BLS fields, BCS would
        // either fail or silently drop bytes and corrupt the on-disk resource.
        let bls = crypto::bls::BLSEngine::consensus();
        let mut seed = [0u8; 32];
        seed[0] = 7;
        let bls_pk = bls.pubkey_raw(&seed);
        let bls_pop = bls.prove_possession_raw(&seed);
        assert_eq!(bls_pk.len(), 48);
        assert_eq!(bls_pop.len(), 96);

        let set = MoveValidatorSet {
            validators: vec![MoveValidatorConfig {
                validator_addr: system_address(),
                stake: MoveCoin {
                    value: 1_000_000_000_000_000_000_000,
                },
                public_key: vec![1u8; 32],
                bls_public_key: bls_pk.clone(),
                bls_pop: bls_pop.clone(),
            }],
            unbonding_queue: vec![],
            total_supply: 1_000_000_000_000_000_000_000,
            current_epoch: 0,
        };

        let hex1 = encode_validator_set_hex(&set).expect("encode");
        let mut decoded = decode_validator_set_hex(&hex1).expect("decode");
        // Mutate total_supply exactly like the commit path does.
        decoded.total_supply += 42;
        let hex2 = encode_validator_set_hex(&decoded).expect("re-encode");
        let decoded2 = decode_validator_set_hex(&hex2).expect("re-decode");

        assert_eq!(
            decoded2.validators[0].bls_public_key, bls_pk,
            "bls_public_key must survive the decode->mutate->encode round-trip"
        );
        assert_eq!(
            decoded2.validators[0].bls_pop, bls_pop,
            "bls_pop must survive the round-trip"
        );
        assert_eq!(decoded2.total_supply, 1_000_000_000_000_000_000_042);
        // And the PoP still verifies on the survived bytes.
        assert!(bls
            .verify_possession(
                &decoded2.validators[0].bls_public_key,
                &decoded2.validators[0].bls_pop
            )
            .unwrap());
    }

    #[test]
    fn test_validator_set_v1_update_is_staged_not_direct_written() {
        let db = temp_db("validator_set_v1_staged");
        let executor = Executor::new(db.clone());
        let mut updates = Vec::new();
        let entry = ValidatorSetV1Entry {
            address: "11111111111111111111111111111111".to_string(),
            stake: 1000,
            ed25519_public_key: "ed25519".to_string(),
            bls_public_key: "bls_pk".to_string(),
            bls_pop: "bls_pop".to_string(),
        };

        executor
            .append_validator_set_v1_update(&mut updates, entry.clone())
            .expect("stage validator-set v1 update");

        assert!(
            db.get(validator_set_v1_key()).unwrap().is_none(),
            "execute_transaction helpers must not write sys:validator_set:v1 directly"
        );
        assert!(
            db.get("sys:validators").unwrap().is_none(),
            "execute_transaction helpers must not write legacy sys:validators directly"
        );
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].0, validator_set_v1_key());
        let staged: Vec<ValidatorSetV1Entry> =
            serde_json::from_str(updates[0].1.as_deref().unwrap()).unwrap();
        assert_eq!(staged, vec![entry.clone()]);
        assert_eq!(updates[1].0, "sys:validators");
        let legacy: Vec<(String, u64)> =
            serde_json::from_str(updates[1].1.as_deref().unwrap()).unwrap();
        assert_eq!(legacy, vec![(entry.address, entry.stake)]);
    }

    #[test]
    fn test_join_validator_requires_payload_public_key_to_match_tx_public_key() {
        let tx_public_key = vec![7u8; 32];
        let forged_public_key = vec![8u8; 32];
        let (bls_public_key, bls_pop) = test_bls_identity(9);
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("staking").unwrap(),
            ),
            function: "join_validator_set".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&system_address()).unwrap(),
                bcs::to_bytes(&1_000_000_000_000_000_000_000u128).unwrap(),
                bcs::to_bytes(&forged_public_key).unwrap(),
                bcs::to_bytes(&bls_public_key).unwrap(),
                bcs::to_bytes(&bls_pop).unwrap(),
            ],
        };

        let err = verify_join_validator_pop(&call, &hex::encode(tx_public_key))
            .expect_err("payload public_key must be bound to tx.public_key");
        assert!(err.contains("public_key arg must equal tx.public_key"));

        let mut good_call = call;
        good_call.args[2] = bcs::to_bytes(&vec![7u8; 32]).unwrap();
        verify_join_validator_pop(&good_call, &hex::encode(vec![7u8; 32]))
            .expect("matching public key and PoP should pass");
        let entry = extract_join_validator_v1(&good_call, "11111111111111111111111111111111")
            .expect("extract validator v1");
        assert_eq!(entry.ed25519_public_key, hex::encode(vec![7u8; 32]));
    }

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
        bls_public_key: Vec<u8>,
        bls_pop: Vec<u8>,
    }

    /// Deterministic valid (bls_public_key, bls_pop) for test validator fixtures.
    fn test_bls_identity(seed: u8) -> (Vec<u8>, Vec<u8>) {
        let bls = crypto::bls::BLSEngine::consensus();
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        ikm[31] = seed.wrapping_add(3);
        (bls.pubkey_raw(&ikm), bls.prove_possession_raw(&ikm))
    }

    #[derive(Serialize, Deserialize)]
    struct TestUnbondingRequest {
        validator_addr: move_core_types::account_address::AccountAddress,
        stake: u128,
        start_height: u64,
        unlock_time: u64,
    }

    #[derive(Serialize, Deserialize)]
    struct TestValidatorSet {
        validators: Vec<TestValidatorConfig>,
        unbonding_queue: Vec<TestUnbondingRequest>,
        total_supply: u128,
        current_epoch: u64,
    }

    /// A validator's `0x1::delegation::Pool` (G5 DL-2); it must exist.
    fn pool_of(db: &StateDB, validator: &str) -> DelegationPool {
        delegation_pool(db, validator).expect("the validator has a pool")
    }

    /// A delegator's `0x1::delegation::Book` (G5 DL-3); it must exist.
    fn book_of(db: &StateDB, delegator: &str) -> DelegationBook {
        delegation_book(db, delegator).expect("the delegator has a book")
    }

    fn put_delegation_resource<T: Serialize>(db: &StateDB, address: &str, tag: &str, value: &T) {
        let _seed = db.seeding();
        db.put(
            &vm_move::state_keys::resource_key_str(&parse_move_address(address).unwrap(), tag),
            &hex::encode(bcs::to_bytes(value).unwrap()),
        )
        .unwrap();
    }

    fn set_pool(db: &StateDB, validator: &str, pool: &DelegationPool) {
        put_delegation_resource(db, validator, "0x1::delegation::Pool", pool);
    }

    fn set_book(db: &StateDB, delegator: &str, book: &DelegationBook) {
        put_delegation_resource(db, delegator, "0x1::delegation::Book", book);
    }

    /// An open pool holding `coins` of active principal as as many points.
    fn open_pool(coins: u128) -> DelegationPool {
        DelegationPool {
            active_coins: coins,
            active_points: coins,
            reward_counter: 0,
            reward_carry: 0,
            unbonding_coins: 0,
            principal: coins,
            rewards: 0,
            commission_rate: 0,
            pending_commission: 0,
            commission_effective_time: 0,
            closed: false,
            slash_count: 0,
            ticket_count: 0,
            position_count: 0,
            slash_events: vec![],
        }
    }

    fn position(validator: &str, points: u128) -> DelegationPosition {
        DelegationPosition {
            validator: parse_move_address(validator).unwrap(),
            points,
            reward_snapshot: 0,
        }
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

    /// SEC-#13 / G3 FX-6: the genesis pin is the only source. The env is never
    /// read, pinned or not; boot refuses an env that disagrees with the pin.
    /// G3 FX-6: execution checks the installed `sys:chain_id`, never the env.
    #[test]
    fn the_execution_chain_id_never_comes_from_the_env() {
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-SOME-OTHER-CHAIN");
        let chain_id = expected_chain_id();
        std::env::remove_var("AINCORE_CHAIN_ID");
        assert_eq!(chain_id, blockchain::chain_id());
        assert_eq!(
            chain_id,
            blockchain::DEFAULT_CHAIN_ID,
            "nothing installed in tests"
        );
    }

    #[test]
    fn epoch_block_interval_never_reads_the_env() {
        let db = temp_db("ebi_no_env");
        let exec = Executor::new(Arc::clone(&db));
        // Nothing else in this test binary reads the variable, so setting it
        // cannot disturb a parallel test.
        std::env::set_var("AINCORE_EPOCH_BLOCK_INTERVAL", "7");
        assert_eq!(
            exec.epoch_block_interval(),
            Executor::DEFAULT_EPOCH_BLOCK_INTERVAL,
            "unpinned: the default, not the env"
        );
        let _seed = db.seeding();
        db.put("sys:config:epoch_block_interval", "20").unwrap();
        assert_eq!(exec.epoch_block_interval(), 20, "pinned: the pin");
        std::env::remove_var("AINCORE_EPOCH_BLOCK_INTERVAL");
    }

    /// SEC-#13: an unpinned database uses the canonical default.
    #[test]
    fn epoch_block_interval_falls_back_to_default() {
        let db = temp_db("ebi_default");
        let exec = Executor::new(Arc::clone(&db));
        assert_eq!(
            exec.epoch_block_interval(),
            Executor::DEFAULT_EPOCH_BLOCK_INTERVAL
        );
    }

    /// SEC-#13: a zero/garbage pin is rejected and the default is used (boot
    /// refuses such a pin, so only an unpinned test database gets here).
    #[test]
    fn epoch_block_interval_invalid_pin_is_skipped() {
        let db = temp_db("ebi_invalid_pin");
        let exec = Executor::new(Arc::clone(&db));
        let _seed = db.seeding();
        db.put("sys:config:epoch_block_interval", "0").unwrap();
        assert_eq!(
            exec.epoch_block_interval(),
            Executor::DEFAULT_EPOCH_BLOCK_INTERVAL,
            "a zero pin must not disable epoch advancement"
        );
        db.put("sys:config:epoch_block_interval", "notanumber").unwrap();
        assert_eq!(
            exec.epoch_block_interval(),
            Executor::DEFAULT_EPOCH_BLOCK_INTERVAL,
            "a garbage pin must fall through to the default"
        );
    }

    /// SEC-#16: an epoch boundary snapshots the live validator set for the new
    /// epoch, advances consensus:epoch + epoch_start_height, and prunes snapshots
    /// past the retention window. (Deterministic from height; runs on both the
    /// consensus and sync block-apply paths via maybe_advance_epoch.)
    #[test]
    fn rotate_validator_epoch_snapshots_advances_and_prunes() {
        let db = temp_db("rotate_epoch");
        let exec = Executor::new(Arc::clone(&db));
        let _seed = db.seeding();
        // SEC-#13: pin the interval, as genesis does.
        db.put("sys:config:epoch_block_interval", "20").unwrap();
        let (a, b, c) = (
            committee_member(91, 5),
            committee_member(92, 7),
            committee_member(93, 9),
        );
        let record = |epoch: u64| -> Vec<blockchain::committee::ValidatorInfo> {
            serde_json::from_str(
                &db.get(&format!("sys:validator_set:epoch:{epoch}"))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap()
        };
        db.put(
            "genesis:validator_set:v1",
            &serde_json::to_string(&vec![a.clone()]).unwrap(),
        )
        .unwrap();

        // G5 EM-2 / G1 EP-2: a valid live set becomes the next committee, in
        // canonical order. Interval 20: boundary 20 opens epoch 1.
        db.put(
            "sys:validator_set:v1",
            &serde_json::to_string(&vec![c.clone(), b.clone()]).unwrap(),
        )
        .unwrap();
        exec.rotate_validator_epoch(20);
        assert_eq!(
            record(1),
            blockchain::committee::canonical_order(&[b.clone(), c.clone()])
        );
        assert_eq!(db.get("consensus:epoch").unwrap().unwrap(), "1");
        assert_eq!(
            db.get("consensus:epoch_start_height:1").unwrap().unwrap(),
            "21"
        );

        // An invalid live set (a forged proof of possession) keeps C_1.
        let mut forged = a.clone();
        forged.bls_pop = b.bls_pop.clone();
        db.put(
            "sys:validator_set:v1",
            &serde_json::to_string(&vec![forged]).unwrap(),
        )
        .unwrap();
        exec.rotate_validator_epoch(40);
        assert_eq!(
            record(2),
            record(1),
            "an invalid proposal keeps the committee"
        );

        // G5 SL-3 retention: an epoch's records stay while evidence of it can
        // still be accepted, tau <= tau_start(E+1) + W, and for at least the
        // last 8 epochs. Epoch 1 began at tau 0 (no clock yet).
        let set_time = |time: u64| {
            db.put(
                &vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock"),
                &hex::encode(
                    bcs::to_bytes(&ChainClock {
                        height: 0,
                        time,
                        block_timestamp: time,
                    })
                    .unwrap(),
                ),
            )
            .unwrap();
        };
        db.put("sys:validator_set:epoch:0", "[]").unwrap();
        set_time(EVIDENCE_MAX_AGE_SECS);
        exec.rotate_validator_epoch(180); // epoch 9
        assert!(
            db.get("sys:validator_set:epoch:0").unwrap().is_some(),
            "evidence of epoch 0 is accepted until exactly W after epoch 1 began"
        );
        set_time(EVIDENCE_MAX_AGE_SECS + 1);
        exec.rotate_validator_epoch(200); // epoch 10
                                          // Epochs 0 and 1 are past W and older than the last 9 (2..=10).
        for gone in [0, 1] {
            assert!(
                db.get(&format!("sys:validator_set:epoch:{gone}"))
                    .unwrap()
                    .is_none(),
                "a snapshot past W and past 8 epochs is pruned"
            );
        }
        assert!(db.get(&epoch_time_key(1)).unwrap().is_none());
        assert_eq!(db.get(RETAINED_FROM_KEY).unwrap().as_deref(), Some("2"));
        assert_eq!(
            db.get(&epoch_time_key(10)).unwrap().as_deref(),
            Some((EVIDENCE_MAX_AGE_SECS + 1).to_string().as_str())
        );
        // Epoch 2 is past W too, but kept: it is one of the last 9.
        assert!(db.get("sys:validator_set:epoch:2").unwrap().is_some());
    }

    /// A committee member with real keys: its Ed25519 key derives its address
    /// and its BLS proof of possession verifies.
    fn committee_member(seed: u8, stake: u64) -> blockchain::committee::ValidatorInfo {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let (bls_public_key, bls_pop) = test_bls_identity(seed);
        blockchain::committee::ValidatorInfo {
            address: crypto::derive_address(key.verifying_key().as_bytes()).unwrap(),
            stake,
            ed25519_public_key: hex::encode(key.verifying_key().as_bytes()),
            bls_public_key: hex::encode(bls_public_key),
            bls_pop: hex::encode(bls_pop),
        }
    }

    fn load_stdlib(db: &StateDB) {
        let _seed = db.seeding();
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
        seed_chain_params(db);
    }

    /// G5 P-1: the `0x1::chain::Params` genesis writes (epoch 20, reward
    /// period 20, a 14 s clock cap, the 6,650 ms value), and the clock at 0.
    /// Caller holds a seeding guard.
    fn seed_chain_params(db: &StateDB) {
        seed_chain_params_with(db, (20, 20, 14));
    }

    /// `seed_chain_params` with (I, R, C_tau).
    fn seed_chain_params_with(db: &StateDB, params: (u64, u64, u64)) {
        db.put(
            &vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Params"),
            &hex::encode(bcs::to_bytes(&params).unwrap()),
        )
        .expect("chain params stored");
        db.put(
            &vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock"),
            &hex::encode(bcs::to_bytes(&ChainClock::default()).unwrap()),
        )
        .expect("chain clock stored");
    }

    /// A test block's BFT timestamp: 7 s per height. Any non-decreasing value
    /// works; tests of consensus time pass their own.
    fn block_time(height: u64) -> u64 {
        height * 7
    }

    fn create_account(db: &StateDB, signing_key: &SigningKey) -> String {
        let _seed = db.seeding();
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
        let _seed = db.seeding();
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

    // SEC-#27: `committed_ain_balance` is the mempool admission gate's balance
    // reader. It MUST read the same CoinStore key the executor charges gas from,
    // and MUST fail-open (None, never a panic) on a missing/corrupt store so the
    // gate never false-rejects a valid tx.
    #[test]
    fn committed_ain_balance_reads_store_and_fails_open() {
        let db = temp_db("committed_ain_balance");
        let addr = "00000000000000000000000000000abc";

        // Missing CoinStore -> None (caller treats as "unknown", not zero).
        assert_eq!(committed_ain_balance(&db, addr), None);

        // Present + well-formed -> Some(value), matching what gas is charged from.
        set_coin_store(&db, addr, 7_500);
        assert_eq!(committed_ain_balance(&db, addr), Some(7_500));

        // Corrupt bytes at the store key -> None (never panics).
        let move_addr = parse_move_address(addr).unwrap();
        let _seed = db.seeding();
        db.put(&coin_store_key(move_addr), "not-hex-zz").unwrap();
        assert_eq!(committed_ain_balance(&db, addr), None);

        // Unparseable address -> None.
        assert_eq!(committed_ain_balance(&db, "not-an-address"), None);
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
        vm_move::state_keys::resource_key(&addr, &tag)
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
        vm_move::state_keys::resource_key(&pool_addr, &tag)
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
        vm_move::state_keys::resource_key(&parse_move_address(owner).unwrap(), &tag)
    }

    fn set_dex_registry(db: &StateDB, pools: Vec<TestPoolInfo>) {
        db.put(
            &dex_registry_key(),
            &hex::encode(bcs::to_bytes(&TestPoolRegistry { pools }).expect("dex registry BCS")),
        )
        .expect("dex registry stored");
    }

    fn dex_registry(db: &StateDB) -> TestPoolRegistry {
        let value = db
            .get(&dex_registry_key())
            .expect("dex registry read")
            .expect("dex registry exists");
        bcs::from_bytes(&hex::decode(value).expect("dex registry hex")).expect("dex registry BCS")
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

    fn set_dex_lp_balance(
        db: &StateDB,
        owner: &str,
        x: move_core_types::language_storage::TypeTag,
        y: move_core_types::language_storage::TypeTag,
        balance: u128,
    ) {
        db.put(
            &dex_lp_key(owner, x, y),
            &hex::encode(bcs::to_bytes(&TestLPToken { balance }).expect("lp token BCS")),
        )
        .expect("lp token stored");
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

    /// SEC-#1: a call whose write set is not statically recognized (unlisted
    /// module / undecodable payload) must be serialized into its own singleton
    /// batch; recognized disjoint calls still parallelize.
    #[test]
    fn sec1_unknown_calls_serialized_known_calls_parallel() {
        let db = temp_db("sec1_sched");
        let exec = Executor::new(db);
        let mk = |sender: &str, payload: &str| Transaction {
            chain_id: "AINCORE-MAINNET-1".to_string(),
            sender: sender.to_string(),
            input_objects: vec![],
            payload: payload.to_string(),
            args: vec![],
            gas_limit: 10_000,
            gas_price: 1,
            sequence_number: 0,
            public_key: String::new(),
            signature: String::new(),
            paymaster: None,
            paymaster_signature: None,
            zkp_proof: None,
        };

        let xfer = entry_payload("coin", "transfer", vec![], vec![]);
        let unknown = entry_payload("universal_mining", "mine", vec![], vec![]);
        // Recognition gate.
        assert!(exec.analyze_tx(&mk(&"a".repeat(32), &xfer)).1, "coin::transfer recognized");
        assert!(
            !exec.analyze_tx(&mk(&"a".repeat(32), &unknown)).1,
            "unlisted module must NOT be recognized"
        );
        assert!(
            !exec.analyze_tx(&mk(&"a".repeat(32), "deadbeef")).1,
            "undecodable payload must NOT be recognized"
        );

        // Two UNKNOWN calls with disjoint senders must each run alone.
        let batches = exec.schedule_batches(vec![
            (mk(&"a".repeat(32), &unknown), "ra".to_string()),
            (mk(&"b".repeat(32), &unknown), "rb".to_string()),
        ]);
        assert_eq!(batches.len(), 2, "unknown calls must be serialized into singleton batches");
        assert!(batches.iter().all(|b| b.len() == 1));

        // Two recognized, disjoint coin::transfers still share one parallel batch.
        let batches2 = exec.schedule_batches(vec![
            (mk(&"c".repeat(32), &xfer), "rc".to_string()),
            (mk(&"d".repeat(32), &xfer), "rd".to_string()),
        ]);
        assert_eq!(batches2.len(), 1, "disjoint known txs stay in one parallel batch");
        assert_eq!(batches2[0].len(), 2);
    }

    /// AUDIT-B2: the unbounded-mint exploit pairing must NEVER share a parallel
    /// batch with a staking transaction.
    ///
    /// The attack: `staking::withdraw_unbonded` removes the unbonding entry from
    /// `0x1::staking::ValidatorSet` and, separately, mints the payout into
    /// `resource_{addr}_CoinStore`. A `token_factory` (or `governance`, or
    /// `delegation`) transaction ALSO mutates `ValidatorSet` — through
    /// `staking::burn_ain` — but never declared it. With disjoint declared
    /// dependency sets the scheduler put both in one batch; both executed against
    /// pre-batch state; the commit sorted by tx_hash and last-write-wins restored
    /// the unbonding entry while the minted payout survived. Repeatable every
    /// block, and `MAX_SUPPLY` never noticed because `withdraw_unbonded` does not
    /// touch `total_supply`.
    ///
    /// The fix declares the staking singletons on every branch that can reach
    /// them, so these transactions now serialize into separate batches.
    #[test]
    fn test_b2_staking_globals_serialize_cross_module_txs() {
        let db = temp_db("b2_conflict_tokens");
        let exec = Executor::new(db);
        let mk = |sender: &str, payload: &str| Transaction {
            chain_id: "AINCORE-MAINNET-1".to_string(),
            sender: sender.to_string(),
            input_objects: vec![],
            payload: payload.to_string(),
            args: vec![],
            gas_limit: 10_000,
            gas_price: 1,
            sequence_number: 0,
            public_key: String::new(),
            signature: String::new(),
            paymaster: None,
            paymaster_signature: None,
            zkp_proof: None,
        };

        let withdraw = entry_payload("staking", "withdraw_unbonded", vec![], vec![]);
        let create_token = entry_payload("token_factory", "create_token", vec![], vec![]);
        let propose = entry_payload("governance", "create_proposal", vec![], vec![]);
        let delegate = entry_payload("delegation", "delegate", vec![], vec![]);

        // Every one of these branches must now declare the staking singletons.
        let vs = super::validator_set_key();
        let ss = super::supply_stats_key();
        for (name, payload) in [
            ("staking", &withdraw),
            ("token_factory", &create_token),
            ("governance", &propose),
            ("delegation", &delegate),
        ] {
            let (deps, recognized) = exec.analyze_tx(&mk(&"a".repeat(32), payload));
            assert!(recognized, "{} must be recognized", name);
            assert!(
                deps.contains(&vs),
                "{} must declare staking::ValidatorSet — it can reach it via staking::burn_ain / \
                 staking::is_validator",
                name
            );
            assert!(
                deps.contains(&ss),
                "{} must declare staking::SupplyStats (the emission cap ledger)",
                name
            );
        }

        // The exploit pairing itself: distinct senders, so nothing else forces a
        // conflict — only the shared staking token can separate them.
        let batches = exec.schedule_batches(vec![
            (mk(&"a".repeat(32), &withdraw), "r_withdraw".to_string()),
            (mk(&"b".repeat(32), &create_token), "r_token".to_string()),
        ]);
        assert_eq!(
            batches.len(),
            2,
            "withdraw_unbonded and create_token must be SERIALIZED — sharing a parallel batch is \
             the unbounded-mint bug"
        );

        // Same for the governance and delegation variants of the same attack.
        for (label, payload) in [("governance", &propose), ("delegation", &delegate)] {
            let batches = exec.schedule_batches(vec![
                (mk(&"c".repeat(32), &withdraw), "r_w".to_string()),
                (mk(&"d".repeat(32), payload), "r_x".to_string()),
            ]);
            assert_eq!(
                batches.len(),
                2,
                "withdraw_unbonded and {} must be serialized",
                label
            );
        }

        // Sanity: the fix must not over-serialize unrelated traffic. Two plain
        // coin::transfers between distinct accounts still share one batch.
        let xfer = entry_payload("coin", "transfer", vec![], vec![]);
        let batches = exec.schedule_batches(vec![
            (mk(&"e".repeat(32), &xfer), "r1".to_string()),
            (mk(&"f".repeat(32), &xfer), "r2".to_string()),
        ]);
        assert_eq!(
            batches.len(),
            1,
            "plain transfers must still parallelize — the fix must not kill throughput"
        );
    }

    fn validator_set_key() -> String {
        super::validator_set_key()
    }

    fn token_registry_key() -> String {
        vm_move::state_keys::resource_key_str(
            &system_address(),
            "0x1::token_factory::TokenRegistry",
        )
    }

    fn token_wallet_key(addr: &str) -> String {
        vm_move::state_keys::resource_key_str(
            &parse_move_address(addr).unwrap(),
            "0x1::token_factory::TokenWallet",
        )
    }

    fn governance_state_key() -> String {
        vm_move::state_keys::resource_key_str(&system_address(), "0x1::governance::GovernanceState")
    }

    fn vote_escrow_key(addr: &str) -> String {
        vm_move::state_keys::resource_key_str(
            &parse_move_address(addr).unwrap(),
            "0x1::governance::VoteEscrow",
        )
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
        let _seed = db.seeding();
        let validator_addr = parse_move_address(validator).expect("validator move address");
        let (bls_public_key, bls_pop) = test_bls_identity(1);
        let set = TestValidatorSet {
            validators: vec![TestValidatorConfig {
                validator_addr,
                stake: TestCoin { value: stake },
                public_key: vec![1, 2, 3],
                bls_public_key,
                bls_pop,
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

    fn supply_stats_cumulative_burned(db: &StateDB) -> u128 {
        db.get(&supply_stats_key())
            .ok()
            .flatten()
            .and_then(|v| decode_supply_stats_hex(&v))
            .map(|s| s.cumulative_burned)
            .unwrap_or(0)
    }

    /// AUDIT-#5: add_stake must resync the QC trust root (sys:validator_set:v1)
    /// and the sys:validators mirror to the validator's NEW authoritative stake
    /// from the Move ValidatorSet — otherwise QC quorum weight stays frozen at the
    /// join-time value while real stake-at-risk grows.
    #[test]
    fn add_stake_resyncs_v1_qc_weight() {
        let db = temp_db("add_stake_resync");
        let exec = Executor::new(Arc::clone(&db));
        let addr = "0000000000000000000000000000000000000000000000000000000000000001";
        // Move ValidatorSet is authoritative: validator now holds 1500 AIN.
        set_validator_set(
            &db,
            addr,
            1_500_000_000_000_000_000_000u128,
            3_000_000_000_000_000_000_000u128,
        );
        // v1 trust root + mirror still carry the STALE join-time weight (1000 AIN).
        let stale_v1 = vec![ValidatorSetV1Entry {
            address: addr.to_string(),
            stake: 1000,
            ed25519_public_key: "aa".into(),
            bls_public_key: "bb".into(),
            bls_pop: "cc".into(),
        }];
        let _seed = db.seeding();
        db.put(validator_set_v1_key(), &serde_json::to_string(&stale_v1).unwrap())
            .unwrap();
        db.put(
            "sys:validators",
            &serde_json::to_string(&vec![(addr.to_string(), 1000u64)]).unwrap(),
        )
        .unwrap();

        let mut updates: Vec<(String, Option<String>)> = Vec::new();
        exec.refresh_validator_set_v1_stake(&mut updates, addr)
            .expect("resync ok");
        apply_updates(&db, updates);

        let v1: Vec<ValidatorSetV1Entry> =
            serde_json::from_str(&db.get(validator_set_v1_key()).unwrap().unwrap()).unwrap();
        assert_eq!(v1[0].stake, 1500, "v1 QC weight resynced to 1500 AIN");
        assert_eq!(
            v1[0].ed25519_public_key, "aa",
            "identity fields (pubkey/bls/pop) preserved — only stake changed"
        );
        let mirror: Vec<(String, u64)> =
            serde_json::from_str(&db.get("sys:validators").unwrap().unwrap()).unwrap();
        assert_eq!(mirror[0].1, 1500, "sys:validators mirror resynced too");
    }

    /// AUDIT-#8: BCS round-trip for the independent SupplyStats resource mirror.
    #[test]
    fn supply_stats_bcs_roundtrip() {
        let s = MoveSupplyStats {
            cumulative_burned: 123_456_789_000_000_000_000u128,
        };
        let hex = encode_supply_stats_hex(&s).expect("encode SupplyStats");
        let back = decode_supply_stats_hex(&hex).expect("decode SupplyStats");
        assert_eq!(back.cumulative_burned, s.cumulative_burned);
    }

    /// AUDIT-#8 (BTC mint-cap): a Rust-native fee burn must (a) decrement net
    /// total_supply and (b) increment SupplyStats.cumulative_burned by the SAME
    /// delta, so cumulative MINTED (= net + burned) — the emission anchor — is
    /// INVARIANT under the burn. This is precisely the fee-path hole the
    /// adversarial verifiers caught: without the SupplyStats credit, `minted`
    /// would drop and burnt fees would become re-mintable emission head-room.
    #[test]
    fn fee_burn_keeps_cumulative_minted_invariant() {
        let db = temp_db("supplystats_fee_burn");
        let exec = Executor::new(Arc::clone(&db));
        let start_supply: u128 = 1_000_000_000_000_000_000_000; // 1000 AIN net
        set_validator_set(&db, "1", 500_000_000_000_000_000_000, start_supply);

        let minted_before = validator_set(&db).total_supply + supply_stats_cumulative_burned(&db);
        assert_eq!(minted_before, start_supply, "no burns yet: minted == net");

        // Called directly, outside a block: test context.
        let _seed = db.seeding();
        let burn: u128 = 7_000_000_000_000_000_000; // 7 AIN fee burn
        exec.burn_supply_trackers(burn);

        let net_after = validator_set(&db).total_supply;
        let burned_after = supply_stats_cumulative_burned(&db);
        assert_eq!(net_after, start_supply - burn, "net total_supply drops by the burn");
        assert_eq!(burned_after, burn, "SupplyStats.cumulative_burned rises by the burn");

        let minted_after = net_after + burned_after;
        assert_eq!(
            minted_after, minted_before,
            "cumulative MINTED invariant under fee burn — emission anchor (MAX - minted) cannot rise, #8 stays closed"
        );

        // A second burn keeps the invariant and accumulates monotonically.
        exec.burn_supply_trackers(3_000_000_000_000_000_000);
        assert_eq!(supply_stats_cumulative_burned(&db), burn + 3_000_000_000_000_000_000);
        assert_eq!(
            validator_set(&db).total_supply + supply_stats_cumulative_burned(&db),
            start_supply,
            "minted still invariant after a second burn"
        );
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
            "{}:{}:{}:{}:{}:{}:{}",
            "AINCORE-MAINNET-1", sender, payload, sequence_number, gas_limit, gas_price, ""
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
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);
        set_coin_store(&db, &recipient, 0);

        let executor = Executor::new(db.clone());
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::ONE,
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

    /// AUDIT-B1 (transaction atomicity): an ABORTED Move transaction must commit
    /// NOTHING except the gas charge.
    ///
    /// This is the audit's proof-of-concept, inverted into a regression test.
    /// `coin::transfer` debits the sender in `coin::withdraw` and only afterwards
    /// calls `coin::deposit`, which asserts the recipient has a CoinStore. Sending
    /// to an unregistered recipient therefore aborts AFTER the debit.
    ///
    /// Before the staged-session fix, move-vm's changeset was finished on the abort
    /// path and the partial write was committed: the sender ended at 899_900 and the
    /// 100 AIN was destroyed by a transaction whose own receipt says "aborted".
    /// With the fix the user session is dropped without `finish()`, so only the
    /// prologue (gas) survives: 1_000_000 - 100_000 = 900_000.
    /// NOTE ON THE ABORT VEHICLE: this test originally triggered the abort by
    /// transferring to a recipient with no CoinStore, which made `coin::deposit`
    /// abort AFTER `coin::withdraw` had already debited the sender — the audit's
    /// exact proof-of-concept. That vehicle no longer exists: the onboarding fix
    /// auto-registers an absent recipient store, so that transfer now succeeds by
    /// design (see `test_transfer_to_brand_new_account_succeeds`). The property
    /// under test is unchanged — an aborting payload must commit NOTHING but gas —
    /// so the test now uses an over-balance transfer, which aborts inside
    /// `coin::withdraw`.
    #[test]
    fn test_b1_aborted_transfer_commits_only_gas() {
        let db = temp_db("b1_abort_atomicity");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[21u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[22u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        let executor = Executor::new(db.clone());
        // Far more than the sender holds -> the payload aborts.
        let payload = coin_transfer_payload(&sender, &recipient, 999_999_999);
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1))
            .expect("transaction is kept (gas is charged) even though the payload aborts");
        assert_eq!(gas, 100_000, "gas must still be charged on an aborted tx");
        apply_updates(&db, updates);

        assert_eq!(
            coin_balance(&db, &sender),
            900_000,
            "an aborted transfer must debit ONLY gas — no write from the \
             partially-executed payload may be committed"
        );
        assert_eq!(
            coin_balance(&db, &recipient),
            0,
            "the recipient must not be credited by an aborted transfer"
        );
    }

    /// AUDIT-B1: the prologue (gas) write must survive the user payload aborting.
    /// If a naive "drop the whole session on abort" were used instead of staged
    /// sessions, gas would be refunded and aborts would be free — an unpriced spam
    /// vector. Pairs with the test above: together they pin BOTH halves of the
    /// contract (user writes discarded, gas write kept).
    #[test]
    fn test_b1_gas_survives_payload_abort() {
        let db = temp_db("b1_gas_survives");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[23u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[24u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 500_000);

        let executor = Executor::new(db.clone());
        // Over-balance transfer -> payload aborts (see the note on the test above).
        let payload = coin_transfer_payload(&sender, &recipient, 999_999_999);
        let (updates, _gas) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 50_000, 1))
            .expect("aborted transaction is still kept and charged");
        apply_updates(&db, updates);

        assert_eq!(
            coin_balance(&db, &sender),
            450_000,
            "gas must be deducted exactly once even though the payload aborted"
        );
    }

    /// ONBOARDING: a transfer to an address that has NEVER held AIN must succeed.
    ///
    /// Found by the first real load test: `coin::deposit` aborts without a
    /// `CoinStore`, and the recipient cannot create one (registering costs gas;
    /// gas is only taken from an existing `CoinStore`). Only genesis-seeded
    /// addresses could ever hold AIN, which silently breaks the whole launch model
    /// — nobody could receive the AIN they bought.
    ///
    /// The adapter now pre-stages an EMPTY store for the declared recipient. This
    /// test is the proof, and it is deliberately end-to-end: brand-new recipient,
    /// no CoinStore anywhere, real Move execution.
    #[test]
    fn test_transfer_to_brand_new_account_succeeds() {
        let db = temp_db("onboarding_new_account");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[31u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[32u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        // The recipient has NO CoinStore — exactly a fresh user's situation.
        let recipient_addr = parse_move_address(&recipient).expect("recipient address");
        assert!(
            db.get(&coin_store_key(recipient_addr))
                .expect("read")
                .is_none(),
            "test setup invariant: recipient must start with no CoinStore"
        );

        let executor = Executor::new(db.clone());
        let payload = coin_transfer_payload(&sender, &recipient, 250);
        let (updates, _gas) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1))
            .expect("transaction accepted");
        apply_updates(&db, updates);

        assert_eq!(
            coin_balance(&db, &recipient),
            250,
            "a brand-new account must be able to receive its first AIN"
        );
        assert_eq!(
            coin_balance(&db, &sender),
            1_000_000 - 100_000 - 250,
            "sender pays gas + the transferred amount"
        );
    }

    /// The auto-registration must never touch an EXISTING balance — it may only
    /// create a store that is genuinely absent, and only ever with value 0.
    #[test]
    fn test_auto_register_never_overwrites_existing_balance() {
        let db = temp_db("onboarding_no_clobber");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[33u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[34u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000_000);
        set_coin_store(&db, &recipient, 777); // already funded

        let executor = Executor::new(db.clone());
        let payload = coin_transfer_payload(&sender, &recipient, 23);
        let (updates, _gas) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1))
            .expect("transaction accepted");
        apply_updates(&db, updates);

        assert_eq!(
            coin_balance(&db, &recipient),
            800,
            "existing balance must be added to, never reset to zero"
        );
    }

    /// ONBOARDING (second layer): an account that has never sent must be able to
    /// send. Caught live: after the CoinStore fix, 6 funded accounts each held
    /// their 1 AIN and every one of their 60 outgoing transactions vanished
    /// SILENTLY — `get_object(&tx.sender)?` dropped them because no AccountData
    /// object existed. Receive-but-never-spend is the same launch-blocking dead
    /// end one step further along.
    #[test]
    fn test_first_time_sender_can_spend_without_preexisting_account() {
        let db = temp_db("onboarding_first_send");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[41u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[42u8; 32]);
        // NOTE: create_account() is deliberately NOT called for the sender.
        let sender = crypto::derive_address(sender_key.verifying_key().as_bytes()).unwrap();
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000").unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        assert!(
            db.get_object(&sender).is_none(),
            "test setup invariant: sender must have no AccountData object"
        );

        let executor = Executor::new(db.clone());
        let payload = coin_transfer_payload(&sender, &recipient, 500);
        let (updates, _gas) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1))
            .expect("a first-time sender must not be silently dropped");
        apply_updates(&db, updates);

        assert_eq!(
            coin_balance(&db, &recipient),
            500,
            "the transfer from a brand-new sender must actually land"
        );
        assert!(
            db.get_object(&sender).is_some(),
            "the account must now exist on chain"
        );
    }

    /// Implicit creation must NOT weaken replay protection: a first transaction
    /// carrying a non-zero nonce must still be rejected.
    #[test]
    fn test_implicit_account_still_enforces_nonce_zero_first() {
        let db = temp_db("onboarding_nonce_guard");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[43u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[44u8; 32]);
        let sender = crypto::derive_address(sender_key.verifying_key().as_bytes()).unwrap();
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000").unwrap();
        set_coin_store(&db, &sender, 1_000_000);

        let executor = Executor::new(db.clone());
        let payload = coin_transfer_payload(&sender, &recipient, 500);
        // Nonce 7 on a brand-new account: must be refused, not silently accepted.
        let out = executor.execute_transaction(&signed_tx(
            &sender_key, &sender, &payload, 7, 100_000, 1,
        ));
        assert!(
            out.is_none(),
            "an implicitly-created account must still start at nonce 0"
        );
    }

    /// RE-AUDIT HIGH (slash determinism): slashes come ONLY from block-carried
    /// evidence that every node can verify. A proposer cannot slash anyone
    /// without real evidence, and real evidence verifies identically everywhere.
    #[test]
    fn test_slash_evidence_verification_equivocation() {
        let db = temp_db("evidence_equiv");
        let key = SigningKey::from_bytes(&[51u8; 32]);
        let offender = create_account(&db, &key);
        let _seed = db.seeding();
        db.put("sys:validators", &format!(r#"[["{}",1000],["other0000",1000]]"#, offender))
            .unwrap();
        let executor = Executor::new(db.clone());

        let mk = |ts: u64| {
            let mut v = blockchain::Vertex {
                epoch: 0,
                round: 9,
                author: offender.clone(),
                parents: vec!["genesis".into()],
                payload: vec![],
                timestamp: ts,
                hash: String::new(),
                signature: String::new(),
                aggregated_signature: None,
            payload_root: None,
                parents_root: None,
                parent_refs: Vec::new(),
            };
            v.hash = v.calculate_hash();
            v.sign_with_ed25519(&key);
            v
        };
        let a = mk(1);
        let b = mk(2);
        let item = |a: &blockchain::Vertex, b: &blockchain::Vertex| {
            serde_json::json!({"kind":"equivocation","offender":offender,"round":9,"vertex_a":a,"vertex_b":b})
                .to_string()
        };

        let ok = executor
            .verify_slash_evidence(&item(&a, &b))
            .expect("valid proof");
        assert_eq!(
            (ok.offender, ok.kind, ok.round),
            (offender.clone(), "equivocation".to_string(), 9)
        );

        // Same vertex twice is not equivocation.
        assert!(executor.verify_slash_evidence(&item(&a, &a)).is_err());
        // Tampered body (hash no longer matches) must fail.
        let mut t = b.clone();
        t.timestamp = 99;
        assert!(executor.verify_slash_evidence(&item(&a, &t)).is_err());
        // Forged: signed by someone else.
        let mut f = b.clone();
        f.sign_with_ed25519(&SigningKey::from_bytes(&[52u8; 32]));
        assert!(executor.verify_slash_evidence(&item(&a, &f)).is_err());
        // An epoch a relay set on a V3 proof (unhashed) is refused (G1 S2
        // review 2): it would otherwise land in durable evidence.
        let mut padded = b.clone();
        padded.epoch = u64::MAX;
        assert_eq!(
            padded.calculate_hash(),
            b.hash,
            "the V3 hash ignores the epoch"
        );
        assert!(executor.verify_slash_evidence(&item(&a, &padded)).is_err());
        assert!(executor.verify_slash_evidence(&item(&padded, &a)).is_err());

        // COMPACT proofs (payload stripped, payload_root carried) must verify
        // identically -- this is what keeps DAG-carried evidence tiny.
        let mk_big = |ts: u64| {
            let mut v = blockchain::Vertex {
                epoch: 0,
                round: 9,
                author: offender.clone(),
                parents: vec!["genesis".into()],
                payload: vec!["z".repeat(200_000)],
                timestamp: ts,
                hash: String::new(),
                signature: String::new(),
                aggregated_signature: None,
                payload_root: None,
                parents_root: None,
                parent_refs: Vec::new(),
            };
            v.hash = v.calculate_hash();
            v.sign_with_ed25519(&key);
            v
        };
        let (ba, bb) = (mk_big(3), mk_big(4));
        let (ca, cb) = (ba.to_compact_proof(), bb.to_compact_proof());
        let compact_item = item(&ca, &cb);
        assert!(
            compact_item.len() < 2_000,
            "compact proof must be small: {}",
            compact_item.len()
        );
        let compact = executor
            .verify_slash_evidence(&compact_item)
            .expect("compact proof verifies");
        assert_eq!(
            (compact.offender, compact.kind, compact.round),
            (offender.clone(), "equivocation".to_string(), 9)
        );
        // A compact proof whose root was tampered fails hash binding.
        let mut bad = ca.clone();
        bad.payload_root = Some("00".repeat(32));
        assert!(executor.verify_slash_evidence(&item(&bad, &cb)).is_err());
    }

    #[test]
    fn test_slash_evidence_verification_downtime_quorum_and_signatures() {
        use ed25519_dalek::Signer;
        let db = temp_db("evidence_downtime");
        let k1 = SigningKey::from_bytes(&[61u8; 32]);
        let k2 = SigningKey::from_bytes(&[62u8; 32]);
        let k3 = SigningKey::from_bytes(&[63u8; 32]);
        let r1 = create_account(&db, &k1);
        let r2 = create_account(&db, &k2);
        let off = create_account(&db, &k3);
        let _seed = db.seeding();
        db.put(
            "sys:validators",
            &format!(r#"[["{}",1000],["{}",1000],["{}",1000]]"#, r1, r2, off),
        )
        .unwrap();
        let executor = Executor::new(db.clone());

        let att = |k: &SigningKey, rep: &str, good: bool| {
            let canonical = format!("{}:{}:{}:{}", off, 4, rep, 400);
            let mut sig = hex::encode(k.sign(canonical.as_bytes()).to_bytes());
            if !good { sig.replace_range(0..2, "00"); }
            serde_json::json!({
                "offender": off, "epoch": 4, "reporter": rep, "round": 400, "rounds_missed": 150,
                "reporter_pubkey": hex::encode(k.verifying_key().to_bytes()), "signature": sig,
            })
        };
        let item = |atts: Vec<serde_json::Value>| {
            serde_json::json!({"kind":"downtime","offender":off,"epoch":4,"attestations":atts}).to_string()
        };

        // 1 of 3 (33%) -> no quorum.
        assert!(executor.verify_slash_evidence(&item(vec![att(&k1, &r1, true)])).is_err());
        // 2 of 3 is exactly 2/3 -> strict quorum NOT met.
        assert!(executor
            .verify_slash_evidence(&item(vec![att(&k1, &r1, true), att(&k2, &r2, true)]))
            .is_err());
        // 3 of 3 including the offender itself attesting? offender is a validator too.
        let ok = executor
            .verify_slash_evidence(&item(vec![att(&k1, &r1, true), att(&k2, &r2, true), att(&k3, &off, true)]))
            .expect("3/3 stake meets quorum");
        assert_eq!(
            (ok.offender, ok.kind, ok.round),
            (off.clone(), "downtime".to_string(), 4)
        );
        // A bad signature invalidates the whole item (proposer cannot pad quorum).
        assert!(executor
            .verify_slash_evidence(&item(vec![att(&k1, &r1, true), att(&k2, &r2, true), att(&k3, &off, false)]))
            .is_err());
    }

    /// ROOT-CAUSE REGRESSION (2026-08-25 burn-in): a height must be executable
    /// exactly ONCE and only in order. Two paths (ChainSync import and the local
    /// commit loop) execute into the single `sys:state_root` chain; when a node
    /// fell behind, sync executed H while the local loop was still building H-1,
    /// so the local block's header captured a root containing H's work. Live
    /// result: the epoch advance for height 6640 landed in the block stored as
    /// 6639, the node's prev_hash chain was permanently offset, and the 4-node
    /// cluster split three ways with ZERO transactions.
    #[test]
    fn test_height_executes_exactly_once_and_only_in_order() {
        let db = temp_db("exec_height_order");
        load_stdlib(&db);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000").unwrap();
        let executor = Executor::new(db.clone());
        let proposer = "0000000000000000000000000000000000000000000000000000000000000001";

        assert_eq!(executor.last_executed_height(), 0, "fresh chain starts at 0");

        seed_genesis_tree(&db);
        // In-order execution advances the marker and the root chain.
        let root0 = executor.current_state_root();
        let state_rows = |db: &StateDB| -> std::collections::BTreeMap<String, String> {
            db.scan_prefix("")
                .into_iter()
                .filter(|(k, _)| {
                    storage::class::classify(k.as_bytes()) == Some(storage::class::KeyClass::State)
                })
                .collect()
        };
        let before = state_rows(&db);
        let s1 = match executor.execute_block_parallel_at(vec![], proposer, 1, block_time(1), &[]) {
            BlockExecOutcome::Executed(s) => s,
            other => panic!("height 1 must execute: {:?}", other),
        };
        assert_eq!(executor.last_executed_height(), 1);
        // G5 CL-2: an empty block changes exactly one state key, the chain
        // clock: its height, and consensus time grown by the timestamp's
        // growth (7 s, under the 14 s cap).
        let after = state_rows(&db);
        let clock_key =
            vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock");
        let changed: Vec<&String> = after
            .keys()
            .chain(before.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter(|k| before.get(*k) != after.get(*k))
            .collect();
        assert_eq!(changed, vec![&clock_key], "only the clock moves");
        let clock = ChainClock {
            height: 1,
            time: 7,
            block_timestamp: 7,
        };
        assert_eq!(
            after[&clock_key],
            hex::encode(bcs::to_bytes(&clock).unwrap())
        );

        // Re-executing the SAME height is refused — this is the double execution
        // that corrupted the root chain live.
        match executor.execute_block_parallel_at(vec![], proposer, 1, block_time(1), &[]) {
            BlockExecOutcome::AlreadyExecuted { last_executed } => {
                assert_eq!(last_executed, 1)
            }
            other => panic!("re-executing height 1 must be refused, got {:?}", other),
        }
        assert_eq!(
            executor.current_state_root(),
            s1.state_root,
            "a refused re-execution must not move the state root"
        );

        // Skipping ahead is refused: executing out of order corrupts the chain.
        match executor.execute_block_parallel_at(vec![], proposer, 3, block_time(3), &[]) {
            BlockExecOutcome::Gap { expected, got } => {
                assert_eq!((expected, got), (2, 3))
            }
            other => panic!("height 3 after 1 must be a Gap, got {:?}", other),
        }
        assert_eq!(executor.last_executed_height(), 1, "a refused gap consumes nothing");

        // The next height in order still works afterwards.
        let s2 = match executor.execute_block_parallel_at(vec![], proposer, 2, block_time(2), &[]) {
            BlockExecOutcome::Executed(s) => s,
            other => panic!("height 2 must execute after 1: {:?}", other),
        };
        assert_eq!(executor.last_executed_height(), 2);
        // The clock write is in the root, so each empty block moves it; the
        // height marker is what makes each height consumable exactly once.
        assert_ne!(root0, s1.state_root, "the clock write is in the root");
        assert_ne!(s1.state_root, s2.state_root, "each height moves the clock");
        assert_eq!(s2.state_root, executor.current_state_root());
    }

    const G5_AIN: u128 = 1_000_000_000_000_000_000;
    const DAY: u64 = 86_400;
    /// U and N, as `0x1::chain` fixes them.
    const UNBONDING: u64 = 21 * DAY;
    const NOTICE: u64 = 7 * DAY;

    /// A chain for the G5 deadline tests: the stdlib, `0x1::chain::Params`
    /// with I = 20 (the executor's default epoch interval), R = 20 and the
    /// given clock cap, a proposer with a coin store and whatever `seed`
    /// adds; then blocks run in order through the real executor, at
    /// timestamps the test controls.
    struct G5Chain {
        db: Arc<StateDB>,
        executor: Executor,
        proposer: String,
        cap: u64,
        height: u64,
        timestamp: u64,
        nonces: std::collections::HashMap<String, u64>,
    }

    impl G5Chain {
        fn new(name: &str, cap: u64, seed: impl FnOnce(&Arc<StateDB>)) -> Self {
            Self::with_period(name, 20, cap, seed)
        }

        /// `new` with reward period `period` (it must divide I = 20).
        fn with_period(
            name: &str,
            period: u64,
            cap: u64,
            seed: impl FnOnce(&Arc<StateDB>),
        ) -> Self {
            let db = temp_db(name);
            load_stdlib(&db);
            {
                let _seed = db.seeding();
                db.set_federation_key("00000000000000000000000000000000")
                    .unwrap();
                seed_chain_params_with(&db, (Executor::DEFAULT_EPOCH_BLOCK_INTERVAL, period, cap));
            }
            let proposer = Self::account(&db, 64, 0).1;
            seed(&db);
            seed_genesis_tree(&db);
            let executor = Executor::new(db.clone());
            Self {
                db,
                executor,
                proposer,
                cap,
                height: 0,
                timestamp: 0,
                nonces: Default::default(),
            }
        }

        /// An account from a key seed, holding `balance`.
        fn account(db: &StateDB, key_seed: u8, balance: u128) -> (SigningKey, String) {
            let key = SigningKey::from_bytes(&[key_seed; 32]);
            let address = create_account(db, &key);
            set_coin_store(db, &address, balance);
            (key, address)
        }

        /// The stored `0x1::chain::Clock`.
        fn clock(&self) -> ChainClock {
            let key = vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock");
            bcs::from_bytes(&hex::decode(self.db.get(&key).unwrap().unwrap()).unwrap()).unwrap()
        }

        /// A signed 0x1 entry call from `key`'s account with its next nonce.
        /// The leading &signer slot is bound to the sender by the executor.
        fn tx(
            &mut self,
            key: &SigningKey,
            module: &str,
            function: &str,
            args: Vec<Vec<u8>>,
        ) -> String {
            let sender = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
            let nonce = self.nonces.entry(sender.clone()).or_insert(0);
            let mut all = vec![bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap()];
            all.extend(args);
            let payload = entry_payload(module, function, vec![], all);
            let raw = signed_tx(key, &sender, &payload, *nonce, 100_000, 1);
            *nonce += 1;
            raw
        }

        /// Runs empty blocks, each a full cap apart, up to `height - 1`, then
        /// `txs` at `height` (also a cap after the previous block).
        fn run_to(&mut self, height: u64, txs: Vec<String>) {
            assert!(height > self.height, "heights only go forward");
            while self.height + 1 < height {
                self.block(self.timestamp + self.cap, vec![]);
            }
            self.block(self.timestamp + self.cap, txs);
        }

        /// Runs `count` empty blocks, each `step` seconds after the last.
        fn run_blocks(&mut self, count: u64, step: u64) {
            for _ in 0..count {
                self.block(self.timestamp + step, vec![]);
            }
        }

        /// Runs blocks, each advancing consensus time by at most the cap,
        /// until it is exactly `time`; `txs` go in the last block.
        fn run_until(&mut self, time: u64, txs: Vec<String>) {
            let mut txs = Some(txs);
            loop {
                let now = self.clock().time;
                assert!(time >= now, "consensus time only goes forward");
                let step = (time - now).min(self.cap);
                let last = now + step == time;
                let batch = if last { txs.take().unwrap() } else { vec![] };
                self.block(self.timestamp + step, batch);
                if last {
                    assert_eq!(self.clock().time, time);
                    return;
                }
            }
        }

        /// One block at `timestamp`; every tx must execute (an aborted call
        /// still executes, and pays gas).
        fn block(&mut self, timestamp: u64, txs: Vec<String>) {
            self.height += 1;
            self.timestamp = timestamp;
            let n = txs.len();
            match self.executor.execute_block_parallel_at(
                txs,
                &self.proposer,
                self.height,
                timestamp,
                &[],
            ) {
                BlockExecOutcome::Executed(s) => {
                    assert_eq!(s.executed_raws.len(), n, "every tx runs at {}", self.height)
                }
                other => panic!("height {} must execute: {other:?}", self.height),
            }
        }
    }

    fn move_addr_arg(address: &str) -> Vec<u8> {
        bcs::to_bytes(&parse_move_address(address).unwrap()).unwrap()
    }

    /// G5 CL-1 (amendment A1): consensus time is the sum of each block's
    /// timestamp growth, capped per block. Fast blocks count in full, a halt
    /// or a forged jump counts at most the cap, a timestamp that goes back
    /// counts nothing, and without Params the clock is frozen.
    #[test]
    fn g5_consensus_time_follows_timestamps_capped_per_block() {
        let db = temp_db("g5_clock");
        let _seed = db.seeding();
        seed_chain_params_with(&db, (20, 20, 14));
        let key = vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock");
        let step = |height: u64, timestamp: u64| -> ChainClock {
            let clock = next_chain_clock(&db, height, timestamp);
            let (k, v) = chain_clock_write(&db, height, timestamp);
            assert_eq!(k, key);
            assert_eq!(v, hex::encode(bcs::to_bytes(&clock).unwrap()));
            db.put(&k, &v).unwrap();
            clock
        };
        // 7 s blocks, then 1 s blocks: time follows the timestamps exactly.
        assert_eq!(
            step(1, 1_000).time,
            14,
            "the first block counts at most the cap"
        );
        assert_eq!(step(2, 1_007).time, 21);
        assert_eq!(step(3, 1_008).time, 22);
        // A 10-day halt ages consensus time by the cap only.
        let halted = step(4, 1_008 + 10 * DAY);
        assert_eq!(
            (halted.time, halted.block_timestamp),
            (36, 1_008 + 10 * DAY)
        );
        // A timestamp that goes back counts nothing and is not stored, so the
        // next growth counts from the highest timestamp seen.
        let back = step(5, 1_000);
        assert_eq!(
            (back.height, back.time, back.block_timestamp),
            (5, 36, 1_008 + 10 * DAY)
        );
        assert_eq!(step(6, 1_008 + 10 * DAY + 1).time, 37);
        // A forged stream of +1,000 s per block advances 14 s per block.
        let mut t = 1_008 + 10 * DAY + 1;
        for h in 7..17 {
            t += 1_000;
            step(h, t);
        }
        assert_eq!(step(17, t).time, 37 + 10 * 14);

        // Without Params (a fixture; boot refuses it) the clock is frozen.
        let bare = temp_db("g5_clock_bare");
        let frozen = next_chain_clock(&bare, 1, 5_000);
        assert_eq!((frozen.time, frozen.block_timestamp), (0, 5_000));
    }

    /// The Move active set: `validators` with their own stake (base units).
    fn set_active_validators(db: &StateDB, validators: &[(&str, u128)], total_supply: u128) {
        let _seed = db.seeding();
        let set = TestValidatorSet {
            validators: validators
                .iter()
                .zip(1u8..)
                .map(|((address, stake), bls_seed)| {
                    let (bls_public_key, bls_pop) = test_bls_identity(bls_seed);
                    TestValidatorConfig {
                        validator_addr: parse_move_address(address).unwrap(),
                        stake: TestCoin { value: *stake },
                        public_key: vec![1, 2, 3],
                        bls_public_key,
                        bls_pop,
                    }
                })
                .collect(),
            unbonding_queue: vec![],
            total_supply,
            current_epoch: 0,
        };
        db.put(
            &validator_set_key(),
            &hex::encode(bcs::to_bytes(&set).unwrap()),
        )
        .unwrap();
    }

    /// G5 CL-1, CL-2 and SL-2 through real blocks: a transaction reads the
    /// consensus time of the block that executes it, and an unbonding unlocks
    /// exactly U after its epoch bound (tau at leave + I x C_tau), refused one
    /// second earlier. The cap here is one day, so 21 days fit in a test.
    #[test]
    fn g5_unbonding_unlocks_exactly_at_its_time() {
        let ain = G5_AIN;
        let mut keys = vec![];
        let mut chain = G5Chain::new("g5_deadlines", DAY, |db| {
            keys.push(G5Chain::account(db, 61, ain));
            keys.push(G5Chain::account(db, 62, 10 * ain));
            keys.push(G5Chain::account(db, 63, ain));
            set_active_validators(
                db,
                &[
                    (keys[0].1.as_str(), 1_000 * ain),
                    (keys[2].1.as_str(), 1_000 * ain),
                ],
                2_000 * ain,
            );
        });
        let [(validator_key, validator), (delegator_key, delegator), (leaver_key, leaver)] =
            <[_; 3]>::try_from(keys).ok().unwrap();
        let db = chain.db.clone();

        let enable = chain.tx(
            &validator_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&500u64).unwrap()],
        );
        chain.run_to(1, vec![enable]);
        let delegate = chain.tx(
            &delegator_key,
            "delegation",
            "delegate",
            vec![
                move_addr_arg(&validator),
                bcs::to_bytes(&(5 * ain)).unwrap(),
            ],
        );
        chain.run_to(2, vec![delegate]);

        // At height 3 consensus time is 3 days; both unlock at
        // 3 d + I x C_tau (20 d) + U (21 d) = 44 d.
        let undelegate = chain.tx(
            &delegator_key,
            "delegation",
            "undelegate",
            vec![
                move_addr_arg(&validator),
                bcs::to_bytes(&(2 * ain)).unwrap(),
            ],
        );
        let leave = chain.tx(&leaver_key, "staking", "leave_validator_set", vec![]);
        chain.run_to(3, vec![undelegate, leave]);
        assert_eq!(chain.clock().time, 3 * DAY);
        let unlock = 3 * DAY + 20 * DAY + UNBONDING;
        let ticket = &book_of(&db, &delegator).tickets[0];
        assert_eq!(
            (ticket.created_epoch, ticket.unlock_time, ticket.amount),
            (0, unlock, 2 * ain)
        );
        let request = &validator_set(&db).unbonding_queue[0];
        assert_eq!((request.start_height, request.unlock_time), (3, unlock));

        // One second before the unlock both withdrawals are refused.
        let withdraw = chain.tx(
            &delegator_key,
            "delegation",
            "withdraw_unbonded",
            vec![move_addr_arg(&validator)],
        );
        let exit = chain.tx(&leaver_key, "staking", "withdraw_unbonded", vec![]);
        chain.run_until(unlock - 1, vec![withdraw, exit]);
        assert_eq!(book_of(&db, &delegator).tickets.len(), 1, "unlocked early");
        assert_eq!(
            validator_set(&db).unbonding_queue.len(),
            1,
            "unlocked early"
        );

        // At the unlock both pay out.
        let delegator_before = coin_balance(&db, &delegator);
        let leaver_before = coin_balance(&db, &leaver);
        let withdraw = chain.tx(
            &delegator_key,
            "delegation",
            "withdraw_unbonded",
            vec![move_addr_arg(&validator)],
        );
        let exit = chain.tx(&leaver_key, "staking", "withdraw_unbonded", vec![]);
        chain.run_until(unlock, vec![withdraw, exit]);
        assert!(
            chain.height < 60,
            "paid by the withdrawals, not by a boundary"
        );
        assert!(book_of(&db, &delegator).tickets.is_empty());
        let pool = pool_of(&db, &validator);
        assert_eq!(
            (pool.principal, pool.active_coins, pool.unbonding_coins),
            (3 * ain, 3 * ain, 0)
        );
        assert!(validator_set(&db).unbonding_queue.is_empty());
        // Each got its stake back less a gas fee below the 100,000 limit.
        let gained = |before: u128, a: &str| coin_balance(&db, a) - before;
        assert!((2 * ain - 100_000..2 * ain).contains(&gained(delegator_before, &delegator)));
        assert!((1_000 * ain - 100_000..1_000 * ain).contains(&gained(leaver_before, &leaver)));
    }

    /// G5 CM-1: an increase takes effect exactly N after its announcement,
    /// never earlier; it may raise the rate in force by at most 500 bps; a
    /// matured increase no payout has charged yet cannot be raised on (that
    /// would charge the unpaid period at the new rate), one period later it
    /// can; a decrease applies at once and cancels a pending increase.
    /// Payouts run every block (R = 1).
    #[test]
    fn g5_commission_increase_waits_its_notice_and_is_capped() {
        let ain = G5_AIN;
        let mut keys = vec![];
        let mut chain = G5Chain::with_period("g5_commission", 1, DAY, |db| {
            keys.push(G5Chain::account(db, 81, ain));
            // Payouts (which the settlement waits on) need the Move supply.
            set_active_validators(db, &[], 1_000_000 * ain);
        });
        let (validator_key, validator) = keys.pop().unwrap();
        let db = chain.db.clone();
        let pool = || {
            let p = pool_of(&db, &validator);
            (
                p.commission_rate,
                p.pending_commission,
                p.commission_effective_time,
            )
        };
        let announce = |chain: &mut G5Chain, bps: u64| {
            chain.tx(
                &validator_key,
                "delegation",
                "update_commission",
                vec![bcs::to_bytes(&bps).unwrap()],
            )
        };

        let enable = chain.tx(
            &validator_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&500u64).unwrap()],
        );
        chain.run_to(1, vec![enable]);
        // +600 bps is over the cap: refused, nothing pending.
        let over = announce(&mut chain, 1_100);
        chain.run_to(2, vec![over]);
        assert_eq!(pool(), (500, 500, 0));
        // +500 bps at 3 d takes effect at 3 d + N.
        let raise = announce(&mut chain, 1_000);
        chain.run_to(3, vec![raise]);
        let effective = 3 * DAY + NOTICE;
        assert_eq!(pool(), (500, 1_000, effective));
        // One second early the rate in force is still 500, so a further raise
        // to 1,500 is over the cap and refused.
        let early = announce(&mut chain, 1_500);
        chain.run_until(effective - 1, vec![early]);
        assert_eq!(
            pool(),
            (500, 1_000, effective),
            "the increase applied early"
        );
        // At the effective time the rate in force is 1,000, but the last
        // payout (effective - 1) has not charged it: a raise to 1,500 would
        // charge the unpaid period at 1,000 as the base. Refused.
        let unsettled = announce(&mut chain, 1_500);
        chain.run_until(effective, vec![unsettled]);
        assert_eq!(
            pool(),
            (500, 1_000, effective),
            "a raise on an uncharged increase"
        );
        // One block later the payout at `effective` has charged it: +500 on
        // 1,000 is accepted.
        let settled = announce(&mut chain, 1_500);
        chain.run_to(chain.height + 1, vec![settled]);
        let now = chain.clock().time;
        assert_eq!(pool(), (1_000, 1_500, now + NOTICE));
        // A decrease applies at once and cancels the pending increase.
        let cut = announce(&mut chain, 300);
        chain.run_to(chain.height + 1, vec![cut]);
        assert_eq!(pool(), (300, 300, 0));
    }

    /// A G5 chain for delegation (DL-1..DL-3): validators from key seeds with
    /// their own stake in whole AIN, each in the genesis committee, the live
    /// set and the Move active set, with 10 AIN for gas; funded delegators;
    /// the Epoch resource, so boundaries run the real Move epoch advance.
    /// Reward period `period`, clock cap `cap`. The Move supply starts at
    /// 1,000,000 AIN.
    #[allow(clippy::type_complexity)]
    fn delegation_chain(
        name: &str,
        period: u64,
        cap: u64,
        validators: &[(u8, u64)],
        delegators: &[(u8, u128)],
    ) -> (
        G5Chain,
        Vec<(SigningKey, String)>,
        Vec<(SigningKey, String)>,
    ) {
        let mut vals = vec![];
        let mut dels = vec![];
        let chain = G5Chain::with_period(name, period, cap, |db| {
            let mut members = vec![];
            for (seed, own) in validators {
                let account = G5Chain::account(db, *seed, 10 * G5_AIN);
                let member = committee_member(*seed, *own);
                assert_eq!(member.address, account.1);
                members.push(member);
                vals.push(account);
            }
            for (seed, balance) in delegators {
                dels.push(G5Chain::account(db, *seed, *balance));
            }
            let own: Vec<(&str, u128)> = validators
                .iter()
                .zip(&vals)
                .map(|((_, stake), (_, address))| (address.as_str(), *stake as u128 * G5_AIN))
                .collect();
            set_active_validators(db, &own, 1_000_000 * G5_AIN);
            let _seed = db.seeding();
            let members = blockchain::committee::canonical_order(&members);
            for key in ["genesis:validator_set:v1", "sys:validator_set:v1"] {
                db.put(key, &serde_json::to_string(&members).unwrap())
                    .unwrap();
            }
            db.put(
                &vm_move::state_keys::resource_key_str(&system_address(), "0x1::epoch::Epoch"),
                &hex::encode(bcs::to_bytes(&0u64).unwrap()),
            )
            .unwrap();
        });
        (chain, vals, dels)
    }

    /// Cumulative minted AIN, the emission's anchor (net supply plus burned).
    fn g5_minted(db: &StateDB) -> u128 {
        let burned = db
            .get(&supply_stats_key())
            .unwrap()
            .and_then(|raw| decode_supply_stats_hex(&raw))
            .map(|stats| stats.cumulative_burned)
            .unwrap_or(0);
        validator_set(db).total_supply + burned
    }

    /// G5 DL-2: what a member's share `r` splits into, for own weight `s`,
    /// delegated weight `d` and commission `bps`: (own part + commission,
    /// the pool's part).
    fn g5_split(r: u128, s: u128, d: u128, bps: u128) -> (u128, u128) {
        let own = r * s / (s + d);
        let delegated = r * d / (s + d);
        let commission = delegated * bps / 10_000;
        (own + commission, delegated - commission)
    }

    /// Runs one empty block `step` seconds after the last, whose payout
    /// (R = 1) pays `validator`, the only committee member, with the split
    /// `(s, d)` at `bps`; checks both parts to the unit and returns the pool's.
    fn g5_paid_block(
        chain: &mut G5Chain,
        validator: &str,
        step: u64,
        s: u128,
        d: u128,
        bps: u128,
    ) -> u128 {
        let db = chain.db.clone();
        let e = g5_expected_emission(g5_minted(&db), step);
        let (own, to_pool) = g5_split(e, s, d, bps);
        let (balance, rewards) = (
            coin_balance(&db, validator),
            pool_of(&db, validator).rewards,
        );
        chain.run_blocks(1, step);
        assert_eq!(
            coin_balance(&db, validator) - balance,
            own,
            "own part and commission at height {}",
            chain.height
        );
        assert_eq!(
            pool_of(&db, validator).rewards - rewards,
            to_pool,
            "the pool's part at height {}",
            chain.height
        );
        to_pool
    }

    /// floor(a x b / c) in u256, as Move's `math::mul_div_floor`.
    fn g5_mul_div(a: u128, b: u128, c: u128) -> u128 {
        use move_core_types::u256::U256;
        (U256::from(a) * U256::from(b) / U256::from(c)).unchecked_as_u128()
    }

    fn g5_committee(db: &StateDB, epoch: u64) -> Vec<(String, u64)> {
        let raw = db
            .get(&format!("sys:validator_set:epoch:{epoch}"))
            .unwrap()
            .unwrap();
        serde_json::from_str::<Vec<blockchain::committee::ValidatorInfo>>(&raw)
            .unwrap()
            .into_iter()
            .map(|m| (m.address, m.stake))
            .collect()
    }

    fn g5_split_record(db: &StateDB, epoch: u64) -> Option<BTreeMap<String, u64>> {
        db.get(&delegated_split_key(epoch))
            .unwrap()
            .map(|raw| serde_json::from_str(&raw).unwrap())
    }

    /// G5 DL-1, DL-2 through real blocks (R = 1, 7 s blocks). A delegation
    /// weighs the committee from the next epoch only, recorded with its
    /// split. Each payout splits the member's share by that frozen split: own
    /// part and commission to the validator, the rest to the pool's counter
    /// with its remainder carried, so rho x P + kappa = S x (rewards minted)
    /// exactly. A joiner mid-epoch starts at the current counter, so it is
    /// paid nothing from before, and the split does not follow the live pool.
    /// A claim takes exactly floor(p x (rho - snapshot) / S) from the escrow.
    /// Principal = C + B, and the points add up.
    #[test]
    fn g5_delegators_are_paid_by_points_from_the_frozen_split() {
        use move_core_types::u256::U256;
        let ain = G5_AIN;
        let (mut chain, validators, delegators) = delegation_chain(
            "g5_dl_payout",
            1,
            14,
            &[(121, 1_000)],
            &[(122, 10_000 * ain), (123, 10_000 * ain)],
        );
        let (validator_key, validator) = &validators[0];
        let [(a_key, a), (b_key, b)] = <[_; 2]>::try_from(delegators).ok().unwrap();
        let db = chain.db.clone();
        let delegate = |chain: &mut G5Chain, key: &SigningKey, amount: u128| {
            chain.tx(
                key,
                "delegation",
                "delegate",
                vec![move_addr_arg(validator), bcs::to_bytes(&amount).unwrap()],
            )
        };

        let enable = chain.tx(
            validator_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&1_000u64).unwrap()],
        );
        chain.block(7, vec![enable]);
        let join_a = delegate(&mut chain, &a_key, 3_000 * ain);
        chain.block(14, vec![join_a]);
        chain.run_blocks(18, 7);
        assert_eq!(chain.height, 20);
        // DL-1: epoch 0 paid the validator's own stake alone.
        assert_eq!(
            pool_of(&db, validator).rewards,
            0,
            "the pool weighs from epoch 1"
        );
        assert!(g5_split_record(&db, 0).is_none());
        // At H_0 the committee of epoch 1 is recorded with the bonded weight
        // and the delegated part.
        assert_eq!(g5_committee(&db, 1), vec![(validator.clone(), 4_000)]);
        assert_eq!(
            g5_split_record(&db, 1),
            Some(BTreeMap::from([(validator.clone(), 3_000)]))
        );

        // 21..29: every payout splits 1,000 : 3,000 at 10 %, and the counter
        // carries its remainder exactly.
        let scale = U256::from(COIN_SCALE);
        for _ in 21..30 {
            g5_paid_block(&mut chain, validator, 7, 1_000, 3_000, 1_000);
            let pool = pool_of(&db, validator);
            assert_eq!(
                U256::from(pool.reward_counter) * U256::from(pool.active_points)
                    + U256::from(pool.reward_carry),
                U256::from(pool.rewards) * scale,
                "rho x P + kappa = S x minted at height {}",
                chain.height
            );
        }

        // 30: B joins mid-epoch at the current counter.
        let rho_before = pool_of(&db, validator).reward_counter;
        let join_b = delegate(&mut chain, &b_key, 1_000 * ain);
        chain.block(chain.timestamp + 7, vec![join_b]);
        assert_eq!(
            book_of(&db, &b).positions[0].reward_snapshot,
            rho_before,
            "a joiner is paid nothing from before it joined"
        );
        assert_eq!(
            g5_committee(&db, 1),
            vec![(validator.clone(), 4_000)],
            "weight changes at the next epoch only"
        );
        // 31: the split is still epoch 1's 1,000 : 3,000, not the live 1,000 : 4,000.
        g5_paid_block(&mut chain, validator, 7, 1_000, 3_000, 1_000);

        // Each owes floor(p x (rho - snapshot) / S); A claims exactly that.
        let pool = pool_of(&db, validator);
        let (position_a, position_b) = (
            book_of(&db, &a).positions[0].clone(),
            book_of(&db, &b).positions[0].clone(),
        );
        let owed_a = g5_mul_div(position_a.points, pool.reward_counter, COIN_SCALE);
        let owed_b = g5_mul_div(
            position_b.points,
            pool.reward_counter - rho_before,
            COIN_SCALE,
        );
        assert_eq!(pool.position_value(&position_a), (3_000 * ain, owed_a));
        assert_eq!(pool.position_value(&position_b), (1_000 * ain, owed_b));
        assert!(
            owed_b > 0 && owed_b < owed_a / 3,
            "B earned two payouts, A twelve"
        );
        let e = g5_expected_emission(g5_minted(&db), 7);
        let (_, to_pool) = g5_split(e, 1_000, 3_000, 1_000);
        let claim = chain.tx(
            &a_key,
            "delegation",
            "claim_rewards",
            vec![move_addr_arg(validator)],
        );
        chain.block(chain.timestamp + 7, vec![claim]);
        let after = pool_of(&db, validator);
        assert_eq!(
            after.rewards,
            pool.rewards - owed_a + to_pool,
            "the claim took exactly its due"
        );
        assert_eq!(
            book_of(&db, &a).positions[0].reward_snapshot,
            pool.reward_counter
        );

        // Conservation.
        let points = book_of(&db, &a).positions[0].points + book_of(&db, &b).positions[0].points;
        assert_eq!(points, after.active_points);
        assert_eq!(after.principal, after.active_coins + after.unbonding_coins);
        assert_eq!(after.position_count, 2);
        let owed: u128 = [&a, &b]
            .iter()
            .map(|d| after.position_value(&book_of(&db, d).positions[0]).1)
            .sum();
        // The escrow also holds the carry kappa / S < P / S base units not yet
        // on the counter, and the flooring of each claim and position.
        assert!(owed <= after.rewards, "the escrow covers every claim");
        assert!(
            after.rewards - owed <= after.active_points / COIN_SCALE + 3,
            "within dust: {} over",
            after.rewards - owed
        );

        // H_1: epoch 2 weighs B too.
        chain.run_blocks(40 - chain.height, 7);
        assert_eq!(g5_committee(&db, 2), vec![(validator.clone(), 5_000)]);
        assert_eq!(
            g5_split_record(&db, 2),
            Some(BTreeMap::from([(validator.clone(), 4_000)]))
        );
    }

    /// G5 CM-1 in the payout (R = 1, one-day blocks, so each payout covers
    /// one day): a raise announced at 21 d takes effect at 28 d; the payout
    /// at 28 d covers (27 d, 28 d] and charges the old rate, the one at 29 d
    /// the new one. While a matured raise is uncharged, a change above the
    /// base rate is refused and one down to it is taken; a decrease applies
    /// to the very next payout.
    #[test]
    fn g5_commission_is_charged_at_the_rate_in_force_when_the_period_began() {
        let ain = G5_AIN;
        let (mut chain, validators, delegators) = delegation_chain(
            "g5_dl_commission",
            1,
            DAY,
            &[(124, 1_000)],
            &[(125, 10_000 * ain)],
        );
        let (validator_key, validator) = &validators[0];
        let (a_key, _) = &delegators[0];
        let db = chain.db.clone();
        let announce = |chain: &mut G5Chain, bps: u64| {
            chain.tx(
                validator_key,
                "delegation",
                "update_commission",
                vec![bcs::to_bytes(&bps).unwrap()],
            )
        };
        let rates = || {
            let p = pool_of(&db, validator);
            (
                p.commission_rate,
                p.pending_commission,
                p.commission_effective_time,
            )
        };

        let enable = chain.tx(
            validator_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&1_000u64).unwrap()],
        );
        chain.run_to(1, vec![enable]);
        let join = chain.tx(
            a_key,
            "delegation",
            "delegate",
            vec![
                move_addr_arg(validator),
                bcs::to_bytes(&(3_000 * ain)).unwrap(),
            ],
        );
        chain.run_to(2, vec![join]);
        chain.run_to(20, vec![]);
        let raise = announce(&mut chain, 1_500);
        chain.run_to(21, vec![raise]);
        assert_eq!(chain.clock().time, 21 * DAY);
        assert_eq!(rates(), (1_000, 1_500, 28 * DAY));
        chain.run_to(27, vec![]);
        // 28: the period began at 27 d, before the raise: 10 %.
        g5_paid_block(&mut chain, validator, DAY, 1_000, 3_000, 1_000);
        // 29: the period began at 28 d: 15 %.
        g5_paid_block(&mut chain, validator, DAY, 1_000, 3_000, 1_500);
        // 30: the raise has been charged, so +500 on it is taken.
        let again = announce(&mut chain, 2_000);
        chain.run_to(30, vec![again]);
        assert_eq!(rates(), (1_500, 2_000, 37 * DAY));
        chain.run_to(36, vec![]);
        // 37: 2,000 is in force but uncharged. 1,800 (above the 1,500 base)
        // is refused; 1,200 (below it) is taken, at once.
        let between = announce(&mut chain, 1_800);
        let down = announce(&mut chain, 1_200);
        chain.run_to(37, vec![between, down]);
        assert_eq!(rates(), (1_200, 1_200, 0));
        g5_paid_block(&mut chain, validator, DAY, 1_000, 3_000, 1_200);
    }

    /// Mirror of the Move `0x1::delegation::Offense` (G5 SL-5).
    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct TestOffense {
        validator: move_core_types::account_address::AccountAddress,
        epoch: u64,
        epoch_began: u64,
        weight: u64,
        committee_weight: u64,
        self_weight: u64,
        delegated_weight: u64,
        settled: bool,
    }

    /// The offense ledger (`0x1::delegation::Offenses`), empty when absent.
    fn g5_offenses(db: &StateDB) -> Vec<TestOffense> {
        db.get(&vm_move::state_keys::resource_key_str(
            &system_address(),
            "0x1::delegation::Offenses",
        ))
        .unwrap()
        .map(|raw| bcs::from_bytes(&hex::decode(raw).unwrap()).unwrap())
        .unwrap_or_default()
    }

    fn g5_offense(db: &StateDB, validator: &str) -> TestOffense {
        let want = parse_move_address(validator).unwrap();
        g5_offenses(db)
            .into_iter()
            .find(|o| o.validator == want)
            .expect("the offense is recorded")
    }

    /// Accepts equivocation evidence against `validator` in committee epoch
    /// `epoch` between blocks, through the executor's acceptance path.
    fn g5_report(chain: &G5Chain, validator: &str, epoch: u64, round: u64) {
        let _seed = chain.db.seeding();
        chain
            .db
            .put(
                &format!("sys:pending_slash:{validator}"),
                &serde_json::json!({ "round": round, "epoch": epoch }).to_string(),
            )
            .unwrap();
        chain.executor.execute_pending_slashes();
    }

    /// A validator's own unbonding entries: (start height, stake).
    fn g5_own_unbonding(db: &StateDB, validator: &str) -> Vec<(u64, u128)> {
        let want = parse_move_address(validator).unwrap();
        validator_set(db)
            .unbonding_queue
            .iter()
            .filter(|r| r.validator_addr == want)
            .map(|r| (r.start_height, r.stake))
            .collect()
    }

    fn g5_burned(db: &StateDB) -> u128 {
        db.get(&supply_stats_key())
            .unwrap()
            .and_then(|raw| decode_supply_stats_hex(&raw))
            .map(|stats| stats.cumulative_burned)
            .unwrap_or(0)
    }

    /// G5 SL-4, SL-5 through real blocks (R = 1, one-day blocks, 7 equal
    /// validators). Offenses count together when their epochs began within
    /// D. Two in epoch 0 cost (6/7)^2 = 73.47 % each, but only once
    /// D + I x C_tau + W = 28 d has passed since epoch 0 began, when every
    /// correlated offense's evidence has landed. A lone offense in epoch 1,
    /// 20 days later, is not raised by them (36 %, still pending); a second
    /// one in its epoch makes a third of that committee, 100 % at once for
    /// both. A leaver that equivocates before its unlock loses its unbonding
    /// stake.
    #[test]
    fn g5_a_slash_settles_by_the_weight_that_equivocated_together() {
        let ain = G5_AIN;
        let seeds: Vec<(u8, u64)> = (160..167).map(|seed| (seed, 1_000)).collect();
        let (mut chain, validators, _) = delegation_chain("g5_sl_correlated", 1, DAY, &seeds, &[]);
        let db = chain.db.clone();
        let v = |i: usize| validators[i].1.clone();

        // V0 leaves at height 3, in epoch 0, which it could still sign.
        let leave = chain.tx(&validators[0].0, "staking", "leave_validator_set", vec![]);
        chain.run_to(3, vec![leave]);
        chain.run_to(5, vec![]);
        let burned = g5_burned(&db);
        g5_report(&chain, &v(0), 0, 1);
        g5_report(&chain, &v(1), 0, 1);
        // 2,000 of 7,000 is below a third: recorded, not settled, nothing
        // burned. V1's whole stake is unbonding.
        assert!(!g5_offense(&db, &v(0)).settled && !g5_offense(&db, &v(1)).settled);
        assert_eq!(g5_own_unbonding(&db, &v(0)), vec![(3, 1_000 * ain)]);
        assert_eq!(g5_own_unbonding(&db, &v(1)), vec![(5, 1_000 * ain)]);
        assert_eq!(g5_burned(&db), burned);

        chain.run_to(21, vec![]);
        assert_eq!(g5_committee(&db, 1).len(), 5, "the offenders left C_1");
        g5_report(&chain, &v(2), 1, 21);
        // Alone within D: 1,000 of 5,000 is 36 %, not final yet.
        assert!(!g5_offense(&db, &v(2)).settled);
        assert_eq!(g5_own_unbonding(&db, &v(2)), vec![(21, 1_000 * ain)]);
        chain.run_to(22, vec![]);
        g5_report(&chain, &v(3), 1, 22);
        // 2,000 of 5,000 within D: a third, so 100 % at once for both.
        assert!(g5_offense(&db, &v(2)).settled && g5_offense(&db, &v(3)).settled);
        assert_eq!(g5_own_unbonding(&db, &v(2)), vec![(21, 0)]);
        assert_eq!(g5_own_unbonding(&db, &v(3)), vec![(22, 0)]);
        assert_eq!(g5_burned(&db), burned + 2_000 * ain);

        // Epoch 0's pair settles at 28 d exactly, not a block earlier.
        chain.run_to(27, vec![]);
        assert_eq!(chain.clock().time, 27 * DAY);
        assert!(!g5_offense(&db, &v(0)).settled);
        assert_eq!(g5_own_unbonding(&db, &v(0)), vec![(3, 1_000 * ain)]);
        chain.run_to(28, vec![]);
        let kept = 1_000 * ain - 1_000 * ain * 7_347 / 10_000;
        assert_eq!(g5_own_unbonding(&db, &v(0)), vec![(3, kept)]);
        assert_eq!(g5_own_unbonding(&db, &v(1)), vec![(5, kept)]);
        assert_eq!(
            g5_burned(&db),
            burned + 2_000 * ain + 2 * (1_000 * ain - kept)
        );
        // Every in-scope entry was still unpaid at settlement: the earliest
        // unlocks at 3 d + I x C_tau + U = 44 d.
        let unlocks: Vec<u64> = validator_set(&db)
            .unbonding_queue
            .iter()
            .map(|r| r.unlock_time)
            .collect();
        assert!(unlocks.iter().all(|u| *u >= 44 * DAY));
    }

    /// G5 SL-6 and SL-1 through real blocks (R = 1, one-day blocks). Five
    /// validators of 3,000, V6 (own 1,000, pool 3,100) and V7 (own 1,000,
    /// pool 500) weigh 20,600 in epoch 1. V6 and V7 equivocate in epoch 1:
    /// Q = 5,600, f = ceil(9e4 x 5,600^2 / 20,600^2) = 6,651 bps.
    /// - V7: A = 0.6651 x 1,500 AIN is below its own 1,000, so the operator
    ///   pays 99.77 % and its delegators nothing.
    /// - V6: A = 0.6651 x 4,100 exceeds its own 1,000: own 100 %, pool
    ///   ceil((27,269,100 - 10,000,000) / 3,100) = 5,571 bps.
    /// - An own entry from before the offense epoch is out of scope.
    /// - Tickets: one from epoch 0 is not cut; ones from epoch 1, before or
    ///   after acceptance, are; one made after settlement is not cut twice,
    ///   even while the event still waits for the others.
    #[test]
    fn g5_the_operator_pays_first_and_only_in_scope_stake() {
        let ain = G5_AIN;
        let mut seeds: Vec<(u8, u64)> = (170..175).map(|seed| (seed, 3_000)).collect();
        seeds.extend([(175u8, 1_000u64), (176, 1_000)]);
        let (mut chain, validators, delegators) = delegation_chain(
            "g5_sl_waterfall",
            1,
            DAY,
            &seeds,
            &[(177, 1_000 * ain), (178, 4_000 * ain), (179, 1_000 * ain)],
        );
        let db = chain.db.clone();
        let (v6_key, v6) = &validators[5];
        let (v7_key, v7) = &validators[6];
        let [(a_key, _), (b_key, b), (c_key, c)] = <[_; 3]>::try_from(delegators).ok().unwrap();
        let call = |chain: &mut G5Chain,
                    key: &SigningKey,
                    pool: &str,
                    function: &str,
                    amount: Option<u128>| {
            let mut args = vec![move_addr_arg(pool)];
            args.extend(amount.map(|a| bcs::to_bytes(&a).unwrap()));
            chain.tx(key, "delegation", function, args)
        };
        let enable = |chain: &mut G5Chain, key: &SigningKey| {
            chain.tx(
                key,
                "delegation",
                "enable_delegation",
                vec![bcs::to_bytes(&0u64).unwrap()],
            )
        };

        let opens = vec![enable(&mut chain, v6_key), enable(&mut chain, v7_key)];
        chain.run_to(1, opens);
        let joins = vec![
            call(&mut chain, &a_key, v7, "delegate", Some(500 * ain)),
            call(&mut chain, &b_key, v6, "delegate", Some(3_100 * ain)),
            call(&mut chain, &c_key, v6, "delegate", Some(100 * ain)),
        ];
        chain.run_to(2, joins);
        let t0 = call(&mut chain, &b_key, v6, "undelegate", Some(100 * ain));
        chain.run_to(3, vec![t0]);
        // An own entry of V7 from epoch 0 (a fixture): out of scope.
        {
            let _seed = db.seeding();
            let mut set = validator_set(&db);
            set.unbonding_queue.push(TestUnbondingRequest {
                validator_addr: parse_move_address(v7).unwrap(),
                stake: 50 * ain,
                start_height: 1,
                unlock_time: u64::MAX / 2,
            });
            db.put(
                &validator_set_key(),
                &hex::encode(bcs::to_bytes(&set).unwrap()),
            )
            .unwrap();
        }
        chain.run_to(20, vec![]);
        let weight = |a: &str| {
            g5_committee(&db, 1)
                .into_iter()
                .find(|m| m.0 == a)
                .unwrap()
                .1
        };
        assert_eq!((weight(v6), weight(v7)), (4_100, 1_500));

        let t1 = call(&mut chain, &b_key, v6, "undelegate", Some(100 * ain));
        chain.run_to(21, vec![t1]);
        g5_report(&chain, v7, 1, 21);
        g5_report(&chain, v6, 1, 21);
        assert!(
            !g5_offense(&db, v6).settled,
            "5,600 of 20,600 is below a third"
        );
        let t2 = call(&mut chain, &b_key, v6, "undelegate", Some(100 * ain));
        chain.run_to(23, vec![t2]);

        // Epoch 1 began at 20 d: settlement at 48 d.
        chain.run_to(47, vec![]);
        assert!(!g5_offense(&db, v6).settled);
        chain.run_to(48, vec![]);
        assert!(g5_offense(&db, v6).settled && g5_offense(&db, v7).settled);
        let mut v7_entries = g5_own_unbonding(&db, v7);
        v7_entries.sort();
        assert_eq!(
            v7_entries,
            vec![
                (1, 50 * ain),
                (21, 1_000 * ain - 1_000 * ain * 9_977 / 10_000)
            ],
            "own pays 99.77 %; the epoch-0 entry is out of scope"
        );
        let v7_pool = pool_of(&db, v7);
        assert_eq!(
            v7_pool.active_coins,
            500 * ain,
            "V7's delegators pay nothing"
        );
        assert!(v7_pool.closed);
        assert_eq!(g5_own_unbonding(&db, v6), vec![(21, 0)]);
        let v6_pool = pool_of(&db, v6);
        let active = 2_900 * ain - 2_900 * ain * 5_571 / 10_000;
        assert_eq!(v6_pool.active_coins, active);
        assert_eq!(
            v6_pool.slash_events,
            vec![DelegationSlashEvent {
                seq: 0,
                infraction_epoch: 1,
                bps: 5_571,
                pending_tickets: 3,
            }]
        );

        // C leaves in full after settlement, at the slashed price.
        let t3 = call(&mut chain, &c_key, v6, "undelegate", Some(1_000 * ain));
        chain.run_to(49, vec![t3]);
        let x3 = g5_mul_div(100 * ain, active, 2_900 * ain);
        assert_eq!(book_of(&db, &c).tickets[0].amount, x3);
        // All unlock by 49 d + I x C_tau + U = 90 d. C is paid first, while
        // the event still waits for B's three tickets: in full.
        chain.run_until(90 * DAY, vec![]);
        let c_before = coin_balance(&db, &c);
        let withdraw_c = call(&mut chain, &c_key, v6, "withdraw_unbonded", None);
        chain.run_to(chain.height + 1, vec![withdraw_c]);
        let gained_c = coin_balance(&db, &c) - c_before;
        assert!(
            (x3 - 100_000..=x3).contains(&gained_c),
            "{gained_c} vs {x3}"
        );
        assert_eq!(pool_of(&db, v6).slash_events[0].pending_tickets, 3);
        // B: t0 (epoch 0) in full; t1 and t2 (epoch 1) cut 55.71 %.
        let b_before = coin_balance(&db, &b);
        let withdraw_b = call(&mut chain, &b_key, v6, "withdraw_unbonded", None);
        chain.run_to(chain.height + 1, vec![withdraw_b]);
        let paid_b = 100 * ain + 2 * (100 * ain * 4_429 / 10_000);
        let gained_b = coin_balance(&db, &b) - b_before;
        assert!(
            (paid_b - 100_000..=paid_b).contains(&gained_b),
            "{gained_b} vs {paid_b}"
        );
        let v6_pool = pool_of(&db, v6);
        assert!(
            v6_pool.slash_events.is_empty(),
            "no ticket can meet it any more"
        );
        assert_eq!(
            v6_pool.principal,
            v6_pool.active_coins + v6_pool.unbonding_coins
        );
    }

    /// G5 SL-3 and SL-5 (tombstone and refusals): a second offense by the
    /// same validator is ignored; evidence for an epoch whose committee does
    /// not hold the validator is refused and changes nothing; a closed pool
    /// takes no delegation even with its validator active again; and a
    /// tombstoned validator's join is refused, while the same join from a
    /// fresh key is accepted.
    #[test]
    fn g5_a_tombstoned_validator_is_slashed_once_and_never_rejoins() {
        let ain = G5_AIN;
        let seeds: Vec<(u8, u64)> = (180..184).map(|seed| (seed, 1_000)).collect();
        let (mut chain, validators, delegators) = delegation_chain(
            "g5_sl_tombstone",
            20,
            14,
            &seeds,
            &[(184, 3_000 * ain), (185, 100 * ain)],
        );
        let db = chain.db.clone();
        let (v0_key, v0) = &validators[0];
        let v1 = &validators[1].1;
        let (fresh_key, _) = &delegators[0];
        let (d_key, _) = &delegators[1];
        {
            let _seed = db.seeding();
            set_coin_store(&db, v0, 3_000 * ain);
        }
        let enable = chain.tx(
            v0_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&0u64).unwrap()],
        );
        chain.run_to(1, vec![enable]);
        g5_report(&chain, v0, 0, 7);
        g5_report(&chain, v0, 0, 8);
        assert_eq!(g5_offenses(&db).len(), 1, "one offense per validator");
        assert_eq!(
            g5_own_unbonding(&db, v0),
            vec![(1, 1_000 * ain)],
            "one removal"
        );
        // V1 is in no committee of epoch 3 (no such record): refused.
        g5_report(&chain, v1, 3, 9);
        assert_eq!(g5_offenses(&db).len(), 1);
        assert!(db.get(&format!("validator:jailed:{v1}")).unwrap().is_none());
        assert!(validator_set(&db)
            .validators
            .iter()
            .any(|c| c.validator_addr == parse_move_address(v1).unwrap()));

        let join = |chain: &mut G5Chain, key: &SigningKey, seed: u8| {
            let (bls_public_key, bls_pop) = test_bls_identity(seed);
            chain.tx(
                key,
                "staking",
                "join_validator_set",
                vec![
                    bcs::to_bytes(&(1_000 * ain)).unwrap(),
                    bcs::to_bytes(&key.verifying_key().to_bytes().to_vec()).unwrap(),
                    bcs::to_bytes(&bls_public_key).unwrap(),
                    bcs::to_bytes(&bls_pop).unwrap(),
                ],
            )
        };
        // A fresh key joins; the tombstoned one is refused before execution.
        let fresh = join(&mut chain, fresh_key, 184);
        chain.run_to(2, vec![fresh]);
        let refused = join(&mut chain, v0_key, 180);
        chain.height += 1;
        chain.timestamp += 14;
        let outcome = chain.executor.execute_block_parallel_at(
            vec![refused],
            &chain.proposer.clone(),
            chain.height,
            chain.timestamp,
            &[],
        );
        match outcome {
            BlockExecOutcome::Executed(s) => assert!(s.executed_raws.is_empty(), "the join ran"),
            other => panic!("the block must execute: {other:?}"),
        }
        let active: Vec<_> = validator_set(&db)
            .validators
            .iter()
            .map(|c| c.validator_addr)
            .collect();
        assert!(!active.contains(&parse_move_address(v0).unwrap()));
        assert_eq!(active.len(), 4, "V1, V2, V3 and the fresh joiner");
        // V0 is back in the Move set only as a fixture: its pool stays closed.
        set_active_validators(
            &db,
            &[(v0.as_str(), 1_000 * ain)],
            validator_set(&db).total_supply,
        );
        let refused = chain.tx(
            d_key,
            "delegation",
            "delegate",
            vec![move_addr_arg(v0), bcs::to_bytes(&(10 * ain)).unwrap()],
        );
        chain.run_to(chain.height + 1, vec![refused]);
        assert_eq!(
            pool_of(&db, v0).active_coins,
            0,
            "a closed pool takes no delegation"
        );
    }

    /// A V4 vertex of `key`'s account at (epoch, round), hashed under this
    /// chain's domain and `genesis_identity`, and signed.
    fn g5_v4_vertex(
        key: &SigningKey,
        epoch: u64,
        round: u64,
        payload: &str,
        genesis_identity: &str,
    ) -> blockchain::Vertex {
        let author = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let mut v =
            blockchain::Vertex::new(round, author, vec!["genesis".into()], vec![payload.into()]);
        v.epoch = epoch;
        v.hash = v.hash_v4_with_domain(&blockchain::chain_id(), genesis_identity);
        v.sign_with_ed25519(key);
        v
    }

    /// G5 SL-3, G1 EQ-1: a V4 proposer-twin pair is checked against the
    /// committee of its epoch, never the live set, and is refused once
    /// older than W: tau > tau_start(E+1) + W. Accepted, it records the
    /// offense in the evidence's own epoch.
    #[test]
    fn g5_v4_twin_evidence_is_checked_against_its_committee_and_age() {
        let ain = G5_AIN;
        let seeds: Vec<(u8, u64)> = (190..194).map(|seed| (seed, 1_000)).collect();
        let (mut chain, validators, _) =
            delegation_chain("g5_sl_v4_evidence", 20, DAY, &seeds, &[]);
        let db = chain.db.clone();
        let gi = "g5-v4-evidence-genesis";
        {
            let _seed = db.seeding();
            db.put("genesis_identity", gi).unwrap();
        }
        let (key, offender) = (&validators[1].0, validators[1].1.clone());
        let item = |a: &blockchain::Vertex, b: &blockchain::Vertex| consensus_evidence_item(a, b);
        let (a, b) = (
            g5_v4_vertex(key, 0, 5, "a", gi),
            g5_v4_vertex(key, 0, 5, "b", gi),
        );
        let ok = chain
            .executor
            .verify_slash_evidence(&item(&a, &b))
            .expect("valid twins");
        assert_eq!(
            ok,
            VerifiedEvidence {
                offender: offender.clone(),
                kind: "equivocation_v4".into(),
                epoch: 0,
                round: 5,
            }
        );
        // Not twins: one vertex twice, or two slots.
        assert!(chain.executor.verify_slash_evidence(&item(&a, &a)).is_err());
        let other_round = g5_v4_vertex(key, 0, 6, "b", gi);
        assert!(chain
            .executor
            .verify_slash_evidence(&item(&a, &other_round))
            .is_err());
        // A key outside C_0 signs nothing that counts, even as a live validator.
        let outsider = SigningKey::from_bytes(&[199; 32]);
        let (x, y) = (
            g5_v4_vertex(&outsider, 0, 5, "a", gi),
            g5_v4_vertex(&outsider, 0, 5, "b", gi),
        );
        {
            let outsider_addr =
                crypto::derive_address(outsider.verifying_key().as_bytes()).unwrap();
            let _seed = db.seeding();
            db.put(
                "sys:validators",
                &serde_json::to_string(&vec![(outsider_addr, 1_000u64)]).unwrap(),
            )
            .unwrap();
        }
        assert!(chain.executor.verify_slash_evidence(&item(&x, &y)).is_err());
        // Another domain, or a pair whose epoch C_0 does not cover.
        let foreign = g5_v4_vertex(key, 0, 5, "b", "another-genesis");
        assert!(chain
            .executor
            .verify_slash_evidence(&item(&a, &foreign))
            .is_err());
        let (a3, b3) = (
            g5_v4_vertex(key, 3, 5, "a", gi),
            g5_v4_vertex(key, 3, 5, "b", gi),
        );
        assert!(chain
            .executor
            .verify_slash_evidence(&item(&a3, &b3))
            .is_err());

        // Age: epoch 1 begins at 20 d, so evidence of epoch 0 is good until
        // 27 d exactly (one-day blocks).
        chain.run_to(27, vec![]);
        assert_eq!(chain.clock().time, 27 * DAY);
        assert!(chain.executor.verify_slash_evidence(&item(&a, &b)).is_ok());
        chain.run_until(27 * DAY + 1, vec![]);
        let refused = chain
            .executor
            .verify_slash_evidence(&item(&a, &b))
            .unwrap_err();
        assert!(refused.contains("older than W"), "{refused}");

        // Carried in a block (epoch 1 evidence, fresh), it records the offense
        // in its own epoch and jails the offender.
        let (a1, b1) = (
            g5_v4_vertex(key, 1, 25, "a", gi),
            g5_v4_vertex(key, 1, 25, "b", gi),
        );
        let height = chain.height + 1;
        chain.height = height;
        chain.timestamp += DAY;
        let proposer = chain.proposer.clone();
        match chain.executor.execute_block_parallel_at(
            vec![],
            &proposer,
            height,
            chain.timestamp,
            &[item(&a1, &b1)],
        ) {
            BlockExecOutcome::Executed(_) => {}
            other => panic!("the block must execute: {other:?}"),
        }
        let offense = g5_offense(&db, &offender);
        assert_eq!(
            (offense.epoch, offense.weight, offense.committee_weight),
            (1, 1_000, 4_000)
        );
        assert!(db
            .get(&format!("validator:jailed:{offender}"))
            .unwrap()
            .is_some());
        assert_eq!(
            g5_own_unbonding(&db, &offender),
            vec![(height, 1_000 * ain)]
        );
    }

    /// The item a V4 node carries for twins (consensus `v4::evidence`).
    fn consensus_evidence_item(a: &blockchain::Vertex, b: &blockchain::Vertex) -> String {
        let (first, second) = if a.hash < b.hash { (a, b) } else { (b, a) };
        serde_json::json!({
            "kind": "equivocation_v4",
            "offender": first.author,
            "epoch": first.epoch,
            "round": first.round,
            "vertex_a": first.to_compact_proof_v4(),
            "vertex_b": second.to_compact_proof_v4(),
        })
        .to_string()
    }

    /// G5 DL-3: tickets are capped per account, so a full account blocks only
    /// itself: A's 17th undelegation aborts and changes nothing, while B's
    /// goes through. Matured tickets are all paid by one withdrawal.
    #[test]
    fn g5_a_full_account_blocks_only_its_own_undelegation() {
        let ain = G5_AIN;
        let (mut chain, validators, delegators) = delegation_chain(
            "g5_dl_tickets",
            20,
            DAY,
            &[(129, 1_000)],
            &[(130, 100 * ain), (131, 100 * ain)],
        );
        let (validator_key, validator) = &validators[0];
        let [(a_key, a), (b_key, b)] = <[_; 2]>::try_from(delegators).ok().unwrap();
        let db = chain.db.clone();
        let call = |chain: &mut G5Chain, key: &SigningKey, function: &str, amount: Option<u128>| {
            let mut args = vec![move_addr_arg(validator)];
            args.extend(amount.map(|a| bcs::to_bytes(&a).unwrap()));
            chain.tx(key, "delegation", function, args)
        };
        let enable = chain.tx(
            validator_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&0u64).unwrap()],
        );
        chain.run_to(1, vec![enable]);
        // B opens a pool but is no validator: it takes no delegation.
        let b_pool = chain.tx(
            &b_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&0u64).unwrap()],
        );
        let to_b = chain.tx(
            &a_key,
            "delegation",
            "delegate",
            vec![move_addr_arg(&b), bcs::to_bytes(&(5 * ain)).unwrap()],
        );
        let joins = vec![
            b_pool,
            to_b,
            call(&mut chain, &a_key, "delegate", Some(20 * ain)),
            call(&mut chain, &b_key, "delegate", Some(5 * ain)),
        ];
        chain.run_to(2, joins);
        assert_eq!(
            pool_of(&db, &b).active_coins,
            0,
            "a non-validator's pool is refused"
        );
        assert_eq!(book_of(&db, &a).positions.len(), 1);
        let mut txs: Vec<String> = (0..17)
            .map(|_| call(&mut chain, &a_key, "undelegate", Some(ain)))
            .collect();
        // 4.5 of 5 would leave 0.5 AIN: B exits in full.
        txs.push(call(&mut chain, &b_key, "undelegate", Some(45 * ain / 10)));
        chain.run_to(3, txs);
        let pool = pool_of(&db, validator);
        let book_a = book_of(&db, &a);
        assert_eq!(book_a.tickets.len(), 16, "the 17th is refused");
        assert_eq!(pool.position_value(&book_a.positions[0]).0, 4 * ain);
        let book_b = book_of(&db, &b);
        assert_eq!(book_b.tickets.len(), 1, "B is not blocked");
        assert_eq!(
            book_b.tickets[0].amount,
            5 * ain,
            "a remainder below 1 AIN exits in full"
        );
        assert!(book_b.positions.is_empty());
        assert_eq!((pool.ticket_count, pool.unbonding_coins), (17, 21 * ain));

        chain.run_until(44 * DAY, vec![]);
        let before = coin_balance(&db, &a);
        let withdraw = call(&mut chain, &a_key, "withdraw_unbonded", None);
        chain.run_to(chain.height + 1, vec![withdraw]);
        let gained = coin_balance(&db, &a) - before;
        assert!((16 * ain - 100_000..=16 * ain).contains(&gained));
        assert!(book_of(&db, &a).tickets.is_empty());
        let pool = pool_of(&db, validator);
        assert_eq!((pool.ticket_count, pool.unbonding_coins), (1, 5 * ain));
        assert_eq!(pool.principal, pool.active_coins + pool.unbonding_coins);
    }

    /// G5 DL-1, DL-2 at the edges. A pool with fewer than 10^18 points, or a
    /// closed one, takes no reward: neither its part nor the commission on it
    /// is minted, and the validator gets its own part only. A closed pool
    /// weighs nothing in the next committee. A committee kept because the
    /// live set is invalid keeps its split. A stake top-up keeps the pool's
    /// weight in the live set.
    #[test]
    fn g5_only_open_pools_of_a_full_point_take_reward_or_weight() {
        let ain = G5_AIN;
        let (mut chain, validators, _) =
            delegation_chain("g5_dl_edges", 20, 14, &[(156, 1_000), (157, 1_000)], &[]);
        let (small_key, small) = &validators[0];
        let closed = validators[1].1.clone();
        let db = chain.db.clone();
        // `small`: 1 AIN at a price of 2, so 0.5e18 points. `closed`: 10 AIN,
        // slashed. The split of epoch 0 counts 1 and 10 AIN of delegation.
        let mut pool = open_pool(ain);
        pool.active_points = ain / 2;
        pool.commission_rate = 1_000;
        pool.pending_commission = 1_000;
        set_pool(&db, small, &pool);
        let mut pool = open_pool(10 * ain);
        pool.closed = true;
        pool.commission_rate = 1_000;
        pool.pending_commission = 1_000;
        set_pool(&db, &closed, &pool);
        {
            let _seed = db.seeding();
            let split = BTreeMap::from([(small.clone(), 1u64), (closed.clone(), 10u64)]);
            db.put(
                &delegated_split_key(0),
                &serde_json::to_string(&split).unwrap(),
            )
            .unwrap();
        }
        let e = g5_expected_emission(g5_minted(&db), 140);
        let share = e * 40 / 80;
        let (small_before, closed_before) = (coin_balance(&db, small), coin_balance(&db, &closed));
        let supply_before = validator_set(&db).total_supply;
        chain.run_blocks(20, 7);
        let (paid_small, paid_closed) = (share * 999 / 1_000, share * 990 / 1_000);
        assert_eq!(coin_balance(&db, small) - small_before, paid_small);
        assert_eq!(coin_balance(&db, &closed) - closed_before, paid_closed);
        assert_eq!(
            validator_set(&db).total_supply - supply_before,
            paid_small + paid_closed,
            "what the payout did not pay stays in the reserve"
        );
        assert_eq!(pool_of(&db, small).rewards, 0);
        assert_eq!(pool_of(&db, &closed).rewards, 0);
        // Epoch 1 weighs the small pool, not the closed one.
        let mut expected = vec![(small.clone(), 1_001), (closed.clone(), 1_000)];
        expected.sort();
        assert_eq!(g5_committee(&db, 1), expected);
        assert_eq!(
            g5_split_record(&db, 1),
            Some(BTreeMap::from([(small.clone(), 1)]))
        );

        // A top-up of 5 AIN: own 1,005 plus the pool's 1.
        let top_up = chain.tx(
            small_key,
            "staking",
            "add_stake",
            vec![bcs::to_bytes(&(5 * ain)).unwrap()],
        );
        chain.run_to(21, vec![top_up]);
        let live: Vec<blockchain::committee::ValidatorInfo> =
            serde_json::from_str(&db.get("sys:validator_set:v1").unwrap().unwrap()).unwrap();
        assert_eq!(
            live.iter().find(|m| &m.address == small).unwrap().stake,
            1_006
        );

        // An empty live set is invalid: epoch 2 keeps epoch 1's committee
        // and its split.
        {
            let _seed = db.seeding();
            db.put("sys:validator_set:v1", "[]").unwrap();
        }
        chain.run_blocks(40 - chain.height, 7);
        assert_eq!(g5_committee(&db, 2), expected);
        assert_eq!(g5_split_record(&db, 2), g5_split_record(&db, 1));
    }

    /// G5 DL-3, SL-1 (bounded work): the pool is aggregates only. Its stored
    /// size is the same with one delegator or twelve, so no operation on it,
    /// a payout or a slash included, can cost more as delegators join; each
    /// delegator's state is its own Book.
    #[test]
    fn g5_a_pool_does_not_grow_with_its_delegators() {
        let ain = G5_AIN;
        let seeds: Vec<(u8, u128)> = (140..152).map(|seed| (seed, 2 * ain)).collect();
        let (mut chain, validators, delegators) =
            delegation_chain("g5_dl_size", 20, 14, &[(139, 1_000)], &seeds);
        let (validator_key, validator) = &validators[0];
        let db = chain.db.clone();
        let size = || {
            let key = vm_move::state_keys::resource_key_str(
                &parse_move_address(validator).unwrap(),
                "0x1::delegation::Pool",
            );
            db.get(&key).unwrap().unwrap().len()
        };
        let enable = chain.tx(
            validator_key,
            "delegation",
            "enable_delegation",
            vec![bcs::to_bytes(&0u64).unwrap()],
        );
        chain.run_to(1, vec![enable]);
        let delegate = |chain: &mut G5Chain, key: &SigningKey| {
            chain.tx(
                key,
                "delegation",
                "delegate",
                vec![move_addr_arg(validator), bcs::to_bytes(&ain).unwrap()],
            )
        };
        let first = delegate(&mut chain, &delegators[0].0);
        chain.run_to(2, vec![first]);
        let one = size();
        let rest: Vec<String> = delegators[1..]
            .iter()
            .map(|(key, _)| delegate(&mut chain, key))
            .collect();
        chain.run_to(3, rest);
        assert_eq!(size(), one, "the pool holds no per-delegator state");
        assert_eq!(pool_of(&db, validator).position_count, 12);
        for (_, delegator) in &delegators {
            assert_eq!(book_of(&db, delegator).positions.len(), 1);
        }
    }

    /// G5 DL-2, DL-3 rounding (EIP-4626: always the pool's way) at a price
    /// C / P = (3e18 + 1) / 2e18, seeded: an undelegation burns
    /// ceil(a x P / C) points and tickets floor(q x C / P) coins; a delegation
    /// gets floor(a x P / C) points. A claim of p x (rho - snapshot) = 4e38,
    /// past u128, is formed in u256, and an escrow one unit short pays what it
    /// holds instead of aborting.
    #[test]
    fn g5_pool_arithmetic_rounds_for_the_pool_and_never_aborts_on_dust() {
        use move_core_types::u256::U256;
        let ain = G5_AIN;
        let (mut chain, validators, delegators) = delegation_chain(
            "g5_dl_rounding",
            20,
            14,
            &[(153, 1_000)],
            &[(154, 10 * ain), (155, 10 * ain)],
        );
        let (_, validator) = &validators[0];
        let [(a_key, a), (b_key, b)] = <[_; 2]>::try_from(delegators).ok().unwrap();
        let db = chain.db.clone();
        let (c, p) = (3 * ain + 1, 2 * ain);
        let rho = 200 * ain;
        let owed = 400 * ain; // floor(2e18 x 2e20 / 1e18)
        let mut pool = open_pool(c);
        pool.active_points = p;
        pool.reward_counter = rho;
        pool.rewards = owed - 1;
        pool.position_count = 1;
        set_pool(&db, validator, &pool);
        set_book(
            &db,
            &a,
            &DelegationBook {
                positions: vec![position(validator, p)],
                tickets: vec![],
            },
        );

        let before = coin_balance(&db, &a);
        let claim = chain.tx(
            &a_key,
            "delegation",
            "claim_rewards",
            vec![move_addr_arg(validator)],
        );
        chain.run_to(1, vec![claim]);
        let gained = coin_balance(&db, &a) - before;
        assert!(
            (owed - 1 - 100_000..=owed - 1).contains(&gained),
            "{gained}"
        );
        assert_eq!(pool_of(&db, validator).rewards, 0);

        let undelegate = chain.tx(
            &a_key,
            "delegation",
            "undelegate",
            vec![move_addr_arg(validator), bcs::to_bytes(&ain).unwrap()],
        );
        chain.run_to(2, vec![undelegate]);
        let q = ((U256::from(ain) * U256::from(p) + U256::from(c) - U256::from(1u8))
            / U256::from(c))
        .unchecked_as_u128();
        let x = g5_mul_div(q, c, p);
        assert_eq!(q, 666_666_666_666_666_667);
        assert_eq!(book_of(&db, &a).tickets[0].amount, x);
        let pool = pool_of(&db, validator);
        assert_eq!((pool.active_coins, pool.active_points), (c - x, p - q));

        let join = chain.tx(
            &b_key,
            "delegation",
            "delegate",
            vec![move_addr_arg(validator), bcs::to_bytes(&ain).unwrap()],
        );
        chain.run_to(3, vec![join]);
        assert_eq!(
            book_of(&db, &b).positions[0].points,
            g5_mul_div(ain, p - q, c - x)
        );
    }

    /// Validators A, B and C with coin stores, `stake` each, and the Epoch
    /// resource, so boundaries run the real Move epoch advance.
    fn seed_three_validators(db: &StateDB, keys: &[(SigningKey, String)], stake: u128) {
        let _seed = db.seeding();
        let validators = keys
            .iter()
            .zip(1u8..)
            .map(|((_, address), bls_seed)| {
                let (bls_public_key, bls_pop) = test_bls_identity(bls_seed);
                TestValidatorConfig {
                    validator_addr: parse_move_address(address).unwrap(),
                    stake: TestCoin { value: stake },
                    public_key: vec![1, 2, 3],
                    bls_public_key,
                    bls_pop,
                }
            })
            .collect();
        let set = TestValidatorSet {
            validators,
            unbonding_queue: vec![],
            total_supply: stake * keys.len() as u128,
            current_epoch: 0,
        };
        db.put(
            &validator_set_key(),
            &hex::encode(bcs::to_bytes(&set).unwrap()),
        )
        .unwrap();
        db.put(
            &vm_move::state_keys::resource_key_str(&system_address(), "0x1::epoch::Epoch"),
            &hex::encode(bcs::to_bytes(&0u64).unwrap()),
        )
        .unwrap();
    }

    fn move_epoch(db: &StateDB) -> u64 {
        let key = vm_move::state_keys::resource_key_str(&system_address(), "0x1::epoch::Epoch");
        bcs::from_bytes(&hex::decode(db.get(&key).unwrap().unwrap()).unwrap()).unwrap()
    }

    /// G5 UB-1: matured unbonding is paid automatically at the first epoch
    /// boundary at or after its unlock, once, and never burned. Boundaries
    /// run the real Move epoch advance.
    #[test]
    fn g5_matured_unbonding_is_paid_at_the_first_boundary() {
        let ain = G5_AIN;
        let mut keys = vec![];
        let mut chain = G5Chain::new("g5_payout", DAY, |db| {
            for seed in [71u8, 72, 73] {
                keys.push(G5Chain::account(db, seed, ain));
            }
            seed_three_validators(db, &keys, 1_000 * ain);
        });
        let db = chain.db.clone();
        let queue = || -> Vec<(u64, u64)> {
            validator_set(&db)
                .unbonding_queue
                .iter()
                .map(|r| (r.start_height, r.unlock_time))
                .collect()
        };

        // A leaves at height 3 (unlock 3 + 20 + 21 = 44 d), B at 45 (86 d).
        let leave_a = chain.tx(&keys[0].0, "staking", "leave_validator_set", vec![]);
        chain.run_to(3, vec![leave_a]);
        let a_before = coin_balance(&db, &keys[0].1);
        chain.run_to(44, vec![]);
        assert_eq!(chain.clock().time, 44 * DAY);
        let leave_b = chain.tx(&keys[1].0, "staking", "leave_validator_set", vec![]);
        chain.run_to(45, vec![leave_b]);
        // Matured at 44 d, but no boundary until height 60.
        chain.run_to(59, vec![]);
        assert_eq!(queue(), vec![(3, 44 * DAY), (45, 86 * DAY)]);
        assert_eq!(coin_balance(&db, &keys[0].1), a_before);
        chain.run_to(60, vec![]);
        assert_eq!(
            queue(),
            vec![(45, 86 * DAY)],
            "A is paid at the first boundary after 44 d"
        );
        let a_paid = coin_balance(&db, &keys[0].1);
        assert!(
            a_paid >= a_before + 1_000 * ain,
            "A got its stake (and any rewards)"
        );
        chain.run_to(80, vec![]);
        assert_eq!(queue(), vec![(45, 86 * DAY)], "B is not matured at 80 d");
        chain.run_to(100, vec![]);
        assert!(queue().is_empty(), "B is paid at the boundary after 86 d");
        assert_eq!(
            move_epoch(&db),
            5,
            "the boundaries at 20, 40, 60, 80 and 100 ran"
        );
        assert_eq!(
            validator_set(&db).current_epoch,
            5,
            "the committee-epoch counter (DePIN's limit) advances at boundaries"
        );
    }

    /// G5 UB-1: a boundary pays at most K = 256 matured entries, in queue
    /// order; the rest wait for the next boundary. An owner without a coin
    /// store keeps its entry at the head, and nothing aborts the epoch.
    #[test]
    fn g5_boundary_payouts_are_bounded_and_ordered() {
        let ain = G5_AIN;
        let owners: Vec<String> = (0..300u32)
            .map(|i| format!("{:064x}", 0x1000 + i))
            .collect();
        let mut keys = vec![];
        let mut chain = G5Chain::new("g5_payout_bound", DAY, |db| {
            for seed in [74u8, 75, 76] {
                keys.push(G5Chain::account(db, seed, ain));
            }
            seed_three_validators(db, &keys, 1_000 * ain);
            let mut set = validator_set(db);
            for (i, owner) in owners.iter().enumerate() {
                // Owner 1 has no coin store.
                if i != 1 {
                    set_coin_store(db, owner, 0);
                }
                set.unbonding_queue.push(TestUnbondingRequest {
                    validator_addr: parse_move_address(owner).unwrap(),
                    stake: 1_000 + i as u128,
                    start_height: 0,
                    unlock_time: i as u64,
                });
            }
            let _seed = db.seeding();
            db.put(
                &validator_set_key(),
                &hex::encode(bcs::to_bytes(&set).unwrap()),
            )
            .unwrap();
        });
        let db = chain.db.clone();
        let queued = || -> Vec<u64> {
            validator_set(&db)
                .unbonding_queue
                .iter()
                .map(|r| r.unlock_time)
                .collect()
        };

        chain.run_to(20, vec![]);
        // 256 scanned: 255 paid, owner 1 kept at the head, 256..299 wait.
        let expected: Vec<u64> = std::iter::once(1).chain(256..300).collect();
        assert_eq!(queued(), expected);
        assert_eq!(coin_balance(&db, &owners[0]), 1_000);
        assert_eq!(coin_balance(&db, &owners[255]), 1_255);
        assert_eq!(coin_balance(&db, &owners[256]), 0, "past K, waits");
        chain.run_to(40, vec![]);
        assert_eq!(queued(), vec![1], "the rest paid; owner 1 still kept");
        assert_eq!(coin_balance(&db, &owners[299]), 1_299);
        assert_eq!(move_epoch(&db), 2);
    }

    /// The Move emission rule (G5 EM-1), for `elapsed` consensus seconds on
    /// `minted` supply: remaining x lambda x dt, dt capped at one day.
    fn g5_expected_emission(minted: u128, elapsed: u64) -> u128 {
        let remaining = MAX_SUPPLY - minted;
        let e = (remaining / 1_000_000_000) * 607_866_866 * (elapsed.min(86_400) as u128)
            / 1_000_000_000;
        e.min(remaining)
    }

    /// A Move ValidatorSet holding only `total_supply` (payouts read it for
    /// the remaining reserve), and `members` as the genesis committee, each
    /// with an empty coin store.
    fn seed_committee_chain(
        db: &StateDB,
        members: &[blockchain::committee::ValidatorInfo],
        total_supply: u128,
    ) {
        for m in members {
            set_coin_store(db, &m.address, 0);
        }
        let _seed = db.seeding();
        let set = TestValidatorSet {
            validators: vec![],
            unbonding_queue: vec![],
            total_supply,
            current_epoch: 0,
        };
        db.put(
            &validator_set_key(),
            &hex::encode(bcs::to_bytes(&set).unwrap()),
        )
        .unwrap();
        db.put(
            "genesis:validator_set:v1",
            &serde_json::to_string(members).unwrap(),
        )
        .unwrap();
    }

    /// G5 EM-1: a payout mints remaining x lambda x (consensus time since the
    /// last payout), split by committee weight; one payout covers at most a
    /// day. lambda realizes 1.90 %/yr of the remaining reserve.
    #[test]
    fn g5_emission_counts_consensus_time_and_caps_one_payout_at_a_day() {
        let ain = G5_AIN;
        let supply = 1_000_000 * ain;
        let (a, b) = (committee_member(101, 100), committee_member(102, 100));
        let members = [a.clone(), b.clone()];
        // 7 s blocks: the payout at height 20 covers 140 s.
        let mut chain = G5Chain::new("g5_emission", 14, |db| {
            seed_committee_chain(db, &members, supply)
        });
        chain.run_blocks(20, 7);
        let e = g5_expected_emission(supply, 140);
        assert!(e > 0);
        // Equal weights (each clipped to 1/50 of the total): half each.
        let each = e * 4 / 8;
        assert_eq!(coin_balance(&chain.db, &a.address), each);
        assert_eq!(coin_balance(&chain.db, &b.address), each);
        assert_eq!(validator_set(&chain.db).total_supply, supply + 2 * each);

        // A payout 20 days after the last covers one day only.
        let mut slow = G5Chain::new("g5_emission_cap", DAY, |db| {
            seed_committee_chain(db, &members, supply)
        });
        slow.run_blocks(20, DAY);
        let capped = g5_expected_emission(supply, 20 * DAY);
        assert_eq!(capped, g5_expected_emission(supply, DAY));
        assert_eq!(
            validator_set(&slow.db).total_supply,
            supply + 2 * (capped * 4 / 8)
        );

        // The rate: a day's draw, compounded over a Julian year, is 1.90 %.
        let remaining = (MAX_SUPPLY - supply) as f64;
        let per_day = g5_expected_emission(supply, DAY) as f64 / remaining;
        let per_year = 1.0 - (1.0 - per_day).powf(365.25);
        assert!((per_year - 0.019).abs() < 1e-5, "{per_year}");
    }

    /// G5 EM-1: the emission depends on consensus time only. 1 s or 7 s blocks,
    /// and a reward period of 1 or 20 blocks, mint the same over the same time
    /// (to the linear form's bound, far below one part in a million).
    #[test]
    fn g5_emission_does_not_depend_on_block_speed_or_period() {
        let ain = G5_AIN;
        let supply = 1_000_000 * ain;
        let members = [committee_member(103, 100), committee_member(104, 300)];
        let minted = |name: &str, period: u64, step: u64, blocks: u64| -> u128 {
            let mut chain = G5Chain::with_period(name, period, 14, |db| {
                seed_committee_chain(db, &members, supply)
            });
            chain.run_blocks(blocks, step);
            assert_eq!(chain.clock().time, 280);
            // Stakes 100 and 300 both exceed the saturation point (1/50 of
            // the total), so the two are paid alike.
            assert_eq!(
                coin_balance(&chain.db, &members[0].address),
                coin_balance(&chain.db, &members[1].address)
            );
            validator_set(&chain.db).total_supply - supply
        };
        let slow = minted("g5_speed_slow", 20, 7, 40);
        let fast = minted("g5_speed_fast", 20, 1, 280);
        let every_block = minted("g5_speed_period1", 1, 7, 40);
        assert!(slow > 0);
        for other in [fast, every_block] {
            let diff = slow.abs_diff(other) as f64 / slow as f64;
            assert!(diff < 1e-6, "slow {slow}, other {other}");
        }
    }

    /// G5 EM-1: a committee weight far beyond any real stake (u64::MAX whole
    /// AIN) is bounded before the pot arithmetic. Unbounded, a day's pot
    /// (about 8e21) times its clipped weight (about 3.7e17) overflows u128 and
    /// aborts every payout, which would stop emission.
    #[test]
    fn g5_an_oversized_committee_weight_cannot_stop_emission() {
        let supply = 1_000_000 * G5_AIN;
        let members = [committee_member(105, u64::MAX), committee_member(106, 100)];
        // Day-long blocks: the payout at 20 covers the capped one day.
        let mut chain = G5Chain::new("g5_weight_bound", DAY, |db| {
            seed_committee_chain(db, &members, supply)
        });
        chain.run_blocks(20, DAY);
        assert!(
            validator_set(&chain.db).total_supply > supply,
            "the payout ran"
        );
        assert!(coin_balance(&chain.db, &members[1].address) > 0);
    }

    /// G5 EM-2, EM-3: rewards and fees pay the committee of the block's
    /// epoch, never the live set. At the boundary H_E the payout pays C_E
    /// before C_{E+1} is recorded: a joiner is paid from its first committee
    /// epoch and a leaver until its last. A jailed member gets nothing.
    #[test]
    fn g5_rewards_and_fees_pay_the_committee_of_the_block_epoch() {
        let ain = G5_AIN;
        let supply = 1_000_000 * ain;
        let (a, b, c) = (
            committee_member(111, 100),
            committee_member(112, 100),
            committee_member(113, 100),
        );
        let bystander = committee_member(114, 100);
        let mut keys = vec![];
        let mut chain = G5Chain::new("g5_recipients", 14, |db| {
            seed_committee_chain(db, &[a.clone(), b.clone()], supply);
            set_coin_store(db, &c.address, 0);
            set_coin_store(db, &bystander.address, 0);
            keys.push(G5Chain::account(db, 115, 10 * ain));
            let _seed = db.seeding();
            // The live set: B left, C joined. A bystander is in the old
            // reward mirror but in no committee.
            db.put(
                "sys:validator_set:v1",
                &serde_json::to_string(&vec![a.clone(), c.clone()]).unwrap(),
            )
            .unwrap();
            db.put(
                "sys:validators",
                &serde_json::to_string(&vec![(bystander.address.clone(), 100u64)]).unwrap(),
            )
            .unwrap();
        });
        let (payer_key, payer) = keys.pop().unwrap();
        let db = chain.db.clone();
        let balance = |m: &blockchain::committee::ValidatorInfo| coin_balance(&db, &m.address);

        // H_0 = 20 pays C_0 = {A, B}, then records C_1 = {A, C}.
        chain.run_blocks(20, 7);
        assert!(
            balance(&a) > 0 && balance(&b) > 0,
            "C_0 is paid at its boundary"
        );
        assert_eq!(balance(&c), 0, "C joins from epoch 1 only");
        let recorded: Vec<blockchain::committee::ValidatorInfo> =
            serde_json::from_str(&db.get("sys:validator_set:epoch:1").unwrap().unwrap()).unwrap();
        assert_eq!(
            recorded,
            blockchain::committee::canonical_order(&[a.clone(), c.clone()])
        );

        // Block 21's fees pay C_1: C and A, not B, not the bystander.
        let (b_before, c_before) = (balance(&b), balance(&c));
        let pay = signed_tx(
            &payer_key,
            &payer,
            &coin_transfer_payload(&payer, &a.address, 1),
            0,
            100_000,
            1,
        );
        chain.block(chain.timestamp + 7, vec![pay]);
        assert!(balance(&c) > c_before, "a C_1 member earns block 21's fees");
        assert_eq!(balance(&b), b_before, "B left the committee");
        assert_eq!(balance(&bystander), 0, "the live reward mirror is not paid");

        // A is jailed before the payout at 40: only C is paid.
        {
            let _seed = db.seeding();
            db.put(&format!("validator:jailed:{}", a.address), "1")
                .unwrap();
        }
        let (a_before, c_before) = (balance(&a), balance(&c));
        chain.run_blocks(19, 7);
        assert_eq!(chain.height, 40);
        assert_eq!(balance(&a), a_before, "a jailed member gets nothing");
        assert!(balance(&c) > c_before, "C is paid for epoch 1");
    }

    /// Build a hex-encoded BCS `coin::transfer` payload from `from` to `to`.
    fn coin_transfer_payload(from: &str, to: &str, amount: u128) -> String {
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                system_address(),
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![aincore_coin_type()],
            args: vec![
                bcs::to_bytes(&parse_move_address(from).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(to).unwrap()).unwrap(),
                bcs::to_bytes(&amount).unwrap(),
            ],
        };
        let payload = vm_move::TransactionPayload::EntryFunction(call);
        hex::encode(bcs::to_bytes(&payload).unwrap())
    }

    fn dep_tx(sender: &str, payload: String) -> Transaction {
        Transaction {
            chain_id: "AINCORE-MAINNET-1".to_string(),
            sender: sender.to_string(),
            input_objects: vec![],
            payload,
            args: vec![],
            gas_limit: 100_000,
            gas_price: 1,
            sequence_number: 0,
            public_key: String::new(),
            signature: String::new(),
            paymaster: None,
            paymaster_signature: None,
            zkp_proof: None,
        }
    }

    /// H2 REGRESSION. A transfer FROM account A and a transfer TO account A must
    /// produce the SAME canonical conflict token for A, so the parallel
    /// scheduler detects the read/write conflict and refuses to co-schedule
    /// them into one batch. We deliberately give the "FROM A" transaction a
    /// NON-canonical (uppercase) sender string to prove the fix normalizes it;
    /// recipients are always emitted in canonical (lowercase, zero-padded)
    /// Move-address form. Before the fix, `tx.sender` was pushed raw, so the two
    /// roles produced different tokens, no conflict was detected, both txs read
    /// A's pre-batch balance, and the atomic last-write-wins commit silently
    /// corrupted A's CoinStore.
    #[test]
    fn test_h2_transfer_from_and_to_same_account_share_canonical_token() {
        let db = temp_db("h2_canonical_token");
        let executor = Executor::new(db.clone());

        let account_a = "0000000000000000000000000000000a".to_string();
        let account_b = "0000000000000000000000000000000b".to_string();
        let other = "00000000000000000000000000000022".to_string();

        // tx1: A -> other, with A supplied in NON-canonical (uppercase) form.
        let a_uppercase = "0000000000000000000000000000000A".to_string();
        let tx_from_a = dep_tx(&a_uppercase, coin_transfer_payload(&account_a, &other, 10));
        // tx2: B -> A (A appears as the canonical recipient token).
        let tx_to_a = dep_tx(
            &account_b,
            coin_transfer_payload(&account_b, &account_a, 10),
        );

        let deps_from_a = executor.get_tx_dependencies(&tx_from_a);
        let deps_to_a = executor.get_tx_dependencies(&tx_to_a);

        let canonical_a = parse_move_address(&account_a).unwrap().to_string();

        // FROM-A must contribute the canonical A token, NOT the raw uppercase.
        assert!(
            deps_from_a.contains(&canonical_a),
            "sender token not canonicalized: {:?}",
            deps_from_a
        );
        assert!(
            !deps_from_a.contains(&a_uppercase),
            "raw uppercase sender token leaked into deps: {:?}",
            deps_from_a
        );
        // TO-A must contribute the SAME canonical A token (recipient side).
        assert!(
            deps_to_a.contains(&canonical_a),
            "recipient token missing canonical A: {:?}",
            deps_to_a
        );

        // Scheduler-level assertion mirroring execute_block_parallel's lock
        // check: after locking tx1's deps, tx2 MUST register a conflict so the
        // batch builder flushes the current batch and isolates tx2.
        let locked: std::collections::HashSet<String> = deps_from_a.iter().cloned().collect();
        let conflict = deps_to_a.iter().any(|d| locked.contains(d));
        assert!(
            conflict,
            "scheduler would NOT detect conflict between FROM-A and TO-A: from={:?} to={:?}",
            deps_from_a, deps_to_a
        );
    }

    /// SECURITY (FIX #1 — VM signer binding). An attacker crafts a
    /// `coin::transfer` whose FIRST argument (the `&signer` slot) is a forged
    /// VICTIM address, signs the transaction with the ATTACKER's own key, and
    /// submits it. Before FIX #1 the move-vm deserialized the signer straight
    /// from the user-supplied arg bytes, so the transfer would withdraw from the
    /// VICTIM — fund theft. After FIX #1 `bind_signer_args` overwrites the leading
    /// signer slot with the authenticated sender (the attacker), so the victim's
    /// balance is untouched. This test would FAIL (victim drained) on the pre-fix
    /// code and PASSES now.
    #[test]
    fn test_fix1_forged_signer_cannot_spend_victim_funds() {
        let db = temp_db("fix1_forged_signer");
        load_stdlib(&db);
        let attacker_key = SigningKey::from_bytes(&[21u8; 32]);
        let victim_key = SigningKey::from_bytes(&[22u8; 32]);
        let sink_key = SigningKey::from_bytes(&[23u8; 32]);
        let attacker = create_account(&db, &attacker_key);
        let victim = create_account(&db, &victim_key);
        let sink = create_account(&db, &sink_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        // Attacker can pay gas; victim holds the funds the attacker wants to steal.
        set_coin_store(&db, &attacker, 1_000_000);
        set_coin_store(&db, &victim, 5_000_000);
        set_coin_store(&db, &sink, 0);

        let executor = Executor::new(db.clone());
        // coin::transfer(from: &signer, to: address, amount). args[0] is the
        // signer slot — the attacker forges it to the VICTIM's address.
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::ONE,
                    module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                    name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                    type_params: vec![],
                }),
            )],
            args: vec![
                // FORGED signer slot = victim.
                bcs::to_bytes(&parse_move_address(&victim).unwrap()).unwrap(),
                // Recipient = attacker-controlled sink.
                bcs::to_bytes(&parse_move_address(&sink).unwrap()).unwrap(),
                bcs::to_bytes(&4_000_000u128).unwrap(),
            ],
        };
        let payload_struct = vm_move::TransactionPayload::EntryFunction(call);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());

        // Signed by the ATTACKER, sender = attacker.
        let _ = executor.execute_transaction(&signed_tx(
            &attacker_key,
            &attacker,
            &payload,
            0,
            100_000,
            1,
        ));
        // Whatever the VM did, it must NOT have spent the victim's coins, and the
        // attacker-controlled sink must NOT have received the victim's funds.
        assert_eq!(
            coin_balance(&db, &victim),
            5_000_000,
            "FIX #1 FAILED: forged signer let the attacker spend the victim's balance"
        );
        assert_eq!(
            coin_balance(&db, &sink),
            0,
            "FIX #1 FAILED: victim funds were redirected to the attacker sink"
        );
    }

    #[test]
    fn test_move_transfer_abort_still_charges_gas_and_records_receipt() {
        let db = temp_db("transfer_abort");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[9u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[10u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 100_050);
        set_coin_store(&db, &recipient, 0);

        let executor = Executor::new(db.clone());
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::ONE,
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
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        set_coin_store(&db, &sender, 1_000);
        set_coin_store(&db, &recipient, 0);

        let executor = Executor::new(db.clone());
        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::ONE,
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
        let _seed = db.seeding();
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
        let _seed = db.seeding();
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
        let _seed = db.seeding();
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
        let _seed = db.seeding();
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
        let _seed = db.seeding();
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
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::ONE,
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
        seed_genesis_tree(&db);

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

    /// G3 S3: genesis commits version 0 of the state tree (`commit_genesis`).
    /// A fixture that writes its own genesis state ends the same way.
    pub(crate) fn seed_genesis_tree(db: &Arc<StateDB>) {
        let seeded = state_commit::seed_genesis(db).expect("seed state tree v0");
        db.write_batch(seeded.batch).unwrap();
    }

    /// A funded sender, a recipient and one signed AIN transfer of 100, on a
    /// chain that burns 10% of fees (the unlogged burn path).
    fn g3_burning_transfer(name: &str) -> (Arc<StateDB>, String, String) {
        let db = temp_db(name);
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[31u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[32u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        let _seed = db.seeding();
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
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::ONE,
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
        seed_genesis_tree(&db);
        (db, sender, tx_json)
    }

    /// G3: the burn path writes `sys:total_supply` with a plain put that never
    /// reached the old hash-chain root. The Jellyfish root covers every staged
    /// state write, so the new supply is provable against the block's root.
    #[test]
    fn an_unlogged_state_write_is_provable_against_the_block_root() {
        let (db, sender, tx_json) = g3_burning_transfer("g3_unlogged_in_root");
        let outcome = Executor::new(db.clone())
            .execute_block_checked_at(vec![tx_json], &sender, 1, block_time(1), &[], |_, _| Ok(()))
            .unwrap();
        let BlockExecOutcome::Executed(summary) = outcome else {
            panic!("block 1 must execute: {outcome:?}");
        };
        let supply = db.get("sys:total_supply").unwrap().unwrap();
        assert_eq!(supply, "999990000", "positive control: the burn happened");
        let root = state_commit::root(&db, 1).unwrap();
        assert_eq!(
            hex::encode(root.0),
            summary.state_root,
            "header root is the tree root"
        );
        let (value, proof) = state_commit::prove(&db, "sys:total_supply", 1).unwrap();
        assert_eq!(value.as_deref(), Some(supply.as_bytes()));
        state_commit::verify(root, "sys:total_supply", Some(supply.as_bytes()), &proof)
            .expect("the unlogged burn write is in the root");
        let (old, old_proof) = state_commit::prove(&db, "sys:total_supply", 0).unwrap();
        assert_eq!(
            old.as_deref(),
            Some(b"1000000000".as_ref()),
            "genesis value at version 0"
        );
        state_commit::verify(
            state_commit::root(&db, 0).unwrap(),
            "sys:total_supply",
            old.as_deref(),
            &old_proof,
        )
        .unwrap();
    }

    /// G3 KV-2 / FX-9: every hand-written system resource key is exactly what
    /// the canonical encoder produces. A drift would make the executor read an
    /// "absent" resource and proofs derive the wrong key hash.
    #[test]
    fn hand_written_state_keys_match_the_canonical_encoder() {
        use vm_move::state_keys::resource_key_str;
        let one = system_address();
        assert_eq!(
            super::validator_set_key(),
            resource_key_str(&one, "0x1::staking::ValidatorSet")
        );
        assert_eq!(
            super::dex_registry_key(),
            resource_key_str(&one, "0x1::dex::PoolRegistry")
        );
        assert_eq!(
            super::supply_stats_key(),
            resource_key_str(&one, "0x1::staking::SupplyStats")
        );
    }

    /// G3 FX-10: an account created implicitly by its first transaction is
    /// byte-for-byte the object genesis would have written for it.
    #[test]
    fn an_implicit_account_has_the_canonical_encoding() {
        let (db, _, _) = g3_burning_transfer("g3_implicit_account");
        let key = SigningKey::from_bytes(&[33u8; 32]);
        let public_key = hex::encode(key.verifying_key().as_bytes());
        let address = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        set_coin_store(&db, &address, 1_000_000);
        assert!(db.get_object(&address).is_none(), "no account object yet");
        let payload = {
            let call = vm_move::EntryFunctionCall {
                module: move_core_types::language_storage::ModuleId::new(
                    move_core_types::account_address::AccountAddress::ONE,
                    move_core_types::identifier::Identifier::new("coin").unwrap(),
                ),
                function: "transfer".to_string(),
                ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                    Box::new(move_core_types::language_storage::StructTag {
                        address: move_core_types::account_address::AccountAddress::ONE,
                        module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                        name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                        type_params: vec![],
                    }),
                )],
                args: vec![
                    bcs::to_bytes(&parse_move_address(&address).unwrap()).unwrap(),
                    bcs::to_bytes(&parse_move_address(&address).unwrap()).unwrap(),
                    bcs::to_bytes(&1u128).unwrap(),
                ],
            };
            hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
        };
        // The client sends its key in upper case; the preimage does not cover
        // it, so the signature still verifies. The stored account must not
        // depend on the spelling (KV-2).
        let mut tx: serde_json::Value =
            serde_json::from_str(&signed_tx(&key, &address, &payload, 0, 100_000, 1)).unwrap();
        tx["public_key"] = serde_json::json!(public_key.to_ascii_uppercase());
        let tx = tx.to_string();
        let Ok(BlockExecOutcome::Executed(summary)) = Executor::new(db.clone())
            .execute_block_checked_at(vec![tx], &address, 1, block_time(1), &[], |_, _| Ok(()))
        else {
            panic!("block must execute");
        };
        assert_eq!(
            summary.executed_raws.len(),
            1,
            "positive control: first tx executed"
        );
        let stored = db.get_object(&address).expect("implicitly created");
        let mut canonical = aa::AccountManager::create_account(address.clone(), public_key);
        // The first transaction bumped the nonce; everything else must match.
        let mut data: aa::AccountData = serde_json::from_slice(&canonical.data).unwrap();
        data.sequence_number = 1;
        canonical.data = serde_json::to_vec(&data).unwrap();
        canonical.version = stored.version;
        assert_eq!(stored.type_struct, "0x1::account::Account");
        assert_eq!(
            serde_json::to_vec(&stored).unwrap(),
            serde_json::to_vec(&canonical).unwrap()
        );
    }

    /// G3 FX-5: a transaction refused in block 2 but byte-identical to one
    /// executed in block 1 must count as NO_RECEIPT. The old code read the
    /// stale block-1 receipt from the database.
    #[test]
    fn a_replayed_transaction_does_not_reuse_a_stale_receipt() {
        let (db, sender, tx_json) = g3_burning_transfer("g3_stale_receipt");
        let executor = Executor::new(db.clone());
        let Ok(BlockExecOutcome::Executed(first)) = executor.execute_block_checked_at(
            vec![tx_json.clone()],
            &sender,
            1,
            block_time(1),
            &[],
            |_, _| Ok(()),
        ) else {
            panic!("block 1 must execute");
        };
        assert_eq!(
            first.executed_raws.len(),
            1,
            "positive control: block 1 executed it"
        );
        let receipt_key = format!("tx_receipt:{}", tx_hash_hex(&tx_json));
        assert!(
            db.get(&receipt_key).unwrap().is_some(),
            "block 1 wrote a receipt"
        );

        let Ok(BlockExecOutcome::Executed(second)) = executor.execute_block_checked_at(
            vec![tx_json.clone()],
            &sender,
            2,
            block_time(2),
            &[],
            |_, _| Ok(()),
        ) else {
            panic!("block 2 must execute");
        };
        assert!(second.executed_raws.is_empty(), "the replay is refused");
        // Outside a transaction nothing is staged, so this is the root with
        // the transaction counted as NO_RECEIPT.
        assert_eq!(
            second.receipts_root,
            executor.receipts_root_for_block(std::slice::from_ref(&tx_json))
        );
        assert_ne!(second.receipts_root, first.receipts_root);
    }

    /// G3 FX-4: a fee share that cannot be paid is queued under the height
    /// being executed. It used to take `latest_height`, which is still the
    /// parent height while a block executes.
    #[test]
    fn a_queued_fee_is_keyed_by_the_executing_height() {
        let (db, sender, tx_json) = g3_burning_transfer("g3_sweep_height");
        // G5 EM-2: fees pay the block's committee (epoch 0: the genesis one).
        let mut good = committee_member(94, 1000);
        good.address = sender.clone();
        let mut bad = committee_member(95, 1000);
        bad.address = "not_a_hex_validator".to_string();
        let _seed = db.seeding();
        db.put(
            "genesis:validator_set:v1",
            &serde_json::to_string(&vec![good, bad]).unwrap(),
        )
        .unwrap();
        let outcome = Executor::new(db.clone())
            .execute_block_checked_at(vec![tx_json], &sender, 1, block_time(1), &[], |_, _| Ok(()))
            .unwrap();
        assert!(matches!(outcome, BlockExecOutcome::Executed(_)));
        let queued: Vec<String> = db
            .scan_prefix("sys:fee_sweep_queue:")
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        assert!(!queued.is_empty(), "positive control: a share was queued");
        assert!(
            queued
                .iter()
                .all(|k| k.starts_with("sys:fee_sweep_queue:1:")),
            "keyed by the executing height 1: {queued:?}"
        );
    }

    /// G3 CM-2: a consensus-state write in `accept`, after the root is sealed,
    /// would escape the header's root. The whole block is refused and nothing
    /// it staged is published.
    #[test]
    fn a_state_write_after_the_root_refuses_the_whole_block() {
        let (db, sender, tx_json) = g3_burning_transfer("g3_sealed_block");
        let executor = Executor::new(db.clone());
        let refused = executor.execute_block_checked_at(
            vec![tx_json.clone()],
            &sender,
            1,
            block_time(1),
            &[],
            |_, view| view.put("obj:escapee", "x").map_err(|e| e.to_string()),
        );
        let err = refused.expect_err("a post-seal state write must refuse the block");
        assert!(err.contains("sealed"), "{err}");
        assert_eq!(executor.last_executed_height(), 0, "nothing committed");
        assert_eq!(db.get("obj:escapee").unwrap(), None);
        assert_eq!(
            state_commit::latest_version(&db).unwrap(),
            Some(0),
            "no tree rows beyond genesis either"
        );

        let accepted = executor.execute_block_checked_at(
            vec![tx_json],
            &sender,
            1,
            block_time(1),
            &[],
            |_, view| view.put("latest_height", "1").map_err(|e| e.to_string()),
        );
        assert!(
            matches!(accepted, Ok(BlockExecOutcome::Executed(_))),
            "positive control: chain data after the seal is fine"
        );
    }

    /// G3 S0: a real block writes its consensus state inside the marked block
    /// transaction, so the storage observer counts none of it as out-of-band.
    #[test]
    fn block_execution_writes_state_only_inside_the_block_transaction() {
        let db = temp_db("g3_s0_block_ctx");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[21u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[22u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        set_coin_store(&db, &sender, 1_000_000);
        set_coin_store(&db, &recipient, 0);
        set_validator_set(&db, &sender, 0, 1_000_000_000);
        let _seed = db.seeding();
        db.put("sys:total_supply", "1000000000").unwrap();
        db.put("total_burned", "0").unwrap();

        let call = vm_move::EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                move_core_types::account_address::AccountAddress::ONE,
                move_core_types::identifier::Identifier::new("coin").unwrap(),
            ),
            function: "transfer".to_string(),
            ty_args: vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: move_core_types::account_address::AccountAddress::ONE,
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

        seed_genesis_tree(&db);
        // Seeding above wrote state on the base DB; that is the test's own
        // out-of-band setup, so measure from here.
        let before = db.db.state_class_stats();
        Executor::new(db.clone()).execute_block_parallel(vec![tx_json], &sender);
        let after = db.db.state_class_stats();

        assert_eq!(
            coin_balance(&db, &recipient),
            100,
            "positive control: the block really executed and moved coins"
        );
        assert!(
            after.writes > before.writes,
            "positive control: writes observed"
        );
        assert_eq!(
            after.state_outside_block, before.state_outside_block,
            "block execution wrote state outside the block transaction: {:?}",
            after.samples
        );
    }

    #[test]
    fn test_dex_create_pool_liquidity_swap_and_remove_end_to_end() {
        let db = temp_db("dex_liquidity_swap");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[32u8; 32]);
        let trader = create_account(&db, &trader_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 1_000_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 1_000_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload(
            "dex",
            "create_pool",
            vec![ain.clone(), wbtc.clone()],
            vec![bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap()],
        );
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
            .execute_transaction(&signed_tx(
                &trader_key,
                &trader,
                &remove_payload,
                3,
                10_000,
                1,
            ))
            .expect("remove liquidity accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 9_900);
        assert_eq!(pool.coin_y.value, 8_185);
        assert_eq!(pool.lp_supply, 9_000);
        assert_eq!(
            dex_lp_balance(&db, &trader, ain.clone(), wbtc.clone()),
            8_000
        );
        assert_eq!(coin_balance_for(&db, &trader, ain), 950_100);
        assert_eq!(coin_balance_for(&db, &trader, wbtc), 991_815);
    }

    #[test]
    fn test_dex_duplicate_and_reverse_pool_creation_abort_after_gas() {
        let db = temp_db("dex_duplicate_reverse");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[35u8; 32]);
        let trader = create_account(&db, &trader_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 100_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload(
            "dex",
            "create_pool",
            vec![ain.clone(), wbtc.clone()],
            vec![bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap()],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(
                &trader_key,
                &trader,
                &create_payload,
                0,
                10_000,
                1,
            ))
            .expect("first create accepted");
        apply_updates(&db, updates);
        assert_eq!(dex_registry(&db).pools.len(), 1);

        let reverse_payload = entry_payload(
            "dex",
            "create_pool",
            vec![wbtc.clone(), ain.clone()],
            vec![bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap()],
        );
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
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 100_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload(
            "dex",
            "create_pool",
            vec![ain.clone(), wbtc.clone()],
            vec![bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap()],
        );
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(
                &trader_key,
                &trader,
                &create_payload,
                0,
                10_000,
                1,
            ))
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
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        let overflow_input = (u128::MAX / 9_970) + 1;
        set_coin_store_for(&db, &trader, ain.clone(), overflow_input + 10_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload(
            "dex",
            "create_pool",
            vec![ain.clone(), wbtc.clone()],
            vec![bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap()],
        );
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(
                &trader_key,
                &trader,
                &create_payload,
                0,
                10_000,
                1,
            ))
            .expect("create pool accepted");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);
        set_dex_pool(
            &db,
            &trader,
            ain.clone(),
            wbtc.clone(),
            10_000,
            10_000,
            10_000,
        );

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
    fn test_dex_swap_zero_output_aborts_before_withdrawal() {
        let db = temp_db("dex_zero_output_swap");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[38u8; 32]);
        let trader = create_account(&db, &trader_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 100_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload(
            "dex",
            "create_pool",
            vec![ain.clone(), wbtc.clone()],
            vec![bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap()],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(
                &trader_key,
                &trader,
                &create_payload,
                0,
                10_000,
                1,
            ))
            .expect("create pool accepted");
        apply_updates(&db, updates);
        set_dex_pool(
            &db,
            &trader,
            ain.clone(),
            wbtc.clone(),
            1_000_000_000_000,
            1,
            1_000_000_000_000,
        );

        let payload = entry_payload(
            "dex",
            "swap_x_to_y",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&1u128).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
            ],
        );
        let tx_json = signed_tx(&trader_key, &trader, &payload, 1, 10_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&tx_json)
            .expect("zero-output swap abort is accepted and gas-charged");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 1_000_000_000_000);
        assert_eq!(pool.coin_y.value, 1);
        assert_eq!(
            coin_balance_for(&db, &trader, ain),
            80_000,
            "only create-pool gas and aborted-swap gas should be charged",
        );
        assert_eq!(coin_balance_for(&db, &trader, wbtc), 100_000);
        let receipt = db
            .get(&format!("tx_receipt:{}", tx_hash_hex(&tx_json)))
            .unwrap()
            .expect("receipt stored");
        let receipt: serde_json::Value = serde_json::from_str(&receipt).unwrap();
        assert_eq!(receipt["status"], "aborted");
    }

    #[test]
    fn test_dex_remove_liquidity_rejects_zero_side_output() {
        let db = temp_db("dex_remove_zero_side");
        load_stdlib(&db);
        let trader_key = SigningKey::from_bytes(&[39u8; 32]);
        let trader = create_account(&db, &trader_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        let ain = aincore_coin_type();
        let wbtc = wbtc_coin_type();
        set_coin_store_for(&db, &trader, ain.clone(), 100_000);
        set_coin_store_for(&db, &trader, wbtc.clone(), 100_000);
        set_dex_registry(&db, vec![]);

        let executor = Executor::new(db.clone());
        let create_payload = entry_payload(
            "dex",
            "create_pool",
            vec![ain.clone(), wbtc.clone()],
            vec![bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap()],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(
                &trader_key,
                &trader,
                &create_payload,
                0,
                10_000,
                1,
            ))
            .expect("create pool accepted");
        apply_updates(&db, updates);
        set_dex_pool(
            &db,
            &trader,
            ain.clone(),
            wbtc.clone(),
            1_000_000,
            1,
            1_000_000,
        );
        set_dex_lp_balance(&db, &trader, ain.clone(), wbtc.clone(), 1);

        let payload = entry_payload(
            "dex",
            "remove_liquidity",
            vec![ain.clone(), wbtc.clone()],
            vec![
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&1u128).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
            ],
        );
        let tx_json = signed_tx(&trader_key, &trader, &payload, 1, 10_000, 1);
        let (updates, gas) = executor
            .execute_transaction(&tx_json)
            .expect("zero-side remove abort is accepted and gas-charged");
        assert_eq!(gas, 10_000);
        apply_updates(&db, updates);

        let pool = dex_pool(&db, &trader, ain.clone(), wbtc.clone());
        assert_eq!(pool.coin_x.value, 1_000_000);
        assert_eq!(pool.coin_y.value, 1);
        assert_eq!(pool.lp_supply, 1_000_000);
        assert_eq!(
            dex_lp_balance(&db, &trader, ain.clone(), wbtc.clone()),
            1,
            "LP token must not burn when one side rounds to zero",
        );
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
    fn test_dex_add_liquidity_uses_only_ratio_matched_amounts() {
        let db = temp_db("dex_liquidity_ratio_guard");
        load_stdlib(&db);
        let maker_key = SigningKey::from_bytes(&[37u8; 32]);
        let maker = create_account(&db, &maker_key);
        let lp2_key = SigningKey::from_bytes(&[38u8; 32]);
        let lp2 = create_account(&db, &lp2_key);
        let _seed = db.seeding();
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
            .execute_transaction(&signed_tx(
                &maker_key,
                &maker,
                &create_payload,
                0,
                10_000,
                1,
            ))
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
            .execute_transaction(&signed_tx(
                &lp2_key,
                &lp2,
                &imbalanced_payload,
                0,
                10_000,
                1,
            ))
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
        let _seed = db.seeding();
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
        let _seed = db.seeding();
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
                bcs::to_bytes(&0u8).unwrap(),
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

    /// G5 GV-1: a proposal carrying any action but signalling (0) is refused
    /// before it burns the fee or is stored. Action 1 was the epoch-duration
    /// change that could stretch every deadline.
    #[test]
    fn test_g5_governance_refuses_every_action_but_signalling() {
        let db = temp_db("governance_gv1");
        load_stdlib(&db);
        let sender_key = SigningKey::from_bytes(&[27u8; 32]);
        let sender = create_account(&db, &sender_key);
        let _seed = db.seeding();
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
        let executor = Executor::new(db.clone());
        for (nonce, action) in [1u8, 2, 255].into_iter().enumerate() {
            let payload = entry_payload(
                "governance",
                "create_proposal",
                vec![],
                vec![
                    bcs::to_bytes(&parse_move_address(&sender).unwrap()).unwrap(),
                    bcs::to_bytes(&b"stretch every deadline".to_vec()).unwrap(),
                    bcs::to_bytes(&action).unwrap(),
                    bcs::to_bytes(&60u64).unwrap(),
                ],
            );
            let raw = signed_tx(&sender_key, &sender, &payload, nonce as u64, 10_000, 1);
            let (updates, _) = executor
                .execute_transaction(&raw)
                .expect("tx runs and aborts");
            apply_updates(&db, updates);
            assert_eq!(
                db.get(&governance_state_key()).unwrap().unwrap(),
                "000000000000000000",
                "action {action} was stored"
            );
            assert_eq!(
                db.get("total_burned").unwrap().unwrap(),
                "0",
                "action {action}"
            );
        }
        assert_eq!(validator_set(&db).total_supply, starting_supply);
        let paid = starting_supply - coin_balance(&db, &sender);
        assert!(paid <= 3 * 10_000, "more than gas was paid: {paid}");
    }

    #[test]
    fn test_governance_vote_escrow_locks_real_coin_without_supply_drift() {
        let db = temp_db("governance_vote_escrow");
        load_stdlib(&db);
        let voter_key = SigningKey::from_bytes(&[25u8; 32]);
        let voter = create_account(&db, &voter_key);
        let _seed = db.seeding();
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

        // Called directly, outside a block: test context.
        let _seed = db.seeding();
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

    /// G5 SL-5 (acceptance): verified evidence takes the offender out of the
    /// Move active set, the native mirror and the QC trust root; jails and
    /// tombstones it; and moves its whole stake into unbonding, unlocking U
    /// after the epoch bound (SL-2). Nothing is burned while the fraction is
    /// not final: here one tenth of the committee equivocated, 9 %.
    #[test]
    fn test_accepted_equivocation_unbonds_all_stake_and_removes_validator() {
        let db = temp_db("slash_acceptance");
        load_stdlib(&db);
        let offender = committee_member(21, 100);
        let validator = offender.address.clone();
        let others: Vec<_> = (24u8..27).map(|seed| committee_member(seed, 300)).collect();
        let _seed = db.seeding();
        let mut committee = others.clone();
        committee.push(offender.clone());
        db.put(
            "genesis:validator_set:v1",
            &serde_json::to_string(&committee).unwrap(),
        )
        .unwrap();
        db.put(
            "sys:validator_set:v1",
            &serde_json::to_string(&committee).unwrap(),
        )
        .unwrap();
        db.put(
            "sys:validators",
            &serde_json::to_string(&vec![
                (validator.clone(), 100u64),
                (others[0].address.clone(), 300u64),
            ])
            .unwrap(),
        )
        .unwrap();
        set_validator_set(&db, &validator, 1_000_000, 1_000_000);
        db.put(
            &format!("sys:pending_slash:{}", validator),
            &serde_json::json!({"round": 78, "epoch": 0}).to_string(),
        )
        .unwrap();
        // Height 25 at consensus time 1,000 s: G5 SL-2 unlocks the stake U
        // after the epoch bound, 1,000 + I x C_tau (20 x 14 s).
        let clock = ChainClock {
            height: 25,
            time: 1_000,
            block_timestamp: 9_000,
        };
        db.put(
            &vm_move::state_keys::resource_key_str(&system_address(), "0x1::chain::Clock"),
            &hex::encode(bcs::to_bytes(&clock).unwrap()),
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
        assert_eq!(
            db.get(&format!("validator:jailed:{}", validator))
                .unwrap()
                .as_deref(),
            Some("78")
        );
        let native_validators: Vec<(String, u64)> =
            serde_json::from_str(&db.get("sys:validators").unwrap().unwrap()).unwrap();
        assert_eq!(native_validators, vec![(others[0].address.clone(), 300)]);
        let live: Vec<blockchain::committee::ValidatorInfo> =
            serde_json::from_str(&db.get("sys:validator_set:v1").unwrap().unwrap()).unwrap();
        assert!(!live.iter().any(|m| m.address == validator));

        let move_validators = validator_set(&db);
        assert!(move_validators.validators.is_empty());
        assert_eq!(move_validators.unbonding_queue.len(), 1);
        let entry = &move_validators.unbonding_queue[0];
        assert_eq!(
            (entry.stake, entry.start_height, entry.unlock_time),
            (1_000_000, 25, 1_000 + 280 + 21 * 86_400)
        );
        assert_eq!(
            move_validators.total_supply, 1_000_000,
            "nothing burned yet"
        );
        let offenses = g5_offenses(&db);
        assert_eq!(offenses.len(), 1);
        assert_eq!(
            (
                offenses[0].weight,
                offenses[0].committee_weight,
                offenses[0].settled
            ),
            (100, 1_000, false)
        );
    }

    // ---- 0x1::universal_mining device registration -------------------------
    //
    // Mirrors of the Move layouts. Registrations live in DeviceClaims at each
    // owner's address; the global DeviceRegistry at @0x1 holds only
    // feeder-verified bindings.

    /// universal_mining::MAX_DEVICES_PER_OWNER.
    const MAX_DEVICES_PER_OWNER: usize = 32;
    /// universal_mining::MAX_VERIFIED_DEVICES.
    const MAX_VERIFIED_DEVICES: usize = 10_000;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    struct TestDeviceClaim {
        device_pubkey: Vec<u8>,
        device_type: u8,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestDeviceClaims {
        devices: Vec<TestDeviceClaim>,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
    struct TestVerifiedDevice {
        device_pubkey: Vec<u8>,
        owner_addr: move_core_types::account_address::AccountAddress,
        last_reward_epoch: u64,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestDeviceRegistry {
        devices: Vec<TestVerifiedDevice>,
    }

    #[derive(Serialize)]
    struct TestOracleConfig {
        feeders: Vec<move_core_types::account_address::AccountAddress>,
        threshold: u64,
        active_proofs: Vec<u8>, // empty -> BCS [0], same as empty Vec<PendingProof>
    }

    #[derive(Serialize)]
    struct TestEmissionPools {
        depin_budget: u128,
    }

    fn um_key(addr: &move_core_types::account_address::AccountAddress, name: &str) -> String {
        vm_move::state_keys::resource_key_str(addr, &format!("0x1::universal_mining::{}", name))
    }

    fn registry_key() -> String {
        um_key(&system_address(), "DeviceRegistry")
    }

    /// An address whose last 8 bytes are `n`, for seeding many owners.
    fn nth_addr(n: u64) -> move_core_types::account_address::AccountAddress {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xd0;
        bytes[24..].copy_from_slice(&n.to_be_bytes());
        move_core_types::account_address::AccountAddress::new(bytes)
    }

    /// A 32-byte device key whose first 8 bytes are `n`.
    fn nth_key(n: u64) -> Vec<u8> {
        let mut key = vec![0x5a; 32];
        key[..8].copy_from_slice(&n.to_be_bytes());
        key
    }

    /// The universal_mining state genesis creates (registry plus an oracle
    /// whose only feeder is @0x1), with `verified` already in the registry.
    fn seed_device_state(db: &StateDB, verified: Vec<TestVerifiedDevice>) {
        let _seed = db.seeding();
        db.put(
            &registry_key(),
            &hex::encode(bcs::to_bytes(&TestDeviceRegistry { devices: verified }).unwrap()),
        )
        .unwrap();
        db.put(
            &um_key(&system_address(), "OracleConfig"),
            &hex::encode(
                bcs::to_bytes(&TestOracleConfig {
                    feeders: vec![system_address()],
                    threshold: 1,
                    active_proofs: vec![],
                })
                .unwrap(),
            ),
        )
        .unwrap();
    }

    fn device_registry(db: &StateDB) -> TestDeviceRegistry {
        bcs::from_bytes(&hex::decode(db.get(&registry_key()).unwrap().unwrap()).unwrap()).unwrap()
    }

    fn device_claims(
        db: &StateDB,
        owner: &move_core_types::account_address::AccountAddress,
    ) -> Option<TestDeviceClaims> {
        db.get(&um_key(owner, "DeviceClaims"))
            .unwrap()
            .map(|v| bcs::from_bytes(&hex::decode(v).unwrap()).unwrap())
    }

    /// Calls `0x1::universal_mining::{function}` as `auth`, with `args` after
    /// the signer slot, at the per-transaction gas ceiling.
    fn device_call(
        executor: &Executor,
        function: &str,
        auth: move_core_types::account_address::AccountAddress,
        args: Vec<Vec<u8>>,
    ) -> (u64, Vec<(String, Option<String>)>, vm_move::ExecutionStatus) {
        let mut all = vec![bcs::to_bytes(&auth).unwrap()];
        all.extend(args);
        executor
            .vm
            .execute_public_entry_function(
                vec![],
                move_core_types::language_storage::ModuleId::new(
                    system_address(),
                    move_core_types::identifier::Identifier::new("universal_mining").unwrap(),
                ),
                function,
                vec![],
                all,
                MAX_GAS_LIMIT,
                auth,
            )
            .expect("universal_mining call executes")
    }

    fn register(
        executor: &Executor,
        owner: move_core_types::account_address::AccountAddress,
        key: &[u8],
    ) -> (u64, Vec<(String, Option<String>)>, vm_move::ExecutionStatus) {
        device_call(
            executor,
            "register_device",
            owner,
            vec![bcs::to_bytes(key).unwrap(), bcs::to_bytes(&1u8).unwrap()],
        )
    }

    fn verify(
        executor: &Executor,
        owner: move_core_types::account_address::AccountAddress,
        key: &[u8],
    ) -> (u64, Vec<(String, Option<String>)>, vm_move::ExecutionStatus) {
        device_call(
            executor,
            "add_verified_device",
            system_address(),
            vec![bcs::to_bytes(&owner).unwrap(), bcs::to_bytes(key).unwrap()],
        )
    }

    /// True when the call aborted in universal_mining with `code`.
    fn aborted_with(status: &vm_move::ExecutionStatus, code: u64) -> bool {
        !status.success
            && status.error.as_deref().is_some_and(|e| {
                e.contains(&format!("ABORTED with sub status {} at", code))
                    && e.contains("universal_mining")
            })
    }

    /// FIX H3: device registration front-run lockout + reward theft.
    /// (1) Owner A registers pubkey P; attacker B registers the SAME pubkey P
    ///     under B -- this must NOT abort (scoped duplicate guard closes the
    ///     lockout). (2) A feeder verifies only (A, P). (3) Only the verified
    ///     binding is eligible for rewards (B stays unverified, earns nothing).
    #[test]
    fn test_h3_no_lockout_and_only_verified_owner_is_bound() {
        let db = temp_db("h3_device");
        load_stdlib(&db);
        // Tests apply execution results outside a block (G3 WG-1).
        let _seed = db.seeding();
        seed_device_state(&db, vec![]);
        let executor = Executor::new(db.clone());
        let owner_a = parse_move_address("12121212121212121212121212121212").unwrap();
        let owner_b = parse_move_address("34343434343434343434343434343434").unwrap();
        let pubkey: Vec<u8> = vec![9u8; 32];

        // A registers P, then B registers the SAME P -- the second MUST succeed.
        for owner in [owner_a, owner_b] {
            let (_gas, updates, status) = register(&executor, owner, &pubkey);
            assert!(
                status.success,
                "register_device must not abort: {:?}",
                status
            );
            apply_updates(&db, updates);
        }
        for owner in [owner_a, owner_b] {
            assert_eq!(
                device_claims(&db, &owner).expect("each owner holds its own registration"),
                TestDeviceClaims {
                    devices: vec![TestDeviceClaim {
                        device_pubkey: pubkey.clone(),
                        device_type: 1
                    }]
                },
                "no lockout: both owners registered the same pubkey"
            );
        }
        assert!(
            device_registry(&db).devices.is_empty(),
            "registrations are unverified and stay out of the registry"
        );

        // Feeder @0x1 verifies ONLY (A, P).
        let (_gas, updates, status) = verify(&executor, owner_a, &pubkey);
        assert!(status.success, "feeder verify must succeed: {:?}", status);
        apply_updates(&db, updates);
        assert_eq!(
            device_registry(&db).devices,
            vec![TestVerifiedDevice {
                device_pubkey: pubkey.clone(),
                owner_addr: owner_a,
                last_reward_epoch: 0
            }],
            "only owner A's binding is verified; B's front-run binding earns nothing"
        );

        // And B cannot be verified for P afterwards: one verified owner per key.
        let (_gas, _updates, status) = verify(&executor, owner_b, &pubkey);
        assert!(aborted_with(&status, 0x50001), "{:?}", status);
    }

    /// G3 S6 open item: `register_device` appended to one global vector for
    /// anyone and scanned it every call. Before this fix the measured cost was
    /// 125 + 180*N gas for N registered devices, key bytes were free, and the
    /// call ran out of gas for everyone at N ~ 55,500.
    ///
    /// Now a registration touches only the caller's own DeviceClaims: its gas
    /// does not depend on how many devices anyone else registered or how full
    /// the verified registry is, and it never writes the registry.
    #[test]
    fn register_device_cost_does_not_grow_with_other_registrations() {
        let fresh_owner_gas = |registry_len: usize, other_owners: u64| {
            let db = temp_db(&format!("device_cost_{}_{}", registry_len, other_owners));
            load_stdlib(&db);
            // Tests apply execution results outside a block (G3 WG-1).
            let _seed = db.seeding();
            seed_device_state(
                &db,
                (0..registry_len as u64)
                    .map(|i| TestVerifiedDevice {
                        device_pubkey: nth_key(i),
                        owner_addr: nth_addr(i),
                        last_reward_epoch: 0,
                    })
                    .collect(),
            );
            let executor = Executor::new(db.clone());
            for i in 0..other_owners {
                let (_gas, updates, status) =
                    register(&executor, nth_addr(1_000_000 + i), &nth_key(i));
                assert!(status.success, "{:?}", status);
                apply_updates(&db, updates);
            }
            let owner = nth_addr(u64::MAX);
            let (gas, updates, status) = register(&executor, owner, &nth_key(7));
            assert!(status.success, "{:?}", status);
            let keys: Vec<&str> = updates.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(
                keys,
                vec![um_key(&owner, "DeviceClaims").as_str()],
                "a registration writes only the caller's own DeviceClaims"
            );
            gas
        };
        let empty = fresh_owner_gas(0, 0);
        let crowded = fresh_owner_gas(MAX_VERIFIED_DEVICES, 200);
        println!("register_device, first device: {empty} gas (empty chain), {crowded} gas (full registry, 200 other owners)");
        assert_eq!(
            empty, crowded,
            "a registration's gas must not depend on anyone else's"
        );

        // One owner's k-th registration: bounded by MAX_DEVICES_PER_OWNER.
        let db = temp_db("device_cost_one_owner");
        load_stdlib(&db);
        // Tests apply execution results outside a block (G3 WG-1).
        let _seed = db.seeding();
        seed_device_state(&db, vec![]);
        let executor = Executor::new(db.clone());
        let owner = nth_addr(1);
        let mut last = 0;
        for k in 0..MAX_DEVICES_PER_OWNER as u64 {
            let (gas, updates, status) = register(&executor, owner, &nth_key(k));
            assert!(status.success, "{:?}", status);
            apply_updates(&db, updates);
            last = gas;
        }
        println!("register_device, device {MAX_DEVICES_PER_OWNER} of one owner: {last} gas");
        assert!(last < 50_000, "the most a registration can cost: {last}");
    }

    /// The pubkey is the only caller-sized part of a registration. It must be
    /// exactly 32 bytes (Ed25519); before this fix a 16 MiB key cost 125 gas.
    #[test]
    fn register_device_refuses_a_pubkey_that_is_not_32_bytes() {
        let db = temp_db("device_key_len");
        load_stdlib(&db);
        // Tests apply execution results outside a block (G3 WG-1).
        let _seed = db.seeding();
        seed_device_state(&db, vec![]);
        let executor = Executor::new(db.clone());
        let owner = nth_addr(1);
        for len in [0usize, 1, 31, 33, 64, 51_200, 1024 * 1024] {
            let (_gas, updates, status) = register(&executor, owner, &vec![7u8; len]);
            assert!(aborted_with(&status, 0x10005), "len {len}: {:?}", status);
            assert!(
                updates.is_empty(),
                "len {len}: an aborted registration writes nothing"
            );
        }
        let (_gas, updates, status) = register(&executor, owner, &[7u8; 32]);
        assert!(status.success, "{:?}", status);
        apply_updates(&db, updates);
        assert_eq!(device_claims(&db, &owner).unwrap().devices.len(), 1);
    }

    #[test]
    fn register_device_caps_devices_per_owner() {
        let db = temp_db("device_owner_cap");
        load_stdlib(&db);
        // Tests apply execution results outside a block (G3 WG-1).
        let _seed = db.seeding();
        seed_device_state(&db, vec![]);
        let executor = Executor::new(db.clone());
        let owner = nth_addr(1);
        for k in 0..MAX_DEVICES_PER_OWNER as u64 {
            let (_gas, updates, status) = register(&executor, owner, &nth_key(k));
            assert!(status.success, "device {k}: {:?}", status);
            apply_updates(&db, updates);
        }
        let (_gas, updates, status) = register(&executor, owner, &nth_key(999));
        assert!(aborted_with(&status, 0x90006), "{:?}", status);
        assert!(updates.is_empty());
        assert_eq!(
            device_claims(&db, &owner).unwrap().devices.len(),
            MAX_DEVICES_PER_OWNER
        );

        // Another owner is unaffected by the first owner's cap.
        let (_gas, _updates, status) = register(&executor, nth_addr(2), &nth_key(999));
        assert!(status.success, "{:?}", status);
    }

    /// Only feeders add to the registry, and only up to MAX_VERIFIED_DEVICES.
    /// A full registry refuses new bindings but still accepts re-verifying one
    /// it holds, and the feeder's worst call stays under a fifth of the
    /// per-transaction ceiling.
    #[test]
    fn add_verified_device_stops_at_the_registry_cap() {
        let db = temp_db("device_registry_cap");
        load_stdlib(&db);
        // Tests apply execution results outside a block (G3 WG-1).
        let _seed = db.seeding();
        seed_device_state(
            &db,
            (0..MAX_VERIFIED_DEVICES as u64 - 1)
                .map(|i| TestVerifiedDevice {
                    device_pubkey: nth_key(i),
                    owner_addr: nth_addr(i),
                    last_reward_epoch: 0,
                })
                .collect(),
        );
        let executor = Executor::new(db.clone());
        let (a, b) = (nth_addr(u64::MAX), nth_addr(u64::MAX - 1));
        let (key_a, key_b) = (vec![0xaa; 32], vec![0xbb; 32]);
        for (owner, key) in [(a, &key_a), (b, &key_b)] {
            let (_gas, updates, status) = register(&executor, owner, key);
            assert!(status.success, "{:?}", status);
            apply_updates(&db, updates);
        }

        let (gas, updates, status) = verify(&executor, a, &key_a);
        assert!(status.success, "the last free slot is usable: {:?}", status);
        apply_updates(&db, updates);
        assert_eq!(device_registry(&db).devices.len(), MAX_VERIFIED_DEVICES);
        println!(
            "add_verified_device into a registry of {} devices: {gas} gas",
            MAX_VERIFIED_DEVICES - 1
        );
        assert!(gas < MAX_GAS_LIMIT / 5, "feeder call at the cap: {gas}");
        let registry_bytes = db.get(&registry_key()).unwrap().unwrap().len() / 2;
        assert!(
            registry_bytes < 1024 * 1024,
            "full registry: {registry_bytes} bytes"
        );

        let (_gas, updates, status) = verify(&executor, b, &key_b);
        assert!(aborted_with(&status, 0x90007), "{:?}", status);
        assert!(updates.is_empty());

        let (_gas, _updates, status) = verify(&executor, a, &key_a);
        assert!(
            status.success,
            "re-verifying a held binding is a no-op: {:?}",
            status
        );

        // The reward lookup's worst case: the last entry of a full registry.
        let (gas, _updates, status) = device_call(
            &executor,
            "submit_mining_proof",
            system_address(),
            vec![
                bcs::to_bytes(&key_a).unwrap(),
                bcs::to_bytes(&100u64).unwrap(),
            ],
        );
        assert!(status.success, "{:?}", status);
        println!("submit_mining_proof for the last of {MAX_VERIFIED_DEVICES} devices: {gas} gas");
        assert!(gas < MAX_GAS_LIMIT / 5, "reward lookup at the cap: {gas}");
    }

    /// The honest reward path through the new registry: register, verify, and
    /// a finalized proof pays the owner once per epoch.
    #[test]
    fn a_verified_device_is_paid_once_per_epoch() {
        let db = temp_db("device_reward");
        load_stdlib(&db);
        // Tests apply execution results outside a block (G3 WG-1).
        let _seed = db.seeding();
        seed_device_state(&db, vec![]);
        let owner_hex = "5656565656565656565656565656565656565656565656565656565656565656";
        let owner = parse_move_address(owner_hex).unwrap();
        set_coin_store(&db, owner_hex, 0);
        let set_epoch = |epoch: u64| {
            let _seed = db.seeding();
            let set = TestValidatorSet {
                validators: vec![],
                unbonding_queue: vec![],
                total_supply: 0,
                current_epoch: epoch,
            };
            db.put(
                &validator_set_key(),
                &hex::encode(bcs::to_bytes(&set).unwrap()),
            )
            .unwrap();
        };
        set_epoch(1);
        {
            let _seed = db.seeding();
            db.put(
                &vm_move::state_keys::resource_key_str(
                    &system_address(),
                    "0x1::staking::EmissionPools",
                ),
                &hex::encode(
                    bcs::to_bytes(&TestEmissionPools {
                        depin_budget: 10_000_000_000_000_000_000,
                    })
                    .unwrap(),
                ),
            )
            .unwrap();
        }
        let executor = Executor::new(db.clone());
        let key = vec![0x42; 32];
        let (_gas, updates, status) = register(&executor, owner, &key);
        assert!(status.success, "{:?}", status);
        apply_updates(&db, updates);
        let (_gas, updates, status) = verify(&executor, owner, &key);
        assert!(status.success, "{:?}", status);
        apply_updates(&db, updates);

        let prove = || {
            let (_gas, updates, status) = device_call(
                &executor,
                "submit_mining_proof",
                system_address(),
                vec![
                    bcs::to_bytes(&key).unwrap(),
                    bcs::to_bytes(&100u64).unwrap(),
                ],
            );
            assert!(status.success, "{:?}", status);
            apply_updates(&db, updates);
        };
        const REWARD: u128 = 360_000_000_000_000_000; // 0.36 AIN at bqi 100
        prove();
        assert_eq!(coin_balance(&db, owner_hex), REWARD, "paid in epoch 1");
        prove();
        assert_eq!(
            coin_balance(&db, owner_hex),
            REWARD,
            "not paid twice in one epoch"
        );
        assert_eq!(device_registry(&db).devices[0].last_reward_epoch, 1);
        set_epoch(2);
        prove();
        assert_eq!(
            coin_balance(&db, owner_hex),
            2 * REWARD,
            "paid again in epoch 2"
        );
    }

    /// Honest registration through a real signed transaction (gas prologue,
    /// signer binding, commit), and an over-long key through the same path:
    /// charged gas, no registration.
    #[test]
    fn register_device_through_a_signed_transaction() {
        let db = temp_db("device_signed_tx");
        load_stdlib(&db);
        // Tests apply execution results outside a block (G3 WG-1).
        let _seed = db.seeding();
        seed_device_state(&db, vec![]);
        let signing_key = SigningKey::from_bytes(&[31u8; 32]);
        let sender = create_account(&db, &signing_key);
        {
            let _seed = db.seeding();
            db.set_federation_key("00000000000000000000000000000000")
                .unwrap();
        }
        set_coin_store(&db, &sender, 1_000_000);
        let executor = Executor::new(db.clone());
        let owner = parse_move_address(&sender).unwrap();
        let payload = |key: Vec<u8>| {
            entry_payload(
                "universal_mining",
                "register_device",
                vec![],
                vec![
                    bcs::to_bytes(&owner).unwrap(),
                    bcs::to_bytes(&key).unwrap(),
                    bcs::to_bytes(&3u8).unwrap(),
                ],
            )
        };

        let (updates, gas) = executor
            .execute_transaction(&signed_tx(
                &signing_key,
                &sender,
                &payload(vec![1; 32]),
                0,
                100_000,
                1,
            ))
            .expect("registration accepted");
        assert_eq!(gas, 100_000);
        apply_updates(&db, updates);
        assert_eq!(
            device_claims(&db, &owner).unwrap().devices,
            vec![TestDeviceClaim {
                device_pubkey: vec![1; 32],
                device_type: 3
            }]
        );
        assert_eq!(coin_balance(&db, &sender), 900_000);

        let (updates, gas) = executor
            .execute_transaction(&signed_tx(
                &signing_key,
                &sender,
                &payload(vec![2; 4096]),
                1,
                100_000,
                1,
            ))
            .expect("the transaction is kept: gas is charged even though it aborts");
        assert_eq!(gas, 100_000);
        apply_updates(&db, updates);
        assert_eq!(
            device_claims(&db, &owner).unwrap().devices.len(),
            1,
            "the over-long key was not registered"
        );
        assert_eq!(coin_balance(&db, &sender), 800_000);
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
        let _seed = db.seeding();
        db.put(
            "sys:validators",
            &serde_json::to_string(&validators).unwrap(),
        )
        .unwrap();

        // Only ONE reporter attests against the offender.
        let offender = &validators[0].0;
        let reporter = &validators[1].0;
        db.put(
            &format!("sys:downtime_attestation:{}:{}:{}", offender, 7, reporter),
            &serde_json::json!({"reason": "downtime"}).to_string(),
        )
        .unwrap();

        let executor = Executor::new(db.clone());
        executor.promote_downtime_attestations_to_slash();

        // No pending_slash queued — single reporter is below quorum.
        assert!(
            db.get(&format!("sys:pending_slash:{}", offender))
                .unwrap()
                .is_none(),
            "single-reporter attestation must NOT promote to a slash"
        );
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
        let _seed = db.seeding();
        db.put(
            "sys:validators",
            &serde_json::to_string(&validators).unwrap(),
        )
        .unwrap();

        let offender = &validators[0].0;
        // 3 distinct reporters (out of 4) — exactly BFT quorum.
        for reporter in &validators[1..] {
            db.put(
                &format!("sys:downtime_attestation:{}:{}:{}", offender, 9, reporter.0),
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
        // Stake-weighted quorum (SEC-#17): 3 reporters × 100 = 300 of 400 total > 2/3.
        assert_eq!(parsed["reporter_stake"].as_str(), Some("300"));
        assert_eq!(parsed["total_stake"].as_str(), Some("400"));

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

    /// SEC-#17: low-stake Sybil reporters that reach COUNT quorum but NOT
    /// stake quorum must NOT slash a high-stake honest validator.
    #[test]
    fn downtime_lowstake_sybil_below_stake_quorum_does_not_slash() {
        let db = temp_db("downtime_sybil_stake");
        // 1 big honest validator + 3 tiny Sybil validators. Count quorum
        // ((4*2/3)+1 = 3) is reachable by the 3 tinies, but their stake
        // (3) is far below 2/3 of total (1003).
        let validators: Vec<(String, u64)> = vec![
            ("aaaa".repeat(8), 1000),
            ("bbbb".repeat(8), 1),
            ("cccc".repeat(8), 1),
            ("dddd".repeat(8), 1),
        ];
        let _seed = db.seeding();
        db.put("sys:validators", &serde_json::to_string(&validators).unwrap())
            .unwrap();
        let offender = &validators[0].0; // the big honest one
        for reporter in &validators[1..] {
            db.put(
                &format!("sys:downtime_attestation:{}:{}:{}", offender, 9, reporter.0),
                &serde_json::json!({"reason": "downtime", "round": 500}).to_string(),
            )
            .unwrap();
        }
        let executor = Executor::new(db.clone());
        executor.promote_downtime_attestations_to_slash();
        // No slash: 3 reporter-stake of 1003 total does not meet >2/3.
        assert!(
            db.get(&format!("sys:pending_slash:{}", offender))
                .unwrap()
                .is_none(),
            "low-stake Sybil reporters must not reach stake quorum to slash"
        );
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
        let _seed = db.seeding();
        db.put(
            "sys:validators",
            &serde_json::to_string(&validators).unwrap(),
        )
        .unwrap();

        let offender = &validators[0].0;
        // 2 valid reporters + 1 stale (not in validator set) = only 2 count.
        // 2 < BFT quorum of 3 → no slash should be queued.
        let valid_reporters = [&validators[1].0, &validators[2].0];
        let stale_reporter = "ffff".repeat(8);

        for reporter in valid_reporters.iter() {
            db.put(
                &format!("sys:downtime_attestation:{}:{}:{}", offender, 11, reporter),
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

        assert!(
            db.get(&format!("sys:pending_slash:{}", offender))
                .unwrap()
                .is_none(),
            "stale reporter must not push the group over quorum"
        );
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
                &format!("sys:downtime_attestation:{}:{}:{}", offender, 7, reporter.0),
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
        let _seed = db.seeding();
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

    fn committee_a1(vs: &[(&str, u64)]) -> Vec<(String, u64)> {
        vs.iter().map(|(a, s)| (a.to_string(), *s)).collect()
    }

    #[test]
    fn a1_empty_validator_set_falls_back_to_leader() {
        let payouts = Executor::compute_block_payouts("leader", 1_000, &[]);

        assert_eq!(payouts.len(), 1);
        assert_eq!(payouts[0], ("leader".to_string(), 1_000));
    }

    #[test]
    fn a1_single_validator_gets_everything() {
        let payouts =
            Executor::compute_block_payouts("alice", 1_000, &committee_a1(&[("alice", 100)]));

        // alice = anchor leader, also sole pool member
        // total must == 1_000, no funds lost
        let total: u128 = payouts.iter().map(|(_, s)| s).sum();
        assert_eq!(total, 1_000);
        // Should be a single entry for alice with 1_000
        assert_eq!(payouts.iter().find(|(a, _)| a == "alice").unwrap().1, 1_000);
    }

    #[test]
    fn a1_stake_proportional_distribution() {
        // 3 validators with stakes 100, 200, 700 (total 1000)
        // Leader bonus: 20% of 1000 = 200 → leader (alice)
        // Pool: 80% of 1000 = 800
        //   alice (100/1000): 80
        //   bob   (200/1000): 160
        //   carol (700/1000): 560
        //   sum: 800 (no remainder)
        // Final: alice = 200 + 80 = 280, bob = 160, carol = 560
        let payouts = Executor::compute_block_payouts(
            "alice",
            1_000,
            &committee_a1(&[("alice", 100), ("bob", 200), ("carol", 700)]),
        );

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
        let payouts = Executor::compute_block_payouts(
            "alice",
            100,
            &committee_a1(&[("alice", 1), ("bob", 1), ("carol", 1)]),
        );

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
        let payouts = Executor::compute_block_payouts(
            "ghost_leader",
            1_000,
            &committee_a1(&[("bob", 100), ("carol", 100)]),
        );

        let map: std::collections::HashMap<String, u128> = payouts.into_iter().collect();
        // ghost_leader gets 20% bonus = 200
        assert_eq!(*map.get("ghost_leader").unwrap_or(&0), 200);
        // bob + carol split 800 equally = 400 each
        assert_eq!(*map.get("bob").unwrap_or(&0), 400);
        assert_eq!(*map.get("carol").unwrap_or(&0), 400);

        let total: u128 = map.values().sum();
        assert_eq!(total, 1_000);
    }

    /// SECURITY (forged non-leading signer): any account may publish its own
    /// module, and `bind_signer_args` used to rebind only the LEADING run of
    /// &signer parameters. A module whose signer is NOT first therefore received
    /// caller-supplied bytes in that slot, which move-vm turns into a signer for
    /// any address the caller names -- a forged signer that `0x1::coin::transfer`
    /// (a public entry fun, callable cross-module) will honour, draining the
    /// victim. This drives the whole thing through the real transaction path
    /// (publish tx, then a call tx) against a module compiled to the attacker's
    /// address, and asserts the victim keeps every coin.
    ///
    /// The fixture module (tests/fixtures/nonleading_signer_exploit.move):
    ///   public entry fun steal<C>(amount: u128, victim: &signer, thief: address)
    ///       { coin::transfer<C>(victim, thief, amount) }
    /// is compiled to 0x0e1b4e0d..., the address derived from ATTACKER_SEED, so
    /// only that key may publish it. If the derivation ever drifts from the
    /// baked-in bytecode, the address assert below fails loudly rather than the
    /// publish silently no-opping.
    #[test]
    fn security_nonleading_signer_cannot_forge_victim() {
        const ATTACKER_SEED: [u8; 32] = [91u8; 32];
        const VICTIM_SEED: [u8; 32] = [92u8; 32];

        let db = temp_db("nonleading_signer_forge");
        load_stdlib(&db);

        let attacker_key = SigningKey::from_bytes(&ATTACKER_SEED);
        let victim_key = SigningKey::from_bytes(&VICTIM_SEED);
        let attacker = create_account(&db, &attacker_key);
        let victim = create_account(&db, &victim_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();

        // The exploit bytecode is compiled to the attacker's address; if the seed
        // ever stops deriving that address the fixture is stale, so pin it.
        assert_eq!(
            attacker, "0e1b4e0d165bed857e8a3232ee9865b7001e4e7945887e6f7d149c5807ccaf08",
            "attacker address drifted from the compiled fixture"
        );

        // Victim holds real coin; attacker holds enough to pay publish + call gas.
        set_coin_store(&db, &victim, 1_000_000);
        set_coin_store(&db, &attacker, 5_000_000);

        let executor = Executor::new(db.clone());

        // 1) Attacker publishes the exploit module.
        let module_bytes = include_bytes!("../tests/fixtures/nonleading_signer_exploit.mv").to_vec();
        let publish = vm_move::TransactionPayload::PublishModule(vec![module_bytes]);
        let publish_hex = hex::encode(bcs::to_bytes(&publish).unwrap());
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&attacker_key, &attacker, &publish_hex, 0, 1_000_000, 1))
            .expect("publish tx accepted");
        apply_updates(&db, updates);

        // 2) Attacker calls steal(amount, victim, thief=attacker) with the victim
        //    address sitting in the non-leading signer slot.
        let ain = move_core_types::language_storage::TypeTag::Struct(Box::new(
            move_core_types::language_storage::StructTag {
                address: move_core_types::account_address::AccountAddress::ONE,
                module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                type_params: vec![],
            },
        ));
        let call = EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                parse_move_address(&attacker).unwrap(),
                move_core_types::identifier::Identifier::new("exploit").unwrap(),
            ),
            function: "steal".to_string(),
            ty_args: vec![ain],
            args: vec![
                bcs::to_bytes(&500_000u128).unwrap(),
                bcs::to_bytes(&parse_move_address(&victim).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_address(&attacker).unwrap()).unwrap(),
            ],
        };
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap(),
        );
        // The call may succeed (signer rebound to attacker -> a self-transfer) or
        // abort; either outcome is fine. What must hold is that the VICTIM is not
        // touched. Include it in a block regardless.
        if let Some((updates, _)) =
            executor.execute_transaction(&signed_tx(&attacker_key, &attacker, &payload, 1, 1_000_000, 1))
        {
            apply_updates(&db, updates);
        }

        assert_eq!(
            coin_balance(&db, &victim),
            1_000_000,
            "victim balance must be untouched: a non-leading signer slot must never \
             carry a caller-supplied address"
        );
    }

    /// SECURITY (forged signer via vector<signer>): the leading/non-leading fix
    /// only inspected top-level signer slots. A signer reached through a
    /// composite -- here `vector<signer>` -- was never rebound, so a published
    /// module could forge @0x1 itself and call coin::deposit_fee_reward, whose
    /// only guard is `address_of(sys) == @0x1`, minting AincoreCoin from nothing.
    /// That is unlimited inflation, strictly worse than the drain. This drives it
    /// through the real publish+call path and asserts no coin is minted.
    ///
    /// Fixture (tests/fixtures/vector_signer_mint_forge.move), compiled to the
    /// attacker address 0e1b4e0d... (seed [91;32]):
    ///   public entry fun forge_mint(sys: vector<signer>, to: address, amount: u128)
    ///       { coin::deposit_fee_reward<staking::AincoreCoin>(vector::borrow(&sys,0), to, amount) }
    #[test]
    fn security_vector_signer_cannot_forge_system_mint() {
        const ATTACKER_SEED: [u8; 32] = [91u8; 32];

        let db = temp_db("vector_signer_mint_forge");
        load_stdlib(&db);

        let attacker_key = SigningKey::from_bytes(&ATTACKER_SEED);
        let attacker = create_account(&db, &attacker_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        assert_eq!(
            attacker, "0e1b4e0d165bed857e8a3232ee9865b7001e4e7945887e6f7d149c5807ccaf08",
            "attacker address drifted from the compiled fixture"
        );

        // Attacker starts with a known AIN balance and a registered store.
        set_coin_store(&db, &attacker, 5_000_000);
        let start = coin_balance(&db, &attacker);

        let executor = Executor::new(db.clone());

        // 1) Publish the vector<signer> mint-forge module.
        let module_bytes =
            include_bytes!("../tests/fixtures/vector_signer_mint_forge.mv").to_vec();
        let publish = vm_move::TransactionPayload::PublishModule(vec![module_bytes]);
        let publish_hex = hex::encode(bcs::to_bytes(&publish).unwrap());
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&attacker_key, &attacker, &publish_hex, 0, 1_000_000, 1))
            .expect("publish tx accepted");
        apply_updates(&db, updates);

        // 2) Call forge_mint(vector<signer>=[@0x1], to=attacker, amount=1e9).
        //    The vector-wrapped signer is the forged @0x1.
        let one = move_core_types::account_address::AccountAddress::ONE;
        let call = EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                parse_move_address(&attacker).unwrap(),
                move_core_types::identifier::Identifier::new("vsigforge").unwrap(),
            ),
            function: "forge_mint".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&vec![one]).unwrap(), // vector<signer> = [@0x1]
                bcs::to_bytes(&parse_move_address(&attacker).unwrap()).unwrap(),
                bcs::to_bytes(&1_000_000_000u128).unwrap(),
            ],
        };
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap(),
        );
        // Must be rejected by bind_signer_args (vector<signer> is non-rebindable).
        // Include in a block regardless; the mint must not happen.
        if let Some((updates, _)) = executor
            .execute_transaction(&signed_tx(&attacker_key, &attacker, &payload, 1, 1_000_000, 1))
        {
            apply_updates(&db, updates);
        }

        let end = coin_balance(&db, &attacker);
        assert!(
            end <= start,
            "attacker minted AIN via a forged @0x1 signer: {} -> {} (must never increase)",
            start,
            end
        );
    }

    /// PRE-MAINNET AUDIT B1 (CRITICAL). The two earlier forge fixes both closed
    /// signer REACHABILITY. This attack forges no signer at all, so neither guard
    /// fires: the attacker declares a plain `Coin<AincoreCoin>` VALUE parameter.
    /// move-vm's `deserialize_args` builds any declared parameter from the
    /// caller's BCS bytes, so `Coin { value: N }` is manufactured from nothing and
    /// deposited -- unlimited inflation from a two-line module any account may
    /// publish. move-vm deliberately delegates argument-type validation to the
    /// adapter, so the fix is an allowlist in `bind_signer_args`.
    ///
    /// Fixture (tests/fixtures/coin_value_arg_forge.move), compiled against the
    /// real stdlib to the attacker address 0e1b4e0d... (seed [91;32]):
    ///   public entry fun forge_coin(to: address, c: coin::Coin<staking::AincoreCoin>)
    ///       { coin::deposit<staking::AincoreCoin>(to, c) }
    /// The Move compiler ACCEPTS that signature -- nothing below the adapter stops it.
    #[test]
    fn security_struct_value_arg_cannot_forge_coin() {
        const ATTACKER_SEED: [u8; 32] = [91u8; 32];

        let db = temp_db("coin_value_arg_forge");
        load_stdlib(&db);

        let attacker_key = SigningKey::from_bytes(&ATTACKER_SEED);
        let attacker = create_account(&db, &attacker_key);
        let _seed = db.seeding();
        db.set_federation_key("00000000000000000000000000000000")
            .unwrap();
        assert_eq!(
            attacker, "0e1b4e0d165bed857e8a3232ee9865b7001e4e7945887e6f7d149c5807ccaf08",
            "attacker address drifted from the compiled fixture"
        );

        set_coin_store(&db, &attacker, 5_000_000);
        let start = coin_balance(&db, &attacker);

        let executor = Executor::new(db.clone());

        // 1) Publish the coin-value-argument forge module to the attacker's own address.
        let module_bytes = include_bytes!("../tests/fixtures/coin_value_arg_forge.mv").to_vec();
        let publish = vm_move::TransactionPayload::PublishModule(vec![module_bytes]);
        let publish_hex = hex::encode(bcs::to_bytes(&publish).unwrap());
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&attacker_key, &attacker, &publish_hex, 0, 1_000_000, 1))
            .expect("publish tx accepted");
        apply_updates(&db, updates);

        // 2) Call forge_coin(to = attacker, c = Coin { value: 1e15 }).
        //    `Coin` is `struct Coin<phantom CoinType> has store { value: u128 }`,
        //    so its BCS encoding is exactly the u128 -- the attacker simply names
        //    the amount they wish to conjure.
        const FORGED: u128 = 1_000_000_000_000_000;
        let call = EntryFunctionCall {
            module: move_core_types::language_storage::ModuleId::new(
                parse_move_address(&attacker).unwrap(),
                move_core_types::identifier::Identifier::new("coinforge").unwrap(),
            ),
            function: "forge_coin".to_string(),
            ty_args: vec![],
            args: vec![
                bcs::to_bytes(&parse_move_address(&attacker).unwrap()).unwrap(),
                bcs::to_bytes(&FORGED).unwrap(), // Coin { value: 1e15 }, from thin air
            ],
        };
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap(),
        );
        // Must be refused by the entry-argument allowlist. Included in a block
        // either way; the mint must not happen.
        if let Some((updates, _)) = executor
            .execute_transaction(&signed_tx(&attacker_key, &attacker, &payload, 1, 1_000_000, 1))
        {
            apply_updates(&db, updates);
        }

        let end = coin_balance(&db, &attacker);
        assert!(
            end <= start,
            "attacker minted {} AIN from a struct value parameter: {} -> {} (must never increase)",
            FORGED,
            start,
            end
        );
    }

    /// AUDIT H6 (CRITICAL). RED BY DESIGN — no state-derived commitment exists
    /// anywhere in AINCORE, so downloaded-state sync is unverifiable in principle.
    ///
    ///   cargo test -p executor --lib test_h6_ -- --ignored --nocapture
    ///
    /// `sys:state_root` is `H(prev_root || H(sorted effective writes))` — a hash
    /// CHAIN over write-sets. It commits to the execution HISTORY, not to state
    /// contents. Confirmed absent at HEAD: no IAVL, no Merkle-Patricia, no state
    /// trie of any kind in the workspace; `Accumulator` appends BLOCK HASHES.
    ///
    /// Deliberately TWO tests rather than two legs of one: a single test
    /// short-circuits at the first failure, so the second property would never
    /// actually run — and an assertion that never runs is precisely the failure
    /// this project has shipped before.
    ///
    /// WHAT A FIX MUST SATISFY, so neither is "fixed" alone: **the root must be a
    /// pure function of the state map.** Both tests then pass together and neither
    /// can pass without the other — the first says the function must see every
    /// write, the second says it must depend on nothing else. A per-block
    /// write-set hash satisfies neither.
    ///
    /// THIS TEST: the root is BLIND to state written outside block execution.
    /// Not hypothetical — the faucet RPC writes objects straight into RocksDB and
    /// nothing in any header disagrees. With a real commitment that write is
    /// detectable at the next block; today it is invisible forever.
    #[test]
    #[ignore = "H6 witness, superseded by C1'/C2' (G3 S3): WG-1 now refuses this test's own out-of-band setup write, so it fails at setup, not on the property; kept until the gate owner reviews the replacement witnesses"]
    fn test_h6_state_root_is_blind_to_out_of_band_writes() {
        use storage::object::{Object, Owner};

        let db = temp_db("h6_blind");
        load_stdlib(&db);
        db.set_federation_key("00000000000000000000000000000000").unwrap();
        let exec = Executor::new(db.clone());
        let proposer = "0000000000000000000000000000000000000000000000000000000000000001";
        match exec.execute_block_parallel_at(vec![], proposer, 1, block_time(1), &[]) {
            BlockExecOutcome::Executed(_) => {}
            other => panic!("height 1 must execute: {:?}", other),
        }
        let root_before = exec.current_state_root();

        let id = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef";
        let smuggled = Object::new(
            id.to_string(),
            Owner::Address("beef".to_string()),
            b"{\"balance\":1000000000}".to_vec(),
            "0x1::coin::CoinStore".to_string(),
        );
        db.put_object(&smuggled).unwrap();
        assert!(
            db.get(&format!("obj:{}", id)).unwrap().is_some(),
            "precondition: the object really is in state"
        );

        assert_ne!(
            exec.current_state_root(),
            root_before,
            "P_STATE_COMMITMENT VIOLATED: an object was written into state and the \
             root did not move. The root is H(prev_root || write-set), so it sees \
             only what block execution wrote — anything else is invisible to every \
             header, forever."
        );
    }

    /// AUDIT H6 (CRITICAL). RED BY DESIGN — no state-derived commitment exists
    /// anywhere in AINCORE, so downloaded-state sync is unverifiable in principle.
    ///
    ///   cargo test -p executor --lib test_h6_ -- --ignored --nocapture
    ///
    /// `sys:state_root` is `H(prev_root || H(sorted effective writes))` — a hash
    /// CHAIN over write-sets. It commits to the execution HISTORY, not to state
    /// contents. Confirmed absent at HEAD: no IAVL, no Merkle-Patricia, no state
    /// trie of any kind in the workspace; `Accumulator` appends BLOCK HASHES.
    ///
    /// Deliberately TWO tests rather than two legs of one: a single test
    /// short-circuits at the first failure, so the second property would never
    /// actually run — and an assertion that never runs is precisely the failure
    /// this project has shipped before.
    ///
    /// WHAT A FIX MUST SATISFY, so neither is "fixed" alone: **the root must be a
    /// pure function of the state map.** Both tests then pass together and neither
    /// can pass without the other — the first says the function must see every
    /// write, the second says it must depend on nothing else. A per-block
    /// write-set hash satisfies neither.
    ///
    /// THIS TEST: a node handed a CORRUPTED state snapshot cannot detect it. The
    /// root travels with the snapshot as a stored value rather than being computed
    /// from it, so a tampered copy and a good one are indistinguishable. This is
    /// the consequence of the blindness above, and it is what makes state sync
    /// unsafe no matter how careful the receiving node is.
    #[test]
    #[ignore = "H6 witness, superseded by C1'/C2' (G3 S3): WG-1 now refuses this test's own out-of-band setup write, so it fails at setup, not on the property; kept until the gate owner reviews the replacement witnesses"]
    fn test_h6_a_corrupted_state_snapshot_is_undetectable() {
        let db_a = temp_db("h6_corrupt_a");
        load_stdlib(&db_a);
        db_a.set_federation_key("00000000000000000000000000000000").unwrap();
        seed_genesis_tree(&db_a);
        let exec_a = Executor::new(db_a.clone());
        let proposer = "0000000000000000000000000000000000000000000000000000000000000001";
        match exec_a.execute_block_parallel_at(vec![], proposer, 1, block_time(1), &[]) {
            BlockExecOutcome::Executed(_) => {}
            other => panic!("height 1 must execute: {:?}", other),
        }

        // B receives a state snapshot from A — every row, root included, the way a
        // syncing node would take it. Then ONE row is corrupted in transit.
        let db_b = temp_db("h6_corrupt_b");
        let exec_b = Executor::new(db_b.clone());
        let rows = db_a.scan_prefix("");
        assert!(!rows.is_empty(), "precondition: A must hold data to hand over");
        let victim = rows
            .iter()
            .find(|(k, _)| k.starts_with("module_"))
            .map(|(k, _)| k.clone())
            .expect("precondition: A must hold at least one module row to corrupt");
        for (k, v) in &rows {
            if *k == victim {
                db_b.put(k, "TAMPERED").unwrap();
            } else {
                db_b.put(k, v).unwrap();
            }
        }
        assert_eq!(
            db_b.get(&victim).unwrap().as_deref(),
            Some("TAMPERED"),
            "precondition: the corruption must actually be in B's state"
        );
        assert_ne!(
            db_a.get(&victim).unwrap().as_deref(),
            Some("TAMPERED"),
            "precondition: A must be uncorrupted, or there is nothing to detect"
        );

        assert_ne!(
            exec_b.current_state_root(),
            exec_a.current_state_root(),
            "P_STATE_COMMITMENT VIOLATED: B's state is CORRUPTED — row `{}` was \
             replaced in transit — and B's root is bit-for-bit identical to A's, \
             because the root travelled WITH the snapshot as a stored value rather \
             than being computed FROM it. Nothing in the node can tell a good \
             snapshot from a tampered one.\n\
             This is distinct from the blindness test: that one shows the root does \
             not see state; this one shows the CONSEQUENCE — state sync cannot be \
             made safe by any amount of care at the receiving end, because there is \
             no quantity to check against. It is unverifiable in PRINCIPLE, not \
             merely unimplemented.",
            victim
        );
    }

    /// A CONTENT-DERIVED root satisfies BOTH H6 properties. GREEN — this is the
    /// target, demonstrated rather than asserted.
    ///
    /// The two H6 tests above say what is broken. This one says what "fixed" means,
    /// so the next attempt has something to aim at and so a partial fix cannot be
    /// mistaken for a whole one: the root must be a PURE FUNCTION OF THE STATE MAP.
    /// Nothing more exotic is required — the toy function below is a sorted hash
    /// over every row, and it already passes both properties that
    /// `H(prev_root || write-set)` fails.
    ///
    /// NOT a production proposal. Hashing the whole state per block is O(state) and
    /// would be ruinous at any real size; that is exactly why production systems use
    /// an incremental authenticated structure (IAVL, Merkle-Patricia) which
    /// recomputes only the path to each changed key. The point here is narrower and
    /// worth pinning: the PROPERTY is satisfiable, and it is satisfiable by anything
    /// that reads state instead of history. The engineering question is which
    /// structure, not whether.
    #[test]
    fn test_h6_a_content_derived_root_would_satisfy_both_properties() {
        use storage::object::{Object, Owner};

        /// Toy content root: sorted hash over every row. Reads STATE, never history.
        fn content_root(db: &std::sync::Arc<storage::StateDB>) -> String {
            use sha2::Digest;
            let mut rows = db.scan_prefix("");
            rows.sort();
            let mut h = sha2::Sha256::new();
            for (k, v) in &rows {
                h.update((k.len() as u64).to_be_bytes());
                h.update(k.as_bytes());
                h.update((v.len() as u64).to_be_bytes());
                h.update(v.as_bytes());
            }
            hex::encode(h.finalize())
        }

        let db_a = temp_db("h6_target_a");
        load_stdlib(&db_a);
        let _seed = db_a.seeding();
        db_a.set_federation_key("00000000000000000000000000000000").unwrap();
        seed_genesis_tree(&db_a);
        let exec_a = Executor::new(db_a.clone());
        let proposer = "0000000000000000000000000000000000000000000000000000000000000001";
        match exec_a.execute_block_parallel_at(vec![], proposer, 1, block_time(1), &[]) {
            BlockExecOutcome::Executed(_) => {}
            other => panic!("height 1 must execute: {:?}", other),
        }

        // PROPERTY 1 — sees an out-of-band write. `sys:state_root` does not.
        let before = content_root(&db_a);
        let id = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef";
        db_a.put_object(&Object::new(
            id.to_string(),
            Owner::Address("beef".to_string()),
            b"{\"balance\":1000000000}".to_vec(),
            "0x1::coin::CoinStore".to_string(),
        ))
        .unwrap();
        assert_ne!(
            content_root(&db_a),
            before,
            "a content-derived root must see every state write, including the ones \
             block execution did not make"
        );

        // PROPERTY 2 — a corrupted snapshot is detectable, and an honest one verifies.
        let db_b = temp_db("h6_target_b");
        let rows = db_a.scan_prefix("");
        let victim = rows
            .iter()
            .find(|(k, _)| k.starts_with("module_"))
            .map(|(k, _)| k.clone())
            .expect("a module row to corrupt");
        for (k, v) in &rows {
            let _seed = db_b.seeding();
            db_b.put(k, if *k == victim { "TAMPERED" } else { v }).unwrap();
        }
        assert_ne!(
            content_root(&db_b),
            content_root(&db_a),
            "a content-derived root must expose a tampered snapshot"
        );

        // The honest control. Without it, a root that simply returned a random
        // value would pass both assertions above and prove nothing at all.
        let db_c = temp_db("h6_target_c");
        for (k, v) in &rows {
            let _seed = db_c.seeding();
            db_c.put(k, v).unwrap();
        }
        assert_eq!(
            content_root(&db_c),
            content_root(&db_a),
            "CONTROL: an HONEST copy must verify. A root that failed here would \
             reject every legitimate snapshot — the opposite defect, and just as fatal."
        );
    }
}
