//! B65: what a transaction's writes cost. Derivation in
//! docs/research/fees_and_block_resources.md, section 4.
//!
//! Every write to a `State` key (what the state root commits to) pays I/O
//! gas, and every byte it adds to the state pays the state byte gas. The
//! byte gas moves with demand, as the base fee does (EIP-1559 applied to
//! state bytes, as EIP-4844 applies it to blob gas): it rises while blocks
//! add more than `TARGET_STATE_BYTES` and falls back to its floor while
//! they add less, so state grows at the target rate however much gas a
//! block can buy.
//!
//! B460: a change to a key also leaves the state tree's history: its old
//! value row and the stale nodes on its path, which the tree keeps
//! `state_commit::HISTORY_VERSIONS` blocks and the pruner removes at
//! `state_commit::PRUNE_ROWS_PER_BLOCK` rows a block. A rewrite added no
//! state, so it paid I/O gas alone (~180 for ~1.5 KB of rows), and neither
//! fee moved. Every changed key now pays for its history in plain gas,
//! which the base fee and the block ceiling count: a block at the gas
//! target leaves no more rows than the pruner removes, and holds no more
//! disk over the history window than a block of body bytes over its own.

use std::collections::BTreeMap;
use storage::class::{classify, KeyClass};
use storage::StateDB;

/// Gas per state write, from Aptos's `storage_io_per_state_slot_write`
/// (895,680 internal units) over its `add` (5,880): 152.
pub const IO_GAS_PER_WRITE: u64 = 152;
/// Bytes written per I/O gas, from Aptos's `storage_io_per_state_byte_write`
/// (890 internal units) over its `add`: 6.6, rounded down to 6.
pub const IO_BYTES_PER_GAS: u64 = 6;
/// State bytes a new key adds beyond its own key and value: the fixed part
/// of the rows the state tree keeps for it (its preimage and value rows, its
/// leaf and its share of the internal nodes), measured by
/// `state_commit`'s `measure_tree_bytes_per_key` (research note, section 4).
pub const NEW_KEY_BYTES: u64 = 492;
/// The floor of the state byte gas: Ethereum's EIP-8037 price of a state
/// byte, 1,530 gas, at 3 gas an `ADD`, is 510 `add`s; an `add` costs 1 gas
/// here.
pub const MIN_STATE_BYTE_GAS: u64 = 510;
/// The state bytes a block aims at: 10 GB of disk a year (four years of the
/// 40 GB the minimum disk keeps for state), over 4,654,000 blocks a year,
/// over 3 bytes of disk per charged byte at most (a value is stored again,
/// in hex, in the tree's value row). Research note, section 4.
pub const TARGET_STATE_BYTES: u64 = 716;
/// EIP-1559's change denominator: the byte gas moves at most 1/8 a block.
pub const STATE_BYTE_GAS_CHANGE_DENOMINATOR: u128 = 8;
/// The state byte gas the next block charges, in state; absent at the floor.
pub const STATE_BYTE_GAS_KEY: &str = "sys:state_byte_gas";

/// B460: gas per row of tree history (`state_commit::prune`'s unit): the
/// gas target over the rows the pruner removes per block (100M / 10,000),
/// so a block at the target leaves no more than the pruner removes. Above
/// the target the base fee rises 1/8 a block, which bounds the excess.
pub const GAS_PER_HISTORY_ROW: u64 = crate::TARGET_BLOCK_GAS / state_commit::PRUNE_ROWS_PER_BLOCK;
/// B460: the history of one changed key: `state_commit::HISTORY_ROWS_PER_KEY`
/// rows (7 x 10,000). Those rows hold at most 7 x 1,900 bytes for 1,100
/// blocks, ~209 disk byte-blocks a gas: under the 500 a gas of body bytes
/// buys (`admission::BYTE_GAS`, 400 a byte stored about twice for 100,000
/// blocks), so the pruner binds, not the disk.
pub const HISTORY_GAS_PER_KEY: u64 = state_commit::HISTORY_ROWS_PER_KEY * GAS_PER_HISTORY_ROW;
/// The blocks a full node keeps (`AINCORE_BLOCK_RETENTION`'s default), over
/// which `admission::BYTE_GAS` prices a body byte.
pub const BODY_BLOCKS_KEPT: u64 = 100_000;
/// B460: the longest the tree keeps a row of history: its window and one
/// pruning interval (1,100 blocks).
pub const HISTORY_BLOCKS_HELD: u64 = state_commit::HISTORY_VERSIONS + state_commit::PRUNE_EVERY;
/// B460: gas per byte of a changed key's previous value, whose value row
/// (the value in hex: two bytes a byte) the tree keeps `HISTORY_BLOCKS_HELD`
/// blocks, at the body's price of disk over time: a body byte (400 gas) is
/// about two disk bytes for 100,000 blocks, so the two factors of two
/// cancel: 400 x 1,100 / 100,000 = 4.4, rounded up.
pub const HISTORY_GAS_PER_OLD_BYTE: u64 =
    (crate::admission::BYTE_GAS * HISTORY_BLOCKS_HELD).div_ceil(BODY_BLOCKS_KEPT);

/// What a set of writes costs, before the byte price.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteCost {
    /// Gas for the writes themselves: their I/O and (B460) the tree history
    /// each changed key leaves.
    pub io_gas: u64,
    /// Bytes the writes add to the state: a new key's key, value and
    /// `NEW_KEY_BYTES`, an existing key's growth. A delete or a shrink adds
    /// nothing and refunds nothing (EIP-3529 removed refunds; GasToken
    /// stored state cheaply to sell back).
    pub new_bytes: u64,
}

impl WriteCost {
    /// The gas these writes cost at `byte_gas` a state byte.
    pub fn gas(&self, byte_gas: u64) -> u64 {
        self.io_gas
            .saturating_add(self.new_bytes.saturating_mul(byte_gas))
    }
}

/// The cost of `updates` over the state `db` holds before them. Only
/// `State` keys count (receipts and indexes are history, paid by the byte
/// gas of the body); a key written twice counts once, at its last value,
/// as the block commits it.
pub fn write_cost(db: &StateDB, updates: &[(String, Option<String>)]) -> WriteCost {
    let mut last: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for (key, value) in updates {
        last.insert(key.as_str(), value.as_deref());
    }
    let mut cost = WriteCost::default();
    for (key, value) in last {
        if classify(key.as_bytes()) != Some(KeyClass::State) {
            continue;
        }
        let written = (key.len() + value.map_or(0, str::len)) as u64;
        cost.io_gas = cost
            .io_gas
            .saturating_add(IO_GAS_PER_WRITE)
            .saturating_add(written.div_ceil(IO_BYTES_PER_GAS));
        let old = db
            .get(key)
            .expect("CRITICAL: a state read for the write charge failed");
        // B460: the tree versions a change (a new key, a rewrite, a delete);
        // the same bytes, or a delete of an absent key, leave nothing.
        if old.as_deref() != value {
            cost.io_gas = cost.io_gas.saturating_add(history_gas(old.as_deref()));
        }
        let Some(value) = value else { continue };
        let added = match old {
            None => (key.len() + value.len()) as u64 + NEW_KEY_BYTES,
            Some(old) => value.len().saturating_sub(old.len()) as u64,
        };
        cost.new_bytes = cost.new_bytes.saturating_add(added);
    }
    cost
}

/// B460: the tree history a change to a key holding `old` leaves: its rows,
/// and its old value's bytes.
pub fn history_gas(old: Option<&str>) -> u64 {
    let old_bytes = old.map_or(0, str::len) as u64;
    HISTORY_GAS_PER_KEY.saturating_add(old_bytes.saturating_mul(HISTORY_GAS_PER_OLD_BYTE))
}

/// The state byte gas this block charges.
pub fn committed_state_byte_gas(db: &StateDB) -> u64 {
    db.get(STATE_BYTE_GAS_KEY)
        .ok()
        .flatten()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(MIN_STATE_BYTE_GAS)
        .max(MIN_STATE_BYTE_GAS)
}

/// EIP-1559's update over state bytes: a block that added more than the
/// target raises the byte gas by `gas * min(added - target, target) / target
/// / 8` (at least 1), one that added less lowers it by
/// `gas * (target - added) / target / 8`; never below the floor. A block may
/// add many times the target (one module is several targets), so the rise
/// is capped at 1/8, as the base fee's is at a full block.
pub fn next_state_byte_gas(byte_gas: u64, added: u64) -> u64 {
    let target = TARGET_STATE_BYTES as u128;
    let gas = byte_gas as u128;
    let added = added as u128;
    let next = if added > target {
        let delta = gas.saturating_mul((added - target).min(target))
            / target
            / STATE_BYTE_GAS_CHANGE_DENOMINATOR;
        gas.saturating_add(delta.max(1))
    } else {
        gas.saturating_sub(
            gas.saturating_mul(target - added) / target / STATE_BYTE_GAS_CHANGE_DENOMINATOR,
        )
    };
    u64::try_from(next)
        .unwrap_or(u64::MAX)
        .max(MIN_STATE_BYTE_GAS)
}

/// What `Executor::estimate_gas` reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GasEstimate {
    /// Gas Move execution used, with the object loads (N-2).
    pub vm_gas: u64,
    /// The writes' cost.
    pub writes: WriteCost,
    /// The state byte gas the writes were priced at.
    pub state_byte_gas: u64,
    /// The least execution gas the payload may carry (a module bundle's
    /// publish floor, B27; 0 otherwise).
    pub floor: u64,
    /// Why the transaction would abort, if it would.
    pub aborted: Option<String>,
}

impl GasEstimate {
    /// The execution gas the transaction needs: Move execution (with its
    /// object loads) and its writes, and at least the floor (the intrinsic
    /// byte gas is on top).
    pub fn execution_gas(&self) -> u64 {
        self.execution_gas_at(self.state_byte_gas)
    }

    /// `execution_gas` with the new bytes priced at `byte_gas`.
    pub fn execution_gas_at(&self, byte_gas: u64) -> u64 {
        self.vm_gas
            .saturating_add(self.writes.gas(byte_gas))
            .max(self.floor)
    }
}
