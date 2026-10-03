//! Multi-validator genesis.json generator (#15 bring-up tooling).
//!
//! A multi-validator genesis CANNOT self-derive BLS keys: each validator's BLS
//! finality key is derived from ITS OWN node.key seed, which only the genesis
//! ceremony operator can collect. If genesis.json omitted the per-validator BLS
//! keys, every booting node would self-derive a DIFFERENT key for the same peer
//! address, write a divergent `sys:validator_set:v1`, and no QC would ever
//! verify against another node (see `node::genesis::resolve_genesis_bls_identity`,
//! SEC-#5). This tool closes that gap: given each validator's 32-byte node-key
//! seed + stake, it emits a genesis.json with the EXACT fields the loader
//! expects, including the embedded `bls_public_key` + `bls_pop`.
//!
//! Derivation chain (must stay byte-identical to a running node):
//!   seed (node.key, 32 bytes)
//!     -> ed25519 SigningKey::from_bytes(seed) -> verifying_key  (public_key)
//!     -> crypto::derive_address(public_key)                     (address)
//!     -> consensus::qc::derive_validator_bls_seed(seed)         (bls seed)
//!         -> BLSEngine::consensus().pubkey_raw(bls_seed)        (bls_public_key)
//!         -> BLSEngine::consensus().prove_possession_raw(...)   (bls_pop)
//!
//! The node treats `node.key` (`signing_key.to_bytes()`) as the genesis node
//! identity, and `SigningKey::to_bytes()` returns exactly the 32-byte seed it was
//! constructed from — so the seed passed here IS the node identity, and the
//! fields generated here match what each node derives from its own node.key.

use clap::Args;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One validator's public genesis entry: what its operator sends the genesis
/// coordinator, from `genesis-tool validator-entry` on its own machine. No
/// secret leaves the validator. `entry_sig` is the node key's ed25519
/// signature over `entry_message`, binding the BLS key to the address and
/// proving the operator holds the node key; `bls_pop` proves it holds the BLS
/// key.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PublicEntry {
    pub address: String,
    pub public_key: String,
    pub bls_public_key: String,
    pub bls_pop: String,
    pub entry_sig: String,
}

/// A line of `--entries-file`: an entry, the stake the coordinator assigns
/// it, and its bootstrap weight (G5 A4 BW-2), both in whole AIN. An operator
/// with bootstrap weight may own no stake.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EntrySpec {
    #[serde(flatten)]
    pub entry: PublicEntry,
    pub stake_ain: u128,
    #[serde(default)]
    pub bootstrap_ain: u64,
    /// G5 A4 BW-11: the party this validator belongs to (the founder's
    /// validators share one); its own otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
}

/// A line of `--accounts-file` (G5 A4 BW-2): liquid AIN at genesis for the
/// incentivized testnet's public track, in whole AIN.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountSpec {
    pub address: String,
    pub balance_ain: u128,
}

/// What `entry_sig` signs.
fn entry_message(address: &str, bls_public_key: &str) -> Vec<u8> {
    format!("AINCORE-GENESIS-ENTRY-V1:{address}:{bls_public_key}").into_bytes()
}

/// The entry for the validator whose node.key seed is `seed`.
pub fn entry_from_seed(seed: &[u8; 32]) -> Result<PublicEntry, Box<dyn std::error::Error>> {
    let (address, public_key, bls_public_key, bls_pop) = derive_validator_fields(seed)?;
    let sig = SigningKey::from_bytes(seed).sign(&entry_message(&address, &bls_public_key));
    Ok(PublicEntry {
        address,
        public_key,
        bls_public_key,
        bls_pop,
        entry_sig: hex::encode(sig.to_bytes()),
    })
}

/// Every check an entry must pass before it goes into a genesis file: the
/// address derives from the key, the node key signed the entry, and the BLS
/// key's proof of possession verifies. (The loader checks the committee
/// again at boot.)
pub fn check_entry(e: &PublicEntry) -> Result<(), String> {
    let pk: [u8; 32] = hex::decode(&e.public_key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{}: public_key is not 32 bytes of hex", e.address))?;
    let derived = crypto::derive_address(&pk).map_err(|err| err.to_string())?;
    if derived != e.address {
        return Err(format!(
            "{}: the address does not derive from public_key",
            e.address
        ));
    }
    let key = ed25519_dalek::VerifyingKey::from_bytes(&pk)
        .map_err(|err| format!("{}: public_key: {err}", e.address))?;
    let sig: [u8; 64] = hex::decode(&e.entry_sig)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| format!("{}: entry_sig is not 64 bytes of hex", e.address))?;
    key.verify(
        &entry_message(&e.address, &e.bls_public_key),
        &ed25519_dalek::Signature::from_bytes(&sig),
    )
    .map_err(|_| format!("{}: entry_sig does not verify under public_key", e.address))?;
    let bls_pk = hex::decode(&e.bls_public_key)
        .map_err(|_| format!("{}: bls_public_key is not hex", e.address))?;
    let pop = hex::decode(&e.bls_pop).map_err(|_| format!("{}: bls_pop is not hex", e.address))?;
    match crypto::bls::BLSEngine::consensus().verify_possession(&bls_pk, &pop) {
        Ok(true) => Ok(()),
        _ => Err(format!("{}: bls_pop does not verify", e.address)),
    }
}

/// A single validator spec on the CLI: `--validator <seed_hex>:<stake_ain>`.
/// `seed_hex` is the 32-byte (64 hex char) node.key seed; `stake_ain` is the
/// whole-AIN stake (converted to 10^18 quanta in the emitted file).
#[derive(Clone, Debug)]
pub struct ValidatorSpec {
    pub seed: [u8; 32],
    pub stake_ain: u128,
}

#[derive(Args, Debug)]
pub struct GenMultiArgs {
    /// One per validator: `<node_key_seed_hex>:<stake_whole_ain>`.
    /// `node_key_seed_hex` = 32-byte hex (64 chars) = the validator's node.key.
    /// Repeat the flag for each validator (order does not matter — the set hash
    /// is address-sorted and order-independent).
    ///
    /// SECURITY: prefer `--seeds-file` — seeds passed on the command line leak
    /// into shell history, `ps` output, and terminal transcripts.
    #[arg(long = "validator", value_name = "SEED_HEX:STAKE_AIN")]
    pub validators: Vec<String>,

    /// Read validator specs from a file instead of the command line: one
    /// `<node_key_seed_hex>:<stake_whole_ain>` per line (blank lines and
    /// `#` comments ignored). This keeps the secret seeds out of shell
    /// history, `ps`, and terminal logs. May be combined with `--validator`.
    #[arg(long = "seeds-file", value_name = "PATH")]
    pub seeds_file: Option<PathBuf>,

    /// Public entries instead of seeds: a JSON array of
    /// `{address, public_key, bls_public_key, bls_pop, entry_sig, stake_ain}`,
    /// one per validator, each made by its operator with `validator-entry`.
    /// This is the path for independent operators: no seed leaves its
    /// machine. May be combined with the seed flags.
    #[arg(long = "entries-file", value_name = "PATH")]
    pub entries_file: Option<PathBuf>,

    /// G5 A4 BW-2: s_min, the genesis committee's weight in whole AIN, which
    /// the entries' `bootstrap_ain` fill up to.
    #[arg(long)]
    pub s_min_ain: Option<u64>,

    /// G5 A4 BW-2: liquid genesis balances, a JSON array of
    /// `{address, balance_ain}` (the incentivized testnet's public track).
    #[arg(long = "accounts-file", value_name = "PATH")]
    pub accounts_file: Option<PathBuf>,

    /// G5 A4-S6: `score-testnet`'s allocations, a JSON array of
    /// `{address, stake_ain, bootstrap_ain}`: each sets the stake and the
    /// bootstrap weight of the entry with that address.
    #[arg(long = "allocations-file", value_name = "PATH")]
    pub allocations_file: Option<PathBuf>,

    /// Output path for the generated genesis.json.
    #[arg(short, long, default_value = "genesis.json")]
    pub out: PathBuf,

    /// Chain ID embedded in genesis.json.
    #[arg(long, default_value = "AINCORE-MAINNET-1")]
    pub chain_id: String,

    /// The block time measured on the release candidate, in milliseconds
    /// (G5 P-1). The consensus-time cap per block is derived from it. It is
    /// required, with no default: a guessed block time is how the emission
    /// and deadlines drifted before.
    #[arg(long)]
    pub block_time_ms: u64,

    /// C_tau, the consensus-time cap per block, measured on the same run
    /// (`genesis-tool clock-cap`): it must lie in [2 t_b, 4 t_b]. Required,
    /// with no default, for the same reason as the block time.
    #[arg(long)]
    pub clock_cap_secs: u64,

    /// The stdlib bytecode the chain starts from; its hash is pinned into
    /// genesis.json (G3 FX-7).
    #[arg(long, default_value = "core/vm_move/stdlib/bytecode")]
    pub stdlib_path: String,

    /// Overwrite the output file if it already exists.
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Launch time, unix seconds (G1 S11): validators take their first guard
    /// origin only within an hour of it. Default: now.
    #[arg(long)]
    pub genesis_time: Option<u64>,
}

/// 10^18 quanta per whole AIN. Mirrors `node::genesis` COIN_SCALE.
const COIN_SCALE: u128 = 1_000_000_000_000_000_000;
/// The Move `MIN_STAKE` and the genesis loader's minimum, in whole AIN.
const MIN_STAKE_AIN: u128 = 1_000;

/// Per-validator genesis entry. Field names + types match
/// `node::genesis::GenesisValidatorConfig` EXACTLY (the loader's
/// `#[derive(Deserialize)]` shape): `address`, `public_key`, `stake` (String),
/// `bls_public_key`, `bls_pop` (hex strings).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GenesisValidatorConfig {
    pub address: String,
    pub public_key: String,
    pub stake: String,
    pub bls_public_key: String,
    pub bls_pop: String,
}

/// Top-level genesis file. Field names + types match
/// `node::genesis::GenesisFile`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct GenesisFile {
    pub chain_id: String,
    pub validators: Vec<GenesisValidatorConfig>,
    /// G5 P-1: derived from the measured block time (`derive_chain_params`):
    /// the committee epoch I and the reward period R in blocks, and C_tau,
    /// the consensus-time cap per block.
    pub epoch_block_interval: u64,
    pub reward_period_blocks: u64,
    pub max_block_interval_secs: u64,
    /// G3 FX-7: the stdlib this chain starts from, by
    /// `node::genesis::stdlib_hash_of`. A node whose stdlib differs refuses
    /// the genesis.
    pub stdlib_hash: String,
    /// G1 S11: the launch time, unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_time: Option<u64>,
    /// G5 A4 BW-2: bootstrap weight (consensus weight with no coins).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<node::genesis::GenesisBootstrap>,
    /// G5 A4 BW-2: liquid genesis balances.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<node::genesis::GenesisAccount>,
    /// B15: the base fee's floor, quanta per gas (`derive_min_base_fee`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_base_fee: Option<String>,
}

/// staking.move's emission rate: per second, `remaining x RATE / 10^18`.
/// A test reads it back from the Move source, so the two cannot drift.
pub const EMISSION_RATE_E18_PER_SEC: u128 = 607_866_866;

/// B15: the base fee's floor. A full block (`MAX_BLOCK_GAS_LIMIT` gas) at
/// the floor costs one block of emission, so filling blocks is never cheaper
/// than what the chain pays to produce them (docs/research/
/// fees_and_block_resources.md). Emission over one `block_time_ms` block is
/// `remaining x RATE x t / 10^18`, computed in staking.move's order.
pub fn derive_min_base_fee(remaining_quanta: u128, block_time_ms: u64) -> u128 {
    let per_block = (remaining_quanta / 1_000_000_000)
        .saturating_mul(EMISSION_RATE_E18_PER_SEC)
        .saturating_mul(block_time_ms as u128)
        / 1_000
        / 1_000_000_000;
    (per_block / executor::MAX_BLOCK_GAS_LIMIT as u128).max(1)
}

/// Derive every genesis field for one validator from its 32-byte node.key seed.
/// Returns `(address, ed25519_pubkey_hex, bls_public_key_hex, bls_pop_hex)`.
///
/// This is the single source of truth the tool uses; it deliberately routes
/// through the same public APIs a node uses so the values can never drift.
pub fn derive_validator_fields(
    seed: &[u8; 32],
) -> Result<(String, String, String, String), Box<dyn std::error::Error>> {
    // 1. ed25519 identity from the seed (same as node.key -> SigningKey).
    let signing_key = SigningKey::from_bytes(seed);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let public_key_hex = hex::encode(public_key_bytes);

    // 2. address = crypto::derive_address(ed25519 pubkey) (#35: full 32-byte).
    let address = crypto::derive_address(&public_key_bytes)
        .map_err(|e| format!("derive_address failed: {}", e))?;

    // 3. BLS finality identity from the SAME seed, via the canonical consensus
    //    derivation (re-exported from consensus::qc). The node uses
    //    signing_key.to_bytes() (== seed) as the node identity, so this matches.
    let bls_seed = consensus::qc::derive_validator_bls_seed(seed);
    let bls = crypto::bls::BLSEngine::consensus();
    let bls_public_key_hex = hex::encode(bls.pubkey_raw(&bls_seed));
    let bls_pop_hex = hex::encode(bls.prove_possession_raw(&bls_seed));

    Ok((address, public_key_hex, bls_public_key_hex, bls_pop_hex))
}

/// Parse a `--validator SEED_HEX:STAKE_AIN` argument.
pub fn parse_validator_spec(raw: &str) -> Result<ValidatorSpec, Box<dyn std::error::Error>> {
    let (seed_hex, stake_str) = raw.rsplit_once(':').ok_or_else(|| {
        format!(
            "invalid --validator '{}': expected <node_key_seed_hex>:<stake_whole_ain>",
            raw
        )
    })?;
    let seed_bytes = hex::decode(seed_hex.trim())
        .map_err(|e| format!("invalid seed hex in '{}': {}", raw, e))?;
    if seed_bytes.len() != 32 {
        return Err(format!(
            "node-key seed must be exactly 32 bytes (64 hex chars), got {} bytes in '{}'",
            seed_bytes.len(),
            raw
        )
        .into());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let stake_ain: u128 = stake_str
        .trim()
        .parse::<u128>()
        .map_err(|e| format!("invalid stake '{}' in '{}': {}", stake_str, raw, e))?;
    if stake_ain == 0 {
        return Err(format!("validator stake must be > 0 (in '{}')", raw).into());
    }

    Ok(ValidatorSpec { seed, stake_ain })
}

/// Build the in-memory `GenesisFile` from parsed validator specs + parameters.
#[cfg(test)]
pub fn build_genesis_file(
    specs: &[ValidatorSpec],
    chain_id: &str,
    block_time_ms: u64,
    clock_cap_secs: u64,
    stdlib_hash: &str,
) -> Result<GenesisFile, Box<dyn std::error::Error>> {
    let mut entries = Vec::with_capacity(specs.len());
    for spec in specs {
        entries.push(EntrySpec {
            entry: entry_from_seed(&spec.seed)?,
            stake_ain: spec.stake_ain,
            bootstrap_ain: 0,
            entity: None,
        });
    }
    build_genesis_from_entries(
        &entries,
        chain_id,
        block_time_ms,
        clock_cap_secs,
        stdlib_hash,
    )
}

/// The genesis file from public entries, each checked by `check_entry`.
pub fn build_genesis_from_entries(
    specs: &[EntrySpec],
    chain_id: &str,
    block_time_ms: u64,
    clock_cap_secs: u64,
    stdlib_hash: &str,
) -> Result<GenesisFile, Box<dyn std::error::Error>> {
    if specs.is_empty() {
        return Err("at least one validator is required".into());
    }
    if chain_id.trim().is_empty() {
        return Err("chain_id must not be empty".into());
    }
    let params = node::genesis::derive_chain_params(block_time_ms, clock_cap_secs)
        .map_err(|e| format!("cannot derive the chain parameters: {e}"))?;
    if stdlib_hash.trim().is_empty() {
        return Err("stdlib_hash must not be empty".into());
    }

    let mut validators = Vec::with_capacity(specs.len());
    let mut seen_addr = std::collections::BTreeSet::new();
    let mut seen_bls = std::collections::BTreeSet::new();
    for spec in specs {
        check_entry(&spec.entry)?;
        // The node's rule: at least 1,000 AIN, or none with bootstrap weight.
        if spec.stake_ain < MIN_STAKE_AIN && !(spec.stake_ain == 0 && spec.bootstrap_ain > 0) {
            return Err(format!(
                "{}: stake {} AIN is below the minimum {MIN_STAKE_AIN} AIN (0 is allowed only \
                 with bootstrap weight)",
                spec.entry.address, spec.stake_ain
            )
            .into());
        }
        let PublicEntry {
            address,
            public_key,
            bls_public_key,
            bls_pop,
            ..
        } = spec.entry.clone();
        if !seen_addr.insert(address.clone()) {
            return Err(format!(
                "duplicate validator address {} — the same node key was supplied twice",
                address
            )
            .into());
        }
        if !seen_bls.insert(bls_public_key.clone()) {
            return Err(format!("{address}: its BLS key is another validator's").into());
        }
        let stake_quanta = spec
            .stake_ain
            .checked_mul(COIN_SCALE)
            .ok_or_else(|| format!("stake {} AIN overflows u128 quanta", spec.stake_ain))?;
        validators.push(GenesisValidatorConfig {
            address,
            public_key,
            stake: stake_quanta.to_string(),
            bls_public_key,
            bls_pop,
        });
    }

    Ok(GenesisFile {
        chain_id: chain_id.to_string(),
        validators,
        epoch_block_interval: params.epoch_blocks,
        reward_period_blocks: params.reward_period,
        max_block_interval_secs: params.max_block_interval_secs,
        stdlib_hash: stdlib_hash.to_string(),
        genesis_time: None,
        bootstrap: None,
        accounts: Vec::new(),
        min_base_fee: None,
    })
}

/// G5 A4 BW-2: add bootstrap weight and liquid accounts to `genesis`,
/// checked as the loader checks them: the committee weighs exactly `s_min`
/// with bootstrap weight, and no member weighs a third of it or more.
pub fn apply_bootstrap_and_accounts(
    genesis: &mut GenesisFile,
    specs: &[EntrySpec],
    s_min_ain: Option<u64>,
    accounts: &[AccountSpec],
) -> Result<(), Box<dyn std::error::Error>> {
    let weights: Vec<node::genesis::GenesisBootstrapWeight> = specs
        .iter()
        .filter(|s| s.bootstrap_ain > 0)
        .map(|s| node::genesis::GenesisBootstrapWeight {
            address: s.entry.address.clone(),
            weight_ain: s.bootstrap_ain,
            entity: s.entity.clone(),
        })
        .collect();
    match (s_min_ain, weights.is_empty()) {
        (None, true) => {}
        (None, false) => return Err("bootstrap weights need --s-min-ain".into()),
        (Some(_), true) => return Err("--s-min-ain needs entries with bootstrap_ain".into()),
        (Some(s_min), false) => {
            let totals: Vec<(String, u128)> = specs
                .iter()
                .map(|s| {
                    (
                        s.entry.address.clone(),
                        s.stake_ain + s.bootstrap_ain as u128,
                    )
                })
                .collect();
            let sum: u128 = totals.iter().map(|(_, t)| *t).sum();
            if sum != s_min as u128 {
                return Err(format!(
                    "stake plus bootstrap weight sums to {sum} AIN, not s_min {s_min}"
                )
                .into());
            }
            // BW-11 by party, as the node checks it.
            let mut parties: std::collections::BTreeMap<String, u128> = Default::default();
            for (spec, (_, t)) in specs.iter().zip(&totals) {
                let party = spec
                    .entity
                    .clone()
                    .unwrap_or_else(|| spec.entry.address.clone());
                *parties.entry(party).or_default() += t;
            }
            if let Some((a, t)) = parties.iter().find(|(_, t)| 3 * **t >= sum) {
                return Err(format!("{a} weighs {t} of {sum} AIN: a third or more").into());
            }
            genesis.bootstrap = Some(node::genesis::GenesisBootstrap {
                s_min_ain: s_min,
                weights,
            });
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for a in accounts {
        let canonical = a.address.to_ascii_lowercase();
        if canonical.len() != 64 || hex::decode(&canonical).is_err() {
            return Err(format!("account {} is not a 64-hex address", a.address).into());
        }
        if !seen.insert(canonical.clone()) {
            return Err(format!("account {} is listed twice", a.address).into());
        }
        if specs
            .iter()
            .any(|s| s.entry.address.to_ascii_lowercase() == canonical)
        {
            return Err(format!("{} is a validator and an account", a.address).into());
        }
        let quanta = a
            .balance_ain
            .checked_mul(COIN_SCALE)
            .ok_or_else(|| format!("balance {} AIN overflows u128 quanta", a.balance_ain))?;
        genesis.accounts.push(node::genesis::GenesisAccount {
            address: a.address.clone(),
            balance: quanta.to_string(),
        });
    }
    Ok(())
}

/// G5 A4-S6: set each allocated entry's stake and bootstrap weight from
/// `score-testnet`. An allocation must name an entry: a qualified operator
/// joins mainnet genesis with the key it qualified with.
pub fn apply_allocations(
    entries: &mut [EntrySpec],
    allocations: &[crate::score::Allocation],
) -> Result<(), String> {
    for a in allocations {
        let entry = entries
            .iter_mut()
            .find(|e| e.entry.address.eq_ignore_ascii_case(&a.address))
            .ok_or_else(|| format!("allocation {} has no validator entry", a.address))?;
        entry.stake_ain = a.stake_ain as u128;
        entry.bootstrap_ain = a.bootstrap_ain;
    }
    Ok(())
}

/// `clock-cap`: the release candidate's block intervals, one whole number of
/// seconds per line (consecutive heights, from its block timestamps).
#[derive(Args, Debug)]
pub struct ClockCapArgs {
    #[arg(long)]
    pub intervals: PathBuf,
}

/// Print the measured mean block time and C_tau (G5 P-1, S6), the two
/// inputs `gen-multi` takes.
pub fn run_clock_cap(args: ClockCapArgs) -> Result<(), Box<dyn std::error::Error>> {
    let raw = std::fs::read_to_string(&args.intervals)
        .map_err(|e| format!("cannot read {}: {e}", args.intervals.display()))?;
    let mut intervals = Vec::new();
    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        intervals.push(
            line.parse::<u64>()
                .map_err(|e| format!("bad interval {line:?}: {e}"))?,
        );
    }
    if intervals.len() < 1_000 {
        return Err(format!(
            "{} intervals: measure at least 1,000 blocks, an epoch's worth",
            intervals.len()
        )
        .into());
    }
    let total: u64 = intervals.iter().sum();
    let block_time_ms = (total * 1_000).div_ceil(intervals.len() as u64);
    let cap = node::genesis::clock_cap_from_intervals(&intervals).ok_or("no time measured")?;
    let lost = |c: u64| -> f64 {
        intervals.iter().map(|&x| x.saturating_sub(c)).sum::<u64>() as f64 * 100.0 / total as f64
    };
    println!("intervals: {}  mean: {block_time_ms} ms", intervals.len());
    println!(
        "C_tau: {cap} s (loses {:.2} % of consensus time; 2 x t_b would lose {:.2} %)",
        lost(cap),
        lost((2 * block_time_ms).div_ceil(1_000))
    );
    println!("gen-multi --block-time-ms {block_time_ms} --clock-cap-secs {cap}");
    Ok(())
}

/// `validator-entry`: run by each operator on its own validator.
#[derive(Args, Debug)]
pub struct EntryArgs {
    /// The validator's node.key, as the node reads it: 32 raw bytes or 64
    /// hex characters.
    #[arg(long)]
    pub key: PathBuf,
}

/// The node.key seed, in either of the forms the node accepts.
pub fn parse_node_key(bytes: &[u8]) -> Result<[u8; 32], String> {
    if let Ok(seed) = <[u8; 32]>::try_from(bytes) {
        return Ok(seed);
    }
    std::str::from_utf8(bytes)
        .ok()
        .map(str::trim)
        .filter(|t| t.len() == 64)
        .and_then(|t| hex::decode(t).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "a node key is 32 raw bytes or 64 hex characters".to_string())
}

/// Print this validator's public entry. Nothing secret is printed.
pub fn run_entry(args: EntryArgs) -> Result<(), Box<dyn std::error::Error>> {
    let bytes =
        std::fs::read(&args.key).map_err(|e| format!("cannot read {}: {e}", args.key.display()))?;
    let entry = entry_from_seed(&parse_node_key(&bytes)?)?;
    println!("{}", serde_json::to_string_pretty(&entry)?);
    Ok(())
}

pub fn run(args: GenMultiArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("🛠️  AINCORE Multi-Validator Genesis Generator");

    let mut raw_specs: Vec<String> = args.validators.clone();
    if let Some(path) = &args.seeds_file {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read --seeds-file {}: {e}", path.display()))?;
        for line in contents.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                raw_specs.push(line.to_string());
            }
        }
    }
    if raw_specs.is_empty() && args.entries_file.is_none() {
        return Err("no validators given: pass --entries-file, --validator or --seeds-file".into());
    }
    let mut entries = Vec::with_capacity(raw_specs.len());
    for raw in &raw_specs {
        let spec = parse_validator_spec(raw)?;
        entries.push(EntrySpec {
            entry: entry_from_seed(&spec.seed)?,
            stake_ain: spec.stake_ain,
            bootstrap_ain: 0,
            entity: None,
        });
    }
    if let Some(path) = &args.entries_file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read --entries-file {}: {e}", path.display()))?;
        let listed: Vec<EntrySpec> = serde_json::from_str(&raw)
            .map_err(|e| format!("--entries-file {}: {e}", path.display()))?;
        entries.extend(listed);
    }

    if let Some(path) = &args.allocations_file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read --allocations-file {}: {e}", path.display()))?;
        let allocations: Vec<crate::score::Allocation> = serde_json::from_str(&raw)
            .map_err(|e| format!("--allocations-file {}: {e}", path.display()))?;
        apply_allocations(&mut entries, &allocations)?;
    }

    let stdlib_hash = node::genesis::stdlib_hash_of(&args.stdlib_path)
        .map_err(|e| format!("cannot hash the stdlib at {}: {e}", args.stdlib_path))?;
    let mut genesis = build_genesis_from_entries(
        &entries,
        &args.chain_id,
        args.block_time_ms,
        args.clock_cap_secs,
        &stdlib_hash,
    )?;
    let accounts: Vec<AccountSpec> = match &args.accounts_file {
        None => Vec::new(),
        Some(path) => {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read --accounts-file {}: {e}", path.display()))?;
            serde_json::from_str(&raw)
                .map_err(|e| format!("--accounts-file {}: {e}", path.display()))?
        }
    };
    apply_bootstrap_and_accounts(&mut genesis, &entries, args.s_min_ain, &accounts)?;
    // B15: the floor from the reserve left after genesis allocates.
    let allocated: u128 = genesis
        .validators
        .iter()
        .map(|v| v.stake.parse::<u128>().unwrap_or(0))
        .chain(
            genesis
                .accounts
                .iter()
                .map(|a| a.balance.parse::<u128>().unwrap_or(0)),
        )
        .sum();
    let remaining = executor::MAX_SUPPLY.saturating_sub(allocated);
    let floor = derive_min_base_fee(remaining, args.block_time_ms);
    genesis.min_base_fee = Some(floor.to_string());
    println!(
        "⛽ Base fee floor: {floor} quanta per gas (a full block at it costs one block of emission)"
    );
    if let Some(boot) = &genesis.bootstrap {
        let b: u64 = boot.weights.iter().map(|w| w.weight_ain).sum();
        println!(
            "🌱 Bootstrap weight (no coins): {b} AIN over {} operators, s_min {} AIN",
            boot.weights.len(),
            boot.s_min_ain
        );
    }
    if !genesis.accounts.is_empty() {
        println!("👥 Genesis accounts: {}", genesis.accounts.len());
    }
    genesis.genesis_time = Some(args.genesis_time.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }));
    println!(
        "🕒 Genesis time: {:?} (the guard-origin launch window starts here)",
        genesis.genesis_time
    );

    if args.out.exists() && !args.force {
        return Err(format!(
            "refusing to overwrite existing {} (pass --force to overwrite)",
            args.out.display()
        )
        .into());
    }

    // The node's own rules, on the file as written: what it would refuse to
    // boot is never written.
    let json = serde_json::to_string_pretty(&genesis)?;
    let identity = node::genesis::check_genesis_json(&json, &args.stdlib_path)
        .map_err(|e| format!("the node refuses this genesis: {e}"))?;
    std::fs::write(&args.out, &json)?;
    println!("🔏 Genesis identity: {identity}");

    println!("⛓️  Chain ID: {}", genesis.chain_id);
    println!("🛡️  Validators: {}", genesis.validators.len());
    for v in &genesis.validators {
        println!(
            "   • {} (stake={} quanta, bls_pk={}…)",
            v.address,
            v.stake,
            &v.bls_public_key[..16.min(v.bls_public_key.len())]
        );
    }
    println!(
        "⏳ From {} ms blocks: reward period {} blocks, consensus-time cap {} s per block",
        args.block_time_ms, genesis.reward_period_blocks, genesis.max_block_interval_secs
    );
    println!("📚 Stdlib hash: {}", genesis.stdlib_hash);
    println!("✅ Wrote {}", args.out.display());
    println!(
        "ℹ️  Each validator must run with its node.key set to the SAME 32-byte seed \
         used here, and all nodes must use this identical genesis.json."
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B15: the Rust copy of the emission rate is staking.move's.
    #[test]
    fn the_emission_rate_is_staking_moves() {
        let source = include_str!("../../vm_move/stdlib/sources/staking.move");
        assert!(source.contains(&format!(
            "const EMISSION_RATE_E18_PER_SEC: u128 = {EMISSION_RATE_E18_PER_SEC};"
        )));
    }

    /// B15: with the V5 testnet's 18.5M AIN allocated and 6.78 s blocks, a
    /// full block at the floor costs one block of emission: 0.54196 AIN,
    /// as the continuous rate -ln(1 - 0.019) per year gives it.
    #[test]
    fn a_full_block_at_the_floor_costs_one_block_of_emission() {
        let remaining = executor::MAX_SUPPLY - 18_500_000 * COIN_SCALE;
        let floor = derive_min_base_fee(remaining, 6_780);
        assert_eq!(floor, 2_709_779_308);
        let block = floor * executor::MAX_BLOCK_GAS_LIMIT as u128;
        let emission = remaining as f64 * -(1.0f64 - 0.019).ln() * 6.78 / 31_557_600.0;
        assert!(
            (block as f64 / emission - 1.0).abs() < 1e-6,
            "{block} vs {emission}"
        );
        assert_eq!(derive_min_base_fee(0, 6_780), 1, "never below 1");
    }
    use std::sync::Arc;
    use storage::StateDB;

    /// Deterministic distinct seeds for tests.
    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn stdlib_path() -> String {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vm_move/stdlib/bytecode")
            .to_string_lossy()
            .to_string()
    }

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = storage::test_dir::process_dir().join(format!(
            "aincore_genmulti_{}_{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(path.to_str().expect("utf8 temp path")).expect("test DB opens"))
    }

    #[test]
    fn parse_validator_spec_roundtrip() {
        let s = format!("{}:{}", hex::encode(seed(3)), 5_000u128);
        let spec = parse_validator_spec(&s).expect("valid spec parses");
        assert_eq!(spec.seed, seed(3));
        assert_eq!(spec.stake_ain, 5_000);
    }

    #[test]
    fn parse_validator_spec_rejects_bad_seed_len() {
        let err = parse_validator_spec("abcd:1000").expect_err("short seed must fail");
        assert!(
            err.to_string().contains("32 bytes"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn parse_validator_spec_rejects_zero_stake() {
        let s = format!("{}:0", hex::encode(seed(4)));
        let err = parse_validator_spec(&s).expect_err("zero stake must fail");
        assert!(err.to_string().contains("stake must be > 0"));
    }

    /// The fields the tool derives MUST equal what a node derives from the same
    /// node.key seed. Address = derive_address(ed25519 pubkey); BLS pk/pop come
    /// from the canonical consensus seed derivation. This locks the tool to the
    /// runtime so the emitted genesis is actually loadable + verifiable.
    #[test]
    fn derived_fields_match_node_runtime_derivation() {
        let s = seed(11);
        let (addr, pk_hex, bls_pk_hex, bls_pop_hex) = derive_validator_fields(&s).expect("derive");

        // ed25519 + address, exactly as the node computes them.
        let sk = SigningKey::from_bytes(&s);
        let vk = sk.verifying_key();
        assert_eq!(pk_hex, hex::encode(vk.to_bytes()));
        assert_eq!(addr, crypto::derive_address(&vk.to_bytes()).unwrap());

        // BLS: the seed the node uses is signing_key.to_bytes() (== s).
        let bls_seed = consensus::qc::derive_validator_bls_seed(&sk.to_bytes());
        let bls = crypto::bls::BLSEngine::consensus();
        assert_eq!(bls_pk_hex, hex::encode(bls.pubkey_raw(&bls_seed)));

        // PoP must verify against the derived public key.
        let pk_bytes = hex::decode(&bls_pk_hex).unwrap();
        let pop_bytes = hex::decode(&bls_pop_hex).unwrap();
        assert!(
            bls.verify_possession(&pk_bytes, &pop_bytes).unwrap(),
            "generated bls_pop must verify against generated bls_public_key"
        );
        // Length invariants the loader enforces (pk=48 MinPk, pop=96).
        assert_eq!(pk_bytes.len(), 48);
        assert_eq!(pop_bytes.len(), 96);
    }

    #[test]
    fn build_genesis_file_rejects_duplicate_seed() {
        let specs = vec![
            ValidatorSpec {
                seed: seed(9),
                stake_ain: 1000,
            },
            ValidatorSpec {
                seed: seed(9),
                stake_ain: 2000,
            },
        ];
        let err = build_genesis_file(&specs, "AINCORE-MAINNET-1", 6_650, 14, "stdlib-hash")
            .expect_err("duplicate must fail");
        assert!(err.to_string().contains("duplicate validator address"));
    }

    /// Two validators independently deriving their genesis fields from the same
    /// emitted set must compute IDENTICAL validator_set_hashes (this is what a QC
    /// binds to). If the BLS keys were embedded wrong, the hashes would differ
    /// and QCs would never verify across nodes.
    #[test]
    fn two_validators_agree_on_validator_set_hash() {
        let specs = vec![
            ValidatorSpec {
                seed: seed(21),
                stake_ain: 1_000_000,
            },
            ValidatorSpec {
                seed: seed(22),
                stake_ain: 2_000_000,
            },
        ];
        let genesis =
            build_genesis_file(&specs, "AINCORE-MAINNET-1", 6_650, 14, "stdlib-hash").unwrap();

        // Reconstruct consensus::qc::ValidatorInfo from the emitted file (this is
        // the same shape genesis.rs writes to sys:validator_set:v1, with stake
        // scaled to whole AIN).
        let to_info = |v: &GenesisValidatorConfig| consensus::qc::ValidatorInfo {
            address: v.address.clone(),
            stake: (v.stake.parse::<u128>().unwrap() / COIN_SCALE) as u64,
            ed25519_public_key: v.public_key.clone(),
            bls_public_key: v.bls_public_key.clone(),
            bls_pop: v.bls_pop.clone(),
        };
        let set: Vec<_> = genesis.validators.iter().map(to_info).collect();

        // validator_set_hash is address-sorted + order-independent: whichever node
        // computes it from the same genesis gets the same hash.
        let hash_a = consensus::qc::validator_set_hash(&set);
        let mut reversed = set.clone();
        reversed.reverse();
        let hash_b = consensus::qc::validator_set_hash(&reversed);
        assert_eq!(hash_a, hash_b, "set hash must be order-independent");
        assert_eq!(hash_a.len(), 64, "set hash must be a 32-byte sha256 hex");
    }

    /// End-to-end: generate a 2-validator genesis, write it to disk, point the
    /// genesis loader at it (AINCORE_GENESIS_PATH), and prove init succeeds with
    /// the embedded BLS keys (no self-derivation, multi-validator path). Then
    /// confirm sys:validator_set:v1 round-trips to the SAME validator_set_hash
    /// the file implies — i.e. the BLS keys were embedded correctly.
    #[test]
    fn generated_multi_validator_genesis_loads_and_set_hash_matches() {
        // Guard the genesis env var against the node crate's own tests, which set
        // AINCORE_GENESIS_PATH / AINCORE_EXPECTED_GENESIS_HASH. We run in a
        // separate process per test binary, but be defensive about leftover env.
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");

        let specs = vec![
            ValidatorSpec {
                seed: seed(31),
                stake_ain: 1_500_000,
            },
            ValidatorSpec {
                seed: seed(32),
                stake_ain: 2_500_000,
            },
        ];
        let genesis = build_genesis_file(
            &specs,
            "AINCORE-MAINNET-1",
            6_650,
            14,
            &node::genesis::stdlib_hash_of(&stdlib_path()).unwrap(),
        )
        .unwrap();

        let dir = storage::test_dir::process_dir()
            .join(format!("aincore_genmulti_e2e_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let genesis_path = dir.join("genesis.json");
        std::fs::write(
            &genesis_path,
            serde_json::to_string_pretty(&genesis).unwrap(),
        )
        .unwrap();
        // The node loads the tool's output as is: same field names, and the
        // pinned stdlib_hash matches the stdlib it builds from.
        let db = temp_db("e2e_load");
        node::genesis::initialize_genesis_from(&db, &stdlib_path(), &genesis_path)
            .expect("multi-validator genesis with embedded BLS keys must load");

        // sys:validator_set:v1 must have been written with all validators.
        let stored = db
            .get("sys:validator_set:v1")
            .unwrap()
            .expect("validator set v1 written");
        let loaded: Vec<consensus::qc::ValidatorInfo> = serde_json::from_str(&stored).unwrap();
        assert_eq!(loaded.len(), 2);

        // Recompute the set hash from the emitted genesis (whole-AIN scaled) and
        // confirm it equals the hash of what genesis init persisted. This is the
        // crux: both "views" agree -> any QC signed under one verifies under the
        // other.
        let expected: Vec<_> = genesis
            .validators
            .iter()
            .map(|v| consensus::qc::ValidatorInfo {
                address: v.address.clone(),
                stake: (v.stake.parse::<u128>().unwrap() / COIN_SCALE) as u64,
                ed25519_public_key: v.public_key.clone(),
                bls_public_key: v.bls_public_key.clone(),
                bls_pop: v.bls_pop.clone(),
            })
            .collect();
        assert_eq!(
            consensus::qc::validator_set_hash(&loaded),
            consensus::qc::validator_set_hash(&expected),
            "persisted validator set hash must match the generated genesis"
        );

        // G5 P-1: the node stores exactly what the tool derived from the block
        // time, and pins the same epoch (I = 1,000) for consensus.
        let derived = node::genesis::derive_chain_params(6_650, 14).unwrap();
        assert_eq!(derived.epoch_blocks, 1_000);
        assert_eq!(node::genesis::stored_chain_params(&db).unwrap(), derived);
        assert_eq!(
            db.get("sys:config:epoch_block_interval").unwrap(),
            Some("1000".to_string())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The coordinator's path: entries made on each validator from its own
    /// node.key build the very genesis the seeds would, so no seed has to
    /// leave its machine.
    #[test]
    fn public_entries_build_the_same_genesis_as_the_seeds() {
        let specs = vec![
            ValidatorSpec {
                seed: seed(21),
                stake_ain: 1_000_000,
            },
            ValidatorSpec {
                seed: seed(22),
                stake_ain: 2_000_000,
            },
        ];
        let from_seeds =
            build_genesis_file(&specs, "AINCORE-MAINNET-1", 6_650, 14, "stdlib-hash").unwrap();
        // Each entry travels as JSON, as the operator sends it.
        let entries: Vec<EntrySpec> = specs
            .iter()
            .map(|s| {
                let json = serde_json::to_string(&entry_from_seed(&s.seed).unwrap()).unwrap();
                EntrySpec {
                    entry: serde_json::from_str(&json).unwrap(),
                    stake_ain: s.stake_ain,
                    bootstrap_ain: 0,
                    entity: None,
                }
            })
            .collect();
        let from_entries =
            build_genesis_from_entries(&entries, "AINCORE-MAINNET-1", 6_650, 14, "stdlib-hash")
                .unwrap();
        assert_eq!(from_entries, from_seeds);
        // The node.key forms the node reads give the same seed.
        assert_eq!(parse_node_key(&seed(21)).unwrap(), seed(21));
        let hex_key = format!("{}\n", hex::encode(seed(21)));
        assert_eq!(parse_node_key(hex_key.as_bytes()).unwrap(), seed(21));
        assert!(parse_node_key(b"short").is_err());
    }

    /// An entry is refused when its address is not its key's, when the node
    /// key did not sign it, when its BLS proof is not its BLS key's, or when
    /// its BLS key is another validator's.
    #[test]
    fn a_forged_or_borrowed_entry_is_refused() {
        let good = entry_from_seed(&seed(31)).unwrap();
        let other = entry_from_seed(&seed(32)).unwrap();
        assert_eq!(check_entry(&good), Ok(()));
        let mut e = good.clone();
        e.address = other.address.clone();
        assert!(check_entry(&e).unwrap_err().contains("does not derive"));
        // Another validator's BLS key with its valid proof, claimed under
        // this node key: the node-key signature does not cover it.
        let mut e = good.clone();
        e.bls_public_key = other.bls_public_key.clone();
        e.bls_pop = other.bls_pop.clone();
        assert!(check_entry(&e).unwrap_err().contains("entry_sig"));
        let mut e = good.clone();
        e.bls_pop = other.bls_pop.clone();
        assert!(check_entry(&e).unwrap_err().contains("bls_pop"));
        let spec = |entry: PublicEntry| EntrySpec {
            entry,
            stake_ain: 1_000,
            bootstrap_ain: 0,
            entity: None,
        };
        let twice = vec![spec(good.clone()), spec(good.clone())];
        let err = build_genesis_from_entries(&twice, "C", 6_650, 14, "h").unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
        let zero = vec![EntrySpec {
            entry: good,
            stake_ain: 0,
            bootstrap_ain: 0,
            entity: None,
        }];
        let err = build_genesis_from_entries(&zero, "C", 6_650, 14, "h").unwrap_err();
        assert!(err.to_string().contains("stake"), "{err}");
    }

    /// G5 A4 BW-2: four operators that own no stake share 18.5 M of bootstrap
    /// weight and a public-track account holds liquid AIN. The node loads the
    /// file: the committee weighs s_min, the bootstrap state matches, and no
    /// bootstrap weight is a coin (the supply is the account's balance
    /// alone). The tool refuses what the loader refuses.
    #[test]
    fn bootstrap_weight_fills_the_genesis_committee_without_coins() {
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let spec = |n: u8, stake_ain: u128, bootstrap_ain: u64| EntrySpec {
            entry: entry_from_seed(&seed(n)).unwrap(),
            stake_ain,
            bootstrap_ain,
            entity: None,
        };
        let ops: Vec<EntrySpec> = (41..45).map(|n| spec(n, 0, 4_625_000)).collect();
        let stdlib_hash = node::genesis::stdlib_hash_of(&stdlib_path()).unwrap();
        let base = build_genesis_from_entries(&ops, "AINCORE-TESTNET-V4", 6_749, 25, &stdlib_hash)
            .unwrap();
        let public = vec![AccountSpec {
            address: entry_from_seed(&seed(45)).unwrap().address,
            balance_ain: 1_000,
        }];
        let mut genesis = base.clone();
        apply_bootstrap_and_accounts(&mut genesis, &ops, Some(18_500_000), &public).unwrap();

        let dir = storage::test_dir::process_dir()
            .join(format!("aincore_genmulti_boot_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("genesis.json");
        std::fs::write(&path, serde_json::to_string_pretty(&genesis).unwrap()).unwrap();
        let db = temp_db("boot_load");
        node::genesis::initialize_genesis_from(&db, &stdlib_path(), &path)
            .expect("a bootstrap genesis loads");
        let committee: Vec<consensus::qc::ValidatorInfo> =
            serde_json::from_str(&db.get("genesis:validator_set:v1").unwrap().unwrap()).unwrap();
        assert_eq!(committee.iter().map(|m| m.stake).sum::<u64>(), 18_500_000);
        assert!(committee.iter().all(|m| m.stake == 4_625_000));
        let state: serde_json::Value =
            serde_json::from_str(&db.get("sys:bootstrap:v1").unwrap().unwrap()).unwrap();
        assert_eq!(state["s_min"], 18_500_000);
        assert_eq!(state["operators"].as_array().unwrap().len(), 4);
        assert_eq!(
            db.get("sys:total_supply").unwrap().unwrap(),
            (1_000 * COIN_SCALE).to_string(),
            "bootstrap weight is no coin: the supply is the account alone"
        );
        let _ = std::fs::remove_dir_all(&dir);

        let refuse = |specs: &[EntrySpec], s_min: Option<u64>, accounts: &[AccountSpec]| {
            apply_bootstrap_and_accounts(&mut base.clone(), specs, s_min, accounts)
                .unwrap_err()
                .to_string()
        };
        assert!(refuse(&ops, Some(18_000_000), &[]).contains("not s_min"));
        assert!(refuse(&ops, None, &[]).contains("--s-min-ain"));
        let owned: Vec<EntrySpec> = (41..45).map(|n| spec(n, 1_000, 0)).collect();
        assert!(refuse(&owned, Some(4_000), &[]).contains("bootstrap_ain"));
        let lopsided = vec![
            spec(41, 0, 7_000_000),
            spec(42, 0, 4_000_000),
            spec(43, 0, 4_000_000),
            spec(44, 0, 3_500_000),
        ];
        assert!(refuse(&lopsided, Some(18_500_000), &[]).contains("a third"));
        // A declared party counts as one: two operators of 25 % are 50 %.
        let mut paired = ops.clone();
        paired[0].entity = Some("founder".into());
        paired[1].entity = Some("founder".into());
        assert!(refuse(&paired, Some(18_500_000), &[]).contains("founder weighs"));
        let taken = vec![AccountSpec {
            address: ops[0].entry.address.clone(),
            balance_ain: 1,
        }];
        assert!(refuse(&ops, Some(18_500_000), &taken).contains("validator and an account"));
        // Parity with the node (review): hex case, duplicates and bad hex.
        let upper = vec![AccountSpec {
            address: ops[0].entry.address.to_uppercase(),
            balance_ain: 1,
        }];
        assert!(refuse(&ops, Some(18_500_000), &upper).contains("validator and an account"));
        let twice = vec![public[0].clone(), public[0].clone()];
        assert!(refuse(&ops, Some(18_500_000), &twice).contains("listed twice"));
        let bad = vec![AccountSpec {
            address: "zz".into(),
            balance_ain: 1,
        }];
        assert!(refuse(&ops, Some(18_500_000), &bad).contains("64-hex"));
        // 1 to 999 owned AIN is below the node's minimum, bootstrap or not.
        let mut thin = ops.clone();
        thin[0].stake_ain = 500;
        thin[0].bootstrap_ain -= 500;
        let err = build_genesis_from_entries(&thin, "AINCORE-TESTNET-V4", 6_749, 25, &stdlib_hash)
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the minimum"), "{err}");
        // What the tool writes, the node accepts: the same rules, one place.
        // score-testnet's allocations set the entries they name, and an
        // allocation without an entry is refused.
        let mut allocated = ops.clone();
        let alloc = crate::score::Allocation {
            address: ops[1].entry.address.to_uppercase(),
            stake_ain: 333_333,
            bootstrap_ain: 4_291_667,
        };
        apply_allocations(&mut allocated, std::slice::from_ref(&alloc)).unwrap();
        assert_eq!(
            (allocated[1].stake_ain, allocated[1].bootstrap_ain),
            (333_333, 4_291_667)
        );
        assert_eq!(allocated[0].bootstrap_ain, 4_625_000, "others keep theirs");
        let stranger = crate::score::Allocation {
            address: "ab".repeat(32),
            ..alloc
        };
        assert!(apply_allocations(&mut allocated, &[stranger])
            .unwrap_err()
            .contains("no validator entry"));
        let check = |g: &GenesisFile| {
            node::genesis::check_genesis_json(&serde_json::to_string(g).unwrap(), &stdlib_path())
        };
        assert!(check(&genesis).is_ok());
        let mut broken = genesis.clone();
        broken.bootstrap.as_mut().unwrap().s_min_ain += 1;
        assert!(check(&broken).is_err());
    }
}
