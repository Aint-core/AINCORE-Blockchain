use move_binary_format::CompiledModule;
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::{StructTag, TypeTag},
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc; // Force rebuild
use storage::class::{classify, KeyClass};
use storage::rocksdb::IteratorMode;
use storage::StateDB;

/// v5 (G3 S3): genesis is built in memory from genesis.json alone, committed
/// as state-tree version 0, and its identity binds `state_root(0)`.
const GENESIS_VERSION: &str = "g3-deterministic-v5";
/// SEC-#13: storage key holding the canonical, genesis-pinned epoch-block
/// interval. It is the only source (G3 FX-6): the node refuses to boot without
/// it, and the AINCORE_EPOCH_BLOCK_INTERVAL env is never read. Folded into the
/// genesis identity hash so it is forge-proof.
const GENESIS_EPOCH_BLOCK_INTERVAL_KEY: &str = "sys:config:epoch_block_interval";
/// Canonical default for the epoch-block interval when genesis.json does not
/// specify one. MUST match `Executor::DEFAULT_EPOCH_BLOCK_INTERVAL`.
const DEFAULT_EPOCH_BLOCK_INTERVAL: u64 = 20;
/// FX-7: the value `StateDB::get_burn_percentage` fell back to.
const DEFAULT_BURN_PERCENTAGE: u8 = 10;
/// FX-7: the value `ChainSync::tip_agreement_n` fell back to.
const DEFAULT_TIP_AGREEMENT_N: u64 = 1;
const GENESIS_STDLIB_MODULES_KEY: &str = "genesis_stdlib_modules";
const GENESIS_STDLIB_COUNT_KEY: &str = "genesis_stdlib_module_count";
/// Module names that MUST be present in the stdlib bundle, published under the
/// system address @0x1. The full storage key is built from `AccountAddress::ONE`
/// so it tracks the address width (#35: 32 bytes / 64 hex via `address32`).
const REQUIRED_STDLIB_MODULE_NAMES: &[&str] =
    &["signer", "vector", "bcs", "hash", "coin", "staking", "dex"];

#[derive(Debug)]
pub enum GenesisError {
    SerializationError(String),
    StorageError(String),
    InvalidData(String),
}

impl fmt::Display for GenesisError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GenesisError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            GenesisError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            GenesisError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
        }
    }
}

impl std::error::Error for GenesisError {}

impl From<serde_json::Error> for GenesisError {
    fn from(err: serde_json::Error) -> Self {
        GenesisError::SerializationError(err.to_string())
    }
}

impl From<rocksdb::Error> for GenesisError {
    fn from(err: rocksdb::Error) -> Self {
        GenesisError::StorageError(err.to_string())
    }
}

impl From<hex::FromHexError> for GenesisError {
    fn from(err: hex::FromHexError) -> Self {
        GenesisError::InvalidData(format!("Hex decode error: {}", err))
    }
}

impl From<bcs::Error> for GenesisError {
    fn from(err: bcs::Error) -> Self {
        GenesisError::SerializationError(format!("BCS error: {}", err))
    }
}

fn system_address() -> AccountAddress {
    AccountAddress::from_hex_literal("0x1").expect("0x1 must be a valid Move address")
}

fn system_resource_key(resource: &str) -> String {
    format!("resource_{}_{}", system_address(), resource)
}

fn parse_move_addr(hex_addr: &str) -> Result<AccountAddress, GenesisError> {
    let bytes = hex::decode(hex_addr)?;
    if bytes.len() != AccountAddress::LENGTH {
        return Err(GenesisError::InvalidData(format!(
            "Invalid Move address length for {}: expected {} bytes, got {}",
            hex_addr,
            AccountAddress::LENGTH,
            bytes.len()
        )));
    }
    let mut addr_array = [0u8; AccountAddress::LENGTH];
    addr_array.copy_from_slice(&bytes);
    Ok(AccountAddress::new(addr_array))
}

fn parse_genesis_amount(value: &str, field: &str) -> Result<u128, GenesisError> {
    value.parse::<u128>().map_err(|err| {
        GenesisError::InvalidData(format!(
            "Invalid genesis {} amount '{}': {}",
            field, value, err
        ))
    })
}

fn parse_validator_public_key(
    public_key_hex: &str,
    validator_addr: &str,
) -> Result<Vec<u8>, GenesisError> {
    let public_key = hex::decode(public_key_hex)?;
    if public_key.len() != 32 {
        return Err(GenesisError::InvalidData(format!(
            "Invalid genesis validator public key length for {}: expected 32 bytes, got {}",
            validator_addr,
            public_key.len()
        )));
    }
    let derived = crypto::derive_address(&public_key).map_err(|err| {
        GenesisError::InvalidData(format!(
            "Failed to derive genesis validator address: {}",
            err
        ))
    })?;
    if derived != validator_addr {
        return Err(GenesisError::InvalidData(format!(
            "Genesis validator address/public_key mismatch: address={} derived={}",
            validator_addr, derived
        )));
    }
    Ok(public_key)
}

/// Decode and PoP-verify a genesis validator's BLS identity.
///
/// G3 FX-7: both keys are required for every validator. Genesis used to
/// derive a missing pair from the booting node's own key for a
/// single-validator genesis, which made genesis state depend on which node
/// built it. Returns `(bls_public_key, bls_pop)` as raw bytes.
fn resolve_genesis_bls_identity(
    validator: &str,
    bls_public_key_hex: Option<&str>,
    bls_pop_hex: Option<&str>,
) -> Result<(Vec<u8>, Vec<u8>), GenesisError> {
    let (Some(pk_hex), Some(pop_hex)) = (bls_public_key_hex, bls_pop_hex) else {
        return Err(GenesisError::InvalidData(format!(
            "genesis validator {validator} must supply both bls_public_key and bls_pop \
             (genesis-tool gen-multi writes them)"
        )));
    };
    let bls = crypto::bls::BLSEngine::consensus();
    let pk = hex::decode(pk_hex.trim())?;
    let pop = hex::decode(pop_hex.trim())?;
    if pk.len() != 48 {
        return Err(GenesisError::InvalidData(format!(
            "Genesis bls_public_key must be 48 bytes (MinPk), got {}",
            pk.len()
        )));
    }
    if pop.len() != 96 {
        return Err(GenesisError::InvalidData(format!(
            "Genesis bls_pop must be 96 bytes, got {}",
            pop.len()
        )));
    }
    match bls.verify_possession(&pk, &pop) {
        Ok(true) => Ok((pk, pop)),
        Ok(false) => Err(GenesisError::InvalidData(
            "Genesis validator bls_pop failed proof-of-possession verification".to_string(),
        )),
        Err(e) => Err(GenesisError::InvalidData(format!(
            "Genesis validator BLS key/PoP invalid: {:?}",
            e
        ))),
    }
}

/// Convert a u128 genesis stake (in 10^18 quanta) to whole-AIN `u64` units for
/// `qc::ValidatorInfo.stake`. Overflow-checked: an absurd stake that does not fit
/// in u64 after scaling is rejected rather than silently truncated.
fn scale_stake_to_whole_ain(stake_quanta: u128) -> Result<u64, GenesisError> {
    const COIN_SCALE: u128 = 1_000_000_000_000_000_000; // 10^18
    let whole = stake_quanta / COIN_SCALE;
    u64::try_from(whole).map_err(|_| {
        GenesisError::InvalidData(format!(
            "Genesis stake {} AIN exceeds u64 range for validator-set stake",
            whole
        ))
    })
}

/// Build a `consensus::qc::ValidatorInfo` for the versioned validator set.
fn crypto_qc_validator_info(
    address: &str,
    stake_quanta: u128,
    ed25519_public_key_hex: &str,
    bls_public_key: &[u8],
    bls_pop: &[u8],
) -> Result<consensus::qc::ValidatorInfo, GenesisError> {
    Ok(consensus::qc::ValidatorInfo {
        address: address.to_string(),
        stake: scale_stake_to_whole_ain(stake_quanta)?,
        ed25519_public_key: ed25519_public_key_hex.to_string(),
        bls_public_key: hex::encode(bls_public_key),
        bls_pop: hex::encode(bls_pop),
    })
}

fn aincore_coin_tag() -> StructTag {
    StructTag {
        address: system_address(),
        module: Identifier::new("staking").expect("valid module"),
        name: Identifier::new("AincoreCoin").expect("valid struct"),
        type_params: vec![],
    }
}

fn coin_store_key(addr: AccountAddress) -> String {
    let tag = StructTag {
        address: system_address(),
        module: Identifier::new("coin").expect("valid module"),
        name: Identifier::new("CoinStore").expect("valid struct"),
        type_params: vec![TypeTag::Struct(Box::new(aincore_coin_tag()))],
    };
    format!("resource_{}_{}", addr, tag)
}

fn stdlib_state_hash(modules: &[(String, Vec<u8>)]) -> String {
    let mut hasher = Sha256::new();
    for (key, bytes) in modules {
        hasher.update((key.len() as u64).to_le_bytes());
        hasher.update(key.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

/// SEC-#30 / G3 TA-1: fold the canonical genesis markers into a single
/// chain-identity digest. Every input comes from the in-memory genesis
/// (`build_genesis`), never from the database, which may later be pruned or
/// restored. The opt-in genesis-hash pin (`AINCORE_EXPECTED_GENESIS_HASH`)
/// compares against this to refuse booting the wrong chain (wrong
/// genesis.json / wrong datadir / wrong validator set). Length-prefixed and
/// domain-tagged, mirroring `stdlib_state_hash`, so it is deterministic and
/// collision-resistant across nodes.
fn genesis_identity_hash(
    stdlib_hash: &str,
    version: &str,
    chain_id: &str,
    validator_set_json: &str,
    epoch_block_interval: &str,
    state_root: &str,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        "AINCORE_GENESIS_ID_V2",
        stdlib_hash,
        version,
        chain_id,
        validator_set_json,
        // SEC-#13: pin the epoch-block interval into chain identity so a node
        // booting with a tampered/divergent interval is rejected by the genesis
        // hash pin (it would advance epochs at different heights → fork).
        epoch_block_interval,
        // G3 TA-1: the root of state-tree version 0 binds every genesis state
        // key, so two chains with the same markers but any other genesis
        // difference have different identities.
        state_root,
    ] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn load_stdlib_modules(stdlib_path: &str) -> Result<Vec<(String, Vec<u8>)>, GenesisError> {
    let entries = fs::read_dir(stdlib_path).map_err(|_| {
        GenesisError::InvalidData(format!(
            "Failed to read Stdlib bytecode directory: {}. Make sure you ran the compiler tool first!",
            stdlib_path
        ))
    })?;

    let mut module_paths: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("mv"))
        .collect();
    module_paths.sort();

    if module_paths.is_empty() {
        return Err(GenesisError::InvalidData(format!(
            "Stdlib bytecode directory has no .mv modules: {}",
            stdlib_path
        )));
    }

    let mut modules = Vec::new();
    let mut seen = BTreeSet::new();
    for path in module_paths {
        let bytes = fs::read(&path).map_err(|err| {
            GenesisError::InvalidData(format!(
                "Failed to read stdlib module {}: {}",
                path.display(),
                err
            ))
        })?;
        let module = CompiledModule::deserialize(&bytes).map_err(|err| {
            GenesisError::InvalidData(format!(
                "Failed to deserialize stdlib module {}: {}",
                path.display(),
                err
            ))
        })?;
        let id = module.self_id();
        let key = format!("module_{}_{}", id.address(), id.name());
        if !seen.insert(key.clone()) {
            return Err(GenesisError::InvalidData(format!(
                "Duplicate stdlib module key from {}: {}",
                path.display(),
                key
            )));
        }
        modules.push((key, bytes));
    }

    modules.sort_by(|(left, _), (right, _)| left.cmp(right));
    validate_required_stdlib_modules(&modules)?;
    Ok(modules)
}

fn validate_required_stdlib_modules(modules: &[(String, Vec<u8>)]) -> Result<(), GenesisError> {
    let available: BTreeSet<&str> = modules.iter().map(|(key, _)| key.as_str()).collect();
    for name in REQUIRED_STDLIB_MODULE_NAMES {
        let required = format!("module_{}_{}", AccountAddress::ONE, name);
        if !available.contains(required.as_str()) {
            return Err(GenesisError::InvalidData(format!(
                "Stdlib bytecode is missing required module: {}",
                required
            )));
        }
    }
    Ok(())
}

fn decode_stored_stdlib_modules(
    storage: &Arc<StateDB>,
) -> Result<Vec<(String, Vec<u8>)>, GenesisError> {
    let module_keys_json = storage.get(GENESIS_STDLIB_MODULES_KEY)?.ok_or_else(|| {
        GenesisError::InvalidData(format!(
            "Genesis marker exists but {} is missing",
            GENESIS_STDLIB_MODULES_KEY
        ))
    })?;
    let module_keys: Vec<String> = serde_json::from_str(&module_keys_json).map_err(|err| {
        GenesisError::InvalidData(format!(
            "Genesis marker exists but {} is not valid JSON: {}",
            GENESIS_STDLIB_MODULES_KEY, err
        ))
    })?;
    if module_keys.is_empty() {
        return Err(GenesisError::InvalidData(
            "Genesis marker exists but stdlib module list is empty".to_string(),
        ));
    }

    let mut modules = Vec::new();
    for key in module_keys {
        let value = storage.get(&key)?.ok_or_else(|| {
            GenesisError::InvalidData(format!(
                "Genesis marker exists but required Move module is missing: {}",
                key
            ))
        })?;
        let bytes = hex::decode(value)?;
        let module = CompiledModule::deserialize(&bytes).map_err(|err| {
            GenesisError::InvalidData(format!(
                "Genesis marker exists but Move module failed bytecode decode: {} ({})",
                key, err
            ))
        })?;
        let module_id = module.self_id();
        let actual_key = format!("module_{}_{}", module_id.address(), module_id.name());
        if actual_key != key {
            return Err(GenesisError::InvalidData(format!(
                "Genesis marker exists but Move module key/id mismatch: key={} module={}",
                key, actual_key
            )));
        }
        modules.push((key, bytes));
    }

    modules.sort_by(|(left, _), (right, _)| left.cmp(right));
    validate_required_stdlib_modules(&modules)?;
    Ok(modules)
}

/// Structural checks on a stored genesis: the stdlib modules and markers are
/// intact and every system resource still decodes. The chain identity is
/// checked separately, against the in-memory genesis (TA-1).
// The mirror structs below exist only to be decoded, never read.
#[allow(dead_code)]
fn verify_genesis_integrity(storage: &Arc<StateDB>) -> Result<(), GenesisError> {
    #[derive(serde::Deserialize)]
    struct Coin {
        value: u128,
    }
    #[derive(serde::Deserialize)]
    struct ValidatorConfig {
        validator_addr: AccountAddress,
        stake: Coin,
        public_key: Vec<u8>,
        bls_public_key: Vec<u8>,
        bls_pop: Vec<u8>,
    }
    #[derive(serde::Deserialize)]
    struct UnbondingRequest {
        validator_addr: AccountAddress,
        stake: u128,
        unlock_time: u64,
    }
    #[derive(serde::Deserialize)]
    struct ValidatorSet {
        validators: Vec<ValidatorConfig>,
        unbonding_queue: Vec<UnbondingRequest>,
        total_supply: u128,
        current_epoch: u64,
    }
    #[derive(serde::Deserialize)]
    struct Epoch {
        epoch_number: u64,
        epoch_start_time: u64,
        epoch_duration: u64,
    }
    #[derive(serde::Deserialize)]
    struct Proposal {
        id: u64,
        proposer: AccountAddress,
        description: Vec<u8>,
        votes_for: u128,
        votes_against: u128,
        executed: bool,
        action_type: u8,
        action_value: u64,
        voters: Vec<AccountAddress>,
    }
    #[derive(serde::Deserialize)]
    struct GovernanceState {
        proposals: Vec<Proposal>,
        next_proposal_id: u64,
    }
    #[derive(serde::Deserialize)]
    struct Treasury {
        reserve: Coin,
        total_sold: u128,
        price_usd_cents: u64,
    }
    #[derive(serde::Deserialize)]
    struct PoolInfo {
        pool_key: Vec<u8>,
        pool_addr: AccountAddress,
        token_x_name: Vec<u8>,
        token_y_name: Vec<u8>,
        fee_bp: u64,
        creator: AccountAddress,
        active: bool,
    }
    #[derive(serde::Deserialize)]
    struct PoolRegistry {
        pools: Vec<PoolInfo>,
    }
    // Mirror the Move field order of 0x1::wbtc::BridgeConfig and
    // 0x1::token_factory::TokenRegistry so a datadir missing either resource
    // fails fast at reopen instead of forking on the first wBTC / token_factory
    // transaction. Genesis seeds both (added in the v2 bump above).
    #[derive(serde::Deserialize)]
    struct WbtcBridgeConfig {
        authority: AccountAddress,
        total_minted: u128,
        total_burned: u128,
    }
    #[derive(serde::Deserialize)]
    struct TokenFactoryRegistry {
        tokens: Vec<Vec<u8>>,
    }

    fn decode_resource<T: DeserializeOwned>(
        storage: &Arc<StateDB>,
        key: &str,
    ) -> Result<T, GenesisError> {
        let value = storage.get(key)?.ok_or_else(|| {
            GenesisError::InvalidData(format!(
                "Genesis marker exists but required Move resource is missing: {}",
                key
            ))
        })?;
        let bytes = hex::decode(value)?;
        bcs::from_bytes::<T>(&bytes).map_err(|err| {
            GenesisError::InvalidData(format!(
                "Genesis marker exists but required Move resource failed BCS decode: {} ({})",
                key, err
            ))
        })
    }

    let stored_modules = decode_stored_stdlib_modules(storage)?;
    let expected_hash = storage.get("genesis_stdlib_hash")?.ok_or_else(|| {
        GenesisError::InvalidData(
            "Genesis marker exists but genesis_stdlib_hash is missing".to_string(),
        )
    })?;
    let actual_hash = stdlib_state_hash(&stored_modules);
    if actual_hash != expected_hash {
        return Err(GenesisError::InvalidData(format!(
            "Genesis stdlib hash mismatch: marker={} actual={}",
            expected_hash, actual_hash
        )));
    }

    let expected_count = storage.get(GENESIS_STDLIB_COUNT_KEY)?.ok_or_else(|| {
        GenesisError::InvalidData(format!(
            "Genesis marker exists but {} is missing",
            GENESIS_STDLIB_COUNT_KEY
        ))
    })?;
    let expected_count = expected_count.parse::<usize>().map_err(|err| {
        GenesisError::InvalidData(format!(
            "Genesis marker exists but {} is invalid: {}",
            GENESIS_STDLIB_COUNT_KEY, err
        ))
    })?;
    if expected_count != stored_modules.len() {
        return Err(GenesisError::InvalidData(format!(
            "Genesis stdlib module count mismatch: marker={} actual={}",
            expected_count,
            stored_modules.len()
        )));
    }

    let version = storage.get("genesis_version")?.ok_or_else(|| {
        GenesisError::InvalidData(
            "Genesis marker exists but genesis_version is missing".to_string(),
        )
    })?;
    if version != GENESIS_VERSION {
        return Err(GenesisError::InvalidData(format!(
            "Genesis version mismatch: expected {} got {}",
            GENESIS_VERSION, version
        )));
    }

    let validator_set: ValidatorSet =
        decode_resource(storage, &system_resource_key("0x1::staking::ValidatorSet"))?;
    let _validator_count = validator_set.validators.len();
    let _epoch: Epoch = decode_resource(storage, &system_resource_key("0x1::epoch::Epoch"))?;
    let _governance: GovernanceState = decode_resource(
        storage,
        &system_resource_key("0x1::governance::GovernanceState"),
    )?;
    let _treasury: Treasury =
        decode_resource(storage, &system_resource_key("0x1::treasury::Treasury"))?;
    let _dex_registry: PoolRegistry =
        decode_resource(storage, &system_resource_key("0x1::dex::PoolRegistry"))?;
    let _bridge_config: WbtcBridgeConfig =
        decode_resource(storage, &system_resource_key("0x1::wbtc::BridgeConfig"))?;
    let _token_registry: TokenFactoryRegistry = decode_resource(
        storage,
        &system_resource_key("0x1::token_factory::TokenRegistry"),
    )?;

    Ok(())
}

/// One validator in genesis.json.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisValidatorConfig {
    pub address: String,
    pub public_key: String,
    pub stake: String,
    /// FX-7: required for every validator. Optional here only so a missing
    /// key gets a clear error rather than a bare serde message.
    #[serde(default)]
    pub bls_public_key: Option<String>,
    #[serde(default)]
    pub bls_pop: Option<String>,
}

/// genesis.json: the only input genesis state depends on, besides the stdlib
/// it pins by hash.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisFile {
    pub chain_id: String,
    pub validators: Vec<GenesisValidatorConfig>,
    pub treasury_reserve: String,
    pub epoch_duration: u64,
    /// SEC-#13: the canonical epoch-BLOCK interval (in blocks). Distinct from
    /// `epoch_duration`, a wall-clock seconds value used by the Move epoch
    /// resource. When omitted, DEFAULT_EPOCH_BLOCK_INTERVAL is used. Pinned
    /// into state and the genesis identity so every node advances epochs at
    /// identical heights.
    #[serde(default)]
    pub epoch_block_interval: Option<u64>,
    /// FX-7: `stdlib_state_hash` of the stdlib this chain starts from.
    pub stdlib_hash: String,
    /// FX-7: seeded into `sys:config:burn_percentage`. Default 10.
    #[serde(default)]
    pub burn_percentage: Option<u8>,
    /// FX-7: seeded into `sys:config:tip_agreement_n`. Default 1.
    #[serde(default)]
    pub tip_agreement_n: Option<u64>,
}

/// The genesis state, built in memory by `build_genesis`.
#[derive(Debug, Clone)]
pub struct GenesisState {
    /// Every key genesis writes, with its exact stored value.
    pub writes: BTreeMap<String, String>,
    /// The root of state-tree version 0 over the state-class writes.
    pub state_root: [u8; 32],
    /// The chain identity: the genesis markers plus `state_root`.
    pub identity: String,
}

/// Genesis writes, collected in memory. Every key has exactly one writer, so
/// a key written twice is refused: it means genesis.json listed something
/// twice.
#[derive(Default)]
struct GenesisWrites(BTreeMap<String, String>);

impl GenesisWrites {
    fn put(&mut self, key: &str, value: &str) -> Result<(), GenesisError> {
        if self.0.insert(key.to_string(), value.to_string()).is_some() {
            return Err(GenesisError::InvalidData(format!(
                "genesis writes {key} twice"
            )));
        }
        Ok(())
    }

    /// The same key and bytes as `StateDB::put_object`.
    fn put_object(&mut self, object: &storage::object::Object) -> Result<(), GenesisError> {
        self.put(
            &format!("obj:{}", object.id),
            &serde_json::to_string(object)?,
        )
    }

    fn set_federation_key(&mut self, addr: &str) -> Result<(), GenesisError> {
        self.put("sys:config:federation_addr", addr)
    }

    /// TA-1: the root of version 0 and the identity, both from these writes.
    fn finish(
        self,
        stdlib_hash: &str,
        chain_id: &str,
        epoch_block_interval: u64,
    ) -> Result<GenesisState, GenesisError> {
        let mut state = BTreeMap::new();
        for (key, value) in &self.0 {
            match classify(key.as_bytes()) {
                Some(KeyClass::State) => {
                    state.insert(key.clone(), value.as_bytes().to_vec());
                }
                Some(_) => {}
                None => {
                    return Err(GenesisError::InvalidData(format!(
                        "genesis writes an unclassified key: {key}"
                    )))
                }
            }
        }
        let root = state_commit::genesis_root(&state)
            .map_err(|e| GenesisError::InvalidData(format!("genesis state root: {e}")))?;
        let validator_set_json = self.0.get("genesis:validator_set:v1").ok_or_else(|| {
            GenesisError::InvalidData("genesis wrote no validator set".to_string())
        })?;
        let identity = genesis_identity_hash(
            stdlib_hash,
            GENESIS_VERSION,
            chain_id,
            validator_set_json,
            &epoch_block_interval.to_string(),
            &hex::encode(root.0),
        );
        Ok(GenesisState {
            writes: self.0,
            state_root: root.0,
            identity,
        })
    }
}

/// Where genesis.json is: `AINCORE_GENESIS_PATH`, else the first standard
/// location that exists. The old `../genesis.json` and `../../genesis.json`
/// fallbacks are gone: they made the result depend on the working directory.
pub fn genesis_file_path() -> Result<PathBuf, GenesisError> {
    if let Ok(path) = std::env::var("AINCORE_GENESIS_PATH") {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path.trim()));
        }
    }
    for path in [
        "genesis.json",
        "/usr/src/aincore/genesis.json",
        "/root/.aincore/genesis.json",
    ] {
        if std::path::Path::new(path).exists() {
            return Ok(PathBuf::from(path));
        }
    }
    Err(GenesisError::InvalidData(
        "genesis.json not found: set AINCORE_GENESIS_PATH or run from the directory that \
         holds it"
            .to_string(),
    ))
}

/// FX-7: a missing or unparseable genesis.json is an error, never a fallback.
pub fn load_genesis_file(path: &std::path::Path) -> Result<GenesisFile, GenesisError> {
    let contents = fs::read_to_string(path)
        .map_err(|e| GenesisError::InvalidData(format!("cannot read {}: {e}", path.display())))?;
    serde_json::from_str(&contents).map_err(|e| {
        GenesisError::InvalidData(format!(
            "{} is not a valid genesis file: {e}",
            path.display()
        ))
    })
}

/// G3 S6: this node's own genesis, built from its genesis.json and stdlib the
/// way `initialize_genesis` builds it, and checked against the operator's
/// pin. A snapshot restore binds the restored state to it (TA-1) and writes
/// its rows outside the state.
pub fn build_local_genesis(stdlib_path: &str) -> Result<GenesisState, GenesisError> {
    let file = load_genesis_file(&genesis_file_path()?)?;
    let genesis = build_genesis(&file, &load_stdlib_modules(stdlib_path)?)?;
    check_genesis_pin(&genesis.identity)?;
    Ok(genesis)
}

/// `stdlib_state_hash` of a stdlib directory: the value genesis.json pins as
/// `stdlib_hash`.
pub fn stdlib_hash_of(stdlib_path: &str) -> Result<String, GenesisError> {
    Ok(stdlib_state_hash(&load_stdlib_modules(stdlib_path)?))
}

/// G3 SN-1b: genesis never runs on a datadir a snapshot restore marked; the
/// restore must finish (or the datadir be wiped) first.
fn refuse_unfinished_restore(storage: &StateDB) -> Result<(), GenesisError> {
    if storage.get(storage::RESTORE_MARKER)?.is_some() {
        return Err(GenesisError::InvalidData(
            "a snapshot restore is unfinished in this datadir: run the restore again, or wipe \
             the datadir"
                .to_string(),
        ));
    }
    Ok(())
}

/// Initialize genesis from the genesis.json `genesis_file_path` finds, or
/// reopen a database that already holds one (which needs no genesis.json).
pub fn initialize_genesis(storage: &Arc<StateDB>, stdlib_path: &str) -> Result<(), GenesisError> {
    refuse_unfinished_restore(storage)?;
    if storage.get("genesis_initialized")?.is_some() {
        return reopen_genesis(storage);
    }
    initialize_genesis_from(storage, stdlib_path, &genesis_file_path()?)
}

/// Initialize genesis from `genesis_path`, or reopen a database that already
/// holds one.
///
/// A fresh database gets the in-memory genesis (TA-1) in one block
/// transaction, as state-tree version 0.
///
/// A reopen reads neither genesis.json nor the stdlib and runs no genesis
/// code. The identity was computed once, at genesis; recomputing it on every
/// boot would make every later stdlib or genesis-code change refuse existing
/// nodes. The operator's `AINCORE_EXPECTED_GENESIS_HASH` pin, checked against
/// the stored identity, is what refuses a wrong datadir.
pub fn initialize_genesis_from(
    storage: &Arc<StateDB>,
    stdlib_path: &str,
    genesis_path: &std::path::Path,
) -> Result<(), GenesisError> {
    refuse_unfinished_restore(storage)?;
    if storage.get("genesis_initialized")?.is_some() {
        return reopen_genesis(storage);
    }
    let file = load_genesis_file(genesis_path)?;
    let genesis = build_genesis(&file, &load_stdlib_modules(stdlib_path)?)?;
    check_genesis_pin(&genesis.identity)?;
    // Genesis state must be exactly the genesis writes. A state key already
    // on disk would sit in the flat store but not in tree version 0.
    if let Some(key) = storage
        .db
        .iterator(IteratorMode::Start)
        .map_while(Result::ok)
        .map(|(key, _)| key)
        .find(|key| classify(key) == Some(KeyClass::State))
    {
        return Err(GenesisError::InvalidData(format!(
            "genesis needs a clean database, but it already holds state key {}",
            String::from_utf8_lossy(&key)
        )));
    }
    println!("🌋 Initializing genesis from {}", genesis_path.display());
    commit_genesis(storage, &genesis)?;
    verify_genesis_integrity(storage)?;
    println!(
        "✅ Genesis committed: {} keys, state root {}, identity {}",
        genesis.writes.len(),
        hex::encode(genesis.state_root),
        genesis.identity
    );
    Ok(())
}

/// Reopen: the stored identity, checked against the operator pin, plus the
/// structural checks.
fn reopen_genesis(storage: &Arc<StateDB>) -> Result<(), GenesisError> {
    let identity = storage.get("genesis_identity")?.ok_or_else(|| {
        GenesisError::InvalidData("genesis is initialized but genesis_identity is missing".into())
    })?;
    check_genesis_pin(&identity)?;
    verify_genesis_integrity(storage)?;
    println!("✨ Genesis already initialized: {}", identity);
    Ok(())
}

/// SEC-#30: when `AINCORE_EXPECTED_GENESIS_HASH` is set, refuse to boot any
/// other genesis. Unset, the check is a no-op until the mainnet hash is frozen.
fn check_genesis_pin(identity: &str) -> Result<(), GenesisError> {
    if let Ok(pin) = std::env::var("AINCORE_EXPECTED_GENESIS_HASH") {
        let pin = pin.trim().to_lowercase();
        if !pin.is_empty() && pin != identity {
            return Err(GenesisError::InvalidData(format!(
                "🚨 [SECURITY] genesis hash pin mismatch: expected {} computed {} — \
                 refusing to boot (wrong genesis.json / wrong datadir / wrong chain)",
                pin, identity
            )));
        }
    }
    Ok(())
}

/// WG-2: genesis writes through the same gate as a block, as state-tree
/// version 0, in one atomic batch. The tree's root must equal the in-memory
/// root the identity binds.
fn commit_genesis(storage: &Arc<StateDB>, genesis: &GenesisState) -> Result<(), GenesisError> {
    use storage::StorageError;
    storage
        .block_transaction(|view| {
            for (key, value) in &genesis.writes {
                view.put(key, value)?;
            }
            let changes = view.staged_state_changes().ok_or_else(|| {
                StorageError::DatabaseOperation("genesis must run in a transaction".into())
            })?;
            let applied = state_commit::apply(&view, 0, changes)
                .map_err(|e| StorageError::DatabaseOperation(format!("genesis state tree: {e}")))?;
            if applied.root.0 != genesis.state_root {
                return Err(StorageError::DatabaseOperation(format!(
                    "genesis tree root {} differs from the in-memory root {}",
                    hex::encode(applied.root.0),
                    hex::encode(genesis.state_root)
                )));
            }
            view.write_batch(applied.batch)?;
            if !view.seal_state() {
                return Err(StorageError::DatabaseOperation(
                    "genesis must be sealed in its block transaction".into(),
                ));
            }
            view.put("genesis_identity", &genesis.identity)?;
            view.put("genesis_initialized", "true")?;
            Ok(())
        })
        .map_err(|e| GenesisError::StorageError(e.to_string()))?;
    // Crash witness: nothing genesis writes may come after its one
    // transaction, so a crash here must leave a complete genesis.
    #[cfg(test)]
    if std::env::var_os("AINCORE_TEST_GENESIS_CRASH_AFTER_COMMIT").is_some() {
        std::process::exit(77);
    }
    Ok(())
}

/// G3 FX-7 / TA-1: the genesis state, computed in memory from `genesis.json`
/// and the stdlib alone. Nothing comes from the booting node: not its key,
/// its working directory or its environment. Every node that builds from the
/// same inputs gets byte-identical writes, the same `state_root(0)` and the
/// same identity (DT-3).
pub fn build_genesis(
    file: &GenesisFile,
    stdlib_modules: &[(String, Vec<u8>)],
) -> Result<GenesisState, GenesisError> {
    validate_required_stdlib_modules(stdlib_modules)?;
    let stdlib_hash = stdlib_state_hash(stdlib_modules);
    // FX-7: genesis.json pins the stdlib it starts from, so a node with other
    // bytecode on disk refuses instead of starting a different chain.
    if !file.stdlib_hash.trim().eq_ignore_ascii_case(&stdlib_hash) {
        return Err(GenesisError::InvalidData(format!(
            "genesis.json pins stdlib_hash {} but the stdlib on disk hashes to {}",
            file.stdlib_hash.trim(),
            stdlib_hash
        )));
    }
    let mut storage = GenesisWrites::default();
    let stdlib_module_keys: Vec<String> =
        stdlib_modules.iter().map(|(key, _)| key.clone()).collect();
    for (key, bytes) in stdlib_modules {
        storage.put(key, &hex::encode(bytes))?;
    }

    // G3 FX-7: no account for the booting node's own key. Genesis state is a
    // function of genesis.json alone. That account existed only on the node
    // that wrote it, so a node that is not a genesis validator had one extra
    // leaf in version 0 of the state tree and refused block 1 forever.
    // Validators get their accounts from the validator loop below.
    use aa::AccountManager;

    // === Initialize Staking (Validator Set) ===
    // We manually create the ValidatorSet resource for the genesis validator
    // Structs must match Move definition (Updated to u128)
    #[derive(serde::Serialize)]
    struct Coin {
        value: u128, // Updated to u128
    }
    #[derive(serde::Serialize)]
    struct ValidatorConfig {
        validator_addr: move_core_types::account_address::AccountAddress,
        stake: Coin,
        public_key: Vec<u8>,
        bls_public_key: Vec<u8>,
        bls_pop: Vec<u8>,
    }
    #[derive(serde::Serialize)]
    struct ValidatorSet {
        validators: Vec<ValidatorConfig>,
        unbonding_queue: Vec<UnbondingRequest>,
        total_supply: u128, // Added total_supply
        current_epoch: u64, // Added current_epoch
    }
    #[derive(serde::Serialize)]
    struct UnbondingRequest {
        validator_addr: move_core_types::account_address::AccountAddress,
        stake: u128,
        unlock_time: u64,
    }

    let mut genesis_validators = Vec::new();
    let mut validator_configs = Vec::new();
    let mut v1_validators: Vec<consensus::qc::ValidatorInfo> = Vec::new();
    let mut total_bootstrap_stake: u128 = 0;
    let treasury_reserve_amount: u128;
    let genesis_epoch_duration: u64;
    // SEC-#13: canonical epoch-block interval to pin into storage + identity hash.
    let genesis_epoch_block_interval: u64;
    let genesis_chain_id: String;
    let genesis_burn_percentage: u8;
    let genesis_tip_agreement_n: u64;

    {
        let config = file;
        if config.chain_id.trim().is_empty() {
            return Err(GenesisError::InvalidData(
                "genesis.json chain_id must not be empty".to_string(),
            ));
        }
        genesis_chain_id = config.chain_id.clone();
        if config.validators.is_empty() {
            return Err(GenesisError::InvalidData(
                "genesis.json must contain at least one validator".to_string(),
            ));
        }
        treasury_reserve_amount =
            parse_genesis_amount(&config.treasury_reserve, "treasury_reserve")?;
        genesis_epoch_duration = config.epoch_duration;
        if genesis_epoch_duration == 0 {
            return Err(GenesisError::InvalidData(
                "genesis.json epoch_duration must be greater than 0".to_string(),
            ));
        }
        // SEC-#13: an explicit 0 is invalid (it would disable epoch advancement);
        // omission falls back to the canonical default.
        genesis_epoch_block_interval = match config.epoch_block_interval {
            Some(0) => {
                return Err(GenesisError::InvalidData(
                    "genesis.json epoch_block_interval must be greater than 0".to_string(),
                ));
            }
            Some(v) => v,
            None => DEFAULT_EPOCH_BLOCK_INTERVAL,
        };
        // FX-7: the defaults these keys' readers used when the keys were absent.
        genesis_burn_percentage = match config.burn_percentage {
            Some(p) if p > 100 => {
                return Err(GenesisError::InvalidData(format!(
                    "genesis.json burn_percentage {p} is above 100"
                )));
            }
            Some(p) => p,
            None => DEFAULT_BURN_PERCENTAGE,
        };
        genesis_tip_agreement_n = match config.tip_agreement_n {
            Some(0) => {
                return Err(GenesisError::InvalidData(
                    "genesis.json tip_agreement_n must be at least 1".to_string(),
                ));
            }
            Some(n) => n,
            None => DEFAULT_TIP_AGREEMENT_N,
        };
        // SEC (audit M-4): genesis writes sys:validator_set:v1 directly, bypassing the
        // Move staking module's MIN_STAKE check. scale_stake_to_whole_ain integer-divides
        // quanta by 10^18, so ANY stake below 1 whole AIN silently becomes 0 whole-AIN
        // voting power (registered but never counted for quorum/leader) — and an all-
        // sub-1-AIN set yields total_stake==0, making strict >2/3 unsatisfiable → the
        // chain never finalizes. Enforce the real minimum (1000 AIN) here, matching the
        // Move staking module, so no genesis validator can be silently disenfranchised.
        const MIN_VALIDATOR_STAKE_QUANTA: u128 = 1000 * 1_000_000_000_000_000_000; // 1000 AIN
        for val in &config.validators {
            let stake = parse_genesis_amount(&val.stake, "validator stake")?;
            if stake < MIN_VALIDATOR_STAKE_QUANTA {
                return Err(GenesisError::InvalidData(format!(
                    "Genesis validator {} stake {} quanta is below the minimum {} quanta \
                     (1000 AIN) and would scale to {} whole-AIN voting power",
                    val.address,
                    stake,
                    MIN_VALIDATOR_STAKE_QUANTA,
                    stake / 1_000_000_000_000_000_000
                )));
            }
            if genesis_validators
                .iter()
                .any(|(a, _): &(String, String)| a == &val.address)
            {
                return Err(GenesisError::InvalidData(format!(
                    "genesis validator {} is listed twice",
                    val.address
                )));
            }
            genesis_validators.push((val.address.clone(), val.public_key.clone()));
            total_bootstrap_stake = total_bootstrap_stake.checked_add(stake).ok_or_else(|| {
                GenesisError::InvalidData("genesis validator stakes overflow u128".to_string())
            })?;

            let account_addr = parse_move_addr(&val.address)?;
            let public_key = parse_validator_public_key(&val.public_key, &val.address)?;
            // FX-7: explicit, PoP-verified BLS keys for every validator.
            let (bls_public_key, bls_pop) = resolve_genesis_bls_identity(
                &val.address,
                val.bls_public_key.as_deref(),
                val.bls_pop.as_deref(),
            )?;

            validator_configs.push(ValidatorConfig {
                validator_addr: account_addr,
                stake: Coin { value: stake },
                public_key,
                bls_public_key: bls_public_key.clone(),
                bls_pop: bls_pop.clone(),
            });
            v1_validators.push(crypto_qc_validator_info(
                &val.address,
                stake,
                &val.public_key,
                &bls_public_key,
                &bls_pop,
            )?);

            let acc = AccountManager::create_account(val.address.clone(), val.public_key.clone());
            storage.put_object(&acc)?;
        }
    }

    // === SYNC NATIVE CONSENSUS STATE (CRITICAL FIX) ===
    // Write 'sys:validators' so the Rust Consensus Engine knows who is allowed to mine.
    // Format: Vec<(String, u64)> -> (address, STAKE in whole-AIN).
    // B4: this must carry REAL per-validator stake (not a uniform weight) so the
    // stake-weighted DAG quorum + leader election are meaningful and consistent
    // with qc::ValidatorInfo.stake. Source from v1_validators (already scaled
    // whole-AIN by crypto_qc_validator_info). A floor of 1 guarantees no active
    // validator has zero voting power (total_stake==0 would dead-chain), which
    // holds anyway since MIN_STAKE is 1000 AIN.
    let native_validators: Vec<(String, u64)> = v1_validators
        .iter()
        .map(|v| (v.address.clone(), v.stake.max(1)))
        .collect();

    storage.put(
        "sys:validators",
        &serde_json::to_string(&native_validators)?,
    )?;

    // Versioned validator set carrying full finality identity for QC verification.
    // Shape == Vec<consensus::qc::ValidatorInfo> { address, stake, ed25519_public_key, bls_public_key, bls_pop }.
    let v1_json = serde_json::to_string(&v1_validators)?;
    storage.put("sys:validator_set:v1", &v1_json)?;
    // FROZEN genesis snapshot: never rewritten. The genesis identity (and
    // therefore the vertex-hash domain) is derived from THIS, not from the
    // live set, so a slash/join/stake change followed by a restart can never
    // change a node's domain and brick it out of consensus.
    storage.put("genesis:validator_set:v1", &v1_json)?;
    storage.put("sys:chain_id", &genesis_chain_id)?;

    // SEC-#13: pin the canonical epoch-block interval on-chain. The executor
    // reads THIS deterministically on every node, eliminating the per-node
    // AINCORE_EPOCH_BLOCK_INTERVAL env fork hazard. Folded into the genesis
    // identity hash below so a tampered value is detected at boot.
    storage.put(
        GENESIS_EPOCH_BLOCK_INTERVAL_KEY,
        &genesis_epoch_block_interval.to_string(),
    )?;

    // === GENESIS LOCK: Register the Genesis Validator address ===
    // This address will be PERMANENTLY BLOCKED from transfers (Anti-Rugpull).
    // The Executor checks sys:config:federation_addr before every transfer.
    if let Some((first_addr, _)) = genesis_validators.first() {
        storage.set_federation_key(first_addr)?;
    }

    // AUDIT-#7 FIX: the Move ValidatorSet.total_supply is the emission anchor —
    // staking.move::distribute_rewards mints against `remaining = MAX_SUPPLY -
    // total_supply`. It MUST include every coin already allocated at genesis, or
    // emission treats the pre-allocated treasury as unminted head-room and over-
    // mints by exactly the treasury reserve over the chain's lifetime (a silent
    // ~50k AIN breach of the 150M cap). Seed it with bootstrap stake + treasury
    // so it agrees with sys:total_supply (set below) and the cap actually holds.
    let initial_total_supply = total_bootstrap_stake
        .checked_add(treasury_reserve_amount)
        .ok_or_else(|| {
            GenesisError::InvalidData("genesis stake plus treasury overflows u128".to_string())
        })?;
    let validator_set = ValidatorSet {
        validators: validator_configs,
        unbonding_queue: vec![],
        total_supply: initial_total_supply,
        current_epoch: 0,
    };

    let key = system_resource_key("0x1::staking::ValidatorSet");

    // Serialize to BCS
    let bytes = bcs::to_bytes(&validator_set)?;
    let hex_bytes = hex::encode(bytes);
    storage.put(&key, &hex_bytes)?;

    for (addr, _) in &genesis_validators {
        let move_addr = parse_move_addr(addr)?;
        let coin_store = Coin { value: 0 };
        storage.put(
            &coin_store_key(move_addr),
            &hex::encode(bcs::to_bytes(&coin_store)?),
        )?;
    }

    // === Initialize Epoch ===
    #[derive(serde::Serialize)]
    struct Epoch {
        epoch_number: u64,
        epoch_start_time: u64,
        epoch_duration: u64,
    }
    let epoch = Epoch {
        epoch_number: 0,
        epoch_start_time: 0,
        epoch_duration: genesis_epoch_duration,
    };
    let epoch_key = system_resource_key("0x1::epoch::Epoch");
    let epoch_bytes = bcs::to_bytes(&epoch)?;
    storage.put(&epoch_key, &hex::encode(epoch_bytes))?;

    // === Initialize Governance ===
    #[derive(serde::Serialize)]
    struct Proposal {
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

    #[derive(serde::Serialize)]
    struct GovernanceState {
        proposals: Vec<Proposal>,
        next_proposal_id: u64,
    }

    let gov_state = GovernanceState {
        proposals: vec![],
        next_proposal_id: 0,
    };

    let gov_key = system_resource_key("0x1::governance::GovernanceState");
    let gov_bytes = bcs::to_bytes(&gov_state)?;
    storage.put(&gov_key, &hex::encode(gov_bytes))?;

    // === Initialize Universal Mining (Oracle & DeviceRegistry) ===
    // Mirrors 0x1::universal_mining::VerifiedDevice in BCS field order. The
    // registry holds verified bindings only; registrations live under each
    // owner's address (DeviceClaims), so genesis writes none.
    #[derive(serde::Serialize)]
    struct VerifiedDevice {
        device_pubkey: Vec<u8>,
        owner_addr: move_core_types::account_address::AccountAddress,
        last_reward_epoch: u64,
    }
    #[derive(serde::Serialize)]
    struct DeviceRegistry {
        devices: Vec<VerifiedDevice>,
    }

    #[derive(serde::Serialize)]
    struct Vote {
        feeder: move_core_types::account_address::AccountAddress,
        bqi_score: u64,
    }
    #[derive(serde::Serialize)]
    struct PendingProof {
        device_pubkey: Vec<u8>,
        votes: Vec<Vote>,
        status: u8,
    }
    #[derive(serde::Serialize)]
    struct OracleConfig {
        feeders: Vec<move_core_types::account_address::AccountAddress>,
        threshold: u64,
        active_proofs: Vec<PendingProof>,
    }

    // Initialize DeviceRegistry
    let device_registry = DeviceRegistry { devices: vec![] };
    let dr_key = system_resource_key("0x1::universal_mining::DeviceRegistry");
    let dr_bytes = bcs::to_bytes(&device_registry)?;
    storage.put(&dr_key, &hex::encode(dr_bytes))?;

    // Initialize OracleConfig
    // We add the Genesis Validator (0x1) as the first trusted feeder
    let mut feeders = Vec::new();
    // Since genesis_addr is 0x1 (system), we use it.
    // But wait, the genesis_validators loop uses 32-byte addresses derived from keys.
    // It does NOT use 0x1.
    // 0x1 is the "System Logic" address.
    // The validator addresses are "9b47...".
    // So we should add the first validator to the feeder list.
    if let Some((first_addr, _)) = genesis_validators.first() {
        feeders.push(parse_move_addr(first_addr)?);
    }
    // Also add 0x1 itself if needed (but 0x1 usually doesn't sign transactions).
    // Let's stick to the physical validators.

    let oracle_config = OracleConfig {
        feeders,
        threshold: 1, // Start with 1/1
        active_proofs: vec![],
    };
    let oc_key = system_resource_key("0x1::universal_mining::OracleConfig");
    let oc_bytes = bcs::to_bytes(&oracle_config)?;
    storage.put(&oc_key, &hex::encode(oc_bytes))?;

    // === Initialize Treasury (Bill Acceptor Reserve) ===
    // We simulate a pre-filled "Vending Machine" with 50,000 AIN.
    // This allows the Bill Acceptor to work immediately.
    #[derive(serde::Serialize)]
    struct Treasury {
        reserve: Coin,
        total_sold: u128,
        price_usd_cents: u64,
    }

    let treasury = Treasury {
        reserve: Coin {
            value: treasury_reserve_amount,
        }, // Funded by Genesis File or Fallback
        total_sold: 0,
        price_usd_cents: 100, // $1.00 Start Price
    };
    let treasury_key = system_resource_key("0x1::treasury::Treasury");
    let treasury_bytes = bcs::to_bytes(&treasury)?;
    storage.put(&treasury_key, &hex::encode(&treasury_bytes))?;

    // === Initialize DEX Pool Registry ===
    #[derive(serde::Serialize)]
    struct PoolInfo {
        pool_key: Vec<u8>,
        pool_addr: move_core_types::account_address::AccountAddress,
        token_x_name: Vec<u8>,
        token_y_name: Vec<u8>,
        fee_bp: u64,
        creator: move_core_types::account_address::AccountAddress,
        active: bool,
    }
    #[derive(serde::Serialize)]
    struct PoolRegistry {
        pools: Vec<PoolInfo>,
    }

    let dex_registry = PoolRegistry { pools: vec![] };
    let dex_registry_key = system_resource_key("0x1::dex::PoolRegistry");
    let dex_registry_bytes = bcs::to_bytes(&dex_registry)?;
    storage.put(&dex_registry_key, &hex::encode(dex_registry_bytes))?;

    // === Initialize wBTC Bridge Config ===
    // wbtc::mint asserts exists<BridgeConfig>(@0x1) before it mints, and
    // wbtc::initialize needs a 0x1 signer that no keypair can produce. Without
    // this seed the bridge can never mint, which kills wBTC -- the chain's only
    // non-AIN coin type, and therefore the only asset a DEX pool can pair AIN
    // against. Seeded here for the same reason the DEX PoolRegistry is.
    //
    // The authority comes from genesis.json (validator #1), never from an env
    // var: every node runs this function independently, so an env-sourced value
    // would seed a different authority per node and fork the state root -- the
    // same hazard SEC-#13 closed for the epoch interval. Rotate it afterwards
    // with wbtc::update_authority.
    #[derive(serde::Serialize)]
    struct BridgeConfig {
        authority: AccountAddress,
        total_minted: u128,
        total_burned: u128,
    }

    if let Some((first_addr, _)) = genesis_validators.first() {
        let bridge_config = BridgeConfig {
            authority: parse_move_addr(first_addr)?,
            total_minted: 0,
            total_burned: 0,
        };
        let bridge_key = system_resource_key("0x1::wbtc::BridgeConfig");
        let bridge_bytes = bcs::to_bytes(&bridge_config)?;
        storage.put(&bridge_key, &hex::encode(bridge_bytes))?;
    }

    // === Initialize Token Factory Registry ===
    // create_token, mint, burn, transfer and disable_minting all reach for
    // borrow_global_mut<TokenRegistry>(@0x1), and token_factory::initialize is a
    // `public fun` that likewise needs an unobtainable 0x1 signer. Without this
    // seed every token_factory entry function aborts for the life of the chain.
    #[derive(serde::Serialize)]
    struct TokenInfo {
        token_id: Vec<u8>,
        name: Vec<u8>,
        symbol: Vec<u8>,
        decimals: u8,
        max_supply: u128,
        current_supply: u128,
        creator: AccountAddress,
        is_mintable: bool,
        icon_url: Vec<u8>,
        project_url: Vec<u8>,
    }
    #[derive(serde::Serialize)]
    struct TokenRegistry {
        tokens: Vec<TokenInfo>,
    }

    let token_registry = TokenRegistry { tokens: vec![] };
    let token_registry_key = system_resource_key("0x1::token_factory::TokenRegistry");
    let token_registry_bytes = bcs::to_bytes(&token_registry)?;
    storage.put(&token_registry_key, &hex::encode(token_registry_bytes))?;

    // === FINAL CHECK: SET TOTAL SUPPLY ===
    // Validators (1M) + Treasury (50k)

    storage.put("sys:total_supply", &initial_total_supply.to_string())?;
    storage.put("genesis_stdlib_hash", &stdlib_hash)?;
    storage.put(
        GENESIS_STDLIB_MODULES_KEY,
        &serde_json::to_string(&stdlib_module_keys)?,
    )?;
    storage.put(GENESIS_STDLIB_COUNT_KEY, &stdlib_modules.len().to_string())?;
    storage.put("genesis_version", GENESIS_VERSION)?;

    // FX-7: parameters every node must agree on are seeded here, not left
    // to each reader's default.
    storage.put(
        "sys:config:burn_percentage",
        &genesis_burn_percentage.to_string(),
    )?;
    storage.put(
        "sys:config:tip_agreement_n",
        &genesis_tip_agreement_n.to_string(),
    )?;
    storage.put("total_burned", "0")?;

    storage.finish(
        &stdlib_hash,
        &genesis_chain_id,
        genesis_epoch_block_interval,
    )
}

#[cfg(test)]
mod tests {

    /// G3 KV-2 / FX-9: every system resource key genesis writes is exactly
    /// the canonical encoder's output, so the genesis tree (version 0) and
    /// every later proof use the same key hashes.
    #[test]
    fn genesis_system_resource_keys_match_the_canonical_encoder() {
        use vm_move::state_keys::resource_key_str;
        let one = move_core_types::account_address::AccountAddress::ONE;
        for tag in [
            "0x1::staking::ValidatorSet",
            "0x1::epoch::Epoch",
            "0x1::governance::GovernanceState",
            "0x1::universal_mining::DeviceRegistry",
            "0x1::universal_mining::OracleConfig",
            "0x1::treasury::Treasury",
            "0x1::dex::PoolRegistry",
            "0x1::wbtc::BridgeConfig",
            "0x1::token_factory::TokenRegistry",
        ] {
            assert_eq!(
                super::system_resource_key(tag),
                resource_key_str(&one, tag),
                "{tag}"
            );
        }
    }

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use executor::{Executor, Transaction};
    use move_core_types::{
        identifier::Identifier,
        language_storage::{ModuleId, StructTag, TypeTag},
    };

    #[derive(serde::Serialize, serde::Deserialize)]
    struct TestCoin {
        value: u128,
    }

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = std::env::temp_dir().join(format!(
            "aincore_phase0_genesis_{}_{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        Arc::new(StateDB::open(path.to_str().expect("utf8 temp path")).expect("test DB opens"))
    }

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aincore_phase1_genesis_dir_{}_{}",
            name,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("temp dir created");
        path
    }

    fn stdlib_path() -> String {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../vm_move/stdlib/bytecode")
            .to_string_lossy()
            .to_string()
    }

    /// Seed of the test validators' BLS keys (see `single_validator_genesis`).
    const TEST_NODE_IDENTITY: [u8; 32] = [7u8; 32];

    fn create_account(db: &StateDB, signing_key: &SigningKey) -> String {
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());
        let address = crypto::derive_address(public_key.as_bytes()).expect("canonical address");
        let object = aa::AccountManager::create_account(address.clone(), public_key_hex);
        let _seed = db.seeding();
        db.put_object(&object).expect("account object stored");
        address
    }

    fn set_coin_store(db: &StateDB, address: &str, value: u128) {
        let move_addr = parse_move_addr(address).expect("valid move address");
        let bytes = bcs::to_bytes(&TestCoin { value }).expect("coin store BCS");
        let _seed = db.seeding();
        db.put(&coin_store_key(move_addr), &hex::encode(bytes))
            .expect("coin store stored");
    }

    fn coin_balance(db: &StateDB, address: &str) -> u128 {
        let move_addr = parse_move_addr(address).expect("valid move address");
        let value = db
            .get(&coin_store_key(move_addr))
            .expect("coin store read")
            .expect("coin store exists");
        let bytes = hex::decode(value).expect("coin store hex");
        bcs::from_bytes::<TestCoin>(&bytes)
            .expect("coin store BCS")
            .value
    }

    fn apply_updates(db: &StateDB, updates: Vec<(String, Option<String>)>) {
        for (key, value) in updates {
            if let Some(value) = value {
                let _seed = db.seeding();
                db.put(&key, &value).expect("update put");
            } else {
                db.delete(&key).expect("update delete");
            }
        }
    }

    fn aincore_coin_type_for_payload() -> TypeTag {
        TypeTag::Struct(Box::new(StructTag {
            address: system_address(),
            module: Identifier::new("staking").expect("valid module"),
            name: Identifier::new("AincoreCoin").expect("valid struct"),
            type_params: vec![],
        }))
    }

    fn transfer_payload(sender: &str, recipient: &str, amount: u128) -> String {
        let call = vm_move::EntryFunctionCall {
            module: ModuleId::new(
                system_address(),
                Identifier::new("coin").expect("valid module"),
            ),
            function: "transfer".to_string(),
            ty_args: vec![aincore_coin_type_for_payload()],
            args: vec![
                bcs::to_bytes(&parse_move_addr(sender).expect("sender address")).unwrap(),
                bcs::to_bytes(&parse_move_addr(recipient).expect("recipient address")).unwrap(),
                bcs::to_bytes(&amount).unwrap(),
            ],
        };
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
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
    fn test_genesis_validator_public_key_must_match_address() {
        let genesis_key = SigningKey::from_bytes(&[19u8; 32]);
        let wrong_addr = "00000000000000000000000000000001";
        let public_key = hex::encode(genesis_key.verifying_key().as_bytes());

        let err = parse_validator_public_key(&public_key, wrong_addr)
            .expect_err("mismatched validator address must fail");
        assert!(
            err.to_string().contains("address/public_key mismatch"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_validator_public_key_must_be_32_bytes() {
        let err = parse_validator_public_key("abcd", "00000000000000000000000000000001")
            .expect_err("short public key must fail");
        assert!(
            err.to_string().contains("public key length"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_amount_parse_is_strict() {
        let err = parse_genesis_amount("not-a-number", "validator stake")
            .expect_err("invalid amount must fail");
        assert!(
            err.to_string()
                .contains("Invalid genesis validator stake amount"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_fresh_genesis_rejects_empty_stdlib_dir() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("empty_stdlib");
        let empty_stdlib = temp_dir("empty_stdlib");
        let genesis_key = SigningKey::from_bytes(&[20u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        let err = init_genesis_with(
            &db,
            empty_stdlib.to_str().expect("utf8 temp path"),
            &genesis_addr,
            &genesis_pubkey,
        )
        .expect_err("empty stdlib bytecode dir must fail");
        assert!(
            err.to_string().contains("no .mv modules"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_fresh_genesis_reopen_and_corrupt_marker_fail_fast() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("integrity");
        let genesis_key = SigningKey::from_bytes(&[21u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        init_genesis(&db, &genesis_addr, &genesis_pubkey).expect("fresh genesis initializes");
        init_genesis(&db, &genesis_addr, &genesis_pubkey).expect("valid genesis reopens");

        let _seed = db.seeding();
        db.delete("module_0000000000000000000000000000000000000000000000000000000000000001_signer")
            .expect("corrupt stdlib delete");
        let err = init_genesis(&db, &genesis_addr, &genesis_pubkey)
            .expect_err("corrupt stdlib marker must fail fast");
        assert!(
            err.to_string().contains("required Move module is missing"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_reopen_rejects_corrupt_module_bytes() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("corrupt_module_bytes");
        let genesis_key = SigningKey::from_bytes(&[25u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        init_genesis(&db, &genesis_addr, &genesis_pubkey).expect("fresh genesis initializes");

        let _seed = db.seeding();
        db.put(
            "module_0000000000000000000000000000000000000000000000000000000000000001_signer",
            "00",
        )
        .expect("corrupt module bytes");
        let err = init_genesis(&db, &genesis_addr, &genesis_pubkey)
            .expect_err("corrupt module bytes must fail fast");
        assert!(
            err.to_string().contains("failed bytecode decode"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_reopen_rejects_stdlib_hash_mismatch() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("stdlib_hash_mismatch");
        let genesis_key = SigningKey::from_bytes(&[26u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        init_genesis(&db, &genesis_addr, &genesis_pubkey).expect("fresh genesis initializes");

        db.put("genesis_stdlib_hash", "deadbeef")
            .expect("corrupt stdlib hash marker");
        let err = init_genesis(&db, &genesis_addr, &genesis_pubkey)
            .expect_err("hash mismatch must fail fast");
        assert!(
            err.to_string().contains("Genesis stdlib hash mismatch"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_reopen_rejects_module_key_id_mismatch() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("module_key_id_mismatch");
        let genesis_key = SigningKey::from_bytes(&[27u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        init_genesis(&db, &genesis_addr, &genesis_pubkey).expect("fresh genesis initializes");

        let coin_bytes = db
            .get("module_0000000000000000000000000000000000000000000000000000000000000001_coin")
            .expect("coin read")
            .expect("coin exists");
        let _seed = db.seeding();
        db.put(
            "module_0000000000000000000000000000000000000000000000000000000000000001_signer",
            &coin_bytes,
        )
        .expect("swap module bytes under signer key");
        let err = init_genesis(&db, &genesis_addr, &genesis_pubkey)
            .expect_err("module key/id mismatch must fail fast");
        assert!(
            err.to_string().contains("key/id mismatch"),
            "unexpected error: {}",
            err
        );
    }

    // === B1 tests ===

    use std::sync::Mutex as StdMutex;
    /// Serializes tests that mutate the process-global AINCORE_GENESIS_PATH env.
    static GENESIS_ENV_LOCK: StdMutex<()> = StdMutex::new(());

    /// BCS mirror of the staking ValidatorSet WITH the new BLS fields, for tests
    /// that decode the freshly-written genesis resource (proves field-order lockstep).
    #[derive(serde::Deserialize)]
    struct TestCoinU128 {
        #[allow(dead_code)]
        value: u128,
    }
    #[derive(serde::Deserialize)]
    struct TestValidatorConfig {
        #[allow(dead_code)]
        validator_addr: AccountAddress,
        #[allow(dead_code)]
        stake: TestCoinU128,
        #[allow(dead_code)]
        public_key: Vec<u8>,
        bls_public_key: Vec<u8>,
        bls_pop: Vec<u8>,
    }
    #[derive(serde::Deserialize)]
    struct TestUnbondingRequest {
        #[allow(dead_code)]
        validator_addr: AccountAddress,
        #[allow(dead_code)]
        stake: u128,
        #[allow(dead_code)]
        unlock_time: u64,
    }
    #[derive(serde::Deserialize)]
    struct TestValidatorSet {
        validators: Vec<TestValidatorConfig>,
        #[allow(dead_code)]
        unbonding_queue: Vec<TestUnbondingRequest>,
        #[allow(dead_code)]
        total_supply: u128,
        #[allow(dead_code)]
        current_epoch: u64,
    }

    fn decode_staking_validator_set(db: &StateDB) -> TestValidatorSet {
        let key = system_resource_key("0x1::staking::ValidatorSet");
        let hex_val = db
            .get(&key)
            .expect("read staking resource")
            .expect("staking resource exists");
        let bytes = hex::decode(hex_val).expect("staking resource hex");
        bcs::from_bytes::<TestValidatorSet>(&bytes)
            .expect("slow-path ValidatorSet BCS decode must succeed on fresh genesis")
    }

    /// Write a genesis.json with a single validator (optionally carrying BLS keys)
    /// and return its path. Caller holds GENESIS_ENV_LOCK.
    fn write_genesis_json(
        name: &str,
        addr: &str,
        pubkey: &str,
        bls_pk_hex: Option<&str>,
        bls_pop_hex: Option<&str>,
    ) -> PathBuf {
        let dir = temp_dir(&format!("gjson_{}", name));
        let path = dir.join("genesis.json");
        let bls_fields = match (bls_pk_hex, bls_pop_hex) {
            (Some(pk), Some(pop)) => {
                format!(",\"bls_public_key\":\"{}\",\"bls_pop\":\"{}\"", pk, pop)
            }
            _ => String::new(),
        };
        let json = format!(
            "{{\"chain_id\":\"AINCORE-MAINNET-1\",\"validators\":[{{\"address\":\"{}\",\"public_key\":\"{}\",\"stake\":\"1000000000000000000000\"{}}}],\"treasury_reserve\":\"0\",\"epoch_duration\":10,\"stdlib_hash\":\"{}\"}}",
            addr, pubkey, bls_fields, test_stdlib_hash()
        );
        fs::write(&path, json).expect("write genesis.json");
        path
    }

    /// The test stdlib's hash, which every test genesis.json pins (FX-7).
    fn test_stdlib_hash() -> String {
        static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        HASH.get_or_init(|| stdlib_hash_of(&stdlib_path()).expect("hash the test stdlib"))
            .clone()
    }

    /// G3 FX-7: a single-validator genesis.json for `(addr, pubkey)`, with
    /// explicit BLS keys derived from `TEST_NODE_IDENTITY` the way
    /// genesis-tool derives them. Every call gets its own file.
    fn single_validator_genesis(addr: &str, pubkey: &str) -> PathBuf {
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let seed = consensus::qc::derive_validator_bls_seed(&TEST_NODE_IDENTITY);
        let bls = crypto::bls::BLSEngine::consensus();
        write_genesis_json(
            &format!("single_{n}"),
            addr,
            pubkey,
            Some(&hex::encode(bls.pubkey_raw(&seed))),
            Some(&hex::encode(bls.prove_possession_raw(&seed))),
        )
    }

    /// Initialize (or reopen) `db` from a single-validator genesis.
    fn init_genesis(db: &Arc<StateDB>, addr: &str, pubkey: &str) -> Result<(), GenesisError> {
        init_genesis_with(db, &stdlib_path(), addr, pubkey)
    }

    fn init_genesis_with(
        db: &Arc<StateDB>,
        stdlib: &str,
        addr: &str,
        pubkey: &str,
    ) -> Result<(), GenesisError> {
        initialize_genesis_from(db, stdlib, &single_validator_genesis(addr, pubkey))
    }

    /// G3 FX-7: every validator needs explicit BLS keys. Genesis used to
    /// derive a missing pair from the booting node's own key, which made
    /// genesis state depend on which node built it.
    #[test]
    fn a_validator_without_bls_keys_is_refused() {
        let key = SigningKey::from_bytes(&[45u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());
        let path = write_genesis_json("no_bls", &addr, &pubkey, None, None);
        let err = initialize_genesis_from(&temp_db("no_bls"), &stdlib_path(), &path)
            .expect_err("a validator without BLS keys is refused");
        assert!(
            err.to_string()
                .contains("must supply both bls_public_key and bls_pop"),
            "{err}"
        );
    }

    #[test]
    fn test_genesis_loads_bls_keys() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let validator_key = SigningKey::from_bytes(&[41u8; 32]);
        let addr = crypto::derive_address(validator_key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(validator_key.verifying_key().as_bytes());

        // Generate a real BLS identity for the operator-supplied path.
        let bls = crypto::bls::BLSEngine::consensus();
        let bls_seed = [42u8; 32];
        let bls_pk = bls.pubkey_raw(&bls_seed);
        let bls_pop = bls.prove_possession_raw(&bls_seed);

        let path = write_genesis_json(
            "loads_bls",
            &addr,
            &pubkey,
            Some(&hex::encode(&bls_pk)),
            Some(&hex::encode(&bls_pop)),
        );
        let db = temp_db("loads_bls");
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        res.expect("genesis with valid BLS keys initializes");

        let set = decode_staking_validator_set(&db);
        assert_eq!(set.validators.len(), 1);
        let v = &set.validators[0];
        assert_eq!(
            v.bls_public_key, bls_pk,
            "operator BLS pubkey must be stored verbatim"
        );
        assert_eq!(v.bls_pop, bls_pop);
        assert_eq!(v.bls_public_key.len(), 48);
        assert_eq!(v.bls_pop.len(), 96);
        assert!(bls
            .verify_possession(&v.bls_public_key, &v.bls_pop)
            .unwrap());
    }

    #[test]
    fn test_genesis_rejects_bad_pop() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let validator_key = SigningKey::from_bytes(&[43u8; 32]);
        let addr = crypto::derive_address(validator_key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(validator_key.verifying_key().as_bytes());

        let bls = crypto::bls::BLSEngine::consensus();
        let pk = bls.pubkey_raw(&[44u8; 32]);
        let bad_pop = bls.prove_possession_raw(&[200u8; 32]); // PoP from a DIFFERENT seed

        let path = write_genesis_json(
            "bad_pop",
            &addr,
            &pubkey,
            Some(&hex::encode(&pk)),
            Some(&hex::encode(&bad_pop)),
        );
        let db = temp_db("bad_pop");
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        let err = res.expect_err("genesis with mismatched bls_pop must be rejected");
        assert!(
            err.to_string().contains("proof-of-possession"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_validator_set_v1_roundtrip() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let validator_key = SigningKey::from_bytes(&[45u8; 32]);
        let addr = crypto::derive_address(validator_key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(validator_key.verifying_key().as_bytes());

        // Known BLS seed so we can sign a vote for the QC round-trip.
        let bls = crypto::bls::BLSEngine::consensus();
        let bls_seed = [70u8; 32];
        let bls_pk = bls.pubkey_raw(&bls_seed);
        let bls_pop = bls.prove_possession_raw(&bls_seed);

        let path = write_genesis_json(
            "v1_roundtrip",
            &addr,
            &pubkey,
            Some(&hex::encode(&bls_pk)),
            Some(&hex::encode(&bls_pop)),
        );
        let db = temp_db("v1_roundtrip");
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        res.expect("genesis initializes");

        let json = db
            .get("sys:validator_set:v1")
            .expect("read v1")
            .expect("v1 exists");
        let set: Vec<consensus::qc::ValidatorInfo> =
            serde_json::from_str(&json).expect("v1 decodes into qc::ValidatorInfo");
        assert_eq!(set.len(), 1);
        let v = &set[0];
        assert_eq!(v.address, addr);
        assert_eq!(v.ed25519_public_key, pubkey);
        // genesis.json stake = 1000 AIN (10^21 quanta) -> 1000 whole-AIN u64.
        assert_eq!(v.stake, 1000);
        let pk = hex::decode(&v.bls_public_key).unwrap();
        let pop = hex::decode(&v.bls_pop).unwrap();
        assert_eq!(pk, bls_pk);
        assert_eq!(pop, bls_pop);
        assert!(bls.verify_possession(&pk, &pop).unwrap());

        // Feed the v1 set into a real build_qc/verify_qc to prove the shape works.
        let vote = consensus::qc::FinalityVote {
            chain_id: "AINCORE-MAINNET-1".into(),
            epoch: 0,
            finalized_round: 1,
            anchor_round: 0,
            anchor_hash: "aa".repeat(32),
            block_height: 1,
            block_hash: "bb".repeat(32),
            state_root: "cc".repeat(32),
            receipts_root: "dd".repeat(32),
            finality_digest: "ee".repeat(32),
            // Must equal validator_set_hash(set): verify_qc binds the QC to the
            // exact validator set (the #7 binding). A dummy hash would be rejected.
            validator_set_hash: consensus::qc::validator_set_hash(&set),
        };
        let sig = bls.sign_raw(&vote.to_signing_bytes(), &bls_seed);
        let qc = consensus::qc::build_qc(&vote, &set, &[0], &[sig]).expect("build qc");
        assert!(
            consensus::qc::verify_qc(&qc, &set, &qc.chain_id).is_ok(),
            "1-of-1 QC over the genesis v1 set must verify"
        );
    }

    #[test]
    fn test_stake_scaling_no_truncation() {
        // Whole-AIN scaling must not lose value vs the u128 genesis stake.
        let one_million_ain: u128 = 1_000_000u128 * 1_000_000_000_000_000_000;
        let scaled = scale_stake_to_whole_ain(one_million_ain).expect("scale ok");
        assert_eq!(scaled, 1_000_000);
        assert_eq!(scaled as u128 * 1_000_000_000_000_000_000, one_million_ain);
        // An overflowing stake (> u64 whole-AIN) must be rejected, not truncated.
        let absurd = u128::MAX;
        assert!(scale_stake_to_whole_ain(absurd).is_err());
    }

    #[test]
    fn test_fresh_genesis_then_executor_accepts_bcs_transfer_path() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("transfer");
        let genesis_key = SigningKey::from_bytes(&[22u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        init_genesis(&db, &genesis_addr, &genesis_pubkey).expect("fresh genesis initializes");

        let sender_key = SigningKey::from_bytes(&[23u8; 32]);
        let recipient_key = SigningKey::from_bytes(&[24u8; 32]);
        let sender = create_account(&db, &sender_key);
        let recipient = create_account(&db, &recipient_key);
        set_coin_store(&db, &sender, 1_000_000);
        set_coin_store(&db, &recipient, 0);

        let payload = transfer_payload(&sender, &recipient, 250);
        let executor = Executor::new(db.clone());
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&sender_key, &sender, &payload, 0, 100_000, 1))
            .expect("BCS transfer accepted after fresh genesis");
        assert_eq!(gas, 100_000);
        apply_updates(&db, updates);

        assert_eq!(coin_balance(&db, &sender), 899_750);
        assert_eq!(coin_balance(&db, &recipient), 250);
    }

    fn entry_payload(
        module: &str,
        function: &str,
        ty_args: Vec<TypeTag>,
        args: Vec<Vec<u8>>,
    ) -> String {
        let call = vm_move::EntryFunctionCall {
            module: ModuleId::new(
                system_address(),
                Identifier::new(module).expect("valid module"),
            ),
            function: function.to_string(),
            ty_args,
            args,
        };
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::EntryFunction(call)).unwrap())
    }

    fn wbtc_store_key(address: &str) -> String {
        let wbtc = StructTag {
            address: system_address(),
            module: Identifier::new("wbtc").expect("valid module"),
            name: Identifier::new("WBTC").expect("valid struct"),
            type_params: vec![],
        };
        let tag = StructTag {
            address: system_address(),
            module: Identifier::new("coin").expect("valid module"),
            name: Identifier::new("CoinStore").expect("valid struct"),
            type_params: vec![TypeTag::Struct(Box::new(wbtc))],
        };
        format!(
            "resource_{}_{}",
            parse_move_addr(address).expect("valid move address"),
            tag
        )
    }

    fn wbtc_balance(db: &StateDB, address: &str) -> u128 {
        let value = db
            .get(&wbtc_store_key(address))
            .expect("wbtc store read")
            .expect("wbtc store exists");
        bcs::from_bytes::<TestCoin>(&hex::decode(value).expect("wbtc store hex"))
            .expect("wbtc store BCS")
            .value
    }

    #[derive(serde::Deserialize)]
    struct DecodedBridgeConfig {
        authority: AccountAddress,
        total_minted: u128,
        total_burned: u128,
    }

    #[derive(serde::Deserialize)]
    struct DecodedTokenRegistry {
        tokens: Vec<Vec<u8>>,
    }

    /// AincoreCoin and WBTC are the only two coin types this chain defines, so
    /// WBTC is the only asset a DEX pool can pair AIN against. wbtc::mint refuses
    /// to run unless BridgeConfig lives at @0x1, and wbtc::initialize requires a
    /// 0x1 signer that no keypair can produce -- so if genesis does not seed the
    /// resource, wBTC is unmintable for the life of the chain and no pool can ever
    /// hold liquidity. Mint through the real executor path here, not just a read:
    /// a correct-looking resource that the VM cannot decode would still be dead.
    #[test]
    fn test_fresh_genesis_enables_wbtc_mint() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("wbtc_mint");
        let authority_key = SigningKey::from_bytes(&[31u8; 32]);
        let authority = crypto::derive_address(authority_key.verifying_key().as_bytes()).unwrap();
        let authority_pubkey = hex::encode(authority_key.verifying_key().as_bytes());

        // Pin the validator set to this key: the seeded bridge authority is
        // genesis validator #1, and the test has to hold that key to sign a mint.
        let path = single_validator_genesis(&authority, &authority_pubkey);
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        res.expect("fresh genesis initializes");

        let raw = db
            .get(&system_resource_key("0x1::wbtc::BridgeConfig"))
            .expect("storage read")
            .expect("genesis seeds wbtc::BridgeConfig");
        let cfg: DecodedBridgeConfig = bcs::from_bytes(&hex::decode(raw).expect("hex"))
            .expect("BridgeConfig decodes in Move field order");
        assert_eq!(cfg.authority, parse_move_addr(&authority).unwrap());
        assert_eq!(cfg.total_minted, 0);
        assert_eq!(cfg.total_burned, 0);

        let holder_key = SigningKey::from_bytes(&[32u8; 32]);
        let holder = create_account(&db, &holder_key);
        set_coin_store(&db, &holder, 1_000_000);
        create_account(&db, &authority_key);
        set_coin_store(&db, &authority, 1_000_000);

        let executor = Executor::new(db.clone());

        // The signer slot is supplied as an explicit address argument, the same
        // way transfer_payload passes `sender` for coin::transfer(from: &signer).
        let register = entry_payload(
            "wbtc",
            "register",
            vec![],
            vec![bcs::to_bytes(&parse_move_addr(&holder).unwrap()).unwrap()],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&holder_key, &holder, &register, 0, 100_000, 1))
            .expect("holder registers a WBTC store");
        apply_updates(&db, updates);

        let mint = entry_payload(
            "wbtc",
            "mint",
            vec![],
            vec![
                bcs::to_bytes(&parse_move_addr(&authority).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&holder).unwrap()).unwrap(),
                bcs::to_bytes(&5_000u128).unwrap(),
            ],
        );
        let (updates, _) = executor
            .execute_transaction(&signed_tx(&authority_key, &authority, &mint, 0, 100_000, 1))
            .expect("bridge authority mints wBTC through the seeded BridgeConfig");
        apply_updates(&db, updates);

        assert_eq!(wbtc_balance(&db, &holder), 5_000);
    }

    /// Every token_factory entry function reaches for TokenRegistry at @0x1 and
    /// its initialize() is a `public fun` needing the same unobtainable 0x1
    /// signer, so an unseeded registry means create_token aborts forever.
    #[test]
    fn test_fresh_genesis_seeds_token_registry() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("token_registry");
        let key = SigningKey::from_bytes(&[33u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        let path = single_validator_genesis(&addr, &pubkey);
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        res.expect("fresh genesis initializes");

        let raw = db
            .get(&system_resource_key("0x1::token_factory::TokenRegistry"))
            .expect("storage read")
            .expect("genesis seeds token_factory::TokenRegistry");
        let bytes = hex::decode(raw).expect("hex");
        // An empty Move vector is a single uleb128 zero, so the element type does
        // not matter for this decode -- only that the registry is present, empty,
        // and consumes the whole value with nothing trailing.
        assert_eq!(bytes, vec![0u8]);
        let registry: DecodedTokenRegistry =
            bcs::from_bytes(&bytes).expect("TokenRegistry decodes as an empty vector");
        assert!(registry.tokens.is_empty());
    }

    // ===== DEX: first on-chain exercise of 0x1::dex =====

    fn wbtc_type_tag() -> StructTag {
        StructTag {
            address: system_address(),
            module: Identifier::new("wbtc").expect("valid module"),
            name: Identifier::new("WBTC").expect("valid struct"),
            type_params: vec![],
        }
    }

    fn ain_type_tag() -> StructTag {
        StructTag {
            address: system_address(),
            module: Identifier::new("staking").expect("valid module"),
            name: Identifier::new("AincoreCoin").expect("valid struct"),
            type_params: vec![],
        }
    }

    /// dex::canonical_token_names asserts the pair is in lexicographic order of
    /// the full type name, and "staking::AincoreCoin" sorts before "wbtc::WBTC",
    /// so AIN is always X and wBTC always Y. Creating the pool the other way
    /// round aborts on EINVALID_PAIR.
    fn dex_pair_ty_args() -> Vec<TypeTag> {
        vec![
            TypeTag::Struct(Box::new(ain_type_tag())),
            TypeTag::Struct(Box::new(wbtc_type_tag())),
        ]
    }

    fn dex_resource_key(name: &str, pool_addr: &str) -> String {
        let tag = StructTag {
            address: system_address(),
            module: Identifier::new("dex").expect("valid module"),
            name: Identifier::new(name).expect("valid struct"),
            type_params: dex_pair_ty_args(),
        };
        format!(
            "resource_{}_{}",
            parse_move_addr(pool_addr).expect("valid move address"),
            tag
        )
    }

    #[derive(serde::Deserialize)]
    struct DecodedPool {
        coin_x: TestCoin,
        coin_y: TestCoin,
        lp_supply: u128,
        fee_bp: u64,
    }

    #[derive(serde::Deserialize)]
    struct DecodedLpToken {
        balance: u128,
    }

    fn read_pool(db: &StateDB, pool_addr: &str) -> DecodedPool {
        let raw = db
            .get(&dex_resource_key("LiquidityPool", pool_addr))
            .expect("pool read")
            .expect("pool resource exists");
        bcs::from_bytes(&hex::decode(raw).expect("pool hex")).expect("pool BCS")
    }

    /// Independent restatement of dex.move's quote_out. If the Move code and this
    /// disagree, one of them is wrong -- which is the point of asserting against
    /// it rather than against a number copied out of a previous run.
    fn reference_quote_out(
        amount_in: u128,
        reserve_in: u128,
        reserve_out: u128,
        fee_bp: u64,
    ) -> u128 {
        let fee_multiplier = 10_000u128 - fee_bp as u128;
        let amount_in_with_fee = amount_in * fee_multiplier;
        let numerator = amount_in_with_fee * reserve_out;
        let denominator = (reserve_in * 10_000) + amount_in_with_fee;
        numerator / denominator
    }

    fn integer_sqrt(y: u128) -> u128 {
        if y < 4 {
            return if y == 0 { 0 } else { 1 };
        }
        let mut z = y;
        let mut x = y / 2 + 1;
        while x < z {
            z = x;
            x = (y / x + x) / 2;
        }
        z
    }

    fn send(
        db: &StateDB,
        executor: &Executor,
        key: &SigningKey,
        addr: &str,
        payload: &str,
        seq: u64,
    ) {
        let (updates, _) = executor
            .execute_transaction(&signed_tx(key, addr, payload, seq, 100_000, 1))
            .unwrap_or_else(|| panic!("tx seq {} for {} was rejected outright", seq, addr));
        apply_updates(db, updates);
    }

    /// 0x1::dex had never executed once on any running chain. Drive the whole
    /// lifecycle -- create_pool, add_liquidity, swap -- against the real executor
    /// and check the results against an independent implementation of the CPMM
    /// formulas, so a wrong constant or a swapped operand cannot pass.
    #[test]
    fn test_dex_pool_lifecycle_on_fresh_genesis() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("dex_lifecycle");
        let authority_key = SigningKey::from_bytes(&[51u8; 32]);
        let authority = crypto::derive_address(authority_key.verifying_key().as_bytes()).unwrap();
        let authority_pubkey = hex::encode(authority_key.verifying_key().as_bytes());

        let path = single_validator_genesis(&authority, &authority_pubkey);
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        res.expect("fresh genesis initializes");

        let lp_key = SigningKey::from_bytes(&[52u8; 32]);
        let trader_key = SigningKey::from_bytes(&[53u8; 32]);
        let lp = create_account(&db, &lp_key);
        let trader = create_account(&db, &trader_key);
        create_account(&db, &authority_key);

        // Gas is charged at the full gas_limit per transaction, so fund AIN well
        // clear of both the deposits and the gas the flow below burns.
        set_coin_store(&db, &lp, 50_000_000);
        set_coin_store(&db, &trader, 50_000_000);
        set_coin_store(&db, &authority, 10_000_000);

        let executor = Executor::new(db.clone());

        // Both sides need a WBTC store before they can hold any.
        let reg_lp = entry_payload(
            "wbtc",
            "register",
            vec![],
            vec![bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap()],
        );
        send(&db, &executor, &lp_key, &lp, &reg_lp, 0);
        let reg_trader = entry_payload(
            "wbtc",
            "register",
            vec![],
            vec![bcs::to_bytes(&parse_move_addr(&trader).unwrap()).unwrap()],
        );
        send(&db, &executor, &trader_key, &trader, &reg_trader, 0);

        let seed_wbtc = entry_payload(
            "wbtc",
            "mint",
            vec![],
            vec![
                bcs::to_bytes(&parse_move_addr(&authority).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&4_000_000u128).unwrap(),
            ],
        );
        send(&db, &executor, &authority_key, &authority, &seed_wbtc, 0);
        assert_eq!(wbtc_balance(&db, &lp), 4_000_000);

        // create_pool: the pool lives at the creator's address.
        let create = entry_payload(
            "dex",
            "create_pool",
            dex_pair_ty_args(),
            vec![bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap()],
        );
        send(&db, &executor, &lp_key, &lp, &create, 1);
        let pool = read_pool(&db, &lp);
        assert_eq!(pool.coin_x.value, 0);
        assert_eq!(pool.coin_y.value, 0);
        assert_eq!(pool.lp_supply, 0);
        assert_eq!(
            pool.fee_bp, 30,
            "fee must be the fixed 30 bp the UI is told to expect"
        );

        // add_liquidity: first deposit locks MINIMUM_LIQUIDITY forever.
        let (dep_x, dep_y) = (1_000_000u128, 4_000_000u128);
        let add = entry_payload(
            "dex",
            "add_liquidity",
            dex_pair_ty_args(),
            vec![
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&dep_x).unwrap(),
                bcs::to_bytes(&dep_y).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
            ],
        );
        send(&db, &executor, &lp_key, &lp, &add, 2);

        let expected_minted = integer_sqrt(dep_x * dep_y) - 1000;
        let pool = read_pool(&db, &lp);
        assert_eq!(pool.coin_x.value, dep_x);
        assert_eq!(pool.coin_y.value, dep_y);
        assert_eq!(
            pool.lp_supply,
            expected_minted + 1000,
            "lp_supply must be the minted amount plus the locked minimum, written once"
        );

        let lp_raw = db
            .get(&dex_resource_key("LPToken", &lp))
            .expect("lp token read")
            .expect("lp token exists");
        let lp_token: DecodedLpToken =
            bcs::from_bytes(&hex::decode(lp_raw).expect("hex")).expect("LPToken BCS");
        assert_eq!(
            lp_token.balance, expected_minted,
            "the locked minimum must NOT be credited to the depositor"
        );
        assert_eq!(wbtc_balance(&db, &lp), 4_000_000 - dep_y);

        // swap: trader sells AIN for wBTC.
        let amount_in = 10_000u128;
        let expected_out = reference_quote_out(amount_in, dep_x, dep_y, 30);
        assert!(expected_out > 0, "test setup must produce a non-zero quote");

        let swap = entry_payload(
            "dex",
            "swap_x_to_y",
            dex_pair_ty_args(),
            vec![
                bcs::to_bytes(&parse_move_addr(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&amount_in).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
            ],
        );
        send(&db, &executor, &trader_key, &trader, &swap, 1);

        assert_eq!(
            wbtc_balance(&db, &trader),
            expected_out,
            "swap output must match the CPMM quote including the 30 bp fee"
        );

        let after = read_pool(&db, &lp);
        assert_eq!(after.coin_x.value, dep_x + amount_in);
        assert_eq!(after.coin_y.value, dep_y - expected_out);
        assert_eq!(after.lp_supply, pool.lp_supply, "a swap must not mint LP");
        assert!(
            after.coin_x.value * after.coin_y.value > dep_x * dep_y,
            "the fee must leave the invariant strictly larger after a swap"
        );
    }

    /// coin::register used to abort when the store already existed, which was a
    /// trap: no RPC can tell "registered with zero" apart from "not registered",
    /// so every client had to guess, and guessing wrong cost a failed tx either
    /// way. It is idempotent now -- and the property that actually matters is
    /// that a second register does not wipe the balance already sitting there.
    #[test]
    fn test_coin_register_is_idempotent_and_preserves_balance() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("register_idempotent");
        let authority_key = SigningKey::from_bytes(&[71u8; 32]);
        let authority = crypto::derive_address(authority_key.verifying_key().as_bytes()).unwrap();
        let authority_pubkey = hex::encode(authority_key.verifying_key().as_bytes());

        let path = single_validator_genesis(&authority, &authority_pubkey);
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        res.expect("fresh genesis initializes");

        let holder_key = SigningKey::from_bytes(&[72u8; 32]);
        let holder = create_account(&db, &holder_key);
        set_coin_store(&db, &holder, 10_000_000);
        create_account(&db, &authority_key);
        set_coin_store(&db, &authority, 10_000_000);

        let executor = Executor::new(db.clone());
        let reg = entry_payload(
            "wbtc",
            "register",
            vec![],
            vec![bcs::to_bytes(&parse_move_addr(&holder).unwrap()).unwrap()],
        );

        send(&db, &executor, &holder_key, &holder, &reg, 0);
        assert_eq!(wbtc_balance(&db, &holder), 0);

        let mint = entry_payload(
            "wbtc",
            "mint",
            vec![],
            vec![
                bcs::to_bytes(&parse_move_addr(&authority).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&holder).unwrap()).unwrap(),
                bcs::to_bytes(&7_777u128).unwrap(),
            ],
        );
        send(&db, &executor, &authority_key, &authority, &mint, 0);
        assert_eq!(wbtc_balance(&db, &holder), 7_777);

        // Register a second time on a funded store. Must succeed, and must leave
        // the balance completely alone.
        send(&db, &executor, &holder_key, &holder, &reg, 1);
        assert_eq!(
            wbtc_balance(&db, &holder),
            7_777,
            "a repeat register must never overwrite a funded store"
        );

        // And a third time, so the client can call it unconditionally forever.
        send(&db, &executor, &holder_key, &holder, &reg, 2);
        assert_eq!(wbtc_balance(&db, &holder), 7_777);
    }

    /// A swap whose min_y_out cannot be met must abort cleanly: the trader keeps
    /// their input and the pool is untouched. This is the "slippage protection
    /// actually protects" case the DEX UI depends on.
    #[test]
    fn test_dex_swap_respects_min_out_and_refunds_nothing_but_gas() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("dex_minout");
        let authority_key = SigningKey::from_bytes(&[61u8; 32]);
        let authority = crypto::derive_address(authority_key.verifying_key().as_bytes()).unwrap();
        let authority_pubkey = hex::encode(authority_key.verifying_key().as_bytes());

        let path = single_validator_genesis(&authority, &authority_pubkey);
        let res = initialize_genesis_from(&db, &stdlib_path(), &path);
        res.expect("fresh genesis initializes");

        let lp_key = SigningKey::from_bytes(&[62u8; 32]);
        let trader_key = SigningKey::from_bytes(&[63u8; 32]);
        let lp = create_account(&db, &lp_key);
        let trader = create_account(&db, &trader_key);
        create_account(&db, &authority_key);
        set_coin_store(&db, &lp, 50_000_000);
        set_coin_store(&db, &trader, 50_000_000);
        set_coin_store(&db, &authority, 10_000_000);

        let executor = Executor::new(db.clone());
        for (key, addr) in [(&lp_key, &lp), (&trader_key, &trader)] {
            let reg = entry_payload(
                "wbtc",
                "register",
                vec![],
                vec![bcs::to_bytes(&parse_move_addr(addr).unwrap()).unwrap()],
            );
            send(&db, &executor, key, addr, &reg, 0);
        }
        let seed = entry_payload(
            "wbtc",
            "mint",
            vec![],
            vec![
                bcs::to_bytes(&parse_move_addr(&authority).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&4_000_000u128).unwrap(),
            ],
        );
        send(&db, &executor, &authority_key, &authority, &seed, 0);

        let create = entry_payload(
            "dex",
            "create_pool",
            dex_pair_ty_args(),
            vec![bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap()],
        );
        send(&db, &executor, &lp_key, &lp, &create, 1);
        let add = entry_payload(
            "dex",
            "add_liquidity",
            dex_pair_ty_args(),
            vec![
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&1_000_000u128).unwrap(),
                bcs::to_bytes(&4_000_000u128).unwrap(),
                bcs::to_bytes(&0u128).unwrap(),
            ],
        );
        send(&db, &executor, &lp_key, &lp, &add, 2);

        let before = read_pool(&db, &lp);
        let trader_ain_before = coin_balance(&db, &trader);

        // Demand far more output than the curve can give.
        let swap = entry_payload(
            "dex",
            "swap_x_to_y",
            dex_pair_ty_args(),
            vec![
                bcs::to_bytes(&parse_move_addr(&trader).unwrap()).unwrap(),
                bcs::to_bytes(&parse_move_addr(&lp).unwrap()).unwrap(),
                bcs::to_bytes(&10_000u128).unwrap(),
                bcs::to_bytes(&u128::MAX).unwrap(),
            ],
        );
        let (updates, gas) = executor
            .execute_transaction(&signed_tx(&trader_key, &trader, &swap, 1, 100_000, 1))
            .expect("an aborted payload is still a valid, gas-charged transaction");
        apply_updates(&db, updates);

        let after = read_pool(&db, &lp);
        assert_eq!(after.coin_x.value, before.coin_x.value, "pool X untouched");
        assert_eq!(after.coin_y.value, before.coin_y.value, "pool Y untouched");
        assert_eq!(after.lp_supply, before.lp_supply, "pool LP untouched");
        assert_eq!(
            wbtc_balance(&db, &trader),
            0,
            "a rejected swap must not deliver output"
        );
        assert_eq!(
            coin_balance(&db, &trader),
            trader_ain_before - gas,
            "the trader loses gas and nothing else"
        );
    }

    // ===== SEC-#30: genesis-hash pin =====

    /// The identity genesis stored. TA-1: it is computed once, in memory,
    /// from genesis.json, and never recomputed from the database.
    fn stored_identity(db: &StateDB) -> String {
        db.get("genesis_identity").unwrap().unwrap()
    }

    /// With the pin env unset, genesis init + reopen behave exactly as before.
    #[test]
    fn test_genesis_pin_unset_is_noop() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let db = temp_db("pin_unset");
        let key = SigningKey::from_bytes(&[31u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        init_genesis(&db, &addr, &pubkey).expect("fresh genesis initializes with pin unset");
        init_genesis(&db, &addr, &pubkey).expect("genesis reopens with pin unset");
    }

    /// The identity hash is deterministic for identical genesis inputs (so every
    /// honest node computes the same pin).
    #[test]
    fn test_genesis_identity_hash_is_deterministic() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let key = SigningKey::from_bytes(&[32u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        let db1 = temp_db("pin_det1");
        let db2 = temp_db("pin_det2");
        init_genesis(&db1, &addr, &pubkey).unwrap();
        init_genesis(&db2, &addr, &pubkey).unwrap();
        assert_eq!(stored_identity(&db1), stored_identity(&db2));
    }

    #[test]
    fn test_format_policy_proposal_binds_actual_genesis_without_migration() {
        use blockchain::identity_v2::policy::{GenesisFormatProof, VerifiedFormatPolicy};

        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let db = temp_db("format_policy_proposal");
        let key = SigningKey::from_bytes(&[33u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());
        init_genesis(&db, &addr, &pubkey).unwrap();
        let rows = || {
            db.db
                .iterator(storage::rocksdb::IteratorMode::Start)
                .map(Result::unwrap)
                .collect::<Vec<_>>()
        };
        let before = rows();
        let old_identity = stored_identity(&db);
        let proof = GenesisFormatProof {
            base_genesis_identity: hex::decode(&old_identity).unwrap().try_into().unwrap(),
            chain_id: db.get("sys:chain_id").unwrap().unwrap(),
            v2_from_height: 21,
        };
        // This test authorizes a candidate pin, not a production bootstrap.
        let candidate = proof.proposed_genesis_identity().unwrap();
        assert_ne!(candidate, proof.base_genesis_identity);
        let policy =
            VerifiedFormatPolicy::verify_against_pin(candidate, &proof.encode().unwrap()).unwrap();
        assert_eq!(policy.chain_id(), proof.chain_id);
        assert_eq!(policy.required_version(20).unwrap(), 1);
        assert_eq!(policy.required_version(21).unwrap(), 2);
        for mutate_base in [false, true] {
            let mut other = proof.clone();
            if mutate_base {
                other.base_genesis_identity[0] ^= 1;
            } else {
                other.v2_from_height = 1;
            }
            assert!(
                VerifiedFormatPolicy::verify_against_pin(candidate, &other.encode().unwrap())
                    .is_err()
            );
        }
        assert_eq!(
            rows(),
            before,
            "proposal verification cannot migrate stored genesis"
        );
        init_genesis(&db, &addr, &pubkey).unwrap();
        assert_eq!(db.get("genesis_identity").unwrap().unwrap(), old_identity);
        assert_eq!(rows(), before, "existing genesis still reopens unchanged");
    }

    /// RE-AUDIT CRITICAL: the vertex-hash domain is derived from the genesis
    /// identity. If that identity tracked the LIVE validator set, then any
    /// join / stake change / slash followed by a restart would give the node a
    /// DIFFERENT domain — every vertex it signed would hash differently and be
    /// unverifiable to the rest of the cluster, i.e. the node bricks itself out
    /// of consensus after the first slash. The identity must be frozen at
    /// genesis and must not move when the live set changes.
    #[test]
    fn test_genesis_identity_is_frozen_against_validator_set_changes() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let key = SigningKey::from_bytes(&[77u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        let db = temp_db("identity_frozen");
        init_genesis(&db, &addr, &pubkey).unwrap();
        let stored = db
            .get("genesis_identity")
            .unwrap()
            .expect("genesis persists the identity for the vertex-hash domain");
        let frozen = db
            .get("genesis:validator_set:v1")
            .unwrap()
            .expect("genesis freezes the validator-set snapshot");
        let expected_committee: Vec<consensus::qc::ValidatorInfo> =
            serde_json::from_str(&frozen).unwrap();
        assert!(db.get("sys:validator_set:epoch:0").unwrap().is_none());
        assert_eq!(
            consensus::qc_producer::load_validator_set_for_epoch(&db, 0),
            Some(expected_committee.clone()),
            "QC bootstrap must consume the actual frozen genesis record"
        );

        // Simulate a slash / join: the LIVE set changes.
        let _seed = db.seeding();
        db.put(
            "sys:validator_set:v1",
            r#"[{"address":"deadbeef","stake":1}]"#,
        )
        .unwrap();

        // Reopen: identity must be unchanged, and the frozen snapshot untouched.
        init_genesis(&db, &addr, &pubkey)
            .expect("reopen must succeed after a live validator-set change");
        assert_eq!(
            db.get("genesis_identity").unwrap().unwrap(),
            stored,
            "genesis identity must NOT track the live validator set"
        );
        assert_eq!(
            db.get("genesis:validator_set:v1").unwrap().unwrap(),
            frozen,
            "the frozen genesis snapshot must never be rewritten"
        );
        assert_eq!(
            consensus::qc_producer::load_validator_set_for_epoch(&db, 0),
            Some(expected_committee),
            "reopening after a live set change must not change epoch-zero QC authority"
        );
    }

    /// A reopened datadir is checked against the operator pin by its stored
    /// identity (TA-1: computed once, at genesis). A datadir whose stored
    /// identity differs from the pin is a different chain, or tampered: boot
    /// must refuse rather than install a domain that makes this node's
    /// vertices unverifiable.
    #[test]
    fn test_genesis_identity_mismatch_refuses_boot() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let key = SigningKey::from_bytes(&[78u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        let db = temp_db("identity_mismatch");
        init_genesis(&db, &addr, &pubkey).unwrap();
        let identity = stored_identity(&db);
        db.put("genesis_identity", &"00".repeat(32)).unwrap();
        std::env::set_var("AINCORE_EXPECTED_GENESIS_HASH", &identity);
        let err = init_genesis(&db, &addr, &pubkey);
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let err = err.expect_err("a stored identity that is not the pinned one must refuse");
        assert!(
            format!("{}", err).contains("genesis hash pin mismatch"),
            "unexpected error: {}",
            err
        );
    }

    /// SEC-#13: genesis writes the canonical epoch-block interval to
    /// sys:config:epoch_block_interval (default 20 when genesis.json omits it).
    #[test]
    fn test_genesis_writes_epoch_block_interval_pin() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let db = temp_db("ebi_genesis_pin");
        let key = SigningKey::from_bytes(&[40u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        init_genesis(&db, &addr, &pubkey).expect("fresh genesis initializes");

        let pinned = db
            .get(GENESIS_EPOCH_BLOCK_INTERVAL_KEY)
            .unwrap()
            .expect("epoch-block interval must be pinned at genesis");
        assert_eq!(
            pinned,
            DEFAULT_EPOCH_BLOCK_INTERVAL.to_string(),
            "a genesis.json without the field pins the canonical default interval"
        );
    }

    /// SEC-#13: the epoch-block interval is folded into the genesis identity hash,
    /// so two otherwise-identical genesis states with different intervals produce
    /// different chain identities (a tampered interval is caught by the pin).
    #[test]
    fn test_epoch_block_interval_changes_identity_hash() {
        let base = genesis_identity_hash("sh", "v", "cid", "vs", "20", "1");
        let other = genesis_identity_hash("sh", "v", "cid", "vs", "21", "1");
        assert_ne!(
            base, other,
            "identity hash must depend on the epoch-block interval"
        );
    }

    /// A matching pin allows boot (reopen path).
    #[test]
    fn test_genesis_pin_match_boots() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let db = temp_db("pin_match");
        let key = SigningKey::from_bytes(&[33u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        init_genesis(&db, &addr, &pubkey).expect("fresh init (pin unset)");
        let identity = stored_identity(&db);

        std::env::set_var("AINCORE_EXPECTED_GENESIS_HASH", &identity);
        let res = init_genesis(&db, &addr, &pubkey);
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        res.expect("matching pin must boot");
    }

    /// A wrong pin refuses to boot a FRESH datadir (the silent-wrong-chain case).
    #[test]
    fn test_genesis_pin_mismatch_refuses_fresh_boot() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        let db = temp_db("pin_mismatch");
        let key = SigningKey::from_bytes(&[34u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        std::env::set_var("AINCORE_EXPECTED_GENESIS_HASH", "ab".repeat(32));
        let res = init_genesis(&db, &addr, &pubkey);
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");

        let err = res.expect_err("a wrong pin must refuse to boot a fresh datadir");
        assert!(
            err.to_string().contains("genesis hash pin mismatch"),
            "unexpected error: {}",
            err
        );
    }

    // ===== G3 S3: deterministic genesis as state-tree version 0 =====

    /// A single-validator genesis.json, as a value, for the S3 tests below.
    fn s3_genesis_file() -> GenesisFile {
        let path = single_validator_genesis(
            &crypto::derive_address(
                SigningKey::from_bytes(&[50u8; 32])
                    .verifying_key()
                    .as_bytes(),
            )
            .unwrap(),
            &hex::encode(
                SigningKey::from_bytes(&[50u8; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
        );
        load_genesis_file(&path).unwrap()
    }

    fn write_file(name: &str, file: &GenesisFile) -> PathBuf {
        let path = temp_dir(&format!("s3_{name}")).join("genesis.json");
        fs::write(&path, serde_json::to_string(file).unwrap()).unwrap();
        path
    }

    fn stdlib() -> Vec<(String, Vec<u8>)> {
        load_stdlib_modules(&stdlib_path()).unwrap()
    }

    /// TA-1: the identity binds `state_root(0)`, so two genesis files that
    /// agree on every old identity marker (stdlib, chain id, validator set,
    /// epoch interval) but differ in any other genesis state get different
    /// identities. Before S3 a different treasury or burn rate kept the same
    /// identity.
    #[test]
    fn the_identity_binds_the_genesis_state_root() {
        let base = s3_genesis_file();
        let mut other = base.clone();
        other.burn_percentage = Some(11);
        let (a, b) = (
            build_genesis(&base, &stdlib()).unwrap(),
            build_genesis(&other, &stdlib()).unwrap(),
        );
        assert_ne!(a.state_root, b.state_root);
        assert_ne!(a.identity, b.identity);
        // Deterministic: the same inputs give the same bytes, root and identity.
        let again = build_genesis(&base, &stdlib()).unwrap();
        assert_eq!(again.writes, a.writes);
        assert_eq!(again.state_root, a.state_root);
        assert_eq!(again.identity, a.identity);
    }

    /// WG-2 / TA-1: genesis is committed through the block gate as version 0
    /// of the state tree, whose root is the in-memory root the identity binds.
    /// Every state key is in the tree, and nothing was written outside the
    /// block transaction.
    #[test]
    fn genesis_is_committed_as_state_tree_version_zero() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let file = s3_genesis_file();
        let path = write_file("v0", &file);
        let db = temp_db("s3_v0");
        let outside_before = db.db.state_class_stats().state_outside_block;
        initialize_genesis_from(&db, &stdlib_path(), &path).unwrap();
        let built = build_genesis(&file, &stdlib()).unwrap();
        assert_eq!(state_commit::latest_version(&db).unwrap(), Some(0));
        assert_eq!(state_commit::root(&db, 0).unwrap().0, built.state_root);
        assert_eq!(db.get("genesis_identity").unwrap().unwrap(), built.identity);
        assert_eq!(
            db.db.state_class_stats().state_outside_block,
            outside_before,
            "genesis wrote state only inside its block transaction"
        );
        // The root over this database's flat state keys is the same root:
        // nothing on disk is outside the tree.
        let flat: BTreeMap<String, Vec<u8>> = db
            .db
            .iterator(IteratorMode::Start)
            .map(Result::unwrap)
            .filter(|(k, _)| classify(k) == Some(KeyClass::State))
            .map(|(k, v)| (String::from_utf8(k.to_vec()).unwrap(), v.to_vec()))
            .collect();
        assert_eq!(
            state_commit::genesis_root(&flat).unwrap().0,
            built.state_root
        );
        state_commit::boot_check(&db).expect("a fresh genesis passes RC-1");
    }

    /// FX-7: genesis.json pins the stdlib; other bytecode is refused.
    #[test]
    fn the_stdlib_pin_refuses_other_bytecode() {
        let mut file = s3_genesis_file();
        file.stdlib_hash = "00".repeat(32);
        let err = build_genesis(&file, &stdlib()).expect_err("wrong stdlib hash");
        assert!(err.to_string().contains("pins stdlib_hash"), "{err}");
    }

    /// FX-7: a missing or unparseable genesis.json is an error, never a
    /// fallback, and so is one without the stdlib pin.
    #[test]
    fn a_missing_or_broken_genesis_file_is_an_error() {
        let dir = temp_dir("s3_broken");
        assert!(load_genesis_file(&dir.join("absent.json")).is_err());
        fs::write(dir.join("broken.json"), "{not json").unwrap();
        assert!(load_genesis_file(&dir.join("broken.json")).is_err());
        let mut no_pin = serde_json::to_value(s3_genesis_file()).unwrap();
        no_pin.as_object_mut().unwrap().remove("stdlib_hash");
        fs::write(dir.join("no_pin.json"), no_pin.to_string()).unwrap();
        let err = load_genesis_file(&dir.join("no_pin.json")).expect_err("no stdlib pin");
        assert!(err.to_string().contains("stdlib_hash"), "{err}");
    }

    /// A validator listed twice is refused, not silently merged.
    #[test]
    fn a_duplicate_validator_is_refused() {
        let mut file = s3_genesis_file();
        file.validators.push(file.validators[0].clone());
        let err = build_genesis(&file, &stdlib()).expect_err("duplicate validator");
        assert!(err.to_string().contains("listed twice"), "{err}");
    }

    /// FX-7: the burn rate, tip agreement and burn counter are genesis state,
    /// with the defaults their readers used, and out-of-range values refused.
    #[test]
    fn genesis_seeds_the_economic_parameters() {
        let built = build_genesis(&s3_genesis_file(), &stdlib()).unwrap();
        let get = |k: &str| built.writes.get(k).map(String::as_str);
        assert_eq!(get("sys:config:burn_percentage"), Some("10"));
        assert_eq!(get("sys:config:tip_agreement_n"), Some("1"));
        assert_eq!(get("total_burned"), Some("0"));
        assert_eq!(get("sys:config:require_exec_roots"), None, "FX-15: removed");
        let mut custom = s3_genesis_file();
        custom.burn_percentage = Some(0);
        custom.tip_agreement_n = Some(3);
        let built = build_genesis(&custom, &stdlib()).unwrap();
        assert_eq!(built.writes["sys:config:burn_percentage"], "0");
        assert_eq!(built.writes["sys:config:tip_agreement_n"], "3");
        for (burn, tip) in [(Some(101), None), (None, Some(0))] {
            let mut bad = s3_genesis_file();
            bad.burn_percentage = burn;
            bad.tip_agreement_n = tip;
            assert!(build_genesis(&bad, &stdlib()).is_err(), "{burn:?} {tip:?}");
        }
    }

    /// G3 SN-1b (review L4): genesis never runs on a datadir that carries a
    /// restore marker.
    #[test]
    fn genesis_refuses_a_datadir_with_an_unfinished_restore() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let db = temp_db("unfinished_restore");
        db.put(storage::RESTORE_MARKER, "{\"height\":10}").unwrap();
        let file = write_file("unfinished_restore", &s3_genesis_file());
        let err = initialize_genesis_from(&db, &stdlib_path(), &file).unwrap_err();
        assert!(err.to_string().contains("restore is unfinished"), "{err}");
        assert!(db.get("genesis_initialized").unwrap().is_none());
        db.delete(storage::RESTORE_MARKER).unwrap();
        initialize_genesis_from(&db, &stdlib_path(), &file).expect("then genesis runs");
    }

    /// Review finding (S3a): a reopen must not depend on genesis.json, the
    /// stdlib on disk or today's genesis code. Otherwise every later stdlib
    /// update, genesis-code change or restart without AINCORE_GENESIS_PATH
    /// would refuse existing nodes.
    #[test]
    fn a_reopen_needs_neither_genesis_json_nor_the_stdlib() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let file = s3_genesis_file();
        let db = temp_db("s3_reopen_bare");
        initialize_genesis_from(&db, &stdlib_path(), &write_file("reopen_bare", &file)).unwrap();
        let missing = temp_dir("s3_reopen_missing");
        initialize_genesis_from(&db, missing.to_str().unwrap(), &missing.join("absent.json"))
            .expect("reopen without genesis.json or stdlib");
        initialize_genesis(&db, missing.to_str().unwrap()).expect("reopen by default path");
        // The pin is still checked, against the stored identity.
        std::env::set_var("AINCORE_EXPECTED_GENESIS_HASH", "ab".repeat(32));
        let pinned = initialize_genesis(&db, missing.to_str().unwrap());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        assert!(pinned.is_err(), "a wrong pin refuses a reopen");
    }

    /// Review finding (S3a): genesis on a database that already holds state
    /// is refused. That state would sit in the flat store but not in tree
    /// version 0.
    #[test]
    fn genesis_on_a_database_that_holds_state_is_refused() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let db = temp_db("s3_dirty");
        let _seed = db.seeding();
        db.put("sys:config:base_reward", "999").unwrap();
        let err = initialize_genesis_from(
            &db,
            &stdlib_path(),
            &write_file("dirty", &s3_genesis_file()),
        )
        .expect_err("a database that holds state");
        assert!(err.to_string().contains("clean database"), "{err}");
        assert!(db.get("genesis_initialized").unwrap().is_none());
    }

    /// DT-3: genesis built in another process, from another working
    /// directory and with another environment, is byte-identical.
    #[test]
    fn genesis_is_identical_across_processes_cwds_and_environments() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let path = write_file("dt3", &s3_genesis_file());
        let db = temp_db("s3_dt3_here");
        initialize_genesis_from(&db, &stdlib_path(), &path).unwrap();
        let here = dt3_fingerprint(&db);
        for (n, env) in [("a", "AINCORE-OTHER-CHAIN"), ("b", "")] {
            let dir = temp_dir(&format!("s3_dt3_cwd_{n}"));
            let out = dir.join("fingerprint");
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "genesis::tests::dt3_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .current_dir(&dir)
                .env("AINCORE_TEST_DT3_GENESIS", &path)
                .env("AINCORE_TEST_DT3_DB", dir.join("db"))
                .env("AINCORE_TEST_DT3_OUT", &out)
                .env("AINCORE_CHAIN_ID", env)
                .env("AINCORE_EPOCH_BLOCK_INTERVAL", "7")
                .env_remove("AINCORE_GENESIS_PATH")
                .status()
                .unwrap();
            assert!(status.success(), "child {n}");
            assert_eq!(fs::read_to_string(&out).unwrap(), here, "child {n}");
        }
    }

    /// Identity, root of version 0, and a digest of every stored state key.
    fn dt3_fingerprint(db: &Arc<StateDB>) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        for row in db.db.iterator(IteratorMode::Start) {
            let (key, value) = row.unwrap();
            if classify(&key) == Some(KeyClass::State) {
                hasher.update((key.len() as u64).to_le_bytes());
                hasher.update(&key);
                hasher.update((value.len() as u64).to_le_bytes());
                hasher.update(&value);
            }
        }
        format!(
            "{} {} {}",
            stored_identity(db),
            hex::encode(state_commit::root(db, 0).unwrap().0),
            hex::encode(hasher.finalize())
        )
    }

    #[test]
    fn dt3_child() {
        let Some(path) = std::env::var_os("AINCORE_TEST_DT3_GENESIS") else {
            return;
        };
        let db = Arc::new(
            StateDB::open(std::env::var("AINCORE_TEST_DT3_DB").unwrap().as_str()).unwrap(),
        );
        initialize_genesis_from(&db, &stdlib_path(), std::path::Path::new(&path)).unwrap();
        fs::write(
            std::env::var("AINCORE_TEST_DT3_OUT").unwrap(),
            dt3_fingerprint(&db),
        )
        .unwrap();
    }

    /// WG-2 atomicity: a crash right after genesis's one transaction leaves a
    /// complete genesis that reopens. Writing any genesis marker after that
    /// transaction would leave tree version 0 without `genesis_initialized`,
    /// and every later boot would fail.
    #[test]
    fn a_crash_after_the_genesis_transaction_leaves_a_complete_genesis() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let path = write_file("crash", &s3_genesis_file());
        let dir = temp_dir("s3_crash_db");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "genesis::tests::dt3_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AINCORE_TEST_DT3_GENESIS", &path)
            .env("AINCORE_TEST_DT3_DB", dir.join("db"))
            .env("AINCORE_TEST_DT3_OUT", dir.join("unused"))
            .env("AINCORE_TEST_GENESIS_CRASH_AFTER_COMMIT", "1")
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(77),
            "the child crashed after the commit"
        );
        let db = Arc::new(StateDB::open(dir.join("db").to_str().unwrap()).unwrap());
        assert!(db.get("genesis_initialized").unwrap().is_some());
        assert_eq!(state_commit::latest_version(&db).unwrap(), Some(0));
        initialize_genesis_from(&db, &stdlib_path(), &path).expect("the crashed genesis reopens");
        state_commit::boot_check(&db).unwrap();
    }
}
