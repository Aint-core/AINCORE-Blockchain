use move_binary_format::CompiledModule;
use move_core_types::{
    account_address::AccountAddress,
    identifier::Identifier,
    language_storage::{StructTag, TypeTag},
};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc; // Force rebuild
use storage::StateDB;

const GENESIS_VERSION: &str = "phase1-bls-stake-v1";
/// SEC-#13: storage key holding the canonical, genesis-pinned epoch-block
/// interval. The executor reads this FIRST (deterministic across all nodes) and
/// only falls back to the AINCORE_EPOCH_BLOCK_INTERVAL env var when it is absent
/// (legacy DBs). Folded into the genesis identity hash so it is forge-proof.
const GENESIS_EPOCH_BLOCK_INTERVAL_KEY: &str = "sys:config:epoch_block_interval";
/// Canonical default for the epoch-block interval when genesis.json does not
/// specify one. MUST match `Executor::DEFAULT_EPOCH_BLOCK_INTERVAL`.
const DEFAULT_EPOCH_BLOCK_INTERVAL: u64 = 20;
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

/// Domain-separation prefix for deriving a validator's BLS key from the node
/// identity. Mirrors `da/src/lib.rs` `derive_da_enc_key` so node.key remains the
/// single secret; the Ed25519 secret is never used directly as a BLS secret.
const VALIDATOR_BLS_DOMAIN: &[u8] = b"AINCORE_VALIDATOR_BLS_V1";

/// Deterministically derive the 32-byte BLS seed from the 32-byte node identity:
/// `bls_seed = SHA256(VALIDATOR_BLS_DOMAIN || node_identity)`.
fn derive_validator_bls_seed(node_identity: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VALIDATOR_BLS_DOMAIN);
    hasher.update(node_identity);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// Derive `(bls_public_key, bls_pop)` (compressed bytes) from the node identity.
fn derive_validator_bls_identity(node_identity: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let seed = derive_validator_bls_seed(node_identity);
    let bls = crypto::bls::BLSEngine::consensus();
    (bls.pubkey_raw(&seed), bls.prove_possession_raw(&seed))
}

/// Resolve the BLS identity for a genesis validator entry.
///
/// If `bls_public_key`/`bls_pop` are supplied (hex), they are decoded,
/// length-checked (pk=48, pop=96), and PoP-verified — rejecting on any failure.
/// If absent, the identity is derived deterministically from the local node
/// identity (single-node / local fallback). Returns `(bls_public_key, bls_pop)`
/// as raw bytes.
fn resolve_genesis_bls_identity(
    bls_public_key_hex: Option<&str>,
    bls_pop_hex: Option<&str>,
    node_identity: &[u8; 32],
    single_node_fallback_allowed: bool,
) -> Result<(Vec<u8>, Vec<u8>), GenesisError> {
    let bls = crypto::bls::BLSEngine::consensus();
    match (bls_public_key_hex, bls_pop_hex) {
        (Some(pk_hex), Some(pop_hex)) => {
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
        (None, None) => {
            // SEC-#5: self-deriving a BLS identity from the LOCAL node identity is
            // only correct for a single-validator genesis. With N>1 validators,
            // every booting node would derive a DIFFERENT key for the same peer
            // address -> each writes a divergent sys:validator_set:v1 -> QCs never
            // verify. Require explicit PoP-verified keys for multi-validator genesis.
            if !single_node_fallback_allowed {
                return Err(GenesisError::InvalidData(
                    "multi-validator genesis MUST supply bls_public_key + bls_pop for every \
                     validator (cannot self-derive another node's BLS key)"
                        .to_string(),
                ));
            }
            Ok(derive_validator_bls_identity(node_identity))
        }
        _ => Err(GenesisError::InvalidData(
            "Genesis validator must supply BOTH bls_public_key and bls_pop, or neither".to_string(),
        )),
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

/// SEC-#30: fold the canonical genesis markers into a single chain-identity
/// digest. All inputs are already computed and stored at genesis. The opt-in
/// genesis-hash pin (`AINCORE_EXPECTED_GENESIS_HASH`) compares against this to
/// refuse booting the wrong chain (wrong genesis.json / wrong datadir / wrong
/// validator set). Length-prefixed + domain-tagged, mirroring `stdlib_state_hash`
/// so it is deterministic and collision-resistant across nodes.
fn genesis_identity_hash(
    stdlib_hash: &str,
    version: &str,
    chain_id: &str,
    validator_set_json: &str,
    epoch_block_interval: &str,
) -> String {
    let mut hasher = Sha256::new();
    for part in [
        "AINCORE_GENESIS_ID_V1",
        stdlib_hash,
        version,
        chain_id,
        validator_set_json,
        // SEC-#13: pin the epoch-block interval into chain identity so a node
        // booting with a tampered/divergent interval is rejected by the genesis
        // hash pin (it would advance epochs at different heights → fork).
        epoch_block_interval,
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

    // SEC-#30: genesis-hash pin. Fold the canonical genesis markers into one
    // chain-identity digest and, when AINCORE_EXPECTED_GENESIS_HASH is set, refuse
    // to boot on mismatch — turning "silently runs a DIFFERENT chain" (wrong
    // genesis.json / wrong CWD / wrong validator set) into a hard FATAL stop. When
    // the env var is unset the check is a no-op (opt-in until the mainnet genesis
    // hash is frozen), so dev/testnet behaviour is unchanged. chain_id/validator
    // markers are read tolerantly so reopening any existing datadir never newly
    // fails when the pin is not in use.
    let chain_id = storage.get("sys:chain_id").ok().flatten().unwrap_or_default();
    let validator_set_json = storage
        .get("sys:validator_set:v1")
        .ok()
        .flatten()
        .unwrap_or_default();
    // SEC-#13: read tolerantly so reopening a legacy datadir that predates the
    // pin never newly fails — an absent key folds the empty string, exactly as a
    // pre-#13 DB would have hashed.
    let epoch_block_interval = storage
        .get(GENESIS_EPOCH_BLOCK_INTERVAL_KEY)
        .ok()
        .flatten()
        .unwrap_or_default();
    let identity = genesis_identity_hash(
        &expected_hash,
        &version,
        &chain_id,
        &validator_set_json,
        &epoch_block_interval,
    );
    println!("🧬 Genesis identity hash: {}", identity);
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

pub fn initialize_genesis(
    storage: &Arc<StateDB>,
    stdlib_path: &str,
    genesis_addr_hex: &str,
    genesis_pubkey_hex: &str,
    node_identity: &[u8; 32],
) -> Result<(), GenesisError> {
    // Check if genesis is already initialized
    if let Ok(Some(_)) = storage.get("genesis_initialized") {
        verify_genesis_integrity(storage)?;
        println!("✨ Genesis already initialized.");
        return Ok(());
    }

    println!("🌋 Initializing Genesis...");

    let stdlib_modules = load_stdlib_modules(stdlib_path)?;
    let stdlib_hash = stdlib_state_hash(&stdlib_modules);
    let stdlib_module_keys: Vec<String> =
        stdlib_modules.iter().map(|(key, _)| key.clone()).collect();
    for (key, bytes) in &stdlib_modules {
        storage.put(key, &hex::encode(bytes))?;
        println!("   Loaded module: {}", key);
    }
    println!(
        "✅ Loaded {} Stdlib modules into StateDB.",
        stdlib_modules.len()
    );

    // === Create Genesis Account ===
    // Address: genesis_addr_hex
    let genesis_addr = genesis_addr_hex;
    let genesis_pubkey = genesis_pubkey_hex;

    use aa::AccountManager;
    let mut account_obj =
        AccountManager::create_account(genesis_addr.to_string(), genesis_pubkey.to_string());

    // Update balance manually (since AccountManager creates with 0)
    use aa::AccountData;
    let mut data: AccountData = serde_json::from_slice(&account_obj.data)?;

    // ZERO PRE-MINE: Start with 0 balance.
    data.balance = 0;
    account_obj.data = serde_json::to_vec(&data)?;
    storage.put_object(&account_obj)?;
    println!(
        "💰 Created Genesis Account: {} (Balance: {})",
        genesis_addr, data.balance
    );

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

    // === GENESIS CEREMONY ===
    // Using genesis.json if present, fallback to local single node if not.
    #[derive(serde::Deserialize)]
    struct GenesisValidatorConfig {
        address: String,
        public_key: String,
        stake: String,
        #[serde(default)]
        bls_public_key: Option<String>,
        #[serde(default)]
        bls_pop: Option<String>,
    }

    #[derive(serde::Deserialize)]
    struct GenesisFile {
        chain_id: String,
        validators: Vec<GenesisValidatorConfig>,
        treasury_reserve: String,
        epoch_duration: u64,
        /// SEC-#13: optional canonical epoch-BLOCK interval (in blocks). This is
        /// distinct from `epoch_duration` (a wall-clock seconds value used by the
        /// Move epoch resource). When omitted, DEFAULT_EPOCH_BLOCK_INTERVAL is
        /// used. Pinned into storage + the genesis identity hash so every node
        /// advances epochs at identical heights (no per-node env fork hazard).
        #[serde(default)]
        epoch_block_interval: Option<u64>,
    }

    let genesis_paths = vec![
        std::env::var("AINCORE_GENESIS_PATH").unwrap_or_default(),
        "genesis.json".to_string(),
        "/usr/src/aincore/genesis.json".to_string(),
        "/root/.aincore/genesis.json".to_string(),
        "../genesis.json".to_string(),
        "../../genesis.json".to_string(),
    ];
    let mut loaded_genesis = None;
    for path in &genesis_paths {
        if path.trim().is_empty() {
            continue;
        }
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(config) = serde_json::from_str::<GenesisFile>(&contents) {
                println!("📄 Loaded genesis config from {}", path);
                loaded_genesis = Some(config);
                break;
            }
        }
    }

    let mut genesis_validators = Vec::new();
    let mut validator_configs = Vec::new();
    let mut v1_validators: Vec<consensus::qc::ValidatorInfo> = Vec::new();
    let mut total_bootstrap_stake: u128 = 0;
    let treasury_reserve_amount: u128;
    let genesis_epoch_duration: u64;
    // SEC-#13: canonical epoch-block interval to pin into storage + identity hash.
    let genesis_epoch_block_interval: u64;
    let mut genesis_chain_id = "AINCORE-MAINNET-1".to_string();

    if let Some(config) = loaded_genesis {
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
        // SEC-#5: BLS self-derivation from the local node identity is only valid
        // for a single-validator genesis (see resolve_genesis_bls_identity).
        let genesis_validator_count = config.validators.len();
        // SEC (audit M-4): genesis writes sys:validator_set:v1 directly, bypassing the
        // Move staking module's MIN_STAKE check. scale_stake_to_whole_ain integer-divides
        // quanta by 10^18, so ANY stake below 1 whole AIN silently becomes 0 whole-AIN
        // voting power (registered but never counted for quorum/leader) — and an all-
        // sub-1-AIN set yields total_stake==0, making strict >2/3 unsatisfiable → the
        // chain never finalizes. Enforce the real minimum (1000 AIN) here, matching the
        // Move staking module, so no genesis validator can be silently disenfranchised.
        const MIN_VALIDATOR_STAKE_QUANTA: u128 = 1000 * 1_000_000_000_000_000_000; // 1000 AIN
        for val in config.validators {
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
            genesis_validators.push((val.address.clone(), val.public_key.clone()));
            total_bootstrap_stake += stake;

            let account_addr = parse_move_addr(&val.address)?;
            let public_key = parse_validator_public_key(&val.public_key, &val.address)?;
            // BLS identity: PoP-verify operator-supplied keys, or derive for the local node.
            let (bls_public_key, bls_pop) = resolve_genesis_bls_identity(
                val.bls_public_key.as_deref(),
                val.bls_pop.as_deref(),
                node_identity,
                genesis_validator_count == 1,
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
            println!(
                "👤 Created Genesis Validator Account: {} (Stake: {})",
                val.address, stake
            );
        }
    } else {
        println!(
            "⚠️ genesis.json not found! Falling back to single-node bootstrap using local key."
        );
        genesis_validators.push((genesis_addr_hex.to_string(), genesis_pubkey_hex.to_string()));
        let stake: u128 = 1_000_000u128 * 1_000_000_000_000_000_000; // M-8 FIX: 1M AIN in quanta (10^18 smallest unit)
        total_bootstrap_stake = stake;
        treasury_reserve_amount = 50_000 * 1_000_000_000_000_000_000;
        genesis_epoch_duration = 10;
        genesis_epoch_block_interval = DEFAULT_EPOCH_BLOCK_INTERVAL;

        let account_addr = parse_move_addr(genesis_addr_hex)?;
        let public_key = parse_validator_public_key(genesis_pubkey_hex, genesis_addr_hex)?;
        // Single-node fallback: derive BLS identity from the local node identity.
        // Single-node bootstrap fallback (no genesis.json validators) — self-derive allowed.
        let (bls_public_key, bls_pop) =
            resolve_genesis_bls_identity(None, None, node_identity, true)?;

        validator_configs.push(ValidatorConfig {
            validator_addr: account_addr,
            stake: Coin { value: stake },
            public_key,
            bls_public_key: bls_public_key.clone(),
            bls_pop: bls_pop.clone(),
        });
        v1_validators.push(crypto_qc_validator_info(
            genesis_addr_hex,
            stake,
            genesis_pubkey_hex,
            &bls_public_key,
            &bls_pop,
        )?);

        let acc = AccountManager::create_account(
            genesis_addr_hex.to_string(),
            genesis_pubkey_hex.to_string(),
        );
        storage.put_object(&acc)?;
        println!("👤 Created Genesis Validator Account: {}", genesis_addr_hex);
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

    if let Ok(json) = serde_json::to_string(&native_validators) {
        storage.put("sys:validators", &json)?;
        println!(
            "🔗 Native Consensus State Synced: {} Validator(s)",
            native_validators.len()
        );
    }

    // Versioned validator set carrying full finality identity for QC verification.
    // Shape == Vec<consensus::qc::ValidatorInfo> { address, stake, ed25519_public_key, bls_public_key, bls_pop }.
    if let Ok(json) = serde_json::to_string(&v1_validators) {
        storage.put("sys:validator_set:v1", &json)?;
        println!(
            "🔐 sys:validator_set:v1 written: {} validator(s)",
            v1_validators.len()
        );
    }
    storage.put("sys:chain_id", &genesis_chain_id)?;
    println!("⛓️  Genesis Chain ID: {}", genesis_chain_id);

    // SEC-#13: pin the canonical epoch-block interval on-chain. The executor
    // reads THIS deterministically on every node, eliminating the per-node
    // AINCORE_EPOCH_BLOCK_INTERVAL env fork hazard. Folded into the genesis
    // identity hash below so a tampered value is detected at boot.
    storage.put(
        GENESIS_EPOCH_BLOCK_INTERVAL_KEY,
        &genesis_epoch_block_interval.to_string(),
    )?;
    println!(
        "⏱️  Genesis Epoch-Block Interval pinned: {} block(s)",
        genesis_epoch_block_interval
    );

    // === GENESIS LOCK: Register the Genesis Validator address ===
    // This address will be PERMANENTLY BLOCKED from transfers (Anti-Rugpull).
    // The Executor checks sys:config:federation_addr before every transfer.
    if let Some((first_addr, _)) = genesis_validators.first() {
        storage.set_federation_key(first_addr)?;
        println!(
            "🔒 Genesis Lock Registered: {} (transfers permanently disabled)",
            first_addr
        );
    }

    let validator_set = ValidatorSet {
        validators: validator_configs,
        unbonding_queue: vec![],
        total_supply: total_bootstrap_stake,
        current_epoch: 0,
    };

    let key = system_resource_key("0x1::staking::ValidatorSet");

    // Serialize to BCS
    let bytes = bcs::to_bytes(&validator_set)?;
    let hex_bytes = hex::encode(bytes);
    storage.put(&key, &hex_bytes)?;
    println!("🛡️  Initialized Genesis Validator Set (Bootstrap Stake: 1 Million AIN)");

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
    println!(
        "⏳ Initialized Genesis Epoch (0) with duration {}s",
        genesis_epoch_duration
    );

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
    println!("⚖️  Initialized Governance Module");

    // === Initialize Universal Mining (Oracle & DeviceRegistry) ===
    #[derive(serde::Serialize)]
    struct DeviceInfo {
        device_pubkey: Vec<u8>,
        owner_addr: move_core_types::account_address::AccountAddress,
        // H3: must mirror 0x1::universal_mining::DeviceInfo BCS field order
        // (verified before device_type).
        verified: bool,
        device_type: u8,
    }
    #[derive(serde::Serialize)]
    struct DeviceRegistry {
        devices: Vec<DeviceInfo>,
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
    println!("🔮 Initialized Oracle Config");

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
    println!("🏦 Initialized Treasury (Reserve: 50,000 AIN)");

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
    println!("💧 Initialized DEX Pool Registry");

    // === FINAL CHECK: SET TOTAL SUPPLY ===
    // Validators (1M) + Treasury (50k)
    let initial_total_supply = total_bootstrap_stake + treasury.reserve.value;
    storage.put("sys:total_supply", &initial_total_supply.to_string())?;
    storage.put("genesis_stdlib_hash", &stdlib_hash)?;
    storage.put(
        GENESIS_STDLIB_MODULES_KEY,
        &serde_json::to_string(&stdlib_module_keys)?,
    )?;
    storage.put(GENESIS_STDLIB_COUNT_KEY, &stdlib_modules.len().to_string())?;
    storage.put("genesis_version", GENESIS_VERSION)?;
    println!(
        "📊 Genesis Total Supply Tracked: {} AIN",
        initial_total_supply / 1_000_000_000_000_000_000
    );

    storage.put("genesis_initialized", "true")?;

    // SEC-#30: run the integrity + genesis-hash-pin check on the freshly written
    // state too. Without this, a brand-new datadir that self-bootstrapped the
    // WRONG chain (e.g. wrong CWD / missing genesis.json fallback) would return
    // Ok here and silently run — the pin only fires on reopen. Re-reading the
    // markers we just wrote is cheap and makes the pin catch fresh init as well.
    verify_genesis_integrity(storage)?;

    println!("✅ Genesis Initialization Complete!");

    Ok(())
}

#[cfg(test)]
mod tests {
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

    /// QC Phase 2 anti-drift guard: the runtime BLS-seed derivation used by the
    /// consensus QC producer MUST be byte-identical to the genesis derivation,
    /// otherwise a validator signs finality votes with a key that is not the one
    /// registered at genesis and every QC it produces fails verification (silent
    /// keystone death). This test sees both definitions and pins them together.
    #[test]
    fn genesis_and_qc_producer_bls_derivation_match() {
        for id_byte in [0u8, 1, 7, 42, 200, 255] {
            let id = [id_byte; 32];
            assert_eq!(
                derive_validator_bls_seed(&id),
                consensus::qc_producer::derive_validator_bls_seed(&id),
                "BLS seed derivation drifted between genesis and qc_producer for id byte {id_byte}"
            );
            // And therefore the derived public keys must match too.
            let bls = crypto::bls::BLSEngine::consensus();
            let (genesis_pk, _) = derive_validator_bls_identity(&id);
            let producer_seed = consensus::qc_producer::derive_validator_bls_seed(&id);
            assert_eq!(
                genesis_pk,
                bls.pubkey_raw(&producer_seed),
                "derived BLS pubkey drifted for id byte {id_byte}"
            );
        }
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

    /// Deterministic node identity for tests (drives the single-node BLS fallback).
    const TEST_NODE_IDENTITY: [u8; 32] = [7u8; 32];

    fn create_account(db: &StateDB, signing_key: &SigningKey) -> String {
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());
        let address = crypto::derive_address(public_key.as_bytes()).expect("canonical address");
        let object = aa::AccountManager::create_account(address.clone(), public_key_hex);
        db.put_object(&object).expect("account object stored");
        address
    }

    fn set_coin_store(db: &StateDB, address: &str, value: u128) {
        let move_addr = parse_move_addr(address).expect("valid move address");
        let bytes = bcs::to_bytes(&TestCoin { value }).expect("coin store BCS");
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

        let err = initialize_genesis(
            &db,
            empty_stdlib.to_str().expect("utf8 temp path"),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
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

        initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
        .expect("fresh genesis initializes");
        initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
        .expect("valid genesis reopens");

        db.delete("module_0000000000000000000000000000000000000000000000000000000000000001_signer")
            .expect("corrupt stdlib delete");
        let err = initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
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

        initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
        .expect("fresh genesis initializes");

        db.put("module_0000000000000000000000000000000000000000000000000000000000000001_signer", "00")
            .expect("corrupt module bytes");
        let err = initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
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

        initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
        .expect("fresh genesis initializes");

        db.put("genesis_stdlib_hash", "deadbeef")
            .expect("corrupt stdlib hash marker");
        let err = initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
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

        initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
        .expect("fresh genesis initializes");

        let coin_bytes = db
            .get("module_0000000000000000000000000000000000000000000000000000000000000001_coin")
            .expect("coin read")
            .expect("coin exists");
        db.put(
            "module_0000000000000000000000000000000000000000000000000000000000000001_signer",
            &coin_bytes,
        )
        .expect("swap module bytes under signer key");
        let err = initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
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
            "{{\"chain_id\":\"AINCORE-MAINNET-1\",\"validators\":[{{\"address\":\"{}\",\"public_key\":\"{}\",\"stake\":\"1000000000000000000000\"{}}}],\"treasury_reserve\":\"0\",\"epoch_duration\":10}}",
            addr, pubkey, bls_fields
        );
        fs::write(&path, json).expect("write genesis.json");
        path
    }

    #[test]
    fn test_single_node_fallback_derives_bls() {
        // The single-node fallback path derives the BLS identity deterministically
        // from the node identity. Unit-test the helper directly (the full
        // initialize_genesis fallback cannot be exercised reliably here because a
        // real genesis.json exists at ../../genesis.json in the search path).
        let bls = crypto::bls::BLSEngine::consensus();
        let (pk, pop) = resolve_genesis_bls_identity(None, None, &TEST_NODE_IDENTITY, true)
            .expect("fallback derivation succeeds");
        assert_eq!(pk.len(), 48, "derived bls_public_key must be 48 bytes");
        assert_eq!(pop.len(), 96, "derived bls_pop must be 96 bytes");
        assert!(
            bls.verify_possession(&pk, &pop).unwrap(),
            "derived PoP must verify"
        );
        // Deterministic: equals derive_validator_bls_identity for the same identity.
        let (expect_pk, expect_pop) = derive_validator_bls_identity(&TEST_NODE_IDENTITY);
        assert_eq!(pk, expect_pk);
        assert_eq!(pop, expect_pop);
        // A different node identity yields a different key.
        let other = [9u8; 32];
        let (other_pk, _) = derive_validator_bls_identity(&other);
        assert_ne!(pk, other_pk);
    }

    /// SEC-#5: in a MULTI-validator genesis, a validator with no explicit
    /// bls_public_key/bls_pop must NOT self-derive (each node would derive a
    /// different key) — it must error.
    #[test]
    fn multi_validator_genesis_rejects_self_derived_bls() {
        let err = resolve_genesis_bls_identity(None, None, &TEST_NODE_IDENTITY, false);
        assert!(
            err.is_err(),
            "multi-validator genesis must reject self-derived BLS keys"
        );
        // Single-node fallback still allowed.
        assert!(resolve_genesis_bls_identity(None, None, &TEST_NODE_IDENTITY, true).is_ok());
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
        std::env::set_var("AINCORE_GENESIS_PATH", &path);
        let db = temp_db("loads_bls");
        let res = initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY);
        std::env::remove_var("AINCORE_GENESIS_PATH");
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
        std::env::set_var("AINCORE_GENESIS_PATH", &path);
        let db = temp_db("bad_pop");
        let res = initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY);
        std::env::remove_var("AINCORE_GENESIS_PATH");
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
        std::env::set_var("AINCORE_GENESIS_PATH", &path);
        let db = temp_db("v1_roundtrip");
        let res = initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY);
        std::env::remove_var("AINCORE_GENESIS_PATH");
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
            consensus::qc::verify_qc(&qc, &set).is_ok(),
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

        initialize_genesis(
            &db,
            &stdlib_path(),
            &genesis_addr,
            &genesis_pubkey,
            &TEST_NODE_IDENTITY,
        )
        .expect("fresh genesis initializes");

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

    // ===== SEC-#30: genesis-hash pin =====

    fn computed_identity(db: &StateDB) -> String {
        let sh = db.get("genesis_stdlib_hash").unwrap().unwrap();
        let v = db.get("genesis_version").unwrap().unwrap();
        let cid = db.get("sys:chain_id").ok().flatten().unwrap_or_default();
        let vs = db
            .get("sys:validator_set:v1")
            .ok()
            .flatten()
            .unwrap_or_default();
        let ebi = db
            .get(GENESIS_EPOCH_BLOCK_INTERVAL_KEY)
            .ok()
            .flatten()
            .unwrap_or_default();
        genesis_identity_hash(&sh, &v, &cid, &vs, &ebi)
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

        initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY)
            .expect("fresh genesis initializes with pin unset");
        initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY)
            .expect("genesis reopens with pin unset");
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
        initialize_genesis(&db1, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY).unwrap();
        initialize_genesis(&db2, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY).unwrap();
        assert_eq!(computed_identity(&db1), computed_identity(&db2));
    }

    /// SEC-#13: genesis writes the canonical epoch-block interval to
    /// sys:config:epoch_block_interval (default 20 when genesis.json omits it /
    /// is absent — the single-node fallback path here).
    #[test]
    fn test_genesis_writes_epoch_block_interval_pin() {
        let _guard = GENESIS_ENV_LOCK.lock().unwrap();
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");
        let db = temp_db("ebi_genesis_pin");
        let key = SigningKey::from_bytes(&[40u8; 32]);
        let addr = crypto::derive_address(key.verifying_key().as_bytes()).unwrap();
        let pubkey = hex::encode(key.verifying_key().as_bytes());

        initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY)
            .expect("fresh genesis initializes");

        let pinned = db
            .get(GENESIS_EPOCH_BLOCK_INTERVAL_KEY)
            .unwrap()
            .expect("epoch-block interval must be pinned at genesis");
        assert_eq!(
            pinned,
            DEFAULT_EPOCH_BLOCK_INTERVAL.to_string(),
            "fallback genesis must pin the canonical default interval"
        );
    }

    /// SEC-#13: the epoch-block interval is folded into the genesis identity hash,
    /// so two otherwise-identical genesis states with different intervals produce
    /// different chain identities (a tampered interval is caught by the pin).
    #[test]
    fn test_epoch_block_interval_changes_identity_hash() {
        let base = genesis_identity_hash("sh", "v", "cid", "vs", "20");
        let other = genesis_identity_hash("sh", "v", "cid", "vs", "21");
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

        initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY)
            .expect("fresh init (pin unset)");
        let identity = computed_identity(&db);

        std::env::set_var("AINCORE_EXPECTED_GENESIS_HASH", &identity);
        let res = initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY);
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
        let res = initialize_genesis(&db, &stdlib_path(), &addr, &pubkey, &TEST_NODE_IDENTITY);
        std::env::remove_var("AINCORE_EXPECTED_GENESIS_HASH");

        let err = res.expect_err("a wrong pin must refuse to boot a fresh datadir");
        assert!(
            err.to_string().contains("genesis hash pin mismatch"),
            "unexpected error: {}",
            err
        );
    }
}
