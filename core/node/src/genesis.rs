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

const GENESIS_VERSION: &str = "phase1-dex-registry-v1";
const GENESIS_STDLIB_MODULES_KEY: &str = "genesis_stdlib_modules";
const GENESIS_STDLIB_COUNT_KEY: &str = "genesis_stdlib_module_count";
const REQUIRED_STDLIB_MODULES: &[&str] = &[
    "module_00000000000000000000000000000001_signer",
    "module_00000000000000000000000000000001_vector",
    "module_00000000000000000000000000000001_bcs",
    "module_00000000000000000000000000000001_hash",
    "module_00000000000000000000000000000001_coin",
    "module_00000000000000000000000000000001_staking",
    "module_00000000000000000000000000000001_dex",
];

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
    for required in REQUIRED_STDLIB_MODULES {
        if !available.contains(required) {
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

    Ok(())
}

pub fn initialize_genesis(
    storage: &Arc<StateDB>,
    stdlib_path: &str,
    genesis_addr_hex: &str,
    genesis_pubkey_hex: &str,
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
    }

    #[derive(serde::Deserialize)]
    struct GenesisFile {
        #[allow(dead_code)]
        chain_id: String,
        validators: Vec<GenesisValidatorConfig>,
        treasury_reserve: String,
        epoch_duration: u64,
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
    let mut total_bootstrap_stake: u128 = 0;
    let treasury_reserve_amount: u128;
    let genesis_epoch_duration: u64;

    if let Some(config) = loaded_genesis {
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
        for val in config.validators {
            let stake = parse_genesis_amount(&val.stake, "validator stake")?;
            if stake == 0 {
                return Err(GenesisError::InvalidData(format!(
                    "Genesis validator {} stake must be greater than 0",
                    val.address
                )));
            }
            genesis_validators.push((val.address.clone(), val.public_key.clone()));
            total_bootstrap_stake += stake;

            let account_addr = parse_move_addr(&val.address)?;
            let public_key = parse_validator_public_key(&val.public_key, &val.address)?;

            validator_configs.push(ValidatorConfig {
                validator_addr: account_addr,
                stake: Coin { value: stake },
                public_key,
            });

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

        let account_addr = parse_move_addr(genesis_addr_hex)?;
        let public_key = parse_validator_public_key(genesis_pubkey_hex, genesis_addr_hex)?;

        validator_configs.push(ValidatorConfig {
            validator_addr: account_addr,
            stake: Coin { value: stake },
            public_key,
        });

        let acc = AccountManager::create_account(
            genesis_addr_hex.to_string(),
            genesis_pubkey_hex.to_string(),
        );
        storage.put_object(&acc)?;
        println!("👤 Created Genesis Validator Account: {}", genesis_addr_hex);
    }

    // === SYNC NATIVE CONSENSUS STATE (CRITICAL FIX) ===
    // Write 'sys:validators' so the Rust Consensus Engine knows who is allowed to mine.
    // Format: Vec<(String, u64)> -> (PubKey, Weight)
    let native_validators: Vec<(String, u64)> = genesis_validators
        .iter()
        .map(|(addr, _)| (addr.clone(), 100)) // Weight 100
        .collect();

    if let Ok(json) = serde_json::to_string(&native_validators) {
        storage.put("sys:validators", &json)?;
        println!(
            "🔗 Native Consensus State Synced: {} Validator(s)",
            native_validators.len()
        );
    }

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
        let db = temp_db("integrity");
        let genesis_key = SigningKey::from_bytes(&[21u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect("fresh genesis initializes");
        initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect("valid genesis reopens");

        db.delete("module_00000000000000000000000000000001_signer")
            .expect("corrupt stdlib delete");
        let err = initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect_err("corrupt stdlib marker must fail fast");
        assert!(
            err.to_string().contains("required Move module is missing"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_reopen_rejects_corrupt_module_bytes() {
        let db = temp_db("corrupt_module_bytes");
        let genesis_key = SigningKey::from_bytes(&[25u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect("fresh genesis initializes");

        db.put("module_00000000000000000000000000000001_signer", "00")
            .expect("corrupt module bytes");
        let err = initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect_err("corrupt module bytes must fail fast");
        assert!(
            err.to_string().contains("failed bytecode decode"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_reopen_rejects_stdlib_hash_mismatch() {
        let db = temp_db("stdlib_hash_mismatch");
        let genesis_key = SigningKey::from_bytes(&[26u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect("fresh genesis initializes");

        db.put("genesis_stdlib_hash", "deadbeef")
            .expect("corrupt stdlib hash marker");
        let err = initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect_err("hash mismatch must fail fast");
        assert!(
            err.to_string().contains("Genesis stdlib hash mismatch"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_genesis_reopen_rejects_module_key_id_mismatch() {
        let db = temp_db("module_key_id_mismatch");
        let genesis_key = SigningKey::from_bytes(&[27u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect("fresh genesis initializes");

        let coin_bytes = db
            .get("module_00000000000000000000000000000001_coin")
            .expect("coin read")
            .expect("coin exists");
        db.put(
            "module_00000000000000000000000000000001_signer",
            &coin_bytes,
        )
        .expect("swap module bytes under signer key");
        let err = initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
            .expect_err("module key/id mismatch must fail fast");
        assert!(
            err.to_string().contains("key/id mismatch"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_fresh_genesis_then_executor_accepts_bcs_transfer_path() {
        let db = temp_db("transfer");
        let genesis_key = SigningKey::from_bytes(&[22u8; 32]);
        let genesis_addr = crypto::derive_address(genesis_key.verifying_key().as_bytes()).unwrap();
        let genesis_pubkey = hex::encode(genesis_key.verifying_key().as_bytes());

        initialize_genesis(&db, &stdlib_path(), &genesis_addr, &genesis_pubkey)
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
}
