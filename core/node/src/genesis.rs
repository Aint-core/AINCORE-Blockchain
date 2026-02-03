use std::sync::Arc; // Force rebuild
use storage::StateDB;
use std::fs;
use move_binary_format::CompiledModule;
use std::fmt;

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
pub fn initialize_genesis(storage: &Arc<StateDB>, stdlib_path: &str, genesis_addr_hex: &str) -> Result<(), GenesisError> {
    // Check if genesis is already initialized
    match storage.get("genesis_initialized") {
        Ok(Some(_)) => {
            println!("✨ Genesis already initialized.");
            return Ok(());
        }
        _ => {}
    }

    println!("🌋 Initializing Genesis...");

    // Path relative to the workspace root (where cargo run is executed)
    // We assume running from phase1-core-prototype directory
    // let stdlib_path = "vm_move/stdlib/bytecode"; // Now passed as parameter
    
    if let Ok(entries) = fs::read_dir(stdlib_path) {
        let mut count = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("mv") {
                if let Ok(bytes) = fs::read(&path) {
                    // Parse module to get ID
                    match CompiledModule::deserialize(&bytes) {
                        Ok(module) => {
                            let id = module.self_id();
                            let key = format!("module_{}_{}", id.address(), id.name());
                            let hex_bytes = hex::encode(&bytes);
                            
                            let _ = storage.put(&key, &hex_bytes);
                            println!("   Loaded module: {}", key);
                            count += 1;
                        }
                        Err(e) => {
                            eprintln!("   ❌ Failed to deserialize module {:?}: {:?}", path, e);
                        }
                    }
                }
            }
        }
        println!("✅ Loaded {} Stdlib modules into StateDB.", count);
        
        // === Create Genesis Account ===
        // Address: genesis_addr_hex
        let genesis_addr = genesis_addr_hex;
        let genesis_pubkey = genesis_addr; // Since address is pubkey in our simple model
        
        use aa::AccountManager;
        let mut account_obj = AccountManager::create_account(genesis_addr.to_string(), genesis_pubkey.to_string());
        
        // Update balance manually (since AccountManager creates with 0)
        use aa::AccountData;
        let mut data: AccountData = serde_json::from_slice(&account_obj.data)
            ?;
        
        // ZERO PRE-MINE: Start with 0 balance.
        data.balance = 0; 
        account_obj.data = serde_json::to_vec(&data)
            ?;
        storage.put_object(&account_obj)?;
        println!("💰 Created Genesis Account: {} (Balance: {})", genesis_addr, data.balance);


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
            total_supply: u128, // Added total_supply
            current_epoch: u64, // Added current_epoch
        }

        // === GENESIS CEREMONY: SINGLE BOOTSTRAP VALIDATOR ===
        // Use the address provided via CLI (e.g., from 'node.key')
        let genesis_validators = vec![
            (genesis_addr_hex.to_string(), genesis_addr_hex.to_string()),
        ];

        let mut validator_configs = Vec::new();
        // Bootstrap stake: 1 Million AIN (1,000,000 * 10^18)
        let bootstrap_stake_per_node: u128 = 1_000_000_000_000_000_000_000_000; 
        let total_bootstrap_stake = bootstrap_stake_per_node * genesis_validators.len() as u128;

        for (addr_hex, pubkey_hex) in &genesis_validators {
            // Create Account for Validator
            let acc = AccountManager::create_account(addr_hex.to_string(), pubkey_hex.to_string());
            // Balance is 0 (Stake is locked in ValidatorSet)
            storage.put_object(&acc)?;
            println!("👤 Created Genesis Validator Account: {}", addr_hex);

            // Create Config (Move Resource)
            let bytes = hex::decode(addr_hex)?;
            let mut addr_array = [0u8; move_core_types::account_address::AccountAddress::LENGTH];
            addr_array.copy_from_slice(&bytes);
            let account_addr = move_core_types::account_address::AccountAddress::new(addr_array);

            validator_configs.push(ValidatorConfig {
                validator_addr: account_addr,
                stake: Coin { value: bootstrap_stake_per_node },
                public_key: hex::decode(pubkey_hex).unwrap_or_default(),
            });
        }
        
        // === SYNC NATIVE CONSENSUS STATE (CRITICAL FIX) ===
        // Write 'sys:validators' so the Rust Consensus Engine knows who is allowed to mine.
        // Format: Vec<(String, u64)> -> (PubKey, Weight)
        let native_validators: Vec<(String, u64)> = genesis_validators.iter()
            .map(|(addr, _)| (addr.clone(), 100)) // Weight 100
            .collect();
            
        if let Ok(json) = serde_json::to_string(&native_validators) {
            storage.put("sys:validators", &json)?;
            println!("🔗 Native Consensus State Synced: {} Validator(s)", native_validators.len());
        }

        let validator_set = ValidatorSet {
            validators: validator_configs,
            total_supply: total_bootstrap_stake, 
            current_epoch: 0,
        };

        // Key: resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::staking::ValidatorSet
        let key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::staking::ValidatorSet";
        
        // Serialize to BCS
        let bytes = bcs::to_bytes(&validator_set)
            ?;
        let hex_bytes = hex::encode(bytes);
        storage.put(key, &hex_bytes)?;
        println!("🛡️  Initialized Genesis Validator Set (Bootstrap Stake: 1 Million AIN)");

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
            epoch_duration: 10,
        };
        // Key: resource_..._0x1::epoch::Epoch
        let epoch_key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::epoch::Epoch";
        let epoch_bytes = bcs::to_bytes(&epoch)
            ?;
        storage.put(epoch_key, &hex::encode(epoch_bytes))?;
        println!("⏳ Initialized Genesis Epoch (0)");

        // === Initialize Governance ===
        #[derive(serde::Serialize)]
        struct Proposal {
            id: u64,
            proposer: move_core_types::account_address::AccountAddress,
            description: Vec<u8>,
            votes_for: u64,
            votes_against: u64,
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
        
        // Key: resource_..._0x1::governance::GovernanceState
        let gov_key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::governance::GovernanceState";
        let gov_bytes = bcs::to_bytes(&gov_state)
            ?;
        storage.put(gov_key, &hex::encode(gov_bytes))?;
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
        let dr_key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::universal_mining::DeviceRegistry";
        let dr_bytes = bcs::to_bytes(&device_registry)
            ?;
        storage.put(dr_key, &hex::encode(dr_bytes))?;

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
             let bytes = hex::decode(first_addr)
                 ?;
             let mut arr = [0u8; 16];
             arr.copy_from_slice(&bytes);
             feeders.push(move_core_types::account_address::AccountAddress::new(arr));
        }
        // Also add 0x1 itself if needed (but 0x1 usually doesn't sign transactions).
        // Let's stick to the physical validators.

        let oracle_config = OracleConfig {
            feeders,
            threshold: 1, // Start with 1/1
            active_proofs: vec![],
        };
        let oc_key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::universal_mining::OracleConfig";
        let oc_bytes = bcs::to_bytes(&oracle_config)
            ?;
        storage.put(oc_key, &hex::encode(oc_bytes))?;
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
            reserve: Coin { value: 0 }, // 0 AIN (Funded by Miners manually)
            total_sold: 0,
            price_usd_cents: 100, // $1.00 Start Price
        };
        // Key: resource_..._0x1::treasury::Treasury
        let treasury_key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::treasury::Treasury";
        let treasury_bytes = bcs::to_bytes(&treasury)
            ?;
        storage.put(treasury_key, &hex::encode(&treasury_bytes))?;
        println!("🏦 Initialized Treasury (Reserve: 50,000 AIN)");

        // === FINAL CHECK: SET TOTAL SUPPLY ===
        // Validators (1M) + Treasury (50k)
        let initial_total_supply = total_bootstrap_stake + treasury.reserve.value;
        storage.put("sys:total_supply", &initial_total_supply.to_string())?;
        println!("📊 Genesis Total Supply Tracked: {} AIN", initial_total_supply / 1_000_000_000_000_000_000);

        
        storage.put("genesis_initialized", "true")?;
        println!("✅ Genesis Initialization Complete!");
        
        Ok(())
    } else {
        Err(GenesisError::InvalidData(format!(
            "Failed to read Stdlib bytecode directory: {}. Make sure you ran the compiler tool first!",
            stdlib_path
        )))
    }
}
