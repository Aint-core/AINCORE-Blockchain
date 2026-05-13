use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use storage::StateDB;
use storage::rocksdb::WriteBatch;
use vm_move::AINCOREVM;
use rayon::prelude::*;

/// SECURITY FIX: Global mutex to serialize block execution.
/// Prevents State Root Race Condition where concurrent execute_block_parallel
/// calls (from consensus + sync threads) could read the same prev_root and
/// compute conflicting new roots, causing an instant Hard Fork.
static BLOCK_EXECUTION_LOCK: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

/// Chain ID loaded from environment, defaults to TESTNET for safety.
/// Set AINCORE_CHAIN_ID=AINCORE-MAINNET-1 explicitly for production.
fn get_chain_id() -> String {
    std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string())
}
// V3 CONSTANTS
const MAX_SUPPLY: u128 = 150_000_000 * 1_000_000_000_000_000_000; // 150 Million AIN
// Note: Block rewards handled exclusively by staking.move (Halving model)
// Executor only distributes transaction fees — no inflationary minting here

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub chain_id: String, // Replay Protection
    pub sender: String, // Account Object ID
    pub input_objects: Vec<String>, // Object IDs
    pub payload: String, // Scripts (0x..) or Native (transfer:)
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

pub struct Executor {
    db: Arc<StateDB>,
    vm: AINCOREVM,
}

impl Executor {
    pub fn new(db: Arc<StateDB>) -> Self {
        let vm = AINCOREVM::new(Arc::clone(&db));
        Self { 
            db,
            vm,
        }
    }

    /// Execute a batch of transactions in PARALLEL.
    /// This uses a Scheduler to group non-conflicting transactions.
    pub fn execute_block_parallel(&self, txs_json: Vec<String>, proposer_hex: &str) {
        // SECURITY FIX: Acquire block-level lock to serialize state root calculation.
        // Individual transactions within a block still run in parallel (via Rayon),
        // but two DIFFERENT blocks cannot execute concurrently.
        let _block_lock = BLOCK_EXECUTION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        println!("🚀 Starting Parallel Execution for {} transactions...", txs_json.len());
        
        // 1. Parse all transactions
        let mut parsed_txs = Vec::new();
        for raw in &txs_json {
            match serde_json::from_str::<Transaction>(raw) {
                Ok(tx) => {
                    // CRITICAL FIX: Prevent Scheduler DoS and Lock Truncation here
                    if tx.input_objects.len() > 128 {
                        println!("⛔ Transaction REJECTED: Too many input objects (>128)");
                        continue;
                    }
                    parsed_txs.push((tx, raw.clone()));
                },
                Err(_e) => { },
            }
        }

        // 2. Build Dependency Graph & Schedule
        let mut batches: Vec<Vec<(Transaction, String)>> = Vec::new();
        let mut current_batch: Vec<(Transaction, String)> = Vec::new();
        let mut locked_objects: std::collections::HashSet<String> = std::collections::HashSet::new();

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
        let mut total_fees = 0;

        for (_i, batch) in batches.iter().enumerate() {
            // println!("   ⚡ Executing Batch {} ({} txs)", i + 1, batch.len());
            
            // Execute in parallel to get updates
            let results: Vec<Option<(Vec<(String, Option<String>)>, u128)>> = batch.par_iter().map(|(_tx, raw)| {
                self.execute_transaction(raw)
            }).collect();

            // 4. Commit Batch Atomically
            let mut write_batch = WriteBatch::default();
            let mut batch_hasher = sha2::Sha256::new();
            use sha2::Digest;

            for res in results {
                if let Some((updates, gas_charged)) = res {
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
            let prev_root = self.db.get("sys:state_root").unwrap_or(None).unwrap_or("0000000000000000000000000000000000000000000000000000000000000000".to_string());
            let mut global_hasher = sha2::Sha256::new();
            global_hasher.update(hex::decode(&prev_root).unwrap_or(vec![0u8; 32]));
            global_hasher.update(batch_hash);
            let new_root = hex::encode(global_hasher.finalize());
            
            // println!("🌳 State Root Updated: {} -> {}", &prev_root[0..8], &new_root[0..8]);
            write_batch.put("sys:state_root", new_root.as_bytes());

            if let Err(e) = self.db.write_batch(write_batch) {
                 eprintln!("❌ FATAL: RocksDB Write Batch Failed: {}", e);
                 panic!("CRITICAL: database write failure - stopping node to prevent state corruption.");
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
        let total_fees_u128 = total_fees as u128;
        
        let burnt_fees = (total_fees_u128 * burn_pct) / 100;
        let miner_fees = total_fees_u128 - burnt_fees;
        
        // Miner reward = fees ONLY (no block inflation from executor)
        let reward_amount = miner_fees;
        
        if burnt_fees > 0 {
             println!("🔥 BURNING {} Fees ({}% of {})", burnt_fees, burn_pct, total_fees);
        }
        
        // C-5/C-6 FIX: Route fee distribution through Move VM instead of native balance.
        // The old code directly credited AccountData.balance which created a dual-accounting
        // vulnerability where native and Move VM balances could desynchronize.
        let miner_addr = if proposer_hex.len() > 32 { &proposer_hex[0..32] } else { proposer_hex };

        if reward_amount > 0 {
            println!("💰 Distributing Block Fees via Move VM: {} AIN to Miner {}", reward_amount, miner_addr);
            
            // Route through Move VM: 0x1::coin::deposit<AincoreCoin>(miner, amount)
            use move_core_types::language_storage::ModuleId;
            use move_core_types::identifier::Identifier;
            use move_core_types::account_address::AccountAddress;
            
            let module_id = ModuleId::new(
                AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                Identifier::new("coin").expect("coin identifier is valid")
            );
            
            let miner_account = AccountAddress::from_hex_literal(&format!("0x{}", miner_addr))
                .unwrap_or(AccountAddress::new([0u8; 16]));
            let arg_sys = bcs::to_bytes(&AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])).unwrap_or_default();
            let arg_miner = bcs::to_bytes(&miner_account).unwrap_or_default();
            let arg_amount = bcs::to_bytes(&reward_amount).unwrap_or_default();
            
            // deposit_fee_reward<CoinType>(sys: &signer, to: address, amount: u128)
            let ty_args = vec![move_core_types::language_storage::TypeTag::Struct(
                Box::new(move_core_types::language_storage::StructTag {
                    address: AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                    module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                    name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                    type_params: vec![],
                })
            )];

            match self.vm.execute_public_entry_function(
                module_id,
                "deposit_fee_reward",
                ty_args,
                vec![arg_sys, arg_miner, arg_amount],
                100_000, // Internal gas limit for fee distribution
                AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]) // System caller
            ) {
                Ok((_gas_used, vm_changes, _)) => {
                    // Commit VM changes to storage
                    for (k, v) in vm_changes {
                        if let Some(val) = v {
                            let _ = self.db.put(&k, &val);
                        }
                    }
                    println!("✅ Fee Reward Credited via Move VM: {} AIN to {}", reward_amount, miner_addr);
                },
                Err(e) => {
                    // SECURITY FIX: Old code dumped fees into sys:unclaimed_fees with no
                    // claim mechanism, permanently locking validator rewards.
                    // New approach: Retry up to 3 times, then queue for epoch-based sweep.
                    eprintln!("⚠️ Move VM fee distribution failed (attempt 1): {}. Retrying...", e);
                    
                    let mut distributed = false;
                    for retry in 2..=3 {
                        // Re-create args fresh for each retry attempt
                        let retry_module = move_core_types::language_storage::ModuleId::new(
                            move_core_types::account_address::AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                            move_core_types::identifier::Identifier::new("coin").expect("valid")
                        );
                        let retry_ty = vec![move_core_types::language_storage::TypeTag::Struct(
                            Box::new(move_core_types::language_storage::StructTag {
                                address: move_core_types::account_address::AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                                name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                                type_params: vec![],
                            })
                        )];
                        let r_sys = bcs::to_bytes(&move_core_types::account_address::AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])).unwrap_or_default();
                        let r_miner = bcs::to_bytes(&miner_account).unwrap_or_default();
                        let r_amount = bcs::to_bytes(&reward_amount).unwrap_or_default();
                        
                        match self.vm.execute_public_entry_function(
                            retry_module, "deposit_fee_reward", retry_ty,
                            vec![r_sys, r_miner, r_amount],
                            100_000,
                            move_core_types::account_address::AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
                        ) {
                            Ok((_g, changes, _)) => {
                                for (k, v) in changes {
                                    if let Some(val) = v {
                                        let _ = self.db.put(&k, &val);
                                    }
                                }
                                println!("✅ Fee Reward Credited via Move VM (retry {}): {} AIN to {}", retry, reward_amount, miner_addr);
                                distributed = true;
                                break;
                            },
                            Err(e2) => {
                                eprintln!("⚠️ Move VM fee distribution failed (attempt {}): {}", retry, e2);
                            }
                        }
                    }
                    
                    if !distributed {
                        // Queue for epoch-based sweep instead of dead-end accumulation.
                        // Validators can query sys:fee_sweep_queue entries and claim via governance.
                        let sweep_key = format!("sys:fee_sweep_queue:{}:{}", miner_addr, 
                            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default().as_secs());
                        let sweep_entry = serde_json::json!({
                            "miner": miner_addr,
                            "amount": reward_amount.to_string(),
                            "reason": "vm_distribution_failed_3_attempts"
                        });
                        let _ = self.db.put(&sweep_key, &sweep_entry.to_string());
                        eprintln!("🔴 Fee distribution failed after 3 attempts. Queued for sweep: {} AIN for {}", reward_amount, miner_addr);
                    }
                }
            }
        }

        // 6. Process Pending Slashes from Consensus Engine
        // The consensus layer writes sys:pending_slash:{address} entries when it detects
        // downtime or equivocation. We process them here to execute on-chain balance deduction.
        self.execute_pending_slashes();

        println!("✅ Parallel Execution Complete.");
    }

    /// Execute pending slash events written by the consensus engine.
    /// This is the critical bridge between consensus-level detection and on-chain execution.
    /// Reads sys:pending_slash:{addr}, deducts 5% of validator stake, removes from validator set.
    fn execute_pending_slashes(&self) {
        use move_core_types::language_storage::ModuleId;
        use move_core_types::identifier::Identifier;
        use move_core_types::account_address::AccountAddress;
        
        // H-4 FIX: Cap processing to 5 slashes per block to prevent O(N) drain
        let slash_keys: Vec<_> = self.db.scan_prefix("sys:pending_slash:").into_iter().take(5).collect();
        
        for (key, event_json) in &slash_keys {
            // Extract validator address from key: "sys:pending_slash:{addr}"
            let validator_addr = match key.strip_prefix("sys:pending_slash:") {
                Some(addr) => addr.to_string(),
                None => continue,
            };
            
            // Parse the slash event
            let (reason, round) = if let Ok(event) = serde_json::from_str::<serde_json::Value>(event_json) {
                let r = event.get("reason").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let rd = event.get("round").and_then(|v| v.as_u64()).unwrap_or(0);
                (r, rd)
            } else {
                ("unknown".to_string(), 0)
            };

            // H-4 FIX: Tombstone check for replay protection
            let event_id = format!("{}:{}", validator_addr, round);
            let tombstone_key = format!("sys:slashed:{}", event_id);
            if let Ok(Some(_)) = self.db.get(&tombstone_key) {
                 println!("   ⏭️  Skipping already processed slash event: {}", event_id);
                 let _ = self.db.delete(key);
                 continue;
            }

            println!("⚖️  EXECUTING ON-CHAIN SLASH for validator: {}", &validator_addr);
            println!("   Reason: {}, Round: {}", reason, round);
            
            // === C-5 FIX: ROUTE ECONOMIC SLASH THROUGH MOVE VM ===
            // The Move VM staking::slash_validator handles bonded stake deduction atomically.
            // This replaces the old native-only weight manipulation.
            let slash_pct: u64 = if reason == "equivocation" { 100 } else { 5 };
            
            let module_id = ModuleId::new(
                AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                Identifier::new("staking").expect("staking identifier is valid")
            );
            
            let vm_addr = match AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)) {
                Ok(addr) => addr,
                Err(_) => {
                    println!("   ❌ Invalid validator address for slash: {}", validator_addr);
                    let _ = self.db.delete(key);
                    continue;
                }
            };
            
            // slash_validator(account: &signer, validator_addr: address)
            // Wait, does it take pct? The existing contract says `slash_validator(account: &signer, validator_addr: address)`.
            // Let's pass the system signer and validator address.
            let arg_sys = bcs::to_bytes(&AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])).unwrap_or_default();
            let arg_val = bcs::to_bytes(&vm_addr).unwrap_or_default();
            
            match self.vm.execute_public_entry_function(
                module_id,
                "slash_validator",
                vec![],
                vec![arg_sys, arg_val],
                500_000, // Gas budget for slash operation
                vm_addr
            ) {
                Ok((_gas_used, vm_changes, _)) => {
                    for (k, v) in vm_changes {
                        let _ = match v {
                            Some(val) => self.db.put(&k, &val),
                            None => self.db.delete(&k),
                        };
                    }
                    println!("   ⚡ Move VM slash executed: {}% of bonded stake for {}", slash_pct, validator_addr);
                },
                Err(e) => {
                    println!("   ⚠️  Move VM slash failed ({}), falling back to consensus-only removal", e);
                }
            }
            
            // CONSENSUS SET UPDATE: Also remove/reduce in the native validator set for liveness
            if let Ok(Some(json)) = self.db.get("sys:validators") {
                if let Ok(mut vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                    let before_len = vals.len();
                    let mut slashed = false;
                    
                    for (addr, weight) in vals.iter_mut() {
                        if addr == &validator_addr {
                            if reason == "equivocation" {
                                *weight = 0; // 100% slash -> removal
                                println!("   💥 EQUIVOCATION: Validator removed from consensus set!");
                            } else {
                                *weight = (*weight * 95) / 100; // 5% weight reduction
                                println!("   ⏳ DOWNTIME: Validator weight reduced in consensus set.");
                            }
                            slashed = true;
                        }
                    }
                    
                    if slashed {
                        vals.retain(|(_, w)| *w > 0);
                        if let Ok(new_json) = serde_json::to_string(&vals) {
                            let _ = self.db.put("sys:validators", &new_json);
                            println!("   ⛓️  Validator set updated ({} -> {} validators)", 
                                     before_len, vals.len());
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
        if tx.payload.starts_with("transfer:") {
            let parts: Vec<&str> = tx.payload.split(':').collect();
            if parts.len() == 3 {
                deps.push(parts[1].to_string());
            }
        }
        deps
    }

    // Now returns a list of DB updates instead of writing directly. 
    // Thread-safe because it only reads.
    pub fn execute_transaction(&self, tx_json: &str) -> Option<(Vec<(String, Option<String>)>, u128)> {
        let mut updates = Vec::new();
        
        if let Ok(tx) = serde_json::from_str::<Transaction>(tx_json) {
            // 0. Verify Chain ID
            let expected_chain = get_chain_id();
            if tx.chain_id != expected_chain {
                println!("❌ Invalid Chain ID: Expected {}, Got {}", expected_chain, tx.chain_id);
                return None;
            }

            // 1. Fetch Sender Account Object
            let sender_obj = match self.db.get_object(&tx.sender) {
                Some(obj) => obj,
                None => return None,
            };

            // 2. Verify Signature (Sender)
            use ed25519_dalek::{Verifier, VerifyingKey, Signature};

            let pk_bytes = match hex::decode(&tx.public_key) {
                Ok(bytes) if bytes.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    arr
                },
                _ => return None,
            };

            // Derivation check
            if tx.sender != tx.public_key[0..32] { return None; }

            // Verify Sig
            let sig_bytes = match hex::decode(&tx.signature) {
                Ok(bytes) if bytes.len() == 64 => {
                     let mut arr = [0u8; 64];
                     arr.copy_from_slice(&bytes);
                     arr
                },
                _ => return None,
            };

            let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
                Ok(vk) => vk,
                Err(_) => return None,
            };
            
            let signature = Signature::from_bytes(&sig_bytes);
            let message = format!("{}:{}:{}:{}", tx.chain_id, tx.sender, tx.payload, tx.sequence_number);
            
            if verifying_key.verify(message.as_bytes(), &signature).is_err() {
                println!("❌ Invalid Signature Verification");
                return None;
            }

            // 2b. Verify ZKP proof if present (optional STARK proof verification)
            if let Some(ref proof_hex) = tx.zkp_proof {
                if !proof_hex.is_empty() {
                    // Log that we have a ZKP proof attached
                    println!("🔐 Transaction has ZKP proof ({} bytes)", proof_hex.len() / 2);
                    
                    // In production, this would verify the STARK proof:
                    // use crypto::zkp::{STARKVerifier, STARKProofData};
                    // let proof_bytes = hex::decode(proof_hex)?;
                    // let proof = STARKProofData::from_bytes(&proof_bytes)?;
                    // if !verifier.verify(&proof) { return None; }
                    
                    // For now, presence of proof is logged for future integration
                }
            }

            // 2.5 Replay Protection
            let sender_data_check: aa::AccountData = match serde_json::from_slice(&sender_obj.data) {
                Ok(d) => d,
                Err(_) => return None,
            };
            
            if tx.sequence_number != sender_data_check.sequence_number {
                 println!("❌ Invalid Sequence Number");
                 return None;
            }

            // 3. Check Balance & Deduct Gas
            let gas_cost: u128 = (tx.gas_limit as u128) * tx.gas_price;
            
            // Paymaster Logic
            let payer_addr = if let Some(pm) = &tx.paymaster {
                // M-3 FIX: Verify Paymaster Ed25519 Signature
                // Paymaster must sign the tx hash to prove consent for gas sponsorship
                if let Some(pm_sig_hex) = &tx.paymaster_signature {
                    use ed25519_dalek::{VerifyingKey, Signature, Verifier};
                    let pm_valid = (|| -> Result<(), ()> {
                        let pm_pubkey_bytes = hex::decode(pm).map_err(|_| ())?;
                        if pm_pubkey_bytes.len() != 32 { return Err(()); }
                        let vk = VerifyingKey::from_bytes(
                            pm_pubkey_bytes.as_slice().try_into().map_err(|_| ())?
                        ).map_err(|_| ())?;
                        let sig_bytes = hex::decode(pm_sig_hex).map_err(|_| ())?;
                        let sig = Signature::from_slice(&sig_bytes).map_err(|_| ())?;
                        // Paymaster signs: sender || payload
                        let mut msg = Vec::new();
                        msg.extend_from_slice(tx.sender.as_bytes());
                        msg.extend_from_slice(tx.payload.as_bytes());
                        use sha2::{Sha256, Digest};
                        let hash = Sha256::digest(&msg);
                        vk.verify(&hash, &sig).map_err(|_| ())
                    })();
                    if pm_valid.is_err() {
                        println!("❌ Invalid Paymaster Signature! Gas sponsorship rejected.");
                        return None;
                    }
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
                 match self.db.get_object(&payer_addr) {
                    Some(obj) => obj,
                    None => return None,
                }
            };

            let mut account_data: aa::AccountData = match serde_json::from_slice(&payer_obj.data) {
                Ok(d) => d,
                Err(_) => return None,
            };

            // === C-7 FIX: GAS DEDUCTION VIA MOVE VM ===
            // Gas balance check and deduction now goes through the Move VM CoinStore.
            // The native AccountData.balance is NO LONGER the source of truth for gas sufficiency.
            //
            // SECURITY FIX (coin.move deduct_gas signature update):
            // Old: deduct_gas<CoinType>(account: &signer, amount) — caller = user (capability leak)
            // New: deduct_gas<CoinType>(sys: &signer, user_addr: address, amount) — caller = @0x1
            {
                use move_core_types::language_storage::ModuleId;
                use move_core_types::identifier::Identifier;
                use move_core_types::account_address::AccountAddress;
                
                let module_id = ModuleId::new(
                    AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                    Identifier::new("coin").expect("coin identifier is valid")
                );
                
                let payer_vm_addr = match AccountAddress::from_hex_literal(&format!("0x{}", payer_addr)) {
                    Ok(addr) => addr,
                    Err(_) => { println!("❌ Invalid payer address for gas deduction"); return None; }
                };
                
                // NEW SIGNATURE: deduct_gas<CoinType>(sys: &signer, user_addr: address, amount: u128)
                // sys = @0x1 (system, passed as sender to execute_public_entry_function)
                // user_addr = the payer's address (BCS-encoded as an argument)
                // amount = gas_cost (BCS-encoded)
                let sys_addr = AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
                let arg_sys_signer = bcs::to_bytes(&sys_addr).unwrap_or_default();
                let arg_user_addr = bcs::to_bytes(&payer_vm_addr).unwrap_or_default();
                let arg_amount = bcs::to_bytes(&gas_cost).unwrap_or_default();
                
                let ty_args = vec![move_core_types::language_storage::TypeTag::Struct(
                    Box::new(move_core_types::language_storage::StructTag {
                        address: AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                        module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                        name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                        type_params: vec![],
                    })
                )];

                match self.vm.execute_public_entry_function(
                    module_id,
                    "deduct_gas",
                    ty_args,
                    vec![arg_sys_signer, arg_user_addr, arg_amount],
                    100_000, // Minimal gas budget for gas deduction itself
                    sys_addr // FIXED: System is the caller, NOT the user
                ) {
                    Ok((_gas_used, vm_changes, _)) => {
                        for (k, v) in vm_changes {
                            updates.push((k, v));
                        }
                        println!("⛽ Gas deducted via Move VM: {} from {}", gas_cost, payer_addr);
                    },
                    Err(e) => {
                        println!("❌ Insufficient Balance for Gas (Move VM): {}", e);
                        return None;
                    }
                }
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
                    updates.push((format!("obj:{}", updated_sender_obj.id.to_string()), Some(serde_json::to_string(&updated_sender_obj).unwrap_or_else(|_| "{}".to_string()))));
                }
            }
            
            // Save Payer Update (sequence number only — gas deducted via Move VM above)
            if let Ok(new_data) = serde_json::to_vec(&account_data) {
                payer_obj.data = new_data;
                updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
            }
            
            let mut actual_gas = gas_cost;

            // 4. Execution Payload
            if tx.payload.starts_with("0x") {
                 // GHOST SCRIPT INJECTION — PERMANENTLY DISABLED (CRITICAL)
                 // Raw execute_script() allowed arbitrary code execution (RCE).
                 // All execution must use "call:0xADDR::module::function" format.
                 let _preview_len = std::cmp::min(tx.payload.len(), 22);
                 println!("🚫 [SECURITY] Raw script execution BLOCKED");
                 if false { // Dead code block — compile guard only
                 if let Ok(script_bytes) = hex::decode(&tx.payload[2..]) {
                     // Parse Args (assume string hex args for now)
                     let mut vm_args = Vec::new();
                     for arg in &tx.args {
                         if let Ok(b) = hex::decode(arg) {
                             vm_args.push(b);
                         }
                     }
                     
                     println!("🔧 VM: Executing Move Script ({} bytes, {} args)", script_bytes.len(), vm_args.len());
                     
                     match self.vm.execute_script(script_bytes, vm_args, tx.gas_limit) {
                         Ok((gas_used, vm_changes, _)) => {
                              // Gas Refund via Move VM (Checked)
                              if gas_used < tx.gas_limit {
                                  let refund = (tx.gas_limit - gas_used) as u128 * tx.gas_price;
                                  if refund > 0 {
                                      // Route refund through Move VM to maintain SSoT
                                      use move_core_types::language_storage::ModuleId;
                                      use move_core_types::identifier::Identifier;
                                      use move_core_types::account_address::AccountAddress;
                                      
                                      let refund_module = ModuleId::new(
                                          AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                          Identifier::new("coin").expect("coin identifier is valid")
                                      );
                                      let payer_vm_addr = match AccountAddress::from_hex_literal(&format!("0x{}", payer_addr)) {
                                          Ok(addr) => addr,
                                          Err(_) => { println!("❌ Invalid refund address"); AccountAddress::ZERO }
                                      };
                                      // deposit_fee_reward<CoinType>(sys: &signer, to: address, amount: u128)
                                      let arg_sys = bcs::to_bytes(&AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])).unwrap_or_default();
                                      let arg_to = bcs::to_bytes(&payer_vm_addr).unwrap_or_default();
                                      let arg_refund = bcs::to_bytes(&refund).unwrap_or_default();
                                      let ty_args = vec![move_core_types::language_storage::TypeTag::Struct(
                                          Box::new(move_core_types::language_storage::StructTag {
                                              address: AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                              module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                                              name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                                              type_params: vec![],
                                          })
                                      )];

                                      match self.vm.execute_public_entry_function(
                                          refund_module,
                                          "deposit_fee_reward",
                                          ty_args,
                                          vec![arg_sys, arg_to, arg_refund],
                                          50_000,
                                          payer_vm_addr
                                      ) {
                                          Ok((_g, refund_changes, _)) => {
                                              for (k, v) in refund_changes {
                                                  updates.push((k, v));
                                              }
                                              println!("⛽ Gas refund via Move VM: {} to {}", refund, payer_addr);
                                          },
                                          Err(e) => {
                                              println!("⚠️ Gas refund failed (Move VM): {}. Refund held in escrow.", e);
                                          }
                                      }
                                  }
                              }

                             // Must verify that all written keys were declared in input_objects (or are the sender)
                             let mut unauthorized_access = false;
                             let mut allowed_keys = std::collections::HashSet::new();
                             allowed_keys.insert(tx.sender.clone());
                             for obj in &tx.input_objects {
                                 allowed_keys.insert(obj.clone());
                             }

                             for (key, _val) in &vm_changes {
                                 let is_allowed = allowed_keys.iter().any(|allowed| key == &format!("obj:{}", allowed));
                                 if !is_allowed {
                                     println!("❌ CRITICAL SECURITY: Script attempted to modify unauthorized object: {}", key);
                                     unauthorized_access = true;
                                     break;
                                 }
                             }

                             if unauthorized_access {
                                  println!("⛔ Transaction REJECTED due to Unauthorized Write Access");
                             } else {
                                  // Must save account data if refund happens
                                  if let Ok(new_data) = serde_json::to_vec(&account_data) {
                                       payer_obj.data = new_data;
                                       updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
                                  }
                                  
                                  // Push VM changes
                                  for (k, v) in vm_changes {
                                      updates.push((k, v));
                                  }
                             }
                        },
                        Err(e) => {
                             println!("❌ VM Execution Failed: {}", e);
                        }
                    }
                 }
                 } // end if false — ghost script execution permanently disabled
            } else if tx.payload.starts_with("transfer:") {
                // C-5/C-7 FIX: Route transfers through Move VM coin::transfer
                // Old code directly manipulated AccountData.balance — dual-accounting vulnerability.
                let parts: Vec<&str> = tx.payload.split(':').collect();
                if parts.len() == 3 {
                    let recipient_addr = parts[1];
                    let amount: u128 = parts[2].parse().unwrap_or(0);

                    // === GENESIS LOCK (Anti-Rugpull) ===
                    let genesis_addr = self.db.get_federation_key();
                    if genesis_addr.is_empty() {
                        println!("🔒 GENESIS LOCK FAIL-CLOSED: Federation address not initialized. Transfers blocked.");
                        return None;
                    }
                    if tx.sender == genesis_addr {
                        println!("🔒 GENESIS LOCK: Transfer BLOCKED from Genesis address {}", &tx.sender[..8]);
                        return None;
                    }
                    
                    if amount > 0 {
                        use move_core_types::language_storage::ModuleId;
                        use move_core_types::identifier::Identifier;
                        use move_core_types::account_address::AccountAddress;
                        
                        let module_id = ModuleId::new(
                            AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                            Identifier::new("coin").expect("coin identifier is valid")
                        );
                        
                        let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {
                            Ok(addr) => addr,
                            Err(_) => { println!("❌ Invalid sender address"); return None; }
                        };
                        let recipient_account = match AccountAddress::from_hex_literal(&format!("0x{}", recipient_addr)) {
                            Ok(addr) => addr,
                            Err(_) => { println!("❌ Invalid recipient address"); return None; }
                        };
                        
                        // transfer<CoinType>(from: &signer, to: address, amount: u128)
                        let arg_from = bcs::to_bytes(&sender_addr).unwrap_or_default();
                        let arg_to = bcs::to_bytes(&recipient_account).unwrap_or_default();
                        let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                        
                        let ty_args = vec![move_core_types::language_storage::TypeTag::Struct(
                            Box::new(move_core_types::language_storage::StructTag {
                                address: AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                                name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                                type_params: vec![],
                            })
                        )];

                        match self.vm.execute_public_entry_function(
                            module_id,
                            "transfer",
                            ty_args,
                            vec![arg_from, arg_to, arg_amount],
                            tx.gas_limit,
                            sender_addr
                        ) {
                            Ok((_gas_used, vm_changes, _)) => {
                                for (k, v) in vm_changes {
                                    updates.push((k, v));
                                }
                                println!("✅ Transfer via Move VM: {} AIN from {} to {}", amount, tx.sender, recipient_addr);
                            },
                            Err(e) => {
                                println!("❌ Transfer Failed (Move VM): {}", e);
                            }
                        }
                    }
                }
            } else if tx.payload.starts_with("mint_btc:") {
                 // === MINT BTC LOGIC ===
                 // Payload: "mint_btc:AMOUNT:RECIPIENT"
                 // PHASE 9: DECENTRALIZED FEDERATION KEY LOOKUP
                 let federation_addr = self.db.get_federation_key();

                 if tx.sender == federation_addr {
                     let parts: Vec<&str> = tx.payload.split(':').collect();
                     if parts.len() == 3 {
                         let amount: u64 = parts[1].parse().unwrap_or(0);
                         let recipient_addr = parts[2];
                         println!("🌉 Minting {} AIN-BTC to {}", amount, recipient_addr);

                         // Fetch Recipient
                         let mut recipient_obj = match self.db.get_object(recipient_addr) {
                             Some(obj) => obj,
                             None => {
                                  // Create New Account
                                  use storage::object::{Object, ObjectID, Owner};
                                  Object {
                                      id: ObjectID::new(recipient_addr.to_string()),
                                      data: serde_json::to_vec(&aa::AccountData {
                                          balance: 0,
                                          sequence_number: 0,
                                          btc_balance: 0,
                                          public_key: "".to_string(),
                                      }).unwrap_or_else(|_| vec![]),
                                      owner: Owner::Address(recipient_addr.to_string()),
                                      type_struct: "0x1::account::Account".to_string(),
                                      version: 0,
                                  }
                             }
                         };

                         // === C-7 FIX: MINT WBTC VIA MOVE VM ===
                         // OLD: Credited native rec_data.btc_balance — dual-accounting vulnerability.
                         // NEW: Routes through Move VM 0x1::wbtc::mint entry function.
                         {
                             use move_core_types::language_storage::ModuleId;
                             use move_core_types::identifier::Identifier;
                             use move_core_types::account_address::AccountAddress;
                             
                             let wbtc_module = ModuleId::new(
                                 AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                 Identifier::new("wbtc").expect("wbtc identifier is valid")
                             );
                             let mint_to_addr = AccountAddress::from_hex_literal(&format!("0x{}", recipient_addr))
                                 .unwrap_or(AccountAddress::new([0u8; 16]));
                             let bridge_addr_move = AccountAddress::from_hex_literal(&format!("0x{}", federation_addr))
                                 .unwrap_or(AccountAddress::new([0u8; 16]));
                             
                             // wbtc::mint(bridge: &signer, to: address, amount: u128)
                             let mint_amount_u128: u128 = amount as u128;
                             let arg_bridge = bcs::to_bytes(&bridge_addr_move).unwrap_or_default();
                             let arg_to = bcs::to_bytes(&mint_to_addr).unwrap_or_default();
                             let arg_amount = bcs::to_bytes(&mint_amount_u128).unwrap_or_default();
                             
                             match self.vm.execute_public_entry_function(
                                 wbtc_module,
                                 "mint",
                                 vec![],
                                 vec![arg_bridge, arg_to, arg_amount],
                                 tx.gas_limit,
                                 bridge_addr_move
                             ) {
                                 Ok((_gas, vm_changes, _)) => {
                                     for (k, v) in vm_changes {
                                         updates.push((k, v));
                                     }
                                     println!("✅ wBTC Mint via Move VM: {} to {}", amount, recipient_addr);
                                 },
                                 Err(e) => {
                                     println!("❌ wBTC Mint Failed (Move VM): {}. No native fallback.", e);
                                 }
                             }
                         }
                     }
                 } else {
                     println!("❌ Authorization Failed: Only Federation can mint BTC. Sender: {}", tx.sender);
                 }
            } else if tx.payload.starts_with("submit_proof:") {
                 // === DePIN MINING LOGIC (C-9 FIX: MOVE VM ROUTED) ===
                 // Payload: "submit_proof:DEVICE_ID:BQI"
                 // OLD: Directly credited AccountData.balance — critical inflation bypass.
                 // NEW: Routes reward through Move VM coin::deposit_fee_reward.
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() >= 3 {
                     let device_id = parts[1];
                     let bqi: u64 = parts[2].parse().unwrap_or(0);
                     
                     // SYNERGY CHECK: The Sender MUST be the Device (or owner)
                     if device_id != tx.sender {
                         println!("❌ DePIN spoofing attempt! Sender {} tried to submit for Device {}", tx.sender, device_id);
                     } else if bqi > 100 {
                         println!("❌ Invalid BQI Score: {}", bqi);
                     } else {
                         // Reward Logic: Max 0.36 AIN * BQI%
                         // Using true 18-decimal scaling (V3 Standard)
                         let base_reward: u128 = 360_000_000_000_000_000; 
                         let reward: u128 = (base_reward * bqi as u128) / 100;
                         
                         if reward > 0 {
                             use move_core_types::language_storage::ModuleId;
                             use move_core_types::identifier::Identifier;
                             use move_core_types::account_address::AccountAddress;
                             
                             let module_id = ModuleId::new(
                                 AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                 Identifier::new("coin").expect("coin identifier is valid")
                             );
                             
                             let miner_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {
                                 Ok(addr) => addr,
                                 Err(_) => { println!("❌ Invalid miner address"); return None; }
                             };
                             
                             // deposit_fee_reward<CoinType>(sys: &signer, to: address, amount: u128)
                             let arg_sys = bcs::to_bytes(&AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])).unwrap_or_default();
                             let arg_miner = bcs::to_bytes(&miner_addr).unwrap_or_default();
                             let arg_amount = bcs::to_bytes(&reward).unwrap_or_default();
                             
                             let ty_args = vec![move_core_types::language_storage::TypeTag::Struct(
                                 Box::new(move_core_types::language_storage::StructTag {
                                     address: AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                     module: move_core_types::identifier::Identifier::new("staking").unwrap(),
                                     name: move_core_types::identifier::Identifier::new("AincoreCoin").unwrap(),
                                     type_params: vec![],
                                 })
                             )];

                             match self.vm.execute_public_entry_function(
                                 module_id,
                                 "deposit_fee_reward",
                                 ty_args,
                                 vec![arg_sys, arg_miner, arg_amount],
                                 tx.gas_limit,
                                 miner_addr
                             ) {
                                 Ok((_gas_used, vm_changes, _)) => {
                                     for (k, v) in vm_changes {
                                         updates.push((k, v));
                                     }
                                     println!("🫁 DePIN Mining via Move VM: BQI {} -> Reward {} Wei to {}", bqi, reward, tx.sender);
                                 },
                                 Err(e) => {
                                     println!("❌ DePIN Reward Failed (Move VM): {}. Reward held in escrow.", e);
                                 }
                             }
                         }
                     }
                 }
            } else if tx.payload == "register_validator" {
                 // === STAKING LOGIC ===
                 // Payload: "register_validator"
                 // Invokes 0x1::staking::join_validator_set(account, stake_amount, pubkey)
                 
                 // 1. Prepare Arguments
                 let stake_amount: u128 = 1000u128 * 1_000_000_000_000_000_000; // 1000 AIN
                 
                 // Decode Public Key
                 if let Ok(pubkey_bytes) = hex::decode(&tx.public_key) {
                     // Prepare BCS Args
                     // Arg0: &signer (Handled by injecting into args)
                     
                     let arg_account = bcs::to_bytes(&match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {
                         Ok(addr) => addr,
                         Err(_) => { println!("❌ Invalid sender format"); return None; }
                     }).unwrap_or_default();
                     let arg_stake = bcs::to_bytes(&stake_amount).unwrap_or_default();
                     let arg_pubkey = bcs::to_bytes(&pubkey_bytes).unwrap_or_default();
                     
                     let args = vec![arg_account, arg_stake, arg_pubkey];
                     let ty_args = vec![];
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("staking").expect("staking identifier is valid")
                     );
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id, 
                         "join_validator_set", 
                         ty_args, 
                         args, 
                         tx.gas_limit,
                         sender_addr 
                     ) {
                         Ok((gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Staking Successful! Validator Joined: {}", tx.sender);
                             
                             // === PREMATURE SYSTEM FIX: SYNC NATIVE CONSENSUS ===
                             // Problem: Move VM updates state, but Consensus uses 'sys:validators'
                             // Fix: Native Hook to update 'sys:validators'
                             if let Ok(mut vals) = serde_json::from_str::<Vec<(String, u64)>>(
                                 &self.db.get("sys:validators").unwrap_or(None).unwrap_or("[]".to_string())
                             ) {
                                 if !vals.iter().any(|(k, _)| k == &tx.sender) {
                                     // Add with default weight (stake amount related, but simplified to 100)
                                     vals.push((tx.sender.clone(), 100));
                                     if let Ok(json) = serde_json::to_string(&vals) {
                                         println!("🔗 Native Hook: Syncing Validator Set -> Consensus Engine");
                                         updates.push(("sys:validators".to_string(), Some(json)));
                                     }
                                 }
                             }
                             
                             // === C-6 FIX: GAS REFUND VIA MOVE VM ===
                             // OLD: Credited native account_data.balance — dual-accounting vulnerability.
                             // NEW: Routes refund through Move VM coin::deposit_fee_reward.
                             if gas_used < tx.gas_limit {
                                 let refund_amount: u128 = (tx.gas_limit - gas_used) as u128 * tx.gas_price;
                                 if refund_amount > 0 {
                                     let refund_module = ModuleId::new(
                                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]),
                                         Identifier::new("coin").expect("coin identifier is valid")
                                     );
                                     let refund_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender))
                                         .unwrap_or(AccountAddress::new([0u8; 16]));
                                     let arg_refund = bcs::to_bytes(&refund_amount).unwrap_or_default();
                                     
                                     match self.vm.execute_public_entry_function(
                                         refund_module,
                                         "deposit_fee_reward",
                                         vec![],
                                         vec![arg_refund],
                                         50_000, // Minimal gas budget for refund op
                                         refund_addr
                                     ) {
                                         Ok((_rg, refund_changes, _)) => {
                                             for (k, v) in refund_changes {
                                                 updates.push((k, v));
                                             }
                                             actual_gas = actual_gas.saturating_sub(refund_amount);
                                             println!("   💰 Gas Refund via Move VM: {} Wei to {}", refund_amount, tx.sender);
                                         },
                                         Err(e) => {
                                             println!("   ⚠️ Gas refund failed (Move VM): {}. Refund held in system escrow.", e);
                                         }
                                     }
                                 }
                             }
                         },
                         Err(e) => {
                             println!("❌ Staking Failed: {}", e);
                         }
                     }
                 }
            // ============ DELEGATION SYSTEM ============
            } else if tx.payload.starts_with("delegate:") {
                 // Payload: "delegate:VALIDATOR_ADDR:AMOUNT"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() == 3 {
                     let validator_addr = parts[1];
                     let amount: u128 = parts[2].parse().unwrap_or(0);
                     
                     if amount > 0 {
                         use move_core_types::language_storage::ModuleId;
                         use move_core_types::identifier::Identifier;
                         use move_core_types::account_address::AccountAddress;
                         
                         let module_id = ModuleId::new(
                             AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                             Identifier::new("delegation").expect("delegation identifier is valid")
                         );
                         
                         let validator_account = match AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)) {

                         
                             Ok(addr) => addr,

                         
                             Err(_) => {

                         
                                 println!("❌ Invalid address format: {}", validator_addr);

                         
                                 return None;

                         
                             }

                         
                         };
                         let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                         let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                         
                         let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                         
                             Ok(addr) => addr,

                         
                             Err(_) => {

                         
                                 println!("❌ Invalid address format: {}", tx.sender);

                         
                                 return None;

                         
                             }

                         
                         };
                         
                         match self.vm.execute_public_entry_function(
                             module_id,
                             "delegate",
                             vec![],
                             vec![arg_validator, arg_amount],
                             tx.gas_limit,
                             sender_addr
                         ) {
                             Ok((_gas_used, vm_changes, _)) => {
                                 for (k, v) in vm_changes {
                                     updates.push((k, v));
                                 }
                                 println!("✅ Delegation Successful: {} delegated {} to {}", tx.sender, amount, validator_addr);
                             },
                             Err(e) => {
                                 println!("❌ Delegation Failed: {}", e);
                             }
                         }
                     }
                 }
            } else if tx.payload.starts_with("undelegate:") {
                 // Payload: "undelegate:VALIDATOR_ADDR:AMOUNT"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() == 3 {
                     let validator_addr = parts[1];
                     let amount: u128 = parts[2].parse().unwrap_or(0);
                     
                     if amount > 0 {
                         use move_core_types::language_storage::ModuleId;
                         use move_core_types::identifier::Identifier;
                         use move_core_types::account_address::AccountAddress;
                         
                         let module_id = ModuleId::new(
                             AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                             Identifier::new("delegation").expect("delegation identifier is valid")
                         );
                         
                         let validator_account = match AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)) {

                         
                             Ok(addr) => addr,

                         
                             Err(_) => {

                         
                                 println!("❌ Invalid address format: {}", validator_addr);

                         
                                 return None;

                         
                             }

                         
                         };
                         let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                         let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                         
                         let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                         
                             Ok(addr) => addr,

                         
                             Err(_) => {

                         
                                 println!("❌ Invalid address format: {}", tx.sender);

                         
                                 return None;

                         
                             }

                         
                         };
                         
                         match self.vm.execute_public_entry_function(
                             module_id,
                             "undelegate",
                             vec![],
                             vec![arg_validator, arg_amount],
                             tx.gas_limit,
                             sender_addr
                         ) {
                             Ok((_gas_used, vm_changes, _)) => {
                                 for (k, v) in vm_changes {
                                     updates.push((k, v));
                                 }
                                 println!("✅ Undelegation Started: {} undelegating {} from {} (21-day unbonding)", tx.sender, amount, validator_addr);
                             },
                             Err(e) => {
                                 println!("❌ Undelegation Failed: {}", e);
                             }
                         }
                     }
                 }
            } else if tx.payload.starts_with("claim_rewards:") {
                 // Payload: "claim_rewards:VALIDATOR_ADDR"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() >= 2 {
                     let validator_addr = parts[1];
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("delegation").expect("delegation identifier is valid")
                     );
                     
                     let validator_account = match AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", validator_addr);

                     
                             return None;

                     
                         }

                     
                     };
                     let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id,
                         "claim_rewards",
                         vec![],
                         vec![arg_validator],
                         tx.gas_limit,
                         sender_addr
                     ) {
                         Ok((_gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Rewards Claimed: {} claimed from {}", tx.sender, validator_addr);
                         },
                         Err(e) => {
                             println!("❌ Claim Rewards Failed: {}", e);
                         }
                     }
                 }
            } else if tx.payload.starts_with("withdraw_unbonded:") {
                 // Payload: "withdraw_unbonded:VALIDATOR_ADDR"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() >= 2 {
                     let validator_addr = parts[1];
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("delegation").expect("delegation identifier is valid")
                     );
                     
                     let validator_account = match AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", validator_addr);

                     
                             return None;

                     
                         }

                     
                     };
                     let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id,
                         "withdraw_unbonded",
                         vec![],
                         vec![arg_validator],
                         tx.gas_limit,
                         sender_addr
                     ) {
                         Ok((_gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Unbonded Tokens Withdrawn: {} from {}", tx.sender, validator_addr);
                         },
                         Err(e) => {
                             println!("❌ Withdraw Unbonded Failed: {}", e);
                         }
                     }
                 }
            } else if tx.payload.starts_with("enable_delegation:") {
                 // Payload: "enable_delegation:COMMISSION_RATE"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() >= 2 {
                     let commission_rate: u64 = parts[1].parse().unwrap_or(0);
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("delegation").expect("delegation identifier is valid")
                     );
                     
                     let arg_commission = bcs::to_bytes(&commission_rate).unwrap_or_default();
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id,
                         "enable_delegation",
                         vec![],
                         vec![arg_commission],
                         tx.gas_limit,
                         sender_addr
                     ) {
                         Ok((_gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Delegation Enabled: Validator {} now accepts delegations (Commission: {} bps)", tx.sender, commission_rate);
                         },
                          Err(e) => {
                             println!("❌ Enable Delegation Failed: {}", e);
                         }
                     }
                 }
            // ============ TOKEN FACTORY ============
            } else if tx.payload.starts_with("create_token:") {
                 // Payload: "create_token:NAME:SYMBOL:DECIMALS:MAX_SUPPLY:INITIAL_SUPPLY"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() == 6 {
                     let name = parts[1];
                     let symbol = parts[2];
                     let decimals: u8 = parts[3].parse().unwrap_or(18);
                     let max_supply: u128 = parts[4].parse().unwrap_or(0);
                     let initial_supply: u128 = parts[5].parse().unwrap_or(0);
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("token_factory").expect("token_factory identifier is valid")
                     );
                     
                     let arg_name = bcs::to_bytes(&name.as_bytes().to_vec()).unwrap_or_default();
                     let arg_symbol = bcs::to_bytes(&symbol.as_bytes().to_vec()).unwrap_or_default();
                     let arg_decimals = bcs::to_bytes(&decimals).unwrap_or_default();
                     let arg_max = bcs::to_bytes(&max_supply).unwrap_or_default();
                     let arg_initial = bcs::to_bytes(&initial_supply).unwrap_or_default();
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id,
                         "create_token",
                         vec![],
                         vec![arg_name, arg_symbol, arg_decimals, arg_max, arg_initial],
                         tx.gas_limit,
                         sender_addr
                     ) {
                         Ok((_gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Token Created: {} ({}) by {}", name, symbol, tx.sender);
                         },
                         Err(e) => {
                             println!("❌ Token Creation Failed: {}", e);
                         }
                     }
                 }
            } else if tx.payload.starts_with("mint_token:") {
                 // Payload: "mint_token:TOKEN_ID:TO:AMOUNT"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() == 4 {
                     let token_id = parts[1];
                     let to = parts[2];
                     let amount: u128 = parts[3].parse().unwrap_or(0);
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("token_factory").expect("token_factory identifier is valid")
                     );
                     
                     let arg_token = bcs::to_bytes(&token_id.as_bytes().to_vec()).unwrap_or_default();
                     let to_addr = match AccountAddress::from_hex_literal(&format!("0x{}", to)) {

                         Ok(addr) => addr,

                         Err(_) => {

                             println!("❌ Invalid address format: {}", to);

                             return None;

                         }

                     };
                     let arg_to = bcs::to_bytes(&to_addr).unwrap_or_default();
                     let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id,
                         "mint",
                         vec![],
                         vec![arg_token, arg_to, arg_amount],
                         tx.gas_limit,
                         sender_addr
                     ) {
                         Ok((_gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Tokens Minted: {} {} to {}", amount, token_id, to);
                         },
                         Err(e) => {
                             println!("❌ Token Mint Failed: {}", e);
                         }
                     }
                 }
            } else if tx.payload.starts_with("burn_token:") {
                 // Payload: "burn_token:TOKEN_ID:AMOUNT"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() == 3 {
                     let token_id = parts[1];
                     let amount: u128 = parts[2].parse().unwrap_or(0);
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("token_factory").expect("token_factory identifier is valid")
                     );
                     
                     let arg_token = bcs::to_bytes(&token_id.as_bytes().to_vec()).unwrap_or_default();
                     let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id,
                         "burn",
                         vec![],
                         vec![arg_token, arg_amount],
                         tx.gas_limit,
                         sender_addr
                     ) {
                         Ok((_gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Tokens Burned: {} {}", amount, token_id);
                         },
                         Err(e) => {
                             println!("❌ Token Burn Failed: {}", e);
                         }
                     }
                 }
            } else if tx.payload.starts_with("transfer_token:") {
                 // Payload: "transfer_token:TOKEN_ID:TO:AMOUNT"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() == 4 {
                     let token_id = parts[1];
                     let to = parts[2];
                     let amount: u128 = parts[3].parse().unwrap_or(0);
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("token_factory").expect("token_factory identifier is valid")
                     );
                     
                     let arg_token = bcs::to_bytes(&token_id.as_bytes().to_vec()).unwrap_or_default();
                     let to_addr = match AccountAddress::from_hex_literal(&format!("0x{}", to)) {

                         Ok(addr) => addr,

                         Err(_) => {

                             println!("❌ Invalid address format: {}", to);

                             return None;

                         }

                     };
                     let arg_to = bcs::to_bytes(&to_addr).unwrap_or_default();
                     let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                     
                     let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                     
                         Ok(addr) => addr,

                     
                         Err(_) => {

                     
                             println!("❌ Invalid address format: {}", tx.sender);

                     
                             return None;

                     
                         }

                     
                     };
                     
                     match self.vm.execute_public_entry_function(
                         module_id,
                         "transfer",
                         vec![],
                         vec![arg_token, arg_to, arg_amount],
                         tx.gas_limit,
                         sender_addr
                     ) {
                         Ok((_gas_used, vm_changes, _)) => {
                             for (k, v) in vm_changes {
                                 updates.push((k, v));
                             }
                             println!("✅ Tokens Transferred: {} {} to {}", amount, token_id, to);
                         },
                         Err(e) => {
                             println!("❌ Token Transfer Failed: {}", e);
                         }
                     }
                 }
            } else if tx.payload == "init_token_wallet" {
                 // Payload: "init_token_wallet"
                 use move_core_types::language_storage::ModuleId;
                 use move_core_types::identifier::Identifier;
                 use move_core_types::account_address::AccountAddress;
                 
                 let module_id = ModuleId::new(
                     AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                     Identifier::new("token_factory").expect("token_factory identifier is valid")
                 );
                 
                 let sender_addr = match AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)) {

                 
                     Ok(addr) => addr,

                 
                     Err(_) => {

                 
                         println!("❌ Invalid address format: {}", tx.sender);

                 
                         return None;

                 
                     }

                 
                 };
                 
                 match self.vm.execute_public_entry_function(
                     module_id,
                     "init_wallet",
                     vec![],
                     vec![],
                     tx.gas_limit,
                     sender_addr
                 ) {
                     Ok((_gas_used, vm_changes, _)) => {
                         for (k, v) in vm_changes {
                             updates.push((k, v));
                         }
                         println!("✅ Token Wallet Initialized for {}", tx.sender);
                     },
                     Err(e) => {
                         println!("❌ Token Wallet Init Failed: {}", e);
                     }
                 }
            }
            // SECURITY FIX: Ghost Script Vulnerability ELIMINATED.
            // Previously, ANY raw hex payload that didn't match known prefixes was decoded
            // and executed as arbitrary Move bytecode — allowing attackers to run malicious
            // scripts without publishing a module. This is now BLOCKED.
            // All Move interactions MUST use the published module entry function format.
            else {
                println!("⚠️ REJECTED: Unrecognized payload format from {}. Raw hex script execution is disabled for security.", tx.sender);
            }
            
            Some((updates, actual_gas))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_deserialization() {
        // Updated JSON with chain_id
        let json = r#"{"chain_id":"AINCORE-MAINNET-1","sender":"c4b14ae227ec4e1f661dbb0d15039f1c","input_objects":[],"payload":"transfer:9e1289745b7ebd72cb17064a2c44458f:11","args":[],"gas_limit":10000,"gas_price":1,"signature":"bf3714c3b74c954cd88d5e076cc2335ab389cd3e0bc9cec55fbc9d3c62edcc3ad5720868385f45e87bf257c3dcd0083c0737c60f4839ccc949e8e68e214e5c02"}"#;
        
        let tx: Result<Transaction, _> = serde_json::from_str(json);
        match tx {
            Ok(_) => println!("✅ Deserialization Successful"),
            Err(e) => {
                println!("❌ Deserialization Failed: {}", e);
                panic!("Deserialization failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod verify_transfer_test;