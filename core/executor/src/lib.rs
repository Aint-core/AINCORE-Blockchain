use serde::{Deserialize, Serialize};
use std::sync::Arc;
use storage::StateDB;
use storage::rocksdb::WriteBatch;
use vm_move::AINCOREVM;
use rayon::prelude::*;

const CHAIN_ID: &str = "AINCORE-MAINNET-1";
// REMOVED: const BLOCK_REWARD: u64 = 50; 
// V3 CONSTANTS
const MAX_SUPPLY: u128 = 150_000_000 * 1_000_000_000_000_000_000; // 150 Million AIN
const TAIL_EMISSION: u128 = 10 * 1_000_000_000_000_000_000; // 10 AIN Min per block
const DECAY_FACTOR: u128 = 5_000_000; // Decay speed factor

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
        println!("🚀 Starting Parallel Execution for {} transactions...", txs_json.len());
        
        // 1. Parse all transactions
        let mut parsed_txs = Vec::new();
        for raw in &txs_json {
            match serde_json::from_str::<Transaction>(raw) {
                Ok(tx) => parsed_txs.push((tx, raw.clone())),
                Err(_e) => { /* Silently ignore parse errors in hot loop, or log trace */ },
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
            let results: Vec<Option<Vec<(String, Option<String>)>>> = batch.par_iter().map(|(_tx, raw)| {
                self.execute_transaction(raw)
            }).collect();

            // 4. Commit Batch Atomically
            let mut write_batch = WriteBatch::default();
            let mut batch_hasher = sha2::Sha256::new();
            use sha2::Digest;

            for res in results {
                if let Some(updates) = res {
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
                    total_fees += 1; // Simplistic fee counting
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

        // 5. Apply Block Rewards (V3 ECONOMICS)
        // A. Basic Params
        let _current_height = self.db.get_chain_height();
        
        // V3 LOGIC: Calculate Reward based on Circulating Supply
        // We get total supply from a tracked key (or estimate via height * avg if missing, strict tracking is better)
        // For now, we simulate "Total Mined" roughly or use storage key if available.
        // Let's use a robust approximation: current_height * 50 (Historical avg) -> Better: Track in DB.
        
        let mut total_supply: u128 = match self.db.get("sys:total_supply") {
            Ok(Some(s)) => s.parse().unwrap_or(0),
            _ => 0, 
        };

        // If total_supply is 0 (genesis), set it to expected genesis supply (1M)
        if total_supply == 0 {
             total_supply = 1_000_000 * 1_000_000_000_000_000_000;
        }

        // B. Calculate V3 Reward (Logarithmic Decay)
        // Formula: BaseReward = (MaxSupply - CurrentSupply) / DecayFactor
        // Floor: TailEmission
        
        let remaining = if MAX_SUPPLY > total_supply { MAX_SUPPLY - total_supply } else { 0 };
        let mut block_inflation = (remaining / DECAY_FACTOR).max(TAIL_EMISSION);
        
        // Cap at 100 AIN to prevent Genesis craziness
        let max_cap = 100 * 1_000_000_000_000_000_000;
        if block_inflation > max_cap { block_inflation = max_cap; }

        // PHASE 15: ANTI-LAZY PENALTY
        // If block is empty (Heartbeat), slash reward by 90%.
        if txs_json.is_empty() {
            println!("💤 Lazy Block (0 Txs) detected. Slashing reward by 90%.");
            block_inflation = block_inflation / 10;
        }

        // C. Fee Logic & Burning
        let burn_pct = self.db.get_burn_percentage() as u128; // Cast to u128
        let total_fees_u128 = total_fees as u128; // Fees are currently unit 1, might need scaling if gas price is high.
        // Assume pure units for now.
        
        let burnt_fees = (total_fees_u128 * burn_pct) / 100;
        let miner_fees = total_fees_u128 - burnt_fees;
        
        // D. Total Miner Reward
        let reward_amount = block_inflation + miner_fees;
        
        // Update Total Supply
        total_supply += block_inflation;
        let _ = self.db.put("sys:total_supply", &total_supply.to_string());
        
        if burnt_fees > 0 {
             println!("🔥 BURNING {} Fees ({}% of {})", burnt_fees, burn_pct, total_fees);
        }
        
        // We use the first 32 chars of the hex public key as the address (simplified model)
        // Or if proposer_hex IS the address (which it is in our consensus), we use it directly.
        let miner_addr = if proposer_hex.len() > 32 { &proposer_hex[0..32] } else { proposer_hex };

        println!("💰 Distributing Block Reward: {} AIN (Inf: {}, Fees: {}) to Miner {}", 
            reward_amount, block_inflation, miner_fees, miner_addr);

        // Fetch Miner Object
        let mut miner_obj = match self.db.get_object(miner_addr) {
            Some(obj) => obj,
            None => {
                // Create New Account if miner doesn't exist (e.g. first block)
                use storage::object::{Object, ObjectID, Owner};
                use aa::AccountData;
                Object {
                    id: ObjectID::new(miner_addr.to_string()),
                    data: serde_json::to_vec(&AccountData {
                        balance: 0,
                        sequence_number: 0,
                        btc_balance: 0,
                        public_key: "".to_string(),
                    }).unwrap_or_default(),
                    owner: Owner::Address(miner_addr.to_string()),
                    type_struct: "0x1::account::Account".to_string(),
                    version: 0,
                }
            }
        };

        // Update Balance
        if let Ok(mut data) = serde_json::from_slice::<aa::AccountData>(&miner_obj.data) {
            if let Some(new_balance) = data.balance.checked_add(reward_amount) {
                data.balance = new_balance;
                if let Ok(new_data) = serde_json::to_vec(&data) {
                    miner_obj.data = new_data;
                    // ...
                    if let Err(e) = self.db.put_object(&miner_obj) {
                         eprintln!("❌ Failed to save mining reward: {}", e);
                    } else {
                         println!("✅ Reward Credited. New Balance: {}", data.balance);
                    }
                }
            } else {
                eprintln!("❌ CRITICAL: Miner balance overflow! Reward discarded to prevent corruption.");
            }
        }

        println!("✅ Parallel Execution Complete.");
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
            if deps.len() > 128 { // QUANTUM AUDIT FIX: Limit deps to prevent Scheduler DoS
                 break;
            }
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
    pub fn execute_transaction(&self, tx_json: &str) -> Option<Vec<(String, Option<String>)>> {
        let mut updates = Vec::new();
        
        if let Ok(tx) = serde_json::from_str::<Transaction>(tx_json) {
            // 0. Verify Chain ID
            if tx.chain_id != CHAIN_ID {
                println!("❌ Invalid Chain ID: Expected {}, Got {}", CHAIN_ID, tx.chain_id);
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
            let message = format!("{}:{}:{}", tx.chain_id, tx.payload, tx.sequence_number);
            
            if verifying_key.verify(message.as_bytes(), &signature).is_err() {
                println!("❌ Invalid Signature Verification");
                return None;
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

            if account_data.balance < gas_cost {
                println!("❌ Insufficient Balance for Gas");
                return None;
            }
            
            // Deduct Gas (Checked)
            if let Some(new_balance) = account_data.balance.checked_sub(gas_cost) {
                account_data.balance = new_balance;
            } else {
                 println!("❌ Insufficient Balance for Gas (Overflow Check)");
                 return None;
            }

            // Special: If payer is sender, we MUST increment seq number here?
            if payer_addr == tx.sender {
                 if let Some(new_seq) = account_data.sequence_number.checked_add(1) {
                     account_data.sequence_number = new_seq;
                 } else {
                     return None; // Sequence overflow
                 }
            }
            
            // Save Payer Update
            if let Ok(new_data) = serde_json::to_vec(&account_data) {
                payer_obj.data = new_data;
                // Add to updates, NOT put
                updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
            }

            // 4. Execution Payload
            if tx.payload.starts_with("0x") {
                 // === PHASE 8: TRUE VM EXECUTION ===
                 // Parse Script Bytecode
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
                             println!("✅ VM Execution Success. Gas: {}", gas_used);
                             // Gas Refund (Checked)
                             if gas_used < tx.gas_limit {
                                 let refund = (tx.gas_limit - gas_used) as u128 * tx.gas_price;
                                 if refund > 0 {
                                     if let Some(new_balance) = account_data.balance.checked_add(refund) {
                                         account_data.balance = new_balance;
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
                                 let is_allowed = allowed_keys.iter().any(|allowed| key.contains(allowed));
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
            } else if tx.payload.starts_with("transfer:") {
                // ... Transfer Logic ...
                let parts: Vec<&str> = tx.payload.split(':').collect();
                if parts.len() == 3 {
                    let recipient_addr = parts[1];
                    let amount: u128 = parts[2].parse().unwrap_or(0);
                    
                    if amount > 0 {
                          // Check balance for transfer (after gas)
                          if account_data.balance >= amount {
                              // Deduct from sender (Checked)
                              if let Some(new_balance) = account_data.balance.checked_sub(amount) {
                                  account_data.balance = new_balance;
                                  
                                  // Update Payer/Sender (Sender-side deduction)
                                  if let Ok(new_data) = serde_json::to_vec(&account_data) {
                                      let mut final_sender_obj = payer_obj.clone(); 
                                      final_sender_obj.data = new_data;
                                      updates.push((format!("obj:{}", final_sender_obj.id.to_string()), Some(serde_json::to_string(&final_sender_obj).unwrap_or_else(|_| "{}".to_string()))));
                                  }

                                  // Credit Recipient
                                  let mut recipient_obj = match self.db.get_object(recipient_addr) {
                                      Some(obj) => obj,
                                      None => {
                                          use storage::object::{Object, ObjectID, Owner};
                                          Object {
                                              id: ObjectID::new(recipient_addr.to_string()),
                                              data: serde_json::to_vec(&aa::AccountData {
                                                  balance: 0,
                                                  sequence_number: 0,
                                                  btc_balance: 0, // Init BTC Balance
                                                  public_key: "".to_string(),
                                              }).unwrap_or_else(|_| vec![]),
                                              owner: Owner::Address(recipient_addr.to_string()),
                                              type_struct: "0x1::account::Account".to_string(),
                                              version: 0,
                                          }
                                      }
                                  };
                                  
                                  if let Ok(mut rec_data) = serde_json::from_slice::<aa::AccountData>(&recipient_obj.data) {
                                       // Credit receiver (Checked)
                                       if let Some(new_rec_balance) = rec_data.balance.checked_add(amount) {
                                            rec_data.balance = new_rec_balance;
                                            if let Ok(new_rec_data) = serde_json::to_vec(&rec_data) {
                                                recipient_obj.data = new_rec_data;
                                                updates.push((format!("obj:{}", recipient_obj.id.to_string()), Some(serde_json::to_string(&recipient_obj).unwrap_or_else(|_| "{}".to_string()))));
                                            }
                                       }
                                  }
                              }
                          } else {
                              println!("❌ Insufficient Balance for Transfer");
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

                         if let Ok(mut rec_data) = serde_json::from_slice::<aa::AccountData>(&recipient_obj.data) {
                             if let Some(new_btc_bal) = rec_data.btc_balance.checked_add(amount) {
                                  rec_data.btc_balance = new_btc_bal;
                                  if let Ok(new_rec_data) = serde_json::to_vec(&rec_data) {
                                      recipient_obj.data = new_rec_data;
                                      updates.push((format!("obj:{}", recipient_obj.id.to_string()), Some(serde_json::to_string(&recipient_obj).unwrap_or_else(|_| "{}".to_string()))));
                                      println!("✅ Mint Successful. New BTC Balance: {}", rec_data.btc_balance);
                                  }
                             } else {
                                  println!("❌ BTC Balance Overflow for {}", recipient_addr);
                             }
                         }
                     }
                 } else {
                     println!("❌ Authorization Failed: Only Federation can mint BTC. Sender: {}", tx.sender);
                 }
            } else if tx.payload.starts_with("submit_proof:") {
                 // === DePIN MINING LOGIC ===
                 // Payload: "submit_proof:DEVICE_ID:BQI"
                 let parts: Vec<&str> = tx.payload.split(':').collect();
                 if parts.len() >= 3 {
                     let device_id = parts[1];
                     let bqi: u64 = parts[2].parse().unwrap_or(0);
                     
                     // SYNERGY CHECK: The Sender MUST be the Device (or owner)
                     // Simplified: Sender Hex must match Device ID (assuming Device ID is address)
                     if device_id != tx.sender {
                         println!("❌ DePIN spoofing attempt! Sender {} tried to submit for Device {}", tx.sender, device_id);
                         account_data.sequence_number += 1; // Burn gas/seq
                     } else if bqi > 100 {
                         println!("❌ Invalid BQI Score: {}", bqi);
                     } else {
                         // Reward Logic: Max 1 AIN (1_000_000 units) * BQI%
                         // Simplified: Reward directly to Sender (Miner)
                         let base_reward: u128 = 1_000_000;
                         let reward: u128 = (base_reward * bqi as u128) / 100;
                         
                         account_data.balance += reward;
                         println!("🫁 DePIN Mining: BQI {} -> Reward {} AIN", bqi, reward);
                         
                         // Save updated balance (Payer/Sender)
                         if let Ok(new_data) = serde_json::to_vec(&account_data) {
                             payer_obj.data = new_data;
                             updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
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
                     // Arg0: &signer (Handled by VM automatically for Entry Function first arg if it's signer)
                     // Wait, VM expects Signer to be injected via sending session??
                     // execute_entry_function signature: 
                     // fun join_validator_set(account: &signer, stake_amount: u128, public_key: vector<u8>)
                     // The VM automatically binds the first &signer argument to the txn sender.
                     // So we only provide args for stake_amount and public_key.
                     
                     let arg_stake = bcs::to_bytes(&stake_amount).unwrap_or_default();
                     let arg_pubkey = bcs::to_bytes(&pubkey_bytes).unwrap_or_default();
                     
                     let args = vec![arg_stake, arg_pubkey];
                     let ty_args = vec![];
                     
                     use move_core_types::language_storage::ModuleId;
                     use move_core_types::identifier::Identifier;
                     use move_core_types::account_address::AccountAddress;
                     
                     let module_id = ModuleId::new(
                         AccountAddress::new([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]), 
                         Identifier::new("staking").expect("staking identifier is valid")
                     );
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                             
                             // Deduct Gas (Refund Logic same as script)
                             if gas_used < tx.gas_limit {
                                 let refund_amount: u128 = (tx.gas_limit - gas_used) as u128 * tx.gas_price;
                                 if refund_amount > 0 {
                                     account_data.balance += refund_amount; 
                                     if let Ok(refunded_data) = serde_json::to_vec(&account_data) {
                                         payer_obj.data = refunded_data;
                                         updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
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
                         
                         let validator_account = AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)).unwrap_or(AccountAddress::ZERO);
                         let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                         let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                         
                         let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                         
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
                         
                         let validator_account = AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)).unwrap_or(AccountAddress::ZERO);
                         let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                         let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                         
                         let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                         
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
                     
                     let validator_account = AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)).unwrap_or(AccountAddress::ZERO);
                     let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                     
                     let validator_account = AccountAddress::from_hex_literal(&format!("0x{}", validator_addr)).unwrap_or(AccountAddress::ZERO);
                     let arg_validator = bcs::to_bytes(&validator_account).unwrap_or_default();
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                     let to_addr = AccountAddress::from_hex_literal(&format!("0x{}", to)).unwrap_or(AccountAddress::ZERO);
                     let arg_to = bcs::to_bytes(&to_addr).unwrap_or_default();
                     let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                     let to_addr = AccountAddress::from_hex_literal(&format!("0x{}", to)).unwrap_or(AccountAddress::ZERO);
                     let arg_to = bcs::to_bytes(&to_addr).unwrap_or_default();
                     let arg_amount = bcs::to_bytes(&amount).unwrap_or_default();
                     
                     let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                     
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
                 
                 let sender_addr = AccountAddress::from_hex_literal(&format!("0x{}", tx.sender)).unwrap_or(AccountAddress::ZERO);
                 
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
            if let Ok(script_bytes) = hex::decode(&tx.payload) {
                 match self.vm.execute_script(script_bytes, vec![], tx.gas_limit) {
                     Ok((gas_used, vm_changes, _)) => {
                         for (k, v) in vm_changes {
                             updates.push((k, v));
                         }
                         println!("✅ Move Script Executed. Gas Used: {}", gas_used);
                         
                         // Gas Refund Logic
                         if gas_used < tx.gas_limit {
                             let refund_amount: u128 = (tx.gas_limit - gas_used) as u128 * tx.gas_price;
                             if refund_amount > 0 {
                                 account_data.balance += refund_amount; 
                                 if let Ok(refunded_data) = serde_json::to_vec(&account_data) {
                                     payer_obj.data = refunded_data;
                                      updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
                                      println!("   💰 Gas Refund: {} AIN", refund_amount);
                                 }
                             }
                         }
                     },
                     Err(e) => {
                         println!("❌ Move Execution Failed: {}", e);
                     }
                 }
            }
            
            Some(updates)
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