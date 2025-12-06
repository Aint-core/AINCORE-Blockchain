use serde::{Deserialize, Serialize};
use std::sync::Arc;
use storage::StateDB;
use storage::rocksdb::WriteBatch;
use vm_move::AINCOREVM;
use rayon::prelude::*;

const CHAIN_ID: &str = "AINCORE-MAINNET-1";
const BLOCK_REWARD: u64 = 50; // 50 AIN coins per block

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transaction {
    pub chain_id: String, // Replay Protection
    pub sender: String, // Account Object ID
    pub input_objects: Vec<String>, // Object IDs
    pub payload: String,
    pub gas_limit: u64,
    pub gas_price: u64,
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
                Err(e) => println!("❌ Failed to parse transaction in parallel batch: {} (Error: {})", raw, e),
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

        for (i, batch) in batches.iter().enumerate() {
            println!("   ⚡ Executing Batch {} ({} txs)", i + 1, batch.len());
            
            // Execute in parallel to get updates
            let results: Vec<Option<Vec<(String, Option<String>)>>> = batch.par_iter().map(|(_tx, raw)| {
                self.execute_transaction(raw)
            }).collect();

            // 4. Commit Batch Atomically
            let mut write_batch = WriteBatch::default();

            for res in results {
                if let Some(updates) = res {
                    for (key, val_opt) in updates {
                         if let Some(val) = val_opt {
                             write_batch.put(key.as_bytes(), val.as_bytes());
                         } else {
                             write_batch.delete(key.as_bytes());
                         }
                    }
                    total_fees += 1; // Simplistic fee counting
                }
            }
            
            if let Err(e) = self.db.write_batch(write_batch) {
                 println!("❌ CRITICAL: Failed to commit batch {}: {}", i, e);
            }
        }

        // 5. Apply Block Rewards (Inflation + Fees)
        // Reward goes to the Proposer (Miner)
        let reward_amount = BLOCK_REWARD + total_fees;
        
        // We use the first 32 chars of the hex public key as the address (simplified model)
        // Or if proposer_hex IS the address (which it is in our consensus), we use it directly.
        let miner_addr = if proposer_hex.len() > 32 { &proposer_hex[0..32] } else { proposer_hex };

        println!("💰 Distributing Block Reward: {} AIN to Miner {}", reward_amount, miner_addr);

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
            data.balance += reward_amount;
            if let Ok(new_data) = serde_json::to_vec(&data) {
                miner_obj.data = new_data;
                // Commit Reward
                if let Err(e) = self.db.put_object(&miner_obj) {
                     eprintln!("❌ Failed to save mining reward: {}", e);
                } else {
                     println!("✅ Reward Credited. New Balance: {}", data.balance);
                }
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
            let message = format!("{}:{}", tx.payload, tx.sequence_number);
            
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
            let gas_cost = tx.gas_limit * tx.gas_price;
            
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
            
            // Deduct Gas
            account_data.balance -= gas_cost;
            // Special: If payer is sender, we MUST increment seq number here?
            // Usually seq number bumps only on success, but gas verification is success.
            if payer_addr == tx.sender {
                 account_data.sequence_number += 1;
            }
            
            // Save Payer Update
            if let Ok(new_data) = serde_json::to_vec(&account_data) {
                payer_obj.data = new_data;
                // Add to updates, NOT put
                updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
            }

            // 4. Execute Payload
            // 4. Execute Payload
            if tx.payload.starts_with("transfer:") {
                // ... Transfer Logic ...
                let parts: Vec<&str> = tx.payload.split(':').collect();
                if parts.len() == 3 {
                    let recipient_addr = parts[1];
                    let amount: u64 = parts[2].parse().unwrap_or(0);
                    
                    if amount > 0 {
                          // Check balance for transfer (after gas)
                          if account_data.balance >= amount {
                              account_data.balance -= amount;
                              
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
                                   rec_data.balance += amount;
                                   if let Ok(new_rec_data) = serde_json::to_vec(&rec_data) {
                                       recipient_obj.data = new_rec_data;
                                       updates.push((format!("obj:{}", recipient_obj.id.to_string()), Some(serde_json::to_string(&recipient_obj).unwrap_or_else(|_| "{}".to_string()))));
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
                 const FEDERATION_ADDR: &str = "c9c32c8d0607850e6d89c8f048dd3a94";

                 if tx.sender == FEDERATION_ADDR {
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
                             rec_data.btc_balance += amount; // Credit Wrapped BTC
                             if let Ok(new_rec_data) = serde_json::to_vec(&rec_data) {
                                 recipient_obj.data = new_rec_data;
                                 updates.push((format!("obj:{}", recipient_obj.id.to_string()), Some(serde_json::to_string(&recipient_obj).unwrap_or_else(|_| "{}".to_string()))));
                                 println!("✅ Mint Successful. New BTC Balance: {}", rec_data.btc_balance);
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
                     let _device_id = parts[1];
                     let bqi: u64 = parts[2].parse().unwrap_or(0);
                     
                     if bqi > 100 {
                         println!("❌ Invalid BQI Score: {}", bqi);
                     } else {
                         // Reward Logic: Max 1 AIN (1_000_000 units) * BQI%
                         // Simplified: Reward directly to Sender (Miner)
                         let base_reward = 1_000_000;
                         let reward = (base_reward * bqi) / 100;
                         
                         account_data.balance += reward;
                         println!("🫁 DePIN Mining: BQI {} -> Reward {} AIN", bqi, reward);
                         
                         // Save updated balance (Payer/Sender)
                         if let Ok(new_data) = serde_json::to_vec(&account_data) {
                             payer_obj.data = new_data;
                             updates.push((format!("obj:{}", payer_obj.id.to_string()), Some(serde_json::to_string(&payer_obj).unwrap_or_else(|_| "{}".to_string()))));
                         }
                     }
                 }
            }
            
            // Move Script Execution (Standard)
            if let Ok(script_bytes) = hex::decode(&tx.payload) {
                 match self.vm.execute_script(script_bytes, vec![], tx.gas_limit) {
                     Ok((gas_used, vm_changes, _)) => {
                         for (k, v) in vm_changes {
                             updates.push((k, v));
                         }
                         println!("✅ Move Script Executed. Gas Used: {}", gas_used);
                         
                         // Gas Refund Logic
                         if gas_used < tx.gas_limit {
                             let refund_amount = (tx.gas_limit - gas_used) * tx.gas_price;
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
        let json = r#"{"chain_id":"AINCORE-MAINNET-1","sender":"c4b14ae227ec4e1f661dbb0d15039f1c","input_objects":[],"payload":"transfer:9e1289745b7ebd72cb17064a2c44458f:11","gas_limit":10000,"gas_price":1,"signature":"bf3714c3b74c954cd88d5e076cc2335ab389cd3e0bc9cec55fbc9d3c62edcc3ad5720868385f45e87bf257c3dcd0083c0737c60f4839ccc949e8e68e214e5c02"}"#;
        
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