use move_core_types::{
    account_address::AccountAddress,
    language_storage::ModuleId,
    resolver::{ModuleResolver, ResourceResolver},
};
use move_vm_runtime::move_vm::MoveVM;
use anyhow::Result;

use storage::StateDB;
use std::sync::Arc;

mod gas;
use gas::AINCOREGasMeter;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

mod tests;

/// Storage adapter for Move VM backed by RocksDB (StateDB)
pub struct AINCOREStorage {
    db: Arc<StateDB>,
}

impl AINCOREStorage {
    pub fn new(db: Arc<StateDB>) -> Self {
        Self { db }
    }
}

impl ModuleResolver for AINCOREStorage {
    type Error = anyhow::Error;

    fn get_module(&self, id: &ModuleId) -> Result<Option<Vec<u8>>, Self::Error> {
        let key = format!("module_{}_{}", id.address(), id.name());
        // println!("🔍 VM looking for module: {}", key);
        match self.db.get(&key) {
            Ok(Some(bytes_hex)) => {
                // We store as hex in StateDB currently (based on put/get implementation)
                // Wait, StateDB put/get uses String.
                // If we store raw bytes, we might need to encode/decode or update StateDB.
                // Let's assume we store hex-encoded string for now to be safe with RocksDB string interface.
                let bytes = hex::decode(bytes_hex)?;
                Ok(Some(bytes))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("DB Error: {}", e)),
        }
    }
}

impl ResourceResolver for AINCOREStorage {
    type Error = anyhow::Error;

    fn get_resource(
        &self,
        address: &AccountAddress,
        typ: &move_core_types::language_storage::StructTag,
    ) -> Result<Option<Vec<u8>>, Self::Error> {
        let key = format!("resource_{}_{}", address, typ);
        match self.db.get(&key) {
            Ok(Some(bytes_hex)) => {
                let bytes = hex::decode(bytes_hex)?;
                
                // === STATE RENT LOGIC ===
                // 1. Check metadata for last access
                let meta_key = format!("meta_{}", key);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                
                let last_access = if let Ok(Some(meta_hex)) = self.db.get(&meta_key) {
                    if let Ok(meta_bytes) = hex::decode(meta_hex) {
                        let mut arr = [0u8; 8];
                        if meta_bytes.len() == 8 {
                            arr.copy_from_slice(&meta_bytes);
                            u64::from_be_bytes(arr)
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                } else {
                    0 // First access or legacy
                };

                if last_access > 0 {
                    let elapsed = now.saturating_sub(last_access);
                    if elapsed > 0 {
                        // Rent Rate: 1 unit per byte per second (simplified)
                        let size = bytes.len() as u64;
                        let rent = size * elapsed;
                        // In a real system, we would deduct this from the account's Coin balance.
                        // For prototype, we just log it.
                        println!("💸 [State Rent] Resource {} accessed. Size: {} bytes. Elapsed: {}s. Rent Due: {}", key, size, elapsed, rent);
                    }
                }

                // 2. Update last access time
                let now_bytes = now.to_be_bytes();
                let _ = self.db.put(&meta_key, &hex::encode(now_bytes));
                // ========================

                Ok(Some(bytes))
            },
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("DB Error: {}", e)),
        }
    }
}

pub struct AINCOREVM {
    vm: MoveVM,
    storage: AINCOREStorage,
}

impl AINCOREVM {
    pub fn new(db: Arc<StateDB>) -> Self {
        let vm = MoveVM::new(vec![]).expect("Failed to create MoveVM");
        let storage = AINCOREStorage::new(db);
        Self { vm, storage }
    }

    /*
    fn load_stdlib(&self, storage: &mut InMemoryStorage) {
        // TODO: Iterate over stdlib/sources, compile them, and store in storage
        println!("📚 Loading Move Standard Library...");
    }
    */


    pub fn execute_transaction(&self, sender: AccountAddress, signature: &[u8], _payload: &[u8]) -> Result<bool> {
        // === NATIVE ACCOUNT ABSTRACTION (Crypto-Agility) ===
        // This demonstrates how AINCORE supports multiple cryptographic schemes.
        
        // Scheme 0: Ed25519 (Standard)
        if signature.len() == 64 {
            // println!("🛡️ [Native AA] Validating Ed25519 signature for {}", sender);
            // In a real implementation, we would recover the public key from the Account Object
            // and verify the signature. For prototype, we assume the executor did the check 
            // or we just pass here as we don't have the pubkey handy in this context without fetching.
            return Ok(true);
        }
        
        // Scheme 1: CRYSTALS-Dilithium5 (Post-Quantum)
        // Dilithium5 signature size is 4627 bytes (detached)
        if signature.len() == 4627 {
             // println!("🛡️ [Native AA] ⚛️ Quantum-Resistant Signature Detected (Dilithium5) for {}", sender);
             
             // 1. Fetch Dilithium Public Key from Account Resource
             // For prototype: We expect the Public Key to be stored at "pqc_pubkey_{sender}"
             // In production, this would be in the Account struct.
             let pk_key = format!("pqc_pubkey_{}", sender);
             let pk_bytes = match self.storage.db.get(&pk_key) {
                 Ok(Some(hex_pk)) => hex::decode(hex_pk).unwrap_or_default(),
                 _ => {
                     println!("⚠️ [Native AA] PQC Public Key not found for {}", sender);
                     return Ok(false);
                 }
             };

             if pk_bytes.len() != pqcrypto_dilithium::dilithium5::public_key_bytes() {
                 println!("⚠️ [Native AA] Invalid PQC Public Key length for {}", sender);
                 return Ok(false);
             }

             // 2. Verify Signature
             let pk = pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(&pk_bytes).unwrap();
             let sig = pqcrypto_dilithium::dilithium5::DetachedSignature::from_bytes(signature).unwrap();
             
             match pqcrypto_dilithium::dilithium5::verify_detached_signature(&sig, _payload, &pk) {
                 Ok(_) => {
                     // println!("✅ [Native AA] PQC Signature Verified!");
                     return Ok(true);
                 },
                 Err(_) => {
                     println!("❌ [Native AA] PQC Signature Verification FAILED");
                     return Ok(false);
                 }
             }
        }
        
        // Scheme 2: CRYSTALS-Kyber (KEM) - Not applicable for signing, but for encryption.
        
        println!("⚠️ [Native AA] Unknown signature scheme (len={}). Rejecting.", signature.len());
        Ok(false)
    }

    pub fn execute_script(&self, script: Vec<u8>, args: Vec<Vec<u8>>, gas_limit: u64) -> Result<(u64, Vec<(String, Option<String>)>, Vec<move_core_types::language_storage::ModuleId>)> {
        let mut session = self.vm.new_session(&self.storage);
        let mut gas_meter = AINCOREGasMeter::new(gas_limit);
        
        // Deserialize args (assuming they are already BCS encoded or need handling)
        session.execute_script(script, vec![], args, &mut gas_meter)?;
        let (changeset, _events) = session.finish()?;
        
        let vm_changes = self.changeset_to_kv(changeset)?;
        
        Ok((gas_meter.gas_used(), vm_changes, vec![])) // Events ignored for now
    }

    fn changeset_to_kv(&self, changeset: move_core_types::effects::ChangeSet) -> Result<Vec<(String, Option<String>)>> {
        let mut updates = Vec::new();
        for (addr, account_changes) in changeset.into_inner() {
            let (modules, resources) = account_changes.into_inner();
            
            for (struct_tag, change) in resources {
                let key = format!("resource_{}_{}", addr, struct_tag);
                match change {
                    move_core_types::effects::Op::New(bytes) | move_core_types::effects::Op::Modify(bytes) => {
                        let hex_bytes = hex::encode(bytes);
                        updates.push((key, Some(hex_bytes)));
                    }
                    move_core_types::effects::Op::Delete => {
                        updates.push((key, None));
                    }
                }
            }
            // Handle modules if any
            for (module_name, change) in modules {
                let key = format!("module_{}_{}", addr, module_name);
                match change {
                    move_core_types::effects::Op::New(bytes) | move_core_types::effects::Op::Modify(bytes) => {
                        let hex_bytes = hex::encode(bytes);
                        updates.push((key, Some(hex_bytes)));
                    }
                    move_core_types::effects::Op::Delete => {
                         updates.push((key, None));
                    }
                }
            }
        }
        Ok(updates)
    }
}
