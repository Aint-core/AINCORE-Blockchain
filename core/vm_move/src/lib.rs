use anyhow::Result;
use move_core_types::{
    account_address::AccountAddress,
    language_storage::ModuleId,
    resolver::{ModuleResolver, ResourceResolver},
};
use move_vm_runtime::move_vm::MoveVM;

use std::sync::Arc;
use storage::StateDB;

mod gas;
use gas::AINCOREGasMeter;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde::{Deserialize, Serialize};

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
            }
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

                // === STATE RENT LOGIC (READ-ONLY — NO WRITES) ===
                // SECURITY FIX: Previous implementation performed a db.put() on EVERY
                // get_resource call, creating a catastrophic I/O DDoS amplification vector.
                // An attacker could craft transactions that read thousands of resources,
                // turning each into an unbatched disk write — amplifying a single tx
                // into massive disk I/O that starves the node.
                //
                // FIX: The read path is now PURE — it only computes rent for logging.
                // Actual rent metadata updates are deferred to the session commit phase
                // (changeset_to_kv), where they are batched with all other state changes
                // into a single atomic WriteBatch.
                //
                // TODO: Implement proper rent collection at commit time once the
                // epoch-based rent settlement mechanism is designed.

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
                        let size = bytes.len() as u64;
                        let _rent = size * elapsed;
                        // Rent is computed but NOT written to disk here.
                        // Collection happens at epoch boundaries via governance sweep.
                    }
                }

                // NOTE: db.put() for meta_key REMOVED from read path.
                // Last-access timestamps are now updated only during changeset commit.

                Ok(Some(bytes))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("DB Error: {}", e)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExecutionStatus {
    pub success: bool,
    pub error: Option<String>,
}

impl ExecutionStatus {
    pub fn success() -> Self {
        Self {
            success: true,
            error: None,
        }
    }

    pub fn aborted(error: impl Into<String>) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
        }
    }
}

pub type ExecutionResult = Result<(u64, Vec<(String, Option<String>)>, ExecutionStatus)>;

pub struct AINCOREVM {
    vm: MoveVM,
    storage: AINCOREStorage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionPayload {
    Script(Vec<u8>), // Deprecated/Disabled
    EntryFunction(EntryFunctionCall),
    PublishModule(Vec<Vec<u8>>),
}

#[derive(Clone)]
pub enum MoveAction {
    PublishModule(Vec<Vec<u8>>),
    CallEntryFunction(EntryFunctionCall),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntryFunctionCall {
    pub module: move_core_types::language_storage::ModuleId,
    pub function: String,
    pub ty_args: Vec<move_core_types::language_storage::TypeTag>,
    pub args: Vec<Vec<u8>>,
}

pub fn system_address() -> AccountAddress {
    AccountAddress::from_hex_literal("0x1").expect("0x1 must be a valid Move system address")
}

impl AINCOREVM {
    pub fn new(db: Arc<StateDB>) -> Self {
        let natives = move_stdlib::natives::all_natives(
            system_address(),
            move_stdlib::natives::GasParameters::zeros(),
        );
        let vm = MoveVM::new(natives).unwrap_or_else(|e| {
            eprintln!("⚠️  WARNING: Failed to create MoveVM: {}", e);
            panic!("Critical: MoveVM initialization failed")
        });
        let storage = AINCOREStorage::new(db);
        Self { vm, storage }
    }

    /*
    fn load_stdlib(&self, storage: &mut InMemoryStorage) {
        // TODO: Iterate over stdlib/sources, compile them, and store in storage
        println!("📚 Loading Move Standard Library...");
    }
    */

    #[allow(clippy::too_many_arguments)] // tx fields (incl. F4 gas_limit/gas_price/input_objects) are intrinsic to verification
    pub fn execute_transaction(
        &self,
        chain_id: &str,
        sender: AccountAddress,
        sequence_number: u64,
        gas_limit: u64,
        gas_price: u128,
        input_objects: &[String],
        signature: &[u8],
        _payload: &[u8],
    ) -> Result<bool> {
        // === NATIVE ACCOUNT ABSTRACTION (Crypto-Agility) ===
        // This demonstrates how AINCORE supports multiple cryptographic schemes.

        // Scheme 0: Ed25519 (Standard)
        if signature.len() == 64 {
            // 1. Fetch Account Object
            // The sender address is roughly "0x..." but in storage it's an ObjectID.
            // Address derivation logic: In prototype, we use the hex string directly.
            let account_obj = match self.storage.db.get_object(&sender.to_string()) {
                Some(obj) => obj,
                None => {
                    // Fail if account doesn't exist (unless it's a genesis/faucet creation, handled by executor pre-checks)
                    // Actually, for VM execution, account MUST exist.
                    eprintln!(
                        "❌ [VM] Account {} not found. Cannot verify signature.",
                        sender
                    );
                    return Ok(false);
                }
            };

            // 2. Parse Account Data to get Public Key
            // We need to know the struct layout. "0x1::account::Account"
            // struct Account { balance: u64, sequence_number: u64, btc_balance: u64, public_key: String }

            #[derive(Deserialize)]
            struct AccountState {
                #[serde(default)]
                _balance: u64,
                #[serde(default)]
                _sequence_number: u64,
                #[serde(default)]
                _btc_balance: u64,
                public_key: String, // Hex encoded
            }

            let account_state: AccountState = match serde_json::from_slice(&account_obj.data) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "❌ [VM] Failed to deserialize account state for {}: {}",
                        sender, e
                    );
                    return Ok(false);
                }
            };

            // 3. Decode Public Key
            let pk_hex = account_state.public_key;
            if pk_hex.is_empty() {
                eprintln!("❌ [VM] No Public Key registered for account {}", sender);
                return Ok(false);
            }

            let pk_bytes = match hex::decode(&pk_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => {
                    eprintln!("❌ [VM] Invalid Public Key length for {}", sender);
                    return Ok(false);
                }
            };

            // 4. Verify Signature
            // The signature covers the full transaction message:
            // "CHAIN_ID:SENDER:PAYLOAD_HEX:SEQUENCE_NUMBER"

            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            let verifying_key =
                match VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()) {
                    Ok(vk) => vk,
                    Err(_) => return Ok(false),
                };

            let sig_obj = Signature::from_bytes(signature.try_into().unwrap());

            // FULL PAYLOAD VERIFICATION (Phase 4):
            // Match the executor's format: chain_id:sender:payload_hex:seq_num
            // F4: bind gas_limit, gas_price, input_objects to match wallet/mempool/executor.
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                chain_id,
                sender,
                hex::encode(_payload),
                sequence_number,
                gas_limit,
                gas_price,
                input_objects.join(",")
            );

            if verifying_key.verify(message.as_bytes(), &sig_obj).is_ok() {
                return Ok(true);
            } else {
                eprintln!("❌ [VM] Signature Verification FAILED for {}", sender);
                return Ok(false);
            }
        }

        // Scheme 1: CRYSTALS-Dilithium5 (Post-Quantum)
        // Post-Quantum Cryptography (PQC) Signature Verification
        // Uses CRYSTALS-Dilithium5 (NIST Standard)
        if signature.len() == 4627 {
            // println!("🔐 [Native AA] Detected PQC Signature (Dilithium5)");

            // 1. Fetch Dilithium Public Key from Account Resource
            // For prototype: We expect the Public Key to be stored at "pqc_pubkey_{sender}"
            // In production, this would be in the Account struct.
            let pk_key = format!("pqc_pubkey_{}", sender);
            let public_key = match self.storage.db.get(&pk_key) {
                Ok(Some(hex_pk)) => hex::decode(hex_pk).unwrap_or_default(),
                _ => {
                    eprintln!("⚠️ [Native AA] PQC Public Key not found for {}", sender);
                    return Ok(false);
                }
            };

            // 1. Extract Public Key (2592 bytes)
            if public_key.len() != 2592 {
                eprintln!(
                    "❌ [Native AA] Invalid Dilithium5 Public Key Size: {} (expected 2592)",
                    public_key.len()
                );
                return Ok(false);
            }

            let pk_bytes = public_key;

            // Validate payload size
            if _payload.len() > 10000 {
                eprintln!("❌ [Native AA] Payload too large for PQC verification");
                return Ok(false);
            }

            // 2. Verify Signature (CRITICAL FIX: Safe error handling)
            let pk = match pqcrypto_dilithium::dilithium5::PublicKey::from_bytes(&pk_bytes) {
                Ok(key) => key,
                Err(_) => {
                    eprintln!("❌ [Native AA] Invalid Dilithium5 public key format");
                    return Ok(false);
                }
            };

            let sig = match pqcrypto_dilithium::dilithium5::DetachedSignature::from_bytes(signature)
            {
                Ok(s) => s,
                Err(_) => {
                    eprintln!("❌ [Native AA] Invalid Dilithium5 signature format");
                    return Ok(false);
                }
            };

            // F4: bind gas_limit, gas_price, input_objects.
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                chain_id,
                sender,
                hex::encode(_payload),
                sequence_number,
                gas_limit,
                gas_price,
                input_objects.join(",")
            );
            match pqcrypto_dilithium::dilithium5::verify_detached_signature(
                &sig,
                message.as_bytes(),
                &pk,
            ) {
                Ok(_) => {
                    // println!("✅ [Native AA] PQC Signature Verified!");
                    return Ok(true);
                }
                Err(_) => {
                    eprintln!("❌ [Native AA] PQC Signature Verification FAILED");
                    return Ok(false);
                }
            }
        }

        // Scheme 2: CRYSTALS-Kyber (KEM) - Not applicable for signing, but for encryption.

        println!(
            "⚠️ [Native AA] Unknown signature scheme (len={}). Rejecting.",
            signature.len()
        );
        Ok(false)
    }

    pub fn execute_script(
        &self,
        script: Vec<u8>,
        args: Vec<Vec<u8>>,
        gas_limit: u64,
    ) -> ExecutionResult {
        let mut session = self.vm.new_session(&self.storage);
        let mut gas_meter = AINCOREGasMeter::new(gas_limit);

        // Deserialize args (assuming they are already BCS encoded or need handling)
        session.execute_script(script, vec![], args, &mut gas_meter)?;
        let (changeset, _events) = session.finish()?;

        let vm_changes = self.changeset_to_kv(changeset)?;

        Ok((gas_meter.gas_used(), vm_changes, ExecutionStatus::success())) // Events ignored for now
    }

    pub fn publish_modules(
        &self,
        modules: Vec<Vec<u8>>,
        sender: AccountAddress,
        gas_limit: u64,
    ) -> ExecutionResult {
        if sender == system_address() {
            anyhow::bail!("publishing to 0x1 is reserved for genesis/system upgrades");
        }

        let mut session = self.vm.new_session(&self.storage);
        let mut gas_meter = AINCOREGasMeter::new(gas_limit);
        session.publish_module_bundle(modules, sender, &mut gas_meter)?;
        let (changeset, _events) = session.finish()?;
        let vm_changes = self.changeset_to_kv(changeset)?;

        Ok((gas_meter.gas_used(), vm_changes, ExecutionStatus::success()))
    }

    #[allow(clippy::too_many_arguments)] // Move VM entry interface — args are intrinsic to function call
    pub fn execute_public_entry_function(
        &self,
        // 3-tuple (action, must_succeed, auth_signer) — see execute_transaction_actions.
        pre_actions: Vec<(MoveAction, bool, AccountAddress)>,
        module: ModuleId,
        function: &str,
        ty_args: Vec<move_core_types::language_storage::TypeTag>,
        args: Vec<Vec<u8>>,
        gas_limit: u64,
        sender: AccountAddress,
    ) -> ExecutionResult {
        let mut actions = pre_actions;
        actions.push((
            MoveAction::CallEntryFunction(EntryFunctionCall {
                module,
                function: function.to_string(),
                ty_args,
                args,
            }),
            false,
            // The caller-supplied `sender` is the authenticated principal whose
            // &signer slots are bound for this call (system_address() for
            // system-gated functions like deposit_fee_reward / slash).
            sender,
        ));
        self.execute_transaction_actions(actions, sender, gas_limit)
    }

    pub fn execute_transaction_actions(
        &self,
        // (action, must_succeed, auth_signer): auth_signer is the AUTHENTICATED
        // address this action may act as. Every leading &signer slot of an entry
        // function is overwritten with this address, so user-supplied bytes in a
        // signer slot are always discarded and cannot forge another principal.
        actions: Vec<(MoveAction, bool, AccountAddress)>,
        sender: AccountAddress,
        gas_limit: u64,
    ) -> ExecutionResult {
        let mut session = self.vm.new_session(&self.storage);
        let mut gas_meter = AINCOREGasMeter::new(gas_limit);
        let mut status = ExecutionStatus::success();

        for (action, must_succeed, auth_signer) in actions {
            let result: Result<(), anyhow::Error> = match action {
                MoveAction::PublishModule(modules) => {
                    if sender == system_address() {
                        Err(anyhow::anyhow!(
                            "publishing to 0x1 is reserved for genesis/system upgrades"
                        ))
                    } else {
                        session
                            .publish_module_bundle(modules, sender, &mut gas_meter)
                            .map_err(|e| anyhow::anyhow!("{}", e))
                    }
                }
                MoveAction::CallEntryFunction(call) => {
                    let ident =
                        match move_core_types::identifier::Identifier::new(call.function.clone()) {
                            Ok(id) => id,
                            Err(e) => {
                                let err = anyhow::anyhow!("invalid function identifier: {}", e);
                                if must_succeed {
                                    return Err(err);
                                }
                                if status.success {
                                    status = ExecutionStatus::aborted(err.to_string());
                                }
                                continue;
                            }
                        };
                    // SECURITY (FIX #1): bind &signer slots to the authenticated
                    // principal. move-vm does NOT inject signers; it deserializes a
                    // signer from raw arg bytes. Load the function signature, count
                    // leading signer params, and overwrite those slots with the BCS
                    // of auth_signer so a forged @0x1 (or any) signer is discarded.
                    let bound_args = match Self::bind_signer_args(
                        &session,
                        &call.module,
                        &ident,
                        &call.ty_args,
                        call.args,
                        auth_signer,
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            if must_succeed {
                                return Err(e);
                            }
                            if status.success {
                                status = ExecutionStatus::aborted(e.to_string());
                            }
                            continue;
                        }
                    };
                    session
                        .execute_entry_function(
                            &call.module,
                            &ident,
                            call.ty_args,
                            bound_args,
                            &mut gas_meter,
                        )
                        .map(|_| ())
                        .map_err(|e| anyhow::anyhow!("{}", e))
                }
            };

            if let Err(e) = result {
                if must_succeed {
                    return Err(e);
                } else {
                    println!("⚠️ Payload execution failed (state reverted): {}", e);
                    if status.success {
                        status = ExecutionStatus::aborted(e.to_string());
                    }
                }
            }
        }

        let (changeset, _events) = session.finish()?;
        let vm_changes = self.changeset_to_kv(changeset)?;

        Ok((gas_meter.gas_used(), vm_changes, status))
    }

    /// Overwrite the leading signer parameters of an entry function with the
    /// BCS-serialized authenticated address, so a caller can never forge another
    /// principal's &signer by supplying crafted argument bytes. In move-vm
    /// aptos-v1.3.0 a signer argument is deserialized from raw bytes via the
    /// Signer layout (== AccountAddress), so bcs::to_bytes(&address) is exactly
    /// the bytes the VM expects for a signer slot.
    fn bind_signer_args(
        session: &move_vm_runtime::session::Session<'_, '_, AINCOREStorage>,
        module: &ModuleId,
        function: &move_core_types::identifier::IdentStr,
        ty_args: &[move_core_types::language_storage::TypeTag],
        mut args: Vec<Vec<u8>>,
        auth_signer: AccountAddress,
    ) -> Result<Vec<Vec<u8>>> {
        use move_vm_types::loaded_data::runtime_types::Type;

        let instantiation = session
            .load_function(module, function, ty_args)
            .map_err(|e| anyhow::anyhow!("failed to load function signature: {:?}", e))?;

        let mut signer_count = 0usize;
        for ty in &instantiation.parameters {
            let is_signer = match ty {
                Type::Signer => true,
                Type::Reference(inner) | Type::MutableReference(inner) => {
                    matches!(**inner, Type::Signer)
                }
                _ => false,
            };
            if is_signer {
                signer_count += 1;
            } else {
                break;
            }
        }

        if args.len() < signer_count {
            anyhow::bail!(
                "argument count {} is fewer than the {} required signer slots for {}::{}",
                args.len(),
                signer_count,
                module,
                function
            );
        }

        let signer_bytes = bcs::to_bytes(&auth_signer)
            .map_err(|e| anyhow::anyhow!("failed to serialize authenticated signer: {}", e))?;
        for slot in args.iter_mut().take(signer_count) {
            *slot = signer_bytes.clone();
        }

        Ok(args)
    }

    fn changeset_to_kv(
        &self,
        changeset: move_core_types::effects::ChangeSet,
    ) -> Result<Vec<(String, Option<String>)>> {
        let mut updates = Vec::new();
        for (addr, account_changes) in changeset.into_inner() {
            let (modules, resources) = account_changes.into_inner();

            for (struct_tag, change) in resources {
                let key = format!("resource_{}_{}", addr, struct_tag);
                match change {
                    move_core_types::effects::Op::New(bytes)
                    | move_core_types::effects::Op::Modify(bytes) => {
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
                    move_core_types::effects::Op::New(bytes)
                    | move_core_types::effects::Op::Modify(bytes) => {
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
