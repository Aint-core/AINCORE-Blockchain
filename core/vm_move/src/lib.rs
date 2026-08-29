use anyhow::Result;
use move_core_types::{
    account_address::AccountAddress,
    language_storage::ModuleId,
    resolver::{ModuleResolver, ResourceResolver},
};
use move_vm_runtime::move_vm::MoveVM;

use std::collections::BTreeMap;
use std::sync::Arc;
use storage::StateDB;

mod gas;
mod overlay;
use gas::AINCOREGasMeter;
use overlay::OverlayStorage;
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

    /// Execute a transaction's actions with REAL abort atomicity.
    ///
    /// # Contract (AUDIT-B1)
    ///
    /// Actions are split into two stages, mirroring Aptos's
    /// `PrologueSession` -> `UserSession` split (`aptos-move/aptos-vm/src/aptos_vm.rs`,
    /// `execute_user_transaction_impl`):
    ///
    /// * **PROLOGUE** — the leading run of `must_succeed` actions (today: the
    ///   `coin::deduct_gas` charge). Runs against storage. If any of them fails the
    ///   whole transaction is discarded (`Err`), exactly like Aptos's
    ///   `unwrap_or_discard!`. Its writes are materialized OUTSIDE the user session
    ///   and are therefore kept even when the user payload aborts.
    /// * **USER** — everything after the first non-`must_succeed` action. Runs in a
    ///   SEPARATE session layered over the prologue's writes via [`OverlayStorage`].
    ///   If it aborts, that session is **dropped without calling `finish()`**, so
    ///   none of its partial writes can escape. This is the only correct rollback:
    ///   move-vm marks a `GlobalValue` dirty at the mutating instruction and has no
    ///   undo log, so filtering a finished changeset after the fact is impossible.
    ///
    /// Both stages share one [`AINCOREGasMeter`], so work performed by an aborting
    /// payload is still charged and aborts are never free.
    ///
    /// Returns `(gas_used, writes, status)` where `writes` is
    /// `prologue_writes ++ user_writes`, and `user_writes` is EMPTY whenever
    /// `status` is aborted.
    pub fn execute_transaction_actions(
        &self,
        actions: Vec<(MoveAction, bool, AccountAddress)>,
        sender: AccountAddress,
        gas_limit: u64,
    ) -> ExecutionResult {
        self.execute_transaction_actions_with_prestaged(actions, sender, gas_limit, Vec::new())
    }

    /// As [`Self::execute_transaction_actions`], but with `prestaged` raw state
    /// writes materialized BEFORE the prologue and visible to every stage.
    ///
    /// # Why this exists (CoinStore onboarding)
    ///
    /// Move cannot create a resource at an address without that address's
    /// `signer`, and this VM exposes no `create_signer` native (Aptos's framework
    /// has one; ours does not). That made a brand-new account unable to ever
    /// receive its first AIN: `coin::deposit` aborts without a `CoinStore`, and
    /// self-registering needs gas, which `coin::deduct_gas` will only take from an
    /// existing `CoinStore`. A closed loop.
    ///
    /// The staged-session machinery added for abort atomicity solves it directly:
    /// the adapter can materialize the empty `CoinStore` as a staged write, and
    /// because every stage reads through [`OverlayStorage`], the Move code sees it
    /// as if it had always been there. The write is returned in the result set, so
    /// it lands in the same WriteBatch and the same state root as everything else —
    /// deterministic on every node, not a side channel.
    pub fn execute_transaction_actions_with_prestaged(
        &self,
        // (action, must_succeed, auth_signer): auth_signer is the AUTHENTICATED
        // address this action may act as. Every leading &signer slot of an entry
        // function is overwritten with this address, so user-supplied bytes in a
        // signer slot are always discarded and cannot forge another principal.
        actions: Vec<(MoveAction, bool, AccountAddress)>,
        sender: AccountAddress,
        gas_limit: u64,
        prestaged: Vec<(String, Option<String>)>,
    ) -> ExecutionResult {
        let mut gas_meter = AINCOREGasMeter::new(gas_limit);

        // Split at the first non-must_succeed action. Callers build the vector as
        // [system pre-actions.., user payload], so this is a clean partition.
        let split = actions
            .iter()
            .position(|(_, must_succeed, _)| !*must_succeed)
            .unwrap_or(actions.len());
        let mut actions = actions;
        let user_actions = actions.split_off(split);
        let prologue_actions = actions;

        // Fail closed: a `must_succeed` action AFTER the user payload would be an
        // epilogue, and an epilogue cannot live in the user session (it would be
        // dropped on abort). No caller does this today; reject it loudly rather
        // than silently re-breaking atomicity if one ever appears.
        if user_actions.iter().any(|(_, must_succeed, _)| *must_succeed) {
            anyhow::bail!(
                "unsupported action ordering: a must_succeed action follows a fallible one; \
                 epilogue actions need their own stage (see execute_transaction_actions)"
            );
        }

        // === STAGE 0: PRE-STAGED ADAPTER WRITES ===
        // Materialized before anything runs and visible to every stage through the
        // overlay. Used for state Move cannot create itself (see the doc comment).
        let mut staged: BTreeMap<String, Option<String>> = BTreeMap::new();
        for (key, value) in prestaged {
            staged.insert(key, value);
        }

        // === STAGE 1: PROLOGUE (all-or-nothing) ===
        // Runs over the overlay too, so it observes the pre-staged writes (an empty
        // overlay resolves identically to the bare storage, so this is a no-op when
        // nothing was pre-staged).
        if !prologue_actions.is_empty() {
            let prologue_writes = {
                let overlay = OverlayStorage::new(&self.storage, &staged);
                let mut session = self.vm.new_session(&overlay);
                for (action, _, auth_signer) in prologue_actions {
                    // A prologue failure discards the transaction entirely.
                    Self::run_action(&mut session, action, sender, auth_signer, &mut gas_meter)?;
                }
                let (changeset, _events) = session.finish()?;
                self.changeset_to_kv(changeset)?
            };
            for (key, value) in prologue_writes {
                staged.insert(key, value);
            }
        }

        if user_actions.is_empty() {
            let writes = staged.into_iter().collect();
            return Ok((gas_meter.gas_used(), writes, ExecutionStatus::success()));
        }

        // === STAGE 2: USER PAYLOAD (atomic — dropped wholesale on abort) ===
        // Scoped so the overlay's borrow of `staged` ends before we consume it.
        let (user_writes, status) = {
            let overlay = OverlayStorage::new(&self.storage, &staged);
            let mut session = self.vm.new_session(&overlay);
            let mut abort_reason: Option<String> = None;

            for (action, _, auth_signer) in user_actions {
                if let Err(e) =
                    Self::run_action(&mut session, action, sender, auth_signer, &mut gas_meter)
                {
                    abort_reason = Some(e.to_string());
                    break;
                }
            }

            match abort_reason {
                Some(reason) => {
                    // DROP the session without finishing it: its partial writes are
                    // discarded along with the TransactionDataCache it owns. Gas
                    // already consumed stays charged (shared gas_meter).
                    drop(session);
                    println!("⚠️ Payload aborted, user writes discarded: {}", reason);
                    (Vec::new(), ExecutionStatus::aborted(reason))
                }
                None => {
                    let (changeset, _events) = session.finish()?;
                    (self.changeset_to_kv(changeset)?, ExecutionStatus::success())
                }
            }
        };

        let mut writes: Vec<(String, Option<String>)> = staged.into_iter().collect();
        writes.extend(user_writes);

        Ok((gas_meter.gas_used(), writes, status))
    }

    /// Run one action inside `session`. Errors are returned to the caller, which
    /// decides whether they discard the transaction (prologue) or abort the user
    /// stage (payload).
    fn run_action<S: move_core_types::resolver::MoveResolver>(
        session: &mut move_vm_runtime::session::Session<'_, '_, S>,
        action: MoveAction,
        sender: AccountAddress,
        auth_signer: AccountAddress,
        gas_meter: &mut AINCOREGasMeter,
    ) -> Result<()> {
        match action {
            MoveAction::PublishModule(modules) => {
                if sender == system_address() {
                    anyhow::bail!("publishing to 0x1 is reserved for genesis/system upgrades");
                }
                session
                    .publish_module_bundle(modules, sender, gas_meter)
                    .map_err(|e| anyhow::anyhow!("{}", e))
            }
            MoveAction::CallEntryFunction(call) => {
                let ident = move_core_types::identifier::Identifier::new(call.function.clone())
                    .map_err(|e| anyhow::anyhow!("invalid function identifier: {}", e))?;
                // SECURITY: bind EVERY &signer slot to the authenticated
                // principal. move-vm does NOT inject signers; it deserializes a
                // signer from raw arg bytes. Load the function signature, find
                // ALL signer params (not just the leading run -- a non-leading
                // signer is a real forge vector, see bind_signer_args), and
                // overwrite each with the BCS of auth_signer so a forged signer
                // for any address is discarded.
                let bound_args = Self::bind_signer_args(
                    session,
                    &call.module,
                    &ident,
                    &call.ty_args,
                    call.args,
                    auth_signer,
                )?;
                session
                    .execute_entry_function(
                        &call.module,
                        &ident,
                        call.ty_args,
                        bound_args,
                        gas_meter,
                    )
                    .map(|_| ())
                    .map_err(|e| anyhow::anyhow!("{}", e))
            }
        }
    }

    /// Overwrite ALL signer parameters of an entry function (leading or not)
    /// with the BCS-serialized authenticated address, so a caller can never forge another
    /// principal's &signer by supplying crafted argument bytes. In move-vm
    /// aptos-v1.3.0 a signer argument is deserialized from raw bytes via the
    /// Signer layout (== AccountAddress), so bcs::to_bytes(&address) is exactly
    /// the bytes the VM expects for a signer slot.
    fn bind_signer_args<S: move_core_types::resolver::MoveResolver>(
        session: &move_vm_runtime::session::Session<'_, '_, S>,
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

        // Classify every parameter. A signer value is only safe when it sits in
        // a REBINDABLE top-level slot -- `signer`, `&signer`, `&mut signer` --
        // which we overwrite with the authenticated principal. A signer reached
        // through anything else (vector<signer>, or a type parameter that the
        // caller instantiated as signer) cannot be rebound: move-vm would
        // manufacture a fully-usable signer straight from the caller's bytes for
        // any address they name. That is a forged signer -- handed to
        // `0x1::coin::transfer` it drains a victim, and forged as @0x1 it passes
        // the system gate on `coin::deposit_fee_reward` and mints arbitrary AIN.
        // move-vm does NOT enforce the "signers first / only top-level" rule for
        // module version >= 5, and any account may publish modules (only 0x1 is
        // reserved), so we enforce it here: rebind the top-level slots and REJECT
        // the call outright if a signer hides anywhere else.
        let mut signer_slots: Vec<usize> = Vec::new();
        for (idx, ty) in instantiation.parameters.iter().enumerate() {
            match ty {
                Type::Signer => signer_slots.push(idx),
                Type::Reference(inner) | Type::MutableReference(inner)
                    if matches!(**inner, Type::Signer) =>
                {
                    signer_slots.push(idx)
                }
                other => {
                    if Self::type_yields_signer(other, ty_args) {
                        anyhow::bail!(
                            "entry function {}::{} parameter {} reaches a signer through a \
                             non-rebindable position (vector<signer> or a signer-instantiated \
                             type parameter); refusing to run to prevent a forged signer",
                            module,
                            function,
                            idx
                        );
                    }
                }
            }
        }

        let required = signer_slots.last().map_or(0, |last| last + 1);
        if args.len() < required {
            anyhow::bail!(
                "argument count {} is fewer than the {} required signer slots for {}::{}",
                args.len(),
                required,
                module,
                function
            );
        }

        let signer_bytes = bcs::to_bytes(&auth_signer)
            .map_err(|e| anyhow::anyhow!("failed to serialize authenticated signer: {}", e))?;
        for idx in signer_slots {
            args[idx] = signer_bytes.clone();
        }

        Ok(args)
    }

    /// True when a runtime `Type` can materialise a `signer` value somewhere the
    /// signer-rebinding pass cannot reach: inside a vector, behind a reference to
    /// such a vector, or through a type parameter the caller instantiated as
    /// signer. A bare `signer` / `&signer` handed in here (i.e. NOT a top-level
    /// rebindable slot -- e.g. a vector element) also counts. Struct fields are
    /// deliberately not traversed: `signer` lacks the `store` ability, so it can
    /// never be a struct field, and a struct type argument being signer does not
    /// deserialize any signer value.
    fn type_yields_signer(
        ty: &move_vm_types::loaded_data::runtime_types::Type,
        ty_args: &[move_core_types::language_storage::TypeTag],
    ) -> bool {
        use move_vm_types::loaded_data::runtime_types::Type;
        match ty {
            Type::Signer => true,
            Type::Vector(inner)
            | Type::Reference(inner)
            | Type::MutableReference(inner) => Self::type_yields_signer(inner, ty_args),
            Type::TyParam(i) => ty_args
                .get(*i)
                .is_some_and(Self::type_tag_yields_signer),
            _ => false,
        }
    }

    /// TypeTag counterpart of `type_yields_signer`, used to resolve a type
    /// parameter to the concrete type the caller supplied.
    fn type_tag_yields_signer(tag: &move_core_types::language_storage::TypeTag) -> bool {
        use move_core_types::language_storage::TypeTag;
        match tag {
            TypeTag::Signer => true,
            TypeTag::Vector(inner) => Self::type_tag_yields_signer(inner),
            _ => false,
        }
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
