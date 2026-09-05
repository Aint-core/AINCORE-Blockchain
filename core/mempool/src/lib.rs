use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use storage::StateDB;

/// B1 (best-effort): early-reject a `0x1::staking::join_validator_set` whose BLS
/// proof-of-possession does not verify, before it enters the mempool. The
/// executor pre-dispatch gate is authoritative; this mirrors it for early reject.
/// `join_validator_set(account: &signer, stake_amount: u128, public_key,
/// bls_public_key, bls_pop)` -> args[2]=public_key, args[3]=bls_public_key,
/// args[4]=bls_pop.
fn verify_join_validator_pop_mempool(
    call: &vm_move::EntryFunctionCall,
    tx_public_key_hex: &str,
) -> Result<(), String> {
    // 0x1 system address renders as 31 zero bytes + 01 in hex (no direct
    // move_core_types dep in mempool, so compare via the canonical Display form).
    let is_system = format!("{}", call.module.address())
        .trim_start_matches("0x")
        .trim_start_matches('0')
        == "1";
    if !is_system
        || call.module.name().as_str() != "staking"
        || call.function != "join_validator_set"
    {
        return Ok(());
    }
    if call.args.len() < 5 {
        return Err(format!(
            "join_validator_set: expected 5 args, got {}",
            call.args.len()
        ));
    }
    let public_key: Vec<u8> = bcs::from_bytes(&call.args[2])
        .map_err(|e| format!("join_validator_set: malformed public_key arg: {}", e))?;
    let bls_public_key: Vec<u8> = bcs::from_bytes(&call.args[3])
        .map_err(|e| format!("join_validator_set: malformed bls_public_key arg: {}", e))?;
    let bls_pop: Vec<u8> = bcs::from_bytes(&call.args[4])
        .map_err(|e| format!("join_validator_set: malformed bls_pop arg: {}", e))?;
    let tx_public_key = hex::decode(tx_public_key_hex.trim_start_matches("0x"))
        .map_err(|e| format!("join_validator_set: malformed tx public_key hex: {}", e))?;
    if public_key.len() != 32 {
        return Err(format!(
            "join_validator_set: public_key must be 32 bytes, got {}",
            public_key.len()
        ));
    }
    if public_key != tx_public_key {
        return Err("join_validator_set: public_key arg must equal tx.public_key".into());
    }
    if bls_public_key.len() != 48 {
        return Err(format!(
            "join_validator_set: bls_public_key must be 48 bytes, got {}",
            bls_public_key.len()
        ));
    }
    if bls_pop.len() != 96 {
        return Err(format!(
            "join_validator_set: bls_pop must be 96 bytes, got {}",
            bls_pop.len()
        ));
    }
    match crypto::bls::BLSEngine::consensus().verify_possession(&bls_public_key, &bls_pop) {
        Ok(true) => Ok(()),
        Ok(false) => Err("join_validator_set: BLS proof-of-possession failed verification".into()),
        Err(e) => Err(format!(
            "join_validator_set: BLS PoP verification error: {:?}",
            e
        )),
    }
}

const MAX_PENDING_TXS: usize = 5000;
/// How many times a loaned transaction may return to the queue before it is
/// dropped for good (orphaned payloads need one; a permanently failing tx must
/// not loop forever).
const MAX_REQUEUE_ATTEMPTS: u8 = 3;
const MAX_SEEN_TXS: usize = 50000;
const MIN_GAS_PRICE: u128 = 1;

/// Dilithium5 signature length as raw bytes (NIST round-3 spec).
const PQC_DILITHIUM5_SIG_BYTES: usize = 4627;
/// Dilithium5 signature length as hex characters.
const PQC_DILITHIUM5_HEX_LEN: usize = PQC_DILITHIUM5_SIG_BYTES * 2;
/// Dilithium5 public key length as raw bytes (NIST round-3 spec).
const PQC_DILITHIUM5_PUBKEY_BYTES: usize = 2592;

pub struct Mempool {
    pending_txs: VecDeque<String>,
    seen_txs: HashSet<String>,       // Deduplication
    seen_order: VecDeque<String>,    // Bounded cache tracking
    pending_nonces: HashSet<String>, // sender:sequence_number in the pending queue
    /// LOANED, NOT GONE (orphan-loss fix): transactions handed to consensus by
    /// `get_pending_transactions` move HERE instead of vanishing. They leave for
    /// good only when `mark_executed` reports them executed in a committed
    /// block; anything still here after `requeue_stale`'s age limit goes back to
    /// `pending_txs`. Before this, a vertex that never committed (a node
    /// briefly behind the network orphans its own vertex) silently destroyed
    /// its whole payload — the sender's nonce sequence then had a permanent
    /// hole, every later transaction died with "Invalid Sequence", and the
    /// account was wedged forever. Keyed by the RAW transaction string; value is loaned_at.
    inflight: std::collections::HashMap<String, (std::time::Instant, u8)>,
    /// RE-AUDIT MEDIUM (perf): parsed (sender, sequence_number, gas_price) per
    /// raw tx, filled once at admission so selection never re-parses every
    /// pending transaction under the mempool lock on every tick.
    meta: std::collections::HashMap<String, (String, u64, u128)>,
    /// Attempt counter carried from `requeue_stale` back into the next pull.
    requeue_attempts: std::collections::HashMap<String, u8>,
    /// Optional storage handle. When `Some`, `add_transaction` performs
    /// full Dilithium5 (PQC) verification by looking up the canonical
    /// `pqc_pubkey_{sender}` binding. When `None`, PQC submissions are
    /// fail-closed at the mempool gate (Phase 1 H-01 behaviour).
    /// Production callers should always pass storage via
    /// [`Mempool::with_storage`].
    storage: Option<Arc<StateDB>>,
}

impl Mempool {
    /// Construct a mempool without storage. PQC submissions will be
    /// fail-closed at the gate. Useful for unit tests that exercise
    /// Ed25519 paths only.
    pub fn new() -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            inflight: std::collections::HashMap::new(),
            meta: std::collections::HashMap::new(),
            requeue_attempts: std::collections::HashMap::new(),
            seen_order: VecDeque::new(),
            pending_nonces: HashSet::new(),
            storage: None,
        }
    }

    /// Construct a mempool with storage access. PQC submissions go
    /// through full Dilithium5 verification against the canonical
    /// `pqc_pubkey_{sender}` binding before being queued.
    ///
    /// Phase 2.1 (H-01): this is the constructor production node code
    /// should use — wiring real PQC verification at the mempool entry
    /// instead of leaving it as a fail-closed gate.
    pub fn with_storage(storage: Arc<StateDB>) -> Self {
        Self {
            pending_txs: VecDeque::new(),
            seen_txs: HashSet::new(),
            inflight: std::collections::HashMap::new(),
            meta: std::collections::HashMap::new(),
            requeue_attempts: std::collections::HashMap::new(),
            seen_order: VecDeque::new(),
            pending_nonces: HashSet::new(),
            storage: Some(storage),
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool {
    /// Phase 5B.11 / PWN-007 PROPER fix: canonical TX identity.
    ///
    /// The dedup key MUST be derived from the same canonical form the
    /// signature is bound to (`chain_id:sender:payload:seq`), NOT from
    /// raw JSON bytes. Otherwise an attacker can replay a signed TX by
    /// reordering JSON keys or tweaking whitespace — different raw bytes,
    /// same signature, same semantic intent — and bypass `seen_txs`.
    ///
    /// Hashing canonical fields at this layer also closes ALL upstream
    /// entry points in one place: api_local.rs, api.rs, P2P TX inbound,
    /// and any future RPC method. None of them can submit a "different"
    /// version of a TX that has already been seen.
    fn canonical_tx_hash(tx: &executor::Transaction) -> String {
        // F4: dedup identity must match the signed canonical form, which now
        // also binds gas_limit, gas_price, and input_objects.
        let canonical = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            tx.chain_id,
            tx.sender,
            tx.payload,
            tx.sequence_number,
            tx.gas_limit,
            tx.gas_price,
            tx.input_objects.join(",")
        );
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn add_transaction(&mut self, tx: String) -> Result<String, String> {
        // === M-04 FIX: SIZE GUARD FIRST (cheapest reject path) ===
        const TX_BYTE_LIMIT: usize = 100 * 1024; // 100KB

        if tx.len() > TX_BYTE_LIMIT {
            return Err(format!(
                "Transaction too large ({} bytes). limit {}KB.",
                tx.len(),
                TX_BYTE_LIMIT / 1024
            ));
        }

        // === CHAIN ID VALIDATION ===
        // L5 FIX: Match mainnet genesis default to prevent unexpected rejections
        let expected_chain =
            std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());

        // Parse the transaction to enforce Chain ID early
        use executor::Transaction;
        let parsed_tx = serde_json::from_str::<Transaction>(&tx)
            .map_err(|_| "Invalid JSON format".to_string())?;
        if parsed_tx.chain_id != expected_chain {
            return Err(format!(
                "Invalid Chain ID (Expected {}, Got {})",
                expected_chain, parsed_tx.chain_id
            ));
        }

        if parsed_tx.gas_price < MIN_GAS_PRICE {
            return Err(format!(
                "Gas price too low: {} < minimum {}",
                parsed_tx.gas_price, MIN_GAS_PRICE
            ));
        }

        if parsed_tx.gas_limit == 0 {
            return Err("Gas limit must be greater than 0".to_string());
        }

        // AUDIT-CRITICAL (pre-mainnet B5): mirror the executor's protocol
        // ceiling so an over-limit transaction is refused at admission rather
        // than occupying a mempool slot it can never be executed from.
        if parsed_tx.gas_limit > executor::MAX_GAS_LIMIT {
            return Err(format!(
                "Gas limit {} exceeds MAX_GAS_LIMIT {}",
                parsed_tx.gas_limit,
                executor::MAX_GAS_LIMIT
            ));
        }

        // SEC-#27: best-effort admission balance gate. The executor reserves the
        // full gas_limit*gas_price upfront (Ethereum-style), so a sender that
        // cannot cover it fails at execution and only wastes block space. Reject
        // such txs at the gate when a committed balance is readable. Fail-open by
        // construction — never false-rejects a valid tx:
        //   * no storage handle, an unreadable/uninitialised CoinStore, or an
        //     overflowing gas cost  -> admit (executor stays authoritative; an
        //     account funded by an earlier same-block tx is not yet visible here),
        //   * a paymaster-sponsored tx is paid by the paymaster, not the sender,
        //     so the sender-balance check is skipped entirely.
        // Phase 5B.11 / PWN-004 + PWN-007 COMBINED: compute the canonical
        // dedup hash and check `seen_txs` IMMEDIATELY after parse + cheap
        // header checks. This:
        //   - PWN-004: rejects byte-identical AND re-encoded replays
        //     BEFORE Dilithium-5 / Ed25519 signature verify (cheapest
        //     possible reject path for any replay attack)
        //   - PWN-007: catches all attacker JSON re-encodings because
        //     the canonical form is the same the signature is bound to
        //     ({chain_id}:{sender}:{payload}:{seq})
        //   - covers ALL upstream entry points (api_local, api.rs, P2P
        //     TX inbound, future RPC methods) in one place — no API-
        //     layer canonicalization needed.
        let tx_hash = Self::canonical_tx_hash(&parsed_tx);
        if self.seen_txs.contains(&tx_hash) {
            return Err(format!("Duplicate transaction: {}", tx_hash));
        }

        // === H-04 PROMOTED (Phase 2.2): WIRE THE STARK VERIFIER ===
        //
        // Phase 1 fail-closed the zkp_proof field. Phase 2.2 routes any
        // attached proof through crypto::zkp::verify_tx_attached_proof,
        // which:
        //   1. hex-decodes the envelope,
        //   2. parses it as STARKProofData (rejects structural garbage),
        //   3. asserts the proof's public inputs commit to
        //      SHA-256("{chain_id}:{sender}:{payload}:{seq}") so a
        //      detached-and-replayed proof cannot be reused on a
        //      different transaction,
        //   4. invokes STARKVerifier::verify on the dispatched proof.
        //
        // The underlying STARKVerifier is a Phase-2 placeholder today,
        // so in practice no valid proof can be constructed yet. But the
        // wiring is real: the moment a real AIR is plumbed in, valid
        // proofs flow through unchanged and invalid ones are rejected
        // with specific diagnostic categories instead of the blanket
        // "fail-closed gate" message.
        if let Some(ref proof_hex) = parsed_tx.zkp_proof {
            if !proof_hex.is_empty() {
                let canonical_msg = format!(
                    "{}:{}:{}:{}",
                    parsed_tx.chain_id,
                    parsed_tx.sender,
                    parsed_tx.payload,
                    parsed_tx.sequence_number
                );
                if let Err(e) =
                    crypto::zkp::verify_tx_attached_proof(proof_hex, canonical_msg.as_bytes())
                {
                    return Err(format!("ZKP proof rejected: {}", e));
                }
            }
        }

        let payload_bytes = hex::decode(parsed_tx.payload.trim_start_matches("0x"))
            .map_err(|_| "Invalid payload hex: expected BCS TransactionPayload".to_string())?;
        match bcs::from_bytes::<vm_move::TransactionPayload>(&payload_bytes) {
            Ok(vm_move::TransactionPayload::EntryFunction(call)) => {
                // B1 (best-effort early reject): if this is a join_validator_set
                // call, verify the BLS proof-of-possession here so a malformed /
                // rogue-key join never enters the mempool. The executor
                // pre-dispatch gate is the AUTHORITATIVE check; this only saves
                // mempool/consensus work. Non-join calls pass through untouched.
                verify_join_validator_pop_mempool(&call, &parsed_tx.public_key)?;
            }
            Ok(vm_move::TransactionPayload::PublishModule(_)) => {}
            Ok(vm_move::TransactionPayload::Script(_)) => {
                return Err("Raw script payloads are disabled".to_string());
            }
            Err(e) => {
                return Err(format!("Invalid BCS TransactionPayload: {}", e));
            }
        }

        // === H-01 PROMOTED (Phase 2.1): REAL DILITHIUM5 VERIFICATION ===
        //
        // PQC submissions used to be silently accepted (DoS surface) or
        // fail-closed (Phase 1). Phase 2.1 wires full Dilithium5
        // verification at the mempool gate by mirroring the VM-layer
        // verify_native_aa_signature path:
        //
        //   1. Look up the canonical pqc_pubkey_{sender} binding in
        //      storage (registered out-of-band during onboarding).
        //   2. Assert sender == derive_address(pqc_pubkey) — catches
        //      pubkey-spoofing-as-sender, an authentication tightening
        //      the VM-layer code does not currently perform.
        //   3. Decode the 9254-hex (4627-byte) detached signature.
        //   4. Verify the Dilithium5 signature against the canonical
        //      submission message format.
        //
        // If storage is not available to this mempool instance (Mempool
        // constructed via ::new() instead of ::with_storage(...) — only
        // used in unit tests that don't exercise PQC), fall back to the
        // Phase 1 fail-closed behaviour so an unconfigured mempool
        // doesn't accidentally accept unverified PQC.
        if parsed_tx.signature.len() == PQC_DILITHIUM5_HEX_LEN {
            let storage = match &self.storage {
                Some(s) => s,
                None => {
                    return Err("PQC (Dilithium5) signatures require a storage-backed \
                         mempool. This instance was constructed without \
                         storage; submit via the node API instead."
                        .to_string());
                }
            };

            // 1. Look up canonical PQC public key.
            let pk_key = format!("pqc_pubkey_{}", parsed_tx.sender);
            let pk_hex = match storage.get(&pk_key) {
                Ok(Some(s)) => s,
                _ => {
                    return Err(format!(
                        "PQC public key not registered for sender {}. \
                         Register pqc_pubkey_{{sender}} before submitting \
                         Dilithium5-signed transactions.",
                        parsed_tx.sender
                    ));
                }
            };
            let pk_bytes = match hex::decode(&pk_hex) {
                Ok(b) => b,
                Err(e) => {
                    return Err(format!("Registered PQC pubkey is not valid hex: {}", e));
                }
            };
            if pk_bytes.len() != PQC_DILITHIUM5_PUBKEY_BYTES {
                return Err(format!(
                    "Registered PQC pubkey has wrong size: {} (expected {})",
                    pk_bytes.len(),
                    PQC_DILITHIUM5_PUBKEY_BYTES
                ));
            }

            // 2. Sender↔pubkey binding via canonical address derivation
            // (matches `aincore-cli pqc-keygen` and the Ed25519 path:
            // hex(SHA-256(pubkey)[..16])).
            let derived = crypto::derive_address(&pk_bytes)
                .map_err(|e| format!("PQC address derivation failed: {}", e))?;
            if derived != parsed_tx.sender {
                return Err(format!(
                    "PQC sender mismatch: registered pubkey derives address \
                     {}, but transaction claims sender {}. Pubkey↔sender \
                     binding has been tampered with.",
                    derived, parsed_tx.sender
                ));
            }

            // 3. Decode detached signature.
            let sig_bytes = match hex::decode(&parsed_tx.signature) {
                Ok(s) => s,
                Err(e) => {
                    return Err(format!("PQC signature is not valid hex: {}", e));
                }
            };
            if sig_bytes.len() != PQC_DILITHIUM5_SIG_BYTES {
                return Err(format!(
                    "PQC signature has wrong size: {} (expected {})",
                    sig_bytes.len(),
                    PQC_DILITHIUM5_SIG_BYTES
                ));
            }

            // 4. Verify Dilithium5.
            use pqcrypto_dilithium::dilithium5;
            use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

            let pk = dilithium5::PublicKey::from_bytes(&pk_bytes)
                .map_err(|_| "Invalid Dilithium5 public key format".to_string())?;
            let sig = dilithium5::DetachedSignature::from_bytes(&sig_bytes)
                .map_err(|_| "Invalid Dilithium5 signature format".to_string())?;

            // Canonical submission message — must match what wallets sign.
            // We use the same shape as the Ed25519 path so wallet code can
            // share message construction between schemes.
            // F4: bind gas_limit, gas_price, input_objects in the signed message.
            let message = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                parsed_tx.chain_id,
                parsed_tx.sender,
                parsed_tx.payload,
                parsed_tx.sequence_number,
                parsed_tx.gas_limit,
                parsed_tx.gas_price,
                parsed_tx.input_objects.join(",")
            );
            if dilithium5::verify_detached_signature(&sig, message.as_bytes(), &pk).is_err() {
                return Err("Invalid Dilithium5 signature verification".to_string());
            }

            // Verification passed — fall through to the rest of the
            // pipeline (hash dedupe, size, mempool limits, nonce dedupe)
            // by jumping past the Ed25519 branch below.
        } else if parsed_tx.signature.len() == 128 {
            // 64 bytes hex
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            if let Ok(pk_bytes) = hex::decode(&parsed_tx.public_key) {
                match crypto::derive_address(&pk_bytes) {
                    Ok(expected_sender) if expected_sender == parsed_tx.sender => {}
                    Ok(expected_sender) => {
                        return Err(format!(
                            "Sender mismatch (expected {}, got {})",
                            expected_sender, parsed_tx.sender
                        ));
                    }
                    Err(e) => {
                        return Err(format!("Address derivation failed: {}", e));
                    }
                }
                if let Ok(vk) =
                    VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0; 32]))
                {
                    if let Ok(sig_bytes) = hex::decode(&parsed_tx.signature) {
                        if let Ok(sig) = Signature::from_slice(&sig_bytes) {
                            // F4: bind gas_limit, gas_price, input_objects.
                            let message = format!(
                                "{}:{}:{}:{}:{}:{}:{}",
                                parsed_tx.chain_id,
                                parsed_tx.sender,
                                parsed_tx.payload,
                                parsed_tx.sequence_number,
                                parsed_tx.gas_limit,
                                parsed_tx.gas_price,
                                parsed_tx.input_objects.join(",")
                            );
                            if vk.verify(message.as_bytes(), &sig).is_err() {
                                return Err("Invalid Signature Verification".to_string());
                            }
                        } else {
                            return Err("Invalid signature bytes".to_string());
                        }
                    } else {
                        return Err("Invalid signature hex".to_string());
                    }
                } else {
                    return Err("Invalid public key".to_string());
                }
            } else {
                return Err("Invalid public key hex".to_string());
            }
        } else {
            // PQC (9254-char Dilithium5) is rejected earlier by the H-01
            // fail-closed gate. Any other length is unsupported.
            return Err("Unknown Signature Scheme size".to_string());
        }

        // (tx_hash already computed early — see PWN-004 + PWN-007 block above.)

        // (M-04: size guard was moved to the top of add_transaction so it
        // runs before any expensive parsing or signature verification.)

        // Economic gate runs AFTER authentication (Ed25519 / PQC) so a rejected
        // signature is reported as such; the gate itself is a single storage read.
        if parsed_tx.paymaster.is_none() {
            if let Some(storage) = &self.storage {
                if let Some(gas_cost) =
                    (parsed_tx.gas_limit as u128).checked_mul(parsed_tx.gas_price)
                {
                    match executor::committed_ain_balance(storage, &parsed_tx.sender) {
                        Some(balance) if balance < gas_cost => {
                            return Err(format!(
                                "Insufficient balance for gas: have {}, need {} (gas_limit {} × gas_price {})",
                                balance, gas_cost, parsed_tx.gas_limit, parsed_tx.gas_price
                            ));
                        }
                        Some(_) => {}
                        // RE-AUDIT HIGH: this used to fail OPEN. An account with no
                        // CoinStore can never pay gas (coin::deduct_gas asserts the
                        // store exists), so admitting it buys an attacker free block
                        // space with unlimited fresh keypairs: the executor refuses
                        // the tx at zero cost, and the loan ledger re-queues it. A
                        // sender without a store is rejected at the gate. (A
                        // paymaster-sponsored tx skips this block entirely.)
                        None => {
                            return Err(
                                "Sender has no AIN balance to pay gas (no CoinStore)".to_string(),
                            );
                        }
                    }
                }
            }
        }


        // RE-AUDIT HIGH: the cap must count LOANED transactions too, or a pull
        // simply moves 500 into `inflight` and frees 500 slots for the attacker.
        if self.pending_txs.len() + self.inflight.len() >= MAX_PENDING_TXS {
            return Err(format!(
                "Mempool full ({}+{} inflight / {})",
                self.pending_txs.len(),
                self.inflight.len(),
                MAX_PENDING_TXS
            ));
        }

        let nonce_key = format!("{}:{}", parsed_tx.sender, parsed_tx.sequence_number);
        if self.pending_nonces.contains(&nonce_key) {
            return Err(format!(
                "Duplicate pending nonce for sender {} sequence {}",
                parsed_tx.sender, parsed_tx.sequence_number
            ));
        }

        // Bounded LRU-style eviction
        if self.seen_txs.len() >= MAX_SEEN_TXS {
            if let Some(old_tx) = self.seen_order.pop_front() {
                self.seen_txs.remove(&old_tx);
            }
        }

        self.seen_txs.insert(tx_hash.clone());
        self.seen_order.push_back(tx_hash.clone());
        self.pending_nonces.insert(nonce_key);
        self.meta.insert(
            tx.clone(),
            (parsed_tx.sender.clone(), parsed_tx.sequence_number, parsed_tx.gas_price),
        );
        self.pending_txs.push_back(tx.clone());

        println!(
            "📥 Added transaction to mempool: {}",
            self.pending_txs.len()
        );
        Ok(tx_hash)
    }

    pub fn get_pending_transactions(&mut self, limit: usize) -> Vec<String> {
        if limit == 0 || self.pending_txs.is_empty() {
            return Vec::new();
        }

        // SEC-#27 (fee market): select up to `limit` txs preferring higher
        // gas_price, while preserving each sender's nonce (sequence_number)
        // order — a sender's seq N MUST be chosen before seq N+1 or the executor
        // rejects the gap. This is the geth-style "best head per sender" merge:
        // repeatedly take the highest-gas_price *front* tx (lowest unselected
        // nonce) across senders. Selection order is deterministic (gas_price desc,
        // then original FIFO index) — the leader's block ordering only needs to be
        // self-consistent; every node executes the block in the order it ships.
        use std::collections::BTreeMap;

        let raws: Vec<String> = self.pending_txs.iter().cloned().collect();

        // sender -> [(sequence_number, gas_price, original_index)], nonce-ordered.
        let mut by_sender: BTreeMap<String, Vec<(u64, u128, usize)>> = BTreeMap::new();
        for (idx, raw) in raws.iter().enumerate() {
            // Metadata was parsed once at admission (see `meta`); a raw without
            // it (should not happen) is simply never selected rather than dropped.
            if let Some((sender, seq, gp)) = self.meta.get(raw) {
                by_sender
                    .entry(sender.clone())
                    .or_default()
                    .push((*seq, *gp, idx));
            }
        }
        for q in by_sender.values_mut() {
            q.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
        }

        // Per-sender cursor into its nonce-ordered queue.
        let mut cursor: BTreeMap<String, usize> =
            by_sender.keys().map(|s| (s.clone(), 0usize)).collect();

        let mut selected: Vec<usize> = Vec::with_capacity(limit.min(raws.len()));
        while selected.len() < limit {
            // Highest-gas_price eligible head; tie-break by FIFO index.
            let mut best: Option<(u128, usize, String)> = None;
            for (sender, q) in by_sender.iter() {
                let c = cursor[sender];
                if c < q.len() {
                    let (_, gp, idx) = q[c];
                    let take = match &best {
                        None => true,
                        Some((bgp, bidx, _)) => gp > *bgp || (gp == *bgp && idx < *bidx),
                    };
                    if take {
                        best = Some((gp, idx, sender.clone()));
                    }
                }
            }
            match best {
                Some((_, idx, sender)) => {
                    selected.push(idx);
                    // advance the chosen sender's cursor
                    if let Some(c) = cursor.get_mut(&sender) {
                        *c += 1;
                    }
                }
                None => break, // all sender queues exhausted
            }
        }

        let selected_set: HashSet<usize> = selected.iter().copied().collect();
        let result: Vec<String> = selected.iter().map(|&i| raws[i].clone()).collect();
        let now = std::time::Instant::now();
        for raw in &result {
            self.remove_pending_nonce(raw);
            // Loaned, not gone: see the `inflight` field doc. Attempts carry
            // over across re-queues so a permanently failing tx is bounded.
            let attempts = self.requeue_attempts.remove(raw).unwrap_or(0);
            self.inflight.insert(raw.clone(), (now, attempts));
        }
        // Keep unselected txs in their original FIFO order for the next round.
        self.pending_txs = raws
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !selected_set.contains(i))
            .map(|(_, r)| r)
            .collect();

        result
    }

    pub fn is_empty(&self) -> bool {
        self.pending_txs.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pending_txs.len()
    }

    pub fn get_all_pending(&self) -> &VecDeque<String> {
        &self.pending_txs
    }

    /// Orphan-loss fix: consensus reports the raw transactions that actually
    /// EXECUTED in a committed block; only those leave the loan ledger for good.
    /// Deferred/failed ones stay inflight and come back via `requeue_stale`.
    pub fn mark_executed(&mut self, raws: &[String]) {
        if raws.is_empty() {
            return;
        }
        let done: std::collections::HashSet<&str> = raws.iter().map(|s| s.as_str()).collect();
        for raw in raws {
            self.inflight.remove(raw);
            // Also clear the nonce guard: an executed tx must not keep blocking
            // a resubmission of the same sender:sequence.
            self.remove_pending_nonce(raw);
            self.meta.remove(raw);
            self.requeue_attempts.remove(raw);
        }
        // An executed tx can also be sitting in pending_txs (returned by
        // return_unshipped or requeue_stale, then executed via another
        // validator's vertex). Without meta it can never be selected again, so
        // leaving it there pins it forever and it counts against MAX_PENDING_TXS.
        self.pending_txs.retain(|r| !done.contains(r.as_str()));
    }

    /// Return loaned transactions that never executed within `max_age` to the
    /// pending queue. Heals both failure shapes the live cluster hit: a vertex
    /// that never committed (orphaned payload), and a transaction that reached a
    /// block ahead of its nonce and was refused by the executor. Re-queued
    /// entries re-register their `sender:sequence` guard so a duplicate
    /// submission is still refused at admission; `seen_txs` is intentionally
    /// left alone (the tx has genuinely been seen — resubmission stays deduped).
    /// Returns how many were re-queued.
    /// Return transactions that were LOANED by `get_pending_transactions` but
    /// never shipped in a vertex (the block-builder trimmed them to fit the
    /// vertex byte budget). They are put back at the FRONT of the queue in
    /// their original order and their nonce guard is re-registered.
    ///
    /// Does not INCREMENT `requeue_attempts` (a byte-budget trim is not a failed
    /// execution) but does PRESERVE any count carried in the loan: the loan
    /// stashes the counter inside the inflight tuple, so simply dropping it
    /// would reset a repeatedly-failing transaction's history to zero and defeat
    /// MAX_REQUEUE_ATTEMPTS.
    ///
    /// `raws` arrives in reverse-payload order (the trimmer pops from the tail),
    /// so pushing to the front in THAT order restores the original sequence.
    pub fn return_unshipped(&mut self, raws: &[String]) {
        for raw in raws.iter() {
            let Some((_, attempts)) = self.inflight.remove(raw) else {
                // Not on loan (already executed or re-queued elsewhere): ignore.
                continue;
            };
            if attempts > 0 {
                self.requeue_attempts.insert(raw.clone(), attempts);
            }
            // A raw with no live `meta` is unselectable: get_pending_transactions
            // builds its per-sender queues only from raws that have one, and
            // mark_executed removes meta when the tx lands via another
            // validator's vertex. Re-queuing it would pin it in pending_txs
            // forever, so drop it instead.
            let Some((sender, seq, _)) = self.meta.get(raw).cloned() else {
                self.requeue_attempts.remove(raw);
                continue;
            };
            self.pending_nonces.insert(format!("{}:{}", sender, seq));
            self.pending_txs.push_front(raw.clone());
        }
    }

    pub fn requeue_stale(&mut self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let stale: Vec<(String, u8)> = self
            .inflight
            .iter()
            .filter(|(_, (at, _))| now.duration_since(*at) > max_age)
            .map(|(raw, (_, n))| (raw.clone(), *n))
            .collect();
        let mut requeued = 0usize;
        let mut dropped = 0usize;
        for (raw, attempts) in &stale {
            self.inflight.remove(raw);
            // RE-AUDIT HIGH: bounded. A tx that keeps failing (bad nonce forever,
            // unpayable gas) must not become an immortal 30s loop that burns
            // every validator's CPU and block space.
            if *attempts + 1 >= MAX_REQUEUE_ATTEMPTS {
                self.meta.remove(raw);
                self.requeue_attempts.remove(raw);
                dropped += 1;
                continue;
            }
            self.requeue_attempts.insert(raw.clone(), attempts + 1);
            if let Some((sender, seq, _)) = self.meta.get(raw) {
                self.pending_nonces.insert(format!("{}:{}", sender, seq));
            }
            self.pending_txs.push_back(raw.clone());
            requeued += 1;
        }
        if requeued > 0 || dropped > 0 {
            println!(
                "♻️  Mempool re-queued {} stale inflight tx(s), dropped {} after {} attempts",
                requeued, dropped, MAX_REQUEUE_ATTEMPTS
            );
        }
        requeued
    }

    fn remove_pending_nonce(&mut self, tx: &str) {
        if let Ok(parsed_tx) = serde_json::from_str::<executor::Transaction>(tx) {
            self.pending_nonces.remove(&format!(
                "{}:{}",
                parsed_tx.sender, parsed_tx.sequence_number
            ));
        }
    }
}

// Fungsi main bisa dihapus jika crate ini adalah library
// fn main() {
//     println!("Hello, world!");
// }
#[cfg(test)]
mod tests;
