use super::*;

/// Generate a valid signed test transaction for mempool testing
fn make_test_tx(index: usize) -> String {
    use ed25519_dalek::{Signer, SigningKey};

    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();

    let chain_id =
        blockchain::chain_id();
    let payload_struct =
        vm_move::TransactionPayload::PublishModule(vec![index.to_le_bytes().to_vec()]);
    let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
    let sequence_number = index as u64;

    // Sign canonical form (F4: + gas_limit:gas_price:input_objects).
    // This helper emits gas_limit=1000, gas_price=1, input_objects=[].
    let message = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, sequence_number, 1000u64, 1u128, ""
    );
    let signature = signing_key.sign(message.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": 1000,
        "gas_price": 1,
        "sequence_number": sequence_number,
        "public_key": public_key,
        "signature": sig_hex,
    })
    .to_string()
}

/// A signed tx from a DISTINCT sender per `seed_byte`, all at sequence 0.
/// Needed where the assertion is about FIFO order: get_pending_transactions
/// sorts each sender's queue by sequence_number, so same-sender fixtures make
/// an order assertion pass even when the ordering under test is broken.
fn make_test_tx_distinct_sender(seed_byte: u8) -> String {
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
    let chain_id =
        blockchain::chain_id();
    let payload_struct =
        vm_move::TransactionPayload::PublishModule(vec![vec![seed_byte; 4]]);
    let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
    let message = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, 0u64, 1000u64, 1u128, ""
    );
    let signature = signing_key.sign(message.as_bytes());
    serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "gas_limit": 1000,
        "gas_price": 1,
        "sequence_number": 0,
        "public_key": public_key,
        "signature": hex::encode(signature.to_bytes()),
    })
    .to_string()
}

fn make_test_tx_with_payload(index: usize, payload: String) -> String {
    make_test_tx_with_payload_and_gas(index, payload, 1000, 1)
}

fn make_test_tx_with_payload_and_gas(
    index: usize,
    payload: String,
    gas_limit: u64,
    gas_price: u128,
) -> String {
    use ed25519_dalek::{Signer, SigningKey};

    let seed = [43u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
    let chain_id =
        blockchain::chain_id();
    let sequence_number = index as u64;
    // F4: bind gas_limit/gas_price/input_objects (input_objects=[] here).
    let message = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, sequence_number, gas_limit, gas_price, ""
    );
    let signature = signing_key.sign(message.as_bytes());

    serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": gas_limit,
        "gas_price": gas_price,
        "sequence_number": sequence_number,
        "public_key": public_key,
        "signature": hex::encode(signature.to_bytes()),
    })
    .to_string()
}

#[test]
fn test_rejects_invalid_bcs_payload_before_enqueue() {
    let mut mempool = Mempool::new();
    let err = mempool
        .add_transaction(make_test_tx_with_payload(1, "transfer:not-bcs".to_string()))
        .expect_err("legacy string payload must reject");

    assert!(err.contains("Invalid payload hex"));
    assert_eq!(mempool.pending_txs.len(), 0);
}

#[test]
fn test_rejects_script_payload_before_enqueue() {
    let mut mempool = Mempool::new();
    let payload =
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::Script(vec![0xca, 0xfe])).unwrap());
    let err = mempool
        .add_transaction(make_test_tx_with_payload(2, payload))
        .expect_err("script payload must reject");

    assert!(err.contains("Raw script payloads are disabled"));
    assert_eq!(mempool.pending_txs.len(), 0);
}

#[test]
fn test_rejects_zero_gas_price_before_enqueue() {
    let mut mempool = Mempool::new();
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![1]])).unwrap(),
    );
    let err = mempool
        .add_transaction(make_test_tx_with_payload_and_gas(3, payload, 1000, 0))
        .expect_err("zero gas price must reject");

    assert!(err.contains("Gas price too low"));
    assert_eq!(mempool.pending_txs.len(), 0);
}

#[test]
fn test_rejects_duplicate_pending_sender_nonce() {
    let mut mempool = Mempool::new();
    let payload_a = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![1]])).unwrap(),
    );
    let payload_b = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![2]])).unwrap(),
    );

    mempool
        .add_transaction(make_test_tx_with_payload(4, payload_a))
        .expect("first tx accepted");
    let err = mempool
        .add_transaction(make_test_tx_with_payload(4, payload_b))
        .expect_err("second tx with same sender nonce must reject");

    assert!(err.contains("Duplicate pending nonce"));
    assert_eq!(mempool.pending_txs.len(), 1);
}

#[test]
fn test_pending_nonce_released_when_tx_drained() {
    let mut mempool = Mempool::new();
    let payload_a = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![1]])).unwrap(),
    );
    let payload_b = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![2]])).unwrap(),
    );

    mempool
        .add_transaction(make_test_tx_with_payload(5, payload_a))
        .expect("first tx accepted");
    let drained = mempool.get_pending_transactions(1);
    assert_eq!(drained.len(), 1);

    mempool
        .add_transaction(make_test_tx_with_payload(5, payload_b))
        .expect("nonce can be re-submitted after pending tx is drained for execution");
    assert_eq!(mempool.pending_txs.len(), 1);
}

#[test]
fn test_mempool_limit() {
    let mut mempool = Mempool::new();

    // Fill up to limit
    for i in 0..MAX_PENDING_TXS {
        let _ = mempool.add_transaction(make_test_tx(i));
    }

    assert_eq!(mempool.pending_txs.len(), MAX_PENDING_TXS);

    // Try to add one more (different index = unique tx)
    let _ = mempool.add_transaction(make_test_tx(MAX_PENDING_TXS + 1));

    // Should be rejected, size stays same
    assert_eq!(mempool.pending_txs.len(), MAX_PENDING_TXS);
}

#[test]
fn test_seen_txs_clearing() {
    let mut mempool = Mempool::new();

    // Fill up seen_txs by adding transactions and clearing pending
    for i in 0..MAX_SEEN_TXS {
        let _ = mempool.add_transaction(make_test_tx(i));
        if mempool.pending_txs.len() >= MAX_PENDING_TXS {
            mempool.pending_txs.clear();
        }
    }

    // seen_txs should be at MAX_SEEN_TXS now (LRU evicts oldest)
    // Add one more to trigger LRU eviction
    mempool.pending_txs.clear(); // Make room
    let _ = mempool.add_transaction(make_test_tx(MAX_SEEN_TXS + 1));

    // seen_txs should still be at MAX_SEEN_TXS (LRU evicts one, adds one)
    assert!(mempool.seen_txs.len() <= MAX_SEEN_TXS);
}

/// M-04 REGRESSION TEST
///
/// Asserts that the 100KB size guard rejects oversized payloads BEFORE any
/// JSON parsing, BCS decoding, or signature verification runs. Previously
/// the size check sat near the bottom of `add_transaction`, meaning an
/// attacker could force the node to burn CPU on serde + Ed25519 verify
/// (or worse, queue PQC) for arbitrarily large payloads before being
/// rejected.
///
/// Strategy: craft a transaction whose serialized form exceeds the 100KB
/// limit AND has a deliberately malformed signature ("not-a-signature"),
/// then assert the returned error mentions the size limit rather than
/// signature/JSON failure. If the size check ever drifts back behind
/// signature verify, the error string will change and this test fails.
#[test]
fn test_oversized_tx_rejected_before_signature_verification() {
    let mut mempool = Mempool::new();

    // ~120KB of hex characters — comfortably above the 100KB cap regardless
    // of how the rest of the JSON envelope is sized.
    let huge_payload = "ab".repeat(60 * 1024); // 120_000 bytes

    let tx = serde_json::json!({
        "chain_id": blockchain::chain_id(),
        "sender": "deadbeefdeadbeefdeadbeefdeadbeef",
        "input_objects": [],
        "payload": huge_payload,
        "args": [],
        "gas_limit": 1000,
        "gas_price": 1,
        "sequence_number": 0,
        "public_key": "00".repeat(32),
        // Deliberately invalid: not 128 hex chars (Ed25519) and not 9254
        // (PQC). If the size check ran AFTER signature verification, we'd
        // see "Unknown Signature Scheme size" or similar instead.
        "signature": "not-a-signature",
    })
    .to_string();

    assert!(
        tx.len() > 100 * 1024,
        "test invariant: payload must exceed 100KB limit"
    );

    let err = mempool
        .add_transaction(tx)
        .expect_err("oversized tx must be rejected");

    assert!(
        err.contains("too large") || err.contains("limit"),
        "size guard must fire BEFORE signature/scheme validation. \
         Got error: {:?}",
        err
    );
}

/// B8: post-quantum transactions are ML-DSA-65 (FIPS 204). The transaction
/// carries its 1952-byte public key, the sender is SHA-256 of it, and the
/// mempool verifies it with nothing but the transaction, like Ed25519.
mod ml_dsa_b8 {
    use super::*;

    fn ml_dsa_tx(seed: u8, sequence_number: u64) -> (serde_json::Value, crypto::MlDsa65Key) {
        let key = crypto::MlDsa65Key::from_seed(&[seed; 32]);
        let public_key = key.public_key();
        let sender = crypto::derive_address(&public_key).unwrap();
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![
                seed,
            ]]))
            .unwrap(),
        );
        let mut tx = serde_json::json!({
            "chain_id": blockchain::chain_id(),
            "sender": sender,
            "input_objects": [],
            "payload": payload,
            "args": [],
            "gas_limit": 1000,
            "gas_price": 1,
            "sequence_number": sequence_number,
            "public_key": hex::encode(&public_key),
            "signature": "",
        });
        sign(&mut tx, &key);
        (tx, key)
    }

    fn sign(tx: &mut serde_json::Value, key: &crypto::MlDsa65Key) {
        let parsed: executor::Transaction = serde_json::from_value(tx.clone()).unwrap();
        let message = executor::admission::signing_message(&parsed);
        tx["signature"] = serde_json::json!(hex::encode(key.sign(message.as_bytes())));
    }

    #[test]
    fn a_signed_ml_dsa_65_transaction_is_admitted() {
        let (tx, _) = ml_dsa_tx(1, 0);
        assert_eq!(tx["signature"].as_str().unwrap().len(), 2 * 3309);
        Mempool::new()
            .add_transaction(tx.to_string())
            .expect("a valid ML-DSA-65 transaction");
    }

    #[test]
    fn a_tampered_ml_dsa_65_transaction_is_refused() {
        let (tx, key) = ml_dsa_tx(2, 0);

        let mut gas = tx.clone();
        gas["gas_limit"] = serde_json::json!(2000);
        let err = Mempool::new().add_transaction(gas.to_string()).unwrap_err();
        assert!(err.contains("Invalid signature"), "{err}");

        let mut flipped = tx.clone();
        let mut sig = hex::decode(tx["signature"].as_str().unwrap()).unwrap();
        sig[17] ^= 1;
        flipped["signature"] = serde_json::json!(hex::encode(sig));
        let err = Mempool::new()
            .add_transaction(flipped.to_string())
            .unwrap_err();
        assert!(err.contains("Invalid signature"), "{err}");

        // Another key's signature over the same transaction.
        let mut other = tx.clone();
        sign(&mut other, &crypto::MlDsa65Key::from_seed(&[3; 32]));
        assert!(Mempool::new().add_transaction(other.to_string()).is_err());

        // A sender that is not the key's address, re-signed by the key.
        let mut sender = tx.clone();
        sender["sender"] = serde_json::json!("ab".repeat(32));
        sign(&mut sender, &key);
        let err = Mempool::new()
            .add_transaction(sender.to_string())
            .unwrap_err();
        assert!(err.contains("Sender mismatch"), "{err}");
    }

    /// The pre-standard Dilithium5 sizes (2592-byte key, 4627-byte signature)
    /// and mixed sizes are no scheme: refused before any verification.
    #[test]
    fn sizes_of_no_scheme_are_refused() {
        let (tx, _) = ml_dsa_tx(4, 0);
        for (key_bytes, sig_bytes) in [(2592usize, 4627usize), (1952, 64), (32, 3309)] {
            let key = vec![7u8; key_bytes];
            let mut t = tx.clone();
            t["public_key"] = serde_json::json!(hex::encode(&key));
            t["sender"] = serde_json::json!(crypto::derive_address(&key).unwrap());
            t["signature"] = serde_json::json!("00".repeat(sig_bytes));
            let err = Mempool::new().add_transaction(t.to_string()).unwrap_err();
            assert!(err.contains("no scheme"), "{key_bytes}/{sig_bytes}: {err}");
        }
    }
}

/// H-04 REGRESSION TEST (updated Phase 2.2)
///
/// Mempool now dispatches any non-empty `zkp_proof` through
/// `crypto::zkp::verify_tx_attached_proof`. We verify the gate still
/// rejects the obvious failure modes — garbage hex, wrong binding —
/// with diagnostic error messages that distinguish them.
#[test]
fn test_zkp_garbage_hex_rejected_with_specific_diagnostic() {
    use ed25519_dalek::{Signer, SigningKey};

    let mut mempool = Mempool::new();

    let seed = [44u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
    let chain_id =
        blockchain::chain_id();
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![7u8]])).unwrap(),
    );
    let sequence_number = 0u64;
    // F4: tx below uses gas_limit=1000, gas_price=1, input_objects=[].
    let message = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, sequence_number, 1000u64, 1u128, ""
    );
    let signature = signing_key.sign(message.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    // "deadbeef" is valid hex but the bytes do not parse as a
    // STARKProofData envelope — the dispatcher's structural check
    // should catch this with a specific diagnostic.
    let tx = serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": 1000,
        "gas_price": 1,
        "sequence_number": sequence_number,
        "public_key": public_key,
        "signature": sig_hex,
        "zkp_proof": "deadbeef",
    })
    .to_string();

    let err = mempool
        .add_transaction(tx)
        .expect_err("ZKP-tagged tx with garbage envelope must be rejected");

    assert!(
        err.contains("ZKP proof rejected"),
        "error must come from the dispatcher, not a generic fail-closed gate. Got: {:?}",
        err
    );
    assert!(
        err.contains("STARKProofData") || err.contains("envelope") || err.contains("structure"),
        "error must specifically call out the structural failure. Got: {:?}",
        err
    );
}

/// Phase 2.2 — REPLAY PROTECTION
///
/// A structurally valid proof whose `public_inputs` commit to a
/// different transaction's canonical message must be rejected. This
/// blocks proof-detach-and-replay across transactions.
#[test]
fn test_zkp_replayed_proof_with_wrong_binding_rejected() {
    use crypto::zkp::STARKProofData;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let mut mempool = Mempool::new();

    let seed = [55u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
    let chain_id =
        blockchain::chain_id();
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![7u8]])).unwrap(),
    );
    let sequence_number = 0u64;
    // F4: tx below uses gas_limit=1000, gas_price=1, input_objects=[].
    let canonical = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, sequence_number, 1000u64, 1u128, ""
    );
    let signature = signing_key.sign(canonical.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    // Construct a structurally-valid STARKProofData but bind it to a
    // DIFFERENT canonical message ("some-other-tx") — replayed proof
    // scenario.
    let wrong_binding = Sha256::digest(b"some-other-tx").to_vec();
    let proof_envelope = STARKProofData::new(vec![0xFF, 0xEE, 0xDD, 0xCC], wrong_binding);
    let proof_hex = hex::encode(proof_envelope.to_bytes());

    let tx = serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": 1000,
        "gas_price": 1,
        "sequence_number": sequence_number,
        "public_key": public_key,
        "signature": sig_hex,
        "zkp_proof": proof_hex,
    })
    .to_string();

    let err = mempool
        .add_transaction(tx)
        .expect_err("ZKP proof bound to a different tx must be rejected (replay block)");

    assert!(
        err.contains("public inputs") || err.contains("bind") || err.contains("replay"),
        "error must explicitly call out the binding/replay violation. Got: {:?}",
        err
    );
}

/// Phase 5B.11 / PWN-007 PROPER: dedup at the mempool layer must be
/// CANONICAL, not raw-bytes. The same signed TX submitted with reordered
/// JSON keys or extra whitespace must be detected as a duplicate — across
/// EVERY entry point (api_local.rs, api.rs, P2P). This test exercises the
/// mempool directly and proves cross-encoding replay is caught with NO
/// API-layer cooperation.
#[test]
fn pwn007_proper_replay_with_reordered_keys_rejected() {
    use ed25519_dalek::{Signer, SigningKey};

    let mut mempool = Mempool::new();

    // Build a real signed TX (canonical form A).
    let seed = [99u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = hex::encode(sk.verifying_key().to_bytes());
    let sender = crypto::derive_address(sk.verifying_key().as_bytes()).unwrap();
    let chain_id =
        blockchain::chain_id();
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![
            b"pwn007".to_vec()
        ]))
        .unwrap(),
    );
    let seq = 42u64;
    // F4: both tx_a and tx_b use gas_limit=1000, gas_price=1, input_objects=[].
    let canonical_msg = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        chain_id, sender, payload, seq, 1000u64, 1u128, ""
    );
    let sig_hex = hex::encode(sk.sign(canonical_msg.as_bytes()).to_bytes());

    // Form A: keys in one order.
    let tx_a = serde_json::json!({
        "chain_id": chain_id,
        "sender": sender,
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": 1000,
        "gas_price": 1u128,
        "sequence_number": seq,
        "public_key": pk,
        "signature": sig_hex,
    })
    .to_string();

    // Form B: same fields, REORDERED + extra whitespace. Different raw
    // bytes, IDENTICAL canonical signed form, identical signature.
    let tx_b = format!(
        r#"{{ "signature": "{}", "public_key": "{}", "sequence_number": {}, "gas_price": 1, "gas_limit": 1000, "args": [], "payload": "{}", "input_objects": [], "sender": "{}", "chain_id": "{}" }}"#,
        sig_hex, pk, seq, payload, sender, chain_id
    );

    assert_ne!(
        tx_a, tx_b,
        "test setup: raw bytes must differ for the test to be meaningful"
    );

    // First submit succeeds.
    let h1 = mempool
        .add_transaction(tx_a)
        .expect("form A must enter mempool");

    // Second submit (reordered) must be rejected as duplicate.
    let err = mempool
        .add_transaction(tx_b)
        .expect_err("PWN-007: re-encoded duplicate must be rejected at mempool layer");
    assert!(
        err.contains("Duplicate"),
        "rejection must call out duplicate. Got: {:?}",
        err
    );

    // Canonical hash must be identical for both forms.
    assert!(
        err.contains(&h1),
        "duplicate error should reference the original canonical hash {}, got: {:?}",
        h1,
        err
    );
}

/// SEC-#27 — fee-market ordering + admission balance gate.
mod fee_market_admission {
    use super::*;
    use std::sync::Arc;
    use storage::StateDB;

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = format!("/tmp/aincore_feemkt_mempool_{}_{}", std::process::id(), name);
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("open temp db"))
    }

    /// Build a valid Ed25519-signed tx with a sender derived from `seed_byte`
    /// (distinct seed => distinct sender) and the given seq/gas. Returns
    /// (json_tx, sender_address).
    fn signed_tx(seed_byte: u8, seq: u64, gas_limit: u64, gas_price: u128) -> (String, String) {
        use ed25519_dalek::{Signer, SigningKey};

        let signing_key = SigningKey::from_bytes(&[seed_byte; 32]);
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
        let chain_id =
            blockchain::chain_id();
        // Vary payload bytes by (seed, seq) so no two test txs collide on dedup.
        let payload_struct =
            vm_move::TransactionPayload::PublishModule(vec![vec![seed_byte, seq as u8]]);
        let payload = hex::encode(bcs::to_bytes(&payload_struct).unwrap());
        let message = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            chain_id, sender, payload, seq, gas_limit, gas_price, ""
        );
        let signature = signing_key.sign(message.as_bytes());

        let tx = serde_json::json!({
            "chain_id": chain_id,
            "sender": sender,
            "input_objects": [],
            "payload": payload,
            "args": [],
            "gas_limit": gas_limit,
            "gas_price": gas_price,
            "sequence_number": seq,
            "public_key": public_key,
            "signature": hex::encode(signature.to_bytes()),
        })
        .to_string();
        (tx, sender)
    }

    /// `any_pending` answers for THIS transaction only, through both states a
    /// waiting transaction can be in: queued, and loaned to a vertex that has not
    /// committed. The RPC's old "pending" check was `!is_empty()`, true for any
    /// hash at all while anyone else had a transaction queued.
    #[test]
    fn any_pending_matches_this_transaction_while_queued_or_loaned() {
        let db = temp_db("any_pending");
        let (tx, sender) = signed_tx(71, 0, 100_000, 1);
        fund(&db, &sender, 1_000_000_000_000_000_000);
        let mut mp = Mempool::with_storage(db);
        mp.add_transaction(tx.clone())
            .expect("a funded, signed tx is admitted");
        let hash = StateDB::raw_tx_hash(&tx);
        let pending = |mp: &Mempool, h: &str| mp.any_pending(|t| StateDB::raw_tx_hash(t) == h);

        assert!(pending(&mp, &hash), "a queued transaction must be pending");
        assert!(
            !pending(&mp, &"00".repeat(32)),
            "an unknown hash was reported pending because another tx is queued"
        );
        let loaned = mp.get_pending_transactions(10);
        assert_eq!(loaned, vec![tx], "the tx was not loaned out");
        assert!(
            pending(&mp, &hash),
            "a loaned, uncommitted transaction must still be pending"
        );
    }

    /// Build the exact `0x1::coin::CoinStore<0x1::staking::AincoreCoin>` storage
    /// key that `executor::committed_ain_balance` reads (and gas is charged from).
    fn ain_store_key(sender: &str) -> String {
        use move_core_types::{
            account_address::AccountAddress,
            identifier::Identifier,
            language_storage::{StructTag, TypeTag},
        };
        let sys = AccountAddress::from_hex_literal("0x1").unwrap();
        let coin_type = TypeTag::Struct(Box::new(StructTag {
            address: sys,
            module: Identifier::new("staking").unwrap(),
            name: Identifier::new("AincoreCoin").unwrap(),
            type_params: vec![],
        }));
        let store = StructTag {
            address: sys,
            module: Identifier::new("coin").unwrap(),
            name: Identifier::new("CoinStore").unwrap(),
            type_params: vec![coin_type],
        };
        let addr =
            AccountAddress::from_hex_literal(&format!("0x{}", sender.trim_start_matches("0x")))
                .unwrap();
        format!("resource_{}_{}", addr, store)
    }

    // A struct {value: u128} encodes in BCS identically to a bare u128, so the
    // executor's MoveCoin reader round-trips this.
    pub(crate) fn fund(db: &Arc<StateDB>, sender: &str, balance: u128) {
        let _seed = db.seeding();
        db.put(
            &ain_store_key(sender),
            &hex::encode(bcs::to_bytes(&balance).unwrap()),
        )
        .unwrap();
    }

    fn gas_price_of(tx: &str) -> u128 {
        serde_json::from_str::<executor::Transaction>(tx)
            .unwrap()
            .gas_price
    }

    fn seq_of(tx: &str) -> u64 {
        serde_json::from_str::<executor::Transaction>(tx)
            .unwrap()
            .sequence_number
    }

    #[test]
    fn fee_market_orders_by_gas_price_across_senders() {
        let mut mp = Mempool::new(); // no storage -> admission gate fail-open
        let (lo, _) = signed_tx(1, 0, 1000, 1);
        let (hi, _) = signed_tx(2, 0, 1000, 50);
        let (mid, _) = signed_tx(3, 0, 1000, 10);
        mp.add_transaction(lo).unwrap();
        mp.add_transaction(hi).unwrap();
        mp.add_transaction(mid).unwrap();

        let got = mp.get_pending_transactions(3);
        let prices: Vec<u128> = got.iter().map(|t| gas_price_of(t)).collect();
        assert_eq!(prices, vec![50, 10, 1], "must drain highest-fee first");
    }

    #[test]
    fn fee_market_preserves_sender_nonce_order() {
        let mut mp = Mempool::new();
        // SAME sender: seq 0 (low fee) then seq 1 (high fee).
        let (s0, _) = signed_tx(7, 0, 1000, 1);
        let (s1, _) = signed_tx(7, 1, 1000, 100);
        mp.add_transaction(s0).unwrap();
        mp.add_transaction(s1).unwrap();

        let got = mp.get_pending_transactions(2);
        let seqs: Vec<u64> = got.iter().map(|t| seq_of(t)).collect();
        assert_eq!(
            seqs,
            vec![0, 1],
            "a sender's seq 0 must precede seq 1 even though seq 1 pays more"
        );
    }

    #[test]
    fn admission_rejects_unaffordable_tx_when_balance_known() {
        let db = temp_db("admission_reject");
        let (tx, sender) = signed_tx(11, 0, 1000, 5); // needs 1000*5 = 5000
        fund(&db, &sender, 100); // only 100 available
        let mut mp = Mempool::with_storage(db);

        let err = mp
            .add_transaction(tx)
            .expect_err("unaffordable tx must be rejected at the gate");
        assert!(
            err.contains("Insufficient balance for gas"),
            "got: {}",
            err
        );
    }

    #[test]
    fn admission_admits_affordable_tx() {
        let db = temp_db("admission_affordable");
        let (tx, sender) = signed_tx(12, 0, 1000, 5); // needs 5000
        fund(&db, &sender, 10_000);
        let mut mp = Mempool::with_storage(db);
        mp.add_transaction(tx)
            .expect("affordable tx must be admitted");
    }

    #[test]
    /// RE-AUDIT HIGH: this gate used to fail OPEN ("balance unknown -> admit").
    /// An account with no CoinStore can never pay gas, so admitting it handed an
    /// attacker free block space with unlimited fresh keypairs. It now fails
    /// CLOSED, for a paymaster too (see the tests below).
    fn admission_fails_closed_when_store_missing() {
        let db = temp_db("admission_no_store");
        let (tx, _sender) = signed_tx(13, 0, 1000, 5);
        let mut mp = Mempool::with_storage(db);
        let err = mp
            .add_transaction(tx)
            .expect_err("sender with no CoinStore must be rejected at admission");
        assert!(err.contains("no CoinStore"), "got: {err}");
    }

    /// `tx` sponsored by the paymaster with Ed25519 key `seed`, signed by it;
    /// returns the transaction and the paymaster's address.
    fn sponsored(tx: &str, seed: u8) -> (String, String) {
        use ed25519_dalek::{Signer, SigningKey};
        let pm = SigningKey::from_bytes(&[seed; 32]);
        let mut v: serde_json::Value = serde_json::from_str(tx).unwrap();
        let parsed: executor::Transaction = serde_json::from_value(v.clone()).unwrap();
        let sig = pm.sign(&executor::admission::paymaster_message(&parsed));
        v["paymaster"] = serde_json::json!(hex::encode(pm.verifying_key().to_bytes()));
        v["paymaster_signature"] = serde_json::json!(hex::encode(sig.to_bytes()));
        let address = crypto::derive_address(pm.verifying_key().as_bytes()).unwrap();
        (v.to_string(), address)
    }

    /// B13: the paymaster pays, so its balance (at the address derived from
    /// its key) is the one the gate checks; the broke sender does not matter.
    #[test]
    fn admission_checks_the_paymasters_balance() {
        let db = temp_db("admission_paymaster");
        let (tx, sender) = signed_tx(14, 0, 1000, 5); // needs 5000
        fund(&db, &sender, 100); // the sender is broke
        let (tx_pm, paymaster) = sponsored(&tx, 40);
        fund(&db, &paymaster, 10_000);
        Mempool::with_storage(Arc::clone(&db))
            .add_transaction(tx_pm)
            .expect("a funded paymaster's sponsorship is admitted");

        let (tx_broke_pm, broke) = sponsored(&tx, 41);
        fund(&db, &broke, 10);
        let err = Mempool::with_storage(db)
            .add_transaction(tx_broke_pm)
            .unwrap_err();
        assert!(err.contains("Insufficient balance for gas"), "{err}");
    }

    /// B13: naming a paymaster used to skip the balance gate with no
    /// paymaster signature checked ("deadbeef" was admitted). A paymaster
    /// without a valid signature is refused at admission now.
    #[test]
    fn a_paymaster_without_a_valid_signature_is_refused() {
        let db = temp_db("admission_paymaster_forged");
        let (tx, sender) = signed_tx(15, 0, 1000, 5);
        fund(&db, &sender, 100);

        let mut v: serde_json::Value = serde_json::from_str(&tx).unwrap();
        v["paymaster"] = serde_json::json!("deadbeef");
        let err = Mempool::with_storage(Arc::clone(&db))
            .add_transaction(v.to_string())
            .unwrap_err();
        assert!(err.contains("paymaster without a signature"), "{err}");

        let (good, _) = sponsored(&tx, 42);
        let mut forged: serde_json::Value = serde_json::from_str(&good).unwrap();
        let other = sponsored(&tx, 43).0;
        let other: serde_json::Value = serde_json::from_str(&other).unwrap();
        forged["paymaster_signature"] = other["paymaster_signature"].clone();
        let err = Mempool::with_storage(db)
            .add_transaction(forged.to_string())
            .unwrap_err();
        assert!(err.contains("Invalid paymaster signature"), "{err}");
    }
}

/// Orphan-loss fix: a pulled transaction that never executes must come BACK,
/// and one that executed must be gone for good. This is the exact live
/// failure: a briefly-lagging node orphaned its own vertex, the payload
/// vanished, the sender's nonce sequence had a permanent hole, and every
/// later transaction died with Invalid Sequence — the sender wedged forever.
#[test]
fn test_inflight_loan_ledger_requeues_orphans_and_settles_executed() {
    let mut mp = Mempool::new();
    let tx_a = make_test_tx(0);
    let tx_b = make_test_tx(1);
    mp.add_transaction(tx_a.clone()).expect("admit a");
    mp.add_transaction(tx_b.clone()).expect("admit b");

    // Pull both: they are LOANED, pending drains.
    let pulled = mp.get_pending_transactions(10);
    assert_eq!(pulled.len(), 2);
    assert!(
        mp.get_pending_transactions(10).is_empty(),
        "pending must be drained after the pull"
    );

    // Block commits with only A executed; B (orphaned/deferred) stays loaned.
    mp.mark_executed(std::slice::from_ref(&tx_a));

    // Too young: nothing to reclaim yet.
    assert_eq!(mp.requeue_stale(std::time::Duration::from_secs(3600)), 0);

    // Old enough: B must come back — and ONLY B.
    assert_eq!(mp.requeue_stale(std::time::Duration::from_secs(0)), 1);
    let back = mp.get_pending_transactions(10);
    assert_eq!(
        back,
        vec![tx_b.clone()],
        "the unexecuted tx must return to pending"
    );

    // Resubmitting either is still refused (seen_txs dedup holds).
    assert!(mp.add_transaction(tx_a).is_err(), "executed tx stays deduped");
    assert!(mp.add_transaction(tx_b).is_err(), "requeued tx stays deduped");
}

/// BUG_LEDGER B9: loans age in the caller's clock, not the wall clock. A
/// loan stamped at 100 is not stale at 129 with a 30 s limit, and is at 130,
/// however much wall time passed; a pinned clock never re-queues.
#[test]
fn loans_age_in_the_callers_clock() {
    let mut mp = Mempool::new();
    let tx = make_test_tx(0);
    mp.add_transaction(tx.clone()).expect("admit");
    assert_eq!(mp.get_pending_transactions_at(10, 100), vec![tx.clone()]);
    assert_eq!(mp.requeue_stale_at(30, 100), 0, "a pinned clock never re-queues");
    assert_eq!(mp.requeue_stale_at(30, 129), 0);
    assert_eq!(mp.requeue_stale_at(30, 130), 1);
    assert_eq!(mp.get_pending_transactions_at(10, 130), vec![tx]);
}

/// The block builder trims transactions that do not fit the vertex byte budget.
/// Those raws are still LOANED (get_pending_transactions moved them to
/// inflight), so they must be handed back intact and re-servable in their
/// ORIGINAL payload order.
///
/// Uses DISTINCT senders on purpose: with one sender, get_pending_transactions
/// sorts by sequence_number and the order assertion passes even when the
/// return order is reversed — the first version of this test did exactly that
/// and would not have caught the double-reverse bug it was written for.
#[test]
fn test_return_unshipped_restores_order_and_preserves_attempts() {
    let mut mempool = Mempool::new();
    let txs: Vec<String> = (0..4).map(|i| make_test_tx_distinct_sender(70 + i)).collect();
    for (i, t) in txs.iter().enumerate() {
        assert!(mempool.add_transaction(t.clone()).is_ok(), "tx {} accepted", i);
    }

    let loaned = mempool.get_pending_transactions(4);
    assert_eq!(loaned.len(), 4, "all four are loaned out");
    assert!(mempool.is_empty(), "loaned txs leave the pending queue");

    // The trimmer pops from the TAIL, so the returned slice is in reverse
    // payload order for a payload that kept [0, 1].
    let trimmed: Vec<String> = vec![loaned[3].clone(), loaned[2].clone()];
    mempool.return_unshipped(&trimmed);

    let again = mempool.get_pending_transactions(4);
    assert_eq!(again.len(), 2, "exactly the two returned txs are re-servable");
    assert_eq!(
        again,
        vec![loaned[2].clone(), loaned[3].clone()],
        "returned txs must come back in their original payload order"
    );

    // A raw that is not on loan is ignored rather than duplicated.
    mempool.return_unshipped(&[make_test_tx_distinct_sender(90)]);
    assert!(
        mempool.get_pending_transactions(4).is_empty(),
        "a raw that was never loaned must not be injected into the queue"
    );
}

/// An executed tx must not linger in pending_txs. mark_executed strips `meta`,
/// and get_pending_transactions only selects raws that HAVE meta, so a raw left
/// behind is unselectable forever and still counts against MAX_PENDING_TXS.
#[test]
fn test_mark_executed_evicts_from_pending_queue() {
    let mut mempool = Mempool::new();
    let a = make_test_tx_distinct_sender(80);
    let b = make_test_tx_distinct_sender(81);
    assert!(mempool.add_transaction(a.clone()).is_ok());
    assert!(mempool.add_transaction(b.clone()).is_ok());

    // Loan both out, then return them (as a byte-budget trim would).
    let loaned = mempool.get_pending_transactions(2);
    assert_eq!(loaned.len(), 2);
    mempool.return_unshipped(&loaned);
    assert!(!mempool.is_empty(), "returned txs are pending again");

    // One of them lands via another validator's vertex.
    mempool.mark_executed(std::slice::from_ref(&a));

    let left = mempool.get_pending_transactions(4);
    assert_eq!(left, vec![b.clone()], "only the unexecuted tx remains servable");
    assert!(
        mempool.is_empty(),
        "no unselectable raw may be left pinned in pending_txs"
    );
}

/// AUDIT-CRITICAL (pre-mainnet B5). `gas_limit` had no ceiling, so a ~0.001 AIN
/// transaction could buy 1e15 units of Move execution on EVERY validator at once
/// and halt the chain (no wall-clock timeout exists on Move execution). Admission
/// must refuse anything above the protocol ceiling.
#[test]
fn test_gas_limit_above_protocol_ceiling_is_rejected() {
    let mut mempool = Mempool::new();

    // The chain-halt shape: enormous gas_limit at the minimum gas price.
    let halt = make_test_tx_with_payload_and_gas(
        1,
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![1u8; 4]])).unwrap()),
        1_000_000_000_000_000,
        1,
    );
    let err = mempool.add_transaction(halt).expect_err("must be rejected");
    assert!(
        err.contains("MAX_GAS_LIMIT"),
        "rejection must name the ceiling, got: {}",
        err
    );

    // Exactly at the ceiling is still admissible.
    let ok_tx = make_test_tx_with_payload_and_gas(
        2,
        hex::encode(bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![2u8; 4]])).unwrap()),
        executor::MAX_GAS_LIMIT,
        1,
    );
    assert!(
        mempool.add_transaction(ok_tx).is_ok(),
        "a transaction at exactly MAX_GAS_LIMIT must still be accepted"
    );
}

/// G3 FX-6: admission checks the chain id installed from `sys:chain_id`. The
/// env is not a source; it is set here, naming another chain, only to prove
/// that nothing reads it. Boot refuses such an env.
#[test]
fn admission_never_reads_the_chain_id_env() {
    std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-SOME-OTHER-CHAIN");
    let result = Mempool::new().add_transaction(make_test_tx(0));
    std::env::remove_var("AINCORE_CHAIN_ID");
    result.expect("a transaction for the installed chain is admitted");
}
