use super::*;

/// Generate a valid signed test transaction for mempool testing
fn make_test_tx(index: usize) -> String {
    use ed25519_dalek::{Signer, SigningKey};

    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();

    let chain_id =
        std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
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
        std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
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
        "chain_id": std::env::var("AINCORE_CHAIN_ID")
            .unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string()),
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

/// H-01 REGRESSION TEST
///
/// Mempool must fail-closed for PQC (9254-char Dilithium5 hex) signatures
/// until full Dilithium5 verification is wired at the mempool layer.
/// Previously this path silently accepted any string of the right length
/// without checking sender↔pubkey binding or running signature verify,
/// turning the mempool into a free DoS surface that only got cleaned up
/// inside block execution.
#[test]
fn test_pqc_signature_rejected_at_mempool_when_storage_absent() {
    // Phase 2.1 (H-01): a storage-less Mempool (Mempool::new) keeps the
    // Phase 1 fail-closed behaviour because real Dilithium5 verification
    // requires the storage handle to look up pqc_pubkey_{sender}.
    let mut mempool = Mempool::new();

    let chain_id =
        std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
    // 9254 hex chars = 4627 bytes raw = Dilithium5 detached signature length.
    let fake_pqc_sig = "ab".repeat(9254 / 2);
    assert_eq!(fake_pqc_sig.len(), 9254);

    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![1u8]])).unwrap(),
    );

    let tx = serde_json::json!({
        "chain_id": chain_id,
        "sender": "deadbeefdeadbeefdeadbeefdeadbeef",
        "input_objects": [],
        "payload": payload,
        "args": [],
        "gas_limit": 1000,
        "gas_price": 1,
        "sequence_number": 0,
        // Public key length is irrelevant — gate triggers off the
        // signature length first.
        "public_key": "00".repeat(32),
        "signature": fake_pqc_sig,
    })
    .to_string();

    let err = mempool
        .add_transaction(tx)
        .expect_err("PQC submissions must be rejected when mempool has no storage");

    assert!(
        err.contains("storage-backed") || err.contains("PQC") || err.contains("Dilithium"),
        "PQC reject must clearly explain why. Got: {:?}",
        err
    );
}

/// Phase 2.1 (H-01) — REAL VERIFICATION TESTS
///
/// These tests exercise the full Dilithium5 verification path that
/// replaces the Phase 1 fail-closed gate when the mempool has a
/// storage handle. They cover:
///   - happy path (legitimate PQC TX accepted)
///   - missing pubkey registration (rejected)
///   - wrong sender↔pubkey binding (rejected, prevents pubkey spoofing)
///   - invalid signature bytes (rejected)
///   - tampered message (rejected)
mod pqc_phase21 {
    use super::*;
    use std::sync::Arc;
    use storage::StateDB;

    fn temp_db(name: &str) -> Arc<StateDB> {
        let path = format!("/tmp/aincore_pqc_mempool_{}_{}", std::process::id(), name);
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("open temp db"))
    }

    fn build_pqc_tx(
        sender: &str,
        signature_hex: &str,
        sequence_number: u64,
        chain_id: &str,
        payload: &str,
    ) -> String {
        serde_json::json!({
            "chain_id": chain_id,
            "sender": sender,
            "input_objects": [],
            "payload": payload,
            "args": [],
            "gas_limit": 1000,
            "gas_price": 1,
            "sequence_number": sequence_number,
            "public_key": "",
            "signature": signature_hex,
        })
        .to_string()
    }

    /// Generates (sender, pubkey_bytes, signing function, chain_id, payload) for tests.
    fn fresh_pqc_identity() -> (
        String,
        Vec<u8>,
        pqcrypto_dilithium::dilithium5::SecretKey,
        String,
        String,
    ) {
        use pqcrypto_traits::sign::PublicKey;
        let (pk, sk) = pqcrypto_dilithium::dilithium5::keypair();
        let pk_bytes = pk.as_bytes().to_vec();
        let sender = crypto::derive_address(&pk_bytes).unwrap();
        let chain_id =
            std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
        let payload = hex::encode(
            bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![9u8]])).unwrap(),
        );
        (sender, pk_bytes, sk, chain_id, payload)
    }

    fn sign_pqc_message(
        sk: &pqcrypto_dilithium::dilithium5::SecretKey,
        chain_id: &str,
        sender: &str,
        payload: &str,
        seq: u64,
    ) -> String {
        use pqcrypto_traits::sign::DetachedSignature;
        // F4: build_pqc_tx emits gas_limit=1000, gas_price=1, input_objects=[].
        let msg = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            chain_id, sender, payload, seq, 1000u64, 1u128, ""
        );
        let sig = pqcrypto_dilithium::dilithium5::detached_sign(msg.as_bytes(), sk);
        hex::encode(sig.as_bytes())
    }

    #[test]
    fn happy_path_real_dilithium5_signature_accepted() {
        let db = temp_db("happy");
        let (sender, pk_bytes, sk, chain_id, payload) = fresh_pqc_identity();
        db.put(&format!("pqc_pubkey_{}", sender), &hex::encode(&pk_bytes))
            .unwrap();
        let sig_hex = sign_pqc_message(&sk, &chain_id, &sender, &payload, 0);

        let mut mempool = Mempool::with_storage(db);
        let tx = build_pqc_tx(&sender, &sig_hex, 0, &chain_id, &payload);

        let hash = mempool
            .add_transaction(tx)
            .expect("legitimate PQC TX must be accepted");
        assert_eq!(hash.len(), 64, "tx hash must be sha256 hex");
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn pubkey_not_registered_rejected() {
        let db = temp_db("not_registered");
        let (sender, _pk_bytes, sk, chain_id, payload) = fresh_pqc_identity();
        // Deliberately DON'T put pqc_pubkey_{sender} into storage.
        let sig_hex = sign_pqc_message(&sk, &chain_id, &sender, &payload, 0);

        let mut mempool = Mempool::with_storage(db);
        let tx = build_pqc_tx(&sender, &sig_hex, 0, &chain_id, &payload);
        let err = mempool
            .add_transaction(tx)
            .expect_err("unregistered must fail");
        assert!(
            err.contains("not registered"),
            "error must explain pubkey is not registered. Got: {:?}",
            err
        );
    }

    #[test]
    fn sender_pubkey_binding_mismatch_rejected() {
        let db = temp_db("binding");
        let (sender_a, pk_a, sk_a, chain_id, payload) = fresh_pqc_identity();
        // Register A's pubkey, but the tx claims sender B (different address).
        db.put(
            &format!("pqc_pubkey_{}", "11111111111111111111111111111111"),
            &hex::encode(&pk_a),
        )
        .unwrap();
        let _ = sender_a;
        // Sign with A's secret key but bind to the spoofed sender so the
        // mempool's storage lookup actually finds the pubkey.
        let spoofed = "11111111111111111111111111111111";
        let sig_hex = sign_pqc_message(&sk_a, &chain_id, spoofed, &payload, 0);

        let mut mempool = Mempool::with_storage(db);
        let tx = build_pqc_tx(spoofed, &sig_hex, 0, &chain_id, &payload);
        let err = mempool
            .add_transaction(tx)
            .expect_err("binding mismatch must fail");
        assert!(
            err.contains("sender mismatch") || err.contains("tampered"),
            "error must surface the pubkey↔sender binding violation. Got: {:?}",
            err
        );
    }

    #[test]
    fn tampered_message_rejected() {
        let db = temp_db("tampered_msg");
        let (sender, pk_bytes, sk, chain_id, payload) = fresh_pqc_identity();
        db.put(&format!("pqc_pubkey_{}", sender), &hex::encode(&pk_bytes))
            .unwrap();
        // Sign sequence_number=0 but submit sequence_number=1 → signature
        // does not match the message the mempool will reconstruct.
        let sig_hex = sign_pqc_message(&sk, &chain_id, &sender, &payload, 0);

        let mut mempool = Mempool::with_storage(db);
        let tx = build_pqc_tx(&sender, &sig_hex, 1, &chain_id, &payload);
        let err = mempool
            .add_transaction(tx)
            .expect_err("tampered msg must fail");
        assert!(
            err.contains("verification"),
            "error must call out failed signature verification. Got: {:?}",
            err
        );
    }

    #[test]
    fn corrupt_signature_bytes_rejected() {
        let db = temp_db("corrupt_sig");
        let (sender, pk_bytes, _sk, chain_id, payload) = fresh_pqc_identity();
        db.put(&format!("pqc_pubkey_{}", sender), &hex::encode(&pk_bytes))
            .unwrap();
        // Construct a syntactically-correct-length signature filled with
        // zeros. Cryptographically invalid; verification must reject.
        let bad_sig = hex::encode(vec![0u8; 4627]);

        let mut mempool = Mempool::with_storage(db);
        let tx = build_pqc_tx(&sender, &bad_sig, 0, &chain_id, &payload);
        let err = mempool
            .add_transaction(tx)
            .expect_err("corrupt sig must fail");
        assert!(
            err.contains("verification") || err.contains("format"),
            "error must call out verification or format failure. Got: {:?}",
            err
        );
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
        std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
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
        std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
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
        std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
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
