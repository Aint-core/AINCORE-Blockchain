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

    // Sign: "chain_id:sender:payload:sequence_number"
    let message = format!("{}:{}:{}:{}", chain_id, sender, payload, sequence_number);
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
    let message = format!("{}:{}:{}:{}", chain_id, sender, payload, sequence_number);
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
fn test_pqc_signature_rejected_at_mempool_until_wired() {
    let mut mempool = Mempool::new();

    let chain_id = std::env::var("AINCORE_CHAIN_ID")
        .unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
    // 9254 hex chars = 4627 bytes raw = Dilithium5 detached signature length.
    let fake_pqc_sig = "ab".repeat(9254 / 2);
    assert_eq!(fake_pqc_sig.len(), 9254);

    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![1u8]]))
            .unwrap(),
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
        // Public key length is irrelevant — H-01 gate triggers off the
        // signature length first, before any Ed25519 / PQC processing.
        "public_key": "00".repeat(32),
        "signature": fake_pqc_sig,
    })
    .to_string();

    let err = mempool
        .add_transaction(tx)
        .expect_err("PQC submissions must be rejected at the mempool layer");

    assert!(
        err.contains("PQC") || err.contains("Dilithium"),
        "PQC reject must clearly tell submitters the gate is closed. \
         Got error: {:?}",
        err
    );
}

/// H-04 REGRESSION TEST
///
/// Mempool must fail-closed for any transaction that carries a non-empty
/// `zkp_proof` field until the STARK verifier is wired into block
/// execution. Previously the executor logged the presence of the proof
/// and continued — pure security theater that gave users a false sense
/// of assurance.
#[test]
fn test_zkp_tagged_transaction_rejected_at_mempool_until_wired() {
    use ed25519_dalek::{Signer, SigningKey};

    let mut mempool = Mempool::new();

    let seed = [44u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();
    let chain_id = std::env::var("AINCORE_CHAIN_ID")
        .unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
    let payload = hex::encode(
        bcs::to_bytes(&vm_move::TransactionPayload::PublishModule(vec![vec![7u8]]))
            .unwrap(),
    );
    let sequence_number = 0u64;
    let message = format!("{}:{}:{}:{}", chain_id, sender, payload, sequence_number);
    let signature = signing_key.sign(message.as_bytes());
    let sig_hex = hex::encode(signature.to_bytes());

    // Attach a non-empty zkp_proof — value doesn't matter, the gate trips
    // on presence + non-emptiness alone.
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
        .expect_err("ZKP-tagged tx must be rejected at mempool until verifier is wired");

    assert!(
        err.contains("ZKP") || err.contains("STARK") || err.contains("fail-closed"),
        "ZKP reject must clearly tell submitters the verifier is not yet wired. \
         Got error: {:?}",
        err
    );
}
