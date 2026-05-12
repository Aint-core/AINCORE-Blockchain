use super::*;

/// Generate a valid signed test transaction for mempool testing
fn make_test_tx(index: usize) -> String {
    use ed25519_dalek::{Signer, SigningKey};
    
    let seed = [42u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    let sender = public_key[0..64].to_string();
    
    let chain_id = std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| "AINCORE-MAINNET-1".to_string());
    let payload = format!("transfer:{}", index);
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
    }).to_string()
}

#[test]
fn test_mempool_limit() {
    let mut mempool = Mempool::new();
    
    // Fill up to limit
    for i in 0..MAX_PENDING_TXS {
        mempool.add_transaction(make_test_tx(i));
    }
    
    assert_eq!(mempool.pending_txs.len(), MAX_PENDING_TXS);
    
    // Try to add one more (different index = unique tx)
    mempool.add_transaction(make_test_tx(MAX_PENDING_TXS + 1));
    
    // Should be rejected, size stays same
    assert_eq!(mempool.pending_txs.len(), MAX_PENDING_TXS);
}

#[test]
fn test_seen_txs_clearing() {
    let mut mempool = Mempool::new();
    
    // Fill up seen_txs by adding transactions and clearing pending
    for i in 0..MAX_SEEN_TXS {
        mempool.add_transaction(make_test_tx(i));
        if mempool.pending_txs.len() >= MAX_PENDING_TXS {
            mempool.pending_txs.clear();
        }
    }
    
    // seen_txs should be at MAX_SEEN_TXS now (LRU evicts oldest)
    // Add one more to trigger LRU eviction
    mempool.pending_txs.clear(); // Make room
    mempool.add_transaction(make_test_tx(MAX_SEEN_TXS + 1));
    
    // seen_txs should still be at MAX_SEEN_TXS (LRU evicts one, adds one)
    assert!(mempool.seen_txs.len() <= MAX_SEEN_TXS);
}
