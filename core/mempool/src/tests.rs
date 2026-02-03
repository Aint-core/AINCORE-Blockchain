use super::*;

#[test]
fn test_mempool_limit() {
    let mut mempool = Mempool::new();
    
    // Fill up to limit
    for i in 0..MAX_PENDING_TXS {
            mempool.add_transaction(format!("tx_{}", i));
    }
    
    assert_eq!(mempool.pending_txs.len(), MAX_PENDING_TXS);
    
    // Try to add one more
    mempool.add_transaction("overflow_tx".to_string());
    
    // Should be rejected, size stays same
    assert_eq!(mempool.pending_txs.len(), MAX_PENDING_TXS);
}

#[test]
fn test_seen_txs_clearing() {
    let mut mempool = Mempool::new();
        // Fill up seen_txs
    for i in 0..MAX_SEEN_TXS {
            mempool.add_transaction(format!("tx_{}", i));
            if mempool.pending_txs.len() >= MAX_PENDING_TXS {
                mempool.pending_txs.clear(); 
            }
    }
    
    // Add one more to trigger clear
    mempool.add_transaction("trigger_clear".to_string());
    
    // seen_txs should be small now
    assert!(mempool.seen_txs.len() < MAX_SEEN_TXS);
    assert_eq!(mempool.seen_txs.len(), 1);
}
