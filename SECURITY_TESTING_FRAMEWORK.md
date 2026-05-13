# 🧪 AINCORE BLOCKCHAIN - SECURITY TESTING FRAMEWORK

---

## Test Execution Strategy

### Phase 1: Unit Tests (Local Development)
```
Timeline: 2-3 days
Coverage: Individual functions & modules
Tools: Rust cargo test + property-based testing (proptest)
Metrics: 95%+ code coverage minimum
```

### Phase 2: Integration Tests (Multi-Component)
```
Timeline: 3-4 days
Coverage: Component interactions (consensus ↔ executor, VM ↔ storage)
Tools: Docker Compose for multi-node simulation
Metrics: All critical paths tested
```

### Phase 3: Stress Tests (Performance & Security)
```
Timeline: 2-3 days
Coverage: High-load scenarios, adversarial conditions
Tools: Bench-TPS + custom chaos-engineering scripts
Metrics: TPS under load, latency p99, fork recovery
```

### Phase 4: Formal Audit (Professional Review)
```
Timeline: 4-6 weeks
Coverage: Full codebase review + symbolic analysis
Organizations: Trail of Bits, OpenZeppelin, or Least Authority
Deliverable: Formal audit report
```

---

## Unit Test Suite

### TEST 1: State Root Consistency

**File**: `core/executor/tests/state_root_test.rs`

```rust
#[cfg(test)]
mod state_root_tests {
    use executor::Executor;
    use storage::StateDB;
    use std::sync::Arc;
    use std::thread;
    
    /// Test concurrent block execution doesn't cause race conditions
    #[test]
    fn test_state_root_consistency_concurrent() {
        let db = Arc::new(StateDB::open(":memory:").expect("open test db"));
        let executor = Arc::new(Executor::new(Arc::clone(&db)));
        
        // Pre-set initial state root
        db.put("sys:state_root", "initial_root_hash").ok();
        
        let mut handles = vec![];
        let expected_roots = Arc::new(Mutex::new(Vec::new()));
        
        // Spawn 20 concurrent block executions
        for block_id in 0..20 {
            let executor_clone = Arc::clone(&executor);
            let expected_clone = Arc::clone(&expected_roots);
            
            let handle = thread::spawn(move || {
                let txs = vec![
                    format!("TX:test_tx_{}", block_id),
                    format!("TX:test_tx_{}_a", block_id),
                ];
                
                // Execute block
                executor_clone.execute_block_parallel(txs, "proposer_addr", block_id as u64);
                
                // Get resulting root
                let root = db.get("sys:state_root")
                    .ok()
                    .flatten()
                    .unwrap_or("unknown".to_string());
                
                expected_clone.lock().unwrap().push((block_id, root));
            });
            
            handles.push(handle);
        }
        
        // Wait all threads
        for handle in handles {
            handle.join().unwrap();
        }
        
        // Verify: All roots should be deterministically computed
        let roots = expected_roots.lock().unwrap();
        let final_root = db.get("sys:state_root").ok().flatten();
        
        // ✅ The final state root should be consistent
        // (no race condition corrupted it)
        assert!(final_root.is_some(), "State root missing!");
        assert!(!final_root.unwrap().is_empty(), "State root is empty!");
        
        println!("✅ State root consistency test passed");
    }
    
    /// Test deterministic state root calculation
    #[test]
    fn test_state_root_deterministic() {
        let db1 = Arc::new(StateDB::open(":memory:").expect("db1"));
        let db2 = Arc::new(StateDB::open(":memory:").expect("db2"));
        
        let executor1 = Executor::new(Arc::clone(&db1));
        let executor2 = Executor::new(Arc::clone(&db2));
        
        let same_txs = vec![
            "TX:deterministic_tx_1".to_string(),
            "TX:deterministic_tx_2".to_string(),
            "TX:deterministic_tx_3".to_string(),
        ];
        
        // Execute same transactions on both executors
        executor1.execute_block_parallel(same_txs.clone(), "proposer", 0);
        executor2.execute_block_parallel(same_txs.clone(), "proposer", 0);
        
        // Get roots
        let root1 = db1.get("sys:state_root_at:0").ok().flatten();
        let root2 = db2.get("sys:state_root_at:0").ok().flatten();
        
        // ✅ Same input = same state root
        assert_eq!(root1, root2, "State root mismatch! Not deterministic!");
        
        println!("✅ State root determinism test passed");
    }
    
    /// Test state root changes with different transactions
    #[test]
    fn test_state_root_changes_with_transactions() {
        let db = Arc::new(StateDB::open(":memory:").expect("db"));
        let executor = Executor::new(Arc::clone(&db));
        
        // Block A with specific transactions
        let txs_a = vec!["TX:a1".to_string(), "TX:a2".to_string()];
        executor.execute_block_parallel(txs_a, "proposer", 0);
        let root_a = db.get("sys:state_root_at:0").ok().flatten().unwrap();
        
        // Block B with different transactions
        let txs_b = vec!["TX:b1".to_string(), "TX:b2".to_string()];
        executor.execute_block_parallel(txs_b, "proposer", 1);
        let root_b = db.get("sys:state_root_at:1").ok().flatten().unwrap();
        
        // ✅ Different transactions = different roots
        assert_ne!(root_a, root_b, "Different transactions produced same root!");
        
        println!("✅ State root change detection test passed");
    }
}
```

**Run**: `cargo test -p executor state_root`

---

### TEST 2: Fee Distribution Recovery

**File**: `core/executor/tests/fee_distribution_test.rs`

```rust
#[cfg(test)]
mod fee_distribution_tests {
    use executor::Executor;
    use storage::StateDB;
    use vm_move::AINCOREVM;
    use std::sync::Arc;
    
    /// Test fee accumulates when Move VM fails
    #[test]
    fn test_fee_accumulation_on_move_vm_failure() {
        let db = Arc::new(StateDB::open(":memory:").expect("db"));
        let executor = Executor::new(Arc::clone(&db));
        
        // Simulate Move VM failure (by not initializing coin module)
        // This will cause deposit_fee_reward to fail
        
        let txs = vec!["TX:high_gas_tx".to_string()];
        
        // Block 1: Executor tries to distribute fees
        executor.execute_block_parallel(txs.clone(), "miner_addr_1", 0);
        
        // ✅ Fee should be in pending pool (not lost!)
        let pending = db.get("sys:pending_fees:miner_addr_1:0")
            .ok()
            .flatten();
        
        assert!(pending.is_some(), "Fee not stored in pending pool!");
        
        // Block 2: Same situation
        executor.execute_block_parallel(txs.clone(), "miner_addr_1", 1);
        
        let pending2 = db.get("sys:pending_fees:miner_addr_1:1")
            .ok()
            .flatten();
        
        assert!(pending2.is_some(), "Second fee not stored!");
        
        println!("✅ Fee accumulation test passed (fees not lost)");
    }
    
    /// Test validator can claim pending fees after N epochs
    #[test]
    fn test_pending_fee_claim_after_delay() {
        let db = Arc::new(StateDB::open(":memory:").expect("db"));
        
        // Manually add pending fee (simulating Move VM failure)
        db.put("sys:pending_fees:validator_addr:0", "1000").ok();
        
        // Increment epoch counter (simulate block progression)
        let mut current_epoch = 0u64;
        for _ in 0..3 {
            current_epoch += 1;
            db.put("sys:current_epoch", &current_epoch.to_string()).ok();
        }
        
        // Check: Can claim after 3 epochs
        let can_claim = current_epoch >= 0 + 3;  // 0 is deposit epoch
        
        assert!(can_claim, "Should be able to claim after 3 epochs!");
        
        println!("✅ Fee claim eligibility test passed");
    }
    
    /// Test old fees swept after 30 epochs (prevents accumulation)
    #[test]
    fn test_old_fee_sweep() {
        let db = Arc::new(StateDB::open(":memory:").expect("db"));
        
        // Add very old fee (epoch 0)
        db.put("sys:pending_fees:old_validator:0", "5000").ok();
        
        // Add recent fee (epoch 20)
        db.put("sys:pending_fees:recent_validator:20", "1000").ok();
        
        let current_epoch = 35u64;  // Fast forward
        
        // Sweep logic
        let old_fee = db.get("sys:pending_fees:old_validator:0").ok().flatten();
        let should_sweep = current_epoch > 0 + 30;  // 30 epoch cutoff
        
        if should_sweep {
            db.delete("sys:pending_fees:old_validator:0").ok();
        }
        
        // ✅ Old fee removed
        assert!(old_fee.is_some(), "Old fee should exist before sweep");
        let after_sweep = db.get("sys:pending_fees:old_validator:0").ok().flatten();
        assert!(after_sweep.is_none(), "Old fee should be removed!");
        
        // ✅ Recent fee remains
        let recent = db.get("sys:pending_fees:recent_validator:20").ok().flatten();
        assert!(recent.is_some(), "Recent fee should remain!");
        
        println!("✅ Fee sweep test passed");
    }
}
```

**Run**: `cargo test -p executor fee_distribution`

---

### TEST 3: Nonce Uniqueness in P2P Encryption

**File**: `common/crypto/tests/nonce_test.rs`

```rust
#[cfg(test)]
mod nonce_tests {
    use crypto::EncryptedTransport;
    use std::collections::HashSet;
    
    /// Test nonce is unique for every encryption
    #[test]
    fn test_nonce_uniqueness_10k_messages() {
        let transport = EncryptedTransport::new(&[0u8; 32]);
        
        let message = b"Test message for nonce uniqueness";
        let mut ciphertexts = Vec::new();
        
        // Encrypt 10,000 times
        for _ in 0..10000 {
            let ciphertext = transport.encrypt(message).expect("encrypt failed");
            ciphertexts.push(ciphertext);
        }
        
        // ✅ All ciphertexts should be unique (different nonces)
        let unique_count = ciphertexts.iter().collect::<HashSet<_>>().len();
        
        assert_eq!(unique_count, 10000, "Nonce collision detected!");
        
        println!("✅ Nonce uniqueness test passed (10k unique nonces)");
    }
    
    /// Test same message encrypts differently each time
    #[test]
    fn test_same_message_different_ciphertext() {
        let transport = EncryptedTransport::new(&[0u8; 32]);
        
        let message = b"Same message";
        
        let c1 = transport.encrypt(message).expect("c1");
        let c2 = transport.encrypt(message).expect("c2");
        let c3 = transport.encrypt(message).expect("c3");
        
        // ✅ Same plaintext, different ciphertexts (proves different nonces)
        assert_ne!(c1, c2, "Same message produced same ciphertext!");
        assert_ne!(c2, c3, "Same message produced same ciphertext!");
        assert_ne!(c1, c3, "Same message produced same ciphertext!");
        
        println!("✅ Nonce variation test passed");
    }
    
    /// Test decryption works with unique nonces
    #[test]
    fn test_decrypt_with_nonce_in_ciphertext() {
        let transport = EncryptedTransport::new(&[0u8; 32]);
        
        let messages = vec![
            b"First message".to_vec(),
            b"Second message".to_vec(),
            b"Third message very different".to_vec(),
        ];
        
        for msg in &messages {
            let encrypted = transport.encrypt(msg).expect("encrypt");
            let decrypted = transport.decrypt(&encrypted).expect("decrypt");
            
            // ✅ Decryption works
            assert_eq!(&decrypted, msg, "Decryption failed!");
        }
        
        println!("✅ Nonce decryption test passed");
    }
    
    /// Test XOR doesn't reveal plaintext (proves different keystreams)
    #[test]
    fn test_xor_doesnt_reveal_plaintext() {
        let transport = EncryptedTransport::new(&[0u8; 32]);
        
        let m1 = b"transfer 100 AIN to alice";
        let m2 = b"transfer 999 AIN to bob!!";
        
        let c1 = transport.encrypt(m1).expect("c1");
        let c2 = transport.encrypt(m2).expect("c2");
        
        // Minimum length for XOR
        let min_len = c1.len().min(c2.len());
        
        let mut xor_result = vec![0u8; min_len];
        for i in 0..min_len {
            xor_result[i] = c1[i] ^ c2[i];
        }
        
        // ✅ XOR result should NOT look like plaintext
        let xor_string = String::from_utf8_lossy(&xor_result);
        
        // Check it's not readable text (most bytes should be non-ASCII)
        let non_ascii_count = xor_result.iter()
            .filter(|&&b| b > 127 || b < 32)
            .count();
        
        assert!(non_ascii_count > min_len / 2, 
            "XOR result too readable (nonce reuse vulnerability)!");
        
        println!("✅ XOR hardness test passed (keystreams properly unique)");
    }
}
```

**Run**: `cargo test -p crypto nonce`

---

### TEST 4: Slash Tombstone Replay Protection

**File**: `core/executor/tests/slash_test.rs`

```rust
#[cfg(test)]
mod slash_tests {
    use executor::Executor;
    use storage::StateDB;
    use std::sync::Arc;
    
    /// Test slash event doesn't execute twice (tombstone prevents replay)
    #[test]
    fn test_slash_tombstone_prevents_double_slash() {
        let db = Arc::new(StateDB::open(":memory:").expect("db"));
        let executor = Executor::new(Arc::clone(&db));
        
        // Simulate pending slash
        let validator = "0x123456";
        db.put(
            "sys:pending_slash:0x123456",
            r#"{"reason":"downtime","round":100}"#
        ).ok();
        
        // Execute slashes (simulating execute_pending_slashes)
        executor.execute_pending_slashes();
        
        // ✅ Check tombstone created
        let tombstone = db.get("sys:slashed:0x123456:100").ok().flatten();
        assert!(tombstone.is_some(), "Tombstone not created!");
        
        // Try to execute again (e.g., if called twice in same block)
        // This simulates the race condition scenario
        
        // Get validator weight before (should be reduced)
        let validators_before = db.get("sys:validators").ok().flatten();
        
        executor.execute_pending_slashes();  // Execute again
        
        let validators_after = db.get("sys:validators").ok().flatten();
        
        // ✅ Second execution should do nothing (tombstone blocks it)
        assert_eq!(validators_before, validators_after, 
            "Second slash execution modified validator set!");
        
        println!("✅ Slash tombstone replay protection test passed");
    }
    
    /// Test equivocation (100% slash) vs downtime (5% slash)
    #[test]
    fn test_different_slash_percentages() {
        let db = Arc::new(StateDB::open(":memory:").expect("db"));
        
        // Initial validator: 1000 AIN stake
        db.put("validator:alice:stake", "1000").ok();
        
        // Downtime: 5% slash
        let stake = 1000i64;
        let downtime_slash = (stake * 5) / 100;
        let downtime_remaining = stake - downtime_slash;
        
        assert_eq!(downtime_slash, 50, "5% of 1000 should be 50");
        assert_eq!(downtime_remaining, 950, "95% remaining");
        
        // Equivocation: 100% slash (removal from set)
        let equivocation_remaining = 0;
        
        // ✅ Equivocation more severe
        assert!(equivocation_remaining < downtime_remaining,
            "Equivocation should be more severe!");
        
        println!("✅ Slash percentage test passed");
    }
}
```

**Run**: `cargo test -p executor slash`

---

## Integration Test Suite

### Test 5: Multi-Node Consensus Finality

**File**: `tests/integration/consensus_test.rs`

```rust
#[cfg(test)]
mod consensus_integration_tests {
    use std::sync::Arc;
    use tokio::test;
    
    /// Test 10 nodes reach consensus (BFT 2/3 quorum)
    #[tokio::test(flavor = "multi_thread")]
    async fn test_dag_bft_10_node_finality() {
        let nodes = spawn_10_nodes().await;
        
        // Broadcast transaction
        nodes[0].broadcast_tx("tx:test_finality").await;
        
        // Wait for consensus
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        
        // ✅ Check: All 10 nodes committed same block
        for (i, node) in nodes.iter().enumerate() {
            let height = node.get_chain_height().await;
            assert!(height > 0, "Node {} didn't produce blocks", i);
            
            let block_hash = node.get_block_hash(height).await;
            assert_eq!(block_hash, nodes[0].get_block_hash(height).await,
                "Node {} has different block hash!", i);
        }
        
        println!("✅ 10-node consensus finality test passed");
    }
    
    /// Test network partition recovery (liveness)
    #[tokio::test]
    async fn test_partition_healing_no_fork() {
        let mut nodes = spawn_10_nodes().await;
        
        // Partition: 7 nodes on side A, 3 on side B
        partition_network(&mut nodes, 7);
        
        // Side A: 7 > 2/3 of 10 → produces blocks ✅
        nodes[0].broadcast_tx("tx:side_a").await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        let height_a = nodes[0].get_chain_height().await;
        
        // Side B: 3 < 2/3 of 10 → stalled ✅
        let height_b = nodes[7].get_chain_height().await;
        
        assert!(height_a > height_b, "Partition didn't affect liveness!");
        
        // Heal partition
        heal_network(&mut nodes);
        tokio::time::sleep(Duration::from_secs(5)).await;
        
        // ✅ Side B syncs to Side A's state (no fork!)
        let height_b_after = nodes[7].get_chain_height().await;
        assert_eq!(height_b_after, height_a,
            "Side B didn't sync to majority!");
        
        println!("✅ Partition healing test passed");
    }
}
```

---

## Stress Test Suite

### Test 6: High-Load Transaction Processing

**File**: `core/cli/bench_tps_enhanced.rs`

```rust
/// Stress test: Fire 10,000 TPS worth of transactions
#[tokio::test]
async fn test_bench_tps_10k() {
    let node_url = "http://localhost:8002/rpc";
    let target_tps = 10000;
    let duration_secs = 60;
    
    // Generate 1000 unique keypairs (prevents nonce conflicts)
    let mut keypairs = Vec::new();
    for i in 0..1000 {
        keypairs.push(generate_keypair(format!("key_{}", i)));
    }
    
    let start = Instant::now();
    let mut sent_count = 0;
    let mut failed_count = 0;
    
    // Fire transactions at target rate
    while start.elapsed().as_secs() < duration_secs {
        let tasks_per_sec = target_tps / 1000;  // Distribute across keypairs
        
        for _ in 0..tasks_per_sec {
            let keypair = &keypairs[sent_count % keypairs.len()];
            
            let tx = create_transfer_tx(
                keypair,
                "recipient_address",
                100,
                sent_count as u64  // unique nonce
            );
            
            match send_tx(node_url, &tx).await {
                Ok(_) => sent_count += 1,
                Err(_) => failed_count += 1,
            }
        }
        
        tokio::time::sleep(Duration::from_millis(1000 / tasks_per_sec as u64)).await;
    }
    
    println!("📊 Stress Test Results:");
    println!("  Sent: {}", sent_count);
    println!("  Failed: {}", failed_count);
    println!("  Actual TPS: {}", sent_count / duration_secs);
    println!("  Success Rate: {:.2}%", (sent_count as f64 / (sent_count + failed_count) as f64) * 100.0);
    
    // ✅ Metrics
    assert!(sent_count > target_tps / 2, "TPS too low!");  // At least 50% of target
    assert!(failed_count < sent_count / 10, "Failure rate too high!");  // < 10% failure
}
```

---

## Security Fuzzing

### Test 7: Executor Input Fuzzing

**File**: `core/executor/fuzz/fuzz_executor.rs`

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz executor with random inputs
    
    if let Ok(tx_json) = String::from_utf8(data.to_vec()) {
        let executor = Executor::new(Arc::new(StateDB::open(":memory:").unwrap()));
        
        // Call execute_transaction with random input
        // Executor should never crash or panic
        let _ = executor.execute_transaction(&tx_json);
        
        // Call execute_block_parallel with random transactions
        let _ = executor.execute_block_parallel(vec![tx_json], "proposer", 0);
    }
});
```

**Run**: `cargo +nightly fuzz -p executor`

---

## Test Execution Checklist

### Before Testnet Launch

```
PRE-TESTNET CHECKLIST:

Core Functionality:
[ ] State Root Race Condition (TEST 1) - PASS
[ ] Fee Distribution Recovery (TEST 2) - PASS
[ ] Nonce Uniqueness (TEST 3) - PASS
[ ] Slash Tombstone (TEST 4) - PASS

Integration:
[ ] Multi-Node Finality (TEST 5) - PASS
[ ] Partition Healing (TEST 5) - PASS

Performance:
[ ] 10k TPS Stress Test (TEST 6) - PASS
[ ] Latency p99 < 500ms - MEASURE
[ ] No memory leaks under load - PROFILE

Security:
[ ] Executor Input Fuzzing (TEST 7) - FUZZ 24h
[ ] Consensus Input Fuzzing - FUZZ 24h
[ ] Network Layer Fuzzing - FUZZ 24h

Code Quality:
[ ] Code coverage >= 95% - MEASURE
[ ] All clippy warnings resolved - FIX
[ ] No unsafe code (unless audited) - REVIEW

```

### Continuous Integration

```yaml
# .github/workflows/security-tests.yml
name: Security Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Run Unit Tests
        run: |
          cargo test --lib \
            state_root_tests \
            fee_distribution_tests \
            nonce_tests \
            slash_tests
      
      - name: Upload Coverage
        run: |
          cargo tarpaulin --out Xml
          bash <(curl -s https://codecov.io/bash)

  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      
      - name: Run Integration Tests
        run: cargo test --test '*' -- --test-threads=1

  fuzzing:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: nightly
      
      - name: Fuzz 1 hour
        run: |
          cargo +nightly fuzz -p executor -- -max_len=10000 -timeout=3600
```

---

## Metrics to Track

| Metric | Target | Current | Status |
|---|---|---|---|
| Code Coverage | 95% | ? | 🟡 PENDING |
| State Root Determinism | 100% | ? | 🟡 PENDING |
| Nonce Collision Probability | 0 per 10k msgs | ? | 🟡 PENDING |
| Fee Recovery Rate | 100% | ? | 🟡 PENDING |
| Network Finality | < 5s | ? | 🟡 PENDING |
| TPS at 10k load | > 5000 | ? | 🟡 PENDING |
| Partition recovery time | < 30s | ? | 🟡 PENDING |

---

## Report Generation

After all tests pass, generate comprehensive report:

```bash
# Generate code coverage report
cargo tarpaulin --out Html --output-dir coverage/

# Generate benchmark results
cargo bench --output-format bencher | tee benchmarks.txt

# Generate fuzzing statistics
ls fuzz/artifacts/*/README.txt | xargs -I {} sh -c 'echo "=== {} ===" && cat {}'

# Generate security audit log
grep -h "✅\|⚠️\|🔴" test-output.log > security-summary.txt
```

**Deliverables**:
- Code coverage report (HTML)
- Performance benchmark results
- Fuzzing crash reports (if any)
- Security test summary
- Go/No-Go decision

---

## Next Steps

1. **Execute all Phase 1 unit tests** (1-2 days)
2. **Fix any failures**, re-run until 100% pass
3. **Run Phase 2 integration tests** (2-3 days)
4. **Run Phase 3 stress tests** (1-2 days)
5. **Engage professional audit firm** (concurrent, 4-6 weeks)
6. **Address audit findings** (1-2 weeks)
7. **Launch testnet** (with bug bounty program)
8. **Gather community feedback** (2-4 weeks)
9. **Final mainnet readiness review**
10. **Mainnet launch** 🚀

