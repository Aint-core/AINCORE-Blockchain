# AINCORE Blockchain - New Security Findings & Implementation Guide
**May 13, 2026** | **Post-Fix Audit** | **4 New Issues Identified**

---

## Overview

During the comprehensive re-audit of the updated codebase, I discovered **4 additional security findings** beyond the original 3 critical issues that were already fixed.

### Quick Summary

| ID | Issue | Severity | Status | Timeline |
|---|---|---|---|---|
| **N-1** | Paymaster Signature Not Validated | 🔴 HIGH | ⏳ TODO | 1-2 days |
| **N-2** | Input Object DoS Risk | 🔴 HIGH | ⏳ TODO | 1-2 days |
| **N-3** | Pubkey Derivation Check Bug | 🟡 MEDIUM | ⏳ TODO | < 1 day |
| **N-4** | Unbonding Queue Unbounded Growth | 🟠 LOW | ⏳ TODO | < 1 day |

**Total Impact**: These fixes are NOT blocking for testnet, but **MUST be fixed before mainnet**.

---

## N-1: Paymaster Signature Not Validated (HIGH)

### The Problem

**Location**: `executor/src/lib.rs` lines 19-20

The `Transaction` struct accepts optional `paymaster` and `paymaster_signature` fields for gas abstraction:

```rust
#[serde(default)]
pub paymaster: Option<String>,
#[serde(default)]
pub paymaster_signature: Option<String>,
```

**BUT** — these are never validated in `execute_transaction()`. An attacker can:

1. Create a transaction with `gas_price = 1000 AIN/unit`
2. Set `paymaster = "0xrich_person"` 
3. Skip validating the paymaster actually authorized this
4. Rich person's account gets charged for a transaction they didn't approve ❌

### Attack Scenario

```json
{
  "chain_id": "AINCORE-MAINNET-1",
  "sender": "0xattacker",
  "paymaster": "0xrich_whale",
  "paymaster_signature": "ANYTHING_HERE_NOT_CHECKED",
  "payload": "transfer:0xrich_whale:1000000",
  "gas_limit": 1000000,
  "gas_price": 1000,
  "public_key": "...",
  "signature": "..."
}
```

**Result**: Attacker steals 1 Billion AIN in gas fees from the whale without consent! 💥

### The Fix

Add comprehensive paymaster validation in `execute_transaction()`:

```rust
// In executor/src/lib.rs - execute_transaction function (after sender signature check)

// === STEP 2.6: PAYMASTER VALIDATION ===
if let Some(pm_addr) = &tx.paymaster {
    if let Some(pm_sig_hex) = &tx.paymaster_signature {
        // Construct the message that the paymaster must sign
        let pm_message = format!(
            "PAYMASTER_AUTH:{}:{}:{}:{}:{}",
            tx.chain_id,
            tx.sender,           // Must authorize THIS sender's tx
            tx.payload,          // Must authorize THIS exact payload
            tx.gas_limit,        // Must authorize THIS gas budget
            tx.sequence_number   // Must authorize THIS nonce (prevent replay)
        );
        
        // Parse paymaster's public key and signature
        let pm_pk_bytes = match hex::decode(&pm_addr) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            },
            _ => {
                println!("❌ Invalid Paymaster Address Format");
                return None;
            }
        };
        
        let pm_sig_bytes = match hex::decode(&pm_sig_hex) {
            Ok(bytes) if bytes.len() == 64 => {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&bytes);
                arr
            },
            _ => {
                println!("❌ Invalid Paymaster Signature Format");
                return None;
            }
        };
        
        // Verify paymaster's signature
        let pm_verifying_key = match VerifyingKey::from_bytes(&pm_pk_bytes) {
            Ok(vk) => vk,
            Err(_) => {
                println!("❌ Invalid Paymaster Public Key");
                return None;
            }
        };
        
        let pm_signature = Signature::from_bytes(&pm_sig_bytes);
        if pm_verifying_key.verify(pm_message.as_bytes(), &pm_signature).is_err() {
            println!("❌ Invalid Paymaster Signature - Paymaster DID NOT authorize this transaction");
            return None;
        }
        
        println!("✅ Paymaster {} authorized gas payment", pm_addr);
        
        // Additional safety: Verify paymaster account has sufficient balance
        let paymaster_obj = match self.db.get_object(&pm_addr) {
            Some(obj) => obj,
            None => {
                println!("❌ Paymaster account not found");
                return None;
            }
        };
        
        let pm_data: aa::AccountData = match serde_json::from_slice(&paymaster_obj.data) {
            Ok(d) => d,
            Err(_) => {
                println!("❌ Failed to parse paymaster account data");
                return None;
            }
        };
        
        let gas_cost = (tx.gas_limit as u128) * tx.gas_price;
        if pm_data.balance < gas_cost {
            println!("❌ Paymaster insufficient balance: {} < {}", pm_data.balance, gas_cost);
            return None;
        }
        
        println!("✅ Paymaster has sufficient balance: {}", pm_data.balance);
        
    } else {
        println!("❌ Paymaster specified but signature not provided - REJECTED");
        return None;
    }
}
```

### Implementation Details

1. **Message Construction**: Uses `PAYMASTER_AUTH:...` prefix to distinguish from regular signatures
2. **Replay Protection**: Includes `sequence_number` so paymaster can't replay old auth
3. **Balance Check**: Verifies paymaster has funds BEFORE committing
4. **Clear Logging**: Each step logs success/failure for debugging

### Testing

```rust
#[test]
fn test_paymaster_signature_validation() {
    // Create two accounts: attacker and rich_person
    let attacker = "0xattacker";
    let rich = "0xrich";
    
    // Rich person signs: "PAYMASTER_AUTH:...:..."
    let pm_message = format!("PAYMASTER_AUTH:{}:{}:{}:{}:{}", 
        "AINCORE-MAINNET-1", attacker, "transfer:...", 1000000, 0);
    let pm_sig = sign_message(&rich_private_key, &pm_message);
    
    // Create attacker's tx with paymaster auth
    let tx = Transaction {
        paymaster: Some(rich.to_string()),
        paymaster_signature: Some(pm_sig),
        ..
    };
    
    // Should PASS with valid signature
    assert!(executor.execute_transaction(&serde_json::to_string(&tx).unwrap()).is_some());
    
    // Try with different payload - should FAIL
    let tx_tampered = Transaction {
        paymaster_signature: Some(pm_sig), // Same signature
        payload: "transfer:0xattacker:999999".to_string(), // Different payload!
        ..
    };
    assert!(executor.execute_transaction(&serde_json::to_string(&tx_tampered).unwrap()).is_none());
}
```

### Deployment Checklist

- [ ] Implement paymaster validation logic
- [ ] Add unit tests (3-5 test cases)
- [ ] Update JSON-RPC API docs (explain paymaster flow)
- [ ] Create example: CLI paymaster transaction
- [ ] Add integration test with actual paymaster account
- [ ] Code review before merging

---

## N-2: Input Object DoS Risk (HIGH)

### The Problem

**Location**: `executor/src/lib.rs` lines 47-51

Currently, there's a per-transaction limit:

```rust
if tx.input_objects.len() > 128 {
    println!("⛔ Transaction REJECTED: Too many input objects (>128)");
    continue;
}
```

**BUT** — there's no per-block or per-batch limit on total objects.

### Attack Scenario

Attacker sends 10,000 transactions in a block, each with 128 input objects:

```
Total objects to load = 10,000 * 128 = 1,280,000 objects
Memory needed = 1,280,000 * 1KB = 1.28 GB per block
```

If block time is 2 seconds, a single attacker can:
- Force validator to load 640GB of data per second
- Crash nodes from memory exhaustion
- Network DoS without even submitting invalid transactions ❌

### The Fix

Implement cumulative object limits per block:

```rust
// In executor/src/lib.rs - execute_block_parallel function

const MAX_OBJECTS_PER_TRANSACTION: usize = 128;
const MAX_OBJECTS_PER_BLOCK: usize = 10000;

pub fn execute_block_parallel(&self, txs_json: Vec<String>, proposer_hex: &str) {
    println!("🚀 Starting Parallel Execution for {} transactions...", txs_json.len());
    
    // === OBJECT COUNTING PHASE ===
    let mut total_block_objects: usize = 0;
    let mut valid_txs = Vec::new();
    
    for raw in &txs_json {
        match serde_json::from_str::<Transaction>(raw) {
            Ok(tx) => {
                // Check per-tx limit
                if tx.input_objects.len() > MAX_OBJECTS_PER_TRANSACTION {
                    println!("⛔ TX REJECTED: {} input objects exceeds max ({})", 
                        tx.input_objects.len(), MAX_OBJECTS_PER_TRANSACTION);
                    continue;
                }
                
                // Check cumulative block limit
                let new_total = total_block_objects + tx.input_objects.len();
                if new_total > MAX_OBJECTS_PER_BLOCK {
                    println!("⛔ BLOCK FULL: Adding {} objects would exceed block limit ({} -> {})", 
                        tx.input_objects.len(), total_block_objects, new_total);
                    // Drop this tx and subsequent ones (block is "full")
                    break;
                }
                
                total_block_objects = new_total;
                valid_txs.push((tx, raw.clone()));
            },
            Err(_) => {
                println!("⛔ Invalid JSON");
                continue;
            }
        }
    }
    
    println!("📊 Block contains {} txs with {} total input objects", 
        valid_txs.len(), total_block_objects);
    
    // Rest of execution with valid_txs instead of parsed_txs
    // ...
}
```

### Enhanced: Per-Batch Object Accounting

For even better protection, account for object loading gas:

```rust
// Add gas cost for object loading
const OBJECT_LOAD_GAS: u64 = 100; // 100 gas per object loaded

pub fn execute_transaction(&self, tx_json: &str) -> Option<(Vec<(String, Option<String>)>, u128)> {
    // ... existing code ...
    
    // Calculate object loading gas
    let object_load_gas = (tx.input_objects.len() as u64) * OBJECT_LOAD_GAS;
    
    // Deduct from gas_limit
    if object_load_gas > tx.gas_limit {
        println!("❌ Insufficient gas for object loading: {} > {}", 
            object_load_gas, tx.gas_limit);
        return None;
    }
    
    let remaining_gas = tx.gas_limit - object_load_gas;
    
    println!("⚙️ Object Loading Gas: {}, Remaining for Execution: {}", 
        object_load_gas, remaining_gas);
    
    // ... continue with remaining_gas for VM execution ...
}
```

### Testing

```rust
#[test]
fn test_input_object_dos_protection() {
    let executor = Executor::new(Arc::new(StateDB::new()));
    
    // Create 100 txs, each with 100 objects
    let mut txs = Vec::new();
    for i in 0..100 {
        let mut tx = create_valid_transaction();
        tx.input_objects = (0..100).map(|j| format!("obj_{}_{}", i, j)).collect();
        txs.push(serde_json::to_string(&tx).unwrap());
    }
    
    // Should accept first txs until limit is hit
    executor.execute_block_parallel(txs, "0xproposer");
    
    // Verify total objects ≤ MAX_OBJECTS_PER_BLOCK
    assert!(executor.total_block_objects_count() <= 10000);
}
```

### Deployment Checklist

- [ ] Implement per-block object counting
- [ ] Implement per-batch object limits
- [ ] Add object loading gas cost
- [ ] Stress test with large object counts
- [ ] Monitor memory usage during 10K TPS test
- [ ] Update validator operator docs

---

## N-3: Pubkey Derivation Check Bug (MEDIUM)

### The Problem

**Location**: `executor/src/lib.rs` lines 155-157

Current code:

```rust
if tx.sender != tx.public_key[0..32] { return None; }
```

**Issues**:
1. `tx.public_key` is stored as **hex string** (64 characters)
2. `tx.sender` is stored as **hex string** (32 characters)
3. Comparing `tx.public_key[0..32]` (first 32 hex chars) to `tx.sender` (32 hex chars) might work by coincidence, but it's wrong!
4. Should use **proper address derivation**: `SHA256(pubkey)[0:16]`

### Concrete Example

```
Public Key:    a1b2c3d4e5f6... (64 hex chars)
tx.public_key[0..32] = "a1b2c3d4e5f6..." (first 32 chars)

But sender should be derived as:
sender = SHA256(hex_decode("a1b2c3d4e5f6..."))
sender = SHA256([0xa1, 0xb2, 0xc3, ...])
sender = [0x12, 0x34, 0x56, ...]  (32 bytes)
sender_hex = "1234567..."  (32 hex chars, i.e. 16 bytes)
```

**Current code allows**: `tx.sender == tx.public_key[0..32]` ← WRONG!  
**Correct code should**: `tx.sender == hex(SHA256(pubkey_bytes)[0:16])`

### The Fix

```rust
// In executor/src/lib.rs - execute_transaction function

// OLD (WRONG):
// if tx.sender != tx.public_key[0..32] { return None; }

// NEW (CORRECT):
// 1. Decode public key from hex
let pubkey_bytes = match hex::decode(&tx.public_key) {
    Ok(bytes) => {
        if bytes.len() != 32 {
            println!("❌ Invalid public key length: {} bytes (expected 32)", bytes.len());
            return None;
        }
        bytes
    },
    Err(e) => {
        println!("❌ Failed to decode public key from hex: {}", e);
        return None;
    }
};

// 2. Derive address using proper algorithm
let derived_sender = match crypto::derive_address(&pubkey_bytes) {
    Ok(addr) => addr,
    Err(e) => {
        println!("❌ Failed to derive address: {}", e);
        return None;
    }
};

// 3. Compare derived address with tx.sender
if tx.sender != derived_sender {
    println!("❌ SENDER ADDRESS MISMATCH");
    println!("  Transaction claims sender: {}", tx.sender);
    println!("  Public key derives to:     {}", derived_sender);
    println!("  This transaction was NOT signed by the claimed sender!");
    return None;
}

println!("✅ Sender address verified: {}", tx.sender);
```

### Verify crypto::derive_address is correct

```rust
// In common/crypto/src/lib.rs (already implemented):
pub fn derive_address(public_key: &[u8]) -> Result<String> {
    if public_key.is_empty() {
        return Err(CryptoError::InvalidInput("Public key cannot be empty".to_string()));
    }
    
    let hash = hash(public_key);  // SHA256
    Ok(hex::encode(&hash[0..16])) // First 16 bytes = 32 hex chars ✅
}
```

**Good news**: This function already exists and is correct! Just need to use it. ✅

### Testing

```rust
#[test]
fn test_pubkey_sender_derivation() {
    // Create a keypair
    let secret = SigningKey::generate(&mut OsRng);
    let pubkey_bytes = secret.verifying_key().to_bytes();
    let pubkey_hex = hex::encode(&pubkey_bytes);
    
    // Derive address
    let expected_sender = crypto::derive_address(&pubkey_bytes).unwrap();
    
    // Create transaction
    let message = "test_message";
    let signature = secret.sign(message.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());
    
    let tx = Transaction {
        sender: expected_sender,
        public_key: pubkey_hex,
        signature: signature_hex,
        ..
    };
    
    // Execute should succeed
    assert!(executor.execute_transaction(&serde_json::to_string(&tx).unwrap()).is_some());
    
    // With wrong sender, should fail
    let tx_wrong = Transaction {
        sender: "0xwrongaddress".to_string(),
        ..tx
    };
    assert!(executor.execute_transaction(&serde_json::to_string(&tx_wrong).unwrap()).is_none());
}

#[test]
fn test_pubkey_derivation_consistency() {
    // Same pubkey must always derive to same address
    let pubkey = vec![0x42u8; 32];
    let addr1 = crypto::derive_address(&pubkey).unwrap();
    let addr2 = crypto::derive_address(&pubkey).unwrap();
    assert_eq!(addr1, addr2); // Deterministic
}
```

### Deployment Checklist

- [ ] Update execute_transaction to use crypto::derive_address
- [ ] Remove old string comparison
- [ ] Add unit tests (3-4 test cases)
- [ ] Integration test with actual keypair generation
- [ ] Verify all existing valid txs still validate
- [ ] Code review

---

## N-4: Unbonding Queue Unbounded Growth (LOW)

### The Problem

**Location**: `staking.move` lines 45-50

When a validator leaves, their stake is locked in an `UnbondingRequest` for 21 days:

```move
vector::push_back(&mut validator_set.unbonding_queue, unbonding_req);
```

**But** — if validators never call `withdraw_unbonded()` after 21 days, the queue grows forever:

```
Day 0:  10 validators leave → queue size = 10
Day 21: They can withdraw, but don't → queue still = 10
Day 42: 10 more leave → queue size = 20
Day 420: Queue size = 200
Day 4200: Queue size = 2000 (scanning becomes slow)
```

This isn't an economic attack, but it causes:
- **State bloat**: Storage grows forever
- **Performance degradation**: Scanning unbonding queue becomes O(N) slow
- **Network sync lag**: New validators must download all historical unbonding requests

### The Fix

Implement automatic cleanup after grace period:

```move
// In staking.move - add helper function

/// Clean up unbonding requests that are older than grace period
/// Called periodically by epoch::on_new_epoch
public fun cleanup_old_unbonding(account: &signer) acquires ValidatorSet {
    let addr = signer::address_of(account);
    assert!(addr == @0x1, error::permission_denied(ENOT_VALIDATOR));
    
    let validator_set = borrow_global_mut(@0x1);
    let current_time = validator_set.current_epoch * 60; // ~60s per epoch
    
    // Grace period: 21 days (unbonding) + 10 days (claim buffer) = 31 days
    const GRACE_PERIOD: u64 = 2678400; // 31 days in seconds
    
    let queue_len = vector::length(&validator_set.unbonding_queue);
    let i = 0;
    let removed_count = 0;
    
    while (i < queue_len) {
        let req = vector::borrow(&validator_set.unbonding_queue, i);
        
        // If request is older than grace period, auto-burn
        if (current_time >= req.unlock_time + GRACE_PERIOD) {
            let old_req = vector::remove(&mut validator_set.unbonding_queue, i);
            let UnbondingRequest { validator_addr, stake: amount, unlock_time: _ } = old_req;
            
            // Auto-burn unclaimed stake (deflationary penalty for not withdrawing)
            println!("🔥 AUTO-BURNING unclaimed stake: {} AIN from {}", amount, validator_addr);
            
            // Reduce total_supply accordingly
            validator_set.total_supply = 
                if (validator_set.total_supply >= amount) {
                    validator_set.total_supply - amount
                } else {
                    0
                };
            
            removed_count = removed_count + 1;
            queue_len = queue_len - 1;
            // Don't increment i (next item shifts down)
        } else {
            i = i + 1;
        }
    };
    
    if (removed_count > 0) {
        println!("🧹 Cleaned up {} expired unbonding requests", removed_count);
    }
}

/// Call this at the start of each epoch
public fun on_new_epoch(account: &signer) acquires ValidatorSet {
    // ... existing epoch logic ...
    
    // Cleanup old unbonding queue
    cleanup_old_unbonding(account);
    
    // ... rest of epoch logic ...
}
```

### Alternative: Memory-Bounded Queue with Eviction

If you want to be even more aggressive:

```move
// Limit queue size to 10,000 entries
const MAX_UNBONDING_QUEUE_SIZE: u64 = 10000;

public entry fun leave_validator_set(account: &signer) acquires ValidatorSet {
    // ... existing code ...
    
    let validator_set = borrow_global_mut(@0x1);
    
    // If queue is full, remove oldest entry (even if not mature)
    if (vector::length(&validator_set.unbonding_queue) >= MAX_UNBONDING_QUEUE_SIZE) {
        let old_req = vector::remove(&mut validator_set.unbonding_queue, 0);
        let UnbondingRequest { validator_addr, stake: amount, unlock_time: _ } = old_req;
        println!("⚠️ Evicting unwithdraw stake due to queue limit: {} from {}", amount, validator_addr);
    }
    
    // Add new request
    vector::push_back(&mut validator_set.unbonding_queue, unbonding_req);
}
```

### Testing

```move
#[test(account = @0x1)]
fun test_unbonding_cleanup(account: &signer) acquires ValidatorSet {
    // Initialize
    initialize(account);
    
    // 100 validators leave (creates 100 unbonding requests)
    let i = 0;
    while (i < 100) {
        leave_validator_set(&create_test_validator(i));
        i = i + 1;
    };
    
    // Verify queue has 100 entries
    let vs = borrow_global(@0x1);
    assert!(vector::length(&vs.unbonding_queue) == 100);
    
    // Advance time past grace period (simulate epoch change)
    advance_epochs(40 * 24 * 60); // ~40 days
    
    // Run cleanup
    cleanup_old_unbonding(account);
    
    // Verify queue is cleared
    let vs = borrow_global(@0x1);
    assert!(vector::length(&vs.unbonding_queue) == 0); // All cleaned up!
}
```

### Deployment Checklist

- [ ] Implement cleanup function
- [ ] Hook into epoch::on_new_epoch
- [ ] Implement tests
- [ ] Decide: Auto-burn or allow recovery period?
- [ ] Document in validator docs
- [ ] Monitor queue size on testnet

---

## Summary Table

| Issue | Severity | Fix Complexity | Est. Time | Test Cases |
|---|---|---|---|---|
| **N-1: Paymaster Validation** | 🔴 HIGH | Medium | 1-2 days | 5-8 |
| **N-2: Input Object DoS** | 🔴 HIGH | Medium | 1-2 days | 4-6 |
| **N-3: Pubkey Derivation** | 🟡 MEDIUM | Low | < 1 day | 4-5 |
| **N-4: Unbonding Bloat** | 🟠 LOW | Low | < 1 day | 3-4 |

---

## Implementation Order

### Phase 1: Critical (Must do before testnet)
1. **N-3: Pubkey Derivation** (easiest, lowest risk)
2. **N-1: Paymaster Validation** (economic security)
3. **N-2: Input Object DoS** (network stability)

### Phase 2: Important (Should do before mainnet)
4. **N-4: Unbonding Cleanup** (state hygiene)

---

## Testing Checklist Before Deployment

```
[ ] Unit tests pass (all 20+ test cases)
[ ] Integration tests pass
[ ] No regressions in existing transactions
[ ] Stress test: 10,000 TPS with mixed paymaster/non-paymaster
[ ] Memory profiling: Object loading doesn't exceed limits
[ ] Address derivation matches across all accounts
[ ] Unbonding cleanup doesn't skip valid requests
[ ] Code review approval from senior engineer
[ ] Security review approval from audit team
```

---

## Questions to Ask Your Team

1. **Paymaster**: Do you want to enable paymaster support at genesis, or gradually roll it out?
2. **Object limits**: Should object loading cost gas? (Recommended: YES)
3. **Pubkey derivation**: Are there any existing txs that rely on the old (wrong) behavior?
4. **Unbonding cleanup**: Auto-burn after grace period, or keep indefinitely?

---

**END OF NEW FINDINGS IMPLEMENTATION GUIDE**
