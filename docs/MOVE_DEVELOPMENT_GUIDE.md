# Move Smart Contract Development Guide

> **Complete guide to developing smart contracts on AINCORE using the Move language**

---

## Table of Contents

1. [Introduction to Move](#introduction-to-move)
2. [Development Environment](#development-environment)
3. [Move Language Basics](#move-language-basics)
4. [AINCORE Stdlib](#aincore-stdlib)
5. [Tutorials](#tutorials)
6. [Best Practices](#best-practices)
7. [Testing](#testing)
8. [Deployment](#deployment)

---

## Introduction to Move

Move adalah bahasa pemrograman smart contract yang dikembangkan oleh Meta (Facebook) untuk blockchain Libra/Diem. AINCORE mengadopsi Move karena:

### Keuntungan Move

| Feature | Benefit |
|---------|---------|
| **Resource Safety** | Aset tidak bisa diduplikasi atau hilang secara tidak sengaja |
| **Linear Types** | Setiap resource harus digunakan tepat sekali |
| **Formal Verification** | Dapat dibuktikan secara matematis |
| **Generics** | Mendukung tipe parametrik |
| **Modules** | Organisasi kode yang jelas |

### Move vs Solidity

| Aspect | Move | Solidity |
|--------|------|----------|
| Reentrancy | Impossible by design | Manually guarded |
| Integer Overflow | Checked by default | Requires SafeMath |
| Assets | First-class resources | Mappings |
| Upgrades | Module publishing | Proxy patterns |

---

## Development Environment

### Install Move Tools

```bash
# Install Move Compiler (included in AINCORE)
cargo build --bin move_compiler_tool --release

# Add to PATH
export PATH="$PATH:$(pwd)/target/release"

# Verify installation
move_compiler_tool --version
```

### Project Structure

```
my-move-project/
├── sources/          # Move source files
│   └── my_module.move
├── scripts/          # Move scripts
├── tests/            # Test files
└── Move.toml         # Project manifest
```

### Move.toml

```toml
[package]
name = "MyProject"
version = "1.0.0"

[addresses]
my_addr = "0x1"
std = "0x1"

[dependencies]
AincoreStdlib = { local = "../aincore/stdlib" }
```

---

## Move Language Basics

### 1. Modules

```move
module my_addr::my_module {
    // Module contents go here
}
```

### 2. Basic Types

```move
// Integers (unsigned only)
let a: u8 = 255;
let b: u64 = 1000000;
let c: u128 = 340282366920938463463374607431768211455;

// Boolean
let flag: bool = true;

// Address
let addr: address = @0x1;

// Vector
let v: vector<u8> = vector[1, 2, 3];
```

### 3. Structs

```move
module 0x1::token {
    // Struct with abilities
    struct Token has key, store, copy, drop {
        value: u64,
        owner: address,
    }
    
    // Resource struct (cannot be copied or dropped)
    struct Vault has key {
        tokens: vector<Token>,
    }
}
```

### Abilities

| Ability | Meaning |
|---------|---------|
| `copy` | Can be copied |
| `drop` | Can be discarded |
| `store` | Can be stored in global storage |
| `key` | Can be used as key in global storage |

### 4. Functions

```move
module 0x1::math {
    // Public function (callable from outside)
    public fun add(a: u64, b: u64): u64 {
        a + b
    }
    
    // Entry function (can be called as transaction)
    public entry fun set_value(account: &signer, value: u64) {
        // Implementation
    }
    
    // Private function (internal only)
    fun internal_helper(): u64 {
        42
    }
    
    // View function (read-only)
    #[view]
    public fun get_value(): u64 {
        0
    }
}
```

### 5. Resources & Global Storage

```move
module 0x1::bank {
    use std::signer;
    
    struct Balance has key {
        value: u64,
    }
    
    // Store resource in account
    public entry fun create_balance(account: &signer) {
        let addr = signer::address_of(account);
        move_to(account, Balance { value: 0 });
    }
    
    // Read resource
    public fun get_balance(addr: address): u64 acquires Balance {
        borrow_global<Balance>(addr).value
    }
    
    // Modify resource
    public fun add_balance(addr: address, amount: u64) acquires Balance {
        let balance = borrow_global_mut<Balance>(addr);
        balance.value = balance.value + amount;
    }
    
    // Remove resource
    public fun destroy_balance(account: &signer): u64 acquires Balance {
        let addr = signer::address_of(account);
        let Balance { value } = move_from<Balance>(addr);
        value
    }
}
```

### 6. Error Handling

```move
module 0x1::errors {
    const E_NOT_FOUND: u64 = 1;
    const E_ALREADY_EXISTS: u64 = 2;
    const E_INSUFFICIENT_BALANCE: u64 = 3;
    
    public fun safe_transfer(from: address, to: address, amount: u64) {
        assert!(exists<Balance>(from), E_NOT_FOUND);
        
        let balance = borrow_global<Balance>(from);
        assert!(balance.value >= amount, E_INSUFFICIENT_BALANCE);
        
        // Continue with transfer...
    }
}
```

---

## AINCORE Stdlib

### Available Modules

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| `coin` | Token operations | `mint`, `burn`, `transfer`, `balance` |
| `staking` | Validator staking | `stake`, `unstake`, `claim_rewards` |
| `delegation` | Stake delegation | `delegate`, `undelegate` |
| `governance` | Voting | `propose`, `vote`, `execute` |
| `dex` | AMM DEX | `create_pool`, `swap`, `add_liquidity` |
| `token_factory` | Create tokens | `create_token`, `mint_token` |

### Using Stdlib

```move
module my_addr::my_token {
    use 0x1::coin;
    use 0x1::token_factory;
    use std::signer;
    
    struct MyToken has drop {}
    
    public entry fun initialize(admin: &signer) {
        token_factory::create_token<MyToken>(
            admin,
            b"My Token",     // name
            b"MTK",          // symbol
            8,               // decimals
            1000000000,      // initial_supply
        );
    }
    
    public entry fun transfer(
        from: &signer,
        to: address,
        amount: u64,
    ) {
        coin::transfer<MyToken>(from, to, amount);
    }
}
```

---

## Tutorials

### Tutorial 1: Simple Counter

```move
module 0x1::counter {
    use std::signer;
    
    struct Counter has key {
        value: u64,
    }
    
    // Initialize counter for an account
    public entry fun initialize(account: &signer) {
        move_to(account, Counter { value: 0 });
    }
    
    // Increment counter
    public entry fun increment(account: &signer) acquires Counter {
        let addr = signer::address_of(account);
        let counter = borrow_global_mut<Counter>(addr);
        counter.value = counter.value + 1;
    }
    
    // Get counter value
    #[view]
    public fun get_count(addr: address): u64 acquires Counter {
        borrow_global<Counter>(addr).value
    }
}
```

### Tutorial 2: Simple Token

```move
module 0x1::simple_token {
    use std::signer;
    
    struct Token has key {
        balance: u64,
    }
    
    const E_ALREADY_HAS_TOKEN: u64 = 1;
    const E_INSUFFICIENT_BALANCE: u64 = 2;
    
    // Create wallet for account
    public entry fun create_wallet(account: &signer) {
        let addr = signer::address_of(account);
        assert!(!exists<Token>(addr), E_ALREADY_HAS_TOKEN);
        move_to(account, Token { balance: 0 });
    }
    
    // Mint tokens (admin only in real implementation)
    public entry fun mint(account: &signer, amount: u64) acquires Token {
        let addr = signer::address_of(account);
        let token = borrow_global_mut<Token>(addr);
        token.balance = token.balance + amount;
    }
    
    // Transfer tokens
    public entry fun transfer(
        from: &signer,
        to: address,
        amount: u64,
    ) acquires Token {
        let from_addr = signer::address_of(from);
        
        // Deduct from sender
        let from_token = borrow_global_mut<Token>(from_addr);
        assert!(from_token.balance >= amount, E_INSUFFICIENT_BALANCE);
        from_token.balance = from_token.balance - amount;
        
        // Add to receiver
        let to_token = borrow_global_mut<Token>(to);
        to_token.balance = to_token.balance + amount;
    }
    
    #[view]
    public fun balance_of(addr: address): u64 acquires Token {
        borrow_global<Token>(addr).balance
    }
}
```

### Tutorial 3: NFT Collection

```move
module 0x1::nft {
    use std::signer;
    use std::vector;
    use std::string::String;
    
    struct NFT has key, store {
        id: u64,
        name: String,
        uri: String,
    }
    
    struct Collection has key {
        nfts: vector<NFT>,
        next_id: u64,
    }
    
    public entry fun create_collection(account: &signer) {
        move_to(account, Collection {
            nfts: vector::empty(),
            next_id: 0,
        });
    }
    
    public entry fun mint_nft(
        account: &signer,
        name: String,
        uri: String,
    ) acquires Collection {
        let addr = signer::address_of(account);
        let collection = borrow_global_mut<Collection>(addr);
        
        let nft = NFT {
            id: collection.next_id,
            name,
            uri,
        };
        
        vector::push_back(&mut collection.nfts, nft);
        collection.next_id = collection.next_id + 1;
    }
}
```

---

## Best Practices

### 1. Security

```move
// ✅ Good: Check before modify
public fun safe_withdraw(account: &signer, amount: u64) acquires Balance {
    let addr = signer::address_of(account);
    let balance = borrow_global_mut<Balance>(addr);
    assert!(balance.value >= amount, E_INSUFFICIENT);
    balance.value = balance.value - amount;
}

// ❌ Bad: No check
public fun unsafe_withdraw(account: &signer, amount: u64) acquires Balance {
    let addr = signer::address_of(account);
    let balance = borrow_global_mut<Balance>(addr);
    balance.value = balance.value - amount; // May underflow!
}
```

### 2. Gas Optimization

```move
// ✅ Good: Early return
public fun process(addr: address) acquires Data {
    if (!exists<Data>(addr)) return;
    
    let data = borrow_global_mut<Data>(addr);
    // Process...
}

// ❌ Bad: Unnecessary computation
public fun process_bad(addr: address) acquires Data {
    let expensive_result = do_expensive_computation();
    
    if (!exists<Data>(addr)) return; // Wasted gas!
    
    // Use expensive_result...
}
```

### 3. Access Control

```move
module 0x1::admin {
    const ADMIN: address = @0x1;
    const E_NOT_ADMIN: u64 = 1;
    
    public fun assert_admin(account: &signer) {
        assert!(
            signer::address_of(account) == ADMIN,
            E_NOT_ADMIN,
        );
    }
    
    public entry fun admin_only_function(admin: &signer) {
        assert_admin(admin);
        // Admin logic...
    }
}
```

---

## Testing

### Unit Tests

```move
#[test_only]
module 0x1::counter_tests {
    use 0x1::counter;
    use std::signer;
    
    #[test(account = @0x1)]
    fun test_increment(account: signer) {
        counter::initialize(&account);
        
        counter::increment(&account);
        counter::increment(&account);
        
        let count = counter::get_count(signer::address_of(&account));
        assert!(count == 2, 0);
    }
    
    #[test(account = @0x1)]
    #[expected_failure(abort_code = 1)]
    fun test_double_init_fails(account: signer) {
        counter::initialize(&account);
        counter::initialize(&account); // Should fail
    }
}
```

### Running Tests

```bash
# Run all tests
cargo test -p vm_move

# Run specific test
cargo test -p vm_move test_increment
```

---

## Deployment

### 1. Compile Module

```bash
# Compile Move source to bytecode
cargo run --bin move_compiler_tool -- \
    --source sources/my_module.move \
    --output build/my_module.mv
```

### 2. Deploy via CLI

```bash
# Deploy module
cargo run --bin cli -- module publish \
    --bytecode build/my_module.mv \
    --sender 0x1 \
    --key-file wallet.key
```

### 3. Call Entry Function

```bash
# Call function
cargo run --bin cli -- call \
    --module 0x1::my_module \
    --function initialize \
    --sender 0x1 \
    --key-file wallet.key
```

### 4. Via JSON-RPC

```bash
# Deploy module via RPC
curl -X POST http://localhost:8001/rpc \
    -H "Content-Type: application/json" \
    -d '{
        "method": "submit_transaction",
        "params": [{
            "sender": "0x1...",
            "action": "publish_module",
            "payload": {
                "bytecode": "<hex-encoded-bytecode>"
            },
            "signature": "..."
        }]
    }'
```

---

## Resources

- [Move Language Book](https://move-language.github.io/move/)
- [AINCORE Stdlib Source](../core/vm_move/stdlib/sources/)
- [Sample Contracts](../examples/move/)

---

## Support

Jika ada pertanyaan tentang Move development:
- Discord: #move-dev channel
- GitHub Issues: https://github.com/aincore/issues
