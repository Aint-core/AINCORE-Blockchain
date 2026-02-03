# AINCORE Blockchain - Complete Technical Documentation

> **A comprehensive guide for developers to understand, build, and contribute to AINCORE**

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Getting Started](#getting-started)
4. [Core Components](#core-components)
5. [Consensus Mechanism](#consensus-mechanism)
6. [Move VM & Smart Contracts](#move-vm--smart-contracts)
7. [Cryptography](#cryptography)
8. [P2P Networking](#p2p-networking)
9. [API Reference](#api-reference)
10. [Contributing](#contributing)

---

## Overview

AINCORE adalah blockchain Layer 1 yang dibangun dengan Rust, menggunakan DAG-based consensus (Narwhal-style) dengan Move VM untuk smart contracts. Blockchain ini dirancang untuk:

- **High Throughput**: Parallel transaction execution
- **BFT Consensus**: Byzantine Fault Tolerant dengan Bullshark ordering
- **Transparency**: Semua transaksi publik dan verifiable
- **Interoperability**: Bridge ke EVM dan Bitcoin

### Key Features

| Feature | Implementation |
|---------|----------------|
| Consensus | DAG + Bullshark (Narwhal-lite) |
| Smart Contracts | Move VM |
| Signatures | Ed25519, BLS, ECDSA |
| P2P | libp2p (gossipsub + Kademlia) |
| Storage | RocksDB |
| DA Layer | Sovereign (erasure coding) |

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           AINCORE Node                               │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │    API      │  │   P2P       │  │  Mempool    │  │  ChainSync  │ │
│  │  (JSON-RPC) │  │  (libp2p)   │  │  (5000 tx)  │  │  (blocks)   │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │
│         │                │                │                │        │
│         └────────────────┴────────┬───────┴────────────────┘        │
│                                   │                                  │
│                    ┌──────────────▼──────────────┐                  │
│                    │       DAG Consensus         │                  │
│                    │  (Narwhal + Bullshark)      │                  │
│                    └──────────────┬──────────────┘                  │
│                                   │                                  │
│         ┌─────────────────────────┼─────────────────────────┐       │
│         │                         │                         │       │
│  ┌──────▼──────┐   ┌──────────────▼──────────────┐  ┌──────▼──────┐│
│  │  Executor   │   │         Move VM             │  │ DA Sequencer││
│  │ (parallel)  │◄──┤  (stdlib: 22 contracts)     │  │ (erasure)   ││
│  └──────┬──────┘   └─────────────────────────────┘  └─────────────┘│
│         │                                                           │
│  ┌──────▼────────────────────────────────────────────────────────┐ │
│  │                      StateDB (RocksDB)                        │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Structure

```
AINCORE-Blockchain/
├── common/                 # Shared libraries
│   ├── crypto/            # Cryptography (zkp, bls, ecdsa)
│   ├── network/           # P2P messaging
│   ├── storage/           # RocksDB wrapper
│   ├── config/            # Node configuration
│   └── keystore/          # Key management
│
├── core/                   # Core node components
│   ├── node/              # Main entry point
│   ├── executor/          # Transaction execution
│   ├── vm_move/           # Move VM integration
│   ├── mempool/           # Transaction pool
│   ├── cli/               # CLI tools
│   ├── genesis-tool/      # Genesis generator
│   └── move_compiler_tool/ # Move compiler
│
├── consensus/              # Consensus layer
│   ├── consensus/         # DAG + Bullshark
│   ├── blockchain/        # Block structures
│   ├── account/           # Account model
│   └── aa/                # Account Abstraction
│
├── da/                     # Data Availability
├── sync/                   # Chain synchronization
├── governance/             # On-chain governance
├── depin/                  # Bridges (EVM, BTC)
└── indexer/                # Block indexer
```

---

## Getting Started

### Prerequisites

```bash
# Rust (1.70+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Required system dependencies (macOS)
brew install rocksdb openssl

# Required system dependencies (Ubuntu)
sudo apt install librocksdb-dev libssl-dev build-essential
```

### Build

```bash
# Clone repository
git clone https://github.com/aincore/AINCORE-Blockchain.git
cd AINCORE-Blockchain

# Build all crates
cargo build --workspace --release

# Run tests
cargo test --workspace
```

### Run a Node

```bash
# 1. Generate node key (REQUIRED)
mkdir -p core/node/data
openssl rand 32 > core/node/data/node.key

# 2. Start node
cargo run --bin node -- \
    --port 9000 \
    --api-port 8001 \
    --datadir ./data

# 3. Check node status
curl http://localhost:8001/rpc -X POST \
    -H "Content-Type: application/json" \
    -d '{"method": "get_status", "params": []}'
```

### Run Multiple Nodes (Local Testnet)

```bash
# Terminal 1: Genesis node
cargo run --bin node -- --port 9000 --api-port 8001 --datadir ./data1

# Terminal 2: Second node (connect to first)
cargo run --bin node -- --port 9001 --api-port 8002 --datadir ./data2 \
    --bootnodes "/ip4/127.0.0.1/tcp/9000"

# Terminal 3: Third node
cargo run --bin node -- --port 9002 --api-port 8003 --datadir ./data3 \
    --bootnodes "/ip4/127.0.0.1/tcp/9000"
```

---

## Core Components

### 1. Node (`core/node`)

Entry point untuk AINCORE node. Menangani:
- Initialization (keypair, storage, genesis)
- P2P networking
- API server
- Consensus loop

**Key Files:**
- `src/main.rs` - Main entry point
- `src/api.rs` - JSON-RPC API
- `src/p2p.rs` - libp2p integration
- `src/genesis.rs` - Genesis block creation

### 2. Executor (`core/executor`)

Menjalankan transaksi secara parallel menggunakan dependency analysis.

```rust
// Example: Execute block with parallel transactions
let executor = Executor::new(Arc::clone(&storage));
executor.execute_block_parallel(txs, &proposer_address);
```

**Features:**
- Parallel execution dengan Rayon
- Dependency graph analysis
- Atomic batch writes
- Gas metering

### 3. Mempool (`core/mempool`)

Transaction pool dengan DoS protection:

| Parameter | Value |
|-----------|-------|
| Max Pending | 5,000 |
| Max Seen | 50,000 |
| Deduplication | SHA-256 hash |

### 4. Storage (`common/storage`)

RocksDB wrapper dengan prefix-based key organization:

| Prefix | Data |
|--------|------|
| `acc:` | Account data |
| `mod:` | Move modules |
| `res:` | Resources |
| `vtx:` | DAG vertices |
| `blk:` | Blocks |
| `tx:` | Transactions |

---

## Consensus Mechanism

### DAG-Based Consensus (Narwhal-style)

AINCORE menggunakan Directed Acyclic Graph (DAG) untuk consensus, bukan linear blockchain tradisional.

```
Round 4:  [V4a]───────[V4b]───────[V4c]
            │╲         │╲         │╲
Round 3:  [V3a]───────[V3b]───────[V3c]
            │╲         │╲         │╲
Round 2:  [V2a]───────[V2b]───────[V2c]
            │╲         │╲         │╲
Round 1:  [V1a]───────[V1b]───────[V1c]
             ╲         │         ╱
              ╲        │        ╱
               ╲       │       ╱
              [GENESIS BLOCK]
```

### Vertex Structure

```rust
pub struct Vertex {
    pub hash: String,           // SHA-256 hash
    pub round: u64,             // Consensus round
    pub author: String,         // Proposer address
    pub payload: Vec<String>,   // Transactions
    pub parents: Vec<String>,   // Parent vertex hashes
    pub timestamp: u64,         // Unix timestamp
    pub signature: String,      // Ed25519 signature
}
```

### Bullshark Ordering

Setelah vertex dibuat, Bullshark ordering menentukan urutan final:

1. **Leader Election**: Round ganjil punya leader
2. **Anchor Detection**: Jika leader punya 2f+1 votes → anchor
3. **Causal Ordering**: Semua vertex yang terhubung ke anchor di-commit

```rust
// BFT Quorum calculation
let n = validators.len();      // Total validators
let f = (n - 1) / 3;           // Byzantine tolerance
let quorum = 2 * f + 1;        // Required votes
```

---

## Move VM & Smart Contracts

### Move Language

AINCORE menggunakan Move sebagai smart contract language (sama seperti Aptos/Sui).

**Keuntungan Move:**
- Resource safety (no duplication, no loss)
- Formal verification support
- Linear type system
- Native generics

### Stdlib Modules (22 Contracts)

| Module | Purpose |
|--------|---------|
| `coin` | Native token operations |
| `staking` | Validator staking |
| `delegation` | Stake delegation |
| `governance` | On-chain voting |
| `treasury` | Protocol treasury |
| `dex` | AMM DEX |
| `token_factory` | Create new tokens |
| `universal_mining` | Mining rewards |
| `wbtc` | Wrapped Bitcoin |

### Writing Move Contracts

```move
module 0x1::my_token {
    use std::signer;
    use 0x1::coin;
    
    struct MyToken has key, store {}
    
    public entry fun mint(account: &signer, amount: u64) {
        let addr = signer::address_of(account);
        coin::mint<MyToken>(addr, amount);
    }
    
    public entry fun transfer(
        from: &signer, 
        to: address, 
        amount: u64
    ) {
        coin::transfer<MyToken>(from, to, amount);
    }
}
```

### Deploying Contracts

```bash
# Compile Move module
cargo run --bin move-compiler -- \
    --source my_module.move \
    --output my_module.mv

# Deploy via CLI
cargo run --bin cli -- deploy \
    --bytecode my_module.mv \
    --address 0x1
```

---

## Cryptography

### Crypto Module Structure

```
common/crypto/src/
├── lib.rs              # Main exports
├── ecdsa.rs            # ECDSA signatures
├── multi_sig.rs        # Multi-signature
├── transport.rs        # Encrypted transport
├── bls/                # BLS signatures
├── threshold/          # Threshold signatures
├── poseidon/           # ZK-friendly hash
├── zkp/                # STARK/SNARK provers
├── accumulator/        # Merkle accumulator
├── mpc/                # Multi-party computation
├── vdf/                # Verifiable delay function
└── bridges/            # Cross-chain verification
```

### Signature Types

```rust
// Ed25519 (default)
use crypto::{Signer, SigningKey, VerifyingKey};

let keypair = SigningKey::generate(&mut OsRng);
let signature = keypair.sign(message);
let is_valid = keypair.verifying_key().verify(message, &signature);

// BLS (aggregate signatures)
use crypto::bls::BLSEngine;

let engine = BLSEngine::new();
let sig1 = engine.sign(&sk1, message);
let sig2 = engine.sign(&sk2, message);
let agg_sig = engine.aggregate(&[sig1, sig2]);

// ECDSA (EVM compatibility)
use crypto::ecdsa::ECDSACrypto;

let crypto = ECDSACrypto::new();
let sig = crypto.sign(&private_key, message)?;
let recovered_addr = crypto.recover_address(&sig, message)?;
```

### STARK Proofs

```rust
use crypto::zkp::{STARKProver, STARKError};

// Generate STARK proof for merkle inclusion
let prover = STARKProver::new();
let proof = prover.prove_merkle_inclusion(leaf, path, root)?;
let is_valid = prover.verify(&proof)?;
```

---

## P2P Networking

### libp2p Stack

AINCORE menggunakan libp2p dengan protokol:

| Protocol | Purpose |
|----------|---------|
| Gossipsub | Message broadcasting |
| Kademlia | Peer discovery (DHT) |
| mDNS | Local peer discovery |
| AutoNAT | NAT traversal |
| dcutr | Hole punching |

### Topics

```rust
// Gossipsub topics
const TOPIC_TRANSACTIONS: &str = "aincore/tx/1.0.0";
const TOPIC_VERTICES: &str = "aincore/vtx/1.0.0";
const TOPIC_DA_BATCHES: &str = "aincore/da/1.0.0";
```

### Connecting Nodes

```bash
# Using multiaddr format
--bootnodes "/ip4/192.168.1.100/tcp/9000"
--bootnodes "/dns4/node1.aincore.io/tcp/9000"

# Multiple bootnodes
--bootnodes "/ip4/1.2.3.4/tcp/9000,/ip4/5.6.7.8/tcp/9000"
```

---

## API Reference

### JSON-RPC Endpoints

Base URL: `http://localhost:8001/rpc`

#### Get Status
```json
{
    "method": "get_status",
    "params": []
}
```

Response:
```json
{
    "node_id": "8f7d00f56518177823e32849fa9e5f83",
    "height": 1234,
    "round": 567,
    "peers": 5
}
```

#### Get Balance
```json
{
    "method": "get_balance",
    "params": ["8f7d00f56518177823e32849fa9e5f83"]
}
```

#### Submit Transaction
```json
{
    "method": "submit_transaction",
    "params": [{
        "sender": "8f7d00...",
        "action": "transfer",
        "payload": {
            "to": "9a8b7c...",
            "amount": 1000000000000000000
        },
        "gas_limit": 100000,
        "gas_price": 1000,
        "nonce": 1,
        "chain_id": "AINCORE-MAINNET-1",
        "signature": "..."
    }]
}
```

#### Get Block
```json
{
    "method": "get_block",
    "params": [1234]
}
```

#### Get Transaction
```json
{
    "method": "get_transaction",
    "params": ["0x123abc..."]
}
```

---

## Contributing

### Development Setup

```bash
# Clone with submodules
git clone --recursive https://github.com/aincore/AINCORE-Blockchain.git

# Install pre-commit hooks
cargo install cargo-husky

# Run formatter
cargo fmt --all

# Run linter
cargo clippy --workspace
```

### Code Style

- Use Rust 2021 edition
- Follow Rust API Guidelines
- Document all public functions
- Add tests for new features

### Pull Request Process

1. Fork repository
2. Create feature branch
3. Write tests
4. Run `cargo fmt` and `cargo clippy`
5. Submit PR with description

---

## License

AINCORE Blockchain is licensed under MIT License.

---

## Contact

- Website: https://aincore.io
- GitHub: https://github.com/aincore
- Discord: https://discord.gg/aincore
