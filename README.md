# AINCORE Blockchain

**Layer-1 Blockchain | DAG BFT Consensus | Move VM | Proof of Stake**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

---

## Overview

AINCORE is a high-performance Layer-1 blockchain built entirely in Rust, featuring DAG-based BFT consensus (inspired by Bullshark), parallel transaction execution via Move VM, and a Delegated Proof of Stake (DPoS) economic model.

### Key Features

- **Consensus:** DAG BFT (Bullshark-inspired) with VDF random beacon for unpredictable leader election
- **Execution:** Parallel Move VM with conflict-aware batch scheduling (Rayon)
- **Smart Contracts:** Move language (Aptos-compatible) for resource-safe programmability
- **Staking:** DPoS with 1,000 AIN minimum stake, 21-day unbonding, halving rewards
- **Token Factory:** Create custom tokens (ERC-20 equivalent) in seconds
- **DePIN Integration:** Bio-Oracle for real-world data mining (Universal Mining)
- **Security:** Ed25519 signatures, AES-256-GCM encrypted P2P, chain-level replay protection

---

## Tokenomics

| Parameter | Value |
|---|---|
| **Native Coin** | $AIN |
| **Max Supply** | 150,000,000 AIN (Hard Cap) |
| **Block Reward** | 36 AIN per epoch (Halving model) |
| **Halving Interval** | ~4 years (2,102,400 epochs) |
| **Min Validator Stake** | 1,000 AIN |
| **Unbonding Period** | 21 days |
| **Consensus** | Delegated Proof of Stake (DPoS) |
| **Reward Formula** | `Reward = 36 AIN >> (epoch / 2,102,400)` |

The halving schedule follows the same geometric decay as Bitcoin, ensuring deflationary pressure over time.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   AINCORE Node                   │
├──────────┬──────────┬──────────┬────────────────┤
│ P2P Net  │ Mempool  │ DAG BFT  │ Ordering Engine│
│ (AES-GCM)│ (Ed25519)│(Bullshark)│  (Commit/VDF) │
├──────────┴──────────┴──────────┴────────────────┤
│              Executor (Parallel Batches)          │
├──────────────────────────────────────────────────┤
│              Move VM (Smart Contracts)            │
├──────────────────────────────────────────────────┤
│              StateDB (RocksDB)                    │
└──────────────────────────────────────────────────┘
```

| Component | Port | Path | Description |
|---|---|---|---|
| Core Node | 9000 (P2P) | `core/node` | Main validator process |
| JSON-RPC API | 8002 (HTTP) | `core/node/src/api_local.rs` | Wallet/DApp interface |
| CLI Wallet | - | `core/cli` | Command-line wallet |
| JS/TS SDK | - | `aincore-js` | DApp development SDK |
| Indexer | 3001 | `indexer` | Transaction history API |
| Bridge | - | `depin/bridge-rust` | Cross-chain bridge |
| Monitor | Terminal | `monitor` | Live dashboard |

---

## Quick Start (Development)

### Prerequisites

- **Rust** 1.75+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **RocksDB** dependencies (macOS: `brew install rocksdb`, Ubuntu: `apt install librocksdb-dev`)

### Build

```bash
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
cargo build --release
```

### Run a Local Dev Node

```bash
cargo run --release -p node -- --port 9000 --datadir .aincore
```

The node will start producing blocks and expose the JSON-RPC API at `http://localhost:8002/rpc`.

---

## Become a Validator (Step-by-Step)

This guide walks you through becoming a validator on the AINCORE network.

### Requirements

| Requirement | Minimum |
|---|---|
| **Server** | VPS or dedicated machine, 24/7 uptime |
| **CPU** | 2+ cores |
| **RAM** | 4 GB |
| **Storage** | 50 GB SSD |
| **Network** | Stable internet, open port 9000 (TCP) |
| **Stake** | 1,000 AIN tokens |

### Step 1: Install and Build

```bash
# Clone the repository
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain

# Build release binary
cargo build --release

# Verify the build
./target/release/node --help
```

### Step 2: Generate Your Validator Identity

```bash
# Build the CLI wallet
cargo build --release --bin aincore-cli

# Generate a new keypair (saves to ~/.aincore/wallet.key)
./target/release/aincore-cli keygen
```

**IMPORTANT:** This will output your:
- **Address** (32-char hex) — Your public validator address
- **Public Key** (64-char hex) — Your identity on the network
- **Seed Phrase** (24 words) — **BACK THIS UP SECURELY. NEVER SHARE IT.**

### Step 3: Get 1,000 AIN Tokens

Before you can stake, your wallet must hold at least **1,000 AIN**.

- **Testnet:** Request tokens from the faucet or existing validators
- **Mainnet:** Acquire AIN through the DEX or from other holders

Check your balance:
```bash
./target/release/aincore-cli balance
```

### Step 4: Configure and Start Your Node

```bash
# Create data directory
mkdir -p /var/aincore/data

# Start the node with your identity
# Replace BOOTNODE_IP with the network's bootnode address
./target/release/node \
  --port 9000 \
  --datadir /var/aincore/data \
  --bootnodes BOOTNODE_IP:9000
```

Wait for your node to fully sync. You will see logs like:
```
✅ DAG Initialized: X vertices, Starting Round Y
🤝 Authenticated Peer registered: ...
```

### Step 5: Register as Validator (Stake 1,000 AIN)

Once your node is synced and running:
```bash
./target/release/aincore-cli register-validator
```

This command will:
1. Lock **1,000 AIN** from your wallet into the staking contract
2. Register your public key with the consensus engine
3. Your node will begin participating in block production

You should see in your node logs:
```
✅ Staking Successful! Validator Joined: <your_address>
🔗 Native Hook: Syncing Validator Set -> Consensus Engine
```

### Step 6: Verify Your Validator Status

```bash
./target/release/aincore-cli balance
```

Your staked amount will be locked. You will start earning block rewards every epoch.

### Step 7: (Optional) Enable Delegation

Allow other users to delegate their AIN to your validator:
```bash
# Set your commission rate (in basis points, e.g., 1000 = 10%)
./target/release/aincore-cli enable-delegation --commission 1000
```

---

## Leaving the Validator Set

If you wish to stop validating:

```bash
./target/release/aincore-cli leave-validator
```

**Important:** Your 1,000 AIN will be locked for a **21-day unbonding period** for network security. After 21 days:

```bash
./target/release/aincore-cli withdraw-unbonded
```

---

## JSON-RPC API

Default endpoint: `http://localhost:8002/rpc`

| Method | Description |
|---|---|
| `aincore_getBalance` | Get account balance |
| `aincore_sendTransaction` | Submit a signed transaction |
| `aincore_getBlock` | Get block by height |
| `aincore_getBlocks` | Get latest N blocks |
| `aincore_getTransaction` | Get transaction by hash |
| `aincore_getChainInfo` | Get chain height, peers, round |
| `aincore_getDAGStatus` | Get DAG consensus state |
| `aincore_getValidators` | Get active validator set |
| `aincore_getPeers` | Get connected peers |

Example request:
```bash
curl -X POST http://localhost:8002/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getBalance","params":["YOUR_ADDRESS"],"id":1}'
```

---

## Smart Contract Development (Move)

AINCORE uses the Move programming language. Built-in modules:

| Module | File | Description |
|---|---|---|
| `staking` | `staking.move` | Validator staking with halving rewards |
| `delegation` | `delegation.move` | DPoS delegation system |
| `token_factory` | `token_factory.move` | Create/Mint/Burn/Transfer custom tokens |
| `governance` | `governance.move` | On-chain proposal and voting |
| `treasury` | `treasury.move` | System treasury management |
| `dex` | `dex.move` | AMM DEX primitives |
| `universal_mining` | `universal_mining.move` | DePIN Bio-Oracle mining |
| `coin` | `coin.move` | Base coin operations |

Compile a Move module:
```bash
cargo run --release -p move_compiler_tool -- compile path/to/your_module.move
```

---

## Network Configuration

### Chain IDs

| Network | Chain ID | Usage |
|---|---|---|
| **Mainnet** | `AINCORE-MAINNET-1` | Production (set via `AINCORE_CHAIN_ID` env var) |
| **Testnet** | `AINCORE-TESTNET-1` | Default if env var is not set |

### Environment Variables

```bash
export AINCORE_CHAIN_ID=AINCORE-MAINNET-1  # Required for production
```

---

## Recent Updates (May 2026)

### Critical Fixes
- **Consensus State Persistence:** `committed_rounds` and `latest_proposed_round` now persist to RocksDB, preventing duplicate blocks after node restart
- **Single Reward Source:** Block inflation is exclusively handled by `staking.move` (Halving model). Executor only distributes transaction fees
- **Ghost Script Prevention:** Raw hex payload execution now properly guarded with `else if` branch and hex validation
- **P2P Stability:** Network read errors properly distinguished from decryption failures, eliminating false "Decryption Failed" spam

### Architecture Validation
- Consensus model validated against Bullshark paper (CCS 2022)
- Halving formula mathematically proven to converge below 150M AIN hard cap
- 21-day unbonding period follows Cosmos SDK security standard
- BFT threshold `ceil(2n/3)` verified against Byzantine fault tolerance requirements

---

## Documentation

Detailed documentation is available in the [`/docs`](./docs) folder:

| Guide | Description |
|---|---|
| [Technical Documentation](./docs/TECHNICAL_DOCUMENTATION.md) | Architecture and core components |
| [Move Development Guide](./docs/MOVE_DEVELOPMENT_GUIDE.md) | Smart contract tutorials |
| [Consensus Deep Dive](./docs/CONSENSUS_DEEP_DIVE.md) | DAG and Bullshark internals |
| [Node Operator Guide](./docs/NODE_OPERATOR_GUIDE.md) | Running and maintaining validators |
| [API Reference](./docs/API_REFERENCE.md) | Complete JSON-RPC API documentation |

---

## Security

- Ed25519 digital signatures on all transactions
- AES-256-GCM encrypted P2P communication with ECDH key exchange
- Chain ID replay protection across networks
- Sequence number anti-replay per account
- Input object access control for Move VM execution
- Slashing for equivocation (double-sign detection)
- 21-day unbonding to prevent Nothing-at-Stake attacks

---

## License

MIT License. See [LICENSE](./LICENSE) for details.

---

**Built with Rust. Secured by Math. Powered by Community.**
