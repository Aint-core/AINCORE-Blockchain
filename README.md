# AINCORE BLOCKCHAIN (Singularity Edition)

**Status:** PRODUCTION READY (Backend/Core) | Devnet Beta

## Overview

AINCORE is a high-performance Layer-1 blockchain featuring:

- **Consensus:** DAG-based Narwhal-Lite for high throughput
- **Execution:** Parallel Move VM (Aptos-compatible)
- **Architecture:** Modular design with separated Node, Indexer, Bridge, and Monitor
- **Safety:** 100% Rust, audited and hardened

---

## Documentation

Complete developer documentation is available in the [`/docs`](./docs) folder:

| Guide | Description |
|-------|-------------|
| [Technical Documentation](./docs/TECHNICAL_DOCUMENTATION.md) | Architecture, getting started, core components |
| [Move Development Guide](./docs/MOVE_DEVELOPMENT_GUIDE.md) | Smart contract development with tutorials |
| [Consensus Deep Dive](./docs/CONSENSUS_DEEP_DIVE.md) | DAG and Bullshark internals |
| [Node Operator Guide](./docs/NODE_OPERATOR_GUIDE.md) | Running and maintaining validators |
| [Crypto Module Guide](./docs/CRYPTO_MODULE_GUIDE.md) | Cryptography primitives reference |
| [API Reference](./docs/API_REFERENCE.md) | Complete JSON-RPC API documentation |

---

## Quick Start

### 1. Start the Full Cluster

Run the master script to compile and launch the Node, Bridge, and Sequencer:

```bash
./scripts/start_validator.sh
```

Wait for "Main Execution Loop started" and "Bridge Service Running" messages.

### 2. Start the Monitor Dashboard

In a new terminal:

```bash
./scripts/start_monitor.sh
```

This displays block height, peer count, and cluster health.

---

## Developer Tools

### Wallet CLI

The command line interface supports all transaction types.

**Location:** `core/cli`

```bash
# Build
cargo build --release --bin aincore-cli

# Create alias
alias wallet="./target/release/aincore-cli"

# Available commands
wallet keygen                              # Create new wallet
wallet balance                             # Check balance
wallet transfer --to <HEX> --amount 100    # Send tokens
wallet submit-proof --device <ID> --quality 95  # DePIN mining
wallet register-validator                  # Stake 1000 AIN
```

### JavaScript/TypeScript SDK

For building DApps or web wallets.

**Location:** `aincore-js`

```typescript
import { Connection, Keypair, Transaction } from 'aincore';

const conn = new Connection("http://localhost:8001/rpc");
const kp = Keypair.fromSecretKey(hexString);

const tx = new Transaction();
tx.payload = "transfer:RECIPIENT:100";
const sig = kp.sign(tx.message);
await conn.sendTransaction(tx);
```

### Indexer API

For querying transaction history (Explorer backend).

**URL:** `http://localhost:3001`

**Endpoints:**
- `GET /history/{address}` - Get last 50 transactions for an account

---

## System Architecture

| Component | Port | Path | Status |
|-----------|------|------|--------|
| Core Node | 8001 (RPC) | `core/node` | Active |
| Consensus | Internal | `consensus` | Active (Bullshark) |
| Data Availability | Internal | `da` | Active (P2P Sharding) |
| Indexer | 3001 (API) | `indexer` | Active |
| Bridge | Internal | `depin/bridge-rust` | Active |
| Monitor | Terminal | `monitor` | Active |
| Governance | N/A | `governance` | In Development |

---

## Recent Updates (Jan 2026)

- **Sovereign DA Layer:** Fully operational Data Availability with P2P sharding
- **Light Client API:** Verifiable Merkle proofs for shard inclusion
- **Logic Hardening:** Complete audit of VM, Consensus, and Networking layers

---

## Known Limitations

1. **No Web Frontend:** Users must use CLI for wallet and explorer functions
2. **Privacy Module Inactive:** ZK-Proof module exists but is not connected to the Executor
3. **Bridge Keys:** Currently uses file-based keys; use `--keystore` flag for production

---

## Security

- 20 critical security vectors addressed
- Replay protection enabled
- Type-safe transaction handling
- DoS hardening implemented
