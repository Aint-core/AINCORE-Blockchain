# AINCORE Blockchain

**Sovereign Layer-1 | DAG-BFT Consensus | Move VM | No-VC Fairlaunch**

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)]()
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Security](https://img.shields.io/badge/audit-pending-yellow)]()

---

## Overview

AINCORE is a high-performance Layer-1 blockchain built entirely in Rust, featuring DAG-based BFT consensus (inspired by Bullshark/Narwhal), parallel transaction execution via Move VM, and a Delegated Proof of Stake (DPoS) economic model with **Zero VC allocation**.

### Key Features

- **Consensus:** DAG-BFT (Bullshark-inspired) with VDF random beacon for unpredictable leader election
- **Execution:** Parallel Move VM with conflict-aware batch scheduling (Rayon)
- **Smart Contracts:** Move language (Aptos-compatible) for resource-safe programmability
- **Staking:** DPoS with 1,000 AIN minimum stake, 21-day unbonding, halving rewards
- **Jail System:** Misbehaving validators are slashed 5% and force-unbonded (not 100% burned)
- **Genesis Lock:** Founder's pre-mine is **mathematically locked** in smart contract — cannot be transferred or sold
- **Token Factory:** Create custom tokens (ERC-20 equivalent) on-chain
- **DEX:** Built-in AMM (Constant Product x*y=k) with 0.3% fee
- **DePIN Integration:** Bio-Oracle for real-world data mining (Universal Mining)
- **Security:** Ed25519 + Dilithium5 (PQC) signatures, ChaCha20-Poly1305 encrypted P2P, full-transaction replay protection
- **Downtime Detection:** Validators missing 100+ rounds are automatically jailed and slashed

---

## Tokenomics

| Parameter | Value |
|---|---|
| **Native Coin** | **$AIN** |
| **Max Supply** | 150,000,000 AIN (Hard Cap, enforced in smart contract) |
| **Genesis Allocation** | ~1,050,000 AIN (0.7% — Validator Stake + Treasury) |
| **Community Supply** | ~148,950,000 AIN (99.3% — Mined via DePIN & Staking) |
| **VC Allocation** | **0% (Zero)** |
| **Block Reward** | 36 AIN per epoch (Halving model) |
| **Halving Interval** | ~4 years (2,102,400 epochs) |
| **Min Validator Stake** | 1,000 AIN |
| **Unbonding Period** | 21 days (1,814,400 seconds) |
| **Slashing Penalty** | 5% stake burn + forced 21-day unbonding |
| **Reward Formula** | `Reward = 36 AIN >> (epoch / 2,102,400)` |

### Fairlaunch Model (No-VC, Hyperliquid-Style)

AINCORE follows a **No-VC Fairlaunch** model inspired by Hyperliquid:

1. **Genesis Validator Lock:** The founder's initial stake (used to bootstrap the network) is **permanently locked** at the protocol level. The `Executor` rejects any `transfer` transaction from the Genesis address. This is enforced in code, not by promise.
2. **Zero VC/Presale:** No tokens were sold to venture capitalists or institutional investors at a discount.
3. **99.3% Community Owned:** Nearly all tokens are minted exclusively through DePIN Mining and Staking Rewards over time.
4. **Buyback Ready:** Transaction fees flow to the Treasury, enabling protocol-level buyback mechanisms.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    AINCORE Node                       │
├───────────┬───────────┬───────────┬──────────────────┤
│  P2P Net  │  Mempool  │  DAG-BFT  │ Ordering Engine  │
│ (AES-GCM) │ (Ed25519) │(Bullshark)│ (Commit/VDF)     │
├───────────┴───────────┴───────────┴──────────────────┤
│          Executor (Parallel Batch Scheduling)         │
│          ├── Genesis Lock (Anti-Rugpull)              │
│          └── Gas Abstraction (Paymaster)              │
├──────────────────────────────────────────────────────┤
│          Move VM (Smart Contracts)                    │
│          ├── staking.move (DPoS + Jail System)        │
│          ├── dex.move (AMM x*y=k)                    │
│          ├── universal_mining.move (DePIN Oracle)     │
│          └── token_factory.move (Custom Tokens)       │
├──────────────────────────────────────────────────────┤
│          StateDB (RocksDB) + DAG Checkpoints          │
└──────────────────────────────────────────────────────┘
```

### Component Map

| Component | Port | Path | Description |
|---|---|---|---|
| Core Node | 9000 (P2P) | `core/node` | Main validator process |
| JSON-RPC API | 8002 (HTTP) | `core/node/src/api_local.rs` | Wallet/DApp interface |
| CLI Wallet | — | `core/cli` | Command-line wallet & tools |
| Bench-TPS | — | `core/cli/src/bin/bench_tps.rs` | Stress test tool |
| JS/TS SDK | — | `aincore-js` | DApp development SDK |
| Indexer | 3001 | `indexer` | Transaction history API |
| Bridge | — | `depin/bridge-rust` | Cross-chain BTC bridge |
| Monitor | Terminal | `monitor` | Live node dashboard |

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

### Run Stress Test (Bench-TPS)

```bash
# Fire 1000 transactions at your local node
cargo run --release --bin bench_tps -- http://127.0.0.1:3030 1000
```

---

## Public Testnet Burst (Temporary VPS Seed)

This is the fastest public-connectivity test path. It uses the current VPS as a
temporary public seed while the NAS/Pi/private observers keep running on
Tailscale. It is meant to prove that outside nodes can reach AINCORE P2P without
turning the home NAS into the public entrypoint.

Current public scope: **observer-only testnet access**.

- External users may run observer peers and verify that they can sync blocks,
  finality, and quorum certificates.
- External users should **not** try to join as validators yet.
- No real funds, BTC/WBTC custody, rewards, or production staking are active on
  this public observer surface.
- The chain can reset during testnet hardening. Always use a fresh data
  directory for this branch.

Current temporary public seed:

```text
/dns4/p2p.aincore.network/tcp/9042
```

Additional libp2p listener exposed for peer discovery experiments:

```text
/dns4/p2p.aincore.network/tcp/9142
```

Sanity check from a new machine:

```bash
dig +short p2p.aincore.network A
nc -vz p2p.aincore.network 9042
nc -vz p2p.aincore.network 9142
```

Run an observer against the public seed:

```bash
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
git checkout audit/p0-security-fixes

cargo build --release --bin node

mkdir -p ./aincore-public-testnet-data

./target/release/node \
  --port 9032 \
  --rpc-port 8032 \
  --datadir ./aincore-public-testnet-data \
  --bootnodes /dns4/p2p.aincore.network/tcp/9042
```

If DNS resolution is unavailable on your machine, use the temporary raw-IP
fallback:

```text
/ip4/45.80.181.141/tcp/9042
```

Verify local observer health:

```bash
curl -fsS http://127.0.0.1:8032/health

curl -fsS -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}' \
  http://127.0.0.1:8032/rpc
```

Expected status:

- `/health` returns `OK`
- `latest_height` increases
- `finalized_round` increases
- `peers_count` becomes at least `1`

Important notes:

- This VPS seed is temporary while the current VPS lease is still active.
- Public RPC is intentionally not exposed here; only P2P seed ports are public.
- This is still a testnet/fresh-chain surface, not a mainnet value network.
- Do not use this path for real BTC/WBTC custody or production funds.
- Keep your local RPC bound to localhost or firewalled. Do not expose your
  observer RPC port to the public internet.

### Storage Mode

AINCORE stores live world-state separately from historical block bodies. Validator
and observer nodes do not need to keep every historical `block_{height}` row
forever.

Set `AINCORE_STORAGE_MODE` before running a node:

```bash
# Default validator mode: keep live state and the last 100k block bodies.
export AINCORE_STORAGE_MODE=full

# Observer mode: keep live state and a short local block-history window.
export AINCORE_STORAGE_MODE=observer

# Archive/indexer mode: keep all historical block bodies and tx indexes.
export AINCORE_STORAGE_MODE=archive
```

Optional retention knobs:

```bash
export AINCORE_BLOCK_RETENTION=100000   # full default: 100k, observer default: 1k
export AINCORE_BLOCK_PRUNE_BATCH=250    # max old block rows deleted per commit
```

Pruning only removes historical `block_*`, `block_txs:*`, and matching
`tx_index:*` rows. It does **not** prune live account/object resources.

### Consensus Tick

Public testnet nodes should use the default 3-second consensus ticker. Faster
ticks are useful for private soak/stress runs, but they increase DB, indexer,
and observer load.

```bash
# Default public-testnet cadence: roughly one block every 3 seconds.
export AINCORE_CONSENSUS_TICK_MS=3000
```

---

## Join as an Observer Peer over Tailscale

Use this path for a non-validator peer that syncs from an existing AINCORE node without exposing public P2P ports. This is the recommended setup for Raspberry Pi, spare laptops, NAS boxes, and private testnet devices.

Runtime networking uses **Tailscale**. GitHub is only used to distribute source code.

### Current Hardening Branch

The latest security-hardening branch for the current testnet/fresh observer flow is:

```bash
audit/p0-security-fixes
```

GitHub URL:

```text
https://github.com/Aint-core/AINCORE-Blockchain/tree/audit/p0-security-fixes
```

### Step 1: Install and Join Tailscale

Install Tailscale on the observer device and log in to the same tailnet as the bootnode:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
tailscale status
```

Confirm you can reach the bootnode's Tailscale IP before building:

```bash
nc -vz 100.111.32.83 9022
```

If the port check fails, fix Tailscale connectivity first. Do not fall back to public internet ports unless you intentionally want a public peer.

### Step 2: Clone the Source

```bash
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
git checkout audit/p0-security-fixes
```

If the repository already exists:

```bash
cd AINCORE-Blockchain
git fetch origin
git checkout audit/p0-security-fixes
git pull --ff-only origin audit/p0-security-fixes
```

### Step 3: Build the Node

```bash
cargo build --release --bin node
```

On small ARM devices such as Raspberry Pi, limit parallel jobs if the build runs out of memory:

```bash
CARGO_BUILD_JOBS=2 cargo build --release --bin node
```

### Step 4: Run the Observer Peer

Pick ports that do not conflict with any local service. This example uses `9032` for P2P and `8032` for RPC:

```bash
mkdir -p ./aincore-peer-data

./target/release/node \
  --port 9032 \
  --rpc-port 8032 \
  --datadir ./aincore-peer-data \
  --bootnodes /ip4/100.111.32.83/tcp/9022
```

The bootnode address above is the NAS fresh-node Tailscale endpoint:

```text
/ip4/100.111.32.83/tcp/9022
```

### Step 5: Verify Health and Sync

Health check:

```bash
curl -fsS http://127.0.0.1:8032/health
```

Status check:

```bash
curl -fsS -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}' \
  http://127.0.0.1:8032/rpc
```

Healthy observer output should show:

- `latest_height` increasing over time
- `finalized_round` increasing over time
- `finality_digest` not empty
- `peers_count` at least `1`
- `/health` returning `OK`

### Step 6: Watch File Descriptors on Small Devices

AINCORE's encrypted P2P transport includes handshake timeouts to prevent stale sockets from pinning file descriptors. On small devices, still monitor the process during long runs:

```bash
pid=$(pgrep -f "target/release/node" | head -n1)
echo "pid=$pid"
ls /proc/$pid/fd | wc -l
ss -tanp | grep "$pid" | wc -l
```

As a rough sanity check, an idle observer should stay in the tens or low hundreds of file descriptors, not thousands.

For a persistent Linux service, use `systemd` and set a higher file descriptor limit:

```ini
[Service]
LimitNOFILE=65535
```

### Notes

- Observer peers do **not** validate or earn rewards.
- Validator registration is not open to outside users on the current public
  observer testnet. The validator runbook below is internal/future-facing.
- Keep node-to-node traffic on Tailscale while this network is still in private testnet mode.
- Do not compare an observer connected to the fresh Tailscale bootnode with an older soak chain if they use different data directories or genesis state.

---

## Validator Guide (Not Active for Public Testnet)

> ⚠️ **Current status:** the public testnet is open for **observer peers only**.
> External validator onboarding, public staking, rewards, and slashing are not
> active for outside users yet. Do not follow the validator flow below against
> the current public observer testnet.
>
> This section is retained as an internal/future validator runbook. It becomes
> relevant only after AINCORE announces a production-like or incentivized
> validator testnet with explicit validator registration instructions.

This guide walks you through becoming a validator on the AINCORE network.

### Requirements

| Requirement | Minimum |
|---|---|
| **Server** | VPS or dedicated machine, **24/7 uptime required** |
| **CPU** | 2+ cores |
| **RAM** | 4 GB |
| **Storage** | 50 GB SSD |
| **Network** | Stable internet, open port 9000 (TCP) |
| **Stake** | 1,000 AIN tokens |

> ⚠️ **WARNING:** Running a validator on unreliable hardware (laptop, home WiFi) risks **automatic slashing**. If your node misses 100+ consecutive rounds, the Jail System will slash 5% of your stake and lock the remaining 95% for 21 days. Use a reliable VPS provider (AWS, Google Cloud, Hetzner, etc.).

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

## Security Model

### Protocol-Level Protections

| Protection | Implementation | File |
|---|---|---|
| **Genesis Lock** | Transfers from Genesis address permanently blocked | `executor/src/lib.rs` |
| **Jail System** | 5% slash + 21-day forced unbonding for misbehavior | `staking.move` |
| **Downtime Detection** | Auto-slash after 100+ missed rounds | `consensus/dag.rs` |
| **Double-Sign Detection** | Equivocation proof triggers immediate slash | `consensus/dag.rs` |
| **Replay Protection** | Full transaction signing: `chain_id:sender:payload:seq_num` | `executor/src/lib.rs` |
| **Chain ID Isolation** | Transactions rejected if chain_id mismatches | `executor/src/lib.rs` |
| **Sequence Numbers** | Per-account nonce prevents transaction replay | `executor/src/lib.rs` |
| **Ed25519 Signatures** | All transactions cryptographically signed | `vm_move/src/lib.rs` |
| **ChaCha20-Poly1305 P2P** | Authenticated encrypted node-to-node communication (X25519 key exchange) | `crypto/src/transport.rs` |
| **BFT Threshold** | `ceil(2n/3)` quorum for consensus finality | `ordering.rs` |
| **Input Object ACL** | Move VM scripts restricted to declared objects | `executor/src/lib.rs` |
| **Supply Hard Cap** | `MAX_SUPPLY` enforced in smart contract with checked arithmetic | `staking.move` |

### Cryptographic Stack

- **Signatures:** Ed25519 (ed25519-dalek) + CRYSTALS-Dilithium5 (Post-Quantum)
- **Hashing:** SHA-256 (sha2), SHA3-256 (sha3)
- **BLS:** BLS12-381 aggregate signatures for consensus
- **Key Exchange:** X25519 (Diffie-Hellman) for ephemeral session keys
- **Encryption:** ChaCha20-Poly1305 authenticated encryption (timing-attack resistant)
- **PQC:** CRYSTALS-Dilithium5 (NIST Standard) for quantum-resistant transaction signing
- **Accumulator:** Cryptographic accumulator for state root proofs

---

## Smart Contract Modules (Move)

AINCORE uses the Move programming language. All core modules live in `core/vm_move/stdlib/sources/`:

| Module | File | Description |
|---|---|---|
| `staking` | `staking.move` | DPoS validator staking, halving rewards, **Jail System** |
| `delegation` | `delegation.move` | Liquid staking delegation with commission |
| `dex` | `dex.move` | AMM DEX (Constant Product x*y=k, 0.3% fee) |
| `token_factory` | `token_factory.move` | Create/Mint/Burn/Transfer custom tokens |
| `governance` | `governance.move` | On-chain proposal creation and voting |
| `treasury` | `treasury.move` | System treasury and reserve management |
| `universal_mining` | `universal_mining.move` | DePIN Bio-Oracle with quorum voting |
| `epoch` | `epoch.move` | Epoch lifecycle management |
| `coin` | `coin.move` | Base coin operations (mint/burn/transfer) |
| `wbtc` | `wbtc.move` | Wrapped BTC bridge integration |

Compile a Move module:
```bash
cargo run --release -p move_compiler_tool -- -s path/to/your_module.move -o ./build
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

## Network Configuration

### Chain IDs

| Network | Chain ID | Usage |
|---|---|---|
| **Mainnet** | `AINCORE-MAINNET-1` | Production (set via `AINCORE_CHAIN_ID` env var) |
| **Current fresh public testnet** | `AINCORE-LATEST-FRESH-1` | Active public observer testnet lineage |
| **Legacy testnet** | `AINCORE-TESTNET-1` | Older local/test fixtures only |

### Environment Variables

```bash
export AINCORE_CHAIN_ID=AINCORE-MAINNET-1  # Required for production
```

---

## Changelog

### v1.1.0 — May 12, 2026 (Security Hardening)

**Genesis Lock (Anti-Rugpull)**
- Executor permanently blocks transfer transactions from the Genesis Validator address
- Genesis funds can only be used for staking, never sold or transferred
- Automatically registered during genesis ceremony

**Jail System (Validator Protection)**
- `slash_validator` now slashes 5% stake and force-unbonds remaining 95% for 21 days
- Replaces the previous 100% immediate burn policy (too destructive for honest mistakes)
- Follows Cosmos SDK economic safety standards

**Downtime Auto-Detection**
- Consensus engine tracks validator participation per round via `validator:last_seen:{id}`
- Validators missing 100+ consecutive rounds are automatically jailed
- Double-slash prevention via jail key tracking
- Efficient: runs every 10 rounds to minimize CPU overhead

**Hardcoded Key Removal**
- Removed all hardcoded genesis validator addresses from `storage/src/lib.rs`
- Validator set now purely driven by `genesis.json` configuration
- `get_active_validators()` returns empty if not initialized (no hidden fallbacks)

**Stress Test Tool**
- New binary: `bench_tps` for network throughput testing
- Generates N unique Ed25519 keypairs and fires transactions at node API
- Real-time TPS monitoring with success/failure counters

### v1.0.0 — May 2026 (Initial Release)

- DAG-BFT consensus with Bullshark-inspired ordering
- Move VM integration with parallel execution (Rayon)
- Full DPoS staking with halving economic model
- 21-day unbonding period (Nothing-at-Stake protection)
- Consensus state persistence (RocksDB) for crash recovery
- DAG checkpoint system for O(1) node startup
- Single reward source (staking.move only, no executor inflation)
- Ghost script execution prevention
- P2P network stability improvements
- Cryptographic accumulator for state proofs
- Data Availability sequencer with erasure coding

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

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT License. See [LICENSE](./LICENSE) for details.

---

**Built with Rust. Secured by Math. Powered by Community. Zero VC.**
