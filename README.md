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

- **Consensus:** DAG-BFT (Bullshark-inspired); leaders follow a public schedule (`committee::leader_for_round`): the VDF beacon feeds nothing in consensus, so leaders are predictable
- **Execution:** Parallel Move VM with conflict-aware batch scheduling (Rayon)
- **Smart Contracts:** Move language (Aptos-compatible) for resource-safe programmability
- **Staking:** DPoS with 1,000 AIN minimum stake, 21-day unbonding, delegation pools with commission
- **Emission:** 1.90 % per year of the remaining reserve (the 150M cap minus everything minted), paid every reward period by consensus time, so it does not depend on block speed
- **Slashing:** equivocation only, by the share of stake that equivocated together: `(3 × share)²`, at least 1 %, 100 % from a third (any safety attack); the operator's own stake pays first, and the offender is jailed for good
- **Genesis:** genesis mints only the validator stakes and account balances its `genesis.json` lists ([Genesis Allocation](#genesis-allocation)); bootstrap weight fills the first committee and carries no coins; no key holds a mint or oracle authority at genesis (B314)
- **Token Factory:** Create custom tokens (ERC-20 equivalent) on-chain
- **DEX:** Built-in AMM (Constant Product x*y=k) with 0.3% fee
- **DePIN Integration:** Bio-Oracle for real-world data mining (Universal Mining); inactive at launch: the oracle has no feeder at genesis (B314) and DePIN gets no share of emission
- **Security:** Ed25519 + ML-DSA-65 (FIPS 204, post-quantum) transaction signatures, ChaCha20-Poly1305 encrypted P2P, full-transaction replay protection
- **Downtime Detection:** Validators missing 100+ rounds are detected and attested (gossip) but NOT slashed in this protocol version; only equivocation is slashed (see Slashing), through evidence carried in the DAG

---

## Tokenomics

| Parameter | Value |
|---|---|
| **Native Coin** | **$AIN** |
| **Max Supply** | 150,000,000 AIN (Hard Cap, enforced in smart contract) |
| **Genesis Allocation** | what `genesis.json` lists, within the cap: genesis validators' stake (bonded) and genesis accounts' balances (liquid); bootstrap weight carries no coins. Mainnet plan: at most 1,500,000 AIN (1 %), none of it to the founder ([details](#genesis-allocation)) |
| **Emission Reserve** | the cap minus the genesis allocation (at least 148,500,000 AIN, 99 %, on the mainnet plan), minted only as emission to the committee and its delegators |
| **VC Allocation** | **0% (Zero)** |
| **Emission** | 1.90 % per year of the remaining reserve, paid to the committee every reward period (20 blocks) for the consensus time since the last payout |
| **Emission Formula** | `e = remaining × λ × Δτ`, λ = −ln(0.981) per year; half of the reserve is emitted after about 36 years |
| **Reward Split** | each committee member's share is its weight (own stake, its pool's coins and any bootstrap weight) over the committee's weight, or over `s_min` when the committee weighs less (the unpaid rest stays in the reserve); its own part, bootstrap weight included, and its commission go to the validator, the rest to its delegators by points |
| **Fees** | EIP-1559 base fee (burned) that moves at most 1/8 a block toward half-full blocks; the tip above it: 10 % burned, then 20 % to the anchor leader and 80 % to the committee by weight, both against at least `s_min` (the part a lighter committee leaves is burned). Gas includes 400 per transaction byte |
| **Min Validator Stake** | 1,000 AIN |
| **Unbonding Period** | 21 days of consensus time, counted from the end of the last committee epoch |
| **Slashing Penalty** | equivocation only: `(3 × share that equivocated together)²`, minimum 1 %, 100 % from a third; settled once, when every correlated piece of evidence is in; the operator's own stake pays first |
| **Commission** | at most 30 %; an increase is at most 5 percentage points and takes effect after 7 days; a decrease applies at once |

### Fair Launch (No VC)

1. **Founder:** the mainnet plan gives the founder no genesis coins. Its validators run on bootstrap weight alone and earn emission by it, like any operator (see [Genesis Allocation](#genesis-allocation)). Nothing locks genesis stake: it is ordinary stake.
2. **Zero VC/Presale:** No tokens were sold to venture capitalists or institutional investors at a discount.
3. **At least 99 % minted as emission:** on the mainnet plan, everything beyond the genesis allocation (at most 1 % of the cap) is minted over time as staking rewards: 1.90 % a year of the remaining reserve, paid to the committee and its delegators. DePIN mining receives no share of emission at launch.
4. **Fees:** each block's base fee (EIP-1559) is burned for every unit of gas charged; of the tip above it, 10 % is burned, then 20 % goes to the block's anchor leader and 80 % to the committee by weight. Only transactions that executed and paid are stored in a block.

### Genesis Allocation

Genesis mints exactly what `genesis.json` lists (`build_genesis` in `core/node/src/genesis.rs`), and refuses a file whose total passes the 150M cap:

- **Validator stake**, bonded from the first block (a genesis validator's coin store starts empty): at least 1,000 AIN, or 0 for an operator with bootstrap weight. It is ordinary stake: leaving the validator set and 21 days of unbonding return it.
- **Account balances**, liquid.
- **Bootstrap weight** (G5 amendment A4) is consensus weight with no coins: it is never in a coin store, a stake or the supply. It fills the genesis committee up to `s_min`, shrinks as owned stake grows, and ends for good once owned stake has held `s_min` for 21 days. An operator forfeits its weight when it is jailed, leaves the validator set, or its participation score (a moving average of the leader slots it commits) falls below one half. It earns emission as stake does. With bootstrap weight, genesis refuses a committee in which one party (a validator, or the validators declaring one entity) holds a third or more.
- **Nothing else:** no treasury (B7: genesis refuses a nonzero `treasury_reserve`), and no key holds a mint or oracle authority (B314: wBTC's mint authority is an address no key signs for, and the DePIN oracle has no feeder).

The node checks the cap and the shape of the file, not who receives the coins: that is a rule of the genesis ceremony, and the file and the founder's addresses are public. The mainnet plan (`docs/G5_ECONOMICS_CONTRACT.md` amendment A4, `docs/research/genesis_bootstrap.md`):

- At most 1,500,000 AIN (1 % of the cap), earned on the incentivized testnet and computed by `genesis-tool score-testnet`: 1,000,000 AIN bonded, split equally among the qualified operators (at least five), and at most 500,000 AIN liquid for the public track (at most 1,000 AIN per funding cluster; what that cap leaves is never minted).
- No coins for the founder: its testnet validators are never scored or paid. Its validators hold bootstrap weight only, at most 30 % of `s_min` (18,500,000 AIN).
- By that weight the founder's validators earn about 30 % of the emission at launch, less as owned stake replaces bootstrap weight. No way to waive it is implemented.

A testnet's genesis lists what its operator chose. AINCORE-TESTNET-V4 predates bootstrap weight: its genesis gave the founder's four validators 4,625,000 AIN each as ordinary stake, a stand-in for `s_min`. Testnet AIN does not carry over: the mainnet allocation is computed from the testnet's leader slots and transactions, never from its balances.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    AINCORE Node                       │
├───────────┬───────────┬───────────┬──────────────────┤
│  P2P Net  │  Mempool  │  DAG-BFT  │ Ordering Engine  │
│  (Noise)  │ (Ed25519) │(Bullshark)│ (Commit)         │
├───────────┴───────────┴───────────┴──────────────────┤
│          Executor (Parallel Batch Scheduling)         │
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
cargo run --release -p node -- --datadir .aincore
```

The node will start producing blocks and expose the JSON-RPC API at `http://localhost:8002/rpc`.

### Run Stress Test (Bench-TPS)

```bash
# Load your local node from a funded account's key file (B308: a file only)
cargo run --release -p bench-tps -- --rpc http://127.0.0.1:8002/rpc \
  --chain-id "$AINCORE_CHAIN_ID" --funder-key ./funder.key
```

It shows the node's gas price and the most the run can pay in fees, and asks
to confirm before the funder signs anything (B381). `--max-gas-price <quanta>`
refuses a higher node price; `--assume-yes` skips the question.

---

## Public Observer Testnet

This is the public-connectivity path for outside users who want to run an
observer peer. It is meant to prove that outside nodes can reach AINCORE P2P and
sync the current fresh testnet without joining the validator set.

Current public scope: **observer-only testnet access**.

- External users may run observer peers and verify that they can sync blocks,
  finality, and quorum certificates.
- External users should **not** try to join as validators yet.
- No real funds, BTC/WBTC custody, rewards, or production staking are active on
  this public observer surface.
- The chain can reset during testnet hardening. Always use a fresh data
  directory for this branch.

### Public seed readiness gate

Before sharing this section with outside users, an operator must verify that the
public seed is reachable from the open internet:

```bash
nc -vz aincore-nas.tail406584.ts.net 443
```

If this check fails, do **not** publish the public observer instructions yet.
The node can still be used privately over Tailscale, but outside users will not
be able to sync.

Current public seed:

```text
/dns4/aincore-nas.tail406584.ts.net/tcp/443
```

### Operator: enable the public TCP seed

The fresh NAS node listens for P2P on host port `9022`. To expose it as a
temporary public TCP seed through Tailscale Funnel:

```bash
tailscale funnel --yes --bg --tcp 443 127.0.0.1:9022
tailscale funnel status
```

If Tailscale says Funnel is not enabled on the tailnet, enable it from the
Tailscale admin link shown by the command, then run the command again.

Sanity check from a new machine:

```bash
dig +short aincore-nas.tail406584.ts.net A
nc -vz aincore-nas.tail406584.ts.net 443
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
  --bootnodes /dns4/aincore-nas.tail406584.ts.net/tcp/443
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

- This public seed is temporary and may be rotated during testnet hardening.
- Public RPC is intentionally not exposed here; only the P2P seed is public.
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
and observer load. A tick is not a block: a block is placed per committed
anchor, and the block time of the current (V4) consensus is measured on the
release candidate before genesis; it is not a published figure yet.

```bash
# Default consensus tick.
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

> ⚠️ **WARNING:** Never run the same validator key on two machines, and never restore a validator from a backup of its database: two bodies or votes for one slot are equivocation, which jails the validator for good and slashes its stake and its delegators' (1 % alone, up to 100 % when a third of the committee equivocates together). Downtime is not slashed, but an offline validator earns nothing and weakens the committee, so use reliable hardware.

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

<!-- B380: Steps 2 to 7 and "Leaving the Validator Set" described CLI
behaviour that does not exist (keygen writing ~/.aincore/wallet.key and a
seed phrase, register-validator without a chain id or fee prompt, and the
enable-delegation, leave-validator and withdraw-unbonded commands). They now
use the commands of core/cli/src/main.rs and say what the CLI cannot do. -->

The validator's key is the node's `node.key` in its datadir: the node signs
with it, and `register-validator` must be signed by the same key (it registers
the signer's own Ed25519 key, and derives the BLS key from it). One file, two
roles. `scripts/validator-join/join-validator.sh` (`prepare`, `start`, `join`,
`verify`) runs Steps 2 to 6 for you.

```bash
# Build the CLI wallet
cargo build --release --bin aincore-cli

# keygen LOADS the key file named by --keyfile (default ./wallet.key, in the
# working directory) and prints its address. It creates the file only when it
# is missing and AINCORE_ALLOW_PLAINTEXT_WALLET=1 is set: a plaintext key, 0600.
mkdir -p /var/aincore/data
AINCORE_ALLOW_PLAINTEXT_WALLET=1 ./target/release/aincore-cli \
  --keyfile /var/aincore/data/node.key keygen
```

It prints three lines, and no seed phrase (there is none: the key file is the
only copy of the key, so back it up, `chmod 600`, never share it):
- **Address** — the display form (`A1n…`)
- **Address (hex)** — 64 hex characters, the form the RPC and `/get_validators` use
- **Public Key** — the Ed25519 public key, 64 hex characters

`aincore-cli keys generate [--out DIR]` makes a password-encrypted keystore
instead (in `~/.aincore/keys` by default), used with `--keystore <file>`. It
suits a spending wallet, not a validator: the node cannot read a keystore, so
a validator registered from one is not the key the node signs with.

### Step 3: Get 1,000 AIN Tokens

Before you can stake, the key must hold at least **1,000 AIN** plus the fee of
the registration.

- **Testnet:** ask the network operator to send AIN to your 64-hex address
  (there is no public faucet; the CLI's `faucet <address> <AIN>` is a plain
  transfer from the signer's own wallet)
- **Mainnet:** Acquire AIN through the DEX or from other holders

Check your balance (the node's RPC is its `--port` less 1000: 8000 for the
node of Step 4):
```bash
./target/release/aincore-cli --rpc http://127.0.0.1:8000/rpc balance <your-64-hex-address>
```

It prints `{ "balance": "<quanta>", "btc_balance": 0 }`; the balance is in
quanta (1 AIN = 10^18 quanta). Without an address it reads the address of
`--keyfile` (or `--keystore`).

### Step 4: Configure and Start Your Node

```bash
# Create data directory (it holds node.key from Step 2)
mkdir -p /var/aincore/data

# Start the node with your identity
# Replace BOOTNODE_IP with the network's bootnode address
./target/release/node \
  --port 9000 \
  --datadir /var/aincore/data \
  --bootnodes BOOTNODE_IP:9000
```

Wait for your node to fully sync. `aincore-cli --rpc http://127.0.0.1:8000/rpc info`
prints the node's status (`aincore_getStatus`); its `latest_height` must reach
the network's.

### Step 5: Register as Validator (Stake 1,000 AIN)

Once your node is synced and running:
```bash
./target/release/aincore-cli --rpc http://127.0.0.1:8000/rpc \
  --keyfile /var/aincore/data/node.key --chain-id "$AINCORE_CHAIN_ID" \
  register-validator
```

- **`--chain-id`** (or the `AINCORE_CHAIN_ID` environment variable) is
  required, and must be the chain the node runs: the CLI asks the node and
  refuses to sign for any other chain.
- `--rpc`, `--keyfile`, `--keystore`, `--pqc-seed` and `--chain-id` go
  **before** the command name; `--execution-gas`, `--max-gas-price` and
  `--assume-yes` may go anywhere.
- **The fee is shown and confirmed.** Before signing, it prints
  `Fee: at most <AIN> AIN (<quanta> quanta): <gas> gas at <price> quanta a gas`
  and asks `Sign and submit? [y/N]`; only `y` or `yes` signs. The gas price is
  the node's; `--max-gas-price <quanta>` refuses a price above it, and
  `--assume-yes` skips the question (for scripts). The execution gas is the
  node's estimate unless `--execution-gas` names it; either way, gas past a
  transaction's limit (10,000,000) is refused.

It sends one transaction, `0x1::staking::join_validator_set`, with:
1. a stake of exactly **1,000 AIN** (the minimum; the CLI does not take an amount)
2. the key's Ed25519 public key
3. a BLS public key and proof of possession, derived from the same key (an
   ML-DSA-65 `--pqc-seed` wallet cannot register)

`✅ Validator Registration Submitted` means the node took the transaction into
its mempool, not that it executed: check Step 6.

### Step 6: Verify Your Validator Status

```bash
# The validator set (address and stake of each): your 64-hex address should be in it
curl -s http://127.0.0.1:8000/get_validators

# Your liquid balance: 1,000 AIN lower, less the fee
./target/release/aincore-cli --rpc http://127.0.0.1:8000/rpc balance <your-64-hex-address>
```

The CLI has no validator-status command. Your staked amount will be locked.
From the next committee epoch you are in the committee if your stake is among
the top 256, and you are paid every reward period (20 blocks) in proportion to
your committee weight.

### Step 7: (Optional) Enable Delegation

**Not available from the CLI.** Delegation is opened on chain by the entry
function `0x1::delegation::enable_delegation(commission_rate)` (basis points,
at most 3,000 = 30 %), signed by the validator's key; `aincore-cli` has no
command that sends it, so it needs a client that builds entry-function
transactions.

---

## Leaving the Validator Set

**Not available from the CLI.** `aincore-cli` has no `leave-validator` or
`withdraw-unbonded` command. On chain, the validator's key signs the entry
function `0x1::staking::leave_validator_set`, which starts a **21-day unbonding
period** (consensus time) for network security; after it,
`0x1::staking::withdraw_unbonded` returns the stake. Both need a client that
builds entry-function transactions.

`aincore-cli --help` lists every command it has: `keygen`, `pqc-keygen`,
`info`, `submit-proof`, `balance`, `transfer`, `publish`, `keys generate`,
`keys import`, `register-validator` and `faucet`.

---

## Security Model

### Protocol-Level Protections

| Protection | Implementation | File |
|---|---|---|
| **Equivocation slashing** | A proven double-sign jails the validator for good and moves its stake into 21-day unbonding at once; the fraction (1 % to 100 %, by the weight that equivocated together) is cut once it is final | `delegation.move`, `executor/src/lib.rs` |
| **Downtime** | Not slashed in this protocol version | — |
| **Double-Sign Detection** | Two bodies for one slot, or two certificates, become evidence carried through the DAG | `consensus/v4/evidence.rs` |
| **Replay Protection** | Full transaction signing: `chain_id:sender:payload:seq_num:gas_limit:gas_price:input_objects` (and the paymaster, when sponsored); a chain id is used by one network incarnation only (B348) | `executor/src/admission.rs` |
| **Chain ID Isolation** | Transactions rejected if chain_id mismatches | `executor/src/lib.rs` |
| **Sequence Numbers** | Per-account nonce prevents transaction replay | `executor/src/lib.rs` |
| **Ed25519 Signatures** | All transactions cryptographically signed | `vm_move/src/lib.rs` |
| **Encrypted P2P** | libp2p Noise (XX handshake, X25519, ChaCha20-Poly1305) between nodes | `core/node/src/p2p.rs` |
| **BFT Threshold** | `ceil(2n/3)` quorum for consensus finality | `ordering.rs` |
| **Input Object ACL** | Move VM scripts restricted to declared objects | `executor/src/lib.rs` |
| **Supply Hard Cap** | `MAX_SUPPLY` enforced in smart contract with checked arithmetic | `staking.move` |

### Cryptographic Stack

- **Signatures:** Ed25519 (ed25519-dalek, strict) + ML-DSA-65 (FIPS 204, aws-lc-rs, post-quantum)
- **Hashing:** SHA-256 (sha2), SHA3-256 (sha3)
- **BLS:** BLS12-381 aggregate signatures for consensus
- **Key Exchange:** X25519 (Diffie-Hellman) for ephemeral session keys
- **Encryption:** ChaCha20-Poly1305 authenticated encryption (timing-attack resistant)
- **PQC:** ML-DSA-65 (FIPS 204) for quantum-resistant transaction signing; the transaction carries its key
- **Accumulator:** Cryptographic accumulator for state root proofs

---

## Smart Contract Modules (Move)

AINCORE uses the Move programming language. All core modules live in `core/vm_move/stdlib/sources/`:

| Module | File | Description |
|---|---|---|
| `staking` | `staking.move` | DPoS validator staking, the emission draw, validator unbonding |
| `delegation` | `delegation.move` | Delegation pools (points and a reward counter), the committee payout, slashing |
| `dex` | `dex.move` | AMM DEX (Constant Product x*y=k, 0.3% fee) |
| `token_factory` | `token_factory.move` | Create/Mint/Burn/Transfer custom tokens |
| `governance` | `governance.move` | On-chain proposal creation and voting |
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
| `aincore_getBalance` | Account balance |
| `aincore_sendTransaction` | Submit a signed transaction |
| `aincore_getBlocks` | Blocks from a height, or the latest N |
| `aincore_getBlockByHash` | A block by its hash |
| `aincore_getTransaction` | A transaction by hash (`aincore_getTransactionReceipt`: its receipt) |
| `aincore_getStatus` | Height, round, peers, finality |
| `aincore_getDag` | DAG consensus state |
| `aincore_getValidatorsWithDelegation` | Validators and their delegation pools (REST: `/get_validators`) |
| `aincore_getPeers` | Connected peers |

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

**Genesis Lock (Anti-Rugpull)** (withdrawn: nothing ever enforced it, and B314 deleted the genesis row (`sys:config:federation_addr`) that named the locked address; genesis stake is ordinary stake, see [Genesis Allocation](#genesis-allocation))

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
- Full DPoS staking (the original economic model, since replaced by consensus-time emission)
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
