# Multi-Validator Cluster Bring-Up (#15)

This guide shows how to stand up an N-validator AINCORE cluster from scratch:
generate per-validator node keys, build a single shared `genesis.json` that
embeds each validator's BLS finality identity, and start the nodes so they peer
and produce quorum certificates (QCs) that verify against one another.

> Each validator derives its Ed25519 and BLS identities on its own machine.
> The coordinator verifies its signed public entry and includes it in the shared
> genesis file. Each operator keeps its own seed.

---

## 0. Prerequisites

From the root of the pinned release checkout, build the two binaries and use that
checkout's committed Move bytecode in `core/vm_move/stdlib/bytecode`. The tool
hashes this directory into genesis. Each initializing node needs the same bytecode.

```bash
cargo build --locked --release -p node -p genesis-tool
```

---

## 1. Generate one node key (seed) per validator

`node.key` is a **32-byte seed** (stored raw, or as 64 hex chars). It is the
single root secret: it re-derives the Ed25519 consensus identity, the BLS
finality seed, and the DA at-rest key. Generate one per validator:

```bash
# Cryptographically random 32-byte seed, hex-encoded:
openssl rand -hex 32                       # -> e.g. 1111...1111 (64 hex chars)
```

Do this **N times** (once per validator) and keep the seeds private. Example for
a 3-validator cluster (use real random seeds in production — these are
illustrative):

```
val1 seed: 1111111111111111111111111111111111111111111111111111111111111111  stake 1000000 AIN
val2 seed: 2222222222222222222222222222222222222222222222222222222222222222  stake 2000000 AIN
val3 seed: 3333333333333333333333333333333333333333333333333333333333333333  stake 1500000 AIN
```

> With independent operators no seed leaves its validator. Each operator runs, on
> its own machine:
>
> ```bash
> ./target/release/genesis-tool validator-entry --key /path/to/datadir/node.key
> ```
>
> and sends the printed entry (address, `public_key`, `bls_public_key`, `bls_pop`,
> `entry_sig`; nothing secret) to the genesis coordinator. `entry_sig` is the node
> key's signature binding the BLS key to the address; `bls_pop` proves the BLS key.

---

## 2. Build the shared `genesis.json`

**Independent operators (the mainnet path).** Collect the signed entries in
`entries.json` with `stake_ain` in whole AIN and the bootstrap fields described below.
Prepare the approved scoring outputs first. Run `genesis-tool clock-cap --intervals intervals.txt`
on consecutive block timestamp intervals from the release candidate. Set `BLOCK_TIME_MS`
and `CLOCK_CAP_SECS` to the two values it prints, and `GENESIS_TIME` to the agreed Unix
launch time. Then generate the file once.

```bash
./target/release/genesis-tool gen-multi \
  --entries-file entries.json \
  --allocations-file score/allocations.json --accounts-file score/accounts.json \
  --s-min-ain 18500000 --chain-id AINCORE-MAINNET-1 --mainnet \
  --block-time-ms "${BLOCK_TIME_MS:?}" --clock-cap-secs "${CLOCK_CAP_SECS:?}" \
  --genesis-time "${GENESIS_TIME:?}" --out genesis.json
```

**A chain id is used once (B348).** A transaction signs its chain id, not its
genesis (as on Ethereum, Aptos and Cosmos), so every incarnation of a network (a
relaunch, a rehearsal, a testnet reset) takes a chain id never used before; under a
reused one, every transaction of one is valid on the other once its sequence number
comes round. `gen-multi` gives `AINCORE-MAINNET-1` only with `--mainnet` (the launch
genesis), and `--mainnet` nothing else: rehearsals use their own ids
(`AINCORE-REHEARSAL-…`).

Every entry is checked before the file is written: the address derives from
`public_key`, `entry_sig` verifies under it, `bls_pop` verifies for `bls_public_key`,
and no address or BLS key appears twice. The loader checks the committee again at boot.

**One operator holding every seed (test clusters only).** `--seeds-file` takes one
`<node_key_seed_hex>:<stake_whole_ain>` per line and derives the same entries; prefer it
to `--validator`, which puts seeds in shell history and `ps`:

```bash
./target/release/genesis-tool gen-multi \
  --seeds-file seeds.txt \
  --chain-id "${REHEARSAL_CHAIN_ID:?set a fresh rehearsal ID}" \
  --block-time-ms "${BLOCK_TIME_MS:?}" --clock-cap-secs "${CLOCK_CAP_SECS:?}" \
  --out genesis.json
```

Entries and seeds give byte-identical validator entries (witness:
`public_entries_build_the_same_genesis_as_the_seeds`).

**Bootstrap weight (G5 amendment A4).** For a launch without a pre-mine, give each launch
operator a `bootstrap_ain` in its entry (it may own `stake_ain: 0`) and pass `--s-min-ain`,
the genesis committee's weight. Stake plus bootstrap weight must sum to exactly
`s_min`. Each party's total weight must stay strictly below one third. Liquid
balances for the incentivized testnet's public track go in `--accounts-file` as
`[{"address": "...", "balance_ain": N}]`. Bootstrap adds voting weight only.
Genesis supply equals owned stake plus liquid genesis accounts. The generator
omits the treasury reserve. The loader accepts only zero if an older file
supplies that field. Owned stake is zero with bootstrap weight or at least
1,000 AIN.

For mainnet, the incentivized testnet's scoring writes these inputs (G5 A4-S6). Stop a testnet
node at least 7 days (W) after the announced snapshot and run, on its datadir:

```bash
./target/release/genesis-tool score-testnet --datadir /data/aincore \
  --from-height "${FIRST_HEIGHT:?}" --to-height "${SNAPSHOT_HEIGHT:?}" \
  --founder "${FOUNDER_ADDRESSES:?comma-separated testnet validator addresses}" \
  --faucet "${TESTNET_FAUCET_ADDRESS:?}" --out-dir score/
```

It writes `allocations.json` (each qualified operator's bonded stake and bootstrap weight),
`accounts.json` (the public track) and `report.json` (every number behind them). Every
qualified operator sends its `validator-entry` made with the key it qualified with; the founder
adds its own entries with `bootstrap_ain` (at most 30 % of `s_min` in total). The generator
matches each scored allocation to its public entry by address, validates the result
using the node's genesis rules and prints the genesis identity. Inspect the values in the generated file before distribution.

```bash
jq '{chain_id, epoch_block_interval, reward_period_blocks, max_block_interval_secs, stdlib_hash, genesis_time}' genesis.json
```

Distribute this **identical** `genesis.json` to every validator node. Order does
not matter — the validator-set hash is address-sorted and order-independent.

> The address shown for each validator is what that node will derive locally from
> its `node.key`, so the operator can match each printed address to the seed it
> belongs to.

---

## 3. Place each validator's `node.key`

For each node, create its datadir and write **its own** 32-byte seed to
`<datadir>/node.key`. The seed in `node.key` **must** be the same one used for
that validator in `gen-multi` — otherwise the node derives a different
address/BLS key than the genesis declares and is rejected as a non-validator.

```bash
# Validator 1
mkdir -p data/val1
echo -n 1111111111111111111111111111111111111111111111111111111111111111 > data/val1/node.key
chmod 600 data/val1/node.key

# Validator 2
mkdir -p data/val2
echo -n 2222222222222222222222222222222222222222222222222222222222222222 > data/val2/node.key
chmod 600 data/val2/node.key

# Validator 3 ... same pattern
```

`node.key` accepts either raw 32 bytes or 64 hex chars. **Never commit
`node.key`.**

---

## 4. Start the cluster (peering via `--bootnodes`)

Each node has a base port (`--port`, default `9002`): libp2p listens on base
port + 100 (every peer conversation, consensus and sync, runs over it), and the
RPC/API port is auto-derived as `port - 1000` (or set with `--rpc-port`). Point every node at
the **same** `genesis.json` (place it in the working directory or set
`AINCORE_GENESIS_PATH`).

Nodes discover each other with `--bootnodes`, a comma-separated list of
*other* nodes' addresses, each given by its **base** port (the node dials base
port + 100):

```
/ip4/<host>/tcp/<base_port>      or      /dns4/<hostname>/tcp/<base_port>
```

For a three-node rehearsal on one host, use the rehearsal genesis generated above. Each process takes its chain ID from that file and dials the two other nodes:

```bash
# Terminal 1 — validator 1 (P2P 9001, RPC 8001)
AINCORE_GENESIS_PATH=$PWD/genesis.json \
./target/release/node --datadir data/val1 --port 9001 \
  --bootnodes /ip4/127.0.0.1/tcp/9002,/ip4/127.0.0.1/tcp/9003

# Terminal 2 — validator 2 (P2P 9002, RPC 8002)
AINCORE_GENESIS_PATH=$PWD/genesis.json \
./target/release/node --datadir data/val2 --port 9002 \
  --bootnodes /ip4/127.0.0.1/tcp/9001,/ip4/127.0.0.1/tcp/9003

# Terminal 3 — validator 3 (P2P 9003, RPC 8003)
AINCORE_GENESIS_PATH=$PWD/genesis.json \
./target/release/node --datadir data/val3 --port 9003 \
  --bootnodes /ip4/127.0.0.1/tcp/9001,/ip4/127.0.0.1/tcp/9002
```

Across separate machines, use each host's reachable IP/DNS in the multiaddr
(e.g. `/ip4/10.0.0.12/tcp/9001`) and open TCP base port + 100 (here 9101)
between hosts.

> `--peers` (the legacy TCP channel) was removed in G4 S6: a node given
> `--peers` refuses to start and names `--bootnodes` instead.

---

## 5. Verify the cluster agrees

On first boot each node initializes genesis from the shared `genesis.json` and
writes the same `sys:validator_set:v1` (all N validators with their embedded BLS
keys). Confirm:

1. **Same validator set everywhere.** Each node logs
   `🔐 sys:validator_set:v1 written: N validator(s)` with the full N. The
   genesis identity hash logged at boot (`🧬 Genesis identity hash: …`) must be
   identical across all nodes — different hashes mean a different `genesis.json`
   or datadir.
2. **(Optional) Pin the genesis hash.** Once you have the identity hash from a
   trusted node, set `AINCORE_EXPECTED_GENESIS_HASH=<hash>` on every node so a
   node booting the wrong chain refuses to start.
3. **Liveness.** Block height advances on all nodes and QCs verify (a QC
   produced by one node's signature aggregates and verifies against the shared
   validator-set hash). With > 2/3 of stake online, finality progresses.

If a node is treated as an observer (cannot mine), its `node.key`-derived
address is not in the validator set — re-check that its `node.key` seed matches
the seed used for it in step 2.

---

## How it stays correct (anti-drift)

The tool derives each field through the *same* public APIs a running node uses,
so values can never silently drift:

| genesis field    | derivation (tool == node)                                              |
|------------------|------------------------------------------------------------------------|
| `public_key`     | `SigningKey::from_bytes(seed).verifying_key()`                         |
| `address`        | `crypto::derive_address(public_key)` (full 32-byte, #35)               |
| `bls_public_key` | `BLSEngine::consensus().pubkey_raw(derive_validator_bls_seed(seed))`   |
| `bls_pop`        | `BLSEngine::consensus().prove_possession_raw(derive_validator_bls_seed(seed))` |

`derive_validator_bls_seed` is re-exported from `consensus::qc`, the exact
function the QC producer and genesis loader use, and the genesis-tool tests
assert the generated `genesis.json` loads and that two validators compute an
identical `validator_set_hash`.
