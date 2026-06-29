# Multi-Validator Cluster Bring-Up (#15)

This guide shows how to stand up an N-validator AINCORE cluster from scratch:
generate per-validator node keys, build a single shared `genesis.json` that
embeds each validator's BLS finality identity, and start the nodes so they peer
and produce quorum certificates (QCs) that verify against one another.

> **Why a tool is required.** A multi-validator genesis **cannot** self-derive
> BLS keys. Each validator's BLS finality key is derived from *its own*
> `node.key` seed (`bls_seed = SHA256("AINCORE_VALIDATOR_BLS_V1" || node.key)`),
> which only the genesis ceremony operator can collect ahead of time. If
> `genesis.json` omits the per-validator BLS keys, every booting node
> self-derives a *different* key for the same peer address, writes a divergent
> `sys:validator_set:v1`, and **no QC ever verifies across nodes** (this is
> rejected on purpose — see `node::genesis::resolve_genesis_bls_identity`,
> SEC-#5). The `genesis-tool gen-multi` subcommand closes that gap: it derives
> every validator's `address`, `public_key`, `bls_public_key`, and `bls_pop`
> from the supplied seeds and writes them into one shared `genesis.json`.

---

## 0. Prerequisites

Compile the Move stdlib bytecode and build the binaries:

```bash
cargo run -p move_compiler_tool    # produces vm_move/stdlib/bytecode/*.mv
cargo build --release -p node -p genesis-tool
```

The genesis loader needs the stdlib bytecode directory at
`vm_move/stdlib/bytecode` (default) on the machine that initializes each node's
datadir.

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

> The genesis ceremony operator needs every validator's **seed** to derive the
> embedded BLS keys. In a trust-minimized ceremony each operator can instead run
> `gen-multi` for their own validator and the coordinator concatenates the
> entries; the field derivation is fully deterministic, so the resulting
> `genesis.json` is byte-identical regardless of who runs the tool.

---

## 2. Build the shared `genesis.json`

`--validator` takes `<node_key_seed_hex>:<stake_whole_ain>` and is repeated once
per validator. Stakes are whole AIN (the tool scales them to 10^18 quanta).

```bash
./target/release/genesis-tool gen-multi \
  --validator 1111111111111111111111111111111111111111111111111111111111111111:1000000 \
  --validator 2222222222222222222222222222222222222222222222222222222222222222:2000000 \
  --validator 3333333333333333333333333333333333333333333333333333333333333333:1500000 \
  --chain-id AINCORE-MAINNET-1 \
  --treasury-reserve-ain 50000 \
  --epoch-duration 10 \
  --out genesis.json
```

This writes a `genesis.json` whose per-validator entries match exactly what the
loader expects:

```json
{
  "chain_id": "AINCORE-MAINNET-1",
  "validators": [
    {
      "address": "10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d",
      "public_key": "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
      "stake": "1000000000000000000000000",
      "bls_public_key": "aea18b00...e073374b",   // 48 bytes (MinPk)
      "bls_pop": "a7b8bb0b...e4cd7a1d"            // 96 bytes, PoP over bls_public_key
    }
    /* ... one entry per validator ... */
  ],
  "treasury_reserve": "50000000000000000000000",
  "epoch_duration": 10
}
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

Each node uses a P2P (TCP) port (`--port`, default `9001`) and an RPC/API port
(auto-derived as `port - 1000`, or set with `--rpc-port`). Point every node at
the **same** `genesis.json` (place it in the working directory or set
`AINCORE_GENESIS_PATH`).

Nodes discover each other with `--bootnodes`, a comma-separated list of libp2p
multiaddrs of *other* nodes' P2P TCP listeners. The multiaddr form is:

```
/ip4/<host>/tcp/<p2p_port>
```

Example three-node bring-up on one host (distinct ports), each pointed at the
other two as bootnodes:

```bash
# Terminal 1 — validator 1 (P2P 9001, RPC 8001)
AINCORE_GENESIS_PATH=$PWD/genesis.json \
AINCORE_CHAIN_ID=AINCORE-MAINNET-1 \
./target/release/node --datadir data/val1 --port 9001 \
  --bootnodes /ip4/127.0.0.1/tcp/9002,/ip4/127.0.0.1/tcp/9003

# Terminal 2 — validator 2 (P2P 9002, RPC 8002)
AINCORE_GENESIS_PATH=$PWD/genesis.json \
AINCORE_CHAIN_ID=AINCORE-MAINNET-1 \
./target/release/node --datadir data/val2 --port 9002 \
  --bootnodes /ip4/127.0.0.1/tcp/9001,/ip4/127.0.0.1/tcp/9003

# Terminal 3 — validator 3 (P2P 9003, RPC 8003)
AINCORE_GENESIS_PATH=$PWD/genesis.json \
AINCORE_CHAIN_ID=AINCORE-MAINNET-1 \
./target/release/node --datadir data/val3 --port 9003 \
  --bootnodes /ip4/127.0.0.1/tcp/9001,/ip4/127.0.0.1/tcp/9002
```

Across separate machines, use each host's reachable IP/DNS in the multiaddr
(e.g. `/ip4/10.0.0.12/tcp/9001`) and open the P2P TCP ports between hosts.

> `--peers <p2p_ports>` is the legacy localhost-only TCP fallback (comma-
> separated port numbers, assumed `127.0.0.1`). Prefer `--bootnodes` multiaddrs
> for anything beyond a single-host smoke test.

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
```
