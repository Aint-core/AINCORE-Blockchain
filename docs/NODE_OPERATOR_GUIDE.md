# Node Operator Guide

> **Complete guide to running and maintaining AINCORE validator nodes**

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running a Node](#running-a-node)
5. [Becoming a Validator](#becoming-a-validator)
6. [Monitoring](#monitoring)
7. [Maintenance](#maintenance)
8. [Troubleshooting](#troubleshooting)

---

## Requirements

### Hardware (Minimum)

| Component | Requirement |
|-----------|-------------|
| CPU | 4 cores |
| RAM | 8 GB |
| SSD | 100 GB |
| Network | 100 Mbps |

### Hardware (Recommended for Validators)

| Component | Requirement |
|-----------|-------------|
| CPU | 8+ cores |
| RAM | 32 GB |
| NVMe SSD | 500 GB |
| Network | 1 Gbps |

### Software

- Ubuntu 22.04 LTS / macOS 12+
- Rust 1.70+
- RocksDB
- OpenSSL

### Time (Validators)

A block's time T is the stake-weighted median of the committee's vertex timestamps (G5
BT-1). Unbonding, commission changes and emission all count from it. Plain NTP can be shifted
by an attacker on the path, so a validator syncs from several authenticated (NTS) sources:

```bash
sudo apt install chrony   # chrony 4.0+ speaks NTS; it replaces systemd-timesyncd
sudo tee /etc/chrony/sources.d/aincore-nts.sources <<'EOF'
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server ptbtime1.ptb.de iburst nts
EOF
echo 'minsources 2' | sudo tee /etc/chrony/conf.d/aincore.conf
sudo systemctl restart chrony
chronyc -N authdata   # every source shows NTS with a non-zero KeyID
chronyc tracking      # "Leap status: Normal", offset in milliseconds
```

The node alarms when the T of the blocks it places differs from its own clock by more than
60 s for 3 blocks in a row: the log shows `[BT-1 ALARM]`, and `aincore_getStatus` returns
`clock_drift_alarm_secs` (local clock − T, in seconds; `null` while there is no alarm). An
alarm on one validator means its clock is wrong; on most validators at once, suspect the time
sources.

---

## Installation

### From Source

```bash
# Install dependencies (Ubuntu)
sudo apt update
sudo apt install -y build-essential libssl-dev librocksdb-dev pkg-config

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repository
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain

# Build release
cargo build --workspace --release

# Install binaries
sudo cp target/release/node /usr/local/bin/aincore-node
sudo cp target/release/aincore-cli /usr/local/bin/aincore-cli
```

### Using Docker

Build the image from this repository (no image is published for you to pull: one
from a registry name you cannot verify could carry a node that leaks its key):

```bash
docker build -t aincore-node .

# The container runs as uid 10001: the data directory must be writable by it.
sudo mkdir -p /data/aincore && sudo chown -R 10001 /data/aincore

# Run node (the image's command is `node`: give it in full with its flags)
docker run -d \
  --name aincore-node \
  -p 0.0.0.0:9102:9102 \
  -p 127.0.0.1:8002:8002 \
  -v /data/aincore:/data \
  aincore-node \
  node --port 9002 --datadir /data
```

---

## Configuration

### Generate Node Key (REQUIRED)

```bash
# Create data directory
mkdir -p /data/aincore

# Generate a node key (32 random bytes), owner-only from its first byte
(umask 077 && openssl rand 32 > /data/aincore/node.key)
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 9002 | Base port: libp2p listens on it + 100 (9102); bootnodes name it |
| `--rpc-port` | `--port` less 1000 (8002) | JSON-RPC API port |
| `--datadir` | ./data | Data directory (the database is `validator_{port}.db`: keep the same `--port` across restarts) |
| `--bootnodes` | - | Comma-separated bootnode addresses |
| `--enable-mdns` | off | Ignored: mDNS was removed (B209) |
| `--enable-nat` | off | Enable NAT traversal |

Any other flag is refused (B331): the node prints its usage and exits.
`--help` prints the usage.

### Bootnode Addresses

Use the bootnode addresses published with the genesis.json of the network you join
(base ports: the node dials base + 100). This guide names none: an address copied
from a page you cannot verify can point a new node at peers that cut it off from the
real network.

---

## Running a Node

### Systemd Service (Recommended)

```bash
# Create service file
sudo nano /etc/systemd/system/aincore.service
```

```ini
[Unit]
Description=AINCORE Node
After=network.target

[Service]
Type=simple
User=aincore
ExecStart=/usr/local/bin/aincore-node \
    --port 9002 \
    --datadir /data/aincore \
    --bootnodes "<the network's published bootnodes>"
Restart=always
RestartSec=10
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable aincore
sudo systemctl start aincore

# Check status
sudo systemctl status aincore

# View logs
journalctl -u aincore -f
```

### Manual Run

```bash
# Foreground (the RPC listens on 8002, the port less 1000)
aincore-node --port 9002 --datadir /data/aincore
```

Run it under systemd (above) so journald bounds its logs. Redirected to a
file, its output grows without bound unless the file is rotated
(`logrotate` with `copytruncate`): a request is logged only with
`AINCORE_LOG_RPC=1` (B306, B327), but peers and blocks still log lines.

```bash
# The node's address and status
curl -s http://localhost:8002/rpc -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}' | jq
```

---

## Becoming a Validator

### 1. Check Node Sync

```bash
# Must be fully synced before staking
curl -s http://localhost:8002/rpc -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}' | jq
```

### 2. Get Your Node Address

```bash
curl -s http://localhost:8002/rpc -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}' | jq -r '.result.node_id'
```

### 3. Stake Tokens and Join

The minimum stake is 1,000 AIN (`staking.move`, `MIN_STAKE`); `register-validator` stakes
exactly that (`join_validator_set`). Register with the node's own key file (`node.key`): the
entry it adds to the validator set names the node's address and the BLS key derived from that
file, and the node signs only under that entry. `--chain-id` must name the chain the node runs:

```bash
aincore-cli --keyfile /data/aincore/node.key --chain-id <chain id> \
  register-validator
```

**Why the timing matters (G1 RC-3, B441).** A validator that joins after launch has no signing
history in its database (no guard origin is written at a first key use), so before it signs it
must show that a block was made after its node booted. While its key is in the live validator
set (`sys:validator_set:v1`, what `/get_validators` lists), the node sends about once a minute a
*proof of boot*: a transfer of a random amount from its account to itself. When it sees a
block that holds one, the node notes N, the height it holds then (step 4). Say the join lands
in epoch E, whose boundary block is H_E. The committee of E+1 is taken from the live set at
H_E, so E+1 is the node's first epoch as a member:

- N below H_E: the activation of E+1 lets the node sign.
- N at or above H_E (a join late in E, or a restart, step 1): the node abstains for its whole
  first member epoch, and signs from the activation after the first boundary above N. In that
  epoch it makes no vertices and takes no leader slots, so it earns no leader bonus (its
  stake-weighted share of emission and fees is still paid), and the committee carries its stake
  without its signatures.

A join sent late in an epoch that lands only after that epoch's boundary is not late: it lands
in the next epoch, the node is first a member in the epoch after that one, and its proof has a
whole epoch to land.

The join procedure:

1. **Run the node, synced, and keep it running** from the join until it signs: from the
   activation of E+1 when N is below H_E. Every start of a node that does not sign yet clears
   the proof it has noted, so a restart before that activation, even one after H_E, throws the
   proof away. The node then sends a fresh proof, and when that one is noted at or above H_E
   (a restart late in E, or between H_E and E+1's activation), the node signs at least one
   epoch later.
2. **Fund the account with the stake plus a little AIN for gas**: the join pays gas, and so
   does the proof, at twice the base fee. `scripts/validator-join/fund-validator.sh` sends
   1,010 AIN by default, and `scripts/validator-join/join-validator.sh join` checks the
   balance. Send nothing else from the validator's account until the proof is noted: the proof
   takes the account's next sequence number. When the node cannot queue a proof, it logs
   `[RC-3] no proof-of-boot transaction this time (<reason>); the account needs a little AIN
   for its gas`. The line always ends with that hint; the reason in parentheses says what
   happened:
   - `Insufficient balance for gas`, or `no AIN balance to pay gas (no CoinStore)`: the account
     cannot pay the proof's gas. Fund it.
   - `Duplicate pending nonce`: the previous proof (or another transaction from the account at
     the same sequence number) still waits in the node's mempool for a block, and the new one
     is refused beside it. This is harmless while it waits: the node notes the proof once a
     block holds it. If the line still repeats as H_E nears, check the node's peers and sync.
   - `Mempool full`: the node's mempool is full; it tries again a minute later.
3. **Join early in an epoch.** The node must note its proof below H_E, the boundary of the
   epoch the join lands in. Epoch E holds blocks `E·I + 1` to `H_E = (E+1)·I`, where I is
   `epoch_blocks` in `aincore_getEconomics` (the next block's epoch is `⌊height / I⌋`). Join in
   the first half of an epoch: I is at least 100 blocks (`MIN_EPOCH_BLOCKS`), so that leaves at
   least 50 blocks for a proof sent once a minute. `join-validator.sh join` (in
   `scripts/validator-join/`) checks it, and refuses in an epoch's second half unless
   `AINCORE_JOIN_LATE=1`. The check reads the node's own height, but the join lands at the
   network's: a node still catching up passes it while the network is already in the epoch's
   second half, or in a later epoch. Set `AINCORE_REFERENCE_RPC` to the JSON-RPC URL of another
   node of the network (one the network publishes, or one its operator opens to you: a node's
   RPC listens on 127.0.0.1 unless `AINCORE_RPC_BIND` says otherwise): `join` then refuses
   while the node trails that node by more than 3 blocks, and counts from the higher of the two
   heights. Without it, `join` warns and assumes the node is at the network's tip.
   A join that aborts with `ECHURN_LIMIT` (abort code 589836, `0x9000C`: staking.move's
   reason 12 in the RESOURCE_EXHAUSTED category) met this epoch's allowance of new stake
   (G5 CH-1: 10 % of the committee's stake an epoch): join early in the next epoch.
4. **Watch for the proof.** When a block holds it, the node logs
   `[RC-3] a block after this boot holds a proof transaction: signing resumes at the first
   boundary above height N`. The node signs from the activation that follows the first
   boundary block above N: from its first member epoch on when N is below H_E, the boundary of
   the epoch the join landed in, and from a later epoch otherwise.

A node whose key is in no live set (an RPC node) sends no proof.

### 4. Verify Validator Status

```bash
curl -s http://localhost:8002/get_validators | jq
```

The list is the live set: your address there means the join landed. The node becomes a member
at the activation that follows H_E, the boundary of the epoch the join landed in, and signs
from then on if the height N its `[RC-3]` line names is below H_E (step 4 above).

### 5. Bootstrap Weight (Launch Operators)

At launch the chain has no pre-mine. Part of the committee's weight is **bootstrap weight**: consensus weight with no coins, owned by nobody, assigned to launch operators in the genesis file (G5 amendment A4; `docs/research/genesis_bootstrap.md`). It earns rewards for the operator who runs it, but you cannot transfer, stake or withdraw it.

The protocol adjusts it automatically, with no human decision:

- **It fills the committee to `s_min`.** At every epoch boundary the operators' weights are
  set to `s_min − owned stake`, pro rata to each operator's genesis weight (its ceiling): they
  shrink as owned stake grows and regrow, never above the ceiling, if owned stake leaves. A
  forfeited operator's share goes to nobody. Once owned stake has held `s_min` for 21 days,
  bootstrap weight ends for good.
- **No party reaches a third.** If forfeits would leave a party (a validator, or the
  validators declared as one entity, such as the founder's) at a third or more of the
  committee, its bootstrap weight is cut below that, every boundary, as long as needed.
  Rewards are paid against at least `s_min`, so nobody earns more from a cut or a forfeit.
- **It is forfeited for good** if your validator is jailed (an accepted equivocation jails at
  once), is convicted in full, leaves the validator set (at the leave transaction itself), or
  its participation score falls below one half. A full validator set never displaces an
  operator that holds bootstrap weight.
- **The score** measures the leader slots the schedule gave you that became blocks. Leader
  election is stake-weighted and public, so the chain knows exactly which rounds were yours;
  an offline validator's rounds are skipped. The score is a moving average with a half-life of
  about 7 days, and healthy validators commit about 90 % of their slots. A validator that goes
  dark loses its bootstrap weight after about 6 days; each dark epoch (about 1.9 hours)
  costs under 1 % of score, which comes back as it runs again.

Check it with:

```bash
curl -s -X POST http://127.0.0.1:8002/rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getBootstrap","params":[]}'
```

It returns `s_min_ain`, `bootstrap_ain`, `ceiling_ain`, `owned_stake_ain`, `target_ain`, and each operator's `ceiling`, `weight` and `score` (parts per million).

---

## Monitoring

### Prometheus Metrics

The node serves Prometheus metrics at `/metrics` on its RPC port (8002 by
default; the node takes no separate metrics flag):

```bash
curl -s http://localhost:8002/metrics
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `aincore_block_height` | Current block height |
| `aincore_transaction_count` | Transactions processed since the node started |
| `aincore_peer_count` | Connected peers |

### Health Check Script

```bash
#!/bin/bash
# healthcheck.sh

STATUS=$(curl -s http://localhost:8002/rpc -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getStatus","params":[]}')

HEIGHT=$(echo $STATUS | jq -r '.result.latest_height')
PEERS=$(echo $STATUS | jq -r '.result.peers_count')

if [ "$PEERS" -lt 2 ]; then
  echo "❌ Low peer count: $PEERS"
  exit 1
fi

echo "✅ Node healthy - Height: $HEIGHT, Peers: $PEERS"
```

---

## Maintenance

A validator that has joined but does not sign yet should keep its node running until it signs:
every start before then clears its noted proof of boot ("Stake Tokens and Join", step 1). That
holds for every stop and start in this section (an update restarts the node; a key backup needs
no stop) and under Troubleshooting.

### Backup

**A validator never restores its database from a backup.** A restored
database carries the node's own signing guards and its signing history marker
(`consensus:guard_origin`) as they were when the backup was taken. The key
still matches the marker, so the node counts its guards as continuous, does
not abstain, and can sign again rounds it already signed after the backup was
taken: that is equivocation (G1 SA-4, B459). The validator is jailed for good
and slashed with its delegators: G5 SL-4 takes 9·(Q/T)² of the stake, where Q
is the weight that equivocated within a day and T the committee's, at least
1 % and all of it from a third. RC-3 protects an empty data directory, not a
restored one. Back up only `node.key`, kept offline and encrypted. To recover
a validator, start from an empty data directory with its `node.key` and let
it sync, as under "Database Corruption" below: it abstains until its proof of
boot lands (RC-3), then signs again. `docs/DR_RUNBOOK.md` §4 gives the steps.

```bash
# Back up the key only (offline, encrypted storage)
sudo cp /data/aincore/node.key /secure/offline/location/node.key
```

A database backup is only for a node that is not a validator (an RPC or
observer node). `scripts/backup_node.sh` and `scripts/restore_node.sh` refuse
to run without `--not-a-validator`, never put a `node.key` in an archive or a
restored data directory, and the restored node runs a new key (B467). Never
copy a validator's `node.key` into a restored data directory.

### Update Node

```bash
# Stop node
sudo systemctl stop aincore

# Pull latest code
cd AINCORE-Blockchain
git pull origin main

# Rebuild
cargo build --workspace --release

# Copy new binary
sudo cp target/release/node /usr/local/bin/aincore-node

# Restart
sudo systemctl start aincore
```

### Prune Database

```bash
# Block history is pruned by the node itself: AINCORE_STORAGE_MODE=full (the
# default) keeps AINCORE_BLOCK_RETENTION blocks (100,000), observer keeps 1,000,
# archive keeps all. A value the node cannot read stops it at boot (B349).
```

---

## Troubleshooting

### Node Won't Start

```bash
# Check if port is in use
lsof -i :9002

# Check key file
ls -la /data/aincore/node.key

# Check logs
journalctl -u aincore --no-pager | tail -100
```

### No Peers

```bash
# Check firewall
sudo ufw status

# Allow ports
sudo ufw allow 9102/tcp   # libp2p listens on the base port + 100

# Check NAT
curl https://api.ipify.org
```

### Falling Behind

```bash
# Check peer quality
curl -s http://localhost:8002/rpc -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getPeers","params":[]}' | jq
```

### High Memory Usage

```bash
# Limit RocksDB cache
export ROCKSDB_MAX_CACHE_SIZE=1073741824  # 1GB

# Restart node
sudo systemctl restart aincore
```

### Database Corruption

```bash
# Stop node
sudo systemctl stop aincore

# Set the corrupted data aside
mv /data/aincore /data/aincore.bak

# Fresh sync: an empty data directory, the key moved (not copied) into it
mkdir -p /data/aincore
mv /data/aincore.bak/node.key /data/aincore/

# Start node (will resync)
sudo systemctl start aincore
```

Never start a node on `/data/aincore.bak` again, and never move it back under the key: once
the new data directory has run, the old database's guards are older than what the key has
signed, which makes it a restored database (Backup above). The key is moved so that no copy of
it stays beside the old database. Start the node without `AINCORE_GUARD_ORIGIN_INIT` in its
environment: up to one hour after the network's `genesis_time` it lets an empty database count
its guards as continuous (`docs/DR_RUNBOOK.md` §4).

---

## Security Best Practices

1. **Secure node key** - Never share, backup securely
2. **Firewall** - Only expose necessary ports
3. **Updates** - Keep software updated
4. **Monitoring** - Set up alerts for anomalies
5. **Separate accounts** - Don't run as root
6. **SSH hardening** - Use keys, disable password auth

---

## Support

Report problems on the project's repository:
https://github.com/Aint-core/AINCORE-Blockchain/issues
