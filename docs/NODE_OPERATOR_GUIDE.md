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
git clone https://github.com/aincore/AINCORE-Blockchain.git
cd AINCORE-Blockchain

# Build release
cargo build --workspace --release

# Install binaries
sudo cp target/release/node /usr/local/bin/aincore-node
sudo cp target/release/cli /usr/local/bin/aincore-cli
```

### Using Docker

```bash
# Pull image
docker pull aincore/node:latest

# Run node
docker run -d \
  --name aincore-node \
  -p 9000:9000 \
  -p 8001:8001 \
  -v /data/aincore:/data \
  aincore/node:latest \
  --port 9000 --api-port 8001 --datadir /data
```

---

## Configuration

### Generate Node Key (REQUIRED)

```bash
# Create data directory
mkdir -p /data/aincore

# Generate secure node key
openssl rand 32 > /data/aincore/node.key

# Secure the key
chmod 600 /data/aincore/node.key
```

### Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `--port` | 9000 | P2P listening port |
| `--api-port` | 8001 | JSON-RPC API port |
| `--datadir` | ./data | Data directory |
| `--bootnodes` | - | Comma-separated bootnode addresses |
| `--enable-mdns` | true | Enable local peer discovery |
| `--enable-nat` | true | Enable NAT traversal |

### Bootnode Addresses

**Mainnet:**
```
/dns4/node1.aincore.io/tcp/9000
/dns4/node2.aincore.io/tcp/9000
/dns4/node3.aincore.io/tcp/9000
```

**Testnet:**
```
/dns4/testnet1.aincore.io/tcp/9000
/dns4/testnet2.aincore.io/tcp/9000
```

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
    --port 9000 \
    --api-port 8001 \
    --datadir /data/aincore \
    --bootnodes "/dns4/node1.aincore.io/tcp/9000"
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
# Foreground
aincore-node --port 9000 --api-port 8001 --datadir /data/aincore

# Background with logging
aincore-node --port 9000 --api-port 8001 --datadir /data/aincore \
  > /var/log/aincore/node.log 2>&1 &
```

---

## Becoming a Validator

### 1. Check Node Sync

```bash
# Must be fully synced before staking
curl -s http://localhost:8001/rpc -X POST \
  -H "Content-Type: application/json" \
  -d '{"method": "get_status", "params": []}' | jq
```

### 2. Get Your Node Address

```bash
# From logs
grep "node running" /var/log/aincore/node.log

# Or via API
curl -s http://localhost:8001/rpc -X POST \
  -d '{"method": "get_node_info", "params": []}' | jq -r '.node_id'
```

### 3. Stake Tokens

Minimum stake: 100,000 AIN

```bash
aincore-cli stake \
  --amount 100000000000000000000000 \
  --key-file /data/aincore/node.key
```

### 4. Verify Validator Status

```bash
curl -s http://localhost:8001/rpc -X POST \
  -d '{"method": "get_validators", "params": []}' | jq
```

### 5. Bootstrap Weight (Launch Operators)

At launch the chain has no pre-mine. Part of the committee's weight is **bootstrap weight**: consensus weight with no coins, owned by nobody, assigned to launch operators in the genesis file (G5 amendment A4; `docs/research/genesis_bootstrap.md`). It earns rewards for the operator who runs it, but you cannot transfer, stake or withdraw it.

The protocol takes it away automatically, with no human decision:

- **It shrinks** as owned stake grows. At every epoch boundary the total is cut to `s_min − owned stake`, pro rata. It never grows back.
- **It is forfeited for good** if your validator is jailed, is convicted of equivocation, leaves the validator set, or takes **3 strikes**.
- **A strike** is an epoch in which you led fewer than a third of the blocks your weight entitles you to. Leader election is stake-weighted, so an online validator leads in proportion to its weight. If you are expected to lead fewer than 9 blocks in an epoch, that epoch is not judged. A judged epoch at a third or more of your expectation clears your strikes.

Check it with:

```bash
curl -s -X POST http://127.0.0.1:8002/rpc -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"aincore_getBootstrap","params":[]}'
```

It returns `s_min_ain`, `bootstrap_ain`, `owned_stake_ain`, `target_ain`, and each operator's `weight` and `strikes`.

---

## Monitoring

### Prometheus Metrics

Enable metrics endpoint:
```bash
aincore-node --metrics-port 9090
```

Metrics available at `http://localhost:9090/metrics`

### Key Metrics

| Metric | Description |
|--------|-------------|
| `aincore_block_height` | Current block height |
| `aincore_peer_count` | Connected peers |
| `aincore_mempool_size` | Pending transactions |
| `aincore_consensus_round` | Current consensus round |
| `aincore_tx_per_second` | Transaction throughput |

### Grafana Dashboard

Import dashboard ID: `AINCORE-NODE-DASHBOARD`

### Health Check Script

```bash
#!/bin/bash
# healthcheck.sh

STATUS=$(curl -s http://localhost:8001/rpc -X POST \
  -H "Content-Type: application/json" \
  -d '{"method": "get_status", "params": []}')

HEIGHT=$(echo $STATUS | jq -r '.height')
PEERS=$(echo $STATUS | jq -r '.peers')

if [ "$PEERS" -lt 2 ]; then
  echo "❌ Low peer count: $PEERS"
  exit 1
fi

echo "✅ Node healthy - Height: $HEIGHT, Peers: $PEERS"
```

---

## Maintenance

### Backup

```bash
# Stop node first
sudo systemctl stop aincore

# Backup data
tar -czvf aincore-backup-$(date +%Y%m%d).tar.gz /data/aincore

# Restart
sudo systemctl start aincore
```

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
# Optional: Prune old data (keeps last 1000 blocks)
aincore-cli prune --keep-blocks 1000 --datadir /data/aincore
```

---

## Troubleshooting

### Node Won't Start

```bash
# Check if port is in use
lsof -i :9000

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
sudo ufw allow 9000/tcp
sudo ufw allow 8001/tcp

# Check NAT
curl https://api.ipify.org
```

### Falling Behind

```bash
# Check peer quality
curl -s http://localhost:8001/rpc -X POST \
  -d '{"method": "get_peers", "params": []}' | jq

# Force resync
aincore-node --resync --datadir /data/aincore
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

# Backup corrupted data
mv /data/aincore /data/aincore.bak

# Fresh sync
mkdir -p /data/aincore
cp /data/aincore.bak/node.key /data/aincore/

# Start node (will resync)
sudo systemctl start aincore
```

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

- Discord: #node-operators
- Telegram: @aincore_ops
- Email: validators@aincore.io
