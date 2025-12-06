# AINCORE - Panduan Deploy ke Komputer/Server Lain

**Status:** ✅ SIAP UNTUK DEPLOYMENT MULTI-NODE

---

## 🎯 CARA DEPLOY KE KOMPUTER LAIN

### Opsi 1: Deploy via GitHub (RECOMMENDED)

#### Di Komputer/Server Baru:

```bash
# 1. Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 2. Install dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev git

# Atau untuk macOS:
# brew install openssl pkg-config

# 3. Clone repository
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain

# 4. Build release
cargo build --release --bin node --bin aincore-cli

# 5. Jalankan node
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1
```

**DONE! Node sudah berjalan di komputer baru!** ✅

---

### Opsi 2: Deploy Binary Langsung (FASTER)

#### Di Komputer Anda (Build):
```bash
cd AINCORE-Blockchain
cargo build --release --bin node --bin aincore-cli

# Binary ada di:
# - target/release/node
# - target/release/aincore-cli
```

#### Transfer ke Server Lain:
```bash
# Via SCP
scp target/release/node user@server-ip:/home/user/aincore-node
scp target/release/aincore-cli user@server-ip:/home/user/aincore-cli

# Atau via rsync
rsync -avz target/release/node user@server-ip:/home/user/
```

#### Di Server Baru:
```bash
chmod +x aincore-node aincore-cli
./aincore-node --port 9000 --rpc-port 8000 --datadir data
```

---

## 🌐 SETUP CLUSTER MULTI-NODE

### Scenario: 4 Validator Nodes di 4 Komputer Berbeda

#### Node 1 (Genesis/Bootnode) - IP: 192.168.1.100
```bash
./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data_node1
```

**Catat Node ID dari log:**
```
🚀 AINCORE node 8f7d00f56518177823e32849fa9e5f83 running on port 9000
```

#### Node 2 - IP: 192.168.1.101
```bash
./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data_node2 \
  --bootnodes /ip4/192.168.1.100/tcp/9000
```

#### Node 3 - IP: 192.168.1.102
```bash
./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data_node3 \
  --bootnodes /ip4/192.168.1.100/tcp/9000
```

#### Node 4 - IP: 192.168.1.103
```bash
./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data_node4 \
  --bootnodes /ip4/192.168.1.100/tcp/9000
```

---

## 🔧 VERIFIKASI KONEKSI

### Cek Peer Count (di setiap node):
```bash
curl http://localhost:8000 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getPeers","params":[],"id":1}'

# Expected: {"result": [3 peers]} untuk 4-node cluster
```

### Cek Block Height (harus sama di semua node):
```bash
curl http://localhost:8000 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getBlockHeight","params":[],"id":1}'
```

### Cek Validator Set:
```bash
curl http://localhost:8000 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getValidators","params":[],"id":1}'
```

---

## 🌍 DEPLOY KE CLOUD (AWS/GCP/Azure)

### AWS EC2 Example:

```bash
# 1. Launch EC2 instance (Ubuntu 22.04, t3.medium)

# 2. SSH ke instance
ssh -i your-key.pem ubuntu@ec2-xx-xx-xx-xx.compute.amazonaws.com

# 3. Install dependencies
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev git
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 4. Clone & build
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
cargo build --release --bin node

# 5. Open firewall
sudo ufw allow 9000/tcp  # P2P
sudo ufw allow 8000/tcp  # RPC (only from trusted IPs!)

# 6. Run node
./target/release/node --port 9000 --rpc-port 8000 --datadir data
```

### Systemd Service (Auto-restart):
```bash
sudo tee /etc/systemd/system/aincore.service > /dev/null <<EOF
[Unit]
Description=AINCORE Blockchain Node
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/AINCORE-Blockchain
ExecStart=/home/ubuntu/AINCORE-Blockchain/target/release/node --port 9000 --rpc-port 8000 --datadir /var/lib/aincore
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable aincore
sudo systemctl start aincore
sudo systemctl status aincore
```

---

## 🔒 SECURITY CHECKLIST

### Firewall Rules:
```bash
# Allow P2P from anywhere
sudo ufw allow 9000/tcp

# Allow RPC ONLY from specific IPs
sudo ufw allow from 192.168.1.0/24 to any port 8000

# Enable firewall
sudo ufw enable
```

### SSH Hardening:
```bash
# Disable password auth
sudo sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

### Backup Node Identity:
```bash
# CRITICAL: Backup this file!
cp data_node1/node_identity.key ~/aincore_backup_$(date +%Y%m%d).key

# Encrypt it
gpg -c ~/aincore_backup_*.key

# Store in 3 locations:
# 1. Encrypted cloud storage
# 2. USB drive (offline)
# 3. Paper backup (QR code)
```

---

## 📊 MONITORING

### Check Node Health:
```bash
# CPU/Memory usage
htop

# Disk usage
df -h

# Node logs
journalctl -u aincore -f

# Block production rate
watch -n 1 'curl -s http://localhost:8000 -X POST -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"aincore_getBlockHeight\",\"params\":[],\"id\":1}"'
```

---

## 🎯 QUICK START COMMANDS

### Single Node (Testing):
```bash
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
cargo build --release --bin node
./target/release/node --port 9000 --rpc-port 8000 --datadir data
```

### Multi-Node Cluster (Production):
```bash
# Node 1 (Bootnode)
./target/release/node --port 9000 --rpc-port 8000 --datadir data1

# Node 2-4 (Connect to bootnode)
./target/release/node --port 9000 --rpc-port 8000 --datadir data2 \
  --bootnodes /ip4/<BOOTNODE_IP>/tcp/9000
```

---

## ✅ SYSTEM REQUIREMENTS

### Minimum (Testnet):
- CPU: 2 cores
- RAM: 4 GB
- Storage: 50 GB SSD
- Network: 10 Mbps

### Recommended (Production):
- CPU: 4+ cores
- RAM: 16 GB
- Storage: 500 GB NVMe SSD
- Network: 100 Mbps with static IP

### Supported OS:
- ✅ Ubuntu 22.04 LTS (recommended)
- ✅ macOS 13+
- ✅ Debian 11+
- ✅ CentOS 8+

---

## 🚀 DEPLOYMENT CHECKLIST

- [ ] Rust installed (1.70+)
- [ ] Dependencies installed (build-essential, libssl-dev)
- [ ] Repository cloned
- [ ] Binary built (`cargo build --release`)
- [ ] Firewall configured (port 9000, 8000)
- [ ] Node identity backed up
- [ ] Systemd service configured (optional)
- [ ] Monitoring setup (optional)
- [ ] Connected to bootnode (for multi-node)
- [ ] Verified peer count (should be > 0)
- [ ] Verified block sync (height increasing)

---

**Status:** ✅ **READY FOR MULTI-COMPUTER DEPLOYMENT**

**Tested On:**
- ✅ macOS (local development)
- ✅ Ubuntu 22.04 (production)
- ✅ AWS EC2 (cloud deployment)

**Next Steps:**
1. Deploy to 4 servers
2. Form validator cluster
3. Start mining!

🎉 **AINCORE SIAP UNTUK DEPLOYMENT GLOBAL!**
