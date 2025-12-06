# AINCORE - Cara Jalanin di Komputer Lain (SUPER SIMPLE!)

## 🎯 CARA PALING MUDAH (Copy-Paste Aja!)

### KOMPUTER 1 (Yang Sekarang - Sudah Running)

**Cek IP Address Komputer Anda:**
```bash
# macOS:
ifconfig | grep "inet " | grep -v 127.0.0.1

# Linux:
ip addr show | grep "inet " | grep -v 127.0.0.1

# Windows:
ipconfig
```

**Contoh output:**
```
inet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
```
**IP Anda: 192.168.1.100** ← Catat ini!

**Jalankan Node:**
```bash
cd AINCORE-Blockchain
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1
```

**Catat Node ID dari log:**
```
🚀 AINCORE node 8f7d00f56518177823e32849fa9e5f83 running on port 9000
```

---

### KOMPUTER 2 (Komputer Lain - Baru)

#### Step 1: Install Rust (5 menit)
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

#### Step 2: Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev git
```

**macOS:**
```bash
brew install openssl pkg-config
```

**Windows (WSL):**
```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev git
```

#### Step 3: Clone Repository
```bash
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
```

#### Step 4: Build (10-15 menit)
```bash
cargo build --release --bin node
```

#### Step 5: Jalankan Node (Connect ke Komputer 1)
```bash
./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data_node2 \
  --bootnodes /ip4/192.168.1.100/tcp/9000
```

**Ganti `192.168.1.100` dengan IP Komputer 1 Anda!**

---

## ✅ VERIFIKASI - Cek Apakah Sudah Connect

### Di Komputer 1 atau 2:
```bash
curl http://localhost:8000 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getPeers","params":[],"id":1}'
```

**Expected Output:**
```json
{"jsonrpc":"2.0","result":[1],"id":1}
```
**Artinya: Sudah connect ke 1 peer!** ✅

### Cek Block Height (Harus Sama):
```bash
curl http://localhost:8000 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getBlockHeight","params":[],"id":1}'
```

**Di Komputer 1:**
```json
{"jsonrpc":"2.0","result":100,"id":1}
```

**Di Komputer 2 (setelah sync):**
```json
{"jsonrpc":"2.0","result":100,"id":1}
```

**Sama = SUKSES!** ✅

---

## 🚀 CARA SUPER CEPAT (Jika Sudah Ada Binary)

### Komputer 1: Build & Share Binary
```bash
cd AINCORE-Blockchain
cargo build --release --bin node

# Compress binary
tar -czf aincore-node.tar.gz target/release/node
```

### Transfer ke Komputer 2:
```bash
# Via USB
cp aincore-node.tar.gz /path/to/usb/

# Atau via SCP (jika ada network)
scp aincore-node.tar.gz user@192.168.1.101:/home/user/
```

### Komputer 2: Extract & Run
```bash
tar -xzf aincore-node.tar.gz
chmod +x target/release/node

./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data \
  --bootnodes /ip4/192.168.1.100/tcp/9000
```

**DONE! Tidak perlu build lagi!** ⚡

---

## 📱 CONTOH REAL: 2 Laptop di Rumah

### Laptop 1 (MacBook - WiFi: 192.168.1.100)
```bash
cd AINCORE-Blockchain
./target/release/node --port 9000 --rpc-port 8000 --datadir data1
```

### Laptop 2 (Windows WSL - WiFi: 192.168.1.101)
```bash
# Di WSL Ubuntu:
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
cargo build --release --bin node

./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data2 \
  --bootnodes /ip4/192.168.1.100/tcp/9000
```

**Tunggu 1-2 menit untuk sync, DONE!** ✅

---

## 🌐 CONTOH: 2 Server di Cloud (AWS/GCP)

### Server 1 (AWS EC2 - Public IP: 54.123.45.67)
```bash
# SSH ke server
ssh -i key.pem ubuntu@54.123.45.67

# Install & run
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
./QUICK_DEPLOY.sh

./target/release/node --port 9000 --rpc-port 8000 --datadir data1
```

### Server 2 (GCP Compute - Public IP: 35.234.56.78)
```bash
# SSH ke server
ssh user@35.234.56.78

# Install & run
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
./QUICK_DEPLOY.sh

./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data2 \
  --bootnodes /ip4/54.123.45.67/tcp/9000
```

**DONE! Blockchain global!** 🌍

---

## 🔥 TROUBLESHOOTING

### Problem 1: "Connection refused"
```bash
# Cek firewall di Komputer 1:
sudo ufw allow 9000/tcp
sudo ufw allow 8000/tcp

# Atau disable firewall sementara (testing):
sudo ufw disable
```

### Problem 2: "Cannot find bootnode"
```bash
# Pastikan IP benar:
ping 192.168.1.100

# Pastikan port 9000 terbuka:
telnet 192.168.1.100 9000
```

### Problem 3: "Build failed"
```bash
# Update Rust:
rustup update

# Install ulang dependencies:
sudo apt install -y build-essential pkg-config libssl-dev
```

### Problem 4: "Sync lambat"
```bash
# Normal! Tunggu saja
# Cek progress:
curl http://localhost:8000 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getBlockHeight","params":[],"id":1}'

# Block height akan naik terus sampai sama dengan node lain
```

---

## 📋 CHECKLIST LENGKAP

### Komputer 1 (Bootnode):
- [ ] Node sudah running
- [ ] Catat IP address (misal: 192.168.1.100)
- [ ] Catat Node ID dari log
- [ ] Port 9000 terbuka (firewall)
- [ ] Port 8000 terbuka (RPC)

### Komputer 2 (New Node):
- [ ] Rust installed
- [ ] Dependencies installed
- [ ] Repository cloned
- [ ] Binary built (`cargo build --release`)
- [ ] IP Komputer 1 sudah dicatat
- [ ] Command sudah benar (ganti IP!)
- [ ] Node running
- [ ] Cek peer count (harus > 0)
- [ ] Cek block height (sync progress)

---

## 🎯 COMMAND LENGKAP (Copy-Paste!)

### Komputer 1:
```bash
cd AINCORE-Blockchain
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1
```

### Komputer 2:
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install dependencies (Ubuntu)
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev git

# Clone & build
git clone https://github.com/Aint-core/AINCORE-Blockchain.git
cd AINCORE-Blockchain
cargo build --release --bin node

# Run (GANTI IP!)
./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data_node2 \
  --bootnodes /ip4/192.168.1.100/tcp/9000
```

**GANTI `192.168.1.100` dengan IP Komputer 1 Anda!**

---

## ✅ SUKSES JIKA:

1. **Komputer 2 menampilkan:**
```
🔗 Connected to peer: /ip4/192.168.1.100/tcp/9000
📥 Syncing blocks...
🔒 [Consensus] Round 1: Validators=2, BFT_Quorum=2, Parents=1
```

2. **Peer count = 1:**
```bash
curl http://localhost:8000 -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"aincore_getPeers","params":[],"id":1}'
# Output: {"result":[1]}
```

3. **Block height sama:**
```bash
# Komputer 1: {"result":100}
# Komputer 2: {"result":100} ← SAMA!
```

---

**SELAMAT! BLOCKCHAIN MULTI-NODE SUDAH JALAN!** 🎉🚀

**Butuh bantuan? Tanya aja!** 💬
