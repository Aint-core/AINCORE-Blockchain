# AINCORE - Troubleshooting P2P Connection

## 🔍 MASALAH: Nodes Tidak Connect

### Gejala:
```
⚠️ [ChainSync] No peers available for sync.
```

### Penyebab Umum:

1. **Port Conflict** - Kedua node pakai port sama (9000)
2. **Firewall** - macOS block incoming connection
3. **Network Issue** - Tidak satu subnet
4. **libp2p Issue** - P2P port berbeda dengan TCP port

---

## ✅ SOLUSI STEP-BY-STEP:

### 1️⃣ STOP Semua Node Dulu

**Di Komputer 1 (MacBook Pro):**
```bash
pkill -f 'target/release/node'
```

**Di Komputer 2 (Mac Mini):**
```bash
pkill -f 'target/release/node'
# Atau Ctrl+C jika masih running di terminal
```

---

### 2️⃣ START Komputer 1 (Bootnode) dengan Port Jelas

**Di MacBook Pro:**
```bash
cd AINCORE-Blockchain

# Start dengan log verbose
./target/release/node \
  --port 9000 \
  --rpc-port 8000 \
  --datadir data_node1 \
  2>&1 | tee node1_p2p.log
```

**Tunggu sampai muncul:**
```
🌐 P2P Listening on /ip4/192.168.18.90/tcp/XXXXX
```

**Catat port P2P yang muncul!** (Bukan 9000, tapi port random seperti 62682)

---

### 3️⃣ START Komputer 2 dengan Bootnode yang BENAR

**Di Mac Mini:**
```bash
cd AINCORE-Blockchain

# Gunakan port berbeda untuk avoid conflict
./target/release/node \
  --port 9001 \
  --rpc-port 8001 \
  --datadir data_node2 \
  --bootnodes /ip4/192.168.18.90/tcp/9000
```

**Atau jika tahu P2P port dari Komputer 1:**
```bash
./target/release/node \
  --port 9001 \
  --rpc-port 8001 \
  --datadir data_node2 \
  --bootnodes /ip4/192.168.18.90/tcp/62682
```

---

### 4️⃣ VERIFIKASI Connection

**Jika SUKSES, Anda akan lihat:**

**Di Komputer 2:**
```
🔗 Adding bootnode: /ip4/192.168.18.90/tcp/9000
✅ Connected to peer!
📥 Syncing blocks from peer...
📦 Synced block #1
📦 Synced block #2
...
```

**Di Komputer 1:**
```
✅ New peer connected: 12D3KooW...
```

---

## 🔧 JIKA MASIH GAGAL:

### Test Network Connectivity:

**Di Mac Mini:**
```bash
# Test ping
ping -c 3 192.168.18.90

# Test port 9000
nc -zv 192.168.18.90 9000
```

**Jika "Connection refused":**
```bash
# Di MacBook Pro, allow firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off
# Atau
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ./target/release/node
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ./target/release/node
```

---

## 🎯 CARA PALING MUDAH: Gunakan Script

**Di MacBook Pro (Komputer 1):**
```bash
./start_node1.sh
```

**Di Mac Mini (Komputer 2):**
```bash
# Buat script
cat > start_node2.sh << 'EOF'
#!/bin/bash
IP_BOOTNODE="192.168.18.90"
./target/release/node \
  --port 9001 \
  --rpc-port 8001 \
  --datadir data_node2 \
  --bootnodes /ip4/$IP_BOOTNODE/tcp/9000
EOF

chmod +x start_node2.sh
./start_node2.sh
```

---

## 📊 EXPECTED OUTPUT (Sukses):

```
Komputer 1:
🌐 P2P Listening on /ip4/192.168.18.90/tcp/62682
🔒 [Consensus] Round 300: Validators=1, BFT_Quorum=1
✅ New peer connected!
🔒 [Consensus] Round 301: Validators=2, BFT_Quorum=2  ← PERHATIKAN INI!

Komputer 2:
🔗 Adding bootnode: /ip4/192.168.18.90/tcp/9000
✅ Connected to peer!
📥 Syncing 300 blocks...
✅ Sync complete!
🔒 [Consensus] Round 301: Validators=2, BFT_Quorum=2  ← SAMA!
```

**Validators=2 dan BFT_Quorum=2 = CONNECTED!** ✅

---

## ⚠️ CATATAN PENTING:

1. **Port berbeda untuk setiap node:**
   - Komputer 1: `--port 9000 --rpc-port 8000`
   - Komputer 2: `--port 9001 --rpc-port 8001`

2. **IP harus benar:**
   - Komputer 1: 192.168.18.90
   - Komputer 2: 192.168.18.89
   - Harus satu subnet!

3. **Firewall harus allow:**
   - Port 9000, 9001 (TCP)
   - Port 8000, 8001 (RPC)

---

**IKUTI STEP 1-4 DI ATAS DENGAN HATI-HATI!** 🚀
