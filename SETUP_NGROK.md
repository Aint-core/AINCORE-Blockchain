# AINCORE - Setup Ngrok untuk P2P Connection

## 🌐 CARA PAKAI NGROK (SOLUSI TERBAIK!)

Ngrok akan expose port 9000 ke internet, jadi Komputer 2 bisa connect dari mana saja!

---

## 📋 STEP-BY-STEP:

### 1️⃣ Install Ngrok (Di MacBook Pro - Komputer 1)

```bash
# Install via Homebrew
brew install ngrok/ngrok/ngrok

# Atau download manual dari https://ngrok.com/download
```

### 2️⃣ Signup & Get Auth Token

1. Buka https://dashboard.ngrok.com/signup
2. Login
3. Copy auth token
4. Setup:
```bash
ngrok config add-authtoken YOUR_AUTH_TOKEN_HERE
```

### 3️⃣ Start Ngrok Tunnel (Komputer 1)

```bash
# Expose port 9000 (P2P port)
ngrok tcp 9000
```

**Output akan seperti ini:**
```
Session Status                online
Account                       your@email.com
Version                       3.x.x
Region                        Asia Pacific (ap)
Latency                       -
Web Interface                 http://127.0.0.1:4040
Forwarding                    tcp://0.tcp.ap.ngrok.io:12345 -> localhost:9000

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```

**CATAT URL INI:** `tcp://0.tcp.ap.ngrok.io:12345`

### 4️⃣ Start Node di Komputer 1

**Di terminal BARU (jangan close Ngrok):**
```bash
cd AINCORE-Blockchain
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1
```

### 5️⃣ Start Node di Komputer 2 (Mac Mini)

```bash
cd AINCORE-Blockchain

# Gunakan Ngrok URL (ganti dengan URL Anda!)
./target/release/node \
  --port 9001 \
  --rpc-port 8001 \
  --datadir data_node2 \
  --bootnodes /dns4/0.tcp.ap.ngrok.io/tcp/12345
```

**GANTI:**
- `0.tcp.ap.ngrok.io` → Ngrok hostname Anda
- `12345` → Ngrok port Anda

---

## ✅ VERIFIKASI CONNECTION

**Jika SUKSES, Anda akan lihat:**

**Di Komputer 2:**
```
🔗 Adding bootnode: /dns4/0.tcp.ap.ngrok.io/tcp/12345
✅ Connected to peer!
📥 Syncing blocks from peer...
📦 Synced block #1
📦 Synced block #2
...
🔒 [Consensus] Round XXX: Validators=2, BFT_Quorum=2
```

**Di Ngrok dashboard (http://127.0.0.1:4040):**
```
HTTP Requests: 0
TCP Connections: 1  ← CONNECTED!
```

---

## 🎯 CARA MUDAH (Script Otomatis):

**Di MacBook Pro (Komputer 1):**
```bash
# Terminal 1: Start Ngrok
ngrok tcp 9000

# Terminal 2: Start Node
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1
```

**Di Mac Mini (Komputer 2):**
```bash
# Ganti dengan Ngrok URL Anda!
NGROK_HOST="0.tcp.ap.ngrok.io"
NGROK_PORT="12345"

./target/release/node \
  --port 9001 \
  --rpc-port 8001 \
  --datadir data_node2 \
  --bootnodes /dns4/$NGROK_HOST/tcp/$NGROK_PORT
```

---

## 📊 KEUNTUNGAN NGROK:

✅ **Tidak perlu firewall config**
✅ **Bisa connect dari mana saja** (bahkan beda WiFi!)
✅ **Gratis** (untuk 1 tunnel)
✅ **Mudah setup** (5 menit)
✅ **Dashboard monitoring** (http://127.0.0.1:4040)

---

## ⚠️ CATATAN PENTING:

1. **Ngrok URL berubah setiap restart** (kecuali pakai paid plan)
2. **Free tier: 1 tunnel, 40 connections/min**
3. **Latency sedikit lebih tinggi** (tapi masih OK untuk mining)

---

## 🔧 TROUBLESHOOTING:

### "ERR_NGROK_108: Session limit exceeded"
```bash
# Upgrade ke paid plan, atau
# Gunakan Ngrok alternatif: localtunnel, serveo
```

### "Connection timeout"
```bash
# Pastikan node di Komputer 1 sudah running
# Pastikan Ngrok masih aktif
# Check Ngrok dashboard: http://127.0.0.1:4040
```

---

## 🚀 QUICK START:

**Komputer 1:**
```bash
# Terminal 1
ngrok tcp 9000

# Terminal 2
./target/release/node --port 9000 --rpc-port 8000 --datadir data_node1
```

**Komputer 2:**
```bash
# Ganti NGROK_URL!
./target/release/node \
  --port 9001 \
  --rpc-port 8001 \
  --datadir data_node2 \
  --bootnodes /dns4/0.tcp.ap.ngrok.io/tcp/12345
```

---

**SELESAI! BLOCKCHAIN GLOBAL READY!** 🌍✅
