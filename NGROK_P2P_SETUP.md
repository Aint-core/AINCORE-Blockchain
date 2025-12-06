# AINCORE - Ngrok P2P Setup Guide

## 🌐 NGROK INFO (Komputer 1):
```
URL: tcp://0.tcp.ap.ngrok.io:10522
Forward: localhost:9000
```

---

## 🚀 CARA SETUP DENGAN NGROK:

### Di Mac Mini (Komputer 2):

**STOP node dulu (Ctrl+C)**

**Lalu jalankan dengan Ngrok bootnode:**
```bash
./target/release/node \
  --port 9001 \
  --rpc-port 8001 \
  --datadir data_node2 \
  --bootnodes /dns4/0.tcp.ap.ngrok.io/tcp/10522
```

**PENTING:** Pakai `/dns4/` bukan `/ip4/` untuk domain!

---

## ✅ EXPECTED OUTPUT (Sukses):

```
🔗 Adding bootnode: /dns4/0.tcp.ap.ngrok.io/tcp/10522
✅ Connected to peer via Ngrok!
📥 Syncing blocks from peer...
📦 Synced block #1
📦 Synced block #2
...
📦 Synced block #300+
✅ Sync complete!
🔒 [Consensus] Round XXX: Validators=2, BFT_Quorum=2
```

**Validators=2 = CONNECTED via Ngrok!** ✅

---

## 📊 VERIFICATION:

**Di Komputer 1 (MacBook Pro):**
```bash
# Cek Ngrok dashboard
curl http://127.0.0.1:4040/api/tunnels

# Atau buka browser:
http://127.0.0.1:4040
```

**Di Komputer 2 (Mac Mini):**
```bash
# Cek log untuk "Connected to peer"
# Cek Validators=2
```

---

## 🎯 TROUBLESHOOTING:

### Jika masih "No peers available":

1. **Cek Ngrok masih running:**
   ```bash
   # Di Komputer 1
   curl http://127.0.0.1:4040/api/tunnels
   ```

2. **Restart Ngrok:**
   ```bash
   ngrok tcp 9000
   ```

3. **Update bootnode dengan URL baru:**
   ```bash
   # Catat URL baru dari Ngrok
   # Update command di Komputer 2
   ```

---

**JALANKAN SEKARANG!** 🚀
