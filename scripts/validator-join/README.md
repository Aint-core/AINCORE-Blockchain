# Menjadi Validator AINCORE

Dokumen ini untuk **orang di luar tim** yang mau menjalankan validator sendiri.
Masuknya **permissionless** — tidak ada whitelist, tidak ada persetujuan admin.
Syaratnya cuma tiga: stake 1000 AIN, kunci BLS yang sah, dan mesin yang bisa
menjangkau jaringan.

---

## Kenapa ini penting

Blockchain baru berarti kalau validatornya **pihak-pihak independen**. Selama
semua validator dipegang satu orang, slashing cuma menghukum diri sendiri dan
"trustless" belum berlaku. Satu validator dari luar mengubah statusnya dari
chain pribadi menjadi jaringan.

---

## Yang kamu butuhkan

| | |
|---|---|
| Mesin | Linux, 4 GB RAM, 20 GB disk (chain tumbuh ~200 MB / 60 jam) |
| Software | Rust toolchain, `curl`, `python3` |
| Jaringan | Port P2P bisa dijangkau validator lain (lihat **Jaringan** di bawah) |
| Stake | **1000 AIN** — minta ke operator jaringan |

---

## Parameter jaringan (testnet saat ini)

```
AINCORE_CHAIN_ID              AINCORE-LOCALTEST-3V
AINCORE_EXPECTED_GENESIS_HASH b0331d0e1fd1e6672205372998c30cf1985239e165d70d7abd6f377141c257af
AINCORE_BOOTNODES             /ip4/192.168.18.202/tcp/9201,/ip4/192.168.18.202/tcp/9205,/ip4/192.168.18.66/tcp/9203
```

> **`AINCORE_EXPECTED_GENESIS_HASH` bukan opsional.** Tanpa itu, genesis.json
> yang salah membuat kamu diam-diam menjalankan **chain yang berbeda** — node-mu
> jalan, terlihat sehat, dan tidak pernah benar-benar bergabung. Dengan pin ini
> node **menolak boot** kalau tidak cocok. Verifikasi nilainya lewat jalur lain
> (telepon, pesan langsung), jangan cuma dari file yang dikirim ke kamu.

Minta `genesis.json` ke operator dan simpan sebagai `genesis.json`.

---

## Langkah

```bash
export AINCORE_CHAIN_ID=AINCORE-LOCALTEST-3V
export AINCORE_EXPECTED_GENESIS_HASH=b0331d0e1fd1e6672205372998c30cf1985239e165d70d7abd6f377141c257af
export AINCORE_GENESIS_PATH=./genesis.json
export AINCORE_BOOTNODES=/ip4/192.168.18.202/tcp/9201,/ip4/192.168.18.202/tcp/9205,/ip4/192.168.18.66/tcp/9203
export AINCORE_P2P_PORT=9301          # pilih port yang bebas di mesinmu

./scripts/validator-join/join-validator.sh prepare   # build + bikin kunci, cetak alamatmu
# → kirim alamatmu ke operator, minta 1000 AIN

./scripts/validator-join/join-validator.sh start     # jalankan node, biarkan sinkron
# (di terminal lain, setelah sinkron dan dana masuk)
./scripts/validator-join/join-validator.sh join      # stake + masuk validator set
./scripts/validator-join/join-validator.sh verify    # pastikan kamu benar-benar validator
```

### Untuk operator jaringan

```bash
# dijalankan DI mesin validator (kunci tidak pernah keluar dari mesin)
AINCORE_CHAIN_ID=AINCORE-LOCALTEST-3V \
  ./scripts/validator-join/fund-validator.sh <alamat-64-hex> 1010
```

---

## Kunci: satu file, dua peran

`data-validator/node.key` adalah **identitas node sekaligus dompetmu**.

- Alamatmu = `hex(SHA256(ed25519_pubkey))` — **64 karakter hex**
- Kunci BLS untuk finality **diturunkan otomatis** dari file yang sama
  (`SHA256("AINCORE_VALIDATOR_BLS_V1" || node.key)`) — kamu tidak perlu
  mengelolanya sendiri

**Kalau file itu hilang, identitas validatormu hilang bersama stake-nya.**
Backup, `chmod 600`, jangan pernah dibagikan.

---

## Jaringan — baca sebelum mengeluh node tidak sinkron

Validator harus bisa **saling menghubungi di port P2P**, bukan cuma menghubungi
keluar. Kalau kamu di belakang NAT rumahan:

- forward port P2P (`AINCORE_P2P_PORT`) ke mesinmu, **atau**
- pakai VPS dengan IP publik, **atau**
- gabung ke jaringan privat yang sama (Tailscale/WireGuard) dengan validator lain

Port RPC (`P2P - 1000`) secara default hanya `127.0.0.1`. Biarkan begitu kecuali
kamu memang mau membukanya; kalau iya, batasi ke subnet tepercaya.

---

## Yang terjadi saat kamu `join`

1. `join_validator_set` dikirim dengan stake, pubkey Ed25519, pubkey BLS, dan PoP
2. Executor **memverifikasi PoP secara kriptografis** (`verify_possession`) dan
   memastikan pubkey pada argumen sama dengan pubkey penanda tangan transaksi —
   jadi kamu tidak bisa mendaftarkan kunci BLS milik orang lain
3. Move mengecek stake ≥ 1000 AIN, panjang kunci, dan kamu belum terdaftar
4. Setelah masuk, kamu ikut memproduksi vertex dan memberi suara finality

---

## Aturan yang mengikatmu

**Double-sign = kehilangan 100% stake.** Ini otomatis, deterministik, dan sudah
diuji langsung di jaringan: satu proses kedua yang memakai kunci sama terdeteksi
dalam hitungan detik dan seluruh stake-nya hangus.

Konsekuensi praktis: **jangan pernah menjalankan dua node dengan `node.key` yang
sama.** Bukan di dua mesin, bukan "sebentar saja untuk migrasi". Matikan yang
lama, pastikan benar-benar mati, baru nyalakan yang baru.

Downtime **tidak** di-slash pada versi protokol ini — hanya dideteksi dan
diatestasi.

---

## Kondisi jujur jaringan ini

Supaya kamu ikut dengan mata terbuka:

- **Testnet.** AIN di sini tidak punya nilai ekonomi.
- **4 validator, 2 mesin, 1 operator.** Kamu akan jadi yang pertama dari luar.
- **Belum ada audit eksternal.** Audit internal menemukan dan menutup puluhan
  bug, termasuk beberapa yang fatal, tapi belum ada mata dari luar.
- **wBTC bukan BTC.** Node sendiri melabelinya `synthetic_test_asset_not_btc_backed`.
- **Belum teruji di internet sungguhan.** WAN masih emulasi (150 ms, loss 2%).
- Yang sudah terbukti: konsensus BFT berjalan 138 jam tanpa fork, slashing
  bekerja pada penyerang sungguhan, dan DEX-nya eksekusi benar di chain hidup.

Toleransi fault sekarang tipis: dengan 4 validator, satu slash menghabiskan
seluruh margin BFT. Itu justru alasan kenapa validator tambahan berharga.
