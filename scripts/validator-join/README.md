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
| Stake | **1000 AIN**, plus sedikit AIN untuk gas — operator mengirim 1010 AIN |

---

## Parameter jaringan (testnet saat ini)

```
AINCORE_CHAIN_ID              AINCORE-LOCALTEST-3V
AINCORE_EXPECTED_GENESIS_HASH <minta ke operator — lihat catatan di bawah>
AINCORE_BOOTNODES             /ip4/192.168.18.202/tcp/9201,/ip4/192.168.18.202/tcp/9205,/ip4/192.168.18.66/tcp/9203
```

> **Nilai genesis hash TIDAK dicantumkan di sini dengan sengaja.** Hash itu
> berubah setiap kali genesis diubah (versi stdlib, parameter konsensus, set
> validator awal), jadi angka yang ditulis di dokumen akan basi tanpa ada yang
> sadar — dan calon validator yang memakai angka basi akan gagal boot atau,
> lebih buruk, mengira dirinya sudah bergabung. Operator mengambil nilai yang
> berlaku dari node yang sedang jalan:
>
> ```bash
> journalctl -u aincore-r1 --no-pager | grep -oE 'Genesis identity hash: [0-9a-f]{64}' | tail -1
> ```
>
> Verifikasi nilainya lewat jalur terpisah (telepon, pesan langsung), jangan
> hanya dari file yang dikirimkan bersama genesis.json.

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
export AINCORE_EXPECTED_GENESIS_HASH=<nilai dari operator>   # WAJIB, lihat catatan di atas
export AINCORE_GENESIS_PATH=./genesis.json
export AINCORE_BOOTNODES=/ip4/192.168.18.202/tcp/9201,/ip4/192.168.18.202/tcp/9205,/ip4/192.168.18.66/tcp/9203
export AINCORE_P2P_PORT=9301          # pilih port yang bebas di mesinmu
export AINCORE_REFERENCE_RPC=<URL RPC dari operator>   # disarankan, lihat langkah 3

./scripts/validator-join/join-validator.sh prepare   # build + bikin kunci, cetak alamatmu
# → kirim alamatmu ke operator, minta 1010 AIN (1000 stake + gas)

./scripts/validator-join/join-validator.sh start     # jalankan node, biarkan sinkron
# (di terminal lain, setelah sinkron dan dana masuk, di paruh pertama epoch)
./scripts/validator-join/join-validator.sh join      # stake + masuk validator set
./scripts/validator-join/join-validator.sh verify    # pastikan kamu benar-benar validator
```

### Waktu join itu penting (B441)

Validator yang bergabung setelah peluncuran belum punya riwayat tanda tangan,
jadi node-mu harus membuktikan boot-nya dulu sebelum menandatangani (G1 RC-3).
Selama kuncimu ada di live set (`/get_validators`), node-mu mengirim sekitar
sekali semenit **bukti boot**: transfer jumlah acak dari akunmu ke akunmu
sendiri. Saat melihat blok yang memuat bukti itu, node mencatat N, tinggi yang
dipegangnya saat itu (langkah 4). Misalkan join-mu masuk di epoch E, yang blok
batasnya H_E = (E+1)·I (I = `epoch_blocks` di `aincore_getEconomics`). Komite
epoch E+1 diambil dari live set di H_E, jadi E+1 adalah epoch pertamamu sebagai
anggota:

- N **di bawah H_E**: node-mu ikut menandatangani sejak aktivasi E+1.
- N di H_E atau di atasnya (join terlambat di epoch E, atau restart, langkah 1):
  node-mu abstain selama seluruh epoch pertamanya sebagai anggota, dan
  menandatangani sejak aktivasi setelah blok batas pertama di atas N. Selama
  epoch itu ia tidak membuat vertex dan tidak mendapat slot leader, jadi tidak
  mendapat bonus leader (bagian reward emisi dan fee menurut stake tetap
  dibayar).

Join yang dikirim di akhir epoch tapi baru masuk setelah blok batas epoch itu
tidak terlambat: ia masuk di epoch berikutnya, node-mu baru menjadi anggota
satu epoch sesudahnya, dan buktinya punya satu epoch penuh untuk masuk.

1. **Biarkan node terus jalan dan sinkron** dari join sampai node-mu ikut
   menandatangani: sejak aktivasi E+1 kalau N di bawah H_E. Setiap start node
   yang belum menandatangani menghapus bukti yang sudah dicatatnya, jadi restart
   sebelum aktivasi itu, termasuk restart setelah H_E, membuang bukti tersebut.
   Node lalu mengirim bukti baru; kalau yang baru tercatat di H_E atau di atasnya
   (restart di akhir epoch E, atau antara H_E dan aktivasi E+1), tanda tanganmu
   tertunda paling sedikit satu epoch.
2. **Sisakan sedikit AIN di atas stake** untuk gas join dan bukti boot (bukti
   membayar gas dua kali base fee); operator mengirim 1010 AIN dan `join` memeriksa
   saldo minimal 1001 AIN, jadi join yang batal masih bisa diulang. Jangan kirim
   transaksi lain dari akun ini sampai bukti tercatat: bukti memakai nomor urut
   akun berikutnya. Kalau bukti tidak bisa diantrekan, node mencetak
   `[RC-3] no proof-of-boot transaction this time (<alasan>); the account needs
   a little AIN for its gas`. Baris itu selalu diakhiri saran soal gas; alasan
   di dalam kurung-lah yang menjelaskan apa yang terjadi:
   - `Insufficient balance for gas` atau `no CoinStore`: akun tidak bisa
     membayar gas bukti. Isi saldonya.
   - `Duplicate pending nonce`: bukti sebelumnya (atau transaksi lain dari akun
     ini dengan nomor urut yang sama) masih menunggu blok di mempool node-mu, dan
     bukti baru ditolak di sampingnya. Ini tidak apa-apa selama ia menunggu: node
     mencatat bukti begitu ada blok yang memuatnya. Kalau baris ini masih
     berulang menjelang H_E, periksa peer dan sinkron node.
   - `Mempool full`: mempool node penuh; node mencoba lagi semenit kemudian.
3. **Join di paruh pertama epoch.** Node harus mencatat buktinya di bawah H_E,
   blok batas epoch tempat join-mu masuk. `join` menolak kalau epoch sudah lewat
   separuh (I paling sedikit 100 blok, jadi tersisa paling sedikit 50 blok untuk
   bukti yang dikirim sekali semenit); `AINCORE_JOIN_LATE=1` memaksa join
   sekarang. Pemeriksaan ini membaca tinggi node-mu sendiri, padahal join masuk
   di tinggi jaringan: node yang masih menyusul lolos walau jaringan sudah di
   paruh kedua epoch, atau di epoch berikutnya. Set `AINCORE_REFERENCE_RPC` ke
   URL JSON-RPC node lain di jaringan (minta ke operator; RPC node hanya
   mendengar di `127.0.0.1` kecuali dibuka, lihat **Jaringan**): `join` lalu
   menolak selama node-mu tertinggal lebih dari 3 blok darinya, dan menghitung
   dari tinggi yang lebih tinggi. Tanpa itu `join` hanya memberi peringatan dan
   menganggap node-mu sudah di ujung jaringan. Join yang gagal dengan abort code
   589836 (`ECHURN_LIMIT`) berarti jatah stake baru epoch ini (10 % stake
   komite, G5 CH-1) sudah habis: join lagi di awal epoch berikutnya.
4. **Lihat log node.** Saat bukti masuk blok, node mencetak
   `[RC-3] a block after this boot holds a proof transaction: signing resumes at
   the first boundary above height N`. Node-mu menandatangani sejak aktivasi
   setelah blok batas pertama di atas N: sejak epoch pertamamu sebagai anggota
   kalau N di bawah H_E, blok batas epoch tempat join-mu masuk; kalau tidak,
   satu epoch kemudian atau lebih.

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
4. Kuncimu masuk live set; node-mu mengirim bukti boot (lihat **Waktu join
   itu penting** di atas)
5. Di blok batas epoch, komite epoch berikutnya diambil dari live set. Sejak
   aktivasinya kamu ikut memproduksi vertex dan memberi suara finality, kalau
   node-mu mencatat bukti boot-nya (N) di bawah blok batas itu

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
