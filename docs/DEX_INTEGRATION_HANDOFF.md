# AINCORE <-> DEX (AMM) — Spesifikasi Integrasi

Dokumen untuk agent/developer yang mengerjakan **aplikasi DEX**. Semua isinya
dibaca langsung dari kode chain, bukan asumsi.

Rantai target saat ini (testnet internal):

| | |
|---|---|
| Chain ID | `AINCORE-LOCALTEST-3V` |
| Validator | 4 (r1/r2 di NAS `192.168.18.202`, r3/r4 di Pi `192.168.18.66`) |
| RPC untuk aplikasi | **`http://192.168.18.202:8201/rpc`** (r1, terbuka ke LAN `192.168.18.0/24`) |
| RPC node lain | r2 `:8205`, r3 `:8203`, r4 `:8206` — tetap localhost-only |
| Waktu blok | ~3 detik (tick 1500 ms, anchor di ronde genap) |

> Sudah diuji dari mesin lain di LAN: `aincore_getStatus`, `aincore_getDexPools`,
> `aincore_getGasPrice`, `aincore_getSupply` semuanya menjawab. Rate limit 100
> req/detik (burst 200). CORS bawaan mengizinkan origin `localhost:3000` dan
> `localhost:5173`, jadi dev server di port itu bisa langsung memanggil.

---

## 0. Revisi penting sejak versi sebelumnya

Versi awal dokumen ini menyebut "pool bisa langsung dibuat". Itu benar untuk
registry DEX-nya, tapi menutupi satu syarat yang lebih dasar, dan syarat itu
sebelumnya **tidak terpenuhi**. Ringkasnya:

1. Pool AMM butuh **dua tipe koin**. Chain ini hanya mendefinisikan dua:
   `0x1::staking::AincoreCoin` (AIN) dan `0x1::wbtc::WBTC`. Jadi satu-satunya
   pasangan yang mungkin sekarang adalah **AIN/wBTC**.
2. `wbtc::mint` menolak jalan kecuali `BridgeConfig` ada di `@0x1`, dan genesis
   **tidak pernah membuatnya**. Fungsi `wbtc::initialize` butuh signer `0x1`
   yang tidak dipegang siapa pun. Akibatnya wBTC tidak bisa dicetak selamanya,
   dan pool tidak akan pernah punya likuiditas.
3. `token_factory` juga mati total karena alasan yang sama (`TokenRegistry`
   tidak pernah dibuat) — jadi token buatan sendiri bukan jalan keluar.

Nomor 2 dan 3 **sudah diperbaiki di kode** (genesis kini menanam kedua resource
tersebut, diverifikasi lewat tes yang benar-benar mencetak wBTC lewat executor).
**Tapi perbaikan itu hanya berlaku untuk genesis baru** — chain yang sekarang
berjalan masih memakai genesis lama, jadi `wbtc::mint` di sana masih gagal.
Artinya: sebelum uji likuiditas sungguhan, chain perlu di-redeploy dengan
genesis baru. Koordinasikan waktunya, jangan diasumsikan sudah terjadi.

Catatan tambahan: `token_factory` **tidak** menghasilkan tipe koin Move. Token
buatannya hanya saldo dalam registry, tidak bisa dipakai sebagai `<X, Y>` di
DEX. Jangan rencanakan listing token factory di AMM ini.

---

## 1. Yang SUDAH ada di chain (jangan dibangun ulang)

Modul `0x1::dex` sudah ter-deploy dan `PoolRegistry` dibuat saat genesis
(`genesis.rs`), jadi tidak perlu langkah init untuk registry-nya.

Entry function, semuanya generic atas dua tipe koin `<X, Y>`:

```move
0x1::dex::create_pool<X, Y>(creator: &signer)
0x1::dex::add_liquidity<X, Y>(account, pool_addr: address,
                              amount_x: u128, amount_y: u128, min_lp: u128)
0x1::dex::remove_liquidity<X, Y>(account, pool_addr: address,
                                 lp_amount: u128, min_x: u128, min_y: u128)
0x1::dex::swap_x_to_y<X, Y>(account, pool_addr: address,
                            amount_x_in: u128, min_y_out: u128)
0x1::dex::swap_y_to_x<X, Y>(account, pool_addr: address,
                            amount_y_in: u128, min_x_out: u128)
```

Fungsi baca (bukan transaksi):

```move
0x1::dex::get_reserves<X, Y>(pool_addr) -> (reserve_x, reserve_y, lp_supply, fee_bp)
```

Konstanta yang mengikat UI:

- **Fee 30 bp** (0,30%) — tetap, `FIXED_FEE_BP = 30`
- **MINIMUM_LIQUIDITY = 1000** dikunci selamanya dari deposit pertama
- Tipe koin: `0x1::staking::AincoreCoin` dan `0x1::wbtc::WBTC`
- `pool_addr` = alamat **pembuat pool**, bukan alamat turunan. Simpan alamat
  ini; semua operasi berikutnya memerlukannya.

---

## 2. JEBAKAN UTAMA — wajib dibaca sebelum menulis kode swap

**Penerima harus punya `CoinStore<T>` sebelum bisa menerima token T.**

Chain punya auto-register, tapi **hanya untuk `0x1::coin::transfer`**. Jalur DEX
tidak tercakup. Jadi:

> Kalau user swap dan akan menerima token yang **belum pernah dia pegang**,
> `coin::deposit` akan **abort** dan swap gagal (user tetap kena gas).

Sebelum swap pertama ke token baru, kirim salah satu:

```move
0x1::coin::register<X>(account: &signer)   // generic, untuk tipe apa pun
0x1::wbtc::register(account: &signer)      // pintasan khusus wBTC
```

`register` **tidak idempoten** — abort kalau store sudah ada. Cek dulu lewat
`aincore_getCoinBalance` / `aincore_getBalance`, baru daftar kalau belum ada.

Pola aman di UI: `pastikanTerdaftar(token)` -> kalau belum ada kirim `register`,
tunggu 1 blok, baru kirim `swap`.

---

## 3. Format transaksi (ini yang paling sering salah)

Semua transaksi adalah **BCS `EntryFunction`** yang di-hex. Bukan JSON, bukan
string.

**Alamat** = `hex(SHA256(ed25519_pubkey))` — turunkan sendiri, jangan pakai
pubkey sebagai alamat.

### Slot signer dikirim sebagai argumen alamat

Parameter `&signer` **tidak** disuntikkan otomatis. Setiap `&signer` di tanda
tangan fungsi harus dikirim sebagai argumen BCS alamat di posisi yang sama.
Ini penyebab error `NUMBER_OF_ARGUMENTS_MISMATCH` yang paling umum:

| Fungsi Move | args BCS yang dikirim |
|---|---|
| `coin::transfer(from: &signer, to, amount)` | `[from_addr, to_addr, amount]` |
| `wbtc::register(account: &signer)` | `[account_addr]` |
| `wbtc::mint(bridge: &signer, to, amount)` | `[bridge_addr, to_addr, amount]` |
| `dex::swap_x_to_y<X,Y>(account: &signer, pool, amt_in, min_out)` | `[account_addr, pool_addr, amt_in, min_out]` |

**Preimage tanda tangan** (urutan wajib persis, dipisah titik dua):

```
chain_id : sender : payload_hex : sequence_number : gas_limit : gas_price : input_objects
```

`input_objects` string kosong untuk transfer/DEX biasa.

**Bentuk JSON yang dikirim:**

```json
{
  "chain_id": "AINCORE-LOCALTEST-3V",
  "sender": "<64 hex>",
  "public_key": "<64 hex>",
  "input_objects": [],
  "payload": "<hex BCS EntryFunction>",
  "gas_limit": 100000,
  "gas_price": 1,
  "sequence_number": <u64>,
  "signature": "<128 hex ed25519>",
  "paymaster": null,
  "paymaster_signature": null
}
```

Dikirim lewat `aincore_sendTransaction` dengan **satu parameter string** berisi
JSON di atas (bukan objek).

**Referensi implementasi yang terbukti jalan** — tiru saja:
`bench-tps/src/main.rs` (`transfer_payload`, `signed_tx`) dan
`core/cli/src/main.rs`. Contoh entry-function generik ada di tes
`core/node/src/genesis.rs::test_fresh_genesis_enables_wbtc_mint`.

---

## 4. Nonce (sequence_number) — sumber kegagalan paling umum

- Nonce **per pengirim**, berurutan, mulai dari 0
- Executor **menolak** nonce yang tidak sama persis dengan nonce akun saat itu
- Transaksi yang ditolak **tidak menaikkan** nonce

Konsekuensi UI: **jangan kirim beberapa transaksi paralel dari satu wallet.**
Antrekan berurutan, tunggu yang sebelumnya mendarat. Kalau user menekan tombol
dua kali cepat, yang kedua akan gagal.

Baca nonce lewat `aincore_getAccountNonce` (lebih langsung daripada field
`sequence_number` di `getBalance`).

---

## 5. Cara mendanai akun uji — baca sebelum memakai faucet

Ada dua jalur, dan salah satunya berbahaya di cluster multi-node.

### Jalur aman: transaksi biasa lewat konsensus

- **AIN**: transfer dari akun yang didanai genesis (validator genesis punya
  saldo) memakai `coin::transfer`.
- **wBTC**: `wbtc::mint` ditandatangani **bridge authority**. Setelah genesis
  baru, authority = alamat validator #1 di `genesis.json`, dan bisa dirotasi
  lewat `wbtc::update_authority`.

Keduanya masuk blok, dieksekusi semua validator, aman.

### Jalur berbahaya: RPC faucet (`aincore_faucet`, `aincore_testMintWbtc`)

Kedua RPC ini **menulis langsung ke RocksDB node yang dihubungi**, di luar
eksekusi blok. Di cluster 4 validator, akibatnya:

> Hanya node itu yang tahu saldo tersebut. Begitu akun yang didanai mengirim
> transaksi, node itu mengeksekusi sukses sementara tiga node lain meng-abort
> karena saldo tidak ada. Write set berbeda -> **state root berbeda -> fork.**

Status saat ini: faucet **mati** (`AINCORE_ENABLE_FAUCET` tidak diset di unit
systemd), dan permanen ditolak di `AINCORE-MAINNET-1`. Biarkan mati. Kalau
benar-benar perlu, panggil dengan parameter **identik ke keempat node** sebelum
akun itu bertransaksi — atau lebih baik, pakai jalur aman di atas.

---

## 6. RPC yang tersedia — DEX sudah didukung penuh

Chain sudah punya endpoint DEX lengkap. Jangan bangun ulang, dan jangan hitung
harga sendiri dari resource mentah.

| Metode | Parameter | Guna |
|---|---|---|
| `aincore_getDexPools` | `[]` | daftar semua pool + cadangan |
| `aincore_getDexPool` | `[token_x, token_y]` | satu pool (null kalau tidak ada) |
| `aincore_getDexQuote` | `[token_in, token_out, amount_in]` | **kuotasi swap** — pakai ini untuk angka di tombol swap |
| `aincore_getDexSpotPrice` | `[token_in, token_out, unit_amount_in?]` | harga spot (default unit 1e18) |
| `aincore_getDexLpBalance` | `[address, pool_addr?]` atau `[address, token_x, token_y]` | saldo LP user |

`amount_in` boleh string atau angka — **selalu kirim string**: JavaScript
kehilangan presisi di atas 2^53 dan nilai u128 di sini jauh melewatinya.

Endpoint umum lain: `aincore_sendTransaction`, `aincore_getBalance`,
`aincore_getCoinBalance`, `aincore_getAccountNonce`,
`aincore_getTransactionReceipt`, `aincore_getBlocks`, `aincore_estimateGas`,
`aincore_getGasPrice`, `aincore_getTokens`, `aincore_getTokenBalance`,
`aincore_getSupply`, `aincore_getStatus`.

---

## 7. Yang perlu diminta ke sisi chain

1. ~~Endpoint RPC~~ — **selesai**, `http://192.168.18.202:8201/rpc` terbuka ke
   LAN. Kalau nanti butuh dari luar LAN, itu permintaan terpisah.
2. **Redeploy dengan genesis baru**, supaya `wbtc::mint` hidup (Bagian 0).
   Ini yang menghalangi uji likuiditas sungguhan. Belum dilakukan.
3. Opsional: memperluas auto-register agar mencakup jalur DEX (Bagian 2).

---

## 8. Urutan kerja yang disarankan

1. **Tulis klien transaksi dulu** (payload BCS, tanda tangan, kirim) dan
   buktikan dengan satu `coin::transfer` sederhana. Kalau ini belum jalan,
   jangan lanjut ke DEX.
2. `wbtc::register` -> cek saldo -> pastikan alur pendaftaran benar
3. Danai wBTC lewat `wbtc::mint` (butuh genesis baru)
4. `create_pool<AincoreCoin, WBTC>` -> `add_liquidity` -> baca cadangan
5. `swap_x_to_y` dengan `min_y_out` realistis, lalu uji `min_y_out` mustahil
   (harus gagal bersih, user hanya kehilangan gas)
6. Baru sambungkan UI

---

## 9. Yang sudah dijamin chain (tidak perlu ditangani aplikasi)

- **Transaksi gagal tidak menghilangkan dana.** Kalau swap abort, user hanya
  kehilangan gas. Diuji dan dibuktikan hidup.
- **Pool tidak bisa di-brick.** Bug lama yang membuat siapa pun bisa mematikan
  pool baru dengan satu transaksi sudah ditutup.
- **Determinisme.** Keempat validator menghasilkan blok, state root, dan
  finality digest identik.

## 10. Status pengujian `dex.move`

Sebelumnya modul ini **belum pernah dieksekusi sekali pun**. Sekarang seluruh
siklusnya sudah dijalankan lewat executor sungguhan
(`core/node/src/genesis.rs::test_dex_pool_lifecycle_on_fresh_genesis`):
`wbtc::register` -> `wbtc::mint` -> `create_pool` -> `add_liquidity` -> `swap`.

Yang sudah terbukti:

- **Rumus swap benar.** Output dicocokkan dengan implementasi CPMM tandingan di
  Rust, bukan angka hasil run sebelumnya. Contoh nyata: cadangan 1.000.000 AIN /
  4.000.000 wBTC, masuk 10.000 AIN -> keluar **39.486 wBTC**. Dibuktikan lewat
  mutasi: kalau fee dibuat 0 hasilnya 39.603 (tes gagal), kalau reserve tertukar
  hasilnya 2.486 (tes gagal). Jadi fee 30 bp dan urutan operand memang dipakai.
- **Invarian `k` naik setelah swap** (fee benar-benar mengendap di pool).
- **MINIMUM_LIQUIDITY terkunci benar** — masuk ke `lp_supply` tapi **tidak**
  dikreditkan ke LPToken penyetor, dan `lp_supply` ditulis tepat sekali.
- **Slippage protection bekerja.** `min_y_out` yang mustahil membuat swap abort
  bersih: cadangan pool tidak berubah, tidak ada output terkirim, dan trader
  hanya kehilangan gas.

Yang masih perlu perhatian:

- **Urutan pasangan tidak bebas.** `canonical_token_names` mewajibkan urutan
  leksikografis nama tipe, jadi **AIN selalu X dan wBTC selalu Y**. Memanggil
  `create_pool<WBTC, AincoreCoin>` akan abort dengan `EINVALID_PAIR`. Kunci ini
  di SDK kalian, jangan biarkan urutannya ditentukan input user.
- **`pool_addr` = alamat pembuat pool.** Tidak ada alamat turunan; simpan.
- Semua di atas diuji **satu proses**, belum di cluster 4 node berjalan (butuh
  redeploy, Bagian 0/7). Perilaku multi-node belum dikonfirmasi.
- Belum diuji lintas WAN (semua pengujian di LAN)
- Slashing sementara dimatikan (alasan: determinisme) — tidak memengaruhi DEX
