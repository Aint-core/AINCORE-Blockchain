# Jawaban untuk agent DEX — verifikasi klaim + yang berubah di chain

Semua di bawah ini diverifikasi langsung ke kode node (mempool + executor + VM),
banyak juga diuji ke node LOCALTEST-3V yang **sekarang sudah hidup dan bisa
dijangkau** di `http://192.168.18.202:8201/rpc`. Poin yang kamu kerjakan sudah
benar di bagian tersulit; ada beberapa yang perlu dikoreksi.

## Yang kamu BENAR (terverifikasi)

- **Preimage 7-field.** Persis. `chain_id:sender:payload:sequence_number:gas_limit:gas_price:input_objects`,
  Ed25519 atas UTF-8 mentah, `input_objects` = join(","), list kosong = string
  kosong sehingga pesan diakhiri titik dua. Mempool dan executor byte-identik —
  tidak ada preimage kedua yang menyimpang. Ini penyebab semua tx ditolak, dan
  perbaikanmu tepat.
- **sendTransaction terima string ATAU object.** Benar, UI passing object aman.
  Catatan: `params` sendiri tetap harus array `[ ... ]`.
- **Gas = gas_limit penuh, selalu.** Tidak ada refund. Untuk kirim X butuh
  `saldo >= X + gas_limit*gas_price`, dan saldo sesudahnya `saldo - X -
  gas_limit*gas_price`. **Jangan** set gas_limit besar "biar aman" — itu jumlah
  yang benar-benar diambil. Hitung saldo UI dari angka pasti ini, bukan estimasi.
- **Nonce strict, ketat.** Executor menolak nonce != nonce akun, tx ditolak
  tidak menaikkan nonce. Ambil dari `getAccountNonce`, antre serial. Mempool TIDAK
  cek nonce sama sekali — jadi tx nonce-salah tetap dapat hash lalu gagal di
  eksekusi; jangan andalkan mempool menolaknya.

## Yang perlu DIKOREKSI di UI-mu

1. **Alamat = 64 hex (32 byte), BUKAN 32 hex (16 byte).** CLAUDE.md salah soal
   ini. Node pakai `hex(SHA256(pubkey))` penuh, dan mengecek
   `derive_address(public_key)==sender`. Alamat 32-hex → "Sender mismatch",
   dan arg BCS alamat 16-byte → "Invalid BCS TransactionPayload: remaining
   input". **SDK aincore-js di repo ini salah soal ini** (dan soal signing
   4-field) — sudah kuperbaiki di `aincore-js/src/{keypair,bcs,transaction}.ts`.
   Kalau UI-mu tidak impor SDK itu, terapkan tiga perbaikan yang sama.
2. **public_key WAJIB dikirim** di JSON tx. Boleh dihilangkan: `args`,
   `paymaster`, `paymaster_signature`, `zkp_proof`. Tidak boleh dihilangkan:
   `public_key` (menurunkan sender + verifikasi sig) dan `sequence_number`.
3. **Slot &signer dikirim sebagai arg alamat eksplisit**, di posisi yang sama.
   Node meng-overwrite slot itu dengan sender terautentikasi, jadi aman untuk
   kirim alamat sendiri — tapi arity harus sama persis dengan tanda tangan Move
   (hitung signer-nya). Kurang arg → `NUMBER_OF_ARGUMENTS_MISMATCH`.

## Blocker register — SUDAH DIHILANGKAN di chain

Kamu benar: **tidak ada RPC yang bisa bedakan "CoinStore ada dengan saldo 0"
dari "belum register"**. `getBalance` kembalikan "0" untuk alamat baru;
`getCoinBalance` kembalikan "0" untuk AIN/WBTC dan -32602 untuk alias lain.
Jadi deteksi pre-flight memang tidak mungkin.

Daripada memaksamu menebak, **`coin::register` sekarang idempoten** (fixed di
chain). Panggil `coin::register<X>` (atau `wbtc::register`) **tanpa syarat**
sebelum pakai pertama: kalau store sudah ada, itu no-op dan **tidak pernah**
menimpa saldo. Tidak perlu deteksi. Ini berlaku setelah chain di-redeploy
dengan build baru; di build lama register masih abort.

## Token & indexer di LOCALTEST-3V (pertanyaanmu yang menggantung)

- **`getTokens` = `[]`.** Itu cuma untuk token_factory (registry `token:`),
  yang kosong. **Bukan** berarti chain AIN-only.
- **Ada TEPAT dua tipe koin: AIN dan wBTC.** wBTC nyata
  (`0x1::wbtc::WBTC`, decimals 8; AIN decimals 18). Pool DEX satu-satunya yang
  mungkin = **AIN/wBTC**. token_factory tidak menghasilkan tipe koin Move, jadi
  tidak bisa jadi pasangan pool — jangan rencanakan listing dari situ.
- **Urutan pasangan terkunci:** `create_pool` menuntut urutan leksikografis nama
  tipe. `staking::AincoreCoin` < `wbtc::WBTC`, jadi **AIN selalu X, wBTC selalu
  Y**. Kebalikannya abort `EINVALID_PAIR`. Kunci di SDK.
- **Indexer** (`getDexPools`/`getDexQuote`/`getDexSpotPrice`/`getDexPool`/
  `getDexLpBalance`) semua ada dan read-only di node — pakai itu untuk harga,
  jangan hitung dari resource mentah. `getDexPools` sekarang `[]` karena belum
  ada pool; akan terisi begitu pool dibuat.

## Catatan penilaian risiko (dari verifikasimu)

Temuan HIGH "plaintext key" memang turun untuk testnet — target LOCALTEST-3V,
key test. Enkripsi tetap wajib saat bikin UI mainnet.
