# AINCORE Blockchain — Deep Security Audit Report

**Tanggal:** 2026-05-21
**Auditor:** Claude Sonnet 4.6 (AI Security Auditor)
**Scope:** Full codebase audit — consensus, crypto, executor, mempool, storage, network, API, bridge, governance, DA
**Version:** AINCORE v0.1.0 (Workspace Cargo.toml)
**Branch:** main
**Commit:** 28e6bcc (Solo founder genesis + mount genesis as volume)

---

## Executive Summary

AINCORE adalah blockchain L1 modular yang dibangun dari nol dengan Rust, menggunakan DAG-based BFT consensus (Bullshark-lite), Move VM, dan RocksDB. Audit ini mencakup pembacaan penuh 40+ source file kritis dan analisis mendalam terhadap semua lapisan keamanan.

**Overall Security Posture: MEDIUM-HIGH RISK — BELUM SIAP MAINNET**

Ditemukan total **28 findings**:
- **4 CRITICAL** — wajib fix sebelum mainnet
- **7 HIGH** — sangat disarankan fix sebelum mainnet
- **9 MEDIUM** — fix dalam 30 hari
- **6 LOW** — fix dalam 90 hari
- **2 INFORMATIONAL**

Kode menunjukkan kualitas engineering yang baik secara keseluruhan: banyak fix keamanan yang sudah diimplementasikan (BLS pairing check, BLOCK_EXECUTION_LOCK, tombstone anti-replay, WAL hardening, equivocation detection). Namun ada beberapa celah kritis yang dapat dieksploitasi sebelum mainnet.

---

## Methodology

1. **Static Code Analysis** — Pembacaan penuh seluruh source code kritis (consensus, executor, mempool, crypto, storage, network, API, bridge, governance, DA)
2. **Pattern Analysis** — grep untuk anti-patterns: `unwrap()` (462 instances), `panic!` (5 instances), integer arithmetic, lock ordering
3. **Threat Modeling** — Identifikasi attack surfaces: validator manipulation, equivocation bypass, DoS, replay attacks, bridge exploits
4. **Architecture Review** — Gap analysis antara implementasi dan whitepaper/roadmap
5. **Referensi Riset** — Narwhal/Bullshark papers (Spiegelman et al.), BLS security (IETF RFC 9380), Ed25519 vulnerabilities (Bernstein et al.), RocksDB documentation, Move VM security model

---

## Findings Summary

| ID | Severity | Layer | Title | Status |
|---|---|---|---|---|
| C-01 | CRITICAL | Consensus | Equivocation reason string mismatch — double-sign menerima 5% bukan 100% slash | Open |
| C-02 | CRITICAL | Bridge | Multi-sig menggunakan ephemeral random wallets — tidak ada keamanan nyata | Open |
| C-03 | CRITICAL | Consensus | VDF bukan VDF sejati — sequential hash bisa di-parallelize, leader election dapat diprediksi | Open |
| C-04 | CRITICAL | Crypto | Address space 16-byte terlalu kecil — collision probability berbahaya untuk mainnet | Open |
| H-01 | HIGH | Mempool | PQC signature path (9254 byte) bypass full validation — eksekutor menjadi single gate | Open |
| H-02 | HIGH | Consensus | Downtime detection hanya dari perspektif satu node — false positive slashing | Open |
| H-03 | HIGH | Bridge | Nonce counter di-reset setiap restart — replay attack pada EVM bridge | Open |
| H-04 | HIGH | Executor | ZKP proof tidak diverifikasi — field `zkp_proof` hanya di-log, tidak divalidasi | Open |
| H-05 | HIGH | Executor | `execute_transaction` tidak di-protect BLOCK_EXECUTION_LOCK — parallel state write | Open |
| H-06 | HIGH | Consensus | DAG checkpoint tidak ada integrity check — checkpoint injection attack | Open |
| H-07 | HIGH | API | `aincore_getTransaction` melakukan full DAG scan O(N) — DoS vektor | Open |
| M-01 | MEDIUM | Consensus | Lock ordering hazard — potential deadlock antara DAG + RoundIndex + OrderingEngine | Open |
| M-02 | MEDIUM | Threshold BLS | Key generation sentralisasi (centralized keygen) — bukan DKG | Open |
| M-03 | MEDIUM | Governance | Vote weight diambil saat voting, bukan saat snapshot — plutocracy attack | Open |
| M-04 | MEDIUM | Mempool | Size check dilakukan SETELAH signature verification — CPU exhaustion vektor | Open |
| M-05 | MEDIUM | Network | Gossipsub menggunakan GossipsubConfig::default() — tidak ada rate limit per-peer | Open |
| M-06 | MEDIUM | Storage | `scan_prefix` iterates seluruh DB — bisa triggered via sync untuk DoS | Open |
| M-07 | MEDIUM | Bridge | Bridge event parsing menggunakan string split — payload injection tidak divalidasi | Open |
| M-08 | MEDIUM | Consensus | `get_validator_set()` melakukan storage I/O di hot path setiap round | Open |
| M-09 | MEDIUM | DA | DA signing key disimpan plaintext di RocksDB — `sys:da:signing_key` | Open |
| L-01 | LOW | Crypto | VDF verify melakukan full re-computation — O(difficulty) verifikasi | Open |
| L-02 | LOW | API | Rate limiting tidak diterapkan ke semua endpoints secara seragam | Open |
| L-03 | LOW | Consensus | current_round tidak dilindungi mutex — race condition jika dipanggil dari thread lain | Open |
| L-04 | LOW | Storage | `from_utf8_lossy` silently menggantikan invalid UTF-8 — data corruption tidak terdeteksi | Open |
| L-05 | LOW | Executor | `unwrap()` pada identifier statics — bisa panic jika nama di-refactor | Open |
| L-06 | LOW | Network | P2P ephemeral keypair dibuat baru setiap restart — tidak ada node identity persistence | Open |
| I-01 | INFO | Architecture | STARK/SNARK prover belum diimplementasikan (Phase 2) — ZKP field ada di TX tapi tidak diverifikasi | Open |
| I-02 | INFO | Architecture | AccountAbstraction trait stubbed — execute_transaction kosong | Open |

---

## Detailed Findings

---

### CRITICAL Issues (Harus fix sebelum mainnet)

---

#### C-01: Equivocation Reason String Mismatch — Double-Sign Mendapat 5% Bukan 100% Slash

- **Layer:** Consensus / Executor
- **File:** `consensus/consensus/src/dag.rs:510` dan `core/executor/src/lib.rs:841`
- **Deskripsi:**
  Ketika equivocation (double-sign) terdeteksi di `dag.rs`, event ditulis ke storage dengan `"reason": "double_sign"`. Di `executor/src/lib.rs`, logika slash memeriksa `if reason == "equivocation"` untuk menerapkan 100% slash. Karena string tidak match (`"double_sign"` vs `"equivocation"`), validator yang melakukan double-sign hanya terkena 5% slash (downtime penalty), bukan 100% slash yang seharusnya.

  ```rust
  // dag.rs:510 — reason yang ditulis:
  "reason": "double_sign",

  // executor/src/lib.rs:841 — kondisi yang dicek:
  let slash_pct: u64 = if reason == "equivocation" { 100 } else { 5 };
  ```

- **Attack Scenario:**
  1. Validator jahat melakukan double-sign (kirim dua vertex berbeda di round yang sama)
  2. Sistem mendeteksi equivocation dan menulis event ke `sys:pending_slash:{addr}`
  3. Executor memproses slash tapi hanya mendeduct 5% karena reason string tidak match
  4. Validator tetap bisa berjalan dengan 95% stake, cukup untuk tetap berpartisipasi di konsensus
  5. Validator dapat melakukan serangan berulang dengan kehilangan hanya 5% per serangan

- **Impact:** KRITIKAL — Validator jahat dapat melakukan equivocation berulang dengan penalti minimal. Dalam jaringan kecil (misal 4 validator), satu validator jahat yang melakukan equivocation bisa menyebabkan fork tanpa konsekuensi besar.

- **Reference:** Tendermint double-sign evidence handling; Cosmos SDK equivocation slashing (100% di semua implementasi BFT serius)

- **Rekomendasi Fix:**
  ```rust
  // Opsi A: Ubah reason di dag.rs
  "reason": "equivocation",  // bukan "double_sign"
  
  // Opsi B: Ubah kondisi di executor/src/lib.rs
  let slash_pct: u64 = if reason == "equivocation" || reason == "double_sign" { 100 } else { 5 };
  
  // Opsi C (BEST): Gunakan enum bukan string untuk reason
  #[derive(Serialize, Deserialize)]
  enum SlashReason { Equivocation, Downtime }
  ```

- **Effort:** S (< 1 jam)

---

#### C-02: Bridge Multi-Sig Menggunakan Ephemeral Random Wallets

- **Layer:** Bridge (EVM)
- **File:** `depin/bridge-rust/src/main.rs:71-72`
- **Deskripsi:**
  Bridge multi-sig diinisialisasi dengan `wallet2` dan `wallet3` yang dibuat dari `rand::thread_rng()` di runtime, bukan dari keystore persisten. Ini berarti:
  1. Setiap kali bridge restart, wallet2 dan wallet3 adalah key yang berbeda
  2. Smart contract EVM tidak dapat memvalidasi signature dari key-key ini karena key berubah setiap restart
  3. Multi-sig tidak memberikan keamanan nyata — hanya wallet1 (dari keystore) yang konsisten

  ```rust
  // main.rs:71-72 — CRITICAL:
  let wallet2 = LocalWallet::new(&mut rand::thread_rng()); // ephemeral!
  let wallet3 = LocalWallet::new(&mut rand::thread_rng()); // ephemeral!
  let evm = EvmClient::new(evm_rpc, contract_addr, vec![wallet, wallet2, wallet3]);
  ```

- **Attack Scenario:**
  1. Attacker mengkompromis satu signer (wallet1 dari keystore)
  2. Seharusnya dengan multi-sig 3-of-5, satu signer tidak cukup
  3. Tetapi wallet2 dan wallet3 adalah random key yang TIDAK terdaftar di smart contract
  4. Contract hanya memvalidasi wallet1 — de facto menjadi 1-of-1 multisig
  5. Attacker dengan kontrol wallet1 dapat mint token tanpa batas di EVM

- **Impact:** KRITIKAL — Seluruh bridge funds dapat dicuri oleh siapapun yang mengkompromis satu key. Bridge Ronin (2022, $625M) dan Wormhole (2022, $320M) juga terkena single-point-of-failure pada signer.

- **Reference:** Bridge attack postmortems: Ronin Network hack (Axie Infinity, 2022), Wormhole exploit (2022)

- **Rekomendasi Fix:**
  ```rust
  // Semua signer HARUS dari keystore persisten dan terdaftar di smart contract:
  let keystore_paths = vec![keystore_path_1, keystore_path_2, keystore_path_3];
  let signers: Vec<LocalWallet> = keystore_paths
      .iter()
      .map(|path| decrypt_keystore(path))
      .collect::<Result<Vec<_>, _>>()?;
  
  // Pastikan public key semua signer sudah didaftarkan di EVM contract sebelum operasi
  ```

- **Effort:** M (perlu koordinasi multi-party keystore setup + contract redeployment)

---

#### C-03: VDF Bukan VDF Sejati — Sequential Hash Dapat Diprediksi dan Diparallelisasi

- **Layer:** Crypto / Consensus
- **File:** `common/crypto/src/vdf/mod.rs:63-78`
- **Deskripsi:**
  `VDFEngine` mengimplementasikan sequential SHA3-256 hashing dengan difficulty 50 iterations. Ini bukan VDF (Verifiable Delay Function) yang sesungguhnya karena:
  1. **Tidak ada delay yang dapat dibuktikan** — verifier harus re-compute, bukan verifikasi proof
  2. **Bisa diparallelisasi** — attacker dengan GPU/ASIC dapat pre-compute semua kemungkinan output
  3. **Difficulty terlalu rendah** (50 iterations) — setiap modern CPU dapat menyelesaikan dalam mikrodetik
  4. **Deterministik** — output sama untuk input sama, memungkinkan pre-computation
  5. VDF yang sesungguhnya memerlukan sequential computation yang TIDAK dapat diparallelisasi (RSA/Class Group)

  ```rust
  // vdf/mod.rs:72 — difficulty = 50 sequential hashes
  for i in 0..self.difficulty {  // 50 hashes! bukan VDF
      let mut hasher = Sha3_256::new();
      hasher.update(&current);
      hasher.update(i.to_le_bytes());
      current = hasher.finalize().to_vec();
  }
  ```

  Komentar di kode sendiri menyatakan: *"Production systems should use Wesolowski VDF, Pietrzak VDF, or MinRoot VDF"*.

- **Attack Scenario:**
  1. Attacker pre-compute semua possible VDF outputs untuk semua rounds sebelumnya
  2. Karena VDF deterministik dan murah dihitung, attacker tahu leader setiap round di masa depan
  3. Attacker bisa selectively partition network untuk mengambil alih leader slot
  4. Atau attacker menghindari round di mana mereka bukan leader untuk menghemat resources

- **Impact:** HIGH-CRITICAL — Leader election menjadi predictable, memungkinkan targeted DoS dan selfish mining

- **Reference:** Ethereum Beacon Chain VDF proposal (Justin Drake, 2018); Wesolowski VDF paper (2018); IETF VDF requirements draft

- **Rekomendasi Fix:**
  Gunakan library VDF yang sesungguhnya:
  ```rust
  // Opsi 1: Pietrzak VDF via vdf crate (crate.io)
  // Opsi 2: IETF MinRoot VDF  
  // Opsi 3 (interim): Gunakan RANDAO-style randomness dari BLS threshold signature
  // sebagai beacon sampai VDF production grade tersedia
  
  // VDF harus memiliki:
  // - Sequentiality: t^(1-ε) total operations tanpa parallelism
  // - Verifiability: O(log t) verification
  // - Soundness: computationally infeasible untuk adversary
  ```

- **Effort:** L (memerlukan penelitian dan implementasi/integrasi library VDF production-grade)

---

#### C-04: Address Space 16-Byte — Birthday Collision Probability Berbahaya untuk Mainnet Scale

- **Layer:** Crypto
- **File:** `common/crypto/src/lib.rs:186`
- **Deskripsi:**
  Address AINCORE diderivasi sebagai `hex(SHA256(pubkey)[0..16])` — hanya 16 byte = 128 bit = 32 hex chars. Ini adalah salah satu ruang address terkecil di antara semua blockchain produksi.

  ```rust
  pub fn derive_address(public_key: &[u8]) -> Result<String, CryptoError> {
      let hash = hash(public_key);
      Ok(hex::encode(&hash[0..16]))  // HANYA 16 BYTE!
  }
  ```

  Analisis birthday collision:
  - Ethereum/Bitcoin: 20 byte = 160 bit → collision pada ~2^80 addresses
  - AINCORE: 16 byte = 128 bit → collision pada ~2^64 addresses
  - Pada 2^64 yang perlu di-compute dengan GPU modern: ~beberapa tahun
  - Tetapi lebih mengkhawatirkan: dengan 100 juta user, probability collision meningkat secara significant
  - Juga tidak compatible dengan Move VM AccountAddress yang menggunakan 32 byte

  Ada mismatch fundamental: Move VM menggunakan 32-byte `AccountAddress`, tetapi AINCORE address hanya 16 byte. Format conversion (`0x{16-byte-addr}`) akan padding ke 32 byte dengan leading zeros, tapi ini membatasi namespace.

- **Attack Scenario:**
  1. Pada scale 100 juta+ transaksi, birthday paradox meningkatkan collision probability
  2. Attacker dapat mencari key pairs yang menghasilkan address sama (vanity attack)
  3. Collision address dapat digunakan untuk mengambil alih account atau membingungkan sistem

- **Impact:** MEDIUM saat ini (jaringan kecil), CRITICAL saat mainnet scale

- **Reference:** Ethereum address collision probability analysis (2016); EIP-55 checksum encoding; Sui Move address format (32 bytes)

- **Rekomendasi Fix:**
  ```rust
  // Ubah ke 32 byte (256 bit) — kompatibel dengan Move VM AccountAddress
  pub fn derive_address(public_key: &[u8]) -> Result<String, CryptoError> {
      let hash = hash(public_key);
      Ok(hex::encode(&hash[0..32]))  // 32 BYTE = 256 bit
  }
  
  // CATATAN: Ini breaking change — perlu migration semua existing account dan genesis
  ```

- **Effort:** L (breaking change, memerlukan migrasi seluruh state dan genesis)

---

### HIGH Issues

---

#### H-01: PQC Signature Path (9254 Bytes) Bypass Full Validation di Mempool

- **Layer:** Mempool
- **File:** `core/mempool/src/lib.rs:118-120`
- **Deskripsi:**
  Mempool memiliki dua path validasi signature:
  - 128 hex chars (64 byte) → Ed25519, dilakukan validasi penuh
  - 9254 hex chars → PQC (Post-Quantum Crypto), **hanya di-pass ke executor** tanpa validasi

  ```rust
  } else if parsed_tx.signature.len() == 9254 {
      // Pass PQC validation down to Executor for performance
  } else {
      return Err("Unknown Signature Scheme size".to_string());
  }
  ```

  Namun di `executor/src/lib.rs`, `execute_transaction` hanya mem-validate Ed25519 signature (mengasumsikan 64-byte signature). TX dengan PQC signature (9254 bytes) akan:
  1. Lolos validasi mempool (tidak divalidasi)
  2. Gagal di executor karena `pk_bytes.len() == 32` check akan fail untuk PQC key
  3. Dikembalikan sebagai `None` (silent failure) — gas cost tidak dikenakan

  Ini membuka window: attacker dapat flood mempool dengan TX "PQC" palsu yang lolos masuk tapi gagal eksekusi, menghabiskan slot mempool tanpa biaya.

- **Attack Scenario:**
  1. Attacker membuat TX dengan signature.len() == 9254 (bisa berisi garbage)
  2. TX lolos masuk ke mempool (5000 slot)
  3. TX tidak dieksekusi dengan benar di executor
  4. Attacker memenuhi mempool dengan TX ini, memblokir TX legitimate

- **Impact:** DoS pada mempool — legitimate transactions terblokir

- **Rekomendasi Fix:**
  ```rust
  } else if parsed_tx.signature.len() == 9254 {
      // Validasi minimal: periksa public_key length untuk PQC (Dilithium5 pubkey = 2592 bytes)
      if parsed_tx.public_key.len() != 2592 * 2 { // hex encoding
          return Err("Invalid PQC public key length".to_string());
      }
      // Verifikasi address derivation untuk PQC:
      if parsed_tx.sender.is_empty() || parsed_tx.public_key.is_empty() {
          return Err("PQC transaction missing sender or public key".to_string());
      }
      // TODO: Implementasi pqdsa::dilithium5 verifikasi
  }
  ```

- **Effort:** M

---

#### H-02: Downtime Detection Hanya Dari Perspektif Satu Node — False Positive Slashing

- **Layer:** Consensus
- **File:** `consensus/consensus/src/dag.rs:307-364`
- **Deskripsi:**
  Downtime slashing diimplementasikan berdasarkan perspektif node yang sedang berjalan: jika node tidak melihat vertex dari validator lain selama 100 rounds, validator itu di-jail. Masalah:
  1. Jika validator A dan validator B terisolasi satu sama lain (partition), A men-slash B dan B men-slash A
  2. Kedua validator yang tidak bersalah bisa ter-slash karena network partition sementara
  3. Setelah partition sembuh, keduanya sudah di-jail
  4. Hanya node yang melakukan check (bukan semua validator) yang bisa trigger jail

  ```rust
  // dag.rs:307 — hanya dari perspektif self
  if self.current_round % 10 == 0 {
      for validator_id in &validators {
          let last_seen = ...;
          if rounds_missed >= DOWNTIME_THRESHOLD {
              // JAIL! — tapi hanya dari perspektif satu node
          }
      }
  }
  ```

- **Attack Scenario (Griefing):**
  1. Attacker membuat partisi sementara (misal via BGP hijack atau DDoS) selama 100+ rounds
  2. Setelah partisi, validator yang tidak bersalah sudah di-jail oleh node lain
  3. Slash event masuk ke queue, dieksekusi di block berikutnya
  4. Validator yang tidak bersalah kehilangan 5% stake

- **Impact:** Griefing attack — validator legitimate bisa ter-slash karena network partition

- **Rekomendasi Fix:**
  Downtime slashing harus memerlukan KONSENSUS dari >2/3 validator, bukan keputusan unilateral satu node. Implementasikan downtime evidence yang harus diverifikasi oleh quorum:
  ```rust
  // Downtime detection hanya boleh memicu slash jika:
  // 1. Lebih dari 2/3 validator melaporkan tidak melihat validator X
  // 2. Evidence periode minimal lebih panjang (misal 1000 rounds)
  // 3. Ada cooldown setelah partition recovery
  
  // Interim fix: Naikkan DOWNTIME_THRESHOLD ke 500+ rounds
  const DOWNTIME_THRESHOLD: u64 = 500;
  ```

- **Effort:** L-M

---

#### H-03: Bridge Nonce Counter Di-reset Setiap Restart — Replay Attack

- **Layer:** Bridge
- **File:** `depin/bridge-rust/src/main.rs:87`
- **Deskripsi:**
  `nonce_counter` diinisialisasi ke 0 setiap restart bridge:
  ```rust
  let mut nonce_counter: u64 = 0;
  loop {
      nonce_counter += 1;
      evm_client.mint_tokens(&eth_addr, amount.into(), nonce_counter).await
  }
  ```
  Nonce ini digunakan sebagai parameter ke smart contract `mint(to, amount, nonce, signatures)`. Jika bridge restart, nonce akan kembali ke 1, 2, 3... yang sudah pernah digunakan. Ini memungkinkan:
  1. Replay attack: attacker bisa re-submit TX lama dengan nonce yang sama
  2. Smart contract menerima TX karena nonce valid (sudah digunakan sebelumnya tapi masih dalam range)

- **Attack Scenario:**
  1. Bridge memproses event: mint 1000 AIN ke ETH address X dengan nonce=50
  2. Bridge restart (maintenance/crash)
  3. Bridge memulai nonce dari 0 lagi
  4. Attacker mengirim kembali message dari nonce=50 yang sudah expired
  5. Tergantung implementasi smart contract, nonce bisa diterima lagi

- **Impact:** Double-mint di EVM, kehilangan dana dari bridge

- **Rekomendasi Fix:**
  ```rust
  // Simpan last_nonce ke persistent storage:
  let last_nonce = storage.get("bridge:evm_nonce").unwrap_or("0").parse::<u64>().unwrap_or(0);
  let mut nonce_counter = last_nonce;
  
  // Setelah setiap sukses mint:
  nonce_counter += 1;
  storage.put("bridge:evm_nonce", &nonce_counter.to_string());
  ```

- **Effort:** S

---

#### H-04: ZKP Proof Field Tidak Diverifikasi — Security Theater

- **Layer:** Executor
- **File:** `core/executor/src/lib.rs:1143-1158`
- **Deskripsi:**
  Field `zkp_proof` ada di Transaction struct dan diterima dari user, tapi hanya di-log tanpa verifikasi:
  ```rust
  if let Some(ref proof_hex) = tx.zkp_proof {
      if !proof_hex.is_empty() {
          println!("🔐 Transaction has ZKP proof ({} bytes)", proof_hex.len() / 2);
          // In production, this would verify the STARK proof:
          // ... (commented out)
          // For now, presence of proof is logged for future integration
      }
  }
  ```
  Ini berarti:
  1. TX dengan invalid ZKP proof tetap dieksekusi
  2. TX yang seharusnya dilindungi ZKP dapat dipalsukan
  3. Jika ada logika di frontend yang mengandalkan ZKP untuk privacy, backend tidak menegakkannya

- **Impact:** ZKP field adalah security theater — memberikan false sense of security ke user yang mengirimkan ZKP proof

- **Rekomendasi Fix:**
  ```rust
  if let Some(ref proof_hex) = tx.zkp_proof {
      if !proof_hex.is_empty() {
          use crypto::zkp::STARKProofData;
          let proof_bytes = hex::decode(proof_hex).map_err(|_| ())?;
          let proof = STARKProofData::from_bytes(&proof_bytes)?;
          // Verifikasi menggunakan STARKVerifier
          // Jika gagal: return None (reject TX)
      }
  }
  ```
  Sampai STARK verifier diimplementasikan, TX dengan `zkp_proof` tidak boleh diterima atau harus di-reject.

- **Effort:** L (tergantung penyelesaian Phase 2 STARK implementation)

---

#### H-05: `execute_transaction` Tidak Di-protect BLOCK_EXECUTION_LOCK

- **Layer:** Executor
- **File:** `core/executor/src/lib.rs:527-535` vs `core/executor/src/lib.rs:1063`
- **Deskripsi:**
  `BLOCK_EXECUTION_LOCK` diakuisisi di `execute_block_parallel`, tetapi `execute_transaction` adalah fungsi `pub` yang dapat dipanggil langsung dari context lain (misal sync module atau test) tanpa lock. Individual `execute_transaction` calls dapat race dengan `execute_block_parallel`:

  ```rust
  // execute_block_parallel — ACQUIRE LOCK:
  let _block_lock = BLOCK_EXECUTION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
  
  // execute_transaction — PUBLIC, TIDAK ADA LOCK:
  pub fn execute_transaction(&self, tx_json: &str) -> Option<(...)> {
      // Membaca dan menulis ke DB langsung
  }
  ```

  Jika `sync` module atau test memanggil `execute_transaction` langsung saat `execute_block_parallel` sedang berjalan, state root bisa corrupt.

- **Impact:** State root divergence antara validator — hard fork

- **Rekomendasi Fix:**
  ```rust
  // Jadikan execute_transaction private atau internal:
  fn execute_transaction(&self, tx_json: &str) -> Option<(Vec<(String, Option<String>)>, u128)> {
  
  // Atau: tambahkan lock acquisition di execute_transaction:
  pub fn execute_transaction_safe(&self, tx_json: &str) -> Option<...> {
      let _lock = BLOCK_EXECUTION_LOCK.lock().unwrap_or_else(|e| e.into_inner());
      self.execute_transaction(tx_json)
  }
  ```

- **Effort:** S

---

#### H-06: DAG Checkpoint Tidak Ada Integrity Check — Checkpoint Injection

- **Layer:** Consensus
- **File:** `consensus/consensus/src/dag.rs:61-79`
- **Deskripsi:**
  Saat restart, DAG di-load dari checkpoint menggunakan `serde_json::from_str::<Vec<Vertex>>`. Tidak ada verifikasi bahwa:
  1. Signature setiap vertex valid
  2. Hash setiap vertex benar (hash dihitung ulang == hash di struct)
  3. Checkpoint sendiri belum di-tamper

  ```rust
  if let Some(checkpoint_data) = storage.get_dag_checkpoint(checkpoint_round) {
      if let Ok(vertices) = serde_json::from_str::<Vec<Vertex>>(&checkpoint_data) {
          for vertex in vertices {
              // Langsung dimasukkan ke DAG tanpa verifikasi!
              dag_map.insert(vertex.hash.clone(), vertex);
          }
      }
  }
  ```

  Jika database diakses oleh attacker (misal via path traversal, SQL-like injection ke RocksDB prefix, atau compromised backup), checkpoint yang sudah di-modifikasi bisa di-inject.

- **Attack Scenario:**
  1. Attacker memodifikasi checkpoint di RocksDB (misal jika mendapat akses disk sementara)
  2. Node restart dan load checkpoint yang sudah di-tamper
  3. Vertex palsu masuk ke DAG tanpa verifikasi signature
  4. Consensus berjalan di atas state yang corrupt

- **Impact:** State corruption setelah restart

- **Rekomendasi Fix:**
  ```rust
  for vertex in vertices {
      // Verifikasi signature setiap vertex dari checkpoint:
      if !vertex.verify_ed25519_signature(&author_pubkey_hex) {
          eprintln!("🚨 Checkpoint tampering detected: invalid signature for vertex {}", vertex.hash);
          // Abort checkpoint load, fall back to full scan
          break;
      }
      // Verifikasi hash consistency:
      let computed_hash = vertex.calculate_hash();
      if computed_hash != vertex.hash {
          eprintln!("🚨 Checkpoint tampering: hash mismatch for vertex {}", vertex.hash);
          break;
      }
      dag_map.insert(vertex.hash.clone(), vertex);
  }
  ```

- **Effort:** S-M

---

#### H-07: `aincore_getTransaction` Full DAG Scan O(N) — DoS Vektor

- **Layer:** API
- **File:** `core/node/src/api.rs:292-313`
- **Deskripsi:**
  Handler `aincore_getTransaction` melakukan full scan semua vertices di in-memory DAG:
  ```rust
  'outer: for vertex in dag.values() {
      for tx_str in &vertex.payload {
          // Compute SHA256 of each TX and compare
          // O(N * M) where N = vertices, M = tx per vertex
      }
  }
  ```
  Ini memerlukan DAG lock selama scan berlangsung. Jika DAG berisi jutaan vertex (setelah berbulan-bulan berjalan), request ini dapat:
  1. Memblokir consensus engine yang memerlukan DAG lock
  2. Menghabiskan CPU untuk SHA256 computation
  3. Tidak ada rate limiting spesifik untuk endpoint ini

- **Attack Scenario:**
  1. Attacker mengirim 1000 request `aincore_getTransaction` secara bersamaan
  2. Setiap request mengakuisisi DAG lock dan melakukan O(N) scan
  3. Consensus engine terblokir tidak bisa menambah vertex baru
  4. Network stall selama beberapa detik/menit

- **Rekomendasi Fix:**
  ```rust
  // Buat index TX hash -> vertex hash saat TX dimasukkan ke DAG
  // Simpan di storage: "tx_loc:{tx_hash}" -> "vertex_hash:{hash}"
  // Lookup O(1) bukan O(N)
  
  // Interim: Batasi DAG scan dengan max 100 vertices
  for vertex in dag.values().take(100) { ... }
  ```

- **Effort:** M

---

### MEDIUM Issues

---

#### M-01: Lock Ordering Hazard — Potential Deadlock

- **Layer:** Consensus
- **File:** `consensus/consensus/src/dag.rs:563-583`
- **Deskripsi:**
  Di `add_vertex`, setelah scope pertama (yang memperoleh `dag` lock + `round_idx` lock), ada scope kedua yang memperoleh `ordering_engine` lock + `dag` lock + `round_idx` lock secara bersamaan. Lock ordering yang tidak konsisten antara thread yang berbeda adalah penyebab klasik deadlock.

  ```rust
  // Scope 1: dag + round_idx acquired
  {
      let mut dag = self.dag.lock()...;
      let mut round_idx = self.round_index.lock()...;
      // ...
  } // Dropped

  // Scope 2: ordering_engine + dag + round_idx acquired
  let committed_result = {
      let mut engine = self.ordering_engine.lock()...;
      let dag = self.dag.lock()...;
      let round_idx = self.round_index.lock()...;
      // ...
  };
  ```

  Jika thread lain (misal dari goroutine atau async task) mengambil locks dalam urutan berbeda, deadlock bisa terjadi.

- **Rekomendasi Fix:** Definisikan dan dokumentasikan lock ordering yang ketat: selalu akuisisi dalam urutan `ordering_engine → dag → round_idx`. Gunakan `tracing` untuk debugging lock contention.

- **Effort:** M

---

#### M-02: Threshold BLS Menggunakan Centralized Key Generation

- **Layer:** Crypto
- **File:** `common/crypto/src/threshold/threshold_bls.rs:78`
- **Deskripsi:**
  `generate_shares()` menggunakan master secret key yang di-generate secara terpusat:
  ```rust
  pub fn generate_shares(&self, master_ikm: &[u8; 32]) -> (Vec<u8>, Vec<ThresholdKeyShare>) {
      let master_sk = self.engine.keygen(master_ikm);
      // Split master_sk menggunakan Shamir SSS
  }
  ```
  Dalam skema ini, satu entitas mengetahui master secret key sebelum membaginya. Ini adalah "trusted dealer" model yang tidak aman untuk production — trusted dealer dapat menghitung semua partial signatures sendiri.

  Komentar di kode sendiri: *"In production, use DKG (Distributed Key Generation) so no single party ever knows the full secret key."*

- **Rekomendasi Fix:** Implementasikan DKG (Distributed Key Generation) menggunakan FROST (Flexible Round-Optimized Schnorr Threshold) atau Pedersen DKG sebelum mainnet. Library: `frost-ed25519` atau `threshold_bls` crate.

- **Effort:** L

---

#### M-03: Vote Weight Diambil Saat Voting, Bukan Snapshot — Plutocracy Attack

- **Layer:** Governance
- **File:** `governance/governance/src/lib.rs:245`
- **Deskripsi:**
  ```rust
  let weight = self.query_move_vm_balance(&voter);
  ```
  Vote weight diambil dari balance saat ini pada saat vote, bukan pada saat proposal dibuat (snapshot). Ini memungkinkan:
  1. Whale meminjam token besar sesaat sebelum vote, vote, lalu kembalikan (flash loan governance attack)
  2. Token beredar bisa di-pool sebelum vote untuk mendapat suara super-majority
  3. Vote tidak representatif dari long-term holders

- **Attack Scenario:**
  1. Proposal berbahaya dibuat
  2. Attacker meminjam/mengkonsolidasi token dalam jumlah besar
  3. Vote dengan weight besar
  4. Setelah voting period, kembalikan token
  5. Proposal lolos dengan suara yang tidak legitimate

- **Rekomendasi Fix:**
  ```rust
  // Implementasikan snapshot block: simpan balance snapshot pada saat proposal dibuat
  // Vote weight = balance pada block N (snapshot), bukan balance saat ini
  proposal.snapshot_block = current_block_height;
  // Saat vote: lookup balance di snapshot
  let weight = self.query_balance_at_snapshot(voter, proposal.snapshot_block);
  ```

- **Effort:** M

---

#### M-04: Size Check Dilakukan SETELAH Signature Verification — CPU Exhaustion

- **Layer:** Mempool
- **File:** `core/mempool/src/lib.rs:75-133`
- **Deskripsi:**
  Urutan validasi di `add_transaction`:
  1. Parse JSON ✓
  2. Chain ID check ✓
  3. Gas checks ✓
  4. BCS payload decode ✓
  5. **Signature verification (CPU-intensive)** ← DI SINI
  6. SHA256 dedup ← DI SINI
  7. **Size check (100KB)** ← SEHARUSNYA LEBIH AWAL

  Attacker dapat mengirim TX dengan signature valid tapi payload besar (mendekati 100KB), memaksa sistem melakukan signature verification terlebih dahulu sebelum menolak ukuran. Signature verification adalah operasi paling mahal dalam pipeline.

- **Rekomendasi Fix:**
  ```rust
  // PINDAHKAN size check ke atas (langkah ke-2):
  if tx.len() > 100 * 1024 {
      return Err(format!("Transaction too large: {} bytes > 100KB limit", tx.len()));
  }
  // Baru kemudian parse dan verify
  ```

- **Effort:** S

---

#### M-05: Gossipsub Menggunakan Default Config — Tidak Ada Rate Limiting Per-Peer

- **Layer:** Network/P2P
- **File:** `core/node/src/p2p.rs:65`
- **Deskripsi:**
  ```rust
  let gossipsub_config = GossipsubConfig::default();
  ```
  Default Gossipsub config tidak memiliki:
  1. `max_transmit_size` yang ketat per-peer
  2. `flood_publish` control
  3. `message_id_fn` yang custom (menggunakan content-based ID, rentan sybil amplification)
  4. Per-peer rate limiting

  Sybil attacker dengan banyak peer connections dapat membanjiri topik gossip dengan pesan berulang.

- **Rekomendasi Fix:**
  ```rust
  let gossipsub_config = GossipsubConfigBuilder::default()
      .max_transmit_size(1024 * 1024) // 1MB max
      .validation_mode(ValidationMode::Strict)
      .message_id_fn(|msg| {
          MessageId::from(crypto::hash(&msg.data))
      })
      .mesh_n(6)
      .mesh_n_high(12)
      .mesh_n_low(4)
      .build()?;
  ```

- **Effort:** S

---

#### M-06: `scan_prefix` Iterates Entire DB Prefix — DoS via Sync

- **Layer:** Storage
- **File:** `common/storage/src/lib.rs:113-127`
- **Deskripsi:**
  `scan_prefix` tidak memiliki limit:
  ```rust
  pub fn scan_prefix(&self, prefix: &str) -> Vec<(String, String)> {
      let mut results = Vec::new();
      // No limit! Bisa return jutaan entries
      for (key, value) in iter.flatten() { ... }
  }
  ```
  Digunakan di executor untuk `sys:pending_slash:` dan `sys:fee_sweep_queue:`. Jika ada ribuan entry (misal attacker melakukan self-slash berulang kali), ini bisa menghabiskan RAM.

- **Rekomendasi Fix:**
  ```rust
  pub fn scan_prefix_limited(&self, prefix: &str, limit: usize) -> Vec<(String, String)> {
      let mut results = Vec::new();
      for (key, value) in iter.flatten().take(limit) { ... }
  }
  ```

- **Effort:** S

---

#### M-07: Bridge Event Parsing via String Split — Payload Injection

- **Layer:** Bridge
- **File:** `depin/bridge-rust/src/aincore_client.rs:155-165`
- **Deskripsi:**
  ```rust
  if tx.payload.starts_with("bridge_lock:") {
      let parts: Vec<&str> = tx.payload.split(':').collect();
      if parts.len() == 3 {
          let eth_addr = parts[2].to_string();
          if let Ok(amount) = parts[1].parse::<u64>() {
  ```
  Format `"bridge_lock:AMOUNT:ETH_ADDR"` diparse dengan string split. Masalah:
  1. Jika ETH_ADDR mengandung `:` (tidak standar tapi valid dalam beberapa format), parsing salah
  2. Tidak ada validasi bahwa `payload` adalah BCS-encoded EntryFunction (inkonsisten dengan mempool yang mensyaratkan BCS)
  3. Bridge tidak memvalidasi bahwa TX sender memiliki authorization untuk bridge operation

- **Rekomendasi Fix:** Gunakan BCS-encoded struct untuk bridge TX payload, bukan plaintext format string.

- **Effort:** M

---

#### M-08: `get_validator_set()` Storage I/O di Hot Path

- **Layer:** Consensus
- **File:** `consensus/consensus/src/dag.rs:838-869`
- **Deskripsi:**
  `get_validator_set()` dipanggil di `try_create_vertex()` dan `add_vertex()` — yaitu setiap consensus round. Fungsi ini melakukan RocksDB `get()` dan BCS deserialization setiap kali dipanggil. Pada 1 round per second, ini adalah 1 RocksDB read + potential BCS decode per detik dalam hot path consensus.

- **Impact:** Performance bottleneck, bukan security issue langsung. Tapi bisa menjadi DoS vector jika disertai write amplification.

- **Rekomendasi Fix:**
  ```rust
  // Cache validator set in-memory dengan TTL atau invalidation on write:
  struct DagConsensus {
      validator_cache: Option<(Vec<String>, std::time::Instant)>, // (validators, cached_at)
  }
  // Refresh cache setiap 10 rounds atau setelah epoch advance
  ```

- **Effort:** S-M

---

#### M-09: DA Signing Key Disimpan Plaintext di RocksDB

- **Layer:** DA
- **File:** `da/src/lib.rs:86-99`
- **Deskripsi:**
  ```rust
  if let Ok(Some(key_hex)) = storage.get("sys:da:signing_key") {
      // Load key from DB
  } else {
      let mut rng = rand::thread_rng();
      rng.fill_bytes(&mut key_bytes);
      let _ = storage.put("sys:da:signing_key", &hex::encode(&key_bytes));
  }
  ```
  Private key DA sequencer disimpan sebagai hex string di RocksDB. Siapapun dengan akses baca ke database (backup, snapshot, disk access) dapat mengekstrak private key ini.

- **Rekomendasi Fix:** Gunakan keystore yang ter-encrypt (sama seperti `wallet.key`) untuk DA signing key, bukan plaintext di DB.

- **Effort:** S-M

---

### LOW Issues

---

#### L-01: VDF `verify()` Melakukan Full Re-computation — O(difficulty) Verifikasi

- **Layer:** Crypto
- **File:** `common/crypto/src/vdf/mod.rs:103-108`
- **Deskripsi:**
  ```rust
  pub fn verify(&self, challenge: &[u8], output: &[u8], _proof: &[u8]) -> Result<bool, VDFError> {
      let (computed_output, _) = self.compute(challenge)?;  // Re-compute!
      Ok(computed_output == output)
  }
  ```
  VDF verification melakukan re-computation yang sama lamanya dengan prover. Ini bukan VDF yang sesungguhnya (VDF sejati memiliki O(log t) verification). Dengan difficulty=50, ini masih fast, tapi menunjukkan implementasi yang tidak production-grade.

---

#### L-02: Rate Limiting Tidak Seragam di Semua API Endpoints

- **Layer:** API
- **File:** `core/node/src/api.rs`
- **Deskripsi:**
  `actix_governor` diimplementasikan tapi tidak semua endpoint mendapat perlakuan sama. Endpoint seperti `aincore_getDag` (yang mengambil seluruh DAG) dan `aincore_getTransaction` (O(N) scan) tidak memiliki specific rate limiting yang ketat.

---

#### L-03: `current_round` Tidak Dilindungi Mutex

- **Layer:** Consensus
- **File:** `consensus/consensus/src/dag.rs:13-29`
- **Deskripsi:**
  `DagConsensus.current_round` adalah `u64` public field tanpa mutex protection. Jika `DagConsensus` dibungkus dalam `Arc<RwLock<DagConsensus>>` (di `api.rs` menggunakan `RwLock`), maka multiple readers bisa membaca `current_round` saat writer sedang memodifikasinya. Rust ownership mencegah data race, tetapi logical race (membaca nilai lama) masih mungkin.

---

#### L-04: `from_utf8_lossy` Silent Replacement

- **Layer:** Storage
- **File:** `common/storage/src/lib.rs:123`
- **Deskripsi:**
  ```rust
  let k = String::from_utf8_lossy(&key).into_owned();
  ```
  Bytes yang tidak valid UTF-8 diganti dengan replacement character `\u{FFFD}`. Ini dapat menyebabkan key collision jika dua key berbeda menghasilkan string yang sama setelah replacement.

---

#### L-05: `unwrap()` pada Identifier Statics di Hot Path

- **Layer:** Executor
- **File:** `core/executor/src/lib.rs:430, 1642, 1643, 1655, 1656`
- **Deskripsi:**
  ```rust
  let module_id = ModuleId::new(system_address(), Identifier::new("coin").unwrap());
  ```
  `unwrap()` pada `Identifier::new()` akan panic jika string tidak valid Move identifier. Walaupun "coin" dan "staking" tidak akan berubah, ini adalah bad practice — gunakan `once_cell::sync::Lazy` atau `const` alternatives.

---

#### L-06: P2P Ephemeral Keypair Dibuat Baru Setiap Restart

- **Layer:** Network
- **File:** `core/node/src/p2p.rs:42`
- **Deskripsi:**
  ```rust
  let local_key = identity::Keypair::generate_ed25519();
  ```
  Node identity (PeerId) berubah setiap restart. Peers yang sudah kenal node ini harus reconnect dan melakukan discovery ulang. Ini mengurangi network stability dan mempersulit peer banning.

---

### INFORMATIONAL

---

#### I-01: STARK/SNARK Prover Phase 2 — ZKP Field di TX Tidak Aktif

- **Layer:** Architecture
- **Deskripsi:**
  `STARKProver.prove()` dan `STARKVerifier.verify()` keduanya mengembalikan `STARKError::LibraryError("Phase 2: AIR circuit implementation required")`. Field `zkp_proof` di Transaction diterima dan di-log tapi tidak diverifikasi. Whitepaper menyebutkan ZK private TX sebagai fitur — saat ini jauh dari siap.

---

#### I-02: AccountAbstraction Trait Stubbed

- **Layer:** Architecture
- **File:** `consensus/aa/src/lib.rs` (berdasarkan CLAUDE.md)
- **Deskripsi:**
  `execute_transaction` di AccountAbstraction trait masih kosong (stub). Native AA yang diklaim sebagai fitur pembeda AINCORE belum diimplementasikan.

---

## Architecture Analysis

### Kesesuaian dengan Whitepaper/Roadmap

| Fitur | Status Whitepaper | Status Aktual | Gap |
|-------|------------------|---------------|-----|
| DAG Consensus (Narwhal-lite) | ✅ Target | ✅ Implemented | Bullshark-lite berjalan, tapi VDF tidak sejati |
| Parallel Execution (Rayon) | ✅ Target | ✅ Implemented | Block-STM style, bukan pure Sui object model |
| Move VM | ✅ Target | ✅ Integrated | Berjalan dengan baik |
| Native AA (Ed25519) | ✅ Target | ⚠️ Partial | AccountData ada, tapi AA trait stubbed |
| Sovereign DA | ✅ Target | ✅ Implemented | Erasure coding + fraud proofs ada |
| PoS + Slashing | ✅ Target | ⚠️ Partial | Ada tapi ada C-01 critical bug (reason mismatch) |
| ZK infra (STARK/SNARK) | ✅ Target | ⚠️ Incomplete | Prover belum diimplementasikan (Phase 2) |
| BLS Aggregation | ✅ Target | ✅ Implemented | blst library, proper pairing check |
| Threshold BLS | ✅ Target | ⚠️ Partial | Centralized dealer, bukan DKG |
| BTC Bridge | 🚧 In Progress | ⚠️ Basic | Struktur ada, belum production |
| EVM Bridge | 🚧 In Progress | 🔴 Critical Bug | Ephemeral wallets (C-02) |
| IBC | ❌ Belum | ❌ Belum | - |
| Celestia DA | ❌ Belum | ❌ Belum | - |
| PQC Mainnet | ❌ Belum | ⚠️ Partial | Dilithium5 ada di multi_sig.rs tapi path tidak divalidasi |
| VDF Production | ❌ Belum | ⚠️ Placeholder | Sequential hash bukan VDF sejati |

### Performance Bottlenecks yang Ditemukan

1. **`get_validator_set()` di hot path** — RocksDB read + BCS decode setiap consensus round (M-08)
2. **`aincore_getTransaction` O(N) scan** — Full DAG scan dengan lock held (H-07)
3. **`committed_sequence` linear search** — `find_causal_history` di `ordering.rs:299` melakukan `Vec::contains` yang O(N) dalam loop
4. **`scan_prefix` tanpa limit** — Bisa return seluruh DB prefix (M-06)
5. **VDF re-computation di verify** — O(difficulty) setiap verifikasi (L-01)
6. **DAG checkpoint save** — Serialize seluruh DAG ke JSON setiap 100 rounds (bisa jutaan vertices)

---

## Mainnet Readiness Score

| Layer | Score | Catatan |
|-------|-------|---------|
| Consensus (DAG/BFT) | 6/10 | Equivocation bug (C-01), VDF placeholder (C-03), false-positive slash (H-02) |
| Cryptography | 7/10 | BLS OK, address space kecil (C-04), VDF tidak sejati (C-03) |
| Mempool | 7/10 | Good DoS protection, PQC path bypass (H-01), size check ordering (M-04) |
| Executor | 7/10 | BLOCK_EXECUTION_LOCK ada, ZKP tidak diverifikasi (H-04), lock bypass (H-05) |
| Storage | 8/10 | WAL hardened, paranoid checks, scan_prefix tanpa limit (M-06) |
| Network/P2P | 6/10 | TCP + Gossipsub OK, rate limiting minimal (M-05), ephemeral identity (L-06) |
| API | 7/10 | Rate limiting ada tapi tidak seragam, O(N) scan endpoint (H-07) |
| Bridge (EVM) | 2/10 | CRITICAL: ephemeral wallets (C-02), nonce reset (H-03) |
| Bridge (BTC) | 4/10 | Masih basic, belum production |
| Governance | 6/10 | Timelock ada, plutocracy attack via vote timing (M-03) |
| DA Layer | 7/10 | Erasure coding OK, signing key plaintext (M-09) |
| **Overall** | **5.9/10** | **BELUM SIAP MAINNET** |

---

## Rekomendasi Prioritas (30-Hari Menuju Mainnet)

### Minggu 1 (Critical Fixes)

1. **[C-01] Fix equivocation reason string** — 1 jam, ubah `"double_sign"` ke `"equivocation"` di dag.rs atau perluas kondisi di executor. **PALING PENTING** karena validator jahat mendapat insentif untuk equivocate.

2. **[C-02] Fix bridge multi-sig wallets** — Ganti ephemeral wallets dengan persisten keystore untuk semua signer. Koordinasikan dengan EVM smart contract untuk mendaftarkan semua public keys.

3. **[H-03] Fix bridge nonce persistence** — Simpan nonce ke storage sebelum restart. 1 jam implementasi.

4. **[H-05] Protect execute_transaction** — Jadikan private atau tambahkan lock.

5. **[M-04] Pindahkan size check ke awal mempool** — 30 menit.

### Minggu 2 (High Priority)

6. **[H-01] Implementasikan PQC validation** — Atau nonaktifkan PQC path sepenuhnya sampai implementasi siap.

7. **[H-06] Tambahkan signature verification saat load checkpoint** — Cegah checkpoint injection.

8. **[H-07] Buat TX index untuk O(1) lookup** — Ganti full DAG scan di API.

9. **[M-05] Configure Gossipsub properly** — Tambahkan rate limiting dan validation mode.

10. **[M-09] Encrypt DA signing key** — Gunakan keystore, bukan plaintext DB.

### Minggu 3 (Medium Priority)

11. **[H-02] Revisi downtime detection** — Naikkan threshold dan tambahkan quorum requirement.

12. **[M-03] Implement vote snapshot** — Snapshot balance pada block proposal dibuat.

13. **[M-06] Tambahkan limit ke scan_prefix** — Cegah unbounded memory allocation.

14. **[M-07] Refactor bridge event parsing** — Gunakan BCS-encoded struct.

15. **[M-08] Cache validator set** — Kurangi storage I/O di hot path.

### Sebelum Mainnet (Architecture)

16. **[C-04] Pertimbangkan migrasi ke 32-byte address** — Breaking change, perlu planning matang.

17. **[C-03] Implementasikan VDF sejati** — Wesolowski atau Pietrzak VDF, atau gunakan RANDAO dari BLS threshold sebagai interim.

18. **[M-02] Implementasikan DKG** — Gantikan centralized key generation untuk threshold BLS.

19. **[I-01] Implementasikan STARK verifier** — Atau nonaktifkan field `zkp_proof` di TX struct.

20. **[I-02] Implementasikan AA trait** — Native account abstraction sesuai whitepaper.

---

## Positive Findings

Audit ini juga menemukan banyak hal yang sudah diimplementasikan dengan baik:

1. **BLS implementasi benar** — `blst` library dengan proper pairing-based verification, subgroup checks, dan correct DST. Menggantikan implementasi lama yang broken (symmetric MAC).

2. **`BLOCK_EXECUTION_LOCK`** — Global serialization untuk state root calculation mencegah race condition antar thread.

3. **WAL Hardening RocksDB** — `set_use_fsync(true)`, `set_paranoid_checks(true)`, `set_manual_wal_flush(true)` sudah dikonfigurasi dengan benar untuk durability.

4. **Equivocation Detection** — Sistem double-sign detection di DAG sudah ada dan logikanya benar (sama author, sama round, beda hash).

5. **Tombstone Anti-Replay** — `sys:slashed:{event_id}` tombstone mencegah re-processing slash event yang sama.

6. **Jailed Validator Check** — Sebelum men-jail validator, sistem mengecek `validator:jailed:{addr}` untuk mencegah double-slash.

7. **Keystore Protection di Bridge** — `--keystore` flag di-enforce dengan `process::exit(1)` jika tidak ada, mencegah penggunaan env var.

8. **Chain ID Validation** — Dilakukan di mempool DAN executor, double validation yang baik.

9. **Observer Mode** — Non-validator tidak bisa mine (enforced).

10. **Split-Brain Prevention** — Validator terisolasi berhenti mine.

11. **Rate Limiting API** — `actix_governor` diimplementasikan.

12. **Downtime Detection** — `DOWNTIME_THRESHOLD` sudah ada walaupun threshold dan detection mechanism perlu improvement.

13. **Ed25519 Standard Library** — Menggunakan `ed25519_dalek` yang well-audited.

14. **BCS Payload Enforcement** — Script payload disabled, hanya EntryFunction dan PublishModule yang diterima.

15. **Finality Depth di Bridge** — 100 block confirmations sebelum processing bridge events.

---

## Referensi

1. Spiegelman, A. et al. "Bullshark: DAG BFT Protocols Made Practical" (2022) — arXiv:2201.05677
2. Spiegelman, A. et al. "Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus" (2022)
3. IETF RFC 9380 — "Hashing to Elliptic Curves" (BLS hash-to-curve)
4. IETF draft-irtf-cfrg-bls-signature-05 — "BLS Signatures"
5. Wesolowski, B. "Efficient Verifiable Delay Functions" (Eurocrypt 2019)
6. Pietrzak, K. "Simple Verifiable Delay Functions" (ITCS 2019)
7. Bernstein, D.J. "Ed25519: high-speed high-security signatures" (2011)
8. Move Language Security Best Practices — Aptos/Sui Documentation
9. Ronin Network Post-Mortem (2022) — Sky Mavis
10. Wormhole Bridge Exploit Analysis (2022)
11. Nomad Bridge Exploit (2022) — Merkle proof replay attack
12. RocksDB WAL documentation — Facebook/Meta
13. Ethereum Birthday Paradox Address Collision Analysis (2016)
14. "Flash Loan Governance Attacks" — DeFi security literature
15. libp2p Gossipsub specification — Protocol Labs

---

*Laporan ini dibuat berdasarkan analisis static code dan pengetahuan mendalam tentang blockchain security. Tidak menggantikan audit keamanan formal oleh firma audit independen sebelum peluncuran mainnet.*

*Auditor: Claude Sonnet 4.6 — AI Security Auditor*
*Tanggal: 2026-05-21*
