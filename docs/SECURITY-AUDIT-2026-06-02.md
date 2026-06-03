# AINCORE Blockchain — Security Audit Report

**Tanggal:** 2026-06-02
**Metode:** Multi-agent parallel audit + adversarial verification (tiap temuan diverifikasi ulang oleh agent yang tugasnya merefute, biar ga ada false positive)
**Cakupan:** 2 gelombang — Wave 1 (11 layer Rust) + Wave 2 (7 grup smart contract Move)
**Effort:** 95 agent total, ~6.6 juta token, ~750 tool calls, ~27 menit wall-clock

---

## RINGKASAN EKSEKUTIF

**Status: BELUM MAINNET-READY.**

Inti blockchain-nya kuat — crypto (BLS, VDF, STARK), consensus DAG, determinism executor, dan AMM/DEX semua lolos review adversarial tanpa cacat exploitable. Tapi ada **2 CRITICAL** dan **9 HIGH** yang harus ditutup sebelum mainnet. Dua-duanya remote/unprivileged dan berdampak fatal (infinite mint + forge governance). Semua temuan well-localized dan fixable — ini bukan masalah desain fundamental, tapi lubang di boundary layer (RPC auth, scope signing, access control Move).

### Rekap Jumlah Temuan (setelah verifikasi adversarial)

| Severity | Wave 1 (Rust) | Wave 2 (Move) | **Total** |
|----------|:---:|:---:|:---:|
| 🔴 CRITICAL | 1 | 1 | **2** |
| 🟠 HIGH | 6 | 3 | **9** |
| 🟡 MEDIUM | 7 | 4 | **11** |
| 🔵 LOW | 10 | 5 | **15** |
| ⚪ INFO | 3 | 4 | **7** |
| **TOTAL** | **27** | **17** | **44** |

### 2 CRITICAL yang BLOCK MAINNET

1. **Infinite Mint** (`delegation.move`) — cetak AIN dari nol sampai cap 150jt. **Paling bahaya.**
2. **Governance RPC No-Auth** (`api_local.rs`) — forge vote/proposal pakai stake address orang lain tanpa private key.

---

# BAGIAN A — WAVE 1: RUST LAYERS

## A.1 Verdict per Layer

| Layer | Status | Catatan |
|-------|--------|---------|
| **Crypto** | ✅ SOLID | BLS, VDF (L-01 fixed), STARK fail-closed, ECDSA, MultiSig semua sound |
| **Consensus** | ✅ SOLID | BFT quorum, equivocation, vertex-hash integrity semua held. 1 medium (committed_rounds unbounded) |
| **Executor** | ⚠️ 1 HIGH | scheduler address mismatch; lock discipline & gas sound |
| **Mempool** | ⚠️ | design solid, tapi scope signing terlalu sempit |
| **Network** | ⚠️ 1 HIGH + 1 MED | panic OOB slice + no per-IP limit |
| **Storage** | ✅ SOLID | WriteBatch atomicity, WAL durability OK. 1 low |
| **DA** | 🔧 NEEDS WORK | auth lemah, tapi blast radius kecil (modul belum live) |
| **Bridges** | ⚠️ | mostly solid; medium EIP-712 domain separation |
| **Governance** | 🔴 TERLEMAH | CRITICAL + HIGH — Rust RPC path ga lewat Move VM |
| **API-RPC** | 🔧 NEEDS WORK | no rate limit, bind 0.0.0.0, faucet, VDF DoS |
| **Economic** | ✅ core solid | 2 low accounting (treasury supply undercount) |

## A.2 CRITICAL

### 🔴 [CRITICAL] Governance RPC tanpa signature auth
**Lokasi:** `core/node/src/api_local.rs:1027-1075`

**Masalah:** `aincore_createProposal` dan `aincore_vote` di-serve di `0.0.0.0:api_port` tanpa middleware auth. Param `voter`/`proposer` cuma string biasa yang langsung di-pass ke `GovernanceManager`, yang ngambil vote weight dari balance address yang DIKLAIM — tanpa bukti kepemilikan key, dan ga pernah masuk Move VM.

**Exploit:**
1. Attacker query `aincore_getCoinBalance` cari whale W
2. Panggil `aincore_vote` dengan `voter=W, approve=true`
3. Full balance W masuk ke `yes_votes`
4. Ulang ke beberapa whale → quorum 1M AIN tercapai → proposal Passed/Queued — **zero keys, zero stake**

**Mitigasi yang ada:** `execute_proposal` belum di-wire ke RPC — itu satu-satunya alasan mutasi on-chain belum langsung reachable. Tutup lubang auth ini SEBELUM execution di-wire.

**Fix:** Route semua mutasi governance lewat signed-transaction → mempool → Move VM `0x1::governance` (yang udah punya fee burn + vote escrow). Hapus/gate handler RPC yang langsung mutasi. Kalau mau ada RPC convenience, wajib signed payload + verify `voter == derive_address(pubkey)`.

## A.3 HIGH (6)

### 🟠 [HIGH] Parallel scheduler address-format mismatch → state corruption
**Lokasi:** `core/executor/src/lib.rs:1535-1567, 1003-1031`

Sender pakai 32-hex address, recipient pakai 64-hex. Akun yang sama menghasilkan 2 conflict token beda. Transfer DARI A dan KE A masuk batch paralel yang sama → dua-duanya baca A=100 dari committed state → commit last-write-wins → **balance corruption + state root divergen antar node (risiko consensus split).**

**Fix:** Canonicalize semua dependency token ke satu representasi (parse `tx.sender` lewat `parse_move_address`, push `addr.to_string()`). Tambah regression test: transfer-from-A dan transfer-to-A harus beda batch.

### 🟠 [HIGH] Signature TX ga cover gas_limit/gas_price/input_objects
**Lokasi:** `core/mempool/src/lib.rs:297-303, 329-336`

Signed message = `{chain_id}:{sender}:{payload}:{sequence_number}`. Gas fields di luar signature. Relayer/RPC jahat bisa rewrite `gas_price` victim jadi 10.000x, signature tetap valid → victim kebayar fee gila + nonce kebakar → TX asli victim ditolak sebagai duplicate (dedup key juga exclude gas).

**Fix:** Masukin `gas_limit`, `gas_price`, `input_objects` ke canonical signed message DAN ke `canonical_tx_hash`. Update konsisten di mempool (PQC + Ed25519 path), executor, ZKP binding, dan semua CLI signing site.

### 🟠 [HIGH] OOB slice panic → sync task mati permanen
**Lokasi:** `common/network/src/lib.rs:402-418, 539-563`

Frame reader client-side cuma cek upper bound (10 MiB), ga cek lower bound (`msg_len >= 12`), terus slice `enc_msg[0..12]`. Peer kirim frame pendek (len 1-11) → panic → task periodic-sync (bare `loop`) mati permanen sampai restart → node diam-diam ketinggalan/fork. Server-side udah ada guard, client-side LUPA.

**Fix:** Tambah `if msg_len < 12 { return Err(InvalidData) }` sebelum kedua slice site, mirror guard server-loop di `lib.rs:165-167`. Isolate per-peer sync supaya 1 peer gagal ga matiin seluruh cycle.

### 🟠 [HIGH] Rust vote() ga escrow stake → transfer-and-revote inflation
**Lokasi:** `governance/governance/src/lib.rs:256-325`

`vote()` baca live balance sebagai weight, ga pernah lock/decrement. Receipt di-key per-address. Voter vote yes dengan balance B, transfer B ke address baru V2, V2 vote yes lagi (ga ada receipt). Proposal hitung ~2B padahal cuma ada B coin. Ulang N hop → tally membengkak arbitrary.

**Fix:** Lock/escrow stake voter selama durasi proposal (sama kayak Move-VM `0x1::governance` `VoteEscrow`), atau deprecate Rust voting path.

### 🟠 [HIGH] Governance RPC: vote pakai stake address orang lain
**Lokasi:** `core/node/src/api_local.rs:1027-1075`

Akar sama (RPC no-auth). Sebelum whale VICTIM vote, attacker panggil `aincore_vote` dengan `[proposal_id, VICTIM, false]` → seluruh stake VICTIM dihitung NO + receipt ditulis → VICTIM ke-lock out. Attacker steer/block proposal dengan zero stake.

**Fix:** Sama dengan CRITICAL — wajib verified signature dari key voter.

### 🟠 [HIGH] aincore_verifyVDF iteration ga dibatasi → DoS
**Lokasi:** `core/node/src/api_local.rs:1868-1898`

Handler baca `iterations` dari params, pass unbounded ke `VDFEngine::new` + `compute` (loop SHA3 sinkron non-yielding + pre-alloc Vec ~sqrt(difficulty)). RPC jalan di runtime single-thread tanpa rate limiter (Governor cuma di `api.rs` yang dead code). Satu curl `iterations=9e18` → 1 core pegged selamanya; nilai near-u64::MAX → alloc ~100GB → OOM.

**Fix:** Clamp `iterations` ke konstanta kecil (return -32602 kalau lewat). Lebih baik: hapus komputasi VDF server-side dari RPC publik. Tambah rate-limiting middleware.

## A.4 MEDIUM (7)

| # | Layer | Title | Lokasi |
|---|-------|-------|--------|
| M1 | consensus | `committed_rounds` set tumbuh unbounded, matiin DAG pruning | `ordering.rs:15,223,229-231` |
| M2 | network | Legacy TCP server ga ada per-IP connection limit (1 IP saturasi 100 slot) | `network/src/lib.rs:6-8,56-76` |
| M3 | da | Proposer identity check salah struktur (DA-key prefix vs node-address) | `da/src/lib.rs:516-523` |
| M4 | bridges | Mint signature WrappedAIN ga ada chainId/contract domain separation (replay cross-deploy) | `bridge-rust/contracts/WrappedAIN.sol:168-178` |
| M5 | api-rpc | Faucet/test-mint RPC nulis balance langsung ke RocksDB (kalau `AINCORE_ENABLE_FAUCET` set di node asli → unlimited mint) | `api_local.rs:444-606` |
| M6 | api-rpc | Live RPC server ga ada rate limiting + bind 0.0.0.0 (Governor cuma di dead `api.rs`) | `api_local.rs:2254-2289` |
| M7 | da | DA batch handler ga ada validator-set authorization (blast radius kecil, modul belum live) | `da/src/lib.rs:493-549` |

## A.5 LOW (10)

| # | Layer | Title | Lokasi |
|---|-------|-------|--------|
| L1 | executor | Governance `burn_percentage > 100` → u128 underflow / fee over-mint (gated governance) | `executor/src/lib.rs:1113-1120` |
| L2 | da | DAS sampling lapor availability tanpa verify shard vs Merkle (modul scaffold, belum live) | `da/src/sampling.rs:40-86` |
| L3 | mempool | `input_objects` unsigned → object-load gas / scheduler perturbation (subsumed L8 gas fix) | `executor/src/lib.rs:1848-1858` |
| L4 | economic | `ValidatorSet.total_supply` ga hitung treasury reserve → cap undercount 50.000 AIN | `genesis.rs:649-654` |
| L5 | economic | `BASE_REWARD` "per block" salah label; emisi/halving per-epoch | `staking.move:23-28,235-262` |
| L6 | network | Growth unbounded LiDAR rate-limit tracker (memory leak pelan) | `p2p.rs:231-232,272-292` |
| L7 | storage | `prune_old_checkpoints` bocor checkpoint-sig keys, window 10-round meleset | `storage/src/lib.rs:638-653` |
| L8 | bridges | BTC deposit amount ke-overwrite pada multi-output payment (under-credit) | `btc-bridge/src/btc_client.rs:44-50` |
| L9 | api-rpc | Verbose stdout logging full RPC params (disclosure tx payload/address) | `api_local.rs:1964` |
| L10 | economic | `charge_move_to/from` pakai gas heuristic flat regardless size (underpriced large write) | `vm_move/src/gas.rs:256-284` |

## A.6 INFO (3)
- Ed25519 pakai non-strict (malleable) verifier — `crypto/src/lib.rs:156` (canonical-hash dedup nyerap, hardening only)
- Timelock di-apply pas tally, quorum/threshold ga di-snapshot — `governance/src/lib.rs:327-358` (cuma bisa delay, ga ada keuntungan attacker)
- getBlocks off-by-one di dead `api.rs` — `api.rs:400-411` (code path ga live)

---

# BAGIAN B — WAVE 2: MOVE SMART CONTRACTS

## B.1 Verdict per Contract

| Contract | Status | Catatan |
|----------|--------|---------|
| **dex.move** | ✅ SAFE | x*y=k math bener (floor ke pool), first-depositor inflation mustahil, resource linearity solid. Cuma INFO |
| **token_factory.move** | ✅ SAFE | mint authority per-token bener, supply cap enforced, Coin conserved |
| **coin.move** | ✅ SAFE | lubang infinite-mint lama ditutup (mint/burn friend-gated) |
| **delegation.move** | 🔴 CRITICAL | permissionless minting + ga ada slash |
| **staking.move** | 🟠 HIGH | delegated stake ga pernah di-slash |
| **universal_mining.move** | 🟠 HIGH | device registration tanpa proof + oracle issues |
| **epoch.move** | 🟠 HIGH | time source governance-mutable |
| **wbtc.move** | 🟡 MEDIUM | arithmetic bersih tapi operasional belum lengkap (no burn event, no pause) |

## B.2 CRITICAL

### 🔴 [CRITICAL] Permissionless minting di delegation.move
**Lokasi:** `core/vm_move/stdlib/sources/delegation.move:338-369`

**Masalah:** `distribute_delegation_rewards` dideklarasi `public fun` TANPA signer, TANPA `assert!(addr == @0x1)`, dan BUKAN `public(friend)`. Dia mint commission via `staking::mint_reward` (yang juga `public fun` ungated) dan inflate `accumulated_rewards_per_share` untuk `validator_addr` apapun + `total_reward` arbitrary.

**Exploit:**
1. Mempool izinin payload `PublishModule`, VM publish bundle user di bawah address sender
2. Visibility Move ngebolehin `entry fun` user manggil `public fun` non-friend di `0x1`
3. Attacker `enable_delegation` (commission cap 30%) + self-delegate minimum
4. Publish wrapper: `public entry fun go() { 0x1::delegation::distribute_delegation_rewards(@attacker, HUGE) }`
5. Submit, lalu `claim_rewards` → commission di-mint langsung ke attacker + sisa claimable via self-delegation
6. **Drain seluruh sisa AIN mintable sampai MAX_SUPPLY 150jt**

Sistem ga pernah manggil fungsi ini secara sah (verified: ga ada call site di executor/node/consensus).

**Fix:** Gate `distribute_delegation_rewards` DAN `staking::mint_reward` ke system-only. Tambah param `sys: &signer` pertama dengan `assert!(signer::address_of(sys) == @0x1, error::permission_denied(...))`, ATAU jadiin `public(friend)`. Wire reward path supaya sistem yang manggil pas block reward distribution. Tambah unit test: caller non-@0x1 harus abort.

## B.3 HIGH (3)

### 🟠 [HIGH] Delegated stake ga pernah di-slash (Nothing-at-Stake)
**Lokasi:** `core/vm_move/stdlib/sources/staking.move:332-385`

Validator 1.000 AIN self-stake narik 1.000.000 AIN delegasi (ga ada cap yang ngiket ukuran delegasi ke self-stake). Validator double-sign → `slash_validator_bps(.., 10000)` cuma bakar 1.000 AIN self-stake; 1.000.000 AIN di `delegation::ValidatorPool.escrowed_coins` ga kesentuh. Delegator `undelegate` → `withdraw_unbonded` balik 100%. **Attack cost ~0.1% dari stake yang misbehave. Ngerusak keamanan PoS.**

**Fix:** Pas slash, apply `slash_bps` yang sama ke `delegation::ValidatorPool` — kurangi `total_delegated` + tiap `delegation.amount` proporsional, bakar dari `escrowed_coins` via `staking::burn_ain`. Expose `public(friend) fun slash_pool(validator_addr, slash_bps)` di delegation, panggil dari `slash_validator_bps`. Test: `escrowed_coins` & `total_delegated` mengecil setelah slash.

### 🟠 [HIGH] Device registration tanpa proof kepemilikan
**Lokasi:** `core/vm_move/stdlib/sources/universal_mining.move:49-71, 190-206`

`register_device` `public entry`, set `owner_addr = caller` untuk `device_pubkey` apapun tanpa bukti caller punya key itu. Pubkey device inherently publik (di-broadcast di proof). Attacker front-run registrasi device asli; guard duplicate (`EDEVICE_ALREADY_REGISTERED`) lalu permanent lock-out owner asli. Setelah itu tiap reward device itu di-mint ke attacker.

**Fix:** Wajib proof kepemilikan key pas registrasi: caller submit Ed25519 signature atas challenge (misal address-nya sendiri) yang verifiable terhadap `device_pubkey` via crypto native. Jangan percaya first-come registration.

### 🟠 [HIGH] Time source governance-mutable → semua time-lock bisa di-rescale
**Lokasi:** `core/vm_move/stdlib/sources/epoch.move:30-43` (dipakai di `delegation.move:219-331`)

`now_seconds()` return `epoch_number * epoch_duration` (start time hardcoded 0). `delegation.move` simpan unlock timestamp ABSOLUT, tapi maturity check recompute `now_seconds()` terhadap `epoch_duration` SAAT INI. Governance `UpdateEconomicParams` yang naikin `epoch_duration` bikin virtual clock loncat jauh melewati semua `unlock_time` → instant matang semua unbonding → validator yang mau di-slash bisa tarik stake sebelum window 21 hari. Turunin → freeze dana.

**Catatan sekunder:** custom VM mungkin ga bind inner `&signer` args ke authenticated tx sender → `@0x1` signer mungkin forgeable (flagged terpisah, worth confirming).

**Fix:** Jangan derive wall-clock dari counter mutable × duration mutable. Pilih: (a) feed monotonic block timestamp dari VM/native host ke `Epoch`, atau (b) simpan semua delay sebagai epoch count (`unlock_epoch = current_epoch + N`). Minimal: bikin `epoch_duration` immutable setelah genesis + set `epoch_start_time` real.

## B.4 MEDIUM (4)

| # | Contract | Title | Lokasi |
|---|----------|-------|--------|
| M8 | delegation | Reward debt maju walau `mint_reward` return 0 di supply cap → silent reward loss | `delegation.move:285-295` |
| M9 | wbtc | `burn()` destroy wBTC tapi ga emit event + ga ada bridge watcher (BTC payout ga bisa rekonsiliasi) | `wbtc.move:71-96` |
| M10 | universal_mining | Ga ada per-device claim cooldown/nonce — device sama reward tiap block | `universal_mining.move:132-153` |
| M11 | universal_mining | `add_feeder` bikin oracle quorum selalu unanimous N-of-N (1 feeder offline → halt semua DePIN reward) | `universal_mining.move:106-111` |

## B.5 LOW (5)

| # | Contract | Title | Lokasi |
|---|----------|-------|--------|
| L11 | coin/treasury | `coin::mint` ga ada supply accounting/cap; `deposit_fee_reward` mint di luar MAX_SUPPLY tracker | `coin.move:32-34,107-112` |
| L12 | wbtc | `initialize()` ga enforce deploy di `@0x1` padahal reader hardcode `@0x1` | `wbtc.move:34-43` |
| L13 | wbtc | Ga ada pause/circuit-breaker di mint/burn/transfer | `wbtc.move:47-106` |
| L14 | universal_mining | `init_oracle` unauthenticated `public fun` | `universal_mining.move:92-103` |
| L15 | epoch/staking | Konversi epoch-to-seconds divergen (10s vs 60s) untuk window 21-hari sama | `epoch.move:15` vs `staking.move:28` |

## B.6 INFO (4)
- `dex.move` `create_pool` fully permissionless, ga ada admin pause (by design, no theft)
- `dex.move` `deposit` butuh recipient CoinStore exist dulu (UX footgun, atomic revert)
- `token_factory.move` token name/symbol bisa impersonate AincoreCoin (client-side phishing, no on-chain substitution)
- `wbtc.move` `burn()` validasi BTC destination by length only (defense-in-depth)

---

# BAGIAN C — REMEDIATION ROADMAP

## P0 — BLOCK MAINNET (fix dulu, remote + high-impact)

1. **🔴 Infinite mint delegation.move** — gate `distribute_delegation_rewards` + `staking::mint_reward` ke system-only `@0x1`. **PALING URGENT.**
2. **🔴 Governance RPC auth** — deprecate Rust `GovernanceManager` mutating RPC, route ke signed Move-VM pipeline. (1 fix nutup CRITICAL + 2 HIGH governance)
3. **🟠 Delegated stake slashing** — wire `slash_pool` ke `slash_validator_bps`
4. **🟠 Transaction signing scope** — tambah gas + input_objects ke signed message & dedup key
5. **🟠 Parallel scheduler canonicalization** — satu representasi address + regression test
6. **🟠 Sync-task OOB panic** — guard `< 12` di dua frame reader
7. **🟠 verifyVDF DoS** — clamp iterations / hapus VDF compute dari RPC publik
8. **🟠 Device registration proof** — wajib Ed25519 ownership proof
9. **🟠 Epoch time source** — pakai epoch-count untuk lock, bukan absolute timestamp dari counter mutable

## P1 — Fix sebelum mainnet (urgency lebih rendah)
10. RPC rate limiting + default bind 127.0.0.1; hapus dead `api.rs`
11. Faucet/test-mint: build-time cfg gate + mainnet chain-id refusal
12. DA proposer authorization vs `sys:validators` + fix identity derivation
13. WrappedAIN EIP-712 domain separation; align EVM bridge save-before-mint
14. consensus `committed_rounds` → monotonic finalized-round watermark
15. Legacy TCP per-IP connection limit
16. Clamp governance `burn_percentage` ke 0..=100
17. universal_mining: per-device cooldown/nonce + fix oracle M-of-N quorum
18. wbtc: burn event + redemption record + pause

## P2 — Hardening (acceptable post-launch)
19. Genesis `total_supply` include treasury + supply-invariant test
20. Storage checkpoint-sig pruning fix
21. BTC multi-output deposit summation
22. LiDAR tracker eviction
23. Ed25519 → `verify_strict`
24. Size-proportional move_to/move_from gas
25. Reduce verbose RPC param logging ke debug level

---

# BAGIAN D — YANG BELUM DIAUDIT (Honest Gaps)

Area non-fund-critical yang belum masuk scope (bisa nyusul):
- `consensus/aa` + `consensus/account` — Account Abstraction layer (96+27 baris, masih stub per CLAUDE.md)
- `indexer/` — block indexer untuk explorer (1423 baris)
- `monitor/` — Prometheus exporter (187 baris)
- `bench-tps/`, `genesis-tool/`, `move_compiler_tool/`, `utils/` — tooling

Cross-cutting manual follow-up yang disaranin reviewer (bukan finding, tapi pre-mainnet pass):
- Verify crash-recovery handle kondisi state-root-ahead-of-height
- Konfirmasi fraud-proof / light-client path belum live sebelum mengandalkan rating LOW DA
- Audit `0x1::governance.move` source langsung
- Perf-review per-message DH handshake di TCP broadcast fallback
- **Konfirmasi apakah custom VM bind inner `&signer` ke authenticated tx sender** (kalau ga, `@0x1` signer forgeable — bisa naikin severity beberapa Move finding)

---

*Laporan ini di-generate dari audit multi-agent dengan verifikasi adversarial. Tiap temuan udah lolos pass refutasi (verifier yang tugasnya merefute, default `is_real=false`). Severity yang tercantum adalah hasil post-refutation, bukan klaim awal auditor.*
