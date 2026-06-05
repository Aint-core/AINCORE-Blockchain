# AINCORE — HIGH Severity Fixes Applied (Auditable Report)

**Tanggal:** 2026-06-05
**Branch:** `audit/p0-security-fixes` (lanjutan setelah commit P0 `5499495`)
**Scope:** 4 HIGH (H1–H4) dari audit Wave 1+2
**Status:** ✅ workspace build clean · ✅ clippy `-D warnings` clean · ✅ executor 40 tests pass (4 test HIGH baru)

---

## RINGKASAN

| Fix | Severity | Nutup |
|-----|----------|-------|
| **H1** Delegated stake slashing | 🟠 HIGH | Stake delegasi (+ unbonding queue) tidak pernah di-slash → Nothing-at-Stake |
| **H2** Scheduler address canonicalization | 🟠 HIGH | Token konflik 32-hex vs 64-hex → lost-update balance + state-root divergen |
| **H3** Device registration ownership | 🟠 HIGH | Front-run registrasi pubkey → lockout owner asli + curi reward |
| **H4** Epoch time source | 🟠 HIGH | `epoch_duration` governance-mutable me-rescale semua time-lock |

---

## H1 — Delegated Stake Slashing 🟠

**Root cause:** `staking::slash_validator_bps` cuma potong self-stake validator; dana delegasi di `delegation::ValidatorPool.escrowed_coins` ga kesentuh → delegator recover 100% via undelegate. Attack cost ~0.1%.

**Fix:**
- `delegation.move`: `public entry fun slash_pool(sys: &signer, validator_addr, slash_bps)` — system-gated (`@0x1` assert, sound karena F1), potong tiap delegasi aktif proporsional, burn dari escrow via `staking::burn_ain`.
- `executor`: panggil `slash_pool` setelah `slash_validator_bps` (non-fatal).

**Residual bypass yang DITUTUP (di luar spec awal, ditemukan saat review):** `slash_pool` awalnya skip `unbonding_queue` — delegator yang undelegate SEBELUM slash tetap selamat 100% (coins masih di escrow sampai withdraw_unbonded). Standar PoS (Cosmos) keep unbonding stake slashable selama window. **Ditambahkan: loop slash unbonding_queue.** Akuntansi dipisah dua akumulator: `active_slashed` (kurangi `total_delegated`) vs `total_slashed` (active + unbonding, di-burn dari escrow) — karena `total_delegated` ga termasuk unbonding.

**Tests:** `test_pending_downtime_slash_also_slashes_delegated_stake` (delegasi aktif), `test_h1_slash_also_slashes_unbonding_queue` (unbonding + akuntansi total_delegated). Bytecode `delegation.mv` regenerated.

---

## H2 — Scheduler Address Canonicalization 🟠

**Root cause:** `get_tx_dependencies` push `tx.sender` mentah (32-hex) sedang recipient pakai `addr.to_string()` (canonical). Akun sama → 2 token konflik beda → transfer FROM A & TO A masuk batch paralel sama → last-write-wins → balance corruption + state-root divergen (consensus split).

**Fix (`executor`):** `sender_token = parse_move_address(&tx.sender).map(|a| a.to_string()).unwrap_or_else(|| tx.sender.clone())` — canonicalize ke representasi yang sama dengan commit-time key, di-propagate ke semua entry path (transfer, delegation, vote, token wallet). DEX path sudah canonical.

**Test:** `test_h2_transfer_from_and_to_same_account_share_canonical_token`. Tidak ada perubahan Move (no bytecode regen). Review: **APPROVE** (no changes).

---

## H3 — Device Registration Ownership 🟠

**Root cause:** `register_device` set `owner_addr = caller` untuk `device_pubkey` apapun tanpa bukti kepemilikan key. Pubkey publik → attacker front-run registrasi → guard global lockout owner asli + `distribute_reward` bayar attacker.

**Keterbatasan teknis (terverifikasi):** TIDAK ada native Ed25519 di Move codebase ini (cuma `move_stdlib::natives::all_natives`). Verifikasi signature on-chain murni butuh VM native baru (di-flag follow-up).

**Fix pragmatis (`universal_mining.move`):**
1. `owner_addr` selalu = authenticated signer (dijamin F1 bind_signer_args).
2. Duplicate guard di-scope ke `(owner_addr, device_pubkey)` → front-runner ga bisa lockout owner asli.
3. Field `verified: bool` + `add_verified_device(feeder, owner, pubkey)` feeder-gated → cuma feeder (trust anchor yang sama dengan reward finalization) yang bind device ke owner.
4. `distribute_reward` cuma bayar binding yang `verified` → registrasi front-run unverified dapat NOL.
5. `genesis.rs` DeviceInfo mirror diupdate (field `verified` sebelum `device_type`, BCS order).

**Test:** `test_h3_no_lockout_and_only_verified_owner_is_bound`. Bytecode `universal_mining.mv` regenerated.
**Follow-up (di-track):** tambah native `0x1::ed25519::verify` untuk proof on-chain trustless.

---

## H4 — Epoch Time Source 🟠

**Root cause:** `now_seconds() = epoch_start_time + epoch_number * epoch_duration`. `epoch_duration` governance-mutable. Karena dikali ke cumulative `epoch_number` dengan duration live, ubah duration me-rescale SEMUA waktu yang sudah lewat → unbonding lock matang/beku instan → validator yang mau di-slash tarik stake sebelum window 21 hari.

**Fix (`epoch.move`):** `epoch_start_time` jadi **akumulator monotonic** — `advance_epoch` nambah `+ epoch_duration` (current) tiap epoch; `now_seconds()` return akumulator langsung. Ubah duration cuma efek ke increment masa depan, ga bisa rescale waktu yang sudah terakumulasi. `delegation.move`/`staking.move` tidak perlu diubah (staking sudah immune — pakai EPOCH_SECONDS const).

**Test:** `test_h4_duration_change_does_not_rescale_elapsed_time` — seed state pasca-duration-change (num=100, dur=1e9), advance 1×, assert clock maju 1 duration (1000+1e9), BUKAN num×dur. Gagal di code lama. Bytecode `epoch.mv` regenerated.
**Catatan:** migrasi untuk chain yang SUDAH mutate epoch_duration — moot karena mainnet belum launch.

---

## VERIFIKASI

```
cargo build --workspace ............ 0 error
cargo clippy -D warnings ........... 0 warning
cargo test:
  executor:  40 passed (4 test HIGH baru: 2x H1, H3, H4)
  consensus: 23 · mempool 17 · network 2 · node 9+9 · vm_move 4
  0 failed
```

Bytecode regen verified: tiap recompile, HANYA modul yang diubah berbeda dari baseline (delegation.mv, epoch.mv, universal_mining.mv), sisanya byte-identik (compiler deterministik).

### File diubah (8)
```
core/executor/src/lib.rs                       H1 (unbonding fix) + H4 test + H3 test
core/node/src/genesis.rs                       H3 (DeviceInfo mirror)
core/vm_move/stdlib/sources/delegation.move    H1 (unbonding slash + accounting)
core/vm_move/stdlib/sources/epoch.move         H4 (monotonic clock)
core/vm_move/stdlib/sources/universal_mining.move  H3 (verified gate)
core/vm_move/stdlib/bytecode/{delegation,epoch,universal_mining}.mv  regen
```
(H1 slash_pool + H2 scheduler base sudah di working tree dari fase spec; di-review + dilengkapi di sini.)

---

## SISA SETELAH INI

P0 (2 CRITICAL + 3 HIGH) + HIGH (4) = **selesai**. Sisa dari audit:
- MEDIUM: rate limiting RPC, faucet gating, DA proposer auth, EIP-712 domain separation, committed_rounds unbounded, dll.
- LOW/INFO: lihat `SECURITY-AUDIT-2026-06-02.md`.
- Follow-up arsitektur: native Ed25519 untuk H3 trustless, RSA-VDF migration, STARK verifier real.
- Belum diaudit: `consensus/aa`, `indexer`, `monitor`, Move utility libs.
