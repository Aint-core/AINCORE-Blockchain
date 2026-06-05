# AINCORE — P0 Security Fixes Applied (Auditable Report)

**Tanggal:** 2026-06-04
**Branch:** `audit/p0-security-fixes`
**Scope:** 5 P0 fixes (F1–F5) dari audit 2 gelombang + analisa AI eksternal
**Status verifikasi:** ✅ workspace build clean · ✅ clippy `-D warnings` clean · ✅ 76+ tests pass (incl. test keamanan F1 baru)

---

## RINGKASAN

Lima kelas kerentanan total-compromise / DoS ditutup. Yang terpenting: **VM signer-binding (F1)** — root cause yang bikin SEMUA gate `@0x1` di Move bisa di-bypass. Tanpa F1, fix lain (F2 gates) percuma. Urutan apply mengikuti dependency: **F5 → F3 → F2-staking → F1 → F2-delegation → F4**, dengan build+test di tiap langkah.

| Fix | Severity | Nutup |
|-----|----------|-------|
| **F1** VM signer-binding | 🔴 CRITICAL | Forge `@0x1` (atau principal manapun) via BCS arg → full system authority / fund theft |
| **F2** Move system-only mint gates | 🔴 CRITICAL | `distribute_delegation_rewards` + `mint_reward` unauthenticated mint → infinite supply |
| **F3** Governance RPC auth | 🟠 HIGH | Vote/proposal forge tanpa signature → governance capture |
| **F4** Signature scope | 🟠 HIGH | Mutasi gas_limit/gas_price/input_objects pada tx yang sudah ditandatangani |
| **F5** Short-frame panic guard | 🟠 HIGH | Frame pendek dari peer → panic sync task permanen (remote DoS) |

---

## F1 — VM Signer-Binding (KEYSTONE) 🔴

### Root cause (terverifikasi di source move-vm asli)
move-vm-runtime `aptos-v1.3.0` (commit `281f7ec`) **tidak inject signer**. Di `runtime.rs::deserialize_args` (line 229-269), tiap arg termasuk `&signer` di-deserialize dari **raw user bytes** via Signer layout (= `AccountAddress`). Adapter AINCORE (`execute_transaction_actions`) pass `call.args` mentah → user bisa BCS-encode `@0x1` di `args[0]` dan lolos tiap `assert!(signer::address_of(s)==@0x1)`.

### Perubahan (`core/vm_move/src/lib.rs` + `core/executor/src/lib.rs`)
1. **`execute_transaction_actions`**: signature jadi `Vec<(MoveAction, bool, AccountAddress)>` — tiap action bawa `auth_signer` (principal terotentikasi).
2. **Helper baru `bind_signer_args`**: load function signature via `session.load_function()`, hitung leading `&signer` params, **overwrite** slot itu dengan `bcs::to_bytes(&auth_signer)`. Forged signer dibuang.
3. **`execute_public_entry_function`**: pre_actions jadi 3-tuple, main call pakai `sender` sebagai auth_signer.
4. **Call sites executor** (per-action auth_signer):
   - User EntryFunction → `sender_addr` (user cuma bisa act as dirinya)
   - User PublishModule → `sender_addr` (3-tuple arity)
   - `advance_epoch`, `deposit_fee_reward`, gas `deduct_gas`, `slash_validator_bps` → `system_address()` (sistem)
   - ⚠️ `slash_validator_bps` diubah dari `vm_addr` → `system_address()` (kalau tidak, signer slot ke-overwrite jadi vm_addr dan assert `@0x1` malah jebol; target validator dibawa terpisah di `arg_val`)

### Bukti keamanan (test baru)
`test_fix1_forged_signer_cannot_spend_victim_funds` (executor): attacker forge `args[0]` = address VICTIM di `coin::transfer`, tanda tangan pakai key attacker. **Assert: balance victim TIDAK berubah** (5.000.000) + sink tidak menerima. Test ini akan GAGAL di code pre-fix (victim terkuras), PASS sekarang. ✅

---

## F2 — Move System-Only Mint Gates 🔴

### Perubahan
**`staking.move`** (F1-independent, link-time enforced):
- Tambah `friend 0x1::delegation;` + `friend 0x1::universal_mining;`
- `mint_reward`: `public fun` → `public(friend) fun` → tidak bisa dipanggil modul user-published

**`delegation.move`** (DEPENDS ON F1 — diterapkan SETELAH F1):
- Tambah `const EUNAUTHORIZED: u64 = 7;`
- `distribute_delegation_rewards`: tambah param `sys: &signer` + `assert!(signer::address_of(sys) == @0x1, ...)`

### Catatan dependency (kritikal)
`distribute_delegation_rewards` jadi `public entry` = user-dispatchable. Guard-nya HANYA `@0x1` assert, yang baru sound setelah F1 mengikat signer. Makanya patch ini sengaja **diterapkan setelah F1**, bukan sebelum (kalau sebelum = net regression, mengubah fungsi unreachable jadi reachable). Caller sah (`delegate`/`undelegate`/`claim_rewards`) tidak terpengaruh — mereka hanya memanggil `mint_reward`, semua dalam modul friend.

### Bytecode
`staking.mv` + `delegation.mv` di `stdlib/bytecode/` di-regenerate (compiler deterministik — diff hanya 2 modul ini, sisanya byte-identik). Runtime memuat bytecode, jadi ini wajib.

---

## F3 — Governance RPC Auth 🟠

### Perubahan (`core/node/src/api_local.rs`)
Handler `aincore_createProposal` dan `aincore_vote` (yang mutasi state governance dari param string **tanpa autentikasi**, derive vote weight dari balance address yang diklaim) → **dinonaktifkan**, return error `-32040` yang mengarahkan klien submit signed transaction lewat `aincore_sendTransaction` → `0x1::governance::{create_proposal,vote}` (yang lewat mempool: verify Ed25519 + `sender==derive_address(pubkey)` + escrow + fee burn di Move VM).

---

## F4 — Signature Scope 🟠

### Format kanonik baru (byte-identik di SEMUA site)
```
{chain_id}:{sender}:{payload}:{sequence_number}:{gas_limit}:{gas_price}:{input_objects.join(",")}
```
gas_limit `u64` Display, gas_price `u128` Display, input_objects kosong → string kosong (trailing `:`).

### Site yang diupdate (sign + verify + dedup, harus konsisten)
- **Sign:** `cli/main.rs` (5 site: SubmitProof, Send, Publish, RegisterValidator, Faucet), test helper `genesis.rs`/`executor`/`vm_move tests`/`mempool tests` (6 helper), `bench_tps.rs`, `gen_test_tx.rs`
- **Verify:** `mempool/src/lib.rs` (Ed25519 + PQC Dilithium5), `executor/src/lib.rs` (Ed25519 inline re-verify), `vm_move/src/lib.rs` (`execute_transaction` — signature param ditambah `gas_limit, gas_price, input_objects`)
- **Dedup:** `canonical_tx_hash` di mempool ikut 7-field

### Dampak keamanan
Attacker yang memutasi gas_limit/gas_price pada tx yang valid → sekarang **gagal verify** di mempool DAN executor (defense-in-depth). Mengikat juga `input_objects` (mencegah perturbation object-load gas / scheduler).

### Catatan
ZKP proof-binding message (`mempool:178`, `executor:1811`) sengaja TETAP 4-field (STARK masih placeholder; didokumentasikan, bukan defect). Reviewer flag ini untuk rekonsiliasi nanti.

---

## F5 — Short-Frame Panic Guard 🟠

### Perubahan (`common/network/src/lib.rs`)
`secure_connect` welcome-read: tambah `if msg_len < 12 { return Err("Welcome message too short") }` sebelum slice `enc_msg[0..12]`. Mirror guard server-loop yang sudah ada (line 165). `read_encrypted_msg` ternyata SUDAH dijaga (line 603 `!(12..=10MiB).contains`) — hanya `secure_connect` yang bolong.

---

## VERIFIKASI (Bukti Auditable)

```
$ cargo build --workspace
   Finished — 0 error

$ cargo clippy -p vm_move -p executor -p mempool -p network -p chain_sync -p node -- -D warnings
   Finished — 0 warning

$ cargo test (affected crates)
   executor:   35 passed (incl. test_fix1_forged_signer_cannot_spend_victim_funds)
   mempool:    17 passed
   vm_move:     4 passed
   network:     2 passed
   node:        9 + 9 passed (incl. genesis→executor end-to-end signed-tx path)
   consensus:  23 passed
   0 failed
```

### File yang diubah (16 file, fokus security)
```
common/network/src/lib.rs              F5
core/node/src/api_local.rs             F3
core/node/src/p2p.rs                   clippy hygiene (pre-existing, scoped allow)
sync/src/lib.rs                        clippy hygiene (pre-existing)
core/vm_move/stdlib/sources/staking.move      F2
core/vm_move/stdlib/sources/delegation.move   F2
core/vm_move/stdlib/bytecode/staking.mv       F2 (regenerated)
core/vm_move/stdlib/bytecode/delegation.mv    F2 (regenerated)
core/vm_move/src/lib.rs                F1 + F4
core/vm_move/src/tests.rs              F4
core/executor/src/lib.rs               F1 + F4 + test keamanan F1
core/mempool/src/lib.rs                F4
core/mempool/src/tests.rs              F4
core/cli/src/main.rs                   F4
core/cli/src/bin/bench_tps.rs          F4
core/cli/src/bin/gen_test_tx.rs        F4
core/node/src/genesis.rs               F4
```

---

## YANG MASIH TERSISA (belum di-fix — dari audit Wave 1+2)

P0 selesai. Berikut antrian berikutnya (lihat `SECURITY-AUDIT-2026-06-02.md` untuk detail):

**HIGH yang belum:**
- Delegated stake tidak di-slash (`staking.move` — wire `slash_pool` ke `slash_validator_bps`)
- Parallel scheduler address-format mismatch (`executor` — canonicalize dependency token)
- Device registration tanpa proof (`universal_mining.move`)
- Epoch time source governance-mutable (`epoch.move`)

**MEDIUM/LOW:** rate limiting RPC, faucet gating, DA proposer auth, EIP-712 domain separation, committed_rounds unbounded, dll.

**Belum diaudit sama sekali:** `consensus/aa`, `indexer`, `monitor`, Move utility libs (vector/option/string), + konfirmasi apakah custom VM bind inner `&signer` ke tx sender (F1 menutup jalur entry-function; perlu cek jalur lain).

---

*Semua perubahan di branch `audit/p0-security-fixes`. Belum di-commit/push (menunggu instruksi). Patch spec lengkap + review adversarial ada di `P0-REMEDIATION-PLAN-2026-06-04.md`.*
