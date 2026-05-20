# AINCORE — Phase 1 Audit Fix Report

**Date:** 2026-05-21
**Branch:** `audit/phase-1-safe-wins`
**Base:** `28e6bcc` (Solo founder genesis + mount genesis as volume)
**Scope:** Phase 1 "safe wins" from `DEEP-AUDIT-REPORT-2026-05-21.md`

---

## Executive Summary

Phase 1 closed **6 of the 28 audit findings** — selected as the subset that
either fixes a real bug today (C-01) or hardens a real DoS / theatre
surface without breaking any L1 invariant (M-04, M-06, H-07, H-01, H-04).

All changes are guarded by **new regression tests at the contract surface**
that exercise the real cross-module path, not just isolated unit logic.
Future drift on any of these issues will surface in `cargo test`
immediately.

### Coverage Numbers

| Metric | Value |
|---|---|
| Audit findings closed | **6 / 28** (21%) |
| New regression tests added | **6** |
| Workspace tests passing | **246 / 246** ✅ |
| Workspace tests failing | **0** |
| `cargo check` workspace | clean |
| `cargo clippy` workspace | no new warnings introduced |
| Commits | **5** (one per finding cluster) |
| Files touched | **9** |

---

## Findings Fixed

### 🔴 C-01 — Equivocation slash uses canonical reason

**Commit:** `1002186`
**Severity:** CRITICAL → CLOSED

**Bug verified end-to-end:**
- `consensus/consensus/src/dag.rs:510` wrote `"reason": "double_sign"` into
  `sys:pending_slash:{addr}` when equivocation was detected.
- `core/executor/src/lib.rs:841` applied 100% slash only when
  `reason == "equivocation"`. Anything else fell through to the 5%
  downtime tier.
- Existing executor unit test (`test_pending_equivocation_slash_burns_all_stake_and_removes_validator`)
  populated the event directly with `"equivocation"` and so passed despite
  the contract mismatch. The DAG path was never exercised by tests.

**Fix:**
- DAG now writes `"reason": "equivocation"` and the misleading penalty
  string `"5% slash + 21-day unbonding"` is replaced with
  `"100% slash + permanent removal"`.
- New integration test `test_equivocation_queues_canonical_slash_reason_for_executor`
  builds two equivocating vertices, invokes `add_vertex` on both, and
  asserts the queued storage event uses `reason == "equivocation"`. This
  catches any future drift at the real DAG → storage contract surface.

**Impact:** Equivocators are now correctly subject to 100% slash + permanent
removal instead of escaping with the downtime-tier 5%.

---

### 🟡 M-04 — Mempool size guard fires before any parsing

**Commit:** `7147586`
**Severity:** MEDIUM → CLOSED

**Bug verified:**
- The 100KB transaction size cap sat near the bottom of `add_transaction`,
  after `serde_json::from_str`, hex decode, BCS payload parse, and full
  Ed25519 signature verification.
- An attacker could force the node to burn CPU on parsing + crypto for
  arbitrarily large payloads before being rejected.

**Fix:**
- The size check is now the very first statement in `add_transaction`,
  running on the raw `tx: String` with a single `.len()` call.
- New regression test `test_oversized_tx_rejected_before_signature_verification`
  submits a 120KB payload with a deliberately malformed signature
  (`"not-a-signature"`) and asserts the rejection error mentions size,
  not signature. If the guard ever slides back behind signature verify,
  the test fails.

---

### 🟡 M-06 — `scan_prefix` is bounded by default; explicit-limit API added

**Commit:** `9fba239`
**Severity:** MEDIUM → CLOSED

**Bug verified:**
- `StateDB::scan_prefix` materialised the entire matching range into a
  `Vec<(String, String)>` with no upper bound.
- Two executor hot paths (`process_fee_sweep_queue`, `execute_pending_slashes`)
  did `.scan_prefix(...).into_iter().take(N).collect()` — the `take` ran
  AFTER the full materialisation, defeating its purpose under attacker
  pressure on those key spaces.

**Fix:**
- New `StateDB::scan_prefix_limited(prefix, limit)` that bails out after
  `limit` matches and pre-allocates with `min(limit, 1024)` capacity.
- `StateDB::scan_prefix(prefix)` now delegates to `scan_prefix_limited`
  with a `SCAN_PREFIX_HARD_CAP = 100_000` backstop, so every legacy
  caller is protected without an API break.
- Executor hot paths switched to explicit limits: 25 for fee sweep, 5
  for pending slash — matching the original downstream caps.
- New regression test `test_scan_prefix_respects_explicit_limit_and_hard_cap`
  inserts 200 keys, asserts explicit limit is respected, limit-of-zero
  returns empty, and the hard cap constant is sane.

---

### 🟠 H-07 — `aincore_getTransaction` O(1) via atomic tx_index

**Commit:** `3146c0b`
**Severity:** HIGH → CLOSED

**Bug verified:**
- The API used to acquire the consensus read lock, take the DAG lock,
  then iterate every vertex hashing every payload tx looking for a
  match — O(N·M) under lock.
- A `tx_index` helper already existed in `storage` (`index_transaction`,
  `get_tx_block_height`) but was never called from production code
  paths. Only a unit test used it.

**Fix:**
- `StateDB::save_block_json` now writes per-tx `tx_index:{tx_hash} -> height`
  entries inside the SAME RocksDB `WriteBatch` as the block, latest_height,
  and latest_block_hash updates. There is no window where a block is
  observable but its transactions are not yet indexable.
- `consensus/consensus/src/dag.rs` block commit now routes through
  `save_block_json` instead of three separate `put()` calls. Side benefit:
  block + height + hash are now crash-safe (single atomic batch), closing a
  small but real divergence window on power loss.
- `aincore_getTransaction` now does O(1) index lookup → load one block →
  search that block's payload (O(M_block) instead of O(N·M_chain)). No
  consensus locks held.
- On index miss we return `null` instead of falling back to a full scan
  — restoring the scan would let attackers re-introduce the original
  DoS via unknown-hash spam.
- Sync path (`sync/src/lib.rs:418`) already used `save_block_json`, so it
  inherits the indexing for free — no changes needed there.
- New regression test `test_save_block_json_indexes_transactions_atomically`
  asserts both txs in a saved block are reachable via
  `get_tx_block_height` immediately after save, and unknown hashes
  return None.
- Added `sha2` and `hex` as direct dependencies of the `storage` crate
  (they were already used transitively elsewhere; now their use here
  is declared explicitly).

---

### 🟠 H-01 — PQC (Dilithium5) fail-closed at the mempool

**Commit:** `9ef54e2`
**Severity:** HIGH → CLOSED (deferred — sementara)

**Bug verified:**
- Mempool checked `parsed_tx.signature.len() == 9254` (Dilithium5 hex
  length) and silently forwarded the tx down without checking
  `sender == derive_address(pubkey)` and without running signature
  verification at all.
- The VM-layer `verify_native_aa_signature` (vm_move/src/lib.rs:299–373)
  DOES correctly verify Dilithium5, but pushing the check that late
  turned the mempool into a free DoS surface: attackers could flood the
  queue with 9254-char garbage that only got rejected during block
  execution.

**Fix:**
- Mempool now refuses any signature of length `PQC_DILITHIUM5_HEX_LEN`
  (9254) at intake with a clear error pointing users to Ed25519.
- Existing PQC infra is intentionally untouched: CLI keygen still
  works, `vm_move::tests::test_pqc_dilithium_detection` still passes —
  they exercise the VM path directly without going through the mempool.
- The "Unknown Signature Scheme size" branch was retained for any
  other malformed length.
- New regression test `test_pqc_signature_rejected_at_mempool_until_wired`
  submits a fake 9254-char signature and asserts the reject error
  mentions "PQC" or "Dilithium".

**Re-open ticket:** when full Dilithium5 verification (mirroring the
VM-layer logic, plus the canonical sender↔pqc_pubkey binding) is wired
at submission time, replace the reject with the real verification.

---

### 🟠 H-04 — ZKP proof fail-closed at the mempool AND executor

**Commit:** `9ef54e2`
**Severity:** HIGH → CLOSED (deferred — sementara)

**Bug verified:**
- `core/executor/src/lib.rs:1142` checked `if let Some(ref proof_hex) = tx.zkp_proof`,
  logged the proof size, and then carried on as if everything was fine.
- The STARK verifier is not wired into block execution. Accepting txs
  tagged with "ZKP proof" while doing nothing with them is worse than
  rejecting them: it gives users a false sense of additional assurance.

**Fix:**
- Mempool refuses any tx with a non-empty `zkp_proof` field at intake
  with a clear error telling submitters the verifier is not yet wired.
- Executor rejects too as defense in depth — ZKP-tagged txs reaching
  block execution via gossip, sync, or older peers cannot slip past.
- New regression test `test_zkp_tagged_transaction_rejected_at_mempool_until_wired`
  signs a valid Ed25519 tx with `"zkp_proof": "deadbeef"` and asserts
  the reject error mentions ZKP / STARK / fail-closed.

**Re-open ticket:** when the STARK verifier is wired, replace the
executor reject with the real flow: decode proof → bind public inputs
to the tx hash → verify → gate execution on the result.

---

## Findings Deferred to Later Phases

These were intentionally NOT touched in Phase 1 per the agreed strategy
of separating quick safe wins from deep redesigns.

| ID | Title | Why deferred | Target phase |
|---|---|---|---|
| C-02 | Bridge multisig uses ephemeral wallets | Crypto redesign + audit again | Phase 3 |
| C-03 | VDF is sequential hash loop, not real VDF | Pietrzak/Wesolowski impl | Phase 3 |
| C-04 | 16-byte address space (collision risk at scale) | Re-genesis level breaking change | Phase 4 (governance gate) |
| H-02 | Downtime slashing unilateral | Needs BFT vote machinery | Phase 2 |
| H-03 | Bridge nonce resets on restart | Bridge redesign | Phase 3 |
| H-05 | `execute_transaction` lock bypass | Already mostly safe (commit path locked); audit downgraded | Phase 2 |
| H-06 | DAG checkpoint signature verify | Needs migration handling | Phase 2 |
| M-03 | Governance snapshot voting | New voting machinery | Phase 2 |
| M-05 | Gossipsub default config | Needs libp2p config audit | Phase 2 |
| M-08 | Validator set hot path storage read | Cache layer needed | Phase 2 |
| M-09 | DA signing key plaintext in RocksDB | Keystore migration | Phase 3 |
| ... | Remaining ~10 lower-severity findings | TBD | Phase 2+ |

---

## Guardrails Observed During Phase 1

Per the agreed protocol:

- ✅ **No NAS / production deploy.** Branch is local; PR-ready.
- ✅ **No bridge code touched.** All bridge findings deferred.
- ✅ **No 32-byte address migration.** Phase 0 decision honoured.
- ✅ **No agent-lain conflict.** User confirmed no parallel agent active.
- ✅ **Branch isolation.** All commits on `audit/phase-1-safe-wins`,
  base `28e6bcc` on main. Easy revert via `git checkout main && git
  branch -D audit/phase-1-safe-wins` if needed.
- ✅ **`clippy -D warnings` not enforced.** Existing legacy warnings
  preserved. New code introduces no warnings.

---

## Files Touched

```
common/storage/Cargo.toml          (+4 lines)   added sha2, hex deps
common/storage/src/lib.rs          ~+60 lines   save_block_json indexing,
                                                 scan_prefix_limited
common/storage/src/tests.rs        ~+90 lines   H-07, M-06 regression tests
consensus/consensus/src/dag.rs     ~-5 lines    C-01 reason fix + route block
                                                 commit through save_block_json
consensus/consensus/src/tests.rs   ~+95 lines   C-01 regression test
core/executor/src/lib.rs           ~+15 lines   H-04 reject + M-06 callers
core/mempool/src/lib.rs            ~+45 lines   M-04 hoist + H-01/H-04 gates
core/mempool/src/tests.rs          ~+130 lines  M-04, H-01, H-04 regression tests
core/node/src/api.rs               ~-15 lines   H-07 O(1) lookup refactor
```

(Lines are net of the dirty Phase 0–4 work that was already in the
working tree when Phase 1 started — those changes were carried into the
branch as-is and are NOT attributable to Phase 1.)

---

## Verification

Reproduce locally:

```bash
git checkout audit/phase-1-safe-wins
cargo check --workspace            # clean
cargo test --workspace             # 246 passed, 0 failed
cargo clippy --workspace           # legacy warnings only, no new ones
```

Targeted test runs:

```bash
# C-01
cargo test -p consensus test_equivocation_queues_canonical_slash_reason_for_executor

# M-04
cargo test -p mempool test_oversized_tx_rejected_before_signature_verification

# M-06
cargo test -p storage test_scan_prefix_respects_explicit_limit_and_hard_cap

# H-01
cargo test -p mempool test_pqc_signature_rejected_at_mempool_until_wired

# H-04
cargo test -p mempool test_zkp_tagged_transaction_rejected_at_mempool_until_wired

# H-07
cargo test -p storage test_save_block_json_indexes_transactions_atomically
```

---

## Recommended Next Steps

1. **Review this branch** and merge into main if signed off.
2. **Re-run the deep audit agent** against the post-merge main — confirm
   the 6 findings now report CLOSED, surface anything Phase 1 missed.
3. **Decide Phase 2 scope.** Candidate: H-02, H-06, M-03 (medium rework
   tier from the audit report).
4. **Plan Phase 3 separately.** Bridge multisig (C-02) and real VDF
   (C-03) each merit their own design doc + branch.
5. **Treat C-04 as governance, not engineering.** The 16-byte vs 32-byte
   decision should be a community/founder call documented before any
   code change.

---

*Generated by Claude during Phase 1 of the AINCORE deep-audit remediation
sprint. All commits are signed `Co-Authored-By: Claude Sonnet 4.6`.*
