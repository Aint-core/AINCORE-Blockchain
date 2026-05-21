# Phase 2.12 — Panic / Unwrap Hot-Path Audit

**Date:** 2026-05-21
**Branch:** `audit/phase-1-safe-wins`
**Scope:** non-test code in `consensus/`, `core/`, `da/`, `common/`,
`sync/`, `governance/`.

---

## Methodology

For every `panic!`, `unwrap()`, and `expect()` in non-test code,
classify as:

- **INTENTIONAL FAIL-FAST** — startup-time invariants, security
  checkpoints (decrypt failure, DB write failure). Panic is the
  correct response because continuing risks state corruption or
  silent compromise.
- **HARDEN** — could be triggered by untrusted input or runtime
  conditions. Replace with logged error + graceful degradation.
- **OK** — covered by surrounding logic (e.g. unwrap inside a
  successful match arm whose precondition was already checked).

---

## Findings

### INTENTIONAL FAIL-FAST (leave alone)

| File | Line | Reason |
|---|---|---|
| `core/vm_move/src/lib.rs:184` | MoveVM initialization failure at startup | Cannot run without VM; panic exits the process cleanly. |
| `core/executor/src/lib.rs:803` | RocksDB write batch failure | Continuing past a write failure risks divergent state roots → fork. Panic is correct. |
| `common/storage/src/lib.rs` (boot path) | RocksDB open failure | Cannot serve without storage; handled higher in `node/src/main.rs` with structured error message and process exit. |
| `da/src/lib.rs:217` (Phase 2.9) | Encrypted DA key blob malformed at boot | Silently regenerating would orphan past signed batches. Panic forces operator attention. |
| `da/src/lib.rs:232` (Phase 2.9) | DA key decryption failure | Same rationale — wrong identity could be a key-rotation accident OR an attacker swapping identities. Either way: stop. |
| `da/src/lib.rs:164` | ErasureEncoder construction at startup | Configuration error, panic at init is correct. |

### HARDENED IN THIS PHASE

| File | Line | What was changed |
|---|---|---|
| `da/src/lib.rs:333` (was) | `serde_json::to_string(&payload).expect(...)` in the DA batch-creation path | Replaced with logged early-return. DABatchPayload is composed of primitives so serialisation should not fail today, but a future schema change introducing a non-serialisable field would have taken down the DA sequencer with a panic. Now logs `❌ Failed to serialise batch payload` and skips the batch. |

### TEST CODE (intentional asserts, leave alone)

| File | Note |
|---|---|
| `common/crypto/src/zkp/tx_proof.rs:181` | test panic on unexpected error variant |
| `common/crypto/src/zkp/stark.rs:307` | test panic on unexpected error variant |
| `da/src/p2p_protocol.rs:78` | test panic on wrong message type |
| `core/executor/src/lib.rs:1831` | test panic on deserialisation failure |

### LOCK-POISON HANDLING (already audited in Phase 1)

The codebase uses `.lock().expect("🚨 FATAL ...")` consistently for
all consensus locks (DAG, round index, ordering engine, peers,
validator cache). This is intentional: if any of these locks are
poisoned, the node has experienced an internal panic that
compromised consensus integrity, and the only safe action is to
restart. The `🚨 FATAL` prefix makes the operator-visible diagnosis
unambiguous. Pre-existing pattern, not a finding.

---

## Bugs Found

**1 hardening fix** (`da/src/lib.rs:333`). All other panics in
non-test production code were determined to be intentional
fail-fast invariants and are left in place.

The codebase's overall panic discipline is reasonable for an L1
sovereign chain: the panics that exist are at points where
continuing past the error would risk fork-class state divergence,
silent key compromise, or undefined behaviour.

---

## Recommendations (Phase 3+)

1. **Structured shutdown for fail-fast panics.** Today a panic in
   `core/executor:803` (DB write failure) takes down the whole node
   abruptly. A controlled shutdown sequence — flush DA batch queue,
   gossip a "shutting down" notice to peers, release the RocksDB
   lock cleanly — would make the failure mode operator-friendlier.

2. **Replace `lock().expect("🚨 FATAL")` with a process-wide
   `consensus_panic!` macro** that performs the same fail-fast but
   captures backtraces and forwards them to a monitoring sink before
   process exit. Pure ergonomics.

3. **No `unwrap` policy** for any code path that handles network or
   user input. Today there are no such violations; institutionalise
   the rule with a clippy lint (`clippy::unwrap_in_result`) once
   pre-existing legacy unwraps in non-hot-path code are cleaned up.

---

## Status

Phase 2.12 closes the audit task. One hardening fix landed, the
rest of the panic/unwrap surface in production code is intentional
or already safe.
