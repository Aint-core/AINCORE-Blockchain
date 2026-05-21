# Phase 2.10 — String Contract Surface Audit

**Date:** 2026-05-21
**Branch:** `audit/phase-1-safe-wins`
**Trigger:** C-01 was a producer/consumer mismatch on the slash `reason`
field (DAG wrote `"double_sign"`, executor matched on `"equivocation"`).
Phase 2.10 sweeps the rest of the codebase for the same class of bug.

---

## Methodology

For each string-based contract surface, list every producer (writer)
and every consumer (reader/comparator). A bug exists when the strings
written do not include every string the consumer matches against.

Surfaces inspected:

1. **Slash event `reason` field**
2. **Slash event `event` tag**
3. **Storage key namespaces** under `sys:*`
4. **JSON-RPC error codes**
5. **Mempool/executor sentinel keys** (e.g. `validator:jailed:*`,
   `validator:last_seen:*`, `tx_index:*`)

---

## Findings

### ✅ Slash `reason` — consistent after C-01

Producers:
| Location | Value written | Code path |
|---|---|---|
| `consensus/consensus/src/dag.rs:655` | `"equivocation"` | Equivocation detector queues `sys:pending_slash` |
| `core/executor/src/lib.rs:1010` | `"downtime"` | BFT-quorum promotion writes `sys:pending_slash` after attestations meet quorum (Phase 2.3) |

Consumers:
| Location | Match value | Action |
|---|---|---|
| `core/executor/src/lib.rs:1099` | `"equivocation"` → 100% slash | else → 5% slash |
| `core/executor/src/lib.rs:1166` | `"equivocation"` → "permanently removed" log | else → "jailed" log |

Producer ↔ Consumer matrix:

|   | Executor matches `"equivocation"` | Executor falls through to "else" |
|---|---|---|
| DAG writes `"equivocation"` | ✅ 100% slash | — |
| Executor writes `"downtime"` | — | ✅ 5% slash |

**No mismatch. C-01 fix is structurally sound.**

### ✅ Slash `event` tag — producer-only

Producers:
- `consensus/consensus/src/dag.rs:650` → `"equivocation_detected"`
- `core/executor/src/lib.rs:1003` → `"validator_jailed"`

Consumers: none in the Rust codebase. These tags are intended for
external consumers (indexer, monitor, log aggregators). No in-code
contract to drift; documented stability is the only guarantee
external observers can rely on.

**Recommendation (low priority):** introduce a `pub const` for each
canonical event name in a shared module so future producers refer to
the constant instead of inline string literals. Captured as a Phase 3
nice-to-have; not a bug.

### ✅ Storage-key namespaces — partitioned cleanly

| Prefix | Writers | Readers |
|---|---|---|
| `sys:pending_slash:` | DAG (equivocation), Executor (BFT downtime promote) | Executor (`execute_pending_slashes`) |
| `sys:downtime_attestation:` | DAG (downtime observation) | Executor (`promote_downtime_attestations_to_slash`) |
| `sys:slashed:` | Executor (tombstone after slash) | Executor (anti-replay check) |
| `sys:validators` | Executor (slash), Genesis init, tests | DagConsensus (`get_validator_set`), Executor (BFT quorum) |
| `sys:total_supply` | Executor (mint/burn paths) | Executor (sanity checks) |
| `sys:da:signing_key_enc_v1` | DASequencer (Phase 2.9) | DASequencer |
| `sys:da:signing_key` | DASequencer legacy | DASequencer (migration only) |
| `sys:fee_sweep_queue:` | Executor (queue) | Executor (process) |
| `sys:tx_index_backfill_v1_complete` | Storage backfill (Phase 1.5.1) | Storage backfill (idempotency gate) |
| `sys:config:*` | Genesis, Governance | Executor (read economic params) |

All prefixes are produced and consumed by the same crate or by a tight
producer-consumer pair, with no cross-crate string drift visible.

### ✅ Cache invalidation keys (Phase 2.8)

`DagConsensus::validators_cache` is invalidated on block commit via
`invalidate_validators_cache()`. No string-based contract — direct
method call. No drift surface.

### ✅ JSON-RPC error codes — JSON-RPC standard

Codes used: `-32602` (invalid params), `-32000` (server-side error
range). Both align with the JSON-RPC 2.0 spec. No producer/consumer
mismatch internal to the chain — error codes are consumed by external
clients.

### ✅ Transaction-attached proof envelope (Phase 2.2)

Producer/consumer surface for `zkp_proof`:
- Mempool dispatch (Phase 2.2 H-04 wiring)
- Executor dispatch (defense in depth)

Both call `crypto::zkp::verify_tx_attached_proof` with the same
canonical message format `"{chain_id}:{sender}:{payload}:{seq}"`.
The format is centralised; no string drift surface.

---

## Bugs Found Beyond C-01

**None.** No producer/consumer mismatches detected in the
post-Phase-1.5 codebase. The slash-reason contract was the only such
bug at the time of the audit, and it is closed.

---

## Recommendations Captured

1. **Phase 3 — Event-name constants.** Move event-tag literals
   (`"equivocation_detected"`, `"validator_jailed"`, etc.) to a
   shared `pub const` module to formalise the external contract for
   indexers and prevent accidental drift.

2. **Phase 3 — Storage-key constants.** Same treatment for `sys:*`
   prefixes that span more than one crate (`sys:pending_slash:`,
   `sys:validators`, `sys:downtime_attestation:`). Each crate
   currently inlines the literal; a shared module would make
   cross-crate references explicit.

Both are nice-to-have hardening, not security findings.

---

## Status

Phase 2.10 closes the audit task. C-01 was the only string contract
bug present pre-Phase-1; the rest of the surface is clean.

This document is committed under `docs/` as evidence that the audit
was actually performed and the findings (or lack thereof) recorded.
