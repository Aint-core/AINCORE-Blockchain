# Durable QC work after local acceptance

## Reproduced failure

The producer durably accepted/executed block 1 and advanced its ordering/adoption
markers before calling QC production. A subprocess exit at that boundary left
no certificate and no retry record. Reopening and calling `reload_chain_tip`
did not retry, because the tip/adoption height had not changed. The real producer
control created a verifiable QC; the crash/reopen witness failed with
`accepted block permanently lost its QC work across crash/reopen` (exit 101).

The follower had a similar second-write window: ordering adoption could commit
before signing, and subsequent adoption would return `None` for an already
decided anchor. Missing adoption metadata also defaulted to the current tip,
incorrectly treating absence as proof of completed adoption.

## Implementation

- Local block execution, block/index acceptance, ordering bookkeeping, adopted
  height and `consensus:qc_pending:{height:020}` now share one storage transaction.
  A failed pending-record write rejects the acceptance transaction; no block or
  ordering memory is published. Successful QC production itself is still not a
  precondition for block acceptance.
- Follower adoption uses `adopt_synced_anchor_with`: ordering metadata, exact QC
  context and adopted height commit together before publishing engine memory.
  Missing adoption metadata defaults to zero, not the current tip.
- Pending context captures chain, block-height epoch, anchor, executed roots and
  the ordering plan's cumulative finality digest. Stage-time checks compare it
  with the held executed block and plan. Never reconstruct a lost older digest
  from the current tip's digest.
- `try_create_vertex`, `reload_chain_tip` and post-acceptance paths invoke the
  worker, including when no new block arrives. Each invocation processes at
  most eight records using a strict iterator and round-robin cursor. A failed
  old item remains pending but does not starve later heights. The memory cursor
  is only a scheduling hint; restart resets it without losing durable work.
- The worker re-reads each record inside the writer-gated transaction. It checks
  context size (16 KiB), key/height, chain, epoch interval, execution high-water,
  held header fields and recomputed header/body commitments before signing.
  Missing/corrupt/pruned history defers the request without a vote or deletion.
- Existing signer guards still prevent a different vote in the same height or
  anchor slot. Signature guards and QC indexes commit before returning a result.
  Completing a QC and removing its pending record are atomic.
- A partial vote remains pending. Repeated attempts reuse the exact guarded
  signature and can gossip it again; send failure or process exit does not imply
  successful delivery. A later matching verified aggregate retires the work and
  checks/repairs its QC indexes in the same transaction. A node outside the
  trusted historical committee has no signing obligation and retires its item.

This applies the transactional-outbox principle: acceptance and durable work
must share a transaction, while delivery is retried and duplicate processing
must be idempotent. See the primary implementation guidance from
[AWS](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/transactional-outbox.html).
AINCORE does not use AWS queues, and this change does not inherit any external
message-delivery guarantee from that example.

## Local adversarial evidence

The previously failing producer crash/reopen test now passes without advancing
height or changing block 1. The complete certificate verifies against the same
frozen genesis committee as the clean control.

Follower subprocess tests exit immediately before/after adoption's durable
transaction. Before commit every row matches the pre-adoption store; after
commit both pending context and adopted height exist, but no QC has escaped.
Reopen produces the same QC as the actual producer. The follower fixture models
an already accepted sync store using the real producer's block; it is not an
end-to-end network/sync execution test.

Worker tests cover partial replay after reopen, completion by a second signer,
byte-identical guarded votes, eleven malformed/mismatched request cases, changed
body/execution metadata, missing history/committee, bounded fair retry and real
native read-only write failure. Subprocess exits before/after worker publication
compare all rows for complete and partial outcomes; replay is idempotent.

The older read-only adoption regression fixture was corrected to seed the held
block and execution marker in its read-only store. A boundary assertion proves
it reaches the native write attempt rather than passing through an earlier
missing-context rejection.

Verification on the current local worktree:

```sh
cargo test --locked --offline -p blockchain -p chain_sync -p consensus -p executor -p governance -p node -p storage -p vm_move -- --test-threads=1
cargo clippy --locked --offline -p storage -p chain_sync -p consensus -p node --all-targets -- -D warnings
node scripts/tests/block_identity_v2_vectors.mjs
cargo build --locked --offline --release -p node --bins
python3 -B scripts/release_security_gate.py --offline
```

The selected regression suite completed with **471 passed, 0 failed, 13 ignored**.
Strict clippy passed (31.33s), and all V2 JavaScript fixed-vector checks passed.
The ignored count includes known red security witnesses; normal regression
success is not a release or readiness verdict. The three new crash tests are
explicitly required by the separate release witness manifest.

The local node release build passed (17.78s). The actual release witness runner
completed with **7 passed, 7 failed**, exit 1: all three new crash witnesses
passed, while the same seven existing security assertions failed (cargo exit
101, not build failures or timeouts). All 14 required names matched and the
inventory had no unclassified ignored tests. The release gate remains RED.

## Still open

This closes the tested post-acceptance/pre-attestation process-exit window for
newly recorded work. It is NOT complete historical QC backfill or an operational
delivery guarantee:

- Old accepted/adopted blocks without pending records are not automatically
  reconstructed. Missing/pruned adoption history can now stall catch-up instead
  of silently declaring it adopted; recovery needs trusted historical evidence.
- Block and epoch-snapshot pruning do not yet pin dependencies for pending work.
  If those dependencies disappear, the request remains pending and cannot sign.
  Retention coordination and trusted historical reconstruction remain required.
- Work per invocation is bounded, but queue length is not capped and repeated
  deferral has no backoff/rate-limited logging yet. Sustained loss of quorum can
  grow pending storage. Production needs backlog metrics, retention policy and
  resource/backpressure tests; this is not a resource-stability closure.
- The pending record and execution high-water are trusted local state, not a
  state proof. Its captured finality digest is not independently authenticated
  by a legacy block header. A substituted database is still outside this check.
- Legacy block-identity ambiguity, uncertified-DAG safety/liveness, epoch proof
  authentication and state-derived commitments remain open. These changes do
  not convert local ordering/adoption into independently proven finality.
- Disk power loss, disk-full behavior, cross-process gossip delivery and
  sustained multi-operator recovery have not been demonstrated here.

No live node, genesis contents, deployment, reset, commit or push was touched.
