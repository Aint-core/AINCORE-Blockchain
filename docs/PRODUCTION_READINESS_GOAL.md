# Production Readiness Goal

Started: 2026-09-12. Baseline: `5f69e26`, `audit/mainnet-hardening`.

## Objective and limits

Bring AINCORE toward production L1 engineering quality, using established
networks such as Ethereum as a standard of rigor, not a claim of equal security,
economic security, decentralization, compatibility, or operational history.
"Perfect" is an aspiration, not an achievable audit verdict.

Local implementation and isolated tests may proceed incrementally. Preserve
unrelated working-tree changes. Do not deploy, restart live services, reset a
chain, modify genesis, or migrate validator identity without explicit approval.
Never fault-inject against the user's live nodes.

## Evidence rules

- Record the source commit, relevant code path, test command and actual outcome.
- Separate static findings, executable reproductions, and live observations.
- A passing test only establishes its stated property under its tested model.
- A failing witness remains an open issue, not a completed remediation.
- Each fix needs a positive control, a negative witness, and regression coverage.
- Protocol changes need a safety AND liveness argument, including stake weights,
  epochs, crash recovery, pruning, and heterogeneous message arrival.
- Track ignored security regression tests explicitly; default-suite green is not
  clearance when relevant witnesses are skipped.
- Independent review and operational evidence cannot be replaced by self-review.

## Ordered release gates

| Gate | Required evidence | Initial state |
|---|---|---|
| G0: Reference and block identity | Forged parent author/round cannot reach an orderable DAG; block identity binds all consensus fields; gossip, fetch, and recovery agree | Parent proof enforcement implemented locally; signed block substitution reproduced through sync persistence, canonical version/activation contract still open |
| G1: Consensus and retrieval | One coherent contract for equivocation, parent retrieval, candidate decisions, ancestry, epochs, and pruning; no conflicting decisions and eventual progress under stated assumptions | Open |
| G2: Crash consistency | Crash at every durable block-execution boundary; recover to the same state as clean replay without duplicate effects or partial-block acceptance | Local producer stages ordering/state/block together; sync stages checked state/block and rejects destructive partial reorgs; authenticated fork recovery, post-commit QC recovery, legacy torn DBs and broader fault coverage remain open |
| G3: State authentication and rejoin | Authenticate snapshot contents and validator-set transitions from a documented trust anchor; rejoin across every retention horizon | Open; current root is history-of-writes based |
| G4: Network isolation | Explicit session authentication, bounded requests/queues/storage/CPU, and validator connectivity under abusive traffic | Open; serving budgets alone are insufficient |
| G5: Execution and economics | Differential replay, abort semantics, nonce/fee/reward/slash/supply invariants, module upgrades and deterministic scheduling under transaction load | Full reassessment required; do not erase prior fixes |
| G6: Public testnet release | Fresh-machine onboarding for supported OS/architectures; pinned artifacts/genesis, recovery docs, correct monitoring, measured failure domains and published limitations | Not cleared |
| G7: Mainnet decision | G0-G6 evidence, no unresolved critical/high launch-scope defects, independent audit/retest, operational recovery/upgrade exercises and explicit risk acceptance | Not cleared |

G6 is a no-value engineering testnet, not authorization to accept public funds.
Disable or explicitly constrain bridges, privacy, external DA, or other optional
features unless their complete trust model and launch path have been audited.
No fixed number of soak days substitutes for these gates.

## Initial reproduction (historical baseline)

Tests added in `consensus/consensus/src/tests.rs`:

- `test_parent_body_identity_rejects_forged_round`
- `test_parent_body_identity_rejects_forged_author`

Both use real signatures, production `DagConsensus::add_vertex`, temporary
RocksDB storage, four known validators, and already-held parent bodies. A genuine
child is admitted as a positive control. The desired assertion is that the forged
child reaches neither the live DAG nor `vertex:{hash}` storage. Initially these
were ignored security witnesses, not fixes; the baseline command was:

```sh
cargo test --locked --offline -p consensus --lib test_parent_body_identity_rejects -- --ignored --nocapture --test-threads=1
```

Outcome on baseline `5f69e26` plus these test-only changes: compilation succeeded;
both explicitly selected witnesses FAILED at the desired rejection assertion
(0 passed, 2 failed, 101 filtered out). Each positive-control child was admitted.
For both forged children, `admitted=true` and `persisted=true` despite all actual
parent bodies being present. The failure is not a signature or fixture setup
failure: the production ingress accepted and persisted the mismatched reference.
This reproduces an admission defect, not a full finality fork, partition recovery,
or the crash-consistency finding. No production fix existed at that stage.
Do not fix only the already-held-body branch and claim completion: orderability
must also be safe before a delayed parent arrives and after restart.

Focused baseline regression command:

```sh
cargo test --locked --offline -p consensus --lib parent -- --test-threads=1
```

Result: 5 passed, 2 ignored, 96 filtered out. The two ignored cases are the same
open witnesses explicitly run above. This result does NOT override their failed
security assertions or establish that the complete consensus suite is green.

## Recovery increment

An independent recovery blocker was reproduced while tracing parent persistence.
`DagConsensus::new` rejected unusable checkpoints but still skipped disk vertices
at or below their advertised round. Five restart cases (unsigned, bad signature,
malformed signature, missing payload, and signed malformed JSON) each recovered
only round 3 despite retaining rounds 1-3 on disk. A valid signed checkpoint plus
tail was the positive control: 1 passed, 5 failed before the fix.

The local fix tracks the checkpoint round actually loaded, rather than trusting
the advertised checkpoint pointer as the scan cutoff. These tests use isolated
temporary databases, flush/drop/reopen them, and check both the DAG and its index.
Rejected checkpoint-only records must not leak into recovery.

The first full regression after this fix returned 99 passed, 1 failed, 9 ignored.
The failing old unsigned-checkpoint test incorrectly asserted an empty recovered
DAG although its producer had persisted individual vertex rows. Its fixture now
explicitly removes those rows to isolate checkpoint rejection; separate fallback
tests require retained rows to be recovered. Post-fixture verification:

```sh
cargo test --locked --offline -p consensus --lib -- --test-threads=1
```

Result: 100 passed, 0 failed, 9 ignored (109 total), including all six new
checkpoint fallback/control tests. Ignored defect witnesses and exploratory
probes are not evidence of safety. The full workspace, release build, live
restart behavior, and independent review were not verified by this command.
The two parent-identity witnesses were rerun explicitly after this recovery fix:
both still failed with `admitted=true, persisted=true` (107 filtered out). They
remained open at that stage; the subsequent identity repair is recorded below.

This cutoff fix alone is not whole-block crash atomicity, authenticated state
sync, or parent-reference validation. The subsequent identity integration tests
cover structural rejection inside signed checkpoints. Full crash-boundary and
round-cursor integrity coverage remain required before declaring G2 complete.
No live deployment, reset, or genesis change has been performed.

## Parent identity repair (local, not deployed)

`ParentRef` now carries an optional-on-decode `ParentIdentityProof`, mandatory for
acceptance of round > 1 vertices. The proof contains the parent timestamp,
payload root, parents root, Ed25519 public key, and signature. Verification derives
the declared author address from that public key, reconstructs the parent's
existing domain-separated compact header hash from the claimed round/author and
proof, matches it to the referenced digest, and verifies the parent's signature.
Roots have canonical fixed-length hex encoding. No new cryptographic primitive
or signing domain was introduced. This is not a BLS quorum certificate or a
Narwhal availability certificate.

The child hash continues to commit to `(round, author, digest)`, not to the
transport witness. Missing or invalid witness bytes are refused even when the
child hash/signature is unchanged; a later valid copy can be accepted. This is
analogous to keeping signature evidence separate from the message it verifies.
It is NOT a claim that arbitrary invalid packet variants cannot stress transport
dedup/rate-limit policies; tests here exercise `handle_message` and `add_vertex`,
not every network implementation's message cache.

The producer supplies these proofs from real held parents. Ingress and all three
boot paths enforce the same identity predicate. A child can be identity-verified
before parent bodies arrive, and its stored proof survives deletion of those
bodies. A partially rejected checkpoint cannot authorize a tail-only scan:
individually verified entries are retained, including entries absent from disk
rows, while all retained disk rows are scanned with hash deduplication.

Tests: the two original forged-author/round witnesses are now normal, non-ignored
regressions. `consensus/consensus/tests/parent_identity.rs` additionally exercises
late bodies, malformed/missing proofs, valid retransmission after rejection,
pruning and restart, scan/checkpoint/tail recovery, no legacy grandfathering,
cross-domain rejection, fixed proof size with a growing parent payload, and
noncanonical roots even when the reconstructed header has a valid signature.

Verification on the local patch:

```sh
cargo test --locked --offline -p blockchain -p consensus --lib --test parent_identity -- --test-threads=1
cargo clippy --locked --offline -p blockchain -p consensus --all-targets --no-deps -- -D warnings
cargo check --locked --offline -p node --bins
```

Tests: blockchain 12 passed; consensus 102 passed, 7 ignored; parent-identity
integration 10 passed. Total 124 passed, zero failed. Both original identity
defect witnesses now execute in the default suite. The remaining ignored
ordering/equivocation witnesses and exploratory probes have not been cleared.
Strict clippy passed after replacing an existing single-pattern `match` in the
H3 test with equivalent `if let`; its assertion was preserved.
Node binary build-check passed. This is not a release build, a whole-workspace
test run, or a live-node test. No deployment or genesis change was performed.

### Compatibility gate (OPEN)

This is a consensus validity-rule change even though existing vertex hashes are
unchanged. Old readers can ignore proof fields; new readers refuse old round > 1
vertices lacking proof. A rolling mixed-version deploy is NOT approved. Older
databases/checkpoints may lack the necessary evidence after pruning and must not
be silently grandfathered. No automatic migration or protocol activation gate
has been implemented. Before release, design and test coordinated activation and
evidence-complete bootstrap/migration, or seek explicit approval for a reset.
Do not start this binary on live data under the old genesis-version guard merely
because the hash format is unchanged. No genesis file/version was modified.

### Remaining availability and ordering work

The previous `ParentRef` documentation overstated the signed-preimage guarantee:
the child signature binds the child's CLAIM about each parent's author and round;
it does not authenticate the truth of that claim. The two executable witnesses
above demonstrate this distinction against the production gate.

The full causal-availability contract still needs to distinguish three outcomes:

- Invalid: resolved parent identity contradicts its reference, or authenticated
  structural/committee rules fail.
- Pending: required body or authenticated historical committee evidence is not
  yet available. Pending must not mean permanently rejected or orderable.
- Eligible: the complete required dependency set is authenticated and bound to
  the exact referenced identities, with a justified finalized-history boundary.

Inline parent signatures resolve the identity portion without a possession test;
they do not resolve missing causal bodies or authenticate an entire snapshot.
The remaining contract must cover proposal parents, quorum-round advancement, anchor ordering,
network ingestion, and boot recovery. Pending work needs bounded accounting,
fair dependency retrieval, and an explicit wake-up path after parent arrival.
Pruned history cannot be blindly accepted by digest, nor required forever as a
body that has already been deleted. A recovery trust boundary is part of the
contract, not an exception added after tests pass.

Do not implement the refuted `DAG_VERTEX_SYNC_DESIGN.md` v3 stages as written.
Its own critique demonstrates that citation discipline without retrieval can
strand honest nodes. Conversely, fetching losing equivocation twins without
repairing arrival-order leader decisions can expose conflicting decisions.
Those coupled properties need one reviewed integration and adversarial schedule
suite; the recovery cutoff fix above is independent of that protocol redesign.

## Ordering metadata durability increment (local, not deployed)

Re-ran H1 against the parent-identity repair:

```sh
cargo test --locked --offline -p consensus --lib test_h1_dropped_twin -- --ignored --nocapture --test-threads=1
```

Result: 0 passed, 1 failed at P_VIEW_EQ. Two nodes receiving the same two signed
round-1 vertices in opposite order retain different live vertex sets. The local
restart control passes. Important correction to the witness's old prose: the
losing FULL BODY is absent from the live DAG / vertex store, but canonical compact
equivocation evidence IS stored by `apply_equivocation_slash`. This run is not a
new end-to-end finality-fork proof. H1 and the coupled decision/retrieval rules
remain OPEN; no naive twin-insertion patch was applied.

An independent fault was then reproduced in `OrderingEngine::apply_anchor_bookkeeping`:
it updated memory first, issued separate durable writes, and ignored I/O errors.
The new `ordering_persistence_tests.rs` harness uses temporary RocksDB databases,
normal-reopen controls, and a child process that exits without dropping RocksDB.
Test-only hooks bracket the first durable write; they are absent in production.
After the repair they bracket the sole atomic batch instead of the first of
several independent writes.

Before the fix, the persistence suite returned 1 passed (child entry), 2 failed:

- Crash after the first write: the restored engine reports finalized 260 and
  cursor 261, but retains round 2's digest and anchor, with no round-260 sequence.
- A real RocksDB read-only write failure still returns a successful CommitInfo
  and advances the engine's in-memory state.

The repair stages the next state and writes the committed-round set, per-round
sequence, evictions, finality high-water mark, cursor, anchor identity, and digest
in ONE `StateDB::write_batch` (existing sync-WAL API). It publishes memory and
returns CommitInfo only after that write succeeds. A write failure returns None
and logs the error; both local commit and synced-anchor adoption use this path.
The key layout and consensus decision algorithm are unchanged.

After the fix, tests cover both atomic-write boundaries, normal reopen, pruning
of the old cseq row, reconstructed beacon, and real write errors on BOTH callers.
The same engine retries after storage reopens writable; the result matches a
clean execution and a duplicate attempt does not fold the digest again.

Caller integration exposed another failed regression: `reload_chain_tip` marked
height 1 adopted even when the ordering-store write failed, and only retried on
a NEW tip. It now keeps the adoption cursor unchanged on an unpersisted anchor
and retries a pending backlog at an unchanged tip. The node-level test uses a
read-only ordering store plus an already-saved signed block in a writable block
store, then restores writable ordering storage without advancing the chain tip.
It verifies adoption occurs once and duplicate reload does not fold the digest.

```sh
cargo test --locked --offline -p blockchain -p consensus --lib --test parent_identity -- --test-threads=1
```

Result: blockchain 12 passed; consensus 107 passed, 7 ignored; parent-identity
integration 10 passed. Total 129 passed, zero failed in this default selection.
Four new unit test entries include the subprocess entry point and three driver
tests; a fifth test covers node-level adoption retry. The separately selected H1
witness still fails; default-suite green does
not override it.

Final verification on this increment also passed strict clippy and node binary
build-check:

```sh
cargo clippy --locked --offline -p blockchain -p consensus --all-targets --no-deps -- -D warnings
cargo check --locked --offline -p node --bins
```

The final-tree explicit H1 run again returned 0 passed, 1 failed (113 filtered).
No release build or whole-workspace test pass is claimed for this increment.

Scope: process exit before/after the single durable metadata write, not power-loss
testing during RocksDB internals. No automatic repair of already-torn legacy
metadata is provided. Ordering metadata still commits BEFORE transaction execution
and block storage (`dag.rs` calls `try_commit`, then the executor, then
`save_block_json`); all three are NOT one transaction. Whole-block crash recovery,
authenticated snapshots, committee-transition binding, and G1 remain release
blockers. No live services, genesis, or validator identities were changed.

## Executor crash witnesses and bounded containment (historical)

The next G2 increment uses real signed Move transfers, not marker-only mocks.
`core/executor/src/block_crash_tests.rs` creates an isolated database with the
compiled standard library, funded accounts, two transfers from the same sender
(nonces 0 and 1), fees and receipts. Separate execution batches are necessary:
the second transfer must read the first transfer's account writes. Child-only
environment variables pin the chain ID; no parent-process or live-node config
is changed. The epoch interval is pinned above the fixture height.

The child exits with code 77 at test-only boundaries, without destructors or
graceful RocksDB close. The driver reopens the DB and compares ALL key/value rows
against complete pre-state and a clean execution. This is process-crash evidence
between acknowledged writes, not simulated power loss inside RocksDB. Whole-DB
materialization is confined to this small test fixture, not a production design.

| Boundary | Required property | Measured result |
|---|---|---|
| Before the first execution write | Complete old state | PASS |
| After the first transaction batch | Old or complete new state | FAIL: partial state, no root or executed-height marker |
| After state root, before executed height | Old or complete new state | FAIL: new root/state with no executed-height marker |
| After executed height | Complete execution post-state | PASS; this does not include persisted block/ordering/QC |
| Restart/replay after first transaction batch | Same full state as clean execution | FAIL: retry consumes height 1 with a different root; the first nonce is already consumed |
| Restart/replay after root write | Same full state as clean execution | PASS for this fixture; not a universal recovery guarantee |

Initial unsplit selection: 2 passed, 3 failed. The replay test initially stopped
at its first failed boundary; it was split so both replay outcomes are measured.
No witness was weakened or marked ignored to obtain green results.

Two adjacent faults were separately reproduced and repaired locally:

1. `execute_block_parallel_at` recovered a poisoned `BLOCK_EXECUTION_LOCK` with
   `into_inner()`. A subprocess injects a Rust panic after the first real batch,
   catches it, and creates a NEW Executor over the same DB. Before the fix, retry
   returned Executed with only the second transaction and a divergent root.
   The lock acquisition now rejects poison instead of authorizing continued
   execution. The same test passes and verifies that retry writes nothing.
   This propagates a panic to the caller; it does NOT guarantee whole-process
   shutdown, handle every possible panic context, or survive process restart.
   Rust documents poisoning as advisory, not a transaction or recovery protocol.
2. `ChainSync::process_blocks` treated AlreadyExecuted with no parseable stored
   block as a successful sync step. The new signed-block regression initially
   returned height 1 despite no `block_1` and storage height 0. It now stops the
   batch without advancing for absent, unreadable, or conflicting stored blocks.
   A matching persisted block permits retry to advance; duplicate retry is a
   no-op. The fixture checks DB rows do not change on refusal. Missing storage
   does not prove a fork: it may also be an in-flight producer, so this does not
   ban the peer or assert automatic recovery of a genuinely torn block.

Verification:

```sh
cargo test --locked --offline -p executor --lib -- --test-threads=1
cargo test --locked --offline -p blockchain -p consensus -p chain_sync --lib --test parent_identity -- --test-threads=1
```

Executor: **75 passed, 3 failed, 2 ignored** (80 total). The three failures are
the new partial-state/crash-replay witnesses above. Two child entry tests are
no-ops without their driver environment and must not be counted as independent
security properties. The poison test's parent driver passed.
Other selection: blockchain 12, chain_sync 41, consensus 107, integration 10
passed, zero failed; consensus still has 7 ignored tests. **This working tree is
not globally test-green or releasable.** The prior default-suite totals do not
supersede these open witnesses.

The existing H6 witnesses were also explicitly rerun, not counted as passing:

```sh
cargo test --locked --offline -p executor --lib test_h6_ -- --ignored --test-threads=1
cargo clippy --locked --offline -p executor -p chain_sync -p blockchain -p consensus --all-targets --no-deps -- -D warnings
```

H6: **0 passed, 2 failed, 78 filtered out**. An out-of-band object write and a
copied DB with a tampered module both retain the same reported root. The precise
finding is that `current_state_root()` reads a stored history commitment rather
than recomputing/authenticating the supplied state. These fixtures directly copy
DB rows; they are NOT a new end-to-end attack on every snapshot transport. Their
older "unverifiable in principle / nothing in the node" prose is too broad:
external authenticated manifests or full trusted replay are separate possible
trust models. Even a Merkle implementation can retain an unchanged stored root
after raw disk corruption; a proper verifier must detect that corruption when
checking contents/proofs against a trusted commitment. Do not treat an unchanged
getter alone as proof against every possible state-authentication design.
Strict clippy for the four named packages passed. `cargo check --locked --offline
-p node --bins` passed as well; this is a debug build-check, not a release build
or deployment validation. The sync regression was rerun after the final fixture
cleanup and passed. No live node was accessed or changed during this increment.

### Required next storage boundary at that checkpoint

No production transaction-layer replacement had been introduced in that increment.
The `block_write_log` merely mirrored writes for hashing; it did not isolate
them. Both sync and the local producer mutated the same StateDB before a block
was stored, and ordering metadata was committed before those operations.
Changing only root/height into a batch would leave the first-batch witness open.

The complete repair needs all of the following, with caller-level tests:

- Stage transactions, fees, burns, slashes, epoch/governance effects, receipts and
  root updates in a read-your-own-writes view. Move resource/module resolution
  and all helper readers must use it; later batches cannot read the old DB.
- Validate a synced block's execution roots BEFORE publishing staged state.
  `sync/src/lib.rs` currently calls `verify_execution_roots` AFTER execution has
  written state. Existing proposer authentication does not make that ordering
  safe against a malicious authorized signer. This remains a static finding,
  not a newly reproduced signed-block exploit in this increment.
- Make state, accepted block/indexes, execution height and finality/ordering
  metadata one durable acceptance boundary, or specify an equivalent recoverable
  journal protocol. Publish in-memory cursors and QC/network effects only after
  durable acceptance. Separate handling is needed for durable local vote intent.
- Define conflict handling for other writers, including prefix/range scans and
  the public raw RocksDB handle. A plain snapshot is not write isolation;
  optimistic transactions need tracked reads and a safe conflict/retry policy.
  Account for VM/module caches when speculative execution is discarded.
- Extend crash/error injection to every phase and both callers, including
  rejected roots, disk errors, epoch boundaries, slashes, delayed persistence,
  and normal restart. Keep the current three failed witnesses as release gates.

RocksDB's native transaction APIs are an implementation candidate, not a selected
or integrated solution. The installed Rust binding is `rocksdb` 0.21.0; changing
from its current DB type affects storage access, VM/governance adapters, and the
existing genuine read-only I/O-failure fixtures. Do not replace those fixtures
with successful mocks or change durability options merely to simplify a port.

## Staged execution and checked sync acceptance

This increment supersedes the three failed executor crash results above; it
does NOT clear whole-system G2 or the other release gates.

`common/storage/src/transaction.rs` adds a serialized write-behind transaction
over the existing RocksDB DB and synced WriteBatch API. It does not introduce a
new DB format, change genesis, or migrate to TransactionDB. The raw DB handle is
now private behind a read-only `ReadStore`: production code cannot bypass the
storage writer gate through `StateDB.db.put/write/delete`. All StateDB write
helpers use the gate, including object writes and checkpoint pruning; those
previously used unsynced raw operations and now also use the synced path.
Existing genuine read-only DB failure fixtures use the same read-only RocksDB
handle wrapped in ReadStore, not mocked failures.

A transaction holds the writer gate for the callback's entire lifetime. The
callback receives a separate Arc<StateDB> backed by the same DB and a staged
put/delete map. Point reads and lazily merged iterators see the staged values;
deletions suppress base entries. The base cannot change under the callback, so
its prefix scans are stable. Only the write set is materialized, not the DB.
Success seals the view and publishes one sync=true batch; error or unwind drops
the staged effects. Escaped views are invalid after the callback and refuse use.
Detected RocksDB read errors are latched so a caller swallowing an error cannot
authorize commit. Invalid UTF-8 point reads and invalid object decoding are also
latched, with a regression that ignores the returned None and attempts a write.
This is not exhaustive validation of all application-level stored schemas.

`Executor::execute_block_parallel_at` now executes on that private view. The VM
is rebuilt per block so its module cache cannot leak speculative changes into a
later block. Fees, burns, receipts, and helper/governance accesses use that same
StateDB view. State root and executed height are part of the single batch, not
separately durable writes. The original signed-transfer fixture retains its
pre-staging golden root:
`0b19b72bb92f73df569edc7ac59a4ccf85dd8529184d007fdc3e51fc482a441a`.
Normal execution economics were not intentionally changed.

`execute_block_checked_at` additionally runs an acceptance callback before
commit. ChainSync now validates execution roots and stages block JSON, height,
hash, and transaction indexes inside that callback. An invalid root does not
consume execution height or mutate balances. The old post-execution verification
and separate block-store write were removed. Preparation and durable-execution
logs are separate; preparation is not reported as durable completion.

An actual ChainSync regression uses a correctly signed active-proposer block
with a wrong state root. Before integration, process_blocks returned height 0
but left `sys:last_executed_height=1`. After integration, wrong state AND receipt
roots leave every DB row unchanged, and a valid block at the same height is
accepted and persisted. This fixture uses an empty block; the checked-executor
subprocess fixture separately exercises two real signed Move transfers, fees,
receipts, block serialization/signing, and transaction indexes.

Coverage added or strengthened:

- Point reads, last-write-wins batches, tombstones, bounded prefix scans and
  forward/reverse iterators over the staged view; reopen after commit.
- Callback rejection and escaped-view refusal; a valid retry after rejection.
- Actual read-only RocksDB commit error leaves all rows unchanged.
- Outside writes wait behind the transaction, then proceed in order.
- Process exit after a staged transaction batch, staged root, and staged height
  leaves complete old state. Exit after durable commit leaves complete new state.
  Replay from each covered boundary matches clean execution.
- Panic after a real transfer sees that transfer in the view but leaves the base
  unchanged; the existing fail-closed poison policy remains in effect.
- Exit before/after checked acceptance's single commit leaves state, block, and
  indexes all absent or all present. Rejection AFTER staging block metadata also
  rolls back the real transfers, and valid retry matches a clean full DB.

Important remaining limits:

- At this increment the local producer still committed ordering before standalone
  execution and a separate block write. The following local-producer increment
  supersedes that specific gap; it does not clear the other limits below.
- Sync finality adoption remains separate from block acceptance. A stored block
  is not itself evidence that a correct QC/committee transition has been checked.
- Existing root-policy compatibility (including optional empty-root acceptance)
  is unchanged. This is not a mainnet policy gate or authenticated-state repair.
- The gate serializes writes, NOT arbitrary read-modify-write sequences outside
  transactions. A legacy writer can read stale data and later overwrite a new
  value. Such writers must be audited/converted or prohibited for consensus
  state. H6 and the faucet/out-of-band state trust model remain open.
- Transaction callbacks must access only the supplied view for DB writes;
  re-entering a base writer would deadlock on the non-reentrant gate. Current
  executor/VM/governance and acceptance paths are exercised in local tests, but
  future callbacks need the same review. Do not let views or work escape.
- Writer-gate contention, maximum write-set memory, epoch/slash fault injection,
  physical power loss and in-RocksDB commit errors need broader tests and
  measurements. No live rolling-deploy safety or throughput claim is made.
- No automatic repair of already-torn legacy databases is provided.

Verification after staging and checked acceptance:

```sh
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move --lib --test parent_identity -- --test-threads=1 --quiet
cargo build --locked --offline --release -p node --bins
```

Tests: blockchain 12, chain_sync 42, consensus 107, parent-identity integration
10, executor 81, governance 15, storage 30, VM 5 passed: **302 passed, 0 failed,
9 ignored** in this default selection. The three executor crash witnesses are
now ordinary passing tests, not newly ignored tests. Child entry points are
included in these test counts, not independent security proofs. The iterator
snapshot test also checks staged overwrite/insert after iterator creation; values
are immutable Arc-backed bytes so iterator creation does not duplicate their
entire payloads. This is a memory-ownership improvement, not a measured upper
bound on execution RAM.

The local macOS release build of the node package's binaries passed. This is not
a Linux release qualification, artifact signing, reproducible-build comparison,
whole-workspace release test, or authorization to deploy. All changes remain
local; unrelated user changes were preserved and no live node was touched.

Final strict clippy for storage, executor, chain_sync, consensus, blockchain,
vm_move and governance (`--all-targets --no-deps -- -D warnings`) passed.
The two H6 witnesses were explicitly rerun AFTER these changes with
`cargo test --locked --offline -p executor --lib test_h6_ -- --ignored --quiet --test-threads=1`:
**0 passed, 2 failed, 81 filtered out**. Staging does not authenticate snapshot
contents; their evidence limitations discussed above still apply. The goal and
mainnet gates remain open despite the default-suite pass.

## Local producer atomic acceptance

A new production-path witness, `test_unplaced_local_anchor_does_not_consume_ordering_cursor`,
first FAILED: with an executed-height marker but no corresponding durable block,
eight placement attempts failed, yet local ordering had persisted finalized
round 2. No block existed. The error log declared `ANCHOR_DROPPED` and allowed
the loop to move on. This is a legacy-torn-state reproduction, not a claim that
the new checked sync path still creates that marker/block window.

The local producer now uses `OrderingEngine::prepare_commit`, which computes
the same one-anchor decision and next bookkeeping without changing DB or memory.
The prepared plan records its preceding cursor, finalized round and digest;
stale reuse is refused. A tip change causes a new ordering decision with fresh
validator/evidence/time inputs, not placement of the old decision at a new tip.
Missing committed bodies stop the attempt instead of building a partial block.

Under the ordering-engine mutex, the producer calls `execute_block_checked_at`.
Its callback checks the durable parent height/hash against the chosen parent,
constructs and signs the block, and stages block JSON, tip, transaction indexes,
ordering cursor/digest/cseq/pruning rows and `consensus:last_adopted_height` on
the SAME view as execution state/root/height. One synced native WriteBatch accepts
them. Only after success does the producer publish engine state, update its
in-memory tip/accumulator, settle mempool entries and run subsequent DA/QC work.
Failure retains the pending anchor and exits the placement loop. Retrying does
not require restarting the process. This does not repair an existing torn DB.

Lock order for local acceptance is ordering -> executor -> storage writers.
No reload or base-DB write runs inside its acceptance callback. Sync releases
executor/storage locks before a subsequent ordering adoption. The legacy
metadata-only API remains for adoption and ordering tests; staging through a
transaction view and publishing engine memory are separate operations.

Added coverage:

- The previously failing unplaced-anchor witness now passes.
- A prepared plan leaves memory and persisted rows unchanged. Rejected staged
  metadata rolls back; valid acceptance publishes once; stale plan reuse fails;
  reopened engine state and beacon match the accepted running engine.
- A subprocess exits without destructors immediately before local acceptance's
  durable write and immediately after it, before engine/tip memory publication.
  The real DagConsensus path admits three genuinely signed vertices and produces
  one empty block. Reopened rows match rejected/pre-acceptance or clean accepted
  state respectively. Resume/retry produces the same block and ordering metadata.
- Rejection leaves all pre-existing rows unchanged; only admitted `vertex:` rows
  may be new. Snapshot comparison explicitly excludes `latest_proposed_round`
  and `validator:last_seen:*`, written as producer/telemetry hints after ingress
  returns. Durable vertices remain compared, and resume uses their recovered
  maximum round. These excluded hints are NOT claimed atomic with block state.
- A real read-only RocksDB execution handle reaches the acceptance callback but
  refuses its native batch. Neither block nor ordering/height publishes; restoring
  the writable executor allows the same pending anchor to succeed.

These local-producer fixtures use empty blocks, not real Move transfers or epoch
changes. The earlier executor crash suite separately covers signed transfers.
Process exit and read-only write failure do not prove physical power-loss,
disk-full, corrupted-sector or all mid-commit I/O-error behavior.

**Still open:** QC production/broadcast and carried-evidence markers are
post-commit effects, not a durable replay/outbox protocol. A crash after block
acceptance but before those effects needs its own recovery evidence; advancing
the adoption cursor is not proof that a QC was produced. Synced anchor adoption
is still separate from checked block execution and needs a properly authenticated
finality/committee contract. Equivocation convergence (G1), authenticated state
(G3/H6), transaction memory/latency bounds and independent audit remain open.
No consensus decision-rule or mainnet safety claim follows from atomic storage.

Verification of this increment:

- The seven-crate/default integration selection above passed: blockchain 12,
  chain_sync 42, consensus 112, parent-identity integration 10, executor 81,
  governance 15, storage 30, vm_move 5: **307 passed, 0 failed, 9 ignored**.
  Consensus was rerun after strengthening the rollback/native-error assertions:
  112 passed, 7 ignored. Child entry points are included in these raw counts.
- Strict clippy across the same seven crates, all targets, passed after fixing
  an Option-return lint and naming the test-hook function type.
- `cargo build --locked --offline --release -p node --bins` passed on this Mac.
  No Linux build, reproducible binary comparison or live deployment was run.
- Explicit ignored H1 witness rerun: **0 passed, 1 failed, 118 filtered out**.
  Opposite arrival orders still retain different live DAG bodies after genuine
  equivocation. This witness is not by itself a conflicting-finality proof;
  the earlier limits concerning compact retained evidence still apply.
- Explicit ignored H6 rerun: **0 passed, 2 failed, 81 filtered out**. The stored
  root getter still does not independently authenticate altered snapshot rows.
  The witness prose's broader impossibility claims are not adopted here.
- `git diff --check` passed. All work is uncommitted/local; user SDK changes
  remain untouched. No live node, genesis or deployment was changed.

## Durable QC signing and publication

Before adding automatic QC recovery, the existing signer/publication boundary
was tested. Two new ordinary tests first FAILED on the prior producer:

- A read-only RocksDB handle rejected the certificate writes, but the function
  returned `QcOutcome::Complete` and logged a stored certificate.
- After producing a certificate, reopening the DB and replaying the identical
  context succeeded, but a second context with a DIFFERENT block hash at the
  same height/anchor round also produced a signed, self-verifying certificate.

The final tests cover both single/supermajority certificates and minority
partial votes. These are real BLS and RocksDB fixtures at the producer API, not
proof that a remote adversary can directly invoke that API with arbitrary input.
They establish why automatic recovery must not blindly call the old signer.

Both local production and inbound aggregation now run through one durable
publication transaction. A signature or `Complete` result is returned only after
its records commit. No failed native write is reported as a stored certificate.
The block-height certificate, round certificate, latest body and latest pointer
updates are atomic; replaying an older certificate does not regress latest.
Conflicting certificate slots and inconsistent latest body/height are refused.

Local production records the complete signed vote under versioned signing
guards indexed by chain-id hash, derived BLS public key, and EACH of block height
and anchor round. Reuse requires identical vote fields and signer address, and
the stored signature must verify. Changing epoch, roots, digest, anchor hash,
finalized round, or either slot while reusing the other is refused. The writer
gate serializes competing requests; only one conflicting candidate can be
published. Identical retries reuse a valid stored signature. No wire encoding,
genesis field or consensus decision rule was changed.

Legacy local raw signatures, collected self-votes, and existing certificate
slots are checked before signing. A legacy signature must verify over the exact
requested bytes; it is not silently overwritten. Matching legacy data can acquire
new guard records. Malformed guard JSON is fail-closed. This does NOT reconstruct
missing signing history, protect a duplicated key running with a different DB,
or make rollback to an old backup safe. Signing-history export/import and safe
retention/pruning require an explicit protocol and operational review. The new
per-slot records currently grow with signed history; capacity is an open gate,
not an assumed solved storage property.
Reusing a chain ID across resets or restoring a key without its corresponding
signing history is not made safe by these guards.

Aggregation also filters each collected signature against the exact candidate
vote BEFORE counting its stake. Four validators with equal stake provide a
negative-control fixture: one stored vote signs different receipt-root bytes;
the remaining three supply valid votes for the requested message. Temporarily
removing only the new filter reproduced failure to aggregate that 75% honest
quorum. Restoring it produces a verifying 75/100 certificate. The legacy
first-vote-per-(round, signer) rule is retained; a Byzantine signer's different
message no longer poisons the other signers' aggregate. Collected scans are
bounded by the existing 10,000-vote backstop.

Tests added:

- Conflicting signing across reopen; exact retry; changes to nine context/slot
  fields; two concurrent conflicting requests (exactly one public partial vote).
- Read-only native errors for local complete/partial publication AND inbound
  quorum completion, followed by a successful writable retry.
- Subprocess exit immediately before/after the shared durable publication boundary
  for complete local QC, local partial vote, and remote aggregation. Full DB rows
  match pre-state or clean post-state, never mixed indexes/guards. Retry after
  reopen preserves records and refuses a different local vote.
- Matching/conflicting legacy records, malformed signing records, out-of-order
  QC replay, and the honest-quorum/off-message signature fixture above.

The complete QC producer selection has 20 passing test entries, including the
subprocess entry point. These tests do not cover physical power loss, storage
rollback, remote signer isolation, or all external failure modes.

Research grounding: [CometBFT's FilePV implementation](https://github.com/cometbft/cometbft/blob/main/privval/file.go)
stores last signing bytes/signature, rejects conflicting requests at its
height/round/step, and persists state before exposing a new vote signature.
[EIP-3076](https://eips.ethereum.org/EIPS/eip-3076) treats signing-history transfer
and conservative protection when history is incomplete as part of validator
safety. These are engineering precedents, not identical voting rules. AINCORE's
height/anchor guards are not an implementation of Ethereum surround-vote rules,
CometBFT's HRS machine, or either network's security proof.

**Not finished:** a block committed before ANY QC context was saved still has
no durable recovery job. Automatic outbox/replay must capture the exact epoch,
committee and commit context at acceptance, not resolve them from a later live
validator set. The existing epoch-to-live-set fallback and caller-supplied
CommitContext remain unaudited trust boundaries. This increment is a prerequisite
for that recovery, not its completion. Signature validation/aggregation currently
runs inside the serialized writer gate; throughput and abusive-traffic latency
must be measured/bounded before release. G1/G3/G4 and mainnet gates remain open.

Verification after this increment: the same seven-crate/default integration
selection passed **317 test entries, 0 failed, 9 ignored** (consensus now 122
passed / 7 ignored; the other crate counts are unchanged). The 20-test QC subset
was rerun after the final public-key reuse change and passed. Strict clippy over
the same crates/all targets passed; local macOS node `--bins` release build
passed. The temporary aggregation-filter mutation was restored before these
checks. `git diff --check` passed. No live deployment, restart, genesis change,
commit or push was performed; pre-existing user changes remain preserved.

## Historical committee substitution increment

While designing durable QC recovery, the epoch resolver exposed a prerequisite
failure: `load_validator_set_for_epoch` silently substituted the live committee
when the requested snapshot was absent, malformed, or empty. The same resolver
feeds local signing, remote aggregation, finality-artifact verification and RPC
verification. A cryptographically valid signature under today's keys is not
evidence those keys were authorized in the requested historical epoch.

Executable negative controls, before the respective fixes:

- The consensus `epoch_` selection returned 1 passed / 2 failed. The two new
  witnesses produced and durably stored a complete QC despite an invalid epoch-0
  snapshot, and despite epoch 0 being absent while the current epoch was 10.
  Each loop stopped at its first failing case; not every matrix case was run on
  the vulnerable version.
- `test_unknown_epoch_cannot_borrow_live_committee_for_finality` failed: the
  actual `ChainSync::apply_finality_artifact` advanced finality to round 9000 for
  a correctly BLS-signed epoch-9 QC without an epoch-9 snapshot. The fixture
  supplies a locally held block/hash to isolate committee authorization; it is
  not a full block-validation, multi-node fork, or live attack demonstration.
- After fixing the shared resolver, the new `parent_identity` integration test
  still failed: the real `DAG_VERTEX` ingress accepted a signed round-2 vertex
  with epoch 3 selected but no snapshot. `epoch_committee` had its own second
  fallback to the live stake cache.

Local changes:

- Nonzero epochs require their exact retained, nonempty JSON snapshot. Missing,
  malformed and empty snapshots fail closed. A pruned snapshot cannot be
  replaced by a newly registered committee. Cryptographic/set validation remains
  the responsibility of the QC verifier; this loader does not authenticate the
  provenance of database contents.
- Epoch-0 fallback is limited to an absent epoch-0 snapshot and an absent/zero
  current epoch. An invalid snapshot, malformed current-epoch marker, or a
  nonzero current epoch cannot enter that exception.
- DAG ingress propagates missing/invalid committee resolution instead of falling
  back a second time. Its legacy non-BLS `sys:validators` bootstrap is limited to
  epoch 0 with neither BLS record present. Rejected vertices are not queued by
  this change; liveness still depends on retrieval/retransmission after repair.
- Existing signing-guard tests now explicitly provide the changed epoch's
  snapshot so that their epoch-conflict case still reaches the signing guard,
  rather than passing due only to missing-committee rejection.

Additional tests cover unknown past/current/future epochs, malformed/empty
snapshots, remote aggregation with zero writes before an exact snapshot is
available, replay after reopen with a changed live committee, refusal after
snapshot pruning, malformed epoch markers, and signed DAG ingress followed by
successful resubmission after explicit fixture repair. Bootstrap compatibility
and retained historical snapshots remain positive controls.

Research grounding: [CometBFT light-client verification](https://github.com/cometbft/cometbft/blob/main/spec/light-client/verification/README.md)
starts with a trusted header/state and checks validator-set hashes and transitions
relative to that trust, with explicit time and fault assumptions. It does not
establish historical authorization merely by finding a currently available key
set. This informs the refusal to substitute committees; AINCORE has not thereby
implemented CometBFT's light client, trusting-period model, or proofs.

**Remaining blockers, not fixed by this increment:**

- The legacy epoch-0 exception still reads a mutable live set. Missing current
  epoch metadata cannot distinguish bootstrap from a damaged legacy database.
  An authenticated, immutable bootstrap/upgrade contract is still required.
- Epoch-boundary semantics are inconsistent: executor `rotate_validator_epoch`
  writes the new epoch while executing boundary block H, but records its start
  height as H+1. Local QC production reads the new epoch after that execution.
  Synced adoption also reads the latest epoch for historical blocks. Freezing
  those values without resolving the contract would persist the ambiguity.
- Durable per-block QC context/outbox and automatic crash replay are NOT added
  yet. Snapshot retention can now surface missing-history failures rather than
  silently passing verification; authenticated recovery across that horizon is
  mandatory before release. No operator should synthesize missing snapshots from
  the current live set as a repair.
- DAG epoch assignment, ordering's other committee reads, checkpoint recovery,
  and the transition proof chain still need a unified contract. The G1/H1 and
  G3/H6 witnesses remain open. No finality-fork proof or safety theorem is claimed.

Verification on the final local code for this increment:

```sh
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move --lib --test parent_identity -- --test-threads=1 --quiet
cargo clippy --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p vm_move -p governance --all-targets --no-deps -- -D warnings
cargo build --locked --offline --release -p node --bins
```

Default regression: **324 passed, 0 failed, 9 ignored**. Breakdown: blockchain
12, chain_sync 43, consensus 127 (+7 ignored), parent_identity integration 11,
executor 81 (+2 ignored), governance 15, storage 30, vm_move 5. Strict clippy
passed (39.29s); local macOS node-bin release build passed (14.70s). This does not
establish Linux deployment or reproducible cross-platform artifacts.

The ignored blockers were separately selected again on this code:

```sh
cargo test --locked --offline -p consensus --lib test_h1_dropped_twin_leaves_two_honest_nodes_holding_different_sets -- --ignored --test-threads=1 --quiet
cargo test --locked --offline -p executor --lib test_h6_ -- --ignored --test-threads=1 --quiet
```

Results remain **1 failed** (different retained DAG views after differently
ordered equivocations) and **2 failed** (stored root unchanged after injected
out-of-band state/snapshot changes). These are still-open negative witnesses,
not green release checks. Their legacy assertion prose about information being
lost "forever" or verification being impossible in principle is not established
by those tests. They do not alone prove a conflicting finalized chain or preclude
a correctly authenticated snapshot/proof design.

No live services, identities, genesis, or remote branch were changed. These are
stricter acceptance rules, not an approved rolling deployment or release gate.

## Atomic imported-finality increment

The epoch review led to an integration defect between ChainSync and the hardened
QC producer: `apply_finality_artifact` wrote only `consensus:qc:latest`, without
`latest_height`, `latest_round`, per-height or per-round QC records. The producer
correctly rejects an incomplete latest pointer/body, so importing a valid QC
could prevent subsequent aggregation. ChainSync also wrote four related finality
fields independently, leaving a process-crash partial-write window.

The new `test_imported_qc_does_not_break_followup_aggregation` reproduced the
first defect before the fix: finality import succeeded, then a real BLS-signed
quorum failed to publish with `incomplete latest QC pointer/body` (0 passed,
1 failed). The test isolates the production import/aggregation APIs, with held
block/hash fixtures; it does not simulate full block execution or network gossip.

Local implementation:

- `qc_producer::import_finality_qc` verifies membership, chain, BLS quorum and
  held-block hash binding inside the existing writer-gated transaction. It reads
  the finality high-water mark in that same view, not before acquiring the gate.
- Four finality fields and all five QC indexes are staged together. It calls the
  same private certificate writer as local signing and remote aggregation, so
  conflict checks and monotonic latest-height indexing are shared, not duplicated.
- ChainSync delegates to this entry point and logs success only after durable
  commit returns. Missing committee/block or an already-finalized round remains
  a no-op; invalid certificates, malformed local finality, conflicting indexes
  and native write failures return errors rather than publishing partial success.
- A late certificate-index error rolls back even an already-staged finalized
  marker. No new nested transaction, raw database writer, wire format or genesis
  field was introduced.

Isolated durability evidence in `qc_import_tests.rs`:

- Subprocess exit 77 after staging the first finality field, after staging all
  nine rows, and after native durable commit before returning. Reopened full DB
  rows match the clean pre-state or post-state. Retry is complete and idempotent.
- A temporary negative-control mutation removed ONLY the transaction around the
  same staging function. The crash test failed at its full-row comparison: the
  first finality field survived alone. The transaction was restored before final
  regression checks. This tests the independent-write failure mode; it is not a
  claim that a live node was crashed or the original binary was deployed.
- A native read-only RocksDB handle rejects import with unchanged rows, then
  writable reopen/retry succeeds. A conflicting existing QC index also leaves
  all rows unchanged despite the earlier staged finality write.
- Concurrent imports at two heights cannot regress each other's finality or
  latest indexes. A malformed finality counter is not silently interpreted as 0.

Research: [RocksDB's atomic updates and synchronous writes](https://github.com/facebook/rocksdb/wiki/Basic-Operations#atomic-updates)
distinguish a grouped WriteBatch from separate updates and describe the sync flag
for persistent writes. The implementation uses the already-tested shared gate
plus synced batch; these subprocess tests do not establish physical power-loss
behavior on the NAS or hardware flush correctness.

Limits: this imports proof metadata for an already accepted block. It does not
make block execution, ordering-memory adoption and the network import a single
protocol operation; local ordering's other writers still need a unified finality
contract. It does not authenticate a snapshot's contents or epoch transitions,
repair old torn indexes, add a local QC outbox, or change the legacy epoch-0
exception. A fixture's held block is not evidence of complete block validation.
Recovery/backfill and those G1/G2/G3 gates remain open. No live action or genesis
migration was performed.

Final verification after restoring the transaction negative control:

```sh
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move --lib --test parent_identity -- --test-threads=1 --quiet
cargo clippy --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p vm_move -p governance --all-targets --no-deps -- -D warnings
cargo build --locked --offline --release -p node --bins
```

Regression: **331 passed, 0 failed, 9 ignored**. Consensus is now 133 passed /
7 ignored and chain_sync 44 passed; other crate counts match the preceding
increment. The six new import test entries include the subprocess entry point.
Strict clippy passed (32.05s), local macOS release build passed (16.59s), and
`git diff --check` passed. The H1/H6 negative results recorded above remain open;
they were not rerun in this import-only increment. No commit/push was performed.

## G1 signed-ingress ordering counterexample

The earlier H1 witness established divergent retained DAGs, not a conflicting
finalized chain. `equivocation_liveness_tests.rs` now exercises signed ingress,
durable reopen and the production ordering APIs with four equal-stake identities,
one Byzantine. Receiver identities are observers to isolate admission and
ordering: this is NOT a complete validator/network/execution/QC simulation.

Schedule and observed results:

- At leader round 2, X first receives signed candidate A and Y first receives
  its same-author/same-round twin B. Both subsequently receive both candidates.
  Three of four round-3 authors reference A; the remaining honest author
  references B. No honest identity signs two vertices for one round.
- Both receivers accept the entire later tail through round 9, with only the
  three honest authors continuing. X's ordering API commits anchor 2/A. Y has
  retained B and discarded A, leaving a hole in the required causal history.
- Three retransmissions of A and the entire tail, followed by database reopen
  and another delivery of A, do not yield an ordering decision at Y. The
  no-equivocation control does decide the same anchor and sequence after reopen.
- The explicit security run returns **1 passed, 1 failed**. The failing witness
  is deliberately ignored by default, labelled OPEN G1; default green tests do
  not satisfy this gate. The finite schedule demonstrates the observed recovery
  failure, not infinite execution, a whole-network halt or failure of every
  possible ChainSync/epoch recovery mechanism.

Negative control: temporarily removing ONLY the equivocation-path `return`
admits both bodies into the live DAG. Y then prepares anchor 2/B, conflicting
with X's earlier A decision. The test fails at the same-anchor-hash assertion
before reopen (**0 passed, 1 failed**). This is a conflicting proposed ordering
decision under that mutation, NOT an executed or QC-finalized fork in current
code. The mutation was restored; no both-twins production patch remains.

```sh
cargo test --locked --offline -p consensus --lib equivocation_liveness_tests -- --include-ignored --test-threads=1 --nocapture
cargo test --locked --offline -p consensus --lib --test parent_identity -- --test-threads=1 --quiet
```

The second command passed: **134 consensus unit tests, 11 integration tests,
0 failures, 8 ignored**. The new positive control is enabled by default. The
negative witness remains a release blocker, not a completed fix.

Strict `cargo clippy --locked --offline -p consensus --all-targets --no-deps --
-D warnings` also passed (40.90s); `git diff --check` passed. No full-workspace
regression or release build was rerun for this test/documentation-only increment.

Protocol constraint from primary research:
[Bullshark section 2](https://arxiv.org/pdf/2209.05633) assumes non-equivocation,
reliable delivery and complete causal histories in its orderable DAG. Its
partially synchronous direct-support threshold is f+1 in the described schedule;
AINCORE's current greater-than-two-thirds next-round rule is not that literal
algorithm. Changing a threshold alone would not establish equivalence.
[Mysticeti v4](https://arxiv.org/html/2310.14821v4) instead defines support through
a specified first-encounter traversal and combines certification patterns,
skip/undecided decisions and indirect decisions. Keeping both twins without
those rules does not inherit its safety argument.

Required next design work before claiming G1 resolved:

1. Specify a coherent certified-DAG contract or a complete uncertified ordering
   protocol. Do not combine partial rules from separate proofs.
2. For the certified route, separate staged bodies from the orderable DAG;
   attest only after durable body/parent validation, with a domain-separated,
   durable one-attestation-per-slot guard and a frozen committee context.
3. Specify quorum-certified candidate uniqueness, causal-body retrieval and
   bounded retention. A recovered losing body must not automatically become a
   second orderable candidate. Arrival order or local minimum-hash choice is
   not a substitute for agreement.
4. Bind slots and certificates to chain/epoch/author/round and settle committee
   activation boundaries. Test delayed messages across the boundary explicitly.
5. Extend the signed schedule to actual producing validators, execution and QC
   agreement; include partitions, withheld bodies, crash/replay and unequal
   stake. Require identical committed prefixes and quantified recovery progress.

No live nodes, deployment, genesis, commit or push were touched in this increment.

## QC block-height epoch binding increment

Reviewing G1's prerequisite committee contract exposed a separate, reproducible
epoch mismatch. `Executor::rotate_validator_epoch(H)` records activation at
`H + 1`, but local post-execution QC creation read the newly advanced current
epoch for block H. `reload_chain_tip` likewise used the current epoch while
adopting older blocks. Neither local signing, aggregation nor finality import
checked that the claimed epoch was active at the claimed block height.

Before this fix, `qc_epoch_height_tests` returned **1 passed, 3 failed**. With
different real BLS keys in retained epochs 0 and 1, and epoch 1 starting at 21,
all three publication APIs accepted epoch-1 certification of block 20. The
import witness had a matching held block and a QC that passed BLS verification;
it advanced local finality anyway. These API fixtures isolate membership/height
binding, not complete block execution or an attacker without committee keys.

Local implementation:

- `epoch_for_block_height` walks retained activation boundaries backward from
  the current epoch, rather than dividing by today's configurable interval.
  It rejects zero block height, malformed markers, missing traversed boundaries
  and nonmonotonic traversed starts. Work is capped at 64 lookups; this cap is
  not a new retention policy. Missing history does not imply epoch 0.
- Both DAG QC callers select the epoch by the accepted/adopted block's height.
  An unavailable range defers attestation instead of inventing an epoch.
- Local signing, aggregation and imported-finality publication independently
  repeat the epoch/height check inside their existing writer-gated transaction.
  A caller's earlier lookup is only a hint, not authority across concurrent
  execution. Wrong ranges cannot publish signatures, QC indexes or finality.
- The legacy absent/zero-current-epoch bootstrap remains explicitly limited;
  exact committee snapshot validation is still separate from range selection.
  Unknown activation history makes import a no-op; an explicitly wrong epoch
  returns an error. No wire format or genesis layout was changed.

New evidence (eight enabled test entries):

- Three rejection tests cover a future committee on the boundary and the old
  committee on its successor; full DB rows remain unchanged on rejection.
- A positive control exercises all three APIs at H/old and H+1/new.
- Historical boundary lookup survives DB reopen and a changed present-day
  interval. Missing, malformed, reversed/duplicate starts and malformed current
  epoch markers fail closed for the queried history; recent known intervals
  remain usable after older history is absent.
- `producer_and_lagged_adoption_use_block_epoch_after_rotation` runs actual
  vertex production, empty-block execution/acceptance, QC signing and later
  `reload_chain_tip` adoption. It asserts boundary epoch 0, successor epoch 1,
  and historical adoption epoch 0 while the current metadata says epoch 2.
  Rotation metadata is injected through the acceptance test hook; this test
  does NOT execute a Move reconfiguration transaction. The adoption half uses
  a held block from that producer, not a network/download execution simulation.
- Restoring ONLY the producer's old current-epoch choice temporarily makes the
  caller test fail with `boundary QC was skipped`. Restoring ONLY the adoption
  caller's old choice fails with `historical adoption QC was skipped`. Each
  negative control returned **0 passed, 1 failed**. Both were restored before
  final regression checks; neither experimental change remains.

The older exact-snapshot tests now include activation markers in their positive
fixtures, so they still reach snapshot validation rather than failing earlier
on unknown height ranges. The changed-epoch anti-double-sign test deliberately
changes activation metadata and proves the signing guard still rejects a second
epoch for an already-signed slot; that guard is not bypassed by this resolver.

Primary-source constraint: [Diem's epoch-change verifier](https://diem.github.io/diem/src/diem_types/epoch_change.rs.html)
verifies a transition using already trusted epoch information before adopting
the carried next-epoch state. Its tests reject broken chains and signatures.
That demonstrates the distinction between looking up local epoch metadata and
authenticating a committee transition. This increment implements the former
consistently; it does not claim the latter or protocol equivalence with Diem.

Important remaining blockers and compatibility limits:

- The current genesis path does not write `sys:validator_set:epoch:0`. The new
  caller fixture explicitly seeds it. After rotation, missing epoch-0 history
  must still fail closed, so fresh bootstrap freezing/recovery remains required
  before claiming complete first-boundary behavior. Do not fill historical
  epoch 0 from a later live set.
- Activation metadata and committee snapshots are not authenticated transition
  proofs. DAG vertex epoch assignment, the G1 equivocation contract and the
  separate ordering/adoption finality writers remain open work.
- Existing wrong-epoch QCs/signing guards are not rewritten. Historical replay
  can conflict with them and requires an explicit recovery/compatibility plan;
  no rolling-deploy safety claim follows from these local tests.
- Missing/pruned boundaries do not trigger automatic history reconstruction,
  outbox replay or resigning. QC durability/backfill and trusted recovery remain
  necessary before a production release.

Final verification after restoring both caller negative controls:

```sh
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move --lib --test parent_identity -- --test-threads=1 --quiet
cargo clippy --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p vm_move -p governance --all-targets --no-deps -- -D warnings
cargo build --locked --offline --release -p node --bins
```

The named regression suite passed **340 tests, 0 failures, 10 ignored**:
consensus 142/8 ignored, parent integration 11, chain_sync 44, executor 81/2
ignored, blockchain 12, governance 15, storage 30, vm_move 5. Strict clippy
passed (45.45s), local macOS release build passed (15.42s), and `git diff --check`
passed. This is not a full-workspace test or a Linux deployment result. The
ignored G1/H6 witnesses remain open; no commit, push or live action was performed.

## Frozen-genesis epoch-zero increment

The preceding increment's bootstrap inventory was incomplete: although genesis
does not write the epoch-0 alias, it ALREADY writes `genesis:validator_set:v1`.
`validate_genesis_integrity` uses this frozen record in the genesis identity and
checks consistency on reopen. Therefore copying today's live set into a new
epoch-0 snapshot would be both unnecessary and potentially wrong. The resolver
now consumes the existing genesis record directly; no metadata migration runs.

Before the change, three new tests failed (**0 passed, 3 failed**): the resolver
selected a changed live committee instead of frozen genesis, accepted an
epoch-0 alias conflicting with genesis, and authorized epoch 0 from live records
alone. After the change all three pass, including identical historical QC replay
after database reopen with the current epoch already advanced.

Implementation and test scope:

- Epoch 0 requires a nonempty, typed frozen genesis committee. An optional
  `sys:validator_set:epoch:0` alias must agree in canonical validator order;
  conflicting, empty or malformed aliases fail closed. A valid alias cannot
  substitute for missing/corrupt genesis. Nonzero epochs keep exact snapshots.
- QC authority no longer falls back to `sys:validator_set:v1` for any epoch.
  Genesis remains available for historical epoch-0 lookup independently of the
  executor's bounded retention of later epoch snapshots. Height-range checks
  from the preceding increment still constrain signing/import/aggregation.
- The separate legacy native-only DAG path cannot bypass a present but corrupt
  genesis record. A real local vertex-production control covers this guard.
  Native-only compatibility when ALL BLS/genesis records are absent still exists;
  it is not a mainnet bootstrap or an authenticated committee mechanism.
- Tests cover changed live keys, reopen/rotation, conflicting alias stake,
  missing/empty/malformed genesis, equivalent reordered aliases and unchanged
  DB rows on failed lookup/signing. Existing durability and cryptographic
  fixtures now seed frozen genesis so they still reach their intended gates.
- The caller timing test from the preceding increment now seeds the actual
  genesis key instead of an epoch-0 alias. Its boundary and successor QCs and
  historical adoption exercise the resolver without an alias.
- The existing node genesis-identity test is extended to call the real QC
  resolver immediately after `initialize_genesis`, then after live-set mutation
  and revalidation. Production genesis code, version, identity inputs and layout
  are unchanged. This does not execute a full distributed Move epoch transition.

Trust boundary: the resolver trusts genesis/history validated by node startup.
It does not recompute the genesis identity on every QC call or authenticate a
database whose contents AND identity were substituted together. An externally
trusted genesis pin and authenticated transition proofs remain release gates.
The [Diem epoch-change verification contract](https://diem.github.io/diem/src/diem_types/epoch_change.rs.html)
likewise begins from trusted epoch information or a waypoint; that is distinct
from merely possessing a local committee JSON record.

Compatibility: datadirs with only a mutable live set no longer produce QCs.
Conflicting historical aliases/signing guards are not silently rewritten, and
old wrong-committee certificates are not repaired. Require a separately reviewed
recovery plan before deployment. G1 equivocation, DAG epoch assignment, QC
outbox/backfill and authenticated state/transition proofs remain open.

Additional review note: the QC RPC handlers in `api.rs` and `api_local.rs` use
the shared committee loader but still derive their `verified` result directly
from cryptographic `verify_qc`, without the block-height activation check added
to publication/import. Existing stored artifacts therefore need a separate
RPC verification-contract review; do not interpret this boolean as complete
state/history/epoch-transition authentication.

Final verification:

```sh
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move -p node --lib --test parent_identity -- --test-threads=1 --quiet
cargo clippy --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p vm_move -p governance -p node --all-targets --no-deps -- -D warnings
cargo build --locked --offline --release -p node --bins
```

**375 passed, 0 failed, 10 ignored**: consensus 148/8 ignored, parent integration
11, chain_sync 44, executor 81/2 ignored, blockchain 12, governance 15, storage 30,
vm_move 5, and node library 29. Strict clippy passed (1m31s); local macOS release
build passed (15.03s); `git diff --check` passed. This remains a selected-crate
regression, not full-workspace, Linux/hardware or independent-audit evidence.
An initial wrong-target `--bin node` genesis-test build was cancelled; only the
correct `--lib` targeted test and the full command above count as test evidence.
No live services, genesis migration, commit or push were performed.

## QC RPC verification-contract increment

Reproduced the preceding RPC review finding through actual in-memory Actix HTTP
handlers in BOTH `api.rs` (node library) and `api_local.rs` (node binary). Before
the repair each target ran four tests: **1 passed, 3 failed**. Real BLS signatures
from a locally retained committee incorrectly produced `valid:true`/`verified:true`
outside that committee's block-height interval. A certificate for height 21,
stored and requested at index 22, also incorrectly returned `verified:true`.
The boundary/successor positive control passed. These are RPC verdict bugs, not
a new demonstration of block execution, accepted finality or a live-network fork.

Both handlers now use `core/node/src/qc_rpc.rs`. Stored results must match their
requested height index; zero height is rejected; the certificate epoch must
match `epoch_for_block_height`; the frozen/exact committee loader and BLS verifier
remain mandatory. Missing/malformed retained history or committee cannot produce
a positive verdict. The external verifier preserves JSON-RPC `-32000` for
unavailable context and `-32602` for malformed parameters; invalid certificates
return `valid:false`. An additive `verification_scope: local_committee_and_epoch`
field makes the limited trust context explicit for parsed verification results.

Seven shared scenarios pass in each API (**14 targeted HTTP tests**): wrong epoch
in all three getter aliases, wrong epoch externally supplied, wrong storage
index, valid boundary and successor, missing/corrupt metadata, signature/chain/
signed-root tampering, and malformed parameters/zero height. Each HTTP call checks
that all database rows are unchanged. The fixtures intentionally have no executed
block: this RPC checks a certificate, not the block's execution or state proof.

This uses separate read-only metadata reads, NOT a consistent database snapshot.
Locally trusted metadata does not authenticate epoch-transition history for a
remote client. The [Diem epoch-change verifier](https://diem.github.io/diem/src/diem_types/epoch_change.rs.html)
starts from trusted epoch information or a waypoint and verifies the transition
chain; AINCORE does not gain that contract from this RPC patch. Authenticated
transitions, snapshot-consistent verification context, malformed optional getter
parameter handling, and full accepted-block proof semantics require further work.
Old invalid stored certificates are reported, not rewritten or migrated.

Final gate commands:

```sh
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move -p node --lib --test parent_identity --bin node -- --test-threads=1 --quiet
cargo clippy --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p vm_move -p governance -p node --all-targets --no-deps -- -D warnings
cargo build --locked --offline --release -p node --bins
```

Selected regression: **400 passed, 0 failed, 10 ignored**. Breakdown: consensus
148/8 ignored, parent integration 11, chain_sync 44, executor 81/2 ignored,
blockchain 12, governance 15, storage 30, vm_move 5, node library 36, node binary
18. The default selection does not clear the remaining ignored security witnesses.
Strict clippy passed (1m23s) after replacing a test-only complex return type with
a named row alias; local macOS release build passed (13.23s). These are not Linux,
physical crash/power-loss, full-workspace, independent review or mainnet evidence.
No live node access, deployment, restart, reset, genesis migration, commit or push.

## Imported QC held-block binding increment

The importer compared only the certificate's block hash with the stored header's
hash string. Two adversarial tests reproduced acceptance and finality publication
for **all ten tested inconsistencies**: validly signed contradictory state root,
receipts root, anchor hash and anchor round; and held-block corruption of height,
timestamp, transactions, committed vertices, slash evidence and anchor hash while
preserving the stored hash. Baseline: **0 passed, 2 failed**. The signatures are
real 1-of-1 BLS fixtures. This proves insufficient local consistency checks, not
an ability for a minority attacker to forge a quorum signature.

`stage_imported_finality` now checks the held block's height, round, anchor and
state/receipt roots against the signed QC, and recomputes the header, transaction,
vertex and evidence commitments with the current protocol functions. These checks
remain inside the same writer-gated transaction as epoch/committee checks and
the nine finality/QC metadata rows. Rejecting an inconsistency leaves all rows
unchanged. The existing crash/import write-failure/retry tests still pass.

The ChainSync fixture now builds certificates over the constructor's actual block
hash instead of a substituted `cd...` string. A receiver-level test exercises
validly signed contradictory roots and a corrupt body through
`apply_finality_artifact`, checks full-row equality on rejection, then demonstrates
acceptance after restoring the correct fixture pair. It does not exercise a real
TCP connection. A separate reopen/positive test covers nonempty body commitments;
its transaction/evidence strings are structural fixtures, not executed Move
transactions or verified slash evidence.

The [Ethereum Paris execution specification's state transition](https://github.com/ethereum/execution-specs/blob/master/src/ethereum/forks/paris/fork.py)
checks computed transaction, state and receipt commitments before state publication.
That is a stronger end-to-end execution contract than this import consistency
patch. Here execution validity still depends on the block's earlier acceptance
path; no state proof, execution replay, genesis/epoch-transition proof or cumulative
`finality_digest` reconstruction is added.

Compatibility/security limits: legacy nonempty vertex bodies without a matching
root can no longer advance imported finality. Existing rows are not repaired.
Current transaction/header hashing still uses concatenation rather than a fully
domain-tagged canonical encoding; recomputation does not eliminate encoding
ambiguity. That requires a protocol-level design and migration review. No claim
of complete body authentication, authenticated recovery, or mainnet readiness.

Final verification uses the same three commands listed in the preceding RPC
increment: **404 passed, 0 failed, 10 ignored**. Consensus is now 151 passed/8
ignored and chain_sync 45 passed; all other counts remain unchanged. Strict clippy
passed (1m37s), local macOS node-binaries release build passed (15.95s), and
`git diff --check` passed. The ten ignored entries were not reclassified, removed
or weakened. Default-suite green is not clearance of the open G1/H6 witnesses.
No live access, deployment, restart, reset, genesis migration, commit or push was
performed.

## Signed block identity counterexample

Follow-up to held-block recomputation: two different accepted block structures can
share the same current hash AND unchanged proposer signature. In
`sync/src/block_identity_tests.rs`, real proposer authentication plus
`process_blocks` executes/persists a round/timestamp resegmentation and an unsigned
anchor substitution in separate stores. The honest unchanged-block control passes.

```sh
cargo test --locked --offline -p chain_sync --lib block_identity -- --include-ignored --test-threads=1 --nocapture
```

**1 passed, 2 failed**. This is equal input encoding, not a cryptographic hash
collision or newly demonstrated conflicting quorum certificates. The two required
rejection witnesses are ignored in the default developer suite, explicitly OPEN;
readiness evaluation must run them. No production identity algorithm was changed.

The full repair must cover canonical field/list boundaries, signed anchor and
chain/epoch identity, one shared hashing implementation, a pinned activation
schedule, historical verification and every producer/consumer/recovery caller.
See `docs/BLOCK_IDENTITY_V2_PLAN.md` for the current-code inventory, primary BCS
reference and required evidence. Changing the hash algorithm in place or silently
accepting either old/new format is not an acceptable migration plan.

Final affected-crate verification:

```sh
cargo test --locked --offline -p chain_sync --lib -- --test-threads=1 --quiet
cargo clippy --locked --offline -p chain_sync --all-targets --no-deps -- -D warnings
```

Default sync suite: **46 passed, 0 failed, 2 ignored**. Explicit witness rerun:
**1 passed, 2 failed**, including observed matching hashes, reused signature and
successful execution/persistence of both substitutions. Strict clippy passed
(48.40s), and `git diff --check` passed. This increment changes tests and design
documents only; the blocker remains open, and no new full-workspace or release
build claim is made. Earlier regression totals are historical, not current gate
clearance for the added ignored witnesses.
No live node access, deployment, restart, reset, genesis migration, commit or push.

## Isolated canonical identity codec increment

Implemented the proposed V2 identity/body codec in
`consensus/blockchain/src/identity_v2.rs`, with a frozen reference vector and an
independent JavaScript fixture encoder. It uses the existing locked BCS 0.1.6
dependency; Cargo.lock changes only by adding BCS to blockchain's dependency list.
The proposed identity binds fifteen fields, including genesis/chain/epoch, anchor,
round/timestamp, typed roots and cumulative finality digest. Hash, proposer-signing,
transaction, vertex and evidence domains are distinct. Unknown versions, trailing
or nonminimal BCS input and invalid/bounds-exceeding identities are rejected.

See `docs/BLOCK_IDENTITY_V2_PLAN.md` for exact tuple order, domains, limits and
verification scope. No current Block constructor, hash function, proposer signer,
sync acceptance path, genesis policy or QC format was switched to this codec.
It therefore does NOT fix the reproduced legacy signed-substitution witnesses.
The codec is required groundwork for the complete activation/integration contract,
not a compatible workaround or a replacement definition of mainnet readiness.

Targeted codec verification: **6 passed** after the final schema/boundary checks.
The JavaScript fixed-vector/domain/list-boundary program passed independently.
Explicit legacy sync witness rerun remains **1 passed, 2 failed**: the old
round/timestamp and anchor substitutions still reach execution/persistence.
Strict clippy for blockchain/chain_sync/consensus/node passed (1m25s); a final
blockchain-only all-targets clippy rerun passed after adding UTF-8/parent-variant
boundary assertions (49.31s). Local macOS node release build passed (17.40s).
Selected broad regression completed:

```sh
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move -p node --lib --test parent_identity --bin node -- --test-threads=1 --quiet
node scripts/tests/block_identity_v2_vectors.mjs
```

**411 passed, 0 failed, 12 ignored**: blockchain 18, chain_sync 46/2 ignored,
consensus 151/8 ignored, parent integration 11, executor 81/2 ignored, governance
15, node library 36, node binary 18, storage 30, vm_move 5. The last added UTF-8,
parent-variant and exact item-bound assertions also passed the final targeted
six-test rerun. `git diff --check` passed. Do not infer readiness from the codec
tests or unchanged legacy path. No live access, deployment, restart, reset,
genesis migration, commit or push.

## Isolated genesis format-policy increment

Added `identity_v2::policy` with bounded canonical proof decoding against an
explicit caller-supplied trusted genesis pin. The proposal commits the existing
base genesis identity, chain ID and a positive V2 activation height. Private-field
verified policies enforce exactly one version per height, reject downgrade and
unknown versions, and check V2 chain/genesis context before producing signing
bytes. This is not startup wiring, an authenticated post-genesis upgrade, an
execution verifier, or a live activation. See `BLOCK_IDENTITY_V2_PLAN.md` for the
exact proposed commitment and trust-anchor limitations.

An independent JavaScript fixture now checks policy bytes and the frozen pin in
addition to the block identity vector. A node test constructs actual genesis in
temporary RocksDB, uses its base identity, rejects modified base/activation under
the same candidate pin, and verifies all stored rows remain unchanged through
policy verification and existing-genesis reopen. There is no runtime writer or
environment activation flag, and no genesis migration.

Verification for this increment:

```sh
cargo test --locked --offline -p blockchain --lib identity_v2 -- --test-threads=1 --quiet
cargo test --locked --offline -p node --lib genesis::tests::test_format_policy_proposal_binds_actual_genesis_without_migration -- --exact --test-threads=1 --quiet
node scripts/tests/block_identity_v2_vectors.mjs
cargo test --locked --offline -p blockchain -p node --lib -- --test-threads=1 --quiet
cargo clippy --locked --offline -p blockchain -p node --all-targets --no-deps -- -D warnings
cargo test --locked --offline -p chain_sync --lib block_identity -- --include-ignored --test-threads=1 --nocapture
```

Results: codec/policy **11 passed**, focused actual-genesis test **1 passed**,
independent JavaScript vectors passed, affected full library suites **60 passed**
(blockchain 23, node 37, no ignored tests in those two suites), strict clippy
passed. The explicit legacy sync security witnesses remain **1 passed, 2 failed**:
both signed substitutions still reach execution/storage. This is an OPEN release
blocker, not an expected-error exception that permits release. The broad 411-test
result above belongs to the previous increment; it was not rerun here. No live
access, deploy, restart, reset, genesis migration, commit or push.

## Executed empty-block reorg corruption

While tracing the acceptance path for V2 integration, found another existing
G2 blocker in `ChainSync::process_blocks`: conflicting already-held blocks called
`rollback_to_height` BEFORE `validate_block`. The rollback exemption checked only
whether orphaned blocks had transactions. It deleted block records and rewound
the public tip, but never rewound execution progress, state, ordering or QC rows.
Even a zero-transaction block advances `sys:last_executed_height`; post-loop fee
sweeps and epoch handling are also not conditional on transaction count.

New `sync/src/reorg_acceptance_tests.rs` uses actual `process_blocks` execution
and persistence in unique temporary RocksDB directories, real validator keys and
matching execution roots. Baseline command:

```sh
cargo test --locked --offline -p chain_sync --lib reorg_acceptance -- --test-threads=1 --nocapture
```

Before the production fix: **1 passed, 3 failed**. The positive duplicate/normal
successor control passed. Unsigned conflict, validly signed conflicting block,
and a longer signed fork deleted already-executed empty history. The two-block
cases explicitly printed `result=1, stored_tip=1, executed=2, block_2_exists=false`.
The longer fork rewound a three-block tip to 1. This demonstrates persistent
chain/execution inconsistency and availability impact, not a theft/double-spend
or a QC-backed conflicting-finality proof.

Removed the partial rollback helper and the transaction-count exemption. A
conflicting peer block now ends that batch without writes or a persistent halt;
normal matching duplicates/extensions still use the existing acceptance path.
Even a valid proposer signature or a longer chain cannot authorize fork adoption.
The old test that expected empty-orphan replacement only seeded block JSON, never
executed those blocks. Its expectation and the historical audit's empty-block
claim were corrected; the new tests cover actual execution and full-row equality
before/after rejection and flush/drop/reopen. A second positive control checks
that rejection does not prevent a subsequent valid extension from executing.

This closes the destructive peer-triggered partial rollback path, NOT complete
fork recovery. Authenticated fork choice and atomic reconstruction/undo of state,
execution markers, ordering and certificates remain required, including a
liveness argument for legitimately divergent unfinalized tips. No repair of
already-damaged databases is attempted. No live access, deploy or reset occurred.
Merely putting the old deletes in one
[RocksDB atomic batch](https://github.com/facebook/rocksdb/wiki/Basic-Operations#atomic-updates)
would make those edits atomic, not supply missing state undo or fork authority.

Post-fix focused reorg run: **7 passed** (four new tests plus three existing
reorg cases), followed by an additional post-rejection extension control. The
final focused `reorg` rerun including that control completed **8 passed**. The
selected broad regression below includes all five new tests and completed with
**422 passed, 0 failed, 12 ignored**: blockchain 23, chain_sync 51/2 ignored,
consensus 151/8 ignored, parent integration 11, executor 81/2 ignored, governance
15, node library 37, node binary 18, storage 30, vm_move 5. Strict all-targets
clippy for chain_sync/executor/node passed (37.13s). The ignored identity,
equivocation and state-authentication witnesses are not cleared by this run.
Local macOS node release build (`cargo build --locked --offline --release -p node
--bins`) passed in 23.51s. `git diff --check` passed. No commit or push.
Explicit final legacy identity rerun (`-p chain_sync --lib block_identity --
--include-ignored --test-threads=1 --nocapture`) still returned **1 passed,
2 failed**, with both substitutions reaching execution/storage. The reorg fix
does not close that separate G0 blocker.

```sh
cargo test --locked --offline -p chain_sync --lib reorg -- --test-threads=1 --nocapture
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move -p node --lib --test parent_identity --bin node -- --test-threads=1 --quiet
cargo clippy --locked --offline -p chain_sync -p executor -p node --all-targets --no-deps -- -D warnings
```

## V2 content and signature envelope

Added `identity_v2::envelope` with an in-memory signed block/body contract. It
shares the canonical identity and list commitments rather than inventing another
hash, and requires caller-supplied trusted epoch/height/parent/eligible keys plus
the verified format policy. Both the deterministic proposer and copy signer must
be eligible and match their address derivation; weak selected keys, absent keys
and malformed signatures are rejected. Builder and verifier use the same content
checks. An authenticated result borrows the block immutably, not the database or
the caller's authority snapshot.

Transactions, vertices and evidence are recomputed against the signed roots.
There is now one combined conservative 16 MiB body budget rather than a separate
16 MiB budget for each byte-list. Tests include its exact boundary and one byte
over it, empty-body commitment requirements, all fifteen identity mutations,
the exact round/timestamp substitution, body resegmentation/reordering, altered
body plus updated roots under an old signature, valid signatures over invalid
context, signer substitution, missing/inconsistent/weak authority keys and wrong
signature domains. The final scope test deliberately accepts signed but unproven
execution/finality claims: authentication is not execution or consensus validity.

A nonempty identity/signature vector was independently encoded and signed using
Node's crypto implementation, then frozen and checked by Rust/dalek and the
JavaScript reference program. See `BLOCK_IDENTITY_V2_PLAN.md` for the exact vector
and API limits. These public test seeds are not validator credentials.

No network deserializer or allocation-safe wire envelope exists yet; callers
must bound raw input before materialization. No production Block, producer,
ChainSync, QC, ordering or genesis caller uses this type. Thus G0's two legacy
substitution witnesses remain open, and there is no activation or migration.
Next work must connect the shared contract to authenticated bootstrap/upgrade
policy and the actual atomic execution/ordering/QC acceptance path; standalone
envelope tests do not satisfy that integration gate.

Verification: the complete blockchain library passed **33 tests**, including ten
new envelope tests. Independent JavaScript vectors passed. Selected broad
regression completed **432 passed, 0 failed, 12 ignored**: blockchain 33,
chain_sync 51/2 ignored, consensus 151/8 ignored, parent integration 11, executor
81/2 ignored, governance 15, node library 37, node binary 18, storage 30, vm_move 5.
Strict clippy for blockchain/chain_sync/node all targets passed (35.80s).
The broad run preceded the final ordering change that verifies the small
signature before hashing a large body. The final complete blockchain-library
rerun after that change again passed all **33 tests**, including an assertion
that invalid-signature rejection precedes body validation. No runtime caller
was switched, and the ignored legacy identity witnesses were not rerun in this
increment; they remain open, not implicitly passed. No live access, deployment,
restart, reset, genesis migration, commit or push.

```sh
cargo test --locked --offline -p blockchain --lib -- --test-threads=1 --quiet
node scripts/tests/block_identity_v2_vectors.mjs
cargo test --locked --offline -p storage -p executor -p chain_sync -p consensus -p blockchain -p governance -p vm_move -p node --lib --test parent_identity --bin node -- --test-threads=1 --quiet
cargo clippy --locked --offline -p blockchain -p chain_sync -p node --all-targets --no-deps -- -D warnings
```

Final blockchain-only all-targets clippy after the verification-order change
passed (8.84s). Local macOS node release build with `--locked --offline --release
-p node --bins` passed (16.24s). `git diff --check` passed. These are local build
and test results, not operational deployment evidence.

## V2 bounded wire increment (not activated)

Added `consensus/blockchain/src/identity_v2/envelope/wire.rs` using the locked
BCS 0.1.6 slice-backed `DeserializeSeed` API. Count bounds are enforced before
vector reservation or element requests; borrowed byte limits and one combined
body budget precede payload copying. The small trusted-context/header signature
check precedes all body decoding. Body commitments are then checked before an
owned block is returned. The returned mutable block is not an adoption token:
execution and authority must still be checked in the eventual acceptance
transaction. No production protocol/Block/producer/sync/QC consumer was switched.

Nine new tests cover canonical round trip, independently encoded full-wire
fixture, every truncation, trailing/unknown/nonminimal framing, header-first
rejection, oversized input/header/item/counts, accepted maximum item counts,
aggregate exact boundary and one byte over, and content/context substitution.
A sequence spy proves invalid counts/framing budgets reject before asking for
elements; the byte visitor retains the original borrowed slice. This is not
allocator fault injection, differential fuzzing, a global network-memory bound,
or authenticated recovery validation. Per-request bounds still need integration
with framing, queues, concurrency and rate budgets.

Selected broad regression on the final source completed **441 passed, 0 failed,
12 ignored**: blockchain 42, chain_sync 51/2 ignored, consensus 151/8 ignored,
parent integration 11, executor 81/2 ignored, governance 15, node library 37,
node binary 18, storage 30, vm_move 5. Independent Node.js vectors and
`git diff --check` passed. Ignored tests are not evidence of passing security
gates; the legacy acceptance witnesses remain a separate explicit gate.

Explicit rerun with `cargo test --locked --offline -p chain_sync --lib
block_identity -- --include-ignored --test-threads=1 --nocapture` finished
**1 passed, 2 failed** (exit 101). The unchanged-block control passed. Both
resegmented round/timestamp and substituted unsigned anchor still reached real
execution/storage under the reused legacy signature. G0 remains open, not
resolved by the new codec's isolated tests. No live access, deployment, restart,
reset, genesis migration, commit or push occurred.

Final source checks for this wire increment: strict all-targets clippy for
blockchain/chain_sync/node passed (36.77s), and local macOS node `--bins` release
build passed (21.20s), both `--locked --offline`. These do not change the two
explicit legacy acceptance failures or demonstrate a Linux deployment.

## Sync admission snapshot correction

The next V2 integration inspection reproduced an existing check/use gap in the
actual `ChainSync::process_blocks` path. A test-only hook changes storage after
the unlocked precheck and before execution takes its locks. Baseline result:
**1 passed, 2 failed**. A revoked author still committed height 1; a child still
committed height 2 after its stored parent was replaced. The unchanged-context
control passed. This proves use of stale admission data under the controlled
interleaving, not remote arbitrary DB mutation or a demonstrated conflicting QC.

Added `Executor::execute_block_admitted_at`, preserving `BLOCK_EXECUTION_LOCK`
and the existing private storage transaction. Admission runs against the
writer-gated pre-execution view before entering execution; acceptance remains in
the same staged write. Legacy sync now re-reads parent, current author/key and
held QC in this callback. Execution-root policy reads also use the transaction
view. A callback error discards all staged state. Existing checked-execution
callers still use their previous contract; local producer admission and full V2
format/epoch policy integration remain unfinished.

Focused verification: **7 sync tests passed** (control, revoked author, changed
signer key, replaced parent, missing parent, newly held conflicting QC, malformed
held QC), checking all stored rows including after flush/drop/reopen. The QC test
injects a prepared held record and does not test or bypass QC import. Its first
fixture accidentally changed the active committee and was rejected too early;
the corrected fixture uses matching proposer/Ed25519 records, re-signs the BLS
vote and explicitly asserts the precheck passes before installing the hook.
**2 executor tests passed** using real signed Move transfers: rejected admission
never enters execution, post-execution rejection preserves all rows, and retry
commits successfully with admission seeing parent state and acceptance seeing
staged execution progress. Reopen checks are not physical power-loss tests.

The design requirement is consistent with RocksDB's distinction between batch
atomicity and protecting read/write preconditions in its
[transaction documentation](https://github.com/facebook/rocksdb/wiki/Transactions#guarding-against-read-write-conflicts).
AINCORE uses its existing shared writer gate and staged view here, NOT native
RocksDB `TransactionDB`/`GetForUpdate`. This change does not prove the entire
application's isolation or prevent writes that bypass the storage abstraction.

Final selected regression: **450 passed, 0 failed, 12 ignored** (blockchain 42,
chain_sync 58/2 ignored, consensus 151/8 ignored, parent integration 11,
executor 83/2 ignored, governance 15, node library 37, node binary 18, storage 30,
vm_move 5). Strict all-targets clippy for executor/chain_sync/node passed (37.36s).
Explicit legacy identity rerun with `--include-ignored` again returned **1 passed,
2 failed**: unchanged control accepted, both signature substitutions accepted
incorrectly. Those failures are still readiness blockers, not hidden successes.
Full legacy validation now runs again under the writer gate; its critical-section
latency and aggregate network CPU/queue budget need measurement before rollout.
Local macOS node `--bins` release build passed (15.45s, `--locked --offline`);
`git diff --check` passed. This is not a deployed or Linux release validation.

Still open: canonical V2 producer/sync/QC/activation integration, the two legacy
identity substitution witnesses, empty-set/historical committee semantics,
equivocation liveness, authenticated state recovery, durable QC backfill and
release/independent operational gates. No live access, deployment, restart,
reset, genesis migration, commit or push.

## Fail-closed current committee admission

The real sync/execution/storage path reproduced five additional invalid-state
admissions: missing committee, empty preferred committee, malformed v1 with a
valid legacy mirror, duplicate addresses, and a zero-stake author. Each signed
block was incorrectly stored at height 1. Initial focused result: **7 passed,
5 failed**. The fixtures use real derived Ed25519 account addresses/signatures;
they do not demonstrate how a remote peer could corrupt local committee records.

Added `StateDB::get_active_validators_checked` and used it for BOTH unlocked
sync prechecks and writer-gated admission. It reads raw bytes so malformed UTF-8
cannot masquerade as an absent v1 record. A present v1 record is authoritative:
invalid JSON/schema, duplicate or blank addresses, empty/zero-power sets fail
closed without selecting the legacy mirror. The legacy record is consulted only
when v1 is absent. Zero-stake entries confer no eligibility; both the block
proposer and copy signer must be in the resulting positive-stake set. Valid
distinct proposer/copy-signer blocks remain accepted.

Five storage tests cover source precedence, malformed/missing/empty/schema and
numeric errors, raw invalid UTF-8, duplicate addresses (including a zero entry),
and staged-view reads. Seven new sync tests exercise the five baseline cases,
committee clearing after precheck, and a zero-power copy signer versus the valid
positive-power control. Rejections preserve all rows through flush/drop/reopen;
they do not write a permanent halt latch or silently repair metadata.
Focused final suites: storage eligibility **5 passed**, complete sync **65 passed,
2 ignored**. Six older hash/timestamp unit fixtures needed explicit validator
membership so they reach their intended later checks; no expected rejection
was weakened or removed.

Selected full regression completed **462 passed, 0 failed, 12 ignored**:
blockchain 42, chain_sync 65/2 ignored, consensus 151/8 ignored, parent integration
11, executor 83/2 ignored, governance 15, node library 37, node binary 18,
storage 35, vm_move 5. Strict storage/chain_sync/node all-targets clippy passed
(40.05s). The explicit legacy identity suite was rerun with `--include-ignored`:
**1 passed, 2 failed** (exit 101), still accepting the round/timestamp and anchor
substitutions under reused signatures. These remain blockers.
Local macOS node `--bins` release build passed (21.31s, `--locked --offline`),
and `git diff --check` passed. No live operations, commit or push occurred.

This loader authenticates neither historical committees nor BLS/PoP or key/address
bindings; it validates current eligibility records for the existing sync rules.
The permissive compatibility/discovery getter still exists for other callers;
this increment does not claim every consensus consumer was migrated. Genesis
contents, hashes, versions, voting thresholds and live nodes were not changed.
Absent v1 still permits a legacy-only store; without a trusted schema/epoch
requirement the loader cannot distinguish legitimate legacy state from deletion
of a newer record. Rejecting malformed PRESENT records is not proof against
wholesale DB substitution. Pinned genesis/history and authenticated recovery
must supply that missing authority in the final integration.
Canonical V2 integration, frozen epoch authority, the two legacy identity
witnesses and the other readiness gates above remain open.

## Release asset security gate

The previous release workflow built and uploaded binaries without running the
ignored security witnesses. `scripts/release_security_gate.py` now inventories
three critical library targets and requires 11 exact tests, including seven
currently red witnesses and four controls. Missing names, new unclassified
ignored tests, stale exclusions, zero-match results and timeouts fail closed.
The real local run returned exit 1: **4 controls passed, 7 assertions failed**.
Eight Python gate tests pass, including zero-test/ignored-result rejection and a
real subprocess timeout. V2 JavaScript fixed vectors also pass.

The locally edited release workflow depends on this gate before binary jobs,
pins Rust 1.90.0, uses locked Cargo commands and retains diagnostic evidence on
failure. YAML and required-job structure were checked locally; hosted Actions
was not run. No publication, push or live operation occurred. This change does
not repair the seven protocol/state witnesses or certify mainnet readiness.
See [Release security gate](RELEASE_SECURITY_GATE.md) for exact commands,
classification reasons, failure scopes and enforcement limits.

## Durable QC work for newly accepted blocks

A real-producer subprocess witness reproduced permanent loss of QC work after
the acceptance transaction committed but before attestation. The unchanged
block survived reopen while its QC remained absent; the clean control succeeded.
The local producer and follower adoption now stage their exact QC context with
acceptance/ordering and adopted-height metadata. A bounded retry worker retains
partial requests until a verified complete QC exists and publishes signatures
only after the existing durable guards commit. Missing adoption metadata no
longer defaults to the current tip.

The producer crash witness, follower adoption crash boundaries and complete/
partial worker crash/replay tests pass. Full consensus library validation is
**160 passed, 0 failed, 8 ignored**. The gate manifest adds the three crash
witnesses; it must still fail for the seven previously open safety/state tests.
Earlier sections describing the absence of an outbox are historical checkpoints;
this increment supersedes them ONLY for newly staged requests.

See [QC recovery](QC_RECOVERY.md) for evidence and limits. Old missing requests,
pending-work dependency retention, queue growth/backoff, trusted historical
reconstruction and operational delivery remain open. No live actions or genesis
migration occurred, and no mainnet-readiness claim follows from these tests.

## Ethereum rigor benchmark

Use portable state-transition fixtures with explicit preconditions, blocks, and
expected postconditions, plus black-box multi-node tests for synchronization,
protocol conformance, and APIs. These are engineering patterns drawn from
Ethereum's execution tests and Hive, not a claim that Ethereum fixtures can run
unchanged against AINCORE or that AINCORE has independent client implementations.
An independent reference model and differential replay remain required work.

## Research anchors

- [Bullshark, partially synchronous version, section 2.1](https://arxiv.org/pdf/2209.05633): ordering assumes causal completeness, reliability and non-equivocation.
- [Narwhal and Tusk, sections 3 and 4](https://sonnino.com/papers/narwhal-and-tusk.pdf): certification and retrieval jointly supply the dissemination contract.
- [Mysticeti v4, algorithms 1-3](https://arxiv.org/html/2310.14821v4): uncertified DAGs require their own voting and decision rules, not a partial substitution into Bullshark.
- [RocksDB atomic updates](https://github.com/facebook/rocksdb/wiki/Basic-Operations#atomic-updates): atomicity of a WriteBatch does not make several separate database operations one transaction.
- [RocksDB transactions](https://github.com/facebook/rocksdb/wiki/Transactions): native transactions provide atomic commit/rollback and conflict handling; plain reads and tracked reads have different isolation semantics.
- [Rust Mutex poisoning](https://doc.rust-lang.org/std/sync/struct.Mutex.html#poisoning): poison recovery is an explicit choice, and poison detection is advisory rather than a complete integrity mechanism.
- [Ethereum Hive overview](https://github.com/ethereum/hive/blob/master/docs/overview.md): black-box client integration, synchronization, protocol compliance, and API tests.
- [Ethereum blockchain test fixtures](https://steel.ethereum.foundation/docs/execution-specs/running_tests/test_formats/blockchain_test/): explicit initial state, block inputs, and expected final state.

These sources constrain the design; they do not prove AINCORE implements it.
Reconcile older register sections against current code before reusing a claimed
fix status or implementation order.
