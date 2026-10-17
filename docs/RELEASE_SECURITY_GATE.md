# Release security witness gate

This is a necessary release-asset gate, not a mainnet-readiness certificate.
Determine the current result by running the gate on the candidate source tree.
The historical results below do not establish the status of later revisions.
Do not turn failures into exclusions to ship a binary. Repairs need protocol
review and adversarial regression evidence.

## 2026-10-16 local hardening checkpoint

This checkpoint preserves the pending round-19-through-30 audit work. It is not
an independent review of every earlier change, a release tag, or authorization
to activate new consensus rules on a running network.

Local verification exposed and repaired these integration problems:

- Workspace lockfile edges for `chain_sync -> da` and `vm_move -> rayon` were
  missing. No dependency versions or checksums were changed.
- The release regression command selected the removed `governance` package.
- The B464 rejoin fixture used six integer literals outside its `u8` key seed
  range; all references now consistently use distinct in-range seeds.
- `staking.mv` and `delegation.mv` were stale relative to their sources. In
  particular, reward execution supplied six arguments to old five-argument
  bytecode. They were regenerated and checked against the pinned Move compiler.
- Gas simulation deducts zero fees. After B460, an unchanged simulated payer
  CoinStore therefore omitted history gas that a real fee deduction incurs.
  Estimates now include that history exactly once, including when the payload
  already changes the payer's balance. Execution pricing itself is unchanged
  by this estimator repair.
- Crash fixtures' old 100K execution budgets no longer paid for retained
  history. Both transfers are now funded and execute before injected crashes.
  Their golden root was repinned for the changed fixture funds, limits and
  stdlib; crash/replay still compares all rows to a separate clean run.
- Generated SDK modules exported by `dist/index.js` are now tracked together
  with the existing distribution, including address, BCS, DA and state proofs.

The B458 pricing change and its limitations are described below. No live
database, service, signing key, or genesis was changed. Bytecode/gas changes
still need an explicitly approved, coordinated activation plan.

### Verification outcome

Code checkpoint: `8f453b5b`, source tree
`07bd8513972546907eff9058cea4995d5d26eb3a`. Local macOS ARM64 verification
used Rust 1.90.0, locked offline dependencies, and serial test execution.

Completed library results, across separate runs (not one green workspace run):

| Package | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| blockchain | 82 | 0 | 0 |
| chain_sync | 253 | 0 | 1 |
| consensus | 416 | 0 | 7 |
| executor, after the final fixture repairs | 218 | 0 | 2 |
| vm_move | 31 | 0 | 0 |

The executor results include the 13 crash/replay tests and gas-estimation
regressions; do not count those subsets again. The VM run includes regenerated
bytecode/source equality. The gate's Python controls passed 10/10. SDK tests,
block identity vectors, and the 12-check synthetic DR roundtrip also passed;
the latter is not evidence of a successful recovery from a live backup.

The broad eight-package run compiled before the final two executor fixture
repairs and reported those two failures. A subsequent complete executor Cargo
run passed 218/218 non-ignored tests. The broad run was stopped at node binary
startup: a process sample remained in `_dyld_start`, before test output. Host
swap usage was approximately 29 GB; the underlying startup cause is not proven.
Node, storage and state_commit full-suite completion is therefore unverified
in this run. No failed result has been relabeled as passing.

The first diagnostic witness gate reported 119 passing witnesses of 121 and
four errors: two pre-repair executor failures and two unclassified measurement
tests. The measurement-only exclusions now state their limits explicitly;
neither is evidence of a storage bound or validated gas calibration. The
current manifest requires 128 witnesses. Its final rerun was canceled during
compilation after the host startup stall, and produced no final JSON report.
**The complete release witness gate is NOT established as passing.**

Strict clippy was also canceled during native dependency compilation and is
not a pass. Fresh release binaries, the hosted Linux workflow, full integration
and feature-matrix testing, independent review, physical crash testing, and
multi-operator operational evidence remain required before release. Only local
verification processes were terminated; no live service was changed.

## 2026-10-17 NAS follow-up

The NAS run of `ed2fa1b` completed with 120 passing witnesses, but the gate
failed: `chain_sync` could not build its normal executor dependency, so its
eight witnesses did not run. The estimator called `coin_store_key`, which
was incorrectly restricted to `cfg(test)` or `test-support`. This is a build
integration failure, not a passing 128-witness result.

The pure resource-key helper is now available in normal builds; no seeding
helper or `test-support` feature was enabled for production. The gate first
builds executor alone with `--no-default-features` and fails if that build fails
or times out, even when all unit witnesses pass. A new gate control tests both
failure modes. A fresh NAS report is required to verify this repair. This
normal development-profile build is not a substitute for release-profile CI.
All 11 Python gate controls passed on the NAS after this change. The Rust
normal-build and witness rerun are still pending; do not infer their success
from those control tests.

## Run locally

NAS verification of clean commit `67cb23f0b4491b824d4aceb06d7f8b4627309b5d`
finished on 2026-10-17 at 11:30:07 UTC using Rust/Cargo 1.95.0: the normal
executor build and all 128 required witnesses passed, with no gate errors.
The NAS report is `target/nas-release-security-gate-67cb23f.json`. This does
not establish the full regression, strict lint or release build results, nor
the separately pinned Rust 1.90.0 hosted workflow.

For the next isolated stage, `bash scripts/hardening_regression.sh` runs gate
controls, the eight-package tests including integration tests, strict clippy,
and release builds of node/indexer/CLI/genesis-tool, stopping at the first
failure. Each stage has its own log under a unique
`target/hardening-regression-*` directory. Only `stage=complete` with
`exit_code=0` in `result.txt` establishes that all stages completed. A missing
result after a power cut or forced termination is incomplete, not success.
Run it with external CPU/RAM/time limits; it does not launch or deploy nodes.

From the repository root, with Rust 1.90.0 and Python 3 available:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_release_security_gate.py' -v
python3 scripts/release_security_gate.py --offline
```

Omit `--offline` on a fresh machine that must download Cargo dependencies.
The runner uses `--locked`. Its default JSON report is
`target/release-security-gate.json`, containing the exact manifest, commands,
stdout/stderr, exit codes, timestamps, compiler versions, HEAD and dirty status.
HEAD alone does not identify dirty compiled source. Reports are local diagnostic
evidence, not signed provenance. Exit 1 means the gate failed, including missing
tools, timeout, inventory errors, missing tests or a red witness.

## Contract

- Build executor as a normal library in a separate Cargo invocation, without
  default features or test-support. A failure or timeout fails the gate even
  if all subsequently collected witnesses pass.
- Enumerate library tests and ignored library tests separately in `blockchain`,
  `chain_sync`, `consensus`, `executor`, `node`, `state_commit`, `storage` and
  `vm_move`. Inventory counts and names must agree.
- Every required exact name must exist. Every ignored test in those inventories
  must be required or have a checked-in exclusion reason. Stale exclusions fail.
- Run each required test with `--exact --include-ignored --test-threads=1`.
  Success requires exit 0, the named test's successful result, and exactly one
  passed / zero failed / zero ignored. A zero-match filter cannot pass.
- Continue through red witnesses to collect all outcomes. A cargo command gets
  at most 30 minutes; timeout kills and reaps its process group and fails the gate.
- Classification lives in `scripts/release_security_witnesses.json`. It needs
  code review, like the tests themselves; there is no CLI skip/waiver option.

This inventory is deliberately limited to these eight library targets. It does not
certify every ignored integration test or every crate/feature combination. The
existing ignored node libp2p smoke test is outside this inventory and is not proof
of cross-process delivery. That remains a separate networking gate.

## Round 28-30 regression coverage

The required manifest includes the VM stack ownership and foreign-pool tests,
the depth-bound VM stack test, the three publish-time layout/entry-return
bounds tests, and native-reference/resource-size gas tests (B434, B458, B461).
The stack witness is named
`gas::tests::a_value_at_the_depth_bound_fits_the_vm_stack`; the older
`a_value_at_the_depth_bound_fits_a_default_stack` name is obsolete.

A passing package or mutation total cannot substitute for any required witness.
The gate tests exercise both a missing stack witness alongside passing VM tests
and an inventoried witness that runs zero tests. Both must fail the gate.
The B458 accounting follow-up charges 16 gas per additional struct occurrence
in a first resource access's type arguments. Native calls pay 16 per struct in
all type arguments before entering the native, plus the type name's size;
an empty vector still pays for its element type. The executor's 9,216-node
per-root work cap derives from the same price at 576 nodes/gas. Cached resource
accesses do not pay a second layout charge. Required witnesses cover branching
and vector-wrapped types, multiple native arguments, cache hits and insufficient
gas. This changes consensus gas accounting and requires coordinated protocol
activation; it is not authorization to deploy or change genesis.

The upstream resource loader still constructs a layout before invoking the gas
hook. This change prices completed accesses; it does not preempt the first
layout build on a failing or out-of-gas access. Publish bounds still limit that
work, and modules accepted before those bounds need separate treatment. These
limits and independent review remain open; a current compiled gate report is
required before claiming even the selected regression set passes.

## Historical local evidence (before the V4/G3 integration)

The actual runner completed with **7 passed controls, 7 failed witnesses**, exit
1. All six inventory commands succeeded, all 14 names matched and no unknown
ignored tests or stale exclusions were found. All seven failures were test
assertions with cargo exit 101, not build failures or timeouts:

| Area | Witnesses | Observed failure and scope |
| --- | --- | --- |
| Legacy block identity | 2 | Round/timestamp resegmentation and substituted unsigned anchor were admitted with reused signatures through sync/execution/storage. Not a SHA-256 collision. |
| Equivocation retention | 1 | Two honest stores retain different twins after receiving the same inputs in different orders. |
| Direct quorum invariant | 1 | Production ordering helper accepts both twin candidates in a direct internal harness. Not by itself proof of a remotely reachable fork or two conflicting QCs. |
| Equivocation liveness | 1 | Signed-message harness cannot recover a discarded supporting parent after retransmission/reopen; finite honest tail does not decide on one side. |
| Authenticated state | 2 | Out-of-band row changes and a tampered snapshot leave the stored state root unchanged. |

Controls cover unchanged signed-block acceptance, complete-history liveness,
both thin/round-skipping anchor ingress defenses, and three durable QC recovery
crash witnesses. See [QC recovery](QC_RECOVERY.md) for their scope and remaining
retention/backfill limitations. Five explicitly classified
ignored tests are excluded: four measurement/experimental-model probes and one
direct ordering scenario that bypasses the enforced thin-anchor ingress premise.
Its two production ingress controls are mandatory. This is not a claim that the
isolated decision function is sound.

## Workflow enforcement and limits

At that historical checkpoint after the durable QC recovery increment, eight Python
tests passed; the then-selected normal Cargo regression command passed with
471 passed, zero failed and 13 ignored; JavaScript fixed vectors passed.
Storage/chain_sync/consensus/node all-targets clippy with `-D warnings` passed
(31.33s). The local node release build passed (17.78s). These build results
did not override the seven red witnesses or prove hosted workflow execution.
The commands below reflect the current package list: the removed `governance`
package is no longer selected. The historical counts above are not results of
rerunning these commands on the current tree.

```sh
cargo test --locked --offline -p blockchain -p chain_sync -p consensus -p executor -p node -p storage -p vm_move -- --test-threads=1
node scripts/tests/block_identity_v2_vectors.mjs
cargo clippy --locked --offline -p storage -p chain_sync -p consensus -p node --all-targets -- -D warnings
cargo build --locked --offline --release -p node --bins
```

`.github/workflows/release.yml` makes the binary build/upload matrix depend on
the security job. That job also requires gate unit tests, the selected normal
regression suite, cross-implementation V2 vectors and strict admission-path
clippy. The witness failures stop subsequent steps and prevent the dependent
binary jobs from starting; only diagnostic artifact upload uses `always()`.
This follows GitHub's documented
[job dependency semantics](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs).

Rust is pinned to 1.90.0, Cargo uses the lockfile and OS labels are explicit.
[Hosted runner images](https://github.com/actions/runner-images) still change;
action tags and native packages are not immutable. This is not bit-for-bit
reproducibility, dependency/supply-chain audit, or signed binary provenance.

The workflow still triggers on `release.created`: the release record can already
exist before testing. This change gates its workflow-produced binary assets, not
manual release creation, manual uploads or external publishing systems. A push
alone does not prove that the hosted workflow has run or passed.

Local Python tests and YAML/dependency-structure checks are not a hosted Actions
run. No release was created, uploaded, dispatched or deployed while developing
this gate. Live nodes, genesis, signing keys and databases were not touched.

Before release, independent review must validate canonical identity and trusted
activation, consensus/dissemination, authenticated state/recovery, durable QC
backfill, network resource/authorization gates, and differential
execution/economics replay. Physical failure exercises and sustained
multi-operator operational evidence remain separate gates. Passing this witness
list alone does not establish them.
