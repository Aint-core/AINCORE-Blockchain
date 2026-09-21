# Release security witness gate

This is a necessary release-asset gate, not a mainnet-readiness certificate.
The current implementation is intentionally RED because required security
properties are still violated. Do not turn these failures into exclusions to
ship a binary. Repairs need protocol review and adversarial regression evidence.

## Run locally

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

- Enumerate library tests and ignored library tests separately in `chain_sync`,
  `consensus` and `executor`. Inventory counts and names must agree.
- Every required exact name must exist. Every ignored test in those inventories
  must be required or have a checked-in exclusion reason. Stale exclusions fail.
- Run each required test with `--exact --include-ignored --test-threads=1`.
  Success requires exit 0, the named test's successful result, and exactly one
  passed / zero failed / zero ignored. A zero-match filter cannot pass.
- Continue through red witnesses to collect all outcomes. A cargo command gets
  at most 30 minutes; timeout kills and reaps its process group and fails the gate.
- Classification lives in `scripts/release_security_witnesses.json`. It needs
  code review, like the tests themselves; there is no CLI skip/waiver option.

This inventory is deliberately limited to three library targets. It does not
certify every ignored integration test or every crate/feature combination. The
existing ignored node libp2p smoke test is outside this inventory and is not proof
of cross-process delivery. That remains a separate networking gate.

## Current local evidence

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

Latest local validation after the durable QC recovery increment: eight Python
tests passed; the selected normal Cargo regression command below passed with
471 passed, zero failed and 13 ignored; JavaScript fixed vectors passed.
Storage/chain_sync/consensus/node all-targets clippy with `-D warnings` passed
(31.33s). The local node release build passed (17.78s). These build results do
not override the seven red witnesses or prove hosted workflow execution.

```sh
cargo test --locked --offline -p blockchain -p chain_sync -p consensus -p executor -p governance -p node -p storage -p vm_move -- --test-threads=1
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
manual release creation, manual uploads or external publishing systems. Until
reviewed and pushed, the workflow change exists only in this local worktree.

Local Python tests and YAML/dependency-structure checks are not a hosted Actions
run. No release was created, uploaded, dispatched or deployed while developing
this gate. Live nodes, genesis, signing keys and databases were not touched.

Still required: canonical identity integration and trusted activation, a complete
consensus/dissemination design, authenticated state/recovery, durable QC backfill,
network resource/authorization gates, differential execution/economics replay,
physical failure exercises, independent review and sustained multi-operator
operational evidence. Passing this witness list alone does not close them.
