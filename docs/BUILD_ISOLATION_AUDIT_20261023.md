# Cross-checkout build artifact isolation

Date: 2026-10-23. Scope: isolated NAS build/test infrastructure, not a consensus
protocol change. Status: defect reproduced; runner controls PASS; full corrected
candidate run still required. No deployment or mainnet clearance.

## Failed candidate

`aincore-final-candidate-20261022.service` ended at 2026-10-22 16:58:06 UTC with
`stage=process-exits`, exit 1. Its source was the clean `e1a8799` checkout at
`/home/alpha/aincore-release-candidate-20261022`.

The inner regression reported success, including 131 required witnesses, but
the selected binary still exited 0 for an occupied P2P listener and an actual
RocksDB flush failure. The latter also printed a false drain-complete message.
The clean-shutdown control passed. Source contained the corrected `ExitCode`
paths from `1943b4e`; their focused process checks had passed on both hosts.

The final release command finished in 2.36 seconds using the shared target
`/home/alpha/aincore-hardening-20261016/target`. The copied binary had the same
hash and earlier modification time as that target's existing node:

`711ca4535e22171b5850413cc1be29bd9656b741f83b9630b4f21c33a33dbe43`.

A matching `.d` path is not evidence that a compiler rebuilt the workspace.
Preserve the failed candidate logs. Its successful stage labels do not establish
source-to-artifact attribution or candidate clearance.

## Independent minimal reproduction

`scripts/tests/cargo_shared_target_probe.py` builds dependency-free disposable
crates on NAS with Cargo/rustc 1.95.0. Both source trees exist before the first
build; package metadata is identical, but their programs have different exits.

| Build | Expected exit | Observed exit | Outcome |
| --- | --- | --- | --- |
| A, shared target | 0 | 0 | Control PASS |
| B, same target after A | 17 | 0 | Stale artifact REPRODUCED |
| B, new isolated target | 17 | 17 | Isolated control PASS |

The first two binaries have identical SHA-256 despite different source hashes;
the isolated B binary differs. See [raw result](evidence/20261023/cargo-cache-reproduction.json).
Unit `aincore-cache-repro-20261023.service` exited 0 in 1.522 seconds under one
CPU, 512 MiB RAM, 256 MiB swap and a four-minute cap. This proves the cache
failure mechanism on the installed toolchain; it is not yet the full AINCORE
candidate retest. Nothing was compiled on the Mac.

Cargo's [cache documentation](https://doc.rust-lang.org/cargo/reference/build-cache.html)
separates target and intermediate build directories. The
[1.95.0 fingerprint implementation](https://github.com/rust-lang/cargo/blob/rust-1.95.0/src/cargo/core/compiler/fingerprint/mod.rs)
describes relative source paths and mtime freshness checks. Those checks explain
why shared output is not an acceptable source-identity guarantee for these
pre-staged checkouts. We do not replace this with an unstable compiler feature.

## Repair and controls

`scripts/hardening_regression.sh` now:

- Creates an empty build directory inside every new report directory. Overrides
  both `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`; disables inherited compiler
  wrappers. Dependency download caches may remain shared, compiled output may not.
- Refuses existing report directories. Does not clean or overwrite an old target.
- Accepts `--output NEW_DIRECTORY` and records the absolute build path in
  `build-target.txt`. Callers must use this run's recorded path for artifacts,
  never their inherited target or a glob for the latest binary.
- Builds deployable binaries before the long regression. Optional
  `--probe-genesis TEST_GENESIS` runs the real Linux process-exit probes against
  this exact binary before continuing. The supplied lab genesis is read-only;
  keys/databases belong only to new disposable probe directories.
- Rejects source/HEAD changes observed at completion and preserves interrupted
  or failed stage status. This check is not protection against an adversarial
  source mutation followed by restoration; use an isolated frozen checkout.

Nine runner unit tests passed on NAS, including shared-cache non-mutation, fresh
directories across runs, explicit artifact handoff, failing process probes,
source/revision changes, and signal handling. These controls use fake build
commands, not actual blockchain compilation. See [test output](evidence/20261023/build-isolation-controls.txt).

## Required follow-through

Run the corrected candidate in a frozen checkout with fresh native and ARM
build directories, bounded serial jobs, full logs and artifact hashes. Require
native process exits 1/0/1, full mandatory regression/witnesses/lint, then package
and extracted-runtime checks. Verify the ARM artifact on Pi separately; a cross
compiler success does not prove ARM runtime behavior. Do not restore a shared
target just to shorten this first corrected run.

The prior runtime fixes are not reverted, and no new consensus bug is established
by this build failure. Other operational, adversarial, independent-review and
launch gates in [MAINNET_LAUNCH_PLAN.md](MAINNET_LAUNCH_PLAN.md) remain applicable.
