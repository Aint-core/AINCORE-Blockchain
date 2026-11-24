# Release runtime packaging audit

Date: 2026-10-22. Scope: release packaging and startup gates, not a release or
mainnet deployment. No live services, existing node data or network genesis
were modified. These are implementation self-tests, not independent sign-off.

## Reproduced defect

The release workflow archived only `node`. A fresh database needs Move stdlib
bytecode from the runtime working directory (`core/node/src/main.rs` genesis
initialization). The source checkout masked this missing artifact dependency.

[Node-only reproduction](evidence/20261022/package-node-only-failure.json):
the actual ARM64 node exited 1 before health became available. Its log reports
failure to read `core/vm_move/stdlib/bytecode` during genesis initialization.
This reconstructed the workflow's artifact layout; it was not a downloaded
published release. It demonstrates an install/startup failure, not corruption
of an existing chain.

## Repair

- Package the selected executable, the source-matching public bytecode, license,
  instructions and per-file hashes. Do not include genesis, environment files,
  signing keys or data. Publish an archive checksum separately.
- Refuse missing stdlib, symlinked modules, non-executable input and existing
  output. The package script publishes a completed archive without clobbering
  another artifact; it does not claim bit-for-bit reproducible archives.
- The release workflow must boot the extracted artifact before uploading it.
  It generates a disposable test genesis and runs an isolated observer with
  no bootnodes and its P2P listener disabled. The probe does not copy stdlib
  from the source checkout. It requires readiness, successful flush and exit 0.
- Preserve failed smoke JSON/logs without publishing generated keys or DBs.
  The probe refuses to overwrite or reuse an earlier smoke directory.
- Align both hosted compiler selections to the measured NAS compiler,
  Rust 1.95.0 (`59807616e1fa2540724bfbac14d7976d7e4a3860`, LLVM 22.1.2).
  This is the current candidate baseline, not a claim to use the latest Rust
  or to have evaluated every newer compiler fix. Hosted execution is pending.
- Pin smoke-test Python to 3.12 for `hashlib.file_digest` support rather than
  depending on the runner's unspecified default Python.

The [packaged README](RELEASE_PACKAGE.md) documents the working directory,
separate trusted genesis, new observer identity and checksum limitations.

## Executed evidence

Pi Linux ARM64. Runtime from `1943b4e`, whose Rust source is unchanged in
`e1a8799`. Binary SHA-256:
`6882bbd71cc21c8db20c8fdb3825d6e81d335025bf5e46e4495d80778bf890b4`.

| Check | Result |
| --- | --- |
| Node-only layout in a fresh working directory | FAIL retained; exit 1 before readiness |
| Packaged executable and 23 stdlib modules; all file hashes checked | PASS |
| [Extracted package runtime](evidence/20261022/package-extracted-arm.json) | PASS; readiness, clean flush, exit 0 |
| [Reusable CI smoke probe](evidence/20261022/package-ci-smoke-arm.json) | PASS locally on Pi, with the pinned disposable lab genesis |
| [Python controls](evidence/20261022/package-harness-controls.txt) | 90 PASS, including 5 package-content and 6 smoke-verdict controls; overlapping older suites are not added again |
| Release workflow YAML parsing | PASS locally; not hosted CI execution |

The first control-job invocation used systemd's home working directory instead
of the source directory and failed before test discovery. Its
[original error](evidence/20261022/package-controls-wrong-cwd.txt) is retained.
The corrected job explicitly set `WorkingDirectory` and completed with exit 0.
This was a test-launch error, not a runtime failure or a passing test run.

Actual package smoke jobs were bounded to one CPU, 1 GiB RAM, 512 MiB swap and
8/10 minutes. They took seconds; no Rust compilation ran on the Mac or Pi.

Archive hash in the extracted-package report identifies that local package,
not a GitHub release. The hosted smoke recipe's generated-genesis step and the
macOS artifact have not been executed by this report. Linux ARM64 remains a
local test target, not a newly advertised hosted release target.

## Remaining release gate

Run the actual candidate release workflow and retain compiler/dependency
metadata, artifact hashes, smoke evidence and trusted provenance for every
advertised target. Checksums are not signatures. The current two-target hosted
matrix does not produce a Linux ARM64 asset. Public joining, authenticated
recovery, G6 load/epoch acceptance and G7 review remain separate obligations.
The final NAS regression on `e1a8799` is still running as of 14:31 UTC; this
script-only repair does not turn an unfinished runtime gate into a pass.

## Primary basis

- [Rust release notes](https://doc.rust-lang.org/releases.html#version-1950-2026-04-16)
  identify the selected compiler release; the actual NAS metadata supplies the
  compiler commit and LLVM version used here.
- [rust-toolchain action](https://github.com/dtolnay/rust-toolchain) supports
  explicit toolchain selection. Selecting a version does not prove a build.
- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) provides the
  testing/remediation framework, not certification of these artifacts.
- [SLSA build requirements](https://slsa.dev/spec/v1.2/build-requirements)
  distinguish build provenance from a bare file digest; no SLSA level is claimed.
