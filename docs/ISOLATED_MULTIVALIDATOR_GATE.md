# Isolated multi-validator gate

This is a local cross-process failure test, not a mainnet certification. The
runner uses four equal-stake validators, new random test-only keys, a unique
test chain ID and a generated test genesis. It never changes the repository's
genesis or any existing node database. Timing parameters are synthetic test
inputs, not measurements suitable for a production genesis.

The first launch alone sets `AINCORE_GUARD_ORIGIN_INIT=1`; a private marker keeps
that flag off on restart. No signing guard is reset during the recovery phase.

## Isolation and resources

Run `scripts/isolated_multivalidator_gate.py` on the NAS, not the Mac. It requires
Docker, a cached Linux image containing Python 3 and the libraries needed by the
release binaries, a clean source checkout, and already-built Linux binaries.
The image tag is resolved to an immutable local image ID before starting.

The runner creates a uniquely named internal Docker network, publishes no ports,
and records each resource it owns. Only those containers and that network are
removed during cleanup. Node data and logs remain in the new output directory.
Each node is limited to 512 MiB RAM, 768 MiB combined RAM/swap, half a CPU and
256 processes. No host networking, privileged mode or Docker socket mounts are
used. RPC requests are made inside each test container.

Example (paths must identify isolated checkouts and a new output directory):

```sh
python3 scripts/isolated_multivalidator_gate.py \
  --source /home/alpha/aincore-hardening-098480d \
  --binaries /home/alpha/aincore-hardening-20261016/target/release \
  --output /home/alpha/aincore-chaos-098480d-run1
```

## Assertions

1. Four distinct validator processes make progress and return locally verified
   QCs with strictly more than two-thirds stake for the expected test chain.
2. At every common certified height checked, block hash, state root, receipts
   root and finality digest agree, including across later crash/recovery phases.
3. After SIGKILL of one validator, the other three continue progressing.
4. Restarting that validator with its original data/key restores agreement.
5. Disconnecting two validators creates a 2+1+1 partition. After 30 seconds to
   drain in-flight work, certified heights remain unchanged for 45 seconds.
6. Reconnecting the same network addresses restores progress and agreement.

`result.json` is authoritative only when `passed` is true and `stage` is
`complete`. Failures and cleanup errors fail the run. `events.jsonl` records
observations; container logs and inspect output are retained. A missing result
is incomplete, never success. A forcibly killed supervisor can leave its own
containers behind; inspect their exact recorded names before manual cleanup.

## Limits

The QC verification is performed by node RPC, not a separate cryptographic
implementation. Unit tests exercise runner rejection of missing verification,
wrong chain/height, insufficient stake and empty commitments. Passing this
test does not establish independent-operator resilience, sustained transaction
load, malicious validator tolerance, epoch-transition soak, physical power-loss
durability, backup restoration, or absence of all bugs. A partition timeout can
also expose a harness/timing limitation and needs diagnosis, not an automatic
consensus-safety verdict. Do not rerun or weaken assertions without recording
why the previous attempt failed.

## Bring-up evidence

The first pilot on 2026-10-19 connected all four processes but did not initialize
their V4 launch guards or fund proof-of-boot transactions. It was interrupted,
reported as failed, and its own containers were removed. This was a fixture
configuration error, not a successful liveness test. The second pilot tried
funding validators through `accounts-file`, which the generator correctly
refused because validator and account entries must be disjoint. The third pilot
uses launch-only guard initialization without that invalid funding shortcut.
Recovery must satisfy the real protocol rules; no funding/guard bypass is used.
Only its eventual `result.json` can establish whether those scenarios passed.
