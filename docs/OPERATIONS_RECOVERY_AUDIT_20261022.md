# Observer backup and restore audit

Date: 2026-10-22. Scope: operational scripts and disposable observer processes.
No live node, signing key, genesis or existing validator database was changed.
This is a self-review with executable evidence, not independent mainnet clearance.

## Findings and fixes

| Finding | Original evidence | Fix and retest |
| --- | --- | --- |
| Raw `--hot` tar copy advertised as crash-consistent | The old script accepted `--hot` and produced a success archive without coordinating live files. This demonstrates unsafe acceptance, not an observed corrupt production backup. | Reject `--hot` regardless of flag order; require stopped acknowledgment. |
| A held RocksDB LOCK only caused a warning | A separate process held a POSIX record lock; the old script still returned success. | Acquire the same POSIX write lock as RocksDB and hold it throughout tar; refuse missing/symlinked/busy locks. A real running observer was refused with exit 3 before archive creation. |
| Restore mutated the destination before validating the archive | With `--force`, invalid or DB-less archives moved the old DB before failing. | Validate extraction and exactly one real DB directory before moving the destination; valid forced restore still retains the old DB. |
| Restore into an existing empty DB folder nested the DB | Restore returned success but `CURRENT` was under a second DB directory. | Remove only that empty destination directory before installing the validated DB. |
| Ambiguous archives and symlinked DB destinations were accepted | Two DB entries picked the first; a symlink destination received nested files. | Reject these shapes before destination mutation. |
| Duplicate DR test used obsolete validator-key recovery | The `scripts/tests/` entrypoint failed with exit 3 at the required observer-only flag. | Delegate to the current canonical `scripts/dr/` drill; no obsolete key restore procedure remains in the duplicate. |

The scripts still require a trusted local archive, correct operator declaration
that the source is not a validator, and a stopped/fenced destination. They are
not an untrusted archive import service. A checksum is not publisher
authentication. The lock does not protect against a privileged actor replacing
the lock inode/datadir or a filesystem that does not honor POSIX locks.

## Primary basis

- [RocksDB Checkpoints](https://github.com/facebook/rocksdb/wiki/Checkpoints)
  documents a coordinated consistent snapshot of live DB files. The previous
  tar path did not use that mechanism.
- [RocksDB BackupEngine](https://github.com/facebook/rocksdb/wiki/How-to-backup-RocksDB)
  provides managed backup and verification APIs; an ordinary live tar is not
  equivalent to these APIs.
- [RocksDB 8.1.1 POSIX environment](https://github.com/facebook/rocksdb/blob/v8.1.1/env/fs_posix.cc)
  uses a whole-file `fcntl(F_SETLK)` write lock. `Cargo.lock` pins
  `librocksdb-sys 0.11.0+8.1.1`. The helper uses `fcntl.lockf`, not `flock`.

## Executed evidence

Linux ARM64 / Pi, Python 3.13.5. Script workspace:
`/home/pi/aincore-backup-safety-20261022`, initially scripts from `e1a8799`.

- [Original backup failures](evidence/20261022/backup-controls-before.txt).
- [Original restore failures](evidence/20261022/restore-controls-before.txt).
- [All Python harness controls](evidence/20261022/operations-harness-controls.txt):
  71 passed, including 8 backup and 6 restore tests. This is not 71 chain tests.
- [Canonical DR fixture](evidence/20261022/observer-dr-fixture.txt): 12 checks
  passed through the compatibility entrypoint. These are fabricated DB files.
- [Real observer roundtrip](evidence/20261022/observer-restore-arm.json): PASS,
  `aincore-observer-dr-20261022.service`, MainPID 0, result success, exit 0.
  Limits: one CPU, 1 GiB RAM, 512 MiB swap, 12 minutes maximum.

The real test used the `1943b4e` ARM binary:
`6882bbd71cc21c8db20c8fdb3825d6e81d335025bf5e46e4495d80778bf890b4`.
The JSON records exact script and genesis hashes. It created a new observer,
refused backup while its real RocksDB lock was held, shut it down with exit 0,
backed up the stopped DB, restored it byte-for-byte without a key, then reopened
it with a distinct new identity. Chain identity, genesis and four account
responses matched; the restored process also flushed and exited 0.

Both observers were at genesis, with no peers and no certified transaction
history. That first experiment does not establish populated-chain recovery.

### Populated-history follow-up

[History restore report](evidence/20261022/observer-history-restore-arm.json):
PASS on the same ARM runtime. A new observer synced from the disposable lab to
at least the pinned reference height 2157, then was backed up while stopped and
restored under a new identity. Before and after restore, certified tip was 2166;
certified commitments at 1263 and 2157 matched the reference validator, the
successful historical receipt remained at block 1263, the recipient retained
1 AIN and the sender's nonce remained 4. Database bytes matched before reopening.
Both processes exited 0 and flushed; a running-DB backup was refused with exit 3.

Two unsuccessful harness runs are retained:
[immediate busy/null](evidence/20261022/observer-history-busy-failure.json) and
[bounded busy timeout](evidence/20261022/observer-history-busy-timeout.json).
The status API intentionally returns a null node identity with
`consensus_busy=true` while replay owns the lock (`core/node/src/api_local.rs`).
The probe now uses the identity from its own isolated child's startup log only
in that explicitly busy case, and records that source. It rejects unknown nulls
and RPC/startup identity mismatches. No state or QC assertion was bypassed.
[The expanded 79-control suite](evidence/20261022/observer-history-harness-controls.txt)
passes, including eight controls on this identity handling.

The history run was `aincore-observer-history-v3-20261022.service`, terminal
MainPID 0/result success/exit 0, limited to one CPU, 1 GiB RAM, 512 MiB swap and
20 minutes. It did not restore a validator's database or copy a validator key.
It verifies QCs through the node RPC, not an independent crypto implementation.

Authenticated checkpoint recovery beyond retention, validator signing-guard
continuity and epoch reactivation, physical power-loss tolerance, and the G6
workload/window still need separate evidence. Those remaining OPS-1/G6 checks
stay open in [the launch plan](MAINNET_LAUNCH_PLAN.md).

### Runtime candidate lab checks

Using the fixed exit-code runtime (`1943b4e`; unchanged Rust source in
`e1a8799`), four validators retained their existing data and genesis:

- [Three steady-state samples](evidence/20261022/exitfix-steady-state.json)
  passed: all members had three committee sessions, certified tips advanced
  2050 -> 2057 -> 2065 and sampled historical commitments agreed.
- [Fresh transaction](evidence/20261022/exitfix-transaction.json) passed at
  block 2052, with an exact 1 AIN recipient increase, invalid-signature and
  duplicate rejection, and no second effect after further blocks.
- [Quorum loss/recovery](evidence/20261022/exitfix-quorum-recovery.json)
  passed: two Pi validators exited 0; two remaining validators stayed at
  certified height 2093 during the bounded no-quorum window. After healing,
  all four reached 2096 and agreed on checked commitments. Historical replay
  was rejected with no balance/nonce divergence.

These are finite tests on two hosts at one site, not independent operators or
a completed sustained G6 acceptance run. Original older-candidate reports stay
available separately; the new lab unit prefix is `aincore-lab-exitfix-20261022`.

No archive or node key is committed. Failed and successful test evidence is
retained separately. The full runtime gate is independently running against
`e1a8799`; these changes touch operational scripts, documentation and controls,
not the Rust runtime under that job.
