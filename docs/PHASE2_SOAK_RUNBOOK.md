# Phase 2 Soak Runbook

This runbook is the operational gate before claiming that the L1 consensus/sync layer is ready for the next hardening phase.

## Quick Smoke

Run a short local soak with restart fault injection:

```bash
AINCORE_SOAK_SECONDS=60 AINCORE_SOAK_SKIP_PREFLIGHT=1 AINCORE_SOAK_KEEP_LOGS=1 ./scripts/phase2_soak_gate.sh
```

## Full Gate

Run the compile/test hardening gate, build release node, start a local cluster, restart one peer mid-run, and keep polling status/finality:

```bash
AINCORE_SOAK_SECONDS=3600 AINCORE_SOAK_KEEP_LOGS=1 ./scripts/phase2_soak_gate.sh
```

## Long Soak

For public-testnet readiness, run 7-30 days:

```bash
AINCORE_SOAK_SECONDS=604800 AINCORE_SOAK_KEEP_LOGS=1 ./scripts/phase2_soak_gate.sh
```

## Pass Criteria

- `phase2_hardening_gate.sh` passes before the soak starts.
- Every node answers `/health`.
- Every node answers `aincore_getStatus` without JSON-RPC error.
- Every node answers `aincore_getFinalityStatus` without JSON-RPC error.
- Restarted node comes back using the same datadir and still answers RPC.
- No node exits unexpectedly during the soak window.

## Fail Criteria

- Any RPC health/status/finality poll fails.
- A restarted node cannot reopen its datadir.
- Logs contain repeated database open failures, invalid genesis marker failures, or consensus finality regressions.
- Node process exits before cleanup.

## Notes

- The script uses isolated data under `.soak/` and does not touch normal validator data.
- Set `AINCORE_SOAK_KEEP_LOGS=1` to inspect logs after a failure.
- Default ports are `19000+` for P2P and `18000+` for RPC to avoid clashing with normal local nodes.
