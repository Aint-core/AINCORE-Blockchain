# Phase 2 Soak Runbook

> Historical health/restart smoke test, not the current mainnet acceptance gate.
> The script below does not assert advancing certified height, matching state
> roots or successful transaction execution. A healthy but stalled chain can
> satisfy its RPC checks. Use [MAINNET_LAUNCH_PLAN.md](MAINNET_LAUNCH_PLAN.md)
> for current acceptance criteria. Do not run these build commands on the Mac
> or assume they are authorized against live services.

These historical commands are retained for context, not release approval.

## Current sampled lab check

After the separately authorized disposable four-validator NAS/Pi lab is running,
the following command reads its RPCs only. It never starts, stops or builds a node:

```bash
python3 -B scripts/check_two_host_test.py --samples 3 --interval 20 --report /tmp/aincore-lab-samples.json
```

The output path must not already exist. Every sample requires all four nodes to
have three committee sessions, available node-verified QCs, and matching commitments at the explicitly
listed heights. Every later sample requires each node's height, finality and
certified height to advance. The previous common tip is rechecked to reject a
rewritten history even if all nodes now agree on it. RPC failures, missing fields,
conflicting roots and incomplete runs cannot pass. Timing and partial samples
are retained in the report; gaps are not evidence of uptime.

This is a steady-state check, not a fault-injection, independent-verifier or
transaction-load gate. A deliberately disconnected validator must fail it.
The fixed endpoints are the named disposable lab, never arbitrary live services.
Passing this command does not clear G6; follow the measured workload and review
requirements in the mainnet launch plan.

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

Historical long-running RPC smoke (duration alone does not establish readiness):

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
