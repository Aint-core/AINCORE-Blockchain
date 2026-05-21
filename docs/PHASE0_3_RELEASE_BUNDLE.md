# AINCORE Phase 0-3 Release Bundle

## Current Goal

Prepare the local Phase 0-3 hardening work as a clean release bundle while the NAS validator continues its soak run. Do not rebuild or restart the NAS validator until a maintenance window is explicitly opened.

## Bundle Groups

### 1. Chain Integrity and Move Runtime

- Canonical address checks across executor, CLI, SDK, and tests.
- Structured BCS transaction payloads for entry calls and module publishing.
- Transaction-scoped Move execution with gas pre-action and receipt status.
- Move stdlib bytecode refreshed and loaded deterministically from genesis.

### 2. Consensus, Sync, and Finality Hardening

- Strict quorum and signer validation in DAG consensus.
- Checkpoint recovery replays persisted tail vertices after the last checkpoint.
- Sync rejects height gaps, wrong parents, bad proposers, bad tx hashes, timestamp drift, and finalized-boundary conflicts.
- Block headers carry execution roots locally, and sync verifies state/receipt roots after execution.

### 3. Economics, Staking, and Security Gates

- Minimum gas price and duplicate pending nonce rejection.
- Deterministic parallel commit ordering.
- Epoch advancement hook and proportional staking rewards.
- DEX overflow/minimum-liquidity guards and wBTC burn address sanity checks.
- Governance and API balance paths use Move CoinStore/supply state.

### 4. Tooling, SDK, and Operations

- JS SDK BCS serializer and parity tests.
- Localnet transaction gate for faucet, transfer, restart, and replay.
- NAS soak watcher with height/finality stall detection.
- Runbooks for Phase 2 soak and gate execution.

## Deploy Window Plan

Run this only after the active NAS soak checkpoint is accepted.

1. Capture pre-deploy status: container uptime, latest height, finalized round, digest, and suspicious logs.
2. Sync the release bundle to `/home/alpha/aincore` while excluding runtime data directories and secrets.
3. Build image with `docker compose -f docker-compose.nas.yml up -d --build aincore-node`.
4. Verify `/health`, `aincore_getStatus`, and `aincore_getFinalityStatus` immediately after restart.
5. Watch at least 3 monitor intervals; height and finality must advance with `height_stall=0` and `finality_stall=0`.
6. If health fails, roots mismatch, or suspicious logs appear, stop and inspect before any further deploy attempt.

## Required Gates Before Deploy

- `git diff --check`
- `./scripts/phase2_hardening_gate.sh`
- `./scripts/phase3_economics_gate.sh`
- `AINCORE_PHASE4_SECONDS=20 AINCORE_SOAK_KEEP_LOGS=0 ./scripts/phase4_localnet_tx_gate.sh`
- `cd aincore-js && npx tsc --noEmit`

## Known Non-Blocking Notes

- `CLAUDE.md` and `.claude/` are owned by another local agent and should not be removed as part of this bundle.
- DEX `create_pool` currently creates a pool under the caller signer, while swap/liquidity paths use the global `@0x1` pool. DEX tests cover the runtime global pool path; public pool creation policy should be finalized before DEX is marketed as open ecosystem infrastructure.
- Bridge/L2 event finality and multisig hardening remain outside this Phase 0-3 release bundle.
