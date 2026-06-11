# AINCORE Testnet Reset Bundle Plan

Date: 2026-06-10
Status: planning spec, no code executed
Branch base: `audit/p0-security-fixes`

## Why this document exists

Several P0 changes touch **genesis state and/or consensus-critical execution
rules**. Each such change bumps the genesis lineage and **cannot be hot-patched**
onto the running fresh testnet DB (proven 2026-06-10: the genesis-version guard
correctly refuses a binary whose genesis differs from the live DB). Deploying
each one separately would mean a testnet reset per change.

**Principle: reset is expensive — reset ONCE for all genesis-touching changes.**

This plan groups every genesis/execution change that should land in the SAME
fresh-genesis reset, so observers (NAS / VPS / Pi / laptop) re-sync once onto a
single clean lineage that already has the full set.

## What goes IN the bundle (one reset)

All four change the genesis stdlib and/or the state-root computation, so all four
must share one fresh genesis.

### B1 — BLS QC Phase 1: validator BLS identity + PoP enforcement
- **Scope:** add `bls_public_key` + `bls_pop` to `staking::ValidatorConfig`
  (`core/vm_move/stdlib/sources/staking.move`) and to genesis validator records
  (`core/node/src/genesis.rs`); add a versioned `sys:validator_set:v1`; **reject
  any BLS key whose PoP does not verify** at genesis AND `join_validator_set`
  (PoP primitive already shipped in `crypto::bls`, commit `2ab3563`).
- **Why reset:** changes the genesis stdlib bytecode + genesis state layout.
- **Test:** PoP-on-register rejects keys with missing/invalid PoP; genesis loads
  validators with BLS keys; `sys:validator_set:v1` round-trips.

### B2 — Gas settlement: charge `min(gas_used, limit)`, refund the rest
- **Scope:** stop charging the full `gas_cost = gas_limit * gas_price`
  (`core/executor/src/lib.rs:1930`); use the VM's real `_gas_used` (currently
  discarded at `:697/:852/:1462`) and refund `gas_limit - gas_used`.
- **Why reset:** changes balances → changes the state root → consensus-critical
  execution rule change (all nodes must run identical rules; effectively a
  fork). Bundle with the reset.
- **Test:** a cheap tx is charged actual usage, not the full limit; refund
  arithmetic is saturating; abort path still charges correctly.

### B3 — Reward integrity: wire `distribute_delegation_rewards`
- **Scope:** `delegation::distribute_delegation_rewards` is system-gated (commit
  from F2) but has **zero callers** (verified: dead). Wire the commit/epoch
  reward path to invoke it with the genuine `@0x1` signer, and reconcile the two
  reward systems into one atomic epoch pass.
- **Why reset:** Move stdlib + execution behavior change.
- **Test:** delegators actually receive rewards through the wired path; no
  double-pay; MAX_SUPPLY cap respected.

### B4 — Stake-weighted voting power
- **Scope:** the legacy vote path in `consensus/src/lib.rs` already sums
  validator stake, but the DAG anchor/parent/leader path still derives quorum
  from `validators.len()` and reads `sys:validators` as addresses only
  (`dag.rs`). Make remaining DAG/finality thresholds and leader selection use
  the stake already stored in `sys:validators`. Natural pairing with B1 (QC is
  stake-weighted; DAG finality must align, or cost-to-attack is not ∝ stake).
- **Why reset:** consensus-critical; changes commit/leader behavior.
- **Test:** a >2/3-stake minority of nodes can finalize; a <2/3-stake majority of
  node-count cannot; leader selection respects stake.

## What stays OUT of the bundle (deploy independently, no reset)

These do not touch genesis or the state root, so they can ship on their own
schedule without a reset:

- **#10 Graceful shutdown** (SIGTERM → drain + RocksDB flush): pure ops, node
  lifecycle. Deploy anytime.
- **#6 DA proposer authorization** (M4): DA module is not in the live block path;
  low blast radius. Deploy anytime. (Also add the `build_qc` bounds-check noted
  in review when QC creation goes live — that's a Phase-2 code item, not genesis.)

## NOT in this bundle, but plan for it NEXT (ends the reset era)

- **#5 On-chain protocol-upgrade path** (Sui ProtocolConfig + feature flags,
  epoch-gated). Once this exists, future protocol changes enact at an epoch
  boundary on >2/3 stake signaling — **no more hard-fork resets.** Strategically
  this should be the LAST thing that requires a manual reset to introduce, then
  every change after rides the upgrade path. Sequence it right after the QC
  bundle is stable.

## Reset procedure (the proven flow, 2026-06-10)

1. **Reconcile lineage first.** Confirm the canonical genesis version for the
   testnet (the live DB was `phase1-stdlib-integrity-v1`; branch is
   `phase1-dex-registry-v1`). Pick ONE; bump it for the bundle (e.g.
   `phase1-qc-bundle-v1`). All four B-changes share this version.
2. **Build off-NAS.** Build the image on VPS (x86_64 Linux) or Mac, never on NAS.
3. **Backup.** Keep the current fresh DB (`fresh_data.pre-reset-<ts>`); keep old
   soak + DEX stopped. No deletion.
4. **Fresh genesis.** New DB/port from the bundled binary; fresh genesis with the
   new lineage (B1 validator BLS keys baked in).
   - **PRESERVE `node.key` (learned 2026-06-11).** A reset that wipes the data
     dir regenerates `node.key` → the node's address changes → it is no longer in
     the genesis validator set → it boots as an **observer** and never produces
     blocks. On the 2026-06-11 reset this happened and was recovered by restoring
     the prior key from `fresh_data_key_keep/node.key` then restarting. **Before
     reset, copy each validator's `node.key` aside; after fresh genesis, restore
     it before first boot.** On a multi-validator set, losing `node.key` on >1/3
     of nodes at once = loss of quorum — treat key preservation as mandatory, not
     best-effort.
5. **Re-seed observers.** Point VPS/Pi/laptop at the new lineage
   (`p2p.aincore.network:9042`), fresh data dirs.
6. **Verify (checklist below) before calling it done.**

## Post-reset verification checklist (no claim until green)

- [ ] All nodes healthy, heights advancing on ONE lineage.
- [ ] **Storage (regression):** latest `dag:checkpoint:*` blob stays ~KB and FLAT
      across rounds (not 130MB) — proves M3/a5a7843 still hold post-bundle.
- [ ] **B1:** genesis validators carry BLS keys; a validator with an invalid PoP
      is rejected on join.
- [ ] **B1/QC:** a single-validator 1-of-1 QC is produced and `verify_qc` passes
      against `sys:validator_set:v1` (when QC creation is wired — Phase 2).
- [ ] **B2:** a small tx is charged actual gas, refund issued; balance math sane.
- [ ] **B3:** delegators receive rewards through the wired path; supply cap holds.
- [ ] **B4:** finality is stake-weighted (verify with a stake-asymmetric test).
- [ ] Observer lag is sync-delay only (poll-based), not divergence.

## Sequencing summary

```
1. Spec this bundle .......................... (this doc) ✓
2. Implement B1-B4 on branch (code + tests) ... code-only, no deploy
3. Reconcile lineage + bump genesis version
4. ONE reset cycle (backup → fresh genesis → re-seed → verify checklist)
5. Independent: #10 shutdown, #6 DA auth (anytime)
6. NEXT: #5 on-chain upgrade path → ends the reset era
7. Then big rocks: #3 authenticated state (JMT), #2 quorum checkpoints
```

## Honest framing

This bundle does NOT make AINCORE "production-perfect." It advances the keystone
(BLS QC) to a live single-validator QC + fixes gas/reward/stake-weight in one
clean reset. "Production-grade L1" still needs authenticated state (#3), full
checkpoint/epoch proofs (#2), and the upgrade path (#5) after this — multi-quarter.
But after this bundle, AINCORE has live stake-weighted finality with verifiable
quorum certs on a clean lineage: the real gateway from "public observer testnet"
to "incentivized validator testnet."
