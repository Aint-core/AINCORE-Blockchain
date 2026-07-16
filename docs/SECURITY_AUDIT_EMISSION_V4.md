# AINCORE Emission v4 + Economic Layer — Final Audit Report

**Auditor verdict basis:** 14 surviving findings, verifier-corrected severities. Two findings (the `universal_mining` u64 overflow, reported twice) are the same defect and are merged. Findings on supply-tracker accounting (treasury cap, phantom burn, stranded pool cuts) are related but kept distinct where the defect differs.

**One-line bottom line:** Emission v4 is **cap-safe** — it never over-mints and cannot cause runaway inflation. But it is **functionally broken in several places**, **permanently strands ~5% of supply**, and contains **one consensus-safety break plus two guaranteed-eventual halts** that are hard mainnet blockers.

---

## TIER 1 — MAINNET BLOCKERS (consensus safety + permanent liveness/economic failure)

### 1. `leave_validator_set` never prunes the QC trust root — nothing-at-stake finality break
**Severity: HIGH** (one verifier rated CRITICAL; the coalition precondition is the only thing keeping it off CRITICAL)
**`core/executor/src/lib.rs:1880-1902` (prune is slash-only); post-exec hook join-only `2558-2590`; `consensus/qc.rs:256-259`**

The v1 QC trust root (`sys:validator_set:v1`) and reward mirror (`sys:validators`) have exactly three production writers: genesis, join, and slash. There is **no `leave` interception anywhere** (grep of core/consensus/common/sync returns zero). Meanwhile Move-side `leave_validator_set` removes the validator from the live set and burns bonded stake into the 21-day unbonding queue, which `withdraw_unbonded` later re-mints in full to the departed validator's liquid account.

**Exploit:** A coalition that once held >2/3 stake (e.g. the genesis set) calls `leave_validator_set`, withdraws 100% of capital after unbonding, and **keeps full frozen weight and live BLS keys in v1 forever**. `rotate_validator_epoch` freezes that stale set into every epoch snapshot; `verify_qc` recomputes signed/total stake from it, so the departed coalition can sign a valid >2/3 QC over a **conflicting/forged finality vote at zero stake-at-risk** — a double-finality / nothing-at-stake safety violation. They also keep drawing 80%-pool block-fee payouts via `compute_block_payouts`.

**Fix:** Intercept `leave_validator_set` (and any partial-unstake path) in the executor post-exec hook exactly as slash does — `retain(|v| v.address != addr)` on **both** `sys:validator_set:v1` and `sys:validators`, or (better) rebuild both mirrors from the authoritative Move `ValidatorSet` resource each epoch instead of maintaining an independent Rust shadow that can desync.

---

### 2. `advance_epoch` runs O(N) reward loops under a fixed 1M gas budget with no validator cap — permanent halt of ALL emission + governance
**Severity: HIGH** (guaranteed-eventual, reachable organically)
**`core/vm_move/stdlib/sources/staking.move:296-419, 205-243`; `core/executor/src/lib.rs:923-972` (budget at `944`)**

`join_validator_set` has **no `MAX_VALIDATORS` cap** (only a dup-scan). Every epoch, `advance_epoch` calls `cleanup_old_unbonding` (O(M) queue loop) then `distribute_rewards`, which loops the validator vector **three times** (total_stake, total_weight, payout). The executor dispatches this under a hard-coded **1,000,000 gas budget that is constant regardless of set size**. At roughly 100–400 gas/validator, the budget is exhausted at ~2,500–5,000 validators.

**Exploit / organic failure:** Once the set (or unbonding queue) crosses the ceiling, the epoch tx aborts with `EXECUTION_LIMIT_REACHED`; `maybe_advance_epoch` returns **before commit, before rotate/sync, and before `drive_governance`**. Set size is deterministic and only shrinks voluntarily — so **every subsequent boundary aborts identically**. Emission (validator + delegation + DePIN accrual) and on-chain governance timelock processing **freeze permanently while blocks keep producing**, with no in-band recovery (governance itself is frozen). Reachable maliciously via ~thousands of recoverable 1000-AIN sybil stakes, or **organically as any successful permissionless L1 accumulates validators.** (Minor note: the abort surfaces via the `must_succeed=true` Err arm at `968-970`, not the `!status.success` arm — impact identical.)

**Fix:** (a) Add a hard `MAX_VALIDATORS` cap on `join_validator_set`; (b) scale the epoch gas budget with set size, or better, make `advance_epoch` uncharged/system-metered so it cannot OOG; (c) bound the unbonding-queue scan (paginate `cleanup_old_unbonding`).

---

### 3. Unbounded unbonding queue + no-minimum undelegate OOG-reverts `slash_pool` — delegated-stake slashing bypass (defeats FIX H1)
**Severity: HIGH**
**`core/vm_move/stdlib/sources/delegation.move:172-232, 404-487`; `core/executor/src/lib.rs:1801-1831` (budget at `1807`)**

`undelegate` has **no minimum on `amount`** (only `d.amount >= amount`) and pushes one `UnbondingDelegation` per call with **no cap on `pool.unbonding_queue`**. `slash_pool` loops the entire queue (plus a whole-resource `borrow_global_mut` that costs ~2 gas/byte) under a fixed **500,000 gas budget**. Because `undelegate` runs under an attacker-chosen (mempool-uncapped) gas limit while `slash_pool` is pinned at 500k and does strictly more work, an OOG window always exists.

**Exploit:** A validator self-delegates large capital as one bonded entry, then spams thousands of cheap `undelegate(amount = 1 base-unit)` txs to pad the queue. On equivocation, `slash_validator_bps` burns only the min self-stake, but `slash_pool` hits `EXECUTION_LIMIT_REACHED` and the whole Move tx reverts — **the large delegated stake is never burned.** The executor swallows the failure (self-stake slash was a separate, already-committed VM call) and continues. This is exactly the nothing-at-stake bypass FIX H1 was written to close. (Narration nit: with `must_succeed=false` the OOG returns `Ok` with an empty changeset and even prints a false "delegation slash executed" — stealthier than the cited Err arm, functionally identical.)

**Fix:** Enforce a `MIN_UNDELEGATE` amount and a minimum-remaining-delegation floor; hard-cap `unbonding_queue` length per delegator/pool; make `slash_pool` gas budget scale with (or be exempt from) queue size; and treat a failed delegation-slash as a **hard error that halts/retries**, never a swallowed warning.

---

### 4. Delegation reward pool is a permanent un-drainable sink — ~5% of emission (~7.45M AIN) stranded forever + supply tracker overcounts
**Severity: HIGH** (unconditional, permanent, but fails safe on the cap)
**`core/vm_move/stdlib/sources/staking.move:343-351, 427-439`; `delegation.move:379-381`**

Every epoch `distribute_rewards` accrues `delegation_cut` (DELEGATION_BPS=500 = 5% of e_epoch) into **both** `pools.delegation_budget` **and** `total_supply`. The only drain is `mint_delegation_reward`, reachable only via delegator payout sites gated on `calculate_pending_reward(d, accumulated_rewards_per_share)`. That accumulator is incremented in **exactly one place** — `distribute_delegation_rewards` — which has **ZERO callers** (the epoch dispatch calls only `distribute_rewards`).

**Consequence (no attacker needed, fires every epoch):** `accumulated_rewards_per_share` is permanently 0, all pending is 0, `mint_delegation_reward` is never called with a positive amount, and `delegation_budget` grows monotonically forever. The 5% slice is **counted against MAX_SUPPLY** (throttling all future emission via `remaining = MAX_SUPPLY - total_supply`) but is **never minted into circulation and has no path back to the reserve**. Over the horizon, `total_supply` asymptotes to 150M while ~5% × ~149M emittable ≈ **7.45M AIN is locked in an un-spendable counter**; circulating supply ends ~7.45M below `total_supply`, and the canonical supply tracker permanently overstates real coins. The entire delegation-reward PoS feature is **non-functional**. (The DePIN pool has a live draw path and does not share this permanent-strand fate, only the idle-epoch strand of Finding 13.)

**Fix:** Wire `distribute_delegation_rewards` into the epoch dispatch (`epoch::advance_epoch`) so `accumulated_rewards_per_share` actually advances and the budget is minted to delegators. Until wired, do **not** accrue `delegation_cut` into `total_supply` (accrue lazily on actual payout), so the 5% is not counted against the cap while unspendable.

---

## TIER 2 — MEDIUM (real economic-security / correctness defects; not cap-breaking, not fund-theft)

### 5. QC quorum weight frozen at join-time stake — `add_stake` and merged rewards never refresh v1
**Severity: MEDIUM** (one verifier LOW; the exploit framing overstates, the defect is real)
**`core/executor/src/lib.rs:115-138, 698-741`; `consensus/qc.rs:258-259`**

v1 stake is written once at join and only mutated by slash-removal. `add_stake` and reward-merge mutate live Move stake but never propagate to v1/`sys:validators`; the staking dep handler treats all staking txs as opaque lock-only. `verify_qc` recomputes the 2/3 threshold from those frozen values, and `rotate_validator_epoch` copies stale v1 into every epoch snapshot — so staleness is **permanent, not epoch-bounded**. Effect: consensus voting weight is pinned to join-time stake and diverges permanently from the live economic stake that rewards and slashing operate on; honest validators who grow stake gain slashable capital but **zero extra finality weight**, eroding the live-stake security margin. (Note: there is no partial-unstake path, so live stake is monotonically ≥ frozen — an attacker cannot inflate frozen weight while withdrawing below it. This is why it is MEDIUM, not a HIGH forgeable-quorum primitive.)

**Fix:** Refresh v1/`sys:validators` stake on `add_stake` (and on reward-merge) via an executor interception, or rebuild the epoch snapshot's per-validator stakes from the live Move `ValidatorSet` at rotation.

---

### 6. Leader-election beacon is a proposer-grindable hash-chain now gating a 20% fee bonus
**Severity: MEDIUM** (code self-admits grindability: "audit H-2")
**`consensus/consensus/src/ordering.rs:268-320, 680-750`; bonus at `core/executor/src/lib.rs:1134-1144`**

The election beacon is a pure SHA3 hash chain (`VDFEngine::new(50)`, "provides determinism, not delay") derived from `finality_digest`, which folds the proposer's own anchor vertex. The unbiasable QC-aggregate fold is deliberately **excluded** from election. So the current anchor proposer can locally enumerate candidate contents (microseconds each), compute the resulting next leader, and pick content electing itself or a partner. This now **directly monetizes** as the flat 20% anchor-leader fee bonus (`LEADER_BONUS_PCT=20`) plus rounding remainder, letting a proposer over-capture fees beyond its stake share. Bounded to the 20% slice (the 80% pool stays stake-weighted); no safety fork, no theft — hence MEDIUM.

**Fix:** Ship the roadmapped real delay-VDF, or fold the unbiasable QC aggregate signature into the election seed so proposer-chosen content cannot steer leadership.

---

### 7. 150M MAX_SUPPLY hard cap is breached by the genesis treasury reserve (cap-base excludes it)
**Severity: MEDIUM** (silent, bounded ~0.033% at default, config-scalable)
**`core/node/src/genesis.rs:958, 1103-1105, 1139-1140`; `staking.move:326`; executor tripwire `lib.rs:788`**

Move `ValidatorSet.total_supply` is seeded to `total_bootstrap_stake` only (`958`), excluding the treasury reserve — a real spendable `Coin` (default 50,000 AIN) created by direct BCS write, never through `coin::mint`, and `coin.move` has no global supply counter. Emission draws `remaining = MAX_SUPPLY - total_supply` against that treasury-excluding base, so it proceeds until `total_supply` hits 150M **on top of** the uncounted treasury coins. True realizable supply → **150M + treasury_reserve (150.05M default) > MAX_SUPPLY**, and the SEC-#14 tripwire (`if new_supply > MAX_SUPPLY`) reads only the treasury-excluded Move value, staying **silent**. Magnitude scales with the operator's `treasury_reserve` config.

**Fix (one line):** Seed `total_supply = total_bootstrap_stake + treasury_reserve_amount`.

---

### 8. Burns re-inflate the emission budget — slashing/burn is NOT net-deflationary
**Severity: MEDIUM** (one verifier LOW; cap holds, it's an economics/docs correctness defect)
**`staking.move:326-332` (driver); burn decrements `230-235, 463-468, 512-517`**

`e_epoch = (MAX_SUPPLY - total_supply) * 81/1e9` is strictly increasing in `remaining`. Every burn path (slash, 21-day auto-burn of expired unbonding, `burn_ain` governance/fee burns) **decrements** `total_supply`, which **raises the next epoch's draw** — the burned amount is recycled into the reserve and re-minted over subsequent epochs to remaining validators + pools. This falsifies the module's own comments ("smooth geometric decay", "deflationary penalty", "Permanently burn"): the 150M cap is a **soft target the reserve perpetually refills**. Root cause: `total_supply` conflates cumulative-minted (drives the reserve) with net-circulating (decremented by burns). No inflation past the cap and no fund loss — hence not HIGH. The finding's secondary claims (slashing deterrence undermined, "manipulable by anyone") are **overstated**: individual slashing still burns 100% of the offender's stake immediately, slash/burn entry points are @0x1-gated or self-costly, and the re-emission is diffuse over decades.

**Fix:** Introduce a separate **monotonic cumulative-minted counter** to drive emission headroom, so burns reduce circulating supply without reopening reserve room; reconcile the "deflationary/permanent burn" documentation with actual behavior.

---

### 9. u64 overflow abort in `universal_mining::distribute_reward` — devices with BQI ≥ 52 can NEVER be paid *(deduped: reported twice)*
**Severity: MEDIUM** (one of four verifier votes said HIGH; three MEDIUM — feeder-gated, fails safe with no inflation)
**`core/vm_move/stdlib/sources/universal_mining.move:276-277`**

`base_reward = 360000000000000000` (3.6e17) is an untyped literal inferred as **u64** (multiplied by `bqi_score: u64`; the `as u128` cast happens only on the result). `3.6e17 * 52 = 1.872e19 > u64::MAX`, so Move aborts on overflow for any finalized `bqi_score ≥ 52`. With threshold 1 a single feeder vote finalizes, so the entire **upper half [52,100] of the intended 0–100 quality curve — including the canonical bqi=100 full-reward case — permanently aborts**, rolling back `p.status=1` so the device never finalizes and never gets paid. Fails safe (Move aborts, no wrap, no inflation); it is a broken-feature + feeder-triggerable abort-grief, not a chain halt.

**Fix:** Compute in u128 — `let reward_amount = (360000000000000000u128 * (bqi_score as u128)) / 100;`.

---

### 10. Repeated finalization: finalized proofs never pruned; a fresh `submit_vote` re-finalizes the same device at threshold 1
**Severity: MEDIUM** (one verifier LOW; gated on feeder compromise, capped to DePIN pool)
**`core/vm_move/stdlib/sources/universal_mining.move:233-249`**

The proof scan matches only `status == 0`; a finalized proof (`status=1`) is never removed, so a repeat vote for the same device falls into the new-proof branch and, at threshold 1, **immediately re-finalizes and re-mints**, defeating the module's own quorum and double-vote guards. A malicious/compromised single feeder (the default sole trust anchor) can verify an owner it controls and re-mint every block, **bounded only by the accrued DePIN pool** drained to attacker addresses. Not an unprivileged exploit (feeder-gated) and cannot breach the supply cap (pool is pre-reserved) — hence MEDIUM, not a treasury drain.

**Fix:** Prune finalized proofs from `active_proofs`, and add a per-device epoch/cooldown binding so payout cadence is enforced on-chain, not by honest-feeder discipline. Raise `threshold` above 1 and grow the feeder set before mainnet.

---

## TIER 3 — LOW / INFORMATIONAL (metrics/accounting defects and by-design notes; no safety or fund impact)

### 11. First epoch advance overwrites `sys:total_supply` from the treasury-excluding Move value — phantom ~50k burn
**Severity: LOW** (deterministic across all nodes → no fork; metrics-only)
**`core/executor/src/lib.rs:802-818, 841-862`**

Genesis seeds `sys:total_supply = bootstrap + treasury` but the Move value excludes the treasury. On the first epoch boundary, `append_supply_tracker_updates` / `sync_supply_trackers_from_validator_set` mirror `sys:total_supply` from the Move value; since first-epoch emission (~12 AIN) ≪ treasury (~50k), the `old>new` branch fires, **dropping the 50k treasury from circulating supply and recording a phantom ~50k burn** in `total_burned`. No coins destroyed; only the supply RPC metrics are corrupted. Self-heals with a zero reserve. **Fix:** subsumed by Finding 7's fix (seed the Move value to include the treasury).

### 12. `OracleConfig.active_proofs` grows without bound — every `submit_vote` O(n)-scans it
**Severity: LOW** (feeder-gated acceleration; prototype DePIN module)
**`core/vm_move/stdlib/sources/universal_mining.move:195-216`**

Finalized proofs are retained and each submission appends a `PendingProof`; at default threshold 1 the vector grows by ≥1 on **every** call under normal operation, and Move re-serializes the whole resource per call, so per-proof gas rises without bound — a slow-burn state-bloat that can eventually brick DePIN finalization. **Fix:** prune on finalize (subsumed by Finding 10) and migrate `active_proofs` to a Move `Table`.

### 13. Empty-epoch DePIN/delegation cut counted against `total_supply` at accrual — idle streams strand reserve
**Severity: LOW / by-design** (one verifier rated NONE — the throttle mechanism is inherent to any emission schedule)
**`core/vm_move/stdlib/sources/staking.move:343-351`**

Each epoch reserves 5% depin + 5% delegation and immediately charges it to `total_supply`, shrinking `remaining` even in epochs with zero proofs/claims. Unspent budget carries forward with no reserve-return path, so a genuinely idle stream strands reserve. This is the deliberate reserve-then-lazy-draw design that makes the cap un-raceable; the "permanent throttle" framing is weak because validator payouts also draw down `remaining` regardless. **Cap-safe, conservative, informational.** No fix required beyond documenting the tradeoff — but note it compounds Finding 4's permanent strand for delegation specifically.

---

## HONEST VERDICT

**Is emission v4 safe to keep running on devnet? — Yes, with eyes open.**
Emission v4 is genuinely **cap-safe**: across every finding, the 150M invariant holds against the Move `total_supply` base (the treasury breach in Finding 7 is a bounded ~0.033% overshoot, not runaway inflation). No finding produces an integer wrap, unbounded mint, or theft of user principal. For devnet testing you will not lose funds or inflate the token. **But be clear about what is already broken on devnet today:**
- Delegation rewards **never pay** (Finding 4) — the entire delegated-PoS reward path is dead.
- DePIN rewards **abort for any quality score ≥ 52** (Finding 9), including the intended max-reward case.
- The chain **will eventually and permanently halt all emission and governance** as the validator set grows (Finding 2) — this is not hypothetical, it is deterministic.
- The reported circulating-supply and `total_burned` metrics are **already wrong** from epoch 1 (Findings 7, 11).

So devnet is fine as a test harness, but treat the emission/reward numbers and the delegation/DePIN features as non-functional, and expect the epoch-halt to surface under any sustained validator growth.

**What MUST be fixed before mainnet — non-negotiable:**
1. **Finding 1** — the `leave_validator_set` QC-trust-root desync is a **consensus finality-safety break** (double-finality / nothing-at-stake). This is the single most dangerous defect in the set; one verifier rated it CRITICAL. **No mainnet with this open.**
2. **Finding 2** — the uncapped-validator-set / fixed-gas epoch OOG **permanently halts emission and governance** with no in-band recovery. A permissionless L1 that halts its own economics as it succeeds cannot launch.
3. **Finding 3** — the `slash_pool` OOG bypass **defeats delegated-stake slashing** (the exact property FIX H1 claimed to restore). Slashing that can be evaded is not slashing.
4. **Finding 4** — delegation rewards must actually be wired and the 5% must stop being counted against the cap while unspendable; otherwise a core PoS feature ships dead and ~7.45M AIN is stranded with a permanently desynced supply tracker.

The Tier-2 MEDIUMs (5–10) should all be fixed before mainnet as well — the QC-weight staleness (5) and grindable leader beacon (6) are economic-security defects, and the treasury cap breach (7) violates the headline max-supply promise even if small. They are not launch-blocking in the safety sense, but shipping them means the advertised "cost to attack" and "150M hard cap" are both literally false as implemented.

**What is honestly fine / overblown:** The burn-reinflation (8) is a real economics/documentation inconsistency, **not** an exploit — the cap holds and slashing still burns the offender's full stake. The empty-epoch strand (13) is by-design and cap-safe. The bqi overflow (9) and repeated-finalization (10) are confined to a self-labeled beta DePIN module and are feeder-gated. Don't let these distract from the four Tier-1 blockers.

---

## PRIORITIZED FIX LIST

| # | Fix | Severity | Blocker? |
|---|-----|----------|----------|
| 1 | Prune `sys:validator_set:v1` + `sys:validators` on `leave_validator_set`/partial-unstake (or rebuild mirrors from live Move `ValidatorSet` each epoch) — `executor lib.rs:1880-1902, 2558-2590` | HIGH (safety) | **YES** |
| 2 | Add `MAX_VALIDATORS` cap on join; scale/exempt the epoch gas budget; paginate `cleanup_old_unbonding` — `staking.move:296-419`, `lib.rs:944` | HIGH (liveness) | **YES** |
| 3 | Enforce `MIN_UNDELEGATE` + min-remaining floor; cap `unbonding_queue`; scale `slash_pool` budget; make delegation-slash failure a hard error not a swallowed warning — `delegation.move:172-232`, `lib.rs:1807/1825` | HIGH (slashing) | **YES** |
| 4 | Wire `distribute_delegation_rewards` into `epoch::advance_epoch`; stop accruing `delegation_cut` into `total_supply` until it is actually payable — `staking.move:343-351`, `delegation.move:379-381` | HIGH (supply) | **YES** |
| 5 | Refresh v1/`sys:validators` stake on `add_stake`/reward-merge (or rebuild epoch snapshot from live stake) — `lib.rs:115-138, 698-741` | MEDIUM | Strongly recommended |
| 6 | Fold the unbiasable QC-aggregate into the leader-election seed (or ship the real delay-VDF) — `ordering.rs:680-750` | MEDIUM | Strongly recommended |
| 7 | Seed `total_supply = total_bootstrap_stake + treasury_reserve_amount` — `genesis.rs:958` (also fixes Finding 11) | MEDIUM | Strongly recommended |
| 8 | Add a separate monotonic cumulative-minted counter to drive emission headroom; fix "deflationary/permanent burn" docs — `staking.move:326-332` | MEDIUM | Recommended |
| 9 | Compute reward in u128: `(360000000000000000u128 * (bqi_score as u128)) / 100` — `universal_mining.move:276-277` | MEDIUM | Recommended |
| 10 | Prune finalized proofs; add per-device epoch/cooldown; raise `threshold` > 1 and grow feeder set — `universal_mining.move:233-249` (also fixes Finding 12) | MEDIUM | Recommended |
| 11 | Migrate `active_proofs` to a Move `Table` (covered by #10's prune) — `universal_mining.move:195-216` | LOW | Hardening |
| 12 | Document the reserve-then-lazy-draw strand tradeoff; no code change required — `staking.move:343-351` | LOW / by-design | Informational |

**Relevant files:** `core/executor/src/lib.rs`, `core/vm_move/stdlib/sources/staking.move`, `core/vm_move/stdlib/sources/delegation.move`, `core/vm_move/stdlib/sources/universal_mining.move`, `core/node/src/genesis.rs`, `consensus/consensus/src/ordering.rs`, `consensus/qc.rs`.