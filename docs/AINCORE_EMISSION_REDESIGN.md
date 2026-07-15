# AINCORE Emission Redesign — Root Cause, Design Spec & Review

## ROOT CAUSE

## THE SINGLE DEEPEST ROOT CAUSE

**AINCORE synthesizes total emission bottom-up as a sum of independent mint calls, instead of deriving it top-down as one supply-anchored number that is then divided.**

Concretely, the emitted-per-period total is

```
total = Σ_streams Σ_validators ( locally-decided mint_amount )
```

— each of the 3 streams and each of the N validators computes its own amount and calls `mint` directly. There is no line of code anywhere that computes **one** figure `E_epoch = f(cap, supply, bonded-ratio)` *first* and partitions it *after*. Every production chain does the inverse: `E_t` is computed once from protocol aggregates a participant cannot inflate by joining, and validators/streams/leaders only receive **shares** of that already-fixed, cap-bounded pot.

All four flaws are the same defect viewed from four angles:

| Flaw | What "divide-then-mint" does to it |
|---|---|
| validator-count-scaling | N is a *multiplier* on the total instead of a *divisor* of a fixed pot |
| curve-to-cap | `R1` was guessed, not solved from the budget, so first-epoch mint > cap and decay is dead code |
| unified-budget | 3 minters race one cap; none observes the global total |
| anti-concentration | reward is a self-minted increment folded back into stake, not an allocation of a fixed pot → `dS/dt ∝ S` |

---

## THE UNIFIED DESIGN PRINCIPLE

**Mint from ONE budget, then divide. Never divide, then mint.**

Exactly one function, called once per epoch under `BLOCK_EXECUTION_LOCK`, computes

```
remaining  = MAX_SUPPLY − read("sys:total_minted")          // 150M − minted
E_epoch    = min( schedule(epoch), remaining )               // top-down, N-independent, stream-independent
```

Everything downstream — the 3 streams, the anchor leader, every validator — receives a **share** of `E_epoch` via a weight function and **only distributes**; nothing else touches `mint`. One invariant closes the whole class of bugs:

```
assert  Σ(all payouts this epoch) == E_epoch ≤ remaining
```

Because `E_epoch` is fixed *before* any division and depends only on `(cap, cumulative-minted, optionally bonded-ratio)`:
- adding validators can only thin the slices (**fixes #1**),
- `schedule()` clamped by `remaining` cannot overshoot the cap (**fixes #2**),
- there is a single observable total to split by policy weights (**fixes #3**),
- and the split weight is now a *pure policy knob decoupled from how much is minted*, so you can make it saturating and route it to a liquid balance without touching the emission math (**fixes #4**).

Note the last point: killing auto-compound is only *coherent* once reward is an allocation of a fixed pot rather than a self-minted increment. The inversion is the precondition for the anti-concentration fix, not just a parallel fix.

---

## PER-FLAW MECHANISM TO ADOPT

### 1. validator-count-scaling → fixed per-block pot, stake-weighted split
Adopt: `block_emission = A_n / 31,536,000` (blocks/yr), then `payout_i = staker_pot · stake_i/total_stake`. The Ethereum/Cosmos pattern: total is a function of aggregate stake, split pro-rata — never `per_validator_const × N`.

**Quantitative why:** current `BASE_REWARD=36 AIN/validator/epoch` × `1,576,800 epochs/yr` = **56.76M AIN per validator per year**, ×N. At just **3 validators that is ~170M/yr > the entire 150M cap** — which is exactly the ~10-month blow-through. Under the fix, year-1 total is `A_1 = 7.45M` *regardless of N*. Ship a regression test: run distribution with N and 10N validators at equal total stake → assert identical total emission.

### 2. curve-to-cap → adopt the paper's geometric schedule; delete the halving constants
The emission paper **already performed the inversion**: `A_n = E(1−δ)δ^(n−1)`, `δ=0.95`, `E=149M` ⇒ `R1 = 0.23623795 AIN/block`, `Σ = 149M` in closed form (`E(1−δ^n)`). The deployed code contradicts its own paper.

**Quantitative why:** deployed `HALVING_INTERVAL = 2,102,400 epochs = 42,048,000 blocks = 1.33 yr`, but per-block emission at N=3 is `36×3/20 = 5.4 AIN/block` — **23× the schedule's 0.236**. Diagnostic identity: `interval_blocks(42.05M) × 5.4 ≈ 227M ≥ 150M`, so the cap clamps at ~10 months and the first halving (month ~16) never fires — dead code, exactly the flaw. Fix: replace `BASE_REWARD`/`HALVING_INTERVAL` with the per-block schedule `R1·... ` (or Avalanche-style reserve-drawdown as belt-and-suspenders). Add a genesis assertion: first-year emission `== E(1−δ) = 7.45M`, and `Σ schedule ≤ 149M`.

### 3. unified-budget → one master emission fn + governance weight table
Adopt the Cosmos/Helium pattern: `E_epoch` (above) partitioned by on-chain weights summing to 1.0. The paper's own split is the natural table: **10% dev fund / 90% stakers**, and within stakers **20% anchor leader / 80% stake-weighted**. Refactor validator-epoch, delegation, and DePIN `universal_mining` from *minters* into *distributors* that receive `alloc_i` and never call `mint`; assign rounding dust to one designated bucket so `Σ alloc_i == E_epoch` exactly. Increment `sys:total_minted` atomically; reject any block whose emission would push it > 150M. Keep schedule and weights as separate `UpdateEconomicParams` knobs so governance retunes the split without touching the curve or endangering the cap.

### 4. anti-concentration → three independent layers on the now-fixed pot
`dS/dt ∝ S` needs *both* the disposition fix and the weighting fix:
- **(a) Kill auto-compound (highest leverage):** route the stake-weighted tranche to a separate liquid `CoinStore`, not into bonded principal. Restaking becomes opt-in (Ethereum pre-Pectra sweep analogue). This alone breaks the exponential feedback loop.
- **(b) Saturating weight, not linear:** `weight_i = min(stake_i, z0)` with `z0 = total_staked / N_target` (Cardano-`k` clip), or `stake_i^α`, `α≈0.7–0.8` — documented result **Gini −23% to −49%, Nakamoto +25% to +200%**. Apply to *both* the VDF leader-selection weight and the payout weight.
- **(c) Mandatory Sybil cost (a concave curve is exploitable without it):** a split whale otherwise recovers `m^(1−α)` of the linear payout. Pair with `min_self_bond`, a bounded active set, per-identity equivocation/downtime slashing (already present), and a hard per-validator stake-share cap `≤ 2–3× (total_stake/N_target)`.
- **Instrument:** emit per-epoch stake Gini and Nakamoto coefficient (min validators controlling >1/3 stake) to Prometheus; treat a falling Nakamoto coefficient as a release-blocking regression. Track *cumulative* Gini, not per-round — cumulative > per-round is the signature of exactly this compounding bug.

Do **not** touch the `2/3+1` BFT quorum (CLAUDE.md rule #5); all of the above are reward-layer changes in `core/executor` + staking, and per rule #9 must ship with `cargo test`.

Reference: `docs/AINCORE_EMISSION_PAPER.md` §5 (already specifies the correct top-down schedule that the deployed constants violate).

---

## DESIGN SPEC

# AINCORE Emission Redesign Spec — `staking.move` v4 (Fair-Launch, Cap-Anchored)

Grounded in the live code: `core/vm_move/stdlib/sources/staking.move`. Current defect confirmed at lines 287 (`epoch_budget = current_reward * (len as u128)` — multiply-by-N), 260–265 (`calculate_reward` halving that never fires), 311/316 (`coin::merge(&mut v.stake, …)` — auto-compound), and three independent minters racing `MAX_SUPPLY` (`distribute_rewards` + `mint_reward` friends `delegation`, `universal_mining`).

**Design axiom: mint ONE cap-anchored number per epoch, then divide. Never divide, then mint.**

---

## 1. Master emission function (top-down, reserve-drawdown)

Cadence is standardized to **epoch = block = 20 s** (set `EPOCH_SECONDS = 20`; current `60` and the "@60s" halving comment are inconsistent — both blow the cap).

- `SECONDS_PER_YEAR = 31,536,000` → **epochs/year = 31,536,000 / 20 = 1,576,800**.
- Emittable budget `E = 149,000,000 AIN` (150M cap − 1M genesis premine).

I reject discrete halving (§4) in favor of **per-epoch reserve drawdown** (Avalanche/Cardano form): each epoch mints a fixed fraction `k` of the *remaining* reserve. This is (a) structurally cap-safe — `E_epoch` is always a fraction of what is left, so it can never overshoot; (b) smoothly geometric — no dead-code halving cliff; (c) integer-exact — truncation simply stays in the reserve and is emitted later (remainder carry is automatic, no separate accumulator).

**Equivalent geometric identity:** reserve after `t` epochs `= E·(1−k)^t`; annual retention `δ = (1−k)^1,576,800`. Cumulative emission `= E·(1−(1−k)^t)` → converges to exactly `E`.

**Solve k for ~25-yr effective life.** Pick integer-clean `k = 81 / 1,000,000,000 = 8.1×10⁻⁸`:
- Annual factor `δ = (1−8.1e-8)^1,576,800 = e^(−0.1277) = 0.8801` (≈12%/yr decay).
- **Reserve half-life** `= ln0.5/ln0.8801 = 5.43 years`.
- **95% emitted** at `T = ln0.05/ln0.8801 = 23.5 yr`; **96%** at **25.2 yr** → "~25-yr effective life." ✓
- **Genesis per-epoch:** `149,000,000 × 8.1e-8 = 12.069 AIN/epoch` (= per-block, N-independent).
- Year-1 total `= E·(1−δ) = 149M × 0.1199 = 17.87M AIN` (front-loaded like BTC's 50%/4yr, but gentler).

**Integer scheme (base units, `COIN_SCALE = 1e18`):**
```
remaining   = MAX_SUPPLY - total_supply         // reserve, in base units
E_epoch     = (remaining * DRAW_NUM) / DRAW_DEN  // DRAW_NUM=81, DRAW_DEN=1_000_000_000
```
`remaining × 81 ≈ 1.2e28` ≪ u128 max (3.4e38): no overflow. Truncation of the division is left in `remaining` and carried forward automatically.

*(Closed-form annual schedule, for whitepaper parity: `Aₙ = E(1−δ)δ^(n−1)`, `δ=0.88`, `Σ=E`. The drawdown above is its per-epoch implementation.)*

---

## 2. Split, not multiply (fixed pot → stake-weighted with saturation)

`E_epoch` is **fixed before any per-validator arithmetic**. Adding validators thins slices; it can never enlarge the pot. Within the validator bucket, allocate by **saturated stake weight** (Cardano-`k` clip — integer-trivial, unlike `stakeᵅ`):

```
z0     = total_staked / N_TARGET          // saturation point; N_TARGET = 50
w_i    = min(stake_i, z0)                  // stake above z0 earns ZERO marginal reward
reward_i = (val_bucket * w_i) / Σ w_j
```
Any validator above `1/N_TARGET = 2%` of total stake is saturated. Dust (`val_bucket − Σ reward_i`) is routed to the anchor leader so the bucket mints exactly.

---

## 3. Bucket allocation (one schedule, Σ = 100%)

```
W_VAL   = 8000 bps  (80%)  // validators; delegators are split INSIDE this bucket
W_DEPIN = 2000 bps  (20%)  // universal_mining
W_DEV   = 0                // founder's choice
```
```
depin_bucket = (E_epoch * W_DEPIN) / 10000
val_bucket   = E_epoch - depin_bucket      // dust to val_bucket → Σ buckets == E_epoch exactly
```
Delegation splits `val_bucket` per validator↔delegator commission *after* the stake-weighted allocation; it does not mint.

---

## 4. Halving vs smooth decay — **recommend smooth**

Discrete halving is what broke: `HALVING_INTERVAL = 2,102,400` epochs × 20 s = **1.33 yr**, but 12 AIN/block (fixed) or 5.4×N (bug) drains 149M long before the first halving fires — dead code. **Recommendation: smooth per-epoch geometric drawdown (§1).** Decay is visible every epoch, monotonic, and cannot desync from the cap. Delete the halving machinery entirely.

---

## 5. Anti-concentration (three layers + instrumentation)

Linear-weight + auto-compound gives `dS/dt ∝ S` (runaway). Fixes, in leverage order:

- **(a) Kill auto-compound (biggest lever, smallest diff).** Line 316 merges rewards back into bonded `stake`. Route them to a **separate liquid `CoinStore`** (`coin::deposit(v.validator_addr, reward_coins)`); restaking becomes opt-in via `add_stake`. Breaks the exponential feedback loop.
- **(b) Saturation clip (§2), `z0 = total/50`.** Applied to **both** payout weight **and** the VDF leader-selection weight in `ordering.rs`.
- **(c) Sybil cost — mandatory, because a hard clip is split-exploitable** (a 5% whale splits into 3×1.67% sub-`z0` validators and recovers full linear weight). Pair the clip with: `MIN_STAKE` self-bond (already 1000 AIN), a bounded active set `MAX_ACTIVE_VALIDATORS`, and per-identity equivocation/downtime slashing (already present). Each split costs a scarce active-set slot + bond + operational identity.

**Quantified improvement** (SRSW/clip literature, arXiv:2402.11170): stake **Gini −23% to −49%**, **Nakamoto +25% to +200%**. With `z0 = 2%` all large validators pin to equal capped weight, so controlling ⅓ of reward weight needs ≈17 validators → **Nakamoto ≥ ~17** vs. ~1–2 under linear compound.

**Instrument** (`monitor/` Prometheus): emit per-epoch **stake Gini** and **Nakamoto coefficient**; treat a falling Nakamoto as a release-blocking regression. Track *cumulative* Gini (the compounding signature), not per-round.

Do **not** touch the `2/3+1` BFT quorum (CLAUDE.md rule #5) — all changes are reward-layer.

---

## 6. Exact constants & pseudocode (before → after)

**Constants block (lines 31–37):**
```move
// BEFORE
const BASE_REWARD: u128 = 36000000000000000000;   // DELETE
const HALVING_INTERVAL: u64 = 2102400;            // DELETE
const EPOCH_SECONDS: u64 = 60;

// AFTER
const DRAW_NUM: u128 = 81;                         // reserve draw = 8.1e-8 / epoch
const DRAW_DEN: u128 = 1000000000;
const EPOCH_SECONDS: u64 = 20;                     // 1,576,800 epochs/yr
const W_DEPIN_BPS: u128 = 2000;                    // 20% DePIN; 80% validators
const N_TARGET: u128 = 50;                         // saturation: z0 = total/50 = 2%
```

**`calculate_reward` (lines 260–265): DELETE.** Replace with reserve draw inside the master path.

**`distribute_rewards` epoch budget (lines 277, 287–290): before → after:**
```move
// BEFORE
let current_reward = calculate_reward(validator_set.current_epoch);
...
let epoch_budget = current_reward * (len as u128);         // ← multiply-by-N BUG
if (total_supply + epoch_budget > MAX_SUPPLY) { epoch_budget = MAX_SUPPLY - total_supply; }

// AFTER  — top-down, N-independent, cap-safe by construction
let remaining = MAX_SUPPLY - validator_set.total_supply;
let e_epoch   = (remaining * DRAW_NUM) / DRAW_DEN;          // whole-epoch pot (all streams)
let depin_bucket = (e_epoch * W_DEPIN_BPS) / 10000;
let val_bucket   = e_epoch - depin_bucket;                  // dust → validators
```

**Weight formula (lines 299–311): before → after:**
```move
// BEFORE
total_weight += coin::value(&validator.stake) / COIN_SCALE;
...
let weight = coin::value(&v.stake) / COIN_SCALE;

// AFTER  — saturation clip
let z0 = total_staked / N_TARGET;                          // total_staked precomputed
let w  = min(coin::value(&v.stake), z0);
total_weight += w / COIN_SCALE;
...
let weight = min(coin::value(&v.stake), z0) / COIN_SCALE;
```

**Payout disposition (line 316): before → after:**
```move
// BEFORE  coin::merge(&mut v.stake, reward_coins);        // auto-compound
// AFTER   coin::deposit<AincoreCoin>(v.validator_addr, reward_coins);  // liquid, opt-in restake
```

---

## 7. Cap-accounting unification (one counter, no race)

Today `distribute_rewards`, `delegation`, and `universal_mining` each call `mint_reward`/`coin::mint` and independently test `total_supply` — a three-way race on `MAX_SUPPLY`.

**Redesign:** `E_epoch` is computed **once per epoch** in `0x1::epoch::advance_epoch`, under `BLOCK_EXECUTION_LOCK`, from the single canonical counter `ValidatorSet.total_supply`. It is split into `val_bucket` / `depin_bucket` and passed to each module as a **pre-allocated amount**. The distributors become *distributors only* — `mint_reward` is downgraded to a private helper callable solely by the master path, and `delegation` / `universal_mining` receive `Coin<AincoreCoin>` handles instead of minting. After distribution:
```move
assert!(distributed == e_epoch, ...);              // Σ payouts == E_epoch
validator_set.total_supply = validator_set.total_supply + e_epoch;   // single atomic bump
```
Invariant, testable: **Σ(all payouts this epoch) == E_epoch ≤ remaining**, and total emission is **identical for N and 10N validators** at equal total stake (regression test — CLAUDE.md rule #9 requires `cargo test` for executor/staking changes).

---

## 8. Migration

This is a **consensus-breaking economic change: hard fork with a new genesis.** `total_supply` resets to the genesis premine (1M), the `DRAW_*` / `N_TARGET` / bucket constants are baked at genesis, reward disposition moves stake→liquid, and `mint_reward` visibility narrows. No in-place upgrade of a running chain — cut a fresh `genesis.json` (do not edit the existing one; CLAUDE.md rule #1) and relaunch the network from block 0. Expose `DRAW_NUM/DRAW_DEN`, `W_DEPIN_BPS`, and `N_TARGET` as `UpdateEconomicParams` governance knobs so the split and horizon retune without ever touching the cap.

---

**Files to change:** `core/vm_move/stdlib/sources/staking.move` (constants, `distribute_rewards`, delete `calculate_reward`, disposition), `.../epoch.move` (single master call site), `.../delegation.move` + `.../universal_mining.move` (demote to distributors), `consensus/consensus/src/ordering.rs` (clip leader weight), `monitor/` (Gini/Nakamoto gauges), new genesis via `core/genesis-tool`.

---

## ADVERSARIAL REVIEW

All spec numbers verified and the code claims confirmed. Here is the adversarial review.

---

# Adversarial Review — `staking.move` v4 Emission Redesign

**Grounding:** I recomputed every headline number and read the live code (`staking.move` lines 25–37 constants, 260–320 reward path; `epoch.move`; `delegation.move`; `universal_mining.move`). The bug diagnoses in the spec's preamble are all accurate: line 287 `epoch_budget = current_reward * (len as u128)` (multiply-by-N), line ~316 `coin::merge(&mut v.stake, reward_coins)` (auto-compound), the never-firing halving at 260–265, and three modules (`staking`, `delegation`, `universal_mining`) all calling mint paths against `MAX_SUPPLY`.

## Part A — Math (checks out, with one honesty caveat)

The arithmetic is **correct and internally consistent**. Recomputed independently:

| Quantity | Spec | Recomputed |
|---|---|---|
| epochs/year @20s | 1,576,800 | 1,576,800 ✓ |
| δ = (1−8.1e-8)^1,576,800 | 0.8801 | 0.88010 ✓ |
| reserve half-life | 5.43 yr | 5.427 yr ✓ |
| 95% / 96% emitted | 23.5 / 25.2 yr | 23.46 / 25.20 yr ✓ |
| genesis per-epoch | 12.069 AIN | 12.069 ✓ |
| year-1 total | 17.87M | 17.865M ✓ |
| `remaining×81` overflow | ~1.2e28 ≪ 3.4e38 | confirmed, no u128 overflow ✓ |

**Finding 1 (honesty, not error): the drawdown never spends E — it asymptotes to it.** "Does the math spend E=149M over the stated horizon?" — No. At the 25-yr "effective life" only ~96% (~143M) is emitted; ~6M AIN remains in reserve, and full emission is mathematically asymptotic. Integer truncation makes `E_epoch → 0` once `remaining < 1e9/81 ≈ 1.23e7` base units (~1.2e-11 AIN), which the geometric decay reaches only around **year ~343**. This is a legitimate design property (Cardano/Avalanche behave identically), but the spec should state plainly that 149M is a **limit, not a payout schedule** — ~4% of the cap is still unminted at the advertised horizon. Whitepaper/marketing must not claim "149M distributed in 25 years."

## Part B — Does the fixed-pot split remove N-scaling? (PROVEN yes)

**Finding 2 (confirmed, the redesign's core win holds).** `e_epoch = (remaining × DRAW_NUM) / DRAW_DEN` depends only on `total_supply`, computed *before* any validator loop. `val_bucket = e_epoch − depin_bucket` is fixed; per-validator `reward_i = (val_bucket × w_i)/Σw_j` is a partition of that fixed pot, and dust is routed so Σ payouts = `val_bucket` exactly. Adding validators at equal total stake thins slices but cannot enlarge the pot. **N-independence is structural and correct** — this genuinely kills the line-287 bug. The §7 regression test ("identical emission for N and 10N validators") is the right invariant.

## Part C — Integer determinism (clean on-chain, one precision trap)

**Finding 3.** No determinism holes on the consensus path: δ/k/half-life are **off-chain documentation only**; the on-chain path (`(remaining×81)/1e9`, `(e_epoch×2000)/10000`, `min`, `/COIN_SCALE`, `(val_bucket×w)/Σw`) is all integer, deterministic across nodes. Good.

**Finding 4 (precision, carried over from legacy code).** The spec preserves `weight = min(stake, z0) / COIN_SCALE` — dividing weight to whole-AIN units *before* summing. This truncates all sub-AIN stake and, more importantly, is a **multiply-after-divide ordering** in the weight aggregation while `reward_i` correctly multiplies-then-divides. It's deterministic but lossy; any validator whose *clipped* weight floors to 0 AIN earns nothing. With `MIN_STAKE = 1000 AIN` (confirmed at line 25) this won't bite in practice, but the double-rounding (weight floor, then reward floor) inflates the dust routed to the anchor leader — see Finding 9.

**Finding 5 (edge case, unhandled abort).** If `total_staked = 0` or all clipped weights floor to 0, `Σw_j = 0`. Current code `return`s early; the redesign's §7 hard `assert!(distributed == e_epoch)` would then **abort the epoch** (nothing distributed but `e_epoch > 0`). Need an explicit fallback (route undistributable `val_bucket` to anchor leader/treasury) or the assert will halt `advance_epoch` under a degenerate-but-reachable stake state.

## Part D — Saturation sybil workaround (the spec is self-aware but the mitigation is weak)

**Finding 6 (the headline weakness).** The spec correctly flags in §5(c) that the hard clip is split-exploitable, but **its mitigation does not hold up**. `z0 = total_staked/50 = 2%`. A whale splits into sub-2% identities to recover full linear weight. The claimed costs:
- **`MIN_STAKE` self-bond = 1000 AIN** — negligible. On a 100M-AIN staked network, 2% = 2M AIN per slot; the 1000-AIN bond is 0.05% of the stake it unlocks. No deterrent.
- **`MAX_ACTIVE_VALIDATORS` slot scarcity** — the *only* real cost, and it's soft. A 10% whale needs 6 sub-z0 identities. Unless the active set is both **small and full**, and slot admission is **competitive by total stake** (spec doesn't specify the admission rule), consuming 6 of e.g. 100 slots is nearly free.
- **Per-identity slashing** — doesn't raise sybil cost; honest splitting incurs no slashable event.

Because §5(b) applies the *same* clip to VDF leader-selection weight in `ordering.rs`, **one split defeats both the payout flattening and the consensus flattening simultaneously.** Consequence: the quantified "**Nakamoto ≥ ~17**" and "+25%–200%" claims (arXiv:2402.11170) describe *honest* stake distributions; against a deliberate splitter they collapse toward the pre-clip baseline. The spec oversells a decentralization guarantee that a rational whale nullifies for ~0.05% cost. **This must be reframed:** either (a) tie admission/leader weight to a sybil-resistant signal (bond that scales with claimed weight, KYC'd/DePIN-attested identity, or quadratic-cost bonding), or (b) drop the Nakamoto numbers to "best case, absent identity-splitting" and stop treating a falling Nakamoto as the sole release gate.

**Finding 7 (auto-compound fix is a speed bump, not a structural fix).** §5(a) claims routing rewards to a liquid store "breaks the exponential feedback loop." It doesn't — it makes restaking **opt-in via `add_stake`**. A rational whale re-stakes every epoch and recovers `dS/dt ∝ S`. The correct claim is "removes *automatic* compounding," which slows passive concentration but does not break the loop for motivated actors.

## Part E — Does unifying the 3 streams break delegation / DePIN? (YES — two concrete breakages)

**Finding 8 (delegation — the redesign breaks its live claim path).** `delegation.move` is **not** a per-epoch distributor. It's a MasterChef-style lazy accumulator: it calls `0x1::staking::mint_reward(pending)` on the **claim/delegate/undelegate paths** (lines 137, 205, 294), minting at claim time against `accumulated_rewards_per_share`. §7 demotes `mint_reward` to "private, callable solely by the master path" — that **breaks all three call sites**. The spec's model ("delegation splits `val_bucket` after allocation; it does not mint") assumes an eager per-epoch feed that doesn't exist in the code. Folding delegation into the fixed bucket requires rewriting its entire reward-accounting model (feed `accumulated_rewards_per_share` from the epoch `val_bucket` instead of lazy-minting), not just narrowing a visibility modifier. Additionally, the disposition pseudocode `coin::deposit(v.validator_addr, reward_coins)` sends **100% of `reward_i` to the validator address**; the delegator commission split is described only in prose ("before deposit") and is absent from the code — as written, **delegators receive nothing**. This is the single most under-specified breakage.

**Finding 9 (DePIN/universal_mining — fundamental cadence mismatch).** `universal_mining::distribute_reward` mints **per verified device proof** (event-driven from `submit_vote`, line 248), `base_reward = 0.36 AIN × bqi_score/100` per proof — **not** a per-epoch schedule. Capping it at a fixed 20% per-epoch bucket is a model change, not a "demotion to distributor," and raises two unanswered questions: (a) in an epoch with **few/no** device proofs, who receives the 20% `depin_bucket`? (spec has no sink → either lost, or the §7 assert fails); (b) with **many** proofs, devices are now rate-limited to 20% and the per-proof BQI-score economics are decoupled from actual reward. The proof timing does not align to epoch boundaries at all. This needs a real design (accrue depin_bucket into a pool that `universal_mining` draws against per-proof, with carry-forward for empty epochs), which the one-line "demote to distributor" does not describe.

## Part F — New centralization / security-budget issues introduced

**Finding 10 (governance knob removes the load-bearing cap clamp — cap-breach path).** §6's AFTER code **deletes** the `if (total_supply + budget > MAX_SUPPLY)` clamp, justified as "cap-safe by construction." That safety holds **only while `DRAW_NUM ≤ DRAW_DEN`**. §8 exposes `DRAW_NUM/DRAW_DEN` as `UpdateEconomicParams` governance knobs. A fat-fingered or malicious `DRAW_NUM > DRAW_DEN` makes `e_epoch = remaining × (>1) > remaining` → mints past `MAX_SUPPLY`. §7 asserts `e_epoch ≤ remaining` but §6's pseudocode omits it — **the two sections contradict**. Fix: either hard-bound `DRAW_NUM < DRAW_DEN` at the governance setter, or keep the `min(e_epoch, remaining)` clamp. Do not ship the clamp deletion alongside a mutable numerator.

**Finding 11 (per-epoch cadence is not wall-clock anchored — horizon is elastic).** The entire 25-yr horizon assumes exactly 1,576,800 `advance_epoch` calls/year. But `epoch.move` shows `advance_epoch` is a **separate call** with a governance-mutable `epoch_duration` (defaulting to `10` for testing, line 22), and emission fires once per call regardless of real elapsed time. If epoch advances aren't pinned to 20s of wall-clock (DAG consensus has no fixed block time), the emission rate and horizon **drift with block cadence** — faster blocks = faster drawdown = shorter effective life. Avalanche/Cardano anchor emission to *slots/time*; this design anchors to *epoch-advance count*. Either drive `E_epoch` from measured elapsed time (`epoch_start_time` accumulator already exists in `epoch.move`) or document that "25 years" assumes a perfectly-held 20s cadence and will compress under real throughput.

**Finding 12 (liquid rewards lower the security budget).** The disposition change (stake→liquid) is good for decentralization but **reduces staked ratio**: rewards that previously auto-bonded are now liquid and likely sold, and restaking is opt-in (Finding 7). Lower `total_staked` → lower cost-to-attack. Combined with a capped, front-loaded, **tail-less** emission (per-epoch reward ≈ 0.5 AIN total by year 25), the long-run security budget leans entirely on fees ("sweep to miner" per CLAUDE.md), which the spec never sizes. Flag: no tail emission + liquid (sellable) rewards is a compounding security-budget risk that should be modeled before mainnet.

**Finding 13 (anchor-leader dust re-introduces a stake-correlated advantage above the clip).** Routing per-epoch dust (inflated by the double-rounding in Finding 4) to the anchor leader gives whoever leads most a systematic bonus. Since leader selection is stake-weighted (even clipped), larger validators lead more often and collect more dust — a small leak *above* the `z0` ceiling that partially undoes the saturation flattening. Minor, but it's a new vector the clip was meant to close; prefer routing dust to a treasury/burn or carrying it in `remaining`.

---

## Verdict: NOT implementation-ready as written. Sound skeleton, three blockers.

The **emission core is correct and ready** — the math is exact, cap-safe (given the clamp fix), N-independent, and integer-deterministic. Findings 1–5 are documentation/edge-case polish.

**Must change before implementation:**

- **BLOCKER — Finding 8:** Delegation's lazy-mint accumulator is incompatible with "demote `mint_reward` to private." Redesign delegation's reward feed to draw from `val_bucket`, and specify the delegator commission split *in code* — the current disposition sends 100% to the validator, zeroing delegators.
- **BLOCKER — Finding 9:** DePIN mints per-proof (event-driven), not per-epoch. A fixed 20% bucket needs a real pool/carry-forward design and an empty-epoch sink, or `advance_epoch` aborts on the §7 assert.
- **BLOCKER — Finding 10:** Restore the cap clamp or bound `DRAW_NUM < DRAW_DEN`; the mutable-numerator + deleted-clamp combination is a cap-breach path. Resolve the §6/§7 contradiction.
- **MAJOR — Finding 6:** Downgrade the Nakamoto/Gini guarantees to "honest-distribution best case." The 1000-AIN bond does not deter stake-splitting; the clip is defeatable for ~0.05% cost and the same split defeats the `ordering.rs` leader-weight clip. Add a sybil-resistant admission/weighting cost or stop gating releases on Nakamoto alone.
- **MAJOR — Finding 11:** Decide whether emission is anchored to epoch-count or wall-clock, and document the horizon's elasticity accordingly.

**Should address:** Findings 5, 7, 12, 13 (edge-case abort, opt-in-restake honesty, tail-less security budget, leader-dust leak).

Once Findings 8/9/10 are specified and 6/11 are reframed, the design is implementable and the emission engine itself is regression-testable exactly as §7 proposes.

**Files that will need the heaviest work beyond the spec's list:** `delegation.move` (reward-accounting rewrite, not a visibility tweak) and `universal_mining.move` (per-proof→pooled cadence), plus a governance setter guard for `DRAW_NUM`. Confirmed source paths: `/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/stdlib/sources/{staking,epoch,delegation,universal_mining}.move`.