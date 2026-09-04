# AINCORE Emission Calibration — Pre-Genesis Research Report

> **Purpose:** decide the permanent-genesis emission calibration (DRAW_NUM), the block-time
> pinning mechanism, delegation-at-launch, and DEX float sizing — with mathematical modeling,
> real-chain empirical evidence, adversarial stress-testing, and academic grounding.
> **Method:** 11 research agents in 2 orchestrated workflows (4 quantitative modeling agents
> running verified Python, 2 chain-history researchers, 3 academic-literature researchers,
> 1 adversarial economist, 1 synthesis judge). Every number below is computed, not estimated.
> **Date:** 2026-07-17. **Model verified against the live chain:** realized emission
> 11.899 AIN/epoch after 5,014 epochs vs model 11.90 — zero drift.

---

## 0. Executive summary — the decision

**The hyper-inflation the founder fears cannot come from the cap** (150M is unbreachable,
proven live: mint anchor = MAX − (net + burned), burns cannot refill emission). **It comes
from the float:** year-1 emission lands on a public float of only ~1M AIN (0.67% of cap).
The calibration question is therefore one ratio — *annual sellable emission vs public float*
— and one coupling — *block time vs DRAW_NUM*.

**RECOMMENDED PACKAGE (four moves, all required together):**

1. **Calibration B — keep DRAW_NUM = 81 (~3.5%/yr of remaining reserve)** at the measured
   3.59 s block time. The highest rate that stays under the 100% effective-float-inflation
   reflexivity threshold (51% with founder restake), while still distributing 66.5% of the
   cap by year 30 (vs 46.9% for the slower option A — and in a 0%-pre-mine model, emission
   *is* the distribution mechanism).
2. **Fix the block-time coupling:** refactor DRAW_NUM from a Move `const` into a
   governance-adjustable stored parameter with hard bounds `[40, 162]` enforced in Move,
   store `target_block_time = 3.59s` on-chain, re-measure on final mainnet hardware before
   genesis. Reject wall-clock epochs and timestamp auto-retargeting (proposer-controlled
   `SystemTime`, no median guard — adds an attack surface emission does not need).
3. **Raise the DEX seed from 1M → 5M AIN (~3.4% of cap)** to reach the BTC-like ~1.0×
   float/emission ratio, and fund the USD side to an absolute floor of **$50k** (below
   that, validator fiat-cost extraction drains the pool terminally under *every*
   calibration — the USD depth, not the emission rate, decides survival).
4. **Wire delegation before genesis (dormant, DELEGATION_BPS = 0), activate before public
   buy-in** — it is the single largest sell-pressure sink (cuts liquid public sell-side
   2.67×) and the only lever that moves emission share to the public without touching
   founder stake. Pair with a published founder restake commitment (≥80% years 1–2) and a
   founder stake-share decay target (<50% by year 3).

**Rejected:** C (5%) — dominated by B, every failure mode ~40% hotter; D (8%), E (12% — the
original design intent), F (17.6% "BTC-equivalent") — all cross the reflexivity threshold
*even with* founder restake (117% / 175% / 257% effective year-1 float inflation) and die on
the death-spiral model. **BTC's schedule without BTC's float is hyperinflation:** BTC ran
~17%/yr-of-remaining in 2010 with a 1.15× float/emission ratio; F gives AINCORE 0.039×.

---

## 1. Verified system facts (inputs to all models)

- Hard cap 150,000,000 AIN; emission `e_epoch = remaining × DRAW_NUM/1e9`, DRAW_NUM = 81,
  epoch = 20 blocks (block-count driven). Geometric drawdown; dust stays in reserve;
  N-independent; cap-anchored on cumulative minted (burns excluded) — all live-verified.
- **Measured block time 3.59 s** → epoch 71.8 s → 439,220 epochs/yr → **realized 3.495%/yr
  of remaining**. The code's design comment assumed ~1 s blocks (~12%/yr): the deployed
  schedule already runs 3.4× slower than its own design intent, purely due to block time.
- Genesis model (locked): 0% dev-fund; ~1M AIN DEX seed (size adjustable — see §5);
  founder bootstrap validator stake (modeled 1–5M; sensitivity negligible); optional
  treasury. 100% of e_epoch to validators; DELEGATION_BPS = DEPIN_BPS = 0 today.

## 2. Candidate calibrations — 30-year trajectories

DRAW_NUM verified to 3 s.f. at 3.59 s blocks (formula:
`rate = 1 − (1 − DRAW_NUM/1e9)^epochs_per_year`):

| Cand | DRAW_NUM | %/yr of remaining | Reserve half-life | 95% emitted | Emission <1M AIN/yr | % of cap emitted by yr 30 |
|---|---|---|---|---|---|---|
| A | 46 | 2.000 | 34.3 y | yr 148 | yr 55 | 46.9% |
| **B (status quo)** | **81** | **3.495** | **19.5 y** | **yr 84** | **yr 47** | **66.5%** |
| C | 117 | 5.009 | 13.5 y | yr 58 | yr 40 | 79.2% |
| D | 190 | 8.007 | 8.3 y | yr 36 | yr 31 | 92.0% |
| E (design intent @1s) | 291 | 11.998 | 5.4 y | yr 23 | yr 24 | 97.5% |
| F ("BTC-equiv") | 440 | 17.573 | 3.6 y | yr 16 | yr 18 | 99.7% |

Notes: (i) F as stated (440) *overshoots* true BTC-equivalence — 50% of remaining per 4 yr
= 15.91%/yr discrete requires DRAW_NUM ≈ 394. (ii) Year-1 *headline* inflation is brutal for
every candidate (A 73% … F 641%) because the circulating base is ~4M; by year 3 the headline
converges to 29–37% for **all six** — the real differentiation is the float ratio (§3) and
years 5–10. (iii) Founder-capture: under F the dominant early validator could accumulate
~47M AIN (31% of cap) in 2 years vs ~10M under B — faster calibration concentrates *more*
supply in the founder exactly when competition is thinnest.

## 3. Float dilution — the actual hyper-inflation risk

BTC comparison: when BTC markets first existed (mid-2010), float ≈ 3.0M vs emission
≈ 2.6M/yr → **ratio 1.15×**. AINCORE at a 1M float:

| Cand | Y1 emission | float/emission @1M | Float needed for 1.0× |
|---|---|---|---|
| A | 2.92M | 0.343× | 2.9M |
| **B** | **5.10M** | **0.196×** | **5.1M** |
| D | 11.69M | 0.086× | 11.7M |
| E | 17.51M | 0.057× | 17.5M |
| F | 25.65M | 0.039× | 25.6M |

**Every candidate fails the BTC float test at 1M — the float is the crisis, not the cap.**

Effective year-1 float inflation (sold rewards / float), founder at ~80% stake restaking
100%, others selling fraction *s*:

| Cand | s=10% | s=50% | s=100% |
|---|---|---|---|
| A | 5.8% | 29.2% | 58.4% |
| **B** | **10.2%** | **51.0%** | **102%** |
| D | 23.4% | 116.9% | 233.8% |
| E | 35.0% | 175.1% | 350.2% |
| F | 51.3% | 256.5% | 513.0% |

Without founder restake, B at just 25% selling = 127% — hyperinflation optics even at the
status-quo rate. **The founder restake commitment is the single biggest shock absorber
(5× reduction in sellable emission).** D/E/F cross the ~100% reflexivity threshold *even
with* the commitment → rejected. The pain is front-loaded and self-healing *iff* year 1 is
crossable (B at 50% sell: 255% → 69% → 40% → 27% → 21% over years 1–5 without restake;
51% → 33% → 24% → 19% → 15% with it).

DEX depth (constant-product): % price drop depends **only** on AIN sold vs the AIN reserve.
On a 1M pool: 10k sold = −2.0%, 100k = −17.4%, 500k = −55.6%. One *week* of candidate-B
emission (~98k) dumped at once craters price 17%. On a 5M pool the same 100k = −3.9%.
The USD side sets what sellers *extract*: at $50k depth, a 100k-AIN sale nets only $4.5k.

## 4. Validator economics — never the binding constraint

- **Break-even AIN price is sub-cent almost everywhere** (worst cell in the whole grid:
  A, N=100, $300/mo server, yr 5 → $0.133/AIN; B at N=25/$100mo → $0.006). No candidate
  fails on "validators can't afford to run."
- **Year-1 APY is absurd for ALL candidates** (196%–1,722% at 50% staked) — caused by the
  0.67% float, not DRAW_NUM. The "ponzi optics" fix is float sizing + staking participation,
  not the emission rate.
- Yield stays in the competitive band (≥15%, ATOM/DOT level) until **year 12 under B** vs
  year 8 under F; falls below ETH's 3.5% at year 32 (B) vs year 14 (F). Lower calibrations
  keep a security-relevant yield for decades.
- Fee-transition deadline (Carlsten/Budish — first year emission/validator < cost): B has
  until year 42–211 depending on price/N; F forces fee-market maturity by year 17–48 —
  far too early for a chain whose fee economy (bridge) is still Phase 7.

## 5. Block-time coupling + the pinning decision

Sensitivity (same DRAW_NUM, different block time):

| Block time | B (81) realizes | E (291) realizes |
|---|---|---|
| 1 s | **11.99%/yr** | 36.80%/yr |
| 2 s | 6.19%/yr | 20.50%/yr |
| 3.59 s (measured) | 3.495%/yr | 12.00%/yr |
| 5 s | 2.52%/yr | 8.77%/yr |
| 8 s | 1.58%/yr | 5.57%/yr |

**A 7.6× silent swing.** A performance optimization that reaches the designed 1 s blocks
turns "safe B" into "rejected E" with zero code change to economics.

Mechanism verdict (assessed against THIS codebase):

| Option | Verdict |
|---|---|
| (a) Calibrate at genesis + monitor | Necessary, insufficient alone |
| (b) Wall-clock epochs | **Reject:** block timestamps are raw proposer `SystemTime::now()` with no median/drift guard — epoch boundary becomes proposer-influencable |
| (c) Bounded governance parameter | **Adopt:** DRAW_NUM → stored param, hard bounds [40, 162] in Move; worst case under full capture + 1 s blocks = 22.5%/yr — ugly but bounded, cap never at risk |
| (d) Timestamp auto-retarget | **Reject:** feeds emission from proposer clocks (10% sustained clock gaming moves 3.495% → 3.876%); year-1 proposer set is founder-dominant — beneficiary controls the input |

Plus the process rule: 7-day measured block time drifting >20% from the on-chain
`target_block_time` triggers a mandatory governance re-pin proposal.

## 6. Delegation at launch

Year-1, candidate B, founder stake 3M:

| Scenario | Liquid public sell-side | Emission to public | Delegator net APY |
|---|---|---|---|
| Delegation OFF (20% of float staked) | 800k | 319k (6.2%) | — |
| Delegation ON (70% of float staked) | **300k (−2.67×)** | 965k (18.9%) | ~124% |

Without delegation, DEX buyers who can't run servers hold a 0%-yield asset whose only
utility is selling. **Recommendation:** wire `distribute_delegation_rewards` into
`epoch::advance_epoch` before genesis but ship dormant (DELEGATION_BPS = 0) — the dead
path is a known hazard (a non-zero BPS previously accrued undistributed supply, audit #4)
— then flip via `UpdateEconomicParams` before public buy-in. This gets the runtime path
audited and testnet-exercised without hot-upgrading live economics post-genesis.

## 7. Real-chain evidence

**Successes (band convergence):** every surviving PoS chain converged to launch ≤8–10%/yr
disinflating to a 1.5–3.5% terminal floor. **Cardano** is the closest structural analogue —
geometric drawdown of remaining reserve, 6 years, zero emission revolts — but it drew
~20%/yr of remaining safely *only because 69% of supply circulated at genesis* (AINCORE
inverts that → must run the same mechanism 5–6× slower). **Polkadot** independently
converged onto AINCORE-v5's exact architecture in 2026 (hard cap + fixed-fraction-of-
remaining) after three governance rounds. **Solana:** 8% launch inflation survivable only
under a monster demand narrative; SIMD-228's emission *cut failed at 61% support* —
validators veto their own pay cut. **ATOM:** 4 years of >10% without demand → −90%, civil
war, chain fork (prop 848, Nov 2023); the late cut did not rescue price. **The ratchet only
turns down, and barely:** no chain has ever voted emission *up* for security, and cuts fail
even with majorities → **launch at the rate you intend to keep.**

**Failures (the death regime):** annual sellable flow ≥50–100% of float against a
pre-priced float: **ICP** −99.6%; **Filecoin** emergency tokenomics patch in week 1;
**Osmosis** ~300% year-1 emission → −97%; **LUNA** −99.99% in 6 days (elastic mint
reflexivity). Binance Research (May 2024): 80% of low-float/high-FDV listings declined
within 6 months; the 2024 average MC/FDV was 12.3% — AINCORE's 0.67% float is **18× thinner
than the already-pathological industry average**. Solana is the existence proof that <2%
float survives *iff* implied FDV at launch is low. Every failure case is the same event:
**supply flow arriving before demand infrastructure.**

## 8. Adversarial stress-test verdicts

Six attack scenarios were constructed against every candidate (float-dilution death
spiral, >100% reflexivity exit, too-slow centralization optics, block-time drift,
governance-knob capture, saturation-clip sybil-split):

| Cand | Verdict |
|---|---|
| A | SURVIVES — bleeds, never spirals; worst founder-dominance optics (79.6M unissued at yr 30) |
| **B** | **SURVIVES CONDITIONALLY** — on (1) founder ≥80% restake yrs 1–2, (2) DEX USD depth >$50–100k, (3) block-time re-pin. 51% eff. float inflation, 22.5% bounded worst case |
| C | RISKY — under the line only with near-total restake; dominated by B |
| D | DIES — 117% eff. float inflation *with* restake; −97% in 24 months on the spiral model |
| E | DIES — 175% with restake; this is what DRAW_NUM=81 *becomes* at 1 s blocks |
| F | DIES FASTEST — 257% with restake; pool dead month 6–19; founder captures 31% of cap in 2 yrs |

**Dominant failure mode (CRITICAL):** the fiat-cost forced-selling spiral. Death-spiral
ignition threshold measured: **monthly fiat extraction > ~2% of the pool's USD reserve.**
At $10–50k USD depth even candidate B dies (month ~8); at $50–100k B bleeds but survives.
The USD side of the DEX pool is the survival variable; the emission rate sets the slope.

## 9. Academic literature grounding

43 high-tier papers surveyed across three fields (13 classical monetary economics, 16
academic cryptoeconomics, 14 microstructure/empirical tokenomics); 34 were new to the
project bibliography and are now archived as **AINCORE_BIBLIOGRAPHY.md sections G and H**
(total references: 106). What the combined literature says:

### 9.1 Where the literature AGREES (robust across all strands)

1. **12% and 17% are eliminated by every strand simultaneously.** Cagan: past every
   estimated seigniorage-Laffer peak against a 1M float (higher rates buy *less* real
   security revenue, not more). Calvo–Végh: calibrated for a captive currency base that
   token holders — whose exit is a wallet click — are not. Khan–Senhadji/Barro: above the
   ~11–12%/yr damage threshold for the whole bootstrap. Saleh (RFS): restores the PoS
   forking regime. Budish: exhausts the reserve exactly when the tail-flow condition needs
   it. Lucas/McCandless–Weber: money growth passes ~1:1 into dilution and buys ~zero real
   adoption. **No high-tier paper supports the high band.**
2. **The binding variable is the sold-emission-to-float ratio, not the rate.** Against a
   1M float, *all six* candidates are Cagan-grade if emission is fully sold (even 2%/yr ≈
   25%/month of float initially). The literature is most emphatic about the plumbing:
   delegation live before public onboarding (Calvo–Végh's pay-interest-on-domestic-money
   defense; emission absorbed as locked stake stays *out* of the Cagan money stock), a
   float enlarged well beyond 1M, and **permanent protocol-owned DEX liquidity as the
   Obstfeld–Rogoff fractional-backing floor** — the hard cap alone cannot rule out a
   self-fulfilling spiral (JPE 1983); a redemption floor can.
3. **Regime credibility beats rate-level.** Sargent ("Ends of Four Big Inflations"):
   hyperinflations end via discrete *credible regime change* — statutory, non-discretionary
   limits — not gradual tightening. Block-time coupling is precisely a silently drifting
   discretionary rate. Within the moderate band, *visible non-discretion matters more than
   the exact number*.
4. **Do not raise emission to dilute the founder.** Roşu–Saleh (Management Science):
   proportional PoS rewards are a martingale on stake shares — a higher rate dilutes
   everyone proportionally and changes nothing; **tradable float depth is the actual
   decentralization mechanism.** (Fanti et al. govern years 0–2 — early entrenchment is
   real while the float is thin — and both papers point at the same remedies: delegation
   and float, not the rate.)
5. **Fee revenue will not arrive on schedule.** Huberman–Leshno–Moallemi (REStud): an
   uncongested chain earns structurally ~zero fees — and AINCORE's pitch *is* high
   throughput. Hinzen–John–Saleh (JFE): limited adoption is an equilibrium, not a phase.
   Emission must carry ~100% of the security budget indefinitely → favors schedules that
   preserve reserve (B keeps 52% of cap at year 20; F keeps ~0.3%).

### 9.2 Where the literature genuinely CONFLICTS (honest disclosure)

- **Saleh vs the security-budget school** — the sharpest real conflict: Saleh wants
  rewards *modest* (else PoS re-admits forking); Budish/Carlsten want reward *flow large
  enough* to dominate one-shot attack payoffs. They bind at different times (Saleh early,
  Budish in the tail); 3.5–5% geometric satisfies both *today*, but if bridged TVL grows
  fast, Budish can demand more flow than Saleh permits — resolvable only by fee revenue,
  not by any DRAW_NUM.
- **Friedman (zero optimal emission) vs Phelps (positive second-best)** — resolved in
  principle by Phelps's no-other-tax-instrument frame; *where* marginal dilution cost
  crosses marginal security benefit depends on an external-validator participation
  constraint that is unobservable pre-launch.
- **Bruno–Easterly (~40% crisis threshold) vs Khan–Senhadji (~11–12%)** — unresolved in
  the source literature; Calvo–Végh's substitution-elasticity argument implies token
  thresholds sit *below* sovereign estimates → prudence takes the lower number.
- **Literature vs codebase on pinning mechanism:** Sargent's ideal is wall-clock-pinned +
  non-adjustable. This codebase's block timestamps are raw proposer `SystemTime` (no
  median guard), so wall-clock epochs would hand proposers an emission input — worse than
  the disease. The adopted compromise (bounded governance parameter, bounds hardcoded in
  Move) delivers the *credible-non-discretion property* Sargent actually requires
  ("hyperinflation impossible by construction: ≤2× genesis rate, ever") without the new
  attack surface. This is a deliberate, documented deviation from the literature's ideal
  on implementation-security grounds.

### 9.3 What remains a founder VALUE JUDGMENT (economics cannot decide)

- The exact point in **3.5–5%**: the literature's conditional rule is *5% iff delegation
  ships at genesis AND the float is enlarged several-fold; 3.5% otherwise* (Uribe's
  hysteresis: over-emission exit is irreversible, under-emission is correctable → err low).
- Float enlargement itself: more float = founder sells/LPs more earned AIN sooner — a
  fair-launch-purity vs spiral-insurance tradeoff.
- Tolerable centralization-time: how many months of founder-only validation before "too
  slow" (Sargent–Wallace's accruing deficit) is a risk preference.
- The Saleh-vs-Budish tail bet: trust future fees, or hold reserve as insurance. The
  geometric never-zero schedule hedges this better than fast drawdown — but it is a bet.

## 10. Must-do before genesis (from the synthesis)

1. Re-measure block time on final mainnet hardware; set DRAW_NUM by formula (81 iff 3.59 s
   holds — at 1 s the same target needs DRAW_NUM ≈ 23).
2. Refactor DRAW_NUM → bounded governance parameter [40, 162] + on-chain
   `target_block_time`; adopt the >20%-drift re-pin rule.
3. Raise DEX seed to 5M AIN; fund the USD side ≥$50k (target ≥12 months of aggregate
   validator fiat-cost extraction).
4. Publish the founder restake commitment (≥80%, years 1–2, on-chain verifiable), the
   no-sybil-split commitment, and a founder stake-share decay target (<50% by year 3).
5. Wire delegation dormant + publish the activation commitment (no later than
   bridge/stablecoin listing).
6. Publish the official emission schedule + a circulating-vs-sellable dashboard *before*
   genesis — define the narrative before third-party dilution trackers do.

## 11. Monitoring dashboard (post-genesis)

7-day block time vs target (±20% alert) · realized emission/epoch vs model · effective
float inflation (<100%) · pool USD reserve vs monthly extraction (2% ignition threshold) ·
founder stake share vs decay target · fee/emission ratio (Carlsten tracker) · APY vs
competitive band · cumulative minted vs schedule.

---

*Full model tables (30-year per-candidate trajectories, float-inflation grids, validator
break-even grids, APY tables, sensitivity matrices) are archived from the research run;
key excerpts embedded above. Companion documents: AINCORE_EMISSION_PAPER.md (v4/v5 design),
SECURITY_AUDIT_EMISSION_V4.md (audit), AINCORE_BIBLIOGRAPHY.md (references).*
