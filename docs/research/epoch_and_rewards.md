# AINCORE: epoch interval and reward cadence (decision report)

- **Date:** 2026-09-29.
- **Scope:** research and recommendation only. Nothing in the repo was edited, built or committed.
- **Code read at:** worktree `.claude/worktrees/g3-activation`, HEAD `2c7c4e4`. All `file:line` references below are to that tree.
- **Inputs:** `docs/G1_CONSENSUS_CONTRACT.md` (EP, GC, RC, Open questions 2, 4, 7, 8), `docs/G3_STATE_AUTHENTICATION_CONTRACT.md` (TA-0..TA-4, SN-4, GC), `core/executor/src/lib.rs`, the Move modules `epoch`, `staking`, `delegation`, `governance` and `universal_mining`, `docs/AINCORE_EMISSION_CALIBRATION.md`, and the primary sources listed at the end.
- **Measured numbers used:** 6.65 s per block, a 3 s consensus tick, one block per committed anchor. That gives 12,992 blocks per day and 4,745,504 per year.
- **Reproducible math:** `scratchpad/research/epoch_math.py`. Every number in section (b) comes from it.

> **Superseded in part, and corrected (2026-09-30).**
> - **Clock: superseded by G5 amendment A1** (`docs/research/clock_and_deadlines.md`). This
>   report counts deadlines and emission in blocks. That holds in real time only while the
>   block time stays at the value measured at genesis, and nothing enforces it. A1 counts
>   them in capped consensus time τ instead. I and R stay in blocks.
> - **Wrong here: "AINCORE has no BFT time" (b.5, (d) 6).** At HEAD the block timestamp is
>   already the stake-weighted median of signed vertex timestamps
>   (`consensus/blockchain/src/lib.rs` `bft_block_timestamp`), with a 30 s future-drift gate.
> - A source check of every citation (89 claims) confirmed 74. The rest are corrected below
>   and inline:
>   1. *Wrong:* the survey by Deirmentzoglou et al. does not list Winkle. Its
>      countermeasures are the longest-chain rule, moving checkpoints, key-evolving
>      cryptography, context-aware transactions, the plenitude rule, economic finality and
>      trusted hardware. Winkle is later work (Azouvi, Danezis and Nikolaenko, AFT 2020).
>   2. *Wrong:* "none counts emission in a period that governance can stretch". Cosmos
>      x/mint counts by `BlocksPerYear`, a governance parameter. The Hub mints about 1.27×
>      its target today, because its blocks are faster than that parameter assumes.
>   3. *Outdated:* the Cosmos Hub evidence age. Launch genesis had 3 weeks. Today it is 48 h
>      AND 1,000,000 blocks, both required, about 66 days, while unbonding stays 21 days.
>   4. *Outdated:* the Ethereum weak-subjectivity table. Electra (live since 2025-05-07)
>      gives 665–3,532 epochs; mainnet is about 3,532 epochs, about 15.7 days.
>   5. *Outdated:* Polkadot. Validators still unbond for 28 eras, with slashing deferred 27.
>      Referendum 1910 (2026) made nominators unslashable with about 2 eras of unbonding. The
>      RFC-0097 queue is not what shipped.
>   6. *Outdated:* Solana. SIMD-0204 was merged in 2025 (it verifies and logs infractions
>      only); SIMD-0212 (slashing) was closed unmerged in 2026-01. There is no active slashing.
>   7. *Caveats:*
>      - Cosmos SDK #6478 was closed by PR #6844 for the validator queue. Its height term is
>        the unbonding start height, so delegations still complete by time only.
>      - Buterin 2014 calls the rule "max revert N blocks", not "revert limit".
>      - The Sui Lutris results quoted are in §7.4 and the §4 preamble, not §4.2.
>      - Aptos's 16.8 s DKG is the paper's fast path.
>      - The Sui staking URL now redirects to the tokenomics page.
>      - Casper's δ is the delay between clients, and W = U is this report's application of
>        it, not Casper's rule.
>   8. *Unsourced:* "Diem epoch-change proofs", Solana's cool-down length, "100+
>      validators" and "none rotates every 2 minutes" have no source here and carry no
>      decision.

**In plain words, for the founder.**
1. Make the validator-set period (the "committee epoch") **1,000 blocks**, about 1.85 hours today. Fix it at genesis and never change it.
2. Keep paying block rewards on a short schedule, **every 20 blocks** (about 2.2 minutes, as today), but make that schedule independent of the committee epoch.
3. Count emission, unbonding, the evidence window and every other deadline **in blocks**. That way tuning the epoch can never move the emission curve or the 21-day unbonding again.
4. **Flipping the epoch to 1,000 on its own, with no other change, would be a serious error.** It would cut emission about 50 times and stretch validator unbonding from about 46 days to about 6.4 years. The three existing clocks are tied to the epoch count (section b.8).

---

## (a) Decision table

| # | Parameter | Recommended value | Formula or reasoning | Production precedent | Citation |
|---|---|---|---|---|---|
| 1 | Committee epoch `I` | **1,000 blocks** (≈1.85 h at 6.65 s). Genesis-pinned and immutable, as G1 requires. | Lower bound: boundary overhead B/I ≤ 1% even at a pessimistic B = 10 blocks, so I ≥ 1,000. Upper bound: at n=4 there is zero slack, so the windows that scale with I (abstention after a wipe, a slashed validator's leftover weight, departure delay) should stay within about 2 h of operator response time, so I·t_b ≤ 7,200 s and I ≤ 1,083. Observer snapshot pins also need I ≤ 2·1,000. | Aptos 2 h epochs. Polkadot 4 h sessions for authority-set changes. | aptos.dev staking; Polkadot wiki; pallet_grandpa |
| 2 | Reward period `R` | **20 blocks** (≈2.2 min). Separate from I, with I mod R = 0 (50 periods per epoch). Genesis-pinned. | Economics do not depend on R, because payouts telescope (b.7). R = 20 keeps today's live-verified cadence and costs 650 payouts a day instead of 12,992 for per-block payouts. Because I mod R = 0, no payout ever spans two committees. | Ethereum pays per slot (proposer and sync committee) and per 6.4-min epoch (attestations), while its light-client committee rotates every 27 h. Cosmos pays every block. Polkadot pays per 24-h era, with 4-h sessions. | consensus-specs phase0 and altair; Cosmos x/distribution |
| 3 | Emission clock | **Blocks, never epochs.** Payout at height h: `e = remaining × d_b × Δh`, where `Δh = h − last_reward_height`. `d_b = 4.05e-9` per block reproduces today's curve exactly. The founder picks the rate separately (calibration doc). | Cumulative emission becomes a function of height only, so changing I or R cannot move the curve. An aborted payout is caught up at the next one. | Bitcoin halves every 210,000 blocks by height. Cosmos x/mint pays each block from `BlocksPerYear`. | bitcoin `validation.cpp`; Cosmos x/mint |
| 4 | Reward recipients | Members of the frozen committee `C_{E(h)}`, weighted by committee stake with today's saturation clip. Jailed members are excluded. | The committee is who actually did the work in epoch E. Paying the live set would pay a joiner for up to I blocks of no work, and stop paying a leaver who is still signing. | Sui and Aptos pay per epoch to that epoch's committee. | docs.sui.io epochs; aptos.dev staking |
| 5 | Stake-change latency | Takes effect at the first block of E+1. The wait is 1 to I blocks: a mean of ≈500 blocks (≈55 min) and at most 1,000 (≈1.85 h), plus the QC activation of EP-4 (a few seconds). | Follows from EP-2 and EP-4. | Aptos: the next epoch, up to 2 h. Ethereum: at least 5 epochs (≈32 min). Cosmos: H+2. | aptos.dev; consensus-specs; CometBFT ABCI++ |
| 6 | Jail and slash latency | The economic slash is immediate: 100% in the block that commits the evidence. Consensus weight is removed at the next boundary, at most I blocks (≈1.85 h) later. | Committees are frozen per epoch (G1 Open question 8). f=1 is still tolerated at n=4, so this cannot break safety. | Ethereum: a slashed validator exits no earlier than 5 epochs later. Cosmos: H+2. | consensus-specs; CometBFT |
| 7 | Unbonding `U` | **273,000 blocks = 273 epochs** (≈21.0 d at 6.65 s). It is counted from `H_{E_leave}`, the last block of the validator's last committee epoch, not from the leave transaction. Stake stays slashable while it unbonds. | `U = ceil(21 d / t_b / I) · I`. The stake must still be there when any evidence younger than U arrives (b.5). | Cosmos: 21 d, and unbonding entries created after the infraction are slashed. Polkadot: 28 eras. Casper: withdrawal delay ω > 4δ. | cosmos/mainnet params; Cosmos x/staking; Polkadot runtime; Casper FFG §4.1 |
| 8 | Evidence max age `W` and retention | W = U (273,000 blocks) from the infraction height. `sys:equiv_seen` is kept for at least 274 epochs, keyed by epoch. | Evidence must never outlive the slashable stake, and stake must never unbond before evidence expires. | CometBFT: evidence expires only when older than *both* `max_age_duration` and `max_age_num_blocks`. The Hub uses 3 weeks, equal to its unbonding. | CometBFT `evidence/verify.go`; cosmos/mainnet params |
| 9 | Weak-subjectivity checkpoint | Maximum age **2/3·U = 182,000 blocks** (≈14 d). Publish a checkpoint with every release and at least every 7 days. A node offline for more than 7 days must boot from a checkpoint. | A checkpoint must be younger than the time after which old committees' keys carry no slashable stake, with margin. | IBC ADR-026: trusting period = 2/3 of unbonding. Ethereum's weak-subjectivity period is 504–3,532 epochs (≈2.2–15.7 d). Polkadot: checkpoints no older than 28 d. | ADR-026; consensus-specs weak-subjectivity; RFC-0097 |
| 10 | All Move deadlines | Store them as **heights**: unbonding, the 31-d claim grace, the 7-d commission delay, governance voting and timelock. Retire the virtual-seconds clocks. | Today three clocks disagree: the staking clock advances 60 s per epoch, the epoch clock 10 s per epoch, and a real epoch lasts 133 s (b.8). | Every chain above counts in its own consensus clock (slots, eras, heights, or BFT time). | as above |

---

## (b) The math

### b.1 Units

- t_b = 6.65 s per block. The tick is 3 s, so there are 2.217 rounds per block.
- Blocks per day = 86,400 / 6.65 = **12,992.5**. Blocks per year (365.25 d) = **4,745,504**.
- G1 epoch numbering is E(h) = ⌊(h−1)/I⌋. The boundary block of epoch E is H_E = (E+1)·I (`G1_CONSENSUS_CONTRACT.md:190-191`).

### b.2 Choosing I

**Lower bound: boundary overhead.**
- Each boundary costs B, which has not been measured (G1 Open question 3).
- The G1 steps at a boundary are:
  1. H_E is accepted.
  2. QC(H_E) forms, and activation needs it (EP-4).
  3. The activation transaction runs, and the DAG, cursor and GC floor are reset.
  4. The first round of E+1 attests and certifies.
  5. The first anchor at `first_round(E+1)` needs votes at the next round.
- Against steady state (one block every ≈2.2 ticks), that is roughly 2–4 extra ticks. **Estimate: B ≈ 1.5–3 blocks (≈10–20 s).** The pessimistic case, with fsync and BLS on the slowest validator (NAS), is 10 blocks (≈66 s).
- Overhead is B / I:

| I (blocks) | Wall time | Boundaries/day | Overhead at B = 1.5 / 3 / 10 blocks | Stake-change wait (mean / max) | TA-3 log entries/yr (≈2.5 KB each, estimate) |
|---:|---:|---:|---|---|---:|
| 20 (today) | 133 s | 649.6 | **7.5% / 15% / 50%** | 1 min / 2.2 min | 237,275 (≈579 MB) |
| **1,000** | **1.85 h** | **13.0** | **0.15% / 0.30% / 1.0%** | **0.92 h / 1.85 h** | **4,746 (≈11.6 MB)** |
| 1,080 | 2.00 h | 12.0 | 0.14% / 0.28% / 0.93% | 1.0 h / 2.0 h | 4,394 |
| 2,000 | 3.69 h | 6.5 | 0.08% / 0.15% / 0.50% | 1.85 h / 3.69 h | 2,373 |
| 3,240 | 5.99 h | 4.0 | 0.05% / 0.09% / 0.31% | 3.0 h / 6.0 h | 1,465 |
| 12,960 | 23.9 h | 1.0 | 0.01% / 0.02% / 0.08% | 12 h / 24 h | 366 |

- Requiring overhead ≤ 1% at the pessimistic B = 10 blocks gives **I ≥ 1,000**. That is a derivation of G1's otherwise unexplained floor (`G1_CONSENSUS_CONTRACT.md:231`).
- **At today's I = 20, a V4 boundary would eat 7.5–15% of all blocks.**
- In seconds, overhead ≤ 1% holds while t_b ≥ B_s / (0.01·I). With I = 1,000 that means t_b ≥ 1.0–2.0 s for B = 10–20 s, and t_b ≥ 6.6 s for B = 66 s.

**Upper bound: exposure windows that scale with I.** With n=4 and one Byzantine or down validator, there is zero slack (G1 LA-2). Each of these lasts up to I blocks:
- **RC-3 abstention.** A validator whose guard database was wiped abstains "for the rest of the epoch". That removes all fault tolerance at n=4 for up to I blocks (G1 Open question 4, `:882`).
- **Leftover weight of a slashed validator.** It keeps consensus weight until H_E (Open question 8, `:890`), with no stake left at risk.
- **Leaver's window.** A validator that has left stays in C_E until H_E. Today its unbonding stake is not slashable (finding F3).
- **Boundary frequency for testing.** A 48-h burn-in sees about 26 boundaries at I = 1,000, but only 2 at 24-h epochs. The boundary is where the FX-14 live halt came from, so its bugs need exercise before mainnet.
- Keeping each window within about 2 h of operator response gives I·t_b ≤ 7,200 s, so **I ≤ 1,083** at 6.65 s.

**Snapshot pins (G3 SN-4).**
- `pin_schedule` (`common/state_commit/src/lib.rs:723-735`) needs 2·keep ≥ I for any pin to fall inside the window.
- In observer mode, keep = 1,000. I = 1,000 gives 2–3 pins, I = 2,000 gives 1–2, and I = 12,960 gives 0–1 (often none).
- In full mode (keep = 100,000), I = 1,000 gives 8–9 pins.

**Result.** At 6.65 s the feasible band is **[1,000, 1,083]**, and **I = 1,000** is the recommendation. The general rule at genesis is:

> I = max(1,000, 100·B_s/t_b), subject to I·t_b ≤ 7,200 s.

If the lower bound ever exceeds the upper bound, fix the boundary cost rather than lengthen epochs.

### b.3 Reconfiguration overhead per epoch at I = 1,000

- **Throughput:** 0.15–0.30% expected, and 1.0% in the pessimistic case (b.2).
- **Storage:**
  - one `consensus:dag_committee:{E}` row and one `consensus:epoch_start:{E}` row, never deleted;
  - one TA-3 log entry, never pruned;
  - one QC.
  - That is 4,746 epochs a year, versus 237,275 at I = 20. At I = 20 the "never deleted" rows alone would be about 0.5 million a year.
- **Light client from a 21-day checkpoint:** 273 TA-3 entries to verify, versus 13,650 at I = 20.
- **Mempool:** in-flight epoch-E payloads are re-injected 13 times a day (EP-4). A crashed author's payloads are lost until resubmitted (Open question 7).

### b.4 How long a stake change or a jailing waits

- **Join, leave or add_stake.** The live set changes in the transaction's block (`executor lib.rs:808-1000`). The committee changes at H_E + 1. For a transaction at a uniformly random height:
  - the wait W is uniform on [1, I];
  - E[W] = (I+1)/2 = 500.5 blocks ≈ **55 min**;
  - max = 1,000 blocks ≈ **1.85 h**;
  - plus QC(H_E) activation, a few seconds.
- **Equivocation.** The steps are:
  1. The evidence rides in the next honest vertex (`SLASH_EVIDENCE:`, `dag.rs:24`).
  2. It is committed in about one block and slashed 100% in that block (`executor lib.rs:2377-2410`, `:2461`).
  3. The committee still counts the equivocator until H_E: at most 1.85 h, mean 0.92 h.
  - At n=4 with f=1 this cannot break safety (Lemma U: a twin can never be certified twice). It is a liveness exposure only.

### b.5 Unbonding, the evidence window and weak subjectivity

**Slashability condition.** Let h_i be the infraction height, h_ev the evidence inclusion height, and W the evidence maximum age (h_ev − h_i ≤ W).
- A validator that leaves in epoch E_leave still signs until H_{E_leave}, so h_i ≤ H_{E_leave}.
- If its stake becomes withdrawable at H_{E_leave} + U, all valid evidence lands while stake is held iff
  - h_i + W ≤ H_{E_leave} + U for every h_i ≤ H_{E_leave},
  - which holds iff **W ≤ U**.
- Setting W = U uses the whole budget. This is the CometBFT rule that `max_age_duration` "should correspond with" the unbonding period, and the Casper FFG §4.1 rule ω > 4δ.
- Worst case measured from the leave transaction: U + I = 274,000 blocks ≈ 21.09 d.

**Sizing U.**
- U = ceil(21 d / 6.65 s / 1,000) · 1,000 = **273,000 blocks** (21.01 d).
- The same block count lasts 11.3 d at 3.59 s blocks, 7.0 d at 2.2 s and 4.1 d at 1.3 s. So U must be re-derived from the block time measured at genesis, like I and the emission rate.
- Casper's condition ω > 4δ then tolerates an evidence propagation and inclusion delay δ of up to U/4 ≈ 5.25 d while the chain runs.
- **Counting in blocks has a real advantage here: a halted chain does not age evidence or unbonding.** The 10-day halt in this project's history would have consumed half of a 21-day wall-clock window. Cosmos SDK issue #6478 is exactly this bug: time-only unbonding against height-and-time evidence expiry.
- Cosmos can require *both* time and height. ~~AINCORE has no BFT time~~ (corrected 2026-09-30: it has one, the stake-weighted median of vertex timestamps). A1 uses it through a capped clock τ.

**Evidence retention.**
- W = 273,000 blocks ≈ 605,150 rounds.
- Today `EQUIV_EVIDENCE_RETENTION_ROUNDS = 100,000` (`dag.rs:49`) is ≈45,113 blocks ≈ **3.5 days**.
- With G1's epoch-bearing key `sys:equiv_seen:{offender}:{E}:{round}` (EQ-1), keep E ≥ E_now − (U/I + 1), which is **274 epochs**.

**Weak-subjectivity checkpoint.**
- Old keys become free to sign a forked history once their stake is withdrawable (Buterin 2014; Casper §4.1). A client's trusted state must therefore be younger than U, with margin.
- IBC's convention of 2/3 gives **182,000 blocks ≈ 14.0 d**.
- A weekly checkpoint (≈90,947 blocks) keeps every node within that bound with 7 days to spare.
- The rule "offline for more than 7 days, use a checkpoint" is safe while t_b ≥ 3.3 s.
- Genesis alone is a valid anchor only during the first 182,000 blocks (this tightens G3 TA-0).

### b.6 Reward cadence

**Cost per payout today.** `distribute_rewards` (`staking.move:366-487`) does two O(N) loops, then one mint and one deposit per validator, then rewrites `ValidatorSet`.

| R | Every | Payouts/day | Extra state writes/day at N=4 (≈N+2 per payout) |
|---:|---:|---:|---:|
| 1 | 6.65 s | 12,992 | ≈78,000 |
| **20** | **2.2 min** | **650** | **≈3,900** |
| 100 | 11 min | 130 | ≈780 |
| 1,000 | 1.85 h | 13 | ≈78 |

- Economically R is irrelevant once emission is block-counted (b.7). R = 1 is also correct if the founder prefers "every block pays".
- **R = 20 is chosen** because:
  - it is today's cadence, with no behaviour change;
  - it keeps writes low;
  - I mod R = 0, so each payout pays exactly one committee: blocks (h−20, h] all lie in one epoch.
- **Fees stay per block**, as today: 20% to the anchor leader and 80% stake-weighted (`executor lib.rs:1419-1500`). They should also be switched to C_{E(h)} for consistency.
- **Order inside a boundary block H_E** (which is also a payout height):
  1. the reward payout for (H_E − R, H_E] to C_E;
  2. the committee derivation for E+1 from the post-state (EP-2);
  3. the start of unbonding for members leaving at H_E.

### b.7 Counting emission in blocks, so epoch tuning never moves the curve

**Invariant.** Cumulative emission after height h, S(h), must depend on h only. With a per-block draw d_b on the remaining reserve:
- remaining(h) = remaining(h₀) · (1 − d_b)^(h − h₀), so S(h) = MAX − remaining(h).
- A payout at height h mints S(h) − S(h_prev) = remaining(h_prev) · (1 − (1 − d_b)^Δh).
- The payouts telescope: S(h₁) − S(h₀) + S(h₂) − S(h₁) + … = S(h_k) − S(h₀), whatever the payout heights are.
- So **neither R nor I can change the curve**. A skipped payout (a Move abort) is paid in full at the next payout, because Δh is larger.

**Integer implementation.**
- e = remaining · D_NUM · Δh / 10¹², with D_NUM = 4,050, which is today's curve.
- The linear form is off by a relative (d_b·Δh)/2: 3.8e-8 at Δh = 20 and 2.0e-6 at Δh = 1,000. Clamp Δh.
- Overflow: remaining < 1.5e26, times 4,050, times 1,000, is about 6e32, which is below u128::MAX ≈ 3.4e38.

**Today's coupling, with numbers.** The current rule is e_epoch = remaining · 81/10⁹ per epoch (`staking.move:57-58`, `:400`).

| Block time | I (reward epoch) | Draw per year of remaining | Reserve half-life | Year-1 mint from 150M |
|---|---:|---:|---:|---:|
| 3.59 s (calibration assumption) | 20 | 3.50% | 19.5 yr | 5.25M |
| **6.65 s (measured now)** | 20 | **1.90%** | 36.1 yr | 2.86M |
| 6.65 s | **1,000 (if flipped alone)** | **0.038%** | 1,803 yr | 0.058M |
| 6.65 s | 12,960 | 0.003% | 23,370 yr | 0.004M |
| 2.2 s | 20 | 5.64% | 11.9 yr | 8.47M |
| 1.0 s | 20 | 12.0% | 5.4 yr | 18.0M |

- The per-block equivalent of today's curve is d_b = 1 − (1 − 81e-9)^(1/20) = **4.050e-9**. Its half-life is 171.1M blocks: 36.07 yr at 6.65 s, and 19.47 yr at 3.59 s, which matches the market kit's "≈19.5 years".
- Counting in blocks removes the coupling to the epoch. It does **not** remove the coupling to block time. The calibration doc's `target_block_time` re-pin rule (`AINCORE_EMISSION_CALIBRATION.md` §5, §10) is still needed.
- **Decision for the founder:** keep today's per-block rate (1.90%/yr at 6.65 s), or re-pin to the calibrated 3.5%/yr. The latter is d_b = −ln(0.965)/4,745,504 = **7.51e-9** (D_NUM ≈ 7,508).

**If a halving is wanted instead.** The deployed code has no halving; see F7.
- The height-based form is reward_per_block(h) = R₀ ≫ ⌊h / H_half⌋, which is Bitcoin's `GetBlockSubsidy`. A payout sums the per-block reward over (h_prev, h].
- A 4-year H_half at 6.65 s is **18,982,015 blocks**.
- The README's 2,102,400 is 4 years only at **60 s** blocks. At 6.65 s it is **162 days**.

### b.8 What breaks if I = 1,000 is flipped alone

Today the executor calls Move `epoch::advance_epoch` every I blocks (`executor lib.rs:1201-1271`). That call:
- advances the Move `Epoch` clock by `epoch_duration` "seconds" (10 from `genesis.json`; `epoch.move:43`);
- advances `staking.current_epoch`, which the staking deadlines multiply by `EPOCH_SECONDS = 60` (`staking.move:82`, `:239`, `:267`, `:307`, `:607`);
- mints one epoch's emission.

A real epoch lasts I·6.65 s: 133 s now, and 6,650 s at I = 1,000.

| Deadline (nominal) | Clock | Real duration at I = 20 (today) | Real duration at I = 1,000 |
|---|---|---:|---:|
| Validator unbonding (21 d) | epoch × 60 | **46.5 d** | **6.37 yr** |
| Validator claim grace (31 d) | epoch × 60 | 68.7 d | 9.4 yr |
| Delegation unbonding (21 d) | +10 per epoch | **279 d** | **38.2 yr** |
| Commission-change delay (7 d) | +10 per epoch | 93 d | 12.7 yr |
| Governance timelock (24 h) | +10 per epoch | 13.3 d | 1.8 yr |
| Emission | per epoch | 1.90%/yr | 0.038%/yr |

The decoupling therefore must land together with the I change, in the same fresh genesis that G1 S11 and G3 S8 already require.

---

## (c) Comparison with production chains

| Chain | Committee / epoch | Stake-change latency | Reward cadence | Unbonding | Evidence vs unbonding | Trust anchor |
|---|---|---|---|---|---|---|
| **Ethereum** | 12 s slots, 32-slot (6.4 min) epochs. Sync committee of 512 frozen for 256 epochs (≈27.3 h). | Activation/exit at `epoch + 1 + MAX_SEED_LOOKAHEAD` (≥5 epochs ≈ 32 min), plus the churn queue. | Proposer and sync rewards **per slot**. Attestation rewards **per epoch** (`process_rewards_and_penalties`). | Withdrawable 256 epochs (≈27.3 h) after exit. Slashed: `EPOCHS_PER_SLASHINGS_VECTOR` = 8,192 epochs (≈36.4 d). | Slashable until withdrawable. | Weak-subjectivity period = `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` + churn term, 504–3,532 epochs in the spec table. |
| **Cosmos Hub / CometBFT** | No epochs. The set can change every block. | An update returned at H **takes effect at H+2**. | **Per block** (x/distribution in BeginBlock, F1 lazy withdraw). x/mint mints per block from `BlocksPerYear`. | 21 d (1,814,400 s). | Evidence expires only when older than *both* `max_age_duration` and `max_age_num_blocks`, which the Hub sets to 3 weeks. Unbonding entries begun after the infraction are slashed. Issue #6478 asks for unbonding to require both time and height too. | Light-client trusting period < unbonding. IBC recommends 2/3. |
| **Aptos** | **2 h** epochs, time-based: `block.move` compares the timestamp with the last reconfiguration time. | Next epoch. | **Per epoch**: rate × stake × (successful proposals / proposals). | 14-d recurring lockup. | No slashing implemented. | — |
| **Sui** | **≈24 h** epochs. "The Sui validator set and their stakes remain unchanged" within an epoch. Four-step reconfiguration (Sui Lutris). | Next epoch. | **Per epoch**, adjusted by the tallying rule. | None beyond the epoch boundary. | No principal slashing. Rewards are cut by the tallying rule. | Committee-signed checkpoints. |
| **Polkadot** | 4-h sessions (authority and GRANDPA set changes signalled on new session). 24-h **eras** (election and rewards). | 1–2 eras. | **Per era**, claimable for 84 eras. | 28 eras (28 d). RFC-0097 queue: 2–28 d. | `SlashDeferDuration` = 27 eras, below bonding of 28. RFC-0097: non-long-range-attack offences are "detected and slashed within 2 days". | Checkpoints no older than 28 d (RFC-0097). |
| **Solana** | 432,000-slot epochs (≈2–3 d). Leader schedule computed one epoch ahead. | Epoch boundary, with a warm-up/cool-down rate limit. | **Per epoch**, spread over the first blocks (SIMD-0118). | ≈1 epoch of cool-down. | No active slashing. SIMD-0204 and SIMD-0212 are in progress. | — |
| **AINCORE (recommended)** | **1,000 blocks ≈ 1.85 h**, frozen (G1). | ≤1.85 h (mean 55 min). | Emission every **20 blocks** (block-counted); fees per block. | **273,000 blocks ≈ 21 d**, from H_{E_leave}, slashable while unbonding. | W = U = 273,000 blocks. Retention ≥ 274 epochs. | Checkpoint ≤ 182,000 blocks (≈14 d), published at least weekly. |

**What the precedents say for AINCORE.**
1. **Rotation and rewards are decoupled almost everywhere.**
   - Ethereum rotates its light-client committee every 27 h but pays every slot or epoch.
   - Polkadot changes authority sets per 4-h session but pays per 24-h era.
   - Cosmos changes sets and pays every block.
   - Only Aptos, Sui and Solana tie both to one epoch, and they do it at 2 h to 3 d with 100+ validators and per-epoch performance accounting that AINCORE does not have.
2. **Epoch-based chains pick hours, not seconds.**
   - None rotates committees every 2 minutes. AINCORE's 133-s epoch is an outlier, and G1's V4 boundary cost makes it untenable (b.2).
   - The chains with 24-h epochs (Sui, Polkadot eras) have committees of about 100 or more. There, one validator abstaining costs a small fraction of the quorum margin. At n=4 it costs all of it, which is why AINCORE should sit at the short end (Aptos, 2 h).
3. **Every slashing chain sizes unbonding to the evidence window:**
   - Cosmos: evidence age = unbonding;
   - Polkadot: slash defer 27 < bonding 28;
   - Casper: ω > 4δ;
   - Ethereum: slashable until withdrawable.
   - AINCORE currently violates this in two places: F3 (unbonding stake is unslashable) and F4 (evidence is GC'd after about 3.5 d).
4. **Emission is counted in the chain's own clock:** Bitcoin by height, Cosmos by block via `BlocksPerYear`, Ethereum by epoch with fixed 12-s slots. Cosmos's `BlocksPerYear` is itself governable and drifts with block time (the Hub mints about 1.27× its target); see A1.

### Research basis

**Long-range attacks and weak subjectivity.**
- **Buterin (2014), "Proof of Stake: How I Learned to Love Weak Subjectivity".**
  - Once deposits are withdrawn, old keys can sign an alternative history for free.
  - The fix is a deposit lock plus a "revert limit", and nodes must obtain a recent checkpoint if they have been offline longer than the lock.
- **Casper FFG (Buterin and Griffith 2017, arXiv 1710.09437).**
  - §3: validators join or leave at dynasty d+2, and deposits stay locked for a withdrawal delay during which violations are still slashed.
  - §4.1: clients must "log on" regularly, and ω > 4δ guarantees that slashing lands in every chain a client accepts.
- **Deirmentzoglou, Papakyriakopoulos and Patsakis (IEEE Access 7, 2019, DOI 10.1109/ACCESS.2019.2901858).**
  - Taxonomy: simple attacks, posterior corruption, and stake bleeding (Gaži, Kiayias and Russell, ePrint 2018/248).
  - Countermeasures include moving checkpoints and key-evolving cryptography (Winkle, often cited alongside, is later work: Azouvi, Danezis and Nikolaenko, AFT 2020).
  - AINCORE's TA-0/TA-4 checkpoints are the "moving checkpoint" class. The unbonding lock is what bounds posterior corruption.
- **Ethereum weak-subjectivity spec.** The safe checkpoint age is the withdrawability delay plus a term that shrinks as churn grows (`SAFETY_DECAY` = 10%).
  - AINCORE has **no churn limit**: the whole committee can change in one epoch. For a permissioned launch this is controlled by the operator. It must be revisited before permissionless operation (d, R10).

**Reconfiguration of BFT and DAG systems.**
- **Lamport, Malkhi and Zhou, "Reconfiguring a State Machine" (MSR-TR-2008-193; SIGACT News 2010).**
  - A configuration change must be decided *in the sequence*. It takes effect α commands later, or behind a "stop sign".
  - CometBFT's H+2 and Casper's d+2 are α=2 instances. G1 EP-1 fixes the switch at H_E by arithmetic.
- **LibraBFT (Diem, 2020 report).**
  - "LibraBFT can reconfigure itself, by embedding configuration-change commands in the sequence."
  - The switch is a "stop the world and restart" operation, and the new epoch begins with an epoch-genesis block.
  - That is G1's `EPOCH_GENESIS` sentinel (EP-3). The model of trusting the next committee through the previous committee's certificate is G1 EP-4 and G3 TA-2/TA-3.
- **Sui Lutris (Blackshear et al., CCS 2024, arXiv 2310.18042) §4.2.**
  - Reconfiguration runs in four steps: stake recalculation, ready, end-of-epoch, handover.
  - Its evaluation ran an epoch change every 10 minutes and found performance "largely unaffected". This supports the view that boundaries are cheap if engineered, while AINCORE's B is still unmeasured.
  - It also names the gap between reconfigurations as the window for "the distribution of global incentives and rewards".
- **Mysticeti (arXiv 2310.14821).** "In each epoch, n = 3f + 1 validators", with static corruption of at most f per epoch. The fault bound is stated per frozen committee.
- **Aptos randomness (arXiv 2407.12172).** Per-epoch weighted DKG takes 16.8 s at mainnet scale, done asynchronously. This is an example of per-epoch setup cost that frozen committees make affordable.

**Why committees are frozen per epoch (synthesis).**
1. A quorum or certificate means something only relative to one known membership (Narwhal certificates; G1 Q_E, `qc.rs:194-196`). Mixing memberships inside a DAG round breaks quorum intersection.
2. The switch point must be agreed through the total order (Lamport, Malkhi and Zhou; LibraBFT; CometBFT H+2).
3. Leader schedules and per-epoch keys (Ethereum seed lookahead, Solana's leader schedule one epoch ahead, Aptos DKG) need a fixed set in advance.
4. Light clients verify one transition per epoch (Ethereum sync committee, Diem epoch-change proofs, G3 TA-3), so the epoch length is a direct cost knob.

The price of freezing is G1 Open question 8: misbehaviour is removed from consensus only at the boundary. This price is proportional to I, which is one of the two reasons for the upper bound.

**Slashing-evidence windows versus unbonding.**
- The consistent rule across Casper (ω > 4δ), CometBFT (evidence age = unbonding), Cosmos x/staking (post-infraction unbonding entries are slashable), Polkadot (defer 27 < bond 28) and Ethereum (slashable until withdrawable) is:
  > stake must remain slashable for the entire evidence window, and that window must run from the last moment the key could sign.
- Hence W ≤ U, with unbonding counted from H_{E_leave}. It also requires slashing the unbonding queue, not only the active set.

---

## (d) Risks and what would change the decision

1. **Block time at genesis differs from 6.65 s.** The TPS roadmap targets the 3 s tick.
   - At genesis, recompute:
     - I = max(1,000, 100·B_s/t_b), with I·t_b ≤ 7,200 s;
     - U = ceil(21 d / t_b / I)·I;
     - d_b from the calibration doc.
   - If t_b < 3.3 s, the "7-day checkpoint" rule must tighten. Below about 1–2 s, I = 1,000 costs more than 1% if B ≈ 10–20 s.
   - A drift of more than 20% after genesis should trigger the calibration doc's re-pin procedure for d_b and U. I is immutable and does not change.
2. **Measured boundary cost B (G1 S10).**
   - If B exceeds about 66 s at 6.65 s, overhead passes 1%.
   - Raise I only up to 2,000, which keeps observer pins and 3.7-h windows, and fix the boundary path first.
3. **Committee size.** At n=7 (f=2) one abstainer leaves slack, so longer epochs of 2,000–3,240 would be tolerable. I is immutable, though, and 1,000 costs only 0.15–0.3% at n=7. Keep 1,000 unless n ≥ 10 is certain at genesis.
4. **Faster removal of a proven equivocator.** Removal at H+2, as in Cosmos, would need an evidence-triggered early epoch end. That breaks E(h) = ⌊(h−1)/I⌋ and is a G1 amendment. It is not recommended. At I = 1,000 the exposure is ≤1.85 h and cannot break safety.
5. **Boundary code is the riskiest path.** FX-14 was a live halt at a boundary, and the abort-return at `executor lib.rs:1242-1248` is still present at this HEAD. I = 1,000 exercises it 13 times a day, which is good for finding bugs and bad if one ships. G1 S9 witnesses (a) to (k) and the unconditional rotation are prerequisites.
6. **BFT time.** The median-timestamp source exists at HEAD. Adopted by G5 amendment A1 as the capped clock τ.
7. **Delegation stream (DELEGATION_BPS > 0).** Per-block Δh accounting must feed the pool index (F1-style lazy accounting) before delegation is switched on.
8. **Governance could re-couple the clocks.** `governance.move:183-186` lets a proposal change `epoch_duration`. Remove it; neither I nor R should be governable.
9. **The emission rate itself.** This report fixes the *unit*. The *rate* is the founder's choice between 1.90%/yr (today's constants at 6.65 s) and 3.5%/yr (the calibration target). Either way it is set in blocks.
10. **Permissionless future.** Without a churn limit, the weak-subjectivity math assumes the operator controls churn. Add a per-epoch churn cap (as Ethereum does) before opening the validator set.
11. **Unverified.** B, the TA-3 entry size and the per-payout write counts are estimates. Nothing was compiled or run. The chain comparison reflects the documentation fetched on 2026-09-29. Polkadot's RFC-0097 rollout status is in flux.

**Findings from reading the code (existing defects, independent of the choice of I).**
- **F1.** Three clocks disagree. Validator unbonding is really 46.5 d, delegation unbonding 279 d, the commission delay 93 d and the governance timelock 13.3 d, at I = 20 and 6.65 s (b.8).
- **F2.** Emission at the measured 6.65 s is 1.90%/yr, not the calibrated 3.5% (b.7).
- **F3.** Unbonding stake cannot be slashed:
  - `slash_validator_bps` searches only `validators` (`staking.move:568-576`);
  - `verify_slash_evidence` rejects offenders missing from the live `sys:validators` (`executor lib.rs:2316-2318`).
  - With frozen committees, a validator can leave and then equivocate for up to I blocks with nothing at stake.
- **F4.** Equivocation evidence is garbage-collected after 100,000 rounds, about 3.5 d (`dag.rs:49`, `:2941-2958`). That is less than the 21-d unbonding.
- **F5.** An aborted `advance_epoch` loses that epoch's emission and skips rotation (`executor lib.rs:1242-1248`; FX-14 at this HEAD).
- **F6.** Emission and fees are paid to the live set (`staking.move:424-485`; `executor lib.rs:1434+` via `sys:validators`), not to the committee that did the work.
- **F7.** The public RPC and docs advertise a halving model that no code implements: 36 AIN halving every 2,102,400 blocks (`core/node/src/api_local.rs:1549-1563`, `:1701-1719`; `README.md:21, 41-42`; `WHITEPAPER.md:14, 91-100`; `CLAUDE.md:18`; `common/storage/src/lib.rs:845-851`). The deployed Move emission is a geometric drawdown with no halving (`staking.move:41-58`).
- **F8.** G3 TA-0 cites "21 days" of unbonding (`G3_STATE_AUTHENTICATION_CONTRACT.md:283`). Per F1 the real value is 46.5 d, and 6.4 yr if I is flipped alone.

---

## (e) Exact places that must change (not edited)

Everything below lands in the one fresh genesis that G1 S11 and G3 S8 already require. `genesis.json` edits require the founder's explicit confirmation (CLAUDE.md rule 1).

**Genesis, pins and boot**

| Place | Change |
|---|---|
| `genesis.json:11` (`epoch_duration: 10`, no `epoch_block_interval`) | Add `epoch_block_interval: 1000`, `reward_period_blocks: 20`, `unbonding_blocks: 273000` and the emission `draw_per_block` (the founder's rate). Drop `epoch_duration` once the Move clock is retired. **Founder confirmation required.** |
| `core/node/src/genesis.rs:25-28` (`DEFAULT_EPOCH_BLOCK_INTERVAL = 20`) | Change to 1000, or remove the default and require an explicit value. |
| `core/node/src/genesis.rs:604-611`, `:989-1005`, `:1120-1125` | Parse, validate and pin `reward_period_blocks` (with I mod R = 0) and `unbonding_blocks` next to the interval pin. |
| `core/node/src/genesis.rs:256-285` (`genesis_identity_hash`) | Fold the new pins into the identity, as the interval already is. |
| `core/node/src/genesis.rs:1168-1182` (Move `Epoch` init with `epoch_duration`) | Initialize `last_reward_height = 0` instead of the virtual-seconds clock. |
| `core/node/src/main.rs:327-345`, `:753-758` | Add the same "pinned or refuse to boot" check for R and U. |
| `common/state_commit/src/lib.rs:741-748` (`unwrap_or(20)`) | Change the fallback to 1000 or refuse, consistent with the boot check. `pin_schedule` (`:723-735`) needs no change for I = 1,000. |

**Executor (Rust)**

| Place | Change |
|---|---|
| `core/executor/src/lib.rs:1172-1175` (`DEFAULT_EPOCH_BLOCK_INTERVAL = 20`) | Change to 1000 and keep it matched with genesis. |
| `core/executor/src/lib.rs:1201-1271` (`maybe_advance_epoch`) | Split into two parts:<br>(i) `maybe_distribute_rewards(h)` at `h % R == 0`, calling Move with the **height as an argument** (today `args` carries only the 0x1 address, `:1224-1230`);<br>(ii) the committee boundary at `h % I == 0`.<br>Rotation must not depend on Move success (`:1242-1248`; FX-14, G1 EP-2). Give each part its own exactly-once guard (`sys:last_epoch_boundary`, `:1210-1220`, and a new `sys:last_reward_height`). |
| `core/executor/src/lib.rs:1283-1315` (`rotate_validator_epoch`, `EPOCH_SNAPSHOT_RETENTION = 8` at `:1306`) | Superseded by G1 EP-1/EP-2 consensus-owned rows that are never deleted. Until then, 8 epochs = 14.8 h at I = 1,000, which is fine. |
| `core/executor/src/lib.rs:1324-1354` (`on_chain_epoch_clock_secs`, `drive_governance`) | Drive governance by **height**. Run it at reward-period heights (every R) or every block, not only at committee boundaries. |
| `core/executor/src/lib.rs:2082` (call site) | Call both new hooks in the order given in b.6. |
| `core/executor/src/lib.rs:2304-2330` (`verify_slash_evidence`, offender check at `:2316-2318`, key via `get_object` at `:2319-2323`) | Check membership and key against **C_{E(round)}** (G1 EQ-1), not the live set. Add the maximum age h_ev − h_i ≤ U. |
| `core/executor/src/lib.rs:2431-2491` (`execute_one_slash`) | Also slash the offender's **unbonding** entries created after the infraction height (Cosmos rule). |
| `core/executor/src/lib.rs:1419-1500` (`compute_block_payouts`, fees over `sys:validators`) | Pay C_{E(h)}, excluding jailed members (G5 consistency). |
| `core/executor/src/lib.rs:3990-4060`, `:7298-7330`; `core/executor/src/block_crash_tests.rs:51`; `core/node/src/main.rs:1704-1715` | Update the tests that pin 20. Add witnesses:<br>- the emission curve is identical for R ∈ {1, 20} and I ∈ {20, 1000};<br>- an aborted payout is caught up;<br>- unbonding completes exactly U blocks after H_{E_leave}. |

**Consensus**

| Place | Change |
|---|---|
| `consensus/consensus/src/dag.rs:49` (`EQUIV_EVIDENCE_RETENTION_ROUNDS = 100_000`) and `:2941-2958` (GC) | Retain evidence for at least U: GC by epoch at 274 epochs, with G1's epoch-bearing key, or ≥ 700,000 rounds as a stopgap. |
| `consensus/consensus/src/qc_producer.rs:130-157` (`epoch_for_block_height` via executor rows) | Replace with the pure E(h) = ⌊(h−1)/I⌋ (G1 EP-1). |
| `consensus/consensus/src/local_acceptance_tests.rs:13`, `qc_epoch_height_tests.rs:150`, `dag.rs:3401-3407` | Test pins. Review them when the defaults change. |

**Move stdlib**

| Place | Change |
|---|---|
| `core/vm_move/stdlib/sources/epoch.move:12-16`, `:22`, `:26-50`, `:52-59`, `:65-68` | Replace the `epoch_duration` virtual-seconds accumulator with `last_reward_height`. Take `height: u64` in the system entry. Remove `update_epoch_duration`. Rename the concept to "reward period" so it is not confused with the consensus epoch. |
| `core/vm_move/stdlib/sources/staking.move:57-58`, `:400` (`DRAW_NUM/DRAW_DEN` per epoch) | Compute a per-block draw: `e = remaining · D_NUM · Δh / 10¹²`, with a clamped Δh. D_NUM = 4,050 keeps today's curve; ≈7,508 gives 3.5%/yr at 6.65 s (founder's choice; bounded parameter per the calibration doc). |
| `staking.move:82` (`EPOCH_SECONDS = 60`), `:86` (`UNBONDING_PERIOD` in seconds) | Replace with `UNBONDING_BLOCKS` (273,000, genesis-derived). |
| `staking.move:239-240` (`leave_validator_set`, unlock time), `:607-608` (slash remainder) | Set `unlock_height = H_{E(h)} + UNBONDING_BLOCKS`, counted from the end of the leaver's last committee epoch. |
| `staking.move:255-301` (`cleanup_old_unbonding`, `:267`, 31-d grace at `:270`), `:304-333` (`withdraw_unbonded`, `:307`, `:317`) | Compare heights. The grace becomes about 403,000 blocks (31 d at 6.65 s), or is re-derived at genesis. |
| `staking.move:366-487` (`distribute_rewards`, `current_epoch++` at `:384`, live-set loop at `:424-485`) | Pay by Δh. Weight by the committee C_E, passed in by the executor or mirrored in Move. Skip jailed members. |
| `staking.move:550-616` (`slash_validator_bps`; `:568-576` searches only `validators`) | Also slash matching `unbonding_queue` entries with `unlock_height` after the infraction. Credit the burn ledger as the active-stake path does. |
| `staking.move:159-164` (`get_current_epoch`), `universal_mining.move:275-276`, `:300-310` | The per-device limit becomes "once per reward period". State this explicitly (R = 20 keeps today's behaviour). |
| `core/vm_move/stdlib/sources/delegation.move:46`, `:49`, `:249-254`, `:263`, `:344-348`, `:356` | Replace `epoch::now_seconds()` deadlines with heights: `UNBONDING_BLOCKS`, and commission delay = 7 d in blocks (≈90,947). |
| `core/vm_move/stdlib/sources/governance.move:183-186` (`action_type 1 → update_epoch_duration`) | Remove, so the clocks cannot be re-coupled through governance. |

**Governance crate, RPC and docs**

| Place | Change |
|---|---|
| `governance/governance/src/lib.rs:336` (`end_time = now + duration_seconds`), `:442` (`TIMELOCK_DELAY = 86400`), `:732` (`process_due_proposals(now_secs, …)`) | Heights instead of virtual seconds, e.g. a timelock of 12,993 blocks for 24 h. |
| `core/node/src/api_local.rs:1549-1563`, `:1701-1719`; `common/storage/src/lib.rs:845-851` | Stop reporting a halving that does not exist. Report the per-block draw, `last_reward_height` and the realized rate. |
| `README.md:21`, `:41-42`; `WHITEPAPER.md:14`, `:91-100`; `CLAUDE.md:18` | Correct the emission description. Public claims must match the code (F7). |
| `docs/G1_CONSENSUS_CONTRACT.md:231`, `:875-878` (Open question 2) | Record I = 1,000 and the separate R = 20 reward period, with this report's derivation. |
| `docs/G3_STATE_AUTHENTICATION_CONTRACT.md:280-290` (TA-0) | U = 273,000 blocks from H_{E_leave}. Checkpoint maximum age 2/3·U = 182,000 blocks. Weekly publication. |

---

## Sources (primary, fetched 2026-09-29)

**Ethereum**
- Consensus specs, phase0 beacon chain (`SLOTS_PER_EPOCH`, `MAX_SEED_LOOKAHEAD`, `MIN_VALIDATOR_WITHDRAWABILITY_DELAY`, `EPOCHS_PER_SLASHINGS_VECTOR`, `compute_activation_exit_epoch`, `slash_validator`): https://ethereum.github.io/consensus-specs/specs/phase0/beacon-chain/
- Altair (sync committee 256 epochs, per-slot sync rewards, per-block proposer rewards): https://ethereum.github.io/consensus-specs/specs/altair/beacon-chain/
- Weak subjectivity spec: https://ethereum.github.io/consensus-specs/specs/phase0/weak-subjectivity/
- Asgaonkar, "Weak Subjectivity in Eth2.0": https://notes.ethereum.org/@adiasg/weak-subjectvity-eth2
- Buterin (2014), "Proof of Stake: How I Learned to Love Weak Subjectivity": https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity
- Buterin and Griffith (2017), "Casper the Friendly Finality Gadget", §3 and §4.1: https://arxiv.org/abs/1710.09437

**Long-range attacks**
- Deirmentzoglou, Papakyriakopoulos and Patsakis (2019), "A Survey on Long-Range Attacks for Proof of Stake Protocols", IEEE Access 7:28712-28725: https://ieeexplore.ieee.org/document/8653269 (DOI 10.1109/ACCESS.2019.2901858); also https://www.researchgate.net/publication/331313599_A_Survey_on_Long-Range_Attacks_for_Proof_of_Stake_Protocols
- Gaži, Kiayias and Russell (2018), "Stake-Bleeding Attacks on Proof-of-Stake Blockchains": https://eprint.iacr.org/2018/248.pdf

**Cosmos / CometBFT**
- CometBFT ABCI++ methods (validator updates at H+2): https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/spec/abci/abci++_methods.md
- CometBFT EvidenceParams: https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/spec/core/data_structures.md
- CometBFT evidence expiry (AND of time and blocks): https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/evidence/verify.go
- CometBFT light client (trusting period < unbonding): https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/spec/light-client/verification/verification_001_published.md
- Cosmos SDK x/distribution: https://raw.githubusercontent.com/cosmos/cosmos-sdk/main/x/distribution/README.md
- Cosmos SDK x/staking: https://raw.githubusercontent.com/cosmos/cosmos-sdk/main/x/staking/README.md
- Cosmos SDK x/mint: https://raw.githubusercontent.com/cosmos/cosmos-sdk/main/x/mint/README.md
- Cosmos SDK issue #6478 (unbonding by height and time): https://github.com/cosmos/cosmos-sdk/issues/6478
- Cosmos Hub parameters: https://github.com/cosmos/mainnet/blob/master/params/README.md
- IBC ADR-026 (trusting period = 2/3 of unbonding): https://docs.cosmos.network/ibc/latest/architecture/adr-026-ibc-client-recovery-mechanisms

**Aptos**
- Staking docs: https://aptos.dev/network/blockchain/staking
- `block.move` (time-based `epoch_interval`): https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/sources/block.move
- "The Latency Price of Threshold Cryptosystem in Blockchains" (per-epoch DKG 16.8 s): https://arxiv.org/pdf/2407.12172

**Sui**
- Epochs and reconfiguration: https://docs.sui.io/develop/sui-architecture/epochs
- Staking and unstaking: https://docs.sui.io/concepts/tokenomics/staking-unstaking
- Tokenomics paper (tallying rule): https://docs.sui.io/paper/tokenomics.pdf
- Validator rewards: https://docs.sui.io/operators/validator/validator-rewards
- Blackshear et al., "Sui Lutris" (CCS 2024), §4.2: https://arxiv.org/abs/2310.18042

**Polkadot**
- Staking (eras, sessions, rewards, unbonding rationale): https://wiki.polkadot.com/learn/learn-staking/
- Chain state values: https://wiki.polkadot.com/general/chain-state-values/
- Polkadot runtime (`SessionsPerEra`, `BondingDuration` = 28, `SlashDeferDuration` = 27): https://github.com/paritytech/polkadot/blob/153543b0c8c582e73f520e5c08cbe33bddfb5f69/runtime/polkadot/src/lib.rs
- `pallet_grandpa` (`schedule_change`, `on_new_session`): https://github.com/paritytech/substrate/blob/master/frame/grandpa/src/lib.rs
- RFC-0097 (unbonding queue, 2–28 d): https://polkadot-fellows.github.io/RFCs/approved/0097-unbonding_queue.html
- Forum thread on shortened unbonding: https://forum.polkadot.network/t/security-risks-of-reducing-polkadots-unbonding-period-to-24-48-hours/17130
- Stewart and Kokoris-Kogias, "GRANDPA: a Byzantine Finality Gadget": https://arxiv.org/abs/2007.01560

**Solana**
- Epoch schedule constants: https://raw.githubusercontent.com/anza-xyz/solana-sdk/master/epoch-schedule/src/lib.rs
- SIMD-0118 (partitioned epoch rewards): https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0118-partitioned-epoch-reward-distribution.md
- SIMD-0204 (slashable event verification): https://github.com/solana-foundation/solana-improvement-documents/pull/204
- Anza on SIMD-0204: https://www.anza.xyz/blog/simd-0204-the-first-step-to-slashing-on-solana

**Bitcoin**
- `GetBlockSubsidy` (halving by height): https://github.com/bitcoin/bitcoin/blob/master/src/validation.cpp

**BFT and DAG reconfiguration**
- Lamport, Malkhi and Zhou, "Reconfiguring a State Machine": https://www.microsoft.com/en-us/research/publication/reconfiguring-a-state-machine/
- LibraBFT, "State Machine Replication in the Libra Blockchain" (2020), epoch changes: https://developers.diem.com/papers/diem-consensus-state-machine-replication-in-the-diem-blockchain/2020-05-26.pdf
- Narwhal and Tusk: https://arxiv.org/abs/2105.11827
- Bullshark: https://arxiv.org/abs/2201.05677
- Mysticeti (fixed committee per epoch): https://arxiv.org/abs/2310.14821
