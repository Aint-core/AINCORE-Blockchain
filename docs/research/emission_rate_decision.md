# Emission rate decision: 1.90%/yr of remaining reserve (2026-09-30)

**Decision (founder, working):** 1.90%/yr of the remaining reserve, pinned **per block** at
the block time measured at genesis (`epoch_and_rewards.md` b.7), not per epoch.

> **Corrected (2026-09-30 source check).**
> - The rule "5% only with delegation, 3.5% otherwise, err low, per Uribe" has no external
>   source. It is the internal calibration doc's synthesis. Uribe (1997) models currency
>   substitution and prescribes no emission rate.
> - "Cuts fail" is wrong: Cosmos Hub Proposal 848 cut maximum inflation from 20% to 10%
>   and passed (2023-11-25). "No chain has raised emission" is unsourced.
> - "Commission typically 5–10%" is unsourced. For reference, the Hub's minimum commission
>   is 5%.
> - Year-1 emission here (2.77M) uses a 146M reserve base, and `epoch_and_rewards.md`
>   (2.86M) uses 150M. The rate (1.90%/yr of the remaining reserve) is the same.
> - Emission is now counted by consensus time, not per block (G5 amendment A1), so the rate
>   no longer depends on the block time.
> - The decision (1.90%/yr) stands. It rests on the re-run model below, not on the
>   unsourced sentences.

## Why the number moved
`DRAW_NUM = 81` per 20-block epoch was calibrated at 3.59 s blocks (3.5%/yr,
`docs/AINCORE_EMISSION_CALIBRATION.md` candidate B). Blocks are measured at 6.65 s now, so
the same constant gives 1.90%/yr. Keeping 1.90% makes the per-block draw
`d_b = −ln(1 − 0.019) / blocks_per_year`, re-derived from the genesis block time.

## Conditions that changed since the calibration
- No USD-side DEX funding ($50k was the calibration's floor). That floor came from
  **forced** fiat selling by outside validators paying servers: required depth ≈ 50 × monthly
  forced extraction. At launch every validator is the founder's own and the founder restakes,
  so forced extraction ≈ 0.
- Participation is expected mostly through **app delegation**, not new nodes: no server
  costs, and delegated stake is locked (21-day unbonding), which shrinks the sellable float.

## Re-run of the model under today's assumptions (`emission_rate_check.py`)
Cap 150M, DEX seed 1M, founder bootstrap stake 3M, 6.65 s blocks. Threshold: sold rewards
≥ 100% of the float per year (the reflexivity line of the calibration report, section 3).

| Year 1 | 1.9% | 3.5% |
|---|---|---|
| Emission | 2.77M | 5.11M |
| Founder only, restakes all | 0% of float sold | 0% |
| Founder 80% of stake, others sell 50% | 28% | 51% |
| Founder 80%, others sell 100% | 56% | **102%** |
| App delegation grows (founder 50%), others sell 50% | 69% | **128%** |
| One week of sold emission dumped at once (worst case) | −2.6% | −4.7% |
| Cap distributed by year 10 / 30 | 20% / 45% | 32% / 67% |

1.9% stays below the line in every scenario; 3.5% crosses it in two. This matches the
literature's conditional rule (calibration report 9.3: 5% only with delegation at genesis and
a much larger float, 3.5% otherwise, err low when unsure, per Uribe) and the chain evidence
(launch at the rate you keep; no chain has raised emission, and cuts fail).

## Consequences to carry out
- Genesis (G1 S11): per-block draw for 1.90% at the measured block time; emission counted in
  blocks.
- Correct public claims: the README/whitepaper "halving of 36 AIN every 2,102,400 blocks" is
  not implemented (`epoch_and_rewards.md` F7).
- Before app staking (G5): turn on the delegation share (`DELEGATION_BPS` is 0), fix the
  delegation unbonding clock (~279 d today), make unbonding stake slashable, and build the
  staking flow in the SDK. The validator commission (typically 5–10%) is a founder business
  decision.
