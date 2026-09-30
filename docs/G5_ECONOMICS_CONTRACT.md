# G5: staking, rewards and clocks (contract)

- **Date:** 2026-09-30. Branch `g1/certified-dag` (after G1 S11a, `bf151f8`).
- **Basis:** `docs/research/epoch_and_rewards.md` (derivations, production precedents,
  findings F1–F8), `docs/research/emission_rate_decision.md` (1.90 %/yr), the G1 and G3
  contracts. Every number below is derived there, from the measured block time, or from a
  production chain; none is a guess.
- **Ships with:** the one fresh genesis (G1 S11, G3 S8). Nothing here is deployed to the
  running V3 chain.

## Why

Today:
- three clocks disagree, so the advertised deadlines are wrong. Delegation unbonding is
  279 days, not 21 (F1);
- emission is counted per 20-block epoch, so any epoch change moves the curve, and
  G1's I = 1,000 would cut emission 50× (b.8);
- stake that is unbonding cannot be slashed, and evidence is deleted after about 3.5
  days, so a leaver can equivocate for free (F3, F4);
- rewards are paid to the live validator set, not to the committee that did the work (F6);
- delegation pays nothing: `DELEGATION_BPS = 0` and its payout function has no caller, so
  staking through the app is empty;
- the RPC and docs advertise a halving that no code implements (F7).

## Rules

**CL-1 (one clock).** Every protocol deadline counts **block heights**: unbonding, the claim
grace, the commission delay, governance voting and timelock, the evidence window and
emission. The Move virtual-seconds clocks (`epoch.move` `epoch_duration`, staking
`EPOCH_SECONDS`) are retired. A halted chain ages nothing (research b.5, Cosmos SDK #6478).

**CL-2 (the executor passes the height).** Every system entry that needs time (reward
payout, epoch boundary, governance driver) takes the block height as an argument, bound by
the block being executed.

**P-1 (parameters).** Genesis pins, and the genesis identity binds:

| Name | Value | Derivation |
|---|---|---|
| I, committee epoch | 1,000 blocks | research (a) 1 and b.2: boundary overhead ≤ 1 % gives I ≥ 1,000; exposure windows ≤ 2 h give I ≤ 1,083 at 6.65 s |
| R, reward period | 20 blocks | research (a) 2 and b.6: today's cadence, I mod R = 0 |
| U, unbonding | ⌈21 d / t_b / I⌉ · I | research b.5; 273,000 at 6.65 s |
| W, evidence max age | U | research b.5: W ≤ U is the slashability condition |
| G, claim grace | ⌈31 d / t_b⌉ | today's 31 days, in blocks |
| C, commission notice | ⌈7 d / t_b⌉ | today's 7 days, in blocks |
| T, governance timelock | ⌈24 h / t_b⌉ | today's 24 hours, in blocks |
| d_b, emission draw per block | −ln(1 − 0.019) / (365.25 d / t_b) | emission decision: 1.90 %/yr of the remaining reserve |

t_b is the block time measured at genesis (6.65 s today). `genesis-tool` derives the
table from one input, `block_time_ms`, and writes the values into genesis.json. The node
re-derives nothing at run time. I, R, U and d_b are immutable; nothing governable touches
them (the governance action `update_epoch_duration` is removed).

**EM-1 (emission by height).** At a payout height h (h mod R = 0) the executor mints
`e = remaining · D_NUM · Δh / 10¹²`, with `Δh = h − last_reward_height`, clamped to
[1, 4·I], and `D_NUM = round(d_b · 10¹²)`. `last_reward_height` is state. Payouts
telescope, so cumulative emission depends on h only; a payout skipped by a Move abort is
caught up at the next one (research b.7). Rounding stays below 2·10⁻⁶ relative at the clamp.

**EM-2 (recipients).** A payout at h pays the members of the frozen committee C_{E(h)}
(G1 EP-2), not the live set. Jailed members are excluded. Weights are the committee stake
with today's saturation clip (1/50 of the total). Per-block fees go to the same committee
(research b.6).

**EM-3 (order inside a boundary block H_E).** First the reward payout for (H_E − R, H_E] to
C_E, then EP-2's derivation of C_{E+1} from the post-state, then the start of unbonding for
members that leave at H_E.

**DL-1 (bonded stake).** A validator's bonded stake is its own stake plus its pool's
delegated stake. `sys:validator_set:v1` carries it, so the committee weight (G1 EP-2) is
the bonded stake. It changes when a delegation or undelegation executes and takes effect at
the next epoch.

**DL-2 (delegator rewards, F1 lazy accounting).** A validator's reward r (EM-2, computed on
bonded stake) splits into:
- the self share, r · self / bonded, to the validator;
- the delegated share, r · delegated / bonded, from which the pool's commission goes to
  the validator and the rest raises `accumulated_rewards_per_share`.

A delegator's pending reward is `amount · acc / 10¹⁸ − reward_debt`, as the pool already
computes. The delegation reward is minted inside the same cap as all emission; the separate
`DELEGATION_BPS` stream and its unpaid budget are removed.

**SL-1 (slashable while unbonding).** Unbonding entries, the validator's and its pool's
delegators', stay slashable until they are withdrawn. A slash for an infraction at height
h_i reduces every entry whose unbonding began at or after h_i, and the bonded stake (the
Cosmos rule, research b.5 and (c)).

**SL-2 (unbonding starts at the end of the last committee epoch).** A validator that leaves
at height h unlocks at `H_{E(h)} + U`, since it keeps signing until H_{E(h)}. A delegator
that undelegates at h unlocks at `H_{E(h)} + U` for the same reason: its stake weighted the
committee until then.

**SL-3 (evidence).** Equivocation evidence is V4 (G1 EQ-1): two V4-hashed vertices, or two
attestations, of one slot, signed by a member of C_{E(slot)}. It is carried through the DAG
(`SLASH_EVIDENCE:`), verified against C_{E(slot)} rather than the live set, refused when
older than W, and applied 100 %. Evidence rows are kept for W, keyed by epoch. The V3
evidence path and the V3 DAG code are deleted with it (G1 S11b part 2).

**DOC-1 (honest claims).** The RPC and every public document describe the per-block draw on
the remaining reserve, report `last_reward_height`, the realized rate and the remaining
reserve, and name no halving.

## Stages

Each stage lands with its witnesses and a mutation run; one independent review runs at the
end of G5, as with G1.

| Stage | Content | Witnesses | Kill list |
|---|---|---|---|
| **S1** | CL-1, CL-2, P-1: heights everywhere in Move (`epoch`, `staking`, `delegation`, `governance`, `universal_mining`), the governance crate, genesis pins and genesis-tool derivation, the executor passes h | every deadline expires exactly at its height; a halt ages nothing; the pins are bound by the identity; genesis-tool reproduces the table from `block_time_ms` | a deadline in seconds; an unpinned parameter; governance able to change I, R or d_b |
| **S2** | EM-1..EM-3: payouts every R blocks by Δh, abort catch-up, committee recipients, fees to the committee, boundary order, I = 1,000 | the emission curve is identical for R ∈ {1, 20} and I ∈ {20, 1,000}; an aborted payout is paid at the next; a joiner is paid from its first committee epoch and a leaver until its last; a jailed member gets nothing | Δh ignored; the live set paid; the clamp removed; payout after derivation at H_E |
| **S3** | DL-1, DL-2: bonded stake in the committee weight; delegator rewards through the pool; commission by height | a delegator earns its share of the pool's reward minus commission, to the unit; delegating shifts committee weight at the next epoch only; the sum paid never exceeds e; total supply stays within MAX_SUPPLY | delegated stake ignored in weight; commission not taken; `reward_debt` not updated |
| **S4** | SL-1..SL-3: unbonding slashable, unlock from H_{E(h)}, V4 evidence (EQ-1) through the DAG, W, V3 deletion | a leaver that equivocates before its unlock loses its unbonding stake; an undelegation after the infraction is slashed and one before it is not; evidence older than W is refused; a V4 node never records V3 evidence (kept from S11b) | only active stake slashed; live-set membership check; no age bound |
| **S5** | DOC-1: RPC fields, README, WHITEPAPER, CLAUDE.md | the RPC reports the Move state; no document names a halving (a grep witness) | — |
| **S6** | The fresh genesis file from genesis-tool, shown to the founder before it is used | the genesis identity changes with each pinned parameter | — |

## Open (to measure, not to guess)

- **t_b at genesis.** V4's block time is not measured yet. The table is derived from the
  value measured on the release candidate, never from today's 6.65 s by default.
- **Boundary cost B** (research b.2): measured in the G1 S10 harness on real hardware before
  genesis. If B exceeds about 66 s at 6.65 s, fix the boundary path before raising I.
- **Churn limit:** needed before the validator set opens (research (d) 10). Not needed at the
  permissioned launch, where the operator controls churn.
