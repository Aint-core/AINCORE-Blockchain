# G5: staking, rewards and clocks (contract)

- **Date:** 2026-09-30. Branch `g1/certified-dag` (after G1 S11a, `bf151f8`).
- **Basis:** `docs/research/epoch_and_rewards.md` (derivations, production precedents,
  findings F1–F8), `docs/research/emission_rate_decision.md` (1.90 %/yr),
  `docs/research/clock_and_deadlines.md` (amendment A1: the clock, unbonding, commission
  and unclaimed stake, with every source), the G1 and G3 contracts. Every number below is
  derived there, from the measured block time, or from a production chain; none is a guess.
- **Amendment A1 (2026-09-30, after S1 `65cc92a`).** S1 counted every deadline in block
  heights. That is exact only while the real block time equals the one measured at genesis:
  at 1 s blocks, 21 days of blocks would last 3.2 days and emission would run at 12 %/yr.
  Nothing enforces a block time (the round timer is a node setting), and both Cosmos (x/mint
  `BlocksPerYear`, re-pinned twice by governance) and this project (3.59 s assumed, 6.65 s
  real) have shipped that drift. A1 moves deadlines and emission to a capped consensus-time
  clock (CL-1), removes the claim grace and its burn (UB-1), and fixes the commission rule
  (CM-1). Heights stay the unit of the committee epoch and the reward period.
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
- the RPC and docs advertise a halving that no code implements (F7);
- unclaimed validator stake is burned 31 days after unlock, which no production chain does
  (A1);
- a matured commission increase stays armed and can be applied weeks later without new
  notice (A1).

## Rules

**CL-1 (one clock: capped consensus time).** Every economic deadline and the emission count
τ, the chain's consensus time in seconds:

> τ(0) = 0, and τ(h) = τ(h−1) + min(T(h) − T(h−1), C_τ)

where T(h) is the block's BT-1 timestamp and C_τ the per-block cap (P-1). The height stays
the unit of the committee epoch I and the reward period R (G1 EP-1 is height arithmetic).
Properties (clock research §5):
- blocks faster than C_τ: τ advances at the real-time rate, so every deadline and the
  emission rate hold in real time at any block speed;
- blocks slower than C_τ, and halts: τ advances at most C_τ per block. A halt of any length
  ages every deadline by at most C_τ ("a halt ages nothing"); slower blocks only lengthen
  deadlines and lower emission, the safe direction;
- a corrupted median (Byzantine stake above 1/3, or most honest clocks shifted) still
  advances τ by at most C_τ per block: a deadline D cannot pass in fewer than D / C_τ blocks,
  which is Cosmos SDK #6478's "height and time" with a height floor, and emission cannot
  exceed C_τ / t_b times its target.

The Move virtual-seconds clocks (`epoch.move` `epoch_duration`, staking `EPOCH_SECONDS`)
are retired.

**BT-1 (block timestamp).** T(h) is the stake-weighted median of one signed vertex timestamp
per committee member among the anchor's committed vertices, clamped to be monotone (CometBFT
BFT Time; Bullshark Algorithm 6; Sui's commit timestamp). If the sampled members do not
carry a quorum of the committee's stake (3·S ≤ 2·total), T(h) = T(h−1): with Byzantine
stake below 1/3 the sample is then more than half honest, so the median lies between honest
values. The existing ingress gate drops vertices timestamped more than 30 s ahead.
Validators run authenticated time (NTS or several independent sources) and alarm when the
tip's T drifts from local time by more than 60 s: NTP alone can be shifted by an attacker.

**CL-2 (the executor writes the clock).** Before any transaction of block h the executor
writes `0x1::chain::Clock { height: h, time: τ(h), block_timestamp: T(h) }`, computed from
the previous Clock, T(h) and C_τ. Nothing in Move writes it. A chain without `Params` (only
a test fixture: boot refuses one) has a frozen clock.

**GV-1 (one governance path).** Governance is Move transactions only. The Rust
`governance` crate's proposal path is removed from the executor (`drive_governance`) and
from the RPC. It created proposals from one node's RPC with that node's wall clock
(`SystemTime::now()`), so deadlines differed per node, and executing such a proposal would
change state on only some nodes. G3's write gate already refuses those RPC writes on the
new chain, so the path is dead there; it is deleted, not converted. Move governance loses
`update_epoch_duration` (see P-1) and keeps signalling proposals. It has no voting period and
no timelock (the 24-hour timelock was the Rust crate's), so it has no parameter: a pinned
value nothing reads is dead state. At the permissioned launch, parameters change by
software upgrade.

**P-1 (parameters).** Two kinds, both immutable after genesis:

*Genesis pins* (`0x1::chain::Params`, bound by the genesis identity), derived by
`genesis-tool` from one input, the V4 block time t_b measured on the release candidate
(`--block-time-ms` is required and has no default):

| Name | Value | Derivation |
|---|---|---|
| I, committee epoch | 1,000 blocks (20 until S2) | research (a) 1 and b.2: boundary overhead ≤ 1 % gives I ≥ 1,000; exposure ≤ 2 h gives I ≤ 1,083 at 6.65 s. With wall-clock boundary cost ≤ 10 s, I = 1,000 meets both for t_b ∈ [1.0 s, 7.2 s] (clock research §4) |
| R, reward period | 20 blocks | research (a) 2 and b.6: I mod R = 0 |
| C_τ, clock cap per block | ⌈2·t_b⌉ s (14 s at 6.65 s) | k = 2 (clock research §5.2): above the normal spread of block intervals, and bounds a corrupted clock to 2× |

*Stdlib constants* (durations; bound by the stdlib hash that genesis pins):

| Name | Value | Derivation |
|---|---|---|
| U, unbonding | 21 d | U ≥ T_trust + T_mis (clock research §3.2). T_trust = 14 d: the longest halt so far was 10 days, checkpoints are weekly, and bridge light clients trust for 2/3·U (IBC ADR-026). T_mis = 7 d to detect misbehaviour and land evidence |
| W, evidence max age | U | research b.5: W ≤ U is the slashability condition |
| N, commission notice | 7 d | the delegator's reaction time. Precedents: Solana ≥ 1 epoch (~2 d), Cardano 5 d, Aptos 3.5–14 d. AINCORE has no redelegation and serves app users, so it sits at the protective end (commission research §4.1) |
| Δc, commission increase per notice | 500 bps | Aptos +10 pp per lockup, Cosmos `max_change_rate`, Polkadot pools. A delegator locked in by U tolerates about (1−c)·U/T before leaving (Farrell–Klemperer switching cost): 5.5 pp for a one-year delegator |
| λ, emission | −ln(1 − 0.019) per year | emission decision: 1.90 %/yr of the remaining reserve |
| K, payouts per boundary | 256 | UB-1; a bounded sweep, as Ethereum's withdrawals |

The claim grace G is removed (UB-1). Nothing governable touches any of these: the governance
action `update_epoch_duration` is removed. Clients offline for more than 14 days must boot
from a checkpoint; checkpoints are published at least weekly.

**EM-1 (emission by consensus time).** At a payout height h (h mod R = 0) Move mints
`e = remaining · λ · Δτ` (`staking::pay_rewards`), with `Δτ` the consensus time since the
last payout (state: `EmissionState.last_reward_time`). Integer form:
`e = (remaining / 10⁹) · Λ · Δτ / 10⁹`, with `Λ = 607,866,866` (λ in 10⁻¹⁸ per second,
realizing 1.9000 %/yr) and `Δτ` capped at one day per payout; the excess of a longer gap
stays in the reserve. Bounds:
- the product stays below 8·10³⁰, far inside u128;
- the linear form's error is under λ·Δτ/2 (4·10⁻⁸ at a 133 s payout, 2.7·10⁻⁵ at the cap);
- truncating `remaining` to 10⁹ base units loses under 10⁻⁹ AIN.

Payouts telescope, so cumulative emission depends on τ only, not on R, I or the block time.
A payout that aborts writes nothing, so the next one covers its time (research b.7). A halt
mints at most C_τ of emission.

**EM-2 (recipients).** A payout at h pays the members of the frozen committee C_{E(h)}
(G1 EP-2), not the live set.
- **Weights and exclusions.** Jailed members are excluded. Weights are the committee stake,
  in whole AIN, with today's saturation clip (1/50 of the total).
- **Fees.** Per-block fees go to the same committee, split as today: 20 % to the anchor
  leader, 80 % by committee stake (research b.6).
- **The committee record.** The executor records each committee in state as
  `sys:validator_set:epoch:{E}` at H_{E−1}; epoch 0 uses the genesis committee.
- **One rule for both sides.** The executor applies the same rule consensus uses (EP-2's
  `validate_committee` and its fallback to C_E, one definition in
  `blockchain::committee`). Consensus refuses a boundary block whose derived committee
  differs from the recorded one, so economics and consensus cannot disagree on who the
  committee is.

**EM-3 (order inside a boundary block H_E).** First the reward payout for (H_E − R, H_E] to
C_E, then EP-2's derivation of C_{E+1} from the post-state, then the start of unbonding for
members that leave at H_E. The derivation does not depend on Move's `advance_epoch`
succeeding (FX-14): an aborted epoch advance still records the next committee. The Move
epoch counter (`staking.current_epoch`, which `universal_mining` uses to limit DePIN
payouts) advances at committee boundaries.

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

**DL-3 (delegator unbonding queue, S3).** A pool's unbonding is kept in buckets by unlock
time, with pooled balances (Polkadot nomination pools' era buckets), and a per-delegator cap
(Cosmos `MaxEntries` = 7). Matured buckets are paid automatically as in UB-1. Today one
global cap of 100 entries per pool, emptied only by each delegator's own withdrawal, lets
anyone with 100 AIN stop every undelegation from that pool.

**CM-1 (commission).** A pool has at most one pending change. An increase may raise the rate
by at most Δc over the rate in force, to at most 30 %, and takes effect at τ ≥ announce + N,
fixed when announced; it applies to reward periods that start at or after that time. It is
applied on the pool's next use; there is no manual apply, so a matured change cannot be held
back and fired later. A new announcement replaces the pending one. A decrease takes effect
at once and cancels a pending increase (Cosmos, Polkadot pools, Solana SIMD-0079).

**UB-1 (unbonded stake is paid, never burned).** At each committee-epoch boundary the system
pays up to K matured entries from the head of the validator unbonding queue, which is sorted
by unlock time; the rest wait for the next boundary. `withdraw_unbonded` stays as the
immediate manual path. No production chain examined burns unclaimed principal (Cosmos and
Ethereum pay automatically; Polkadot, Aptos, Solana and NEAR keep it), and the burn had no
security role once the stake unlocked.

**SL-1 (slashable while unbonding).** Unbonding entries, the validator's and its pool's
delegators', stay slashable until they are paid. A slash for an infraction at height h_i
reduces every entry whose unbonding began at or after h_i, and the bonded stake (the Cosmos
rule, research b.5 and (c)).

**SL-2 (unbonding counts from the end of the last committee epoch).** Stake that leaves at
height h unlocks at `τ(h) + I·C_τ + U`. Its key can sign until H_{E(h)}, and
τ(H_{E(h)}) ≤ τ(h) + (H_{E(h)} − h)·C_τ ≤ τ(h) + I·C_τ, so the stake stays locked for at
least U after the last block it could sign, and the queue stays sorted. The extra wait is at
most I·C_τ (3.9 h at I = 1,000 and 14 s, 0.8 % of U). The same rule holds for a validator
that leaves, the remainder of a partial slash, and a delegator that undelegates.

**SL-3 (evidence).** Equivocation evidence is V4 (G1 EQ-1): two V4-hashed vertices, or two
attestations, of one slot, signed by a member of C_{E(slot)}. It is carried through the DAG
(`SLASH_EVIDENCE:`), verified against C_{E(slot)} rather than the live set, refused when
older than W in τ, and applied 100 %. Evidence rows are kept for W, keyed by epoch. The V3
evidence path and the V3 DAG code are deleted with it (G1 S11b part 2).

**DOC-1 (honest claims).** The RPC and every public document describe the draw on the
remaining reserve by consensus time, report `last_reward_height`, the realized rate and the
remaining reserve, and name no halving.

## Stages

Each stage lands with its witnesses and a mutation run; one independent review runs at the
end of G5, as with G1.

| Stage | Content | Witnesses | Kill list |
|---|---|---|---|
| **S1** (done, `65cc92a`) | CL-1, CL-2, P-1, GV-1 counted in heights: the `0x1::chain` clock and parameters, heights in Move, genesis pins and derivation, the Rust governance path removed | every deadline expires exactly at its height; a halt ages nothing; the pins are bound by the identity; genesis-tool reproduces the table | a deadline in seconds; an unpinned parameter; governance able to change a parameter |
| **S1b** | Amendment A1: CL-1 τ, BT-1's quorum guard, CL-2 writing τ from the block timestamp, P-1's new split (C_τ pinned; U, N, Δc, K constants; G removed), SL-2 unlock by τ, UB-1, CM-1 | with 1 s blocks unbonding completes at 21 d of block time, not at a block count; a 10-day timestamp jump advances τ by C_τ; a corrupted timestamp stream cannot unlock before U / C_τ blocks; a below-quorum sample does not advance T; one author at +30 s cannot move T out of the honest range; a matured entry is paid once, at the first boundary at or after its unlock, in queue order; a commission increase applies exactly at N and never earlier, above Δc it is refused, a decrease applies at once | τ uncapped; cap ignored after a halt; quorum guard removed; unlock from h without I·C_τ; burn restored; payout not bounded by K; manual apply restored; increase cap removed |
| **S2** | EM-1..EM-3: payouts every R blocks by Δτ, committee recipients from a state record shared with consensus, fees to the committee, boundary order, rotation independent of Move, I = 1,000 written by genesis-tool | a payout mints exactly the EM-1 integer form and a day's draw compounds to 1.90 %/yr; the emission over the same τ matches (within 10⁻⁶) for 1 s or 7 s blocks and R ∈ {1, 20}; a payout after a long gap covers one day; a joiner is paid from its first committee epoch and a leaver until its last; fees pay C_{E(h)}, not the live set; a jailed member gets nothing; an invalid live set keeps the committee; the executor's record equals consensus's committee on real nodes | Δτ ignored; the cap removed; the live set paid; payout after derivation at H_E; jailed paid; fees to the live set; rotation skipped when Move aborts; consensus cross-check removed |
| **S3** | DL-1..DL-3, CM-1 in the payout: bonded stake in the committee weight; delegator rewards through the pool; bucketed delegator unbonding with automatic payout | a delegator earns its share of the pool's reward minus commission, to the unit; delegating shifts committee weight at the next epoch only; the sum paid never exceeds e; total supply stays within MAX_SUPPLY; 100 tiny undelegations cannot stop another delegator's | delegated stake ignored in weight; commission not taken; `reward_debt` not updated; the pool-wide cap restored |
| **S4** | SL-1..SL-3: unbonding slashable, V4 evidence (EQ-1) through the DAG, W in τ, V3 deletion | a leaver that equivocates before its unlock loses its unbonding stake; an undelegation after the infraction is slashed and one before it is not; evidence older than W is refused; a V4 node never records V3 evidence (kept from S11b) | only active stake slashed; live-set membership check; no age bound |
| **S5** | DOC-1: RPC fields, README, WHITEPAPER, CLAUDE.md | the RPC reports the Move state; no document names a halving (a grep witness) | — |
| **S6** | The fresh genesis file from genesis-tool with the measured t_b, shown to the founder before it is used | the genesis identity changes with each pinned parameter | — |

## Open (to measure, not to guess)

- **t_b at genesis.** V4's block time is not measured yet. C_τ is derived from the value
  measured on the release candidate; genesis-tool has no default.
- **Boundary cost B**, split into protocol rounds and wall-clock time (fsync, BLS, the
  QC(H_E) wait): measured in the G1 S10 harness on real hardware before genesis. I = 1,000
  needs the wall-clock part at or below 10 s for blocks down to 1 s.
- **Validator time:** NTS or several independent time sources on every validator, and the
  60 s drift alarm (BT-1), before genesis.
- **Churn limit:** needed before the validator set opens (research (d) 10). Not needed at the
  permissioned launch, where the operator controls churn.
