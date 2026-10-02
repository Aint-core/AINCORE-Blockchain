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
| C_τ, clock cap per block | measured (S6): the smallest whole second at which capping loses ≤ 0.5 % of the release candidate's measured consensus time, within [⌈2·t_b⌉, ⌈4·t_b⌉]; 24 s on the S6 cluster (t_b 6.86 s) | k = 2 (clock research §5.2) assumed it was above the normal spread of intervals. The S6 measurement refutes that: about 15 % of anchors are skipped even with four honest validators (gaps of 2, 3 and up to 6 leader rounds), p99 21 s, max 43 s, and 14 s lost 3.99 % of consensus time (emission 1.82 %/yr, unbonding ~21.9 d). The upper bound k = 4 keeps a corrupted clock's speed-up of emission and deadlines at 4× (the BT-1 alarm flags it). `genesis-tool clock-cap` computes it from the block intervals |

*Stdlib constants* (durations; bound by the stdlib hash that genesis pins):

| Name | Value | Derivation |
|---|---|---|
| U, unbonding | 21 d | U ≥ T_trust + T_mis (clock research §3.2). T_trust = 14 d: the longest halt so far was 10 days, checkpoints are weekly, and bridge light clients trust for 2/3·U (IBC ADR-026). T_mis = 7 d to detect misbehaviour and land evidence |
| W, evidence max age | 7 d | Amendment A2. W = T_mis, the misbehaviour budget U's derivation already reserves; W ≤ U is the slashability condition (research b.5). W bounds how long committee records are kept, and W + D + I·C_τ < U lets every slash settle before any stake it reaches can unlock (SL-5) |
| D, correlation window | 1 d | Amendment A2. Offenses within D of each other count together (SL-4). Every recorded operator-error incident clustered within hours (Ethereum 2022–2025); Ethereum and Polkadot both raise the fraction with concurrent offenses (docs/research/slash_policy.md) |
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
  in whole AIN; a member's share is pot × w / W (Amendment A4, BW-7 removed the saturation
  clip).
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
C_E, then EP-2's derivation of C_{E+1} from the post-state. (A leaver's unbonding starts at
its leave transaction, not at H_E.) The derivation does not depend on Move's `advance_epoch`
succeeding (FX-14): an aborted epoch advance still records the next committee. The Move
epoch counter (`staking.current_epoch`, which `universal_mining` uses to limit DePIN
payouts) advances at committee boundaries.

**DL-1 (bonded stake).** A validator's bonded stake is its own stake plus its pool's active
delegated principal. At each boundary H_E, after the payout, the executor recomputes every
live member's bonded stake from Move state into `sys:validator_set:v1`, so C_{E+1} is weighted
by bonded stake. It records the split next to the committee
(`sys:validator_set:epoch_delegated:{E+1}`). A delegation therefore changes committee weight
at the next epoch, never inside one.

**DL-2 (delegator rewards).** A pool keeps aggregates only (docs/research/delegation_pools.md
§4): active principal C, points P, a reward counter ρ scaled by S = 10¹⁸ with a carried
remainder κ, a principal escrow (C plus unbonding) and a reward escrow.
- **Split.** A payout gives member v its share r_v (EM-2), split with the frozen
  record (s_v, d_v) of its epoch, b_v = s_v + d_v:
  - r_s = ⌊r_v·s_v/b_v⌋ and r_d = ⌊r_v·d_v/b_v⌋;
  - the commission m = ⌊r_d·c*/10⁴⌋, with c* the rate in force at the start of the reward
    period (CM-1);
  - π = r_d − m.
- **Minting.** r_s + m is minted to the validator. π is minted into the pool's reward escrow
  with ρ += ⌊(π·S + κ)/P⌋ and κ ← remainder. If the pool is not open or holds fewer than
  10¹⁸ points, neither π nor m is minted; that part stays in the reserve.
- **Nothing beyond e.** The payout draws e as one `staking::Emission`, a value with no
  abilities: Move forces every unit either to a recipient or back to the reserve within
  the same transaction, and nothing but drawn coins can go back. Nothing else mints for
  delegation: the `DELEGATION_BPS` stream, its budget and `mint_delegation_reward` are
  removed.
- **Fees.** Per-block fees go to the validators alone, by committee weight (EM-2), as
  block-author fees do on Polkadot and Ethereum. Delegators are paid from emission.
- **Positions.** A position of p points with snapshot σ is owed ⌊p·(ρ − σ)/S⌋, paid (clamped to
  the escrow) whenever it changes or on claim.
- **Joiners.** A new position starts at σ = ρ, so it earns nothing from before it joined. It
  earns from the next payout; its weight counts from the next epoch.
- **Escrow.** The reward escrow covers every position's claim. It exceeds their sum by at
  most P/S + (positions) + 1 base units: the carry κ, plus the flooring. A claim is clamped
  to the escrow, so this dust never makes a claim abort.

**DL-3 (delegator state per account, unbonding tickets).** Each delegator's state lives at its
own address: at most 8 positions and 16 unbonding tickets. No operation touches another
account or iterates a pool's delegators, so every operation costs the same whatever a pool's
size.
- **Points.** Points are issued ⌊a·P/C⌋ on delegate and burned ⌈a·P/C⌉ on undelegate;
  coins paid are ⌊q·C/P⌋. Rounding always favours the pool (EIP-4626).
- **Minimums.** A remainder below 1 AIN makes the exit full.
- **Who takes deposits.** Only an open pool of a validator in the active set takes
  deposits. A slashed pool is closed for good (SL-1).
- **Price.** An open pool's price C/P never falls, since only a slash lowers it. So P ≤ C,
  and an empty pool (P = 0) holds C = 0.
  - A first depositor inherits nothing.
  - No donation path exists: coins enter the principal only through `delegate`, which
    issues points.
  - The share-inflation attack (ERC-4626) has nothing to act on.
- **Tickets.** A ticket unlocks at τ + I·C_τ + U (SL-2). The owner withdraws it once matured,
  with the pool's slash events applied (SL-1). Nothing burns it.
- **Why no automatic payout for delegators.** An automatic sweep of delegator tickets needs a
  global queue linked through other accounts' records. Polkadot, Aptos, Solana and NEAR keep
  unbonded stake until the owner withdraws, and the per-account cap already removes the
  pool-wide freeze (100 entries of 1 AIN blocking a pool). Validator unbonding stays
  automatic (UB-1).

**CM-1 (commission).** A pool has at most one pending change. An increase may raise the rate
by at most Δc over the rate in force, to at most 30 %, and takes effect at τ ≥ announce + N,
fixed when announced. A payout applies the rate in force at the start of its reward period,
so no change is retroactive. There is no manual apply, so a matured change cannot be held
back and fired later. A new announcement replaces the pending one. A decrease takes effect at
once and cancels a pending increase (Cosmos, Polkadot pools, Solana SIMD-0079).
- **An increase no payout has charged yet.** A matured increase becomes the base rate
  once a payout has charged it. Until then, at most one reward period, a change above the
  base rate is refused, so a period that began before the increase is never charged at
  it.

**UB-1 (unbonded stake is paid, never burned).** At each committee-epoch boundary the system
pays up to K matured entries from the head of the validator unbonding queue, which is sorted
by unlock time; the rest wait for the next boundary. `withdraw_unbonded` stays as the
immediate manual path. No production chain examined burns unclaimed principal (Cosmos and
Ethereum pay automatically; Polkadot, Aptos, Solana and NEAR keep it), and the burn had no
security role once the stake unlocked.

**SL-1 (slashable while unbonding).** Unbonding entries, the validator's and its pool's
delegators', stay slashable until they are paid. A slash for an infraction in epoch E_i
reduces the bonded stake and every entry created in epoch E_i or later and before the slash
was applied. Stake that left during E_i still weighed C_{E_i}, since committees are frozen
per epoch (DL-1). Tickets created after the slash are not cut twice.
- **Pool side.** The pool closes for good when the evidence is accepted (SL-5). At
  settlement the active principal is cut, rounded up, and the pool records the slash as an
  event: E_i, its sequence number, the fraction, and how many unpaid tickets it may reach.
  - A ticket records the pool's slash count when it is made, so it is cut only by later
    events, and only once.
  - Each ticket is cut when withdrawn. The cut is burned.
  - An event is dropped once every ticket it may reach is paid. A pool keeps at most 8
    events; past that, the two oldest merge into one that cuts at least as much for every
    ticket.
- **Infraction epoch.** E_i is the epoch of the equivocated slot, taken from the evidence
  (SL-3).
- **Atomicity.** The validator's own stake and its pool are slashed in one Move call,
  `delegation::report_equivocation` and `settle_offenses`, so a slash cannot be half applied:
  without Move's offense record nothing is jailed or pruned (amendment A3).

**SL-2 (unbonding counts from the end of the last committee epoch).** Stake that leaves at
height h unlocks at `τ(h) + I·C_τ + U`. Its key can sign until H_{E(h)}, and
τ(H_{E(h)}) ≤ τ(h) + (H_{E(h)} − h)·C_τ ≤ τ(h) + I·C_τ, so the stake stays locked for at
least U after the last block it could sign, and the queue stays sorted. The extra wait is at
most I·C_τ (3.9 h at I = 1,000 and 14 s, 0.8 % of U). The same rule holds for a validator
that leaves, the remainder of a partial slash, and a delegator that undelegates.

**SL-3 (evidence).** Evidence is V4 and names a slot (E, round, author).
- **Kinds.**
  - Proposer twins (G1 EQ-1): two V4 vertices of one slot with different `hash_v4`, both
    signed with the author's key in C_E.
  - A certificate conflict (G1 CE-3): two certificates of one slot on different digests.
    Every signer in both is an offender: both BLS aggregates verify, so each of them signed
    both digests. Two quorums of C_E intersect in more than a third of its weight, so this
    evidence always reaches SL-4's 100 %.
    - **One key, one member.** A set bit proves only that a registered BLS key signed.
      So `join_validator_set` refuses a key an active validator holds, and
      `validate_committee` refuses a committee in which two members share one.
    - **When it applies.** A conflict means safety was attacked, so ordering halts
      where it is seen (CE-3). The pair is kept in an epoch-keyed row and carried
      like any evidence row once ordering resumes after recovery.
- **Verification.** Evidence is carried through the DAG (`SLASH_EVIDENCE:`) and verified
  against C_E (keys and membership), never the live set.
- **Age.** It is refused once τ > τ_start(E+1) + W. That is never before W has passed since
  the latest moment the offense could have happened. It is also refused once C_E's record
  is gone. Committee records, their splits and τ_start(E) are kept while τ ≤ τ_start(E+1) + W
  and for at least 8 epochs.
- **Tombstone.** A validator's first accepted offense is its only one:
  - it is jailed for good and never re-enters a committee;
  - its `join_validator_set` is refused;
  - later evidence against it is ignored.
- **Keys.** Evidence rows are keyed by epoch.
- **V3.** The V3 evidence path and the V3 DAG code are deleted (G1 S11b part 2).

**SL-4 (fraction).** Offender v's fraction is

  `f = 10⁴ bps if 3·Q ≥ T, else max(100, ⌈9·10⁴·Q²/T²⌉) bps`.

- T is the total weight of C_{e_v}.
- Q is the sum of w_u over the distinct offenders u (v included) with |τ_u − τ_v| ≤ D.
  - τ_e = τ_start(e_u) is the start of the offense epoch.
  - w_u is u's weight in C_{e_u}.
- Isolated faults cost from 1 % up. The fraction rises with the square of the share that
  equivocated together, and is 100 % from a third, the least any safety attack needs. It is
  Polkadot's (3k/n)² by stake instead of by count, with Ethereum's 1 % realized floor.
- The fraction is stake-weighted: splitting stake across validators does not lower Q.
- Integer form: Q, T ≤ 1.5·10⁸, so 9·10⁴·Q² < 2.1·10²¹, far inside u128.

**SL-5 (acceptance and settlement).**
- **Acceptance.** In the block that carries the evidence:
  - the offender is jailed and leaves the live set;
  - its own stake moves to unbonding, which is in scope, and none of it is burned yet;
  - its pool closes: no deposits, no reward, no weight;
  - the offense is recorded with e_v, τ_v, w_v, T and the frozen split (s_v, d_v) of
    C_{e_v}.
- **Settlement.** The fraction is final once τ ≥ τ_v + D + I·C_τ + W. By then every
  correlated offense's evidence has landed or been refused. It settles at the first reward
  period after that, or at once when 3·Q ≥ T, since 100 % cannot rise. The settlement is
  one Move call.
- **No freeze is needed.** In-scope stake unlocks at τ_v + U or later (SL-2). Settlement
  happens by τ_v + D + I·C_τ + W + R·C_τ < τ_v + U, since 1 d + 3.9 h + 7 d is far below
  21 d. `chain::valid` requires I·C_τ ≤ U − W − D − R·C_τ.
- **No cancel, and burned.** There is no discretionary cancel: the founder would be
  cancelling his own slashes. Slashed coins are burned.

**SL-6 (who pays).** The operator's own stake takes the loss first. With the frozen split
(s, d) of C_{e_v} and b = s + d:

  `A = f·b` (bps × weight), `self = min(10⁴, ⌈A/s⌉)`, `pool = min(10⁴, ⌈max(0, A − 10⁴·s)/d⌉)`
  (bps), so an operator without a pool pays exactly f.

- Every unbonding entry of the validator made in epoch e_v or later is cut by `self`. Earlier
  entries are out of scope.
- The pool is cut by `pool` (SL-1).
- At f = 100 % both are 100 %, so the cost of an attack is unchanged.
- An isolated fault reaches delegators only when f·b > s.

**DOC-1 (honest claims).** The RPC and every public document describe the draw on the
remaining reserve by consensus time and name no halving.
- `aincore_getSupply` and `aincore_getEconomics` report, from Move state, the remaining
  reserve (the cap minus net supply and burns), the consensus time of the last payout
  (`last_reward_time`) and the rate.
- `aincore_getEconomics` also reports the pinned I, R and C_τ.

## Amendment A3 (the end-of-G5 review, 2026-10-01)

Five independent reviews (Move economics, executor determinism, consensus evidence and the
V3 deletion, an adversary, contract conformance) found one CRITICAL, five HIGH and several
MEDIUM defects. Each fix below has a witness in the release manifest.

- **One path into the validator set (CRITICAL).** `join_validator_set`,
  `leave_validator_set` and `add_stake` are `entry`, never `public`. The executor checks the
  BLS proof of possession, refuses a tombstoned validator and keeps `sys:validator_set:v1` in
  step only for a direct call; a module could call the old `public entry` functions and skip
  all three (leave through a module, take the stake back after U, keep the seat). Witness
  `g5_a_module_cannot_call_the_staking_entries` (the attacker's module, compiled against the
  old stdlib, published before and is refused now). The Move set is also the authority at
  every boundary: a member it does not hold leaves `v1` (`g5_a_committee_member_without_move_stake_loses_its_seat`).
- **EP-2's committee is the top 256 by stake** (HIGH). 257 joins made the live set invalid,
  which kept C_E for good, leavers included. The committee is now the 256 positive-stake
  members with the most stake, ties by address (Cosmos `MaxValidators`); more may be bonded
  and are not paid. When the proposal is still invalid, the kept C_E drops members the live set
  no longer holds. Witnesses `more_than_256_validators_elect_the_top_256_by_stake`,
  `a_kept_committee_drops_members_whose_stake_left`.
- **SL-3 fails closed** (HIGH). Evidence of epoch E is refused once E's records are pruned
  (`sys:validator_set:retained_from`) or E+1's start time is gone while E+1 has begun; epoch
  0's committee is the genesis record, never pruned, which made epoch-0 evidence acceptable
  for ever.
- **SL-3, one slot per offender** (HIGH). Evidence against a jailed validator is refused at
  verification (it took one of the block's five slots), and the block's dedup key is the set
  it convicts, not the slot, so a sacrificed equivocator cannot crowd out real evidence. A
  node retires evidence rows the executor can never accept again.
- **SL-5 never fails at acceptance** (HIGH). `report_equivocation` records and settles
  nothing; the executor runs `settle_offenses` in the same block. Settlement is one linear
  sweep over the ledger, kept sorted by `epoch_began` (it was quadratic: about 550 sybil
  offenses made every record abort, and the executor then jailed without slashing). An
  aborted record now applies nothing (SL-1). The deadline is strict, τ > τ_v + D + I·C_τ + W:
  at equality a correlated offense's evidence can still land.
- **CE-3 relays** (HIGH). A node that sees two certificates for a slot relays both once, so
  every honest node halts and keeps the evidence (a coalition able to make two could halt the
  chain anyway). It is carried after recovery (Open).
- **P-1 has no default.** A genesis file must pin I, R and C_τ; genesis-tool derives them only
  for t_b ∈ [1.0 s, 7.2 s], where I = 1,000 holds. The genesis committee is checked like every
  later one (`validate_committee`: no shared BLS key, at most 256).
- **EM-2:** a leader outside the paid committee (jailed since it was elected) gets no fee
  bonus.
- **DOC-1:** README and WHITEPAPER no longer claim a downtime slash, an immediate slash, a
  block reward, a 1–2 s block time, 10,000 TPS, a zero genesis supply, fees to the treasury
  or DePIN emission. Witness `the_public_documents_make_no_claim_the_code_contradicts` (a lib
  test, in the gate). Still awaiting the founder: the "Genesis Lock" and Dilithium claims.
- **A3b, from the review of A3** (one HIGH, two MEDIUM):
  - *A certificate conflict convicts at 100 %* (HIGH). Two certificates for one slot overlap in
    more than a third of the committee, so SL-4 gives 100 % without counting Q. Before, a
    coalition could get each member jailed for a small, spread-out twin offense (about 2.7 %
    each) and then, still holding its C_E seats for the rest of the epoch, make conflicting
    certificates whose evidence was refused because all were jailed. Now the conflict raises
    each convict's lesser offense: an unsettled one settles at 100 % with the earlier scope, a
    settled one loses what remains in scope at once (`report_certificate_conflict`;
    `validator:convicted_full` marks the end). Witness
    `g5_a_certificate_conflict_raises_a_lesser_offense_to_full`.
  - *Slashable stake cannot leave before settlement* (MEDIUM). An offender's unbonding entries
    of its scope are frozen from acceptance to settlement (`staking::FrozenPayouts`), and a
    delegator's ticket in an unsettled scope waits too. Settlement handles at most 32 offenses
    per call, so its work is bounded whatever the unbonding queue holds; the rest wait frozen.
  - *A full validator set does not freeze membership* (MEDIUM). With 1,000 members, a joiner
    with more stake than the smallest member displaces it into unbonding; one with no more
    stake is refused. Witness `g5_a_full_validator_set_takes_a_larger_joiner_and_unbonds_the_smallest`.
  - Evidence age is checked before the committee lookup, and a node checks its in-flight map
    before verifying a row, so a pruned epoch's rows are retired and no row is verified twice.
  - Accepted LOW: with every member of the paid committee jailed, the fees still go to the
    leader (the chain cannot continue then anyway).
- **Known, accepted:** the first accepted offense of a validator sets its scope, so a later
  acceptance of an earlier offense is ignored (the earliest twins are normally the first
  carried). A second offense recorded in Move is unreachable (the executor's jail refuses it
  first); the Move check is defence in depth.

## Amendment A4: bootstrap weight (BW-1, 2026-10-02; revised after review)

Accepted by the founder after the research in `docs/research/genesis_bootstrap.md`: the
chain launches without a pre-mine. Consensus weight at block 1 comes from **bootstrap
weight**: weight with no coins, owned by nobody, assigned at genesis to operators. It fills
the committee up to `s_min` while owned stake is short, and it is forfeited by operators who
fail objective rules. Emission is paid by committee weight, so the operators running the
chain are paid for it, as miners are.

The first implementation (31c631e) was reviewed by three independent agents (conformance,
correctness, adversarial). Their findings changed BW-4, BW-6 and BW-7 and added BW-11 and
BW-12; the table at the end maps each finding to its fix.

**BW-1 (state).** `sys:bootstrap:v1` (State class, in the root) holds:
- `s_min`, the minimum committee weight in whole AIN;
- per operator: `ceiling` (its genesis weight), `weight` (its weight in the current
  committee) and `score` (BW-6), all whole AIN except the score, in parts per million.

Genesis writes it from `genesis.json`'s `bootstrap` field. A chain without the key has no
bootstrap weight (test fixtures).

**BW-2 (genesis).**
- Every bootstrap operator is a genesis validator, with weight > 0.
- The weights sum to exactly `s_min` minus the genesis committee's owned stake, so the
  genesis committee weighs exactly `s_min`.
- No member's total (owned + bootstrap) reaches a third of the committee.
- A genesis validator owns 0 AIN or at least 1,000 AIN; 0 only with bootstrap weight.
- The genesis committee record, the leader and quorum weights, and `sys:validators` carry
  owned + bootstrap weight. Genesis also writes epoch 0's bootstrap split (BW-8) and the
  protected list (BW-12).
- `genesis.json` may also list `accounts` (address, balance): liquid AIN for the public
  track of the incentivized testnet, counted in the total supply. An account is compared
  with the validators as an address, so hex case cannot hide a validator.
- `genesis-tool gen-multi` builds the file with the node's own `build_genesis` before writing
  it (`check_genesis_json`), so it cannot write a file the node refuses, and prints its
  identity.

**BW-3 (committee weight).** At every boundary refresh, a live-set member weighs its own Move
stake, plus its open pool's coins, plus its bootstrap weight. A top-up inside an epoch
updates the live set with the bootstrap weight included. A member absent from the Move set
loses its seat and its bootstrap weight.

**BW-4 (fill to s_min within the ceilings).**
- P is the owned weight (own + pool) of the members the next committee would hold: the top
  256 by owned + current bootstrap weight, as the election ranks them. Owned stake outside
  the committee secures nothing, so it does not count.
- The target is B = max(0, s_min − P). Each operator's weight is
  ⌊ceiling × min(B, C) / C⌋, with C the sum of the ceilings. So bootstrap weight shrinks pro
  rata as owned stake grows and **regrows up to the ceilings** when owned stake leaves: s_min
  is a floor while the bootstrap lasts (review LOW-7: under "never grows", stake that came
  and left lowered the floor for good).
- The bootstrap ends for good the first time B = 0: every ceiling becomes 0, and it never
  returns, so an operator that held nothing for years cannot get weight back while absent.
- A forfeited ceiling is never redistributed: nobody gains weight from another's forfeit.
- Order at the boundary: refresh owned weights, score (BW-6), forfeit (BW-5), fill (BW-4),
  cap (BW-11), add the weights to the live set, then elect C_{E+1}.

**BW-5 (forfeit).** An operator's ceiling becomes 0 for good when it is jailed, is convicted
in full, leaves the Move set, or its score falls below one half (BW-6). Leaving forfeits in
the leave transaction itself, so a leave and a rejoin inside one epoch keep nothing.

**BW-6 (participation, by the leader schedule).**
- Each block carries its anchor round (the header's `round`, certified with the block). The
  executor counts, for every even round in (previous anchor round, this anchor round], the
  leader that consensus's own function names (`blockchain::committee::leader_for_round`,
  the one definition consensus uses) under the committee of the block's epoch: a slot for
  that leader, and a commit if the round is this block's anchor. Only operators are counted,
  in `sys:bootstrap:slots:{E}`; `sys:bootstrap:round` holds the last anchor round. A gap of
  more than 65,536 rounds counts only its last rounds.
- This is exact, not an estimate: an offline operator holds its slots and commits none. It
  has no variance, so small operators are judged as well as large ones, and choosing the
  schedule by grinding stake changes cannot make an online operator fail (review MEDIUM-6).
- At the boundary each operator with slots in the closed epoch updates its score:
  score ← score − ⌊score/128⌋ + ⌊ratio/128⌋, with ratio = 10⁶ × commits / slots. It starts
  at 10⁶. An operator forfeits when its score is below 500,000.
- Derivation:
  - **Bar ½.** On AINCORE-TESTNET-V4 (567 blocks, 2026-10-02) every validator committed
    88–92 % of its scheduled slots. Half leaves a margin of ~0.4 against honest operators and
    requires 56 % uptime (0.9 × u ≥ ½); a lazy operator can no longer alternate failing and
    passing epochs (review MEDIUM-5), since the score is an average.
  - **Memory N = 128 epochs.** Half-life 88.4 epochs, 6.9 days at the measured 6.75 s blocks:
    the 7-day human reaction budget T_mis this contract already uses (W). A dead operator
    forfeits after 75 epochs (5.9 days) from 0.9, or 89 from a fresh start; an outage,
    DDoS or censorship of a few hours costs a few percent of score, not the weight (review
    HIGH-2: three failing epochs, ~5.7 h, used to forfeit for good).
  - **False forfeit.** An honest operator's per-epoch ratio has variance at most 0.09/n for
    n slots; the average's standard deviation is at most √(0.09/256) ≈ 0.019 with one slot an
    epoch: the bar is 21 deviations below 0.9.
- Residual risk: a coalition over a third can withhold votes for one operator's anchors for
  six days, visibly, on chain. Any coalition over a third can halt the chain anyway.

**BW-7 (rewards and fees).** A member's share of a payout is pot × w / W, its weight over
the paid committee's whole weight, as Cosmos, Ethereum and Solana pay. Bootstrap weight
counts in the member's own part, never its pool's: delegators did not provide it.
- The saturation clip (total / 50, inherited from before G5, not derived in it) is removed.
  It divided the pot by the clipped total, so with fewer than 50 members every seat earned
  the same slice: four founder seats took 4/7 of all emission and a 370 k seat earned what a
  4.3 M seat earned (review HIGH-3). Paid by weight, a seat earns nothing by being a seat,
  and splitting stake gains nothing.
- Cardano's form of the cap (divide by the whole weight, leave the excess unpaid) was
  considered and rejected. With no pre-mine, emission is the only source of coins; at launch
  every member would be saturated, so only n/50 of each draw would be paid (10 % with five
  members), owned stake would grow about ten times slower than the model assumes, and the
  bootstrap phase, whose authority BW-1 exists to end, would last decades.
- So the operators who run the chain earn the emission by their weight, as miners earn
  Bitcoin's: the founder's validators at most 30 % of it, falling as owned stake replaces
  bootstrap weight (`genesis_bootstrap.md`).
- Fees are unchanged: 20 % to the anchor leader, 80 % by committee weight.

**BW-8 (never coins).** Bootstrap weight never enters a CoinStore, `ValidatorSet` stake, the
total supply, or the emission reserve's accounting. At each boundary the executor records
the bootstrap part of every member's weight next to the committee
(`sys:validator_set:epoch_bootstrap:{E}`, pruned with it). An offense passes the waterfall
the operator's own coins (weight − pool − bootstrap) and its pool's part; the correlation
still uses the whole weight. Bootstrap weight cannot absorb a loss its delegators owe (review
HIGH: it was counted as own stake, which left delegators almost unslashed).

**BW-9 (churn, slashing).** CH-1's base and the correlation fraction's T are committee
weights, so they include bootstrap weight. This is consistent with the leader and quorum
weights.

**BW-10 (transparency).** `aincore_getBootstrap` returns `s_min_ain`, `bootstrap_ain`,
`ceiling_ain`, `owned_stake_ain` (P as BW-4 counts it), `target_ain`, and each operator's
ceiling, weight and score, all as numbers, computed by the executor's own functions.

**BW-11 (below a third, at every boundary).** After BW-4, bootstrap weight is cut so that no
member of the next committee reaches a third of it: each member's weight becomes at most
max(owned, L), with L the largest level such that 3L is below the new total (at most the
total with exactly three members; nothing is cut with two or fewer). Only bootstrap weight
is cut, the cut goes to nobody, and it is recomputed every boundary from the ceilings.
- Why: forfeits shrink the committee, so survivors' shares grow. With the founder at 30 % and
  three operators, one forfeit would put the founder at 38 %, and a founder-plus-one
  coalition (53 %) striking out another operator would reach 68 % (review HIGH-1). With the
  cap, one forfeit leaves the founder below a third and any two members below two thirds.
- Precedent: Sui caps each validator's voting power every epoch at max(10 %, 1/n)
  (`voting_power.move`); it redistributes the excess, AINCORE drops it, so nobody gains.
- Cost: when only two large members are left beside small ones, the cap shrinks the
  committee to about three times the small members' weight (2 M AIN in the example of
  `genesis_bootstrap.md`). That is the honest state of a chain with two large parties; more
  launch operators keep a margin (IT-5).

**BW-12 (protected seats).** `0x1::staking::BootstrapProtected` lists the operators with a
ceiling. A full validator set (1,000) never displaces them; a joiner takes the smallest
unprotected member's place, or is refused. Genesis writes the list and the executor rewrites
it at every boundary. Without it, filling the set with 1,000-AIN validators (about 1 M AIN,
refunded after unbonding) displaced operators that own 0 AIN and forfeited their weight
(review MEDIUM-HIGH-4).

**Known, accepted.**
- If a boundary's proposed committee is invalid, C_E is kept with its old weights for one
  epoch, so a forfeit takes effect one epoch late (review LOW-8).
- An owned stake of a third or more is never cut (only bootstrap weight is); CH-1 bounds how
  fast it can be bought (review INFO).
- The founder's share (≤ 30 %) and the operator count are rules of the genesis ceremony, not
  of the loader: the genesis file and the founder's addresses are public, so anyone can check
  them (review INFO).

**Review findings and their fixes.**

| Finding | Severity | Fix |
|---|---|---|
| Bootstrap weight counted as own stake in the slash waterfall | HIGH | BW-8: per-epoch bootstrap split; own = weight − pool − bootstrap; Move `record` takes own + pool ≤ weight |
| The third checked only at genesis | HIGH | BW-11 |
| Three bad epochs (~5.7 h) forfeit for good | HIGH | BW-6: exact schedule, score with a 6.9-day half-life |
| Saturation clip paid per seat | HIGH | BW-7: paid by weight, no clip |
| A full set displaced operators owning 0 AIN | MEDIUM-HIGH | BW-12 |
| A mid-epoch top-up dropped bootstrap weight from the live set | MEDIUM | BW-3 |
| Alternating epochs kept full weight at 13 % uptime | MEDIUM | BW-6: averaged score, bar ½ |
| Grinding the schedule to frame an operator | MEDIUM | BW-6: judged against its own slots |
| Floored expectation, owned stake outside the committee in P, leave and rejoin kept weight | LOW | BW-6 replaced; BW-4 counts the next committee; BW-5 forfeits at the leave |
| Stake that came and left lowered the floor | LOW | BW-4: regrowth to the ceilings |
| Genesis compared accounts as strings; the tool accepted 1–999 AIN, duplicate and malformed accounts | LOW | BW-2: addresses compared, the node's rules run in the tool |
| The lead count rewritten every block for every leader | LOW | only operators' slots, only when one is scheduled |

**Stages.**

| Stage | Content | Witnesses |
|---|---|---|
| A4-S1 | BW-1, BW-2, BW-8: genesis field, validation, committee and supply; genesis-tool entries' `bootstrap_ain`, `--s-min-ain`, `--accounts-file` | `a_bootstrap_genesis_weighs_s_min_and_mints_nothing`, `bootstrap_weight_fills_the_genesis_committee_without_coins` |
| A4-S2 | BW-3, BW-4, BW-5, BW-7, BW-8, BW-9, BW-11, BW-12 in the executor and Move | `g5_bootstrap_weight_fills_to_s_min_within_its_ceilings`, `g5_bootstrap_weight_is_capped_below_a_third`, `g5_the_cap_cuts_only_bootstrap_weight`, `g5_owned_stake_counts_only_the_next_committee`, `g5_a_jailed_bootstrap_operator_forfeits_its_weight`, `g5_an_offense_record_leaves_bootstrap_weight_out_of_the_waterfall`, `g5_a_full_set_never_displaces_a_bootstrap_operator` |
| A4-S3 | BW-6 participation by the schedule | `g5_a_silent_bootstrap_operator_forfeits_when_its_score_falls_below_half`, `g5_the_bootstrap_score_has_a_week_long_memory`, `the_leader_schedule_matches_live_testnet_blocks` |
| A4-S4 | BW-10 RPC, operator guide | `get_bootstrap_reports_the_state` |
| A4-S5 | Crash pin re-proof, mutation campaign, independent review | every kill list item killed; findings fixed |
| A4-S6 | Incentivized-testnet scoring (`genesis-tool score-testnet`, `gen-multi --allocations-file`) producing P0 (operators' genesis stake and bootstrap weight, the public track's accounts) from testnet chain data | `the_testnet_scores_operators_by_their_leader_slots`, `a_jail_counts_only_up_to_the_snapshot`, `the_public_track_counts_points_on_three_days` |

## End-of-G5 mutation campaigns (2026-10-01/02)

Each mutant was applied to the committed tree and the stage's witnesses were run (on the Pi
and the NAS; scratchpad drivers `mut_g5end.py`, `mut_remote.py`).

- **Campaign 1 (S4a, S4b, S4d, S4c kill lists): 24 of 27 killed.**
  - A5 (D zero in the old `correlated_weight`): that function is gone in A3. Its
    replacement, the linear sweep, is mutant F22, killed by
    `g5_offenses_correlate_across_epochs_within_d`.
  - A11 (a second offense counted in Move): unobservable. The executor's jail refuses a
    second offense first; the Move check is defence in depth.
  - B3 (a round-only evidence row key): equivalent. V4 rounds never repeat across epochs.
- **Campaign 2 (A3 and A3b): 29 of 29 killed.** It covered:
  - the staking entries made `public entry` again;
  - the boundary refresh keeping members without Move stake;
  - the top-256 election and the kept-committee filter;
  - evidence age, retention and jailed refusal;
  - the evidence key;
  - settlement after evidence, the strict deadline, recording that settles again, and D = 0
    in the sweep;
  - the atomic record;
  - the CE-3 relay;
  - the jailed leader's bonus;
  - the genesis committee check, the P-1 pins and the block-time range;
  - conviction in full, its routing, frozen payouts at boundaries and by hand, and eviction
    by an equal joiner;
  - the S4c leftovers: decision rows, the inert node's three gates, the boot format check
    and the V3 evidence kind.
- **Not witnessed, accepted:**
  - `record_twin` and the CE-3 alarm in one transaction: no crash test.
  - The ticket guard in an unsettled scope: a ticket cannot mature before settlement unless
    settlement is late.
  - The 32-offense settlement cap: no test exceeds it.

## Stages

Each stage lands with its witnesses and a mutation run; one independent review runs at the
end of G5, as with G1.

| Stage | Content | Witnesses | Kill list |
|---|---|---|---|
| **S1** (done, `65cc92a`) | CL-1, CL-2, P-1, GV-1 counted in heights: the `0x1::chain` clock and parameters, heights in Move, genesis pins and derivation, the Rust governance path removed | every deadline expires exactly at its height; a halt ages nothing; the pins are bound by the identity; genesis-tool reproduces the table | a deadline in seconds; an unpinned parameter; governance able to change a parameter |
| **S1b** | Amendment A1: CL-1 τ, BT-1's quorum guard, CL-2 writing τ from the block timestamp, P-1's new split (C_τ pinned; U, N, Δc, K constants; G removed), SL-2 unlock by τ, UB-1, CM-1 | with fast or slow blocks unbonding completes at 21 d of block time, not at a block count; a 10-day timestamp jump advances τ by C_τ; a corrupted timestamp stream cannot unlock before U / C_τ blocks; a below-quorum sample does not advance T; one author at +30 s cannot move T out of the honest range; a matured entry is paid once, at the first boundary at or after its unlock, in queue order; a commission increase applies exactly at N and never earlier, above Δc it is refused, a decrease applies at once | τ uncapped; cap ignored after a halt; quorum guard removed; unlock from h without I·C_τ; burn restored; payout not bounded by K; increase cap removed |
| **S2** | EM-1..EM-3: payouts every R blocks by Δτ, committee recipients from a state record shared with consensus, fees to the committee, boundary order, rotation independent of Move, I = 1,000 written by genesis-tool | a payout mints exactly the EM-1 integer form and a day's draw compounds to 1.90 %/yr; the emission over the same τ matches (within 10⁻⁶) for 1 s or 7 s blocks and R ∈ {1, 20}; a payout after a long gap covers one day; a joiner is paid from its first committee epoch and a leaver until its last; fees pay C_{E(h)}, not the live set; a jailed member gets nothing; an invalid live set keeps the committee; the executor's record equals consensus's committee on real nodes | Δτ ignored; the cap removed; the live set paid; jailed paid; fees to the live set; rotation skipped when Move aborts; consensus cross-check removed |
| **S3** | DL-1..DL-3, CM-1 in the payout, the atomic slash: pools of aggregates with per-account positions and tickets; the reward split from the frozen record; bonded weight at boundaries; `math` u256 mul_div; the RPC reads the Move state | conservation: principal escrow = C + unbonding, Σ points = P, reward escrow covers every claim within dust; ρ·P + κ = S·Σπ exactly; each payout's two parts match the frozen split to the unit, and a mid-epoch joiner does not move it; a delegator is paid ⌊p·Δρ/S⌋ to the unit and a joiner nothing from before; weight changes at the next epoch only; commission uses the rate at the period start; the active and ticket slash follow SL-1 in one call; a closed pool refuses deposits; a pool's stored size does not grow with its delegators; a full account cannot block another's undelegation; exits and deposits round the pool's way; a claim past u128 works and a 1-unit shortfall does not abort | the carry dropped; points rounded up on deposit; coins rounded up on exit; deposits into a dead pool; tickets of an earlier epoch slashed; live stake used in the split; a vector of delegators in the pool; the escrow clamp removed; u128 intermediates |
| **S4a** | Amendment A2 policy: SL-4..SL-6, acceptance and settlement in Move, the offense ledger, the tombstone, W = 7 d and D = 1 d pinned | SL-4 to the basis point (isolated 1/4, 1/10, 1/100 of weight; a third); offenses within D count together, beyond D they do not; 3Q ≥ T settles at once at 100 %; otherwise nothing settles before τ_v + D + I·C_τ + W; the waterfall leaves delegators whole when the operator covers A; in-scope own unbonding is cut, earlier entries are not; a leaver that equivocates before its unlock loses its unbonding stake; every in-scope entry is still unpaid at settlement; a tombstoned join is refused | floor dropped; linear instead of square; threshold at half; D unbounded or zero; settlement before the deadline; waterfall reversed; pool left open at acceptance; out-of-scope entries cut |
| **S4b** | SL-3: V4 proposer twins detected when a slot stages a second digest, kept in durable epoch-keyed rows before GC, carried through the DAG and verified against C_E with the age bound | a twin pair from real V4 nodes is recorded, carried in a block and jails its author on every node; a pair signed by a non-member of C_E (even a live validator), from another domain, of two slots or of an unrecorded epoch is refused; evidence of epoch 0 is accepted until τ_start(1) + W exactly and refused after; accepted, the offense is recorded in the evidence's own epoch | live-set membership; no age bound; a round-only key; the V3 hash |
| **S4d** | SL-3's certificate-conflict kind: `join_validator_set` and committee validation refuse a BLS key already held; the attestation and certificate types move to `blockchain::attest`, so the executor checks the aggregates; the halting node keeps the pair; every signer in both is convicted | real V4 nodes keep the pair where CE-3 halts, and it convicts exactly the members in both; two convicts forming half the committee settle at 100 % at once; one digest, no member in both, another committee, a bit past the committee or a forged aggregate is refused; a shared BLS key is refused at join and in a committee | a duplicate key accepted; the intersection taken from one certificate |
| **S4c** | G1 S11b part 2: V3 ingress, producer, boot recovery, checkpoints, pruning and evidence deleted from `dag.rs`; a database without the V4 format is refused at boot (`verify_genesis_integrity`) and a node opened on one is inert; only V4 evidence kinds pass the block split; the node routes no V3 prefix to consensus | the five V3-fixture witnesses re-expressed on V4 with their schedules: the accepted block's QC work survives a process crash after acceptance (one-member committee); a follower holding block and QC adopts all-or-nothing across a crash inside and after adoption; observers given a complete history, then three replays and a reopen, decide what the other decided; thin one-parent Byzantine vertices are refused on every node and round r's leader commits; a round-skipping anchor citing three certified round-r parents (a stake quorum) is refused while every honest vertex is admitted; a V4 node never records V3 evidence; an inert node writes nothing; a V3 database does not boot | Layer S without `parent_refs_admissible_above`; the round clause dropped; QC work staged after the acceptance commit; the adoption height written outside the adoption transaction; the decision row not persisted; the inert gate removed; the boot format check removed |
| **S5** | DOC-1: RPC fields, README, WHITEPAPER, CLAUDE.md | the supply and economics RPCs report the Move emission state and nothing of a halving; README, WHITEPAPER and CLAUDE.md name no halving (node witnesses `public_documents_name_no_halving`, `the_economics_rpcs_report_the_move_emission_state`) | — |
| **S6** | The fresh genesis file from genesis-tool with the measured t_b, shown to the founder before it is used | the genesis identity changes with each pinned parameter | — |

## Open (to measure, not to guess)

- **t_b at genesis (measured, S6).** Four V4 validators on the NAS and the Pi, 1,126 blocks
  over 2 h: mean 6.78 s by T (6.86 s by wall clock), p50 6 s, p90 12 s, p99 21 s, max 43 s.
  The mainnet genesis re-measures on its release candidate with `genesis-tool clock-cap`.
- **Boundary cost B (measured, S6).** Blocks 1,000 → 1,002 took 12 s, two normal intervals:
  the wall-clock cost of the epoch boundary is within noise, under the 10 s that I = 1,000
  needs. T(1,001) = T(1,000) (the first anchor of epoch 1 sampled below quorum, BT-1 holds T).
- **Skipped anchors (performance, G1).** ~15 % of leader rounds commit no anchor with four
  honest validators; this is the timer-driven round (3 s tick) and the cause of the interval
  tail. Fixing it narrows the tail; C_τ is pinned at genesis from what was measured.
- **Memory (measured, S6).** RSS is a sawtooth bounded by the RocksDB memtable (64 MiB, flushed
  at ~1,050 blocks): peak ~110 MB per validator, 36–40 MB after a flush. No leak.
- **Validator time:** NTS or several independent time sources on every validator, before
  genesis. The operator guide gives the chrony NTS setup (`docs/NODE_OPERATOR_GUIDE.md`,
  Time); each operator must apply it, and nothing in the node can check that it did.
- **Churn limit (CH-1, implemented, uncommitted until its tests pass):** stake added within an epoch (join,
  add_stake, delegation deposit) is capped at 10 % of C_E's stake, enforced in Move; exits are
  not capped. It protects takeover speed (1/3 needs ≥ 5 epochs) and newcomer liveness, not
  weak subjectivity (U > checkpoint age here). Derivation and sources:
  `docs/research/churn_limit.md`. Required before the validator set opens to independent
  operators, which precedes public mainnet.
- **The BT-1 drift alarm** (done): a node alarms when the T of the blocks it places differs
  from its clock by more than 60 s for 3 blocks in a row (`[BT-1 ALARM]` in the log,
  `clock_drift_alarm_secs` in `aincore_getStatus`). Witness:
  `a_node_whose_clock_drifts_from_the_chain_alarms`.
- **Recovery after a certificate-conflict halt** (G1 CE-3, done): the operator procedure is
  `docs/CERT_CONFLICT_RECOVERY_RUNBOOK.md`, and its tool is `cert_recovery` (inspect, choose,
  export, pin). Pinning verifies the canonical certificate under C_E, replaces the slot's
  certificate row, takes the certified role from the other digest and clears the alarm in one
  transaction; it refuses a node that ordered the other digest, which is restored by state
  sync. Witness: `the_recovery_tool_pins_the_canonical_certificate_on_every_node`.
- **A genesis from public entries** (done): `genesis-tool validator-entry` prints a
  validator's public entry, signed by its node key, and `gen-multi --entries-file` builds the
  genesis from them, so no operator's seed leaves its machine. Required before independent
  operators join. Witnesses: `public_entries_build_the_same_genesis_as_the_seeds`,
  `a_forged_or_borrowed_entry_is_refused`.
