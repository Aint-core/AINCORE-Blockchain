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

**DL-1 (bonded stake).** A validator's bonded stake is its own stake plus its pool's active
delegated principal. At each boundary H_E, after the payout, the executor recomputes every
live member's bonded stake from Move state into `sys:validator_set:v1`, so C_{E+1} is weighted
by bonded stake. It records the split next to the committee
(`sys:validator_set:epoch_delegated:{E+1}`). A delegation therefore changes committee weight
at the next epoch, never inside one.

**DL-2 (delegator rewards).** A pool keeps aggregates only (docs/research/delegation_pools.md
§4): active principal C, points P, a reward counter ρ scaled by S = 10¹⁸ with a carried
remainder κ, a principal escrow (C plus unbonding) and a reward escrow.
- **Split.** A payout gives member v its clipped share r_v (EM-2), split with the frozen
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
  `delegation::slash`, so a slash cannot be half applied.

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
| **S3** | DL-1..DL-3, CM-1 in the payout, the atomic slash: pools of aggregates with per-account positions and tickets; the reward split from the frozen record; bonded weight at boundaries; `math` u256 mul_div; the RPC reads the Move state | conservation: principal escrow = C + unbonding, Σ points = P, reward escrow covers every claim within dust; ρ·P + κ = S·Σπ exactly; each payout's two parts match the frozen split to the unit, and a mid-epoch joiner does not move it; a delegator is paid ⌊p·Δρ/S⌋ to the unit and a joiner nothing from before; weight changes at the next epoch only; commission uses the rate at the period start; the active and ticket slash follow SL-1 in one call; a closed pool refuses deposits; a pool's stored size does not grow with its delegators; a full account cannot block another's undelegation; exits and deposits round the pool's way; a claim past u128 works and a 1-unit shortfall does not abort | the carry dropped; points rounded up on deposit; coins rounded up on exit; deposits into a dead pool; tickets of an earlier epoch slashed; the applied-height guard dropped; live stake used in the split; a vector of delegators in the pool; the escrow clamp removed; u128 intermediates |
| **S4a** | Amendment A2 policy: SL-4..SL-6, acceptance and settlement in Move, the offense ledger, the tombstone, W = 7 d and D = 1 d pinned | SL-4 to the basis point (isolated 1/4, 1/10, 1/100 of weight; a third); offenses within D count together, beyond D they do not; 3Q ≥ T settles at once at 100 %; otherwise nothing settles before τ_v + D + I·C_τ + W; the waterfall leaves delegators whole when the operator covers A; in-scope own unbonding is cut, earlier entries are not; a leaver that equivocates before its unlock loses its unbonding stake; every in-scope entry is still unpaid at settlement; a tombstoned join is refused | floor dropped; linear instead of square; threshold at half; D unbounded or zero; settlement before the deadline; waterfall reversed; pool left open at acceptance; out-of-scope entries cut |
| **S4b** | SL-3: V4 proposer twins detected when a slot stages a second digest, kept in durable epoch-keyed rows before GC, carried through the DAG and verified against C_E with the age bound | a twin pair from real V4 nodes is recorded, carried in a block and jails its author on every node; a pair signed by a non-member of C_E (even a live validator), from another domain, of two slots or of an unrecorded epoch is refused; evidence of epoch 0 is accepted until τ_start(1) + W exactly and refused after; accepted, the offense is recorded in the evidence's own epoch | live-set membership; no age bound; a round-only key; the V3 hash |
| **S4d** | SL-3's certificate-conflict kind: `join_validator_set` and committee validation refuse a BLS key already held; the attestation and certificate types move to `blockchain::attest`, so the executor checks the aggregates; the halting node keeps the pair; every signer in both is convicted | real V4 nodes keep the pair where CE-3 halts, and it convicts exactly the members in both; two convicts forming half the committee settle at 100 % at once; one digest, no member in both, another committee, a bit past the committee or a forged aggregate is refused; a shared BLS key is refused at join and in a committee | a duplicate key accepted; the intersection taken from one certificate |
| **S4c** | G1 S11b part 2: V3 ingress, producer, recovery and evidence deleted; the V3-fixture witnesses re-expressed on V4 | the release gate's V3-fixture witnesses pass on V4 fixtures; a V4 node never records V3 evidence (kept from S11b) | — |
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
