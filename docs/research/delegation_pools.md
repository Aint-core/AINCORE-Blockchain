# Delegation pools with constant work per operation (G5 S3)

- **Date:** 2026-10-01. Code read at `0873859` and `4730a90` (branch `g1/certified-dag`).
- **Method:** one research pass that had to fetch its primary sources: source code,
  specifications, the F1 paper, issues, pull requests and security advisories. This document
  states the findings in our own words. The sources are listed at the end.
  - **[V]** marks a fact read in a fetched source.
  - **[C]** marks a fact in AINCORE's code.
  - **[I]** marks our own inference or derivation.
- **Decisions:** recorded as rules in `docs/G5_ECONOMICS_CONTRACT.md` (DL-1..DL-3, CM-1,
  SL-1) and implemented in `core/vm_move/stdlib/sources/delegation.move`.

## 1. What was wrong

The delegation module that S3 replaces kept every delegation and every unbonding entry in two
vectors inside one resource at the validator's address [C]. Five defects followed from that
layout. D4, that rewards were never paid, was already known.

| # | Defect | Consequence |
|---|---|---|
| D1 | `delegate`, `undelegate`, `claim_rewards` and the slash scanned the vectors | Each operation cost O(number of delegators) in gas and bytes rewritten [C, I] |
| D2 | The pool slash ran as a second VM call that the executor only logged on failure | About 50,000 delegations of 1 AIN (≈ 50 k AIN) make the slash run out of gas, and every delegator then escapes it [C, I] |
| D3 | A pool-wide cap of 100 unbonding entries, emptied only by their owners | 100 entries of 1 AIN block every other delegator's exit [C] |
| D5 | `amount × index` in u128, with the index scaled by 10¹⁸ | It overflows once `amount × index` passes 340 AIN, about 65 days at 1.9 %/yr for a 100,000 AIN delegation. The delegator's stake then freezes for good [C, I] |
| D6, D7 | The slash cut every unbonding entry, including stake that left before the infraction, and it was not atomic with the validator's own slash | Over-slashing, or a half-applied slash [C] |

D2 is the same class as the AUDIT-#3 finding: a loop whose length an attacker controls.
Capping the vector trades that for D3. Only a layout without such a loop removes both [I].

## 2. How production pools stay constant-cost

Every production design keeps aggregates in the pool and each delegator's state in a record
of its own. No operation iterates over delegators [V].

| | Aptos `delegation_pool` | Polkadot nomination pools | Sui `staking_pool` | Cosmos F1 |
|---|---|---|---|---|
| Delegator state | table entry | `PoolMember`, its own storage key | an owned `StakedSui` object | `DelegatorStartingInfo`, its own key |
| Principal | shares; price = coins / shares | points; price = balance / points | pool tokens and an exchange-rate history | tokens / shares |
| Rewards | compound through the share price | liquid, through a per-point reward counter | compound through the exchange rate | liquid, through cumulative ratios per period |
| Unbonding | one share pool per lockup cycle, withdrawn by the owner | up to 32 era buckets, withdrawn by the owner | none | ≤ 7 entries per delegator and validator, completed automatically |
| Slash on active stake | through the price | through the points-to-balance ratio | none (rewards only) | through the price |
| Slash on unbonding stake | none | eagerly on era buckets at or after the slash era | none | per entry at or after the infraction height, iterated without gas |

The Polkadot pallet states the goal directly: every operation is independent of the number of
members, because member data is stored with the member [V]. The F1 paper makes the matching
point for slashing: a slash cannot iterate over all delegators, so each delegator's reward
calculation replays the slash events of its period instead [V].

All four rely on a keyed map (tables, storage maps or objects). AINCORE's Move stdlib has none.
We get the same property by putting each delegator's record at the delegator's own address
[I].

## 3. Attacks, and the rule each one teaches

1. **Share inflation and the first depositor.** In an empty or nearly empty vault, a
   "donation" can inflate the share price so that the next depositor's shares round to little
   or nothing. That is the ERC-4626 attack; OpenZeppelin adds virtual shares against it [V].
   Production answers are these [V]:
   - Aptos keeps a minimum of 10 APT per holder;
   - Polkadot refuses joins once points exceed 10× the balance;
   - Cosmos refuses delegation to a validator with shares but no tokens.

   In our pools the price moves only when a slash happens, and there is no donation path.
   Rules: a slashed pool is closed, and an empty open pool holds no coins (§4.3).
2. **Rounding direction.** EIP-4626 rounds in the vault's favour: shares issued and assets
   paid round down, shares burned and assets taken round up [V]. Cosmos truncates, Polkadot
   rounds slashes up, and Aptos and Sui floor both conversions [V]. Rule: always round
   against the user or the slashed party.
3. **Dust must not abort anything.** Sui PR #7571: a reward withdrawal aborted because the
   pool held one unit less than the rounded claim. The fix clamps to the balance [V].
   Polkadot #13147 (2026-09-09): floored member balances sum below the pool total, so an
   exact-equality invariant rejects valid states [V]. Rules: clamp every escrow payout, and
   write the invariants as bounds, not equalities.
4. **Reward timing.** Three production cases [V]:
   - Cosmos #2764: an approximate index let a proposer capture others' fees.
   - Substrate #10861 and #11669: pool joiners shared other members' unclaimed rewards. The
     fix introduced the reward counter and a migration of every pool.
   - Aptos charges new stake a refundable fee equal to the dilution it causes.

   Rule: an exact counter with a snapshot per position, so a joiner starts at the current
   counter.
5. **Commission changes.** A validator must not be able to raise the commission after rewards
   have accrued [V]:
   - Solana issue #28628: validators switched 0 → 100 → 0 % around epoch boundaries.
   - Polkadot applies the rate in force when rewards enter the pool.
   - Aptos caps each increase and requires notice.

   Rule: charge a payout at the rate in force when its period began.
6. **Slash evasion.** Cosmos advisory ASA-2024-005: stake escaped a pending slash through
   redelegation [V]. D2 above escapes a slash by gas exhaustion. Rules: every move of stake
   carries its liability, and the slash path has no loop an attacker can lengthen.
7. **Precision.** Products of two balance-sized numbers reach 2.25·10⁵² at our supply,
   beyond u128 [I]. Aptos and Polkadot widen these products internally [V]. Rule: form
   them in u256 (`0x1::math`).

We found no public audit report dedicated to Aptos `delegation_pool`, Polkadot's nomination
pools or Sui's `staking_pool`. The defects above come from issues, pull requests and
advisories.

## 4. The design

### 4.1 State

- **`Pool`**, at the validator's address, of fixed size:
  - C, the active principal, and P, the points of all positions;
  - ρ, the rewards per point scaled by S = 10¹⁸, with κ < P its carried remainder;
  - B, the nominal amount of the pool's unpaid tickets;
  - the principal escrow (C + B) and the reward escrow;
  - the commission (the rate, one pending change, its effective time);
  - `closed`, the slash count, the ticket and position counts, and at most 8 slash events.
- **`Book`**, at the delegator's address: at most 8 positions (pool, points, snapshot σ) and
  at most 16 unbonding tickets.
  - A ticket holds its pool, amount, creation epoch, the pool's slash count at creation, and
    its unlock time.

### 4.2 Operations

| Operation | Effect |
|---|---|
| settle (before any change to a position) | pay ⌊p·(ρ − σ)/S⌋, clamped to the reward escrow; σ ← ρ |
| delegate a | points ⌊a·P/C⌋ (a when P = 0); C += a, P += points |
| undelegate a | burn q = ⌈a·P/C⌉ points, ticket x = ⌊q·C/P⌋ coins; a remainder below 1 AIN, or a ≥ the position's value, exits in full |
| withdraw | pay each matured ticket, cut by every slash event that reaches it; burn the cut |
| payout (every R blocks, by the executor) | for each committee member: r_s = ⌊r·s/b⌋ and r_d = ⌊r·d/b⌋ from the frozen split; m = ⌊r_d·c*/10⁴⌋ at the rate c* in force when the period began; the validator gets r_s + m; the pool gets π = r_d − m, with ρ += ⌊(π·S + κ)/P⌋ and κ ← the remainder |
| slash f for epoch E_i | the validator's own stake and the pool in one call; C −= ⌈C·f⌉, burned; the pool closes; if tickets exist, record (E_i, sequence, f, tickets outstanding) |

A ticket is reached by an event when it was made before the slash (its recorded slash count
is at most the event's sequence) and in the infraction's epoch or later. Stake that left
during E_i still weighed the frozen committee of E_i, so it is liable. The sequence number
makes this exact whatever the order of slashes and transactions inside a block, and a ticket
made after a slash is never cut by it [I].

### 4.3 Why an open pool cannot be inflated

Deposits round points down, and exits round burned points up and coins down. So each operation
can only raise the price C/P, by less than two base units [I]. A slash lowers it, and a slash
closes the pool for good. Hence:
- in an open pool, P ≤ C;
- P = 0 implies C = 0, because the last exit takes exactly C;
- a first depositor starts at 1:1 and inherits nothing;
- coins enter the principal only through `delegate`, so there is no donation path.

The Polkadot and Cosmos guards (§3.1) would therefore never fire. The pool keeps the rule that
makes them unnecessary.

### 4.4 Bounds

- ρ stays in u128: with P ≥ 10¹⁸ (a pool with fewer points takes no reward), each step adds
  at most π + 1, so ρ stays below the total emission (1.5·10²⁶) [I].
- p·(ρ − σ) and π·S reach about 10⁵²; they are formed in u256 [I].
- The reward escrow exceeds the sum of all claims by at most P/S + positions + 1 base units:
  κ/S, plus the flooring of each claim [I]. For a 10⁸ AIN pool that is about 10⁻¹⁰ AIN.
- One member's payout mints at most its share r. The payout draws the emission as one
  `staking::Emission` value with no abilities, so Move itself forces every unit to a
  recipient or back to the reserve, in the same transaction [C].

### 4.5 Constants

| Name | Value | Basis |
|---|---|---|
| Minimum delegation, undelegation and remainder | 1 AIN | kept from the old module; Aptos rounds a partial exit below its minimum up to a full one [V] |
| Positions per account | 8 | bounds a `Book` load |
| Tickets per account | 16 | Cosmos allows 7 per delegator and validator, Polkadot 32 per member [V]. Counted per account, so no one can fill another's |
| Points for a pool to take rewards | 10¹⁸ | bounds each counter step (§4.4) |
| S | 10¹⁸ | Polkadot's `RewardCounter` is FixedU128 [V]; a typical reward per point is about 10⁻⁷ units, so S = 1 would round it away [I] |
| Slash events per pool | 8 | bounds a ticket's payout. An event is dropped once its tickets are paid. Past the bound the two oldest merge into one that cuts at least as much, for the earlier epoch and the later sequence |

## 5. Decisions that changed during design

- **Delegator unbonding is withdrawn by its owner, not paid automatically.**
  - The first draft linked every ticket into one global queue through the delegators' books,
    so the payout could sweep matured tickets.
  - Writing a neighbour's book from another account's transaction cannot be declared as a
    conflict key, and it couples unrelated accounts.
  - Polkadot, Aptos, Solana and NEAR all leave unbonded stake until the owner withdraws it
    [V]. The per-account cap already removes D3.
  - Validator unbonding stays automatic (UB-1).
- **A slash sequence, not a height.** The draft compared a ticket's creation height with the
  slash's height. That is correct only because slashes run before transactions in a block. The
  sequence number does not depend on that order [I].
- **A slashed pool closes for good.** It then weighs nothing and earns nothing, so later
  committees do not count it and the number of events it can gather stays small. Cosmos
  tombstones a double-signing validator for good [V].
- **The dust bound.** The draft wrote the escrow bound as positions + 1. It is
  P/S + positions + 1, because the carry κ stays in the escrow; the S3 witness found this.

## 6. What is proved, and where

The contract's S3 row lists the witnesses. Each runs real blocks through the executor. Every
item of the kill list (DL-1..DL-3, CM-1, SL-1) is a mutation that one of them must fail.

- `g5_delegators_are_paid_by_points_from_the_frozen_split`:
  - each payout's two parts match the frozen split to the unit;
  - ρ·P + κ = S·Σπ exactly;
  - a joiner starts at the counter, and a mid-epoch join moves neither the split nor the
    weight;
  - the claim is exact, and the conservation bounds hold.
- `g5_commission_is_charged_at_the_rate_in_force_when_the_period_began`.
- `g5_slash_cuts_stake_pool_and_reached_tickets_in_one_call`:
  - the three ticket cases;
  - the closed pool;
  - the spent event is dropped.
- `g5_a_full_account_blocks_only_its_own_undelegation`.
- `g5_a_pool_does_not_grow_with_its_delegators`.
- `g5_pool_arithmetic_rounds_for_the_pool_and_never_aborts_on_dust`: exact rounding at a
  non-unit price, a claim past u128, and a claim one unit short.

## 7. Residual risks

1. **Joiners after an infraction are slashed** if they joined before the evidence lands.
   Polkadot issue #460 and the Cosmos effective fraction behave the same way [V]. Evidence
   normally lands within rounds, but W allows up to 21 days. The exact fix, join cohorts per
   epoch, needs per-epoch aggregates. S4 decides the slash fraction; a 100 % fraction makes
   this sharper.
2. **One epoch of weight against reward.** A joiner earns from the next payout but weighs the
   committee from the next epoch. The gain is at most one epoch's yield, about 4·10⁻⁶ of the
   stake. Repeating it costs an exit of U with no yield, about 1.1·10⁻³, so it does not pay
   [I].
3. **Deferred burn.** A ticket's slashed part is burned when the ticket is withdrawn. Until
   then it counts in `total_supply`. Emission is unaffected, since it is anchored on the
   minted total (AUDIT-#8) [C].
4. **Merged events** over-cut a ticket that only one of the two would have reached. This
   needs more than 8 slashes of one pool with tickets still unpaid from all of them.

## Sources (fetched 2026-10-01)

- Aptos:
  - `delegation_pool.move`, `pool_u64_unbound.move` and `stake.move` in
    https://github.com/aptos-labs/aptos-core (aptos-move/framework);
  - AIP-6, https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-006-delegation-pool-for-node-operators.md;
  - pull requests #13230, #16283 and #11608.
- Polkadot:
  - `pallet-nomination-pools` and `StakingLedger::slash` in
    https://github.com/paritytech/polkadot-sdk (substrate/frame);
  - the relay runtime configuration in https://github.com/polkadot-fellows/runtimes;
  - issues #460, #416 and #13147, and Substrate #10861 and PR #11669.
- Sui: `staking_pool.move`, `validator.move` and `validator_set.move` in
  https://github.com/MystenLabs/sui (sui-system); pull requests #7571, #20022 and #8768.
- Cosmos:
  - D. Ojha and C. Goes, "F1 Fee Distribution", Tokenomics 2019,
    https://drops.dagstuhl.de/opus/volltexte/2020/11974/pdf/OASIcs-Tokenomics-2019-10.pdf;
  - `x/distribution`, `x/staking` and `x/slashing` in https://github.com/cosmos/cosmos-sdk;
  - issues #2764 and #8914, and advisory ASA-2024-005 (GHSA-86h5-xcpx-cfqc).
- Vaults and rounding:
  - EIP-4626, https://eips.ethereum.org/EIPS/eip-4626;
  - OpenZeppelin `ERC4626.sol`, https://github.com/OpenZeppelin/openzeppelin-contracts.
- Solana: issue #28628 (commission switching around epoch boundaries).
- Audit repositories searched, with no relevant report found:
  - https://github.com/srlabs/audit-reports
  - https://github.com/oak-security/audit-reports
  - https://security.parity.io/audits
