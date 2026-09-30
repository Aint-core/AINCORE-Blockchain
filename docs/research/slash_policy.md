# How much to slash for equivocation (G5 amendment A2)

- **Date:** 2026-10-01. Code read at `67f978a` (branch `g1/certified-dag`).
- **Method:** one research pass that fetched its primary sources (specifications, runtime and
  SDK source, governance records, papers, incident reports). This document states the findings
  in our own words.
  - **[V]** marks a fact read in a fetched source.
  - **[V2]** marks a fact from news or forum coverage.
  - **[I]** marks our own inference.
- **Decisions:** `docs/G5_ECONOMICS_CONTRACT.md` SL-3..SL-6 and the W and D rows of P-1.

## 1. The problem

Until A2, AINCORE slashed 100 % of a validator's stake, and 100 % of its pool, for any single
equivocation [C]. No production chain does that for an isolated fault [V]. Every recorded
real-world equivocation was an operator running one key in two places, never an attack [V/V2]:
- Staked.us: 75 validators on one day.
- Launchnodes: 20 validators.
- SSV/Ankr, 2025: 39 validators within 1.5 h, about 1 % lost each.

On AINCORE, app users delegate to operators, so a 100 % penalty for an operator's
configuration mistake falls on them.

## 2. What production chains do

| Chain | Isolated fault | Correlated fault | Who pays | Timing |
|---|---|---|---|---|
| Ethereum (Electra) | balance/4096 at once; about 1 % realized in 2025 [V/V2] | adds `min(3·S, T)/T`, where S is the stake slashed within ±18 days; 100 % at a third [V] | the validator [V] | correlation applied about 18 days later [V] |
| Polkadot | `(3k/n)²` over offenders in the same slot [V] | the same curve, 100 % at a third [V] | validator self-stake only since Referendum 1910 (2026-07) [V] | deferred 27 eras; governance can cancel [V] |
| Cosmos Hub | flat 5 %, validator tombstoned [V] | 5 % (correlated slashing, ADR-014, never implemented) [V] | validator and delegators alike [V] | immediate [V] |
| Aptos, Sui, Solana, NEAR | no principal slashing [V] | — | — | — |

Two lessons:
- **Scale the penalty with correlation.** A safety attack needs at least a third of stake to
  equivocate together, so the fraction should reach 100 % there. Isolated faults, which in
  practice are mistakes, should cost little (Buterin's anti-correlation rationale [V]).
- **Wait for the window.** Slashing at once, with no later top-up, lets an early offender pay
  less than its colluders [V: W3F]. Top-ups need the same waiting that one final settlement
  needs.

## 3. The rule

**Fraction (SL-4)**

  `f = 100 % if 3Q ≥ T, else max(1 %, ⌈(3Q/T)²⌉)`

- Q is the weight of the distinct offenders whose offense epochs began within D = 1 day of each
  other.
- T is the offender's committee weight.
- This is Polkadot's curve, measured in stake instead of in validator count, with Ethereum's
  realized floor.
- It is stake-weighted, so splitting stake across validators does not lower Q [I].
- Worked values [I]:

  | Share of committee weight | f |
  |---|---|
  | 1/100 | 1 % (floor) |
  | 1/10 | 9 % |
  | 1/4 | 56.25 % |
  | ≥ 1/3 | 100 % |

**Window D = 1 day.** Security needs only the offense's own epoch, since an attack is a third
of one committee. The extra day catches correlated operator mistakes, which cluster within
hours in every incident on record [V/V2].

**Evidence age W = 7 days (SL-3).**
- W = T_mis, the misbehaviour budget already reserved in U = T_trust + T_mis
  (`clock_and_deadlines.md`).
- A slash therefore settles within D + I·C_τ + W + one reward period of the offense epoch.
  That is about 8.2 days at launch parameters, well before any stake it reaches can unlock
  (U = 21 days).
- So no extra freeze is needed [I]. `chain::valid` enforces `(I + R)·C_τ + W + D ≤ U`.

**Who pays (SL-6).**
- The operator's own stake takes A = f·(s + d) first; the pool pays only the excess.
- At f = 100 % everyone pays in full, so the cost of an attack is unchanged.
- The model is Rocket Pool's operator bond and Polkadot's validators-bear-risk principle [V/U],
  applied inside the protocol.

**Delegators stay slashable.**
- Committee weight counts delegated stake, and the cost of a safety attack is the slashable
  stake behind a third of that weight (Casper FFG's accountable safety, and the
  cost-of-corruption literature [V]).
- Polkadot's exemption of nominators gives this up [I].
- The founder decided to decentralize before public mainnet (2026-10-01), so the founder-only
  phase is testnet only and no exemption is needed.

**No discretionary cancel.** On AINCORE the founder would be cancelling his own slashes. A slash
traced to a protocol bug is reimbursed openly, with a post-mortem [V: W3F's stated practice].

## 4. Residual risks

1. **Forensics coverage.** 100 % needs proof that more than a third equivocated. Proposer twins
   and certificate conflicts cover same-slot equivocation. The DAG protocol's forensic support
   for every safety violation should be shown [V: Sheng et al., *BFT Protocol Forensics*].
2. **Value at risk.** Slashing deters only while the value an attack can win (bridges, the DEX)
   stays below the stake it burns [V: STAKESURE].
3. **Operations first.** The chain-side rule does not stop a key running twice. The controls are
   a persistent signing guard, duplicate-instance detection before signing, and the G1 rule
   against restoring a validator from backup.

## Sources (fetched 2026-10-01)

- **Ethereum:**
  - consensus-specs (Phase0 to Electra `process_slashings`, `slash_validator`, and the
    constants);
  - V. Buterin, *Serenity design rationale*;
  - incident coverage of Staked.us, Launchnodes and SSV/Ankr.
- **Polkadot:**
  - `polkadot-sdk` `substrate/frame/staking` (the slashing curve and `SlashDeferDuration`);
  - `polkadot-fellows/runtimes`;
  - Referendums 1890 and 1910.
- **Cosmos:**
  - `cosmos-sdk` `x/slashing` and `x/staking`;
  - ADR-014 (proportional slashing);
  - Hub parameters, read live.
- **Aptos, Sui, Solana, NEAR:** the framework sources and SIMD-0204.
- **Papers:**
  - Buterin and Griffith, *Casper the Friendly Finality Gadget*;
  - Sheng et al., *BFT Protocol Forensics*;
  - Deb et al., *STAKESURE*.
