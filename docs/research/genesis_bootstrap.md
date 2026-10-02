# Genesis bootstrap: a PoS launch without a pre-mine

Status: **accepted by the founder 2026-10-02** ("follow your proposal; build and complete what is missing"). BW-1 is to be built as G5 amendment A4. The testnet launches first with S_min = 18.5 M as ordinary stake on the four founder validators (4 x 4.625 M), recorded as a stand-in until A4 lands.
Supersedes the stake number in `genesis_allocation.md` (S = 15 M had lost its derivation).
Three research passes (launch precedents, distribution and inflation literature, public entry
mechanisms) read primary sources: genesis files, ledger code, specs and papers. Every number
below comes from `genesis_bootstrap_model.py` next to this file.

## Goals (founder, 2026-10-02)

The chain is a public good, like Bitcoin: no pre-mine or business allocation for anyone
(the founder included), no hyperinflation, secure from block 1, and decentralized before
public use.

## What the evidence says

**PoS needs weight at block 1; a pre-mine is one way to supply it, not the only one.**
- Polkadot launched with six Web3 Foundation validators holding **no stake** (genesis decoded:
  0 balance, nothing bonded), no era payouts (`ForceEra = ForceNone`), transfers locked; NPoS
  came by a Sudo-triggered election three weeks later.
- Cardano's federated nodes held no stake; emission was minted only in proportion to blocks
  made by stake pools, and the shortfall stayed in the reserve (`PulsingReward.hs`).
- NEAR and Avalanche ended their bootstrap by protocol rules: a 2/3-stake vote (NEAR) and
  stake that expires on a staggered schedule (Avalanche, 90 days).
- No chain has combined these into a no-pre-mine launch. All had public holders at genesis
  (sales, claims, ETH deposits).

**A pre-mine is permanent.** With proportional rewards and everyone staking, each holder's
share is a martingale whose limit has the starting share as its mean (Roşu, Saleh,
Management Science 2021, Prop. 1). Issuance dilutes only non-stakers. Fanti et al. (FC 2019):
a large initial stake pool lowers the variance of shares.

**Launch inflation of PoS chains, year 1, of total supply** (from genesis files and code):
Cardano 4.0 %, Tezos 4.8 %, NEAR 5.0 %, Aptos 6.0 %, Cosmos ~7 %, Solana ~7.4 %,
Polkadot 9.3 %. Cagan's hyperinflation is prices rising more than 50 % in a month; no paper
transfers it, or Khan and Senhadji's 11–12 %/yr growth threshold, to token supply.

**Public entry without money.** Incentivized testnets chose validators but distributed
little (Cosmos Game of Stakes 0.12 % of supply to 54 addresses; Celestia's 75 genesis
validators 0.31 %); stake came from foundations and investors. Airdrops are sold fast
(13.6–65.8 % in the first transfer, Messias et al.) and attract sybils (Gitcoin GR14: 22 %).
Foundation delegation with objective, automatic rules (Solana Foundation: uptime, commission
≤ 5 %, stake caps, automatic withdrawal) is the closest model for weight that nobody owns.

## The trade-off, proven

With owned genesis stake S and emission 1.90 %/yr of the remaining reserve:
year-1 supply growth = 0.019 (150 M − S) / S. The precedent band (≤ 10 %) needs S ≥ 24 M,
which is a 16 % pre-mine that stays (Roşu–Saleh). A small S is fair but its supply grows
fast. No paper picks the point: an owned S trades inflation against a pre-mine.

The way out is weight that nobody owns.

## BW-1: bootstrap weight

1. **Bootstrap weight B: consensus weight with no coins.** It is owned by nobody and
   delegated by objective on-chain rules to qualified operators: uptime, commission cap,
   per-operator cap, and automatic withdrawal on failure, as the Solana Foundation does. The
   founder's machines are operators under the same rules, with at most 30 % of the committee.
2. **Owned stake P starts with what was earned.** P0 is paid at genesis, already bonded, to
   participants who earned it on the incentivized testnet (operators, plus a public track for
   completed tasks), capped per participant. The founder receives none.
3. **Emission is unchanged.** 1.90 %/yr of the remaining reserve, all minted to the people
   doing the work: B's share to the operators who run it (as mining pays miners), P's share
   to its owners.
4. **Handover is automatic.** B = max(0, S_min − P). B fills the gap to a minimum committee
   weight and shrinks as owned stake grows; nobody decides when.

**Rewards by weight.** Emission is paid by committee weight, pot × w / W (G5 A4 BW-7). The
earlier saturation clip paid every seat the same slice below 50 members and was removed after
review. The model's totals assume the whole draw is paid, which this keeps.

**Comparison with Bitcoin.** Bitcoin issued 2.628 M BTC/yr at launch: 12.5 % of its cap
per year. BW-1 issues 1.9 % of the cap per year, 6.6 times slower. Both start from almost no
owned supply, so growth measured against circulating supply is high at first in both.

## Parameters

| Parameter | Value | Basis | Kind |
|---|---|---|---|
| Emission | 1.90 %/yr of the remaining reserve | G5 EM-1 (unchanged) | decided earlier |
| P0, earned at genesis | 1.5 M (1 % of cap) | Keeps every month's owned-supply growth below Cagan's 50 % with margin: 0.30 % gives 52 % in month 1, 0.50 % gives 31 %, 1 % gives 15 %. Testnets gave 0.12–0.31 %, but those chains also had sales | math (bound) + choice of margin |
| S_min | 18.5 M | Owned stake passes 2/3 of the committee (bootstrap weight below 1/3 cannot break safety alone) within 4 years, about one Bitcoin halving period | math given the 4-year target, which is a choice |
| B at genesis | 17.5 M (= S_min − the 1.0 M bonded) | the public track's 0.5 M is liquid at genesis and counts once staked | math |
| Founder share of B | ≤ 30 % | decided 2026-10-01 (founder < 1/3) | decided |
| Founder pre-mine | 0 | goal | decided |

With these: owned stake passes 1/3 of the committee at 1.7 years and 2/3 at 4.0 years, and
the bootstrap weight is gone at 6.4 years, if the whole 1.5 M is staked. With only the
operators' 1.0 M staked: 1.9, 4.2 and 6.6 years (`genesis_bootstrap_model.py`, P0 = 1.0 M);
the bootstrap ends U (21 days) after that. The worst month for owned-supply growth is 15 %
(the supply holds the whole 1.5 M either way).

| S_min | Owned > 1/3 | Owned > 2/3 | Bootstrap gone |
|---|---|---|---|
| 18.5 M | 1.7 y | 4.0 y | 6.4 y |
| 20 M | 1.9 y | 4.4 y | 7.0 y |
| 24 M | 2.4 y | 5.4 y | 8.6 y |

(All rows at P0 = 1.5 M.)

## Honest risks

- **Until owned stake passes 2/3 (~4 years), safety rests partly on operators' honesty.**
  Bootstrap weight is not slashable money. This is the authority phase that Polkadot and NEAR
  ran openly. Two things mitigate it:
  - many independent operators under public, automatic rules;
  - slashing of their own stake, and loss of delegation and income.
  It must be stated publicly.
- **Operational decentralization comes at launch** (independent operators). **Economic
  decentralization** (who owns stake) comes gradually, as it did for Bitcoin.
- **Concentration.** Early operators earn most of the emission. Per-operator caps and
  automatic rebalancing are the defence, plus the churn limit CH-1.
- **Handover gaming.** Bootstrap weight is never counted in any vote or threshold (NEAR's
  handover vote counted the foundation's own stake).
- **Exchange capture once a market exists** (Steem, 2020).

## Revision after review (2026-10-02)

Two rounds of three independent reviews changed these rules. The G5 contract, Amendment A4,
has the rules and the findings; this is why.

- **The founder must stay below a third after forfeits (BW-11).** With the founder at 30 %
  and three operators of 23.3 % each, one operator's forfeit puts the founder at 38 %. Each
  boundary now cuts bootstrap weight so that no party reaches a third, and the cut goes to
  nobody. The founder's validators are one party, declared at genesis, so splitting them
  changes nothing. With five operators (IT-5) the founder stays below a third through four
  forfeits; the table is in the contract's BW-11. Only with two large parties left does the
  committee shrink to what the small members can balance.
- **Losing the weight needs a week, not five hours (BW-6).** Participation is measured
  against each operator's exact leader slots, taken from the leader schedule, as a moving
  average with a 6.9-day half-life, and the weight is forfeited below one half. Measured on
  AINCORE-TESTNET-V4, honest validators commit 88–92 % of their slots.
- **s_min is a floor while the bootstrap lasts (BW-4).** Bootstrap weight regrows toward
  each operator's genesis weight when owned stake leaves, scaled against the genesis
  ceilings so that a forfeit frees weight for nobody, and ends for good once owned stake has
  held s_min in the elected committee for U (21 days).
- **Paid by weight, against at least s_min (BW-7).** See above; a forfeited or capped share
  stays in the reserve, so no one earns more from another's loss.

## The founder's earnings (a decision for the founder)

Paid by weight, the founder's validators earn about 30 % of the emission at launch, falling
as owned stake replaces bootstrap weight. If every party restakes everything, the founder
ends the bootstrap with about 5.05 M owned (27 % of owned stake, 3.4 % of the cap): a slow
allocation earned by running the chain, as Bitcoin's early miners earned theirs (second
review MEDIUM-6). Two consistent choices:
- **Keep it:** the founder's validators are paid like any operator's.
- **Waive it:** the founder's bootstrap weight is unpaid; its share stays in the reserve
  for later stakers, and the founder runs its validators as a public service. This also
  removes any income motive the founder could have to shrink rivals' weight.

The protocol supports either; waiving needs a genesis flag on the founder's entity and a
change in the payout (its weight counted in W, its share not paid).

## What has to be built

1. Committee weight that includes delegated bootstrap weight (no coins), recorded per epoch.
2. Reward routing for B's share to its operators.
3. The decay rule.
4. The operator rules, enforced automatically.
5. Incentivized-testnet scoring that produces P0 objectively.

This is a G5 amendment (A4) with tests, mutation and review like the others. The testnet is
where P0 is earned, so the testnet runs before BW-1 reaches mainnet.
