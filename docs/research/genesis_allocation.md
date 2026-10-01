# Genesis allocation: what can be derived and what is a founder decision

Status: **accepted by the founder 2026-10-02** ("I follow your proposal, as long as it is
accountable and follows the math, economics and papers"): S = 15 M, F = 5 M, T = 0, founder
≤ 30 %, operators' stake by option B (founder-owned, delegated). U is sized by R4 when the
operators and their costs are known, and needs the founder's funds. Inputs: cap 150 M AIN; emission 1.90 %/yr of the
remaining reserve by consensus time (G5 EM-1); the founder's locked model (no dev-fund pre-mine,
a DEX float, the founder earns as a validator; `launch-economic-model`); decentralization before
public mainnet (founder < 1/3 of committee stake, independent operators with their own keys);
the churn limit CH-1 (10 % of the committee's stake added per epoch, `churn_limit.md`); the float
analysis in `docs/AINCORE_EMISSION_CALIBRATION.md` §3, §8, §9. References are in
`docs/AINCORE_BIBLIOGRAPHY.md`.

## Revision 2026-10-02 (founder): no business inputs

The founder removed every business input: nothing in the design may depend on someone funding
it (the DEX's USD side, operators' server costs, a treasury). The chain is a public good: usable
by anyone, fast, secure, cheap, decentralized, and never hyperinflationary. Consequences:

- **Mainnet genesis = the committee stake only: S = 15 M, F = 0, T = 0.** 135 M (90 % of the
  cap) is emitted. R4 is dropped (no founder-funded pool). R2 holds trivially at launch: there
  is no float to buy.
- **Emission stays.** It is not funding: like Bitcoin's block reward, it is what pays strangers
  to run validators, which is what keeps the chain decentralized without anyone's budget.
- **Inflation.** Supply growth with G = 15 M: 17.1 % in year 1, 14.3 % in year 2, 9.5 % in
  year 5, 5.9 % in year 10, 2.0 % in year 30 (1.90 %/yr of the remaining reserve). Cagan's
  hyperinflation threshold is 50 % per month. Bitcoin's supply grew by more than 100 % in 2010,
  ~60 % in 2011 and ~30 % in 2012.
- **Open before public mainnet: a public entry path.** In Bitcoin anyone earns coins with
  hardware alone; in PoS staking needs coins first. With proportional rewards each holder's
  share is a martingale (Roşu, Saleh 2021, C5), so if only genesis holders have coins,
  ownership stays where genesis put it. A non-business path for the public to obtain the first
  AIN (delegated stake to independent operators earning commission, a sybil-resistant free
  distribution, or a lower MIN_STAKE with public delegation) must be designed and researched
  before public mainnet. It can ship as a stdlib change after the chain exists.
- **Testnet** keeps 4 × 3.75 M stake plus 5 M of worthless test coins in the treasury account,
  for testers and DEX testing (the faucet RPC was removed in G3).

The original proposal below is kept for the derivation.

## Notation

S = committee stake at launch (founder F_s plus independent operators O), F = the DEX seed (AIN
side), U = its USD side, T = treasury, G = S + F + T (allocated at genesis), E1 = year-1 emission
= 0.019 × (150 M − G).

## Derived from math (accountable)

| Rule | Formula | Why | Source |
|---|---|---|---|
| R1. Float ≥ year-1 emission | F ≥ E1 (BTC 2010: 1.15×) | Emission sold into a float smaller than itself is a Cagan spiral: the float, not the cap, is the money stock | Cagan 1956 (G1); calibration §3; Binance Research 2024 (H20) |
| R2. Buying the whole float stays below 1/3 | F / (S + F) < 1/3, so S > 2 F | BFT safety and liveness need Byzantine stake < 1/3; at launch the DEX float is all an outsider can buy | Lamport, Shostak, Pease 1982 (A1); Castro, Liskov 1999 (A2) |
| R3. Founder below 1/3 | F_s < S / 3, so O > 2 F_s | The chain must survive every founder node failing (founder decision 2026-10-01) | A1, A2 |
| R4. USD depth | U ≥ 50 × the AIN sold for fiat per month (in USD) | Death-spiral ignition measured at monthly fiat extraction > ~2 % of the pool's USD reserve | calibration §8; Obstfeld, Rogoff 1983 (G5) |
| R5. Attack cost | buying a fraction x of the pool's AIN costs U·x/(1−x) | Constant-product pricing | — |
| R6. Bridged value cap | value bridged in < value of 1/3 of the stake | Cost of corruption (1/3 of stake, slashed 100 % by SL-4) must exceed the profit from corruption | Budish 2025 (C1) |

## Proposal

| Item | Value | Check |
|---|---|---|
| F, DEX seed | 5 M AIN | E1 = 2.47 M/yr, so F / E1 = 2.0× (R1 holds with margin; calibration §0 also recommends 5 M) |
| S, committee stake | 15 M AIN | Buying the whole 5 M float gives 25 % < 33 % (R2); S = 10 M gives exactly 33.3 %, no margin |
| F_s, founder's own validators | ≤ 4.5 M (30 %) | R3 |
| O, independent operators | ≥ 10.5 M, no operator above ~10 % | R3; with fewer operators the founder plus one operator can halt (liveness only; safety still needs > 1/3 signing twice, slashed at 100 %) |
| T, treasury | 0 | No formula sizes a treasury; it is a pre-mine to everyone outside. Bitcoin has none; Zcash (ZIP 1014, 20 %) and Decred (10 %) fund theirs from a share of block rewards instead, which can be added later by a stdlib change |
| G | 20 M (13.3 % of cap) | 130 M stays in the emission reserve |
| U, USD side | ≥ 50 × the operators' monthly fiat costs | 7 operators at $100/mo: $35 k; at $300/mo: $105 k (R4). At $50 k, buying 80 % of the pool costs $200 k and still gives only 21 % of the stake (R2, R5) |

R6 is an operating rule, not a genesis number: bridge caps must keep bridged value below a third
of the stake's market value.

## Founder decisions (economics cannot decide them)

1. **Who owns the operators' 10.5 M.**
   - (A) Granted to the operators at genesis (they own it, like genesis validators elsewhere).
   - (B) Owned by the founder and delegated to operators' pools after launch, as foundation
     delegation programs do (Solana Foundation). Operators hold the keys; the founder's coins
     are slashable if an operator misbehaves (G5: delegators are slashable). Under CH-1 moving
     10.5 M from a 15 M committee takes about 8 epochs (~15 h), before public buy-in opens.
   - B keeps "no coins given to outsiders" but leaves ownership concentrated; A spreads
     ownership but is a grant.
2. **U, the USD side of the DEX pool**: money only the founder can provide, sized by R4.
3. Whether a treasury should exist at all (proposal: no; if yes, from a share of emission).

## Testnet

The testnet should carry the same layout so it exercises it: 15 M stake over the four founder
validators (3.75 M each) and 5 M held for the DEX seed (as the treasury account, until the DEX
is seeded). Its tokens have no value; the numbers matter only as a rehearsal.
