# Incentivized testnet: how P0 is earned (G5 A4-S6)

Status: proposal, 2026-10-02. BW-1 (`genesis_bootstrap.md`) fixes P0 = 1.5 M AIN: the
owned supply at mainnet genesis, earned on the incentivized testnet, with the founder
excluded. This document fixes how it is earned. The rules must be published before the
incentivized testnet starts; nothing below may change during it.

## What the research says (`genesis_bootstrap.md`, entry mechanisms)

- **Testnets select validators well but distribute little.** Cosmos Game of Stakes paid
  0.12 % of supply; Celestia's 75 genesis validators held 0.31 %. Their stake came from sales.
  Here P0 is the stake.
- **Liquid drops are sold fast.** 13.6–65.8 % of tokens moved in the first transfer after an
  airdrop (Messias, Yaish, Livshits); Optimism's median holder sold within 0.30 days.
  **Bonded stake** cannot be sold before unbonding (21 days).
- **Sybils are unavoidable without identity** (Douceur 2002). They are only made expensive:
  - Arbitrum deducted points for activity squeezed into 48 hours;
  - Game of Stakes, even with identity checks, still paid one sybil team.
- **Objective, automatic operator rules work.** The Solana Foundation delegation program polls
  testnet performance (a baseline in 5 of the last 10 epochs, votes at least 97 % of the cluster
  average) and removes stake automatically.

## Rules

**IT-1 (two tracks).**
- **Operator track: 1.0 M AIN, bonded** as operators' genesis stake. It counts toward owned
  stake P, so it speeds BW-1's handover.
- **Public track: 0.5 M AIN, liquid** genesis accounts, for people who use the chain without
  running a validator.

The 2 : 1 split is a choice: security needs bonded stake, and delegation needs holders.

**IT-2 (window).** Scoring covers the last 14 days of the incentivized testnet, about 179
epochs at the measured 6.75 s blocks. One snapshot height is announced in advance.

**IT-3 (operator qualification).** An operator qualifies if, over the window:
- it is in the committee for at least 90 % of the epochs;
- it committed at least 90 % as large a share of its scheduled leader slots as the median
  committee member did. Slots come from the leader schedule, exactly as BW-6 counts them, so
  the measure has no luck in it and the testnet rehearses mainnet's rule. Relative to the
  median, a slow network does not fail everyone;
- its BW-6 score never fell below one half;
- it was never jailed or convicted;
- it is not the founder.

90 % sits between Solana's delegation bars: a baseline in 5 of the last 10 epochs, and vote
credits at 97 % of the cluster average.

**IT-3a (being measured needs slots).** Slots come in proportion to weight. To measure a
commit ratio near 0.9 within ±0.05 at three standard deviations takes
n ≥ 9 × 0.9 × 0.1 / 0.05² = 324 slots over the window. The window holds about 179 epochs of
about 1,113 anchor rounds (631 rounds for 567 blocks on TESTNET-V4), so an operator needs
324 / (179 × 1,113) = 0.16 % of the committee's weight: 30,100 test AIN at 18.5 M. The testnet
genesis therefore lists a faucet account (`accounts`, test coins with no value), and every
accepted operator applicant receives 50,000 test AIN from it: first come, same amount,
published. 50 k keeps the 324 slots while the committee grows up to 30 M. Staking it shrinks
the founder's bootstrap weight (BW-4), so the testnet also rehearses the handover.

**IT-4 (operator share).**
- The qualified operators share 1.0 M equally.
- If equal shares would put any operator at a third or more of the mainnet genesis committee's
  weight (including bootstrap weight), the share is capped and the excess is not minted.

**IT-5 (bootstrap assignment at mainnet genesis).**
- B0 = s_min − bonded P0 = 18.5 M − 1.0 M = 17.5 M.
- The founder's validators receive at most 30 % of s_min (5.55 M), decided 2026-10-01.
- The qualified operators share the rest equally. No operator's total (owned + bootstrap) may
  reach a third.
- Mainnet needs at least 3 qualified independent operators: with 3, each holds about
  (18.5 − 5.55) / 3 ≈ 4.3 M, 23 %. Five or more are recommended: with three, two forfeits
  shrink the committee to about 2 M under BW-11; with five, to about 12.3 M
  (`genesis_bootstrap.md`, revision after review).

**IT-6 (public track).** Points for actions on the testnet chain:
- a transfer to another account, 1 point (to itself, none);
- a delegation held for one epoch inside the window (no undelegation within I blocks), 3 points;
- a DEX swap or added liquidity, 2 points;
- a governance vote, 2 points.

Only transactions whose receipt says they succeeded count, and validators of the window's
committees earn nothing on this track (they have the operator track). An account counts only
if its points fall on at least 3 distinct UTC days of block time (Arbitrum's rule against
burst farming). The 0.5 M is split pro rata by points, capped at 1,000 AIN per account. What
the cap leaves is not minted: it stays in the emission reserve.

**IT-7 (reproducibility).** The scoring tool (`genesis-tool score-testnet`) reads only chain
data, and anyone running a testnet node can rerun it to the same output. It runs on a stopped
node's datadir at least W (7 days) past the snapshot, so every offense of the window has
landed (SL-5); a jail counts when its offense round is at or before the snapshot's. A
qualified operator joins mainnet genesis with the key it qualified with
(`gen-multi --allocations-file`). It reads:
- block proposers and anchor rounds, to rebuild the leader schedule;
- the committee record per epoch;
- jail and conviction records;
- transactions.

## Known limits

- One person can run several qualified validators or many public accounts. Defences:
  - Operators must run real nodes for 14 days and meet IT-3, and each share is capped.
  - Public accounts must act on 3 distinct days, and each account is capped at 1,000 AIN.
  - Neither defence makes sybils impossible; they make them expensive (Douceur).
- Test AIN for joining the testnet comes from the testnet faucet account (IT-3a). Who gets it
  is a gate the founder controls. The rules make the gate predictable: published, first come,
  50 k each for operators, a fixed small amount for the public track.
