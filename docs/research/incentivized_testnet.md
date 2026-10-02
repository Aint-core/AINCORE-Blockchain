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
- in at least 90 % of its judged epochs it led at least a third of its expected blocks (the
  same test as BW-6, so the testnet rehearses mainnet's rule);
- it was never jailed or convicted;
- it is not the founder.

90 % sits between Solana's baseline (5 of 10 epochs) and its vote-credit bar (97 %).

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
  (18.5 − 5.55) / 3 ≈ 4.3 M, 23 %.

**IT-6 (public track).** Points for actions on the testnet chain:
- a transfer, 1 point;
- a delegation held for one epoch, 3 points;
- a DEX swap or added liquidity, 2 points;
- a governance vote, 2 points.

An account counts only if its points fall on at least 3 distinct days (Arbitrum's rule against
burst farming). The 0.5 M is split pro rata by points, capped at 1,000 AIN per account. What
the cap leaves is not minted: it stays in the emission reserve.

**IT-7 (reproducibility).** The scoring tool reads only chain data, and anyone running a
testnet node can rerun it to the same output:
- block proposers;
- the committee record per epoch;
- jail and conviction records;
- transactions.

## Known limits

- One person can run several qualified validators or many public accounts. Defences:
  - Operators must run real nodes for 14 days and meet IT-3, and each share is capped.
  - Public accounts must act on 3 distinct days, and each account is capped at 1,000 AIN.
  - Neither defence makes sybils impossible; they make them expensive (Douceur).
- Test AIN for joining the testnet comes from the founder's validators' rewards. Who gets it is
  a gate the founder controls. The rules should be published so the gate is predictable:
  first come, same amount each.
