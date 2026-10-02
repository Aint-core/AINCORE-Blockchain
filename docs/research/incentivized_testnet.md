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

**IT-2 (window, and a fair one).** Scoring covers the last 14 days of the incentivized
testnet, about 179 epochs at the measured 6.75 s blocks. One snapshot height is announced in
advance. In every committee of the window the founder's nodes must hold less than a third;
the scoring tool refuses a window where they did not (second review HIGH-3: on a testnet where
the founder holds most of the weight, whether an operator's vertices are certified is the
founder's choice, and a deliberate omission looks like latency).
- The testnet's `s_min` is set so that this follows from IT-5's minimum: the founder's nodes
  own nothing and hold B = s_min − P, which is below a third once P > ⅔ s_min. Five
  operators staking IT-3a's 50 k each make P = 250 k, so s_min_testnet = 1.5 × 250 k =
  **375,000** (the founder's four nodes 93,750 each). Every further operator lowers the
  founder's share; at 375 k of operator stake the bootstrap reaches 0 and, after U, ends,
  which the testnet then rehearses too.
- The window starts once the founder holds less than a third, announced in advance.

**IT-3 (operator qualification).** An operator qualifies if, over the window:
- it is in the committee for at least 90 % of the window's blocks;
- it held leader slots, and committed at least 90 % as large a share of them as the median
  operator did. Slots come from the leader schedule, exactly as BW-6 counts them, so the
  measure has no luck in it and the testnet rehearses mainnet's rule. Relative to the median,
  a slow network does not fail everyone; the median is taken over operators only, so the
  founder's nodes cannot move it;
- its BW-6 score never fell below one half;
- it was never jailed for an offense up to the snapshot;
- it is not the founder.

90 % sits between Solana's delegation bars: a baseline in 5 of the last 10 epochs, and vote
credits at 97 % of the cluster average.

**IT-3a (being measured needs slots).** Slots come in proportion to weight. To measure a
commit ratio near 0.9 within ±0.05 at three standard deviations takes
n ≥ 9 × 0.9 × 0.1 / 0.05² = 324 slots over the window. The window holds about 179 epochs of
about 1,113 anchor rounds (631 rounds for 567 blocks on TESTNET-V4), so an operator needs
324 / (179 × 1,113) = 0.16 % of the committee's weight. The testnet genesis lists a faucet
account (`accounts`, test coins with no value), and every accepted operator applicant receives
50,000 test AIN from it: first come, same amount, published. 50 k is 0.16 % of a committee of
30 M, far above the testnet's.

**IT-3b (one operator, one identity).** Equal shares per qualified address reward running
several (second review HIGH-3: three cheap servers beside three honest operators would take
35 %). No protocol rule can tell one person's nodes apart (Douceur 2002), so the defence is
the genesis ceremony's, as for Cosmos Hub gentxs:
- every applicant publishes an identity statement (person or organization, contact, the
  machines' hosting) signed with its validator key;
- the coordinator refuses applicants whose statements or infrastructure show a shared
  operator, and any parties declared as one entity are capped as one (BW-11);
- the statements are published with the genesis, so anyone can challenge them.

**IT-4 (operator share).**
- The qualified operators share 1.0 M equally.
- With at least five qualified operators no share can reach a third of the mainnet genesis
  committee: even with no founder weight, (18.5 M) / 5 is 20 %.

**IT-5 (bootstrap assignment at mainnet genesis).**
- B0 = s_min − bonded P0 = 18.5 M − 1.0 M = 17.5 M.
- The founder's validators receive at most 30 % of s_min (5.55 M), decided 2026-10-01, and
  are declared as one entity.
- The qualified operators share the rest equally.
- Mainnet needs **at least 5** qualified independent operators: 200 k owned + 2.39 M
  bootstrap each (14 %). With three, one jail (which removes the operator's owned seat too)
  left three parties and the founder at exactly a third (second review M1); with five, the
  founder stays below a third through four forfeits or three jails (BW-11's table).

**IT-6 (public track).** Points for actions on the testnet chain, each kind at most once per
account and UTC day of block time:
- a transfer to another account, 1 point (to itself, none);
- a delegation held for one epoch inside the window (no undelegation from the same pool
  within I blocks), 3 points;
- a DEX swap or added liquidity, 2 points;
- a governance vote, 2 points.

Only transactions whose receipt says they succeeded count; validators of the window's
committees, the founder and the faucet earn nothing on this track. An account counts only if
its points fall on at least 3 distinct days (Arbitrum's rule against burst farming).
- **Funding clusters.** An account's funder is the sender of the first successful transfer
  it received, from genesis on; its cluster is the account the faucet funded at the top of
  that chain (or the chain's root). The 0.5 M is split pro rata by points among clusters,
  each capped at 1,000 AIN, and a cluster's share is split among its accounts by points.
  What the cap leaves is not minted: it stays in the emission reserve.
- Why: transfers cost dust in gas, so without these rules 500 scripted accounts could take
  94 % of the track (second review MEDIUM-4). A farm now needs one faucet claim per cluster,
  and the faucet's claims are the gate (Known limits).

**IT-7 (reproducibility).** The scoring tool (`genesis-tool score-testnet`) reads only chain
data, and anyone running a testnet node can rerun it to the same output. It runs on a stopped
node's datadir at least W (7 days) past the snapshot, so every offense of the window has
landed (SL-5); a jail counts when its offense round is at or before the snapshot's (a
conviction always comes with a jail record). A qualified operator joins mainnet genesis with
the key it qualified with (`gen-multi --allocations-file`). It reads:
- block proposers and anchor rounds, to rebuild the leader schedule;
- the committee record per epoch;
- jail records;
- transactions and their receipts, from genesis (for funding clusters).

## Known limits

- One person can run several qualified validators or many public accounts. Defences:
  - Operators must run real nodes for 14 days, meet IT-3 and publish a signed identity
    (IT-3b); declared parties are capped as one.
  - Public accounts must act on 3 distinct days, each kind once a day, and each funding
    cluster is capped at 1,000 AIN.
  - Neither defence makes sybils impossible; they make them expensive (Douceur).
- Test AIN for joining the testnet comes from the testnet faucet account (IT-3a). Who gets it
  is a gate the founder controls. The rules make the gate predictable: published, first come,
  50 k each for operators, a fixed small amount for the public track.
