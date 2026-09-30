# Clock, unbonding, commission and unclaimed stake (G5 amendment A1)

- **Date:** 2026-09-30. Code read at `65cc92a` (branch `g1/certified-dag`).
- **Method:** three independent research passes, each required to fetch its primary sources
  (papers, specifications, source code, live chain parameters):
  1. a check of every citation in `epoch_and_rewards.md` and `emission_rate_decision.md`,
     whose corrections are recorded at the top of those two documents;
  2. commission-change notice and unclaimed unbonded stake;
  3. unbonding length, epoch length, and deadlines under a changing block time.

  This document states their findings in our own words, with the sources at the end.
  **[V]** marks a fact read in a fetched source. **[C]** marks a fact in AINCORE's code.
  **[I]** marks our own inference or derivation.
- **Decisions:** recorded as rules in `docs/G5_ECONOMICS_CONTRACT.md` (CL-1, BT-1, CL-2,
  P-1, EM-1, UB-1, CM-1, DL-3, SL-2).

## 1. The problem: a block count is not a duration

S1 counted every deadline and the emission in blocks, derived once from the block time t_b
measured at genesis. Nothing in the protocol enforces t_b: the round timer is a node setting
(`AINCORE_CONSENSUS_TICK_MS`, default 3 s, floor 100 ms) [C]. If blocks later run faster, the
same block counts shrink in real time [I]:

| t_b | U = 273,000 blocks | Weak-subjectivity window (2/3·U) | Emission (4,042·10⁻¹² per block) |
|---|---|---|---|
| 6.65 s (measured on V3) | 21.0 d | 14.0 d | 1.90 %/yr |
| 3.3 s | 10.4 d | 7.0 d | 3.79 %/yr |
| 1.0 s | 3.2 d | 2.1 d | 11.98 %/yr |

This has happened in production:
- **Cosmos Hub.** Cosmos x/mint counts emission per block through the governance parameter
  `BlocksPerYear`. The Hub needed two governance proposals to re-pin it (Proposals 1 and 30)
  after measured block times moved away from the assumption [V]. SDK issue #5411 was closed
  without an SDK-level fix [V]. Today the Hub mints about 1.27× its target [V].
- **This project.** Emission was calibrated at 3.59 s blocks, and the chain ran at 6.65 s.
  The same constant then gave 1.90 %/yr instead of 3.5 %/yr (`emission_rate_decision.md`).

Slower blocks and halts only lengthen height-counted deadlines, which is the safe
direction. Faster blocks, the goal of the throughput work, shorten them.

## 2. How production chains keep economic time real [V]

| Chain | Deadlines count in | Emission clock | Block time bound |
|---|---|---|---|
| Ethereum | slots, which are wall-clock time | per slot and epoch | one block per slot; future blocks rejected |
| Polkadot | eras and sessions in slots (slot = timestamp / 6 s) | elapsed era time, capped by `MaxEraDuration` | `MinimumPeriod` 3 s; 30 s future drift |
| Aptos | seconds (14-day lockup, 2-hour epochs) | per time-based epoch | proposer timestamp, strictly increasing, ≤ 5 min ahead |
| Sui | epochs ended by the commit timestamp | per epoch | commit timestamp = stake-weighted median of the leader's parents |
| Cosmos SDK | unbonding by BFT time; evidence by time AND blocks | per block via `BlocksPerYear` (drifts) | none |
| Bitcoin | height; timelocks by median time past | height, kept near 10 min by difficulty retargeting | statistical |

- Every chain whose block rate is not pinned to wall-clock slots counts economic deadlines
  in consensus time [I from the table].
- The one production example of per-block emission under a variable block time (Cosmos
  x/mint) is also the one with a record of repeated re-pins.

## 3. AINCORE already has a Byzantine-resistant timestamp

- **What exists [C].** The block timestamp is `bft_block_timestamp`: one sample per author
  (its latest vertex timestamp), weighted by committee stake, the first timestamp past half
  of the sampled stake, clamped monotone. V4 vertex timestamps are signed, and ingress drops
  vertices more than 30 s in the future.
- **Where the rule comes from [V].** The same median rule is CometBFT's BFT Time, whose spec
  states that the median of any vote set with at least 2f+1 power lies between correct
  values. It is also Bullshark's Algorithm 6 (median of the leader's parents) and Sui's
  commit timestamp.
- **Why it is safe here [I].** A new anchor's round r−1 parents carry more than 2/3 of the
  committee's stake. No earlier anchor can have committed them, so every committed set holds
  a quorum of distinct authors. With Byzantine stake below 1/3 of the total, it is below half
  of the sample.
- **The weak point, now closed [I].** The median is taken over the *sampled* stake, and that
  argument about samples is structural rather than checked. BT-1 checks it: if the sampled
  stake is not a quorum of the committee, the timestamp does not advance.
- **Operations [V].** NTP can be shifted by on-path and even off-path attackers (Malhotra et
  al., NDSS 2016). Validators therefore run authenticated time and a drift alarm.

## 4. The rule: a capped consensus-time clock τ

Four options were compared (research pass 3, §5):

| | Security | Cost | Failure mode | Verdict |
|---|---|---|---|---|
| (a) Count from a minimum block time | valid only if a minimum interval is enforced | new validity rule | AINCORE enforces none. At a 0.5 s floor, U would be 279 days at 6.65 s | reject; keep the idea as a per-block cap |
| **(b) Consensus time, capped per block** | median in the honest range; the cap bounds any failure | one clock field, one comparison | a shifted clock is bounded by the cap | **adopt** |
| (c) Re-derive counts by upgrade | none between the change and the re-pin | process | forgetting it (Cosmos; this project) | escape hatch for the cap only |
| (d) On-chain recalibration | no stronger than (b) | high | timewarp-style manipulation (Bitcoin BIP 54) | reject |

**Definition.** τ(0) = 0, and τ(h) = τ(h−1) + min(T(h) − T(h−1), C_τ). T is the block
timestamp and C_τ = ⌈2·t_b⌉ seconds (14 s at 6.65 s).

**Properties [I].**
1. **Faster blocks.** When T(h) − T(h−1) < C_τ, τ advances at the real-time rate.
   Deadlines and the emission rate hold at any block speed.
2. **Slower blocks and halts.** τ advances at most C_τ per block. A 10-day halt ages every
   deadline by at most 14 s. This keeps S1's "a halt ages nothing" without a catch-up burst:
   Osmosis's time-based epochs do catch up after a halt [V].
3. **Corrupted time.** Suppose the median is wrong: Byzantine stake above 1/3, or most
   honest clocks shifted. τ still advances at most C_τ per block.
   - A 21-day deadline cannot pass in fewer than 1,814,400 / 14 = 129,600 blocks, about
     10 days at 6.65 s.
   - Emission cannot exceed 14 / 6.65 = 2.1× its target, about 3.96 %/yr, and only while
     the fault lasts.
   - This is the "height and time" requirement of Cosmos SDK #6478, with a height floor.
4. **Why a factor of 2.** Missed anchors make single block gaps two to three times the mean.
   A cap of 1× would clip normal jitter and bias every deadline long. A factor in
   [1.5, 3] is defensible [I]; Bitcoin clamps retargets at 4× [V]. At 2×, the
   corrupted-clock floor (about 10 days) stays above the 7-day misbehaviour budget of §5.
5. **Emission stays additive.** τ is a per-block function of the chain, so cumulative
   emission depends only on τ(h). It does not depend on the payout period or on aborted
   payouts. A per-payout minimum would lose this: the minimum of sums is at least the sum of
   minimums.

Heights remain the unit of the committee epoch I and the reward period R. G1's epoch
arithmetic E(h) = ⌊(h−1)/I⌋ is keyed to heights, and I's criteria are throughput and
liveness budgets, not safety conditions (§6).

## 5. Unbonding U = 21 days, derived rather than copied

- **What the literature constrains [V].**
  - **Casper FFG §4.1.** The withdrawal delay must exceed four times the maximum delay
    between clients, and both are real-time quantities.
  - **Light clients.** The trusting period must be shorter than unbonding, checked against
    the client's own clock (CometBFT light-client spec, ICS-07). IBC ADR-026 recommends
    2/3 of unbonding. When trust expires, recovery needs an external, social checkpoint.
  - **Babylon (IEEE S&P 2023).** No proof-of-stake protocol gets slashable safety without an
    external trust source. Long withdrawal delays exist because social checkpoints are slow.
  - **Ethereum's weak-subjectivity period.** For a tiny validator set with no churn limit,
    the spec's formula collapses to the withdrawal delay itself [I, from the spec formula].
- **Derivation [I].** U ≥ T_trust + T_mis.
  - T_trust is the longest time any follower (a restarting node, a light client, a bridge's
    on-chain client) must be able to verify new headers from the committee it trusts.
  - T_mis is the time to detect misbehaviour and land its evidence.
- **Values chosen [I].**
  - **T_trust = 14 d.** This chain has halted for 10 days, and light-client trust expires on
    wall-clock time even with no blocks. A bridge with 7 days of trust would have expired,
    and there is no client-recovery path. 14 d also covers a weekly checkpoint plus a week of
    slack, and matches ADR-026's 2/3 ratio.
  - **T_mis = 7 d.** This leaves a week for human response, the realistic detection channel
    at four founder-run nodes.
- **Result:** U = 21 d of τ, W = U, checkpoints at most 14 days old and published weekly.
  The number equals Cosmos's, but it comes from this chain's own halt history and bridge
  requirement.
- **Revisit:** only if a client-recovery path ships and no bridge depends on AINCORE. Then
  T_trust = 7 d would give U ≈ 10.5 d.

**Counting U from the end of the last committee epoch (SL-2).** A key can sign until
H_{E(h)}, whose τ is not known when the stake leaves at h. The unlock time is therefore set to
τ(h) + I·C_τ + U. Since τ(H_{E(h)}) ≤ τ(h) + (H_{E(h)} − h)·C_τ, this is never earlier than
τ(H_{E(h)}) + U [I]. It is also non-decreasing in h, so the unbonding queue stays sorted by
unlock time, which UB-1 relies on. The extra wait is at most I·C_τ: 3.9 h at I = 1,000.

## 6. Epoch length I

- **Evidence [V].**
  - Sui runs 24-hour epochs in production. Its experiments with an epoch change every 10
    minutes showed no loss of performance (Sui Lutris, §7.4).
  - LibraBFT reconfiguration stops the world, so each boundary costs a fixed amount.
  - Aptos runs its per-epoch key generation (16.8 s, fast path) asynchronously, and its
    epochs last 2 h.
- **Criteria [I].** Both of research (a) 1's criteria are sound: boundary overhead at most
  1 %, and exposure windows at most about 2 h at n = 4, where one abstainer removes all
  slack. The overhead must be split into protocol rounds (independent of block time) and
  wall-clock work (fsync, BLS, the QC(H_E) wait).
- **Result.** With at most 10 s of wall-clock boundary work, I = 1,000 meets both criteria for
  every t_b from 1.0 s to 7.2 s. It stays; the boundary cost is measured before genesis.

## 7. Commission notice N = 7 days and increases of at most 500 bps

- **The attack [V].** In a commission rug, a validator raises commission just before rewards
  are computed and lowers it after. Solana documented cases of 0 → 100 % → 0 % across
  consecutive epochs (issue #28628). Its fix delays any change by at least one full epoch
  (SIMD-0249, active on mainnet). Cardano's formal ledger spec stages pool parameter changes
  so that delegators get an entire epoch to respond.
- **Precedents [V].**
  - Solana: at least one epoch, about 2 d.
  - Cardano: one 5-day epoch.
  - Aptos: at least a quarter of the lockup (3.5 d) ahead, and at most +10 points per
    change.
  - Sui and Polkadot: about 1 day, but delegators there can switch or withdraw freely.
  - Cosmos: immediate, rate-limited per day, with instant redelegation.
- **What a notice cannot do [I].** It removes surprise, not lock-in. Without redelegation, a
  delegator who leaves gives up yield for U whatever the notice is. The switching-cost model
  of Farrell and Klemperer [V] then bounds how far a validator can raise its commission
  before leaving pays: about (1 − c)·U/T. That is 5.5 points for a one-year delegator.
  Only a cap per increase, or real redelegation, lowers it.
- **Decisions [I].**
  - **N = 7 d.** AINCORE has no redelegation and serves app users, so it sits at the
    protective end of the band. A weekly check-in is the natural human cycle.
  - **Δc = 500 bps.** This matches the lock-in bound above. With the 30 % maximum, going from
    0 to 30 % takes at least six notices (six weeks).
  - **Effective time fixed at the announcement** and applied on the pool's next use. Today a
    matured change stays armed and can be applied weeks later without new notice [C]; every
    precedent applies automatically at a boundary [V].
  - **Decreases apply at once** (Cosmos, Polkadot pools, Solana SIMD-0079) [V].

## 8. Unclaimed unbonded stake: pay it, never burn it

- **Today [C].** A validator's unlocked stake left unclaimed for 31 days was burned at an
  epoch boundary.
- **Precedents [V]:**
  - none of the nine systems examined burns unclaimed principal;
  - Cosmos completes unbonding automatically at the end of the block, and Ethereum sweeps
    withdrawals automatically;
  - Polkadot, Aptos, Solana and NEAR keep the stake until the owner withdraws;
  - Sui and Cardano have no lock;
  - the nearest analogues are not principal: Polkadot's unclaimed rewards expire after 84
    eras, and Cardano sends refunds with no valid recipient to its treasury.
- **Why not burn [I].**
  - The lock exists so stake is still there while evidence can arrive. After unlock the
    protocol has no claim on it.
  - A burn punishes inattention (lost keys, illness, an uninstalled app), not misbehaviour.
  - The supply ledger keeps minted supply invariant under burns, so the burn has no monetary
    effect.
  - It raises consumer and legal exposure for a founder-run chain. This is a flag for
    counsel, not legal advice.
- **Decision (UB-1) [I].**
  - At each epoch boundary, pay up to K = 256 matured entries from the head of the
    validator queue, which is sorted by unlock time. The rest wait for the next boundary, as
    with Ethereum's bounded sweep.
  - The manual withdrawal stays.
- **Finding for S3 (DL-3) [C, I].** Each delegation pool's unbonding queue is capped at 100
  entries, and only each delegator's own withdrawal removes one. So anyone with 100 AIN
  (100 undelegations of 1 AIN) can stop every other delegator of that pool from
  undelegating. The fix is Polkadot nomination pools' buckets by unlock time, a
  per-delegator cap (Cosmos uses 7), and automatic payout.

## 9. Residual risks and measurements [I]

1. **Economics now assume roughly correct validator clocks; consensus safety does not.**
   Mitigations: authenticated time, a 60 s drift alarm, and the per-block cap.
2. **Blocks persistently slower than C_τ,** for example on degraded hardware: deadlines
   stretch and emission falls. That is safe, and it is fixed by raising C_τ at an upgrade.
3. **Measure before genesis:**
   - the V4 block time t_b, which sets C_τ and checks I's band;
   - the boundary cost, split into rounds and wall-clock time.

## Sources (fetched 2026-09-30)

**Cosmos, CometBFT, IBC**
- Cosmos SDK x/mint README: https://raw.githubusercontent.com/cosmos/cosmos-sdk/main/x/mint/README.md
- Cosmos SDK issue #5411: https://github.com/cosmos/cosmos-sdk/issues/5411
- Cosmos Hub Proposal 1: https://forum.cosmos.network/t/proposal-1-accepted-adjustment-of-blocks-per-year-to-come-aligned-with-actual-block-time/1682
- Cosmos Hub Proposal 30: https://forum.cosmos.network/t/proposal-30-accepted-governance-proposal-update-blocks-per-year-inflation-param/4076
- Cosmos SDK issue #6478: https://github.com/cosmos/cosmos-sdk/issues/6478
- Cosmos SDK PR #6844: https://github.com/cosmos/cosmos-sdk/pull/6844
- Cosmos SDK x/staking README: https://github.com/cosmos/cosmos-sdk/blob/main/x/staking/README.md
- Cosmos SDK commission rules: https://github.com/cosmos/cosmos-sdk/blob/main/x/staking/types/commission.go
- CometBFT evidence expiry: https://raw.githubusercontent.com/cometbft/cometbft/main/evidence/verify.go
- CometBFT BFT Time: https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/spec/consensus/bft-time.md
- CometBFT ADR-071, proposer-based timestamps: https://raw.githubusercontent.com/cometbft/cometbft/main/docs/references/architecture/tendermint-core/adr-071-proposer-based-timestamps.md
- CometBFT light-client verification: https://raw.githubusercontent.com/cometbft/cometbft/v0.38.x/spec/light-client/verification/verification_001_published.md
- IBC ADR-026: https://docs.cosmos.network/ibc/latest/architecture/adr-026-ibc-client-recovery-mechanisms
- ICS-07: https://github.com/cosmos/ibc/blob/main/spec/client/ics-007-tendermint-client/README.md
- Osmosis x/epochs: https://raw.githubusercontent.com/osmosis-labs/osmosis/main/x/epochs/README.md

**Ethereum**
- Phase0 beacon chain and fork choice: https://ethereum.github.io/consensus-specs/specs/phase0/beacon-chain/
- Weak subjectivity: https://raw.githubusercontent.com/ethereum/consensus-specs/master/specs/phase0/weak-subjectivity.md
- Capella and Electra withdrawals: https://github.com/ethereum/consensus-specs/blob/master/specs/capella/beacon-chain.md
- Buterin (2014), "Proof of Stake: How I Learned to Love Weak Subjectivity": https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity
- Buterin and Griffith (2017), "Casper the Friendly Finality Gadget": https://arxiv.org/abs/1710.09437

**Polkadot**
- Polkadot runtime constants: https://raw.githubusercontent.com/polkadot-fellows/runtimes/main/relay/polkadot/constants/src/lib.rs
- pallet-timestamp: https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/substrate/frame/timestamp/src/lib.rs
- staking-async `MaxEraDuration`: https://raw.githubusercontent.com/paritytech/polkadot-sdk/master/substrate/frame/staking-async/src/pallet/mod.rs
- Nomination pools: https://docs.rs/pallet-nomination-pools/latest/pallet_nomination_pools/

**Aptos**
- Staking: https://aptos.dev/network/blockchain/staking
- `block.move`: https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/sources/block.move
- `delegation_pool.move`: https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/aptos-framework/sources/delegation_pool.move
- "The Latency Price of Threshold Cryptosystem in Blockchains": https://arxiv.org/abs/2407.12172

**Sui**
- Epochs: https://docs.sui.io/concepts/sui-architecture/epochs
- Commit timestamp (linearizer): https://github.com/MystenLabs/sui/blob/main/consensus/core/src/linearizer.rs
- Blackshear et al., "Sui Lutris" (CCS 2024): https://arxiv.org/abs/2310.18042

**Solana**
- Commission rugs, issue #28628: https://github.com/solana-labs/solana/issues/28628
- SIMD-0249, delayed commission updates: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0249-delay-commission-updates.md
- SIMD-0079, decreases at any time: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0079-allow_commission_decrease_at_any_time.md

**Cardano**
- Shelley formal ledger spec: https://github.com/intersectmbo/cardano-ledger/releases/latest/download/shelley-ledger.pdf
- Shelley delegation design spec: https://github.com/intersectmbo/cardano-ledger/releases/latest/download/shelley-delegation.pdf

**Bitcoin**
- `pow.cpp`: https://github.com/bitcoin/bitcoin/blob/master/src/pow.cpp
- BIP 54 (timewarp): https://github.com/bitcoin/bips/blob/master/bip-0054.md
- BIP 113 (median time past): https://github.com/bitcoin/bips/blob/master/bip-0113.mediawiki

**Consensus and security papers**
- Bullshark: https://arxiv.org/abs/2201.05677
- Mysticeti: https://arxiv.org/abs/2310.14821
- Narwhal and Tusk: https://arxiv.org/abs/2105.11827
- LibraBFT (2020): https://developers.diem.com/papers/diem-consensus-state-machine-replication-in-the-diem-blockchain/2020-05-26.pdf
- Lamport and Melliar-Smith, "Synchronizing Clocks in the Presence of Faults", JACM 1985: https://lamport.azurewebsites.net/pubs/pubs.html
- Malhotra et al., "Attacking the Network Time Protocol", NDSS 2016: https://eprint.iacr.org/2015/1020
- Tas et al., "Bitcoin-Enhanced Proof-of-Stake Security" (Babylon), IEEE S&P 2023: https://arxiv.org/abs/2207.08392
- Gaži, Kiayias and Russell, "Stake-Bleeding Attacks": https://eprint.iacr.org/2018/248

**Staking economics**
- Brünjes, Kiayias, Koutsoupias and Stouka, "Reward Sharing Schemes for Stake Pools": https://arxiv.org/abs/1807.11218
- Farrell and Klemperer, "Coordination and Lock-In: Competition with Switching Costs and Network Effects": https://www.nuff.ox.ac.uk/users/klemperer/lockinwebversion.pdf
- Gersbach, Mamageishvili and Schneider, "Staking Pools on Blockchains": https://arxiv.org/abs/2203.05838
