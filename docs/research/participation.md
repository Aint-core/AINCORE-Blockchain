# Participation: pay and seats (B464, G5 Amendment A5)

- **Date:** 2026-10-15. Branch `g1/certified-dag`.
- **Finding:** round-30 audit B464 (MEDIUM, three verifiers MEDIUM). Emission and fees paid
  every committee member by weight alone (`paid_committee`, `delegation::pay_rewards`,
  `block_payouts`), and nothing removed a member that took no part. B4 had bound the
  authors of each block's committed vertices into the block and used them for bootstrap
  weight only (BW-6).
- **Founder rules:** downtime is not slashed; only equivocation is. Non-participation may
  cost rewards or the seat.

## 1. The problem in numbers

At launch W = s_min = 18.5 M AIN and emission is about 2.85 M AIN a year. A member with
200,000 AIN of its own (the IT-5 size) that runs no node took 200,000 / 18.5 M of every
payout, about 30,800 AIN a year, plus the same share of the 80 % fee pool:
- at zero operating cost;
- with zero slash exposure (it signs nothing, so it cannot equivocate);
- for ever: it was elected every epoch by stake.

Its delegators earned the full yield without risk, so delegation drifted toward pools that
run nothing. Each dark member's anchors were skipped (slower blocks), and its weight came
off the fault margin: with dark weight d and Byzantine weight b, certificates need
d + b < 1/3. Lazy operators, lost keys and RC-3 joiners whose proof landed late only added
dark weight; nothing took it away.

## 2. The measure (PA-1)

**Choice: committed vertices authored per round closed.** A block with anchor round r,
after a block with anchor round r_prev, closes the rounds (r_prev, r]. Every member of the
epoch's committee could author one vertex in each. The block's `committed_authors` names
the author of each committed vertex, and the header binds it (B4). p = min(1, vertices /
rounds), counted per committee epoch and per reward period.

The alternatives considered:

| Measure | Why not (for pay and seats) |
|---|---|
| Attestations (certificate signatures) | A certificate holds only its first quorum of signatures, so a slower honest member scores low (B4, accepted there) |
| Leader slots committed (BW-6) | About 15 % of anchors are skipped with four honest validators (G5 S6), mostly by the timer, not the leader. A reward period of R = 20 blocks holds about 23 anchor rounds, so a member of share s holds about 23 s slots: at s = 1 % one slot in four periods, all noise |
| Uptime reports by peers (Sui's tallying rule) | Needs a reporting quorum and trusts reporters; a coalition could report an honest rival |

Vertex authorship is the same on every node and costs nothing new: the block already
carries it. A coalition below a third cannot keep an honest member's vertices out of the
committed sub-DAG: honest successors reference them.

**Boundary effect.** The vertices of a period's last anchor round (other than the anchor)
are committed in the next period's first block. A non-leader's period counts telescope to
exactly the rounds; the leader of the period's last anchor has one vertex more in that
period and one fewer in the next. One vertex beyond the rounds carries into the next
period, worth about 1/47 of a period for that leader (R = 20 blocks of ~2.35 rounds,
2 / 0.85 with ~15 % of anchors skipped), or s / 47 of its pay on average. More does not
carry, so a member cannot bank late vertices for a later absence.

**Cost.** The counts live in one Move resource, `0x1::staking::Participation`, rewritten
every block: two u64 counts per member (the epoch's and the period's) and the list of
members under half in the last closed epoch. At 256 members that is 4 KB of BCS (8 KB as
stored hex) plus 32 bytes per low member, against the 256 coin stores a block's fees
already write. The last period's rates (`PeriodParticipation`, 40 bytes a member) are
written once per reward period. Counts are kept on a chain with `0x1::chain::Params`
(boot refuses one without), as payouts are.

## 3. Pay (PA-2)

**Rule:** a member's emission share is pot × w / max(W, s_min) × p, with p its
participation in the period paid. Fees share the 80 % pool and the 20 % bonus by w × p of
the last period paid, against max(W, s_min) of the unscaled weights. The emission a member
did not take part for stays in the reserve; the fee part is burned.

| Chain | Rule |
|---|---|
| Aptos (`stake.move`, `distribute_rewards`) | rewards = stake × rewards_rate × successful proposals / total proposals in the epoch: linear in performance, nothing redistributed |
| Solana | inflation rewards by vote credits earned in the epoch (timely-vote credits, SIMD-0033): linear in votes landed |
| Ethereum | each attestation duty pays only if done (and a missed one is penalized) |
| Polkadot | era points redistribute the era's payout among those who earned points |

AINCORE takes the linear rule (Aptos, Solana) and does not redistribute (unlike Polkadot):
- Redistributing the absent members' part would raise every other member's pay when a
  rival goes dark, the motive to censor rivals that BW-7 removed (second review HIGH-2).
- With the part returned to the reserve or burned, a member's income is its weight times
  its own participation, whatever the others do.

**The leader's bonus.** The 20 % bonus is scaled by Σ w·p / max(W, s_min). Absent
members' anchors are skipped, so a member that leads takes w / Σ_participating of the
blocks instead of w / W. Its bonus income per unit of time, (w / Σ w·p) × bonus ×
Σ w·p / max(W, s_min) per block, does not change when others go dark: no motive there
either. Example: four equal members, one dark. Each other leads 1/3 of the blocks
instead of 1/4, and gets 15 % instead of 20 % of each block's fees as bonus: 5 % either way.

**Why fees use the last period.** A block's fees are paid in the block. The count of the
current period so far would pay a member that is online at each period's start and leaves:
online for 1 block of 20, it would be paid Σ_k min(1, 1/k) ≈ 3.6 of 20 blocks' shares,
3.6 times its work. The last closed period's count is proportional in aggregate and lags
by one period (R blocks, ~2 min).

## 4. Seats (PA-3)

**Rule:** at H_E, a member of C_{E−1} and C_E with p < ½ in both epochs is out from E+1:
weight 0 in the live set, stake bonded, nothing slashed. `staking::reactivate` returns it.

| Chain | Downtime rule |
|---|---|
| Cosmos SDK default (`x/slashing`) | jailed when it signed fewer than 50 % of the last 100 blocks; 1 % slashed; may unjail (`MsgUnjail`) after 10 minutes |
| Cosmos Hub | 5 % of the last 10,000 blocks (~17 h); 0.01 % slashed; unjail after 10 minutes |
| Aptos, Sui | no removal; pay falls with performance |
| Ethereum | no removal while finalizing; the inactivity leak drains offline stake only when finality stops |

- **No slash.** Founder rule: downtime is not slashed.
- **Window in epochs.** Committees change only at boundaries (EP-2), so a removal cannot
  take effect inside an epoch, and the count is kept per epoch.
- **Two epochs, each below the bar.** RC-3 makes a member legitimately abstain for one
  whole epoch: a joiner's first member epoch (B441), or a node restored without its
  guards. One low epoch must never remove a member, so removal needs two in a row, both
  as a member. A member that returns, like a joiner, therefore has one epoch of grace.
  Requiring the two-epoch total below ½ instead would remove an RC-3 joiner (0 then 0.98
  averages 0.49).
- **Bar ½.** The Cosmos SDK default and BW-6's bar. To remove a member an outage must
  cover half of each of two consecutive epochs, so at least one epoch's length across
  their boundary (I = 1,000 blocks at 6.75 s ≈ 1.9 h). Honest members author nearly every
  round: on AINCORE-TESTNET-V4 they committed 88–92 % even of their leader slots, which
  also need the anchor to be voted. The margin is about 0.4.
- **Worst-case dark time.** A member that goes dark at fraction x of epoch k:
  - x < ½: k and k+1 are low, so it is out from k+2, after (1 − x) + 1 < 2 epochs;
  - x ≥ ½: k passes, k+1 and k+2 are low, so it is out from k+3, after (1 − x) + 2 ≤ 2.5
    epochs.
  So dark weight leaves the committee within 2.5 epochs (~4.7 h at launch). Dark stake no
  longer accumulates: the margin returns to 1/3 − b once the dark weight is out.
- **Liveness.** Removal never lowers liveness. With dark weight d out, the remaining
  committee needs two thirds of itself, which the members taking part already hold. A
  coalition below a third cannot make an honest member's vertices go uncommitted. A DDoS
  that takes an honest member offline for two epochs removes it, as Cosmos jails one. The
  member reactivates with one transaction, and nothing is slashed.
- **Re-entry right away.** `reactivate` restores the live weight in the same block. RC-3's
  `seeks_boot_proof` asks the live set for a positive weight, so the node proves its boot
  during the epoch and is not left abstaining in its first epoch back.

## 5. Bootstrap weight

An operator that is out keeps its ceiling and folds a ratio of 0 into its BW-6 score for
each epoch that closes while it is out (the epoch in which it reactivates folds nothing: it
was not in that committee). A dark operator therefore forfeits on BW-6's schedule (75 epochs,
~5.9 days, from 0.9) whether or not it is out, and an honest operator back after a few
hours loses a few percent of score, not its weight (BW-6's design point, review HIGH-2).
- While out, its weight stays reserved under C0, so nobody gains it (BW-4's rule).
- P, the BW-11 cap and the bootstrap's end count only the members the next committee can
  hold. Counted with the operator that is out, the cap measured each party against a
  committee larger than the one elected: a party at 6,000 of 22,000 (27 %) held 6,000 of
  18,000, a third, once a 4,000 operator was out.

## 6. Residuals

- **Alternation.** A member can be at or above ½ in one epoch and below in the next and
  keep its seat. It is paid by p, so it gains nothing; its weight is dark at most one epoch
  in two.
- **Leader slots and attestations** do not scale pay (§2). A member that authors every
  round but withholds its anchors loses only its leader bonus; it gains nothing, and its
  stake counts toward f.
- **Late vertices.** Vertices above the GC floor (~50 rounds) that consensus still
  certifies and commits count when committed. At most one carries between periods.
- **A payout that aborts.** Its period's count is consumed; the next payout covers the
  time (EM-1) at the next period's rate.
- **Delegation to a member that is out** stays open and earns nothing until it returns.
- **B389's mid-epoch refresh** of the protected list still counts a member that is out as
  electable, so until the next boundary a joiner into a full set cannot displace it.
- **Tooling.** No RPC shows participation or the inactive list, and no CLI command or
  operator-guide step sends `reactivate` yet.
