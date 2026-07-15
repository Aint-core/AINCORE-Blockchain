# Supply-Neutral Perpetual Security: A Burn-Funded Tail Emission Model for a Hard-Capped, Fair-Launch Proof-of-Stake L1

**AINCORE Research**
*Draft — July 2026*

---

## Abstract

Hard-capped cryptocurrencies face an unresolved tension between monetary credibility and perpetual security funding. We study this tension in the context of AINCORE, a sovereign proof-of-stake L1 with DAG/BFT consensus (strict $>2/3$ stake quorum), one-second blocks, and a promised 150M hard cap, and we address four open problems simultaneously: (i) *fee-only instability* — a chain paying validators exclusively from fees earns zero on an empty chain, inviting the death-spiral and deviant-equilibrium dynamics formalized by Carlsten et al.; (ii) the *hard-cap security-budget problem* — Bitcoin's unsolved endgame, in which Budish's flow-versus-stock constraint $P_{\text{block}} > V_{\text{attack}}/\alpha$ must hold in perpetuity from fees alone; (iii) *halving revenue cliffs*, which impose discontinuous 50% revenue shocks that minority chains are poorly positioned to absorb; and (iv) the *PoS fair-launch paradox* — proof-of-stake requires an initial stake distribution, yet every distribution mechanism is formally deficient. We propose a composite mechanism: a bootstrap-minimal genesis (1M AIN, 0.667% of cap), a smooth geometric disinflation schedule $A_n = E(1-\delta)\delta^{n-1}$ with $\delta = 0.95$ over an emission budget $E = 149{,}000{,}000$ AIN, a 90/10 staker/dev-fund split with governance sunset, and a *burn-funded tail emission* in which cumulative post-schedule minting is gated on cumulative fee burn, yielding a provable net-supply invariant $S(t) \le 150{,}000{,}000$ at every instant. We prove the invariant, show the stake-acquisition attack is supply-constrained in *every* year whenever staking participation exceeds $1/3$ (a scale-free consequence of the $2/3$ BFT threshold), give an integer-deterministic implementation with exact conservation, and honestly situate the design against prior art — including Zcash's Network Sustainability Mechanism, which anticipates the core burn-recycling idea — and against the failure modes the mechanism does *not* solve.

---

## 1. Introduction

A blockchain's security budget is the recurring payment that makes honest participation an equilibrium. Budish [1] showed that this payment is fundamentally a *flow* defending against a *stock*: the per-block prize $P_{\text{block}}$ must exceed the one-shot value of attacking, $V_{\text{attack}}$, divided by a net-cost multiple $\alpha$. Nakamoto-style chains bootstrap this flow with newly minted coins, but any chain that promises a hard supply cap also promises that this subsidy eventually reaches zero. What then?

The literature's answer is discouraging. Bonneau et al. [6] flagged fee-only stability as an open question in 2015; Carlsten et al. [2] answered it negatively for proof-of-work in 2016, exhibiting undercutting equilibria with unbounded transaction backlogs and selfish-mining strategies profitable at arbitrarily low hash power; Auer [3] showed the decentralized fee equilibrium underfunds security by a factor of roughly the number of transactions per block; and Chitra [4] proved the proof-of-stake analogue — deflationary reward schedules with terminal supply $C_\infty$ are vulnerable to security-draining stake rebalances whose threshold *worsens* with $C_\infty$. As of 2026, work such as Lee [7] still treats the fee-only endgame as unsolved mechanism design.

At the same time, tail emission — the standard prescription (Monero's fixed 0.6 XMR/block, Carlsten et al.'s "make the block reward permanent") — breaks the hard cap, and with it a monetary promise that is, for better or worse, commercially and socially load-bearing. And proof-of-stake introduces a second-order problem that proof-of-work does not have: *someone must own the initial stake*. Srivastava et al. [8] prove that airdrops violate incentive compatibility, proof-of-burn violates individual rationality, and only importing stake via an external costly resource satisfies both — a luxury a sovereign fair-launch chain does not have.

This paper presents the emission design adopted for AINCORE, a sovereign PoS L1 (DAG-based consensus with BFT finality at strict $>2/3$ stake, BLS quorum certificates, Move VM, 1s blocks) that currently pays validators *only* fees — i.e., it currently sits exactly in the regime the literature warns about, earning zero on an empty chain. The design goals are: a credible net 150M hard cap; a fair launch with no premine beyond a 1M bootstrap stake and no venture allocation; a Decred-style 10% governance-controlled development fund; smooth geometric disinflation with no halving cliffs; and a *perpetual* security budget.

**Contributions.**

1. **A composite emission mechanism** combining geometric disinflation ($A_n = E(1-\delta)\delta^{n-1}$, $\delta = 0.95$), a 90/10 staker/dev split with per-block 20/80 leader/stake-weighted routing, and a burn-funded tail, with a full parameter study across $\delta \in \{0.90, 0.93, 0.95\}$ (§5, §8).
2. **A supply invariant with proof**: gating cumulative tail minting on cumulative realized fee burn guarantees net supply $S(t) \le 150\text{M}$ at every intermediate time, not merely asymptotically (Proposition 2, §6).
3. **A scale-free attack-feasibility result**: under a $>2/3$ BFT threshold, stock acquisition of a supermajority is supply-constrained in every year iff staking participation $\sigma > 1/3$, independent of circulating supply and price — reframing $\sigma$ itself as the security parameter to monitor (Proposition 1, §4, §7).
4. **An integer-deterministic implementation scheme** (u128 base units, remainder-carry geometric decay, Bresenham per-block payout, hierarchical dust-safe splits) with a machine-checked conservation argument and 200-year simulation results (§5.3).
5. **An honest novelty and limitations assessment**: burn-funded tails have direct prior art (Zcash ZIP-233/234/235; Avalanche's implicit recycling; Freicoin; Ergo), and the mechanism provably cannot fund security on an unused chain. We scope our claims accordingly (§3, §6.3, §9).

---

## 2. Related Work

**The security-budget problem.** Budish [1] (NBER w24717; published as *Trust at Scale*, QJE 2025) derives the canonical constraint from two equilibrium conditions: free entry, $N^* c = P_{\text{block}}$, and incentive compatibility, $\alpha \cdot N^* c > V_{\text{attack}}$ with $\alpha = (A-1)t$, combining to $P_{\text{block}} > V_{\text{attack}}/\alpha$ — the recurring flow payment must permanently exceed the one-off stock benefit of attack. Security is *linear* in expenditure, and the sabotage extension $p_{\text{tx}} > \frac{(1-\Delta_{\text{attack}})}{(A-1+\Delta_{\text{attack}})t}\bar v_{\text{tx}}$ makes the post-attack value collapse $\Delta_{\text{attack}}$ a "pick your poison" parameter. Auer [3] (BIS WP 765) derives economic finality (his Eq. 7) and proves security scales only linearly in confirmation delay; his "tragedy of the common chain" shows the decentralized fee equilibrium $\bar F = \mu S/N$ underfunds the coordinated optimum by a factor $\sim N$. Chitra [4] proves a phase transition between predominantly-staked and predominantly-lent equilibria and, most directly relevant here, shows deflationary schedules $R_t = kr^{-t}$ with terminal supply $C_\infty$ suffer security-draining rebalances whenever $\delta > (C_\infty - 1)\gamma_t \tau_{\text{stake}}\tau_{\text{lend}}/n$, concluding "PoS in deflationary systems is unstable"; Chitra & Evans [5] extend this to staking derivatives with a sharp safe/unsafe transition. Bonneau et al. [6] first labeled fee-only stability an open question; Lee [7] (2026) characterizes rational deviation by $G_t \ge \varphi(w) X_t$, a threshold that mechanically relaxes as subsidies vanish, and evaluates base fees, fee floors, and adaptive block sizes as mitigations — still an open problem.

**Fee-only instability.** Carlsten et al. [2] show that even with fees arriving at a *constant* rate, the fee-only regime admits mining gaps, strictly dominant petty-compliant tie-breaking, an undercutting equilibrium (Theorem 5.1, via a Lambert-$W$ fee-claiming function) with $\Theta(\sqrt n)$ backlog growth, undercutting profitable even against 66% honest miners, and a cutoff selfish-mining variant profitable for *all* $\alpha > 0$, immediately upon deployment. Their design lesson — permanent block rewards — motivates every tail-emission design including ours. Tsabary & Eyal [9] show gaps and centralization pressure begin well *before* the fee-only endpoint, with mining-power utilization falling as low as $\sim$10%. Gong et al. [10] refine the picture: with block-size limits, undercutting is profitable only under closed-form conditions on the fee ratio $\gamma$ (e.g., $\gamma < \beta_u^2/(2(1-\beta_u))$ for a two-block safe margin), demanding for weak miners but feasible near 50%; their Theorem V.1 gives an "avoidance" fee-claiming rule that is a Nash-equilibrium defense. Roughgarden [11, 12] proves EIP-1559 is MMIC, OCA-proof, and DSIC outside demand spikes — and, critically for us, that the base fee *must be burned*, since paying it to the proposer lets miner–user collusion costlessly recreate a first-price auction. He is explicit that TFM design does not repair consensus-layer instability.

**Tail emission and cap-compatible recycling — novelty statement.** Monero's tail emission (0.6 XMR/block since block 2,641,623, June 2022) is the deployed exemplar of a perpetual fixed subsidy; Peter Todd's equilibrium argument [13] ($dN/dt = k - \lambda N \Rightarrow N(\infty) = k/\lambda$) shows fixed emission with proportional coin loss is asymptotically supply-neutral in *real* terms — but Monero abandons the nominal hard cap. Avalanche caps supply at 720M and mints staking rewards from $(\text{MaxSupply} - \text{Supply})$ while burning all fees, so burned fees implicitly re-enlarge future reward headroom — structural but non-earmarked recycling. **We must be candid: a burn-funded tail under a hard cap is not a novel concept.** Zcash's Network Sustainability Mechanism (ZIP-233/234/235, drafted 2023, still Draft status [14]) is direct prior art: 60% of fees are removed into a Money Reserve and reissued as $\text{BlockSubsidy} = \lceil 4126 \times 10^{-10} \cdot \text{Reserve} \rceil$ per block under the 21M cap. Vitalik Buterin's EIP-1559 FAQ [15] sketches routing $\sim$50% of base-fee revenue into a smoothing pool drained into future block rewards. Freicoin (2012) funded a perpetual miner reward from demurrage at constant supply; Ergo's deployed storage rent recycles dormant UTXOs to miners under a 97M cap [16]. What we claim as contributions are therefore *mechanism-level*: the specific invariant formulation and its every-instant proof under a strict-inequality gate; the interaction with a geometric (not halving) primary schedule chosen for its 91-year subsidy horizon; the scale-free BFT attack-window analysis; and the exact integer implementation. The concept space is well-trodden; the composition and its formal treatment for a DAG/BFT PoS L1 are, to our knowledge, new.

**Fair launch and treasuries.** Srivastava et al. [8] formalize PoS bootstrapping: airdrops fail incentive compatibility (Sybil), proof-of-burn fails individual rationality, and only external-cost stake import (PoW-first, à la the Merge) satisfies IR + IC + decentralization. Bentov et al. [17] identified fair initial distribution as a fundamental pure-PoS hurdle in 2014. Fanti et al. [18] prove proportional staking rewards amplify genesis inequality, *worst* with small initial stake pools and large early rewards — precisely our year-1 regime, a point we return to in §7 and §9. Empirically, Edgeware's capital-weighted lockdrop (1.2M ETH locked for 90% of supply) reproduced whale governance; Celestia's Genesis Drop distributed 6% to 584k addresses; Mina's Genesis Program (equal, earned, 4-year-vested grants of 66,000 MINA to up to 1,000 members, 6.67% of supply) is the cleanest earned-equal-vested template. Jensen et al. [19] measured launch design driving concentration directly (UNI retro-airdrop Gini 0.82/Nakamoto 82 vs. VC-heavy COMP 0.99/9; even "fair-launch" YFI hit 0.90). On treasuries, Decred's constant 10% block-reward treasury funded a decade of development without a foundation — with a documented chronic-underspend pathology (~876k DCR accumulated, only ~205k spent across 42 stakeholder-ratified TSpends) — while Zcash's dev fund produced a decade of recurring legitimacy crises across four regimes (20% Founders Reward → ZIP 1014 → ZIP 1015 lockbox → proposed coinholder control [20]). We adopt the Decred shape (constant 10%, on-chain controlled) with an explicit governance sunset.

---

## 3. Model

**Setting.** Time is discrete in blocks $b = 1, 2, \dots$ at 1s intervals; $N = 31{,}536{,}000$ blocks/year. A validator set $\mathcal V$ holds stake; consensus is BFT over a DAG with commit requiring quorum certificates from validators holding strictly more than $2/3$ of total stake. Let $C_n$ denote circulating supply in year $n$, $\sigma \in (0,1]$ the staked fraction (so honest stake $H_n = \sigma C_n$), and $P$ the token price. Equivocation is detected and slashed in-protocol (slash fraction $s$); downtime beyond 100 rounds jails with a 5% slash.

**Reward flow.** The protocol emits $A_n$ per year (schedule in §5), split per block as 10% to a dev-fund account and 90% to stakers; of the staker share, 20% to the committing anchor leader and 80% pro-rata by stake. Users pay fees; a burn parameter $\beta \in [0,1]$ burns $\beta \cdot \text{fees}$, with the remainder swept to the leader.

**Attack conditions.** Following Budish [1], deterrence requires the attacker's *flow* cost to exceed the *stock* value $V_{\text{attack}}$ extractable in one shot. In PoS the attack vector is stake acquisition. Two conditions matter:

- *Stock condition:* an attacker who buys and stakes $A$ tokens controls $A/(A + H_n)$ of post-acquisition stake and needs this to exceed $2/3$:
$$\frac{A}{A + H_n} > \frac{2}{3} \iff A > 2H_n = 2\sigma C_n.$$
- *Flow condition:* if stock acquisition is infeasible (§4), the marginal attack rents stake at rate $r$. Deterrence requires
$$V_{\text{attack}} \le r \cdot 2\sigma C_n \cdot t_{\text{attack}} + s \cdot 2\sigma C_n + \Lambda,$$
where $s \cdot 2\sigma C_n$ is slashing exposure on rented-and-slashed capital and $\Lambda$ is the price-collapse loss on any owned stake (Budish's $\Delta_{\text{attack}}$ term). The honest reward flow $0.9 A_n / N$ per block is what pays for $\sigma$ to exist at all; as $A_n \to 0$, that flow must migrate to fees — the transition §6 is designed to survive.

We deliberately do not model MEV, and we treat $\sigma$ as exogenous within a year (see §9 for both).

---

## 4. Attack-Cost Dynamics: the $\sigma > 1/3$ Window

**Proposition 1 (scale-free supply constraint).** *Under a $>2/3$ BFT threshold, the stake required for a supermajority stock attack exceeds the entire non-staked float in every year if and only if $\sigma > 1/3$.*

*Proof.* The attacker needs $A > 2\sigma C_n$; the purchasable float is $(1-\sigma)C_n$. Market feasibility requires $2\sigma C_n \le (1-\sigma)C_n \iff \sigma \le 1/3$. Both sides scale with $C_n$, which cancels: the condition is independent of supply, year, and price. $\blacksquare$

The coincidence that the BFT threshold $2/3$ makes $\sigma = 1/3$ the critical participation rate is the key design fact. For $\sigma = 0.4$ the attacker needs $0.8\,C_n$ against a float of $0.6\,C_n$ (a deficit of $0.2\,C_n$ — 33% more than everything unstaked); for $\sigma = 0.6$ he needs $1.2\,C_n$ against a $0.4\,C_n$ float ($3\times$ the float). Concretely in year 1 ($\delta = 0.95$, $C_1 = 4.725$M): $\sigma = 0.4 \Rightarrow 2H = 3.78$M vs. float $2.835$M; $\sigma = 0.6 \Rightarrow 2H = 5.67$M vs. float $1.89$M.

Two things *do* change over time: the absolute dollar cost $2\sigma C_n P$ grows with supply and price, and — the real long-run threat — $\sigma$ may decay as nominal yields fall (§8) or as on-chain lending outcompetes staking (Chitra's rebalancing condition [4]). The design implication is that $\sigma$ must be *monitored as a consensus security parameter*, not assumed; the emission schedule's job is to keep staking yield above competing on-chain yields long enough for fee demand to develop.

---

## 5. The AINCORE Emission Mechanism

### 5.1 Geometric disinflation

Fixed parameters: hard cap 150,000,000 AIN; genesis 1,000,000 AIN (0.667%); emission budget $E = 149{,}000{,}000$ AIN; $N = 31{,}536{,}000$ blocks/yr; 1 AIN $= 10^8$ base units (bu).

Annual pools decay geometrically, $A_n = A_1 \delta^{n-1}$. Requiring $\sum_{n=1}^\infty A_n = A_1/(1-\delta) = E$ pins $A_1 = E(1-\delta)$; cumulative emission through year $n$ is $E(1-\delta^n)$ in closed form, and the half-life is $\ln 2 / \ln(1/\delta)$. Unlike halvings, revenue declines by at most $(1-\delta) = 5\%$ year-over-year — no cliff for validators to fall off, and no periodic fee-market stress test of the kind Bitcoin schedules every four years.

**Candidate comparison:**

| $\delta$ | $A_1$ (AIN) | $R_1 = A_1/N$ (AIN/block) | Half-life (yr) | Years until $A_n < 0.01 A_1$ |
|---|---|---|---|---|
| 0.95 | 7,450,000 | 0.23623795 | 13.513 | 91 |
| 0.93 | 10,430,000 | 0.33073313 | 9.551 | 65 |
| 0.90 | 14,900,000 | 0.47247590 | 6.579 | 45 |

We select $\boldsymbol{\delta = 0.95}$: smallest year-1 supply shock ($i_1 = 158\%$ vs. $176\%$ for $\delta = 0.90$; §8), longest half-life, and — decisively — a **91-year horizon** during which the scheduled subsidy exceeds 1% of $A_1$ (first $n$ with $\delta^{n-1} < 0.01$: $0.95^{90} = 0.00989$). Selected schedule ($\delta = 0.95$):

| Year $n$ | $A_n$ (AIN) | Cumulative | % of $E$ |
|---|---|---|---|
| 1 | 7,450,000 | 7,450,000 | 5.000% |
| 2 | 7,077,500 | 14,527,500 | 9.750% |
| 3 | 6,723,625 | 21,251,125 | 14.263% |
| 5 | 6,068,072 | 33,706,640 | 22.622% |
| 10 | 4,695,358 | 59,788,196 | 40.126% |
| 20 | 2,811,284 | 95,585,598 | 64.151% |
| 30 | 1,683,220 | 117,018,824 | 78.536% |

(Closed-form cross-check: $0.95^{10} = 0.59873694$; $149\text{M} \times (1 - 0.59873694) = 59{,}788{,}196$ ✓.)

### 5.2 The 90/10 split

Each block's payout divides 10% to the on-chain dev fund and 90% to stakers; the staker share divides 20% to the anchor leader (the DAG leader whose vertex anchors the committed wave, elected via VDF randomness) and 80% stake-weighted. The leader tranche compensates the marginal work of proposal and DA batching; the stake-weighted tranche pays for the *existence* of $\sigma$. The 10% dev share follows Decred's constant-treasury design and is governance-controlled with a sunset (§7.3).

### 5.3 Integer-deterministic implementation

Consensus arithmetic must be bit-identical across nodes; floating point is excluded. All amounts are u128 base units; $E = 1.49 \times 10^{16}$ bu. $A_1$ is exact for all three candidates ($E \times 5/100$, $\times 7/100$, $\times 10/100$ divide exactly; for $\delta = 0.95$, $A_1 = 745{,}000{,}000{,}000{,}000$ bu).

**Yearly decay with remainder carry** ($\delta = Q_{\text{num}}/Q_{\text{den}}$, e.g. $19/20$):

```rust
// state: (a: u128 /* bu */, carry: u128 /* < Q_DEN */)
let t = a * Q_NUM + carry;   // max ≈ 1.5e17 « u128::MAX
let a_next  = t / Q_DEN;     // floor — deterministic
let carry_n = t % Q_DEN;     // deferred, never dropped
```

Floor division never rounds up, so $A_n \le A_1\delta^{n-1}$ exactly and $\sum A_n < E$ — **the cap cannot be exceeded by construction** — while the carry defers (rather than loses) sub-unit dust. A 200-year simulation confirms: $\sum A_n = 14{,}899{,}477{,}715{,}272{,}882$ bu for $\delta = 0.95$, a shortfall of 5,222.85 AIN that matches the analytic un-emitted tail $E \cdot 0.95^{200} \approx 5{,}215$ AIN — i.e., essentially zero floor loss. ($\delta = 0.93$: short 74.09 AIN; $\delta = 0.90$: short 0.105 AIN. The invariant $\sum \le E$ held every year in all three runs.)

**Per-block payout** uses a Bresenham accumulator, $\text{pay}_b = \lfloor A_n b / N \rfloor - \lfloor A_n (b-1)/N \rfloor$, which telescopes to exactly $A_n$ over $N$ blocks and is restart-safe (recomputable from the block index alone). Maximum intermediate $A_1 N \approx 4.7 \times 10^{22} \ll 2^{127}$. Year 1 ($\delta = 0.95$): base payout 23,623,795 bu with 880,000 of the $N$ blocks paying $+1$ bu.

**Dust-safe split** by hierarchical subtraction: $\text{dev} = \lfloor \text{pay} \cdot 10/100 \rfloor$; $\text{staker} = \text{pay} - \text{dev}$; $\text{leader} = \lfloor \text{staker} \cdot 20/100 \rfloor$; $\text{weighted} = \text{staker} - \text{leader}$. The parts always sum to $\text{pay}$ exactly — no bu is created or destroyed. (Year-1 example on the 23,623,795 bu base block: dev 2,362,379; leader 4,252,283; stake-weighted 17,009,133; sum ✓.)

---

## 6. Burn-Funded Tail Emission

### 6.1 Definition

Let $G(t) = 1{,}000{,}000 + \sum \text{scheduled emission} \le 1\text{M} + E$ be genesis-plus-schedule issuance, $B(t) = \beta \cdot (\text{cumulative fees})$ the cumulative burn, $M_{\text{tail}}(t)$ cumulative tail minting, and define net supply
$$S(t) = G(t) + M_{\text{tail}}(t) - B(t).$$

**Tail rule.** After a governance-activated year $T^\*$ (when the scheduled subsidy is judged no longer load-bearing), the protocol may mint tail rewards subject to the gate: every new grant must satisfy $M_{\text{tail}}(t) \le B(t) - M_{\text{tail}}^{\text{prior}}(t)$, i.e.
$$\sum M_{\text{tail}} \le B(t) \quad \text{at all times.}$$
Burned fees are thus not destroyed but *escrowed against the cap*: they refill headroom that the tail re-issues as validator rewards. This simultaneously satisfies Roughgarden's requirement that base-fee revenue be withheld from the current proposer [11] (the burn is not paid to the block's leader; it funds *future* leaders' rewards, breaking the off-chain-collusion channel) and Carlsten et al.'s prescription of a permanent reward [2].

### 6.2 The supply invariant

**Proposition 2 (net-cap invariant).** *Under the tail rule, $S(t) \le 150{,}000{,}000$ AIN for all $t$.*

*Proof sketch.* $S(t) = 1\text{M} + E_{\text{sched}}(t) + \sum M_{\text{tail}} - B(t) \le 1\text{M} + E + B(t) - B(t) = 150{,}000{,}000$, using $E_{\text{sched}}(t) \le E$ (guaranteed exactly by the floor-division schedule of §5.3) and the tail gate $\sum M_{\text{tail}} \le B(t)$. The bound is *monotone-safe*: $B(t)$ is non-decreasing and every mint is gated on already-realized burn, so the inequality holds at every intermediate $t$, not merely in the limit — there is no transient overshoot even under adversarial timing of fee bursts and tail grants. $\blacksquare$

In implementation terms, the gate is a single u128 comparison against two monotone counters (`sys:cumulative_burn`, `sys:cumulative_tail_mint`) checked in the executor's reward path under the existing block-execution lock, and is therefore as auditable as the balance arithmetic itself.

### 6.3 Security floor and honest limitations

In steady state the annual tail budget is bounded by $\beta F$, where $F$ is annual fee volume in AIN, so the staker security-flow floor is
$$\text{flow}_{\text{tail}} = 0.9\,\beta F \text{ per year} \approx 0.9\,\beta F / N \text{ per block}.$$
Security becomes a function of usage, with $\beta$ the governance throttle between "burn as monetary policy" and "burn as security escrow."

**Limitation (stated plainly).** If usage $\to 0$ then $F \to 0$ and the tail $\to 0$: *a burn-funded tail cannot conjure security from an unused chain.* The mechanism converts the hard-cap problem into a fee-sufficiency problem; it does not eliminate it. Worse, the empirical record says fee revenue is violently demand-elastic: Ethereum's EIP-1559 burn collapsed from thousands of ETH/day to 50–70 ETH/day after Dencun moved L2 data to blobs — two orders of magnitude [21]. A burn-funded tail inherits this volatility, which argues for a *reserve-and-smoothing* release curve (as Zcash's ZIP-234 does, releasing a fixed fraction of the reserve per block) rather than pass-through refill; we adopt reserve-based release as the reference implementation.

The design's mitigation is the schedule's long reserve horizon: $A_n$ stays above 1% of $A_1$ until year **91** ($\delta = 0.95$; year 65 for 0.93, year 45 for 0.90). The chain has nearly a century of non-trivial scheduled subsidy in which to develop the fee demand the tail will eventually depend on. This is the strongest single argument for $\delta = 0.95$ over the faster schedules, and it is an argument about *buying time*, not about solving the endgame — see §9.

---

## 7. Fair-Launch Analysis

### 7.1 Bootstrap-minimal genesis

Genesis allocates exactly 1,000,000 AIN (0.667% of cap) as operational bootstrap stake for the initial validator set — an order of magnitude below the "Ethereum-class" $<20\%$ insider benchmark and far below the 38–48% typical of VC-backed L1s [22]. There is no investor allocation. The bootstrap is the minimum stake needed to make the $>2/3$ quorum meaningful at block 1; everything else is earned through the emission schedule. Given Srivastava et al.'s impossibility triad [8] — no Sybil-proof airdrop, no individually-rational burn, no external PoW to import — a minimal, transparent, validator-operational premine is the least-bad feasible point, and its *smallness* is the fairness claim: 99.33% of terminal supply is distributed by protocol operation.

### 7.2 The supply-constrained attack window

The classical worry for tiny-genesis PoS is that early supply is so small that an attacker simply buys control. Proposition 1 dissolves the *scale* version of this worry: because both attack requirement and float scale with $C_n$, there is no year in which growth flips feasibility — the chain is not "safe later but vulnerable while small." As long as $\sigma > 1/3$, supermajority acquisition demands more tokens than exist outside staking in year 1 and in year 30 alike. The genuine early-years exposure is different: low absolute market cap makes the *dollar* cost of accumulating toward $\sigma$-eroding positions small, and OTC acquisition of the bootstrap validators themselves is a social-layer attack no emission schedule prevents. The protocol's slashing (instant equivocation slash, downtime jailing) raises the flow cost per Budish's $\alpha$; the emission schedule's job is to make $\sigma$ large quickly — which the year-1–2 yields (§8) do aggressively.

### 7.3 Distribution dynamics and the dev-fund sunset

Fanti et al. [18] prove proportional rewards *compound* whatever inequality exists at genesis, worst with small pools and large early rewards — exactly our year-1 profile. Three design features push against this: (i) the stake-weighted 80% tranche is proportional (neutral, not equalizing — we do not claim otherwise), but the 20% leader tranche is VDF-randomized per committed round, giving small validators lumpy, equitability-improving income in the Fanti et al. sense; (ii) the schedule's smoothness avoids the concentrated "reward era" that a front-loaded or cliff schedule hands to the earliest cohort; (iii) the open validator set with low stake minimums keeps entry cheap while yields are high, diluting the bootstrap cohort fastest precisely when its share is largest — by year 2, scheduled emission alone (14.5M) is $14.5\times$ genesis.

The 10% dev fund is an on-chain account spendable only via the existing governance pipeline (proposal → stake-weighted vote → timelock → execution), mirroring Decred's stakeholder-ratified TSpends. Decred's decade of data shows the failure mode is *underspend and accumulation*, not raiding; Zcash's shows that fixed-recipient streams generate recurring legitimacy crises [20]. We therefore (a) route to a treasury, never to named recipients, and (b) attach a **sunset**: the 10% share itself must be re-ratified by governance every 4 years, defaulting to redirection into the staker share (not to burn) on failure to ratify. The sunset converts "governance capture of the dev fund" from a perpetual entitlement into a recurring, contestable decision — mitigation, not solution (§9).

---

## 8. Numerical Results

All values computed twice with independent exact methods (rational arithmetic and 50-digit decimal), agreeing to every displayed digit; the integer scheme of §5.3 was validated by a third, pure-u128 simulation. Yields use mid-year circulating supply $C_n = 1\text{M} + E(1-\delta^{n-1}) + A_n/2$ and the identity $y_n = (0.9/\sigma) i_n$ as a cross-check; $C_n$ ignores burn ($\beta \cdot \text{fees}$), so true yields are slightly *higher* than shown (conservative for security, aggressive for dilution optics).

**Nominal staking yield** $y_n = 0.9 A_n / (\sigma C_n)$:

| $\delta$ | Year | $C_n$ (AIN) | $y_n$, $\sigma = 0.4$ | $y_n$, $\sigma = 0.6$ |
|---|---|---|---|---|
| 0.95 | 1 | 4,725,000 | 354.76% | 236.51% |
| 0.95 | 2 | 11,988,750 | 132.83% | 88.55% |
| 0.95 | 5 | 31,672,605 | 43.11% | 28.74% |
| 0.95 | 10 | 58,440,517 | 18.08% | 12.05% |
| 0.93 | 1 | 6,215,000 | 377.59% | 251.73% |
| 0.93 | 5 | 42,441,342 | 41.36% | 27.58% |
| 0.93 | 10 | 75,172,692 | 16.25% | 10.83% |
| 0.90 | 1 | 8,450,000 | 396.75% | 264.50% |
| 0.90 | 5 | 57,129,045 | 38.50% | 25.67% |
| 0.90 | 10 | 95,160,630 | 13.65% | 9.10% |

(Spot check, $\delta = 0.95$, $n = 1$, $\sigma = 0.4$: $C_1 = 1\text{M} + 3.725\text{M} = 4.725\text{M}$; $y = 6.705\text{M}/1.89\text{M} = 3.547619$ ✓.)

**Dilution and real yield.** Circulating inflation $i_n = A_n/C_n$; staker real yield $y_n - i_n = i_n(0.9/\sigma - 1)$, i.e. $+1.25\,i_n$ for $\sigma = 0.4$ and $+0.5\,i_n$ for $\sigma = 0.6$:

| $\delta$ | Year | $i_n$ | Real yield ($\sigma = 0.4$) | Real yield ($\sigma = 0.6$) |
|---|---|---|---|---|
| 0.95 | 1 | 157.67% | +197.09% | +78.84% |
| 0.95 | 2 | 59.03% | +73.79% | +29.52% |
| 0.95 | 5 | 19.16% | +23.95% | +9.58% |
| 0.95 | 10 | 8.03% | +10.04% | +4.02% |
| 0.93 | 10 | 7.22% | +9.03% | +3.61% |
| 0.90 | 10 | 6.07% | +7.58% | +3.03% |

Since $0.9/\sigma > 1$ for both participation candidates, stakers always earn positive real yield; non-stakers are diluted at $i_n$, transferring value to stakers plus the dev fund. This is deliberate: the dilution tax is the mechanism that pushes realized $\sigma$ up and holds Proposition 1's $\sigma > 1/3$ condition — and it is directly responsive to Chitra's calibration requirement that staking yield dominate on-chain lending yields [4]; year-10 nominal yields of 12–18% leave ample headroom over historical DeFi lending rates.

**Caveat, flagged.** Year-1 yields are enormous *purely because the float is tiny* (1M genesis + half of $A_1$). This is an artifact of the 0.667% bootstrap, not a schedule error, but it will drive extreme early volatility and mercenary staking; it is also the exact regime Fanti et al. warn compounds inequality fastest (§7.3). $\delta = 0.95$ minimizes it among the candidates ($i_1 = 158\%$ vs. 176% at $\delta = 0.90$).

**Attack cost.** Per §4 the stock attack is supply-constrained every year for $\sigma > 1/3$; the dollar-flow deterrent grows as $2\sigma C_n P$: at $\delta = 0.95$, the stake an attacker must exceed is 3.78M AIN ($\sigma = 0.4$) in year 1 and 46.8M AIN by year 10 — against floats of 2.835M and 35.1M respectively, deficits that no market depth can fill without staker cooperation.

---

## 9. Open Problems

Honesty about what remains unsolved is a design requirement, not a rhetorical flourish.

1. **Usage-coupled tail collapse.** The tail floor is $0.9\beta F$; at $F \to 0$ it is zero. If AINCORE fails to develop durable fee demand within its 91-year subsidy horizon, no monetary mechanism rescues it — the design *defers* Budish's constraint by a century, it does not discharge it. Whether *any* mechanism can fund security on a demand-less chain is, per Bonneau et al. [6] and Lee [7], still open; our reading is that it cannot, and the honest framing of every tail design (ours, Monero's, Zcash's) is runway extension plus demand-coupling.
2. **MEV is not modeled.** Our flow condition omits extractable value from ordering, which in the DAG setting concentrates in the anchor leader. MEV both supplements the honest flow (helping) and inflates $V_{\text{attack}}$ and Lee's deviation gain $G_t$ (hurting); its net sign for a Bullshark-style ordering rule is unknown to us. Gong-style fee-taking rules [10] and MEV-smoothing across the leader schedule are candidate mitigations, unanalyzed here.
3. **Long-run fee-market sufficiency.** Even with healthy usage, Auer's free-rider result [3] says decentralized fees underfund the coordinated optimum by $\sim 1/N$; whether $\beta$-burned base fees under an EIP-1559-style mechanism close that gap at AINCORE's throughput is an empirical question we cannot answer pre-launch. Budish's per-transaction bound ($p_{\text{tx}} > \bar v_{\text{tx}}/\alpha$) may ultimately cap the value of individual transactions the chain can safely carry.
4. **Stake concentration and compounding.** Proportional rewards compound genesis inequality [18]; our leader-lottery tranche and open entry mitigate but do not reverse this, and liquid-staking derivatives could re-concentrate effective control or push the system into Chitra & Evans's unsafe region [5]. We have no in-protocol Gini control and claim none.
5. **Governance capture of the dev fund.** A 4-year sunset makes capture contestable, but stake-weighted voting means the same concentration dynamics in (4) determine who contests it; Decred-style ratification has never been stress-tested against a hostile stake majority. The 10%/sunset design is a bet on Decred's track record, not a theorem.
6. **$\sigma$ as a live parameter.** Proposition 1's guarantee evaporates if $\sigma$ drifts below $1/3$. The protocol should expose $\sigma$ as a monitored consensus-health metric with governance-adjustable yield response; the correct feedback controller (Avalanche-style hysteresis-bounded parameters are the nearest prior art) is future work.

---

## 10. Conclusion

We have presented a complete emission design for a hard-capped, fair-launch PoS L1 that takes the security-budget literature at its word. The literature says fee-only regimes are unstable (Carlsten et al.), underfunded (Auer), and stake-unstable under terminal supplies (Chitra); it prescribes permanent rewards, yield calibration, and burned base fees. Our composition delivers all three while keeping the monetary promise: geometric disinflation with no cliffs and a 91-year subsidy horizon; a $>2/3$-BFT-derived, scale-free supply-constrained attack window active whenever $\sigma > 1/3$; a Decred-shaped, sunset-guarded 10% treasury; and a burn-funded tail whose every-instant net-cap invariant $S(t) \le 150\text{M}$ is a one-line proof over two monotone counters, implemented in exact integer arithmetic with machine-checked conservation. We have been explicit that the burn-funded-tail *concept* belongs to prior art — Zcash's NSM most directly — and that the mechanism's floor is proportional to usage: it buys a century of runway and couples perpetual security to demand, which is, we argue, the strongest position available to a hard-capped chain given everything currently proven. The problems that remain open — fee sufficiency at scale, MEV, compounding concentration, governance capture — are the field's open problems, and we prefer to inherit them visibly than to obscure them behind a cap that quietly cannot pay its guards.

---

## References

[1] E. Budish. *Trust at Scale: The Economic Limits of Cryptocurrencies and Blockchains.* Quarterly Journal of Economics 140(1), 2025 (NBER Working Paper w24717). https://www.nber.org/system/files/working_papers/w24717/w24717.pdf ; https://academic.oup.com/qje/article/140/1/1/7824430

[2] M. Carlsten, H. Kalodner, S. M. Weinberg, A. Narayanan. *On the Instability of Bitcoin Without the Block Reward.* ACM CCS 2016. https://www.cs.princeton.edu/~arvindn/publications/mining_CCS.pdf

[3] R. Auer. *Beyond the Doomsday Economics of "Proof-of-Work" in Cryptocurrencies.* BIS Working Paper 765, 2019. https://www.bis.org/publ/work765.pdf

[4] T. Chitra. *Competitive Equilibria Between Staking and On-chain Lending.* arXiv:2001.00919, 2019. https://arxiv.org/abs/2001.00919

[5] T. Chitra, A. Evans. *Why Stake When You Can Borrow?* arXiv:2006.11156, 2020. https://arxiv.org/abs/2006.11156

[6] J. Bonneau, A. Miller, J. Clark, A. Narayanan, J. Kroll, E. Felten. *SoK: Research Perspectives and Challenges for Bitcoin and Cryptocurrencies.* IEEE S&P 2015. https://css.csail.mit.edu/6.566/2018/readings/sok-bitcoin.pdf

[7] J. Lee. *Bitcoin After Block Rewards.* arXiv:2606.05503, 2026. https://arxiv.org/abs/2606.05503

[8] V. Srivastava, S. Damle, S. Gujar. *Bootstrapping Proof-of-Stake Blockchains.* arXiv:2404.09627, 2024. https://arxiv.org/abs/2404.09627

[9] I. Tsabary, I. Eyal. *The Gap Game.* ACM CCS 2018. https://arxiv.org/abs/1805.05288

[10] T. Gong, M. Minaei, W. Sun, A. Kate. *Towards Overcoming the Undercutting Problem.* Financial Cryptography 2022. https://arxiv.org/abs/2007.11480

[11] T. Roughgarden. *Transaction Fee Mechanism Design for the Ethereum Blockchain: An Economic Analysis of EIP-1559.* arXiv:2012.00854, 2020. https://arxiv.org/abs/2012.00854

[12] T. Roughgarden. *Transaction Fee Mechanism Design.* ACM EC 2021. https://arxiv.org/abs/2106.01340

[13] P. Todd. *Surprisingly, Tail Emission Is Not Inflationary.* 2022. https://petertodd.org/2022/surprisingly-tail-emission-is-not-inflationary ; Monero tail emission: https://www.getmonero.org/resources/moneropedia/tail-emission.html ; https://p2pool.io/tail.html

[14] Zcash Improvement Proposals 233, 234, 235 (Network Sustainability Mechanism, Draft). https://zips.z.cash/zip-0233 ; https://zips.z.cash/zip-0234 ; https://zips.z.cash/zip-0235

[15] V. Buterin. *EIP-1559 FAQ.* https://notes.ethereum.org/@vbuterin/eip-1559-faq ; EIP-1559 spec: https://eips.ethereum.org/EIPS/eip-1559

[16] Freicoin FAQ: http://freico.in/faq/ ; Ergo Platform. *Storage Rent and the Future of Mining.* 2022. https://ergoplatform.org/en/blog/2022-01-27-storage-rent-and-the-future-of-mining/ ; Avalanche rewards formula: https://build.avax.network/docs/primary-network/validate/rewards-formula ; https://www.avax.network/about/tokens

[17] I. Bentov, A. Gabizon, A. Mizrahi. *Cryptocurrencies Without Proof of Work.* arXiv:1406.5694, 2014. https://arxiv.org/pdf/1406.5694

[18] G. Fanti, L. Kogan, S. Oh, K. Ruan, P. Viswanath, G. Wang. *Compounding of Wealth in Proof-of-Stake Cryptocurrencies.* Financial Cryptography 2019. https://arxiv.org/abs/1809.07468

[19] J. R. Jensen, V. von Wachter, O. Ross. *How Decentralized Is the Governance of Blockchain-based Finance?* arXiv:2102.10096, 2021. https://arxiv.org/abs/2102.10096

[20] Decred premine and issuance: https://docs.decred.org/advanced/premine/ ; DCP-0010: https://github.com/decred/dcps/blob/master/dcp-0010/dcp-0010.mediawiki ; DCP-0012: https://github.com/decred/dcps/blob/master/dcp-0012/dcp-0012.mediawiki ; treasury: https://dcrdata.decred.org/treasury ; Zcash ZIP 1014: https://zips.z.cash/zip-1014 ; ZIP 1015: https://zips.z.cash/zip-1015 ; ZIP 1016: https://zips.z.cash/zip-1016

[21] EIP-1559 burn data: https://www.theblock.co/data/on-chain-metrics/ethereum/burned-eth-after-eip-1559-daily ; https://ultrasound.money ; post-Dencun collapse analysis: https://ecoinimist.com/2025/04/14/ethereum-inflation-puzzle-4-5m-eth/

[22] Messari token allocation analysis: https://messari.io/token-unlocks/allocation-analysis ; Mina Genesis Program: https://minaprotocol.com/genesis ; Celestia Genesis Drop: https://blog.celestia.org/genesis-drop/ ; Edgeware lockdrop: https://docs.edgeware.wiki/edgeware-stack/lockdrop ; Keyrock airdrop study: https://keyrock.com/airdrops-in-the-barren-desert/ ; Nakamoto coefficients: https://chainspect.app/dashboard/decentralization