# Adversarial Review: "Supply-Neutral Perpetual Security" (AINCORE Research, Draft July 2026)

All key tables were independently recomputed with exact rational/decimal arithmetic and a pure-integer 200-year simulation of the paper's own carry algorithm.

## Category 1 — Arithmetic errors

The core tables are **almost entirely correct**. Verified as accurate: A₁ = 7,450,000 / 10,430,000 / 14,900,000; per-block rewards 0.23623795 / 0.33073313 / 0.47247590; half-lives 13.513 / 9.551 / 6.579 yr; 1%-of-A₁ years 91 / 65 / 45; the full §5.1 cumulative table; C₁ = 4.725M / 6.215M / 8.45M; every nominal-yield cell (e.g. 354.76%, 236.51%, 132.83%, 18.08%, 12.05%); every iₙ cell; the Bresenham base payout 23,623,795 bu with exactly 880,000 (+1)-blocks; the dust-split example (2,362,379 / 4,252,283 / 17,009,133 sums exactly); the 200-year simulated sum 14,899,477,715,272,882 bu and shortfalls 5,222.85 / 74.09 / 0.105 AIN. The errors that remain:

1. **§5.3, analytic tail value wrong.** "matches the analytic un-emitted tail $E \cdot 0.95^{200} \approx 5{,}215$ AIN" — recomputed: E·0.95²⁰⁰ = **5,222.85 AIN** (0.95²⁰⁰ = 3.50527×10⁻⁵). Ironically the paper's own simulated shortfall (5,222.85) matches the correct analytic value to 8 significant figures; the quoted "5,215" understates the paper's own agreement. Correct to ≈ 5,223.

2. **§5.3, decay-loop bound off by ~10×.** "`let t = a * Q_NUM + carry;   // max ≈ 1.5e17`" — actual maxima: δ=0.95: 1.416×10¹⁶; δ=0.93: 9.70×10¹⁶; δ=0.90: 1.34×10¹⁶. Worst case is ≈ **1.0×10¹⁷**, not 1.5×10¹⁷. Conclusion (≪ u128::MAX) unaffected, but the stated constant is wrong.

3. **§5.3, Bresenham intermediate bound uses the wrong δ.** "Maximum intermediate $A_1 N \approx 4.7 \times 10^{22}$" — for the *selected* schedule (δ=0.95, A₁ = 7.45×10¹⁴ bu), A₁N = **2.35×10²²**. 4.7×10²² is the δ=0.90 candidate's value. Either say "worst-case candidate (δ=0.90)" or correct to 2.35×10²².

4. **§8, "real yield" is the wrong formula at these magnitudes.** The table computes yₙ − iₙ (e.g. "+197.09%" at year 1, σ=0.4). The additive approximation is only valid for small rates; the correct real yield is (1+y)/(1+i)−1. Recomputed year 1, δ=0.95: σ=0.4 → **+76.5%** (not +197.09%); σ=0.6 → **+30.6%** (not +78.84%). Year 2: +46.4% / +18.6% (not +73.79% / +29.52%). Even year 10 is off: +9.30% vs the stated +10.04%. The qualitative claim (real yield positive iff y > i) survives, but every number in the real-yield table overstates staker real returns — by a factor of ~2.6 in year 1. This is the most material numeric defect in the paper.

5. **§2, Mina percentage.** "grants of 66,000 MINA to up to 1,000 members, 6.67% of supply" — 66,000 × 1,000 = 66M of 1B genesis supply = **6.6%**, not 6.67%.

6. **§6.3, dimensional typo.** "$\text{flow}_{\text{tail}} = 0.9\,\beta F \text{ per year} \approx 0.9\,\beta F / N \text{ per block}$" — the "≈" equates a per-year quantity with a per-block quantity that is 3.15×10⁷ times smaller. Should read "per year, i.e. 0.9βF/N per block."

## Category 2 — Overclaims

7. **The central security claim analyzes the wrong (hardest) attack.** Proposition 1 and the abstract ("the stake-acquisition attack is supply-constrained in *every* year whenever staking participation exceeds 1/3") cover only unilateral **supermajority (>2/3)** takeover. In BFT with a >2/3 quorum, the standard adversary needs only **>1/3 of stake** to halt liveness, and safety violation via conflicting quorum certificates requires only >1/3 (quorum-intersection argument). That attack needs A > σCₙ/2 — versus a float of (1−σ)Cₙ — which is market-feasible whenever σ < 2/3, i.e. under **both** of the paper's own scenarios: σ=0.4 needs 0.2Cₙ against a 0.6Cₙ float; σ=0.6 needs 0.3Cₙ against 0.4Cₙ. So the economically relevant attack is *never* supply-constrained in the paper's own parameter range. Prop 1 is arithmetically correct but its framing as "the" attack window is an overclaim; the paper needs a companion analysis of the 1/3 threshold or an explicit scope restriction in the abstract and §7.2.

8. **"machine-checked conservation argument" (§1, Contribution 4) is not machine-checked.** What §5.3 delivers is a 200-year *simulation* in three implementations. "Machine-checked" implies a proof assistant (Coq/Lean/Isabelle) verified the conservation invariant. Rename to "simulation-validated" or actually mechanize it.

9. **"We prove the invariant" vs. "Proof sketch" (Prop 2).** The abstract and §1 say "provable"/"We prove"; §6.2 labels it a *sketch*. The algebra is fine, but what is proven is not what is defined, because the gate itself is garbled (see #12) — so at present the paper proves a proposition about a rule it never correctly states.

10. **The Roughgarden-compliance claim is only partially true.** §6.1: "This simultaneously satisfies Roughgarden's requirement that base-fee revenue be withheld from the current proposer." But §3 says the *unburned* remainder (1−β) of fees "is swept to the leader" — for any β < 1 the direct proposer-payment channel Roughgarden warns about (miner–user collusion recreating a first-price auction) remains open on the (1−β) fraction. Additionally, under reserve-based release, a validator with large stake share recaptures a proportional fraction of its own burned fees over time, weakening the collusion-breaking argument at high concentration. The claim should be scoped to "for the burned fraction β, and only up to recapture effects."

11. **Long-range / posterior-corruption attacks are not even listed as an open problem.** For a chain whose fairness claim rests on a 1M-AIN genesis and enormous early yields, the classic cheap attack is buying *old validator keys* after those validators exit, and rewriting history from a point where the attacker's purchased keys held ≥2/3 — cost decoupled from current stake price. §7.2 mentions OTC acquisition of bootstrap validators as a "social-layer attack" but never addresses key-selling/weak-subjectivity, and §9 omits it. This is a real hole in a paper whose Prop 1 argues "the chain is not safe later but vulnerable while small."

## Category 3 — Internal inconsistencies

12. **The tail gate formula is garbled.** §6.1: "every new grant must satisfy $M_{\text{tail}}(t) \le B(t) - M_{\text{tail}}^{\text{prior}}(t)$". If M_tail(t) is cumulative (as defined two sentences earlier and as used in Prop 2), this reads M_prior + grant ≤ B − M_prior, i.e. grant ≤ B − 2·M_prior — which is neither the intended rule nor the summarized one. The intended condition is either grant ≤ B(t) − M_tail^prior(t), or equivalently cumulative M_tail(t) ≤ B(t). As written, the definition, the display equation below it, and Prop 2's proof use three inconsistent readings.

13. **"Strict-inequality gate" vs. "≤".** Abstract: "its every-instant proof under a *strict-inequality* gate." §6.1 and Prop 2 use non-strict "≤" throughout. Pick one.

14. **Symbol collision on δ.** §2 quotes Chitra's rebalancing condition "$\delta > (C_\infty - 1)\gamma_t \tau_{\text{stake}}\tau_{\text{lend}}/n$" where δ is Chitra's *discount factor*, while everywhere else in the paper δ = 0.95 is the decay parameter. A reader plugging the paper's δ into the quoted condition gets nonsense. Rename one of them (e.g. Chitra's as δ_disc).

15. **§6.1 pass-through gate vs. §6.3 reserve release.** §6.1 defines the mechanism as mint-gated-on-cumulative-burn; §6.3 then "adopt[s] reserve-based release as the reference implementation" (ZIP-234 style). These are compatible (reserve release implies the gate), but the paper never says so, and Prop 2 is proven for the §6.1 rule only. One sentence noting reserve-release ⊆ gate-compliant policies is needed.

16. **Auer underfunding factor stated two ways.** §1: "underfunds security by a factor of roughly the number of transactions per block"; §9.3: "underfund the coordinated optimum by ∼1/N". These intend the same fact but literally say "under by factor N" vs "under by ~1/N of optimum"; harmonize the phrasing.

## Category 4 — Missing standard citations

17. **Narwhal/Tusk and Bullshark — the most glaring omission.** The consensus layer is described as "Narwhal/Tusk (DAG consensus)"-inspired with "Bullshark-style ordering rule" (§9.2), yet neither Danezis, Kokoris-Kogias, Sonnino, Spiegelman, *Narwhal and Tusk* (EuroSys 2022) nor Spiegelman et al., *Bullshark* (CCS 2022) appears in the references.

18. **BFT threshold classics.** The >2/3 quorum and the 1/3 fault bound carry Prop 1; cite Pease–Shostak–Lamport (JACM 1980) and/or Castro–Liskov, *PBFT* (OSDI 1999).

19. **Eyal & Sirer, *Majority Is Not Enough* (FC 2014).** "Selfish mining" is invoked repeatedly (§1, §2) only via Carlsten et al.; the originating paper is a standard cite.

20. **VDFs.** VDF leader election is load-bearing (§5.2, §7.3) with no citation — Boneh, Bonneau, Bünz, Fisch (CRYPTO 2018), plus Pietrzak/Wesolowski constructions.

21. **PoS long-range attack literature** (goes with issue #11): Gaži–Kiayias–Russell *Stake-Bleeding Attacks* (2018) and/or Buterin's weak-subjectivity note.

22. **Saleh, *Blockchain Without Waste: Proof-of-Stake* (Review of Financial Studies, 2021)** — the standard PoS-security-economics reference; conspicuously absent next to Chitra and Fanti et al.

## Category 5 — Supply-cap invariant holes

The algebra of Prop 2 is sound *given* a correctly stated gate and the verified floor-division schedule (∑Aₙ ≤ E confirmed by recomputation). The holes are in scope, not arithmetic:

23. **Slashing flows are outside S(t).** §3 models slashing (fraction s, 5% downtime slash), but S(t) = G + M_tail − B has no slash term. If slashed stake is burned: is it credited to B(t) and thus *re-mintable as tail*? If slash proceeds are paid to reporters/whistleblowers or the treasury as fresh mint, the cap breaks outright. The paper must state where slashed value goes and whether it enters the burn counter.

24. **B(t) is misdefined under variable β.** §6.1: "$B(t) = \beta \cdot (\text{cumulative fees})$" — but §6.3 makes β "the governance throttle," i.e. time-varying. Current-β-times-cumulative-fees is then wrong (retroactively re-scales past burns). B(t) must be defined as the sum of *actually burned* amounts, ∑ β(τ)·fees(τ) — which is also what the "monotone counter" implementation actually tracks. The proof survives; the definition doesn't.

25. **The invariant silently assumes emission-schedule + tail are the *only* mint paths.** G(t) ≤ 1M + E holds only if nothing else ever mints: no fraud-proof bounties (the DA layer has FraudProofVerifier/SlashingParams), no bridge mint/burn asymmetry (EVM/BTC bridges are in scope for AINCORE), no governance emergency issuance. Prop 2 should state this closure assumption explicitly, since the surrounding system has at least two candidate violators.

26. **Net vs. gross cap — the monetary-credibility claim is semantic.** Under the mechanism, *gross cumulative issuance is unbounded*; only net outstanding supply is ≤150M. §1 does say "net 150M hard cap," but the abstract's framing ("a promised 150M hard cap … yielding a provable net-supply invariant") invites reading it as preserving the original gross promise. A chain that has minted 300M total with 150M outstanding satisfies S(t) ≤ 150M. Whether the market accepts a net cap as "the hard cap kept" is exactly the credibility question the paper claims to resolve; it should be argued, not assumed.

## Per-category verdict

1. **Arithmetic:** sound except issues #1–6; all headline tables (A₁, per-block, half-lives, schedule, nominal yields, attack costs, integer simulation) recompute exactly. The real-yield table (#4) is the one materially misleading set of numbers.
2. **Overclaims:** not sound — #7 (1/3-threshold attack ignored) and #8 (machine-checked) require substantive revision; the novelty scoping in §2, by contrast, is commendably honest and survives adversarial reading.
3. **Internal consistency:** not sound — #12 (garbled gate) must be fixed before Prop 2 can be called proven; #13–16 are editorial.
4. **Citations:** not sound — #17 (Narwhal/Bullshark) is a must-fix; #18–22 expected by any referee.
5. **Supply-cap invariant:** algebra sound; scope holes #23–25 need explicit closure assumptions, and #26 needs an argument rather than an assertion.