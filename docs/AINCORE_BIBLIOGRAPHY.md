# AINCORE — Master Annotated Bibliography

> Research foundation for AINCORE: a sovereign DAG-BFT PoS L1 (Narwhal/Tusk-style separated mempool, Bullshark-lite ordering, BLS quorum-certificate >2/3-stake finality, VDF anchor-leader election, Move VM, 150M hard-capped fair-launch token with emission v4 and equivocation slashing).
>
> **Legend** — `[ALREADY CITED]` = present in `docs/AINCORE_EMISSION_PAPER.md` refs [1–22]; `[NEW]` = not yet cited (candidate for the whitepaper). Within each section, entries run **foundational → important → supporting**. All citations verified against primary sources (arXiv / IACR ePrint / venue / author-hosted); none fabricated.
>
> Last updated: 2026-07-16

---

## A. Consensus & BFT

**A1. Lamport, Shostak, Pease — "The Byzantine Generals Problem" (TOPLAS 1982; companion "Reaching Agreement in the Presence of Faults", JACM 1980)** · *foundational* · `[NEW]`
<https://lamport.azurewebsites.net/pubs/byz.pdf>
- **Key result:** Byzantine agreement is impossible unless n > 3f; the companion fixes the 3f+1 bound.
- **Why AINCORE cites it:** Theoretical origin of AINCORE's `(n*2/3)+1` quorum and >2/3-stake finality — the stake-weighted instantiation of the 3f+1 bound.

**A2. Castro, Liskov — "Practical Byzantine Fault Tolerance" (OSDI 1999)** · *foundational* · `[NEW]`
<https://pmg.csail.mit.edu/papers/osdi99.pdf>
- **Key result:** First practical partially-synchronous BFT SMR: three-phase pre-prepare/prepare/commit with view changes, tolerating f of 3f+1.
- **Why AINCORE cites it:** Source of the quorum-certificate + equivocation-detection vocabulary AINCORE's vote collection and double-sign slashing inherit.

**A3. Keidar, Kokoris-Kogias, Naor, Spiegelman — "All You Need is DAG" (DAG-Rider) (PODC 2021)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/2102.08325>
- **Key result:** First asynchronous BFT atomic broadcast where ordering is extracted by locally interpreting a round-based DAG — zero extra ordering messages.
- **Why AINCORE cites it:** The theoretical basis of AINCORE's OrderingEngine — commit by interpreting the vertex DAG, no additional voting rounds.

**A4. Danezis, Kokoris-Kogias, Sonnino, Spiegelman — "Narwhal and Tusk: A DAG-based Mempool and Efficient BFT Consensus" (EuroSys 2022)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/2105.11827>
- **Key result:** Separates data dissemination (Narwhal certified-mempool DAG) from consensus (Tusk zero-overhead ordering), sustaining throughput under partitions.
- **Why AINCORE cites it:** THE architectural blueprint — AINCORE's `try_create_vertex`/`add_vertex` certified-vertex DAG and throughput/ordering decoupling are Narwhal by design. Most load-bearing single citation.

**A5. Spiegelman, Giridharan, Sonnino, Kokoris-Kogias — "Bullshark: DAG BFT Protocols Made Practical" (ACM CCS 2022)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/2201.05677>
- **Key result:** Low-latency partially-synchronous commit over a Narwhal DAG using predefined anchor leaders, with async fallback and no extra consensus messages.
- **Why AINCORE cites it:** AINCORE's ordering is explicitly "Bullshark-lite" — this defines the anchor-leader rule (`try_commit`, 2f+1 support from the next round) it implements.

**A6. Yin, Malkhi, Reiter, Golan Gueta, Abraham — "HotStuff: BFT Consensus with Linearity and Responsiveness" (PODC 2019)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/1803.05069>
- **Key result:** Partially-synchronous BFT with O(n) per-view communication via aggregate/threshold signatures, optimistic responsiveness, pipelined leader rotation.
- **Why AINCORE cites it:** Canonical source for aggregating 2f+1 votes into one linear-size quorum certificate — the BLS QC design AINCORE uses — and the leader-based baseline DAG-BFT improves on.

**A7. Buchman, Kwon, Milosevic — "The latest gossip on BFT consensus" (Tendermint) (2018)** · *important* · `[NEW]`
<https://arxiv.org/abs/1807.04938>
- **Key result:** Gossip-based, PBFT-derived BFT with immediate deterministic finality under a >2/3 voting-power commit and accountable propose/prevote/precommit rounds.
- **Why AINCORE cites it:** Canonical reference for stake-weighted >2/3 instant finality plus slashing-on-double-sign accountability — AINCORE's finality model.

**A8. Buterin, Griffith — "Casper the Friendly Finality Gadget" (2017)** · *important* · `[NEW]`
<https://arxiv.org/abs/1710.09437>
- **Key result:** Accountable safety: two slashing conditions (no double-vote, no surround-vote); if two conflicting checkpoints finalize, ≥1/3 of stake is provably attributable and burnable.
- **Why AINCORE cites it:** Theoretical backbone of AINCORE's slashing subsystem (`sys:pending_slash`, `validator:jailed`, equivocation instant-slash) and the ≥1/3-attributability guarantee it should claim.

**A9. Nakamoto — "Bitcoin: A Peer-to-Peer Electronic Cash System" (2008)** · *important* · `[NEW]`
<https://bitcoin.org/bitcoin.pdf>
- **Key result:** Permissionless Sybil-resistant consensus via PoW and the longest-chain rule, giving probabilistic finality and open membership.
- **Why AINCORE cites it:** The baseline AINCORE departs from — deterministic BFT finality (not probabilistic), stake-weighting (not PoW), ~1s blocks — while keeping open participation via staking + slashing.

**A10. Kiayias, Russell, David, Oliynykov — "Ouroboros: A Provably Secure Proof-of-Stake Blockchain Protocol" (CRYPTO 2017; ePrint 2016/889)** · *important* · `[NEW]`
<https://eprint.iacr.org/2016/889>
- **Key result:** First PoS with a rigorous persistence + liveness proof; identifies grinding and defends with a secure randomness beacon.
- **Why AINCORE cites it:** Grounds the stake-weighted validator model and motivates VDF-based unbiasable anchor-leader election in `ordering.rs`.

**A11. Sompolinsky, Zohar — "Secure High-Rate Transaction Processing in Bitcoin" / GHOST (FC 2015; ePrint 2013/881)** · *supporting* · `[NEW]`
<https://eprint.iacr.org/2013/881>
- **Key result:** Heaviest-subtree chain selection lets block-rate/throughput rise without sacrificing security against orphan/selfish-mining attacks.
- **Why AINCORE cites it:** The intellectual bridge from single-chain to DAG-structured consensus that AINCORE's Narwhal-style mempool DAG generalizes.

**A12. Team Rocket et al. — "Scalable and Probabilistic Leaderless BFT Consensus through Metastability" (Avalanche) (2019)** · *supporting* · `[NEW]`
<https://arxiv.org/abs/1906.08936>
- **Key result:** Leaderless repeated subsampled voting drives the network to a metastable decision with high-probability safety and no fixed quorum round.
- **Why AINCORE cites it:** The main non-quorum alternative — cited to justify choosing deterministic QC-BFT for instant >2/3 finality and slashing accountability.

**A13. Abraham, Malkhi, Nayak, Ren, Yin — "Sync HotStuff" (IEEE S&P 2020; ePrint 2019/270)** · *supporting* · `[NEW]`
<https://eprint.iacr.org/2019/270>
- **Key result:** Optimally-resilient synchronous BFT tolerating f < n/2 with a two-round steady state and ~2Δ latency.
- **Why AINCORE cites it:** Frames the synchrony trade-off — the reference for why AINCORE adopts a partially-synchronous n/3 model over the n/2 resilience a synchrony assumption would buy.

---

## B. PoS Security & Attacks

**B1. David, Gaži, Kiayias, Russell — "Ouroboros Praos" (EUROCRYPT 2018; ePrint 2017/573)** · *foundational* · `[NEW]`
<https://eprint.iacr.org/2017/573>
- **Key result:** Adaptive-adversary security in a semi-synchronous net via VRF private leader election and forward-secure signatures.
- **Why AINCORE cites it:** Two hardening items — unpredictable leader selection to a lookahead adversary, and forward-secure keys to close AINCORE's plain-Ed25519 old-key long-range vector.

**B2. Gaži, Kiayias, Russell — "Stake-Bleeding Attacks on Proof-of-Stake Blockchains" (CVCBT 2018; ePrint 2018/248)** · *foundational* · `[NEW]`
<https://eprint.iacr.org/2018/248>
- **Key result:** A constant-stake adversary grows a private chain from the past using fees + transaction replay until it overtakes — checkpoint-free PoS breaks within a few years.
- **Why AINCORE cites it:** The canonical demonstration justifying why AINCORE's BFT finality + 100-round DAG checkpoints (and the `finality_digest` rolling hash) are non-optional.

**B3. Neu, Tas, Tse — "Ebb-and-Flow Protocols: A Resolution of the Availability-Finality Dilemma" (IEEE S&P 2021)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/2009.04987>
- **Key result:** No single ledger is both available under dynamic participation and safe under partition; resolve by coupling a dynamically-available ledger with a finalized BFT prefix.
- **Why AINCORE cites it:** Exactly AINCORE's design — DAG availability layer + BFT finality gadget — and validates the split-brain rule (isolated validators stop mining) as the correct safety-over-liveness posture under partition.

**B4. Buterin — "Proof of Stake: How I Learned to Love Weak Subjectivity" (Ethereum Foundation blog, 2014)** · *important* · `[NEW]`
<https://blog.ethereum.org/2014/11/25/proof-stake-learned-love-weak-subjectivity>
- **Key result:** A PoS client offline longer than the weak-subjectivity period cannot pick the canonical chain from protocol rules alone and needs a recent trusted checkpoint.
- **Why AINCORE cites it:** Defines the operational onboarding requirement — a new/long-offline AINCORE node must receive a recent trusted checkpoint, not just `genesis.json`.

**B5. Brown-Cohen, Narayanan, Psomas, Weinberg — "Formal Barriers to Longest-Chain Proof-of-Stake Protocols" (ACM EC 2019)** · *important* · `[NEW]`
<https://dl.acm.org/doi/10.1145/3328526.3329567>
- **Key result:** Longest-chain PoS cannot be simultaneously incentive-compatible, unpredictable, and fair; formalizes the predictability-vs-grinding trade-off.
- **Why AINCORE cites it:** Justifies choosing a BFT/DAG finality gadget over longest-chain PoS, and reminds that any predictable leader schedule invites selfish-proposing — so VDF unpredictability matters.

**B6. Deb, Kannan, Tse — "PoSAT: Proof-of-Work Availability and Unpredictability, without the Work" (FC 2021)** · *important* · `[NEW]`
<https://arxiv.org/abs/2010.08154>
- **Key result:** VRF + VDF forces real wall-clock block production, restoring PoW-like availability and full proposer unpredictability while defending against posterior corruption / costless simulation.
- **Why AINCORE cites it:** Shows the VDF is not just an unbiased-randomness tool but a defense against costless history re-simulation — rationale for making the VDF a hard timing gate.

**B7. Azouvi, Danezis, Nikolaenko — "Winkle: Foiling Long-Range Attacks in Proof-of-Stake Systems" (ACM AFT 2020; ePrint 2019/1440)** · *important* · `[NEW]`
<https://eprint.iacr.org/2019/1440>
- **Key result:** Client-based checkpointing — users co-sign a recent block hash with normal transactions; coin-weighted confirmations become checkpoints resistant to later validator-key leakage.
- **Why AINCORE cites it:** A deployable, decentralized long-range defense — AINCORE's user-signed mempool transactions can carry Winkle-style checkpoint confirmations, avoiding reliance on a single trusted checkpoint provider.

**B8. Poelstra — "On Stake and Consensus" (2015)** · *supporting* · `[NEW]`
<https://download.wpsoftware.net/bitcoin/pos.pdf>
- **Key result:** Canonical statement of nothing-at-stake — because signing is costless, rational validators build on every fork, preventing convergence.
- **Why AINCORE cites it:** The problem statement motivating AINCORE's equivocation slashing (same author + round + different hash → instant slash); use it to stress-test that the detector catches all cross-fork double-signing.

**B9. Aiyer / Daian, Pass, Shi — "Snow White: Robustly Reconfigurable Consensus…" (FC 2019; ePrint 2016/919)** · *supporting* · `[NEW]`
<https://eprint.iacr.org/2016/919>
- **Key result:** Early provably-secure PoS with robust validator-set reconfiguration and explicit posterior-corruption treatment via time-bounded corruption.
- **Why AINCORE cites it:** Reference for secure validator-set reconfiguration — that stake churn (`sys:validators` / BCS `ValidatorSet` updates) must not open equivocation or long-range windows.

**B10. Dembo, Kannan, Tas, Tse, Viswanath, Wang, Zeitouni — "Everything is a Race and Nakamoto Always Wins" (ACM CCS 2020)** · *supporting* · `[NEW]`
<https://arxiv.org/abs/2005.10484>
- **Key result:** Unifying private-chain "race" analysis giving tight settlement/confirmation-depth bounds; PoS longest-chain tolerates less than PoW due to grinding.
- **Why AINCORE cites it:** Supplies the quantitative vocabulary to argue AINCORE's BFT finality is strictly stronger than probabilistic longest-chain settlement (consensus-analysis appendix).

---

## C. Token & Monetary Economics

**C1. Budish — "Trust at Scale: The Economic Limits of Cryptocurrencies and Blockchains" (QJE 2025; NBER WP 24717)** · *foundational* · `[ALREADY CITED]`
<https://academic.oup.com/qje/article/140/1/1/7824430>
- **Key result:** Zero-profit + incentive-compatibility jointly force the recurring reward flow to dominate the one-off attack payoff; equilibrium security cost scales ~linearly with value secured.
- **Why AINCORE cites it:** Master constraint — per-round flow + slashable stock must dominate the largest reorg payoff; the yardstick for whether a tail emission or fee floor is mandatory under the 150M cap.

**C2. Saleh — "Blockchain Without Waste: Proof-of-Stake" (RFS 2021)** · *foundational* · `[NEW]`
<https://academic.oup.com/rfs/article-abstract/34/3/1156/5868423>
- **Key result:** A sufficiently modest reward schedule yields a unique consensus equilibrium and rules out persistent forking, because validators are stakeholders.
- **Why AINCORE cites it:** The reference for calibrating emission v4 magnitude and slashing — over-rewarding validators re-introduces the forking equilibrium; also frames whether fee-sweep-to-leader distorts incentives.

**C3. Carlsten, Kalodner, Weinberg, Narayanan — "On the Instability of Bitcoin Without the Block Reward" (ACM CCS 2016)** · *foundational* · `[ALREADY CITED]`
<https://www.cs.princeton.edu/~arvindn/publications/mining_CCS.pdf>
- **Key result:** A fee-only regime is unstable: lumpy fee accumulation makes forking/undercutting a wealthy block profitable.
- **Why AINCORE cites it:** Directly critical — once halving drives emission to zero, AINCORE approaches the fee-dominated regime, and sweeping fees to the leader is exactly the undercutting hazard; argues for fee smoothing or tail emission.

**C4. Auer — "Beyond the Doomsday Economics of 'Proof-of-Work'…" (BIS WP 765, 2019)** · *foundational* · `[ALREADY CITED]`
<https://www.bis.org/publ/work765.htm>
- **Key result:** A fee market cannot by itself fund adequate security (users free-ride); subsidy withdrawal is a structural threat.
- **Why AINCORE cites it:** Macro-prudential backbone for the emission-v4 decision — motivates seriously evaluating a Monero-style tail emission vs. an accepted shrinking security budget.

**C5. Roşu, Saleh — "Evolution of Shares in a Proof-of-Stake Cryptocurrency" (Management Science 2021)** · *foundational* · `[NEW]`
<https://pubsonline.informs.org/doi/10.1287/mnsc.2020.3791>
- **Key result:** Absent trading, each holder's fractional stake is a martingale — proportional staking does not mechanically concentrate ownership.
- **Why AINCORE cites it:** Defends the fair-launch narrative: stake-proportional rewards are not "rich-get-richer"; decentralization must be protected at genesis distribution, not by fighting compounding.

**C6. Fanti, Kogan, Oh, Ruan, Viswanath, Wang — "Compounding of Wealth in Proof-of-Stake Cryptocurrencies" (FC 2019)** · *foundational* · `[ALREADY CITED]`
<https://arxiv.org/abs/1809.07468>
- **Key result:** Poor "equitability" arises from a small initial stake pool and/or large rewards relative to it; geometric reward schemes help.
- **Why AINCORE cites it:** Pinpoints the real fair-launch risk — a thin genesis validator set + large pre-halving rewards; argues for broad genesis distribution and bounded early emission.

**C7. Chitra — "Competitive Equilibria Between Staking and On-Chain Lending" (SBC / arXiv 2020)** · *foundational* · `[ALREADY CITED]`
<https://arxiv.org/abs/2001.00919>
- **Key result:** When lending yield exceeds staking inflation, holders unstake to lend, lowering the staked fraction and cost of attack toward an insecure equilibrium.
- **Why AINCORE cites it:** As Move DeFi grows, AINCORE's real staking yield must stay competitive with its own lending markets — a hard floor on how far post-halving emission can be cut.

**C8. John, Rivera, Saleh — "Equilibrium Staking Levels in a Proof-of-Stake Blockchain" (SSRN 3965599, 2021)** · *foundational* · `[NEW]`
<https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3965599>
- **Key result:** Equilibrium staking is non-monotonic in block rewards — higher rewards can lower total staked value.
- **Why AINCORE cites it:** Warns against "raise emission → more security"; the map from emission rate to dollar-value-of-stake securing AINCORE must be optimized, not front-loaded.

**C9. Pagnotta — "Decentralizing Money: Bitcoin Prices and Blockchain Security" (RFS 2022)** · *important* · `[NEW]`
<https://academic.oup.com/rfs/article-abstract/35/2/866/6104899>
- **Key result:** Price↔security feedback yields multiple equilibria (high/high vs low/low) and boom-bust cycles.
- **Why AINCORE cites it:** Security is endogenous to AIN price — a hard cap does not secure the chain if price collapses; argues for a budget robust across price regimes and cautions that halvings can shift equilibria.

**C10. Cong, Li, Wang — "Tokenomics: Dynamic Adoption and Valuation" (RFS 2021)** · *important* · `[NEW]`
<https://academic.oup.com/rfs/article-abstract/34/3/1105/5891182>
- **Key result:** Token value derives from aggregated transactional demand (network externality); adoption follows an S-curve with price↔adoption feedback.
- **Why AINCORE cites it:** Valuation framework for AIN as a utility/gas/staking token — the demand-side model complementing the supply-side emission schedule.

**C11. Cong, He, Li — "Decentralized Mining in Centralized Pools" (RFS 2021; NBER WP 25592)** · *important* · `[NEW]`
<https://academic.oup.com/rfs/article-abstract/34/3/1191/5815571>
- **Key result:** Larger risk-sharing pools charge higher fees and grow more slowly — an endogenous brake on centralization — but escalate the arms race.
- **Why AINCORE cites it:** Same logic governs AINCORE staking-pool formation; concentration is partly self-limiting, but the externality argues for protocol-level pool caps / anti-Sybil in validator-set logic.

**C12. Brünjes, Kiayias, Koutsoupias, Stouka — "Reward Sharing Schemes for Stake Pools" (IEEE EuroS&P 2020)** · *important* · `[NEW]`
<https://arxiv.org/abs/1807.11218>
- **Key result:** Cardano's (k, a0) scheme makes "exactly k pools" a Nash equilibrium and uses operator pledge to trade efficiency against Sybil-resistance.
- **Why AINCORE cites it:** A deployable blueprint if AINCORE wants to steer toward a target validator/pool count and use self-stake pledge to deter Sybil splitting.

**C13. Schilling, Uhlig — "Some Simple Bitcoin Economics" (JME 2019)** · *important* · `[NEW]`
<https://www.sciencedirect.com/science/article/pii/S0304393219301199>
- **Key result:** With deterministic supply the crypto price is a martingale; "mutual impatience" rules out bubbles; block rewards are a real resource cost.
- **Why AINCORE cites it:** Canonical monetary treatment of a fixed-supply currency — exactly AINCORE's 150M-cap halving; provides the martingale-price benchmark and seigniorage-incidence framing.

**C14. Fernández-Villaverde, Sanches — "Can Currency Competition Work?" (JME 2019)** · *important* · `[NEW]`
<https://www.nber.org/papers/w22157>
- **Key result:** Competing private monies admit a stable equilibrium but also a continuum where value drifts to zero; productive capital removes the zero paths.
- **Why AINCORE cites it:** Frames the existential risk — a fixed supply alone does not prevent value→0; AINCORE must couple the cap with genuine on-chain utility to select the good equilibrium.

**C15. Liu, Lu, Nayak, Zhang, Zhang, Zhao — "Empirical Analysis of EIP-1559…" (ACM CCS 2022)** · *important* · `[ALREADY CITED]`
<https://arxiv.org/abs/2201.05574>
- **Key result:** EIP-1559 improved fee estimation and cut variance/waiting time but had only small effects on average fees and consensus security.
- **Why AINCORE cites it:** Reality check — a fee-burn upgrade would improve AINCORE UX (mitigating Carlsten lumpiness) but should not be sold as a security-budget fix.

**C16. Cong, He — "The Tokenomics of Staking" (NBER WP 33640, 2025)** · *supporting* · `[NEW]`
<https://www.nber.org/papers/w33640>
- **Key result:** Structural treatment of participation, reward-rate setting, and the staking-yield / inflation / security interplay with PoS-era data.
- **Why AINCORE cites it:** Up-to-date synthesis for calibrating AINCORE's target staking ratio and reward rate, complementing John-Rivera-Saleh.

**C17. John, Rivera, Saleh — "Proof-of-Work versus Proof-of-Stake: A Comparative Economic Analysis" (SSRN 3750467, 2020)** · *supporting* · `[NEW]`
<https://papers.ssrn.com/sol3/papers.cfm?abstract_id=3750467>
- **Key result:** Formal head-to-head on cost of security; clarifies when PoS achieves comparable security at lower real cost and how the budget must be funded.
- **Why AINCORE cites it:** Backs the PoS choice on cost grounds — emission + slashing calibration, not hashrate, are AINCORE's security levers.

**C18. Zargham, Shorish, Paruch — "From Curved Bonding to Configuration Spaces" (IEEE ICBC 2020; cadCAD)** · *supporting* · `[NEW]`
<https://blog.block.science/from-curved-bonding-to-configuration-spaces/>
- **Key result:** Generalizes bonding curves to invariant conservation functions over a token economy's configuration space.
- **Why AINCORE cites it:** Methodology + cadCAD tooling to simulate emission v4, slashing, and future bonding/AMM mechanisms before mainnet.

**C19. Xiong et al. — "SoK: Liquid Staking Tokens (LSTs) and Emerging Trends in Restaking" (2024)** · *supporting* · `[NEW]`
<https://arxiv.org/abs/2404.00644>
- **Key result:** Systematizes LST/restaking mechanics and their impact on security thresholds; centralized-governance LSTs track rewards more efficiently, sharpening the efficiency-vs-centralization tension.
- **Why AINCORE cites it:** Guidance on whether/how to constrain LSTs in the staking module and how slashing must propagate to derivative holders.

**C20. Wang et al. — "Leverage Staking with Liquid Staking Derivatives (LSDs)…" (2024)** · *supporting* · `[NEW]`
<https://arxiv.org/abs/2401.08610>
- **Key result:** Recursive leverage-staking amplifies yield but stacks depeg, liquidation-cascade, and correlated-slashing risk.
- **Why AINCORE cites it:** Concrete risk catalog for AINCORE staking × Move DeFi — a slashing event could cascade into liquidations; informs slashing-parameter guardrails.

---

## D. Mechanism Design & MEV

**D1. Myerson — "Optimal Auction Design" (Math. of OR, 1981)** · *foundational* · `[NEW]`
<https://doi.org/10.1287/moor.6.1.58>
- **Key result:** Revenue-optimal single-item auction via the Revelation Principle and virtual valuations (Myerson's Lemma).
- **Why AINCORE cites it:** Sets the theoretical ceiling and the IC/IR/reserve-price language for AINCORE's fee market; shows a naive first-price "highest fee wins" sweep is not truthful.

**D2. Vickrey (1961) / Clarke (1971) / Groves (1973) — the VCG mechanism** · *foundational* · `[NEW]`
<https://doi.org/10.1111/j.1540-6261.1961.tb02789.x>
- **Key result:** Dominant-strategy-truthful, welfare-maximizing mechanism where each winner pays the externality it imposes (second price in the single-item case).
- **Why AINCORE cites it:** Baseline truthful blockspace auction — explains why AINCORE's first-price fee sweep is not incentive-compatible and what a second-price alternative buys (plus VCG's permissionless-L1 fragilities).

**D3. Roughgarden — "Transaction Fee Mechanism Design…" (EIP-1559 analysis, 2020; EC 2021 / JACM 2024)** · *foundational* · `[ALREADY CITED]`
<https://arxiv.org/abs/2012.00854>
- **Key result:** TFM axioms UIC/MIC/OCA-proofness; EIP-1559 is UIC and MIC under non-congestion, and the burned base fee is what gives MIC.
- **Why AINCORE cites it:** Directly diagnoses AINCORE's fee design — paying fees to the block producer breaks miner-incentive-compatibility; the load-bearing paper for the burn-vs-sweep decision.

**D4. Chung, Shi — "Foundations of Transaction Fee Mechanism Design" (SODA 2023; ePrint 2021/1474)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/2111.03151>
- **Key result:** No non-trivial TFM is simultaneously UIC, MIC, and OCA-proof; burning is essential to escape degenerate cases.
- **Why AINCORE cites it:** Forces an explicit "which axiom do we sacrifice?" choice — a proposer who both orders and keeps all fees is maximally exposed to the OCA/collusion failure this isolates.

**D5. Daian, Goldfeder, Kell, Li, Zhao, Bentov, Breidenbach, Juels — "Flash Boys 2.0…" (IEEE S&P 2020)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/1904.05234>
- **Key result:** Coins MEV; shows priority-gas-auction front-running and proves that when MEV exceeds the block reward, rational miners fork/re-org to steal it (consensus instability).
- **Why AINCORE cites it:** The core threat model — AINCORE's Bullshark anchor leader both orders and receives the fee sweep, exactly the MEV-capture position; the fee-based-forking result must be weighed against slashing defenses.

**D6. Roughgarden, Talgam-Cohen — "Approximately Optimal Mechanism Design" (Annual Review of Economics, 2019)** · *important* · `[NEW]`
<https://arxiv.org/abs/1812.11896>
- **Key result:** Simple, detail-free mechanisms (posted prices, anchored reserves) achieve constant-factor approximations to optimal revenue without knowing the distribution.
- **Why AINCORE cites it:** Justifies a simple, prior-free base-fee/posted-price rule over a prior-dependent auction on a permissionless L1 with adversarially manipulable demand.

**D7. Kelkar, Zhang, Goldfeder, Juels — "Order-Fairness for Byzantine Consensus" (Aequitas) (CRYPTO 2020)** · *important* · `[NEW]`
<https://eprint.iacr.org/2020/269>
- **Key result:** Formalizes receive-order-fairness, shows the Condorcet obstruction, and builds batch-order-fair Byzantine protocols.
- **Why AINCORE cites it:** A concrete anti-MEV mechanism enforceable at AINCORE's DAG-ordering layer to remove the leader's profit-motivated reordering discretion.

**D8. Babel, Daian, Kelkar, Juels — "Clockwork Finance: Automated Analysis of Economic Security in Smart Contracts" (IEEE S&P 2023)** · *important* · `[NEW]`
<https://arxiv.org/abs/2109.04347>
- **Key result:** Mechanizes MEV as the value an optimal ordering/insertion adversary extracts, generalizing the front-run/back-run/sandwich taxonomy into computable worst-case bounds.
- **Why AINCORE cites it:** Methodology to bound how much value AINCORE's anchor leader could extract from Move DEX/lending — the trigger condition for the Flash Boys 2.0 instability.

**D9. Buterin et al. — "Proposer/Builder Separation-friendly fee market designs" (PBS) (ethresear.ch, 2021)** · *important* · `[NEW]`
<https://ethresear.ch/t/proposer-block-builder-separation-friendly-fee-market-designs/9725>
- **Key result:** Split producer into a builder (constructs the ordered block, bids) and a proposer (blindly commits to the top bid), democratizing MEV and confining ordering power to a competitive builder market.
- **Why AINCORE cites it:** The leading structural remedy for AINCORE's "leader both orders and profits" problem — the VDF-elected anchor would only pick the top bid, decoupling election from MEV extraction.

**D10. Kursawe — "Wendy, the Good Little Fairness Widget…" (AFT 2020)** · *supporting* · `[NEW]`
<https://eprint.iacr.org/2020/885>
- **Key result:** A lightweight bolt-on widget enforcing relative/timed order-fairness via timestamps and threshold agreement.
- **Why AINCORE cites it:** A low-cost modular fairness layer that fits between AINCORE's DAG mempool and OrderingEngine, connecting to its existing BLS/threshold/VDF primitives.

**D11. Heimbach, Kiffer, Ferreira Torres, Wattenhofer — "Ethereum's Proposer-Builder Separation: Promises and Realities" (ACM IMC 2023)** · *supporting* · `[NEW]`
<https://arxiv.org/abs/2305.19037>
- **Key result:** Live PBS shows severe builder/relay centralization and evidence of censorship — PBS shifts rather than eliminates centralization.
- **Why AINCORE cites it:** A cautionary counterweight — if AINCORE considers PBS, this quantifies the imported attack surface and argues for enshrined/committee-based over off-chain-relay PBS.

**D12. Qin, Zhou, Gervais — "Quantifying Blockchain Extractable Value: How dark is the forest?" (IEEE S&P 2022)** · *supporting* · `[NEW]`
<https://arxiv.org/abs/2101.05511>
- **Key result:** Empirically measures realized BEV (sandwich, liquidation, arbitrage) at hundreds of millions of dollars.
- **Why AINCORE cites it:** Grounds AINCORE's MEV threat in real magnitudes and supplies the attack catalog a Move DEX would expose to the anchor leader.

**D13. Eskandari, Moosavi, Clark — "SoK: Transparent Dishonesty: Front-Running Attacks on Blockchain" (FC 2019 Workshops)** · *supporting* · `[NEW]`
<https://arxiv.org/abs/1902.05164>
- **Key result:** Partitions front-running into displacement, insertion, and suppression (censorship).
- **Why AINCORE cites it:** A clean checklist of ordering-based attack classes to test AINCORE's OrderingEngine against, especially suppression that fair-ordering and PBS address differently.

---

## E. Cryptographic Primitives

**E1. Boneh, Lynn, Shacham — "Short Signatures from the Weil Pairing" (BLS) (ASIACRYPT 2001; J. Cryptology 2004)** · *foundational* · `[NEW]`
<https://www.iacr.org/archive/asiacrypt2001/22480516.pdf>
- **Key result:** Short, deterministic, non-interactively aggregatable pairing signatures verified with a single pairing check.
- **Why AINCORE cites it:** Base scheme behind `bls/mod.rs` and `threshold_bls.rs`; aggregation is what makes a >2/3 quorum certificate constant-size.

**E2. Bernstein, Duif, Lange, Schwabe, Yang — "High-speed high-security signatures" (Ed25519) (CHES 2011; JCEN 2012)** · *foundational* · `[NEW]`
<https://ed25519.cr.yp.to/ed25519-20110926.pdf>
- **Key result:** Deterministic EdDSA over edwards25519 — fast, side-channel-resistant, 64-byte signatures at ~128-bit security.
- **Why AINCORE cites it:** Primary transaction and vertex-author signature scheme (mempool step 5; addresses = `hex(SHA256(pubkey)[0..16])`) — the hot path for every TX and DAG vertex.

**E3. Boneh, Bonneau, Bünz, Fisch — "Verifiable Delay Functions" (CRYPTO 2018; ePrint 2018/601)** · *foundational* · `[NEW]`
<https://eprint.iacr.org/2018/601>
- **Key result:** Defines VDFs — T sequential non-parallelizable steps to evaluate, polylog to verify — with sequentiality, soundness, uniqueness.
- **Why AINCORE cites it:** Underpins `VDFEngine`-based anchor-leader election; sequentiality makes leader randomness unbiasable and prevents grinding which round a validator leads.

**E4. Boneh, Drijvers, Neven — "Compact Multi-Signatures for Smaller Blockchains" (BDN) (ASIACRYPT 2018; ePrint 2018/483)** · *foundational* · `[NEW]`
<https://eprint.iacr.org/2018/483>
- **Key result:** BLS aggregation secure against rogue-key attacks without proofs-of-possession, via per-signer exponent randomization.
- **Why AINCORE cites it:** **Security-critical** — naive BLS aggregation is broken by rogue-key attacks; AINCORE's aggregate quorum signatures must adopt BDN-style randomization or PoP.

**E5. Pietrzak — "Simple Verifiable Delay Functions" (ITCS 2019; ePrint 2018/627)** · *important* · `[NEW]`
<https://eprint.iacr.org/2018/627>
- **Key result:** Iterated-squaring VDF in groups of unknown order with O(log T) proof and cheap verification.
- **Why AINCORE cites it:** One of two concrete VDF constructions `VDFEngine` can instantiate — prover-cheap proof generation each leader round.

**E6. Wesolowski — "Efficient Verifiable Delay Functions" (EUROCRYPT 2019; ePrint 2018/623)** · *important* · `[NEW]`
<https://eprint.iacr.org/2018/623>
- **Key result:** VDF with a single-group-element proof and constant-size, very fast verification under the adaptive-root assumption.
- **Why AINCORE cites it:** Preferred VDF — leader-election proofs are gossiped and verified by every validator each round, so O(1) verification minimizes consensus overhead vs. Pietrzak's log-size proofs.

**E7. Micali, Rabin, Vadhan — "Verifiable Random Functions" (FOCS 1999)** · *important* · `[NEW]`
<https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Pseudo%20Randomness/Verifiable_Random_Functions.pdf>
- **Key result:** A keyed PRF whose output carries a non-interactive correctness proof while remaining unpredictable without the secret key.
- **Why AINCORE cites it:** Primitive model for verifiable per-validator randomness in leader/committee selection — complements the VDF delay path.

**E8. Gennaro, Jarecki, Krawczyk, Rabin — "Secure Distributed Key Generation…" (GJKR) (EUROCRYPT 1999; J. Cryptology 2007)** · *important* · `[NEW]`
<https://link.springer.com/article/10.1007/s00145-006-0347-3>
- **Key result:** Pedersen-VSS-based DKG producing a uniformly random shared public key against a rushing adversary, fixing Feldman-DKG bias.
- **Why AINCORE cites it:** Required bootstrap for `threshold/` and MPC — a validator committee holding a shared threshold-BLS key with no trusted dealer; bias-resistance matters if that key seeds randomness/federation control.

**E9. Boldyreva — "Threshold, Multi- and Blind Signatures based on Gap-Diffie-Hellman" (PKC 2003; ePrint 2002/118)** · *important* · `[NEW]`
<https://eprint.iacr.org/2002/118>
- **Key result:** Provably-secure (t,n)-threshold BLS — partial signatures combine via Lagrange interpolation into one standard BLS signature.
- **Why AINCORE cites it:** Direct theory for `threshold_bls.rs` (`PartialSignature`, `aggregate_bls`) — t-of-n validators producing one standard-verifiable finality/bridge signature.

**E10. Ben-Sasson, Bentov, Horesh, Riabzev — "Scalable, transparent, post-quantum secure computational integrity" (STARKs) (ePrint 2018/046)** · *important* · `[NEW]`
<https://eprint.iacr.org/2018/046>
- **Key result:** Transparent (no trusted setup), hash-based, post-quantum-plausible proofs via AIR arithmetization + FRI low-degree testing.
- **Why AINCORE cites it:** Direct basis of `zkp/` (AIR definitions + `STARKProver`); transparency matches AINCORE's ceremony-free design and enables succinct light-client / rollup validity proofs.

**E11. Groth — "On the Size of Pairing-based Non-interactive Arguments" (Groth16) (EUROCRYPT 2016; ePrint 2016/260)** · *important* · `[NEW]`
<https://eprint.iacr.org/2016/260>
- **Key result:** Most succinct pairing zk-SNARK: 3-element proofs, 3-pairing verification, per-circuit trusted setup.
- **Why AINCORE cites it:** Reference construction for the SNARK path (`zkp/snark.rs`, `HashPreimageCircuit`) — constant-size proofs for future shielded-TX and succinct bridge/rollup proofs.

**E12. Grassi, Khovratovich, Rechberger, Roy, Schofnegger — "Poseidon: A New Hash Function for ZK Proof Systems" (USENIX Security 2021; ePrint 2019/458)** · *important* · `[NEW]`
<https://eprint.iacr.org/2019/458>
- **Key result:** Algebraic sponge hash (HADES) minimizing R1CS/AIR constraints — orders of magnitude cheaper in-circuit than SHA-256/Keccak.
- **Why AINCORE cites it:** Exactly the ZK-friendly hash in `poseidon/` used by the `poseidon_merkle_air` circuit — efficient in-circuit Merkle proofs for accumulator/light-client and STARK state commitments.

**E13. Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Seiler, Stehlé — "CRYSTALS-Dilithium" (TCHES 2018; ePrint 2017/633; NIST FIPS 204)** · *important* · `[NEW]`
<https://eprint.iacr.org/2017/633>
- **Key result:** Fiat-Shamir-with-aborts lattice signature over module-LWE/SIS; NIST's primary PQC signature standard.
- **Why AINCORE cites it:** The PQC signature target in AINCORE's roadmap — consistent with the ~9254-byte PQC signature path passed to the executor.

**E14. Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé — "CRYSTALS-Kyber" (IEEE EuroS&P 2018; ePrint 2017/634; NIST FIPS 203)** · *important* · `[NEW]`
<https://eprint.iacr.org/2017/634>
- **Key result:** IND-CCA2 module-lattice KEM via FO transform; NIST's PQC KEM standard.
- **Why AINCORE cites it:** The PQC key-exchange half of the quantum-resistance plan — post-quantum P2P session keys and keystore wrapping, complementing Dilithium.

**E15. Barreto, Lynn, Scott — "Constructing Elliptic Curves with Prescribed Embedding Degrees" (SCN 2002; ePrint 2002/088)** · *supporting* · `[NEW]`
<https://eprint.iacr.org/2002/088>
- **Key result:** The BLS method for pairing-friendly curves — the family yielding BLS12-381.
- **Why AINCORE cites it:** Defines the concrete curve under every pairing op (BLS signatures, aggregation, threshold BLS) and the security level the `bls`/`threshold` modules depend on.

**E16. Ben-Sasson, Bentov, Horesh, Riabzev — "Fast Reed-Solomon IOP of Proximity" (FRI) (ICALP 2018; ECCC TR17-134)** · *supporting* · `[NEW]`
<https://eccc.weizmann.ac.il/report/2017/134/>
- **Key result:** Hash-based low-degree proximity test with O(log n) verifier work — the engine inside every STARK.
- **Why AINCORE cites it:** The core sub-protocol `STARKProver` must implement; its soundness/round parameters are essential to correctly parameterizing AINCORE's STARK security.

---

## F. Fair-Launch, Distribution & Governance

**F1. Srivastava, Damle, Gujar — "Centralization in Proof-of-Stake Blockchains: A Game-Theoretic Analysis of Bootstrapping Protocols" (GAIW-24 @ AAMAS, 2024)** · *foundational* · `[ALREADY CITED]`
<https://arxiv.org/abs/2404.09627>
- **Key result:** An ideal PoS bootstrapping protocol needs IR + IC + Decentralization; airdrop and proof-of-burn provably fail Decentralization.
- **Why AINCORE cites it:** AINCORE's PoS genesis stake distribution *is* a bootstrapping protocol — the IR/IC/Decentralization checklist for evaluating genesis allocation and the warning that a naive airdrop genesis is non-ideal.

**F2. Jensen, von Wachter, Ross — "How Decentralized is the Governance of Blockchain-based Finance…" (2021)** · *foundational* · `[ALREADY CITED]`
<https://arxiv.org/abs/2102.10096>
- **Key result:** All four studied DeFi governance-token distributions have Gini > 0.9 — extreme concentration.
- **Why AINCORE cites it:** Supplies the measurement methodology AINCORE should run on the AIN distribution before enabling on-chain governance execution, and quantifies the plutocracy risk its stake-weighted `governance/` module faces.

**F3. Buterin, Hitzig, Weyl — "A Flexible Design for Funding Public Goods" (Quadratic Funding) (Management Science 2019)** · *foundational* · `[NEW]`
<https://pubsonline.informs.org/doi/10.1287/mnsc.2019.3337>
- **Key result:** Quadratic Funding — funding ∝ square of the sum of contribution square-roots — yields first-best public-goods provision with sublinear (anti-whale) weighting.
- **Why AINCORE cites it:** The primary mechanism to weaken whale dominance in AINCORE's 1-token-1-vote Proposal/Vote system and to allocate treasury toward ecosystem public goods.

**F4. Srinivasan, Lee — "Quantifying Decentralization" (the Nakamoto coefficient) (2017)** · *foundational* · `[ALREADY CITED]`
<https://messari.io/report/analysis-quantifying-decentralization-balaji-srinivasan-and-leland-lee>
- **Key result:** Nakamoto coefficient = minimum number of entities that must collude to control ≥51% of any essential subsystem.
- **Why AINCORE cites it:** A single auditable decentralization number over the validator set (stake to reach `(n*2/3)+1`) and AIN ownership — directly usable in the `monitor/` Prometheus exporter.

**F5. Kiayias, Lazos — "SoK: Blockchain Governance" (ACM AFT 2022)** · *foundational* · `[NEW]`
<https://arxiv.org/abs/2201.07188>
- **Key result:** A taxonomy and evaluation grid (participation, decentralization, accountability, sustainability) surveying Decred, Tezos, MakerDAO, Dash, Zcash.
- **Why AINCORE cites it:** The best single scholarly anchor to position AINCORE's Proposal/Vote/TimeLock governance against established treasury-and-voting designs.

**F6. "How Does Stake Distribution Influence Consensus? Analyzing Blockchain Decentralization" (arXiv:2312.13938, 2023)** · *important* · `[NEW]`  *(cite by title/ID — no clearly attributable authors)*
<https://arxiv.org/abs/2312.13938>
- **Key result:** Proposes a Square-Root Stake Weight (SRSW) model improving Gini ~37% and Nakamoto liveness/safety coefficients ~101%/80% on average.
- **Why AINCORE cites it:** SRSW is a drop-in — a sqrt transform on validator stake weights raises Nakamoto coefficients without changing the `(2/3)+1` safety threshold.

**F7. Fritsch, Müller, Wattenhofer — "Analyzing Voting Power in Decentralized Governance: Who controls DAOs?" (2022)** · *important* · `[NEW]`
<https://arxiv.org/abs/2204.01176>
- **Key result:** Compound/Uniswap/ENS voting power is concentrated in a few delegates with low participation; quantifies who can unilaterally pass/block.
- **Why AINCORE cites it:** Delegate-concentration and quorum-participation metrics AINCORE's governance module should adopt as monitoring invariants and to set quorum thresholds.

**F8. Barbereau, Smethurst, Papageorgiou, Sedlmeir, Fridgen — "DeFi's timocratic governance…" (Technology in Society 2023)** · *important* · `[NEW]`
<https://www.sciencedirect.com/science/article/pii/S0160791X23000568>
- **Key result:** Tokenised voting rights are both highly concentrated AND barely exercised, making "minority rule" the probable equilibrium.
- **Why AINCORE cites it:** Sharpens the point that stake-weighted governance needs structural counter-measures (delegation defaults, quadratic weighting, participation incentives), not just wide token trading.

**F9. Messias, Yaish, et al. — "Airdrops: Giving Money Away Is Harder Than It Seems" (2023)** · *important* · `[NEW]`
<https://arxiv.org/abs/2312.02752>
- **Key result:** Up to 66% of airdropped tokens are sold almost immediately; farmers game eligibility; engagement decays fast.
- **Why AINCORE cites it:** Quantifies the dump/farming risk if AINCORE considers an AIN airdrop — motivates Sybil-resistant eligibility and vesting/lock conditions over a pure free drop.

**F10. Optimism PBC & Buterin — "Retroactive Public Goods Funding" (RetroPGF) (2021)** · *important* · `[NEW]`
<https://medium.com/ethereum-optimism/retroactive-public-goods-funding-33c9b7d00f0c>
- **Key result:** Reward public goods after value is proven ("easier to agree on what was useful than what will be useful"); operationalized as Retro Funding rounds.
- **Why AINCORE cites it:** A treasury model where fee sweeps or an emission carve-out retroactively reward ecosystem contributors (indexer, explorer, bridge tooling), reducing capture vs. forward grants.

**F11. Allen, Berg, Lane — "Why airdrop cryptocurrency tokens?" (Journal of Business Research 2023)** · *supporting* · `[NEW]`
<https://www.sciencedirect.com/science/article/pii/S014829632300303X>
- **Key result:** Institutional-economics analysis identifying marketing vs. decentralisation-of-control as the two primary airdrop rationales.
- **Why AINCORE cites it:** Separates the marketing motive from the genuine decentralization motive — the latter being what Srivastava shows is hardest to achieve via airdrop.

**F12. Zcash Community — "ZIP 1014: Establishing a Dev Fund…" (with ZIP 214, Canopy 2020)** · *supporting* · `[ALREADY CITED]`
<https://zips.z.cash/zip-1014>
- **Key result:** A 4-year dev fund taking 20% of block subsidies (35/25/40 split), with sunset-by-default back to miners.
- **Why AINCORE cites it:** A directly relevant precedent for carving a percentage of AINCORE's block subsidy into a treasury with explicit sunset and split rules — plus the governance fights it triggered.

**F13. Decred — Politeia proposal system & Constitution (2018–present)** · *supporting* · `[ALREADY CITED]`
<https://docs.decred.org/governance/overview/>
- **Key result:** Ticket-based treasury governance requiring ≥60% approval AND ≥20% turnout, funded against demonstrated progress.
- **Why AINCORE cites it:** The two-threshold rule (approval % + minimum turnout) is a battle-tested defense against both plutocracy and voter apathy that AINCORE can adopt in its governance quorum logic.

**F14. Chen / Commonwealth Labs — "What's in a Lockdrop?" (Edgeware lockdrop, 2019)** · *supporting* · `[ALREADY CITED]`
<https://medium.com/commonwealth-labs/whats-in-a-lockdrop-194218a180ca>
- **Key result:** Participants time-lock ETH (longer lock → more tokens); Edgeware distributed ~90% of supply this way for a commitment-weighted holder base.
- **Why AINCORE cites it:** A fairer-launch alternative to a plain airdrop — a lockdrop weights initial AIN by time-locked commitment, Sybil-dampening and aligning early holders with long-term governance.

---

## Priority Additions — the ~10 highest-value NEW papers to add

The emission paper's existing 22 references are almost entirely token/monetary and fair-launch economics (Budish, Carlsten, Auer, Fanti, Chitra, Roughgarden, Zcash/Decred/Edgeware, etc.). It has **no consensus theory, no cryptographic-primitive, and no MEV/mechanism-design citations** — yet AINCORE's core novelty *is* its DAG-BFT consensus, BLS/VDF crypto stack, and leader-fee-sweep design. These ten close exactly that gap:

1. **A4 · Narwhal & Tusk** <https://arxiv.org/abs/2105.11827> — the direct architectural blueprint for AINCORE's certified-vertex mempool DAG; the single most load-bearing missing citation.
2. **A5 · Bullshark** <https://arxiv.org/abs/2201.05677> — the source of AINCORE's "Bullshark-lite" anchor-leader ordering rule; the algorithm `try_commit` implements.
3. **A3 · DAG-Rider** <https://arxiv.org/abs/2102.08325> — the "commit by interpreting the DAG" foundation the whole OrderingEngine rests on.
4. **A6 · HotStuff** <https://arxiv.org/abs/1803.05069> — canonical source for aggregating 2f+1 votes into one linear BLS quorum certificate.
5. **A2 · PBFT (Castro-Liskov)** — with A1 Byzantine Generals — <https://pmg.csail.mit.edu/papers/osdi99.pdf> — the 3f+1 / quorum-certificate origin of AINCORE's `(n*2/3)+1` finality and equivocation detection.
6. **A8 · Casper FFG** <https://arxiv.org/abs/1710.09437> — accountable safety: the theoretical proof behind AINCORE's ≥1/3-attributable slashing on double-sign.
7. **B3 · Ebb-and-Flow (Neu-Tas-Tse)** <https://arxiv.org/abs/2009.04987> — the availability-finality design pattern AINCORE embodies and the justification for its split-brain rule.
8. **E4 · BDN Compact Multi-Signatures** <https://eprint.iacr.org/2018/483> — security-critical: naive BLS aggregation for quorum certificates is rogue-key-broken; this is the mandated fix.
9. **D4 · Chung-Shi, Foundations of TFM** <https://arxiv.org/abs/2111.03151> — the impossibility theorem that makes AINCORE's fee-sweep-to-leader a principled trade-off rather than an oversight.
10. **D5 · Daian et al., Flash Boys 2.0** <https://arxiv.org/abs/1904.05234> — coins MEV and proves the fee-based-forking instability that AINCORE's leader-orders-and-keeps-fees design directly triggers.

**Breadth this gives the AINCORE research foundation.** Before, the whitepaper's citations could defend the *token economics* (why 150M, why halving, why slashing sizing) but silently assumed the consensus, crypto, and fee-market design were sound. Adding these ten transforms the bibliography from a one-dimensional monetary-economics dossier into a full-stack research foundation that traces every core claim to primary literature: consensus safety back to Byzantine Generals → PBFT → HotStuff → the DAG-BFT lineage (DAG-Rider/Narwhal/Bullshark); accountable-safety slashing to Casper FFG; the availability-vs-finality posture to Ebb-and-Flow; the BLS quorum certificate to its rogue-key-hardened form (BDN); and the fee-sweep/MEV exposure to the TFM impossibility (Chung-Shi) and MEV-instability (Flash Boys 2.0) results. That is the difference between "our token model is grounded" and "every load-bearing design decision in the protocol is grounded" — and it surfaces two concrete hardening actions (adopt BDN-style aggregation; reconsider a burned base fee or PBS) that the current reference set cannot even frame.

---

## G. Monetary Economics & Calibration

> Classical monetary economics applied to emission calibration: the float — not the cap — is the money stock; emission is a second-best security tax; regime credibility, not the rate level, is what anchors expectations. Complements section C (crypto-native token economics), which already holds Budish, Saleh, Carlsten, Roşu-Saleh, Fanti, John-Rivera-Saleh, Chitra, and Schilling-Uhlig.

**G1. Cagan — "The Monetary Dynamics of Hyperinflation" (in Friedman ed., *Studies in the Quantity Theory of Money*, U. Chicago Press 1956, pp. 25–117)** · *foundational* · `[NEW]`
<https://www.academia.edu/97478512/The_monetary_dynamics_of_hyperinflation>
- **Key result:** Semi-log money demand across seven hyperinflations (semi-elasticity α ≈ 3–6) implies a seigniorage Laffer curve; adaptive expectations feed back into money-demand collapse — the canonical inflation-spiral mechanics.
- **Why AINCORE cites it:** The validator-sell death spiral *is* a Cagan spiral with the ~1M liquid float (not the 150M cap) as the money stock — makes the sold-emission-to-float ratio, not the DRAW rate, the binding variable, and motivates float enlargement + stake absorption.

**G2. Friedman — "The Optimum Quantity of Money" (Aldine, 1969)** · *foundational* · `[NEW]`
<https://miltonfriedman.hoover.org/objects/57539/the-optimum-quantity-of-money-and-other-essays>
- **Key result:** Welfare-optimal monetary policy is ~zero expected inflation (the Friedman rule) — any positive emission is a distortionary tax on money holders.
- **Why AINCORE cites it:** The holder-welfare benchmark forcing the calibration question into its correct form — "minimum rate that clears the external-validator participation constraint" — and ruling out any stimulus/liquidity framing for 8–17%.

**G3. Phelps — "Inflation in the Theory of Public Finance" (Swedish Journal of Economics 75(1), 1973)** · *foundational* · `[NEW]`
<https://www.semanticscholar.org/paper/INFLATION-IN-THE-THEORY-OF-PUBLIC-FINANCE-Phelps/12bee310b095aefe1732a2579c0f897f9c613c16>
- **Key result:** With no lump-sum taxes available, the second-best optimum features *positive* inflation — set where the marginal deadweight loss of seigniorage equals that of other instruments.
- **Why AINCORE cites it:** The precise frame for emission: an L1 with ~zero launch fee revenue has emission as its only security-tax instrument, so a positive rate is second-best optimal — calibrated to marginal security benefit, not minimized to zero.

**G4. Sargent, Wallace — "Some Unpleasant Monetarist Arithmetic" (FRB Minneapolis Quarterly Review 5(3), 1981)** · *foundational* · `[NEW]`
<https://www.minneapolisfed.org/research/quarterly-review/some-unpleasant-monetarist-arithmetic>
- **Key result:** Under a binding fiscal requirement, tighter money now forces higher inflation later — monetary policy cannot be evaluated apart from the intertemporal budget constraint.
- **Why AINCORE cites it:** The security budget is the chain's non-optional fiscal requirement: a too-low rate (2%) that starves external validation accrues a centralization deficit forcing a later credibility-destroying DRAW_NUM hard-fork increase — bounds the candidate band from below.

**G5. Obstfeld, Rogoff — "Speculative Hyperinflations in Maximizing Models: Can We Rule Them Out?" (Journal of Political Economy 91(4), 1983)** · *foundational* · `[NEW]`
<https://www.nber.org/papers/w0855>
- **Key result:** Self-fulfilling speculative hyperinflations cannot be ruled out even with a constant money supply; they are eliminated only by a fractional *real backing* (redemption floor) for the currency.
- **Why AINCORE cites it:** The hard cap alone does not exclude the validator-sell death spiral on a thin float — permanent protocol-owned DEX liquidity (the ~1M seed paired with a hard quote asset) is the backing analogue and equilibrium-selection device.

**G6. Sargent — "The Ends of Four Big Inflations" (in Hall ed., *Inflation: Causes and Effects*, U. Chicago Press for NBER, 1982, pp. 41–98)** · *important* · `[NEW]`
<https://www.nber.org/system/files/chapters/c11452/c11452.pdf>
- **Key result:** The 1920s hyperinflations ended abruptly and cheaply via discrete *credible regime change* (statutory limits on money creation), not gradual tightening — expectations reset overnight.
- **Why AINCORE cites it:** What prevents a float-dilution spiral is regime credibility: pin the emission epoch to wall-clock time (block-time coupling = silent discretionary drift in the effective rate) and make DRAW_NUM consensus-enforced, non-governance-adjustable.

**G7. Lucas — "Two Illustrations of the Quantity Theory of Money" (American Economic Review 70(5), 1980)** · *important* · `[NEW]`
<https://www.bu.edu/econ/files/2011/01/Lucas2illustrations1.pdf>
- **Key result:** At long-run frequencies, money growth passes essentially one-for-one into inflation and nominal interest rates.
- **Why AINCORE cites it:** Whatever DRAW_NUM is chosen passes ~1:1 into AIN depreciation and into the nominal staking yield validators demand — headline APY funded by equal dilution is ~0% real yield; calibrate on real validator flows, not APY competitiveness.

**G8. McCandless, Weber — "Some Monetary Facts" (FRB Minneapolis Quarterly Review 19(3), 1995)** · *important* · `[NEW]`
<https://www.minneapolisfed.org/research/qr/qr1931.pdf>
- **Key result:** Across 110 countries / 30 years: money growth ↔ inflation correlate at ~0.92–0.96 with slope ~1; money growth ↔ real output growth uncorrelated.
- **Why AINCORE cites it:** The cross-sectional evidence that 12–17% emission buys no real adoption — only proportionally faster reserve exhaustion (17%/yr halves the reserve every ~3.7 years), spending the future security budget on the chain's least valuable years.

**G9. Barro — "Inflation and Economic Growth" (NBER WP 5326, 1995)** · *important* · `[NEW]`
<https://www.nber.org/papers/w5326>
- **Key result:** Instrumented panel of ~100 countries: +10pp inflation lowers real growth 0.2–0.3pp/yr and investment 0.4–0.6pp; damage concentrates above ~15–20%/yr.
- **Why AINCORE cites it:** The harm gradient measured against circulating supply — persistent >15% dilution suppresses exactly the ecosystem capital formation (DEX LPs, external stake) AINCORE needs; supports the band whose medium-term circulating inflation settles into single digits (3.5–5%).

**G10. Bruno, Easterly — "Inflation Crises and Long-Run Growth" (Journal of Monetary Economics 41(1), 1998; NBER WP 5209)** · *important* · `[NEW]`
<https://www.nber.org/papers/w5209>
- **Key result:** No robust growth-inflation relationship below ~40%/yr; damage is a discrete crisis regime above it, with surprisingly strong recovery once inflation falls.
- **Why AINCORE cites it:** Reframes the fear: transiently scary year-1 headline dilution is survivable if the schedule visibly declines and staking absorbs the flow — design so the crisis regime (sold flow vs float) is unreachable, rather than minimizing the rate per se.

**G11. Khan, Senhadji — "Threshold Effects in the Relationship Between Inflation and Growth" (IMF Staff Papers 48(1), 2001)** · *important* · `[NEW]`
<https://www.imf.org/external/pubs/ft/staffp/2001/01a/pdf/khan.pdf>
- **Key result:** Threshold regressions on 140 countries: inflation harms growth only above ~1–3%/yr (industrial) / ~11–12%/yr (developing); below-threshold effect is zero-to-positive.
- **Why AINCORE cites it:** The single most usable steady-state number — post-bootstrap circulating-supply inflation should sit under the ~11–12% developing-economy threshold, which 3.5–5% achieves while preserving >70% of reserve; effectively eliminates 12% and 17%.

**G12. Calvo, Végh — "Currency Substitution in Developing Countries: An Introduction" (IMF WP 92/40, 1992)** · *important* · `[NEW]`
<https://www.elibrary.imf.org/view/journals/001/1992/040/001.1992.issue-040-en.xml>
- **Key result:** When residents can hold a substitute currency, inflationary finance erodes its own base — the seigniorage Laffer curve peaks at far lower inflation and stabilization loses its anchor.
- **Why AINCORE cites it:** Token holders' substitution elasticity dwarfs dollarization (exit is a wallet click, no capital controls) — compresses the viable dilution band to low single digits net of staking yield, and motivates the classic defense: pay competitive interest on domestic money, i.e. delegation at launch.

**G13. Uribe — "Hysteresis in a Simple Model of Currency Substitution" (Journal of Monetary Economics 40(1), 1997)** · *supporting* · `[NEW]`
<https://www.columbia.edu/~mu2166/chap2.pdf>
- **Key result:** Network externalities in transacting make currency substitution hysteretic — once users switch, accumulated "dollarization capital" keeps them switched even after inflation falls; multiple steady states.
- **Why AINCORE cites it:** Makes the loss function asymmetric: over-emission that drives users/validators/LPs to a rival chain is irreversible, while under-emission is correctable from an intact reserve — under asymmetric irreversibility, launch one notch below the symmetric optimum and invest in retention (delegation, LP incentives).

---

## H. Market Microstructure, Thin-Float Dynamics & Fee-Transition Economics

> Added by the 2026-07-17 calibration research: (i) the seven top-journal cryptoeconomics papers on fee-market endgames, mining/validation industrial organization, and equilibrium multiplicity that were missing from section C; (ii) the market-microstructure and empirical-tokenomics literature for the thin-float problem — the decision variable is net validator sell flow vs market depth, not the headline emission rate.

### H-i. Fee-transition, industrial organization & equilibrium multiplicity

**H1. Huberman et al. — "Monopoly without a Monopolist: An Economic Analysis of the Bitcoin Payment System" (Review of Economic Studies 88(6), 2021, pp. 3011-3040)** · *top-journal* · `[NEW]`
- **Key result:** In a decentralized payment platform with free entry, no entity can set fees; users pay fees only to buy priority under CONGESTION (closed-form queueing formulas). Without congestion, equilibrium fees are ~zero — fee revenue is generated exclusively by delay, and protocol capacity choices directly set the fee level.
- **Why AINCORE cites it:** The fee-transition endgame paper: a young, fast, uncongested DAG chain (AINCORE's whole pitch is high throughput) earns structurally ~zero fee revenue for YEARS. Therefore emission must carry 100% of the security budget through the entire adoption phase — the decisive argument for a slow drawdown (3.5-5%) that preserves >60% of reserve at year 10, and against 12/17% schedules that implicitly assume fees arrive on schedule. Also warns that AINCORE's throughput scaling permanently suppresses its own fee market.

**H2. Hinzen et al. — "Bitcoin's Limited Adoption Problem" (Journal of Financial Economics 144(2), 2022, pp. 347-369)** · *top-journal* · `[NEW]`
- **Key result:** Limited adoption is an EQUILIBRIUM outcome, not a transitional one: consensus-driven network delay creates negative network effects that cap adoption, and raising throughput fails (it raises fork probability, prolonging consensus). Fee revenue therefore never scales to the level the fee-transition thesis requires.
- **Why AINCORE cites it:** Complements Huberman et al. from the adoption side: even optimistic growth does not deliver a fee-funded security budget, so the geometric reserve must remain the budget indefinitely — again favoring 2-5% tail-preserving rates. Secondary payoff: it is the academic justification for AINCORE's BFT-finality DAG design (which escapes the fork-probability mechanism), a claim the whitepaper can now cite; but the fee-revenue pessimism applies to ANY young chain including AINCORE.

**H3. Prat et al. — "An Equilibrium Model of the Market for Bitcoin Mining" (Journal of Political Economy 129(8), 2021, pp. 2415-2452)** · *top-journal* · `[NEW]`
- **Key result:** Dynamic free-entry model, estimated on data: computing power (security investment) is driven by the fiat VALUE of the reward flow and follows price with a lag because entry is irreversible; reward quantity per unit time, not per block, is the economically relevant variable, and entry responds to price increases rather than to protocol reward-rate changes.
- **Why AINCORE cites it:** Bears on two sub-decisions. (1) Block-time pinning: entry responds to reward VALUE per unit wall-clock time, so coupling emission to block time is an economics bug — a performance retune (faster blocks) silently multiplies the emission rate. Pin e_epoch to wall-clock epochs, with DRAW_NUM recomputed if block time changes. (2) External-validator attraction: raising the rate from 5% to 17% cannot buy validators if expected AIN price falls in proportion — entry follows expected reward value, which the higher rate itself depresses (John-Rivera-Saleh channel).

**H4. Arnosti et al. — "Bitcoin: A Natural Oligopoly" (Management Science 68(7), 2022, pp. 4755-4771 (also ITCS 2019))** · *top-journal* · `[NEW]`
- **Key result:** In equilibrium, mining-market concentration is driven by small ASYMMETRIES in operational cost: a participant with even a modest per-unit cost advantage captures a disproportionately large, oligopolistic share; near-symmetric costs are necessary for a decentralized market structure.
- **Why AINCORE cites it:** Formalizes the centralization half of the AINCORE dilemma: the founder's cost asymmetry (already-running infrastructure, zero coin-acquisition cost, no listing risk) — not the emission rate — is what predicts durable dominance. The remedy the model implies is cost-symmetrization for outsiders: delegation AT LAUNCH (external holders validate with zero hardware/ops cost) and a float large enough that stake acquisition cost is not prohibitive. Choosing 17% emission does not fix an Arnosti-Weinberg asymmetry; delegation does.

**H5. Biais et al. — "The Blockchain Folk Theorem" (Review of Financial Studies 32(5), 2019, pp. 1662-1715)** · *top-journal* · `[NEW]`
- **Key result:** Blockchain consensus is a coordination game with a folk-theorem-style MULTIPLICITY of equilibria: the honest single-chain outcome is an equilibrium, but so are persistent forks and wars of attrition, and reward structures/computing-cost shocks determine which equilibrium players coordinate on.
- **Why AINCORE cites it:** Frames what the emission schedule can and cannot buy: no rate in {2%...17%} guarantees the good equilibrium — coordination devices do (AINCORE's BFT finality + equivocation slashing are exactly such devices, and can now be cited as the folk-theorem remedy). For calibration it reinforces Saleh: large validation rewards increase the payoff of fork-based deviation strategies, so conditional on slashing doing the coordination work, choose the modest rate (3.5-5%) rather than paying a coordination premium that buys nothing.

**H6. Biais et al. — "Equilibrium Bitcoin Pricing" (Journal of Finance 78(2), 2023, pp. 967-1014)** · *top-journal* · `[NEW]`
- **Key result:** General-equilibrium OLG pricing: crypto value equals discounted net transactional benefits, but equilibrium multiplicity means prices load on sunspots — calibration shows the LARGER share of Bitcoin return variance is extrinsic (belief-driven) volatility, not fundamentals.
- **Why AINCORE cites it:** The rigorous version of the 'validator-sell death spiral' fear: with a 0.67%-of-cap float, AIN price will be overwhelmingly sunspot-driven, and a crash-then-sell-then-crash path is a self-fulfilling equilibrium AVAILABLE AT ANY EMISSION RATE — rate fine-tuning between 3.5% and 5% cannot exclude it. What shifts probability mass toward the good equilibrium is larger net transactional benefits (utility) and a float deep enough that validator sales do not move price discontinuously. Concrete implication: revisit float sizing (1M is likely too thin) with at least as much priority as the rate choice.

**H7. Catalini et al. — "Some Simple Economics of the Blockchain" (Communications of the ACM 63(7), 2020 (NBER WP 22952, 2016))** · *NBER/CEPR* · `[NEW]`
- **Key result:** Blockchain lowers the cost of verification and the cost of networking; native-token issuance is the mechanism that funds network bootstrapping without equity dilution — early participants are compensated by expected token appreciation, which requires a credible scarcity/issuance commitment.
- **Why AINCORE cites it:** The academic grounding for the fair-launch design itself: emission-as-earned-compensation (founder and validators paid in issuance against a hard 150M cap) is exactly the Catalini-Gans bootstrapping subsidy, and its power depends on the issuance rule being CREDIBLE and simple — an argument for locking DRAW_NUM at genesis (or behind governance timelock) rather than leaving it retunable, and against rates so high (12-17%) that the appreciation channel compensating early participants is destroyed by expected dilution. Mild support for the middle band over 2% as well: the subsidy must be material enough to pull in early validators.

### H-ii. Microstructure, AMM depth & empirical tokenomics

**H8. Kyle et al. — "Continuous Auctions and Insider Trading" (Econometrica 53(6), 1985, pp. 1315-1335)** · *top-journal* · `[NEW]`
- **Key result:** Defines market depth as the inverse of lambda, the permanent price impact per unit of net order flow; equilibrium price impact is linear in net signed volume, and a single informed monopolist seller optimally spreads trades over time to minimize impact. Depth is set by the capital of liquidity providers relative to the variance of flow.
- **Why AINCORE cites it:** The decision variable is not the annual emission % but net validator sell flow divided by market depth. Year-1 emission of ~3M AIN (2% candidate) to ~25M (17%) against a depth set by a 1M-AIN float means EVERY candidate produces flow that is a multiple of depth — 12%/17% are indefensible on impact grounds, and even 2% is 3x float. Also: the founder as dominant early validator is exactly Kyle's monopolist seller — a published gradual-sale policy (dribbling) is the impact-minimizing strategy, and delegation-at-launch spreads emission across sellers so flow is not one correlated block.

**H9. Amihud et al. — "Illiquidity and Stock Returns: Cross-Section and Time-Series Effects" (Journal of Financial Markets 5(1), 2002, pp. 31-56)** · *top-journal* · `[NEW]`
- **Key result:** Introduces ILLIQ = |daily return| / dollar volume; expected illiquidity raises required returns (prices are discounted), and unexpected illiquidity shocks depress prices contemporaneously — the illiquidity premium is strongest in small, thin stocks.
- **Why AINCORE cites it:** Cuts against the too-slow-emission failure mode: a 1M-AIN float gives AIN an extreme ILLIQ, so external validators/holders rationally demand a large expected-return premium to hold it. Staking yield must clear that illiquidity-adjusted hurdle or no external validator comes (centralization failure). This argues against 2%/yr with a strict 1M float, and shows float enlargement is doubly effective: it lowers ILLIQ (raising price via a smaller discount) while the same emission is spread over more depth.

**H10. Angeris et al. — "An Analysis of Uniswap Markets" (Cryptoeconomic Systems 1(1), 2021 (arXiv:1911.03380, 2019))** · *arXiv-highly-cited* · `[NEW]`
- **Key result:** Proves constant-product market makers track the reference price under no-arbitrage and are stable under mild conditions; gives the closed-form execution arithmetic: selling Delta into an AIN reserve R moves the marginal price by factor (R/(R+Delta))^2 — selling Delta = 0.41R halves the price; the pool's absorption capacity is strictly its reserve size.
- **Why AINCORE cites it:** Supplies the exact float-sizing formula for the DEX seed. If the 1M float sits as ~1M AIN reserve, one month of 5%/yr emission (~600k AIN) sold entirely into the pool drives price down ~60%; at 50% sell-propensity (~300k/month) still ~-40%/month absent external buyers. Pool depth must be sized against expected MONTHLY net sell flow, not annual emission — which pins the joint (rate, float) choice: either rate <= ~3.5-5% with a materially larger seed, or the 1M seed forces the 2% candidate.

**H11. Milionis et al. — "Automated Market Making and Loss-Versus-Rebalancing" (arXiv:2208.06046, 2022)** · *arXiv-highly-cited* · `[NEW]`
- **Key result:** Decomposes LP P&L into fees minus LVR, the cost of standing quotes picked off by arbitrageurs; instantaneous LVR = (sigma^2)/8 x pool value for constant-product pools, so LP losses scale with the SQUARE of volatility. LPs are profitable only when fee income exceeds LVR.
- **Why AINCORE cites it:** Kills the assumption that the 1M-AIN DEX seed is durable depth. A microcap L1 token has extreme sigma, so LVR will exceed fee income and organic LPs will not stay — the pool only persists if the founder/protocol subsidizes it (protocol-owned liquidity) and commits not to withdraw. Any calibration that counts on the seed pool absorbing 5M AIN/yr of validator flow must budget the LVR subsidy as a real ongoing cost of the chosen emission rate.

**H12. Lehar et al. — "Decentralized Exchange: The Uniswap Automated Market Maker" (Journal of Finance 80(1), 2025, pp. 321-374)** · *top-journal* · `[NEW]`
- **Key result:** Using all 95.8M Uniswap interactions: AMM liquidity is endogenous — depth chases fee income and shrinks under adverse-selection losses; there are no long-lived arbitrage deviations; and the AMM dominates a centralized limit-order book precisely for low-volume, high-gas-relative-value (thin) assets.
- **Why AINCORE cites it:** Validates the DEX-seed-only listing choice — for a thin microcap like launch-AIN, an AMM is the correct venue class (an order book would be empty). But its endogenous-depth result is the warning: sustained one-sided validator sell flow generates LP losses that mechanically shrink pool reserves over time, so absorption capacity DECAYS under exactly the high-emission candidates (8-17%) — the death spiral operates through liquidity withdrawal before it operates through price.

**H13. Capponi et al. — "The Adoption of Blockchain-based Decentralized Exchanges" (arXiv:2103.08842, 2021 (Columbia; companion pubs in Management Science))** · *arXiv-highly-cited* · `[NEW]`
- **Key result:** AMM order execution imposes token-value losses on LPs that grow with exchange-rate volatility; LPs rationally withdraw in high-volatility regimes, and higher-curvature pricing functions reduce arbitrage losses but also trader surplus. AMMs are only adopted for pairs with high personal-use value or correlated prices.
- **Why AINCORE cites it:** Names the precise death-spiral mechanism the founder fears: a validator-sell shock raises volatility, volatility triggers LP withdrawal, withdrawal thins the pool, thinner depth amplifies the next sale's impact. Two implementable countermeasures for AINCORE: lock the DEX seed as protocol/founder-owned liquidity that cannot flee (removing the withdrawal leg), and consider a higher-curvature (stable-heavy) pool geometry for the seed to dampen the arbitrage bleed during the bootstrap year.

**H14. Liu et al. — "Risks and Returns of Cryptocurrency" (Review of Financial Studies 34(6), 2021, pp. 2689-2727)** · *top-journal* · `[NEW]`
- **Key result:** Crypto returns are unexplained by equity/currency/commodity factors; they are strongly predicted by crypto momentum (past 1-4 week returns) and investor-attention proxies (Google searches, Twitter counts) — attention shocks predict ~weeks-ahead returns.
- **Why AINCORE cites it:** AIN demand at launch will be attention- and momentum-driven, not fundamentals-driven. This cuts both ways for calibration: an emission so slow the chain has no visible validator economy generates no attention (demand never arrives to meet even small supply); an emission whose sell flow creates a persistent visible downtrend flips crypto momentum negative and self-reinforces. The calibration target is therefore flow small enough relative to depth that the chart does not exhibit a mechanical downtrend in year one — a testable criterion favoring 3.5-5% with enlarged float.

**H15. Liu et al. — "Common Risk Factors in Cryptocurrency" (Journal of Finance 77(2), 2022, pp. 1133-1177)** · *top-journal* · `[NEW]`
- **Key result:** A three-factor model (crypto market, size, momentum) prices the cross-section of coin returns; small-capitalization coins carry a significant size premium — systematically higher expected returns compensating their risk/illiquidity.
- **Why AINCORE cites it:** Quantifies the hurdle rate for external validator capital: launch-AIN is a deep-microcap loading maximally on the size factor, so rational external stakers require expected returns far above blue-chip staking yields. AINCORE's real staking yield (emission yield minus expected float-dilution price impact) must clear this microcap hurdle — a structural argument that the lowest candidate (2%) risks the no-external-validators/centralization failure unless the float discount shrinks first.

**H16. Howell et al. — "Initial Coin Offerings: Financing Growth with Cryptocurrency Token Sales" (Review of Financial Studies 33(9), 2020, pp. 3925-3974)** · *top-journal* · `[NEW]`
- **Key result:** Across 1,520 ICOs, post-launch liquidity and volume are strongly predicted by credible-commitment signals: public source code, transparent token-supply schedules, insider vesting, and disclosure of budgets/use of funds; hype without commitment devices predicts failure.
- **Why AINCORE cites it:** The strongest empirically-supported lever on whether AINCORE's launch attracts liquidity is not the float number but commitment credibility: ship the emission schedule as verifiable on-chain code (hard-coded DRAW_NUM, no discretionary knob), and publish a binding vesting/sale policy for the founder's validator-earned stake. This directly supports pinning the schedule (block-time decoupled, so the annual rate is invariant) and publicly locking founder rewards — those choices buy more absorption capacity than a percentage point of emission costs.

**H17. Hu et al. — "Cryptocurrencies: Stylized Facts on a New Investible Instrument" (Financial Management 48(4), 2019, pp. 1049-1068)** · *top-journal* · `[NEW]`
- **Key result:** Across 222 cryptocurrencies, altcoin returns are strongly positively correlated with Bitcoin returns (a dominant common crypto factor) and essentially uncorrelated with traditional asset classes; new tokens exhibit high idiosyncratic volatility and skewed, attention-sensitive returns.
- **Why AINCORE cites it:** AIN's absorption capacity is regime-dependent: the dollar depth of the 1M-AIN pool co-moves with the broad crypto market via BTC beta, so a calibration that works at launch-day prices can fail in a 60-70% BTC drawdown when the same AIN sell flow hits a pool worth a third as much. The emission rate must be stress-tested against a bear-regime scenario (depth shrunk 3x, sell-propensity up), not steady-state assumptions — a robustness argument for the conservative end (2-5%) of the candidate set.

**H18. Cong et al. — "Token-Based Platform Finance" (Journal of Financial Economics 144(3), 2022, pp. 972-991)** · *top-journal* · `[NEW]`
- **Key result:** Dynamic model of a platform financing growth by issuing tokens to compensate participants: token issuance accelerates adoption when the user base is small, but over-issuance depresses token price and undermines the very incentives it funds; under commitment the optimal issuance rate is front-loaded then declining as the platform matures.
- **Why AINCORE cites it:** The closest theoretical template for AINCORE's geometric reserve drawdown: emission IS the platform's growth financing (paying validators to bootstrap security), and the optimal policy shape is exactly declining absolute issuance — which the remaining x DRAW_NUM/1e9 schedule delivers automatically. It rationalizes picking a rate high enough to buy validator adoption early (the 3.5-5% middle) while rejecting both a flat-forever high rate (12-17% over-issuance regime) and starving the bootstrap (2%).

**H19. Research et al. — "From Locked to Liquidity: What 16,000+ Token Unlocks Teach Us" (Keyrock, 2024)** · *rigorous-industry* · `[NEW]`
- **Key result:** Across 16,000+ unlock events: ~90% are followed by negative price action within a 30-day window (often starting up to 30 days before the event); team unlocks are worst (drawdowns up to ~25%); unlock size matters — larger unlocks produce up to 2.4x sharper drops; cliff unlocks cause shocks while linear/continuous unlocks create steady, better-absorbed pressure.
- **Why AINCORE cites it:** The largest empirical dataset on supply hitting thin floats. Two direct reads for AINCORE: (1) its per-epoch continuous emission is the 'linear unlock' pattern the data favors over cliffs — keep epochs short and emission smooth, never batch rewards into lumpy releases; (2) the size-sensitivity result (2.4x sharper for large unlocks) is direct evidence against 8-17% candidates, whose annual flow relative to float dwarfs even the 'large unlock' cohort in this study. Also flags that founder (team-analog) selling is the most price-toxic category — reinforcing a public founder-sale policy.

**H20. Research et al. — "Low Float & High FDV: How Did We Get Here?" (Binance Research, May 2024)** · *rigorous-industry* · `[NEW]`
- **Key result:** Tokens launched in 2024 averaged only 12.3% MC/FDV (some as low as 6%, none above 20%); ~$155B of locked tokens unlock 2024-2030; the documented pattern is an initial thin-float pump followed by sustained sell pressure as supply growth outruns demand, requiring ~$80B of new demand just to hold prices.
- **Why AINCORE cites it:** Benchmarks how extreme AINCORE's plan is: a 1M float on a 150M cap is 0.67% MC/FDV — roughly 10x lower than the LOWEST of the cohort this report criticizes as dysfunctional. The report's mechanism (thin float distorts price discovery upward, then dilution crushes it) is precisely the founder's 'float-dilution hyperinflation' fear, and its prescription maps to AINCORE's sub-decisions: enlarge the effective float at genesis (bigger DEX seed) and disperse emission widely (delegation at launch, so new supply lands with many heterogeneous holders rather than one dominant validator's sell wall).

**H21. Aramonte et al. — "DeFi Risks and the Decentralisation Illusion" (BIS Quarterly Review, December 2021)** · *rigorous-industry* · `[NEW]`
- **Key result:** DeFi liquidity is highly procyclical and run-prone: liquidity provision concentrates in a few large actors, evaporates in stress episodes, and leverage/collateral spirals amplify shocks; apparent decentralization masks concentrated points of failure.
- **Why AINCORE cites it:** A central-bank-grade caution against treating the DEX seed as a stable monetary anchor: when AIN's ONLY public market is one AMM pool, DeFi run dynamics become the chain's price-discovery dynamics — depth is greatest when least needed and vanishes in stress. For calibration this means the emission rate must be survivable assuming the pool's effective depth in a stress month is a fraction of its nominal size, and it supports maintaining a protocol-owned liquidity backstop as an explicit line item of the launch design rather than relying on third-party LPs.
