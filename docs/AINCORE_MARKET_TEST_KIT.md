# AINCORE Market-Test Kit

> Ready-to-paste materials for the pre-launch synthetic-audience tests.
> Stack: Artificial Societies (framing/virality) → Synthetic Users (objection mining)
> → OASIS (adversarial propagation) → FinRobot (hostile analyst note) → small real
> human panel (final gate). Read only RELATIVE results (A vs B); absolute sentiment
> from LLM personas is noise. Date: 2026-07-21.

---

## 1. Project one-pager (feed this as RAG / context everywhere)

**AINCORE** — a sovereign Layer-1 blockchain, built from scratch in Rust.

- **Consensus:** DAG-based BFT (Narwhal/Bullshark-inspired), stake-weighted BLS quorum
  certificates, ~sub-5s finality, parallel transaction execution.
- **VM:** Move (resource-oriented, formal-verification-friendly) — not EVM.
- **Token:** AIN. **Hard cap 150,000,000 — unbreachable by construction** (mint anchor
  counts cumulative minted; burns can never re-open emission headroom).
- **Emission:** geometric drawdown — each epoch mints a fixed fraction of the
  *remaining* reserve (~3.5%/yr of remaining). Smooth decay, no halving cliffs,
  emission is independent of validator count. Reserve half-life ~19.5 years.
- **Fair launch: 0% pre-mine, 0% dev fund, no VC allocation.** Every AIN in existence
  is earned by running a validator (or delegating), except a ~5M AIN DEX seed that is
  the initial public float, sold openly on the on-chain DEX.
- **Founder commitments (published, on-chain verifiable):** restake ≥80% of validator
  rewards for years 1–2; no sybil-splitting the anti-whale saturation cap; founder
  stake share target <50% of total stake by year 3.
- **Emission rate is bounded by protocol:** the rate parameter can only move within
  [0.5×, 2×] of genesis via governance — hyperinflation is impossible by construction.
- **Staking:** run a validator (server required) or delegate (no hardware, earn yield
  minus commission). Anti-whale saturation cap per validator (Cardano-style).
- **Status:** 3-machine live testnet, lockstep finality, economics live-verified
  (realized emission matches model to 4 decimal places over 5,000+ epochs).
- Bridges (BTC/EVM) and stablecoin on-ramp: post-launch roadmap.

*(Comparable economic designs: Cardano's reserve-drawdown emission, Bitcoin's hard
cap + 0% pre-mine, Cosmos-style delegation. The combination — fair-launch PoS with a
DEX-seeded float — is novel.)*

---

## 2. STEP 1 — Announcement framing test (Artificial Societies, $0–40)

Society to configure: *crypto-native X/Twitter audience — traders, BTC maximalists,
L1 developers, DeFi users, airdrop farmers, skeptics.*

Post all three variants as separate simulations; compare spread + sentiment + which
objections appear in simulated replies. Also run variant A twice (name-only vs
name+tagline) to test the name.

**Variant A — fairness-led:**
> Zero pre-mine. Zero VC. Zero dev fund. AINCORE is a new L1 where every coin is
> earned by validating — 150M hard cap, enforced by code, not promises. The only
> float at launch is a small DEX seed anyone can buy. Fair launches died in 2009.
> We brought one back.

**Variant B — tech-led:**
> AINCORE: a sovereign L1 written from scratch in Rust. DAG consensus with BLS
> quorum finality, Move VM, parallel execution. No fork of anything. 150M hard cap,
> smooth geometric emission, zero pre-mine. Built for people who read the code
> before the docs.

**Variant C — scarcity-led:**
> Bitcoin's monetary policy, modern architecture. AINCORE: 150M hard cap that
> physically cannot be exceeded, emission that only decays, 0% pre-mine, and a
> protocol bound that makes hyperinflation impossible by construction. Scarcity
> you can verify, not trust.

**Read-out:** relative engagement A vs B vs C · sentiment split per variant ·
hand-tally of objection classes in replies (rug fear / "another L1" fatigue /
Move-chain graveyard / thin-float manipulation / founder-dominance).

---

## 3. STEP 2 — Objection-mining interviews (Synthetic Users, ~$50–150)

RAG-feed: the one-pager above (+ whitepaper if the tool accepts it).

**Personas (run 2 interviews each):**
1. DeFi power user burned by 3 failed L1 launches
2. Bitcoin maximalist, self-custody, hostile to VC chains
3. Professional validator operator (runs nodes on 5 chains)
4. Move/Sui/Aptos developer
5. Indonesian retail crypto trader, mid experience
6. Crypto journalist / due-diligence researcher

**Interview script (ask in order, follow up on anything specific):**
1. What is the FIRST thing about this project that makes you suspicious?
2. The team takes 0% at launch and earns only by validating. Does that make you
   trust it more, or less? Why?
3. The only launch float is ~5M AIN (3.4% of cap) sold on the project's own DEX.
   Is that a fairness feature or a manipulation risk?
4. What would you need to SEE before you would stake or delegate real money?
5. What does the name "AINCORE" make you assume this project is?
6. (validator/dev personas) What would make you run a validator in month 1 — and
   what yield would be too low to bother?
7. If this project fails, what will have been the reason?

**Read-out:** recurring objection themes at saturation · exact phrasings (steal for
FAQ/whitepaper) · which rebuttal flips each skeptic in follow-up turns.

---

## 4. STEP 3 — Adversarial propagation (OASIS, free + LLM tokens)

Synthetic crypto-Twitter, 1k–10k agents (mix: 30% traders, 20% skeptics, 15% BTC
maxis, 15% devs, 10% influencers-with-followers, 10% airdrop farmers).

Seed: the WINNING variant from Step 1, posted by the official account.
Then inject hostile posts from high-follower skeptic agents:

- "Another Move chain. The Move-chain graveyard says hi."
- "5M float on their own DEX = insider pump machine. You are exit liquidity."
- "0% dev fund is a marketing trick — the founder IS the biggest validator, he
  mints himself the supply either way."
- "3 validators is not a blockchain, it's a group chat."
- "No VC = no money for security audits. Your funds, their hobby."

**Measure:** which narrative reaches further after N rounds · sentiment half-life ·
which official-rebuttal timing/wording contains each attack.
**Decision gate:** only a narrative that survives this gets real marketing budget.

---

## 5. STEP 4 — Hostile analyst note (FinRobot, free + LLM tokens)

Prompt FinRobot's equity-research pipeline with the one-pager + emission tables and
ask for: *"a skeptical institutional research note on AINCORE's token economics:
valuation risks, supply-side risks, red flags, and what would change your rating."*
Treat every objection it raises as a FAQ item to pre-empt — regardless of whether
the note is 'right'.

---

## 6. Final gate — real humans (~50-person crypto-native panel)

Synthetic results steer wording and pre-empt objections; they cannot predict real
buy/stake behavior. Before spending marketing money: run the winning narrative +
FAQ past ~50 real crypto-native people (communities, X poll + DM depth interviews).
Only real skin-in-the-game intent counts as demand signal.

---

## Scorecard template

| Test | Metric | A | B | C |
|---|---|---|---|---|
| Societies spread | relative engagement | | | |
| Societies sentiment | pos/neg split | | | |
| Top objection | class + frequency | | | |
| Interviews | objections at saturation | | | |
| OASIS | narrative vs attack reach | | | |
| FinRobot | red-flag count (fixable vs structural) | | | |
