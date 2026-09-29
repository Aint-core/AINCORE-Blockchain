# G1 Consensus Contract: Math and Rules Review

**Scope.** This is a read-only review of `docs/G1_CONSENSUS_CONTRACT.md` against the primary papers and the code in the `g3-activation` worktree at HEAD `2c7c4e4`. I read these files:

- `consensus/consensus/src/vcert.rs`
- `consensus/consensus/src/qc.rs`
- `consensus/consensus/src/ordering.rs`
- `dag.rs`, `genesis.rs` and `qc_producer.rs`, where the review needed them
- `CLAUDE.md`

Nothing was built, run or modified. The one exception is a pure-Python enumeration of quorum sets, kept in the scratchpad at `research/quorum_enum.py`; its output is reproduced in section (b).

**Papers read for this review (primary sources, full text):**

| Ref | Source | Sections used |
|---|---|---|
| [NW] | Danezis, Kokoris-Kogias, Sonnino, Spiegelman, *Narwhal and Tusk*, arXiv 2105.11827v4, https://arxiv.org/abs/2105.11827 | §3.1 (the four validity conditions), §3.3 (GC), §4.1 (pull), §5.1 (Tusk f+1 commit), App. A Lemma A.2 (Block-Availability), Lemma A.5 (Containment) |
| [BS] | Spiegelman, Giridharan, Sonnino, Kokoris-Kogias, *Bullshark: The Partially Synchronous Version*, arXiv 2209.05633v1, https://arxiv.org/abs/2209.05633 | §2.1 (DAG properties), §2.2 (commit rule, path ordering), Alg. 1–2, §2.3 ("Advancing rounds", timeouts, responsiveness) |
| [NW-code] | Narwhal reference implementation: https://github.com/MystenLabs/narwhal/blob/main/consensus/src/bullshark.rs and https://github.com/MystenLabs/narwhal/blob/main/config/src/lib.rs | leader support uses `validity_threshold()`; leaders on even rounds; `quorum_threshold = 2T/3+1`, `validity_threshold = (T+2)/3` |
| [SUI-code] | Sui consensus committee: https://github.com/MystenLabs/sui/blob/main/consensus/config/src/committee.rs | `f = (T−1)/3`, `quorum = T − f`, `validity = f + 1` |
| [LUT] | Blackshear et al., *Sui Lutris* (CCS '24), arXiv 2310.18042, https://arxiv.org/abs/2310.18042 | §4.2 Committee Reconfiguration: registration cutoff at checkpoint S, a "Ready" quorum of the new committee, End-of-Epoch by 2f+1, handover |
| [LBFT] | LibraBFT Team, *State Machine Replication in the Libra Blockchain* (2020-05-26), https://developers.diem.com/papers/diem-consensus-state-machine-replication-in-the-diem-blockchain/2020-05-26.pdf | "Epoch changes": no payload after the reconfiguration command, and an epoch-genesis block |
| [APT-code] | Aptos (Diem lineage) `EpochChangeProof`: https://github.com/aptos-labs/aptos-core/blob/main/types/src/epoch_change.rs | each epoch-ending LedgerInfo is verified by the previous verifier and carries the full `next_epoch_state` |

I did not re-read Mysticeti (arXiv 2310.14821) or DAG-Rider. The contract uses Mysticeti only for the vote-from-own-refs idea and as background for the refuted route, so no verdict below depends on it.

**A discrepancy in the brief.** The task statement says `first_round(E+1) = r*+1`. The contract says `r*+2`:

- Definitions, line 194;
- EP-3, line 634;
- S9 (line 862) lists "first_round = r*+1" as a *mutation* that must go red.

Both values are analysed in §4 of part (b).

---

## (a) Verdict table

Legend: **H** = holds; **HC** = holds with conditions (listed); **W** = wrong as stated; **DEV-SAFE** = a deviation from the paper that is safe but undocumented or mis-described.

| # | Contract claim | Verdict | Paper | Code (file:line at 2c7c4e4) |
|---|---|---|---|---|
| 1 | Q_E(S) ⇔ `3·stake(S) > 2·T`, implemented exactly with integer arithmetic, with no rounding hole (Defs, l.186-188) | **H**. u128, ≤256 u64 addends (max 2^72), so `saturating_mul` never saturates. Proven equal to Narwhal's `S ≥ ⌊2T/3⌋+1` and to Sui's `S ≥ T − ⌊(T−1)/3⌋` for every T (see b.1). | [NW-code] config `quorum_threshold`; [SUI-code] | `qc.rs:194-196` |
| 2 | Two quorums intersect in more than T/3, which exceeds β, so the intersection contains an honest member | **H**. The integer bound is `3·s(Q1∩Q2) ≥ T+2`, so `s(∩) − β ≥ 1` unit (b.1). The minimum intersection at the 4 profiles is 2000/4000, 4000/10000, 4400/10000 and 3000/5000, each greater than the largest tolerable β. | [NW] Lemma A.5 proof; [BS] §2.2 quorum intersection | `qc.rs:190-193` (comment), `:194-196` |
| 3 | All stake-quorum checks share one predicate | **H**. Certificate collection (`vcert.rs:599`), certificate verify (`qc.rs:420` via `vcert.rs:252`), the parent gate (`qc.rs:304`) and direct commit (`ordering.rs:700`) all use it. The legacy path `consensus/src/lib.rs:388` uses `(T*2)/3+1` in u64. That is equivalent, and it is not on the DagConsensus path. | — | as listed |
| 4 | CLAUDE.md "BFT Quorum: `(n * 2/3) + 1`" | **W for unequal stake.** It is a *count* formula. At 4000/3000/2000/1000 it accepts {3000,2000,1000} (60% of stake) and rejects {4000,3000} (70%). Paired with a stake fault bound it breaks safety (b.2). The executor comment at `core/executor/src/lib.rs:2152` repeats it, although that code uses stake (`:2228-2234`). | — | `CLAUDE.md` "Consensus Mechanics"; `executor/src/lib.rs:2152` |
| 5 | LA-2 "at n=4 … 3 nodes, zero slack" | **HC**. True only for equal stake (and for 3300/2300/2200/2200). At 4000/3000/2000/1000 a 2-node set is a quorum and a 3-node set is not. At that profile and at 2000/1000/1000/1000, one member is in *every* quorum, so its crash alone halts the chain (b.2). | — | — |
| 6 | Lemma U: one certified digest per slot (l.711-714) | **HC**. The argument is Narwhal Lemma A.5's argument lifted to stake. It needs assumptions U1–U10 (b.3). The contract names only SA-1 and AT-2. Committee agreement (U2) and weight units (U1) must be stated. | [NW] Lemma A.5 ("Containment"; the uniqueness claim is inside its proof) | `vcert.rs:213-262`, `:285-294`, `:370-427`, `:455-473`; `qc.rs:377-454` |
| 7 | Lemma A: an honest durable holder exists for every certified body | **HC**. It holds as in [NW] Lemma A.2. Duplicate BLS keys are allowed by join (the contract's known limit), so a set bit may name a member that stores nothing. The fetch target list must therefore tolerate non-holding signers. RE-2 rotation does. | [NW] Lemma A.2 | `vcert.rs:207-212` |
| 8 | DE-1: at most one candidate per anchor round | **H**, given Lemma U and OR-2 | [BS] §2.1 Non-equivocation | today `ordering.rs:659-671` (`find_map`) |
| 9 | DE-2 vote = the voter's own signed edge to λ(r) | **H**. It is exactly Bullshark's edge vote ("a vertex in round r votes for the anchor in round r−1 if there is an edge"). | [BS] §2.2 | today `ordering.rs:689-694` |
| 10 | DE-2 threshold Q_E (>2/3) is Bullshark's rule (l.775 "exactly Bullshark's edge vote"; `ordering.rs:526-527` doc) | **DEV-SAFE / W as described.** Bullshark commits an anchor with **f+1** votes. The Narwhal reference code uses `validity_threshold()` (stake form `3S ≥ T`). AINCORE uses 2f+1. This is stricter, so it is safe (b.4), but it costs liveness, and the contract never states the deviation. | [BS] §2.2, Alg. 2 l.13; [NW-code] `bullshark.rs`; [NW] §5.1 (Tusk also f+1) | `ordering.rs:675-701` |
| 11 | DE-3: commit the smallest directly decidable anchor ≥ cursor | **H**. It gives the same anchor sequence as Bullshark's trigger-plus-recursion (Lemma P plus the path rule). | [BS] Alg. 2 `TryCommitting` / `orderAnchors` | `ordering.rs:585-599` |
| 12 | DE-4 path walk-back; 0 candidates in H means a provable Skip | **H**. This is Bullshark's `orderAnchors` with `path(anchor, prevAnchor)` over strong edges only. Taking CandH from the walk is equivalent to `getAnchor` on the local DAG under Validity (OR-1 down-closure). | [BS] Alg. 1 `path`, Alg. 2 l.15-26 | `ordering.rs:605-627`, `:708-739` |
| 13 | Lemma P: a direct commit propagates to every later anchor (l.720-726) | **H, with slack.** It only needs `s(voters) + s(parents) > T`. With Q_E voters and Q_E parents the intersection exceeds T/3; with validity voters (3S ≥ T) it is still non-empty. | [BS] §2.2 (the quorum-intersection paragraph); [NW] §5.1 Lemma 1 | — |
| 14 | GC-1/GC-2: an agreed floor g, with "settled" judged by declared round ≤ g | **H**. This is Narwhal §3.3: the GC round is agreed through consensus. Declared rounds are authenticated (S6 requires every declared parent round = r−1, `qc.rs:265-270`). | [NW] §3.3 | `qc.rs:257-271` |
| 15 | Theorem 1: anchor agreement within an epoch | **HC** (U1–U10; OR-1 down-closure; g and `committed_set` functions of the prefix; one anchor per call). One structural argument checked here: a committed vertex can never shield a path, because round(c) ≤ previous anchor < j. | [BS] §2.2 corollary; [NW] Lemma A.6 | `ordering.rs:708-739`, `:1066-1111` |
| 16 | PR-3 leader wait answers "T_LEADER never specified" | **HC**. It matches Bullshark's even-round (anchor) wait. Bullshark's *odd-round* wait (f+1 votes, or 2f+1 non-votes, or a timeout) is omitted. That is acceptable only because DE-2 counts over all of O_E[r+1], not over one r+2 vertex's edges; the contract must say so. Also note that the contract's timeouts are in [BS] §2.3, not in Algorithm 2 as cited (l.913). | [BS] §2.3 "Advancing rounds" | — |
| 17 | EP: frozen C_E; activation needs QC(H_E) binding `next_validator_set_hash` (EP-4) | **HC**. The structure matches Diem's EpochChangeProof and LibraBFT's "stop the world and restart" plus the epoch-genesis block. Three items are missing: (i) C_E must stay live until QC(H_E) forms; (ii) C_{E+1} must be synced at activation, because there is no registration cutoff (Sui Lutris closes registration at checkpoint S and requires a "Ready" quorum); (iii) the QC binds only a hash, while Diem carries the full next verifier (b.5). | [APT-code]; [LBFT] "Epoch changes"; [LUT] §4.2 | `qc_producer.rs:104-123` (C_0 load) |
| 18 | `first_round(E+1) = r*+2`; `r*+1` "overlap red" (S9) | **HC for both values; the S9 rationale is W.** Round numbers overlap across epochs under *either* choice, because epoch-E vertices exist up to cursor+LEAD ≈ r*+200. Safety comes from E-keyed state. What the code actually needs is that every E+1 anchor round is greater than r*, because `anchor_already_on_chain` is round-only. Both choices satisfy that. "Rounds are counted per epoch" (l.193) is misleading (b.5). | [LUT], [LBFT]: both restart rounds per epoch | `dag.rs:581-583`; `consensus:cseq:{anchor_round}` (no E) |
| 19 | Cross-epoch replay protection | **H**. The epoch is in AttestBody (`vcert.rs:41`), in the guard key (`:285-294`), in the verifier check (`:236-241`), in `hash_v4` and in the FinalityVote. **Condition for the test:** when C_{E+1} = C_E (carry-over), `committee_hash` is identical, so the `epoch` field alone separates the epochs. The S9 "drop epoch" mutation is vacuous unless it is run with a carried-over committee. | — | `vcert.rs:38-47`, `:236-241` |
| 20 | Liveness sketch after GST, under LA-1..LA-9 (l.745-756) | **W**. The LEAD hard cap (PR-1, E5, AT-1) can deadlock permanently from a state reachable before GST (b.6). Apart from LEAD it holds with conditions. | [BS] §2.3 (liveness via timeouts, responsiveness) | — |
| 21 | "LEAD halt probability ≤ 3^−100 per window" (l.753) | **W (model)**. The bound covers only silent Byzantine leaders chosen by the draw. Before GST, an adversary that schedules the network can force 100 consecutive unsupported anchors with certainty. With n=4 and one node down, a single slow honest node can do the same without any adversary. | — | — |
| 22 | At most 1.5 expected anchor rounds between honest-leader commits | **H.** The count of rounds until an online honest leader is geometric with p = online-honest share > 2/3. There is no deterministic bound; [BS] assumes a predefined leader mapping. | [BS] §2.2 "predefined leader" | `ordering.rs:1018-1064` |
| 23 | About 36 messages per round at n=4 | **H logically**: 3n(n−1), the Narwhal pattern. Physically it is at least 60 frames (≥ 2× on vertex and certificate), because both are sent by gossip *and* TCP fan-out, with gossipsub forwarding on top (b.7). | [NW] §3.1 | `dag.rs:2027-2045`; `p2p.rs:112-119` |
| 24 | About 11 BLS operations per node per round | **H for the certification layer**: 4 signs + 7 verifies. It is 12 if the collector re-verifies the node's own attestation (`add` verifies every attestation, `vcert.rs:558-563`). Finality QCs add about 2.5 per round. Retry-driven guard re-verification is unbounded (b.7). | — | `vcert.rs:390-396`, `:558-563`, `:619-625` |
| 25 | IM-5: at most one QC per height | **H**. It is the same argument as Lemma U, over the height guard. | — | `qc_producer.rs` height guard |

---

## (b) Counterexamples and computations

### b.1 Exactness of the quorum predicate

Let T be total stake, S signed stake and β Byzantine stake, all non-negative integers (whole-AIN weights). Stake is floored from quanta, so SA-1 is a statement about *weights*: `genesis.rs:190-199`.

1. **Three formulas are one predicate.** `3S > 2T` (AINCORE) ⇔ `S ≥ ⌊2T/3⌋+1` (Narwhal) ⇔ `S ≥ T − ⌊(T−1)/3⌋` (Sui).
   - Proof by cases on T mod 3:
     - T = 3k gives 2k+1 in all three;
     - T = 3k+1 gives 2k+1;
     - T = 3k+2 gives 2k+2.
   - The script also checked every T ≤ 30000 at the boundary S values.
2. **Validity threshold.** Narwhal's `(T+2)/3` ⇔ Sui's `f+1` ⇔ **`3S ≥ T`**.
3. **Intersection bound.**
   - If `3s1 ≥ 2T+1` and `3s2 ≥ 2T+1`, then `3·s(Q1∩Q2) ≥ 3(s1+s2) − 3T ≥ T+2`.
   - With SA-1 (`3β ≤ T−1`): `3(s∩ − β) ≥ 3`, so s∩ ≥ β + 1.
   - So at least one weight unit of every intersection is non-Byzantine. No rounding hole.
4. **Strictness is needed on only one side.**
   - If the quorum were `3S ≥ 2T` (non-strict) while SA-1 stays strict (`3β < T`), then `3·s∩ ≥ T > 3β` and Lemma U still holds.
   - Consequence for testing: a `>`→`>=` mutation of `stake_quorum_met` is **not** a useful safety mutation, because it will not go red. Mutate to the count formula, or trust claimed stake, instead (d, INV-1).
5. **Overflow.** Stakes are u64 whole AIN, and total supply is 1.5·10^8, so T < 2^28. `saturating_mul` in u128 is therefore never exercised. In the unreachable case where both sides saturate it fails closed.
6. **Legacy formula.** `consensus/src/lib.rs:388` computes `(total_stake*2)/3+1` in u64. It is equivalent, overflows only when T > 2^63, and is unreachable.
7. **One committee record per epoch.** `sys:validators` is written as `stake.max(1)` (`genesis.rs:1099`), while `ValidatorInfo.stake` is the raw floor. The two agree only because the genesis minimum is 1000 AIN and EP-2 drops zero-stake entries. **Condition:** every per-epoch quorum and leader computation must derive (addr, stake) from the single C_E record, never from `sys:validators`.

### b.2 The four n=4 stake profiles (exhaustive enumeration, `research/quorum_enum.py`)

| Profile (T) | Quorum needs | Minimal stake quorums | Largest tolerable Byzantine sets (3β<T) | Min \|Q1∩Q2\| | Member in every quorum (crash halts) | Count-quorum ≠ stake-quorum |
|---|---|---|---|---|---|---|
| 4×1000 (4000) | ≥2667 | any 3 (3000) | any single node (1000) | 2000 | none | none |
| 4000/3000/2000/1000 (10000) | ≥6667 | {4000,3000}=7000; {4000,2000,1000}=7000 | {3000}; **{2000,1000}=3000** (two nodes!) | 4000 | **4000** (40% ≥ T/3) | count accepts {3000,2000,1000}=6000 ✗; count rejects {4000,3000}=7000 ✓ |
| 3300/2300/2200/2200 (10000) | ≥6667 | any 3 (min {2300,2200,2200}=6700) | any single node (max 3300 < 3333.3) | 4400 | none | none |
| 2000/1000/1000/1000 (5000) | ≥3334 | {2000, any two 1000s}=4000 | any single 1000 | 3000 | **2000** (40%) | count accepts {1000,1000,1000}=3000 ✗ |

**Counterexample: the CLAUDE.md count formula breaks safety.**
- Take profile 4000/3000/2000/1000 with Byzantine {2000c, 1000d}. Their stake is β = 3000 < T/3, so SA-1 is satisfied.
- Under the count rule "≥ 3 of 4", {4000a, 2000c, 1000d} and {3000b, 2000c, 1000d} are both quorums. Their whole intersection is Byzantine.
- A twin-signing Byzantine pair plus two honest attesters that each saw a different twin yields **two certificates for one slot**.
- Under the stake rule, the second set is 6000 < 6667, so it is not a quorum. Only {4000}+{2000,1000} certifies, and uniqueness holds.
- Conclusion: count and stake cannot be mixed. CLAUDE.md must state the stake predicate.

**Liveness facts the S10 profiles will expose.**
- **General rule.** A member is in every quorum ⇔ T − s_i ≤ 2T/3 ⇔ **s_i ≥ T/3**. Such a member is also never tolerable as Byzantine.
- 4000/3000/2000/1000 and 2000/1000/1000/1000 therefore each have a **veto validator**: its *crash* (no fault needed) halts the chain. S10 must expect that halt by design, or genesis/EP-2 must reject any committee with `3·max_i s_i ≥ T`.
- 3300/2300/2200/2200 survives the crash of its largest node with margin 6700 − 6667 = 33 weight units. That node is 33 AIN away from becoming a veto (3300 vs 3333.3). A stake top-up of ≥ 34 AIN, or an unbond elsewhere, crosses the line at the next epoch.
- 4000/3000/2000/1000 tolerates *two* Byzantine nodes ({2000,1000}), which count-based intuition ("f=1 at n=4") gets wrong in the other direction.

**Direct-commit thresholds** (relevant to b.4):

| Profile | Q_E voters | Bullshark validity (`3S ≥ T`) voters |
|---|---|---|
| 4×1000 | 3 | 2 |
| 4000/3000/2000/1000 | {4000,3000} or {4000,2000,1000} | {4000} alone, or {3000,1000}, or {3000,2000}, … |
| 3300/2300/2200/2200 | any 3 | any 2 |
| 2000/1000/1000/1000 | {2000}+2 | {2000} alone, or {1000,1000} |

### b.3 Lemma U (certificate uniqueness): the assumptions it actually needs

Narwhal Lemma A.5 needs three things:
- honest validators never sign two blocks of one (author, round);
- 2f+1 signatures per certificate;
- implicitly, n = 3f+1.

AINCORE's lifted version needs all of the following. **Bold** marks items the contract does not state next to the lemma.

- **U1: fault bound in weight units.** `3·β_E < T_E`, where β counts the stake of every C_E entry whose registered BLS key a Byzantine party can use. That includes cloned `node.key`s and restored databases (SA-4), and entries that copied an honest key: their bits can only ever be set where the honest key signed, so they are harmless. **Weights are floored whole AIN** (`genesis.rs:190-199`).
- **U2: committee agreement.** Every honest attester and every verifier uses the same C_E. This is enforced by the `committee_hash` inside the signed body (`vcert.rs:45-46`, `:345-351`), the set-hash binding (`qc.rs:432-438`) and the epoch check (`vcert.rs:236-241`). Without U2 the intersection argument is meaningless: two certificates valid under different committees need not intersect. SA-2 supplies U2 through EP-4.
- **U3: stake recomputed from C_E**, never taken from certificate fields. Holds at `qc.rs:403-417` and `vcert.rs:107-128`.
- **U4: distinct signer entries.**
  - The bitmap is positional over `canonical_order(C_E)`, with a canonical length (`vcert.rs:245-251`).
  - Addresses are unique: genesis rejects duplicates (`genesis.rs:1045-1053`), and EP-2 validates.
  - `canonical_order` is a *stable* sort. With a duplicate address it would depend on input order, so `validator_set_hash` would not be canonical. Uniqueness is therefore load-bearing.
- **U5: one digest per slot per honest key, durably.** Each of these holds:
  - read, decide, write and commit happen before release (`vcert.rs:370-427`, `:455-473`);
  - the guard key is exactly (cg, bls_pk, E, author, r), without digest or committee_hash (`vcert.rs:285-294`);
  - one instance per directory (`c2da08d`) and one directory per key (RC-3; open hazard: `validator_{port}.db` versus `node.key`);
  - guards are deleted only for rounds ≤ g − RETAIN_SLACK, while AT-1 refuses rounds ≤ g, and g is durable and monotone;
  - a corrupt or foreign guard row is refused, never overwritten (`vcert.rs:397-401`).
- **U6: signed fields come from the validated body.** An honest attester builds AttestBody from the IN-1-validated body (`hash_v4` binds E, r and author), never from request fields. Otherwise a certified (E, r, a, d) could name a digest whose body is another slot. OR-1/RE-4 re-check `hash_v4 == digest`; U6 makes the certificate agree with them.
- **U7: cryptography.**
  - BLS min-pk (`bls/mod.rs:93-107`) is EUF-CMA in the random-oracle model.
  - PoP is verified for every key in C_E, which defends `fast_aggregate_verify` against rogue keys (`qc.rs:449`). PoP is checked at genesis, at join, and by EP-2.
  - The PoP DST differs from the consensus DST (`bls/mod.rs:24`, `:34`).
  - The attestation and finality domains are equal-length, distinct prefixes (`vcert.rs:29-32`).
  - SHA-256 is collision resistant for digest integrity ([NW] Lemma A.1).
- **U8: durability.** A synced write survives a crash (SA-4). This is untested under power loss (a known limit).
- **U9: exact arithmetic** (b.1).
- **U10: a certificate is verified only against the committee of its own epoch**, and the caller passes the right C_E. The library checks `body.epoch == expected_epoch` but trusts the caller's committee.

**Worked check (profile 2, Byzantine {2000,1000}, twins A and B).**
- Honest 4000 attests A and honest 3000 attests B; the Byzantine pair attests both.
- cert(A) = {4000, 2000, 1000} = 7000 ✓.
- cert(B) = {3000, 2000, 1000} = 6000 ✗.
- Result: exactly one certificate.
- Negative control. Not every set that violates SA-1 can close two quorums, so the S1-style control must choose its Byzantine set carefully:
  - Byzantine {3000, 1000} = 4000 violates SA-1, yet cert(B) = {2000}+{3000,1000} = 6000 still fails. Only one certificate forms, so this set is useless as a control.
  - Byzantine {4000} (40%) works: cert(A) = {4000, 3000} = 7000 and cert(B) = {4000, 2000, 1000} = 7000. Two certificates form.

### b.4 The Bullshark commit rule versus DE-1..DE-4

| Element | Bullshark PS [BS] | AINCORE DE | Assessment |
|---|---|---|---|
| Leader rounds | even rounds, predefined leader (§2.2) | even rounds ≥ max(first_round, 2) (`ordering.rs:647-654`) | same |
| Vote | an edge from a round-(r+1) vertex to the anchor (§2.2) | the voter's own signed ref to λ(r) (DE-2) | same on certified input |
| Commit threshold | **f+1 votes** (§2.2; Alg. 2 l.13); reference code uses `validity_threshold` | **Q_E (2f+1)** (`ordering.rs:700`) | **deviation, safe** |
| Where votes are counted | among the edges of one round-(r+2) vertex v (Alg. 2 l.11-13) | over all of O_E[r+1] | safe: every counted vote is a unique, certified vertex |
| Ordering earlier anchors | `path(anchor, prevAnchor)` over edges, recursive, skip otherwise (Alg. 2 l.15-26) | DE-4 walk from `chain`, CandH from H | same; no weak links on either side |
| Timeouts | wait for the anchor in even rounds; wait for f+1 votes, 2f+1 non-votes or a timeout in odd rounds (§2.3) | PR-3 anchor wait only; tick-driven proposals | partial (see row 16) |
| DAG premises | Validity, Reliability, Non-equivocation (§2.1) | OR-1, RE, Lemma U | supplied by certification |

**Why the threshold deviation is safe.**
- Lemma P needs a round-(j+1) author that is both a voter and a parent of every certified round-(j+2) vertex.
- With voters V and parents P (3·s(P) > 2T), non-empty intersection needs only `s(V) + s(P) > T`, which `3·s(V) ≥ T` already gives.
- AINCORE requires `3·s(V) > 2T`, so its intersection exceeds T/3. It is strictly more conservative.

**What the deviation costs.**
- With honest-online stake just above 2T/3 (4×1000 with one node down; 4000/3000/2000/1000 with {2000,1000} silent), **every** online honest node must vote for the leader, or that anchor is not directly committed.
- Bullshark needs only f+1. A single slow honest node whose T_LEADER fires therefore kills the direct commit.
- This feeds straight into the LEAD deadlock (b.6).

**Options.** Either:
- (a) keep Q_E, document it as a deliberate deviation, and state its liveness cost; or
- (b) move DE-2 to `3·S ≥ T`, as the Narwhal reference code does. This keeps safety, since Lemma P still holds, but it breaks S4's "bit-identical on V3 input" claim and changes the 0.42-floor corpus. It is a gate-owner decision.

**Extensional identity with today's code** (l.504-506): confirmed.
- `any(p == anchor)` over parents with one ref per author equals `vote(u) == anchor`.
- `find_map` over an index with at most one vertex per author equals |Cand| ≤ 1.
- `visited.contains(local leader)` equals CandH(j) under down-closure.
- The walk floor in `walk_history` (`ordering.rs:729`) includes round j itself, as DE-4 needs.

### b.5 Epochs and reconfiguration

**What is sound.**

| AINCORE rule | Reference design it matches |
|---|---|
| Frozen C_E and QC(H_E)-bound activation (EP-4) | Diem/Aptos `EpochChangeProof`: each epoch-ending LedgerInfo is verified by the old verifier and names the next one [APT-code] |
| Epoch-E vertices above r* never ordered; EPOCH_GENESIS sentinel | LibraBFT: blocks after the reconfiguration command carry no payload, and "a new epoch starts with an epoch-genesis block" [LBFT] |
| Return of unshipped payloads (EP-4) | Sui Lutris: end-of-epoch discards transactions, which must be resent with the new epoch [LUT §4.2] |
| Height-based boundary E(h) = ⌊(h−1)/I⌋ | Sui ends an epoch in-band, by 2f+1 End-of-Epoch messages. AINCORE's boundary is deterministic and simpler; the one-anchor-per-block mapping carries the agreement (Theorem 3, via `anchor_already_on_chain`). |

**Missing liveness assumptions** (none of these threatens safety):
1. **The old committee must stay live after H_E.** QC(H_E) is signed by C_E. Departing members must keep running until QC(H_E) forms and is disseminated, and must serve epoch-E bodies and certificates for the retention window.
2. **The new committee must be ready at activation.** C_{E+1} comes from the *post-state of H_E*, so a validator that joins in H_E becomes a member at activation with no time to sync. Sui closes registration at checkpoint S and hands over only after a quorum of the new committee signals "Ready" [LUT §4.2]. Either add a cutoff (for example, take C_{E+1} from the post-state of H_E − K) or add LA-10: ">2/3 of T_{E+1} is synced and online at activation".
3. **Rejoin transport.** FinalityVote V2 binds only `next_validator_set_hash`. Diem's LedgerInfo carries the full next verifier. A node that rejoins without executing (G3 snapshot, light client) needs the committee list sent next to QC(H_E). The hash check suffices once the list is delivered, but the transport must be specified (IM-4 / EP-4).
4. **Posterior corruption.** SA-1 must hold for *every historical* epoch a rejoining node verifies. Old committees' keys stop being bonded after they unbond. The standard answer is a weak-subjectivity checkpoint (Diem "waypoints"), or an unbonding period longer than the maximum offline period. This is out of G1 scope but should be named.

**`first_round(E+1)`: r*+1 versus r*+2.**
- In epoch E, vertices exist at rounds up to about cursor + LEAD > r*+2. **Round numbers therefore overlap across epochs under either choice.**
- What makes the overlap harmless:
  - every durable key carries E (except `vertex:{digest}`, where the digest includes E);
  - in-memory state is reset at activation;
  - IN-1 runs E1 first.
- The code does need one numeric property. Round-only comparisons — `anchor_already_on_chain(r) = r ≤ latest_block_round` (`dag.rs:581-583`) and the `consensus:cseq:{anchor_round}` key — require **every committed anchor of E+1 to have a round greater than r*_E**.
- Both choices satisfy this, because the first E+1 anchor is r*+2 either way. A Sui/Diem-style *round reset* would silently skip every E+1 anchor (`r ≤ latest_block_round`).
- Two parity notes: r*+1 gives E>0 the same shape as E=0 (an odd, non-anchor first round). r*+2 makes the first round itself an anchor round whose vertices cite only the sentinel. Both are sound.
- **The S9 mutation "first_round = r*+1 → overlap red" is therefore not a safety mutation.** If it goes red, it has found a surviving round-only index (a bug), not a flaw in r*+1.

### b.6 Liveness: the LEAD hard cap can deadlock permanently

**Mechanism.**
- PR-1 forbids proposing above `cursor + LEAD`, AT-1 forbids attesting there, and E5 drops vertices there. LEAD = 200 rounds, which is 100 anchor rounds.
- Suppose every anchor in `[c, c+LEAD)` lacks Q_E votes at its r+1 round.
- Every round up to c+LEAD is then already proposed, and the per-slot guards (`vproposed`) forbid a second vertex.
- No anchor in the window can ever gain votes, the cursor never moves, and no round above c+LEAD can exist. **Permanent deadlock**, which survives GST and restarts.

**How it is reached.**
- *Pre-GST scheduling (the standard partial-synchrony adversary).* Delay each leader's certificate past T_LEADER at one honest node for 100 consecutive anchors. With one node down (at 4×1000, or {2000,1000} down at 4000/3000/2000/1000), Q_E needs every remaining vote, so one late honest node per anchor is enough. At a 3 s tick that takes about 600 s.
- *Without any adversary.* One node offline plus one validator (for example the Pi) whose effective certification latency spikes above T_LEADER for about 10 minutes.

**Why the contract's bound does not cover this.** The (β/T)^100 < 3^−100 bound only covers leaders drawn Byzantine and silent. Bullshark's liveness claim — after GST, honest anchors commit via timeouts [BS §2.3] — requires that progress be possible from *any* pre-GST state. The hard cap breaks that requirement.

**Fixes** (any one works; the first is cheapest):
1. At the cap, keep advancing with **payload-free vertices**: headers plus certificates, about 0.5–1 KB each at n=4. Keep attesting. Bound payload bytes, not rounds.
2. Make the cap soft: after T_STALL at the cap, allow k further rounds.
3. Adopt the validity threshold (b.4). This lowers the frequency of the trap but does not remove it.

Also add an S10 witness: adversarial pre-GST skipping of ≥ LEAD/2 anchors, then GST, then a direct commit within K rounds. It is predicted red against the contract as written.

**Other liveness items.**
- **LA-3/LA-4 (tick and clocks)** are not in the papers. They are acceptable additions. Bullshark is responsive (it advances at network speed); AINCORE's 3 s tick is not. Throughput and latency pay for that, not correctness.
- **Liveness step 3** needs every honest node to eventually hold every honest round-(r+1) certificate. `DAG_CERT` is pushed once, and CERT_REQ fires only below the round quorum (RE-1(d)). The eventual trigger is honest round-(r+2) children embedding all held certificates (PR-4 plus E4). State this. It replaces Bullshark's odd-round vote wait.
- **LA-1** (fair-lossy links plus pull) matches Narwhal §4.1, which gives up perfect links for signer-pull.
- **LA-8** (stake-weighted draw): probabilistic progress, as the contract states.

### b.7 Cost at n=4, recomputed

**Messages per round.**

| Message | Logical point-to-point |
|---|---|
| `DAG_VERTEX` | 4×3 = 12 |
| `DAG_ATTEST` | 4×3 = 12 |
| `DAG_CERT` | 4×3 = 12 |
| **Total** | **36 = 3n(n−1)** ✓ |

- Physical frames are higher. `DAG_VERTEX` and `DAG_CERT` are each sent by gossip *and* TCP fan-out (`dag.rs:2027-2045`), so the count is at least 24+12+24 = 60.
- Gossipsub at n=4 is a full mesh (`mesh_n(6)`, `p2p.rs:115`). Each publish can be forwarded by each receiver to 2 more peers, giving up to 9 gossip frames per broadcast, or about 108 frames per round as an upper bound.
- ATTEST_REQ retries every `T_RETRY` and CERT_REQ pulls come on top.

**BLS operations per node per round.** min-pk: 48 B G1 public keys, 96 B G2 signatures (`bls/mod.rs:93-107`).

| Operation | Count | Where |
|---|---|---|
| Sign (hash-to-G2 plus G2 multiplication) | 4: own `vattest` + 3 other authors | PR-4, AT-2 |
| Single verify (2-pairing product) | 3, or 4 if the own attestation passes through `add` | `vcert.rs:558-563` |
| Aggregate verify | 1 self-check of the formed certificate + 3 received certificates = 4 | `vcert.rs:619-625`; CE-2 |
| Aggregation (G2 additions, cheap) | 1 | `vcert.rs:606-610` |
| **Total expensive operations** | **11–12** ✓ (contract: about 11) | — |

- Finality adds, per committed anchor (about every 2 rounds), 1 sign + 3 vote verifies + 1 QC verify: about 2.5 per round, for about 14 in total.
- In pairings: about 8 verifies means about 16 Miller loops plus 8 final exponentiations. Each `fast_aggregate_verify` also re-decompresses and subgroup-checks every public key (`qc.rs:441-446` via `bls/mod.rs`); caching them per committee is free.
- Embedded parent certificates (E4) add up to 3×4 = 12 aggregate verifies per round unless the cache is keyed by (E, r, author, digest). Key it that way: a Byzantine relay can embed a *different but valid* certificate for the same digest.
- **DoS surface.** Every ATTEST_REQ that hits an existing guard re-verifies the stored attestation (`vcert.rs:390-396`). An author retrying every `T_RETRY`, or a spoofed one before G4 lands, forces one pairing check per request. Cache the verified guard row per slot, or rate-limit.

**Fsyncs per node per round.**
- 4 synced transactions (1 proposal + 3 attestation stages), plus 1 acceptance per committed anchor: about 4.5.
- Given the known NAS fsync bottleneck, allow group commit: stage several attestations in one transaction and release all of their signatures after that commit. AT-2 still holds.
- Optimistic aggregate verification (verify the aggregate once, fall back to individual checks on failure) cuts the 3 per-attestation verifies to 1 in the common case.

---

## (c) Required contract corrections, ranked by severity

**MAJOR**

1. **The LEAD hard cap deadlocks permanently** (PR-1 l.434, E5 l.342, AT-1 l.372; liveness point 5 l.753; Open Q10 l.892).
   - Replace "does not propose above cursor+LEAD" with payload-free advancement or a soft cap.
   - Restate GC-5's byte bound over payload-bearing rounds.
   - Delete the 3^−100 claim, or restrict it to its model.
   - Add the pre-GST-skip-then-GST witness to S10.
2. **Epoch-boundary liveness assumptions are missing** (LA list; EP-2/EP-4).
   - Add: C_E stays live until QC(H_E) forms and is served.
   - Add: >2/3 of T_{E+1} is synced at activation, or a registration cutoff at H_E − K, as in Sui Lutris.
   - Add: the committee list travels with QC(H_E) for non-executing rejoin, as in Diem's `next_epoch_state`.

**MEDIUM**

3. **DE-2 threshold deviation** (l.468-471, l.775, `ordering.rs:526-527`).
   - State that Bullshark commits with f+1 (validity, `3S ≥ T`) and that Q_E is a deliberate strengthening.
   - Give the Lemma P argument with its true requirement, `s(V)+s(P) > T`.
   - State the liveness cost (every online honest node must vote when honest stake is near 2T/3).
   - The gate owner decides whether to move to validity. That would forfeit S4's bit-identity claim and change the corpus.
4. **Unequal-stake guidance.**
   - Any member with `3·s_i ≥ T` is a liveness veto and is never tolerable as Byzantine. Two of the four S10 profiles have one: 4000 of 10000, and 2000 of 5000.
   - Either reject such committees in genesis validation and EP-2 (with carry-over), or record the veto as a founder decision and set per-profile S10 expectations (a crash of the veto node halts by design).
   - Rephrase LA-2 in stake terms; "3 nodes" is equal-stake only.
   - Note that 3300/2300/2200/2200 sits 33 AIN from a veto.
5. **Round numbering** (Defs l.193; EP-3; S9 l.862).
   - Replace "rounds are counted per epoch" with two invariants: "slots are epoch-scoped; anchor rounds are globally strictly increasing (every E+1 anchor > r*_E)". Code depends on the second (`dag.rs:581-583`; `cseq:{anchor_round}`).
   - Drop the S9 mutation "first_round = r*+1 → overlap red": both values are safe, and cross-epoch overlap exists regardless.
   - Replace it with a witness that injects epoch-E vertices at rounds r*+1 … r*+LEAD after activation.
   - Resolve the r*+1 versus r*+2 inconsistency between the task brief and the contract.
6. **Lemma U must list its assumptions.** Add U1–U10 (b.3). In particular:
   - committee agreement (U2);
   - weight-unit SA-1 with floor scaling (U1);
   - AttestBody derived from the validated body (U6);
   - the caller supplies the epoch's committee (U10).

**MINOR**

7. **Replay test non-vacuity.** The S9 "remove epoch from AttestBody → replay red" mutation must run with **C_{E+1} = C_E**. Otherwise `committee_hash` rejects the replay and masks the mutation.
8. **Citations.**
   - Bullshark timeouts are in §2.3 "Advancing rounds", not in Algorithm 2 (l.913).
   - Narwhal Lemma A.5 is titled "Containment"; the uniqueness claim is in its proof.
   - Narwhal condition (2), "at the local round r", is relaxed to (g, cursor+LEAD]. That is safe, since only condition (4) feeds A.5, but it should be documented as a deviation.
9. **CLAUDE.md quorum line.** Replace `(n * 2/3) + 1` with `3·stake(S) > 2·T` (`qc::stake_quorum_met`) and cite the counterexample in b.2. Also fix the executor doc comment at `core/executor/src/lib.rs:2152`. CLAUDE.md rule 5 applies: this is a documentation correction, not a formula change.
10. **Cost section** (Open Q3).
    - Add physical amplification (gossip plus TCP double-send).
    - Add the own-attestation verify, QC work (+~2.5 per round), and certificate-cache keying.
    - Add the retry-driven guard re-verify DoS (`vcert.rs:390-396`).
    - Recommend group commit and optimistic aggregate verify.
11. **Liveness step 3.** Name the certificate-dissemination trigger that replaces Bullshark's odd-round vote wait: children embed all held certificates, via RE-1(a)/(c).
12. **GC-3 across epochs.** Delete closed-epoch rows *by epoch*. Rows of epoch E above the new floor would otherwise leak: about LEAD × n rows per epoch. This is safe because AT-1 refuses E ≠ E_active.
13. **Posterior corruption / weak subjectivity** for rejoin across many epochs. Name it as an assumption, and hand it to G3/G5.

---

## (d) The five hardest invariants: tests and mutations for S2–S11

Each test's mutations must be *run and observed red*; the positive controls must stay green.

### INV-1: At most one certified digest per slot, under stake weights, crashes and concurrency (Lemma U)

**Test** `lemma_u_exhaustive_unequal_stake` (S1 extension, then S3 and S5 with real RocksDB).
- Profiles: 4×1000, 4000/3000/2000/1000, 3300/2300/2200/2200, 2000/1000/1000/1000.
- For each profile, and each *maximal tolerable* Byzantine set from b.2 (for example {2000,1000} in profile 2), Byzantine members attest both twins.
- Honest members call real `attest_slot` / `attest_slot_in`.
- Enumerate every honest delivery order × {no crash, `exit(77)` at boundary 0, `exit(77)` at boundary 1} per honest node, then reopen and retry.
- Assert that the number of distinct certified digests is ≤ 1, using `CertCollector` plus an independent `verify_vertex_cert`.
- Negative control: in profile 2, Byzantine {4000}. Two certificates must form.

**Mutations that must go red:**
- (a) `stake_quorum_met` replaced by the count rule `k ≥ n*2/3+1`. Profile 2 with Byzantine {2000,1000} yields two certificates. This is the unequal-stake mutation.
- (b) Skip the stake recompute and trust `signed_stake` (`qc.rs:403-417`), with a forged field.
- (c) Guard key without E, or without the author, or with the digest added.
- (d) Release before commit.
- (e) Read the guard via lossy `StateDB::get`, then corrupt the row.
- (f) GC deletes guards above g − RETAIN_SLACK, then re-request.

**Positive control (must stay green):** `3S ≥ 2T` in place of `3S > 2T`, which documents b.1 item 4.

**Plus:** a power-loss harness (for example, fsync-dropping storage) to close SA-4's untested half.

### INV-2: Cross-node anchor-decision agreement, including skips (Theorem 1 via Lemma P), under different views and GC timing

**Test** `de_prefix_agreement_differential` (S4 decision function, S5/S7 system).
- Generate certified DAGs through SimNet with real certification, using these schedules:
  - an equivocating leader;
  - a rushing non-equivocating Byzantine;
  - withheld bodies;
  - 20% omission.
- Use at least 3 node views per DAG (subsets and permutations) and 2 prune/checkpoint timings.
- Run DE-1..DE-6 to quiescence.
- Assert that every pair of `(anchor_round, Commit(d) | Skip)` sequences is prefix-consistent, and that sequences and finality digests match on the common prefix.
- Include a targeted case: node X directly commits j with *exactly* Q_E voters; node Y sees fewer and first commits a later anchor. Y must commit j by the walk.

**Mutations that must go red:**
- DE-4 skips when λ(j) is in H but absent from the local index.
- A missing non-settled parent is treated as settled.
- g is taken from the local prune horizon (the old `dag.rs` horizon).
- DE-2 counts uncertified round-(r+1) bodies.
- The S6 parent quorum *and* DE-2 are both weakened to validity. Lemma P then fails.

**Positive control:** DE-2 alone at validity (`3S ≥ T`) stays green. This proves the b.4 deviation is safety-neutral, and it measures the liveness gain.

### INV-3: O_E is down-closed, certified, at most one per author per round, and OR-1 is its only writer

**Test** `or_invariants_fuzz` (S3/S5).
- Randomly interleave IN, ST, CE, OR and floor-rise events: certificate before body, body before certificate, 3 twins, certificate conflict, reopen.
- After every step, assert OR-2, and assert that O_E above g is a down-closed subset of certified digests with staged bodies.
- Also run the S5 twin-flood witness, the S3 3-twin witness and the S7 floor-rise witness.
- Make `round_index` private behind a single OR-1 setter, with a test that it is the only writer.

**Mutations that must go red:**
- OR-1 without the certificate check (A3c).
- The producer takes parents from staged bodies (twin-flood).
- OR-3 removed (floor-rise).
- The ST-2 reservation removed (3-twin).

### INV-4: Epoch boundary agreement and cross-epoch isolation

The invariant: every honest node closes E at the same (H_E, r*, A*), derives the same C_{E+1}, and activates only with a verified QC(H_E) binding it. No epoch-E artifact changes an epoch-(E+1) decision, and anchor rounds strictly increase across the boundary.

**Tests:**
- The S9 witnesses (a)–(k), run with *both* `first_round = r*+1` and `r*+2`, both expected green.
- `replay_with_carry_over_committee`: C_{E+1} = C_E, so `committee_hash` is identical. Replay epoch-E attestations, certificates and vertices into E+1 at identical round numbers; all must be rejected or STALE.
- `stale_epoch_vertices_up_to_lead`: deliver epoch-E vertices at rounds r*+1 … r*+LEAD after activation; O_{E+1} must be unchanged.
- An assertion that every E+1 anchor round is greater than r*.
- Two liveness witnesses: a joiner that is not synced at activation, and a departing validator that goes offline before QC(H_E). Their expected outcomes follow correction 2.

**Mutations that must go red:**
- Drop `epoch` from AttestBody. This goes red **only with a carried-over committee**.
- Drop the epoch check (`vcert.rs:236-241`).
- Take r* from `header.round` instead of `QC.anchor_round`, fed a Byzantine block with a forged round.
- Activate without QC(H_E).
- FinalityVote V2 without `next_validator_set_hash`, with a divergent committee.
- Take C_{E+1} from the live set.
- Reset rounds per epoch. This must go red through `anchor_already_on_chain`, proving the monotone-round invariant is load-bearing.

### INV-5: No second decision writer (Theorem 4, IM-1..IM-3)

The invariant: every executed or adopted block is either this node's own DE-5 decision, or carries a QC under C_{E(h)} whose eight bound fields all match.

**Tests:**
- The S8 witnesses.
- One test per IM-1 clause: forge exactly that field on an otherwise valid block and QC pair, and require refusal with no writes.
- A crash at every IM-2 boundary.
- A conflict between a local decision and a QC must halt.

**Mutations that must go red:**
- Remove each IM-1 clause in turn (8 mutations, each a dedicated red test).
- Check `block_hash` only (fake anchor).
- Drop `qcs` from SYNC_RESP (outage witness).
- Import without the IM-2 single transaction (crash witness).

### LIV-1 (liveness; predicted red against the contract as written): progress after GST from any pre-GST state

**Test** `post_gst_progress_after_lead_exhaustion` (S10).
- n=4 at 4×1000, with one validator offline.
- An adversarial scheduler delays each leader's certificate past T_LEADER at one honest node for LEAD/2 + 1 consecutive anchor rounds.
- Then GST.
- Assert a direct commit within K rounds.
- Repeat at 4000/3000/2000/1000 with {2000,1000} silent.
- Expected result: red until correction 1 lands. This witness is what proves the fix.
- Companion per-profile check: a crash of the veto node halts profiles 2 and 4 by design, unless correction 4 rejects those committees.
