# DAG Vertex Synchronization — Design

**Status:** DRAFT v3 — v2 attacked by six critics: 34 claimed, 66/68 verified, **21 confirmed** (10 CRITICAL, 8 HIGH, 3 MEDIUM). All folded in. v3 is split into two independently-critiqued parts (§0). NOT approved for implementation.
**Branch / HEAD:** `audit/mainnet-hardening` @ `3208d29`
**Closes:** B3/B4 (audit-119 CRITICAL, open at HEAD, `dag.rs:1090-1115`)
**Inputs:** `docs/research/{A,B,C,D}-*.json`; I1–I16; v1 critique (9 holes); v2 critique (21 holes, task `wczn6qne3`).

Every AINCORE claim cites `file:line` at HEAD `3208d29`.

---

## 0. Structure of v3 and what v2 got wrong

v2's 21 holes have a shape. **Five CRITICALs (v2 #2, #3, #4, #8, #10) are one root cause:** the anchor decision for a round whose leader equivocated depended on `round_index` arrival order (`leader_vertex_hash`, `ordering.rs:641-646`, `find_map`), so v2's shadow bodies completed the walk on both sides while each side then selected a different twin — turning HEAD's *wedge* into a *fork*. Two more (v2 #6, #9) are one cause: the ingress membership check reads the *current* validator set (`dag.rs:1082`), so a fetched body from a since-slashed author is rejected forever. One (v2 #5) is admission being a function of *local* state. One (v2 #1) is a floor bug in R1's walk. The rest are bounds and tests.

The core citing-side rule (R1 + R4 + R4′) survived with **one** correction. The equivocation sub-design did not survive at all.

So v3 is **two parts with separate critiques and separate gates**:

- **Part I — Stage 1: citation discipline.** `dag.rs` + `ordering.rs`, no messages, no WANTED, no shadow. Closes the malicious wedge and the false-skip fork. Must be critiqued and shippable **alone**.
- **Part II — Stages 2–4: fetch and equivocation.** Depends on Part I. Its equivocation section (§6) is the part that has failed twice; it is redesigned from the critics' converging fix and must pass its own critique before Stage 4 starts.

## 1. Problem statement (unchanged)

Parents are cited by bare hash (`blockchain/src/lib.rs` `Vertex.parents`); ingress checks only count/uniqueness (`dag.rs:1046-1061`); `walk_history` returns `None` on any absent, non-genesis, non-committed hash (`ordering.rs:697-702`) and `commit_one_anchor` propagates it with `?` (`:731-737`). A Byzantine key can cite a hash that hashes nothing; honest proposers cite `round_index[prev]` verbatim (`dag.rs:529-536`); the poison enters every cone; no anchor commits again. Honest loss is routine (drop-only limiter `p2p.rs:345-352, 391-398`; 60 s dedup `:119-123`); the only redelivery is a push by nodes *below* quorum (`dag.rs:621, 881-926`). Narwhal avoids all of this with 2f+1 availability certificates (Track A §3.1); AINCORE has none, so "late vs never" is undecidable at ingress. v3 decides it on the citing side with quorum enforced, and makes *being unable to cite* the fetch trigger.

## 2. Vertex state model

| State | Definition | Written by |
|---|---|---|
| S0 UNKNOWN | in no store | — |
| S1 IN_DAG | `dag`, `round_index`, `vertex:H` (`dag.rs:1174-1187`) | ingress |
| S2 SETTLED | `H ∈ committed_set`; body may be absent (`ordering.rs:739-748`; `:869-888` via `dag.rs:2852-2884`) | commit / sync |
| S3 PRUNED | gone from all three; min_round = min(finalized, latest_block_round) − 10 (`dag.rs:1786-1808, 2770-2783`) | local block build |
| S4 SHADOW *(Part II)* | body of the second twin of an equivocating pair; never in `round_index` | §6 |
| S5 WANTED *(Part II)* | cited by something held, absent, tracked | §5 |

Settled predicate used by commit: `{dag} ∪ {"genesis"} ∪ committed_set` (`ordering.rs:697-702`).

---

# Part I — Stage 1: citation discipline

## 3. R1 — full-history resolution (v2 #1, #5, #13 fixed)

**Definition.** `V` is *resolved* on this node iff `resolve_walk(V)` returns `Some`, where `resolve_walk` is `walk_history` with **floor 0** — identical termination set to `commit_one_anchor`'s gate (`ordering.rs:731`: `walk_history(anchor, 0, …)`). Every path from `V` must terminate in `"genesis"` or `committed_set` through bodies this node holds.

**Why floor 0 (v2 #1):** `walk_history` does not push the parents of a vertex whose `round <= floor` (`ordering.rs:704`). v2 used `floor = last_committed_anchor_round`, so a poison vertex sitting *at* that round was opaque — its fake parent was never examined — and the attacker's next vertex resolved, was cited, and re-created the original halt one anchor later. With floor 0 the walk descends through every held uncommitted body and stops only at `committed_set`, exactly as the commit walk does; the cost bound is the same as the commit walk's (C10).

**Edge checks inside the walk (v2 #5).** Admission must be a pure function of the vertex bytes plus state identical on every node. Therefore round-exactness and author-membership are **not** ingress rejections (v2's R2 was evaluated on local state and produced admit-here/reject-there — an unrepairable, non-deterministic hole). They are **edge validity checks inside `resolve_walk`**: an edge `child → parent` is valid iff `parent.round == child.round − 1` (or `parent == "genesis"` and `child.round == 1`) **and** `parent.author ∈ validator_set_at(parent.round)` (§3.2). A vertex with an invalid edge is admitted everywhere and **resolves nowhere** — never cited by any honest node — which is deterministic.

**Cache.** `resolved: HashMap<hash, Verdict{Resolved | Unresolved{blocked_on: BTreeSet<hash>}}>`, ≤ 4096 entries, LRU by receiver round. A `Resolved` entry is authoritative until the vertex is pruned. An `Unresolved` entry is **never** treated as resolved because of its round (v2 #1 corollary). It is re-walked when (a) any hash in `blocked_on` is admitted, **or** (b) any hash in `blocked_on` enters `committed_set` via sync adoption (v2 #13 — both settlement paths share the one release hook), **or** (c) **every tick while R4 is failing**, for the round-(r−1) candidates only (bounded by n walks per tick; needed because Stage 1 has no WANTED to drive (a)/(b)).

### 3.1 R4 — cited-parent quorum, proposer side (v1 #1, #4)

`try_create_vertex` cites only resolved round-(r−1) vertices. `parent_quorum_met` (`dag.rs:566-585`) is computed over that **cited** list. If the cited authors' distinct stake is not > 2/3 total, **the node does not propose** and takes the existing below-quorum branch (`dag.rs:881`). This restores the premise of the ancestry skip verbatim: "every vertex at j+2 references > 2/3 of the j+1 vertices" (`ordering.rs:513-517`).

### 3.2 Validator set as of a round (v2 #6, #9)

`dag.rs:1082` checks the author against the **current** set (`get_validator_set_with_stake`, `dag.rs:3024-3063`). After a slash or a voluntary leave (`executor/src/lib.rs:2532-2580, 866-912`) the author is gone, and any late or fetched body from it is rejected forever — while honest vertices already cite it. Stage 1 introduces `validator_set_at(round)`: the executor persists the set snapshot keyed by the anchor round at which it took effect (`sys:validator_set_at:{round}`, written where `sys:validator_set:v1` is written today, bounded to the unpruned window). Ingress membership (`:1082`) and the walk's edge check both use `validator_set_at(vertex.round)`. The **current** set is still used for `parent_quorum_met`, `direct_quorum_met`, and leader election — unchanged.

### 3.3 R4′ — commit-side anchor eligibility (v1 #4, #6)

In `try_commit`, a vertex is **anchor-eligible** — as the direct anchor in step 1 (`ordering.rs:558-567`) or as a chain link in step 2 (`:583-597`) — only if the distinct-author stake of its **present** parent bodies is > 2/3 of `validator_set_at(round − 1)`. Otherwise it **defers** (returns empty); it is never skipped by proof. A parentless or sub-quorum vertex can therefore never anchor and never prove a skip.

**Ingress keeps only what is a pure function of bytes:** `round > 1 ⇒ parents non-empty`; the existing 12 checks (C4). A parentless vertex at `round > 1` is rejected identically everywhere (v2 #16 resolved: the test asserts *skip*, see §10).

### 3.4 Consequence for the malicious case, traced at HEAD

Attacker `V_r` cites fake `P`. Every honest `resolve_walk(V_r)` reaches `P` → `Unresolved{P}`. Attacker `A_{r+1}` cites `[V_r, honest_r…]`: `resolve_walk(A_{r+1})` (floor 0) reaches `V_r` → `P` → `Unresolved`. Not cited. If the attacker leads an even round, its vertex is cited by no honest r+1 vertex → `direct_quorum_met` false → step 1 scans past; it is a chain link in step 2 only if some honest vertex cited it, which none did → never in `visited` → the existing skip (`test_b4b_missing_leader_is_skipped_deterministically`, `ordering.rs:1655`) applies, and its premise now holds because every honest vertex cites > 2/3 (R4). **No buffer, no fetch, no state.**

## 4. Part I bounds, locks, exit

- New state: the `resolved` cache (≤ 4096 × ~200 B) and `sys:validator_set_at:{round}` rows (one per set change, pruned with the DAG horizon). Nothing sender-inflatable.
- Locks: `resolve_walk` runs where `try_create_vertex` already holds `dag`/`round_index` (`dag.rs:529-536`); the cache is a field on `DagConsensus` mutated under the same guards; no new lock, no re-entry (I16).
- **Exit criterion:** tests §10 rows 1–7 green; adversarial gate on Part I alone returns no CRITICAL/HIGH; 48 h 4-node burn-in with **byte-identical committed sequences and identical `anchor_hash` per height** on every node — not merely "no stall" (v1's criterion was blind to silent exclusion).

---

# Part II — Stages 2–4: fetch and equivocation

## 5. Fetching

### 5.1 Trigger

The trigger is the proposer's own `resolve_walk` (I14, v1 #2): each `Unresolved{blocked_on}` verdict inserts every hash in `blocked_on` into WANTED with the candidate's author as a witness. **The walk collects every missing hash reachable through present bodies**, not just the first (v2 #21). `walk_history`'s hole in `try_commit` is a secondary trigger (holes below the cursor after sync adoption).

### 5.2 Fetch-worthiness (v1 #8, #9; v2 #14, #21)

`WANTED[H] = { witnesses: BTreeSet<author>, first_seen_tick, attempts, in_flight, blocked: BTreeSet<vertex_hash>, tier }`.

- **Tier A — witnessed:** distinct-witness stake > 1/3 total ⇒ ≥ 1 honest holder. Full rate.
- **Tier B — author-claimed (observable form):** for each unresolvable parent of a vertex authored by `X` at round `r`, request it **from X only**, ≤ `MAX_PARENTS` hashes per `(X, r)`, one frame per 16 ticks per `(X, r)`. Defined on what the node can observe (the citer's author and round), not on the absent body's fields.
- **Probe:** everything else, citers only, one request per 16 ticks.

**Quotas and eviction (v2 #11, #14, #17):** Tier A has its own budget of 256. Tier B + probe share a budget of 256 **with a per-witness-author quota of 4** (LRU within the author). Every entry carries a receiver-tick TTL of 64 ticks regardless of tier. WANTED is **never** populated at ingress for vertices with `round > current_round + 2`, and the boot walk skips them too (far-future admitted vertices are the I11 bound, tracked separately).

### 5.3 Messages — direct TCP only (unchanged)

`VERTEX_REQ:{hashes ≤ 32, requester_id}` / `VERTEX_RESP:{vertices, unknown}`, modelled on `DA_SHARD` (`da/src/lib.rs:707-757`). Server in `chain_sync`: `vertex:{H}` **or** `vertex_shadow:{H}`, no consensus lock, reply ≤ 1 MiB (`network/src/lib.rs:239`). Client: own task with `Arc<RwLock<DagConsensus>>`, `secure_connect(…, Some(peer_id), …)`, never via `tx_in` (B13). Each body enters through `handle_message` — the single gate — with membership evaluated by `validator_set_at(vertex.round)` (§3.2) so a body from a since-removed author is admissible (v2 #6, #9).

### 5.4 Request policy (v2 #12)

- Whom: witnesses first (random order per attempt), then validators with `peer_ip`; Tier B: the author only.
- **Per-request deadline: 2 receiver ticks**, independent of the transport's 120 s timeouts; abort on expiry.
- In flight: ≤ 2 per hash; **≤ 2 per peer**; **separate pools** — Tier A ≤ 12, Tier B + probe ≤ 4 — so honest-guaranteed fetches never wait behind attacker-routed ones.
- Exclude for that hash, until TTL, any peer that timed out, answered `unknown`, or returned an invalid body.
- Backoff `min(2ᵏ, 16)` receiver ticks. Exit on admission, settlement, no dependents, or `round < prune_horizon`.

### 5.5 Release (I7, I8)

On admission **or** sync settlement of `H`: remove `WANTED[H]`, invalidate `resolved` entries listed in `blocked`, re-walk those on the next tick. O(dependents); never a drain.

## 6. Equivocation — redesigned from the converging fix (v2 #2, #3, #4, #7, #8, #10, #15, #18, #19)

**Principle.** A round whose leader is a known equivocator is **never decided by ancestry and never depends on which twin arrived first.** It is decided by **direct votes keyed on `(author, round)`**, which is a pure function of held bodies.

**Rule E1 — twin-aware leader lookup.** `leader_vertex_hash(r)` returns **all** vertices by `leader(r)` at round `r` in `dag ∪ shadow` (a set, ordered by hash for determinism), not the first in `round_index`.

**Rule E2 — decision for a leader round.** Let `T` be the twins from E1 and `votes(t)` the distinct-author stake of held round-(r+1) bodies citing `t`.
- Commit `r` at twin `t` iff `votes(t) > 2/3` (step 1, as today, but per twin — at most one twin can pass, by quorum intersection).
- If the walked round-(r+1) set held ≥ 2/3 stake and `Σ_t votes(t) ≤ 1/3`: **skip** `r` (quorum intersection proves no direct quorum for any twin ever existed).
- Otherwise **defer** and WANTED the missing round-(r+1) votes.
- Step 2 never decides a twinned round by `visited` membership. For an untwinned leader, step 2 is unchanged.

This is consistent with a node that already committed `r` directly at `t` before any proof existed: it had `votes(t) > 2/3`, so no node can ever see `> 2/3` for another twin, and every node that later learns of the twin still reaches "commit at `t`" via E2. **No exclusion rule** is needed for anchor determinism (v2 #7, #18: the exclusion keyed on node-local `sys:equiv_seen` is dropped; the sequence orders whatever the cone contains, and the slash still lands via block-carried evidence, `dag.rs:2046`, `executor:2266-2339`).

**Shadow storage (v2 #15, #19).** On equivocation detection, at most **one** shadow per `(author, round)` — the first counterpart — stored as compact form **plus parents** (the walk needs parents, not payload); any further same-round body from that author is dropped without writing (the existing `sys:equiv_seen` latch, `dag.rs:2287-2290`). The write happens after the ingress guards drop. Shadow rows are indexed by round and pruned by `prune_dag` under the same `min_round`. Ingress dedups by hash over `dag ∪ shadow` before the equivocation branch. Shadow rows are loaded at boot. The equivocation check runs **before** the membership check for hashes in WANTED (v2 #9).

**`resolve_walk` reads `dag ∪ shadow`** so a citation of either twin resolves once both are held; the fetch (§5) is what brings the second one.

## 7. Interaction table (Part II)

| Situation | v3 |
|---|---|
| Asymmetric equivocation, offender **not** leader | witnesses of the missing twin > 1/3 ⇒ Tier A fetch ⇒ shadow; walks resolve; sequence identical (cone-determined). |
| Asymmetric equivocation, offender **is** leader (v2 #2/#3/#4/#8/#10) | E2: each node commits `r` at the twin with `> 2/3` votes, or skips if ≤ 1/3 total, or defers and fetches votes. Arrival order irrelevant. Node that committed directly is consistent by intersection. |
| Fetched body from slashed/left author (v2 #6/#9) | admitted via `validator_set_at(vertex.round)`. |
| `prune_dag`, `committed_set` window, sync adoption, boot loops, re-gossip, limiter, observer, restart, forged `VERTEX_RESP`, `VERTEX_REQ` flood | as v2, with the §5 quotas/TTLs/deadlines. |

## 8. Lock discipline

No new lock; no new nesting. `resolve_walk` and cache mutation under the guards `try_create_vertex` already holds. E1/E2 are pure functions inside `try_commit` over `dag ∪ shadow` (shadow read under the `dag` guard). Fetcher: `consensus.write()` per body, nothing held across `.await`. Server: storage only. Sync sweep: lookup + invalidate, no re-entry.

## 9. Invariant checklist

| Inv | Part I | Part II |
|---|---|---|
| I1 | R1 floor 0 + R4 + R4′ + existing skip | — |
| I2 | — | proposer-walk trigger; pull from witnesses |
| I3 | cache LRU by receiver round | TTL 64 receiver ticks; per-author quota |
| I4 | cache < 1 MiB | WANTED < 2 MiB; shadow ≤ 1 per (author, round), compact + parents |
| I5 | cache by hash | WANTED by hash; shadow dedup by hash |
| I6 | — | single gate; `validator_set_at` |
| I7 | re-walk O(dependents) | release O(dependents) |
| I8 | tick re-walk + sync hook | sync hook shares release |
| I9 | — | E1/E2 direct-vote decision; no local-row keying |
| I10 | tick re-walk while R4 fails | boot walk (bounded ≤ current+2) + fetch |
| I11 | **not addressed** | **not addressed** (far-future byte bound, separate) |
| I12–I14 | no ban; bounded maps; own-tick scheduling | same |
| I15 | — | server cost bounded; TCP slots = Stage 5 |
| I16 | §8 | §8 |

## 10. Test plan — each row names the mutation that must fail it (v2 #16, #20, #21 fixed)

| Test | Asserts | Mutation |
|---|---|---|
| `poison_at_floor_round_is_not_laundered` | poison at round == last committed anchor; attacker link at +1; honest nodes do **not** cite the link; anchors r+2, r+4 commit | reintroduce `floor = last_committed` |
| `one_hop_launder_rejected` | attacker's r+1 child citing [poison, honest] never cited | make R1 one-hop |
| `sub_quorum_cited_parents_do_not_propose` | node lacking the r leader vertex, leading r+2, enters below-quorum branch; no anchor ≥ r on it; peers and it converge after redelivery | quorum over present instead of cited |
| `parentless_vertex_rejected_and_round_skipped` | parents=[] at round>1 rejected on all nodes; round skipped identically; chain continues | remove the non-empty check |
| `one_parent_leader_not_eligible` | leader with 1 present parent on all nodes → not anchor-eligible → skipped identically within 2 anchors | treat sub-quorum-present as eligible |
| `bad_edge_admitted_everywhere_resolves_nowhere` | vertex citing a round-(r−5) parent: admitted on every node, cited by none, identical sequences | move round-exactness back to ingress |
| `three_test_b4b_fingerprints_unchanged` | `ordering.rs:1655-1808` green | — |
| `slashed_author_body_still_admissible_at_its_round` | after slash at height h, a fetched body from the offender at round < slash round is admitted | check current set |
| `lacker_triggers_fetch_without_committed_hole` | X dropped at N3,N4; WANTED[X] Tier A within 1 tick; admitted ≤ 8 ticks; identical sequences | trigger only in walk_history |
| `self_vertex_lost_everywhere_fetched_from_author` | X_r lost at all receivers; X_{r+1} cites it; Tier B requests **X only**; X_r admitted everywhere; X's leader slots not skipped | remove Tier B |
| `leader_equivocation_A3_B1` / `_A2_B2` | offender leads r; twins split 3:1 and 2:2; **identical `anchor_hash` for r on all nodes** (commit at the > 2/3 twin, or skip) | decide r by `visited` |
| `phantom_proof_does_not_change_anchors` | attacker sends `EQUIV_PROOF` for a never-gossiped twin to one node; sequences unchanged | key any decision on `sys:equiv_seen` |
| `wanted_quotas_hold` | 1 key emits 300 fake-parent vertices; WANTED ≤ 4 entries for that author; honest holes still admitted | remove per-author quota |
| `request_deadline_and_pools` | attacker peers stall; Tier A fetches complete within 4 ticks | single pool / no deadline |
| `sync_settlement_rewalks_blocked` | ChainSync disabled except adoption; blocked candidates re-resolve after adoption with 0 `add_vertex` calls | drop the sync hook |
| `restart_rejoin_without_chainsync` | ChainSync fully disabled; gap > uncommitted cone; node rejoins via tick re-walk + fetch | remove tick re-walk |
| live | 4 validators, 5 % loss all links, 6 h: identical sequences and `anchor_hash` per height, cursor lag ≤ 4 | — |

## 11. Staged rollout

**Stage 1 (Part I).** R1 floor 0 + edge checks; `validator_set_at`; R4; R4′; non-empty parents at ingress; tick re-walk. Gate: rows 1–8 + Part I critique + 48 h identical-sequence burn-in.
**Stage 2.** Serve + shadow rows (bounded). **Stage 3.** WANTED, tiers, quotas, deadlines, fetcher, release. **Stage 4.** E1/E2. Gate for each: its rows + Part II critique. **Stage 5.** TCP slot reservation (I15).

## 12. Deliberately not done; residual risk

- **I11** far-future vertex bytes per author — separate ingress bound; Part II avoids depending on it by not walking or WANTED-ing beyond `current + 2`.
- **I15** — Stage 5.
- Timestamp future-drift is node-local (`dag.rs:980-991`); deferral, retried; BFT-time bound is separate.
- Partition: bounded probing; deferral, never wedge or fork.
- R4 stops a lagging node from proposing until it resolves > 2/3 — intended (Narwhal), and what makes the skip proof sound.
- Pull-induction (Beluga) — bounded per round; reputation out of scope.

## Changelog

- **v3:** split into Part I / Part II with separate critiques. R1 floor → 0 (v2 #1). Round-exactness and membership moved from ingress into walk-edge checks so admission is a pure function of bytes (v2 #5). `validator_set_at(round)` (v2 #6, #9). Walk collects all missing hashes; Tier B on observables (v2 #21). WANTED per-author quota, receiver-tick TTL, no far-future entries, split budgets (v2 #11, #14, #17). Request deadline, per-peer cap, separate pools (v2 #12). Sync settlement shares the release hook; tick re-walk while R4 fails (v2 #13). Equivocation redesigned: twin-aware leader lookup + direct-vote decision keyed on (author, round), no local-row exclusion (v2 #2, #3, #4, #7, #8, #10, #18). Shadow bounded to one compact+parents per (author, round), pruned, written after guards drop (v2 #15, #19). Tests rewritten to pin skip outcomes and to isolate their mutations (v2 #16, #20, #21).
- **v2:** quorum enforcement on the citing side; witnessed fetch; shadow bodies.
- **v1:** initial.
