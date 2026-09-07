# DAG Vertex Synchronization — Design

**Status:** DRAFT v2 — v1 was attacked by six independent critics; 9 holes confirmed (7 CRITICAL). All folded in below. v2 awaits its own critique. NOT approved for implementation.
**Branch / HEAD:** `audit/mainnet-hardening` @ `3208d29`
**Closes:** B3/B4 (audit-119 CRITICAL, open at HEAD, documented at `dag.rs:1090-1115`)
**Inputs:** `docs/research/{A,B,C,D}-*.json`; invariants I1–I16; v1 critique (`scratchpad` task `wf13urqsh`).

Every AINCORE claim cites `file:line` at HEAD `3208d29`. Every reference claim cites its source.

---

## 0. What v1 got wrong, in one paragraph

v1 claimed the malicious never-existing-parent case was neutralised by a citing-side rule alone. The critics showed three things. (1) The rule as written was **one hop** — "every parent of V is in dag" — so the attacker's own next vertex, which cites the poison plus honest vertices, laundered it back into every honest cone. (2) Letting a node propose with fewer than 2/3-stake of cited parents broke the **quorum-intersection premise** of the existing ancestry skip (`ordering.rs:513-517`): a node that lacked a leader vertex could prove a *false* skip while its peers committed that round — a block-level fork. (3) The fetch trigger sat in `walk_history`, which only walks *committed* cones — which the rule guaranteed hole-free — so the trigger was unreachable exactly when fetching mattered, and 50 % of honest stake could be silently excluded from the committed order while the cursor kept advancing. Every one of these is a **quorum** mistake: Narwhal's validity rule 3 requires 2f+1 *certified* parents from round r−1; v1 copied the "cite only what you hold" half and dropped the "and hold ≥ 2/3 of them" half.

## 1. Problem statement

A vertex cites its parents by **bare hash** (`consensus/blockchain/src/lib.rs` `Vertex.parents`). Ingress checks only count ≤ 256 and uniqueness (`dag.rs:1046-1061`). `walk_history` returns `None` on any absent, non-genesis, non-committed hash (`ordering.rs:697-702`); `commit_one_anchor` propagates it with `?` before touching state (`ordering.rs:731-737`).

1. **Malicious never-existing parent.** A validator key plus a 64-hex string suffices (C4/C22). Honest proposers cite `round_index[prev]` verbatim (`dag.rs:529-536`); the poison enters every honest cone; no anchor commits again. Not slashable.
2. **Honest late parent.** Loss is by design: drop-only limiter (`p2p.rs:345-352, 391-398`), 60 s gossipsub dedup (`p2p.rs:119-123`), restarts reload only what was admitted (`dag.rs:211-373`). The only redelivery is a **push** by nodes *below* parent quorum (`dag.rs:621, 881-926`); holders are above quorum and never re-send (C16/C24).

**Root cause (Track A):** Narwhal makes (1) impossible by construction — a parent is citable only with a 2f+1 availability certificate, so ≥ f+1 honest holders exist. AINCORE has no certificate. "Late vs never" is therefore undecidable **at ingress**; every ingress buffer/drop policy was adversary-controlled. This design decides it on the **citing** side, with quorum enforced, and treats being-unable-to-cite as the fetch trigger.

## 2. Vertex state model

Per node, a hash `H` lives in four stores (C2): `dag`/`round_index` (`dag.rs:51-52`), row `vertex:{H}` (`dag.rs:1177`), `committed_set` (bounded 8192, `ordering.rs:90, 474-486`), `consensus:cseq:{round}`.

| State | Definition | Written by |
|---|---|---|
| S0 UNKNOWN | in none | — |
| S1 IN_DAG | `dag`, `round_index`, `vertex:H` written together | `dag.rs:1174-1187` |
| S2 SETTLED | `H ∈ committed_set`; body may be absent (sync adoption) | `ordering.rs:739-748`; `ordering.rs:869-888` via `dag.rs:2852-2884` |
| S3 PRUNED | gone from dag, round_index, `vertex:H` | `dag.rs:2770-2783`; only after a **local** block build, min_round = min(finalized, latest_block_round) − 10 (`dag.rs:1786-1808`) |
| S4 SHADOW *(replaces v1's S4/S6)* | second vertex of an equivocating pair: **full body** stored under `vertex_shadow:{H}`, never in `round_index`, never leader-eligible | this design, §6 |
| S5 WANTED *(new)* | cited by something this node holds, absent locally, tracked for fetch | this design, §5 |

Settled predicate used by commit today: `{dag} ∪ {"genesis"} ∪ committed_set` (C9). §6 extends the *walk* (not the predicate) with S4 shadow bodies.

## 3. Citation discipline with enforced quorum

### R1 — full-history resolution (fixes holes 5, 7)

`V` is **resolved** on this node iff `walk_history(V, floor = last_committed_anchor_round, dag ∪ shadow, committed_set)` returns `Some` — every path from `V` terminates in `"genesis"`, `committed_set`, or a body this node holds. **Not** one hop. Cached per hash in a bounded `HashMap<hash, Resolved{ at_round }>` (≤ 4096 entries, LRU by receiver round); a resolved vertex stays resolved until pruned; an unresolved one is re-walked only when a WANTED hash it depends on is admitted (§5.6). Cost bound: one walk per vertex per dependency arrival; each walk is bounded by the uncommitted cone, as `commit_one_anchor`'s already is (C10).

`try_create_vertex` cites only **resolved** round-(r−1) vertices.

### R4 — cited-parent quorum, proposer side (fixes holes 1, 4)

`parent_quorum_met` (`dag.rs:566-585`) is computed over the **R1-filtered** `parents` list — the list actually cited — exactly as HEAD computes it over `parents`. If the resolved subset's distinct-author stake is not > 2/3 total, **the node does not propose**; it falls into the existing below-quorum branch (`dag.rs:881`), which is now *also* the fetch trigger (§5.1). This restores the B4b premise verbatim: every honest vertex at j+2 cites > 2/3 of the j+1 vertices (`ordering.rs:513-517`).

### R4′ — cited-parent quorum, ingress + commit side (fixes holes 4, 6)

Honest behaviour must not be the only guarantee. Two enforcement points:

- **Ingress:** for `round > 1`, `parents` must be non-empty, and every *locally-resolvable* parent's author must be in the validator set at exactly round r−1 (R2). Stake cannot be fully checked for absent parents at ingress; the load-bearing check is the next one.
- **Commit side (`try_commit`):** a vertex is **anchor-eligible** — as the direct anchor in step 1 (`ordering.rs:558-567`) or as a chain link in step 2 (`ordering.rs:583-597`) — only if the distinct-author stake of its **present** parent bodies is > 2/3 total. An anchor with an absent parent **defers** (returns empty), it is never skipped. A parentless or sub-quorum vertex can therefore never anchor and never prove a skip. This is the check Narwhal performs on certificates; here it is performed on bodies.

**Consequence for the malicious case, traced through HEAD code:** attacker `V_r` cites fake `P`. Honest nodes: R1 walk of `V_r` hits `P` → unresolved → not cited. Attacker `A_{r+1}` cites `[V_r, honest_r…]`: R1 walk of `A_{r+1}` reaches `V_r` → `P` → unresolved → **not cited** (full walk, hole 5/7 closed). The attacker's chain is an island that no honest vertex ever cites. If the attacker leads an even round, its vertex has < 2/3 present-parent stake among honest citers → not anchor-eligible → step 1 scans past it; step 2's skip is only reached for rounds whose chain links all satisfy R4′, so the skip proof's premise holds. No buffer, no fetch, no ingress rejection for this case.

## 4. Ingress rules

Applied after the existing 12 checks (C4). **Reject** on failure:

- **R2 (round exactness).** Every locally-resolvable parent `p ≠ "genesis"` has `p.round == vertex.round − 1`; `"genesis"` only at `round == 1`.
- **R3 (age floor).** `vertex.round − 1 ≥ prune_horizon − 1`, `prune_horizon = min(finalized_round, latest_block_round) − 10` (`dag.rs:1806-1808`).
- **R4′-ingress.** `round > 1 ⇒ parents non-empty`; resolvable parents' authors ∈ validator set.

Unresolvable parents are **not** rejected — undecidable at ingress (§1). They are recorded as WANTED (§5.2) *and* the vertex is admitted.

## 5. Fetching

### 5.1 Trigger — the lacker discovers what it lacks (fixes hole 2)

The trigger is **R1's own walk**, run by `try_create_vertex` on this node's own tick (I14). When the walk of a candidate parent `C` fails at missing hash `H`: `WANTED[H].citers ∪= {C.author}` and `WANTED[H].first_seen = current_round`. This fires precisely on the node that lacks data, whether or not any committed cone ever contains `H`. `walk_history`'s hole in `try_commit` is kept as a **secondary** trigger (it surfaces holes below the cursor after sync adoption). The v1 trigger alone was unreachable.

### 5.2 Fetch-worthiness — witnesses of holding (fixes holes 8, 9)

`WANTED[H].citers` are **transitive** witnesses: every author whose vertex's R1 walk reached `H`. Under R1 an honest author holds everything its walk resolved, so each citer is a holder-claim. Two admission tiers:

- **Tier A (witnessed):** distinct-citer stake > 1/3 total ⇒ ≥ 1 honest holder guaranteed (Byzantine ≤ 1/3) — fetch at full rate. (Stake-weighted Beluga ImPoA.)
- **Tier B (author-claimed):** `H` is cited by a vertex whose author is `H.author` at round `H.round + 1` — the author signed a claim to hold its own vertex. Fetch **from that author only**, bounded to **one WANTED slot per (author, round)** so a Byzantine author citing fake "own" hashes occupies one slot per round and induces requests only to itself. This covers the self-vertex-lost-at-every-receiver case (hole 9).
- Below both tiers: **probe** at the floor rate (one request per 16 ticks, to citers only), never hard-refuse — a low-citation hash can still be real (hole 8). A fake hash from one key sits in one Tier-B slot and costs one request per 16 ticks to the attacker itself.

### 5.3 Messages — direct TCP only (unchanged from v1)

Gossipsub cannot unicast (B10); `send_message` never reads a reply (B9). Model on `DA_SHARD` (`da/src/lib.rs:707-757`) and `SYNC_REQ` (`sync/src/lib.rs:625-699`, `network/src/lib.rs:375-377`).

```
VERTEX_REQ:{ "hashes": [String; ≤ 32], "requester_id": String }
VERTEX_RESP:{ "vertices": [Vertex], "unknown": [String] }
```

Server in `chain_sync` (B24): per hash one `storage.get("vertex:{H}")` **or** `vertex_shadow:{H}` (§6), no consensus lock; trims reply to ≤ 1 MiB (`network/src/lib.rs:239`); echoes unknowns. Wired at `main.rs:788-798`. Client: own tokio task with `Arc<RwLock<DagConsensus>>`; `secure_connect(peer_ip, port, "__vsync__", 0, Some(peer_id), …)`; one frame out, one in; never via `tx_in` (B13). Each vertex is delivered as `DAG_VERTEX:{json}` to `handle_message` under a fresh write lock — the single gate (C25). Response bytes ≠ original broadcast, so no dedup suppression (C17).

### 5.4 Request policy

- **Whom:** `WANTED[H].citers` first (holders by R1), then validators with a persisted `peer_ip` (`sync/src/lib.rs:625-632`). Tier B: the author only.
- **Fan-out:** ≤ 2 in flight per hash; cancel on first valid (Narwhal §4.1). Global ≤ 16.
- **Batching:** ≤ 32 hashes/frame (the 100 msg/s connection cutoff, B7).
- **Backoff:** attempt k waits `min(2ᵏ, 16)` **receiver ticks** (I3).
- **Exit from WANTED:** `H` admitted (S1/S4), or settled (S2), or no vertex in `dag` still depends on it, or `H.round < prune_horizon` (R3).

### 5.5 Bounds

| Quantity | Bound | Sender cannot inflate because |
|---|---|---|
| WANTED entries | ≤ 256 Tier A/probe + ≤ 1 Tier B per (author, round) within the last 16 rounds | Tier A needs > 1/3 stake; Tier B is keyed per validator key per round |
| citers per entry | ≤ n (bounded `BTreeSet<author>`) | authors ∈ validator set |
| resolved-cache | ≤ 4096 entries, LRU by receiver round | receiver-owned |
| in flight | ≤ 2 per hash, ≤ 16 total | fixed |
| frames | req < 4 KiB; resp ≤ 1 MiB | fixed |
| admitted bytes | each vertex re-enters the 768 KiB gate (`dag.rs:32`) | existing |
| server work | ≤ 32 point reads, no lock | fixed |

Full WANTED ⇒ new holes logged and dropped; the node stays below parent quorum (R4) and keeps proposing nothing — a liveness degradation only under > 256 simultaneous holes, never a wedge and never a fork.

### 5.6 Release on arrival

When `H` is admitted (any path), remove `WANTED[H]` and invalidate the resolved-cache entries of vertices that recorded `H` as their blocking hash (stored on the WANTED entry: `blocked: BTreeSet<vertex_hash>`, bounded by the cache). Their next R1 evaluation re-walks them. This is O(dependents of H), never a drain of anything (I7). Sync adoption (`reload_chain_tip`) removes every hash now in `committed_set` from WANTED by lookup (I8).

## 6. Equivocation — shadow bodies, no forked walk (fixes hole 3)

v1 made an equivocation *proof* a settled state; `to_compact_proof` strips `parents` (`blockchain/src/lib.rs:454-459`), so nodes holding twin A could not walk below B and vice-versa — the two sides committed different subtrees. v2:

- On detection (`dag.rs:1143-1168`): keep slash + gossiped compact proof **unchanged**; additionally persist the **full body** of the rejected twin under `vertex_shadow:{hash}`. Shadow rows are never inserted into `round_index`, so `leader_vertex_hash` (`ordering.rs:641-643`, `find_map` in arrival order) is unaffected — admit-both is still rejected.
- `walk_history` and `find_causal_history` read `dag ∪ shadow`. A citation of either twin resolves on every node once both bodies are present (the fetch, §5, is what brings the second one).
- **Deterministic exclusion rule:** every vertex authored by an offender at round ≥ its equivocation round is excluded from the committed *sequence* on every node (its citers still resolve through it for walking purposes). Determinism follows because the exclusion keys on `(offender, round)`, which the gossiped proof fixes identically everywhere; before a node has the proof, its anchor **defers** (R4′ commit-side: the twin's body is absent → not anchor-eligible), it does not skip.

## 7. Interaction table

| Situation | v2 behaviour | Invariant |
|---|---|---|
| Asymmetric equivocation (A→N1,N2; B→N3,N4) | N1's R1 walk of N3's vertex hits B → WANTED[B] Tier A (citers N3,N4 = 1/2 > 1/3). Fetch from N3. `add_vertex(B)` → equivocation branch → slash, proof, **shadow body**. Walk resolves through shadow; offender subtree excluded deterministically. | I9 |
| `prune_dag` deletes `vertex:H` | server answers unknown; R3 keeps honest citations above horizon; entry exits WANTED when below horizon | I3 |
| `committed_set` window eviction | body still in `dag` ⇒ resolvable; both evicted and pruned ⇒ below horizon ⇒ R3 | I3 |
| Sync adoption settles hashes w/o bodies | preserved; WANTED swept by lookup; no replay | I7, I8, I16 |
| Boot recovery loops | after load: R1-walk every loaded vertex; misses → WANTED with the loaded citers as witnesses | I10 |
| Re-gossip else-branch | unchanged; now entered *by design* whenever R4 fails, and it coincides with fetching | I12 |
| Gossip rate limiter | drop-only, untouched; VERTEX_* never traverse gossipsub | I12, I13 |
| Observer node | serves `VERTEX_REQ` (deepest unpruned history, C27); no fetch client | — |
| Validator restart after long gap | R1 blocks citing what it lacks; R4 stops it proposing; WANTED fills from the boot walk and from R1 misses; fetch + sync adoption bring it back; it never proposes a sub-quorum vertex | I10 |
| Attacker withholds its own valid vertex from a subset | the subset's R1 walks fail at it → Tier A (honest citers > 1/3) or Tier B (author cited it) → fetched from citers/author. Under R4 the subset does not propose narrow vertices meanwhile, so no false skip | I2 |
| Attacker floods `VERTEX_REQ` | ≤ 32 point reads/request, no lock, existing connection caps (B7) | I15 partial |
| Forged `VERTEX_RESP` | full ingress gate (`dag.rs:999-1088`); rejected; next peer | I6 |

## 8. Lock discipline (unchanged from v1)

No new lock; no new nesting. R1 walks run in `try_create_vertex` under the locks it already takes (`dag.rs:529-536` region), producing a WANTED delta applied after the guards drop. The fetcher takes `consensus.write()` per received vertex, holds nothing across `.await`. Server: storage only. `reload_chain_tip` sweep: lookup only, no re-entry (I16).

## 9. Invariant checklist

| Inv | Satisfied by |
|---|---|
| I1 | R1 full walk + R4/R4′ quorum enforcement + existing deterministic skip whose premise now holds |
| I2 | trigger is the lacker's own R1 walk (§5.1); pull from citers/author (§5.4) |
| I3 | backoff/eviction on receiver ticks and prune horizon only |
| I4 | no bodies held; WANTED + cache < 2 MiB at n = 64 |
| I5 | WANTED and cache keyed by hash; dedup at `dag.rs:1082` |
| I6 | single ingress gate for fetched vertices |
| I7 | release is O(dependents) by index; no drain |
| I8 | sync sweep by lookup |
| I9 | shadow bodies + deterministic offender exclusion (§6) |
| I10 | boot walk + R1/R4 + sync adoption |
| I11 | **not addressed** (separate bound) |
| I12 | no ban path |
| I13 | all maps bounded |
| I14 | fetch scheduling on the fetcher's own tick; trigger on the proposer's own tick |
| I15 | server cost bounded; TCP slot reservation is Stage 5 |
| I16 | §8 |

## 10. Test plan — each test names the mutation that must fail it

| Test | Asserts | Mutation |
|---|---|---|
| `poison_parent_never_enters_honest_cone` | attacker cites fake P; attacker's r+1 child cites [V, honest]; honest nodes commit r+2, r+4; WANTED never holds P in Tier A | make R1 one-hop |
| `sub_quorum_cited_parents_do_not_propose` | node lacking the r leader vertex, leading r+2, **defers** (no anchor ≥ r) and enters the below-quorum branch | compute parent_quorum_met over present instead of cited |
| `parentless_leader_cannot_anchor` | leader emits parents=[]; no node ever commits or skips via it; all defer identically | remove commit-side R4′ |
| `lacker_triggers_fetch_without_committed_hole` | X dropped at N3,N4 only; both record WANTED[X] Tier A within 1 tick and admit X within ≤ 8 ticks; committed sequences identical on all four | move the trigger back to walk_history only |
| `self_vertex_lost_everywhere_is_fetched_from_author` | X dropped at every receiver; Tier B fires; X admitted on all nodes; author's leader slots not skipped | remove Tier B |
| `asymmetric_equivocation_converges` | A→{N1,N2}, B→{N3,N4}; all four hold both bodies (shadow + live), identical committed sequence, offender excluded | drop shadow storage (compact-proof-only) |
| `three_test_b4b_fingerprints_unchanged` | `ordering.rs:1655-1808` green | — |
| `sync_adoption_sweeps_wanted_without_replay` | `add_vertex` invocations during adoption == 0 | reintroduce drain |
| `restart_after_60_rounds_rejoins` | proposes a > 2/3-cited vertex within 32 ticks | remove boot walk |
| `wanted_bounds_hold_under_attacker` | 1 Byzantine key emits 10 000 fake-parent vertices; WANTED ≤ 256 + 16 Tier B; requests to honest peers == 0 | remove per-(author,round) cap |
| live | 4 validators, 5 % extra loss all links, 6 h: 0 fork, identical sequences, cursor lag ≤ 4 rounds | — |

## 11. Staged rollout

**Stage 1 — Citation discipline + quorum.** R1 (full walk, cached), R4 (proposer), R4′ (ingress + commit-side), R2/R3. `dag.rs` + `ordering.rs`. No messages, no WANTED. Closes the malicious wedge and the false-skip fork. Exit: rows 1–3 and 7 of §10 green; adversarial gate clean; 48 h burn-in with identical sequences on all nodes (not merely "no stall").
**Stage 2 — Serve.** `VERTEX_REQ/RESP` server + shadow rows. Exit: trim/unknown tests; no consensus lock on serve.
**Stage 3 — Fetch.** WANTED, Tier A/B, fetcher task, release-on-arrival, boot walk. Exit: rows 4–5, 8–10; correlated-loss cluster test.
**Stage 4 — Equivocation.** Shadow walk + deterministic exclusion. Exit: row 6.
**Stage 5 (separate) — Inbound TCP reservation** (I15).

## 12. Deliberately not done; residual risk

- **I11** far-future storage: separate per-author byte bound at ingress.
- **I15** TCP slot exhaustion: Stage 5.
- **Timestamp drift is node-local** (`dag.rs:980-991`): a fetched vertex rejected for drift stays WANTED and retries; anchors defer. BFT-time bound is separate work.
- **Partition:** WANTED probes at floor rate; bounded; deferral, never wedge or fork.
- **R4 stops a lagging node from proposing** until it resolves > 2/3 of the previous round — this is the *intended* Narwhal behaviour and is what makes the skip proof sound.
- **Pull-induction** (Beluga): one bounded fetch per withheld vertex per round; reputation is out of scope.

## Changelog

- **v2:** R1 redefined as a full cached walk (holes 5, 7). R4 — `parent_quorum_met` over cited parents, no proposal below quorum (holes 1, 4). R4′ — ingress non-empty/in-set parents and commit-side anchor eligibility on present-parent stake (holes 4, 6). Trigger moved to the proposer's R1 walk, `walk_history` secondary (hole 2). Transitive citers as witnesses; Tier B author-claim; probe instead of hard refuse (holes 8, 9). S6 replaced by shadow bodies + deterministic offender exclusion (hole 3). Stage 1 exit now requires identical sequences, not merely no stall.
- **v1:** initial draft from tracks A–D.
