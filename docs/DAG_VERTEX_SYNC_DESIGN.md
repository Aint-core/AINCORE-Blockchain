# DAG Vertex Synchronization — Design

**Status:** DRAFT v1 — awaiting independent adversarial critique. NOT approved for implementation.
**Branch / HEAD:** `audit/mainnet-hardening` @ `3208d29`
**Closes:** B3/B4 (audit-119 CRITICAL, open at HEAD, documented at `dag.rs:1090-1115`)
**Inputs:** four research tracks (`scratchpad/research/{A,B,C,D}-*.json`); 16 invariants I1–I16 extracted from four failed review rounds.

Every AINCORE claim below cites `file:line` at HEAD `3208d29`. Every reference claim cites its source.

---

## 1. Problem statement

A vertex cites its parents by **bare hash** (`consensus/blockchain/src/lib.rs` `Vertex.parents: Vec<String>`). Nothing at ingress checks that a cited hash exists (`dag.rs:1046-1061` — only count ≤ 256 and uniqueness). The commit path is fail-closed on an absent hash: `walk_history` returns `None` the moment it pops a hash that is not in `dag`, not `"genesis"`, and not in `committed_set` (`ordering.rs:697-702`), and `commit_one_anchor` propagates that with `?` before touching any state (`ordering.rs:731-737`).

Two facts pull in opposite directions:

1. **Malicious never-existing parent.** A validator key plus a 64-hex string that hashes nothing is sufficient (Track C, C4/C22). Honest proposers cite `round_index[prev]` verbatim (`dag.rs:529-536`), so one admitted poison vertex enters every honest node's causal cone, and no anchor commits again. Not slashable. Unrecoverable without hand-purging RocksDB.
2. **Honest late parent.** Ordinary loss is *by design*: the gossip limiter drops silently (`p2p.rs:345-352, 391-398`), gossipsub dedups byte-identical re-sends for 60 s (`p2p.rs:119-123`), and restarts reload only what the node already admitted (`dag.rs:211-373`). Today the only redelivery is a **push** of `dag.values()` that runs only while the *sender* is below parent quorum (`dag.rs:621, 881-926`) — so the nodes that hold a missing vertex never re-send it (C16, C24).

**Why four attempts failed (Track A, Narwhal §3.1):** Narwhal makes case (1) impossible by construction — a parent may only be cited if it carries a 2f+1 *certificate of availability*, which guarantees ≥ f+1 honest holders. AINCORE has no certificate. Without one, "late" versus "never" is **undecidable at ingress**, and every buffer or drop policy is a heuristic the adversary controls. Both prior designs put the decision at ingress. This design does not.

## 2. Vertex state model

Per node, a hash `H` is a function of four stores (C2): `dag`/`round_index` (`dag.rs:51-52`), row `vertex:{H}` (`dag.rs:1177`), the ordering engine's bounded `committed_set` (`ordering.rs:90, 474-486`), and per-round `consensus:cseq:{round}` rows.

| State | Definition | Written by |
|---|---|---|
| S0 UNKNOWN | in none of the stores | — |
| S1 IN_DAG | `dag[H]`, `round_index[H.round] ∋ H`, `vertex:H` — written together | `dag.rs:1174-1187` |
| S2 SETTLED | `H ∈ committed_set`; body may be absent (sync adoption) | `ordering.rs:739-748` (local), `ordering.rs:869-888` via `dag.rs:2852-2884` (sync) |
| S3 PRUNED | removed from dag, round_index and `vertex:H` | `dag.rs:2770-2783`, only after a **local** block build at height%10==0 and current_round>50, min_round = min(finalized, latest_block_round) − 10 (`dag.rs:1786-1808`) |
| S4 DROPPED_EQUIV | second vertex of an equivocating pair: rejected before persist, compact proof stored under `sys:equiv_seen` and gossiped | `dag.rs:1143-1168` |
| **S5 WANTED** *(new)* | cited by an admitted vertex, absent locally, qualifies for fetch (§5) | this design |

Settled predicate used by commit today: `{dag} ∪ {"genesis"} ∪ committed_set` (C9). §6 extends it deterministically.

Two transitions matter most: S2 is reachable **without a body** via `adopt_synced_anchor` — this is how sync heals a follower's cursor today (C6, C20) and is preserved unchanged. A hash both S3-pruned and evicted from the 8192-entry `committed_set` window is indistinguishable from S0 (C7); §4 bounds parent age so honest vertices never cite that old.

## 3. The new formulation: resolve the adversary on the citing side

**Rule R1 (citation discipline).** `try_create_vertex` cites a round-(r−1) vertex `V` only if `V` is *history-resolved*: every parent of `V` is `"genesis"`, in `dag`, or in `committed_set`, evaluated with the same predicate `walk_history` uses (C9). Vertices that fail R1 remain in `dag` (admitted, persisted, counted for `quorum_round`/`parent_quorum_met`) but are **not citable by this node**.

This is Narwhal's own rule — "reference only blocks whose causal history you hold" (Track A, §3.1 validity rule 3) — applied without certificates.

**Consequence for the malicious case, traced through HEAD code (C22, C11, C13, C28):**

- Attacker vertex `V` at round r, `parents = [P]`, `P` fake. `V` passes all 12 ingress checks and is S1 on every node.
- Round r+1: honest proposers evaluate R1 on `V`; `P` is unresolved; **they do not cite `V`**. `V` is cited only by the attacker's own r+1 vertex `A₁`, which is itself unresolved (transitively), so honest r+2 proposers do not cite `A₁` either. The attacker's chain is an island.
- Anchor at r (if even) commits: its cone is below `V`.
- Anchor at r+2: an honest leader's vertex cites only R1-resolved r+1 vertices; `walk_history` from it never reaches `A₁` or `V`. Commits.
- If the **attacker is leader** at r+2: its anchor is unresolved; no honest r+3 vertex cites it; `direct_quorum_met` (`ordering.rs:650-676`, counts distinct-author stake among r+3 vertices whose parents contain the anchor) fails; step 1 of `try_commit` skips it and scans on (`ordering.rs:554-567`). This is exactly the pinned behaviour of `test_b4b_missing_leader_is_skipped_deterministically` (`ordering.rs:1655-1705`): *a leader nobody cites is skipped deterministically.*

No buffer, no fetch, no TTL, no new state — the adversary's vertex is neutralised by the discipline of honest citers, using skip semantics that already exist and are already tested. **I1 is satisfied by R1 plus the existing skip, not by an ingress gate.**

**What R1 costs.** A node that lacks an *honest* vertex `X` will not cite `X`'s citers until `X` arrives — its proposals are temporarily narrower than its peers'. `parent_quorum_met` (`dag.rs:566-585`) is stake-weighted over *present* vertices and is unaffected. This is the honest-late case, handled by §5.

## 4. Ingress: cheap deterministic bounds only

Add to `add_vertex`, after the existing 12 checks (C4), **rejecting** on failure:

- **R2 (round exactness).** For every parent `p ≠ "genesis"` that IS resolvable locally, `p.round == vertex.round − 1`. `"genesis"` is permitted only when `vertex.round == 1`. Unresolvable parents are **not** rejected (undecidable — §1); they are recorded as WANTED (§5).
- **R3 (parent age floor).** `vertex.round − 1 ≥ prune_horizon − 1`, where `prune_horizon = min(finalized_round, latest_block_round) − 10` (`dag.rs:1806-1808`). Prevents citing hashes that every peer has legitimately pruned (C7/C21 case (ii)).

R2 follows Narwhal (validity rule 3, "certificates for … blocks of round r−1") and Mysticeti (§II-C, "2f+1 distinct hashes of blocks from the previous round"). It does **not** reject a vertex for an absent parent — that is the mistake both prior attempts made.

## 5. Fetching honest late vertices

### 5.1 Trigger

`walk_history` (`ordering.rs:683-714`) already knows the exact missing hash and the child that cited it (B18). Change its hole return from `None` to `Err(Hole { hash, cited_by })`; `commit_one_anchor`/`try_commit` collect holes into the return value; `add_vertex`'s commit loop (`dag.rs:1273-1295`) pushes them onto a new bounded channel `wanted_tx: Option<mpsc::Sender<Wanted>>` beside `p2p_tx` (`dag.rs:78`, B24). The send happens **after** the ordering and dag locks are released (I16).

### 5.2 Implicit Proof-of-Availability (ImPoA), stake-weighted

A hash `H` is **fetch-worthy** iff the set of *distinct authors* of admitted vertices citing `H` holds **stake > total_stake / 3** (Beluga ImPoA — "referenced by at least f+1 blocks from subsequent rounds" — restated in AINCORE's stake terms because quorum is `signed*3 > total*2`, `qc.rs:194-196`).

- > 1/3 stake citing ⇒ at least one **honest** citer (Byzantine stake ≤ 1/3) ⇒ under R1 an honest citer holds `H` ⇒ `H` exists and is obtainable.
- A fake hash is cited only by Byzantine stake ⇒ never fetch-worthy ⇒ **never fetched, never buffered, never chased.** The adversary cannot induce a single request.

Citation counts are derived from `dag` at trigger time (the citers are admitted S1 vertices); no new store is consulted. The WANTED set is the only new state: `HashMap<hash, WantedEntry{ citers: BTreeSet<author>, first_seen_tick, attempts, in_flight: u8 }>`, keyed by hash (idempotent, I5).

### 5.3 Messages — direct TCP only

Gossipsub cannot unicast and has no request-response behaviour (B10); `send_message` is fire-and-forget and never reads a reply (B9). The reply-on-same-socket pattern exists and is proven: `DA_SHARD` (`da/src/lib.rs:707-757`, B23) and `SYNC_REQ` (`sync/src/lib.rs:625-699`, `common/network/src/lib.rs:375-377`, B1–B3).

```
VERTEX_REQ:{ "hashes": [String; ≤ 32], "requester_id": String }
VERTEX_RESP:{ "vertices": [Vertex], "unknown": [String] }
```

- Server (in `chain_sync`, B24): for each hash, one `storage.get("vertex:{hash}")` (`dag.rs:1177`, B14) — **no consensus lock**; echoes unknowns; truncates the reply to ≤ 1 MiB (inbound frame cap `network/src/lib.rs:239`; B7) and reports the remainder as unknown so the client re-requests. Wired at `main.rs:788-798` beside `SYNC_REQ` (B22, B27-W2).
- Client (own tokio task spawned in `main.rs`, holds `Arc<RwLock<DagConsensus>>`, B24/B25): `secure_connect(peer_ip, port, "__vsync__", 0, Some(peer_id), ephemeral_key)` — bound to the validator being asked (B6) — send one frame, read one frame, close. Never through `tx_in` (capacity 64, the liveness bottleneck — B13).
- Every received vertex is delivered as `DAG_VERTEX:{json}` to `handle_message` under a fresh write lock (`dag.rs:2557-2587`, B21) — the **same gate**, never a side door (C25; the reverted buffer's re-entrancy hole came from bypassing it). Its admission fires the existing commit retry (C12) — no extra trigger needed.
- `VERTEX_RESP` bytes differ from the original `DAG_VERTEX` broadcast, so the 60 s gossipsub dedup cannot suppress them (C17). Responses are never re-published.

### 5.4 Request policy

- **Whom.** Citers first — authors in `WantedEntry.citers`, which under R1 demonstrably hold `H` if honest (Narwhal §4.1: "request … from validators that signed the certificates"; B26). Then every other validator with a persisted `peer_ip` (B8), in `sys:validators` order. Peers without `peer_ip` are skipped exactly as `sync_from_peers` does (`sync/src/lib.rs:625-632`).
- **Fan-out.** ≤ 2 in flight per hash (Narwhal §4.1: "only O(1) requests for each block are active"); cancel the other on first valid response. Global in-flight ≤ 16.
- **Batching.** Up to 32 hashes per request, one frame — a frame per hash would trip the server's 100 msg/s connection cutoff (`network/src/lib.rs:207-233`, B7).
- **Backoff.** Attempt k waits `min(2ᵏ, 16)` **consensus ticks** — measured on the receiver's own clock, never on `vertex.round` (I3). Tick = `AINCORE_CONSENSUS_TICK_MS`, default 3000 (C16).
- **Give-up.** None for a fetch-worthy hash: ImPoA guarantees an honest holder, so persistent failure means partition, and the entry stays at the floor rate (one probe per 16 ticks). Entries leave WANTED when (a) `H` becomes S1/S2/S6, or (b) `H` is no longer cited by any vertex in `dag` (its citers were pruned — C8), or (c) `H.round < prune_horizon` (R3).

### 5.5 Bounds (I3, I4, I11, I13)

| Quantity | Bound | Why the adversary cannot inflate it |
|---|---|---|
| WANTED entries | ≤ 256 (= `MAX_PARENTS`) | entry requires > 1/3 honest-including citing stake |
| in-flight requests | ≤ 2 per hash, ≤ 16 total | fixed |
| request frame | ≤ 32 hashes, < 4 KiB | fixed |
| response frame | ≤ 1 MiB (server-trimmed) | fixed |
| bytes admitted per response | each vertex re-enters `handle_message` under the existing `MAX_VERTEX_BYTES` = 768 KiB gate (`dag.rs:32`) | existing |
| memory of WANTED | 256 × (64 B hash + ≤ n×64 B citers + 16 B) < 1.1 MiB at n = 64 | fixed |
| server work per request | ≤ 32 RocksDB point reads, no lock | fixed |
| age | entries keyed on receiver ticks; eviction on R3 horizon | receiver-owned |

If WANTED is full, new holes are logged and dropped; the anchor stays deferred (C28 semantics) and sync adoption still heals it if any validator commits (C6). This is a liveness degradation only under > 256 simultaneous honest holes, i.e. mass loss — and even then no wedge.

## 6. Interaction table

| Situation | What happens under this design | Invariant |
|---|---|---|
| **Equivocation, asymmetric delivery** (`dag.rs:1143-1168`): N1,N2 hold A; N3,N4 hold B; each side cites its own | N1 sees N3's vertex citing B; B unresolved → not cited by N1 (R1). B is cited by N3+N4 = 2/4 stake > 1/3 ⇒ fetch-worthy. N1 fetches B from N3 (a citer), `add_vertex(B)` hits the equivocation branch: slash applied, compact proofs of A and B written to `sys:equiv_seen`, proof gossiped (`dag.rs:1143-1168, 2287-2290`). **The fetch is what surfaces the equivocation.** `walk_history`'s settled predicate is extended: a hash whose compact proof is in `sys:equiv_seen` is **settled** (new state S6). Proofs are self-authenticating and gossiped, so all nodes converge; until then the anchor defers (C28), never wedges. `leader_vertex_hash` (`ordering.rs:641-643`, `find_map` — arrival-order dependent) is **unchanged**: only the first-admitted vertex is ever in `dag`, so no fork. Admit-both (Mysticeti §II-C) is explicitly rejected for AINCORE because of that `find_map`. | I9 |
| `prune_dag` deletes `vertex:H` (`dag.rs:2770-2783`) | Server answers `unknown`; client tries the next peer. R3 ensures honest vertices never cite below the horizon. If every peer has pruned, the hash is < horizon on the requester too and leaves WANTED (5.4c); sync adoption covers the cursor. | I3 |
| `committed_set` window eviction (8192, `ordering.rs:90`) | A hash can be evicted while still in `dag` — it is then resolvable via `dag`. Both evicted **and** pruned ⇒ below horizon ⇒ R3. | I3 |
| `adopt_synced_anchor` settles hashes without bodies (`ordering.rs:869-888`) | Preserved. After adoption, `reload_chain_tip` drops from WANTED every hash now in `committed_set` — O(newly settled), by lookup, **no re-validation of anything** (I7). No re-entry into `add_vertex`. | I7, I8, I16 |
| `reload_chain_tip` round cap (`dag.rs:2998-3011`) | Unchanged. | — |
| Boot recovery loops (`dag.rs:211-373`) | After loading, one pass: every parent of every loaded vertex that is not `"genesis"`, in `dag`, or in `committed_set` → WANTED candidate; ImPoA evaluated from the loaded citers. A hole persisted before restart is therefore re-requested on boot (fixes I10 half of the restart case; the other half is the catch-up floor, C19). | I10 |
| Re-gossip else-branch (`dag.rs:881-926`) | Unchanged; remains a push-side complement. Its 4 rounds × n authors burst is drop-only at the limiter (I12) and never causes a ban. | I12 |
| Gossip rate limiter (`p2p.rs:255-398`) | Drop-only, unchanged. `VERTEX_REQ/RESP` never traverse gossipsub, so they neither consume nor are throttled by the 100/s publisher budget (B11). | I12, I13 |
| Non-validator observer | Serves `VERTEX_REQ` (deepest unpruned history — C27). Runs no fetch client (needs no commit). | — |
| Validator restarting after a long gap | R1 keeps it from citing what it cannot resolve; holes surface on its first `try_commit`; boot scan pre-populates WANTED; sync adoption advances its cursor; fetch fills bodies it needs to propose. It rejoins without already holding recent vertices. | I10 |
| Attacker floods `VERTEX_REQ` | Server cost ≤ 32 point reads per request, no lock, under the existing per-connection 100 msg/s cutoff and 100/60 connection caps (B7). Unauthenticated, as `SYNC_REQ` is (B6). | I15 (partial — see §11) |
| Attacker returns a forged/wrong vertex | It goes through `add_vertex`: hash recomputed, author signature verified against the on-chain key, author in set (`dag.rs:999-1088`). Rejected; the request stays in flight to the next peer. | I6 |

## 7. Lock discipline

Existing order: `try_commit` holds `ordering_engine` then reads `dag`/`round_index` under their own locks (`dag.rs:1273-1295`). This design adds **no** new lock and **no** new lock nesting:

- Hole detection happens inside `walk_history`, already under the existing locks; the hole list is *returned*, and the channel send occurs in `add_vertex` **after** the commit loop's guards drop.
- The fetcher task takes `consensus.write()` once per received vertex to call `handle_message`, holding nothing else. It never holds the write lock across an `await`.
- The server path takes **no** consensus lock (storage reads only).
- `reload_chain_tip`'s WANTED cleanup is a lookup-only sweep under the lock it already holds; it calls nothing that re-enters ingress (the reverted `retry_parked_vertices` did — I16).

Proof sketch: the only new code that runs under a consensus lock is (a) pure computation inside `walk_history`, (b) a `HashMap::remove` sweep. Neither acquires a lock nor calls back into `DagConsensus`. Every `add_vertex` entry from the fetcher is a fresh top-level acquisition.

## 8. Invariant checklist

| Inv | Satisfied by |
|---|---|
| I1 | R1 + existing deterministic leader skip (§3). Poison never enters an honest cone. |
| I2 | §5.3: pull from citers/holders over TCP; nothing requires the lacker to hold data. |
| I3 | Backoff and eviction keyed on receiver ticks and the local prune horizon; `vertex.round` is never an eviction key. |
| I4 | No vertex bodies are held; WANTED holds hashes + author sets, < 1.1 MiB. |
| I5 | WANTED keyed by hash; fetched vertices dedup at `add_vertex` (`dag.rs:1082`). |
| I6 | Fetched vertices use the single ingress gate; no admission flag is introduced. |
| I7 | Sync-settlement cleanup is a per-hash lookup; no replay, no re-verification. |
| I8 | `reload_chain_tip` sweep removes settled hashes from WANTED. |
| I9 | Fetch surfaces the second vertex; `sys:equiv_seen` proofs become settled (S6). |
| I10 | Boot hole scan + R1 + catch-up floor. |
| I11 | **Not addressed** — far-future storage bound is orthogonal (see §11). |
| I12 | No ban path exists at HEAD; this design adds none. |
| I13 | WANTED bounded at 256; in-flight bounded; no remote-keyed unbounded map. |
| I14 | Fetch scheduling runs on the fetcher task's own tick, independent of inbound traffic. |
| I15 | **Partially** — server cost is bounded, but inbound TCP slot reservation is out of scope (§11). |
| I16 | §7. |

## 9. Test plan

Each test names the mutation that must make it fail.

| Invariant | Test | Mutation that must fail it |
|---|---|---|
| I1 | `never_existing_parent_does_not_wedge_honest_nodes`: 4 validators, attacker cites fake `P`; assert honest nodes commit anchors r+2, r+4 and `WANTED` never contains `P`. | disable R1 in `try_create_vertex` |
| I1 | C28's three `test_b4b_*` fingerprint tests remain green unchanged. | — (regression) |
| R2 | `parent_at_wrong_round_rejected` | remove the round-exactness check |
| ImPoA | `hash_cited_by_one_third_stake_is_not_fetched` / `…by_more_than_one_third_is_fetched` | flip the stake comparison |
| I2/I5 | `correlated_loss_heals_by_fetch`: drop honest `X` on ALL nodes' ingress once; assert every node's cursor advances past X's round within ≤ 16 ticks and `X` is admitted exactly once per node. | disable the fetcher |
| I3 | `backoff_uses_receiver_ticks`: vertex.round = current+9000 citing fake hash; assert WANTED empty (not fetch-worthy) and no request emitted. | key backoff on vertex.round |
| I9 | `asymmetric_equivocation_is_surfaced_and_slashed`: A→{N1,N2}, B→{N3,N4}; assert all four hold the equivocation proof and commit identical sequences. | remove S6 from the settled predicate |
| I7/I8 | `sync_adoption_clears_wanted_without_replay`: count `add_vertex` invocations during adoption == 0. | reintroduce a drain-and-replay |
| I10 | `restart_after_60_rounds_rejoins`: kill a validator for 60 rounds; assert it proposes a cited vertex within 32 ticks of return. | remove the boot hole scan |
| I16 | `fetcher_never_holds_lock_across_await` (static: `clippy::await_holding_lock` enforced in CI for `consensus` and `node`). | — |
| server | `vertex_req_response_trimmed_to_1mib` and `server_reads_storage_only` (no `consensus` lock acquired — assert via a lock-count probe in tests). | — |
| live | 4-node cluster: inject 5 % additional loss via `tc netem` on ALL links for 6 hours; assert 0 fork, cursor lag ≤ 4 rounds, WANTED high-water ≤ 8. | — |

## 10. Staged rollout

Each stage is gate-able alone and useful alone.

**Stage 1 — Citation discipline (no new messages).** R1 in `try_create_vertex`; R2/R3 at ingress. Closes the malicious wedge outright via existing skip semantics. Touches `dag.rs` only. Exit: I1 tests + C28 regression green; adversarial gate clean; 48 h burn-in with no cursor stall.

**Stage 2 — Serve.** `VERTEX_REQ/RESP` structs, server arm in `chain_sync` + `main.rs`, 1 MiB trim. No client. Exit: unit tests for trimming/unknowns; server never takes the consensus lock.

**Stage 3 — Fetch.** `walk_history` hole surfacing, WANTED set, ImPoA, fetcher task, backoff, bounds, sync-adoption sweep. Exit: I2/I3/I5/I7/I8 tests; correlated-loss cluster test; adversarial gate clean.

**Stage 4 — Equivocation settlement + boot scan.** S6 in the settled predicate; boot WANTED scan. Exit: I9/I10 tests; asymmetric-equivocation cluster test.

**Stage 5 (separate work) — Inbound TCP reservation** for I15.

## 11. Deliberately not done; residual risk

- **Far-future vertex storage (I11)** — `MAX_ROUND_JUMP` = 10 000 × 768 KiB per author is a separate bound (per-author bytes per window at ingress). Not a sync problem; tracked separately.
- **Inbound TCP slot exhaustion (I15)** — Stage 5.
- **Timestamp future-drift is node-local** (`dag.rs:980-991`, C25): the same signed vertex can be admissible on one node and not on another. A fetched vertex rejected for drift stays WANTED and is re-fetched after backoff; the anchor defers. Full fix (BFT-time bound instead of wall clock) is separate.
- **Partition with no honest holder reachable** — WANTED entries probe at the floor rate indefinitely; bounded at 256 entries; no wedge, only deferral until the partition heals.
- **R1 narrows a lagging node's proposals** until it catches up. Accepted: correctness of the causal cone over breadth of citation.
- **Pull-induction (Beluga)** — an attacker that withholds its vertex from most nodes forces them to fetch it (cost: one bounded request per round). Beluga's reputation mechanism is out of scope for v1; AINCORE's downtime-attestation path is the natural place for it later.

## Changelog

- v1: initial draft from tracks A–D. Awaiting six-lens adversarial critique (`scratchpad/vertex-sync-critique.js`).
