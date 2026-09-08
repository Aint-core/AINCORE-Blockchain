# DEFECT REGISTER — AINCORE DAG Vertex Synchronisation

**Repo:** `/Users/macbookpro/Documents/AINCORE-Blockchain` · **Branch:** `audit/mainnet-hardening`
**HEAD at time of writing:** `1c059f1` (the task names `59926d8`; `1c059f1` is the docs-only commit on top of it — `git diff 59926d8..1c059f1` touches only `docs/research/`, so every consensus line number below is identical at both). Working tree carries 4 modified files under `aincore-js/dist/`, none consensus-relevant.
**Design v3:** `docs/DAG_VERTEX_SYNC_DESIGN.md` — header line 3 reads `DRAFT v3 — REFUTED ON ITS CENTRAL STAGING CLAIM. DO NOT IMPLEMENT.` **Invariants:** `docs/research/D-failure-catalog.json` (I1–I16). **Clusters:** `docs/research/v3-clusters.json`.
Every AINCORE claim below was read at HEAD in this session unless the row says otherwise.

---

## 1. What is broken at HEAD today

A vertex enters the DAG with **no check that its parents are obtainable and no check that they carry any quorum** — `add_vertex` validates only compact-proof form (`dag.rs:1036`), round ceiling (`dag.rs:945-946`, `ABSOLUTE_ROUND_CEILING = u64::MAX/2`, `MAX_ROUND_JUMP = 10_000`), future-timestamp drift (`dag.rs:980`), parent count `<= MAX_PARENTS` (`dag.rs:1046`, =256 at `dag.rs:37`), parent uniqueness (`dag.rs:1054-1060`), hash recomputation (`dag.rs:1062`), author-in-validator-set, dedup, and equivocation — and then inserts at `dag.rs:1183`. The commit path evaluates the resolvability predicate far too late: `walk_history` returns `None` on any parent that is neither in `dag`, nor `"genesis"`, nor in `committed_set` (`ordering.rs:697-702`), and both callers turn that into `return out` (`ordering.rs:584-586`, `:730-737`), so the anchor cursor never advances again. **One validator key signing one vertex with one fabricated 64-hex parent is a permanent halt**, and honest producers then propagate the poison because `try_create_vertex` picks parents straight out of `round_index` (`dag.rs:530-545`). The second, independent halt is equivocation: on the second twin `add_vertex` slashes and `return`s at `dag.rs:1167`, **before** the `vertex:{hash}` persist (`dag.rs:1173-1181`) and the `dag.insert` (`dag.rs:1183`) — so the losing twin is never stored, never indexed, never servable, and never re-derivable after restart, while any honest node that cited it wedges every node that dropped it. Underneath both sits a view-dependence bug that is currently *masked* by the halt: `leader_vertex_hash` picks the anchor with `round_index.get(&round)?.iter().find_map(...)` (`ordering.rs:641-646`) over a vector that is push-ordered by gossip arrival (`dag.rs:1183-1187`), and the ancestry arm decides commit-vs-skip on `visited.contains(&hj)` for that locally-chosen hash (`ordering.rs:587-597`). The **server** half of the repair shipped (`sync/src/lib.rs:1272-1301`, routed at `core/node/src/main.rs:788-801`); the **client** half does not exist — `grep -rn VERTEX_REQ --include="*.rs"` returns only the server, its route, `sync/src/tests.rs`, and two comment lines at `dag.rs:1105,1111`. A builder must treat the two halts, the twin-storability gap, and the view-dependence as **one coupled change set with a forced order**, not four independent fixes.

---

## 2. Defect register

Severity is the reviewed severity. Status vocabulary: **CONFIRMED** = attack/defect established against code or design text; **REFUTED** = the claim as written does not hold; **UNVERIFIED-OPEN** = carried forward from the credit-exhausted v3 run, never adjudicated; **FIXED-PARTIAL** = shipped but incomplete.

| ID | Severity | Status | AINCORE file:line | Substance |
|---|---|---|---|---|
| **C1** | CRITICAL | CONFIRMED (established, not re-verified here) | design §5.3 `DAG_VERTEX_SYNC_DESIGN.md:136`; executor write path | `validator_set_at(vertex.round)` is written at block-execution time, i.e. node-locally, so it cannot appear in a validity rule — nodes that execute at different times admit different vertices and fork. |
| **C2** | CRITICAL | CONFIRMED (established) | design §5 citation discipline | Citation discipline with **no pull** is itself a wedge: a Byzantine node hands one perfectly VALID vertex to exactly one honest node, and that node's output is excluded forever. Any "reject/park until parents resolve" without a working fetch reproduces this. |
| **C3** | CRITICAL | CONFIRMED (established) | design R4' | "Defer, never skip" applied to a resolvable sub-quorum leader vertex pins every cursor — strictly worse than HEAD, which at least skips. |
| **P1-D** | — | **REFUTED** | `dag.rs:1140-1171` | The proposed attack requires obtaining the twin; the equivocation branch `return`s at `:1167` before the persist at `:1173-1186`, so the twin is permanently unobtainable and the sequence cannot be run as written. (The *unobtainability* is real and is logged separately as H1.) |
| **P1-E** | HIGH | CONFIRMED | `dag.rs:974-991` (guard at `:980-991`, `MAX_FUTURE_DRIFT_SECS = 30` at `:980`) | A vertex whose proposer clock is >30 s ahead of the **receiver's** `SystemTime` is hard-`return`ed with no park, no queue, no retry — and this runs *before* the dedup check at `:1126-1129`, so nothing local records that it was seen. Honest clock skew silently deletes honest vertices. |
| **P1-F** | HIGH | CONFIRMED (2 of 3 components; row 3 refuted) | design §4 exit criterion | §4's "byte-identical" exit criterion is vacuously satisfiable; two of three components hold. The third component is refuted and does not carry the cluster. |
| **P1-G** | MEDIUM | CONFIRMED (under-specification, node-local consequences) | `ordering.rs:693-711` | A *settled* parent can legitimately have no body, and the settled test (`h == "genesis" \|\| committed_set.contains(&h)`, `ordering.rs:698-700`) precedes any body inspection — the design never says what a decision rule may read from such a parent. |
| **P2-A** | CRITICAL | CONFIRMED (both legs) | design §6 `:154-172`; `ordering.rs:641-646`, `:664-670` | v3's **E2 rule is unsound as written**. E1 requires `leader_vertex_hash(r)` to return all twins in `dag ∪ shadow`; E2's skip arm fires when "the walked round-(r+1) set held >= 2/3 stake and Σ votes(t) <= 1/3". Both premises are evaluated over a node's held bodies, so two honest nodes holding different subsets reach different verdicts. No other design section rescues it. |
| **P2-B** | CRITICAL | CONFIRMED | `consensus/blockchain/src/lib.rs:454-461` | `to_compact_proof()` sets `payload_root`/`parents_root` and clears **both** `payload` and `parents` (unit test at `:585` asserts "compact proof strips parents too"). The design's "compact form **plus parents**" (§6, §9 I4) does not exist in the code, and such a vertex is rejected at ingress by the `is_live_form` gate (`dag.rs:1036-1041`). The gossiped equivocation proof therefore can never deliver a usable twin body. |
| **P2-C** | CRITICAL | CONFIRMED | design `:168`, `:170` | §6 caps shadow storage at "at most **one** shadow per `(author, round)` — the first counterpart", and `:170` states the binary assumption ("a citation of **either** twin resolves"). Nothing bounds an equivocator to k=2; a third or later body is both uncitable-resolvable and unstorable. |
| **P2-D** | HIGH | CONFIRMED | design §9 I10 row; `dag.rs:1806-1809`, `dag.rs:2756-2783` | §9's I10 row ("boot walk bounded ≤ current+2 + fetch") claims an invariant the described pull provably cannot satisfy for I10's own catalogued case: retention is ~10 rounds below `finalized_round.min(latest_block_round)` (`dag.rs:1806-1809`) and `prune_dag` deletes exactly the `vertex:{hash}` rows the server would serve. |
| **P2-E** | MEDIUM (lowered from HIGH) | CONFIRMED on facts; 2 critic overstatements corrected | design `:133`, `:134`, `:136` | Every Part II fetch timer is denominated in **receiver ticks only** ("one frame per 16 ticks per (X,r)"; "TTL of 64 ticks"), which is correct w.r.t. I14 but leaves the mechanism's real-time behaviour unspecified across nodes with different tick rates. |
| **P2-F** | HIGH | CONFIRMED (mechanism; 2 non-load-bearing critic details wrong) | `common/network/src/lib.rs:264-378`, dispatch at `:374-377` | The transport dispatches every decrypted non-`HELLO:` frame to the node handler (`handler_clone(msg)`) with **no check that the session ever completed a valid HELLO**. VERTEX_REQ and DA_SHARD are therefore served to unauthenticated callers; `VertexRequest.requester_id` (`sync/src/lib.rs:30`) is never read on the serving path (grep: only `sync/src/tests.rs` and the unrelated DA protocol) and is self-declared anyway. |
| **P2-G** | HIGH (chain-wide-halt escalation NOT confirmed) | CONFIRMED | `common/network/src/lib.rs:6` (`MAX_CONNECTIONS = 100`), `:10` (`MAX_CONN_PER_IP_MIN = 60`), global cap evaluated before per-IP cap at `:108-135` | 60 sessions from one IP + 40 from a second occupy every accept slot; further accepts are dropped with a bare `continue` and there is no reservation or eviction for validator-set peers. In a 4-validator cluster the other three validators can be denied their 3 slots. |
| **P2-H** | — | **REFUTED** | `common/network/src/lib.rs:308-349` | Load-bearing claim "inbound-only sessions leave `storage.get_peer_ip(X)` unset" is a misread: the inbound accept path persists `peer_ip` from the socket source after HELLO verification (`:309-311` onward). |
| **P2-I** | — | **REFUTED** | `dag.rs:945-946`, `:963-973` | The premise chain is textually correct (one key can get a vertex admitted at `current_round + 10_000`) but the claimed consequence does not follow; `dag.rs` is byte-identical to the design's `3208d29` baseline and the critic's line numbers drift 2-7 lines. |
| **P2-J** | MEDIUM (HIGH not earned) | CONFIRMED IN PART — observer leg holds, validator/partition leg is a misread | `dag.rs:604-612` (RULE 1 at `:608`), fn starts `dag.rs:527` | Everything the design places on the proposer path sits *after* the observer gate `if !is_active_validator { … return; }`, so a non-validator never reaches R4's below-quorum branch. The partition leg of the claim does not hold. |
| **P2-K** | — | **REFUTED** | design `:152` (§5.5), `:136` (§5.2) | Limb 1 (key release on the WANTED entry) is textually correct but inert; the damaging limb rests on a premise the design explicitly contradicts, and a sibling section already covers the scenario. |
| **H1** | CRITICAL | CONFIRMED (read this session) | `dag.rs:1140-1171`; persist `:1173-1181`; insert `:1183`; boot recovery `:231-250`, `:298-317` | **Twin-unstorability.** The equivocation branch `return`s at `:1167` before both the storage put and the DAG insert. Consequence: (a) the loser is unobtainable network-wide from any node that saw it second, (b) a peer that saw it *first* will serve it via VERTEX_REQ and the requester re-drops it at `:1167`, (c) which twin survives a restart is decided by storage-iteration order in the two recovery loops, so a restart can flip the answer. Violates the reference-system rule (Mysticeti §III-A, CometBFT `evidence.md`): no production system deletes the losing twin. |
| **H2** | CRITICAL | CONFIRMED (read this session) | `ordering.rs:634-647` (`find_map` at `:641`); index push-ordered at `dag.rs:1183-1187` | **First-seen twin selection at the DECIDE step.** `leader_vertex_hash` returns the first leader-authored hash in an arrival-ordered vector, applying no quorum test to the choice. Narwhal's first-seen rule (§3.1 cond. 4) governs *signing* only; nothing in the reference set lets arrival order reach the decision function. |
| **H3** | CRITICAL | **REPRODUCED** (test + 4 gates, see DST section) — CONFIRMED (read this session) | `ordering.rs:587-597` (skip arm `_ => {}` at `:596`); soundness comment at `:505-523`; producer-only enforcement at `dag.rs:566-585`; ingress checks at `dag.rs:1046-1060` | **Ancestry decision is not view-independent, and its published proof's premise is not an invariant.** The commit/skip arm tests `visited.contains(&hj)` for a locally-chosen hash, and the comment at `:505-523` argues soundness from "every vertex at j+2 references >2/3 of the j+1 vertices" — a rule enforced *only* in `try_create_vertex` (`dag.rs:566-585`, `qc::stake_quorum_met` over distinct parent authors) and never at ingress. A Byzantine anchor with one parent splits direct-committers from ancestry-skippers. **This is a safety fork that the H4/current halt currently masks; it is unmasked the moment a pull client lands.** |
| **H4** | MEDIUM (hardening; not a safety break under the standard bound) | CONFIRMED (read this session) | `ordering.rs:664-670` | **Double-counted voter.** `v.parents.iter().any(\|p\| p == anchor_hash)` lets one round-(r+1) author's stake count toward *both* twins. Arithmetic checked: both twins exceeding >2/3 requires b > 1/3, so it does not break safety under the standard bound — but it consumes the entire margin, and Mysticeti's `IsVote`/`SupportedBlock` (Alg. 1:14-23) makes it structurally impossible for free. |
| **H5** | CRITICAL | CONFIRMED (read this session) | `dag.rs:1090-1116` (standing comment), `:1046-1060` (only parent checks), `:1183` (insert), `ordering.rs:697-702`, `:584-586` | **The B3/B4 halt itself.** A vertex naming a never-existing parent enters the DAG and wedges `commit_one_anchor` permanently; the tree's own comment records both prior repair attempts and why each was worse. Still open. |
| **H6** | CRITICAL (blocking prerequisite for Regime C) | CONFIRMED (read this session) | `core/executor/src/lib.rs:2047-2067`; read at `:1009-1015`; contiguity at `:1693-1710`; cursor `sys:last_executed_height` at `:1627-1631` | **No state-derived commitment exists.** `sys:state_root = H(prev_root ‖ H(sorted effective writes of this block))` is a commitment to execution *history*, not to state contents; `current_state_root()` is a bare KV read and nothing recomputes it from the KV set. No Merkle/IAVL/Jellyfish trie over AINCORE state exists anywhere in the tree. Any downloaded-state mechanism is unverifiable in principle, not merely unimplemented. |
| **H7** | HIGH | CONFIRMED (read this session) | `sync/src/lib.rs:773-786`; `core/node/src/main.rs:57-60`; retention `common/storage/src/lib.rs:493-500` (`AINCORE_BLOCK_RETENTION` default 100_000) | **Rejoin below the block-prune horizon has no in-protocol regime.** On hitting a peer's `prune_horizon` the client prints advice to set `AINCORE_BOOTSTRAP_SNAPSHOT`; `maybe_extract_bootstrap_snapshot` returns `false` immediately when `db_path` exists (`main.rs:58-60`), and a node that has been *down* has a datadir. The remedy is unreachable from the state that triggers it. The snapshot path itself is a raw RocksDB tarball over HTTPS with an optional tarball-SHA256 — trust-by-URL, no consensus signature. |
| **H8** | HIGH | **FIXED** (see H8-FIX below) — was CONFIRMED | `sync/src/lib.rs:1272-1301` (loop at `:1277`, storage get at `:1284`); `common/network/src/lib.rs:6,10,207`; `core/node/src/main.rs:153` (`#[tokio::main]`, no `worker_threads`) | **Serving path has no lookup budget, no deadline, no per-peer budget, no concurrency cap, no metrics.** A 32-hash all-miss request executes 32 RocksDB `get`s while `bytes` stays 0, so the 900 KiB cap cannot fire. Transport admits 60 conns/IP × 100 msg/s = 6,000 req/s = 192,000 lookups/s from one IP; the handler runs blocking RocksDB reads directly on tokio workers shared with every consensus loop. `DA_SHARD` (`main.rs:777-786`) is a second unauthenticated serving endpoint on the same budget. |
| **F1** | — | **FIXED-PARTIAL (serving only; no client)** | `sync/src/lib.rs:1272-1301`, consts `:46` (`MAX_VERTEX_REQ_HASHES = 32`), `:48` (`MAX_VERTEX_RESP_BYTES = 900 KiB`), dispatch `:1242-1250`, route `core/node/src/main.rs:788-801` | VERTEX_REQ/VERTEX_RESP **server** shipped at `59926d8`: storage reads only, no consensus lock, 64-hex key guard, over-budget hashes reported `unknown` so the requester re-asks rather than concluding absence. Additive; changes no consensus decision. **No client exists** — verified by grep: no `VertexRequest` is constructed outside `sync/src/tests.rs`. Until a client exists, F1 repairs nothing, and it cannot repair the twin case at all while H1 stands (a served twin is re-dropped at `dag.rs:1167`). |

**Unverified-open backlog.** The v3 critique run exhausted usage credits with 89 of 110 agents failing; `docs/DAG_VERTEX_SYNC_DESIGN.md:4` records **43 findings left unverified and treated as OPEN**, deduplicated into the 15 clusters in `docs/research/v3-clusters.json`. Eleven clusters are adjudicated above (P1-D…P2-K). Any cluster in that file not appearing in the table above remains **UNVERIFIED-OPEN** and must not be assumed closed.

---

## 3. Required properties

Each property is stated so a failing test can be written directly against it. All named tests fail at HEAD.

### 3.1 Leader-round decision under equivocation

Let `D_n(r) ∈ {Commit(h), Skip, Undecided}` be honest node *n*'s decision for anchor round *r*; the round-*r* leader emits *k ≥ 0* validly-signed vertices (nothing bounds *k* — see P2-C).

- **AD-1 (Agreement, including the hash).** For all honest *n*, *m*: `D_n(r) ≠ Undecided ∧ D_m(r) ≠ Undecided ⇒ D_n(r) = D_m(r)`, equality covering the committed **hash**, not merely "some twin". *(Mysticeti Corollary 1: "if two validators have decided the state of a slot, then both either commit the same block or skip the slot"; Jolteon Appendix A.1 Observation 1: "at most one block is certified in each round".)*
- **AD-2 (No retraction).** Once `D_n(r) ≠ Undecided` it never changes — across restarts, checkpoint recovery, and validator-set changes executed after *r*.
- **AD-3 (Constructive view-independence).** There exists a total function `decide(r, VS_r, H)`, where *H* is the parent-closed causal history of the deciding anchor, with `D_n(r) = decide(r, VS_r, H)` for every *n* holding *H*. `D_n(r)` must **not** depend on (a) iteration order of `round_index[r]`, (b) *which subset* of the leader's twins *n* holds, or (c) any vertex *n* holds outside *H*. AD-1 without AD-3 is unwritable as a test; AD-3 is the testable form. *(Bullshark §5 restricts the recursive rule's potential votes to "all the vertices in round v′.round+1 in its DAG such that there is a strong path between the last leader p_i previously ordered and v′" — the anchor's causal history, not the local DAG. Mysticeti §II-C defines support as a DFS over the **voting block's own** declared parent order.)*
- **AD-4 (Reference closure / twin-storability).** If any vertex an honest node accepts names hash *h* as a parent, *h* must be **installable** by every honest node — including a second vertex from an `(author, round)` already held. Without AD-4, AD-3's input *H* is not constructible and the rule is vacuous. *(Mysticeti §III-A keeps the equivocating block and links to both; CometBFT `evidence.md` carries **both** conflicting votes on chain.)*

**Tests (all fail at HEAD).**
- **T1 twin-permutation invariance** (AD-1+AD-3a). 4-validator DAG over rounds 1..r+3, leader emits twins A,B at even round *r*, honest r+1 authors split citations in a fixed pattern. For every delivery permutation π, assert `|{(anchor_round, anchor_hash, finality_digest) sequences}| == 1`. Fails: `ordering.rs:641`.
- **T2 twin-subset invariance** (AD-3b+AD-4). Node X gets {A}, Y gets {B}, Z gets {A,B}; all three must return the same `D(r)`. Fails, and **Z is unconstructible**: `dag.rs:1167`.
- **T3 restart invariance** (AD-2). Decide *r*, kill, restart from RocksDB, decide again; assert equal. Fails: recovery loops `dag.rs:231-250`, `:298-317` pick by storage order.
- **T4 sparse-anchor invariance** (AD-3c — a **safety fork**, not a halt). Round *j* has a full >2/3 direct quorum in the complete DAG; a Byzantine round-*r'* leader emits a 1-parent anchor whose history omits the round-*j* leader. Node X direct-commits *j* (`ordering.rs:556-567`); node Y ancestry-skips it (`ordering.rs:596`). Assert `D_X(j) == D_Y(j)`. Fails: the premise at `ordering.rs:505-523` is enforced only at `dag.rs:566-585`, never at ingress. *(Narwhal §3.1 cond. 3 makes 2f+1 previous-round certificates a **validity** condition; Bullshark §4.2 makes ">= 2f+1 strong edges" a **delivery legality** check; Mysticeti Lemma 1's proof opens with it.)*
- **T5 no double-counted voter.** Assert each round-(r+1) author contributes stake to at most one candidate. Fails: `ordering.rs:664-670`.

### 3.2 Availability decidability

**Framing that four attempts have skipped:** "will this hash ever exist?" is **not decidable** in an asynchronous network, and neither Narwhal nor Beluga decides it. Absence is never provable — a pull returning `unknown` from every peer is evidence, not proof. Every design that tries to decide non-existence (drop-on-unresolved, TTL-then-reject, "ask N peers then declare fake") is wrong at the root. Both reference systems replace the undecidable question with a decidable **positive** predicate.

- **P1 Ingress resolvability (structural).** For every vertex *V* inserted into the structures the commit path traverses (`dag`, `round_index` — `dag.rs:1183-1189`), every `p ∈ V.parents` satisfies, **at insert time**, `resolvable(p) ::= p == "genesis" ∨ p ∈ dag ∨ p ∈ committed_set`. This is the predicate `walk_history` already evaluates at commit time (`ordering.rs:696-700`); P1 moves it from "commit time, where the only response is to stop" to "insert time, where the response can be to wait". **Test:** fuzz `add_vertex` with well-formed, correctly-signed vertices whose `parents` contain random 64-hex strings; assert `walk_history` never returns `None` for any anchor and `next_anchor_round` strictly advances — equivalently, that `ordering.rs:701` is unreachable.
- **P2 Bounded retrieval from a holder (liveness).** For every *V* held back by P1 there exists a bounded, **receiver-clocked** process that issues a retrieval to a node that provably **holds** *p*, and admits *V* on arrival. "Provably holds" must be established by construction: under P1 the **author** of *V* admitted *p* before it could build *V*; if it did not, the author is Byzantine and *V* is owed no liveness. This is invariant **I2**. **Test:** deliver *V* to node A but never deliver parent *P* to A by gossip, while B holds *P*; assert A admits *V* within *k* retrieval intervals and A's cursor advances. **Removing P1 must break the first test and removing P2 must break this one, independently** — if either mutation leaves both green, the change is half. *(Narwhal §4.1 pulls a certificate's causal history "from validators that signed the certificates", with "only O(1) requests for each block active"; Aptos `consensus/src/block_storage/sync_manager.rs` fetches by `TargetBlockId(HashValue)` and asserts the returned block's id equals the requested id.)*
- **P3 Resolvability is admission TIMING, never validity.** `resolvable()` is node-local and time-varying, so it must not appear in any accept/reject/ban/peer-score/slash decision — only in admit-now-vs-admit-later. This is the precise generalisation of **C1** (a node-local quantity in a *validity* rule forks; in a *timing* rule it is sound) and of **C2** (a citation discipline that *rejects* is a wedge because rejection is a validity decision on a local view). **Test:** no control-flow path from the resolvability check reaches ban/disconnect/peer-score/slash (**I12**); and two nodes admitting the same *V* at deliberately staggered times still satisfy the existing assertion `follower.committed_set == producer.committed_set` (`ordering.rs:1843`).
- **P4 Precondition, currently latent and free.** Beluga's ImPoA precondition — "a validator references B only if it (i) receives B, and (ii) can verify the availability of B's causal history" (§4.3.1) — is **false at HEAD** and becomes **true by construction** under P1, because `try_create_vertex` already draws parents exclusively from `round_index` (`dag.rs:530-535`). Any ImPoA-style rule imported into HEAD *as-is* is unsound: AINCORE references attest to nothing today.

### 3.3 Rejoin beyond the pruning window

Three regimes by deficit from the tip. **A:** deficit < ~10 rounds (`dag.rs:1806-1809`) — repair = fetch vertex bodies; the only regime where a vertex is both needed and obtainable; **this is the entire legitimate scope of the missing client**. **B:** above the vertex horizon but within `AINCORE_BLOCK_RETENTION` (default 100_000, `common/storage/src/lib.rs:493-500`) — repair = block sync alone, **already closed at HEAD** via `Block::committed_vertices` + `vertices_root`, `adopt_synced_anchor` (`ordering.rs:869-888`, hash strings only), `catchup_floor`, `quorum_round`; any design making a vertex fetch a prerequisite here is strictly worse than HEAD. **C:** beyond that — repair = **state**, not vertices and not blocks; nothing in-protocol exists.

- **P1 State-derived commitment.** For any state adopted **without** re-executing the transactions that produced it there must exist *V* such that (a) `V = f(adopted state)` — a function of state **contents alone**, not of history; (b) *V* is committed in a block header carrying >2/3 stake-weighted signatures; (c) the rejoining node recomputes *V* from exactly what it downloaded and compares before accepting. **Test (no network needed):** node A executes blocks 1..N; node B installs A's state at N by direct KV copy; `f` must return the same *V*. **`sys:state_root` fails clause (a)** — H6. *(Cosmos compares the restored **app hash**, the IAVL root, against a light-client-verified `trust_hash`, and "only after the entire snapshot has been restored"; Sui's formal snapshot is checked against a **protocol-signed commitment to the end-of-epoch live object set**; Aptos verifies downloaded state values against validator-signed ledger info anchored on genesis + waypoint.)*
- **P2 Regime totality and termination.** For every reachable `(local_height, local_round, network_tip, datadir_state)` exactly one regime applies and terminates at the tip. **Test:** `local_height = tip − 200_000` with a **non-empty** datadir. No regime applies today — H7.
- **P3 No node-local input in any acceptance rule.** Nothing produced by this node's own execution or signed by this node's own key may gate acceptance of rejoin data. This kills two shortcuts: `sys:state_root` (node-local by P1), and the **DAG checkpoint**, which is signed with the node's own Ed25519 key and verified against that same key (`dag.rs:1819-1849`; `common/storage/src/lib.rs:785-800`, `:820-827`) — exactly the C1 class. It is a local fast-restart artifact and can never be shipped to a peer.
- **Corollary (atomicity).** Any snapshot install is an atomic multi-key transition or it bricks the node: the executor refuses any height ≠ `last_executed+1` (`BlockExecOutcome::Gap`, `core/executor/src/lib.rs:1701-1710`) keyed on `sys:last_executed_height` (`:1627-1631`). `sys:last_executed_height`, `sys:state_root`, `latest_height`, `latest_block_hash`, `consensus:finalized_round`, `consensus:next_anchor_round`, `consensus:finality_digest` and `latest_proposed_round` must move in one WriteBatch.
- **Accepted price** (state, not aspiration): a Regime-C rejoin yields forward participation, not history. *(Aptos: fast-synced nodes "cannot replay the network's past"; CometBFT: "the node will not contain historical data from previous heights".)*

### 3.4 Serving DoS bounds

- **P1 Charged on misses, not only bytes.** Every disk lookup the serving path performs decrements a budget whether or not it yields bytes. **Test:** a 32-hash all-miss request consumes at least as much budget as one returning 900 KiB. Fails at `sync/src/lib.rs:1277-1293`. *(geth `ServiceGetBlockBodiesQuery` breaks on `bytes >= softResponseLimit || len(bodies) >= maxBodiesServe || lookups >= 2*maxBodiesServe`; snap adds `maxTrieNodeTimeSpent = 5*time.Second`, justified because overrunning it means "there's a fairly high chance of timing out at the remote side, which means all the work is in vain".)*
- **P2 Keyed on something the requester cannot cheaply inflate** (**I3** applied to the serving path). **Test:** enumerate what the attacker spends for a second budget. Today the only keys are a TCP connection (one socket, 100 msg/s, `common/network/src/lib.rs:207`) and a source IP (60 concurrent, `:10`); `requester_id` is unread and self-declared. *(libp2p's transient scope is "a DMZ … for connections and streams that are not fully established"; only after `SetProtocol` does a stream move onto per-peer/per-protocol budgets.)*
- **P3 Aggregate ceiling set from the slowest validator's measured serving capacity, not from the transport's frame budget.** **Test:** worst-case sustained work admitted by the transport ÷ **measured** single-node serving throughput on the Pi must be ≤ 1. Transport admits 6,000 req/s from one IP; a Pi at an *estimated* 0.5-2 ms per cold point lookup sustains roughly 60-250 req/s across 4 tokio workers — **≈24-100× over capacity**. That estimate must be replaced by a measurement on the actual Pi validators before any number is chosen.
### H8-FIX — vertex serving is bounded (closed)

`sync/src/lib.rs`: `VertexServeBudget` on `ChainSync` (per-node, not a process
global, so tests cannot starve each other). Three bounds now stand between an
unauthenticated TCP peer and RocksDB:

| Bound | Value | Effect |
|---|---|---|
| Concurrency | `MAX_CONCURRENT_VERTEX_SERVES = 4` | over that, requests are **shed**, not queued — a queued request still owns its tokio worker, which is the resource being protected |
| Rate | `VERTEX_SERVE_LOOKUPS_PER_SEC = 512`, burst `1024` | node-wide token bucket; costed only for well-formed hashes, so malformed floods cannot drain an honest peer's allowance |
| Deadline | `VERTEX_SERVE_DEADLINE_MS = 50` | caps worst-case worker blocking at 4 × 50 ms |

Worst case reaching storage drops from 192,000 lookups/s (one IP) to 512/s
node-wide. The all-miss amplification in the original report is closed by the rate
bound, which is costed per *lookup*, not per byte returned.

**Shed load is reported, never omitted** — every hash a request names comes back
in `vertices` or in `unknown`. A silent omission would read as "peer does not have
it", and the requester would stop asking: the exact unobtainability this pull was
built to fix.

Mutation-proven (`sync/src/tests.rs`): disabling the concurrency cap fails 2 tests,
disabling the rate check fails 1, replacing the shed report with an empty `unknown`
fails 1; restoring goes green. The **deadline is not mutation-proven** — that needs
injectable time or a stallable `StateDB`, neither of which exists. It is a backstop
for the other two.

**NOT closed by this, deliberately:** the bucket is node-wide, not per-peer, so a
spammer can still starve honest peers of *vertex service* (it can no longer starve
*consensus*, which is what H8 was). Per-peer fairness is unreachable here —
`requester_id` is an unauthenticated attacker-chosen string, and the peer's real
address is not plumbed to the handler (`start_server` passes `Fn(&str) -> Option<String>`).
Keying on `requester_id` would look like a control and be bypassed by varying one field.
**`DA_SHARD` (`main.rs:777-786`) is a second unauthenticated serving endpoint and is
still unbounded.**

### DST — deterministic simulation testing: decision and first result

An 18-agent adversarial gate (map -> 4 rival designs -> 2 refuters each -> synthesis)
ran before any harness code. **All four designs were refuted**, three by reviewers who
compiled and ran code rather than arguing. What survived is worth more than a surviving
design:

**FACT 1 — H1 reproduces at HEAD with ZERO production change.** Two reviewers
independently built it from the existing in-process test seam. This killed the
justification for the invasive Clock/Egress refactor ("H1 is provably unreachable
without injection") and for the record/replay recorder in one stroke.

**FACT 2 — exhaustive model checking is dead.** A reviewer built the Stateright model and
measured: depth <=7 is 26,717,121 states, exhaustive, and **not one commit is reachable**;
the ground-truth witness sits at depth 38 and the space ceiling is ~1.1e12. The
generalizable lesson: the interesting states are DEEP, so the action space must be
inverted — seed a complete DAG and make OMISSION and PERMUTATION the actions, never
"deliver from empty".

**FACT 3 — 4 of 4 designs shipped a proof-of-life gate that could not discriminate.**
One ran 0 checks and printed green both before and after its own mandatory fix-mutation.
The failure mode is not consensus reasoning: **the author writes an assertion, predicts
how it behaves under mutation, and is wrong.** Hence the standing rule below.

> **DISCIPLINE RULE, outranking every technical choice: no predicate is believed until its
> fix-mutation has been EXECUTED and observed to flip. A predicted mutation outcome is
> worth nothing.**

**AIM CHECK (run before building, result negative as predicted).** Tier 1 provably cannot
express `P-ANCHOR-HEIGHT` — the `anchor_round -> block_height` map whose violation WAS the
live B4b block fork. Measured, not argued:

    error[E0609]: no field `height` on type `&CommitInfo`
      = note: available fields are: sequence, leader, anchor_round, anchor_hash, finality_digest

Height is fixed at `dag.rs:1508` as `latest_block_height + 1` **inside an 8x250ms retry
loop** racing ChainSync's storage visibility (`dag.rs:1459-1512`), i.e. decided by real
time, not message order. Consequences: (i) tier 1 sits one layer BELOW the live fork
surface; (ii) the Clock seam is **required and pulled forward**, not optional "Stage B";
(iii) the tier-2 corpus, which runs at ~1e3 schedules/night rather than 1e6, is the
deliverable that bears on mainnet. Budget against 1e3.

**H3 IS NOW REPRODUCED** — `ordering.rs`, `test_h3_sparse_anchor_forks_direct_committer_from_ancestry_skipper`,
0.01 s, zero production lines changed, `#[ignore]`d only to keep `cargo test --workspace`
usable:

    cargo test -p consensus --lib test_h3_sparse -- --ignored --nocapture

4 validators, equal stake. The round-4 leader emits ONE-PARENT vertices at r3 and r4 whose
causal history is COMPLETE (no hole -> no deferral) but excludes the round-2 leader. X holds
everything and direct-commits round 2 (3 votes, 9000 > 8000). Y is missing two honest r3
vertices — **plain gossip loss, no second Byzantine act** — advances to the thin r4 anchor,
finds the round-2 leader provably absent, and SKIPS round 2 permanently. Both decisions final.

All four gates RUN and OBSERVED:

| Gate | Required | Observed |
|---|---|---|
| HEAD | RED | RED — fork reproduced |
| M0 `BYZ_HONEST=true` (negative control) | silent | silent — Y hits a real hole, defers, `Undecided` |
| M1 min-hash tie-break on `round_index` (the H2-shaped fix) | stay RED | stayed RED |
| M2 parent quorum at admission | GREEN + P-LIVE green | GREEN |

`P-LIVE` is asserted FIRST and unconditionally: the trivially "safe" fix — defer
everything — makes agreement vacuously true. **B3/B4 IS a halt**, so any safety-only
harness reports green on a wedged chain.

M2's limit, stated so it is never mistaken for validation: tier 1 does not run `add_vertex`,
so the filter is a SECOND IMPLEMENTATION of the ingress rule. It proves the property is
ACHIEVABLE. Validating the production fix needs tier 2.

**B3/B4 IS NOW PINNED** — `ordering.rs`,
`test_b3b4_fabricated_parent_wedges_the_cursor_and_p_live_catches_it`. Unlike the H3
test this one is **GREEN at HEAD, and green does NOT mean healthy**: it is a
CHARACTERISATION test that pins current behaviour. When a real fix lands, leg 2 must be
inverted and the fix is acceptable only if leg 1 stays green.

Three legs: (1) P-LIVE positive control on a clean full mesh — without it, leg 2's
"cursor frozen" assertion would also pass on a harness that never commits anything;
(2) the wedge — the round-2 leader cites a 64-hex parent that never existed, and the
mechanism is pinned in three separate facts (the leader vertex is present AND elected,
it IS directly committable so quorum is not the blocker, and `walk_history` reports the
hole) before the symptom is asserted over 32 consecutive ticks; (3) the escape —
`adopt_synced_anchor` bypasses `walk_history` entirely, so a wedged node only recovers by
being TOLD the answer out of band. That asymmetry is why B3/B4 is a liveness defect and
not a slow path.

**B3/B4 can be "fixed" wrongly in two OPPOSITE directions, and both are now caught:**

| Mutation | Direction | Required | Observed |
|---|---|---|---|
| M1 `walk_history` always `None` | fail-CLOSED, "defer whenever unsure" | leg 1 fails P-LIVE | fails: "cursor stayed at 1" |
| M2 hole treated as settled | fail-OPEN, the live-fork behaviour | leg 2 fails | fails |

M1 is the halt-as-fix trap: under it **every safety property still passes**. That is the
whole reason P-LIVE is asserted before anything else.

Second-order check, because the first-order one was not enough: under M2 leg 2 fails at
the *mechanism* assertion, which short-circuits before the freeze loop — leaving the
freeze loop itself unproven, the same trap one level down. Verified separately with that
assertion removed: M2 then fails inside the freeze loop at tick 0. **Both layers
discriminate independently.**

**THE SEEDED SCHEDULER IS LIVE** — `ordering.rs`, three gates plus a measurement probe.
Action space INVERTED per FACT 2: start from a COMPLETE DAG, take things away. Actions are
OMISSION and PERMUTATION, so every state is one step from interesting instead of thirty-eight.
Measured throughput: **100,000 schedules in 7.42 s** (~13,500/s) — "millions overnight" is
real at tier 1, and only at tier 1.

| Gate | Claim | Mutation that must break it | Observed |
|---|---|---|---|
| 1 `corpus_honest_emissions_never_fork_and_never_reach_the_ancestry_arms` | honest-only never forks; ancestry arms unreachable | feed it the Byzantine menu | FAILS at seed 77 |
| 2 `corpus_rediscovers_the_h3_witness_unaided` | the search re-finds H3 unaided, and the seed replays | neuter the Byzantine script | FAILS: exhausts all 100,000 |
| 3 `corpus_permutation_is_inert_until_twins_are_injectable` | reordering changes nothing today | inject an equivocation twin | FAILS at seed 9 |

**GATE 2 rediscovered H3 at seed 77** — three orders of magnitude inside the 100,000 budget,
with the Byzantine AUTHOR drawn at random and no hint that the fork needs it to land on an
anchor-round leader. Its shape matches the hand-written witness exactly (one view Commits an
even round, another Skips it), and the seed replays identically three times. **This gate is
what gives any future "the corpus found nothing" its meaning**: a search that cannot re-find
a known answer proves nothing when it comes back empty.

**NEW MEASURED FINDING — the ancestry walk-back gets ZERO coverage from honest traffic.**
Across 20,000 schedules at world sizes of 6, 10 and 16 rounds, honest-only emissions
exercised `ancestry_commit` and `ancestry_skip` **exactly zero times**, while direct commits
ran to 153,030 at 16 rounds. Both non-direct arms are reachable only via a Byzantine thin
anchor. **This is why H3 survived every audit**: the most subtle branch of the ordering
algorithm is never touched by honest traffic — not in tests, and not in production either.
No amount of honest running would have found it.

**HONEST LIMIT, proven rather than assumed — permutation is currently INERT.** Every consumer
of `round_index` order except one accumulates into a set (`direct_quorum_met` collects
distinct authors, `walk_history` collects visited hashes). The only order-sensitive reader is
`leader_vertex_hash`'s `find_map`, and it matters only when a round holds TWO vertices by one
author — twins, which `add_vertex` drops at dag.rs:1167 (H1) and which this corpus does not
yet inject. So half the action space explores nothing today. Gate 3's mutation makes this
CAUSAL rather than a guess: inject a twin and gate 3 fails at seed 9. When step 4 lands,
gate 3 must fail, and that failure is the proof the twins took effect.

The FABRICATED-PARENT script (B3/B4) is deliberately excluded from the menu: it is a
known-open wedge that would fire on nearly every seed and drown the agreement signal. It has
its own characterisation test.

**H2 + H4 ARE NOW EXPRESSED — written deliberately while H4 is UNREACHABLE end-to-end.**
`ordering.rs`, `test_h2_h4_twin_anchors_double_count_stake_and_break_subset_independence`,
RED by design:

    cargo test -p consensus --lib test_h2_h4_twin -- --ignored --nocapture

At HEAD `add_vertex` drops the losing twin at dag.rs:1167 before the persist at :1173, so
no honest node ever HOLDS both twins, so no honest vertex ever cites both, so H4 cannot
fire. **An end-to-end-only harness scores H4 green today, and fixing H1 silently opens
it.** "Currently unreachable" is the reason to write the property, never the reason to
skip it — patching what is reachable and calling the class closed is this project's
documented failure mode.

Three legs, each shown to fire INDEPENDENTLY (each isolated so no earlier assertion
short-circuits a later one):

| Property | Violation at HEAD |
|---|---|
| `P_NODOUBLECOUNT` | twin A backed by 4000 stake, twin B by 4000, total **200% of the whole validator set** |
| `P_VIEWINDEP_SUBSET` | a node holding only twin A commits `#1`; one holding only twin B commits `#2` |
| `P_VIEWINDEP_ORDER` | identical vertex SET, reversed arrival order, `#1` vs `#2` |

**THE HALF-FIX GATE — measured, and this is the one that matters.** Sorting `round_index`
before the `find_map`:

| Leg | Under the sort |
|---|---|
| `P_VIEWINDEP_ORDER` | **GREEN** — the half-fix does repair this |
| `P_VIEWINDEP_SUBSET` | **RED** — it does not |
| `P_NODOUBLECOUNT` | **RED** — untouched; sorting never reaches `direct_quorum_met` |

A harness asserting only ORDER would sign off on that sort and ship a fork. The real fix
is not a tie-break: anchor identity has to be fixed by a 2f+1-weighted certificate over a
specific hash, so "which twin" is not a question any individual node answers from its own
view.

**Corpus menu `Equivocate` added** — and the two Byzantine classes are measurably
DIFFERENT defects, not one seen twice (20,000 schedules each):

| Menu | AD-1 breaches | first seed | shape | ancestry arms |
|---|---|---|---|---|
| Honest | 0 | — | — | 0 / 0 |
| SparseAnchor (H3) | 175 | 77 | Commit vs **Skip** | 157 / 184 |
| Equivocate (H2) | **1,737** | 3 | Commit vs **Commit** | 0 / 0 |

The twin fork is ~10x more frequent than H3 and runs entirely on the direct-commit path,
never touching the ancestry arms. Gate 3 (permutation inert) is now SCOPED to
SparseAnchor, and gate 4 asserts permutation is LIVE under Equivocate — the two standing
side by side are what make gate 3's inertness CAUSAL rather than a broken harness.

**A DEFECT IN OUR OWN HARNESS, found and fixed — worth recording because it would have
invalidated everything above.** The corpus was process-DEPENDENT: permutations were
applied by iterating `v.idx`, a `HashMap`, whose iteration order Rust randomises PER
PROCESS. The same seed therefore built different worlds in different processes,
destroying the one property the corpus exists for — that a seed IS a reproducible bug
report. It surfaced as exactly ONE flaked debug run and nothing else; the within-process
replay assertion could never catch it, because within one process the hasher seed is
fixed.

Fixed by walking rounds in sorted order, then guarded by **pinned first-breach seeds**
(`H3_FIRST_BREACH_SEED = 77`, `TWIN_FIRST_BREACH_SEED = 3`). Verified stable 8/8 across
separate processes in both profiles; and with the bug reintroduced the pin fires 6/6,
with the seed visibly wandering (7, 9, 7) between runs. Production is NOT affected —
`find_causal_history` sorts by `(round, hash)` before returning, so traversal order does
not leak there. Checked, not assumed.

**TIER 2 IS LIVE, AND ITS FIRST RESULT REFUTES THE RECOMMENDED H1 FIX.**
`consensus/consensus/src/tests.rs`,
`test_h1_dropped_twin_leaves_two_honest_nodes_holding_different_sets`, RED by design:

    cargo test -p consensus --lib test_h1_dropped_twin -- --ignored --nocapture

Two real `DagConsensus` nodes, real `StateDB`, real ingress. The only difference between
them is arrival order: X sees twin A then B, Y sees B then A. The predicate is
**P_VIEW_EQ** — two honest nodes that received the same message SET hold the same
accepted-vertex set. Deliberately NOT `P_CLOSURE`, which an earlier design named as the
gate here and which was measured to run zero checks and print green both before AND after
its own mandatory fix-mutation.

**The measured result (each leg isolated so neither short-circuits the other):**

| | HEAD | with the naive hoist |
|---|---|---|
| `P_VIEW_EQ` | **RED** | **GREEN** |
| `P_RESTART_STABLE` | **GREEN** | **RED** |

**The recommended fix — hoist the persist and `dag.insert` above the `return;` at
dag.rs:1167 — trades one defect for another.** It was named as the one empirically
established red→green flip in this whole line of work, and two independent reviewers had
built and confirmed that flip. They confirmed it on `P_VIEW_EQ` alone.

Why: in memory the surviving twin is chosen by ARRIVAL order; on reboot the recovery loops
(dag.rs:245-256, :318-330) refuse the second vertex from one author at one round and choose
by `scan_vertices` BYTE order (`prefix_iterator`, storage/lib.rs:280). Those orders are
unrelated. At HEAD the question cannot arise, because only one twin is ever persisted — so
`P_RESTART_STABLE` is green today for precisely the reason the hoist removes. A node would
change its own mind about what it accepted, across nothing but a restart.

**Persisting both twins is half a fix.** Something must then choose between them
deterministically — and the missing half is not local: once a node can hold both twins, H4
opens, because `direct_quorum_met` counts one author's stake toward BOTH (measured: the two
twins together carry **200%** of the validator set). **H1, H2 and H4 are ONE change set
with a forced order, not three fixes.** The register said so; this is the first
experimental confirmation.

Two silent-null preconditions are handled in `tier2_open` because missing either drops
vertices with nothing to distinguish that from rejection: `resolve_author_pubkey`
(dag.rs:998) hard-returns without an `0x1::account::AccountData` object for the author, and
the validator-set gate (dag.rs:1082) only runs while `current_round > 0`. A non-vacuity
assertion catches both.

**Rejected outright:** exhaustive model checking (FACT 2; and `held: BTreeSet` collapses
every delivery permutation into one fingerprint, making the root defect H2 *unrepresentable*);
the record/replay recorder (it misses ChainSync's client path, `sync/src/lib.rs:722`, the
very input driving the race it was sold on).

**What this harness will NOT catch, written down because "green" gets cited as clearance:**
B4b and the anchor->height race (real-time, not message order); the double-execution
state-root race (two OS threads — a `loom` problem, not a DST problem); clock-skew admission
P1-E (the harness's clock defence IS the blind spot); `try_create_vertex` and therefore the
whole slashing-consequence path (`drain_evidence_for_vertex` has exactly one caller,
`dag.rs:647`, inside it); heterogeneous config (every knob is a per-call `env::var`,
`VERTEX_DOMAIN` is a process-global `OnceLock`); the transport and sync serving path — and
**B3/B4 lives on exactly that path**. Green is evidence, never proof: if a property is
mis-stated, every seed passes forever.

- **P4 Serving must not consume the resource consensus needs to advance.** **Acceptance test for the cluster:** 60 connections from one IP to r1 driving 6,000 miss-only VERTEX_REQ/s; assert (i) r1's round-advance interval unchanged within a stated tolerance, (ii) the other three validators can still open connections to r1, (iii) served bytes/s and lookups/s stay under configured ceilings. (iii) fails trivially (no ceilings exist); (i) and (ii) fail by construction (H8, P2-G).
- **Missing budgets, named:** per-request lookup budget charged on misses; per-request wall-clock deadline; per-peer served-bytes/lookups bucket (unimplementable until P2-F is closed); global serving-concurrency semaphore + blocking-IO isolation; send-queue watermark with resumable serving *(Bitcoin `ProcessGetData` stops at `fPauseSend` and resumes from `vRecvGetData`)*; reserved slots/eviction for validator-set peers *(Bitcoin `AttemptToEvictConnection`; geth reserved trusted-peer slots)*; age/scope restriction on what may be served *(Bitcoin `MAX_BLOCKTXN_DEPTH = 10`, `HISTORICAL_BLOCK_AGE = 7d`)*; and **any counter at all** — grep for metric/counter/prometheus in `sync/src/lib.rs` returns nothing, so none of the above could be tuned or shown to have fired. Metrics first, budgets second.
- **Note the shared budget:** `DA_SHARD` (`core/node/src/main.rs:777-786` → `da/src/lib.rs`) is a second unauthenticated storage-serving endpoint on the same per-connection allowance and the same worker threads. A budget scoped to VERTEX_REQ alone leaves the aggregate unbounded.

---

## 4. Known UNWORKABLE — do not repeat

1. **v3's E2 rule (design `:154-172`).** Unsound as written (P2-A). Its skip arm — "if the walked round-(r+1) set held ≥ 2/3 stake and `Σ_t votes(t) ≤ 1/3`: skip" — and its commit arm both quantify over **bodies the deciding node happens to hold**, so two honest nodes with different holdings decide differently. It violates AD-3 directly. E2 also depends on two mechanisms that do not exist: shadow rows "as compact form **plus parents**", which `to_compact_proof()` cannot produce (P2-B, `blockchain/src/lib.rs:454-461`), and a one-shadow-per-`(author,round)` cap that assumes k=2 twins when nothing bounds k (P2-C). **E2 must be discarded, not patched.**
2. **Any ingress-side "late vs never" decision.** Non-existence is not decidable asynchronously. Every variant — drop-on-unresolved, park-with-TTL-then-reject, ask-N-peers-then-declare-fake, or any peer-score/ban keyed on an unanswered hash — is wrong at the root, and this is why the previous attempts produced defects rather than fixes. The equivocation case makes the indistinguishability concrete: under H1 a twin can be legitimately answerable by exactly one peer, so a majority of honest `unknown` replies is normal, not evidence of fabrication. The only sound response is to keep holding within a bounded budget and never conclude anything about existence (P3 of §3.2).
3. **Unconditional drop at ingress** (`dag.rs:1090-1116`, the tree's own record). Wedges any validator that misses one vertex; the "re-gossip will redeliver it" justification is inverted — the re-gossip loop pushes `dag.values()`, i.e. what a node already holds, and nodes that *do* hold the missing vertex are above parent quorum and never enter that branch.
4. **The orphan-buffer park as previously built** (same comment block). Produced six defects across three rounds: unbounded bytes, a TTL that could not evict future-round entries, O(blocks × orphans) re-validation on catch-up, a re-entrancy hole, and a drain that never ran on non-validator nodes. Any replacement must satisfy I3 (eviction key the sender cannot inflate — **not** `vertex.round`, attacker-choosable to `current+10_000` at `dag.rs:946`), I4 (bounded in **bytes and per-author**; 10_000 × 768 KiB ≈ 7 GB otherwise — I11), I7/I8 (release keyed by the newly-settled hash, firing identically for gossip and for `adopt_synced_anchor`), I14 (timers independent of inbound traffic), and I16 (lock order: insert takes dag→round_index at `dag.rs:1118-1121`, the commit path takes ordering_engine→dag at `dag.rs:1274-1278`; `resolvable()` reads `committed_set`, so getting this backwards deadlocks).
5. **C3's "defer, never skip" on a resolvable sub-quorum leader vertex.** Pins every cursor; worse than HEAD. Note that under a correct P1 this policy question **disappears** rather than needing tuning: `ordering.rs:701` becomes unreachable and the deferral sites at `:584` and `:735` become assertions.
6. **Shipping the pull client before the twin and ancestry rules change.** Today H5's halt *masks* H3's safety fork; a working client produces exactly the hole-free histories under which two nodes holding different twins reach opposite commit/skip verdicts. **A halt is recoverable; a finality fork is not.** The order is forced: twin-storability → ingress parent quorum → candidate enumeration → per-vertex support rule → ancestry rule over the anchor's history → *then* the client.
7. **`validator_set_at(vertex.round)` in any membership/validity test** (C1, design `:136`), and equally the **DAG checkpoint as a rejoin artifact** (§3.3 P3) — both are node-local values in acceptance rules.
8. **Narwhal/Bullshark certification via reliable broadcast, now.** It is the cleanest answer (the twin cannot exist) but it is a network-layer rewrite: per-`(author, round)` RB instances, a signature-collection service, certificates as DAG nodes, n² signature verifications per round, push latency δ → 3δ. AINCORE broadcasts a bare signed `Vertex` as `DAG_VERTEX:{json}` over Gossipsub with no acknowledgment path anywhere in the tree. That is a re-architecture, and this problem has already failed four code attempts and three design drafts.
9. **Copying reference constants verbatim.** Beluga/Narwhal's "f+1" is one-validator-one-weight; AINCORE is stake-weighted (`qc.rs:194`, `stake_quorum_met` is the **>2/3** predicate and is the wrong one for "at least one honest referencer" — that is >1/3 stake, and no such helper exists). Bullshark's "commit at 2f+1, recurse at f+1" must be re-derived over stake before anyone writes it down. Beluga's ImPoA is stated over "blocks from the subsequent rounds" and presupposes a parent-round rule AINCORE does not have. geth's 2 MB / 1024-item caps are sized for x86 on NVMe. Beluga specifies **no** per-peer request cap and no byte quota at all, so it cannot be cited as authority for a serving budget.

---

## 5. The open question that must be answered before any further code

**Given that `resolvable()` is node-local and time-varying while `committed_set` is a bounded 8192-hash window (`ordering.rs:90`) and `prune_dag` deletes `vertex:{hash}` rows below `min_committed_round − 10` (`dag.rs:2756-2783`, `:1806-1809`) — what is the exact third resolvability arm for a parent that is both pruned from storage and evicted from the committed window, such that two honest nodes with different prune horizons and different admission times still produce byte-identical committed sequences (P3 of §3.2), and such that a vertex held for an unresolvable parent is bounded in bytes and per-author without its eviction key being anything the sender can inflate?**