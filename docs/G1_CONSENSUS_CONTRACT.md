# G1 Consensus and Retrieval Contract

> This is the proposed contract for release gate G1, "Consensus and retrieval" (`docs/PRODUCTION_READINESS_GOAL.md:35`). It was written read-only against commit `3550fa9` on `audit/mainnet-hardening`.
>
> - Nothing in this document is implemented, compiled, run or measured.
> - Every file:line citation was re-checked at `3550fa9`.
> - Citations inside `docs/DEFECT_REGISTER.md` are older. For example, the register cites `dag.rs:1167` for the equivocation `return`, which is now `dag.rs:1356`. Use the numbers in this document.
> - Its author took no code, git, push, deploy or node action.

> **Implementation status (2026-09-24).** S1 is implemented as a library in `consensus/consensus/src/vcert.rs`; S0 and S2–S11 are not. Nothing is wired: no ingress, production, ordering or recovery path calls it, and the release gate is unchanged at 7 red / 7 green.
>
> - **CE-2** `verify_vertex_cert` shares its stake and aggregate core with `qc::verify_qc` through the new `qc::verify_stake_aggregate`. `verify_qc`'s signature and behaviour are unchanged: an independent differential test against a verbatim copy of the old `verify_qc` found 0 divergences in 11,520 cases.
> - **AT-2** has two entry points. `attest_slot_in` runs inside the CALLER's transaction, which is what AT-2 requires ("in the same transaction that stages the body"); `attest_slot` wraps it in a transaction of its own. Either way a signature is released only after the guard row commits.
> - **CE-1** `CertCollector` counts only attestations of its own exact body, and records `ATTEST_EQUIV` evidence for any signer seen with two digests for one slot — whether or not either digest is its own, and whatever committee hash each claims. At most one pair per signer, so evidence is bounded by the committee size.
> - **Acceptance.** All ten S1 criteria have a test in `vcert/tests.rs`, including the exhaustive n=4 check (exactly one certificate in all 8 honest delivery orders, with the certificate count as an independent witness of the guard) and its negative control.
> - **Review.** Three independent adversarial reviewers (soundness, guard, contract conformance) attacked S1 before it was pushed. Their confirmed findings are fixed and each has a mutation-proven test:
>   - one datadir under two spellings opened two instances, so one key could sign twice — fixed in `StateDB::open` for every guard (`c2da08d`);
>   - `{cg}` was not injective (corrected above);
>   - the guard could not join a caller's transaction (now `attest_slot_in`);
>   - the same digest under another committee hash was reported as `Conflict` (now `CommitteeChangedWithinEpoch`);
>   - a guard row for another slot, or one that is not UTF-8, is refused (`InvalidGuard`) before anything is signed;
>   - evidence missed equivocations between two foreign digests and across committee hashes;
>   - a non-canonical bitmap length is refused (`NonCanonicalBitmap`).
> - **Beyond the contract.** A certificate or attestation whose author is not a committee member with positive stake is refused.
> - **Known limits, stated rather than tested.**
>   - The crash test kills the process with `exit(77)`, which keeps the OS page cache, so it cannot tell a synced guard write from an unsynced one. The write IS synced (`StateDB::transaction` → `write_durable`); proving it needs a power-loss harness.
>   - A set signer bit proves the member's *registered key* signed, not the member: validator join does not yet refuse a BLS key another member holds. Lemma U is unaffected. Nothing may read per-member attribution from a bitmap until join rejects duplicate keys (a staking change, outside G1).
>   - RC-3 guard continuity: `node.key` lives at `{datadir}/node.key` but the guard database is `{datadir}/validator_{port}.db`, so restarting with a different `--port` keeps the key and starts an empty guard. `consensus:guard_origin` must catch this when S2+ wires RC-3; the same hazard applies to the live `qc_signing` guard today.
> - **Still open inside S1's scope.** The durable `vcollect` rows (CE-1) and the `vcert` row (CE-3) are not written; the collector is in-memory. They land with the wiring in S2+.
---

## Status and scope

**Corrections from the independent math review (2026-09-29).** The review
(`docs/research/g1_math_review.md`, against Narwhal arXiv 2105.11827,
Bullshark arXiv 2209.05633, Sui Lutris and Diem/Aptos reconfiguration) found
the safety math sound and the liveness argument wrong in one place. Decisions,
taken by the implementer under the founder's delegation:

- **C1 (MAJOR, applied): `LEAD` bounds payload, not rounds.** PR-1, AT-1 and E5
  now let payload-free vertices advance past `cursor + LEAD`. Before, every
  round up to the cap could be proposed with no anchor supported, and the chain
  then could never move again. S10 adds LIV-1: a scheduler skips `LEAD/2 + 1`
  anchors before GST; after GST a direct commit follows within K rounds. GC-5's
  byte bound is over payload-bearing rounds.
- **C2 (MAJOR): epoch-boundary liveness assumptions**, added to the list:
  LA-10, C_E stays live until QC(H_E) forms and is served; LA-11, more than
  2/3 of T_{E+1} is synced at activation (a registration cutoff at H_E − K, as
  in Sui Lutris, if not); LA-12, the committee list itself travels with
  QC(H_E) for nodes that rejoin without executing (Diem's `next_epoch_state`).
- **C3: DE-2 counts votes with Q_E (2f+1), where Bullshark commits with f+1.**
  Kept as a deliberate strengthening: safe, and it keeps S4's bit-identity with
  today's ordering. Its cost is liveness: with one node down every online honest
  node must vote. Revisited only with S10's measurements.
- **C4: no member may hold a liveness veto.** A committee where one member has
  `3·s_i ≥ T` is refused at genesis and by EP-2 (the old committee carries over,
  with an alarm). Such a member halts the chain alone by crashing. Precedent:
  Sui caps a validator's voting power. LA-2 reads in stake terms.
- **C5: round numbering.** Slots are epoch-scoped, and anchor rounds are
  globally strictly increasing: every E+1 anchor round exceeds r*_E, because
  `anchor_already_on_chain` and `consensus:cseq:{anchor_round}` are round-only.
  S9's "first_round = r*+1 → overlap red" mutation is dropped (both values are
  safe); S9 instead injects epoch-E vertices at rounds r*+1 … r*+LEAD after
  activation and requires O_{E+1} unchanged. S9's replay mutation must run with
  C_{E+1} = C_E, or `committee_hash` masks it.
- **C6: Lemma U states its assumptions U1–U10**: the fault bound in floored
  weight units, committee agreement via `committee_hash`, stake recomputed from
  C_E, distinct signer entries (unique addresses: `canonical_order` is a stable
  sort), one durable digest per slot per key, signed fields taken from the
  validated body, BLS with verified PoPs and distinct domains, durable synced
  writes, exact arithmetic, and verification only against the certificate's own
  epoch committee.
- **C7: GC-3 deletes a closed epoch's rows by epoch**, so rows above the new
  floor do not leak (about LEAD × n per epoch).
- **C8: weak subjectivity** for rejoin across many epochs is an assumption,
  handed to G3 (checkpoints) and G5 (unbonding).
- **C9: the quorum is `3·stake(S) > 2·T`** (`qc::stake_quorum_met`), not the
  count formula `(n·2/3)+1` that CLAUDE.md stated: with unequal stake a count
  quorum lets 30% Byzantine stake certify twins.

**What this contract settles.** It answers the five items of required design work at `PRODUCTION_READINESS_GOAL.md:971-986` with one contract. The contract covers:

- equivocation;
- body and certificate retrieval;
- candidate and ancestry decisions;
- epoch and committee boundaries;
- garbage collection and retention;
- crash recovery;
- the second decision writer (sync import and follower adoption).

**What it does not settle.**
- **G0 block identity.** Witnesses B1 and B2 need `identity_v2` activation.
- **G3 state authentication.** This covers witnesses C1 and C2 (H6), H7 rejoin and Regime-C snapshot rejoin.
- **G4 transport authentication and resource isolation.** This contract depends on two things from G4, named under Assumptions: an authenticated session identity and reserved connection slots.
- **G5 slashing and economics.** This includes attester-equivocation slashing.
- **G2.** Anything beyond the acceptance transactions named here.

**Release-gate status, unchanged by this document.**
- The gate still fails on 7 of its 14 required witnesses.
- The red witnesses are:
  - H1 twin retention;
  - H2/H4 direct quorum;
  - equivocation liveness;
  - two legacy block-identity substitutions;
  - two H6 state-root witnesses.
- Evidence: `docs/RELEASE_SECURITY_GATE.md:46-57` and `scripts/release_security_witnesses.json:4-37`.
- This document belongs to the hardening checkpoint on `audit/mainnet-hardening`. It is not a release, not a mainnet-readiness claim, and not a plan approved for live nodes.

**Activation.**
- Every change here lands behind a V4 genesis format. It activates only in the one fresh genesis that `ParentRef` already requires (`DEFECT_REGISTER.md:587`).
- That same genesis also carries G0's `identity_v2` and the FinalityVote V2 field.
- No live node, deployment, genesis change or migration happens without the user's explicit approval (`PRODUCTION_READINESS_GOAL.md:12-15`).

---

## Route decision

**Decision.** Neither candidate route survived its attacks as designed. This contract adopts the **certified-DAG route (Narwhal-style certification feeding the existing Bullshark-lite ordering)**, repaired as specified below.

| Attack lens | Certified route (as designed) | Uncertified route (as designed) |
|---|---|---|
| Safety | **Survived, with MAJOR gaps:** epoch activation rested on a skippable executor rotation; I10 was not re-evaluated when the GC floor rises; the "stateless ingress" claim was overstated at epoch edges | **Survived, with MAJOR gaps:** the sync/adoption writer was underspecified; the epoch boundary was read from unbound header fields; two epoch numberings |
| Liveness | **Refuted (MAJOR):** QC-gated catch-up had no per-height QC transport; a node-wide serving bucket can be starved by one Byzantine node; the leader wait was assumed but never specified | **Refuted (FATAL):** the per-round wait timers its proof needs do not exist; one non-equivocating rushing Byzantine suppresses every two-level implicit certificate; its own model predicts a decided-rate of about 0.418, below the 0.42 floor |
| Recovery, epochs, pruning | **Refuted (MAJOR):** staging twins before readers are re-pointed is unsafe; a 3-twin slot leaves a permanent hole; guard continuity was assumed; round-only indexes collide after an epoch rewind; durable-boundary gaps | **Refuted (MAJOR):** it read the committee from executor snapshots that are deleted after 8 epochs; sync carries no per-block QC; its first increment was underspecified; the checkpoint boot path bypasses ingress; step 2 alone breaks the floor |

**Why the certified route is chosen.**

1. **It supplies premises; it does not invent a decision rule.**
   - Bullshark's ordering assumes three properties of its DAG (Bullshark §2.1): non-equivocation, reliable delivery, and complete causal histories.
   - AINCORE's `prepare_commit` has Bullshark's shape (`ordering.rs:559-645`) but runs on fire-and-forget gossip that provides none of the three. The missing primitive has already been named as Byzantine Consistent Broadcast (`DEFECT_REGISTER.md:657-664`).
   - Certification plus retrieval is how Narwhal supplies those premises (Narwhal §3.1, §4.1).
   - Seven home-grown decision rules in this family were refuted. H3 closed only when the *data format* changed (`DEFECT_REGISTER.md:573-596`).
   - This route changes the data the decision function receives. The decision function itself stays essentially the one that is already instrumented and measured.
2. **The uncertified route's failure is structural and costly to repair.**
   - Its direct commit needs *two* levels of support: votes at r+1, then implicit certificates at r+2.
   - Producers today sign at their first parent quorum (`dag.rs:713-748`, `:784`). A Byzantine node that simply delivers its non-supporting r+1 vertex first sits inside every honest r+2 parent set. That removes every implicit certificate, without any equivocation.
   - Repairing this needs Mysticeti-style timeouts at every round, plus the whole Mysticeti decision procedure re-derived for stake weights and AINCORE's stricter validity rules. That is new timing machinery that is unproven in this codebase.
3. **The certified route's failures are plumbing, not core.**
   - Its failures were catch-up, retrieval budgets, leader-wait and epoch plumbing.
   - Its own liveness attacker concluded the repairs "do not touch the safety core (Lemmas U and P, D1-D5)".
4. **No reference system tie-breaks between twins; certification makes the question unreachable.**
   - Every system that keeps twins pairs them with a pull client (`DEFECT_REGISTER.md:648-656, :666-670`).
   - Under certification, at most one twin per slot can ever become orderable (Lemma U below).

**The uncertified route's strongest point, stated fairly.**
- **Cheaper.** It needs no new vote message and no extra hops. A vertex is citable after one hop instead of three, and a round costs 12 point-to-point messages instead of about 36 at n=4, with no per-round BLS work.
- **Better on the existing witnesses.** Because it reads support from each voter's *own signed parent references*, it flips A1 and A2 unmodified, and A2 non-vacuously.
- **What this contract takes from it.** That last property is adopted here (rule DE-2). Under this contract A2 also flips unmodified and non-vacuously; see the witness mapping.
- **Why its cost advantage matters less than it looks.**
  - The producer runs once per consensus tick, which defaults to 3000 ms (`core/node/src/main.rs:633-637, :676-685`).
  - Attestation and certificate formation here are event-driven, not tick-driven.
  - So on a LAN the extra two hops land inside the same tick. The added cost is BLS and fsync work, which must be measured on the slowest validator (stage S10).

**Repairs incorporated (traceability).**

| Attack finding | Resolution in this contract |
|---|---|
| Certified-safety M1: epoch activation depends on `rotate_validator_epoch`, which only runs if Move `advance_epoch` succeeds (`core/executor/src/lib.rs:1263-1291`); epoch = height/interval | Consensus-owned epoch rows (EP-1..EP-4). The committee is derived and validated in the acceptance transaction, with carry-over when validation fails. Activation needs QC(H) binding `next_validator_set_hash`. Consensus no longer reads executor epoch rows. **Checked:** M1(b)'s crash window does not exist, because rotation puts are staged in the block transaction (`executor lib.rs:1737-1747, :2122`). |
| Certified-safety M2: a child whose parent falls under the GC floor waits forever | OR-3: re-run the orderability check on every increase of the floor g. The "settled" test also uses the parent's declared round. |
| Certified-safety M3: "stateless" is overstated at epoch edges | IN-1: two-layer ingress. Layer S is stateless given the epoch record. Layer E can only yield PENDING, STALE or DROP, never INVALID. Epoch-edge witnesses are added. |
| Certified-liveness 1: no per-height QC transport, and a circular dependency via D8 | IM-4: SYNC_RESP carries per-block QCs, which are retained as long as blocks are. The durable QC retry worker already exists (`qc_producer/recovery.rs:97-161`). Committee transitions are authenticated through the QC chain (EP-4). |
| Certified-liveness 2: one Byzantine node starves a node-wide serving bucket | RE-6: per-member reserved budgets keyed on authenticated identity (G4 dependency), and parallel fetch from all signers for blocking digests. |
| Certified-liveness 3: T_LEADER was never specified | PR-3: an explicit leader-wait rule. Producers cite *all* held certificates. |
| Certified-liveness 4: transactions dropped at epoch close | EP-4: each author returns its own uncommitted epoch-E payloads through `return_unshipped` (`core/mempool/src/lib.rs:720`). The residual gap is under Open questions. |
| Certified-recovery 1: staging twins while `round_index`/`dag` readers are unchanged | V4-only wiring. `round_index` becomes the certified orderable index, written by one function (OR-1). Every reader is re-pointed in the same increment (S5), and a twin-flood witness is added. |
| Certified-recovery 2: a certified third twin cannot be staged | ST-2 certified-body reservation, fetch installs it regardless of arrival order, and a 3-twin witness. |
| Certified-recovery 3: guard rows lost after a restore or wipe | RC-3: continuity marker, abstain for the rest of the epoch, and an operating rule. |
| Certified-recovery 4: round-only indexes collide after an epoch rewind | Every durable key carries E. In-memory per-epoch state is reset on activation. Epoch classification runs before any round-relative check. |
| Certified-recovery 5: durable-boundary gaps | `vproposed` is written in the proposal transaction. Deletes are by range. Epoch and committee rows are never deleted. `committed_set` is kept by round instead of FIFO. BLS keys with PoP are required, with carry-over otherwise. |
| Uncertified-recovery 1: the committee is read from snapshots that the executor deletes | C_E is read from consensus-owned rows (`consensus:dag_committee:{E}`) that are never deleted. |
| Uncertified-recovery 4: the checkpoint boot path bypasses ingress (`dag.rs:148-302`) | RC-1: V4 boot populates only from `vslot` and `vcert` rows, through the ingress predicates. |
| Uncertified-recovery 6: epoch-less evidence key | `sys:equiv_seen:{offender}:{E}:{round}`. |
| Uncertified-safety M1/M2: second writer and header-derived epoch boundary | IM-1..IM-3: QC-gated import and adoption in one transaction. The boundary round r* comes only from the local decision record or from `QC.anchor_round`. |

---

## Assumptions

**Safety. No timing assumption is needed for safety.**
- **SA-1 (fault bound).** In every epoch E whose certificates or QCs a node accepts, Byzantine stake β_E is strictly less than T_E/3, where T_E is the total stake of the frozen committee C_E. Stake distribution is arbitrary.
- **SA-2 (committee agreement).** Two parts:
  - C_0 is the genesis-frozen `genesis:validator_set:v1` (`qc_producer.rs:104-118`).
  - For E > 0, an honest node uses C_E only if a verified QC of epoch E−1, for the boundary block, binds `validator_set_hash(C_E)` (EP-4).
  - Committee agreement therefore follows from SA-1 in epoch E−1 plus QC uniqueness. It does not depend on deterministic execution.
- **SA-3 (cryptography).**
  - SHA-256 is collision resistant.
  - Ed25519 is EUF-CMA secure.
  - BLS12-381 keys are registered with proof-of-possession: at genesis (`core/node/src/genesis.rs:216`) and at join (`executor lib.rs:208, :3509`).
  - BCS encoding is canonical.
- **SA-4 (durability).**
  - A synced write survives a crash (`common/storage/src/transaction.rs:148-152, :288`).
  - A validator's guard rows (`vattest`, `vproposed`, `qc_signing`) are never lost while its key is in use.
  - A key never runs on two databases.
  - A detectable loss triggers abstention (RC-3). An undetectable loss, such as a restore from backup or a cloned key, is Byzantine behaviour and counts toward β.
- **SA-5 (single format).** A V4 chain runs only V4 rules from genesis. There is no mixed V3/V4 operation.

**Liveness.**
- **LA-1 (partial synchrony).**
  - After an unknown GST, honest-to-honest messages and request/response exchanges complete within Δ.
  - Before GST, links are fair-lossy: resends are eventually delivered.
  - Resends use TCP, because gossip suppresses byte-identical payloads for 60 s (`core/node/src/p2p.rs:119-123`).
- **LA-2 (connectivity).** More than 2/3 of stake is honest, online, mutually connected and addressable. At n=4 with equal stake that means 3 nodes, with zero slack.
- **LA-3 (timing).**
  - `T_LEADER` is at least the slowest honest validator's certification latency (about 3Δ plus two fsyncs plus BLS work).
  - The tick is at least that latency.
- **LA-4 (clocks).** Honest clocks agree within 30 s (`dag.rs:1141-1151`).
- **LA-5 (transport, a G4 dependency).**
  - An adversary cannot exhaust an honest committee member's reserved serving budget or connection slots.
  - This requires two G4 changes:
    - HELLO must be verified before any non-HELLO frame is dispatched. Today non-HELLO frames reach the handler unconditionally (`common/network/src/lib.rs:364-374`).
    - The verified peer identity must be passed to the handler.
  - The accept-slot exhaustion in P2-G (`DEFECT_REGISTER.md:35`) must also be closed.
- **LA-6 (catch-up path).**
  - A lagging honest node is within `GC_DEPTH + RETAIN_SLACK` rounds of the network, or it catches up by QC-gated block sync within block retention.
  - Beyond block retention it needs G3 state rejoin (H7).
- **LA-7 (execution).** Honest nodes execute identical blocks identically (G3/G5). A violation halts QC formation and epoch activation; it never forks.
- **LA-8 (leader schedule).**
  - Leaders are a predictable SHA-256 draw weighted by stake (`ordering.rs:1018-1064`), the documented H-2 trade-off.
  - Progress is probabilistic.
  - There is no claim under targeted denial of service against upcoming leaders.
- **LA-9 (capacity).**
  - Disk holds the bounds in GC-5.
  - The committee has at most 256 members (`MAX_PARENTS`, `dag.rs:40`).

---

## Definitions

- **Committee C_E.**
  - A list of `ValidatorInfo` entries: address, stake, `ed25519_public_key`, `bls_public_key`, `bls_pop` (`qc.rs:29-37`).
  - Canonical order is by address (`qc.rs:140-144`). T_E is the sum of stakes.
  - C_0 comes from `genesis:validator_set:v1`. C_E for E > 0 comes from `consensus:dag_committee:{E}` (EP-2).
- **Quorum.**
  - Q_E(S) holds when `3 · stake_E(distinct members of S) > 2 · T_E`. This is `qc::stake_quorum_met` (`qc.rs:194-196`).
  - Every quorum in this contract counts distinct authors or signers.
- **Epoch of a block.**
  - E(h) = ⌊(h−1)/I⌋ for h ≥ 1. I is the genesis-pinned, immutable epoch interval (`sys:config:epoch_block_interval`, `genesis.rs:16-20`).
  - The boundary block of epoch E is H_E = (E+1)·I, the last block of E.
- **Round.**
  - Rounds are counted per epoch.
  - `first_round(0) = 1`, and `first_round(E+1) = r*_E + 2` (EP-3).
  - Anchor rounds are even rounds r ≥ max(first_round(E), 2).
- **Slot.** (E, r, a). A **twin** is a second distinct digest validly signed by `a` for the same slot.
- **V4 vertex.** The `Vertex` struct (`blockchain/src/lib.rs:333-374`) plus a signed `epoch: u64` field. Its **digest** is `hash_v4` (see Messages and durable state).
- **Staged body.**
  - A validly signed V4 body, persisted under `vertex:{digest}` and listed in `consensus:vslot` for its slot.
  - Staging never implies orderability.
  - In memory, `DagConsensus::dag` (`dag.rs:54`) holds staged bodies.
- **Attestation.** A BLS signature by a committee member over `ATTEST_DOMAIN ‖ BCS(AttestBody)`.
- **Certificate.** An aggregate of attestations over one `AttestBody` whose signers satisfy Q_E, verified against C_E. The **certified digest** of a slot is the digest of its unique certificate (Lemma U).
- **Orderable vertex.**
  - A certified vertex whose body is held and whose parents are all orderable or settled (OR-1).
  - The **orderable index** O_E maps round → at most one digest per author.
  - In V4 `DagConsensus::round_index` (`dag.rs:55`) holds O_E, and OR-1 is its only writer.
- **Leader.** λ_E(r) = `leader_for_round(r, C_E stakes, 0)` (`ordering.rs:1018-1064`), evaluated over the frozen committee.
- **Candidates.** Cand(r) = { d ∈ O_E[r] : author(d) = λ_E(r) }.
- **Vote.**
  - For u ∈ O_E[r+1], vote(u) is the digest of the first element of `u.parent_refs`, in u's signed order, whose author is λ_E(r). It is empty if there is none.
  - A vote is read from the voter's own signed bytes, never from a DAG lookup.
- **GC floor g.** `consensus:gc_floor`. It is a pure function of the committed prefix (GC-1).
- **Settled parent.** A parent p of a vertex being walked is settled iff one of these holds:
  - p is an epoch sentinel;
  - p's round, as declared in the child's authenticated `ParentRef`, is ≤ g;
  - p ∈ `committed_set`.
- **Anchor status.** For an anchor round: `Commit(d)`, `Skip`, or `Undecided`.

---

## Messages and durable state

**Constants.** Pinned by the V4 genesis unless marked local.

| Name | Value | Notes |
|---|---|---|
| `VERTEX_FORMAT` | 4 | Genesis-pinned. One DAG format per chain. |
| `GC_DEPTH` | 50 rounds | Consensus rule (GC-1). |
| `RETAIN_SLACK` | 50 rounds | Serving obligation (GC-3). |
| `I` (epoch interval) | ≥ 1000 blocks recommended | Immutable; excluded from governance. Today's default is 20 (`executor lib.rs:1185`). See Open questions. |
| `MAX_STAGED_PER_SLOT` | 2 | Includes the certified reservation (ST-2). |
| `PENDING_MAX_PER_AUTHOR` | 16 vertices | Evicts the highest round first. |
| `B_AUTH` (local) | 64 MiB per author | Only for bodies that are neither certified nor self-attested. |
| `LEAD` (local) | 200 rounds | Payload back-pressure above this node's cursor (PR-1). Rounds are not capped (Correction C1). |
| `T_LEADER` (local) | ≥ measured certification latency; default 2 ticks | Liveness only. |
| `T_RETRY`, `T_FETCH` (local) | 1 tick; fetch backoff doubling to 8 ticks | Driven by the receiver's clock. |

**The V3 path refuses V4 fields.** A V3 vertex with `epoch ≠ 0` or any `ParentRef.cert` is refused at V3 ingress (`dag.rs` `add_vertex`): the V3 hash binds neither, so a relay could otherwise pad an honest vertex for every node to store (S2 review HIGH-1). V4 equivocation evidence uses `Vertex::to_compact_proof_v4`, whose carried parents root is the V4 one (S2 review MEDIUM-2).

**Signed-bytes domains.** Every new signed message is `DOMAIN ‖ BCS(struct)`, as for FinalityVote (`qc.rs:56-66`).

| Domain | Use |
|---|---|
| `AINCORE_VERTEX_V4` | Vertex hash (V3 is `AINCORE_VERTEX_V2`, `blockchain/src/lib.rs:664`). |
| `AINCORE_PARENTS_V4` | Parents root. Same layout as `parents_root_of` (`lib.rs:492-509`); V3 is `AINCORE_PARENTS_V3`, `:494`. |
| `AINCORE_VERTEX_ATTEST_V1` | Attestation (BLS, `BLSEngine::consensus()`). 24 bytes, differing from `AINCORE_FINALITY_VOTE_V1` (`qc.rs:25`). |
| `AINCORE_FINALITY_VOTE_V2` | FinalityVote with `next_validator_set_hash` (IM-5). |
| `AINCORE_EPOCH_GENESIS_V1` | Epoch sentinel. |

**Types.**
- `hash_v4(v) = hex(SHA256(AINCORE_VERTEX_V4 ‖ put(chain_id) ‖ put(genesis_identity) ‖ epoch_be8 ‖ round_be8 ‖ put(author) ‖ put(parents_root_v4) ‖ agg ‖ timestamp_be8 ‖ put(payload_root)))`, where `agg` is `0x00` when `aggregated_signature` is absent and `0x01 ‖ put(aggregated_signature)` when present.
  - *(Corrected at S2: the first text, `put(aggregated_signature or "")`, hashed an absent aggregate and an empty one alike, the same non-injective class as FX-18. The S2 codec test caught it.)*
  - `put` means a u64 big-endian length prefix, as in `calculate_hash_with_domain` (`lib.rs:658-681`).
  - The Ed25519 signature is still over the hash hex (`lib.rs:602-606`).
- `ParentRef` keeps its hashed fields `{round, author, digest}` (`lib.rs:404-423`). It gains a *transport* field `cert: Option<CompactCert>`, which is not hashed.
  - `CompactCert = {signer_bitmap, aggregate_signature}`.
  - The body and the stakes are reconstructed from the child's epoch, the ref and C_E.
  - `ParentIdentityProof` (`lib.rs:425-482`) is no longer admission evidence. A certificate authenticates (E, round, author, digest) with more than 2T/3 stake of attesters.
- `EPOCH_GENESIS(0) = "genesis"`.
  - `EPOCH_GENESIS(E>0) = hex(SHA256(AINCORE_EPOCH_GENESIS_V1 ‖ put(chain_id) ‖ put(genesis_identity) ‖ E_be8 ‖ first_round(E)_be8 ‖ put(block_hash(H_{E−1})) ‖ put(anchor_hash(A*_{E−1}))))`.
- `AttestBody = {chain_id, genesis_identity, epoch, round, author, digest, committee_hash}`, with `committee_hash = qc::validator_set_hash(C_E)` (`qc.rs:162-166`).
  - `VertexAttestation = {body, signer, signature}`.
- `VertexCertificate = {version: 1, body: AttestBody, signer_bitmap, signed_stake, total_stake, aggregate_signature}`.
  - The bitmap is over `canonical_order(C_E)`.
- `FinalityVote V2` = the fields at `qc.rs:42-54`, plus `next_validator_set_hash = validator_set_hash(C_{E(h+1)})`.

**Wire messages.**

| Message | Transport | Sender → receiver | New? |
|---|---|---|---|
| `DAG_VERTEX:{VertexV4}` | Gossip + TCP fan-out (`dag.rs:2003-2040`) | Author → all | Format change |
| `DAG_ATTEST:{VertexAttestation}` | TCP (`network::send_message`) | Attester → author | New |
| `DAG_CERT:{VertexCertificate}` | Gossip + TCP fan-out | Author → all; also embedded in child refs | New |
| `EQUIV_PROOF:{offender, epoch, round, vertex_a, vertex_b}` | As today (`dag.rs:2485-2524`) | Any → all | Epoch added |
| `ATTEST_EQUIV:{att_a, att_b}` | Gossip | Any → all | New (evidence only) |
| `QC_VOTE:{QcVoteMessage}` | As today (`dag.rs:2582-2615`) | Validator → all | Vote V2 |
| `VERTEX_REQ` / `VERTEX_RESP` | Request/response over `secure_connect` (`sync/src/lib.rs:27-42, :1268-1276`) | Fetcher → signer | **Client is new** |
| `CERT_REQ{epoch, slots≤64}` / `CERT_RESP{certs, unknown}` | Request/response | Any → member | New |
| `ATTEST_REQ{vertex}` / `ATTEST_RESP{attestation \| conflict \| pending}` | Request/response | Author → member | New |
| `SYNC_REQ` / `SYNC_RESP` | As today (`sync:161-179, :1366-1403`) | — | Adds `qcs: Vec<QuorumCertificate>`, one per block, `#[serde(default)]` |

**Durable keys.** Every write goes through `StateDB::transaction` (`common/storage/src/transaction.rs:245-290`) unless marked unsynced. `{cg}` is `hex(SHA256(put(chain_id) ‖ put(genesis_identity)))`, with `put` the u64 big-endian length prefix used throughout this contract. *(Corrected 2026-09-24: this contract first specified `chain_id ‖ 0x00 ‖ genesis_identity`, which is not injective once either string contains 0x00 — ("X\0Y", "Z") and ("X", "Y\0Z") hash the same bytes, so two chains would share one guard row. It is the same class of defect as the legacy block-header hash.)*

| Key | Value | Written | Deleted |
|---|---|---|---|
| `vertex:{digest}` | Staged body (existing key) | ST-1 | GC-3 |
| `consensus:vslot:v1:{E:020}:{r:020}:{author}` | Up to 2 `{digest, role ∈ staged/certified/self}` | ST-1 | GC-3 |
| `consensus:vattest:v1:{cg}:{bls_pk}:{E}:{author}:{r:020}` | VertexAttestation (**attestation guard**) | AT-2, before the signature leaves the process | GC-3 |
| `consensus:vproposed:v1:{cg}:{ed25519_pk}:{E}:{r:020}` | Digest (**producer guard**) | PR-4, in the proposal transaction | GC-3 |
| `consensus:vcert:v1:{E:020}:{r:020}:{author}` | VertexCertificate (at most 1) | CE-3 (may be unsynced) | GC-3 |
| `consensus:vcollect:v1:{E}:{r}:{author}:{digest}:{signer}` | Signature (author side) | CE-1 (unsynced) | GC-3 |
| `consensus:dag_committee:{E}` (E > 0) | Canonical `Vec<ValidatorInfo>` | EP-2, boundary acceptance transaction | Never |
| `consensus:epoch_start:{E}` | `{H_{E−1}, r*, anchor_digest, block_hash, first_round, committee_hash}` | EP-3, same transaction | Never |
| `consensus:epoch_active` | E | EP-4 activation transaction | — |
| `consensus:gc_floor` | g (monotone) | DE-6, acceptance transaction | — |
| `consensus:anchor_decision:{E}:{r:020}` | `C:{digest}` or `S` (write-once) | DE-6, acceptance transaction | With blocks |
| `consensus:cseq:{anchor_round}` | `[(digest, round)]` (extends today's format) | DE-6 | When anchor_round ≤ g |
| `consensus:qc:{h}` | QC (existing, `qc_producer.rs:391-419`) | As today | With `block_{h}` |
| `consensus:guard_origin` | `{cg, node_ed25519_pk, bls_pk}` | Genesis init or first key use | Never |
| `sys:equiv_seen:{offender}:{E}:{round}` | Evidence (epoch added to `dag.rs:2406`) | EQ-1 | As today |
| `alarm:vcert_conflict:{E}:{r}:{a}`, `alarm:decision_conflict:{h}`, `alarm:committee_mismatch:{E}` | Diagnostic | On detection | Never |

**Derived in-memory state, rebuilt at boot and never authoritative.**
- `dag`: the staged bodies.
- `round_index`: O_E for the active epoch.
- A certificate index, (E, r) → author → (digest, CompactCert).
- A waiting map, parent → children.
- A pending buffer.
- A fetch queue.

---

## Rules

### Ingress (IN)

Verdicts:
- **INVALID**: drop this copy. It never feeds a ban, a peer score or a slash (`DEFECT_REGISTER.md:80`). Every verdict is about the copy, never keyed by digest: a relay can alter the unhashed transport fields of an honest vertex.
- **DROP**: timing only. The vertex can be obtained again.
- **PENDING(epoch|cert)**: kept in a bounded buffer and re-evaluated on a trigger.
- **STALE**: used as evidence only.
- **STAGE**.

No rule concludes that a digest does not exist (`DEFECT_REGISTER.md:750`).

**IN-1 (two layers).** Checks run cheapest first.

- **Layer S (stateless given the record of the vertex's own epoch E).** Every node that holds that record reaches the same verdict. E1 picks the record (E_active − 1, E_active or E_active + 1) before S3–S6 run under it, so no vertex is kept, pending or stale, before it is authenticated (S2 review MEDIUM-1).
  - S1: raw size ≤ `MAX_VERTEX_BYTES`, checked before parsing (`dag.rs:2681`).
  - S2: `is_live_form`; `aggregated_signature` is `None`; parents ≤ `MAX_PARENTS`; parent digests unique (`dag.rs:1185-1220`).
  - S3: `v.hash == hash_v4(v)`.
  - S4: the author is in C_E with stake > 0, and the Ed25519 signature (canonical lowercase hex) verifies under `C_E[author].ed25519_public_key`. This replaces the live account lookup (`dag.rs:1158`, `:2114-2161`) and live membership (`dag.rs:1262-1273`).
  - S4b: every `ParentRef` names a member of C_E with stake > 0 and a canonical 64-character lowercase-hex digest. A ref no certificate could ever satisfy is refused, not left pending (S2 review LOW-1). A ref carrying a V3 `ParentIdentityProof`, or a certificate of the wrong shape, is refused for that copy (S2 review 2).
  - S5: `first_round(E) ≤ v.round ≤ ABSOLUTE_ROUND_CEILING` (`dag.rs:1107`).
  - S6: if `v.round == first_round(E)`, then `parents == [EPOCH_GENESIS(E)]` and `parent_refs` is empty. Otherwise `qc::parent_refs_admissible(v, C_E)` applies, with its four clauses unchanged (`qc.rs:243-311`). The only edit is that its round-≤1 exemption (`qc.rs:247-249`) becomes `round == first_round(E)`.
  - Any failure → INVALID.
- **Layer E (context).** Outcomes are only PENDING, STALE, DROP or STAGE. This layer never returns INVALID.
  - E1 epoch (runs first, and selects the record Layer S uses):
    - E = E_active → continue under C_E.
    - E = E_active + 1 → Layer S under C_{E+1} (recorded with H_E), then PENDING(epoch). Before C_{E+1} is recorded → DROP.
    - E = E_active − 1 → Layer S under C_{E−1}, then STALE. Without that record → DROP.
    - Any other E → DROP.
    - A vertex of E_active above its closing round r* (once known) → STALE (EP-5).
  - E2 clock: `timestamp > now + 30 s` → DROP. Today this is a hard reject (`dag.rs:1141-1151`); here it is timing only.
  - E3 floor: `v.round ≤ g` → STALE.
  - E4 parent certificates (for `round > first_round(E)`):
    - For each ref, take the embedded `CompactCert`, or else the local `vcert` for (E, ref.round, ref.author) with the ref's digest. Verify it with CE-2 (results are cached).
    - A missing or invalid certificate → PENDING(cert), and send `CERT_REQ`.
    - An invalid *embedded* certificate never makes the vertex INVALID. It is an unhashed transport field that any relay can corrupt.
  - E5 back-pressure: `v.round > cursor + LEAD` **and the vertex carries payload** → DROP. A payload-free vertex is never dropped for its round (Correction C1), but past the lead it is staged only when every parent certificate already verifies; otherwise DROP, with no PENDING and no CERT_REQ (S2 review MEDIUM-3).
  - No parent **body** is ever required.
- **Run order.** Epoch classification (E1) runs before any round-relative check. The single-vertex round-jump check (`dag.rs:1126`) is removed. Its role is taken by E4 (a vertex above the certified frontier stays PENDING) and E5.

**IN-2.** A fetched body goes through exactly the same IN-1 path as a gossiped one. Boot recovery also re-runs Layer S (RC-1).

### Staging (ST)

**ST-1 (stage, don't order).** This replaces the `return` at `dag.rs:1356` and the three boot refusals at `dag.rs:263-274`, `:337-348` and `:395-406`. It runs as one transaction, with S = `vslot(E, r, author)`:
- digest ∈ S → no-op;
- |S| < 2 → put `vertex:{digest}`, append the digest to S, commit;
- otherwise apply ST-2.

**ST-2 (certified reservation).**
- If |S| = 2 and the digest is the slot's certified digest, evict the member of S that is neither self-attested nor certified, then insert the digest with role `certified`.
- At most one member can be self-attested (AT-2), and it cannot be the certified digest (otherwise that digest would already be in S), so an evictable member always exists.
- Any other third digest → evidence only, with no body stored (P2-C, `DEFECT_REGISTER.md:31`).
- A certified digest is always installable, whatever order bodies arrive in.

**ST-3 (bounds).**
- Bodies that are neither certified nor self-attested count against `B_AUTH` for their author. Over budget → evidence only.
- The PENDING buffer holds at most `PENDING_MAX_PER_AUTHOR` vertices per author and evicts the highest round first.

**ST-4.** Staging never writes to O_E. Only OR-1 does.

**S3 implementation notes** (`consensus::staging`, unwired until S5):
- `stage_in` runs inside the caller's transaction, so staging, the node's own attestation guard (RC-2) and the plain-body counter commit or abort together. `stage` is the stand-alone form.
- Slot rows: `consensus:vslot:v1:{E:020}:{r:020}:{author}` hold up to two `{digest, role, bytes}`. The plain-body counter per author and epoch is `consensus:vbytes:v1:{E:020}:{author}`. All are Local keys.
- ST-2 eviction: of two plain members the greater digest is evicted, so the choice is the same after every restart. The evicted body is deleted and its bytes released. A second certified digest for a slot is evidence only (and an alarm at S5, `alarm:vcert_conflict`).
- A body certified or self-attested after it was staged is promoted in place, and its bytes leave `B_AUTH`.
- Boot (`load`) is RC-1 steps 2 and 3: every slot entry of the epoch above `g − RETAIN_SLACK`, each re-checked with Layer S (both twins, no load-order dedup), plus the epoch's `vcert` rows that verify. Step 4, O_E through OR-1, is S5.

### Attestation (AT)

**AT-1 (preconditions).**
- self ∈ C_E with stake > 0.
- E = E_active.
- g < v.round, and v.round ≤ cursor + LEAD unless v is payload-free (Correction C1).
- IN-1 passed, including verification of every parent **certificate**.
- The derived BLS key equals `C_E[self].bls_public_key`. Otherwise skip and log, as QC production does (`qc_producer.rs:286-296`).
- Guard continuity holds (RC-3).
- Parent validation means verifying parent *certificates*, as in Narwhal §3.1 condition 3. It does not mean holding parent bodies:
  - a certificate already guarantees more than T/3 of honest durable holders (Lemma A);
  - requiring possession would add a dependency on local holdings, the class of rule that measured 0.3914 at ingress (`qc.rs:204-208`).

**AT-2 (durable guard, one per slot).**
- In the same transaction that stages the body, read G = `vattest(E, author, r)`:
  - G exists with a different digest → refuse, and answer `conflict(G)`;
  - G exists with the same digest → reuse its signature;
  - no G → sign `ATTEST_DOMAIN ‖ BCS(AttestBody)` and put G.
- Only after the commit returns is the attestation sent: `DAG_ATTEST` to the author, or as the `ATTEST_RESP`.
- This follows the `qc_signing` pattern (`qc_producer.rs:298-336`) but keys on epoch and author, which that key lacks (`:373-377`).

**AT-3.** The first staged digest of a slot is the one attested (Narwhal §3.1 condition 4). This governs *signing*, never *deciding*.

### Certificates (CE)

**CE-1 (formation).**
- The author verifies each attestation against `C_E[signer].bls_public_key` and requires the body to equal its own `vproposed` digest.
- It records the attestation in `vcollect`.
- When Q_E(signers) holds, it aggregates in canonical order, runs CE-2, puts `vcert` and broadcasts `DAG_CERT`.
- A signer seen with two digests for one slot → `ATTEST_EQUIV`.

**CE-2 (`verify_vertex_cert`).** Checks, in order:
1. chain and genesis;
2. the bitmap is non-empty and in range;
3. signed and total stake recomputed from C_E;
4. Q_E;
5. `committee_hash == validator_set_hash(C_E)`;
6. `fast_aggregate_verify`.

This is the core of `verify_qc` (`qc.rs:338-425`) refactored into one shared verifier used by both certificate kinds.

**CE-3 (ingest).**
- No certificate for the slot → put it.
- Same digest → no-op.
- A different digest → write `alarm:vcert_conflict`, keep both certificates as accountability evidence, and **halt ordering**. The node never chooses between them.
- Then run OR-1 for the digest. A missing body → fetch (RE).

### Orderable index (OR)

**OR-1 (single writer).**
- A digest d becomes orderable iff:
  - the slot's `vcert` digest is d;
  - d's body is staged;
  - `round(d) == first_round(E)`, or every parent p is orderable or has declared round ≤ g.
- On insert: set `O_E[round][author] = d`, wake the waiting children, and run the ordering loop (`dag.rs:1462`).

**OR-2 (assertion).**
- Every digest in O_E has a verified certificate, and no author appears twice in any `O_E[r]`.
- This is checked in debug and test builds and on every boot. A violation → alarm and halt.

**OR-3 (floor re-check).** Every increase of g re-evaluates every waiting vertex. This answers certified-safety M2.

### Production and round advance (PR)

**PR-1 (round).**
- The current round is `max(first_round(E), 1 + max{r : held certificates for (E, r) come from authors satisfying Q_E})`.
- This replaces `quorum_round` over held bodies (`dag.rs:631-663`, `:1419-1428`).
- Above `cursor + LEAD` a node proposes only payload-free vertices: rounds keep advancing, payload waits (Correction C1).

**PR-2 (when to propose).** At a tick, propose round r iff all of the following hold:
- self ∈ C_E and E is active;
- guard continuity holds;
- `vproposed(E, r)` is absent;
- certificates for (E, r−1) from a Q_E set of authors are held (or r = `first_round(E)`);
- PR-3 is satisfied.

**PR-3 (leader wait).**
- If r−1 is an anchor round and `cert(λ_E(r−1))` is not held, wait until it is held, or until `T_LEADER` has passed since the quorum at r−1 was first held (local monotonic clock).
- This rule exists nowhere today. `try_create_vertex` signs at first quorum (`dag.rs:713-748`, `:784`).

**PR-4 (parents and atomic proposal).**
- Parents are **all** certificates held for (E, r−1), one per author (the certified digest), sorted by author, each with a `CompactCert`. The first round cites `EPOCH_GENESIS(E)`.
- Payload, evidence carriage and the byte budget are as today (`dag.rs:785-880`).
- One transaction stages the node's own body, writes `vproposed(E, r)` and writes its own `vattest`. Only then is `DAG_VERTEX` broadcast.
- Until the vertex is certified, the node sends `ATTEST_REQ` over TCP every `T_RETRY` to members missing from `vcollect`.
- This replaces:
  - the `round_index` parents (`dag.rs:669-675`);
  - the live set (`dag.rs:692`);
  - `latest_proposed_round`, written after broadcast with its result ignored (`dag.rs:915-917`);
  - push re-gossip (`dag.rs:1044-1088`).

### Decision (DE)

The decision is Bullshark-lite over O_E. `prepare_commit`, `direct_quorum_met` and `leader_vertex_hash` keep their signatures (`ordering.rs:559-568`, `:659-664`, `:675-682`), so the tier-1 harness and corpus stay comparable.

**DE-1 (candidates).**
- Cand(r) as defined above.
- Under V4, |Cand(r)| ≤ 1 (Lemma U and OR-2).
- The set form exists so that inputs violating that precondition fail safe.
- The `find_map` choice by arrival order (`ordering.rs:666-670`) is removed.

**DE-2 (support).**
- support(d) is the stake of distinct authors a that have exactly one vertex u in O_E[r+1] with vote(u) = d.
- Direct(r) is the d ∈ Cand(r) with Q_E(support(d)). There is at most one such d (Lemma V).
- `direct_quorum_met` returns `Q_E(support(anchor_hash))`, replacing `any(p == anchor_hash)` at `ordering.rs:691`.

**DE-3 (scan).**
- The direct anchor (r_D, d_D) is the smallest anchor round r ≥ cursor, with r < max(O_E), for which Direct(r) is defined.
- If there is none → Undecided, and nothing is written.

**DE-4 (walk back).** Set `chain := d_D`. For each anchor round j from r_D − 2 down to the cursor:
- H := the walk from `chain` to floor j, descending only into non-settled parents. A non-settled parent missing from O_E → Undecided. OR-1's down-closure makes that unreachable; it is kept as a guard.
- CandH(j) := {h ∈ H : round(h) = j ∧ author(h) = λ_E(j)}.
  - Exactly 1 → Commit(h), and `chain := h`.
  - 0 → Skip(j). This is a proof: H is the complete certified history above g.
  - 2 or more → Undecided, with an alarm (unreachable under Lemma U).
- This replaces `Some(hj) if visited.contains(&hj)` and `_ => {}` (`ordering.rs:616-626`).

**DE-5 (emit).**
- Emit the lowest decided anchor, one per call (`ordering.rs:629-642`).
- Its sequence is its history above g minus `committed_set`, sorted by (round, digest) (`find_causal_history`, `ordering.rs:1066-1111`, with floor g).
- `prepare_one_anchor`'s walk floor of 0 (`ordering.rs:754-760`) becomes g.
- The sort linearizes a set that is already agreed; it chooses nothing.

**DE-6 (persist).** The acceptance transaction (`dag.rs:1679-1715`) additionally stages:
- write-once `anchor_decision` rows for every anchor round in [cursor, anchor], each Skip or Commit, so skips are now recorded;
- the new `gc_floor` (GC-1);
- the epoch rows, if the block is a boundary (EP-2, EP-3).

A conflicting write-once row halts ordering.

**DE-7 (frozen committee).**
- C_E feeds the leader, the votes and the reward recipient (`dag.rs:1516`).
- C_E also supplies the BFT-time weights (`dag.rs:1604-1607`).
- The per-anchor re-sampling of the live set (`dag.rs:1455-1461`, `:1477-1478`) is removed.
- One anchor per call is kept, so that boundary blocks close their epoch before the next decision.

**S4 status (branch `g1/certified-dag`).** DE-1 (`leader_candidates`, a set in digest
order), DE-2 (`vote` from the voter's own refs; an author counts only with exactly one
vertex at r+1) and DE-4 (the leaders inside the chain's history; two means Undecided, with
an alarm) are in `ordering.rs`. The settled-by-floor arm is **not**: see the S3/S4 review
below. Measured, 3,000 schedules, release (`probe_corpus_fingerprint`):
- Honest and SparseAnchor fingerprints are bit-identical before and after, so the
  honest decided rate stays 0.4407;
- Equivocate: Commit-vs-Commit 283 → 0 (decided rate 0.4464 → 0.4139: twins no longer
  commit through double-counted votes);
- Equivocate, C1-legal: all breaches 123 → 0, decided rate 0.3967 → 0.4167.

A2 is green and non-vacuous. The characterization gate is inverted as
`corpus_equivocation_arrival_order_is_inert_and_twins_never_fork`, and its old first-breach
seed (3) is kept as a regression. One test fixture
(`ordering_persistence_tests::advance_local`) gained the parent refs every round > 1
vertex carries at ingress: a V3-unreachable input.

**S3/S4 review (CRITICAL C-1, fixed).** The S4 floor arm skipped a parent whose ref
*declared* a round ≤ g. At g = 0 that meant a declared round 0, and V3 checked no ref at
round ≤ 1 and admitted round 0. A Byzantine author's round-1 vertex citing its own round-0
vertex Y therefore passed the completeness walk on every node, while `find_causal_history`
collected Y only where it was held: two honest nodes placed different blocks at height 1
(reproduced through `add_vertex`). Two fixes, each sufficient on its own:
- The arm is removed. It returns at S7 only together with a sequence builder that applies
  the same settled predicate (DE-5); a gate and a collector that disagree on "settled" is
  this defect at any g.
- V3 ingress refuses the shape (`Vertex::verify_parent_identities`, the one predicate at
  `add_vertex` and at the three boot-reload paths): nothing at round 0, and round 1 cites
  `["genesis"]` only, with no refs. That is exactly what the producer builds, and it is the
  V4 first-round rule (Layer S). Every honest vertex passes; test fixtures that built
  round 1 otherwise were changed to the producer's shape.

This closes C-1 as an **instance**, not as a class. The second review showed the class is
still open across nodes: "settled" (`committed_set`) is node-local (a restart rebuilds it from
a window; pruning depends on who built the block), so a validator that withholds and later
releases a legal chain splits a live from a restarted node, or halts every pruning node
(DEFECT_REGISTER **H9**, two red witnesses). The fix is S7's, as below. The same review's
MEDIUM (boot measured the stored body while ingress measured the copy received, so a node
could attest a body its own boot refused) is fixed: the size bound is on the canonical body,
inside Layer S.

Regressions: `a_round0_parent_is_refused_and_two_nodes_place_one_block` (node level),
`a_round0_parent_one_view_lacks_never_forks_the_sequence` and
`a_missing_parent_is_a_hole_whatever_round_its_ref_declares` (ordering). The review's LOWs
are fixed too: boot `load` starts strictly above g − RETAIN_SLACK and re-runs S1/S2 and the
size bound (Layer S now carries every check but the wire size); `stage` rolls back on an
inner error; attesting a third digest for a full slot is an error (AT-3); two leaders in a
history raise an alarm.

**Extensional identity.**
- On any input where each author has at most one vertex per round in the index and at most one ref per author, DE-1..DE-4 compute exactly what `ordering.rs:586-627` computes today.
- That covers every V3-reachable input (twins are dropped at `dag.rs:1356`; C1 is at `qc.rs:293-298`; round ≤ 1 carries no ref since the C-1 fix) and every V4 input.

**S5 status (branch `g1/certified-dag`), part 1: the engine.** `consensus::v4::Engine`
implements IN-1 → ST → AT (one transaction, RC-2) → CE-1/2/3 → OR-1/OR-2 → DE over O_E
with the frozen C_0 → PR-1..PR-4 → RC-1 boot and RC-3 guard continuity, behind the
`ConsensusNet` seam; tests drive four validators on real RocksDB over a simulated network.
Green: A2c (all 8 delivery orders, a Byzantine leader that signs and aggregates both twins:
exactly one certificate every time, every honest node commits it at round 2), A3c-push
(before and after every node reopens; B stays staged, never orderable; A takes the certified
role on h0), the twin flood (next vertices pass C1), `v4_cert_conflict_halts_ordering` (the
2-Byzantine negative control), the slow-leader and absent-leader witnesses, reopen, RC-3
abstention, an observer, votes counted from O_E only, PENDING on stripped certificates, OR-1
down-closure, and ST-2 eviction through the engine. The contract's S5 kill list is observed
red (OR-1 without a certificate, DE over staged bodies, producer over staged bodies, PR-3
removed), with 10 more mutants, 14 of 14 killed. Deliberate gaps, each owned by a later
part or stage:
- EQ-1 twin evidence (the V3 equivocation path does not run on a V4 chain; V4 proposer
  twins are staged and never orderable, but not yet carried as slashing evidence: G5).
- **S6:** pull (fetch, CERT_REQ, ATTEST_REQ). Push retries are a rebroadcast every tick.
- **S7:** g > 0. OR-1 has no settled-by-floor arm (review C-1), and H9 applies to the engine
  too: `committed_set` is rebuilt from a window at boot.
- `vcollect` is not persisted: attestations are obtained again after a restart (RC-2 allows
  unsynced), because the rebroadcast makes attesters answer `Reused`.
- RC-3's origin is written only when the engine opens with `genesis_init`; the look-back and
  listen rules of `docs/research/validator_signing_safety.md` are S9.

**S5 status, part 2: the engine in the node.** A chain whose genesis pins
`genesis:vertex_format` = 4 runs `DagConsensus` through the engine (`open_shared`): `dag`
holds the staged bodies and `round_index` O_E (OR-1 its only writer), the V3 recovery,
`add_vertex`, pruning and checkpoints are off, and `DAG_V4:{json}` messages go through
`handle_message` (routed in `main.rs`). The V3 commit loop is extracted as
`commit_ready_anchors` and runs unchanged over O_E with C_0 (`decision_committee`, DE-7):
block building, execution, the acceptance transaction and QC work are the same code. The
producer gathers its payload (mempool, evidence, byte budget, now `gather_payload`, shared
with V3) only when PR-2/PR-3 open a slot, and returns it if the proposal fails. DE-6 is in
the acceptance transaction (`stage_prepared_anchor`, V3 and V4 alike): write-once
`anchor_decision` rows, `C:{digest}` for the emitted anchor and `S` for every anchor round it
skips; a conflicting row refuses the acceptance, so ordering stops. RC-3's origin is written
only with `AINCORE_GUARD_ORIGIN_INIT=1` on the first start. Node-level witnesses (four real
nodes, real execution): identical blocks, one per even anchor round; a transaction through a
V4 vertex into the same block everywhere; every node restarting mid-run; a 70-tick run
restarted past the V3 prune point; a node that never mixes formats; `v4_leader_uses_frozen_committee`
(the live set changed on one node mid-run).

The review of part 1 found no CRITICAL; all of it is fixed with regressions:
- HIGH-1: embedded parent certificates were verified but never ingested, so one lost
  `DAG_CERT` stalled every node that did not receive it. Every verified embedded certificate
  of a staging (or already staged) vertex now goes through CE-3, conflict check included.
- HIGH-2: the standalone engine persists a decision before anything is built from it. It is
  now test-only; the node decides through `prepare_commit` → acceptance transaction →
  publish, as V3 does.
- MEDIUM-1: the CE-3 halt is reloaded at boot from `alarm:vcert_conflict`.
- MEDIUM-2: E4 results are cached (`v4_verdict_cached`: a ref already in the certificate index
  is not verified again) and a new certificate wakes only the pending vertices waiting on its
  slot.
- LOW: no signature for a digest its slot is certified against; a copy of a staged body
  skips the verdict and the transaction (certificates harvested, the attestation re-sent from
  its guard); boot re-promotes a certified body's role; test gaps (RC-3 and halted nodes
  attest nothing, a collector survives a restart, a lost proposal is rebroadcast) closed.

Mutation, part 2 and the fixes: 21 mutants, 19 killed. The two survivors are the cache and
the duplicate fast path (M2, L2), which change cost, not outcomes.

**S6 status (branch `g1/certified-dag`): pull.** `consensus::v4::pull`. Every RE-1 trigger makes
a want:
- (a) a certificate whose body is not held → a body want, asked of the certificate's signers
  in rotation (RE-2);
- (b) a waiting child's parent without a certificate → a certificate want;
- (c) PENDING(cert) → the refs' certificates;
- (d) no certificate for `STALL_TICKS` → the current and previous rounds' certificates from
  every member.

Wants retry with `T_FETCH` doubling to 8 ticks and retire only when satisfied (RE-4: an
`unknown` answer never retires one). A returned body is taken only if wanted and goes through
IN-1 (its hash is the digest). The server (`serve`, RE-5) reads only: staged bodies (≤ 32,
900 KiB) and indexed certificates (≤ 64). Wants are rebuilt at boot from the certificates
whose bodies are missing (reopen mid-fetch). ATTEST_REQ is the per-tick rebroadcast of the
node's own uncertified proposal (answered from the attestation guard).

RE-6, the contract's interim until G4's session identity: a request is signed by its sender's
committee key with a strictly increasing number (reserved durably in blocks, so it survives a
restart). A member gets `MEMBER_REQS_PER_TICK` of its own; a request claiming a member without
its signature, or replaying a number, is dropped without charging anyone; outsiders share
`RESIDUAL_REQS_PER_TICK`. The transport is `send`: in the node, requests and answers travel as
`DAG_V4:` gossip and only the addressee acts (a direct authenticated channel is an ops
optimization for S10).

Witnesses: A3c-pull (A withheld from h0, its author refuses to serve, restart mid-fetch: h0
fetches A from the other signers and commits 2/A), a wrong body refused and the next signer
asked, `unknown` never ending the search, a node cut off for several rounds catching up, a
node receiving no push at all keeping up by pull alone, a lost certificate row fetched after a
restart, the flood witness (a Byzantine member, a spoofer of the honest fetcher and outsiders,
20 requests each per server per tick), and a node-level catch-up through `DagConsensus`.

**S5 second review (no CRITICAL), fixed.**
- HIGH: in the node, the CE-3 halt stopped only signing, and the commit loop kept placing
  blocks. Now `ordering_halted()` stops the commit loop, finality-vote signing and sync
  adoption.
- DE-6 conflicts halt the same way: they write `alarm:decision_conflict:{h}`, and the halt is
  reloaded at boot.
- MEDIUM: a copy of a staged body is neither verified nor harvested (it was a free BLS-cost
  lever).
- MEDIUM: DE-6 refuses an adopted anchor that is odd or more than `MAX_DECISION_ROWS` anchor
  rounds past the cursor, instead of looping a row per round.
- LOW: the guard origin is taken only by a database that never signed; the V4 mode is a
  boot-fixed flag and fails closed; sync adoption on V4 decides with C_0.

**S7 status: GC, and H9 closed.**
- In `OrderingEngine`, "settled" is one predicate built from agreed data: the sentinel,
  `committed_set`, or a declared ref round ≤ g.
- `committed_set` maps each digest to the anchor round that committed it. It is pruned when
  that anchor falls to g or below, and rebuilt at boot from the `cseq` rows above g (GC-4).
  It is no longer a FIFO or 256-round window.
- g = anchor − `GC_DEPTH` is persisted in the acceptance transaction (GC-1).
- The committed sequence is the visited set of the completeness walk itself (DE-5), so the
  gate and the collector cannot disagree.
- Both H9 witnesses are green and now ordinary tests. The restart witness also asserts that
  the committed set and g are identical.
- The regressions from review C-1 now assert the right invariant: two views, one holding a
  parent the other lacks, commit the same sequences.
- In the engine:
  - Ingress uses the real g.
  - OR-1 has the same settled arm.
  - OR-3: when g rises, every waiting child is re-evaluated, and wants and PENDING vertices
    at or below g retire.
  - GC-3: rows and memory at or below g − `RETAIN_SLACK` are deleted, and the plain-body
    budget gets its bytes back (review LOW-6).
- Catch-up, found by the 200-round witness: a node cut off for 40 rounds learned its gap one
  level per round trip. That is slower than the chain grows, so its gap left the retention
  window. Now new wants are sent as soon as an answer reveals them, a batch never drops a
  want, and a vertex that goes PENDING far above O_E wants the certificates of the whole gap
  at once.
- Witnesses:
  - 200 rounds with every node restarting at a different time and one cut off for 40 rounds:
    all agree; the old rows are deleted; memory is bounded; the committed set is identical.
  - The floor-rise witness (OR-3).
  - Guards are deleted only where ingress refuses everything.
  - GC gives a plain twin's bytes back.
- Mutation: 13 mutants, including the contract's kill list (drop OR-3, guards deleted above
  g, a FIFO committed set). 11 are killed. The two survivors are the gap fetch and the
  immediate send: each is sufficient on its own under SimNet's instant delivery, so they are
  redundant catch-up accelerators rather than untested rules. S10's delayed network is
  where each one is timed.

**S8 status: QC authority on the V4 path.**

What landed:
- **IM-1 at import.** `ChainSync::process_blocks_with_qcs` executes a synced block only
  together with a QC (`qc_producer::verify_block_qc`). The QC must verify under the committee
  of the block's epoch and bind the block's hash, anchor round, anchor hash, state root and
  receipts root. The QC is then imported (`import_finality_qc`).
  - A validly signed block with a substituted anchor is therefore refused on V4, even though
    the header hash does not bind the anchor yet (G0).
- **IM-1 at adoption.** `reload_chain_tip` adopts a synced block on V4 only with a stored QC
  that verifies and binds it.
- **IM-1's last clause and IM-3.** A mismatch between the QC's finality digest and this
  node's fold of the same sequence is a decision conflict: an alarm is written and ordering
  halts. The same holds for a DE-6 row conflict during adoption.
  - `adopt_synced_anchor_with` now returns its error, so a conflict is no longer swallowed as
    "retry later".
- **IM-4.** `SyncResponse.qcs` carries the QC of every served block that has one.

Deviations:
- IM-2 is two steps, not one transaction: execution with its block (and, since the final
  review, its QC), then adoption with its QC work. **Corrected by the final review:** the claim
  that "a crash between them only delays adoption" was false while the import wrote the ordering
  keys (a restarted node forked). On V4 the import no longer writes them, and no local decision
  is made while a held block is unadopted.
- FinalityVote V2 (`next_validator_set_hash`, IM-5) lands with epochs at S9.
- The node-level outage witness (a node offline past the window catches up from per-height
  QCs, and the survivors form new QCs) needs QC formation across nodes in the harness, so it
  moves to S10's system suite.

V3 behaves as before: no QC is required on a V3 chain.

Witnesses:
- a V4 block without its QC is not executed;
- a substituted anchor is refused and the real block executes;
- a QC below quorum, or for another block, is refused;
- a sync response carries each block's QC.

Mutation: 5 of 5 killed (the contract's list: no QC check, block hash only, dropped `qcs`),
plus unverified signatures and a QC that is not imported.

**S9 status, part 1: epochs in the engine (`consensus::v4::epoch`).** The node wiring
(closing at H_E's acceptance from the post-state validator set, activation on QC(H_E),
FinalityVote V2) is S9b.

What landed:
- **EP-2/EP-3 close.** `close_epoch(r*, anchor, block_hash, proposed)` writes E+1's record
  (`consensus:epoch_start:{E+1}`): the proposed committee if `validate_committee` accepts it
  (non-empty, ≤ 256, unique, positive stake, the ed25519 key derives the address, the BLS
  PoP verifies), else C_E again with `alarm:committee_invalid:{E+1}`; first round r* + 2; the
  sentinel `epoch_genesis(chain, genesis, E+1, first_round, block_hash, anchor)`. Ordering
  scans no anchor above r* (`close_epoch_at`), and production stops.
- **EP-4 activate.** `epoch_active` is written first; `begin_epoch` moves the cursor and g to
  the new first round and marks the sentinel settled; derived state resets. RC-3: a node that
  abstained under a wiped guard database resumes. Rows two epochs back are deleted (GC-3 by
  epoch). Early E+1 certificates and pending E+1 vertices are evaluated.
- **EP-4 orphans.** Payloads of this node's uncommitted epoch-E proposals above g_E are handed
  back (`take_orphaned_payloads`). They are judged against E's floor and committed set
  *before* `begin_epoch` replaces both. (The first version judged after, and returned nothing:
  witness (f) caught it.) The mempool's loan timeout remains the backstop after a crash.
- **RC-1 for epochs.** Boot reads `epoch_active`, E's and E−1's records and E+1's if E closed.
  A standalone engine that crashed between closing and activating activates on its first call.
- **LA-6 across a boundary (found by the catch-up witness).** A node cut off just before a
  boundary could never finish E, for two reasons. Its peers had cleared E's bodies and
  certificates at activation. And the only authenticated evidence that it was behind, E+1
  vertices, were dropped before any fetch (it holds no C_{E+1}). Fixed:
  - the tail of the closed epoch is kept and served until the next activation, and rebuilt
    from its rows at boot;
  - `CERT_REQ` names its epoch;
  - an E+1 vertex signed by a member of C_E, arriving while this node holds no E+1 record, is a
    new verdict, `Ahead`. It is not kept, but its gap is fetched (bounded, as RE-1 (c)).
  A node further behind than the closed tail catches up by IM-1 block sync, as LA-6 says.

Deviation: the standalone engine (tests) counts decisions as blocks and closes every
`epoch_interval` of them; that count is not atomic with the decision rows. The node (S9b)
closes at H_E inside the block's transaction, so this does not ship.

Witnesses (engine, 4 validators, real RocksDB guards): rotation and agreement across ≥ 3
boundaries with r* + 2 and the epoch-0 rows gone; (e) a committee change dropping a member,
adding a newcomer with new keys and unequal stake (the newcomer's vertices are ordered in
epoch 1, the leaver's are not, the leaver follows); (j) an invalid PoP → carry-over with the
alarm on every node; (a)(d)(i) a stale epoch-E vertex at E+1's first round and an E+1
first-round vertex citing a wrong sentinel change nothing; (k) a wiped guard database abstains
until the next activation and then proposes; (f) an orphaned payload is handed back; a node
behind at the boundary catches up into E+1; restarted servers still serve the closed tail; a
crash between close and activation still activates. `(b)`, `(c)`, `(g)` and `(h)` need the
node (S9b).

Mutation: 18 mutants. 13 were killed on the first run; K5 (round index kept), K6 (no continuity
check), N5 (committed orphans returned) and N12 (early certificates dropped) survived and got
witnesses: the index-epoch invariant in the rotation test, a foreign guard origin, a committed
payload that must not come back, and an E+1 certificate delivered between close and activation.
Their re-run is in part 2's result.

**S9 status, part 2 (S9b): epochs in the node.**

What landed:
- **EP-1.** On a V4 chain `epoch_for_block_height` is ⌊(h−1)/I⌋ from the pinned
  `sys:config:epoch_block_interval`, and `load_validator_set_for_epoch` is the epoch record's
  committee (genesis's for 0). The executor's `consensus:epoch*` and
  `sys:validator_set:epoch:*` rows are no longer read on V4, so rotation does not depend on
  Move's `advance_epoch` succeeding.
- **EP-2/EP-3.** `epoch::stage_boundary` runs inside the transaction that accepts a boundary
  block H_E. That covers both the local build (`commit_ready_anchors`) and the sync import
  (`process_blocks_with_qcs`). It derives C_{E+1} from `sys:validator_set:v1` in H_E's
  post-state, validates it (else C_E and `alarm:committee_invalid`), and writes E+1's record
  write-once. A different existing record is a decision conflict. Right after placement the node
  closes E in memory, before anything else is decided.
- **IM-5, FinalityVote V2.** A vote and a QC carry `next_validator_set_hash`. It is non-empty only
  on a V4 boundary block, where it is signed under `AINCORE_FINALITY_VOTE_V2`. Every other vote
  keeps its V1 bytes exactly (the empty field is skipped in BCS and JSON), so V3 is unchanged.
- **EP-4.** The node activates E+1 when it holds QC(H_E), and only if that QC:
  - verifies under C_E;
  - binds H_E's height, hash, anchor round and anchor;
  - carries a next hash equal to the hash of the committee this node derived.
  A mismatch writes `alarm:committee_mismatch:{E+1}` and halts. The alarm survives restarts, and
  the sync import path writes the same alarm. Orphaned payloads go back to the mempool.
- **QC(H_E) transport (found by the witnesses).** Activation makes one QC liveness-critical on
  every node. A node that missed the boundary votes had no way to get it:
  - sync asks only for blocks above its tip;
  - `GET_FINALITY` returns only the latest QC;
  - `import_finality_qc` stores only a QC that advances finality, and a node that built H_E itself
    is already past that round.
  With unequal stake this stalled three of four nodes at H_1.
  Fix, part 1: `QC_WANT:{h}` / `QC_CERT:{qc}`. A node closed and missing QC(H_E) asks, throttled.
  Peers answer only for a boundary height they hold a QC for, at most once per throttle window
  per height.
  Fix, part 2: `store_block_qc` stores a QC for a held block after IM-1, without the finality
  rule.

Deviations and open items:
- The adoption loop closes and activates between adopted heights, but the node harness has no
  sync. The sync-level witnesses cover the import half, and S10's system suite covers adoption
  across a boundary.
- **Snapshot restore across epochs is open.** Epoch records are Local, so a state snapshot does
  not carry them, and a node restored in epoch E > 0 cannot verify QCs. The fix is an epoch
  change proof: the chain of QC(H_E) with its next hashes, from C_0. It is needed before any
  restore on a multi-epoch chain (G6 / before S11's launch).
- (b) is covered by construction (DE scans no anchor above r*) and by the engine's stale
  witness. It has no separate node witness.

Witnesses:
- Node level, 4 real nodes with real multi-node QCs (the harness now routes QC votes), I = 4:
  - rotation through 3 boundaries: each record matches H_E; QC(H_E) binds hash(C_{E+1}) and is
    V2; the first block of E+1 has a QC of epoch E+1 under C_{E+1}. With (g) non-vacuous: Move's
    `advance_epoch` never ran.
  - (e) a stake change in H_0's post-state becomes C_1 and its stakes decide.
  - (h) a node restarted right after H_E activates like the others.
  - (c) a node that missed the boundary votes: it closes, stays inactive, refuses a forged
    `QC_CERT`, fetches QC(H_E), activates and agrees. `QC_WANT` for a non-boundary height is not
    answered, and repeated asks get one answer.
  - A QC(H_E) binding another committee halts with the alarm, across a restart.
- Sync level, I = 2, with C_1 ≠ C_0 by a real key change:
  - H_0's import writes epoch 1's record, and block 3 is accepted with a C_1 QC and refused with a
    C_0 QC;
  - a boundary QC binding another committee is refused and raises the alarm.

Mutation (S9b): the four part-1 survivors re-ran and were all killed. Then 15 new mutants ran:
- 13 were killed on the first run;
- B10 survived: dropping the in-memory close right after placement.
- B14 survived: the record not written once.

Their witnesses:
- B10: in normal runs production stops at the close, so an epoch-E anchor above r* never
  becomes decidable. The new witness stalls placement on every node while rounds continue.
  Without the close, block 5 anchors an epoch-0 vertex at round 10 above r* = 8; with it, every
  block after H_0 anchors an epoch-1 vertex.
- B14: a direct unit witness of write-once.

Both were verified killed. Total S9: 33 mutants, all killed.

**G0 anchor binding (for S11).** The substituted-anchor witness (B2) is closed on V4 by a
validation rule, with no format change: the anchor must be the last vertex of the committed
sequence, which `vertices_root` binds (DE-5 makes the anchor the unique top-round vertex of its
own walk). B1, the resegmented round and timestamp, was closed by FX-18. See the update in
`BLOCK_IDENTITY_V2_PLAN.md`.

**S10 status: the system suite (`sync/src/system_tests.rs`).**
- Setup: real `DagConsensus` nodes on a V4 genesis, each with its own `ChainSync`, and real multi-node QCs.
- The consensus crate has a `sim` feature that exposes only the outbox transport. chain_sync enables it for its tests only.
- Every agreement check compares every block hash and allows at most one QC per height across nodes. The block hash binds the state and receipts roots.

Witnesses:
- **Outage (from S8):** Y is offline past GC_DEPTH + RETAIN_SLACK rounds and syncs back by
  IM-1, with every imported block carrying its QC. W then crashes for good, and every new QC
  carries Y's signature.
- **Adoption across boundaries:** Y syncs back through two boundaries (I = 4), ends in the
  others' epoch, and votes there.
- **Partitions:**
  - 2|2: nothing is placed on either side; after healing, the nodes agree.
  - 1|3: the three keep deciding; the one catches up.
- **Faults:**
  - 10% loss, 15% delay of up to 3 ticks, and every batch reordered, across epoch boundaries;
  - a restart every 5 ticks, rotating through the nodes;
  - a slow node that ticks 1 step in 4.
- **Stake profiles:** 4×1000, 4000/3000/2000/1000, 3300/2300/2200/2200 and
  2000/1000/1000/1000 all decide and agree.
- **IM-3 on adoption:** a synced block conflicting with a local decision row halts the node with
  the alarm, and the block is not adopted.
- **Decided-rate (engine SimNet), floor 0.42:**
  - honest nodes: 1.000;
  - one member that never attests: 1.000;
  - 25% of messages a tick late plus a member that never attests and shows each vertex to one
    honest node only: 0.656.

Open in S10:
- the V3 baseline on the same SimNet;
- R(P) for P ∈ {5, 50, 99, 150};
- per-round BLS and fsync cost on the Pi (a hardware measurement);
- exit-77 crashes at every durable boundary (the suite restarts between calls; the block
  transaction makes each acceptance atomic);
- the equivocating-leader and withheld-body cases at system level (they are witnessed at engine
  level by A2c, A3c and the twin flood);
- re-running every earlier mutation at system level.

**G1 final review (2026-09-30, at df26933).** Five independent reviewers covered decision
safety, ingress and certificates, node integration and sync, resource exhaustion, and test
quality. Every finding came with a PoC test; each PoC is now a regression test.

CRITICAL, fixed:
- **A crash between sync import and adoption forked the node.** Three reviewers found it
  independently. S8's note ("a crash between them only delays adoption") was wrong.
- **The mechanism:**
  - the QC import wrote the ordering engine's own keys (`consensus:finalized_round`, the last
    anchor, the finality digest);
  - a restart then moved the cursor past the imported blocks;
  - adoption skipped them as already decided, so their sequences never reached the committed
    set;
  - the node's next local anchor re-committed them.
- **The fix, as a class:**
  - on V4 an import only records the certificate. The ordering keys are written only by
    acceptance and adoption, with the sequence they commit;
  - no local decision is made while any held block is unadopted.

HIGH, all fixed:
- **A diverged node was never detected.** A verified QC for another block at a held height is
  now a decision conflict. It raises the alarm on every path: storing a certificate, sync's
  conflict branch, and its QC-pin branch. A running node halts on an alarm at its next tick.
- **RC-3: a wiped or resynced validator re-armed signing at the first activation it performed**,
  even inside an epoch it had already signed in. It resigned slots, so one Byzantine node got
  two certificates for one slot.
  - It now re-arms only at the activation of an epoch whose boundary block's BFT time is later
    than its first guard-less boot plus a clock-skew margin (`consensus:guard_resume_after`,
    `EpochStart.prev_timestamp`).
- **Pull answers could exceed the node's own pre-parse cap**, so a near-maximal body could never
  be fetched. `v4::MAX_WIRE_BYTES` is now the one bound: answers are packed to fit it, and one
  maximal body always fits.
- **RE-6's single sequence high-water mark dropped every reordered request**, so a node behind
  never caught up. Each member's numbers are now accepted once each, in any order, within a
  window (`SeqWindow`).
- **A crash between a synced block's execution and its QC import left adoption waiting
  forever.** The QC is now stored in the block's own transaction. A held block's missing QC is
  imported from a re-sent block. `QC_WANT` asks for any held height the node is stuck on
  (adoption, or its own pending vote), not only boundaries.
- **A frozen-committee leader that leaves the live set made its blocks unsyncable.** On V4,
  sync checks leader and signer against C_E(h).

MEDIUM and LOW, fixed:
- **A dry spell of more than 10,000 rounds wedged decisions forever.**
  - The scan now has a memo instead of a cap. This is safe by the indirect rule: an anchor that
    gains a direct quorum late lies in every later anchor's history.
  - The walk-back is incremental (`DescendingWalk`, proven equal to `walk_history` at every
    floor, holes included). The 10,002-round case went from 296 s to under a second.
  - On V4 the DE-6 rows cover only the last `MAX_DECISION_ROWS` anchor rounds, instead of the
    anchor being refused.
- **Pull:**
  - certificate answers are taken only for wanted, unheld slots, and capped;
  - wants share one peer list, and their rotation start is spread;
  - the client sends at most `CLIENT_REQS_PER_TICK` requests per tick.
- **Throttles and dedup:**
  - an attestation is re-sent at most once per slot per tick;
  - early E+1 certificates are deduplicated;
  - QC answers are throttled per height with oldest-entry eviction, under a global per-tick
    budget.
- **Epoch handling:**
  - nothing of E is attested after E closes (EP-3);
  - an unreadable epoch record halts instead of being ignored.

Test quality:
- 22 kill tests from the review were added. They cover among others:
  - the E4 cache digest;
  - each EP-2 committee clause;
  - IM-1's finality-digest clause at adoption;
  - adoption without a QC;
  - the decision committee after activation;
  - guard deletion above the cut;
  - the DE-4 walk-back chain;
  - PR-1 by stake.
- Vacuous witnesses were rewritten:
  - the twin flood now really certifies a twin;
  - the stale leg now reaches EP-5 (it is asserted to pass Layer S);
  - the system suite now requires QCs.

Mutation of the fixes: 17 mutants, each reverting one fix, run against both crates. All are
killed except F3 (no local decision while a held block is unadopted), which is equivalent in
effect. The commit loop decides the smallest ready anchor first, and an anchor at or below the
tip round is "already on chain", so the guard is defense in depth. A timing-based review test
that failed under load (and so "killed" six mutants spuriously) was made deterministic. Two
survivors got witnesses: attestation after the close (white-box) and pacing of body fetches.

Deferred:
- **The RC-3 init flag left set on a wiped database** still re-arms at once. The fix belongs
  with S11's genesis: a launch window, or f+1 peers reporting height 0.
- **Snapshot restore across epochs** needs an epoch-change proof.
- **A stored QC that conflicts with this node's own pending vote** (retry path) only errors.
  Storing one is already refused on V4.

### Imported decisions and finality votes (IM)

**IM-1 (QC authority).**
- Both paths accept block h only together with a QC q:
  - `ChainSync::process_blocks` (`sync/src/lib.rs:1043-1251`);
  - `reload_chain_tip` adoption (`dag.rs:2975-3045`).
- q must satisfy all of:
  - `verify_qc(q, C_{E(h)}, chain)` (`qc.rs:338-425`);
  - `q.epoch == E(h)`;
  - `q.block_height == h`;
  - `q.block_hash == header.hash`;
  - `q.anchor_round == header.round`;
  - `q.anchor_hash == block.anchor_hash`;
  - `q.state_root` and `q.receipts_root` equal the header's;
  - `q.finality_digest == fold(local finality digest after h−1, block.committed_vertices)` (`ordering.rs:480-487`).
- Today's gates are insufficient: one proposer signature (`dag.rs:3001`, `sync:530-558`) and a pin on only the latest QC (`sync:1062-1076`). The anchor fields themselves are unauthenticated (`blockchain/src/lib.rs:45-47`, `:282-301`).

**IM-2 (one transaction).**
- Execution, block save, ordering adoption (`adopt_synced_anchor_with`, `ordering.rs:960-990`), QC import and any epoch rows commit together.
- A block without a matching QC is not executed. The batch stops with no writes, as today's rejection path does.

**IM-3 (conflicts).**
- A QC-bound anchor that differs from a local `anchor_decision` → `alarm:decision_conflict` and halt ordering.
- The B4b dedup (`dag.rs:3064-3066`) takes the anchor round from the QC, never from `header.round`.

**IM-4 (per-height QC transport).**
- `SYNC_RESP` carries `qcs` for its blocks, read from `consensus:qc:{h}`.
- `consensus:qc:{h}` is retained exactly as long as `block_{h}`.
- Every accepted or adopted height already stages durable QC work that retries until a complete QC exists (`qc_producer/recovery.rs:18-55`, `:97-161`).

**IM-5 (votes).**
- Honest FinalityVotes are signed only for blocks from the node's own DE-5 decision or from an IM-1 import. Existing staging does this at `dag.rs:1705-1707` and `:3013`.
- V2 adds `next_validator_set_hash`.
- At most one QC per height follows from the height guard (`qc_producer.rs:373-377`) and quorum intersection.

### Retrieval (RE)

**RE-1 (triggers).**
- (a) A verified certificate whose body is not held.
- (b) A waiting child's parent body.
- (c) PENDING(cert) → `CERT_REQ`.
- (d) Below the round quorum → `CERT_REQ` for (E, r−1).
- (e) The node's own uncertified vertex → `ATTEST_REQ`.
- Push delivery is never relied upon:
  - publish results are discarded (`p2p.rs:275`);
  - over-budget messages are dropped (`p2p.rs:352`, `:398`);
  - TCP sends are spawned and ignored (`common/network/src/lib.rs:702-707`; `dag.rs:2036`).

**RE-2 (targets).**
- For a body: the certificate's signers except self. If the digest blocks an anchor's down-closure, ask all signers in parallel; otherwise rotate.
- For certificates: all members.
- Addresses come from `PeerList` and `get_peer_ip` (`dag.rs:2025-2037`).

**RE-3 (client).**
- New `sync::VertexFetcher`, using `secure_connect` with the node's **committee identity key**. Today's `fetch_verified_tip` uses an ephemeral `"__sync__"` identity (`sync:968-981`); the fetcher must not.
- Up to 32 digests per request and 4 outstanding requests per peer.
- Retry every `T_FETCH`, doubling up to 8 ticks.

**RE-4 (validation).**
- A returned body must satisfy `hash_v4(body) == requested digest == certificate digest`. It then passes IN-1, ST-2 and OR-1.
- A wrong or garbage reply → try the next signer.
- An `unknown` reply never retires a want. A want retires only when:
  - its body is staged;
  - its round is ≤ g;
  - its epoch is closed;
  - or IM-1 supersedes it.

**RE-5 (servers).**
- `handle_vertex_request` (`sync:1298-1364`) is logically unchanged: storage reads only, a 32-hash cap, a 900 KiB cap and a deadline. It serves every staged body.
- The `CERT_REQ` server reads `vcert` rows.
- The `ATTEST_REQ` server reads only the guard row. If none exists, it queues the vertex into normal ingress (bounded) and answers `pending`. No signing happens on the serving thread.

**RE-6 (budgets).**
- Each committee member gets a reserved concurrency slot and a reserved lookup bucket, keyed on the authenticated session identity (LA-5).
- Non-members share a small residual bucket.
- The node-wide bucket (`sync:74-83`) is no longer the only bound. Its starvation limit is recorded at `sync:65-71`.

**RE-7 (work bound).**
- A P-round gap needs at most n·P bodies, in ⌈n·P/32⌉ requests.
- Beyond `GC_DEPTH + RETAIN_SLACK`, catch-up uses IM-1 block sync.
- The order is forced as `DEFECT_REGISTER.md:754` requires: the client ships only after staging, certification and DE-1..DE-4 (stages S3–S5 before S6).

### Equivocation (EQ)

**EQ-1 (proposer twins).**
- Detected when a slot receives a second digest (ST-1), or when a certified digest conflicts with a staged body (the certified body is fetched to build the pair).
- The evidence is a compact pair in canonical hash order (`dag.rs:2402-2479`) under an epoch-bearing key.
- SLASH_EVIDENCE carriage is unchanged.
- `verify_equivocation_proof` (`dag.rs:2375-2396`) recomputes `hash_v4` and uses the keys and membership of C_E, not the live account and set at `:2386` and `:2392`.

**EQ-2 (decision impact).**
- None. A twin reaches O_E only through OR-1, which requires the slot's unique certificate.
- A recovered, retransmitted or fetched losing body is only ever staged.

**EQ-3 (attester equivocation).** `ATTEST_EQUIV` is self-authenticating BLS evidence. Detection only; slashing belongs to G5.

**EQ-4.** A certificate conflict halts ordering (CE-3).

**EQ-5.** Arrival order affects only two things:
- which twin an honest attester signs;
- which bodies fill the two staging cells.

No decision reads arrival order or a minimum hash.

### Epochs (EP)

**EP-1 (numbering).**
- E(h) = ⌊(h−1)/I⌋ with I immutable.
- `epoch_for_block_height` (`qc_producer.rs:130-157`) returns exactly E(h).
- Consensus no longer reads `consensus:epoch`, `consensus:epoch_start_height:*` or `sys:validator_set:epoch:*` (`executor lib.rs:1305-1337`). Those rows stop mattering to consensus whether or not Move `advance_epoch` succeeded (`executor lib.rs:1263-1291`) and whether or not they were pruned (`:1328-1336`).

**EP-2 (committee).**
- When accepting or importing H_E, derive C_{E+1} from `sys:validator_set:v1` in the post-state of H_E.
- Validate it:
  - non-empty;
  - unique addresses;
  - drop entries with zero stake;
  - each Ed25519 key derives its address;
  - each BLS PoP verifies;
  - at most 256 members.
- If validation fails: C_{E+1} := C_E, plus an alarm row. The result is deterministic, so no node halts.
- Write `consensus:dag_committee:{E+1}` in the same transaction as the block.

**EP-3 (boundary).**
- A* is the anchor of H_E, at round r*. It comes from the local decision or from `QC(H_E).anchor_round`, never from header fields.
- Epoch E closes at r*: no epoch-E anchor above r* is decided, and no epoch-E vertex is proposed or attested after H_E is accepted.
- `first_round(E+1) = r* + 2` and `EPOCH_GENESIS(E+1)` are written in the same transaction as H_E.

**EP-4 (activation).**
- A node activates E+1 only when it holds QC(H_E), verified under C_E, whose `next_validator_set_hash` equals `validator_set_hash(C_{E+1})` as the node derived it. A mismatch → `alarm:committee_mismatch` and halt.
- The activation transaction writes `consensus:epoch_active = E+1`.
- In memory, activation:
  - resets `dag`, `round_index`, the certificate index and the current round to `first_round(E+1)`;
  - sets the cursor to `first_round(E+1)` and g to `first_round(E+1) − 1`;
  - releases the PENDING(epoch) buffer;
  - returns the node's own uncommitted epoch-E payloads to the mempool (`mempool lib.rs:720`).
- The QC chain from C_0 authenticates every later committee. That gives a rejoining node a Diem-style transition path (`PRODUCTION_READINESS_GOAL.md:1052-1057`).

**EP-5 (validity).** The classification in IN-1 E1:
- (E, a, r) and (E+1, a, r) are distinct slots, so signing both is not equivocation;
- an epoch-E message with r > r* is STALE after the boundary;
- an epoch-(E+1) message before activation is PENDING;
- an epoch-(E+1) first-round vertex with the wrong sentinel is INVALID at every node that knows the boundary.

**EP-6.** Delayed-message witnesses are listed in stage S9.

### Pruning, GC and retention (GC)

**GC-1.**
- After committing anchor a_k of epoch E, set g := max(first_round(E) − 1, a_k − GC_DEPTH). It is persisted in the acceptance transaction.
- This replaces the node-local horizon `finalized_round.min(latest_block_round) − 10` (`dag.rs:1905-1907`), which violates the agreed-GC requirement of Narwhal §3.3.

**GC-2 (answer to `DEFECT_REGISTER.md:761-763`).**
- The third resolvability arm is: p is settled iff `declared_round(p) ≤ g`. `declared_round` is read from the child's authenticated `ParentRef`, and g is a function of the agreed prefix.
- Two nodes with different prune timing therefore walk identical sets.

**GC-3 (deletion).**
- After each commit, a separate batch deletes by idempotent *range* every row of (E, r ≤ g − RETAIN_SLACK): `vertex:` (via `vslot`), `vslot`, `vcert`, `vcollect`, `vattest`, `vproposed`.
- Deleting guards below g is safe because AT-1 refuses round ≤ g, and g is durable and monotone.
- Epoch, committee, `guard_origin` and `gc_floor` rows are never deleted.
- **Serving obligation:** honest signers keep attested bodies until round ≤ g − RETAIN_SLACK.

**GC-4.**
- `committed_set` is exactly the map of committed digests to rounds with round > g.
- It is rebuilt at boot from the `cseq` rows whose anchor_round > g, and pruned by round, not FIFO.
- The FIFO window (`ordering.rs:92`, `:493-505`) and the 256-round window (`ordering.rs:84`) stop being correctness inputs.
- This removes the undercounted window bound the recovery attack found.

**GC-5 (bounds).**
- At most 2 staged bodies per slot, over at most `LEAD + GC_DEPTH + RETAIN_SLACK` payload-bearing rounds per epoch.
- Above `cursor + LEAD` only payload-free bodies on certified parents are staged (C1): at most one certified slot per author per round. A payload-free body is about 2.4 KB at n=4 and grows with n (each ref carries a compact certificate in transit; staged bodies store none): about 49 KB at n=100. Certified rounds advance at most once per tick, so while commits stall the growth is at most n bodies per tick, about 10 KB at n=4 (roughly n² bytes), reclaimed by GC once commits resume. The growth is unbounded in time while commits stall; that is the price of C1's liveness.
- Plus `B_AUTH` per author and 16 PENDING vertices per author.
- Honest operation stages about one body per slot. The worst case at n=4 is dominated by a single Byzantine author's `B_AUTH`.

### Crash recovery and boot (RC)

**RC-1 (boot, V4; replaces `dag.rs:144-426`).**
1. Load the ordering metadata, `gc_floor`, `epoch_active`, the committees and the epoch rows.
2. Load staged bodies from the `vslot` rows of the active epoch with round > g − RETAIN_SLACK. Re-run Layer S on each. There is no load-order dedup and there are no refusal loops.
3. Load and verify the `vcert` rows.
4. Rebuild O_E through OR-1 in increasing round.
5. Rebuild the certificate index and the fetch queue.
6. For each `vproposed(E, r)` with r ≥ current round − 1, rebroadcast that exact body. Never build a second vertex for a slot.

The signed checkpoint fast path (`dag.rs:148-302`) is **not used** in V4. It checks hash, form and parent proofs, but not the signature, the parent gate or the committee (`dag.rs:241-252`).

**RC-2 (atomic boundaries).** Each of these commits as one unit:
- stage plus the node's own attestation guard;
- the node's own proposal: body, `vslot`, `vproposed` and `vattest`;
- block acceptance: block, execution, ordering, `gc_floor`, `anchor_decision`, epoch rows and QC work;
- IM-2 import;
- epoch activation.

Certificates and `vcollect` may be written unsynced because they can be obtained again. Retries are idempotent through the guards.

**RC-3 (guard continuity).**
- Suppose the node's key is a member of C_{E_active} and `consensus:guard_origin` is missing or mismatched. That means a fresh, wiped or resynced database under a live key.
- In that case the node **abstains from attesting and proposing for the rest of the epoch**, and resumes at the next activation.
- Two situations are Byzantine under SA-4, not handled by the node: restoring a validator database from a backup, and running a copied `node.key` on a second database. The latter was a practice in earlier slashing live tests, and it must not be done with production keys.

### Safety argument (sketch; not mechanized)

Let T = T_E and β < T/3.

- **Lemma U (one certificate per slot).**
  - Two certificates for (E, a, r) with different digests have signer sets whose stakes each exceed 2T/3.
  - Their intersection exceeds T/3 > β, so it contains an honest signer.
  - That signer's AT-2 guard refused the second digest. Contradiction.
- **Lemma A (availability).** Signers of a certificate carry more than 2T/3 of stake, so honest signers carry more than 2T/3 − β > T/3 > 0. Each of them staged the body durably before signing (AT-2), and keeps it (GC-3).
- **Lemma C (down-closure).** By OR-1, a vertex's history above g lies inside O_E. Walks therefore never meet a hole, and bodies are identical everywhere because digests are certified.
- **Lemma V (unique direct candidate, across nodes).**
  - Each author has at most one certified vertex at r+1 (Lemma U), and that vertex's vote is a function of its own signed bytes.
  - Two digests with Q_E support would need a common supporter voting for both. Impossible.
- **Lemma P (a direct commit propagates).**
  - Suppose some honest node has Direct(j) = d.
  - Let w be any certified epoch-E vertex at round j+2. Its certificate includes an honest signer, who checked S6 and E4 on w. So w's refs name round-(j+1) authors carrying Q_E stake, each through a verified certificate.
  - Those authors intersect the voters for d in more than T/3 of stake.
  - For any author a in the intersection, the certified vertex w cites for a *is* a's voter vertex, by Lemma U. That vertex cites d.
  - Higher rounds follow by induction, since every certified vertex cites certified vertices of the previous round.
  - The author of w need not be honest.
- **Theorem 1 (anchor agreement within an epoch).**
  - Honest decisions per anchor round are equal whenever both are defined.
  - Direct decisions agree (Lemma V).
  - A walk from any later committed anchor contains the direct-committed digest (Lemma P), and CandH is unique (Lemma U).
  - At each decision step, walks run over identical histories with identical g and `committed_set`, both functions of the committed prefix (Lemma C, GC-1, GC-4).
  - Induction over the committed anchor chain, as in Bullshark §2, gives prefix-consistent sequences, including agreed skips.
- **Theorem 2 (blocks and QCs).**
  - Identical sequences give identical finality digests, blocks and FinalityVotes. This also relies on BFT time from signed vertex timestamps weighted by C_E, and on LA-7 for execution.
  - At most one QC per height (IM-5).
- **Theorem 3 (epochs).**
  - Every honest node closes E at the same A*: committed anchors map one-to-one onto heights (`anchor_already_on_chain`, `dag.rs:550-552`), and H_E is agreed.
  - Every honest node activates the same C_{E+1}, because QC(H_E) is unique (EP-4).
  - Epoch-E vertices above r* are never ordered, because E closes inside H_E's acceptance transaction and the cursor is strict.
- **Theorem 4 (no second writer).**
  - Every imported decision carries a QC (IM-1). A QC includes more than T/3 honest signers.
  - Each of them signed only its own decision or an earlier QC-bound import (IM-5).
  - By induction, an imported decision equals the unique decision.

### Liveness argument (sketch; after GST, under LA-1..LA-9)

1. **Certification.** An honest proposal is certified within about 3Δ, plus two fsyncs and BLS work. Pushes are backed by `ATTEST_REQ` retries.
2. **Round advance.** Honest certificates reach Q_E each round, so honest nodes advance at the tick rate.
3. **Honest-leader commit.** With PR-3 and LA-3, every honest vertex at r+1 cites λ(r)'s certificate. Honest stake exceeds 2T/3, so Direct(r) holds at every honest node once the voters are orderable (step 4).
4. **Retrieval.** Every needed body has an honest retaining signer (Lemma A, GC-3), and RE-6 prevents starvation. A want succeeds within |signers| rotations.
5. **Leader draw.** Each anchor round's leader is honest with probability at least the honest stake share, which exceeds 2/3. That gives at most 1.5 anchor rounds expected between direct commits.
   - There is **no deterministic bound**, because the stake-weighted draw is not round-robin (Mysticeti Lemma 11 assumes round-robin).
   - `LEAD` bounds payload, not rounds (Correction C1). A hard round cap deadlocked for good once every round up to it was proposed with no anchor supported, which a pre-GST scheduler reaches with certainty; the 3^−100 figure that stood here covered silent Byzantine leaders only and is withdrawn.
6. **Blocks and QCs.** There is one block per committed anchor. A QC per block follows from the durable retry worker.
7. **Epochs.** QC(H_E) forms, and activation follows.
8. **Rejoin.** Within the retention window, catch-up is by step 4. Beyond it, by IM-1 with per-height QCs.

**Recovery progress.**
- Define R(P) as the number of ticks from heal or restart until every honest node's committed prefix equals the largest honest prefix at heal time.
- Model: R(P) ≈ ⌈n·P/32⌉·RTT/(servers queried) + (P/2)·(per-anchor replay) + O(1).
- It is pinned by measurement in stage S10.

---

## The gate owner's five required points

1. **One coherent contract, not combined partial rules.**
   - The design is a certified DAG (Narwhal §3.1, §4.1) feeding the Bullshark-lite decision function that already exists.
   - Certification supplies exactly the three premises Bullshark §2.1 assumes:
     - non-equivocation, by Lemma U;
     - complete histories, by OR-1;
     - reliable delivery, by Lemma A plus RE.
   - DE-1..DE-4 restate `prepare_commit` over certified input and are extensionally identical on legal input.
   - Nothing from Mysticeti's decision procedure is imported: no skip pattern, no waves, no implicit certificates.
   - The one borrowed idea is that a vote is read from the voter's own signed refs (DE-2). On certified, C1-legal input that is exactly Bullshark's edge vote.
2. **Staged versus orderable bodies; attest after durable validation; guard; frozen committee.**
   - Staging (ST) is separate from O_E (OR-1, a single writer).
   - A node attests only after the body is durably staged in the same transaction as the guard, and after every parent certificate is verified against C_E (AT-1, AT-2).
   - The guard is keyed by (chain+genesis, BLS key, epoch, author, round) under the domain `AINCORE_VERTEX_ATTEST_V1`.
   - The committee context is frozen twice: `committee_hash` is inside the signed body, and verification uses only C_E.
3. **Quorum-certified uniqueness, causal retrieval and bounded retention.**
   - Lemma U gives uniqueness; RE gives retrieval from signers with a digest check; GC gives agreed retention with byte bounds.
   - A recovered losing twin is only staged (EQ-2).
   - Arrival order governs only which twin an honest node signs, never a decision.
   - No minimum-hash choice exists anywhere.
4. **Binding and boundaries.**
   - The vertex digest binds chain, genesis, epoch, round and author.
   - Attestations and certificates also bind the digest and `committee_hash`.
   - Guards, certificates and evidence keys carry the epoch.
   - FinalityVote V2 binds the next committee.
   - The boundary is the anchor of H_E. Activation requires QC(H_E).
   - Delayed messages across the boundary are tested explicitly (S9).
5. **Producing validators, execution, QC agreement and adversity.**
   - Stage S10 runs 4 producing validators with real execution, QC production, partitions, withheld bodies, crash/replay at every durable boundary, unequal stake and epoch changes.
   - It requires identical committed prefixes, at most one QC per height, and a measured recovery bound R(P).

---

## Witness mapping

Release rule: a witness passes only with exactly 1 passed, 0 failed, 0 ignored (`scripts/release_security_gate.py:80-86`, `:118-126`). Predictions below are **not** measurements. The discipline rule (`DEFECT_REGISTER.md:158-160`) requires each one to be observed.

**The seven red witnesses.**

| Witness | Root | Flips under this contract? | When | Reason and evidence value |
|---|---|---|---|---|
| `tests::tests::test_h1_dropped_twin_leaves_two_honest_nodes_holding_different_sets` (`tests.rs:2282-2353`) | H1 | **Yes.** The test body is unmodified; two tier-2 helpers are ported: `tier2_open` seeds a frozen `genesis:validator_set:v1` (`:2155-2199`), and `tier2_signed` adds `epoch: 0` (`:2204-2222`) | S11 | ST-1 stages both round-1 twins into `dag`, and RC-1 reloads `vslot` verbatim, so both sets are {A, B} and stable across restart. **Evidence of storability and restart stability only**: a min-hash rule would also pass. |
| `ordering::tests::test_h2_h4_twin_anchors_double_count_stake_and_break_subset_independence` (`ordering.rs:2088-2150`) | H2/H4 | **Yes, unmodified. Predicted non-vacuous.** | S4 | Every round-3 voter's first ref naming the leader is `twin_a` (`ordering.rs:2004-2005`, `:2017-2021`, `:1678-1688`), so `twin_a` has 4000 support and `twin_b` has 0. Predicted outcomes: the full, reversed and only-A views commit `twin_a`; the only-B view is Undecided (`twin_a` is not held). All three legs pass without any all-Undecided trap. **Evidence**: the decision function fails safe on C1-illegal input. It does not show end-to-end safety, because this schedule is illegal at ingress (`qc.rs:293-298`). It is paired with A2c. |
| `equivocation_liveness_tests::equivocated_parent_must_not_permanently_block_supported_anchor` (`:222-226`) | H1+H2 | **No.** It cannot be constructed under V4. | Replaced by A3c (S5/S6); manifest change at S11 | honest[0] cites an uncertified B (`:131-135`). Every node holds that vertex PENDING(cert) (IN-1 E4). The tail carries no certificates, so nothing becomes orderable, and X's `expect` at `:167-168` fails. The old schedule becomes a non-ignored "refused at ingress" regression. |
| `sync_must_reject_resegmented_round_timestamp_with_reused_signature` (`block_identity_tests.rs:45-69`) | G0 | **No.** | — | The header hash concatenates decimal round and timestamp (`blockchain lib.rs:282-301`). **Correction to both route designs:** under IM-1 this test stays red, now failing at its *acceptance* leg (`:66`), because a fresh store refuses the unchanged block when it has no QC. It must be re-expressed with a QC input, jointly with G0. |
| `sync_must_reject_substituted_anchor_with_reused_signature` (`:71-89`) | G0 | **No.** | — | `anchor_hash` is outside the header hash (`lib.rs:45-47`). The same IM-1 note applies at `:83`. |
| `executor tests::test_h6_state_root_is_blind_to_out_of_band_writes` (`executor lib.rs:7821`) | G3 | **No.** | — | `current_state_root` is a stored value (`lib.rs:1016-1022`). |
| `executor tests::test_h6_a_corrupted_state_snapshot_is_undetectable` (`:7886`) | G3 | **No.** | — | Same root cause. |

**The seven green controls.**

| Control | Fate |
|---|---|
| `complete_signed_history_decides_after_retransmission_and_reopen` (`equivocation_liveness_tests.rs:217-220`) | Green on V3 through S10. At S11 its uncertified fixture decides nothing, so it is replaced by a V4 twin with the same schedule plus certificates and the same assertions (landed at S5). |
| `test_h3_tier2_stateless_gate_prevents_the_ancestry_fork` (`tests.rs:2977-3088`) | The same. Its V4 analogue lands at S5. The non-vacuity check (`:3066-3072`) needs certified fixtures. |
| `test_h3_tier2_round_skipping_anchor_is_refused` (`tests.rs:3111-3213`) | The crafted-anchor leg (`:3184-3192`) holds, because S6's round clause is unchanged. The honest-admitted leg (`:3196-3210`) needs certificate-carrying fixtures at S11. Its assertions do not change. |
| `unchanged_signed_block_is_accepted_identically_by_two_fresh_stores` (`block_identity_tests.rs:33-43`) | Unaffected until IM-1 reaches the default path at S11. It then goes red (no QC in a fresh store) and is re-expressed with a QC, jointly with G0. |
| `accepted_block_qc_work_survives_crash_before_attestation` (`local_acceptance_tests.rs:325-341`) | 1-of-1 committee: the node certifies its own vertices, so it is expected to stay green. Must be re-run after FinalityVote V2. |
| `adopted_block_qc_work_and_cursor_commit_together_across_crash` (`:343-374`) | Red under IM-1, because the follower receives the block without its QC (`:356`). Re-expressed at S8 with the block's QC delivered and the crash boundaries kept. |
| `crash_during_retry_atomically_keeps_work_or_publishes_guarded_outcome` (`qc_recovery_tests.rs:236-237`) | Touches only the QC worker. Re-run after V2. |

**Rules for every re-expression.**
- It lands in the same commit as the change that invalidates the old test.
- The old schedule stays as a non-ignored ingress-refusal regression.
- The manifest diff states, for each name, why the old schedule can no longer be constructed.
- It gets independent review.

**G1 closure evidence.**
- A1 and A2 green.
- A2c and A3c green.
- The S1–S10 witnesses green, with every listed mutation observed red.
- The 0.42 floor and the V4 floor are met.
- B1, B2, C1 and C2 remain with G0 and G3.

---

## Staged implementation plan

**Standing rules.**
- Every listed mutation is **run and observed red** (`DEFECT_REGISTER.md:158-160`).
- `corpus_honest_liveness_does_not_regress` (`ordering.rs:2776-2811`, floor 0.42) stays green at every stage.
- The seven controls stay green unless a stage names their re-expression.
- Until S11, V4 code runs only under a V4 genesis format, which no production genesis can set. The V3 path that every live node runs changes only through S4's decision edits, which are extensionally identical on V3-reachable input.
- CLAUDE.md rules 8 and 9 apply: unit tests for crypto use, and `cargo test -p executor` after executor edits.

| Stage | Scope (landable alone) | Observable gate | Mutations that must go red |
|---|---|---|---|
| **S0** | Pre-register the witness names and measurement methodology below; propose manifest additions for review | Document and manifest review | — |
| **S1** | `vcert` library: `AttestBody`, `VertexAttestation`, `VertexCertificate`, `CompactCert`, the shared verifier, the `attest_slot` guard transaction, and the collector. No wiring. | Attestation bytes do not cross-verify with FinalityVote; the verifier rejects a wrong chain, genesis, committee, epoch, stake or bitmap; the guard refuses a conflicting digest across reopen; an identical retry is idempotent; (E,a,r) and (E+1,a,r) are both attestable; different authors never collide; two concurrent conflicting requests yield exactly one attestation; an exit-77 crash before or after commit never publishes an unguarded signature; exhaustive n=4 check: at most 1 certificate over all 8 honest delivery orders with the Byzantine signer attesting both twins; negative control: with 2 Byzantine validators, two certificates *do* form. Witness status stays 7 red / 7 green. | Skip the guard read → uniqueness red. Drop E from the key → cross-epoch red. Drop the author → collision red. Send before commit → crash red. Reuse the finality domain → domain red. |
| **S2** | V4 codec and the pure predicate `v4_verdict` (IN-1 Layers S and E): `Vertex.epoch`, `hash_v4`, `parents_root_v4`, `ParentRef.cert`, `EPOCH_GENESIS`. Mechanical fixture change: add `epoch: 0`. | Per-clause tests: tampered epoch; certificate from the wrong epoch; missing certificate → Pending; stripped embedded certificate with a local copy → Stage; corrupted embedded certificate → Pending (never Invalid); round-skip or thin anchor → Invalid; duplicate author → Invalid; wrong sentinel → Invalid; a first-round vertex across a boundary. V3 path unchanged; all 14 witnesses keep their status. | Remove each clause in turn → its test red. Treat a bad embedded certificate as Invalid → the transport-corruption test red. |
| **S3** | Staging store and boot at the StateDB level (ST-1..ST-3, RC-1 steps 2-4), not yet driving consensus | Twins staged equally across arrival orders; restart-stable; a third twin → evidence only; a certified third twin evicts correctly (**3-twin witness**); `B_AUTH` holds; an exit-77 crash mid-stage recovers | Refuse the second twin → P_VIEW_EQ red. Dedup by load order → restart red. Remove the reservation → 3-twin red. |
| **S4** | Shared decision edits DE-1..DE-4 in `ordering.rs` (the settled-by-floor arm moved to S7 after review C-1) | **A2 turns green, and must be observed non-vacuous** (≥3 of 4 views commit `twin_a`). Honest corpus rate **bit-identical** at the same seeds. On the C1-legal Equivocate universe, Commit-vs-Skip is predicted to go from 807 to 0, and the Commit-vs-Undecided count is reported. Every existing ordering test is green, including `test_b4b_missing_voted_leader_defers_instead_of_false_skip` (`ordering.rs:3255`). Characterization gate `corpus_equivocation_arrival_order_is_inert_and_twins_never_fork` (`:2688`) is inverted under review: it now asserts no Commit-vs-Commit and inert permutation. Release gate expected at 6 red / 8 green. | DE-2 back to `any()` → A2 P_NODOUBLECOUNT red. DE-1 back to `find_map` → A2 ORDER leg red. DE-4 back to `leader_vertex_hash ∈ visited` → inverted Equivocate gate red. |
| **S5** | V4 pipeline under the V4 flag: all IN/ST/AT/CE/OR/PR rules, DE on O_E with a frozen C_0, RC boot, and a transport seam (`ConsensusNet` trait, production plus SimNet). Every reader re-pointed in this same increment. | **Twin-flood witness** (an equivocating leader sends both twins to all nodes; the honest producer's next vertex passes C1 and there is no 2/B plan). **A2c** `v4_certified_twin_decisions_agree_and_decide` (real RocksDB guards on 4 validators; all 8 delivery orders; at most 1 certificate; order and subset permutations agree; *mandatory* non-vacuity: the full view commits the certified twin at round 2; negative control with 2 Byzantine validators). **A3c-push** (h0 attests B first; cert(A) = {byz, h1, h2}; everyone commits 2/A with the same sequence and finality digest before and after reopen; B ∈ `dag`, B ∉ O_E). V4 twins of the complete-history control and both H3 controls. `v4_cert_conflict_halts_ordering`. `v4_leader_uses_frozen_committee` (live set mutated mid-epoch). **Slow-leader witness**: an honest leader with injected lag is still directly committed. | OR-1 without a certificate → A3c red (Y prepares 2/B, the old negative control). DE-1 over staged bodies → A2c red. Producer reads staged bodies → twin-flood witness red. Remove PR-3 → slow-leader witness red. |
| **S6** | Pull: `VertexFetcher`, CERT_REQ and ATTEST_REQ servers, per-member budgets (behind the G4 session-identity change, or signed requests as an interim) | **A3c-pull** (A's body withheld from h0; byz refuses to serve; h0 decides within K ticks; reopen mid-fetch); a withheld body is fetched from signers; a wrong body is rejected and the next signer tried; `unknown` never ends the search; **flood witness** (a spoofing non-member plus one Byzantine member flooding cannot starve an honest member's fetch) | Client off → A3c-pull red. No digest check → wrong-body red. Ask non-signers → signer-only-holder red. Treat `unknown` as absence → red. Restore the node-wide bucket → flood red. |
| **S7** | GC-1..GC-5, OR-3, and the settled-by-floor arm with a sequence builder sharing its predicate | Two nodes with different prune and checkpoint timing produce byte-identical sequences over 200 rounds; a parent one node holds and another settled never enters one sequence only (review C-1 at g > 0); **the H9 witnesses turn green** (a live and a restarted node agree after a withheld chain is released; no pruning node halts); rejoin inside the window by fetch; **floor-rise witness** (a waiting child is released when g passes its parent); `committed_set` exact above g; deleting guards below g cannot enable a second attestation; byte bounds hold under a Byzantine flood | Restore the `dag.rs:1905` horizon → divergence red. Drop OR-3 → floor-rise red. FIFO `committed_set` → exactness red. Delete guards above g → double-attestation red. |
| **S8** | IM-1..IM-5: FinalityVote V2, per-height QCs in SYNC_RESP, atomic import and adoption (V4 path) | A synced block without a QC is neither executed nor adopted; a validly signed block from one Byzantine validator with a fake anchor or sequence is refused while the real QC'd block is adopted; a conflict between a local decision and a QC halts; **outage witness** (Y offline past the window, W then crashes, Y catches up from per-height QCs, and X, Z, Y form new QCs); re-expressed adopted-block control | Remove the QC check → Byzantine-block red. Check `block_hash` only → fake-anchor red. Drop `qcs` from SYNC_RESP → outage red. |
| **S9** | EP-1..EP-6 and RC-3 | Delayed-message and boundary witnesses: **(a)** epoch-E proposal or certificate with r ≥ first_round(E+1) arriving after the boundary is inert; **(b)** late epoch-E message with r ≤ r* is ordered only if in A*'s history; **(c)** epoch-(E+1) vertex or certificate arriving before activation is PENDING and yields the same O_{E+1} as a node that received it later; **(d)** wrong sentinel → invalid everywhere; **(e)** committee and stake change with a real key change and unequal stake; **(f)** a node partitioned across the boundary discards its E work above r* and re-injects it; **(g)** Move `advance_epoch` aborts at the boundary, yet the epoch advances and C_{E+1} = C_E; **(h)** crash exactly at H_E acceptance; **(i)** epoch rewind with stale epoch-E vertices at the same round numbers as E+1; **(j)** a joining member with an invalid PoP → carry-over and alarm; **(k)** a wiped guard database under a live key → abstain until the next epoch | first_round = r*+1 → overlap red. Remove the epoch from AttestBody → replay red. Use the node's current epoch instead of the vertex's → stake-change red. Make rotation depend on Move success → (g) red. Round-only in-memory index → (i) red. No continuity check → (k) red. |
| **S10** | System suite on SimNet: 4 **producing** validators with real execution and QC; loss, delay, reordering; 2\|2 and 1\|3 partitions; withheld bodies; an equivocating leader; a **rushing non-equivocating Byzantine**; a slow node; exit-77 crash at every durable boundary; stake profiles 4×1000, 4000/3000/2000/1000, 3300/2300/2200/2200 and 2000/1000/1000/1000; epoch boundaries | Identical committed prefixes (anchor round and digest, sequence, finality digest, block hash, state root, QC); at most 1 QC per height; measured R(P) for P ∈ {5, 50, 99, 150}; K for A3c; V4 decided-rate ≥ 0.42 **and** ≥ the V3 baseline on the same SimNet and seeds; per-round BLS and fsync cost measured on the Pi; tick and `T_LEADER` validated | Re-run every earlier mutation at system level. Each must break prefix identity or the progress bound. |
| **S11** | Activation in one fresh genesis together with G0's `identity_v2`: V4 becomes the only format; V3 ingress, producer and recovery are deleted; tier-2 helpers ported; epoch interval pinned; reviewed manifest diff | `scripts/release_security_gate.py`: A1, A2, A2c and A3c green, plus the S-witnesses; B1/B2 green only if G0 lands in the same genesis; C1/C2 still red (G3) | `dag` pointed at O_E → A1 red. Ordering fed from staged bodies → A3c red. |

**Methodology the gate owner must approve before S10.** The V4 decided-rate uses the same 20% per-message omission as the tier-1 corpus (`ordering.rs:2206`), with fetch enabled, over the same seeds. It is compared against V3 on the same SimNet. The 0.42 floor is never lowered in the same change as a rule change.

---

## Open questions and known limits

1. **Decided-rate measure for V4.**
   - The tier-1 floor stays meaningful for the decision function, because S4 is extensionally identical there.
   - The end-to-end V4 floor needs the gate owner's ruling on the S10 methodology.
2. **Epoch interval versus reward cadence.**
   - Today one interval of 20 blocks drives both rewards and committees (`executor lib.rs:1185`, `:1223-1293`). This contract needs I ≥ 1000 and immutable.
   - Whether Move reward epochs keep a separate shorter cadence is a G5/founder decision.
3. **Cost at n=4 is unmeasured.**
   - About 36 point-to-point messages per round instead of 12, and about 11 BLS operations per node per round.
   - Fsync count is comparable to today only if certificates and `vcollect` are written unsynced.
   - There is zero slack: one slow validator paces every certificate while another is down.
4. **Guard continuity.**
   - Abstaining for the rest of an epoch after a detectable wipe removes all fault tolerance at n=4 for up to I blocks.
   - Restores from backup and cloned keys cannot be detected. They are Byzantine by definition (SA-4) and need an operating rule.
5. **G4 dependency.**
   - LA-5: HELLO-before-dispatch, the identity passed to the handler, reserved connection slots.
   - BLS verification of junk attestations and certificates remains a CPU denial-of-service surface until G4 lands.
6. **Sync authority change.** IM-1 replaces proposer-signature authority, so the three chain_sync manifest tests must be re-expressed with QCs jointly with G0. After G0, an optimization would authorize ancestors by hash-chain to a QC'd descendant; it is not required.
7. **Inclusion fairness.** A certified vertex not cited by round r+1 is never ordered, because there are no weak links. Its author re-injects the payload (EP-4). Payloads of a Byzantine or crashed author are lost until users resubmit, and `seen_txs` may block resubmission on nodes that saw them (`mempool lib.rs:699-705`). This is a throughput and censorship-resistance limit, not a safety one.
8. **Economic lag.** A slashed or jailed validator keeps consensus weight until the next epoch, because C_E is frozen. This is a G5 trade-off.
9. **Execution determinism.** It is needed for liveness (LA-7) but not for safety. A divergence halts QC formation and activation instead of forking.
10. **Leader predictability.** This is the H-2 trade-off. There is no deterministic worst-case progress bound, and `LEAD` back-pressure carries a vanishing but nonzero halt probability (liveness point 5).
11. **Witness rewrites.** A3c, A2c and the V4 controls need independent review so that they cannot be weakened. The churn in tier-2 helpers and `Vertex` literals is large.
12. **Proofs.** The proofs are informal and not mechanized. The combination of stake weights, frozen epochs and QC-bound activation is AINCORE's own and needs review.
13. **Research disagreement.** The two research readers disagree on what the printed proof of Mysticeti v4 Lemma 5 argues. This contract does not rely on it.
14. **Not verified.**
    - Nothing was compiled or run.
    - The A2 flip, the corpus predictions and every cost figure are predictions or estimates.
    - The claim that one block is produced per committed anchor rests on `anchor_already_on_chain` and its existing test (`DEFECT_REGISTER.md:438-460`), not on a new trace.

---

## Research anchors

- **Narwhal and Tusk**, arXiv 2105.11827v4. Read from the primary PDF by the research pass.
  - §3.1: the four validity conditions before signing; acknowledgement over (digest, round, creator); certificate of availability.
  - §3.3: the garbage-collection round is agreed through consensus.
  - §4.1–4.2: pulling causal history from certificate signers.
  - Appendix A, Lemma A.5: two same-author, same-round blocks cannot both be certified.
  - The paper does not cover chain or epoch binding, stake weights, or crash-durability of the vote guard. Those are AINCORE additions here.
- **Bullshark (partially synchronous)**, arXiv 2209.05633.
  - §2.1: the DAG is assumed to be valid, reliable and non-equivocating.
  - §2.2 and Algorithm 2: edge votes, commit and path-based ordering, timeouts.
  - Also cited at `PRODUCTION_READINESS_GOAL.md:961-969`.
- **Mysticeti v4**, arXiv 2310.14821v4. Read from the HTML.
  - §II-A: fixed committee per epoch.
  - §II-C: support from the voter's own signed bytes; twins kept.
  - §III and Algorithms 1–3.
  - Appendix C: Lemma 4, and Lemmas 8–12 on timeouts and the round-robin schedule.
  - Used here for the vote-from-signed-refs idea (DE-2), and as the source of the uncertified route's liveness requirements.
- **Byzantine Consistent Broadcast**, Cachin, Guerraoui and Rodrigues, Module 3.10, as named in `DEFECT_REGISTER.md:657-664`. It is the primitive that certification provides.
- **DAG-Rider**, Claim 2 ("computed locally based on v's fields"), and **Sui** `DuplicatedAncestorsAuthority`, as cited at `qc.rs:214-217` and `qc.rs:281-285`. These justify a stateless ingress gate.
- **Diem epoch-change verifier**, as cited at `PRODUCTION_READINESS_GOAL.md:1052-1057` and `:1136-1138`. It is the model for trusting a committee transition via the previous committee's certificate (EP-4).
- **RocksDB atomic updates and transactions**, as cited at `PRODUCTION_READINESS_GOAL.md:1723-1724`. A batch gives atomicity, not read-write isolation. The acceptance transactions here use AINCORE's writer-gated `StateDB::transaction` (`common/storage/src/transaction.rs:245-290`).

These sources constrain the design. They do not prove that AINCORE implements it.
