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
| `LEAD` (local) | 200 rounds | Back-pressure above this node's cursor (PR-1). |
| `T_LEADER` (local) | ≥ measured certification latency; default 2 ticks | Liveness only. |
| `T_RETRY`, `T_FETCH` (local) | 1 tick; fetch backoff doubling to 8 ticks | Driven by the receiver's clock. |

**Signed-bytes domains.** Every new signed message is `DOMAIN ‖ BCS(struct)`, as for FinalityVote (`qc.rs:56-66`).

| Domain | Use |
|---|---|
| `AINCORE_VERTEX_V4` | Vertex hash (V3 is `AINCORE_VERTEX_V2`, `blockchain/src/lib.rs:664`). |
| `AINCORE_PARENTS_V4` | Parents root. Same layout as `parents_root_of` (`lib.rs:492-509`); V3 is `AINCORE_PARENTS_V3`, `:494`. |
| `AINCORE_VERTEX_ATTEST_V1` | Attestation (BLS, `BLSEngine::consensus()`). 24 bytes, differing from `AINCORE_FINALITY_VOTE_V1` (`qc.rs:25`). |
| `AINCORE_FINALITY_VOTE_V2` | FinalityVote with `next_validator_set_hash` (IM-5). |
| `AINCORE_EPOCH_GENESIS_V1` | Epoch sentinel. |

**Types.**
- `hash_v4(v) = hex(SHA256(AINCORE_VERTEX_V4 ‖ put(chain_id) ‖ put(genesis_identity) ‖ epoch_be8 ‖ round_be8 ‖ put(author) ‖ put(parents_root_v4) ‖ put(aggregated_signature or "") ‖ timestamp_be8 ‖ put(payload_root)))`.
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
- **INVALID**: drop this copy. It never feeds a ban, a peer score or a slash (`DEFECT_REGISTER.md:80`).
- **DROP**: timing only. The vertex can be obtained again.
- **PENDING(epoch|cert)**: kept in a bounded buffer and re-evaluated on a trigger.
- **STALE**: used as evidence only.
- **STAGE**.

No rule concludes that a digest does not exist (`DEFECT_REGISTER.md:750`).

**IN-1 (two layers).** Checks run cheapest first.

- **Layer S (stateless given the epoch record of E).** Every node that knows epoch E reaches the same verdict.
  - S1: raw size ≤ `MAX_VERTEX_BYTES`, checked before parsing (`dag.rs:2681`).
  - S2: `is_live_form`; `aggregated_signature` is `None`; parents ≤ `MAX_PARENTS`; parent digests unique (`dag.rs:1185-1220`).
  - S3: `v.hash == hash_v4(v)`.
  - S4: the author is in C_E with stake > 0, and the Ed25519 signature verifies under `C_E[author].ed25519_public_key`. This replaces the live account lookup (`dag.rs:1158`, `:2114-2161`) and live membership (`dag.rs:1262-1273`).
  - S5: `first_round(E) ≤ v.round ≤ ABSOLUTE_ROUND_CEILING` (`dag.rs:1107`).
  - S6: if `v.round == first_round(E)`, then `parents == [EPOCH_GENESIS(E)]` and `parent_refs` is empty. Otherwise `qc::parent_refs_admissible(v, C_E)` applies, with its four clauses unchanged (`qc.rs:243-311`). The only edit is that its round-≤1 exemption (`qc.rs:247-249`) becomes `round == first_round(E)`.
  - Any failure → INVALID.
- **Layer E (context).** Outcomes are only PENDING, STALE, DROP or STAGE. This layer never returns INVALID.
  - E1 epoch: E = E_active → continue. E = E_active + 1, not yet activated → PENDING(epoch). E > E_active + 1 → DROP. E < E_active → STALE.
  - E2 clock: `timestamp > now + 30 s` → DROP. Today this is a hard reject (`dag.rs:1141-1151`); here it is timing only.
  - E3 floor: `v.round ≤ g` → STALE.
  - E4 parent certificates (for `round > first_round(E)`):
    - For each ref, take the embedded `CompactCert`, or else the local `vcert` for (E, ref.round, ref.author) with the ref's digest. Verify it with CE-2 (results are cached).
    - A missing or invalid certificate → PENDING(cert), and send `CERT_REQ`.
    - An invalid *embedded* certificate never makes the vertex INVALID. It is an unhashed transport field that any relay can corrupt.
  - E5 back-pressure: `v.round > cursor + LEAD` → DROP.
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

### Attestation (AT)

**AT-1 (preconditions).**
- self ∈ C_E with stake > 0.
- E = E_active.
- g < v.round ≤ cursor + LEAD.
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
- A node does not propose above `cursor + LEAD`.

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

**Extensional identity.**
- On any input where each author has at most one vertex per round in the index and at most one ref per author, DE-1..DE-4 compute exactly what `ordering.rs:586-627` computes today.
- That covers every V3-reachable input (twins are dropped at `dag.rs:1356`; C1 is at `qc.rs:293-298`) and every V4 input.

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
- At most 2 staged bodies per slot, over at most `LEAD + GC_DEPTH + RETAIN_SLACK` rounds per epoch.
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
   - PR-1's `LEAD` back-pressure could halt the chain after `LEAD/2` consecutive silent Byzantine leaders. With β < 1/3, the probability of that per window is at most 3^−100.
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
| **S4** | Shared decision edits DE-1..DE-4 in `ordering.rs`; settled-by-floor arm (a no-op with g=0) | **A2 turns green, and must be observed non-vacuous** (≥3 of 4 views commit `twin_a`). Honest corpus rate **bit-identical** at the same seeds. On the C1-legal Equivocate universe, Commit-vs-Skip is predicted to go from 807 to 0, and the Commit-vs-Undecided count is reported. Every existing ordering test is green, including `test_b4b_missing_voted_leader_defers_instead_of_false_skip` (`ordering.rs:3255`). Characterization gate `corpus_equivocation_makes_arrival_order_decisive` (`:2688`) is inverted under review: it now asserts no Commit-vs-Commit and inert permutation. Release gate expected at 6 red / 8 green. | DE-2 back to `any()` → A2 P_NODOUBLECOUNT red. DE-1 back to `find_map` → A2 ORDER leg red. DE-4 back to `leader_vertex_hash ∈ visited` → inverted Equivocate gate red. |
| **S5** | V4 pipeline under the V4 flag: all IN/ST/AT/CE/OR/PR rules, DE on O_E with a frozen C_0, RC boot, and a transport seam (`ConsensusNet` trait, production plus SimNet). Every reader re-pointed in this same increment. | **Twin-flood witness** (an equivocating leader sends both twins to all nodes; the honest producer's next vertex passes C1 and there is no 2/B plan). **A2c** `v4_certified_twin_decisions_agree_and_decide` (real RocksDB guards on 4 validators; all 8 delivery orders; at most 1 certificate; order and subset permutations agree; *mandatory* non-vacuity: the full view commits the certified twin at round 2; negative control with 2 Byzantine validators). **A3c-push** (h0 attests B first; cert(A) = {byz, h1, h2}; everyone commits 2/A with the same sequence and finality digest before and after reopen; B ∈ `dag`, B ∉ O_E). V4 twins of the complete-history control and both H3 controls. `v4_cert_conflict_halts_ordering`. `v4_leader_uses_frozen_committee` (live set mutated mid-epoch). **Slow-leader witness**: an honest leader with injected lag is still directly committed. | OR-1 without a certificate → A3c red (Y prepares 2/B, the old negative control). DE-1 over staged bodies → A2c red. Producer reads staged bodies → twin-flood witness red. Remove PR-3 → slow-leader witness red. |
| **S6** | Pull: `VertexFetcher`, CERT_REQ and ATTEST_REQ servers, per-member budgets (behind the G4 session-identity change, or signed requests as an interim) | **A3c-pull** (A's body withheld from h0; byz refuses to serve; h0 decides within K ticks; reopen mid-fetch); a withheld body is fetched from signers; a wrong body is rejected and the next signer tried; `unknown` never ends the search; **flood witness** (a spoofing non-member plus one Byzantine member flooding cannot starve an honest member's fetch) | Client off → A3c-pull red. No digest check → wrong-body red. Ask non-signers → signer-only-holder red. Treat `unknown` as absence → red. Restore the node-wide bucket → flood red. |
| **S7** | GC-1..GC-5 and OR-3 | Two nodes with different prune and checkpoint timing produce byte-identical sequences over 200 rounds; rejoin inside the window by fetch; **floor-rise witness** (a waiting child is released when g passes its parent); `committed_set` exact above g; deleting guards below g cannot enable a second attestation; byte bounds hold under a Byzantine flood | Restore the `dag.rs:1905` horizon → divergence red. Drop OR-3 → floor-rise red. FIFO `committed_set` → exactness red. Delete guards above g → double-attestation red. |
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
