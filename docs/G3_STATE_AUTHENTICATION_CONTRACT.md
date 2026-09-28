# G3 State Authentication and Rejoin Contract

> This is the proposed contract for release gate G3, "State authentication and rejoin"
> (`docs/PRODUCTION_READINESS_GOAL.md:37`): *authenticate snapshot contents and
> validator-set transitions from a documented trust anchor; rejoin across every retention
> horizon.*
>
> - Written read-only against `b7ab25a` on `audit/mainnet-hardening`, 2026-09-28.
> - **Nothing here is implemented.** Appendix B was measured on a real validator database.
>   The `jmt` behaviour cited as P1–P9 was measured by running the crate (a throwaway probe,
>   not in the repo).
> - **The data structure is a founder decision (2026-09-28):** a Jellyfish Merkle Tree from
>   the `jmt` crate (0.12, `Sha256Jmt`), behind a swappable interface.
>
> **Revision 2 (2026-09-29).** Two independent adversarial reviews attacked revision 1:
>
> 1. **Completeness.** It swept 86 production write templates and 300 write sites. No
>    template was missing. It found one misclassification (`genesis_identity`) and several
>    detail errors.
> 2. **Soundness.** It found 0 CRITICAL, 6 HIGH, 8 MEDIUM and 4 LOW.
>
> Every finding was re-checked in the code and is addressed below. The largest changes:
> - TA now builds on G1's committee and vote (EP-2, EP-4) instead of a parallel chain.
> - The trust assumption is stated, and a checkpoint is mandatory past the unbonding period.
> - SN specifies a restore procedure that survives `jmt`'s real behaviour.
> - The two H6 release witnesses are replaced, not claimed closed.
> - S0 ships in observe mode.
> - Tree storage has its own class.

---

## Status and scope

**Today.** Every block header carries `state_root`, and validators sign it inside
`FinalityVote` (`consensus/consensus/src/qc.rs:45-55`). But the value is
`H(prev_root ‖ H(sorted effective writes))` (`core/executor/src/lib.rs:2139-2163`), a hash
chain over part of each block's write-set. The two required H6 release witnesses
(`scripts/release_security_witnesses.json:31-36`, tests at `core/executor/src/lib.rs:7821`
and `:7886`) are red by design:

1. the root is blind to state written outside block execution;
2. a corrupted state snapshot is undetectable.

The inventory also found that the chain is **incomplete**: about a third of the state keys
written during block execution use plain `db.put`. Those writes are atomic with the block
but never reach the root, including:
- the per-epoch committee that QC verification binds to (`lib.rs:1313-1336`);
- `sys:total_supply` on the burn path (`lib.rs:1398-1400`);
- everything governance writes (`lib.rs:1286`).

It is also **impure**: chain data (`tx_receipt:*`) is folded into it (`lib.rs:3683`).

As a result, there is:
- no proof of any account's state;
- no verifiable snapshot;
- no authenticated committee transition;
- no rejoin except replay from genesis or a hand-copied database
  (`docs/PUBLIC-TESTNET-JOIN.md`).

**This contract settles:**
1. what `state_root` commits to;
2. which keys are consensus state;
3. the single gate those keys are written through;
4. state proofs;
5. the trust assumption and committee transitions;
6. snapshot sync and rejoin across every retention horizon;
7. pruning;
8. crash recovery and boot audit;
9. the prerequisite fixes;
10. activation.

**Dependencies:**
- **G1**
  - QCs sign `state_root`, so G3 is only as strong as G1's finality.
  - TA builds on G1 EP-1/2/4 and FinalityVote V2. **TA-2 requires a joint amendment to G1
    EP-2** (open question 5).
  - The local-view leaks listed in FX-13 are G1's to fix.
- **G0:** the legacy header hash is not injective (`consensus/blockchain/src/lib.rs:282-301`).
  Until G0 block identity v2 lands, PF-2 binds to the QC, never to the header hash.
- **G2:** atomic block commit is shared ground. CM-3 restates the part G3 needs.
- **Crypto agility / ML-DSA:** only the activation is shared (AC-1).

## Route decision

| Option | Verdict |
|---|---|
| **Jellyfish Merkle Tree (`jmt` 0.12, `Sha256Jmt`)** | **Chosen.** A sparse Merkle tree whose root is a pure function of the key→value map. It is versioned per block, and an empty change set carries the root forward (P1). Deleting an absent key, or rewriting a value with the same bytes, leaves the root unchanged (P2, P3). It provides inclusion, exclusion and range proofs, restore from chunks, and ICS23 for IBC, and it separates leaf and internal hashing. In production at Aptos (Move), Penumbra and Sovereign SDK. Apache-2.0, `sha2 0.10`. |
| Merkle Patricia Trie | Rejected: heavy reads and large proofs, and Ethereum is leaving it. |
| IAVL | Rejected: slow, and Cosmos is replacing it. |
| Verkle / EIP-7864 binary tree | Deferred: Verkle is not post-quantum, and EIP-7864 is still a draft. |
| QMDB / NOMT | Deferred: they replace RocksDB and need NVMe. Revisit through the interface. |
| Multiset or lattice hash (Sui, Solana) | Rejected: consistency only, with no per-key proofs. |
| In-house tree | Rejected: a bug means a fork or a forged proof. |

**What the crate does NOT do,** measured by probe. Our wrapper must do all of it (CM-7, SN-2):

- **P4, P5 — no version sequencing.** Applying version `v` when `v−1` is missing silently
  gives a root over `Δ_v` alone, or the empty root.
- **P9 — overwrite.** Re-applying an existing version is not refused.
- **P6 — incomplete restore accepted.** `JellyfishMerkleRestore::finish()` accepts a partial
  restore whose root is wrong.
- **P7 — restore needs an empty store.** Restoring into a store that still holds an older
  tree panics (`node_type.rs:92`).
- **No key preimages.** Restore chunks carry key hashes only.

The tree sits behind a `StateCommitment` trait: `apply`, `prove`, `prove_range` and `restore`.
A later backend (NOMT/QMDB, or a binary + Poseidon tree for ZK) can replace it without
touching the executor.

**Hash: SHA-256.** It matches the codebase, and EVM verifies it cheaply via a precompile.
Hash-only commitments are post-quantum safe (Grover only).

**Size.** 79 consensus-state keys out of 2,982,055, tens of KB of values (Appendix B). The
tree is tiny.

## Definitions

- **Classes** (Appendix A assigns every template):
  - **S, consensus state.** In the tree. See CL-2.
  - **C, chain data.** Finalized history and its deterministic indexes, committed through
    block hashes.
  - **L, consensus-local.** This node's own consensus view; it may differ between honest
    nodes.
  - **N, node-local.** Operational data and secrets.
  - **K, chain constant.** Fixed by the genesis inputs. Computed once from `genesis.json`,
    never from the tree.
  - **T, tree internals.** The tree's own nodes, value history, stale index, preimages and
    markers. Never in the tree.
  - **A, transition log.** Self-authenticating entries (TA-3). Never in the tree.
- **Version `v`:** the block height. Genesis is version 0.
- **`M_h`:** every S key mapped to its exact stored bytes after block `h`.
- **`Δ_h`:** the S keys whose value differs from `M_{h-1}`, with deletions as `None`.
- **`KeyHash(k)`:** `SHA-256(k)` over the UTF-8 key (the `jmt` default).
- **`state_root(h)`:** the `Sha256Jmt` root over `{(KeyHash(k), M_h[k])}`.
- **`E(h)`:** the epoch of height `h`, per G1 EP-1: `⌊(h−1)/I⌋`, with `I` fixed at genesis.
- **`C_E`:** the committee of epoch `E` (TA-2).

## Rules

### Classification (CL)
- **CL-1:** One total function `state_class(key)` in `common/storage`.
  - It matches **exact templates, including zero-padding**, never prefixes. Every prefix is
    mixed today:
    - `sys:` holds S, L, N and a node secret;
    - `consensus:` holds S epoch keys among L;
    - `validator:` holds S and L;
    - `block_` also matches `block_txs:`.
  - An unknown key is refused at write time, **from S3 on**. Before that, in S0, it is
    logged and counted (observe mode).
- **CL-2:** A key is S iff:
  - (a) its value is a deterministic function of genesis plus finalized blocks; and
  - (b) block execution or genesis writes it as protocol state: not history, not a cursor,
    not a cache of history.

  Every key that influences a future block's execution or a validity rule meets this test.
  So does governed or tracked state that no rule reads today (for example
  `sys:config:base_reward`, `validator:jailed`); it goes in the tree so clients can prove it.
- **CL-3:** Block execution reads only S keys, plus C keys that are pure functions of
  finalized history. A read guard on the executor's view enforces this in test builds.
  - A C key may **gate** whether a height executes (`sys:last_executed_height`,
    `lib.rs:1636`), but must never change the result.
  - Today's violations are `latest_height` feeding a state key name (FX-4) and `tx_receipt:*`
    feeding `receipts_root` (FX-5).
  - `genesis_identity` (K) reaches execution through the process-global vertex domain
    (`core/node/src/main.rs:566-575` → `Vertex::calculate_hash`, used by slash-evidence
    checks at `lib.rs:2392`). The view guard cannot see this read. It is allowed because K is
    fixed and verified at boot (TA-1).
  - Sync admission reads the L keys `consensus:qc:latest` and `consensus:finalized_round`
    (`sync/src/lib.rs:583`, `599-611`, `1062`). These are G1 finality gates and are exempt
    here (FX-13).
- **CL-4:** No S value depends on:
  - wall clock;
  - node identity;
  - the environment;
  - arrival order;
  - hash-map order;
  - floating point.

  Every known exception is listed under FX.

### Write gate (WG)
- **WG-1:** S keys are written only inside the **block transaction**: the one
  `StateDB::transaction` that the executor's commit opens and marks at construction. In any
  other transaction, and on the base database, `put`, `delete` and `write_batch` refuse S keys.
  - **Enforced from S3.** In S0 the refusal is logged and counted, and the counter is a
    witness.
  - Tests seed S keys through a gated seeding API, not through base-database puts.
- **WG-2:** Genesis writes its S keys through the same gate, as version 0 (FX-7).
- **WG-3:** No RPC, startup migration, backfill, sync shortcut, CLI or consensus path writes
  an S key (FX-1, FX-3, FX-8).
- **WG-4:** A persisted copy of S data is itself S and is written in the same block
  transaction.

### Commit (CM)
- **CM-1:** `Δ_h` is derived from the block transaction's **staged changes**, not from a
  write log.
  - Every block-time write is already staged in one private view and published as one
    synced batch (`common/storage/src/transaction.rs:264-309`). The stage keeps the last
    write per key (`BTreeMap`, `:13`, `:155`, `:194-204`).
  - At commit, the executor filters the staged changes to class S and diffs each against the
    **committed tree value at `h−1`**. That value equals the flat pre-block value whenever
    RC-2 holds. Diffing against the tree keeps the result deterministic even if a flat key
    drifted, and RC-2 catches the drift.
  - A delete of an absent key, or a same-bytes rewrite, is not a change. Today every slash
    stages such a delete (`lib.rs:2507`, `2534`, `2692`).
  - The write log (`block_effective_writes` / `block_write_log`) is deleted.
- **CM-2:** `(root_h, tree_batch) = tree.put_value_set(Δ_h, h)`, computed inside the
  transaction before the header is built. The stage is then **sealed** for S keys: any S
  write after sealing fails the transaction.

  The `accept` closures run after this point (`lib.rs:1737-1751`; `dag.rs:1704-1741`;
  `sync/src/lib.rs:1169-1172`) and may write only C, L and T keys.
- **CM-3:** One synced `WriteBatch` holds:
  - `Δ_h`;
  - the tree batch (T keys);
  - block `h` and its C indexes;
  - the height markers;
  - the T marker `jmt:latest = h`.

  No S write for block `h` exists outside this batch.
- **CM-4:** `header.state_root = hex(root_h)`. The vote is **FinalityVote V2** (G1 IM-5 /
  `G1_CONSENSUS_CONTRACT.md:263`). It must keep `state_root` and adds
  `next_validator_set_hash`.
- **CM-5:** Every executed block creates version `h`. An empty `Δ_h` carries the root
  forward (P1).
- **CM-6:** Sync import and local build share `execute_block_admitted_at` and one
  transaction, so they produce the same `Δ_h` and root. FX-1 removes the only S asymmetry
  found.
- **CM-7: sequencing, which the crate does not enforce (P4, P5, P9).**
  - Before `put_value_set(Δ_h, h)`, require `jmt:latest == h−1` and that the root node of
    `h−1` exists. Otherwise abort the transaction.
  - The `TreeWriter` refuses to overwrite an existing node key.
  - Witness: delete the root of `h−1`; execution must refuse.
- **CM-8: tree storage.**
  - Tree data lives only under T templates (Appendix A).
  - Binary node and value bytes are hex-encoded, or read through the byte-level
    `ReadStore::get` (`transaction.rs:90-105`). `StateDB::get` treats non-UTF-8 as a failed
    read (`common/storage/src/lib.rs:201-213`), and that fails the whole block
    (`transaction.rs:295-299`).
  - `get_value_option(max_version, key_hash)` needs a reverse seek over
    `jmt:val:{kh}:{version:020}`, so the storage layer gains a bounded reverse-iteration read.
  - **The flat S key is the execution source.** The tree's value history is used for proofs
    only.

### Determinism (DT)
- **DT-1:** The root does not depend on the parallel batch schedule. Witness: the same block
  run under two schedules gives byte-identical roots.
- **DT-2:** After any random block sequence, the incremental root equals a from-scratch root
  over the S keys (differential witness).
- **DT-3:** Two nodes built from the same `genesis.json` on different machines, CWDs and
  `node.key`s produce the same `state_root(0)` and genesis identity (FX-7).

### Keys and values (KV)
- **KV-1:** The tree value is exactly the stored bytes of the flat key.
- **KV-2:** One canonical encoder builds every `resource_`, `module_` and account key,
  replacing four hand-written builders (FX-9). Its format is frozen and published, and proof
  clients derive `KeyHash` from it themselves.
- **KV-3:** Accounts and governance proposals get separate namespaces, if governance is kept
  (FX-9).

### Proofs (PF)
- **PF-1:** `aincore_getStateProof(key, height?)` returns
  `{key, value | null, height, proof, header, qc}`. An absent key returns an exclusion proof.
- **PF-2:** A client verifies all of the following. Any failure means the result is
  rejected:
  1. The QC verifies under `C_{E(height)}`, with the committee selected **by height** from a
     committee chain the client trusts (TA).
  2. `qc.epoch == E(qc.block_height)`.
  3. `qc.block_height == height`.
  4. The proof verifies against **`qc.state_root`**, not against header fields. That holds
     until G0 identity v2 makes the header binding injective.
  5. `KeyHash` is derived locally from the canonical key (KV-2), never taken from the server.
  6. Freshness: `height` is at least the client's known finalized height, or equals the
     height the client asked for. A proof at an old height is not an answer to "latest".
- **PF-3:** Proofs are served at or above the retention floor marker `jmt:floor` only.
- **PF-4:** A Rust verifier ships in the workspace and a JS verifier in `aincore-js`. Both
  are tested against one shared vector set.

### Trust assumption and committee transitions (TA)
- **TA-0: stated assumption.** Past committees are assumed never to have 1/3 or more of their
  stake compromised while that stake is still bonded.

  After unbonding (21 days, `core/vm_move/stdlib/sources/staking.move:84`), an old
  committee's keys carry no stake at risk. They could sign a forked transition chain (a
  long-range attack). Therefore:
  - Any node or client whose trusted state is **older than the unbonding period** must
    anchor on a **weak-subjectivity checkpoint**, `(height, block hash, state_root, QC)`,
    no older than that period.
  - Checkpoints are published with every release and pinned by the operator.
  - Genesis alone is a valid anchor only within the unbonding period from genesis.
- **TA-1: genesis anchor (K).**
  - The genesis identity (`core/node/src/genesis.rs:296-325`) is extended with
    `state_root(0)`.
  - Both are computed **once, in memory, from `genesis.json`** by deterministic genesis
    (FX-7). The genesis state is small.
  - The result is checked against `AINCORE_EXPECTED_GENESIS_HASH` and never recomputed from
    the tree, which may be pruned or restored (fixing `genesis.rs:620-669`).
- **TA-2: committee record (joint with G1 EP-2).**
  - For each epoch there is one S record, `sys:committee:{E+1}`.
    - The executor writes it at `H_E`, the last block of epoch `E`, **before the seal**.
    - It is derived by G1 EP-2's validated rule, which carries over `C_E` if the new set is
      invalid.
    - The write happens **whether or not Move `advance_epoch` succeeds** (FX-14).
  - G1 EP-2 is amended to **read this record** instead of deriving and writing its own
    `consensus:dag_committee:{E+1}` after the seal. This makes one committee and one source.
  - **Primary authentication** is `QC(H_E)`, verified under `C_E`, whose FinalityVote V2
    `next_validator_set_hash` equals `validator_set_hash(C_{E+1})`.
  - The state proof of `sys:committee:{E+1}` against `qc.state_root` supplies the member
    list.
  - G1 EP-4 guarantees `QC(H_E)` exists before `E+1` activates.
- **TA-3: transition log (class A).**
  - One entry per epoch: `E`, the header of `H_E`, `QC(H_E)`, `C_{E+1}`, and its state proof.
  - Entries are self-authenticating: each is verified on receipt against the previous
    entry's committee, and any valid QC is accepted.
  - A node captures the committee proof in the post-commit step of `H_E`, while version
    `H_E` is certainly retained. It appends the entry when `QC(H_E)` is held, and G1 EP-4
    makes that unavoidable before `E+1`.
  - Transport is `TA_LOG_REQ` / `TA_LOG_RESP`.
  - A node serves as a TA source only while its log is complete from its anchor.
  - Never pruned.
- **TA-4: checkpoints** are the TA-0 mechanism. They are signed by the release process and
  published with each release, including in its notes.

### Snapshot sync and rejoin (SN)
- **SN-1:** A joining or long-offline node establishes a trusted `(h, header, QC(h))` through
  TA from its anchor. The anchor is a checkpoint when TA-0 requires one.
- **SN-2: restore procedure.** It survives `jmt`'s real behaviour (P6, P7).
  1. Restore into a **fresh database**, or an empty tree namespace, with the marker
     `sys:restore_in_progress = {h, qc.state_root}` (class N).
  2. Delete every flat S key first. Stale flat keys would otherwise be read by prefix scans
     (`lib.rs:1586`) and fork the node at `h+1`.
  3. Chunks carry `(key, value)` pairs plus the `jmt` range proof, and come from untrusted
     peers. For each pair the joiner checks that `SHA-256(key) == leaf KeyHash` and that
     `state_class(key) == S`. It writes the flat key only from a verified chunk, and records
     the preimage (T).
  4. After `finish()`, it reads the root at version `h` and requires it to equal
     `qc.state_root`. Otherwise it wipes and restarts. `finish()` alone proves nothing (P6).
  5. The marker is removed in the same batch that writes the SN-1b record. RC-1 treats a
     present marker as "restore incomplete": wipe and restart, never boot.
- **SN-1b: consensus bootstrap record.** It is written atomically at the end of SN-2, and
  every field comes from the TA-verified `QC(h)` and header, never from a peer's database:
  - `consensus:finality_digest := qc.finality_digest` (G1 IM-1 needs it for `h+1`);
  - `consensus:last_anchor_round` and `consensus:last_anchor_hash` from the QC;
  - `block_{h} := header`;
  - `latest_height = latest_block_hash-height = sys:last_executed_height = jmt:latest = h`;
  - the committee for `E(h)`, from TA;
  - `genesis_initialized`. Genesis initialization never runs on a datadir that carries a
    restore marker or a bootstrap record.
  - K values are recomputed from the local `genesis.json` and checked against the anchor.
- **SN-3:** The node then imports blocks `h+1…` through the normal path.
- **SN-4: every retention horizon.**
  - **Offline for less than block retention:** block replay.
  - **Beyond block retention:** snapshot at a **pinned** version. Every epoch-boundary version
    `H_E` is retained for at least `T_restore_max`. The joiner picks the largest pinned
    version that is at or above `tip − block_retention`.
  - **Beyond the unbonding period:** a TA-0 checkpoint, then the TA-3 log from it, then a
    pinned snapshot.
  - Witnesses:
    - a peer prunes during a restore;
    - a long-offline node with stale flat keys;
    - a crash mid-restore;
    - a truncated final chunk;
    - a forged chunk.
- **SN-5:** This supersedes the unverified snapshot install (`core/node/src/main.rs:57-151`)
  and `state_chunks_root` in `docs/STATE-SYNC-SPEC-2026-06-16.md`.
- **SN-6: signing guards.**
  - A restored node, or any new datadir, starts with empty L signing guards. It never
    restores `consensus:qc_signing:*` or `consensus:vattest:*` from any source.
  - It triggers **G1 RC-3 abstention** (`G1_CONSENSUS_CONTRACT.md:702-705`) until the next
    epoch, so an old key can never sign a second time for a slot it already signed.

### Pruning and retention (GC)
- **GC-1:**
  - **Tree nodes:** pruned below the floor `jmt:floor` through the stale-node index.
  - **Values:** for each key, keep the newest value at or below the floor, plus all newer
    ones. The stale index covers nodes only (`writer.rs:102-111`).
  - **Carried roots:** a root carried forward by an empty block is marked stale at the next
    version (`tree_cache.rs:316-323` does not do this).
  - **Pinned versions** (SN-4) are exempt until `T_restore_max` expires.
  - Archive mode keeps everything.
- **GC-2:** Pruning is node-local and never changes a root. S keys are deleted only by
  protocol rules inside CM.
- **GC-3:** The TA-3 log is never pruned.

### Crash recovery and boot audit (RC)
- **RC-1:** At boot, `jmt:latest`, `sys:last_executed_height` and the latest block height
  must be equal, and no restore marker may be present. Otherwise the node refuses to start.
- **RC-2: flat-vs-tree consistency, and only that.** At boot the node:
  1. walks the tree's leaves at the latest version and compares each with its flat key;
  2. walks the flat S templates. They share no prefix with the large families (`block_`,
     `consensus:qc*`, `da_`), so the cost is O(|S|), not O(DB).

  Any divergence means it refuses to start and lists the keys. The comparison is against each
  leaf's newest value row. This detects an out-of-band edit to a flat S key, and a stale
  value row left behind (for example by a failed restore). It does **not** detect a
  self-consistent replacement (see RC-3).
- **RC-3:** When the node holds a QC-verified header for its latest height, or for any
  height at or above the floor, the tree root at that version must equal `qc.state_root`.
  That is how a self-consistent but foreign database (a restored backup, a copied datadir) is
  caught once the node sees the network's QC.
- **RC-4:** Guard continuity follows SN-6. A restored backup of a validator's own datadir
  also triggers G1 RC-3 abstention.

### Prerequisite fixes (FX)

Each item was found by the inventory or a review, and re-checked at `b7ab25a`.

- **Neutral** fixes change no root or header on today's chain.
- **Changing** fixes alter execution results and land with the fresh genesis.

| # | Fix | Where | Kind |
|---|---|---|---|
| FX-1 | `validator:jailed:{addr}` has two writers: the in-block jail (`lib.rs:2451`) and a consensus-local write when *this node* detects an equivocation (`dag.rs:2500`). The local value is the most recent round this node detected. The local write moves to its own L key, `sys:equiv_local_jail:{addr}`. The downtime detector skips a validator that holds either key. | consensus | neutral (done in S0) |
| FX-2 | Classify the legacy committee keys `sys:validator_set:epoch:{E}`, `consensus:epoch` and `consensus:epoch_start_height:{E}` as S **for today's chain**. They feed QC verification and admission now. G1 EP-1 retires them from consensus at activation, when `sys:committee:{E}` replaces them. | classifier | neutral |
| FX-3 | The governance module upgrade installs bytecode from `sys:pending_module_upgrade:{name}`, which **no production code writes** (only tests). It bypasses the VM verifier (`governance/lib.rs:550-627`). Remove the path until staging is an executed transaction and installation goes through VM publish. | governance | neutral (dead today) |
| FX-4 | The fee-sweep key uses `latest_height` (C) instead of the executing block height. | `lib.rs:2105`, `1562` | changing |
| FX-5 | `receipts_root` re-reads `tx_receipt:*` from the database. A transaction whose bytes repeat an earlier one hashes the stale receipt, and a node restored without receipts computes a different root. Receipts are never pruned today (`storage/src/lib.rs:537-540`). Compute it from this block's in-memory results. | `lib.rs:1024-1038`, `2183` | changing |
| FX-6 | The chain id comes from two sources. Validity reads the env `AINCORE_CHAIN_ID` (executor `lib.rs:18`/`3095`, mempool `lib.rs:207`, `qc.rs:328`), while the vertex domain and QC signing prefer `sys:chain_id`. Make `sys:chain_id` the only source, and assert at boot that the env equals it. Also remove the `AINCORE_EPOCH_BLOCK_INTERVAL` fallback (`lib.rs:1212-1218`): refuse to start instead. A test-only symptom already exists today: the node test suite races on this env var. | executor, mempool, qc | neutral while env == genesis |
| FX-7 | **Genesis must be identical on every node:** | `genesis.rs` | genesis |
| | • Drop the account each node writes **for itself** (`genesis.rs:720-730`). | | |
| | • Require explicit BLS keys for every validator (`:885-890`). | | |
| | • Fail on a missing or unparseable `genesis.json` (`:793-813`, `:914-953`). | | |
| | • Pin the stdlib by hash in `genesis.json` (`main.rs:512-520`). | | |
| | • Seed `sys:config:burn_percentage`, `sys:config:tip_agreement_n` and `total_burned`. | | |
| | • Write everything in one batch through WG-2. | | |
| | • Compute the identity and `state_root(0)` in memory (TA-1). | | |
| FX-8 | Remove the direct state writes of `aincore_faucet` and `aincore_testMintWbtc` (`api_local.rs:480-650`). A testnet faucet becomes a service that sends signed transactions. Remove the unverified snapshot install once SN lands. | node | neutral |
| FX-9 | One canonical key encoder (KV-2). Canonicalize the paymaster lookup, which uses a caller-supplied public-key string as an object id (`lib.rs:3372`). Move proposals out of `obj:` only if governance is kept: nothing in production creates a proposal (the RPCs are disabled, `api_local.rs:1214-1237`), so the Rust governance driver never writes anything today. | executor, genesis, api | changing |
| FX-10 | One account, one encoding. `type_struct` is `0x1::account::AccountData` on implicit creation (`lib.rs:3146`) but `0x1::account::Account` via genesis or the faucet. | executor, aa | changing |
| FX-11 | **Delete dead state-shaped code:** | several | neutral |
| | • `meta_resource_*` reads with the wall clock (`vm_move/src/lib.rs:82-102`) | | |
| | • `promote_downtime_attestations_to_slash` (`lib.rs:2228`) | | |
| | • `create_proposal`, `vote`, and the `pub` non-test `test_seed_proposal` (`governance/lib.rs:288-417`, `788-791`) | | |
| | • `update_validator_weight` | | |
| | • the unreachable downtime branches (`lib.rs:2453-2464`, `2397-2427`) | | |
| | • the writer-less RPC namespaces (`delegation:`, `unbonding:`, `validator_pool:`, `token:`, `token_balance:`, `sys:fhe:*`, legacy `total_supply`) | | |
| | • if governance is not kept, the Rust governance driver | | |
| FX-12 | The mempool reads state without a snapshot while a block commits (`mempool/lib.rs:504-532`). Read the chain id from `sys:chain_id` and balances from a committed snapshot. **Lands in S2**: it needs versioned reads. | mempool | neutral |
| FX-13 | **For G1, recorded here:** vertex admission uses the node's tip epoch and committee (`dag.rs:619-634`, `1287-1297`); commit and skip decisions use the tip committee (`dag.rs:1502-1505`); QC chain-id sources differ (`dag.rs:2003-2026` vs `qc.rs:328`); sync admission reads L finality keys; and `verify_qc` never checks `qc.epoch` against the height (`qc.rs:338-360`). | consensus | G1 |
| FX-14 | **Live halt path.** If Move `advance_epoch` aborts or errors, `maybe_advance_epoch` returns before rotating (`lib.rs:1263-1270`, `1289-1291`). That leaves a gap in `consensus:epoch_start_height:*`. At the next boundary `epoch_for_block_height` returns None (`qc_producer.rs:130-157`) and `stage_pending_qc` fails (`recovery.rs:32-33`) on every retry, so every validator halts. Rotate at every boundary whatever the Move outcome, with carry-over. The fix is tracked as its own task because today's chain runs this code. | executor | neutral on the success path |
| FX-16 | **Found in S2:** the paymaster field is the payer's PUBLIC KEY, and it is used directly as the payer's object and CoinStore key (`obj:{pubkey}`, `resource_{pubkey}_…`), not the address `SHA-256(pubkey)` that every other account uses. S2 only canonicalizes its spelling (FX-9). Making the payer an address changes paymaster semantics and needs its own decision. | executor | changing (open) |
| FX-15 | Make root binding unconditional. Remove the `sys:config:require_exec_roots` knob and its env fallback, and the empty-root bypass in sync (`sync/src/lib.rs:215-222`, `275-294`). | sync, genesis | changing |

### Activation (AC)
- **AC-1:** BREAKING. `state_root` changes meaning, the vote becomes FinalityVote V2, the
  genesis identity gains `state_root(0)`, and FX-4/5/7/9/10/15 change execution results.
  Activation needs a new `GENESIS_VERSION` and one fresh genesis, shared with G1 S11 and
  crypto agility.
- **AC-2:** No dual mode. The hash-chain root and its write log are deleted.

## Witness mapping

The two required release witnesses **cannot turn green under this design; they are
replaced.** Under WG-1 their base-database puts are refused, so they panic. And the
properties they probe move to boot, restore and QC comparison.

The replacements below must be reviewed by the gate owner in the same way as any change to
the witness list.

| Witness | Replacement / closure |
|---|---|
| **C1** `test_h6_state_root_is_blind_to_out_of_band_writes` (`lib.rs:7821`) | **C1′:** an out-of-band S write through **every** `StateDB` entry point is refused (WG-1). A raw RocksDB edit of a flat S key makes boot fail and lists that key (RC-2). |
| **C2** `test_h6_a_corrupted_state_snapshot_is_undetectable` (`lib.rs:7886`) | **C2′:** a snapshot with one tampered S row is refused by SN-2 at the chunk that contains it. A copied database with one tampered flat S row fails RC-2. A self-consistent foreign database fails RC-3 against a network QC. |
| execution reads only S or finalized C | CL-3 read guard |
| schedule independence; incremental equals from-scratch | DT-1, DT-2 |
| genesis identical across machines | DT-3, FX-7 |
| every S write is under the header's root | CM-2 seal: an S write after sealing fails |
| version sequencing | CM-7: a missing `h−1` root refuses; an overwrite refuses |
| proof round-trip; stale or foreign proof refused | PF-1..4: absent keys, deletions, an old-height QC, a QC from the wrong epoch, a server-supplied KeyHash |
| committee chain | TA-2, TA-3, from genesis to epoch N, **including an epoch whose `advance_epoch` aborted** (FX-14) |
| long-range fork refused | TA-0: a forged transition chain from an unbonded committee is refused by a checkpoint |
| restore from adversarial peers | SN-2: a forged chunk, a truncated final chunk, a partial `finish()`, stale flat keys, a crash mid-restore |
| rejoin at every horizon | SN-4, including a peer that prunes mid-restore |
| guard continuity | SN-6, RC-4: a restored or copied datadir abstains |
| crash at every point of the commit batch | CM-3, RC-1 |
| unclassified key | CL-1: logged in S0, refused from S3 |
| no out-of-band S writer remains | WG-1: drive every RPC, boot path and consensus path, and no S key changes |

Every witness needs a mutation proof: break the rule, watch the test fail, restore it. Each
also needs a **positive control that the mutant was actually applied and the test actually
ran**. "0 tests ran", or an unapplied mutant, must never count as green.

## Staged implementation plan

| Stage | Content | Breaking? |
|---|---|---|
| **S0** | `state_class` in **observe mode** (CL-1, WG-1 counted, not refused); FX-1, FX-2, FX-3, FX-6, FX-8, FX-11; the gated test-seeding API. FX-14 ships separately and first (live halt path). | **No.** Rolling deploy; the counters show what enforcement would refuse. |
| S1 | `StateCommitment` + `jmt` backend as a library: apply with CM-7 sequencing, prove, range proof, restore per SN-2; DT-2 and PF vectors; T storage (CM-8) | No |

**S0 status (branch `audit/mainnet-hardening`, rolling).**
- Part a is live: the classifier in observe mode, which classifies the FX-2 committee keys
  as S; FX-1; the rent read and `update_validator_weight` removed.
- Part b:
  - **FX-6:** `blockchain::chain_id()` is the one accessor for transaction admission,
    execution and QC signing and verification. The node installs it from `sys:chain_id`
    at boot. The env is never read. Boot refuses to start when `sys:chain_id` is
    missing, or when `AINCORE_CHAIN_ID` names another chain. The epoch interval comes
    only from the genesis pin, and boot refuses a missing pin or an env that disagrees
    with it. The node test race is gone: 10 of 10 parallel runs are green, where it used
    to be 19 of 20 red, and the stopgap test lock is removed.
  - **FX-8:** `aincore_faucet` and `aincore_testMintWbtc` are removed. The names answer
    `-32030` with the reason, and nothing is written. The unverified snapshot install is
    still there; it goes with SN.
- Still open in S0:
  - FX-3, which waits for the founder's governance decision;
  - the rest of FX-11. `promote_downtime` is kept on purpose, and the downtime branches
    wait for S2.

**S1 notes.**
- It lives in `common/state_commit` and pins `jmt = "=0.12.0"`, the version P1–P9 were
  measured on.
- Every call into `jmt` is wrapped so that a panic becomes an error. `jmt` unwraps reader
  results and asserts on restore state, so a corrupt row or a hostile peer could otherwise
  crash the node. This relies on `panic = "unwind"`, the workspace default.
- A restore that refuses one chunk is poisoned: `jmt` mutates its state before verifying and
  never rolls back. The caller must `wipe_tree` and begin again.
- `finish` returns the `jmt:latest` marker as a batch, for SN-1b to commit atomically.
- Proof vectors for the JS verifier come with S4. S1 pins one golden root, reproduced
  independently without `jmt`.
| S2 | Executor integration: `Δ_h` from staged changes, seal, one batch, `state_root = root_h`. Includes FX-4, FX-5, FX-9, FX-10, FX-12, FX-15. | **Yes** |

**S2 status (branch `g3/activation`).**
- CM-1/2/3/5/6 are done:
  - the hash chain and write log are deleted;
  - the root is `state_commit::apply` over the staged state changes, and the stage is then
    sealed;
  - version 0 is seeded when block 1 starts (S3 moves it into genesis).
- RC-1 is done: `state_commit::boot_check` runs before the executor starts.
- FX-4: the fee sweep is keyed by the executing height.
- FX-5: `receipts_root` uses only the block's own staged receipts.
- FX-9 (partial):
  - `vm_move::state_keys` is the encoder for the VM resolver, overlay and changeset;
  - golden tests pin the validator-set key and the genesis system-resource keys to it;
  - consensus uses the executor's validator-set key;
  - the paymaster spelling is lowercased.

  Still hand-written, and producing identical strings today:
  - executor `resource_…` builders (`lib.rs` near 83, 108, 337, 353, 369);
  - the literal-hex Epoch key near 1342;
  - the conflict tokens near 2706-2935;
  - the RPC read helpers in `api_local.rs`.

  The `obj:` account key has no canonical encoder, and it stores `tx.public_key` in whatever
  case the client sent. The rest of FX-9 lands in S3.
- FX-10: implicit accounts use the genesis constructor.
- FX-15: empty roots are always refused; the switch and its env fallback are gone.
- FX-12 needs no change: S2 changed nothing in the mempool. The block commit was already
  one atomic batch, and the mempool's one balance read is a single key, so it cannot see a
  torn block. Its chain-id half is FX-6.
- FX-16 is recorded above and still open.
- FX-7, first bullet, moved up from S3: genesis no longer writes an account for the
  booting node's own key. With a lazily seeded version 0, that account made every node
  that is not a genesis validator compute a different block-1 root. Witness:
  `a_follower_and_a_validator_agree_on_the_block_one_root`.
- FX-15 remainder for S3: genesis still writes `sys:config:require_exec_roots`, which
  nothing reads. It is in version 0 and in the genesis identity.
- **No pruning yet.** With 20,000 state keys and 8 changed keys per block, the tree
  grows by about 35 KB per block, which is roughly 1 GB a day at 3-second blocks. Do not
  run S2 long-lived without S7.

| S3 | Genesis as version 0; identity with `state_root(0)` in memory; **WG-1 enforcement on** | **Yes** |

**S3 go/no-go.** The S0 counters alone are not enough to switch enforcement on:
- They live in memory and reset on every restart.
- Databases built offline (`genesis-tool`) or installed as snapshots never pass through them.
- Until S2 seals the stage, state written by the accept/admit closures still counts as a
  block write.

Enforcement therefore requires all of the following:
- the logged `[STATE_CLASS]` lines, collected across restarts on every node, show no
  legitimate refusal;
- the snapshot install is gone (FX-8/SN-5);
- genesis runs through WG-2.

The `aincore_getStateClassStats` RPC is public. It exposes only masked key shapes and
counters, never values.

**S3 status (branch `g3/activation`).**
- **Go/no-go evidence, 2026-09-29.** The live cluster runs observe mode.
  - r1 and r2 logged no `[STATE_CLASS]` line in 40 hours across 4 restarts.
  - All four validators report `unclassified = 0` and `state_outside_block = 0` across
    190,000 to 500,000 writes since boot.
  - The faucet is removed (S0b, live).
  - Genesis now runs through WG-2 (S3a).
  - The snapshot install remains, and goes in S3c.
- **S3a (deterministic genesis) is done.**
  - `build_genesis(genesis.json, stdlib)` builds the genesis state purely in memory. It
    takes nothing from the booting node: not its key, CWD or env.
  - `commit_genesis` writes it in one block transaction as state-tree version 0, and
    checks that the tree root equals the in-memory root. Then it seals.
  - The identity (`AINCORE_GENESIS_ID_V2`) binds `state_root(0)`. It is computed once, in
    memory, at genesis, and never recomputed: not from the tree, and not from genesis.json
    on a reopen.
  - A reopen reads neither genesis.json nor the stdlib. A rebuild on every boot would make
    each later stdlib update or genesis-code change refuse existing nodes (S3a review,
    MEDIUM). The operator's `AINCORE_EXPECTED_GENESIS_HASH`, checked against the stored
    identity, refuses a wrong datadir.
  - Genesis refuses a database that already holds any state key (S3a review, LOW).
  - FX-7:
    - no self-account;
    - explicit BLS keys for every validator;
    - a missing or unparseable genesis.json is an error, and the `../` search paths are
      gone;
    - genesis.json pins `stdlib_hash`;
    - `sys:config:burn_percentage` (default 10), `sys:config:tip_agreement_n` (default 1)
      and `total_burned` are seeded;
    - a validator listed twice, or any key written twice, is refused.
  - FX-15 is complete: `sys:config:require_exec_roots` is no longer written.
  - The executor's lazy v0 seeding is gone. RC-1 refuses a database with no tree after
    genesis.
  - `GENESIS_VERSION` is `g3-deterministic-v5`.
  - **Activation note:** every genesis.json needs the `stdlib_hash` field and explicit
    BLS keys. `genesis-tool gen-multi` writes both. The live `genesis.4r.json` has
    neither, as expected: S3 activates only with the S8 fresh genesis.
- **S3b (WG-1 enforcement) is done.**
  - `ReadStore::write`, the single write funnel, refuses any batch holding a state key
    outside the block transaction: base writes and plain transactions alike. The whole
    batch is refused and nothing is written. The error is `StorageError::WriteGate`, and
    `state_outside_block` counts the refusals. `aincore_getStateClassStats` reports
    `mode: enforce`.
  - The write APIs return `StorageError`. Every caller compiled unchanged.
  - Tests seed genesis-like state through `StateDB::seeding()`, a scoped guard. It exists
    only under `cfg(test)` and the `test-seeding` feature, which crates enable in
    `[dev-dependencies]` only. `cargo tree -e normal,features` shows that no production
    build of `node` has it. The guard holds only its counter, never the database.
  - Production calls that ignore a write result (`let _ = storage.put(..)`) would lose a
    refused write silently. A test pins that every key they write outside a block is
    non-state (`best_effort_production_writes_are_never_state`). The executor's epoch keys
    are state, but they are written inside the block transaction.
  - **Witness C1′ (storage half):** a state write through every `StateDB` entry point
    outside the block transaction is refused. The entry points are put, delete, a mixed
    batch, `put_object`, the federation key, the economic config and a plain transaction.
    The ignored H6 witnesses C1 and C2 stay as they are until the gate owner reviews
    C1′ and C2′. C1′'s RC-2 half and C2′ need S6 and S7.
- **S3c is done.**
  - SN-5: the unverified snapshot install (`AINCORE_BOOTSTRAP_SNAPSHOT`) is removed. A
    node that still sets the variable refuses to start. Until S6, a node syncs from
    genesis. The DR runbook, the join doc and the backup script say so.
  - The rest of FX-9: the executor's stored-key builders, its conflict tokens and the
    RPC read helpers all build `resource_…` keys through `vm_move::state_keys`. An
    implicit account stores its public key in lower case, whatever case the client sent.
    The strings were already identical; the one encoder now builds them all.
  - Still hand-built, deliberately: governance's `system_module_storage_key`, the FX-3
    upgrade path that waits for the founder's decision; and an unparseable sender's
    conflict token, which only has to be distinct.
- **S3 is complete.** S4 (proof RPC and verifiers) is next.
| S4 | Proof RPC + Rust and JS verifiers (PF) | No, once S2 is live |

**S4 status (branch `g3/activation`).**
- **PF-1:** `aincore_getStateProof(key, height?)` returns `{key, value | null, height,
  state_root, proof, header, quorum_certificate}`. It serves state keys only. The height
  defaults to the latest one with a QC. It refuses heights outside `jmt:floor..=latest`
  (PF-3).
- **Wire proof:** `{leaf: {key_hash, value_hash} | null, siblings: [hash…]}`, all 64-hex,
  with siblings from the bottom to the root. `state_commit::wire_proof` decodes `jmt`'s
  borsh proof. The client verifier checks every proof against the tree's root before it
  leaves the node.
- **PF-4:**
  - `common/state_proof` is a Rust verifier with no database and no `jmt`.
  - `aincore-js/src/stateProof.ts` mirrors it line for line.
  - Both pass `common/state_proof/vectors/pf_vectors.json`: 12 valid and 13 refused
    vectors, generated from real trees and pinned byte for byte.
  - The vectors cover inclusion, an empty value, an update, a deleted key before and
    after, and both exclusion shapes. The refused ones include the neighbour-value forgery
    that the key check stops.
  - So `jmt`, the Rust verifier and the JS verifier agree.
- **PF-2 client check:** `consensus::state_proof_client::verify_answer` runs checks
  1-6:
  - QC under the trusted committee and chain;
  - expected epoch;
  - QC height equals the answer height;
  - freshness;
  - proof against `qc.state_root`;
  - key hash derived locally.

  Until S5, the caller supplies the committee and epoch for the height. The JS SDK checks
  the Merkle proof only; its BLS QC check is not built yet, and the SDK says so.
| S5 | Committee record + FinalityVote V2 binding + transition log + `TA_LOG_*` (TA; joint with G1 EP-2/EP-4) | **Yes** |
| S6 | Snapshot restore + bootstrap record + pinned versions + rejoin at every horizon (SN) | No |
| S7 | Pruning with the value rule; boot audits RC-2 and RC-3 | No |
| S8 | Activation in the shared fresh genesis with G1 S11 (AC) | Genesis |

## Open questions and founder decisions

1. **Retention:** `R_state`, block retention, and `T_restore_max` for pinned versions. These
   set how long a node can be offline before it needs a snapshot, and the disk cost.
2. **Checkpoints (TA-0/TA-4):** who signs and publishes them. For a permissioned launch this
   is the operator; later it can be the validator set.
3. **Governance module upgrades:** remove the path (FX-3; recommended, and in line with the
   feature cut), or rebuild it properly.
4. **Two account records:** `obj:{addr}` plus Move `CoinStore`. Both are S, which is safe.
   Merging them is cleaner but not required for G3.
5. **Joint G1 amendment:** G1 EP-2 reads `sys:committee:{E+1}` (TA-2). This needs the G1
   owner's agreement. G3 is also in the gate owner's goal document, so stage ownership must
   be agreed.

---

## Appendix A — key classification

Classification uses **exact templates, including zero-padding**. The L, N and Dead lists
name families; S0 turns each into exact templates. On top of the per-row writers below, the
**unverified snapshot install** (`core/node/src/main.rs:57-151`) writes every template at
once (FX-8, SN-5).

### S — consensus state (in the tree)

| Template | Written in block by | Out-of-band writers today | Readers that matter |
|---|---|---|---|
| `resource_{addr64}_{StructTag}` | Move changesets; fee, slash and epoch VM calls; Rust re-encodes of `ValidatorSet`/`SupplyStats` (`lib.rs:1404-1439`); CoinStore auto-register | faucet (`api_local.rs:551`, `636`); genesis | VM resolver; executor; mempool balance |
| `module_{addr64}_{name}` | `PublishModule` | governance upgrade (FX-3); genesis | VM resolver |
| `obj:{addr64}` (account: nonce, public key) | `execute_transaction` (`lib.rs:3430-3450`) | faucet (`api_local.rs:525`, `610`); genesis, including the node's own account (FX-7) | executor; vertex author key (`dag.rs:2140`); block signer (`sync/lib.rs:541`); slash evidence |
| `obj:{proposal_id}`, `gov:active_proposal_ids` | governance driver (never fires today) | dead `create_proposal`/`vote` | governance driver |
| `sys:validators` | join, leave, add_stake, slash | genesis | fee split; evidence verification |
| `sys:validator_set:v1` | join, leave, add_stake, slash | genesis | QC; admission; sync; committee source |
| `genesis:validator_set:v1` | — | genesis | epoch-0 committee |
| **`sys:committee:{E:020}`** (new, TA-2) | executor at `H_{E−1}`, before the seal, whatever the Move outcome | — | G1 EP-2 (amended); TA-3; PF |
| `sys:validator_set:epoch:{E}`, `consensus:epoch`, `consensus:epoch_start_height:{E}` | `rotate_validator_epoch` (outside today's root) | — | today's QC verify and admission. Retired at activation (FX-2). |
| `sys:last_epoch_boundary` | `maybe_advance_epoch` | — | exactly-once guard |
| `sys:chain_id` | — | genesis | vertex domain; QC signing; after FX-6, all validity |
| `sys:config:epoch_block_interval` | — | genesis | epoch schedule |
| `sys:config:require_exec_roots` | — | genesis | sync validity (removed by FX-15) |
| `sys:config:tip_agreement_n` | — | not seeded (FX-7) | sync policy |
| `sys:config:burn_percentage` | governance | not seeded (FX-7) | fee burn |
| `sys:config:federation_addr`, `sys:config:base_reward`, `sys:config:halving_interval` | governance | genesis (federation) | RPC only. The "transfers disabled" lock claimed at `genesis.rs:1016` is **not enforced** anywhere. |
| `sys:total_supply`, `total_burned` | supply trackers | genesis | trackers |
| `sys:fee_sweep_queue:{h}:{miner}` | fee path | — | fee sweep (FX-4) |
| `sys:slashed:{addr}:{round}` | `execute_one_slash` | — | evidence carry |
| `sys:pending_slash:{addr}` | deletes only | — | none live |
| `validator:jailed:{addr}` | `apply_slash_evidence` | consensus `dag.rs:2500` (FX-1) | none live in execution |
| `sys:stdlib_version`, `sys:pending_module_upgrade:{name}` | governance upgrade | none in production (FX-3) | governance upgrade |
| `pqc_pubkey_{addr}` | — | tests only | mempool. A real S key once account-key registration lands. |

### C — chain data
- `block_{h}`: the header hash is identical on all nodes; the stored signed copy differs
- `block_txs:{h}`, `tx_index:{hash}`
- `tx_receipt:{hash}`: stops feeding the root (FX-5)
- `latest_height`, `latest_block_hash`, `sys:last_executed_height`
- `genesis_stdlib_hash`, `genesis_stdlib_modules`, `genesis_stdlib_module_count`, `genesis_version`
- `sys:state_root`: deleted at activation (AC-2)

### L — consensus-local
- **DAG:**
  - `vertex:{hash}`, `latest_proposed_round`, `validator:last_seen:{addr}`
  - `sys:downtime_attestation:*`, `sys:equiv_seen:*`, `sys:equiv_carried:*`, `sys:equiv_gossiped:*`
  - `sys:equiv_local_jail:{addr}`: FX-1; this node's own equivocation detection
  - `dag:checkpoint:{r}`, `dag:checkpoint_sig:{r}`, `dag:checkpoint:latest`
- **Ordering:**
  - `consensus:last_adopted_height`, `consensus:committed_rounds`, `consensus:cseq:{r}`
  - `consensus:finalized_round`, `consensus:next_anchor_round`
  - `consensus:last_anchor_round`, `consensus:last_anchor_hash`
  - `consensus:finality_digest`: a hash chain over history. SN-1b rebuilds it from the QC, it
    is never restored from a peer.
  - `consensus:beacon_folded_qc_height`, `consensus:beacon_folded_anchor_round`
- **QC:**
  - `consensus:qc_pending:{h:020}`, `consensus:qc_signing:v1:*`
  - `consensus:qc_vote:*`, `consensus:qc_vote_agg:*`
  - `consensus:qc:{h}`, `consensus:qc_by_round:{r}`
  - `consensus:qc:latest`, `consensus:qc:latest_height`, `consensus:qc:latest_round`
  - `consensus:vattest:v1:{cg}:{bls_pk}:{E}:{author}:{r:020}`
- **G1 durable rows** (owned by G1; exact templates follow G1's implementation):
  - `consensus:dag_committee:*`: superseded by `sys:committee:*` if open question 5 is
    agreed
  - `consensus:epoch_start`, `consensus:epoch_active`, `consensus:gc_floor`
  - `consensus:anchor_decision`
  - `consensus:vslot`, `consensus:vproposed`, `consensus:vcert`, `consensus:vcollect`
  - `consensus:guard_origin`
- **DA:** every `da_*` key. They are keyed by an in-memory counter that resets on boot
  (`da/src/lib.rs:173`).

### N — node-local
- `peer:{id}`, `peer_ip:{id}`, `peer_addr:{id}`
- **`sys:da:signing_key_enc_v1`** and `sys:da:signing_key`: a **node secret**; never in the
  tree
- `sys:block_prune_cursor_v1`, `sys:tx_index_backfill_v1_complete`
- `genesis_initialized`
- `alarm:*`
- `sync:halt_reason`: read only; the comment at `sync/src/lib.rs:686` is stale
- `sys:restore_in_progress` (new, SN-2)

### K — chain constants
- `genesis_identity`: computed once from `genesis.json`, with `state_root(0)` (TA-1). It is
  installed as the vertex-hash domain, so it reaches validity and execution (CL-3).

### T — tree internals (new; hex-encoded values, CM-8)
- `jmt:node:{hex(NodeKey)}`
- `jmt:val:{keyhash64}:{version:020}`: value history, encoded as `v{hex}` for a value (so an
  empty value stays distinct) or `d` for a deletion
- `jmt:stale:{stale_since:020}:{hex(NodeKey)}`
- `jmt:pre:{keyhash64}`: key preimage
- `jmt:latest`, `jmt:floor`, `jmt:pinned:{version:020}`

### A — transition log (new, TA-3)
- `ta:{E:020}`: `{E, header(H_E), QC(H_E), C_{E+1}, proof}`, self-authenticating, never
  pruned

### Dead — delete before activation (FX-11)
- `meta_resource_*`, `vote_receipt:*`
- `delegation:*`, `unbonding:*`, `validator_pool:*`
- `token:*`, `token_balance:*`
- `sys:fhe:*`
- legacy `total_supply`
- `consensus:committed_sequence`

## Appendix B — measured key census

Source: the preserved validator r1 database of the previous chain (`pre-wipe-r1-20260923.tgz`
on the NAS), read offline with a read-only RocksDB handle. `node.key` was filtered out on the
NAS side before copying.

| | |
|---|---|
| Keys | 2,982,055 |
| Distinct templates | 62 (the census script's normaliser reported 104 raw patterns) |
| **S instances** | **79**: 22 modules, 23 Move resources, 6 account objects, 9 epoch committees, 9 epoch start heights and 10 singletons. Values total tens of KB; the per-family rounding bounds the total between about 35 and 300 KB. A HEAD genesis also writes `sys:config:require_exec_roots`, so a fresh chain starts with at least 80. |
| Largest families | `block_{h}` 154 MB; `consensus:qc:{h}` and `consensus:qc_by_round:{r}` 101 MB each; `da_shard_*` 73 MB (1.83 M keys); `consensus:qc_vote_agg:*` 73 MB |

Most of the database is history that is never pruned. That is a G4/GC matter, recorded here
because retention (open question 1) touches it.
