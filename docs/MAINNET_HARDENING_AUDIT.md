# AINCORE Mainnet Hardening — Audit Handoff

> Audience: a reviewing engineer / AI agent auditing the `audit/mainnet-hardening` branch before mainnet.
> Generated 2026-06-28, last updated 2026-07-01. Branch HEAD: **`e5ce4d4`**. Commits are **LOCAL (not pushed)**.
>
> **⚠️ SCOPE.** This is a *branch hardening + audit-handoff* record. It is **NOT** a certification that AINCORE is ready for mainnet. The mainnet-readiness verdict is **NOT READY** — see the [MAINNET VERDICT](#mainnet-verdict-not-ready) section immediately below for the required-before-launch checklist. Read every "fixed / done / proven" claim as "this specific hazard was closed on this branch," never as "the chain is launch-ready."

---

## MAINNET VERDICT: NOT READY

**This branch is mainnet-*hardening*, not mainnet-*ready*.** The security findings in §2 are closed and the multi-party finality path is proven *functional* on a healthy local cluster (§5) — but launching to mainnet requires everything below to pass first. None of these are cosmetic; each is a way the chain can fork or lose funds in production.

**Required before mainnet:**

1. **Fresh 32-byte genesis dry-run.** `#35` is a hard fork — there is no in-place upgrade from any 16-byte chain. Produce the real mainnet genesis (validators, stakes, BLS keys, stdlib-hash pin) and boot it clean end-to-end. — *Status: build smoke-tested only; a real mainnet-parameter genesis has NOT been produced.*
2. **3+ validator live cluster.** — *Status: **PARTIAL**. A 3-validator local cluster finalized to block #42 with all-3 aggregate QC (§5). Proves the mechanism on a healthy mesh; NOT yet a geographically-distributed, independently-operated cluster.*
3. **Multi-validator failure / chaos soak.** Kill a validator mid-round, partition the network, restart a node, feed a lagging joiner — confirm liveness resumes with no fork / double-finalize. — *Status: **NOT DONE**; only the happy path was exercised.*
4. **Determinism audit pass.** Caller-by-caller sign-off that every `SystemTime::now` / `env::var` / `rand` / `Instant` in executor · consensus · sync · governance is off the block-execution / state-root path. — *Status: **first pass DONE + clean** (2026-07-01, all 21 hits class-A, [§6](#6-determinism-checklist-first-pass-done--clean-formal-sign-off-still-required)). Still required: widen to `da`/`common`/`core-node`, add a CI grep-gate, delete the dead `SimpleConsensus`.*
5. **Upgrade path end-to-end test.** Exercise `#17` governance `UpgradeModule` on a live-like node: stage bytecode → pass proposal → apply → confirm `sys:stdlib_version` bump + module swap + no brick. — *Status: unit-verified only.*
6. **Backup/restore drill on a live-like node.** Run `#16` `backup_node.sh`/`restore_node.sh` against a node with real block history + validator identity, not a fixture. — *Status: roundtrip passes on fixtures only.*
7. **Decide DA & bridge posture — disable or fully enforce.** No half-on paths on mainnet. — *Status: **PARTIAL**. Cross-node DA serve+sample landed (#3 Stage-2) but its gating is **alert-only, not a commit gate**; bridge client-side `verify_qc` landed (#18 Tier-B); BTC mint is still a stub with no SPV proof. Each must ship as explicitly-disabled OR fully-enforced.*
8. **Mainnet-candidate soak 7–14 days.** Sustained multi-validator load under monitoring before opening to the public. — *Status: not started.*

**Bottom line:** direction is right and the hardening is substantial, but this document must not be cited as evidence of "mainnet ready." It is a *hardening audit + roadmap-proof pack*.

---

## 0. How to verify the whole branch

```bash
git checkout audit/mainnet-hardening
cargo build --workspace
cargo test --workspace            # expect: 45 test binaries, 0 failures
cargo clippy --workspace --all-targets -- -D warnings   # expect: exit 0
```

Last run (2026-06-28): **build green · test green (45 binaries, 0 failures) · clippy exit 0.**
The 32-byte build was also runtime-smoke-tested live (solo validator: mined 20 blocks, 20 QCs, 4 epoch rotations, 0 panics).

### ⚠️ Critical caveats for the auditor
1. **`#35` is a HARD FORK.** `crypto::derive_address` now emits 32-byte (64-hex) addresses and the Move stdlib bytecode was recompiled with the `address32` feature. `genesis.json` was regenerated. **Any existing 16-byte chain/testnet cannot upgrade in place — it must start from the new genesis.** The new genesis.json + `core/vm_move/stdlib/bytecode/*.mv` are the source of truth.
2. **Determinism is the #1 audit axis.** Every change that runs during block execution must produce byte-identical state on every node, or the chain forks. Grep audit targets: `SystemTime::now`, `std::env::var`, `rand`, `Instant` in `core/executor`, `consensus/consensus`, `governance`, `sync`. (Known acceptable env reads: `AINCORE_CHAIN_ID`, `AINCORE_EPOCH_BLOCK_INTERVAL` [see §Determinism notes], opt-in `AINCORE_EXPECTED_GENESIS_HASH` / `AINCORE_REQUIRE_EXEC_ROOTS` which are boot-time gates not per-block.)
3. **Consensus-metadata vs state-root.** Keys like `consensus:*`, `sys:validator_set:epoch:*`, `sys:equiv_seen:*`, `consensus:qc*` are consensus metadata written with direct `put`/`WriteBatch` — they are NOT part of the executor state root. Verify the auditor understands which writes enter the state root (Move resource changes via the executor `WriteBatch` under `BLOCK_EXECUTION_LOCK`) vs which are side-band.

---

## 1. Commit index (30 hardening commits, newest first)

| Commit | Audit # | One-line |
|--------|---------|----------|
| `e5ce4d4` | #13-test | pin epoch interval in storage for rotate test (parallel-run env isolation) |
| `5be7dfd` | #18-TierB | bridge verifies QCs client-side, drops trust in RPC `verified` flag |
| `6a5db6b` | #12-Step2 | fold multi-party QC aggregate BLS sig into leader beacon |
| `236bf6d` | #3-Stage2 | real cross-node DA serve + peer sample (gating alert-only) |
| `02143ef` | #13 | genesis-pin epoch-block interval (kills per-node env fork) |
| `46e10e6` | #17 | governance-gated on-chain Move module upgrade path |
| `3e9d51d` | #16 | backup/restore DR drill + runbook |
| `d2dc489` | #15-bringup | multi-validator genesis generator (`genesis-tool gen-multi`) |
| `bea71a3` | #35 | widen addresses 16→32 bytes via Move `address32` (**hard fork**) |
| `8920d19` | #32b | deterministic on-chain governance execution |
| `d69172f` | #33 | BTC bridge per-output dedup + custody scriptPubKey verification |
| `a451424` | #15 | multi-party QC vote gossip + aggregation (Phase 3) |
| `7a72af5` | #29 | seed-anchor peer ordering + N-peer tip agreement |
| `e03c2b8` | — | fix(cli): deref `Zeroizing<String>` for key printout |
| `7b1b353` | #18 | bridge requires verified QC before acting on AINCORE state |
| `1dc3da8` | #7 | opt-in require non-empty execution roots at cutover |
| `b755dfb` | #16/#5 | validator-set epoch snapshots for stable QC binding |
| `74b2cdc` | #2/#3 | DAS verifies sampled shards + real shard storage |
| `341c9a8` | #14/#15 | fix supply RPC double-subtract + add cap tripwire |
| `7fbac2d` | #30 | opt-in genesis-hash pin to refuse wrong-chain boot |
| `562ffdf` | #12 | bind leader beacon to cumulative finality digest |
| `4dfbc02` | #9/#10 | gossip equivocation evidence + retain past prune |
| `7a5e289` | #27 | mempool fee market + admission balance gate |
| `b4a9c28` | #8 | halt on state-changing reorg pending state-undo |
| `ebfe01d` | #6/#24 | bind finality to the locally-held block |
| `f755b46` | #1 | serialize unknown-write-set txs (parallel-exec consensus split) |
| `fc9e630` | #5/#22/#32/#19 | genesis BLS guard, VDF beacon restore, read-only tally, DA merkle domain-sep |
| `28cbc00` | #34/#28 | zeroize keystore secrets + per-IP connection cap |
| `705c5ba` | #26/#17 | vertex timestamp future-drift cap + stake-weighted downtime slash (downtime slash later made NON-LIVE in protocol v2: attestation only) |
| `bd11af8` | #4/#20/#36 | node.key 0600, fraud-proof fail-closed, saturating fee math |

---

## 2. Per-finding detail

Format: **Problem → Fix → Key files/symbols → Verify → Audit focus.**

### BLOCKER

#### #1 — Parallel-execution determinism (`f755b46`)
- **Problem:** the rayon parallel scheduler grouped txs by disjoint conflict tokens. A tx whose call wasn't in the recognized allow-list got an *empty* dependency set → ran in parallel with everything → last-write-wins on an unrecognized write-set is non-deterministic across nodes → state-root fork.
- **Fix:** `Executor::analyze_tx(&tx) -> (Vec<String> deps, bool recognized)` sets `recognized=true` only in known arms (coin::transfer, staking, delegation, governance, token_factory×2, dex). New `schedule_batches()`: an **unrecognized** tx flushes the current batch and runs as its **own serialized singleton batch**; recognized txs keep the disjoint-token batching.
- **Files:** `core/executor/src/lib.rs` (`analyze_tx`, `schedule_batches`, `execute_block_parallel`).
- **Verify:** executor test `sec1_unknown_calls_serialized_known_calls_parallel`.
- **Audit focus:** confirm EVERY state-mutating entry function is either in the recognized allow-list with correct conflict tokens, or falls to the serialized path. A mis-classified function with wrong tokens is the fork risk.

#### #2/#3 — Real data availability (`74b2cdc`)
- **Problem:** (#3) `DASampler::sample()` counted any successful fetch and ignored the bytes — a peer could "prove availability" with garbage. (#2) `ShardManager::update_validators` was never called → `get_my_shards()` returned `[]` → zero `da_shard_*` rows persisted ("32 shards/3× replication" computed and discarded).
- **Fix:** `sample()`/`verify_da()` now take the committed `merkle_root` + a fetcher returning `(bytes, proof)` and verify each sampled shard via `verify_shard` (retrieved-but-unverifiable = unavailable). `create_batch` seeds `shard_manager.update_validators(peers+self)` before storing. New `DASequencer::get_commitment(epoch)` + `verify_local_availability(epoch)` (network-free DAS over local shards).
- **Files:** `da/src/sampling.rs`, `da/src/lib.rs`.
- **Verify:** `da_sequencer` tests `sample_rejects_unverifiable_shards`, `stage0_shards_persisted_and_local_availability_verifies`.
- **Audit focus / STATUS UPDATE (`236bf6d`, #3 Stage-2 — LANDED):** cross-node DA now works — `DA_SHARD:` is served in the node TCP callback (`main.rs`), `fetch_shard_from_peer` + `verify_availability_from_peers` sample peers' shards against the committed merkle root, and `audit_epoch_availability` emits `🚨 [SECURITY][DA_UNAVAILABLE]` on shortfall. **REMAINING GAP (deliberate):** the availability check is **alert-only — it does NOT gate/halt commit**, and the periodic background audit spawn is not wired in. So DA is *observable* cross-node but not *enforced* on the critical path. Auditor: treat DA as monitored, not consensus-gating. (See MAINNET VERDICT §7 — must be disabled-or-fully-enforced before mainnet.)

### HIGH

#### #6/#24 — Finality bound to the locally-held block (`ebfe01d`)
- **Problem:** `apply_finality_artifact` advanced `consensus:finalized_round` from a peer's QC without checking the QC's block matches the block this node actually holds.
- **Fix:** before persisting finality, look up `block_{qc.block_height}`; if not held → no-op `Ok(())` (#24); if held but `block.header.hash != qc.block_hash` → `Err` (#6).
- **Files:** `sync/src/lib.rs` (`apply_finality_artifact`), tests in `sync/src/tests.rs`.
- **Audit focus:** confirm `qc.block_hash` == the committed block header hash invariant (dag.rs commit path). Confirm the no-op path can't be abused to stall.

#### #8 — Reorg over un-reverted state halts (`b4a9c28`)
- **Problem:** `rollback_to_height` only deletes block records + resets height/hash pointers; it does NOT revert Move/executor state (CoinStore, resources). Re-executing a new fork over un-reverted state silently diverges the node.
- **Fix:** in `process_blocks`, a non-finalized reorg that would orphan **state-changing** blocks now latches `sync:halt_reason` and stops for operator re-bootstrap. Empty (no-tx) orphans still roll back + re-execute.
- **Files:** `sync/src/lib.rs`.
- **Audit focus / KNOWN LIMITATION:** this is an **interim** — there is no per-height state-undo log. A legitimate unfinalized-tip reorg with txs HALTS the node (safe but blunt). Verify finalized-boundary reorgs are rejected earlier (they are) so this only triggers above the finalized boundary.

#### #9/#10 — Equivocation gossip + prune retention (`4dfbc02`)
- **Problem:** double-sign was detected + slashed only on the node that received both conflicting vertices; not gossiped; the proving vertices were deleted by normal prune.
- **Fix:** `add_vertex` routes detection through `apply_equivocation_slash` (idempotent via `sys:equiv_seen:{offender}:{round}`) + `broadcast_equivocation_proof` (`EQUIV_PROOF:` over gossip+TCP). `verify_equivocation_proof` independently re-verifies inbound proofs (same author/round, distinct body-bound hashes, both sigs valid vs offender's key, offender in validator set). Evidence stored in a plain KV (survives DAG prune); bounded GC (`EQUIV_EVIDENCE_RETENTION_ROUNDS`).
- **Files:** `consensus/consensus/src/dag.rs` (+ `resolve_author_pubkey` extracted), `core/node/src/main.rs` (`EQUIV_PROOF:` dispatch on both libp2p + TCP arms).
- **Audit focus:** the slash event JSON must be byte-identical across nodes (no timestamps). Confirm a forged proof cannot slash an honest validator (the dual-signature requirement). Confirm executor applies the slash once via `sys:slashed:{addr}:{round}` tombstone.

#### #12 — Unbiasable leader beacon (`562ffdf`)
- **Problem:** the leader-election beacon was seeded from the bare anchor-vertex hash, which the round's proposer fully controls (payload/parents/timestamp). With the hash-chain "VDF" (difficulty 50, no real delay) a malicious leader could grind its own vertex to re-elect itself.
- **Fix:** beacon seeded from `(anchor_round, cumulative finality_digest)` via a domain-separated challenge; the finality digest is over the entire committed sequence → binds the seed to the whole prefix. Reconstructed on restart from persisted `consensus:last_anchor_round` + `consensus:finality_digest`.
- **Files:** `consensus/consensus/src/ordering.rs` (`beacon_challenge`, `update_random_beacon`, `new_with_storage`).
- **Audit focus / STATUS UPDATE (`6a5db6b`, #12 Step-2 — LANDED):** the multi-party QC aggregate BLS signature is now folded into the beacon — `mix_qc_into_beacon(agg)` = `VDF("AINCORE_BEACON_QC_V1" ‖ step1_beacon ‖ aggregate_signature)`, applied idempotently/monotonically per height via `fold_qc_for_height` (persisted `consensus:beacon_folded_qc_height`). Step 1 (digest-binding) + Step 2 (QC-agg folding) are both done. **REMAINING GAP (deferred, roadmap):** a real class-group delay-VDF. The current construction provides determinism + multi-party unpredictability but NOT a proven time-delay; a colluding >2/3 could still in principle influence the aggregate. Acceptable interim, not a mainnet-final randomness beacon.

#### #5/#16 — Validator-set epoch snapshots (`b755dfb`) + genesis BLS guard (`fc9e630`)
- **Problem:** validators join/leave by mutating the live `sys:validator_set:v1`; binding QCs to the live set means any mid-epoch change shifts the `validator_set_hash` → in-flight QCs fail everywhere.
- **Fix:** `executor::rotate_validator_epoch` (called from `maybe_advance_epoch`, which fires on BOTH consensus + sync paths) snapshots the live set to `sys:validator_set:epoch:{E}` at each boundary + advances `consensus:epoch`. `qc_producer::load_validator_set_for_epoch(epoch)` resolves the frozen snapshot (fallback to live). Producer binds to current epoch's snapshot; verifiers resolve by `qc.epoch`. A join during E activates in E+1. `fc9e630` adds `resolve_genesis_bls_identity(single_node_fallback_allowed)` so a multi-validator genesis cannot self-derive BLS.
- **Files:** `core/executor/src/lib.rs`, `consensus/consensus/src/qc_producer.rs`, `sync/src/lib.rs`, `core/node/src/api.rs`, `core/node/src/api_local.rs`, `core/node/src/genesis.rs`.
- **Audit focus:** epoch boundary = `height % interval == 0`. Both paths must rotate identically — verify sync-path block apply also goes through `maybe_advance_epoch`. Retention window for old snapshots (8 epochs).

#### #13/#14/#15 — Tokenomics / supply (`341c9a8`)
- **Problem:** `aincore_getSupply` computed `circulating = total_minted - total_burned` where `total_minted` was already net of burns → double-subtracted burns. No cap tripwire.
- **Fix (VERIFIED-SAFE, mechanics left intact):** confirmed first that gas is burned (`deduct_gas`) and `deposit_fee_reward` re-mints ≤ the burned amount (balanced transfer, not inflation); block-reward inflation is cap-clamped in `staking.move`. Then: new `supply_view(net, burned)` → `circulating=net`, `total_minted=net+burned`. Cap tripwire in `append_supply_tracker_updates`: if net supply > `MAX_SUPPLY` (150M) emit a loud SECURITY alarm (read-only — must not abort an in-flight block).
- **Files:** `core/node/src/api_local.rs` (`supply_view`), `core/executor/src/lib.rs` (tripwire, un-dead `MAX_SUPPLY`).
- **Audit focus / STATUS UPDATE (`02143ef`, #13 — LANDED):** the per-node env fork hazard is fixed — `Executor::epoch_block_interval(&self)` now reads `sys:config:epoch_block_interval` from storage **first** (deterministic, written at genesis, folded into `genesis_identity_hash`), and env `AINCORE_EPOCH_BLOCK_INTERVAL` is only a fallback when the key is absent. So all nodes on a given genesis agree on the interval by construction. **REMAINING GAP (deferred):** the Move halving clock still keys on epoch count rather than block height — a Move-stdlib-recompile change, deferred to avoid a second fork in this batch. (Test note: `e5ce4d4` pins the interval in storage inside the rotate test because #13's own env-setting tests otherwise polluted the process-global env under `cargo test` parallelism.)

### MED

#### #27 — Mempool fee market + admission balance (`7a5e289`)
- **Fix:** `get_pending_transactions` selects by gas_price desc while preserving each sender's nonce order (geth-style best-head merge). `add_transaction` gains a fail-open admission balance gate (rejects only when a committed AIN balance is readable AND < `gas_limit*gas_price`; skips paymaster-sponsored txs; admits on any uncertainty so an intra-block-funded tx is never false-rejected). New `executor::committed_ain_balance(db,addr) -> Option<u128>`.
- **Files:** `core/mempool/src/lib.rs`, `core/executor/src/lib.rs`.
- **Audit focus:** the fee ordering only needs to be self-consistent per block (the leader builds it, all execute that order). Confirm the admission gate's fail-open can't be turned into a false-reject (it reads committed state; intra-block funding is the documented limitation).

#### #30 — Genesis-hash pin (`7fbac2d`)
- **Fix:** `genesis_identity_hash` folds `genesis_stdlib_hash + version + sys:chain_id + sys:validator_set:v1`. When `AINCORE_EXPECTED_GENESIS_HASH` is set, `verify_genesis_integrity` refuses to boot on mismatch; also runs at the END of `initialize_genesis` so a fresh wrong-chain bootstrap is caught. Off by default.
- **Files:** `core/node/src/genesis.rs`.

#### #7 (cutover) — Require non-empty execution roots (`1dc3da8`)
- **Fix:** opt-in (`sys:config:require_exec_roots`, env fallback `AINCORE_REQUIRE_EXEC_ROOTS`) gate in `verify_execution_roots` — when on, a block with empty state_root/receipts_root is rejected. Off by default (preserves the running testnet); enable at fresh-genesis cutover.
- **Files:** `sync/src/lib.rs`.

#### #18 — Bridge requires verified QC (`7b1b353`)
- **Problem:** EVM bridge defined "finalized" as `latest-100` and emitted lock events with NO finality proof — a forged/forked RPC could mint on the far chain.
- **Fix:** `verify_block_finalized(height, hash)` queries `aincore_getQuorumCertificate` and accepts only when `available && verified && qc.block_height==height && qc.block_hash==hash`. `fetch_bridge_events` gates each block; first unprovable block halts the scan (cursor not advanced). Pure `qc_response_confirms` is unit-tested.
- **Files:** `depin/bridge-rust/src/aincore_client.rs`.
- **Audit focus / STATUS UPDATE (`5be7dfd`, #18 Tier-B — LANDED):** the bridge no longer trusts the RPC's `verified` flag. `qc_response_confirms` now deserializes the returned QC and runs `consensus::qc::verify_qc` **client-side** against a `TrustedValidatorSet` loaded from `AINCORE_VALIDATOR_SET_PATH` (fail-closed if the path is unset/unreadable — the bridge refuses to act rather than trust a bare flag). The server `verified` field is advisory only. **REMAINING GAP:** the operator must ship + rotate the trusted validator set out-of-band; there is no on-chain validator-set light-client sync yet. (See MAINNET VERDICT §7 — bridge posture must be a deliberate disable-or-enforce decision.)

#### #32b — Deterministic governance execution (`8920d19`)
- **Problem:** governance proposals passed/queued but execution was manual; `tally`/`execute_proposal` used `SystemTime::now()` (non-deterministic).
- **Fix:** `tally_at(id, now)` / `execute_proposal_at(id, now)` pure variants (public methods delegate with wall clock for back-compat). `process_due_proposals(now, height)` walks a bounded index `gov:active_proposal_ids`. Wired via `Executor::drive_governance` inside `maybe_advance_epoch` (single deterministic point, both paths) using an **on-chain clock** (`0x1::epoch::Epoch.epoch_start_time`), no SystemTime. Only the two enumerated actions execute.
- **Files:** `governance/governance/src/lib.rs`, `core/executor/src/lib.rs` (+ executor→governance dep).
- **Audit focus:** confirm the time source (`on_chain_epoch_clock_secs`) is deterministic across nodes; confirm idempotency (only acts on Active/Queued, flips to Executed). Verify the action match is not widened beyond UpdateFederationKey/UpdateEconomicParams.

#### #33 — BTC bridge per-output dedup + custody (`d69172f`)
- **Fix:** dedup key `tx_hash` → `{txid}:{vout}` (per output). New `custody.rs` derives the canonical custody scriptPubKey/address from a configured redeem/witness script (P2WSH/P2SH); boot asserts derived == configured `BTC_MULTISIG_ADDRESS` (exit on mismatch); per-deposit verifies the output's scriptPubKey pays custody (not an indexer string compare). Confirmation threshold preserved via pure `is_finalized`.
- **Files:** `depin/btc-bridge/src/{btc_client.rs,storage.rs,main.rs,custody.rs}`.
- **Audit focus / KNOWN LIMITATION:** the actual mint is a disabled stub (intentionally not un-stubbed). SPV/Merkle-proof of the deposit tx is NOT implemented (deposits still come from an indexer JSON) — dual-source / real SPV is a documented follow-up.

#### #29 — Seed-anchor + N-peer tip agreement (`7a72af5`)
- **Fix:** `sync_from_peers` orders peers seed-first (`order_peers_seed_first`, seeds = active validator addresses). N-peer tip agreement via `sys:config:tip_agreement_n` (default 1 = current behavior): when N>1, require ≥N distinct seed peers advertising a consistent verifiable `(qc.block_height, qc.block_hash)` before advancing; disagreement logs `TIP_DISAGREEMENT` and refuses. QC-gated `apply_finality_artifact` untouched (it's the crypto backstop).
- **Files:** `sync/src/lib.rs`.

#### #15 — Multi-party QC aggregation, Phase 3 (`a451424`)
- **Problem:** `qc_producer` only emitted a complete QC if THIS node's stake alone met >2/3 — no way for N validators to jointly finalize.
- **Fix:** sub-quorum nodes broadcast a signed partial vote (`QC_VOTE:{json}` = full `FinalityVote` + signer addr + BLS sig). `collect_vote_and_try_aggregate` verifies each single BLS sig against the signer's key in the **frozen epoch** set, binds to this node's committed `(round, block_hash, validator_set_hash)`, dedups per `(round, signer)` (bounded `MAX_VOTES_PER_ROUND`), and on >2/3 collected stake builds + `verify_qc`s + stores the aggregate QC under the same `consensus:qc:*` keys. `QcOutcome::{Complete,Partial,Skipped}`.
- **Files:** `consensus/consensus/src/qc_producer.rs`, `consensus/consensus/src/dag.rs` (`broadcast_qc_vote`, `handle_remote_qc_vote`, `QC_VOTE:` in handle_message), `core/node/src/main.rs` (dispatch).
- **Audit focus:** this is **side-effect-only** — never gates commit/finality, so a bug can't fork/halt (verify this invariant). Confirm an unverifiable QC is never stored; confirm votes are deduped + bounded; confirm the BLS single-sig verify is subgroup-checked.

### HARD FORK

#### #35 — 32-byte addresses (`bea71a3`)
- **Problem:** `derive_address` truncated to 16 bytes → ~2⁶⁴ birthday-collision resistance, and it was zero-padded into the Move 16-byte `AccountAddress`.
- **Fix:** `crypto::derive_address` → `hex(SHA256(pubkey))` full 32 bytes (`ADDRESS_BYTES=32`, `ADDRESS_HEX_LEN=64`). `address32` feature enabled on `move-core-types` in 8 Cargo.tomls → `AccountAddress::LENGTH==32`. **Move stdlib recompiled** (`core/vm_move/stdlib/bytecode/*.mv`). `genesis.json` regenerated (64-hex validator address). Fixed: cli `parse_move_address`, executor miner-addr truncation + `AccountAddress::ONE/ZERO` literals, dag `resolve_author_pubkey` (no length heuristic), api_local resource-key widths. **Critical latent bugs fixed:** `da/src/lib.rs` + `utils/derive_keys` were deriving the id from `hex(raw_pubkey)[0..32]` (NOT SHA256) — would have broken every peer handshake + DA identity post-widening; both unified on `crypto::derive_address`.
- **Files:** `common/crypto/src/lib.rs`, 8× Cargo.toml, `core/vm_move/stdlib/bytecode/*.mv`, `core/vm_move/src/tests.rs`, `core/node/src/genesis.rs`, `core/node/src/api_local.rs`, `core/executor/src/lib.rs`, `consensus/consensus/src/dag.rs`, `core/cli/src/main.rs`, `da/src/lib.rs`, `utils/derive_keys/src/main.rs`, `genesis.json`.
- **Audit focus:** verify the recompiled `.mv` deserialize + embed the 32-byte `0x1`; verify golden BCS test vectors were regenerated correctly (`core/vm_move/src/tests.rs`); verify NO remaining code assumes 32-hex addresses (grep `[0..32]`, `len() == 32` on address-typed values). This is irreversible — scrutinize hardest.

### ROADMAP (now implemented)

#### #15-bringup — Multi-validator genesis generator (`d2dc489`)
- `genesis-tool gen-multi --validator <seed_hex>:<stake> ...` emits a genesis.json declaring N validators each with `address = derive_address(pk)`, `public_key`, `stake`, `bls_public_key = BLSEngine::consensus().pubkey_raw(derive_validator_bls_seed(seed))`, `bls_pop`. Field names match `node::genesis` loader exactly. Doc: `docs/MULTI_VALIDATOR_BRINGUP.md`.
- **Files:** `core/genesis-tool/src/multi_genesis.rs`, `core/genesis-tool/src/main.rs`, `docs/MULTI_VALIDATOR_BRINGUP.md`.
- **Audit focus:** the BLS derivation MUST match `qc_producer::derive_validator_bls_seed` exactly (anti-drift test `derived_fields_match_node_runtime_derivation` + `two_validators_agree_on_validator_set_hash`).

#### #16 — Backup/restore DR (`3e9d51d`)
- `scripts/backup_node.sh` (consistent tar.gz of `validator_*.db` + node.key + genesis, with sha256), `scripts/restore_node.sh` (never clobbers a non-empty DB; sha256-verified; `--new-identity` for observers), `docs/DR_RUNBOOK.md`, `scripts/tests/dr_roundtrip_test.sh` (7/7). New files only — no Rust/consensus edits.

#### #17 — On-chain upgrade path (`46e10e6`)
- `GovernanceAction::UpgradeModule { module_name, new_bytecode_hash }`. `apply_module_upgrade` (fail-closed, in order): allow-list `UPGRADEABLE_SYSTEM_MODULES`; read staged bytecode `sys:pending_module_upgrade:{name}`; verify `SHA256(bytecode)==approved`; `CompiledModule::deserialize` must succeed AND self-id == `@0x1::{name}` (anti-brick/anti-masquerade); overwrite `module_{0x1}_{name}`; bump `sys:stdlib_version`. Rides the #32b deterministic governance driver.
- **Files:** `governance/governance/src/lib.rs` (+ `sha2`, `move-binary-format` deps).
- **Audit focus:** this is the most security-sensitive new feature — verify the allow-list cannot be bypassed, the hash commitment is enforced before install, un-loadable bytecode is rejected, and it only runs via governance (not arbitrary callers). Also verify `genesis_stdlib_hash` semantics after an upgrade (the pin reflects genesis, not post-upgrade state).

---

## 3. Mechanical/lower-severity batch (earlier commits)

- `bd11af8` (#4/#20/#36): `node.key` written `0600` (unix perms); `da/fraud_proofs.rs` MissingData/InvalidErasure arms return `false` (fail-closed); fee math `saturating_*`.
- `705c5ba` (#26/#17): `add_vertex` rejects `vertex.timestamp > now + 30s` (future-drift); `promote_downtime_attestations_to_slash` uses **stake-weighted** quorum (`reporter_stake*3 > total_stake*2`). **Protocol v2 note:** downtime slashing is NOT LIVE (attestation only; no deterministic DAG producer); only equivocation is slashed, via DAG-carried compact proofs.
- `28cbc00` (#34/#28): keystore `create`/`decrypt` return `zeroize::Zeroizing<String>`; `ConnectionGuard` per-IP cap (`AINCORE_MAX_CONN_PER_IP`).
- `fc9e630` (#5/#22/#32/#19): multi-validator genesis rejects self-derived BLS; VDF beacon restored on boot; `aincore_tally` made read-only; DA merkle leaf(0x00)/internal(0x01) domain separation (CVE-2012-2459 family).
- `e03c2b8`: cli `Zeroizing<String>` deref for the key printout (workspace build fix).

---

## 4. Outstanding / deferred

### 4a. Landed since the first draft (were "deferred" at `46e10e6`, now done)

| Item | Commit | Note |
|------|--------|------|
| Cross-node DA serve + peer sampling (#3 Stage-2) | `236bf6d` | Serve + fetch + sample + alert done. Gating is **alert-only, NOT a commit gate** (see §7). |
| Multi-party QC aggregate folded into beacon (#12 Step-2) | `6a5db6b` | Class-group delay-VDF still deferred (below). |
| Genesis-pin epoch-block interval (#13 env fork) | `02143ef` | Interval now storage-first + genesis-folded. Move halving clock still epoch-keyed (below). |
| Bridge client-side `verify_qc` (#18 Tier-B) | `5be7dfd` | Now verifies QCs against operator-shipped trusted set; server flag advisory. |
| Multi-validator finalize-together, **functional** proof (#15) | live 2026-06-29 | 3-validator cluster → block #42, all-3 aggregate (§5). Chaos soak still pending (below). |

### 4b. Still genuinely deferred (NOT done — real work, not cosmetic)

| Item | Status |
|------|--------|
| Real delay-VDF (class-group) for leader randomness (#12 full) | Deferred — current is digest-bound hash-chain + QC-agg fold; no proven time-delay |
| Per-height state-undo log for reorgs (#8 full) | Deferred — interim **halts** the node on a state-changing unfinalized reorg (safe but blunt) |
| Move halving clock epoch→block (#13 remainder) | Deferred — needs Move stdlib recompile (avoided a second fork in this batch) |
| BTC SPV / Merkle-proof of deposit + un-stub mint (#33 full) | Deferred — per-output dedup + custody verify done; SPV proof + actual mint still stubbed |
| DA availability **enforcement/gating** (#3 Stage-3) | Deferred — Stage-2 is observe+alert only; must become disable-or-enforce before mainnet (§7) |
| Multi-validator **failure/chaos soak** on a live cluster (#15) | Deferred — only the happy path ran; see MAINNET VERDICT §3 |

---

## 5. Multi-validator finality — what was run + how to reproduce

**What actually ran (2026-06-29, local 3-validator cluster).** Using `genesis-tool gen-multi` (3 equal-stake validators, BLS embedded), full-mesh + near-simultaneous start, all three nodes finalized in lock-step to **block #42**: `signed_stake=3000000/3000000` (all-3 aggregate), `"3 votes AGGREGATED multi-party"` logged ×42, 2 epoch rotations, 0 panics.

This is a **functional proof that the #15 multi-party QC path produces decentralized finality on a healthy mesh.** It is **NOT** a robustness proof: no fault injection, no partition, no independent operators — all 3 nodes were local, honest, and up the whole time. The chaos/failure soak and the distributed-operator cluster are items §3 and §2 of the [MAINNET VERDICT](#mainnet-verdict-not-ready).

> ⚠️ **Bootstrap topology matters.** gossipsub does not backfill: a late-joining or staggered validator misses early-round vertices and the cluster deadlocks at `Parents < quorum`. Bring-up needs a FULL MESH (each node bootnodes every other) + near-simultaneous start. n=3 needs all 3 vertices (2/3 is not strictly >2/3); n≥4 is more robust.

**Reproduce it:**

```bash
# 1. generate N validator seeds (32-byte hex)
for i in 1 2 3; do openssl rand -hex 32 > /tmp/v$i.seed; done

# 2. one shared genesis with all 3 validators (BLS embedded)
cargo run -p genesis-tool -- gen-multi \
  --validator $(cat /tmp/v1.seed):1000000 \
  --validator $(cat /tmp/v2.seed):1000000 \
  --validator $(cat /tmp/v3.seed):1000000 \
  --chain-id AINCORE-LOCALTEST-3V --out /tmp/genesis.3v.json

# 3. run 3 nodes, each with its seed as node.key, peered, isolated ports
#    (see docs/MULTI_VALIDATOR_BRINGUP.md for the exact per-node invocation)
# 4. expected: peers connect → gossip vertices + QC_VOTE → aggregate >2/3 QC → blocks FINAL across all 3
```

Single-validator + 32-byte build was also smoke-verified independently (20 blocks, 20 QCs, 4 epoch rotations, 0 panics). Again: the 3-validator run proves the aggregation *mechanism* live on a healthy mesh — it does not substitute for the chaos soak (§3) and distributed-operator cluster (§2) required before mainnet.

---

## 6. Determinism checklist (FIRST PASS DONE — clean; formal sign-off still required)

Determinism is the #1 fork risk (caveat 2). A caller-by-caller **first pass was run 2026-07-01** over the four consensus-relevant crates:

```bash
grep -rnE 'SystemTime::now|Instant::now|std::env::var|env::var\b|rand::|thread_rng|from_entropy|OsRng' \
  core/executor/src consensus/consensus/src sync/src governance/governance/src
```
21 hits (excluding `sync/src/tests.rs`). Classification — **(A)** off the block-execution / state-root path (OK) vs **(B)** on the path that writes state or derives a consensus value (must fix). **Result: all 21 are class A. No class-B fork risk found on the replicated execution path.**

| Category | Hits | Why class A |
|----------|------|-------------|
| **Author-set replicated timestamp** | `dag.rs:429` (vertex ts) | Set once by the proposer, gossiped + replicated as bytes; verifiers do NOT re-derive it. |
| **Reject-only liveness guard** | `dag.rs:621`, `sync/lib.rs:288` | Reads wall-clock only to *reject* a future-dated vertex/block (±30s drift); never writes state. |
| **Boot-time env gate** | `dag.rs:1086/1091` (chain_id, genesis_path), `executor:18` (chain_id), `executor:912` (epoch-interval **fallback** — storage-first per `02143ef`), `sync:62` (require_exec_roots, opt-in) | Same across a chain by construction; not per-block state input. |
| **Ephemeral transport RNG** | `sync/lib.rs:575`, `sync/lib.rs:780` | `OsRng` mints an ephemeral session key for the `secure_connect` handshake — randomness here is *correct*; never touches state. |
| **Governance — replicated path uses on-chain clock** | wrappers `governance:206/325/358` | `process_due_proposals` → `tally_at`/`execute_proposal_at` take the **on-chain** clock (`8920d19`, #32b). The `SystemTime` wrappers (`tally`/`execute_proposal`/`create_proposal`/`vote`) have **no non-test caller** (verified: only `#[cfg(test)]` block, lines 875-987). |
| **Dead / legacy code** | `consensus/lib.rs:49/115/292` | The retired `SimpleConsensus` + its `Block`/`Proposal` (fresh-keypair `new`, proposal-ts verify). `SimpleConsensus` is constructed **nowhere** outside its own file; the node uses `dag.rs` DagConsensus + `qc`. |
| **Test helper** | `governance:815`, `sync/tests.rs:362` | `#[cfg(test)]` temp-db naming. |

**Hygiene recommendations (not blockers):**
1. **Delete the retired `SimpleConsensus`/`Block`/`Proposal`/`Vote` in `consensus/consensus/src/lib.rs`** — dead code with a fresh-keypair path is a footgun for the next auditor.
2. **Keep governance proposal *creation* off the replicated path.** Creation currently sets `end_time` from wall-clock and is RPC/manual only (no consensus caller) — that is fine *because* only the deterministic *execution* driver runs during block execution. If proposal creation is ever wired into a Move TX / executor path, its timestamp MUST switch to the on-chain clock.

**Why this is a FIRST pass, not a certification (still MAINNET VERDICT §4):** this is a point-in-time grep-and-classify, not a proof. It does not (a) cover crates outside the four (e.g. `da`, `common/*`, `core/node` request handlers that could feed executor inputs), (b) rule out non-determinism introduced via dependency behavior or HashMap iteration order in serialized output, or (c) re-run automatically on new commits. Treat determinism as **first-pass clean, formal sign-off + CI grep-gate pending.**

---

*All commits local on `audit/mainnet-hardening`. Nothing pushed. The full design notes per task are in the session scratchpad `designs/` and the agent summaries in the workflow task outputs.*
