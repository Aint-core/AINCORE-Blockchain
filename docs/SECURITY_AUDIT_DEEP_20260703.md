# AINCORE Deep Adversarial Audit — 2026-07-03 (HEAD 6950bf0)

> Red-team lead report. Branch `audit/mainnet-hardening`, HEAD `6950bf061e2486deb3877505b44cf6282ed9451e`.
> Every finding below survived **double verification** — two independent skeptics each re-derived the kill-chain against the source and both confirmed it exploitable. Findings that only one verifier could confirm, or that could not be reproduced against the actual code, were dropped and are **not** listed here.

---

## Executive summary

**Severity counts (double-confirmed only):**

| Severity | Count |
|---|---|
| CRITICAL | 16 |
| HIGH | 19 |
| **Total** | **35** |

**Overall posture: NOT MAINNET-READY.** This is not a matter of residual hardening — the audit found *systemic* breaks in the three properties a sovereign L1 must never lose: **supply conservation** (AIN minted from nothing), **finality safety** (honest nodes provably fork with zero Byzantine stake), and **state integrity under sync** (one unauthenticated peer permanently corrupts or halts a victim). Several of these are not new code — they are pre-existing holes the prior remediation walked past, and in three cases the prior fix itself *converted* a benign condition into an exploitable one.

**Did the prior 14 fixes hold, or did any regress?** Mixed, and the regressions are the most alarming result:

- **H-3 (sync remote-DoS halt) — INCOMPLETE + REGRESSED.** `d488bc6` removed the persistent `sync:halt_reason` write from the *execution-root* path (now a bare `break` at `sync/src/lib.rs:987`) but left the **structurally identical latch in the sibling reorg branch at `sync/src/lib.rs:912` fully intact and reachable with strictly less attacker effort** (no execution, no root computation, fires *before* `validate_block`). The exact remote-DoS H-3 set out to close is still live (findings #1, #12, #23, #28). Worse, removing the halt without adding pre-execution authentication turned a clean self-halt into **silent permanent state poisoning** (#4, #10, #15).
- **H-1 / H-2 (leader-election grinding) — REGRESSED into a finality-safety fork.** `6593423` re-routed election onto `step1_beacon` to restore cross-node determinism, but (a) left the beacon **grindable** by the anchor proposer through an instant VDF(50) (#3, #25), and (b) newly made a benign persistence quirk — the reversed+truncated `committed_sequence` at `ordering.rs:517` — into a **consensus-safety fork that any honest validator restart triggers** (#9, #14), plus a gossip-timing fork with no Byzantine stake (#11).
- **M-2 (crash-durability) — REGRESSED.** The commit advertises "durable against power loss," but only `write_batch` got `sync=true`; plain `put()`/`delete()` (confirmed at `common/storage/src/lib.rs:108,125`) remain non-fsync'd. This *split* crash-consistency: the state root is now durable one fsync *ahead of* the block record and settlement writes, so an ordinary crash forks the chain (#20, #33).
- **M-1 (QC chain_id binding) — held, but insufficient.** `verify_qc` is cryptographically sound relative to the set it is handed; the trust root `sys:validator_set:v1` is **append-only** and never prunes slashed/departed validators, so a ghost quorum forges finality without honest supermajority (#7). M-1 does not touch this.
- **SEC-#18 Tier-B (client-side bridge QC verify) — BYPASSED.** The QC authenticates the block *hash*; the bridge never binds `transactions` to that hash (#5, #8, #13, #16). A malicious RPC pairs a genuine QC with a forged tx list and mints unbacked tokens. The control guards the wrong field.

Fixes that genuinely held at their own scope: M-1 chain_id binding, the M-5 publish-gas *byte floor* (though it does not bound super-linear verifier cost — #34), H-4/M-3/M-4/L-1 (not re-broken by any confirmed finding), and the H-5/H-6/M-6 CLI key hardening (out of adversarial reach this round).

**Single most dangerous new attack:** **Finding #2 — paymaster gas double-credit (`core/executor/src/lib.rs:1922`).** `analyze_tx` derives parallel-execution conflict tokens from `tx.sender` but **never from `tx.paymaster`**, so N same-paymaster/different-sender sponsored txs land in one parallel batch, all read the pre-batch payer balance, and last-write-wins collapses N gas deductions into **one** — while `total_fees` counts all N and mints the full amount to the proposer. This is unbounded AIN minted from nothing every block, directly breaching the 150M cap, requires only a trivial paymaster balance, and the mempool balance gate is *explicitly skipped* for sponsored txs. It is a live supply-conservation break, not a griefing edge case.

---

## Remediation status (updated 2026-07-03, after manual code re-verification)

The 35 double-verified raw findings collapsed to **~7 distinct root causes** (each rediscovered across rounds). A human re-read of the actual source separated genuinely-exploitable from verifier over-claims, then fixed the confirmed ones:

| Root cause | Verdict | Status | Commit |
|---|---|---|---|
| **C-1 paymaster gas double-mint** (`executor:1908` analyze_tx) | ✅ REAL (confirmed in code) | **FIXED** — paymaster is now a parallel-exec conflict token | `25a776a` |
| **C-2 `sys:validator_set:v1` append-only → ghost quorum** (`executor:1841`) | ✅ REAL | **FIXED (slash path)** — slashed validator pruned from v1; leave/unbond-path prune tracked | `25a776a` |
| **#3 bridge tx list not bound to QC hash** (`aincore_client:406`) | ✅ REAL | **FIXED** — bridge recomputes tx_hash + header hash and binds to the QC-attested hash | `27e81c9` |
| **#4 H-3 second halt latch** (`sync:912` reorg branch) | ✅ REAL (my audit-1 fix was incomplete) | **FIXED** — reorg rejected, no persistent halt latched | `dfff584` |
| **#6 M-2 split durability** (`storage` put/delete non-fsync) | ✅ REAL (my audit-1 fix was incomplete) | **FIXED** — put/delete now fsync (sync=true) | `dfff584` |
| **#5 H-1 restart digest divergence** (`ordering:517`) | ❌ FALSE POSITIVE | not a bug — restart LOADS the persisted `consensus:finality_digest`; the live 3-machine cluster runs lockstep for 1500+ rounds (deterministic committed_sequence) | — |
| **#7 Block::new SystemTime → fork** (`blockchain:56`) | ❌ LIKELY FALSE POSITIVE | on the live commit path, but a trivial all-validator fork is contradicted by the running lockstep cluster; block hash not consensus-relevant in the claimed way | — |
| **H-2 leader-beacon grindable** | known DEFERRED (real-VDF) | pre-existing documented deferral, not a new finding | — |

**Net:** 5 distinct real issues fixed (2 new criticals + 1 bridge + 2 incomplete audit-1 fixes completed), 2 verifier over-claims dismissed after code re-read, 1 known deferral. The "16 CRITICAL" raw count was inflated by cross-round rediscovery of the same ~5 defects. Full workspace build/test/clippy re-run after the fixes.

**Residual (tracked):** C-2 voluntary-leave/unbond v1 prune (slower attack than the equivocation path already fixed) → the clean form is rebuilding `sys:validator_set:v1` from the Move `ValidatorSet` resource at each epoch boundary; H-2 real delay-VDF; M-5 super-linear verifier cost bound; the deep sync-block pre-execution authentication (H-3 residual, a block-format change).

---

## Confirmed attacks

Grouped by severity, most-dangerous first within each group. Shared root causes are de-duplicated: several rounds independently rediscovered the same four defect families (sync-block-not-authenticated, election-beacon-not-deterministic-or-grindable, paymaster-not-a-conflict-token, bridge-tx-not-bound-to-QC). Each is stated once as a canonical finding with the corroborating rediscoveries cross-referenced.

### CRITICAL

---

#### C-1 — Paymaster CoinStore is not a parallel-exec conflict token → gas double-credit, AIN minted from nothing
**`core/executor/src/lib.rs:1922`** (also rediscovered as C-24 root, `analyze_tx` @ :1908) — *goal: create AIN from nothing / double-credit fees to the proposer every block.*

**Kill-chain:** Attacker holds one paymaster key P and N cheap throwaway senders S1..SN. Build N txs in one block, each `sender=Si` (distinct), `paymaster=P`, valid paymaster signature over `PAYMASTER_AUTH:{chain_id}:{Si}:{payload}:{gas_limit}:{seq}` (verified `:2343`). Mempool admits all N: dedup is keyed `{sender}:{seq}` (`core/mempool/src/lib.rs:492`, distinct senders never collide) and the balance gate is **explicitly skipped for paymaster txs** (`if parsed_tx.paymaster.is_none()`, `mempool:216`), so P's balance is never checked. In `execute_block_parallel`, `analyze_tx` derives conflict tokens from `sender_token = tx.sender` (`:1922-1925`) + input_objects + recipients and **never references `tx.paymaster`**; the N txs get disjoint token sets and `schedule_batches` (`:2096`) places them in the **same** rayon batch. Each worker builds its Move session against the committed pre-batch DB, so all read P's balance `B` and emit `resource_{P}_CoinStore = B-G`. The last-write-wins merge (`:1361-1377`) collapses N deductions to one → P ends at `B-G`. But `total_fees = total_fees.saturating_add(gas_charged)` (`:1375`) counts every tx → `N*G`, and `deposit_fee_reward` mints `N*G*(1-burn%)` to the proposer (`:1471` → `coin.move`). Net: `(N-1)*G` AIN created from nothing, harvested by the proposer, every block, unbounded, breaching the 150M cap (the staking cap-clamp does not cover the executor fee-mint path).

**Why exploitable:** `analyze_tx` contains zero references to `tx.paymaster` (confirmed by grep — only `:2326/2327` in `execute_transaction` mention it), yet `deduct_gas` mutates `resource_{paymaster}_CoinStore`. The scheduler contract (comment `:2116-2147`) requires any two txs mutating the same key to share a token; the paymaster CoinStore is a shared mutated key with no covering token. Mempool provides no backstop (gate skipped, dedup per-sender).

**Fix:** In `analyze_tx`, when `tx.paymaster == Some(pm)`, push `parse_move_address(pm).to_string()` **and** the concrete `resource_{pm}_CoinStore<...AincoreCoin>` key into `deps` so same-paymaster txs serialize into separate batches. Defense-in-depth: (a) make realized gas the single source of truth by summing actual committed CoinStore deltas rather than trusting each tx's returned `gas_charged`; (b) reinstate a paymaster balance check at mempool admission; (c) assert `sum(realized burns) == amount fed to burn+deposit_fee_reward` before committing the block. The same class applies to any account whose CoinStore is written by a path not reflected in `analyze_tx` (e.g. a normal `coin::transfer` FROM the paymaster racing a sponsored tx also collides on `resource_{P}_CoinStore`). *(C-24/HIGH is the same defect rediscovered in round 2; fix once.)*

---

#### C-2 — QC trust root `sys:validator_set:v1` is append-only → ghost quorum forges finality
**`core/executor/src/lib.rs:698`** — *goal: produce a QC that passes `verify_qc` (>2/3 stake, correct set-hash, valid BLS, matching chain_id) without controlling >2/3 of real bonded honest stake.*

**Kill-chain:** `verify_qc` resolves its validator set exclusively from `sys:validator_set:v1` via `load_validator_set_v1`/`load_validator_set_for_epoch` (`qc_producer.rs:70-98`). That key is written in only two places — genesis (`genesis.rs:922`) and the JOIN path `append_validator_set_v1_update` (`executor:698`, called only at `:2541` on `join_validator_set`). It is **never** decremented/pruned on leave/unbond/slash. (A) *Leave-and-reclaim ghost quorum*: attacker calls `leave_validator_set` (`staking.move:127`); after the 21-day unbond, `withdraw_unbonded` (`staking.move:209`) re-mints and returns 100% of coins. Real economic stake now zero, but the v1 entry (stake weight, BLS key, PoP) is untouched. The departed set signs a `FinalityVote` for any `(height, hash, state_root, anchor)`; `verify_qc` recomputes `signed_stake/total_stake` from the stale v1 (`qc.rs:258-259`), sees stale stake exceed 2/3 of stale total, set-hash matches, chain_id matches, BLS aggregate verifies → `Ok(())`. (B) *Equivocation survivor*: a validator slashed for equivocation is removed from the Move set and zeroed in `sys:validators` (`:1845-1878`) but v1 gets **no write** — the proven-Byzantine key keeps full QC weight. `rotate_validator_epoch` (`:992`) freezes the stale v1 into `sys:validator_set:epoch:{E}`.

**Why exploitable:** grep for `sys:validator_set:v1` writes shows join+genesis only; the slash mirror at `:1845` updates `sys:validators` (`*weight=0; retain(|_,w| *w>0)`) but never `validator_set_v1_key()`; `staking.move` mutates only Move state, never reflected back into v1. `verify_qc` is sound only relative to the slice it is handed and has no independent notion of who is currently bonded. The M-1 chain_id / set-hash / PoP guards are all satisfied by a stale-but-internally-consistent v1. The `<1/3 Byzantine ⇒ honest intersection` safety argument (`qc.rs:184-196`) is void because v1 stake is decoupled from real honest stake.

**Fix:** Make v1 authoritative-by-reconstruction. On every commit boundary (and inside slash/leave/unbond), rebuild v1 by decoding the Move `ValidatorSet` resource and emitting one entry per *currently-active* `ValidatorConfig`. At minimum add a v1 removal in the slash loop (`:1845` region) mirroring the `sys:validators` update, and prune v1 on `leave_validator_set`/`withdraw_unbonded`. Regression test: join two, slash one for equivocation (and separately leave+withdraw one), assert `load_validator_set_for_epoch` no longer contains the address and a QC from the removed key fails `verify_qc` with `BelowThreshold`/`ValidatorSetMismatch`.

---

#### C-3 — Leader-election beacon is grindable by the anchor proposer (instant VDF-50)
**`consensus/consensus/src/ordering.rs:579`** — *goal: bias/monopolize leader election with far less than 2/3 stake.*

**Kill-chain:** Any active validator that becomes anchor leader of round R authored that anchor via `try_create_vertex` (`dag.rs:330-448`) with freely-chosen parents/payload/timestamp → controls the anchor vertex hash. `find_causal_history` appends it to `committed_sequence`; `digest = finality_digest(committed_sequence)` (`:505`) is a plain SHA256 the attacker steers. `update_random_beacon` sets `step1_beacon = VDF(anchor_round || digest)` (`:215-227`). `get_leader_with_fallback` (`:552-622`) derives the election seed from `step1_beacon[0..8]`. Because `VDFEngine::new(50)` runs only 50 SHA3 hashes (microseconds — `common/crypto/src/vdf/mod.rs:150-206`), the attacker enumerates thousands of candidate anchor contents offline in milliseconds and picks the one whose beacon names itself leader — and since **one beacon seeds many future rounds**, of a long consecutive run. Reproduced against the exact math: a 25%-stake attacker won R+1 in 4 trials; a ~20k-trial (~ms) search yielded a beacon making the attacker leader of 20/20 subsequent anchor rounds vs a fair ~5/20.

**Why exploitable:** The H-1 fix only changed *which* beacon election reads (`&self.step1_beacon` at `:579`) to restore determinism — it added **no** grinding resistance. `finality_digest` is a SHA256 the proposer biases via unconstrained vertex content (`dag.rs:426-440`). The only barrier is `VDFEngine::new(50)` = 50 sequential hashes = no wall-clock delay. The code comment at `:574-578` explicitly concedes the Step-1 base is "still proposer-biasable via chosen content (audit H-2)"; the unpredictable QC-folded value is deliberately *excluded* from election, so nothing unpredictable enters the value that selects leaders. *(C-25/HIGH is the same live exploit rediscovered in round 2.)*

**Fix:** Do not elect from a value the current proposer can grind offline. Either (a) elect round R's leader from the QC-folded beacon of a height buried below a fixed finality lag L (so every honest node folds the same unpredictable QC before electing — use `mix_qc_into_beacon` at height H-L, not `step1_beacon`), or (b) deploy a genuine delay-VDF (Wesolowski/Pietrzak, difficulty ≥ 50_000 as the VDF module itself recommends).

---

#### C-4 — Restart forks leader election: `finality_digest` recomputed from reversed+truncated `committed_sequence`
**`consensus/consensus/src/ordering.rs:505/517`** — *goal: split finalized state (finality-safety fork) with NO Byzantine stake, by causing/awaiting any honest validator restart.*

**Kill-chain:** The H-1 fix asserts `finality_digest` is "a pure function of already-committed state, identical on every honest node at commit time." But `finality_digest` is order-sensitive SHA256 over the entire in-memory `committed_sequence` (`:346-352, :505`). On persist it is written **reversed and truncated to the last 10000**: `committed_sequence.iter().rev().take(10000)` (`:517-518`). On restart, `new_with_storage` loads that JSON verbatim with **no re-reversal** (`:110-114`). The restart path reconstructs `step1_beacon` from the persisted `consensus:finality_digest` string (`:133-137`) so the node *boots* matching peers — but the first subsequent commit recomputes `digest = finality_digest(&self.committed_sequence)` over the reversed/truncated vector, producing a digest no honest peer computes. That flows into `update_random_beacon` → `step1_beacon` → `get_leader_with_fallback`, so the restarted node elects a **different** anchor leader, commits a different causal history, and forks. Order-sensitivity proven numerically (live `b20dd8…` vs restart `6bd514…`). Reversal alone forks even below the 10000 threshold; an attacker needs only to trigger a restart (crash-loop, or routine upgrade of one honest validator).

**Why exploitable:** `git -S` confirms the reversed/truncated persist predates the fix (`80b95d6`) while the election-beacon binding was made the *sole* input by H-1 (`6593423`) — the fix newly upgraded a benign persistence quirk into a consensus-safety fork trigger. No block-replay reconstruction of `committed_sequence` exists; the restart beacon reconstruction fixes only the *first* beacon and never the post-restart recomputed digest; `try_commit` persists the divergent digest (`:530`), permanently poisoning all future beacons on that node. *(C-14 is the identical defect rediscovered in round 3; fix once.)*

**Fix:** Maintain a rolling, restart-stable incremental hash chain `digest_n = SHA256(domain || digest_{n-1} || new_vertex_hashes_in_order)`, persisted every commit and reloaded directly (next digest chains off the persisted value, never rehashed from the stored sequence). Cross-restart determinism test: commit N>10000, snapshot next-commit digest, restart from DB, commit one more, assert digest/elected-leader equals a never-restarted engine's.

---

#### C-5 — Gossip-timing-dependent `committed_sequence` membership forks election under normal async
**`consensus/consensus/src/ordering.rs:579`** — *goal: two honest nodes elect different anchor leaders for the same round, no Byzantine >2/3.*

**Kill-chain:** The commit gate needs only (a) the leader's anchor vertex present in round R and (b) >2/3 round-R+1 stake listing it as parent (`:445-476`) — **not** the anchor's full causal history. `find_causal_history` (`:624-668`) walks only vertices currently in the local DAG (`if let Some(vertex) = dag.get(&hash)`, `:635`; missing parents silently skipped) and stops at any parent already in `committed_sequence` (`:638`). Attacker validator M produces its legitimate round-(R-1) vertex X and delivers X to node A *before* A commits anchor R but delays X to B until *after* B commits. Both still commit anchor R (X is irrelevant to the R+1 vote quorum). A's batch contains X; B's does not (B appends X later). From that commit on, A and B hold permanently different `committed_sequence` orders → different `finality_digest` → different `step1_beacon` → different elected leader for the next anchor round → two different `CommitInfo.anchor_hash`, two chains. Reachable with a single low-stake (or merely well-connected) participant, no equivocation.

**Why exploitable:** The H-1 comment's "identical on every honest node at commit time" is false: the base is order- and membership-sensitive over the cumulative committed list, and there is no gate requiring causal completeness before committing. Asynchronous gossip alone induces this; an attacker controlling forwarding timing of even one of its own vertices makes it deterministic.

**Fix:** Seed the beacon from a value identical across all honest nodes that commit the same anchor regardless of local DAG completeness — e.g. VDF over `(anchor_round, anchor_vertex_hash)` only, or the QC's canonical finality fields, not the cumulative causal ordering. Alternatively require full causal history locally present before committing and compute `finality_digest` over a canonicalized (round, hash)-sorted set. Two-node integration test: commit identical anchors from DAGs with different arrival order, assert byte-identical digest and identical next-round leader.

---

#### C-6 — Unauthenticated sync block permanently halts a node via latched `sync:halt_reason` (reorg path)
**`sync/src/lib.rs:912`** — *goal: permanently halt a target node's sync/finality with one cheap unauthenticated message.*

**Kill-chain:** Attacker completes the normal secure-TCP handshake (proves key↔id only, not stake) so it lands in the victim's peer table. On periodic pull-sync (`main.rs:992`, default 3s), the victim dials each peer in `ordered_peers` (`:552`; `order_peers_seed_first` includes non-seeds; default `tip_agreement_n=1` skips the N-of-seed gate at `:534`). Attacker answers `GET_HEIGHT` with `HEIGHT:<my_height+1>` (`:603-607`), so the victim enters the block-request loop and calls `process_blocks(blocks, my_height)` (`:676`). Attacker's `SYNC_RESP` (`SyncResponse.blocks`, deserialized straight from JSON at `:641`) contains one fabricated Block with `header.height == victim tip` (so `height <= last_processed`, `:862` true), an arbitrary `header.hash` ≠ the victim's real block (`:866` fails → reorg branch), and `header.round` > `consensus:finalized_round` (`:869-870` passes; finalized_round is 0/low on fresh/observer nodes). Because the victim's own chain has any real tx-bearing block above `rollback_target` (normal on a live chain), `state_changing_orphan` is true (`:892-903`) and the victim executes `storage.put("sync:halt_reason", …)` at `:912`. Every subsequent `sync_from_peers` returns immediately at `:502-508`; the key is in RocksDB, survives restart, clearable only by manual operator deletion. The node stops advancing forever.

**Why exploitable:** The persistent halt at `:912` is written from a reorg branch that runs *before* any authentication: `validate_block` is only called at `:956` and execution-root verification at `:967` — both strictly after the halt is persisted. The only gating conditions are three attacker-controlled unsigned header fields (`height`, `hash`, `round`) plus the victim's own pre-existing state-changing blocks. Blocks carry no proposer signature. **`d488bc6` removed the persistent halt from the sibling exec-root path (`:987` now merely `break`s, per its own comment about remote DoS) but left this earlier, MORE reachable halt-write untouched** — the exact remote-DoS the audit claimed to close, via a path that fires pre-validation, pre-execution. Confirmed intact at HEAD 6950bf0. *(C-12, H-23, H-28 are the same defect rediscovered across rounds; fix once.)*

**Fix:** Do not latch a durable, node-wide `sync:halt_reason` from unauthenticated peer input. Move `validate_block` + a verifiable QC/proposer-signature check to the very top of the loop iteration so no attacker-controlled block reaches the halt sink; on a forged block, `break`/`continue` to the next peer exactly like the exec-root path now does. Reserve a persistent halt strictly for divergence proven against a QC-certified competing finality, scoped per-peer rather than node-wide.

---

#### C-7 — Forged sync block poisons committed state (writes + chained `sys:state_root`) BEFORE verification
**`sync/src/lib.rs:965` / `core/executor/src/lib.rs:1393-1395`** — *goal: one unauthenticated peer permanently corrupts an honest node's committed Move state so it forks/stalls forever.*

**Kill-chain:** Attacker forces a pull (`GET_HEIGHT` → victim+1) and returns `SyncResponse{blocks:[forged]}`. Forged block at `height=victim_tip+1`: real executable txs (any 0x1 Move entry fn writing a resource, or a self-transfer the attacker legitimately signs) whose `tx_hash` matches; `proposer_id` = any address in the victim's active set (public string, no signature); `prev_hash` = victim's real tip; valid round/timestamp; `state_root` set to a wrong (or empty) value. `validate_block` (`:956`) passes — it checks height/prev_hash/proposer-membership/tx_hash/timestamp/count/verify_block_hash but **never** `state_root`, and the header hash is a keyless SHA256 over attacker fields (`blockchain/src/lib.rs:93-106`). `execute_block_parallel` (`sync:965`) runs the txs and at `executor:1364-1395` writes their KV updates **and** `new_root = hash(prev_root || batch_hash)` into a WriteBatch, committing **unconditionally** with `sync=true` (fsync'd/durable). `verify_execution_roots` (`sync:967`) runs *after* the commit; with empty `state_root` the mismatch check is skipped (`:120-133`) so the block is even accepted+saved, or with a wrong root it returns Err → H-3 path just logs and `break`s (no rollback, no halt). `sys:state_root` is a running accumulator folding `prev_root`, so every subsequent honest block computes `hash(poisoned_root || honest_batch)` ≠ canonical → permanent silent fork; if `require_exec_roots` is on at mainnet cutover, every later honest block fails verification and sync stalls forever.

**Why exploitable:** `executor:1395` commits (KV + `sys:state_root`) with no dependency on root verification; `verify_execution_roots` is only called by the caller afterward. Blocks are unauthenticated (no signature; keyless header hash). The empty-state_root branch skips the only rejecting check. **The H-3 change (`d488bc6`) replaced the halt with a bare `break` (its own residual comment at `:979-982` concedes the block still executes), so nothing reverts the committed poison** — there is no per-height state-undo (SEC-#8 deferred). Confirmed at HEAD 6950bf0. *(C-10, H-15 are the same commit-before-verify defect rediscovered; fix once.)*

**Fix:** Authenticate blocks BEFORE execution (verifiable QC covering `(height, hash)`, or proposer vertex signature) gating `execute_block_parallel`. Interim without a format change: execute against a scratch/overlay (or snapshot `sys:state_root` + the tx write-set) and only `write_batch` AFTER `verify_execution_roots` succeeds; on mismatch discard the batch entirely. Stop treating empty header roots as a skip once `require_exec_roots` is the mainnet default.

---

#### C-8 — Non-deterministic `SystemTime::now()` folded into committed block header hash → permanent fork
**`consensus/blockchain/src/lib.rs:56`** — *goal: force honest validators to permanently disagree on the canonical block-hash chain, no Byzantine majority, no attacker action required.*

**Kill-chain:** Every committing validator independently builds its block at `dag.rs:866` via `Block::new_with_roots(...)` — there is **no** gate limiting construction to the anchor leader. `Block::new_with_roots` (`blockchain:56`) sets `timestamp = SystemTime::now()...as_secs()` from the local wall clock. `calculate_header_hash` (`:104`) folds `header.timestamp.to_string()` into the SHA, so `header.hash = f(…, local_wallclock_second)`. Two honest nodes committing the same anchor one second apart produce different `header.hash`. `dag.rs:875` sets `latest_block_hash = new_block.header.hash` and `:869` passes it as the next block's `prev_hash`, so divergence chains forward. It propagates into the QC (`block_hash`, `dag.rs:968`) and DA batch (`:933`). When A syncs from B, `validate_block` (`sync:264`) enforces `prev_hash` equality; the timestamp-embedded hashes differ, peers hard-reject each other → permanent partition.

**Why exploitable:** `calculate_header_hash` unconditionally hashes `header.timestamp`, produced by `SystemTime::now()` with no deterministic override on the commit path — never range-checked, never taken from the monotonic epoch clock, never normalized. The `state_root` cross-check in sync (`:120`) covers only per-tx VM effects, not the header hash. The prior audit hardened the DAG *vertex* timestamp and made checkpoints byte-canonical, but left the *block header* timestamp fully non-deterministic — a regression-adjacent blind spot.

**Fix:** Derive the block timestamp from already-agreed consensus data — the on-chain monotonic epoch clock (`executor::on_chain_epoch_clock_secs`) or the anchor vertex's validated timestamp — or exclude timestamp from `calculate_header_hash` and store it as unhashed metadata. Pass an explicit deterministic timestamp into `Block::new_with_roots` on the commit path. Cross-node determinism test: two engines committing identical anchor state produce byte-identical `header.hash`.

---

#### C-9 — Bridge mints on attacker-chosen transactions: QC binds the block HASH but not the tx list (Tier-B bypass)
**`depin/bridge-rust/src/aincore_client.rs:406`** — *goal: mint unlimited AIN-pegged tokens on EVM without any real `bridge_lock` finalized on AINCORE, defeating the client-side `verify_qc` gate.*

**Kill-chain:** Threat model is exactly Tier-B's: a malicious/compromised (or MitM'd, plain HTTP no TLS pin) RPC the bridge polls. `fetch_bridge_events` → `get_blocks_range` → the RPC returns a `Block` deserialized into `{header:{hash}, transactions:Vec<String>}` (`:29-42`) — `BlockHeader` deserializes **only `hash`** (no `tx_hash`). Attacker sets `header.hash` = a REAL finalized block's hash (one with a genuine >2/3 QC) and sets `transactions = [forged bridge_lock:AMOUNT:0xATTACKER]` never in that block. `verify_block_finalized(height, &block.header.hash)` (`:406`) queries the real QC, `qc_response_confirms` checks `qc.block_height==height && qc.block_hash==expected_hash` (the echoed real hash) and BLS-verifies against the trusted set → `Ok(())`. Back in `fetch_bridge_events` (`:415-445`) the bridge iterates the **fabricated** `transactions`, parses the `bridge_lock`, and emits the event; `tx.signature` is `#[allow(dead_code)]` and never verified. `main.rs:146-179` mints to the attacker EVM address. Dedup keys on `(sender,amount,eth,height,tx_index)` — attacker-controlled — so vary tuples to double-mint arbitrarily.

**Why exploitable:** The QC attests only `block_height, block_hash, state_root, receipts_root, validator_set_hash` — **not** the transaction list or `tx_hash`. `block.header.hash` and `block.transactions` arrive in the *same* attacker response, and the bridge **never recomputes** `calculate_tx_hash(transactions)` or `calculate_header_hash(header)` to prove the returned txs belong to that hash (grep confirms no such recomputation in `depin/bridge-rust/src`; `BlockHeader` has no `tx_hash` field to even attempt it). The on-chain binding exists (`blockchain:84-106`) but is thrown away at the bridge. Tier-B moved QC verification client-side to stop a lying RPC faking finality but left the tx→block binding to that same RPC — it keeps the QC honest and forges the payload instead. `tx.signature` is additionally never checked. *(C-13, C-16, H-8 are the same defect rediscovered across all three rounds; fix once.)*

**Fix:** Extend the bridge `BlockHeader` to deserialize `tx_hash` (and the other hashed fields). After fetching each block, recompute `tx_hash = blockchain::calculate_tx_hash(&transactions)` and `header_hash = calculate_header_hash(&header)` and require `recomputed_header_hash == block.header.hash == qc.block_hash` AND `recomputed_tx_hash == header.tx_hash` BEFORE using `block.transactions`; reject (fail-closed) otherwise. Additionally verify each `bridge_lock` tx's Ed25519 signature and sender derivation. Consider putting a Merkle tx-root in the QC so it directly attests the tx set.

---

### HIGH

---

#### H-1 — Equivocation slash evadable by withholding the second conflicting vertex until its round is pruned
**`consensus/consensus/src/dag.rs:705`** — *goal: double-sign at round R yet never be slashed.*

**Kill-chain:** Attacker validator crafts two validly-signed conflicting vertices A, B for round R (same author, different hash). Broadcasts only A; the chain commits round R normally. Withholds B. `add_vertex` has no lower-round bound (`:589-676` checks only upper bounds, timestamp drift, signature, hash-binding, membership). Once finalized round > R, `prune_dag(finalized_round-10)` (every 10 blocks) runs `round_idx.retain(|r,_| *r >= min_round)` (`:1750`), deleting `round_index[R]` and `vertex:{A.hash}`; checkpoint replay on restart also drops rounds ≤ checkpoint (`:198`). Attacker now broadcasts B: `contains_key(B.hash)` false (new hash, passes `:687`); B persisted; the equivocation loop at `:705` does `round_idx.get(&R)` → None (pruned) → same-author scan never runs → B inserted at `:735`. No slash, no proof. Every honest node that pruned past R behaves identically → zero slashes network-wide; attacker keeps 100% stake.

**Why exploitable:** The detector at `:705-733` is a pure lookup into in-memory `round_index`, which is pruned every 10 blocks (`:1750`) and not fully repopulated on restart (`:198`). No persistent per-`(author,round)` "a vertex already exists" record survives pruning; `add_vertex` enforces only upper round bounds. The gossip `EQUIV_PROOF` path (`:1350`) triggers only as a consequence of local detection. Release timing of B is fully attacker-controlled — deterministic evasion. *(H-30 is the same defect rediscovered in round 3; fix once.)*

**Fix:** Maintain a prune-durable `sys:vertex_seen:{author}:{round} = firsthash` (not a `vertex:{hash}` row, retained far beyond the prune horizon like `sys:equiv_seen`). In `add_vertex`, before insert, look up `(author, round)`; if present and ≠ `vertex.hash`, apply slash + broadcast proof regardless of `round_index`. Add a lower-round admission bound rejecting vertices below `finalized_round - safety_buffer`.

---

#### H-2 — Reward/fee-burn/slashing balance mutations committed outside `sys:state_root` → silent balance divergence
**`core/executor/src/lib.rs:1505`** — *goal: permanent undetectable divergence of validator/CoinStore balances between producer and re-executing nodes.*

**Kill-chain:** `execute_block_parallel` folds only per-tx VM updates into `sys:state_root` (`:1382-1393`). After the fold it mutates committed balances via direct `self.db` writes bypassing the hasher: `deposit_fee_reward` (`:1205`), `burn_supply_trackers`, `process_fee_sweep_queue` (`:1256`), `promote_downtime_attestations_to_slash` (`:1657/1661`), `execute_pending_slashes` (`:1779/1815/1869`). `execute_pending_slashes` drains `sys:pending_slash:*`, populated **asynchronously per-node** by equivocation detection and P2P-gossiped downtime attestations. A syncing node re-executing the same block applies whatever pending slashes *its* storage holds at that height — a different set than the producer's — so 100%/5% burns land at different heights on different nodes. `verify_execution_roots` (`sync:120`) compares only `header.state_root` vs the tx-only summary root and passes, so the balance divergence is never detected; nodes now disagree on staking weight, feeding back into quorum and leader election.

**Why exploitable:** `summary.state_root = current_state_root()` reads `sys:state_root` (`:744-749`), advanced only by the tx-batch fold. Every reward/burn/slash write goes through `self.db.put`/`write_batch` without updating `sys:state_root`; sync's only economic gate is the root comparison. No Merkle/commitment binds balances or the slash set into the header. The pending-slash and attestation stores are gossip-populated and time-skewed by design. *(H-35 is the same class rediscovered in round 3 for the downtime path specifically; fix once.)*

**Fix:** Fold ALL balance-affecting committed writes (fee distribution, burns, epoch rewards, slashes) into `sys:state_root`, OR bind a full account-state commitment into the block header. Make slash/attestation application deterministic per height — only apply slashes whose evidence is itself committed into the block/QC at a fixed finality lag, rather than draining a locally-gossiped queue during arbitrary block execution.

---

#### H-3 — All Move stdlib natives registered with `GasParameters::zeros()` → per-tx CPU-exhaustion DoS
**`core/vm_move/src/lib.rs:180`** — *goal: escape gas metering, impose unbounded CPU on every validator for a negligible fee, halting block production.*

**Kill-chain:** Attacker holds a trivial balance. Submits an EntryFunction whose Move code tightly loops `std::hash::sha3_256(buf)` over a multi-KB vector. Passes mempool and executor re-checks (`:2287/2295`). Each iteration is charged only `Branch=1`, `charge_call=10`, `before_execution=2`, and `charge_native_function=_amount` which move-vm computes from `GasParameters::zeros()` ⇒ **0**. So a full SHA3 over a KB buffer costs ~15-20 gas. Setting `gas_limit ≈ 2e8` (fee ≈ 2e-10 AIN) funds ~1e7 SHA3 calls ≈ ~10 GB of hashing synchronously inside one tx. `execute_block_parallel` holds the process-wide `BLOCK_EXECUTION_LOCK` (`:1288`) for the whole block, with no per-block gas ceiling and no wall-clock timeout. Every validator (consensus and sync path) stalls seconds-to-minutes; repeat each block → sustained chain-halt-grade DoS at ~0 cost.

**Why exploitable:** `:178-181` builds the native table with `all_natives(system_address(), GasParameters::zeros())` — every native's declared cost is zero. `charge_native_function` (`gas.rs:75-82`) charges exactly `_amount` (0). The meter bounds surrounding bytecode instructions, not native CPU, which the attacker inflates cheaply via a large `gas_limit`. Fee deducted is flat `gas_limit * gas_price` with `gas_price` floored at 1 and no `MAX_GAS_PER_BLOCK`/timeout.

**Fix:** Replace `GasParameters::zeros()` with real per-byte/per-op native parameters (move_stdlib ships production values). Add a per-block cumulative gas ceiling and a hard wall-clock execution budget in `execute_block_parallel`.

---

#### H-4 — MoveVM runs with `VMConfig::default()` → structural verifier limits all `None`, super-linear publish DoS bypasses M-5 byte floor
**`core/vm_move/src/lib.rs:182`** — *goal: force super-linear bytecode-verification CPU on every validator for a fee scaling only linearly with submitted bytes.*

**Kill-chain:** `AINCOREVM::new` calls `MoveVM::new(natives)` → `VMConfig::default()` → `VerifierConfig::default()`, which sets `max_loop_depth/max_basic_blocks/max_type_nodes/max_function_definitions/max_back_edges_*/max_dependency_depth` all **None**; only meter units (8M) are set. On `PublishModule`, the pipeline runs BoundsChecker, DuplicationChecker, **SignatureChecker**, RecursiveStructDefChecker, **InstantiationLoopChecker** with **no meter** — only CodeUnitVerifier's abstract-interpreter passes consult the meter. SignatureChecker recurses over every `SignatureToken`; InstantiationLoopChecker builds a (function × type-param) graph and runs `tarjan_scc` — both super-linear in structural node/edge count, which a compact module inflates far beyond its byte length. The M-5 fix requires only `gas_limit >= 10*bytes + 5000*modules` (a linear floor), so a few-KB module whose verification is orders of magnitude costlier passes for a near-minimal fee. Every honest validator re-runs this unmetered verification on commit.

**Why exploitable:** `MoveVM::new(natives)` takes the default config; the M-5 comment (`executor:2570`) concedes "module verification runs with the move-vm gas meter ignored." The only added defense is a linear byte floor, which cannot bound a super-linear structural pass that takes no meter.

**Fix:** Construct with `MoveVM::new_with_config` setting explicit production limits (`max_basic_blocks`, `max_type_nodes`, `max_function_definitions`, `max_struct_definitions`, `max_fields_in_struct`, `max_back_edges_*`, `max_dependency_depth`, `max_generic_instantiation_length`, lower meter units). Charge publish gas from actual metered verifier units or a structural-complexity estimate, not raw bytes.

---

#### H-5 — Non-finalized reorg re-runs `advance_epoch`/`distribute_rewards` → double-minted epoch rewards
**`sync/src/lib.rs:915`** — *goal: create AIN from nothing by forcing epoch reward distribution to run twice for the same heights.*

**Kill-chain:** A malicious peer serves a competing fork conflicting with the victim's non-finalized tip; `process_blocks` enters the conflict path (`:862-881`). The finalized-boundary guard (`:869`) passes (tip is non-finalized). The "state-changing orphan" guard (`:892-914`) only inspects `block.transactions.is_empty()`. Heartbeat mining executes even EMPTY blocks to trigger rewards (`dag.rs:845`), and every 20th height is an epoch boundary where `maybe_advance_epoch → advance_epoch → distribute_rewards` already minted an epoch's rewards. An empty boundary block therefore passes the "safe to roll back" check while actually having minted. `rollback_to_height` (`:454-489`) deletes only `block_{h}` records and resets height/hash — it does **not** revert `resource_0x1_0x1::staking::ValidatorSet` (total_supply, current_epoch, stakes) or `epoch::Epoch`. Re-executing the fork over the un-reverted state crosses the same boundary and `distribute_rewards` runs a second time → epoch reward minted twice, halving clock double-advanced.

**Why exploitable:** `distribute_rewards` (`staking.move:268-320`) and `advance_epoch` (`epoch.move:26-39`) are not idempotent — unconditional `current_epoch += 1` and mint, no replay guard. `rollback_to_height` provably touches only block records (SEC-#8 comment at `:882-890` concedes executor state is not reverted). The only guard is `transactions.is_empty()`, but the epoch mint is a system side-effect, not a transaction, so an empty boundary block is misclassified as carrying no state.

**Fix:** Make `advance_epoch` idempotent — gate the mint on a monotonic on-chain marker (`consensus:last_reward_epoch` or a per-boundary-height flag). Alternatively treat any height whose execution advanced the epoch as a state-changing orphan (trigger the re-bootstrap path, not a silent rollback+re-exec), or implement a real per-height undo log.

---

#### H-6 — M-2 split-fsync: `sys:state_root` + `committed_rounds` become durable one fsync before `latest_height`; crash forks
**`core/executor/src/lib.rs:1395`** — *goal: permanent state-root/block-content divergence from a single crash in the M-2 commit path, no attacker input.*

**Kill-chain:** Per-block commit is THREE independently-fsync'd transactions with no reconciliation: (1) `try_commit` plain-puts `consensus:committed_rounds/sequence/last_anchor_round` (`ordering.rs:514-528`) — un-fsync'd WAL under M-2; (2) `execute_block_parallel` → `write_batch` (`executor:1395`, `sync=true`, fsync A) commits `sys:state_root=root_N`, whose fsync **also flushes the step-1 puts** (shared WAL); (3) `save_block_json` → `write_batch` (`storage:361`, fsync B) writes `block_N`/`latest_height=N`/`latest_block_hash`. Crash between fsync A and B: on reboot the ordering engine loads `committed_rounds ∋ round_R` and the executor loads `sys:state_root=root_N` (both durable), but `dag.rs:268` loads `latest_height=N-1`. `try_commit` de-dups round_R (`ordering.rs:384/487`) so block N is never re-committed; the next commit does `latest_block_height += 1 = N` and builds a NEW block N from the NEXT round's txs, folding them onto the already-durable `root_N`. Different txs, different `state_root` than the canonical block N → the node's height-N QC votes never match >2/3 → permanent fork / stuck finality.

**Why exploitable:** M-2 claims "atomically durable" but the block commit is not one atomic unit: `sys:state_root` is fsync'd in a separate earlier transaction than `latest_height`. The earlier fsync flushes the ordering high-water marks, so ordering+state advance to N while block/height stays N-1. No startup guard reconciles the three domains (`dag::new`, executor, `ordering::new_with_storage` each load independently). M-2 explicitly made `sys:state_root` individually fsync-durable — turning a transient window into a durable, non-recoverable inconsistency.

**Fix:** Commit the entire block in ONE `WriteBatch`/one fsync: fold `sys:state_root`, all reward/burn/supply/slash Move-KV mutations, the ordering high-water marks, AND `block_N`/`latest_height`/`latest_block_hash` into a single `sync=true` batch. If impractical, add a startup invariant that refuses to start (or rolls back `sys:state_root`+`committed_rounds`) whenever `latest_height` lags the height implied by them, forcing deterministic re-execution.

---

#### H-7 — M-2 regression: post-commit settlement writes are non-durable `put()`s, splitting crash-consistency from the fsync'd root
**`core/executor/src/lib.rs:1430`** — *goal: permanent state-root divergence on any validator that crashes in the normal post-commit window, no attacker stake.*

**Kill-chain:** After the fsync-durable state-root batch (`:1393-1395`), the settlement phase for the same block writes `total_burned`/`sys:total_supply`/validator_set (`burn_supply_trackers`, `:1069/1079/1088`), miner/validator CoinStore balances (`deposit_fee_reward`, `:1205`), plus `execute_pending_slashes`/`maybe_advance_epoch` — ALL via plain `self.db.put()`, which after M-2 removed `set_manual_wal_flush(true)` reaches only the OS page cache, not disk (confirmed: `storage:108` `put` uses default WriteOptions). Power loss after the state-root fsync but before the shutdown-only `flush()` (`main.rs:1020`): on restart RocksDB recovers `sys:state_root` for block N but rolls settlement back to pre-values. Block N+1 reads the un-burned supply/un-credited balances, folds them into `sys:state_root = SHA256(prev_root || batch_hash)` producing a root differing from every peer that persisted settlement → irreconcilable fork; height and root advance normally so nothing self-detects.

**Why exploitable:** M-2 hardened only `write_batch` (`sync=true`); `put()`/`delete()` (`storage:108-125`) still use default non-sync WriteOptions and `set_manual_wal_flush(true)` was removed — plain writes lost on power loss exactly as before, just relocated. The settlement writes are world state the next block reads and folds into the root, so their loss deterministically changes future roots. No post-commit flush on the consensus path; no reconciliation between the durable root and the non-durable settlement layer.

**Fix:** Fold the entire block settlement (rewards, burn, supply-tracker, epoch-advance, slash execution, `save_block_json`) into ONE fsync'd `WriteBatch` per block, atomic with `sys:state_root` and `latest_height`. Have the settlement helpers RETURN their `(key,val)` mutations instead of calling `self.db.put()` directly, accumulate alongside the tx updates and block record, commit the whole block as one `sync=true` batch.

---

#### H-8 — Gossip-timing-dependent downtime-slash promotion applies Move mutations at divergent heights → later state-root fork
**`core/executor/src/lib.rs:1500`** — *goal: fork finality with no >2/3 attacker stake by making honest nodes diverge on committed balances.*

**Kill-chain:** Each honest validator records local `sys:downtime_attestation:{V}:{epoch}:{reporter}` and gossips it (`dag.rs:532-548`). Attestations propagate with jitter, so the quorum-crossing attestation lands in different nodes' RocksDB at different heights; an attacker co-located as one low-stake validator amplifies this by delaying/selectively broadcasting. `execute_block_parallel` calls `promote_downtime_attestations_to_slash()` (`:1500`) then `execute_pending_slashes()` (`:1505`) unconditionally on every block, no height gate. Whichever node first sees quorum writes `sys:pending_slash:{V}` and runs `slash_validator_bps`+`slash_pool`, mutating V's ValidatorSet/CoinStore via `self.db.put` (`:1777-1782, 1841-1843`). Node A slashes V at block N; node B not until N+m. These slash writes bypass the root (`sys:state_root` written only in the per-tx loop at `:1393`), so blocks N..N+m carry matching roots and finality proceeds silently. At block N+k a NORMAL rooted staking/coin tx reads V's now-divergent resource → A read slashed, B read un-slashed → the rooted update differs → `new_root` differs → permanent fork.

**Why exploitable:** Promotion executes with no deterministic gate and its input is node-local gossip state (`scan_prefix("sys:downtime_attestation:")`, `:1578`), inherently timing-dependent. Slash mutations hit the exact `resource_{addr}_…` keys ordinary rooted txs read; the root does not hash the slash writes, so the mismatch only surfaces k blocks later, defeating early rejection. The H-02 comment claiming gossip makes this safe is wrong — arrival order is exactly what is non-deterministic.

**Fix:** Fold each signature-verified attestation into ROOTED state as a system tx and promote only from on-chain (rooted) attestation state; OR gate promotion to a fixed epoch boundary AND require attestations committed at a finalized height below a fixed lag so every node has the identical set before any slash. Additionally route slash `vm_changes` through the `batch_hasher` (into `state_root`) or add a committed-slash commitment in the header.

---

#### H-9 — Per-IP cap defaults to 60% of global cap → two source IPs eclipse all inbound TCP peering
**`common/network/src/lib.rs:10`** — *goal: isolate a victim from honest peers by saturating its inbound connection budget.*

**Kill-chain:** `MAX_CONNECTIONS=100`, `MAX_CONN_PER_IP_MIN=60`. From IP-A open 60 concurrent secure-TCP connections (global and per-IP checks pass for the first 60, `:124`); each task holds its `ConnectionGuard` slot for the connection lifetime — never close them (sit in the read loop within the 60s idle timeout, refreshed by a heartbeat under the 100 msg/s limit). From IP-B open 40 more → `active_connections == 100`. Every subsequent inbound connection from any honest peer hits `active_connections >= MAX_CONNECTIONS` (`:108`) and is dropped before handshake. Honest peers that lose their session (restart, blip) can never reconnect inbound.

**Why exploitable:** The per-IP cap (SEC-#28) is 60% of the global 100, so a 2-IP attacker consumes 100/100. The guard slot is held for the whole connection; nothing bounds how long a handshaked-idle connection lives below 60s, refreshed cheaply. No PoS, no per-identity cost, no reservation for known validators/seeds.

**Fix:** Default the per-IP cap to a small fraction of global (3-5, env-tunable up for CGNAT), and/or reserve a portion of `MAX_CONNECTIONS` for connections whose HELLO identity is in the active validator/seed set. Cap total pre-first-useful-message idle connections separately.

---

#### H-10 — Authenticated-HELLO path persists unlimited distinct peer identities per source IP → peer-store poisoning eclipse
**`common/network/src/lib.rs:318/341`** — *goal: dominate the victim's persistent peer set so its reconnect/sync loops dial attacker identities, surviving reboot.*

**Kill-chain:** Attacker generates N (e.g. 50,000) fresh Ed25519 keypairs. Sequentially (never reaching the 60-concurrent cap), from one IP: open connection, complete DH+HELLO with keypair_i (valid sig over ephemeral keys, `derive_address==peer_id`, `port!=0` — all pass `:279-312`), close. Each success runs `save_peer(peer_id, peer_port)` + `save_peer_ip(peer_id, remote_ip)` (`:341-344`) writing permanent `peer:{id}`/`peer_ip:{id}` rows (attacker's real IP, attacker-chosen port) and `peers.insert` (`:318-320`). The 15s reconnect service (`scan_peers`, `main.rs:820-865`) re-dials EVERY saved peer; `sync_from_peers` (`order_peers_seed_first`) iterates ALL peers (`sync:552`). N records dialed forever, surviving reboots.

**Why exploitable:** No per-IP registration cap and no total-size cap anywhere (grep: no `MAX_PEERS`, no count-based eviction; `remove_peer` fires only for docker-bridge IPs or snapshot bootstrap). The concurrent per-IP cap limits simultaneous sockets, not distinct durable identities. `save_peer`/`save_peer_ip`/`scan_peers` are unbounded. The in-memory `peers` map is the broadcast fan-out target (`dag.rs:1134-1147`) and sync source, so the attacker also dominates outbound bandwidth and keeps `has_peers` pinned true (disabling split-brain isolation). *(H-18, H-26 are the same defect rediscovered; fix once.)*

**Fix:** Cap distinct persisted peer identities per source IP (bounded, e.g. ≤4) and a global peer-store ceiling with LRU/last-seen eviction. Only persist a peer after it proves usefulness (served a valid sync/height response), not merely on HELLO. Rate-limit HELLO-completions per IP. Treat non-validator inbound HELLOs as session-only (memory, evictable), like the docker-bridge branch at `:328-339`.

---

#### H-11 — Unauthenticated TCP → DA: self-signed `DA_COMMIT` batches drive unbounded RocksDB + memory growth pre-auth
**`da/src/lib.rs:581`** — *goal: inject a state-driving p2p message with no valid on-chain identity and exhaust a target's disk + memory.*

**Kill-chain:** Attacker opens raw TCP to the P2P port. The server handshake requires only a 32-byte X25519 ephemeral key; the client is never required to authenticate (comment at `network:238` calls it "the unauthenticated path"). Any decrypted non-`HELLO:` frame falls through to `handler_clone(msg)` (`:375`); the node routes `DA_COMMIT:` to `da_sequencer.handle_incoming_batch` (`main.rs:733-737`). Attacker generates one throwaway keypair, builds a `DABatch` with `proposer_pubkey=their pubkey`, `proposer_id=derive_address(their_pubkey)`, signs `SHA256(payload_json)` with their own key, ~1 MiB blob. `handle_incoming_batch` (`:509-590`) verifies the sig against the attacker's OWN embedded pubkey (passes) and `derive_address(pubkey)==proposer_id` (passes) — but performs NO check that `proposer_id` is an authorized sequencer/validator, and NO bound on `payload.epoch`. It unconditionally writes `da_root_{epoch}` to RocksDB (`:581-584`) and inserts into the unbounded `HashMap<u64,DABatch>` (`:97/587-589`), keyed by attacker-chosen epoch. Iterating distinct epochs at 100 msg/s/conn × 60 conns/IP ≈ 6000 unique ~1 MiB batches/sec → multi-GB/s disk fill + unbounded memory → OOM/disk-full crash → downtime jail+slash of the victim.

**Why exploitable:** The only gate is a self-referential signature (verified against attacker-supplied pubkey). No authorization predicate (grep: no validator/authorized/is_sequencer check in `handle_incoming_batch`). `batches` has no eviction/cap; `da_root_{epoch}` puts are unbounded. M-3 rate-limit and the 1 MiB frame cap bound per-message cost, not aggregate distinct-key durable writes. The legacy branch (`:564`, empty pubkey) is weaker still — logs "Legacy batch" and writes with NO signature check.

**Fix:** In `handle_incoming_batch`: require `proposer_id` ∈ current validator set / authorized-sequencer allowlist before any write; reject epochs outside a small window around the node's current epoch; remove the empty-pubkey legacy fall-through; bound `batches` with an LRU/size cap.

---

#### H-12 — Unauthenticated peer injects forged empty-root blocks into a syncing/observer node's canonical chain
**`sync/src/lib.rs:965`** — *goal: drive attacker-authored non-consensus blocks into a fresh-join/observer/catching-up node's persistent chain.*

**Kill-chain:** Attacker completes the ordinary HELLO handshake (proves only self-generated key ownership, not validator status) and is persisted as a dialable peer (`network:341-344`). The victim's periodic sync iterates all peers seed-first (`sync:552`) and connects. `tip_agreement_n` defaults to 1 (`:160-168`; nothing sets `sys:config:tip_agreement_n`), skipping the multi-seed gate (`:534`). Attacker answers `GET_HEIGHT` above the victim's, then returns `SYNC_RESP` with forged blocks: `proposer_id` = a REAL validator address (passes `:271-277`), correct `prev_hash`/`tx_hash`/self-consistent header hash (no signature), in-range timestamp, and empty `state_root`/`receipts_root`. `process_blocks` executes then calls `verify_execution_roots`; `require_exec_roots` defaults false (`:58-65`), so the empty-root branch skips the mismatch check (`:120/126`) and returns Ok. `save_block_json` persists the forged block and advances `latest_height`/`latest_block_hash` (`:990-996`).

**Why exploitable:** Block acceptance is not gated by any signature or QC — the crypto backstop (`apply_finality_artifact`/`verify_qc`) governs finality advancement, not which blocks get written (comment `:968-982` admits synced blocks are unauthenticated). Both mitigations are off by default and set nowhere: `require_exec_roots` (empty-root bypass) and `tip_agreement_n>1`. The proposer-in-set check only forces the attacker to NAME a real validator. The reorg/finalized-boundary guard protects only heights ≤ the local finalized boundary, so behind/observer/fresh nodes are fed a forged extension.

**Fix:** Require each synced block covered by a verifiable QC (or proposer vertex signature) BEFORE `execute_block_parallel`. Immediate hardening: pin `sys:config:require_exec_roots=1` and `tip_agreement_n>=2` at mainnet genesis; reject any block whose `state_root`/`receipts_root` is empty on a require-roots chain.

---

## Method

The audit ran as a **goal-oriented adversarial fan-out**, not a checklist sweep. Each attacker "cell" was handed a concrete *goal* (mint AIN from nothing; fork finality with sub-2/3 stake; halt a node remotely; forge a bridge deposit) rather than a file to skim, and told to build a full kill-chain from an untrusted entry point (network peer, malicious RPC, low-stake validator, ordinary crash) to the goal.

**Three rounds with escalating angles:**

1. **Round 1 — direct.** Attack each subsystem head-on against its stated invariant (executor supply conservation, consensus finality safety, sync block acceptance, bridge finality gate). Produced the paymaster mint (C-1), the QC ghost quorum (C-2), the grindable beacon (C-3), the reorg-halt DoS (C-6), the commit-before-verify poison (C-7), the timestamp fork (C-8), and the Tier-B bridge bypass (C-9).

2. **Round 2 — cross-layer.** Chain a weakness in one layer into another (unauthenticated TCP transport → DA durable writes, H-11; gossip-timing → executor state root, H-8; append-only v1 → QC verify → sync/RPC/bridge all at once, C-2). This is where the transport→DA and mempool→executor→mint compositions surfaced.

3. **Round 3 — edge / regression.** Target the seams the six fix commits created: the restart seam of the H-1 persistence (C-4/C-14), the gossip-order seam of the same beacon (C-5), the M-2 fsync-split seams (H-6/H-7), the reorg-vs-exec-root seam left by H-3 (C-6/C-7 siblings, H-5 epoch double-mint), and the M-5 byte-floor-vs-structural-cost seam (H-4).

**Loop-until-dry:** each round re-ran its cells until a full pass produced no new candidate exceeding the confirmation bar. Rounds independently rediscovered the same four defect families (sync-block-unauthenticated, beacon-nondeterministic/grindable, paymaster-not-a-conflict-token, bridge-tx-not-bound); this convergence is itself signal, and the report de-duplicates them into canonical findings with cross-references.

**Double verification:** every surviving candidate was handed to **two independent skeptics** who each re-derived the kill-chain against the actual source at HEAD 6950bf0 (reading the cited `file:line`, checking guards on the real path, confirming defaults, and — where feasible — reproducing the math, e.g. the SHA256 order-sensitivity and the VDF-50 grind counts). **Only candidates both skeptics confirmed exploitable are included.** Candidates where one skeptic could not reproduce the path, or where a guard actually blocked it, were dropped and are not in this report. The 35 findings above are the both-verifier-confirmed set.

---

## Regression check on the six fix commits

Explicit clean-or-not verdict per commit. **The commit set is NOT clean** — three of six introduced or failed to close an exploitable condition.

| Commit | Scope | Verdict | Detail |
|---|---|---|---|
| `28895bd` | H-5/H-6/M-6 CLI key handling | **CLEAN** (this round) | No confirmed finding re-broke it; out of adversarial reach for the network/consensus/bridge goals pursued here. Not exhaustively re-pentested. |
| `80962c1` | H-4/M-3/M-4/L-1 (da, net, genesis) | **NOT CLEAN — insufficient, not regressed** | M-3 per-message rate-limit and the frame cap are per-message and do **not** bound aggregate distinct-key durable writes (H-11 DA disk-fill) or serial distinct-identity registration (H-10 peer-store poisoning). The fixes hold at their own scope but leave the aggregate-resource class open. No new bug introduced. |
| `1397e2f` | M-1/L-2 QC chain_id binding | **CLEAN as written, but does not cover the real gap** | The chain_id binding is correct and did not false-reject legit input (the HEAD test aligns QC chain_id to the M-1 binding). It is satisfied by a stale-but-consistent `sys:validator_set:v1`, so it provides **zero** protection against the append-only ghost quorum (C-2). No regression; scope simply excludes the vulnerability. |
| `d488bc6` | H-3/M-2/M-5 + burn clamp | **NOT CLEAN — INCOMPLETE + REGRESSED** | **H-3:** removed the persistent halt from the exec-root path (`sync:987` `break`, confirmed) but left the **identical latch in the reorg branch at `sync:912` intact and more reachable** (C-6, and its DoS twins C-12/H-23/H-28) — the remote-DoS is still live. Removing the halt without adding pre-execution authentication **converted a clean self-halt into silent permanent state poisoning** (C-7, C-10, H-15) and enabled the epoch double-mint on rollback+re-exec (H-5). **M-2:** made only `write_batch` fsync-durable while `put()`/`delete()` remain non-sync (confirmed `storage:108,125`) and removed `set_manual_wal_flush(true)` — **splitting** crash-consistency so the state root is durable ahead of the block record and settlement, forking the chain on an ordinary crash (H-6, H-7). **M-5:** the publish byte-floor holds but does not bound super-linear structural verifier cost (H-4). The burn clamp itself was not re-broken. |
| `6593423` | H-1/H-2 leader election | **NOT CLEAN — REGRESSED into finality-safety fork** | Restored cross-node election determinism at the value level, but (a) left the Step-1 beacon **grindable** by the anchor proposer via instant VDF-50 (C-3, H-25) — H-2 explicitly deferred; and (b) newly made the election beacon the *sole* input, turning the pre-existing reversed+truncated `committed_sequence` persistence (`ordering:517`, predates the fix) into a **restart-triggered honest-node fork** (C-4/C-14) and exposing a gossip-order fork (C-5). The fix's own docstring assertion ("identical on every honest node at commit time") is false across both restart and async gossip. Did not false-reject legit input, but broke liveness-adjacent safety under routine operation. |
| `6950bf0` | tests + doc alignment | **CLEAN** | Test/doc-only (QC test chain_id alignment, storage doc lint, remediation table). No behavioral change; introduced no finding. |

**Bottom line on regressions:** the two consensus-critical hardening commits (`d488bc6` H-3, `6593423` H-1) each *created* an exploitable condition worse than or equal to the one they closed — silent state poisoning replacing a clean halt, and an honest-node finality fork replacing a determinism gap. These must be treated as active regressions, not merely incomplete fixes, before mainnet.
