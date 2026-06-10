All critical claims are verified against the actual code. `delegation::initialize` exists but has zero callers in genesis.rs (registry never bootstrapped — B3 blocker confirmed). BLS API confirmed (`keygen`, `pubkey_raw`, `prove_possession_raw`, `verify_possession`, `consensus()`). I have enough to produce the auditable plan.

---

# REMEDIATION PLAN — RESET BUNDLE B1–B4 (single fresh-genesis testnet reset)

## VERDICT SUMMARY (reviewer-aligned, code-verified)

| Change | Reviewer verdict | Code-verified status | Ship in this reset? |
|---|---|---|---|
| **B1** validator BLS identity | approve-with-changes | 4 required fixes valid; all confirmed against code | **YES, after required-changes** |
| **B2** gas refund | **reject** | DoS finding CONFIRMED (`coin::transfer` is `public entry`, line 80; drain-assert line 100) | **NO — redesign required** |
| **B3** delegation reward wiring | **reject** | Registry-bootstrap blocker CONFIRMED (`delegation::initialize` zero callers) + inflation-doubling | **NO — redesign + economics sign-off** |
| **B4** stake-weighted consensus | approve-with-changes | 5 required fixes valid; Coin u64/u128 + 4 call sites CONFIRMED | **YES, after required-changes** |

**Bottom line: only B1 and B4 are shippable in this reset (after their required-changes are applied). B2 and B4 share NO files. B1 and B3 BOTH touch Move stdlib + genesis — but B3 is rejected, so it does not co-apply. B2 and B3 must be re-specced and re-reviewed before they touch the tree.**

---

## CODE-GROUNDED VERIFICATION (what I confirmed this session)

1. **B4 dag.rs `Coin.value: u64`** — CONFIRMED at dag.rs:1492 (`#[allow(dead_code)] value: u64`). Genesis stake is u128 (10^24). The slow-path `bcs::from_bytes::<ValidatorSet>` **already fails today** and falls through to `Vec::new()`. Reviewer is correct; B1's dag.rs rationale ("omitting BLS breaks decode") is false until this is fixed.
2. **B4 four call sites** — CONFIRMED: get_validator_set() at dag.rs **348, 695, 845, 1238** (spec only mentions 3; line 1238 is unaddressed).
3. **B2 free-execution DoS** — CONFIRMED: `coin::transfer` is `public entry fun` (coin.move:80) with `assert!(store.coin.value >= amount)` drain (line 100). End-of-session re-read-balance charge is exploitable exactly as the reviewer describes.
4. **B3 registry never bootstrapped** — CONFIRMED: `delegation::initialize` exists (delegation.move:73) but has zero callers in genesis.rs. `distribute_all_delegation_rewards` would abort every epoch.
5. **BLS API** — CONFIRMED: `BLSEngine::consensus()`, `keygen(&[u8;32])`, `pubkey_raw`, `prove_possession_raw`, `verify_possession` all present (common/crypto/src/bls/*.rs).
6. **qc::ValidatorInfo shape** — CONFIRMED: `{address:String, stake:u64, ed25519_public_key:String, bls_public_key:String, bls_pop:String}` (qc.rs:28). **stake is u64** → B1's u128→u64 downcast is real and unresolved.
7. **node→consensus dep** — CONFIRMED present (core/node/Cargo.toml:17). B1 open-question #5 resolved: **no Cargo.toml change needed**.
8. **GENESIS_VERSION** — CONFIRMED: `"phase1-dex-registry-v1"` (genesis.rs:16), gated at line 408, written at line 841.
9. **node_identity threading** — CONFIRMED: main.rs:401 holds `signing_key.to_bytes()`; initialize_genesis (genesis.rs:431) currently takes `(&storage, stdlib_path, &node_addr_hex, &pub_key_hex)` — **no node_identity param yet** (B1 must add it).

---

## SAFE APPLY ORDER (within the single reset)

### Shared-file analysis
- **B1** touches: `staking.move`, `genesis.rs`, `executor/lib.rs`, `dag.rs`, `main.rs`, stdlib bytecode.
- **B4** touches: `dag.rs`, `ordering.rs`, `consensus/tests.rs`.
- **B1 ∩ B4 = `dag.rs`** (the one shared file). B1 appends BLS fields to the dag.rs `ValidatorConfig` BCS mirror; B4 changes `Coin.value u64→u128` + restructures `read_validators_from_storage`/`get_validator_set` in the same file. **These edits overlap in the same struct region** → must be coordinated, not blindly applied in two independent commits.
- B2 and B3 are dropped from this reset, so no further sharing.

### Recommended commit sequence (sequential, NOT one squashed commit)

**Commit 1 — B4 consensus stake-weighting** (land first; it owns the dag.rs `ValidatorConfig`/`Coin` rework)
- Apply all B4 patches **plus the 5 required-changes** (slow-path patch, single-source-of-truth, line-1238 verify, genesis non-zero-stake invariant, threat-model doc).
- This commit fixes the `Coin.value u64→u128` defect, so the dag.rs slow-path actually decodes.
- Gate: `cargo build -p consensus && cargo test -p consensus`. No bytecode regen (B4 is Rust-only).

**Commit 2 — B1 validator BLS identity** (lands on top; appends BLS to the now-correct dag.rs struct)
- Apply all B1 patches **plus the 4 required-changes** (split destructure, u128→u64 scaling, dag.rs Coin already fixed by Commit 1, GENESIS_VERSION + PoP hook confirmed).
- Because Commit 1 already set `Coin.value: u128` and added the stake field as a live read, B1's dag.rs `ValidatorConfig` append is a clean trailing-field add on top.
- Gate: regen stdlib bytecode → `cargo build -p node && cargo test -p node && cargo test -p executor`.

**Then:** single fresh-genesis reset, GENESIS_VERSION bumped once (see below), nodes redeployed.

> **Why sequential not squashed:** B4 is consensus-safety-critical and Rust-only; B1 is genesis/BCS-layout-critical and needs bytecode regen. Bisectable history matters here — if the reset chain forks, you need to know whether the leader-schedule change or the BCS-layout change caused it. Keep them as two reviewable commits on the same `audit/p0-security-fixes` branch.

---

## DESIGN DECISIONS THE MAINTAINER MUST CONFIRM BEFORE APPLY

**[B1-DD1] Validator BLS key source — CONFIRM the deterministic derivation.**
Spec recommends `bls_seed = SHA256("AINCORE_VALIDATOR_BLS_V1" || node_identity)`, reusing node.key (Ed25519) as the single root secret, mirroring `da/src/lib.rs:25 derive_da_enc_key`. This is sound and consistent with the existing security model. **Maintainer must confirm** (a) the exact domain-separation string, and (b) that multi-validator genesis operators will each run a derive tool against their own node.key and paste `bls_public_key+bls_pop` into genesis.json. *Recommendation: APPROVE as specced.*

**[B1-DD2] u128→u64 stake scaling for `qc::ValidatorInfo.stake`.** Genesis stake = 10^24 ≫ u64::MAX (1.8e19). A naive cast wraps and corrupts verify_qc's `signed*3 > total*2`. **Maintainer must pick the scale.** *Recommendation: whole-AIN units `value / 10^18` with `checked` conversion, documented; add the no-truncation test.* This is REQUIRED before B1 lands.

**[B1-DD3] join_validator_set Rust PoP hook point.** Move can't run blst. **Confirm**: executor pre-dispatch PoP check + mempool early-reject guard, and whether runtime `join` also appends to `sys:validator_set:v1` (to keep v1 live, not genesis-only). *Recommendation: executor pre-dispatch is the authoritative gate; mempool guard is best-effort early reject; YES append to v1 at runtime.*

**[B1-DD4] GENESIS_VERSION string.** Confirm exact value, e.g. `"phase1-bls-validators-v1"`. Since B1+B4 ship together, one bump covers both.

**[B4-DD1] Byzantine bound restatement (consensus-safety).** The fault model shifts from "<1/3 of validators by count" to "<1/3 of total stake." The BFT safety argument is sound under the stake model, but **any whitepaper/onboarding doc must be reconciled** or it will mislead validator onboarding. Non-code, ships in the same reset. **REQUIRED sign-off.**

**[B4-DD2] Parent quorum left count-based — confirm intent.** B4 deliberately keeps `bft_quorum_threshold` (parent gate in try_create_vertex) count-based to isolate the safety change from the liveness change. *Recommendation: APPROVE — ship commit+leader stake-weighting now, evaluate parent-quorum stake-weighting as a separate change.*

**[B4-DD3] Genesis non-zero-stake invariant.** `try_commit` returns None when `total_stake==0` → dead chain. **Confirm genesis-tool seeds non-zero per-validator stake in sys:validators.** REQUIRED pre-reset check.

---

## PER-CHANGE REQUIRED-CHANGES (must be in the patch before apply)

### B1 — 4 required changes
1. **Split the destructure patch into two byte-exact patches.** staking.move line 132 keeps `validator_addr: _`; **line 365 (slash_validator_bps) must quote the real text** `let ValidatorConfig { validator_addr, stake, public_key: _ } = config;` → `let ValidatorConfig { validator_addr, stake, public_key: _, bls_public_key: _, bls_pop: _ } = config;` (KEEP `validator_addr` bound — it's used at line 388). The spec's single combined patch will NOT apply.
2. **Implement overflow-checked u128→u64 stake scaling** in `crypto_qc_validator_info` (see B1-DD2). Add `test_validator_set_v1_roundtrip` asserting no truncation vs the u128 genesis input.
3. **dag.rs `Coin.value u64→u128` is handled by B4 Commit 1** — but B1 must NOT re-introduce a u64 Coin when appending BLS fields. After Commit 1, B1's dag.rs append is a clean trailing add. Add a test that slow-path `bcs::from_bytes::<ValidatorSet>` succeeds on a fresh genesis DB (this validates B1's stated rationale, which is only true once Coin is u128).
4. **Confirm GENESIS_VERSION string (B1-DD4) and join PoP hook (B1-DD3)** before merge.

The remaining 11 B1 BCS-append patches (genesis.rs ×2 [Serialize writer 489-493, Deserialize verifier 287-292], executor MoveValidatorConfig 70-75, dag.rs struct append, GenesisValidatorConfig optional fields, sys:validator_set:v1 write) are **byte-exact against current code and correctly ordered** — confirmed.

### B4 — 5 required changes
1. **Add the MISSING slow-path patch** (dag.rs ~1468-1487): change `read_validators_from_storage` to push `(v.validator_addr.to_string(), v.stake.value)` pairs, apply the SAME `sort_by(|a,b| a.0.cmp(&b.0))` + `dedup_by(|a,b| a.0==b.0)`, final fallback `Vec::new()` typed as `Vec<(String,u64)>`. **Without this the crate does not compile** (return type changes to `Vec<(String,u64)>` but slow path still builds `Vec<String>`). Also change `Coin.value u64→u128` and remove `#[allow(dead_code)]` from `Coin.value` and `ValidatorConfig.stake` (now live reads).
2. **Resolve single-source-of-truth contradiction:** either route ordering.rs `try_commit` through `DagConsensus::stake_quorum_met`, OR drop the dead `stake_quorum_met` and keep the inline check. Do not ship three copies of `signed*3 > total*2`. *Recommendation: route ordering.rs through `stake_quorum_met` so the "one rule" claim is true.*
3. **Verify dag.rs:1238** `get_validator_set()` is a pure `Vec<String>` membership consumer (spec never mentions it). I confirmed it's one of the 4 call sites; it stays on the address-only adapter — just needs a one-line confirmation in the patch.
4. **Genesis non-zero-stake invariant** (B4-DD3) + GENESIS_VERSION bump.
5. **Update threat-model wording** (B4-DD1) from "<1/3 validators by count" to "<1/3 total stake."

B4's BFT safety argument, author-dedup (genuine latent-bug fix), formula parity with qc.rs:204, and leader determinism-via-canonical-sort are **CORRECT and approved**.

### B2 — DO NOT SHIP. Redesign required.
The end-of-session re-read-balance model reintroduces a **free-execution + infinite-replay DoS** (CONFIRMED: `coin::transfer` public entry drains payer → end deduct aborts → must_succeed Err → executor returns None → nonce never committed → tx infinitely replayable, work done for free). Required redesign (reviewer's path 1):
- Keep the **full-gas pre-deduct as the FIRST in-session action** (as today), then **REFUND `(gas_limit - gas_used) * price` at the END of the SAME session** via a NEW must_succeed system entry `coin::refund_gas<CoinType>(sys, user, amount)`. Both writes land in one changeset on one key (deterministic ordering, no cross-session collision). `actual_gas = gas_cost - refund = gas_used * price`.
- This **requires a Move stdlib addition** → `bytecode_regen_needed = TRUE` and `genesis_version_bump = TRUE` (spec's `bytecode_regen_needed=false` is WRONG).
- Do NOT meter the refund/epilogue against the user's gas_meter (avoids spurious EXECUTION_LIMIT_REACHED).
- Provide the **concrete PublishModule-arm patch** (not "same pattern"), the production `move_coin_balance` reader, and the vm_move-side AincoreCoin StructTag.
- Add tests: transfer-drain attacker still charged + nonce bumped; PublishModule `gas_charged > 0`.
- **If B2 redesign also needs Move bytecode regen, it CAN co-reset with B1 (both touch stdlib + genesis)** — but only after a fresh spec + review pass. Not in this commit.

### B3 — DO NOT SHIP. Redesign + economics sign-off required.
- **BLOCKER: bootstrap `DelegationRegistry`** (CONFIRMED zero callers). Either genesis.rs writes the BCS resource at `resource_<0x1>_0x1::delegation::DelegationRegistry = {validator_pools: empty}`, OR guard `if (!exists<DelegationRegistry>(@0x1)) return;` in both the new entry AND `enable_delegation`. Option (a) is mandatory anyway for `enable_delegation` to work.
- **BLOCKER: missing test scaffolding** — add a `TestDelegationRegistry` BCS mirror + seeder, else tests only hit the abort branch.
- **MAJOR (economics):** flat-per-pool `current_epoch_reward()` roughly DOUBLES per-epoch inflation (spec's "matches self-stake per-validator reward" is false — `distribute_rewards` splits a stake-weighted budget). **Requires economics-owner sign-off** before a non-reversible reset.
- **MAJOR (cap honesty):** delegator reward is lazily minted at `claim_rewards`; the accumulator over-promises near MAX_SUPPLY (first-come-first-served). Either document it or only bump the accumulator by the mintable amount.
- Acyclic-deps reasoning (loop in delegation.move, executor-driven, mirroring slash_pool) is CORRECT.

---

## BCS READER-IMPACT LIST (consolidated, for the shippable B1+B4)

**B1 — `staking::ValidatorConfig` gains 2 trailing `vector<u8>` (`bls_public_key`, `bls_pop`). ALL mirrors must append in identical order:**
1. genesis.rs:287-292 — Deserialize (verify_genesis_integrity, reads resource at startup). ✅ patch present.
2. genesis.rs:489-493 — Serialize (initialize_genesis, WRITES genesis resource via bcs::to_bytes line 659). ✅ patch present.
3. executor/lib.rs:70-75 — MoveValidatorConfig (Serialize+Deserialize). **CRITICAL**: lib.rs:747-749 decode→mutate total_supply→re-encode round-trips the WHOLE set; missing fields silently corrupt the on-disk staking resource on every burn. ✅ patch present + roundtrip test required.
4. dag.rs:1497-1505 — Deserialize slow-path (read at 1472). ✅ patch present (mark dead_code).

**NOT BCS readers of ValidatorConfig (unaffected by the Move struct change):** storage/src/lib.rs (sys:validators JSON `Vec<(String,u64)>`), executor slash-path JSON rewrite (lib.rs:1531). `sys:validators` legacy format UNCHANGED. New `sys:validator_set:v1` = JSON `Vec<consensus::qc::ValidatorInfo>` (additive).

**B4 — no serialized struct change.** `sys:validators` stays `Vec<(String,u64)>` JSON (the change is to STOP discarding the u64). dag.rs BCS `ValidatorSet`/`ValidatorConfig`/`Coin` readers unchanged ON THE WIRE — but `Coin.value` must be corrected `u64→u128` to match what genesis actually writes (a read-correctness fix, not a layout change). `validators_cache` field type `Vec<String>`→`Vec<(String,u64)>` is in-memory only, no BCS/persistence impact.

---

## BYTECODE / GENESIS-VERSION FLAGS

| Change | Bytecode regen | Genesis version bump | Why |
|---|---|---|---|
| B1 | **YES** | **YES** | staking.move struct + join signature + 2 new error consts change stdlib bytecode → `stdlib_state_hash` + `GENESIS_STDLIB_COUNT_KEY` change; new BCS layout invalidates all DBs |
| B4 | **NO** | **YES** | Rust-only, but finality predicate + leader schedule change → mixed old/new nodes fork; needs clean reset |
| B2 (redesign) | **YES** (refund_gas stdlib fn) | YES | Move stdlib addition |
| B3 (redesign) | YES (new entries) | YES | stdlib new functions |

**One combined bump for this reset** (B1+B4): change genesis.rs:16 `GENESIS_VERSION` from `"phase1-dex-registry-v1"` to the confirmed string (recommend `"phase1-bls-stake-v1"` to reflect both changes). Regen stdlib: `cargo run -p move_compiler_tool -- --sources core/vm_move/stdlib/sources/*.move --output <dir>`.

---

## FINAL PRE-RESET VERIFICATION CHECKLIST

**Code/spec gates (before commit):**
- [ ] B4 slow-path patch authored (Coin u64→u128, return type `Vec<(String,u64)>`, sort_by/dedup_by, `Vec::new()` typed) — crate compiles.
- [ ] B4 single-source-of-truth resolved (ordering.rs calls `stake_quorum_met` OR dead helper dropped).
- [ ] B4 dag.rs:1238 confirmed pure `Vec<String>` consumer.
- [ ] B1 destructure split into two byte-exact patches (line 132 + line 365 with `validator_addr` bound).
- [ ] B1 u128→u64 stake scaling implemented + no-truncation test (B1-DD2 confirmed).
- [ ] B1 initialize_genesis signature adds `node_identity: &[u8;32]`, threaded from main.rs:401.
- [ ] GENESIS_VERSION string confirmed (B1-DD4) and bumped once.

**Design sign-offs:**
- [ ] B1-DD1 BLS key source approved (domain-sep string).
- [ ] B1-DD3 join PoP hook point confirmed.
- [ ] B4-DD1 threat model doc updated to "<1/3 total stake."
- [ ] B4-DD2 parent-quorum-stays-count approved.
- [ ] B4-DD3 / B1: genesis-tool seeds NON-ZERO per-validator stake (else dead chain at block 4).

**Build/test gates:**
- [ ] Commit 1 (B4): `cargo build -p consensus && cargo test -p consensus` (incl. stake_supermajority, count-majority-stake-minority-fails, equivocator-counted-once, leader determinism-across-node-order, stake_quorum_met boundary tests).
- [ ] Commit 2 (B1): regen stdlib bytecode; `cargo build -p node && cargo test -p node && cargo test -p executor` (incl. bad-PoP reject, genesis loads BLS, validator_set_v1 roundtrip no-truncation, MoveValidatorSet BCS roundtrip preserves BLS, single-node fallback derives BLS).
- [ ] `cargo clippy --workspace -- -D warnings` clean.
- [ ] Fresh-genesis smoke: init a clean DB, verify `verify_genesis_integrity` passes with new GENESIS_VERSION, dag.rs slow-path decodes the ValidatorSet (B4 fix proven), node mines and commits a block.

**Reset ops gates:**
- [ ] B2 and B3 explicitly EXCLUDED from this reset (tracked for a later spec+review cycle).
- [ ] All existing DBs wiped (BCS layout + GENESIS_VERSION change invalidates them — intended).
- [ ] No mixed old/new nodes (B4 finality predicate + leader schedule change guarantees a fork otherwise).
- [ ] Multi-validator genesis.json carries each operator's `bls_public_key+bls_pop` (PoP-verified at load).

---

## HONESTY FLAGS (changes needing deeper review before safe to ship)

- **B2 and B3 are NOT safe to ship as specced** — both rejected with confirmed blockers (B2 free-exec DoS; B3 registry never bootstrapped + undisclosed inflation doubling). They need full re-spec + re-review. If their redesigns require Move bytecode regen, they are natural co-resets with B1 in a *future* reset, not this one.
- **B1 u128→u64 stake scaling (B1-DD2) is an open monetary/consensus decision** — `verify_qc` is stake-weighted, so a wrong scale silently corrupts the >2/3 threshold. Must be decided + tested before B1 lands.
- **B4 is safe in isolation** but its safety is *conditional on the threat model being restated in stake terms* — a doc change that ships in the same reset and must not be skipped.
- The two shippable changes share **`dag.rs`**; apply B4 first (it owns the Coin/ValidatorConfig rework) so B1's trailing-field append is clean. Do not attempt a single squashed B1+B4 commit.

Relevant files (absolute):
- `/Users/macbookpro/Documents/AINCORE-Blockchain/consensus/consensus/src/dag.rs` (B1+B4 shared)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/consensus/consensus/src/ordering.rs` (B4)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/consensus/consensus/src/qc.rs` (B1 v1 shape, B4 formula parity)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/core/node/src/genesis.rs` (B1)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/core/node/src/main.rs` (B1 node_identity)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/core/executor/src/lib.rs` (B1 mirror, B2)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/stdlib/sources/staking.move` (B1, B3)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/stdlib/sources/delegation.move` (B3)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/stdlib/sources/coin.move` (B2 transfer-drain confirmed)