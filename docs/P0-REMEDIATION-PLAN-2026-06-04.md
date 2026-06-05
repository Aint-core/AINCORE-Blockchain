All anchors confirmed: F3 arms at 1027/1046 with `-32040` precedent at 764; F4 has 16 `{}:{}:{}:{}` sites; F5 server guard at 165, unguarded `secure_connect` slice at 476 (line 627 is `read_encrypted_msg`, already range-guarded). The specs are accurate against the live tree. Producing the remediation document.

---

# AINCORE P0 Security Remediation Plan — Phase 1 Safe Wins

**Branch:** `audit/phase-1-safe-wins` (verified pre-F1: no signer-binding commit present)
**Scope:** 5 P0 fixes (F1–F5)
**Document status:** auditable; all spec line-anchors verified against the live tree on 2026-06-04.

---

## 1. Executive Summary

These five fixes close five distinct classes of total-compromise or denial-of-service vectors:

| Fix | Closes | Severity |
|-----|--------|----------|
| **F1 — VM signer binding** | User payloads can BCS-encode `@0x1` into `args[0]` and pass every `assert!(signer::address_of(s)==@0x1)` gate, forging full system authority: mint via `deposit_fee_reward`, `slash_validator_bps`, gas-free `deduct_gas`, governance execution. The Move VM (aptos-v1.3.0, commit `281f7ec`) deserializes a signer from raw user bytes and never injects it; the adapter never bound it. | **Critical — full chain takeover** |
| **F2 — Move system-only mint gates** | `staking::mint_reward` is `public fun` (over-exposed to any 0x1 module); `delegation::distribute_delegation_rewards` is `public fun` with no auth and zero callers — pure unauthenticated mint surface. | **Critical — supply inflation** |
| **F3 — Governance RPC auth** | `aincore_createProposal` / `aincore_vote` mutate governance state from unauthenticated string params, letting anyone vote with any whale's full stake weight or spoof a proposer. | **High — governance capture** |
| **F4 — Signature scope** | The signed message and dedup hash exclude `gas_limit`, `gas_price`, `input_objects`. A MITM can mutate gas fields / rewrite input objects on a validly signed tx and it still verifies. | **High — fee griefing / intent forgery** |
| **F5 — Short-frame panic guard** | `secure_connect` slices `enc_msg[0..12]` without a lower-bound check; a peer sending a frame of `msg_len ∈ 0..=11` panics the spawned periodic-sync task, permanently disabling sync. | **High — remote DoS** |

### Why F1 is the keystone

**F1 is a hard prerequisite for F2 being meaningful, and is the security foundation the whole system rests on.**

- F2's `delegation.move` hardening adds `assert!(signer::address_of(sys) == @0x1)` and makes the function `public entry`. Pre-F1, the executor forwards the user's decoded `EntryFunctionCall.args` **verbatim** with zero signer-to-sender binding (`core/executor/src/lib.rs:2051` — verified). An attacker simply BCS-encodes `@0x1` as `args[0]`, the assert passes, and **F2's `public entry` change converts a currently-unreachable mint into a reachable, exploitable one.** Landing F2's delegation patch before F1 is a *net regression*.
- The `staking.move` `public(friend)` change in F2 is link-time enforced by the Move bytecode verifier and is **independent of F1** — it is safe to land at any time.
- F4 touches the same `vm_move`/`executor` tx-verification path as F1 and must be reconciled with it (same `execute_transaction` signature, same canonical message), so the two must land coherently.

The dependency edges are therefore: **F1 → F2 (delegation arm)**, **F1 ↔ F4 (shared files, reconcile together)**. F3 and F5 are fully independent.

---

## 2. SAFE APPLY ORDER

Dependency and shared-file analysis:

- **Shared file `core/vm_move/src/lib.rs`:** touched by F1 (`execute_transaction_actions`, `bind_signer_args`, `execute_public_entry_function`) **and** F4 (`execute_transaction` signature + Ed25519/PQC verify messages). Different functions, but both change public signatures — **apply sequentially, F1 then F4**, and reconcile the `execute_transaction` arg list once.
- **Shared file `core/executor/src/lib.rs`:** touched by F1 (call sites + tuple arity) **and** F4 (verify message + `signed_tx` helper). Different lines but same file — **apply F1's executor edits first, then F4's**, rebuild between.
- **Shared file `core/vm_move/src/tests.rs`:** touched by F1 (new security tests) and F4 (call-site arg updates). Apply after both code changes land.
- **F2 delegation arm depends on F1.** F2 staking arm does not.

### Step-by-step

> Build/test gates use CLAUDE.md rules: crypto/executor changes require `cargo test`; `cargo clippy --workspace -- -D warnings` must be clean before commit.

**Step 0 — Baseline.**
Files: none. Run `cargo build --release -p node -p vm_move -p executor -p mempool` and `cargo test -p vm_move -p executor -p mempool` to capture a green baseline. Record which tests pass so F4's mass test-helper edits can be diffed against it.

**Step 1 — F5 (independent, lowest risk).**
Files: `common/network/src/lib.rs` (add `if msg_len < 12` guard), `sync/src/lib.rs` (comment-only marker).
Build/test: `cargo build -p network -p sync`; `cargo test -p network` (run the 3 new short-frame tests).
Rationale: zero coupling, pure panic→`Err` conversion. Land first to de-risk the queue.

**Step 2 — F3 (independent).**
Files: `core/node/src/api_local.rs` (replace both RPC arms with `-32040` errors).
Build/test: `cargo build -p node`; `cargo test -p node` (3 new RPC-disabled tests).
Rationale: independent, reviewer verdict **approve** (no required changes).

**Step 3 — F2 staking arm ONLY (F1-independent).**
Files: `core/vm_move/stdlib/sources/staking.move` (friend decls + `public(friend) fun mint_reward`).
Build/test: recompile stdlib (`cargo run -p move_compiler_tool` over the stdlib sources, or the genesis stdlib build path) to surface any non-friend caller; `cargo build -p node`.
Rationale: link-time enforced, F1-independent. **Do NOT apply the delegation.move arm yet.**

**Step 4 — F1 (keystone). Apply ALL F1 patches in a single commit.**
Files: `core/vm_move/src/lib.rs`, `core/executor/src/lib.rs`, `core/vm_move/src/tests.rs`.
Includes the reviewer-required PublishModule 3-tuple patch (§3, F1, Patch 8b).
Build/test: `cargo build -p vm_move -p executor`; `cargo test -p vm_move` — **gate the merge on at least one passing execution test proving a forged `@0x1` in `args[0]` is overwritten** (the negative/security test). Requires the stdlib-bootstrap test helper (§3, F1, required change #2).
Rationale: per CLAUDE.md rules 8–9 (crypto/executor changes require tests).

**Step 5 — F2 delegation arm (now unblocked by F1).**
Files: `core/vm_move/stdlib/sources/delegation.move` (`EUNAUTHORIZED` const + `public entry` + `assert @0x1`).
Build/test: recompile stdlib; `cargo test -p executor` (add `test_distribute_delegation_rewards_non_system_aborts` **only now** — it assumes F1 semantics and would not abort pre-F1).
Rationale: F1 must be merged and verified first or this is a regression.

**Step 6 — F4. Apply ALL sign + verify + dedup + test edits in a SINGLE commit.**
Files: `core/cli/src/main.rs`, `core/mempool/src/lib.rs`, `core/executor/src/lib.rs`, `core/vm_move/src/lib.rs`, `core/vm_move/src/tests.rs`, `core/node/src/genesis.rs`, `core/cli/src/bin/bench_tps.rs`, `core/cli/src/bin/gen_test_tx.rs`, `core/mempool/src/tests.rs`.
Reconcile with F1: `vm_move::execute_transaction` now carries both F1's logic and F4's new params; the executor verify block and `execute_transaction` must use the **single** 7-field message form.
Build/test: `cargo test -p mempool -p executor -p vm_move` + a node/genesis integration test. **Partial rollout = total tx breakage**, so all sites move together.

**Step 7 — Final workspace gate.**
`cargo build --release`; `cargo test --workspace`; `cargo clippy --workspace -- -D warnings`; manual end-to-end smoke (§4).

---

## 3. Per-Fix Detail

---

### F1 — VM Signer Binding *(keystone)*

**Root cause.** `move-vm-runtime` aptos-v1.3.0 (`runtime.rs::deserialize_args`, lines 229–269) builds every arg — including `Type::Signer` — from raw user bytes via `Value::simple_deserialize`. It does **not** inject signers; the session doc-comment (`session.rs:52–55`) states this is the adapter's responsibility. AINCORE's adapter `core/vm_move/src/lib.rs::execute_transaction_actions` (verified at line 445, tuple `Vec<(MoveAction, bool)>` at line 447) passes `call.args` raw and never binds the signer slot. The executor BCS-decodes the user payload and pushes it raw (`core/executor/src/lib.rs:2051`, verified). Every entry fn takes `&signer` first, so a user encodes `@0x1` into `args[0]` and passes every `assert address_of(s)==@0x1` gate.

**Patches.**

**Patch 1 — `execute_transaction_actions` signature + loop (`core/vm_move/src/lib.rs`, lines 445–490).**
Current tuple shape `Vec<(MoveAction, bool)>` → `Vec<(MoveAction, bool, AccountAddress)>`; destructure `auth_signer` per action; replace the inline `Identifier::new(...).unwrap()` with non-panicking handling; route the entry call through `bind_signer_args`. Apply the spec's `proposed_code` block verbatim (the `CallEntryFunction` arm that loads the ident safely, calls `Self::bind_signer_args(...)`, and on error in non-`must_succeed` records aborted status and `continue`s).

**Patch 2 — new helper `bind_signer_args` (`core/vm_move/src/lib.rs`, above `changeset_to_kv`, line 498).** Insert verbatim. Loads the function instantiation via `session.load_function`, counts leading `Type::Signer` / `Reference(Signer)` / `MutableReference(Signer)` params, errors if `args.len() < signer_count` ("required signer slots"), then overwrites each leading slot with `bcs::to_bytes(&auth_signer)`. `Type` lives at `move_vm_types::loaded_data::runtime_types::Type` (already a dep — no manifest change).

**Patch 3 — `execute_public_entry_function` (`core/vm_move/src/lib.rs`, 421–443).** `pre_actions: Vec<(MoveAction, bool)>` → `Vec<(MoveAction, bool, AccountAddress)>`; rename `_sender` → `auth_signer`; push `(CallEntryFunction{...}, false, auth_signer)` and call `execute_transaction_actions(actions, auth_signer, gas_limit)`.

**Patch 4 — `advance_epoch` call site (`core/executor/src/lib.rs`, ~685–694, verified `advance_epoch` at line 687).**
`execute_transaction_actions(vec![(action, true)], system_address(), 1_000_000)` → `vec![(action, true, system_address())]`.

**Patch 5 — `deposit_fee_reward` (`core/executor/src/lib.rs`, ~853–861, verified line 853).** Trailing `system_address()` is now interpreted as `auth_signer` — no value change, add the clarifying comment.

**Patch 6 — `slash_validator_bps` (`core/executor/src/lib.rs`, ~1449–1457, verified line 1449 with `vm_addr` at 1456).** **BUG FIX:** change the last arg from `vm_addr` → `system_address()`. `slash_validator_bps` asserts `@0x1`; passing `vm_addr` (the validator) was a latent bug that binding now surfaces. `arg_val` (the validator target, built at line 1446) is a plain address arg, untouched by binding.

**Patch 7 — `deduct_gas` pre-action (`core/executor/src/lib.rs`, ~1947–1953, verified push at line 1953).**
`pre_actions.push((gas_action, true))` → `pre_actions.push((gas_action, true, system_address()))`. **Critical:** `deduct_gas` asserts `@0x1` even though the bundling tx's sender is the user — this is why `auth_signer` must be per-action.

**Patch 8a — user EntryFunction arm (`core/executor/src/lib.rs`, lines 2049–2051, verified).**
```rust
// current (line 2051):
actions.push((vm_move::MoveAction::CallEntryFunction(call), false));
// proposed:
actions.push((
    vm_move::MoveAction::CallEntryFunction(call),
    false,
    sender_addr,
));
```

**Patch 8b — user PublishModule arm (`core/executor/src/lib.rs`, line 2080, verified). [REVIEWER-REQUIRED — was missing from spec; without it the code does not compile.]**
```rust
// current (line 2080):
actions.push((vm_move::MoveAction::PublishModule(modules), false));
// proposed:
actions.push((vm_move::MoveAction::PublishModule(modules), false, sender_addr));
```
`auth_signer` is unused for PublishModule but the tuple arity must match.

**New tests (`core/vm_move/src/tests.rs`).** Per reviewer-required change #2, these need a **stdlib-bootstrap test helper** first (the existing tests.rs only has serialization/sig-detection harnesses; `load_stdlib` at `lib.rs:191` is a TODO stub). Add a helper that publishes the precompiled stdlib bytecode (the same `vm_move/stdlib/bytecode` source `core/node/src/genesis.rs` uses) into a test `AINCOREVM`/storage and initializes `CoinStore` for test accounts. Then:
- `test_user_cannot_forge_system_signer` — attacker A, payload `coin::deduct_gas` with `args[0]=bcs(@0x1)`, `auth_signer=A`; assert ABORT (permission_denied). **This is the merge-gating negative test.**
- `test_normal_transfer_uses_real_sender` — `coin::transfer` with `args[0]=bcs(@0x1)` (wrong) and `auth_signer=A`; assert success debiting A, not 0x1.
- `test_gas_deduction_passes_with_system_signer` — `deduct_gas` as pre-action with `auth_signer=system_address()` while call-level sender is a user; assert success.
- `test_bind_signer_args_rejects_too_few_args` — entry fn needing 1 signer, empty args; assert `Err` mentioning "required signer slots". (Reachable only after a successful `load_function`, hence needs the bootstrap helper.)
- `test_bind_noop_when_zero_signers` — function with no leading signer params; assert args unchanged.

**Regression risk.** Honest txs already place the sender in `args[0]`; binding overwrites it with the *same* authenticated address — no change. System pre-actions (`deduct_gas`, `deposit_fee_reward`, `slash_validator_bps`, `advance_epoch`) now carry explicit per-action `auth_signer=system_address()`. The trap a naive fix hits — bundled `deduct_gas` needs `@0x1` while the bundling tx sender is the user — is handled by per-action signers. Removing `Identifier::new().unwrap()` also closes a panic-DoS via crafted function name. Open-question #1 resolved by inspection: this build uses 16-byte `AccountAddress`; `bcs::to_bytes(&address)` emits exactly LENGTH raw bytes == the Signer-slot bytes — length-agnostic and correct.

**Reviewer verdict:** `approve-with-changes`. Closes vuln, no regression. **Required before merge (incorporated above):**
1. ✅ Patch 8b (PublishModule 3-tuple) — added explicitly.
2. ✅ Replace prose tests with runnable tests; add stdlib-bootstrap helper; **gate merge on the passing negative/security test**.
3. ✅ Run `cargo build -p vm_move -p executor` + `cargo test -p vm_move` (CLAUDE.md rules 8–9).

---

### F2 — Move System-Only Mint Gates

**Root cause.** `staking::mint_reward` (verified `public fun` at `staking.move:299`) is over-exposed; `delegation::distribute_delegation_rewards` (verified `public fun` at `delegation.move:338`) has no signer/auth and **zero callers** (verified: only the def site; the 4 `mint_reward` callers are at delegation 130/198/287/358 and universal_mining 215).

**Patches.**

**Patch 1 — friend decls (`staking.move`, after line 5 `use 0x1::coin::{Self, Coin};`).** Insert `friend 0x1::delegation;` and `friend 0x1::universal_mining;`. Mirrors the existing `coin.move` idiom.

**Patch 2 — restrict mint_reward (`staking.move:299`).**
`public fun mint_reward(...)` → `public(friend) fun mint_reward(...)`. Link-time enforced by the Move bytecode verifier; F1-independent. All 4 call sites are inside the two declared friend modules — zero call-site edits.

**Patch 3 — error const (`delegation.move`, after line 18 `ECOMMISSION_CHANGE_TOO_SOON: u64 = 6;`).** Add `const EUNAUTHORIZED: u64 = 7;`.

**Patch 4 — gate distribute_delegation_rewards (`delegation.move:338`).**
```move
public fun distribute_delegation_rewards(
    validator_addr: address,
    total_reward: u128
) acquires ValidatorPool {
```
→
```move
public entry fun distribute_delegation_rewards(
    sys: &signer,
    validator_addr: address,
    total_reward: u128
) acquires ValidatorPool {
    assert!(signer::address_of(sys) == @0x1, error::permission_denied(EUNAUTHORIZED));
```
`signer` and `error` already imported. **This arm must NOT land before F1.**

**New tests (Rust `#[test]` in `core/executor/src/lib.rs`).**
- `test_mint_reward_not_callable_by_user` — EntryFunctionCall to `0x1::staking::mint_reward` from a funded user; assert tx aborts / no state change (non-public, unresolvable as entry).
- `test_distribute_delegation_rewards_non_system_aborts` — **add only after F1.** Non-system originator; assert abort `permission_denied(EUNAUTHORIZED)` (category PERMISSION_DENIED, reason 7), `total_supply` and `accumulated_rewards_per_share` unchanged. Pre-F1 this would NOT abort (forged `@0x1` passes) — do not add it as a red test.
- `test_distribute_delegation_rewards_system_ok` — system path (first arg `bcs(system_address())`, 0x1 signer); assert success and per-share increases.

**Regression risk.** `mint_reward`'s 4 call sites stay compiling under `public(friend)`. `distribute_delegation_rewards` has no callers, so adding a param breaks nothing today. Watch: (a) any non-friend 0x1 module calling `mint_reward` fails compile — grep confirms none; **recompile stdlib to surface any missed caller**; (b) future executor wiring must BCS-encode `system_address()` as the new first arg; (c) marking it `entry` makes it tx-dispatchable — the `@0x1` assert is the only guard, hence the hard F1 dependency.

**Reviewer verdict:** `approve-with-changes`; flags **`introduces_regression: true`** specifically for the merge-order hazard. **Required (incorporated into Apply Order):**
1. ✅ **Gate the delegation.move patch behind F1** (Step 5, after F1 in Step 4).
2. Reviewer's stronger alternative — *delete* `distribute_delegation_rewards` (zero callers) to remove the surface without an F1 dependency. **Decision for maintainer:** this plan ships the spec's gate-with-sys-signer approach but flags deletion as the lower-risk option if the function is confirmed permanently unused. If retained but F1 slips, keep it `public fun` (non-entry, unreachable) until F1 lands.
3. ✅ Do not add `test_distribute_delegation_rewards_non_system_aborts` before F1.
   The `staking.move` `public(friend)` changes are safe to land now (Step 3).

---

### F3 — Governance RPC Auth

**Root cause.** `core/node/src/api_local.rs` handles `aincore_createProposal` (verified line 1027) and `aincore_vote` (verified line 1046) with zero authentication. `aincore_vote` derives vote weight from the *claimed* voter address's on-chain balance (`governance/governance/src/lib.rs:256` via `query_move_vm_balance`) with no key-ownership proof — anyone votes with any whale's full stake.

**Patches.** Replace both arms with unconditional `Err(JsonRpcError{ code: -32040, message: ... })` (apply the spec's `proposed_code` for both). `-32040` mirrors the existing `submit_transaction_with_key` deprecation (verified at line 764). The `aincore_vote` patch also removes the dead duplicate `else`-branch. Governance now flows only via signed tx → `aincore_sendTransaction` → mempool (Ed25519 + `sender==derive_address(pubkey)`) → Move entry fns `0x1::governance::create_proposal` (governance.move:40) / `vote` (governance.move:78). Read-only `aincore_getProposal`/`aincore_tally` untouched.

**New tests (`api_local.rs` test module, AppState pattern at line 2327).**
- `test_aincore_vote_rpc_is_disabled` — assert `Err` code `-32040`, message contains "disabled"/"aincore_sendTransaction".
- `test_aincore_create_proposal_rpc_is_disabled` — assert `Err` code `-32040`.
- `test_aincore_vote_rpc_does_not_mutate_governance` — after the disabled call, assert tally unchanged.

**Regression risk.** Clients calling these RPCs directly get `-32040` (intended). Move entry fns already exist; read-only RPCs unaffected; `GovernanceManager` API intact (still used by executor/Move path + unit tests). No consensus/mempool/sig changes.

**Reviewer verdict:** `approve` — **no required changes.** Non-blocking, pre-existing notes: legacy `GovernanceManager` store remains authoritative for `getProposal`/`tally` reads while writes route through the VM (split-brain risk, tracked in open questions, not introduced here).

---

### F4 — Signature Covers Gas & Input Objects

**Root cause.** The canonical signed message is `"{chain_id}:{sender}:{payload}:{sequence_number}"` at every site and excludes `gas_limit`, `gas_price`, `input_objects`. `canonical_tx_hash` (verified `mempool/src/lib.rs:82`) likewise excludes them. A MITM can mutate gas fields or rewrite `input_objects` and the tx still passes Ed25519/Dilithium verify at mempool, executor, and vm_move.

**Canonical format (byte-identical at ALL sites):**
```
format!("{}:{}:{}:{}:{}:{}:{}", chain_id, sender, payload, sequence_number, gas_limit, gas_price, input_objects.join(","))
```
Rules: `gas_limit` u64 Display, `gas_price` u128 Display (no padding), `input_objects` joined by single `,` no brackets, empty Vec → empty string (trailing `:`). For all current production signers (`input_objects=[]`, `gas_price=1`) the suffix is `":{gas_limit}:1:"`. A free-standing `format!` (not a shared helper) is used because `cli`/`vm_move` cannot reach an executor helper without a dependency cycle.

**Patches (apply ALL in one commit — partial rollout = total breakage):**

| Site | File:loc (verified) | Change |
|------|------|--------|
| CLI SubmitMiningProof | `cli/main.rs:~200` | 7-field, suffix `:5000:1:` |
| CLI Send | `cli/main.rs:~318` | 7-field, `, gas_limit, gas_price, ""` |
| CLI Publish | `cli/main.rs:~424` | 7-field, `:50000:1:` |
| CLI RegisterValidator | `cli/main.rs:~501` | 7-field, `:50000:1:` |
| CLI Faucet | `cli/main.rs:~572` | 7-field, `:50000:1:` |
| `canonical_tx_hash` | `mempool/lib.rs:82` | add `tx.gas_limit, tx.gas_price, tx.input_objects.join(",")` |
| Mempool PQC verify | `mempool/lib.rs:297` | 7-field from `parsed_tx.*` |
| Mempool Ed25519 verify | `mempool/lib.rs:329` | 7-field from `parsed_tx.*` |
| Executor Ed25519 verify | `executor/lib.rs:1767` | 7-field from `tx.*` |
| Executor `signed_tx` helper | `executor/lib.rs:2597` | 7-field, `, gas_limit, gas_price, ""` |
| vm_move `execute_transaction` sig | `vm_move/lib.rs:197` | add params `gas_limit: u64, gas_price: u128, input_objects: &[String]` |
| vm_move Ed25519 verify | `vm_move/lib.rs:283` | 7-field |
| vm_move PQC verify | `vm_move/lib.rs:352` | 7-field |
| vm_move tests call sites/msgs | `vm_move/tests.rs` (~138/143/151/215/218/249) | new arg list `(…, 0u64, 1u128, &[], …)`; 7-field signed msgs |
| genesis `signed_tx` helper | `genesis.rs:966` | 7-field, `, gas_limit, gas_price, ""` |
| bench_tps signing | `bench_tps.rs:~90` | 7-field, **exact suffix `:10000:1:`** (gas_limit 10000, gas_price 1, input_objects []) |
| gen_test_tx signing | `gen_test_tx.rs:~76` | 7-field, **exact suffix `:10000:1:`** |

**[REVIEWER-REQUIRED] `core/mempool/src/tests.rs` — explicit patches (spec listed the file but gave zero edits; without these the entire mempool suite fails verify):** Convert every signing helper to the 7-field form, appending `:{gas_limit}:{gas_price}:{input_objects.join(",")}` matching each helper's emitted JSON (all currently `input_objects:[]`, so suffix `:{gas_limit}:{gas_price}:`):
- line 20 `make_test_tx` (Ed25519)
- line 58 `make_test_tx_with_payload_and_gas` (Ed25519)
- line 376 `sign_pqc_message` (PQC)
- lines 513, 574, 637 (additional helpers)
These updated helpers are the "7-field test signing helper" the new tests depend on.

**New tests (`mempool::tests`, `executor::tests`, `vm_move::tests`).**
- `mutated_gas_price_fails_verification` — valid tx Ok; bump `gas_price` in the signed JSON; assert `Err("Invalid Signature Verification")`.
- `mutated_gas_limit_fails_verification` — same, mutate `gas_limit`.
- `mutated_input_objects_fails_verification` — sign with `[]`, inject `["obj1"]` unsigned; assert `Err`.
- `unmutated_tx_with_objects_and_high_gas_accepts` — non-empty `input_objects` + `gas_price>1`, correctly signed; verifies (guards sign/verify symmetry).
- `executor_rejects_gas_mutated_tx` — `signed_tx()`, mutate gas_price; assert `execute_transaction` returns `None`.
- `vm_move::aa_verify_rejects_gas_mutation` — sign with `gas_price=P`, call with different `gas_price` arg; assert `Ok(false)`.

**Regression risk.** Main risk is partial rollout — any single site left at 4-field breaks every tx through that pair. Mitigated by single-commit all-sites change with the fixed format. `join(",")` is unambiguous for current usage (all production signers use `[]`); a future multi-object tx must ensure object ids never contain `,` (today hex/address strings — safe). vm_move `execute_transaction` signature change is source-breaking but its only in-tree callers are vm_move tests (updated); production executor verifies inline and does not call it.

**Reviewer verdict:** `approve-with-changes`; flags `introduces_regression: true` for the test-helper gap. **Required (incorporated):**
1. ✅ Concrete `mempool/src/tests.rs` helper patches (lines 20, 58, 376, 513, 574, 637).
2. ✅ Define the 7-field test helper (= the updated existing helpers).
3. ✅ Exact `bench_tps.rs`/`gen_test_tx.rs` suffix `:10000:1:` (note: both declare `gas_price` as local `u64`, but Display matches `u128`, so bytes still match).
4. ✅ Single commit; run `cargo test -p mempool -p executor -p vm_move` + node/genesis integration.
5. **Recommended (non-blocking):** reconcile the ZKP proof-binding message (`mempool/lib.rs:170`, `executor/lib.rs:1798`), still 4-field, to the same 7-field form, or document why it stays 4-field. (Vuln still closed: signature now covers gas, and STARK is a placeholder with no constructible valid proofs.)
   **Observation (pre-existing, not introduced):** executor `execute_transaction` accepts only 64-byte sigs (`lib.rs:1753`), so PQC txs are rejected at execution regardless — spec correctly patches only the Ed25519 executor site.

---

### F5 — Short-Frame Panic Guard

**Root cause.** `common/network/src/lib.rs::secure_connect` guards only the upper bound (`msg_len > 10*1024*1024`, verified line 464) then unconditionally slices `enc_msg[0..12]` (verified line 476). A frame with `msg_len ∈ 0..=11` panics with slice-OOB. The server accept loop already guards `msg_len < 12` (verified line 165) and `read_encrypted_msg` is range-guarded (line 627 slice sits behind its own check) — only `secure_connect` was missed. `secure_connect` runs in `ChainSync::sync_from_peers` (`sync/src/lib.rs:344`) in a plain `for` loop inside the 30s periodic task (`core/node/src/main.rs:696`) — a panic permanently kills sync.

**Patches.**

**Patch 1 — `common/network/src/lib.rs`, after line 464 upper-bound guard, before allocation/slice.**
```rust
// A valid encrypted frame is at least a 12-byte nonce. A shorter frame
// (e.g. a truncated or hostile peer reply) would otherwise panic on the
// enc_msg[0..12] slice below and kill the caller's task. Mirror the
// server accept loop (msg_len < 12 -> break) by rejecting it here.
if msg_len < 12 {
    return Err("Welcome message too short".into());
}
```
Uses the identical `Box<dyn std::error::Error + Send + Sync>` `.into()` construction already on line 465. Runs before `enc_msg` allocation and the `[0..12]` slice.

**Patch 2 — `sync/src/lib.rs`, before the `for (peer_id, peer_port)` loop (~line 320).** Comment-only marker documenting the per-peer panic-isolation point. **No behavioral change.**

**New tests (`common/network`).**
- `network_secure_connect_short_welcome_returns_err` — fake server completes the real handshake through step 4, then writes a length-prefixed frame with `msg_len = 5`; assert `secure_connect` returns `Err` (not panic), message contains "too short", and the test completes without unwind.
- `network_secure_connect_zero_len_welcome_returns_err` — `msg_len = 0`; assert `Err`, no panic on empty Vec.
- `network_read_encrypted_msg_short_frame_still_err` — regression lock: `read_encrypted_msg` returns `InvalidData` for `msg_len < 12`.

**Regression risk.** Genuine WELCOME frames from `send_encrypted` are ≥28 bytes (12-byte nonce + ChaCha20-Poly1305 ciphertext + 16-byte tag), comfortably passing `>= 12`. The new branch runs before allocation/slice — cannot affect valid inputs. Error path already handled by both callers (`handshake()` logs; `sync_from_peers` matches `Err`). `sync` change is comment-only.

**Reviewer verdict:** `approve` — **no blocking changes.** **Test-harness caveat (incorporated into §4):** the fake server must sign `server_x25519_pub || client_x25519_pub` **in that exact order**, framed `32+32+64`, or `secure_connect` errors at the signature check (`lib.rs:425–430`) *before* reaching the guard, making the test pass without exercising it. The guard fires before decrypt/identity-check, so a matching `peer_id`/valid WELCOME plaintext is NOT needed. **Non-blocking recommendation:** either implement the documented per-peer isolation (`catch_unwind`/per-peer task + restart guard around `sync_from_peers().await` at `main.rs:696–707`) OR soften the summary's "isolate per-peer sync failures" claim, since the comment-only patch delivers no actual isolation — it only removes *this* panic.

---

## 4. Final Verification Checklist

### Build
```bash
cargo build --release                                          # full workspace
cargo build --release -p node -p vm_move -p executor -p mempool -p network -p sync
cargo clippy --workspace -- -D warnings                        # must be clean (CLAUDE.md)
cargo fmt --all
```
Recompile the Move stdlib after F2 to surface any non-friend `mint_reward` caller and to rebuild the gated `distribute_delegation_rewards`.

### Test per crate
```bash
cargo test -p network     # F5: short/zero-len welcome -> Err, no panic; read_encrypted_msg lock
cargo test -p node        # F3: aincore_vote/createProposal disabled (-32040), no mutation
cargo test -p vm_move     # F1: forged @0x1 overwritten (GATING negative test); normal transfer uses real sender;
                          #     bind rejects too-few-args; noop on zero signers. F4: aa_verify rejects gas mutation
cargo test -p executor    # F1: slash/deduct_gas/deposit_fee_reward via system signer; F2: mint_reward unreachable,
                          #     distribute_delegation_rewards non-system aborts (POST-F1 only) / system ok;
                          #     F4: executor rejects gas-mutated tx
cargo test -p mempool     # F4: mutated gas_price/gas_limit/input_objects fail verify; unmutated objects+high-gas accepts;
                          #     ALL existing helpers migrated to 7-field (no mass failure)
cargo test --workspace    # final gate
```

### Manual end-to-end signed-tx smoke (positive path)
1. Start a node (`cargo run --release -p node`) with a funded account.
2. CLI `send` a native transfer (`cargo run -p cli -- send ...`). Confirm: accepted by mempool, executed, recipient credited, gas deducted from sender.
3. Confirm the signed message is the **7-field** form (F4) and the tx still verifies at mempool *and* executor (independent re-verify).
4. Submit a governance action as a **signed tx** via `aincore_sendTransaction` calling `0x1::governance::vote` — confirm it executes (F3 left the legitimate path intact).

### Forged-@0x1 negative test (attack path must fail)
1. **VM-level (F1):** craft an `EntryFunction` payload for `coin::deduct_gas` with `args[0] = bcs(@0x1)`, authenticated as attacker A. Submit. **Expect: ABORT (permission_denied)** — `bind_signer_args` overwrote the slot with A, so `address_of(sys)==@0x1` fails.
2. **Mint forgery (F2 + F1):** craft a tx to `0x1::staking::mint_reward`. **Expect: rejected** (non-public/non-entry, unresolvable). Craft a tx to `0x1::delegation::distribute_delegation_rewards` with `args[0]=bcs(@0x1)` from a non-system sender. **Expect: ABORT permission_denied(EUNAUTHORIZED)**; `ValidatorSet.total_supply` and pool `accumulated_rewards_per_share` unchanged. (This negative test is only valid **after** F1 is merged.)
3. **Governance spoof (F3):** call `aincore_vote` / `aincore_createProposal` over JSON-RPC with an unsigned/foreign address. **Expect: `Err -32040`**, no tally mutation.
4. **Gas/intent tamper (F4):** take a validly signed tx JSON, bump `gas_price` (or rewrite `input_objects`) without resigning. **Expect: rejected at mempool AND executor** ("Invalid Signature Verification").
5. **Short-frame DoS (F5):** have a peer send a welcome frame with `msg_len < 12`. **Expect: `secure_connect` returns `Err("Welcome message too short")`, the periodic sync task survives** and continues on the next 30s tick.

### Merge-order assertions to re-confirm before each push
- F2 delegation arm and `test_distribute_delegation_rewards_non_system_aborts` land **only after** F1 is merged and the F1 gating negative test passes.
- F4 lands as a **single commit** spanning all sign/verify/dedup/test sites (including the `mempool/src/tests.rs` helper migrations) — never partially.
- F1's PublishModule 3-tuple (Patch 8b) is present, or `core/executor` will not compile.

---

**Relevant files (absolute paths):**
`/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/src/lib.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/src/tests.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/executor/src/lib.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/mempool/src/lib.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/mempool/src/tests.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/cli/src/main.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/cli/src/bin/bench_tps.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/cli/src/bin/gen_test_tx.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/node/src/api_local.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/node/src/genesis.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/node/src/main.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/stdlib/sources/staking.move`, `/Users/macbookpro/Documents/AINCORE-Blockchain/core/vm_move/stdlib/sources/delegation.move`, `/Users/macbookpro/Documents/AINCORE-Blockchain/common/network/src/lib.rs`, `/Users/macbookpro/Documents/AINCORE-Blockchain/sync/src/lib.rs`.