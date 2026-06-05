All facts verified. The reviews are accurate on every flagged point. I now have everything needed to produce the auditable plan.

```markdown
# Tier-A MEDIUM Remediation Plan — Adversarial-Reviewed
Branch base: `audit/p0-security-fixes` · 4 fixes (M1, M2, M3, M4) · Date: 2026-06-05

All four reviews returned **approve-with-changes**. M2 and M4 carry **blocking** required-changes
(test regression / functional regression) that MUST be incorporated before apply. Every code anchor
below was re-verified byte-exact against the working tree.

---

## SAFE APPLY ORDER

| Step | Fix | File(s) | Why this order |
|------|-----|---------|----------------|
| 1 | **M1** | `core/node/src/api_local.rs` | M1 & M2 both edit `api_local.rs`. Apply M1 first (top-of-file import + server wiring; touches lines 1, ~2224, ~2244, 2264 — server region). |
| 2 | **M2** | `core/node/src/api_local.rs` | Apply after M1. M2 touches the faucet region (~438–540) + tests (~2316–2380) — **disjoint line ranges from M1**, so no merge conflict. Sequential because same file. |
| 3 | **M3** | `consensus/consensus/src/ordering.rs`, `consensus/consensus/src/dag.rs` | Independent of api_local.rs. Apply `ordering.rs` (adds `finalized_round` field) **before** `dag.rs` (consumes `engine.finalized_round`) so the crate never has a transient missing-field state in a single commit. |
| 4 | **M4** | `da/src/lib.rs` | Fully independent crate (`da`). Order vs M1–M3 irrelevant. **Do NOT ship standalone where DA propagation is depended upon** — see M4 blocking note. |

Rationale for sequential M1→M2: actix `App::new()` builder region (M1) and the faucet fn/test region (M2)
do not overlap, but both are in one file; apply and re-`cargo check -p node` between them.

---

## M1 — RPC rate-limit + loopback bind (`M1-rpc-ratelimit-bind`)

### Root cause
Live actix server is `api_local.rs::start_api_server` (confirmed: `main.rs:26 use api_local as api;`).
Its `App::new()` wraps **only** `.wrap(cors)` — no Governor, no rate limit — and binds hardcoded
`("0.0.0.0", api_port)` at line 2264. The fully-configured `GovernorConfigBuilder` lives only in the
**dead** `api.rs` (reachable via `lib.rs`, never by the binary). Net: live RPC is remotely reachable and
unthrottled. `actix-governor = "0.4"` already in `core/node/Cargo.toml` → no Cargo change.

### Patches (file: `core/node/src/api_local.rs`)

**P1 — imports, line 1**
```rust
// current:
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
// proposed:
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
```

**P2 — after `app_state` (between line 2224 `});` and the `// gunakan tokio…` comment)**
```rust
// insert after the app_state web::Data::new({...}); block:
    // Rate limiter: 100 req/s per IP, burst 200. Mirrors the (previously dead)
    // config in api.rs so the LIVE server is throttled.
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(100)
        .burst_size(200)
        .finish()
        .expect("governor config is valid");

    // Bind host: loopback by default; operators opt into a wider interface
    // (e.g. 0.0.0.0) explicitly via AINCORE_RPC_BIND.
    let bind_host = std::env::var("AINCORE_RPC_BIND")
        .unwrap_or_else(|_| "127.0.0.1".to_string());
    println!(
        "🔒 RPC bind host: {} (override with AINCORE_RPC_BIND), rate limit: 100 req/s burst 200",
        bind_host
    );
```

**P3 — `App::new()` builder, line 2244–2245**
```rust
// current:
                App::new()
                    .wrap(cors)
                    .app_data(app_state.clone())
// proposed:
                App::new()
                    .wrap(cors)
                    .wrap(Governor::new(&governor_conf))
                    .app_data(app_state.clone())
```

**P4 — bind call, line 2264**
```rust
// current:
            .bind(("0.0.0.0", api_port))?
// proposed:
            .bind((bind_host.as_str(), api_port))?
```

### Tests
- **Build-level (required, sufficient):** `cargo build --release -p node` + `cargo clippy -p node -- -D warnings`. Proves the import/config/`.wrap`/`.bind` compile against actix-governor 0.4.1.
- **Reviewer-mandated correction to the spec:** the spec's `new_tests` describes a `resolve_bind_host()` unit test, but **no patch hunk adds that helper** — the env expression is inlined. **DROP the `resolve_bind_host` test claim** (recommended, least churn) OR add a real hunk extracting `fn resolve_bind_host() -> String` + a `#[cfg(test)]` test serialized with `faucet_env_lock()`. As written the two contradict; do not leave both.

### Regression risk — Medium-low
1. **Bind default `0.0.0.0`→`127.0.0.1`** breaks remote RPC clients until they set `AINCORE_RPC_BIND=0.0.0.0`. Intended hardening — **must be in release notes / runbook**.
2. Rate limit 100 req/s burst 200 per-IP could throttle a busy single-IP client (indexer/load test); parity with api.rs values.
3. Governor keys on **socket peer IP** (`PeerIpKeyExtractor`), not `X-Forwarded-For` — behind a reverse proxy all clients collapse to one IP and may be over-throttled. Same limitation as api.rs; no new risk.
4. No consensus/executor/mempool/state paths touched.

### Reviewer verdict: **approve-with-changes** (no code-correctness changes)
Required (non-blocking): (1) reconcile the `resolve_bind_host` test claim with the inlined code (drop it or add the helper); (2) add `AINCORE_RPC_BIND` to the CLAUDE.md env table and call out the bind default change in release notes.

---

## M2 — Faucet mainnet hard-gate (`M2-faucet-gate`)

### Root cause
`credit_testnet_faucet` (line 444) and `credit_testnet_wbtc` (line ~526) write balances **directly** into
Move CoinStore RocksDB keys, bypassing executor, mempool, supply accounting, and `BLOCK_EXECUTION_LOCK`.
Only gate is `faucet_enabled()` (env `AINCORE_ENABLE_FAUCET`). No chain-awareness → a single mis-set flag
on mainnet = unlimited mint + state-root race + supply desync.

### Patches (file: `core/node/src/api_local.rs`)

**P1 — insert above `fn faucet_enabled()` (line 438)**
```rust
/// Canonical mainnet chain id. Mirrors mempool + genesis defaults.
const MAINNET_CHAIN_ID: &str = "AINCORE-MAINNET-1";

fn resolve_chain_id() -> String {
    std::env::var("AINCORE_CHAIN_ID").unwrap_or_else(|_| MAINNET_CHAIN_ID.to_string())
}

/// Hard safety gate for ALL direct-write faucet/test-mint paths. Fail-closed:
/// unset chain_id => mainnet => refused, EVEN IF AINCORE_ENABLE_FAUCET is set.
fn faucet_chain_guard() -> Result<(), JsonRpcError> {
    let chain_id = resolve_chain_id();
    if chain_id == MAINNET_CHAIN_ID {
        eprintln!(
            "[SECURITY] Faucet/test-mint RPC refused: chain_id={} is mainnet. \
             Direct-write faucet is permanently disabled on mainnet regardless of \
             AINCORE_ENABLE_FAUCET. Set AINCORE_CHAIN_ID to a testnet id to use it.",
            chain_id
        );
        return Err(JsonRpcError {
            code: -32041,
            message: "Faucet permanently disabled on mainnet (AINCORE-MAINNET-1).".into(),
        });
    }
    Ok(())
}
```
> **Reviewer-mandated change:** spec used `-32040`, but `-32040` is ALREADY in use at api_local.rs:764/1035/1048 (verified) and asserted by a test at line 2635. **Use `-32041`** (verified unused) so mainnet refusal is distinguishable, and correct the spec's false "unused" rationale. Update both faucet asserts below to `-32041`.

**P2 — top of `credit_testnet_faucet` body (before `if !faucet_enabled()`)**
```rust
    public_key_hex: Option<&str>,
) -> Result<serde_json::Value, JsonRpcError> {
    faucet_chain_guard()?;          // mainnet refusal FIRST
    if !faucet_enabled() {
```

**P3 — top of `credit_testnet_wbtc` body (before `if !faucet_enabled()`)** — identical `faucet_chain_guard()?;` insertion.

**P4 — `test_faucet_creates_account_and_credits_move_coinstore` (line 2326), set testnet id + cleanup**
```rust
        std::env::set_var("AINCORE_ENABLE_FAUCET", "1");
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-TESTNET-1");   // add
        ...
        std::env::remove_var("AINCORE_ENABLE_FAUCET");
        std::env::remove_var("AINCORE_CHAIN_ID");                     // add
```

**P5 — new test (append after P4 test)**
```rust
    #[test]
    fn test_faucet_refused_on_mainnet_even_when_enabled() {
        let _guard = faucet_env_lock().lock().unwrap();
        std::env::set_var("AINCORE_ENABLE_FAUCET", "1");
        std::env::set_var("AINCORE_CHAIN_ID", "AINCORE-MAINNET-1");
        let db = temp_db("mainnet_refused");
        let signing_key = SigningKey::from_bytes(&[34u8; 32]);
        let public_key = hex::encode(signing_key.verifying_key().as_bytes());
        let address = crypto::derive_address(signing_key.verifying_key().as_bytes()).unwrap();

        let err = credit_testnet_faucet(&db, &address, 1, Some(&public_key))
            .expect_err("faucet must refuse on mainnet even when enabled");
        assert_eq!(err.code, -32041);
        assert_eq!(move_balance(&db, &address), "0");   // nothing written

        let err = credit_testnet_wbtc(&db, &address, 1, Some(&public_key))
            .expect_err("wbtc mint must refuse on mainnet even when enabled");
        assert_eq!(err.code, -32041);

        std::env::remove_var("AINCORE_ENABLE_FAUCET");
        std::env::remove_var("AINCORE_CHAIN_ID");
    }
```

**P6 — `test_coin_balance_endpoint_reads_ain_and_synthetic_wbtc_coinstores` (line 2368)**: add `set_var("AINCORE_CHAIN_ID","AINCORE-TESTNET-1")` + matching `remove_var`.

**P7 (BLOCKING — added per review) — fix the two negative-path tests the spec broke:**
- `test_faucet_disabled_by_default` (line 2316): currently asserts `-32030`. Without a chain id it now hits the guard → `-32041` → test FAILS. **Add** `std::env::set_var("AINCORE_CHAIN_ID","AINCORE-TESTNET-1")` at top and `remove_var` at end so it keeps asserting `-32030`.
- `test_faucet_rejects_public_key_address_mismatch` (line 2348): asserts `-32602`; same fix so the guard does not pre-empt it.

### Tests
New: `test_faucet_refused_on_mainnet_even_when_enabled`. Updated: 4 existing faucet tests (P4, P6, P7×2). All serialize on `faucet_env_lock()` → env mutation is race-safe. Run: `cargo test -p node`.

### Regression risk — Low (prod), Medium (test suite)
Guard is fail-closed. Default chain_id = mainnet means **every faucet test not setting `AINCORE_CHAIN_ID` now hits the guard first** — P4/P6/P7 cover all of them. Without P7 the suite breaks (violates CLAUDE.md rule 9).

### Reviewer verdict: **approve-with-changes** (introduces_regression: true)
**Required (blocking):** add P7 (fix `test_faucet_disabled_by_default` + `test_faucet_rejects_public_key_address_mismatch`). **Required (correctness of rationale):** switch `-32040`→`-32041` (the spec's "unused" claim is false). Then `cargo test -p node` must pass.

---

## M3 — Bounded committed_rounds + monotonic finality (`M3-committed-rounds`)

### Root cause
`OrderingEngine.committed_rounds: HashSet<u64>` is unbounded, fully JSON-serialized to
`consensus:committed_rounds` every commit (O(n) growing write). `dag.rs:969` derives the prune watermark
from `committed_rounds.iter().min()` — permanently pinned to the **earliest** committed round → `prune_dag`
targets a fixed ancient round → DAG pruning is a **permanent no-op**, unbounded memory/disk growth.

### Patches

**File `consensus/consensus/src/ordering.rs`**

P1 — struct (lines 14–23): add `pub finalized_round: u64` field (documented as monotonic high-water) and add module const after the struct:
```rust
const COMMITTED_ROUNDS_WINDOW: u64 = 256;
```
P2 — `new()` (lines 36–42): add `finalized_round: 0,` to the struct literal.
P3 — `new_with_storage()` load (lines 49–74): derive `finalized_round = rounds.iter().copied().max().unwrap_or(0)`, retain only `>= finalized_round.saturating_sub(COMMITTED_ROUNDS_WINDOW)` into the set, then prefer an explicit persisted `consensus:finalized_round` via `.max(persisted)`; add `finalized_round,` to the literal. (Backward-compatible: legacy huge `Vec<u64>` is read, max kept, set trimmed.)
P4 — `try_commit` de-dup guard (~lines 127–130):
```rust
        let anchor_round = current_round - 2;
        if self.committed_rounds.contains(&anchor_round)
            || (self.finalized_round > 0 && anchor_round <= self.finalized_round)
        {
            return None;
        }
```
P5 — `try_commit` state update + persist (~lines 222–245): after `insert(anchor_round)`, add
```rust
        self.finalized_round = self.finalized_round.max(anchor_round);
        let cutoff = self.finalized_round.saturating_sub(COMMITTED_ROUNDS_WINDOW);
        if cutoff > 0 {
            self.committed_rounds.retain(|r| *r >= cutoff);
        }
```
and change the persisted finalized_round source from `committed_rounds.iter().max()` to
`&self.finalized_round.to_string()`.

**File `consensus/consensus/src/dag.rs`** — prune watermark (lines 966–985):
```rust
                if self.latest_block_height.is_multiple_of(10) && self.current_round > 50 {
                    let finalized_round = {
                        if let Ok(engine) = self.ordering_engine.lock() {
                            engine.finalized_round
                        } else {
                            0 // don't prune if we can't verify finality
                        }
                    };
                    if finalized_round > 10 {
                        self.prune_dag(finalized_round - 10);   // advances every commit
                    }
                }
```
(replaces the `committed_rounds.iter().min()` block; `prune_dag(&self, min_round: u64)` signature unchanged.)

### Tests (BLOCKING per review — must be concrete compiling Rust, not prose)
1. `committed_rounds_stays_bounded_and_watermark_advances` — loop rounds 2..5000 replicating insert + `finalized_round.max` + `retain(>=cutoff)`; assert `committed_rounds.len() <= COMMITTED_ROUNDS_WINDOW + 1`, `finalized_round` monotonic, **and** an explicit assertion that an aged-out round (e.g. 2) satisfies `2 <= finalized_round` so the guard would still reject it.
2. `finalized_round_restored_from_legacy_unbounded_data` — write legacy `consensus:committed_rounds` = `0..10000` (no `consensus:finalized_round`), call `new_with_storage`, assert `finalized_round == 9999` and `committed_rounds.len() <= 257`. **`StateDB` only exposes `StateDB::open(path)`** — add a temp-dir helper inside `ordering.rs::tests` (mirror `get_test_db_path` in `consensus/consensus/src/tests.rs`) with cleanup; the existing helper is not in scope in this module.

Run: `cargo test -p consensus`.

### Regression risk — Low-to-moderate (consensus finality bookkeeping only)
- Anti-double-commit invariant **preserved and strengthened**: guard rejects both windowed rounds and any `round <= finalized_round`. Sound because anchors commit in non-decreasing order (`anchor = current_round - 2`, `current_round` monotonic).
- Genesis edge: `finalized_round == 0` explicitly guarded so first anchor (≥2) is not spuriously rejected.
- Pruning now actually runs (reclaims `< finalized_round - 10`); 10-round buffer + `current_round > 50` keep margin; `prune_dag` body unchanged.
- **Reviewer note (out of M3 scope, not a regression):** `sync/src/lib.rs::apply_finality_artifact` persists `consensus:finalized_round` but never updates the live in-memory `OrderingEngine.finalized_round`; a sync-advanced running node's prune watermark won't reflect synced finality until restart (the new boot loader picks it up on restart — improvement). Worth a follow-up note.
- **Open question for consensus reviewer:** confirm no legitimate path commits anchors out of round order (view-change/partition recovery). Only affects rounds older than the 256-round window, which are causally settled.

### Reviewer verdict: **approve-with-changes** (no source changes; six hunks byte-exact and compile)
**Required:** deliver both tests as concrete compiling code (add the temp-DB helper to `ordering.rs::tests`; add the aged-out-round assertion to test 1).

---

## M4 — DA proposer authorization + identity binding (`M4-da-proposer-auth`)

### Root cause
`da/src/lib.rs`: (1) `create_batch` sets `proposer_id = self.node_id` (node-key address) but
`proposer_pubkey = self.signage_key` (a **separate** DA key); receiver computes
`expected_id = hex::encode(&pubkey_bytes)[0..32]` (line 516 — first 32 hex chars of the 64-hex DA pubkey)
and compares to `proposer_id` — two unrelated values, so the check is **vacuous**. (2) `handle_incoming_batch`
verifies the signature but **never checks `sys:validators`** — any Ed25519 key authors accepted batches.

### Patches (file: `da/src/lib.rs`)

**P1 — `create_batch` payload (lines 264–271):** derive `proposer_id` from the signing key:
```rust
        let proposer_pubkey_bytes = self.signage_key.verifying_key().to_bytes();
        let proposer_id = match crypto::derive_address(&proposer_pubkey_bytes) {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("❌ [DA Sequencer] Failed to derive proposer address (epoch {}): {} — skipping batch.", self.epoch, e);
                return;
            }
        };
        let payload = DABatchPayload {
            epoch: self.epoch,
            root_hash: root_hash.clone(),
            tx_count,
            proposer_id,
            proposer_pubkey: hex::encode(proposer_pubkey_bytes),
            timestamp: Utc::now().timestamp(),
        };
```

**P2 — `handle_incoming_batch` identity block (lines 514–523):** replace prefix compare with canonical derivation + authorization gate:
```rust
                                let expected_id = match crypto::derive_address(&pubkey_bytes) {
                                    Ok(addr) => addr,
                                    Err(_) => {
                                        eprintln!("🚨 [DA] Cannot derive proposer address for batch epoch {}", payload.epoch);
                                        return;
                                    }
                                };
                                if expected_id != payload.proposer_id {
                                    eprintln!("🚨 [DA] Identity mismatch for batch epoch {}", payload.epoch);
                                    return;
                                }
                                if !self.is_authorized_proposer(&expected_id) {
                                    eprintln!("🚨 [DA] Unauthorized proposer {} (not in validator set) for batch epoch {}", expected_id, payload.epoch);
                                    return;
                                }
```

**P3 — new helper before `pub fn handle_incoming_batch` (line 493). REVIEWER-MANDATED: mirror BOTH dag.rs paths (fast `sys:validators` + slow BCS `0x1::staking::ValidatorSet`), not fast-path only:**
```rust
    /// Returns true iff `addr` is in the current validator set. Mirrors
    /// consensus/dag.rs::read_validators_from_storage: fast path (sys:validators
    /// JSON Vec<(String,u64)>) AND slow path (BCS ValidatorSet resource).
    /// Fail-closed: missing/unparseable set authorizes no proposer.
    fn is_authorized_proposer(&self, addr: &str) -> bool {
        // FAST PATH
        if let Ok(Some(json)) = self.storage.get("sys:validators") {
            if let Ok(vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                return vals.iter().any(|(v_addr, _stake)| v_addr == addr);
            }
        }
        // SLOW PATH: BCS ValidatorSet resource (must import/define ValidatorSet
        // in the da crate, matching the type dag.rs decodes; see required-change).
        let key = "resource_0000000000000000000000000000000000000000000000000000000000000001_0x1::staking::ValidatorSet";
        if let Ok(Some(bytes_hex)) = self.storage.get(key) {
            if let Ok(bytes) = hex::decode(bytes_hex) {
                if let Ok(val_set) = bcs::from_bytes::<ValidatorSet>(&bytes) {
                    return val_set.validators.iter()
                        .any(|v| v.validator_addr.to_string() == addr);
                }
            }
        }
        false
    }
```

### Tests (file `da/src/lib.rs`, existing `#[cfg(test)]` mod at line 758)
`m4_da_batch_rejected_from_non_validator_accepted_from_validator`. **REVIEWER-MANDATED test fix:** `create_batch` returns `()` — the batch cannot be obtained via `serde_json::to_string(&batch)`. Read the produced `DABatch` back from storage (`da_root_{epoch}`) or the in-memory cache **before** clearing it; account for the side-effecting shard/commitment/meta writes + peer broadcast `create_batch` performs. Assertions: (a) empty `sys:validators` → batch NOT persisted; (b) after writing `sys:validators` containing `crypto::derive_address(seq.signage_key.verifying_key().to_bytes())` → persisted, and `derived == batch.payload.proposer_id`; (c) a clone with `proposer_id` overwritten to an arbitrary 32-hex value is rejected even when that value is inserted into `sys:validators`. Run: `cargo test -p da m4_da_batch`.

### Regression risk — MEDIUM (functional, introduces_regression: true)
**BLOCKING:** `self.signage_key` (from `load_or_generate_signing_key`) is **independent** of node identity, so `derive_address(DA pubkey) != validator address in sys:validators`. After this patch **every honest validator's DA batch is rejected** until a companion change lands. Blast radius limited: DA is **off** the live block/finality path (`handle_incoming_batch` reached only via `DA_COMMIT:` P2P, does not gate consensus/executor/state), so DA rejection cannot stall block production — but DA propagation is fully broken if depended upon. Legacy `proposer_pubkey.is_empty()` branch (lines 535–540) untouched. Fail-closed read on missing `sys:validators` is the safe direction, consistent with dag.rs strict no-fallback.

### Reviewer verdict: **approve-with-changes** (introduces_regression: true)
**Required (blocking) before relying on DA propagation:**
1. Land a companion key change: derive the DA signing key from node identity (`HKDF(node_identity, "da-signing-v1")` in `load_or_generate_signing_key`) so `derive_address(DA pubkey) == validator address` already in `sys:validators` (option A, smallest surface) **OR** register each validator's DA-derived address.
2. `is_authorized_proposer` must mirror dag.rs's **slow path** (BCS `0x1::staking::ValidatorSet`) in addition to the fast path — incorporated in P3 above; requires importing/defining the `ValidatorSet` type in the `da` crate to match what dag.rs decodes.
3. Fix the test to read the `DABatch` back from storage/cache (since `create_batch` returns `()`); keep all three assertions.

---

## FINAL VERIFICATION CHECKLIST

Run in apply order; each step must pass before the next.

```bash
# After M1, then M2 (same crate, run between each apply):
cargo build --release -p node
cargo clippy -p node -- -D warnings
cargo test -p node            # incl. faucet tests: refused-on-mainnet, disabled-by-default (-32030),
                              # pubkey-mismatch (-32602), success paths (testnet chain id)

# After M3 (ordering.rs then dag.rs):
cargo build --release -p consensus
cargo clippy -p consensus -- -D warnings
cargo test -p consensus       # incl. committed_rounds_stays_bounded_and_watermark_advances,
                              # finalized_round_restored_from_legacy_unbounded_data

# After M4:
cargo build --release -p da
cargo clippy -p da -- -D warnings
cargo test -p da m4_da_batch
cargo test -p da              # full crate

# Workspace gate before PR (CLAUDE.md rules 8/9 + clippy -D warnings):
cargo build --release
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo fmt --all --check
```

### Pre-merge documentation / sign-off
- [ ] Add `AINCORE_RPC_BIND` to the env-var table in `CLAUDE.md`.
- [ ] Release notes: M1 bind default `0.0.0.0`→`127.0.0.1` (remote RPC clients break until they opt in).
- [ ] M4: confirm companion DA-key derivation (option A/B) is landed OR explicitly note DA propagation is disabled pending it.
- [ ] M3: consensus reviewer confirms no out-of-order anchor commit path beyond the 256-round window.
- [ ] No push to `main` (rule 7); PR from `audit/p0-security-fixes`. `genesis.json` / `wallet.key` untouched (rules 1–2).
```

**Files involved (absolute):**
- `/Users/macbookpro/Documents/AINCORE-Blockchain/core/node/src/api_local.rs` (M1 + M2)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/consensus/consensus/src/ordering.rs` (M3)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/consensus/consensus/src/dag.rs` (M3)
- `/Users/macbookpro/Documents/AINCORE-Blockchain/da/src/lib.rs` (M4)

**Two blocking deviations from the supplied specs, verified against the tree and incorporated above:**
1. **M2:** error code must be `-32041`, not `-32040` (`-32040` already used at `api_local.rs:764/1035/1048`, asserted at line 2635); and tests `test_faucet_disabled_by_default` (2316) + `test_faucet_rejects_public_key_address_mismatch` (2348) must set `AINCORE_CHAIN_ID=AINCORE-TESTNET-1` or they regress to `-32041`.
2. **M4:** `is_authorized_proposer` must include the BCS slow path (dag.rs `read_validators_from_storage` has both fast + slow, confirmed at `dag.rs:1438-1466`), and the companion DA-key-from-node-identity change must land before DA propagation is relied upon, else all honest batches are rejected.