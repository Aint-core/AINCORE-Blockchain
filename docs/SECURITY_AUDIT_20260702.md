# AINCORE Security Audit — 2026-07-02 (HEAD 5f723a7)

## Executive summary

This audit covers the AINCORE L1 blockchain at commit `5f723a7` on branch `audit/mainnet-hardening`, focused on pre-mainnet readiness. Twenty subsystem/dimension finders produced candidate issues; each finding below survived **double independent adversarial verification** (two skeptics both confirmed the issue is real against source).

Severity counts (after de-duplication of shared-root-cause findings):

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 6 |
| MEDIUM   | 6 |
| LOW      | 2 |
| **Total**| **14** |

(The raw finder list contained 15 items; findings #7, #11, and #15 share the single root cause "QC verification never checks `chain_id`" and are merged into one MEDIUM finding covering all three call sites, yielding 14 distinct findings.)

**Overall risk posture: NOT READY for mainnet.** The chain currently has a consensus-safety fork vector reachable on an otherwise-honest network (leader-election beacon divergence), a remote unauthenticated permanent-sync-halt DoS, an unauthenticated DA commitment overwrite, and multiple plaintext/world-readable signing-key exposures. The most urgent issue is the leader-election beacon divergence (H-1), which can fork finalized state with **no Byzantine participant required**. These must be resolved and re-verified before any mainnet launch.

---

## Remediation status (updated 2026-07-02, HEAD 6593423)

All 14 findings were addressed the same day. **12 fully fixed**; **3 mitigated with a tracked residual** (the residual in each case is a larger design change — real delay-VDF, pre-execution block authentication, and full transport auth-gating — noted inline). Full workspace `build`/`test`/`clippy` green after the fixes; consensus 61/0 (incl. a new H-1 regression test); the fixed build was re-verified on the live 3-machine cluster.

| # | Status | Commit | Note |
|---|--------|--------|------|
| H-1 | ✅ FIXED | `6593423` | leader election now seeds from the deterministic `step1_beacon`, not the timing-dependent QC-folded value; + cross-node regression test |
| H-2 | 🟡 MITIGATED | `6593423` | fold-divergence removed; full anti-grinding needs a real delay-VDF (deferred, tracked) |
| H-3 | 🟡 MITIGATED | `d488bc6` | persistent remote-halt DoS removed (no more `sync:halt_reason` latch); full fix = authenticate blocks before execution (deferred, tracked) |
| H-4 | ✅ FIXED | `80962c1` | unauthenticated `BatchAnnouncement` no longer writes/overwrites `da_commitment_{epoch}` |
| H-5 | ✅ FIXED | `28895bd` | PQC privkey written 0600 (+ address widened to 32-byte) |
| H-6 | ✅ FIXED | `28895bd` | `keys import` reads the secret from a no-echo prompt, not a CLI arg |
| M-1 | ✅ FIXED | `1397e2f` | `verify_qc` binds to expected chain_id (sync/api/bridge) |
| M-2 | ✅ FIXED | `d488bc6` | removed manual WAL flush; `write_batch` is a single fsync'd durable write |
| M-3 | 🟡 MITIGATED | `80962c1` | per-connection rate limit + 1 MiB frame cap; full HELLO auth-gate deferred (broadcast `send_message` carries no signing key) |
| M-4 | ✅ FIXED | `80962c1` | genesis enforces MIN_STAKE (1000 AIN); no silent scale-to-0 voting power |
| M-5 | ✅ FIXED | `d488bc6` | `PublishModule` requires a size-proportional gas floor |
| M-6 | ✅ FIXED | `28895bd` | CLI `wallet.key` written 0600 |
| L-1 | ✅ FIXED | `80962c1` | per-IP cap applies to docker-bridge IPs unless `AINCORE_TRUST_DOCKER_BRIDGE=1` |
| L-2 | ✅ FIXED | `1397e2f` | folded into M-1 (chain_id) |
| econ-LOW | ✅ FIXED | `d488bc6` | `get_burn_percentage` clamped ≤100 |

Also from the re-run executor economic audit (the unit that failed on rate-limit in the main run): **no CRITICAL/HIGH economic bug** — fee burn/mint conservation, gas-meter checked arithmetic, MAX_SUPPLY cap, slashing idempotency, and the parallel scheduler are all sound (2 further LOW/informational items: legacy `sys:validators` reward-set vs authoritative `sys:validator_set:v1`, and the epoch-vs-block halving unit).

---

## Findings

### HIGH

---

#### H-1 — Leader-election beacon diverges across nodes; QC-fold timing forks anchor selection
**File:** `consensus/consensus/src/ordering.rs:566` (leader select), `:215-227` (step-1 beacon), `:270-344` (QC fold), `:402`/`:470` (commit); `consensus/consensus/src/dag.rs:1517-1532`; `consensus/consensus/src/qc_producer.rs:198-211`; `core/node/src/main.rs:683-684,729-730`
**Category:** Consensus safety / chain fork

**Description.** `get_leader_with_fallback` (ordering.rs:566-588) elects the anchor-round leader from `self.last_vdf_output`. That field holds one of two values for the same logical chain point: the pure Step-1 base `VDF(anchor_round, finality_digest)` (set by `update_random_beacon`), or that base folded with a complete QC aggregate BLS signature (`fold_qc_for_height` / `mix_qc_into_beacon`). Which value a node holds at the instant of leader selection depends entirely on whether it has already assembled the **complete** quorum certificate for the relevant height.

In a genuine multi-party topology (no validator holds >2/3 stake), `produce_and_store_qc` returns `Partial` for every node at commit time, so no node folds at commit. Each node folds later, independently, as it aggregates a complete QC from inbound `QC_VOTE` gossip via `handle_remote_qc_vote → collect_vote_and_try_aggregate → fold_qc_for_height` — completing at different wall-clock moments purely as a function of network delivery order. Because `handle_message` (QC-vote folding) and `add_vertex` (commit + leader election) share the single `RwLock<DagConsensus>` write lock, the relative order of "fold QC for height H" vs. "commit round R+2 and pick its leader" is decided by arrival timing and is **not** identical across nodes.

The design comment asserts the fold is "timing-independent" because it re-derives from the immutable `step1_beacon`. That guarantees the *final* folded value is identical once folded, but not the beacon value *at the instant of leader selection*: a node that has folded QC_H elects off `VDF(step1_base || agg_sig)` while a node that has not folded elects off `step1_base`. `get_leader_with_fallback` recomputes the leader on every `try_commit` with no per-round lock-in, so the two nodes can pick different stake-weighted leaders for the same anchor round and fork the linearized chain.

**Exploit scenario.** 3 validators, stake 40/40/20 (no >2/3 holder). All commit at height H, each broadcasts a Partial finality vote; none folds. Node A aggregates the complete QC for H and folds its aggregate signature **before** the round-(R+3) vertex that drives `try_commit(R+2)` arrives. Node B receives the round-(R+3) vertex first and runs `try_commit(R+2)` while still on the unfolded base. A's folded `last_vdf_output` and B's unfolded value differ, so `get_leader_with_fallback(R+2)` returns different validator addresses on A vs. B. They commit different anchor vertices for R+2, producing divergent committed sequences / block hashes — a finality-safety violation on an honest network. A Byzantine node can additionally provoke it by timing QC-vote delivery.

**Recommended fix.** Make leader election read a beacon that is a pure function of already-finalized state, independent of local QC-assembly timing. Either (a) only fold a height's QC into the election seed once that height is buried below the commit horizon all honest nodes are guaranteed to have folded before electing that leader, or (b) drop the QC fold from the leader-election seed entirely and elect from the deterministic Step-1 base (already agreed by all nodes at commit time), keeping the QC-folded beacon only for non-consensus randomness. Add a cross-node test: commit several anchors on two engines where one folds a height's QC before the next commit and the other after, asserting identical leader selection every round.

---

#### H-2 — Leader-election beacon is grindable in the unfolded window (fast VDF, difficulty 50)
**File:** `consensus/consensus/src/ordering.rs:536` (step-1 beacon), `:346-352`/`:505` (finality_digest), `:588-605` (leader derive); `common/crypto/src/vdf/mod.rs` (header)
**Category:** Consensus fairness / leader grinding

**Description.** The Step-1 beacon is `VDF(domain || anchor_round || finality_digest)`, where the VDF is a difficulty-50 sequential SHA3 chain the implementation itself documents as providing "determinism, not delay." `finality_digest` is the SHA256 over the entire committed sequence, and that sequence is largely determined by the anchor proposer's chosen vertex content and tx ordering. Because computing the beacon is microsecond-cheap with no wall-clock delay, the anchor proposer at round X can locally enumerate many valid vertex/payload arrangements, recompute `finality_digest → step1_beacon(X) →` the resulting next-round leader, and pick the arrangement that re-elects itself or a colluder. The intended defense is the Step-2 QC aggregate-signature fold — but, per H-1, the next leader is elected off the beacon **before** that QC has necessarily folded, so during the fold-propagation window the grind defense is absent and the proposer-grindable Step-1 base selects the leader.

**Exploit scenario.** A validator that is anchor leader for round X enumerates valid orderings/inclusions of its vertex transactions, computing `step1_beacon(X)` for each (cheap difficulty-50 hash chain), and selects the ordering whose beacon makes itself (or a bribed low-stake colluder) leader for the next anchor round — before the intervening height's >2/3 QC has folded on peers. Repeated across rounds, a minority-stake coalition captures leadership far above its stake share, enabling targeted censorship and MEV, and defeating stake-weighted fairness.

**Recommended fix.** Do not let a single proposer's freely-chosen content determine the next leader off a fast (non-delay) VDF. Bind leader election only to values no single party can grind before election: the multi-party QC aggregate BLS signature of a height already finalized on all nodes (with a fixed finality lag guaranteeing the fold is present everywhere), or a proper delay VDF / drand-style beacon. Until then, treat leader election as biasable by the current proposer.

---

#### H-3 — Forged block with bogus state_root permanently halts a node's sync (remote DoS)
**File:** `sync/src/lib.rs:967-969` (halt write), `:120-133` (verify_execution_roots), `:246-309` (validate_block), `:502-508` (halt gate), `:552`/`:607` (peer iteration); `core/node/src/main.rs:992` (periodic sync); `consensus/blockchain/src/lib.rs` (unauthenticated Block)
**Category:** Denial of service / missing authentication

**Description.** During sync, `process_blocks` re-executes each synced block and compares re-executed roots to the header's declared `state_root`/`receipts_root` in `verify_execution_roots`. On any mismatch it writes a **persistent** `sync:halt_reason` key and breaks; `sync_from_peers` then refuses to sync at all while that key is present — a node-wide, permanent halt requiring manual operator intervention.

The root problem is that AINCORE blocks are **completely unauthenticated**. `Block`/`BlockHeader` carry no proposer signature — only a self-referential header `hash`. `validate_block` performs only structural checks: height, parent-hash chaining (public data), `proposer_id` string membership in the validator set (no signature, so any real validator address can be claimed), `tx_hash` recomputation, a 30s future-timestamp bound, tx-count limit, and `verify_block_hash` (which the attacker satisfies by hashing their own forged header, since `round`/`state_root`/`proposer_id` are attacker-chosen). A forged block passes every check, then re-executes to the correct root, which does not equal the attacker's deliberately-wrong non-empty `state_root`, triggering the permanent halt. The mismatch fires whenever `state_root` is non-empty regardless of the `require_exec_roots` cutover flag, so it works with default config. `sync_from_peers` runs on a ~3s timer on every node type, so even a fully-synced validator can be targeted (advertise a height one above the victim's).

**Exploit scenario.** Attacker joins the gossip-populated peer set as an ordinary peer, connects to victim V, answers `GET_HEIGHT` with `HEIGHT:<V_height+1>`, then answers `SYNC_REQ` with one forged block: prev_hash = V's public tip, proposer_id = a real validator address from the public set, arbitrary transactions with correct `tx_hash`, timestamp = now, `state_root = "00"*32` (non-empty but wrong), header hash computed over the forged header. V's `validate_block` passes, V re-executes and gets a different root, writes `sync:halt_reason` permanently, and can never catch up or reorg until an operator deletes the key. Repeated against all reachable nodes, this stalls network growth and recovery.

**Recommended fix.** Do not treat an execution-root mismatch on a synced block as a global permanent halt — because blocks are unauthenticated, a mismatch is expected adversarial input, not proof of local divergence. Reject that block and blacklist/skip that peer, continuing to the next. Reserve persistent-halt behavior for blocks bound to finality this node already accepts (e.g., a QC-certified block whose re-execution diverges, which genuinely indicates a local binary/state problem). More fundamentally, add a cryptographic authenticator to synced blocks (require the anchor round to be covered by a verifiable QC, or carry the proposer's vertex signature) so forged blocks are rejected before execution.

---

#### H-4 — Unauthenticated DA BatchAnnouncement overwrites the epoch Merkle commitment
**File:** `da/src/lib.rs:1040-1041` (blind put), `:509-591` (authenticated DA_COMMIT path), `:656-702`/`:890-908`/`:1000-1013` (commitment consumers); `da/src/p2p_protocol.rs:23-29` (unsigned struct); `core/node/src/main.rs:738-748` (routing); `core/node/src/api_local.rs:1784-1798,1829-1844` (RPC exposure)
**Category:** Missing authentication / data-availability integrity

**Description.** `handle_p2p_message` dispatches `ShardMessage::BatchAnnouncement { epoch, merkle_root, shard_count, proposer_id }` and unconditionally executes `storage.put("da_commitment_{epoch}", hex::encode(merkle_root))`. Unlike the `DA_COMMIT` path (`handle_incoming_batch`) which verifies the Ed25519 signature over the payload **and** checks `crypto::derive_address(pubkey) == proposer_id`, the `BatchAnnouncement` struct carries no signature and no pubkey, and the handler performs no signature check, no proposer authentication, and no "commitment already exists" guard — it is a blind RocksDB overwrite. The message is reachable from untrusted network input: any inbound `DA_SHARD:` frame is routed straight into `handle_p2p_message`. The encrypted transport authenticates only the connection's node identity, not that the sender is the legitimate batch proposer, so any peer completing the P2P handshake can replace the commitment for an arbitrary epoch. `da_commitment_{epoch}` is the trusted root for (1) DAS verification in `verify_local_availability`/`verify_availability_from_peers`/`DASampler::sample`, (2) the `ShardResponse` accept-and-store gate, and (3) the public RPCs `aincore_sampleDA` and `aincore_getShardProof` returned to light clients as the authoritative `merkle_root`.

**Exploit scenario.** Node N commits epoch E in `create_batch()`, writing true root R_legit and storing honest shards. An attacker peer sends `DA_SHARD:{"BatchAnnouncement":{"epoch":E,"merkle_root":<R_attacker>,"shard_count":32,"proposer_id":"x"}}`. N overwrites `da_commitment_E` with R_attacker. Consequences: (a) `verify_local_availability(E)` rebuilds the true tree from honest shards and verifies proofs against R_attacker — all fail — so N reports its own honest data as UNAVAILABLE, records a bogus MissingData fraud proof, and emits `[SECURITY][DA_UNAVAILABLE]` alerts; done per-epoch network-wide, the DA monitor becomes an attacker-controlled false-alarm generator. (b) `aincore_sampleDA`/`aincore_getShardProof` now serve R_attacker to external light clients, so DAS verifies retrieved shards against a forged root. (c) The `ShardResponse` handler accepts-and-stores attacker shards matching R_attacker, poisoning N's shard store.

**Recommended fix.** Do not derive trust from `BatchAnnouncement`. Either (1) drop the `storage.put` entirely and require the authoritative commitment to come only from the signature-verified `DA_COMMIT` path or the node's own `create_batch`; or (2) add an Ed25519 signature + proposer pubkey to `BatchAnnouncement` and verify it identically to `handle_incoming_batch` (sig over canonical payload, `derive_address(pubkey)==proposer_id`, proposer in validator set), and refuse to overwrite an existing differing `da_commitment_{epoch}` — treating a conflicting signed announcement as equivocation evidence.

---

#### H-5 — PQC (Dilithium5) private key written in plaintext with world-readable permissions
**File:** `core/cli/src/main.rs:162` (`fs::write(&sk_path, sk_bytes)`), `:154` (address derive); cf. `core/node/src/main.rs:239-243` (correct 0600 hardening); `core/vm_move/src/lib.rs:343-351` (PQC sig verification)
**Category:** Key management / secret exposure

**Description.** `Commands::PqcKeygen` writes the raw, unencrypted Dilithium5 secret key to `{out}/pqc_privkey.bin` via `std::fs::write`. Unlike the node key (chmod 0600) and the eth-keystore path (scrypt-encrypted), this file receives the OS default mode (typically 0644, world-readable) with zero encryption. The Dilithium5 keypair is a genuine on-chain signing identity — the mempool recognizes 9254-hex PQC signatures and `vm_move` verifies Dilithium5 signatures for transaction authorization — and its derived address is a spendable account.

**Exploit scenario.** An operator runs `aincore-cli pqc-keygen --out /home/user/pqc_keys` on a shared/multi-tenant host. `pqc_privkey.bin` lands at mode 0644. Any other local user or a compromised low-privilege service reads the raw secret with `cat`, reconstructs the Dilithium5 signing key, derives the same address, and signs transactions to drain the victim's AIN balance. No password, decryption, or privilege escalation needed.

**Recommended fix.** Encrypt the PQC secret at rest (route through `keystore::KeyManager` / eth-keystore with a password prompt like the Ed25519 keys), and on Unix set the file to 0600 via `OpenOptions().mode(0o600)` / `PermissionsExt` before writing, mirroring `core/node/src/main.rs:239-243`. Never persist an unencrypted signing key.

---

#### H-6 — Private key passed as CLI argument in `keys import` leaks via process args and shell history
**File:** `core/cli/src/main.rs:113-116` (`--priv-key <PRIV_KEY>` clap arg); `core/cli/src/keys.rs:36-53`
**Category:** Key management / secret exposure

**Description.** `KeysSubcommand::Import` takes the raw private key as a clap argument `--priv-key <PRIV_KEY>`. Command-line arguments are visible to every user on the host via `ps aux`, `/proc/<pid>/cmdline`, and process-accounting/audit logs for the process's entire lifetime (which includes an interactive `rpassword` prompt — potentially seconds to minutes). The value is also written verbatim to shell history (`~/.bash_history`, `~/.zsh_history`) and to `sudo`/`auditd`/multiplexer scrollback logs.

**Exploit scenario.** An operator runs `aincore-cli keys import --priv-key <64-hex-secret> --out ./keys`. While the process waits at the password prompt, a co-tenant or monitoring agent runs `ps -eo args | grep aincore-cli` (or reads `/proc/<pid>/cmdline`) and captures the full private key. Even after exit, the secret persists in shell history readable by anyone who later gains that account. The attacker imports the same key elsewhere and steals the funds — defeating the entire point of encrypting the keystore, since the plaintext was exposed before encryption.

**Recommended fix.** Do not accept private keys via CLI args. Read the secret from a no-echo interactive prompt (`rpassword`, as already used for the password) or from a file path / stdin, and zeroize after use. If a flag is kept for scripting, require a file path (`--priv-key-file`) rather than the inline secret.

---

### MEDIUM

---

#### M-1 — QC verification never checks `chain_id`, enabling cross-chain finality-proof replay (sync, RPC, and bridge)
**File:** `consensus/consensus/src/qc.rs:211-281` (`verify_qc`, no chain_id check), `:43`/`:60-66` (chain_id signed but unenforced), `:158-162`/`:258-264` (validator_set_hash binding); `sync/src/lib.rs:388` and `:380-389`/`:803-809` (`apply_finality_artifact`/`fetch_verified_tip`); `depin/bridge-rust/src/aincore_client.rs:91` and `:61-151` (`qc_response_confirms`); `core/node/src/api.rs:247-314`; `common/crypto/src/bls/mod.rs:24` (fixed DST)
**Category:** Cryptographic domain separation / cross-chain replay
**Note:** Merged root cause covering the three finder items originally reported at qc.rs:211 (MEDIUM), aincore_client.rs:91 (MEDIUM), and sync/src/lib.rs:388 (LOW).

**Description.** `FinalityVote` carries `chain_id` and includes it in the BCS signing bytes, so validators *do* sign over the chain id. But `verify_qc` never compares `qc.chain_id` against the verifier's expected chain id, and none of the consumers do either — sync (`apply_finality_artifact`/`fetch_verified_tip`), the RPC handlers (`aincore_getQuorumCertificate`/`aincore_verifyQuorumCertificate`), and the bridge gate (`qc_response_confirms`) all resolve a validator set purely by `qc.epoch` and call `verify_qc` with no chain_id equality check. The BLS domain-separation tag `DST_CONSENSUS` is a fixed constant with no chain id mixed in, so signatures are not chain-bound at the crypto layer either. The only thing preventing a QC minted on chain A from verifying on chain B is the `validator_set_hash` binding — derived only from `(address, stake, ed25519_pk, bls_pk, bls_pop)` — which is identical across two chains that share a validator set. So a chain relaunch reusing keys, a staging/fork chain run by the same operators, or any two AINCORE deployments sharing the genesis validator set will accept each other's QCs.

**Exploit scenario.** Operators run mainnet (`AINCORE-MAINNET-1`) and a staging chain (`AINCORE-STAGING-1`) with the same genesis validator set (same addresses, stakes, BLS keys) — a common cost-saving setup and the exact post-relaunch situation when `node.key` is preserved (the branch's own test vector at qc.rs:382-396 shows key preservation across a reset). On staging, validators legitimately produce a valid >2/3 QC for staging block height=1000, hash=X (e.g. a large bridge-withdrawal event intended only on staging). An attacker controlling the bridge's RPC feed serves that staging QC to the mainnet bridge for height=1000; `qc_response_confirms` resolves the identical set/hash, `verify_qc` passes (real >2/3 aggregate, correct set hash), chain_id is never checked, and the bridge treats the staging block as finalized mainnet — releasing funds against a withdrawal that never happened on mainnet. The same replay can poison a mainnet node's `consensus:finalized_round` via `apply_finality_artifact` where a same-height block-hash collision exists locally (block-hash binding limits, but does not eliminate, the sync surface).

**Recommended fix.** Bind the QC to the verifier's chain: thread the expected chain_id (from `AINCORE_CHAIN_ID` / operator config) into `verify_qc` and reject on mismatch, so every consumer inherits the check. Additionally mix the chain_id into the consensus BLS DST (`DST = base || chain_id`) so cross-chain signatures cannot pair-verify at the crypto layer. Have sync/api/bridge each assert `qc.chain_id` equals their configured chain id before acting.

---

#### M-2 — RocksDB durability config is inert: `set_use_fsync(true)` never fsyncs on writes; silent data-loss window under `manual_wal_flush`
**File:** `common/storage/src/lib.rs:72` (`set_use_fsync`), and `manual_wal_flush`, `:98-100` (`put`), `:115-117` (`delete`), `:279-280` (`write_batch`), `:289` (`flush`), `:54-72` (misleading comment); consumers: `consensus/consensus/src/dag.rs:1336-1343`; `core/executor/src/lib.rs:861,1079,1205,1230,1869,1881`
**Category:** Durability / crash-consistency (state-root divergence)

**Description.** `open()` sets `set_use_fsync(true)` and `set_manual_wal_flush(true)` with a comment claiming per-write fsync durability. The claim is false. `set_use_fsync` only selects fsync-vs-fdatasync *when a sync is requested*; it does not force any write to sync. Neither `put()` nor `delete()` nor `write_batch`'s internal `self.db.write(batch)` ever set `WriteOptions.sync=true` — all use `WriteOptions::default()` (sync=false). Worse, under `set_manual_wal_flush(true)`, a plain `put()`/`delete()` does not even push its WAL record to the OS — it stays in RocksDB's in-process WAL buffer until an explicit `flush_wal()`. The only things that actually persist are `flush_wal(true)`, called inside `write_batch()` and `flush()`. Consequences: (1) every `db.put(...)` not followed by a `write_batch()`/`flush` before a crash is silently lost despite returning Ok — including the equivocation slash record and jail marker written via `storage.put()` in dag.rs:1336-1343 and numerous executor puts for `sys:total_supply`, validator-set updates, tombstones, and fee-sweep entries. (2) `write_batch()` does `db.write(batch)` then `db.flush_wal(true)` as two steps; a kill between them loses an already-acknowledged batch (neither memtable nor buffered WAL survives).

**Exploit scenario.** A validator commits block N: `execute_block_parallel` writes the state root via `write_batch` (WAL flushed), then `deposit_fee_reward` writes each affected CoinStore via `db.put` (lib.rs:1205), which under manual WAL flush only lands in the WAL buffer. If the node is power-cycled after the reward puts return Ok but before `save_block_json`'s `flush_wal` completes, the memtable and buffered WAL are gone: on restart the node loads `latest_height`/`state_root` from the last durably-flushed batch but the "committed" reward mutations are absent, producing a world-state disagreeing with peers that did flush. Because Move state feeds the next state_root, divergence compounds and the node forks off canonical. The equivocation-slash path is more exposed still: dag.rs:1336 writes `sys:pending_slash` via `put()` with no following batch, so a crash before the next commit silently drops the pending slash despite Ok.

**Recommended fix.** Do not rely on `set_use_fsync` for per-write durability. Either (a) remove `set_manual_wal_flush(true)` and set per-write `WriteOptions` with sync/WAL enabled on the durability-critical path, or (b) keep manual WAL flush but make the storage API explicit — route `put()`/`delete()` through `WriteOptions` that keep WAL enabled and ensure every logical commit ends with `flush_wal(true)`. Fix `write_batch()` to issue the batch with `WriteOptions.sync=true` (single fsync'd write) rather than write-then-flush as two racy steps. Correct the misleading doc comment at lib.rs:54-72.

---

#### M-3 — TCP transport processes application messages without requiring a completed authenticated handshake
**File:** `common/network/src/lib.rs:333` (else-branch dispatch), `:190` (shared_key), `:194+` (loop), `:234-332` (HELLO verify), `:112` (per-IP cap exemption); `core/node/src/main.rs:729` (write-lock guard)
**Category:** Authentication / denial of service

**Description.** In `start_server`, the encrypted session becomes usable the instant the ephemeral DH completes. The message loop dispatches every frame, but only `HELLO:` frames run Ed25519 identity verification; all other message types fall into the else branch and are handed straight to `handler_clone(msg)` with no check that the peer ever sent a valid HELLO. There is no per-connection `authenticated` flag. A client can perform the DH, read the server hello, skip HELLO entirely, and immediately send `DAG_VERTEX:`, `QC_VOTE:`, `TX:`, `SYNC_REQ:`, `GET_FINALITY`, or `DA_COMMIT:` — each is processed. This is not a fork/theft bug (every downstream consumer independently re-verifies cryptographic authenticity), but it is an unauthenticated resource/DoS surface: any host reaching the TCP port can drive the consensus write lock and storage writes without any validator identity, and the TCP path has no per-message rate limiting (unlike the gossipsub 100 msg/s cap) and allows 10 MiB frames (vs gossipsub's 1 MiB).

**Exploit scenario.** An attacker opens N connections (up to the per-IP cap of 60, or unlimited by source-spoofing a 172.16-31.x docker-bridge IP exempt from the cap at lib.rs:112). On each, it completes the DH, never sends HELLO, then streams valid-format `DAG_VERTEX`/`QC_VOTE`/`SYNC_REQ` frames at line rate (each up to 10 MiB, no rate limit). Every frame acquires the global consensus write lock and triggers signature-verification work plus RocksDB reads, starving `try_create_vertex` mining and degrading liveness — an unauthenticated CPU/lock-contention DoS that attributes to no slashable identity.

**Recommended fix.** Track a per-connection `authenticated: bool` set only after the HELLO signature verifies, and drop any non-HELLO message until it is true. Add per-connection message-rate limiting to the TCP loop equivalent to the gossipsub cap, and align the TCP max frame size (10 MiB) with gossipsub's 1 MiB.

---

#### M-4 — Genesis accepts sub-1-AIN validator stake that silently scales to 0 voting power
**File:** `core/node/src/genesis.rs:803` (`if stake == 0`), `:224-233` (`scale_stake_to_whole_ain`), `:888-893` (incorrect B4 comment), `:896` (`.max(1)` on legacy mirror only); `consensus/consensus/src/dag.rs:1868`; `consensus/consensus/src/qc.rs:190-192,229-251`
**Category:** Consensus liveness / governance integrity

**Description.** The genesis validator loop rejects only a stake of exactly 0 quanta. Any stake in 1..10^18 quanta (any positive amount below 1 whole AIN) passes and is converted for `sys:validator_set:v1` via `scale_stake_to_whole_ain`, which does integer division `stake_quanta / 10^18` and thus yields whole-AIN stake 0 for every sub-1-AIN validator. `sys:validator_set:v1` is the authoritative source read by both the DAG quorum path (`read_validators_from_storage`) and QC verification (which recomputes total/signed stake from `ValidatorInfo.stake` and requires strict >2/3). A validator persisted with whole-AIN stake 0 contributes 0 to both signed and total stake — zero voting power, never leader-weighted — despite being fully registered. If every genesis validator is sub-1-AIN, `total_stake` is 0 and `stake_quorum_met(signed, 0)` (`signed*3 > 0*2`) is always false, so no QC can ever assemble and the chain never finalizes (permanent liveness halt). The `.max(1)` floor is applied only to the legacy `sys:validators` mirror, not the authoritative set. The B4 comment is wrong on both counts: the floor is not on the authoritative set, and genesis performs no MIN_STAKE check (the 1000-AIN minimum is enforced only by the Move staking module for runtime joins, which genesis bypasses by writing state directly).

**Exploit scenario.** A genesis-ceremony operator (or a mis-generated `genesis.json`) sets a validator with stake below 1 AIN (e.g. `"stake": "500000000000000000"` = 0.5 AIN, or a typo dropping 18 zeros). Genesis init succeeds silently and writes `sys:validator_set:v1` entries with whole-AIN stake 0. On boot, QC verification computes total_stake=0 (if all validators are sub-1-AIN) and the strict-2/3 predicate can never be met — finality never attaches and the chain halts permanently; or (mixed stakes) sub-1-AIN validators are silently stripped of all voting power while appearing healthy — a decentralization integrity failure invisible until finality behaviour is analyzed.

**Recommended fix.** In the genesis validator loop, reject any validator whose stake scales to 0 whole-AIN (enforce the real MIN_STAKE, e.g. `stake < 1000 * 10^18`), matching the Move staking module, and add an explicit check that the sum of whole-AIN stakes across all genesis validators is > 0. Correct the B4 comment, or apply the same minimum semantics consistently to `sys:validator_set:v1` rather than only the legacy mirror.

---

#### M-5 — Move module publishing is entirely unmetered — cheap DoS via costly bytecode verification
**File:** `core/vm_move/src/lib.rs:426` and `:414-431` (`publish_modules`), `:484-486` (`PublishModule` arm); `core/executor/src/lib.rs:2313,2401-2410` (flat upfront gas), `:2535`/`:2583` (`_gas_used` ignored); `core/mempool/src/lib.rs:299` (no publish validation), `:169` (100KB cap); pinned move-vm `runtime.rs:70` (`_gas_meter` unused)
**Category:** Denial of service / gas metering

**Description.** Both `publish_modules` and the `MoveAction::PublishModule` arm call `session.publish_module_bundle(modules, sender, &mut gas_meter)`. In the pinned move-vm, that gas-meter parameter is prefixed `_` and never used: module deserialization and full bytecode verification (`verify_module_bundle_for_publication`, plus dependency/cyclic checks) run with zero gas charged. `AINCOREGasMeter` meters only execution opcodes, none of which fire during a publish. Separately, the executor charges gas as a flat upfront `gas_limit * gas_price` and ignores the VM's returned `gas_used`, so a tiny `gas_limit` does not make a publish run out of gas. The mempool applies no publish-specific validation (`PublishModule(_) => {}`) and only the generic 100KB TX cap bounds module size. Net: an attacker submits ~100KB of adversarially-crafted Move bytecode with a near-minimal `gas_limit`, paying a near-minimum fee while forcing every validator to run superlinear verification each block.

**Exploit scenario.** Attacker crafts a 100KB module bundle maximizing verifier cost (many functions, deep type/borrow-graph complexity, many cross-module dependencies), wraps it as `PublishModule`, sets `gas_limit` just above the metered `deduct_gas` pre-action cost with `gas_price=1`. It passes mempool (only the 100KB cap and `gas_limit>0` apply). During block execution `publish_module_bundle` deserializes and verifies the whole bundle with zero metered gas, never aborting on gas. Repeated each block from many accounts, every validator burns CPU on verification for a trivial fee — chain-halt-grade DoS at scale with no proportional economic cost.

**Recommended fix.** Charge gas proportional to submitted module bundle size and count *before* dispatch (in the executor prior to `execute_transaction_actions`, or by charging the gas meter for total module bytes and per module verified), reject publishes whose declared `gas_limit` is below a size-derived floor, and add a per-tx module byte/count sublimit in the mempool for `PublishModule` payloads far tighter than the generic 100KB cap.

---

#### M-6 — CLI plaintext `wallet.key` written without restricting file permissions
**File:** `core/cli/src/wallet.rs:51` (`fs::write(path, hex::encode(...))`); cf. `core/node/src/main.rs:239-243` (correct 0600 hardening)
**Category:** Key management / secret exposure

**Description.** `Wallet::load_or_create`, when auto-creating the wallet (guarded by `AINCORE_ALLOW_PLAINTEXT_WALLET`), writes the hex-encoded Ed25519 secret key via `fs::write(path, hex::encode(wallet.key_pair.to_bytes()))` with the OS default mode (typically 0644, world-readable). The node process explicitly hardens the equivalent `node.key` to 0600, but the CLI wallet — which holds the user's spending key and signs every Transfer/Faucet/RegisterValidator tx — does not. The plaintext secret is left world-readable.

**Exploit scenario.** A developer/operator sets `AINCORE_ALLOW_PLAINTEXT_WALLET=1` and runs any CLI command; `wallet.key` is created at mode 0644 in the working directory. On a shared host, another local user reads the hex secret, reconstructs the `SigningKey`, and signs transactions draining the victim's funds. The asymmetry with the node's own 0600 hardening shows the omission is unintentional.

**Recommended fix.** On Unix, create the file with `OpenOptions().write(true).create(true).mode(0o600)` or call `set_permissions(path, Permissions::from_mode(0o600))` immediately after write, matching `core/node/src/main.rs:239-243`.

---

### LOW

---

#### L-1 — Docker-bridge source IPs are fully exempt from the per-IP inbound connection cap
**File:** `common/network/src/lib.rs:112` (`if !is_docker_bridge_ip(peer_ip)`), `:100` (refusal), global `MAX_CONNECTIONS`
**Category:** Sybil/eclipse mitigation weakening

**Description.** `start_server` enforces a per-IP concurrent inbound connection cap (default 60) but wraps the whole check in `if !is_docker_bridge_ip(peer_ip)`. Any source IP in 172.16.0.0/12 bypasses the per-IP cap entirely, bounded only by the global `MAX_CONNECTIONS` (100). The stated rationale (many containers egress one bridge gateway) is applied unconditionally, not gated behind a deployment flag. On a node where an attacker can originate or spoof traffic from a 172.16-31.x address (shared docker host, co-tenant container, or on-link attacker forging source IPs since no return-path handshake authenticates the accept), the entire per-IP anti-Sybil control is void.

**Exploit scenario.** A malicious container co-located on the same docker host (or an attacker sourcing packets from 172.16-31.x on the segment) opens ~99 inbound TCP sessions from a single 172.x address. The per-IP cap never triggers, so global `MAX_CONNECTIONS` is reached from one origin. Honest peers are refused, reducing peer diversity toward the attacker — an eclipse/Sybil precursor and connection-slot DoS.

**Recommended fix.** Gate the docker-bridge exemption behind an explicit opt-in env flag (e.g. `AINCORE_TRUST_DOCKER_BRIDGE=1`) intended only for single-host compose deployments, defaulting to applying the per-IP cap to all IPs. Alternatively apply a separate, tunable higher cap for bridge IPs rather than exempting them completely.

---

#### L-2 — (folded into M-1)
The finder item at `sync/src/lib.rs:388` ("finality QC applied during sync without checking `qc.chain_id`") is the same root cause as M-1 and is covered there; its sync-specific call site (`apply_finality_artifact` at sync/src/lib.rs:388, and `fetch_verified_tip`) and the block-hash-binding mitigation that reduces (but does not eliminate) its exploitability are documented in M-1's file list and fix.

---

## Methodology

**Scope.** AINCORE L1 monorepo at commit `5f723a7`, branch `audit/mainnet-hardening`, targeting pre-mainnet readiness.

**Finder fan-out.** Twenty subsystem/dimension finders were run across the workspace, spanning: consensus DAG (`dag.rs`), consensus ordering/leader-election (`ordering.rs`), quorum certificates (`qc.rs`, `qc_producer.rs`), sync (`sync/`), data availability (`da/`), node P2P/transport (`common/network`, `core/node/p2p.rs`, `main.rs`), node genesis (`core/node/src/genesis.rs`), Move VM (`core/vm_move`), executor (`core/executor`), mempool (`core/mempool`), storage/durability (`common/storage`), keystore/CLI (`core/cli`, `common/keystore`), and the EVM/BTC bridges (`depin/`).

**Double adversarial verification.** Every candidate finding was independently re-examined by two skeptics against the actual source (not against the finder's prose). A finding is included in this report **only if both verifiers confirmed** it is real and exploitable as described; each finding carries a dual verdict of the form `<confidence>/<severity>`. Findings that failed either verifier were dropped.

**De-duplication.** Findings sharing a single root cause across multiple call sites were merged: the three separately-reported `chain_id`-unchecked items (qc.rs, bridge `aincore_client.rs`, sync `lib.rs`) are consolidated into **M-1** with all locations enumerated. This yields 14 distinct findings from 15 raw finder items.

**Line-reference discipline.** File:line references were spot-checked against the working tree at HEAD `5f723a7` (e.g. `ordering.rs:566`, `sync/src/lib.rs:967-969`, `da/src/lib.rs:1040-1041`, `core/cli/src/main.rs:162`, `common/storage/src/lib.rs:72`) and confirmed to point at the described code.

**Constraint.** No findings were introduced beyond the verified finder list. Severity labels reflect the verifiers' consensus severity, not the finder's initial tag.
