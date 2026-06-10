# AINCORE — Path to Production-Grade L1

*Chief Protocol Architect's Verdict — synthesized from 11 grounded per-layer gap analyses (consensus, execution/VM, state/storage, sync/networking, checkpoints/finality, mempool, data-availability, crypto/key-mgmt, economics/staking, ops/observability), each cross-checked against the actual code and the Sui/Aptos/CometBFT standards.*

## 0. Fact-Check Status

This document is a **fact-checked draft**, not a final production-readiness certificate.

Codex re-checked the highest-risk claims against the current branch on 2026-06-10. The core thesis holds: AINCORE lacks a portable quorum certificate / quorum-signed finality object, lacks authenticated state proofs, and lacks validator-set reconfiguration into the live consensus committee.

Corrections from the re-check:

- `aincore_getTransaction` over JSON-RPC is **not** an O(n) 1000-block scan anymore. It uses `tx_index:{tx_hash} -> block_height` in `core/node/src/api.rs` and `core/node/src/api_local.rs`. A legacy REST helper (`get_transaction_handler`) and `aincore_getBlockByHash` still scan the last 1000 blocks.
- The live NAS DB bloat diagnosis is now known: `dag:checkpoint:` dominated the DB, while `block_{height}` was only ~42MB for ~309k blocks. That is runtime evidence, not inferred from observer DB size.
- Checkpoint signatures must distinguish **branch code** from **deployed runtime**. Current branch code saves signed checkpoints; the live NAS runtime inspected on 2026-06-10 was built before the latest storage/checkpoint patches, and its DB had no `dag:checkpoint_sig:` entries.
- Governance vote weight is locked at vote time. The proposal records a snapshot height, but the current Rust vote path reads live balance at vote time rather than replaying the proposal snapshot. The remaining risk is snapshot-semantics / flash-borrow-at-vote-time, not post-vote balance mutation.

External standards referenced here were spot-checked against official/current sources: Sui checkpoint verification, Aptos Block-STM execution, Aptos/Jellyfish Merkle Tree lineage, and Aptos validator/BFT documentation. This document should still be treated as an engineering roadmap, not an external audit certificate.

---

## 1. Executive Verdict

**AINCORE today is an advanced, security-conscious *testnet-grade prototype* — roughly "early single-operator devnet that has done its first security-hardening pass" — not a near-production L1.**

Be precise about *why*, because the honest picture is more flattering than a naive read and more damning than the marketing:

- **The code quality and security hygiene are genuinely above the prototype norm.** The grounding passes repeatedly confirmed real, correct, audited-style fixes: strict 2/3 BFT quorum enforced on both DAG-construction and commit sides, equivocation→100% slash, hash re-verification on every recovery path, a *correct* blst BLS12-381 engine, canonical dedup that closes JSON-reencoding replay, fsync/WAL-hardened RocksDB, finality-aware reorg protection that refuses to rewrite below the finalized boundary, encrypted DA keys at rest, and the H1 delegated-stake-slashing fix. This is not vaporware; the hard cryptographic and durability primitives are present and tested.

- **But the chain is missing the load-bearing properties that *define* a production L1**, and the same failure mode recurs across **eight independent layers**: *the system computes the right things locally but never produces a portable, quorum-attested proof of anything.*

The single most damning cross-cutting finding: **there is no quorum certificate anywhere in the system.** The same root gap surfaces independently in consensus (`ordering.rs:227-246` counts votes in local memory), checkpoints (single-node Ed25519-signed), blocks (`BlockHeader` has no signature field), and DA (single-proposer attestation). `Vertex.aggregated_signature` is hardcoded `None` at all 7 construction sites; the correct BLS engine is dead code w.r.t. consensus. **Consequence: no light clients, no trust-minimized bridges, no fast sync, no IBC — every node must full-replay the entire chain to be sure of state.** A chain whose own CLAUDE.md lists BTC/EVM bridges as goals cannot currently support a single trust-minimized bridge.

Three more properties that gate the word "mainnet" are entirely absent:

1. **The validator set is frozen at genesis** (economics gap #1, critical) — `sys:validators` is written once at genesis and only ever mutated by slashing. On-chain `join_validator_set` never enters the consensus committee. *A PoS chain that cannot rotate validators after launch is not a PoS chain in the operational sense.*
2. **No on-chain protocol-upgrade mechanism** (ops gap #1, critical) — `protocol_version` is a hardcoded literal `1`. Any consensus/executor/VM bugfix after launch is an uncoordinated hard fork that splits the network.
3. **State is not authenticated** (storage gap #1, critical) — `state_root` is a chained delta-hash, not a Merkle commitment over the state set; no inclusion proofs are possible.

**Class verdict: testnet-grade prototype.** It can run a multi-node devnet under honest, static, low-contention conditions and survive a single-node restart. It cannot yet safely (a) onboard/rotate validators, (b) be upgraded without a fork, (c) serve a light client or bridge, (d) sustain throughput under contention, or (e) be operated on-call. Those are not polish items; they are the definition of production. **Realistic distance: a focused, well-staffed effort is measured in quarters, not weeks — the P0 set below is ~5 x-large/large workstreams.**

---

## 2. Strengths — Where AINCORE Is Already At-Par

Credit where the grounding passes confirmed it against code. These are real and should not be re-litigated.

| Area | What's genuinely at-par | Evidence |
|---|---|---|
| **BFT quorum correctness** | Strict `(n*2/3)+1` enforced on *both* DAG-construction and commit sides, with unit tests pinning the math | `dag.rs:43-51`, `ordering.rs:126-134,404-412` |
| **Equivocation handling** | The one provable Byzantine fault (same author+round+different hash) → 100% slash + permanent jail, correct reason string | `dag.rs:735-769` |
| **BLS12-381 primitive** | Correct blst MinPk (Eth2 scheme), real pairing verify, subgroup checks, RFC 9380 DST, aggregate/fast-aggregate-verify. The hard part is done well | `common/crypto/src/bls/mod.rs:108-291` |
| **Tx dedup identity** | Canonical hash over signed form (not raw JSON) closes reencoding replay across all entry points — same property Aptos relies on | `mempool/src/lib.rs:82-98` |
| **Mempool crypto gate** | Full Ed25519 + Dilithium5 PQC verify with `sender==derive_address(pk)` binding; Script payloads rejected; cheapest-reject ordering | `mempool/src/lib.rs:197-369` |
| **Storage durability** | fsync-on-write, manual WAL flush, paranoid checksums, atomic block-commit WriteBatch (body+height+hash+tx-index) | `common/storage/src/lib.rs:54-90,285-319` |
| **Execution determinism** | `BLOCK_EXECUTION_LOCK` + sort-by-tx-hash before commit + sorted WriteBatch → order-independent state root; H2 sender canonicalization closes a real balance-corruption bug | `executor/src/lib.rs:12,950,1052,1596` |
| **Sync safety** | Full continuity + state_root *and* receipts_root verification by re-execution; finality-aware reorg protection refusing rollback below finalized boundary | `sync/src/lib.rs:67-87,535-546` |
| **Transport security** | Mutually-authenticated ECDH with explicit MitM check (`node_id == derive_address(peer_pk)`); FD-exhaustion timeouts with regression tests | `network/src/lib.rs:511-536,719-767` |
| **DA building blocks** | Working Reed-Solomon (16+16), Merkle proofs, consistent-hash sharding, DAS sampler, encrypted DA key at rest (ChaCha20-Poly1305) | `da/src/erasure.rs, merkle.rs, lib.rs:25-258` |
| **Staking correctness (post-audit)** | Delegated-stake slashing cuts active + unbonding-queue from escrow (closes undelegate-before-double-sign bypass); F1-style reward accounting; hard MAX_SUPPLY cap at every mint site | `delegation.move:404-487`, `staking.move:265-315` |
| **Governance runtime (corrected by grounding)** | The *Rust* `GovernanceManager` (not the minimal `.move` stub) has a real timelock, Active→Queued→Executed lifecycle, voting-period end_time, and recorded snapshot height | `governance/governance/src/lib.rs:95-98,344-371` |

**Notable "already has it" wins that early L1s often lack:** finality-aware reorg protection; tx_index with idempotent backfill migration; pruning with archive/full/observer modes; signed DAG checkpoints with verify-on-load; per-block object caps (DoS bound); loopback-only RPC default + rate limiting. The governance grounding correction matters: two claimed governance gaps were **largely hallucinated** — AINCORE's real governance runtime is more mature than the Move stub suggests.

---

## 3. Confirmed Gaps — Sorted by Severity

Only gaps the grounding pass marked **real-gap** or **partially-implemented** are included. Already-implemented items are dropped.

### CRITICAL (blocks mainnet)

| Sev | Layer | Gap | Why it matters | Sui/Aptos approach | Effort |
|---|---|---|---|---|---|
| 🔴 Crit | Consensus | **No quorum/commit certificate** — commit = local in-memory vote count (`ordering.rs:227-246`); `aggregated_signature` always `None` | Finality is neither portable nor attributable. No light client/bridge can verify finality; no fraud proof for a conflicting commit | Aptos Jolteon BLS QC+CC over 2f+1 votes; Sui Narwhal cert; CometBFT Commit | x-large |
| 🔴 Crit | Checkpoints | **Checkpoints single-node-signed**, not quorum/BLS — signer and verifier are the *same* node's key (`dag.rs:1026-1034`) | No trustless interop primitive at all; no fraud-proof anchor | Sui certified CheckpointSummary (>2/3 BLS); Aptos LedgerInfoWithSignatures | large |
| 🔴 Crit | Checkpoints | **Block headers carry no validator signatures/QC** — `BlockHeader` (`blockchain/lib.rs:5-19`) is unauthenticated; sync "verifies" only by full re-execution | A light client/bridge/wallet cannot exist without running a full node | Quorum signature on the canonical finality object + Merkle proof | large |
| 🔴 Crit | Checkpoints | **No epoch / validator-set-transition object, no waypoint** — "epoch" is only a slashing window `current_round/50` (`dag.rs:504-505`) | No trustless cold-start; trust cannot roll forward across validator churn | Aptos Waypoint→EpochChangeProof chain; Sui chain-of-committees; CometBFT NextValidatorsHash | large |
| 🔴 Crit | State | **State is not authenticated** — `state_root` = `SHA256(prev_root‖SHA256(deltas))` (`executor/lib.rs:1080-1091`), not a Merkle root over state; no proof API | No light clients, no state-proof RPC, no trust-minimized bridges; new nodes must full-replay | Aptos Jellyfish Merkle Tree (versioned sparse); Cosmos IAVL+; Sui ECMH accumulator | x-large |
| 🔴 Crit | Economics | **Post-genesis validator rotation non-functional** — `sys:validators` written once at genesis, only mutated by slashing; `join_validator_set` never enters the committee (`genesis.rs:625-631`, `main.rs:714-719`) | The chain cannot decentralize or rotate validators — the defining property of a PoS L1. Staking module is cosmetic for consensus | Aptos `on_new_epoch` reconfiguration; Sui `validator_set::advance_epoch`; CometBFT EndBlock ValidatorUpdates | large |
| 🔴 Crit | DA | **DA commitment not bound into block header** — `BlockHeader` has no `da_root`; DA epoch is a separate counter; `create_batch` runs post-hash (`dag.rs:961`) | DA is unverifiable advisory metadata; data behind a block can be swapped without changing the block hash | Sui embeds tx+effects digests in quorum-signed checkpoint; Celestia commits NMT roots in header | medium |
| 🔴 Crit | DA | **No quorum availability certificate** — single Ed25519 signer (`da/lib.rs:294`), peers accept on one signature | The central DA-withholding attack is unmitigated | Aptos Quorum Store PoS (2f+1); EigenDA aggregated attestation; Sui >2/3 checkpoint sigs | large |
| 🔴 Crit | Ops | **No on-chain protocol-upgrade mechanism** — `protocol_version` hardcoded `1` (`api_local.rs:2199`); no feature flags/readiness signaling | Any consensus/executor/VM change post-launch is an uncoordinated hard fork → chain split | Sui ProtocolConfig flags flipped at epoch on >2/3 signaling; Aptos governance + reconfiguration | x-large |

### HIGH (blocks production-like / incentivized testnet)

| Sev | Layer | Gap | Why it matters | Sui/Aptos approach | Effort |
|---|---|---|---|---|---|
| 🟠 High | Consensus | **No leader reputation/liveness scoring** — leader = `(round+vdf+attempt) mod n` (`ordering.rs:308-338`); crashed leader → no commit that round | ~f/n of anchor rounds stall under faults, inflating finality latency exactly under stress | Shoal/Shoal++ reputation; Sui HammerHead (2x latency, +40% throughput) | large |
| 🟠 High | Consensus | **Single proposer per round** (not a populated Narwhal DAG) — one self-authored vertex, opportunistic parents (`dag.rs:331-340`) | Weak censorship resistance; throughput can't scale by decoupling dissemination | Narwhal/Quorum Store certified dissemination; Mysticeti parallel proposers | x-large |
| 🟠 High | Consensus | **Commit safety from local round_index membership**, not a certified vote set (`ordering.rs:225-246`); no lock/unlock or proof-of-fork | Honest nodes with partial views can diverge with no attributable evidence | CometBFT PoLC/proof-of-fork; DAG-BFT certified-block commit | large |
| 🟠 High | Execution | **No optimistic STM/MVCC** — pessimistic barrier batching flushes whole batch on one conflict (`executor/lib.rs:998-1035`); all staking txs share `validator_set_key` | Effective parallelism →1x under any hotspot; execution becomes the throughput bottleneck | Aptos Block-STM (160k+ TPS, graceful contention); Sui object-ownership parallelism | x-large |
| 🟠 High | Execution | **Full gas limit charged every tx** — `actual_gas = gas_limit*gas_price`; VM's real `_gas_used` discarded everywhere (`executor/lib.rs:2070`) | Massive overcharge; perverse incentive to underset limit; broken fee market | Aptos/Sui charge `gas_used` only, refund the rest | medium |
| 🟠 High | State | **No state snapshots / fast state-sync** — joining nodes full-replay from genesis (`sync/lib.rs:597-608`) | Bootstrap grows linearly with chain age → days/weeks at scale; high barrier to running a node | Sui formal snapshots→S3/GCS; Cosmos state-sync; Aptos fast-sync | large |
| 🟠 High | Sync | **No apply-outputs / fast-sync** — every synced block re-executed (`sync/lib.rs:597-604`) | Catch-up is CPU-bound → "sync falls further behind" under load | Aptos ApplyTransactionOutputs / intelligent mode / fast-sync | large |
| 🟠 High | Sync | **Block/finality propagation poll-only (30s)** — only `DAG_VERTEX` gossiped; no committed-block/finality announce (`main.rs:728-739`) | Up to 30s fullnode lag; slow reconvergence after partition | Sui checkpoint-availability gossip; Aptos data-streaming service | medium |
| 🟠 High | Sync | **No GossipSub v1.1 peer scoring** — only a fixed 100 msg/s limiter (`p2p.rs:112-129`) | Eclipse/sybil/mesh-abuse exposure; eclipsing a validator can stall liveness | Sui/Eth beacon enable P1–P6 scoring + graylist | medium |
| 🟠 High | Mempool | **No mempool gossip** — API submit inserts locally only; no `TX:` publisher exists (`api_local.rs:791`, `main.rs:475`) | A tx reaches the network only if the receiving node wins a proposal; non-proposing nodes add zero capacity; no censorship resistance | Aptos shared mempool gossip; CometBFT flood; Sui client-broadcast | large |
| 🟠 High | Mempool | **No tx TTL/expiry** — no age eviction; no expiration field (`mempool/lib.rs:416`) | Stale txs re-proposed forever; cap fills with dead txs | Aptos system_ttl + client expiration; CometBFT ttl-num-blocks | medium |
| 🟠 High | Mempool | **No fee-market/priority ordering** — strict FIFO `pop_front` (`mempool/lib.rs:419-425`) | No graceful load-shedding; trivially spammable by cheap txs | Aptos gas-price buckets; Eth tip priority | medium |
| 🟠 High | Mempool | **No sequence-gap handling/future-tx buffering** — only duplicate-(sender,seq) reject (`mempool/lib.rs:389`) | Burst pipelines (n,n+1,n+2) burn block slots on guaranteed-fail txs | Aptos parking_lot + next-seq selection | medium |
| 🟠 High | DA | **Proposer authorization not enforced against validator set** — only self-consistency checked (`da/lib.rs:498-523`) | Any node can fabricate a signed DABatch for any epoch; honest peers persist it | Aptos/Sui accept only current-committee signatures | small–medium |
| 🟠 High | DA | **Erasure-shard dispersal dead in production** — `update_validators` only called in tests; node stores full blob locally (`da/lib.rs:386`) | "Sharded, 3x-replicated DA" is inoperative; lose proposer → lose data | Celestia/EigenDA disperse + per-chunk signatures | medium |
| 🟠 High | DA | **DAS not wired for light clients** — `DASampler`/`LightClient` zero live callers; 0.75 threshold decoupled from confidence (`sampling.rs:82-85`) | Light clients can't verify availability; DA reduces to honest-majority trust | Celestia DAS with NMT proofs | large |
| 🟠 High | DA | **No bad-encoding fraud proof / dispute / slashing flow** — `InvalidErasure`/`MissingData` stubs `return true`; verifier RPC-only (`fraud_proofs.rs:102-110`) | Malicious encoding can't be challenged on-chain; DA requires honest majority | Celestia bad-encoding fraud proofs; EigenDA KZG validity | x-large |
| 🟠 High | Crypto | **Consensus QC uses N individual Ed25519 sigs, not BLS aggregation** — `aggregated_signature` always None | O(n) verify/bandwidth; no succinct finality proof; the good BLS engine yields zero production value | Sui Mysticeti v2 in-block BLS aggregation; Aptos BLS QC | large |
| 🟠 High | Crypto | **Validator key in plaintext on disk; no HSM/remote-signer** — raw `node.key`, auto-generated (`main.rs:76-139`); encrypted KeyManager unused by node | Host compromise/volume snapshot → consensus key → equivocation → stake-destroying slash | Cosmos tmkms/Horcrux (HSM, separate host) | large |
| 🟠 High | Crypto | **No signer-enforced double-sign (high-water-mark)** — only post-hoc detection (`dag.rs:728-768`) | The most catastrophic irreversible operator mistake is not prevented at the signer | tmkms/Horcrux persist height/round HWM, hard-refuse | medium |
| 🟠 High | Crypto | **No consensus-key rotation; no account/consensus key separation** — identity = single key (`main.rs:143-150`) | Leaked hot key can't be rotated without abandoning stake/identity | Aptos `rotate_consensus_key`; Sui epoch-boundary key rotation | large |
| 🟠 High | Economics | **Consensus weights flat (100 each)** — stake ignored; BFT quorum discards weight entirely (`dag.rs:1461`), fee pool flat-weighted | Breaks cost-to-attack ∝ stake; low-stake sybil set = high-stake honest set in voting power | Sui/Aptos/Cosmos: voting power = stake | medium |
| 🟠 High | Economics | **Two disconnected reward systems; delegators may earn zero** — `distribute_delegation_rewards` has no executor/epoch call site; only `slash_pool` wired (`lib.rs:1487`) | Delegators bear slashing risk but earn no rewards — broken incentive / financial-integrity bug | Aptos/Sui compute all rewards in one atomic epoch pass | large |
| 🟠 High | Ops | **No graceful shutdown/signal handling** — infinite `loop{sleep}`, no SIGTERM (`main.rs:744-760`) | Hard kills mid-write risk WAL stalls; rolling restarts are table stakes | Aptos/Sui SIGTERM drain+flush; Cosmovisor | small |
| 🟠 High | Ops | **Metrics far below production** — 3 metrics, `transaction_count` always 0; no consensus/sync/storage/latency/histograms (`metrics.rs:5-16`) | Operators can't detect a stalled-but-alive node; on-call is impossible | Aptos Node Inspection Service (:9101), hundreds of metrics + Grafana | medium |
| 🟠 High | Ops | **No snapshot/fast-bootstrap** — block-by-block from genesis (`main.rs:692,731`) | Genesis replay → days/weeks; impractical to add/recover validators | Sui DB snapshots; Aptos fast-sync + backup/restore | large |
| 🟠 High | Ops | **No protocol/version handshake gating** — fixed `/aincore/1.0.0`, agent_version only printed (`p2p.rs:153-156,374-375`) | Incompatible-logic nodes connect and gossip, producing divergence noise | Sui/Aptos enforce supported version range | medium |

### MEDIUM / LOW (hardening)

| Sev | Layer | Gap | Why it matters | Effort |
|---|---|---|---|---|
| 🟡 Med | Consensus | No formal safety/liveness proof; heuristic recovery constants (`MAX_ROUND_JUMP`, `DOWNTIME_THRESHOLD`) — code comment documents a prior constant *wedging* recovery (`dag.rs:565-572`) | x-large |
| 🟡 Med | Consensus | VDF beacon locally computed, proof discarded, unverified (`ordering.rs:107`) — no Byzantine-resistant shared randomness | medium |
| 🟡 Med | Consensus | Equivocation evidence in-memory only, stores proof *hashes* not signed bodies, no gossip/independent confirmation (`dag.rs:731-769`) | medium |
| 🟡 Med | Execution | No storage deposit/rebate; rent computed-and-discarded (`vm_move/lib.rs:101-111`) — unbounded state bloat | large |
| 🟡 Med | Execution | Gas schedule = uncalibrated Rust constants, not on-chain governable; **natives cost zero** (`GasParameters::zeros()`) → DoS vector | large |
| 🟡 Med | Execution | No Move bytecode upgrade-compatibility checker (`vm_move/lib.rs:478-487`) | medium |
| 🟡 Med | Execution | Dependency analysis is a hardcoded allowlist that under-approximates conflicts for unknown modules with **no conservative fallback** — latent state-corruption landmine once user contracts exist (`executor/lib.rs:1623-1690`) | large |
| 🟡 Med | State | No historical state versioning (overwrite-in-place); single RocksDB CF for all data classes; no DeleteRange/compaction strategy for prune tombstones | medium–large |
| 🟡 Med | Sync | No latency/throughput peer selection; in-memory-only bans; no archival fallback for pruned blocks; no adaptive backpressure | medium–large |
| 🟡 Med | Checkpoints | Checkpoint is a full-DAG JSON dump, not a chained succinct summary; `finalized_round`/`finality_digest` unsigned and never gossiped | medium |
| 🟡 Med | Mempool | No batch dissemination/PoS (raw JSON in vertices); weak DoS economics (no per-sender cap, no balance pre-check); lossy handoff (pulled txs dropped if proposal not committed) | medium–x-large |
| 🟡 Med | DA | Binary 32-leaf Merkle (not KZG/2D-RS), no namespacing; unbounded duplicative storage + zero-filled placeholder shards in proofs (`da/lib.rs:589-601`) | x-large |
| 🟡 Med | Crypto | ThresholdBLS uses ad-hoc hashing not field arithmetic / no DKG (self-documented non-production) | large |
| 🟡 Med | Economics | Slashing/stake params hardcoded, not governable; **partially-implemented** — economic params (reward/halving/burn) *are* governable via Rust `UpdateEconomicParams`, but slash bps / min-stake / unbonding / commission caps are not | medium |
| 🟡 Med | Economics | Self-stake burn-then-remint weakens supply invariant; `cleanup_old_unbonding` silently confiscates unclaimed principal (`staking.move:169-187`) | medium |
| 🟡 Med | Economics | Governance **partially-implemented** — real timelock/lifecycle exists in Rust crate, but vote weight = live liquid balance, not the recorded snapshot → flash-loan vote-borrowing risk (`governance/lib.rs:295`) | large |
| 🟡 Med | Ops | `/health` static OK (no readiness/liveness); narrow DEX-only SQLite indexer, no GraphQL/reorg handling; JSON-RPC `aincore_getTransaction` is indexed, but legacy REST/hash/address lookup paths still scan recent blocks; no config governance | medium–large |
| ⚪ Low | Execution | `SystemTime::now()` on VM read path — latent consensus-split if rent is ever wired (`vm_move/lib.rs:79-83`) | small |
| ⚪ Low | Crypto | PQC covers user txs but not consensus keys (at-par with Sui/Aptos); no formal audit of in-tree ZK/VDF primitives; 128-bit addresses vs 256-bit norm | x-large |
| ⚪ Low | Economics | O(n) vector scans for validators/delegations/voters (self-documented prototype shortcut) | medium |

---

## 4. The Top 5 Production-Readiness Blockers

These five, in order, are what most stand between AINCORE and "production L1." Each is a *cross-layer root cause*, not a leaf bug.

### #1 — No quorum certificate anywhere (the keystone gap)
**The single most consequential divergence.** Commit (`ordering.rs:227-246`), checkpoints (`dag.rs:1026`), blocks (`blockchain/lib.rs:5-19`), and DA (`da/lib.rs:294`) all rely on *one node's local computation or signature*. `Vertex.aggregated_signature` is `None` at all 7 sites; the correct blst BLS engine is unused by consensus.
**Fix:** Wire the existing `BLSEngine` into consensus. Aggregate 2f+1 validator votes into a BLS12-381 QC/CC bound to the committed anchor — exactly Aptos Jolteon's `LedgerInfoWithSignatures` / Sui Mysticeti v2 in-block aggregation. This single construct unlocks light clients, bridges, fast sync, checkpoint certification, and fork accountability. *Build this first; most other criticals depend on it.*

### #2 — Validator set is frozen at genesis
`sys:validators` is written once (`genesis.rs:625-631`), mutated only by slashing; on-chain `join_validator_set` never reaches the committee. A PoS chain that cannot rotate validators is not operationally PoS.
**Fix:** Make the Move `staking::ValidatorSet` the single source of truth, reflected into the consensus committee atomically at an epoch boundary — Aptos `on_new_epoch`/reconfiguration, Sui `validator_set::advance_epoch`, CometBFT EndBlock `ValidatorUpdates`. Couple this with **stake-weighted** voting power (gap: `dag.rs:1461` discards weight) so cost-to-attack ∝ stake.

### #3 — State is not authenticated
`state_root` is a chained delta-hash (`executor/lib.rs:1080-1091`), not a Merkle commitment over the state set; no inclusion proofs possible; new nodes must full-replay.
**Fix:** Replace the delta-hash with a versioned authenticated tree. The reference is Aptos's **Jellyfish Merkle Tree** (sparse, version-indexed) so `state_root` *is* the JMT root and every account/resource gets a sparse-Merkle proof — directly enabling state-proof RPC, light clients, and verifiable snapshots. (Cosmos IAVL+ is the alternative model.)

### #4 — No on-chain protocol-upgrade path
`protocol_version` is a hardcoded `1` (`api_local.rs:2199`); governance can't touch protocol behavior. Any consensus/VM bugfix after launch splits the network.
**Fix:** Adopt Sui's **ProtocolConfig + integer protocol_version + feature flags** model: validators signal readiness, and the new version enacts at the next epoch once >2/3 stake signals — deterministic flip, no hard-fork coordination. Pair with peer version-handshake gating (`p2p.rs:153-156`) so out-of-band nodes are refused.

### #5 — Execution collapses under contention + broken gas economics
Pessimistic barrier batching degenerates to ~1x parallelism under any hotspot (all staking txs share `validator_set_key`, `executor/lib.rs:1630`), *and* users are charged their full gas limit with real consumption discarded (`executor/lib.rs:2070`). Together these cap real throughput far below the consensus layer and break the fee market.
**Fix:** Two tracks. (a) Replace the static scheduler with **Aptos Block-STM** (optimistic MVCC + selective abort/re-execute) — correct for arbitrary contracts and gracefully degrading, which also closes the unknown-module conflict landmine. (b) Settle gas at `min(gas_used, limit)` and refund the remainder — table-stakes Aptos/Sui fee mechanics. Track (b) is `medium` effort and should ship long before (a).

---

## 5. Prioritized Roadmap

### P0 — Blocks mainnet (must-have before any value-bearing launch)
1. **BLS quorum certificates for consensus commit** → *Aptos Jolteon QC/CC, Sui Mysticeti v2.* (x-large) — keystone; unblocks most below.
2. **Quorum-signed, chained checkpoints + block-header signatures + epoch/waypoint object** → *Sui CheckpointSummary, Aptos LedgerInfoWithSignatures + EpochChangeProof.* (large) — builds on #1.
3. **Authenticated state tree (JMT) + state-proof RPC** → *Aptos Jellyfish Merkle Tree.* (x-large)
4. **Epoch-boundary validator-set rotation + stake-weighted voting power** → *Aptos reconfiguration / Sui advance_epoch / CometBFT ValidatorUpdates.* (large)
5. **On-chain protocol-version/feature-flag upgrade mechanism + peer version gating** → *Sui ProtocolConfig.* (x-large)
6. **DA commitment bound into block header + quorum availability cert + proposer-authorization check** → *Aptos Quorum Store PoS / Sui checkpoint binding.* (medium→large; the auth check is `small` and should land immediately)
7. **Gas settlement = `min(gas_used, limit)` with refund** → *Aptos base-gas.* (medium)
8. **Signer-side double-sign high-water-mark + consensus key off plaintext disk** → *tmkms/Horcrux.* (medium→large)
9. **Reward integrity: wire `distribute_delegation_rewards`; reconcile the two reward systems** → *Aptos/Sui single atomic epoch reward pass.* (large)
10. **Graceful shutdown (SIGTERM → drain + RocksDB flush)** → *Aptos/Sui/Cosmovisor.* (small — cheap, do early)

### P1 — Before production-like / incentivized public testnet
1. **State snapshots / fast-sync (apply-outputs + snapshot bootstrap)** → *Aptos fast-sync / Sui formal snapshots.* (large)
2. **Mempool gossip + TTL + fee-priority ordering + sequence-gap buffering + non-lossy commit-driven GC** → *Aptos shared mempool / Quorum Store.* (large, bundle)
3. **GossipSub v1.1 peer scoring + event-driven block/finality announce + multi-topic** → *Sui/Eth beacon.* (medium)
4. **Leader reputation/liveness scoring** → *Shoal/HammerHead.* (large)
5. **Production metrics surface + structured `tracing` logging + readiness/liveness `/health`** → *Aptos Node Inspection Service.* (medium)
6. **Block-STM optimistic execution (closes contention + unknown-module conflict landmine)** → *Aptos Block-STM.* (x-large)
7. **On-chain gas schedule (non-zero natives, governable) + Move upgrade-compatibility checker** → *Aptos gas_schedule / code::check_compatibility.* (large)
8. **Consensus-key rotation + account/consensus key separation** → *Aptos rotate_consensus_key.* (large)
9. **Governable staking/slashing params; vote weight from snapshot not live balance** → *Aptos staking_config / x/gov.* (medium)
10. **DA shard dispersal actually populated + DAS wired for light clients** → *Celestia/EigenDA.* (medium→large)

### P2 — Hardening
1. **Formal/published safety+liveness proof + pacemaker/view-synchronizer** replacing heuristic recovery constants → *Bullshark/Jolteon/Tendermint proofs.* (x-large)
2. **Storage deposit/rebate (priced reclaimable state); remove `SystemTime::now()` from VM path** → *Aptos AIP-32 / Sui storage fund.* (large + small)
3. **Storage hardening: column families, historical versioning, DeleteRange/compaction** → *Aptos typed CFs / Sui per-table CFs.* (medium)
4. **DA: KZG or 2D-RS + namespacing; bounded finality-tied DA storage; real bad-encoding fraud proofs + slashing wiring** → *EigenDA KZG / Celestia 2D-RS+NMT.* (x-large)
5. **Equivocation evidence: persist signed bodies + gossip for independent confirmation** → *CometBFT DuplicateVoteEvidence.* (medium)
6. **Verifiable shared random beacon (DKG + threshold-BLS, replacing local VDF); real field-arithmetic ThresholdBLS** → *Aptos on-chain DKG/VUF.* (large)
7. **Table-based staking/governance storage (O(1)); general reorg-safe Postgres+GraphQL indexer; archival fallback; peer-latency selection; config governance** (medium, bundle)
8. **Third-party audit of in-tree ZK/VDF primitives.** (x-large)

---

## 6. What AINCORE Will *Never* Need to Copy From Sui/Aptos

Avoid cargo-culting. These are deliberate, defensible divergences — chasing parity here would be wasted effort or actively wrong for AINCORE's design.

1. **A separate minimal `governance.move` lifecycle.** The grounding pass caught two *hallucinated* gaps here: AINCORE already runs a full-featured **Rust** `GovernanceManager` with timelock, lifecycle, and snapshot height. It does *not* need to reimplement Aptos's on-chain Move `aptos_governance`/`voting.move` machinery — it needs to fix *one* real sub-gap (vote weight should read the recorded snapshot, not live balance). Copying the whole Aptos governance framework would be redundant.

2. **PQC consensus keys, right now.** Neither Sui nor Aptos ships post-quantum consensus keys. AINCORE is *ahead* — it already has Dilithium5 wired for user-tx account abstraction. The honest framing is "PQC is forward-looking for everyone"; AINCORE should not burn effort making validators PQ before the rest of the industry, and should not feel behind for not having it.

3. **Sui's owned-object single-writer fast path / full object-centric model.** AINCORE deliberately chose a Block-STM-style shared-state model ("Narwhal-lite" per CLAUDE.md), not Sui Lutris object ownership. Adopting Block-STM (P1) is the right parallelism answer for *this* architecture; bolting on Sui's owned/shared-object typing would be a different chain. Don't.

4. **RSA-group Wesolowski/Pietrzak VDF as the randomness source.** AINCORE's own VDF comments correctly flag the hash-chain VDF as non-production — but the *right* destination is a **threshold-BLS/DKG beacon** (Aptos's actual production approach), not a heavyweight RSA-group VDF. Aptos itself uses round-derived leaders + reputation + DKG randomness, *not* a VDF. Don't chase the VDF rabbit hole; go straight to the threshold beacon.

5. **EigenDA/Celestia-grade external DA.** AINCORE's design intent is *sovereign* DA, and CLAUDE.md lists external-DA integration as an explicit *future* roadmap item, not a launch requirement. The real P0/P1 DA work is making the *existing* sovereign DA honest (bind to header, quorum cert, authorize proposer, actually disperse shards). KZG/2D-RS/namespacing (P2) is a ceiling-raiser, not a parity requirement — don't block on matching a dedicated DA layer.

6. **128-bit → 256-bit address migration as a priority.** The 16-byte address (~64-bit collision resistance) is a theoretical deviation from the 32-byte norm, not an exploitable gap at any realistic scale. Flagged honestly as low; it does not warrant a disruptive address-format migration ahead of the criticals.

---

## 7. External Reference Anchors

These are not exhaustive citations, but they anchor the comparison points used above:

- [Sui checkpoint verification](https://docs.sui.io/develop/sui-architecture/checkpoint-verification): Sui clients verify checkpoints using validator committee public keys and aggregated BLS quorum signatures.
- [Sui protocol message reference](https://docs.sui.io/doc/protocol-messages-full.html): includes `ValidatorAggregatedSignature` and checkpoint-related message fields.
- [Aptos validator node overview](https://aptos.dev/network/blockchain/validator-nodes): AptosBFT fault tolerance up to one-third malicious validators.
- [Aptos Labs Block-STM writeup](https://medium.com/aptoslabs/block-stm-how-we-execute-over-160k-transactions-per-second-on-the-aptos-blockchain-3b003657e4ba): primary Aptos Labs explanation of Block-STM's optimistic parallel execution model.
- [Aptos JMT overview](https://aptosnetwork.com/currents/why-aptos-8-innovations-powering-aptos-network): Aptos describes use of Jellyfish Merkle Tree over RocksDB/LSM-style storage.
- [Aptos Labs Quorum Store writeup](https://medium.com/aptoslabs/quorum-store-how-consensus-horizontally-scales-on-the-aptos-blockchain-988866f6d5b0): describes Quorum Store as a deployed Narwhal-style data dissemination design.

Use these as orientation, not as a substitute for implementation-specific review of AINCORE.

---

**Bottom line for the "are we production-ready?" question:** *No — and saying otherwise would be dishonest.* AINCORE is a well-built **testnet-grade prototype** with unusually strong security hygiene and correct low-level primitives, held back by one recurring architectural absence — **portable, quorum-attested proofs** — plus a genesis-frozen validator set and no upgrade path. The current public observer testnet is valid as an engineering/devnet network, but P0/P1 is what graduates it toward a production-like or incentivized public testnet. Until then, it should be described as *"sovereign L1 architecture, devnet maturity, P0 security fixes in progress"* — which is exactly what the current branch name (`audit/p0-security-fixes`) honestly implies.
