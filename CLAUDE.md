# AINCORE Blockchain — Claude Context File

> Dibaca otomatis di setiap session. Jangan hapus file ini.
> Last updated: 2026-05-20

---

## 🎯 Project Overview

AINCORE adalah **L1 blockchain berdaulat** yang dibangun dari nol dengan Rust.
Arsitektur: **Modular** — terinspirasi Narwhal/Tusk (DAG consensus) + Sui Move VM + Sovereign DA.

- **Bahasa:** Rust (workspace multi-crate)
- **VM:** Move (via `move-vm-runtime`, bukan EVM)
- **Consensus:** DAG-based (Bullshark-lite ordering)
- **Storage:** RocksDB (via `common/storage`)
- **Network:** libp2p (Gossipsub) + TCP fallback
- **Token:** AIN, 150 juta supply, halving model
- **Chain ID:** `AINCORE-MAINNET-1` (env: `AINCORE_CHAIN_ID`)
- **API Port:** 8002 (default), `port - 1000` jika custom port
- **P2P Port:** 9001 (default)

---

## 🗂️ Struktur Workspace (Semua Crate)

```
AINCORE-Blockchain/
├── common/
│   ├── crypto/          ← Semua primitif crypto (ED25519, STARK, BLS, ECDSA, MPC, VDF, ZKP)
│   ├── config/          ← NodeConfig (port, datadir, bootnodes, peers)
│   ├── keystore/        ← KeyManager: enkripsi/dekripsi keystore JSON
│   ├── network/         ← TCP send_message, PeerList (Arc<Mutex<HashMap<String,u16>>>)
│   └── storage/         ← StateDB (RocksDB), Object model, WAL hardened
├── consensus/
│   ├── consensus/       ← DagConsensus + OrderingEngine (KRITIS: logika core)
│   ├── blockchain/      ← Block, Vertex struct, hash kalkulasi
│   ├── account/         ← Account struct, AccountAbstraction trait (masih simple)
│   └── aa/              ← Account Abstraction layer
├── core/
│   ├── node/            ← Main node: API (actix-web), P2P, genesis loader, metrics
│   ├── executor/        ← Executor: execute_block_parallel, gas, slashing (FILE BESAR >600 baris)
│   ├── mempool/         ← Mempool: validasi TX, dedup, nonce check, BCS payload
│   ├── vm_move/         ← AINCOREVM: wrapper Move VM, gas metering, EntryFunctionCall
│   ├── cli/             ← CLI wallet: send TX, keys, client
│   ├── genesis-tool/    ← Generator genesis.json
│   └── move_compiler_tool/ ← Compiler Move contracts
├── da/                  ← DASequencer: erasure coding, Merkle, sharding, DAS sampling, fraud proofs
├── sync/                ← ChainSync: blok sinkronisasi antar node
├── governance/          ← Governance: Proposal, Vote, TimeLock, on-chain execution
├── depin/
│   ├── bridge-rust/     ← EVM bridge (Ethereum/BSC), pakai keystore WAJIB
│   └── btc-bridge/      ← Bitcoin bridge, PSBT, multisig
├── indexer/             ← Block indexer untuk explorer
├── monitor/             ← Prometheus metrics exporter
├── bench-tps/           ← Benchmark TPS tool
└── utils/derive_keys/   ← Key derivation utility
```

---

## 🔑 File-File Paling Kritis (Jangan Utak-atik Sembarangan)

| File | Kenapa Kritis |
|------|--------------|
| `consensus/consensus/src/dag.rs` | Core DAG consensus, BFT quorum, slashing, vertex ordering |
| `consensus/consensus/src/ordering.rs` | Bullshark-lite: OrderingEngine, VDF leader election |
| `core/executor/src/lib.rs` | Eksekusi TX paralel (rayon), gas, Move VM call, reward distribusi |
| `core/mempool/src/lib.rs` | Gate pertama TX: chain ID, signature verify, nonce dedup |
| `common/crypto/src/lib.rs` | Root semua crypto primitif |
| `common/crypto/src/zkp/stark.rs` | STARK prover/verifier |
| `common/storage/src/lib.rs` | RocksDB dengan WAL hardening — jangan ubah options |
| `genesis.json` | Genesis state — JANGAN EDIT langsung |
| `wallet.key` | Private key node — JANGAN HAPUS, JANGAN COMMIT |

---

## 🏗️ Arsitektur Alur Data (Penting untuk Debugging)

```
User TX
  ↓
[Mempool] → validasi: chain_id, signature Ed25519, BCS payload, nonce, gas
  ↓
[DagConsensus::try_create_vertex()] → ambil TX dari mempool, buat Vertex
  ↓
[DagConsensus::add_vertex()] → verifikasi sig, cek validator set, deteksi equivocation
  ↓
[OrderingEngine::try_commit()] → Bullshark-lite, anchor leader via VDF
  ↓
[Executor::execute_block_parallel()] → rayon parallel, Move VM, gas deduct
  ↓
[StateDB (RocksDB)] → commit state, block hash, height
  ↓
[DASequencer::create_batch()] → erasure coding, Merkle proof, shard distribution
```

---

## 🔐 Sistem Crypto (common/crypto)

| Module | Fungsi |
|--------|--------|
| `lib.rs` | hash(SHA256), verify_signature(Ed25519), derive_address (32 byte = 64 hex) |
| `ecdsa.rs` | ECDSACrypto, ECDSAError |
| `bls/` | BLSEngine, aggregate BLS |
| `threshold/threshold_bls.rs` | ThresholdBLS, PartialSignature, aggregate_bls |
| `zkp/stark.rs` | STARKProver, STARKError |
| `zkp/snark.rs` | SNARKProver, HashPreimageCircuit, SNARKError |
| `poseidon/` | Poseidon hash (ZK-friendly) |
| `mpc/` | MPCProtocol, MPCError |
| `vdf/` | VDFEngine (leader election randomness) |
| `accumulator/` | Merkle accumulator untuk light clients |
| `multi_sig.rs` | MultiSigVerifier, SignatureScheme |

**Address derivation:** `hex(SHA256(pubkey))` = 64 char hex string (full 32-byte digest, NOT truncated)

---

## ⛓️ Consensus Mechanics

### DagConsensus (dag.rs)
- **BFT Quorum:** `(n * 2/3) + 1` — wajib untuk finality
- **Validator set:** dibaca dari `sys:validators` (storage) atau BCS `ValidatorSet` resource
- **Observer mode:** node yang bukan validator tidak boleh mine
- **Split-brain prevention:** validator terisolasi (no peers) berhenti mine
- **Downtime detection:** `DOWNTIME_THRESHOLD = 100 rounds` → attestation only (NOT slashed in protocol v2; only equivocation is slashed, 100%, via DAG-carried compact proofs)
- **Equivocation (double-sign):** deteksi same author + same round + different hash → instant slash
- **Checkpoint:** setiap 100 round, simpan DAG checkpoint untuk fast recovery
- **Pruning:** setiap 10 blok, prune round < `min_committed_round - 10`

### OrderingEngine (ordering.rs)
- **Algoritma:** Bullshark-lite (simplified)
- **Leader election:** round ganjil = leader round, cek support dari round sebelumnya
- **VDF randomness:** `VDFEngine::new(50)` untuk unpredictable leader
- **State persistence:** `consensus:committed_rounds`, `consensus:committed_sequence` di RocksDB

### Validator Set
- **Fast path:** `storage.get("sys:validators")` → `Vec<(String, u64)>`
- **Slow path:** BCS decode dari `resource_0x1_0x1::staking::ValidatorSet`
- **No fallback ke P2P peers** — strict enforcement

---

## 💾 Mempool (core/mempool)

Validasi yang dilakukan sebelum TX masuk:
1. Chain ID match (`AINCORE_CHAIN_ID` env)
2. Gas price ≥ `MIN_GAS_PRICE = 1`
3. Gas limit > 0
4. BCS payload valid: hanya `EntryFunction` atau `PublishModule` (Script DISABLED)
5. Ed25519 signature verify (64 byte) atau PQC (9254 byte = pass ke executor)
6. Sender address derivasi match public key
7. SHA256 dedup (seen_txs HashSet)
8. Size limit: 100KB max per TX
9. Nonce dedup: `sender:sequence_number`
10. Max pending: 5000 TX

---

## ⚡ Executor (core/executor)

- **Global lock:** `BLOCK_EXECUTION_LOCK` (LazyLock<Mutex>) — prevent state root race condition
- **Parallel execution:** `rayon::prelude` — TX dengan object yang tidak overlap dieksekusi paralel
- **Object limit per block:** `MAX_OBJECTS_PER_BLOCK = 10_000`
- **Object load gas:** `OBJECT_LOAD_GAS = 100`
- **Move system address:** `0x1` (semua stdlib ada di sini)
- **AincoreCoin type:** `0x1::staking::AincoreCoin`
- **CoinStore key format:** `resource_{addr}_{StructTag}`
- **Reward:** distribusi ke `anchor_leader` (dari ordering engine)
- **Fee:** sweep ke miner, bukan burn

---

## 📡 DA Layer (da/)

- **DASequencer:** node_id, signing_key (Ed25519), epoch counter
- **Erasure coding:** 16 data + 16 parity shards (reed-solomon)
- **Compressor:** zstd level 3
- **ShardManager:** 32 shards total, 3x replication
- **Fraud proofs:** FraudProofVerifier, SlashingParams
- **DAS sampling:** LightClient dapat verify tanpa download full block
- **Integration:** dipanggil dari DagConsensus setelah block finalized

---

## 🔗 Network Layer (common/network + core/node/p2p.rs)

- **Libp2p:** Gossipsub untuk broadcast vertex (`DAG_VERTEX:{json}`)
- **TCP fallback:** `send_message(addr, msg)` untuk legacy/sync nodes
- **Peer IP resolution:** `storage.get_peer_ip(peer_id)` (default `127.0.0.1`)
- **P2P channel:** `tokio::sync::mpsc::Sender<String>` di DagConsensus
- **Message format:** `"DAG_VERTEX:{serialized_vertex}"`

---

## 🌐 API (core/node/api.rs)

- **Framework:** actix-web
- **Rate limiting:** actix-governor
- **CORS:** opt-in via `AINCORE_PERMISSIVE_CORS=1`
- **Middleware:** Logger
- **Max limit query:** 1000
- **Balance query:** via Move CoinStore resource (bukan AccountData lama)

---

## 🌉 Bridge (depin/)

### EVM Bridge (bridge-rust)
- Koneksi ke Ethereum/BSC via ethers-rs
- **WAJIB:** `--keystore /path/to/keystore.json` saat run production
- Env: `AINCORE_RPC`, `EVM_RPC`, `CONTRACT_ADDRESS`

### BTC Bridge (btc-bridge)
- Bitcoin PSBT, multisig
- Komponen: `btc_client.rs`, `aincore_client.rs`, `storage.rs`

---

## 🏛️ Governance (governance/)

- **Proposal:** id, title, description, proposer, action, start/end time
- **TimeLock:** `execution_time` sebelum proposal bisa dieksekusi
- **Vote weight:** u128 (match stake balance)
- **Actions:** `UpdateFederationKey`, `UpdateEconomicParams`
- **Balance source:** `query_move_vm_balance()` — bukan AccountData lama
- **Status:** Active → Passed → Queued → Executed / Rejected

---

## 🛠️ Build Commands

```bash
# Build semua crate
cargo build --release

# Build node saja (paling sering)
cargo build --release -p node

# Test semua
cargo test --workspace

# Test crate spesifik
cargo test -p crypto
cargo test -p mempool
cargo test -p consensus

# Lint (HARUS bersih sebelum commit)
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all

# Benchmark STARK
cargo bench -p crypto

# Benchmark TPS
cargo run -p bench-tps

# Generate genesis
cargo run -p genesis-tool

# Compile Move contract
cargo run -p move_compiler_tool -- --input contract.move

# Derive keys
cargo run -p derive_keys
```

---

## 🔧 Environment Variables

| Var | Default | Fungsi |
|-----|---------|--------|
| `AINCORE_CHAIN_ID` | `AINCORE-MAINNET-1` | Chain ID (wajib match di semua TX) |
| `AINCORE_PERMISSIVE_CORS` | `0` | Enable CORS permissive untuk dev |
| `AINCORE_RPC` | `http://localhost:8001/rpc` | RPC endpoint (untuk bridge) |
| `EVM_RPC` | `https://rpc.sepolia.org` | EVM RPC endpoint |
| `CONTRACT_ADDRESS` | `0x000...` | Bridge contract address |

---

## 🚨 ATURAN WAJIB (JANGAN DILANGGAR)

1. **JANGAN** edit `genesis.json` tanpa explicit konfirmasi dari user
2. **JANGAN** hapus atau commit `wallet.key` ke git
3. **JANGAN** ubah `RocksDB` options di `storage/src/lib.rs` tanpa test durability
4. **JANGAN** hapus `BLOCK_EXECUTION_LOCK` di executor — ini prevent state root race
5. **JANGAN** ubah BFT quorum formula tanpa full consensus review
6. **JANGAN** aktifkan Script payload di mempool (sengaja disabled)
7. **JANGAN** push langsung ke branch main
8. Setiap perubahan di `common/crypto/` **WAJIB** ada unit test
9. Setiap perubahan di `core/executor/` **WAJIB** ada cargo test setelahnya
10. Bridge production **WAJIB** pakai `--keystore`, bukan env var private key

---

## 🐛 Known Issues & In-Progress

- `consensus/account/src/lib.rs` — `AccountAbstraction` trait masih stub (execute_transaction kosong)
- `ROADMAP.md` Phase 7 (BTC Bridge, EVM Bridge, IBC) belum complete
- DA Layer masih sovereign (belum integrate ke Celestia/EigenDA — roadmap Phase X)
- ZK-SNARKs untuk private TX belum aktif (ada di `zkp/snark.rs` tapi belum wire ke executor)
- Governance belum ada on-chain execution trigger (masih manual)

---

## 📊 Dependency Graph (Simplified)

```
node → consensus → executor → vm_move
                           → storage
     → mempool  → executor
     → sync     → storage
     → da
     → governance → storage

crypto ← consensus, executor, mempool, da, sync, bridge
storage ← consensus, executor, sync, da, governance, bridge
network ← consensus, sync, da
```

---

## 🎯 Visi Arsitektur (dari Whitepaper)

AINCORE dirancang sebagai **modular blockchain L1**:
- **Consensus:** Narwhal & Tusk inspired (DAG + mempool terpisah)
- **Execution:** Object-centric parallel (Sui-inspired)
- **DA:** Sovereign sekarang, target Celestia integration
- **Language:** Move VM (resource-linear, formal verification ready)
- **AA:** Native Account Abstraction (bukan ERC-4337)
- **Interop:** Target IBC (Cosmos standard)
- **Privacy:** Future: ZK-SNARK shielded pools (Zcash model)
- **PQC:** CRYSTALS-Kyber/Dilithium untuk quantum resistance

**Status vs Whitepaper:**
- ✅ DAG consensus (Narwhal-lite) — DONE
- ✅ Parallel execution (rayon) — DONE (Block-STM style, bukan pure Sui object model)
- ✅ Move VM — DONE
- ✅ Native AA (Ed25519, bukan ERC-4337) — DONE
- ✅ Sovereign DA — DONE
- ✅ PoS + Slashing — DONE
- ✅ ZK infra (STARK, SNARK, BLS) — Ada, belum fully wired
- 🚧 BTC/EVM Bridge — In progress
- ❌ IBC — Belum
- ❌ Celestia DA integration — Belum
- ❌ ZK private TX — Belum
- ❌ PQC mainnet — Belum

---

## 🤖 Orchestrator Mode — Cara Gue Kerja

Gue adalah **orchestrator** untuk AINCORE. Setiap perintah dari user gue analisa dulu,
lalu koordinasi departemen yang tepat secara otomatis. User gak perlu tau detail teknisnya.

### Trigger → Aksi Otomatis

| Kata kunci dari user | Gue spawn |
|---|---|
| "audit", "review kode", "cek security" | Security Agent + Code Auditor (sequential) |
| "test", "validasi", "cek test" | QA (cargo test + clippy + build) |
| "pentest", "red team", "coba hack" | Pen Tester Agent |
| "sprint", "planning", "roadmap" | PM Agent → Sprint plan |
| "implement", "bikin", "fix", "code" | Blockchain Dev Agent |
| "research", "riset", "compare" | Researcher + Tech Writer |
| "full cycle", "audit dan fix", "semua" | PM → Security → Audit → Dev → QA → Report |

### Prinsip Koordinasi
1. **Gue yang mikir** urutan agent mana yang dipanggil — user cukup bilang tujuannya
2. **Hasil tiap agent** jadi context untuk agent berikutnya (downstream aware)
3. **Gue compile** semua output jadi satu laporan bersih ke user
4. **Kalau ragu** soal scope → tanya user dulu sebelum eksekusi yang modifikasi kode
5. **Perubahan kode** selalu divalidasi dengan `cargo test` sebelum lapor selesai

### Agent Roles (detail di .claude/crew/agents/)
- `pm.md` — Product Manager: sprint planning, task specs
- `security.md` — Security Lead: vulnerability hunting, threat model
- `auditor.md` — Code Auditor: deep review, checklist, invariants
- `pentest.md` — Pen Tester: red team, exploit PoC
- `developer.md` — Blockchain Dev: implementation, fixes, tests
- `researcher.md` — Researcher: protocol research, ZKP, PQC

---

## 💡 Tips untuk Claude di Session Ini

- **Saat debug consensus:** mulai dari `dag.rs::add_vertex()` → `ordering.rs::try_commit()`
- **Saat debug TX gagal:** mulai dari `mempool::add_transaction()` → `executor::execute_block_parallel()`
- **Saat audit crypto:** fokus ke `common/crypto/src/zkp/` dan `bls/`
- **Saat ada state inconsistency:** cek `BLOCK_EXECUTION_LOCK` dan RocksDB WAL config
- **Storage key patterns:**
  - Block: `block_{height}`
  - Vertex: `vertex:{hash}`
  - Validator state: `sys:validators`
  - Latest height: `latest_height`
  - Latest hash: `latest_block_hash`
  - Jailed validator: `validator:jailed:{addr}`
  - Slash queue: `sys:pending_slash:{addr}`
  - DAG checkpoint: stored via `storage.save_dag_checkpoint(round, json)`
  - Committed rounds: `consensus:committed_rounds`
  - Resource: `resource_{addr}_{StructTag}`
  - Peer IP: stored via `storage.get_peer_ip(peer_id)`
