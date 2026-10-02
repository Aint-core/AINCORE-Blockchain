# Bug ledger

Every known defect, its evidence, its fix and the commit that closed it. The founder's rule
(2026-10-03): fix every known bug, then audit, fix what the audit finds, and repeat until an
audit round confirms nothing above LOW and every LOW is fixed or accepted here with a reason.

Status: **OPEN**, **FIXED** (commit), **ACCEPTED** (with the reason), **REFUTED**.

## Round 0: the bugs known on 2026-10-03

| ID | Severity | Bug | Evidence | Plan | Status |
|---|---|---|---|---|---|
| B1 | HIGH | The DA layer provides no data availability: it erasure-codes a ~200-byte JSON (a block hash and a tx count), not the block; every peer batch is refused (a separate random DA key is checked against the node address); an unsigned "legacy" batch is accepted; no committee check; the DA epoch counter restarts at 0 on every boot and overwrites earlier rows; peer batches and the node's own share keys (`da_root_{epoch}`); the broadcast dials `127.0.0.1` for unknown peers | `da/src/lib.rs:141-182`, `:261-445`, `:520-600`; S6 cluster: 2,595 of 2,595 batches refused (G4 draft) | Bind a DA root of the block body into the block header (deterministic erasure coding, no compression), store and serve shards per height, sample against the QC-certified header; delete the signed-batch broadcast and the separate DA key | OPEN |
| B2 | HIGH | Unknown peer addresses default to `127.0.0.1` | `storage.get_peer_ip` default; a restarted S6 validator dialled its peers on 127.0.0.1 | G4 S1: addresses come from the authenticated session or the bootnodes; never a guessed loopback | OPEN |
| B3 | HIGH | No per-peer budgets, queues, size caps before decode, or gossip scoring; the legacy TCP channel opens a connection per message | G4 contract, "What exists today" | G4 S1-S7 | OPEN |
| B4 | MEDIUM | Participation is measured by leader slots only: a member that authors only its leader-round vertices and signs nothing else is paid in full | A4 second review MEDIUM-5 | Blocks carry the authors of their committed vertices, bound in the header; rewards and BW-6 use them | OPEN |
| B5 | MEDIUM | About 15 % of anchor rounds commit no anchor with four honest validators (interval p99 21 s, max 43 s) | S6 measurement; TESTNET-V4 631 rounds for 567 blocks | Find why the leader's vertex misses its round (3 s timer rounds) and fix | OPEN |
| B6 | LOW | About 10 KB of storage per empty block (~47 GB a year) | S6 measurement | Measure what each block writes; prune and encode compactly | OPEN |
| B7 | LOW | `0x1::treasury` is dead code that would sell AIN from a genesis reserve at a fixed USD price ("bill acceptor"). It mints nothing and only @0x1 can call it, which no user can forge; with the reserve at 0 it holds nothing. It contradicts the no-business decision and misleads readers | `core/vm_move/stdlib/sources/treasury.move:44-80`; genesis writes `0x1::treasury::Treasury` (`core/node/src/genesis.rs:1673-1682`) and boot reads it (`:606`) | Delete the module, its genesis resource and the treasury reserve | OPEN |
| B8 | HIGH | Post-quantum signatures use pre-standard Dilithium (pqcrypto-dilithium), not FIPS 204 ML-DSA | `common/crypto` PQC; mempool 9,254-byte path | ML-DSA-65 with crypto agility, before mainnet genesis | OPEN |
| B9 | LOW | A test fails intermittently (`a_transaction_travels...`): the mempool requeue uses the wall clock | flaky on the NAS and Pi | Inject the clock | OPEN |
| B10 | MEDIUM | RPC endpoints answer with invented data: `aincore_getFheKey` returns `FHE_MOCK_PUBLIC_KEY_12345`; `aincore_getMiningStats` reports a "network hashrate" of peers × 10 TH/s; `aincore_verifyFraudProof` "accepts for review" any JSON with three field names; `aincore_getDaStatus` returns a placeholder epoch | `core/node/src/api_local.rs:1144-1245`, `:1795-1810` | Return real data or an explicit "not supported" error; never invented values | OPEN |
| B11 | INFO | The STARK verifier is a placeholder that always refuses, so a transaction carrying a ZK proof is always rejected | `common/crypto/src/zkp/stark.rs:245` | Fail-closed, so not a vulnerability; documented as "not available" wherever ZK is claimed | ACCEPTED (fail-closed; the claims are corrected under B10's honesty rule) |
