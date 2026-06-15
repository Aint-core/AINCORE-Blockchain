# AINCORE In-Protocol State-Sync — Design Spec

Date: 2026-06-16
Status: design spec (no code). Branch base: `audit/p0-security-fixes`.
Prereq context: docs/PUBLIC-TESTNET-JOIN.md (manual snapshot bootstrap),
docs/BLS-QUORUM-CERT-SPEC-2026-06-10.md (QC keystone).

## Problem

A fresh / long-offline node cannot join a running network:
- the seed prunes old blocks, so block-replay from genesis is impossible
  (`block_1` is gone — confirmed via ldb);
- the anti-jump guards correctly refuse a 0→tip leap.

Today this is bridged by a **manual** snapshot (copy DB → sanitise → seed). That
works but is operator-driven, per-node, and trust-by-operator. It also blocks
**multi-validator onboarding** (a new validator hits the same wall).

State-sync makes bootstrap **automatic and trust-minimised**: a node fetches a
recent state snapshot from a peer, verifies it against a quorum certificate,
then resumes normal block-sync for the small delta.

## Trust model — verify against a QC (the synthesis with the keystone)

The snapshot is a `(height H, state_root S, block_hash B)` tuple plus the raw
state at H. The joiner must NOT trust it blindly. It verifies:

1. Obtain a **QuorumCertificate** for height H (the QC already certifies
   `state_root` + `block_hash` + `validator_set_hash` over a >2/3-stake
   `FinalityVote` — see the QC spec). The joiner is configured with a **trusted
   genesis validator set** (weak-subjectivity checkpoint) and verifies the QC's
   aggregate BLS signature against it.
2. Recompute the state digest of the received state and check it equals the
   QC-certified `state_root`.

=> the joiner trusts the snapshot iff a >2/3-stake quorum signed its state_root.
No operator trust required. This is why QC Phase 2 had to land first.

## Wire protocol (over the existing encrypted P2P channel)

Three request/response messages, same framing as `GET_HEIGHT`/`SYNC_REQ`:

- `STATE_MANIFEST_REQ` → `STATE_MANIFEST:{height, state_root, block_hash,
  chunk_count, chunk_size, qc}` — the snapshot header + the QC for `height`.
- `STATE_CHUNK_REQ:{index}` → `STATE_CHUNK:{index, bytes}` — one chunk of the
  serialised state (RocksDB key/value range, excluding per-identity keys:
  `sys:da:signing_key*`, `peer:*`). Chunked because state is 100s of MB and the
  frame layer caps message size.
- Reuse `GET_HEIGHT` to pick the most-advanced peer to sync from.

Each chunk carries a Merkle path to a `state_chunks_root` committed in the
manifest so chunks are individually verifiable and resumable.

## Bootstrap flow (joiner)

```
1. GET_HEIGHT from peers → pick peer at height H (>> local, beyond prune horizon
   — signalled by `prune_horizon`, already implemented).
2. STATE_MANIFEST_REQ → manifest + QC.
3. verify_qc(qc, trusted_validator_set); require qc.state_root == manifest.state_root.
4. STATE_CHUNK_REQ * chunk_count → assemble; verify each chunk vs state_chunks_root;
   verify assembled state digest == state_root.
5. Atomically install state at H, set latest_height/hash, generate own node.key
   + DA key (never import the peer's).
6. Resume normal ChainSync for [H+1 .. tip] (those blocks exist, < prune window).
```

This supersedes the manual snapshot + the startup `AINCORE_BOOTSTRAP_SNAPSHOT`
shim (which stays as a fallback / for air-gapped seeding).

## Seed side

- Serve a manifest + chunks from a **point-in-time RocksDB checkpoint** (created
  via the RocksDB checkpoint API — consistent, near-instant, no node stop;
  replaces the brief-stop snapshot of the manual flow).
- Refresh the checkpoint every K blocks; serve the latest.
- Exclude per-identity keys from the served state (DA key, peer table) so the
  joiner needs no post-sanitisation.

## Security / DoS

- Verification is mandatory (QC + state_root + per-chunk Merkle) — a malicious
  peer cannot inject fake state.
- Rate-limit chunk serving; cap concurrent state-sync sessions per peer.
- Weak-subjectivity: the trusted genesis validator set (or a recent trusted QC)
  is the anchor; document the trust assumption for operators.

## Phasing

1. **P1 — checkpoint export on the seed** (RocksDB checkpoint + manifest, no
   wire protocol yet; reuse for the published snapshot). Low risk.
2. **P2 — manifest+chunk wire protocol + QC verification on the joiner.** The
   core. Consensus-adjacent → full design→review→test, dedicated effort.
3. **P3 — multi-validator onboarding** on top: a new validator state-syncs, then
   `catch-up-before-produce` (does not propose until within N rounds of tip),
   closing the bootstrap gap noted in RESET-BUNDLE-PLAN.

## What already exists (building blocks landed this cycle)

- QC produce + `verify_qc` against `sys:validator_set:v1` (QC Phase 2).
- `prune_horizon` signalling (joiner knows when to state-sync).
- `AINCORE_BOOTSTRAP_SNAPSHOT` startup load + self-sanitise (the manual-flow
  shim P2 will supersede).
- Proven manual snapshot procedure (scripts/testnet-make-snapshot.sh) — the
  reference for the checkpoint export.

## Honest scope

This is a multi-week, consensus-adjacent feature; P2 must not be rushed. P1
(checkpoint export) is a safe, useful first step that also improves the manual
flow. Until state-sync ships, tailnet-invite + manual/shim snapshot bootstrap
(working today) remains the join path.
