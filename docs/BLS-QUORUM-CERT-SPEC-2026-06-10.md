# AINCORE BLS Quorum Certificate Spec

Date: 2026-06-10
Status: design spec, not implemented

## Purpose

AINCORE already has a live public observer testnet. That is not the same as a production-like validator network.

The missing cryptographic root is a quorum certificate: a compact proof that a finalized anchor/checkpoint was signed by validators representing at least 2/3 of active stake.

This unlocks:

- trust-minimized light clients
- bridge finality proofs
- trustless checkpoint bootstrap
- faster observer sync
- future multi-validator/incentivized testnet operation

## Grounded Code Facts

This spec is based on the current codebase, not generic Sui/Aptos cargo-culting.

### Already Present

- BLS12-381 engine exists in `common/crypto/src/bls/mod.rs`.
- The engine supports:
  - `sign`
  - `aggregate_signatures`
  - `fast_aggregate_verify`
  - `verify_aggregated`
  - `aggregate_public_keys`
- Block headers already contain:
  - `height`
  - `round`
  - `state_root`
  - `receipts_root`
  - `hash`
- Consensus already persists:
  - `consensus:finalized_round`
  - `consensus:last_anchor_round`
  - `consensus:last_anchor_hash`
  - `consensus:finality_digest`
- DAG checkpoints already exist at:
  - `dag:checkpoint:{round}`
  - `dag:checkpoint_sig:{round}`
  - `dag:checkpoint:latest`

### Missing

- Validator records do not carry BLS public keys.
- `sys:validators` currently stores only `(address, stake)`.
- Move `staking::ValidatorConfig` contains `public_key`, but no `bls_public_key`.
- Current checkpoint signatures are single-node Ed25519 integrity signatures.
- There is no finality vote message signed by validators.
- Current anchor support is count-based and derived locally from DAG vertices, not an explicit BLS vote set.
- There is no `QuorumCertificate` structure.
- There is no stake-weighted QC verifier.

## Non-Goals

This spec does not replace consensus.

AINCORE should keep the current DAG/BFT path. BLS QC is a finality proof layer over committed anchors/checkpoints, not a new consensus protocol.

This spec also does not implement full state snapshot sync yet. QC is the prerequisite that makes later snapshot sync trust-minimized.

## Core Data Structures

### Validator Identity

Each active validator must have two public identities:

- Ed25519 public key: existing node/network/vertex identity
- BLS public key: finality vote and QC identity

Proposed runtime representation:

```rust
pub struct ValidatorInfo {
    pub address: String,
    pub stake: u64,
    pub ed25519_public_key: String,
    pub bls_public_key: String,
    pub bls_pop: String, // proof-of-possession over bls_public_key (MANDATORY)
}
```

Migration note: current `sys:validators` is `Vec<(String, u64)>`. Do not silently reinterpret that format. Introduce versioned validator metadata, for example:

```text
sys:validator_set:v1
```

Keep legacy `sys:validators` as a compatibility cache until all callers move.

### Proof of Possession (MANDATORY — security-critical)

`fast_aggregate_verify` aggregates validator public keys and verifies them against
ONE common message (the `FinalityVote`). Per IETF draft-irtf-cfrg-bls-signature,
`fast_aggregate_verify` over a common message is ONLY secure under the
**proof-of-possession** scheme. Without it, AINCORE is exposed to the **rogue
public key attack**:

> A malicious validator registers `pk_evil = g^x · (pk_victim)^-1`, computed to
> cancel an honest validator's key. When `pk_evil` and `pk_victim` are aggregated,
> `pk_victim` cancels out, leaving a key the attacker fully controls. The attacker
> can then forge an aggregate signature that verifies as if `pk_victim` signed —
> without the victim ever signing. With enough cancellation, a low-stake attacker
> forges a 2/3 QC and forges finality. This breaks the entire trust model (light
> clients / bridges would accept forged finality).

**Defense (Eth2 standard):** every validator MUST submit a proof-of-possession
when registering its BLS public key, and registration MUST verify it before
accepting the key.

- PoP = a BLS signature over the validator's OWN compressed public key bytes,
  using a SEPARATE domain-separation tag (the `..._POP_` DST), NOT the consensus
  signing DST. Distinct DST is required so a PoP can never be replayed as a
  finality vote or vice-versa.
- Engine work: add `prove_possession(sk) -> Vec<u8>` and
  `verify_possession(pk_bytes, pop) -> Result<bool>` to `BLSEngine`
  (`common/crypto/src/bls/mod.rs`). blst exposes the primitives; only a wrapper +
  POP DST constant are needed.
- Registration: at genesis AND `join_validator_set`, reject any `bls_public_key`
  whose `bls_pop` does not verify. No PoP, no registration.

This is a Phase-1 BLOCKER, not a later hardening item: Phase-4 multi-validator
QCs are forgeable without it.

### Finality Vote

All validators must sign the same canonical message for fast BLS aggregation.

Proposed message:

```rust
pub struct FinalityVote {
    pub chain_id: String,
    pub epoch: u64,
    pub finalized_round: u64,
    pub anchor_round: u64,
    pub anchor_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    pub finality_digest: String,
    pub validator_set_hash: String,
}
```

Canonical encoding must be deterministic. Prefer BCS or a dedicated byte encoder. Do not use ad hoc JSON serialization for signing.

Domain separation:

```text
AINCORE_FINALITY_VOTE_V1
```

The existing BLS engine already has a consensus DST. If that DST is reused, the signed message must still include the vote version/domain bytes.

### Quorum Certificate

```rust
pub struct QuorumCertificate {
    pub version: u8,
    pub chain_id: String,
    pub epoch: u64,
    pub finalized_round: u64,
    pub anchor_round: u64,
    pub anchor_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    pub finality_digest: String,
    pub validator_set_hash: String,
    pub signer_bitmap: Vec<u8>,
    pub signed_stake: u128,
    pub total_stake: u128,
    pub aggregate_signature: Vec<u8>,
}
```

The `signer_bitmap` indexes validators in canonical validator-set order. The canonical order must be deterministic, preferably by validator address bytes.

## Threshold Rule

The threshold must be stake-weighted, not validator-count-weighted.

Valid QC condition:

```text
signed_stake * 3 > total_stake * 2
```

Use strict greater-than 2/3. Avoid floating point. Use `u128` arithmetic and checked/saturating guards where appropriate.

For the current one-validator testnet, one signer with 100% stake is a valid QC. That makes migration possible without special consensus rules.

## Signing Flow

1. Consensus commits an anchor through the existing DAG/BFT path.
2. The node constructs `FinalityVote` from the committed anchor and block execution result.
3. Validator nodes with active stake and BLS keys sign the canonical `FinalityVote`.
4. Votes are collected through the existing network layer or a dedicated finality-vote topic/message.
5. Once collected stake exceeds 2/3, the node aggregates signatures.
6. The node stores a `QuorumCertificate`.
7. The checkpoint/finality artifact includes or references the QC.

## Verification Algorithm

Inputs:

- trusted validator set for the relevant epoch
- candidate `QuorumCertificate`
- canonical vote bytes reconstructed from QC fields

Algorithm:

1. Verify `chain_id`.
2. Verify `validator_set_hash`.
3. Decode signer bitmap.
4. Reject duplicate/out-of-range signers.
5. Sum signer stake from the trusted validator set.
6. Reject if `signed_stake` in QC does not match recomputed stake.
7. Reject if stake threshold is not greater than 2/3.
8. Collect BLS public keys for bitmap signers.
9. Run `BLSEngine::fast_aggregate_verify(vote_bytes, signer_pubkeys, aggregate_signature)`.
10. Accept only if BLS verification succeeds.

Pseudo-code:

```rust
fn verify_qc(qc: &QuorumCertificate, validators: &[ValidatorInfo]) -> Result<bool> {
    let vote = FinalityVote::from_qc(qc);
    let vote_bytes = vote.to_canonical_bytes();
    let signers = decode_bitmap(&qc.signer_bitmap, validators.len())?;
    let signed_stake = sum_stake(&signers, validators)?;

    ensure!(signed_stake == qc.signed_stake);
    ensure!(qc.total_stake == sum_total_stake(validators));
    ensure!(signed_stake * 3 > qc.total_stake * 2);

    let pubkeys = signers
        .iter()
        .map(|idx| validators[*idx].bls_public_key_bytes())
        .collect::<Vec<_>>();

    BLSEngine::consensus()
        .fast_aggregate_verify(&vote_bytes, &pubkeys, &qc.aggregate_signature)
}
```

## Storage Plan

Add new keys:

```text
consensus:qc:{round}
consensus:qc:latest
sys:validator_set:v1
```

Do not overload existing `dag:checkpoint_sig:{round}`. That key currently means single-node Ed25519 checkpoint integrity. Reusing it for BLS quorum would create audit ambiguity.

Checkpoint artifact v2 should contain:

```rust
pub struct CheckpointV2 {
    pub version: u8,
    pub round: u64,
    pub latest_block_height: u64,
    pub latest_block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    pub finality_digest: String,
    pub validator_set_hash: String,
    pub qc: QuorumCertificate,
}
```

Important: long-term checkpoints should not dump the full recent DAG. The current bounded checkpoint is operationally safe, but trustless snapshot sync wants compact metadata plus QC.

## Migration Plan

### Phase 0: Spec/Test Only

- Add data structures behind tests.
- Add canonical encoding tests.
- Add synthetic QC verification tests using in-memory validators.

No node behavior change.

### Phase 1: Validator Metadata

- Add BLS key generation/loading.
- **Add `prove_possession` / `verify_possession` to the BLS engine (separate POP DST).**
- Add BLS public key **+ proof-of-possession** to genesis validator records;
  **reject any BLS key whose PoP does not verify** (genesis AND join_validator_set).
- Add versioned `sys:validator_set:v1`.
- Keep legacy `sys:validators` for old call sites.

### Phase 2: QC Creation

- Produce a single-validator QC on current testnet.
- Store `consensus:qc:{round}` and `consensus:qc:latest`.
- Keep current Ed25519 checkpoint signature in parallel.

### Phase 3: QC Verification

- Add RPC:
  - `aincore_getLatestQuorumCertificate`
  - `aincore_getQuorumCertificate(round)`
  - `aincore_getValidatorSet(epoch)`
- Add boot-time optional QC verification.
- Do not make QC mandatory until it is proven stable in testnet.

### Phase 4: Multi-Validator

- Enable multiple validators with BLS keys.
- Use stake-weighted quorum.
- Reject QC below threshold.
- Add negative tests for forged bitmap, wrong stake, wrong message, wrong validator set, and duplicate signer.

### Phase 5: Trustless Sync

- Let new observer nodes bootstrap from latest QC-backed checkpoint.
- State snapshot sync can be built on top after QC verification is stable.

## Tests Required Before Shipping

- BLS aggregate verify succeeds for same-message votes.
- BLS verify rejects:
  - wrong message
  - wrong signer public key
  - missing signer
  - forged signer bitmap
  - duplicate signer
  - signed stake below threshold
  - QC from wrong chain ID
  - QC from wrong validator set hash
- Single-validator QC validates in 1-of-1 testnet.
- Multi-validator weighted case validates, including a high-stake minority that must not pass alone.
- Legacy checkpoint Ed25519 signature remains separate from BLS QC.
- **Proof-of-possession verifies for an honestly generated key; registration REJECTS a key with a missing or invalid PoP.**
- **Rogue-key resistance: a constructed cancelling key cannot be registered (PoP fails), so it can never enter an aggregate.**
- **Finality-vote equivocation (two different votes, same epoch+round) is detected and slashable.**

## Dependencies & Liveness Notes

- **Cross-epoch verification depends on a real epoch / validator-set-transition
  object, which AINCORE does not yet have.** Today "epoch" is only a slashing
  window (`current_round/50` in `dag.rs`). For a STATIC / single validator set,
  QC verification works with `validator_set_hash` alone. But once validators
  join/leave, a light client must be able to roll trust forward across set
  changes — that requires an EpochChangeProof / waypoint chain (Aptos) bound to
  each validator-set transition. `validator_set_hash` in the QC is necessary but
  NOT sufficient for multi-epoch trustless sync. Track this as a coupled P0
  (validator rotation) prerequisite for Phase 4/5.
- **Finality-vote equivocation is slashable.** A validator that BLS-signs two
  different `FinalityVote`s for the same `(epoch, finalized_round)` has
  double-signed and MUST be slashed, mirroring the existing consensus
  equivocation slash. Add this to the slashing rules and to the negative tests.
- **QC formation failure is NOT a consensus halt.** Consensus (DAG/BFT) commits
  anchors independently. The QC is a proof layer on top. If fewer than 2/3 stake
  sign a round's `FinalityVote` (slow/offline validators), the QC for that round
  simply does not form — the chain keeps progressing, and a light client uses the
  next QC-backed round. QC liveness must never be wired as a precondition for
  block/finality liveness.

## Design Warnings

- **Proof-of-possession is mandatory** (see dedicated section). Without it,
  `fast_aggregate_verify` over a common message is forgeable via rogue keys.
- Do not aggregate current vertex signatures as QC. They sign different vertex messages, not a single finality message.
- Do not make QC count-based. A validator with 1% stake must not equal one with 60% stake.
- Do not sign JSON. Use canonical bytes.
- Do not reuse `dag:checkpoint_sig:{round}` for quorum proofs.
- Do not call a single-node Ed25519 checkpoint trustless.
- Do not make bridge/light-client claims until QC verification works against validator-set data.
- Do not reuse the consensus signing DST for the PoP. Distinct DST per use.

## Current Verdict

AINCORE has the BLS crypto engine and enough consensus metadata to build QC without replacing consensus.

The real missing work is wiring:

1. BLS validator identity
2. canonical finality vote
3. stake-weighted quorum accounting
4. QC storage and verification
5. migration from 1 validator to N validators

This is the correct next architectural root before serious bridge, light client, or incentivized validator work.
