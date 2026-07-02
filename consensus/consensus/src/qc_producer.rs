//! QC Phase 2 — live quorum-certificate production (side-effect-only).
//!
//! This module wires the keystone (`crate::qc`) into the live commit path. After
//! a block is committed AND executed (state root known), the node:
//!   1. reads the active validator set (`sys:validator_set:v1`, written at genesis
//!      by B1, carrying each validator's BLS public key + PoP),
//!   2. derives ITS OWN BLS secret from the persistent node identity (the SAME
//!      derivation genesis used — `SHA256(VALIDATOR_BLS_DOMAIN || node_key)`),
//!   3. signs the canonical `FinalityVote` for the committed block,
//!   4. if this node's stake alone meets the strict >2/3 quorum (the live
//!      single-validator / supermajority-holder topology), aggregates a complete
//!      1-of-1 QC, self-verifies it, and stores it; otherwise records the node's
//!      partial vote AND gossips it so peers can aggregate (Phase 3).
//!
//! ## Phase 3 — multi-party aggregation
//! When no single node holds >2/3 stake, every validator broadcasts its partial
//! `FinalityVote` signature (`QC_VOTE:{json}`). On receiving a valid vote a node
//! verifies the single BLS signature against the signer's key in the FROZEN epoch
//! validator set, checks the vote matches THIS node's committed
//! (round, block_hash, validator_set_hash), persists it (deduped per
//! (round, signer)), and then deterministically attempts aggregation: if the set
//! of distinct collected signers' stake is >2/3 it builds the aggregate QC via
//! [`crate::qc::build_qc`], `verify_qc`s it, and stores the complete QC under the
//! same keys [`produce_and_store_qc`] uses. Aggregation is deterministic given
//! the same collected vote set, and a QC is NEVER stored unless it verifies.
//!
//! ## SAFETY INVARIANT — additive only
//! QC production is NOT a precondition for commit or finality. Every fallible
//! step returns `None` / logs and the commit path continues unchanged. A bug
//! here can at worst fail to produce an attestation; it can never fork, halt, or
//! alter consensus. QC keys (`consensus:qc:*`) are consensus metadata, written
//! with the same direct-`put` pattern as DAG checkpoints — they are not Move
//! state and do not enter the state root.

use crate::qc::{self, build_qc, verify_qc, FinalityVote, QuorumCertificate, ValidatorInfo};
use serde::{Deserialize, Serialize};
use storage::StateDB;

pub use crate::qc::derive_validator_bls_seed;

/// Upper bound on distinct partial votes retained + aggregated per anchor round.
/// Prevents an unbounded set of votes (e.g. many small validators, or repeated
/// distinct signers) from growing storage / aggregation cost without limit. A
/// round can never have more legitimate voters than the validator-set size; this
/// is a hard backstop far above any realistic set so it never rejects an honest
/// vote.
const MAX_VOTES_PER_ROUND: usize = 10_000;

/// A signed partial finality vote, gossiped to peers for multi-party QC
/// aggregation (Phase 3). Carries the FULL [`FinalityVote`] so the receiver
/// reconstructs byte-identical signing bytes, plus the signer's address (for the
/// dedup key) and its compact BLS signature (hex). The signer's canonical index
/// and BLS pubkey are resolved by the receiver from the frozen epoch validator
/// set — never trusted from the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QcVoteMessage {
    /// The exact vote this node signed (binds chain_id, epoch, round, hashes,
    /// state/receipts roots, finality digest, and validator_set_hash).
    pub vote: FinalityVote,
    /// Address of the signing validator (used only for the dedup key; the BLS
    /// key and stake are looked up authoritatively from the trusted set).
    pub signer_address: String,
    /// Compressed BLS signature over `vote.to_signing_bytes()`, hex-encoded.
    pub signature: String,
}

/// Load and parse the active validator set written by B1 at genesis. This is the
/// LIVE set (`sys:validator_set:v1`) — it may change mid-epoch as validators
/// join/leave. For QC production/verification prefer [`load_validator_set_for_epoch`].
pub fn load_validator_set_v1(storage: &StateDB) -> Option<Vec<ValidatorInfo>> {
    let raw = storage.get("sys:validator_set:v1").ok()??;
    let set: Vec<ValidatorInfo> = serde_json::from_str(&raw).ok()?;
    if set.is_empty() {
        None
    } else {
        Some(set)
    }
}

/// SEC-#16: load the validator set FROZEN for a given consensus epoch.
///
/// QCs for any round in epoch `E` are produced AND verified against
/// `sys:validator_set:epoch:{E}` — a snapshot taken at the `E-1 -> E` boundary by
/// the executor — so the set (and its `validator_set_hash`) is stable for the
/// whole epoch even if validators join/leave mid-epoch (a join during `E`
/// activates in `E+1`, when the next snapshot captures it). Falls back to the
/// live `sys:validator_set:v1` when no snapshot exists (epoch 0 / pre-rotation /
/// older DBs), so single-validator and legacy behaviour is unchanged.
pub fn load_validator_set_for_epoch(storage: &StateDB, epoch: u64) -> Option<Vec<ValidatorInfo>> {
    if let Ok(Some(raw)) = storage.get(&format!("sys:validator_set:epoch:{}", epoch)) {
        if let Ok(set) = serde_json::from_str::<Vec<ValidatorInfo>>(&raw) {
            if !set.is_empty() {
                return Some(set);
            }
        }
    }
    load_validator_set_v1(storage)
}

/// Commit context captured at the point a block is finalized + executed.
pub struct CommitContext {
    pub chain_id: String,
    pub epoch: u64,
    pub finalized_round: u64,
    pub anchor_round: u64,
    pub anchor_hash: String,
    pub block_height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub receipts_root: String,
    /// The canonical finality digest computed by the ordering engine for this
    /// committed anchor (reused so the QC binds to the exact digest consensus
    /// finalized over, not a separately-recomputed one).
    pub finality_digest: String,
}

/// Outcome of contributing THIS node's signature to a committed block.
///
/// Distinguishes the live single-validator / supermajority case (a complete QC
/// was produced) from the multi-party case (only a partial vote — the caller
/// should gossip it so peers can aggregate). `None`/abort cases are folded into
/// [`QcOutcome::Skipped`].
#[derive(Debug, Clone)]
pub enum QcOutcome {
    /// A complete, self-verified >2/3 QC was produced + stored.
    Complete(QuorumCertificate),
    /// Sub-quorum: this node's partial vote was recorded; gossip it for Phase-3
    /// aggregation. The caller broadcasts `QC_VOTE:{json(message)}`.
    Partial(QcVoteMessage),
    /// Nothing produced (not a validator, derivation drift, set unavailable, …).
    Skipped,
}

/// Produce (and store) a quorum certificate for a committed block, contributing
/// THIS node's BLS signature. Returns [`QcOutcome::Complete`] iff a complete
/// quorum (strictly more than 2/3 stake) was achievable from this node alone
/// (the live single-validator / supermajority case); otherwise
/// [`QcOutcome::Partial`] carrying the gossipable vote, or [`QcOutcome::Skipped`].
/// Side-effect-only; never affects the commit path.
pub fn produce_and_store_qc(
    storage: &StateDB,
    node_key: &[u8; 32],
    node_address: &str,
    ctx: &CommitContext,
) -> QcOutcome {
    // SEC-#16: bind the QC to the validator set FROZEN for this commit's epoch,
    // so the validator_set_hash is stable across the whole epoch (matches what
    // verifiers use via load_validator_set_for_epoch(qc.epoch)).
    let validators = match load_validator_set_for_epoch(storage, ctx.epoch) {
        Some(v) => v,
        None => return QcOutcome::Skipped,
    };
    let ordered = qc::canonical_order(&validators);

    // Position of this node in the canonical set, by validator address.
    let my_idx = match ordered.iter().position(|v| v.address == node_address) {
        Some(i) => i,
        None => return QcOutcome::Skipped,
    };

    let vote = FinalityVote {
        chain_id: ctx.chain_id.clone(),
        epoch: ctx.epoch,
        finalized_round: ctx.finalized_round,
        anchor_round: ctx.anchor_round,
        anchor_hash: ctx.anchor_hash.clone(),
        block_height: ctx.block_height,
        block_hash: ctx.block_hash.clone(),
        state_root: ctx.state_root.clone(),
        receipts_root: ctx.receipts_root.clone(),
        finality_digest: ctx.finality_digest.clone(),
        validator_set_hash: qc::validator_set_hash(&validators),
    };

    let seed = derive_validator_bls_seed(node_key);
    let bls = crypto::bls::BLSEngine::consensus();

    // Derived pubkey MUST equal the genesis-registered key for our address; if it
    // does not, derivation drift / misconfig — abort (a QC that can never verify
    // must not be produced).
    let our_pk = hex::encode(bls.pubkey_raw(&seed));
    if our_pk != ordered[my_idx].bls_public_key {
        eprintln!(
            "🚨 [QC] derived BLS pubkey != genesis-registered key for {node_address} — skipping QC production"
        );
        return QcOutcome::Skipped;
    }

    let sig = bls.sign_raw(&vote.to_signing_bytes(), &seed);

    // Does our stake alone meet the strict >2/3 quorum (single-validator or
    // supermajority holder)? If not, record the partial vote for Phase 3
    // aggregation, ALSO record our own vote into the collected-vote store (so a
    // later inbound peer vote can aggregate against ours), and return it for the
    // caller to gossip. No complete QC is produced.
    let my_stake = ordered[my_idx].stake as u128;
    let total_stake: u128 = ordered.iter().map(|v| v.stake as u128).sum();
    if !qc::stake_quorum_met(my_stake, total_stake) {
        // Legacy single-vote key (kept for backward-compat / forensics).
        let key = format!("consensus:qc_vote:{}:{}", ctx.anchor_round, node_address);
        let _ = storage.put(&key, &hex::encode(&sig));
        // Persist our own vote into the aggregation store so an incoming peer
        // vote can combine with it. Self-store can race a same-round QC already
        // built (idempotent) — harmless.
        store_collected_vote(storage, ctx.anchor_round, node_address, &hex::encode(&sig));
        return QcOutcome::Partial(QcVoteMessage {
            vote,
            signer_address: node_address.to_string(),
            signature: hex::encode(&sig),
        });
    }

    let qc = match build_qc(&vote, &validators, &[my_idx], std::slice::from_ref(&sig)) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("🚨 [QC] build_qc failed: {e} — skipping");
            return QcOutcome::Skipped;
        }
    };

    // Self-verify before storing: an unverifiable QC must never be persisted.
    if let Err(e) = verify_qc(&qc, &validators, &qc.chain_id) {
        eprintln!("🚨 [QC] self-verify failed: {e} — not storing");
        return QcOutcome::Skipped;
    }

    match serde_json::to_string(&qc) {
        Ok(json) => {
            let _ = storage.put(&format!("consensus:qc:{}", ctx.block_height), &json);
            let _ = storage.put(&format!("consensus:qc_by_round:{}", ctx.anchor_round), &json);
            let _ = storage.put("consensus:qc:latest", &json);
            let _ = storage.put(
                "consensus:qc:latest_height",
                &ctx.block_height.to_string(),
            );
            let _ = storage.put(
                "consensus:qc:latest_round",
                &ctx.anchor_round.to_string(),
            );
            println!(
                "🔏 [QC] stored quorum cert for block #{} (signed_stake={}/{} > 2/3)",
                ctx.block_height, qc.signed_stake, qc.total_stake
            );
        }
        Err(e) => {
            eprintln!("🚨 [QC] serialize failed: {e} — not storing");
            return QcOutcome::Skipped;
        }
    }

    QcOutcome::Complete(qc)
}

/// Storage key prefix under which the per-(round, signer) collected votes live.
/// Distinct from the legacy `consensus:qc_vote:{round}:{addr}` single-vote key so
/// the Phase-3 aggregation store can be reasoned about / bounded independently.
fn collected_vote_key(round: u64, signer_address: &str) -> String {
    format!("consensus:qc_vote_agg:{}:{}", round, signer_address)
}

/// Persist a collected partial-vote signature (hex) for `(round, signer)`,
/// deduped: re-storing the same signer is idempotent and does not grow the set.
/// Returns `true` if this was a NEW distinct signer (set grew), `false` if it was
/// already present or the per-round bound was hit.
fn store_collected_vote(
    storage: &StateDB,
    round: u64,
    signer_address: &str,
    sig_hex: &str,
) -> bool {
    let key = collected_vote_key(round, signer_address);
    // Dedup per (round, signer): if we already have a vote for this signer at
    // this round, do not overwrite or re-count it.
    if matches!(storage.get(&key), Ok(Some(_))) {
        return false;
    }
    // Bound the number of distinct signers retained per round.
    if collected_signers(storage, round).len() >= MAX_VOTES_PER_ROUND {
        eprintln!(
            "⚠️ [QC] vote store for round {round} hit MAX_VOTES_PER_ROUND — dropping vote from {signer_address}"
        );
        return false;
    }
    let _ = storage.put(&key, sig_hex);
    true
}

/// Enumerate the distinct signer addresses that have a collected vote for `round`,
/// in deterministic (storage-prefix-sorted) order. Returned as `(address, sig_hex)`.
fn collected_signers(storage: &StateDB, round: u64) -> Vec<(String, String)> {
    let prefix = format!("consensus:qc_vote_agg:{}:", round);
    let mut out: Vec<(String, String)> = storage
        .scan_prefix(&prefix)
        .into_iter()
        .filter_map(|(k, v)| {
            k.strip_prefix(&prefix)
                .map(|addr| (addr.to_string(), v))
        })
        .collect();
    // Deterministic order so two nodes aggregating the same vote set behave
    // identically (the QC is canonicalized by build_qc anyway, but ordering the
    // inputs keeps logs / bounds stable).
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Collect an inbound peer finality vote and, if the collected set now meets the
/// strict >2/3 quorum, deterministically aggregate + store a complete QC.
///
/// Steps (all fail-closed — any error returns [`QcOutcome::Skipped`] and never
/// affects consensus):
///   1. Resolve the FROZEN validator set for `msg.vote.epoch`.
///   2. Bind the vote to THIS node's committed block: its `validator_set_hash`
///      MUST equal the trusted set's hash, AND (when we have a locally produced
///      reference vote at the same round) its `block_hash` MUST match — this is
///      the "matches THIS node's committed (round, block_hash, validator_set_hash)"
///      check. A vote over a different fork/round is dropped.
///   3. Locate the signer in the canonical set; verify the SINGLE BLS signature
///      against the signer's registered key over `vote.to_signing_bytes()`.
///   4. Dedup-persist the vote (`consensus:qc_vote_agg:{round}:{addr}`).
///   5. Gather all collected signers; if their distinct stake is >2/3, build the
///      aggregate QC via `build_qc`, `verify_qc` it, and store it (same keys as
///      [`produce_and_store_qc`]). A QC is NEVER stored unless it verifies.
///
/// `expected_block_hash` is THIS node's committed block hash for the vote's
/// anchor round, if known (e.g. from the QC the node is trying to assemble). When
/// `None`, the validator_set_hash + BLS-over-exact-vote binding still prevents
/// cross-fork aggregation (a vote for a different block has a different signature
/// payload and cannot combine into a verifying QC), but passing it tightens the
/// check to an explicit early reject.
pub fn collect_vote_and_try_aggregate(
    storage: &StateDB,
    msg: &QcVoteMessage,
    expected_block_hash: Option<&str>,
) -> QcOutcome {
    let vote = &msg.vote;

    // (1) Frozen validator set for the vote's epoch.
    let validators = match load_validator_set_for_epoch(storage, vote.epoch) {
        Some(v) => v,
        None => return QcOutcome::Skipped,
    };
    let ordered = qc::canonical_order(&validators);

    // (2) Bind to the exact set this node verifies against.
    let expected_set_hash = qc::validator_set_hash(&validators);
    if vote.validator_set_hash != expected_set_hash {
        // Vote is over a different validator set — cannot aggregate into a QC
        // that verifies against ours.
        return QcOutcome::Skipped;
    }
    // Bind to THIS node's committed block at this round when known.
    if let Some(bh) = expected_block_hash {
        if vote.block_hash != bh {
            return QcOutcome::Skipped;
        }
    }

    // (3) Locate signer + verify the single BLS signature against its key.
    let signer_idx = match ordered.iter().position(|v| v.address == msg.signer_address) {
        Some(i) => i,
        None => return QcOutcome::Skipped, // signer not in the trusted set
    };
    let sig_bytes = match hex::decode(&msg.signature) {
        Ok(b) => b,
        Err(_) => return QcOutcome::Skipped,
    };
    let pk_bytes = match hex::decode(&ordered[signer_idx].bls_public_key) {
        Ok(b) => b,
        Err(_) => return QcOutcome::Skipped,
    };
    let bls = crypto::bls::BLSEngine::consensus();
    let vote_bytes = vote.to_signing_bytes();
    match bls.verify(&vote_bytes, &sig_bytes, &pk_bytes) {
        Ok(true) => {}
        _ => return QcOutcome::Skipped, // bad signature — drop, never store
    }

    // (4) Dedup-persist this signer's vote for the round.
    store_collected_vote(storage, vote.anchor_round, &msg.signer_address, &msg.signature);

    // If a complete QC for this round already exists, nothing more to do.
    if matches!(
        storage.get(&format!("consensus:qc_by_round:{}", vote.anchor_round)),
        Ok(Some(_))
    ) {
        return QcOutcome::Skipped;
    }

    // (5) Attempt deterministic aggregation over the collected vote set.
    let collected = collected_signers(storage, vote.anchor_round);
    let mut indices: Vec<usize> = Vec::with_capacity(collected.len());
    let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(collected.len());
    let mut signed_stake: u128 = 0;
    let total_stake: u128 = ordered.iter().map(|v| v.stake as u128).sum();
    for (addr, sig_hex) in &collected {
        // Re-resolve each collected signer against the trusted set; ignore any
        // that are no longer present (defensive — set is frozen per-epoch).
        let Some(idx) = ordered.iter().position(|v| &v.address == addr) else {
            continue;
        };
        let Ok(raw) = hex::decode(sig_hex) else {
            continue;
        };
        indices.push(idx);
        sigs.push(raw);
        signed_stake += ordered[idx].stake as u128;
    }

    if !qc::stake_quorum_met(signed_stake, total_stake) {
        // Not enough stake yet — keep collecting.
        return QcOutcome::Skipped;
    }

    let qc = match build_qc(vote, &validators, &indices, &sigs) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("🚨 [QC] aggregate build_qc failed: {e} — not storing");
            return QcOutcome::Skipped;
        }
    };
    // NEVER store an unverifiable QC.
    if let Err(e) = verify_qc(&qc, &validators, &qc.chain_id) {
        eprintln!("🚨 [QC] aggregate self-verify failed: {e} — not storing");
        return QcOutcome::Skipped;
    }

    match serde_json::to_string(&qc) {
        Ok(json) => {
            let _ = storage.put(&format!("consensus:qc:{}", vote.block_height), &json);
            let _ = storage.put(
                &format!("consensus:qc_by_round:{}", vote.anchor_round),
                &json,
            );
            let _ = storage.put("consensus:qc:latest", &json);
            let _ = storage.put("consensus:qc:latest_height", &vote.block_height.to_string());
            let _ = storage.put("consensus:qc:latest_round", &vote.anchor_round.to_string());
            println!(
                "🔏 [QC] AGGREGATED quorum cert for block #{} from {} votes (signed_stake={}/{} > 2/3)",
                vote.block_height,
                indices.len(),
                qc.signed_stake,
                qc.total_stake
            );
        }
        Err(e) => {
            eprintln!("🚨 [QC] aggregate serialize failed: {e} — not storing");
            return QcOutcome::Skipped;
        }
    }

    QcOutcome::Complete(qc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qc::ValidatorInfo;

    fn validator_for(node_key: &[u8; 32], stake: u64, address: &str) -> ValidatorInfo {
        let bls = crypto::bls::BLSEngine::consensus();
        let seed = derive_validator_bls_seed(node_key);
        ValidatorInfo {
            address: address.to_string(),
            stake,
            ed25519_public_key: "00".repeat(32),
            bls_public_key: hex::encode(bls.pubkey_raw(&seed)),
            bls_pop: hex::encode(bls.prove_possession_raw(&seed)),
        }
    }

    fn ctx_for(height: u64) -> CommitContext {
        CommitContext {
            chain_id: "AINCORE-TEST-1".into(),
            epoch: 0,
            finalized_round: height + 2,
            anchor_round: height,
            anchor_hash: "ab".repeat(32),
            block_height: height,
            block_hash: "cd".repeat(32),
            state_root: "ef".repeat(32),
            receipts_root: "12".repeat(32),
            finality_digest: "34".repeat(32),
        }
    }

    #[test]
    fn single_validator_produces_verifiable_qc() {
        let dir = std::env::temp_dir().join(format!("qc_prod_single_{}", std::process::id()));
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();
        let node_key = [7u8; 32];
        let addr = "deadbeef";
        let v = validator_for(&node_key, 1_000_000, addr);
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&vec![v.clone()]).unwrap())
            .unwrap();

        let qc = match produce_and_store_qc(&storage, &node_key, addr, &ctx_for(42)) {
            QcOutcome::Complete(qc) => qc,
            other => panic!("single validator must produce a complete QC, got {other:?}"),
        };
        // The produced QC verifies against the trusted set.
        assert!(verify_qc(&qc, &[v], &qc.chain_id).is_ok());
        // And it was stored at the height key.
        assert!(storage.get("consensus:qc:42").unwrap().is_some());
        assert_eq!(
            storage.get("consensus:qc:latest_height").unwrap().as_deref(),
            Some("42")
        );
        assert_eq!(
            storage.get("consensus:qc:latest_round").unwrap().as_deref(),
            Some("42")
        );
        assert!(storage.get("consensus:qc:latest").unwrap().is_some());
        assert!(storage.get("consensus:qc_by_round:42").unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn observer_node_not_in_set_produces_nothing() {
        let dir = std::env::temp_dir().join(format!("qc_prod_obs_{}", std::process::id()));
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();
        // Set contains a DIFFERENT validator; our node_key is not registered.
        let other = validator_for(&[9u8; 32], 1_000_000, "aaaa");
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&vec![other]).unwrap())
            .unwrap();

        let got = produce_and_store_qc(&storage, &[7u8; 32], "deadbeef", &ctx_for(7));
        assert!(
            matches!(got, QcOutcome::Skipped),
            "node not in validator set must produce no QC"
        );
        assert!(storage.get("consensus:qc:7").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn minority_stake_records_partial_vote_no_qc() {
        let dir = std::env::temp_dir().join(format!("qc_prod_minor_{}", std::process::id()));
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();
        let my_key = [7u8; 32];
        // Our node holds 10 of 100 total stake — far below >2/3.
        let me = validator_for(&my_key, 10, "bbbb");
        let big = validator_for(&[9u8; 32], 90, "aaaa");
        storage
            .put(
                "sys:validator_set:v1",
                &serde_json::to_string(&vec![me, big]).unwrap(),
            )
            .unwrap();

        let got = produce_and_store_qc(&storage, &my_key, "bbbb", &ctx_for(5));
        // Minority stake yields a gossipable partial vote, NOT a complete QC.
        assert!(
            matches!(got, QcOutcome::Partial(_)),
            "minority stake must yield a partial vote, not a complete QC"
        );
        // No complete QC stored, but a partial vote was recorded for Phase 3.
        assert!(storage.get("consensus:qc:5").unwrap().is_none());
        assert!(
            storage.get("consensus:qc_vote:5:bbbb").unwrap().is_some(),
            "partial vote must be recorded under anchor_round"
        );
        // And our own vote was placed into the aggregation store.
        assert!(
            storage.get("consensus:qc_vote_agg:5:bbbb").unwrap().is_some(),
            "self-vote must enter the aggregation store"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validator_set_hash_is_order_independent() {
        let a = validator_for(&[1u8; 32], 10, "zzzz");
        let b = validator_for(&[2u8; 32], 20, "aaaa");
        let h1 = qc::validator_set_hash(&[a.clone(), b.clone()]);
        let h2 = qc::validator_set_hash(&[b, a]);
        assert_eq!(h1, h2, "set hash must be canonical-order invariant");
    }

    /// SEC-#16: epoch resolution prefers the frozen per-epoch snapshot and falls
    /// back to the live set when no snapshot exists.
    #[test]
    fn load_validator_set_for_epoch_prefers_snapshot_then_falls_back() {
        let dir = std::env::temp_dir().join(format!("qc_prod_epoch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();

        let live = vec![validator_for(&[1u8; 32], 100, "aaaa")];
        let snap = vec![validator_for(&[2u8; 32], 200, "bbbb")];
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&live).unwrap())
            .unwrap();
        storage
            .put(
                "sys:validator_set:epoch:3",
                &serde_json::to_string(&snap).unwrap(),
            )
            .unwrap();

        // Exact snapshot for epoch 3.
        let got3 = load_validator_set_for_epoch(&storage, 3).expect("epoch 3 snapshot");
        assert_eq!(got3[0].address, "bbbb");
        // No snapshot for epoch 9 → fall back to the live set.
        let got9 = load_validator_set_for_epoch(&storage, 9).expect("fallback to live");
        assert_eq!(got9[0].address, "aaaa");
    }

    // ===== Phase 3: multi-party aggregation =====

    /// Build the canonical FinalityVote for `ctx` against `validators`, mirroring
    /// what `produce_and_store_qc` signs.
    fn vote_for(ctx: &CommitContext, validators: &[ValidatorInfo]) -> FinalityVote {
        FinalityVote {
            chain_id: ctx.chain_id.clone(),
            epoch: ctx.epoch,
            finalized_round: ctx.finalized_round,
            anchor_round: ctx.anchor_round,
            anchor_hash: ctx.anchor_hash.clone(),
            block_height: ctx.block_height,
            block_hash: ctx.block_hash.clone(),
            state_root: ctx.state_root.clone(),
            receipts_root: ctx.receipts_root.clone(),
            finality_digest: ctx.finality_digest.clone(),
            validator_set_hash: qc::validator_set_hash(validators),
        }
    }

    /// Construct a signed QcVoteMessage from `node_key` (deriving the BLS seed the
    /// same way production does).
    fn signed_vote_msg(node_key: &[u8; 32], address: &str, vote: &FinalityVote) -> QcVoteMessage {
        let bls = crypto::bls::BLSEngine::consensus();
        let seed = derive_validator_bls_seed(node_key);
        let sig = bls.sign_raw(&vote.to_signing_bytes(), &seed);
        QcVoteMessage {
            vote: vote.clone(),
            signer_address: address.to_string(),
            signature: hex::encode(&sig),
        }
    }

    /// Two validators each contributing a vote aggregate into a verifiable >2/3 QC.
    #[test]
    fn two_validators_aggregate_into_complete_qc() {
        let dir = std::env::temp_dir().join(format!("qc_agg_two_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();

        // 3 validators, stake 40/40/20. No single one is >2/3, but any two of the
        // 40s + the 20, or the two 40s (80/100), exceed it.
        let key_a = [11u8; 32];
        let key_b = [12u8; 32];
        let a = validator_for(&key_a, 40, "aaaa");
        let b = validator_for(&key_b, 40, "bbbb");
        let c = validator_for(&[13u8; 32], 20, "cccc");
        let set = vec![a.clone(), b.clone(), c.clone()];
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&set).unwrap())
            .unwrap();

        let ctx = ctx_for(100);
        let vote = vote_for(&ctx, &set);

        // First validator's vote: not enough stake alone (40/100) → no QC yet.
        let msg_a = signed_vote_msg(&key_a, "aaaa", &vote);
        let r1 = collect_vote_and_try_aggregate(&storage, &msg_a, Some(&ctx.block_hash));
        assert!(
            matches!(r1, QcOutcome::Skipped),
            "single 40/100 vote must not yet aggregate"
        );
        assert!(storage.get("consensus:qc:100").unwrap().is_none());

        // Second validator's vote: now 80/100 > 2/3 → complete QC produced.
        let msg_b = signed_vote_msg(&key_b, "bbbb", &vote);
        let r2 = collect_vote_and_try_aggregate(&storage, &msg_b, Some(&ctx.block_hash));
        let qc = match r2 {
            QcOutcome::Complete(qc) => qc,
            other => panic!("two votes (80/100) must aggregate into a complete QC, got {other:?}"),
        };
        assert!(verify_qc(&qc, &set, &qc.chain_id).is_ok(), "aggregated QC must verify");
        assert_eq!(qc.signed_stake, 80);
        assert_eq!(qc.total_stake, 100);
        // Stored under the canonical keys.
        assert!(storage.get("consensus:qc:100").unwrap().is_some());
        assert!(storage.get("consensus:qc_by_round:100").unwrap().is_some());
        assert_eq!(
            storage.get("consensus:qc:latest_height").unwrap().as_deref(),
            Some("100")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A vote with a bad signature must be rejected and never stored / aggregated.
    #[test]
    fn vote_with_bad_signature_rejected() {
        let dir = std::env::temp_dir().join(format!("qc_agg_badsig_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();

        let key_a = [11u8; 32];
        let a = validator_for(&key_a, 80, "aaaa");
        let b = validator_for(&[12u8; 32], 20, "bbbb");
        let set = vec![a, b];
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&set).unwrap())
            .unwrap();

        let ctx = ctx_for(101);
        let vote = vote_for(&ctx, &set);
        let mut msg = signed_vote_msg(&key_a, "aaaa", &vote);
        // Corrupt the signature (flip a hex nibble) so BLS verify fails.
        let mut sig = hex::decode(&msg.signature).unwrap();
        sig[0] ^= 0xff;
        msg.signature = hex::encode(&sig);

        let r = collect_vote_and_try_aggregate(&storage, &msg, Some(&ctx.block_hash));
        assert!(matches!(r, QcOutcome::Skipped), "bad-sig vote must be skipped");
        // Nothing persisted: no vote, no QC (even though aaaa alone holds 80/100).
        assert!(storage.get("consensus:qc_vote_agg:101:aaaa").unwrap().is_none());
        assert!(storage.get("consensus:qc:101").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A vote whose validator_set_hash does not match the trusted set is rejected.
    #[test]
    fn vote_with_wrong_validator_set_hash_rejected() {
        let dir = std::env::temp_dir().join(format!("qc_agg_wrongset_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();

        let key_a = [11u8; 32];
        let a = validator_for(&key_a, 80, "aaaa");
        let b = validator_for(&[12u8; 32], 20, "bbbb");
        let set = vec![a, b];
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&set).unwrap())
            .unwrap();

        let ctx = ctx_for(102);
        let mut vote = vote_for(&ctx, &set);
        // Tamper the validator_set_hash to a set we are NOT verifying against.
        vote.validator_set_hash = "00".repeat(32);
        // Sign the tampered vote (so the signature itself is valid over its bytes)
        // — the binding check must still reject it before/independent of BLS.
        let msg = signed_vote_msg(&key_a, "aaaa", &vote);

        let r = collect_vote_and_try_aggregate(&storage, &msg, Some(&ctx.block_hash));
        assert!(
            matches!(r, QcOutcome::Skipped),
            "vote bound to a different validator set must be skipped"
        );
        assert!(storage.get("consensus:qc_vote_agg:102:aaaa").unwrap().is_none());
        assert!(storage.get("consensus:qc:102").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A vote for a different committed block_hash than ours is rejected.
    #[test]
    fn vote_for_wrong_block_hash_rejected() {
        let dir = std::env::temp_dir().join(format!("qc_agg_wrongblk_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();

        let key_a = [11u8; 32];
        let a = validator_for(&key_a, 80, "aaaa");
        let b = validator_for(&[12u8; 32], 20, "bbbb");
        let set = vec![a, b];
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&set).unwrap())
            .unwrap();

        let ctx = ctx_for(103);
        let vote = vote_for(&ctx, &set);
        let msg = signed_vote_msg(&key_a, "aaaa", &vote);

        // We expect a DIFFERENT block hash for this round than the vote carries.
        let r = collect_vote_and_try_aggregate(&storage, &msg, Some(&"99".repeat(32)));
        assert!(
            matches!(r, QcOutcome::Skipped),
            "vote over a different block must be skipped"
        );
        assert!(storage.get("consensus:qc_vote_agg:103:aaaa").unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sub-quorum collection does NOT produce a complete QC; duplicate votes from
    /// the same signer do not double-count toward the threshold.
    #[test]
    fn subquorum_and_duplicate_votes_do_not_finalize() {
        let dir = std::env::temp_dir().join(format!("qc_agg_sub_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();

        // Stakes 40/40/20. Only one 40 votes (and votes twice) → 40/100, sub-quorum.
        let key_a = [11u8; 32];
        let a = validator_for(&key_a, 40, "aaaa");
        let b = validator_for(&[12u8; 32], 40, "bbbb");
        let c = validator_for(&[13u8; 32], 20, "cccc");
        let set = vec![a, b, c];
        storage
            .put("sys:validator_set:v1", &serde_json::to_string(&set).unwrap())
            .unwrap();

        let ctx = ctx_for(104);
        let vote = vote_for(&ctx, &set);
        let msg_a = signed_vote_msg(&key_a, "aaaa", &vote);

        let r1 = collect_vote_and_try_aggregate(&storage, &msg_a, Some(&ctx.block_hash));
        assert!(matches!(r1, QcOutcome::Skipped));
        // Same signer votes again — must be deduped, still 40/100.
        let r2 = collect_vote_and_try_aggregate(&storage, &msg_a, Some(&ctx.block_hash));
        assert!(
            matches!(r2, QcOutcome::Skipped),
            "duplicate vote from same signer must not reach quorum"
        );
        assert!(storage.get("consensus:qc:104").unwrap().is_none());
        // Exactly one distinct collected signer for the round.
        assert_eq!(collected_signers(&storage, 104).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
