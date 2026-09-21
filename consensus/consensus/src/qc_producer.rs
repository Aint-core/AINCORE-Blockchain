//! QC production with durable signing guards and acceptance-staged retry work.
//!
//! This module wires the keystone (`crate::qc`) into the live commit path. After
//! a block is committed AND executed (state root known), the node:
//!   1. resolves the block-height epoch and its retained validator snapshot
//!      (epoch 0 uses the immutable genesis committee described below),
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
//! QC production is not a precondition for local block acceptance, but signer
//! safety and durable publication are still security-critical. Local signing
//! guards and QC indexes commit in one synced transaction before an outcome is
//! returned for gossip. QC metadata is not Move state and does not enter the
//! execution root. These guards do not establish the correctness of ordering,
//! authenticated epoch transitions, or the caller's full supplied commit context.
//! Signing, aggregation and finality import additionally check epoch activation
//! intervals inside the same transaction as their publication.
//! Production local acceptance and synced-anchor adoption stage an exact QC
//! request atomically with their bookkeeping. The recovery worker retries it
//! against the held executed block and retained committee, keeping partial work
//! until a complete QC exists. This does not reconstruct historical requests
//! lost before the outbox existed or authenticate a substituted local database.

use crate::qc::{self, build_qc, verify_qc, FinalityVote, QuorumCertificate, ValidatorInfo};

mod recovery;
pub(crate) use recovery::{retry_pending_qcs, stage_pending_qc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
/// activates in `E+1`, when the next snapshot captures it). Missing, corrupt or
/// empty snapshots MUST NOT be replaced with today's committee. This includes
/// snapshots pruned by retention: absence is not evidence of membership.
///
/// Epoch 0 is defined by `genesis:validator_set:v1`, which genesis validation
/// binds to the chain identity. If an epoch-0 alias also exists, it must agree.
/// No epoch can borrow the mutable live set. This lookup trusts locally validated
/// genesis/history; it does not replace a pinned genesis or transition proof.
pub fn load_validator_set_for_epoch(storage: &StateDB, epoch: u64) -> Option<Vec<ValidatorInfo>> {
    if epoch == 0 {
        let raw = storage.get("genesis:validator_set:v1").ok()??;
        let set: Vec<ValidatorInfo> = serde_json::from_str(&raw).ok()?;
        if set.is_empty() {
            return None;
        }
        if let Some(alias) = storage.get("sys:validator_set:epoch:0").ok()? {
            let alias: Vec<ValidatorInfo> = serde_json::from_str(&alias).ok()?;
            if qc::canonical_order(&alias) != qc::canonical_order(&set) {
                return None;
            }
        }
        return Some(set);
    }
    if let Some(raw) = storage.get(&format!("sys:validator_set:epoch:{}", epoch)).ok()? {
        let set: Vec<ValidatorInfo> = serde_json::from_str(&raw).ok()?;
        return (!set.is_empty()).then_some(set);
    }
    None
}

/// Resolve the committee epoch for a block, not the epoch of the current tip.
/// The executor activates each new epoch at boundary_height + 1. Missing or
/// malformed retained boundaries are not permission to use today's committee.
/// This trusts locally executed metadata; it is not an epoch-transition proof.
pub fn epoch_for_block_height(storage: &StateDB, height: u64) -> Option<u64> {
    if height == 0 {
        return None;
    }
    let mut epoch = match storage.get("consensus:epoch").ok()? {
        Some(raw) => raw.parse::<u64>().ok()?,
        None => 0,
    };
    let mut upper_start = None;
    // Work bound, not a retention policy. The executor currently retains only
    // nine epochs; never scan an attacker-sized range from corrupt metadata.
    for _ in 0..64 {
        if epoch == 0 {
            return Some(0);
        }
        let start = storage.get(&format!("consensus:epoch_start_height:{epoch}")).ok()??
            .parse::<u64>().ok()?;
        if start < 2 || upper_start.is_some_and(|upper| start >= upper) {
            return None;
        }
        if height >= start {
            return Some(epoch);
        }
        upper_start = Some(start);
        epoch -= 1;
    }
    None
}

/// Commit context captured at the point a block is finalized + executed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
    with_durable_qc(storage, |view| produce_qc_staged(view, node_key, node_address, ctx))
}

fn with_durable_qc(
    storage: &StateDB,
    stage: impl FnOnce(&StateDB) -> Result<QcOutcome, String>,
) -> QcOutcome {
    let result = storage.transaction(|view| {
        let outcome = stage(&view).map_err(storage::StorageError::DatabaseOperation)?;
        #[cfg(test)]
        qc_crash_boundary(0, &outcome);
        Ok(outcome)
    });
    match result {
        Ok(outcome) => {
            #[cfg(test)]
            qc_crash_boundary(1, &outcome);
            if let QcOutcome::Complete(cert) = &outcome {
                println!("[QC] durably stored certificate for block #{}", cert.block_height);
            }
            outcome
        }
        Err(error) => {
            eprintln!("[QC] vote/certificate not published: {error}");
            QcOutcome::Skipped
        }
    }
}

#[cfg(test)]
fn qc_crash_boundary(boundary: u8, outcome: &QcOutcome) {
    if std::env::var("AINCORE_TEST_QC_BOUNDARY").ok().as_deref() == Some(&boundary.to_string()) {
        assert!(!matches!(outcome, QcOutcome::Skipped), "crash fixture never prepared a vote/QC");
        std::process::exit(77);
    }
}

// Only called inside the storage transaction. No signature may leave this
// callback until its signing guards and public records are durably committed.
fn produce_qc_staged(
    storage: &StateDB,
    node_key: &[u8; 32],
    node_address: &str,
    ctx: &CommitContext,
) -> Result<QcOutcome, String> {
    if epoch_for_block_height(storage, ctx.block_height) != Some(ctx.epoch) {
        return Ok(QcOutcome::Skipped);
    }
    // SEC-#16: bind the QC to the validator set FROZEN for this commit's epoch,
    // so the validator_set_hash is stable across the whole epoch (matches what
    // verifiers use via load_validator_set_for_epoch(qc.epoch)).
    let validators = match load_validator_set_for_epoch(storage, ctx.epoch) {
        Some(v) => v,
        None => return Ok(QcOutcome::Skipped),
    };
    let ordered = qc::canonical_order(&validators);

    // Position of this node in the canonical set, by validator address.
    let my_idx = match ordered.iter().position(|v| v.address == node_address) {
        Some(i) => i,
        None => return Ok(QcOutcome::Skipped),
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
    let public_key = bls.pubkey_raw(&seed);
    let our_pk = hex::encode(&public_key);
    if our_pk != ordered[my_idx].bls_public_key {
        eprintln!(
            "🚨 [QC] derived BLS pubkey != genesis-registered key for {node_address} — skipping QC production"
        );
        return Ok(QcOutcome::Skipped);
    }
    let signing_bytes = vote.to_signing_bytes();
    let guard_keys = signing_guard_keys(&vote, &our_pk);
    let mut previous = None;
    for key in &guard_keys {
        if let Some(raw) = storage.get(key).map_err(|e| e.to_string())? {
            let message: QcVoteMessage = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            if message.vote != vote || message.signer_address != node_address {
                return Err("conflicting local vote at an already-signed height or anchor round".to_string());
            }
            let signature = hex::decode(&message.signature).map_err(|e| e.to_string())?;
            if !bls.verify(&signing_bytes, &signature, &public_key).unwrap_or(false) {
                return Err("invalid persisted local signature".to_string());
            }
            previous = Some(signature);
        }
    }
    // Legacy stores contain only a signature, not the signed context. Validate
    // it against this exact request; never overwrite a conflicting old vote.
    for key in [
        format!("consensus:qc_vote:{}:{}", ctx.anchor_round, node_address),
        collected_vote_key(ctx.anchor_round, node_address),
    ] {
        if let Some(raw) = storage.get(&key).map_err(|e| e.to_string())? {
            let signature = hex::decode(raw).map_err(|e| e.to_string())?;
            if !bls.verify(&signing_bytes, &signature, &public_key).unwrap_or(false) {
                return Err("legacy local vote conflicts with requested signing bytes".to_string());
            }
            previous = Some(signature);
        }
    }
    ensure_certificate_slot(storage, &format!("consensus:qc:{}", ctx.block_height), &vote)?;
    ensure_certificate_slot(storage, &format!("consensus:qc_by_round:{}", ctx.anchor_round), &vote)?;
    let sig = previous.unwrap_or_else(|| bls.sign_raw(&signing_bytes, &seed));
    let message = QcVoteMessage {
        vote: vote.clone(), signer_address: node_address.to_string(), signature: hex::encode(&sig),
    };
    let encoded = serde_json::to_string(&message).map_err(|e| e.to_string())?;
    for key in guard_keys {
        storage.put(&key, &encoded).map_err(|e| e.to_string())?;
    }

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
        storage.put(&key, &message.signature).map_err(|e| e.to_string())?;
        // Persist our own vote into the aggregation store so an incoming peer
        // vote can combine with it. Self-store can race a same-round QC already
        // built (idempotent) — harmless.
        store_collected_vote(storage, ctx.anchor_round, node_address, &message.signature)?;
        return Ok(QcOutcome::Partial(message));
    }

    let qc = match build_qc(&vote, &validators, &[my_idx], std::slice::from_ref(&sig)) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("🚨 [QC] build_qc failed: {e} — skipping");
            return Err(e.to_string());
        }
    };

    // Self-verify before storing: an unverifiable QC must never be persisted.
    if let Err(e) = verify_qc(&qc, &validators, &qc.chain_id) {
        eprintln!("🚨 [QC] self-verify failed: {e} — not storing");
        return Err(e.to_string());
    }
    store_certificate(storage, &qc)?;
    Ok(QcOutcome::Complete(qc))
}

fn signing_guard_keys(vote: &FinalityVote, public_key: &str) -> [String; 2] {
    let chain = hex::encode(Sha256::digest(vote.chain_id.as_bytes()));
    let prefix = format!("consensus:qc_signing:v1:{chain}:{public_key}");
    [format!("{prefix}:height:{}", vote.block_height), format!("{prefix}:round:{}", vote.anchor_round)]
}

fn ensure_certificate_slot(storage: &StateDB, key: &str, vote: &FinalityVote) -> Result<(), String> {
    if let Some(raw) = storage.get(key).map_err(|e| e.to_string())? {
        let previous: QuorumCertificate = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if previous.finality_vote() != *vote {
            return Err(format!("conflicting certificate at {key}"));
        }
    }
    Ok(())
}

// Caller supplies a transaction view. All indexes describe one accepted QC;
// replay of an older height must not regress the latest pointer.
fn store_certificate(storage: &StateDB, cert: &QuorumCertificate) -> Result<(), String> {
    let height_key = format!("consensus:qc:{}", cert.block_height);
    let round_key = format!("consensus:qc_by_round:{}", cert.anchor_round);
    ensure_certificate_slot(storage, &height_key, &cert.finality_vote())?;
    ensure_certificate_slot(storage, &round_key, &cert.finality_vote())?;
    let latest_height = storage.get("consensus:qc:latest_height").map_err(|e| e.to_string())?
        .map(|raw| raw.parse::<u64>()).transpose().map_err(|e| e.to_string())?;
    let latest = storage.get("consensus:qc:latest").map_err(|e| e.to_string())?
        .map(|raw| serde_json::from_str::<QuorumCertificate>(&raw)).transpose().map_err(|e| e.to_string())?;
    if let (Some(height), Some(latest)) = (latest_height, &latest) {
        if height != latest.block_height { return Err("inconsistent latest QC pointer".to_string()); }
    }
    if latest_height.is_some() != latest.is_some() {
        return Err("incomplete latest QC pointer/body".to_string());
    }
    let high_water = latest.as_ref().map(|q| q.block_height).unwrap_or(0);
    if latest.is_some() && cert.block_height == high_water {
        ensure_certificate_slot(storage, "consensus:qc:latest", &cert.finality_vote())?;
    }
    let json = serde_json::to_string(cert).map_err(|e| e.to_string())?;
    storage.put(&height_key, &json).map_err(|e| e.to_string())?;
    storage.put(&round_key, &json).map_err(|e| e.to_string())?;
    if cert.block_height >= high_water {
        storage.put("consensus:qc:latest", &json).map_err(|e| e.to_string())?;
        storage.put("consensus:qc:latest_height", &cert.block_height.to_string()).map_err(|e| e.to_string())?;
        storage.put("consensus:qc:latest_round", &cert.anchor_round.to_string()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Verify an imported finality QC against local epoch membership and a held
/// block, then publish all finality metadata and QC indexes in one durable batch.
/// Returns false for missing committee/block or an already-finalized round.
/// The held block must have passed the caller's block-acceptance pipeline; this
/// does not execute blocks, prove epoch transitions, or advance ordering memory.
pub fn import_finality_qc(storage: &StateDB, cert: &QuorumCertificate) -> Result<bool, String> {
    let advanced = storage.transaction(|view| {
        stage_imported_finality(&view, cert).map_err(storage::StorageError::DatabaseOperation)
    }).map_err(|e| e.to_string())?;
    #[cfg(test)]
    if advanced {
        qc_import_crash_boundary(2);
    }
    Ok(advanced)
}

fn stage_imported_finality(storage: &StateDB, cert: &QuorumCertificate) -> Result<bool, String> {
    match epoch_for_block_height(storage, cert.block_height) {
        None => return Ok(false),
        Some(epoch) if epoch != cert.epoch => {
            return Err("finality QC epoch does not match the block's retained activation interval".into());
        }
        Some(_) => {}
    }
    let Some(validators) = load_validator_set_for_epoch(storage, cert.epoch) else {
        return Ok(false);
    };
    verify_qc(cert, &validators, &qc::expected_chain_id())
        .map_err(|e| format!("finality QC verification failed: {e:?}"))?;
    let current = storage.get("consensus:finalized_round").map_err(|e| e.to_string())?
        .map(|raw| raw.parse::<u64>()).transpose().map_err(|e| e.to_string())?.unwrap_or(0);
    if cert.finalized_round == 0 || cert.finalized_round <= current {
        return Ok(false);
    }
    if cert.anchor_round > cert.finalized_round {
        return Err("QC anchor round exceeds finalized round".into());
    }
    let Some(json) = storage.get(&format!("block_{}", cert.block_height)).map_err(|e| e.to_string())? else {
        return Ok(false);
    };
    let block: blockchain::Block = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    if block.header.hash != cert.block_hash {
        return Err(format!("finality QC block_hash differs from local block_{}", cert.block_height));
    }
    // A stored hash string alone does not bind the held body or the redundant
    // fields signed in the QC. Validate before publishing any finality rows.
    if block.header.height != cert.block_height
        || block.header.round != cert.anchor_round
        || block.anchor_hash != cert.anchor_hash
        || block.header.state_root != cert.state_root
        || block.header.receipts_root != cert.receipts_root
    {
        return Err("finality QC fields differ from the held block".into());
    }
    if blockchain::calculate_header_hash(&block.header) != block.header.hash
        || blockchain::calculate_tx_hash(&block.transactions) != block.header.tx_hash
        || blockchain::calculate_vertices_root(&block.committed_vertices) != block.header.vertices_root
        || blockchain::calculate_evidence_root(&block.slash_evidence) != block.header.evidence_root
    {
        return Err("finality QC held block has inconsistent header/body commitments".into());
    }

    storage.put("consensus:finalized_round", &cert.finalized_round.to_string()).map_err(|e| e.to_string())?;
    #[cfg(test)]
    qc_import_crash_boundary(0);
    storage.put("consensus:last_anchor_round", &cert.anchor_round.to_string()).map_err(|e| e.to_string())?;
    storage.put("consensus:last_anchor_hash", &cert.anchor_hash).map_err(|e| e.to_string())?;
    storage.put("consensus:finality_digest", &cert.finality_digest).map_err(|e| e.to_string())?;
    // Conflict/serialization failure rolls back even the staged finality marker.
    store_certificate(storage, cert)?;
    #[cfg(test)]
    qc_import_crash_boundary(1);
    Ok(true)
}

#[cfg(test)]
fn qc_import_crash_boundary(boundary: u8) {
    if std::env::var("AINCORE_TEST_QC_IMPORT_BOUNDARY").ok().as_deref() == Some(&boundary.to_string()) {
        std::process::exit(77);
    }
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
) -> Result<bool, String> {
    let key = collected_vote_key(round, signer_address);
    // Dedup per (round, signer): if we already have a vote for this signer at
    // this round, do not overwrite or re-count it.
    if storage.get(&key).map_err(|e| e.to_string())?.is_some() {
        return Ok(false);
    }
    // Bound the number of distinct signers retained per round.
    if collected_signers(storage, round).len() >= MAX_VOTES_PER_ROUND {
        eprintln!(
            "⚠️ [QC] vote store for round {round} hit MAX_VOTES_PER_ROUND — dropping vote from {signer_address}"
        );
        return Err("collected vote store is full".to_string());
    }
    storage.put(&key, sig_hex).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Enumerate the distinct signer addresses that have a collected vote for `round`,
/// in deterministic (storage-prefix-sorted) order. Returned as `(address, sig_hex)`.
fn collected_signers(storage: &StateDB, round: u64) -> Vec<(String, String)> {
    let prefix = format!("consensus:qc_vote_agg:{}:", round);
    let mut out: Vec<(String, String)> = storage
        .scan_prefix_limited(&prefix, MAX_VOTES_PER_ROUND)
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
    with_durable_qc(storage, |view| collect_vote_staged(view, msg, expected_block_hash))
}

fn collect_vote_staged(
    storage: &StateDB,
    msg: &QcVoteMessage,
    expected_block_hash: Option<&str>,
) -> Result<QcOutcome, String> {
    let vote = &msg.vote;
    if epoch_for_block_height(storage, vote.block_height) != Some(vote.epoch) {
        return Ok(QcOutcome::Skipped);
    }

    // (1) Frozen validator set for the vote's epoch.
    let validators = match load_validator_set_for_epoch(storage, vote.epoch) {
        Some(v) => v,
        None => return Ok(QcOutcome::Skipped),
    };
    let ordered = qc::canonical_order(&validators);

    // (2) Bind to the exact set this node verifies against.
    let expected_set_hash = qc::validator_set_hash(&validators);
    // RE-AUDIT MEDIUM: bind every remote vote to THIS chain before it can
    // contribute to a QC. A vote set from a foreign chain (same validator keys,
    // e.g. a testnet reusing mainnet identities) could otherwise aggregate into
    // a QC that self-verifies under ITS OWN chain_id and poison finality here.
    if vote.chain_id != qc::expected_chain_id() {
        eprintln!(
            "🚨 [QC] remote vote for foreign chain_id {} (expected {}) — dropped",
            vote.chain_id,
            qc::expected_chain_id()
        );
        return Ok(QcOutcome::Skipped);
    }
    if vote.validator_set_hash != expected_set_hash {
        // Vote is over a different validator set — cannot aggregate into a QC
        // that verifies against ours.
        return Ok(QcOutcome::Skipped);
    }
    // Bind to THIS node's committed block at this round when known.
    if let Some(bh) = expected_block_hash {
        if vote.block_hash != bh {
            return Ok(QcOutcome::Skipped);
        }
    }

    // (3) Locate signer + verify the single BLS signature against its key.
    let signer_idx = match ordered.iter().position(|v| v.address == msg.signer_address) {
        Some(i) => i,
        None => return Ok(QcOutcome::Skipped), // signer not in the trusted set
    };
    let sig_bytes = match hex::decode(&msg.signature) {
        Ok(b) => b,
        Err(_) => return Ok(QcOutcome::Skipped),
    };
    let pk_bytes = match hex::decode(&ordered[signer_idx].bls_public_key) {
        Ok(b) => b,
        Err(_) => return Ok(QcOutcome::Skipped),
    };
    let bls = crypto::bls::BLSEngine::consensus();
    let vote_bytes = vote.to_signing_bytes();
    match bls.verify(&vote_bytes, &sig_bytes, &pk_bytes) {
        Ok(true) => {}
        _ => return Ok(QcOutcome::Skipped), // bad signature — drop, never store
    }

    // (4) Dedup-persist this signer's vote for the round.
    store_collected_vote(storage, vote.anchor_round, &msg.signer_address, &msg.signature)?;

    // If a complete QC for this round already exists, nothing more to do.
    if matches!(
        storage.get(&format!("consensus:qc_by_round:{}", vote.anchor_round)),
        Ok(Some(_))
    ) {
        return Ok(QcOutcome::Skipped);
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
        // Old records only contain signatures, not full messages. Count only
        // signatures over this exact vote; one equivocator's other message
        // must not poison an otherwise sufficient honest quorum.
        let Ok(public_key) = hex::decode(&ordered[idx].bls_public_key) else { continue };
        if !bls.verify(&vote_bytes, &raw, &public_key).unwrap_or(false) { continue; }
        indices.push(idx);
        sigs.push(raw);
        signed_stake += ordered[idx].stake as u128;
    }

    if !qc::stake_quorum_met(signed_stake, total_stake) {
        // Not enough stake yet — keep collecting.
        return Ok(QcOutcome::Skipped);
    }

    let qc = match build_qc(vote, &validators, &indices, &sigs) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("🚨 [QC] aggregate build_qc failed: {e} — not storing");
            return Err(e.to_string());
        }
    };
    // NEVER store an unverifiable QC.
    if let Err(e) = verify_qc(&qc, &validators, &qc::expected_chain_id()) {
        eprintln!("🚨 [QC] aggregate self-verify failed: {e} — not storing");
        return Err(e.to_string());
    }

    store_certificate(storage, &qc)?;
    Ok(QcOutcome::Complete(qc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qc::ValidatorInfo;
    mod persistence {
        include!("qc_persistence_tests.rs");
    }

    #[test]
    fn local_vote_refuses_conflicting_context_after_reopen() {
        for minority in [false, true] {
            let dir = std::env::temp_dir().join(format!("qc-sign-conflict-{}-{}", std::process::id(), rand::random::<u64>()));
            let db = StateDB::open(dir.to_str().unwrap()).unwrap();
            let mut set = vec![validator_for(&[7; 32], 40, "local")];
            if minority { set.push(validator_for(&[8; 32], 60, "other")); }
            db.put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap()).unwrap();
            let ctx = ctx_for(10);
            assert!(!matches!(produce_and_store_qc(&db, &[7; 32], "local", &ctx), QcOutcome::Skipped));
            drop(db);
            let db = StateDB::open(dir.to_str().unwrap()).unwrap();
            assert!(!matches!(produce_and_store_qc(&db, &[7; 32], "local", &ctx), QcOutcome::Skipped), "identical replay must remain possible");
            let mut conflict = ctx_for(10);
            conflict.block_hash = "99".repeat(32);
            assert!(matches!(produce_and_store_qc(&db, &[7; 32], "local", &conflict), QcOutcome::Skipped), "signed two conflicting votes in one slot (minority={minority})");
            drop(db);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn local_vote_must_not_escape_failed_native_write() {
        for minority in [false, true] {
            let dir = std::env::temp_dir().join(format!("qc-sign-readonly-{}-{}", std::process::id(), rand::random::<u64>()));
            let db = StateDB::open(dir.to_str().unwrap()).unwrap();
            let mut set = vec![validator_for(&[7; 32], 40, "local")];
            if minority { set.push(validator_for(&[8; 32], 60, "other")); }
            db.put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap()).unwrap();
            drop(db);
            let db = StateDB { db: storage::rocksdb::DB::open_for_read_only(&storage::rocksdb::Options::default(), &dir, false).unwrap().into() };
            assert!(matches!(produce_and_store_qc(&db, &[7; 32], "local", &ctx_for(10)), QcOutcome::Skipped), "vote/certificate escaped despite failed durable write (minority={minority})");
            drop(db);
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

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
            chain_id: qc::expected_chain_id(),
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
            .put("genesis:validator_set:v1", &serde_json::to_string(&vec![v.clone()]).unwrap())
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
            .put("genesis:validator_set:v1", &serde_json::to_string(&vec![other]).unwrap())
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
                "genesis:validator_set:v1",
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

    /// Exact snapshots take precedence; unknown epochs cannot borrow live keys.
    #[test]
    fn load_validator_set_for_epoch_requires_exact_nonzero_snapshot() {
        let dir = std::env::temp_dir().join(format!("qc_prod_epoch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = StateDB::open(dir.to_str().unwrap()).unwrap();

        let live = vec![validator_for(&[1u8; 32], 100, "aaaa")];
        let snap = vec![validator_for(&[2u8; 32], 200, "bbbb")];
        storage
            .put("genesis:validator_set:v1", &serde_json::to_string(&live).unwrap())
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
        assert!(load_validator_set_for_epoch(&storage, 9).is_none());
        let bootstrap = load_validator_set_for_epoch(&storage, 0).expect("frozen genesis");
        assert_eq!(bootstrap[0].address, "aaaa");
        drop(storage);
        std::fs::remove_dir_all(dir).unwrap();
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
            .put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap())
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
            .put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap())
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
            .put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap())
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
            .put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap())
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
            .put("genesis:validator_set:v1", &serde_json::to_string(&set).unwrap())
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
