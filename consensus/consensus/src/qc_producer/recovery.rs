//! Durable local QC work, staged with block acceptance or ordering adoption.
//! This trusts the local executed store, not an unauthenticated recovery snapshot.

use super::*;
use crate::ordering::CommitInfo;
use storage::rocksdb::{Direction, IteratorMode};

const PREFIX: &str = "consensus:qc_pending:";
const BATCH: usize = 8;
const MAX_CONTEXT_BYTES: usize = 16 * 1024;

fn key(height: u64) -> String {
    format!("{PREFIX}{height:020}")
}

/// Caller MUST supply the same transaction view as block/order acceptance.
/// Do not infer a lost historical digest from the current tip on restart.
/// The lowest height with pending QC work, if any. B419: a read error, or a
/// row whose key names no height (a corrupt row), is an error, never "no
/// pending work": read as none, pruning dropped B369's clamp and the epoch
/// step skipped B317's wait.
pub(crate) fn try_lowest_pending_qc_height(storage: &StateDB) -> Result<Option<u64>, String> {
    let Some(row) = storage.db.prefix_iterator(PREFIX.as_bytes()).next() else {
        return Ok(None);
    };
    let (key, _) = row.map_err(|e| e.to_string())?;
    let Some(height) = key.strip_prefix(PREFIX.as_bytes()) else {
        return Ok(None);
    };
    std::str::from_utf8(height)
        .ok()
        .and_then(|h| h.parse::<u64>().ok())
        .map(Some)
        .ok_or_else(|| {
            format!(
                "a pending QC row names no height ({})",
                String::from_utf8_lossy(&key)
            )
        })
}

/// B419: `try_lowest_pending_qc_height` for the callers with no error path.
/// An error reads as pending work at height 0, the most conservative answer
/// (finality lags, the vertex is sent again), never as no pending work.
pub(crate) fn lowest_pending_qc_height(storage: &StateDB) -> Option<u64> {
    try_lowest_pending_qc_height(storage).unwrap_or(Some(0))
}

/// B164: this node's pending QC work at `height`, if it has some: the
/// (round, epoch, block hash) a peer's vote for that height must name. A
/// point read of a bounded row; reading the block itself let junk votes for
/// fresh rounds cost a whole block each. B469: a row that cannot be read (a
/// read error, or not UTF-8), is over the bound, does not parse or names
/// another height is an error, never "no work" (B419's class, at the value):
/// read as none, the finality floor released B255's retention and the
/// B262/B318 brakes.
pub(crate) fn pending_context(
    storage: &StateDB,
    height: u64,
) -> Result<Option<CommitContext>, String> {
    let Some(raw) = storage.try_get(&key(height)).map_err(|e| e.to_string())? else {
        return Ok(None);
    };
    if raw.len() > MAX_CONTEXT_BYTES {
        return Err(format!("the pending QC work of height {height} exceeds its bound"));
    }
    let ctx: CommitContext = match serde_json::from_str(&raw) {
        Ok(ctx) => ctx,
        Err(e) => return Err(format!("the pending QC work of height {height} does not parse: {e}")),
    };
    if ctx.block_height != height {
        return Err(format!(
            "the pending QC work of height {height} names height {}",
            ctx.block_height
        ));
    }
    Ok(Some(ctx))
}

pub(crate) fn stage_pending_qc(
    view: &StateDB,
    block: &blockchain::Block,
    info: &CommitInfo,
    chain_id: String,
) -> Result<(), String> {
    if block.header.round != info.anchor_round
        || block.anchor_hash != info.anchor_hash
        || block.committed_vertices != info.sequence
    {
        return Err("QC work differs from accepted ordering plan".into());
    }
    let ctx = CommitContext {
        chain_id,
        epoch: epoch_for_block_height(view, block.header.height)
            .ok_or("QC work epoch unavailable")?,
        finalized_round: info.anchor_round,
        anchor_round: info.anchor_round,
        anchor_hash: info.anchor_hash.clone(),
        block_height: block.header.height,
        block_hash: block.header.hash.clone(),
        state_root: block.header.state_root.clone(),
        receipts_root: block.header.receipts_root.clone(),
        finality_digest: info.finality_digest.clone(),
        // EP-4: the boundary block's vote binds the next committee, as this
        // node derived it earlier in this same transaction.
        next_validator_set_hash: next_committee_hash(view, block.header.height)?,
        decision_floor: Some(info.decision_floor),
        decision_cursor: Some(info.decision_cursor),
    };
    validate_held(view, &ctx, &ctx.chain_id)?;
    let encoded = serde_json::to_string(&ctx).map_err(|e| e.to_string())?;
    if encoded.len() > MAX_CONTEXT_BYTES {
        return Err("QC work context exceeds bound".into());
    }
    let key = key(ctx.block_height);
    if let Some(previous) = view.get(&key).map_err(|e| e.to_string())? {
        if previous != encoded {
            return Err("conflicting pending QC context".into());
        }
    }
    view.put(&key, &encoded).map_err(|e| e.to_string())
}

/// `validator_set_hash(C_{E+1})` if `height` is a V4 boundary block H_E.
pub(crate) fn next_committee_hash(view: &StateDB, height: u64) -> Result<String, String> {
    if !crate::v4::is_v4_chain(view) {
        return Ok(String::new());
    }
    let interval =
        crate::v4::epoch::epoch_interval(view).ok_or("a V4 chain needs its epoch interval")?;
    if !height.is_multiple_of(interval) {
        return Ok(String::new());
    }
    let next = crate::v4::epoch::epoch_of_height(height, interval) + 1;
    let start = crate::v4::epoch::read_start_from(view, next)?
        .ok_or("a boundary block without the next epoch's record")?;
    Ok(qc::validator_set_hash(&start.committee))
}

/// The context's own fields, and the executed block it names: its stored
/// text, as `held_header` or `validate_held` reads it.
fn context_held(view: &StateDB, ctx: &CommitContext, chain_id: &str) -> Result<String, String> {
    if ctx.chain_id != chain_id
        || ctx.block_height == 0
        || ctx.anchor_round == 0
        || ctx.finalized_round != ctx.anchor_round
        || epoch_for_block_height(view, ctx.block_height) != Some(ctx.epoch)
    {
        return Err("pending QC chain/height/round/epoch mismatch".into());
    }
    let executed = view
        .get("sys:last_executed_height")
        .map_err(|e| e.to_string())?
        .ok_or("pending QC has no execution marker")?
        .parse::<u64>()
        .map_err(|e| e.to_string())?;
    if executed < ctx.block_height {
        return Err("pending QC block was not executed".into());
    }
    view.get(&format!("block_{}", ctx.block_height))
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "pending QC held block unavailable (possibly pruned)".to_string())
}

/// The held block is the context's, body and all: run once, when the work
/// is staged with the block.
fn validate_held(view: &StateDB, ctx: &CommitContext, chain_id: &str) -> Result<(), String> {
    let raw = context_held(view, ctx, chain_id)?;
    let block: blockchain::Block = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if block.header.height != ctx.block_height
        || block.header.hash != ctx.block_hash
        || block.header.round != ctx.anchor_round
        || block.anchor_hash != ctx.anchor_hash
        || block.header.state_root != ctx.state_root
        || block.header.receipts_root != ctx.receipts_root
        || block.check_commitments().is_err()
    {
        return Err("pending QC context/body differs from held block".into());
    }
    Ok(())
}

/// B358: on a retry, the held block is still the one `validate_held`
/// checked at staging: its header names the context and hashes to its hash
/// (which binds the body through its roots), and its anchor is the
/// context's. The rest of the body is skipped, not rebuilt: each retry
/// built the whole block and recomputed every root, a Reed-Solomon
/// extension included, under the storage writer gate.
fn held_header(view: &StateDB, ctx: &CommitContext, chain_id: &str) -> Result<(), String> {
    #[derive(serde::Deserialize)]
    struct Held {
        header: blockchain::BlockHeader,
        #[serde(default)]
        anchor_hash: String,
    }
    let raw = context_held(view, ctx, chain_id)?;
    let held: Held = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let header = &held.header;
    if header.height != ctx.block_height
        || header.hash != ctx.block_hash
        || header.round != ctx.anchor_round
        || held.anchor_hash != ctx.anchor_hash
        || header.state_root != ctx.state_root
        || header.receipts_root != ctx.receipts_root
        || blockchain::calculate_header_hash(header) != header.hash
    {
        return Err("pending QC context differs from the held block".into());
    }
    Ok(())
}

/// B420: an alarm `retry_one` found, recorded after its transaction (which
/// the error rolls back): the alarm, the height (a decision conflict) or the
/// next epoch (a committee mismatch), and why.
type FoundAlarm = Option<(crate::alarm::Alarm, u64, String)>;

fn retry_one(
    view: &StateDB,
    row_key: &str,
    node_key: &[u8; 32],
    address: &str,
    chain: &str,
    found: &mut FoundAlarm,
) -> Result<QcOutcome, String> {
    let Some(raw) = view.get(row_key).map_err(|e| e.to_string())? else {
        return Ok(QcOutcome::Skipped);
    };
    if raw.len() > MAX_CONTEXT_BYTES {
        return Err("pending QC context exceeds bound".into());
    }
    let ctx: CommitContext = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if row_key != key(ctx.block_height) {
        return Err("pending QC key/height mismatch".into());
    }
    let validators =
        load_validator_set_for_epoch(view, ctx.epoch).ok_or("pending QC committee unavailable")?;
    // Completed remote aggregation may have happened since the last local vote.
    if let Some(raw) = view
        .get(&format!("consensus:qc:{}", ctx.block_height))
        .map_err(|e| e.to_string())?
    {
        // B353: a stored QC was verified by what stored it; only its vote
        // is compared (it was paired again on every retry).
        let cert: QuorumCertificate = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let vote = cert.finality_vote();
        let expected = FinalityVote {
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
            next_validator_set_hash: ctx.next_validator_set_hash.clone(),
        };
        if vote != expected {
            // B420: the stored QC was verified when it was stored, so this
            // node's work disagrees with a certified decision: a durable
            // alarm halts ordering and sync. The error alone kept the row
            // for good, a silent stall (EP-4's check waits behind B317 for
            // this very row, so its alarm was never reached).
            let next_only = FinalityVote {
                next_validator_set_hash: vote.next_validator_set_hash.clone(),
                ..expected
            } == vote;
            *found = Some(if next_only {
                (
                    crate::alarm::Alarm::CommitteeMismatch,
                    ctx.epoch.saturating_add(1),
                    format!(
                        "{}: QC({}) binds next committee {:?}, this node derived {:?}",
                        crate::v4::epoch::COMMITTEE_MISMATCH,
                        ctx.block_height,
                        vote.next_validator_set_hash,
                        ctx.next_validator_set_hash
                    ),
                )
            } else {
                (
                    crate::alarm::Alarm::DecisionConflict,
                    ctx.block_height,
                    format!(
                        "{}: the stored QC of height {} differs from this node's pending work",
                        crate::ordering::DECISION_CONFLICT,
                        ctx.block_height
                    ),
                )
            });
            return Err("stored QC conflicts with pending work".into());
        }
        store_certificate(view, &cert)?;
        view.delete(row_key).map_err(|e| e.to_string())?;
        return Ok(QcOutcome::Complete(cert));
    }
    // B369: the held block is read only to vote; a stored QC retires the
    // work above without it (read first, a block gone kept the row for
    // good, and 50 blocks later the member proposed nothing again).
    held_header(view, &ctx, chain)?;
    if !validators
        .iter()
        .any(|v| v.address == address && v.stake > 0)
    {
        // This node had no signing obligation in the frozen historical set.
        view.delete(row_key).map_err(|e| e.to_string())?;
        return Ok(QcOutcome::Skipped);
    }
    let outcome = produce_qc_staged(view, node_key, address, &ctx)?;
    if matches!(outcome, QcOutcome::Complete(_)) {
        view.delete(row_key).map_err(|e| e.to_string())?;
    }
    // Partial remains durable until a complete QC exists; restart/send failure
    // replays the guarded signature, not a new context or an assumed delivery.
    Ok(outcome)
}

/// `retry_one` in its own transaction. B420: an alarm it found is written
/// after it, durably (the error rolled the transaction back).
fn retry_row(
    storage: &StateDB,
    row_key: &str,
    node_key: &[u8; 32],
    address: &str,
    chain: &str,
) -> QcOutcome {
    let mut found = None;
    let outcome = with_durable_qc(storage, |view| {
        retry_one(view, row_key, node_key, address, chain, &mut found)
    });
    match found {
        Some((crate::alarm::Alarm::CommitteeMismatch, next, why)) => {
            eprintln!("🚨 [EP-4] {why}: ordering halts");
            let _ = storage.put(&format!("alarm:committee_mismatch:{next:020}"), &why);
        }
        Some((crate::alarm::Alarm::DecisionConflict, height, why)) => {
            record_decision_conflict(storage, height, &why);
        }
        None => {}
    }
    outcome
}

/// B358: the pending work of the block at `height` alone, just staged with
/// it (its first vote, or the QC it was adopted with).
pub(crate) fn retry_pending_qc_at(
    storage: &StateDB,
    node_key: &[u8; 32],
    address: &str,
    chain: &str,
    height: u64,
) -> QcOutcome {
    retry_row(storage, &key(height), node_key, address, chain)
}

pub(crate) fn retry_pending_qcs(
    storage: &StateDB,
    node_key: &[u8; 32],
    address: &str,
    chain: &str,
    cursor: &mut String,
) -> Result<Vec<QcOutcome>, String> {
    let start = if cursor.is_empty() {
        PREFIX
    } else {
        cursor.as_str()
    };
    let mut keys = Vec::with_capacity(BATCH);
    for row in storage
        .db
        .iterator(IteratorMode::From(start.as_bytes(), Direction::Forward))
    {
        let (k, _) = row.map_err(|e| e.to_string())?;
        if !k.starts_with(PREFIX.as_bytes()) {
            break;
        }
        let k = String::from_utf8(k.to_vec()).map_err(|e| e.to_string())?;
        if !cursor.is_empty() && k <= *cursor {
            continue;
        }
        keys.push(k);
        if keys.len() == BATCH {
            break;
        }
    }
    if keys.is_empty() {
        cursor.clear();
    }
    let mut outcomes = Vec::with_capacity(keys.len());
    for k in keys {
        // Fair round-robin work bound: an unavailable oldest item must not
        // starve later heights. Cursor is only a scheduling hint, never authority.
        *cursor = k.clone();
        outcomes.push(retry_row(storage, &k, node_key, address, chain));
    }
    Ok(outcomes)
}
