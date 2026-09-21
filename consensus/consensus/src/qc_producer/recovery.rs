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

fn validate_held(view: &StateDB, ctx: &CommitContext, chain_id: &str) -> Result<(), String> {
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
    let raw = view
        .get(&format!("block_{}", ctx.block_height))
        .map_err(|e| e.to_string())?
        .ok_or("pending QC held block unavailable (possibly pruned)")?;
    let block: blockchain::Block = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    if block.header.height != ctx.block_height
        || block.header.hash != ctx.block_hash
        || block.header.round != ctx.anchor_round
        || block.anchor_hash != ctx.anchor_hash
        || block.header.state_root != ctx.state_root
        || block.header.receipts_root != ctx.receipts_root
        || blockchain::calculate_header_hash(&block.header) != block.header.hash
        || blockchain::calculate_tx_hash(&block.transactions) != block.header.tx_hash
        || blockchain::calculate_vertices_root(&block.committed_vertices)
            != block.header.vertices_root
        || blockchain::calculate_evidence_root(&block.slash_evidence) != block.header.evidence_root
    {
        return Err("pending QC context/body differs from held block".into());
    }
    Ok(())
}

fn retry_one(
    view: &StateDB,
    row_key: &str,
    node_key: &[u8; 32],
    address: &str,
    chain: &str,
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
    validate_held(view, &ctx, chain)?;
    let validators =
        load_validator_set_for_epoch(view, ctx.epoch).ok_or("pending QC committee unavailable")?;
    // Completed remote aggregation may have happened since the last local vote.
    if let Some(raw) = view
        .get(&format!("consensus:qc:{}", ctx.block_height))
        .map_err(|e| e.to_string())?
    {
        let cert: QuorumCertificate = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        verify_qc(&cert, &validators, chain).map_err(|e| e.to_string())?;
        let vote = cert.finality_vote();
        if vote
            != (FinalityVote {
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
            })
        {
            return Err("stored QC conflicts with pending work".into());
        }
        store_certificate(view, &cert)?;
        view.delete(row_key).map_err(|e| e.to_string())?;
        return Ok(QcOutcome::Complete(cert));
    }
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
        outcomes.push(with_durable_qc(storage, |view| {
            retry_one(view, &k, node_key, address, chain)
        }));
    }
    Ok(outcomes)
}
