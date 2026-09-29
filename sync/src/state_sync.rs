//! G3 S6: restore a node's consensus state from untrusted peers at a
//! checkpoint the operator trusts (SN-1, SN-2, SN-1b).
//!
//! Trust. Until the transition log (TA, S5) exists, the anchor is a
//! weak-subjectivity checkpoint `(height, block hash, state root)` that the
//! operator pins (TA-0, TA-4). Every chunk is proven against that root, and
//! nothing a peer sends is written unproven. The block and quorum certificate
//! at the checkpoint also come from peers, and must match it. The QC is then
//! verified under the committee the restored state records for its epoch.
//! That is a consistency check, not trust: the committee comes from the same
//! state the checkpoint pins.

use crate::ChainSync;
use blockchain::Block;
use consensus::qc::QuorumCertificate;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use storage::class::{classify, KeyClass};
use storage::rocksdb::{Direction, IteratorMode, WriteBatch};
use storage::{StateDB, RESTORE_MARKER};

pub const ANCHOR_REQ: &str = "STATE_ANCHOR_REQ:";
pub const ANCHOR_RESP: &str = "STATE_ANCHOR_RESP:";
pub const CHUNK_REQ: &str = "STATE_CHUNK_REQ:";
pub const CHUNK_RESP: &str = "STATE_CHUNK_RESP:";

/// The most leaves a server sends in one chunk.
pub const MAX_CHUNK_ENTRIES: usize = 2_000;
/// Encoded chunk budget, well under the transport's 10 MiB frame.
const MAX_CHUNK_BYTES: usize = 6 * 1024 * 1024;
/// Whole-restore restarts (a refused chunk, a truncated stream, a root that
/// does not match) before the restore gives up.
const MAX_RESTARTS: usize = 8;
/// Rows deleted per batch while clearing a datadir.
const CLEAR_BATCH: usize = 10_000;

/// Genesis state keys no transaction changes. The restored state must hold
/// this node's own genesis values for them, which binds the checkpoint to
/// this node's genesis.json, not only to its chain id.
pub const GENESIS_FIXED: [&str; 3] = [
    "sys:chain_id",
    "genesis:validator_set:v1",
    "sys:config:epoch_block_interval",
];

/// A weak-subjectivity checkpoint (TA-0): the trust anchor of a restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

impl std::str::FromStr for Checkpoint {
    type Err = String;

    /// `{height}:{block hash}:{state root}`, each hash 64 hex characters.
    fn from_str(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.trim().split(':').collect();
        let [height, block_hash, state_root] = parts.as_slice() else {
            return Err("a checkpoint is height:block_hash:state_root".into());
        };
        let height: u64 = height
            .parse()
            .map_err(|_| format!("checkpoint height {height:?} is not a number"))?;
        if height == 0 {
            return Err("a checkpoint at genesis: sync from genesis instead".into());
        }
        for (what, hash) in [("block hash", block_hash), ("state root", state_root)] {
            if hex32(hash).is_none() {
                return Err(format!("checkpoint {what} is not 64 hex characters"));
            }
        }
        Ok(Self {
            height,
            block_hash: block_hash.to_ascii_lowercase(),
            state_root: state_root.to_ascii_lowercase(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorRequest {
    pub height: u64,
}

/// The block and QC a server holds at the requested height. Unverified.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnchorResponse {
    pub block: Option<Block>,
    pub quorum_certificate: Option<QuorumCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    pub version: u64,
    /// Hex key hash of the last leaf already received; none for the first.
    pub after: Option<String>,
    pub max: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChunkResponse {
    /// `(key, hex(value))` in key-hash order, after the cursor.
    pub entries: Vec<(String, String)>,
    /// Hex of the borsh range proof up to the last entry.
    pub proof: String,
    /// No leaf follows the cursor.
    pub done: bool,
    /// Why nothing was served. Never trusted; the client asks elsewhere.
    pub error: Option<String>,
}

impl ChainSync {
    /// Serve the block and QC at a height, straight from storage.
    pub fn handle_state_anchor(&self, req: AnchorRequest) -> AnchorResponse {
        let read = |key: String| self.storage.get(&key).ok().flatten();
        AnchorResponse {
            block: read(format!("block_{}", req.height))
                .and_then(|json| serde_json::from_str(&json).ok()),
            quorum_certificate: read(format!("consensus:qc:{}", req.height))
                .and_then(|json| serde_json::from_str(&json).ok()),
        }
    }

    /// Serve one restore chunk (SN-2) of a version this node retains
    /// (`state_commit::servable`). Bounded like vertex serving: one of the
    /// shared serving slots, at most `MAX_CHUNK_ENTRIES` leaves and
    /// `MAX_CHUNK_BYTES` per answer.
    pub fn handle_state_chunk(&self, req: ChunkRequest) -> ChunkResponse {
        let refuse = |why: &str| ChunkResponse {
            error: Some(why.to_string()),
            ..Default::default()
        };
        let Some(_slot) = self.serve_budget.try_enter() else {
            return refuse("busy");
        };
        let keep = StateDB::block_pruning_policy_from_env().map(|(keep, _)| keep);
        match state_commit::servable(&self.storage, req.version, keep) {
            Ok(true) => {}
            Ok(false) => return refuse("version not retained"),
            Err(_) => return refuse("state tree unreadable"),
        }
        let after = match req.after.as_deref() {
            None => None,
            Some(hex) => match hex32(hex) {
                Some(hash) => Some(hash),
                None => return refuse("malformed cursor"),
            },
        };
        let mut max = req.max.clamp(1, MAX_CHUNK_ENTRIES);
        loop {
            match state_commit::wire_chunk(&self.storage, req.version, after, max) {
                Ok(None) => {
                    return ChunkResponse {
                        done: true,
                        ..Default::default()
                    }
                }
                Ok(Some((entries, proof))) => {
                    let size: usize = entries.iter().map(|(k, v)| k.len() + 2 * v.len() + 8).sum();
                    if size + 2 * proof.len() <= MAX_CHUNK_BYTES {
                        return ChunkResponse {
                            entries: entries
                                .into_iter()
                                .map(|(k, v)| (k, hex::encode(v)))
                                .collect(),
                            proof: hex::encode(proof),
                            done: false,
                            error: None,
                        };
                    }
                    if max == 1 {
                        return refuse("one leaf exceeds the chunk budget");
                    }
                    max /= 2;
                }
                Err(_) => return refuse("version not whole here"),
            }
        }
    }
}

/// What the joining node brings from its own configuration.
pub struct RestorePlan<'a> {
    pub checkpoint: &'a Checkpoint,
    /// Every row this node's own genesis writes, built in memory from its
    /// genesis.json (TA-1). The restored state must agree on the
    /// `GENESIS_FIXED` keys, and the rows outside the state are written with
    /// the bootstrap record.
    pub genesis: &'a BTreeMap<String, String>,
    /// This node's genesis identity, from the same build.
    pub genesis_identity: &'a str,
    /// Replace the chain this datadir already holds (a node offline past
    /// block retention, SN-4). Without it a restore only runs on a fresh
    /// datadir, or one an interrupted restore left marked.
    pub replace_existing: bool,
}

/// A finished restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restored {
    pub height: u64,
    pub leaves: usize,
    pub restarts: usize,
}

/// Rows a restore removes before it starts. Consensus state and the tree go
/// (SN-2 step 2: a stale flat key would fork the node at `h + 1`), and so
/// does the chain data and consensus view of the old chain. The signing
/// guards stay (SN-6: a restored key never signs a slot twice), and so do
/// node-local rows and the transition log.
fn cleared_by_restore(key: &[u8]) -> bool {
    match classify(key) {
        Some(KeyClass::State | KeyClass::Chain | KeyClass::Tree | KeyClass::Dead) => true,
        Some(KeyClass::Local) => {
            !(key.starts_with(b"consensus:qc_signing:")
                || key.starts_with(b"consensus:vattest:")
                || key == b"latest_proposed_round")
        }
        _ => false,
    }
}

fn clear(storage: &Arc<StateDB>) -> Result<(), String> {
    let mut from: Vec<u8> = Vec::new();
    loop {
        let mut doomed = Vec::new();
        let mut finished = true;
        for row in storage
            .db
            .iterator(IteratorMode::From(&from, Direction::Forward))
        {
            let (key, _) = row.map_err(|e| e.to_string())?;
            if key.as_ref() == RESTORE_MARKER.as_bytes() || !cleared_by_restore(&key) {
                continue;
            }
            doomed.push(key.to_vec());
            if doomed.len() == CLEAR_BATCH {
                from = key.to_vec();
                from.push(0);
                finished = false;
                break;
            }
        }
        if !doomed.is_empty() {
            storage
                .restore_transaction(|view| {
                    let mut batch = WriteBatch::default();
                    for key in &doomed {
                        batch.delete(key);
                    }
                    view.write_batch(batch)
                })
                .map_err(|e| e.to_string())?;
        }
        if finished {
            return Ok(());
        }
    }
}

/// The block and QC match the checkpoint, and the block is internally
/// whole. The QC's signature is checked after the restore.
fn check_anchor(cp: &Checkpoint, block: &Block, qc: &QuorumCertificate) -> Result<(), String> {
    let h = &block.header;
    if h.height != cp.height
        || !h.hash.eq_ignore_ascii_case(&cp.block_hash)
        || !h.state_root.eq_ignore_ascii_case(&cp.state_root)
    {
        return Err("the block is not the checkpoint's".into());
    }
    if blockchain::calculate_header_hash(h) != h.hash
        || blockchain::calculate_tx_hash(&block.transactions) != h.tx_hash
        || blockchain::calculate_vertices_root(&block.committed_vertices) != h.vertices_root
        || blockchain::calculate_evidence_root(&block.slash_evidence) != h.evidence_root
    {
        return Err("the block's header does not commit to its body".into());
    }
    if qc.block_height != h.height
        || qc.block_hash != h.hash
        || qc.state_root != h.state_root
        || qc.receipts_root != h.receipts_root
        || qc.anchor_round != h.round
        || qc.anchor_hash != block.anchor_hash
    {
        return Err("the QC is not for the checkpoint's block".into());
    }
    Ok(())
}

/// The checkpoint's block and every QC for it that the peers hold.
async fn fetch_anchor<F, Fut>(
    cp: &Checkpoint,
    peers: usize,
    ask: &mut F,
) -> Result<(Block, Vec<QuorumCertificate>), String>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let request =
        serde_json::to_string(&AnchorRequest { height: cp.height }).map_err(|e| e.to_string())?;
    let mut found: Option<Block> = None;
    let mut qcs: Vec<QuorumCertificate> = Vec::new();
    for peer in 0..peers {
        let Ok(reply) = ask(peer, format!("{ANCHOR_REQ}{request}")).await else {
            continue;
        };
        let Some(anchor) = reply
            .strip_prefix(ANCHOR_RESP)
            .and_then(|json| serde_json::from_str::<AnchorResponse>(json).ok())
        else {
            continue;
        };
        let (Some(block), Some(qc)) = (anchor.block, anchor.quorum_certificate) else {
            continue;
        };
        if let Err(e) = check_anchor(cp, &block, &qc) {
            eprintln!("⚠️ [STATE_SYNC] peer {peer}: {e}");
            continue;
        }
        if !qcs.contains(&qc) {
            qcs.push(qc);
        }
        found.get_or_insert(block);
    }
    match found {
        Some(block) => Ok((block, qcs)),
        None => Err(format!(
            "no peer holds block {} and its QC as the checkpoint names them",
            cp.height
        )),
    }
}

fn short(value: &str) -> &str {
    value.get(..48).unwrap_or(value)
}

/// The restored state is of this node's genesis (`GENESIS_FIXED`). Returns
/// the chain id.
fn check_genesis(storage: &StateDB, plan: &RestorePlan<'_>) -> Result<String, String> {
    for key in GENESIS_FIXED {
        let local = plan
            .genesis
            .get(key)
            .ok_or_else(|| format!("this node's genesis has no {key}"))?;
        let restored = storage
            .get(key)
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        if &restored != local {
            return Err(format!(
                "the checkpoint's {key} is {:?}, this node's genesis has {:?}",
                short(&restored),
                short(local)
            ));
        }
    }
    Ok(plan.genesis["sys:chain_id"].clone())
}

/// The restored state is of this node's genesis, and its own committee
/// signed one of the QCs under this node's chain id. Returns that QC.
fn verify_restored_qc(
    storage: &StateDB,
    plan: &RestorePlan<'_>,
    qcs: &[QuorumCertificate],
) -> Result<QuorumCertificate, String> {
    let chain_id = check_genesis(storage, plan)?;
    let height = plan.checkpoint.height;
    let epoch = consensus::qc_producer::epoch_for_block_height(storage, height)
        .ok_or("the restored state has no epoch for the checkpoint height")?;
    let committee = consensus::qc_producer::load_validator_set_for_epoch(storage, epoch)
        .ok_or("the restored state has no committee for the checkpoint's epoch")?;
    let mut last_error = String::from("no QC");
    for qc in qcs {
        if qc.epoch != epoch {
            last_error = format!("QC epoch {} is not the restored epoch {epoch}", qc.epoch);
            continue;
        }
        match consensus::qc::verify_qc(qc, &committee, &chain_id) {
            Ok(()) => return Ok(qc.clone()),
            Err(e) => last_error = format!("{e:?}"),
        }
    }
    Err(format!(
        "no QC for the checkpoint verifies under the restored committee: {last_error}"
    ))
}

/// SN-1b: the consensus bootstrap record, in the batch that also completes
/// the tree and removes the restore marker. Every field comes from the
/// checkpoint's block and verified QC, never from a peer's database.
fn bootstrap_record(
    mut batch: WriteBatch,
    plan: &RestorePlan<'_>,
    block: &Block,
    qc: &QuorumCertificate,
) -> Result<WriteBatch, String> {
    let h = block.header.height.to_string();
    let block_json = serde_json::to_string(block).map_err(|e| e.to_string())?;
    let qc_json = serde_json::to_string(qc).map_err(|e| e.to_string())?;
    let anchor_round = qc.anchor_round.to_string();
    let finalized_round = qc.finalized_round.to_string();
    let rows: Vec<(String, &str)> = vec![
        ("jmt:floor".into(), &h),
        (format!("block_{h}"), &block_json),
        ("latest_height".into(), &h),
        ("latest_block_hash".into(), &block.header.hash),
        ("sys:last_executed_height".into(), &h),
        ("consensus:last_adopted_height".into(), &h),
        ("consensus:finality_digest".into(), &qc.finality_digest),
        ("consensus:last_anchor_round".into(), &anchor_round),
        ("consensus:last_anchor_hash".into(), &qc.anchor_hash),
        ("consensus:finalized_round".into(), &finalized_round),
        (format!("consensus:qc:{h}"), &qc_json),
        (format!("consensus:qc_by_round:{anchor_round}"), &qc_json),
        ("consensus:qc:latest".into(), &qc_json),
        ("consensus:qc:latest_height".into(), &h),
        ("consensus:qc:latest_round".into(), &anchor_round),
        ("genesis_identity".into(), plan.genesis_identity),
        ("genesis_initialized".into(), "true"),
    ];
    for (key, value) in rows {
        batch.put(key.as_bytes(), value.as_bytes());
    }
    // Genesis rows outside the state (stdlib pins, version), from this
    // node's own build; the state rows came with the restore.
    for (key, value) in plan.genesis {
        if classify(key.as_bytes()) != Some(KeyClass::State) {
            batch.put(key.as_bytes(), value.as_bytes());
        }
    }
    batch.delete(RESTORE_MARKER.as_bytes());
    Ok(batch)
}

/// Refuse to overwrite a chain unless asked (`replace_existing`). A fresh
/// datadir, or one an interrupted restore marked, is always fine.
fn check_datadir(storage: &StateDB, replace_existing: bool) -> Result<(), String> {
    let marked = storage
        .get(RESTORE_MARKER)
        .map_err(|e| e.to_string())?
        .is_some();
    let holds_chain = storage
        .get("genesis_initialized")
        .map_err(|e| e.to_string())?
        .is_some()
        || storage
            .get("latest_height")
            .map_err(|e| e.to_string())?
            .is_some();
    if holds_chain && !marked && !replace_existing {
        return Err(
            "this datadir already holds a chain; restoring replaces it, so it must be asked for"
                .into(),
        );
    }
    Ok(())
}

/// SN-2: restore the state at `plan.checkpoint` from `peers` peers, asking
/// peer `i` with `ask(i, message)`, then write the bootstrap record (SN-1b).
///
/// A refused chunk, a stream that ends early or a root that does not match
/// wipes the partial restore and starts over with the next peer. A peer
/// that fails to answer is skipped without a restart. The datadir carries
/// the restore marker from the first write to the last, so a crash at any
/// point leaves a node that refuses to boot (RC-1) and restores again.
pub async fn restore_state<F, Fut>(
    storage: &Arc<StateDB>,
    plan: &RestorePlan<'_>,
    peers: usize,
    mut ask: F,
) -> Result<Restored, String>
where
    F: FnMut(usize, String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    if peers == 0 {
        return Err("no peers to restore from".into());
    }
    check_datadir(storage, plan.replace_existing)?;
    let cp = plan.checkpoint;
    let root = hex32(&cp.state_root).ok_or("malformed checkpoint root")?;
    let (block, qcs) = fetch_anchor(cp, peers, &mut ask).await?;

    let marker = serde_json::json!({"height": cp.height, "state_root": cp.state_root});
    storage
        .put(RESTORE_MARKER, &marker.to_string())
        .map_err(|e| e.to_string())?;

    let mut peer = 0usize;
    let mut restarts = 0usize;
    let mut restart = |why: String, peer: &mut usize| -> Result<(), String> {
        eprintln!("⚠️ [STATE_SYNC] restore restarts: {why}");
        restarts += 1;
        *peer = (*peer + 1) % peers;
        if restarts > MAX_RESTARTS {
            return Err(format!(
                "restore gave up after {MAX_RESTARTS} restarts: {why}"
            ));
        }
        Ok(())
    };
    'restore: loop {
        clear(storage)?;
        let mut restore = state_commit::Restore::begin(
            Arc::clone(storage),
            cp.height,
            state_commit::RootHash(root),
        )
        .map_err(|e| e.to_string())?;
        let mut leaves = 0usize;
        let mut silent = 0usize;
        loop {
            let request = ChunkRequest {
                version: cp.height,
                after: restore.cursor().map(hex::encode),
                max: MAX_CHUNK_ENTRIES,
            };
            let message = format!(
                "{CHUNK_REQ}{}",
                serde_json::to_string(&request).map_err(|e| e.to_string())?
            );
            let reply = ask(peer, message).await.ok().and_then(|reply| {
                reply
                    .strip_prefix(CHUNK_RESP)
                    .and_then(|json| serde_json::from_str::<ChunkResponse>(json).ok())
            });
            let decoded = reply.filter(|r| r.error.is_none()).and_then(|r| {
                let entries: Option<Vec<(String, Vec<u8>)>> = r
                    .entries
                    .into_iter()
                    .map(|(k, v)| hex::decode(v).ok().map(|v| (k, v)))
                    .collect();
                Some((entries?, hex::decode(&r.proof).ok()?, r.done))
            });
            let Some((entries, proof, done)) = decoded else {
                // No answer, a refusal or a garbled one: ask the next peer
                // from the same cursor.
                silent += 1;
                peer = (peer + 1) % peers;
                if silent >= 3 * peers {
                    return Err("no peer serves the checkpoint's state".into());
                }
                continue;
            };
            silent = 0;
            if done {
                break;
            }
            match restore.add_wire_chunk(entries, &proof) {
                Ok(verified) => {
                    leaves += verified.len();
                    storage
                        .restore_transaction(|view| {
                            let mut batch = WriteBatch::default();
                            for (key, value) in &verified {
                                batch.put(key.as_bytes(), value);
                            }
                            view.write_batch(batch)
                        })
                        .map_err(|e| e.to_string())?;
                }
                Err(e) => {
                    restart(format!("peer {peer} sent a refused chunk: {e}"), &mut peer)?;
                    continue 'restore;
                }
            }
        }
        let tree = match restore.finish() {
            Ok(batch) => batch,
            Err(e) => {
                restart(
                    format!("peer {peer} ended the stream early: {e}"),
                    &mut peer,
                )?;
                continue 'restore;
            }
        };
        // The tree is whole at `root` but `jmt:latest` is not written yet;
        // the QC check reads only flat state.
        let qc = match verify_restored_qc(storage, plan, &qcs) {
            Ok(qc) => qc,
            Err(e) => {
                clear(storage)?;
                storage.delete(RESTORE_MARKER).map_err(|e| e.to_string())?;
                return Err(format!("the checkpoint is inconsistent: {e}"));
            }
        };
        let record = bootstrap_record(tree, plan, &block, &qc)?;
        storage.write_batch(record).map_err(|e| e.to_string())?;
        return Ok(Restored {
            height: cp.height,
            leaves,
            restarts,
        });
    }
}

type Connections =
    tokio::sync::Mutex<std::collections::HashMap<usize, (tokio::net::TcpStream, [u8; 32])>>;

/// `restore_state` over the node's encrypted TCP transport, to the peers'
/// sync ports. One connection per peer, kept across requests and reopened
/// after a failure.
pub async fn restore_over_tcp(
    storage: &Arc<StateDB>,
    plan: &RestorePlan<'_>,
    peers: &[(String, u16)],
    my_port: u16,
) -> Result<Restored, String> {
    let key = crypto::SigningKey::generate(&mut rand::rngs::OsRng);
    let connections: Arc<Connections> = Arc::default();
    restore_state(storage, plan, peers.len(), |peer, msg| {
        let connections = Arc::clone(&connections);
        let (ip, port) = peers[peer].clone();
        let key = key.clone();
        async move { ask_over_tcp(&connections, peer, &ip, port, my_port, &key, &msg).await }
    })
    .await
}

async fn ask_over_tcp(
    connections: &Connections,
    peer: usize,
    ip: &str,
    port: u16,
    my_port: u16,
    key: &crypto::SigningKey,
    msg: &str,
) -> Result<String, String> {
    let mut open = connections.lock().await;
    if let std::collections::hash_map::Entry::Vacant(slot) = open.entry(peer) {
        let (stream, shared, _) =
            network::secure_connect(ip, port, "__state_sync__", my_port, None, key)
                .await
                .map_err(|e| format!("{ip}:{port}: {e}"))?;
        slot.insert((stream, shared));
    }
    let (stream, shared) = open.get_mut(&peer).ok_or("no connection")?;
    let reply = match network::send_encrypted_msg(stream, shared, msg).await {
        Ok(()) => network::read_encrypted_msg(stream, shared).await,
        Err(e) => Err(e),
    };
    reply.map_err(|e| {
        open.remove(&peer);
        format!("{ip}:{port}: {e}")
    })
}

#[cfg(test)]
mod tests;
