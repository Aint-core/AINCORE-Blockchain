//! G1 S9: epochs (EP-1..EP-5 and RC-3 of `docs/G1_CONSENSUS_CONTRACT.md`).
//!
//! An epoch E closes when its boundary block H_E is accepted: its anchor A*
//! at round r* is the last epoch-E anchor, and E+1's record is written (its
//! committee, derived and validated, its first round r* + 2 and its sentinel).
//! E+1 becomes active only at activation, which resets the engine's derived
//! state to the new epoch. The host (the node) closes at H_E's acceptance and
//! activates once it holds QC(H_E); a standalone engine (tests) does both
//! after its own boundary decision.

use super::*;

/// What a node records about an epoch when the previous one closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochStart {
    pub epoch: u64,
    pub first_round: u64,
    /// `blockchain::epoch_genesis` of this epoch ("genesis" for epoch 0).
    pub sentinel: String,
    /// C_E, canonical order.
    pub committee: Vec<ValidatorInfo>,
    /// The previous epoch's closing round r*, its anchor and boundary block.
    pub prev_closing_round: u64,
    pub prev_anchor: String,
    pub prev_block_hash: String,
    /// H_{E−1}'s height: activation waits for its QC (EP-4).
    #[serde(default)]
    pub prev_height: u64,
    /// H_{E−1}'s BFT timestamp: RC-3 re-arms a node whose guards were lost
    /// only in an epoch that began after it booted (`resume_point`).
    #[serde(default)]
    pub prev_timestamp: u64,
}

impl EpochStart {
    fn record(&self, closing_round: Option<u64>) -> EpochRecord<'_> {
        EpochRecord {
            epoch: self.epoch,
            first_round: self.first_round,
            closing_round,
            sentinel: &self.sentinel,
            committee: &self.committee,
        }
    }
}

/// The closed epoch's tail: bodies above its last g − RETAIN_SLACK and their
/// certificates, served (`pull::serve`) until the next activation.
#[derive(Debug, Default)]
pub(super) struct ClosedEpoch {
    pub(super) epoch: u64,
    pub(super) bodies: HashMap<String, Vertex>,
    pub(super) certs: HashMap<(u64, String), VertexCertificate>,
}

/// `consensus:epoch_start:{E:020}`: E's record, written with H_{E−1}.
pub fn epoch_start_key(epoch: u64) -> String {
    format!("consensus:epoch_start:{epoch:020}")
}

/// EP-1: the epoch length I in blocks, pinned at genesis (the executor's
/// boundary uses the same key).
pub const EPOCH_INTERVAL_KEY: &str = "sys:config:epoch_block_interval";

/// I, if the chain pinned a positive one.
pub fn epoch_interval(storage: &StateDB) -> Option<u64> {
    storage
        .get(EPOCH_INTERVAL_KEY)
        .ok()
        .flatten()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|v| *v > 0)
}

/// EP-1: E(h) = ⌊(h−1)/I⌋ for h ≥ 1.
pub fn epoch_of_height(height: u64, interval: u64) -> u64 {
    height.saturating_sub(1) / interval
}

/// E's record as written with H_{E−1}.
pub fn read_start_from(storage: &StateDB, epoch: u64) -> Result<Option<EpochStart>, String> {
    let Some(raw) = storage
        .get(&epoch_start_key(epoch))
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("a corrupt epoch record for {epoch}: {e}"))
}

/// C_E on a V4 chain: the genesis committee for epoch 0, E's record after.
/// Never the live set, and never the executor's snapshots (EP-1).
pub fn committee_of(storage: &StateDB, epoch: u64) -> Option<Vec<ValidatorInfo>> {
    if epoch == 0 {
        let raw = storage.get("genesis:validator_set:v1").ok()??;
        let set: Vec<ValidatorInfo> = serde_json::from_str(&raw).ok()?;
        return (!set.is_empty()).then_some(set);
    }
    read_start_from(storage, epoch)
        .ok()
        .flatten()
        .map(|s| s.committee)
}

/// Epoch E's boundary block H_E, as EP-2 and EP-3 need it.
pub struct Boundary<'a> {
    /// E, the epoch closing.
    pub epoch: u64,
    /// C_E.
    pub current: &'a [ValidatorInfo],
    /// r*, A* and H_E.
    pub closing_round: u64,
    pub anchor: &'a str,
    pub block_hash: &'a str,
    pub height: u64,
    /// H_E's timestamp (BFT time on the node).
    pub timestamp: u64,
}

/// EP-2 and EP-3: E+1's record. The proposed committee if it validates, C_E
/// again otherwise (the reason is returned for the alarm row, so every node
/// derives the same record and none halts); first round r* + 2; the sentinel
/// binds the chain, E+1, its first round, H_E and A*.
pub fn next_start(
    chain_id: &str,
    genesis_identity: &str,
    b: &Boundary<'_>,
    proposed: &[ValidatorInfo],
) -> (EpochStart, Option<String>) {
    let (committee, invalid) = blockchain::committee::next_committee(b.current, proposed);
    let epoch = b.epoch + 1;
    let first_round = b.closing_round + 2;
    let start = EpochStart {
        epoch,
        first_round,
        sentinel: blockchain::epoch_genesis(
            chain_id,
            genesis_identity,
            epoch,
            first_round,
            b.block_hash,
            b.anchor,
        ),
        committee,
        prev_closing_round: b.closing_round,
        prev_anchor: b.anchor.to_string(),
        prev_block_hash: b.block_hash.to_string(),
        prev_height: b.height,
        prev_timestamp: b.timestamp,
    };
    (start, invalid)
}

/// Write E+1's record (and the alarm, if the proposal was invalid). Written
/// once: an existing different record is a conflict, never overwritten.
pub fn write_next(
    store: &StateDB,
    start: &EpochStart,
    invalid: Option<&str>,
) -> Result<(), String> {
    let json = serde_json::to_string(start).map_err(|e| e.to_string())?;
    let key = epoch_start_key(start.epoch);
    if let Some(held) = store.get(&key).map_err(|e| e.to_string())? {
        if held == json {
            return Ok(());
        }
        return Err(crate::alarm::raise(
            crate::alarm::Alarm::DecisionConflict,
            format!(
                "{}: epoch {} already has a different record",
                crate::ordering::DECISION_CONFLICT,
                start.epoch
            ),
        ));
    }
    if let Some(why) = invalid {
        store
            .put(&format!("alarm:committee_invalid:{:020}", start.epoch), why)
            .map_err(|e| e.to_string())?;
    }
    store.put(&key, &json).map_err(|e| e.to_string())
}

/// EP-2 and EP-3 on a V4 host, inside the transaction that accepts or imports
/// `block`: if it is a boundary block H_E, derive C_{E+1} from the live set
/// in its post-state (`sys:validator_set:v1`, whether or not Move's
/// `advance_epoch` succeeded) and write E+1's record. Returns it.
pub fn stage_boundary(
    view: &StateDB,
    block: &blockchain::Block,
) -> Result<Option<EpochStart>, String> {
    if !is_v4_chain(view) {
        return Ok(None);
    }
    let interval = epoch_interval(view).ok_or("a V4 chain needs its epoch interval")?;
    let height = block.header.height;
    if height == 0 || !height.is_multiple_of(interval) {
        return Ok(None);
    }
    let epoch = epoch_of_height(height, interval);
    let current = committee_of(view, epoch).ok_or("no committee for the closing epoch")?;
    let proposed: Vec<ValidatorInfo> = view
        .get("sys:validator_set:v1")
        .map_err(|e| e.to_string())?
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();
    let genesis_identity = view
        .get("genesis_identity")
        .map_err(|e| e.to_string())?
        .ok_or("a V4 chain needs its genesis identity")?;
    let boundary = Boundary {
        epoch,
        current: &current,
        closing_round: block.header.round,
        anchor: &block.anchor_hash,
        block_hash: &block.header.hash,
        height,
        timestamp: block.header.timestamp,
    };
    let (start, invalid) = next_start(
        &blockchain::chain_id(),
        &genesis_identity,
        &boundary,
        &proposed,
    );
    // G5 EM-2: the executor recorded C_{E+1} in this block's state with the
    // same rule, and pays rewards and fees to that record. A different record
    // is a determinism fault: refuse the block rather than pay another set.
    let recorded: Option<Vec<ValidatorInfo>> = view
        .get(&format!("sys:validator_set:epoch:{}", start.epoch))
        .map_err(|e| e.to_string())?
        .and_then(|raw| serde_json::from_str(&raw).ok());
    if recorded.as_ref() != Some(&start.committee) {
        return Err(crate::alarm::raise(
            crate::alarm::Alarm::DecisionConflict,
            format!(
                "{}: the executor recorded another committee for epoch {}",
                crate::ordering::DECISION_CONFLICT,
                start.epoch
            ),
        ));
    }
    write_next(view, &start, invalid.as_deref())?;
    Ok(Some(start))
}

/// EP-4: QC(H_E) binds a next committee other than the one this node
/// derived. Written as `alarm:committee_mismatch:{E+1:020}`; ordering halts.
pub const COMMITTEE_MISMATCH: &str = "COMMITTEE_MISMATCH";

/// RC-3: where a node that lost its guards may resume signing.
pub const GUARD_RESUME_KEY: &str = "consensus:guard_resume_after";

/// RC-3: the resume point of a node whose guards are not continuous, written
/// once at its first such boot (a later boot keeps it). The margin covers
/// clock skew both ways (this node's clock and the BFT time of honest
/// vertices, each within `MAX_FUTURE_DRIFT_SECS`): a boundary block whose BFT
/// time is later than the point was made after the boot, so the epoch it
/// opens began after the guards were lost and holds no earlier signature.
pub fn resume_point(storage: &StateDB, now: u64) -> Result<u64, String> {
    if let Some(held) = storage
        .get(GUARD_RESUME_KEY)
        .map_err(|e| e.to_string())?
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Ok(held);
    }
    let point = now.saturating_add(2 * crate::ingress_v4::MAX_FUTURE_DRIFT_SECS);
    storage
        .put(GUARD_RESUME_KEY, &point.to_string())
        .map_err(|e| e.to_string())?;
    Ok(point)
}

/// `consensus:epoch_active`: the active epoch, written at activation.
pub const EPOCH_ACTIVE_KEY: &str = "consensus:epoch_active";
/// Standalone engines count their own blocks (one per decided anchor).
const STANDALONE_HEIGHT_KEY: &str = "consensus:standalone_height";

/// EP-2: a committee is non-empty, has unique addresses and at most 256
/// members, keeps only positive stake, and every member's Ed25519 key derives
/// its address and its BLS proof of possession verifies. One definition,
/// shared with the executor, which pays exactly this committee (G5 EM-2).
pub use blockchain::committee::validate_committee;

impl Engine {
    /// E's record as the engine holds it.
    pub(super) fn active_start(&self) -> EpochStart {
        EpochStart {
            epoch: self.epoch,
            first_round: self.first_round,
            sentinel: self.sentinel.clone(),
            committee: self.cfg.committee.clone(),
            prev_closing_round: 0,
            prev_anchor: String::new(),
            prev_block_hash: String::new(),
            prev_height: 0,
            prev_timestamp: 0,
        }
    }

    pub(super) fn previous_record(&self) -> Option<EpochRecord<'_>> {
        self.previous
            .as_ref()
            .map(|p| p.record(Some(self.previous_closing)))
    }

    pub(super) fn next_record(&self) -> Option<EpochRecord<'_>> {
        self.next.as_ref().map(|n| n.record(None))
    }

    /// Make `start` the active epoch: its committee decides, and signing
    /// follows membership in it (AT-1).
    fn set_active(&mut self, start: EpochStart) {
        let bls_pk = hex::encode(
            BLSEngine::consensus().pubkey_raw(&qc::derive_validator_bls_seed(&self.cfg.node_key)),
        );
        self.can_sign = start
            .committee
            .iter()
            .any(|m| m.address == self.cfg.address && m.stake > 0 && m.bls_public_key == bls_pk);
        self.stakes = start
            .committee
            .iter()
            .map(|m| (m.address.clone(), m.stake))
            .collect();
        self.committee_hash = qc::validator_set_hash(&start.committee);
        self.epoch = start.epoch;
        self.first_round = start.first_round;
        self.sentinel = start.sentinel;
        self.cfg.committee = start.committee;
        self.closing_round = None;
    }

    fn read_start(&self, epoch: u64) -> Result<Option<EpochStart>, String> {
        read_start_from(&self.storage, epoch)
    }

    /// RC-1 step 1 for epochs: the active epoch, the one before it, and the
    /// next one if its predecessor already closed.
    pub(super) fn load_epoch_state(&mut self) -> Result<(), String> {
        let active = self
            .storage
            .get(EPOCH_ACTIVE_KEY)
            .map_err(|e| e.to_string())?
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        self.blocks = self
            .storage
            .get(STANDALONE_HEIGHT_KEY)
            .map_err(|e| e.to_string())?
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        if active > 0 {
            let start = self
                .read_start(active)?
                .ok_or(format!("epoch {active} is active but has no record"))?;
            self.previous_closing = start.prev_closing_round;
            self.previous = match active - 1 {
                0 => Some(self.genesis.clone()),
                e => self.read_start(e)?,
            };
            lock(&self.ordering).begin_epoch(start.first_round, &start.sentinel)?;
            self.set_active(start);
        }
        if let Some(next) = self.read_start(active + 1)? {
            self.adopt_close(next);
            // A standalone engine that crashed between closing and activating
            // activates at the end of its first call (a host activates on
            // QC(H_E) as always).
            self.activation_due = self.cfg.epoch_interval > 0;
        }
        Ok(())
    }

    /// EP-2 and EP-3 (standalone): H_E is decided. E+1's record is written
    /// through `next_start` and `write_next`, and E closes. Idempotent.
    pub fn close_epoch(
        &mut self,
        closing_round: u64,
        anchor: &str,
        block_hash: &str,
        proposed: &[ValidatorInfo],
    ) -> Result<(), String> {
        if self.next.is_some() {
            return Ok(());
        }
        let boundary = Boundary {
            epoch: self.epoch,
            current: &self.cfg.committee,
            closing_round,
            anchor,
            block_hash,
            height: self.blocks,
            timestamp: (self.now_secs)(),
        };
        let (start, invalid) = next_start(
            &self.cfg.chain_id,
            &self.cfg.genesis_identity,
            &boundary,
            proposed,
        );
        write_next(&self.storage, &start, invalid.as_deref())?;
        self.adopt_close(start);
        Ok(())
    }

    /// E closes at the record's r*: ordering scans no anchor above it and
    /// production stops (EP-3).
    fn adopt_close(&mut self, next: EpochStart) {
        self.closing_round = Some(next.prev_closing_round);
        lock(&self.ordering).close_epoch_at(next.prev_closing_round);
        self.next = Some(next);
    }

    /// The host wrote E+1's record in H_E's transaction (`stage_boundary`):
    /// close E in memory. Returns whether E is (now) closed.
    pub fn observe_close(&mut self) -> Result<bool, String> {
        if self.next.is_some() {
            return Ok(true);
        }
        match self.read_start(self.epoch + 1)? {
            Some(next) => {
                self.adopt_close(next);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// E+1's record while E is closed and not yet succeeded.
    pub fn next_start(&self) -> Option<&EpochStart> {
        self.next.as_ref()
    }

    /// C_E, the active committee.
    pub fn committee(&self) -> &[ValidatorInfo] {
        &self.cfg.committee
    }

    /// The active epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The committee E+1 will have, once E has closed.
    pub fn next_committee(&self) -> Option<&[ValidatorInfo]> {
        self.next.as_ref().map(|n| n.committee.as_slice())
    }

    /// EP-4: activate E+1. The derived state resets to the new epoch (bodies,
    /// O_E, certificates, wants, the current round at its first round, the
    /// cursor there and g just below); this node's uncommitted epoch-E
    /// payloads go back to the host's mempool (`take_orphaned_payloads`); a
    /// node that abstained under RC-3 resumes; and E+1 messages held before
    /// activation are evaluated.
    pub fn activate_next(&mut self, net: &dyn ConsensusNet) -> Result<(), String> {
        let Some(next) = self.next.take() else {
            return Ok(());
        };
        self.storage
            .put(EPOCH_ACTIVE_KEY, &next.epoch.to_string())
            .map_err(|e| e.to_string())?;
        // Orphans are judged against E's floor and committed set, before
        // begin_epoch replaces both: above g_E the set is exact (GC-4), so a
        // committed proposal is never handed back. Below it GC already dropped
        // them, and the mempool's loan timeout reclaims their payloads (as it
        // does after a crash here: `orphaned` is not persisted).
        {
            let ordering = lock(&self.ordering);
            let floor = ordering.gc_floor();
            let uncommitted = self
                .own
                .iter()
                .filter(|(r, v)| **r > floor && !ordering.is_committed(&v.hash))
                .flat_map(|(_, v)| v.payload.iter().cloned());
            self.orphaned.extend(uncommitted);
        }
        lock(&self.ordering).begin_epoch(next.first_round, &next.sentinel)?;
        let closed = self.active_start();
        self.previous_closing = next.prev_closing_round;
        let closed_epoch = closed.epoch;
        let two_back = closed_epoch.checked_sub(1);
        self.previous = Some(closed);
        // E's tail (everything above g − RETAIN_SLACK) stays servable until
        // the next activation: a node behind the boundary finishes E from it.
        self.closed = Some(ClosedEpoch {
            epoch: closed_epoch,
            bodies: std::mem::take(&mut *lock(&self.dag)),
            certs: std::mem::take(&mut self.certs),
        });
        lock(&self.round_index).clear();
        self.cert_stake.clear();
        self.quorum_since.clear();
        self.owed_at.clear();
        self.orderable.clear();
        self.waiting.clear();
        self.body_wants.clear();
        self.cert_wants.clear();
        self.gap_high = 0;
        self.last_floor = self.gc_floor();
        self.own.clear();
        self.collectors.clear();
        let began_at = next.prev_timestamp;
        self.set_active(next);
        // RC-3: a node that abstained resumes at the activation of an epoch
        // that began after its guards were lost (review HIGH: "the next
        // activation it performs" re-armed a re-syncing node inside an epoch
        // it had already signed in).
        let began_after_loss = self.resume_after.is_some_and(|point| began_at > point);
        if !self.guards_continuous && began_after_loss {
            let origin = guard_origin(
                &self.cfg.chain_id,
                &self.cfg.genesis_identity,
                &self.cfg.node_key,
            );
            if self.storage.put("consensus:guard_origin", &origin).is_ok() {
                self.guards_continuous = true;
                self.resume_after = None;
                let _ = self.storage.delete(GUARD_RESUME_KEY);
            }
        }
        // GC-3 by epoch (Correction C7): the epoch before the one just closed
        // is forgotten; the closed one stays for late serving and evidence.
        if let Some(old) = two_back {
            self.delete_epoch_rows(old, u64::MAX);
        }
        self.early_keys.clear();
        for cert in std::mem::take(&mut self.early_certs) {
            self.on_cert(cert, net);
        }
        for v in self.pending.take_all() {
            let len = ingress_v4::canonical_body(&v).map_or(usize::MAX, |b| b.len());
            self.on_vertex(len, v, net);
        }
        Ok(())
    }

    /// RC-1 for the closed tail: E−1's rows above its last floor are still
    /// held (GC-3 by epoch deletes them only at the next activation).
    pub(super) fn load_closed(&mut self) -> Result<(), String> {
        let Some(record) = self.previous_record() else {
            return Ok(());
        };
        let floor = self
            .previous_closing
            .saturating_sub(crate::ordering::GC_DEPTH);
        let loaded = staging::load(
            &self.storage,
            &record,
            &self.cfg.chain_id,
            &self.cfg.genesis_identity,
            floor,
        )?;
        let epoch = record.epoch;
        self.closed = Some(ClosedEpoch {
            epoch,
            bodies: loaded
                .bodies
                .into_iter()
                .map(|(_, v)| (v.hash.clone(), v))
                .collect(),
            certs: loaded
                .certs
                .into_iter()
                .map(|c| ((c.body.round, c.body.author.clone()), c))
                .collect(),
        });
        Ok(())
    }

    /// Payloads of this node's epoch-E proposals that the boundary left
    /// uncommitted: the host returns them to its mempool.
    pub fn take_orphaned_payloads(&mut self) -> Vec<String> {
        std::mem::take(&mut self.orphaned)
    }

    /// Standalone only: the committee epoch `epoch` should get (tests stand in
    /// for the post-state of H_{epoch−1}).
    pub fn schedule_committee(&mut self, epoch: u64, committee: Vec<ValidatorInfo>) {
        self.scheduled.insert(epoch, committee);
    }

    /// Standalone only: count this decision as a block, and close the epoch
    /// on its boundary block (activation follows at the end of the call).
    pub(super) fn standalone_block(&mut self, info: &CommitInfo) {
        if self.cfg.epoch_interval == 0 {
            return;
        }
        self.blocks += 1;
        let _ = self
            .storage
            .put(STANDALONE_HEIGHT_KEY, &self.blocks.to_string());
        if self.blocks == (self.epoch + 1) * self.cfg.epoch_interval && self.next.is_none() {
            let proposed = self
                .scheduled
                .get(&(self.epoch + 1))
                .cloned()
                .unwrap_or_else(|| self.cfg.committee.clone());
            if self
                .close_epoch(
                    info.anchor_round,
                    &info.anchor_hash,
                    &info.finality_digest,
                    &proposed,
                )
                .is_ok()
            {
                self.activation_due = true;
            }
        }
    }
}
