use blockchain::Block;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use storage::StateDB;

/// G3 S6: snapshot restore from peers (SN-2).
pub mod state_sync;

/// `SYNC_REQ`: the blocks from `from_height` on. The requester is the
/// session that sent it (G4); the request names no one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub from_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub blocks: Vec<Block>,
    #[serde(default)]
    pub finality: Option<FinalityArtifact>,
    /// Set when the requested range is below the seed's prune horizon (the
    /// requested blocks no longer exist). Carries the lowest block height the
    /// seed can still serve, so the requester knows block-replay can't bridge
    /// the gap and it must bootstrap from a state snapshot instead of looping on
    /// empty responses. `None` from older peers (serde default).
    #[serde(default)]
    pub prune_horizon: Option<u64>,
    /// G1 IM-4: the QC of each served block that has one. A V4 chain imports a
    /// block only together with its QC (IM-1). Empty from older peers.
    #[serde(default)]
    pub qcs: Vec<consensus::qc::QuorumCertificate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalityArtifact {
    pub finalized_round: String,
    pub last_anchor_round: String,
    pub last_anchor_hash: String,
    pub finality_digest: String,
    /// The quorum certificate that cryptographically proves this finality (>2/3
    /// stake BLS signature). This is the ONLY thing that authorises advancing
    /// `consensus:finalized_round` on a syncing node — the legacy string fields
    /// above are unauthenticated hints. `None` from pre-QC peers (serde default),
    /// in which case finality is NOT advanced.
    #[serde(default)]
    pub qc: Option<consensus::qc::QuorumCertificate>,
}

pub struct ChainSync {
    storage: Arc<StateDB>,
    /// G3 S6: snapshot serving's own budget, global and per client IP.
    state_budget: state_sync::StateBudget,
    /// The values last served in parts.
    state_value_cache: Mutex<state_sync::ValueCache>,
    /// G3 S6: whether this node serves state snapshots at all
    /// (`AINCORE_SERVE_SNAPSHOTS=1`). Off by default: a snapshot read load
    /// on a validator's disk competes with consensus.
    serves_snapshots: bool,
    /// Block retention (`StateDB::block_pruning_policy_from_env`), read once.
    /// Imported blocks prune under it like built ones (G3 GC-1).
    retention: Option<(u64, u64)>,
    /// G4 S1: the sessions the network task holds; sync talks to peers over
    /// them only (the legacy TCP channel is gone, S6). None in tests that
    /// only serve.
    sessions: Option<network::SessionClient>,
    /// B33 review: passes in which each session advertised a height above
    /// this node's and delivered nothing. Those sessions are asked after
    /// the others, so peers that advertise a height they never serve cannot
    /// hold every one of a pass's slots.
    stalls: Mutex<HashMap<String, u32>>,
    #[cfg(test)]
    before_execution_hook: Option<fn(&StateDB)>,
}

/// G4 S1: how long one sync request on a session may take.
const SYNC_ASK_TIMEOUT: Duration = Duration::from_secs(60);
/// B33: how long a height or finality answer may take (a few bytes; a
/// choice far above a round trip).
const QUICK_ASK_TIMEOUT: Duration = Duration::from_secs(5);
/// B33: the sessions a pass takes blocks from, the highest first (a choice).
const SYNC_PEERS_PER_PASS: usize = 3;

/// NI-4: the blocks of one SYNC_RESP stop at this many bytes (at least one
/// block is sent), so the answer stays under the 10 MiB a client reads.
pub const SYNC_RESP_BLOCK_BYTES: usize = 8 << 20;

/// A seed's finality tip as this node can judge it.
enum Tip {
    /// Its QC verifies under its epoch's committee.
    Verified(Box<consensus::qc::QuorumCertificate>),
    /// B57: its QC is in an epoch whose committee this node does not hold
    /// yet, above this node's tip.
    Ahead,
    /// No answer, or a QC that does not verify.
    None,
}

/// The peer a sync client talks to: a session the network task holds (G4
/// S1).
enum SyncLink {
    Session {
        client: network::SessionClient,
        peer: String,
    },
}

impl SyncLink {
    async fn ask(&mut self, msg: &str) -> Result<String, String> {
        self.ask_within(msg, SYNC_ASK_TIMEOUT).await
    }

    async fn ask_within(&mut self, msg: &str, timeout: Duration) -> Result<String, String> {
        match self {
            Self::Session { client, peer } => client.ask(peer, msg, timeout).await,
        }
    }
}

impl ChainSync {
    pub fn new(storage: Arc<StateDB>) -> Self {
        Self {
            storage,
            state_budget: state_sync::StateBudget::default(),
            state_value_cache: Mutex::new(state_sync::ValueCache::default()),
            serves_snapshots: std::env::var("AINCORE_SERVE_SNAPSHOTS").as_deref() == Ok("1"),
            retention: StateDB::block_pruning_policy_from_env(),
            sessions: None,
            stalls: Mutex::default(),
            #[cfg(test)]
            before_execution_hook: None,
        }
    }

    /// Tests only: a retention policy other than the environment's.
    #[cfg(test)]
    pub(crate) fn with_retention(mut self, retention: Option<(u64, u64)>) -> Self {
        self.retention = retention;
        self
    }

    /// Serve state snapshots (G3 S6), whatever `AINCORE_SERVE_SNAPSHOTS` says.
    pub fn with_snapshot_serving(mut self, serve: bool) -> Self {
        self.serves_snapshots = serve;
        self
    }

    /// G4 S1: sync over the network task's sessions.
    pub fn with_sessions(mut self, client: network::SessionClient) -> Self {
        self.sessions = Some(client);
        self
    }

    fn verify_block_hash(block: &Block) -> Result<bool, String> {
        let computed_hash = blockchain::calculate_header_hash(&block.header);

        if computed_hash == block.header.hash {
            Ok(true)
        } else {
            Err(format!(
                "Hash Mismatch. Expected: {}, Computed: {}",
                block.header.hash, computed_hash
            ))
        }
    }

    #[cfg(test)]
    fn verify_execution_roots(
        &self,
        block: &Block,
        summary: &executor::BlockExecutionSummary,
    ) -> Result<(), String> {
        Self::verify_execution_roots_in(block, summary)
    }

    fn verify_execution_roots_in(
        block: &Block,
        summary: &executor::BlockExecutionSummary,
    ) -> Result<(), String> {
        // G3 FX-15: every block binds to the state it executes, always. There
        // is no switch and no env fallback: an empty root used to skip the
        // comparison entirely, letting a producer ship blocks bound to nothing.
        if block.header.state_root.is_empty() {
            return Err(format!(
                "block {} has an empty state_root; execution roots are required",
                block.header.height
            ));
        }
        if block.header.receipts_root.is_empty() {
            return Err(format!(
                "block {} has an empty receipts_root; execution roots are required",
                block.header.height
            ));
        }
        if block.header.state_root != summary.state_root {
            return Err(format!(
                "State root mismatch at block {}: header={}, executed={}",
                block.header.height, block.header.state_root, summary.state_root
            ));
        }
        if block.header.receipts_root != summary.receipts_root {
            return Err(format!(
                "Receipts root mismatch at block {}: header={}, executed={}",
                block.header.height, block.header.receipts_root, summary.receipts_root
            ));
        }
        // B14: a body is what executed and paid. A transaction in it that does
        // not execute here was stored for nothing on the producer.
        if block.transactions != summary.body {
            return Err(format!(
                "block {} carries {} transactions, {} of which execute",
                block.header.height,
                block.transactions.len(),
                summary.body.len()
            ));
        }
        Ok(())
    }

    fn active_validator_addresses(&self) -> Vec<String> {
        self.storage
            .get_active_validators()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect()
    }

    /// TASK-#29: number of distinct seed peers that must advertise a CONSISTENT
    /// finalized tip before this node will accept it as the head to sync past.
    ///
    /// Resolved from the genesis-pinned `sys:config:tip_agreement_n` so it is
    /// deterministic and identical across nodes (NO env var, NO wall-clock — this
    /// path runs during sync and must not fork). Default 1 preserves the current
    /// single-seed behaviour. A value below 1 is clamped to 1.
    fn tip_agreement_n(&self) -> usize {
        self.storage
            .get("sys:config:tip_agreement_n")
            .ok()
            .flatten()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .max(1)
    }

    /// TASK-#29 (pure, unit-testable): decide whether a set of seed-advertised
    /// finalized tips agree well enough to advance past.
    ///
    /// `tips` are the QCs gathered from DISTINCT seed peers (one entry per peer).
    /// Each QC has ALREADY been cryptographically verified by the caller (the QC
    /// crypto backstop in `apply_finality_artifact` is NOT weakened — this is an
    /// additional N-of-seed agreement gate on top of it). We require at least `n`
    /// of them to advertise the SAME `(block_height, block_hash)` finalized tip.
    ///
    /// Returns the agreed `(block_height, block_hash)` on success, or an `Err`
    /// describing the disagreement/shortfall so the caller can refuse to advance
    /// and log `🚨 [SECURITY][TIP_DISAGREEMENT]`.
    fn tip_agreement_decision(
        tips: &[consensus::qc::QuorumCertificate],
        n: usize,
    ) -> Result<(u64, String), String> {
        let n = n.max(1);
        if tips.len() < n {
            return Err(format!(
                "need {} agreeing seed tips but only {} seed(s) advertised a verifiable tip",
                n,
                tips.len()
            ));
        }
        // B44: each tip is a verified QC, so a tip that is merely behind
        // agrees with the head; only two different blocks certified at one
        // height disagree (a member one block behind used to fail the pass).
        let mut at: HashMap<u64, &str> = HashMap::new();
        for qc in tips {
            match at.get(&qc.block_height) {
                Some(hash) if *hash != qc.block_hash => {
                    return Err(format!(
                        "seeds disagree on the finalized head: two blocks certified at height {}",
                        qc.block_height
                    ))
                }
                _ => {
                    at.insert(qc.block_height, &qc.block_hash);
                }
            }
        }
        let head = tips
            .iter()
            .max_by(|a, b| a.block_height.cmp(&b.block_height))
            .map(|qc| (qc.block_height, qc.block_hash.clone()));
        head.ok_or_else(|| "no seed advertised a verifiable finalized tip".to_string())
    }

    fn validate_block(
        &self,
        block: &Block,
        expected_height: u64,
        prev_hash: &str,
    ) -> Result<(), String> {
        Self::validate_block_in(&self.storage, block, expected_height, prev_hash)
    }

    fn validate_block_in(
        storage: &StateDB,
        block: &Block,
        expected_height: u64,
        prev_hash: &str,
    ) -> Result<(), String> {
        if block.header.height != expected_height {
            return Err(format!(
                "Height mismatch: expected {}, got {}",
                expected_height, block.header.height
            ));
        }
        if expected_height == 1 && block.header.prev_hash != "genesis" {
            return Err(format!(
                "Genesis parent mismatch: expected genesis, got {}",
                block.header.prev_hash
            ));
        }
        if expected_height > 1 && block.header.prev_hash != prev_hash {
            return Err(format!(
                "Parent hash mismatch at {}: exp {}, got {}",
                expected_height, prev_hash, block.header.prev_hash
            ));
        }

        let validators = Self::eligible_proposers(storage, block.header.height)?;
        if !validators.contains(&block.header.proposer_id) {
            return Err(format!(
                "Proposer {} is not in active validator set",
                block.header.proposer_id
            ));
        }

        // Consumer-side invariant: only equivocation evidence is ordered
        // through the DAG. Reject a block carrying any other kind outright.
        if let Some(bad) = block
            .slash_evidence
            .iter()
            .find(|it| !consensus::DagConsensus::is_equivocation_item(it))
        {
            return Err(format!(
                "block {} carries non-equivocation slash evidence kind: {}",
                block.header.height,
                bad.chars().take(80).collect::<String>()
            ));
        }

        // S3-4a: Reject blocks with future timestamps (30s drift tolerance)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
            .as_secs();
        if block.header.timestamp > now + 30 {
            return Err(format!(
                "Future timestamp rejected: block={}, now={}",
                block.header.timestamp, now
            ));
        }

        // S3-4b: Reject blocks with excessive transaction count (DoS prevention)
        if block.transactions.len() > 10_000 {
            return Err(format!(
                "Transaction count {} exceeds max 10,000",
                block.transactions.len()
            ));
        }

        Self::verify_block_hash(block)?;
        // RE-AUDIT CRITICAL: a synced block must PROVE it was produced by a
        // validator. Followers adopt its committed sequence and BLS-vote for it,
        // so any peer able to forge a block could harvest votes on a fork. The
        // signer is the validator that BUILT this copy (`proposer_signer`) — every
        // validator builds every block deterministically, so binding to the anchor
        // leader's key instead made blocks syncable only from the leader itself
        // (98 rejections in one catch-up; a dead leader's blocks unsyncable).
        let signer = block.proposer_signer.clone();
        if signer.is_empty() {
            return Err(format!("Block #{} carries no proposer signer", block.header.height));
        }
        if !validators.contains(&signer) {
            return Err(format!(
                "Block #{} signer {} is not an active validator",
                block.header.height, signer
            ));
        }
        Self::verify_proposer_signature_in(storage, block)?;
        // B41: the costly checks last, once a validator's signature binds the
        // header (the DA root's encode costs up to ~0.6 s a batch).
        // Every header root against the body: transactions, the committed
        // vertex sequence a follower adopts, slash evidence, and the DA root
        // a light client samples against. Unconditional (G3 FX-18): an empty
        // root must mean an empty list, or a peer could attach vertices to a
        // block that has none.
        block.check_commitments()?;
        // G0 (V4): the anchor is the sequence's last vertex, which the header
        // binds; a substituted anchor under a reused signature stops here.
        if consensus::v4::is_v4_chain(storage) && !block.anchor_is_bound() {
            return Err(format!(
                "block {}'s anchor {} is not its last committed vertex",
                block.header.height, block.anchor_hash
            ));
        }
        Ok(())
    }

    /// Who may lead or sign block `height`. On V4 (G1 DE-7) the frozen
    /// committee of the height's epoch, C_E(h): a member that leaves or is
    /// slashed mid-epoch still leads its anchors, and the QC is the authority
    /// anyway (final review HIGH: gating on the live set made its blocks
    /// unsyncable). On V3 the live set, as before.
    fn eligible_proposers(storage: &StateDB, height: u64) -> Result<Vec<String>, String> {
        if consensus::v4::is_v4_chain(storage) {
            let epoch = consensus::qc_producer::epoch_for_block_height(storage, height)
                .ok_or("no epoch for this height")?;
            let committee = consensus::v4::epoch::committee_of(storage, epoch)
                .ok_or_else(|| format!("no committee for epoch {epoch}"))?;
            return Ok(committee.into_iter().map(|m| m.address).collect());
        }
        Ok(storage
            .get_active_validators_checked()
            .map_err(|e| format!("cannot resolve validator eligibility: {e}"))?
            .into_iter()
            .map(|(address, _)| address)
            .collect())
    }

    /// The block's proposer signature, under the public key its signer's
    /// account records in `storage`.
    pub(crate) fn verify_proposer_signature_in(
        storage: &StateDB,
        block: &Block,
    ) -> Result<(), String> {
        let signer = &block.proposer_signer;
        let signer_pk = storage
            .get_object(signer)
            .and_then(|obj| serde_json::from_slice::<serde_json::Value>(&obj.data).ok())
            .and_then(|v| v.get("public_key").and_then(|k| k.as_str()).map(String::from));
        match signer_pk {
            Some(pk) if block.verify_proposer_signature(&pk) => Ok(()),
            Some(_) => Err(format!(
                "Proposer signature invalid or missing on block #{} (signer {})",
                block.header.height, signer
            )),
            None => Err(format!(
                "Cannot resolve signer {} public key to authenticate block #{}",
                signer, block.header.height
            )),
        }
    }

    // Run before execution while holding the storage writer gate. In particular,
    // do not reuse parent/key/QC reads from the unlocked network precheck.
    fn validate_admission_in(storage: &StateDB, block: &Block) -> Result<(), String> {
        let height = block.header.height;
        if height == 0 {
            return Err("cannot admit block height zero".into());
        }
        let parent_hash = if height == 1 {
            "genesis".to_owned()
        } else {
            let parent_json = storage.get(&format!("block_{}", height - 1))
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "missing parent at admission".to_owned())?;
            let parent: Block = serde_json::from_str(&parent_json)
                .map_err(|e| format!("invalid parent at admission: {e}"))?;
            if parent.header.height != height - 1 {
                return Err("stored parent height mismatch at admission".into());
            }
            parent.header.hash
        };
        if let Some(json) = storage.get("consensus:qc:latest").map_err(|e| e.to_string())? {
            let qc: consensus::qc::QuorumCertificate = serde_json::from_str(&json)
                .map_err(|e| format!("invalid held QC at admission: {e}"))?;
            if qc.block_height == height && qc.block_hash != block.header.hash {
                return Err("held QC conflicts with block at admission".into());
            }
        }
        Self::validate_block_in(storage, block, height, &parent_hash)
    }

    fn get_local_height(&self) -> u64 {
        self.storage.get_chain_height()
    }

    fn finalized_round_boundary(&self) -> u64 {
        self.storage
            .get("consensus:finalized_round")
            .ok()
            .flatten()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0)
    }

    fn collect_finality_artifact(&self) -> FinalityArtifact {
        FinalityArtifact {
            finalized_round: self
                .storage
                .get("consensus:finalized_round")
                .ok()
                .flatten()
                .unwrap_or_else(|| "0".to_string()),
            last_anchor_round: self
                .storage
                .get("consensus:last_anchor_round")
                .ok()
                .flatten()
                .unwrap_or_else(|| "0".to_string()),
            last_anchor_hash: self
                .storage
                .get("consensus:last_anchor_hash")
                .ok()
                .flatten()
                .unwrap_or_default(),
            finality_digest: self
                .storage
                .get("consensus:finality_digest")
                .ok()
                .flatten()
                .unwrap_or_default(),
            // Serve the quorum certificate so peers can cryptographically VERIFY
            // (not trust) the finality we advertise.
            qc: self
                .storage
                .get("consensus:qc:latest")
                .ok()
                .flatten()
                .and_then(|j| serde_json::from_str::<consensus::qc::QuorumCertificate>(&j).ok()),
        }
    }

    /// The trusted validator set that a finality QC is verified against. SEC-#16:
    /// resolved by the QC's epoch (`sys:validator_set:epoch:{epoch}`, the snapshot
    /// frozen at that epoch's start) so a QC produced in an earlier epoch still
    /// verifies against the set that produced it. Missing historical snapshots
    /// cannot be substituted with the live set (legacy epoch-0 bootstrap aside).
    fn trusted_validator_set(&self, epoch: u64) -> Option<Vec<consensus::qc::ValidatorInfo>> {
        consensus::qc_producer::load_validator_set_for_epoch(&self.storage, epoch)
    }

    /// Apply a finality artifact — QC-GATED.
    ///
    /// SECURITY: only a quorum certificate that verifies (>2/3-stake aggregate
    /// BLS signature over the canonical FinalityVote) against our trusted
    /// validator set may advance `consensus:finalized_round`. The previous
    /// round-drift heuristic was forgeable: an unsigned `block.header.round`
    /// (blocks carry no proposer signature) could inflate the accepted round and
    /// poison `consensus:finalized_round`, halting a validator. With QC-gating a
    /// peer cannot move our finalized round without the validators' aggregate
    /// signature; a peer that supplies no/invalid QC simply does not advance our
    /// finality (a no-op, not a failure).
    fn apply_finality_artifact(&self, artifact: &FinalityArtifact) -> Result<(), String> {
        let Some(qc) = artifact.qc.as_ref() else {
            return Ok(()); // pre-QC peer: cannot move our finality, harmless
        };
        // Membership, local-block binding, monotonicity, finality metadata and
        // every QC index share one writer-gated transaction. Never publish just
        // the latest body: the producer consumes its height/round indexes too.
        if consensus::qc_producer::import_finality_qc(&self.storage, qc)? {
            println!(
                "✅ [ChainSync] Applied durable QC-verified finality: round={} (signed_stake={}/{})",
                qc.finalized_round, qc.signed_stake, qc.total_stake
            );
        }
        Ok(())
    }

    /// Sync over the network sessions (G4 S1).
    /// Returns the final synced height (0 if no sync happened)
    pub async fn sync_from_peers(&self) -> u64 {
        println!("🔄 [ChainSync] Starting sync over network sessions...");

        // Audit #3: `sync:halt_reason` stops syncing while it is present. No
        // code writes it any more (a block whose roots differ is refused on
        // its own, B45); an operator may set it to hold a node, and deletes
        // it to resume.
        if let Ok(Some(reason)) = self.storage.get("sync:halt_reason") {
            eprintln!(
                "🛑 [ChainSync] HALTED after a state divergence: {reason} — not syncing. \
                 Investigate, then clear `sync:halt_reason` to resume."
            );
            return self.get_local_height();
        }

        match self.sessions.clone() {
            Some(client) => self.sync_over_sessions(&client).await,
            None => {
                println!("📡 [ChainSync] No network sessions to sync over.");
                self.get_local_height()
            }
        }
    }

    /// G4 S1: sync over the sessions the network task holds, committee
    /// members first. The tip-agreement gate counts a member only by the key
    /// its session authenticated, never by an id a peer claims.
    async fn sync_over_sessions(&self, client: &network::SessionClient) -> u64 {
        let sessions = client.sessions();
        let mut final_height = self.get_local_height();
        if sessions.is_empty() {
            println!("📡 [ChainSync] No sessions available.");
            return final_height;
        }
        let tip_n = self.tip_agreement_n();
        if tip_n > 1 {
            let seed_set = self.active_validator_addresses();
            let mut tips = Vec::new();
            let mut ahead = 0usize;
            for session in &sessions {
                if !session
                    .member
                    .as_ref()
                    .is_some_and(|m| seed_set.contains(m))
                {
                    continue;
                }
                let mut link = SyncLink::Session {
                    client: client.clone(),
                    peer: session.peer.clone(),
                };
                match self.verified_tip_over(&mut link).await {
                    Tip::Verified(qc) => {
                        tips.push(*qc);
                        if tips.len() >= tip_n {
                            break;
                        }
                    }
                    Tip::Ahead => ahead += 1,
                    Tip::None => {}
                }
            }
            // B57: seeds whose tips lie in an epoch this node cannot verify
            // yet (it has not imported the boundary block) are ahead of it;
            // with too few verifiable tips then, the pass goes on, and every
            // block it imports still needs its own QC. Refusing left a
            // follower one boundary behind stalled for good. B72: an "ahead"
            // claim is unverified, so it counts as one seed's answer, never
            // as the agreement of N: the pass goes on only when verified
            // tips and ahead claims together reach N, and the verified tips
            // still agree among themselves. One seed naming an epoch the
            // node does not know used to waive the gate.
            if tips.len() < tip_n && tips.len() + ahead >= tip_n {
                // The verified tips, if any, must agree (with none, the
                // ahead claims alone reach N: B57's follower).
                let disagree = if tips.is_empty() {
                    Ok(())
                } else {
                    Self::tip_agreement_decision(&tips, tips.len()).map(|_| ())
                };
                if let Err(e) = disagree {
                    eprintln!(
                        "🚨 [SECURITY][TIP_DISAGREEMENT] {} — refusing to advance",
                        e
                    );
                    return final_height;
                }
                println!(
                    "📡 [ChainSync] {ahead} seed(s) are past an epoch this node has not reached; syncing toward them"
                );
            } else if let Err(e) = Self::tip_agreement_decision(&tips, tip_n) {
                eprintln!(
                    "🚨 [SECURITY][TIP_DISAGREEMENT] {} — refusing to advance",
                    e
                );
                return final_height;
            }
        }
        // B33: every session's height at once, each within
        // QUICK_ASK_TIMEOUT; then blocks from the highest few, members first.
        // Asked one after another with 60 s timeouts, one stalling peer cost
        // every pass about two minutes.
        let sessions_now: std::collections::HashSet<String> =
            sessions.iter().map(|s| s.peer.clone()).collect();
        let mut asks = tokio::task::JoinSet::new();
        for session in sessions {
            let client = client.clone();
            asks.spawn(async move {
                let height = client
                    .ask(&session.peer, "GET_HEIGHT", QUICK_ASK_TIMEOUT)
                    .await
                    .ok()
                    .and_then(|r| {
                        r.strip_prefix("HEIGHT:")
                            .and_then(|h| h.trim().parse::<u64>().ok())
                    });
                (session, height)
            });
        }
        // Peers at this node's height too: their finality artifact may carry
        // the QC of the tip.
        let mut ahead = Vec::new();
        while let Some(joined) = asks.join_next().await {
            if let Ok((session, Some(height))) = joined {
                if height >= final_height {
                    ahead.push((session, height));
                }
            }
        }
        let stalls = self.stalls.lock().map(|s| s.clone()).unwrap_or_default();
        let stalled = |peer: &str| stalls.get(peer).copied().unwrap_or(0);
        ahead.sort_by(|(a, ha), (b, hb)| {
            stalled(&a.peer)
                .cmp(&stalled(&b.peer))
                .then(b.member.is_some().cmp(&a.member.is_some()))
                .then(hb.cmp(ha))
                .then(a.peer.cmp(&b.peer))
        });
        for (session, advertised) in ahead.into_iter().take(SYNC_PEERS_PER_PASS) {
            let label = session
                .member
                .clone()
                .unwrap_or_else(|| session.peer.clone());
            let peer = session.peer.clone();
            let mut link = SyncLink::Session {
                client: client.clone(),
                peer: session.peer,
            };
            let before = self.get_local_height();
            let reached = self.sync_over(&mut link, &label, before).await;
            final_height = final_height.max(reached);
            if let Ok(mut stalls) = self.stalls.lock() {
                if reached > before {
                    stalls.remove(&peer);
                } else if advertised > before {
                    let n = stalls.entry(peer).or_insert(0);
                    *n = n.saturating_add(1);
                }
            }
        }
        if let Ok(mut stalls) = self.stalls.lock() {
            stalls.retain(|peer, _| sessions_now.contains(peer));
        }
        final_height
    }

    /// One peer's blocks over `link`: its height, then batches up to it, then
    /// its finality artifact. Returns the height reached.
    async fn sync_over(&self, link: &mut SyncLink, peer_id: &str, my_height: u64) -> u64 {
        let mut final_height = my_height;
        // 2. Request Chain Height
        let Ok(resp) = link.ask_within("GET_HEIGHT", QUICK_ASK_TIMEOUT).await else {
            return final_height;
        };
        // Parse Height response e.g. "HEIGHT:100"
        let Some(peer_height) = resp
            .strip_prefix("HEIGHT:")
            .and_then(|h| h.trim().parse::<u64>().ok())
        else {
            return final_height;
        };
        println!("📊 [ChainSync] Peer Height: {}", peer_height);

        if peer_height > my_height {
            // 3. Request Blocks — loop in batches until caught up
            let mut current = my_height;
            while current < peer_height {
                let sync_req = SyncRequest {
                    from_height: current,
                };
                let req_json = match serde_json::to_string(&sync_req) {
                    Ok(j) => j,
                    Err(e) => {
                        eprintln!("❌ [ChainSync] Failed to serialize sync request: {}", e);
                        break;
                    }
                };
                // 4. Receive Blocks Batch
                let data_resp = match link.ask(&format!("SYNC_REQ:{}", req_json)).await {
                    Ok(data_resp) => data_resp,
                    Err(e) => {
                        eprintln!(
                            "❌ [ChainSync] Failed to read SYNC_RESP from {}: {}",
                            peer_id, e
                        );
                        break;
                    }
                };
                let Some(json_data) = data_resp.strip_prefix("SYNC_RESP:") else {
                    eprintln!(
                        "❌ [ChainSync] Unexpected sync response prefix: {}",
                        data_resp.chars().take(80).collect::<String>()
                    );
                    break;
                };
                let Ok(sync_resp) = serde_json::from_str::<SyncResponse>(json_data) else {
                    eprintln!(
                        "❌ [ChainSync] Failed to parse SYNC_RESP JSON ({} bytes)",
                        json_data.len()
                    );
                    break;
                };
                let finality = sync_resp.finality.clone();
                if sync_resp.blocks.is_empty() {
                    if let Some(finality) = finality {
                        if let Err(e) = self.apply_finality_artifact(&finality) {
                            eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                        }
                    }
                    // Below the peer's prune horizon: block-replay
                    // cannot bridge this gap. Surface it clearly
                    // instead of looping silently on empty replies.
                    if let Some(horizon) = sync_resp.prune_horizon {
                        let local_now = self.get_local_height();
                        if horizon > local_now + 1 {
                            eprintln!(
                                "🛑 [ChainSync] peer pruned below us: earliest block #{} but we are at #{}. \
                                 Block-replay cannot bridge this: restore from a checkpoint \
                                 (AINCORE_STATE_SYNC_CHECKPOINT) or sync from a peer that keeps history.",
                                horizon, local_now
                            );
                        }
                    }
                    break; // No more blocks
                }
                let synced =
                    self.process_blocks_with_qcs(sync_resp.blocks, &sync_resp.qcs, current);
                if synced <= current {
                    eprintln!(
                        "⚠️ [ChainSync] Batch made no progress from height {}",
                        current
                    );
                    break; // No progress made
                }
                current = synced;
                final_height = synced;
                if let Some(finality) = finality {
                    if let Err(e) = self.apply_finality_artifact(&finality) {
                        eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                    }
                }
            }
        } else {
            println!("✅ [ChainSync] Already caught up with peer {}", peer_id);
        }

        if let Ok(finality_resp) = link.ask_within("GET_FINALITY", QUICK_ASK_TIMEOUT).await {
            if let Some(json) = finality_resp.strip_prefix("FINALITY:") {
                if let Ok(artifact) = serde_json::from_str::<FinalityArtifact>(json) {
                    if let Err(e) = self.apply_finality_artifact(&artifact) {
                        eprintln!("🚨 [SECURITY][SYNC_FINALITY_REJECT] {}", e);
                    }
                }
            }
        }
        final_height
    }

    /// A peer's finalized tip over `link`, iff its QC verifies against the
    /// trusted validator set of its epoch.
    async fn verified_tip_over(&self, link: &mut SyncLink) -> Tip {
        let Ok(resp) = link.ask_within("GET_FINALITY", QUICK_ASK_TIMEOUT).await else {
            return Tip::None;
        };
        let Some(qc) = resp
            .strip_prefix("FINALITY:")
            .and_then(|json| serde_json::from_str::<FinalityArtifact>(json).ok())
            .and_then(|artifact| artifact.qc)
        else {
            return Tip::None;
        };
        let Some(validators) = self.trusted_validator_set(qc.epoch) else {
            // B57: no committee yet for its epoch, past this node's tip.
            return if qc.block_height > self.get_local_height() {
                Tip::Ahead
            } else {
                Tip::None
            };
        };
        match consensus::qc::verify_qc(&qc, &validators, &consensus::qc::expected_chain_id()) {
            Ok(()) => Tip::Verified(Box::new(qc)),
            Err(_) => Tip::None,
        }
    }

    /// Process synced blocks — returns the final height reached
    #[cfg(test)]
    fn process_blocks(&self, blocks: Vec<Block>, current_height: u64) -> u64 {
        self.process_blocks_with_qcs(blocks, &[], current_height)
    }

    /// `process_blocks` with the peer's per-height QCs. On a V4 chain (G1
    /// IM-1) a block is executed only together with a QC that verifies under
    /// its epoch's committee and binds its hash, anchor and roots; the QC is
    /// imported with it. A proposer signature alone is not enough.
    fn process_blocks_with_qcs(
        &self,
        blocks: Vec<Block>,
        qcs: &[consensus::qc::QuorumCertificate],
        current_height: u64,
    ) -> u64 {
        let v4 = consensus::v4::is_v4_chain(&self.storage);
        let qc_of = |b: &Block| -> Option<&consensus::qc::QuorumCertificate> {
            qcs.iter().find(|q| q.block_height == b.header.height)
        };
        let mut last_processed = current_height;
        let executor = executor::Executor::new(std::sync::Arc::clone(&self.storage));
        let total_blocks = blocks.len();
        let finalized_round = self.finalized_round_boundary();

        // AUDIT-H2 (verify-before-execute, QC pin): `consensus:qc:latest` is only
        // ever written AFTER apply_finality_artifact has cryptographically
        // verified a quorum certificate (chain-id + trusted-validator-set bound)
        // — so its (block_height, block_hash) is an AUTHENTICATED pin. If this
        // downloaded batch claims to contain the certified height, its block
        // there MUST carry the certified hash; a mismatch proves the peer is
        // serving a fabricated chain, and the ENTIRE batch is rejected BEFORE a
        // single transaction of it executes. Blocks above the pin (not yet
        // certified) keep today's defense (execute + re-derived-root check +
        // reject), and the executor's own signature/nonce gates bound what an
        // unauthenticated block can do. This closes H-2's "forged block executes
        // first, gets rejected after" window for everything at or below the
        // latest certified height.
        if let Ok(Some(qc_json)) = self.storage.get("consensus:qc:latest") {
            if let Ok(qc) = serde_json::from_str::<consensus::qc::QuorumCertificate>(&qc_json) {
                if let Some(b) = blocks.iter().find(|b| b.header.height == qc.block_height) {
                    if b.header.hash != qc.block_hash {
                        // G1 IM-3 (V4): the peer's block has its own verified
                        // QC. Two certified blocks at one height is a conflict.
                        if v4 {
                            if let Some(q) = qc_of(b) {
                                if consensus::qc_producer::verify_block_qc(&self.storage, b, q)
                                    .is_ok()
                                {
                                    consensus::qc_producer::record_decision_conflict(
                                        &self.storage,
                                        b.header.height,
                                        &format!(
                                            "{}: two QCs at height {}: {} and {}",
                                            consensus::ordering::DECISION_CONFLICT,
                                            b.header.height,
                                            qc.block_hash,
                                            b.header.hash
                                        ),
                                    );
                                }
                            }
                        }
                        eprintln!(
                            "🚨 [SECURITY][SYNC_QC_PIN_REJECT] peer's block #{} hash {} does not \
                             match the QC-certified hash {} — rejecting the whole batch before \
                             execution (fabricated chain)",
                            qc.block_height, b.header.hash, qc.block_hash
                        );
                        return last_processed;
                    }
                }
            }
        }

        for (i, block) in blocks.iter().enumerate() {
            if block.header.height <= last_processed {
                let key = format!("block_{}", block.header.height);
                if let Ok(Some(existing_json)) = self.storage.get(&key) {
                    if let Ok(existing) = serde_json::from_str::<Block>(&existing_json) {
                        if existing.header.hash == block.header.hash {
                            // A held block's missing QC (a crash lost it, or it
                            // never formed here) is imported from the peer's.
                            if v4
                                && consensus::qc_producer::stored_qc(
                                    &self.storage,
                                    block.header.height,
                                )
                                .is_none()
                            {
                                if let Some(q) = qc_of(block) {
                                    self.import_block_qc(q);
                                }
                            }
                            continue;
                        }
                        if existing.header.round <= finalized_round
                            || block.header.round <= finalized_round
                        {
                            eprintln!(
                                "🚨 [SECURITY][SYNC_REORG_REJECT] conflict at finalized boundary height={} local_round={} remote_round={} finalized_round={}",
                                block.header.height,
                                existing.header.round,
                                block.header.round,
                                finalized_round
                            );
                            break;
                        }
                        // G1 IM-3 (V4): a verified QC for this other block
                        // proves the local chain is not the certified one.
                        // Halt with the alarm; never serve or build on it.
                        if v4 {
                            if let Some(q) = qc_of(block) {
                                if consensus::qc_producer::verify_block_qc(&self.storage, block, q)
                                    .is_ok()
                                {
                                    let why = format!(
                                        "{}: a QC certifies block {} at height {}, this node holds {}",
                                        consensus::ordering::DECISION_CONFLICT,
                                        block.header.hash,
                                        block.header.height,
                                        existing.header.hash
                                    );
                                    consensus::qc_producer::record_decision_conflict(
                                        &self.storage,
                                        block.header.height,
                                        &why,
                                    );
                                    break;
                                }
                            }
                        }
                        // A proposer signature or a longer peer chain is not a
                        // fork-choice proof. Even zero-TX blocks advance execution
                        // and may sweep fees or advance epochs. Deleting block rows
                        // cannot undo that state, QC indexes or ordering history.
                        // Until authenticated fork adoption and atomic state recovery
                        // exist, reject every conflict without writes or a halt latch.
                        eprintln!(
                            "[SECURITY][SYNC_REORG_REJECT] conflict at height {} requires authenticated fork choice and complete state recovery; preserving local chain",
                            block.header.height
                        );
                        break;
                    } else {
                        eprintln!(
                            "🚨 [SECURITY][SYNC_REORG_REJECT] corrupt local block json at height {}",
                            block.header.height
                        );
                        break;
                    }
                } else {
                    continue;
                }
            }

            let expected_height = last_processed + 1;
            let prev_hash = if expected_height > 1 {
                let prev_key = format!("block_{}", last_processed);
                match self
                    .storage
                    .get(&prev_key)
                    .ok()
                    .flatten()
                    .and_then(|json| serde_json::from_str::<Block>(&json).ok())
                    .map(|b| b.header.hash)
                {
                    Some(hash) => hash,
                    None => {
                        eprintln!(
                            "🚨 [SECURITY] Cannot verify parent for block #{}: missing local block #{}",
                            expected_height, last_processed
                        );
                        break;
                    }
                }
            } else {
                "genesis".to_string()
            };

            if let Err(e) = self.validate_block(block, expected_height, &prev_hash) {
                eprintln!(
                    "🚨 [SECURITY] Block #{} validation FAILED: {}",
                    block.header.height, e
                );
                break;
            }
            let qc = if v4 {
                let checked = qc_of(block).map(|q| {
                    consensus::qc_producer::verify_block_qc(&self.storage, block, q).map(|()| q)
                });
                match checked {
                    Some(Ok(q)) => Some(q.clone()),
                    Some(Err(e)) => {
                        eprintln!(
                            "🚨 [SECURITY][SYNC_QC_REJECT] block #{}: {e}",
                            block.header.height
                        );
                        break;
                    }
                    None => {
                        eprintln!(
                            "[ChainSync] block #{} came without its QC; not executed (V4)",
                            block.header.height
                        );
                        break;
                    }
                }
            } else {
                None
            };

            // Validate roots and stage block/index storage in the SAME transaction
            // as execution. Rejection must not consume a nonce or execution height.
            #[cfg(test)]
            if let Some(hook) = self.before_execution_hook {
                hook(&self.storage);
            }
            // B23: only an alarm this block's import raises can halt.
            consensus::alarm::clear();
            match executor.execute_block_admitted_at(
                block.transactions.clone(),
                &block.header.proposer_id,
                // The synced block's own height (epoch determinism — see
                // executor::execute_block_parallel_at).
                block.header.height,
                // G5 CL-2: its certified BFT timestamp drives consensus time.
                block.header.timestamp,
                // G5 BW-6: its certified anchor round.
                block.header.round,
                // RE-AUDIT HIGH: the block's own slash evidence, verified by
                // the executor — identical on every node.
                &block.slash_evidence,
                &block.committed_authors,
                |view| Self::validate_admission_in(view, block),
                |summary, view| {
                    Self::verify_execution_roots_in(block, summary)?;
                    let json = serde_json::to_string(block).map_err(|e| e.to_string())?;
                    view.save_block_json(block.header.height, &json).map_err(|e| e.to_string())?;
                    // G1 EP-2/EP-3: an imported boundary block closes its epoch
                    // in its own transaction, so H_E + 1's QC verifies under
                    // C_{E+1}. EP-4: QC(H_E) must bind the committee derived.
                    // G1 IM-2 (V4): the block's QC is stored in the block's own
                    // transaction; a crash between them used to leave the
                    // block without its QC, and adoption waiting forever.
                    if let Some(q) = &qc {
                        consensus::qc_producer::stage_block_qc(view, q)?;
                    }
                    if let Some(start) = consensus::v4::epoch::stage_boundary(view, block)? {
                        let derived = consensus::qc::validator_set_hash(&start.committee);
                        if let Some(q) = &qc {
                            if q.next_validator_set_hash != derived {
                                return Err(consensus::alarm::raise(
                                    consensus::alarm::Alarm::CommitteeMismatch,
                                    format!(
                                        "{}: QC(H_{}) binds next committee {:?}, this node derived {derived}",
                                        consensus::v4::epoch::COMMITTEE_MISMATCH,
                                        start.epoch - 1,
                                        q.next_validator_set_hash
                                    ),
                                ));
                            }
                        }
                    }
                    Ok(())
                },
            ) {
                Ok(executor::BlockExecOutcome::Executed(_)) => {
                    // (its QC was stored in the same transaction)
                    last_processed = block.header.height;
                    consensus::dag::prune_history(&self.storage, last_processed, self.retention);
                }
                Ok(executor::BlockExecOutcome::AlreadyExecuted { last_executed }) => {
                    // Execution completion alone does not identify the block.
                    // Missing storage may mean an in-flight producer OR a crash
                    // between execution and save_block_json. Wait for a matching
                    // persisted block; never infer identity from the height.
                    let stored = self
                        .storage
                        .get(&format!("block_{}", block.header.height))
                        .ok()
                        .flatten()
                        .and_then(|j| serde_json::from_str::<Block>(&j).ok())
                        .map(|b| b.header.hash);
                    match stored {
                        Some(h) if h != block.header.hash => {
                            eprintln!(
                                "🚨 [SECURITY][SYNC_HEIGHT_ALREADY_EXECUTED] peer's block #{} hash {} \
                                 conflicts with our stored {} at an executed height (last_executed={}) \
                                 — rejecting this peer's batch",
                                block.header.height, block.header.hash, h, last_executed
                            );
                            break;
                        }
                        Some(_) => {
                            last_processed = last_processed.max(block.header.height);
                            if let Some(q) = &qc {
                                self.import_block_qc(q);
                            }
                            continue;
                        }
                        None => {
                            eprintln!(
                                "[ChainSync][EXECUTION_WITHOUT_BLOCK] height {} was executed \
                                 (last_executed={}) but its stored block is missing or unreadable; \
                                 stopping this batch without advancing sync",
                                block.header.height, last_executed
                            );
                            break;
                        }
                    }
                }
                // Executing out of order would corrupt the state-root chain.
                Ok(executor::BlockExecOutcome::Gap { expected, got }) => {
                    eprintln!(
                        "⏸️  [ChainSync] execution gap: expected height {}, peer offered {} — stopping this batch",
                        expected, got
                    );
                    break;
                }
                Err(error) => {
                    // The error can be invalid roots OR local storage failure.
                    // Neither authorizes progress or a permanent peer-triggered halt.
                    eprintln!(
                        "[ChainSync][BLOCK_ACCEPTANCE_FAILED] block #{} was not accepted: {}",
                        block.header.height, error
                    );
                    // Except EP-4's: a verified QC(H_E) (>2/3 of C_E) certifies
                    // a next committee this node did not derive from the same
                    // post-state. That is not a peer's fault: the node halts.
                    if consensus::alarm::take() == Some(consensus::alarm::Alarm::CommitteeMismatch) {
                        if let Some(interval) = consensus::v4::epoch::epoch_interval(&self.storage) {
                            let next = consensus::v4::epoch::epoch_of_height(
                                block.header.height,
                                interval,
                            ) + 1;
                            let _ = self.storage.put(
                                &format!("alarm:committee_mismatch:{next:020}"),
                                &error,
                            );
                        }
                    }
                    break;
                }
            }

            // Progress logging for large syncs
            if total_blocks > 10 && (i + 1) % 50 == 0 {
                println!(
                    "📦 [ChainSync] Progress: {}/{} blocks processed",
                    i + 1,
                    total_blocks
                );
            }
        }
        if last_processed > current_height {
            println!(
                "✅ [ChainSync] Synced up to block #{} (+{} blocks)",
                last_processed,
                last_processed - current_height
            );
        }
        last_processed
    }

    /// Store a verified block QC (IM-1/IM-4). Idempotent; a failure only
    /// delays adoption, which waits for a stored QC.
    fn import_block_qc(&self, q: &consensus::qc::QuorumCertificate) {
        if let Err(e) = consensus::qc_producer::import_finality_qc(&self.storage, q) {
            eprintln!(
                "[ChainSync] QC of block #{} not stored ({e}); adoption waits",
                q.block_height
            );
        }
    }

    /// The requests `handle_message` answers. The node's session layer routes
    /// exactly these here, so a request type is added in one place.
    pub fn serves(msg: &str) -> bool {
        msg == "GET_HEIGHT"
            || msg == "GET_FINALITY"
            || [
                "SYNC_REQ:",
                state_sync::ANCHOR_REQ,
                state_sync::CHUNK_REQ,
                state_sync::VALUE_REQ,
            ]
            .iter()
            .any(|prefix| msg.starts_with(prefix))
    }

    /// G4 S1/S6: a request a libp2p session sent: what `serves` lists
    /// (snapshot serving charged to `peer`, the key the session
    /// authenticated), and a boundary QC (`QC_WANT:h`, answered
    /// `QC_CERT:{qc}` for a held height, so an observer can activate an
    /// epoch).
    pub fn serve_session(&self, msg: &str, peer: &str) -> Option<String> {
        if let Some(height) = msg.strip_prefix(consensus::dag::QC_WANT_PREFIX) {
            let height = height.parse::<u64>().ok()?;
            if height > self.get_local_height() {
                return None;
            }
            let qc = consensus::qc_producer::stored_qc(&self.storage, height)?;
            return Some(format!(
                "{}{}",
                consensus::dag::QC_CERT_PREFIX,
                serde_json::to_string(&qc).ok()?
            ));
        }
        if Self::serves(msg) {
            self.handle_request(msg, Some(peer))
        } else {
            None
        }
    }

    /// A request from an in-process caller (global limits only).
    pub fn handle_message(&self, msg: &str) -> Option<String> {
        self.handle_request(msg, None)
    }

    /// A request charged to `client` (the key a session authenticated;
    /// `None` is an in-process caller, global limits only).
    fn handle_request(&self, msg: &str, client: Option<&str>) -> Option<String> {
        // Handle Request Logic
        if msg == "GET_HEIGHT" {
            let h = self.get_local_height();
            return Some(format!("HEIGHT:{}", h));
        }

        if msg == "GET_FINALITY" {
            if let Ok(json) = serde_json::to_string(&self.collect_finality_artifact()) {
                return Some(format!("FINALITY:{}", json));
            }
            return None;
        }

        if let Some(req_json) = msg.strip_prefix(state_sync::CHUNK_REQ) {
            let req = serde_json::from_str::<state_sync::ChunkRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.serve_state_chunk(req, client)).ok()?;
            return Some(format!("{}{}", state_sync::CHUNK_RESP, resp));
        }
        if let Some(req_json) = msg.strip_prefix(state_sync::VALUE_REQ) {
            let req = serde_json::from_str::<state_sync::ValueRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.serve_state_value(req, client)).ok()?;
            return Some(format!("{}{}", state_sync::VALUE_RESP, resp));
        }
        if let Some(req_json) = msg.strip_prefix(state_sync::ANCHOR_REQ) {
            let req = serde_json::from_str::<state_sync::AnchorRequest>(req_json).ok()?;
            let resp = serde_json::to_string(&self.handle_state_anchor(req)).ok()?;
            return Some(format!("{}{}", state_sync::ANCHOR_RESP, resp));
        }
        if let Some(req_json) = msg.strip_prefix("SYNC_REQ:") {
            if let Ok(req) = serde_json::from_str::<SyncRequest>(req_json) {
                let resp = self.handle_sync_request(req);
                if let Ok(resp_json) = serde_json::to_string(&resp) {
                    return Some(format!("SYNC_RESP:{}", resp_json));
                }
            }
        }
        None
    }

    pub fn handle_sync_request(&self, req: SyncRequest) -> SyncResponse {
        let mut blocks_to_send = Vec::new();
        let local_height = self.get_local_height();

        // Limit batch size to avoid huge messages (Optimized to 500 for Production Performance)
        let end_height = std::cmp::min(local_height, req.from_height + 500);
        // NI-4: and by bytes, so the answer fits what a client reads (500
        // full blocks would be far over it); at least one block goes.
        let mut bytes = 0usize;

        for height in (req.from_height + 1)..=end_height {
            let key = format!("block_{}", height);
            if let Ok(Some(block_data)) = self.storage.get(&key) {
                if !blocks_to_send.is_empty() && bytes + block_data.len() > SYNC_RESP_BLOCK_BYTES {
                    break;
                }
                if let Ok(block) = serde_json::from_str::<Block>(&block_data) {
                    bytes += block_data.len();
                    blocks_to_send.push(block);
                }
            }
        }
        // Prune-horizon signal (audit #9): trigger whenever the FIRST requested
        // block is missing — not only when the whole batch is empty. Otherwise a
        // request whose start is pruned but whose tail (e.g. from_height+50)
        // still exists returns non-empty blocks the requester cannot apply (height
        // gap) AND no signal, so it never learns it must state-sync.
        let first_block_pruned = req.from_height < local_height
            && self
                .storage
                .get(&format!("block_{}", req.from_height + 1))
                .ok()
                .flatten()
                .is_none();
        let prune_horizon = if first_block_pruned {
            Some(self.earliest_available_block(req.from_height + 1, local_height))
        } else {
            None
        };
        let qcs = blocks_to_send
            .iter()
            .filter_map(|b| consensus::qc_producer::stored_qc(&self.storage, b.header.height))
            .collect();
        SyncResponse {
            blocks: blocks_to_send,
            finality: Some(self.collect_finality_artifact()),
            prune_horizon,
            qcs,
        }
    }

    /// Lowest block height still present, searched within `[lo, hi]`. After
    /// prefix-pruning, block existence is monotonic (absent below the horizon,
    /// present from it to the tip), so a binary search finds the horizon.
    fn earliest_available_block(&self, lo: u64, hi: u64) -> u64 {
        let exists = |h: u64| {
            self.storage
                .get(&format!("block_{}", h))
                .ok()
                .flatten()
                .is_some()
        };
        if exists(lo) {
            return lo;
        }
        let (mut lo, mut hi) = (lo, hi);
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            if exists(mid) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        hi
    }
}

#[cfg(test)]
mod tests;

/// Test helper: the state root an empty block at `height` with BFT timestamp
/// `timestamp` would have on top of the executed chain, found by executing it
/// in a block transaction that is then discarded (nothing is written). It is
/// exact at any height, including boundary blocks, whose committee record and
/// epoch writes a fixture would otherwise have to predict.
#[cfg(test)]
pub(crate) fn dry_run_empty_block_root(storage: &Arc<StateDB>, height: u64, timestamp: u64) -> String {
    let executor = executor::Executor::new(Arc::clone(storage));
    let mut root = None;
    let outcome = executor.execute_block_admitted_at(
        vec![],
        "dry-run",
        height,
        timestamp,
        0,
        &[],
        &[],
        |_| Ok(()),
        |summary, _| {
            root = Some(summary.state_root.clone());
            Err("dry run".into())
        },
    );
    assert!(outcome.is_err(), "the dry run must not commit");
    root.expect("the parent height is executed")
}
