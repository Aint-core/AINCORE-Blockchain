use serde::{Deserialize, Serialize};
use std::sync::Arc;
use storage::StateDB;

fn serialize_u128_string<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

fn deserialize_u128_string<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U128StringOrNumber {
        String(String),
        Number(u128),
    }

    match U128StringOrNumber::deserialize(deserializer)? {
        U128StringOrNumber::String(value) => value.parse().map_err(serde::de::Error::custom),
        U128StringOrNumber::Number(value) => Ok(value),
    }
}

// === Governance Structs ===
// NOTE: Native AccountData is no longer used in this module.
// All balance queries now go through query_move_vm_balance() which reads
// the authoritative Move VM CoinStore<AincoreCoin> resource directly.

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VoteRecord {
    pub proposal_id: String,
    pub voter: String,
    pub timestamp: u64,
    /// Phase 2.6 (M-03): voter's voting weight locked in at the moment
    /// of the vote. Subsequent transfers of the voter's CoinStore
    /// balance cannot change this number — anti "vote then transfer
    /// then vote again" — and the audit trail records exactly what
    /// stake each address committed to a given proposal.
    #[serde(default)]
    #[serde(serialize_with = "serialize_u128_string")]
    #[serde(deserialize_with = "deserialize_u128_string")]
    pub weight: u128,
    /// Phase 2.6 (M-03): chain height at the moment the vote was cast.
    /// Used together with `Proposal::snapshot_block_height` so future
    /// historical-state replay (when the indexer ships) can verify
    /// the voter actually held that stake at that height.
    #[serde(default)]
    pub block_height_at_vote: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EconomicParams {
    pub base_reward: Option<u64>,
    pub halving_interval: Option<u64>,
    pub burn_percentage: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum GovernanceAction {
    UpdateFederationKey(String), // New Federation Address
    UpdateEconomicParams(EconomicParams),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Proposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub proposer: String,
    pub action: Option<GovernanceAction>, // Executable Action
    pub start_time: u64,
    pub end_time: u64,
    pub execution_time: Option<u64>, // TimeLock: Earliest execution time
    pub yes_votes: u128,             // L3 FIX: Match u128 balance type
    pub no_votes: u128,
    pub status: ProposalStatus,
    /// Phase 2.6 (M-03): chain height when this proposal was created.
    /// Voting weight semantics: a vote's weight is the voter's CoinStore
    /// balance AT THE MOMENT OF THE VOTE, locked in via the VoteRecord
    /// and the Move-level escrow. When a historical-state indexer ships
    /// (block-height → state-root mapping), this field becomes the
    /// canonical snapshot point so vote weights can be re-verified
    /// against the voter's balance at `snapshot_block_height`.
    /// Until then, the field is recorded for forensic / audit use.
    #[serde(default)]
    pub snapshot_block_height: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ProposalStatus {
    Active,
    Passed, // Vote Succeeded, but waiting for TimeLock
    Queued, // (Optional intermediate state)
    Rejected,
    Executed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vote {
    pub proposal_id: String,
    pub voter: String,
    pub approve: bool,
    pub weight: u128, // L3 FIX: Stake amount in u128 to match coin module
}

pub struct GovernanceManager {
    db: Arc<StateDB>,
}

/// Storage key holding a JSON `Vec<String>` of proposal ids that are not yet in
/// a terminal state (Active / Passed / Queued). The deterministic driver walks
/// this bounded list each epoch boundary; terminal proposals (Executed /
/// Rejected) are pruned out so the list cannot grow without bound.
const ACTIVE_PROPOSAL_INDEX_KEY: &str = "gov:active_proposal_ids";

/// Hard cap on the number of tracked active proposals. Keeps the per-epoch
/// driver work bounded and deterministic regardless of proposal creation rate.
const MAX_ACTIVE_PROPOSALS: usize = 1024;

impl GovernanceManager {
    pub fn new(db: Arc<StateDB>) -> Self {
        Self { db }
    }

    /// Local node wall-clock seconds. Used ONLY by the non-deterministic
    /// `tally`/`execute_proposal` convenience wrappers, never on a consensus
    /// path.
    fn wall_clock_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// === C-12 FIX: Query Move VM CoinStore<AincoreCoin> for authoritative balance ===
    /// Reads the BCS-encoded CoinStore resource directly from RocksDB storage.
    /// This bypasses the native AccountData entirely, ensuring the governance module
    /// uses the Single Source of Truth (SSoT) for all balance-dependent decisions.
    ///
    /// Resource key format: resource_{hex_address}_0x1::coin::CoinStore<0x1::staking::AincoreCoin>
    /// BCS layout of CoinStore<T>: { coin: Coin<T> { value: u128 } }
    /// Since Coin<T> is a single-field struct, the BCS encoding is just a u128 (16 bytes LE).
    fn query_move_vm_balance(&self, address: &str) -> u128 {
        let trimmed = address.trim_start_matches("0x");
        let canonical_addr =
            match move_core_types::account_address::AccountAddress::from_hex_literal(&format!(
                "0x{}",
                trimmed
            )) {
                Ok(addr) => addr.to_string(),
                Err(_) => {
                    println!("⚠️ GOVERNANCE: Invalid address format '{}'", address);
                    return 0;
                }
            };

        let resource_key = format!(
            "resource_{}_0x1::coin::CoinStore<0x1::staking::AincoreCoin>",
            canonical_addr
        );

        match self.db.get(&resource_key) {
            Ok(Some(hex_data)) => {
                // Decode hex -> bytes
                match hex::decode(&hex_data) {
                    Ok(bytes) => {
                        // BCS layout: CoinStore { coin: Coin { value: u128 } }
                        // Coin is a single-field struct, so BCS encodes it as just the u128.
                        // CoinStore wraps Coin, so the total BCS is still just a u128 (16 bytes LE).
                        if bytes.len() >= 16 {
                            let mut arr = [0u8; 16];
                            arr.copy_from_slice(&bytes[0..16]);
                            u128::from_le_bytes(arr)
                        } else {
                            println!(
                                "⚠️ GOVERNANCE: CoinStore resource too short ({} bytes) for {}",
                                bytes.len(),
                                address
                            );
                            0
                        }
                    }
                    Err(e) => {
                        println!(
                            "⚠️ GOVERNANCE: Failed to decode CoinStore hex for {}: {}",
                            address, e
                        );
                        0
                    }
                }
            }
            Ok(None) => {
                // No CoinStore resource exists — account has no AIN balance in Move VM
                println!(
                    "ℹ️ GOVERNANCE: No CoinStore resource found for {} — balance is 0",
                    address
                );
                0
            }
            Err(e) => {
                println!(
                    "⚠️ GOVERNANCE: DB error querying CoinStore for {}: {}",
                    address, e
                );
                0
            }
        }
    }

    // Updated Signature: Added action parameter
    pub fn create_proposal(
        &self,
        id: String,
        title: String,
        description: String,
        proposer: String,
        duration_seconds: u64,
        action: Option<GovernanceAction>,
    ) -> Result<String, String> {
        // PREVENT SPAM: Require 10,000 AIN to create a proposal
        let required_stake: u128 = 10_000 * 1_000_000_000_000_000_000;

        // === C-12 FIX: Query Move VM CoinStore for authoritative balance ===
        // OLD: Read from native AccountData.balance — dual-accounting vulnerability.
        // NEW: Read directly from Move VM CoinStore<AincoreCoin> resource in storage.
        // This is a READ-ONLY check. The actual fee deduction is performed atomically
        // by the Move VM governance::create_proposal entry function when the transaction
        // is processed by the executor.
        let proposer_balance = self.query_move_vm_balance(&proposer);

        if proposer_balance < required_stake {
            return Err(format!(
                "Insufficient balance to create proposal. Required: {} AIN, Available: {} AIN (Move VM CoinStore)",
                required_stake / 1_000_000_000_000_000_000,
                proposer_balance / 1_000_000_000_000_000_000
            ));
        }

        // SECURITY NOTE: Fee deduction is NOT performed here.
        // The Move VM governance::create_proposal entry function handles atomic
        // withdrawal + burn of the 10,000 AIN fee via coin::withdraw + coin::burn.
        // This Rust module only validates the pre-condition (sufficient balance).
        println!(
            "🏛️ GOVERNANCE: Proposal fee verified via Move VM CoinStore ({} AIN available)",
            proposer_balance / 1_000_000_000_000_000_000
        );

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let proposal = Proposal {
            id: id.clone(),
            title,
            description,
            proposer,
            action,
            start_time: now,
            end_time: now + duration_seconds,
            execution_time: None,
            yes_votes: 0,
            no_votes: 0,
            status: ProposalStatus::Active,
            snapshot_block_height: self.db.get_chain_height(),
        };

        self.save_proposal(&proposal)?;
        Ok(id)
    }

    pub fn vote(
        &self,
        proposal_id: &str,
        voter: String,
        approve: bool,
        _weight_arg: u64,
    ) -> Result<(), String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;

        // 1. Check Time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > proposal.end_time {
            return Err("Voting period ended".to_string());
        }
        if proposal.status != ProposalStatus::Active {
            return Err("Proposal not active".to_string());
        }

        // 2. Check for Double Voting
        let receipt_key = format!("vote_receipt:{}:{}", proposal_id, voter);
        if self
            .db
            .get(&receipt_key)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err(
                "Double voting detected: User has already voted on this proposal".to_string(),
            );
        }

        // 3. === C-12 FIX: Fetch Voting Weight from Move VM CoinStore ===
        // OLD: Read from native AccountData.balance — desynchronized from Move VM state.
        // NEW: Query Move VM CoinStore<AincoreCoin> directly for authoritative balance.
        // The Move VM governance::vote entry function also performs vote escrow (token locking)
        // to prevent double-vote via transfer attacks.
        let weight = self.query_move_vm_balance(&voter);
        if weight == 0 {
            return Err(
                "Voter has no stake in Move VM CoinStore — cannot vote with zero balance"
                    .to_string(),
            );
        }

        if approve {
            proposal.yes_votes += weight;
        } else {
            proposal.no_votes += weight;
        }

        // 4. Save Vote Receipt
        let receipt = VoteRecord {
            proposal_id: proposal_id.to_string(),
            voter: voter.clone(),
            timestamp: now,
            weight,
            block_height_at_vote: self.db.get_chain_height(),
        };
        let receipt_json = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
        self.db
            .put(&receipt_key, &receipt_json)
            .map_err(|e| e.to_string())?;

        // 5. Save Proposal
        self.save_proposal(&proposal)?;
        Ok(())
    }

    /// Wall-clock entrypoint. Kept for existing API callers / tests; delegates
    /// to the deterministic `tally_at` using the local node's `SystemTime`.
    /// MUST NOT be called from any consensus-relevant path (it is non-
    /// deterministic across nodes). The deterministic driver uses `tally_at`.
    pub fn tally(&self, proposal_id: &str) -> Result<ProposalStatus, String> {
        self.tally_at(proposal_id, Self::wall_clock_now())
    }

    /// Deterministic tally: caller supplies `now_secs` so the decision is a pure
    /// function of (persisted proposal state, now_secs). When invoked from the
    /// executor's epoch boundary with the on-chain monotonic clock, every node
    /// computes the identical transition.
    pub fn tally_at(&self, proposal_id: &str, now_secs: u64) -> Result<ProposalStatus, String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;
        let now = now_secs;

        if now >= proposal.end_time && proposal.status == ProposalStatus::Active {
            let total_votes = proposal.yes_votes + proposal.no_votes;
            let minimum_quorum: u128 = 1_000_000 * 1_000_000_000_000_000_000; // 1M AIN Quorum

            if total_votes >= minimum_quorum && proposal.yes_votes > proposal.no_votes {
                // TIMELOCK ENFORCEMENT
                // 24 Hours Delay
                const TIMELOCK_DELAY: u64 = 86400;
                proposal.status = ProposalStatus::Queued;
                proposal.execution_time = Some(now + TIMELOCK_DELAY);
                println!(
                    "🔒 Proposal {} Passed! Entring Timelock until {}",
                    proposal_id,
                    now + TIMELOCK_DELAY
                );
            } else {
                proposal.status = ProposalStatus::Rejected;
            }
            self.save_proposal(&proposal)?;
        }

        Ok(proposal.status.clone())
    }

    /// Wall-clock entrypoint. Kept for existing API callers / tests; delegates
    /// to the deterministic `execute_proposal_at`. MUST NOT run on a consensus
    /// path — use `execute_proposal_at` with the on-chain clock there.
    pub fn execute_proposal(&self, proposal_id: &str) -> Result<(), String> {
        self.execute_proposal_at(proposal_id, Self::wall_clock_now())
    }

    /// Deterministic execution: caller supplies `now_secs`. The applied action
    /// (federation key / economic params) and the resulting `Executed` status
    /// are a pure function of (persisted proposal state, now_secs), so all nodes
    /// converge identically when driven from the epoch boundary.
    pub fn execute_proposal_at(&self, proposal_id: &str, now_secs: u64) -> Result<(), String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;

        if proposal.status != ProposalStatus::Queued {
            return Err("Proposal is not in Queued state".to_string());
        }

        let now = now_secs;
        let ready_time = proposal.execution_time.unwrap_or(u64::MAX);

        if now < ready_time {
            let wait = ready_time - now;
            return Err(format!("Timelock Active! Wait {} seconds.", wait));
        }

        // EXECUTE ACTION
        if let Some(action) = &proposal.action {
            match action {
                GovernanceAction::UpdateFederationKey(new_key) => {
                    println!(
                        "🏛️ GOVERNANCE EXECUTION: Updating Federation Key to {}",
                        new_key
                    );
                    self.db
                        .set_federation_key(new_key)
                        .map_err(|e| e.to_string())?;
                }
                GovernanceAction::UpdateEconomicParams(params) => {
                    println!(
                        "🏛️ GOVERNANCE EXECUTION: Updating Economic Params {:?}",
                        params
                    );
                    self.db
                        .update_economic_config(
                            params.base_reward,
                            params.halving_interval,
                            params.burn_percentage,
                        )
                        .map_err(|e| e.to_string())?;
                }
            }
        }

        proposal.status = ProposalStatus::Executed;
        println!("🚀 Proposal {} EXECUTED (Timelock passed)", proposal_id);

        self.save_proposal(&proposal)?;
        Ok(())
    }

    fn save_proposal(&self, proposal: &Proposal) -> Result<(), String> {
        let val = serde_json::to_string(proposal).map_err(|e| e.to_string())?;
        use storage::object::{Object, ObjectID, Owner};
        let obj = Object {
            id: ObjectID::new(proposal.id.clone()),
            data: val.into_bytes(),
            owner: Owner::Shared,
            type_struct: "0x1::governance::Proposal".to_string(),
            version: 0,
        };

        self.db.put_object(&obj).map_err(|e| e.to_string())?;
        self.maintain_active_index(&proposal.id, &proposal.status)?;
        Ok(())
    }

    /// Returns true once a proposal can no longer change state and may be
    /// dropped from the active index.
    fn is_terminal(status: &ProposalStatus) -> bool {
        matches!(status, ProposalStatus::Executed | ProposalStatus::Rejected)
    }

    fn load_active_index(&self) -> Result<Vec<String>, String> {
        match self.db.get(ACTIVE_PROPOSAL_INDEX_KEY) {
            Ok(Some(raw)) => serde_json::from_str(&raw).map_err(|e| e.to_string()),
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn store_active_index(&self, ids: &[String]) -> Result<(), String> {
        let raw = serde_json::to_string(ids).map_err(|e| e.to_string())?;
        self.db
            .put(ACTIVE_PROPOSAL_INDEX_KEY, &raw)
            .map_err(|e| e.to_string())
    }

    /// Keep `gov:active_proposal_ids` in sync as a proposal is saved: add
    /// non-terminal ids (deduped, capped at MAX_ACTIVE_PROPOSALS) and remove
    /// terminal ones. Deterministic: only depends on the persisted index and
    /// the proposal status.
    fn maintain_active_index(
        &self,
        proposal_id: &str,
        status: &ProposalStatus,
    ) -> Result<(), String> {
        let mut ids = self.load_active_index()?;
        let present = ids.iter().any(|id| id == proposal_id);

        if Self::is_terminal(status) {
            if present {
                ids.retain(|id| id != proposal_id);
                self.store_active_index(&ids)?;
            }
            return Ok(());
        }

        if !present {
            // Cap enforcement: drop the oldest entry if at capacity. This bounds
            // driver work; a dropped-but-still-active proposal can still be
            // tallied/executed via the explicit API.
            if ids.len() >= MAX_ACTIVE_PROPOSALS {
                ids.remove(0);
            }
            ids.push(proposal_id.to_string());
            self.store_active_index(&ids)?;
        }
        Ok(())
    }

    /// Deterministic on-chain governance driver.
    ///
    /// Walks the bounded active-proposal index and, using the supplied
    /// `now_secs` (which MUST be a deterministic, identical-across-nodes clock —
    /// e.g. the executor's on-chain epoch clock):
    ///   * runs `tally_at` for `Active` proposals whose voting period has ended,
    ///   * runs `execute_proposal_at` for `Queued` proposals past their timelock.
    ///
    /// Idempotent: only Active/Queued proposals are acted on, so re-running with
    /// the same (or a later) `now_secs` is a no-op once a proposal is terminal.
    /// Per-proposal errors are logged and skipped — one bad proposal never
    /// stalls the rest. Terminal proposals are pruned from the index here too,
    /// in case they reached a terminal state outside `save_proposal`.
    ///
    /// `chain_height` is accepted for logging/forensic context; the transition
    /// decisions are driven purely by `now_secs` and persisted state.
    pub fn process_due_proposals(&self, now_secs: u64, chain_height: u64) {
        let ids = match self.load_active_index() {
            Ok(ids) => ids,
            Err(e) => {
                println!("⚠️ GOVERNANCE DRIVER: failed to load active index: {}", e);
                return;
            }
        };

        for id in ids {
            let proposal = match self.get_proposal(&id) {
                Some(p) => p,
                None => {
                    // Stale index entry (object missing) — drop it.
                    let _ = self.maintain_active_index(&id, &ProposalStatus::Rejected);
                    continue;
                }
            };

            match proposal.status {
                ProposalStatus::Active => {
                    if now_secs >= proposal.end_time {
                        if let Err(e) = self.tally_at(&id, now_secs) {
                            println!(
                                "⚠️ GOVERNANCE DRIVER: tally failed for {} @h{}: {}",
                                id, chain_height, e
                            );
                        }
                    }
                }
                ProposalStatus::Queued => {
                    let ready = proposal.execution_time.unwrap_or(u64::MAX);
                    if now_secs >= ready {
                        if let Err(e) = self.execute_proposal_at(&id, now_secs) {
                            println!(
                                "⚠️ GOVERNANCE DRIVER: execute failed for {} @h{}: {}",
                                id, chain_height, e
                            );
                        }
                    }
                }
                // Passed (intermediate), Rejected, Executed: nothing to do here.
                // Terminal states are pruned from the index by save_proposal /
                // maintain_active_index; prune defensively if we see one.
                ref other => {
                    if Self::is_terminal(other) {
                        let _ = self.maintain_active_index(&id, other);
                    }
                }
            }
        }
    }

    /// Test-only helper: persist a fully-formed proposal (bypassing the
    /// create_proposal stake check) so downstream crates can construct
    /// deterministic governance fixtures in their own tests.
    #[doc(hidden)]
    pub fn test_seed_proposal(&self, proposal: &Proposal) {
        self.save_proposal(proposal).expect("seed proposal");
    }

    pub fn get_proposal(&self, id: &str) -> Option<Proposal> {
        if let Some(obj) = self.db.get_object(id) {
            if obj.type_struct == "0x1::governance::Proposal" {
                serde_json::from_slice(&obj.data).ok()
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GovernanceManager, ProposalStatus};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use storage::StateDB;

    fn temp_db_path(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("aincore-governance-{name}-{unique}"))
    }

    fn put_coin_store(db: &StateDB, address: &str, amount: u128) {
        // The Move VM writes CoinStore resource keys using the canonical
        // AccountAddress Display (#35: 32 bytes / 64 hex), so the test seed must
        // use the same normalization that query_move_vm_balance applies.
        let canonical = move_core_types::account_address::AccountAddress::from_hex_literal(
            &format!("0x{}", address.trim_start_matches("0x")),
        )
        .expect("valid test address")
        .to_string();
        let key = format!(
            "resource_{}_0x1::coin::CoinStore<0x1::staking::AincoreCoin>",
            canonical
        );
        db.put(&key, &hex::encode(amount.to_le_bytes()))
            .expect("write CoinStore");
    }

    use super::{EconomicParams, GovernanceAction, Proposal};

    /// Persist a fully-formed proposal directly (bypassing create_proposal's
    /// stake check) so timelock / driver behaviour can be tested in isolation.
    fn seed_proposal(gov: &GovernanceManager, p: Proposal) {
        gov.save_proposal(&p).expect("seed proposal");
    }

    fn base_proposal(id: &str) -> Proposal {
        Proposal {
            id: id.to_string(),
            title: "t".to_string(),
            description: "d".to_string(),
            proposer: "0x11111111111111111111111111111111".to_string(),
            action: None,
            start_time: 0,
            end_time: 100,
            execution_time: None,
            yes_votes: 0,
            no_votes: 0,
            status: ProposalStatus::Active,
            snapshot_block_height: 0,
        }
    }

    #[test]
    fn create_proposal_reads_canonical_move_balance() {
        let path = temp_db_path("proposal");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        let governance = GovernanceManager::new(db.clone());
        let address = "11111111111111111111111111111111";
        let min_stake = 10_000u128 * 1_000_000_000_000_000_000;

        put_coin_store(&db, address, min_stake);

        let proposal_id = governance
            .create_proposal(
                "p1".to_string(),
                "Canonical Address".to_string(),
                "Checks CoinStore lookup".to_string(),
                format!("0x{}", address),
                60,
                None,
            )
            .expect("proposal should be created");

        let proposal = governance
            .get_proposal(&proposal_id)
            .expect("proposal saved");
        assert_eq!(proposal.status, ProposalStatus::Active);

        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn create_proposal_rejects_missing_move_balance() {
        let path = temp_db_path("empty");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        let governance = GovernanceManager::new(db);

        let err = governance
            .create_proposal(
                "p2".to_string(),
                "No Stake".to_string(),
                "Should fail without CoinStore".to_string(),
                "22222222222222222222222222222222".to_string(),
                60,
                None,
            )
            .expect_err("proposal should fail");

        assert!(err.contains("Insufficient balance"));
        let _ = std::fs::remove_dir_all(path);
    }

    // ========================================================================
    // Phase 2.6 (M-03): governance snapshot voting tests
    // ========================================================================

    /// `create_proposal` records the chain height at which the proposal
    /// was created. Forensic / future-replay use; lets a historical-
    /// state indexer re-verify per-voter weights at the snapshot.
    #[test]
    fn m03_create_proposal_records_snapshot_block_height() {
        let path = temp_db_path("m03_snapshot_height");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        // Simulate that we're at block height 42 when the proposal is created.
        db.put("latest_height", "42").unwrap();

        let governance = GovernanceManager::new(db.clone());
        let address = "11111111111111111111111111111111";
        let min_stake = 10_000u128 * 1_000_000_000_000_000_000;
        put_coin_store(&db, address, min_stake);

        let pid = governance
            .create_proposal(
                "p_snap_height".to_string(),
                "Snapshot height".to_string(),
                "Records height at create".to_string(),
                format!("0x{}", address),
                60,
                None,
            )
            .expect("proposal should be created");

        let p = governance.get_proposal(&pid).expect("proposal saved");
        assert_eq!(
            p.snapshot_block_height, 42,
            "proposal must record the chain height at creation as the snapshot"
        );
        let _ = std::fs::remove_dir_all(path);
    }

    /// `vote` locks in the voter's voting weight at the moment of the
    /// vote. The VoteRecord captures `weight` and
    /// `block_height_at_vote` for audit and future replay. Subsequent
    /// changes to the voter's CoinStore must not retroactively change
    /// the recorded weight.
    #[test]
    fn m03_vote_locks_weight_into_receipt() {
        let path = temp_db_path("m03_vote_weight_lock");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        db.put("latest_height", "100").unwrap();

        let governance = GovernanceManager::new(db.clone());
        let proposer = "22222222222222222222222222222222";
        let voter = "33333333333333333333333333333333";
        let min_stake = 10_000u128 * 1_000_000_000_000_000_000;
        put_coin_store(&db, proposer, min_stake);
        let voter_initial = 5_000u128 * 1_000_000_000_000_000_000;
        put_coin_store(&db, voter, voter_initial);

        let pid = governance
            .create_proposal(
                "p_weight_lock".to_string(),
                "Vote weight lock".to_string(),
                "M-03 anti-replay test".to_string(),
                format!("0x{}", proposer),
                3600,
                None,
            )
            .unwrap();

        // Advance height between create and vote so we can verify the
        // receipt captures the vote-time height, not the proposal's.
        db.put("latest_height", "150").unwrap();

        governance
            .vote(&pid, format!("0x{}", voter), true, 0)
            .expect("vote should succeed");

        // Pull the receipt directly from storage. Use the typed VoteRecord
        // for parsing so u128 round-trips correctly regardless of
        // serde_json number-vs-string encoding decisions.
        let receipt_key = format!("vote_receipt:{}:0x{}", pid, voter);
        let raw = db.get(&receipt_key).unwrap().expect("receipt present");
        let receipt: super::VoteRecord = serde_json::from_str(&raw).unwrap();

        assert_eq!(
            receipt.weight, voter_initial,
            "vote receipt must record the voter's stake AT VOTE TIME"
        );
        assert_eq!(
            receipt.block_height_at_vote, 150,
            "vote receipt must record the chain height at vote time, not the proposal's"
        );

        // Now mutate the voter's balance after the vote. The receipt
        // (which is what would be replayed in tally) must NOT change.
        put_coin_store(&db, voter, 1u128); // collapse balance to near-zero
        let raw2 = db.get(&receipt_key).unwrap().expect("receipt present");
        let receipt2: super::VoteRecord = serde_json::from_str(&raw2).unwrap();
        assert_eq!(
            receipt2.weight, voter_initial,
            "post-vote balance change must NOT alter the locked-in vote weight"
        );

        let _ = std::fs::remove_dir_all(path);
    }

    // ========================================================================
    // #32b: deterministic on-chain governance execution tests
    // ========================================================================

    /// A passing proposal seeded with enough yes-votes and a past end_time
    /// reaches the SAME deterministic status when tally_at is run on two
    /// independent GovernanceManager instances over the same DB.
    #[test]
    fn b32_tally_at_is_deterministic_across_instances() {
        let path = temp_db_path("b32_tally_det");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        let quorum: u128 = 1_000_000 * 1_000_000_000_000_000_000;

        let g1 = GovernanceManager::new(db.clone());
        let mut p = base_proposal("det1");
        p.yes_votes = quorum;
        p.no_votes = 0;
        p.end_time = 100;
        seed_proposal(&g1, p);

        // now == end_time → eligible. Both instances compute identical result.
        let s1 = g1.tally_at("det1", 100).expect("tally");
        let g2 = GovernanceManager::new(db.clone());
        // Re-seed a fresh proposal to compare a pure transition (g1 already
        // mutated det1 → Queued). Use a second id with identical inputs.
        let mut p2 = base_proposal("det2");
        p2.yes_votes = quorum;
        p2.end_time = 100;
        seed_proposal(&g2, p2);
        let s2 = g2.tally_at("det2", 100).expect("tally");

        assert_eq!(s1, ProposalStatus::Queued);
        assert_eq!(s1, s2, "tally_at must be a pure function of (state, now)");
        let _ = std::fs::remove_dir_all(path);
    }

    /// Timelock boundary: execute_proposal_at at T-1 is rejected, at T accepted.
    #[test]
    fn b32_timelock_boundary_reject_then_accept() {
        let path = temp_db_path("b32_timelock");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        let gov = GovernanceManager::new(db.clone());

        let mut p = base_proposal("tl1");
        p.status = ProposalStatus::Queued;
        p.execution_time = Some(1_000);
        p.action = Some(GovernanceAction::UpdateFederationKey("FEDKEY".to_string()));
        seed_proposal(&gov, p);

        // T-1: must reject (timelock active), proposal stays Queued.
        let err = gov.execute_proposal_at("tl1", 999).expect_err("must reject at T-1");
        assert!(err.contains("Timelock"), "expected timelock error, got: {err}");
        assert_eq!(
            gov.get_proposal("tl1").unwrap().status,
            ProposalStatus::Queued
        );

        // T: accepted.
        gov.execute_proposal_at("tl1", 1_000).expect("accept at T");
        assert_eq!(
            gov.get_proposal("tl1").unwrap().status,
            ProposalStatus::Executed
        );
        let _ = std::fs::remove_dir_all(path);
    }

    /// Executing an UpdateEconomicParams action writes the storage config keys.
    #[test]
    fn b32_action_application_writes_config() {
        let path = temp_db_path("b32_action");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        let gov = GovernanceManager::new(db.clone());

        let mut p = base_proposal("act1");
        p.status = ProposalStatus::Queued;
        p.execution_time = Some(500);
        p.action = Some(GovernanceAction::UpdateEconomicParams(EconomicParams {
            base_reward: Some(777),
            halving_interval: Some(888),
            burn_percentage: Some(9),
        }));
        seed_proposal(&gov, p);

        gov.execute_proposal_at("act1", 500).expect("execute");

        // update_economic_config persists these keys in storage.
        assert_eq!(db.get_base_reward(), 777);
        assert_eq!(db.get_halving_interval(), 888);
        assert_eq!(db.get_burn_percentage(), 9);
        let _ = std::fs::remove_dir_all(path);
    }

    /// Double-run of execute_proposal_at is idempotent: the second call errors
    /// (no longer Queued) and the config is not re-applied / state unchanged.
    #[test]
    fn b32_execute_is_idempotent() {
        let path = temp_db_path("b32_idem");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        let gov = GovernanceManager::new(db.clone());

        let mut p = base_proposal("idem1");
        p.status = ProposalStatus::Queued;
        p.execution_time = Some(10);
        p.action = Some(GovernanceAction::UpdateFederationKey("K1".to_string()));
        seed_proposal(&gov, p);

        gov.execute_proposal_at("idem1", 10).expect("first execute");
        assert_eq!(
            gov.get_proposal("idem1").unwrap().status,
            ProposalStatus::Executed
        );

        let err = gov
            .execute_proposal_at("idem1", 10)
            .expect_err("second execute must be a no-op error");
        assert!(err.contains("not in Queued"), "got: {err}");
        let _ = std::fs::remove_dir_all(path);
    }

    /// Driver end-to-end: walks the active index and applies BOTH Active→Queued
    /// (tally) and Queued→Executed (execute) transitions deterministically,
    /// leaves Rejected / not-yet-due proposals untouched, and is idempotent on
    /// a second run.
    #[test]
    fn b32_process_due_proposals_end_to_end() {
        let path = temp_db_path("b32_driver");
        let db = Arc::new(StateDB::open(path.to_str().expect("utf8 path")).expect("open db"));
        let gov = GovernanceManager::new(db.clone());
        let quorum: u128 = 1_000_000 * 1_000_000_000_000_000_000;

        // (a) Active, past end_time, passing → should go Queued.
        let mut pass = base_proposal("d_pass");
        pass.yes_votes = quorum;
        pass.end_time = 100;
        seed_proposal(&gov, pass);

        // (b) Active, past end_time, no quorum → should go Rejected.
        let mut fail = base_proposal("d_fail");
        fail.yes_votes = 1; // below quorum
        fail.end_time = 100;
        seed_proposal(&gov, fail);

        // (c) Queued, timelock due → should Execute (and apply action).
        let mut queued = base_proposal("d_queued");
        queued.status = ProposalStatus::Queued;
        queued.execution_time = Some(200);
        queued.action = Some(GovernanceAction::UpdateFederationKey("DRIVER".to_string()));
        seed_proposal(&gov, queued);

        // (d) Active, NOT yet ended → must stay Active.
        let mut future = base_proposal("d_future");
        future.yes_votes = quorum;
        future.end_time = 10_000;
        seed_proposal(&gov, future);

        // Run driver at now=300 (≥ end_times of a/b, ≥ exec_time of c, < d's end).
        gov.process_due_proposals(300, 42);

        assert_eq!(
            gov.get_proposal("d_pass").unwrap().status,
            ProposalStatus::Queued,
            "passing proposal moves to Queued"
        );
        assert_eq!(
            gov.get_proposal("d_fail").unwrap().status,
            ProposalStatus::Rejected,
            "no-quorum proposal moves to Rejected"
        );
        assert_eq!(
            gov.get_proposal("d_queued").unwrap().status,
            ProposalStatus::Executed,
            "due queued proposal executes"
        );
        assert_eq!(
            gov.get_proposal("d_future").unwrap().status,
            ProposalStatus::Active,
            "not-yet-due proposal stays Active"
        );
        // Action was applied.
        assert_eq!(db.get_federation_key(), "DRIVER");

        // Index pruning: terminal proposals (Rejected/Executed) removed; the
        // newly-Queued d_pass and still-Active d_future remain.
        let idx = gov.load_active_index().expect("index");
        assert!(idx.contains(&"d_pass".to_string()));
        assert!(idx.contains(&"d_future".to_string()));
        assert!(!idx.contains(&"d_fail".to_string()));
        assert!(!idx.contains(&"d_queued".to_string()));

        // Idempotent: a second run does not change terminal states. d_pass is
        // now Queued with no execution_time set ⇒ unwrap_or(MAX) ⇒ not due.
        gov.process_due_proposals(300, 43);
        assert_eq!(
            gov.get_proposal("d_fail").unwrap().status,
            ProposalStatus::Rejected
        );
        assert_eq!(
            gov.get_proposal("d_queued").unwrap().status,
            ProposalStatus::Executed
        );
        let _ = std::fs::remove_dir_all(path);
    }
}
