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

impl GovernanceManager {
    pub fn new(db: Arc<StateDB>) -> Self {
        Self { db }
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

    pub fn tally(&self, proposal_id: &str) -> Result<ProposalStatus, String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;

        // For prototype, we tally whenever requested, checks time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

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

    pub fn execute_proposal(&self, proposal_id: &str) -> Result<(), String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;

        if proposal.status != ProposalStatus::Queued {
            return Err("Proposal is not in Queued state".to_string());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
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

        self.db.put_object(&obj).map_err(|e| e.to_string())
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
        let key = format!(
            "resource_{}_0x1::coin::CoinStore<0x1::staking::AincoreCoin>",
            address
        );
        db.put(&key, &hex::encode(amount.to_le_bytes()))
            .expect("write CoinStore");
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
}
