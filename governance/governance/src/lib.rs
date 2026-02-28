use serde::{Deserialize, Serialize};
use std::sync::Arc;
use storage::StateDB;

// === Governance Structs ===

#[derive(Debug, Serialize, Deserialize)]
struct AccountData {
    pub balance: u128, // L3 FIX: Match staking module's u128 coin representation
    pub sequence_number: u64,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VoteRecord {
    pub proposal_id: String,
    pub voter: String,
    pub timestamp: u64,
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
    pub yes_votes: u128, // L3 FIX: Match u128 balance type
    pub no_votes: u128,
    pub status: ProposalStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ProposalStatus {
    Active,
    Passed,   // Vote Succeeded, but waiting for TimeLock
    Queued,   // (Optional intermediate state)
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
    
    // Updated Signature: Added action parameter
    pub fn create_proposal(&self, id: String, title: String, description: String, proposer: String, duration_seconds: u64, action: Option<GovernanceAction>) -> Result<String, String> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
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
        };

        self.save_proposal(&proposal)?;
        Ok(id)
    }

    pub fn vote(&self, proposal_id: &str, voter: String, approve: bool, _weight_arg: u64) -> Result<(), String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;
        
        // 1. Check Time
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        if now > proposal.end_time {
             return Err("Voting period ended".to_string());
        }
        if proposal.status != ProposalStatus::Active {
             return Err("Proposal not active".to_string());
        }

        // 2. Check for Double Voting
        let receipt_key = format!("vote_receipt:{}:{}", proposal_id, voter);
        if self.db.get(&receipt_key).map_err(|e| e.to_string())?.is_some() {
            return Err("Double voting detected: User has already voted on this proposal".to_string());
        }

        // 3. Fetch User Balance for Weight
        let account_obj = self.db.get_object(&voter).ok_or("Voter account not found")?;
        
        let account_data: AccountData = serde_json::from_slice(&account_obj.data).map_err(|_| "Failed to parse account data")?;
        
        let weight = account_data.balance;
        if weight == 0 { return Err("Voter has no stake".to_string()); }

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
        };
        let receipt_json = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
        self.db.put(&receipt_key, &receipt_json).map_err(|e| e.to_string())?;

        // 5. Save Proposal
        self.save_proposal(&proposal)?;
        Ok(())
    }

    pub fn tally(&self, proposal_id: &str) -> Result<ProposalStatus, String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;
        
        // For prototype, we tally whenever requested, checks time
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        
        if now >= proposal.end_time && proposal.status == ProposalStatus::Active {
             if proposal.yes_votes > proposal.no_votes {
                 // TIMELOCK ENFORCEMENT
                 // 24 Hours Delay
                 const TIMELOCK_DELAY: u64 = 86400; 
                 proposal.status = ProposalStatus::Queued;
                 proposal.execution_time = Some(now + TIMELOCK_DELAY);
                 println!("🔒 Proposal {} Passed! Entring Timelock until {}", proposal_id, now + TIMELOCK_DELAY);
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

        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let ready_time = proposal.execution_time.unwrap_or(u64::MAX);

        if now < ready_time {
             let wait = ready_time - now;
             return Err(format!("Timelock Active! Wait {} seconds.", wait));
        }

        // EXECUTE ACTION
        if let Some(action) = &proposal.action {
            match action {
                GovernanceAction::UpdateFederationKey(new_key) => {
                    println!("🏛️ GOVERNANCE EXECUTION: Updating Federation Key to {}", new_key);
                    self.db.set_federation_key(new_key).map_err(|e| e.to_string())?;
                },
                GovernanceAction::UpdateEconomicParams(params) => {
                    println!("🏛️ GOVERNANCE EXECUTION: Updating Economic Params {:?}", params);
                    self.db.update_economic_config(params.base_reward, params.halving_interval, params.burn_percentage).map_err(|e| e.to_string())?;
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
