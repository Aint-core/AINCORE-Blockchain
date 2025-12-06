use serde::{Deserialize, Serialize};
use std::sync::Arc;
use storage::StateDB;

// === Governance Structs ===

#[derive(Debug, Serialize, Deserialize)]
struct AccountData {
    pub balance: u64,
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
pub struct Proposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub proposer: String,
    pub start_time: u64,
    pub end_time: u64,
    pub yes_votes: u64,
    pub no_votes: u64,
    pub status: ProposalStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ProposalStatus {
    Active,
    Passed,
    Rejected,
    Executed,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vote {
    pub proposal_id: String,
    pub voter: String,
    pub approve: bool,
    pub weight: u64, // Stake amount
}

pub struct GovernanceManager {
    db: Arc<StateDB>,
    // In-memory cache for active proposals (could be fully DB backed)
}

impl GovernanceManager {
    pub fn new(db: Arc<StateDB>) -> Self {
        Self { db }
    }

    pub fn create_proposal(&self, id: String, title: String, description: String, proposer: String, duration_seconds: u64) -> Result<String, String> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let proposal = Proposal {
            id: id.clone(),
            title,
            description,
            proposer,
            start_time: now,
            end_time: now + duration_seconds,
            yes_votes: 0,
            no_votes: 0,
            status: ProposalStatus::Active,
        };

        self.save_proposal(&proposal)?;
        Ok(id)
    }

    pub fn vote(&self, proposal_id: &str, voter: String, approve: bool, _weight_arg: u64) -> Result<(), String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;
        
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        if now > proposal.end_time {
             return Err("Voting period ended".to_string());
        }
        if proposal.status != ProposalStatus::Active {
             return Err("Proposal not active".to_string());
        }

        // 1. Check for Double Voting
        let receipt_key = format!("vote_receipt:{}:{}", proposal_id, voter);
        if self.db.get(&receipt_key).map_err(|e| e.to_string())?.is_some() {
            return Err("Double voting detected: User has already voted on this proposal".to_string());
        }

        // 2. Fetch User Balance for Weight
        // We need to fetch the Account Object
        let account_obj = self.db.get_object(&voter).ok_or("Voter account not found")?;
        let account_data: AccountData = serde_json::from_slice(&account_obj.data).map_err(|_| "Failed to parse account data")?;
        
        // Weight is strictly based on balance
        let weight = account_data.balance;
        
        if weight == 0 {
            return Err("Voter has no stake".to_string());
        }

        if approve {
            proposal.yes_votes += weight;
        } else {
            proposal.no_votes += weight;
        }
        
        // 3. Save Vote Receipt
        let receipt = VoteRecord {
            proposal_id: proposal_id.to_string(),
            voter: voter.clone(),
            timestamp: now,
        };
        let receipt_json = serde_json::to_string(&receipt).map_err(|e| e.to_string())?;
        self.db.put(&receipt_key, &receipt_json).map_err(|e| e.to_string())?;

        // 4. Update Proposal

        self.save_proposal(&proposal)?;
        Ok(())
    }

    pub fn tally(&self, proposal_id: &str) -> Result<ProposalStatus, String> {
        let mut proposal = self.get_proposal(proposal_id).ok_or("Proposal not found")?;
        
        // For prototype, we tally whenever requested, checks time
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        
        if now >= proposal.end_time && proposal.status == ProposalStatus::Active {
             if proposal.yes_votes > proposal.no_votes {
                 proposal.status = ProposalStatus::Passed;
             } else {
                 proposal.status = ProposalStatus::Rejected;
             }
             self.save_proposal(&proposal)?;
        }
        
        Ok(proposal.status.clone())
    }

    fn save_proposal(&self, proposal: &Proposal) -> Result<(), String> {
        let val = serde_json::to_string(proposal).map_err(|e| e.to_string())?;
        // Use generic put if available, or create specific helper
        // Since StateDB put is raw K-V...
        // We need accessibility to `db` put. 
        // Assuming StateDB has `put(key, val)`
        // NOTE: StateDB API might be `put_object` or `db.put`. 
        // Let's check StateDB API.
        // Assuming we can use raw DB access or `put_object` wrapper.
        // For now, assume a `put_raw` exists or we use internal db.
        // Actually, StateDB exposes `db` as public? No, usually encapsulated.
        // We will assume `put_object` wrapper or verify via `storage` crate.
        
        // Let's try to frame it as an Object?
        // Or assume we add `put_raw` to StateDB? Not ideal to change Storage again.
        // Let's wrap Proposal in an Object!
        
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
