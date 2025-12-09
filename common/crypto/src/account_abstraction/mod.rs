// Account Abstraction - Paymaster Implementation
//
// Implements ERC-4337 style UserOperations and Paymaster logic
//
// Features:
// - UserOperation struct
// - Paymaster validation
// - Gas sponsorship logic
// - Signature aggregation (future enhancement)

use crate::poseidon::PoseidonHash;

#[derive(Clone, Debug)]
pub struct UserOperation {
    pub sender: u64,
    pub nonce: u64,
    pub init_code: Vec<u8>,
    pub call_data: Vec<u8>,
    pub call_gas_limit: u64,
    pub verification_gas_limit: u64,
    pub pre_verification_gas: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub paymaster_and_data: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct Paymaster {
    pub balance: u64,
    pub verification_key: Vec<u8>,
}

impl UserOperation {
    pub fn new(sender: u64, nonce: u64, call_data: Vec<u8>) -> Self {
        Self {
            sender,
            nonce,
            init_code: vec![],
            call_data,
            call_gas_limit: 100000,
            verification_gas_limit: 50000,
            pre_verification_gas: 21000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 1,
            paymaster_and_data: vec![],
            signature: vec![],
        }
    }
    
    pub fn hash(&self) -> u64 {
        // Simple hash of fields for signing
        let mut hasher = PoseidonHash::new();
        hasher.hash_two(self.sender, self.nonce)
    }
}

impl Paymaster {
    pub fn new(initial_balance: u64) -> Self {
        Self {
            balance: initial_balance,
            verification_key: vec![], // In real impl, this validates paymaster data
        }
    }

    pub fn validate_paymaster_user_op(&self, user_op: &UserOperation) -> bool {
        // 1. Check if paymaster is specified
        if user_op.paymaster_and_data.is_empty() {
            return false;
        }

        // 2. Check sufficient capability/balance (simplified)
        let required_gas = user_op.call_gas_limit + user_op.verification_gas_limit;
        let required_fund = required_gas * user_op.max_fee_per_gas;
        
        self.balance >= required_fund
    }

    pub fn execute_sponsorship(&mut self, user_op: &UserOperation) -> Result<u64, String> {
        if !self.validate_paymaster_user_op(user_op) {
            return Err("Paymaster validation failed".to_string());
        }

        let required_gas = user_op.call_gas_limit + user_op.verification_gas_limit;
        let cost = required_gas * user_op.max_fee_per_gas;
        
        self.balance -= cost;
        Ok(cost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_paymaster_flow() {
        let mut paymaster = Paymaster::new(1_000_000);
        let mut user_op = UserOperation::new(1, 0, vec![1, 2, 3]);
        
        // Set realistic gas limits that paymaster can afford
        user_op.call_gas_limit = 50000;
        user_op.verification_gas_limit = 30000;
        user_op.max_fee_per_gas = 10;
        
        // Add paymaster data to indicate paymaster should sponsor
        user_op.paymaster_and_data = vec![1]; // Mark as present
        
        // Execute sponsorship
        let result = paymaster.execute_sponsorship(&user_op);
        assert!(result.is_ok());
        
        // Verify balance decreased
        assert!(paymaster.balance < 1_000_000);
        
        // Verify exact cost calculation
        let expected_cost = (50000 + 30000) * 10; // 800,000
        assert_eq!(paymaster.balance, 1_000_000 - expected_cost);
    }
}
