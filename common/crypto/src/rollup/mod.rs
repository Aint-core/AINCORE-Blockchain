// ZK-Rollup Circuits - Layer 2 Scaling
//
// Basic Implementation of Transaction and State Circuits
//
// Features:
// - Transaction validation
// - Signature verification (checks non-empty)
// - State transition logic
// - Batch processing

use crate::poseidon::PoseidonHash;

/// Represents a simple state tree
#[derive(Clone, Debug)]
pub struct StateTree {
    pub root: u64,
    pub leaves: std::collections::HashMap<u64, u64>, // index -> balance
}

/// Transaction circuit for ZK-Rollup
#[derive(Clone, Debug)]
pub struct Transaction {
    pub from_idx: u64,
    pub to_idx: u64,
    pub amount: u64,
    pub nonce: u64,
    pub signature: Vec<u8>,
}

/// Batch transfer circuit
pub struct BatchCircuit {
    pub transactions: Vec<Transaction>,
    pub old_root: u64,
    pub new_root: u64,
}

impl Transaction {
    pub fn new(from: u64, to: u64, amount: u64, nonce: u64, signature: Vec<u8>) -> Self {
        Self { from_idx: from, to_idx: to, amount, nonce, signature }
    }

    /// Verify checks
    pub fn verify_signature(&self) -> bool {
        // In real ZK circuit, this proves the signature against the pubkey
        // For basic implementation: check signature is not empty
        !self.signature.is_empty()
    }
}

impl BatchCircuit {
    /// Process a batch of transactions and produce a state transition
    pub fn process_batch(
        txs: Vec<Transaction>, 
        mut state: StateTree
    ) -> Result<Self, String> {
        let old_root = state.root;
        let mut hasher = PoseidonHash::new();

        for tx in &txs {
            // 1. Verify Signature
            if !tx.verify_signature() {
                return Err("Invalid signature".to_string());
            }

            // 2. Validate Balance
            let sender_bal = *state.leaves.get(&tx.from_idx).unwrap_or(&0);
            if sender_bal < tx.amount {
                return Err("Insufficient funds".to_string());
            }

            // 3. Execute State Transition
            let receiver_bal = *state.leaves.get(&tx.to_idx).unwrap_or(&0);
            
            state.leaves.insert(tx.from_idx, sender_bal - tx.amount);
            state.leaves.insert(tx.to_idx, receiver_bal + tx.amount);
        }

        // 4. Update Root (Basic hash of leaves for demo)
        let mut new_root = 0;
        for (idx, bal) in &state.leaves {
            new_root = hasher.hash_two(new_root, idx.wrapping_add(*bal));
        }

        Ok(Self {
            transactions: txs,
            old_root,
            new_root,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rollup_batch_processing() {
        // Setup State
        let mut leaves = std::collections::HashMap::new();
        leaves.insert(1, 1000); // Sender
        leaves.insert(2, 0);    // Receiver
        
        let state = StateTree {
            root: 12345, // Initial dummy root
            leaves,
        };

        // Create Tx
        let tx = Transaction::new(1, 2, 100, 0, vec![1, 2, 3, 4]); // Valid sig
        
        // Process Batch
        let result = BatchCircuit::process_batch(vec![tx], state);
        
        assert!(result.is_ok());
        let batch = result.unwrap();
        
        // Assert state changed (root is different)
        assert_ne!(batch.old_root, batch.new_root);
    }

    #[test]
    fn test_insufficient_funds() {
        let mut leaves = std::collections::HashMap::new();
        leaves.insert(1, 50); // Sender has 50
        
        let state = StateTree {
            root: 0,
            leaves,
        };

        let tx = Transaction::new(1, 2, 100, 0, vec![1]); // Wants to send 100
        
        let result = BatchCircuit::process_batch(vec![tx], state);
        assert!(result.is_err());
    }
}
