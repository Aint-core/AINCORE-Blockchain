use serde::{Serialize, Deserialize};
use crate::merkle::MerkleTree;

/// Types of fraud proofs
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum FraudProofType {
    /// Merkle commitment doesn't match actual data
    InvalidCommitment,
    
    /// Data is not available (failed DA sampling)
    MissingData,
    
    /// Erasure coding is incorrect
    InvalidErasure,
    
    /// Shard doesn't match Merkle proof
    InvalidShard,
}

/// Fraud proof structure
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FraudProof {
    /// Epoch of the fraudulent batch
    pub epoch: u64,
    
    /// Type of fraud
    pub proof_type: FraudProofType,
    
    /// Claimed Merkle root
    pub claimed_root: [u8; 32],
    
    /// Actual data (evidence)
    pub evidence: Vec<u8>,
    
    /// Additional proof data (e.g., Merkle proof, shard index)
    pub proof_data: Vec<u8>,
    
    /// Submitter of the fraud proof
    pub submitter: String,
    
    /// Timestamp
    pub timestamp: i64,
}

impl FraudProof {
    /// Create fraud proof for invalid commitment
    pub fn invalid_commitment(
        epoch: u64,
        claimed_root: [u8; 32],
        actual_data: Vec<u8>,
        submitter: String,
    ) -> Self {
        Self {
            epoch,
            proof_type: FraudProofType::InvalidCommitment,
            claimed_root,
            evidence: actual_data,
            proof_data: Vec::new(),
            submitter,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
    
    /// Create fraud proof for invalid shard
    pub fn invalid_shard(
        epoch: u64,
        claimed_root: [u8; 32],
        shard_data: Vec<u8>,
        shard_index: u32,
        merkle_proof: Vec<[u8; 32]>,
        submitter: String,
    ) -> Self {
        // Serialize proof data
        let mut proof_data = shard_index.to_le_bytes().to_vec();
        for hash in merkle_proof {
            proof_data.extend_from_slice(&hash);
        }
        
        Self {
            epoch,
            proof_type: FraudProofType::InvalidShard,
            claimed_root,
            evidence: shard_data,
            proof_data,
            submitter,
            timestamp: chrono::Utc::now().timestamp(),
        }
    }
}

/// Fraud proof verifier
pub struct FraudProofVerifier;

impl FraudProofVerifier {
    /// Verify a fraud proof
    /// 
    /// Returns true if the fraud proof is valid (fraud actually occurred)
    pub fn verify(proof: &FraudProof) -> bool {
        match proof.proof_type {
            FraudProofType::InvalidCommitment => {
                Self::verify_invalid_commitment(proof)
            }
            FraudProofType::InvalidShard => {
                Self::verify_invalid_shard(proof)
            }
            FraudProofType::MissingData => {
                // This requires network sampling, handled separately
                true
            }
            FraudProofType::InvalidErasure => {
                // This requires erasure code verification
                true
            }
        }
    }
    
    /// Verify invalid commitment fraud proof
    fn verify_invalid_commitment(proof: &FraudProof) -> bool {
        // Recompute Merkle root from evidence
        // Evidence should be the full set of shards
        
        // For now, simplified: hash the evidence and compare
        // For now, simplified: hash the evidence and compare
        let h = crypto::hash(&proof.evidence);
        let mut computed_hash = [0u8; 32];
        computed_hash.copy_from_slice(&h[0..32]);
        
        // If computed hash != claimed root, fraud is proven
        computed_hash != proof.claimed_root
    }
    
    /// Verify invalid shard fraud proof
    fn verify_invalid_shard(proof: &FraudProof) -> bool {
        // Extract shard index from proof_data
        if proof.proof_data.len() < 4 {
            return false;
        }
        
        let shard_index = u32::from_le_bytes([
            proof.proof_data[0],
            proof.proof_data[1],
            proof.proof_data[2],
            proof.proof_data[3],
        ]) as usize;
        
        // Extract Merkle proof
        let merkle_proof_bytes = &proof.proof_data[4..];
        let mut merkle_proof = Vec::new();
        
        for chunk in merkle_proof_bytes.chunks(32) {
            if chunk.len() == 32 {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(chunk);
                merkle_proof.push(hash);
            }
        }
        
        // Verify shard against Merkle root
        let valid = MerkleTree::verify_proof(
            &proof.evidence,
            &merkle_proof,
            &proof.claimed_root,
            shard_index,
        );
        
        // If verification fails, fraud is proven
        !valid
    }
}

/// Slashing parameters
pub struct SlashingParams {
    /// Percentage of stake to slash (0-100)
    pub slash_percentage: u8,
    
    /// Percentage to reward fraud proof submitter (0-100)
    pub reward_percentage: u8,
    
    /// Percentage to burn (0-100)
    pub burn_percentage: u8,
}

impl SlashingParams {
    /// Default slashing params (50% slash, 10% reward, 40% burn)
    pub fn default() -> Self {
        Self {
            slash_percentage: 50,
            reward_percentage: 10,
            burn_percentage: 40,
        }
    }
    
    /// Validate parameters sum to slash_percentage
    pub fn validate(&self) -> bool {
        self.reward_percentage + self.burn_percentage == self.slash_percentage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fraud_proof_creation() {
        let proof = FraudProof::invalid_commitment(
            100,
            [1u8; 32],
            vec![1, 2, 3, 4],
            "validator1".to_string(),
        );
        
        assert_eq!(proof.epoch, 100);
        assert_eq!(proof.proof_type, FraudProofType::InvalidCommitment);
        assert_eq!(proof.submitter, "validator1");
    }
    
    #[test]
    fn test_invalid_commitment_verification() {
        // Create proof with mismatched data
        let proof = FraudProof::invalid_commitment(
            100,
            [1u8; 32], // Claimed root
            vec![1, 2, 3, 4], // Actual data (will hash differently)
            "validator1".to_string(),
        );
        
        let valid = FraudProofVerifier::verify(&proof);
        assert!(valid, "Should detect fraud");
    }
    
    #[test]
    fn test_slashing_params() {
        let params = SlashingParams::default();
        assert!(params.validate());
        assert_eq!(params.slash_percentage, 50);
        assert_eq!(params.reward_percentage, 10);
        assert_eq!(params.burn_percentage, 40);
    }
    
    #[test]
    fn test_invalid_shard_proof() {
        // Create test shards
        let shards = vec![
            b"shard0".to_vec(),
            b"shard1".to_vec(),
            b"shard2".to_vec(),
        ];
        
        // Build Merkle tree
        let tree = MerkleTree::new(&shards);
        let root = tree.root();
        
        // Get proof for shard 1
        let merkle_proof = tree.get_proof(1).unwrap();
        
        // Create fraud proof with WRONG shard data
        let proof = FraudProof::invalid_shard(
            100,
            root,
            b"wrong_data".to_vec(), // Wrong data!
            1,
            merkle_proof,
            "validator1".to_string(),
        );
        
        // Verify fraud proof
        let is_fraud = FraudProofVerifier::verify(&proof);
        assert!(is_fraud, "Should detect invalid shard");
    }
}
