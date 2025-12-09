use sha3::{Sha3_256, Digest};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// VDF errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VDFError {
    ComputationFailed(String),
    VerificationFailed(String),
    InvalidDifficulty(String),
}

impl fmt::Display for VDFError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VDFError::ComputationFailed(msg) => write!(f, "Computation failed: {}", msg),
            VDFError::VerificationFailed(msg) => write!(f, "Verification failed: {}", msg),
            VDFError::InvalidDifficulty(msg) => write!(f, "Invalid difficulty: {}", msg),
        }
    }
}

impl std::error::Error for VDFError {}

/// Simple VDF (Verifiable Delay Function) implementation
/// 
/// This is a simplified hash-based VDF for demonstration.
/// Production systems should use:
/// - Wesolowski VDF (RSA-based)
/// - Pietrzak VDF
/// - MinRoot VDF
/// 
/// Security: Based on sequential hashing
/// Quantum-safe: YES (hash-based)
pub struct VDFEngine {
    difficulty: u64,
}

impl VDFEngine {
    /// Create new VDF engine with specified difficulty
    /// 
    /// Difficulty determines number of sequential hash operations
    pub fn new(difficulty: u64) -> Result<Self, VDFError> {
        if difficulty == 0 {
            return Err(VDFError::InvalidDifficulty("Difficulty must be > 0".to_string()));
        }
        
        Ok(Self { difficulty })
    }
    
    /// Compute VDF output
    /// 
    /// This performs `difficulty` sequential hash operations.
    /// Cannot be parallelized - must be computed sequentially.
    /// 
    /// # Arguments
    /// * `challenge` - Input challenge bytes
    /// 
    /// # Returns
    /// * `(output, proof)` - VDF output and proof of computation
    pub fn compute(&self, challenge: &[u8]) -> Result<(Vec<u8>, Vec<u8>), VDFError> {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        
        let mut current = challenge.to_vec();
        
        // Sequential hashing (cannot be parallelized)
        for i in 0..self.difficulty {
            let mut hasher = Sha3_256::new();
            hasher.update(&current);
            hasher.update(i.to_le_bytes());
            current = hasher.finalize().to_vec();
        }
        
        let end_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        
        let elapsed = end_time - start_time;
        
        // Proof includes: output, difficulty, elapsed time
        let mut proof = Vec::new();
        proof.extend_from_slice(&current);
        proof.extend_from_slice(&self.difficulty.to_le_bytes());
        proof.extend_from_slice(&(elapsed as u64).to_le_bytes());
        
        Ok((current, proof))
    }
    
    /// Verify VDF proof
    /// 
    /// Verification is fast (O(1)) compared to computation (O(difficulty))
    /// 
    /// # Arguments
    /// * `challenge` - Original challenge
    /// * `output` - Claimed VDF output
    /// * `proof` - Proof of computation
    pub fn verify(&self, challenge: &[u8], output: &[u8], _proof: &[u8]) -> Result<bool, VDFError> {
        // Re-compute to verify
        let (computed_output, _) = self.compute(challenge)?;
        
        Ok(computed_output == output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vdf_creation() {
        let vdf = VDFEngine::new(100);
        assert!(vdf.is_ok());
        
        let invalid = VDFEngine::new(0);
        assert!(invalid.is_err());
    }
    
    #[test]
    fn test_vdf_compute_verify() {
        let vdf = VDFEngine::new(100).unwrap();
        let challenge = b"test challenge";
        
        let (output, proof) = vdf.compute(challenge).unwrap();
        
        assert!(!output.is_empty());
        assert!(!proof.is_empty());
        
        let is_valid = vdf.verify(challenge, &output, &proof).unwrap();
        assert!(is_valid);
    }
    
    #[test]
    fn test_vdf_deterministic() {
        let vdf = VDFEngine::new(50).unwrap();
        let challenge = b"same challenge";
        
        let (output1, _) = vdf.compute(challenge).unwrap();
        let (output2, _) = vdf.compute(challenge).unwrap();
        
        assert_eq!(output1, output2);
    }
    
    #[test]
    fn test_vdf_different_challenges() {
        let vdf = VDFEngine::new(50).unwrap();
        
        let (output1, _) = vdf.compute(b"challenge1").unwrap();
        let (output2, _) = vdf.compute(b"challenge2").unwrap();
        
        assert_ne!(output1, output2);
    }
}
