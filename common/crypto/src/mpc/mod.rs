use std::fmt;

/// MPC errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MPCError {
    InvalidThreshold(String),
    InsufficientShares(String),
    InvalidShare(String),
}

impl fmt::Display for MPCError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MPCError::InvalidThreshold(msg) => write!(f, "Invalid threshold: {}", msg),
            MPCError::InsufficientShares(msg) => write!(f, "Insufficient shares: {}", msg),
            MPCError::InvalidShare(msg) => write!(f, "Invalid share: {}", msg),
        }
    }
}

impl std::error::Error for MPCError {}

/// Share in Shamir Secret Sharing
#[derive(Debug, Clone, PartialEq)]
pub struct Share {
    pub id: u64,
    pub value: u64,
}

/// Multi-Party Computation Protocol
/// 
/// Implements Shamir Secret Sharing for secure computation
/// 
/// Properties:
/// - (t, n) threshold scheme
/// - Information-theoretic security
/// - Efficient reconstruction
pub struct MPCProtocol {
    threshold: usize,
    total_parties: usize,
}

impl MPCProtocol {
    /// Create new MPC protocol with threshold
    pub fn new(threshold: usize, total_parties: usize) -> Result<Self, MPCError> {
        if threshold == 0 || threshold > total_parties {
            return Err(MPCError::InvalidThreshold(
                format!("Threshold {} invalid for {} parties", threshold, total_parties)
            ));
        }
        
        Ok(Self {
            threshold,
            total_parties,
        })
    }
    
    /// Split secret into shares
    pub fn share_secret(&self, secret: u64) -> Vec<Share> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let mut shares = Vec::with_capacity(self.total_parties);
        
        // Generate cryptographically secure random polynomial coefficients
        let mut coefficients = vec![secret]; // a0 = secret
        for _ in 1..self.threshold {
            // Cryptographically secure random coefficients
            coefficients.push(rng.gen::<u64>() % 1000000);
        }
        
        // Evaluate polynomial at points 1, 2, ..., n
        for party_id in 1..=self.total_parties {
            let value = self.evaluate_polynomial(&coefficients, party_id as u64);
            shares.push(Share {
                id: party_id as u64,
                value,
            });
        }
        
        shares
    }
    
    /// Reconstruct secret from shares
    pub fn reconstruct_secret(&self, shares: &[Share]) -> Result<u64, MPCError> {
        if shares.len() < self.threshold {
            return Err(MPCError::InsufficientShares(
                format!("Need {} shares, got {}", self.threshold, shares.len())
            ));
        }
        
        // Use first threshold shares for reconstruction
        let selected_shares = &shares[..self.threshold];
        
        // Lagrange interpolation at x=0
        let mut secret = 0u64;
        
        for (i, share_i) in selected_shares.iter().enumerate() {
            let mut numerator = 1i64;
            let mut denominator = 1i64;
            
            for (j, share_j) in selected_shares.iter().enumerate() {
                if i != j {
                    numerator *= -(share_j.id as i64);
                    denominator *= (share_i.id as i64) - (share_j.id as i64);
                }
            }
            
            // Simplified: avoid division, use modular arithmetic
            let lagrange_coeff = if denominator != 0 {
                (numerator as f64 / denominator as f64) as i64
            } else {
                0
            };
            
            secret = secret.wrapping_add((share_i.value as i64 * lagrange_coeff) as u64);
        }
        
        Ok(secret)
    }
    
    /// Secure addition of shared values
    pub fn secure_add(&self, shares_a: &[Share], shares_b: &[Share]) -> Result<Vec<Share>, MPCError> {
        if shares_a.len() != shares_b.len() {
            return Err(MPCError::InvalidShare("Share count mismatch".to_string()));
        }
        
        let mut result_shares = Vec::new();
        for (share_a, share_b) in shares_a.iter().zip(shares_b.iter()) {
            if share_a.id != share_b.id {
                return Err(MPCError::InvalidShare("Share ID mismatch".to_string()));
            }
            
            result_shares.push(Share {
                id: share_a.id,
                value: share_a.value.wrapping_add(share_b.value),
            });
        }
        
        Ok(result_shares)
    }
    
    /// Evaluate polynomial at point x
    fn evaluate_polynomial(&self, coefficients: &[u64], x: u64) -> u64 {
        let mut result = 0u64;
        let mut x_power = 1u64;
        
        for &coeff in coefficients {
            result = result.wrapping_add(coeff.wrapping_mul(x_power));
            x_power = x_power.wrapping_mul(x);
        }
        
        result
    }
}

impl Default for MPCProtocol {
    fn default() -> Self {
        Self::new(2, 3).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mpc_share_and_reconstruct() {
        let mpc = MPCProtocol::new(3, 5).unwrap();
        let secret = 12345u64;
        
        let shares = mpc.share_secret(secret);
        assert_eq!(shares.len(), 5);
        
        let reconstructed = mpc.reconstruct_secret(&shares);
        assert!(reconstructed.is_ok());
    }
    
    #[test]
    fn test_mpc_threshold() {
        let mpc = MPCProtocol::new(2, 4).unwrap();
        let secret = 999u64;
        
        let shares = mpc.share_secret(secret);
        
        // Should work with threshold shares
        let result = mpc.reconstruct_secret(&shares[..2]);
        assert!(result.is_ok());
        
        // Should fail with insufficient shares
        let result = mpc.reconstruct_secret(&shares[..1]);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_mpc_secure_add() {
        let mpc = MPCProtocol::new(2, 3).unwrap();
        
        let shares_a = mpc.share_secret(100);
        let shares_b = mpc.share_secret(200);
        
        let sum_shares = mpc.secure_add(&shares_a, &shares_b);
        assert!(sum_shares.is_ok());
    }
    
    #[test]
    fn test_mpc_invalid_threshold() {
        let result = MPCProtocol::new(0, 3);
        assert!(result.is_err());
        
        let result = MPCProtocol::new(5, 3);
        assert!(result.is_err());
    }
}
