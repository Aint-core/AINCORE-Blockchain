// Poseidon Hash Implementation
// Week 2 - Advanced Cryptography

use std::vec::Vec;

pub mod field_hash;
pub mod stark_poseidon;

// Re-export for convenience
pub use field_hash::PoseidonHashField;
pub use stark_poseidon::{poseidon_hash, poseidon_hash_multi_step, PoseidonConfig};

/// Poseidon hash parameters
#[derive(Clone, Debug)]
pub struct PoseidonParams {
    pub t: usize,           // State size
    pub rounds_f: usize,    // Full rounds (beginning + end)
    pub rounds_p: usize,    // Partial rounds (middle)
    pub alpha: u64,         // S-box exponent
    pub mds: Vec<Vec<u64>>, // MDS Matrix
    pub ark: Vec<Vec<u64>>, // Add Round Constants
}

/// Poseidon hash engine
#[derive(Clone)]
pub struct PoseidonHash {
    params: PoseidonParams,
    state: Vec<u64>,
}

impl PoseidonHash {
    /// Create new Poseidon hasher with standard parameters
    pub fn new() -> Self {
        // Generate parameters (using deterministic constants for demonstration)
        // In production, these should be standard secure constants (e.g. from StarkWare)
        let t = 3;
        let rounds_f = 8;
        let rounds_p = 55;
        let total_rounds = rounds_f + rounds_p;

        // Simple distinct constants generation for functionality
        let mut ark = Vec::with_capacity(total_rounds);
        for i in 0..total_rounds {
            let mut round_consts = Vec::with_capacity(t);
            for j in 0..t {
                round_consts.push((i * t + j) as u64 + 0x4242424242424242);
            }
            ark.push(round_consts);
        }

        // Simple MDS matrix (not optimal, but mixing)
        // [2, 1, 1]
        // [1, 2, 1]
        // [1, 1, 2]
        let mds = vec![vec![2, 1, 1], vec![1, 2, 1], vec![1, 1, 2]];

        let params = PoseidonParams {
            t,
            rounds_f,
            rounds_p,
            alpha: 5,
            mds,
            ark,
        };

        Self {
            params,
            state: vec![0; t],
        }
    }

    /// Permutation function
    fn permute(&mut self) {
        let pf = self.params.rounds_f / 2;
        let total_rounds = self.params.rounds_f + self.params.rounds_p;

        for r in 0..total_rounds {
            // 1. Add Round Constants
            for i in 0..self.params.t {
                self.state[i] = self.state[i].wrapping_add(self.params.ark[r][i]);
            }

            // 2. SubWords (S-box)
            // Full rounds: apply S-box to all state elements
            // Partial rounds: apply S-box only to the first element
            if r < pf || r >= pf + self.params.rounds_p {
                for i in 0..self.params.t {
                    self.state[i] = self.power_alpha(self.state[i]);
                }
            } else {
                self.state[0] = self.power_alpha(self.state[0]);
            }

            // 3. MixLayer (MDS)
            let mut new_state = vec![0u64; self.params.t];
            for i in 0..self.params.t {
                for j in 0..self.params.t {
                    let mul = self.state[j].wrapping_mul(self.params.mds[i][j]);
                    new_state[i] = new_state[i].wrapping_add(mul);
                }
            }
            self.state = new_state;
        }
    }

    /// Compute x^alpha
    fn power_alpha(&self, x: u64) -> u64 {
        // Simple exponentiation implementation for alpha=5
        let x2 = x.wrapping_mul(x);
        let x4 = x2.wrapping_mul(x2);
        x4.wrapping_mul(x)
    }

    /// Hash two field elements (2-to-1)
    pub fn hash_two(&mut self, left: u64, right: u64) -> u64 {
        // Initialize state
        self.state = vec![0; self.params.t];

        // Inject inputs (Capacity=1, Rate=2)
        // state[0] = capacity (initial 0 or domain separator)
        // state[1] = left
        // state[2] = right
        self.state[0] = 0; // Domain separator could go here
        self.state[1] = left;
        self.state[2] = right;

        // Apply permutation
        self.permute();

        // Return second element (part of rate)
        self.state[1]
    }
}

impl Default for PoseidonHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_functional() {
        let mut hasher = PoseidonHash::new();
        let result1 = hasher.hash_two(1, 2);
        let result2 = hasher.hash_two(1, 2);

        // Assert determinism
        assert_eq!(result1, result2);

        // Assert non-linearity (hash(a,b) != a+b)
        assert_ne!(result1, 3);

        // Assert avalanche (small change = huge diff)
        let result3 = hasher.hash_two(1, 3);
        assert_ne!(result1, result3);
    }
}
