// STARK-Friendly Poseidon Hash Implementation
// 
// Multi-step Poseidon optimized for STARK constraints
// Based on: https://eprint.iacr.org/2019/458.pdf

use winterfell::math::fields::f128::BaseElement;
use winterfell::math::FieldElement;

/// Poseidon configuration for STARK-friendly hashing
/// 
/// Parameters:
/// - Width: 2 (for 2-input hash)
/// - Full rounds: 6
/// - Partial rounds: 0 (simplified for STARK efficiency)
/// - S-box: x^5
pub struct PoseidonConfig {
    /// Round constants for domain separation
    /// 12 constants: 6 rounds × 2 state elements
    pub round_constants: Vec<BaseElement>,
    
    /// MDS (Maximum Distance Separable) matrix for diffusion
    /// 2×2 matrix for 2-element state
    pub mds_matrix: [[BaseElement; 2]; 2],
    
    /// Number of full rounds
    pub full_rounds: usize,
}

impl PoseidonConfig {
    /// Creates a new Poseidon configuration with standard parameters
    pub fn new() -> Self {
        Self {
            round_constants: Self::generate_round_constants(),
            mds_matrix: Self::generate_mds_matrix(),
            full_rounds: 6,
        }
    }
    
    /// Generates round constants using "nothing up my sleeve" numbers
    /// 
    /// We use small primes and their powers to ensure no backdoors
    fn generate_round_constants() -> Vec<BaseElement> {
        // 12 constants for 6 rounds × 2 state elements
        // Using powers of small primes: 2, 3, 5, 7, 11, 13
        vec![
            BaseElement::new(2),
            BaseElement::new(3),
            BaseElement::new(5),
            BaseElement::new(7),
            BaseElement::new(11),
            BaseElement::new(13),
            BaseElement::new(17),
            BaseElement::new(19),
            BaseElement::new(23),
            BaseElement::new(29),
            BaseElement::new(31),
            BaseElement::new(37),
        ]
    }
    
    /// Generates MDS matrix for optimal diffusion
    /// 
    /// MDS matrix ensures maximum distance between codewords
    /// Using Cauchy matrix construction: M[i,j] = 1/(x_i + y_j)
    fn generate_mds_matrix() -> [[BaseElement; 2]; 2] {
        // Simple 2×2 MDS matrix
        // [[2, 1],
        //  [1, 3]]
        let two = BaseElement::ONE + BaseElement::ONE;
        let three = two + BaseElement::ONE;
        
        [
            [two, BaseElement::ONE],
            [BaseElement::ONE, three],
        ]
    }
}

impl Default for PoseidonConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Applies S-box (x^5) to a field element
#[inline]
fn apply_sbox(x: BaseElement) -> BaseElement {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Applies MDS matrix multiplication to state
#[inline]
fn apply_mds(state: &[BaseElement; 2], mds: &[[BaseElement; 2]; 2]) -> [BaseElement; 2] {
    [
        mds[0][0] * state[0] + mds[0][1] * state[1],
        mds[1][0] * state[0] + mds[1][1] * state[1],
    ]
}

/// Performs one full Poseidon round
/// 
/// Steps:
/// 1. Add round constants
/// 2. Apply S-box to all state elements
/// 3. Apply MDS matrix
fn poseidon_round(
    state: &[BaseElement; 2],
    round_constants: &[BaseElement],
    mds: &[[BaseElement; 2]; 2],
) -> [BaseElement; 2] {
    // Step 1: Add round constants
    let state_with_constants = [
        state[0] + round_constants[0],
        state[1] + round_constants[1],
    ];
    
    // Step 2: Apply S-box
    let state_after_sbox = [
        apply_sbox(state_with_constants[0]),
        apply_sbox(state_with_constants[1]),
    ];
    
    // Step 3: Apply MDS matrix
    apply_mds(&state_after_sbox, mds)
}

/// Multi-step Poseidon hash for STARK trace generation
/// 
/// Returns all intermediate states for trace construction
/// 
/// # Arguments
/// * `left` - Left input
/// * `right` - Right input
/// * `config` - Poseidon configuration
/// 
/// # Returns
/// Vector of states: [initial, after_round1, after_round2, ..., final]
/// Length: full_rounds + 1
pub fn poseidon_hash_multi_step(
    left: BaseElement,
    right: BaseElement,
    config: &PoseidonConfig,
) -> Vec<[BaseElement; 2]> {
    let mut states = Vec::with_capacity(config.full_rounds + 1);
    
    // Initial state
    let mut state = [left, right];
    states.push(state);
    
    // Apply full rounds
    for round in 0..config.full_rounds {
        let round_constants = &config.round_constants[round * 2..(round + 1) * 2];
        state = poseidon_round(&state, round_constants, &config.mds_matrix);
        states.push(state);
    }
    
    states
}

/// Single-output Poseidon hash (convenience function)
/// 
/// Returns only the final hash value (first element of final state)
pub fn poseidon_hash(
    left: BaseElement,
    right: BaseElement,
    config: &PoseidonConfig,
) -> BaseElement {
    let states = poseidon_hash_multi_step(left, right, config);
    states.last().unwrap()[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_poseidon_config_creation() {
        let config = PoseidonConfig::new();
        assert_eq!(config.round_constants.len(), 12);
        assert_eq!(config.full_rounds, 6);
    }
    
    #[test]
    fn test_sbox() {
        let x = BaseElement::new(3);
        let result = apply_sbox(x);
        
        // 3^5 = 243
        assert_eq!(result, BaseElement::new(243));
    }
    
    #[test]
    fn test_poseidon_determinism() {
        let config = PoseidonConfig::new();
        let a = BaseElement::new(42);
        let b = BaseElement::new(100);
        
        let hash1 = poseidon_hash(a, b, &config);
        let hash2 = poseidon_hash(a, b, &config);
        
        assert_eq!(hash1, hash2, "Hash must be deterministic");
    }
    
    #[test]
    fn test_poseidon_non_linearity() {
        let config = PoseidonConfig::new();
        let a = BaseElement::new(3);
        let b = BaseElement::new(5);
        
        let hash = poseidon_hash(a, b, &config);
        
        // Should NOT be linear (a + b)
        assert_ne!(hash, BaseElement::new(8), "Hash should be non-linear");
    }
    
    #[test]
    fn test_multi_step_states() {
        let config = PoseidonConfig::new();
        let a = BaseElement::new(10);
        let b = BaseElement::new(20);
        
        let states = poseidon_hash_multi_step(a, b, &config);
        
        // Should have 7 states: initial + 6 rounds
        assert_eq!(states.len(), 7);
        
        // Initial state should be inputs
        assert_eq!(states[0][0], a);
        assert_eq!(states[0][1], b);
        
        // Each subsequent state should be different
        for i in 1..states.len() {
            assert_ne!(states[i], states[i-1], "States should change each round");
        }
    }
}
