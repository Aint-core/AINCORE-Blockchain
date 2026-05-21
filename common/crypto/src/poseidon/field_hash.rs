//! Poseidon Hash - STARK-Friendly Hash Function
//!
//! Compatible with Winterfell field elements

use winterfell::math::FieldElement;

/// Poseidon constants for field-generic implementation
const ROUNDS_FULL: usize = 8;
const ROUNDS_PARTIAL: usize = 56;

/// Poseidon hash for field elements
pub struct PoseidonHashField;

impl PoseidonHashField {
    /// Hash two field elements using Poseidon
    pub fn hash_two<E: FieldElement>(left: E, right: E) -> E {
        let mut state = [left, right, E::ZERO];

        // Full rounds
        for _ in 0..ROUNDS_FULL / 2 {
            Self::full_round(&mut state);
        }

        // Partial rounds
        for _ in 0..ROUNDS_PARTIAL {
            Self::partial_round(&mut state);
        }

        // Full rounds
        for _ in 0..ROUNDS_FULL / 2 {
            Self::full_round(&mut state);
        }

        state[0]
    }

    fn full_round<E: FieldElement>(state: &mut [E; 3]) {
        // S-box (x^5)
        for slot in state.iter_mut() {
            *slot = Self::sbox(*slot);
        }

        // MDS matrix (simplified)
        let t0 = state[0] + state[1] + state[2];
        let t1 = state[0] + state[1];
        let t2 = state[1] + state[2];

        state[0] += t0;
        state[1] = t0 + t1;
        state[2] = t0 + t2;

        // Add round constants (simplified - use field element arithmetic)
        state[0] += E::ONE;
        state[1] = state[1] + E::ONE + E::ONE;
        state[2] = state[2] + E::ONE + E::ONE + E::ONE;
    }

    fn partial_round<E: FieldElement>(state: &mut [E; 3]) {
        // S-box only on first element
        state[0] = Self::sbox(state[0]);

        // MDS matrix (simplified)
        let t0 = state[0] + state[1] + state[2];
        let t1 = state[0] + state[1];

        state[0] += t0;
        state[1] = t0 + t1;
        state[2] += t0;

        // Add round constant
        state[0] += E::ONE;
    }

    fn sbox<E: FieldElement>(x: E) -> E {
        // x^5 = x * x^2 * x^2
        let x2 = x * x;
        let x4 = x2 * x2;
        x4 * x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::fields::f128::BaseElement;

    #[test]
    fn test_poseidon_field() {
        let a = BaseElement::new(123);
        let b = BaseElement::new(456);

        let result = PoseidonHashField::hash_two(a, b);

        // Should be deterministic
        let result2 = PoseidonHashField::hash_two(a, b);
        assert_eq!(result, result2);

        // Should be different for different inputs
        let c = BaseElement::new(789);
        let result3 = PoseidonHashField::hash_two(a, c);
        assert_ne!(result, result3);
    }
}
