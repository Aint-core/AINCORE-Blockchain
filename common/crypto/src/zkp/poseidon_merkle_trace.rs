// Multi-Step Poseidon Merkle Trace
//
// Generates 32-row trace for 8-level Merkle tree using Poseidon hash

use winterfell::math::fields::f128::BaseElement;
use winterfell::math::FieldElement;
use winterfell::{Trace, TraceTable};

use crate::poseidon::{poseidon_hash_multi_step, PoseidonConfig};

/// Multi-step Poseidon Merkle trace
pub struct PoseidonMerkleTrace {
    trace: TraceTable<BaseElement>,
}

impl PoseidonMerkleTrace {
    /// Creates new trace for Poseidon-based Merkle proof
    ///
    /// # Arguments
    /// * `leaf` - Leaf value
    /// * `path` - Merkle path (8 siblings)
    /// * `path_bits` - Path bits (8 bits)
    pub fn new(leaf: u64, path: Vec<u64>, path_bits: Vec<bool>) -> Self {
        assert_eq!(path.len(), 8, "Must have 8-level path");
        assert_eq!(path_bits.len(), 8, "Must have 8 path bits");

        let config = PoseidonConfig::new();
        let mut col0 = Vec::with_capacity(32);
        let mut col1 = Vec::with_capacity(32);
        let mut col2 = Vec::with_capacity(32);
        let mut col3 = Vec::with_capacity(32);

        let mut current = BaseElement::new(leaf as u128);

        // Generate trace for each Merkle level
        for level in 0..8 {
            let sibling = BaseElement::new(path[level] as u128);
            let bit = path_bits[level];

            // Determine hash inputs based on path bit
            let (left, right) = if bit {
                (sibling, current)
            } else {
                (current, sibling)
            };

            // Get all Poseidon intermediate states
            let states = poseidon_hash_multi_step(left, right, &config);

            // Map 7 states to 4 trace rows
            // Row 0: states[0] -> states[2]
            // Row 1: states[2] -> states[4]
            // Row 2: states[4] -> states[6]
            // Row 3: states[6] (final)

            let bit_field = if bit {
                BaseElement::ONE
            } else {
                BaseElement::ZERO
            };

            // Row 0: Initial + rounds 1-2
            col0.push(states[0][0]);
            col1.push(states[0][1]);
            col2.push(states[2][0]);
            col3.push(bit_field);

            // Row 1: Rounds 3-4
            col0.push(states[2][0]);
            col1.push(states[2][1]);
            col2.push(states[4][0]);
            col3.push(bit_field);

            // Row 2: Rounds 5-6
            col0.push(states[4][0]);
            col1.push(states[4][1]);
            col2.push(states[6][0]);
            col3.push(bit_field);

            // Row 3: Finalize
            col0.push(states[6][0]);
            col1.push(states[6][1]);
            col2.push(states[6][0]); // Output
            col3.push(bit_field);

            // Parent for next level
            current = states[6][0];
        }

        let trace = TraceTable::init(vec![col0, col1, col2, col3]);

        Self { trace }
    }

    pub fn get_root(&self) -> BaseElement {
        // Root is in column 2, last row
        self.trace.get(2, 31)
    }

    pub fn get_leaf(&self) -> BaseElement {
        self.trace.get(0, 0)
    }
}

impl Trace for PoseidonMerkleTrace {
    type BaseField = BaseElement;

    fn length(&self) -> usize {
        self.trace.length()
    }

    fn info(&self) -> &winterfell::TraceInfo {
        self.trace.info()
    }

    fn read_main_frame(
        &self,
        row_idx: usize,
        frame: &mut winterfell::EvaluationFrame<Self::BaseField>,
    ) {
        self.trace.read_main_frame(row_idx, frame)
    }

    fn main_segment(&self) -> &winterfell::matrix::ColMatrix<Self::BaseField> {
        self.trace.main_segment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_trace_creation() {
        let leaf = 42;
        let path = vec![10, 20, 30, 40, 50, 60, 70, 80];
        let path_bits = vec![false; 8];

        let trace = PoseidonMerkleTrace::new(leaf, path, path_bits);

        assert_eq!(trace.length(), 32);
        assert_eq!(trace.get_leaf(), BaseElement::new(42));
    }

    #[test]
    fn test_poseidon_trace_root() {
        let leaf = 100;
        let path = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let path_bits = vec![true, false, true, false, true, false, true, false];

        let trace = PoseidonMerkleTrace::new(leaf, path, path_bits);

        let root = trace.get_root();
        assert_ne!(root, BaseElement::ZERO, "Root should be non-zero");
    }
}
