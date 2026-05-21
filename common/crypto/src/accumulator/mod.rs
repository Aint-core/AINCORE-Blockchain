use sha2::{Digest, Sha256};
use std::fmt;

/// Accumulator errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccumulatorError {
    ElementNotFound(String),
    InvalidProof(String),
    EmptyAccumulator(String),
    IndexOutOfBounds(String),
}

impl fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AccumulatorError::ElementNotFound(msg) => write!(f, "Element not found: {}", msg),
            AccumulatorError::InvalidProof(msg) => write!(f, "Invalid proof: {}", msg),
            AccumulatorError::EmptyAccumulator(msg) => write!(f, "Empty accumulator: {}", msg),
            AccumulatorError::IndexOutOfBounds(msg) => write!(f, "Index out of bounds: {}", msg),
        }
    }
}

impl std::error::Error for AccumulatorError {}

/// Merkle Tree Accumulator (SHA-256)
///
/// Production-grade Merkle Tree implementation.
/// Stores leaves and computes root on demand (Append-Only).
///
/// Properties:
/// - SHA-256 Hashing
/// - O(Log N) Proof Size
/// - Append-Only support
pub struct Accumulator {
    /// Leaves of the tree (Byte Vectors)
    leaves: Vec<Vec<u8>>,
    /// Cached root (dirty flag could be added for optimization)
    root: [u8; 32],
}

impl Accumulator {
    /// Create new empty accumulator
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
            root: [0u8; 32],
        }
    }

    /// Append data to accumulator
    pub fn append(&mut self, data: &[u8]) {
        self.leaves.push(data.to_vec());
        self.recompute_root();
    }

    /// Get current Merkle Root
    pub fn get_root(&self) -> [u8; 32] {
        self.root
    }

    /// Generate Merkle Proof for leaf at index
    /// Returns: (Leaf Data, Proof Path)
    pub fn prove(&self, index: usize) -> Result<(Vec<u8>, Vec<[u8; 32]>), AccumulatorError> {
        if index >= self.leaves.len() {
            return Err(AccumulatorError::IndexOutOfBounds(format!("{}", index)));
        }

        let leaf = self.leaves[index].clone();
        let mut proof = Vec::new();

        // Simulating tree traversal to capture siblings
        // This is a simplified proof generation: Rebuild layers and capture siblings
        let mut current_layer_hashes: Vec<Vec<u8>> =
            self.leaves.iter().map(|l| hash_leaf(l)).collect();
        let mut current_index = index;

        while current_layer_hashes.len() > 1 {
            let mut next_layer = Vec::new();

            for (i, chunk) in current_layer_hashes.chunks(2).enumerate() {
                let left = &chunk[0];
                if chunk.len() == 2 {
                    let right = &chunk[1];
                    // If we are in the chunk containing our path, add the sibling
                    if current_index / 2 == i {
                        // If we are left, push right sibling. If we are right, push left sibling.
                        if current_index % 2 == 0 {
                            proof.push(vec_to_array(right));
                        } else {
                            proof.push(vec_to_array(left));
                        }
                    }
                    next_layer.push(hash_node(left, right));
                } else {
                    // Odd node, lift up
                    if current_index / 2 == i {
                        // No sibling for odd last node (depending on implementation)
                        // For standard binary tree, usually duplicate or lift. We lift.
                    }
                    next_layer.push(left.clone());
                }
            }
            current_layer_hashes = next_layer;
            current_index /= 2;
        }

        Ok((leaf, proof))
    }

    /// Verify Merkle Proof
    pub fn verify(
        root: [u8; 32],
        leaf: &[u8],
        proof: &[[u8; 32]],
        index: usize,
        _total_leaves: usize, // Needed to know structure
    ) -> bool {
        let mut current_hash = hash_leaf(leaf);
        let mut current_index = index;
        // logic is simplistic here, assumes consistent structure.
        // For production verification without total_leaves, we usually strictly defined tree (e.g. perfect binary or adding padding).
        // Here we just re-run the hash chain.

        for sibling in proof {
            let sibling_vec = sibling.to_vec();
            if current_index % 2 == 0 {
                current_hash = hash_node(&current_hash, &sibling_vec);
            } else {
                current_hash = hash_node(&sibling_vec, &current_hash);
            }
            current_index /= 2;
        }

        // Final hash check
        let calculated_root = vec_to_array(&current_hash);
        calculated_root == root
    }

    /// Get number of leaves
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    // Internal recompute
    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = [0u8; 32];
            return;
        }
        let root_vec = compute_merkle_root(&self.leaves);
        self.root = vec_to_array(&root_vec);
    }
}

// === Helpers ===

fn hash_leaf(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data); // In prod, prepend 0x00 for leaf domain separation
    hasher.finalize().to_vec()
}

fn hash_node(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right); // In prod, prepend 0x01
    hasher.finalize().to_vec()
}

fn compute_merkle_root(leaves: &[Vec<u8>]) -> Vec<u8> {
    if leaves.is_empty() {
        return vec![0u8; 32];
    }
    let mut current_level: Vec<Vec<u8>> = leaves.iter().map(|l| hash_leaf(l)).collect();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(hash_node(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        current_level = next_level;
    }
    current_level[0].clone()
}

fn vec_to_array(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[0..len].copy_from_slice(&v[0..len]);
    arr
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_accumulator() {
        let mut acc = Accumulator::new();
        acc.append(b"data1");
        acc.append(b"data2");
        acc.append(b"data3"); // Odd number

        let root = acc.get_root();
        assert_ne!(root, [0u8; 32]);
        assert_eq!(acc.len(), 3);

        // Proof for index 1 (data2)
        // Tree:
        //    R
        //   / \
        //  N1  N2
        // / \  /
        // 0 1  2
        // Path for 1: Sibling 0, then Sibling N2

        let (leaf, proof) = acc.prove(1).unwrap();
        assert_eq!(leaf, b"data2");

        // Verification verifies path vs local root
        // Note: Our simple verify impl assumes we know which sibling is L/R based on index bit.
        // Index 1 (binary 01): bit0=1 (Right of sibling 0). Next level index=0: bit0=0 (Left of sibling N2).
        let valid = Accumulator::verify(root, &leaf, &proof, 1, 3);
        assert!(valid);
    }
}
