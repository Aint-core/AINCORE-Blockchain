use sha2::{Sha256, Digest};

/// A simple Merkle Accumulator (Append-only Merkle Tree)
/// For prototype, we keep the full list of leaves to recalculate root easily.
/// In production, this should be an MMR (Merkle Mountain Range).
#[derive(Debug, Clone)]
pub struct Accumulator {
    leaves: Vec<Vec<u8>>,
}

impl Accumulator {
    pub fn new() -> Self {
        Self {
            leaves: Vec::new(),
        }
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Accumulator {
    pub fn append(&mut self, hash: Vec<u8>) {
        self.leaves.push(hash);
    }

    pub fn get_root(&self) -> Vec<u8> {
        if self.leaves.is_empty() {
            return vec![0u8; 32];
        }
        self.compute_root(&self.leaves)
    }

    fn compute_root(&self, leaves: &[Vec<u8>]) -> Vec<u8> {
        if leaves.len() == 1 {
            return leaves[0].clone();
        }

        let mut next_level = Vec::new();
        for chunk in leaves.chunks(2) {
            if chunk.len() == 2 {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                next_level.push(hasher.finalize().to_vec());
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        self.compute_root(&next_level)
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }
}
