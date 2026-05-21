use crypto::hash;

/// Merkle tree for DA commitments
#[allow(dead_code)]
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
    root: [u8; 32],
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build Merkle tree from shard hashes
    pub fn new(shards: &[Vec<u8>]) -> Self {
        if shards.is_empty() {
            return Self {
                leaves: vec![],
                root: [0u8; 32],
                levels: vec![],
            };
        }

        // Hash each shard to create leaves
        let leaves: Vec<[u8; 32]> = shards
            .iter()
            .map(|shard| {
                let h = hash(shard);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h[0..32]);
                arr
            })
            .collect();

        // Build tree levels
        let mut levels = vec![leaves.clone()];
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    // Hash pair
                    Self::hash_pair(&chunk[0], &chunk[1])
                } else {
                    // Odd number, hash with itself
                    Self::hash_pair(&chunk[0], &chunk[0])
                };
                next_level.push(hash);
            }

            levels.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level[0];

        Self {
            leaves,
            root,
            levels,
        }
    }

    /// Get Merkle root
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Generate Merkle proof for a shard
    pub fn get_proof(&self, shard_index: usize) -> Result<Vec<[u8; 32]>, String> {
        if shard_index >= self.leaves.len() {
            return Err("Shard index out of bounds".to_string());
        }

        let mut proof = Vec::new();
        let mut index = shard_index;

        // Traverse up the tree
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_index = if index.is_multiple_of(2) { index + 1 } else { index - 1 };

            if sibling_index < level.len() {
                proof.push(level[sibling_index]);
            } else {
                // No sibling (odd number of nodes), use same node
                proof.push(level[index]);
            }

            index /= 2;
        }

        Ok(proof)
    }

    /// Verify Merkle proof
    pub fn verify_proof(
        shard: &[u8],
        proof: &[[u8; 32]],
        root: &[u8; 32],
        shard_index: usize,
    ) -> bool {
        // Hash the shard
        let h = hash(shard);
        let mut current_hash = [0u8; 32];
        current_hash.copy_from_slice(&h[0..32]);

        let mut index = shard_index;

        // Traverse up using proof
        for sibling in proof {
            current_hash = if index.is_multiple_of(2) {
                Self::hash_pair(&current_hash, sibling)
            } else {
                Self::hash_pair(sibling, &current_hash)
            };
            index /= 2;
        }

        &current_hash == root
    }

    /// Hash two nodes together
    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(left);
        input.extend_from_slice(right);
        let h = hash(&input);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h[0..32]);
        arr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree() {
        let shards = vec![
            b"shard0".to_vec(),
            b"shard1".to_vec(),
            b"shard2".to_vec(),
            b"shard3".to_vec(),
        ];

        let tree = MerkleTree::new(&shards);
        let root = tree.root();

        // Get proof for shard 1
        let proof = tree.get_proof(1).unwrap();

        // Verify proof
        let valid = MerkleTree::verify_proof(&shards[1], &proof, &root, 1);
        assert!(valid);

        // Invalid shard should fail
        let invalid = MerkleTree::verify_proof(b"wrong", &proof, &root, 1);
        assert!(!invalid);
    }

    #[test]
    fn test_odd_number_shards() {
        let shards = vec![b"shard0".to_vec(), b"shard1".to_vec(), b"shard2".to_vec()];

        let tree = MerkleTree::new(&shards);
        let root = tree.root();

        // Verify all shards
        for (i, shard) in shards.iter().enumerate() {
            let proof = tree.get_proof(i).unwrap();
            let valid = MerkleTree::verify_proof(shard, &proof, &root, i);
            assert!(valid, "Shard {} verification failed", i);
        }
    }
}
