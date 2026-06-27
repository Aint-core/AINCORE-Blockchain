use crate::merkle::MerkleTree;

use std::collections::HashSet;

/// DA Sampling for light clients
///
/// Allows light clients to verify data availability with high confidence
/// without downloading all shards
#[allow(dead_code)]
pub struct DASampler {
    sample_size: usize,
    confidence: f64,
}

impl DASampler {
    /// Create new DA sampler
    ///
    /// # Arguments
    /// * `sample_size` - Number of random samples (default: 30)
    /// * `confidence` - Statistical confidence level (default: 0.999 = 99.9%)
    pub fn new(sample_size: usize, confidence: f64) -> Self {
        Self {
            sample_size,
            confidence,
        }
    }
}

impl Default for DASampler {
    /// Default sampler (30 samples, 99.9% confidence)
    fn default() -> Self {
        Self::new(30, 0.999)
    }
}

impl DASampler {
    /// Sample random shards to verify DA.
    ///
    /// Returns true if data is available with high confidence. SEC-#3: each
    /// fetched shard is verified against the committed `merkle_root` — a shard
    /// that is retrieved but does NOT match its Merkle proof counts as
    /// UNAVAILABLE, so a peer cannot fake availability by returning garbage.
    /// The fetcher therefore returns `(shard_bytes, merkle_proof)`.
    pub fn sample<F>(
        &self,
        total_shards: u32,
        merkle_root: &[u8; 32],
        shard_fetcher: F,
    ) -> Result<bool, String>
    where
        F: Fn(u32) -> Result<(Vec<u8>, Vec<[u8; 32]>), String>,
    {
        // Input validation
        if self.sample_size > total_shards as usize {
            return Err(format!(
                "Sample size ({}) cannot exceed total shards ({})",
                self.sample_size, total_shards
            ));
        }

        let mut sampled = HashSet::new();
        let mut successful_samples = 0;

        // Generate random shard indices
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..self.sample_size {
            // Pick random shard (avoid duplicates)
            let mut shard_id = rng.gen_range(0..total_shards);
            while sampled.contains(&shard_id) {
                shard_id = rng.gen_range(0..total_shards);
            }
            sampled.insert(shard_id);

            // Fetch AND verify against the committed root. Retrieved-but-
            // unverifiable bytes do NOT count toward availability.
            match shard_fetcher(shard_id) {
                Ok((data, proof)) => {
                    if self.verify_shard(&data, shard_id as usize, &proof, merkle_root) {
                        successful_samples += 1;
                    }
                }
                Err(_) => {
                    // Shard not available
                }
            }
        }

        // Calculate availability percentage
        let availability = successful_samples as f64 / self.sample_size as f64;

        // Check if meets confidence threshold
        // With 30 samples and 99.9% confidence, need at least 75% availability
        let required_availability = 0.75;

        Ok(availability >= required_availability)
    }

    /// Verify a single shard against Merkle root
    pub fn verify_shard(
        &self,
        shard_data: &[u8],
        shard_index: usize,
        merkle_proof: &[[u8; 32]],
        merkle_root: &[u8; 32],
    ) -> bool {
        MerkleTree::verify_proof(shard_data, merkle_proof, merkle_root, shard_index)
    }

    /// Calculate required samples for desired confidence
    ///
    /// Formula: n = log(1 - confidence) / log(1 - availability)
    pub fn calculate_sample_size(confidence: f64, expected_availability: f64) -> usize {
        // Input validation
        if expected_availability <= 0.0 || expected_availability >= 1.0 {
            eprintln!(
                "⚠️  Invalid availability: {}, using 0.75",
                expected_availability
            );
            return Self::calculate_sample_size(confidence, 0.75);
        }
        if confidence <= 0.0 || confidence >= 1.0 {
            eprintln!("⚠️  Invalid confidence: {}, using 0.999", confidence);
            return Self::calculate_sample_size(0.999, expected_availability);
        }

        let numerator = (1.0 - confidence).ln();
        let denominator = (1.0 - expected_availability).ln();
        (numerator / denominator).ceil() as usize
    }

    /// Calculate confidence given sample size and availability
    pub fn calculate_confidence(sample_size: usize, availability: f64) -> f64 {
        1.0 - (1.0 - availability).powi(sample_size as i32)
    }
}

/// Light client for DA verification
pub struct LightClient {
    sampler: DASampler,
}

impl Default for LightClient {
    fn default() -> Self {
        Self::new()
    }
}

impl LightClient {
    pub fn new() -> Self {
        Self {
            sampler: DASampler::default(),
        }
    }

    /// Verify DA for a batch
    ///
    /// Returns true if data is available with 99.9% confidence. SEC-#3: shards
    /// are verified against `merkle_root`; see [`DASampler::sample`].
    pub fn verify_da<F>(
        &self,
        total_shards: u32,
        merkle_root: &[u8; 32],
        shard_fetcher: F,
    ) -> Result<bool, String>
    where
        F: Fn(u32) -> Result<(Vec<u8>, Vec<[u8; 32]>), String>,
    {
        self.sampler.sample(total_shards, merkle_root, shard_fetcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build `n` deterministic shards + their Merkle tree for sampling tests.
    fn build_shards(n: u32) -> (Vec<Vec<u8>>, MerkleTree) {
        let shards: Vec<Vec<u8>> = (0..n).map(|i| format!("shard-{i}").into_bytes()).collect();
        let tree = MerkleTree::new(&shards);
        (shards, tree)
    }

    #[test]
    fn test_sampling_full_availability() {
        let sampler = DASampler::new(10, 0.99);
        let (shards, tree) = build_shards(32);
        let root = tree.root();

        // Every shard returns correct bytes + a valid proof.
        let fetcher = |id: u32| -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
            Ok((shards[id as usize].clone(), tree.get_proof(id as usize).unwrap()))
        };

        let result = sampler.sample(32, &root, fetcher).unwrap();
        assert!(result, "Should detect full availability");
    }

    #[test]
    fn test_sampling_partial_availability() {
        let sampler = DASampler::new(20, 0.99);
        let (shards, tree) = build_shards(32);
        let root = tree.root();

        // 50% of shards are unavailable (Err).
        let fetcher = |id: u32| -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
            if id.is_multiple_of(2) {
                Ok((shards[id as usize].clone(), tree.get_proof(id as usize).unwrap()))
            } else {
                Err("Not available".to_string())
            }
        };

        let result = sampler.sample(32, &root, fetcher).unwrap();
        assert!(!result, "Should detect insufficient availability");
    }

    #[test]
    fn test_sampling_high_availability() {
        let sampler = DASampler::new(30, 0.999);
        let (shards, tree) = build_shards(32);
        let root = tree.root();

        // ~80% available.
        let fetcher = |id: u32| -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
            if id.is_multiple_of(5) {
                Err("Not available".to_string())
            } else {
                Ok((shards[id as usize].clone(), tree.get_proof(id as usize).unwrap()))
            }
        };

        let result = sampler.sample(32, &root, fetcher).unwrap();
        assert!(result, "Should detect sufficient availability");
    }

    /// SEC-#3 regression: shards that are RETRIEVED but do not verify against the
    /// committed root must NOT count toward availability. Previously sample()
    /// ignored the bytes and counted any successful fetch, so a peer could fake
    /// availability with garbage.
    #[test]
    fn sample_rejects_unverifiable_shards() {
        let sampler = DASampler::new(20, 0.99);
        let (shards, tree) = build_shards(32);
        let root = tree.root();

        // Even ids: correct bytes + valid proof. Odd ids: GARBAGE bytes but a
        // (real) proof for that index — verification must fail → ~50% verified.
        let fetcher = |id: u32| -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
            let proof = tree.get_proof(id as usize).unwrap();
            if id.is_multiple_of(2) {
                Ok((shards[id as usize].clone(), proof))
            } else {
                Ok((b"garbage-not-the-real-shard".to_vec(), proof))
            }
        };

        let result = sampler.sample(32, &root, fetcher).unwrap();
        assert!(
            !result,
            "garbage shards must not count as available (was a false-positive before #3)"
        );
    }

    #[test]
    fn test_calculate_sample_size() {
        // For 99.9% confidence with 75% availability
        let n = DASampler::calculate_sample_size(0.999, 0.75);
        println!("Required samples: {}", n);
        // Formula gives ~5 samples, but we use 30 in practice for safety
        assert!(
            (3..=10).contains(&n),
            "Sample size should match formula: got {}",
            n
        );
    }

    #[test]
    fn test_calculate_confidence() {
        // With 30 samples and 75% availability
        let confidence = DASampler::calculate_confidence(30, 0.75);
        println!("Confidence: {:.4}", confidence);
        assert!(confidence > 0.999, "Should achieve 99.9% confidence");
    }

    #[test]
    fn test_merkle_verification() {
        let sampler = DASampler::default();

        // Create test shards
        let shards = vec![
            b"shard0".to_vec(),
            b"shard1".to_vec(),
            b"shard2".to_vec(),
            b"shard3".to_vec(),
        ];

        // Build Merkle tree
        let tree = MerkleTree::new(&shards);
        let root = tree.root();

        // Get proof for shard 1
        let proof = tree.get_proof(1).unwrap();

        // Verify
        let valid = sampler.verify_shard(&shards[1], 1, &proof, &root);
        assert!(valid, "Merkle proof should verify");

        // Invalid shard should fail
        let invalid = sampler.verify_shard(b"wrong", 1, &proof, &root);
        assert!(!invalid, "Invalid shard should not verify");
    }
}
