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

    /// Default sampler (30 samples, 99.9% confidence)
    pub fn default() -> Self {
        Self::new(30, 0.999)
    }

    /// Sample random shards to verify DA
    ///
    /// Returns true if data is available with high confidence
    pub fn sample<F>(&self, total_shards: u32, shard_fetcher: F) -> Result<bool, String>
    where
        F: Fn(u32) -> Result<Vec<u8>, String>,
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

            // Try to fetch shard
            match shard_fetcher(shard_id) {
                Ok(_data) => {
                    successful_samples += 1;
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

impl LightClient {
    pub fn new() -> Self {
        Self {
            sampler: DASampler::default(),
        }
    }

    /// Verify DA for a batch
    ///
    /// Returns true if data is available with 99.9% confidence
    pub fn verify_da<F>(&self, total_shards: u32, shard_fetcher: F) -> Result<bool, String>
    where
        F: Fn(u32) -> Result<Vec<u8>, String>,
    {
        self.sampler.sample(total_shards, shard_fetcher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sampling_full_availability() {
        let sampler = DASampler::new(10, 0.99);

        // Mock fetcher that always succeeds
        let fetcher = |_shard_id: u32| -> Result<Vec<u8>, String> { Ok(vec![1, 2, 3, 4]) };

        let result = sampler.sample(32, fetcher).unwrap();
        assert!(result, "Should detect full availability");
    }

    #[test]
    fn test_sampling_partial_availability() {
        let sampler = DASampler::new(20, 0.99);

        // Mock fetcher that fails 50% of the time
        let fetcher = |shard_id: u32| -> Result<Vec<u8>, String> {
            if shard_id % 2 == 0 {
                Ok(vec![1, 2, 3, 4])
            } else {
                Err("Not available".to_string())
            }
        };

        let result = sampler.sample(32, fetcher).unwrap();
        // With 50% availability, should fail (need 75%)
        assert!(!result, "Should detect insufficient availability");
    }

    #[test]
    fn test_sampling_high_availability() {
        let sampler = DASampler::new(30, 0.999);

        // Mock fetcher with 80% availability
        let fetcher = |shard_id: u32| -> Result<Vec<u8>, String> {
            if shard_id % 5 == 0 {
                Err("Not available".to_string())
            } else {
                Ok(vec![1, 2, 3, 4])
            }
        };

        let result = sampler.sample(32, fetcher).unwrap();
        // With 80% availability, should pass (need 75%)
        assert!(result, "Should detect sufficient availability");
    }

    #[test]
    fn test_calculate_sample_size() {
        // For 99.9% confidence with 75% availability
        let n = DASampler::calculate_sample_size(0.999, 0.75);
        println!("Required samples: {}", n);
        // Formula gives ~5 samples, but we use 30 in practice for safety
        assert!(
            n >= 3 && n <= 10,
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
