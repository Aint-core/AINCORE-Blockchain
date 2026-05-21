use reed_solomon_erasure::galois_8::ReedSolomon;

/// Maximum batch size (100MB)
const MAX_BATCH_SIZE: usize = 100 * 1024 * 1024;

/// Erasure coding for data availability
/// Uses Reed-Solomon coding to create redundant shards
pub struct ErasureEncoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl ErasureEncoder {
    /// Create new encoder with specified shard counts
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards (e.g., 16)
    /// * `parity_shards` - Number of parity shards (e.g., 16)
    ///
    /// With 16+16, you can recover from losing any 16 shards
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, String> {
        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| format!("Failed to create Reed-Solomon encoder: {:?}", e))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
        })
    }

    /// Encode data into shards
    ///
    /// Returns vector of shards (data + parity)
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        // Input validation
        if data.len() > MAX_BATCH_SIZE {
            return Err(format!(
                "Batch too large: {} bytes exceeds maximum {} bytes",
                data.len(),
                MAX_BATCH_SIZE
            ));
        }

        let total_shards = self.data_shards + self.parity_shards;

        // Calculate shard size (round up)
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;

        // Create data shards
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);

        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, data.len());

            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let copy_len = end - start;
                shard[..copy_len].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }

        // Create empty parity shards
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode (generate parity)
        self.rs
            .encode(&mut shards)
            .map_err(|e| format!("Encoding failed: {:?}", e))?;

        Ok(shards)
    }

    /// Decode data from available shards
    ///
    /// # Arguments
    /// * `shards` - Vector of Option<Vec<u8>>, None for missing shards
    /// * `original_size` - Original data size before encoding
    ///
    /// Returns reconstructed data
    pub fn decode(
        &self,
        mut shards: Vec<Option<Vec<u8>>>,
        original_size: usize,
    ) -> Result<Vec<u8>, String> {
        // Verify we have enough shards
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.data_shards {
            return Err(format!(
                "Not enough shards: have {}, need {}",
                available, self.data_shards
            ));
        }

        // Reconstruct
        self.rs
            .reconstruct(&mut shards)
            .map_err(|e| format!("Reconstruction failed: {:?}", e))?;

        // Extract data from data shards
        let mut result = Vec::with_capacity(original_size);

        for i in 0..self.data_shards {
            if let Some(shard) = &shards[i] {
                result.extend_from_slice(shard);
                if result.len() >= original_size {
                    break;
                }
            }
        }

        // Trim to original size
        result.truncate(original_size);

        Ok(result)
    }

    /// Verify a single shard is valid
    pub fn verify_shard(&self, shards: &[Option<Vec<u8>>], shard_index: usize) -> bool {
        if shard_index >= shards.len() {
            return false;
        }

        // This is a simplified check - in production, use Merkle proofs
        shards[shard_index].is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let encoder = ErasureEncoder::new(10, 5).unwrap();
        let data = b"Hello, World! This is a test of erasure coding.";

        // Encode
        let shards = encoder.encode(data).unwrap();
        assert_eq!(shards.len(), 15);

        // Simulate losing 5 shards
        let mut partial_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        partial_shards[2] = None;
        partial_shards[5] = None;
        partial_shards[7] = None;
        partial_shards[11] = None;
        partial_shards[13] = None;

        // Decode
        let recovered = encoder.decode(partial_shards, data.len()).unwrap();
        assert_eq!(&recovered[..], data);
    }

    #[test]
    fn test_insufficient_shards() {
        let encoder = ErasureEncoder::new(10, 5).unwrap();
        let data = b"Test data";

        let shards = encoder.encode(data).unwrap();

        // Lose too many shards (6 out of 15, need at least 10)
        let mut partial_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for i in 0..6 {
            partial_shards[i] = None;
        }

        let result = encoder.decode(partial_shards, data.len());
        assert!(result.is_err());
    }
}
