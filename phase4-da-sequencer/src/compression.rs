
/// Compression utilities for data availability
/// Uses Zstandard for optimal compression ratio
pub struct Compressor {
    level: i32,
}

impl Compressor {
    /// Create new compressor with specified level
    /// 
    /// # Arguments
    /// * `level` - Compression level (1-22, default 3)
    ///   - 1: Fastest, lower ratio
    ///   - 3: Balanced (recommended)
    ///   - 22: Slowest, highest ratio
    pub fn new(level: i32) -> Self {
        Self {
            level: level.clamp(1, 22),
        }
    }
    
    /// Default compressor (level 3)
    pub fn default() -> Self {
        Self::new(3)
    }
    
    /// Compress data
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        zstd::encode_all(data, self.level)
            .map_err(|e| format!("Compression failed: {}", e))
    }
    
    /// Decompress data
    pub fn decompress(&self, compressed: &[u8]) -> Result<Vec<u8>, String> {
        zstd::decode_all(compressed)
            .map_err(|e| format!("Decompression failed: {}", e))
    }
    
    /// Get compression ratio
    pub fn ratio(&self, original_size: usize, compressed_size: usize) -> f64 {
        if compressed_size == 0 {
            return 0.0;
        }
        original_size as f64 / compressed_size as f64
    }
}

/// Content-addressed deduplication
pub struct Deduplicator {
    // In production, this would be a persistent store
    // For now, we'll use the DA batch hash as content address
}

impl Deduplicator {
    pub fn new() -> Self {
        Self {}
    }
    
    /// Get content address (SHA-256 hash)
    pub fn content_address(data: &[u8]) -> [u8; 32] {
        let h = crypto::hash(data);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&h[0..32]);
        arr
    }
    
    /// Check if content exists (simplified - in production, check storage)
    pub fn exists(&self, _address: &[u8; 32]) -> bool {
        // TODO: Check RocksDB for this content address
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compression() {
        let compressor = Compressor::default();
        let data = b"Hello, World! ".repeat(100); // Repetitive data compresses well
        
        let compressed = compressor.compress(&data).unwrap();
        println!("Original: {} bytes, Compressed: {} bytes", data.len(), compressed.len());
        println!("Ratio: {:.2}x", compressor.ratio(data.len(), compressed.len()));
        
        assert!(compressed.len() < data.len());
        
        let decompressed = compressor.decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..], &data[..]);
    }
    
    #[test]
    fn test_content_address() {
        let data1 = b"Hello, World!";
        let data2 = b"Hello, World!";
        let data3 = b"Different data";
        
        let addr1 = Deduplicator::content_address(data1);
        let addr2 = Deduplicator::content_address(data2);
        let addr3 = Deduplicator::content_address(data3);
        
        assert_eq!(addr1, addr2); // Same data = same address
        assert_ne!(addr1, addr3); // Different data = different address
    }
}
