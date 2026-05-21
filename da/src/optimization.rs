use chrono::{Duration, Utc};
use std::collections::HashMap;

/// DA pruning configuration
pub struct PruningConfig {
    /// How long to keep DA data (in days)
    pub retention_days: i64,

    /// Whether to enable pruning
    pub enabled: bool,

    /// Archive path for old data (optional)
    pub archive_path: Option<String>,
}

impl PruningConfig {
    /// Default: 30 days retention, enabled
    pub fn default() -> Self {
        Self {
            retention_days: 30,
            enabled: true,
            archive_path: None,
        }
    }

    /// Calculate cutoff epoch based on retention period
    pub fn cutoff_timestamp(&self) -> i64 {
        let now = Utc::now();
        let cutoff = now - Duration::days(self.retention_days);
        cutoff.timestamp()
    }
}

/// DA pruner for managing storage
pub struct DAPruner {
    config: PruningConfig,
}

impl DAPruner {
    pub fn new(config: PruningConfig) -> Self {
        Self { config }
    }

    /// Check if an epoch should be pruned
    pub fn should_prune(&self, epoch_timestamp: i64) -> bool {
        if !self.config.enabled {
            return false;
        }

        epoch_timestamp < self.config.cutoff_timestamp()
    }

    /// Get list of epochs to prune
    pub fn get_prunable_epochs(&self, epochs: &HashMap<u64, i64>) -> Vec<u64> {
        let cutoff = self.config.cutoff_timestamp();

        epochs
            .iter()
            .filter(|(_, &timestamp)| timestamp < cutoff)
            .map(|(&epoch, _)| epoch)
            .collect()
    }
}

/// Performance metrics for DA operations
#[derive(Debug, Clone)]
pub struct DAMetrics {
    /// Total batches processed
    pub total_batches: u64,

    /// Total data compressed (bytes)
    pub total_compressed: u64,

    /// Total data original (bytes)
    pub total_original: u64,

    /// Average compression ratio
    pub avg_compression_ratio: f64,

    /// Total shards created
    pub total_shards: u64,

    /// Total shards stored locally
    pub total_shards_stored: u64,

    /// Storage efficiency (%)
    pub storage_efficiency: f64,
}

impl DAMetrics {
    pub fn new() -> Self {
        Self {
            total_batches: 0,
            total_compressed: 0,
            total_original: 0,
            avg_compression_ratio: 1.0,
            total_shards: 0,
            total_shards_stored: 0,
            storage_efficiency: 100.0,
        }
    }

    /// Update metrics with new batch
    pub fn record_batch(
        &mut self,
        original_size: u64,
        compressed_size: u64,
        shards_created: u64,
        shards_stored: u64,
    ) {
        self.total_batches += 1;
        self.total_original += original_size;
        self.total_compressed += compressed_size;
        self.total_shards += shards_created;
        self.total_shards_stored += shards_stored;

        // Recalculate averages
        if self.total_original > 0 {
            self.avg_compression_ratio = self.total_original as f64 / self.total_compressed as f64;
        }

        if self.total_shards > 0 {
            self.storage_efficiency =
                (self.total_shards_stored as f64 / self.total_shards as f64) * 100.0;
        }
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        format!(
            "DA Metrics: {} batches | Compression: {:.2}x | Storage: {:.1}% | Shards: {}/{}",
            self.total_batches,
            self.avg_compression_ratio,
            self.storage_efficiency,
            self.total_shards_stored,
            self.total_shards
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pruning_config() {
        let config = PruningConfig::default();
        assert_eq!(config.retention_days, 30);
        assert!(config.enabled);

        let cutoff = config.cutoff_timestamp();
        let now = Utc::now().timestamp();
        assert!(cutoff < now);
    }

    #[test]
    fn test_should_prune() {
        let config = PruningConfig {
            retention_days: 30,
            enabled: true,
            archive_path: None,
        };

        let pruner = DAPruner::new(config);

        // Old timestamp (60 days ago)
        let old_ts = Utc::now().timestamp() - (60 * 24 * 3600);
        assert!(pruner.should_prune(old_ts));

        // Recent timestamp (1 day ago)
        let recent_ts = Utc::now().timestamp() - (1 * 24 * 3600);
        assert!(!pruner.should_prune(recent_ts));
    }

    #[test]
    fn test_metrics() {
        let mut metrics = DAMetrics::new();

        // Record batch: 1000 bytes -> 250 bytes (4x compression)
        // 32 shards created, 10 stored locally
        metrics.record_batch(1000, 250, 32, 10);

        assert_eq!(metrics.total_batches, 1);
        assert_eq!(metrics.avg_compression_ratio, 4.0);
        assert_eq!(metrics.storage_efficiency, 31.25); // 10/32 = 31.25%

        println!("{}", metrics.summary());
    }
}
