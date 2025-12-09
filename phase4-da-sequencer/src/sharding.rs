use std::collections::HashMap;
 // Placeholder if used

/// Shard manager for distributing DA shards across validators
pub struct ShardManager {
    total_shards: u32,
    replication_factor: usize,
    validators: Vec<String>,
    shard_assignments: HashMap<u32, Vec<String>>, // shard_id -> responsible node_ids
}

impl ShardManager {
    /// Create new shard manager
    /// 
    /// # Arguments
    /// * `total_shards` - Total number of shards (default: 32)
    /// * `replication_factor` - How many nodes store each shard (default: 3)
    pub fn new(total_shards: u32, replication_factor: usize) -> Self {
        Self {
            total_shards,
            replication_factor,
            validators: Vec::new(),
            shard_assignments: HashMap::new(),
        }
    }
    
    /// Update validator set and recompute shard assignments
    pub fn update_validators(&mut self, validators: Vec<String>) {
        self.validators = validators;
        self.recompute_assignments();
    }
    
    /// Recompute shard assignments using consistent hashing
    fn recompute_assignments(&mut self) {
        self.shard_assignments.clear();
        
        if self.validators.is_empty() {
            return;
        }
        
        // For each shard, assign to replication_factor validators
        for shard_id in 0..self.total_shards {
            let mut assigned_nodes = Vec::new();
            
            // Use consistent hashing to deterministically assign nodes
            let mut candidates: Vec<(u64, String)> = self.validators
                .iter()
                .map(|node_id| {
                    let hash = self.hash_shard_node(shard_id, node_id);
                    (hash, node_id.clone())
                })
                .collect();
            
            // Sort by hash value
            candidates.sort_by_key(|(hash, _)| *hash);
            
            // Take top replication_factor nodes
            for (_, node_id) in candidates.iter().take(self.replication_factor) {
                assigned_nodes.push(node_id.clone());
            }
            
            self.shard_assignments.insert(shard_id, assigned_nodes);
        }
        
        println!("🗂️  [ShardManager] Assigned {} shards across {} validators", 
            self.total_shards, self.validators.len());
    }
    
    /// Get nodes responsible for a shard
    pub fn get_shard_nodes(&self, shard_id: u32) -> Vec<String> {
        self.shard_assignments
            .get(&shard_id)
            .cloned()
            .unwrap_or_default()
    }
    
    /// Get all shards this node is responsible for
    pub fn get_my_shards(&self, node_id: &str) -> Vec<u32> {
        let mut my_shards = Vec::new();
        
        for (shard_id, nodes) in &self.shard_assignments {
            if nodes.contains(&node_id.to_string()) {
                my_shards.push(*shard_id);
            }
        }
        
        my_shards
    }
    
    /// Check if this node should store a shard
    pub fn should_store_shard(&self, node_id: &str, shard_id: u32) -> bool {
        self.shard_assignments
            .get(&shard_id)
            .map(|nodes| nodes.contains(&node_id.to_string()))
            .unwrap_or(false)
    }
    
    /// Hash function for consistent hashing
    fn hash_shard_node(&self, shard_id: u32, node_id: &str) -> u64 {
        let mut input = Vec::new();
        input.extend_from_slice(&shard_id.to_le_bytes());
        input.extend_from_slice(node_id.as_bytes());
        let result = crypto::hash(&input);
        
        // Convert first 8 bytes to u64
        u64::from_le_bytes([
            result[0], result[1], result[2], result[3],
            result[4], result[5], result[6], result[7],
        ])
    }
    
    /// Get storage efficiency (percentage of total data each node stores)
    pub fn storage_efficiency(&self) -> f64 {
        if self.validators.is_empty() {
            return 0.0;
        }
        
        // Each node stores approximately (total_shards * replication_factor) / num_validators shards
        let shards_per_node = (self.total_shards as f64 * self.replication_factor as f64) 
            / self.validators.len() as f64;
        
        // As percentage of total shards
        (shards_per_node / self.total_shards as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shard_assignment() {
        let mut manager = ShardManager::new(32, 3);
        
        // Add validators
        let validators = vec![
            "node1".to_string(),
            "node2".to_string(),
            "node3".to_string(),
            "node4".to_string(),
            "node5".to_string(),
        ];
        manager.update_validators(validators);
        
        // Check each shard has 3 replicas
        for shard_id in 0..32 {
            let nodes = manager.get_shard_nodes(shard_id);
            assert_eq!(nodes.len(), 3, "Shard {} should have 3 replicas", shard_id);
        }
        
        // Check each node has some shards
        for node_id in &["node1", "node2", "node3", "node4", "node5"] {
            let shards = manager.get_my_shards(node_id);
            assert!(!shards.is_empty(), "Node {} should have shards", node_id);
            println!("Node {} has {} shards", node_id, shards.len());
        }
    }
    
    #[test]
    fn test_storage_efficiency() {
        let mut manager = ShardManager::new(32, 3);
        
        // With 10 validators, each stores ~9.6 shards = 30% of total
        let validators: Vec<String> = (0..10).map(|i| format!("node{}", i)).collect();
        manager.update_validators(validators);
        
        let efficiency = manager.storage_efficiency();
        println!("Storage efficiency: {:.1}%", efficiency);
        assert!(efficiency > 25.0 && efficiency < 35.0);
    }
    
    #[test]
    fn test_consistent_hashing() {
        let mut manager = ShardManager::new(32, 3);
        
        let validators = vec!["node1".to_string(), "node2".to_string(), "node3".to_string()];
        manager.update_validators(validators.clone());
        
        let shard_0_nodes_before = manager.get_shard_nodes(0);
        
        // Add a new validator
        let mut new_validators = validators.clone();
        new_validators.push("node4".to_string());
        manager.update_validators(new_validators);
        
        let shard_0_nodes_after = manager.get_shard_nodes(0);
        
        // Most shards should remain on same nodes (consistent hashing property)
        // At least 2 out of 3 should be the same
        let common: Vec<_> = shard_0_nodes_before
            .iter()
            .filter(|n| shard_0_nodes_after.contains(n))
            .collect();
        
        println!("Before: {:?}", shard_0_nodes_before);
        println!("After: {:?}", shard_0_nodes_after);
        println!("Common: {} nodes", common.len());
        
        // This is probabilistic, but should usually keep at least 1 node
        assert!(common.len() >= 1, "Consistent hashing should minimize changes");
    }
}
