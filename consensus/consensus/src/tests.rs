#[cfg(test)]
mod tests {
    // use super::*; // Unused
    use crate::dag::DagConsensus;
    use std::sync::{Arc, Mutex};
    use storage::StateDB;
    use mempool::Mempool;
    use executor::Executor;
    use std::collections::HashMap;

    // Helper to get a unique DB path for each test
    fn get_test_db_path(suffix: &str) -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("aincore_dag_test_db_{}_{}", std::process::id(), suffix));
        let _ = std::fs::remove_dir_all(&path); // Clean start
        path.to_string_lossy().to_string()
    }

    fn setup_dag(suffix: &str) -> (DagConsensus, String) {
        let path = get_test_db_path(suffix);
        let db = Arc::new(StateDB::open(&path).unwrap());
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let executor = Arc::new(Executor::new(Arc::clone(&db)));
        let peers = Arc::new(Mutex::new(HashMap::new()));
        
        // Generate a deterministic Ed25519 key for testing
        let node_key = [42u8; 32]; // Deterministic seed
        let signing_key = crypto::SigningKey::from_bytes(&node_key);
        let node_id = hex::encode(&signing_key.verifying_key().to_bytes());

        // Seed the validator set so the test node is an active validator
        // (without this, try_create_vertex enters Observer Mode and creates 0 vertices)
        // Format: Vec<(String, u64)> = [(address, stake_amount)]
        let validator_json = format!(r#"[["{}",1000]]"#, node_id);
        let _ = db.put("sys:validators", &validator_json);

        (DagConsensus::new(node_id, peers, mempool, executor, db, None, None, node_key), path)
    }

    #[test]
    fn test_dag_vertex_creation() {
        let (mut consensus, path) = setup_dag("vertex_creation");
        
        // 1. Create Genesis Vertex (Round 1)
        consensus.try_create_vertex();
        
        let dag = consensus.dag.lock().unwrap();
        assert_eq!(dag.len(), 1, "Should have 1 vertex (Genesis)");
        
        // Verify Round 1 properties
        let vertices: Vec<_> = dag.values().collect();
        assert_eq!(vertices[0].round, 1);
        assert_eq!(vertices[0].parents, vec!["genesis".to_string()]);
        
        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_dag_growth_and_ordering() {
        let (mut consensus, path) = setup_dag("growth");
        
        // 1. Create Round 1
        consensus.try_create_vertex();
        assert_eq!(consensus.current_round, 2);

        // 2. Create Round 2 (Should reference Round 1)
        consensus.try_create_vertex();
        assert_eq!(consensus.current_round, 3);
        
        let dag = consensus.dag.lock().unwrap();
        assert_eq!(dag.len(), 2, "Should have 2 vertices");
        
        // Verify Round 2 parent is Round 1
        let r2_vertex = dag.values().find(|v| v.round == 2).unwrap();
        let r1_vertex = dag.values().find(|v| v.round == 1).unwrap();
        
        assert!(r2_vertex.parents.contains(&r1_vertex.hash));
        
        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }
    
    #[test]
    fn test_dag_pruning() {
        let (mut consensus, path) = setup_dag("pruning");
        
        // Create 10 rounds
        for _ in 0..10 {
            consensus.try_create_vertex();
        }
        
        {
            let dag = consensus.dag.lock().unwrap();
            assert_eq!(dag.len(), 10);
        }
        
        // Prune older than round 5
        consensus.prune_dag(5);
        
        {
            let dag = consensus.dag.lock().unwrap();
            // Should have rounds 5, 6, 7, 8, 9, 10 (6 items)
            assert_eq!(dag.len(), 6);
            
            // Verify no round < 5 exists
            for v in dag.values() {
                assert!(v.round >= 5);
            }
        }
        
        // Cleanup
        let _ = std::fs::remove_dir_all(&path);
    }
}
