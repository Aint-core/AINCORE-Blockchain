#[cfg(test)]
mod tests {
    use crate::{StateDB, object::{self, Object}};
    use std::fs;

    fn temp_db(name: &str) -> StateDB {
        let path = format!("/tmp/aincore_test_db_{}", name);
        let _ = fs::remove_dir_all(&path);
        StateDB::open(&path).expect("Failed to open test DB")
    }

    #[test]
    fn test_put_get_roundtrip() {
        let db = temp_db("put_get");
        db.put("hello", "world").unwrap();
        assert_eq!(db.get("hello").unwrap(), Some("world".to_string()));
    }

    #[test]
    fn test_get_missing_key() {
        let db = temp_db("missing");
        assert_eq!(db.get("nonexistent").unwrap(), None);
    }

    #[test]
    fn test_delete() {
        let db = temp_db("delete");
        db.put("key1", "val1").unwrap();
        db.delete("key1").unwrap();
        assert_eq!(db.get("key1").unwrap(), None);
    }

    #[test]
    fn test_chain_height_empty() {
        let db = temp_db("height_empty");
        assert_eq!(db.get_chain_height(), 0);
    }

    #[test]
    fn test_chain_height_set() {
        let db = temp_db("height_set");
        db.put("latest_height", "42").unwrap();
        assert_eq!(db.get_chain_height(), 42);
    }

    #[test]
    fn test_save_block_json_updates_height_and_hash() {
        let db = temp_db("block_json");
        let block_json = r#"{"header":{"hash":"abc123","height":1},"transactions":[]}"#;
        db.save_block_json(1, block_json).unwrap();
        
        assert_eq!(db.get_chain_height(), 1);
        assert_eq!(db.get("latest_block_hash").unwrap(), Some("abc123".to_string()));
        assert_eq!(db.get("block_1").unwrap(), Some(block_json.to_string()));
    }

    #[test]
    fn test_tx_index_roundtrip() {
        let db = temp_db("tx_index");
        db.index_transaction("0xdeadbeef", 99).unwrap();
        assert_eq!(db.get_tx_block_height("0xdeadbeef"), Some(99));
        assert_eq!(db.get_tx_block_height("0xnonexistent"), None);
    }

    #[test]
    fn test_scan_prefix() {
        let db = temp_db("scan_prefix");
        db.put("metric:cpu", "50").unwrap();
        db.put("metric:mem", "80").unwrap();
        db.put("other:key", "val").unwrap();
        
        let results = db.scan_prefix("metric:");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_peer_save_and_get() {
        let db = temp_db("peers");
        db.save_peer("node_abc", 8080).unwrap();
        assert_eq!(db.get_peer("node_abc"), Some(8080));
        assert_eq!(db.get_peer("unknown"), None);
    }

    #[test]
    fn test_peer_ip_tracking() {
        let db = temp_db("peer_ip");
        db.save_peer_ip("node_1", "192.168.1.100").unwrap();
        assert_eq!(db.get_peer_ip("node_1"), Some("192.168.1.100".to_string()));
        assert_eq!(db.get_peer_ip("node_2"), None);
    }

    #[test]
    fn test_federation_key() {
        let db = temp_db("federation");
        assert_eq!(db.get_federation_key(), "");
        db.set_federation_key("0xFEDERATION").unwrap();
        assert_eq!(db.get_federation_key(), "0xFEDERATION");
    }

    #[test]
    fn test_economic_config() {
        let db = temp_db("economics");
        // Defaults
        assert_eq!(db.get_base_reward(), 50);
        assert_eq!(db.get_halving_interval(), 2_100_000);
        assert_eq!(db.get_burn_percentage(), 10);
        
        // Update
        db.update_economic_config(Some(36), Some(2_102_400), Some(5)).unwrap();
        assert_eq!(db.get_base_reward(), 36);
        assert_eq!(db.get_halving_interval(), 2_102_400);
        assert_eq!(db.get_burn_percentage(), 5);
    }

    #[test]
    fn test_validator_set() {
        let db = temp_db("validators");
        assert_eq!(db.get_active_validators().len(), 0);
        
        db.update_validator_weight("pk_alice", 1000).unwrap();
        db.update_validator_weight("pk_bob", 2000).unwrap();
        
        let vals = db.get_active_validators();
        assert_eq!(vals.len(), 2);
        assert!(vals.iter().any(|(pk, w)| pk == "pk_alice" && *w == 1000));
        assert!(vals.iter().any(|(pk, w)| pk == "pk_bob" && *w == 2000));
        
        // Update existing weight
        db.update_validator_weight("pk_alice", 3000).unwrap();
        let vals = db.get_active_validators();
        assert!(vals.iter().any(|(pk, w)| pk == "pk_alice" && *w == 3000));
    }

    #[test]
    fn test_dag_checkpoint() {
        let db = temp_db("dag_ckpt");
        assert_eq!(db.get_latest_checkpoint_round(), 0);
        
        db.save_dag_checkpoint(100, r#"[{"round":100}]"#).unwrap();
        assert_eq!(db.get_latest_checkpoint_round(), 100);
        assert!(db.get_dag_checkpoint(100).is_some());
        assert!(db.get_dag_checkpoint(50).is_none());
    }

    #[test]
    fn test_object_roundtrip() {
        let db = temp_db("object");
        let obj = Object::new(
            "obj_001".to_string(),
            object::Owner::Address("alice".to_string()),
            b"hello world".to_vec(),
            "0x1::coin::Coin".to_string(),
        );
        db.put_object(&obj).unwrap();
        
        let loaded = db.get_object("obj_001");
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.owner, object::Owner::Address("alice".to_string()));
        assert_eq!(loaded.version, 0);
        assert_eq!(loaded.data, b"hello world".to_vec());
    }

    #[test]
    fn test_overwrite_value() {
        let db = temp_db("overwrite");
        db.put("key", "v1").unwrap();
        assert_eq!(db.get("key").unwrap(), Some("v1".to_string()));
        
        db.put("key", "v2").unwrap();
        assert_eq!(db.get("key").unwrap(), Some("v2".to_string()));
    }
}
