use serde::{Serialize, Deserialize};

/// P2P messages for shard distribution
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ShardMessage {
    /// Request a shard from a peer
    ShardRequest {
        epoch: u64,
        shard_id: u32,
        requester_id: String,
    },
    
    /// Response with shard data
    ShardResponse {
        epoch: u64,
        shard_id: u32,
        data: Vec<u8>,
        merkle_proof: Vec<[u8; 32]>,
    },
    
    /// Announce new DA batch
    BatchAnnouncement {
        epoch: u64,
        merkle_root: [u8; 32],
        shard_count: u32,
        proposer_id: String,
    },
}

impl ShardMessage {
    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self)
            .map_err(|e| format!("Serialization failed: {}", e))
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Deserialization failed: {}", e))
    }
    
    /// Get message type as string
    pub fn message_type(&self) -> &str {
        match self {
            ShardMessage::ShardRequest { .. } => "SHARD_REQUEST",
            ShardMessage::ShardResponse { .. } => "SHARD_RESPONSE",
            ShardMessage::BatchAnnouncement { .. } => "BATCH_ANNOUNCEMENT",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_shard_request_serialization() {
        let msg = ShardMessage::ShardRequest {
            epoch: 100,
            shard_id: 5,
            requester_id: "node1".to_string(),
        };
        
        let json = msg.to_json().unwrap();
        let decoded = ShardMessage::from_json(&json).unwrap();
        
        match decoded {
            ShardMessage::ShardRequest { epoch, shard_id, requester_id } => {
                assert_eq!(epoch, 100);
                assert_eq!(shard_id, 5);
                assert_eq!(requester_id, "node1");
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn test_batch_announcement() {
        let msg = ShardMessage::BatchAnnouncement {
            epoch: 42,
            merkle_root: [1u8; 32],
            shard_count: 32,
            proposer_id: "validator1".to_string(),
        };
        
        assert_eq!(msg.message_type(), "BATCH_ANNOUNCEMENT");
        
        let json = msg.to_json().unwrap();
        assert!(json.contains("\"epoch\":42"));
    }
}
