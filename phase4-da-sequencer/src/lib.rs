use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::Utc;
use storage::StateDB;
use network::{secure_connect, send_encrypted_msg};
use crypto::{Signer, SigningKey};

/// Data Batch Representation (Payload)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DABatchPayload {
    pub epoch: u64,
    pub root_hash: String,
    pub tx_count: usize,
    pub proposer_id: String,
    pub timestamp: i64,
}

/// Signed DA Batch (Production Grade)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DABatch {
    pub payload: DABatchPayload,
    pub signature: String, // Hex encoded signature
}

// Sovereign DA modules
mod erasure;
mod compression;
mod merkle;
mod sharding;
mod p2p_protocol;
mod sampling;
mod fraud_proofs;
mod optimization;

use erasure::ErasureEncoder;
use compression::Compressor;
use merkle::MerkleTree;
use sharding::ShardManager;
// use p2p_protocol::ShardMessage;
pub use sampling::{DASampler, LightClient};
pub use fraud_proofs::{FraudProof, FraudProofType, FraudProofVerifier, SlashingParams};
pub use optimization::{DAPruner, PruningConfig, DAMetrics};

/// Sequencer utama untuk Data Availability
pub struct DASequencer {
    pub node_id: String,
    pub signage_key: SigningKey, // Private Key for signing batches
    pub epoch: u64,
    pub batches: Arc<Mutex<HashMap<u64, DABatch>>>,
    pub storage: Arc<StateDB>,
    pub peers: Arc<Mutex<HashMap<String, u16>>>,
    
    // Sovereign DA components
    pub compressor: Compressor,
    pub erasure_encoder: ErasureEncoder,
    pub shard_manager: ShardManager,
}

impl DASequencer {
    /// Inisialisasi DA Sequencer
    pub fn new(node_id: String, storage: Arc<StateDB>, peers: Arc<Mutex<HashMap<String, u16>>>) -> Self {
        println!("⚙️ Initializing Sovereign Data Availability Sequencer (Production Grade)...");
        println!("🏰 [DA Sequencer] 100% Sovereign Mode - No external dependencies!");
        
        // Initialize erasure encoder (16 data + 16 parity shards)
        let erasure_encoder = ErasureEncoder::new(16, 16)
            .expect("Failed to create erasure encoder");
        
        // Initialize compressor (level 3 for balance)
        let compressor = Compressor::default();
        
        // Initialize shard manager (32 total shards, 3x replication)
        let shard_manager = ShardManager::new(32, 3);

        // Generate a random signing key for this sequencer instance
        // In reality, this should be loaded from a secure keystore.
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let signage_key = SigningKey::from_bytes(&key_bytes);
        let pubkey_bytes = signage_key.verifying_key().to_bytes();
        println!("🔑 [DA Sequencer] ID: {} | PubKey: {}", node_id, hex::encode(pubkey_bytes));
        
        Self {
            node_id,
            signage_key,
            epoch: 0,
            batches: Arc::new(Mutex::new(HashMap::new())),
            storage,
            peers,
            compressor,
            erasure_encoder,
            shard_manager,
        }
    }

    /// Membuat DA batch baru dengan sovereign DA processing
    pub fn create_batch(&mut self, root_hash: String, tx_count: usize) {
        self.epoch += 1;
        
        let payload = DABatchPayload {
            epoch: self.epoch,
            root_hash: root_hash.clone(),
            tx_count,
            proposer_id: self.node_id.clone(),
            timestamp: Utc::now().timestamp(),
        };

        // Sign the payload
        let payload_json = serde_json::to_string(&payload).expect("Serialization failed");
        let payload_hash = crypto::hash(payload_json.as_bytes());
        let signature = self.signage_key.sign(&payload_hash);
        
        let batch = DABatch {
            payload,
            signature: hex::encode(signature.to_bytes()),
        };

        // Serialize batch
        let batch_json = match serde_json::to_string(&batch) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("❌ [DA Sequencer] Failed to serialize batch: {}", e);
                return;
            }
        };
        
        // === SOVEREIGN DA PROCESSING ===
        
        // Step 1: Compress data
        let compressed = match self.compressor.compress(batch_json.as_bytes()) {
            Ok(data) => {
                let ratio = self.compressor.ratio(batch_json.len(), data.len());
                println!("📦 [DA] Compressed batch: {} → {} bytes ({:.2}x)", 
                    batch_json.len(), data.len(), ratio);
                data
            }
            Err(e) => {
                eprintln!("⚠️  [DA] Compression failed: {}, using uncompressed", e);
                batch_json.as_bytes().to_vec()
            }
        };
        
        // Step 2: Erasure encode into shards
        let shards = match self.erasure_encoder.encode(&compressed) {
            Ok(shards) => {
                println!("🧩 [DA] Created {} shards (16 data + 16 parity)", shards.len());
                shards
            }
            Err(e) => {
                eprintln!("❌ [DA] Erasure encoding failed: {}", e);
                return;
            }
        };
        
        // Step 3: Create Merkle commitment
        let merkle_tree = MerkleTree::new(&shards);
        let merkle_root = merkle_tree.root();
        let merkle_root_hex = hex::encode(merkle_root);
        
        println!("🌳 [DA] Merkle root: {}", merkle_root_hex);
        
        // Step 4: Determine which shards this node should store
        let my_shards = self.shard_manager.get_my_shards(&self.node_id);
        println!("🗂️  [DA] This node stores {} out of {} shards", my_shards.len(), shards.len());
        
        // Step 5: Store only assigned shards (distributed storage)
        let mut stored_count = 0;
        for shard_id in &my_shards {
            if let Some(shard_data) = shards.get(*shard_id as usize) {
                let shard_key = format!("da_shard_{}_{}", self.epoch, shard_id);
                let _ = self.storage.put(&shard_key, &hex::encode(shard_data));
                stored_count += 1;
            }
        }
        
        println!("✅ [DA Sequencer] Batch epoch={} processed:", self.epoch);
        println!("   - Compression: {:.2}x", self.compressor.ratio(batch_json.len(), compressed.len()));
        println!("   - Shards created: {}", shards.len());
        println!("   - Shards stored locally: {}", stored_count);
        println!("   - Merkle root: {}", merkle_root_hex);
        
        // Store Merkle root as DA commitment
        let commitment_key = format!("da_commitment_{}", self.epoch);
        let _ = self.storage.put(&commitment_key, &merkle_root_hex);
        
        // Store compressed data (Full Data for simple nodes, but in sharding we rely on p2p)
        // For redundant safety in this phase, we store full data locally too.
        let data_key = format!("da_data_{}", self.epoch);
        let _ = self.storage.put(&data_key, &hex::encode(&compressed));
        
        // Store shard count for reconstruction
        let meta_key = format!("da_meta_{}", self.epoch);
        let meta = format!("{{\"shards\":{},\"original_size\":{}}}", 
            shards.len(), batch_json.len());
        let _ = self.storage.put(&meta_key, &meta);
        
        // Store original batch info
        let batch_key = format!("da_root_{}", self.epoch);
        let _ = self.storage.put(&batch_key, &batch_json);

        // Cache in memory
        if let Ok(mut batches) = self.batches.lock() {
            batches.insert(self.epoch, batch.clone());
        }

        // Broadcast to peers via Encrypted P2P (Spawned)
        let batch_clone = batch.clone();
        let node_id_clone = self.node_id.clone();
        let peers_clone = self.peers.clone();
        let storage_clone = self.storage.clone();
        
        std::thread::spawn(move || {
             let rt = match tokio::runtime::Runtime::new() {
                 Ok(r) => r,
                 Err(e) => {
                     eprintln!("❌ [DA] FAILED TO START RUNTIME: {}", e);
                     return;
                 }
             };
             rt.block_on(async move {
                 // Reconstruct a temporary sequencer context or just call logic directly
                 // We can't call self.broadcast_batch because 'self' is not Send/Sync safely here across thread boundary 
                 // without Arc.
                 // We replicate broadcast logic or simple helper. 
                 // Implementing "broadcast_batch_static" or similar.
                 
                let peers_snapshot = if let Ok(peers) = peers_clone.lock() {
                    peers.clone()
                } else {
                    HashMap::new()
                };
                
                let msg = match serde_json::to_string(&batch_clone) {
                    Ok(m) => m,
                    Err(_) => return,
                };
                let full_msg = format!("DA_COMMIT:{}", msg);

                println!("📡 [DA Sequencer] Broadcasting batch to {} peers...", peers_snapshot.len());

                for (peer_id, port) in peers_snapshot.iter() {
                    let peer_ip = storage_clone.get_peer_ip(peer_id).unwrap_or("127.0.0.1".to_string());
                    match secure_connect(&peer_ip, *port, &node_id_clone, 0, None).await {
                        Ok((mut stream, shared_key)) => {
                            let _ = send_encrypted_msg(&mut stream, &shared_key, &full_msg).await;
                        }
                        Err(e) => eprintln!("❌ [DA] Connection failed: {}", e),
                    }
                }
             });
        });
    }

    /// Broadcast DA batch ke seluruh peers using Encrypted Transport
    async fn broadcast_batch(&self, batch: DABatch) {
        let peers_snapshot = if let Ok(peers) = self.peers.lock() {
            peers.clone()
        } else {
            HashMap::new()
        };
        
        let msg = match serde_json::to_string(&batch) {
            Ok(m) => m,
            Err(_) => return,
        };
        let full_msg = format!("DA_COMMIT:{}", msg);

        println!("📡 [DA Sequencer] Broadcasting batch to {} peers...", peers_snapshot.len());

        for (peer_id, port) in peers_snapshot.iter() {
            // Ideally get IP from storage, fallback to localhost for demo
            let peer_ip = self.storage.get_peer_ip(peer_id).unwrap_or("127.0.0.1".to_string());
            
            // Ephemeral encrypted connection for broadcast
            // Optimization: Maintain persistent connections in a ConnectionPool
            match secure_connect(&peer_ip, *port, &self.node_id, 0, Some(peer_id)).await {
                Ok((mut stream, shared_key)) => {
                    if let Err(e) = send_encrypted_msg(&mut stream, &shared_key, &full_msg).await {
                        eprintln!("❌ [DA] Failed to send to {}: {}", peer_id, e);
                    } else {
                         println!("📤 [DA] Sent batch to {}", peer_id);
                    }
                }
                Err(e) => eprintln!("❌ [DA] Connection failed to {}: {}", peer_id, e),
            }
        }
    }

    /// Sinkronisasi batch DA dari peer lain
    pub fn handle_incoming_batch(&self, raw_msg: &str) {
        if let Ok(batch) = serde_json::from_str::<DABatch>(raw_msg) {
             let payload = &batch.payload;
             
             // 1. Verify Signature
             // In a real system, we'd lookup the proposer's public key from a Registry.
             // For now, we assume implicit trust or Self-Verification if we had the key.
             // TODO: Add Registry Lookup.
             
            println!(
                "📥 [DA Sequencer] Received DA_COMMIT epoch={} from {}",
                payload.epoch, payload.proposer_id
            );

            // Simpan ke RocksDB
            let key = format!("da_root_{}", payload.epoch);
            if let Ok(val) = serde_json::to_string(&batch) {
                let _ = self.storage.put(&key, &val);
            }

            // Simpan ke cache in-memory
            if let Ok(mut batches) = self.batches.lock() {
                batches.insert(payload.epoch, batch);
            }
        } else {
            eprintln!("⚠️ [DA Sequencer] Invalid DA_COMMIT payload");
        }
    }
}
