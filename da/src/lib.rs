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
    #[serde(default)]
    pub proposer_pubkey: String,
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
            proposer_pubkey: hex::encode(self.signage_key.verifying_key().to_bytes()),
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

        // Broadcast to peers using the highly optimized GOSSIP_RUNTIME in network module
        let batch_clone = batch.clone();
        let peers_clone = self.peers.clone();
        let storage_clone = self.storage.clone();
        
        let msg = match serde_json::to_string(&batch_clone) {
            Ok(m) => m,
            Err(_) => return,
        };
        let full_msg = format!("DA_COMMIT:{}", msg);

        let peers_snapshot = if let Ok(peers) = peers_clone.lock() {
            peers.clone()
        } else {
            HashMap::new()
        };

        if !peers_snapshot.is_empty() {
             println!("📡 [DA Sequencer] Broadcasting batch to {} peers...", peers_snapshot.len());
             for (peer_id, port) in peers_snapshot.iter() {
                 let peer_ip = storage_clone.get_peer_ip(peer_id).unwrap_or_else(|| "127.0.0.1".to_string());
                 let addr = format!("{}:{}", peer_ip, port);
                 let _ = network::send_message(&addr, &full_msg);
             }
        }
    }

    /// Broadcast DA batch ke seluruh peers using Encrypted Transport
    #[allow(dead_code)] // Kept for external API use
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
            use rand::rngs::OsRng;
            let mut csprng = OsRng;
            let ephemeral_signing_key = SigningKey::generate(&mut csprng);
            
            // Optimization: Maintain persistent connections in a ConnectionPool
            match secure_connect(&peer_ip, *port, "__da__", 0, Some(peer_id), &ephemeral_signing_key).await {
                Ok((mut stream, shared_key, _peer_node_id)) => {
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

    pub fn handle_incoming_batch(&self, raw_msg: &str) {
        if let Ok(batch) = serde_json::from_str::<DABatch>(raw_msg) {
             let payload = &batch.payload;
             
             // 1. Strict Signature Verification (Mitigate DA Poisoning)
             if let Ok(pubkey_bytes) = hex::decode(&payload.proposer_pubkey) {
                 use ed25519_dalek::{VerifyingKey, Signature, Verifier};
                 if let Ok(vk) = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap_or(&[0;32])) {
                     if let Ok(sig_bytes) = hex::decode(&batch.signature) {
                         if let Ok(signature) = Signature::from_slice(&sig_bytes) {
                             if let Ok(payload_json) = serde_json::to_string(payload) {
                                 let payload_hash = crypto::hash(payload_json.as_bytes());
                                 if vk.verify(&payload_hash, &signature).is_err() {
                                     eprintln!("🚨 [DA] Invalid Signature for batch epoch {}", payload.epoch);
                                     return;
                                 }
                                 
                                 // Verify Identity matches
                                 let expected_id = hex::encode(&pubkey_bytes)[0..32].to_string();
                                 if expected_id != payload.proposer_id {
                                     eprintln!("🚨 [DA] Identity mismatch for batch epoch {}", payload.epoch);
                                     return;
                                 }
                             }
                         } else {
                             eprintln!("🚨 [DA] Invalid signature format");
                             return;
                         }
                     } else { return; }
                 } else { return; }
             } else {
                 if payload.proposer_pubkey.is_empty() {
                     // For backwards compatibility: warning only if old block from DB
                     println!("⚠️  [DA] Legacy batch detected without pubkey (epoch {})", payload.epoch);
                 } else {
                     eprintln!("🚨 [DA] Missing or invalid proposer_pubkey");
                     return;
                 }
             }
             
            println!(
                "📥 [DA Sequencer] Verified DA_COMMIT epoch={} from {}",
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
        }
    }

    /// Get Merkle proof for a specific shard (used by light clients for DAS)
    /// 
    /// Light clients use this to verify that a shard is part of the committed batch
    /// without downloading all shards.
    pub fn get_shard_proof(&self, epoch: u64, shard_id: usize) -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
        // 1. Retrieve all shards for this epoch to rebuild Merkle tree
        let mut shards = Vec::new();
        let meta_key = format!("da_meta_{}", epoch);
        
        let meta = self.storage.get(&meta_key)
            .map_err(|_| "Storage error")?
            .ok_or("Epoch metadata not found")?;
        
        let shard_count: usize = serde_json::from_str::<serde_json::Value>(&meta)
            .ok()
            .and_then(|v| v["shards"].as_u64())
            .unwrap_or(32) as usize;
        
        // 2. Load shards from storage
        for i in 0..shard_count {
            let shard_key = format!("da_shard_{}_{}", epoch, i);
            if let Ok(Some(hex_data)) = self.storage.get(&shard_key) {
                shards.push(hex::decode(hex_data).unwrap_or_default());
            } else {
                // Missing shard - use empty placeholder
                shards.push(vec![0u8; 64]);
            }
        }
        
        if shard_id >= shards.len() {
            return Err(format!("Shard {} out of range (max: {})", shard_id, shards.len()));
        }
        
        // 3. Build Merkle tree and get proof
        let merkle_tree = MerkleTree::new(&shards);
        let proof = merkle_tree.get_proof(shard_id)?;
        
        println!("🔍 [DA] Generated Merkle proof for epoch={} shard={}", epoch, shard_id);
        
        Ok((shards[shard_id].clone(), proof))
    }

    /// Handle incoming P2P shard request and respond with shard + proof
    /// 
    /// This enables distributed shard storage - nodes only store subset of shards
    /// and request missing ones from peers when needed.
    pub fn handle_shard_request(&self, epoch: u64, shard_id: u32) -> Option<p2p_protocol::ShardMessage> {
        match self.get_shard_proof(epoch, shard_id as usize) {
            Ok((shard_data, merkle_proof)) => {
                println!("📤 [DA] Responding to shard request epoch={} shard={}", epoch, shard_id);
                Some(p2p_protocol::ShardMessage::ShardResponse {
                    epoch,
                    shard_id,
                    data: shard_data,
                    merkle_proof,
                })
            }
            Err(e) => {
                eprintln!("⚠️  [DA] Cannot fulfill shard request: {}", e);
                None
            }
        }
    }

    /// Handle incoming P2P messages for shard distribution
    /// 
    /// Integrates with the p2p_protocol module for full shard distribution:
    /// - SHARD_REQUEST: Respond with shard data + Merkle proof
    /// - SHARD_RESPONSE: Store received shard
    /// - BATCH_ANNOUNCEMENT: Trigger shard fetching from peers
    pub fn handle_p2p_message(&self, raw_msg: &str) -> Option<String> {
        // Strip prefix if present
        let json = if raw_msg.starts_with("DA_SHARD:") {
            &raw_msg[9..]
        } else if raw_msg.starts_with("DA_COMMIT:") {
            self.handle_incoming_batch(&raw_msg[10..]);
            return None;
        } else {
            raw_msg
        };
        
        let message = match p2p_protocol::ShardMessage::from_json(json) {
            Ok(m) => m,
            Err(_) => return None,
        };
        
        match message {
            p2p_protocol::ShardMessage::ShardRequest { epoch, shard_id, requester_id } => {
                println!("📥 [DA] Shard request from {} for epoch={} shard={}", requester_id, epoch, shard_id);
                
                if let Some(response) = self.handle_shard_request(epoch, shard_id) {
                    if let Ok(response_json) = response.to_json() {
                        return Some(format!("DA_SHARD:{}", response_json));
                    }
                }
                None
            }
            
            p2p_protocol::ShardMessage::ShardResponse { epoch, shard_id, data, merkle_proof } => {
                // Verify Merkle proof against stored commitment
                let commitment_key = format!("da_commitment_{}", epoch);
                if let Ok(Some(root_hex)) = self.storage.get(&commitment_key) {
                    let mut root = [0u8; 32];
                    if let Ok(root_bytes) = hex::decode(&root_hex) {
                        if root_bytes.len() == 32 {
                            root.copy_from_slice(&root_bytes);
                        }
                    }
                    
                    // Verify the proof
                    if MerkleTree::verify_proof(&data, &merkle_proof, &root, shard_id as usize) {
                        // Store verified shard
                        let shard_key = format!("da_shard_{}_{}", epoch, shard_id);
                        let _ = self.storage.put(&shard_key, &hex::encode(&data));
                        println!("✅ [DA] Verified and stored shard {} for epoch {}", shard_id, epoch);
                    } else {
                        eprintln!("❌ [DA] Merkle proof verification FAILED for shard {}", shard_id);
                    }
                }
                None
            }
            
            p2p_protocol::ShardMessage::BatchAnnouncement { epoch, merkle_root, shard_count, proposer_id } => {
                println!("📢 [DA] Batch announcement from {} - epoch={} shards={}", 
                    proposer_id, epoch, shard_count);
                
                // Store commitment
                let commitment_key = format!("da_commitment_{}", epoch);
                let _ = self.storage.put(&commitment_key, &hex::encode(merkle_root));
                
                // Determine which shards we need to request
                let my_shards = self.shard_manager.get_my_shards(&self.node_id);
                println!("🗂️  [DA] Need to request {} shards from peers", my_shards.len());
                
                // Return list of shards to request (caller handles actual P2P requests)
                None
            }
        }
    }
}
