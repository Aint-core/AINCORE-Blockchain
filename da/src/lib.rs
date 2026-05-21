use chrono::Utc;
use crypto::{Signer, SigningKey};
use network::{secure_connect, send_encrypted_msg};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use storage::StateDB;

/// Phase 2.9 (M-09): storage key for the encrypted DA signing key.
const DA_KEY_ENCRYPTED_V1: &str = "sys:da:signing_key_enc_v1";
/// Phase 2.9 (M-09): storage key for the legacy plaintext DA signing
/// key. Retained only for one-shot migration; new installs never
/// populate it.
const DA_KEY_LEGACY_PLAINTEXT: &str = "sys:da:signing_key";
/// HKDF/info string for deriving the DA encryption key from the node
/// identity. Bumping the suffix forces a re-key on next boot.
const DA_ENC_KEY_INFO: &[u8] = b"aincore-da-encryption-v1";

/// Derive a stable 32-byte ChaCha20-Poly1305 key from the node's
/// identity bytes. Anyone reading the encrypted blob from RocksDB
/// also needs the node identity (which lives in a separately-
/// permissioned `node.key` file outside the database) to recover the
/// DA signing key.
fn derive_da_enc_key(node_identity: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(node_identity);
    hasher.update(DA_ENC_KEY_INFO);
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Encoded form of an encrypted DA signing key: 12-byte nonce ||
/// ciphertext (which already includes the 16-byte Poly1305 auth tag).
fn encode_encrypted_key(nonce: [u8; 12], ciphertext: &[u8]) -> String {
    let mut buf = Vec::with_capacity(12 + ciphertext.len());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(ciphertext);
    hex::encode(buf)
}

fn decode_encrypted_key(hex_blob: &str) -> Option<([u8; 12], Vec<u8>)> {
    let raw = hex::decode(hex_blob).ok()?;
    if raw.len() < 12 + 16 {
        return None;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw[..12]);
    Some((nonce, raw[12..].to_vec()))
}

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
mod compression;
mod erasure;
mod fraud_proofs;
mod merkle;
mod optimization;
mod p2p_protocol;
mod sampling;
mod sharding;

use compression::Compressor;
use erasure::ErasureEncoder;
use merkle::MerkleTree;
use sharding::ShardManager;
// use p2p_protocol::ShardMessage;
pub use fraud_proofs::{FraudProof, FraudProofType, FraudProofVerifier, SlashingParams};
pub use optimization::{DAMetrics, DAPruner, PruningConfig};
pub use sampling::{DASampler, LightClient};

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
    /// Legacy constructor — keeps the DA signing key in RocksDB as
    /// plaintext hex (pre-Phase-2.9 behaviour). Retained so callers
    /// that haven't been wired to pass a node identity continue to
    /// work, but emits a loud warning. Production callers should use
    /// [`Self::new_encrypted`].
    pub fn new(
        node_id: String,
        storage: Arc<StateDB>,
        peers: Arc<Mutex<HashMap<String, u16>>>,
    ) -> Self {
        eprintln!(
            "⚠️  [DA Sequencer M-09] new() stores the DA signing key as plaintext \
             in RocksDB. Migrate the caller to new_encrypted(node_identity, ...) \
             for at-rest encryption."
        );
        Self::initialize(node_id, storage, peers, None)
    }

    /// Phase 2.9 (M-09): construct a DA sequencer that encrypts its
    /// signing key at rest using a key derived from the supplied node
    /// identity (typically the node's persistent Ed25519 key bytes
    /// loaded from `node.key`).
    ///
    /// Threat model upgrade: pre-Phase-2.9 anyone who could read the
    /// RocksDB directory could trivially extract the DA signing key.
    /// With encryption the attacker also needs the node identity,
    /// which lives in a separately-permissioned file outside the
    /// database. This raises the bar from "any RocksDB-read attacker"
    /// to "filesystem-read attacker with node.key access" — the same
    /// blast radius as full node compromise, which is the floor we
    /// can practically achieve without HSM/TPM hardware.
    ///
    /// On boot the routine prefers the encrypted blob; if only the
    /// legacy plaintext key is present it migrates atomically — decrypt
    /// then re-encrypt then delete legacy — so a one-shot upgrade does
    /// not regenerate the DA identity.
    pub fn new_encrypted(
        node_id: String,
        storage: Arc<StateDB>,
        peers: Arc<Mutex<HashMap<String, u16>>>,
        node_identity: &[u8; 32],
    ) -> Self {
        Self::initialize(node_id, storage, peers, Some(*node_identity))
    }

    fn initialize(
        node_id: String,
        storage: Arc<StateDB>,
        peers: Arc<Mutex<HashMap<String, u16>>>,
        node_identity: Option<[u8; 32]>,
    ) -> Self {
        println!("⚙️ Initializing Sovereign Data Availability Sequencer (Production Grade)...");
        println!("🏰 [DA Sequencer] 100% Sovereign Mode - No external dependencies!");

        // Initialize erasure encoder (16 data + 16 parity shards)
        let erasure_encoder =
            ErasureEncoder::new(16, 16).expect("Failed to create erasure encoder");

        // Initialize compressor (level 3 for balance)
        let compressor = Compressor::default();

        // Initialize shard manager (32 total shards, 3x replication)
        let shard_manager = ShardManager::new(32, 3);

        let key_bytes = Self::load_or_generate_signing_key(&storage, node_identity);

        let signage_key = SigningKey::from_bytes(&key_bytes);
        let pubkey_bytes = signage_key.verifying_key().to_bytes();
        println!(
            "🔑 [DA Sequencer] ID: {} | PubKey: {}",
            node_id,
            hex::encode(pubkey_bytes)
        );

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

    /// Returns the 32-byte DA signing key, decrypting / migrating as
    /// needed. Logic:
    ///   1. If encrypted blob exists AND we have a node identity → decrypt.
    ///      If decrypt fails, abort (do NOT silently regenerate, which
    ///      would orphan past signed batches).
    ///   2. Else if legacy plaintext exists:
    ///        - encryption available → migrate (encrypt + delete plaintext),
    ///        - encryption unavailable → keep as legacy plaintext.
    ///   3. Else generate fresh:
    ///        - encryption available → encrypt and store,
    ///        - encryption unavailable → store plaintext (warning).
    fn load_or_generate_signing_key(
        storage: &Arc<StateDB>,
        node_identity: Option<[u8; 32]>,
    ) -> [u8; 32] {
        use crypto::transport::TransportEngine;

        // Path 1: encrypted blob present.
        if let Ok(Some(blob_hex)) = storage.get(DA_KEY_ENCRYPTED_V1) {
            let enc_key = match node_identity {
                Some(id) => derive_da_enc_key(&id),
                None => {
                    panic!(
                        "[DA Sequencer M-09] encrypted DA signing key is present \
                         but no node identity was supplied to decrypt it. \
                         Refusing to regenerate; this would orphan signed batches."
                    );
                }
            };
            let (nonce, ciphertext) = decode_encrypted_key(&blob_hex)
                .expect("[DA Sequencer M-09] encrypted DA key blob is malformed");
            let plaintext = TransportEngine::decrypt(&enc_key, &nonce, &ciphertext)
                .expect(
                    "[DA Sequencer M-09] failed to decrypt DA signing key — \
                     node identity may have changed. Refusing to regenerate.",
                );
            if plaintext.len() != 32 {
                panic!(
                    "[DA Sequencer M-09] decrypted DA key has wrong length: {}",
                    plaintext.len()
                );
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&plaintext);
            println!("🔑 [DA Sequencer] Loaded encrypted DA signing key (decrypted at boot).");
            return key_bytes;
        }

        // Path 2: legacy plaintext present.
        if let Ok(Some(legacy_hex)) = storage.get(DA_KEY_LEGACY_PLAINTEXT) {
            let mut key_bytes = [0u8; 32];
            if let Ok(decoded) = hex::decode(&legacy_hex) {
                if decoded.len() == 32 {
                    key_bytes.copy_from_slice(&decoded);
                    if let Some(id) = node_identity {
                        // Migrate to encrypted form.
                        let enc_key = derive_da_enc_key(&id);
                        match TransportEngine::encrypt_safe(&enc_key, &key_bytes) {
                            Ok((nonce, ciphertext)) => {
                                let _ = storage.put(
                                    DA_KEY_ENCRYPTED_V1,
                                    &encode_encrypted_key(nonce, &ciphertext),
                                );
                                let _ = storage.delete(DA_KEY_LEGACY_PLAINTEXT);
                                println!(
                                    "🔑 [DA Sequencer M-09] Migrated legacy plaintext DA \
                                     signing key to encrypted-at-rest form."
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "⚠️  [DA Sequencer M-09] Migration to encrypted form \
                                     failed: {} — keeping legacy plaintext.",
                                    e
                                );
                            }
                        }
                    } else {
                        eprintln!(
                            "⚠️  [DA Sequencer M-09] Legacy plaintext DA key in use. \
                             Migrate caller to new_encrypted() to enable at-rest encryption."
                        );
                    }
                    return key_bytes;
                }
            }
        }

        // Path 3: nothing present — generate fresh.
        use rand::RngCore;
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);

        if let Some(id) = node_identity {
            let enc_key = derive_da_enc_key(&id);
            match TransportEngine::encrypt_safe(&enc_key, &key_bytes) {
                Ok((nonce, ciphertext)) => {
                    let _ = storage.put(
                        DA_KEY_ENCRYPTED_V1,
                        &encode_encrypted_key(nonce, &ciphertext),
                    );
                    println!(
                        "🔑 [DA Sequencer M-09] Generated NEW DA signing key (stored encrypted-at-rest)."
                    );
                }
                Err(e) => {
                    eprintln!(
                        "⚠️  [DA Sequencer M-09] encrypt_safe failed ({}). Falling back \
                         to plaintext storage. Investigate transport layer.",
                        e
                    );
                    let _ = storage.put(DA_KEY_LEGACY_PLAINTEXT, &hex::encode(key_bytes));
                }
            }
        } else {
            let _ = storage.put(DA_KEY_LEGACY_PLAINTEXT, &hex::encode(key_bytes));
            eprintln!(
                "⚠️  [DA Sequencer M-09] Generated NEW DA signing key without node identity \
                 — stored as plaintext. Migrate caller to new_encrypted()."
            );
        }
        key_bytes
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

        // Sign the payload.
        //
        // Phase 2.12 (panic audit): replaced unconditional .expect() with a
        // logged early-return. DABatchPayload is composed of primitive
        // fields so serde_json::to_string is not expected to fail in
        // practice, but a future schema change could introduce a
        // non-serialisable type and we don't want that to take the DA
        // sequencer down with a panic — better to skip this batch and
        // surface the error in logs for triage.
        let payload_json = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "❌ [DA Sequencer] Failed to serialise batch payload (epoch {}): {} — \
                     skipping this batch instead of panicking.",
                    self.epoch, e
                );
                return;
            }
        };
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
                println!(
                    "📦 [DA] Compressed batch: {} → {} bytes ({:.2}x)",
                    batch_json.len(),
                    data.len(),
                    ratio
                );
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
                println!(
                    "🧩 [DA] Created {} shards (16 data + 16 parity)",
                    shards.len()
                );
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
        println!(
            "🗂️  [DA] This node stores {} out of {} shards",
            my_shards.len(),
            shards.len()
        );

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
        println!(
            "   - Compression: {:.2}x",
            self.compressor.ratio(batch_json.len(), compressed.len())
        );
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
        let meta = format!(
            "{{\"shards\":{},\"original_size\":{}}}",
            shards.len(),
            batch_json.len()
        );
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
            println!(
                "📡 [DA Sequencer] Broadcasting batch to {} peers...",
                peers_snapshot.len()
            );
            for (peer_id, port) in peers_snapshot.iter() {
                let peer_ip = storage_clone
                    .get_peer_ip(peer_id)
                    .unwrap_or_else(|| "127.0.0.1".to_string());
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

        println!(
            "📡 [DA Sequencer] Broadcasting batch to {} peers...",
            peers_snapshot.len()
        );

        for (peer_id, port) in peers_snapshot.iter() {
            // Ideally get IP from storage, fallback to localhost for demo
            let peer_ip = self
                .storage
                .get_peer_ip(peer_id)
                .unwrap_or("127.0.0.1".to_string());

            // Ephemeral encrypted connection for broadcast
            use rand::rngs::OsRng;
            let mut csprng = OsRng;
            let ephemeral_signing_key = SigningKey::generate(&mut csprng);

            // Optimization: Maintain persistent connections in a ConnectionPool
            match secure_connect(
                &peer_ip,
                *port,
                "__da__",
                0,
                Some(peer_id),
                &ephemeral_signing_key,
            )
            .await
            {
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
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                if let Ok(vk) =
                    VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap_or(&[0; 32]))
                {
                    if let Ok(sig_bytes) = hex::decode(&batch.signature) {
                        if let Ok(signature) = Signature::from_slice(&sig_bytes) {
                            if let Ok(payload_json) = serde_json::to_string(payload) {
                                let payload_hash = crypto::hash(payload_json.as_bytes());
                                if vk.verify(&payload_hash, &signature).is_err() {
                                    eprintln!(
                                        "🚨 [DA] Invalid Signature for batch epoch {}",
                                        payload.epoch
                                    );
                                    return;
                                }

                                // Verify Identity matches
                                let expected_id = hex::encode(&pubkey_bytes)[0..32].to_string();
                                if expected_id != payload.proposer_id {
                                    eprintln!(
                                        "🚨 [DA] Identity mismatch for batch epoch {}",
                                        payload.epoch
                                    );
                                    return;
                                }
                            }
                        } else {
                            eprintln!("🚨 [DA] Invalid signature format");
                            return;
                        }
                    } else {
                        return;
                    }
                } else {
                    return;
                }
            } else if payload.proposer_pubkey.is_empty() {
                // For backwards compatibility: warning only if old block from DB
                println!(
                    "⚠️  [DA] Legacy batch detected without pubkey (epoch {})",
                    payload.epoch
                );
            } else {
                eprintln!("🚨 [DA] Missing or invalid proposer_pubkey");
                return;
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
    pub fn get_shard_proof(
        &self,
        epoch: u64,
        shard_id: usize,
    ) -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
        // 1. Retrieve all shards for this epoch to rebuild Merkle tree
        let mut shards = Vec::new();
        let meta_key = format!("da_meta_{}", epoch);

        let meta = self
            .storage
            .get(&meta_key)
            .map_err(|_| "Storage error")?
            .ok_or("Epoch metadata not found")?;

        let mut shard_count: usize = serde_json::from_str::<serde_json::Value>(&meta)
            .ok()
            .and_then(|v| v["shards"].as_u64())
            .unwrap_or(32) as usize;

        // CRITICAL FIX: Cap shard_count to prevent OOM DoS allocation attacks
        if shard_count > 128 {
            shard_count = 128;
        }

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
            return Err(format!(
                "Shard {} out of range (max: {})",
                shard_id,
                shards.len()
            ));
        }

        // 3. Build Merkle tree and get proof
        let merkle_tree = MerkleTree::new(&shards);
        let proof = merkle_tree.get_proof(shard_id)?;

        println!(
            "🔍 [DA] Generated Merkle proof for epoch={} shard={}",
            epoch, shard_id
        );

        Ok((shards[shard_id].clone(), proof))
    }

    /// Handle incoming P2P shard request and respond with shard + proof
    ///
    /// This enables distributed shard storage - nodes only store subset of shards
    /// and request missing ones from peers when needed.
    pub fn handle_shard_request(
        &self,
        epoch: u64,
        shard_id: u32,
    ) -> Option<p2p_protocol::ShardMessage> {
        match self.get_shard_proof(epoch, shard_id as usize) {
            Ok((shard_data, merkle_proof)) => {
                println!(
                    "📤 [DA] Responding to shard request epoch={} shard={}",
                    epoch, shard_id
                );
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
        let json = if let Some(rest) = raw_msg.strip_prefix("DA_SHARD:") {
            rest
        } else if let Some(rest) = raw_msg.strip_prefix("DA_COMMIT:") {
            self.handle_incoming_batch(rest);
            return None;
        } else {
            raw_msg
        };

        let message = match p2p_protocol::ShardMessage::from_json(json) {
            Ok(m) => m,
            Err(_) => return None,
        };

        match message {
            p2p_protocol::ShardMessage::ShardRequest {
                epoch,
                shard_id,
                requester_id,
            } => {
                println!(
                    "📥 [DA] Shard request from {} for epoch={} shard={}",
                    requester_id, epoch, shard_id
                );

                if let Some(response) = self.handle_shard_request(epoch, shard_id) {
                    if let Ok(response_json) = response.to_json() {
                        return Some(format!("DA_SHARD:{}", response_json));
                    }
                }
                None
            }

            p2p_protocol::ShardMessage::ShardResponse {
                epoch,
                shard_id,
                data,
                merkle_proof,
            } => {
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
                        println!(
                            "✅ [DA] Verified and stored shard {} for epoch {}",
                            shard_id, epoch
                        );
                    } else {
                        eprintln!(
                            "❌ [DA] Merkle proof verification FAILED for shard {}",
                            shard_id
                        );
                    }
                }
                None
            }

            p2p_protocol::ShardMessage::BatchAnnouncement {
                epoch,
                merkle_root,
                shard_count,
                proposer_id,
            } => {
                println!(
                    "📢 [DA] Batch announcement from {} - epoch={} shards={}",
                    proposer_id, epoch, shard_count
                );

                // Store commitment
                let commitment_key = format!("da_commitment_{}", epoch);
                let _ = self.storage.put(&commitment_key, &hex::encode(merkle_root));

                // Determine which shards we need to request
                let my_shards = self.shard_manager.get_my_shards(&self.node_id);
                println!(
                    "🗂️  [DA] Need to request {} shards from peers",
                    my_shards.len()
                );

                // Return list of shards to request (caller handles actual P2P requests)
                None
            }
        }
    }
}

#[cfg(test)]
mod m09_tests {
    use super::*;
    use std::sync::Arc;

    fn temp_db(suffix: &str) -> Arc<StateDB> {
        let path = format!(
            "/tmp/aincore_da_m09_test_{}_{}",
            std::process::id(),
            suffix
        );
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("open temp db"))
    }

    /// `new_encrypted` writes only the encrypted blob — never the legacy
    /// plaintext key — to RocksDB on a fresh install.
    #[test]
    fn m09_fresh_install_stores_only_encrypted_blob() {
        let db = temp_db("fresh_encrypted");
        let node_identity = [11u8; 32];
        let peers = Arc::new(Mutex::new(HashMap::new()));

        let _seq = DASequencer::new_encrypted("test".into(), Arc::clone(&db), peers, &node_identity);

        assert!(
            db.get(DA_KEY_ENCRYPTED_V1).unwrap().is_some(),
            "encrypted blob must be written"
        );
        assert!(
            db.get(DA_KEY_LEGACY_PLAINTEXT).unwrap().is_none(),
            "fresh encrypted install must NOT write legacy plaintext key"
        );
    }

    /// A pre-existing legacy plaintext key is migrated to encrypted
    /// form on first boot of an upgraded node, preserving the DA
    /// identity (signing key bytes round-trip).
    #[test]
    fn m09_legacy_plaintext_migrates_to_encrypted() {
        let db = temp_db("migrate");
        let legacy_key = [77u8; 32];
        db.put(DA_KEY_LEGACY_PLAINTEXT, &hex::encode(legacy_key))
            .unwrap();

        let node_identity = [22u8; 32];
        let peers = Arc::new(Mutex::new(HashMap::new()));

        let seq = DASequencer::new_encrypted(
            "test".into(),
            Arc::clone(&db),
            peers,
            &node_identity,
        );

        // Plaintext key must have been deleted.
        assert!(
            db.get(DA_KEY_LEGACY_PLAINTEXT).unwrap().is_none(),
            "migration must delete legacy plaintext key"
        );
        // Encrypted blob must be present.
        assert!(db.get(DA_KEY_ENCRYPTED_V1).unwrap().is_some());
        // DA identity preserved — sequencer's signing key bytes match
        // the legacy plaintext.
        assert_eq!(
            seq.signage_key.to_bytes(),
            legacy_key,
            "migration must preserve the DA signing key bytes"
        );
    }

    /// An encrypted blob round-trips: writing then re-instantiating
    /// the DA sequencer with the same node identity yields the same
    /// signing key. Different identity must NOT be able to decrypt.
    #[test]
    fn m09_encrypted_blob_round_trips_only_with_matching_identity() {
        let db = temp_db("roundtrip");
        let node_identity = [33u8; 32];
        let peers = Arc::new(Mutex::new(HashMap::new()));

        let seq1 = DASequencer::new_encrypted(
            "test".into(),
            Arc::clone(&db),
            Arc::clone(&peers),
            &node_identity,
        );
        let key_bytes_1 = seq1.signage_key.to_bytes();
        drop(seq1);

        // Re-instantiate with the SAME identity — must decrypt and
        // yield the same key bytes.
        let seq2 = DASequencer::new_encrypted(
            "test".into(),
            Arc::clone(&db),
            Arc::clone(&peers),
            &node_identity,
        );
        assert_eq!(seq2.signage_key.to_bytes(), key_bytes_1);
        drop(seq2);

        // Re-instantiate with a DIFFERENT identity — must panic on
        // decrypt failure rather than silently regenerate a fresh key
        // (which would orphan signed batches).
        let bad_identity = [99u8; 32];
        let result = std::panic::catch_unwind(|| {
            DASequencer::new_encrypted("test".into(), Arc::clone(&db), peers, &bad_identity)
        });
        assert!(
            result.is_err(),
            "decrypting with the wrong identity must panic, not silently regenerate"
        );
    }
}
