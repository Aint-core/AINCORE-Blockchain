use chrono::Utc;
use crypto::{Signer, SigningKey};
use network::{read_encrypted_msg, secure_connect, send_encrypted_msg};
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
    /// Phase 2.9 (M-09) + Phase 5.3 (C1): the ONLY way to construct a DA
    /// sequencer. The signing key is encrypted at rest with a key derived
    /// from `node_identity` (typically the node's persistent Ed25519 key
    /// bytes loaded from `node.key`).
    ///
    /// Threat model: pre-Phase-2.9 anyone who could read the RocksDB
    /// directory could trivially extract the DA signing key. With
    /// encryption the attacker also needs the node identity, which lives
    /// in a separately-permissioned file outside the database. This
    /// raises the bar from "any RocksDB-read attacker" to "filesystem-
    /// read attacker with node.key access" — the same blast radius as
    /// full node compromise, which is the floor we can practically
    /// achieve without HSM/TPM hardware.
    ///
    /// On boot the routine prefers the encrypted blob; if only the
    /// legacy plaintext key is present it migrates atomically — decrypt
    /// then re-encrypt then delete legacy — so a one-shot upgrade does
    /// not regenerate the DA identity.
    ///
    /// Phase 5.3 cleanup: the legacy `new()` constructor (which stored
    /// the signing key as plaintext when no identity was supplied) has
    /// been removed. There is no longer a path that writes a plaintext
    /// DA key to disk — the only remaining plaintext read path is the
    /// one-shot legacy migration into the encrypted form.
    pub fn new_encrypted(
        node_id: String,
        storage: Arc<StateDB>,
        peers: Arc<Mutex<HashMap<String, u16>>>,
        node_identity: &[u8; 32],
    ) -> Self {
        Self::initialize(node_id, storage, peers, *node_identity)
    }

    fn initialize(
        node_id: String,
        storage: Arc<StateDB>,
        peers: Arc<Mutex<HashMap<String, u16>>>,
        node_identity: [u8; 32],
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
    /// needed. Phase 5.3 cleanup: node_identity is now mandatory and
    /// there is no plaintext-write fallback. Logic:
    ///   1. If encrypted blob exists → decrypt (panic on failure rather
    ///      than silently regenerate, which would orphan signed batches).
    ///   2. Else if legacy plaintext exists → migrate atomically
    ///      (decrypt-read + encrypt-write + delete-legacy). If the
    ///      encrypt step fails the boot is aborted via panic — we never
    ///      keep a key in plaintext on a fresh write.
    ///   3. Else generate fresh and store encrypted.
    fn load_or_generate_signing_key(storage: &Arc<StateDB>, node_identity: [u8; 32]) -> [u8; 32] {
        use crypto::transport::TransportEngine;
        let enc_key = derive_da_enc_key(&node_identity);

        // Path 1: encrypted blob present.
        if let Ok(Some(blob_hex)) = storage.get(DA_KEY_ENCRYPTED_V1) {
            let (nonce, ciphertext) = decode_encrypted_key(&blob_hex)
                .expect("[DA Sequencer M-09] encrypted DA key blob is malformed");
            let plaintext = TransportEngine::decrypt(&enc_key, &nonce, &ciphertext).expect(
                "[DA Sequencer M-09] failed to decrypt DA signing key — \
                     node identity may have changed. Refusing to regenerate.",
            );
            assert_eq!(
                plaintext.len(),
                32,
                "[DA Sequencer M-09] decrypted DA key has wrong length"
            );
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&plaintext);
            println!("🔑 [DA Sequencer] Loaded encrypted DA signing key (decrypted at boot).");
            return key_bytes;
        }

        // Path 2: legacy plaintext present — one-shot migration to encrypted.
        if let Ok(Some(legacy_hex)) = storage.get(DA_KEY_LEGACY_PLAINTEXT) {
            let decoded = hex::decode(&legacy_hex)
                .expect("[DA Sequencer M-09] legacy plaintext DA key is not valid hex");
            assert_eq!(
                decoded.len(),
                32,
                "[DA Sequencer M-09] legacy plaintext DA key has wrong length"
            );
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&decoded);
            let (nonce, ciphertext) = TransportEngine::encrypt_safe(&enc_key, &key_bytes).expect(
                "[DA Sequencer M-09 / C1] legacy → encrypted migration failed; \
                     refusing to keep the key as plaintext. Investigate transport layer.",
            );
            let _ = storage.put(
                DA_KEY_ENCRYPTED_V1,
                &encode_encrypted_key(nonce, &ciphertext),
            );
            let _ = storage.delete(DA_KEY_LEGACY_PLAINTEXT);
            println!(
                "🔑 [DA Sequencer M-09] Migrated legacy plaintext DA signing key \
                 to encrypted-at-rest form."
            );
            return key_bytes;
        }

        // Path 3: nothing present — generate fresh and store encrypted.
        use rand::RngCore;
        let mut key_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);

        let (nonce, ciphertext) = TransportEngine::encrypt_safe(&enc_key, &key_bytes).expect(
            "[DA Sequencer M-09 / C1] failed to encrypt fresh DA key; \
                 refusing to write plaintext fallback. Investigate transport layer.",
        );
        let _ = storage.put(
            DA_KEY_ENCRYPTED_V1,
            &encode_encrypted_key(nonce, &ciphertext),
        );
        println!("🔑 [DA Sequencer M-09] Generated NEW DA signing key (stored encrypted-at-rest).");
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

        // Step 4: Determine which shards this node should store.
        // SEC-#2: populate shard assignments from the live peer set + self FIRST.
        // Without this, `update_validators` is never called, `shard_assignments`
        // stays empty, `get_my_shards` returns [], and NO `da_shard_{epoch}_{id}`
        // rows are ever written — the "32 shards / 3x replication" is computed and
        // discarded. Seeding it makes sharded storage real; on a single-node
        // topology all shards land locally, which makes DAS verifiable with no
        // network (see `verify_local_availability`).
        {
            let mut validators: Vec<String> = self
                .peers
                .lock()
                .map(|p| p.keys().cloned().collect())
                .unwrap_or_default();
            validators.push(self.node_id.clone());
            self.shard_manager.update_validators(validators);
        }
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

                                // Verify Identity matches.
                                // Node identity is the canonical AINCORE address =
                                // hex(SHA256(pubkey)) (crypto::derive_address), NOT a
                                // prefix of the raw public key. Must stay in lockstep
                                // with core/node's node_id derivation.
                                let expected_id = match crypto::derive_address(&pubkey_bytes) {
                                    Ok(id) => id,
                                    Err(_) => {
                                        eprintln!(
                                            "🚨 [DA] Cannot derive proposer id for batch epoch {}",
                                            payload.epoch
                                        );
                                        return;
                                    }
                                };
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

    /// SEC-#3: read the committed Merkle root for an epoch (`da_commitment_{epoch}`)
    /// — the root that DAS verifies retrieved shards against. `None` if absent or
    /// malformed.
    pub fn get_commitment(&self, epoch: u64) -> Option<[u8; 32]> {
        let hex_root = self
            .storage
            .get(&format!("da_commitment_{}", epoch))
            .ok()
            .flatten()?;
        let bytes = hex::decode(hex_root).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Some(root)
    }

    /// SEC-#3: run DAS over this node's locally-stored shards for `epoch`,
    /// verifying each sampled shard against the committed Merkle root. This is
    /// deterministic and network-free, and proves the verify-on-sample path
    /// end-to-end: it returns `Ok(true)` only when enough shards both load AND
    /// verify against the commitment (a missing/corrupt shard set rebuilds a
    /// different tree whose proofs fail against the committed root).
    pub fn verify_local_availability(&self, epoch: u64) -> Result<bool, String> {
        let root = self
            .get_commitment(epoch)
            .ok_or("DA commitment not found for epoch")?;
        let meta = self
            .storage
            .get(&format!("da_meta_{}", epoch))
            .map_err(|_| "Storage error")?
            .ok_or("Epoch metadata not found")?;
        let mut shard_count = serde_json::from_str::<serde_json::Value>(&meta)
            .ok()
            .and_then(|v| v["shards"].as_u64())
            .unwrap_or(32) as u32;
        if shard_count > 128 {
            shard_count = 128;
        }
        if shard_count == 0 {
            return Ok(false);
        }
        // DASampler::sample errors if sample_size > total; cap to the shard count.
        let sample_size = 30usize.min(shard_count as usize);
        let sampler = DASampler::new(sample_size, 0.999);
        sampler.sample(shard_count, &root, |id| {
            self.get_shard_proof(epoch, id as usize)
        })
    }

    /// TASK #3 Stage-2 REQUEST: fetch a single shard (+ Merkle proof) from a
    /// remote peer over the same encrypted TCP channel used by sync/broadcast.
    ///
    /// This mirrors `sync::fetch_verified_tip`: open an ephemeral
    /// `secure_connect`, send a `DA_SHARD:{ShardRequest}` frame, read back the
    /// `DA_SHARD:{ShardResponse}` frame, and return `(bytes, merkle_proof)`.
    ///
    /// NOTE: the caller is responsible for verifying the returned bytes+proof
    /// against the epoch commitment (the Stage-1 sampler does exactly this) —
    /// this function performs no trust decision, it is a dumb transport so that
    /// a lying peer cannot be distinguished here from an honest one. Serving and
    /// fetching are side-effect-only and touch NO consensus state, so they are
    /// determinism-safe.
    pub async fn fetch_shard_from_peer(
        &self,
        peer_ip: &str,
        port: u16,
        epoch: u64,
        shard_id: u32,
    ) -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let ephemeral_signing_key = SigningKey::generate(&mut csprng);

        let (mut stream, shared_key, _peer_node_id) = secure_connect(
            peer_ip,
            port,
            "__da__",
            0,
            None,
            &ephemeral_signing_key,
        )
        .await
        .map_err(|e| format!("secure_connect failed: {}", e))?;

        let request = p2p_protocol::ShardMessage::ShardRequest {
            epoch,
            shard_id,
            requester_id: self.node_id.clone(),
        };
        let req_json = request.to_json()?;
        let req_msg = format!("DA_SHARD:{}", req_json);

        send_encrypted_msg(&mut stream, &shared_key, &req_msg)
            .await
            .map_err(|e| format!("send failed: {}", e))?;

        let resp = read_encrypted_msg(&mut stream, &shared_key)
            .await
            .map_err(|e| format!("read failed: {}", e))?;

        let json = resp
            .strip_prefix("DA_SHARD:")
            .ok_or("peer returned non-DA_SHARD response")?;
        let message = p2p_protocol::ShardMessage::from_json(json)?;

        match message {
            p2p_protocol::ShardMessage::ShardResponse {
                epoch: r_epoch,
                shard_id: r_shard_id,
                data,
                merkle_proof,
            } => {
                if r_epoch != epoch || r_shard_id != shard_id {
                    return Err(format!(
                        "peer returned mismatched shard (asked epoch={} shard={}, got epoch={} shard={})",
                        epoch, shard_id, r_epoch, r_shard_id
                    ));
                }
                Ok((data, merkle_proof))
            }
            other => Err(format!(
                "peer returned unexpected message type: {}",
                other.message_type()
            )),
        }
    }

    /// TASK #3 Stage-2 REQUEST: real cross-node data-availability sampling for
    /// `epoch`. Samples N random shards; for each sampled shard it tries the
    /// LOCAL store first (`get_shard_proof`), and only if that fails does it
    /// reach out to a peer (`fetch_shard_from_peer`). Each retrieved
    /// `(bytes, proof)` is fed into the Stage-1 verified sampler, which checks it
    /// against the committed Merkle root (`get_commitment`). A shard that is
    /// retrieved but does not verify counts as UNAVAILABLE — a lying peer cannot
    /// fake availability.
    ///
    /// Returns `Ok(true)` when enough sampled shards both retrieve AND verify;
    /// `Ok(false)` when the network cannot supply a verifiable shard set; `Err`
    /// only when the epoch has no commitment/metadata to sample against.
    ///
    /// Determinism: this is an OUT-OF-BAND availability check (monitoring), never
    /// on the block-execution path, so its use of network + RNG is safe.
    pub async fn verify_availability_from_peers(&self, epoch: u64) -> Result<bool, String> {
        let root = self
            .get_commitment(epoch)
            .ok_or("DA commitment not found for epoch")?;

        let meta = self
            .storage
            .get(&format!("da_meta_{}", epoch))
            .map_err(|_| "Storage error")?
            .ok_or("Epoch metadata not found")?;
        let mut shard_count = serde_json::from_str::<serde_json::Value>(&meta)
            .ok()
            .and_then(|v| v["shards"].as_u64())
            .unwrap_or(32) as u32;
        if shard_count > 128 {
            shard_count = 128;
        }
        if shard_count == 0 {
            return Ok(false);
        }

        // Snapshot peers once so the sample is over a stable peer set.
        let peers_snapshot = if let Ok(peers) = self.peers.lock() {
            peers.clone()
        } else {
            HashMap::new()
        };

        // Pick the sampled shard indices up-front (random, dedup) so we can do
        // the async per-shard fetches before handing fully-resolved results to
        // the (synchronous) Stage-1 sampler closure.
        let sample_size = 30usize.min(shard_count as usize);
        let sampled_ids: Vec<u32> = {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            let mut ids: Vec<u32> = (0..shard_count).collect();
            ids.shuffle(&mut rng);
            ids.truncate(sample_size);
            ids
        };

        // Resolve each sampled shard: local first, else fetch from peers.
        let mut resolved: HashMap<u32, (Vec<u8>, Vec<[u8; 32]>)> = HashMap::new();
        for &id in &sampled_ids {
            if let Ok(local) = self.get_shard_proof(epoch, id as usize) {
                resolved.insert(id, local);
                continue;
            }
            // Local miss — try peers until one supplies the shard.
            for (peer_id, port) in peers_snapshot.iter() {
                let peer_ip = self
                    .storage
                    .get_peer_ip(peer_id)
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                if let Ok(fetched) = self.fetch_shard_from_peer(&peer_ip, *port, epoch, id).await {
                    resolved.insert(id, fetched);
                    break;
                }
            }
        }

        // Feed the resolved shards into the Stage-1 verified sampler. Because we
        // pre-selected exactly `sample_size` distinct ids and the sampler also
        // draws `sample_size` distinct ids from the same range, any id the
        // sampler asks for is one we attempted to resolve; an unresolved id (no
        // local copy, no peer supplied it) returns Err → counts as unavailable.
        let sampler = DASampler::new(sample_size, 0.999);
        sampler.sample(shard_count, &root, |id| {
            resolved
                .get(&id)
                .cloned()
                .ok_or_else(|| format!("shard {} unavailable (local miss + no peer)", id))
        })
    }

    /// TASK #3 Stage-2 GATE (SAFE): out-of-band availability check for a
    /// committed `epoch`. This NEVER blocks finality — it is intended to run on a
    /// background/periodic task. On `Ok(false)` it logs a loud
    /// `[SECURITY][DA_UNAVAILABLE]` alert and (best-effort) records a
    /// `MissingData` fraud proof so the condition is observable on-chain by
    /// monitoring; it does not halt the node.
    ///
    /// Returns the underlying availability result so callers can drive metrics.
    pub async fn audit_epoch_availability(&self, epoch: u64) -> Result<bool, String> {
        match self.verify_availability_from_peers(epoch).await {
            Ok(true) => Ok(true),
            Ok(false) => {
                eprintln!(
                    "🚨 [SECURITY][DA_UNAVAILABLE] epoch={} failed cross-node availability sampling \
                     — committed data may be WITHHELD. Alerting (node continues; finality NOT halted).",
                    epoch
                );
                // Best-effort: surface the condition as a recorded fraud proof.
                if let Some(root) = self.get_commitment(epoch) {
                    let fp = FraudProof {
                        epoch,
                        proof_type: FraudProofType::MissingData,
                        claimed_root: root,
                        evidence: format!(
                            "cross-node DA sampling returned unavailable for epoch {}",
                            epoch
                        )
                        .into_bytes(),
                        proof_data: Vec::new(),
                        submitter: self.node_id.clone(),
                        timestamp: Utc::now().timestamp(),
                    };
                    let key = format!("da_fraud_missingdata_{}", epoch);
                    if let Ok(json) = serde_json::to_string(&fp) {
                        let _ = self.storage.put(&key, &json);
                    }
                }
                Ok(false)
            }
            Err(e) => {
                // No commitment/metadata to sample against is not itself a
                // withholding alert (the epoch may simply be unknown locally).
                eprintln!(
                    "ℹ️  [DA] availability audit skipped for epoch={}: {}",
                    epoch, e
                );
                Err(e)
            }
        }
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
        let path = format!("/tmp/aincore_da_m09_test_{}_{}", std::process::id(), suffix);
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

        let _seq =
            DASequencer::new_encrypted("test".into(), Arc::clone(&db), peers, &node_identity);

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

        let seq = DASequencer::new_encrypted("test".into(), Arc::clone(&db), peers, &node_identity);

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

    /// SEC-#2/#3: create_batch actually persists shards (previously zero rows),
    /// and verify_local_availability verifies them against the committed root —
    /// passing for an intact set, failing for a corrupted one.
    #[test]
    fn stage0_shards_persisted_and_local_availability_verifies() {
        let db = temp_db("stage0_da");
        let node_identity = [33u8; 32];
        // Single-node (no peers) → all shards assigned locally.
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let mut seq =
            DASequencer::new_encrypted("test".into(), Arc::clone(&db), peers, &node_identity);

        seq.create_batch("deadbeefroot".into(), 4);
        let epoch = seq.epoch; // create_batch increments then uses self.epoch

        // SEC-#2: shards are actually stored now.
        let stored = (0..32)
            .filter(|id| {
                db.get(&format!("da_shard_{}_{}", epoch, id))
                    .unwrap()
                    .is_some()
            })
            .count();
        assert!(stored > 0, "create_batch must persist da_shard rows (#2)");
        assert!(
            seq.get_commitment(epoch).is_some(),
            "commitment must be stored"
        );

        // SEC-#3: DAS verifies the intact stored shards against the commitment.
        assert_eq!(seq.verify_local_availability(epoch), Ok(true));

        // Corrupt half the shards → the rebuilt tree diverges from the committed
        // root → DAS must now report unavailable.
        for id in 0..16 {
            let k = format!("da_shard_{}_{}", epoch, id);
            if db.get(&k).unwrap().is_some() {
                db.put(&k, &hex::encode(b"corrupted-shard-bytes")).unwrap();
            }
        }
        assert_eq!(
            seq.verify_local_availability(epoch),
            Ok(false),
            "corrupted shards must fail DAS verification (#3)"
        );
    }
}

/// TASK #3 Stage-2: real cross-node Data Availability — serve, request, audit.
#[cfg(test)]
mod stage2_tests {
    use super::*;
    use std::sync::Arc;

    fn temp_db(suffix: &str) -> Arc<StateDB> {
        let path = format!(
            "/tmp/aincore_da_stage2_test_{}_{}",
            std::process::id(),
            suffix
        );
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(StateDB::open(&path).expect("open temp db"))
    }

    /// Seed `epoch` with a fully-available, committed shard set on `db`, exactly
    /// the way `get_shard_proof` reads it back (rebuilds a `MerkleTree` over the
    /// stored shards). Returns the shard count. Deterministic — no erasure /
    /// compression pipeline, so the test is pure-function over fixed bytes.
    fn seed_available_epoch(db: &Arc<StateDB>, epoch: u64, n: usize) -> usize {
        let shards: Vec<Vec<u8>> = (0..n)
            .map(|i| format!("stage2-shard-{}-{}", epoch, i).into_bytes())
            .collect();
        let tree = MerkleTree::new(&shards);
        let root = tree.root();
        for (i, s) in shards.iter().enumerate() {
            db.put(&format!("da_shard_{}_{}", epoch, i), &hex::encode(s))
                .unwrap();
        }
        db.put(&format!("da_commitment_{}", epoch), &hex::encode(root))
            .unwrap();
        db.put(
            &format!("da_meta_{}", epoch),
            &format!("{{\"shards\":{},\"original_size\":0}}", n),
        )
        .unwrap();
        n
    }

    fn make_seq(node_id: &str, db: Arc<StateDB>, identity: u8) -> DASequencer {
        let peers = Arc::new(Mutex::new(HashMap::new()));
        DASequencer::new_encrypted(node_id.into(), db, peers, &[identity; 32])
    }

    /// handle_p2p_message round-trips a ShardRequest → ShardResponse purely
    /// in-process, and the returned (bytes, proof) verify against the
    /// commitment. This is the SERVE path the TCP callback in main.rs invokes.
    #[test]
    fn serve_shard_request_returns_verifiable_response() {
        let db = temp_db("serve");
        let epoch = 7u64;
        seed_available_epoch(&db, epoch, 32);
        let seq = make_seq("server", Arc::clone(&db), 1);

        let req = p2p_protocol::ShardMessage::ShardRequest {
            epoch,
            shard_id: 5,
            requester_id: "client".into(),
        };
        let req_msg = format!("DA_SHARD:{}", req.to_json().unwrap());

        let resp = seq
            .handle_p2p_message(&req_msg)
            .expect("server must answer a known shard request");
        let json = resp.strip_prefix("DA_SHARD:").expect("DA_SHARD prefix");
        let msg = p2p_protocol::ShardMessage::from_json(json).unwrap();

        match msg {
            p2p_protocol::ShardMessage::ShardResponse {
                epoch: e,
                shard_id,
                data,
                merkle_proof,
            } => {
                assert_eq!(e, epoch);
                assert_eq!(shard_id, 5);
                let root = seq.get_commitment(epoch).unwrap();
                assert!(
                    MerkleTree::verify_proof(&data, &merkle_proof, &root, 5),
                    "served shard must verify against the commitment"
                );
            }
            other => panic!("expected ShardResponse, got {}", other.message_type()),
        }
    }

    /// Full two-node round-trip over the encrypted TCP transport: a server
    /// sequencer runs network::start_server (routing DA_SHARD: into
    /// handle_p2p_message, mirroring core/node/src/main.rs); a client sequencer
    /// fetches a shard with fetch_shard_from_peer and the bytes+proof verify.
    #[tokio::test]
    async fn fetch_shard_from_peer_roundtrip() {
        let server_db = temp_db("rt_server");
        let epoch = 11u64;
        seed_available_epoch(&server_db, epoch, 32);
        let server_seq = Arc::new(Mutex::new(make_seq("server", Arc::clone(&server_db), 2)));

        // Bind an ephemeral port for the server.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener); // free it for start_server to re-bind

        // The transport's MitM check requires the server's advertised node_id to
        // equal derive_address(server pubkey) — the production invariant. Derive
        // it from the transport identity key (independent of the DA signing key).
        let server_signing_key = Arc::new(ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]));
        let server_node_id = crypto::derive_address(
            &server_signing_key.verifying_key().to_bytes(),
        )
        .expect("derive server node id");
        let server_peers: network::PeerList = Arc::new(Mutex::new(HashMap::new()));
        let server_seq_cb = Arc::clone(&server_seq);
        let srv_db = Arc::clone(&server_db);

        tokio::spawn(async move {
            network::start_server(
                port,
                server_node_id,
                server_peers,
                srv_db,
                server_signing_key,
                move |msg: String| -> Option<String> {
                    if msg.starts_with("DA_SHARD:") {
                        if let Ok(guard) = server_seq_cb.lock() {
                            return guard.handle_p2p_message(&msg);
                        }
                    }
                    None
                },
            )
            .await;
        });

        // Give the server a moment to bind.
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // Client has NOTHING locally — must fetch from the server.
        let client_db = temp_db("rt_client");
        let client_seq = make_seq("client", client_db, 3);

        let (data, proof) = client_seq
            .fetch_shard_from_peer("127.0.0.1", port, epoch, 9)
            .await
            .expect("client must fetch shard 9 from the server");

        // The client trusts NOTHING from the wire until it verifies against the
        // (independently-known) commitment.
        let root = server_seq.lock().unwrap().get_commitment(epoch).unwrap();
        assert!(
            MerkleTree::verify_proof(&data, &proof, &root, 9),
            "fetched shard must verify against the commitment"
        );
    }

    /// verify_availability_from_peers resolves LOCALLY when the node already has
    /// every shard — no peers needed → Ok(true).
    #[tokio::test]
    async fn availability_local_first_ok() {
        let db = temp_db("avail_local");
        let epoch = 3u64;
        seed_available_epoch(&db, epoch, 32);
        let seq = make_seq("solo", db, 4);

        assert_eq!(
            seq.verify_availability_from_peers(epoch).await,
            Ok(true),
            "all shards local must report available without any peer"
        );
    }

    /// With NO local shards and NO reachable peers, cross-node sampling reports
    /// unavailable (Ok(false)) — and audit_epoch_availability raises the SAFE
    /// alert path: it records a MissingData fraud proof but does NOT halt.
    #[tokio::test]
    async fn availability_unavailable_raises_alert_not_halt() {
        let db = temp_db("avail_missing");
        let epoch = 5u64;
        // Seed commitment + meta but DELETE every shard so nothing is retrievable
        // and there are no peers to fetch from.
        seed_available_epoch(&db, epoch, 32);
        for i in 0..32 {
            db.delete(&format!("da_shard_{}_{}", epoch, i)).unwrap();
        }
        let seq = make_seq("solo", Arc::clone(&db), 5);

        assert_eq!(
            seq.verify_availability_from_peers(epoch).await,
            Ok(false),
            "no shards + no peers must report unavailable"
        );

        // The SAFE gate: returns Ok(false) (does not panic/halt) AND records a
        // MissingData fraud proof for monitoring.
        let audited = seq.audit_epoch_availability(epoch).await;
        assert_eq!(audited, Ok(false), "audit must not halt — returns Ok(false)");
        assert!(
            db.get(&format!("da_fraud_missingdata_{}", epoch))
                .unwrap()
                .is_some(),
            "audit must record a MissingData fraud proof on unavailability"
        );
    }

    /// audit_epoch_availability on an epoch with no commitment is a no-op alert:
    /// it returns Err (unknown epoch) and records NO fraud proof.
    #[tokio::test]
    async fn audit_unknown_epoch_is_noop() {
        let db = temp_db("avail_unknown");
        let seq = make_seq("solo", Arc::clone(&db), 6);
        let epoch = 999u64;

        assert!(
            seq.audit_epoch_availability(epoch).await.is_err(),
            "unknown epoch (no commitment) must Err, not alert"
        );
        assert!(
            db.get(&format!("da_fraud_missingdata_{}", epoch))
                .unwrap()
                .is_none(),
            "unknown epoch must NOT record a fraud proof"
        );
    }
}
