use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use chrono::Utc;
use storage::StateDB;
use network::send_message;

/// Representasi data batch dalam DA Layer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DABatch {
    pub epoch: u64,
    pub root_hash: String,
    pub tx_count: usize,
    pub proposer_id: String,
    pub timestamp: i64,
}

// === CELESTIA INTEGRATION ===
pub struct CelestiaClient {
    pub rpc_url: String,
    pub auth_token: String,
}

impl CelestiaClient {
    pub fn new(rpc_url: String, auth_token: String) -> Self {
        Self { rpc_url, auth_token }
    }

    pub fn submit_blob(&self, namespace_hex: &str, data: &[u8]) -> Result<(u64, String), String> {
        use celestia_rpc::{BlobClient, Client};
        use celestia_types::{nmt::Namespace, Blob, AppVersion};
        use tokio::runtime::Runtime;


        // Create a separate thread to run the async runtime.
        // This avoids "Cannot start a runtime from within a runtime" panic.
        let rpc_url = self.rpc_url.clone();
        let auth_token = self.auth_token.clone();
        let namespace_hex = namespace_hex.to_string();
        let data = data.to_vec();

        std::thread::spawn(move || {
            let rt = Runtime::new().map_err(|e| format!("Failed to create runtime: {}", e))?;

            rt.block_on(async {
                // 1. Initialize Client
                let client = Client::new(&rpc_url, Some(&auth_token))
                    .await
                    .map_err(|e| format!("Failed creating RPC client: {}", e))?;

                // 2. Prepare Namespace
                let input_bytes = hex::decode(&namespace_hex).unwrap_or_default();
                let namespace = Namespace::new_v0(&input_bytes)
                    .map_err(|e| format!("Invalid namespace: {}", e))?;

                // 3. Create Blob
                // Blob::new(namespace, data, signer, app_version)
                let blob = Blob::new(namespace, data, None, AppVersion::V1)
                    .map_err(|e| format!("Blob creation failed: {}", e))?;

                println!("🌌 [Celestia Client] Submitting blob via Official Client to {}...", rpc_url);

                // 4. Submit Blob
                // Using Default::default() to force compiler to tell us the type
                let height = client.blob_submit(&[blob.clone()], Default::default())
                    .await
                    .map_err(|e| format!("Failed submitting blob: {}", e))?;

                // 5. Return Result
                // Commitment: use serde_json as fallback
                let commitment = serde_json::to_string(&blob.commitment).unwrap_or_default();
                
                Ok((height, commitment))
            })
        }).join().map_err(|_| "Thread panicked".to_string())?
    }
}

/// Sequencer utama untuk Data Availability
pub struct DASequencer {
    pub node_id: String,
    pub epoch: u64,
    pub batches: Arc<Mutex<HashMap<u64, DABatch>>>,
    pub storage: Arc<StateDB>,
    pub peers: Arc<Mutex<HashMap<String, u16>>>,
    pub celestia_client: Option<CelestiaClient>,
}

impl DASequencer {
    /// Inisialisasi DA Sequencer
    pub fn new(node_id: String, storage: Arc<StateDB>, peers: Arc<Mutex<HashMap<String, u16>>>) -> Self {
        println!("⚙️ Initializing Data Availability Sequencer...");
        
        let da_layer = std::env::var("DA_LAYER").unwrap_or_else(|_| "NATIVE".to_string());
        let mut celestia_client = None;

        if da_layer == "CELESTIA" {
            let rpc_url = std::env::var("CELESTIA_RPC").unwrap_or_else(|_| "http://localhost:26659".to_string());
            let auth_token = std::env::var("CELESTIA_AUTH_TOKEN").unwrap_or_else(|_| "".to_string());
            
            if auth_token.is_empty() {
                println!("⚠️ [DA Sequencer] CELESTIA_AUTH_TOKEN not set. Blob submission will likely fail.");
            } else {
                println!("🌌 [DA Sequencer] Celestia Mode ENABLED. Connected to {}", rpc_url);
                celestia_client = Some(CelestiaClient::new(rpc_url, auth_token));
            }
        } else {
            println!("🏰 [DA Sequencer] Sovereign Native Mode ENABLED. Using internal storage (RocksDB).");
        }

        Self {
            node_id,
            epoch: 0,
            batches: Arc::new(Mutex::new(HashMap::new())),
            storage,
            peers,
            celestia_client,
        }
    }

    /// Membuat DA batch baru setiap kali ada blok yang berhasil di-commit
    pub fn create_batch(&mut self, root_hash: String, tx_count: usize) {
        self.epoch += 1;
        let batch = DABatch {
            epoch: self.epoch,
            root_hash: root_hash.clone(),
            tx_count,
            proposer_id: self.node_id.clone(),
            timestamp: Utc::now().timestamp(),
        };

        // Serialize batch for submission
        let batch_json = match serde_json::to_string(&batch) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("❌ [DA Sequencer] Failed to serialize batch: {}", e);
                return;
            }
        };
        
        // 1. Submit to Celestia (If Enabled)
        if let Some(client) = &self.celestia_client {
            // Namespace ID for AINCORE (random hex for now)
            let namespace_id = "0000000000000001"; 
            match client.submit_blob(namespace_id, batch_json.as_bytes()) {
                Ok((height, commitment)) => {
                    println!("✅ [DA Sequencer] Batch stored on Celestia! Height: {}, Commitment: {}", height, commitment);
                }
                Err(e) => {
                    eprintln!("❌ [DA Sequencer] Failed to submit to Celestia: {}", e);
                }
            }
        } else {
            // Native Mode
            println!("✅ [DA Sequencer] Batch stored locally (Sovereign Mode). Root: {}", root_hash);
        }

        println!("🧩 [DA Sequencer] Created batch epoch={} root={}", self.epoch, root_hash);

        // Simpan ke persistent storage
        let key = format!("da_root_{}", self.epoch);
        let _ = self.storage.put(&key, &batch_json);

        // Simpan ke cache memory
        if let Ok(mut batches) = self.batches.lock() {
            batches.insert(self.epoch, batch.clone());
        }

        // Broadcast batch ke seluruh peers
        self.broadcast_batch(batch);
    }

    /// Broadcast DA batch ke seluruh peers
    fn broadcast_batch(&self, batch: DABatch) {
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

        for (_peer_id, port) in peers_snapshot.iter() {
            let addr = format!("127.0.0.1:{}", port);
            match send_message(&addr, &full_msg) {
                Ok(_) => println!("📤 Sent DA_COMMIT to {}", addr),
                Err(e) => eprintln!("❌ Failed to send DA_COMMIT to {}: {}", addr, e),
            }
        }
    }

    /// Sinkronisasi batch DA dari peer lain
    pub fn handle_incoming_batch(&self, raw_msg: &str) {
        if let Ok(batch) = serde_json::from_str::<DABatch>(raw_msg) {
            println!(
                "📥 [DA Sequencer] Received DA_COMMIT epoch={} from {}",
                batch.epoch, batch.proposer_id
            );

            // Simpan ke RocksDB
            let key = format!("da_root_{}", batch.epoch);
            if let Ok(val) = serde_json::to_string(&batch) {
                let _ = self.storage.put(&key, &val);
            }

            // Simpan ke cache in-memory
            if let Ok(mut batches) = self.batches.lock() {
                batches.insert(batch.epoch, batch);
            }
        } else {
            eprintln!("⚠️ [DA Sequencer] Invalid DA_COMMIT payload: {}", raw_msg);
        }
    }
}
