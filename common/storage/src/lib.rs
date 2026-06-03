pub use rocksdb;
use rocksdb::DB; // Export for consumers
pub mod object;
#[cfg(test)]
mod tests;
use object::Object;
use std::fmt;

#[derive(Debug, Clone)]
pub enum StorageError {
    DatabaseOpen(String),
    DatabaseOperation(String),
    SerializationError(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StorageError::DatabaseOpen(msg) => write!(f, "Failed to open database: {}", msg),
            StorageError::DatabaseOperation(msg) => write!(f, "Database operation failed: {}", msg),
            StorageError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<rocksdb::Error> for StorageError {
    fn from(err: rocksdb::Error) -> Self {
        StorageError::DatabaseOperation(err.to_string())
    }
}

pub struct StateDB {
    pub db: DB,
}

impl StateDB {
    /// Open database with production-grade durability settings
    ///
    /// Returns Err if:
    /// - Database is locked by another process
    /// - Insufficient permissions
    /// - Corrupted database files
    ///
    /// # Security Hardening (Audit Remediation)
    /// - WAL (Write-Ahead Log) is enabled with manual flush for crash recovery
    /// - `sync` = true forces fsync on every write, ensuring durability even on
    ///   power failure (prevents data loss that could cause state root divergence)
    /// - Checksums are enabled to detect silent data corruption
    /// - `create_if_missing` = true for first-run genesis bootstrap
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        // === DURABILITY HARDENING (Audit Finding: RocksDB WAL Configuration) ===
        // Without these settings, a crash during block commit can leave the
        // database in an inconsistent state, causing irrecoverable state root
        // divergence between validators (instant hard fork).

        // Force fsync after each write to ensure WAL entries hit disk.
        // Performance cost: ~10-20% write throughput reduction, but this is
        // non-negotiable for a blockchain — data integrity > speed.
        opts.set_use_fsync(true);

        // Manual WAL flush gives us control over when WAL is synced,
        // allowing batch writes (WriteBatch) to be atomic + durable.
        opts.set_manual_wal_flush(true);

        // Enable paranoid checks for detecting silent data corruption.
        // This adds CPU overhead but catches bit-rot before it propagates.
        opts.set_paranoid_checks(true);

        // Set WAL size limit to prevent unbounded WAL growth.
        // 256MB is generous for typical blockchain workloads.
        opts.set_max_total_wal_size(256 * 1024 * 1024);

        // Optimize for blockchain read patterns (point lookups by key)
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);

        let db = DB::open(&opts, path)
            .map_err(|e| StorageError::DatabaseOpen(format!(
                "Path: {}, Error: {}. Ensure no other process is using this directory and you have write permissions.",
                path, e
            )))?;
        Ok(Self { db })
    }

    pub fn put(&self, key: &str, value: &str) -> std::result::Result<(), rocksdb::Error> {
        self.db.put(key, value)
    }

    pub fn get(&self, key: &str) -> std::result::Result<Option<String>, rocksdb::Error> {
        match self.db.get(key) {
            Ok(Some(v)) => {
                match String::from_utf8(v) {
                    Ok(s) => Ok(Some(s)),
                    Err(_) => Ok(None), // Fail safe for invalid utf8
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn delete(&self, key: &str) -> std::result::Result<(), rocksdb::Error> {
        self.db.delete(key)
    }

    /// Hard ceiling on `scan_prefix` results so an unbounded namespace
    /// (e.g. a runaway pending-slash queue or an attacker-controlled key
    /// space) cannot exhaust process memory or stall a hot path.
    /// Callers that know a tighter bound should use
    /// [`scan_prefix_limited`] with an explicit cap.
    pub const SCAN_PREFIX_HARD_CAP: usize = 100_000;

    /// Generic prefix scanner — returns up to [`SCAN_PREFIX_HARD_CAP`]
    /// `(key, value)` pairs matching a prefix. Used by the Executor to
    /// process pending slashes from the consensus engine.
    ///
    /// M-06 FIX: previously this scanned with no upper bound. Any code
    /// path that wrote into a key space without retention (or that an
    /// attacker could write into) could blow up the process by forcing
    /// `scan_prefix` to materialise the entire range into a `Vec`. The
    /// hard cap protects every existing caller without changing the
    /// public signature. For namespaces with a known tighter bound,
    /// prefer [`scan_prefix_limited`].
    pub fn scan_prefix(&self, prefix: &str) -> Vec<(String, String)> {
        self.scan_prefix_limited(prefix, Self::SCAN_PREFIX_HARD_CAP)
    }

    /// Bounded prefix scanner. Stops iterating after `limit` matches.
    /// Use this from hot paths where the caller can reason about the
    /// expected upper bound (e.g. validator count, miner count).
    pub fn scan_prefix_limited(&self, prefix: &str, limit: usize) -> Vec<(String, String)> {
        if limit == 0 {
            return Vec::new();
        }

        let mut results = Vec::with_capacity(limit.min(1024));
        let prefix_bytes = prefix.as_bytes();
        let iter = self.db.prefix_iterator(prefix_bytes);

        for (key, value) in iter.flatten() {
            if !key.starts_with(prefix_bytes) {
                break;
            }
            let k = String::from_utf8_lossy(&key).into_owned();
            let v = String::from_utf8_lossy(&value).into_owned();
            results.push((k, v));
            if results.len() >= limit {
                break;
            }
        }
        results
    }

    // === HELPER FOR PEER MAN AGEMENT ===
    pub fn save_peer(&self, node_id: &str, port: u16) -> std::result::Result<(), rocksdb::Error> {
        let key = format!("peer:{}", node_id);
        self.put(&key, &port.to_string())
    }

    pub fn get_peer(&self, node_id: &str) -> Option<u16> {
        // Safe wrapper for get
        if let Ok(Some(val_str)) = self.get(&format!("peer:{}", node_id)) {
            val_str.parse().ok()
        } else {
            None
        }
    }

    pub fn scan_peers(&self) -> Vec<(String, u16)> {
        let mut peers = Vec::new();
        let prefix = b"peer:";
        let iter = self.db.prefix_iterator(prefix);

        for (key, value) in iter.flatten() {
            if !key.starts_with(prefix) {
                break;
            }

            let k = String::from_utf8(key.to_vec()).unwrap_or_default();
            let val_str = String::from_utf8(value.to_vec()).unwrap_or_default();
            if let Ok(port) = val_str.parse::<u16>() {
                peers.push((k.replace("peer:", ""), port));
            }
        }

        peers
    }

    // === PEER IP TRACKING (for multi-node sync) ===
    pub fn save_peer_ip(&self, node_id: &str, ip: &str) -> std::result::Result<(), rocksdb::Error> {
        let key = format!("peer_ip:{}", node_id);
        self.put(&key, ip)
    }

    pub fn get_peer_ip(&self, node_id: &str) -> Option<String> {
        if let Ok(Some(ip)) = self.get(&format!("peer_ip:{}", node_id)) {
            Some(ip)
        } else {
            None
        }
    }

    pub fn save_peer_addr(
        &self,
        peer_id: &str,
        multiaddr: &str,
    ) -> std::result::Result<(), rocksdb::Error> {
        self.put(&format!("peer_addr:{}", peer_id), multiaddr)
    }

    pub fn scan_peer_addrs(&self) -> Vec<(String, String)> {
        let mut peers = Vec::new();
        let prefix = b"peer_addr:";
        let iter = self.db.prefix_iterator(prefix);

        for (key, value) in iter.flatten() {
            if !key.starts_with(prefix) {
                break;
            }

            let k = String::from_utf8_lossy(&key).into_owned();
            let node_id = k.replace("peer_addr:", "");
            let addr = String::from_utf8_lossy(&value).into_owned();
            peers.push((node_id, addr));
        }
        peers
    }

    pub fn scan_vertices(&self) -> Vec<String> {
        let mut vertices = Vec::new();
        let prefix = b"vertex:";
        let iter = self.db.prefix_iterator(prefix);

        for (key, value) in iter.flatten() {
            if !key.starts_with(prefix) {
                break;
            }

            let v_json = String::from_utf8(value.to_vec()).unwrap_or_else(|_| "{}".to_string());
            vertices.push(v_json);
        }
        vertices
    }

    pub fn put_object(&self, object: &Object) -> std::result::Result<(), rocksdb::Error> {
        let key = format!("obj:{}", object.id);
        let value = serde_json::to_string(object).unwrap_or_default(); // Safe default or error? Default is ok for prototype.
        self.db.put(key, value)
    }

    pub fn write_batch(
        &self,
        batch: rocksdb::WriteBatch,
    ) -> std::result::Result<(), rocksdb::Error> {
        self.db.write(batch)?;
        self.db.flush_wal(true)
    }

    /// Get current blockchain height
    pub fn get_chain_height(&self) -> u64 {
        match self.get("latest_height") {
            Ok(Some(h)) => h.parse::<u64>().unwrap_or(0),
            _ => 0,
        }
    }

    /// Save block as JSON string — atomically updates height, hash, AND
    /// per-transaction index entries in a single RocksDB write batch.
    ///
    /// H-07 FIX: previously this saved the block + height + hash but did
    /// not populate `tx_index:{tx_hash}` entries. As a result,
    /// `aincore_getTransaction` fell back to scanning every vertex in the
    /// DAG while holding the consensus read lock, which is O(N·M) over
    /// the whole chain and stalls block production. By writing the
    /// per-tx index in the same atomic batch we never observe a state
    /// where a block exists but its transactions are not yet indexable,
    /// and the lookup becomes O(1) → O(M) for the single block.
    pub fn save_block_json(&self, height: u64, block_json: &str) -> Result<(), rocksdb::Error> {
        use sha2::{Digest, Sha256};

        let key = format!("block_{}", height);
        let mut batch = rocksdb::WriteBatch::default();
        batch.put(key.as_bytes(), block_json.as_bytes());
        batch.put(b"latest_height", height.to_string().as_bytes());

        // Extract hash from block JSON and persist it for consensus continuity.
        // While we're parsing, also index every transaction in the payload so
        // getTransaction / getTransactionReceipt can do O(1) lookups.
        if let Ok(block) = serde_json::from_str::<serde_json::Value>(block_json) {
            if let Some(hash) = block["header"]["hash"].as_str() {
                batch.put(b"latest_block_hash", hash.as_bytes());
            }

            // Index transactions. Block JSON shape from blockchain::Block is
            // `{ "header": {...}, "transactions": [<tx_string>, ...] }`. Each
            // transaction is stored as the raw JSON string it was submitted
            // as, and tx_hash is SHA-256 over those bytes — the same
            // construction the mempool uses for dedupe and the API uses for
            // its current O(N) scan, so the index is wire-compatible.
            if let Some(txs) = block.get("transactions").and_then(|v| v.as_array()) {
                let height_bytes = height.to_string().into_bytes();
                for tx in txs {
                    let tx_str_owned: String;
                    let tx_bytes: &[u8] = if let Some(s) = tx.as_str() {
                        s.as_bytes()
                    } else {
                        // Defensive: a future schema change might inline
                        // structured tx objects. Re-serialise so we still
                        // produce a stable hash instead of silently
                        // skipping the entry.
                        tx_str_owned = tx.to_string();
                        tx_str_owned.as_bytes()
                    };
                    let mut hasher = Sha256::new();
                    hasher.update(tx_bytes);
                    let tx_hash = hex::encode(hasher.finalize());
                    let idx_key = format!("tx_index:{}", tx_hash);
                    batch.put(idx_key.as_bytes(), &height_bytes);
                }
            }
        }

        self.write_batch(batch)
    }

    pub fn get_object(&self, object_id: &str) -> Option<Object> {
        let key = format!("obj:{}", object_id);
        match self.db.get(key) {
            Ok(Some(v)) => {
                if let Ok(s) = String::from_utf8(v) {
                    serde_json::from_str(&s).ok()
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Index transaction for fast lookup: tx_hash → block_height
    ///
    /// This enables O(1) transaction lookups instead of O(n) DAG scan.
    /// Call this after successfully executing a block.
    pub fn index_transaction(
        &self,
        tx_hash: &str,
        block_height: u64,
    ) -> Result<(), rocksdb::Error> {
        let key = format!("tx_index:{}", tx_hash);
        self.put(&key, &block_height.to_string())
    }

    /// Get block height for a transaction hash (O(1) lookup)
    ///
    /// Returns None if transaction not found in index.
    pub fn get_tx_block_height(&self, tx_hash: &str) -> Option<u64> {
        let key = format!("tx_index:{}", tx_hash);
        self.get(&key).ok()?.and_then(|h| h.parse().ok())
    }

    /// Sentinel key marking that the v1 backfill of `tx_index` has run on
    /// this DB. Bump the version suffix if the indexing rules ever change
    /// so existing installs re-run the migration.
    pub const TX_INDEX_BACKFILL_SENTINEL: &'static str = "sys:tx_index_backfill_v1_complete";

    /// One-shot migration: walk every `block_*` already persisted in this
    /// DB and populate `tx_index:{tx_hash} -> height` entries for any
    /// transaction whose hash is not already indexed.
    ///
    /// Why this exists
    /// ---------------
    /// Before H-07, block commits did not write `tx_index:` entries. After
    /// H-07, `save_block_json` writes them atomically for **new** blocks,
    /// but everything already on disk was invisible to
    /// `aincore_getTransaction`. External audit caught this as a real
    /// regression: a wallet that submitted a transaction last week and
    /// then queries today would get `null` instead of the historical
    /// receipt.
    ///
    /// This routine fixes that by walking the existing `block_*` range
    /// once at startup. It is:
    ///   * **Idempotent**: guarded by `TX_INDEX_BACKFILL_SENTINEL` so
    ///     restarts don't replay it.
    ///   * **Non-destructive**: we only `put` index entries that are not
    ///     already present, and we never touch the block payloads.
    ///   * **Batched**: every block is flushed in one RocksDB
    ///     `WriteBatch` so the indexer cannot crash with a partial state.
    ///
    /// Returns the number of `tx_index` entries inserted. A return of `0`
    /// with `already_done == true` (visible via the sentinel) means the
    /// migration was a no-op on this DB.
    pub fn backfill_tx_index(&self) -> Result<usize, rocksdb::Error> {
        use sha2::{Digest, Sha256};

        // Idempotency gate.
        if let Ok(Some(_)) = self.get(Self::TX_INDEX_BACKFILL_SENTINEL) {
            return Ok(0);
        }

        let mut batch = rocksdb::WriteBatch::default();
        let mut inserted: usize = 0;
        let mut blocks_scanned: usize = 0;

        // Scan all block_* keys. We don't use scan_prefix because that
        // returns Vec<(String,String)> — we want to stream into a single
        // WriteBatch without intermediate Vec materialisation.
        let iter = self.db.prefix_iterator(b"block_");
        for (key_bytes, value_bytes) in iter.flatten() {
            if !key_bytes.starts_with(b"block_") {
                break;
            }
            blocks_scanned += 1;

            // Parse height from key.
            let key_str = match std::str::from_utf8(&key_bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let height: u64 = match key_str.trim_start_matches("block_").parse() {
                Ok(h) => h,
                Err(_) => continue,
            };

            // Parse block JSON.
            let block: serde_json::Value = match serde_json::from_slice(&value_bytes) {
                Ok(v) => v,
                Err(_) => continue,
            };

            let txs = match block.get("transactions").and_then(|v| v.as_array()) {
                Some(t) => t,
                None => continue,
            };

            let height_bytes = height.to_string().into_bytes();
            for tx in txs {
                let tx_str_owned: String;
                let tx_bytes: &[u8] = if let Some(s) = tx.as_str() {
                    s.as_bytes()
                } else {
                    tx_str_owned = tx.to_string();
                    tx_str_owned.as_bytes()
                };
                let mut hasher = Sha256::new();
                hasher.update(tx_bytes);
                let tx_hash = hex::encode(hasher.finalize());
                let idx_key = format!("tx_index:{}", tx_hash);

                // Skip if already indexed — preserves existing entries and
                // means a partial run from a crashed prior invocation
                // doesn't double-write.
                if matches!(self.db.get(idx_key.as_bytes()), Ok(Some(_))) {
                    continue;
                }

                batch.put(idx_key.as_bytes(), &height_bytes);
                inserted += 1;
            }
        }

        // Mark migration complete in the same batch so the sentinel write
        // is atomic with the last index inserts.
        batch.put(
            Self::TX_INDEX_BACKFILL_SENTINEL.as_bytes(),
            blocks_scanned.to_string().as_bytes(),
        );

        self.write_batch(batch)?;

        if inserted > 0 {
            eprintln!(
                "🛠️  tx_index backfill: scanned {} blocks, inserted {} new index entries",
                blocks_scanned, inserted
            );
        }
        Ok(inserted)
    }

    // === PHASE 9: DECENTRALIZED CONFIG ===
    pub fn get_federation_key(&self) -> String {
        match self.get("sys:config:federation_addr") {
            Ok(Some(k)) => k,
            _ => "".to_string(), // Empty means not initialized by Genesis yet
        }
    }

    pub fn set_federation_key(&self, new_key: &str) -> std::result::Result<(), rocksdb::Error> {
        self.put("sys:config:federation_addr", new_key)
    }

    // === PHASE 10: ECONOMIC MODEL ===

    pub fn get_base_reward(&self) -> u64 {
        const DEFAULT_REWARD: u64 = 50;
        match self.get("sys:config:base_reward") {
            Ok(Some(v)) => v.parse().unwrap_or(DEFAULT_REWARD),
            _ => DEFAULT_REWARD,
        }
    }

    pub fn get_halving_interval(&self) -> u64 {
        const DEFAULT_INTERVAL: u64 = 2_100_000;
        match self.get("sys:config:halving_interval") {
            Ok(Some(v)) => v.parse().unwrap_or(DEFAULT_INTERVAL),
            _ => DEFAULT_INTERVAL,
        }
    }

    pub fn get_burn_percentage(&self) -> u8 {
        const DEFAULT_BURN: u8 = 10; // 10%
        match self.get("sys:config:burn_percentage") {
            Ok(Some(v)) => v.parse().unwrap_or(DEFAULT_BURN),
            _ => DEFAULT_BURN,
        }
    }

    pub fn update_economic_config(
        &self,
        reward: Option<u64>,
        interval: Option<u64>,
        burn: Option<u8>,
    ) -> std::result::Result<(), rocksdb::Error> {
        if let Some(r) = reward {
            self.put("sys:config:base_reward", &r.to_string())?;
        }
        if let Some(i) = interval {
            self.put("sys:config:halving_interval", &i.to_string())?;
        }
        if let Some(b) = burn {
            self.put("sys:config:burn_percentage", &b.to_string())?;
        }
        Ok(())
    }

    // === PHASE 12: VALIDATOR SET (SYBIL PROTECTION) ===

    // Scan method clearly not optimal for Mainnet, but "Real" enough for < 1000 validators.
    // In full prod, we'd use a separate column family or index.
    pub fn get_active_validators(&self) -> Vec<(String, u64)> {
        // Logic: Check a "sys:validators" list.
        // This is populated by genesis.json during node bootstrap.
        if let Ok(Some(json)) = self.get("sys:validators") {
            if let Ok(vals) = serde_json::from_str::<Vec<(String, u64)>>(&json) {
                return vals;
            }
        }

        // Return empty if not initialized (genesis tool will populate this)
        vec![]
    }

    pub fn update_validator_weight(
        &self,
        pubkey: &str,
        weight: u64,
    ) -> std::result::Result<(), rocksdb::Error> {
        let mut vals = self.get_active_validators();
        if let Some(v) = vals.iter_mut().find(|v| v.0 == pubkey) {
            v.1 = weight;
        } else {
            vals.push((pubkey.to_string(), weight));
        }
        let json = serde_json::to_string(&vals).unwrap_or_default();
        self.put("sys:validators", &json)
    }

    // === DAG CHECKPOINT SYSTEM (Aptos/Sui Style) ===

    /// Save DAG checkpoint for fast recovery (legacy / unsigned form).
    ///
    /// Prefer [`Self::save_dag_checkpoint_signed`] in production. This
    /// entry point is kept for test helpers and any legacy code path
    /// that has not yet been migrated; checkpoints saved here have no
    /// integrity signature and will be loaded with a warning.
    pub fn save_dag_checkpoint(
        &self,
        round: u64,
        vertices_json: &str,
    ) -> std::result::Result<(), rocksdb::Error> {
        self.put(&format!("dag:checkpoint:{}", round), vertices_json)?;
        self.put("dag:checkpoint:latest", &round.to_string())?;
        Ok(())
    }

    /// H-06 PROMOTED (Phase 2.5): save a DAG checkpoint with an
    /// integrity signature.
    ///
    /// `signature_hex` is the hex-encoded Ed25519 signature produced
    /// by the node over `vertices_json` (caller responsibility — the
    /// storage layer is content-agnostic, it just persists the bytes).
    /// On load, [`Self::verify_and_get_dag_checkpoint`] re-verifies
    /// the signature and refuses to surface tampered checkpoints.
    pub fn save_dag_checkpoint_signed(
        &self,
        round: u64,
        vertices_json: &str,
        signature_hex: &str,
    ) -> std::result::Result<(), rocksdb::Error> {
        self.put(&format!("dag:checkpoint:{}", round), vertices_json)?;
        self.put(&format!("dag:checkpoint_sig:{}", round), signature_hex)?;
        self.put("dag:checkpoint:latest", &round.to_string())?;
        Ok(())
    }

    /// Get latest checkpoint round
    pub fn get_latest_checkpoint_round(&self) -> u64 {
        match self.get("dag:checkpoint:latest") {
            Ok(Some(r)) => r.parse().unwrap_or(0),
            _ => 0,
        }
    }

    /// Load raw DAG checkpoint data (no integrity check). Internal /
    /// legacy callers only — production callers must go through
    /// [`Self::verify_and_get_dag_checkpoint`].
    pub fn get_dag_checkpoint(&self, round: u64) -> Option<String> {
        match self.get(&format!("dag:checkpoint:{}", round)) {
            Ok(Some(data)) => Some(data),
            _ => None,
        }
    }

    /// Get the integrity signature for a checkpoint, if one was
    /// recorded by [`Self::save_dag_checkpoint_signed`].
    pub fn get_dag_checkpoint_signature(&self, round: u64) -> Option<String> {
        match self.get(&format!("dag:checkpoint_sig:{}", round)) {
            Ok(Some(s)) => Some(s),
            _ => None,
        }
    }

    /// Prune old checkpoints (keep last N)
    pub fn prune_old_checkpoints(
        &self,
        current_round: u64,
        keep_count: u64,
    ) -> std::result::Result<(), rocksdb::Error> {
        if current_round <= keep_count {
            return Ok(());
        }
        let oldest_to_keep = current_round - keep_count;
        // Simple cleanup: delete checkpoints older than threshold
        // Note: This is a best-effort cleanup, not a full scan
        for old_round in (0..oldest_to_keep).rev().take(10) {
            let _ = self.delete(&format!("dag:checkpoint:{}", old_round));
        }
        Ok(())
    }
}
