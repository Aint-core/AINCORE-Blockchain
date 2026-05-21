/// Phase 3 / H-03 — Bridge Nonce Replay Protection
///
/// Persists bridge state to disk so that:
///  1. `last_processed_height` survives restarts (no re-scanning old blocks).
///  2. `nonce_counter` survives restarts (no EVM nonce collision).
///  3. `processed_events` acts as a tombstone set: even if a block is
///     re-scanned (e.g. after a crash before height was saved), the same
///     `{sender}:{block_height}:{amount}:{eth_addr}` key cannot be
///     minted twice.
///
/// State file: `./bridge_state.json` (path configurable via env
/// `BRIDGE_STATE_PATH`).
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeState {
    /// Last AINCORE block height fully processed.
    pub last_processed_height: u64,
    /// Monotonically increasing nonce sent to EVM contract.
    pub nonce_counter: u64,
    /// Tombstone set — canonical event keys that have already been minted.
    /// Key format: `{tx_sender}:{block_height}:{amount}:{eth_addr}`
    pub processed_events: HashSet<String>,
}

impl Default for BridgeState {
    fn default() -> Self {
        Self {
            last_processed_height: 0,
            nonce_counter: 0,
            processed_events: HashSet::new(),
        }
    }
}

impl BridgeState {
    fn state_path() -> PathBuf {
        let path = env::var("BRIDGE_STATE_PATH")
            .unwrap_or_else(|_| "./bridge_state.json".to_string());
        PathBuf::from(path)
    }

    /// Load state from disk (default path from env), or return default.
    pub fn load() -> Self {
        Self::load_from(&Self::state_path())
    }

    /// Load state from an explicit path (used in tests for isolation).
    pub fn load_from(path: &PathBuf) -> Self {
        match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str::<BridgeState>(&json) {
                Ok(state) => {
                    info!(
                        "📂 [H-03] Loaded bridge state: height={}, nonce={}, seen_events={}",
                        state.last_processed_height,
                        state.nonce_counter,
                        state.processed_events.len()
                    );
                    state
                }
                Err(e) => {
                    warn!(
                        "⚠️  [H-03] Bridge state file malformed ({}), starting fresh",
                        e
                    );
                    BridgeState::default()
                }
            },
            Err(_) => {
                info!("📂 [H-03] No bridge state at {:?}, starting from genesis", path);
                BridgeState::default()
            }
        }
    }

    /// Persist state to disk atomically (write to tmp → rename).
    pub fn save(&self) {
        self.save_to(&Self::state_path());
    }

    /// Save to an explicit path (used in tests for isolation).
    pub fn save_to(&self, path: &PathBuf) {
        let tmp = path.with_extension("json.tmp");

        match serde_json::to_string_pretty(self) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&tmp, &json) {
                    error!("❌ [H-03] Failed to write bridge state tmp: {}", e);
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, path) {
                    error!("❌ [H-03] Failed to rename bridge state: {}", e);
                }
            }
            Err(e) => error!("❌ [H-03] Failed to serialise bridge state: {}", e),
        }
    }

    /// Build the canonical event key for deduplication.
    /// Includes sender + amount + eth_addr + block_height for uniqueness.
    pub fn event_key(sender: &str, amount: u64, eth_addr: &str, block_height: u64) -> String {
        format!("{}:{}:{}:{}", sender, amount, eth_addr, block_height)
    }

    /// Returns `true` if this event has already been processed (replay).
    pub fn is_seen(&self, key: &str) -> bool {
        self.processed_events.contains(key)
    }

    /// Mark event as processed and increment nonce.
    /// Caller must call `save()` after processing the batch.
    pub fn mark_processed(&mut self, key: String) -> u64 {
        self.nonce_counter += 1;
        self.processed_events.insert(key);
        self.nonce_counter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(suffix: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("bridge_state_test_{}_{}.json", std::process::id(), suffix));
        p
    }

    #[test]
    fn test_h03_nonce_survives_restart() {
        let path = tmp_path("nonce_restart");
        let _ = std::fs::remove_file(&path);

        let mut state = BridgeState::load_from(&path);
        assert_eq!(state.nonce_counter, 0);
        let n1 = state.mark_processed(BridgeState::event_key("alice", 100, "0xABCD", 5));
        assert_eq!(n1, 1);
        state.last_processed_height = 5;
        state.save_to(&path);

        let state2 = BridgeState::load_from(&path);
        assert_eq!(state2.nonce_counter, 1, "nonce must survive restart");
        assert_eq!(state2.last_processed_height, 5, "height must survive restart");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_h03_replay_detected() {
        let path = tmp_path("replay");
        let _ = std::fs::remove_file(&path);

        let mut state = BridgeState::load_from(&path);
        let key = BridgeState::event_key("bob", 200, "0x1234", 10);

        assert!(!state.is_seen(&key));
        state.mark_processed(key.clone());
        assert!(state.is_seen(&key), "same event must be detected as replay");

        state.save_to(&path);
        let state2 = BridgeState::load_from(&path);
        assert!(state2.is_seen(&key), "replay detection must survive restart");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_h03_different_events_not_blocked() {
        let path = tmp_path("diff_events");
        let _ = std::fs::remove_file(&path);

        let mut state = BridgeState::load_from(&path);
        let k1 = BridgeState::event_key("alice", 100, "0xAA", 1);
        let k2 = BridgeState::event_key("alice", 100, "0xAA", 2);
        let k3 = BridgeState::event_key("bob", 100, "0xAA", 1);

        state.mark_processed(k1);
        assert!(!state.is_seen(&k2), "different block height = different event");
        assert!(!state.is_seen(&k3), "different sender = different event");

        let _ = std::fs::remove_file(&path);
    }
}
