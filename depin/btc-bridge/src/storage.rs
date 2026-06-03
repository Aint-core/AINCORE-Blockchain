/// Phase 5.1 / H-03 BTC port — Bridge Replay Protection (SCOPE: replay only).
///
/// ⚠️  HONEST SCOPE — what this port DOES and DOES NOT achieve vs the
/// EVM bridge:
///
/// ## DOES (replay-protection parity):
///   1. Atomic save: write to `*.tmp` then rename — crash-safe (no
///      partial JSON file on disk).
///   2. Tombstone-before-mint flow: caller marks a deposit `InProgress`
///      BEFORE attempting the wBTC mint. On crash between mint and
///      "completed" mark, the operator sees an InProgress entry and
///      can investigate; automatic retry will NOT re-mint (tombstone
///      already exists).
///   3. Legacy `HashSet<String>` state file migrates one-shot to the
///      new schema on boot.
///
/// ## DOES NOT (NOT full EVM-bridge feature parity):
///   - No range-based block scanning. `last_seen_height` is stored
///     but currently INFORMATIONAL ONLY — the upstream blockchain.info
///     API does not expose `getBlocksInRange(start, end)`, so the
///     scanner still re-reads the full address history each cycle and
///     relies on tx-hash dedup for correctness. The EVM bridge has
///     this through `aincore_getBlocks(limit, start_height)`; BTC
///     does not, yet.
///   - No multisig (C-02 scope, deferred).
///
/// State file: `./processed_txs.json` (path configurable in `Storage::new`).
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DepositStatus {
    /// Mint has been attempted; if process crashes here, operator must
    /// investigate before re-running (do NOT re-mint automatically).
    InProgress,
    /// Mint completed successfully.
    Completed,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
struct PersistedState {
    /// tx_hash → DepositStatus
    deposits: HashMap<String, DepositStatus>,
    /// Highest BTC block height we have ever observed a finalized deposit at.
    /// Informational — not used to skip scans (blockchain.info has no range).
    last_seen_height: u64,
}

pub struct Storage {
    path: PathBuf,
    state: PersistedState,
}

impl Storage {
    pub fn new(path: &str) -> Self {
        let path_buf = PathBuf::from(path);
        let state = Self::load(&path_buf).unwrap_or_default();
        if !state.deposits.is_empty() {
            let in_progress = state
                .deposits
                .values()
                .filter(|s| **s == DepositStatus::InProgress)
                .count();
            println!(
                "📂 [BTC H-03] Loaded {} deposits ({} in_progress), last_seen_height={}",
                state.deposits.len(),
                in_progress,
                state.last_seen_height
            );
            if in_progress > 0 {
                eprintln!(
                    "⚠️  [BTC H-03] {} deposits in InProgress state — \
                     a prior run crashed between mint attempt and confirmation. \
                     Operator must investigate before next mint cycle.",
                    in_progress
                );
            }
        }
        Self {
            path: path_buf,
            state,
        }
    }

    fn load(path: &Path) -> Option<PersistedState> {
        let content = fs::read_to_string(path).ok()?;
        // New format
        if let Ok(s) = serde_json::from_str::<PersistedState>(&content) {
            return Some(s);
        }
        // Legacy format: plain `HashSet<String>` of processed tx hashes.
        // One-shot migrate to the new schema with Completed status.
        if let Ok(legacy) = serde_json::from_str::<std::collections::HashSet<String>>(&content) {
            let deposits = legacy
                .into_iter()
                .map(|h| (h, DepositStatus::Completed))
                .collect();
            return Some(PersistedState {
                deposits,
                last_seen_height: 0,
            });
        }
        None
    }

    /// Returns true if the tx has any record (in_progress OR completed) — in
    /// either case the caller must NOT re-mint without operator intervention.
    pub fn is_seen(&self, tx_hash: &str) -> bool {
        self.state.deposits.contains_key(tx_hash)
    }

    /// H-03 fix: tombstone BEFORE attempting the mint. If `save()` fails the
    /// caller MUST abort the mint — otherwise a crash after a successful mint
    /// but before `mark_completed` would cause a double-mint on next boot.
    pub fn mark_in_progress(&mut self, tx_hash: String) -> Result<()> {
        self.state
            .deposits
            .insert(tx_hash, DepositStatus::InProgress);
        self.save()
    }

    /// Promote an in-progress tombstone to completed after a successful mint.
    pub fn mark_completed(&mut self, tx_hash: &str) -> Result<()> {
        self.state
            .deposits
            .insert(tx_hash.to_string(), DepositStatus::Completed);
        self.save()
    }

    /// Update the highest finalized block height we have observed.
    /// Reserved for future use by `main.rs` once range-based BTC scanning
    /// is wired in.
    #[allow(dead_code)]
    pub fn set_last_seen_height(&mut self, height: u64) {
        if height > self.state.last_seen_height {
            self.state.last_seen_height = height;
        }
    }

    /// Atomic save: write to `*.tmp` then rename so a crash mid-write can
    /// never leave a half-flushed JSON on disk.
    fn save(&self) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let json = serde_json::to_string_pretty(&self.state)?;
        fs::write(&tmp, json)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(suffix: &str) -> String {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "btc_bridge_state_{}_{}.json",
            std::process::id(),
            suffix
        ));
        p.to_string_lossy().to_string()
    }

    #[test]
    fn h03_btc_tombstone_survives_restart() {
        let path = tmp_path("survives_restart");
        let _ = fs::remove_file(&path);

        let mut s = Storage::new(&path);
        assert!(!s.is_seen("tx1"));
        s.mark_in_progress("tx1".into()).unwrap();
        assert!(s.is_seen("tx1"));

        // Simulate restart
        let s2 = Storage::new(&path);
        assert!(s2.is_seen("tx1"), "tombstone must survive restart");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn h03_btc_in_progress_blocks_re_mint() {
        let path = tmp_path("in_progress_blocks");
        let _ = fs::remove_file(&path);

        let mut s = Storage::new(&path);
        // Mint attempt: write tombstone first.
        s.mark_in_progress("tx_xyz".into()).unwrap();
        // Even though mint "crashed" before mark_completed, the tombstone
        // exists and the caller will skip this tx on next boot.
        let s2 = Storage::new(&path);
        assert!(
            s2.is_seen("tx_xyz"),
            "in-progress tombstone must prevent re-mint"
        );

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn h03_btc_legacy_hashset_migrates_to_new_schema() {
        let path = tmp_path("legacy_migrate");
        let _ = fs::remove_file(&path);
        // Pre-Phase-5.1 schema: bare HashSet<String>.
        let legacy_json = r#"["tx_a","tx_b","tx_c"]"#;
        fs::write(&path, legacy_json).unwrap();

        let s = Storage::new(&path);
        assert!(s.is_seen("tx_a"));
        assert!(s.is_seen("tx_b"));
        assert!(s.is_seen("tx_c"));
        assert!(!s.is_seen("tx_d"));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn h03_btc_atomic_save_no_partial_write() {
        let path = tmp_path("atomic_save");
        let _ = fs::remove_file(&path);

        let mut s = Storage::new(&path);
        s.mark_in_progress("tx_atomic".into()).unwrap();
        // The tmp file must not be left on disk after a successful save.
        let tmp = PathBuf::from(&path).with_extension("json.tmp");
        assert!(!tmp.exists(), "tmp file must be renamed away after save");
        assert!(PathBuf::from(&path).exists(), "main file must exist");

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn h03_btc_height_cursor_monotonic() {
        let path = tmp_path("height_cursor");
        let _ = fs::remove_file(&path);

        let mut s = Storage::new(&path);
        s.set_last_seen_height(100);
        s.set_last_seen_height(50); // Must not regress
        s.mark_in_progress("any".into()).unwrap();
        let s2 = Storage::new(&path);
        assert_eq!(s2.state.last_seen_height, 100, "cursor must be monotonic");

        let _ = fs::remove_file(&path);
    }
}
