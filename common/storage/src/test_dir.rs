//! B20: where tests keep their databases. Every test directory in the
//! workspace comes from [`test_dir`]: `<temp>/aincore-tests/<pid>/<name>-<n>`.
//! The first call in a process removes the directories of test processes
//! that have exited, so a run leaves at most its own databases behind and
//! nothing piles up across runs (four runs had filled the NAS's 1.9 GB
//! `/dev/shm` with 1,253 databases).
//!
//! Not for production paths: a node's data directory is the operator's.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;

/// The parent of every process's test directories.
pub fn tests_root() -> PathBuf {
    std::env::temp_dir().join("aincore-tests")
}

/// This process's test directory, `<temp>/aincore-tests/<pid>` (created).
/// Every test path in the workspace lives under it. The first call removes
/// the directories of test processes that have exited.
pub fn process_dir() -> PathBuf {
    static REAPED: Once = Once::new();
    let root = tests_root();
    REAPED.call_once(|| {
        reap_exited(&root, &process_alive);
    });
    let dir = root.join(std::process::id().to_string());
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// A fresh, empty directory path for one test database, unique in this
/// process (a counter: two calls with the same name never share it). The
/// directory itself is not created; `StateDB::open` creates it.
pub fn test_dir(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = process_dir().join(format!("{name}-{n}"));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// [`test_dir`] as a string, for `StateDB::open`.
pub fn test_dir_str(name: &str) -> String {
    test_dir(name).to_string_lossy().into_owned()
}

/// Remove `root/<pid>` for every pid `alive` says has exited. Entries that
/// are not a pid are left alone.
pub fn reap_exited(root: &Path, alive: &dyn Fn(u32) -> bool) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid != std::process::id() && !alive(pid) && std::fs::remove_dir_all(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Whether process `pid` is running. Where that cannot be told (no
/// `/proc`), every process counts as running and nothing is reaped.
fn process_alive(pid: u32) -> bool {
    let proc = Path::new("/proc");
    !proc.is_dir() || proc.join(pid.to_string()).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_call_gets_its_own_empty_directory() {
        let a = test_dir("same");
        let b = test_dir("same");
        assert_ne!(a, b);
        assert!(a.starts_with(process_dir()));
        assert_eq!(
            process_dir(),
            tests_root().join(std::process::id().to_string())
        );
        assert!(!a.exists(), "fresh: nothing there yet");
    }

    #[test]
    fn only_the_directories_of_exited_processes_are_reaped() {
        let root = test_dir("reap_root");
        for name in ["101", "202", "not-a-pid"] {
            std::fs::create_dir_all(root.join(name).join("db")).unwrap();
        }
        let own = root.join(std::process::id().to_string());
        std::fs::create_dir_all(&own).unwrap();
        let removed = reap_exited(&root, &|pid| pid == 202);
        assert_eq!(removed, 1);
        assert!(!root.join("101").exists(), "exited: reaped");
        assert!(root.join("202").exists(), "running: kept");
        assert!(root.join("not-a-pid").exists(), "not ours: kept");
        assert!(own.exists(), "this process: kept");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// B20 witness: every test path in the workspace comes from
    /// `process_dir`, so it is reaped. The two bridge crates keep a small
    /// JSON file each and do not depend on this crate.
    #[test]
    fn no_test_path_bypasses_the_reaped_directory() {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with('.') || name == "target" || name == "node_modules" {
                    continue;
                }
                if path.is_dir() {
                    walk(&path, out);
                } else if name.ends_with(".rs") {
                    out.push(path);
                }
            }
        }
        let allowed = [
            "common/storage/src/test_dir.rs",
            "depin/bridge-rust/src/nonce_store.rs",
            "depin/btc-bridge/src/storage.rs",
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        walk(&root, &mut files);
        assert!(
            files
                .iter()
                .any(|f| f.ends_with("sync/src/state_sync/tests.rs")),
            "positive control: the walk reached the state-sync tests"
        );
        let bypasses = [concat!("std::env::", "temp_dir()"), concat!("\"/", "tmp/")];
        let mut found = Vec::new();
        for file in files {
            if allowed.iter().any(|a| file.ends_with(a)) {
                continue;
            }
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            for bypass in bypasses {
                if text.contains(bypass) {
                    found.push(format!("{}: {bypass}", file.display()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "test paths outside process_dir: {found:#?}"
        );
    }
}
