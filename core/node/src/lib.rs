/// B21: transactions forwarded from outside the committee.
pub mod forward;
pub mod genesis;
pub mod p2p;
pub mod qc_rpc;
pub mod sessions;
pub const API_PORT: u16 = 8002;
pub mod metrics;
#[cfg(test)]
mod public_claims_tests;

/// B77: a panic anywhere ends the process, and systemd starts it again. The
/// node keeps its state behind `std::sync` locks: a panic under one
/// poisoned it, every loop that took it skipped (`if let Ok`) from then on,
/// and the process stayed up doing nothing, so nothing restarted it.
pub fn abort_on_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        std::process::abort();
    }));
}

#[cfg(test)]
mod abort_on_panic_tests {
    /// B77 witness: a panic under a lock, on any thread, ends the process
    /// (a child test process, so the abort is observed from outside).
    #[test]
    fn a_panic_on_any_thread_ends_the_process() {
        if std::env::var("AINCORE_TEST_PANIC_CHILD").is_ok() {
            super::abort_on_panic();
            let lock = std::sync::Arc::new(std::sync::RwLock::new(0u8));
            let held = std::sync::Arc::clone(&lock);
            let _ = std::thread::spawn(move || {
                let _guard = held.write().unwrap();
                panic!("a panic under the consensus lock");
            })
            .join();
            // Reached only if the process outlived the panic.
            std::process::exit(0);
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "abort_on_panic_tests::a_panic_on_any_thread_ends_the_process",
                "--test-threads=1",
            ])
            .env("AINCORE_TEST_PANIC_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success(), "the process outlived a panic: {status}");
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(6), "aborted (SIGABRT): {status}");
        }
    }
}
