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
///
/// Except a panic caught on purpose (B92): one inside
/// `storage::panic_guard::caught` (the state tree's `no_panic`: jmt panics on
/// missing or hostile rows), or inside the Move bytecode verifier or
/// deserializer, which catch their own panics (Aptos's crash handler spares
/// the same two states). Aborting there turned a bad input into a crash.
pub fn abort_on_panic() {
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        report(info);
        if caught_on_purpose() {
            return;
        }
        std::process::abort();
    }));
}

/// B92: whether the panic now unwinding will be caught by code that expects it.
fn caught_on_purpose() -> bool {
    use move_core_types::state::{get_state, VMState};
    storage::panic_guard::catching()
        || matches!(get_state(), VMState::VERIFIER | VMState::DESERIALIZER)
}

#[cfg(test)]
mod abort_on_panic_tests {
    const CAUGHT_STAYED_CAUGHT: &str = "B92: the caught panics stayed caught";

    /// B77 witness: a panic under a lock, on any thread, ends the process
    /// (a child test process, so the abort is observed from outside).
    #[test]
    fn a_panic_on_any_thread_ends_the_process() {
        if std::env::var("AINCORE_TEST_PANIC_CHILD").is_ok() {
            super::abort_on_panic();
            // B92: a panic caught on purpose stays caught: the state tree's
            // guard, and the Move verifier's own catch.
            assert!(storage::panic_guard::caught(|| panic!("a jmt panic")).is_err());
            let prev = move_core_types::state::set_state(move_core_types::state::VMState::VERIFIER);
            assert!(std::panic::catch_unwind(|| panic!("a verifier panic")).is_err());
            move_core_types::state::set_state(prev);
            // The parent looks for this line: an abort at either caught panic
            // would also end the process with SIGABRT, before it.
            eprintln!("{CAUGHT_STAYED_CAUGHT}");
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
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "abort_on_panic_tests::a_panic_on_any_thread_ends_the_process",
                "--test-threads=1",
                "--nocapture",
            ])
            .env("AINCORE_TEST_PANIC_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .output()
            .unwrap();
        let status = output.status;
        assert!(!status.success(), "the process outlived a panic: {status}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(CAUGHT_STAYED_CAUGHT),
            "a panic caught on purpose ended the process"
        );
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(6), "aborted (SIGABRT): {status}");
        }
    }
}
