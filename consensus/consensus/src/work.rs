//! B51: costly checks that failed, counted on the thread that ran them.
//!
//! A BLS verification costs a pairing or two (milliseconds on the Pi), and
//! the consensus lock is held around it. A member that sends what fails
//! such a check (a junk certificate in a pull answer, a forged embedded
//! certificate, a bad vote) is doing what no honest member does. The node
//! asks how many failed while it handled one member's message and stops
//! hearing that member for a while once it has failed enough
//! (`DagConsensus::handle_message_from`).

use std::cell::Cell;

thread_local! {
    static FAILED: Cell<u64> = const { Cell::new(0) };
}

/// A costly check failed on this thread.
pub fn note_failed_check() {
    FAILED.with(|f| f.set(f.get().saturating_add(1)));
}

/// The costly checks that failed on this thread so far.
pub fn failed_checks() -> u64 {
    FAILED.with(Cell::get)
}

/// Run `f` and return how many costly checks failed in it.
pub fn failed_in<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = failed_checks();
    let out = f();
    (out, failed_checks().saturating_sub(before))
}
