//! A panic that code catches on purpose (a library known to panic on bad
//! input, wrapped in `catch_unwind`) must stay caught when the node aborts
//! on every other panic (B77). `caught` runs a closure under
//! `catch_unwind` and marks the thread while it does; the node's panic
//! hook leaves a panic alone while `catching` is true.

use std::cell::Cell;

thread_local! {
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Run `f`, catching a panic in it; while it runs, `catching()` is true on
/// this thread.
pub fn caught<T>(f: impl FnOnce() -> T) -> std::thread::Result<T> {
    DEPTH.with(|d| d.set(d.get().saturating_add(1)));
    let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
    out
}

/// Whether this thread is inside `caught`.
pub fn catching() -> bool {
    DEPTH.with(|d| d.get() > 0)
}
