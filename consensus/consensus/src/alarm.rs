//! B23: whether an error is a consensus alarm (a decision conflict, a
//! committee mismatch) is never read from its text. Errors carry text a
//! peer chose (a QC's chain id, a block's fields), and a forged QC whose
//! chain id was the marker made every validator halt for good. The code
//! that finds an alarm raises it here, on the thread that returns the
//! error; the caller asks whether its own call raised one.

use std::cell::Cell;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alarm {
    /// A certified decision this node disagrees with (IM-3, DE-6, EP-3).
    DecisionConflict,
    /// A verified QC(H_E) binds a next committee this node did not derive
    /// (EP-4).
    CommitteeMismatch,
}

thread_local! {
    static RAISED: Cell<Option<Alarm>> = const { Cell::new(None) };
}

/// Mark the error being returned as `alarm`; `msg` comes back unchanged.
/// Called only where the alarm is found (for a QC, after it verified).
pub fn raise(alarm: Alarm, msg: String) -> String {
    RAISED.with(|r| r.set(Some(alarm)));
    msg
}

/// Forget any mark, before a call whose alarm is asked for with `take`.
pub fn clear() {
    RAISED.with(|r| r.set(None));
}

/// The alarm raised since the last `clear` on this thread, if any.
pub fn take() -> Option<Alarm> {
    RAISED.with(|r| r.replace(None))
}

/// Run `f` and return the alarm it raised, if any (only `f`'s counts).
pub fn raised_by<T>(f: impl FnOnce() -> T) -> (T, Option<Alarm>) {
    clear();
    let out = f();
    (out, take())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_raised_alarm_counts_whatever_the_text() {
        let forged = format!("{}: chain id", crate::ordering::DECISION_CONFLICT);
        let (_, alarm) = raised_by(|| Err::<(), _>(forged));
        assert_eq!(alarm, None, "text is not an alarm");
        let (_, alarm) = raised_by(|| Err::<(), _>(raise(Alarm::DecisionConflict, "found".into())));
        assert_eq!(alarm, Some(Alarm::DecisionConflict));
        // A stale mark from an earlier call does not leak into the next.
        let _ = raise(Alarm::CommitteeMismatch, String::new());
        let (_, alarm) = raised_by(|| Ok::<(), String>(()));
        assert_eq!(alarm, None);
    }
}
