//! The self-integrity watcher's pieces the self-defence and the actuators
//! name, which move here (Wave 4 restructure, R09a, lab PR 253): the op of
//! the signed integrity findings and the jitter of a self-check's interval,
//! cut verbatim from the agent's `self_integrity`, which re-exports them.
//! The watcher itself is R09c's.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The op of the signed integrity findings (the audit chain's since R04a,
/// lab PR 241).
pub const AUDIT_OP: &str = crate::audit::INTEGRITY_DRIFT_OP;

/// Jitter `base` by ±20 % (xorshift on the clock; unpredictability, not
/// cryptography).
pub fn jittered(base: Duration) -> Duration {
    let mut x = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ ((std::process::id() as u64) << 17);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    let ms = base.as_millis() as u64;
    let span = ms / 5; // 20 %
    if span == 0 {
        return base;
    }
    Duration::from_millis(ms - span + x % (2 * span + 1))
}
