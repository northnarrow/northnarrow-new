//! R12c-2 (lab PR 270): the heartbeat's period — the variable that sets it
//! and whether a value weakens it (the self-integrity check reports the
//! weakening ones). The heartbeat itself is the agent's (`heartbeat`).

use std::time::Duration;

/// The beats' period by default (s).
pub const DEFAULT_INTERVAL_SECS: u64 = 30;
/// The variable that sets it: 5 to 300 s; anything else keeps the default
/// — there is no off.
pub const INTERVAL_ENV: &str = "NN_HEARTBEAT_SECS";

/// The beats' period: [`INTERVAL_ENV`] when it is 5 to 300, else
/// [`DEFAULT_INTERVAL_SECS`].
pub fn interval_from_env() -> Duration {
    interval_of(std::env::var(INTERVAL_ENV).ok().as_deref())
}

/// [`interval_from_env`] of a value.
pub fn interval_of(value: Option<&str>) -> Duration {
    let secs = value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| (5..=300).contains(s))
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    Duration::from_secs(secs)
}

/// Does this value of [`INTERVAL_ENV`] weaken the heartbeat? When it spaces
/// the beats out beyond the default.
pub fn interval_weakens(value: &str) -> bool {
    interval_of(Some(value)).as_secs() > DEFAULT_INTERVAL_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 5 to 300 s from the variable, else 30 — never off; a longer period
    /// than the default weakens.
    #[test]
    fn the_period_has_no_off() {
        assert_eq!(interval_of(Some("10")).as_secs(), 10);
        assert_eq!(interval_of(Some("0")).as_secs(), 30);
        assert_eq!(interval_of(Some("4")).as_secs(), 30);
        assert_eq!(interval_of(Some("301")).as_secs(), 30);
        assert_eq!(interval_of(Some("x")).as_secs(), 30);
        assert_eq!(interval_of(None).as_secs(), 30);
        assert!(interval_weakens("120"));
        assert!(!interval_weakens("30"));
        assert!(!interval_weakens("10"));
        assert!(!interval_weakens("0"), "0 is not taken: the default stays");
    }
}
