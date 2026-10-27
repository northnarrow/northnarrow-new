//! Lab PR 249: the time the signed chains stamp on their rows, behind a
//! trait.
//!
//! Every row a chain writer signs carries the time it was written: an audit
//! row's `ts` ([`crate::audit::AuditLog`]), a rotating log's terminator and
//! manifest rows ([`crate::chainlog::RotatingChainLog`]), the head anchor's
//! snapshot ([`crate::chain_anchor::Anchor`]). The hash covers it, and the
//! signature the hash, so a chain written twice from the same inputs was
//! two chains: the writers read `Utc::now` where they stamped. They read it
//! through a [`Clock`] now. [`SystemClock`] is that same `Utc::now`, the
//! writers' default — the agent's chains are stamped as before; a replay or
//! a test gives a clock of its own and writes the same bytes every run (the
//! posture golden's signed rows, `agent/src/posture/golden.rs`).
//!
//! What a writer reads besides the time to stamp a row — the audit rows'
//! `client_pid` of the writer itself — is [`crate::audit::AuditStamps`].
//! Timers (the rotating log's time-based checkpoint) stay on the monotonic
//! clock: they choose when a row is written, they are not written in it.

use chrono::{DateTime, Utc};

/// Where a chain writer reads the time it stamps on a row.
pub trait Clock: Send + Sync {
    /// The wall clock now.
    fn now(&self) -> DateTime<Utc>;
}

/// The host's clock (`Utc::now`): every writer's unless it is given another.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// The stamp of a row written now by `clock`: ISO-8601 UTC, microseconds
/// ([`crate::audit::format_ts`], the format of every chain's timestamps).
pub fn stamp(clock: &dyn Clock) -> String {
    crate::audit::format_ts(clock.now())
}

/// The chain code's own tests: a clock that moves only when told.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Mutex;

    use chrono::{DateTime, TimeDelta, Utc};

    use super::Clock;

    /// Starts at `at`; [`Self::advance`] moves it.
    pub(crate) struct FixedClock(Mutex<DateTime<Utc>>);

    impl FixedClock {
        pub(crate) fn at(rfc3339: &str) -> Self {
            Self(Mutex::new(
                DateTime::parse_from_rfc3339(rfc3339)
                    .expect("an RFC 3339 time")
                    .with_timezone(&Utc),
            ))
        }

        pub(crate) fn advance(&self, by: TimeDelta) {
            let mut t = self.0.lock().unwrap();
            *t += by;
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default clock is the host's: a stamp falls between two readings
    /// of `Utc::now`, in the chains' format.
    #[test]
    fn the_system_clock_is_utc_now() {
        let before = Utc::now();
        let t = SystemClock.now();
        let s = stamp(&SystemClock);
        let after = Utc::now();
        assert!(before <= t && t <= after, "{before} <= {t} <= {after}");
        assert_eq!(s.len(), "2026-01-01T00:00:00.000000Z".len(), "{s}");
        assert!(s.ends_with('Z'), "{s}");
        // The stamp keeps microseconds: it is at most 1 µs before `before`.
        let stamped = DateTime::parse_from_rfc3339(&s).unwrap();
        assert!(
            stamped >= before - chrono::TimeDelta::microseconds(1),
            "{s}"
        );
        assert!(stamped <= after, "{s}");
    }

    /// A clock of the caller's own is what the stamp says, to the
    /// microsecond.
    #[test]
    fn a_stamp_is_the_clocks_time() {
        let c = testing::FixedClock::at("2026-01-01T00:02:00.123456789Z");
        assert_eq!(stamp(&c), "2026-01-01T00:02:00.123456Z");
        c.advance(chrono::TimeDelta::microseconds(5));
        assert_eq!(stamp(&c), "2026-01-01T00:02:00.123461Z");
    }
}
