//! Lab PR 243: the clock the posture reads, behind a trait.
//!
//! The posture's timers (the ledger's corroboration window, decay, the
//! quiet window of an unlocked COMBAT, the admin release's stamp) run on
//! the monotonic clock, and its transition records carry a wall-clock
//! second. Both used to be read where they were needed (`Instant::now`,
//! `SystemTime::now`), so a replay of the posture could not be the same
//! twice. [`SystemClock`] reads the two clocks as before — production is
//! unchanged; the golden replay of the posture and the COMBAT ladder
//! (`posture::golden`, `docs/validation/GOLDEN_REPLAY.md`) gives the
//! machine a clock of its own, which the trusted-installer window reads
//! too.
//!
//! The restructure plan's `Clock` (§2.3, R04b) counts monotonic
//! nanoseconds; this one returns the [`Instant`] the posture's state
//! already holds, so no timer changes type before R08 moves the posture.
//! `anti_tamper::admin_auth::Clock` is another one: the wall-clock second
//! of the admin timestamp skew check.

use std::time::{Instant, SystemTime};

/// Where the posture reads the time.
pub trait Clock: Send + Sync {
    /// The monotonic now (`CLOCK_MONOTONIC`, what [`Instant::now`] reads):
    /// every timer.
    fn now(&self) -> Instant;
    /// The wall clock now (what [`SystemTime::now`] reads): records only,
    /// never a timer.
    fn wall(&self) -> SystemTime;
}

/// The host's clocks — the agent's.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Tests: a clock that moves only when told (lab PR 243). R08a (lab PR
/// 250): the agent's tests of the trusted-installer window read it too
/// (`test-util`).
#[cfg(any(test, feature = "test-util"))]
pub struct TestClock {
    base: Instant,
    wall_at_base: SystemTime,
    elapsed: parking_lot::Mutex<std::time::Duration>,
}

#[cfg(any(test, feature = "test-util"))]
impl TestClock {
    /// At `wall_at_base` on the wall clock.
    pub fn at(wall_at_base: SystemTime) -> Self {
        Self {
            base: Instant::now(),
            wall_at_base,
            elapsed: parking_lot::Mutex::new(std::time::Duration::ZERO),
        }
    }

    pub fn advance(&self, by: std::time::Duration) {
        *self.elapsed.lock() += by;
    }
}

#[cfg(any(test, feature = "test-util"))]
impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.base + *self.elapsed.lock()
    }

    fn wall(&self) -> SystemTime {
        self.wall_at_base + *self.elapsed.lock()
    }
}
