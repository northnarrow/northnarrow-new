//! Runtime [`PostureState`] — the in-memory state held by a
//! [`super::PostureMachine`].
//!
//! Design notes:
//!
//! - We use [`std::time::Instant`] (monotonic) for every timestamp.
//!   The decay timers must be immune to NTP jumps and wall-clock
//!   skew; an attacker should not be able to force a posture
//!   down-shift by tampering with the host clock.
//! - The serializable, audit-friendly shape lives in
//!   [`common::posture_types::PostureKind`]; this enum carries the
//!   timing/lock fields that the runtime needs but that don't belong
//!   on the wire.

use std::time::Instant;

use common::posture_types::PostureKind;

/// Live posture, including timing fields used for decay.
///
/// `since` records when the agent first entered this state; it is
/// useful for telemetry (`dwell time = now - since`).
/// `last_trigger` records the last upward-trigger fire; decay timers
/// fire when `now - last_trigger >= decay window`.
///
/// `Combat::locked = true` blocks every automatic down-transition;
/// only [`super::PostureMachine::admin_release_combat`] can clear it.
#[derive(Debug, Clone, Default)]
pub enum PostureState {
    #[default]
    Observing,
    Alerted {
        since: Instant,
        last_trigger: Instant,
    },
    Engaged {
        since: Instant,
        last_trigger: Instant,
    },
    Combat {
        since: Instant,
        locked: bool,
    },
}

impl PostureState {
    /// Project to the serializable [`PostureKind`].
    pub fn kind(&self) -> PostureKind {
        match self {
            PostureState::Observing => PostureKind::Observing,
            PostureState::Alerted { .. } => PostureKind::Alerted,
            PostureState::Engaged { .. } => PostureKind::Engaged,
            PostureState::Combat { .. } => PostureKind::Combat,
        }
    }

    /// Returns `true` if the state is `Combat` with `locked = true`.
    pub fn is_combat_locked(&self) -> bool {
        matches!(self, PostureState::Combat { locked: true, .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_observing() {
        let s = PostureState::default();
        assert_eq!(s.kind(), PostureKind::Observing);
    }

    #[test]
    fn combat_lock_query() {
        let now = Instant::now();
        let unlocked = PostureState::Combat {
            since: now,
            locked: false,
        };
        let locked = PostureState::Combat {
            since: now,
            locked: true,
        };
        assert!(!unlocked.is_combat_locked());
        assert!(locked.is_combat_locked());
        assert_eq!(locked.kind(), PostureKind::Combat);
    }

    #[test]
    fn kind_matches_variant() {
        let now = Instant::now();
        assert_eq!(
            PostureState::Alerted {
                since: now,
                last_trigger: now,
            }
            .kind(),
            PostureKind::Alerted
        );
        assert_eq!(
            PostureState::Engaged {
                since: now,
                last_trigger: now,
            }
            .kind(),
            PostureKind::Engaged
        );
    }
}
