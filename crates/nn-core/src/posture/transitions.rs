//! Transition rules + decay timers.
//!
//! `apply_trigger` is the single place where a [`TriggerType`] turns
//! into a state mutation. It encodes the "you can only ever go up to
//! the trigger's `target_level`" invariant — a `Reconnaissance`
//! firing while the agent is already in `Engaged` re-arms the
//! decay timer but does not down-shift.
//!
//! `apply_decay` is the time-based counterpart: with no fresh
//! triggers, `Alerted` decays back to `Observing` after
//! [`ALERTED_DECAY`], and `Engaged` decays back to `Alerted` after
//! [`ENGAGED_DECAY`]. `Combat` does not decay automatically.

use std::time::{Duration, Instant};

use nn_model::posture_types::{PostureKind, TriggerType};

use super::state::PostureState;

/// 1 hour: ALERTED -> OBSERVING decay window.
pub const ALERTED_DECAY: Duration = Duration::from_secs(60 * 60);
/// 24 hours: ENGAGED -> ALERTED decay window.
pub const ENGAGED_DECAY: Duration = Duration::from_secs(24 * 60 * 60);
/// External audit POS-001: an unlocked COMBAT (heuristic evidence only)
/// decays to ENGAGED after this long without a new escalation signal,
/// twice the corroboration window. A locked COMBAT never decays.
pub const COMBAT_QUIET_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Apply `trigger` to `state`, returning the new state.
///
/// Logic:
///
/// - Triggers can only push posture *up* to the trigger's
///   `target_level()`. They never down-shift.
/// - When a trigger fires at-or-below the current level (e.g. a
///   `Reconnaissance` event during `Engaged`), the function re-arms
///   `last_trigger` so the decay timer slides forward.
/// - `Combat` is sticky: nothing here can leave it. Down-transitions
///   from `Combat` go through a signed release
///   ([`super::PostureMachine::admin_release_combat_with_token`]) or,
///   unlocked, the quiet-window decay of `tick_decay_at`.
pub fn apply_trigger(state: &PostureState, trigger: TriggerType, now: Instant) -> PostureState {
    apply_to_level(state, trigger.target_level(), now)
}

/// The level-based core of [`apply_trigger`]. Drives the state up to
/// `target` (never down — triggers only promote), preserving the
/// Combat-is-terminal + same-tier-re-arm rules.
///
/// BUG-032: `observe()` calls this with an *effective* level — a blunt
/// COMBAT-tier signal without corroboration is capped at ENGAGED — so
/// escalation precision lives in `observe()` while the transition
/// mechanics stay here.
pub fn apply_to_level(state: &PostureState, target: PostureKind, now: Instant) -> PostureState {
    let current = state.kind();

    if matches!(state, PostureState::Combat { .. }) {
        // Combat is terminal under automatic control. Stay put.
        return state.clone();
    }

    if target <= current {
        // No upward shift; only re-arm the decay timer for the
        // matching tier so dwell time is accurate.
        return touch_last_trigger(state.clone(), now);
    }

    match target {
        PostureKind::Observing => state.clone(),
        PostureKind::Alerted => PostureState::Alerted {
            since: now,
            last_trigger: now,
        },
        PostureKind::Engaged => PostureState::Engaged {
            since: now,
            last_trigger: now,
        },
        PostureKind::Combat => PostureState::Combat {
            since: now,
            locked: true,
        },
    }
}

/// Re-arm `last_trigger` (and only `last_trigger`) without changing
/// the posture level. Used when a same-tier trigger refreshes the
/// decay clock.
fn touch_last_trigger(state: PostureState, now: Instant) -> PostureState {
    match state {
        PostureState::Observing => PostureState::Observing,
        PostureState::Alerted { since, .. } => PostureState::Alerted {
            since,
            last_trigger: now,
        },
        PostureState::Engaged { since, .. } => PostureState::Engaged {
            since,
            last_trigger: now,
        },
        PostureState::Combat { since, locked } => PostureState::Combat { since, locked },
    }
}

/// Lot 314 (the third bug hunt, BUG-84): the state an administrator's
/// order to `target` leaves (`force-posture`, and the debug hatch). Another
/// kind: that kind, fresh — its decay timers from `now`, a forced COMBAT
/// locked (external audit POS-001: the administrator ordered it). The kind
/// it is in: the state as it is, its decay timers untouched — except an
/// unlocked COMBAT, which the order locks (an explicit lock, which the
/// machine records as a transition of its own). The state was rewritten
/// whole: a force to the current ALERTED or ENGAGED re-armed its decay (one
/// hour, a day), and an unlocked COMBAT was locked without a trace.
pub fn forced(state: &PostureState, target: PostureKind, now: Instant) -> PostureState {
    if state.kind() == target {
        return match state {
            PostureState::Combat { since, .. } => PostureState::Combat {
                since: *since,
                locked: true,
            },
            other => other.clone(),
        };
    }
    match target {
        PostureKind::Observing => PostureState::Observing,
        PostureKind::Alerted => PostureState::Alerted {
            since: now,
            last_trigger: now,
        },
        PostureKind::Engaged => PostureState::Engaged {
            since: now,
            last_trigger: now,
        },
        PostureKind::Combat => PostureState::Combat {
            since: now,
            locked: true,
        },
    }
}

/// Apply decay if the appropriate window has elapsed.
///
/// Returns `Some(new_state)` if a transition fired, `None`
/// otherwise. Caller should call this on a periodic timer (the agent
/// loop wakes once a minute by default).
pub fn apply_decay(state: &PostureState, now: Instant) -> Option<PostureState> {
    match state {
        PostureState::Observing => None,
        PostureState::Combat { .. } => None, // never decays automatically
        PostureState::Alerted { last_trigger, .. } => {
            if now.saturating_duration_since(*last_trigger) >= ALERTED_DECAY {
                Some(PostureState::Observing)
            } else {
                None
            }
        }
        PostureState::Engaged { last_trigger, .. } => {
            if now.saturating_duration_since(*last_trigger) >= ENGAGED_DECAY {
                Some(PostureState::Alerted {
                    since: now,
                    last_trigger: now,
                })
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Instant {
        Instant::now()
    }

    #[test]
    fn observing_to_alerted_on_recon() {
        let s = PostureState::Observing;
        let s2 = apply_trigger(&s, TriggerType::Reconnaissance, now());
        assert_eq!(s2.kind(), PostureKind::Alerted);
    }

    #[test]
    fn alerted_to_engaged_on_exploit_attempt() {
        let t = now();
        let s = PostureState::Alerted {
            since: t,
            last_trigger: t,
        };
        let s2 = apply_trigger(&s, TriggerType::ExploitAttempt, now());
        assert_eq!(s2.kind(), PostureKind::Engaged);
    }

    #[test]
    fn engaged_to_combat_on_confirmed_intrusion() {
        let t = now();
        let s = PostureState::Engaged {
            since: t,
            last_trigger: t,
        };
        let s2 = apply_trigger(&s, TriggerType::ConfirmedIntrusion, now());
        assert_eq!(s2.kind(), PostureKind::Combat);
        assert!(s2.is_combat_locked());
    }

    #[test]
    fn combat_is_sticky_under_automatic_triggers() {
        let s = PostureState::Combat {
            since: now(),
            locked: true,
        };
        let s2 = apply_trigger(&s, TriggerType::Reconnaissance, now());
        assert_eq!(s2.kind(), PostureKind::Combat);
        assert!(s2.is_combat_locked());
    }

    /// Lot 314 (BUG-84): a force toward the kind the posture is in leaves
    /// it as it is — its timers too — except an unlocked COMBAT, locked with
    /// its entry time kept; toward another kind, that kind from `now`.
    #[test]
    fn a_force_toward_the_current_kind_keeps_the_state() {
        let t = now();
        let later = t + Duration::from_secs(3540);
        let alerted = PostureState::Alerted {
            since: t,
            last_trigger: t,
        };
        match forced(&alerted, PostureKind::Alerted, later) {
            PostureState::Alerted {
                since,
                last_trigger,
            } => assert_eq!((since, last_trigger), (t, t)),
            other => panic!("{other:?}"),
        }
        let unlocked = PostureState::Combat {
            since: t,
            locked: false,
        };
        match forced(&unlocked, PostureKind::Combat, later) {
            PostureState::Combat { since, locked } => assert_eq!((since, locked), (t, true)),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            forced(&PostureState::Observing, PostureKind::Observing, later),
            PostureState::Observing
        ));
        match forced(&alerted, PostureKind::Engaged, later) {
            PostureState::Engaged {
                since,
                last_trigger,
            } => assert_eq!((since, last_trigger), (later, later)),
            other => panic!("{other:?}"),
        }
        match forced(&PostureState::Observing, PostureKind::Combat, later) {
            PostureState::Combat { since, locked } => assert_eq!((since, locked), (later, true)),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn observing_does_not_decay() {
        let s = PostureState::Observing;
        // Pretend we are way in the future.
        let later = Instant::now() + Duration::from_secs(48 * 3600);
        assert!(apply_decay(&s, later).is_none());
    }

    #[test]
    fn alerted_decays_to_observing_after_one_hour() {
        let t = Instant::now();
        let s = PostureState::Alerted {
            since: t,
            last_trigger: t,
        };
        let later = t + ALERTED_DECAY;
        match apply_decay(&s, later) {
            Some(PostureState::Observing) => {}
            other => panic!("expected Observing, got {:?}", other),
        }
    }

    #[test]
    fn alerted_does_not_decay_too_early() {
        let t = Instant::now();
        let s = PostureState::Alerted {
            since: t,
            last_trigger: t,
        };
        let too_early = t + Duration::from_secs(60 * 30); // 30 min
        assert!(apply_decay(&s, too_early).is_none());
    }

    #[test]
    fn engaged_decays_to_alerted_after_24h() {
        let t = Instant::now();
        let s = PostureState::Engaged {
            since: t,
            last_trigger: t,
        };
        let later = t + ENGAGED_DECAY;
        match apply_decay(&s, later) {
            Some(PostureState::Alerted { .. }) => {}
            other => panic!("expected Alerted, got {:?}", other),
        }
    }

    #[test]
    fn combat_never_decays() {
        let s = PostureState::Combat {
            since: Instant::now(),
            locked: true,
        };
        let way_later = Instant::now() + Duration::from_secs(365 * 24 * 3600);
        assert!(apply_decay(&s, way_later).is_none());
    }

    #[test]
    fn same_tier_trigger_only_refreshes_last_trigger() {
        let t0 = Instant::now();
        let s = PostureState::Alerted {
            since: t0,
            last_trigger: t0,
        };
        let t1 = t0 + Duration::from_secs(120);
        let s2 = apply_trigger(&s, TriggerType::Reconnaissance, t1);
        match s2 {
            PostureState::Alerted {
                since,
                last_trigger,
            } => {
                assert_eq!(since, t0);
                assert_eq!(last_trigger, t1);
            }
            other => panic!("expected Alerted retained, got {:?}", other),
        }
    }
}
