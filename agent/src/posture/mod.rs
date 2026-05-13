//! Adaptive Defensive Posture state machine (Sub-tappa 6.5).
//!
//! NorthNarrow keeps a 4-tier posture (`OBSERVING < ALERTED < ENGAGED
//! < COMBAT`) that is *persistent across events*. Most commercial
//! EDRs evaluate every event in isolation; we don't. The posture
//! shifts up as evidence accumulates (recon → exploit → confirmed
//! intrusion) and:
//!
//! - tightens ADE confidence floors / severity inflation,
//! - lifts ambiguous `Allow` verdicts into `Alert` so OBSERVING-era
//!   noise becomes signal once the posture is hot,
//! - blocks automatic exit from `COMBAT` (admin-signed release only).
//!
//! Public surface:
//!
//! - [`PostureMachine`] is the runtime handle. Cheap to clone
//!   (`Arc`-backed) and `Send + Sync`. Construct once, share across
//!   tokio tasks.
//! - [`PostureState`] is the live state (with monotonic
//!   [`Instant`](std::time::Instant) timestamps).
//! - [`common::posture_types::PostureKind`] is the serializable
//!   projection used in logs and on the wire.
//! - [`TriggerDetector`] / [`triggers`] enumerate every condition
//!   that can move the posture up.
//!
//! Decay is monotonic-clock based (immune to wall-clock skew): the
//! caller is expected to invoke [`PostureMachine::tick_decay`] on a
//! periodic timer (60 s in `agent/src/main.rs`).
//!
//! Admin release from `COMBAT` is a stub for Sub-tappa 6.5 — it
//! takes a boolean flag. The Tappa 8 milestone replaces it with an
//! Ed25519-signed command path.

pub mod modulation;
pub mod state;
pub mod transitions;
pub mod triggers;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;

use common::ade_types::AdeVerdict;
use common::posture_types::{PostureKind, PostureTransition, TriggerType};
use common::Event;

pub use state::PostureState;
pub use triggers::TriggerDetector;

/// Cap on the in-memory transition log. Older entries are dropped to
/// keep memory predictable on a noisy host.
const TRANSITION_LOG_CAP: usize = 256;

/// Runtime handle for the posture state machine.
///
/// The handle is `Send + Sync + Clone` (cheap clones — internally an
/// `Arc<Inner>`), so callers can stash it in tokio tasks without
/// extra plumbing.
#[derive(Clone)]
pub struct PostureMachine {
    inner: Arc<Inner>,
}

/// Hook invoked exactly once per Observing/Alerted/Engaged →
/// COMBAT edge. The agent's `main.rs` wires this to
/// `NetworkIsolator::engage`. Stored as `Arc<dyn Fn() + Send +
/// Sync>` so the machine itself can stay `Clone + Send + Sync`.
pub type CombatHook = Arc<dyn Fn() + Send + Sync>;

struct Inner {
    state: RwLock<PostureState>,
    transitions: RwLock<Vec<PostureTransition>>,
    triggers: TriggerDetector,
    combat_hook: Option<CombatHook>,
}

impl PostureMachine {
    pub fn new() -> Self {
        Self::build(None)
    }

    /// Build a machine that fires `hook` whenever a transition crosses
    /// into [`PostureKind::Combat`] from any non-Combat state. The
    /// hook runs *after* the state mutation, with no lock held, so
    /// it is free to do blocking I/O (the production hook shells out
    /// to `iptables-restore`, which can take tens of milliseconds).
    ///
    /// The hook fires exactly once per upward edge into Combat; if the
    /// machine is already in Combat when another trigger fires, the
    /// hook is NOT re-invoked. The wiring in `observe()` checks
    /// `before.kind() != Combat && after.kind() == Combat`.
    pub fn new_with_combat_hook(hook: CombatHook) -> Self {
        Self::build(Some(hook))
    }

    fn build(combat_hook: Option<CombatHook>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(PostureState::default()),
                transitions: RwLock::new(Vec::new()),
                triggers: TriggerDetector::new(),
                combat_hook,
            }),
        }
    }

    /// Snapshot of the current posture state.
    pub fn current(&self) -> PostureState {
        self.inner.state.read().clone()
    }

    /// Project the current state to its serializable kind.
    pub fn current_kind(&self) -> PostureKind {
        self.inner.state.read().kind()
    }

    /// Notify the machine of a new event. Returns `Some(new_state)`
    /// when the event drove a transition, `None` otherwise.
    ///
    /// `recent_events` should be the correlated context the agent
    /// already maintains (the same slice that ADE consumes).
    pub fn observe(&self, event: &Event, recent_events: &[Event]) -> Option<PostureState> {
        let now = Instant::now();
        let hits = self.inner.triggers.detect(event, recent_events);
        if hits.is_empty() {
            return None;
        }

        let mut guard = self.inner.state.write();
        let before = guard.kind();
        let mut current = (*guard).clone();
        let mut firing: Option<TriggerType> = None;

        // Rank triggers by target_level so the strongest one decides
        // the destination state. Equal-level triggers all collapse
        // to a single transition.
        let mut sorted = hits.clone();
        sorted.sort_by_key(|t| t.target_level());
        for t in sorted {
            let next = transitions::apply_trigger(&current, t, now);
            if next.kind() > current.kind() {
                firing = Some(t);
            }
            current = next;
        }

        let after = current.kind();
        *guard = current.clone();
        drop(guard);

        if after != before {
            self.log_transition(before, after, firing, describe_triggers(&hits));
            // Combat-entry edge — fire the hook exactly once per
            // upward crossing. We deliberately check `before` so a
            // re-trigger while already in Combat does NOT re-engage
            // network isolation (which would be a redundant shell-out
            // and could mask audit signal).
            if before != PostureKind::Combat && after == PostureKind::Combat {
                if let Some(hook) = self.inner.combat_hook.as_ref() {
                    hook();
                }
            }
            Some(current)
        } else {
            None
        }
    }

    /// Modulate `verdict` according to the current posture. See
    /// [`modulation`] for the table.
    pub fn modulate_verdict(&self, verdict: AdeVerdict) -> AdeVerdict {
        let kind = self.inner.state.read().kind();
        modulation::modulate(&verdict, kind)
    }

    /// Apply decay if the appropriate window has elapsed. Returns
    /// `Some(new_state)` if a transition fired.
    pub fn tick_decay(&self) -> Option<PostureState> {
        let now = Instant::now();
        let mut guard = self.inner.state.write();
        let before = guard.kind();
        let next = transitions::apply_decay(&guard, now)?;
        let after = next.kind();
        *guard = next.clone();
        drop(guard);
        self.log_transition(
            before,
            after,
            None,
            format!("decay {} -> {}", before, after),
        );
        Some(next)
    }

    /// Force a down-transition from `Combat`. Sub-tappa 6.5 ships a
    /// boolean stub (`admin_authorized`). Tappa 8 replaces it with
    /// an Ed25519 verifier.
    ///
    /// Returns:
    /// - `Ok(new_state)` on success (always `Engaged`).
    /// - `Err(AdminReleaseError::NotInCombat)` if posture is not
    ///   `Combat`.
    /// - `Err(AdminReleaseError::Unauthorized)` if the boolean is
    ///   `false`.
    pub fn admin_release_combat(
        &self,
        admin_authorized: bool,
    ) -> Result<PostureState, AdminReleaseError> {
        if !admin_authorized {
            tracing::warn!("admin override required to leave COMBAT (denied)");
            return Err(AdminReleaseError::Unauthorized);
        }
        let now = Instant::now();
        let mut guard = self.inner.state.write();
        if !matches!(*guard, PostureState::Combat { .. }) {
            return Err(AdminReleaseError::NotInCombat);
        }
        let next = PostureState::Engaged {
            since: now,
            last_trigger: now,
        };
        *guard = next.clone();
        drop(guard);
        self.log_transition(
            PostureKind::Combat,
            PostureKind::Engaged,
            None,
            "admin override".into(),
        );
        Ok(next)
    }

    /// Snapshot of the most recent transitions (oldest first, capped).
    pub fn transition_log(&self) -> Vec<PostureTransition> {
        self.inner.transitions.read().clone()
    }

    fn log_transition(
        &self,
        from: PostureKind,
        to: PostureKind,
        trigger: Option<TriggerType>,
        reason: String,
    ) {
        let unix_ts_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let record = PostureTransition {
            from,
            to,
            trigger,
            unix_ts_secs,
            reason,
        };
        let mut log = self.inner.transitions.write();
        if log.len() >= TRANSITION_LOG_CAP {
            log.remove(0);
        }
        log.push(record);
    }
}

impl Default for PostureMachine {
    fn default() -> Self {
        Self::new()
    }
}

/// Reasons [`PostureMachine::admin_release_combat`] can refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminReleaseError {
    Unauthorized,
    NotInCombat,
}

impl core::fmt::Display for AdminReleaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdminReleaseError::Unauthorized => f.write_str("admin override not authorized"),
            AdminReleaseError::NotInCombat => f.write_str("posture is not in COMBAT"),
        }
    }
}

impl std::error::Error for AdminReleaseError {}

fn describe_triggers(hits: &[TriggerType]) -> String {
    let mut s = String::new();
    for (i, t) in hits.iter().enumerate() {
        if i > 0 {
            s.push('+');
        }
        s.push_str(t.as_str());
    }
    s
}
