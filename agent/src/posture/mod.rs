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

pub mod exempt;
pub mod lineage;
pub mod modulation;
pub mod state;
pub mod transitions;
pub mod triggers;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use common::ade_types::AdeVerdict;
use common::posture_types::{PostureKind, PostureTransition, TriggerType};
use common::Event;

use crate::anti_tamper::network_isolate::UnlockToken;

pub use exempt::{
    resolve_verified_watchdog_pid, ExemptPids, WatchdogResolution, DEFAULT_WATCHDOG_EXE,
    DEFAULT_WATCHDOG_PIDFILE,
};
pub use lineage::{AuthSessionTracker, AUTH_BINARY_EXES};
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
pub type CombatEntryHook = Arc<dyn Fn() + Send + Sync>;

/// Hook invoked when the admin successfully releases COMBAT via
/// [`PostureMachine::admin_release_combat_with_token`]. Receives the
/// validated [`UnlockToken`] by value so the implementation can pass
/// it straight into `NetworkIsolator::release`.
///
/// Fires AFTER the posture state transition and AFTER the write
/// lock is dropped — keep that contract so the hook is free to
/// shell out to `iptables` (which can take tens of ms) without
/// blocking other observers.
pub type CombatReleaseHook = Arc<dyn Fn(UnlockToken) + Send + Sync>;

/// Pre-#6 alias retained so any in-flight references keep building.
pub type CombatHook = CombatEntryHook;

struct Inner {
    state: RwLock<PostureState>,
    transitions: RwLock<Vec<PostureTransition>>,
    triggers: TriggerDetector,
    combat_entry_hook: Option<CombatEntryHook>,
    combat_release_hook: Option<CombatReleaseHook>,
    /// Monotonic timestamp of the most recent successful admin
    /// release. `None` if no admin action has occurred since boot.
    /// Read by `StatusResponse` via [`PostureMachine::last_admin_action_secs_ago`].
    last_admin_action: Mutex<Option<Instant>>,
}

impl PostureMachine {
    pub fn new() -> Self {
        Self::build(
            None,
            None,
            ExemptPids::default(),
            AuthSessionTracker::default(),
        )
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
    pub fn new_with_combat_hook(hook: CombatEntryHook) -> Self {
        Self::build(
            Some(hook),
            None,
            ExemptPids::default(),
            AuthSessionTracker::default(),
        )
    }

    /// Build a machine that fires both an entry hook (on the
    /// non-Combat → Combat edge) and a release hook (during
    /// [`Self::admin_release_combat_with_token`]). The release hook
    /// receives the validated [`UnlockToken`] by value.
    ///
    /// This is the production constructor — `main.rs` uses it to
    /// wire `NetworkIsolator::engage` and `NetworkIsolator::release`
    /// to the posture state machine in one place.
    pub fn new_with_hooks(entry: CombatEntryHook, release: CombatReleaseHook) -> Self {
        Self::build(
            Some(entry),
            Some(release),
            ExemptPids::default(),
            AuthSessionTracker::default(),
        )
    }

    /// Production constructor: like [`Self::new_with_hooks`] but also
    /// records the agent's own PID so the trigger detector excludes
    /// the agent's own events (its continuous state-log writes would
    /// otherwise self-trip the mass-write heuristic into COMBAT — see
    /// [`TriggerDetector`] docs). `main.rs` passes `std::process::id()`.
    pub fn new_with_hooks_and_self_pid(
        entry: CombatEntryHook,
        release: CombatReleaseHook,
        self_pid: u32,
    ) -> Self {
        Self::build(
            Some(entry),
            Some(release),
            ExemptPids::with_agent(self_pid),
            AuthSessionTracker::default(),
        )
    }

    /// Production constructor (Beta Step 3): like
    /// [`Self::new_with_hooks_and_self_pid`] but takes a shared
    /// [`ExemptPids`] so the trigger detector excludes both the agent's
    /// own PID *and* the verified watchdog PID. `main.rs` builds the
    /// handle with the agent PID and refreshes the watchdog slot on a
    /// timer.
    pub fn new_with_hooks_and_exempt(
        entry: CombatEntryHook,
        release: CombatReleaseHook,
        exempt: ExemptPids,
    ) -> Self {
        Self::build(
            Some(entry),
            Some(release),
            exempt,
            AuthSessionTracker::default(),
        )
    }

    /// Production constructor (Beta Step 5, T7.13): like
    /// [`Self::new_with_hooks_and_exempt`] but also accepts a
    /// shared [`AuthSessionTracker`] so the trigger detector can
    /// suppress `sensitive_file_access` and the mass-write arm of
    /// `confirmed_intrusion` for sudo-mediated PIDs. `main.rs`
    /// constructs the tracker once at boot and shares it through
    /// the posture machine.
    pub fn new_with_hooks_and_exempt_and_auth(
        entry: CombatEntryHook,
        release: CombatReleaseHook,
        exempt: ExemptPids,
        auth: AuthSessionTracker,
    ) -> Self {
        Self::build(Some(entry), Some(release), exempt, auth)
    }

    fn build(
        combat_entry_hook: Option<CombatEntryHook>,
        combat_release_hook: Option<CombatReleaseHook>,
        exempt: ExemptPids,
        auth: AuthSessionTracker,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(PostureState::default()),
                transitions: RwLock::new(Vec::new()),
                triggers: TriggerDetector::with_exempt_and_auth(exempt, auth),
                combat_entry_hook,
                combat_release_hook,
                last_admin_action: Mutex::new(None),
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
                if let Some(hook) = self.inner.combat_entry_hook.as_ref() {
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

    /// Force a down-transition from `Combat`. Sub-tappa 6.5 stub
    /// kept around so `agent/examples/posture_demo.rs` and the older
    /// unit tests keep building; production code uses
    /// [`Self::admin_release_combat_with_token`], wired from
    /// `AdminAuth::verify_unlock` in `main.rs`.
    // NOTE: this bool stub is the Sub-tappa 6.5 placeholder.
    // Production code uses `admin_release_combat_with_token`. We
    // intentionally do NOT add a `#[deprecated]` attribute today —
    // the legacy callers (the demo binary + several posture tests)
    // need to be migrated first; doing both in one commit would blow
    // up the diff. Migration tracked as a follow-up cleanup.
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

    /// Production path out of Combat — invoked from the agent's
    /// admin socket handler after `AdminAuth::verify_unlock` returns
    /// a token. Drops the posture down to `Alerted` (NOT `Engaged`
    /// like the legacy bool stub), then fires the combat-release
    /// hook with the consumed token so `NetworkIsolator::release`
    /// can tear down the iptables ruleset.
    ///
    /// ## Target-state rationale (Alerted, not Engaged)
    ///
    /// A legitimate admin unlock means *"threat acknowledged,
    /// network restored"* — it does NOT mean *"incident over."*
    /// The operator just told us they're in the loop; the right
    /// posture after that signal is still elevated (Alerted)
    /// because there is no semantic basis to assume the broader
    /// threat is gone. If the host was actively compromised when
    /// COMBAT engaged, the attacker's foothold is unchanged by
    /// the admin's signature — we just stopped quarantining the
    /// network. Alerted preserves heightened sensitivity to
    /// subsequent triggers.
    ///
    /// The legacy `admin_release_combat` bool stub returns to
    /// Engaged instead, for state-machine-exercise reasons that
    /// predate the Tappa 7/8 work. That stub is `#[cfg(test)]`-
    /// shaped (its only callers are the demo example and unit
    /// tests); the asymmetry is intentional and deliberate.
    ///
    /// Idempotent w.r.t. "already out of Combat" only at the socket
    /// layer — this method itself errors with `NotInCombat` if the
    /// state isn't Combat, leaving caller-side policy to map that to
    /// `UnlockResult::Success`.
    ///
    /// On success records `Instant::now()` in `last_admin_action`,
    /// surfaced via [`Self::last_admin_action_secs_ago`] for the
    /// `nn-admin status` response.
    pub fn admin_release_combat_with_token(
        &self,
        token: UnlockToken,
    ) -> Result<PostureState, AdminReleaseError> {
        let now = Instant::now();
        let mut guard = self.inner.state.write();
        if !matches!(*guard, PostureState::Combat { .. }) {
            return Err(AdminReleaseError::NotInCombat);
        }
        let next = PostureState::Alerted {
            since: now,
            last_trigger: now,
        };
        *guard = next.clone();
        drop(guard);
        *self.inner.last_admin_action.lock() = Some(now);
        self.log_transition(
            PostureKind::Combat,
            PostureKind::Alerted,
            None,
            "admin token release".into(),
        );

        // Hook runs *after* state mutation + lock drop + log so it
        // can shell out to iptables without blocking other observers.
        if let Some(hook) = self.inner.combat_release_hook.as_ref() {
            hook(token);
        }
        // In the no-hook configuration the token falls out of scope
        // here; UnlockToken has no Drop impl, so the explicit
        // `drop()` clippy nagged about was a no-op anyway. The
        // capability invariant is intact because the token's
        // *constructor* is what's visibility-gated.
        Ok(next)
    }

    /// Seconds since the last successful admin release, or `None` if
    /// no admin action has occurred since the agent booted.
    pub fn last_admin_action_secs_ago(&self) -> Option<u64> {
        self.inner
            .last_admin_action
            .lock()
            .map(|t| t.elapsed().as_secs())
    }

    /// Tappa 8 A10 — production force-posture (design §12.2).
    /// Capability-gated by [`UnlockToken`] in the same way as
    /// [`Self::admin_release_combat_with_token`]; consumed at the
    /// type-system level so only [`crate::anti_tamper::admin_auth::AdminAuth`]
    /// (the sole minting site outside `cfg(test)`) can drive this
    /// path. Allowed direction: any state → any state.
    ///
    /// Side effects per design §12.2:
    /// - non-COMBAT → COMBAT fires `combat_entry_hook` (iptables
    ///   engage — identical to a detector-driven entry).
    /// - COMBAT → non-COMBAT fires `combat_release_hook` (iptables
    ///   release — identical to an unlock).
    /// - Same-direction (before == target) is a no-op: no log, no
    ///   hooks, token drops out of scope.
    /// - Lateral non-COMBAT transitions (e.g. Alerted → Engaged)
    ///   log the transition but fire no hook.
    ///
    /// Records `Instant::now()` in `last_admin_action` on any
    /// actual transition — surfaced via
    /// [`Self::last_admin_action_secs_ago`] for `nn-admin status`.
    ///
    /// Returns the post-transition [`PostureState`] (or the unchanged
    /// state when before == target). Never errors today — every
    /// `target` is a valid PostureKind and the type-system gate on
    /// `UnlockToken` is the only authorisation check.
    pub fn admin_force_state_with_token(
        &self,
        token: UnlockToken,
        target: PostureKind,
    ) -> Result<PostureState, AdminReleaseError> {
        let now = Instant::now();
        let mut guard = self.inner.state.write();
        let before = guard.kind();
        let next = match target {
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
        };
        *guard = next.clone();
        drop(guard);

        if before == target {
            // No-op transition — no log, no hook. The capability
            // check (the type-system gate on minting) has already
            // done its work by the time we got here; the `token`
            // binding falls out of scope on return. UnlockToken
            // has no Drop impl so an explicit `drop()` would be a
            // no-op (clippy::drop_non_drop).
            let _ = token;
            return Ok(next);
        }

        *self.inner.last_admin_action.lock() = Some(now);
        self.log_transition(before, target, None, "admin token force-posture".into());

        // Side-effects per §12.2.
        if before != PostureKind::Combat && target == PostureKind::Combat {
            // Non-COMBAT → COMBAT: entry hook fires (iptables
            // engage). The entry hook's signature is `Fn()`, not
            // `Fn(UnlockToken)` (entry isn't gated by capability —
            // detectors can fire it autonomously). The `token`
            // binding falls out of scope on return.
            if let Some(hook) = self.inner.combat_entry_hook.as_ref() {
                hook();
            }
            let _ = token;
        } else if before == PostureKind::Combat && target != PostureKind::Combat {
            // COMBAT → non-COMBAT: release hook consumes the token
            // when present (identical to admin_release_combat_with_token).
            // When no hook is configured, the token binding falls
            // out of scope on return.
            if let Some(hook) = self.inner.combat_release_hook.as_ref() {
                hook(token);
            } else {
                let _ = token;
            }
        } else {
            // Lateral non-COMBAT transition (e.g., Alerted →
            // Engaged). No hook fires.
            let _ = token;
        }

        Ok(next)
    }

    /// Test-only hatch used by the `nn-admin debug --force-posture`
    /// integration scenario. Bypasses every trigger and decay rule
    /// to slam the state machine to `target`. Only compiled when
    /// the `debug-trigger` Cargo feature is on; refusing to build it
    /// in production prevents accidental misuse.
    #[cfg(feature = "debug-trigger")]
    pub fn force_state_for_test(&self, target: PostureKind) {
        let now = Instant::now();
        let mut guard = self.inner.state.write();
        let before = guard.kind();
        let next = match target {
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
        };
        *guard = next;
        drop(guard);
        let after = target;
        if before != after {
            self.log_transition(
                before,
                after,
                None,
                "debug-trigger force_state_for_test".into(),
            );
            if before != PostureKind::Combat && after == PostureKind::Combat {
                if let Some(hook) = self.inner.combat_entry_hook.as_ref() {
                    hook();
                }
            }
        }
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
