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

pub mod corroboration;
pub mod escalation_allow;
pub mod exempt;
pub mod lineage;
pub mod mass_write_overlay;
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
use common::posture_types::{
    Confidence, EvidenceClass, PostureKind, PostureTransition, TriggerType,
};
use common::Event;

use crate::anti_tamper::network_isolate::UnlockToken;
use corroboration::CorroborationLedger;
use escalation_allow::EscalationAllowList;

pub use exempt::{
    resolve_verified_watchdog_pid, sibling_watchdog_exe, ExemptPids, WatchdogResolution,
    DEFAULT_WATCHDOG_EXE, DEFAULT_WATCHDOG_PIDFILE,
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
    /// BUG-032 — recent escalation signals, used to decide whether a
    /// blunt COMBAT-tier heuristic has corroboration. Only ever touched
    /// inside `observe()`'s `state.write()` critical section (consistent
    /// lock order, no hazard).
    corroboration: Mutex<CorroborationLedger>,
    combat_entry_hook: Option<CombatEntryHook>,
    combat_release_hook: Option<CombatReleaseHook>,
    /// Monotonic timestamp of the most recent successful admin
    /// release. `None` if no admin action has occurred since boot.
    /// Read by `StatusResponse` via [`PostureMachine::last_admin_action_secs_ago`].
    last_admin_action: Mutex<Option<Instant>>,
    /// External audit POS-001: run when an unlocked COMBAT decays (the
    /// agent stands the ladder down). Set once at boot.
    combat_decay_hook: std::sync::OnceLock<CombatEntryHook>,
}

impl PostureMachine {
    pub fn new() -> Self {
        Self::build(
            None,
            None,
            ExemptPids::default(),
            AuthSessionTracker::default(),
            Vec::new(),
            EscalationAllowList::empty(),
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
            Vec::new(),
            EscalationAllowList::empty(),
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
            Vec::new(),
            EscalationAllowList::empty(),
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
            Vec::new(),
            EscalationAllowList::empty(),
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
            Vec::new(),
            EscalationAllowList::empty(),
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
        Self::build(
            Some(entry),
            Some(release),
            exempt,
            auth,
            Vec::new(),
            EscalationAllowList::empty(),
        )
    }

    /// BUG-017 P-8 production constructor — like
    /// [`Self::new_with_hooks_and_exempt_and_auth`] but also accepts
    /// the operator-supplemental mass-write path-prefix carve-out list
    /// (loaded from `/etc/northnarrow/mass-write-carveout.local` at
    /// agent boot). Empty list = same behaviour as the simpler
    /// constructor.
    pub fn new_with_hooks_and_exempt_and_auth_and_extras(
        entry: CombatEntryHook,
        release: CombatReleaseHook,
        exempt: ExemptPids,
        auth: AuthSessionTracker,
        mass_write_extras: Vec<String>,
        escalation_allow: EscalationAllowList,
    ) -> Self {
        Self::build(
            Some(entry),
            Some(release),
            exempt,
            auth,
            mass_write_extras,
            escalation_allow,
        )
    }

    fn build(
        combat_entry_hook: Option<CombatEntryHook>,
        combat_release_hook: Option<CombatReleaseHook>,
        exempt: ExemptPids,
        auth: AuthSessionTracker,
        mass_write_extras: Vec<String>,
        escalation_allow: EscalationAllowList,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(PostureState::default()),
                transitions: RwLock::new(Vec::new()),
                triggers: TriggerDetector::with_exempt_and_auth(exempt, auth)
                    .with_mass_write_extras(mass_write_extras)
                    .with_escalation_allow(escalation_allow),
                corroboration: Mutex::new(CorroborationLedger::new()),
                combat_entry_hook,
                combat_release_hook,
                last_admin_action: Mutex::new(None),
                combat_decay_hook: std::sync::OnceLock::new(),
            }),
        }
    }

    /// External audit POS-001: COMBAT on evidence an unprivileged user
    /// cannot produce (or forced by an administrator) — the only COMBAT in
    /// which the ladder may isolate the host.
    pub fn is_combat_locked(&self) -> bool {
        matches!(
            *self.inner.state.read(),
            PostureState::Combat { locked: true, .. }
        )
    }

    /// Lab PR 162: the trusted-installer window, inside which a tamper of
    /// an anti-tamper control-surface file does not raise the posture (the
    /// FIM-024 rule still acts). Unwired, the trigger always fires. Set
    /// once; a second call is ignored.
    pub fn set_installer_window(
        &self,
        window: Arc<crate::anti_tamper::trusted_installer::TrustedInstallerOverride>,
    ) {
        self.inner.triggers.set_installer_window(window);
    }

    /// External audit POS-001: run `hook` when an unlocked COMBAT decays.
    /// Set once; a second call is ignored.
    pub fn on_combat_decay(&self, hook: CombatEntryHook) {
        let _ = self.inner.combat_decay_hook.set(hook);
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
    pub fn observe<'a>(
        &self,
        event: &Event,
        recent_events: impl Into<triggers::Recent<'a>>,
    ) -> Option<(PostureState, Option<TriggerType>)> {
        let now = Instant::now();
        let hits = self.inner.triggers.detect(event, recent_events);
        if hits.is_empty() {
            return None;
        }
        // Review `posture-ledger-scope-1`: corroboration is per actor
        // scope; a weak signal from one user, service or container never
        // vouches for a blunt signal from another (external audit POS-005:
        // a container, and a process with no login uid, is scoped by its
        // workload).
        let scope = self.inner.triggers.session_scope(event);
        // Review 52, read before the state lock (they read `/proc`); see
        // the recording below.
        let admin_change = self.inner.triggers.admin_change_status(event);
        {
            let mut ledger = self.inner.corroboration.lock();
            ledger.prune(now);
            if ledger.has_pending() {
                ledger.resolve_pending(|pid| self.inner.triggers.place_writer(pid));
            }
        }

        let mut guard = self.inner.state.write();
        let mut ledger = self.inner.corroboration.lock();
        ledger.prune(now);

        // BUG-032 — escalation signals (ENGAGED-tier and above) this
        // round. They seed the ledger for LATER rounds (never this one,
        // see posture-1 below); ALERTED-tier recon/DNS is too noisy to
        // count as corroboration, and so is a staging-directory exec with
        // no second factor (external audit POS-015).
        let escalation_now: Vec<TriggerType> = hits
            .iter()
            .copied()
            .filter(TriggerType::is_corroboration)
            .collect();

        // Effective level: a blunt (NeedsCorroboration) COMBAT-tier
        // signal is capped at ENGAGED unless a distinct PRIOR escalation
        // signal in the ledger corroborates it. Decisive
        // (kernel-adjudicated) signals reach COMBAT on their own.
        //
        // Audit `posture-1`: signals raised in the SAME `detect()` round
        // deliberately do NOT corroborate each other. One `FileOpen`
        // under `/etc/systemd/system/` can raise both the mass-write
        // arm of ConfirmedIntrusion and PersistenceMechanism at once;
        // letting them vouch for each other collapsed OBSERVING→COMBAT
        // (locked, isolation ladder armed) in a single hop on a routine
        // bulk unit install. The ledger — written AFTER this read — is
        // the only corroboration source, so a blunt signal needs a
        // second, earlier signal within the corroboration window:
        // at most one tier of blunt escalation per round.
        let mut leveled: Vec<(TriggerType, PostureKind)> = hits
            .iter()
            .copied()
            .map(|t| {
                let level = if t.target_level() == PostureKind::Combat
                    && t.confidence() == Confidence::NeedsCorroboration
                {
                    if ledger.corroborated_as(t, triggers::evidence_class(t, event), &scope) {
                        PostureKind::Combat
                    } else {
                        PostureKind::Engaged
                    }
                } else {
                    t.target_level()
                };
                (t, level)
            })
            .collect();
        // Strongest EFFECTIVE level decides the destination. Equal-level
        // triggers collapse to a single transition.
        leveled.sort_by_key(|(_, level)| *level);
        // External audit POS-005: this round's signal is corroborated in its
        // own scope — by an earlier signal of another kind from the same
        // actor — whatever its tier (a root `sshd_config` edit is ENGAGED
        // tier).
        let corroborated_here = escalation_now
            .iter()
            .any(|t| ledger.corroborated_as(*t, triggers::evidence_class(*t, event), &scope));

        let before = guard.kind();
        let mut current = (*guard).clone();
        let mut firing: Option<TriggerType> = None;
        for (t, level) in leveled {
            let next = transitions::apply_to_level(&current, level, now);
            if next.kind() > current.kind() {
                firing = Some(t);
            }
            current = next;
        }

        // External audit POS-001 (NN-AUD-002): COMBAT is LOCKED — no decay,
        // a signed release, and the ladder may isolate the host — only on
        // evidence an unprivileged user cannot produce: a kernel-adjudicated
        // signal, or root changing a system file outside an administrator's
        // interactive session. COMBAT reached on heuristics alone (two
        // patterns any user can trigger) is unlocked: the ladder stays at
        // the process level and the posture decays once quiet.
        //
        // External audit POS-005: root's change locks COMBAT only when its
        // own actor's evidence pairs with it — this round's signal
        // corroborated in its scope. A root daemon rewriting a unit file
        // (puppet, salt) while another actor's COMBAT ran unlocked used to
        // lock it: no decay, and isolation if NEUTRALIZE failed.
        let file_system =
            |t: &TriggerType| triggers::evidence_class(*t, event) == EvidenceClass::FileSystem;
        let root_change =
            triggers::event_uid(event) == Some(0) && escalation_now.iter().any(file_system);
        let privileged_now = root_change && admin_change == Some(false);
        let mut lock_acquired = false;
        if let PostureState::Combat { since, .. } = current {
            let was_locked = matches!(*guard, PostureState::Combat { locked: true, .. });
            let locked = was_locked
                || hits.iter().any(|t| t.confidence() == Confidence::Decisive)
                || (corroborated_here && (privileged_now || ledger.has_privileged(&scope)));
            lock_acquired = locked && !was_locked && before == PostureKind::Combat;
            current = PostureState::Combat { since, locked };
        }

        // Record this round's escalation signals AFTER the decision, so
        // the current signal does not self-corroborate via the ledger
        // (same-round corroboration is handled by `escalation_now`).
        //
        // Review 52: a configuration change written in an administrator's
        // interactive sudo/su session still raises the posture, but it is
        // not recorded as corroboration. Editing `sshd_config` and then
        // adding a unit is routine administration; recorded, the first
        // signal promoted the second to COMBAT and the ladder then killed
        // the session's writer. A prior signal of another kind in the same
        // session (an exploit tool, exfiltration) still promotes it. A
        // short-lived writer (`sudo tee`) has often exited before its exec
        // event is read; its change is then recorded pending, and placed
        // when the next signal consults the ledger.
        for t in &escalation_now {
            let config_change = matches!(
                t,
                TriggerType::CriticalFileModification | TriggerType::PersistenceMechanism
            );
            match (
                config_change,
                admin_change,
                triggers::event_owner_pid(event),
            ) {
                (true, Some(true), _) => {}
                (true, None, Some(writer)) => ledger.record_pending(
                    *t,
                    now,
                    scope.clone(),
                    writer,
                    root_change && file_system(t),
                ),
                _ => ledger.record_with(
                    *t,
                    triggers::evidence_class(*t, event),
                    now,
                    scope.clone(),
                    privileged_now && file_system(t),
                ),
            }
        }
        drop(ledger);

        let after = current.kind();
        *guard = current.clone();
        drop(guard);
        if lock_acquired {
            tracing::warn!(
                triggers = %describe_triggers(&hits),
                %scope,
                "COMBAT locked: evidence an unprivileged user cannot produce — the ladder may \
                 isolate the host, and only a signed release ends COMBAT"
            );
        }

        if after != before {
            // External audit POS-005: whose signal moved the posture.
            tracing::info!(
                from = %before,
                to = %after,
                triggers = %describe_triggers(&hits),
                %scope,
                "posture signal scope"
            );
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
            Some((current, firing))
        } else {
            None
        }
    }

    /// External audit SNS-009: raise a trigger that no event carries (a
    /// ring buffer that lost events). Only ALERTED-tier triggers are
    /// accepted: they move the posture up to their level (or re-arm its
    /// decay) and are never written to the corroboration ledger, so they
    /// can never vouch for a COMBAT-tier heuristic. Anything stronger is
    /// refused (`None`, nothing changes): escalation must come from an
    /// event the trigger detector adjudicated.
    pub fn raise_signal(&self, trigger: TriggerType, reason: &str) -> Option<PostureState> {
        if trigger.target_level() > PostureKind::Alerted {
            tracing::warn!(%trigger, "raise_signal refused: only ALERTED-tier signals are accepted");
            return None;
        }
        let now = Instant::now();
        let mut guard = self.inner.state.write();
        let before = guard.kind();
        let next = transitions::apply_to_level(&guard, trigger.target_level(), now);
        let after = next.kind();
        *guard = next.clone();
        drop(guard);
        if after != before {
            self.log_transition(before, after, Some(trigger), format!("{trigger}: {reason}"));
            Some(next)
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
        self.tick_decay_at(Instant::now())
    }

    /// [`Self::tick_decay`] as of `now`.
    ///
    /// External audit POS-001: an unlocked COMBAT (heuristic evidence
    /// only) decays to ENGAGED once no escalation signal has been recorded
    /// for [`transitions::COMBAT_QUIET_WINDOW`]; the decay hook stands the
    /// ladder down. A locked COMBAT never decays.
    pub fn tick_decay_at(&self, now: Instant) -> Option<PostureState> {
        let mut guard = self.inner.state.write();
        if let PostureState::Combat {
            since,
            locked: false,
        } = *guard
        {
            let newest = self.inner.corroboration.lock().newest();
            let quiet_since = newest.map_or(since, |n| n.max(since));
            if now.saturating_duration_since(quiet_since) < transitions::COMBAT_QUIET_WINDOW {
                return None;
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
                "unlocked COMBAT (heuristic evidence only) quiet: decay COMBAT -> ENGAGED".into(),
            );
            if let Some(hook) = self.inner.combat_decay_hook.get() {
                hook();
            }
            return Some(next);
        }
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
    /// kept for the older unit tests of the state machine; production
    /// code uses [`Self::admin_release_combat_with_token`], wired from
    /// `ConnAuth::verify_unlock` in the admin socket.
    ///
    /// It leaves COMBAT on a `bool`, without the release hook (no
    /// isolation lift, no ladder stand-down) and without recording an
    /// admin action. External audit POS-013 compiled it only for the unit
    /// tests and the `posture-demo` feature; WDG-R02 (NN-AUD-368) makes it
    /// a crate-private test helper: no build of the library, the demo
    /// example's included, has such a door, and `examples/posture_demo.rs`
    /// ends in COMBAT, whose exit is the signed unlock.
    #[cfg(test)]
    pub(crate) fn admin_release_combat(
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
        self.clear_corroboration_on_release();
        self.log_transition(
            PostureKind::Combat,
            PostureKind::Engaged,
            None,
            "admin override".into(),
        );
        Ok(next)
    }

    /// Production path out of Combat — invoked from the agent's
    /// admin socket handler after `ConnAuth::verify_unlock` returns
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
    /// predate the Tappa 7/8 work. That stub is a crate-private helper
    /// of the unit tests (external audit POS-013, WDG-R02); the asymmetry
    /// is intentional and deliberate.
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
        self.clear_corroboration_on_release();
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
    /// Audit `posture-2`: an admin release adjudicates the signals
    /// that built up to COMBAT. Wipe the corroboration ledger so they
    /// cannot vouch for the next blunt heuristic and re-lock COMBAT
    /// minutes after a signed unlock.
    fn clear_corroboration_on_release(&self) {
        let mut ledger = self.inner.corroboration.lock();
        let dropped = ledger.len();
        ledger.clear();
        drop(ledger);
        if dropped > 0 {
            tracing::info!(dropped, "corroboration ledger cleared on admin release");
        }
    }

    /// Number of signals currently in the corroboration ledger.
    pub fn corroboration_len(&self) -> usize {
        self.inner.corroboration.lock().len()
    }

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
    /// state when before == target).
    ///
    /// External audit NN-AUD-083: COMBAT → non-COMBAT releases the
    /// containment exactly like an unlock, so it needs `may_release`
    /// (a signer holding the `unlock` role). Without it the call returns
    /// [`AdminReleaseError::NeedsUnlock`] and leaves the state untouched.
    /// The check runs under the state write lock: a check by the caller
    /// before the call would race with an autonomous COMBAT entry.
    pub fn admin_force_state_with_token(
        &self,
        token: UnlockToken,
        target: PostureKind,
        may_release: bool,
    ) -> Result<PostureState, AdminReleaseError> {
        let now = Instant::now();
        let mut guard = self.inner.state.write();
        let before = guard.kind();
        if before == PostureKind::Combat && target != PostureKind::Combat && !may_release {
            drop(guard);
            let _ = token;
            tracing::warn!(
                to = ?target,
                "force-posture out of COMBAT refused: it needs the unlock role"
            );
            return Err(AdminReleaseError::NeedsUnlock);
        }
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
            // COMBAT → non-COMBAT: same ledger reset as the release verbs.
            self.clear_corroboration_on_release();
            // Release hook consumes the token
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

/// Reasons [`PostureMachine::admin_release_combat_with_token`],
/// [`PostureMachine::admin_force_state_with_token`] and the test-only
/// `admin_release_combat` can refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminReleaseError {
    Unauthorized,
    NotInCombat,
    /// External audit NN-AUD-083: a force-posture out of COMBAT signed
    /// without the `unlock` role.
    NeedsUnlock,
}

impl core::fmt::Display for AdminReleaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdminReleaseError::Unauthorized => f.write_str("admin override not authorized"),
            AdminReleaseError::NotInCombat => f.write_str("posture is not in COMBAT"),
            AdminReleaseError::NeedsUnlock => {
                f.write_str("leaving COMBAT needs a signer holding the unlock role")
            }
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
