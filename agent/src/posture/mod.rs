//! Adaptive Defensive Posture state machine (Sub-tappa 6.5).
//!
//! NorthNarrow keeps a 4-tier posture (`OBSERVING < ALERTED < ENGAGED
//! < COMBAT`) that is *persistent across events*. Most commercial
//! EDRs evaluate every event in isolation; we don't. The posture
//! shifts up as evidence accumulates (recon → exploit → confirmed
//! intrusion) and:
//!
//! - engages the COMBAT active-response ladder ([`crate::combat`]) when
//!   it reaches `COMBAT`,
//! - blocks automatic exit from `COMBAT` (admin-signed release only).
//!
//! It also used to modulate the verdicts of the on-host LLM advisor
//! (an ambiguous `Allow` became an `Alert` once the posture was hot); the
//! advisor and that modulation were removed in Wave 4 (lab PR 214).
//!
//! Public surface:
//!
//! - [`PostureMachine`] is the runtime handle. Cheap to clone
//!   (`Arc`-backed) and `Send + Sync`. Construct once, share across
//!   tokio tasks.
//! - [`PostureState`] is the live state (with monotonic
//!   [`Instant`](std::time::Instant) timestamps).
//! - [`nn_model::posture_types::PostureKind`] is the serializable
//!   projection used in logs and on the wire.
//! - [`TriggerDetector`] / [`triggers`] enumerate every condition
//!   that can move the posture up.
//!
//! Decay is monotonic-clock based (immune to wall-clock skew): the
//! caller is expected to invoke [`PostureMachine::tick_decay`] on a
//! periodic timer (60 s in `agent/src/main.rs`). Lab PR 243: the machine
//! reads both clocks through [`clock::Clock`] (the host's by default), so
//! the golden replay (`posture::golden`) runs it on a clock of its own.
//!
//! Admin release from `COMBAT` is a stub for Sub-tappa 6.5 — it
//! takes a boolean flag. The Tappa 8 milestone replaces it with an
//! Ed25519-signed command path.

pub mod clock;
pub mod entry;
pub mod triggers;
/// R08a shim (lab PR 250; plan §4.1 rule 2, removed in R17): the ledger, the
/// state, the transitions and the operator's two overlays are nn-core's.
pub use nn_core::posture::{
    corroboration, escalation_allow, mass_write_overlay, state, transitions,
};

/// R08a shim (lab PR 250): the lineage is nn-core's; the agent's tracker
/// reads the Linux host.
pub mod lineage {
    pub use nn_core::posture::lineage::*;

    /// [`nn_core::posture::lineage::AuthSessionTracker`] on the agent's host.
    pub type AuthSessionTracker =
        nn_core::posture::lineage::AuthSessionTracker<crate::chain_host_linux::LinuxHost>;
}

/// R08a shim (lab PR 250): the stack exemption is nn-core's; the agent's
/// reads the Linux host, and so do its two watchdog lookups, under their
/// names and signatures.
pub mod exempt {
    use std::path::{Path, PathBuf};

    use crate::chain_host_linux::LinuxHost;

    pub use nn_core::posture::exempt::*;

    /// [`nn_core::posture::exempt::ExemptPids`] on the agent's host.
    pub type ExemptPids = nn_core::posture::exempt::ExemptPids<LinuxHost>;

    /// [`nn_core::posture::exempt::sibling_watchdog_exe`] on the agent's
    /// host.
    pub fn sibling_watchdog_exe(own_exe: Option<&Path>) -> PathBuf {
        nn_core::posture::exempt::sibling_watchdog_exe::<LinuxHost>(own_exe)
    }

    /// [`nn_core::posture::exempt::resolve_verified_watchdog_pid`] on the
    /// agent's host.
    pub fn resolve_verified_watchdog_pid(
        pidfile: &Path,
        expected_exe: &Path,
    ) -> WatchdogResolution {
        nn_core::posture::exempt::resolve_verified_watchdog_pid::<LinuxHost>(pidfile, expected_exe)
    }
}

#[cfg(test)]
mod golden;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::{Instant, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};

use nn_model::posture_types::{
    Confidence, EvidenceClass, PostureKind, PostureTransition, TriggerType,
};
use nn_model::Event;

use crate::anti_tamper::network_isolate::UnlockToken;
use crate::decision::rule_policy::PolicyHandle;
use clock::Clock;
use corroboration::CorroborationLedger;
use escalation_allow::EscalationAllowList;

pub use entry::{CombatCause, CombatEntry, EntryProcess, TriggerEvidence};
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
/// COMBAT edge. The agent's `main.rs` wires it to the COMBAT ladder
/// (`CombatLadder::engage`). Stored as an `Arc<dyn Fn>` so the machine
/// itself can stay `Clone + Send + Sync`.
///
/// Lab PR 245: it receives the [`CombatEntry`] — the cause (the trigger
/// and the evidence it cites, or a forced COMBAT) and the process the
/// event names — so the ladder's episode opens with them. It took no
/// argument, and the episode opened without either.
pub type CombatEntryHook = Arc<dyn Fn(&CombatEntry) + Send + Sync>;

/// External audit POS-001: run when an unlocked COMBAT decays
/// ([`PostureMachine::on_combat_decay`]).
pub type CombatDecayHook = Arc<dyn Fn() + Send + Sync>;

/// What a release hook did with the containment (lab PR 217, NN-AUD-243
/// residue): `Ok` with what was released — the tables read back clear —
/// or `Err` with what is still in place, or could not be checked.
pub type ReleaseResult = std::result::Result<String, String>;

/// What a release covers (lab PR 217).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseScope {
    /// Leaving COMBAT: stand the ladder down, then lift the isolation.
    Combat,
    /// The posture is not in COMBAT: no ladder episode is touched; the
    /// tables are torn down and read back (an isolation is never legitimate
    /// outside COMBAT — a stale chain the boot teardown could not remove is
    /// lifted).
    IsolationOnly,
}

/// Hook invoked when the admin releases COMBAT via
/// [`PostureMachine::admin_release_combat_with_token`] (or forces the
/// posture out of it). Receives the validated [`UnlockToken`] by value so
/// the implementation can pass it straight into `NetworkIsolator::release`.
///
/// Lab PR 217 (NN-AUD-243 residue, capability C17): it returns what it did,
/// and runs BEFORE the posture leaves COMBAT, with no lock held (it shells
/// out to `iptables`) — the posture changes only after a verified release.
/// It used to return nothing and run after the state had already been
/// written ALERTED, so a teardown that failed was answered `Success` and
/// recorded as one.
pub type CombatReleaseHook = Arc<dyn Fn(UnlockToken, ReleaseScope) -> ReleaseResult + Send + Sync>;

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
    combat_decay_hook: std::sync::OnceLock<CombatDecayHook>,
    /// Lab PR 243: where the machine reads the time — the host's clocks
    /// ([`clock::SystemClock`]), or a replay's ([`PostureMachine::with_clock`]).
    clock: Arc<dyn Clock>,
    /// Lab PR 249: the per-rule policy this machine reads its ransomware
    /// directive from (`combat-without-corroboration NN-L-IMP-001`, lab PR
    /// 236) — production: the agent's `rule_policy::global()`, the handle
    /// the engine reads and `nn-admin policy set` swaps
    /// ([`PostureMachine::with_rule_policy`]); the built-in defaults
    /// otherwise. It was a process-wide switch.
    rule_policy: PolicyHandle,
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
                clock: Arc::new(clock::SystemClock),
                rule_policy: PolicyHandle::default(),
            }),
        }
    }

    /// Lab PR 243: run the machine on `clock` — its timers and the
    /// wall-clock second of its transition records — instead of the
    /// host's clocks (the golden replay of the posture). Call before the
    /// machine is shared (cloned); a later call is ignored, said so.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        match Arc::get_mut(&mut self.inner) {
            Some(inner) => inner.clock = clock,
            None => tracing::warn!("posture clock set after the machine was shared — ignored"),
        }
        self
    }

    /// Lab PR 249: read the ransomware directive of the per-rule policy
    /// `handle` holds — production: the agent's `rule_policy::global()`,
    /// so a policy `nn-admin policy set` puts in force reaches the posture
    /// at its next event, as it reaches the engine. Without it the machine
    /// reads the built-in defaults (off). Call before the machine is
    /// shared (cloned); a later call is ignored, said so.
    pub fn with_rule_policy(mut self, handle: PolicyHandle) -> Self {
        match Arc::get_mut(&mut self.inner) {
            Some(inner) => inner.rule_policy = handle,
            None => {
                tracing::warn!("posture rule policy set after the machine was shared — ignored")
            }
        }
        self
    }

    /// Whether RansomwareEncryption reaches COMBAT without corroboration on
    /// this machine now: the directive of the policy it reads (lab PR 236,
    /// 249).
    pub fn ransomware_combat_without_corroboration(&self) -> bool {
        self.inner
            .rule_policy
            .current()
            .ransomware_combat_without_corroboration
    }

    /// Tappa 10.9 step 1, lab PR 249: switch this machine's mass-write arm
    /// to the kernel count — set by `main.rs` once the LSM file-open sensor
    /// is armed (`MassWrite` events, carve-outs applied in the kernel) —
    /// or back to the userland count of `FileOpen` (tracepoint mode, the
    /// default). It was a process-wide switch.
    pub fn set_kernel_mass_write(&self, on: bool) {
        self.inner.triggers.set_kernel_mass_write(on);
    }

    /// Whether the mass-write arm reads the kernel count
    /// ([`Self::set_kernel_mass_write`]).
    pub fn kernel_mass_write(&self) -> bool {
        self.inner.triggers.kernel_mass_write()
    }

    /// The monotonic now of the machine's clock.
    fn now(&self) -> Instant {
        self.inner.clock.now()
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

    /// Lab PR 225: the ransomware tracker the rules share; the posture
    /// raises `RansomwareEncryption` on its decisive assessments. Unwired,
    /// the trigger never fires. Set once; a second call is ignored.
    pub fn set_ransom_tracker(&self, tracker: Arc<crate::impact::RansomTracker>) {
        self.inner.triggers.set_ransom_tracker(tracker);
    }

    /// Lab PR 225: the security-tool detector the rules share; the posture
    /// raises `DefenseImpairment` on its unsanctioned findings. Set once.
    pub fn set_defense_detector(&self, detector: Arc<crate::impair::DefenseDetector>) {
        self.inner.triggers.set_defense_detector(detector);
    }

    /// External audit POS-001: run `hook` when an unlocked COMBAT decays.
    /// Set once; a second call is ignored.
    pub fn on_combat_decay(&self, hook: CombatDecayHook) {
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
    /// `recent_events` should be the recent events the agent already
    /// keeps ([`crate::correlation::CorrelationBuffer`]).
    pub fn observe<'a>(
        &self,
        event: &Event,
        recent_events: impl Into<triggers::Recent<'a>>,
    ) -> Option<(PostureState, Option<TriggerType>)> {
        let now = self.now();
        let hits = self.inner.triggers.detect(event, recent_events);
        if hits.is_empty() {
            return None;
        }
        // Lab PR 249: the ransomware directive in force for this machine,
        // read once for the round (it was a process-wide switch, read at
        // each confidence).
        let ransomware_decisive = self.ransomware_combat_without_corroboration();
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
                    && t.confidence(ransomware_decisive) == Confidence::NeedsCorroboration
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
        // Lab PR 245: the trigger that crossed into COMBAT, when one did.
        let mut combat_by: Option<TriggerType> = None;
        for (t, level) in leveled {
            let next = transitions::apply_to_level(&current, level, now);
            if next.kind() > current.kind() {
                firing = Some(t);
                if next.kind() == PostureKind::Combat {
                    combat_by = Some(t);
                }
            }
            current = next;
        }
        // Lab PR 245: the signals a heuristic's COMBAT cites, read from the
        // ledger the decision read — before this round's signals are
        // recorded (audit `posture-1`: they never corroborate each other).
        let corroborated_by = match combat_by {
            Some(t) if t.confidence(ransomware_decisive) == Confidence::NeedsCorroboration => {
                ledger.corroborating(t, triggers::evidence_class(t, event), &scope)
            }
            _ => Vec::new(),
        };

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
                // Lab PR 225: by what locks, not by what is decisive — the
                // ransomware combination reaches COMBAT on its own but does
                // not lock it (`TriggerType::locks_combat`).
                || hits.iter().any(TriggerType::locks_combat)
                || (corroborated_here && (privileged_now || ledger.has_privileged(&scope)));
            lock_acquired = locked && !was_locked && before == PostureKind::Combat;
            current = PostureState::Combat { since, locked };
        }
        // Lab PR 245: what the entry hook hands the ladder — the trigger,
        // the evidence it cites and the process the event names.
        let entry = combat_by.map(|t| {
            CombatEntry::of_event(
                event,
                TriggerEvidence {
                    trigger: t,
                    raised: hits.clone(),
                    class: triggers::evidence_class(t, event),
                    confidence: t.confidence(ransomware_decisive),
                    corroborated_by,
                    locked: matches!(current, PostureState::Combat { locked: true, .. }),
                    scope: scope.to_string(),
                    event_kind: triggers::event_kind(event),
                    event_pid: triggers::event_owner_pid(event),
                    event_ns: Some(triggers::event_time_ns(event)).filter(|ns| *ns != 0),
                },
            )
        });

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
            // Combat-entry edge — fire the hook exactly once per upward
            // crossing: `entry` exists only when this round crossed into
            // COMBAT from below, so a re-trigger while already in Combat
            // does NOT re-engage the ladder. Lab PR 245: with the entry —
            // the ladder's episode opens with its trigger and offender.
            if let Some(entry) = &entry {
                debug_assert!(before != PostureKind::Combat && after == PostureKind::Combat);
                if let Some(hook) = self.inner.combat_entry_hook.as_ref() {
                    hook(entry);
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
        let now = self.now();
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

    /// Apply decay if the appropriate window has elapsed. Returns
    /// `Some(new_state)` if a transition fired.
    pub fn tick_decay(&self) -> Option<PostureState> {
        self.tick_decay_at(self.now())
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
        let now = self.now();
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

    /// Production path out of Combat — invoked from the agent's admin
    /// socket handler after a signed `unlock` verified (lab PR 217:
    /// `OperationCode::Unlock`). Runs the combat-release hook with the
    /// consumed token — the ladder stood down, then `NetworkIsolator::release`
    /// tears down the iptables ruleset and reads the tables back — and only
    /// once that succeeded drops the posture down to `Alerted` (NOT `Engaged`
    /// like the legacy bool stub).
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
    /// ## Truthful outcome (lab PR 217, NN-AUD-243 residue, C-25)
    ///
    /// The hook ran after the state was written ALERTED and returned
    /// nothing: an iptables teardown that failed still answered the
    /// operator `Success`, recorded "success", and left the host isolated
    /// in ALERTED. Now:
    /// - in COMBAT, a hook that fails returns
    ///   [`AdminReleaseError::ReleaseFailed`] and the posture stays COMBAT
    ///   (the ladder's episode is closed — its soft blocks lifted — and the
    ///   isolation still in place is what `nn-admin status` shows); a new
    ///   signed unlock retries the teardown;
    /// - outside COMBAT the hook still runs, without the ladder
    ///   ([`ReleaseScope::IsolationOnly`]: the tables torn down and read
    ///   back, e.g. a stale chain the boot teardown could not remove), and
    ///   its outcome is returned the same way — an unlock outside COMBAT is
    ///   idempotent when the tables read back clear.
    ///
    /// On success records the machine's now in `last_admin_action`,
    /// surfaced via [`Self::last_admin_action_secs_ago`] for the
    /// `nn-admin status` response.
    pub fn admin_release_combat_with_token(
        &self,
        token: UnlockToken,
    ) -> Result<ReleaseOutcome, AdminReleaseError> {
        let in_combat = matches!(*self.inner.state.read(), PostureState::Combat { .. });
        let scope = if in_combat {
            ReleaseScope::Combat
        } else {
            ReleaseScope::IsolationOnly
        };
        // No lock held: the hook shells out to iptables.
        let detail = match self.inner.combat_release_hook.as_ref() {
            Some(hook) => hook(token, scope).map_err(AdminReleaseError::ReleaseFailed)?,
            // In the no-hook configuration the token falls out of scope
            // here; UnlockToken has no Drop impl. The capability invariant
            // is intact because the token's *constructor* is what's
            // visibility-gated.
            None => "no isolation to release in this configuration".to_string(),
        };
        if !in_combat {
            return Ok(ReleaseOutcome {
                left_combat: false,
                state: self.current(),
                detail,
            });
        }
        let now = self.now();
        let mut guard = self.inner.state.write();
        if !matches!(*guard, PostureState::Combat { .. }) {
            // COMBAT ended while the release ran (an unlocked COMBAT that
            // decayed): the containment is released, the newer state stays.
            let state = guard.clone();
            drop(guard);
            *self.inner.last_admin_action.lock() = Some(now);
            return Ok(ReleaseOutcome {
                left_combat: false,
                state,
                detail,
            });
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
            "admin token release (isolation released, read back)".into(),
        );
        Ok(ReleaseOutcome {
            left_combat: true,
            state: next,
            detail,
        })
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
        let now = self.now();
        self.inner
            .last_admin_action
            .lock()
            .map(|t| now.saturating_duration_since(t).as_secs())
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
    /// Records the machine's now in `last_admin_action` on any
    /// actual transition — surfaced via
    /// [`Self::last_admin_action_secs_ago`] for `nn-admin status`.
    ///
    /// Returns a [`ForceOutcome`]: the state before the call and the
    /// post-transition [`PostureState`] (the unchanged state when
    /// before == target). External audit ASK-015: the caller logged the
    /// returned state as `from`, so every force-posture line said it left
    /// the state it entered; `from` is read under the same write lock as
    /// the transition, so no concurrent change can slip between them.
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
    ) -> Result<ForceOutcome, AdminReleaseError> {
        self.admin_force_state_signed_by(token, target, may_release, Vec::new())
    }

    /// [`Self::admin_force_state_with_token`], naming the keys that signed
    /// the request (lab PR 245): a COMBAT it enters cites them as its cause
    /// in the ladder's signed rows.
    pub fn admin_force_state_signed_by(
        &self,
        token: UnlockToken,
        target: PostureKind,
        may_release: bool,
        signers: Vec<String>,
    ) -> Result<ForceOutcome, AdminReleaseError> {
        let leaving_combat = {
            let guard = self.inner.state.read();
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
            before == PostureKind::Combat && target != PostureKind::Combat
        };
        // Lab PR 217 (NN-AUD-243 residue): COMBAT → non-COMBAT releases the
        // containment exactly like an unlock — the release runs first, with
        // no lock held, and the posture changes only if it was verified. A
        // failed release leaves COMBAT in place and returns why.
        let (token, release) = if leaving_combat {
            match self.inner.combat_release_hook.as_ref() {
                Some(hook) => {
                    let detail = hook(token, ReleaseScope::Combat)
                        .map_err(AdminReleaseError::ReleaseFailed)?;
                    (None, Some(detail))
                }
                None => (Some(token), None),
            }
        } else {
            (Some(token), None)
        };
        let now = self.now();
        let mut guard = self.inner.state.write();
        let before = guard.kind();
        if before == PostureKind::Combat && target != PostureKind::Combat {
            // External audit NN-AUD-083: checked under the write lock too —
            // an autonomous COMBAT entry may have landed since the read.
            if !may_release {
                drop(guard);
                tracing::warn!(
                    to = ?target,
                    "force-posture out of COMBAT refused: it needs the unlock role"
                );
                return Err(AdminReleaseError::NeedsUnlock);
            }
            if !leaving_combat {
                // COMBAT was entered while the request ran: its containment
                // was not released, so the posture does not leave it.
                drop(guard);
                return Err(AdminReleaseError::ReleaseFailed(
                    "COMBAT was entered while the request ran — nothing was changed; send it \
                     again"
                        .to_string(),
                ));
            }
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
            return Ok(ForceOutcome {
                from: before,
                state: next,
                release,
            });
        }

        *self.inner.last_admin_action.lock() = Some(now);
        self.log_transition(before, target, None, "admin token force-posture".into());

        // Side-effects per §12.2.
        if before != PostureKind::Combat && target == PostureKind::Combat {
            // Non-COMBAT → COMBAT: entry hook fires (the ladder engages).
            // The entry hook takes the entry, not the `UnlockToken` (entry
            // isn't gated by capability — detectors can fire it
            // autonomously). Lab PR 245: the cause is the administrator's
            // signed order, naming the keys; no process. The `token`
            // binding falls out of scope on return.
            if let Some(hook) = self.inner.combat_entry_hook.as_ref() {
                hook(&CombatEntry::forced(CombatCause::AdminForce { signers }));
            }
            let _ = token;
        } else if before == PostureKind::Combat && target != PostureKind::Combat {
            // COMBAT → non-COMBAT: same ledger reset as the release verbs;
            // the release itself ran above, before the transition.
            self.clear_corroboration_on_release();
            let _ = token;
        } else {
            // Lateral non-COMBAT transition (e.g., Alerted →
            // Engaged). No hook fires.
            let _ = token;
        }

        Ok(ForceOutcome {
            from: before,
            state: next,
            release,
        })
    }

    /// Test-only hatch used by the `nn-admin debug --force-posture`
    /// integration scenario. Bypasses every trigger and decay rule
    /// to slam the state machine to `target`. Only compiled when
    /// the `debug-trigger` Cargo feature is on; refusing to build it
    /// in production prevents accidental misuse.
    #[cfg(feature = "debug-trigger")]
    pub fn force_state_for_test(&self, target: PostureKind) {
        let now = self.now();
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
                    hook(&CombatEntry::forced(CombatCause::DebugForce));
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
        let unix_ts_secs = self
            .inner
            .clock
            .wall()
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

/// What [`PostureMachine::admin_force_state_with_token`] did. External
/// audit ASK-015: the state the agent was in before the force is what the
/// journal line and the audit row record as `from`; the in-memory
/// transition log that also has it is capped and not persisted.
#[derive(Debug, Clone)]
pub struct ForceOutcome {
    /// The state before the call, read under the transition's write lock.
    pub from: PostureKind,
    /// The state after it (the target; unchanged when `from` was already
    /// the target).
    pub state: PostureState,
    /// Lab PR 217: what the release hook released, when the force left
    /// COMBAT (`None` otherwise, or without a hook).
    pub release: Option<String>,
}

/// What [`PostureMachine::admin_release_combat_with_token`] did (lab PR
/// 217).
#[derive(Debug, Clone)]
pub struct ReleaseOutcome {
    /// The posture left COMBAT (to ALERTED) — `false` when it was not in
    /// COMBAT, or left it on its own while the release ran.
    pub left_combat: bool,
    /// The posture after the call.
    pub state: PostureState,
    /// What the release hook released (the tables read back clear).
    pub detail: String,
}

/// Reasons [`PostureMachine::admin_release_combat_with_token`],
/// [`PostureMachine::admin_force_state_with_token`] and the test-only
/// `admin_release_combat` can refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminReleaseError {
    Unauthorized,
    NotInCombat,
    /// External audit NN-AUD-083: a force-posture out of COMBAT signed
    /// without the `unlock` role.
    NeedsUnlock,
    /// Lab PR 217 (NN-AUD-243 residue): the release ran and did not leave
    /// the tables clear (read back), or could not be checked — what is
    /// still in place. The posture stayed COMBAT.
    ReleaseFailed(String),
}

impl core::fmt::Display for AdminReleaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdminReleaseError::Unauthorized => f.write_str("admin override not authorized"),
            AdminReleaseError::NotInCombat => f.write_str("posture is not in COMBAT"),
            AdminReleaseError::NeedsUnlock => {
                f.write_str("leaving COMBAT needs a signer holding the unlock role")
            }
            AdminReleaseError::ReleaseFailed(why) => {
                write!(
                    f,
                    "the isolation was not released (posture stays COMBAT): {why}"
                )
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
