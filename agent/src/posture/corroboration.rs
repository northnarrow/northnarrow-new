//! COMBAT escalation corroboration (BUG-032).
//!
//! A NeedsCorroboration COMBAT-tier trigger (the blunt network/file
//! heuristics) escalates to ENGAGED on its own and reaches COMBAT only
//! with a SECOND distinct escalation signal within
//! [`CORROBORATION_WINDOW`]. Decisive triggers (kernel-adjudicated,
//! [`common::posture_types::Confidence::Decisive`]) bypass this and
//! reach COMBAT immediately. This makes the FSM ladder
//! (Observing→Alerted→Engaged→Combat) mean what it says, instead of a
//! single blunt heuristic jumping straight to locked isolation.
//!
//! ## Documented beta limit — single-vector
//!
//! With [`SUSTAINED_SAME_TYPE_PROMOTES`] = `false` (default), a
//! single-vector attack — even sustained (pure massive exfil with no
//! other distinct signal) — tops out at ENGAGED (alert), never
//! auto-isolates. This is a deliberate precision-over-autonomous-
//! completeness choice for beta: the operator sees the alert and acts.
//! The sustained knob exists if single-vector autonomy is later
//! required. (BUG-032.)

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use common::posture_types::{EvidenceClass, TriggerType};

/// Calibration knob (NOT a fixed constant — tune on the VM). Window in
/// which a second distinct escalation signal corroborates a blunt
/// COMBAT-tier heuristic.
pub const CORROBORATION_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Defensive bound on ledger size vs a trigger flood. The time window
/// is the primary prune; this caps a burst.
const LEDGER_CAP: usize = 64;

/// Single-vector knob — OFF by default. When `true`, the SAME trigger
/// firing >= [`SUSTAINED_SAME_TYPE_MIN`] times in-window self-
/// corroborates (covers a pure single-vector attack at the cost of more
/// false positives). See the module-level note on the beta limit.
pub const SUSTAINED_SAME_TYPE_PROMOTES: bool = false;
const SUSTAINED_SAME_TYPE_MIN: usize = 2;

/// Which "actor" a signal belongs to, for corroboration purposes (review
/// `posture-ledger-scope-1`). Signals corroborate each other only within
/// the same scope: two weak signals from two unrelated users, services or
/// containers do not add up to a host-wide COMBAT.
///
/// External audit POS-005: every process without a login uid — each
/// daemon, each container — used to share one host-level scope (`None`),
/// and with it the lock: a root daemon changing a unit file locked a
/// COMBAT that any other daemon or container then corroborated. Interim,
/// without a wire change: a process with no login uid is scoped by the
/// workload its cgroup names; the full fix is the workload-context design
/// (`TAPPA10_9_WORKLOAD_CONTEXT_DESIGN.md` §4.3), which carries the cgroup
/// id in every record and scopes a login session by workload too.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// A PAM login session: its login uid (inherited by everything the
    /// session runs, `sudo` included).
    Login(u32),
    /// No login uid: the workload the process's cgroup names — a systemd
    /// unit or a container — as the cgroup path up to that unit
    /// (`/system.slice/puppet.service`, `/system.slice/docker-<id>.scope`).
    Workload(String),
    /// Neither could be read: no owning pid, or the owner and every
    /// ancestor the spawn cache knows have exited. Recorded, but it never
    /// corroborates, is never corroborated and never locks COMBAT: a
    /// signal that cannot be placed must not vouch for any actor.
    Unattributed,
}

impl Scope {
    /// Signals in this scope may corroborate each other.
    pub fn is_attributed(&self) -> bool {
        !matches!(self, Scope::Unattributed)
    }
}

impl core::fmt::Display for Scope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Scope::Login(uid) => write!(f, "login uid {uid}"),
            Scope::Workload(w) => write!(f, "workload {w}"),
            Scope::Unattributed => f.write_str("unattributed"),
        }
    }
}

#[derive(Clone)]
struct LedgerEntry {
    trigger: TriggerType,
    /// External audit POS-001: the kind of evidence it is.
    class: EvidenceClass,
    at: Instant,
    scope: Scope,
    /// Review 52: the writer of a configuration change that could not be
    /// placed when it was recorded (it had exited and its exec event was
    /// still in flight). It corroborates nothing until
    /// [`CorroborationLedger::resolve_pending`] finds it was not an
    /// administrator's interactive session.
    pending_writer: Option<u32>,
    /// External audit POS-001: root changed a system file (a file-system
    /// signal from uid 0) — evidence an unprivileged user cannot produce,
    /// which locks COMBAT and allows isolation.
    privileged: bool,
}

/// Bounded, in-memory record of recent escalation signals (ENGAGED-tier
/// and above), used to decide whether a blunt COMBAT-tier signal has
/// independent corroboration. Lives in `PostureMachine::Inner` and is
/// only ever touched inside `observe()`'s state-write critical section.
#[derive(Default)]
pub struct CorroborationLedger {
    entries: VecDeque<LedgerEntry>,
}

impl CorroborationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop entries older than the window, then cap the size. Call
    /// before every query/record.
    pub fn prune(&mut self, now: Instant) {
        while self
            .entries
            .front()
            .is_some_and(|e| now.saturating_duration_since(e.at) > CORROBORATION_WINDOW)
        {
            self.entries.pop_front();
        }
        while self.entries.len() > LEDGER_CAP {
            self.entries.pop_front();
        }
    }

    /// Is there a DISTINCT escalation signal already in the ledger
    /// (corroborating `current`)? With the sustained knob on, a
    /// sufficiently-repeated SAME signal also corroborates.
    ///
    /// Caller must [`prune`](Self::prune) first.
    pub fn corroborated(&self, current: TriggerType, scope: &Scope) -> bool {
        self.corroborated_as(current, current.evidence_class(), scope)
    }

    /// [`Self::corroborated`] for `current` raised as evidence of `class`
    /// (see `triggers::evidence_class`).
    pub fn corroborated_as(
        &self,
        current: TriggerType,
        class: EvidenceClass,
        scope: &Scope,
    ) -> bool {
        // External audit POS-005: a signal that cannot be placed is
        // corroborated by nothing.
        if !scope.is_attributed() {
            return false;
        }
        // posture-ledger-scope-1: only same-scope entries count.
        let same_scope = self
            .entries
            .iter()
            .filter(|e| e.scope == *scope && e.pending_writer.is_none());
        // External audit POS-001 (NN-AUD-002): a different kind of
        // evidence, not merely a different trigger of the same kind.
        if same_scope.clone().any(|e| e.class != class) {
            return true;
        }
        SUSTAINED_SAME_TYPE_PROMOTES
            && same_scope.filter(|e| e.trigger == current).count() + 1 >= SUSTAINED_SAME_TYPE_MIN
    }

    /// Record an escalation signal. The caller records only signals
    /// whose `target_level() >= Engaged` (ALERTED-tier recon/DNS is too
    /// noisy to count as corroboration).
    pub fn record(&mut self, trigger: TriggerType, at: Instant, scope: Scope) {
        self.record_with(trigger, trigger.evidence_class(), at, scope, false);
    }

    /// [`Self::record`] as evidence of `class`, marking a privileged
    /// signal (external audit POS-001: root changing a system file).
    pub fn record_with(
        &mut self,
        trigger: TriggerType,
        class: EvidenceClass,
        at: Instant,
        scope: Scope,
        privileged: bool,
    ) {
        self.entries.push_back(LedgerEntry {
            trigger,
            class,
            at,
            scope,
            pending_writer: None,
            privileged,
        });
    }

    /// External audit POS-001: a privileged signal is on record in `scope`.
    /// External audit POS-005: never in [`Scope::Unattributed`].
    pub fn has_privileged(&self, scope: &Scope) -> bool {
        scope.is_attributed()
            && self
                .entries
                .iter()
                .any(|e| e.scope == *scope && e.privileged && e.pending_writer.is_none())
    }

    /// External audit POS-001: when the newest signal was recorded (any
    /// scope); `None` when the ledger is empty. An unlocked COMBAT decays
    /// once this is a quiet window old.
    pub fn newest(&self) -> Option<Instant> {
        self.entries.iter().map(|e| e.at).max()
    }

    /// Review 52: record a configuration change whose writer could not be
    /// placed yet. See [`Self::resolve_pending`]. `privileged` (external
    /// audit POS-001) takes effect only once the writer is placed outside
    /// an administrator's session.
    pub fn record_pending(
        &mut self,
        trigger: TriggerType,
        at: Instant,
        scope: Scope,
        writer: u32,
        privileged: bool,
    ) {
        self.entries.push_back(LedgerEntry {
            class: trigger.evidence_class(),
            trigger,
            at,
            scope,
            pending_writer: Some(writer),
            privileged,
        });
    }

    /// Review 52: place the pending writers. `place` answers `None` while
    /// it still cannot tell (the entry stays pending), else whether the
    /// writer was an administrator's interactive session (the entry is
    /// dropped: routine administration corroborates nothing) and its
    /// session's scope (otherwise the entry becomes an ordinary signal in
    /// that scope). Call after [`Self::prune`], before
    /// [`Self::corroborated`].
    pub fn resolve_pending(&mut self, place: impl Fn(u32) -> Option<(bool, Scope)>) {
        self.entries
            .retain_mut(|e| match e.pending_writer.map(&place) {
                Some(Some((true, _))) => false,
                Some(Some((false, scope))) => {
                    e.pending_writer = None;
                    e.scope = scope;
                    true
                }
                _ => true,
            });
    }

    /// `true` when an entry still waits for [`Self::resolve_pending`].
    pub fn has_pending(&self) -> bool {
        self.entries.iter().any(|e| e.pending_writer.is_some())
    }

    /// Forget every recorded signal. Called when an admin releases
    /// COMBAT: the signals that justified the lockdown have been
    /// adjudicated by a human, so they must not keep corroborating
    /// the NEXT blunt heuristic for another 15 minutes — otherwise a
    /// single weak signal re-locks COMBAT right after a signed unlock
    /// (audit `posture-2`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of signals currently in the ledger.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when no signal is recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> Scope {
        Scope::Workload(format!("/system.slice/{name}"))
    }

    /// Review 52: a pending configuration change corroborates nothing
    /// until it is placed; placed as an admin session it is dropped, as
    /// anything else it counts.
    #[test]
    fn pending_writer_counts_only_once_placed_outside_an_admin_session() {
        let now = Instant::now();
        let host = unit("x.service");
        let mut l = CorroborationLedger::new();
        l.record_pending(
            TriggerType::CriticalFileModification,
            now,
            host.clone(),
            42,
            false,
        );
        assert!(!l.corroborated(TriggerType::PersistenceMechanism, &host));
        l.resolve_pending(|_| None);
        assert!(l.has_pending());
        assert!(!l.corroborated(TriggerType::PersistenceMechanism, &host));
        l.resolve_pending(|_| Some((true, Scope::Login(1000))));
        assert!(l.is_empty(), "an admin change is dropped");

        // Placed outside an admin session, in the scope of its session.
        // External audit POS-001: it corroborates evidence of another
        // kind, and a root change counts as privileged only once placed.
        l.record_pending(
            TriggerType::CriticalFileModification,
            now,
            host.clone(),
            43,
            true,
        );
        assert!(!l.has_privileged(&host), "not before it is placed");
        l.resolve_pending(|_| Some((false, Scope::Login(1000))));
        assert!(!l.has_pending());
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &host));
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &Scope::Login(1000)));
        assert!(!l.corroborated(TriggerType::PersistenceMechanism, &Scope::Login(1000)));
        assert!(l.has_privileged(&Scope::Login(1000)));
        assert!(!l.has_privileged(&host));
    }

    #[test]
    fn lone_signal_is_not_corroborated() {
        let l = CorroborationLedger::new();
        // empty ledger: nothing corroborates the first firing.
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &unit("x.service")));
    }

    /// External audit POS-001: a prior signal of another kind of evidence
    /// corroborates.
    #[test]
    fn prior_signal_of_another_class_corroborates() {
        let now = Instant::now();
        let s = unit("x.service");
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::ConfirmedIntrusion, now, s.clone());
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &s));
        assert!(l.corroborated(TriggerType::PersistenceMechanism, &s));
    }

    /// External audit POS-001 (NN-AUD-002): two network patterns are one
    /// kind of behaviour — an update's HTTPS burst, then three internal
    /// SSH sessions — not two pieces of evidence; likewise two file-system
    /// or two execution signals.
    #[test]
    fn same_class_pair_does_not_corroborate() {
        let now = Instant::now();
        let s = Scope::Login(1000);
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::LateralMovement, now, s.clone());
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &s));
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::CriticalFileModification, now, s.clone());
        assert!(!l.corroborated(TriggerType::PersistenceMechanism, &s));
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::ExploitAttempt, now, s.clone());
        assert!(!l.corroborated(TriggerType::ConfirmedIntrusion, &s));
    }

    #[test]
    fn same_type_repeat_not_corroborated_with_knob_off() {
        // Default SUSTAINED_SAME_TYPE_PROMOTES = false: a repeated SAME
        // signal does NOT promote (the documented single-vector limit).
        let now = Instant::now();
        let s = Scope::Login(1000);
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::ExfiltrationPattern, now, s.clone());
        const _: () = assert!(!SUSTAINED_SAME_TYPE_PROMOTES, "guard: knob default");
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &s));
    }

    #[test]
    fn prune_drops_out_of_window_entries() {
        let base = Instant::now();
        let s = Scope::Login(1000);
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::LateralMovement, base, s.clone());
        // Advance well past the window.
        let later = base + CORROBORATION_WINDOW + Duration::from_secs(1);
        l.prune(later);
        assert_eq!(l.len(), 0, "stale entry pruned");
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &s));
    }

    #[test]
    fn ledger_capped_against_flood() {
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        for _ in 0..(LEDGER_CAP + 50) {
            l.record(TriggerType::ExfiltrationPattern, now, Scope::Login(1000));
        }
        l.prune(now);
        assert!(l.len() <= LEDGER_CAP, "size cap holds under a flood");
    }

    /// posture-ledger-scope-1: signals from different scopes (two login
    /// sessions, or a session and a service) do not corroborate.
    #[test]
    fn different_scopes_do_not_corroborate() {
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::ConfirmedIntrusion, now, Scope::Login(1000));
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &Scope::Login(1001)));
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &unit("x.service")));
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &Scope::Login(1000)));
        l.record(TriggerType::ConfirmedIntrusion, now, unit("x.service"));
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &unit("x.service")));
    }

    /// External audit POS-005: two services (or two containers) without a
    /// login uid are two actors — they used to share the host-level scope;
    /// two signals inside one of them still corroborate.
    #[test]
    fn two_daemons_do_not_corroborate() {
        let now = Instant::now();
        let puppet = unit("puppet.service");
        let container = Scope::Workload("/system.slice/docker-0123abcd.scope".into());
        let mut l = CorroborationLedger::new();
        l.record_with(
            TriggerType::PersistenceMechanism,
            EvidenceClass::FileSystem,
            now,
            puppet.clone(),
            true,
        );
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &container));
        assert!(!l.has_privileged(&container));
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &puppet));
        l.record(TriggerType::ExploitAttempt, now, container.clone());
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &container));
    }

    /// External audit POS-005: a root change recorded for one unit is
    /// privileged evidence in that unit only.
    #[test]
    fn a_privileged_signal_locks_only_its_own_unit() {
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        l.record_with(
            TriggerType::CriticalFileModification,
            EvidenceClass::FileSystem,
            now,
            unit("salt-minion.service"),
            true,
        );
        assert!(l.has_privileged(&unit("salt-minion.service")));
        assert!(!l.has_privileged(&unit("nginx.service")));
        assert!(!l.has_privileged(&Scope::Login(0)));
        assert!(!l.has_privileged(&Scope::Unattributed));
    }

    /// External audit POS-005: a signal that cannot be placed is recorded
    /// (it keeps an unlocked COMBAT from decaying) but corroborates
    /// nothing, is corroborated by nothing — not even another unplaced
    /// signal — and never counts as privileged.
    #[test]
    fn an_unattributed_signal_corroborates_nothing() {
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        l.record_with(
            TriggerType::PersistenceMechanism,
            EvidenceClass::FileSystem,
            now,
            Scope::Unattributed,
            true,
        );
        assert_eq!(l.len(), 1, "recorded");
        assert_eq!(l.newest(), Some(now));
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &Scope::Unattributed));
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &unit("x.service")));
        assert!(!l.has_privileged(&Scope::Unattributed));
        // Nor is an unplaced signal vouched for by a placed one.
        l.record(TriggerType::ExploitAttempt, now, unit("x.service"));
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &Scope::Unattributed));
    }
}
