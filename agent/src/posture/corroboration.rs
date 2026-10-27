//! COMBAT escalation corroboration (BUG-032).
//!
//! A NeedsCorroboration COMBAT-tier trigger (the blunt network/file
//! heuristics) escalates to ENGAGED on its own and reaches COMBAT only
//! with a SECOND distinct escalation signal within
//! [`CORROBORATION_WINDOW`]. Decisive triggers (kernel-adjudicated,
//! [`nn_model::posture_types::Confidence::Decisive`]) bypass this and
//! reach COMBAT immediately. Lab PR 225: so would the ransomware
//! combination (`RansomwareEncryption`: two independent shapes of one
//! actor's file activity, its own corroboration), decisive without being
//! kernel-adjudicated — reaching COMBAT without locking it
//! (`TriggerType::locks_combat`, external audit POS-001) — once the signed
//! per-rule policy turns that on
//! (`posture_types::RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`, off by
//! default: until then it needs corroboration). This makes the FSM ladder
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

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use nn_model::posture_types::{EvidenceClass, TriggerType};

/// Calibration knob (NOT a fixed constant — tune on the VM). Window in
/// which a second distinct escalation signal corroborates a blunt
/// COMBAT-tier heuristic.
pub const CORROBORATION_WINDOW: Duration = Duration::from_secs(15 * 60);

/// External audit POS-008: the entries one scope keeps. A repeat of a
/// signal refreshes its entry instead of adding one
/// ([`LedgerEntry::same_signal`]), so a scope holds at most one entry per
/// trigger, evidence class and privilege — 18 with today's triggers (lab
/// PR 225 added `RansomwareEncryption`, file system with and without
/// privilege, and `DefenseImpairment`, execution) — plus the configuration
/// changes still waiting for their writer to be placed. Above the bound the
/// scope's own least useful entry goes ([`LedgerEntry::keep_rank`]): a
/// flood from one actor never evicts another actor's evidence.
const SCOPE_CAP: usize = 19;

/// Defensive bound on the whole ledger against a trigger flood spread
/// over many scopes (external audit POS-008: was one FIFO of 64 shared by
/// every scope). The time window is the primary prune. When the bound is
/// hit, the entry that goes belongs to the actor holding the most entries
/// ([`Tenant`]), never to a quieter one.
const LEDGER_CAP: usize = 256;

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
/// COMBAT that any other daemon or container then corroborated; and the
/// containers one user started (rootless Podman or Docker) shared that
/// user's login scope. Without a wire change, a process is scoped by the
/// workload its cgroup names, read from `/proc` after the event; the
/// workload-context design (`TAPPA10_9_WORKLOAD_CONTEXT_DESIGN.md` §4.1)
/// would capture the cgroup id with the event itself.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// A PAM login session: its login uid (inherited by everything the
    /// session runs, `sudo` included), outside any container.
    Login(u32),
    /// A container, whoever started it, or a process with no login uid:
    /// the workload its cgroup names, as the cgroup path up to that
    /// container or unit (`/system.slice/puppet.service`,
    /// `/system.slice/docker-<id>.scope`,
    /// `/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-<id>.scope`).
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

    /// External audit POS-008: who answers for this scope's entries when
    /// the ledger is full ([`Tenant`]).
    fn tenant(&self) -> Tenant<'_> {
        match self {
            Scope::Login(uid) => Tenant::User(*uid),
            Scope::Workload(path) => match delegated_uid(path) {
                Some(uid) => Tenant::User(uid),
                None => Tenant::Unit(owning_unit(path)),
            },
            Scope::Unattributed => Tenant::Unattributed,
        }
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

/// External audit POS-008: the actor that can create a scope, which the
/// ledger's global bound charges. A user creates as many scopes as they
/// like inside their own cgroup subtree — a rootless container, or a
/// cgroup of their delegated subtree named like one, is a scope of its
/// own (POS-005) — so every scope below `/user.slice/user-<uid>.slice`
/// counts with that user's login scope; a unit's sub-cgroups (a
/// `Delegate=yes` service creating its own) count with the unit. When the
/// ledger is full the tenant holding the most entries loses one, so an
/// actor who splits a flood over many scopes still pays for all of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Tenant<'a> {
    User(u32),
    Unit(&'a str),
    Unattributed,
}

/// The uid whose cgroup subtree `path` lies in
/// (`/user.slice/user-<uid>.slice[/…]`), if any.
fn delegated_uid(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("/user.slice/user-")?;
    let (uid, tail) = rest.split_once(".slice")?;
    if uid.is_empty()
        || !uid.bytes().all(|b| b.is_ascii_digit())
        || !(tail.is_empty() || tail.starts_with('/'))
    {
        return None;
    }
    uid.parse().ok()
}

/// `path` up to its first unit (a `.service` or `.scope` component): the
/// unit that owns the cgroups below it. A path with no unit is its own.
fn owning_unit(path: &str) -> &str {
    let mut end = 0;
    for comp in path.split('/') {
        end += comp.len();
        if comp.ends_with(".service") || comp.ends_with(".scope") {
            return &path[..end];
        }
        end += 1;
    }
    path
}

#[derive(Clone)]
struct LedgerEntry {
    trigger: TriggerType,
    /// External audit POS-001: the kind of evidence it is.
    class: EvidenceClass,
    /// The latest time the signal was recorded (external audit POS-008: a
    /// repeat refreshes it).
    at: Instant,
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
    /// External audit POS-008: how many times the signal was recorded
    /// while its entry lived (the sustained knob counts them).
    seen: u32,
}

impl LedgerEntry {
    /// External audit POS-008: `other` repeats this signal — the same
    /// trigger, evidence class and privilege, and the same pending writer
    /// (or none). Every answer the ledger gives is the same with the
    /// older of the two dropped: it is younger evidence of the same
    /// thing. `privileged` is part of the key, not merged, so an
    /// unprivileged repeat never extends a privileged entry's window; two
    /// pending writers are kept apart, as each is placed on its own.
    fn same_signal(&self, other: &LedgerEntry) -> bool {
        self.trigger == other.trigger
            && self.class == other.class
            && self.privileged == other.privileged
            && self.pending_writer == other.pending_writer
    }

    /// External audit POS-008: which entry of a full scope goes first —
    /// the lowest rank, the oldest within it: a change still waiting for
    /// its writer (no evidence yet), then an ordinary signal, then a
    /// privileged one (what locks COMBAT).
    fn keep_rank(&self) -> (u8, Instant) {
        let rank = if self.pending_writer.is_some() {
            0
        } else if !self.privileged {
            1
        } else {
            2
        };
        (rank, self.at)
    }

    fn placed(&self) -> bool {
        self.pending_writer.is_none()
    }
}

/// Drop the entry of `entries` that [`LedgerEntry::keep_rank`] values
/// least.
fn evict_least(entries: &mut Vec<LedgerEntry>) {
    if let Some(i) = entries
        .iter()
        .enumerate()
        .min_by_key(|(_, e)| e.keep_rank())
        .map(|(i, _)| i)
    {
        entries.remove(i);
    }
}

fn newest_of(entries: &[LedgerEntry]) -> Option<Instant> {
    entries.iter().map(|e| e.at).max()
}

/// Bounded, in-memory record of recent escalation signals (ENGAGED-tier
/// and above), used to decide whether a blunt COMBAT-tier signal has
/// independent corroboration. Lives in `PostureMachine::Inner` and is
/// only ever touched inside `observe()`'s state-write critical section.
///
/// External audit POS-008: kept per scope, each scope bounded on its own
/// ([`SCOPE_CAP`]) and the whole by [`LEDGER_CAP`]; a scope is only ever
/// read whole, so the order of its entries carries nothing.
#[derive(Default)]
pub struct CorroborationLedger {
    scopes: BTreeMap<Scope, Vec<LedgerEntry>>,
    len: usize,
    /// The global bound was hit since the ledger was last half empty
    /// (one WARN per episode).
    full: bool,
}

impl CorroborationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop entries older than the window. Call before every
    /// query/record. (External audit POS-008: the size bounds are
    /// enforced as entries are recorded.)
    pub fn prune(&mut self, now: Instant) {
        let mut len = 0;
        self.scopes.retain(|_, entries| {
            entries.retain(|e| now.saturating_duration_since(e.at) <= CORROBORATION_WINDOW);
            len += entries.len();
            !entries.is_empty()
        });
        self.len = len;
        if self.len <= LEDGER_CAP / 2 {
            self.full = false;
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
        let Some(entries) = self.scopes.get(scope) else {
            return false;
        };
        let placed = entries.iter().filter(|e| e.placed());
        // External audit POS-001 (NN-AUD-002): a different kind of
        // evidence, not merely a different trigger of the same kind.
        if placed.clone().any(|e| e.class != class) {
            return true;
        }
        SUSTAINED_SAME_TYPE_PROMOTES
            && placed
                .filter(|e| e.trigger == current)
                .map(|e| e.seen as usize)
                .sum::<usize>()
                + 1
                >= SUSTAINED_SAME_TYPE_MIN
    }

    /// Lab PR 245: the signals of `scope` that corroborate `current`
    /// raised as evidence of `class` — what [`Self::corroborated_as`]
    /// finds — as (trigger, kind of evidence), each once, sorted: the
    /// evidence a COMBAT reached on a heuristic cites. Empty when nothing
    /// corroborates it. Caller must [`prune`](Self::prune) first.
    pub fn corroborating(
        &self,
        current: TriggerType,
        class: EvidenceClass,
        scope: &Scope,
    ) -> Vec<(TriggerType, EvidenceClass)> {
        if !self.corroborated_as(current, class, scope) {
            return Vec::new();
        }
        let Some(entries) = self.scopes.get(scope) else {
            return Vec::new();
        };
        let placed = entries.iter().filter(|e| e.placed());
        let mut out: Vec<(TriggerType, EvidenceClass)> = placed
            .clone()
            .filter(|e| e.class != class)
            .map(|e| (e.trigger, e.class))
            .collect();
        if out.is_empty() {
            // The sustained knob: repeats of the same signal.
            out = placed
                .filter(|e| e.trigger == current)
                .map(|e| (e.trigger, e.class))
                .collect();
        }
        out.sort_by_key(|(t, c)| (t.as_str(), format!("{c:?}")));
        out.dedup();
        out
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
        self.insert(
            scope,
            LedgerEntry {
                trigger,
                class,
                at,
                pending_writer: None,
                privileged,
                seen: 1,
            },
        );
    }

    /// External audit POS-008: add `entry` to `scope` — refreshing the
    /// entry it repeats, else within the scope's bound and then the
    /// ledger's.
    fn insert(&mut self, scope: Scope, entry: LedgerEntry) {
        let entries = self.scopes.entry(scope).or_default();
        if let Some(e) = entries.iter_mut().find(|e| e.same_signal(&entry)) {
            e.at = e.at.max(entry.at);
            e.seen = e.seen.saturating_add(entry.seen);
            return;
        }
        if entries.len() >= SCOPE_CAP {
            evict_least(entries);
            self.len -= 1;
        }
        entries.push(entry);
        self.len += 1;
        while self.len > LEDGER_CAP && self.evict_from_the_noisiest() {}
    }

    /// External audit POS-008: the ledger is full — the tenant holding
    /// the most entries (on a tie, the one that recorded last) loses the
    /// least useful entry of its fullest scope. `false` when nothing is
    /// left to evict.
    fn evict_from_the_noisiest(&mut self) -> bool {
        let mut tenants: BTreeMap<Tenant<'_>, (usize, Option<Instant>)> = BTreeMap::new();
        for (scope, entries) in &self.scopes {
            let t = tenants.entry(scope.tenant()).or_default();
            t.0 += entries.len();
            t.1 = t.1.max(newest_of(entries));
        }
        let Some((&tenant, _)) = tenants.iter().max_by_key(|(_, size)| **size) else {
            return false;
        };
        let Some(scope) = self
            .scopes
            .iter()
            .filter(|(s, _)| s.tenant() == tenant)
            .max_by_key(|(_, entries)| (entries.len(), newest_of(entries)))
            .map(|(s, _)| s.clone())
        else {
            return false;
        };
        if !self.full {
            self.full = true;
            tracing::warn!(
                cap = LEDGER_CAP,
                %scope,
                "posture corroboration ledger full: the actor holding the most signals loses its \
                 least useful one"
            );
        }
        let Some(entries) = self.scopes.get_mut(&scope) else {
            return false;
        };
        evict_least(entries);
        self.len -= 1;
        if entries.is_empty() {
            self.scopes.remove(&scope);
        }
        true
    }

    /// External audit POS-001: a privileged signal is on record in `scope`.
    /// External audit POS-005: never in [`Scope::Unattributed`].
    pub fn has_privileged(&self, scope: &Scope) -> bool {
        scope.is_attributed()
            && self
                .scopes
                .get(scope)
                .is_some_and(|entries| entries.iter().any(|e| e.privileged && e.placed()))
    }

    /// External audit POS-001: when the newest signal was recorded (any
    /// scope); `None` when the ledger is empty. An unlocked COMBAT decays
    /// once this is a quiet window old.
    pub fn newest(&self) -> Option<Instant> {
        self.scopes.values().filter_map(|e| newest_of(e)).max()
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
        self.insert(
            scope,
            LedgerEntry {
                class: trigger.evidence_class(),
                trigger,
                at,
                pending_writer: Some(writer),
                privileged,
                seen: 1,
            },
        );
    }

    /// Review 52: place the pending writers. `place` answers `None` while
    /// it still cannot tell (the entry stays pending), else whether the
    /// writer was an administrator's interactive session (the entry is
    /// dropped: routine administration corroborates nothing) and its
    /// session's scope (otherwise the entry becomes an ordinary signal in
    /// that scope, within that scope's bounds). Call after
    /// [`Self::prune`], before [`Self::corroborated`].
    pub fn resolve_pending(&mut self, place: impl Fn(u32) -> Option<(bool, Scope)>) {
        let mut placed: Vec<(Scope, LedgerEntry)> = Vec::new();
        let mut len = 0;
        self.scopes.retain(|_, entries| {
            entries.retain(|e| match e.pending_writer.map(&place) {
                Some(Some((true, _))) => false,
                Some(Some((false, scope))) => {
                    let mut e = e.clone();
                    e.pending_writer = None;
                    placed.push((scope, e));
                    false
                }
                _ => true,
            });
            len += entries.len();
            !entries.is_empty()
        });
        self.len = len;
        for (scope, e) in placed {
            self.insert(scope, e);
        }
    }

    /// Lab PR 243 (tests: the golden replay of the posture): the signals
    /// `scope` holds within the window as of `now` — trigger, evidence
    /// class, privileged, placed — in an order a reader can compare (the
    /// order of a scope's entries carries nothing). Reads only: the ledger
    /// is pruned where it always was.
    #[cfg(test)]
    pub(crate) fn signals_of(
        &self,
        scope: &Scope,
        now: Instant,
    ) -> Vec<(TriggerType, EvidenceClass, bool, bool)> {
        let mut out: Vec<(TriggerType, EvidenceClass, bool, bool)> = self
            .scopes
            .get(scope)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| now.saturating_duration_since(e.at) <= CORROBORATION_WINDOW)
                    .map(|e| (e.trigger, e.class, e.privileged, e.placed()))
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by_key(|(t, c, p, placed)| (t.as_str(), format!("{c:?}"), *p, *placed));
        out
    }

    /// `true` when an entry still waits for [`Self::resolve_pending`].
    pub fn has_pending(&self) -> bool {
        self.scopes
            .values()
            .any(|entries| entries.iter().any(|e| !e.placed()))
    }

    /// Forget every recorded signal. Called when an admin releases
    /// COMBAT: the signals that justified the lockdown have been
    /// adjudicated by a human, so they must not keep corroborating
    /// the NEXT blunt heuristic for another 15 minutes — otherwise a
    /// single weak signal re-locks COMBAT right after a signed unlock
    /// (audit `posture-2`).
    pub fn clear(&mut self) {
        self.scopes.clear();
        self.len = 0;
        self.full = false;
    }

    /// Number of signals currently in the ledger.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when no signal is recorded.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> Scope {
        Scope::Workload(format!("/system.slice/{name}"))
    }

    /// Lab PR 245: the signals that vouch for a heuristic are the ones
    /// `corroborated_as` counts — another kind of evidence, placed, in the
    /// same scope — each once; nothing when it is not corroborated.
    #[test]
    fn the_corroborating_signals_are_the_ones_that_vouch() {
        let now = Instant::now();
        let session = Scope::Login(1000);
        let mut l = CorroborationLedger::new();
        let fs = EvidenceClass::FileSystem;
        assert!(l
            .corroborating(TriggerType::ConfirmedIntrusion, fs, &session)
            .is_empty());
        l.record(TriggerType::CriticalFileModification, now, session.clone());
        // the same kind of evidence vouches for nothing
        assert!(l
            .corroborating(TriggerType::ConfirmedIntrusion, fs, &session)
            .is_empty());
        l.record(TriggerType::ExploitAttempt, now, session.clone());
        l.record(TriggerType::ExploitAttempt, now, session.clone());
        l.record(TriggerType::LateralMovement, now, unit("other.service"));
        // a writer not placed yet vouches for nothing
        l.record_pending(TriggerType::LateralMovement, now, session.clone(), 7, false);
        assert_eq!(
            l.corroborating(TriggerType::ConfirmedIntrusion, fs, &session),
            vec![(TriggerType::ExploitAttempt, EvidenceClass::Execution)],
            "another class, placed, in this scope, once"
        );
        assert!(l
            .corroborating(TriggerType::ConfirmedIntrusion, fs, &Scope::Unattributed)
            .is_empty());
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

    /// External audit POS-008: the size bounds hold under a flood of
    /// distinct entries — pending changes of distinct writers, which are
    /// never merged — in one scope and over many.
    #[test]
    fn ledger_capped_against_flood() {
        let now = Instant::now();
        let mut l = CorroborationLedger::new();
        for w in 0..1_000 {
            l.record_pending(
                TriggerType::PersistenceMechanism,
                now,
                Scope::Login(1000),
                w,
                false,
            );
        }
        l.prune(now);
        assert_eq!(l.len(), SCOPE_CAP, "one scope's bound holds under a flood");
        for u in 0..100 {
            for w in 0..100 {
                l.record_pending(
                    TriggerType::PersistenceMechanism,
                    now,
                    unit(&format!("u{u}.service")),
                    w,
                    false,
                );
            }
        }
        l.prune(now);
        assert_eq!(
            l.len(),
            LEDGER_CAP,
            "the ledger's bound holds under a flood"
        );
        assert_eq!(
            l.scopes.values().map(Vec::len).sum::<usize>(),
            l.len(),
            "the count is the entries'"
        );
        assert!(l.scopes.values().all(|e| e.len() <= SCOPE_CAP));
    }

    /// External audit POS-008: what one actor's evidence looks like in the
    /// tests below — an exploit tool (execution), a control-surface tamper
    /// (lab PR 162, kernel) or root's change to a unit file (file system,
    /// privileged) — and what the flood is.
    fn evidence_kinds() -> [(TriggerType, EvidenceClass, bool); 3] {
        [
            (TriggerType::ExploitAttempt, EvidenceClass::Execution, false),
            (
                TriggerType::ControlSurfaceTamper,
                EvidenceClass::Kernel,
                false,
            ),
            (
                TriggerType::PersistenceMechanism,
                EvidenceClass::FileSystem,
                true,
            ),
        ]
    }

    /// The finding: an unprivileged user runs `nc` in a loop — each exec
    /// an ExploitAttempt recorded at ENGAGED — and pushes another scope's
    /// evidence out of the ledger, a privileged entry included (was: one
    /// FIFO of 64 for every scope). Another scope's evidence stays, and
    /// still corroborates and locks.
    #[test]
    fn another_scopes_flood_does_not_evict_this_scopes_evidence() {
        let now = Instant::now();
        let victim = unit("victim.service");
        for (trigger, class, privileged) in evidence_kinds() {
            let mut l = CorroborationLedger::new();
            l.record_with(trigger, class, now, victim.clone(), privileged);
            for i in 0..1_000u64 {
                let at = now + Duration::from_millis(i);
                l.record(TriggerType::ExploitAttempt, at, Scope::Login(1000));
                l.record(TriggerType::LateralMovement, at, Scope::Login(1000));
                l.prune(at);
            }
            assert!(
                l.corroborated(TriggerType::ExfiltrationPattern, &victim),
                "{trigger} still corroborates"
            );
            assert_eq!(l.has_privileged(&victim), privileged, "{trigger}");
            assert_eq!(l.len(), 3, "{trigger}: the flood is two entries");
        }
    }

    /// External audit POS-008: a flood of one kind of evidence keeps the
    /// one signal of another kind the same actor raised before it (was:
    /// evicted after 64 repeats).
    #[test]
    fn a_same_class_flood_keeps_the_distinct_signal() {
        let now = Instant::now();
        let s = Scope::Login(1000);
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::ExploitAttempt, now, s.clone());
        for i in 0..1_000u64 {
            let at = now + Duration::from_millis(i);
            l.record(TriggerType::LateralMovement, at, s.clone());
            l.prune(at);
        }
        assert_eq!(l.len(), 2, "a repeat refreshes its entry");
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &s));
    }

    /// External audit POS-008: a privileged entry survives a flood, its
    /// own scope's included — pending changes of distinct writers (the
    /// only entries never merged) and every other signal.
    #[test]
    fn a_privileged_entry_survives_a_flood() {
        let now = Instant::now();
        let s = unit("salt-minion.service");
        let mut l = CorroborationLedger::new();
        l.record_with(
            TriggerType::CriticalFileModification,
            EvidenceClass::FileSystem,
            now,
            s.clone(),
            true,
        );
        for w in 0..1_000 {
            let at = now + Duration::from_millis(u64::from(w));
            l.record_pending(TriggerType::PersistenceMechanism, at, s.clone(), w, true);
            l.record(TriggerType::ExploitAttempt, at, s.clone());
            l.record(TriggerType::ExploitAttempt, at, Scope::Login(1000));
            l.prune(at);
        }
        assert!(l.has_privileged(&s));
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &s));
        assert_eq!(l.scopes[&s].len(), SCOPE_CAP);
    }

    /// External audit POS-008: a user splits a flood over many scopes —
    /// rootless containers, or cgroups of their delegated subtree named
    /// like them, each a scope of its own (POS-005) — until the ledger is
    /// full. The global bound charges the user, not the quieter unit,
    /// whose two entries would be the fullest scope.
    #[test]
    fn a_users_many_scopes_evict_only_their_own_entries() {
        let now = Instant::now();
        let victim = unit("victim.service");
        let mut l = CorroborationLedger::new();
        l.record(TriggerType::ExploitAttempt, now, victim.clone());
        l.record_with(
            TriggerType::CriticalFileModification,
            EvidenceClass::FileSystem,
            now,
            victim.clone(),
            true,
        );
        for i in 0..1_000u64 {
            let at = now + Duration::from_millis(i);
            let container = Scope::Workload(format!(
                "/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-{i:064x}.scope"
            ));
            l.record(TriggerType::LateralMovement, at, container);
        }
        l.prune(now + Duration::from_secs(1));
        assert_eq!(l.len(), LEDGER_CAP);
        assert_eq!(l.scopes[&victim].len(), 2, "the unit keeps its evidence");
        assert!(l.has_privileged(&victim));
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &victim));
    }

    /// External audit POS-008: a repeat refreshes its entry, which then
    /// lives a window from the repeat; an unprivileged repeat does not
    /// refresh a privileged entry, which ages out on its own.
    #[test]
    fn a_repeat_refreshes_only_its_own_entry() {
        let base = Instant::now();
        let s = unit("x.service");
        let later = base + Duration::from_secs(10 * 60);
        let mut l = CorroborationLedger::new();
        l.record_with(
            TriggerType::CriticalFileModification,
            EvidenceClass::FileSystem,
            base,
            s.clone(),
            true,
        );
        l.record(TriggerType::ExploitAttempt, base, s.clone());
        l.record(TriggerType::CriticalFileModification, later, s.clone());
        l.record(TriggerType::ExploitAttempt, later, s.clone());
        assert_eq!(l.len(), 3);
        l.prune(base + CORROBORATION_WINDOW + Duration::from_secs(1));
        assert_eq!(l.len(), 2, "the privileged entry aged out");
        assert!(!l.has_privileged(&s));
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &s));
        assert_eq!(l.newest(), Some(later));
    }

    /// External audit POS-008: pending changes of two writers stay apart
    /// (each is placed on its own); one writer's repeat is one entry.
    #[test]
    fn pending_writers_are_placed_one_by_one() {
        let now = Instant::now();
        let s = Scope::Login(1000);
        let mut l = CorroborationLedger::new();
        for writer in [42, 43, 43] {
            l.record_pending(
                TriggerType::PersistenceMechanism,
                now,
                s.clone(),
                writer,
                false,
            );
        }
        assert_eq!(l.len(), 2);
        l.resolve_pending(|w| Some((w == 42, unit("x.service"))));
        assert_eq!(
            l.len(),
            1,
            "the admin's change is dropped, the other placed"
        );
        assert!(!l.has_pending());
        assert!(l.corroborated(TriggerType::ExfiltrationPattern, &unit("x.service")));
        assert!(!l.corroborated(TriggerType::ExfiltrationPattern, &s));
    }

    /// External audit POS-008: the actor a scope's entries are charged to.
    #[test]
    fn a_scope_is_charged_to_whoever_can_create_it() {
        let w = |p: &str| Scope::Workload(p.into());
        assert_eq!(Scope::Login(1000).tenant(), Tenant::User(1000));
        for p in [
            "/user.slice/user-1000.slice/session-3.scope",
            "/user.slice/user-1000.slice/user@1000.service/app.slice/run-x.scope",
            "/user.slice/user-1000.slice",
        ] {
            assert_eq!(w(p).tenant(), Tenant::User(1000), "{p}");
        }
        assert_eq!(
            w("/system.slice/ci.service/libpod-ab.scope").tenant(),
            Tenant::Unit("/system.slice/ci.service"),
            "a delegated unit's sub-cgroups are the unit's"
        );
        assert_eq!(
            w("/system.slice/puppet.service").tenant(),
            Tenant::Unit("/system.slice/puppet.service")
        );
        assert_eq!(w("/docker/abc").tenant(), Tenant::Unit("/docker/abc"));
        for p in [
            "/user.slice/user-1000x.slice/a.scope",
            "/user.slice/user-.slice/a.scope",
            "/user.slice/user-1000.slicex/a.scope",
        ] {
            assert!(!matches!(w(p).tenant(), Tenant::User(_)), "{p}");
        }
        assert_eq!(Scope::Unattributed.tenant(), Tenant::Unattributed);
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
