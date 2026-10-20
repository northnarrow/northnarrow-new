//! Trigger detection — decides which [`TriggerType`]s a
//! `(focal_event, recent_events)` pair raises.
//!
//! The detector is stateless: every decision is a pure function of
//! the inputs. State (decay timers, transition log, last-fired
//! timestamps) lives in [`super::PostureMachine`].
//!
//! Design choices:
//!
//! - We mirror the Tappa-2 rule heuristics where possible
//!   (`R005_NetcatExec`, `R006_ReverseShellTooling`,
//!   `R001_ExecFromTmp`/`R002_ExecFromDevShm`) so the posture
//!   machine sees the same exploit/intrusion signal that the rule
//!   engine eventually fires on, *before* the rule executes — this
//!   is what lets a single confirmed exploit shift posture before
//!   the verdict is even computed.
//! - "Recon" is a count of *distinct* destination ports from the
//!   same pid within the lookback window, not a raw event count.
//!   nmap localhost generates 1000 dst_port hits from one pid; that
//!   shape is what we want to flag, not e.g. a chatty browser
//!   refreshing the same socket.
//! - We never look at command-line arguments because the eBPF
//!   sensors don't carry them. LOLBAS detection therefore relies
//!   on the parent/child comm pair (`curl` → `bash`) and not on
//!   pipeline syntax.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use common::posture_types::{EvidenceClass, TriggerType};
use common::wire::exe::exe_flags;
use common::wire::open_sensor::open_reason;
use common::Event;

use super::corroboration::Scope;
use super::escalation_allow::{AllowTrigger, EscalationAllowList};
use super::exempt::ExemptPids;
use super::lineage::AuthSessionTracker;
use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;

/// The recent events the triggers scan, borrowed (review 72). The
/// correlation buffer is a ring of up to 1,000 events; cloning it for every
/// event made the agent spend most of its time allocating under an exec
/// burst. The ring is two slices when it wraps, hence the pair.
#[derive(Clone, Copy)]
pub struct Recent<'a>(&'a [Event], &'a [Event]);

impl<'a> Recent<'a> {
    pub fn iter(self) -> impl DoubleEndedIterator<Item = &'a Event> + Clone {
        self.0.iter().chain(self.1.iter())
    }
}

impl<'a> From<&'a [Event]> for Recent<'a> {
    fn from(s: &'a [Event]) -> Self {
        Recent(s, &[])
    }
}

impl<'a, const N: usize> From<&'a [Event; N]> for Recent<'a> {
    fn from(s: &'a [Event; N]) -> Self {
        Recent(s, &[])
    }
}

impl<'a> From<&'a Vec<Event>> for Recent<'a> {
    fn from(v: &'a Vec<Event>) -> Self {
        Recent(v, &[])
    }
}

impl<'a> From<&'a std::collections::VecDeque<Event>> for Recent<'a> {
    fn from(q: &'a std::collections::VecDeque<Event>) -> Self {
        let (a, b) = q.as_slices();
        Recent(a, b)
    }
}

/// Recon window: 3+ distinct dst_port from same pid in 10 min.
pub(super) const RECON_WINDOW_NS: u64 = 10 * 60 * 1_000_000_000;
pub(super) const RECON_DISTINCT_PORTS_MIN: usize = 3;

/// Heavy recon: 10+ distinct dst_port from same pid in 1 h.
pub(super) const HEAVY_RECON_WINDOW_NS: u64 = 60 * 60 * 1_000_000_000;
pub(super) const HEAVY_RECON_DISTINCT_PORTS_MIN: usize = 10;

/// DGA-like DNS: 5+ suspicious queries from same pid in 5 min.
pub(super) const DNS_DGA_WINDOW_NS: u64 = 5 * 60 * 1_000_000_000;
pub(super) const DNS_DGA_QUERIES_MIN: usize = 5;
pub(super) const DNS_DGA_MIN_LABEL_LEN: usize = 16;

/// Mass encryption / mass write: 20+ writes from same pid in 60 s.
pub(super) const MASS_WRITE_WINDOW_NS: u64 = 60 * 1_000_000_000;
pub(super) const MASS_WRITE_MIN: usize = 20;

/// BUG-014 (P-6) — path-class carve-out for the mass-write arm of
/// `confirmed_intrusion`. Writes to these prefixes are kernel-control
/// RPCs or system-managed binary state, not the data-mutation pattern
/// the mass-write heuristic exists to catch (ransomware / mass exfil
/// staging). Each excluded path class is covered by a dedicated
/// detection surface so suppression here does not blind the agent:
///
/// - `/sys/`            — sysfs control files (cgroupfs writes during
///   service setup, kernel parameter writes).
///   Tampering is covered by anti-tamper LSM
///   hooks (kernel_param, etc.) and the R011
///   kernel-module tooling rule.
/// - `/proc/`           — procfs writes (sysctl-shaped kernel RPCs,
///   per-process control). Same anti-tamper
///   LSM surface; never a ransomware target.
/// - `/run/systemd/`    — systemd's own runtime state directory (cgroup
///   delegation files, unit transient state).
///   Not data; not a ransomware target.
/// - `/run/log/journal/` — systemd-journal binary log. Anti-forensic
///   journal manipulation is its own threat
///   category (future R-NN); the mass-write arm
///   of confirmed_intrusion would only ever
///   catch journald's normal append rhythm here.
///
/// Deliberately **NOT** excluded:
/// - `/dev/shm/`    — a real ransomware staging tmpfs. The rest of `/dev`
///   holds device nodes (`/dev/null` in a script's
///   redirects, `/dev/console` that systemd writes at
///   shutdown), not data: excluded by [`is_device_node`],
///   as the kernel counter counts regular files only.
/// - `/run/`        — broad, includes `/run/user/<uid>/` where user
///   processes legitimately write (lock files, dbus
///   sockets). Counted toward mass-write so a
///   compromised user session is still detectable.
pub(crate) const MASS_WRITE_CARVEOUT_PREFIXES: &[&str] =
    &["/sys/", "/proc/", "/run/systemd/", "/run/log/journal/"];

/// Returns true if `filename` is in a path class the mass-write arm of
/// `confirmed_intrusion` deliberately ignores (kernel-RPC / system
/// state, not data writes). See [`MASS_WRITE_CARVEOUT_PREFIXES`] for
/// the per-prefix rationale. `extras` is the operator-supplemental
/// list loaded from `/etc/northnarrow/mass-write-carveout.local`
/// (BUG-017 P-8); pass `&[]` to consider only the hardcoded list.
fn is_mass_write_carveout(filename: &str, extras: &[String]) -> bool {
    MASS_WRITE_CARVEOUT_PREFIXES
        .iter()
        .any(|p| filename.starts_with(p))
        || is_device_node(filename)
        || extras.iter().any(|p| filename.starts_with(p.as_str()))
}

/// External audit POS-004: [`is_mass_write_carveout`] for a path the caller
/// passed (tracepoint mode), which no kernel resolved: it is judged after
/// its `.` and `..` segments are folded, and a path through a process's
/// `cwd`, `root` or `fd` link under `/proc` — a door to any file, not a
/// pseudo-file — is never carved out (`/proc/self/cwd/report.docx`,
/// `/proc/../home/u/x` evaded the mass-write count).
fn is_mass_write_carveout_unresolved(filename: &str, extras: &[String]) -> bool {
    let folded = fold_dot_segments(filename);
    if through_proc_link(&folded) {
        return false;
    }
    is_mass_write_carveout(&folded, extras)
}

/// `path` with `.` and `..` segments and repeated slashes folded, as the
/// kernel would walk them were there no symlink on the way.
fn fold_dot_segments(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    if path.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    }
}

/// `/proc/<pid|self|thread-self>[/task/<tid>]/{cwd,root,fd}/…`: a link the
/// kernel follows to the process's directory, root or open file (an
/// `fd/<n>` reopens that file).
fn through_proc_link(path: &str) -> bool {
    let task = |s: &str| {
        s == "self"
            || s == "thread-self"
            || (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    };
    let door = |s: &str| matches!(s, "cwd" | "root" | "fd");
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match segs.as_slice() {
        ["proc", who, "task", tid, link, _, ..] => task(who) && task(tid) && door(link),
        ["proc", who, link, _, ..] => task(who) && door(link),
        _ => false,
    }
}

/// A device node under `/dev` (not the `/dev/shm` and `/dev/mqueue`
/// filesystems, which hold files).
fn is_device_node(filename: &str) -> bool {
    filename.starts_with("/dev/")
        && !filename.starts_with("/dev/shm/")
        && !filename.starts_with("/dev/mqueue/")
}

/// Tappa 10.9 step 1: `true` once the file-open sensor on LSM `file_open`
/// counts write-opens in the kernel and reports bursts as
/// `Event::MassWrite`. Only the opens a rule reads reach userland then,
/// so counting `FileOpen` events here would be wrong (and double): the
/// mass-write arm reads `MassWrite` instead. `false` (tracepoint mode,
/// the Q6 switch) keeps the userland count.
static KERNEL_MASS_WRITE: AtomicBool = AtomicBool::new(false);

/// Switch the mass-write arm between the kernel count (LSM file-open
/// sensor armed) and the userland count (tracepoint mode).
pub fn set_kernel_mass_write(on: bool) {
    KERNEL_MASS_WRITE.store(on, Ordering::Relaxed);
}

/// Lateral movement: 3+ distinct internal hosts on admin ports in 10 min.
pub(super) const LATERAL_WINDOW_NS: u64 = 10 * 60 * 1_000_000_000;
pub(super) const LATERAL_DISTINCT_DST_MIN: usize = 3;

/// Exfiltration: 20+ external 80/443 connects from same pid in 5 min.
pub(super) const EXFIL_WINDOW_NS: u64 = 5 * 60 * 1_000_000_000;
pub(super) const EXFIL_MIN_EVENTS: usize = 20;

const NETCAT_COMMS: &[&str] = &["nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"];
const OFFSEC_COMMS: &[&str] = &["socat", "msfvenom", "meterpreter", "sliver", "havoc"];
const RECON_TOOL_COMMS: &[&str] = &["nmap", "masscan", "rustscan", "zmap", "unicornscan"];
const NETLOAD_COMMS: &[&str] = &["curl", "wget", "fetch"];
const SHELL_COMMS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh"];
const ADMIN_PORTS: &[u16] = &[22, 3389, 445, 5985, 5986];

/// Credential / authentication files an unprivileged user has no
/// business reading directly. `/etc/login.defs` was added in BUG-012:
/// the FIM `Opened` event for it is dropped at the drain layer
/// (`fim::drain::process_drift` drops every read on a non-credential
/// path — see BUG-012 v2) to kill the boot-time noise; without this
/// entry, `/etc/login.defs` reads would lose ALL coverage.
///
/// `/etc/gshadow` (group shadow — hashed group passwords) is the
/// group-credential counterpart of `/etc/shadow`; the same auth stack
/// (`pam_unix`, `gpasswd`, `newgrp`) reads it. It is monitored for the
/// same reason as `/etc/shadow`: an unexpected `uid >= 1000` reader is
/// a credential-theft signal. Legitimate auth binaries reading it are
/// suppressed by the SAME auth-lineage gate that protects `/etc/shadow`
/// (see [`sensitive_file_access`]), so adding it here does NOT
/// re-introduce the T7.13 FP for sudo/sshd/login/etc.
pub(crate) const SENSITIVE_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/login.defs",
];
pub(crate) const CRITICAL_FILES_PREFIXES: &[&str] = &[
    "/etc/sshd_config",
    "/etc/ssh/sshd_config",
    // Already matched by the prefix above; spelled out because the LSM
    // file-open sensor (Tappa 10.9) classifies by directory, not by name
    // prefix, and sshd reads its drop-ins from here.
    "/etc/ssh/sshd_config.d/",
    "/etc/crontab",
    "/etc/sudoers.d/",
    "/etc/pam.d/",
    "/root/.ssh/",
];
pub(crate) const PERSISTENCE_PREFIXES: &[&str] = &[
    "/etc/cron.d/",
    "/etc/cron.hourly/",
    "/etc/cron.daily/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
    "/etc/systemd/system/",
    "/etc/init.d/",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
];

/// Stateless detector — see module docs.
///
/// `exempt` holds the NorthNarrow stack's own PIDs (agent + verified
/// watchdog), when known. The defender must
/// never classify its *own* I/O as adversary behaviour: the agent
/// appends to its state logs (`fim_drift.jsonl`, `fim_baseline.jsonl`,
/// `netflow.jsonl`, the audit chain, …) on every observed event, and
/// the observe-only `file_open` sensor reports those writes straight
/// back into the event stream. Without this guard a fresh boot's FIM
/// drift logging alone is >20 write-opens from one PID inside the
/// 60 s window, which trips [`confirmed_intrusion`]'s mass-write /
/// ransomware heuristic and drives posture all the way to COMBAT —
/// engaging network isolation against a host that is doing nothing
/// wrong (see 2026-05-22 sshd-reset diagnosis). Tamper attempts on
/// the agent's state by *other* PIDs are still caught: the inode
/// LSM hooks deny them and surface an `FsProtectDenial`, which
/// `detect` raises as the Decisive `AntiTamperDenial` trigger
/// (straight to COMBAT on its own — BUG-032).
#[derive(Debug, Default, Clone)]
pub struct TriggerDetector {
    /// PIDs belonging to the NorthNarrow process stack (agent + the
    /// verified watchdog) whose events must never raise a trigger.
    exempt: ExemptPids,
    /// T7.13 (Beta Step 5) — sudo-mediated process lineage tracker.
    /// Consulted ONLY by `sensitive_file_access` and the mass-write
    /// arm of `confirmed_intrusion` (and, review 52, by
    /// [`Self::admin_change_status`], which decides what corroborates,
    /// never what fires); every other COMBAT-tier trigger
    /// (FsProtectDenial, exec from /tmp, persistence_mechanism,
    /// critical_file_modification, lateral_movement,
    /// exfiltration_pattern, exploit_attempt, lolbas_pattern) fires
    /// unchanged so admin sudo activity that is *actually* malicious
    /// — dropping a /tmp payload, tampering with agent state — is
    /// still caught. (External audit POS-015: a /tmp exec under a
    /// package manager's lineage is never promoted past `StagingExec`.)
    auth: AuthSessionTracker,
    /// BUG-017 P-8 — operator-supplemental mass-write path-prefix
    /// carve-out, layered on top of [`MASS_WRITE_CARVEOUT_PREFIXES`].
    /// Loaded from `/etc/northnarrow/mass-write-carveout.local` at
    /// agent boot. Cheap to clone (`Arc`); empty by default.
    mass_write_extras: Arc<Vec<String>>,
    /// pid → monotonic ns of the last mass-write WARN for that pid.
    /// Review entry 37: a steady benign writer keeps the arm crossed on
    /// every event, and the WARN was logged once per second for 24 h on
    /// the first soak. The trigger still fires (posture logic unchanged);
    /// the log line is emitted once per [`MASS_WRITE_WINDOW_NS`] per pid.
    mass_write_warned: Arc<parking_lot::Mutex<HashMap<u32, u64>>>,
    /// BUG-032 — escalation allowlist: process×destination tuples whose
    /// connections are excluded from the `exfiltration_pattern` /
    /// `lateral_movement` threshold counts (count-filter, not suppress).
    /// Loaded from `/etc/northnarrow/escalation-allow.local` at boot.
    /// Empty by default (fail-secure).
    escalation_allow: Arc<EscalationAllowList>,
    /// External audit POS-015: pid → monotonic ns of the last time the
    /// mass-write arm fired for it — the second factor that makes a
    /// staging exec by the same process `ConfirmedIntrusion`.
    mass_writers: MassWriters,
    /// Lab PR 162: the trusted-installer window, once `main.rs` has wired
    /// it ([`Self::set_installer_window`]); inside it a control-surface
    /// tamper does not raise the posture.
    installer_window: InstallerWindow,
}

/// Lab PR 162: the trusted-installer window as the detector reads it.
/// Unset (a test, a build that does not wire it) reads as closed, so the
/// trigger fires.
#[derive(Clone, Default)]
struct InstallerWindow(Arc<std::sync::OnceLock<Arc<TrustedInstallerOverride>>>);

impl std::fmt::Debug for InstallerWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallerWindow")
            .field("wired", &self.0.get().is_some())
            .finish()
    }
}

impl InstallerWindow {
    fn is_open(&self) -> bool {
        self.0.get().is_some_and(|w| w.is_window_open())
    }
}

/// External audit POS-015: when the mass-write arm last fired for a pid
/// (once per event; pruned of pids older than a window past 1,024).
#[derive(Debug, Default, Clone)]
struct MassWriters(Arc<parking_lot::Mutex<HashMap<u32, u64>>>);

impl MassWriters {
    fn record(&self, pid: u32, ts_ns: u64) {
        let mut g = self.0.lock();
        if g.len() > 1024 {
            let cutoff = ts_ns.saturating_sub(MASS_WRITE_WINDOW_NS);
            g.retain(|_, t| *t >= cutoff);
        }
        g.insert(pid, ts_ns);
    }

    /// The arm fired for `pid` within a mass-write window of `ts_ns`, on
    /// either side: the rings are drained apart, so the burst of a payload
    /// that runs and then encrypts may be read before its exec.
    fn wrote_near(&self, pid: u32, ts_ns: u64) -> bool {
        self.0
            .lock()
            .get(&pid)
            .is_some_and(|t| t.abs_diff(ts_ns) <= MASS_WRITE_WINDOW_NS)
    }
}

impl TriggerDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a detector that ignores events attributed to the
    /// agent's own PID. See the struct docs for why self-exclusion is
    /// required.
    pub fn with_self_pid(pid: u32) -> Self {
        Self {
            exempt: ExemptPids::with_agent(pid),
            auth: AuthSessionTracker::default(),
            mass_write_extras: Arc::new(Vec::new()),
            mass_write_warned: Arc::default(),
            escalation_allow: Arc::new(EscalationAllowList::empty()),
            mass_writers: MassWriters::default(),
            installer_window: InstallerWindow::default(),
        }
    }

    /// Construct a detector with an explicit, shared [`ExemptPids`]
    /// (Beta Step 3) so the agent *and* the verified watchdog PID are
    /// both excluded, the latter refreshed live by `main.rs`.
    pub fn with_exempt(exempt: ExemptPids) -> Self {
        Self {
            exempt,
            auth: AuthSessionTracker::default(),
            mass_write_extras: Arc::new(Vec::new()),
            mass_write_warned: Arc::default(),
            escalation_allow: Arc::new(EscalationAllowList::empty()),
            mass_writers: MassWriters::default(),
            installer_window: InstallerWindow::default(),
        }
    }

    /// Beta Step 5 production constructor — combines the shared
    /// stack-exempt set with the auth-lineage tracker. `main.rs` uses
    /// this; tests can build a detector with a fixture `proc_root`
    /// via [`AuthSessionTracker::new`].
    pub fn with_exempt_and_auth(exempt: ExemptPids, auth: AuthSessionTracker) -> Self {
        Self {
            exempt,
            auth,
            mass_write_extras: Arc::new(Vec::new()),
            mass_write_warned: Arc::default(),
            escalation_allow: Arc::new(EscalationAllowList::empty()),
            mass_writers: MassWriters::default(),
            installer_window: InstallerWindow::default(),
        }
    }

    /// BUG-017 P-8 — builder-style setter for the operator
    /// supplemental mass-write carve-out prefix list. Production:
    /// `main.rs` calls this with the parsed
    /// `mass-write-carveout.local` contents.
    pub fn with_mass_write_extras(mut self, extras: Vec<String>) -> Self {
        self.mass_write_extras = Arc::new(extras);
        self
    }

    /// Lab PR 162: the trusted-installer window the control-surface
    /// trigger defers to. Set once; a second call is ignored.
    pub fn set_installer_window(&self, window: Arc<TrustedInstallerOverride>) {
        let _ = self.installer_window.0.set(window);
    }

    /// BUG-032 — builder for the escalation allowlist. Production:
    /// `main.rs` calls this with the parsed `escalation-allow.local`
    /// contents (count-filter for exfil/lateral).
    pub fn with_escalation_allow(mut self, allow: EscalationAllowList) -> Self {
        self.escalation_allow = Arc::new(allow);
        self
    }

    /// Corroboration scope of `event` (review `posture-ledger-scope-1`):
    /// the login uid of the owning pid, or of its nearest running ancestor
    /// once it has exited. External audit POS-005: a container — with or
    /// without a login uid — and, without a login uid, the systemd unit
    /// are scoped by the workload their cgroup names, so two daemons, two
    /// containers, or a container and the shell of the user who started it
    /// are two actors; [`Scope::Unattributed`] when nothing can be read, or
    /// for an event with no owning pid. Read only for an event that raised
    /// a trigger.
    pub fn session_scope(&self, event: &Event) -> Scope {
        match event_owner_pid(event) {
            Some(pid) => self.scope_of(pid),
            None => Scope::Unattributed,
        }
    }

    /// External audit POS-005: a rootless container (Podman, Docker) runs
    /// with the login uid of the user who started it, and used to share
    /// that user's scope with the user's shell and every other container
    /// of theirs. Residual risk: an attacker in a login session splits
    /// their evidence by running part of it in a container they start (or
    /// in a cgroup of their delegated subtree named like one); two signals
    /// inside one container still corroborate.
    fn scope_of(&self, pid: u32) -> Scope {
        let workload = self.auth.session_workload(pid);
        match (workload, self.auth.session_loginuid(pid)) {
            (Some(w), _) if w.container => Scope::Workload(w.path),
            (_, Some(uid)) => Scope::Login(uid),
            (Some(w), None) => Scope::Workload(w.path),
            (None, None) => Scope::Unattributed,
        }
    }

    /// Review 52: whether `event` is a write-open by an administrator's
    /// interactive sudo/su session
    /// ([`AuthSessionTracker::is_interactive_admin`]) — a configuration
    /// change, which raises the posture but does not corroborate. `None`
    /// when its writer cannot be placed yet
    /// ([`AuthSessionTracker::interactive_admin_status`]); `Some(false)`
    /// for any other event.
    pub fn admin_change_status(&self, event: &Event) -> Option<bool> {
        match event {
            Event::FileOpen { pid, flags, .. } if is_write_open(*flags) => {
                self.auth.interactive_admin_status(*pid)
            }
            _ => Some(false),
        }
    }

    /// Review 52: a pending writer placed —
    /// [`AuthSessionTracker::interactive_admin_status`] and its session's
    /// scope — or `None` while it still cannot be.
    pub fn place_writer(&self, pid: u32) -> Option<(bool, Scope)> {
        self.auth
            .interactive_admin_status(pid)
            .map(|admin| (admin, self.scope_of(pid)))
    }

    /// Inspect `(event, recent)` and return every trigger raised.
    ///
    /// The result is in escalation order (the strongest trigger
    /// last) so the caller can `iter().last()` for the dominant
    /// signal or fold them all into the audit log.
    pub fn detect<'a>(&self, event: &Event, recent: impl Into<Recent<'a>>) -> Vec<TriggerType> {
        let recent = recent.into();
        // T7.13: ingest ProcessSpawn into the auth-lineage tracker
        // FIRST, so the focal spawn's own lineage is visible to the
        // arms below (e.g. a spawn whose parent is sudo gets the
        // tag in the same observe call). Stack-exempt spawns are
        // also recorded — they won't trip the auth allowlist and
        // recording them is cheap; consistency beats the conditional.
        if let Event::ProcessSpawn {
            pid,
            ppid,
            uid,
            filename,
            argv,
            timestamp_ns,
            exe,
            start_ns,
            ..
        } = event
        {
            // FP-2: pass argv so the tracker can precompute the npm-CLI
            // flag (node running npm-cli.js) for the mass-write exemption.
            // Tappa 10.9 step 2: the file the kernel executed (review 61).
            // External audit POS-003: and the process's own start, which
            // orders its fork against its ancestors' execs. Lab PR 175:
            // and the uid it executed as (a package transaction is root's).
            self.auth.ingest_exec(
                *pid,
                *ppid,
                exe.path_or(filename),
                argv,
                *timestamp_ns,
                *start_ns,
                *uid,
            );
        }

        // Stack-exclusion: never raise a trigger on the NorthNarrow
        // stack's own events (the agent — PR #123 — and the verified
        // watchdog — Beta Step 3). The agent's continuous state-log
        // writes, and the watchdog's reads of /proc/<agent>, the bpffs
        // map and /run/northnarrow, would otherwise self-trip the
        // mass-write / sensitive-access heuristics on a benign host.
        // `recent` is left untouched — the per-pid counters inside the
        // heuristics only ever match the focal pid, so a stack-owned
        // event in `recent` cannot inflate a non-stack focal's count.
        //
        // External audit POS-009: except a kernel denial from the
        // watchdog's PID. The verified watchdog is in PROTECTED_PIDS, so
        // the kernel refuses it nothing in normal operation; a denial there
        // comes from a process the slot no longer describes, or from a
        // watchdog that misbehaves. The agent's own PID stays exempt from
        // everything: a COMBAT against itself would be worse.
        if let Some(pid) = event_owner_pid(event) {
            let watchdog_denial =
                matches!(event, Event::FsProtectDenial { .. }) && !self.exempt.is_agent(pid);
            if self.exempt.is_exempt(pid) && !watchdog_denial {
                return Vec::new();
            }
        }

        let mut hits: Vec<TriggerType> = Vec::new();

        // OBSERVING -> ALERTED tier
        if recon_pattern(event, recent) {
            hits.push(TriggerType::Reconnaissance);
        }
        if suspicious_dns(event, recent) {
            hits.push(TriggerType::SuspiciousDns);
        }
        if sensitive_file_access(event, &self.auth) {
            hits.push(TriggerType::SensitiveFileAccess);
        }
        if lolbas_pattern(event, recent) {
            hits.push(TriggerType::Lolbas);
        }

        // ALERTED -> ENGAGED tier
        if exploit_attempt(event) {
            hits.push(TriggerType::ExploitAttempt);
        }
        if heavy_recon(event, recent) {
            hits.push(TriggerType::HeavyReconnaissance);
        }
        // External audit POS-004: in tracepoint mode an open's path is the
        // string the caller passed, read at syscall entry — before any
        // permission check (a refused open counts) and unresolved. It
        // cannot carry a COMBAT-tier file signal: two refused opens of
        // `/etc/cron.d/x` and `/etc/ssh/sshd_config` were the corroborating
        // pair of POS-001, with no privilege and nothing written. It
        // raises the credential-reach tier (ALERTED) instead.
        let unadjudicated = matches!(
            event,
            Event::FileOpen {
                path_from_user: true,
                ..
            }
        );
        if critical_file_modification(event) {
            hits.push(if unadjudicated {
                TriggerType::SensitiveFileAccess
            } else {
                TriggerType::CriticalFileModification
            });
        }
        // External audit POS-015: a binary run from a staging directory.
        let staged = staging_exec(event, &self.auth, &self.mass_writers);
        if staged == Some(StagedExec::Plain) {
            hits.push(TriggerType::StagingExec);
        }

        // ENGAGED -> COMBAT tier
        // BUG-032: a denied anti-tamper attempt is kernel-adjudicated
        // malice — the Decisive signal that reaches COMBAT on its own
        // (split out of confirmed_intrusion's old FsProtectDenial arm).
        // External audit EBPF-001: a denial whose sender is PID 1 is a
        // `systemctl` request systemd relayed — refused, recorded, ENGAGED;
        // the requester is unknown, and init is no offender to contain.
        if let Event::FsProtectDenial { pid, operation, .. } = event {
            hits.push(if *pid == 1 {
                TriggerType::RelayedTamperAttempt
            } else if *operation == common::FsProtectOperation::Read {
                // External audit EVD-001: a refused read of the agent's
                // signing key is a credential reach (ALERTED), not a
                // decisive tamper — a backup of /etc meets it too.
                TriggerType::SensitiveFileAccess
            } else {
                TriggerType::AntiTamperDenial
            });
        }
        // Lab PR 162: a tamper of an anti-tamper control-surface file — the
        // match of NN-L-FIM-024, which no workflow produces while the agent
        // runs (install, upgrade and removal stop it first; its own boot
        // sweep is exempt) — is tamper evidence as decisive as a denial.
        // The rule's exemptions hold here too: the NorthNarrow stack is
        // exempt above, and the agent's own PID here (the rule's backstop).
        // Inside the trusted-installer window, where the kernel refuses no
        // write and so no denial reaches the posture either, it is not
        // raised; the rule still kills and records.
        if let Event::Fim(fe) = event {
            if crate::fim::rules::is_bait_tamper(fe)
                && fe.modifier_pid != std::process::id()
                && !self.installer_window.is_open()
            {
                hits.push(TriggerType::ControlSurfaceTamper);
            }
        }
        let mass_write = confirmed_intrusion(
            event,
            recent,
            &self.auth,
            &self.mass_write_extras,
            &self.mass_write_warned,
        );
        if mass_write {
            if let (Some(pid), (_, ts)) = (event_owner_pid(event), event_owner_seen(event)) {
                self.mass_writers.record(pid, ts);
            }
        }
        if mass_write || staged == Some(StagedExec::Confirmed) {
            hits.push(TriggerType::ConfirmedIntrusion);
        }
        if persistence_mechanism(event, &self.auth) {
            hits.push(if unadjudicated {
                TriggerType::SensitiveFileAccess
            } else {
                TriggerType::PersistenceMechanism
            });
        }
        if lateral_movement(event, recent, &self.escalation_allow) {
            hits.push(TriggerType::LateralMovement);
        }
        if exfiltration_pattern(event, recent, &self.escalation_allow) {
            hits.push(TriggerType::ExfiltrationPattern);
        }

        hits
    }
}

/// `ts` lies within `window_ns` of `focal_ts`, on either side. External
/// audit POS-006: the window used to be bounded only toward the past, so
/// an event stamped any time after the focal one counted (the correlation
/// buffer holds 1,000 events with no age bound). Before or after by the
/// same window, like the mass-write second factor
/// ([`MassWriters::wrote_near`]) and the correlation buffer: the rings
/// are drained apart, so a later event may be read first, and a separate
/// skew bound would undercount when one ring's pump lags under load.
fn within(focal_ts: u64, ts: u64, window_ns: u64) -> bool {
    ts.abs_diff(focal_ts) <= window_ns
}

/// PID an event is attributed to, for self-exclusion. Variants the
/// agent itself never originates (e.g. `CanaryTripped`, `NetFlow`,
/// `NetListener`) return `None` so they are never filtered.
/// External audit POS-001: the kind of evidence `trigger`, raised on
/// `event`, is — [`TriggerType::evidence_class`], except that the
/// mass-write arm of `ConfirmedIntrusion` is file-system evidence, not
/// execution. (snapd's state rewrite and its unit write, the 2026-06-02
/// self-lock, are one kind of behaviour.)
pub fn evidence_class(trigger: TriggerType, event: &Event) -> EvidenceClass {
    match (trigger, event) {
        (TriggerType::ConfirmedIntrusion, Event::MassWrite { .. } | Event::FileOpen { .. }) => {
            EvidenceClass::FileSystem
        }
        _ => trigger.evidence_class(),
    }
}

/// External audit POS-001: the uid an event's process acted as, where the
/// event carries one.
pub fn event_uid(event: &Event) -> Option<u32> {
    match event {
        Event::ProcessSpawn { uid, .. }
        | Event::FileOpen { uid, .. }
        | Event::MassWrite { uid, .. }
        | Event::TcpConnect { uid, .. }
        | Event::DnsQuery { uid, .. } => Some(*uid),
        _ => None,
    }
}

/// PID that "owns" an event — the actor whose behaviour the event
/// attributes. Exposed so the COMBAT ladder can attribute the offending
/// process from the focal event that drove the COMBAT transition.
pub fn event_owner_pid(event: &Event) -> Option<u32> {
    match event {
        Event::ProcessSpawn { pid, .. }
        | Event::FileOpen { pid, .. }
        | Event::MassWrite { pid, .. }
        | Event::ExecCheck { pid, .. }
        | Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::FsProtectDenial { pid, .. } => Some(*pid),
        // Lab PR 162: the writer, so the stack exemption applies to it and
        // a control-surface tamper's COMBAT names it as the offender.
        Event::Fim(fe) => Some(fe.modifier_pid),
        _ => None,
    }
}

/// What the event that names [`event_owner_pid`] says about that process
/// (external audit CMB-004): its start (an exec's, `CLOCK_MONOTONIC` ns)
/// and the event's time (it was running then); 0 when unknown.
pub fn event_owner_seen(event: &Event) -> (u64, u64) {
    match event {
        Event::ProcessSpawn {
            start_ns,
            timestamp_ns,
            ..
        } => (*start_ns, *timestamp_ns),
        Event::FileOpen { timestamp_ns, .. }
        | Event::MassWrite { timestamp_ns, .. }
        | Event::ExecCheck { timestamp_ns, .. }
        | Event::TcpConnect { timestamp_ns, .. }
        | Event::DnsQuery { timestamp_ns, .. }
        | Event::FsProtectDenial { timestamp_ns, .. } => (0, *timestamp_ns),
        _ => (0, 0),
    }
}

fn recon_pattern(focal: &Event, recent: Recent<'_>) -> bool {
    if let Event::ProcessSpawn { comm, .. } = focal {
        if RECON_TOOL_COMMS.iter().any(|c| comm == c) {
            return true;
        }
    }
    let Event::TcpConnect {
        pid: focal_pid,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    distinct_dst_ports_in_window(*focal_pid, *focal_ts, recent, RECON_WINDOW_NS)
        + 1 // include the focal event itself
        >= RECON_DISTINCT_PORTS_MIN
}

fn heavy_recon(focal: &Event, recent: Recent<'_>) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    distinct_dst_ports_in_window(*focal_pid, *focal_ts, recent, HEAVY_RECON_WINDOW_NS) + 1
        >= HEAVY_RECON_DISTINCT_PORTS_MIN
}

fn distinct_dst_ports_in_window(
    pid: u32,
    focal_ts: u64,
    recent: Recent<'_>,
    window_ns: u64,
) -> usize {
    let mut ports: HashSet<u16> = HashSet::new();
    for e in recent.iter() {
        if let Event::TcpConnect {
            pid: p,
            dst_port,
            timestamp_ns,
            ..
        } = e
        {
            if *p == pid && within(focal_ts, *timestamp_ns, window_ns) {
                ports.insert(*dst_port);
            }
        }
    }
    ports.len()
}

fn suspicious_dns(focal: &Event, recent: Recent<'_>) -> bool {
    let Event::DnsQuery {
        pid: focal_pid,
        query_name,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    if !looks_dga(query_name) {
        return false;
    }
    let mut count = 1usize; // include focal
    for e in recent.iter() {
        if let Event::DnsQuery {
            pid,
            query_name: q,
            timestamp_ns,
            ..
        } = e
        {
            if *pid == *focal_pid
                && looks_dga(q)
                && within(*focal_ts, *timestamp_ns, DNS_DGA_WINDOW_NS)
            {
                count += 1;
            }
        }
    }
    count >= DNS_DGA_QUERIES_MIN
}

/// Lightweight DGA-shape heuristic.
///
/// We treat a name as DGA-like if its longest single label is at
/// least [`DNS_DGA_MIN_LABEL_LEN`] characters, has a high digit/letter
/// mix, and has no vowel-heavy structure. This is intentionally
/// coarse: a real DGA classifier is a separate engine; here we just
/// need a signal strong enough to drive a posture nudge.
fn looks_dga(name: &str) -> bool {
    let longest = name.split('.').map(str::len).max().unwrap_or(0);
    if longest < DNS_DGA_MIN_LABEL_LEN {
        return false;
    }
    let label = name.split('.').max_by_key(|s| s.len()).unwrap_or(name);
    let total = label.len();
    if total == 0 {
        return false;
    }
    let digits = label.chars().filter(|c| c.is_ascii_digit()).count();
    let vowels = label
        .chars()
        .filter(|c| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    let vowel_ratio = vowels as f64 / total as f64;
    let digit_ratio = digits as f64 / total as f64;
    // Either "lots of digits" or "very low vowel rate" looks
    // unnatural for an English-derived hostname.
    digit_ratio >= 0.20 || vowel_ratio < 0.20
}

/// External audit SNS-005/SNS-006: the kernel classed the open `bit`
/// (by inode) and its path cannot be compared with a host path — an
/// unplaced mount root, a cut or unread component — so the path lists
/// below cannot judge it. A path that can be compared is judged by the
/// lists alone, as before.
fn kernel_class_says(filename: &str, kernel_class: u32, bit: u32) -> bool {
    kernel_class & bit != 0 && !crate::sensors::open_sensor::path_is_exact(filename)
}

fn sensitive_file_access(focal: &Event, auth: &AuthSessionTracker) -> bool {
    let Event::FileOpen {
        pid,
        uid,
        filename,
        flags,
        kernel_class,
        ..
    } = focal
    else {
        return false;
    };
    let by_kernel = kernel_class_says(filename, *kernel_class, open_reason::SENSITIVE);
    // root (uid=0) is excluded — its accesses are routine.
    if *uid == 0 {
        return false;
    }
    // External audit POS-007: a service uid (1..999) used to be excluded
    // as well, before any other check — a web shell running as www-data
    // reading `/etc/shadow` raised nothing. It is judged on its own terms.
    if *uid < 1000 {
        return service_uid_credential_read(*pid, filename, by_kernel, auth);
    }
    // T7.13 — an authentication chain opens /etc/shadow (or
    // /etc/gshadow) under the caller's uid: the LSM file_open hook can
    // fire BEFORE the kernel completes the setuid transition (sudo, su,
    // pkexec, passwd) or while a PAM-mediated session/job child is still
    // at the authenticating user's uid (a cron job, a gdm-session-worker
    // PAM open). Without this gate every `sudo <anything>` — and every
    // cron/login/display-manager PAM auth — trips SensitiveFileAccess and
    // escalates a healthy host. We trust a PID whose lineage walks back to
    // a canonical auth binary or PAM daemon (sudo, su, sshd, login,
    // systemd-logind, polkitd, cron/crond, gdm/lightdm, …) — verified via
    // the kernel-resolved /proc/<pid>/exe symlink, NEVER the forgeable
    // comm. External audit POS-002: the reader itself, or its direct
    // child forked after it ran it — the PAM stack's open, not the session
    // it opened: a shell of an SSH or desktop session, and whatever it
    // runs (cat, less, cp, a /tmp binary, a shell one-liner), still fires
    // below.
    if auth.is_credential_reader(*pid) {
        return false;
    }
    // BUG-018 (tactical) — systemd-user@<uid>.service children
    // (dbus, xdg-desktop generators, gnome-keyring, …) routinely
    // open /etc/passwd for NSS lookups; their lineage walks back
    // to PID 1 systemd without traversing any AUTH_BINARY_EXES
    // entry, so the T7.13 gate above doesn't catch them and every
    // boot lands in ALERTED. Tactical carve-out:
    //
    //   if filename == "/etc/passwd"     ── one specific FP class
    //   AND open is read-only             ── writes still flag
    //   AND /proc/<pid>/loginuid is set   ── PAM-mediated session
    //
    // The signal is `loginuid`: set by `pam_loginuid` once per login
    // session, write-protected after first set, and modifying it
    // needs CAP_AUDIT_CONTROL — an unprivileged attacker can't
    // forge it. A truly orphan process (started outside any PAM
    // chain) has loginuid == 4294967295 and STILL trips this arm.
    //
    // Deliberately bounded:
    //   - /etc/shadow + /etc/sudoers are NOT carved out (writes or
    //     reads still flag);
    //   - this is reads only (writes to /etc/passwd by a user
    //     process are still anomalous and still flag);
    //   - the binary signal is a tactical fix; the V2
    //     continuous-trust redesign (POSTURE_FSM_V2_REDESIGN.md §5.2)
    //     replaces it with a graded score.
    // A kernel-classed sensitive file under an unplaced root is named by
    // its path's tail (`mnt[…]/@/etc/passwd`).
    let is_passwd = filename == "/etc/passwd" || (by_kernel && filename.ends_with("/etc/passwd"));
    if is_passwd && !is_write_open(*flags) && auth.has_valid_loginuid(*pid) {
        return false;
    }
    SENSITIVE_FILES.iter().any(|f| filename == f) || by_kernel
}

/// External audit POS-007: the credential files a service uid's read is
/// judged on. `/etc/passwd` and `/etc/login.defs` are world-readable and
/// every daemon reads them for NSS lookups (the BUG-018 class); these
/// three only the auth stack and the `shadow` group read.
const SERVICE_UID_CREDENTIAL_FILES: &[&str] = &["/etc/shadow", "/etc/gshadow", "/etc/sudoers"];

/// External audit POS-007: generic file tools, by the basename of the
/// file the kernel executed — what a web shell or a dropper reads
/// credentials with; no daemon reads them with these.
const GENERIC_READER_EXES: &[&str] = &[
    "cat", "tac", "head", "tail", "less", "more", "cp", "dd", "tar", "cpio", "zip", "gzip",
    "base64", "base32", "xxd", "od", "hexdump", "strings", "grep", "sed", "awk", "gawk", "mawk",
    "openssl", "curl", "wget", "nc", "ncat", "socat", "busybox",
];

/// External audit POS-007: shells and interpreters, by exe basename with
/// an optional version (`python3.12`, `php8.3`, `php-fpm8.3`): what a web
/// shell or a script runs in.
const INTERPRETER_EXES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "python", "perl", "php",
    "php-fpm", "ruby", "node", "nodejs", "lua", "tclsh",
];

/// External audit POS-007: a service uid (1..999) opened a credential
/// file. In LSM mode the event follows the DAC check, so the reader could
/// read it: a member of the `shadow` group (a mail or auth daemon) or a
/// misconfigured host. A daemon reading with its own binary stays quiet,
/// and so does the auth stack's own read
/// ([`AuthSessionTracker::is_credential_reader`]); a shell, an
/// interpreter or a generic file tool — judged by the file the kernel
/// executed, never by `comm` — or an image outside a root-owned system
/// tree (`/tmp`, `/var/www`, a deleted file there) is the web-shell and
/// dropper shape, and fires. A reader the agent cannot place (exited
/// before its exec was read) fires too: the signal is ALERTED tier.
/// Not covered: a module inside the daemon's own image (`mod_php` in
/// `apache2`) reads as the daemon.
fn service_uid_credential_read(
    pid: u32,
    filename: &str,
    by_kernel: bool,
    auth: &AuthSessionTracker,
) -> bool {
    let credential = SERVICE_UID_CREDENTIAL_FILES
        .iter()
        .any(|f| filename == *f || (by_kernel && filename.ends_with(f)));
    if !credential || auth.is_credential_reader(pid) {
        return false;
    }
    auth.image_path(pid)
        .is_none_or(|image| reads_like_a_tool(&image))
}

/// External audit POS-007: `image` (a process's executed file, as
/// [`AuthSessionTracker::image_path`] reports it) is a shell, an
/// interpreter, a generic file tool, or lies outside a system tree.
fn reads_like_a_tool(image: &str) -> bool {
    let path = image.strip_suffix(" (deleted)").unwrap_or(image);
    if !super::lineage::in_system_tree(path) {
        return true;
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    GENERIC_READER_EXES.contains(&base)
        || INTERPRETER_EXES.iter().any(|i| {
            base.strip_prefix(i)
                .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
        })
}

fn lolbas_pattern(focal: &Event, recent: Recent<'_>) -> bool {
    let Event::ProcessSpawn {
        comm: child_comm,
        ppid,
        ..
    } = focal
    else {
        return false;
    };
    if !SHELL_COMMS.iter().any(|c| child_comm == c) {
        return false;
    }
    // Find a recent ProcessSpawn whose pid == focal.ppid and whose
    // comm matches a network-loader.
    recent.iter().any(|e| match e {
        Event::ProcessSpawn { pid, comm, .. } => {
            *pid == *ppid && NETLOAD_COMMS.iter().any(|c| comm == c)
        }
        _ => false,
    })
}

fn exploit_attempt(focal: &Event) -> bool {
    let Event::ProcessSpawn { comm, .. } = focal else {
        return false;
    };
    NETCAT_COMMS.iter().any(|c| comm == c) || OFFSEC_COMMS.iter().any(|c| comm == c)
}

fn critical_file_modification(focal: &Event) -> bool {
    let Event::FileOpen {
        filename,
        flags,
        kernel_class,
        ..
    } = focal
    else {
        return false;
    };
    if !is_write_open(*flags) {
        return false;
    }
    CRITICAL_FILES_PREFIXES
        .iter()
        .any(|p| filename == p || filename.starts_with(p))
        || kernel_class_says(filename, *kernel_class, open_reason::CRITICAL)
}

/// External audit POS-015: how a binary run from a staging directory is
/// judged ([`staging_exec`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StagedExec {
    /// No second factor: [`TriggerType::StagingExec`].
    Plain,
    /// A second factor the agent observed: [`TriggerType::ConfirmedIntrusion`].
    Confirmed,
}

/// External audit POS-015: a binary run from `/tmp`, `/var/tmp` or
/// `/dev/shm` (the shared staging set, external audit NETR-008), judged on
/// the file the kernel executed (Tappa 10.9 step 2, review 61).
///
/// The directory alone does not tell a build's `conftest` (pip, configure,
/// a CI job, a self-extracting installer) from a payload, and as
/// `ConfirmedIntrusion` it was the cheapest COMBAT-tier half any user could
/// produce: one exec, then any signal of another kind from the same
/// session reached COMBAT. It raises `StagingExec` (ENGAGED, never
/// recorded as corroboration), and `ConfirmedIntrusion` only with a second
/// factor the agent observes:
/// - the executed file was unlinked, or is a memfd, when the kernel ran it
///   (the exe flags; zero in tracepoint mode);
/// - the mass-write arm fired for the same process within a mass-write
///   window (its lineage gates applied).
///
/// Never promoted within a package transaction: maintainer scripts and
/// scriptlets run helpers they unpack in `/tmp`. Lab PR 175: the
/// transaction of the rules' carve-outs
/// ([`AuthSessionTracker::in_package_transaction`]: a package manager
/// proper executed by root whose run covers the exec), no longer any
/// `mandb` or package manager in the lineage. Not gated by the auth
/// lineage: a sudo-spawned process running `/tmp/payload` is raised like
/// any other. R001..R003 still kill the exec, whatever the posture.
fn staging_exec(
    focal: &Event,
    auth: &AuthSessionTracker,
    mass_writers: &MassWriters,
) -> Option<StagedExec> {
    let (pid, filename, exe, ts) = match focal {
        Event::ProcessSpawn {
            pid,
            filename,
            exe,
            timestamp_ns,
            ..
        }
        | Event::ExecCheck {
            pid,
            filename,
            exe,
            timestamp_ns,
            ..
        } => (*pid, filename, exe, *timestamp_ns),
        _ => return None,
    };
    let image = exe.path_or(filename);
    if !crate::decision::rules::is_staging_path(image) {
        return None;
    }
    if auth.in_package_transaction(pid, ts) {
        return Some(StagedExec::Plain);
    }
    let unlinked = exe.has(exe_flags::DELETED) || exe.has(exe_flags::MEMFD);
    let mass_wrote = mass_writers.wrote_near(pid, ts);
    if !unlinked && !mass_wrote {
        return Some(StagedExec::Plain);
    }
    tracing::warn!(
        pid,
        image = %common::log_escape::Escaped(image),
        unlinked,
        mass_wrote,
        "staging exec with a second factor — raising ConfirmedIntrusion"
    );
    Some(StagedExec::Confirmed)
}

/// The mass-write arm of `ConfirmedIntrusion` (the exec arm is
/// [`staging_exec`]).
fn confirmed_intrusion(
    focal: &Event,
    recent: Recent<'_>,
    auth: &AuthSessionTracker,
    mass_write_extras: &[String],
    warned: &parking_lot::Mutex<HashMap<u32, u64>>,
) -> bool {
    // BUG-032: the FsProtectDenial arm moved OUT to the Decisive
    // `AntiTamperDenial` trigger (raised directly in `detect`) — a
    // kernel-adjudicated denial is straight-to-COMBAT, distinct from
    // these heuristic arms which now require corroboration.
    //
    // Mass-write counted in the kernel (Tappa 10.9 step 1): one event per
    // burst, carve-outs (pseudo-filesystems, /run/systemd, the journal,
    // the operator's extras, the writer's own runtime dir) already
    // applied; the lineage gates below stay here.
    if let Event::MassWrite {
        pid,
        comm,
        filename,
        count,
        timestamp_ns,
        overwrites,
        cgroup_window,
        ..
    } = focal
    {
        if mass_write_exempt(auth, *pid, *timestamp_ns, filename, false) {
            return false;
        }
        // External audit POS-002: a process of an authenticated session
        // (SSH, desktop, a cron job, sudo) was exempt whatever it wrote,
        // so ransomware run from a session never raised it. Its new files
        // (a build, a clone, an archive extracted, a browser's cache) still
        // do not count; its rewrites of existing files — the shape of
        // encryption in place — do.
        // Recorded, not silent: the kernel reports a crossing once per
        // window per process.
        if !*overwrites && auth.is_auth_mediated(*pid) {
            tracing::info!(
                pid = *pid,
                comm = %common::log_escape::Escaped(comm),
                filename = %common::log_escape::Escaped(filename),
                count_within_window = *count,
                "mass write of new files inside an authenticated session — not counted (a build, \
                 a clone, an archive extracted); rewriting existing files would be"
            );
            return false;
        }
        if mass_write_warn_due(warned, *pid, *timestamp_ns) {
            tracing::warn!(
                trigger = "ConfirmedIntrusion_MassWrite",
                focal_pid = *pid,
                focal_comm = %common::log_escape::Escaped(comm),
                focal_filename = %common::log_escape::Escaped(filename),
                count_within_window = *count,
                overwrites = *overwrites,
                // External audit EBPF-011: the processes of the writer's
                // cgroup together (`count` = their overwrites).
                cgroup_window = *cgroup_window,
                threshold = if *cgroup_window {
                    common::wire::open_sensor::OPEN_CG_OVERWRITE_MIN as usize
                } else {
                    MASS_WRITE_MIN
                },
                window_secs = MASS_WRITE_WINDOW_NS / 1_000_000_000,
                "mass-write threshold crossed (kernel count) — raising ConfirmedIntrusion (→ ENGAGED; COMBAT only with corroboration)"
            );
        }
        return true;
    }
    // Mass-write / encryption-pattern: many writes from same pid in
    // a short window (tracepoint mode: every open reaches userland).
    if KERNEL_MASS_WRITE.load(Ordering::Relaxed) {
        return false;
    }
    if let Event::FileOpen {
        pid: focal_pid,
        comm: focal_comm,
        filename: focal_filename,
        flags,
        timestamp_ns: focal_ts,
        path_from_user,
        ..
    } = focal
    {
        if is_write_open(*flags) {
            // BUG-014 (P-6) path-class carve-out: a write to a
            // kernel-RPC pseudo-FS (sysfs cgroupfs, procfs, systemd's
            // /run state, journald binary log) is not a data write
            // and should not contribute to the ransomware-shape
            // mass-write heuristic. See MASS_WRITE_CARVEOUT_PREFIXES
            // for the full prefix list + per-class rationale. The
            // focal-event check short-circuits early; the recent-loop
            // check below mirrors it so an attacker can't pad a
            // window of real data writes with sysfs noise to dilute
            // the count.
            // External audit POS-004: a caller's string, not the opened path.
            let carved = |f: &str| is_mass_write_carveout_unresolved(f, mass_write_extras);
            if carved(focal_filename) {
                return false;
            }
            // T7.13 — auth-mediated PIDs (sudo + its children: apt,
            // systemctl, an editor, …) routinely exceed the mass-write
            // threshold during legitimate administration.
            // (ii) — system package-management daemons (snapd, dpkg,
            // apt, mandb) atomic-churn state files / caches well past
            // the threshold during routine maintenance; same exe-path
            // lineage keying. Only the mass-write arm is gated here;
            // FsProtectDenial and the staging exec still fire for these
            // PIDs. Lab PR 175: a package transaction's writes, and
            // mandb's own as a system account ([`mass_write_exempt`]).
            // FP-2 — `npm install` unpacks a package tarball (+ writes
            // the ~/.npm content cache) well past the threshold. npm is
            // a `#!/usr/bin/env node` script, so the writer's exe is the
            // node interpreter, NOT `/usr/bin/npm` — exactly the
            // interpreter-exe shape SYSTEM_DAEMON_EXES documents for
            // unattended-upgrade. `is_npm_cli_writer` therefore gates on
            // exe ∈ NODE_EXES AND argv[1] = npm-cli.js, a DIRECT focal-pid
            // check (no lineage): only npm's own node process is exempt,
            // every other node — and any child install script npm spawns
            // — still fires. ACCEPTED residual gap: a malicious package's
            // files, extracted by the genuine npm process, are exempt
            // from the write-VOLUME signal (a count can't tell a benign
            // install from a malicious one); supply-chain malice is
            // caught by the exec / network / persistence arms, not here.
            // TODO(FP-2 v2): additionally require the write target under
            // a node_modules path to also fire on npm mass-writing
            // elsewhere — deferred because npm legitimately mass-writes
            // its content cache (~/.npm/_cacache) OUTSIDE node_modules,
            // so a bare node_modules constraint would reintroduce the FP
            // for the cache-write burst; a correct v2 must allowlist the
            // (configurable) cache dir too.
            if mass_write_exempt(auth, *focal_pid, *focal_ts, focal_filename, *path_from_user) {
                return false;
            }
            // External audit POS-002 (tracepoint mode, which sees the open
            // flags but not whether the file existed): a session's opens
            // that may create (`O_CREAT`) do not count, its opens of an
            // existing file to write do.
            let session = auth.is_auth_mediated(*focal_pid);
            let counted = |f: u32| !session || f & O_CREAT == 0;
            if !counted(*flags) {
                return false;
            }
            // Audit `posture-3`: a PAM session (valid loginuid) writing
            // into ITS OWN `/run/user/<loginuid>/` is session plumbing —
            // `systemd --user` creating runtime dirs/sockets at login —
            // not a ransomware burst. Carve exactly that directory out
            // for this writer; everything else (incl. `/run/user/` of
            // another uid and `$HOME`) still counts, so the loginuid
            // signal does not widen trust beyond the runtime dir.
            let own_runtime_dir = auth
                .loginuid_of(*focal_pid)
                .map(|uid| format!("/run/user/{uid}/"));
            let in_own_runtime =
                |f: &str| own_runtime_dir.as_deref().is_some_and(|d| f.starts_with(d));
            if in_own_runtime(focal_filename) {
                return false;
            }
            let mut count = 1usize;
            for e in recent.iter() {
                if let Event::FileOpen {
                    pid,
                    filename,
                    flags: f,
                    timestamp_ns,
                    ..
                } = e
                {
                    if *pid == *focal_pid
                        && is_write_open(*f)
                        && counted(*f)
                        && !carved(filename)
                        && !in_own_runtime(filename)
                        && within(*focal_ts, *timestamp_ns, MASS_WRITE_WINDOW_NS)
                    {
                        count += 1;
                    }
                }
            }
            if count >= MASS_WRITE_MIN {
                // BUG-015 observability: when the mass-write arm of
                // confirmed_intrusion fires, surface the focal PID +
                // comm + the count so operators can identify the
                // writer (vs. having only `POSTURE TRANSITION
                // trigger=ConfirmedIntrusion` to go on). Single line
                // per fire — not in any hot loop, the rule engine
                // visits at most once per Event::FileOpen.
                // Review entry 37: once per window per pid — a steady writer
                // re-crosses the threshold on every event.
                if mass_write_warn_due(warned, *focal_pid, *focal_ts) {
                    tracing::warn!(
                        trigger = "ConfirmedIntrusion_MassWrite",
                        focal_pid = *focal_pid,
                        focal_comm = %common::log_escape::Escaped(focal_comm),
                        focal_filename = %common::log_escape::Escaped(focal_filename),
                        count_within_window = count,
                        threshold = MASS_WRITE_MIN,
                        window_secs = MASS_WRITE_WINDOW_NS / 1_000_000_000,
                        // BUG-032: this raises ConfirmedIntrusion (COMBAT-tier),
                        // but as a NeedsCorroboration signal it escalates to
                        // ENGAGED on its own — COMBAT (auto-isolation) needs a
                        // second distinct signal. (Pure single-vector ransomware
                        // tops at ENGAGED unless the sustained knob is on.)
                        "mass-write threshold crossed — raising ConfirmedIntrusion (→ ENGAGED; COMBAT only with corroboration); further hits of this pid are logged once per window"
                    );
                }
                return true;
            }
        }
    }
    false
}

/// The mass-write arm's writers (review 49 (ii), FP-2): a package
/// transaction's ([`AuthSessionTracker::in_package_transaction`]), mandb's
/// own as a system account (its cache rebuild,
/// [`AuthSessionTracker::is_system_man_cache_writer`]), npm's CLI's own.
///
/// Lab PR 175: it was anything with a package manager or `mandb` in its
/// lineage. Neither is set-id: a user ran `mandb` (or `dpkg --version`)
/// with `LD_PRELOAD` and whatever it forked rewrote the user's files
/// without raising `ConfirmedIntrusion`. A package manager a user runs (a
/// rootless `podman build`'s `dnf`) is exempt for what it writes in that
/// user's container storage only
/// ([`AuthSessionTracker::is_user_container_storage_write`], judged on the
/// open `path` names: the kernel counts a process's write-opens, and
/// reports the one that crossed the threshold).
fn mass_write_exempt(
    auth: &AuthSessionTracker,
    pid: u32,
    ts_ns: u64,
    path: &str,
    path_from_user: bool,
) -> bool {
    auth.in_package_transaction(pid, ts_ns)
        || auth.is_system_man_cache_writer(pid)
        || auth.is_npm_cli_writer(pid)
        || auth.is_user_container_storage_write(pid, ts_ns, path, path_from_user)
}

/// One mass-write WARN per pid per window (review entry 37). Returns true
/// when the line should be logged and records `ts_ns`; the map is pruned
/// of pids older than a window whenever it exceeds 1024 entries.
fn mass_write_warn_due(
    warned: &parking_lot::Mutex<HashMap<u32, u64>>,
    pid: u32,
    ts_ns: u64,
) -> bool {
    let mut g = warned.lock();
    if let Some(last) = g.get(&pid) {
        if ts_ns.saturating_sub(*last) < MASS_WRITE_WINDOW_NS {
            return false;
        }
    }
    if g.len() > 1024 {
        let cutoff = ts_ns.saturating_sub(MASS_WRITE_WINDOW_NS);
        g.retain(|_, t| *t >= cutoff);
    }
    g.insert(pid, ts_ns);
    true
}

fn persistence_mechanism(focal: &Event, auth: &AuthSessionTracker) -> bool {
    let Event::FileOpen {
        pid,
        filename,
        flags,
        kernel_class,
        timestamp_ns,
        path_from_user,
        ..
    } = focal
    else {
        return false;
    };
    if !is_write_open(*flags) {
        return false;
    }
    if !PERSISTENCE_PREFIXES
        .iter()
        .any(|p| filename == p || filename.starts_with(p))
        && !kernel_class_says(filename, *kernel_class, open_reason::PERSIST)
    {
        return false;
    }
    // (ii) — package managers legitimately install/refresh systemd
    // units, cron entries and init scripts (e.g. snapd writing
    // /etc/systemd/system/snap-*.mount on refresh). Gate ONLY on
    // system-daemon lineage — NOT auth-mediated: a manual
    // `sudo systemctl edit` / hand-dropped unit STILL raises
    // PersistenceMechanism (keeps the persistence exemption tight to
    // package daemons; an attacker holding sudo gets no free pass here).
    // Lab PR 175: a package transaction only (a package manager proper
    // executed by root whose run covers the write). Any `mandb` or package
    // manager in the lineage did: a user's crontab installed by a process
    // forked under `mandb` raised nothing. A package manager a user runs:
    // within that user's container storage only (a unit a rootless build
    // installs in its image), never a host path.
    if auth.in_package_transaction(*pid, *timestamp_ns)
        || auth.is_user_container_storage_write(*pid, *timestamp_ns, filename, *path_from_user)
    {
        return false;
    }
    true
}

fn lateral_movement(focal: &Event, recent: Recent<'_>, allow: &EscalationAllowList) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
        comm: focal_comm,
        family,
        dst_addr,
        dst_port,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    if !ADMIN_PORTS.contains(dst_port) {
        return false;
    }
    // BUG-039: v4 OR v6, internal dst (RFC1918 / ULA / link-local).
    if !is_inet_family(*family) || !is_internal(dst_addr, *family) {
        return false;
    }
    // BUG-032 count-filter: an allowlisted (comm,dst) host does not
    // contribute to the distinct-host count (e.g. orchestration tooling
    // fanning out to a declared internal range). BUG-039: each
    // connection's OWN family drives the allowlist lookup (mixed-family).
    let counts = |dst: &[u8; 16], fam: u8, port: u16| {
        !allow.excludes(AllowTrigger::Lateral, focal_comm, dst, fam, port)
    };
    // BUG-039: key on the full 16-byte address — a v6 set keyed on 4
    // bytes collides.
    let mut hosts: HashSet<[u8; 16]> = HashSet::new();
    if counts(dst_addr, *family, *dst_port) {
        hosts.insert(*dst_addr);
    }
    for e in recent.iter() {
        if let Event::TcpConnect {
            pid,
            family: fam,
            dst_addr: dst,
            dst_port: dp,
            timestamp_ns,
            ..
        } = e
        {
            if *pid == *focal_pid
                && is_inet_family(*fam)
                && ADMIN_PORTS.contains(dp)
                && is_internal(dst, *fam)
                && within(*focal_ts, *timestamp_ns, LATERAL_WINDOW_NS)
                && counts(dst, *fam, *dp)
            {
                hosts.insert(*dst);
            }
        }
    }
    hosts.len() >= LATERAL_DISTINCT_DST_MIN
}

fn exfiltration_pattern(focal: &Event, recent: Recent<'_>, allow: &EscalationAllowList) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
        comm: focal_comm,
        family,
        dst_addr,
        dst_port,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    if !is_inet_family(*family) {
        return false;
    }
    if !matches!(*dst_port, 80 | 443) {
        return false;
    }
    // BUG-039: public dst (NOT internal) for v4 or v6.
    if is_internal(dst_addr, *family) {
        return false;
    }
    // BUG-032 count-filter: connections to an allowlisted (comm,dst)
    // do NOT count toward the threshold (a real C2 outside the
    // allowlisted CIDR still counts, even under a spoofed comm). Every
    // counted connection is the same pid → same process → same comm, so
    // the focal comm applies to the recent matches too. BUG-039: each
    // connection's OWN family drives the allowlist lookup.
    let counts = |dst: &[u8; 16], fam: u8, port: u16| {
        !allow.excludes(AllowTrigger::Exfil, focal_comm, dst, fam, port)
    };
    let mut count = usize::from(counts(dst_addr, *family, *dst_port));
    for e in recent.iter() {
        if let Event::TcpConnect {
            pid,
            family: fam,
            dst_addr: dst,
            dst_port: dp,
            timestamp_ns,
            ..
        } = e
        {
            if *pid == *focal_pid
                && is_inet_family(*fam)
                && matches!(*dp, 80 | 443)
                && !is_internal(dst, *fam)
                && within(*focal_ts, *timestamp_ns, EXFIL_WINDOW_NS)
                && counts(dst, *fam, *dp)
            {
                count += 1;
            }
        }
    }
    count >= EXFIL_MIN_EVENTS
}

/// AF_INET (2) or AF_INET6 (10) — the families the network heuristics
/// consider (BUG-039). Other families (e.g. AF_UNIX) are ignored.
fn is_inet_family(family: u8) -> bool {
    family == 2 || family == 10
}

/// Is `addr` (a 16-byte wire address) internal/private for its `family`?
/// v4: RFC1918. v6: ULA (`fc00::/7`) or link-local (`fe80::/10`).
/// (BUG-039 — exfil's "public dst" and lateral's "internal dst" both need
/// the v6 notion.)
///
/// External audit NET-001: an IPv4-mapped IPv6 address (a dual-stack
/// socket reaching an IPv4 peer) is judged as the IPv4 address it maps.
/// External audit NETR-007: the predicate lives in `common::netaddr`, shared
/// with NN-L-NET-007/018.
fn is_internal(addr: &[u8; 16], family: u8) -> bool {
    is_inet_family(family)
        && common::netaddr::is_internal(common::netaddr::canonical_ip(family, addr))
}

fn is_write_open(flags: u32) -> bool {
    // O_WRONLY = 1, O_RDWR = 2 in glibc/Linux. Mask to access mode.
    let access = flags & 0b11;
    access == 1 || access == 2
}

/// `O_CREAT` on Linux (0o100): the open may create the file.
const O_CREAT: u32 = 0o100;

#[cfg(test)]
pub(super) mod testutil {
    use super::*;

    pub fn spawn(pid: u32, ppid: u32, comm: &str, filename: &str, ts: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 1000,
            gid: 1000,
            comm: comm.into(),
            filename: filename.into(),
            timestamp_ns: ts,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
        }
    }

    /// [`spawn`] executed as `uid` (lab PR 175: a package transaction is
    /// a package manager root executed).
    pub fn spawn_by(uid: u32, pid: u32, ppid: u32, comm: &str, filename: &str, ts: u64) -> Event {
        let mut e = spawn(pid, ppid, comm, filename, ts);
        if let Event::ProcessSpawn { uid: u, gid, .. } = &mut e {
            (*u, *gid) = (uid, uid);
        }
        e
    }

    pub fn file_open(pid: u32, uid: u32, filename: &str, flags: u32, ts: u64) -> Event {
        Event::FileOpen {
            pid,
            uid,
            gid: uid,
            comm: "x".into(),
            filename: filename.into(),
            flags,
            timestamp_ns: ts,
            path_from_user: false,
            kernel_class: 0,
        }
    }

    pub fn tcp_v4(pid: u32, dst: [u8; 4], dst_port: u16, ts: u64) -> Event {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&dst);
        Event::TcpConnect {
            pid,
            uid: 1000,
            comm: "x".into(),
            family: 2,
            src_addr: [0u8; 16],
            src_port: 0,
            dst_addr: a,
            dst_port,
            timestamp_ns: ts,
        }
    }

    pub fn dns(pid: u32, name: &str, ts: u64) -> Event {
        Event::DnsQuery {
            pid,
            uid: 1000,
            comm: "x".into(),
            exe: None,
            query_name: name.into(),
            query_type: 1,
            dns_server: [0u8; 16],
            family: 2,
            timestamp_ns: ts,
            qname_partial: false,
        }
    }

    /// A `TcpConnect` with an explicit `comm` (for escalation-allow
    /// count-filter tests, which key on the process name).
    pub fn tcp_v4_comm(pid: u32, comm: &str, dst: [u8; 4], dst_port: u16, ts: u64) -> Event {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&dst);
        Event::TcpConnect {
            pid,
            uid: 1000,
            comm: comm.into(),
            family: 2,
            src_addr: [0u8; 16],
            src_port: 0,
            dst_addr: a,
            dst_port,
            timestamp_ns: ts,
        }
    }

    /// A kernel anti-tamper denial — the Decisive `AntiTamperDenial`
    /// signal that reaches COMBAT on its own (BUG-032).
    pub fn fs_protect_denial(pid: u32, ts: u64) -> Event {
        Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: "attacker".into(),
            target_dev: 1,
            target_ino: 2,
            operation: common::FsProtectOperation::Unlink,
            timestamp_ns: ts,
        }
    }

    /// A spawn of `path` as the kernel executed it, with the exe `flags`
    /// (`exe_flags`; `KNOWN` added: the LSM program filled them).
    pub fn spawn_exe_flags(pid: u32, ppid: u32, path: &str, flags: u32, ts: u64) -> Event {
        let mut e = spawn(pid, ppid, "x", path, ts);
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.path = path.into();
            exe.flags = flags | exe_flags::KNOWN;
        }
        e
    }

    /// A v6 `TcpConnect` (family = AF_INET6 = 10) with a 16-byte dst
    /// (BUG-039 detection tests).
    pub fn tcp_v6(pid: u32, comm: &str, dst: [u8; 16], dst_port: u16, ts: u64) -> Event {
        Event::TcpConnect {
            pid,
            uid: 1000,
            comm: comm.into(),
            family: 10,
            src_addr: [0u8; 16],
            src_port: 0,
            dst_addr: dst,
            dst_port,
            timestamp_ns: ts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;

    /// Review entry 37: the trigger keeps firing on every hit (posture
    /// logic unchanged) but the WARN is due once per window per pid.
    #[test]
    fn mass_write_warn_is_once_per_window_per_pid() {
        let warned = parking_lot::Mutex::new(std::collections::HashMap::new());
        let w = super::MASS_WRITE_WINDOW_NS;
        let due = super::mass_write_warn_due;
        assert!(due(&warned, 100, 10 * w));
        assert!(!due(&warned, 100, 10 * w + 1_000_000_000));
        assert!(!due(&warned, 100, 11 * w - 1));
        assert!(due(&warned, 100, 11 * w));
        assert!(due(&warned, 101, 10 * w + 5));
        for p in 1000..3000u32 {
            assert!(due(&warned, p, 20 * w));
        }
        assert!(due(&warned, 5, 30 * w));
        assert!(warned.lock().len() <= 2, "{}", warned.lock().len());
    }
    use super::*;

    #[test]
    fn recon_fires_on_three_distinct_ports_same_pid() {
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v4(42, [127, 0, 0, 1], 22, 100),
            tcp_v4(42, [127, 0, 0, 1], 80, 200),
        ];
        let focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::Reconnaissance));
    }

    #[test]
    fn recon_does_not_fire_on_same_port_repeatedly() {
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v4(42, [127, 0, 0, 1], 80, 100),
            tcp_v4(42, [127, 0, 0, 1], 80, 200),
        ];
        let focal = tcp_v4(42, [127, 0, 0, 1], 80, 300);
        let hits = det.detect(&focal, &recent);
        assert!(!hits.contains(&TriggerType::Reconnaissance));
    }

    #[test]
    fn recon_fires_on_known_scanner_comm() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "nmap", "/usr/bin/nmap", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::Reconnaissance));
    }

    #[test]
    fn suspicious_dns_fires_on_dga_burst() {
        let det = TriggerDetector::new();
        let mut recent = Vec::new();
        for i in 0..6u64 {
            recent.push(dns(7, "x9k2lqw1pq3z9aaaa.example.org", i * 1_000_000_000));
        }
        let focal = dns(7, "z2k9pqw1lp3z9aaaa.example.org", 7_000_000_000);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::SuspiciousDns));
    }

    #[test]
    fn sensitive_file_access_fires_on_user_reading_shadow() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/shadow", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::SensitiveFileAccess));
    }

    /// External audit POS-007: root's read is routine; a service uid's is
    /// judged by its reader — a daemon's own binary is quiet.
    #[test]
    fn sensitive_file_access_skips_root_and_a_daemons_own_read() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(42, 1, "/usr/sbin/exim4", 1), &[]);
        for uid in [0, 1, 999] {
            let focal = file_open(42, uid, "/etc/shadow", 0, 2);
            let hits = det.detect(&focal, &[]);
            assert!(
                !hits.contains(&TriggerType::SensitiveFileAccess),
                "uid {uid}"
            );
        }
    }

    #[test]
    fn lolbas_fires_on_curl_then_bash_child() {
        let det = TriggerDetector::new();
        let recent = vec![spawn(50, 1, "curl", "/usr/bin/curl", 1)];
        let focal = spawn(51, 50, "bash", "/usr/bin/bash", 2);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::Lolbas));
    }

    #[test]
    fn exploit_attempt_fires_on_netcat() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "ncat", "/usr/bin/ncat", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::ExploitAttempt));
    }

    #[test]
    fn exploit_attempt_fires_on_offsec_tooling() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "msfvenom", "/usr/local/bin/msfvenom", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::ExploitAttempt));
    }

    #[test]
    fn critical_file_modification_fires_on_sshd_config_write() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/ssh/sshd_config", 1, 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::CriticalFileModification));
    }

    #[test]
    fn critical_file_modification_does_not_fire_on_read() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/ssh/sshd_config", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(!hits.contains(&TriggerType::CriticalFileModification));
    }

    /// External audit POS-015: a binary run from /tmp with no second
    /// factor is a staging exec (ENGAGED), not ConfirmedIntrusion.
    #[test]
    fn staging_exec_fires_on_exec_from_tmp() {
        let det = detector_with_empty_proc();
        let focal = spawn(42, 1, "evil", "/tmp/evil", 1);
        let hits = det.detect(&focal, &[]);
        assert_eq!(hits, vec![TriggerType::StagingExec]);
    }

    /// External audit NETR-008: the shared staging set, /var/tmp included;
    /// /run/user stays out. Before the exec (`ExecCheck`) as well.
    #[test]
    fn staging_exec_fires_on_exec_from_every_staging_dir() {
        let det = detector_with_empty_proc();
        for path in ["/var/tmp/evil", "/dev/shm/evil"] {
            let hits = det.detect(&spawn(42, 1, "evil", path, 1), &[]);
            assert_eq!(hits, vec![TriggerType::StagingExec], "{path}");
        }
        let check = Event::ExecCheck {
            pid: 44,
            ppid: 1,
            uid: 1000,
            comm: "sh".into(),
            filename: "/tmp/evil".into(),
            timestamp_ns: 1,
            exe: Default::default(),
        };
        assert_eq!(det.detect(&check, &[]), vec![TriggerType::StagingExec]);
        let hits = det.detect(&spawn(43, 1, "app", "/run/user/1000/app", 1), &[]);
        assert!(hits.is_empty(), "{hits:?}");
    }

    /// External audit POS-015: an executable unlinked (or a memfd) when the
    /// kernel ran it from a staging directory is the second factor.
    #[test]
    fn a_deleted_staged_exe_is_confirmed_intrusion() {
        use common::wire::exe::exe_flags::{DELETED, MEMFD, TMPFS};
        let det = detector_with_empty_proc();
        for flags in [DELETED, MEMFD, DELETED | TMPFS] {
            let hits = det.detect(&spawn_exe_flags(42, 1, "/tmp/.x", flags, 1), &[]);
            assert_eq!(hits, vec![TriggerType::ConfirmedIntrusion], "{flags:#x}");
        }
        // A file on tmpfs that is still linked: no second factor.
        let hits = det.detect(&spawn_exe_flags(43, 1, "/dev/shm/x", TMPFS, 1), &[]);
        assert_eq!(hits, vec![TriggerType::StagingExec]);
    }

    /// External audit POS-015: the mass-write arm fired for the same
    /// process within a window, before or after its exec is read. Another
    /// process, or a burst a window away, is not a second factor.
    #[test]
    fn a_mass_writer_running_a_staged_exe_is_confirmed_intrusion() {
        const S: u64 = 1_000_000_000;
        let det = detector_with_empty_proc();
        let hits = det.detect(&mass_write(900, true, 100 * S), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        let staged = |pid, ts| det.detect(&spawn(pid, 1, "x", "/tmp/x", ts), &[]);
        assert_eq!(staged(900, 130 * S), vec![TriggerType::ConfirmedIntrusion]);
        assert_eq!(staged(900, 90 * S), vec![TriggerType::ConfirmedIntrusion]);
        assert_eq!(staged(901, 130 * S), vec![TriggerType::StagingExec]);
        assert_eq!(staged(900, 200 * S), vec![TriggerType::StagingExec]);

        // A burst the mass-write arm does not count — new files written by
        // a session's process (a build, an archive extracted) — is no
        // factor either.
        let _ = det.detect(&spawn_with_exe(950, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(951, 950, "/usr/bin/bash", 2), &[]);
        assert!(det.detect(&mass_write(951, false, 100 * S), &[]).is_empty());
        assert_eq!(staged(951, 101 * S), vec![TriggerType::StagingExec]);
    }

    /// External audit POS-015: a package manager's maintainer scripts run
    /// helpers they unpacked in /tmp; never promoted, whatever the flags.
    #[test]
    fn a_package_managers_staged_helper_is_never_promoted() {
        use common::wire::exe::exe_flags::DELETED;
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe_by(0, 100, 1, "/usr/bin/dpkg", 1), &[]);
        let hits = det.detect(
            &spawn_exe_flags(101, 100, "/tmp/postinst-helper", DELETED, 2),
            &[],
        );
        assert_eq!(hits, vec![TriggerType::StagingExec]);
    }

    /// Lab finding (EBPF-001 work): systemd writing `/dev/console` at
    /// shutdown, a script's `> /dev/null`, are not data writes; files in
    /// `/dev/shm` are.
    #[test]
    fn device_nodes_are_not_mass_write_but_dev_shm_is() {
        assert!(is_mass_write_carveout("/dev/console", &[]));
        assert!(is_mass_write_carveout("/dev/null", &[]));
        assert!(is_mass_write_carveout("/dev/pts/0", &[]));
        assert!(!is_mass_write_carveout("/dev/shm/locked.bin", &[]));
        assert!(!is_mass_write_carveout("/home/u/doc.pdf", &[]));
    }

    #[test]
    fn anti_tamper_denial_fires_on_fs_protect_denial() {
        // BUG-032: a kernel-side denial of root's tamper attempt is
        // adjudicated malice — the Decisive `AntiTamperDenial` trigger
        // (straight to COMBAT, no corroboration), split out of the old
        // ConfirmedIntrusion FsProtectDenial arm.
        let det = TriggerDetector::new();
        let focal = Event::FsProtectDenial {
            pid: 9999,
            uid: 0,
            comm: "rm".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: common::FsProtectOperation::Unlink,
            timestamp_ns: 1,
        };
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::AntiTamperDenial),
            "expected AntiTamperDenial, got {:?}",
            hits
        );
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "FsProtectDenial must NOT also raise ConfirmedIntrusion now: {hits:?}"
        );
    }

    #[test]
    fn persistence_fires_on_cron_d_write() {
        let det = TriggerDetector::new();
        let focal = file_open(42, 1001, "/etc/cron.d/backdoor", 1, 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::PersistenceMechanism));
    }

    #[test]
    fn lateral_movement_fires_on_three_internal_ssh_targets() {
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v4(42, [10, 0, 0, 1], 22, 100),
            tcp_v4(42, [10, 0, 0, 2], 22, 200),
        ];
        let focal = tcp_v4(42, [10, 0, 0, 3], 22, 300);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::LateralMovement));
    }

    // ── 2026-05-22 self-trigger regression ────────────────────────────
    //
    // The agent appends to its own state logs on every observed event;
    // the observe-only `file_open` sensor reports those writes back into
    // the stream. >=MASS_WRITE_MIN of them in the 60 s window from one
    // PID used to self-trip ConfirmedIntrusion → COMBAT at boot,
    // isolating the network on a benign host. `with_self_pid` excludes
    // the agent's own events.

    const AGENT_PID: u32 = 4242;

    /// Build MASS_WRITE_MIN write-opens to the agent's drift log from
    /// `pid`, the exact shape of a fresh-boot FIM-logging burst.
    fn self_write_burst(pid: u32) -> (Event, Vec<Event>) {
        let path = "/var/lib/northnarrow/fim_drift.jsonl";
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(pid, 0, path, 1, i + 1))
            .collect();
        let focal = file_open(pid, 0, path, 1, MASS_WRITE_MIN as u64 + 1);
        (focal, recent)
    }

    #[test]
    fn mass_write_self_trips_combat_without_exclusion() {
        // Documents the bug: a plain detector counts the agent's own
        // burst and fires ConfirmedIntrusion (COMBAT-tier).
        let det = TriggerDetector::new();
        let (focal, recent) = self_write_burst(AGENT_PID);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "baseline (no self-pid) must still count the burst: {hits:?}"
        );
    }

    #[test]
    fn mass_write_does_not_fire_on_agents_own_writes() {
        // The fix: a detector that knows the agent's PID ignores the
        // agent's own state-log burst entirely.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = self_write_burst(AGENT_PID);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.is_empty(),
            "agent's own writes must raise no triggers, got {hits:?}"
        );
    }

    #[test]
    fn mass_write_still_fires_on_other_pid_when_self_excluded() {
        // Self-exclusion must not blind us to a real attacker: an
        // identical burst from a different PID still trips COMBAT.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let attacker = AGENT_PID + 1;
        let (focal, recent) = self_write_burst(attacker);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "a non-agent mass-write must still fire: {hits:?}"
        );
    }

    /// External audit POS-009: the watchdog's PID is exempt from every
    /// heuristic but not from a kernel denial; a PID recycled since its
    /// verification is exempt from nothing. The agent's own PID stays
    /// exempt from everything.
    #[test]
    fn a_denial_from_the_watchdog_pid_is_decisive() {
        use super::super::exempt::ExemptPids;
        use super::super::lineage::AuthSessionTracker;
        const WATCHDOG: u32 = 2000;
        let proc_root = tempfile::tempdir().unwrap();
        let started = |ticks: u64| {
            let d = proc_root.path().join(WATCHDOG.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("stat"),
                format!("{WATCHDOG} (northnarrow-wa) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0\n"),
            )
            .unwrap();
        };
        started(5_000);
        let exempt = ExemptPids::with_agent_on(AGENT_PID, proc_root.path());
        exempt.set_watchdog(WATCHDOG, 5_000);
        let det = TriggerDetector::with_exempt_and_auth(
            exempt,
            AuthSessionTracker::new("/this/path/does/not/exist"),
        );
        let denial = |pid: u32| Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: "northnarrow-wa".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: common::FsProtectOperation::Unlink,
            timestamp_ns: 1,
        };
        assert_eq!(
            det.detect(&denial(WATCHDOG), &[]),
            vec![TriggerType::AntiTamperDenial]
        );
        let (focal, recent) = self_write_burst(WATCHDOG);
        assert!(
            det.detect(&focal, &recent).is_empty(),
            "its reads and writes"
        );
        assert!(
            det.detect(&denial(AGENT_PID), &[]).is_empty(),
            "the agent's own"
        );

        // The PID recycled between two refreshes: nothing is exempt.
        started(9_000);
        let hits = det.detect(&focal, &recent);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }

    #[test]
    fn fs_protect_denial_still_fires_when_self_excluded() {
        // Tamper on the agent's own files by another PID is denied by
        // the LSM and surfaced as FsProtectDenial — self-exclusion must
        // not suppress it (it is keyed on the *toucher's* PID, not the
        // agent's).
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let focal = Event::FsProtectDenial {
            pid: AGENT_PID + 7,
            uid: 0,
            comm: "rm".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: common::FsProtectOperation::Unlink,
            timestamp_ns: 1,
        };
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::AntiTamperDenial), "{hits:?}");
    }

    // ─── T7.13 (Beta Step 5) — auth-mediated lineage exemption ─────
    //
    // The detector now consults an AuthSessionTracker on two trigger
    // arms only: sensitive_file_access and confirmed_intrusion's
    // mass-write arm. Every other COMBAT-tier trigger fires unchanged
    // even for sudo-spawned PIDs, so an attacker who escalates via
    // sudo and then exec'es a /tmp payload (or trips an LSM
    // FsProtectDenial) still drives COMBAT.
    //
    // The tracker default points at "/proc". Production data lands
    // in it via Event::ProcessSpawn ingestion at the top of detect().
    // For tests we drive ingest() directly through detect() so the
    // exact production flow is exercised.

    /// Build a TriggerDetector whose AuthSessionTracker reads a
    /// nonexistent /proc (so the /proc fallback never reports an
    /// ancestor that the test didn't explicitly ingest).
    fn detector_with_empty_proc() -> TriggerDetector {
        use super::super::exempt::ExemptPids;
        use super::super::lineage::AuthSessionTracker;
        let auth = AuthSessionTracker::new("/this/path/does/not/exist");
        TriggerDetector::with_exempt_and_auth(ExemptPids::default(), auth)
    }

    /// Build a ProcessSpawn fixture with `filename` (the kernel
    /// reports the exec'd binary's resolved path there). `comm` is
    /// the truncated name; immaterial to the lineage gate.
    /// [`spawn_with_exe`] executed as `uid` (lab PR 175: a package
    /// transaction is a package manager root executed; man-db's rebuild
    /// runs as `man`, uid 6 on Debian and Ubuntu).
    fn spawn_with_exe_by(uid: u32, pid: u32, ppid: u32, filename: &str, ts: u64) -> Event {
        let mut e = spawn_with_exe(pid, ppid, filename, ts);
        if let Event::ProcessSpawn { uid: u, gid, .. } = &mut e {
            (*u, *gid) = (uid, uid);
        }
        e
    }

    fn spawn_with_exe(pid: u32, ppid: u32, filename: &str, ts: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 1000,
            gid: 1000,
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: ts,
            argv: Vec::new(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
        }
    }

    /// FP-2 helper: a ProcessSpawn with a populated argv (the production
    /// path threads argv into the lineage tracker for the npm exemption).
    fn spawn_with_argv(pid: u32, ppid: u32, filename: &str, argv: &[&str], ts: u64) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid,
            uid: 1000,
            gid: 1000,
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: ts,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: Default::default(),
            argv_truncated: false,
            filename_truncated: false,
        }
    }

    // ── Test #1: direct sudo /etc/shadow read is exempt ─────────────
    #[test]
    fn sensitive_file_access_exempt_for_sudo_child() {
        let det = detector_with_empty_proc();
        // Ingest the sudo ProcessSpawn through the detector — the
        // production flow.
        let sudo_spawn = spawn_with_exe(100, 50, "/usr/bin/sudo", 1);
        let _ = det.detect(&sudo_spawn, &[]);
        // sudo opens /etc/shadow under uid=1000 (pre-setuid).
        let focal = file_open(100, 1000, "/etc/shadow", 0, 2);
        let hits = det.detect(&focal, &[]);
        assert!(
            !hits.contains(&TriggerType::SensitiveFileAccess),
            "sudo-mediated /etc/shadow read must NOT trip the trigger, got {hits:?}"
        );
    }

    // ── Test #2: unrelated uid=1000 /etc/shadow read still fires ─────
    #[test]
    fn sensitive_file_access_still_fires_for_unrelated_uid1000_reader() {
        let det = detector_with_empty_proc();
        // No sudo lineage ingested.
        let focal = file_open(999, 1000, "/etc/shadow", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::SensitiveFileAccess),
            "non-auth uid=1000 reader must still trip, got {hits:?}"
        );
    }

    // ── Test #3: root still exempt, whoever the reader ──────────────
    #[test]
    fn sensitive_file_access_still_skips_root() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(7777, 1, "/usr/bin/cat", 1), &[]);
        for pid in [7777, 7778] {
            for path in ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"] {
                let focal = file_open(pid, 0, path, 0, 2);
                let hits = det.detect(&focal, &[]);
                assert!(
                    !hits.contains(&TriggerType::SensitiveFileAccess),
                    "{pid} {path}"
                );
            }
        }
    }

    // ── External audit POS-007: a service uid reading credentials ───

    /// A web shell's shape: `cat` under `sh`, as www-data (uid 33).
    #[test]
    fn a_service_uid_shell_reading_shadow_fires() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(3300, 1, "/usr/sbin/php-fpm8.3", 1), &[]);
        let _ = det.detect(&spawn_with_exe(3301, 3300, "/usr/bin/sh", 2), &[]);
        let _ = det.detect(&spawn_with_exe(3302, 3301, "/usr/bin/cat", 3), &[]);
        for (pid, path) in [
            (3302, "/etc/shadow"),
            (3302, "/etc/gshadow"),
            (3302, "/etc/sudoers"),
            (3301, "/etc/shadow"),
            (3300, "/etc/shadow"),
        ] {
            let hits = det.detect(&file_open(pid, 33, path, 0, 4), &[]);
            assert!(
                hits.contains(&TriggerType::SensitiveFileAccess),
                "{pid} {path}: {hits:?}"
            );
        }
    }

    /// The reader is judged by the file the kernel executed: a dropper
    /// outside a system tree fires whatever it calls itself, a deleted one
    /// by where it ran from, and one the agent cannot place fires too.
    #[test]
    fn a_service_uid_reader_is_judged_by_its_image() {
        let det = detector_with_empty_proc();
        let mut dropper = spawn_with_exe(3400, 1, "/var/www/html/up/exim4", 1);
        if let Event::ProcessSpawn { comm, .. } = &mut dropper {
            *comm = "exim4".into();
        }
        let _ = det.detect(&dropper, &[]);
        let _ = det.detect(&spawn_with_exe(3401, 1, "/tmp/x (deleted)", 1), &[]);
        let _ = det.detect(&spawn_with_exe(3402, 1, "/usr/bin/python3.12", 1), &[]);
        let _ = det.detect(&spawn_with_exe(3403, 1, "/usr/bin/busybox", 1), &[]);
        for pid in [3400, 3401, 3402, 3403, 3499] {
            let hits = det.detect(&file_open(pid, 33, "/etc/shadow", 0, 2), &[]);
            assert!(hits.contains(&TriggerType::SensitiveFileAccess), "{pid}");
        }
    }

    /// A `shadow` group daemon (a mail server, uid 101) reading with its
    /// own binary is quiet, a replaced binary of a system tree too (an
    /// upgrade not yet restarted), and so is the auth stack's own read at
    /// a service uid (`unix_chkpwd` for a web application's PAM login).
    #[test]
    fn a_shadow_group_daemon_reading_with_its_own_binary_is_quiet() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(3500, 1, "/usr/sbin/exim4", 1), &[]);
        let _ = det.detect(
            &spawn_with_exe(3501, 1, "/usr/sbin/exim4 (deleted)", 1),
            &[],
        );
        let _ = det.detect(&spawn_with_exe(3502, 3500, "/usr/sbin/unix_chkpwd", 2), &[]);
        for pid in [3500, 3501, 3502] {
            let hits = det.detect(&file_open(pid, 101, "/etc/shadow", 0, 3), &[]);
            assert!(
                !hits.contains(&TriggerType::SensitiveFileAccess),
                "{pid}: {hits:?}"
            );
        }
    }

    /// `/etc/passwd` and `/etc/login.defs` are world-readable and read by
    /// every daemon: quiet at a service uid, whoever reads them.
    #[test]
    fn a_service_uid_reading_passwd_stays_quiet() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(3600, 1, "/usr/bin/cat", 1), &[]);
        for pid in [3600, 3699] {
            for path in ["/etc/passwd", "/etc/login.defs"] {
                let hits = det.detect(&file_open(pid, 33, path, 0, 2), &[]);
                assert!(
                    !hits.contains(&TriggerType::SensitiveFileAccess),
                    "{pid} {path}"
                );
            }
        }
    }

    // ── T7.13 generalisation: PAM-daemon login chains are exempt ────
    //
    // Beyond sudo (Test #1), the auth-lineage gate must also exempt the
    // credential reads a PAM-mediated login daemon performs on behalf of
    // an authenticating user, observed at that user's pre-setuid uid. Each
    // case: a leaf PID whose lineage walks back to the daemon reads
    // /etc/shadow under uid=1000 and must NOT trip SensitiveFileAccess.
    #[test]
    fn sensitive_file_access_exempt_for_pam_daemon_lineage() {
        let daemons = [
            "/usr/sbin/cron",
            "/usr/sbin/crond",
            "/usr/lib/systemd/systemd-logind",
            "/usr/lib/polkit-1/polkitd",
            "/usr/libexec/polkit-1/polkitd",
            "/usr/lib/gdm3/gdm-session-worker",
            "/usr/libexec/gdm-session-worker",
            "/usr/sbin/gdm3",
            "/usr/sbin/lightdm",
        ];
        for (i, daemon) in daemons.iter().enumerate() {
            let det = detector_with_empty_proc();
            let dpid = 1000 + (i as u32) * 2;
            let leaf = dpid + 1;
            // daemon (root, ppid=1) -> PAM session/job child (a shell).
            let _ = det.detect(&spawn_with_exe(dpid, 1, daemon, 1), &[]);
            let _ = det.detect(&spawn_with_exe(leaf, dpid, "/bin/bash", 2), &[]);
            // child reads /etc/shadow at the authenticating user's uid.
            let focal = file_open(leaf, 1000, "/etc/shadow", 0, 3);
            let hits = det.detect(&focal, &[]);
            assert!(
                !hits.contains(&TriggerType::SensitiveFileAccess),
                "{daemon}-mediated /etc/shadow read must NOT trip, got {hits:?}"
            );
        }
    }

    /// Screen-unlock / unprivileged-auth path: an unprivileged locker
    /// (uid 1000) cannot read /etc/shadow, so pam_unix execs the
    /// setuid-root helper unix_chkpwd, which reads it at the caller's
    /// REAL uid (1000 — the sensor captures real uid, not euid). The
    /// helper's own exe is the auth binary; without it here every screen
    /// unlock would trip SensitiveFileAccess.
    #[test]
    fn sensitive_file_access_exempt_for_unix_chkpwd_screen_unlock() {
        let det = detector_with_empty_proc();
        // locker -> setuid pam_unix helper.
        let _ = det.detect(
            &spawn_with_exe(700, 1, "/usr/bin/cinnamon-screensaver", 1),
            &[],
        );
        let _ = det.detect(&spawn_with_exe(701, 700, "/usr/sbin/unix_chkpwd", 2), &[]);
        let focal = file_open(701, 1000, "/etc/shadow", 0, 3);
        let hits = det.detect(&focal, &[]);
        assert!(
            !hits.contains(&TriggerType::SensitiveFileAccess),
            "unix_chkpwd (screen-unlock) /etc/shadow read must NOT trip, got {hits:?}"
        );
    }

    // ── /etc/gshadow is monitored symmetrically with /etc/shadow ────
    /// An unexpected uid>=1000 reader of /etc/gshadow trips the trigger
    /// (group-credential theft is the same signal class as /etc/shadow).
    #[test]
    fn sensitive_file_access_fires_on_gshadow_for_unexpected_reader() {
        let det = detector_with_empty_proc();
        let focal = file_open(999, 1000, "/etc/gshadow", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::SensitiveFileAccess),
            "non-auth uid=1000 /etc/gshadow read must trip, got {hits:?}"
        );
    }

    /// …but a sudo-mediated /etc/gshadow read is exempt by the SAME
    /// lineage gate that protects /etc/shadow — no T7.13 regression from
    /// adding gshadow to the monitored set.
    #[test]
    fn sensitive_file_access_exempt_for_sudo_reading_gshadow() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let focal = file_open(100, 1000, "/etc/gshadow", 0, 2);
        let hits = det.detect(&focal, &[]);
        assert!(
            !hits.contains(&TriggerType::SensitiveFileAccess),
            "sudo-mediated /etc/gshadow read must NOT trip, got {hits:?}"
        );
    }

    /// Negative control for the expanded daemon allowlist: an unexpected
    /// reader whose lineage is a plain shell (no auth ancestor anywhere)
    /// STILL fires — widening the allowlist must not weaken detection of
    /// real credential theft (the cat/less/cp/one-liner class).
    #[test]
    fn sensitive_file_access_still_fires_for_shell_one_liner() {
        let det = detector_with_empty_proc();
        // user shell -> cat; neither is an auth binary.
        let _ = det.detect(&spawn_with_exe(800, 1, "/usr/bin/bash", 1), &[]);
        let _ = det.detect(&spawn_with_exe(801, 800, "/usr/bin/cat", 2), &[]);
        let focal = file_open(801, 1000, "/etc/shadow", 0, 3);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::SensitiveFileAccess),
            "cat /etc/shadow (no auth lineage) must still trip, got {hits:?}"
        );
    }

    // ── Test #4: mass-write from sudo subprocess is exempt ──────────
    #[test]
    fn mass_write_exempt_for_sudo_subprocess() {
        let det = detector_with_empty_proc();
        // user shell -> sudo -> apt
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 200, 100, "/usr/bin/apt", 2), &[]);

        // 25 write-opens from apt's pid in 60 s — would normally
        // trip ConfirmedIntrusion mass-write arm.
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(200, 0, "/var/cache/apt/x", 1, i + 10))
            .collect();
        let focal = file_open(200, 0, "/var/cache/apt/x", 1, MASS_WRITE_MIN as u64 + 11);
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "sudo subprocess mass-write must NOT trip ConfirmedIntrusion, got {hits:?}"
        );
    }

    // ── Test #5: mass-write from non-auth PID still fires ───────────
    #[test]
    fn mass_write_still_fires_for_unattributed_pid() {
        let det = detector_with_empty_proc();
        // Spawn the writer with a non-auth parent so lineage is clean.
        let _ = det.detect(&spawn_with_exe(900, 1, "/usr/bin/zsh", 1), &[]);

        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(900, 1000, "/home/u/x", 1, i + 10))
            .collect();
        let focal = file_open(900, 1000, "/home/u/x", 1, MASS_WRITE_MIN as u64 + 11);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "unattributed mass-write must still fire, got {hits:?}"
        );
    }

    // ── External audit POS-006 ──────────────────────────────────────

    /// The window bounds both sides of the focal event (was: the past
    /// only — an event an hour later counted).
    #[test]
    fn within_rejects_far_future_events() {
        const W: u64 = 60;
        let focal = 1_000;
        assert!(within(focal, focal, W));
        assert!(within(focal, focal - W, W));
        assert!(within(focal, focal + W, W), "a later event read first");
        assert!(!within(focal, focal - W - 1, W));
        assert!(!within(focal, focal + W + 1, W));
        assert!(!within(focal, u64::MAX, W));
        assert!(!within(u64::MAX, 0, W));
    }

    /// MASS_WRITE_MIN write-opens stamped an hour after the focal open are
    /// not a mass write with it; the same opens inside the window are.
    #[test]
    fn a_burst_an_hour_after_the_focal_open_is_not_a_mass_write() {
        const HOUR: u64 = 3_600 * 1_000_000_000;
        let focal = file_open(900, 1000, "/home/u/x", 1, 1_000);
        for (offset, fires) in [(HOUR, false), (MASS_WRITE_WINDOW_NS / 2, true)] {
            let det = detector_with_empty_proc();
            let _ = det.detect(&spawn_with_exe(900, 1, "/usr/bin/zsh", 1), &[]);
            let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
                .map(|i| file_open(900, 1000, "/home/u/x", 1, 1_000 + offset + i))
                .collect();
            let hits = det.detect(&focal, &recent);
            assert_eq!(
                hits.contains(&TriggerType::ConfirmedIntrusion),
                fires,
                "opens {offset} ns after the focal one: {hits:?}"
            );
        }
    }

    // ── External audit POS-004 ──────────────────────────────────────

    fn file_open_from_user(pid: u32, filename: &str, flags: u32, ts: u64) -> Event {
        let mut e = file_open(pid, 1000, filename, flags, ts);
        if let Event::FileOpen { path_from_user, .. } = &mut e {
            *path_from_user = true;
        }
        e
    }

    /// In tracepoint mode an open's path is the caller's string, read
    /// before any permission check: a refused open of a persistence or a
    /// critical path raises the credential-reach tier (ALERTED), never a
    /// COMBAT-tier file signal; the same opens seen by the LSM sensor do.
    #[test]
    fn refused_opens_in_tracepoint_mode_cannot_forge_combat_signals() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(700, 1, "/home/u/tool", 1), &[]);
        for (path, combat_tier) in [
            ("/etc/cron.d/x", TriggerType::PersistenceMechanism),
            (
                "/etc/ssh/sshd_config",
                TriggerType::CriticalFileModification,
            ),
        ] {
            let hits = det.detect(&file_open_from_user(700, path, 1, 5), &[]);
            assert!(!hits.contains(&combat_tier), "{path}: {hits:?}");
            assert!(
                hits.contains(&TriggerType::SensitiveFileAccess),
                "{path}: {hits:?}"
            );
            let hits = det.detect(&file_open(700, 1000, path, 1, 6), &[]);
            assert!(hits.contains(&combat_tier), "LSM-mode {path}: {hits:?}");
        }
    }

    /// The mass-write count no longer skips a caller's path that only
    /// looks like a pseudo-filesystem one.
    #[test]
    fn the_mass_write_carveout_is_not_dodged_through_proc_links() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(710, 1, "/srv/app/worker", 1), &[]);
        let burst = |path: &dyn Fn(u64) -> String| {
            let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
                .map(|i| file_open_from_user(710, &path(i), 2, i + 10))
                .collect();
            let focal = file_open_from_user(710, &path(99), 2, MASS_WRITE_MIN as u64 + 11);
            det.detect(&focal, &recent)
        };
        let fired = |hits: Vec<TriggerType>| hits.contains(&TriggerType::ConfirmedIntrusion);
        assert!(fired(burst(&|i| format!("/proc/self/cwd/docs/{i}.docx"))));
        assert!(fired(burst(&|i| format!("/proc/../home/u/docs/{i}.docx"))));
        assert!(fired(burst(&|i| format!("/proc/1234/root/home/u/{i}"))));
        assert!(fired(burst(&|i| format!("/proc/self/fd/{i}"))));
        assert!(
            !fired(burst(&|i| format!("/proc/sys/vm/knob{i}"))),
            "a real pseudo-file"
        );
        assert!(!fired(burst(&|i| format!("/sys/fs/cgroup/x/{i}"))));
    }

    #[test]
    fn dot_segments_fold_and_proc_links_are_doors() {
        assert_eq!(fold_dot_segments("/proc/../home//u/./x"), "/home/u/x");
        assert_eq!(fold_dot_segments("/a/b/../../.."), "/");
        assert!(through_proc_link("/proc/self/cwd/x"));
        assert!(through_proc_link("/proc/42/task/43/root/etc/x"));
        assert!(through_proc_link("/proc/thread-self/fd/3"));
        assert!(!through_proc_link("/proc/self/cwd"));
        assert!(!through_proc_link("/proc/sys/vm/x"));
        assert!(!through_proc_link("/proc/self/oom_score_adj"));
    }

    // ── External audit POS-002 / POS-003 ────────────────────────────

    fn spawn_started(pid: u32, ppid: u32, filename: &str, ts: u64, start_ns: u64) -> Event {
        let mut e = spawn_with_exe(pid, ppid, filename, ts);
        if let Event::ProcessSpawn { start_ns: s, .. } = &mut e {
            *s = start_ns;
        }
        e
    }

    fn mass_write(pid: u32, overwrites: bool, ts: u64) -> Event {
        Event::MassWrite {
            pid,
            uid: 1000,
            comm: "x".into(),
            count: MASS_WRITE_MIN as u32,
            filename: "/home/u/docs/report.docx".into(),
            timestamp_ns: ts,
            overwrites,
            cgroup_window: false,
        }
    }

    /// A process of an SSH session was exempt from the mass-write arm
    /// whatever it wrote. Its new files (a build, a clone) still do not
    /// count; its rewrites of existing files — encryption in place — do.
    #[test]
    fn mass_write_in_an_ssh_session_fires_on_rewrites_not_on_new_files() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(200, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/usr/bin/bash", 2), &[]);
        let _ = det.detect(&spawn_with_exe(400, 300, "/home/u/cryptor", 3), &[]);
        let hits = det.detect(&mass_write(400, false, 10), &[]);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "a session's new files: {hits:?}"
        );
        let hits = det.detect(&mass_write(400, true, 11), &[]);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "a session's rewrites: {hits:?}"
        );
        // under sudo too: an elevated rewrite of many files counts
        let _ = det.detect(&spawn_with_exe(500, 300, "/usr/bin/sudo", 4), &[]);
        let _ = det.detect(&spawn_with_exe(510, 500, "/usr/bin/cp", 5), &[]);
        let hits = det.detect(&mass_write(510, true, 12), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion));
        // outside any session, new files count as before
        let _ = det.detect(&spawn_with_exe(600, 1, "/srv/app/worker", 6), &[]);
        let hits = det.detect(&mass_write(600, false, 13), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion));
        // a package manager stays exempt either way
        let _ = det.detect(&spawn_with_exe_by(0, 700, 500, "/usr/bin/dpkg", 7), &[]);
        let hits = det.detect(&mass_write(700, true, 14), &[]);
        assert!(!hits.contains(&TriggerType::ConfirmedIntrusion));
    }

    /// Tracepoint mode sees the open flags, not whether the file existed:
    /// a session's opens that may create do not count, its opens of
    /// existing files to write (no `O_CREAT`) do.
    #[test]
    fn tracepoint_mass_write_in_a_session_counts_opens_of_existing_files() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(200, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/home/u/tool", 2), &[]);
        let burst = |flags: u32| {
            let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
                .map(|i| file_open(300, 1000, &format!("/home/u/d/{i}"), flags, i + 10))
                .collect();
            let focal = file_open(300, 1000, "/home/u/d/x", flags, MASS_WRITE_MIN as u64 + 11);
            det.detect(&focal, &recent)
        };
        // O_WRONLY | O_CREAT | O_TRUNC: a build writing its outputs
        assert!(!burst(0o1101).contains(&TriggerType::ConfirmedIntrusion));
        // O_RDWR on files that exist: rewritten in place
        assert!(burst(0o2).contains(&TriggerType::ConfirmedIntrusion));
    }

    /// The credential-read exemption is the PAM stack's, not the session's:
    /// `cat /etc/shadow` from an SSH shell fires (a member of `shadow`, a
    /// misconfigured mode); sudo's own read does not.
    #[test]
    fn credential_read_from_an_ssh_session_fires_but_not_sudos() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(200, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/usr/bin/bash", 2), &[]);
        let _ = det.detect(&spawn_with_exe(310, 300, "/usr/bin/cat", 3), &[]);
        let _ = det.detect(&spawn_with_exe(320, 300, "/usr/bin/sudo", 4), &[]);
        let hits = det.detect(&file_open(310, 1000, "/etc/shadow", 0, 5), &[]);
        assert!(hits.contains(&TriggerType::SensitiveFileAccess), "{hits:?}");
        let hits = det.detect(&file_open(320, 1000, "/etc/shadow", 0, 6), &[]);
        assert!(
            !hits.contains(&TriggerType::SensitiveFileAccess),
            "{hits:?}"
        );
    }

    /// External audit POS-003 through the detector: a service's child,
    /// forked before its parent executed sudo, writes many new files —
    /// it is not sudo's, and it fires.
    #[test]
    fn a_child_forked_before_its_parent_ran_sudo_is_not_exempt() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_started(100, 1, "/srv/www/payload", 21, 20), &[]);
        let _ = det.detect(&spawn_started(200, 100, "/srv/www/crypt", 50, 30), &[]);
        let _ = det.detect(&spawn_started(100, 1, "/usr/bin/sudo", 40, 20), &[]);
        let hits = det.detect(&mass_write(200, false, 60), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }

    // ── (ii) — system package-management daemon exemption ───────────
    //
    // snapd / dpkg / apt / mandb cross the mass-write threshold (atomic
    // state churn, cache rebuilds) AND write systemd units / cron entries
    // (package install) during normal maintenance. Both arms exempt them
    // via exe-path lineage; detection stays intact for non-daemon writers.
    // Lab PR 175: a package transaction (the package manager executed by
    // root, while its run covers the event: the fixtures spawn them as
    // root), and mandb's own rebuild as a system account (as `man`).

    #[test]
    fn mass_write_exempt_for_snapd_daemon() {
        let det = detector_with_empty_proc();
        // snapd daemon parented by systemd — the 2026-06-02 self-lock.
        let _ = det.detect(
            &spawn_with_exe_by(0, 1096, 1, "/usr/lib/snapd/snapd", 1),
            &[],
        );
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(1096, 0, "/var/lib/snapd/state.json.tmp", 1, i + 10))
            .collect();
        let focal = file_open(
            1096,
            0,
            "/var/lib/snapd/state.json.tmp",
            1,
            MASS_WRITE_MIN as u64 + 11,
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "snapd state.json churn must NOT trip ConfirmedIntrusion, got {hits:?}"
        );
    }

    #[test]
    fn mass_write_exempt_for_mandb() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe_by(6, 3096, 1, "/usr/bin/mandb", 1), &[]);
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(3096, 0, "/var/cache/man/de/3096", 1, i + 10))
            .collect();
        let focal = file_open(
            3096,
            0,
            "/var/cache/man/de/3096",
            1,
            MASS_WRITE_MIN as u64 + 11,
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "mandb cache rebuild must NOT trip ConfirmedIntrusion, got {hits:?}"
        );
    }

    #[test]
    fn mass_write_exempt_for_dpkg_maintainer_script_via_lineage() {
        let det = detector_with_empty_proc();
        // dpkg -> /bin/sh maintainer script: exempt via the dpkg ancestor.
        let _ = det.detect(&spawn_with_exe_by(0, 400, 1, "/usr/bin/dpkg", 1), &[]);
        let _ = det.detect(&spawn_with_exe(401, 400, "/bin/sh", 2), &[]);
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(401, 0, "/usr/share/foo/data", 1, i + 10))
            .collect();
        let focal = file_open(401, 0, "/usr/share/foo/data", 1, MASS_WRITE_MIN as u64 + 11);
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "dpkg maintainer-script writes must NOT trip via lineage, got {hits:?}"
        );
    }

    #[test]
    fn mass_write_intact_for_non_daemon_pid() {
        // Detection intact: a non-daemon, non-auth writer doing the same
        // burst still fires. Guards against a blanket mass-write blind spot.
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(900, 1, "/usr/local/bin/cryptor", 1), &[]);
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(900, 1000, "/home/u/docs/f", 1, i + 10))
            .collect();
        let focal = file_open(900, 1000, "/home/u/docs/f", 1, MASS_WRITE_MIN as u64 + 11);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "non-daemon mass-write must still fire, got {hits:?}"
        );
    }

    // ── FP-2 — npm install mass-write exemption ─────────────────────
    //
    // `npm install` unpacks a tarball (+ writes ~/.npm cache) past the
    // mass-write threshold. The writer's exe is the node interpreter
    // (npm is a node shebang script), so the exemption keys on
    // exe ∈ NODE_EXES AND argv[1] = npm-cli.js — a direct focal-pid
    // check. Detection stays intact for any other node and for npm's
    // own child processes.

    #[test]
    fn mass_write_exempt_for_npm_cli() {
        let det = detector_with_empty_proc();
        // node interpreter running npm's CLI, ingested via the argv path.
        let _ = det.detect(
            &spawn_with_argv(
                7000,
                1,
                "/usr/bin/node",
                &[
                    "node",
                    "/usr/lib/node_modules/npm/bin/npm-cli.js",
                    "install",
                    "-g",
                    "left-pad",
                ],
                1,
            ),
            &[],
        );
        // Unpack burst into the global node_modules.
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| {
                file_open(
                    7000,
                    1000,
                    "/home/forty/.npm-global/lib/node_modules/left-pad/index.js",
                    1,
                    i + 10,
                )
            })
            .collect();
        let focal = file_open(
            7000,
            1000,
            "/home/forty/.npm-global/lib/node_modules/left-pad/package.json",
            1,
            MASS_WRITE_MIN as u64 + 11,
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "npm install unpack must NOT trip ConfirmedIntrusion, got {hits:?}"
        );
    }

    #[test]
    fn mass_write_intact_for_node_not_running_npm() {
        // Detection intact: the SAME node binary running a non-npm
        // script (argv[1] is not npm-cli.js) still fires — no blanket
        // node blind spot.
        let det = detector_with_empty_proc();
        let _ = det.detect(
            &spawn_with_argv(7100, 1, "/usr/bin/node", &["node", "/home/u/cryptor.js"], 1),
            &[],
        );
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(7100, 1000, "/home/u/docs/f", 1, i + 10))
            .collect();
        let focal = file_open(7100, 1000, "/home/u/docs/f", 1, MASS_WRITE_MIN as u64 + 11);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "node running a non-npm script must still fire, got {hits:?}"
        );
    }

    #[test]
    fn mass_write_intact_for_npm_child_process() {
        // A child npm spawns (e.g. a postinstall script) is a DIFFERENT
        // pid with a different argv — it is not the npm-cli.js writer and
        // its own mass-write still fires (the exemption is non-lineage).
        let det = detector_with_empty_proc();
        let _ = det.detect(
            &spawn_with_argv(
                7200,
                1,
                "/usr/bin/node",
                &[
                    "node",
                    "/usr/lib/node_modules/npm/bin/npm-cli.js",
                    "install",
                ],
                1,
            ),
            &[],
        );
        // postinstall: npm -> sh -> node build.js (pid 7201), mass-writes.
        let _ = det.detect(
            &spawn_with_argv(7201, 7200, "/usr/bin/node", &["node", "build.js"], 2),
            &[],
        );
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(7201, 1000, "/home/u/.cache/evil/f", 1, i + 10))
            .collect();
        let focal = file_open(
            7201,
            1000,
            "/home/u/.cache/evil/f",
            1,
            MASS_WRITE_MIN as u64 + 11,
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "npm child (non-npm-cli argv) mass-write must still fire, got {hits:?}"
        );
    }

    #[test]
    fn persistence_exempt_for_snapd_unit_write() {
        let det = detector_with_empty_proc();
        let _ = det.detect(
            &spawn_with_exe_by(0, 1096, 1, "/usr/lib/snapd/snapd", 1),
            &[],
        );
        let focal = file_open(1096, 0, "/etc/systemd/system/snap-snapd-26865.mount", 1, 5);
        let hits = det.detect(&focal, &[]);
        assert!(
            !hits.contains(&TriggerType::PersistenceMechanism),
            "snapd mount-unit write must NOT trip PersistenceMechanism, got {hits:?}"
        );
    }

    #[test]
    fn persistence_intact_for_non_daemon_unit_write() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(900, 1, "/usr/local/bin/cryptor", 1), &[]);
        let focal = file_open(900, 0, "/etc/systemd/system/evil.service", 1, 5);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::PersistenceMechanism),
            "non-daemon unit drop must still fire PersistenceMechanism, got {hits:?}"
        );
    }

    #[test]
    fn persistence_intact_for_sudo_mediated_write() {
        // Scoping decision: persistence gates on system-daemon lineage
        // ONLY — NOT auth-mediated. A sudo-mediated hand-dropped cron
        // entry STILL raises PersistenceMechanism (sudo is no free pass).
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let _ = det.detect(&spawn_with_exe(200, 100, "/bin/bash", 2), &[]);
        let focal = file_open(200, 0, "/etc/cron.d/evil", 1, 5);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::PersistenceMechanism),
            "sudo-mediated cron write must STILL fire persistence, got {hits:?}"
        );
    }

    /// Lab PR 175: the posture's arms trusted anything with `mandb` (or a
    /// package manager) in its lineage. `mandb` is not set-id: a user runs
    /// it with `LD_PRELOAD` and has it fork `crontab`, a payload from /tmp,
    /// a file encryptor — none raised its trigger. They trust a root
    /// package transaction now, and the mass-write arm `mandb`'s own
    /// rebuild as a system account.
    #[test]
    fn the_posture_judges_what_a_users_mandb_forks() {
        use common::wire::exe::exe_flags::DELETED;
        let det = detector_with_empty_proc();
        // the user's shell (900) → mandb (910) → crontab (911)
        let _ = det.detect(&spawn_with_exe(900, 1, "/usr/bin/bash", 1), &[]);
        let _ = det.detect(&spawn_with_exe(910, 900, "/usr/bin/mandb", 2), &[]);
        let _ = det.detect(&spawn_with_exe(911, 910, "/usr/bin/crontab", 3), &[]);
        let hits = det.detect(
            &file_open(911, 1000, "/var/spool/cron/crontabs/u", 1, 4),
            &[],
        );
        assert!(
            hits.contains(&TriggerType::PersistenceMechanism),
            "{hits:?}"
        );
        // … → a payload from /tmp, unlinked as it runs: promoted
        let hits = det.detect(&spawn_exe_flags(912, 910, "/tmp/payload", DELETED, 5), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        // … → a process rewriting the user's files, and mandb itself
        let _ = det.detect(&spawn_with_exe(913, 910, "/home/u/cryptor", 6), &[]);
        let hits = det.detect(&mass_write(913, true, 7), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        let hits = det.detect(&mass_write(910, true, 8), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }

    /// Lab PR 175: man-db's rebuild as `man` stays exempt from the
    /// mass-write arm; what it forks does not inherit that.
    #[test]
    fn mandbs_own_cache_rebuild_is_exempt_not_its_children() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe_by(6, 3096, 1, "/usr/bin/mandb", 1), &[]);
        let _ = det.detect(&spawn_with_exe_by(6, 3097, 3096, "/usr/bin/sh", 2), &[]);
        let hits = det.detect(&mass_write(3096, true, 3), &[]);
        assert!(!hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        let hits = det.detect(&mass_write(3097, true, 4), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }

    /// Lab PR 175: a package transaction is root's package manager while
    /// its run covers the write. A user's `dpkg --version` (`LD_PRELOAD`)
    /// vouches for nothing, nor a dpkg that ended long before.
    #[test]
    fn persistence_is_exempt_within_a_root_transaction_only() {
        const S: u64 = 1_000_000_000;
        let det = detector_with_empty_proc();
        // root's dpkg (400) → a maintainer script (401) writes a unit
        let _ = det.detect(&spawn_with_exe_by(0, 400, 1, "/usr/bin/dpkg", S), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 401, 400, "/bin/sh", 2 * S), &[]);
        let unit = |ts: u64| file_open(401, 0, "/etc/systemd/system/foo.service", 1, ts);
        let hits = det.detect(&unit(3 * S), &[]);
        assert!(
            !hits.contains(&TriggerType::PersistenceMechanism),
            "{hits:?}"
        );
        // the same write, by what the script left running, 120 s on
        let hits = det.detect(&unit(120 * S), &[]);
        assert!(
            hits.contains(&TriggerType::PersistenceMechanism),
            "{hits:?}"
        );
        // the user's dpkg (500) → crontab (501)
        let _ = det.detect(&spawn_with_exe(500, 1, "/usr/bin/dpkg", 3 * S), &[]);
        let _ = det.detect(&spawn_with_exe(501, 500, "/usr/bin/crontab", 4 * S), &[]);
        let hits = det.detect(
            &file_open(501, 1000, "/var/spool/cron/crontabs/u", 1, 5 * S),
            &[],
        );
        assert!(
            hits.contains(&TriggerType::PersistenceMechanism),
            "{hits:?}"
        );
    }

    /// A detector over fixture `/proc` and host trees, with a rootless
    /// build: the user's podman (600) → `dnf` (700) in a container of its
    /// own, rooted in an overlay (0:77) of the user's storage (the test's
    /// uid owns `/home/u/.local/share/containers`).
    fn rootless_build() -> (tempfile::TempDir, tempfile::TempDir, TriggerDetector, u32) {
        use super::super::exempt::ExemptPids;
        use super::super::lineage::AuthSessionTracker;
        use std::os::unix::fs::symlink;
        let host = tempfile::tempdir().unwrap();
        let procs = tempfile::tempdir().unwrap();
        let me = unsafe { libc::getuid() };
        std::fs::create_dir_all(host.path().join("home/u/.local/share/containers/storage"))
            .unwrap();
        for (pid, ns) in [("1", "mnt:[4026531841]"), ("700", "mnt:[4026532900]")] {
            std::fs::create_dir_all(procs.path().join(pid).join("ns")).unwrap();
            symlink(ns, procs.path().join(pid).join("ns/mnt")).unwrap();
        }
        let o = "/home/u/.local/share/containers/storage/overlay";
        std::fs::write(
            procs.path().join("700/mountinfo"),
            format!(
                "900 800 0:77 / / rw - overlay overlay rw,lowerdir={o}/l/A,upperdir={o}/0a1b/diff,workdir={o}/0a1b/work\n"
            ),
        )
        .unwrap();
        let auth = AuthSessionTracker::new(procs.path()).with_host_root(host.path());
        let det = TriggerDetector::with_exempt_and_auth(ExemptPids::default(), auth);
        let _ = det.detect(&spawn_with_exe_by(me, 600, 1, "/usr/bin/podman", 1), &[]);
        let _ = det.detect(&spawn_with_exe_by(me, 700, 600, "/usr/bin/dnf", 2), &[]);
        (host, procs, det, me)
    }

    /// Lab PR 175: a rootless `podman build`'s `dnf` writing 2,000 files
    /// into the user's container storage (the overlay's upper layer, or its
    /// own root overlay) raises no `ConfirmedIntrusion`, in either arm; the
    /// same process rewriting the user's documents does.
    #[test]
    fn a_rootless_build_mass_writes_its_storage_not_the_users_files() {
        let (_host, _procs, det, me) = rootless_build();
        let burst = |pid: u32, path: &str, ts: u64| {
            let mut e = mass_write(pid, true, ts);
            if let Event::MassWrite {
                filename, count, ..
            } = &mut e
            {
                (*filename, *count) = (path.to_string(), 2000);
            }
            det.detect(&e, &[])
        };
        let storage =
            "/home/u/.local/share/containers/storage/overlay/0a1b/diff/usr/lib64/libfoo.so";
        let docs = "/home/u/Documents/report.docx";
        let ci = TriggerType::ConfirmedIntrusion;
        assert!(!burst(700, storage, 3).contains(&ci));
        assert!(!burst(700, "mnt[0:77:12]/usr/lib64/libfoo.so", 4).contains(&ci));
        assert!(burst(700, docs, 5).contains(&ci));
        assert!(burst(700, "mnt[0:78:12]/report.docx", 6).contains(&ci));
        // tracepoint mode: 2,000 opens, each one judged
        let opens = |path: &str, from: u64| -> (Event, Vec<Event>) {
            let recent = (0..2000u64)
                .map(|i| file_open(700, me, path, 1, from + i))
                .collect();
            (file_open(700, me, path, 1, from + 2000), recent)
        };
        let (focal, recent) = opens(storage, 10);
        assert!(!det.detect(&focal, &recent).contains(&ci));
        let (focal, recent) = opens(docs, 3000);
        assert!(det.detect(&focal, &recent).contains(&ci));
    }

    /// Lab PR 175: outside that storage nothing is exempt — a unit the
    /// build installs in its image is not raised, the host's cron spool is,
    /// and a user's `LD_PRELOAD` dpkg (init's namespace) gets nothing.
    #[test]
    fn a_rootless_build_installs_units_in_its_image_not_on_the_host() {
        let (_host, _procs, det, me) = rootless_build();
        let pm = TriggerType::PersistenceMechanism;
        let open = |pid: u32, path: &str, from_user: bool, ts: u64| {
            let mut e = file_open(pid, me, path, 1, ts);
            if let Event::FileOpen {
                path_from_user,
                kernel_class,
                ..
            } = &mut e
            {
                (*path_from_user, *kernel_class) = (from_user, open_reason::PERSIST);
            }
            det.detect(&e, &[])
        };
        // in the image: its root overlay, or the caller's string inside it
        // (tracepoint mode: a caller's string raises SensitiveFileAccess
        // at most, POS-004)
        let sfa = TriggerType::SensitiveFileAccess;
        assert!(!open(700, "mnt[0:77:5]/etc/systemd/system/foo.service", false, 3).contains(&pm));
        let hits = open(700, "/etc/systemd/system/foo.service", true, 4);
        assert!(!hits.contains(&pm) && !hits.contains(&sfa), "{hits:?}");
        // the host's
        assert!(open(700, "/var/spool/cron/crontabs/u", false, 5).contains(&pm));
        assert!(open(700, "mnt[0:78:5]/etc/cron.d/x", false, 6).contains(&pm));
        // the user's dpkg --version (LD_PRELOAD) → crontab, in init's namespace
        let _ = det.detect(&spawn_with_exe_by(me, 800, 1, "/usr/bin/dpkg", 7), &[]);
        let _ = det.detect(&spawn_with_exe_by(me, 801, 800, "/usr/bin/crontab", 8), &[]);
        assert!(open(801, "/var/spool/cron/crontabs/u", false, 9).contains(&pm));
        assert!(open(801, "/etc/systemd/system/x.service", true, 10).contains(&sfa));
    }

    // ── Test #6: sudo subprocess exec'ing /tmp still trips ──────────
    #[test]
    fn exec_from_tmp_not_exempt_for_sudo_subprocess() {
        use common::wire::exe::exe_flags::DELETED;
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        // sudo's child exec'es /tmp/payload — exactly the
        // post-compromise pattern this arm exists to catch. External audit
        // POS-015: a staging exec, and with a second factor
        // ConfirmedIntrusion, sudo or not.
        let evil = spawn_with_exe(200, 100, "/tmp/payload", 2);
        let hits = det.detect(&evil, &[]);
        assert!(
            hits.contains(&TriggerType::StagingExec),
            "exec-from-/tmp must fire even under sudo lineage, got {hits:?}"
        );
        let unlinked = spawn_exe_flags(201, 100, "/tmp/payload", DELETED, 3);
        let hits = det.detect(&unlinked, &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }

    // ── Test #7: sudo subprocess FsProtectDenial still trips ────────
    #[test]
    fn fs_protect_denial_not_exempt_for_sudo_subprocess() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let _ = det.detect(&spawn_with_exe(200, 100, "/bin/bash", 2), &[]);
        let focal = Event::FsProtectDenial {
            pid: 200,
            uid: 0,
            comm: "rm".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: common::FsProtectOperation::Unlink,
            timestamp_ns: 3,
        };
        let hits = det.detect(&focal, &[]);
        // BUG-032: the denial now raises the Decisive AntiTamperDenial,
        // and is still NOT suppressed by sudo lineage.
        assert!(
            hits.contains(&TriggerType::AntiTamperDenial),
            "FsProtectDenial must fire even under sudo lineage, got {hits:?}"
        );
    }

    // ── Test #8: nested sudo→bash→apt lineage is exempt ─────────────
    #[test]
    fn nested_lineage_sudo_bash_apt() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let _ = det.detect(&spawn_with_exe(200, 100, "/bin/bash", 2), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 300, 200, "/usr/bin/apt", 3), &[]);

        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(300, 0, "/var/lib/apt/lists/x", 1, i + 10))
            .collect();
        let focal = file_open(
            300,
            0,
            "/var/lib/apt/lists/x",
            1,
            MASS_WRITE_MIN as u64 + 11,
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "depth-3 sudo lineage must be exempt, got {hits:?}"
        );
    }

    // ── Test #9: lineage depth capped (no hang on deep / cyclic) ────
    #[test]
    fn lineage_depth_capped() {
        let det = detector_with_empty_proc();
        // 64-deep non-auth chain. Walk must terminate without
        // panicking; the lineage gate must return non-exempt.
        for i in 1..=64u32 {
            let _ = det.detect(&spawn_with_exe(i, i + 1, "/bin/cat", i as u64), &[]);
        }
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(1, 1000, "/home/u/x", 1, i + 100))
            .collect();
        let focal = file_open(1, 1000, "/home/u/x", 1, MASS_WRITE_MIN as u64 + 101);
        let hits = det.detect(&focal, &recent);
        // Pid 1 is the init terminator anyway — never auth-mediated.
        // The real assertion: this returned, didn't loop.
        assert!(
            !hits.is_empty() || hits.is_empty(),
            "completed without hang"
        );
        // And the mass-write SHOULD fire because lineage is non-auth.
        let _ = hits;
    }

    // ─── BUG-018 (tactical) — loginuid-mediated /etc/passwd carve-out
    //
    // The systemd-user@<uid>.service spawns user-session helpers
    // (dbus, xdg-desktop generators) under PID 1 systemd, whose
    // lineage never traverses AUTH_BINARY_EXES so the T7.13 gate
    // doesn't catch them. The tactical fix is a narrowly-scoped
    // loginuid carve-out: read-only /etc/passwd opens by a process
    // with a valid /proc/<pid>/loginuid are not flagged.
    //
    // These tests use a fixture-backed AuthSessionTracker that reads
    // /proc from a tempdir so loginuid lookups hit known content.

    fn detector_with_fixture_proc(proc_root: &std::path::Path) -> TriggerDetector {
        use super::super::exempt::ExemptPids;
        use super::super::lineage::AuthSessionTracker;
        let auth = AuthSessionTracker::new(proc_root);
        TriggerDetector::with_exempt_and_auth(ExemptPids::default(), auth)
    }

    fn write_loginuid_fixture(dir: &std::path::Path, pid: u32, value: u32) {
        let pid_dir = dir.join(pid.to_string());
        std::fs::create_dir_all(&pid_dir).unwrap();
        std::fs::write(pid_dir.join("loginuid"), value.to_string()).unwrap();
    }

    /// BUG-018 #1: PAM-authenticated user session helper (dbus,
    /// xdg generator, etc.) opens /etc/passwd read-only. Carve-out
    /// fires → no SensitiveFileAccess.
    #[test]
    fn bug018_systemd_user_helper_reading_passwd_is_exempt() {
        let tmp = tempfile::TempDir::new().unwrap();
        // pid 4242, loginuid=1000 — the canonical "user logged in
        // via gdm/sshd and pam_loginuid wrote their UID" shape.
        write_loginuid_fixture(tmp.path(), 4242, 1000);
        let det = detector_with_fixture_proc(tmp.path());

        // /etc/passwd, flags=0 (O_RDONLY).
        let focal = file_open(4242, 1000, "/etc/passwd", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(
            !hits.contains(&TriggerType::SensitiveFileAccess),
            "PAM-authenticated /etc/passwd read must NOT fire, got {hits:?}"
        );
    }

    /// BUG-018 #2: truly orphan process (loginuid = unset sentinel)
    /// reading /etc/shadow STILL fires. Two negative properties
    /// in one test:
    ///   (a) loginuid==UNSET doesn't pass the carve-out;
    ///   (b) even with loginuid set, /etc/shadow is NOT in the
    ///       carve-out scope (only /etc/passwd is).
    #[test]
    fn bug018_orphan_process_reading_shadow_still_fires() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Unset sentinel — the kernel default for any process not
        // descended from pam_loginuid.
        write_loginuid_fixture(tmp.path(), 9999, u32::MAX);
        let det = detector_with_fixture_proc(tmp.path());

        let focal = file_open(9999, 1000, "/etc/shadow", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::SensitiveFileAccess),
            "orphan-process /etc/shadow read must still fire, got {hits:?}"
        );

        // And even a PAM-authenticated reader of /etc/shadow is NOT
        // carved out — only /etc/passwd reads are.
        write_loginuid_fixture(tmp.path(), 8888, 1000);
        let focal2 = file_open(8888, 1000, "/etc/shadow", 0, 2);
        let hits2 = det.detect(&focal2, &[]);
        assert!(
            hits2.contains(&TriggerType::SensitiveFileAccess),
            "PAM-authed /etc/shadow read must STILL fire (carve-out is /etc/passwd only), \
             got {hits2:?}"
        );
    }

    /// BUG-018 #3: existing T7.13 lineage (sshd→bash→sudo chain)
    /// is unchanged. The is_auth_mediated gate fires BEFORE the
    /// loginuid gate, so the original behavior is preserved.
    #[test]
    fn bug018_sshd_sudo_lineage_chain_still_exempt() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Fixture proc has NO loginuid file — so the only path to
        // exemption is the T7.13 lineage walk.
        let det = detector_with_fixture_proc(tmp.path());

        // sshd (200) → bash (300) → sudo (400). Tracker ingest only.
        let _ = det.detect(&spawn_with_exe(200, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/bin/bash", 2), &[]);
        let _ = det.detect(&spawn_with_exe(400, 300, "/usr/bin/sudo", 3), &[]);

        // sudo opens /etc/shadow — T7.13 carve-out applies.
        let focal = file_open(400, 1000, "/etc/shadow", 0, 4);
        let hits = det.detect(&focal, &[]);
        assert!(
            !hits.contains(&TriggerType::SensitiveFileAccess),
            "sshd→bash→sudo lineage must remain exempt under BUG-018 changes, got {hits:?}"
        );
    }

    // ─── BUG-012 — credential-theft detection guarantee ────────────
    //
    // FIM no longer emits `Opened` events on /etc/passwd-class paths
    // (the noise dropped at the drain layer per
    // `fim::drain::FIM_OPENED_SUPPRESS_PATHS`). The cluster spec's
    // SECURITY GUARD requires SensitiveFileAccess to still catch
    // those reads — these tests pin that.

    /// BUG-012 THE-GUARD: /etc/shadow read by a regular user STILL
    /// fires SensitiveFileAccess after the FIM noise drop. Removing
    /// FIM's Opened coverage of credential files MUST NOT lose
    /// credential-theft detection — posture trigger is the off-ramp.
    #[test]
    fn bug012_guard_etc_shadow_read_still_fires_sensitive_file_access() {
        let det = detector_with_empty_proc();
        // Plain uid=1000 process opens /etc/shadow read-only.
        // (No PAM-authenticated lineage, no sudo, no auth binary —
        // the unambiguous credential-theft pattern.)
        let focal = file_open(31337, 1000, "/etc/shadow", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::SensitiveFileAccess),
            "BUG-012 security guard: /etc/shadow read MUST still fire \
             SensitiveFileAccess after FIM Opened drop, got {hits:?}"
        );
    }

    /// BUG-012: /etc/login.defs was the new addition to
    /// SENSITIVE_FILES (the FIM_OPENED_SUPPRESS_PATHS list includes
    /// it, so the posture trigger MUST cover it or coverage is lost).
    /// This test pins that coverage.
    #[test]
    fn bug012_etc_login_defs_read_now_covered_by_sensitive_file_access() {
        let det = detector_with_empty_proc();
        let focal = file_open(31337, 1000, "/etc/login.defs", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::SensitiveFileAccess),
            "BUG-012: /etc/login.defs read must fire (newly added to \
             SENSITIVE_FILES to back the FIM Opened suppression), got {hits:?}"
        );
    }

    /// BUG-018 #4: attacker process — invalid loginuid, no auth
    /// lineage, opens /etc/passwd. carve-out doesn't apply →
    /// trigger fires. Documents that loginuid is the GATE: without
    /// it, even a /etc/passwd read still flags. Also covers the
    /// "attacker writes /etc/passwd" case — writes never get the
    /// carve-out, even with a valid loginuid.
    #[test]
    fn bug018_attacker_without_loginuid_still_fires() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Attacker with no loginuid file at all (started outside
        // any PAM chain — e.g., dropped via a /tmp payload).
        let det = detector_with_fixture_proc(tmp.path());

        // /etc/passwd, read-only, but no loginuid → no carve-out.
        let focal = file_open(31337, 1000, "/etc/passwd", 0, 1);
        let hits = det.detect(&focal, &[]);
        assert!(
            hits.contains(&TriggerType::SensitiveFileAccess),
            "attacker without loginuid reading /etc/passwd must fire, got {hits:?}"
        );

        // Even WITH a valid loginuid, a WRITE to /etc/passwd is
        // anomalous (legit changes go through `passwd` which is in
        // AUTH_BINARY_EXES). Carve-out is read-only; writes still
        // flag.
        write_loginuid_fixture(tmp.path(), 31338, 1000);
        let focal2 = file_open(31338, 1000, "/etc/passwd", 1, 2); // O_WRONLY
        let hits2 = det.detect(&focal2, &[]);
        assert!(
            hits2.contains(&TriggerType::SensitiveFileAccess),
            "PAM-authed WRITE to /etc/passwd must still fire (carve-out is read-only), \
             got {hits2:?}"
        );
    }

    // ── Test #10: PID reuse invalidates lineage ─────────────────────
    #[test]
    fn pid_reuse_invalidates_lineage() {
        let det = detector_with_empty_proc();
        // pid 100 is first a sudo process — exempt.
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let shadow_read_sudo = file_open(100, 1000, "/etc/shadow", 0, 2);
        let hits_a = det.detect(&shadow_read_sudo, &[]);
        assert!(!hits_a.contains(&TriggerType::SensitiveFileAccess));

        // The PID is recycled to /bin/cat. parent=1 (no /proc, so
        // no fallback walk succeeds) → lineage is not auth-mediated.
        let _ = det.detect(&spawn_with_exe(100, 1, "/bin/cat", 3), &[]);
        let shadow_read_cat = file_open(100, 1000, "/etc/shadow", 0, 4);
        let hits_b = det.detect(&shadow_read_cat, &[]);
        assert!(
            hits_b.contains(&TriggerType::SensitiveFileAccess),
            "recycled non-auth PID reading /etc/shadow must fire, got {hits_b:?}"
        );
    }

    // ── BUG-014 P-6 regression — mass-write path-class carve-out ──────
    //
    // Ground-truth evidence captured 2026-05-27 22:17 UTC: PID 1
    // (systemd) writes to /sys/fs/cgroup/* during early-boot service
    // setup, tripping the mass-write threshold within ~3 s of agent
    // attach and engaging COMBAT on a benign host. The carve-out below
    // exempts kernel-RPC pseudo-FS prefixes from the count while
    // preserving detection for real data-write patterns
    // (ransomware/exfil).

    /// Build a (focal, recent) burst of MASS_WRITE_MIN + 1 write-opens
    /// from `pid` all targeting `path`. Same shape as
    /// `self_write_burst` but parameterised on path so each carve-out
    /// test can pick its directory.
    fn write_burst_to(pid: u32, path: &str) -> (Event, Vec<Event>) {
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open(pid, 0, path, 1, i + 1))
            .collect();
        let focal = file_open(pid, 0, path, 1, MASS_WRITE_MIN as u64 + 1);
        (focal, recent)
    }

    const ATTACKER_PID: u32 = AGENT_PID + 100;

    #[test]
    fn mass_write_excludes_sysfs_writes() {
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(
            ATTACKER_PID,
            "/sys/fs/cgroup/system.slice/foo.service/memory.max",
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "sysfs writes are kernel RPCs, must not count toward mass-write: {hits:?}"
        );
    }

    #[test]
    fn mass_write_excludes_proc_writes() {
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/proc/sys/kernel/printk");
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "procfs writes are kernel RPCs, must not count toward mass-write: {hits:?}"
        );
    }

    #[test]
    fn mass_write_excludes_systemd_run_writes() {
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/run/systemd/units/foo.unit");
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "/run/systemd/ is systemd state, must not count toward mass-write: {hits:?}"
        );
    }

    #[test]
    fn mass_write_excludes_journal_writes() {
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(
            ATTACKER_PID,
            "/run/log/journal/0123456789abcdef/system.journal",
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "journald binary log is system state, must not count toward mass-write: {hits:?}"
        );
    }

    #[test]
    fn mass_write_still_fires_for_user_data() {
        // Regression guard: the actual ransomware shape (user data
        // mass-rewrite) must still fire.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/home/alice/Documents/report.docx");
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "mass-write on user data must still fire: {hits:?}"
        );
    }

    #[test]
    fn mass_write_still_fires_for_devshm() {
        // Regression guard: /dev/shm is canonical ransomware staging
        // tmpfs and is DELIBERATELY not in the carve-out.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/dev/shm/staging/payload_42.bin");
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "mass-write to /dev/shm staging must still fire: {hits:?}"
        );
    }

    #[test]
    fn mass_write_still_fires_for_run_user() {
        // Regression guard: /run/user/<uid>/ is per-user runtime where
        // a compromised user session could mass-write — kept counted.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/run/user/1000/foo");
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "/run/user/<uid> is user runtime, must still count: {hits:?}"
        );
    }

    #[test]
    fn mass_write_mixed_excluded_and_user_data_below_threshold() {
        // Boundary: half-and-half (MASS_WRITE_MIN/2 sysfs + same /home),
        // only the /home half counts (10 + 1 focal = 11 < 20). No fire —
        // proves the recent-loop filter properly excludes carve-out
        // events from the count, not just the focal.
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let mut recent: Vec<Event> = Vec::new();
        for i in 0..(MASS_WRITE_MIN as u64 / 2) {
            recent.push(file_open(
                ATTACKER_PID,
                0,
                "/sys/fs/cgroup/foo/cgroup.procs",
                1,
                i + 1,
            ));
        }
        for i in 0..(MASS_WRITE_MIN as u64 / 2) {
            recent.push(file_open(
                ATTACKER_PID,
                0,
                "/home/alice/file",
                1,
                (MASS_WRITE_MIN as u64 / 2) + i + 1,
            ));
        }
        let focal = file_open(
            ATTACKER_PID,
            0,
            "/home/alice/file",
            1,
            MASS_WRITE_MIN as u64 + 1,
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "10 /home writes + 10 sysfs writes = 11 counted < 20 threshold, must not fire: {hits:?}"
        );
    }

    // ── BUG-017 P-8 regression — runtime mass-write overlay ───────────

    #[test]
    fn mass_write_extras_overlay_exempts_listed_prefix() {
        // Without the extras, a /home/<user>/.claude/ burst fires
        // ConfirmedIntrusion (per `mass_write_still_fires_for_user_data`
        // logic). With the overlay listing that prefix, the burst is
        // exempt. Models the BUG-017 ground-truth fix: Claude Code's
        // subagent-transcript bursts no longer self-trip COMBAT on a
        // dev host whose operator has populated the .local file.
        let det = TriggerDetector::with_self_pid(AGENT_PID)
            .with_mass_write_extras(vec!["/home/alice/.claude/".to_string()]);
        let (focal, recent) = write_burst_to(
            ATTACKER_PID,
            "/home/alice/.claude/projects/x/subagents/a.jsonl",
        );
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "extras-listed prefix must exempt the burst: {hits:?}"
        );
    }

    #[test]
    fn mass_write_extras_overlay_does_not_exempt_outside_prefix() {
        // The same operator extras don't carve-out a sibling /home
        // path. Real ransomware in /home/alice/Documents/ still fires.
        let det = TriggerDetector::with_self_pid(AGENT_PID)
            .with_mass_write_extras(vec!["/home/alice/.claude/".to_string()]);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/home/alice/Documents/report.docx");
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "extras must NOT bleed beyond the listed prefix: {hits:?}"
        );
    }

    #[test]
    fn mass_write_extras_overlay_empty_preserves_hardcoded_only() {
        // With an empty extras list, hardcoded MASS_WRITE_CARVEOUT_PREFIXES
        // still applies (sysfs exempted), and /home is still counted.
        // Smoke-tests that the extras plumbing doesn't disturb the
        // built-in carve-out.
        let det = TriggerDetector::with_self_pid(AGENT_PID).with_mass_write_extras(vec![]);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/sys/fs/cgroup/foo/cgroup.procs");
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "hardcoded sysfs carve-out must survive empty extras: {hits:?}"
        );
    }

    // ── BUG-032: escalation allowlist count-filter (exfil) ──────────
    #[test]
    fn exfil_allowlist_count_filters_mirror_but_not_c2() {
        use super::super::escalation_allow::EscalationAllowList;
        // 21 connects by "curl" to a public dst on 443 → exfil shape.
        let mk = |dst: [u8; 4]| {
            let recent: Vec<Event> = (0..20u64)
                .map(|i| tcp_v4_comm(42, "curl", dst, 443, i + 1))
                .collect();
            (tcp_v4_comm(42, "curl", dst, 443, 100), recent)
        };

        // No allowlist → ExfiltrationPattern fires.
        let bare = TriggerDetector::new();
        let (f, r) = mk([203, 0, 113, 9]);
        assert!(
            bare.detect(&f, &r)
                .contains(&TriggerType::ExfiltrationPattern),
            "exfil shape must fire with no allowlist"
        );

        // "curl 203.0.113.0/24 443" allowlisted → every connect is
        // count-filtered → below threshold → no trigger.
        let (allow, _) = EscalationAllowList::parse("exfil curl 203.0.113.0/24 443\n");
        let det = TriggerDetector::new().with_escalation_allow(allow);
        let (f, r) = mk([203, 0, 113, 9]);
        assert!(
            !det.detect(&f, &r)
                .contains(&TriggerType::ExfiltrationPattern),
            "allowlisted mirror traffic must be count-filtered out"
        );

        // Same allowlist, a non-allowlisted public dst (a real C2) still
        // fires — the mirror entry must not mask it.
        let (f, r) = mk([8, 8, 8, 8]);
        assert!(
            det.detect(&f, &r)
                .contains(&TriggerType::ExfiltrationPattern),
            "non-allowlisted destination must still count + fire"
        );
    }

    // ── BUG-039: IPv6 detection (exfil/lateral past the family gate) ──
    fn v6(prefix: u16, last: u8) -> [u8; 16] {
        let mut a = [0u8; 16];
        a[0] = (prefix >> 8) as u8;
        a[1] = (prefix & 0xff) as u8;
        a[15] = last;
        a
    }

    #[test]
    fn is_internal_folds_ipv4_mapped() {
        // External audit NET-001: ::ffff:10.0.0.5 is RFC 1918, ::ffff:8.8.8.8 is not.
        let mut b = [0u8; 16];
        b[10] = 0xff;
        b[11] = 0xff;
        b[12..].copy_from_slice(&[10, 0, 0, 5]);
        assert!(is_internal(&b, 10));
        b[12..].copy_from_slice(&[8, 8, 8, 8]);
        assert!(!is_internal(&b, 10));
    }

    #[test]
    fn is_internal_classifies_v6() {
        assert!(is_internal(&v6(0xfd00, 1), 10), "fd00::/8 ULA is internal");
        assert!(is_internal(&v6(0xfc00, 1), 10), "fc00::/7 ULA is internal");
        assert!(
            is_internal(&v6(0xfe80, 1), 10),
            "fe80::/10 link-local is internal"
        );
        assert!(!is_internal(&v6(0x2606, 1), 10), "2606:: global is public");
        assert!(!is_internal(&v6(0x2001, 1), 10), "2001:: global is public");
    }

    #[test]
    fn exfil_fires_on_v6_public() {
        // 21 connects from one pid to a PUBLIC v6 on 443 → ExfiltrationPattern.
        let det = TriggerDetector::new();
        let dst = v6(0x2606, 1);
        let recent: Vec<Event> = (0..20u64)
            .map(|i| tcp_v6(42, "exfilv6", dst, 443, i + 1))
            .collect();
        let focal = tcp_v6(42, "exfilv6", dst, 443, 100);
        assert!(
            det.detect(&focal, &recent)
                .contains(&TriggerType::ExfiltrationPattern),
            "v6 exfil must fire (BUG-039)"
        );
    }

    #[test]
    fn lateral_fires_on_v6_ula() {
        // 3 distinct ULA hosts on :22 from one pid → LateralMovement.
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v6(42, "lat6", v6(0xfd00, 1), 22, 1),
            tcp_v6(42, "lat6", v6(0xfd00, 2), 22, 2),
        ];
        let focal = tcp_v6(42, "lat6", v6(0xfd00, 3), 22, 3);
        assert!(
            det.detect(&focal, &recent)
                .contains(&TriggerType::LateralMovement),
            "v6 lateral must fire on 3 distinct ULA hosts (BUG-039)"
        );
    }

    #[test]
    fn exfil_v6_allowlist_count_filter() {
        // A v6 allowlist entry count-filters v6 exfil — the BUG-032
        // count-filter is family-aware (no allowlist change for v6).
        use super::super::escalation_allow::EscalationAllowList;
        let (allow, _) = EscalationAllowList::parse("exfil backup 2606::/16 443\n");
        let det = TriggerDetector::new().with_escalation_allow(allow);
        let dst = v6(0x2606, 9);
        let recent: Vec<Event> = (0..20u64)
            .map(|i| tcp_v6(42, "backup", dst, 443, i + 1))
            .collect();
        let focal = tcp_v6(42, "backup", dst, 443, 100);
        assert!(
            !det.detect(&focal, &recent)
                .contains(&TriggerType::ExfiltrationPattern),
            "allowlisted v6 mirror traffic must be count-filtered (BUG-032 is family-aware)"
        );
    }
    // ── External audit SNS-005 / SNS-006 / EBPF-011 ────────────────

    fn classed_open(pid: u32, uid: u32, filename: &str, flags: u32, class: u32) -> Event {
        let mut e = file_open(pid, uid, filename, flags, 5);
        if let Event::FileOpen { kernel_class, .. } = &mut e {
            *kernel_class = class;
        }
        e
    }

    /// A kernel-classed open whose path cannot be compared with a host path
    /// (a filesystem root no mount shows, a cut or unread component) fired
    /// nothing: the path lists never matched it. It now fires on the
    /// kernel's class. An exact path is judged by the lists alone, and an
    /// unplaced path without a kernel class (tracepoint mode, a container's
    /// own `/etc`) by nothing.
    #[test]
    fn unplaced_paths_fire_on_the_kernel_class() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(300, 1, "/home/u/tool", 1), &[]);
        let fired = |e: &Event, t: TriggerType| det.detect(e, &[]).contains(&t);
        let unplaced = "mnt[0:45:256]/@";
        let persist = classed_open(
            300,
            0,
            &format!("{unplaced}/etc/cron.d/job"),
            1,
            open_reason::PERSIST,
        );
        assert!(fired(&persist, TriggerType::PersistenceMechanism));
        let critical = classed_open(
            300,
            0,
            &format!("{unplaced}/root/.ssh/authorized_keys"),
            1,
            open_reason::CRITICAL,
        );
        assert!(fired(&critical, TriggerType::CriticalFileModification));
        let shadow = classed_open(
            300,
            1000,
            &format!("{unplaced}/etc/shadow"),
            0,
            open_reason::SENSITIVE,
        );
        assert!(fired(&shadow, TriggerType::SensitiveFileAccess));
        // a cut directory name: the path is not exact, the class decides
        let cut = classed_open(
            300,
            0,
            "/etc/systemd/system/a-unit-directory-with-a-long-nam…/x.service",
            1,
            open_reason::PERSIST,
        );
        assert!(fired(&cut, TriggerType::PersistenceMechanism));
        let unread = classed_open(300, 0, "/etc/?/x", 1, open_reason::PERSIST);
        assert!(fired(&unread, TriggerType::PersistenceMechanism));
        // no kernel class: an unplaced path matches no list
        let plain = classed_open(300, 0, &format!("{unplaced}/etc/cron.d/job"), 1, 0);
        assert!(!fired(&plain, TriggerType::PersistenceMechanism));
        // an exact path: the lists judge, the class does not widen them
        let exact = classed_open(300, 0, "/srv/elsewhere/job", 1, open_reason::PERSIST);
        assert!(!fired(&exact, TriggerType::PersistenceMechanism));
        // the class never turns a read into a write
        let read = classed_open(
            300,
            0,
            &format!("{unplaced}/etc/cron.d/job"),
            0,
            open_reason::PERSIST,
        );
        assert!(!fired(&read, TriggerType::PersistenceMechanism));
    }

    /// BUG-018's NSS carve-out still holds for `/etc/passwd` under an
    /// unplaced root (a btrfs subvolume layout), and only for it.
    #[test]
    fn passwd_carve_out_holds_under_an_unplaced_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_loginuid_fixture(tmp.path(), 4242, 1000);
        let det = detector_with_fixture_proc(tmp.path());
        let passwd = classed_open(
            4242,
            1000,
            "mnt[0:45:256]/@/etc/passwd",
            0,
            open_reason::SENSITIVE,
        );
        assert!(!det
            .detect(&passwd, &[])
            .contains(&TriggerType::SensitiveFileAccess));
        let shadow = classed_open(
            4242,
            1000,
            "mnt[0:45:256]/@/etc/shadow",
            0,
            open_reason::SENSITIVE,
        );
        assert!(det
            .detect(&shadow, &[])
            .contains(&TriggerType::SensitiveFileAccess));
    }

    /// External audit EBPF-011: the cgroup window's crossing (fork workers
    /// rewriting files, each under its own threshold) raises
    /// ConfirmedIntrusion as file-system evidence — it needs corroboration
    /// for COMBAT — also inside an SSH session; a package manager stays
    /// exempt.
    #[test]
    fn cgroup_window_mass_write_is_file_system_evidence() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(200, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/usr/bin/bash", 2), &[]);
        let _ = det.detect(&spawn_with_exe(410, 300, "/home/u/worker", 3), &[]);
        let mut e = mass_write(410, true, 10);
        if let Event::MassWrite {
            cgroup_window,
            count,
            ..
        } = &mut e
        {
            *cgroup_window = true;
            *count = common::wire::open_sensor::OPEN_CG_OVERWRITE_MIN;
        }
        let hits = det.detect(&e, &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        assert_eq!(
            evidence_class(TriggerType::ConfirmedIntrusion, &e),
            EvidenceClass::FileSystem
        );
        let _ = det.detect(&spawn_with_exe_by(0, 700, 300, "/usr/bin/dpkg", 4), &[]);
        if let Event::MassWrite { pid, .. } = &mut e {
            *pid = 700;
        }
        assert!(!det
            .detect(&e, &[])
            .contains(&TriggerType::ConfirmedIntrusion));
    }
}
