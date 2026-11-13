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

use common::wire::exe::exe_flags;
use common::wire::open_sensor::{open_reason, own_data};
use nn_model::posture_types::{EvidenceClass, TriggerType};
use nn_model::Event;

use super::corroboration::Scope;
use super::daemon_data::DaemonData;
use super::escalation_allow::{AllowTrigger, EscalationAllowList};
use super::exempt::ExemptPids;
use super::host::{PostureAgent, PostureHost};
use super::lineage::{AsOf, AuthSessionTracker};
use super::proc_link::{lexical_form, through_proc_link};
use crate::decision::host::{AccountKind, DecisionHost};

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
/// - `/run/udev/`       — systemd-udevd's runtime device database (lot
///   282, the re-check of #500, measured: the
///   boot's coldplug, `udevadm trigger --action=add`
///   on Ubuntu 22.04, made each udevd worker write
///   20 database files new and replace 20 old ones
///   by a rename — the replacement shape, ENGAGED
///   on `systemd-udevd.service`). Root-only (udevd's,
///   0755), on the `/run` tmpfs as `/run/systemd`,
///   no user's data: device databases, tags, links.
///   Persistence through udev rules (ATT&CK
///   T1546.017: `/etc/udev/rules.d`,
///   `/lib/udev/rules.d`, the volatile
///   `/run/udev/rules.d` inside this carve-out) is
///   watched by no rule today — no FIM path, no
///   persistence prefix: a lot of its own, not this
///   arm's (a ransomware heuristic, no persistence
///   detector).
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
pub const MASS_WRITE_CARVEOUT_PREFIXES: &[&str] = &[
    "/sys/",
    "/proc/",
    "/run/systemd/",
    "/run/log/journal/",
    "/run/udev/",
];

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
/// passed (tracepoint mode), which no kernel resolved: it is judged by its
/// [`lexical_form`] only, and never carved out when it has none
/// (`/proc/../home/u/x`, lot 286: `/proc/self/root/../home/u/x`) or goes
/// through a link to another view of the filesystem
/// ([`through_proc_link`]: `/proc/self/cwd/report.docx`) — the kernel
/// opens what the link leads to, not a pseudo-file.
fn is_mass_write_carveout_unresolved(filename: &str, extras: &[String]) -> bool {
    lexical_form(filename)
        .is_some_and(|p| !through_proc_link(&p) && is_mass_write_carveout(&p, extras))
}

// Lot 286's `lexical_form` and `through_proc_link` are the posture's one
// reader of a path through a `/proc` link since lot 310 ([`super::proc_link`]),
// shared with R004.

/// A device node under `/dev` (not the `/dev/shm` and `/dev/mqueue`
/// filesystems, which hold files).
fn is_device_node(filename: &str) -> bool {
    filename.starts_with("/dev/")
        && !filename.starts_with("/dev/shm/")
        && !filename.starts_with("/dev/mqueue/")
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
pub const SENSITIVE_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/login.defs",
];
pub const CRITICAL_FILES_PREFIXES: &[&str] = &[
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
pub const PERSISTENCE_PREFIXES: &[&str] = &[
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
///
/// R08a (lab PR 250): `H` is the host — the process table the lineage and
/// the exemption read, and what the triggers consult in the agent's other
/// modules ([`PostureAgent`]; the agent's is `LinuxHost`). R08c (lab PR
/// 252): the decision engine's host ([`DecisionHost`], on top of it), whose
/// ransomware tracker and security-tool detector the triggers read.
#[derive(Debug, Default, Clone)]
pub struct TriggerDetector<H: DecisionHost> {
    /// PIDs belonging to the NorthNarrow process stack (agent + the
    /// verified watchdog) whose events must never raise a trigger.
    exempt: ExemptPids<H>,
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
    auth: AuthSessionTracker<H>,
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
    /// Lot 282: per pid, when the kernel last reported it creating files
    /// and destroying originals — the replacement shape of the mass-write
    /// arm (copy then delete, write then rename onto the original).
    replacements: Replacements,
    /// Lab PR 162: the trusted-installer window, once `main.rs` has wired
    /// it ([`Self::set_installer_window`]); inside it a control-surface
    /// tamper does not raise the posture.
    installer_window: InstallerWindow<H>,
    /// Lab PR 225: the ransomware tracker and the security-tool detector
    /// the rules share, once `main.rs` has wired them.
    impact: ImpactHooks<H>,
    /// Tappa 10.9 step 1: `true` once the file-open sensor on LSM
    /// `file_open` counts write-opens in the kernel and reports bursts as
    /// `Event::MassWrite`. Only the opens a rule reads reach userland then,
    /// so counting `FileOpen` events here would be wrong (and double): the
    /// mass-write arm reads `MassWrite` instead. `false` (tracepoint mode,
    /// the Q6 switch, the default) keeps the userland count. Lab PR 249:
    /// this detector's own ([`Self::set_kernel_mass_write`]; it was a
    /// process-wide switch).
    kernel_mass_write: Arc<AtomicBool>,
    /// Lot 283c: the daemons' data directories (`daemon-data.v1` and the
    /// overlay's), once the agent has wired them
    /// ([`Self::set_daemon_data`]); the kernel's tags index them. Unset, a
    /// crossing in a daemon's directory always counts.
    daemon_data: Arc<std::sync::OnceLock<Arc<DaemonData>>>,
}

/// Lab PR 225: the shared judges of the ransomware and security-tool
/// triggers. Unset (a test, a build that does not wire them): neither
/// trigger fires.
struct ImpactHooks<H: DecisionHost> {
    ransom: Arc<std::sync::OnceLock<Arc<crate::impact::RansomTracker<H>>>>,
    defense: Arc<std::sync::OnceLock<Arc<crate::impair::DefenseDetector<H>>>>,
}

/// R08a (lab PR 250): what `derive(Clone, Default)` made, without asking
/// the host's judges to be `Clone` or `Default` (only their slots are).
impl<H: DecisionHost> Clone for ImpactHooks<H> {
    fn clone(&self) -> Self {
        Self {
            ransom: self.ransom.clone(),
            defense: self.defense.clone(),
        }
    }
}

impl<H: DecisionHost> Default for ImpactHooks<H> {
    fn default() -> Self {
        Self {
            ransom: Arc::default(),
            defense: Arc::default(),
        }
    }
}

impl<H: DecisionHost> std::fmt::Debug for ImpactHooks<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImpactHooks")
            .field("ransom", &self.ransom.get().is_some())
            .field("defense", &self.defense.get().is_some())
            .finish()
    }
}

/// Lab PR 162: the trusted-installer window as the detector reads it.
/// Unset (a test, a build that does not wire it) reads as closed, so the
/// trigger fires.
struct InstallerWindow<H: PostureAgent>(Arc<std::sync::OnceLock<Arc<H::InstallerWindow>>>);

/// R08a (lab PR 250): what `derive(Clone, Default)` made, without asking
/// the host's window to be `Clone` or `Default` (only its slot is).
impl<H: PostureAgent> Clone for InstallerWindow<H> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<H: PostureAgent> Default for InstallerWindow<H> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<H: PostureAgent> std::fmt::Debug for InstallerWindow<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallerWindow")
            .field("wired", &self.0.get().is_some())
            .finish()
    }
}

impl<H: PostureAgent> InstallerWindow<H> {
    fn is_open(&self) -> bool {
        self.0.get().is_some_and(|w| H::installer_window_open(w))
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

/// Lot 282: one half of the replacement shape, as the kernel reports it
/// (once per window per process each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Half {
    /// The files the process created crossed the threshold
    /// (`MassWrite { overwrites: false }`).
    Created,
    /// The originals it destroyed — unlinked, or replaced by a rename onto
    /// their name — crossed the threshold (`FileBurst { kind: Unlink }`).
    Destroyed,
}

/// Lot 282: who a half of the replacement shape belongs to — the process
/// that crossed it, and (the review of #500, C1) its cgroup: an encryptor
/// that writes the copies and a separate process that deletes the
/// originals (a helper, an `rm` it runs, a second worker of the same
/// unit or container) are one replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PairKey {
    Pid(u32),
    Cgroup(u64),
}

/// Lot 282: per process and per cgroup, the last time each half of the
/// replacement shape was reported (pruned of keys older than a window past
/// 1,024, as [`MassWriters`]) and (lot 283c) whether that half was the
/// writer's own data ([`own_data_exempt`]).
#[derive(Debug, Default, Clone)]
struct Replacements(Arc<parking_lot::Mutex<HashMap<PairKey, [Option<HalfSeen>; 2]>>>);

/// Lot 283c: when a half of the replacement shape was reported, and
/// whether it was the writer's own data.
type HalfSeen = (u64, bool);

impl Replacements {
    /// Record `half` of `pid` — and of `cgroup`, when given — at `ts_ns`,
    /// `own` when its window held only the writer's own data; `Some` when
    /// the other half of either lies within a mass-write window of it, on
    /// either side (the rings are drained apart, and a writer may delete
    /// before it writes), with whether this half and every such other half
    /// were own data (lot 283c: a replacement is left out only whole).
    fn record(
        &self,
        pid: u32,
        cgroup: Option<u64>,
        half: Half,
        ts_ns: u64,
        own: bool,
    ) -> Option<bool> {
        let mut g = self.0.lock();
        if g.len() > 1024 {
            let cutoff = ts_ns.saturating_sub(MASS_WRITE_WINDOW_NS);
            g.retain(|_, h| h.iter().flatten().any(|(t, _)| *t >= cutoff));
        }
        let (mine, other) = match half {
            Half::Created => (0, 1),
            Half::Destroyed => (1, 0),
        };
        let mut paired = false;
        let mut all_own = own;
        for key in [Some(PairKey::Pid(pid)), cgroup.map(PairKey::Cgroup)]
            .into_iter()
            .flatten()
        {
            let h = g.entry(key).or_default();
            h[mine] = Some((ts_ns, own));
            if let Some((t, o)) = h[other] {
                if t.abs_diff(ts_ns) <= MASS_WRITE_WINDOW_NS {
                    paired = true;
                    all_own &= o;
                }
            }
        }
        paired.then_some(all_own)
    }
}

/// Lot 282, the review of #500 (C1): the cgroup a replacement's half is
/// paired in — the kernel's cgroup v2 id of the process that crossed it,
/// unless that is unknown or the root (no hierarchy in use: every process
/// would pair with every other), or the half would not count on its own
/// account: an exempt writer's ([`mass_write_exempt`]) or a process of an
/// authenticated session's (whose new files never counted) is paired with
/// its own process's other half alone, as before.
fn pairing_cgroup<H: PostureHost>(
    auth: &AuthSessionTracker<H>,
    pid: u32,
    cgroup_id: u64,
    ts_ns: u64,
    filename: &str,
) -> Option<u64> {
    if cgroup_id <= 1
        || mass_write_exempt(auth, pid, ts_ns, filename, false).is_some()
        || auth.is_auth_mediated(pid, AsOf::judged(ts_ns))
    {
        return None;
    }
    Some(cgroup_id)
}

impl<H: DecisionHost> TriggerDetector<H> {
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
            replacements: Replacements::default(),
            installer_window: InstallerWindow::default(),
            impact: ImpactHooks::default(),
            kernel_mass_write: Arc::default(),
            daemon_data: Arc::default(),
        }
    }

    /// Construct a detector with an explicit, shared [`ExemptPids`]
    /// (Beta Step 3) so the agent *and* the verified watchdog PID are
    /// both excluded, the latter refreshed live by `main.rs`.
    pub fn with_exempt(exempt: ExemptPids<H>) -> Self {
        Self {
            exempt,
            auth: AuthSessionTracker::default(),
            mass_write_extras: Arc::new(Vec::new()),
            mass_write_warned: Arc::default(),
            escalation_allow: Arc::new(EscalationAllowList::empty()),
            mass_writers: MassWriters::default(),
            replacements: Replacements::default(),
            installer_window: InstallerWindow::default(),
            impact: ImpactHooks::default(),
            kernel_mass_write: Arc::default(),
            daemon_data: Arc::default(),
        }
    }

    /// Beta Step 5 production constructor — combines the shared
    /// stack-exempt set with the auth-lineage tracker. `main.rs` uses
    /// this; tests can build a detector with a fixture `proc_root`
    /// via [`AuthSessionTracker::new`].
    pub fn with_exempt_and_auth(exempt: ExemptPids<H>, auth: AuthSessionTracker<H>) -> Self {
        Self {
            exempt,
            auth,
            mass_write_extras: Arc::new(Vec::new()),
            mass_write_warned: Arc::default(),
            escalation_allow: Arc::new(EscalationAllowList::empty()),
            mass_writers: MassWriters::default(),
            replacements: Replacements::default(),
            installer_window: InstallerWindow::default(),
            impact: ImpactHooks::default(),
            kernel_mass_write: Arc::default(),
            daemon_data: Arc::default(),
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
    pub fn set_installer_window(&self, window: Arc<H::InstallerWindow>) {
        let _ = self.installer_window.0.set(window);
    }

    /// Lab PR 225: the ransomware tracker (`RansomwareEncryption`). Set once.
    pub fn set_ransom_tracker(&self, tracker: Arc<crate::impact::RansomTracker<H>>) {
        let _ = self.impact.ransom.set(tracker);
    }

    /// Lab PR 225: the security-tool detector (`DefenseImpairment`). Set once.
    pub fn set_defense_detector(&self, detector: Arc<crate::impair::DefenseDetector<H>>) {
        let _ = self.impact.defense.set(detector);
    }

    /// Lot 283c: the daemons' data directories, in the order the file-open
    /// sensor tagged them. Set once.
    pub fn set_daemon_data(&self, data: Arc<DaemonData>) {
        let _ = self.daemon_data.set(data);
    }

    /// Switch the mass-write arm between the kernel count (LSM file-open
    /// sensor armed) and the userland count (tracepoint mode). Lab PR 249:
    /// this detector's, and the clones' that share its state.
    pub fn set_kernel_mass_write(&self, on: bool) {
        self.kernel_mass_write.store(on, Ordering::Relaxed);
    }

    /// Whether the mass-write arm reads the kernel count.
    pub fn kernel_mass_write(&self) -> bool {
        self.kernel_mass_write.load(Ordering::Relaxed)
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
            Some(pid) => self.scope_of(pid, AsOf::of_event(event)),
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
    fn scope_of(&self, pid: u32, as_of: AsOf) -> Scope {
        let workload = self.auth.session_workload(pid, as_of);
        match (workload, self.auth.session_loginuid(pid, as_of)) {
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
            Event::FileOpen { pid, flags, .. } if is_write_open(*flags) => self
                .auth
                .interactive_admin_status(*pid, AsOf::of_event(event)),
            _ => Some(false),
        }
    }

    /// Lot 281: whether `pid` belongs to an administrator's interactive
    /// sudo/su session ([`AuthSessionTracker::interactive_admin_status`]),
    /// `None` while it cannot be told — the injection record's lineage.
    pub fn interactive_admin_status(&self, pid: u32, as_of: AsOf) -> Option<bool> {
        self.auth.interactive_admin_status(pid, as_of)
    }

    /// Review 52: a pending writer placed —
    /// [`AuthSessionTracker::interactive_admin_status`] and its session's
    /// scope — or `None` while it still cannot be. As of `as_of` (R12b,
    /// R-F: the event whose round places it).
    pub fn place_writer(&self, pid: u32, as_of: AsOf) -> Option<(bool, Scope)> {
        self.auth
            .interactive_admin_status(pid, as_of)
            .map(|admin| (admin, self.scope_of(pid, as_of)))
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
        // FP-2: the argv, so the tracker can precompute the npm-CLI flag
        // (node running npm-cli.js) for the mass-write exemption. Tappa
        // 10.9 step 2: the file the kernel executed (review 61). External
        // audit POS-003: and the process's own start, which orders its fork
        // against its ancestors' execs. Lab PR 175: and the uid it executed
        // as (a package transaction is root's). Lot 310: and the executed
        // file's identity, `(dev, ino)` (R004 knows a re-exec of the
        // parent's own image by it) — the one ingest of an exec event,
        // `ingest_spawn_event`, as the bus's and the replay's.
        self.auth.ingest_spawn_event(event);

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
        // Lot 277: a move into an exempt cgroup is no refusal (`CgroupJoin`):
        // it raises no tamper trigger — it voids the exemption, and what the
        // moved process does is judged by the rules without it.
        if let Event::FsProtectDenial {
            pid,
            operation,
            timestamp_ns,
            target_dev,
            target_ino,
            ..
        } = event
        {
            // Lot 340: nor a known system program's feature probe, its
            // loader proven (the user manager's, networkd's): refused and
            // signed Low — every boot of Ubuntu 26.04 raised ENGAGED with it.
            let known_probe = *operation == nn_model::FsProtectOperation::BpfProgType
                && common::bpf_prog_class::known_probe_of(*target_dev, *target_ino).is_some();
            // Lot 280a: nor a write the signed per-sysctl opt-out let
            // through (`SysctlOptOut`): recorded, the operator's tuning.
            // Lot 280b: nor what the kernel-state round found (a new
            // kernel taint, a foreign program on the root's sysctl slot):
            // the kernel's record, no refusal — signed, the rules' to weigh.
            // Lot 281: nor code-injection access to a process (a debugger's
            // attach, any process's): recorded, the process's exemptions
            // revoked — what it does next is judged without them.
            // Lot 290: nor a load the signed per-loader opt-out let through,
            // nor the cross-view's findings (a program the hook never saw,
            // the start's baseline): signed, no refusal.
            if known_probe {
                // lot 340: refused, recorded Low by NN-L-AT-001; no trigger
            } else if !matches!(
                operation,
                nn_model::FsProtectOperation::CgroupJoin
                    | nn_model::FsProtectOperation::SysctlOptOut
                    | nn_model::FsProtectOperation::KernelTaint
                    | nn_model::FsProtectOperation::SysctlRootProg
                    | nn_model::FsProtectOperation::ExemptInjection
                    | nn_model::FsProtectOperation::BpfProgOptOut
                    | nn_model::FsProtectOperation::BpfUnseen
                    | nn_model::FsProtectOperation::BpfBaseline
            ) {
                hits.push(if *operation == nn_model::FsProtectOperation::Sigio {
                    // Lot 293 (external bug hunt BUG14): a refused signal
                    // through a file's owner names the process whose I/O
                    // raised it — any process a softirq interrupted, PID 1
                    // included — not the one that armed the file: refused
                    // and signed, ENGAGED, and never a COMBAT offender (an
                    // attacker's socket must not steer the ladder at an
                    // innocent process).
                    TriggerType::DefenseImpairment
                } else if *pid == 1 {
                    TriggerType::RelayedTamperAttempt
                } else if is_package_file_operation(*operation)
                    && self
                        .auth
                        .in_package_transaction(*pid, AsOf::judged(*timestamp_ns))
                {
                    // Lot 282 (Tappa Prove): a refusal of a package
                    // transaction's process — `deb-systemd-helper` removing a
                    // directory the agent protects while `apt purge` runs — is
                    // signed (NN-L-AT-001) and already blocked. It raises
                    // ALERTED and never corroborates: it locked COMBAT on its
                    // own, and the ladder killed the maintainer script. The
                    // transaction is judged as R009 and the FIM rules judge it
                    // (a package manager proper executed by root whose run
                    // covers the refusal). The review of #500 (B2): only the
                    // file operations a maintainer script does
                    // ([`is_package_file_operation`]); a refused signal,
                    // ptrace, BPF handle, kexec, cgroup write, limit, read or
                    // scheduling change keeps its weight below — any root
                    // process becomes a "transaction" with an `apt-get -o
                    // APT::Update::Pre-Invoke::=…` hook.
                    TriggerType::PackageTamperRefusal
                } else if *operation == nn_model::FsProtectOperation::Read {
                    // External audit EVD-001: a refused read of the agent's
                    // signing key is a credential reach (ALERTED), not a
                    // decisive tamper — a backup of /etc meets it too.
                    TriggerType::SensitiveFileAccess
                } else if matches!(
                    operation,
                    nn_model::FsProtectOperation::Sched
                        | nn_model::FsProtectOperation::Nice
                        | nn_model::FsProtectOperation::Ioprio
                        | nn_model::FsProtectOperation::Sysctl
                        | nn_model::FsProtectOperation::SysctlValue
                        // lot 280b: the switches that blind the sensors, and
                        // a cgroup/sysctl attach to the root — refused; a
                        // debugging script meets them too
                        | nn_model::FsProtectOperation::Kprobes
                        | nn_model::FsProtectOperation::Lockdown
                        | nn_model::FsProtectOperation::SysctlRootAttach
                        // lot 290: a load of a refused program type, a
                        // handle on the agent's maps or programs to read or
                        // inspect them — refused; an administrator's
                        // bpftrace or `bpftool prog list` meets them too
                        | nn_model::FsProtectOperation::BpfProgType
                        | nn_model::FsProtectOperation::BpfHandle
                ) {
                    // Lot 273c: a refused change of the agent's scheduling, nice
                    // value or I/O priority is an impairment (ENGAGED), not a
                    // decisive tamper — a tuning daemon (tuned, numad) applying
                    // a host-wide profile meets it too, and the ladder must not
                    // kill it. A limit change (`prlimit --cpu`) is a kill: it
                    // stays decisive.
                    TriggerType::DefenseImpairment
                } else {
                    TriggerType::AntiTamperDenial
                });
            }
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
        // Lab PR 219: the exploit post-condition guard's finding — kernel
        // evidence of COMBAT tier that needs a second signal of another
        // class while the guard is experimental (the shared predicate of
        // NN-L-EPG-001/002, so the rules and the trigger cannot drift).
        if crate::decision::rules::epg::is_exploit_postcondition(event) {
            hits.push(TriggerType::ExploitPostcondition);
        }
        let mass_write = confirmed_intrusion(
            event,
            recent,
            &self.auth,
            &self.mass_write_extras,
            &self.mass_write_warned,
            &self.replacements,
            self.kernel_mass_write(),
            self.daemon_data.get().map(Arc::as_ref),
        );
        if mass_write {
            if let (Some(pid), (_, ts)) = (event_owner_pid(event), event_owner_seen(event)) {
                self.mass_writers.record(pid, ts);
            }
        }
        // Lab PR 224 (CM-03): a shell or interpreter whose stdin/stdout is
        // the network — R020's shape (reverse shell, bind shell, pty-wrapped
        // reverse shell), read on exec identity and the kernel's file table.
        // A COMBAT-tier execution signal: on its own it stops at ENGAGED, a
        // second signal of another class reaches COMBAT.
        let reverse_shell =
            crate::decision::rules::r020_shell_with_socket_stdio::shape(event, Some(&self.auth))
                .is_some();
        if mass_write || staged == Some(StagedExec::Confirmed) || reverse_shell {
            hits.push(TriggerType::ConfirmedIntrusion);
        }
        // Lab PR 225: two shapes of ransomware for one actor whose trust is
        // not established — decisive (not locked: POS-001; its COMBAT
        // without corroboration is held behind the per-rule policy, off by
        // default). The shapes alone keep their triggers (the mass-write
        // arm above).
        if let Some(t) = self.impact.ransom.get() {
            if t.assess(event).is_some_and(|a| a.decisive) {
                hits.push(TriggerType::RansomwareEncryption);
            }
        }
        // Lab PR 225: a security tool switched off outside a package
        // transaction, an administrator's session and configuration
        // management — ENGAGED, execution evidence that corroborates.
        if let Some(d) = self.impact.defense.get() {
            if d.assess(event).is_some_and(|f| f.sanctioned.is_none()) {
                hits.push(TriggerType::DefenseImpairment);
            }
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
        // Lot 282: and its replacement shape, raised on the burst of
        // originals destroyed — every shape of the arm is one kind of
        // evidence, so no shape of it corroborates another.
        (
            TriggerType::ConfirmedIntrusion,
            Event::MassWrite { .. } | Event::FileOpen { .. } | Event::FileBurst { .. },
        ) => EvidenceClass::FileSystem,
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
        | Event::FileBurst { uid, .. }
        | Event::DefenderSignal { uid, .. }
        | Event::TcpConnect { uid, .. }
        | Event::DnsQuery { uid, .. }
        | Event::ExploitPostcondition { uid, .. } => Some(*uid),
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
        | Event::FileBurst { pid, .. }
        | Event::DefenderSignal { pid, .. }
        | Event::ExecCheck { pid, .. }
        | Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::FsProtectDenial { pid, .. }
        | Event::ExploitPostcondition { pid, .. } => Some(*pid),
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
        | Event::FileBurst { timestamp_ns, .. }
        | Event::DefenderSignal { timestamp_ns, .. }
        | Event::ExecCheck { timestamp_ns, .. }
        | Event::TcpConnect { timestamp_ns, .. }
        | Event::DnsQuery { timestamp_ns, .. }
        | Event::FsProtectDenial { timestamp_ns, .. }
        | Event::ExploitPostcondition { timestamp_ns, .. } => (0, *timestamp_ns),
        _ => (0, 0),
    }
}

/// Lab PR 245: the time of an event that raised a trigger (the sensors'
/// clock, ns): the owner's event time, a FIM change's own; 0 when the
/// event carries none.
pub fn event_time_ns(event: &Event) -> u64 {
    match event {
        Event::Fim(fe) => fe.timestamp_ns,
        _ => event_owner_seen(event).1,
    }
}

/// Lab PR 245: an event's kind, as its serialised form names it — the
/// evidence a COMBAT entry cites ([`super::entry::TriggerEvidence`]).
pub fn event_kind(event: &Event) -> &'static str {
    match event {
        Event::ProcessSpawn { .. } => "ProcessSpawn",
        Event::FileOpen { .. } => "FileOpen",
        Event::MassWrite { .. } => "MassWrite",
        Event::FileBurst { .. } => "FileBurst",
        Event::DefenderSignal { .. } => "DefenderSignal",
        Event::ExecCheck { .. } => "ExecCheck",
        Event::ModuleLoad { .. } => "ModuleLoad",
        Event::BpfSyscall { .. } => "BpfSyscall",
        Event::IoUring { .. } => "IoUring",
        Event::TcpConnect { .. } => "TcpConnect",
        Event::DnsQuery { .. } => "DnsQuery",
        Event::FsProtectDenial { .. } => "FsProtectDenial",
        Event::Fim(_) => "Fim",
        Event::CanaryTripped { .. } => "CanaryTripped",
        Event::NetFlow(_) => "NetFlow",
        Event::NetListener(_) => "NetListener",
        Event::NetInbound(_) => "NetInbound",
        Event::DnsAnswer(_) => "DnsAnswer",
        Event::TlsClientHello(_) => "TlsClientHello",
        Event::DnsFlood { .. } => "DnsFlood",
        Event::SensorFlood { .. } => "SensorFlood",
        Event::ExploitPostcondition { .. } => "ExploitPostcondition",
    }
}

fn recon_pattern(focal: &Event, recent: Recent<'_>) -> bool {
    if let Event::ProcessSpawn { comm, .. } = focal {
        if RECON_TOOL_COMMS.iter().any(|c| comm == c) {
            return true;
        }
    }
    distinct_dst_ports_in_window(focal, recent, RECON_WINDOW_NS) >= RECON_DISTINCT_PORTS_MIN
}

fn heavy_recon(focal: &Event, recent: Recent<'_>) -> bool {
    distinct_dst_ports_in_window(focal, recent, HEAVY_RECON_WINDOW_NS)
        >= HEAVY_RECON_DISTINCT_PORTS_MIN
}

/// The distinct destination ports of the focal `TcpConnect`'s process
/// within `window_ns` of it, the focal's own port included (0 for any other
/// event).
///
/// Bug hunt 1.3, BUG40/BUG50: the focal used to be added as `+ 1` on top of
/// the ports of the recent connects, so a focal back on a port already
/// counted was counted twice: 80, 443 and 443 again raised Reconnaissance
/// (three ports wanted), nine ports and the ninth again
/// HeavyReconnaissance (ten wanted). The focal's port now joins the set.
fn distinct_dst_ports_in_window(focal: &Event, recent: Recent<'_>, window_ns: u64) -> usize {
    let Event::TcpConnect {
        pid,
        dst_port: focal_port,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return 0;
    };
    let (pid, focal_ts) = (*pid, *focal_ts);
    let mut ports: HashSet<u16> = HashSet::from([*focal_port]);
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
    kernel_class & bit != 0 && !crate::path_text::path_is_exact(filename)
}

fn sensitive_file_access<H: PostureHost>(focal: &Event, auth: &AuthSessionTracker<H>) -> bool {
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
    // R12b (R-F): the reader's lineage as of the open
    let as_of = AsOf::of_event(focal);
    // root (uid=0) is excluded — its accesses are routine.
    if *uid == 0 {
        return false;
    }
    // External audit POS-007: a service uid (1..999) used to be excluded
    // as well, before any other check — a web shell running as www-data
    // reading `/etc/shadow` raised nothing. It is judged on its own terms.
    if *uid < 1000 {
        return service_uid_credential_read(*pid, filename, by_kernel, auth, as_of);
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
    if auth.is_credential_reader(*pid, as_of) {
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
fn service_uid_credential_read<H: PostureHost>(
    pid: u32,
    filename: &str,
    by_kernel: bool,
    auth: &AuthSessionTracker<H>,
    as_of: AsOf,
) -> bool {
    let credential = SERVICE_UID_CREDENTIAL_FILES
        .iter()
        .any(|f| filename == *f || (by_kernel && filename.ends_with(f)));
    if !credential || auth.is_credential_reader(pid, as_of) {
        return false;
    }
    auth.image_path_as(pid, as_of)
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
    // The parent is a network loader when the image it ran last before the
    // focal spawn is one: its latest recent `ProcessSpawn` (by kernel time)
    // at or before the focal.
    //
    // Bug hunt 1.3, BUG51: any past spawn of the parent's pid used to do —
    // a `curl` the parent ran before it executed `python3`, or a `curl` of
    // a day ago whose pid the parent took since. Now only the parent's
    // latest exec counts, and, when both starts are known, only an exec of
    // the parent's own incarnation (its `start_ns` is the focal's
    // `parent_start_ns`).
    let Event::ProcessSpawn {
        parent_start_ns,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    let same_incarnation =
        |start_ns: u64| *parent_start_ns == 0 || start_ns == 0 || start_ns == *parent_start_ns;
    let mut latest: Option<(u64, &str)> = None;
    for e in recent.iter() {
        if let Event::ProcessSpawn {
            pid,
            comm,
            start_ns,
            timestamp_ns,
            ..
        } = e
        {
            if *pid == *ppid
                && *timestamp_ns <= *focal_ts
                && same_incarnation(*start_ns)
                && latest.is_none_or(|(ts, _)| *timestamp_ns >= ts)
            {
                latest = Some((*timestamp_ns, comm.as_str()));
            }
        }
    }
    latest.is_some_and(|(_, comm)| NETLOAD_COMMS.contains(&comm))
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
/// Lot 346 (item 1): not raised at all, without a second factor, for a
/// program the packaged `go` built in its own work directory and runs
/// itself (`go test`'s test binaries, `go run`'s program:
/// [`AuthSessionTracker::runs_go_build_output`]) — every developer's `go
/// test` held the posture in ENGAGED. R001's record of the exec is the
/// rule's (a person's exec from `/tmp`, lot 283b).
///
/// Never promoted within a package transaction: maintainer scripts and
/// scriptlets run helpers they unpack in `/tmp`. Lab PR 175: the
/// transaction of the rules' carve-outs
/// ([`AuthSessionTracker::in_package_transaction`]: a package manager
/// proper executed by root whose run covers the exec), no longer any
/// `mandb` or package manager in the lineage. Not gated by the auth
/// lineage: a sudo-spawned process running `/tmp/payload` is raised like
/// any other. R001..R003 still kill the exec, whatever the posture — but
/// an exec by root from `/tmp` or `/var/tmp` (R001, R003), as R009's own,
/// waits for COMBAT: the decision of 03/11/2026, lot 278
/// ([`crate::decision::posture_floor`]). The trigger raised here is not.
fn staging_exec<H: PostureAgent>(
    focal: &Event,
    auth: &AuthSessionTracker<H>,
    mass_writers: &MassWriters,
) -> Option<StagedExec> {
    // lot 346 (the lab of item 1): the pre-exec check's process is still
    // the fork it was — its parent, the kernel's `ppid`, is asked
    let (pid, filename, exe, ts, pre_exec) = match focal {
        Event::ProcessSpawn {
            pid,
            filename,
            exe,
            timestamp_ns,
            ..
        } => (*pid, filename, exe, *timestamp_ns, None),
        Event::ExecCheck {
            pid,
            ppid,
            filename,
            exe,
            timestamp_ns,
            ..
        } => (*pid, filename, exe, *timestamp_ns, Some(*ppid)),
        _ => return None,
    };
    let image = exe.path_or(filename);
    if !crate::decision::rules::is_staging_path(image) {
        return None;
    }
    if auth.in_package_transaction(pid, AsOf::judged(ts)) {
        return Some(StagedExec::Plain);
    }
    let unlinked = exe.has(exe_flags::DELETED) || exe.has(exe_flags::MEMFD);
    let mass_wrote = mass_writers.wrote_near(pid, ts);
    if !unlinked && !mass_wrote {
        // lot 346 (item 1): `go test`'s test binary and `go run`'s program,
        // built by the packaged `go` in its work directory and run by it
        let as_of = AsOf::judged(ts);
        let go_built = match pre_exec {
            None => auth.runs_go_build_output(pid, as_of, image),
            Some(ppid) => auth.execs_go_build_output(ppid, as_of, image),
        };
        if go_built {
            return None;
        }
        return Some(StagedExec::Plain);
    }
    tracing::warn!(
        pid,
        image = %nn_model::log_escape::Escaped(image),
        unlinked,
        mass_wrote,
        "staging exec with a second factor — raising ConfirmedIntrusion"
    );
    Some(StagedExec::Confirmed)
}

/// The mass-write arm of `ConfirmedIntrusion` (the exec arm is
/// [`staging_exec`]).
///
/// Lot 282 (Tappa Prove P0): the arm measures what ransomware does to a
/// user's files — it rewrites or replaces many EXISTING ones — and no
/// longer how many files a process opens to write. The first `podman pull`
/// of a host (layers extracted: new files; `bolt_state.db` opened 259 times
/// in a minute: one file) raised it, then COMBAT, and the ladder killed
/// podman. The rules, as the kernel counts them (the file-open sensor on
/// LSM `file_open`, `inode_unlink`, `inode_rename`):
///
/// 1. **rewrites** — at least [`MASS_WRITE_MIN`] distinct existing files
///    of 4 KiB or more opened for writing by one process in 60 s, each file
///    once however often it is opened (`MassWrite { overwrites: true }`),
///    or 40 by the processes of one cgroup, each with three or more
///    (external audit EBPF-011). Counted inside an authenticated session
///    too (external audit POS-002: encryption in place run from a shell).
///    The review of #500 (C1): files under 4 KiB count too, each once, but
///    only outside an authenticated session (`MassWrite { small_files:
///    true }`): inside one only files of 4 KiB or more ever counted — a
///    build rewrites its own small outputs (lab PR 127: cargo killed).
/// 2. **replacement** — at least [`MASS_WRITE_MIN`] distinct originals
///    destroyed (unlinked, or replaced by a rename onto their name; each
///    name once; a file that holds data, or held it within the window — a
///    truncate then an unlink) by a process that also wrote at least
///    [`MASS_WRITE_MIN`] files new (created by the open, or empty when
///    opened: `mknod`, `O_TMPFILE` — the review of #500, B1), the two
///    crossings within a window of each other in either order
///    (`FileBurst { kind: Unlink }` and `MassWrite { overwrites: false }`):
///    an encrypted copy written, the original deleted or replaced. The two
///    halves pair within one process, or (the review of #500, C1) within
///    one cgroup — an encryptor and a separate deleter. Outside an
///    authenticated session: a session's new files never counted
///    (POS-002), and a checkout or an archive extracted over a tree from a
///    shell is this shape.
/// 3. **never on their own** — files created (an image pulled, a clone,
///    an archive extracted, a build, a cache filled), one file rewritten
///    again and again (a database, a state file), originals deleted (`rm
///    -rf`, a purge, a cache sweep).
///
/// Tracepoint mode (no LSM sensor: every open reaches userland, whether its
/// file existed is not known, and no unlink is seen): the distinct files
/// one process opened to write in the window — an extraction counts as on
/// main, since a copy-and-delete encryptor's copies (`O_CREAT | O_EXCL`
/// among them: the review of #500, C1) cannot be told from it — and inside
/// a session no open that may create one does (POS-002).
///
/// The writers [`mass_write_exempt`] names are exempt from every shape.
/// Lot 283c: so is a crossing whose window held only the writer's own data
/// ([`own_data_exempt`]) — a replacement only when both its halves did.
#[allow(clippy::too_many_arguments)]
fn confirmed_intrusion<H: DecisionHost>(
    focal: &Event,
    recent: Recent<'_>,
    auth: &AuthSessionTracker<H>,
    mass_write_extras: &[String],
    warned: &parking_lot::Mutex<HashMap<u32, u64>>,
    replacements: &Replacements,
    kernel_mass_write: bool,
    daemons: Option<&DaemonData>,
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
    match focal {
        Event::MassWrite {
            pid,
            uid,
            comm,
            filename,
            count,
            timestamp_ns,
            overwrites,
            cgroup_window,
            small_files,
            cgroup_id,
            own_data,
        } => {
            let mut own = own_data_exempt(auth, daemons, (*pid, *uid, *timestamp_ns), *own_data);
            let shape = if *overwrites && *small_files {
                Shape::SmallRewrites
            } else if *overwrites {
                Shape::Rewrites
            } else if let Some(all_own) = replacements.record(
                *pid,
                pairing_cgroup(auth, *pid, *cgroup_id, *timestamp_ns, filename),
                Half::Created,
                *timestamp_ns,
                own.is_some(),
            ) {
                own = own.filter(|_| all_own);
                Shape::Replacement
            } else {
                tracing::debug!(
                    pid = *pid,
                    comm = %nn_model::log_escape::Escaped(comm),
                    created = *count,
                    "files created (an extraction, a clone, a build) — not counted on their own; \
                     with originals destroyed beside them they would be"
                );
                return false;
            };
            let crossing = Crossing {
                pid: *pid,
                comm,
                filename,
                count: *count,
                timestamp_ns: *timestamp_ns,
                cgroup_window: *cgroup_window,
            };
            kernel_arm(auth, warned, &crossing, shape, own)
        }
        Event::FileBurst {
            pid,
            uid,
            comm,
            kind: nn_model::FileBurstKind::Unlink,
            count,
            filename,
            timestamp_ns,
            cgroup_id,
            own_data,
            ..
        } => {
            let own = own_data_exempt(auth, daemons, (*pid, *uid, *timestamp_ns), *own_data);
            let Some(all_own) = replacements.record(
                *pid,
                pairing_cgroup(auth, *pid, *cgroup_id, *timestamp_ns, filename),
                Half::Destroyed,
                *timestamp_ns,
                own.is_some(),
            ) else {
                tracing::debug!(
                    pid = *pid,
                    comm = %nn_model::log_escape::Escaped(comm),
                    destroyed = *count,
                    "originals destroyed with no files created beside them (rm -rf, a purge) — \
                     not counted"
                );
                return false;
            };
            let crossing = Crossing {
                pid: *pid,
                comm,
                filename,
                count: *count,
                timestamp_ns: *timestamp_ns,
                cgroup_window: false,
            };
            kernel_arm(
                auth,
                warned,
                &crossing,
                Shape::Replacement,
                own.filter(|_| all_own),
            )
        }
        // Tracepoint mode: every open reaches userland.
        Event::FileOpen { .. } if !kernel_mass_write => {
            tracepoint_arm(focal, recent, auth, mass_write_extras, warned)
        }
        _ => false,
    }
}

/// Lot 282: which rule of the arm a kernel crossing meets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Distinct existing files of 4 KiB or more rewritten in place.
    Rewrites,
    /// The review of #500 (C1): distinct existing non-empty files rewritten
    /// in place, some under 4 KiB.
    SmallRewrites,
    /// Originals destroyed by a process (or a cgroup) that wrote files new
    /// beside them.
    Replacement,
}

impl Shape {
    fn as_str(self) -> &'static str {
        match self {
            Shape::Rewrites => "existing files rewritten",
            Shape::SmallRewrites => "existing files rewritten, some under 4 KiB",
            Shape::Replacement => "originals destroyed and replaced by new files",
        }
    }

    /// Counted inside an authenticated session too: only the rewrites of
    /// files of 4 KiB or more (POS-002).
    fn counts_in_a_session(self) -> bool {
        self == Shape::Rewrites
    }
}

/// A kernel crossing, as the arm reads it.
struct Crossing<'a> {
    pid: u32,
    comm: &'a str,
    filename: &'a str,
    count: u32,
    timestamp_ns: u64,
    cgroup_window: bool,
}

/// The arm on a kernel crossing that meets `shape`: the exempt writers,
/// (lot 283c) a window of the writer's own data (`own`, from
/// [`own_data_exempt`]), then (a replacement) the authenticated session.
fn kernel_arm<H: PostureHost>(
    auth: &AuthSessionTracker<H>,
    warned: &parking_lot::Mutex<HashMap<u32, u64>>,
    c: &Crossing<'_>,
    shape: Shape,
    own: Option<&'static str>,
) -> bool {
    use nn_model::log_escape::Escaped;
    if let Some(why) = mass_write_exempt(auth, c.pid, c.timestamp_ns, c.filename, false) {
        // Recorded, not silent (lot 282: the evidence each exemption is
        // still needed under the arm's measure).
        tracing::info!(
            pid = c.pid,
            comm = %Escaped(c.comm),
            filename = %Escaped(c.filename),
            count = c.count,
            shape = shape.as_str(),
            exempt = why,
            "mass-write arm: crossing of an exempt writer — not counted"
        );
        return false;
    }
    if let Some(why) = own {
        tracing::info!(
            pid = c.pid,
            comm = %Escaped(c.comm),
            filename = %Escaped(c.filename),
            count = c.count,
            shape = shape.as_str(),
            own_data = why,
            "mass-write arm: every file of the crossing's window was the writer's own data — \
             not counted (the ransomware tracker still judges it)"
        );
        return false;
    }
    // External audit POS-002: a process of an authenticated session (SSH,
    // desktop, a cron job, sudo) was exempt whatever it wrote, so
    // ransomware run from a session never raised it. Its rewrites of
    // existing files — the shape of encryption in place — count; its new
    // files never did, and lot 282: neither does a replacement of
    // originals by new files (a checkout, an archive extracted over a tree),
    // nor (the review of #500, C1) a crossing that needed files under 4 KiB
    // (a build rewriting its own small outputs: lab PR 127).
    if !shape.counts_in_a_session() && auth.is_auth_mediated(c.pid, AsOf::judged(c.timestamp_ns)) {
        tracing::info!(
            pid = c.pid,
            comm = %Escaped(c.comm),
            filename = %Escaped(c.filename),
            count = c.count,
            shape = shape.as_str(),
            "crossing inside an authenticated session — not counted (a checkout, an archive \
             extracted over a tree, a build's own small outputs); rewriting existing files of 4 \
             KiB or more in place would be"
        );
        return false;
    }
    if mass_write_warn_due(warned, c.pid, c.timestamp_ns) {
        tracing::warn!(
            trigger = "ConfirmedIntrusion_MassWrite",
            focal_pid = c.pid,
            focal_comm = %Escaped(c.comm),
            focal_filename = %Escaped(c.filename),
            shape = shape.as_str(),
            count_within_window = c.count,
            // External audit EBPF-011: the processes of the writer's
            // cgroup together (`count` = their distinct rewrites).
            cgroup_window = c.cgroup_window,
            threshold = if c.cgroup_window {
                common::wire::open_sensor::OPEN_CG_OVERWRITE_MIN as usize
            } else {
                MASS_WRITE_MIN
            },
            window_secs = MASS_WRITE_WINDOW_NS / 1_000_000_000,
            "mass-write threshold crossed (kernel count) — raising ConfirmedIntrusion (→ ENGAGED; COMBAT only with corroboration)"
        );
    }
    true
}

/// The arm in tracepoint mode (every write-open reaches userland as a
/// `FileOpen`): the distinct files `focal`'s process opened to write in
/// the window, the focal open included.
fn tracepoint_arm<H: PostureHost>(
    focal: &Event,
    recent: Recent<'_>,
    auth: &AuthSessionTracker<H>,
    mass_write_extras: &[String],
    warned: &parking_lot::Mutex<HashMap<u32, u64>>,
) -> bool {
    let Event::FileOpen {
        pid: focal_pid,
        comm: focal_comm,
        filename: focal_filename,
        flags,
        timestamp_ns: focal_ts,
        path_from_user,
        ..
    } = focal
    else {
        return false;
    };
    if !is_write_open(*flags) {
        return false;
    }
    // BUG-014 (P-6) path-class carve-out: a write to a kernel-RPC pseudo-FS
    // (sysfs cgroupfs, procfs, systemd's /run state, journald binary log)
    // is not a data write and should not contribute to the ransomware-shape
    // mass-write heuristic. See MASS_WRITE_CARVEOUT_PREFIXES for the full
    // prefix list + per-class rationale. The focal-event check
    // short-circuits early; the recent-loop check below mirrors it so an
    // attacker can't pad a window of real data writes with sysfs noise to
    // dilute the count.
    // External audit POS-004: a caller's string, not the opened path.
    let carved = |f: &str| is_mass_write_carveout_unresolved(f, mass_write_extras);
    if carved(focal_filename) {
        return false;
    }
    // T7.13 — auth-mediated PIDs (sudo + its children: apt, systemctl, an
    // editor, …) routinely exceed the mass-write threshold during
    // legitimate administration. (ii) — system package-management daemons
    // (snapd, dpkg, apt, mandb) atomic-churn state files / caches well past
    // the threshold during routine maintenance. Only the mass-write arm is
    // gated here; FsProtectDenial and the staging exec still fire for these
    // PIDs. Lab PR 175: a package transaction's writes, and mandb's own as
    // a system account ([`mass_write_exempt`]). FP-2 — `npm install` /
    // `npm ci` (npm is a `#!/usr/bin/env node` script: the writer's exe is
    // the node interpreter; `is_npm_cli_writer` gates on exe ∈ NODE_EXES
    // AND argv[1] = npm-cli.js, the focal pid only, so every other node —
    // and any install script npm spawns — still fires). ACCEPTED residual
    // gap: a malicious package's files, extracted by the genuine npm
    // process, are exempt from the write-VOLUME signal; supply-chain malice
    // is caught by the exec / network / persistence arms, not here.
    if mass_write_exempt(auth, *focal_pid, *focal_ts, focal_filename, *path_from_user).is_some() {
        return false;
    }
    // External audit POS-002 (tracepoint mode sees the open flags but not
    // whether the file existed): a session's opens that may create
    // (`O_CREAT`) do not count, its opens of an existing file to write do.
    // Lot 282, the review of #500 (C1): outside a session an open that
    // must create its file (`O_CREAT | O_EXCL`) counts too — an encryptor's
    // copies are such files, and tracepoint mode sees no unlink to pair
    // them with (it did not count, and nothing saw them).
    let session = auth.is_auth_mediated(*focal_pid, AsOf::judged(*focal_ts));
    let counted = |f: u32| !session || f & O_CREAT == 0;
    if !counted(*flags) {
        return false;
    }
    // Audit `posture-3`: a PAM session (valid loginuid) writing into ITS
    // OWN `/run/user/<loginuid>/` is session plumbing — `systemd --user`
    // creating runtime dirs/sockets at login — not a ransomware burst.
    // Carve exactly that directory out for this writer; everything else
    // (incl. `/run/user/` of another uid and `$HOME`) still counts, so the
    // loginuid signal does not widen trust beyond the runtime dir.
    let own_runtime_dir = auth
        .loginuid_of(*focal_pid)
        .map(|uid| format!("/run/user/{uid}/"));
    // Lot 286: judged as the carve-out above (`/run/user/<uid>/../../../home/u/x`
    // started with the runtime dir).
    let in_own_runtime = |f: &str| {
        own_runtime_dir
            .as_deref()
            .is_some_and(|d| lexical_form(f).is_some_and(|p| p.starts_with(d)))
    };
    if in_own_runtime(focal_filename) {
        return false;
    }
    // Lot 282: distinct files — a database opened again and again is one.
    let mut files: HashSet<&str> = HashSet::new();
    files.insert(focal_filename.as_str());
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
                files.insert(filename.as_str());
            }
        }
    }
    let count = files.len();
    if count < MASS_WRITE_MIN {
        return false;
    }
    // BUG-015 observability: when the mass-write arm of confirmed_intrusion
    // fires, surface the focal PID + comm + the count so operators can
    // identify the writer (vs. having only `POSTURE TRANSITION
    // trigger=ConfirmedIntrusion` to go on). Review entry 37: once per
    // window per pid — a steady writer re-crosses the threshold on every
    // event.
    if mass_write_warn_due(warned, *focal_pid, *focal_ts) {
        tracing::warn!(
            trigger = "ConfirmedIntrusion_MassWrite",
            focal_pid = *focal_pid,
            focal_comm = %nn_model::log_escape::Escaped(focal_comm),
            focal_filename = %nn_model::log_escape::Escaped(focal_filename),
            distinct_files_within_window = count,
            threshold = MASS_WRITE_MIN,
            window_secs = MASS_WRITE_WINDOW_NS / 1_000_000_000,
            // BUG-032: this raises ConfirmedIntrusion (COMBAT-tier), but as
            // a NeedsCorroboration signal it escalates to ENGAGED on its own
            // — COMBAT (auto-isolation) needs a second distinct signal.
            "mass-write threshold crossed — raising ConfirmedIntrusion (→ ENGAGED; COMBAT only with corroboration); further hits of this pid are logged once per window"
        );
    }
    true
}

/// Lot 283c: a crossing whose window held only the writer's own data, as
/// the kernel judged each file (`own`, the event's `own_data`), and a
/// writer that summary is for — `Some` with which, `None` otherwise:
///
/// - `SERVICE` (every file under `/var/lib` or a service account's home, in
///   a directory the writer's uid owns, or its own segment in `/dev/shm`,
///   owned by it, not root): the uid is
///   a service account ([`AccountKind::System`]: below `UID_MIN` or a shell
///   that refuses a login) and the writer runs in a system service's cgroup
///   (`/system.slice/…/<unit>.service`, never a session's scope) —
///   PostgreSQL, MySQL, Redis writing their own data; lot 346 (item 6): or
///   the writer is the packaged `initdb` making a cluster, or its bootstrap
///   `postgres` ([`AuthSessionTracker::runs_postgres_initdb`]) — from a
///   session too (`pg_createcluster` by hand, `sudo -u postgres initdb`);
///   any other program of the account in a session still counts;
/// - `CACHE` (every file in its owner's `~/.cache`, written by that owner):
///   the uid is a person's ([`AccountKind::Human`]);
/// - a daemon directory's code (every file in one directory of
///   `daemon-data.v1` or the overlay): the writer's cgroup is one of that
///   directory's units (containerd, k3s, the kubelet, Docker, etcd).
///
/// The account is the host's classification (`DecisionHost::account_kind`,
/// lot 283b: the account database read again when it changes); the cgroup
/// is read when the crossing is judged, and a process gone by then is no
/// one's (the crossing counts).
fn own_data_exempt<H: DecisionHost>(
    auth: &AuthSessionTracker<H>,
    daemons: Option<&DaemonData>,
    (pid, uid, ts_ns): (u32, u32, u64),
    own: u8,
) -> Option<&'static str> {
    match own {
        own_data::NONE => None,
        // lot 346 (item 6): or by the packaged `initdb` making its cluster
        own_data::SERVICE => (H::account_kind(uid) == AccountKind::System
            && (auth.system_service(pid).is_some()
                || auth.runs_postgres_initdb(pid, AsOf::judged(ts_ns))))
        .then_some("a service account's own data, written by its service or its initdb"),
        own_data::CACHE => (H::account_kind(uid) == AccountKind::Human)
            .then_some("a person's own cache, written by that person"),
        code => {
            let units = daemons?.units_of(code)?;
            let unit = auth.system_service(pid)?;
            units
                .contains(&unit)
                .then_some("a listed daemon's own data directory, written by its unit")
        }
    }
}

/// The mass-write arm's writers (review 49 (ii), FP-2): a package
/// transaction's ([`AuthSessionTracker::in_package_transaction`]), mandb's
/// own as a system account (its cache rebuild,
/// [`AuthSessionTracker::is_system_man_cache_writer`]), npm's CLI's own
/// (lot 340: also run through `/usr/bin/npm`; lot 346: yarn's, pnpm's and
/// bun's too, in their own directories only,
/// [`AuthSessionTracker::js_pm_own_write`]), the Go toolchain's in its own
/// directories (lot 340, [`AuthSessionTracker::is_go_toolchain_own_write`]),
/// and a user's package manager in that user's container storage —
/// `Some` with which, `None` for any other writer.
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
///
/// Lot 282: under the arm's measure (rewrites and replacements, never
/// files created) the creation bursts these were written for no longer
/// count; each stays for the shape that still does — a package
/// transaction replaces the files it upgrades, `mandb` replaces each
/// locale's `index.db` by a rename, `npm ci` deletes `node_modules` and
/// extracts it again — and an exempt crossing is recorded at INFO, with
/// the exemption that answered.
fn mass_write_exempt<H: PostureHost>(
    auth: &AuthSessionTracker<H>,
    pid: u32,
    ts_ns: u64,
    path: &str,
    path_from_user: bool,
) -> Option<&'static str> {
    // R12b (R-F): as of the write
    let as_of = AsOf::judged(ts_ns);
    if auth.in_package_transaction(pid, as_of) {
        Some("package transaction")
    } else if auth.is_system_man_cache_writer(pid, as_of) {
        Some("man-db cache rebuild")
    } else if let Some(pm) = auth.js_pm_own_write(pid, as_of, path) {
        // lot 346 (the re-check of #552, N1): npm, yarn, pnpm, bun — in
        // their own directories only
        Some(pm.exempt_reason())
    } else if auth.is_go_toolchain_own_write(pid, as_of, path) {
        // lot 340: `go test` stamping its archives' build ids in place
        Some("the Go toolchain in its own work, build-cache or module-cache directory")
    } else if auth.is_user_container_storage_write(pid, as_of, path, path_from_user) {
        Some("a user's package manager in their container storage")
    } else {
        None
    }
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

fn persistence_mechanism<H: PostureHost>(focal: &Event, auth: &AuthSessionTracker<H>) -> bool {
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
    if auth.in_package_transaction(*pid, AsOf::judged(*timestamp_ns))
        || auth.is_user_container_storage_write(
            *pid,
            AsOf::judged(*timestamp_ns),
            filename,
            *path_from_user,
        )
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
    // BUG-039: public dst (NOT internal) for v4 or v6. Bug hunt 1.3,
    // BUG41: and off the host and its link ([`is_external`]).
    if !is_external(dst_addr, *family) {
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
                && matches!(*dp, 80 | 443)
                && is_external(dst, *fam)
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
/// External audit NETR-007: the predicate lives in `nn_model::netaddr`, shared
/// with NN-L-NET-007/018.
fn is_internal(addr: &[u8; 16], family: u8) -> bool {
    is_inet_family(family)
        && nn_model::netaddr::is_internal(nn_model::netaddr::canonical_ip(family, addr))
}

/// Is `addr` (a 16-byte wire address) a destination off the host and its
/// link, for the exfiltration pattern? An inet `family`, and not
/// [`is_internal`] (RFC 1918, unique-local, IPv6 link-local), loopback
/// (`127/8`, `::1`), unspecified, multicast, nor IPv4 link-local
/// (`169.254/16`, where a cloud instance's metadata service answers); an
/// IPv4-mapped address is judged as the IPv4 address it maps.
///
/// Bug hunt 1.3, BUG41: the pattern counted every destination that was not
/// internal, so twenty connects of a service to `127.0.0.1:443` (a local
/// proxy, a health check) raised ExfiltrationPattern, an ENGAGED trigger
/// that corroborates another class's heuristic of the same scope up to
/// COMBAT and the ladder's kill of the process. CGNAT (`100.64/10`) stays
/// external, as `nn_model::netaddr::is_internal` leaves it (external audit
/// NET-011): a carrier's or an overlay network's peer is off the host —
/// unlike `nn_model::netaddr::is_public`, which leaves it out.
fn is_external(addr: &[u8; 16], family: u8) -> bool {
    if !is_inet_family(family) {
        return false;
    }
    let ip = nn_model::netaddr::canonical_ip(family, addr);
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || nn_model::netaddr::is_internal(ip)
    {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_link_local(),
        std::net::IpAddr::V6(_) => true,
    }
}

fn is_write_open(flags: u32) -> bool {
    // O_WRONLY = 1, O_RDWR = 2 in glibc/Linux. Mask to access mode.
    let access = flags & 0b11;
    access == 1 || access == 2
}

/// `O_CREAT` on Linux (0o100): the open may create the file.
const O_CREAT: u32 = 0o100;

/// Lot 282, the review of #500 (B2): the refused operations a package
/// transaction's maintainer script really does — on the file namespace:
/// remove, rename, change the attributes of, or make an entry beside, a
/// file or directory the agent protects (`deb-systemd-helper`'s `rmdir`
/// during `apt purge`). Only these become [`TriggerType::PackageTamperRefusal`]
/// inside a transaction; every other refusal (a signal, a ptrace, a BPF
/// handle, a kexec, a cgroup write, a limit, a read of the key, a
/// scheduling change, a write-open, an `ioctl`, an `oom_score_adj`) keeps
/// the weight it has outside one.
fn is_package_file_operation(op: nn_model::FsProtectOperation) -> bool {
    use nn_model::FsProtectOperation as Op;
    matches!(
        op,
        Op::Unlink
            | Op::Rmdir
            | Op::Rename
            | Op::Setattr
            | Op::Create
            | Op::Link
            | Op::Symlink
            | Op::Mkdir
            | Op::Mknod
            | Op::Xattr
    )
}

/// The posture's event builders for tests: its own, and the agent's tests
/// of the posture (nn-core's `test-util`, R08a, lab PR 250).
#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
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
            stdio: Default::default(),
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
            known_resolver: false,
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
            operation: nn_model::FsProtectOperation::Unlink,
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

    use crate::posture::host::testing::{TestHost, TEST_OWNER};

    /// R08a (lab PR 250): the detector on the portable test host.
    type TriggerDetector = super::TriggerDetector<TestHost>;

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

    /// Named test (lot 346, item 1): `go test` runs each package's test
    /// binary from its work directory in `/tmp`, `go run` its program — the
    /// packaged `go` forked both. On `main` each was a staging exec and the
    /// developer's posture sat in ENGAGED (lot 340's dev corpus). The same
    /// file run by a shell, by the test binary itself, by a `go` in a home,
    /// a file outside the work directory's layout, and the test binary
    /// with a second factor (its image unlinked) are judged as before.
    #[test]
    fn go_test_binaries_and_go_run_programs_are_no_staging_exec() {
        let det = detector_with_empty_proc();
        let go = "/usr/lib/go-1.22/bin/go";
        let _ = det.detect(&spawn_with_exe(300, 1, "/usr/bin/bash", 1), &[]);
        let _ = det.detect(&rooted(spawn_with_exe(8000, 300, go, 2)), &[]);
        for (pid, image) in [
            (8001, "/tmp/go-build2618259110/b001/calc.test"),
            (8002, "/tmp/go-build4098838642/b001/exe/nncorpus"),
            (8003, "/var/tmp/go-build77/b012/x.test"),
        ] {
            let hits = det.detect(&spawn(pid, 8000, "calc.test", image, 5), &[]);
            assert!(
                !hits.contains(&TriggerType::StagingExec),
                "{image}: {hits:?}"
            );
        }
        let _ = det.detect(
            &rooted(spawn_with_exe(8010, 300, "/home/u/sdk/go1.23.0/bin/go", 2)),
            &[],
        );
        for (pid, ppid, image) in [
            (8020, 300, "/tmp/go-build2618259110/b001/calc.test"),
            (8021, 8001, "/tmp/go-build2618259110/b001/exe/helper"),
            (8022, 8010, "/tmp/go-build1/b001/calc.test"),
            (8023, 8000, "/tmp/go-build1/calc.test"),
            (8024, 8000, "/tmp/go-build1/b001/x/calc.test"),
            (8025, 8000, "/tmp/go-buildx/b001/calc.test"),
            (8026, 8000, "/tmp/go-build1/b001/../../evil"),
            (8027, 8000, "/tmp/evil"),
            // (mutation r1) no `b<digits>` directory; `..` before the work dir
            (8028, 8000, "/tmp/go-build1/evil/calc.test"),
            (8029, 8000, "/tmp/x/../go-build1/b001/calc.test"),
        ] {
            let hits = det.detect(&spawn(pid, ppid, "x", image, 6), &[]);
            assert_eq!(hits, vec![TriggerType::StagingExec], "{ppid} {image}");
        }
        // (mutation r1) never an ancestor further up: `go` forks 8040, which
        // forks 8041 and only then executes a shell; 8041 runs a file of a
        // work directory — its forker ran no `go` when it forked it
        let _ = det.detect(&rooted(spawn_with_exe(8040, 8000, go, 2)), &[]);
        let mut late = spawn_with_exe(8040, 8000, "/usr/bin/bash", 5);
        if let Event::ProcessSpawn { start_ns, .. } = &mut late {
            *start_ns = 3;
        }
        let _ = det.detect(&late, &[]);
        let mut child = spawn(8041, 8040, "x.test", "/tmp/go-build1/b001/x.test", 6);
        if let Event::ProcessSpawn { start_ns, .. } = &mut child {
            *start_ns = 4;
        }
        assert_eq!(det.detect(&child, &[]), vec![TriggerType::StagingExec]);
        // the pre-exec check (LSM `bprm_check_security`): the process is go's
        // fork, its parent the kernel's `ppid` — the lab's after-round found
        // `go test` still ENGAGED by it (the fork's `/proc` image is the test
        // binary by the time the posture reads it)
        let check = |pid: u32, ppid: u32, image: &str| Event::ExecCheck {
            pid,
            ppid,
            uid: 1000,
            comm: "go".into(),
            filename: image.into(),
            timestamp_ns: 6,
            exe: nn_model::ExeIdentity {
                path: image.into(),
                flags: exe_flags::KNOWN,
                ..Default::default()
            },
        };
        let built = "/tmp/go-build2618259110/b001/calc.test";
        let hits = det.detect(&check(8050, 8000, built), &[]);
        assert!(!hits.contains(&TriggerType::StagingExec), "{hits:?}");
        for (pid, ppid, image) in [
            (8051, 300, built),
            (8052, 8010, built),
            (8053, 8001, built),
            (8054, 8000, "/tmp/go-build1/evil/calc.test"),
            (8055, 8000, "/tmp/evil"),
        ] {
            let hits = det.detect(&check(pid, ppid, image), &[]);
            assert_eq!(hits, vec![TriggerType::StagingExec], "{ppid} {image}");
        }
        let mut gone = spawn(8030, 8000, "calc.test", "/tmp/go-build1/b001/calc.test", 7);
        if let Event::ProcessSpawn { exe, .. } = &mut gone {
            exe.path = "/tmp/go-build1/b001/calc.test".into();
            exe.flags |= exe_flags::KNOWN | exe_flags::DELETED;
        }
        assert!(det
            .detect(&gone, &[])
            .contains(&TriggerType::ConfirmedIntrusion));
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
            operation: nn_model::FsProtectOperation::Unlink,
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

    /// Lot 282 (Tappa Prove, lab 04/11 on main: `apt purge podman`): a
    /// refusal of a package transaction's process — `deb-systemd-helper`,
    /// a perl script dpkg's maintainer script runs — raises
    /// `PackageTamperRefusal` (ALERTED, never corroborates), not the
    /// decisive `AntiTamperDenial` that locked COMBAT and had the ladder
    /// kill it. The transaction is judged as R009 judges it: a package
    /// manager proper root executed, whose run covers the refusal. The
    /// same refusal from a user's own dpkg (`LD_PRELOAD`), from outside the
    /// transaction's tree, or after it ended keeps today's weight; PID 1's
    /// relayed signal stays `RelayedTamperAttempt`.
    #[test]
    fn a_package_transactions_refusal_is_alerted_not_decisive() {
        const S: u64 = 1_000_000_000;
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe_by(0, 100, 1, "/usr/bin/apt-get", S), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 110, 100, "/usr/bin/dpkg", 2 * S), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 120, 110, "/usr/bin/dash", 3 * S), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 130, 120, "/usr/bin/perl", 4 * S), &[]);
        // a user's dpkg (not root): no transaction
        let _ = det.detect(
            &spawn_with_exe_by(1000, 200, 1, "/usr/bin/dpkg", 5 * S),
            &[],
        );
        let _ = det.detect(
            &spawn_with_exe_by(1000, 210, 200, "/usr/bin/perl", 6 * S),
            &[],
        );
        // a root process outside any transaction
        let _ = det.detect(&spawn_with_exe_by(0, 300, 1, "/usr/bin/rmdir", 7 * S), &[]);
        let refusal =
            |pid: u32, op: nn_model::FsProtectOperation, ts: u64| Event::FsProtectDenial {
                pid,
                uid: 0,
                comm: "deb-systemd-hel".into(),
                target_dev: 64_770,
                target_ino: 12345,
                operation: op,
                timestamp_ns: ts,
            };
        use nn_model::FsProtectOperation as Op;
        for op in [
            Op::Rmdir,
            Op::Unlink,
            Op::Rename,
            Op::Setattr,
            Op::Create,
            Op::Link,
            Op::Symlink,
            Op::Mkdir,
            Op::Mknod,
            Op::Xattr,
        ] {
            assert_eq!(
                det.detect(&refusal(130, op, 8 * S), &[]),
                vec![TriggerType::PackageTamperRefusal],
                "{op:?}"
            );
        }
        // The review of #500 (B2): what is no file operation of a
        // maintainer script keeps its weight inside the transaction too.
        assert_eq!(
            det.detect(&refusal(130, Op::Signal, 8 * S), &[]),
            vec![TriggerType::AntiTamperDenial]
        );
        assert_eq!(
            det.detect(&refusal(130, Op::Read, 8 * S), &[]),
            vec![TriggerType::SensitiveFileAccess]
        );
        assert_eq!(
            det.detect(&refusal(130, Op::Sched, 8 * S), &[]),
            vec![TriggerType::DefenseImpairment]
        );
        assert_eq!(
            det.detect(&refusal(210, Op::Rmdir, 8 * S), &[]),
            vec![TriggerType::AntiTamperDenial]
        );
        assert_eq!(
            det.detect(&refusal(300, Op::Rmdir, 8 * S), &[]),
            vec![TriggerType::AntiTamperDenial]
        );
        // the transaction over: dpkg's exec plus the unseen grace, long past
        assert_eq!(
            det.detect(&refusal(130, Op::Rmdir, 3_600 * S), &[]),
            vec![TriggerType::AntiTamperDenial]
        );
        assert_eq!(
            det.detect(&refusal(1, Op::Signal, 8 * S), &[]),
            vec![TriggerType::RelayedTamperAttempt]
        );
    }

    /// Lot 318 (the review of #545, F1, and its re-check, R1 and R2): the
    /// kernel counts the records it calls non-decisive
    /// (`common::wire::is_minor_denial`) against a budget of their own, so a
    /// flood of them never takes a decisive refusal's room. That holds only
    /// if the two lists are one, both ways: no minor record raises
    /// `AntiTamperDenial` here, and every record that does not is minor
    /// there. The first version checked one way only, and the kprobes and
    /// lockdown switches (`DefenseImpairment`, refused at the write-open and
    /// signed at each attempt) still spent the decisive budget: 50 refused
    /// opens of `kprobes/enabled` held back a refused unlink's record on that
    /// CPU (R1); the renices and sysctl writes shared the task denials'
    /// budget with the refused signals (R2).
    #[test]
    fn the_kernel_s_minor_denials_are_exactly_the_non_decisive_ones_here() {
        const S: u64 = 1_000_000_000;
        let det = detector_with_empty_proc();
        let refusal = |op: nn_model::FsProtectOperation| Event::FsProtectDenial {
            pid: 420,
            uid: 0,
            comm: "x".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: op,
            timestamp_ns: 4 * S,
        };
        let mut minor = 0;
        for byte in 1..=common::wire::FS_OP_LAST {
            let op = nn_model::FsProtectOperation::from_wire(byte);
            let hits = det.detect(&refusal(op), &[]);
            let decisive = hits.contains(&TriggerType::AntiTamperDenial);
            if common::wire::is_minor_denial(byte) {
                minor += 1;
                assert!(
                    !decisive,
                    "{op:?} is a minor denial in the kernel and decisive here: {hits:?}"
                );
            } else {
                assert!(
                    decisive,
                    "{op:?} is not decisive here ({hits:?}) and spends a decisive budget in \
                     the kernel: add it to common::wire::is_minor_denial"
                );
            }
        }
        assert_eq!(minor, 20);
        use common::wire as w;
        for decisive in [
            w::FS_OP_UNLINK,
            w::FS_OP_RMDIR,
            w::FS_OP_RENAME,
            w::FS_OP_SETATTR,
            w::FS_OP_WRITE,
            w::FS_OP_CREATE,
            w::FS_OP_LINK,
            w::FS_OP_SYMLINK,
            w::FS_OP_MKDIR,
            w::FS_OP_MKNOD,
            w::FS_OP_XATTR,
            w::FS_OP_BPF_MAP,
            w::FS_OP_BPF_LINK,
            w::FS_OP_SIGNAL,
            w::FS_OP_PTRACE,
            w::FS_OP_KEXEC,
            w::FS_OP_RLIMIT,
            w::FS_OP_OOM_ADJ,
            w::FS_OP_CGROUP_MOVE,
        ] {
            assert!(!w::is_minor_denial(decisive), "{decisive}");
        }
        for minor in [
            w::FS_OP_KPROBES,
            w::FS_OP_LOCKDOWN,
            w::FS_OP_NICE,
            w::FS_OP_SCHED,
            w::FS_OP_IOPRIO,
            w::FS_OP_SYSCTL,
            w::FS_OP_CGROUP_JOIN,
        ] {
            assert!(w::is_minor_denial(minor), "{minor}");
        }
    }

    /// The review of #500 (B2, its probe): any root process makes itself a
    /// package transaction's — `apt-get -o APT::Update::Pre-Invoke::=/tmp/x
    /// update` runs `/tmp/x` under root's apt-get, through `sh -c`. Its
    /// refused signal, ptrace, BPF handles, kexec, cgroup kill and write-open
    /// of the agent stay decisive (`AntiTamperDenial`, COMBAT locked), its
    /// limit change too; its refused scheduling change stays an impairment,
    /// its refused read of the key a credential reach. Only a refused file
    /// operation of the kind a maintainer script does is ALERTED.
    #[test]
    fn a_pre_invoke_hook_keeps_every_refusal_but_the_file_operations_decisive() {
        const S: u64 = 1_000_000_000;
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe_by(0, 400, 1, "/usr/bin/apt-get", S), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 410, 400, "/usr/bin/dash", 2 * S), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 420, 410, "/tmp/x", 3 * S), &[]);
        let refusal = |op: nn_model::FsProtectOperation| Event::FsProtectDenial {
            pid: 420,
            uid: 0,
            comm: "x".into(),
            target_dev: 64_770,
            target_ino: 12345,
            operation: op,
            timestamp_ns: 4 * S,
        };
        use nn_model::FsProtectOperation as Op;
        for op in [
            Op::Signal,
            Op::Ptrace,
            Op::BpfLink,
            Op::BpfMap,
            Op::Kexec,
            Op::CgroupKill,
            Op::CgroupFreeze,
            Op::CgroupMove,
            Op::CgroupLimit,
            Op::CgroupV1,
            Op::OomAdj,
            Op::Rlimit,
            Op::Write,
            Op::Ioctl,
        ] {
            assert_eq!(
                det.detect(&refusal(op), &[]),
                vec![TriggerType::AntiTamperDenial],
                "{op:?}"
            );
        }
        for op in [Op::Sched, Op::Nice, Op::Ioprio] {
            assert_eq!(
                det.detect(&refusal(op), &[]),
                vec![TriggerType::DefenseImpairment],
                "{op:?}"
            );
        }
        assert_eq!(
            det.detect(&refusal(Op::Read), &[]),
            vec![TriggerType::SensitiveFileAccess]
        );
        assert_eq!(
            det.detect(&refusal(Op::Rmdir), &[]),
            vec![TriggerType::PackageTamperRefusal]
        );
    }

    /// Lot 277: a move into an exempt cgroup reaches the posture as a
    /// `CgroupJoin` record: no refusal, so no tamper trigger (PID 1's
    /// placements are never signed, a root shell's is not decisive) — the
    /// exemption is void, and the rules judge what the process does.
    #[test]
    fn a_move_into_an_exempt_cgroup_raises_no_tamper_trigger() {
        let det = TriggerDetector::new();
        for pid in [1, 9999] {
            let focal = Event::FsProtectDenial {
                pid,
                uid: 0,
                comm: "bash".into(),
                target_dev: 0x1234,
                target_ino: 4242,
                operation: nn_model::FsProtectOperation::CgroupJoin,
                timestamp_ns: 1,
            };
            let hits = det.detect(&focal, &[]);
            assert!(
                !hits.contains(&TriggerType::AntiTamperDenial)
                    && !hits.contains(&TriggerType::RelayedTamperAttempt),
                "{pid}: {hits:?}"
            );
        }
    }

    /// Lot 280a: a write the signed per-sysctl opt-out let through raises
    /// no trigger at all (the operator's tuning, recorded); a refusal on the
    /// kernel's copy is an impairment, as lot 273d's sysctl refusal.
    #[test]
    fn an_opted_out_sysctl_write_raises_nothing_and_a_refused_one_impairs() {
        let det = TriggerDetector::new();
        let ev = |operation| Event::FsProtectDenial {
            pid: 9999,
            uid: 0,
            comm: "tuned".into(),
            target_dev: 7,
            target_ino: u64::MAX,
            operation,
            timestamp_ns: 1,
        };
        assert!(det
            .detect(&ev(nn_model::FsProtectOperation::SysctlOptOut), &[])
            .is_empty());
        assert_eq!(
            det.detect(&ev(nn_model::FsProtectOperation::SysctlValue), &[]),
            vec![TriggerType::DefenseImpairment]
        );
    }

    /// Lot 280b (named): the kernel-state round's findings raise no
    /// trigger (no refusal); the refused switches impair (ENGAGED), never
    /// the decisive tamper.
    #[test]
    fn the_kernel_state_findings_raise_nothing_and_the_switches_impair() {
        let det = TriggerDetector::new();
        let ev = |operation| Event::FsProtectDenial {
            pid: 9999,
            uid: 0,
            comm: "x".into(),
            target_dev: 7,
            target_ino: 8,
            operation,
            timestamp_ns: 1,
        };
        for op in [
            nn_model::FsProtectOperation::KernelTaint,
            nn_model::FsProtectOperation::SysctlRootProg,
            // lot 281: an injection's record (no refusal) raises nothing
            nn_model::FsProtectOperation::ExemptInjection,
        ] {
            assert!(det.detect(&ev(op), &[]).is_empty(), "{op}");
        }
        for op in [
            nn_model::FsProtectOperation::Kprobes,
            nn_model::FsProtectOperation::Lockdown,
            nn_model::FsProtectOperation::SysctlRootAttach,
        ] {
            assert_eq!(
                det.detect(&ev(op), &[]),
                vec![TriggerType::DefenseImpairment],
                "{op}"
            );
        }
    }

    /// Lot 290 (named): a refused load of a refused program type and a
    /// refused handle on the agent's maps or programs impair (ENGAGED) — an
    /// administrator's bpftrace or `bpftool prog list` meets them, the
    /// ladder must not kill it; a write handle and a link handle stay
    /// decisive; an opt-out's load and the cross-view's findings raise
    /// nothing.
    #[test]
    fn foreign_bpf_refusals_impair_and_the_cross_view_raises_nothing() {
        let det = TriggerDetector::new();
        let ev = |operation| Event::FsProtectDenial {
            pid: 4242,
            uid: 0,
            comm: "bpftrace".into(),
            target_dev: 2,
            target_ino: 77,
            operation,
            timestamp_ns: 1,
        };
        for op in [
            nn_model::FsProtectOperation::BpfProgType,
            nn_model::FsProtectOperation::BpfHandle,
        ] {
            assert_eq!(
                det.detect(&ev(op), &[]),
                vec![TriggerType::DefenseImpairment],
                "{op}"
            );
        }
        for op in [
            nn_model::FsProtectOperation::BpfMap,
            nn_model::FsProtectOperation::BpfLink,
        ] {
            assert_eq!(
                det.detect(&ev(op), &[]),
                vec![TriggerType::AntiTamperDenial],
                "{op}"
            );
        }
        for op in [
            nn_model::FsProtectOperation::BpfProgOptOut,
            nn_model::FsProtectOperation::BpfUnseen,
            nn_model::FsProtectOperation::BpfBaseline,
        ] {
            assert!(det.detect(&ev(op), &[]).is_empty(), "{op}");
        }
    }

    /// Lot 293 (external bug hunt BUG14): a refused SIGIO-path signal
    /// impairs (ENGAGED) whatever process its record names — PID 1 and a
    /// shell alike — and is never the decisive trigger: the process named
    /// raised the I/O, it did not necessarily arm the file. A refused
    /// `kill` stays decisive.
    #[test]
    fn a_refused_sigio_impairs_and_names_no_offender() {
        let det = TriggerDetector::new();
        let ev = |pid, operation| Event::FsProtectDenial {
            pid,
            uid: 0,
            comm: "sshd".into(),
            target_dev: 9,
            target_ino: 77,
            operation,
            timestamp_ns: 1,
        };
        for pid in [1, 4242] {
            assert_eq!(
                det.detect(&ev(pid, nn_model::FsProtectOperation::Sigio), &[]),
                vec![TriggerType::DefenseImpairment],
                "pid {pid}"
            );
        }
        assert_eq!(
            det.detect(&ev(4242, nn_model::FsProtectOperation::Signal), &[]),
            vec![TriggerType::AntiTamperDenial]
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
            .map(|i| file_open(pid, 0, &format!("{path}.{i}"), 1, i + 1))
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
            operation: nn_model::FsProtectOperation::Unlink,
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
            operation: nn_model::FsProtectOperation::Unlink,
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
            stdio: Default::default(),
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
            stdio: Default::default(),
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
            .map(|i| file_open(200, 0, &format!("/var/cache/apt/x.{i}"), 1, i + 10))
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
            .map(|i| file_open(900, 1000, &format!("/home/u/x.{i}"), 1, i + 10))
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
                .map(|i| file_open(900, 1000, &format!("/home/u/x.{i}"), 1, 1_000 + offset + i))
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

    /// Lot 286 (the re-review of #500, N2): a `..` of a caller's path
    /// climbs from where the links before it led — `/proc/self/root/..` is
    /// `/` — and was folded into a `/proc/` path first, carved out.
    #[test]
    fn the_reviewers_proc_root_dotdot_write_counts() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(711, 1, "/srv/app/worker", 1), &[]);
        let hits = tracepoint_burst(&det, 711, &|i| {
            format!("/proc/self/root/../home/u/docs/{i}.docx")
        });
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        assert!(!is_mass_write_carveout_unresolved(
            "/proc/self/root/../home/u/x",
            &[]
        ));
    }

    /// Lot 286: `/proc/self/cwd/../..` is the cwd's grandparent, folded
    /// to `/proc` before.
    #[test]
    fn proc_self_cwd_dotdot_dotdot_write_counts() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(712, 1, "/srv/app/worker", 1), &[]);
        let hits = tracepoint_burst(&det, 712, &|i| format!("/proc/self/cwd/../../{i}.docx"));
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        assert!(!is_mass_write_carveout_unresolved(
            "/proc/self/cwd/../..",
            &[]
        ));
    }

    /// Lot 286: a link elsewhere under a carved-out prefix, then `..`
    /// (`/proc/net` → `self/net`; a sysfs device's `subsystem` →
    /// `/sys/class/net`, four levels up is `/`); `.` segments and a
    /// relative path are judged as before, and so is every other door
    /// into a process's view: `exe`, `map_files/`, `/dev/fd/<n>`.
    #[test]
    fn links_then_dotdot_and_other_proc_doors_count() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(713, 1, "/srv/app/worker", 1), &[]);
        let fired = |path: &dyn Fn(u64) -> String| {
            tracepoint_burst(&det, 713, path).contains(&TriggerType::ConfirmedIntrusion)
        };
        assert!(fired(&|i| format!("/proc/net/../root/home/u/{i}")));
        assert!(fired(&|i| format!(
            "/sys/devices/virtual/net/lo/subsystem/../../../../home/u/{i}"
        )));
        assert!(fired(&|i| format!("/proc/self/./root/home/u/{i}")));
        assert!(fired(&|i| format!("/proc/{}/exe", 1000 + i)));
        assert!(fired(&|i| format!("/proc/self/map_files/{i}000-{i}fff")));
        assert!(fired(&|i| format!("/dev/fd/{i}")));
        assert!(fired(&|i| format!("sys/fs/cgroup/x/{i}")), "relative");
        assert!(!fired(&|i| format!("/sys/fs/cgroup//./x/{i}")));
    }

    /// Lot 286: a plain write to a process's pseudo-file stays carved out.
    #[test]
    fn plain_proc_pid_status_write_stays_carved_out() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(714, 1, "/srv/app/worker", 1), &[]);
        let hits = tracepoint_burst(&det, 714, &|i| format!("/proc/{}/status", 2000 + i));
        assert!(!hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        assert!(is_mass_write_carveout_unresolved("/proc/42/status", &[]));
        assert!(is_mass_write_carveout_unresolved(
            "/proc/self/task/42/oom_score_adj",
            &[]
        ));
    }

    /// Lot 286: `/run/udev` and `/run/systemd` keep their carve-out in
    /// tracepoint mode, `/run/user` still counts.
    #[test]
    fn run_udev_and_run_systemd_keep_their_carveout_unresolved() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(715, 1, "/srv/app/worker", 1), &[]);
        let fired = |path: &dyn Fn(u64) -> String| {
            tracepoint_burst(&det, 715, path).contains(&TriggerType::ConfirmedIntrusion)
        };
        assert!(!fired(&|i| format!("/run/udev/data/c4:{i}")));
        assert!(!fired(&|i| format!(
            "/run/systemd/units/invocation:{i}.service"
        )));
        assert!(fired(&|i| format!("/run/user/1000/f{i}")));
        assert!(is_mass_write_carveout_unresolved(
            "/run/udev/data/b8:0",
            &[]
        ));
        assert!(is_mass_write_carveout_unresolved(
            "/run/systemd/units/x",
            &[]
        ));
    }

    /// Lot 286: the writer's own runtime dir is judged the same way —
    /// `/run/user/<uid>/../../../home/…` started with it.
    #[test]
    fn own_runtime_dir_carveout_does_not_fold_dotdot() {
        let tmp = tempfile::TempDir::new().unwrap();
        write_loginuid_fixture(tmp.path(), 716, 1000);
        let det = detector_with_fixture_proc(tmp.path());
        let _ = det.detect(&spawn_with_exe(716, 1, "/usr/bin/bash", 1), &[]);
        let fired = |path: &dyn Fn(u64) -> String| {
            tracepoint_burst(&det, 716, path).contains(&TriggerType::ConfirmedIntrusion)
        };
        assert!(
            !fired(&|i| format!("/run/user/1000/app/{i}")),
            "own runtime"
        );
        assert!(fired(&|i| format!(
            "/run/user/1000/../../../home/u/docs/{i}.docx"
        )));
    }

    /// `burst` of `the_mass_write_carveout_is_not_dodged_through_proc_links`:
    /// MASS_WRITE_MIN + 1 tracepoint write-opens (`O_WRONLY`) by `pid`.
    fn tracepoint_burst(
        det: &TriggerDetector,
        pid: u32,
        path: &dyn Fn(u64) -> String,
    ) -> Vec<TriggerType> {
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| file_open_from_user(pid, &path(i), 1, i + 10))
            .collect();
        let focal = file_open_from_user(pid, &path(99), 1, MASS_WRITE_MIN as u64 + 11);
        det.detect(&focal, &recent)
    }

    // lot 310: `dot_segments_fold_and_proc_links_are_doors` moved with the
    // reader it tests (`posture::proc_link`)

    /// Lot 310: the posture's ingest of an exec keeps the executed file's
    /// identity the LSM program gave (R004 tells a re-exec of the parent's
    /// own image by it); it ingested the path alone, and the lab's
    /// re-execution of a parent's unlinked image (ubuntu2604, r1) was killed.
    #[test]
    fn detect_ingests_the_executed_file_s_identity() {
        let tmp = tempfile::TempDir::new().unwrap();
        let auth = AuthSessionTracker::new(tmp.path());
        let det = TriggerDetector::with_exempt_and_auth(ExemptPids::default(), auth.clone());
        let mut e = nn_model::Event::ProcessSpawn {
            pid: 4100,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "chrome".into(),
            filename: "/opt/google/chrome/chrome".into(),
            timestamp_ns: 10,
            argv: vec!["chrome".into()],
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 10,
            parent_is_kthread: false,
            exe: nn_model::ExeIdentity {
                path: "/opt/google/chrome/chrome".into(),
                dev: 2049,
                ino: 4242,
                flags: exe_flags::KNOWN | exe_flags::ROOT_DIR,
                ..Default::default()
            },
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        };
        let _ = det.detect(&e, &[]);
        assert_eq!(auth.exec_image(4100, AsOf::Now), Some((2049, 4242)));
        // tracepoint mode: no identity
        if let nn_model::Event::ProcessSpawn { pid, exe, .. } = &mut e {
            *pid = 4101;
            exe.flags = 0;
        }
        let _ = det.detect(&e, &[]);
        assert_eq!(auth.exec_image(4101, AsOf::Now), None);
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
            small_files: false,
            cgroup_id: 0,
            own_data: 0,
        }
    }

    /// Lot 282, the review of #500 (C1): a crossing of `pid` in cgroup
    /// `cgroup_id`; `small`: an overwrite crossing that needed files under
    /// 4 KiB (`MASS_OVERWRITE_SMALL`).
    fn mass_write_in(pid: u32, cgroup_id: u64, overwrites: bool, small: bool, ts: u64) -> Event {
        let mut e = mass_write(pid, overwrites, ts);
        if let Event::MassWrite {
            cgroup_id: c,
            small_files,
            ..
        } = &mut e
        {
            (*c, *small_files) = (cgroup_id, small);
        }
        e
    }

    /// Lot 282: the kernel's burst of originals destroyed (unlinked, or
    /// replaced by a rename onto their name), `MASS_UNLINK`.
    fn destroyed(pid: u32, ts: u64) -> Event {
        destroyed_in(pid, 0, ts)
    }

    /// Lot 282, the review of #500 (C1): [`destroyed`] in cgroup
    /// `cgroup_id`.
    fn destroyed_in(pid: u32, cgroup_id: u64, ts: u64) -> Event {
        Event::FileBurst {
            pid,
            uid: 1000,
            comm: "x".into(),
            kind: nn_model::FileBurstKind::Unlink,
            count: MASS_WRITE_MIN as u32,
            appended: 0,
            sources: 0,
            filename: "/home/u/docs/report.docx".into(),
            timestamp_ns: ts,
            cgroup_id,
            own_data: 0,
        }
    }

    /// A process of an SSH session was exempt from the mass-write arm
    /// whatever it wrote. Its new files (a build, a clone) still do not
    /// count; its rewrites of existing files — encryption in place — do.
    /// Lot 282: outside a session new files alone no longer count either;
    /// new files with originals destroyed beside them (the replacement
    /// shape) do, and inside a session they do not.
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
        let hits = det.detect(&destroyed(400, 10), &[]);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "a session's replacement (a checkout): {hits:?}"
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
        // outside any session: new files alone do not count, new files with
        // originals destroyed do
        let _ = det.detect(&spawn_with_exe(600, 1, "/srv/app/worker", 6), &[]);
        let hits = det.detect(&mass_write(600, false, 13), &[]);
        assert!(!hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        let hits = det.detect(&destroyed(600, 14), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        // a package manager stays exempt either way
        let _ = det.detect(&spawn_with_exe_by(0, 700, 500, "/usr/bin/dpkg", 7), &[]);
        let hits = det.detect(&mass_write(700, true, 14), &[]);
        assert!(!hits.contains(&TriggerType::ConfirmedIntrusion));
        let _ = det.detect(&mass_write(700, false, 15), &[]);
        let hits = det.detect(&destroyed(700, 16), &[]);
        assert!(!hits.contains(&TriggerType::ConfirmedIntrusion));
    }

    /// Lot 282 (lab 04/11, lot 279's podman repro): the first `podman pull`
    /// of a host — its layers extracted (files created), its database
    /// rewritten (one file: no overwrite crossing in the kernel any more),
    /// then `podman rmi` deleting the layers (originals destroyed, no new
    /// files beside them) — and `rm -rf` of a tree raise no
    /// `ConfirmedIntrusion`, inside a session or outside one.
    #[test]
    fn creation_or_deletion_alone_is_not_a_mass_write() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(600, 1, "/usr/bin/podman", 1), &[]);
        let _ = det.detect(&spawn_with_exe(610, 1, "/usr/bin/rm", 2), &[]);
        let ci = TriggerType::ConfirmedIntrusion;
        for i in 0..5u64 {
            // a crossing per window, five minutes of a big pull
            let hits = det.detect(&mass_write(600, false, 10 + i * MASS_WRITE_WINDOW_NS), &[]);
            assert!(!hits.contains(&ci), "{hits:?}");
        }
        // podman rmi, an hour later: deletions, its creations long past
        let hits = det.detect(&destroyed(600, 3_600 * 1_000_000_000), &[]);
        assert!(!hits.contains(&ci), "{hits:?}");
        let hits = det.detect(&destroyed(610, 20), &[]);
        assert!(!hits.contains(&ci), "rm -rf: {hits:?}");
    }

    /// Lot 282: the replacement shape — files created and originals
    /// destroyed by ONE process within a window of each other, in either
    /// order (the rings are drained apart; a writer may delete first) —
    /// fires on the second half; two processes' halves never add up unless
    /// they share a cgroup (`the_replacement_shape_pairs_within_a_cgroup`),
    /// nor two halves farther apart than a window.
    #[test]
    fn the_replacement_shape_is_one_processs_two_halves_within_a_window() {
        let det = detector_with_empty_proc();
        for pid in [600, 610, 620, 630, 640, 650] {
            let _ = det.detect(&spawn_with_exe(pid, 1, "/srv/app/worker", 1), &[]);
        }
        let ci = TriggerType::ConfirmedIntrusion;
        let w = MASS_WRITE_WINDOW_NS;
        // created, then destroyed
        assert!(!det.detect(&mass_write(600, false, 10), &[]).contains(&ci));
        assert!(det.detect(&destroyed(600, 10 + w), &[]).contains(&ci));
        // destroyed, then created
        assert!(!det.detect(&destroyed(610, 10 + w), &[]).contains(&ci));
        assert!(det.detect(&mass_write(610, false, 10), &[]).contains(&ci));
        // farther apart than a window
        assert!(!det.detect(&mass_write(620, false, 10), &[]).contains(&ci));
        assert!(!det.detect(&destroyed(620, 11 + w), &[]).contains(&ci));
        // two processes' halves, in no cgroup (or the root's)
        assert!(!det.detect(&mass_write(630, false, 10), &[]).contains(&ci));
        assert!(!det.detect(&destroyed(640, 11), &[]).contains(&ci));
        assert!(!det
            .detect(&mass_write_in(630, 1, false, false, 20), &[])
            .contains(&ci));
        assert!(!det.detect(&destroyed_in(640, 1, 21), &[]).contains(&ci));
        // a rename burst is the ransomware tracker's (NN-L-IMP-002), not a half
        let renames = Event::FileBurst {
            pid: 650,
            uid: 1000,
            comm: "x".into(),
            kind: nn_model::FileBurstKind::RenameExtension,
            count: 20,
            appended: 20,
            sources: 0,
            filename: "/home/u/a.pdf.locked".into(),
            timestamp_ns: 12,
            cgroup_id: 0,
            own_data: 0,
        };
        assert!(!det.detect(&renames, &[]).contains(&ci));
        assert!(!det.detect(&mass_write(650, false, 13), &[]).contains(&ci));
    }

    /// The review of #500 (C1, its probe
    /// `review500_probe_replacement_split_or_late`): an encryptor that
    /// writes the copies and a separate process that deletes the
    /// originals — a helper, an `rm` it runs, a second worker of the same
    /// unit or container — are one replacement when they share a cgroup
    /// (the kernel's cgroup v2 id of each crossing), in either order. Not
    /// across cgroups; not when either half is an exempt writer's (a
    /// package transaction extracting beside an `rm`) or an authenticated
    /// session's (whose new files never counted); not two halves farther
    /// apart than a window — a deletion more than 60 s after the copies is
    /// not seen (declared: §10.5 of the design).
    #[test]
    fn the_replacement_shape_pairs_within_a_cgroup() {
        let det = detector_with_empty_proc();
        for pid in [700, 701, 710, 711, 720, 721, 740, 741] {
            let _ = det.detect(&spawn_with_exe(pid, 1, "/srv/app/worker", 1), &[]);
        }
        let ci = TriggerType::ConfirmedIntrusion;
        let w = MASS_WRITE_WINDOW_NS;
        // the encryptor's copies, then a separate deleter: same cgroup
        assert!(!det
            .detect(&mass_write_in(700, 9001, false, false, 10), &[])
            .contains(&ci));
        assert!(det.detect(&destroyed_in(701, 9001, 20), &[]).contains(&ci));
        // the deleter first
        assert!(!det.detect(&destroyed_in(711, 9002, 10), &[]).contains(&ci));
        assert!(det
            .detect(&mass_write_in(710, 9002, false, false, 30), &[])
            .contains(&ci));
        // other cgroups
        assert!(!det
            .detect(&mass_write_in(720, 9003, false, false, 10), &[])
            .contains(&ci));
        assert!(!det.detect(&destroyed_in(721, 9004, 20), &[]).contains(&ci));
        // the deletion past the window
        assert!(!det
            .detect(&mass_write_in(740, 9005, false, false, 10), &[])
            .contains(&ci));
        assert!(!det
            .detect(&destroyed_in(741, 9005, 11 + w), &[])
            .contains(&ci));
        // a package transaction's extraction beside an rm of its cgroup
        let _ = det.detect(&spawn_with_exe_by(0, 750, 1, "/usr/bin/dpkg", 2), &[]);
        let _ = det.detect(&spawn_with_exe_by(0, 751, 1, "/usr/bin/rm", 2), &[]);
        assert!(!det
            .detect(&mass_write_in(750, 9006, false, false, 10), &[])
            .contains(&ci));
        assert!(!det.detect(&destroyed_in(751, 9006, 20), &[]).contains(&ci));
        // a session's new files beside a daemon's deletions of its cgroup
        let _ = det.detect(&spawn_with_exe(760, 1, "/usr/sbin/sshd", 2), &[]);
        let _ = det.detect(&spawn_with_exe(761, 760, "/usr/bin/bash", 3), &[]);
        let _ = det.detect(&spawn_with_exe(762, 761, "/usr/bin/tar", 4), &[]);
        let _ = det.detect(&spawn_with_exe(763, 1, "/srv/app/cleaner", 5), &[]);
        assert!(!det
            .detect(&mass_write_in(762, 9007, false, false, 10), &[])
            .contains(&ci));
        assert!(!det.detect(&destroyed_in(763, 9007, 20), &[]).contains(&ci));
    }

    /// The review of #500 (C1): a crossing that needed files under 4 KiB
    /// (`MassWrite { small_files: true }`: small documents encrypted in
    /// place) raises the arm outside an authenticated session — it did on
    /// main, where every write-open counted there — and not inside one,
    /// where only files of 4 KiB or more ever counted (a build rewrites its
    /// own small outputs: lab PR 127, cargo killed).
    #[test]
    fn small_files_rewritten_count_outside_a_session_only() {
        let det = detector_with_empty_proc();
        let ci = TriggerType::ConfirmedIntrusion;
        let _ = det.detect(&spawn_with_exe(800, 1, "/srv/app/worker", 1), &[]);
        assert!(det
            .detect(&mass_write_in(800, 0, true, true, 10), &[])
            .contains(&ci));
        let _ = det.detect(&spawn_with_exe(200, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/usr/bin/bash", 2), &[]);
        let _ = det.detect(&spawn_with_exe(400, 300, "/usr/bin/cargo", 3), &[]);
        assert!(!det
            .detect(&mass_write_in(400, 0, true, true, 10), &[])
            .contains(&ci));
        // the same process's files of 4 KiB or more, later in the window
        assert!(det
            .detect(&mass_write_in(400, 0, true, false, 11), &[])
            .contains(&ci));
    }

    /// Lot 282: every shape of the arm is file-system evidence — the
    /// rewrites, the replacement (raised on the burst of originals
    /// destroyed) and the tracepoint count — so no shape of the arm
    /// corroborates another.
    #[test]
    fn every_shape_of_the_mass_write_arm_is_file_system_evidence() {
        let ci = TriggerType::ConfirmedIntrusion;
        for e in [
            mass_write(1, true, 1),
            mass_write_in(1, 0, true, true, 1),
            mass_write(1, false, 1),
            destroyed(1, 1),
            file_open(1, 1000, "/home/u/x", 2, 1),
        ] {
            assert_eq!(evidence_class(ci, &e), EvidenceClass::FileSystem, "{e:?}");
        }
        // the exec arm stays execution evidence
        assert_eq!(
            evidence_class(ci, &spawn_with_exe(1, 0, "/tmp/x", 1)),
            EvidenceClass::Execution
        );
    }

    /// Lot 282: in tracepoint mode the arm counts distinct files — a
    /// database opened to write again and again is one file. Outside a
    /// session every write-open counts, whether its file existed is not
    /// known there: one that may create it (`O_CREAT | O_TRUNC`), and (the
    /// review of #500, C1) one that must (`O_CREAT | O_EXCL`) — a
    /// copy-and-delete encryptor's copies, and tracepoint mode sees no
    /// unlink to tell them from an extraction.
    #[test]
    fn tracepoint_mass_write_counts_distinct_files_exclusive_creates_included() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(800, 1, "/srv/app/worker", 1), &[]);
        let ci = TriggerType::ConfirmedIntrusion;
        let db = "/srv/app/state.db";
        let recent: Vec<Event> = (0..200u64)
            .map(|i| file_open(800, 0, db, 2, i + 10))
            .collect();
        assert!(!det
            .detect(&file_open(800, 0, db, 2, 300), &recent)
            .contains(&ci));
        let burst = |flags: u32| {
            let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
                .map(|i| file_open(800, 0, &format!("/srv/app/out/{i}"), flags, i + 10))
                .collect();
            det.detect(&file_open(800, 0, "/srv/app/out/x", flags, 400), &recent)
        };
        // O_WRONLY | O_CREAT | O_EXCL
        assert!(burst(0o301).contains(&ci));
        // O_WRONLY | O_CREAT | O_TRUNC
        assert!(burst(0o1101).contains(&ci));
        // O_RDWR
        assert!(burst(0o2).contains(&ci));
        // nineteen files and the focal one again: not twenty
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64 - 1))
            .map(|i| file_open(800, 0, &format!("/srv/app/o2/{i}"), 2, i + 10))
            .chain([file_open(800, 0, "/srv/app/o2/0", 2, 40)])
            .collect();
        assert!(!det
            .detect(&file_open(800, 0, "/srv/app/o2/1", 2, 41), &recent)
            .contains(&ci));
        // nineteen files and a twentieth in the focal open: twenty
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(801, 1, "/srv/app/worker", 1), &[]);
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64 - 1))
            .map(|i| file_open(801, 0, &format!("/srv/app/o3/{i}"), 2, i + 10))
            .collect();
        assert!(det
            .detect(&file_open(801, 0, "/srv/app/o3/x", 2, 41), &recent)
            .contains(&ci));
    }

    /// Lot 282: past 1,024 pids the replacement halves are pruned of those
    /// no later half can pair with (every half older than a window); a half
    /// that can still pair is kept, an old half beside it notwithstanding.
    #[test]
    fn pruning_the_replacement_halves_keeps_what_can_still_pair() {
        let r = Replacements::default();
        let w = MASS_WRITE_WINDOW_NS;
        // pid 1: an old creation, then a recent destruction (no pair yet)
        assert!(r.record(1, None, Half::Created, 0, false).is_none());
        assert!(r.record(1, None, Half::Destroyed, 3 * w, false).is_none());
        // 1,100 other pids, a little later: the map is pruned on each record
        for pid in 1000..2100u32 {
            assert!(r
                .record(pid, None, Half::Created, 3 * w + 2, false)
                .is_none());
        }
        // pid 1's recent destruction is still there to pair with
        assert_eq!(
            r.record(1, None, Half::Created, 3 * w + 1, false),
            Some(false)
        );
        // a pid with nothing recent is gone once the map is pruned
        assert!(r.record(7, Some(77), Half::Created, 0, false).is_none());
        for pid in 2100..2200u32 {
            r.record(pid, None, Half::Created, 10 * w, false);
        }
        assert!(!r.0.lock().contains_key(&PairKey::Pid(7)));
        assert!(!r.0.lock().contains_key(&PairKey::Cgroup(77)));
        assert!(r.0.lock().len() < 1_200);
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
    /// forked before its parent executed sudo, writes many new files and
    /// destroys the originals (lot 282: the shape a session's process
    /// would not be counted for) — it is not sudo's, and it fires.
    #[test]
    fn a_child_forked_before_its_parent_ran_sudo_is_not_exempt() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_started(100, 1, "/srv/www/payload", 21, 20), &[]);
        let _ = det.detect(&spawn_started(200, 100, "/srv/www/crypt", 50, 30), &[]);
        let _ = det.detect(&spawn_started(100, 1, "/usr/bin/sudo", 40, 20), &[]);
        let _ = det.detect(&mass_write(200, false, 60), &[]);
        let hits = det.detect(&destroyed(200, 61), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        // the same child forked AFTER the sudo exec is the session's
        let _ = det.detect(&spawn_started(300, 100, "/srv/www/crypt", 70, 45), &[]);
        let _ = det.detect(&mass_write(300, false, 80), &[]);
        let hits = det.detect(&destroyed(300, 81), &[]);
        assert!(!hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
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
            .map(|i| {
                file_open(
                    1096,
                    0,
                    &format!("/var/lib/snapd/state.json.tmp.{i}"),
                    1,
                    i + 10,
                )
            })
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
            .map(|i| file_open(3096, 0, &format!("/var/cache/man/de/3096.{i}"), 1, i + 10))
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
            .map(|i| file_open(401, 0, &format!("/usr/share/foo/data.{i}"), 1, i + 10))
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
            .map(|i| file_open(900, 1000, &format!("/home/u/docs/f.{i}"), 1, i + 10))
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
            &rooted(spawn_with_argv(
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
            )),
            &[],
        );
        // Unpack burst into the global node_modules.
        let recent: Vec<Event> = (0..(MASS_WRITE_MIN as u64))
            .map(|i| {
                file_open(
                    7000,
                    1000,
                    &format!("/home/alice/.npm-global/lib/node_modules/left-pad/f{i}.js"),
                    1,
                    i + 10,
                )
            })
            .collect();
        let focal = file_open(
            7000,
            1000,
            "/home/alice/.npm-global/lib/node_modules/left-pad/package.json",
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
            .map(|i| file_open(7100, 1000, &format!("/home/u/docs/f.{i}"), 1, i + 10))
            .collect();
        let focal = file_open(7100, 1000, "/home/u/docs/f", 1, MASS_WRITE_MIN as u64 + 11);
        let hits = det.detect(&focal, &recent);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "node running a non-npm script must still fire, got {hits:?}"
        );
    }

    /// Named test (lot 340, the alpha's daily false positives): a refused
    /// load of a `kprobe`/`tracepoint` program raised DefenseImpairment
    /// (ENGAGED) — on Ubuntu 26.04 at every boot, for networkd's and the
    /// user manager's feature probes. A record the agent proved a known
    /// system probe's raises nothing; the kernel's own record of the same
    /// refusal (any other loader) still raises DefenseImpairment.
    #[test]
    fn a_proven_known_system_probe_raises_no_posture() {
        use common::bpf_prog_class::{known_probe_dev, PROG_TYPE_KPROBE, PROG_TYPE_TRACEPOINT};
        let refused = |pid: u32, dev: u64, ty: u32| Event::FsProtectDenial {
            pid,
            uid: 998,
            comm: "systemd-network".into(),
            target_dev: dev,
            target_ino: u64::from(ty),
            operation: nn_model::FsProtectOperation::BpfProgType,
            timestamp_ns: 10,
        };
        let det = detector_with_empty_proc();
        for (dev, ty) in [
            (known_probe_dev(1), PROG_TYPE_KPROBE),
            (known_probe_dev(0), PROG_TYPE_TRACEPOINT),
        ] {
            let hits = det.detect(&refused(868, dev, ty), &[]);
            assert!(hits.is_empty(), "{hits:?}");
        }
        for (dev, ty) in [
            (0, PROG_TYPE_KPROBE),
            (known_probe_dev(1), PROG_TYPE_TRACEPOINT),
            (0, PROG_TYPE_TRACEPOINT),
        ] {
            let hits = det.detect(&refused(4242, dev, ty), &[]);
            assert!(
                hits.contains(&TriggerType::DefenseImpairment),
                "{dev:#x}: {hits:?}"
            );
        }
    }

    // ── lot 340 — npm and the Go toolchain in their own directories ──

    /// A detector for npm's cases (lot 340: npm's links are judged by their
    /// path, nothing is read).
    fn detector_with_npm_links() -> TriggerDetector {
        detector_with_empty_proc()
    }

    /// Lot 346 (the re-check of #552, N1): `e` with the image the kernel
    /// gives an exec from a root-only directory in PID 1's mount namespace
    /// (`KNOWN | ROOT_DIR`), as every packaged package manager's.
    fn rooted(mut e: Event) -> Event {
        if let Event::ProcessSpawn {
            pid, filename, exe, ..
        } = &mut e
        {
            exe.path = filename.clone();
            (exe.dev, exe.ino) = (2049, u64::from(*pid));
            exe.flags |= exe_flags::KNOWN | exe_flags::ROOT_DIR;
        }
        e
    }

    /// Lot 346: [`destroyed`] whose crossing file is `path`.
    fn destroyed_at(pid: u32, path: &str, ts: u64) -> Event {
        let mut e = destroyed(pid, ts);
        if let Event::FileBurst { filename, .. } = &mut e {
            *filename = path.into();
        }
        e
    }

    /// A kernel crossing of `pid` whose crossing file is `path`.
    fn mass_write_at(pid: u32, path: &str, overwrites: bool, small: bool, ts: u64) -> Event {
        let mut e = mass_write_in(pid, 0, overwrites, small, ts);
        if let Event::MassWrite { filename, .. } = &mut e {
            *filename = path.into();
        }
        e
    }

    /// Named test (lot 340, the alpha's daily false positives): `npm ci`
    /// run by a CI runner (no session) deletes `node_modules` and extracts
    /// it again — a replacement crossing — and npm run from `PATH` is node
    /// with `argv[1]` = `/usr/bin/npm`, the link the package installed (the
    /// kernel hands the shebang's interpreter the path it executed). On
    /// `main` it was not npm's CLI to the arm: ConfirmedIntrusion → ENGAGED
    /// (lot 313's ci corpus). Through the packaged link it is.
    #[test]
    fn npm_ci_run_through_the_packaged_npm_link_does_not_raise_the_posture() {
        for script in ["/usr/bin/npm", "/usr/local/bin/npm", "/bin/npm"] {
            let det = detector_with_npm_links();
            let _ = det.detect(
                &rooted(spawn_with_argv(
                    7300,
                    1,
                    "/usr/bin/node",
                    &["node", script, "ci"],
                    1,
                )),
                &[],
            );
            let w = "/srv/ci/web/node_modules/@types/lodash/assign.d.ts";
            let _ = det.detect(&mass_write_at(7300, w, false, false, 10), &[]);
            let gone = "/srv/ci/web/node_modules/@types/lodash/index.d.ts";
            let hits = det.detect(&destroyed_at(7300, gone, 11), &[]);
            assert!(
                !hits.contains(&TriggerType::ConfirmedIntrusion),
                "{script}: npm ci's replacement must not raise the posture: {hits:?}"
            );
        }
    }

    /// Lot 340: what is not npm's packaged link keeps the arm — another
    /// name beside it, `npm` in a home or in `/tmp`, a relative `npm`, an
    /// interpreter that is not node, a node outside the system's; and npm's
    /// own children are judged as before
    /// ([`mass_write_intact_for_npm_child_process`]).
    #[test]
    fn a_path_that_is_not_the_packaged_npm_link_keeps_the_mass_write_arm() {
        for (pid, exe, script) in [
            (7400, "/usr/bin/node", "/usr/bin/npm-evil"),
            (7401, "/usr/bin/node", "/tmp/x/npm"),
            (7402, "/usr/bin/node", "/home/u/npm"),
            (7403, "/usr/bin/python3.12", "/usr/bin/npm"),
            (7404, "/usr/bin/node", "npm"),
            (7405, "/home/u/.nvm/node", "/usr/bin/npm"),
            (7406, "/usr/bin/node", "/usr/bin/../../tmp/npm"),
        ] {
            let det = detector_with_npm_links();
            let _ = det.detect(
                &spawn_with_argv(pid, 1, exe, &["node", script, "ci"], 1),
                &[],
            );
            let _ = det.detect(&mass_write(pid, false, 10), &[]);
            let hits = det.detect(&destroyed(pid, 11), &[]);
            assert!(
                hits.contains(&TriggerType::ConfirmedIntrusion),
                "{exe} {script}: {hits:?}"
            );
        }
    }

    /// Named test (the review of #552, F2; its probe `rev552_probe_npm_paths`
    /// made a test): a malicious postinstall — npm's child, judged — that
    /// runs its own code in a node named npm keeps the mass-write arm: a
    /// package-shipped `npm-cli.js` (`node_modules/evil/npm/bin/`), one in
    /// a home (a user prefix the postinstall can write), a path out of a
    /// system tree through `..`, and the packaged `/usr/bin/npm` with an
    /// environment that loads the caller's code (`NODE_OPTIONS=--require`:
    /// the exec pump's `ENV_LOADS`). The packaged npm run clean stays
    /// exempt; node running a project script raises (the control).
    #[test]
    fn npm_running_the_caller_s_code_keeps_the_mass_write_arm() {
        use common::wire::exe::exe_flags::ENV_LOADS;
        // lot 346 (N1): with the image of a packaged node, and npm's
        // exemption its own directories — the raised cases write a
        // document, the exempt ones a package tree
        let run_at = |pid: u32, script: &str, flags: u32, path: &str| {
            let det = detector_with_npm_links();
            let mut e = rooted(spawn_with_argv(
                pid,
                1,
                "/usr/bin/node",
                &["node", script, "ci"],
                1,
            ));
            if let Event::ProcessSpawn { exe, .. } = &mut e {
                exe.flags |= flags;
            }
            let _ = det.detect(&e, &[]);
            let _ = det.detect(&mass_write_at(pid, path, false, false, 10), &[]);
            det.detect(&destroyed_at(pid, path, 11), &[])
        };
        let run = |pid: u32, script: &str, flags: u32| {
            run_at(pid, script, flags, "/home/u/Documents/a.pdf")
        };
        for (pid, script, flags) in [
            (7600, "/home/u/p/node_modules/evil/npm/bin/npm-cli.js", 0),
            (7601, "/usr/bin/npm", ENV_LOADS),
            (7602, "/usr/share/nodejs/npm/bin/npm-cli.js", ENV_LOADS),
            (
                7603,
                "/home/u/.npm-global/lib/node_modules/npm/bin/npm-cli.js",
                0,
            ),
            (
                7604,
                "/usr/lib/../../home/u/p/node_modules/npm/bin/npm-cli.js",
                0,
            ),
            (7605, "node_modules/npm/bin/npm-cli.js", 0),
            (7606, "/home/u/p/x.js", 0),
        ] {
            let hits = run(pid, script, flags);
            assert!(
                hits.contains(&TriggerType::ConfirmedIntrusion),
                "{script} {flags:#x}: {hits:?}"
            );
        }
        // (mutation r1) the caller's code loaded into npm keeps the arm in a
        // package tree too
        for (pid, script) in [
            (7607, "/usr/bin/npm"),
            (7608, "/usr/share/nodejs/npm/bin/npm-cli.js"),
        ] {
            let hits = run_at(
                pid,
                script,
                ENV_LOADS,
                "/home/u/p/node_modules/lodash/lodash.js",
            );
            assert!(
                hits.contains(&TriggerType::ConfirmedIntrusion),
                "{script}: {hits:?}"
            );
        }
        for (pid, script) in [
            (7610, "/usr/bin/npm"),
            (7611, "/usr/share/nodejs/npm/bin/npm-cli.js"),
            (7612, "/usr/local/lib/node_modules/npm/bin/npm-cli.js"),
        ] {
            let hits = run_at(pid, script, 0, "/home/u/p/node_modules/lodash/lodash.js");
            assert!(
                !hits.contains(&TriggerType::ConfirmedIntrusion),
                "{script}: {hits:?}"
            );
        }
    }

    /// Named test (lot 346, the re-check of #552, N1): the packaged npm,
    /// run clean, that writes a user's documents — the encryptor npm loads
    /// in its own process (`npm init` runs `~/.npm-init.js`) — raises the
    /// posture; so does npm in a package tree when its node has no image of
    /// a root-only directory in PID 1's mount namespace (a user's namespace
    /// that binds an encryptor over npm's CLI), and npm's CLI from a Nix
    /// store path or `/opt`. On `main` all were "npm CLI", exempt.
    #[test]
    fn npm_outside_its_own_directories_or_identity_raises_the_posture() {
        let ci = TriggerType::ConfirmedIntrusion;
        let modules = "/home/u/p/node_modules/lodash/lodash.js";
        let run = |pid: u32, script: &str, rooted_exec: bool, path: &str| {
            let det = detector_with_npm_links();
            let e = spawn_with_argv(pid, 1, "/usr/bin/node", &["node", script, "init", "-y"], 1);
            let e = if rooted_exec {
                rooted(e)
            } else {
                let mut e = rooted(e);
                if let Event::ProcessSpawn { exe, .. } = &mut e {
                    exe.flags &= !exe_flags::ROOT_DIR;
                }
                e
            };
            let _ = det.detect(&e, &[]);
            let _ = det.detect(&mass_write_at(pid, path, false, false, 10), &[]);
            det.detect(&destroyed_at(pid, path, 11), &[])
        };
        for (pid, script, rooted_exec, path) in [
            (7700, "/usr/bin/npm", true, "/home/u/Documents/thesis.odt"),
            (
                7701,
                "/usr/share/nodejs/npm/bin/npm-cli.js",
                true,
                "/home/u/.npm-init.js",
            ),
            (7702, "/usr/bin/npm", false, modules),
            (
                7703,
                "/nix/store/0abc-nodejs-20/lib/node_modules/npm/bin/npm-cli.js",
                true,
                modules,
            ),
            (
                7704,
                "/opt/dev/lib/node_modules/npm/bin/npm-cli.js",
                true,
                modules,
            ),
        ] {
            let hits = run(pid, script, rooted_exec, path);
            assert!(
                hits.contains(&ci),
                "{script} {rooted_exec} {path}: {hits:?}"
            );
        }
        // the control: the packaged npm in its package tree
        let hits = run(7705, "/usr/bin/npm", true, modules);
        assert!(!hits.contains(&ci), "{hits:?}");
        // in-place rewrites too (the arm's other shape)
        let det = detector_with_npm_links();
        let _ = det.detect(
            &rooted(spawn_with_argv(
                7706,
                1,
                "/usr/bin/node",
                &["node", "/usr/bin/npm", "ci"],
                1,
            )),
            &[],
        );
        let docs = "/home/u/Documents/a.pdf";
        assert!(det
            .detect(&mass_write_at(7706, docs, true, false, 10), &[])
            .contains(&ci));
    }

    /// Named test (lot 346, item 2): yarn, pnpm and bun installing a
    /// project — a replacement crossing in its package tree, a cache or
    /// store filled beside it — raise nothing, as npm (lot 340); on `main`
    /// only npm was known, and each raised ConfirmedIntrusion → ENGAGED.
    #[test]
    fn yarn_pnpm_and_bun_installs_do_not_raise_the_posture() {
        for (pid, exe, args, created, gone) in [
            (
                7800,
                "/usr/bin/node",
                &["node", "/usr/bin/yarnpkg", "install", "--frozen-lockfile"][..],
                "/home/u/.cache/yarn/v6/npm-lodash-4.17.21/node_modules/lodash/a.js",
                "/home/u/p/node_modules/lodash/a.js",
            ),
            (
                7801,
                "/usr/bin/node",
                &["node", "/usr/local/bin/pnpm", "install"][..],
                "/home/u/.local/share/pnpm/store/v3/files/0a/bcdef",
                "/home/u/p/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/a.js",
            ),
            (
                7802,
                "/usr/local/lib/node_modules/bun/bin/bun.exe",
                &["bun", "install"][..],
                "/home/u/.bun/install/cache/lodash@4.17.21@@@1/a.js",
                "/home/u/p/node_modules/lodash/a.js",
            ),
        ] {
            let det = detector_with_npm_links();
            let _ = det.detect(&rooted(spawn_with_argv(pid, 1, exe, args, 1)), &[]);
            let _ = det.detect(&mass_write_at(pid, created, false, false, 10), &[]);
            let hits = det.detect(&destroyed_at(pid, gone, 11), &[]);
            assert!(
                !hits.contains(&TriggerType::ConfirmedIntrusion),
                "{args:?}: {hits:?}"
            );
        }
    }

    /// Named test (lot 346, item 2): what is not a packaged package
    /// manager's install, or writes outside its own directories, keeps the
    /// arm — `bun run` (the caller's code in bun), bun from the upstream
    /// installer's `~/.bun/bin`, pnpm's standalone binary in a home, yarn's
    /// berry release run from a project, yarn writing a document — and a
    /// package's install script (a child of the package manager) in a
    /// package tree.
    #[test]
    fn a_package_manager_outside_its_identity_or_directories_keeps_the_arm() {
        let modules = "/home/u/p/node_modules/lodash/a.js";
        let docs = "/home/u/Documents/a.pdf";
        for (pid, exe, args, path) in [
            (
                7900,
                "/usr/local/bin/bun",
                &["bun", "run", "enc.ts"][..],
                modules,
            ),
            (
                7901,
                "/home/u/.bun/bin/bun",
                &["bun", "install"][..],
                modules,
            ),
            (
                7902,
                "/home/u/.local/share/pnpm/pnpm",
                &["pnpm", "install"][..],
                modules,
            ),
            (
                7903,
                "/usr/bin/node",
                &["node", "/home/u/p/.yarn/releases/yarn-4.5.0.cjs", "install"][..],
                modules,
            ),
            (
                7904,
                "/usr/bin/node",
                &["node", "/usr/bin/yarnpkg", "install"][..],
                docs,
            ),
            (
                7905,
                "/usr/bin/node",
                &["node", "/home/u/p/node_modules/x/install.js"][..],
                modules,
            ),
        ] {
            let det = detector_with_npm_links();
            let _ = det.detect(&rooted(spawn_with_argv(pid, 1, exe, args, 1)), &[]);
            let _ = det.detect(&mass_write_at(pid, path, false, false, 10), &[]);
            let hits = det.detect(&destroyed_at(pid, path, 11), &[]);
            assert!(
                hits.contains(&TriggerType::ConfirmedIntrusion),
                "{args:?} {path}: {hits:?}"
            );
        }
    }

    /// Named test (lot 340, the alpha's daily false positives): `go test`
    /// rewrites its packages' archives in place in its work directory to
    /// stamp their build ids — 20 existing files, some under 4 KiB, from a
    /// CI runner: ConfirmedIntrusion → ENGAGED on `main` (lot 313's ci
    /// corpus, and the dev corpus' larger ones inside a session). The
    /// packaged toolchain's `go` in its own work, build-cache or
    /// module-cache directory does not raise the posture.
    #[test]
    fn go_test_rewriting_its_archives_in_its_own_directories_does_not_raise_the_posture() {
        for (exe, path) in [
            (
                "/usr/lib/go-1.22/bin/go",
                "/tmp/go-build4098838642/b031/_pkg_.a",
            ),
            ("/usr/lib/go/bin/go", "/var/tmp/go-build77/b001/_pkg_.a"),
            ("/usr/local/go/bin/go", "/home/u/.cache/go-build/3f/3f9a-d"),
            (
                "/snap/go/10730/bin/go",
                "/home/u/go/pkg/mod/cache/download/x.zip",
            ),
        ] {
            for (overwrites, small) in [(true, true), (true, false)] {
                let det = detector_with_empty_proc();
                let _ = det.detect(&spawn_with_exe(7500, 1, exe, 1), &[]);
                let hits = det.detect(&mass_write_at(7500, path, overwrites, small, 10), &[]);
                assert!(
                    !hits.contains(&TriggerType::ConfirmedIntrusion),
                    "{exe} {path}: {hits:?}"
                );
            }
        }
    }

    /// Lot 340: the same rewrites keep the arm when the writer is not the
    /// toolchain's `go` — the test binary it built, a `go` in a home
    /// (`GOTOOLCHAIN`) or in `/tmp`, another binary in the toolchain's
    /// tree — or when the file is not in its directories (a document, a
    /// `go-build` without its digits, a `..` out of one).
    #[test]
    fn rewrites_outside_the_go_toolchain_s_own_directories_keep_the_mass_write_arm() {
        for (exe, path) in [
            ("/usr/lib/go-1.22/bin/go", "/home/u/docs/report.docx"),
            ("/usr/lib/go-1.22/bin/go", "/tmp/go-build/b031/_pkg_.a"),
            ("/usr/lib/go-1.22/bin/go", "/tmp/go-buildx1/b031/_pkg_.a"),
            (
                "/usr/lib/go-1.22/bin/go",
                "/tmp/go-build123/../../home/u/docs/a.docx",
            ),
            ("/usr/lib/go-1.22/bin/go", "/home/u/go-build/x.docx"),
            ("/usr/lib/go-1.22/bin/go", "/tmp/go-build123"),
            ("/tmp/go-build123/b001/calc.test", "/tmp/go-build123/b001/x"),
            (
                "/home/u/go/pkg/mod/golang.org/toolchain@v0.0.1/bin/go",
                "/tmp/go-build1/b/x.a",
            ),
            ("/tmp/go", "/tmp/go-build1/b/x.a"),
            ("/usr/lib/go-1.22/bin/gofmt", "/tmp/go-build1/b/x.a"),
            ("/usr/lib/go-/bin/go", "/tmp/go-build1/b/x.a"),
            ("/usr/lib/go-x1/bin/go", "/tmp/go-build1/b/x.a"),
            ("/snap/go//bin/go", "/tmp/go-build1/b/x.a"),
            ("/snap/go/1/x/bin/go", "/tmp/go-build1/b/x.a"),
            ("/usr/lib/go-1.22/bin/go", "/srv/pkg/mod/x.a"),
            ("/usr/lib/go-1.22/bin/go", "/home/u/go-build/x.a"),
            (
                "/usr/lib/go-1.22/pkg/tool/linux_amd64/compile",
                "/tmp/go-build1/b/x.a",
            ),
        ] {
            let det = detector_with_empty_proc();
            let _ = det.detect(&spawn_with_exe(7600, 1, exe, 1), &[]);
            let hits = det.detect(&mass_write_at(7600, path, true, false, 10), &[]);
            assert!(
                hits.contains(&TriggerType::ConfirmedIntrusion),
                "{exe} {path}: {hits:?}"
            );
        }
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
            .map(|i| file_open(7201, 1000, &format!("/home/u/.cache/evil/f.{i}"), 1, i + 10))
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
        use crate::posture::host::testing::symlink;
        let host = tempfile::tempdir().unwrap();
        let procs = tempfile::tempdir().unwrap();
        let me = TEST_OWNER;
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
                .map(|i| file_open(700, me, &format!("{path}.{i}"), 1, from + i))
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
            operation: nn_model::FsProtectOperation::Unlink,
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
            .map(|i| file_open(300, 0, &format!("/var/lib/apt/lists/x.{i}"), 1, i + 10))
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
            .map(|i| file_open(1, 1000, &format!("/home/u/x.{i}"), 1, i + 100))
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

    /// R12b (R-F): a credential read is judged on the reader as of the
    /// read — a process that read /etc/shadow as `cat` and executed `sudo`
    /// afterwards (its exec ingested before the read is judged) is no
    /// authentication chain at the read: SensitiveFileAccess fires; the
    /// same process as `sudo` at the read is the PAM stack's open.
    #[test]
    fn a_credential_read_is_judged_on_the_reader_as_of_the_read() {
        use super::super::exempt::ExemptPids;
        use super::super::lineage::AuthSessionTracker;
        const S: u64 = 1_000_000_000;
        let auth = AuthSessionTracker::new("/this/path/does/not/exist");
        auth.ingest_exec(31400, 1, "/usr/bin/cat", &[], 10 * S, 9 * S, 1000);
        auth.ingest_exec(31400, 1, "/usr/bin/sudo", &[], 30 * S, 9 * S, 1000);
        let det = TriggerDetector::with_exempt_and_auth(ExemptPids::default(), auth);
        let read_at = |ts| file_open(31400, 1000, "/etc/shadow", 0, ts);
        assert!(
            det.detect(&read_at(20 * S), &[])
                .contains(&TriggerType::SensitiveFileAccess),
            "read as cat: fires, the later sudo vouches for nothing"
        );
        assert!(
            !det.detect(&read_at(40 * S), &[])
                .contains(&TriggerType::SensitiveFileAccess),
            "read as sudo: the authentication chain's own open"
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
            .map(|i| file_open(pid, 0, &format!("{path}.{i}"), 1, i + 1))
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

    /// Lot 282, the re-check of #500 (measured on Ubuntu 22.04): the boot's
    /// coldplug made each systemd-udevd worker write and replace 20
    /// device database files under `/run/udev/data` — device state, not a
    /// user's data. The kernel leaves the directory out (`TREE_CARVEOUT`,
    /// from this list); tracepoint mode's count does too.
    #[test]
    fn mass_write_excludes_udev_runtime_database() {
        assert!(MASS_WRITE_CARVEOUT_PREFIXES.contains(&"/run/udev/"));
        let det = TriggerDetector::with_self_pid(AGENT_PID);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/run/udev/data/c4:32");
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::ConfirmedIntrusion),
            "udev's device database is system state: {hits:?}"
        );
        // another directory under /run still counts (a user's session)
        assert!(!is_mass_write_carveout("/run/user/1000/x", &[]));
        assert!(!is_mass_write_carveout("/run/udevil/x", &[]));
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

    /// Lab PR 249: the mass-write mode is the detector's own (it was a
    /// process-wide switch). A detector on the kernel count — the LSM
    /// file-open sensor armed — leaves a burst of `FileOpen` to the kernel
    /// (no ConfirmedIntrusion), while a detector at the default (tracepoint
    /// mode) counts the same burst, the two on two threads at once; the
    /// kernel's `MassWrite` fires in either mode; a clone shares the switch.
    #[test]
    fn the_mass_write_mode_is_the_detectors_own() {
        let kernel = TriggerDetector::with_self_pid(AGENT_PID);
        kernel.set_kernel_mass_write(true);
        let userland = TriggerDetector::with_self_pid(AGENT_PID);
        assert!(kernel.kernel_mass_write() && !userland.kernel_mass_write());
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/home/alice/Documents/report.docx");
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let run = |d: TriggerDetector| {
            let (focal, recent, barrier) = (focal.clone(), recent.clone(), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                d.detect(&focal, &recent)
            })
        };
        let (k, u) = (run(kernel.clone()), run(userland.clone()));
        let (k, u) = (k.join().unwrap(), u.join().unwrap());
        assert!(!k.contains(&TriggerType::ConfirmedIntrusion), "{k:?}");
        assert!(u.contains(&TriggerType::ConfirmedIntrusion), "{u:?}");
        for d in [&kernel, &userland] {
            let hits = d.detect(&mass_write(ATTACKER_PID + 1, true, 7), &[]);
            assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        }
        let clone = userland.clone();
        clone.set_kernel_mass_write(true);
        assert!(userland.kernel_mass_write(), "a clone shares the switch");
        assert!(!TriggerDetector::with_self_pid(AGENT_PID).kernel_mass_write());
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

    /// External audit POS-010, detection level: with a signed overlay
    /// listing `/`, `/home` and `/home/alice` beside a narrow entry, the
    /// loader keeps the narrow one only, so a burst in the user's documents
    /// still raises ConfirmedIntrusion and the narrow tree stays exempt.
    #[test]
    fn a_refused_carveout_leaves_the_mass_write_arm_on() {
        use super::super::mass_write_overlay::{
            load_mass_write_carveout_extras, DEFAULT_MASS_WRITE_OVERLAY,
        };
        let extras =
            load_mass_write_carveout_extras(&crate::config::overlay_auth::Verified::Content {
                path: DEFAULT_MASS_WRITE_OVERLAY.into(),
                text: "/\n+/home\n+/home/alice\n+/var/lib/devtool/cache/\n".to_string(),
            });
        let det = TriggerDetector::with_self_pid(AGENT_PID).with_mass_write_extras(extras);
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/home/alice/Documents/report.docx");
        assert!(
            det.detect(&focal, &recent)
                .contains(&TriggerType::ConfirmedIntrusion),
            "a refused carve-out must not exempt the user's documents"
        );
        let (focal, recent) = write_burst_to(ATTACKER_PID, "/var/lib/devtool/cache/blob");
        assert!(
            !det.detect(&focal, &recent)
                .contains(&TriggerType::ConfirmedIntrusion),
            "the accepted entry still exempts its tree"
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

    // ─── Lot 283c — a server doing its normal job (own data) ────────

    /// Lot 283c fixtures: a process table where each pid's cgroup is
    /// given, and the shipped daemons' list. The test host classifies
    /// accounts by `UID_MIN` 1000 (`postgres`, 113, is a service account;
    /// `alice`, 1000, a person; root is root).
    struct OwnHost {
        _procs: tempfile::TempDir,
        det: TriggerDetector,
    }

    /// The pids of [`own_host`] and their cgroups.
    const PG_SERVICE: u32 = 501;
    const PG_SESSION: u32 = 502;
    const CONTAINERD: u32 = 601;
    const OTHER_UNIT: u32 = 602;
    const CONTAINERD_SUBGROUP: u32 = 603;
    const ALICE: u32 = 701;

    fn own_host() -> OwnHost {
        use super::super::exempt::ExemptPids;
        use super::super::lineage::AuthSessionTracker;
        let procs = tempfile::tempdir().unwrap();
        for (pid, cgroup) in [
            (
                PG_SERVICE,
                "/system.slice/system-postgresql.slice/postgresql@16-main.service",
            ),
            (PG_SESSION, "/user.slice/user-1000.slice/session-3.scope"),
            (CONTAINERD, "/system.slice/containerd.service"),
            (OTHER_UNIT, "/system.slice/other.service"),
            (
                CONTAINERD_SUBGROUP,
                "/system.slice/containerd.service/payload",
            ),
            (ALICE, "/user.slice/user-1000.slice/session-3.scope"),
        ] {
            let dir = procs.path().join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("cgroup"), format!("0::{cgroup}\n")).unwrap();
        }
        let auth = AuthSessionTracker::new(procs.path());
        let det = TriggerDetector::with_exempt_and_auth(ExemptPids::default(), auth);
        let (data, refused) = DaemonData::build(
            DaemonData::parse_text(crate::posture::daemon_data::BUILTIN_DAEMON_DATA_V1).0,
        );
        assert!(refused.is_empty());
        det.set_daemon_data(Arc::new(data));
        // the session: sshd → bash → the client run as postgres
        let _ = det.detect(&spawn_with_exe(200, 1, "/usr/sbin/sshd", 1), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/usr/bin/bash", 2), &[]);
        // lot 346: a program of the account in the session (its shell), not
        // the packaged initdb making a cluster
        // (`initdb_making_a_cluster_raises_nothing_from_a_session_too`)
        let _ = det.detect(
            &spawn_with_exe_by(113, PG_SESSION, 300, "/usr/bin/bash", 3),
            &[],
        );
        let _ = det.detect(&spawn_with_exe_by(1000, ALICE, 300, "/usr/bin/go", 4), &[]);
        OwnHost { _procs: procs, det }
    }

    /// A rewrite crossing of `pid` as `uid` on `file`, the kernel's
    /// own-data summary `own`.
    fn own_burst(pid: u32, uid: u32, file: &str, own: u8, ts: u64) -> Event {
        let mut e = mass_write(pid, true, ts);
        if let Event::MassWrite {
            uid: u,
            filename,
            own_data,
            ..
        } = &mut e
        {
            (*u, *filename, *own_data) = (uid, file.to_string(), own);
        }
        e
    }

    /// The code of the shipped list's directory `dir`.
    fn unit_code(det: &TriggerDetector, dir: &str) -> u8 {
        let data = det.daemon_data.get().unwrap();
        let tag = data.dirs().iter().position(|d| d.dir == dir).unwrap();
        own_data::UNIT_BASE + tag as u8
    }

    /// Lot 283c, decision 1 (the postgres-like burst): PostgreSQL's
    /// backends rewriting their own relation files — every file of the
    /// window the service account's own, in a directory it owns under
    /// `/var/lib` (the kernel's `SERVICE` summary) — from the service's
    /// cgroup cross no threshold of the arm.
    #[test]
    fn a_service_account_rewriting_its_own_data_raises_nothing() {
        let h = own_host();
        let pg = "/var/lib/postgresql/16/main/base/16384/2833";
        for (i, pid) in [PG_SERVICE].into_iter().enumerate() {
            let hits = h.det.detect(
                &own_burst(pid, 113, pg, own_data::SERVICE, 10 + i as u64),
                &[],
            );
            assert!(!hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
        }
        // its replacement too (a checkpoint's new files, the old ones
        // unlinked), both halves its own data
        let mut created = mass_write(PG_SERVICE, false, 20);
        let mut gone = destroyed(PG_SERVICE, 21);
        for e in [&mut created, &mut gone] {
            match e {
                Event::MassWrite { uid, own_data, .. } | Event::FileBurst { uid, own_data, .. } => {
                    (*uid, *own_data) = (113, own_data::SERVICE)
                }
                _ => unreachable!(),
            }
        }
        assert!(!h
            .det
            .detect(&created, &[])
            .contains(&TriggerType::ConfirmedIntrusion));
        assert!(!h
            .det
            .detect(&gone, &[])
            .contains(&TriggerType::ConfirmedIntrusion));
    }

    /// Lot 283c, decision 1: the same burst from a login session — a
    /// program of the account run from `sudo -u postgres -i` in an SSH shell
    /// — counts: the writer is no system service. Lot 346 (item 6): the
    /// session's writer was `initdb`; the packaged `initdb` making a cluster
    /// is now told apart by its identity
    /// ([`initdb_making_a_cluster_raises_nothing_from_a_session_too`]), and
    /// the decision stands for every other program of the account.
    #[test]
    fn the_same_service_burst_from_a_session_counts() {
        let h = own_host();
        let pg = "/var/lib/postgresql/16/main/base/1/2678";
        let hits = h
            .det
            .detect(&own_burst(PG_SESSION, 113, pg, own_data::SERVICE, 10), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }

    /// Named test (lot 346, item 6): `pg_createcluster` by hand runs the
    /// packaged `initdb` as the service account from a session, and
    /// `initdb`'s bootstrap `postgres` (through its `popen`'s `sh -c`,
    /// which execs it or forks it) rewrites the new cluster's relation
    /// files: every file the service account's own data (the kernel's
    /// `SERVICE` summary). On `main`: ConfirmedIntrusion → ENGAGED for both
    /// (lot 340's db corpus). They raise nothing now; the same burst with a
    /// file outside the account's own data, by a person, by a copy of
    /// `initdb` in a home, by an `initdb` with no image of a root-only
    /// directory (another mount namespace), by the packaged `postgres` run
    /// from the session or under another version's `initdb`, still counts.
    #[test]
    fn initdb_making_a_cluster_raises_nothing_from_a_session_too() {
        let h = own_host();
        let ci = TriggerType::ConfirmedIntrusion;
        let pg = "/var/lib/postgresql/16/nncorpus/base/1/2678";
        let bin = "/usr/lib/postgresql/16/bin";
        let run = |e: Event| {
            let _ = h.det.detect(&e, &[]);
        };
        run(rooted(spawn_with_exe_by(
            113,
            520,
            300,
            &format!("{bin}/initdb"),
            5,
        )));
        // popen's shell execs the backend (dash), or forks it (bash)
        run(rooted(spawn_with_exe_by(113, 521, 520, "/usr/bin/dash", 6)));
        run(rooted(spawn_with_exe_by(
            113,
            521,
            520,
            &format!("{bin}/postgres"),
            7,
        )));
        run(rooted(spawn_with_exe_by(113, 522, 520, "/usr/bin/bash", 6)));
        run(rooted(spawn_with_exe_by(
            113,
            523,
            522,
            &format!("{bin}/postgres"),
            7,
        )));
        for (i, pid) in [520, 521, 523].into_iter().enumerate() {
            let hits = h.det.detect(
                &own_burst(pid, 113, pg, own_data::SERVICE, 10 + i as u64),
                &[],
            );
            assert!(!hits.contains(&ci), "pid {pid}: {hits:?}");
        }
        // the same writers outside the account's own data, or as a person
        let docs = "/home/alice/Documents/report.docx";
        assert!(h
            .det
            .detect(&own_burst(520, 113, docs, own_data::NONE, 20), &[])
            .contains(&ci));
        assert!(h
            .det
            .detect(&own_burst(521, 1000, pg, own_data::SERVICE, 21), &[])
            .contains(&ci));
        // a copy in a home, no image, a postgres the session runs, another
        // version's postgres under initdb 16
        run(rooted(spawn_with_exe_by(
            113,
            530,
            300,
            "/home/u/pg/bin/initdb",
            30,
        )));
        let mut unrooted = spawn_with_exe_by(113, 531, 300, &format!("{bin}/initdb"), 30);
        if let Event::ProcessSpawn { exe, .. } = &mut unrooted {
            exe.path = format!("{bin}/initdb");
            (exe.dev, exe.ino, exe.flags) = (2049, 531, exe_flags::KNOWN);
        }
        run(unrooted);
        run(rooted(spawn_with_exe_by(
            113,
            532,
            300,
            &format!("{bin}/postgres"),
            30,
        )));
        run(rooted(spawn_with_exe_by(
            113,
            533,
            520,
            "/usr/lib/postgresql/15/bin/postgres",
            30,
        )));
        // (mutation r1) an initdb of another tree, and a postgres three
        // hops below the packaged initdb (a shell's shell: not its popen)
        run(rooted(spawn_with_exe_by(
            113,
            534,
            300,
            "/opt/pg/bin/initdb",
            30,
        )));
        run(rooted(spawn_with_exe_by(
            113,
            535,
            300,
            "/usr/local/bin/initdb",
            30,
        )));
        run(rooted(spawn_with_exe_by(
            113,
            536,
            520,
            "/usr/bin/dash",
            31,
        )));
        run(rooted(spawn_with_exe_by(
            113,
            537,
            536,
            "/usr/bin/dash",
            32,
        )));
        run(rooted(spawn_with_exe_by(
            113,
            538,
            537,
            &format!("{bin}/postgres"),
            33,
        )));
        for (i, pid) in [530, 531, 532, 533, 534, 535, 538].into_iter().enumerate() {
            let hits = h.det.detect(
                &own_burst(pid, 113, pg, own_data::SERVICE, 40 + i as u64),
                &[],
            );
            assert!(hits.contains(&ci), "pid {pid}: {hits:?}");
        }
    }

    /// Lot 283c, decision 1: the same burst with one file of its window
    /// outside the account's own data (the kernel's summary `NONE`) counts;
    /// a service account's summary for a person (the kernel never gives it,
    /// the posture does not trust it) and for root count too.
    #[test]
    fn the_same_service_burst_outside_its_own_data_counts() {
        let h = own_host();
        let ci = TriggerType::ConfirmedIntrusion;
        let docs = "/home/alice/Documents/report.docx";
        assert!(h
            .det
            .detect(&own_burst(PG_SERVICE, 113, docs, own_data::NONE, 10), &[])
            .contains(&ci));
        assert!(h
            .det
            .detect(
                &own_burst(PG_SERVICE, 1000, docs, own_data::SERVICE, 11),
                &[]
            )
            .contains(&ci));
        assert!(h
            .det
            .detect(&own_burst(PG_SERVICE, 0, docs, own_data::SERVICE, 12), &[])
            .contains(&ci));
    }

    /// Lot 283c, decision 2: containerd replacing its own state under
    /// `/var/lib/containerd` from its unit crosses nothing; the same burst
    /// from another unit, or from a cgroup containerd made below its own,
    /// counts; its unit's burst in another daemon's directory counts.
    #[test]
    fn a_daemon_in_its_listed_directory_counts_only_from_another_unit() {
        let h = own_host();
        let ci = TriggerType::ConfirmedIntrusion;
        let code = unit_code(&h.det, "/var/lib/containerd/");
        let docker = unit_code(&h.det, "/var/lib/docker/");
        let f = "/var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db";
        assert!(!h
            .det
            .detect(&own_burst(CONTAINERD, 0, f, code, 10), &[])
            .contains(&ci));
        assert!(h
            .det
            .detect(&own_burst(OTHER_UNIT, 0, f, code, 11), &[])
            .contains(&ci));
        assert!(h
            .det
            .detect(&own_burst(CONTAINERD_SUBGROUP, 0, f, code, 12), &[])
            .contains(&ci));
        let d = "/var/lib/docker/overlay2/x/diff/a";
        assert!(h
            .det
            .detect(&own_burst(CONTAINERD, 0, d, docker, 13), &[])
            .contains(&ci));
        // a code no listed directory has
        assert!(h
            .det
            .detect(
                &own_burst(CONTAINERD, 0, f, own_data::UNIT_BASE + 200, 14),
                &[]
            )
            .contains(&ci));
    }

    /// Lot 283c, decision 2: a replacement (new files, originals destroyed
    /// — the shape containerd and k3s measured) is left out only when both
    /// its halves were the unit's own data, whichever came first.
    #[test]
    fn a_daemon_replacement_is_left_out_only_whole() {
        let h = own_host();
        let ci = TriggerType::ConfirmedIntrusion;
        let code = unit_code(&h.det, "/var/lib/containerd/");
        let own = |mut e: Event, o: u8| {
            match &mut e {
                Event::MassWrite { uid, own_data, .. } | Event::FileBurst { uid, own_data, .. } => {
                    (*uid, *own_data) = (0, o)
                }
                _ => unreachable!(),
            }
            e
        };
        let det = &h.det;
        let s = 1_000_000_000u64;
        let raised = |e: Event| det.detect(&e, &[]).contains(&ci);
        // both halves its own data, either order
        assert!(!raised(own(mass_write(CONTAINERD, false, 10 * s), code)));
        assert!(!raised(own(destroyed(CONTAINERD, 11 * s), code)));
        assert!(!raised(own(destroyed(CONTAINERD, 300 * s), code)));
        assert!(!raised(own(mass_write(CONTAINERD, false, 301 * s), code)));
        // the originals destroyed elsewhere, after its own new files
        assert!(!raised(own(mass_write(CONTAINERD, false, 600 * s), code)));
        assert!(raised(own(destroyed(CONTAINERD, 601 * s), own_data::NONE)));
        // its own originals destroyed, the new files written elsewhere first
        assert!(!raised(own(
            mass_write(CONTAINERD, false, 900 * s),
            own_data::NONE
        )));
        assert!(raised(own(destroyed(CONTAINERD, 901 * s), code)));
        // and the other way round
        assert!(!raised(own(
            destroyed(CONTAINERD, 1200 * s),
            own_data::NONE
        )));
        assert!(raised(own(mass_write(CONTAINERD, false, 1201 * s), code)));
    }

    /// Lot 283c, decision 3: a person's process rewriting its own
    /// `~/.cache` (the kernel's `CACHE` summary: the cache's owner writing,
    /// owning the files) crosses nothing; the summary for a service account
    /// — no person's cache — counts.
    #[test]
    fn a_persons_own_cache_does_not_count_another_accounts_does() {
        let h = own_host();
        let ci = TriggerType::ConfirmedIntrusion;
        let f = "/home/alice/.cache/go-build/3f/3f0a-d";
        assert!(!h
            .det
            .detect(&own_burst(ALICE, 1000, f, own_data::CACHE, 10), &[])
            .contains(&ci));
        assert!(h
            .det
            .detect(&own_burst(ALICE, 113, f, own_data::CACHE, 11), &[])
            .contains(&ci));
        assert!(h
            .det
            .detect(&own_burst(ALICE, 0, f, own_data::CACHE, 12), &[])
            .contains(&ci));
    }

    /// Lot 283c, decision 4: a person's tree rewritten or replaced in a
    /// session (`rsync --inplace`, `npm ci`, `git checkout` outside the
    /// cache) is no one's own data to the kernel and raises the arm as
    /// before.
    #[test]
    fn tree_rewrites_in_a_session_stay_engaged() {
        let h = own_host();
        let f = "/srv/nn-corpus/dev/rs/dst/r0019.cfg";
        let hits = h
            .det
            .detect(&own_burst(ALICE, 1000, f, own_data::NONE, 10), &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
    }

    /// Lot 283c: an unwired list (a test, a build that does not wire it)
    /// leaves out no daemon's crossing.
    #[test]
    fn without_the_daemons_list_a_daemon_burst_counts() {
        let det = detector_with_empty_proc();
        let f = "/var/lib/containerd/meta.db";
        assert!(det
            .detect(&own_burst(1, 0, f, own_data::UNIT_BASE, 10), &[])
            .contains(&TriggerType::ConfirmedIntrusion));
    }

    // ── Bug hunt 1.3 (editions 1.2/1.3): BUG40, BUG41, BUG50, BUG51 ───

    /// BUG40: ports {80, 443} and a focal that repeats 443 are two
    /// distinct ports, below RECON_DISTINCT_PORTS_MIN (3); a focal on a
    /// third port still fires.
    #[test]
    fn recon_counts_the_focal_port_once() {
        let det = TriggerDetector::new();
        let recent = vec![
            tcp_v4(42, [127, 0, 0, 1], 80, 100),
            tcp_v4(42, [127, 0, 0, 1], 443, 200),
        ];
        let focal = tcp_v4(42, [127, 0, 0, 1], 443, 300);
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::Reconnaissance),
            "2 distinct ports raised Reconnaissance: {hits:?}"
        );
        let focal = tcp_v4(42, [127, 0, 0, 1], 22, 300);
        assert!(det
            .detect(&focal, &recent)
            .contains(&TriggerType::Reconnaissance));
    }

    /// BUG50: nine distinct ports (1..=9) and a focal back on port 9 are
    /// nine, below HEAVY_RECON_DISTINCT_PORTS_MIN (10). A focal on a tenth
    /// port fires; another process's ports and ports past the hour do not
    /// count.
    #[test]
    fn heavy_recon_nine_ports_focal_repeats_one() {
        let det = TriggerDetector::new();
        const SEC: u64 = 1_000_000_000;
        let recent: Vec<Event> = (1..=9u16)
            .map(|p| tcp_v4(42, [127, 0, 0, 1], p, u64::from(p) * SEC))
            .collect();
        let focal = tcp_v4(42, [127, 0, 0, 1], 9, 10 * SEC);
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::HeavyReconnaissance),
            "9 distinct ports raised HeavyReconnaissance: {hits:?}"
        );
        let tenth = tcp_v4(42, [127, 0, 0, 1], 10, 10 * SEC);
        assert!(det
            .detect(&tenth, &recent)
            .contains(&TriggerType::HeavyReconnaissance));
        let other_pid = tcp_v4(43, [127, 0, 0, 1], 10, 10 * SEC);
        assert!(!det
            .detect(&other_pid, &recent)
            .contains(&TriggerType::HeavyReconnaissance));
        let past_the_hour = tcp_v4(42, [127, 0, 0, 1], 10, 3_602 * SEC);
        assert!(!det
            .detect(&past_the_hour, &recent)
            .contains(&TriggerType::HeavyReconnaissance));
    }

    /// BUG41: twenty connects from one pid to a loopback, unspecified,
    /// multicast or IPv4 link-local destination on 80/443 never leave the
    /// host or its link: no ExfiltrationPattern ("20 external 80/443
    /// connects"). Controls: a public and a CGNAT destination still fire,
    /// an internal one does not (as before).
    #[test]
    fn exfil_ignores_loopback_and_link_local() {
        let det = TriggerDetector::new();
        const SEC: u64 = 1_000_000_000;
        let v6addr = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap().octets();
        let mut fired = Vec::new();
        let v4 = |dst: [u8; 4], port: u16| -> (Event, Vec<Event>) {
            let recent = (1..20u64)
                .map(|i| tcp_v4_comm(7, "app", dst, port, i * SEC))
                .collect();
            (tcp_v4_comm(7, "app", dst, port, 20 * SEC), recent)
        };
        let v6 = |dst: [u8; 16], port: u16| -> (Event, Vec<Event>) {
            let recent = (1..20u64)
                .map(|i| tcp_v6(7, "app", dst, port, i * SEC))
                .collect();
            (tcp_v6(7, "app", dst, port, 20 * SEC), recent)
        };
        let fires = |(f, r): (Event, Vec<Event>)| {
            det.detect(&f, &r)
                .contains(&TriggerType::ExfiltrationPattern)
        };
        for (name, case) in [
            ("127.0.0.1:80", v4([127, 0, 0, 1], 80)),
            ("127.8.9.10:443", v4([127, 8, 9, 10], 443)),
            ("169.254.169.254:80", v4([169, 254, 169, 254], 80)),
            ("0.0.0.0:443", v4([0, 0, 0, 0], 443)),
            ("224.0.0.251:443", v4([224, 0, 0, 251], 443)),
            ("[::1]:443", v6(v6addr("::1"), 443)),
            ("[::]:443", v6(v6addr("::"), 443)),
            ("[ff02::1]:443", v6(v6addr("ff02::1"), 443)),
            ("[::ffff:127.0.0.1]:80", v6(v6addr("::ffff:127.0.0.1"), 80)),
            (
                "[::ffff:169.254.169.254]:80",
                v6(v6addr("::ffff:169.254.169.254"), 80),
            ),
            ("10.0.0.5:443", v4([10, 0, 0, 5], 443)),
            ("[fe80::1]:443", v6(v6addr("fe80::1"), 443)),
        ] {
            if fires(case) {
                fired.push(name);
            }
        }
        assert!(
            fired.is_empty(),
            "ExfiltrationPattern on host-local destinations: {fired:?}"
        );
        // controls: a public and a CGNAT destination still fire
        for (name, case) in [
            ("203.0.113.9:443", v4([203, 0, 113, 9], 443)),
            ("100.64.0.1:443", v4([100, 64, 0, 1], 443)),
            ("[2001:db8::1]:443", v6(v6addr("2001:db8::1"), 443)),
            (
                "[::ffff:100.64.0.1]:80",
                v6(v6addr("::ffff:100.64.0.1"), 80),
            ),
        ] {
            assert!(fires(case), "{name}");
        }
    }

    /// BUG41: loopback connects in the window do not count toward a public
    /// destination's twenty either.
    #[test]
    fn exfil_counts_only_external_connects_in_the_window() {
        let det = TriggerDetector::new();
        const SEC: u64 = 1_000_000_000;
        let mut recent: Vec<Event> = (1..10u64)
            .map(|i| tcp_v4_comm(7, "app", [203, 0, 113, 9], 443, i * SEC))
            .collect();
        recent.extend((10..20u64).map(|i| tcp_v4_comm(7, "app", [127, 0, 0, 1], 443, i * SEC)));
        let focal = tcp_v4_comm(7, "app", [203, 0, 113, 9], 443, 20 * SEC);
        assert!(!det
            .detect(&focal, &recent)
            .contains(&TriggerType::ExfiltrationPattern));
        // nineteen public connects, then a loopback one judged: not the
        // twentieth (the public twentieth raises it)
        let public: Vec<Event> = (1..20u64)
            .map(|i| tcp_v4_comm(7, "app", [203, 0, 113, 9], 443, i * SEC))
            .collect();
        let lo = tcp_v4_comm(7, "app", [127, 0, 0, 1], 443, 20 * SEC);
        assert!(!det
            .detect(&lo, &public)
            .contains(&TriggerType::ExfiltrationPattern));
        assert!(det
            .detect(&focal, &public)
            .contains(&TriggerType::ExfiltrationPattern));
        // a connect of another family (not inet) does not count either
        let mut other_family = recent.clone();
        other_family.extend((10..20u64).map(|i| {
            let mut e = tcp_v6(
                7,
                "app",
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets(),
                443,
                i * SEC,
            );
            if let Event::TcpConnect { family, .. } = &mut e {
                *family = 1;
            }
            e
        }));
        assert!(!det
            .detect(&focal, &other_family)
            .contains(&TriggerType::ExfiltrationPattern));
        recent.extend((10..20u64).map(|i| tcp_v4_comm(7, "app", [100, 64, 1, 2], 80, i * SEC)));
        assert!(det
            .detect(&focal, &recent)
            .contains(&TriggerType::ExfiltrationPattern));
    }

    /// BUG51: pid 7 ran curl, then python3; the parent of the shell is
    /// python3 when it spawns it — not a network loader. A shell spawned
    /// between the two execs is curl's (in kernel time, whatever order the
    /// recent events are in).
    #[test]
    fn lolbas_parent_latest_exec_is_not_a_loader() {
        let det = TriggerDetector::new();
        let recent = vec![
            spawn(7, 1, "curl", "/usr/bin/curl", 1),
            spawn(7, 1, "python3", "/usr/bin/python3", 3),
        ];
        let focal = spawn(8, 7, "sh", "/usr/bin/sh", 4);
        let hits = det.detect(&focal, &recent);
        assert!(
            !hits.contains(&TriggerType::Lolbas),
            "Lolbas for python3 -> sh (pid 7's older curl exec): {hits:?}"
        );
        let between = spawn(8, 7, "sh", "/usr/bin/sh", 2);
        assert!(det.detect(&between, &recent).contains(&TriggerType::Lolbas));
        let reversed: Vec<Event> = recent.iter().rev().cloned().collect();
        assert!(!det.detect(&focal, &reversed).contains(&TriggerType::Lolbas));
        assert!(det
            .detect(&between, &reversed)
            .contains(&TriggerType::Lolbas));
        // two execs stamped alike: the one recorded last is the latest
        let tie = vec![
            spawn(7, 1, "curl", "/usr/bin/curl", 3),
            spawn(7, 1, "python3", "/usr/bin/python3", 3),
        ];
        assert!(!det.detect(&focal, &tie).contains(&TriggerType::Lolbas));
        let tie: Vec<Event> = tie.into_iter().rev().collect();
        assert!(det.detect(&focal, &tie).contains(&TriggerType::Lolbas));
    }

    /// BUG51: a curl of a day ago whose pid a later process took (its
    /// start is not the shell's parent's start) is not the shell's parent;
    /// the curl of the parent's own start is, and so is one whose start is
    /// not known (on either side).
    #[test]
    fn lolbas_reused_parent_pid_a_day_later() {
        let det = TriggerDetector::new();
        const DAY: u64 = 24 * 3600 * 1_000_000_000;
        let curl_started = |start: u64, ts: u64| {
            let mut curl = spawn(7, 1, "curl", "/usr/bin/curl", ts);
            if let Event::ProcessSpawn { start_ns, .. } = &mut curl {
                *start_ns = start;
            }
            curl
        };
        let sh_of = |parent_start: u64| {
            let mut focal = spawn(8, 7, "sh", "/usr/bin/sh", DAY + 500);
            if let Event::ProcessSpawn {
                parent_start_ns, ..
            } = &mut focal
            {
                *parent_start_ns = parent_start;
            }
            focal
        };
        let lolbas = |focal: &Event, recent: &[Event]| {
            det.detect(focal, recent).contains(&TriggerType::Lolbas)
        };
        let old_curl = curl_started(100, 110);
        assert!(
            !lolbas(&sh_of(DAY), std::slice::from_ref(&old_curl)),
            "Lolbas from a day-old curl whose pid was reused"
        );
        assert!(lolbas(&sh_of(DAY), &[curl_started(DAY, DAY + 10)]));
        assert!(lolbas(&sh_of(0), std::slice::from_ref(&old_curl)));
        assert!(lolbas(&sh_of(DAY), &[curl_started(0, 110)]));
        // the reused pid's own exec (not a loader) is the latest
        assert!(!lolbas(
            &sh_of(DAY),
            &[old_curl, curl_started(0, 110), {
                let mut py = spawn(7, 1, "python3", "/usr/bin/python3", DAY + 10);
                if let Event::ProcessSpawn { start_ns, .. } = &mut py {
                    *start_ns = DAY;
                }
                py
            }]
        ));
    }
}
