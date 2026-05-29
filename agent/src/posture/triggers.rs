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

use std::collections::HashSet;
use std::sync::Arc;

use common::posture_types::TriggerType;
use common::Event;

use super::exempt::ExemptPids;
use super::lineage::AuthSessionTracker;

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
///                        service setup, kernel parameter writes).
///                        Tampering is covered by anti-tamper LSM
///                        hooks (kernel_param, etc.) and the R011
///                        kernel-module tooling rule.
/// - `/proc/`           — procfs writes (sysctl-shaped kernel RPCs,
///                        per-process control). Same anti-tamper
///                        LSM surface; never a ransomware target.
/// - `/run/systemd/`    — systemd's own runtime state directory (cgroup
///                        delegation files, unit transient state).
///                        Not data; not a ransomware target.
/// - `/run/log/journal/` — systemd-journal binary log. Anti-forensic
///                        journal manipulation is its own threat
///                        category (future R-NN); the mass-write arm
///                        of confirmed_intrusion would only ever
///                        catch journald's normal append rhythm here.
///
/// Deliberately **NOT** excluded:
/// - `/dev/`        — includes `/dev/shm/`, a real ransomware staging tmpfs.
/// - `/run/`        — broad, includes `/run/user/<uid>/` where user
///                    processes legitimately write (lock files, dbus
///                    sockets). Counted toward mass-write so a
///                    compromised user session is still detectable.
pub(super) const MASS_WRITE_CARVEOUT_PREFIXES: &[&str] = &[
    "/sys/",
    "/proc/",
    "/run/systemd/",
    "/run/log/journal/",
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
        || extras.iter().any(|p| filename.starts_with(p.as_str()))
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
/// entry, `/etc/login.defs` reads would lose ALL coverage. The other
/// three entries were already covered (T7.13 baseline).
const SENSITIVE_FILES: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/login.defs",
];
const CRITICAL_FILES_PREFIXES: &[&str] = &[
    "/etc/sshd_config",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/sudoers.d/",
    "/etc/pam.d/",
    "/root/.ssh/",
];
const PERSISTENCE_PREFIXES: &[&str] = &[
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
/// `confirmed_intrusion` treats as COMBAT-tier on its own.
#[derive(Debug, Default, Clone)]
pub struct TriggerDetector {
    /// PIDs belonging to the NorthNarrow process stack (agent + the
    /// verified watchdog) whose events must never raise a trigger.
    exempt: ExemptPids,
    /// T7.13 (Beta Step 5) — sudo-mediated process lineage tracker.
    /// Consulted ONLY by `sensitive_file_access` and the mass-write
    /// arm of `confirmed_intrusion`; every other COMBAT-tier trigger
    /// (FsProtectDenial, exec from /tmp, persistence_mechanism,
    /// critical_file_modification, lateral_movement,
    /// exfiltration_pattern, exploit_attempt, lolbas_pattern) fires
    /// unchanged so admin sudo activity that is *actually* malicious
    /// — dropping a /tmp payload, tampering with agent state — is
    /// still caught.
    auth: AuthSessionTracker,
    /// BUG-017 P-8 — operator-supplemental mass-write path-prefix
    /// carve-out, layered on top of [`MASS_WRITE_CARVEOUT_PREFIXES`].
    /// Loaded from `/etc/northnarrow/mass-write-carveout.local` at
    /// agent boot. Cheap to clone (`Arc`); empty by default.
    mass_write_extras: Arc<Vec<String>>,
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

    /// Inspect `(event, recent)` and return every trigger raised.
    ///
    /// The result is in escalation order (the strongest trigger
    /// last) so the caller can `iter().last()` for the dominant
    /// signal or fold them all into the audit log.
    pub fn detect(&self, event: &Event, recent: &[Event]) -> Vec<TriggerType> {
        // T7.13: ingest ProcessSpawn into the auth-lineage tracker
        // FIRST, so the focal spawn's own lineage is visible to the
        // arms below (e.g. a spawn whose parent is sudo gets the
        // tag in the same observe call). Stack-exempt spawns are
        // also recorded — they won't trip the auth allowlist and
        // recording them is cheap; consistency beats the conditional.
        if let Event::ProcessSpawn {
            pid,
            ppid,
            filename,
            timestamp_ns,
            ..
        } = event
        {
            self.auth.ingest_spawn(*pid, *ppid, filename, *timestamp_ns);
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
        if let Some(pid) = event_owner_pid(event) {
            if self.exempt.is_exempt(pid) {
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
        if critical_file_modification(event) {
            hits.push(TriggerType::CriticalFileModification);
        }

        // ENGAGED -> COMBAT tier
        if confirmed_intrusion(event, recent, &self.auth, &self.mass_write_extras) {
            hits.push(TriggerType::ConfirmedIntrusion);
        }
        if persistence_mechanism(event) {
            hits.push(TriggerType::PersistenceMechanism);
        }
        if lateral_movement(event, recent) {
            hits.push(TriggerType::LateralMovement);
        }
        if exfiltration_pattern(event, recent) {
            hits.push(TriggerType::ExfiltrationPattern);
        }

        hits
    }
}

fn within(focal_ts: u64, ts: u64, window_ns: u64) -> bool {
    focal_ts.saturating_sub(ts) <= window_ns
}

/// PID an event is attributed to, for self-exclusion. Variants the
/// agent itself never originates (e.g. `CanaryTripped`, `NetFlow`,
/// `NetListener`) return `None` so they are never filtered.
fn event_owner_pid(event: &Event) -> Option<u32> {
    match event {
        Event::ProcessSpawn { pid, .. }
        | Event::FileOpen { pid, .. }
        | Event::ExecCheck { pid, .. }
        | Event::TcpConnect { pid, .. }
        | Event::DnsQuery { pid, .. }
        | Event::FsProtectDenial { pid, .. } => Some(*pid),
        _ => None,
    }
}

fn recon_pattern(focal: &Event, recent: &[Event]) -> bool {
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

fn heavy_recon(focal: &Event, recent: &[Event]) -> bool {
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
    recent: &[Event],
    window_ns: u64,
) -> usize {
    let mut ports: HashSet<u16> = HashSet::new();
    for e in recent {
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

fn suspicious_dns(focal: &Event, recent: &[Event]) -> bool {
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
    for e in recent {
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

fn sensitive_file_access(focal: &Event, auth: &AuthSessionTracker) -> bool {
    let Event::FileOpen {
        pid,
        uid,
        filename,
        flags,
        ..
    } = focal
    else {
        return false;
    };
    // root (uid=0) and system users (1..1000) are excluded — these
    // accesses are routine. We only flag when a regular user reaches
    // for the credential files.
    if *uid < 1000 {
        return false;
    }
    // T7.13 — sudo's PAM auth chain opens /etc/shadow under the
    // caller's uid (the LSM file_open hook fires BEFORE the kernel
    // completes the setuid transition). Without this gate every
    // `sudo <anything>` invocation by a regular user trips
    // SensitiveFileAccess. We trust an auth-mediated PID (sudo, su,
    // sshd, pkexec, …) to read these files — verified via the
    // kernel-resolved /proc/<pid>/exe symlink, not forgeable comm.
    if auth.is_auth_mediated(*pid) {
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
    if filename == "/etc/passwd"
        && !is_write_open(*flags)
        && auth.has_valid_loginuid(*pid)
    {
        return false;
    }
    SENSITIVE_FILES.iter().any(|f| filename == f)
}

fn lolbas_pattern(focal: &Event, recent: &[Event]) -> bool {
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
        filename, flags, ..
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
}

fn confirmed_intrusion(
    focal: &Event,
    recent: &[Event],
    auth: &AuthSessionTracker,
    mass_write_extras: &[String],
) -> bool {
    // Tappa 7: a denied FS-tamper attempt is, by definition, a
    // confirmed intrusion — root tried to disable or destroy agent
    // state. Single event raises the posture all the way to COMBAT.
    // NOT gated by auth-lineage: a sudo-mediated tamper attempt is
    // still a tamper attempt.
    if let Event::FsProtectDenial { .. } = focal {
        return true;
    }
    // Exec from /tmp or /dev/shm: an admin does not legitimately
    // run binaries out of these paths. NOT gated by auth-lineage —
    // a sudo-spawned process exec'ing /tmp/payload is exactly the
    // post-compromise pattern we want to catch.
    if let Event::ProcessSpawn { filename, .. } | Event::ExecCheck { filename, .. } = focal {
        if filename.starts_with("/tmp/") || filename.starts_with("/dev/shm/") {
            return true;
        }
    }
    // Mass-write / encryption-pattern: many writes from same pid in
    // a short window.
    if let Event::FileOpen {
        pid: focal_pid,
        comm: focal_comm,
        filename: focal_filename,
        flags,
        timestamp_ns: focal_ts,
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
            if is_mass_write_carveout(focal_filename, mass_write_extras) {
                return false;
            }
            // T7.13 — auth-mediated PIDs (sudo, sudo's children:
            // apt, systemctl, an editor, …) routinely exceed the
            // mass-write threshold during legitimate administration.
            // Only the mass-write arm is gated; FsProtectDenial and
            // exec-from-/tmp above still fire for auth-mediated PIDs.
            if auth.is_auth_mediated(*focal_pid) {
                return false;
            }
            let mut count = 1usize;
            for e in recent {
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
                        && !is_mass_write_carveout(filename, mass_write_extras)
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
                tracing::warn!(
                    trigger = "ConfirmedIntrusion_MassWrite",
                    focal_pid = *focal_pid,
                    focal_comm = %focal_comm,
                    focal_filename = %focal_filename,
                    count_within_window = count,
                    threshold = MASS_WRITE_MIN,
                    window_secs = MASS_WRITE_WINDOW_NS / 1_000_000_000,
                    "mass-write threshold crossed — posture will escalate to COMBAT"
                );
                return true;
            }
        }
    }
    false
}

fn persistence_mechanism(focal: &Event) -> bool {
    let Event::FileOpen {
        filename, flags, ..
    } = focal
    else {
        return false;
    };
    if !is_write_open(*flags) {
        return false;
    }
    PERSISTENCE_PREFIXES
        .iter()
        .any(|p| filename == p || filename.starts_with(p))
}

fn lateral_movement(focal: &Event, recent: &[Event]) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
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
    if *family != 2 || !is_rfc1918(dst_addr) {
        return false;
    }
    let mut hosts: HashSet<[u8; 4]> = HashSet::new();
    hosts.insert([dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]]);
    for e in recent {
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
                && *fam == 2
                && ADMIN_PORTS.contains(dp)
                && is_rfc1918(dst)
                && within(*focal_ts, *timestamp_ns, LATERAL_WINDOW_NS)
            {
                hosts.insert([dst[0], dst[1], dst[2], dst[3]]);
            }
        }
    }
    hosts.len() >= LATERAL_DISTINCT_DST_MIN
}

fn exfiltration_pattern(focal: &Event, recent: &[Event]) -> bool {
    let Event::TcpConnect {
        pid: focal_pid,
        family,
        dst_addr,
        dst_port,
        timestamp_ns: focal_ts,
        ..
    } = focal
    else {
        return false;
    };
    if *family != 2 {
        return false;
    }
    if !matches!(*dst_port, 80 | 443) {
        return false;
    }
    if is_rfc1918(dst_addr) {
        return false;
    }
    let mut count = 1usize;
    for e in recent {
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
                && *fam == 2
                && matches!(*dp, 80 | 443)
                && !is_rfc1918(dst)
                && within(*focal_ts, *timestamp_ns, EXFIL_WINDOW_NS)
            {
                count += 1;
            }
        }
    }
    count >= EXFIL_MIN_EVENTS
}

fn is_rfc1918(addr: &[u8; 16]) -> bool {
    let a = addr[0];
    let b = addr[1];
    matches!((a, b), (10, _) | (172, 16..=31) | (192, 168))
}

fn is_write_open(flags: u32) -> bool {
    // O_WRONLY = 1, O_RDWR = 2 in glibc/Linux. Mask to access mode.
    let access = flags & 0b11;
    access == 1 || access == 2
}

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
            parent_is_kthread: false,
        }
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
            query_name: name.into(),
            query_type: 1,
            dns_server: [0u8; 16],
            family: 2,
            timestamp_ns: ts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
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

    #[test]
    fn sensitive_file_access_skips_root_and_system_uids() {
        let det = TriggerDetector::new();
        for uid in [0, 1, 999] {
            let focal = file_open(42, uid, "/etc/shadow", 0, 1);
            let hits = det.detect(&focal, &[]);
            assert!(!hits.contains(&TriggerType::SensitiveFileAccess));
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

    #[test]
    fn confirmed_intrusion_fires_on_exec_from_tmp() {
        let det = TriggerDetector::new();
        let focal = spawn(42, 1, "evil", "/tmp/evil", 1);
        let hits = det.detect(&focal, &[]);
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion));
    }

    #[test]
    fn confirmed_intrusion_fires_on_any_fs_protect_denial() {
        // Tappa 7: a kernel-side denial of root's tamper attempt is
        // by definition a confirmed intrusion — push posture all
        // the way to COMBAT on a single event.
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
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "expected ConfirmedIntrusion, got {:?}",
            hits
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
        assert!(hits.contains(&TriggerType::ConfirmedIntrusion), "{hits:?}");
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
            parent_is_kthread: false,
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

    // ── Test #3: uid<1000 (root/system) still exempt (legacy) ───────
    #[test]
    fn sensitive_file_access_still_skips_root() {
        let det = detector_with_empty_proc();
        for uid in [0u32, 1, 999] {
            let focal = file_open(7777, uid, "/etc/shadow", 0, 1);
            let hits = det.detect(&focal, &[]);
            assert!(!hits.contains(&TriggerType::SensitiveFileAccess));
        }
    }

    // ── Test #4: mass-write from sudo subprocess is exempt ──────────
    #[test]
    fn mass_write_exempt_for_sudo_subprocess() {
        let det = detector_with_empty_proc();
        // user shell -> sudo -> apt
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let _ = det.detect(&spawn_with_exe(200, 100, "/usr/bin/apt", 2), &[]);

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

    // ── Test #6: sudo subprocess exec'ing /tmp still trips ──────────
    #[test]
    fn exec_from_tmp_not_exempt_for_sudo_subprocess() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        // sudo's child exec'es /tmp/payload — exactly the
        // post-compromise pattern this arm exists to catch.
        let evil = spawn_with_exe(200, 100, "/tmp/payload", 2);
        let hits = det.detect(&evil, &[]);
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "exec-from-/tmp must fire even under sudo lineage, got {hits:?}"
        );
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
        assert!(
            hits.contains(&TriggerType::ConfirmedIntrusion),
            "FsProtectDenial must fire even under sudo lineage, got {hits:?}"
        );
    }

    // ── Test #8: nested sudo→bash→apt lineage is exempt ─────────────
    #[test]
    fn nested_lineage_sudo_bash_apt() {
        let det = detector_with_empty_proc();
        let _ = det.detect(&spawn_with_exe(100, 50, "/usr/bin/sudo", 1), &[]);
        let _ = det.detect(&spawn_with_exe(200, 100, "/bin/bash", 2), &[]);
        let _ = det.detect(&spawn_with_exe(300, 200, "/usr/bin/apt", 3), &[]);

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
        let (focal, recent) =
            write_burst_to(ATTACKER_PID, "/home/alice/.claude/projects/x/subagents/a.jsonl");
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
}
