//! Self-integrity check (Tappa 10.8, adversarial anti-tamper findings).
//!
//! The kernel hooks stop root from killing, tracing or rewriting the agent;
//! they do not stop root from changing what systemd and the kernel will do
//! to it next. `deploy/lab/adversarial/anti-tamper.sh` found these allowed
//! and silent: a drop-in that overrides `ExecStart=`/`Environment=`,
//! `systemctl set-property` (MemoryMax, TasksMax, CPUQuota — the OOM and
//! starvation route), `oom_score_adj` raised to make the agent the OOM
//! killer's first victim, a bind mount over `/etc/northnarrow` or the
//! binaries, a second bpffs. None of them can be denied without breaking
//! systemd, so the agent proves it instead: every [`BASE_SECS`] (±20 %
//! jitter, so a change cannot be timed between two checks) it compares
//! these against what it saw at boot and against what the install laid
//! down, and every new finding is an ERROR in the journal and a signed
//! audit entry (`integrity_drift`, `kind` + `detail`).
//! Weakening environment variables are reported once at boot. An admin
//! private key left on the host (external audit DEP-001) is reported the
//! same way: it is a credential for whoever is root here.
//!
//! External audit NN-AUD-114: what a round recomputes (drop-ins, shadows,
//! overlays, mounts, admin keys, limits) is a set of active findings, not
//! a "seen once, silent forever" set. A finding that goes away is recorded
//! (`integrity_drift_cleared`, signed); one that comes back is reported
//! again, at most once per [`REREPORT_SECS`] with the number of times it
//! came back in between. Each kind is capped at [`MAX_PER_KIND`] findings
//! per round. External audit NN-AUD-113: the boot round compares the
//! limits with what the units set, and a limit that appears or vanishes
//! after the baseline is drift too.
//!
//! Lab PR 180 (external audit EVD-011, EVD-014): drop-ins are read from
//! the whole unit search path ([`UNIT_SEARCH_PATH`], one list with the
//! unit copies); a round that cannot read the host's mounts reads the
//! agent's own namespace, and one that can read neither says so
//! (`mountinfo_unreadable`); a mount laid after the start over a directory
//! above the agent's paths is reported like one on the paths themselves
//! ([`mount_round`]).
//!
//! Lab PR 184 (external audit DEP-005): where the unit's memory cap is at
//! or above the host's memory, the agent raises its own `oom_score_adj` to
//! 0 at boot ([`relax_oom_score_adj`]), and the limits round expects 0 there.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tracing::{error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

pub const BASE_SECS: u64 = 30;
pub const AUDIT_OP: &str = "integrity_drift";

/// Units whose drop-ins, copies and masks are checked. Lab PR 216: the
/// watchdog's `OnFailure=` handler too — masked or overridden, systemd's
/// giving up on the watchdog would leave no record.
pub const UNITS: [&str; 3] = [
    "northnarrow-agent.service",
    "northnarrow-watchdog.service",
    "northnarrow-watchdog-failed.service",
];

/// systemd's system unit load path, highest precedence first
/// (`systemd.unit(5)`, "Unit File Load Path"). A unit file in an earlier
/// directory replaces one with the same name in a later directory — the
/// runtime ones (`/run/systemd/transient`, `system.control`, the
/// generator outputs) outrank even `/etc/systemd/system`. systemd reads a
/// unit's `.d/` drop-ins from every one of them, so this one list is where
/// both the copies ([`unit_shadows`]) and the drop-ins ([`unit_dropins`])
/// are looked for. External audit EVD-011 (NN-AUD-276, lab PR 180): the
/// drop-ins were looked for in eight of these thirteen; a drop-in under
/// `/etc/systemd/system.attached` or `/run/systemd/system.attached` (the
/// portable-service directories) changed the agent's unit unseen. The
/// generator directories are rewritten at every `daemon-reload`, but a
/// drop-in a generator writes there is as effective as any.
const UNIT_SEARCH_PATH: &[&str] = &[
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
];

/// Drop-ins `install.sh` lays down itself, with the content it writes.
/// External audit DEP-002: matched on content, not on path alone — the
/// path used to be skipped whatever the file said.
const KNOWN_DROPINS: &[(&str, &str)] = &[
    (
        "/etc/systemd/system/northnarrow-agent.service.d/10-debian-perf-paranoid.conf",
        include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/deploy/systemd/10-debian-perf-paranoid.conf"
        )),
    ),
    // Lab PR 222: `install.sh --cow-guard` (the guard's fanotify group).
    (
        "/etc/systemd/system/northnarrow-agent.service.d/20-cow-guard.conf",
        include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/deploy/systemd/20-cow-guard.conf"
        )),
    ),
];

/// Environment variables that switch a protection off, into observe mode,
/// or cut the evidence the agent keeps. Each comes with the test its
/// consumer applies (external audit MAIN-008: a narrower test here let a
/// value the consumer honours pass unreported).
pub const WEAKENING_ENV: &[(&str, WeakensWith)] = &[
    ("NN_ANTI_TAMPER_ALLOW_DEGRADED", any_value),
    ("NN_BPF_DEFENSE_OBSERVE", is_one),
    ("NN_ALLOW_UNVERIFIED_BINARY", is_one),
    ("NN_AUDIT_ALLOW_UNWRITABLE", any_value),
    (
        crate::telemetry_probe::INTERVAL_ENV,
        crate::telemetry_probe::interval_weakens,
    ),
    ("NN_DETECT_ONLY", crate::response::config::is_truthy),
    ("NORTHNARROW_DRY_RUN", crate::response::config::is_truthy),
    ("NN_OVERLAY_ALLOW_UNSIGNED", is_one),
    // NN_ADE_ALLOW_MOCK and NN_ADE_ENFORCE (the LLM advisor's mock backend
    // and its licence to act) left with the advisor in Wave 4, lab PR 214:
    // nothing reads them, the agent names them in a WARN at start
    // (`crate::removed_settings`).
    // External audit MAIN-004: the evidence logs' rotation caps; any
    // override changes how much evidence survives.
    (crate::chainlog::FIM_DRIFT_CAP_ENV, any_value),
    (crate::chainlog::DETECTIONS_CAP_ENV, any_value),
    (crate::chainlog::STATUS_EVENTS_CAP_ENV, any_value),
    // External audit PROC-015 (NN-AUD-302): a demo-tappa5 build enforces
    // its demo rules R901..R904 under this variable (in any other build
    // nothing reads it, so it is not reported there).
    (
        crate::decision::engine::ALLOW_DEMO_RULES_ENV,
        crate::decision::engine::allow_demo_rules_weakens,
    ),
    // Lab PR 219: `off` leaves the exploit post-condition guard unattached
    // (`detect` and `enforce` do not weaken).
    (
        crate::sensors::epg::MODE_ENV,
        crate::sensors::epg::turns_off,
    ),
    // Lab PR 224 (CM-14, CM-02 b): a fan-out threshold above its default,
    // a shorter window, a kill tier turned off; an open-flow snapshot
    // interval or age above the default, or no snapshots at all.
    ("NN_NET_SCAN_HOSTS", |v| {
        crate::decision::rules::net_fanout::FanoutConfig::value_weakens("NN_NET_SCAN_HOSTS", v)
    }),
    ("NN_NET_SCAN_PAIRS", |v| {
        crate::decision::rules::net_fanout::FanoutConfig::value_weakens("NN_NET_SCAN_PAIRS", v)
    }),
    ("NN_NET_SCAN_KILL_HOSTS", |v| {
        crate::decision::rules::net_fanout::FanoutConfig::value_weakens("NN_NET_SCAN_KILL_HOSTS", v)
    }),
    ("NN_NET_SCAN_WINDOW_SECS", |v| {
        crate::decision::rules::net_fanout::FanoutConfig::value_weakens(
            "NN_NET_SCAN_WINDOW_SECS",
            v,
        )
    }),
    ("NN_NET_BRUTE_CONNECTS", |v| {
        crate::decision::rules::net_fanout::FanoutConfig::value_weakens("NN_NET_BRUTE_CONNECTS", v)
    }),
    ("NN_NET_BRUTE_KILL_CONNECTS", |v| {
        crate::decision::rules::net_fanout::FanoutConfig::value_weakens(
            "NN_NET_BRUTE_KILL_CONNECTS",
            v,
        )
    }),
    ("NN_NET_BRUTE_WINDOW_SECS", |v| {
        crate::decision::rules::net_fanout::FanoutConfig::value_weakens(
            "NN_NET_BRUTE_WINDOW_SECS",
            v,
        )
    }),
    // Any program exempt from the fan-out rules is a blind spot.
    ("NN_NET_FANOUT_EXEMPT", |v| !v.trim().is_empty()),
    ("NN_NET_SNAPSHOT_INTERVAL_SECS", |v| {
        crate::net::flow_tracker::snapshot_value_weakens(v)
    }),
    ("NN_NET_SNAPSHOT_MIN_AGE_SECS", |v| {
        crate::net::flow_tracker::snapshot_value_weakens(v)
    }),
    ("NN_NET_SNAPSHOT_MAX", |v| {
        v.trim().parse::<u64>().map_or(true, |n| n == 0)
    }),
];

/// Does this value of the variable weaken the agent?
pub type WeakensWith = fn(&str) -> bool;

fn any_value(_: &str) -> bool {
    true
}

fn is_one(value: &str) -> bool {
    value == "1"
}

/// Host paths a mount must not cover (prefix match on the mount point).
const PROTECTED_MOUNT_PREFIXES: &[&str] = &[
    "/etc/northnarrow",
    "/var/lib/northnarrow",
    "/run/northnarrow",
    "/sys/fs/bpf/northnarrow",
    "/etc/systemd/system/northnarrow-",
    // Review 26: the units of a distro package.
    "/usr/lib/systemd/system/northnarrow-",
    // Review 53: hiding the kernel BTF keeps every LSM hook from
    // attaching at the agent's next start.
    "/sys/kernel/btf",
];

/// The canonical bpffs; any other bpf mount is reported.
const BPFFS_ROOT: &str = "/sys/fs/bpf";

/// Operator overlays the agent reads at its next start (`*.local`): an
/// allowlist overlay exempts a comm from detection, a FIM overlay disables
/// a watched path. A new one is refused outside a trusted-installer window
/// since external audit EBPF-015 (the directory is NOCREATE); an existing
/// one stays writable in place, legitimate configuration — so overlays
/// are reported with their hash when they appear or change, and a silent
/// exemption is impossible.
pub const CONFIG_DIR: &str = "/etc/northnarrow";

/// A check that runs this much later than scheduled means the agent did not
/// run in between (cgroup freezer, a stopped VM, starvation).
pub const STALL_SLACK_SECS: u64 = 15;

/// Audit op of a recomputed finding that went away (external audit NN-AUD-114).
pub const CLEARED_OP: &str = "integrity_drift_cleared";

/// External audit NN-AUD-114: a finding that clears and comes back is
/// reported again at most once per this many seconds.
pub const REREPORT_SECS: u64 = 600;

/// External audit NN-AUD-114: findings of one kind listed per round; the
/// rest become one "N more" finding.
pub const MAX_PER_KIND: usize = 64;

/// External audit NN-AUD-113: the units as installed, for the limits they
/// set (`KNOWN_DROPINS` embeds the drop-in the same way).
const AGENT_UNIT: &str = include_str!(concat!(
    env!("NN_REPO_ROOT"),
    "/deploy/systemd/northnarrow-agent.service"
));
const WATCHDOG_UNIT: &str = include_str!(concat!(
    env!("NN_REPO_ROOT"),
    "/deploy/systemd/northnarrow-watchdog.service"
));

/// The agent unit's cgroup (cgroup v2 path, as in `/proc/self/cgroup`).
const AGENT_UNIT_CGROUP: &str = "/system.slice/northnarrow-agent.service";

/// Limit names as [`limits`] reports them.
const LIMIT_CGROUP: &str = "agent cgroup";
const LIMIT_WATCHDOG_OOM: &str = "watchdog oom_score_adj";

/// One finding: `kind` groups, `detail` is what changed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finding {
    pub kind: &'static str,
    pub detail: String,
}

/// Jitter `base` by ±20 % (xorshift on the clock; unpredictability, not
/// cryptography).
pub fn jittered(base: Duration) -> Duration {
    let mut x = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ ((std::process::id() as u64) << 17);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    let ms = base.as_millis() as u64;
    let span = ms / 5; // 20 %
    if span == 0 {
        return base;
    }
    Duration::from_millis(ms - span + x % (2 * span + 1))
}

/// Environment variables of this process that weaken it.
pub fn weakening_env(vars: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (name, weakens) in WEAKENING_ENV {
        if let Some((_, v)) = vars.iter().find(|(k, _)| k == name) {
            if weakens(v) {
                out.push(Finding {
                    kind: "weakening_env",
                    detail: format!("{name}={v}"),
                });
            }
        }
    }
    out
}

/// Lab PR 224: the agent flags that set what a [`WEAKENING_ENV`] variable
/// sets (clap reads either). A weaker value given on the command line —
/// `ExecStart` of a unit, a drop-in, a manual start — is as much a
/// weakening as the variable, and is reported the same way, as
/// `weakening_flag`.
pub const WEAKENING_FLAGS: &[(&str, &str)] = &[
    ("--net-scan-hosts", "NN_NET_SCAN_HOSTS"),
    ("--net-scan-pairs", "NN_NET_SCAN_PAIRS"),
    ("--net-scan-kill-hosts", "NN_NET_SCAN_KILL_HOSTS"),
    ("--net-scan-window-secs", "NN_NET_SCAN_WINDOW_SECS"),
    ("--net-brute-connects", "NN_NET_BRUTE_CONNECTS"),
    ("--net-brute-kill-connects", "NN_NET_BRUTE_KILL_CONNECTS"),
    ("--net-brute-window-secs", "NN_NET_BRUTE_WINDOW_SECS"),
    ("--net-fanout-exempt", "NN_NET_FANOUT_EXEMPT"),
    (
        "--net-snapshot-interval-secs",
        "NN_NET_SNAPSHOT_INTERVAL_SECS",
    ),
    (
        "--net-snapshot-min-age-secs",
        "NN_NET_SNAPSHOT_MIN_AGE_SECS",
    ),
    ("--net-snapshot-max", "NN_NET_SNAPSHOT_MAX"),
];

/// The flags of [`WEAKENING_FLAGS`] in this process's command line (`args`,
/// the program first) whose value weakens it, by the test of the variable
/// they stand for: `--flag value` and `--flag=value`, each occurrence.
pub fn weakening_flags(args: &[String]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        for (flag, env) in WEAKENING_FLAGS {
            let value = if arg == *flag {
                i += 1;
                args.get(i).map(String::as_str)
            } else {
                arg.strip_prefix(flag).and_then(|r| r.strip_prefix('='))
            };
            let Some(value) = value else { continue };
            let weakens = WEAKENING_ENV
                .iter()
                .find(|(name, _)| name == env)
                .is_some_and(|(_, w)| w(value));
            if weakens {
                out.push(Finding {
                    kind: "weakening_flag",
                    detail: format!("{flag}={value}"),
                });
            }
            break;
        }
        i += 1;
    }
    out
}

/// [`UNIT_SEARCH_PATH`] under `prefix` (`/` on the host; a temporary
/// root in the tests): the directories a round reads drop-ins and unit
/// copies from.
pub fn unit_roots(prefix: &Path) -> Vec<PathBuf> {
    UNIT_SEARCH_PATH
        .iter()
        .map(|d| prefix.join(d.trim_start_matches('/')))
        .collect()
}

/// Unexpected drop-in files for our units under `roots`.
pub fn unit_dropins(roots: &[&Path]) -> Vec<Finding> {
    unit_dropins_with(roots, KNOWN_DROPINS)
}

/// [`unit_dropins`] with the drop-ins to accept (path, exact content).
fn unit_dropins_with(roots: &[&Path], known_dropins: &[(&str, &str)]) -> Vec<Finding> {
    let mut out = Vec::new();
    // One directory reached twice (merged /usr: /lib/systemd/system is
    // /usr/lib/systemd/system) is read once, under its first spelling.
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for root in roots {
        let mut dirs: Vec<PathBuf> = UNITS.iter().map(|u| root.join(format!("{u}.d"))).collect();
        dirs.push(root.join("northnarrow-.service.d"));
        dirs.push(root.join("service.d"));
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            if let Ok(canon) = std::fs::canonicalize(&dir) {
                if !seen.insert(canon) {
                    continue;
                }
            }
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().and_then(|x| x.to_str()) != Some("conf") {
                    continue;
                }
                let shown = path.to_string_lossy().to_string();
                // Read as the overlay gate reads (no link, no waiting on a
                // FIFO): anything else is not the known content.
                if known_dropins.iter().any(|(known, content)| {
                    *known == shown
                        && crate::config::overlay_auth::read_overlay(&path)
                            .is_ok_and(|b| b == content.as_bytes())
                }) {
                    continue;
                }
                let stamp = e
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                out.push(Finding {
                    kind: "unit_dropin",
                    detail: format!("{shown} (mtime {stamp})"),
                });
            }
        }
    }
    out
}

/// Review 26: more than one copy of one of our units across the unit
/// search path (`roots`, highest precedence first, [`UNIT_SEARCH_PATH`]
/// in production). A copy in a higher-precedence directory replaces the
/// installed unit at the next `daemon-reload`: `/etc/systemd/system`
/// over a package's `/usr/lib/systemd/system` (nothing existed there to
/// protect at boot), and the tmpfs runtime directories
/// (`/run/systemd/transient`, `system.control`) over either layout;
/// `systemctl mask` is the same shape (a symlink to `/dev/null`). Copies
/// are deduplicated by canonical path, so the merged-`/usr` spellings
/// `/lib/systemd/system` and `/usr/lib/systemd/system` count once.
pub fn unit_shadows(roots: &[&Path]) -> Vec<Finding> {
    let mut out = Vec::new();
    for unit in UNITS {
        let mut copies: Vec<(PathBuf, PathBuf)> = Vec::new();
        for root in roots {
            let path = root.join(unit);
            if std::fs::symlink_metadata(&path).is_err() {
                continue;
            }
            let target = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            if copies.iter().any(|(_, t)| *t == target) {
                continue;
            }
            copies.push((path, target));
        }
        if copies.len() > 1 {
            let chain: Vec<String> = copies
                .iter()
                .map(|(p, t)| {
                    if p == t {
                        p.display().to_string()
                    } else {
                        format!("{} -> {}", p.display(), t.display())
                    }
                })
                .collect();
            out.push(Finding {
                kind: "unit_shadowed",
                detail: format!("{unit}: {} (the first one wins)", chain.join(" shadows ")),
            });
        }
    }
    out
}

/// Where a round reads the host's mounts: PID 1's mount namespace.
const MOUNTINFO_HOST: &str = "/proc/1/mountinfo";

/// External audit EVD-014 (NN-AUD-277, lab PR 180): read when
/// [`MOUNTINFO_HOST`] cannot be — the agent's own namespace, a copy of
/// the host's at the unit's start that receives the host's later mounts.
const MOUNTINFO_OWN: &str = "/proc/self/mountinfo";

/// External audit EVD-014 (lab PR 180): paths whose mount must not change
/// while the agent runs. A mount over a directory above one of them (a
/// tmpfs over `/var/lib`, a bind over `/etc`, a second bpffs stacked on
/// `/sys/fs/bpf`) hides it as surely as a mount on the path itself, which
/// [`PROTECTED_MOUNT_PREFIXES`] catches: the operator, `nn-admin` and the
/// next start of the agent then see another directory, while the running
/// agent keeps writing to the one it anchored. The agent's own binaries
/// are added at run time.
const MOUNT_WATCHED: &[&str] = &[
    "/etc/northnarrow",
    "/var/lib/northnarrow",
    "/run/northnarrow",
    "/sys/fs/bpf/northnarrow",
    "/sys/kernel/btf",
    "/etc/systemd/system/northnarrow-agent.service",
    "/etc/systemd/system/northnarrow-watchdog.service",
    "/usr/lib/systemd/system/northnarrow-agent.service",
    "/usr/lib/systemd/system/northnarrow-watchdog.service",
    "/etc/systemd/system/northnarrow-watchdog-failed.service",
    "/usr/lib/systemd/system/northnarrow-watchdog-failed.service",
];

/// One line of a `mountinfo` text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mount {
    id: u64,
    parent: u64,
    /// `major:minor` of the filesystem.
    dev: String,
    /// The directory of the filesystem mounted here (`/` for a whole one).
    root: String,
    mount_point: String,
    fstype: String,
}

/// The lines of a `mountinfo` text, in order; malformed lines are skipped.
fn parse_mountinfo(mountinfo: &str) -> Vec<Mount> {
    let mut out = Vec::new();
    for line in mountinfo.lines() {
        // id parent major:minor root mount_point opts [optional...] - fstype source superopts
        let mut parts = line.split(" - ");
        let (Some(left), Some(right)) = (parts.next(), parts.next()) else {
            continue;
        };
        let fields: Vec<&str> = left.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let (Ok(id), Ok(parent)) = (fields[0].parse(), fields[1].parse()) else {
            continue;
        };
        out.push(Mount {
            id,
            parent,
            dev: fields[2].to_string(),
            root: unescape(fields[3]),
            mount_point: unescape(fields[4]),
            fstype: right.split_whitespace().next().unwrap_or("").to_string(),
        });
    }
    out
}

/// Is `mp` the path or a directory above it?
fn on_path(mp: &str, path: &str) -> bool {
    mp == "/"
        || path == mp
        || path
            .strip_prefix(mp)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The mounts a lookup of `path` crosses, from the namespace's root to the
/// one it ends on. At each step the next mount is a child of the current
/// one on the path, the shallowest (a deeper child of the same parent is
/// under it, out of reach); of children at one mount point, the last
/// listed (mounted on top).
fn mount_chain<'a>(mounts: &'a [Mount], path: &str) -> Vec<&'a Mount> {
    let ids: HashSet<u64> = mounts.iter().map(|m| m.id).collect();
    let Some(mut cur) = mounts
        .iter()
        .rfind(|m| m.mount_point == "/" && !ids.contains(&m.parent))
    else {
        return Vec::new();
    };
    let mut chain = vec![cur];
    while chain.len() <= mounts.len() {
        let next = mounts
            .iter()
            .filter(|m| {
                m.parent == cur.id
                    && m.id != cur.id
                    && m.mount_point.len() >= cur.mount_point.len()
                    && on_path(&m.mount_point, path)
            })
            .fold(None, |best: Option<&Mount>, m| match best {
                Some(b) if b.mount_point.len() < m.mount_point.len() => Some(b),
                _ => Some(m),
            });
        match next {
            Some(n) if !chain.iter().any(|c| c.id == n.id) => {
                chain.push(n);
                cur = n;
            }
            _ => break,
        }
    }
    chain
}

/// A mount the agent's own unit makes in its namespace: `ReadWritePaths=`
/// and `RuntimeDirectory=` bind each directory onto itself (same
/// filesystem as the mount below it, the directory's own path as root).
/// Only in [`MountSource::Own`]: in the host's namespace there is none.
fn is_unit_sandbox(m: &Mount, mounts: &[Mount], sandbox: &[String]) -> bool {
    sandbox.contains(&m.mount_point)
        && m.root != "/"
        && m.mount_point.ends_with(&m.root)
        && mounts
            .iter()
            .find(|p| p.id == m.parent)
            .is_some_and(|p| p.dev == m.dev)
}

/// The directories the agent's unit makes writable (and so binds onto
/// themselves in its own namespace).
fn unit_sandbox_dirs() -> Vec<String> {
    let mut out: Vec<String> = unit_directive(AGENT_UNIT, "ReadWritePaths")
        .unwrap_or("")
        .split_whitespace()
        .map(|d| d.trim_start_matches(['-', '+']).to_string())
        .collect();
    if let Some(rt) = unit_directive(AGENT_UNIT, "RuntimeDirectory") {
        out.extend(rt.split_whitespace().map(|d| format!("/run/{d}")));
    }
    out
}

fn covers_protected(mp: &str, extra_files: &[String]) -> bool {
    PROTECTED_MOUNT_PREFIXES.iter().any(|p| mp.starts_with(p))
        || extra_files.iter().any(|f| mp == f)
}

/// Mounts in a `mountinfo` text that cover a protected path, a bpffs
/// outside the canonical root, or the tracefs the agent reads its
/// tracepoint offsets from.
pub fn mount_findings(mountinfo: &str, extra_files: &[String]) -> Vec<Finding> {
    mounts_over_protected(&parse_mountinfo(mountinfo), extra_files, &[])
}

/// [`mount_findings`] on parsed lines; a mount of the unit's own sandbox
/// (`sandbox`, the agent's namespace only) is not a finding.
fn mounts_over_protected(
    mounts: &[Mount],
    extra_files: &[String],
    sandbox: &[String],
) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in mounts {
        let (mp, root, fstype) = (&m.mount_point, &m.root, m.fstype.as_str());
        if covers_protected(mp, extra_files) {
            if !sandbox.is_empty() && is_unit_sandbox(m, mounts, sandbox) {
                continue;
            }
            out.push(Finding {
                kind: "mount_over_protected",
                detail: format!("{mp} ({fstype}, source root {root})"),
            });
        } else if fstype == "bpf" && mp != BPFFS_ROOT {
            out.push(Finding {
                kind: "bpffs_mount",
                detail: mp.clone(),
            });
        } else if covers_tracefs(mp, root, fstype) {
            out.push(Finding {
                kind: "tracefs_mount",
                detail: format!("{mp} ({fstype}, source root {root})"),
            });
        }
    }
    out
}

/// Which namespace a [`MountWatch`] baseline was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountSource {
    /// PID 1's ([`MOUNTINFO_HOST`]).
    Host,
    /// The agent's own ([`MOUNTINFO_OWN`]).
    Own,
}

/// External audit EVD-014 (lab PR 180): how each watched path resolved
/// when the agent started (the first read of a source), to tell a mount
/// laid over it since from the mounts it always crossed (`/`, a separate
/// `/var`, `/run`, `/sys/fs/bpf`).
#[derive(Debug, Default)]
pub struct MountWatch {
    source: Option<MountSource>,
    chains: BTreeMap<String, Vec<Mount>>,
}

/// One round of the mount check. `primary` is [`MOUNTINFO_HOST`]; when it
/// cannot be read, `fallback` ([`MOUNTINFO_OWN`]) is, and the unit's own
/// bind mounts there are not findings; when neither can, the round's one
/// mount finding is `mountinfo_unreadable` (it used to be skipped without
/// a trace). Mounts over the protected paths are reported as before; a
/// mount laid since the first read over a directory above a watched path
/// ([`MOUNT_WATCHED`], `own_files`) is `mount_over_protected` too, and a
/// mount a watched path resolved through that is gone is
/// `protected_mount_gone`.
pub fn mount_round(
    primary: std::io::Result<String>,
    fallback: impl FnOnce() -> std::io::Result<String>,
    own_files: &[String],
    watch: &mut MountWatch,
) -> Vec<Finding> {
    let (text, source) = match primary {
        Ok(t) => (t, MountSource::Host),
        Err(host_err) => match fallback() {
            Ok(t) => (t, MountSource::Own),
            Err(own_err) => {
                return vec![Finding {
                    kind: "mountinfo_unreadable",
                    detail: format!(
                        "{MOUNTINFO_HOST}: {host_err}; {MOUNTINFO_OWN}: {own_err} — mounts over \
                         the agent's directories are not checked"
                    ),
                }]
            }
        },
    };
    let mounts = parse_mountinfo(&text);
    let watched: Vec<String> = MOUNT_WATCHED
        .iter()
        .map(|p| p.to_string())
        .chain(own_files.iter().cloned())
        .collect();
    if watch.source != Some(source) {
        if watch.source.is_some() {
            warn!(
                from = ?watch.source,
                to = ?source,
                "integrity: the mount check now reads another namespace — mounts laid before \
                 this round are its new baseline"
            );
        }
        watch.source = Some(source);
        watch.chains.clear();
    }
    for p in &watched {
        // A chain not resolved yet (no root mount in an odd read) is taken
        // from the next read that has one, never compared against.
        let base = watch.chains.entry(p.clone()).or_default();
        if base.is_empty() {
            *base = mount_chain(&mounts, p).into_iter().cloned().collect();
        }
    }
    let sandbox = match source {
        MountSource::Host => Vec::new(),
        MountSource::Own => unit_sandbox_dirs(),
    };
    let mut out = mounts_over_protected(&mounts, own_files, &sandbox);
    out.extend(hidden_by_mounts(
        &mounts,
        &watched,
        &watch.chains,
        own_files,
    ));
    out
}

/// The watched paths whose resolution differs from the baseline, grouped
/// by the mount that differs.
fn hidden_by_mounts(
    mounts: &[Mount],
    watched: &[String],
    base: &BTreeMap<String, Vec<Mount>>,
    own_files: &[String],
) -> Vec<Finding> {
    // (new?, mount id, mount point) -> (mount, paths)
    let mut by_mount: BTreeMap<(bool, u64, String), (Mount, Vec<String>)> = BTreeMap::new();
    for p in watched {
        let Some(before) = base.get(p).filter(|b| !b.is_empty()) else {
            continue;
        };
        let now = mount_chain(mounts, p);
        let same = now
            .iter()
            .zip(before.iter())
            .take_while(|(a, b)| ***a == **b)
            .count();
        if same == now.len() && same == before.len() {
            continue;
        }
        let (new, m) = match now.get(same) {
            // Already reported as a mount over the protected path itself.
            Some(m) if covers_protected(&m.mount_point, own_files) => continue,
            Some(m) => (true, (*m).clone()),
            None => (false, before[same].clone()),
        };
        by_mount
            .entry((new, m.id, m.mount_point.clone()))
            .or_insert_with(|| (m, Vec::new()))
            .1
            .push(p.clone());
    }
    by_mount
        .into_iter()
        .map(|((new, _, _), (m, paths))| {
            let paths = paths.join(", ");
            if new {
                Finding {
                    kind: "mount_over_protected",
                    detail: format!(
                        "{} ({}, source root {}) hides {paths}: mounted over a directory above \
                         them after the agent started",
                        m.mount_point, m.fstype, m.root
                    ),
                }
            } else {
                Finding {
                    kind: "protected_mount_gone",
                    detail: format!(
                        "{} ({}, source root {}) is no longer mounted: {paths} resolved through it \
                         when the agent started and now resolve through the mount below",
                        m.mount_point, m.fstype, m.root
                    ),
                }
            }
        })
        .collect()
}

/// External audit NN-AUD-098: a mount that changes what the agent reads
/// at a tracefs root (`btf_revalidate::TRACEFS_ROOTS`) — anything but a
/// whole tracefs at the root itself, or anything mounted below it (a file
/// over one `format`, even from tracefs). The offsets the tracepoint
/// sensors read come from there at the next start.
fn covers_tracefs(mp: &str, source_root: &str, fstype: &str) -> bool {
    crate::anti_tamper::btf_revalidate::TRACEFS_ROOTS
        .iter()
        .any(|r| match mp.strip_prefix(r) {
            Some("") => fstype != "tracefs" || source_root != "/",
            Some(rest) => rest.starts_with('/'),
            None => false,
        })
}

fn unescape(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// `*.local` overlays in `dir` with size and a short sha256.
pub fn config_overlays(dir: &Path) -> Vec<Finding> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    // External audit ATP-001 / DEP-003: the COMBAT files too, reported as
    // soon as they differ from what the agent was built with — not only
    // when COMBAT engages (a signed change is not drift: see the checker).
    let combat_kind = |p: &Path| {
        p.file_name()
            .and_then(|n| n.to_str())
            .and_then(nn_proto::admin_signed_payload::OverlayKind::from_keyword)
            .filter(|k| crate::config::overlay_auth::shipped_default(*k).is_some())
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|x| x.to_str()) == Some("local") || combat_kind(p).is_some()
        })
        .collect();
    paths.sort();
    for path in paths {
        // External audit LLMR-013: read as the overlay gate reads — once, not
        // through a link, never waiting on a FIFO planted at the name (that
        // stopped this check for good); what cannot be read so is reported.
        let bytes = match crate::config::overlay_auth::read_overlay(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                out.push(Finding {
                    kind: "config_overlay",
                    detail: format!("{} (not read: {e})", path.display()),
                });
                continue;
            }
        };
        if let Some(kind) = combat_kind(&path) {
            if crate::config::overlay_auth::shipped_default(kind)
                .is_some_and(|d| d.as_bytes() == bytes.as_slice())
            {
                continue;
            }
        }
        let digest = Sha256::digest(&bytes);
        let short: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        out.push(Finding {
            kind: "config_overlay",
            detail: format!(
                "{} ({} bytes, sha256 {short}…)",
                path.display(),
                bytes.len()
            ),
        });
    }
    out
}

fn read_trim(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// `oom_score_adj` and cgroup limits, as `name → value`.
fn limits(watchdog_pidfile: &Path) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some(x) = read_trim(Path::new("/proc/self/oom_score_adj")) {
        v.push(("agent oom_score_adj".to_string(), x));
    }
    if let Some(pid) = read_trim(watchdog_pidfile).and_then(|p| p.parse::<u32>().ok()) {
        if let Some(x) = read_trim(&PathBuf::from(format!("/proc/{pid}/oom_score_adj"))) {
            v.push((LIMIT_WATCHDOG_OOM.to_string(), x));
        }
    }
    if let Some(cg) = own_cgroup() {
        // External audit NN-AUD-113: the path itself, so a move to another
        // cgroup (the root has none of the files below) is drift.
        v.push((LIMIT_CGROUP.to_string(), cg.clone()));
        let base = PathBuf::from("/sys/fs/cgroup").join(cg.trim_start_matches('/'));
        for f in [
            "memory.max",
            "memory.high",
            "pids.max",
            "cpu.max",
            "cgroup.freeze",
        ] {
            if let Some(x) = read_trim(&base.join(f)) {
                v.push((format!("agent {f}"), x));
            }
        }
    }
    v
}

/// The shutdown markers the watchdog refused, one JSON line each
/// ([`nn_proto::shutdown_marker::RejectedRecord`]) at `path`.
pub fn rejected_shutdowns(path: &Path) -> Vec<Finding> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let detail = match serde_json::from_str::<nn_proto::shutdown_marker::RejectedRecord>(l)
            {
                Ok(r) => format!(
                    "the watchdog refused a shutdown marker at {} (agent pid {}): {} [sha256 {}]",
                    r.at, r.agent_pid, r.reason, r.sha256
                ),
                Err(_) => format!(
                    "the watchdog refused a shutdown marker: {}",
                    l.chars().take(300).collect::<String>()
                ),
            };
            Finding {
                kind: "shutdown_marker_rejected",
                detail,
            }
        })
        .collect()
}

/// External audit DEP-004: the holds the watchdog recorded while the agent
/// was down ([`nn_proto::watchdog_hold::HoldRecord`], one JSON line each) at
/// `path` — a respawn that brought no agent back (a start job queued for a
/// unit that then failed or was skipped) or the restart ceiling. The same
/// file carries the supervision events the watchdog cannot sign, each under
/// its own kind: `admin_socket_vanished` (external audit WDG-007: the
/// agent's admin socket gone after it answered — a frozen agent signs it
/// after its recovery) and `respawn_argv_degraded` (WDG-008: the exec
/// backend respawns with a recorded or the minimal argv).
pub fn watchdog_holds(path: &Path) -> Vec<Finding> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            use nn_proto::watchdog_hold as wh;
            let (kind, detail) = match serde_json::from_str::<wh::HoldRecord>(l) {
                Ok(r) => {
                    let (kind, what) = match r.reason.as_str() {
                        wh::REASON_ADMIN_SOCKET_VANISHED => (
                            "admin_socket_vanished",
                            "the watchdog found the agent's admin socket gone",
                        ),
                        wh::REASON_RESPAWN_ARGV_DEGRADED => (
                            "respawn_argv_degraded",
                            "the watchdog could not capture the agent's argv for its respawns",
                        ),
                        // Lab PR 216: the supervisor's own failures.
                        wh::REASON_WATCHDOG_EXIT => (
                            "watchdog_exit",
                            "the watchdog exited on an error (systemd restarts it)",
                        ),
                        wh::REASON_WATCHDOG_FAILED => (
                            "watchdog_failed",
                            "systemd put the watchdog unit in the failed state and stopped \
                             restarting it",
                        ),
                        wh::REASON_STUCK_RECOVERY_FAILED => (
                            "stuck_recovery_failed",
                            "the watchdog could not stop an unresponsive agent; it kept it \
                             protected and supervised",
                        ),
                        wh::REASON_EVENT_LOOP_STALLED => (
                            "event_loop_stalled",
                            "the watchdog found the agent's event loop standing still while its \
                             admin socket answered",
                        ),
                        wh::REASON_HOLD_RETRY => (
                            "watchdog_hold",
                            "the holding watchdog tried to start the agent again",
                        ),
                        wh::REASON_HOLD_ENDED => ("watchdog_hold", "the watchdog's hold ended"),
                        _ => ("watchdog_hold", "the watchdog stopped respawning the agent"),
                    };
                    let mut d = format!(
                        "{what} at {} (last agent pid {}): {}: {}",
                        r.at,
                        r.agent_pid,
                        r.reason,
                        r.detail.chars().take(400).collect::<String>()
                    );
                    if let Some(state) = r.unit_state {
                        d.push_str(&format!(
                            " [unit: {}]",
                            state.chars().take(256).collect::<String>()
                        ));
                    }
                    (kind, d)
                }
                Err(_) => (
                    "watchdog_hold",
                    format!(
                        "the watchdog recorded a hold: {}",
                        l.chars().take(300).collect::<String>()
                    ),
                ),
            };
            Finding { kind, detail }
        })
        .collect()
}

/// Lab PR 216 (static review TD-10): the watchdog the agent had verified
/// (`prev`) no longer runs — reported as a signed `integrity_drift`
/// (`watchdog_gone`, [`report_event`]) instead of the `info` line that was
/// all the agent left. A crash, a kill or a stop: the watchdog's own record
/// (`watchdog_exit`, or systemd's `watchdog_failed`) says why, when one
/// could be written. `now` is what the agent's refresh finds in its place.
pub fn watchdog_gone(prev: u32, now: &crate::posture::exempt::WatchdogResolution) -> Finding {
    use crate::posture::exempt::WatchdogResolution as R;
    let now = match now {
        R::Verified { pid, .. } => format!("a new watchdog (pid {pid}) is verified"),
        R::NotPresent => "no watchdog runs now (its pidfile is absent)".to_string(),
        R::InvalidPidfile { .. } | R::Unverifiable { .. } | R::ExeMismatch { .. } => {
            "no watchdog is verified now (its pidfile names no running watchdog)".to_string()
        }
    };
    Finding {
        kind: "watchdog_gone",
        detail: format!("the verified watchdog (pid {prev}) no longer runs; {now}"),
    }
}

/// The last `key=value` of a unit's `[Service]` section, comments skipped.
fn unit_directive<'a>(unit: &'a str, key: &str) -> Option<&'a str> {
    let mut in_service = false;
    let mut found = None;
    for line in unit.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_service = line == "[Service]";
            continue;
        }
        if !in_service || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                found = Some(v.trim());
            }
        }
    }
    found
}

/// A systemd byte size (`9G`, `512M`, `4096`; base 1024) as the cgroup
/// file shows it. `infinity` is `max`.
fn systemd_bytes(v: &str) -> Option<String> {
    if v == "infinity" {
        return Some("max".to_string());
    }
    let (num, mult) = match v.chars().last()? {
        'K' => (&v[..v.len() - 1], 1u64 << 10),
        'M' => (&v[..v.len() - 1], 1 << 20),
        'G' => (&v[..v.len() - 1], 1 << 30),
        'T' => (&v[..v.len() - 1], 1 << 40),
        c if c.is_ascii_digit() => (v, 1),
        _ => return None,
    };
    num.parse::<u64>()
        .ok()?
        .checked_mul(mult)
        .map(|b| b.to_string())
}

/// `MemTotal` of `/proc/meminfo` (reported in kB), in bytes.
fn parse_mem_total(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|l| {
        let kb: u64 = l
            .strip_prefix("MemTotal:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(kb.saturating_mul(1024))
    })
}

fn mem_total_bytes() -> Option<u64> {
    parse_mem_total(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

/// The agent's own cgroup (cgroup v2 path, as in `/proc/self/cgroup`).
fn own_cgroup() -> Option<String> {
    std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(str::to_string))
}

/// External audit DEP-005 (NN-AUD-381): does the agent's memory cap bind
/// on this host? `memory_max` as the cgroup file shows it (bytes, or
/// `max`). The unit's `MemoryMax=` is an absolute size (11G, sized for the
/// LLM advisor removed in Wave 4, lab PR 214, and not re-sized yet); at or
/// above the host's memory (`MemTotal`) the cgroup's own OOM killer can
/// never fire before the host's does.
pub fn memory_cap_binds(memory_max: &str, mem_total_bytes: u64) -> bool {
    memory_max
        .trim()
        .parse::<u64>()
        .is_ok_and(|cap| cap < mem_total_bytes)
}

/// The `oom_score_adj` the agent runs with where its cap does not bind:
/// the unit's value raised to 0, never lowered.
fn relaxed_oom_adj(unit_adj: i32) -> i32 {
    unit_adj.max(0)
}

/// External audit DEP-005: the `oom_score_adj` to write at boot, if any.
/// Only in the unit's own cgroup, where the unit set both values; with any
/// input unreadable, nothing (the unit's value stands, and so does the
/// check's expectation).
fn boot_oom_adj(
    cgroup: Option<&str>,
    memory_max: Option<&str>,
    mem_total: Option<u64>,
    current: Option<i32>,
) -> Option<i32> {
    if cgroup? != AGENT_UNIT_CGROUP || memory_cap_binds(memory_max?, mem_total?) {
        return None;
    }
    let current = current?;
    let relaxed = relaxed_oom_adj(current);
    (relaxed != current).then_some(relaxed)
}

/// External audit DEP-005 (NN-AUD-381), at the agent's start: where the
/// unit's memory cap cannot bind, `OOMScoreAdjust=-500` would make the
/// agent — leaking past what the host has — the last process the host's
/// OOM killer picks, after sshd and the workload. There the agent raises
/// its own `oom_score_adj` to 0 (raising needs no capability): an ordinary
/// candidate, which the watchdog (-900) respawns. The self-integrity check
/// expects that value on such a host ([`expected_limits`]). Not done with
/// a percentage in the unit: [`systemd_bytes`] cannot compare `N%` with
/// the cgroup file (the expectation would be dropped), and 70 % of a large
/// host is far above 11G.
pub fn relax_oom_score_adj() {
    let cgroup = own_cgroup();
    let memory_max = cgroup.as_deref().and_then(|cg| {
        read_trim(
            &PathBuf::from("/sys/fs/cgroup")
                .join(cg.trim_start_matches('/'))
                .join("memory.max"),
        )
    });
    let mem_total = mem_total_bytes();
    let path = Path::new("/proc/self/oom_score_adj");
    let current = read_trim(path).and_then(|v| v.parse::<i32>().ok());
    let Some(to) = boot_oom_adj(cgroup.as_deref(), memory_max.as_deref(), mem_total, current)
    else {
        return;
    };
    let memory_max = memory_max.unwrap_or_default();
    let mem_total = mem_total.unwrap_or_default();
    match std::fs::write(path, to.to_string()) {
        Ok(()) => warn!(
            memory_max,
            mem_total,
            from = current.unwrap_or_default(),
            to,
            "memory cap at or above the host's memory: the agent's cgroup limit cannot bind, \
             oom_score_adj raised so a leak is an ordinary OOM candidate (external audit DEP-005)"
        ),
        Err(e) => warn!(
            memory_max,
            mem_total,
            error = %e,
            "memory cap at or above the host's memory, and oom_score_adj could not be raised: \
             the self-integrity check will report the value (external audit DEP-005)"
        ),
    }
}

/// One limit the units set, as [`limits`] names it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedLimit {
    name: String,
    value: String,
    /// Absent at boot is itself a finding. `false`: compared only when
    /// the file exists at boot (`cpu.max` needs the cpu controller).
    required: bool,
}

/// External audit NN-AUD-113: the limits the shipped units set. A
/// directive the parser does not understand is left out (never a guess);
/// a test keeps every one the units set understood. External audit DEP-005:
/// where the agent's memory cap does not bind (`cap_binds` false, from
/// [`memory_cap_binds`]) the agent raised its `oom_score_adj` at boot
/// ([`relax_oom_score_adj`]), and that value is the expected one.
fn expected_limits(cap_binds: bool) -> Vec<ExpectedLimit> {
    let mut out = Vec::new();
    let mut push = |name: &str, value: Option<String>, required: bool| {
        if let Some(value) = value {
            out.push(ExpectedLimit {
                name: name.to_string(),
                value,
                required,
            });
        }
    };
    push(LIMIT_CGROUP, Some(AGENT_UNIT_CGROUP.to_string()), true);
    push(
        "agent oom_score_adj",
        unit_directive(AGENT_UNIT, "OOMScoreAdjust")
            .and_then(|v| v.parse::<i32>().ok())
            .map(|v| if cap_binds { v } else { relaxed_oom_adj(v) })
            .map(|v| v.to_string()),
        true,
    );
    push(
        "agent memory.high",
        unit_directive(AGENT_UNIT, "MemoryHigh").and_then(systemd_bytes),
        true,
    );
    push(
        "agent memory.max",
        unit_directive(AGENT_UNIT, "MemoryMax").and_then(systemd_bytes),
        true,
    );
    push(
        "agent pids.max",
        unit_directive(AGENT_UNIT, "TasksMax")
            .filter(|v| v.chars().all(|c| c.is_ascii_digit()))
            .map(str::to_string),
        true,
    );
    // No CPUQuota= in the agent's unit: no quota, the kernel's default
    // period.
    if unit_directive(AGENT_UNIT, "CPUQuota").is_none() {
        push("agent cpu.max", Some("max 100000".to_string()), false);
    }
    // The watchdog registers later: compared when it first can be read.
    push(
        LIMIT_WATCHDOG_OOM,
        unit_directive(WATCHDOG_UNIT, "OOMScoreAdjust").map(str::to_string),
        false,
    );
    out
}

/// External audit NN-AUD-113: `oom_score_adj` and cgroup limits against a
/// baseline. With the unit's expectations (the agent runs in its unit's
/// cgroup), the baseline holds what the units set, so a value changed
/// before the first round is drift too (`limit_unexpected`). Otherwise it
/// is what the first round saw. A limit that appears or vanishes after
/// the baseline is drift (`limit_appeared` / `limit_removed`), except the
/// watchdog's `oom_score_adj`: its process comes and goes with the
/// watchdog, so its absence is not drift and its first value is compared
/// with the unit's (or adopted, without the unit's expectations).
#[derive(Default)]
struct LimitWatch {
    baseline: BTreeMap<String, String>,
    from_unit: BTreeSet<String>,
    /// Limits the unit does not require (`cpu.max`): the controller comes
    /// and goes with systemd's delegation (a daemon-reload, a sibling's
    /// accounting) — its absence is not drift, a different value is.
    optional: BTreeSet<String>,
    armed: bool,
}

impl LimitWatch {
    /// The limit findings for `now`. The first call takes the baseline.
    fn observe(&mut self, now: &[(String, String)], expected: &[ExpectedLimit]) -> Vec<Finding> {
        let now: BTreeMap<String, String> = now.iter().cloned().collect();
        if !self.armed {
            self.armed = true;
            self.baseline = now.clone();
            for e in expected {
                if !e.required && e.name != LIMIT_WATCHDOG_OOM {
                    self.optional.insert(e.name.clone());
                }
                if e.required || e.name == LIMIT_WATCHDOG_OOM || now.contains_key(&e.name) {
                    self.baseline.insert(e.name.clone(), e.value.clone());
                    self.from_unit.insert(e.name.clone());
                }
            }
        }
        let names: BTreeSet<String> = self.baseline.keys().chain(now.keys()).cloned().collect();
        let mut out = Vec::new();
        for name in names {
            let before = self.baseline.get(&name).cloned();
            let after = now.get(&name).cloned();
            if before == after {
                continue;
            }
            if after.is_none() && self.optional.contains(&name) {
                continue;
            }
            if name == LIMIT_WATCHDOG_OOM {
                let Some(after) = &after else { continue };
                if before.is_none() {
                    self.baseline.insert(name, after.clone());
                    continue;
                }
            }
            let shown = |v: &Option<String>| v.clone().unwrap_or_else(|| "absent".to_string());
            let finding = if self.from_unit.contains(&name) {
                Finding {
                    kind: "limit_unexpected",
                    detail: format!(
                        "{name}: expected {} (unit), found {}",
                        shown(&before),
                        shown(&after)
                    ),
                }
            } else {
                let kind = match (&before, &after) {
                    (None, _) => "limit_appeared",
                    (_, None) => "limit_removed",
                    _ => "limit_changed",
                };
                Finding {
                    kind,
                    detail: format!("{name}: {} → {}", shown(&before), shown(&after)),
                }
            };
            out.push(finding);
        }
        out
    }
}

/// What one round records for a recomputed finding.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Emit {
    /// Present and reported; `reappeared`: times it came back since the
    /// previous report, while the re-report was held back.
    Detected { f: Finding, reappeared: u32 },
    /// Gone. `reappeared` as above, when the comebacks were never reported.
    Cleared { f: Finding, reappeared: u32 },
}

#[derive(Debug, Clone, Copy)]
struct History {
    last_report: Option<u64>,
    /// Comebacks since `last_report`, not reported yet.
    suppressed: u32,
    /// The present occurrence has been reported (so its end is recorded).
    reported: bool,
}

/// External audit NN-AUD-114: the findings a round recomputes, as a set
/// diffed from round to round, instead of a set of everything ever seen.
#[derive(Default)]
struct ActiveSet {
    active: HashSet<Finding>,
    history: HashMap<Finding, History>,
}

impl ActiveSet {
    /// Diff `current` (already capped, [`cap_per_kind`]) against the
    /// previous round, at unix second `now`.
    fn update(&mut self, current: HashSet<Finding>, now: u64) -> Vec<Emit> {
        let mut out = Vec::new();
        let mut gone: Vec<&Finding> = self.active.difference(&current).collect();
        gone.sort_by(|a, b| (a.kind, &a.detail).cmp(&(b.kind, &b.detail)));
        for f in gone {
            if let Some(h) = self.history.get_mut(f) {
                if h.reported {
                    h.reported = false;
                    out.push(Emit::Cleared {
                        f: f.clone(),
                        reappeared: 0,
                    });
                }
            }
        }
        let mut present: Vec<&Finding> = current.iter().collect();
        present.sort_by(|a, b| (a.kind, &a.detail).cmp(&(b.kind, &b.detail)));
        for f in present {
            let h = self.history.entry(f.clone()).or_insert(History {
                last_report: None,
                suppressed: 0,
                reported: false,
            });
            if h.reported {
                continue;
            }
            let due = h
                .last_report
                .is_none_or(|t| now.saturating_sub(t) >= REREPORT_SECS);
            if !due {
                // came back inside the back-off window: counted, held back
                if !self.active.contains(f) {
                    h.suppressed = h.suppressed.saturating_add(1);
                }
            } else {
                out.push(Emit::Detected {
                    f: f.clone(),
                    reappeared: h.suppressed,
                });
                h.last_report = Some(now);
                h.suppressed = 0;
                h.reported = true;
            }
        }
        // Forget what is gone and out of its back-off window; comebacks
        // that were held back and never reported are recorded first.
        let mut expired: Vec<(Finding, u32)> = Vec::new();
        self.history.retain(|f, h| {
            let keep = current.contains(f)
                || h.last_report
                    .is_some_and(|t| now.saturating_sub(t) < REREPORT_SECS);
            if !keep && h.suppressed > 0 {
                expired.push((f.clone(), h.suppressed));
            }
            keep
        });
        expired.sort_by(|a, b| (a.0.kind, &a.0.detail).cmp(&(b.0.kind, &b.0.detail)));
        out.extend(
            expired
                .into_iter()
                .map(|(f, reappeared)| Emit::Cleared { f, reappeared }),
        );
        self.active = current;
        out
    }
}

/// External audit NN-AUD-114: at most [`MAX_PER_KIND`] findings of each
/// kind (the first by detail, so the same ones are listed every round),
/// then one finding that counts the rest.
fn cap_per_kind(findings: Vec<Finding>) -> HashSet<Finding> {
    let mut by_kind: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for f in findings {
        by_kind.entry(f.kind).or_default().insert(f.detail);
    }
    let mut out = HashSet::new();
    for (kind, details) in by_kind {
        let n = details.len();
        for detail in details.into_iter().take(MAX_PER_KIND) {
            out.insert(Finding { kind, detail });
        }
        if n > MAX_PER_KIND {
            out.insert(Finding {
                kind,
                detail: format!(
                    "{} more {kind} findings not listed (cap {MAX_PER_KIND} per round)",
                    n - MAX_PER_KIND
                ),
            });
        }
    }
    out
}

/// One-shot findings remembered at most (a bounded dedup; see
/// [`Checker::report_once`]).
const MAX_ONCE: usize = 1024;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Checker {
    /// One-shot findings already reported (weakening environment, refused
    /// shutdown markers, stalls): they are events, not state, so they are
    /// never "cleared" (external audit NN-AUD-114).
    once: HashSet<Finding>,
    /// External audit NN-AUD-114: the findings each round recomputes.
    active: ActiveSet,
    /// Signed overlays are configuration, not drift (Tappa 10.8).
    overlay_gate: Option<Arc<crate::config::overlay_auth::OverlayGate>>,
    limits: LimitWatch,
    /// External audit EVD-014: how the watched paths resolved at start.
    mounts: MountWatch,
    watchdog_pidfile: PathBuf,
    own_files: Vec<String>,
    audit_log: Option<Arc<Mutex<AuditLog>>>,
}

impl Checker {
    /// This round's mount findings ([`mount_round`] on the live files).
    fn read_mounts(&mut self) -> Vec<Finding> {
        mount_round(
            std::fs::read_to_string(MOUNTINFO_HOST),
            || std::fs::read_to_string(MOUNTINFO_OWN),
            &self.own_files,
            &mut self.mounts,
        )
    }

    /// A one-shot finding, reported once.
    fn report_once(&mut self, f: Finding, at_boot: bool) {
        if self.once.contains(&f) {
            return;
        }
        if self.once.len() >= MAX_ONCE {
            self.once.clear();
        }
        self.once.insert(f.clone());
        self.record_detected(&f, at_boot, 0);
    }

    fn record_detected(&self, f: &Finding, at_boot: bool, reappeared: u32) {
        if f.kind == "bpffs_mount" {
            warn!(kind = f.kind, detail = %f.detail, at_boot, reappeared, "integrity: bpffs mounted outside /sys/fs/bpf");
        } else {
            error!(
                kind = f.kind,
                detail = %f.detail,
                at_boot,
                reappeared,
                "INTEGRITY DRIFT — systemd/kernel state around the agent changed outside the agent"
            );
        }
        let mut extra =
            serde_json::json!({ "kind": f.kind, "detail": f.detail, "at_boot": at_boot });
        if reappeared > 0 {
            extra["reappeared"] = reappeared.into();
        }
        self.append(AUDIT_OP, extra, "detected");
    }

    fn record_cleared(&self, f: &Finding, at_boot: bool, reappeared: u32) {
        warn!(
            kind = f.kind,
            detail = %f.detail,
            reappeared,
            "integrity drift cleared — the state reported earlier is gone"
        );
        let mut extra =
            serde_json::json!({ "kind": f.kind, "detail": f.detail, "at_boot": at_boot });
        if reappeared > 0 {
            extra["reappeared"] = reappeared.into();
        }
        self.append(CLEARED_OP, extra, "cleared");
    }

    fn append(&self, op: &str, extra: serde_json::Value, result: &str) {
        append_entry(self.audit_log.as_ref(), op, extra, result);
    }

    /// A `config_overlay` finding for a known overlay whose content carries
    /// a valid signature (a `nn-admin config overlay set`) is not drift.
    fn overlay_is_signed(&self, f: &Finding) -> bool {
        let Some(gate) = &self.overlay_gate else {
            return false;
        };
        let Some(path) = f.detail.split(" (").next() else {
            return false;
        };
        let path = Path::new(path);
        let Some(kind) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(nn_proto::admin_signed_payload::OverlayKind::from_keyword)
        else {
            return false;
        };
        gate.is_signed(kind, path)
    }

    /// The state findings of this round (everything but one-shot events).
    fn collect_round(&mut self) -> Vec<Finding> {
        let mut c = Vec::new();
        // External audit EVD-011: one list for the drop-ins and the copies.
        let roots = unit_roots(Path::new("/"));
        let search: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        c.extend(unit_dropins(&search));
        c.extend(unit_shadows(&search));
        c.extend(
            config_overlays(Path::new(CONFIG_DIR))
                .into_iter()
                .filter(|f| !self.overlay_is_signed(f)),
        );
        c.extend(self.read_mounts());
        // External audit DEP-001: an admin private key on the host (the
        // bootstrap key install.sh writes, until the operator moves it
        // offline) is a credential for whoever is root here. Seen through
        // PID 1's mount namespace when it can be reached (the unit's own
        // view of /root is read-only, not hidden, so either works).
        let root = if std::fs::metadata("/proc/1/root/").is_ok() {
            Path::new("/proc/1/root")
        } else {
            Path::new("/")
        };
        for path in crate::host_hardening::admin_keys_on_host(root) {
            c.push(Finding {
                kind: "admin_key_on_host",
                detail: format!(
                    "{path}: an admin private key on this host lets root release COMBAT, \
                     open trusted-installer windows and sign overlays — move it offline"
                ),
            });
        }
        // External audit NN-AUD-113: the units' limits apply when the agent
        // runs as its unit — in its cgroup, or moved out of it while the
        // unit's cgroup exists. A manual run elsewhere keeps the observed
        // baseline (and cgroup v1 hosts read no cgroup metrics).
        let now = limits(&self.watchdog_pidfile);
        let expected = if self.limits.armed {
            Vec::new()
        } else {
            let in_unit = now
                .iter()
                .any(|(n, v)| n == LIMIT_CGROUP && v == AGENT_UNIT_CGROUP);
            let unit_exists = Path::new("/sys/fs/cgroup")
                .join(AGENT_UNIT_CGROUP.trim_start_matches('/'))
                .is_dir();
            if in_unit || unit_exists {
                // External audit DEP-005: the same test the boot took
                // (`relax_oom_score_adj`); unreadable is "binds", as there.
                let cap_binds = match (
                    now.iter()
                        .find(|(n, _)| n == "agent memory.max")
                        .map(|(_, v)| v.as_str()),
                    mem_total_bytes(),
                ) {
                    (Some(max), Some(total)) => memory_cap_binds(max, total),
                    _ => true,
                };
                expected_limits(cap_binds)
            } else {
                Vec::new()
            }
        };
        c.extend(self.limits.observe(&now, &expected));
        c
    }

    /// Diff this round's state findings against the last round's and
    /// record what appeared and what went away.
    fn apply(&mut self, findings: Vec<Finding>, now: u64, at_boot: bool) {
        for e in self.active.update(cap_per_kind(findings), now) {
            match e {
                Emit::Detected { f, reappeared } => self.record_detected(&f, at_boot, reappeared),
                Emit::Cleared { f, reappeared } => self.record_cleared(&f, at_boot, reappeared),
            }
        }
    }

    fn round(&mut self, at_boot: bool) {
        let findings = self.collect_round();
        self.apply(findings, unix_now(), at_boot);
        // External audit WDG-001: shutdown markers the watchdog refused
        // (forged, replayed or stale) while the agent was down.
        let rejected = Path::new(nn_proto::shutdown_marker::REJECTED_PATH);
        let found = rejected_shutdowns(rejected);
        if !found.is_empty() {
            for f in cap_per_kind(found) {
                self.report_once(f, at_boot);
            }
            let _ = std::fs::remove_file(rejected);
        }
        // External audit DEP-004: the watchdog's holds (no agent after a
        // respawn, or the restart ceiling) while the agent was down.
        let holds = Path::new(nn_proto::watchdog_hold::HOLD_PATH);
        let found = watchdog_holds(holds);
        if !found.is_empty() {
            for f in cap_per_kind(found) {
                self.report_once(f, at_boot);
            }
            let _ = std::fs::remove_file(holds);
        }
    }
}

/// One signed entry of the agent itself (`key_fp` `agent-self`).
fn append_entry(
    audit_log: Option<&Arc<Mutex<AuditLog>>>,
    op: &str,
    extra: serde_json::Value,
    result: &str,
) {
    let Some(log) = audit_log else { return };
    let draft = AuditEntryDraft {
        op: op.to_string(),
        extra,
        key_fp: "agent-self".to_string(),
        cosigner_fps: Vec::new(),
        result: result.to_string(),
        client_pid: std::process::id(),
        client_uid: 0,
        client_comm: "northnarrow-agent".to_string(),
        client_exe: None,
    };
    if let Err(e) = log.lock().append(draft) {
        warn!(error = format!("{e:#}"), "integrity: audit entry failed");
    }
}

/// A finding another task of the agent detected between two rounds (the
/// admin socket's own watch, external audit WDG-007): an ERROR and one
/// signed `integrity_drift`, as a round records one. The caller bounds
/// how often.
pub fn report_event(audit_log: Option<&Arc<Mutex<AuditLog>>>, f: &Finding) {
    error!(
        kind = f.kind,
        detail = %f.detail,
        at_boot = false,
        "INTEGRITY DRIFT — the agent's runtime state changed outside the agent"
    );
    append_entry(
        audit_log,
        AUDIT_OP,
        serde_json::json!({ "kind": f.kind, "detail": f.detail, "at_boot": false }),
        "detected",
    );
}

/// Start the check (from `main`, once the audit log exists).
pub fn spawn(
    audit_log: Option<Arc<Mutex<AuditLog>>>,
    watchdog_pidfile: PathBuf,
    overlay_gate: Option<Arc<crate::config::overlay_auth::OverlayGate>>,
) {
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let mut own_files = Vec::new();
    if let Ok(exe) = std::env::current_exe().and_then(|p| p.canonicalize()) {
        if let Some(dir) = exe.parent() {
            for f in ["northnarrow-agent", "northnarrow-watchdog", "nn-admin"] {
                own_files.push(dir.join(f).to_string_lossy().to_string());
            }
        }
    }
    let mut checker = Checker {
        once: HashSet::new(),
        active: ActiveSet::default(),
        overlay_gate,
        limits: LimitWatch::default(),
        mounts: MountWatch::default(),
        watchdog_pidfile,
        own_files,
        audit_log,
    };
    for f in weakening_env(&vars) {
        checker.report_once(f, true);
    }
    let args: Vec<String> = std::env::args().collect();
    for f in weakening_flags(&args) {
        checker.report_once(f, true);
    }
    // External audit EVD-014: the mount baseline is the agent's start, not
    // the first round 15 s later (the round reports what it finds then).
    let _ = checker.read_mounts();
    info!(
        every_secs = BASE_SECS,
        jitter_pct = 20,
        "self-integrity check armed (unit drop-ins, set-property limits, oom_score_adj, mounts, admin keys on the host)"
    );
    tokio::spawn(async move {
        // the watchdog registers a few seconds after the agent
        tokio::time::sleep(Duration::from_secs(15)).await;
        checker.round(true);
        loop {
            let nap = jittered(Duration::from_secs(BASE_SECS));
            let t0 = std::time::Instant::now();
            tokio::time::sleep(nap).await;
            let late = t0.elapsed().saturating_sub(nap);
            if late > Duration::from_secs(STALL_SLACK_SECS) {
                // keyed by the start of the stall so each one is reported once
                let at = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
                    .saturating_sub(late.as_secs());
                checker.report_once(
                    Finding {
                        kind: "agent_stalled",
                        detail: format!("did not run for ~{} s (from unix {at}): cgroup freeze, stopped VM or starvation", late.as_secs()),
                    },
                    false,
                );
            }
            checker.round(false);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_shutdown_markers_become_findings() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("agent.shutdown_rejected");
        assert!(rejected_shutdowns(&path).is_empty());
        let rec = nn_proto::shutdown_marker::RejectedRecord {
            at: 1_800_000_000,
            agent_pid: 4242,
            reason: "the admin signatures do not authorise it".to_string(),
            sha256: "ab".repeat(32),
        };
        std::fs::write(
            &path,
            format!("{}\nnot json\n", serde_json::to_string(&rec).unwrap()),
        )
        .unwrap();
        let f = rejected_shutdowns(&path);
        assert_eq!(f.len(), 2);
        assert!(f.iter().all(|x| x.kind == "shutdown_marker_rejected"));
        assert!(f[0].detail.contains("agent pid 4242"), "{}", f[0].detail);
        assert!(f[1].detail.contains("not json"), "{}", f[1].detail);
    }

    /// External audit DEP-004: a hold the watchdog recorded becomes a
    /// finding, with the unit state that tells a failed or skipped start.
    /// Lab PR 216: a vanished watchdog is a finding of its own kind, with
    /// what replaced it.
    #[test]
    fn a_watchdog_gone_is_a_finding() {
        use crate::posture::exempt::WatchdogResolution as R;
        let f = watchdog_gone(
            4242,
            &R::Verified {
                pid: 4343,
                start_ticks: 1,
            },
        );
        assert_eq!(f.kind, "watchdog_gone");
        assert!(
            f.detail.contains("pid 4242") && f.detail.contains("pid 4343"),
            "{}",
            f.detail
        );
        let f = watchdog_gone(4242, &R::NotPresent);
        assert!(f.detail.contains("absent"), "{}", f.detail);
        let f = watchdog_gone(
            4242,
            &R::Unverifiable {
                pid: 1,
                reason: String::new(),
            },
        );
        assert!(f.detail.contains("no watchdog is verified"), "{}", f.detail);
    }

    #[test]
    fn watchdog_holds_become_findings() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("watchdog.hold");
        assert!(watchdog_holds(&path).is_empty());
        let rec = nn_proto::watchdog_hold::HoldRecord {
            at: 1_800_000_000,
            agent_pid: 4242,
            reason: "agent respawn failed".to_string(),
            detail: "start job for northnarrow-agent.service queued, but no agent within 30 s"
                .to_string(),
            unit_state: Some("ActiveState=failed SubState=failed Result=exit-code".to_string()),
        };
        let bare = nn_proto::watchdog_hold::HoldRecord {
            unit_state: None,
            ..rec.clone()
        };
        std::fs::write(
            &path,
            format!(
                "{}\n{}\nnot json\n",
                serde_json::to_string(&rec).unwrap(),
                serde_json::to_string(&bare).unwrap()
            ),
        )
        .unwrap();
        let f = watchdog_holds(&path);
        assert_eq!(f.len(), 3);
        assert!(f.iter().all(|x| x.kind == "watchdog_hold"));
        assert!(
            f[0].detail.contains("last agent pid 4242"),
            "{}",
            f[0].detail
        );
        assert!(
            f[0].detail.contains("queued, but no agent"),
            "{}",
            f[0].detail
        );
        assert!(
            f[0].detail.contains("[unit: ActiveState=failed"),
            "{}",
            f[0].detail
        );
        assert!(!f[1].detail.contains("[unit:"), "{}", f[1].detail);
        assert!(f[2].detail.contains("not json"), "{}", f[2].detail);
    }

    /// External audit WDG-007 / WDG-008: the supervision events the
    /// watchdog records next to its holds are signed under their own kind,
    /// not as a hold.
    #[test]
    fn watchdog_events_are_signed_under_their_own_kind() {
        use nn_proto::watchdog_hold::{
            HoldRecord, REASON_ADMIN_SOCKET_VANISHED, REASON_RESPAWN_ARGV_DEGRADED,
        };
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("watchdog.hold");
        let ev = |reason: &str, detail: &str| HoldRecord {
            at: 1_800_000_000,
            agent_pid: 77,
            reason: reason.to_string(),
            detail: detail.to_string(),
            unit_state: None,
        };
        let body = [
            ev(
                REASON_ADMIN_SOCKET_VANISHED,
                "/run/northnarrow/admin.sock: nothing that is the agent answers there",
            ),
            ev(
                REASON_RESPAWN_ARGV_DEGRADED,
                "respawns use the minimal argv",
            ),
        ]
        .iter()
        .map(|r| serde_json::to_string(r).unwrap() + "\n")
        .collect::<String>();
        std::fs::write(&path, body).unwrap();
        let f = watchdog_holds(&path);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].kind, "admin_socket_vanished");
        assert!(
            f[0].detail.contains("admin socket gone") && f[0].detail.contains("pid 77"),
            "{}",
            f[0].detail
        );
        assert_eq!(f[1].kind, "respawn_argv_degraded");
        assert!(
            !f[1].detail.contains("stopped respawning"),
            "{}",
            f[1].detail
        );
    }

    /// Lab PR 216: the supervisor's own failures are signed under their own
    /// kind; a hold's retries and its end stay `watchdog_hold`.
    #[test]
    fn the_supervisors_failures_are_their_own_kind() {
        use nn_proto::watchdog_hold as wh;
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("watchdog.hold");
        let ev = |reason: &str| wh::HoldRecord {
            at: 1_800_000_000,
            agent_pid: 77,
            reason: reason.to_string(),
            detail: format!("detail of {reason}"),
            unit_state: None,
        };
        let reasons = [
            (wh::REASON_WATCHDOG_EXIT, "watchdog_exit"),
            (wh::REASON_WATCHDOG_FAILED, "watchdog_failed"),
            (wh::REASON_STUCK_RECOVERY_FAILED, "stuck_recovery_failed"),
            (wh::REASON_EVENT_LOOP_STALLED, "event_loop_stalled"),
            (wh::REASON_HOLD_RETRY, "watchdog_hold"),
            (wh::REASON_HOLD_ENDED, "watchdog_hold"),
        ];
        let body = reasons
            .iter()
            .map(|(r, _)| serde_json::to_string(&ev(r)).unwrap() + "\n")
            .collect::<String>();
        std::fs::write(&path, body).unwrap();
        let f = watchdog_holds(&path);
        assert_eq!(f.len(), reasons.len());
        for (finding, (reason, kind)) in f.iter().zip(reasons) {
            assert_eq!(finding.kind, kind, "{reason}");
            assert!(
                finding.detail.contains(&format!("detail of {reason}"))
                    && finding.detail.contains("last agent pid 77"),
                "{}",
                finding.detail
            );
        }
        assert!(
            f[4].detail.contains("tried to start the agent again"),
            "{}",
            f[4].detail
        );
    }

    /// External audit WDG-007: a finding another task reports between two
    /// rounds is one signed `integrity_drift`, like a round's.
    #[test]
    fn an_event_reported_between_rounds_is_signed() {
        let dir = tempfile::TempDir::new().unwrap();
        let (checker, log_path) = checker_with_log(dir.path());
        report_event(
            checker.audit_log.as_ref(),
            &Finding {
                kind: "admin_socket_removed",
                detail: "/run/northnarrow/admin.sock: removed".to_string(),
            },
        );
        assert_eq!(
            audit_ops(&log_path),
            [(AUDIT_OP.to_string(), "admin_socket_removed".to_string())]
        );
    }

    /// External audit ATP-001 / DEP-003: a COMBAT file is reported once it
    /// differs from the shipped content; the shipped content is not.
    #[test]
    fn combat_files_are_reported_when_changed() {
        let dir = tempfile::TempDir::new().unwrap();
        let v4 = dir.path().join("combat-rules.v4");
        std::fs::write(&v4, crate::anti_tamper::network_isolate::BUILTIN_RULES_V4).unwrap();
        assert!(config_overlays(dir.path()).is_empty());
        let mut tampered = crate::anti_tamper::network_isolate::BUILTIN_RULES_V4.to_string();
        tampered.push_str("*filter\n-I NORTHNARROW_COMBAT 1 -j ACCEPT\nCOMMIT\n");
        std::fs::write(&v4, tampered).unwrap();
        let f = config_overlays(dir.path());
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.contains("combat-rules.v4"), "{}", f[0].detail);
    }

    #[test]
    fn jitter_stays_within_twenty_percent() {
        for _ in 0..200 {
            let d = jittered(Duration::from_secs(30)).as_millis();
            assert!((24_000..=36_000).contains(&d), "{d}");
        }
    }

    /// Lab PR 224: a weaker fan-out or snapshot value given as a flag is a
    /// weakening as the variable is; a stronger one, or another flag's
    /// value that looks like one, is not.
    #[test]
    fn weakening_flags_are_reported_like_the_variables() {
        let args: Vec<String> = [
            "northnarrow-agent",
            "--net-scan-hosts",
            "1000",
            "--net-brute-kill-connects=0",
            "--net-scan-pairs",
            "10",
            "--net-fanout-exempt",
            "nmap",
            "--pid-file",
            "--net-scan-hosts=5",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let d: Vec<String> = weakening_flags(&args)
            .into_iter()
            .map(|f| {
                assert_eq!(f.kind, "weakening_flag");
                f.detail
            })
            .collect();
        assert_eq!(
            d,
            vec![
                "--net-scan-hosts=1000",
                "--net-brute-kill-connects=0",
                "--net-fanout-exempt=nmap"
            ]
        );
        // Every flag stands for a variable the environment check knows.
        for (_, env) in WEAKENING_FLAGS {
            assert!(WEAKENING_ENV.iter().any(|(n, _)| n == env), "{env}");
        }
    }

    #[test]
    fn weakening_env_matches_names_and_values() {
        let vars = vec![
            ("NN_BPF_DEFENSE_OBSERVE".to_string(), "1".to_string()),
            ("NN_TELEMETRY_PROBE_SECS".to_string(), "60".to_string()),
            (
                "NN_ANTI_TAMPER_ALLOW_DEGRADED".to_string(),
                "yes".to_string(),
            ),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let f = weakening_env(&vars);
        let d: Vec<&str> = f.iter().map(|x| x.detail.as_str()).collect();
        assert_eq!(
            d,
            vec![
                "NN_ANTI_TAMPER_ALLOW_DEGRADED=yes",
                "NN_BPF_DEFENSE_OBSERVE=1"
            ]
        );
    }

    #[test]
    fn weakening_env_matches_what_the_consumers_honour() {
        // External audit MAIN-008: `yes` / `true` switch detect-only on, so
        // they are reported like `1`; `no` does not, so it is not.
        let pairs = [
            ("NN_DETECT_ONLY", "yes", true),
            ("NN_DETECT_ONLY", "true", true),
            ("NN_DETECT_ONLY", "no", false),
            ("NORTHNARROW_DRY_RUN", "yes", true),
            // the probe is off with any spelling of 0, and a longer
            // interval than the default thins it out
            ("NN_TELEMETRY_PROBE_SECS", "00", true),
            ("NN_TELEMETRY_PROBE_SECS", " 0", true),
            ("NN_TELEMETRY_PROBE_SECS", "86400", true),
            ("NN_TELEMETRY_PROBE_SECS", "60", false),
            ("NN_TELEMETRY_PROBE_SECS", "30", false),
            // Wave 4 (lab PR 214): the removed advisor's variables weaken
            // nothing any more
            ("NN_ADE_ALLOW_MOCK", "1", false),
            ("NN_ADE_ENFORCE", "1", false),
            // MAIN-004: any rotation-cap override is reported
            ("NN_DETECTIONS_CAP_BYTES", "16384", true),
            ("NN_STATUS_EVENTS_CAP_BYTES", "1", true),
            ("NN_FIM_DRIFT_CAP_BYTES", "33554432", true),
        ];
        for (name, value, reported) in pairs {
            let f = weakening_env(&[(name.to_string(), value.to_string())]);
            assert_eq!(f.len() == 1, reported, "{name}={value}");
            if reported {
                assert_eq!(f[0].kind, "weakening_env");
                assert_eq!(f[0].detail, format!("{name}={value}"));
            }
        }
    }

    #[test]
    fn mountinfo_flags_bind_over_protected_and_foreign_bpffs() {
        let mi = "\
24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 24 0:25 / /sys/fs/bpf rw,nosuid shared:9 - bpf bpf rw
91 24 8:1 /tmp/fake /etc/northnarrow rw,relatime shared:1 - ext4 /dev/sda1 rw
92 24 0:40 / /mnt/nn-bpf2 rw,relatime shared:50 - bpf bpf rw
93 24 8:1 /tmp/x /usr/local/bin/northnarrow-agent rw shared:1 - ext4 /dev/sda1 rw
94 24 0:41 / /etc/systemd/system/northnarrow-agent.service rw shared:51 - tmpfs tmpfs rw
";
        let own = vec!["/usr/local/bin/northnarrow-agent".to_string()];
        let f = mount_findings(mi, &own);
        let kinds: Vec<(&str, &str)> = f.iter().map(|x| (x.kind, x.detail.as_str())).collect();
        assert_eq!(kinds.len(), 4, "{kinds:?}");
        assert!(kinds[0]
            .1
            .starts_with("/etc/northnarrow (ext4, source root /tmp/fake)"));
        assert_eq!(kinds[1], ("bpffs_mount", "/mnt/nn-bpf2"));
        assert_eq!(kinds[2].0, "mount_over_protected");
        assert!(kinds[3]
            .1
            .starts_with("/etc/systemd/system/northnarrow-agent.service"));
    }

    /// External audit NN-AUD-098: the tracefs a stock host mounts (and the
    /// debugfs automount) is not drift; a tmpfs over it, a file mounted
    /// over one `format`, or a tracefs subtree bound at the root is.
    #[test]
    fn mount_findings_flags_tmpfs_over_tracefs() {
        let mi = "\
24 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
35 23 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:17 - tracefs tracefs rw
36 23 0:7 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:18 - debugfs debugfs rw
37 36 0:12 / /sys/kernel/debug/tracing rw,nosuid,nodev,noexec,relatime shared:19 - tracefs tracefs rw
95 35 0:60 / /sys/kernel/tracing rw,relatime shared:60 - tmpfs tmpfs rw
96 35 0:61 /f /sys/kernel/tracing/events/sched/sched_process_exec/format rw shared:61 - tmpfs tmpfs rw
97 37 0:12 /instances/x /sys/kernel/debug/tracing rw shared:62 - tracefs tracefs rw
98 24 8:1 / /sys/kernel/tracing-not rw shared:63 - ext4 /dev/sda1 rw
";
        let f = mount_findings(mi, &[]);
        let kinds: Vec<(&str, &str)> = f.iter().map(|x| (x.kind, x.detail.as_str())).collect();
        assert_eq!(
            kinds,
            vec![
                (
                    "tracefs_mount",
                    "/sys/kernel/tracing (tmpfs, source root /)"
                ),
                (
                    "tracefs_mount",
                    "/sys/kernel/tracing/events/sched/sched_process_exec/format (tmpfs, source root /f)"
                ),
                (
                    "tracefs_mount",
                    "/sys/kernel/debug/tracing (tracefs, source root /instances/x)"
                ),
            ]
        );
    }

    /// A stock host's mounts (Ubuntu 24.04 / Debian 12 shape): `/`, a
    /// separate `/var`, `/run`, `/sys`, the bpffs.
    const HOST_MI: &str = "\
24 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
25 24 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
26 24 0:25 / /run rw,nosuid,nodev,noexec,relatime shared:2 - tmpfs tmpfs rw
27 24 8:3 / /var rw,relatime shared:3 - ext4 /dev/sda3 rw
30 25 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:9 - bpf bpf rw
";

    fn not_readable() -> std::io::Result<String> {
        Err(std::io::Error::from_raw_os_error(libc::EACCES))
    }

    fn round(primary: &str, watch: &mut MountWatch) -> Vec<(&'static str, String)> {
        mount_round(Ok(primary.to_string()), not_readable, &[], watch)
            .into_iter()
            .map(|f| (f.kind, f.detail))
            .collect()
    }

    /// External audit EVD-014: neither mountinfo readable is a finding,
    /// not a round that silently checks no mount.
    #[test]
    fn mount_round_reports_unreadable_mountinfo() {
        let mut w = MountWatch::default();
        let f = mount_round(not_readable(), not_readable, &[], &mut w);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, "mountinfo_unreadable");
        assert!(f[0].detail.contains("/proc/1/mountinfo"), "{f:?}");
        assert!(f[0].detail.contains("/proc/self/mountinfo"), "{f:?}");
    }

    /// Both readable: the host's view, and the same findings as before.
    #[test]
    fn mount_round_on_the_host_view_is_unchanged() {
        let mi = format!(
            "{HOST_MI}91 24 8:2 /tmp/fake /etc/northnarrow rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
        );
        let mut w = MountWatch::default();
        let f = mount_round(Ok(mi.clone()), || Ok(String::new()), &[], &mut w);
        assert_eq!(f, mount_findings(&mi, &[]));
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, "mount_over_protected");
    }

    /// The host's view unreadable: the agent's own namespace, where the
    /// unit's `ReadWritePaths=` binds are not findings and a bind over a
    /// protected directory still is.
    #[test]
    fn mount_round_falls_back_to_the_agents_own_namespace() {
        let own = "\
400 380 8:2 / / ro,relatime shared:200 master:1 - ext4 /dev/sda2 rw
401 400 0:25 / /run rw,nosuid,nodev shared:201 master:2 - tmpfs tmpfs rw
402 400 8:3 / /var ro,relatime shared:202 master:3 - ext4 /dev/sda3 rw
403 401 0:25 /northnarrow /run/northnarrow rw,nosuid,nodev shared:203 master:2 - tmpfs tmpfs rw
404 402 8:3 /lib/northnarrow /var/lib/northnarrow rw,relatime shared:204 master:3 - ext4 /dev/sda3 rw
405 400 8:2 /etc/northnarrow /etc/northnarrow rw,relatime shared:205 master:1 - ext4 /dev/sda2 rw
406 405 0:61 / /etc/northnarrow rw,relatime shared:206 master:60 - tmpfs tmpfs rw
";
        let mut w = MountWatch::default();
        let f = mount_round(not_readable(), || Ok(own.to_string()), &[], &mut w);
        assert_eq!(
            f,
            vec![Finding {
                kind: "mount_over_protected",
                detail: "/etc/northnarrow (tmpfs, source root /)".to_string(),
            }]
        );
        // The same lines read as the host's view: the binds are reported.
        assert_eq!(mount_findings(own, &[]).len(), 4);
    }

    /// External audit EVD-014 (lab PR 180): a mount laid after the start
    /// over a directory above a watched path hides it; the mounts crossed
    /// since the start and unrelated mounts are not drift.
    #[test]
    fn a_mount_over_a_directory_above_the_agents_paths_is_reported() {
        let mut w = MountWatch::default();
        assert!(round(HOST_MI, &mut w).is_empty(), "the baseline");
        // Unrelated mounts after the start: a login, a container, a snap.
        let busy = format!(
            "{HOST_MI}\
60 26 0:70 / /run/user/1000 rw shared:80 - tmpfs tmpfs rw
61 27 0:71 / /var/lib/docker/overlay2/abc/merged rw shared:81 - overlay overlay rw
62 24 7:1 / /snap/core22/1380 ro shared:82 - squashfs /dev/loop1 ro
"
        );
        assert!(round(&busy, &mut w).is_empty());
        // A tmpfs over /var/lib hides the state directory.
        let tmpfs = format!("{busy}90 27 0:90 / /var/lib rw shared:90 - tmpfs tmpfs rw\n");
        assert_eq!(
            round(&tmpfs, &mut w),
            vec![(
                "mount_over_protected",
                "/var/lib (tmpfs, source root /) hides /var/lib/northnarrow: mounted over a \
                 directory above them after the agent started"
                    .to_string()
            )]
        );
        // Gone again: nothing (the round's set clears the finding).
        assert!(round(&busy, &mut w).is_empty());
        // A bind over /etc hides the configuration and the unit files.
        let etc = format!("{HOST_MI}91 24 8:2 /srv/etc /etc rw shared:1 - ext4 /dev/sda2 rw\n");
        let f = round(&etc, &mut w);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].1.starts_with("/etc (ext4, source root /srv/etc) hides /etc/northnarrow, /etc/systemd/system/northnarrow-agent.service, /etc/systemd/system/northnarrow-watchdog.service"), "{f:?}");
        // A bind of /var/lib onto itself (the first step of a read-only
        // remount) changes how the path resolves too.
        let selfbind =
            format!("{HOST_MI}92 27 8:3 /lib /var/lib rw shared:3 - ext4 /dev/sda3 rw\n");
        let f = round(&selfbind, &mut w);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0]
            .1
            .starts_with("/var/lib (ext4, source root /lib) hides /var/lib/northnarrow"));
    }

    /// A second bpffs stacked on /sys/fs/bpf hides the pins; the canonical
    /// one alone was never drift and still is not.
    #[test]
    fn a_bpffs_stacked_on_the_canonical_root_is_reported() {
        let mut w = MountWatch::default();
        assert!(round(HOST_MI, &mut w).is_empty());
        let stacked = format!("{HOST_MI}93 30 0:94 / /sys/fs/bpf rw shared:94 - bpf bpf rw\n");
        assert!(
            mount_findings(&stacked, &[]).is_empty(),
            "invisible to the prefix check"
        );
        let f = round(&stacked, &mut w);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].0, "mount_over_protected");
        assert!(f[0]
            .1
            .starts_with("/sys/fs/bpf (bpf, source root /) hides /sys/fs/bpf/northnarrow"));
    }

    /// A mount the agent's paths resolved through at the start that is
    /// gone (a lazy unmount of a separate /var) is reported too.
    #[test]
    fn a_mount_gone_from_under_the_agents_paths_is_reported() {
        let mut w = MountWatch::default();
        assert!(round(HOST_MI, &mut w).is_empty());
        let without_var: String = HOST_MI
            .lines()
            .filter(|l| !l.contains(" /var "))
            .map(|l| format!("{l}\n"))
            .collect();
        let f = round(&without_var, &mut w);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].0, "protected_mount_gone");
        assert!(f[0]
            .1
            .starts_with("/var (ext4, source root /) is no longer mounted: /var/lib/northnarrow"));
    }

    /// The agent's binaries are watched too: a mount over their directory.
    #[test]
    fn a_mount_over_the_binaries_directory_is_reported() {
        let own = vec!["/usr/local/bin/northnarrow-agent".to_string()];
        let mut w = MountWatch::default();
        assert!(mount_round(Ok(HOST_MI.to_string()), not_readable, &own, &mut w).is_empty());
        let mi = format!("{HOST_MI}94 24 0:95 / /usr/local/bin rw shared:95 - tmpfs tmpfs rw\n");
        assert!(
            mount_findings(&mi, &own).is_empty(),
            "invisible to the exact-file check"
        );
        let f = mount_round(Ok(mi), not_readable, &own, &mut w);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].detail
                .contains("hides /usr/local/bin/northnarrow-agent"),
            "{f:?}"
        );
    }

    /// A read without a root mount is no baseline: the next good read is.
    #[test]
    fn an_odd_first_read_is_not_a_baseline() {
        let mut w = MountWatch::default();
        assert!(round("garbage\n", &mut w).is_empty());
        assert!(
            round(HOST_MI, &mut w).is_empty(),
            "the baseline, not \"/ hides …\""
        );
        let tmpfs = format!("{HOST_MI}90 27 0:90 / /var/lib rw shared:90 - tmpfs tmpfs rw\n");
        assert_eq!(round(&tmpfs, &mut w).len(), 1);
    }

    /// A mount on the protected path itself stays one finding (the prefix
    /// check's), not two.
    #[test]
    fn a_mount_on_the_protected_path_is_reported_once() {
        let mut w = MountWatch::default();
        assert!(round(HOST_MI, &mut w).is_empty());
        let mi = format!("{HOST_MI}95 24 0:96 / /etc/northnarrow rw shared:96 - tmpfs tmpfs rw\n");
        assert_eq!(
            round(&mi, &mut w),
            vec![(
                "mount_over_protected",
                "/etc/northnarrow (tmpfs, source root /)".to_string()
            )]
        );
    }

    #[test]
    fn mount_chain_follows_stacking_and_skips_shadowed_mounts() {
        // /var/lib mounted on the root filesystem, then /var over it: the
        // first is out of reach.
        let mi = "\
24 1 8:2 / / rw - ext4 /dev/sda2 rw
50 24 8:4 / /var/lib rw - ext4 /dev/sda4 rw
51 24 8:3 / /var rw - ext4 /dev/sda3 rw
52 51 0:40 / /var rw - tmpfs tmpfs rw
";
        let m = parse_mountinfo(mi);
        let ids: Vec<u64> = mount_chain(&m, "/var/lib/northnarrow")
            .iter()
            .map(|m| m.id)
            .collect();
        assert_eq!(ids, vec![24, 51, 52]);
        assert_eq!(mount_chain(&m, "/etc/northnarrow").len(), 1);
    }

    #[test]
    fn the_unit_sandbox_is_the_shipped_units_writable_paths() {
        let d = unit_sandbox_dirs();
        for p in [
            "/run/northnarrow",
            "/var/lib/northnarrow",
            "/etc/northnarrow",
        ] {
            assert!(d.iter().any(|x| x == p), "{p} not in {d:?}");
        }
    }

    #[test]
    fn overlays_are_listed_with_size_and_hash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("process-comm-allowlist.local"), "+evil\n").unwrap();
        std::fs::write(dir.path().join("process-comm-allowlist.v1"), "x").unwrap();
        let f = config_overlays(dir.path());
        assert_eq!(f.len(), 1);
        assert!(f[0]
            .detail
            .contains("process-comm-allowlist.local (6 bytes, sha256 "));
        std::fs::write(dir.path().join("process-comm-allowlist.local"), "+evil2\n").unwrap();
        assert_ne!(
            config_overlays(dir.path())[0],
            f[0],
            "a change is a new finding"
        );
    }

    /// External audit LLMR-013 (found in the lab): a FIFO planted at an
    /// overlay's name stopped this check in `open()`; it is reported, not
    /// waited on, and so is a link.
    #[test]
    fn a_fifo_or_a_link_at_an_overlay_name_is_reported_not_waited_on() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("mass-write-carveout.local");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "+x\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("fim-paths.local")).unwrap();
        let f = config_overlays(dir.path());
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|x| x.detail.contains("(not read: ")), "{f:?}");
    }

    #[test]
    fn unit_shadows_report_a_second_copy_and_a_mask() {
        let hi = tempfile::tempdir().unwrap();
        let lo = tempfile::tempdir().unwrap();
        std::fs::write(lo.path().join("northnarrow-agent.service"), "[Service]\n").unwrap();
        // One copy: the normal case for either install layout.
        assert!(unit_shadows(&[hi.path(), lo.path()]).is_empty());
        // A higher-precedence copy shadows it.
        std::fs::write(hi.path().join("northnarrow-agent.service"), "[Service]\n").unwrap();
        let f = unit_shadows(&[hi.path(), lo.path()]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, "unit_shadowed");
        assert!(
            f[0].detail.starts_with("northnarrow-agent.service: "),
            "{}",
            f[0].detail
        );
        // `systemctl mask` is a symlink to /dev/null: reported with its target.
        std::fs::remove_file(hi.path().join("northnarrow-agent.service")).unwrap();
        std::os::unix::fs::symlink("/dev/null", hi.path().join("northnarrow-agent.service"))
            .unwrap();
        let f = unit_shadows(&[hi.path(), lo.path()]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].detail.contains("-> /dev/null"), "{}", f[0].detail);
    }

    #[test]
    fn unit_shadows_count_one_directory_reached_twice_once() {
        // Merged /usr: /lib/systemd/system is a symlink to the vendor dir.
        let usr = tempfile::tempdir().unwrap();
        std::fs::write(
            usr.path().join("northnarrow-watchdog.service"),
            "[Service]\n",
        )
        .unwrap();
        let alias = tempfile::tempdir().unwrap();
        let lib = alias.path().join("lib-systemd-system");
        std::os::unix::fs::symlink(usr.path(), &lib).unwrap();
        assert!(unit_shadows(&[usr.path(), lib.as_path()]).is_empty());
    }

    #[test]
    fn dropins_skip_known_and_non_conf() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("zz-tamper.conf"), "[Service]\n").unwrap();
        std::fs::write(d.join("README"), "x").unwrap();
        let s = dir.path().join("service.d");
        std::fs::create_dir_all(&s).unwrap();
        std::fs::write(s.join("all.conf"), "[Service]\n").unwrap();
        let f = unit_dropins(&[dir.path()]);
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f.iter().all(|x| x.kind == "unit_dropin"));
    }

    /// External audit EVD-011 (lab PR 180): the drop-ins are read from
    /// every directory of the unit search path — `system.attached` and the
    /// generator directories included — and one directory reached by two
    /// spellings counts once.
    #[test]
    fn dropins_are_read_from_every_directory_of_the_unit_search_path() {
        let root = tempfile::tempdir().unwrap();
        let roots = unit_roots(root.path());
        assert_eq!(roots.len(), UNIT_SEARCH_PATH.len());
        for (i, r) in roots.iter().enumerate() {
            let d = r.join(UNITS[i % 2].to_string() + ".d");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join(format!("zz{i}.conf")),
                "[Service]\nEnvironment=NNX180=1\n",
            )
            .unwrap();
        }
        let refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        let f = unit_dropins(&refs);
        assert_eq!(f.len(), UNIT_SEARCH_PATH.len(), "{f:?}");
        for dir in [
            "/etc/systemd/system.attached/northnarrow-",
            "/run/systemd/system.attached/northnarrow-",
            "/run/systemd/generator/northnarrow-",
            "/run/systemd/generator.early/northnarrow-",
            "/run/systemd/generator.late/northnarrow-",
        ] {
            assert!(
                f.iter()
                    .any(|x| x.kind == "unit_dropin" && x.detail.contains(dir)),
                "{dir}: {f:?}"
            );
        }
        // A second spelling of one directory (merged /usr) adds nothing.
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&roots[5], &alias).unwrap();
        let mut twice = refs.clone();
        twice.push(alias.as_path());
        assert_eq!(unit_dropins(&twice).len(), UNIT_SEARCH_PATH.len());
    }

    /// The shipped Debian drop-in is still accepted where install.sh puts
    /// it, whatever else the search path holds.
    #[test]
    fn the_known_dropin_passes_under_the_full_search_path() {
        let content = KNOWN_DROPINS[0].1;
        let root = tempfile::tempdir().unwrap();
        let roots = unit_roots(root.path());
        let etc = root
            .path()
            .join("etc/systemd/system/northnarrow-agent.service.d");
        std::fs::create_dir_all(&etc).unwrap();
        let file = etc.join("10-debian-perf-paranoid.conf");
        std::fs::write(&file, content).unwrap();
        let shown = file.to_string_lossy().to_string();
        let known = [(shown.as_str(), content)];
        let refs: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        assert!(unit_dropins_with(&refs, &known).is_empty());
        // The same file under system.attached is not the known one.
        let att = root
            .path()
            .join("etc/systemd/system.attached/northnarrow-agent.service.d");
        std::fs::create_dir_all(&att).unwrap();
        std::fs::write(att.join("10-debian-perf-paranoid.conf"), content).unwrap();
        let f = unit_dropins_with(&refs, &known);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].detail.contains("system.attached"), "{f:?}");
    }

    /// External audit DEP-002: install.sh's own drop-in is skipped only
    /// while it holds what install.sh wrote.
    #[test]
    fn the_known_dropin_is_judged_on_its_content() {
        let content = KNOWN_DROPINS[0].1;
        let root = tempfile::tempdir().unwrap();
        let d = root.path().join("northnarrow-agent.service.d");
        std::fs::create_dir_all(&d).unwrap();
        let file = d.join("10-debian-perf-paranoid.conf");
        std::fs::write(&file, content).unwrap();
        let shown = file.to_string_lossy().to_string();
        let known = [(shown.as_str(), content)];
        assert!(unit_dropins_with(&[root.path()], &known).is_empty());
        std::fs::write(&file, format!("{content}ExecStart=\nExecStart=/bin/true\n")).unwrap();
        let f = unit_dropins_with(&[root.path()], &known);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].detail.contains("10-debian-perf-paranoid.conf"));
    }

    fn finding(kind: &'static str, detail: &str) -> Finding {
        Finding {
            kind,
            detail: detail.to_string(),
        }
    }

    fn set(fs: &[&Finding]) -> HashSet<Finding> {
        fs.iter().map(|f| (*f).clone()).collect()
    }

    /// External audit NN-AUD-114: a drop-in reported, removed, then put
    /// back identically (same path and mtime) is reported again, and its
    /// removal is recorded. Before the fix the second occurrence was
    /// silent for the life of the process (`seen` was never cleared).
    #[test]
    fn a_finding_that_clears_and_reappears_is_reported_again() {
        let f = finding(
            "unit_dropin",
            "/etc/systemd/system/northnarrow-agent.service.d/zz.conf (mtime 1700000000)",
        );
        let mut a = ActiveSet::default();
        let t0 = 1_800_000_000;
        assert_eq!(
            a.update(set(&[&f]), t0),
            vec![Emit::Detected {
                f: f.clone(),
                reappeared: 0
            }]
        );
        // still there: nothing new
        assert!(a.update(set(&[&f]), t0 + 30).is_empty());
        // removed: recorded
        assert_eq!(
            a.update(HashSet::new(), t0 + 60),
            vec![Emit::Cleared {
                f: f.clone(),
                reappeared: 0
            }]
        );
        // back after the back-off window: reported again at once
        let t1 = t0 + REREPORT_SECS + 60;
        assert_eq!(
            a.update(set(&[&f]), t1),
            vec![Emit::Detected {
                f: f.clone(),
                reappeared: 0
            }]
        );
        // flapping inside the window: held back, counted, and reported
        // when the window ends if it is still there
        assert_eq!(
            a.update(HashSet::new(), t1 + 30),
            vec![Emit::Cleared {
                f: f.clone(),
                reappeared: 0
            }]
        );
        assert!(a.update(set(&[&f]), t1 + 60).is_empty());
        assert!(a.update(HashSet::new(), t1 + 90).is_empty());
        assert!(a.update(set(&[&f]), t1 + 120).is_empty());
        assert_eq!(
            a.update(set(&[&f]), t1 + REREPORT_SECS),
            vec![Emit::Detected {
                f: f.clone(),
                reappeared: 2
            }]
        );
        // held-back comebacks of a finding that is gone by the end of the
        // window are recorded when it is forgotten
        let t2 = t1 + REREPORT_SECS;
        a.update(HashSet::new(), t2 + 30);
        assert!(a.update(set(&[&f]), t2 + 60).is_empty());
        assert!(a.update(HashSet::new(), t2 + 90).is_empty());
        assert_eq!(
            a.update(HashSet::new(), t2 + REREPORT_SECS),
            vec![Emit::Cleared {
                f: f.clone(),
                reappeared: 1
            }]
        );
        assert!(a.history.is_empty(), "nothing kept for what is gone");
    }

    fn checker_with_log(dir: &Path) -> (Checker, PathBuf) {
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.join("agent.key")).unwrap();
        let path = dir.join("audit.log");
        let log = AuditLog::open(&path, key, [0u8; 16]).unwrap();
        let checker = Checker {
            once: HashSet::new(),
            active: ActiveSet::default(),
            overlay_gate: None,
            limits: LimitWatch::default(),
            mounts: MountWatch::default(),
            watchdog_pidfile: dir.join("watchdog.pid"),
            own_files: Vec::new(),
            audit_log: Some(Arc::new(Mutex::new(log))),
        };
        (checker, path)
    }

    fn audit_ops(path: &Path) -> Vec<(String, String)> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| {
                let v: serde_json::Value = serde_json::from_str(l).unwrap();
                (
                    v["op"].as_str().unwrap().to_string(),
                    v["extra"]["kind"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    /// External audit NN-AUD-114: an environment variable is a property of
    /// this process, not state a round recomputes: reported once, never
    /// "cleared" by a round that does not see it.
    #[test]
    fn weakening_env_is_reported_once_and_never_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let (mut c, path) = checker_with_log(dir.path());
        let env = weakening_env(&[("NN_DETECT_ONLY".to_string(), "1".to_string())]);
        assert_eq!(env.len(), 1);
        for f in env.iter().chain(env.iter()) {
            c.report_once(f.clone(), true);
        }
        let drop_in = finding("unit_dropin", "/x.conf (mtime 1)");
        c.apply(vec![drop_in.clone()], 1_000, true);
        c.apply(Vec::new(), 1_030, false);
        c.apply(Vec::new(), 1_060, false);
        assert_eq!(
            audit_ops(&path),
            vec![
                (AUDIT_OP.to_string(), "weakening_env".to_string()),
                (AUDIT_OP.to_string(), "unit_dropin".to_string()),
                (CLEARED_OP.to_string(), "unit_dropin".to_string()),
            ]
        );
    }

    /// External audit NN-AUD-114: a directory of rewritten overlays cannot
    /// grow the state or the audit log without bound.
    #[test]
    fn findings_per_kind_are_capped() {
        let mut v: Vec<Finding> = (0..200)
            .map(|i| Finding {
                kind: "config_overlay",
                detail: format!("/etc/northnarrow/f{i:03}.local (1 bytes, sha256 00…)"),
            })
            .collect();
        v.push(finding("unit_dropin", "/a.conf (mtime 1)"));
        let capped = cap_per_kind(v);
        let overlays: Vec<&Finding> = capped
            .iter()
            .filter(|f| f.kind == "config_overlay")
            .collect();
        assert_eq!(overlays.len(), MAX_PER_KIND + 1);
        assert!(capped.contains(&finding(
            "config_overlay",
            &format!(
                "{} more config_overlay findings not listed (cap {MAX_PER_KIND} per round)",
                200 - MAX_PER_KIND
            )
        )));
        // the same ones are listed every round: the first by detail
        assert!(capped
            .iter()
            .any(|f| f.detail.starts_with("/etc/northnarrow/f000.local")));
        assert!(!capped
            .iter()
            .any(|f| f.detail.starts_with("/etc/northnarrow/f199.local")));
        assert!(capped.contains(&finding("unit_dropin", "/a.conf (mtime 1)")));
    }

    fn lim(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    /// External audit NN-AUD-113: a limit that appears or vanishes after
    /// the baseline is drift. Before the fix only a value present in both
    /// was compared, so a move to the root cgroup (every cgroup file gone)
    /// was silent.
    #[test]
    fn limit_appearing_or_vanishing_after_baseline_is_reported() {
        let mut w = LimitWatch::default();
        let boot = lim(&[
            ("agent oom_score_adj", "-500"),
            ("agent cgroup", "/user.slice/x.scope"),
            ("agent memory.max", "max"),
        ]);
        assert!(w.observe(&boot, &[]).is_empty());
        let moved = lim(&[
            ("agent oom_score_adj", "-500"),
            ("agent cgroup", "/"),
            ("agent pids.max", "512"),
        ]);
        let f = w.observe(&moved, &[]);
        let got: Vec<(&str, &str)> = f.iter().map(|x| (x.kind, x.detail.as_str())).collect();
        assert_eq!(
            got,
            vec![
                ("limit_changed", "agent cgroup: /user.slice/x.scope → /"),
                ("limit_removed", "agent memory.max: max → absent"),
                ("limit_appeared", "agent pids.max: absent → 512"),
            ]
        );
        // back to the baseline: nothing
        assert!(w.observe(&boot, &[]).is_empty());
    }

    /// External audit NN-AUD-113: the shipped units' values are parsed as
    /// the cgroup files show them.
    /// Lab PR 130: `cpu.max` vanished when systemd dropped the cpu
    /// controller after a daemon-reload — not drift; a changed value is.
    #[test]
    fn an_optional_limit_vanishing_is_not_drift() {
        let expected = vec![ExpectedLimit {
            name: "agent cpu.max".to_string(),
            value: "max 100000".to_string(),
            required: false,
        }];
        let mut w = LimitWatch::default();
        let seen = |v: &str| vec![("agent cpu.max".to_string(), v.to_string())];
        assert!(w.observe(&seen("max 100000"), &expected).is_empty());
        assert!(w.observe(&[], &expected).is_empty(), "absent: not drift");
        let f = w.observe(&seen("50000 100000"), &expected);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "limit_unexpected");
    }

    #[test]
    fn expected_limits_match_the_shipped_units() {
        let e: Vec<(String, String, bool)> = expected_limits(true)
            .into_iter()
            .map(|e| (e.name, e.value, e.required))
            .collect();
        let want = |n: &str, v: &str, r: bool| (n.to_string(), v.to_string(), r);
        assert_eq!(
            e,
            vec![
                want("agent cgroup", AGENT_UNIT_CGROUP, true),
                want("agent oom_score_adj", "-500", true),
                want("agent memory.high", "9663676416", true),
                want("agent memory.max", "11811160064", true),
                want("agent pids.max", "512", true),
                want("agent cpu.max", "max 100000", false),
                want("watchdog oom_score_adj", "-900", false),
            ]
        );
        assert_eq!(systemd_bytes("64M").as_deref(), Some("67108864"));
        assert_eq!(systemd_bytes("infinity").as_deref(), Some("max"));
        assert_eq!(systemd_bytes("10%"), None);
    }

    /// External audit NN-AUD-113: a limit changed in the 15 s before the
    /// first round (the lab probe: `echo 100M >` the agent cgroup's
    /// `memory.max`, bypassing systemd) is compared with the unit, not
    /// taken as the baseline. Before the fix the boot round only stored it.
    #[test]
    fn boot_limits_differing_from_the_unit_are_reported() {
        let mut w = LimitWatch::default();
        let boot = lim(&[
            ("agent oom_score_adj", "-500"),
            ("agent cgroup", AGENT_UNIT_CGROUP),
            ("agent memory.max", "104857600"),
            ("agent memory.high", "9663676416"),
            ("agent pids.max", "512"),
            ("agent cpu.max", "max 100000"),
            ("agent cgroup.freeze", "0"),
        ]);
        let f = w.observe(&boot, &expected_limits(true));
        let got: Vec<(&str, &str)> = f.iter().map(|x| (x.kind, x.detail.as_str())).collect();
        assert_eq!(
            got,
            vec![(
                "limit_unexpected",
                "agent memory.max: expected 11811160064 (unit), found 104857600"
            )]
        );
        // put back as the unit sets it: the finding goes away
        let mut fixed = boot.clone();
        fixed[2].1 = "11811160064".to_string();
        assert!(w.observe(&fixed, &[]).is_empty());
        // without the cpu controller cpu.max is not required
        let mut w = LimitWatch::default();
        let no_cpu: Vec<_> = fixed
            .iter()
            .filter(|(n, _)| n != "agent cpu.max")
            .cloned()
            .collect();
        assert!(w.observe(&no_cpu, &expected_limits(true)).is_empty());
    }

    /// External audit NN-AUD-113: the watchdog registers after the agent;
    /// its value is compared with its unit's at the first readable round,
    /// its absence is not drift, and without the unit's expectations its
    /// first value is adopted.
    #[test]
    fn watchdog_oom_is_baselined_late_against_expected() {
        let base = [
            ("agent oom_score_adj", "-500"),
            ("agent cgroup", AGENT_UNIT_CGROUP),
        ];
        let mut w = LimitWatch::default();
        let full = |extra: &[(&str, &str)]| {
            let mut v = lim(&base);
            v.extend(lim(&[
                ("agent memory.max", "11811160064"),
                ("agent memory.high", "9663676416"),
                ("agent pids.max", "512"),
            ]));
            v.extend(lim(extra));
            v
        };
        assert!(w.observe(&full(&[]), &expected_limits(true)).is_empty());
        let f = w.observe(&full(&[("watchdog oom_score_adj", "1000")]), &[]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].kind, "limit_unexpected");
        assert_eq!(
            f[0].detail,
            "watchdog oom_score_adj: expected -900 (unit), found 1000"
        );
        assert!(w
            .observe(&full(&[("watchdog oom_score_adj", "-900")]), &[])
            .is_empty());
        assert!(
            w.observe(&full(&[]), &[]).is_empty(),
            "a restarting watchdog is not drift"
        );

        // manual run: adopted at first sight, then compared
        let mut w = LimitWatch::default();
        assert!(w.observe(&lim(&base), &[]).is_empty());
        let mut v = lim(&base);
        v.extend(lim(&[("watchdog oom_score_adj", "-900")]));
        assert!(w.observe(&v, &[]).is_empty());
        v[2].1 = "1000".to_string();
        let f = w.observe(&v, &[]);
        assert_eq!(f[0].kind, "limit_changed");
    }

    const GIB: u64 = 1 << 30;

    /// External audit DEP-005 (NN-AUD-381): the unit's 11G cap on a host
    /// with no more memory than that cannot bind; there the agent raises
    /// its own -500 to 0 at boot, and only there.
    #[test]
    fn oom_adj_relaxed_when_memory_max_exceeds_memtotal() {
        let cap = systemd_bytes(unit_directive(AGENT_UNIT, "MemoryMax").unwrap()).unwrap();
        let unit = Some(AGENT_UNIT_CGROUP);
        let at =
            |total: u64, current: i32| boot_oom_adj(unit, Some(&cap), Some(total), Some(current));
        // a 4 GiB and an 8 GiB guest (MemTotal a little under the RAM)
        assert_eq!(at(3_900_000 * 1024, -500), Some(0));
        assert_eq!(at(8_000_000 * 1024, -500), Some(0));
        // exactly the cap: it cannot fire before the host's OOM killer
        assert_eq!(at(11 * GIB, -500), Some(0));
        // 16 GiB (the reference host has 15.24 GiB): the cap binds
        assert_eq!(at(15_980_000 * 1024, -500), None);
        assert_eq!(at(12 * GIB, -500), None);
        // never lowered; already at or above 0: nothing to write
        assert_eq!(at(4 * GIB, 0), None);
        assert_eq!(at(4 * GIB, 300), None);
        // no cap at all
        assert_eq!(
            boot_oom_adj(unit, Some("max"), Some(64 * GIB), Some(-500)),
            Some(0)
        );
        // outside the unit's cgroup, or anything unreadable: unchanged
        let small = Some(4 * GIB);
        assert_eq!(
            boot_oom_adj(Some("/user.slice/x.scope"), Some(&cap), small, Some(-500)),
            None
        );
        assert_eq!(boot_oom_adj(None, Some(&cap), small, Some(-500)), None);
        assert_eq!(boot_oom_adj(unit, None, small, Some(-500)), None);
        assert_eq!(boot_oom_adj(unit, Some(&cap), None, Some(-500)), None);
        assert_eq!(boot_oom_adj(unit, Some(&cap), small, None), None);
        assert!(memory_cap_binds("11811160064", 12 * GIB));
        assert!(!memory_cap_binds("11811160064", 11 * GIB));
        assert!(!memory_cap_binds("max", u64::MAX));
        let meminfo = "MemTotal:        8025360 kB\nMemFree:  12 kB\nMemAvailable: 9 kB\n";
        assert_eq!(parse_mem_total(meminfo), Some(8_025_360 * 1024));
        assert_eq!(parse_mem_total("MemFree: 1 kB\n"), None);
    }

    /// External audit DEP-005: the check expects what the boot did — 0 on
    /// a host the cap does not bind, the unit's -500 elsewhere — so neither
    /// install gives a finding, and each value on the other host does.
    #[test]
    fn expected_limits_follow_the_relaxed_adj() {
        let adj = |binds: bool| {
            expected_limits(binds)
                .into_iter()
                .find(|e| e.name == "agent oom_score_adj")
                .map(|e| (e.value, e.required))
        };
        assert_eq!(adj(true), Some(("-500".to_string(), true)));
        assert_eq!(adj(false), Some(("0".to_string(), true)));
        let rest = |binds: bool| {
            expected_limits(binds)
                .into_iter()
                .filter(|e| e.name != "agent oom_score_adj")
                .collect::<Vec<_>>()
        };
        assert_eq!(rest(true), rest(false), "only the agent's adj follows");

        let host = |oom: &str| {
            lim(&[
                ("agent oom_score_adj", oom),
                ("agent cgroup", AGENT_UNIT_CGROUP),
                ("agent memory.max", "11811160064"),
                ("agent memory.high", "9663676416"),
                ("agent pids.max", "512"),
            ])
        };
        for (binds, ok, other) in [(false, "0", "-500"), (true, "-500", "0")] {
            let mut w = LimitWatch::default();
            assert!(
                w.observe(&host(ok), &expected_limits(binds)).is_empty(),
                "binds={binds}: {ok} is the expected value"
            );
            let mut w = LimitWatch::default();
            let f = w.observe(&host(other), &expected_limits(binds));
            assert_eq!(f.len(), 1, "{f:?}");
            assert_eq!(
                f[0].detail,
                format!("agent oom_score_adj: expected {ok} (unit), found {other}")
            );
        }
    }

    /// External audit DEP-005 (the triage's note): every limit the units set
    /// is one [`expected_limits`] understands. A `MemoryMax=70%`, a
    /// `TasksMax=infinity` or an `OOMScoreAdjust` that is not a number
    /// would drop its expectation without a word.
    #[test]
    fn every_limit_the_units_set_is_understood() {
        for key in ["MemoryHigh", "MemoryMax"] {
            let v = unit_directive(AGENT_UNIT, key).unwrap_or_else(|| panic!("{key}"));
            assert!(systemd_bytes(v).is_some(), "{key}={v}");
        }
        let tasks = unit_directive(AGENT_UNIT, "TasksMax").expect("TasksMax");
        assert!(
            tasks.chars().all(|c| c.is_ascii_digit()),
            "TasksMax={tasks}"
        );
        for unit in [AGENT_UNIT, WATCHDOG_UNIT] {
            let adj = unit_directive(unit, "OOMScoreAdjust").expect("OOMScoreAdjust");
            assert!(adj.parse::<i32>().is_ok(), "OOMScoreAdjust={adj}");
        }
        let names: Vec<String> = expected_limits(true).into_iter().map(|e| e.name).collect();
        for want in [
            "agent oom_score_adj",
            "agent memory.high",
            "agent memory.max",
            "agent pids.max",
            "watchdog oom_score_adj",
        ] {
            assert!(names.iter().any(|n| n == want), "{want} missing: {names:?}");
        }
    }

    /// Lab PR 230 (D0 of the dependency plan): the overlay hash the
    /// self-integrity round reports, pinned before the sha2 0.11 bump.
    mod crypto_vectors {
        use super::*;

        /// Protects: an overlay's short SHA-256 in the self-integrity report survives the bump.
        #[test]
        fn overlay_short_sha256_is_pinned() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("process-comm-allowlist.local"), "abc").unwrap();
            let f = config_overlays(dir.path());
            assert_eq!(f.len(), 1, "{f:?}");
            assert_eq!(
                f[0].detail,
                format!(
                    "{} (3 bytes, sha256 ba7816bf8f01cfea…)",
                    dir.path().join("process-comm-allowlist.local").display()
                )
            );
        }
    }
}
