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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tracing::{error, info, warn};

use crate::audit::{AuditEntryDraft, AuditLog};

pub const BASE_SECS: u64 = 30;
pub const AUDIT_OP: &str = "integrity_drift";

/// Units whose drop-ins are checked.
pub const UNITS: [&str; 2] = ["northnarrow-agent.service", "northnarrow-watchdog.service"];

/// Directories systemd reads unit drop-ins from (`systemd.unit(5)`):
/// persistent, runtime, `set-property` (`system.control`), vendor.
const DROPIN_ROOTS: &[&str] = &[
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// systemd's system unit load path, highest precedence first
/// (`systemd.unit(5)`, "Unit File Load Path"). A unit file in an earlier
/// directory replaces one with the same name in a later directory — the
/// runtime ones (`/run/systemd/transient`, `system.control`, the
/// generator outputs) outrank even `/etc/systemd/system`.
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
const KNOWN_DROPINS: &[(&str, &str)] = &[(
    "/etc/systemd/system/northnarrow-agent.service.d/10-debian-perf-paranoid.conf",
    include_str!("../../deploy/systemd/10-debian-perf-paranoid.conf"),
)];

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
    // External audit: the mock ADE backend answers instead of a model
    // that failed to load.
    ("NN_ADE_ALLOW_MOCK", is_one),
    // Lab PR 134: the ADE is a consultant; this lets a model's verdict —
    // built from strings an attacker writes — kill, quarantine or block.
    (
        crate::ade::advisory::ADE_ENFORCE_ENV,
        crate::response::config::is_truthy,
    ),
    // External audit MAIN-004: the evidence logs' rotation caps; any
    // override changes how much evidence survives.
    (crate::chainlog::FIM_DRIFT_CAP_ENV, any_value),
    (crate::chainlog::DETECTIONS_CAP_ENV, any_value),
    (crate::chainlog::STATUS_EVENTS_CAP_ENV, any_value),
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
/// a watched path. They are legitimate configuration, so they cannot be
/// denied — but they are reported with their hash when they appear or
/// change, so a silent exemption is impossible.
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
const AGENT_UNIT: &str = include_str!("../../deploy/systemd/northnarrow-agent.service");
const WATCHDOG_UNIT: &str = include_str!("../../deploy/systemd/northnarrow-watchdog.service");

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

/// Unexpected drop-in files for our units under `roots`.
pub fn unit_dropins(roots: &[&Path]) -> Vec<Finding> {
    unit_dropins_with(roots, KNOWN_DROPINS)
}

/// [`unit_dropins`] with the drop-ins to accept (path, exact content).
fn unit_dropins_with(roots: &[&Path], known_dropins: &[(&str, &str)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for root in roots {
        let mut dirs: Vec<PathBuf> = UNITS.iter().map(|u| root.join(format!("{u}.d"))).collect();
        dirs.push(root.join("northnarrow-.service.d"));
        dirs.push(root.join("service.d"));
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
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

/// Mounts in a `mountinfo` text that cover a protected path, a bpffs
/// outside the canonical root, or the tracefs the agent reads its
/// tracepoint offsets from.
pub fn mount_findings(mountinfo: &str, extra_files: &[String]) -> Vec<Finding> {
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
        let root = fields[3];
        let mp = unescape(fields[4]);
        let fstype = right.split_whitespace().next().unwrap_or("");
        let covered = PROTECTED_MOUNT_PREFIXES.iter().any(|p| mp.starts_with(p))
            || extra_files.iter().any(|f| &mp == f);
        if covered {
            out.push(Finding {
                kind: "mount_over_protected",
                detail: format!("{mp} ({fstype}, source root {root})"),
            });
        } else if fstype == "bpf" && mp != BPFFS_ROOT {
            out.push(Finding {
                kind: "bpffs_mount",
                detail: mp,
            });
        } else if covers_tracefs(&mp, root, fstype) {
            out.push(Finding {
                kind: "tracefs_mount",
                detail: format!("{mp} ({fstype}, source root {root})"),
            });
        }
    }
    out
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
            .and_then(common::wire::admin_signed_payload::OverlayKind::from_keyword)
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
    if let Some(cg) = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_string))
        })
    {
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
/// ([`common::shutdown_marker::RejectedRecord`]) at `path`.
pub fn rejected_shutdowns(path: &Path) -> Vec<Finding> {
    let Ok(body) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let detail = match serde_json::from_str::<common::shutdown_marker::RejectedRecord>(l) {
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
/// directive the parser does not understand is left out (never a guess).
fn expected_limits() -> Vec<ExpectedLimit> {
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
        unit_directive(AGENT_UNIT, "OOMScoreAdjust").map(str::to_string),
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
    watchdog_pidfile: PathBuf,
    own_files: Vec<String>,
    audit_log: Option<Arc<Mutex<AuditLog>>>,
}

impl Checker {
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
        let Some(log) = &self.audit_log else { return };
        let draft = AuditEntryDraft {
            op: op.to_string(),
            extra,
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: result.to_string(),
            client_pid: std::process::id(),
            client_uid: 0,
            client_comm: "northnarrow-agent".to_string(),
        };
        if let Err(e) = log.lock().append(draft) {
            warn!(error = format!("{e:#}"), "integrity: audit entry failed");
        }
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
            .and_then(common::wire::admin_signed_payload::OverlayKind::from_keyword)
        else {
            return false;
        };
        gate.is_signed(kind, path)
    }

    /// The state findings of this round (everything but one-shot events).
    fn collect_round(&mut self) -> Vec<Finding> {
        let mut c = Vec::new();
        let roots: Vec<&Path> = DROPIN_ROOTS.iter().map(Path::new).collect();
        c.extend(unit_dropins(&roots));
        let search: Vec<&Path> = UNIT_SEARCH_PATH.iter().map(Path::new).collect();
        c.extend(unit_shadows(&search));
        c.extend(
            config_overlays(Path::new(CONFIG_DIR))
                .into_iter()
                .filter(|f| !self.overlay_is_signed(f)),
        );
        if let Ok(mi) = std::fs::read_to_string("/proc/1/mountinfo") {
            c.extend(mount_findings(&mi, &self.own_files));
        }
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
                expected_limits()
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
        let rejected = Path::new(common::shutdown_marker::REJECTED_PATH);
        let found = rejected_shutdowns(rejected);
        if !found.is_empty() {
            for f in cap_per_kind(found) {
                self.report_once(f, at_boot);
            }
            let _ = std::fs::remove_file(rejected);
        }
    }
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
        watchdog_pidfile,
        own_files,
        audit_log,
    };
    for f in weakening_env(&vars) {
        checker.report_once(f, true);
    }
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
        let rec = common::shutdown_marker::RejectedRecord {
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
            ("NN_ADE_ALLOW_MOCK", "1", true),
            ("NN_ADE_ALLOW_MOCK", "0", false),
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
        let e: Vec<(String, String, bool)> = expected_limits()
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
        let f = w.observe(&boot, &expected_limits());
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
        assert!(w.observe(&no_cpu, &expected_limits()).is_empty());
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
        assert!(w.observe(&full(&[]), &expected_limits()).is_empty());
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
}
