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
//! audit entry (`integrity_drift`, `kind` + `detail`), once per finding.
//! Weakening environment variables are reported once at boot. An admin
//! private key left on the host (external audit DEP-001) is reported the
//! same way: it is a credential for whoever is root here.

use std::collections::HashSet;
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

/// Environment variables that switch a protection off or into observe
/// mode; `None` = any value counts.
pub const WEAKENING_ENV: &[(&str, Option<&str>)] = &[
    ("NN_ANTI_TAMPER_ALLOW_DEGRADED", None),
    ("NN_BPF_DEFENSE_OBSERVE", Some("1")),
    ("NN_ALLOW_UNVERIFIED_BINARY", Some("1")),
    ("NN_AUDIT_ALLOW_UNWRITABLE", None),
    ("NN_TELEMETRY_PROBE_SECS", Some("0")),
    ("NN_DETECT_ONLY", Some("1")),
    ("NORTHNARROW_DRY_RUN", Some("1")),
    ("NN_OVERLAY_ALLOW_UNSIGNED", Some("1")),
];

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
    for (name, want) in WEAKENING_ENV {
        if let Some((_, v)) = vars.iter().find(|(k, _)| k == name) {
            if want.map(|w| v == w).unwrap_or(true) {
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
                if known_dropins.iter().any(|(known, content)| {
                    *known == shown && std::fs::read(&path).is_ok_and(|b| b == content.as_bytes())
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

/// Mounts in a `mountinfo` text that cover a protected path, or a bpffs
/// outside the canonical root.
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
        }
    }
    out
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
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
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
            v.push(("watchdog oom_score_adj".to_string(), x));
        }
    }
    if let Some(cg) = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_string))
        })
    {
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

struct Checker {
    seen: HashSet<Finding>,
    /// Signed overlays are configuration, not drift (Tappa 10.8).
    overlay_gate: Option<Arc<crate::config::overlay_auth::OverlayGate>>,
    baseline: Vec<(String, String)>,
    watchdog_pidfile: PathBuf,
    own_files: Vec<String>,
    audit_log: Option<Arc<Mutex<AuditLog>>>,
}

impl Checker {
    fn report(&mut self, f: Finding, at_boot: bool) {
        if !self.seen.insert(f.clone()) {
            return;
        }
        if f.kind == "bpffs_mount" {
            warn!(kind = f.kind, detail = %f.detail, at_boot, "integrity: bpffs mounted outside /sys/fs/bpf");
        } else {
            error!(
                kind = f.kind,
                detail = %f.detail,
                at_boot,
                "INTEGRITY DRIFT — systemd/kernel state around the agent changed outside the agent"
            );
        }
        let Some(log) = &self.audit_log else { return };
        let draft = AuditEntryDraft {
            op: AUDIT_OP.to_string(),
            extra: serde_json::json!({ "kind": f.kind, "detail": f.detail, "at_boot": at_boot }),
            key_fp: "agent-self".to_string(),
            cosigner_fps: Vec::new(),
            result: "detected".to_string(),
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

    fn round(&mut self, at_boot: bool) {
        let roots: Vec<&Path> = DROPIN_ROOTS.iter().map(Path::new).collect();
        for f in unit_dropins(&roots) {
            self.report(f, at_boot);
        }
        let search: Vec<&Path> = UNIT_SEARCH_PATH.iter().map(Path::new).collect();
        for f in unit_shadows(&search) {
            self.report(f, at_boot);
        }
        for f in config_overlays(Path::new(CONFIG_DIR)) {
            if self.overlay_is_signed(&f) {
                continue;
            }
            self.report(f, at_boot);
        }
        if let Ok(mi) = std::fs::read_to_string("/proc/1/mountinfo") {
            for f in mount_findings(&mi, &self.own_files) {
                self.report(f, at_boot);
            }
        }
        // External audit WDG-001: shutdown markers the watchdog refused
        // (forged, replayed or stale) while the agent was down.
        let rejected = Path::new(common::shutdown_marker::REJECTED_PATH);
        let found = rejected_shutdowns(rejected);
        if !found.is_empty() {
            for f in found {
                self.report(f, at_boot);
            }
            let _ = std::fs::remove_file(rejected);
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
            self.report(
                Finding {
                    kind: "admin_key_on_host",
                    detail: format!(
                        "{path}: an admin private key on this host lets root release COMBAT, \
                         open trusted-installer windows and sign overlays — move it offline"
                    ),
                },
                at_boot,
            );
        }
        let now = limits(&self.watchdog_pidfile);
        if at_boot {
            self.baseline = now;
            return;
        }
        for (name, value) in &now {
            let before = self
                .baseline
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str());
            if before.is_some() && before != Some(value.as_str()) {
                self.report(
                    Finding {
                        kind: "limit_changed",
                        detail: format!("{name}: {} → {value}", before.unwrap_or("?")),
                    },
                    false,
                );
            }
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
        seen: HashSet::new(),
        overlay_gate,
        baseline: Vec::new(),
        watchdog_pidfile,
        own_files,
        audit_log,
    };
    for f in weakening_env(&vars) {
        checker.report(f, true);
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
                checker.report(
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
}
