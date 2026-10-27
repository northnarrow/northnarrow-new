//! Lab PR 225 (countermeasure CM-18): the host's other defences switched
//! off — auditd, AppArmor, the firewall, the logging, EDR and cloud agents.
//!
//! What is a security tool is content, not code: the signed list
//! `security-tools.v1` ([`SecurityTools`], shipped in `configs/`, applied
//! as built in unless the file on disk is that copy). The
//! [`DefenseDetector`] reads four kinds of evidence against it:
//!
//! | Rule | Evidence |
//! |---|---|
//! | NN-L-EVA-001 | an exec of `systemctl stop/disable/mask/kill`, `service … stop`, `invoke-rc.d`, `update-rc.d … disable/remove`, `chkconfig … off`, `rc-service … stop`, `rc-update del`, `/etc/init.d/<name> stop` naming a listed unit |
//! | NN-L-EVA-002 | an exec of a listed switch-off command (`auditctl -e 0`, `-D`, `ufw disable`, `setenforce 0`, `nft flush ruleset`, …) |
//! | NN-L-EVA-003 | a stop or end signal to a listed tool's process — on `task_kill` (`Event::DefenderSignal`, a shell's builtin `kill` included), or an exec of `kill`, `pkill`, `killall` naming one |
//! | NN-L-EVA-004 | a change of a listed configuration file (FIM: the files are watched, with those a listed directory holds at boot) |
//!
//! ATT&CK v20 (the ids of lab PR 221): T1685 Disable or Modify Tools
//! (Defense Impairment, TA0112), T1685.004 for the audit system, T1686 for
//! the firewall.
//!
//! Each finding is **sanctioned** — a package transaction run by root, an
//! administrator's interactive sudo/su session, a configuration-management
//! actor of `process-comm-allowlist`, or (for the agent's own units only) a
//! stop or restart inside a valid signed trusted-installer window — and then
//! Low, or not, and then High and the posture's `DefenseImpairment`
//! (ENGAGED). The window sanctions nothing of another tool: auditd stopped
//! inside it is High as anywhere (decision of 21/10/2026). Outside a window,
//! or once it expired, a stop of the agent's units is High as before. Not sanctioned and asked
//! by a lineage that holds a program from a staging directory or a deleted
//! or memory-only executable (a cryptojacking script from `/tmp`), the
//! verdict kills that program's tree.
//!
//! NN-L-EVA-002 is recorded once per switch-off command and process tree
//! within [`SWITCH_OFF_COALESCE`]: `ufw disable` runs `ufw-init`, which
//! flushes and resets each chain with an `iptables`/`ip6tables` exec of its
//! own — dozens of the same listed command in a second or two, each a High
//! record until then. The first is recorded at once; the repeats are
//! counted against it ([`crate::detection_budget::count_coalesced`]: the
//! next record of the rule and uid carries them in `suppressed_before`, the
//! signed `detections_held` row in its count). A finding whose lineage
//! holds a staged program (the kill path) is never coalesced.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use nn_model::telemetry::FimOp;
use nn_model::Event;
use parking_lot::Mutex;

use crate::anti_tamper::trusted_installer::TrustedInstallerOverride;
use crate::config::comm_allowlist::CommAllowlist;
use crate::config::overlay::{self, DefaultsSource, Shipped};
use crate::posture::lineage::{AuthSessionTracker, ExecIdentity};

/// Deploy location of the list.
pub const SECURITY_TOOLS_V1: &str = "/etc/northnarrow/security-tools.v1";
/// The shipped list, built in.
pub const BUILTIN_SECURITY_TOOLS_V1: &str =
    include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/security-tools.v1"));
/// SHA-256 of every `security-tools.v1` an earlier release shipped.
pub const EARLIER_SECURITY_TOOLS_V1_SHA256: &[&str] = &[];
/// The shipped `security-tools.v1` (built-in copy, earlier ones).
pub const SECURITY_TOOLS_SHIPPED: Shipped<'static> =
    Shipped::new(BUILTIN_SECURITY_TOOLS_V1, EARLIER_SECURITY_TOOLS_V1_SHA256);

/// Files of one listed configuration directory watched at most.
const DIR_FILES_MAX: usize = 256;

/// What kind of defence a tool is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolClass {
    Audit,
    Mac,
    Firewall,
    Log,
    Ids,
    Edr,
    Cloud,
}

impl ToolClass {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "audit" => Self::Audit,
            "mac" => Self::Mac,
            "firewall" => Self::Firewall,
            "log" => Self::Log,
            "ids" => Self::Ids,
            "edr" => Self::Edr,
            "cloud" => Self::Cloud,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Mac => "mac",
            Self::Firewall => "firewall",
            Self::Log => "log",
            Self::Ids => "ids",
            Self::Edr => "edr",
            Self::Cloud => "cloud",
        }
    }

    /// The ATT&CK v20 technique of disabling a tool of this class.
    pub fn attack(self) -> &'static str {
        match self {
            Self::Audit => "T1685.004",
            Self::Firewall => "T1686",
            _ => "T1685",
        }
    }
}

/// One listed tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    pub name: String,
    pub class: ToolClass,
    /// Unit names, `.service` dropped.
    pub units: Vec<String>,
    /// Executables or trees (ending in `/`).
    pub procs: Vec<String>,
    /// Files or directories (ending in `/`).
    pub configs: Vec<String>,
}

/// One switch-off command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchOff {
    pub tool: String,
    pub program: String,
    pub args: Vec<String>,
}

/// The list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityTools {
    pub tools: Vec<Tool>,
    pub cmds: Vec<SwitchOff>,
}

fn unit_key(unit: &str) -> &str {
    unit.strip_suffix(".service").unwrap_or(unit)
}

impl SecurityTools {
    /// Parse the list. A line that is not an entry is an error naming it.
    pub fn parse(text: &str) -> Result<Self> {
        let mut out = Self::default();
        for (n, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut words = line.split_whitespace();
            match words.next() {
                Some("tool") => {
                    let name = words
                        .next()
                        .ok_or_else(|| anyhow!("line {}: tool without a name", n + 1))?;
                    let mut tool = Tool {
                        name: name.to_string(),
                        class: ToolClass::Edr,
                        units: Vec::new(),
                        procs: Vec::new(),
                        configs: Vec::new(),
                    };
                    let mut class = None;
                    for field in words {
                        let (k, v) = field
                            .split_once('=')
                            .ok_or_else(|| anyhow!("line {}: `{field}` is not key=value", n + 1))?;
                        let values: Vec<String> = v
                            .split(',')
                            .filter(|x| !x.is_empty())
                            .map(String::from)
                            .collect();
                        match k {
                            "class" => {
                                class = Some(ToolClass::parse(v).ok_or_else(|| {
                                    anyhow!("line {}: unknown class `{v}`", n + 1)
                                })?)
                            }
                            "unit" => tool
                                .units
                                .extend(values.iter().map(|u| unit_key(u).to_string())),
                            "proc" | "config" => {
                                if let Some(bad) = values.iter().find(|p| !p.starts_with('/')) {
                                    return Err(anyhow!(
                                        "line {}: `{bad}` is not an absolute path",
                                        n + 1
                                    ));
                                }
                                if k == "proc" {
                                    tool.procs.extend(values);
                                } else {
                                    tool.configs.extend(values);
                                }
                            }
                            other => {
                                return Err(anyhow!("line {}: unknown field `{other}`", n + 1))
                            }
                        }
                    }
                    tool.class = class
                        .ok_or_else(|| anyhow!("line {}: tool `{name}` has no class", n + 1))?;
                    out.tools.push(tool);
                }
                Some("cmd") => {
                    let tool = words.next();
                    let program = words.next();
                    let (Some(tool), Some(program)) = (tool, program) else {
                        return Err(anyhow!("line {}: cmd <tool> <program> [<arg>…]", n + 1));
                    };
                    out.cmds.push(SwitchOff {
                        tool: tool.to_string(),
                        program: program.to_string(),
                        args: words.map(String::from).collect(),
                    });
                }
                Some(other) => return Err(anyhow!("line {}: unknown entry `{other}`", n + 1)),
                None => {}
            }
        }
        for c in &out.cmds {
            if out.tool(&c.tool).is_none() {
                return Err(anyhow!("cmd for `{}`, which no tool line names", c.tool));
            }
        }
        Ok(out)
    }

    /// The list in force: `path` when it is the shipped copy, else the
    /// built-in one ([`overlay::load_pinned_defaults`], which says why). The
    /// list is not signed and has no operator overlay: it is pinned to the
    /// built-in copy, and a modified file is never applied, not even under
    /// `NN_OVERLAY_ALLOW_UNSIGNED`.
    pub fn load(path: &Path) -> (Self, DefaultsSource) {
        overlay::load_pinned_defaults(
            "security-tools",
            path,
            SECURITY_TOOLS_SHIPPED,
            |label, text| {
                Self::parse(text).unwrap_or_else(|e| {
                tracing::error!(error = %e, list = label, "security-tools: list refused — the built-in copy is in force");
                Self::builtin()
            })
            },
        )
    }

    /// The built-in list.
    pub fn builtin() -> Self {
        Self::parse(BUILTIN_SECURITY_TOOLS_V1).expect("the shipped security-tools.v1 parses")
    }

    pub fn tool(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// The tool a unit argument names (`auditd`, `auditd.service`, a
    /// glob `falcon*`).
    pub fn tool_of_unit(&self, arg: &str) -> Option<(&Tool, String)> {
        let key = unit_key(arg);
        if let Some(prefix) = key
            .strip_suffix('*')
            .filter(|p| !p.is_empty() && !p.contains('*'))
        {
            return self.tools.iter().find_map(|t| {
                t.units
                    .iter()
                    .find(|u| u.starts_with(prefix))
                    .map(|u| (t, u.clone()))
            });
        }
        self.tools
            .iter()
            .find_map(|t| t.units.iter().find(|u| *u == key).map(|u| (t, u.clone())))
    }

    /// The tool whose process `id` is (its executable, or the script an
    /// interpreter runs, is a listed `proc`).
    pub fn tool_of_process(&self, id: &ExecIdentity) -> Option<&Tool> {
        let exe = id.exe.to_string_lossy();
        let paths: Vec<&str> = std::iter::once(exe.as_ref())
            .chain(id.script.as_deref().filter(|s| s.starts_with('/')))
            .collect();
        self.tools.iter().find(|t| {
            t.procs.iter().any(|p| {
                paths.iter().any(|x| {
                    if p.ends_with('/') {
                        x.starts_with(p.as_str())
                    } else {
                        x == p
                    }
                })
            })
        })
    }

    /// The tool a process name given to `pkill`/`killall` names: the
    /// basename of a listed executable (or its first 15 bytes, the kernel's
    /// `comm`), or a listed unit.
    pub fn tool_of_name(&self, name: &str) -> Option<&Tool> {
        let name = name.trim_start_matches('^').trim_end_matches('$');
        if name.is_empty() || name.len() < 3 {
            return None;
        }
        self.tools.iter().find(|t| {
            t.units.iter().any(|u| u == name)
                || t.procs.iter().filter(|p| !p.ends_with('/')).any(|p| {
                    let base = p.rsplit('/').next().unwrap_or(p);
                    base == name || (name.len() == 15 && base.starts_with(name))
                })
        })
    }

    /// The tool a configuration path belongs to.
    pub fn tool_of_config(&self, path: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| {
            t.configs.iter().any(|c| {
                if c.ends_with('/') {
                    path.starts_with(c.as_str()) || path == c.trim_end_matches('/')
                } else {
                    path == c
                }
            })
        })
    }

    /// The paths FIM watches for NN-L-EVA-004: each listed file, each
    /// listed directory and the regular files it holds now (at most
    /// [`DIR_FILES_MAX`] each; FIM does not enumerate a directory's
    /// children, so an edit in place of one present at boot is seen only
    /// this way). Missing ones are left to FIM (skipped).
    pub fn fim_paths(&self) -> BTreeSet<PathBuf> {
        let mut out = BTreeSet::new();
        for c in self.tools.iter().flat_map(|t| t.configs.iter()) {
            let p = PathBuf::from(c.trim_end_matches('/'));
            if c.ends_with('/') {
                if let Ok(entries) = std::fs::read_dir(&p) {
                    for e in entries.take(DIR_FILES_MAX).flatten() {
                        if e.file_type().is_ok_and(|t| t.is_file()) {
                            out.insert(e.path());
                        }
                    }
                }
            }
            out.insert(p);
        }
        out
    }
}

/// The entry of `security-tools.v1` that is this agent: the only tool a
/// trusted-installer window sanctions.
pub const AGENT_TOOL: &str = "northnarrow";
/// The agent's units a window sanctions a stop or restart of.
pub const AGENT_UNITS: [&str; 2] = ["northnarrow-agent", "northnarrow-watchdog"];

/// Which rule a finding is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaRule {
    ServiceStopped,
    SwitchedOff,
    Killed,
    ConfigChanged,
}

/// What the detector made of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: EvaRule,
    pub tool: String,
    pub class: ToolClass,
    /// What was done, for the reasoning.
    pub what: String,
    /// `Some(why)`: a package transaction, an administrator's session or a
    /// configuration-management actor — Low.
    pub sanctioned: Option<String>,
    /// `Some((pid, program))`: the lineage holds a program from a staging
    /// directory or a deleted or memory-only executable — kill its tree.
    pub suspicious: Option<(u32, String)>,
    /// The process that did it.
    pub pid: u32,
    pub filename: String,
    pub timestamp_ns: u64,
    /// NN-L-EVA-002: `Some(pid)` when this finding repeats the switch-off
    /// command another child of the same parent (`pid`) ran and was
    /// recorded for, within [`SWITCH_OFF_COALESCE`]: it is counted against
    /// that record, not recorded again.
    pub coalesced_into: Option<u32>,
}

/// NN-L-EVA-002: how long the repeats of one switch-off command by one
/// process tree (the children of one parent) are coalesced into its first
/// record, on the events' clock.
pub const SWITCH_OFF_COALESCE: Duration = Duration::from_secs(10);
/// Coalescing windows kept at most; past it (expired ones dropped first) a
/// new command and tree is recorded without one, toward detection.
const COALESCE_MAX: usize = 256;
/// The rule the coalesced repeats are counted under.
pub const SWITCHED_OFF_RULE_ID: &str = "NN-L-EVA-002_SecurityToolSwitchedOff";

/// One switch-off command by one process tree, at one level.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CoalesceKey {
    tool: String,
    what: String,
    /// The parent of the process that ran it: pid and start.
    parent: (u32, u64),
    sanctioned: bool,
}

/// The record a [`CoalesceKey`] drew last.
#[derive(Debug, Clone, Copy)]
struct CoalesceWindow {
    /// Its event's time (ns).
    opened_ns: u64,
    /// Its process.
    pid: u32,
}

/// Counters for `status`.
#[derive(Debug, Default)]
pub struct DefenseCounters {
    /// Findings not sanctioned (High).
    pub findings: AtomicU64,
    /// Sanctioned findings (Low).
    pub sanctioned: AtomicU64,
    /// Security tools' processes registered in `DEFENDER_PIDS` now.
    pub defenders: AtomicU64,
    /// NN-L-EVA-002 repeats coalesced into a record (counted in neither
    /// of the first two).
    pub coalesced: AtomicU64,
}

/// A snapshot of [`DefenseCounters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DefenseCounts {
    pub findings: u64,
    pub sanctioned: u64,
    pub defenders: u64,
    pub coalesced: u64,
}

/// The kernel map of the tools' processes ([`DefenseDetector::attach_map`]).
pub type DefenderMap = aya::maps::HashMap<aya::maps::MapData, u32, u8>;

/// The detector the rules and the posture share.
pub struct DefenseDetector {
    tools: Arc<SecurityTools>,
    lineage: AuthSessionTracker,
    actors: Option<Arc<CommAllowlist>>,
    /// Registered tool processes: pid → (tool, start in clock ticks).
    defenders: Mutex<HashMap<u32, (String, Option<u64>)>>,
    map: Mutex<Option<DefenderMap>>,
    proc_root: PathBuf,
    counters: DefenseCounters,
    /// The last events assessed: the four rules and the posture read each
    /// event, and it is assessed (and counted) once.
    memo: Mutex<std::collections::VecDeque<(MemoKey, Option<Finding>)>>,
    /// `/proc` scans a tool's exec asked for ([`FORK_RESCAN_AFTER`]), and
    /// the last one run.
    rescans: Mutex<(Vec<Instant>, Option<Instant>)>,
    /// NN-L-EVA-002's coalescing windows ([`SWITCH_OFF_COALESCE`]).
    coalesce: Mutex<HashMap<CoalesceKey, CoalesceWindow>>,
    /// The trusted-installer window ([`Self::set_installer_window`]).
    installer: std::sync::OnceLock<Arc<TrustedInstallerOverride>>,
}

/// After a tool's exec, when `/proc` is scanned again for its processes:
/// a daemon of `Type=forking` (Debian's auditd) runs as a child the exec'd
/// process forks before it exits, so the pid its exec registered is gone at
/// once and the daemon's own pid was never in `DEFENDER_PIDS` — until the
/// next agent start, a builtin `kill -STOP` of a restarted auditd went
/// unseen (lab, MS-25 on debian12).
pub const FORK_RESCAN_AFTER: [Duration; 3] = [
    Duration::from_millis(300),
    Duration::from_secs(2),
    Duration::from_secs(6),
];
/// The least time between two such scans (a burst of tool execs).
pub const FORK_RESCAN_SPACING: Duration = Duration::from_millis(250);
/// Scans waiting at most.
const FORK_RESCANS_MAX: usize = 9;

/// An event's identity for the memo: its process, time, kind and file.
type MemoKey = (u32, u64, u8, u64);

const MEMO_CAP: usize = 16;

fn memo_key(event: &Event) -> Option<MemoKey> {
    use std::hash::{Hash, Hasher};
    let hash = |s: &str| {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        s.hash(&mut h);
        h.finish()
    };
    match event {
        Event::ProcessSpawn {
            pid,
            timestamp_ns,
            filename,
            ..
        } => Some((*pid, *timestamp_ns, 0, hash(filename))),
        Event::DefenderSignal {
            pid,
            timestamp_ns,
            target_pid,
            ..
        } => Some((*pid, *timestamp_ns, 1, u64::from(*target_pid))),
        Event::Fim(fe) => Some((
            fe.modifier_pid,
            fe.timestamp_ns,
            2 + fe.op as u8,
            hash(&fe.path),
        )),
        _ => None,
    }
}

/// The agent's detector, for `status` ([`publish`]).
static PUBLISHED: std::sync::OnceLock<Arc<DefenseDetector>> = std::sync::OnceLock::new();

/// Make `detector` the one `status` reports (`main.rs`, once).
pub fn publish(detector: &Arc<DefenseDetector>) {
    let _ = PUBLISHED.set(Arc::clone(detector));
}

/// The published detector's counters; `None` before [`publish`].
pub fn published_counts() -> Option<DefenseCounts> {
    PUBLISHED.get().map(|d| d.counts())
}

/// [`DefenseDetector::sanction_of`] on the published detector.
pub fn published_sanction(event: &Event) -> Option<String> {
    PUBLISHED.get().and_then(|d| d.sanction_of(event))
}

impl DefenseDetector {
    pub fn new(
        tools: Arc<SecurityTools>,
        lineage: AuthSessionTracker,
        actors: Option<Arc<CommAllowlist>>,
    ) -> Self {
        Self::with_proc_root(tools, lineage, actors, "/proc")
    }

    /// With a `/proc` of its own (tests).
    pub fn with_proc_root(
        tools: Arc<SecurityTools>,
        lineage: AuthSessionTracker,
        actors: Option<Arc<CommAllowlist>>,
        proc_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            tools,
            lineage,
            actors,
            defenders: Mutex::new(HashMap::new()),
            map: Mutex::new(None),
            proc_root: proc_root.into(),
            counters: DefenseCounters::default(),
            memo: Mutex::new(std::collections::VecDeque::new()),
            rescans: Mutex::new((Vec::new(), None)),
            coalesce: Mutex::new(HashMap::new()),
            installer: std::sync::OnceLock::new(),
        }
    }

    /// Wire the trusted-installer window (`main.rs`, once): inside a valid
    /// one a stop or restart of the agent's own units is sanctioned.
    pub fn set_installer_window(&self, window: Arc<TrustedInstallerOverride>) {
        let _ = self.installer.set(window);
    }

    /// Why the finding of `event` was sanctioned, if it was (assessed
    /// already: the memo; `None` otherwise) — for its record.
    pub fn sanction_of(&self, event: &Event) -> Option<String> {
        let key = memo_key(event)?;
        self.memo
            .lock()
            .iter()
            .find(|(k, _)| *k == key)
            .and_then(|(_, f)| f.as_ref().and_then(|f| f.sanctioned.clone()))
    }

    pub fn tools(&self) -> &SecurityTools {
        &self.tools
    }

    pub fn counts(&self) -> DefenseCounts {
        DefenseCounts {
            findings: self.counters.findings.load(Ordering::Relaxed),
            sanctioned: self.counters.sanctioned.load(Ordering::Relaxed),
            defenders: self.counters.defenders.load(Ordering::Relaxed),
            coalesced: self.counters.coalesced.load(Ordering::Relaxed),
        }
    }

    /// Hand over the kernel's `DEFENDER_PIDS` and fill it from `/proc`.
    pub fn attach_map(&self, map: DefenderMap) {
        *self.map.lock() = Some(map);
        self.scan_proc();
    }

    /// The `/proc` scans a tool's exec at `now` asks for
    /// ([`FORK_RESCAN_AFTER`]): the processes it forks are registered by
    /// [`Self::rescan_if_due`].
    pub fn schedule_rescan(&self, now: Instant) {
        let mut r = self.rescans.lock();
        for after in FORK_RESCAN_AFTER {
            if r.0.len() < FORK_RESCANS_MAX {
                r.0.push(now + after);
            }
        }
    }

    /// A scan a tool's exec asked for is due at `now` (and the last one is
    /// at least [`FORK_RESCAN_SPACING`] old).
    pub fn rescan_due(&self, now: Instant) -> bool {
        let r = self.rescans.lock();
        r.0.iter().any(|t| *t <= now)
            && !r
                .1
                .is_some_and(|last| now.saturating_duration_since(last) < FORK_RESCAN_SPACING)
    }

    /// Scan `/proc` again ([`Self::scan_proc`]) when [`Self::rescan_due`];
    /// the agent ticks it. Whether it scanned.
    pub fn rescan_if_due(&self, now: Instant) -> bool {
        if !self.rescan_due(now) {
            return false;
        }
        {
            let mut r = self.rescans.lock();
            r.0.retain(|t| *t > now);
            r.1 = Some(now);
        }
        self.scan_proc();
        true
    }

    /// Register every running process of a listed tool (boot).
    pub fn scan_proc(&self) {
        let Ok(dir) = std::fs::read_dir(&self.proc_root) else {
            return;
        };
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(id) = self.lineage.exec_identity(pid) {
                if let Some(t) = self.tools.tool_of_process(&id) {
                    let name = t.name.clone();
                    self.register(pid, &name);
                }
            }
        }
    }

    fn register(&self, pid: u32, tool: &str) {
        let start = start_ticks(&self.proc_root, pid);
        let mut d = self.defenders.lock();
        // A tool process gone, or its pid now another process's, leaves the
        // set (and the kernel's map).
        let gone: Vec<u32> = d
            .iter()
            .filter(|(p, (_, s))| **p != pid && start_ticks(&self.proc_root, **p) != *s)
            .map(|(p, _)| *p)
            .collect();
        for p in &gone {
            d.remove(p);
        }
        d.insert(pid, (tool.to_string(), start));
        self.counters
            .defenders
            .store(d.len() as u64, Ordering::Relaxed);
        drop(d);
        if let Some(m) = self.map.lock().as_mut() {
            for p in &gone {
                let _ = m.remove(p);
            }
            if let Err(e) = m.insert(pid, 1, 0) {
                tracing::warn!(pid, error = %e, "DEFENDER_PIDS: insert refused");
            }
        }
    }

    /// The tool `pid` was registered as (unless the pid now names another
    /// process), or runs now.
    fn defender(&self, pid: u32) -> Option<String> {
        if let Some((t, start)) = self.defenders.lock().get(&pid) {
            match start_ticks(&self.proc_root, pid) {
                // Gone (the signal ended it), or still the same process.
                None => return Some(t.clone()),
                now if now == *start => return Some(t.clone()),
                _ => {}
            }
        }
        let id = self.lineage.exec_identity(pid)?;
        self.tools.tool_of_process(&id).map(|t| t.name.clone())
    }

    /// The finding `event` is, if any (assessed once per event).
    pub fn assess(&self, event: &Event) -> Option<Finding> {
        let key = memo_key(event)?;
        if let Some((_, f)) = self.memo.lock().iter().find(|(k, _)| *k == key) {
            return f.clone();
        }
        let f = self.assess_once(event);
        let mut memo = self.memo.lock();
        if memo.len() >= MEMO_CAP {
            memo.pop_front();
        }
        memo.push_back((key, f.clone()));
        f
    }

    fn assess_once(&self, event: &Event) -> Option<Finding> {
        let (rule, tool, what, pid, filename, ts) = match event {
            Event::ProcessSpawn {
                pid,
                filename,
                argv,
                exe,
                timestamp_ns,
                ..
            } => {
                let image = exe.path_or(filename).to_string();
                let id = ExecIdentity::of_exec(&image, argv);
                // A tool's own process starting: registered, nothing else —
                // and the processes it forks, a moment later.
                if let Some(t) = self.tools.tool_of_process(&id) {
                    let name = t.name.clone();
                    self.register(*pid, &name);
                    self.schedule_rescan(Instant::now());
                    return None;
                }
                let (rule, tool, what) = self.spawn_finding(&id, argv)?;
                (rule, tool, what, *pid, image, *timestamp_ns)
            }
            Event::DefenderSignal {
                pid,
                target_pid,
                signal,
                timestamp_ns,
                ..
            } => {
                let tool = self.defender(*target_pid)?;
                (
                    EvaRule::Killed,
                    tool.clone(),
                    format!("signal {signal} sent to {tool}'s process {target_pid}"),
                    *pid,
                    String::new(),
                    *timestamp_ns,
                )
            }
            Event::Fim(fe) => {
                let op = match fe.op {
                    FimOp::Modified => "modified",
                    FimOp::Created => "created",
                    FimOp::Deleted => "deleted",
                    FimOp::Renamed => "renamed",
                    FimOp::AttrChanged => "changed (mode or owner)",
                    _ => return None,
                };
                let t = self.tools.tool_of_config(&fe.path)?;
                (
                    EvaRule::ConfigChanged,
                    t.name.clone(),
                    format!("{} {op}", fe.path),
                    fe.modifier_pid,
                    fe.path.clone(),
                    fe.timestamp_ns,
                )
            }
            _ => return None,
        };
        let class = self
            .tools
            .tool(&tool)
            .map(|t| t.class)
            .unwrap_or(ToolClass::Edr);
        let sanctioned = self
            .sanctioned(event, pid, ts)
            .or_else(|| self.own_units_in_window(rule, &tool, &what));
        let suspicious = if sanctioned.is_none() {
            self.suspicious(pid)
        } else {
            None
        };
        // NN-L-EVA-002: a repeat of the command by the same process tree,
        // never on the kill path.
        let (coalesced_into, uid, parent) = match event {
            Event::ProcessSpawn {
                ppid,
                parent_start_ns,
                uid,
                ..
            } if rule == EvaRule::SwitchedOff && suspicious.is_none() => (
                self.coalesce(
                    CoalesceKey {
                        tool: tool.clone(),
                        what: what.clone(),
                        parent: (*ppid, *parent_start_ns),
                        sanctioned: sanctioned.is_some(),
                    },
                    pid,
                    ts,
                ),
                *uid,
                *ppid,
            ),
            _ => (None, 0, 0),
        };
        if let Some(first) = coalesced_into {
            self.counters.coalesced.fetch_add(1, Ordering::Relaxed);
            crate::detection_budget::count_coalesced(SWITCHED_OFF_RULE_ID, uid, || {
                (
                    format!("{tool} {what} {parent}"),
                    format!(
                        "{what} ({tool}) again by the children of pid {parent}, coalesced into \
                         the record of pid {first}"
                    ),
                )
            });
        } else if sanctioned.is_some() {
            self.counters.sanctioned.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.findings.fetch_add(1, Ordering::Relaxed);
        }
        Some(Finding {
            rule,
            tool,
            class,
            what,
            sanctioned,
            suspicious,
            pid,
            filename,
            timestamp_ns: ts,
            coalesced_into,
        })
    }

    /// The process whose record `key` repeats (`pid` at `ts`), within
    /// [`SWITCH_OFF_COALESCE`]; `None` when this is the record — a window
    /// opens on it.
    fn coalesce(&self, key: CoalesceKey, pid: u32, ts: u64) -> Option<u32> {
        let window = SWITCH_OFF_COALESCE.as_nanos() as u64;
        let mut w = self.coalesce.lock();
        if let Some(open) = w.get(&key) {
            // The recorded event itself, assessed again (memo evicted), is
            // never its own repeat.
            if open.pid == pid && open.opened_ns == ts {
                return None;
            }
            // Events reach userland a little out of order across CPUs.
            if ts.abs_diff(open.opened_ns) < window {
                return Some(open.pid);
            }
        }
        if w.len() >= COALESCE_MAX && !w.contains_key(&key) {
            w.retain(|_, o| ts.abs_diff(o.opened_ns) < window);
            if w.len() >= COALESCE_MAX {
                return None;
            }
        }
        w.insert(key, CoalesceWindow { opened_ns: ts, pid });
        None
    }

    fn spawn_finding(
        &self,
        id: &ExecIdentity,
        argv: &[String],
    ) -> Option<(EvaRule, String, String)> {
        let prog = program_name(id, argv);
        let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
        // NN-L-EVA-002: a listed switch-off command.
        if let Some(c) = self.tools.cmds.iter().find(|c| {
            let named = if c.program.starts_with('/') {
                id.exe.to_string_lossy() == c.program.as_str()
                    || id.script.as_deref() == Some(c.program.as_str())
                    || argv.iter().any(|a| a == &c.program)
            } else {
                prog.iter().any(|p| *p == c.program)
            };
            named && contains_run(&args, &c.args)
        }) {
            let shown = if c.args.is_empty() {
                format!("`{}`", c.program)
            } else {
                format!("`{} {}`", c.program, c.args.join(" "))
            };
            return Some((EvaRule::SwitchedOff, c.tool.clone(), shown));
        }
        // NN-L-EVA-001: a listed unit stopped, disabled, masked or killed.
        for (verb, unit) in service_targets(&prog, argv) {
            if let Some((t, u)) = self.tools.tool_of_unit(&unit) {
                return Some((
                    EvaRule::ServiceStopped,
                    t.name.clone(),
                    format!("unit {u} {verb}"),
                ));
            }
        }
        // NN-L-EVA-003: kill, pkill, killall naming a tool's process.
        if prog.contains(&"kill") {
            if kill_signal_is_probe(&args) {
                return None;
            }
            for a in args.iter().filter(|a| !a.starts_with('-')) {
                if let Ok(target) = a.parse::<u32>() {
                    if let Some(tool) = self.defender(target) {
                        return Some((
                            EvaRule::Killed,
                            tool.clone(),
                            format!("`kill` of {tool}'s process {target}"),
                        ));
                    }
                }
            }
        }
        if prog.iter().any(|p| *p == "pkill" || *p == "killall") {
            for a in pattern_args(&args) {
                if let Some(t) = self.tools.tool_of_name(a) {
                    return Some((
                        EvaRule::Killed,
                        t.name.clone(),
                        format!("`{} {a}`", prog[0]),
                    ));
                }
            }
        }
        None
    }

    /// A stop or restart of the agent's own units ([`AGENT_TOOL`]'s
    /// [`AGENT_UNITS`]: `stop`, `force-stop`, `kill` — `systemctl kill` is
    /// how a window restarts it) inside a valid signed trusted-installer
    /// window: the window's grant, named. A disable, mask or freeze, another
    /// tool, no window or an expired one: `None`.
    fn own_units_in_window(&self, rule: EvaRule, tool: &str, what: &str) -> Option<String> {
        if rule != EvaRule::ServiceStopped || tool != AGENT_TOOL {
            return None;
        }
        // `what` is "unit <name> <verb>" for NN-L-EVA-001.
        let mut w = what.split(' ');
        let (Some("unit"), Some(unit), Some(verb), None) = (w.next(), w.next(), w.next(), w.next())
        else {
            return None;
        };
        if !AGENT_UNITS.contains(&unit) || !matches!(verb, "stop" | "force-stop" | "kill") {
            return None;
        }
        let g = self.installer.get()?.current_grant()?;
        Some(format!(
            "inside the signed trusted-installer window of key {} (until {}): a stop or restart \
             of the agent's own unit",
            g.key_id, g.expires_at
        ))
    }

    /// Package transaction, administrator's interactive session, or a
    /// configuration-management actor.
    fn sanctioned(&self, event: &Event, pid: u32, ts: u64) -> Option<String> {
        let package = match event {
            Event::Fim(fe) => self
                .lineage
                .is_package_transaction_write(fe.modifier_pid, fe.timestamp_ns),
            _ => self.lineage.in_package_transaction(pid, ts),
        };
        if package {
            return Some("in a package transaction run by root".to_string());
        }
        if self.lineage.is_interactive_admin(pid) {
            return Some(format!(
                "in an administrator's interactive sudo/su session (login uid {})",
                self.lineage
                    .loginuid_of(pid)
                    .map_or_else(|| "?".to_string(), |u| u.to_string())
            ));
        }
        if let Some(actor) = self.actors.as_ref().and_then(|a| a.actor_of(pid)) {
            return Some(format!(
                "run under {}, a configuration-management actor of process-comm-allowlist",
                actor.display()
            ));
        }
        None
    }

    /// The nearest hop of `pid`'s lineage that runs from a staging
    /// directory, or a deleted or memory-only executable.
    fn suspicious(&self, pid: u32) -> Option<(u32, String)> {
        let hops = self.lineage.lineage_identities(pid)?;
        hops.into_iter().find_map(|(p, id)| {
            let exe = id.exe.to_string_lossy().into_owned();
            let script = id.script.clone().unwrap_or_default();
            let staged = |s: &str| crate::decision::rules::is_staging_path(s);
            let unlinked = exe.ends_with(" (deleted)") || exe.starts_with("/memfd:");
            (staged(&exe) || staged(&script) || unlinked).then(|| {
                (
                    p,
                    if script.is_empty() {
                        exe
                    } else {
                        format!("{exe} {script}")
                    },
                )
            })
        })
    }
}

/// `starttime` of `/proc/<pid>/stat` (field 22, after the `(comm)` field).
fn start_ticks(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// The names a program goes by: its executable's basename and its
/// `argv[0]`'s (`iptables` is `xtables-nft-multi`; a tool named by its
/// `argv[0]` gains nothing from it but a detection).
fn program_name<'a>(id: &'a ExecIdentity, argv: &'a [String]) -> Vec<&'a str> {
    let mut out = Vec::new();
    if let Some(b) = id.exe.file_name().and_then(|b| b.to_str()) {
        out.push(b);
    }
    if let Some(a0) = argv.first() {
        let b = a0.rsplit('/').next().unwrap_or(a0);
        if !out.contains(&b) {
            out.push(b);
        }
    }
    out
}

/// `args` holds `run` as consecutive arguments (an empty run: always).
fn contains_run(args: &[&str], run: &[String]) -> bool {
    if run.is_empty() {
        return true;
    }
    args.windows(run.len())
        .any(|w| w.iter().zip(run).all(|(a, b)| *a == b.as_str()))
}

/// `kill -0 …` (an existence probe), `kill -l` (a listing).
fn kill_signal_is_probe(args: &[&str]) -> bool {
    args.iter().any(|a| {
        matches!(
            *a,
            "-0" | "-l"
                | "-L"
                | "--list"
                | "--table"
                | "-s0"
                | "-SIG0"
                | "-CONT"
                | "-SIGCONT"
                | "-18"
        )
    }) || args
        .windows(2)
        .any(|w| matches!(w[0], "-s" | "-n" | "--signal") && w[1] == "0")
}

/// The pattern arguments of `pkill`/`killall`: what is not an option or
/// an option's value.
fn pattern_args<'a>(args: &[&'a str]) -> Vec<&'a str> {
    const WITH_VALUE: &[&str] = &[
        "-s",
        "--signal",
        "-u",
        "--euid",
        "-U",
        "--uid",
        "-g",
        "--pgroup",
        "-G",
        "--group",
        "-P",
        "--parent",
        "-t",
        "--terminal",
        "--ns",
        "--nslist",
        "-o",
        "--older-than",
        "-y",
        "--younger-than",
        "-n",
        "--session",
        "-c",
        "--cgroup",
        "-F",
        "--pidfile",
    ];
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if WITH_VALUE.contains(a) {
            it.next();
        } else if !a.starts_with('-') {
            out.push(*a);
        }
    }
    out
}

/// `(verb, unit)` pairs a service-manager command stops, disables, masks
/// or kills. `prog`: the program's names.
fn service_targets(prog: &[&str], argv: &[String]) -> Vec<(String, String)> {
    let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    let is = |n: &str| prog.contains(&n);
    let free: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    let mut out = Vec::new();
    if is("systemctl") {
        if args.iter().any(|a| matches!(*a, "--user" | "--global")) {
            return out;
        }
        const WITH_VALUE: &[&str] = &[
            "-H",
            "--host",
            "-M",
            "--machine",
            "-t",
            "--type",
            "-s",
            "--signal",
            "-p",
            "--property",
            "-n",
            "--lines",
            "-o",
            "--output",
            "--kill-whom",
            "--kill-value",
            "--root",
            "--image",
            "--what",
            "--job-mode",
            "--state",
            "--timestamp",
            "--when",
            "--drop-in",
            "--boot-loader-entry",
            "--reboot-argument",
        ];
        let mut words = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if WITH_VALUE.contains(a) {
                it.next();
            } else if !a.starts_with('-') {
                words.push(*a);
            }
        }
        if let Some((verb, units)) = words.split_first() {
            if matches!(*verb, "stop" | "disable" | "mask" | "kill" | "freeze") {
                out.extend(units.iter().map(|u| (verb.to_string(), u.to_string())));
            }
        }
        return out;
    }
    let pair = |name: usize, action: usize, stops: &[&str]| -> Option<(String, String)> {
        let (n, a) = (free.get(name)?, free.get(action)?);
        stops.contains(a).then(|| (a.to_string(), n.to_string()))
    };
    if is("service") || is("invoke-rc.d") || is("rc-service") {
        out.extend(pair(0, 1, &["stop", "force-stop"]));
    } else if is("update-rc.d") {
        out.extend(pair(0, 1, &["disable", "remove"]));
    } else if is("chkconfig") {
        out.extend(pair(0, 1, &["off"]));
    } else if is("rc-update") && free.first() == Some(&"del") {
        out.extend(free.get(1).map(|n| ("del".to_string(), n.to_string())));
    }
    // `/etc/init.d/<name> stop`: the script is an argument of its
    // interpreter's exec.
    for (i, a) in argv.iter().enumerate() {
        if let Some(name) = a.strip_prefix("/etc/init.d/") {
            if argv
                .get(i + 1)
                .is_some_and(|x| matches!(x.as_str(), "stop" | "force-stop"))
            {
                out.push(("stop".to_string(), name.to_string()));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
