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

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::overlay::{self, DefaultsSource, Shipped};
use crate::content_host::ContentHost;
use crate::decision::host::DecisionHost;
use crate::posture::host::PostureHost;
use crate::posture::lineage::{AsOf, AuthSessionTracker, ExecIdentity};
use crate::posture::script_args::Parsed;
use tool_options::{read_listed, Program, SystemTool};
use unit_glob::fnmatch;

/// Deploy location of the list.
pub const SECURITY_TOOLS_V1: &str = "/etc/northnarrow/security-tools.v1";
/// The shipped list, built in.
pub const BUILTIN_SECURITY_TOOLS_V1: &str =
    include_str!(concat!(env!("NN_REPO_ROOT"), "/configs/security-tools.v1"));
/// SHA-256 of every `security-tools.v1` an earlier release shipped.
pub const EARLIER_SECURITY_TOOLS_V1_SHA256: &[&str] = &[
    // lab PR 225 to lot 316 (before the units' aliases)
    "38cef57a92f6b394be9307c0f16e8799d553d0cff7bb6d7fd3db0b3906736335",
];
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
    pub fn load<H: ContentHost>(path: &Path) -> (Self, DefaultsSource) {
        overlay::load_pinned_defaults::<H, _>(
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
    /// glob `falcon*`): the first of [`Self::tools_of_unit`].
    pub fn tool_of_unit(&self, arg: &str) -> Option<(&Tool, String)> {
        self.tools_of_unit(arg).into_iter().next()
    }

    /// Every listed unit a unit argument names, with its tool: one for a
    /// name (`auditd`, `auditd.service`); for a glob (`falcon*`), lot 316,
    /// every one systemctl matches among the units in memory —
    /// `fnmatch(…, FNM_NOESCAPE)` on the unit's full name ([`unit_glob`]:
    /// `falcon*`, `*uditd*`, `audit?.service`, `[[:alpha:]]uditd.service`,
    /// `snap.*.service`). Linear in the pattern and the name: a glob of many
    /// stars never holds the decision thread (the review of #548, F1).
    pub fn tools_of_unit(&self, arg: &str) -> Vec<(&Tool, String)> {
        let key = unit_key(arg);
        let glob = arg.contains(['*', '?', '[']);
        let mut out = Vec::new();
        for t in &self.tools {
            for u in &t.units {
                let full = full_unit_name(u);
                let named = if glob { fnmatch(arg, &full) } else { *u == key };
                if named {
                    out.push((t, u.clone()));
                }
            }
        }
        out
    }

    /// The tool whose process `id` is (its executable, or the script an
    /// interpreter runs, is a listed `proc`).
    pub fn tool_of_process(&self, id: &ExecIdentity) -> Option<&Tool> {
        let exe = id.exe.to_string_lossy();
        let paths: Vec<&str> = std::iter::once(exe.as_ref())
            // lot 292: what an argv whose options could not be read may
            // run — a tool is registered to be watched, which trusts nothing
            .chain(id.runs.mentioned().filter(|s| s.starts_with('/')))
            .collect();
        // Lot 316 (BUG-86): the program of a listed switch-off command (a
        // cloud agent's uninstaller, in its own tool's tree) is that command
        // run, never the tool's process starting
        if self
            .cmds
            .iter()
            .any(|c| c.program.starts_with('/') && paths.contains(&c.program.as_str()))
        {
            return None;
        }
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
        self.tool_of_pattern(name, NameMatch::default())
    }

    /// Lot 316: the tool a name given to `pkill` or `killall` names, as
    /// the tool matches it ([`NameMatch`]): a part of the name (pkill's
    /// pattern, unless `-x`) at least half of it, in any case (`-i`,
    /// killall's `-I`), the full
    /// path of a listed program or tree (pkill's `-f`; killall's name with a
    /// `/`, which it matches against the executable).
    fn tool_of_pattern(&self, name: &str, m: NameMatch) -> Option<&Tool> {
        let name = name.trim_start_matches('^').trim_end_matches('$');
        if name.is_empty() || name.len() < 3 {
            return None;
        }
        let fold = |s: &str| {
            if m.ignore_case {
                s.to_lowercase()
            } else {
                s.to_string()
            }
        };
        let want = fold(name);
        // a part names a program when it is at least half of its name: `pkill
        // audit` ends auditd, `pkill -f agent` is no listed agent's (it may
        // be anyone's; what it ends is seen on `task_kill`)
        let hit = |have: &str| {
            let have = fold(have);
            if m.part {
                have.contains(&want) && 2 * want.chars().count() >= have.chars().count()
            } else {
                have == want
            }
        };
        self.tools.iter().find(|t| {
            let by_path = || {
                t.procs.iter().any(|p| {
                    if m.full {
                        hit(p) || (p.ends_with('/') && want.starts_with(&fold(p)))
                    } else if m.path && name.contains('/') {
                        // killall: the executable itself, or one of a tree,
                        // its path read as stat() reads it (`//usr/sbin/x`,
                        // `/usr/bin/../sbin/x`: the review of #548, F10)
                        let want = fold(&lexical_path(name));
                        want == fold(p) || (p.ends_with('/') && want.starts_with(&fold(p)))
                    } else {
                        false
                    }
                })
            };
            // a unit's name, as a process's, in full
            t.units.iter().any(|u| fold(u) == want)
                || t.procs.iter().filter(|p| !p.ends_with('/')).any(|p| {
                    let base = p.rsplit('/').next().unwrap_or(p);
                    hit(base) || (want.len() == 15 && fold(base).starts_with(&want))
                })
                || by_path()
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

/// The detector the rules and the posture share.
pub struct DefenseDetector<H: DecisionHost> {
    tools: Arc<SecurityTools>,
    lineage: AuthSessionTracker<H>,
    actors: Option<Arc<CommAllowlist<H>>>,
    /// Registered tool processes: pid → (tool, start in clock ticks).
    defenders: Mutex<HashMap<u32, (String, Option<u64>)>>,
    map: Mutex<Option<H::DefenderMap>>,
    proc_root: PathBuf,
    /// The re-check of #548 (N4): the cgroup tree's root (`/sys/fs/cgroup`),
    /// where a unit's processes are listed ([`Self::with_cgroup_root`]).
    cgroup_root: PathBuf,
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
    installer: std::sync::OnceLock<Arc<H::InstallerWindow>>,
    /// Lot 282: which programs a package installed — a container runtime's
    /// own chain flush is vouched for by its packaged program
    /// ([`Self::flushed_by_its_runtime`]). The host's package database in
    /// production; a fixture's in the replays and tests
    /// ([`Self::with_program_owners`]).
    owners: crate::impact::trust::ProgramOwners<H>,
}

/// Lot 282 (Tappa Prove P0; the coordinator's review of the design): the
/// chains of the container runtimes and orchestrators — CNI's (`CNI-…`),
/// Docker's (`DOCKER…`), kube-proxy's (`KUBE-…`), Calico's (`cali-…`),
/// Cilium's (`cilium_…`), netavark's (`NETAVARK…`). Their flush by the
/// runtime that owns them is its own networking at work (podman's CNI
/// plugin at a container's removal, dockerd at its start), not a firewall
/// switched off. The chains among them whose function is filtering
/// ([`FILTER_CHAINS`]) are not. The host firewall's chains — ufw's
/// (`ufw-…`), fail2ban's (`f2b-…`), firewalld's zones, the built-in ones —
/// hold its filtering: emptied by anyone, the firewall is off.
const RUNTIME_CHAIN_PREFIXES: &[&str] =
    &["CNI-", "DOCKER", "KUBE-", "cali-", "cilium_", "NETAVARK"];

/// Lot 282, the review of #500 (C2): the chains a runtime creates whose
/// function is a firewall's, judged as the host firewall's whoever flushes
/// them — `DOCKER-USER` (the administrator's own rules for the containers'
/// traffic), `CNI-ADMIN` (the same for CNI's `firewall` plugin) and
/// `KUBE-FIREWALL` (kube-proxy's and the kubelet's drop of marked packets,
/// the guard of `route_localnet`). No runtime empties them at its start or
/// at a container's removal.
const FILTER_CHAINS: &[&str] = &["DOCKER-USER", "CNI-ADMIN", "KUBE-FIREWALL"];

/// Lot 282: a chain of [`RUNTIME_CHAIN_PREFIXES`] that is no filter chain
/// ([`FILTER_CHAINS`]).
fn is_runtime_chain(chain: &str) -> bool {
    !FILTER_CHAINS.contains(&chain) && RUNTIME_CHAIN_PREFIXES.iter().any(|p| chain.starts_with(p))
}

/// Lot 282: the programs that flush a runtime's chains when they are the
/// runtime — the CNI plugins' directories (Debian and Ubuntu, Fedora and
/// RHEL), and the runtimes that run `iptables` themselves. Judged on what
/// the kernel executed for the flushing `iptables`'s parent, in a system
/// tree and installed by a package ([`DefenseDetector::flushed_by_its_runtime`]):
/// never a name or a path alone.
const RUNTIME_PROGRAM_DIRS: &[&str] = &["/usr/lib/cni/", "/usr/libexec/cni/"];
const RUNTIME_PROGRAMS: &[&str] = &[
    "/usr/bin/containerd",
    "/usr/bin/crio",
    "/usr/bin/dockerd",
    "/usr/bin/kube-proxy",
    "/usr/bin/kubelet",
    "/usr/bin/podman",
    "/usr/lib/podman/netavark",
    "/usr/libexec/podman/netavark",
    "/usr/sbin/dockerd",
];

/// Lot 282: `exe` is one of [`RUNTIME_PROGRAMS`] or a plugin of
/// [`RUNTIME_PROGRAM_DIRS`] (a file directly in it).
fn is_runtime_program(exe: &Path) -> bool {
    let e = exe.to_string_lossy();
    RUNTIME_PROGRAMS.contains(&e.as_ref())
        || RUNTIME_PROGRAM_DIRS.iter().any(|d| {
            e.strip_prefix(d)
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        })
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

impl<H: DecisionHost> DefenseDetector<H> {
    pub fn new(
        tools: Arc<SecurityTools>,
        lineage: AuthSessionTracker<H>,
        actors: Option<Arc<CommAllowlist<H>>>,
    ) -> Self {
        Self::with_proc_root(tools, lineage, actors, H::PROC_ROOT)
    }

    /// With a `/proc` of its own (tests).
    pub fn with_proc_root(
        tools: Arc<SecurityTools>,
        lineage: AuthSessionTracker<H>,
        actors: Option<Arc<CommAllowlist<H>>>,
        proc_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            tools,
            lineage,
            actors,
            defenders: Mutex::new(HashMap::new()),
            map: Mutex::new(None),
            proc_root: proc_root.into(),
            cgroup_root: Path::new(H::HOST_ROOT).join("sys/fs/cgroup"),
            counters: DefenseCounters::default(),
            memo: Mutex::new(std::collections::VecDeque::new()),
            rescans: Mutex::new((Vec::new(), None)),
            coalesce: Mutex::new(HashMap::new()),
            installer: std::sync::OnceLock::new(),
            owners: crate::impact::trust::ProgramOwners::default(),
        }
    }

    /// With a cgroup tree of its own (tests).
    pub fn with_cgroup_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.cgroup_root = root.into();
        self
    }

    /// Lot 282: judge package ownership on `owners` (a replay's fixture,
    /// a test's) instead of the host's package database.
    pub fn with_program_owners(mut self, owners: crate::impact::trust::ProgramOwners<H>) -> Self {
        self.owners = owners;
        self
    }

    /// Lot 282: the `iptables` process `pid` was executed by a container
    /// runtime flushing its own chain — its parent (what the kernel
    /// executed for it) is a runtime program ([`is_runtime_program`]: in a
    /// system tree by construction) installed by a package. A parent that
    /// cannot be read, a shell, an unpackaged copy (`/opt/cni/bin`, k3s's
    /// bundled tools) or a host with no package database vouches for
    /// nothing.
    fn flushed_by_its_runtime(&self, pid: u32, as_of: AsOf) -> bool {
        let parent = self.lineage.parent_identity(pid, as_of);
        let runtime = parent.as_ref().is_some_and(|p| is_runtime_program(&p.exe));
        let packaged = parent
            .as_ref()
            .filter(|_| runtime)
            .and_then(|p| self.owners.owned(&p.exe));
        let vouched = runtime && packaged == Some(true);
        if !vouched {
            // Recorded, not silent: why a runtime's chain flush is a
            // switch-off (the lab reads it).
            tracing::info!(
                pid,
                parent = %parent.as_ref().map_or_else(
                    || "unknown".to_string(),
                    |p| p.exe.to_string_lossy().into_owned()
                ),
                runtime_program = runtime,
                packaged = ?packaged,
                "NN-L-EVA-002: a container runtime's chain flushed by a process its runtime \
                 does not vouch for — still the firewall switched off"
            );
        }
        vouched
    }

    /// Wire the trusted-installer window (`main.rs`, once): inside a valid
    /// one a stop or restart of the agent's own units is sanctioned.
    pub fn set_installer_window(&self, window: Arc<H::InstallerWindow>) {
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
    pub fn attach_map(&self, map: H::DefenderMap) {
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
        let Ok(dir) = H::read_dir(&self.proc_root) else {
            return;
        };
        for e in dir.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            // the boot's scan (and its rescans): the processes running now
            if let Some(id) = self.lineage.exec_identity(pid, AsOf::Now) {
                if let Some(t) = self.tools.tool_of_process(&id) {
                    let name = t.name.clone();
                    self.register(pid, &name);
                }
            }
        }
    }

    fn register(&self, pid: u32, tool: &str) {
        let start = start_ticks::<H>(&self.proc_root, pid);
        let mut d = self.defenders.lock();
        // A tool process gone, or its pid now another process's, leaves the
        // set (and the kernel's map).
        let gone: Vec<u32> = d
            .iter()
            .filter(|(p, (_, s))| **p != pid && start_ticks::<H>(&self.proc_root, **p) != *s)
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
                H::defender_map_remove(m, *p);
            }
            if let Err(e) = H::defender_map_insert(m, pid) {
                tracing::warn!(pid, error = %e, "DEFENDER_PIDS: insert refused");
            }
        }
    }

    /// The tool `pid` was registered as (unless the pid now names another
    /// process), or ran as of `as_of` (R12b, R-F: the judged event's time;
    /// in a judgement the spawn cache only).
    fn defender(&self, pid: u32, as_of: AsOf) -> Option<String> {
        if let Some((t, start)) = self.defenders.lock().get(&pid) {
            match start_ticks::<H>(&self.proc_root, pid) {
                // Gone (the signal ended it), or still the same process.
                None => return Some(t.clone()),
                now if now == *start => return Some(t.clone()),
                _ => {}
            }
        }
        let id = self.lineage.exec_identity(pid, as_of)?;
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
        // R12b (R-F): the lineage as of the event's own time
        let as_of = AsOf::of_event(event);
        // NN-L-EVA-001: the verb and every listed unit the command names
        let mut stopped: Option<UnitsStopped> = None;
        let mut reload: Option<Reload> = None;
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
                let asked = self.spawn_finding(*pid, &id, argv, as_of)?;
                stopped = asked.stopped;
                reload = asked.reload;
                (
                    asked.rule,
                    asked.tool,
                    asked.what,
                    *pid,
                    image,
                    *timestamp_ns,
                )
            }
            Event::DefenderSignal {
                pid,
                target_pid,
                signal,
                timestamp_ns,
                ..
            } => {
                let tool = self.defender(*target_pid, as_of)?;
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
            .or_else(|| self.own_units_in_window(stopped.as_ref()))
            .or_else(|| self.reload_caught(reload.as_ref()));
        let suspicious = if sanctioned.is_none() {
            self.suspicious(pid, as_of)
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
        pid: u32,
        id: &ExecIdentity,
        argv: &[String],
        as_of: AsOf,
    ) -> Option<Asked> {
        // lot 316: the program by its names (the xtables multi-call
        // binary's included), and where its own arguments start
        let prog = Program::of(&id.exe, argv);
        let args: Vec<&str> = argv
            .iter()
            .skip(prog.args_from)
            .map(String::as_str)
            .collect();
        // NN-L-EVA-002: a listed switch-off command.
        for c in &self.tools.cmds {
            let named = if c.program.starts_with('/') {
                id.exe.to_string_lossy() == c.program.as_str()
                    || id.runs.mentioned() == Some(c.program.as_str())
                    || argv.iter().any(|a| a == &c.program)
            } else {
                prog.is(&c.program)
            };
            if !named {
                continue;
            }
            // lot 316 (N4): a tool with a table is read by it — the
            // listed command's options by name, whatever their spelling
            let understood = match SystemTool::named(&c.program) {
                Some(tool) => {
                    let listed = read_listed(tool, &c.args);
                    let by_its_runtime = || self.flushed_by_its_runtime(pid, as_of);
                    tool.read(argv, prog.args_from)
                        .iter()
                        .find(|r| holds(tool, r, &listed, &by_its_runtime))
                        .map(|r| r.understood)
                }
                None => switches_off(&args, &c.args).then_some(true),
            };
            let Some(understood) = understood else {
                continue;
            };
            let shown = if c.args.is_empty() {
                format!("`{}`", c.program)
            } else {
                format!("`{} {}`", c.program, c.args.join(" "))
            };
            return Some(Asked::of(
                EvaRule::SwitchedOff,
                c.tool.clone(),
                with_reading(shown, understood),
            ));
        }
        // NN-L-EVA-001: a listed unit stopped, disabled, masked or killed;
        // lot 316 (BUG-96): every unit of the command, the finding named by
        // another tool's before the agent's own
        let mut units: Vec<(String, String, String)> = Vec::new();
        let mut understood = true;
        let mut signals: Vec<Option<u8>> = Vec::new();
        for t in service_targets(&prog, argv) {
            for (tool, u) in self.tools.tools_of_unit(&t.unit) {
                if !units.iter().any(|(n, x, _)| *n == tool.name && *x == u) {
                    units.push((tool.name.clone(), u, t.verb.clone()));
                }
                understood &= t.understood;
                signals.push(t.reload);
            }
        }
        if !units.is_empty() {
            let first = units
                .iter()
                .position(|(n, _, _)| n != AGENT_TOOL)
                .unwrap_or(0);
            let (tool, unit, unit_verb) = units[first].clone();
            let others: Vec<&str> = units
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != first)
                .map(|(_, (_, u, _))| u.as_str())
                .collect();
            let mut what = format!("unit {unit} {unit_verb}");
            if !others.is_empty() {
                // a glob or an isolate names many: the first five, and how
                // many more
                let shown: Vec<&str> = others.iter().take(5).copied().collect();
                let more = others.len() - shown.len();
                what.push_str(&format!(" (with {}", shown.join(", ")));
                if more > 0 {
                    what.push_str(&format!(" and {more} more"));
                }
                what.push(')');
            }
            // the review of #548 (F12): `systemctl -s HUP kill` of units
            // whose processes catch the signal, every reading of the argv
            // sending it (the re-check, N1: `ServiceTarget::reload`); the
            // re-check (N4): `systemctl kill` reaches every process of the
            // unit's cgroup, and each must catch it
            let signal = match signals.split_first() {
                Some((first, rest)) if rest.iter().all(|s| s == first) => *first,
                _ => None,
            };
            let reload = signal
                .filter(|_| units.iter().all(|(_, _, v)| v == "kill"))
                .and_then(|signal| {
                    let mut pids = Vec::new();
                    for (tool, unit, _) in &units {
                        pids.extend(self.unit_pids(tool, unit)?);
                    }
                    Some(Reload {
                        signal,
                        pids,
                        tools: units.iter().map(|(n, _, _)| n.clone()).collect(),
                    })
                });
            return Some(Asked {
                rule: EvaRule::ServiceStopped,
                tool,
                what: with_reading(what, understood),
                stopped: Some(UnitsStopped {
                    verbs: units.iter().map(|(_, _, v)| v.clone()).collect(),
                    units: units.into_iter().map(|(n, u, _)| (n, u)).collect(),
                }),
                reload,
            });
        }
        // NN-L-EVA-003: kill, pkill, killall naming a tool's process.
        match prog.tool() {
            Some(SystemTool::Kill) => {
                let readings = SystemTool::Kill.read(argv, prog.args_from);
                // the first tool's process a reading signals names the
                // finding; every one any reading signals is reached
                let mut asked: Option<Asked> = None;
                let mut reached: Vec<(u32, String)> = Vec::new();
                for r in &readings {
                    if kill_is_probe(r) {
                        continue;
                    }
                    for a in &r.operands {
                        let Some(target) = pid_of(a) else {
                            continue;
                        };
                        let Some(tool) = self.defender(target, as_of) else {
                            continue;
                        };
                        asked.get_or_insert_with(|| {
                            Asked::of(
                                EvaRule::Killed,
                                tool.clone(),
                                with_reading(
                                    format!("`kill` of {tool}'s process {target}"),
                                    r.understood,
                                ),
                            )
                        });
                        if !reached.iter().any(|(p, _)| *p == target) {
                            reached.push((target, tool));
                        }
                    }
                }
                let mut asked = asked?;
                // the review of #548 (F12): a reload signal every process
                // reached catches; the re-check (N1): the signal every
                // reading sends (procps' TERM when it names none)
                asked.reload = one_reload(
                    readings
                        .iter()
                        .map(|r| r.understood.then(|| kill_signal(r).unwrap_or("TERM"))),
                )
                .and_then(|signal| {
                    Some(Reload {
                        signal,
                        pids: reached
                            .iter()
                            .map(|(p, _)| self.registered(*p))
                            .collect::<Option<Vec<u32>>>()?,
                        tools: reached.iter().map(|(_, t)| t.clone()).collect(),
                    })
                });
                return Some(asked);
            }
            Some(tool @ (SystemTool::Pkill | SystemTool::Killall)) => {
                for r in tool.read(argv, prog.args_from) {
                    let m = NameMatch::of(tool, &r);
                    for a in &r.operands {
                        if let Some(t) = self.tools.tool_of_pattern(a, m) {
                            let name = if tool == SystemTool::Pkill {
                                "pkill"
                            } else {
                                "killall"
                            };
                            return Some(Asked::of(
                                EvaRule::Killed,
                                t.name.clone(),
                                with_reading(format!("`{name} {a}`"), r.understood),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// A stop or restart of the agent's own units ([`AGENT_TOOL`]'s
    /// [`AGENT_UNITS`]: `stop`, `force-stop`, `kill` — `systemctl kill` is
    /// how a window restarts it) inside a valid signed trusted-installer
    /// window: the window's grant, named. A disable, mask or freeze, another
    /// tool, no window or an expired one: `None`. Lot 316 (BUG-96): every
    /// listed unit the command stops must be the agent's own — auditd
    /// stopped with the agent is High as anywhere.
    fn own_units_in_window(&self, stopped: Option<&UnitsStopped>) -> Option<String> {
        let stopped = stopped?;
        let own = |(tool, unit): &(String, String)| {
            tool == AGENT_TOOL && AGENT_UNITS.contains(&unit.as_str())
        };
        let restart =
            |verb: &String| matches!(verb.as_str(), "stop" | "condstop" | "force-stop" | "kill");
        if stopped.units.is_empty()
            || !stopped.units.iter().all(own)
            || !stopped.verbs.iter().all(restart)
        {
            return None;
        }
        let g = H::installer_grant(self.installer.get()?)?;
        Some(format!(
            "inside the signed trusted-installer window of key {} (until {}): a stop or restart \
             of the agent's own unit",
            g.key_id, g.expires_at
        ))
    }

    /// The registered processes of the tools `tools`, still the process
    /// registered.
    fn defender_pids<'t>(&self, tools: impl Iterator<Item = &'t str>) -> Vec<u32> {
        let tools: Vec<&str> = tools.collect();
        let d = self.defenders.lock();
        let mut pids: Vec<u32> = d
            .iter()
            .filter(|(p, (t, start))| {
                tools.contains(&t.as_str())
                    && start.is_some()
                    && start_ticks::<H>(&self.proc_root, **p) == *start
            })
            .map(|(p, _)| *p)
            .collect();
        pids.sort_unstable();
        pids
    }

    /// `pid`, when it is a registered process still the one registered.
    fn registered(&self, pid: u32) -> Option<u32> {
        let d = self.defenders.lock();
        let (_, start) = d.get(&pid)?;
        (start.is_some() && start_ticks::<H>(&self.proc_root, pid) == *start).then_some(pid)
    }

    /// The re-check of #548 (N4): every process of the listed unit `unit`
    /// of `tool` — the processes of its cgroup, which `systemctl kill`
    /// signals (`--kill-whom=all`, the default). The cgroup is the one a
    /// registered process of the tool runs in, its path down to the unit's
    /// own name (`0::/system.slice/rsyslog.service`). `None` when no
    /// registered process runs in it (an alias's name, a unit not
    /// running), when it cannot be read, or when it has cgroups below it
    /// (a delegated tree: its processes are not all listed here).
    fn unit_pids(&self, tool: &str, unit: &str) -> Option<Vec<u32>> {
        let full = full_unit_name(unit);
        let dir = self
            .defender_pids(std::iter::once(tool))
            .into_iter()
            .find_map(|pid| {
                let text =
                    H::read_state(self.proc_root.join(pid.to_string()).join("cgroup")).ok()?;
                let path = text.lines().find_map(|l| l.strip_prefix("0::"))?;
                let parts: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
                let at = parts.iter().position(|c| *c == full)?;
                Some(
                    parts[..=at]
                        .iter()
                        .fold(self.cgroup_root.clone(), |d, c| d.join(c)),
                )
            })?;
        for e in H::read_dir(&dir).ok()? {
            if e.ok()?.file_type().ok()?.is_dir() {
                return None;
            }
        }
        let procs = H::read_state(dir.join("cgroup.procs")).ok()?;
        let pids: Vec<u32> = procs
            .lines()
            .map(|l| l.trim().parse().ok())
            .collect::<Option<_>>()?;
        (!pids.is_empty()).then_some(pids)
    }

    /// The review of #548 (F12): a reload signal every process it reaches
    /// catches (`SigCgt` of `/proc/<pid>/status` has its bit) is no stop: a
    /// Low record, named. A process that does not catch it, none known or
    /// one unreadable: no sanction (it ends, and is judged). The re-check
    /// (N3): only a signal every tool reached documents as its reload
    /// ([`RELOADS`]).
    fn reload_caught(&self, reload: Option<&Reload>) -> Option<String> {
        let r = reload?;
        if r.pids.is_empty()
            || !r
                .tools
                .iter()
                .all(|t| RELOADS.contains(&(t.as_str(), r.signal)))
        {
            return None;
        }
        let bit = 1u64 << (r.signal - 1);
        for pid in &r.pids {
            let status = H::read_state(self.proc_root.join(pid.to_string()).join("status")).ok()?;
            let mask = status
                .lines()
                .find_map(|l| l.strip_prefix("SigCgt:"))
                .and_then(|m| u64::from_str_radix(m.trim(), 16).ok())?;
            if mask & bit == 0 {
                return None;
            }
        }
        let pids: Vec<String> = r.pids.iter().map(u32::to_string).collect();
        Some(format!(
            "SIGHUP, which the tool's process {} catches (SigCgt): a reload, no stop",
            pids.join(", ")
        ))
    }

    /// Package transaction, administrator's interactive session, or a
    /// configuration-management actor.
    fn sanctioned(&self, event: &Event, pid: u32, ts: u64) -> Option<String> {
        // R12b (R-F): as of the event's time
        let package = match event {
            Event::Fim(fe) => self
                .lineage
                .is_package_transaction_write(fe.modifier_pid, AsOf::judged(fe.timestamp_ns)),
            _ => self.lineage.in_package_transaction(pid, AsOf::judged(ts)),
        };
        if package {
            return Some("in a package transaction run by root".to_string());
        }
        if self.lineage.is_interactive_admin(pid, AsOf::judged(ts)) {
            return Some(format!(
                "in an administrator's interactive sudo/su session (login uid {})",
                self.lineage
                    .loginuid_of(pid)
                    .map_or_else(|| "?".to_string(), |u| u.to_string())
            ));
        }
        if let Some(actor) = self
            .actors
            .as_ref()
            .and_then(|a| a.actor_of(pid, AsOf::judged(ts)))
        {
            return Some(format!(
                "run under {}, a configuration-management actor of process-comm-allowlist",
                actor.display()
            ));
        }
        None
    }

    /// The nearest hop of `pid`'s lineage that runs from a staging
    /// directory, or a deleted or memory-only executable — among the hops
    /// read, below a cut too (it looks for one: the re-check 4 of #539).
    fn suspicious(&self, pid: u32, as_of: AsOf) -> Option<(u32, String)> {
        let hops = self.lineage.lineage_identities_seen(pid, as_of)?;
        hops.into_iter().find_map(|(p, id)| {
            let exe = id.exe.to_string_lossy().into_owned();
            // lot 292: what an argv whose options could not be read may run
            let script = id.runs.mentioned().unwrap_or_default().to_string();
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
fn start_ticks<H: PostureHost>(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = H::read_state(proc_root.join(pid.to_string()).join("stat")).ok()?;
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// Lot 316: what an exec asked, before it is judged.
struct Asked {
    rule: EvaRule,
    tool: String,
    what: String,
    /// NN-L-EVA-001: what the command stops.
    stopped: Option<UnitsStopped>,
    /// A reload signal (HUP) to the tool's processes, which a catch of it
    /// makes no stop.
    reload: Option<Reload>,
}

impl Asked {
    fn of(rule: EvaRule, tool: String, what: String) -> Self {
        Self {
            rule,
            tool,
            what,
            stopped: None,
            reload: None,
        }
    }
}

/// The review of #548 (F12): a reload signal sent to a tool's processes —
/// `systemctl -s HUP kill rsyslog.service`, `kill -HUP <pid>`.
struct Reload {
    /// Its number (1).
    signal: u8,
    /// The processes it reaches: `kill`'s, still the process registered
    /// (their start read back); `systemctl kill`'s, every process of each
    /// unit's cgroup (N4).
    pids: Vec<u32>,
    /// The tools it reaches.
    tools: Vec<String>,
}

/// The re-check of #548 (N3): the signals a tool documents as a reload,
/// which leaves it running — a tool and a signal not listed here are
/// judged as any other signal. SIGHUP only: auditd's SIGUSR1 rotates its
/// logs (with `num_logs`, five in a row delete the older ones), rsyslogd's
/// toggles debugging.
/// - auditd(8): SIGHUP makes auditd reconfigure (re-read `auditd.conf`);
/// - rsyslogd(8): SIGHUP closes the open files (logrotate's
///   `rsyslog-rotate`);
/// - firewalld(1): SIGHUP reloads the configuration (its unit's
///   `ExecReload`);
/// - falco: SIGHUP restarts its engine on the configuration and rules
///   (hot reload).
const RELOADS: [(&str, u8); 4] = [
    ("auditd", 1),
    ("rsyslog", 1),
    ("firewalld", 1),
    ("falco", 1),
];

/// SIGHUP, by name (`HUP`, `SIGHUP`, any case) or number: the signal a
/// daemon catches to reload or reopen its logs. Any other: none.
fn reload_signal(s: &str) -> Option<u8> {
    let up = s.to_ascii_uppercase();
    match up.strip_prefix("SIG").unwrap_or(&up) {
        "HUP" | "1" => Some(1),
        _ => None,
    }
}

/// The re-check of #548 (N1): the reload signal every reading of an argv
/// sends — `None` for a reading not understood (its signal unknown), and
/// when they differ: under `POSIXLY_CORRECT`, `systemctl kill rsyslog -s
/// HUP` and `kill <pid> -s HUP` send TERM.
fn one_reload<'a>(each: impl IntoIterator<Item = Option<&'a str>>) -> Option<u8> {
    let mut each = each.into_iter().map(|s| s.and_then(reload_signal));
    let first = each.next()??;
    each.all(|s| s == Some(first)).then_some(first)
}

/// The review of #548 (F9): a pid as procps' `strtol_or_err` reads it —
/// leading blanks and a `+` skipped, digits to the end.
fn pid_of(a: &str) -> Option<u32> {
    let t = a.trim_start_matches(|c: char| c.is_ascii_whitespace() || c == '\x0b');
    let t = t.strip_prefix('+').unwrap_or(t);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// Lot 316 (BUG-96): every listed unit a service-manager command names —
/// its tool and unit — and the verb each is named with.
struct UnitsStopped {
    units: Vec<(String, String)>,
    verbs: Vec<String>,
}

/// `what`, said as read from an argv not understood (an option its table
/// does not hold: the over-approximation of the reader).
fn with_reading(what: String, understood: bool) -> String {
    if understood {
        what
    } else {
        format!("{what} (options not understood)")
    }
}

/// `args` holds the switch-off command `run` as consecutive arguments (an
/// empty run: always) — for a program with no table of its own
/// ([`tool_options`]: `auditctl`, `ufw`, `setenforce`, the uninstallers).
fn switches_off(args: &[&str], run: &[String]) -> bool {
    run.is_empty()
        || args
            .windows(run.len())
            .any(|w| w.iter().zip(run).all(|(a, b)| *a == b.as_str()))
}

/// Lot 316 (N4): the reading `r` of a tool's argv holds the listed command
/// `listed`, read by the same table: each of its options, by name, with its
/// arguments when the list gives them (`iptables -F` is a flush of any
/// chain, `-P INPUT ACCEPT` that policy), and its operands next to each
/// other (`nft flush ruleset`, nft's words). Lot 282 (Tappa Prove P0):
/// except a flush of a container runtime's own chain ([`is_runtime_chain`])
/// that the runtime itself runs (`by_its_runtime`, asked only then).
/// Podman's CNI plugin flushes its NAT chain (`iptables -t nat -F CNI-…`)
/// at a container's removal: NN-L-EVA-002 recorded "`iptables -F`", and the
/// posture's DefenseImpairment, recorded in the administrator's scope,
/// corroborated podman's own mass write — COMBAT, locked, and the ladder
/// killed podman (lab 04/11, on main). The same chain flushed by any other
/// process, and any other chain — the host firewall's (ufw, fail2ban,
/// firewalld), a built-in one, every chain of a table (no chain named) — is
/// still the firewall switched off.
fn holds(
    tool: SystemTool,
    r: &Parsed<'_>,
    listed: &Parsed<'_>,
    by_its_runtime: &dyn Fn() -> bool,
) -> bool {
    let flush = |name: &str| tool == SystemTool::Iptables && name == tool_options::IPTABLES_FLUSH;
    let options = listed.options.iter().all(|(name, values)| {
        r.option(name).any(|v| {
            (values.is_empty() || v == values.as_slice())
                && !(flush(name)
                    && values.is_empty()
                    && v.first().is_some_and(|chain| is_runtime_chain(chain))
                    && by_its_runtime())
        })
    });
    let operands = listed.operands.is_empty()
        || r.operands
            .windows(listed.operands.len())
            .any(|w| w == listed.operands.as_slice());
    options && operands
}

/// The review of #548 (F8): the signal procps' `kill` sends for the
/// reading `r` — the last `-s`/`--signal`, else the first `-SIGNAL` word
/// (`skill_sig_option` takes it before the options are read): `kill -s KILL
/// -0 <pid>` kills.
fn kill_signal<'a>(r: &Parsed<'a>) -> Option<&'a str> {
    r.option("s")
        .filter_map(|v| v.first().copied())
        .last()
        .or_else(|| {
            r.option(crate::posture::script_args::SIGNAL)
                .filter_map(|v| v.first().copied())
                .next()
        })
}

/// Lot 316: `kill`'s reading `r` sends no signal that stops — an existence
/// probe (`-0`, `-s 0`, `-SIG0`), `SIGCONT`, or a listing (`-l`, `-L`,
/// help, version: procps' kill prints and exits). Never for an argv not
/// understood, whose signal is not known.
fn kill_is_probe(r: &Parsed<'_>) -> bool {
    if !r.understood {
        return false;
    }
    if ["l", "L", "h", "V"].iter().any(|o| r.has(o)) {
        return true;
    }
    kill_signal(r).is_some_and(|s| {
        let up = s.to_ascii_uppercase();
        let name = up.strip_prefix("SIG").unwrap_or(&up);
        matches!(name, "0" | "CONT" | "18")
    })
}

/// The review of #548 (F10): an absolute path with `//`, `.` and `..` folded
/// as the kernel walks them (symbolic links aside).
fn lexical_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for c in p.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

/// Lot 316: how `pkill` or `killall` matches a name to a process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NameMatch {
    /// A part of the name is enough (pkill's pattern, a regular expression
    /// searched in the name, unless `-x`; killall's `-r`).
    part: bool,
    /// Against the full command line (pkill's `-f`).
    full: bool,
    /// In any case (pkill's `-i`, killall's `-I`).
    ignore_case: bool,
    /// A name with a `/` is the executable (killall).
    path: bool,
}

impl NameMatch {
    /// As `tool`'s reading `r` asks; for an argv not understood, every
    /// way at once.
    fn of(tool: SystemTool, r: &Parsed<'_>) -> Self {
        if !r.understood {
            return Self {
                part: true,
                full: true,
                ignore_case: true,
                path: true,
            };
        }
        match tool {
            SystemTool::Pkill => Self {
                part: !r.has("x"),
                full: r.has("f"),
                ignore_case: r.has("i"),
                path: false,
            },
            _ => Self {
                part: r.has("r"),
                full: false,
                ignore_case: r.has("I"),
                path: true,
            },
        }
    }
}

/// The unit types systemd knows by their suffix: a listed unit without one
/// is a `.service` (`snap.amazon-ssm-agent.amazon-ssm-agent` included).
const UNIT_TYPES: &[&str] = &[
    ".service",
    ".socket",
    ".target",
    ".device",
    ".mount",
    ".automount",
    ".swap",
    ".timer",
    ".path",
    ".slice",
    ".scope",
];

/// A listed unit's full name, as a glob is matched against it (the review
/// of #548, F3: a dotted name with no type suffix is a service too).
fn full_unit_name(u: &str) -> String {
    if UNIT_TYPES.iter().any(|t| u.ends_with(t)) {
        u.to_string()
    } else {
        format!("{u}.service")
    }
}

/// One unit a service-manager command stops, disables, masks or kills.
struct ServiceTarget {
    verb: String,
    unit: String,
    /// Read from an argv its table understood (systemctl's).
    understood: bool,
    /// `systemctl kill`'s reload signal (`-s`, `--signal`), when every
    /// reading of the argv sends it ([`one_reload`]).
    reload: Option<u8>,
}

/// How a systemctl verb reaches the units it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// Every operand after the verb is a unit.
    Units,
    /// The first operand is the unit, the rest its settings
    /// (`set-property auditd CPUQuota=1%`).
    FirstUnit,
    /// The operands are unit files' paths (`link /x/auditd.service`): the
    /// unit their name is.
    Paths,
    /// Every unit (`rescue`, `emergency`, `preset-all`).
    Every,
    /// `isolate <target>`: every unit the target does not want — every
    /// listed one, unless the target is the system's usual one.
    Isolate,
}

/// The review of #548 (F2): systemd's verbs (`systemctl.c`, 249–262) that
/// stop, freeze, signal, disable, mask, revert, re-point, reconfigure or
/// clean a unit. Not judged: `start`, the reload and restart family
/// (`restart`, `try-restart`, `condrestart`, …: the unit runs again after
/// it, as an administrator's everyday restart), `enable`, `unmask`, and the
/// system's own transitions (`reboot`, `poweroff`, `halt`, `suspend`, …).
const SYSTEMCTL_VERBS: &[(&str, Reach)] = &[
    ("stop", Reach::Units),
    ("condstop", Reach::Units),
    ("kill", Reach::Units),
    ("freeze", Reach::Units),
    ("clean", Reach::Units),
    ("disable", Reach::Units),
    ("mask", Reach::Units),
    ("preset", Reach::Units),
    ("revert", Reach::Units),
    ("edit", Reach::Units),
    ("link", Reach::Paths),
    ("set-property", Reach::FirstUnit),
    ("service-log-level", Reach::FirstUnit),
    ("service-log-target", Reach::FirstUnit),
    ("bind", Reach::FirstUnit),
    ("mount-image", Reach::FirstUnit),
    ("isolate", Reach::Isolate),
    ("rescue", Reach::Every),
    ("emergency", Reach::Every),
    ("preset-all", Reach::Every),
];

/// The targets an `isolate` keeps the system's services under.
const USUAL_TARGETS: &[&str] = &["default", "multi-user", "graphical"];

/// The units a judged verb reaches, from its operands: the verb as the
/// record says it, and each unit argument (`*`: every listed unit).
fn reached<'a>(verb: &'a str, reach: Reach, rest: &[&'a str]) -> Vec<(String, &'a str)> {
    let say = |v: &str| v.to_string();
    match reach {
        Reach::Units => rest.iter().map(|u| (say(verb), *u)).collect(),
        Reach::FirstUnit => rest.first().map(|u| (say(verb), *u)).into_iter().collect(),
        Reach::Paths => rest
            .iter()
            .map(|p| (say(verb), p.rsplit('/').next().unwrap_or(p)))
            .collect(),
        Reach::Every => vec![(say(verb), "*")],
        Reach::Isolate => match rest.first() {
            Some(t) => {
                let name = t.strip_suffix(".target").unwrap_or(t);
                if USUAL_TARGETS.contains(&name) {
                    Vec::new()
                } else {
                    vec![(format!("{verb} {t}"), "*")]
                }
            }
            None => Vec::new(),
        },
    }
}

/// Lot 316 (BUG-106, BUG-96): the units systemctl's reading `r` reaches —
/// with each verb of [`SYSTEMCTL_VERBS`] its own way, on the system's
/// manager (the last of `--system`, `--user`, `--global`, `--capsule`). For
/// an argv not understood, any operand may be the verb and every later one
/// a unit, and the manager is the system's.
fn systemctl_targets<'a>(r: &Parsed<'a>) -> Vec<(String, &'a str)> {
    let reach = |v: &str| {
        SYSTEMCTL_VERBS
            .iter()
            .find(|(n, _)| *n == v)
            .map(|(_, r)| *r)
    };
    if !r.understood {
        let mut out = Vec::new();
        for (i, verb) in r.operands.iter().enumerate() {
            if let Some(how) = reach(verb) {
                out.extend(reached(verb, how, &r.operands[i + 1..]));
            }
        }
        return out;
    }
    let system = r
        .options
        .iter()
        .rev()
        .find_map(|(n, _)| match *n {
            "system" => Some(true),
            "user" | "global" | "C" => Some(false),
            _ => None,
        })
        .unwrap_or(true);
    match r.operands.split_first() {
        Some((verb, rest)) if system => match reach(verb) {
            Some(how) => reached(verb, how, rest),
            None => Vec::new(),
        },
        _ => Vec::new(),
    }
}

/// The units a service-manager command stops, disables, masks or kills.
/// Lot 316: systemctl's argv read by its table, every way it may be read
/// (BUG-106: an option the old exact-match list did not hold moved the verb
/// onto its value; `POSIXLY_CORRECT` makes an option after the verb a
/// unit).
fn service_targets(prog: &Program, argv: &[String]) -> Vec<ServiceTarget> {
    let mut out: Vec<ServiceTarget> = Vec::new();
    if prog.is("systemctl") {
        let readings = SystemTool::Systemctl.read(argv, prog.args_from);
        // `systemctl kill`'s signal: a reading's last `-s`, TERM when it
        // names none. The re-check of #548 (N1): a reload only when every
        // reading sends it — under `POSIXLY_CORRECT` a `-s` after the verb
        // is a unit and the signal TERM (`systemctl kill -s HUP
        // rsyslog.service` is then `-s.service`, `HUP.service` and rsyslog
        // killed).
        let reload = one_reload(readings.iter().map(|r| {
            r.understood.then(|| {
                r.option("s")
                    .filter_map(|v| v.first().copied())
                    .last()
                    .unwrap_or("TERM")
            })
        }));
        for r in readings {
            out.extend(
                systemctl_targets(&r)
                    .into_iter()
                    .map(|(verb, unit)| ServiceTarget {
                        verb,
                        unit: unit.to_string(),
                        understood: r.understood,
                        reload,
                    }),
            );
        }
        return out;
    }
    let target = |verb: &str, unit: &str| ServiceTarget {
        verb: verb.to_string(),
        unit: unit.to_string(),
        understood: true,
        reload: None,
    };
    let free: Vec<&str> = argv
        .iter()
        .skip(1)
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect();
    let pair = |name: usize, action: usize, stops: &[&str]| -> Option<ServiceTarget> {
        let (n, a) = (free.get(name)?, free.get(action)?);
        stops.contains(a).then(|| target(a, n))
    };
    if prog.is("service") || prog.is("invoke-rc.d") || prog.is("rc-service") {
        out.extend(pair(0, 1, &["stop", "force-stop"]));
    } else if prog.is("update-rc.d") {
        out.extend(pair(0, 1, &["disable", "remove"]));
    } else if prog.is("chkconfig") {
        out.extend(pair(0, 1, &["off"]));
    } else if prog.is("rc-update") && free.first() == Some(&"del") {
        out.extend(free.get(1).map(|n| target("del", n)));
    }
    // `/etc/init.d/<name> stop`: the script is an argument of its
    // interpreter's exec.
    for (i, a) in argv.iter().enumerate() {
        if let Some(name) = a.strip_prefix("/etc/init.d/") {
            if argv
                .get(i + 1)
                .is_some_and(|x| matches!(x.as_str(), "stop" | "force-stop"))
            {
                out.push(target("stop", name));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
mod tool_options;
mod unit_glob;
