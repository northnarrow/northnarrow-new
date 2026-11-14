//! Lot 349 (pre-alpha R001; the review of #557, F1): the agent's own CPUs.
//!
//! Root can confine the agent to one CPU without touching it: a sibling
//! cgroup put in `cpuset.cpus.partition=root` (or `isolated`) takes its CPUs
//! from every other cgroup of the parent — the agent's among them — and no
//! hook sees it (the `task_setscheduler` guard refuses `taskset -p` on the
//! agent, the cgroup guard a write of its own `cpuset.cpus`; neither is
//! asked). Confined to one busy CPU, the agent's rings overflow and its
//! responses come late.
//!
//! So the kernel-state round reads, every [`crate::kernel_state::PERIOD`],
//! what the agent may run on: the CPU affinity of each of its threads
//! (`sched_getaffinity`) and its cgroup's `cpuset.cpus.effective`, against
//! what it should — the host's online CPUs, less those the kernel's command
//! line isolates (`isolcpus=`, the scheduler's domain: no task runs there
//! unless pinned), narrowed by systemd's own default affinity
//! (`CPUAffinity=` of `system.conf`, read once at the agent's start) and by
//! a slice above it whose `cpuset.cpus` systemd set (an `AllowedCPUs=` of
//! `northnarrow.slice`, a reservation the drop-in judge accepts: made in a
//! signed window, the cgroup guard refuses any other write of it). When they
//! shrink, [`Watch::round`] gives a [`Confinement`] naming the cause — a
//! partition, the agent's own cgroup's `cpuset.cpus`, a thread's affinity,
//! a move to another cgroup — which the round signs (NN-L-AT-001 High,
//! `FsProtectOperation::CpuConfined`) and keeps as a degradation
//! ([`DEGRADATION`], `nn-admin status`) while it holds.
//!
//! No record when nothing was taken: a CPU taken offline leaves the online
//! set, the effective set and the affinities alike; a container runtime
//! enabling the cpuset controller above the agent (#557) gives its cgroup
//! the parent's CPUs, all of them.
//!
//! The review of #558:
//! - F2: a round whose online CPUs moved (a hotplug, or root toggling a
//!   CPU every round) is no longer skipped: it is judged against the CPUs
//!   every read saw online — the round's two reads and the last round's —
//!   which a real hotplug cannot turn into a record (the kernel ANDs the
//!   cpusets and the affinities with the active CPUs, and a CPU that came
//!   back is expected from the next settled round on). Such a round never
//!   clears nor changes the confinement in force. A round that cannot be
//!   judged (no online CPU read, a mount crossed in the cgroup tree) is
//!   skipped, and [`UNJUDGED_ROUNDS`] skipped or unsettled rounds in a row
//!   with nothing in force are signed ([`Cause::Unjudged`]). The online
//!   CPUs are read through descriptors opened once at the watch's start
//!   ([`Sources`], `pread` at offset 0: the kernel makes the text afresh),
//!   each checked to be sysfs or procfs (`fstatfs`): a file bound over the
//!   path later changes nothing, a FUSE file there at the start is refused.
//! - F3: the cgroup files are opened beneath a descriptor of the cgroup2
//!   root opened at the start ([`Tree`], `openat2` with `RESOLVE_NO_XDEV`
//!   and no symbolic link): a file bound over the slice's `cpuset.cpus`, or
//!   a directory over the slice, is a mount crossed — the round is not
//!   judged, never a narrower expectation.
//! - F6: repeated `CPUAffinity=` assignments are merged as systemd merges
//!   them (an empty one resets), and the agent's own unit's `CPUAffinity=`
//!   is what it should run on when every file assigning it predates the
//!   agent's install (the installer's check listed it, the integrity round
//!   signs it: `own_dropins::preinstall_harmful`); one changed since is not
//!   taken — a confinement.
//! - F7: every read is bounded and never blocks (a regular file only,
//!   opened `O_NONBLOCK`, at most [`SOURCE_MAX`]).

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::{Path, PathBuf};

/// The degradation's source while the agent is confined.
pub const DEGRADATION: &str = "own_cpus";

/// The cgroup v2 hierarchy.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The host's online CPUs.
pub const ONLINE: &str = "/sys/devices/system/cpu/online";
/// The kernel's per-CPU counters: one `cpuN` line per online CPU (the
/// online list's second source).
pub const PROC_STAT: &str = "/proc/stat";
/// How many cgroups the search for a partition reads at most.
pub const PARTITION_SCAN_MAX: usize = 4096;
/// How many partitions, and confined threads, a record names at most.
pub const NAMED_MAX: usize = 4;
/// The review of #558 (F2): after how many rounds in a row the watch could
/// not judge (skipped, or its online CPUs moving) it signs it.
pub const UNJUDGED_ROUNDS: u32 = 3;
/// The review of #558 (F7): the most a source of the watch is read of —
/// `/proc/stat` of an 8192-CPU host is about 1 MiB (a `cpuN` line each and
/// the interrupt counts); a cgroup or online file is a line.
pub const SOURCE_MAX: u64 = 4 << 20;
/// `statfs` types a source must be on (the review of #558, F2, F3).
pub const SYSFS_MAGIC: u64 = 0x6265_6572;
pub const PROC_SUPER_MAGIC: u64 = 0x9fa0;
pub const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;

pub use common::wire::{
    cpu_confined_of as of_target_dev, CPU_CAUSE_AFFINITY as CAUSE_AFFINITY,
    CPU_CAUSE_CGROUP_CPUSET as CAUSE_CGROUP_CPUSET, CPU_CAUSE_CGROUP_MOVE as CAUSE_CGROUP_MOVE,
    CPU_CAUSE_PARTITION as CAUSE_PARTITION, CPU_CAUSE_UNJUDGED as CAUSE_UNJUDGED,
};

/// Why the agent runs on fewer CPUs than it should.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cause {
    /// A cgroup in `cpuset.cpus.partition` `root` or `isolated` took them
    /// (those found, `path cpus`; none found: the partition is gone, or
    /// its cgroup could not be read).
    Partition(Vec<String>),
    /// The agent's own cgroup's `cpuset.cpus` (its floor is empty: its
    /// parent's CPUs): the cgroup and the value.
    CgroupCpuset(String, Vec<u32>),
    /// Threads whose CPU affinity is narrower than the cgroup's CPUs (tid,
    /// CPUs; at most [`NAMED_MAX`]) and how many there are.
    Affinity(Vec<(u32, Vec<u32>)>, usize),
    /// The agent is in another cgroup than at its start.
    CgroupMove { from: String, to: String },
    /// The review of #558 (F2, F3): the watch could not judge for `rounds`
    /// rounds in a row — why (the last round's reason).
    Unjudged { rounds: u32, why: String },
}

impl Cause {
    pub fn code(&self) -> u64 {
        match self {
            Cause::Partition(_) => CAUSE_PARTITION,
            Cause::CgroupCpuset(..) => CAUSE_CGROUP_CPUSET,
            Cause::Affinity(..) => CAUSE_AFFINITY,
            Cause::CgroupMove { .. } => CAUSE_CGROUP_MOVE,
            Cause::Unjudged { .. } => CAUSE_UNJUDGED,
        }
    }

    fn is_unjudged(&self) -> bool {
        matches!(self, Cause::Unjudged { .. })
    }

    /// What the record's `comm` names: the partition, the cgroup, the
    /// thread (printable, at most 64 bytes — a cgroup's name is anyone's).
    pub fn subject(&self) -> String {
        let s = match self {
            Cause::Partition(found) => found
                .first()
                .map(|p| p.split(' ').next().unwrap_or("").to_string())
                .unwrap_or_else(|| "partition".to_string()),
            Cause::CgroupCpuset(cg, _) => cg.clone(),
            Cause::Affinity(t, _) => t
                .first()
                .map(|(tid, _)| format!("tid {tid}"))
                .unwrap_or_default(),
            Cause::CgroupMove { to, .. } => to.clone(),
            Cause::Unjudged { why, .. } => why.clone(),
        };
        printable(&s, 64)
    }

    /// The cause in words (the degradation's line, the journal).
    pub fn describe(&self) -> String {
        match self {
            Cause::Partition(found) if found.is_empty() => {
                "a cgroup partition took them (cpuset.cpus.partition root or isolated; none \
                 found at this read)"
                    .to_string()
            }
            Cause::Partition(found) => format!(
                "a cgroup partition took them (cpuset.cpus.partition root or isolated: {})",
                found
                    .iter()
                    .map(|p| printable(p, 96))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Cause::CgroupCpuset(cg, cpus) => format!(
                "its own cgroup's cpuset.cpus is {} ({})",
                cpu_list_text(cpus),
                printable(cg, 96)
            ),
            Cause::Affinity(threads, n) => format!(
                "the CPU affinity of {n} of its threads was narrowed ({})",
                threads
                    .iter()
                    .map(|(t, c)| format!("tid {t}: {}", cpu_list_text(c)))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Cause::CgroupMove { from, to } => format!(
                "it was moved from cgroup {} to {}",
                printable(from, 96),
                printable(to, 96)
            ),
            Cause::Unjudged { rounds, why } => format!(
                "the watch could not judge them for {rounds} rounds in a row ({})",
                printable(why, 160)
            ),
        }
    }
}

/// The agent confined: the CPUs it may run on, those it should, why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confinement {
    /// The CPUs every thread of the agent may run on (the cgroup's, or the
    /// narrowest thread's).
    pub left: Vec<u32>,
    /// The CPUs it should run on.
    pub expected: Vec<u32>,
    pub cause: Cause,
}

impl Confinement {
    /// What tells two confinements apart: the cause, the CPUs left and
    /// expected (not the partitions or threads named, which a read may
    /// list in another order).
    pub fn key(&self) -> (u64, &[u32], &[u32]) {
        (self.cause.code(), &self.left, &self.expected)
    }

    /// The degradation's line (and the journal's).
    pub fn line(&self) -> String {
        if self.cause.is_unjudged() {
            return format!(
                "{} — what the agent may run on is unknown (its threads may run on CPUs {}, of \
                 the {} online)",
                self.cause.describe(),
                cpu_list_text(&self.left),
                cpu_list_text(&self.expected)
            );
        }
        format!(
            "the agent may run on CPUs {} of the {} it should ({}): {} — confined, its sensors \
             and responses keep up with less",
            cpu_list_text(&self.left),
            cpu_list_text(&self.expected),
            self.expected.len(),
            self.cause.describe()
        )
    }

    /// The record's `target_dev` (`common::wire::cpu_confined_dev`): the
    /// cause, the CPUs left, the CPUs expected, the threads confined.
    pub fn target_dev(&self) -> u64 {
        let threads = match &self.cause {
            Cause::Affinity(_, k) => *k,
            Cause::Unjudged { rounds, .. } => *rounds as usize,
            _ => 0,
        };
        common::wire::cpu_confined_dev(
            self.cause.code(),
            self.left.len() as u64,
            self.expected.len() as u64,
            threads as u64,
        )
    }

    /// The record's `target_ino`: the CPUs left below 64, as a mask.
    pub fn target_ino(&self) -> u64 {
        cpu_mask(&self.left)
    }
}

/// The online CPUs: those of the online list and of `/proc/stat`'s `cpuN`
/// lines together — one source faked or unreadable (a file bound over the
/// online list) does not narrow what the agent should run on.
pub fn online_of(list: Vec<u32>, proc_stat: &str) -> Vec<u32> {
    let mut out = list;
    out.extend(proc_stat.lines().filter_map(|l| {
        let n = l.split_whitespace().next()?.strip_prefix("cpu")?;
        n.parse::<u32>().ok()
    }));
    out.sort_unstable();
    out.dedup();
    out
}

/// A mask of the CPUs below 64.
pub fn cpu_mask(cpus: &[u32]) -> u64 {
    cpus.iter()
        .filter(|c| **c < 64)
        .fold(0u64, |m, c| m | 1u64 << c)
}

/// A CPU list (`0-3,5`) as its CPUs, sorted.
pub fn cpu_list(t: &str) -> Vec<u32> {
    antitamper_bpf::cgroup_floors::cpu_list(t)
}

/// CPUs as the kernel writes a list (`0-2,5`); `none` when empty.
pub fn cpu_list_text(cpus: &[u32]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < cpus.len() {
        let start = cpus[i];
        let mut end = start;
        while i + 1 < cpus.len() && cpus[i + 1] == end + 1 {
            i += 1;
            end = cpus[i];
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out.join(",")
    }
}

fn printable(s: &str, max: usize) -> String {
    let mut out: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if out.len() > max {
        out.truncate(max);
    }
    out
}

fn subset(a: &[u32], b: &[u32]) -> bool {
    a.iter().all(|c| b.contains(c))
}

fn intersect(a: &[u32], b: &[u32]) -> Vec<u32> {
    a.iter().copied().filter(|c| b.contains(c)).collect()
}

/// One read of what the agent may run on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reading {
    /// The host's online CPUs.
    pub online: Vec<u32>,
    /// The agent's cgroup now (`/proc/self/cgroup`'s `0::` line).
    pub cgroup: Option<String>,
    /// `cpuset.cpus.effective` of the agent's cgroup, or of its nearest
    /// ancestor that has the file (`None`: none could be read).
    pub effective: Option<Vec<u32>>,
    /// The non-empty `cpuset.cpus` of each cgroup from the start's cgroup
    /// up to (not including) the root: (path, CPUs), the agent's own first.
    pub configured: Vec<(String, Vec<u32>)>,
    /// Each thread's CPU affinity (the kernel's, its active CPUs only).
    pub threads: Vec<(u32, Vec<u32>)>,
    /// The review of #558 (F3): why this read cannot be judged — a mount
    /// crossed in the cgroup tree (a file bound over a `cpuset.cpus`, a
    /// directory over a cgroup); `None` when it can.
    pub unjudged: Option<String>,
}

/// What narrows the CPUs the agent should run on, read once at its start:
/// the CPUs the kernel's command line isolates, systemd's default affinity,
/// the agent's unit's own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    /// `isolcpus=` (the domain isolation: plain, or with the `domain` flag).
    pub isolated: Vec<u32>,
    /// systemd's `[Manager] CPUAffinity=` (`None`: not set, or a value this
    /// read does not take — `numa`).
    pub manager: Option<Vec<u32>>,
    /// The review of #558 (F6): the agent's unit's `[Service] CPUAffinity=`
    /// when every file assigning it predates the agent's install
    /// ([`unit_affinity`]); `None`: not set, or not taken.
    pub unit: Option<Vec<u32>>,
}

/// What the agent should run on: the online CPUs less the isolated ones,
/// narrowed by its unit's `CPUAffinity=` (signed, [`Host::unit`]) or else
/// by systemd's default affinity (which the unit's replaces, as systemd
/// does at the exec), and by the `cpuset.cpus` a SLICE above it holds
/// (systemd's `AllowedCPUs=`; never the agent's own cgroup's, whose floor
/// is its parent's CPUs).
pub fn expected(start_cgroup: &str, host: &Host, r: &Reading) -> Vec<u32> {
    let mut out: Vec<u32> = r
        .online
        .iter()
        .copied()
        .filter(|c| !host.isolated.contains(c))
        .collect();
    if let Some(m) = host.unit.as_ref().or(host.manager.as_ref()) {
        out = intersect(&out, m);
    }
    // a narrowing that leaves no online CPU (a stale list) narrows nothing:
    // the watch never goes blind for want of an expectation
    if out.is_empty() {
        out = r.online.clone();
    }
    for (path, cpus) in &r.configured {
        if path != start_cgroup {
            out = intersect(&out, cpus);
        }
    }
    out
}

/// The confinement `r` shows against the start's cgroup, if any; the
/// partitions are looked for with `partitions` only then.
pub fn judge(
    start_cgroup: &str,
    host: &Host,
    r: &Reading,
    partitions: &dyn Fn() -> Vec<String>,
) -> Option<Confinement> {
    let expected = expected(start_cgroup, host, r);
    if expected.is_empty() {
        return None;
    }
    let effective = r.effective.clone().unwrap_or_else(|| r.online.clone());
    let cgroup_left = intersect(&effective, &expected);
    let narrowed: Vec<&(u32, Vec<u32>)> = r
        .threads
        .iter()
        .filter(|(_, cpus)| !subset(&cgroup_left, cpus))
        .collect();
    let cgroup_short = !subset(&expected, &effective);
    if !cgroup_short && narrowed.is_empty() {
        return None;
    }
    let left = match narrowed.iter().min_by_key(|(_, c)| c.len()) {
        Some((_, c)) if !cgroup_short => intersect(&cgroup_left, c),
        _ => cgroup_left.clone(),
    };
    let own_configured = r
        .configured
        .iter()
        .find(|(p, cpus)| p == start_cgroup && !subset(&expected, cpus));
    let cause = match (&r.cgroup, own_configured) {
        (Some(now), _) if now != start_cgroup => Cause::CgroupMove {
            from: start_cgroup.to_string(),
            to: now.clone(),
        },
        (_, Some((p, cpus))) if cgroup_short => Cause::CgroupCpuset(p.clone(), cpus.clone()),
        _ if cgroup_short => Cause::Partition(partitions()),
        _ => Cause::Affinity(
            narrowed
                .iter()
                .take(NAMED_MAX)
                .map(|(t, c)| (*t, c.clone()))
                .collect(),
            narrowed.len(),
        ),
    };
    Some(Confinement {
        left,
        expected,
        cause,
    })
}

/// What a round does with a confinement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Nothing new.
    Same,
    /// The round was not judged: the first read (the baseline), or one that
    /// cannot be ([`Reading::unjudged`], no online CPU read).
    Skipped,
    /// A new confinement, or a different one: sign it, keep it.
    Confined(Confinement),
    /// The confinement in force ended.
    Cleared(Confinement),
}

/// What the watch keeps between two rounds.
#[derive(Debug, Default)]
pub struct Watch {
    /// The agent's cgroup at its start (the first read).
    pub start_cgroup: Option<String>,
    /// What narrows the expected CPUs, read at the start.
    pub host: Host,
    /// The online CPUs as the last round read them (its second read).
    pub online: Option<Vec<u32>>,
    /// The confinement in force (signed).
    pub current: Option<Confinement>,
    /// The review of #558 (F2): the rounds in a row not judged, or judged
    /// while the online CPUs moved.
    pub unsettled: u32,
    /// The descriptors the round reads through, opened at its first round
    /// ([`round`]; `None` in a test that steps the watch by hand).
    pub sources: Option<Sources>,
}

impl Watch {
    /// One round on `r` (`online_again`: the online CPUs read once more
    /// after the rest).
    ///
    /// The review of #558 (F2): judged against the CPUs every read saw
    /// online — `r`'s, `online_again` and the last round's second read —
    /// and never skipped for a move of them. A round whose online CPUs
    /// moved is unsettled: it signs a confinement when none is in force,
    /// but never clears nor changes the one in force (the next settled
    /// round does). [`UNJUDGED_ROUNDS`] rounds in a row skipped or
    /// unsettled, with nothing found and nothing in force, are signed
    /// ([`Cause::Unjudged`]).
    pub fn step(
        &mut self,
        r: &Reading,
        online_again: &[u32],
        partitions: &dyn Fn() -> Vec<String>,
    ) -> Step {
        let start = match (&self.start_cgroup, &r.cgroup) {
            (Some(s), _) => s.clone(),
            (None, Some(now)) => {
                self.start_cgroup = Some(now.clone());
                now.clone()
            }
            (None, None) => String::new(),
        };
        let Some(last) = self.online.replace(online_again.to_vec()) else {
            // the first read is the baseline
            self.unsettled = 1;
            return Step::Skipped;
        };
        let settled = r.online == last && r.online == online_again;
        let online = intersect(&intersect(&r.online, online_again), &last);
        let why = r.unjudged.clone().or_else(|| {
            online
                .is_empty()
                .then(|| "no online CPU could be read".to_string())
        });
        if let Some(why) = why {
            self.unsettled = self.unsettled.saturating_add(1);
            return match self.unjudged(why, r) {
                Some(signed) => signed,
                None => Step::Skipped,
            };
        }
        self.unsettled = if settled {
            0
        } else {
            self.unsettled.saturating_add(1)
        };
        let at = Reading {
            online,
            ..r.clone()
        };
        // the partitions are looked for only for a confinement to sign
        let found = judge(&start, &self.host, &at, &Vec::new);
        match (found, self.current.take()) {
            (Some(now), Some(was)) if now.key() == was.key() => {
                self.current = Some(was);
                Step::Same
            }
            // unsettled: the confinement in force stands until a settled
            // round tells it changed
            (Some(_), Some(was)) if !settled && !was.cause.is_unjudged() => {
                self.current = Some(was);
                Step::Same
            }
            (Some(first), _) => {
                let now = judge(&start, &self.host, &at, partitions).unwrap_or(first);
                self.current = Some(now.clone());
                Step::Confined(now)
            }
            (None, Some(was)) if settled => Step::Cleared(was),
            (None, Some(was)) => {
                self.current = Some(was);
                Step::Same
            }
            (None, None) if settled => Step::Same,
            (None, None) => self
                .unjudged(
                    format!(
                        "the online CPUs moved in each of the last {} rounds",
                        self.unsettled
                    ),
                    r,
                )
                .unwrap_or(Step::Same),
        }
    }

    /// The record of rounds not judged, when [`UNJUDGED_ROUNDS`] of them
    /// came in a row and nothing is in force (a confinement signed stands:
    /// the stricter answer).
    fn unjudged(&mut self, why: String, r: &Reading) -> Option<Step> {
        if self.unsettled < UNJUDGED_ROUNDS || self.current.is_some() {
            return None;
        }
        let left = r
            .threads
            .iter()
            .map(|(_, c)| c.clone())
            .reduce(|a, b| intersect(&a, &b))
            .unwrap_or_default();
        let c = Confinement {
            left,
            expected: r.online.clone(),
            cause: Cause::Unjudged {
                rounds: self.unsettled,
                why,
            },
        };
        self.current = Some(c.clone());
        Some(Step::Confined(c))
    }
}

// ── the host's reads ─────────────────────────────────────────────────────

/// The CPUs `isolcpus=` isolates from the scheduler's domains (the kernel's
/// command line): its CPU list when it has no flag or the `domain` one —
/// `nohz` and `managed_irq` alone leave every task's affinity as it was.
/// The last `isolcpus=` holds.
pub fn isolated_by_cmdline(cmdline: &str) -> Vec<u32> {
    let Some(v) = cmdline
        .split_whitespace()
        .filter_map(|t| t.strip_prefix("isolcpus="))
        .next_back()
    else {
        return Vec::new();
    };
    let (flags, cpus): (Vec<&str>, Vec<&str>) = v
        .split(',')
        .filter(|p| !p.is_empty())
        .partition(|p| p.chars().next().is_some_and(|c| c.is_ascii_alphabetic()));
    if !flags.is_empty() && !flags.contains(&"domain") {
        return Vec::new();
    }
    cpu_list(&cpus.join(","))
}

/// What a run of `CPUAffinity=` assignments leaves.
#[derive(Debug, Default)]
enum Affinity {
    #[default]
    Unset,
    Cpus(Vec<u32>),
    /// A value that is not a CPU list (`numa`: the NUMA policy's nodes).
    Other,
}

impl Affinity {
    fn cpus(self) -> Option<Vec<u32>> {
        match self {
            Affinity::Cpus(c) if !c.is_empty() => Some(c),
            _ => None,
        }
    }
}

/// The `CPUAffinity=` assignments of `text`'s `section` (`[Manager]`,
/// `[Service]`) merged into `acc` as systemd merges them
/// (systemd-system.conf(5), systemd.exec(5)): each list is added to the
/// mask, an empty assignment resets it. Whether `text` assigns it at all.
fn merge_affinity(acc: &mut Affinity, text: &str, section: &str) -> bool {
    let mut inside = false;
    let mut assigned = false;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            inside = l == section;
            continue;
        }
        if !inside || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        let Some(v) = l.strip_prefix("CPUAffinity=") else {
            continue;
        };
        assigned = true;
        let v = v.trim();
        *acc = if v.is_empty() {
            Affinity::Unset
        } else if !v
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '-' | ',' | ' ' | '\t'))
        {
            Affinity::Other
        } else {
            match std::mem::take(acc) {
                Affinity::Unset => Affinity::Cpus(cpu_list(v)),
                Affinity::Cpus(mut c) => {
                    c.extend(cpu_list(v));
                    c.sort_unstable();
                    c.dedup();
                    Affinity::Cpus(c)
                }
                Affinity::Other => Affinity::Other,
            }
        };
    }
    assigned
}

/// systemd's `[Manager] CPUAffinity=` in the files of `system.conf` given
/// in systemd's order (the main file, then the drop-ins). The review of
/// #558 (F6): the assignments are merged, as systemd merges them — `0-1`
/// then `3` is `0-1,3` — an empty one resets the mask; `None` when unset or
/// a value that is not a CPU list (`numa`: the NUMA policy's nodes).
pub fn manager_affinity(files: &[String]) -> Option<Vec<u32>> {
    let mut acc = Affinity::Unset;
    for text in files {
        merge_affinity(&mut acc, text, "[Manager]");
    }
    acc.cpus()
}

/// One file of the agent's unit (the unit file or a drop-in), read for its
/// `CPUAffinity=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFile {
    /// Its text; `None` when what systemd reads there cannot be read (a
    /// FIFO, a device: `state_read::read_config`).
    pub text: Option<String>,
    /// It predates the agent's install and lies in our units' own
    /// directories (the unit file, `northnarrow-agent.service.d`,
    /// `northnarrow-.service.d`): the installer's check listed it and the
    /// integrity round signs it (`own_dropins::preinstall_harmful`); after
    /// the install those directories take a file only inside a window,
    /// whose close moves a narrower `CPUAffinity=` away.
    pub signed: bool,
}

/// The review of #558 (F6): the agent's unit's `[Service] CPUAffinity=`
/// (its files in systemd's order, merged as systemd merges them) — what the
/// agent should run on, as the slice's `AllowedCPUs=` of a signed window
/// is; `None` when unset, when a file assigning it is not signed (a
/// confinement: a narrower mask is recorded), or when one cannot be read.
pub fn unit_affinity(files: &[UnitFile]) -> Option<Vec<u32>> {
    let mut acc = Affinity::Unset;
    for f in files {
        let text = f.text.as_deref()?;
        if merge_affinity(&mut acc, text, "[Service]") && !f.signed {
            return None;
        }
    }
    acc.cpus()
}

/// The agent's unit.
const AGENT_UNIT: &str = "northnarrow-agent.service";

/// The agent's unit files under `root` (`/`), in systemd's order: the unit
/// file (the first on the unit search path), then the drop-ins of
/// `northnarrow-agent.service.d`, `northnarrow-.service.d` and the
/// type-wide `service.d` by name (a name in an earlier directory of the
/// search path hides the later; the type-wide ones are the host's, never
/// signed). `installed`: the agent's install
/// (`own_dropins::install_time`).
pub fn agent_unit_files(root: &Path, installed: Option<std::time::SystemTime>) -> Vec<UnitFile> {
    let dirs: Vec<PathBuf> = antitamper_bpf::host_dropins::UNIT_SEARCH_PATH
        .iter()
        .map(|d| root.join(d.trim_start_matches('/')))
        .collect();
    let mut out = Vec::new();
    if let Some(p) = dirs
        .iter()
        .map(|d| d.join(AGENT_UNIT))
        .find(|p| std::fs::symlink_metadata(p).is_ok())
    {
        out.extend(unit_file(&p, installed, true));
    }
    let mut dropins: std::collections::BTreeMap<std::ffi::OsString, (PathBuf, bool)> =
        std::collections::BTreeMap::new();
    for d in &dirs {
        for (sub, ours) in [
            ("northnarrow-agent.service.d", true),
            ("northnarrow-.service.d", true),
            ("service.d", false),
        ] {
            let Ok(entries) = std::fs::read_dir(d.join(sub)) else {
                continue;
            };
            for e in entries.flatten() {
                let name = e.file_name();
                if name.to_string_lossy().ends_with(".conf") {
                    dropins.entry(name).or_insert((e.path(), ours));
                }
            }
        }
    }
    out.extend(
        dropins
            .values()
            .filter_map(|(p, ours)| unit_file(p, installed, *ours)),
    );
    out
}

/// The file at `p` for [`unit_affinity`]; `None` when there is none.
fn unit_file(p: &Path, installed: Option<std::time::SystemTime>, ours: bool) -> Option<UnitFile> {
    use std::os::unix::fs::MetadataExt;
    use crate::state_read::Config;
    let text = match crate::state_read::read_config(p) {
        Config::Absent => return None,
        Config::Text(t) => Some(t),
        Config::Unjudgeable(_) => None,
    };
    let predates = |installed: std::time::SystemTime| {
        std::fs::symlink_metadata(p).is_ok_and(|m| {
            let ct = std::time::UNIX_EPOCH
                + std::time::Duration::new(
                    m.ctime().max(0) as u64,
                    m.ctime_nsec().clamp(0, 999_999_999) as u32,
                );
            ct < installed
        })
    };
    let signed = ours
        && crate::own_dropins::regular_with_one_name(p)
        && installed.is_some_and(predates);
    Some(UnitFile { text, signed })
}

/// The `system.conf` files under `root` (`/`), in systemd's order: the
/// main file, then the drop-ins by name across `/usr/lib`, `/usr/local/lib`,
/// `/run` and `/etc` (a name in a later directory replaces the earlier).
pub fn system_conf_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(t) = read_text(&root.join("etc/systemd/system.conf")) {
        out.push(t);
    }
    let mut dropins: std::collections::BTreeMap<std::ffi::OsString, PathBuf> =
        std::collections::BTreeMap::new();
    for dir in [
        "usr/lib/systemd/system.conf.d",
        "usr/local/lib/systemd/system.conf.d",
        "run/systemd/system.conf.d",
        "etc/systemd/system.conf.d",
    ] {
        if let Ok(entries) = std::fs::read_dir(root.join(dir)) {
            for e in entries.flatten() {
                let name = e.file_name();
                if name.to_string_lossy().ends_with(".conf") {
                    dropins.insert(name, e.path());
                }
            }
        }
    }
    out.extend(dropins.values().filter_map(|p| read_text(p)));
    out
}

/// [`Host`] as this host is now.
pub fn host_now() -> Host {
    Host {
        isolated: read_text(Path::new("/proc/cmdline"))
            .map(|t| isolated_by_cmdline(&t))
            .unwrap_or_default(),
        manager: manager_affinity(&system_conf_files(Path::new("/"))),
    }
}

/// The agent's cgroup (`/proc/self/cgroup`'s unified line).
pub fn own_cgroup(proc_self_cgroup: &str) -> Option<String> {
    proc_self_cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(|p| p.trim().to_string())
        .filter(|p| p.starts_with('/'))
}

/// Every read of the watch: the file as text (`state_read::read_state`),
/// `None` when it cannot be read — which narrows nothing the agent should run
/// on (the wider set is expected: a record, the stricter side) and names no
/// partition; an unreadable online list leaves the other source.
fn read_text(p: &Path) -> Option<String> {
    crate::state_read::read_state(p).ok()
}

fn read_cpus(p: &Path) -> Option<Vec<u32>> {
    let t = read_text(p)?;
    Some(cpu_list(t.trim()))
}

/// The cgroup directory of `cgroup` (`/a/b`) under `root`.
fn dir_of(root: &Path, cgroup: &str) -> PathBuf {
    root.join(cgroup.trim_start_matches('/'))
}

/// `cgroup` and each ancestor up to (not including) the root, the cgroup
/// first.
fn chain(cgroup: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = cgroup.trim_end_matches('/').to_string();
    while !cur.is_empty() && cur != "/" {
        out.push(cur.clone());
        cur = match cur.rfind('/') {
            Some(0) | None => String::new(),
            Some(i) => cur[..i].to_string(),
        };
    }
    out
}

/// One read under `root` (`/sys/fs/cgroup`) with `online` and the threads'
/// affinities given.
pub fn read_under(
    root: &Path,
    online: Vec<u32>,
    cgroup: Option<String>,
    start_cgroup: Option<&str>,
    threads: Vec<(u32, Vec<u32>)>,
) -> Reading {
    let effective = cgroup.as_deref().and_then(|cg| {
        chain(cg)
            .iter()
            .map(|c| dir_of(root, c))
            .chain(std::iter::once(root.to_path_buf()))
            .find_map(|d| read_cpus(&d.join("cpuset.cpus.effective")).filter(|v| !v.is_empty()))
    });
    let configured = start_cgroup
        .or(cgroup.as_deref())
        .map(|start| {
            chain(start)
                .into_iter()
                .filter_map(|c| {
                    let cpus = read_cpus(&dir_of(root, &c).join("cpuset.cpus"))?;
                    (!cpus.is_empty()).then_some((c, cpus))
                })
                .collect()
        })
        .unwrap_or_default();
    Reading {
        online,
        cgroup,
        effective,
        configured,
        threads,
    }
}

/// The cgroups under `root` in a partition (`cpuset.cpus.partition` `root`
/// or `isolated`, valid or not), as `path state cpus`, breadth first, at
/// most [`PARTITION_SCAN_MAX`] cgroups read, [`NAMED_MAX`] named.
pub fn partitions_under(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::from([root.to_path_buf()]);
    let mut read = 0usize;
    while let Some(dir) = queue.pop_front() {
        read += 1;
        if read > PARTITION_SCAN_MAX || out.len() >= NAMED_MAX {
            break;
        }
        if dir != root {
            if let Some(state) = read_text(&dir.join("cpuset.cpus.partition")) {
                let state = state.trim();
                if state.starts_with("root") || state.starts_with("isolated") {
                    let cpus = read_text(&dir.join("cpuset.cpus.effective"))
                        .map(|t| t.trim().to_string())
                        .unwrap_or_default();
                    let rel = dir.strip_prefix(root).unwrap_or(&dir);
                    out.push(format!("/{} {state} {cpus}", rel.display()));
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    queue.push_back(e.path());
                }
            }
        }
    }
    out
}

/// The CPU affinity of thread `tid` (the kernel's, active CPUs only).
pub fn affinity(tid: u32) -> Option<Vec<u32>> {
    // SAFETY: a zeroed cpu_set_t is a valid empty set; the kernel fills at
    // most its size.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::sched_getaffinity(
            tid as libc::pid_t,
            std::mem::size_of::<libc::cpu_set_t>(),
            &mut set,
        )
    };
    if r != 0 {
        return None;
    }
    let max = 8 * std::mem::size_of::<libc::cpu_set_t>();
    Some(
        (0..max)
            .filter(|c| unsafe { libc::CPU_ISSET(*c, &set) })
            .map(|c| c as u32)
            .collect(),
    )
}

/// Each thread of this process and its affinity (a thread gone between the
/// listing and its read is left out).
pub fn own_threads() -> Vec<(u32, Vec<u32>)> {
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|tid| Some((tid, affinity(tid)?)))
        .collect()
}

/// One read of the host: the online CPUs (read twice: before and after the
/// rest) and the reading.
pub fn read_host(start_cgroup: Option<&str>) -> (Reading, Vec<u32>) {
    let online = || {
        online_of(
            read_cpus(Path::new(ONLINE)).unwrap_or_default(),
            read_text(Path::new(PROC_STAT)).as_deref().unwrap_or(""),
        )
    };
    let first = online();
    let cgroup = read_text(Path::new("/proc/self/cgroup")).and_then(|t| own_cgroup(&t));
    let r = read_under(
        Path::new(CGROUP_ROOT),
        first,
        cgroup,
        start_cgroup,
        own_threads(),
    );
    (r, online())
}

/// One round of the watch on the host: the confinement to sign, if a new
/// one; the degradation set, changed or cleared.
pub fn round(w: &mut Watch) -> Option<Confinement> {
    if w.start_cgroup.is_none() {
        w.host = host_now();
    }
    let (r, again) = read_host(w.start_cgroup.as_deref());
    let partitions = || partitions_under(Path::new(CGROUP_ROOT));
    match w.step(&r, &again, &partitions) {
        Step::Same | Step::Skipped => None,
        Step::Confined(c) => {
            let line = c.line();
            tracing::warn!(detail = %line, "own CPUs: the agent runs on fewer CPUs than it should");
            crate::boot::degradation::withdraw(DEGRADATION, &[]);
            if crate::boot::degradation::report(DEGRADATION, &line) {
                crate::boot::degradation::flush();
            }
            Some(c)
        }
        Step::Cleared(was) => {
            tracing::info!(
                was = %was.line(),
                "own CPUs: the agent may run on every CPU it should again"
            );
            crate::boot::degradation::withdraw(DEGRADATION, &[]);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: &str = "/northnarrow.slice/northnarrow-agent.service";
    const SLICE: &str = "/northnarrow.slice";

    fn all() -> Vec<u32> {
        vec![0, 1, 2, 3]
    }

    fn reading(effective: &[u32], threads: &[&[u32]]) -> Reading {
        Reading {
            online: all(),
            cgroup: Some(START.to_string()),
            effective: Some(effective.to_vec()),
            configured: Vec::new(),
            threads: threads
                .iter()
                .enumerate()
                .map(|(i, c)| (100 + i as u32, c.to_vec()))
                .collect(),
        }
    }

    fn none() -> Vec<String> {
        Vec::new()
    }

    /// R001: a sibling partition takes CPUs 1–3 — the cgroup's effective
    /// CPUs and every thread's affinity are CPU 0 alone: confined, the
    /// partition named.
    #[test]
    fn a_sibling_partition_confining_the_agent_is_a_confinement() {
        let r = reading(&[0], &[&[0], &[0]]);
        let found = || vec!["/k349part root 1-3".to_string()];
        let c = judge(START, &Host::default(), &r, &found).expect("confined");
        assert_eq!(c.left, vec![0]);
        assert_eq!(c.expected, all());
        assert_eq!(c.cause, Cause::Partition(vec!["/k349part root 1-3".into()]));
        assert_eq!(c.cause.subject(), "/k349part");
        assert_eq!(of_target_dev(c.target_dev()), (CAUSE_PARTITION, 1, 4, 0));
        assert_eq!(c.target_ino(), 1);
        assert!(
            c.line().contains("CPUs 0 of the 0-3 it should (4)"),
            "{}",
            c.line()
        );
        assert!(c.line().contains("/k349part root 1-3"), "{}", c.line());
    }

    /// No cgroup file readable (a host without the cpuset controller
    /// below the root): the threads' affinity alone tells it.
    #[test]
    fn without_a_cpuset_file_the_affinity_tells_it() {
        let mut r = reading(&[], &[&[0], &[0]]);
        r.effective = None;
        let c = judge(START, &Host::default(), &r, &none).expect("confined");
        assert_eq!(c.left, vec![0]);
        assert!(matches!(c.cause, Cause::Affinity(_, 2)), "{:?}", c.cause);
    }

    #[test]
    fn all_the_cpus_is_no_confinement() {
        assert_eq!(
            judge(
                START,
                &Host::default(),
                &reading(&all(), &[&all(), &all()]),
                &none
            ),
            None
        );
    }

    /// A CPU taken offline: the online CPUs, the effective ones and the
    /// affinities lose it alike — nothing was taken from the agent.
    #[test]
    fn a_cpu_taken_offline_is_no_confinement() {
        let mut r = reading(&[0, 1, 2], &[&[0, 1, 2]]);
        r.online = vec![0, 1, 2];
        assert_eq!(judge(START, &Host::default(), &r, &none), None);
    }

    /// #557: a container runtime enables the cpuset controller above the
    /// agent — its cgroup gets the file, with the parent's CPUs (all).
    #[test]
    fn the_cpuset_controller_enabled_above_the_agent_is_no_confinement() {
        let mut r = reading(&all(), &[&all()]);
        r.effective = None;
        assert_eq!(judge(START, &Host::default(), &r, &none), None);
        r.effective = Some(all());
        assert_eq!(judge(START, &Host::default(), &r, &none), None);
    }

    /// systemd's own `AllowedCPUs=0-1` on the slice (a reservation the
    /// drop-in judge accepts): what the agent should run on.
    #[test]
    fn a_slice_s_allowed_cpus_is_what_the_agent_should_run_on() {
        let mut r = reading(&[0, 1], &[&[0, 1], &[0, 1]]);
        r.configured = vec![(SLICE.to_string(), vec![0, 1])];
        assert_eq!(expected(START, &Host::default(), &r), vec![0, 1]);
        assert_eq!(judge(START, &Host::default(), &r, &none), None);
        // a partition taking CPU 1 of those two is still one
        r.effective = Some(vec![0]);
        r.threads = vec![(100, vec![0])];
        let c = judge(START, &Host::default(), &r, &none).expect("confined");
        assert_eq!((c.left, c.expected), (vec![0], vec![0, 1]));
    }

    /// The agent's own cgroup's `cpuset.cpus` (its floor is empty): never
    /// what it should run on.
    #[test]
    fn its_own_cgroup_s_cpuset_is_a_confinement() {
        let mut r = reading(&[2], &[&[2]]);
        r.configured = vec![(START.to_string(), vec![2])];
        assert_eq!(expected(START, &Host::default(), &r), all());
        let c = judge(START, &Host::default(), &r, &none).expect("confined");
        assert_eq!(c.cause, Cause::CgroupCpuset(START.to_string(), vec![2]));
        assert_eq!(c.left, vec![2]);
    }

    #[test]
    fn a_thread_s_narrowed_affinity_is_a_confinement() {
        let r = reading(&all(), &[&all(), &[3], &all()]);
        let c = judge(START, &Host::default(), &r, &none).expect("confined");
        assert_eq!(c.cause, Cause::Affinity(vec![(101, vec![3])], 1));
        assert_eq!(c.left, vec![3]);
        assert_eq!(of_target_dev(c.target_dev()), (CAUSE_AFFINITY, 1, 4, 1));
        assert!(c.line().contains("tid 101: 3"), "{}", c.line());
    }

    #[test]
    fn a_move_to_a_narrower_cgroup_is_a_confinement() {
        let mut r = reading(&[0], &[&[0]]);
        r.cgroup = Some("/k349/pen".into());
        let c = judge(START, &Host::default(), &r, &none).expect("confined");
        assert_eq!(
            c.cause,
            Cause::CgroupMove {
                from: START.into(),
                to: "/k349/pen".into()
            }
        );
        // a move that leaves every CPU is no confinement
        r.effective = Some(all());
        r.threads = vec![(100, all())];
        assert_eq!(judge(START, &Host::default(), &r, &none), None);
    }

    /// The round: once per confinement, again when it changes, cleared
    /// when it ends; a round whose online CPUs moved is skipped.
    #[test]
    fn the_round_signs_each_confinement_once_and_skips_a_hotplug() {
        let mut w = Watch::default();
        let free = reading(&all(), &[&all()]);
        let pinned = reading(&[0], &[&[0]]);
        assert_eq!(
            w.step(&free, &all(), &none),
            Step::Skipped,
            "the first read is the baseline"
        );
        assert_eq!(w.start_cgroup.as_deref(), Some(START));
        assert_eq!(w.step(&free, &all(), &none), Step::Same);
        let Step::Confined(c) = w.step(&pinned, &all(), &none) else {
            panic!("not signed")
        };
        assert_eq!(c.left, vec![0]);
        assert_eq!(w.step(&pinned, &all(), &none), Step::Same, "signed once");
        let wider = reading(&[0, 1], &[&[0, 1]]);
        assert!(
            matches!(w.step(&wider, &all(), &none), Step::Confined(_)),
            "changed"
        );
        assert!(matches!(w.step(&free, &all(), &none), Step::Cleared(_)));
        assert_eq!(w.current, None);
        // a hotplug: the online set moved since the last round — skipped,
        // whatever the cpusets say
        let mut off = reading(&[0], &[&[0]]);
        off.online = vec![0, 1, 2];
        assert_eq!(w.step(&off, &[0, 1, 2], &none), Step::Skipped);
        assert!(matches!(w.step(&off, &[0, 1, 2], &none), Step::Confined(_)));
        let mut w = Watch::default();
        assert_eq!(w.step(&free, &all(), &none), Step::Skipped);
        let Step::Confined(_) = w.step(&pinned, &all(), &none) else {
            panic!("not signed")
        };
        // … or between the round's two reads: skipped, the confinement kept
        assert_eq!(w.step(&pinned, &[0, 1, 2], &none), Step::Skipped);
        assert!(w.current.is_some());
        assert_eq!(w.step(&pinned, &all(), &none), Step::Same);
    }

    /// The partitions are named in the record, but a read that lists them
    /// in another order is the same confinement (signed once).
    #[test]
    fn the_partitions_named_do_not_make_a_new_confinement() {
        let mut w = Watch::default();
        let pinned = reading(&[0], &[&[0]]);
        let one = || vec!["/a root 1".to_string(), "/b root 2-3".to_string()];
        let other = || vec!["/b root 2-3".to_string(), "/a root 1".to_string()];
        assert_eq!(w.step(&pinned, &all(), &one), Step::Skipped);
        let Step::Confined(c) = w.step(&pinned, &all(), &one) else {
            panic!("not signed")
        };
        assert_eq!(c.cause, Cause::Partition(one()));
        assert_eq!(w.step(&pinned, &all(), &other), Step::Same);
    }

    /// The kernel's isolated CPUs and systemd's default affinity narrow
    /// what the agent should run on (no task runs there unless pinned).
    #[test]
    fn isolated_cpus_and_systemd_s_default_affinity_are_not_a_confinement() {
        assert_eq!(
            isolated_by_cmdline("ro quiet isolcpus=2-3 nohz_full=2-3"),
            vec![2, 3]
        );
        assert_eq!(
            isolated_by_cmdline("isolcpus=domain,managed_irq,1,3"),
            vec![1, 3]
        );
        assert_eq!(
            isolated_by_cmdline("isolcpus=nohz,managed_irq,1-3"),
            Vec::<u32>::new()
        );
        assert_eq!(isolated_by_cmdline("isolcpus=1 isolcpus=2"), vec![2]);
        assert_eq!(isolated_by_cmdline("ro quiet"), Vec::<u32>::new());
        let conf = |t: &str| t.to_string();
        assert_eq!(
            manager_affinity(&[conf("[Manager]\n#CPUAffinity=1\nCPUAffinity=0-1\n")]),
            Some(vec![0, 1])
        );
        assert_eq!(
            manager_affinity(&[
                conf("[Manager]\nCPUAffinity=0-1\n"),
                conf("[Manager]\nCPUAffinity=\n")
            ]),
            None,
            "an empty assignment resets it"
        );
        assert_eq!(
            manager_affinity(&[conf("[Manager]\nCPUAffinity=numa\n")]),
            None
        );
        assert_eq!(manager_affinity(&[conf("[Other]\nCPUAffinity=0\n")]), None);
        assert_eq!(
            manager_affinity(&[conf("[Manager]\nCPUAffinity=0 2\n")]),
            Some(vec![0, 2])
        );
        // tuned's cpu-partitioning: CPUs 2-3 isolated, systemd on 0-1
        let host = Host {
            isolated: vec![2, 3],
            manager: Some(vec![0, 1]),
        };
        let r = reading(&all(), &[&[0, 1], &[0, 1]]);
        assert_eq!(expected(START, &host, &r), vec![0, 1]);
        assert_eq!(judge(START, &host, &r, &none), None);
        let pinned = reading(&[0], &[&[0]]);
        assert!(judge(START, &host, &pinned, &none).is_some());
        // each alone: isolcpus without systemd's affinity, and the reverse
        let isolated = Host {
            isolated: vec![2, 3],
            manager: None,
        };
        assert_eq!(expected(START, &isolated, &r), vec![0, 1]);
        assert_eq!(judge(START, &isolated, &r, &none), None);
        let manager = Host {
            isolated: Vec::new(),
            manager: Some(vec![0, 1]),
        };
        assert_eq!(judge(START, &manager, &r, &none), None);
        assert!(judge(START, &Host::default(), &r, &none).is_some());
        // a narrowing to CPUs that are not online is no expectation of none
        let stale = Host {
            isolated: Vec::new(),
            manager: Some(vec![9]),
        };
        assert_eq!(expected(START, &stale, &r), all());
        assert!(judge(START, &stale, &pinned, &none).is_some());
        // the files in systemd's order
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("etc/systemd/system.conf.d")).unwrap();
        std::fs::create_dir_all(t.path().join("usr/lib/systemd/system.conf.d")).unwrap();
        std::fs::write(
            t.path().join("etc/systemd/system.conf"),
            "[Manager]\nCPUAffinity=0-3\n",
        )
        .unwrap();
        std::fs::write(
            t.path().join("usr/lib/systemd/system.conf.d/10-a.conf"),
            "[Manager]\nCPUAffinity=0\n",
        )
        .unwrap();
        std::fs::write(
            t.path().join("etc/systemd/system.conf.d/10-a.conf"),
            "[Manager]\nCPUAffinity=0-1\n",
        )
        .unwrap();
        std::fs::write(
            t.path().join("etc/systemd/system.conf.d/20-b.txt"),
            "[Manager]\nCPUAffinity=3\n",
        )
        .unwrap();
        assert_eq!(
            manager_affinity(&system_conf_files(t.path())),
            Some(vec![0, 1])
        );
    }

    /// The online CPUs from two sources: a fake online list (a file bound
    /// over it, `0`) does not hide the CPUs `/proc/stat` counts.
    #[test]
    fn the_online_cpus_are_both_sources_together() {
        let stat = "cpu  1 2 3\ncpu0 1 2\ncpu1 1 2\ncpu2 1 2\ncpu3 1 2\nintr 5\nctxt 9\n";
        assert_eq!(online_of(vec![0], stat), all());
        assert_eq!(online_of(all(), ""), all());
        assert_eq!(online_of(vec![], "cpu  1\ncpu1 2\n"), vec![1]);
    }

    #[test]
    fn the_cgroup_line_and_the_lists() {
        assert_eq!(
            own_cgroup("12:cpu:/x\n0::/northnarrow.slice/northnarrow-agent.service\n").as_deref(),
            Some(START)
        );
        assert_eq!(own_cgroup("0::\n"), None);
        assert_eq!(cpu_list_text(&[0, 1, 2, 5, 7, 8]), "0-2,5,7-8");
        assert_eq!(cpu_list_text(&[]), "none");
        assert_eq!(cpu_mask(&[0, 3, 64, 70]), 0b1001);
        assert_eq!(chain(START), vec![START.to_string(), SLICE.to_string()]);
        assert_eq!(chain("/"), Vec::<String>::new());
        assert_eq!(printable("a\nb\u{1b}c", 64), "a?b?c");
        // a cgroup's name is anyone's: the record's subject is cut, printable
        let long = Cause::CgroupMove {
            from: START.into(),
            to: format!("/{}\u{1b}[31m", "x".repeat(200)),
        };
        let subject = long.subject();
        assert_eq!(subject.len(), 64);
        assert!(subject.chars().all(|c| c.is_ascii_graphic()), "{subject}");
    }

    /// The host's reads, on a cgroup tree in a tempdir: the effective CPUs
    /// of the nearest cgroup that has the file, the slices' configured
    /// CPUs, the partitions.
    #[test]
    fn the_reads_of_a_cgroup_tree() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let agent = root.join("northnarrow.slice/northnarrow-agent.service");
        std::fs::create_dir_all(&agent).unwrap();
        std::fs::write(root.join("cpuset.cpus.effective"), "0\n").unwrap();
        std::fs::write(root.join("northnarrow.slice/cpuset.cpus"), "0-1\n").unwrap();
        std::fs::write(agent.join("cpuset.cpus"), "\n").unwrap();
        let part = root.join("k349part");
        std::fs::create_dir_all(&part).unwrap();
        std::fs::write(part.join("cpuset.cpus.partition"), "root\n").unwrap();
        std::fs::write(part.join("cpuset.cpus.effective"), "1-3\n").unwrap();
        let member = root.join("system.slice");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("cpuset.cpus.partition"), "member\n").unwrap();
        // an isolated partition takes CPUs as surely; an invalid one is named
        // too (its state as the kernel writes it)
        let iso = root.join("rt.slice/iso");
        std::fs::create_dir_all(&iso).unwrap();
        std::fs::write(
            iso.join("cpuset.cpus.partition"),
            "isolated invalid (cpus not exclusive)\n",
        )
        .unwrap();
        // an empty effective list is no answer: the nearest ancestor's is read
        std::fs::write(agent.join("cpuset.cpus.effective"), "\n").unwrap();
        let r = read_under(root, all(), Some(START.into()), None, vec![(1, vec![0])]);
        assert_eq!(
            r.effective,
            Some(vec![0]),
            "the root's, the nearest with the file"
        );
        assert_eq!(r.configured, vec![(SLICE.to_string(), vec![0, 1])]);
        assert_eq!(
            partitions_under(root),
            vec![
                "/k349part root 1-3".to_string(),
                "/rt.slice/iso isolated invalid (cpus not exclusive) ".to_string()
            ]
        );
        let c = judge(START, &Host::default(), &r, &|| partitions_under(root)).expect("confined");
        assert_eq!((c.left, c.expected), (vec![0], vec![0, 1]));
        std::fs::write(agent.join("cpuset.cpus.effective"), "0-1\n").unwrap();
        let r = read_under(root, all(), Some(START.into()), None, vec![(1, vec![0, 1])]);
        assert_eq!(r.effective, Some(vec![0, 1]));
        assert_eq!(judge(START, &Host::default(), &r, &none), None);
    }

    /// This process's own threads are read (the test runner's affinity:
    /// a subset of the online CPUs).
    #[test]
    fn this_process_s_threads_are_read() {
        let threads = own_threads();
        assert!(!threads.is_empty());
        let online = read_cpus(Path::new(ONLINE)).unwrap_or_default();
        for (_, cpus) in &threads {
            assert!(!cpus.is_empty());
            assert!(
                online.is_empty() || subset(cpus, &online),
                "{cpus:?} {online:?}"
            );
        }
    }
}
