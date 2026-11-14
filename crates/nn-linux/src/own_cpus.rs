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
//! set, the effective set and the affinities alike (and a round whose
//! online set changed since the last one, or between its two reads, is
//! skipped: the kernel updates the cpusets after the hotplug); a container
//! runtime enabling the cpuset controller above the agent (#557) gives its
//! cgroup the parent's CPUs, all of them.

use std::path::{Path, PathBuf};

/// The degradation's source while the agent is confined.
pub const DEGRADATION: &str = "own_cpus";

/// The cgroup v2 hierarchy.
pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// The host's online CPUs.
pub const ONLINE: &str = "/sys/devices/system/cpu/online";
/// How many cgroups the search for a partition reads at most.
pub const PARTITION_SCAN_MAX: usize = 4096;
/// How many partitions, and confined threads, a record names at most.
pub const NAMED_MAX: usize = 4;

pub use common::wire::{
    cpu_confined_of as of_target_dev, CPU_CAUSE_AFFINITY as CAUSE_AFFINITY,
    CPU_CAUSE_CGROUP_CPUSET as CAUSE_CGROUP_CPUSET, CPU_CAUSE_CGROUP_MOVE as CAUSE_CGROUP_MOVE,
    CPU_CAUSE_PARTITION as CAUSE_PARTITION,
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
}

impl Cause {
    pub fn code(&self) -> u64 {
        match self {
            Cause::Partition(_) => CAUSE_PARTITION,
            Cause::CgroupCpuset(..) => CAUSE_CGROUP_CPUSET,
            Cause::Affinity(..) => CAUSE_AFFINITY,
            Cause::CgroupMove { .. } => CAUSE_CGROUP_MOVE,
        }
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
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
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
}

/// What narrows the CPUs the agent should run on, read once at its start:
/// the CPUs the kernel's command line isolates, systemd's default affinity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Host {
    /// `isolcpus=` (the domain isolation: plain, or with the `domain` flag).
    pub isolated: Vec<u32>,
    /// systemd's `[Manager] CPUAffinity=` (`None`: not set, or a value this
    /// read does not take — `numa`).
    pub manager: Option<Vec<u32>>,
}

/// What the agent should run on: the online CPUs less the isolated ones,
/// narrowed by systemd's default affinity and by the `cpuset.cpus` a SLICE
/// above it holds (systemd's `AllowedCPUs=`; never the agent's own
/// cgroup's, whose floor is its parent's CPUs).
pub fn expected(start_cgroup: &str, host: &Host, r: &Reading) -> Vec<u32> {
    let mut out: Vec<u32> = r
        .online
        .iter()
        .copied()
        .filter(|c| !host.isolated.contains(c))
        .collect();
    if let Some(m) = &host.manager {
        out = intersect(&out, m);
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
    /// The round was skipped (the online CPUs moved: a hotplug).
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
    /// The online CPUs as the last round read them.
    pub online: Option<Vec<u32>>,
    /// The confinement in force (signed).
    pub current: Option<Confinement>,
}

impl Watch {
    /// One round on `r` (`online_again`: the online CPUs read once more
    /// after the rest).
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
        let moved = self.online.as_deref() != Some(r.online.as_slice());
        self.online = Some(r.online.clone());
        if r.online.is_empty() || r.online != online_again || moved {
            return Step::Skipped;
        }
        // the partitions are looked for only for a confinement to sign
        let found = judge(&start, &self.host, r, &Vec::new);
        match (found, self.current.take()) {
            (None, None) => Step::Same,
            (None, Some(was)) => Step::Cleared(was),
            (Some(now), Some(was)) if now.key() == was.key() => {
                self.current = Some(was);
                Step::Same
            }
            (Some(first), _) => {
                let now = judge(&start, &self.host, r, partitions).unwrap_or(first);
                self.current = Some(now.clone());
                Step::Confined(now)
            }
        }
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
        .last()
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

/// systemd's `[Manager] CPUAffinity=` in the files of `system.conf` given
/// in systemd's order (the main file, then the drop-ins): the last
/// assignment holds, an empty one resets it; `None` when unset or a value
/// that is not a CPU list (`numa`: the NUMA policy's nodes).
pub fn manager_affinity(files: &[String]) -> Option<Vec<u32>> {
    let mut out: Option<Option<Vec<u32>>> = None;
    for text in files {
        let mut manager = false;
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('[') {
                manager = l == "[Manager]";
                continue;
            }
            if !manager || l.starts_with('#') || l.starts_with(';') {
                continue;
            }
            if let Some(v) = l.strip_prefix("CPUAffinity=") {
                let v = v.trim();
                out = Some(if v.is_empty() {
                    None
                } else if v
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '-' | ',' | ' ' | '\t'))
                {
                    Some(cpu_list(v)).filter(|c| !c.is_empty())
                } else {
                    None
                });
            }
        }
    }
    out.flatten()
}

/// The `system.conf` files under `root` (`/`), in systemd's order: the
/// main file, then the drop-ins by name across `/usr/lib`, `/usr/local/lib`,
/// `/run` and `/etc` (a name in a later directory replaces the earlier).
pub fn system_conf_files(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(t) = std::fs::read_to_string(root.join("etc/systemd/system.conf")) {
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
    out.extend(
        dropins
            .values()
            .filter_map(|p| std::fs::read_to_string(p).ok()),
    );
    out
}

/// [`Host`] as this host is now.
pub fn host_now() -> Host {
    Host {
        isolated: std::fs::read_to_string("/proc/cmdline")
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

fn read_cpus(p: &Path) -> Option<Vec<u32>> {
    let t = std::fs::read_to_string(p).ok()?;
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
            if let Ok(state) = std::fs::read_to_string(dir.join("cpuset.cpus.partition")) {
                let state = state.trim();
                if state.starts_with("root") || state.starts_with("isolated") {
                    let cpus = std::fs::read_to_string(dir.join("cpuset.cpus.effective"))
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
    let online = || read_cpus(Path::new(ONLINE)).unwrap_or_default();
    let first = online();
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|t| own_cgroup(&t));
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
        assert!(c.line().contains("CPUs 0 of the 0-3 it should (4)"), "{}", c.line());
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
        assert_eq!(judge(START, &Host::default(), &reading(&all(), &[&all(), &all()]), &none), None);
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
        assert_eq!(w.step(&free, &all(), &none), Step::Skipped, "the first read is the baseline");
        assert_eq!(w.start_cgroup.as_deref(), Some(START));
        assert_eq!(w.step(&free, &all(), &none), Step::Same);
        let Step::Confined(c) = w.step(&pinned, &all(), &none) else {
            panic!("not signed")
        };
        assert_eq!(c.left, vec![0]);
        assert_eq!(w.step(&pinned, &all(), &none), Step::Same, "signed once");
        let wider = reading(&[0, 1], &[&[0, 1]]);
        assert!(matches!(w.step(&wider, &all(), &none), Step::Confined(_)), "changed");
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
        assert_eq!(isolated_by_cmdline("ro quiet isolcpus=2-3 nohz_full=2-3"), vec![2, 3]);
        assert_eq!(isolated_by_cmdline("isolcpus=domain,managed_irq,1,3"), vec![1, 3]);
        assert_eq!(isolated_by_cmdline("isolcpus=nohz,managed_irq,1-3"), Vec::<u32>::new());
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
        assert_eq!(manager_affinity(&[conf("[Manager]\nCPUAffinity=numa\n")]), None);
        assert_eq!(manager_affinity(&[conf("[Other]\nCPUAffinity=0\n")]), None);
        assert_eq!(manager_affinity(&[conf("[Manager]\nCPUAffinity=0 2\n")]), Some(vec![0, 2]));
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
        // the files in systemd's order
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("etc/systemd/system.conf.d")).unwrap();
        std::fs::create_dir_all(t.path().join("usr/lib/systemd/system.conf.d")).unwrap();
        std::fs::write(t.path().join("etc/systemd/system.conf"), "[Manager]\nCPUAffinity=0-3\n").unwrap();
        std::fs::write(t.path().join("usr/lib/systemd/system.conf.d/10-a.conf"), "[Manager]\nCPUAffinity=0\n").unwrap();
        std::fs::write(t.path().join("etc/systemd/system.conf.d/10-a.conf"), "[Manager]\nCPUAffinity=0-1\n").unwrap();
        std::fs::write(t.path().join("etc/systemd/system.conf.d/20-b.txt"), "[Manager]\nCPUAffinity=3\n").unwrap();
        assert_eq!(manager_affinity(&system_conf_files(t.path())), Some(vec![0, 1]));
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
        let r = read_under(root, all(), Some(START.into()), None, vec![(1, vec![0])]);
        assert_eq!(r.effective, Some(vec![0]), "the root's, the nearest with the file");
        assert_eq!(r.configured, vec![(SLICE.to_string(), vec![0, 1])]);
        assert_eq!(partitions_under(root), vec!["/k349part root 1-3".to_string()]);
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
            assert!(online.is_empty() || subset(cpus, &online), "{cpus:?} {online:?}");
        }
    }
}
