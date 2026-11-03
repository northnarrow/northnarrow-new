//! Lot 273c (the review of #490, and of #492's C1): the host's type- and
//! slice-wide drop-ins that reach our units, judged by what they do to
//! OUR units — never moved, never deleted.
//!
//! systemd applies `service.d/*.conf` to every service (ours included),
//! `slice.d/*.conf` to every slice and `system.slice.d/*.conf` to the slice
//! both units run in, from every directory of the unit search path. The
//! units' own drop-in directories refuse a new entry outside a window
//! (NOCREATE); these are the host's, and what they hold is the host's
//! configuration for every other service too: a global `LimitNOFILE`, a
//! Kubernetes node's `system.slice` reservation, a hardening
//! `SystemCallFilter`, an `LD_PRELOAD` of an allocator. The review of #492
//! found the first version of this module moving every drop-in that named
//! one of ~95 directives, whatever the value — stripping that
//! configuration from every service. Now nothing is moved:
//!
//! * a directive whose VALUE harms our units ([`harms`]) — a resource
//!   limit below their floors (`antitamper_bpf::cgroup_floors`, the same
//!   table the registrations restore), a finite CPU / address-space / data
//!   limit, a nice value above 0, an idle scheduling class, a kill or OOM
//!   semantics other than ours, a condition that fails, an exec line, an
//!   `NN_` / `LD_` variable, another slice or user, a mount over our paths
//!   — is a signed `unit_dropin_harmful` drift, each round it is there;
//!   our units' values are held by the deny hooks (PID 1's write of a
//!   value other than the registered one is refused) and restored to their
//!   floors at every registration (the agent's start, the watchdog's check
//!   of a respawned agent, a window's close);
//! * any other drop-in there is the signed `unit_dropin` finding, as
//!   before (`self_integrity::unit_dropins`): an alert, nothing more.
//!
//! A drop-in the host had before the install is judged the same and never
//! touched. Moving one would take a signed overlay listing what may be
//! quarantined — the only opt-in the design allows, not part of this lot.

use std::path::{Path, PathBuf};

use antitamper_bpf::cgroup_floors::{below_floor, floor_of, FloorRole};
use common::cgroup_limits::limit_kind_of;

/// The type- and slice-wide drop-in directories, under each directory of
/// the unit search path, and whom they reach.
pub const TYPE_DIRS: &[(&str, Reach)] = &[
    ("service.d", Reach::Services),
    ("slice.d", Reach::Slices),
    ("system.slice.d", Reach::SystemSlice),
];

/// Whom a drop-in directory reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Every service: our two units.
    Services,
    /// Every slice: `system.slice`, our units' slice.
    Slices,
    /// `system.slice`.
    SystemSlice,
}

impl Reach {
    fn who(self) -> &'static str {
        match self {
            Reach::Services => "northnarrow-agent.service and northnarrow-watchdog.service",
            Reach::Slices | Reach::SystemSlice => "system.slice, the units' slice",
        }
    }

    /// The floor roles a value is judged against: both units for a
    /// service drop-in (below either one's floor is harmful), the slice's
    /// for a slice drop-in.
    fn roles(self) -> &'static [FloorRole] {
        match self {
            Reach::Services => &[FloorRole::Agent, FloorRole::Watchdog],
            Reach::Slices | Reach::SystemSlice => &[FloorRole::Slice],
        }
    }
}

/// What the host gives a percentage of: its memory, its task limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostLimits {
    /// Bytes of physical memory (`MemTotal`).
    pub mem_total: u64,
    /// The system's maximum number of tasks (`min(pid_max, threads-max)`).
    pub tasks_max: u64,
}

impl HostLimits {
    /// This host's, read from `/proc` (a value that cannot be read is
    /// taken as large: a percentage of it is then not judged harmful).
    pub fn read() -> Self {
        let mem_total = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|t| {
                t.lines().find_map(|l| {
                    let kb = l.strip_prefix("MemTotal:")?.trim().strip_suffix("kB")?;
                    kb.trim().parse::<u64>().ok().map(|k| k * 1024)
                })
            })
            .unwrap_or(u64::MAX);
        let read = |p: &str| {
            std::fs::read_to_string(p)
                .ok()
                .and_then(|t| t.trim().parse::<u64>().ok())
                .unwrap_or(u64::MAX)
        };
        let tasks_max = read("/proc/sys/kernel/pid_max").min(read("/proc/sys/kernel/threads-max"));
        Self {
            mem_total,
            tasks_max,
        }
    }
}

/// Our paths: what a mount directive must not cover.
pub const OUR_PATHS: &[&str] = &[
    "/usr/local/bin",
    "/etc/northnarrow",
    "/var/lib/northnarrow",
    "/run/northnarrow",
    "/sys/fs/bpf",
    "/sys/fs/cgroup",
];

/// The environment variables that change the agent: its own switches, the
/// dynamic loader's, the allocator's.
pub const DANGEROUS_ENV: &[&str] = &["NN_", "LD_", "RUST_", "MALLOC_", "GLIBC_"];

/// One directive of a drop-in, harmful to our units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Harm {
    pub path: PathBuf,
    pub directive: String,
    pub value: String,
    pub why: String,
    pub reach: Reach,
}

impl Harm {
    /// One line for the journal and the signed drift.
    pub fn detail(&self) -> String {
        format!(
            "{} sets {}={} for {}: {}; held for our units by the deny hooks and the floors at \
             every registration; the drop-in is the host's (left in place)",
            self.path.display(),
            self.directive,
            self.value,
            self.reach.who(),
            self.why
        )
    }
}

/// `size` in bytes (`infinity` and an empty value: `None`, no limit): a
/// number with an optional base-1024 suffix, or a percentage of `total`.
fn bytes(v: &str, total: u64) -> Option<u128> {
    let v = v.trim();
    if v.is_empty() || v == "infinity" {
        return None;
    }
    if let Some(p) = v.strip_suffix('%') {
        let p: f64 = p.trim().parse().ok()?;
        return Some((total as f64 * p / 100.0) as u128);
    }
    let (num, mul) = match v.chars().last()? {
        'K' | 'k' => (&v[..v.len() - 1], 1u128 << 10),
        'M' | 'm' => (&v[..v.len() - 1], 1 << 20),
        'G' | 'g' => (&v[..v.len() - 1], 1 << 30),
        'T' | 't' => (&v[..v.len() - 1], 1 << 40),
        'P' | 'p' => (&v[..v.len() - 1], 1 << 50),
        'E' | 'e' => (&v[..v.len() - 1], 1 << 60),
        _ => (v, 1),
    };
    let n: f64 = num.trim().parse().ok()?;
    Some((n * mul as f64) as u128)
}

/// A resource limit's soft and hard values (`infinity` as `None`).
fn rlimit(v: &str) -> (Option<u128>, Option<u128>) {
    let one = |s: &str| bytes(s, u64::MAX);
    match v.split_once(':') {
        Some((s, h)) => (one(s), one(h)),
        None => (one(v), one(v)),
    }
}

/// `true` when `path` is one of ours, or inside one, or (`parent_too`)
/// above one.
fn touches_ours(path: &str, parent_too: bool) -> bool {
    let p = path
        .trim_start_matches(['-', '+', '!'])
        .trim_end_matches('/');
    if p.is_empty() {
        return parent_too;
    }
    OUR_PATHS.iter().any(|ours| {
        let inside = p == *ours || p.starts_with(&format!("{ours}/"));
        let above = ours.starts_with(&format!("{p}/"));
        inside || (parent_too && above)
    })
}

/// The cgroup file a resource directive sets, and its value as the file
/// would hold it (`None`: the directive sets no limit).
fn cgroup_value(key: &str, value: &str, host: &HostLimits) -> Option<(&'static str, String)> {
    let v = value.trim();
    Some(match key {
        "MemoryMax" | "MemoryLimit" => ("memory.max", bytes(v, host.mem_total)?.to_string()),
        "MemoryHigh" => ("memory.high", bytes(v, host.mem_total)?.to_string()),
        "TasksMax" => ("pids.max", bytes(v, host.tasks_max)?.to_string()),
        "CPUQuota" => {
            let p: f64 = v.strip_suffix('%')?.trim().parse().ok()?;
            ("cpu.max", format!("{} 100000", (p * 1000.0) as u64))
        }
        "CPUWeight" | "StartupCPUWeight" if v == "idle" => ("cpu.idle", "1".into()),
        "CPUWeight" | "StartupCPUWeight" => ("cpu.weight", v.to_string()),
        // the v1 shares, as systemd maps them to a weight (1024 = 100)
        "CPUShares" | "StartupCPUShares" => {
            let s: u64 = v.parse().ok()?;
            ("cpu.weight", (s * 100 / 1024).to_string())
        }
        "IOWeight" | "StartupIOWeight" => ("io.weight", format!("default {v}")),
        "IODeviceWeight" => {
            let w = v.split_whitespace().nth(1)?;
            ("io.weight", format!("default {w}"))
        }
        "IOReadBandwidthMax"
        | "IOWriteBandwidthMax"
        | "IOReadIOPSMax"
        | "IOWriteIOPSMax"
        | "BlockIOReadBandwidth"
        | "BlockIOWriteBandwidth" => {
            let mut it = v.split_whitespace();
            let dev = it.next()?;
            let limit = it.next()?;
            if limit == "infinity" || limit == "max" {
                return None;
            }
            ("io.max", format!("{dev} rbps={limit}"))
        }
        "AllowedCPUs" | "StartupAllowedCPUs" if !v.is_empty() => ("cpuset.cpus", v.to_string()),
        "AllowedMemoryNodes" | "StartupAllowedMemoryNodes" if !v.is_empty() => {
            ("cpuset.mems", v.to_string())
        }
        _ => return None,
    })
}

/// The condition `key=value` evaluated as systemd would, for the path
/// conditions; `None` for the others (not evaluated here).
fn path_condition(key: &str, value: &str) -> Option<bool> {
    let base = key
        .strip_prefix("Condition")
        .or_else(|| key.strip_prefix("Assert"))?;
    let v = value.trim().trim_start_matches('|');
    let (neg, p) = match v.strip_prefix('!') {
        Some(p) => (true, p),
        None => (false, v),
    };
    let path = Path::new(p);
    let holds = match base {
        "PathExists" => path.exists(),
        "PathIsDirectory" => path.is_dir(),
        "FileNotEmpty" => std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() > 0),
        "DirectoryNotEmpty" => std::fs::read_dir(path).is_ok_and(|mut d| d.next().is_some()),
        "FileIsExecutable" => {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        }
        "PathIsSymbolicLink" => {
            std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
        }
        _ => return None,
    };
    Some(holds != neg)
}

/// Why `key=value`, set for `reach`, harms our units; `None` when it does
/// not (the directive is the host's business, an alert at most).
pub fn harms(reach: Reach, key: &str, value: &str, host: &HostLimits) -> Option<String> {
    let v = value.trim();
    // A resource limit, judged against the floors of whom it reaches.
    if let Some((file, val)) = cgroup_value(key, v, host) {
        let kind = limit_kind_of(file);
        for role in reach.roles() {
            if let Some(floor) = floor_of(*role, file) {
                if below_floor(kind, &val, &floor) {
                    return Some(format!(
                        "{file} {val:?} is below the {} floor {floor:?}",
                        match role {
                            FloorRole::Agent => "agent's",
                            FloorRole::Watchdog => "watchdog's",
                            FloorRole::Slice => "slice's",
                        }
                    ));
                }
            }
        }
        return None;
    }
    if key.starts_with("Condition") || key.starts_with("Assert") {
        return match path_condition(key, v) {
            Some(true) => None,
            Some(false) => Some("the condition fails here: our units would not start".into()),
            None => {
                Some("a condition not evaluated here: it may skip or fail our units' start".into())
            }
        };
    }
    // The rest applies to processes: a service drop-in only.
    if reach != Reach::Services {
        return None;
    }
    match key {
        // any value but `infinity` (a number, a size, a time span) is finite
        "LimitCPU" | "LimitAS" | "LimitDATA" | "LimitRSS" | "LimitFSIZE" => v
            .split(':')
            .any(|part| !matches!(part.trim(), "" | "infinity"))
            .then(|| "a finite limit: the kernel ends or fails the agent at it".into()),
        "LimitNOFILE" => {
            let (s, h) = rlimit(v);
            (s.is_some_and(|n| n < 1024) || h.is_some_and(|n| n < 1024))
                .then(|| "below 1024 open files".into())
        }
        "LimitMEMLOCK" => {
            let (s, h) = rlimit(v);
            (s.is_some_and(|n| n < 64 << 10) || h.is_some_and(|n| n < 64 << 10))
                .then(|| "below 64 KiB of locked memory".into())
        }
        "LimitSTACK" => {
            let (s, _) = rlimit(v);
            s.is_some_and(|n| n < 1 << 20)
                .then(|| "below 1 MiB of stack".into())
        }
        "Nice" => v
            .parse::<i32>()
            .ok()
            .filter(|n| *n > 0)
            .map(|n| format!("nice {n}: a lower priority than every other service's")),
        "CPUSchedulingPolicy" => {
            matches!(v, "idle" | "batch").then(|| format!("the {v} scheduling class"))
        }
        "IOSchedulingClass" => matches!(v, "idle" | "3").then(|| "the idle I/O class".into()),
        "CPUAffinity" | "NUMAMask" if !v.is_empty() => {
            Some("a CPU or memory node set narrower than the host's".into())
        }
        "KillMode" => {
            (v != "control-group").then(|| format!("KillMode {v}, ours is control-group"))
        }
        "KillSignal" => (!matches!(v, "SIGTERM" | "TERM" | "15"))
            .then(|| format!("KillSignal {v}, ours is SIGTERM")),
        "SendSIGKILL" => (!matches!(v, "no" | "false" | "0" | "off"))
            .then(|| "SendSIGKILL on, ours is off".into()),
        "FinalKillSignal" => {
            (!matches!(v, "SIGKILL" | "KILL" | "9")).then(|| format!("FinalKillSignal {v}"))
        }
        "OOMPolicy" => {
            (v == "kill").then(|| "OOMPolicy kill: one worker's OOM ends the unit".into())
        }
        "OOMScoreAdjust" => v
            .parse::<i32>()
            .ok()
            .filter(|n| *n > -500)
            .map(|n| format!("OOM score {n}, ours is -500 (the agent) and -900 (the watchdog)")),
        "Restart" => matches!(v, "no" | "on-success")
            .then(|| format!("Restart {v}: the watchdog's is always")),
        "Slice" => (v != "system.slice").then(|| format!("another slice ({v}): our cgroups move")),
        "User" => {
            (!matches!(v, "" | "root" | "0")).then(|| format!("user {v}: the agent needs root"))
        }
        "DynamicUser" => (!matches!(v, "no" | "false" | "0" | "off"))
            .then(|| "a dynamic user: the agent needs root".into()),
        "RootDirectory"
        | "RootImage"
        | "MountImages"
        | "ExtensionImages"
        | "ExtensionDirectories"
            if !v.is_empty() =>
        {
            Some("another root or image: our binaries and files are not there".into())
        }
        "BindPaths" | "BindReadOnlyPaths" => v
            .split_whitespace()
            .filter_map(|b| b.split(':').nth(1).or(Some(b)))
            .find(|dst| touches_ours(dst, false))
            .map(|dst| format!("a bind mount over {dst}, one of our paths")),
        "ReadOnlyPaths" | "InaccessiblePaths" | "NoExecPaths" => v
            .split_whitespace()
            .find(|p| touches_ours(p, false))
            .map(|p| format!("{p} is one of our paths")),
        "TemporaryFileSystem" => v
            .split_whitespace()
            .map(|t| t.split(':').next().unwrap_or(t))
            .find(|p| touches_ours(p, true))
            .map(|p| format!("a tmpfs over {p}: our paths are not there")),
        "ExecStart" | "ExecStartPre" | "ExecStartPost" | "ExecCondition" => {
            Some("a command our units would run, or lose, at their start".into())
        }
        "Environment" => v.split_whitespace().find_map(|a| {
            let var = a.trim_matches('"').split('=').next().unwrap_or("");
            DANGEROUS_ENV
                .iter()
                .any(|p| var.starts_with(p))
                .then(|| format!("{var} set in our units' environment"))
        }),
        "EnvironmentFile" => {
            let p = v.trim_start_matches('-');
            let text = std::fs::read_to_string(p).unwrap_or_default();
            text.lines().find_map(|l| {
                let var = l
                    .trim()
                    .trim_start_matches("export ")
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim();
                DANGEROUS_ENV
                    .iter()
                    .any(|pre| var.starts_with(pre))
                    .then(|| format!("{var} set in our units' environment (from {p})"))
            })
        }
        _ => None,
    }
}

/// The directives of a drop-in's text: `(key, value)`, comments and
/// section headers left out, continuation lines joined.
fn directives(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if pending.is_empty()
            && (line.is_empty()
                || line.starts_with('#')
                || line.starts_with(';')
                || line.starts_with('['))
        {
            continue;
        }
        if let Some(cont) = line.strip_suffix('\\') {
            pending.push_str(cont);
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        let whole = std::mem::take(&mut pending);
        if let Some((k, v)) = whole.split_once('=') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

/// The harmful directives of the type- and slice-wide drop-ins under
/// `roots` (the unit search path). Reads only: nothing is moved, written
/// or deleted.
pub fn harmful(roots: &[&Path], host: &HostLimits) -> Vec<Harm> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        for (name, reach) in TYPE_DIRS {
            let dir = root.join(name);
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            if let Ok(canon) = std::fs::canonicalize(&dir) {
                if !seen.insert(canon) {
                    continue;
                }
            }
            let mut files: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
            files.sort();
            for path in files {
                if path.extension().and_then(|x| x.to_str()) != Some("conf") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for (key, value) in directives(&text) {
                    if let Some(why) = harms(*reach, &key, &value, host) {
                        out.push(Harm {
                            path: path.clone(),
                            directive: key,
                            value,
                            why,
                            reach: *reach,
                        });
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: HostLimits = HostLimits {
        mem_total: 16 << 30,
        tasks_max: 4_194_304,
    };

    fn h(reach: Reach, kv: &str) -> Option<String> {
        let (k, v) = kv.split_once('=').unwrap();
        harms(reach, k, v, &HOST)
    }

    /// The review of #492 (C1): the host's legitimate configuration is
    /// not harmful to our units, and is never touched.
    #[test]
    fn the_hosts_own_configuration_is_not_harmful() {
        for kv in [
            "LimitNOFILE=1048576",
            "LimitNOFILE=65536:1048576",
            "SystemCallFilter=@system-service",
            "ReadOnlyPaths=/usr/share",
            "InaccessiblePaths=/home",
            "IPAddressDeny=any",
            "TimeoutStopSec=30",
            "MemoryMax=8G",
            "MemoryMax=10%",
            "TasksMax=4096",
            "CPUQuota=200%",
            "CPUWeight=200",
            "IOWeight=500",
            "Nice=-5",
            "KillMode=control-group",
            "OOMScoreAdjust=-900",
            "Environment=http_proxy=http://p:3128",
            "ConditionPathExists=/",
            "MemorySwapMax=0",
        ] {
            assert_eq!(h(Reach::Services, kv), None, "{kv}");
        }
        // a Kubernetes node's system reservation on the slice
        for kv in [
            "MemoryMax=4G",
            "CPUQuota=400%",
            "AllowedCPUs=0-1",
            "TasksMax=infinity",
        ] {
            assert_eq!(h(Reach::SystemSlice, kv), None, "{kv}");
        }
    }

    #[test]
    fn a_value_below_our_floors_or_against_our_semantics_is_harmful() {
        let svc = |kv| h(Reach::Services, kv).unwrap_or_else(|| panic!("{kv} not harmful"));
        assert!(svc("MemoryMax=4K").contains("below the agent's floor"));
        // below the agent's floor, above the watchdog's
        assert!(svc("MemoryMax=256M").contains("agent's"));
        assert!(svc("MemoryMax=1%").contains("memory.max"));
        assert!(svc("MemoryHigh=100M").contains("memory.high"));
        assert!(svc("TasksMax=4").contains("pids.max"));
        assert!(svc("CPUQuota=20%").contains("cpu.max"));
        assert!(svc("CPUWeight=idle").contains("cpu.idle"));
        assert!(svc("CPUWeight=1").contains("cpu.weight"));
        assert!(svc("IOWeight=10").contains("io.weight"));
        assert!(svc("IOWriteBandwidthMax=/dev/sda 1M").contains("io.max"));
        assert!(svc("AllowedCPUs=0").contains("cpuset.cpus"));
        assert!(svc("LimitCPU=1").contains("finite"));
        assert!(svc("LimitCPU=1h").contains("finite"));
        assert!(svc("LimitAS=1G").contains("finite"));
        assert!(svc("LimitNOFILE=16").contains("1024"));
        assert!(svc("LimitMEMLOCK=0").contains("locked"));
        assert!(svc("Nice=19").contains("nice 19"));
        assert!(svc("CPUSchedulingPolicy=idle").contains("idle"));
        assert!(svc("IOSchedulingClass=idle").contains("idle"));
        assert!(svc("KillMode=none").contains("control-group"));
        assert!(svc("SendSIGKILL=yes").contains("SendSIGKILL"));
        assert!(svc("OOMScoreAdjust=1000").contains("OOM score"));
        assert!(svc("OOMPolicy=kill").contains("kill"));
        assert!(svc("Restart=no").contains("watchdog"));
        assert!(svc("Slice=other.slice").contains("slice"));
        assert!(svc("User=nobody").contains("root"));
        assert!(svc("ReadOnlyPaths=/etc/northnarrow").contains("our paths"));
        assert!(svc("InaccessiblePaths=/var/lib/northnarrow/x").contains("our paths"));
        assert!(svc("TemporaryFileSystem=/var").contains("tmpfs over /var"));
        assert!(svc("BindPaths=/tmp/x:/usr/local/bin").contains("/usr/local/bin"));
        assert!(svc("ExecStartPre=/bin/false").contains("start"));
        assert!(
            svc("Environment=\"A=1\" NN_ANTI_TAMPER_ALLOW_DEGRADED=1").contains("NN_ANTI_TAMPER")
        );
        assert!(svc("Environment=LD_PRELOAD=/usr/lib/libjemalloc.so").contains("LD_PRELOAD"));
        assert!(svc("ConditionPathExists=/nonexistent-nn-lab").contains("fails"));
        assert!(svc("ConditionVirtualization=kvm").contains("not evaluated"));
        // a slice drop-in, judged against the slice's floors
        let sl = |kv| h(Reach::SystemSlice, kv).unwrap_or_else(|| panic!("{kv} not harmful"));
        assert!(sl("MemoryMax=4K").contains("slice's floor"));
        assert!(
            sl("MemoryMax=600M").contains("slice's floor"),
            "above the agent's, below the slice's"
        );
        assert!(sl("TasksMax=16").contains("pids.max"));
        assert!(h(Reach::Slices, "CPUQuota=10%").is_some());
        // a process setting in a slice drop-in reaches no process
        assert_eq!(h(Reach::SystemSlice, "Nice=19"), None);
    }

    #[test]
    fn the_drop_ins_are_read_and_left_where_they_are() {
        let root = tempfile::tempdir().unwrap();
        let svc = root.path().join("service.d");
        let sl = root.path().join("system.slice.d");
        std::fs::create_dir_all(&svc).unwrap();
        std::fs::create_dir_all(&sl).unwrap();
        let nofile = svc.join("10-nofile.conf");
        let scf = svc.join("20-hardening.conf");
        let mem = sl.join("99-mem.conf");
        std::fs::write(&nofile, "[Service]\nLimitNOFILE=1048576\n").unwrap();
        std::fs::write(&scf, "[Service]\nSystemCallFilter=@system-service\n").unwrap();
        std::fs::write(&mem, "[Slice]\nMemoryMax=4K\n").unwrap();
        std::fs::write(svc.join("notes.txt"), "MemoryMax=4K").unwrap();
        let before: Vec<_> = [&nofile, &scf, &mem]
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        let r = harmful(&[root.path()], &HOST);
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(r[0].path, mem);
        assert_eq!(
            (r[0].directive.as_str(), r[0].value.as_str()),
            ("MemoryMax", "4K")
        );
        assert!(r[0].detail().contains("for system.slice, the units' slice"));
        assert!(r[0].detail().contains("left in place"));
        let after: Vec<_> = [&nofile, &scf, &mem]
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        assert_eq!(before, after, "nothing moved or changed");
    }

    #[test]
    fn continuation_lines_and_comments_are_read_as_systemd_reads_them() {
        assert_eq!(
            directives("[Service]\n# MemoryMax=4K\n; TasksMax=1\nEnvironment=A=1 \\\n  NN_X=1\n"),
            vec![("Environment".to_string(), "A=1  NN_X=1".to_string())]
        );
    }
}
