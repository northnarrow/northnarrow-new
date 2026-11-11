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

use crate::cgroup_floors::{below_floor, floor_on, FloorRole};
use common::cgroup_limits::limit_kind_of;

/// The unit search path, highest precedence first: where the drop-ins and
/// the copies of a unit are read from (the agent's integrity round, this
/// judge, the watchdog before a respawn).
pub const UNIT_SEARCH_PATH: &[&str] = &[
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

/// The first harmful directive of `harms` — what withholds a reload (a
/// breaks-the-agent warning does not).
pub fn withholding(harms: &[Harm]) -> Option<&Harm> {
    harms.iter().find(|h| h.kind == Kind::Harmful)
}

/// The harmful drop-ins of this host (the unit search path under `/`).
pub fn harmful_here() -> Vec<Harm> {
    let roots: Vec<&Path> = UNIT_SEARCH_PATH.iter().map(Path::new).collect();
    harmful(&roots, &HostLimits::read())
}

/// The type- and slice-wide drop-in directories, under each directory of
/// the unit search path, and whom they reach.
pub const TYPE_DIRS: &[(&str, Reach)] =
    &[("service.d", Reach::Services), ("slice.d", Reach::Slices)];

/// Whom a drop-in directory reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Every service: our two units.
    Services,
    /// Every slice: `system.slice`, our units' slice.
    Slices,
    /// `northnarrow.slice`, the units' slice of their own (lot 273d; its
    /// drop-in directories are ours, judged at a window's close).
    OurSlice,
    /// Lot 273d: the agent's unit alone (its own drop-in directory).
    Agent,
    /// Lot 273d: the watchdog's unit alone.
    Watchdog,
}

impl Reach {
    fn who(self) -> &'static str {
        match self {
            Reach::Services => "northnarrow-agent.service and northnarrow-watchdog.service",
            Reach::Slices => "every slice, the units' northnarrow.slice among them",
            Reach::OurSlice => "northnarrow.slice, the units' slice",
            Reach::Agent => "northnarrow-agent.service",
            Reach::Watchdog => "northnarrow-watchdog.service",
        }
    }

    /// The floor roles a value is judged against: both units for a
    /// service drop-in (below either one's floor is harmful), the slice's
    /// for a slice drop-in.
    fn roles(self) -> &'static [FloorRole] {
        match self {
            Reach::Services => &[FloorRole::Agent, FloorRole::Watchdog],
            Reach::Slices | Reach::OurSlice => &[FloorRole::Slice],
            Reach::Agent => &[FloorRole::Agent],
            Reach::Watchdog => &[FloorRole::Watchdog],
        }
    }
}

/// What the host is: what a percentage is of, what a slice's floors follow
/// (`crate::cgroup_floors::Host`), its online CPUs, and what the
/// conditions read (lot 273d: evaluated on their merits).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostLimits {
    /// Bytes of physical memory (`MemTotal`).
    pub mem_total: u64,
    /// The system's maximum number of tasks (`min(pid_max, threads-max)`).
    pub tasks_max: u64,
    /// The online CPUs.
    pub cpus: Vec<u32>,
    /// systemd's `Virtualization` (empty: none), when it was read.
    pub virtualization: Option<String>,
    pub hostname: String,
    pub machine_id: String,
    /// `/proc/cmdline`'s words.
    pub cmdline: Vec<String>,
    /// systemd's name of the architecture (`x86-64`, `arm64`, …).
    pub architecture: String,
    /// The active LSMs (`/sys/kernel/security/lsm`).
    pub lsms: Vec<String>,
    /// The cgroup v2 controllers (`/sys/fs/cgroup/cgroup.controllers`).
    pub controllers: Vec<String>,
}

/// The most a drop-in or an environment file is read of (systemd's own
/// limit on a unit file is far below it).
pub const MAX_CONFIG_BYTES: u64 = 1 << 20;

/// Lot 311 (F4): a configuration file read as bytes, what is not UTF-8
/// replaced (U+FFFD): a byte in a comment no longer hides the file's
/// directives from the judge. The review of #538 (F9): a regular file
/// only, opened without blocking (a FIFO named by `EnvironmentFile=` no
/// longer stalls the judge) and read up to [`MAX_CONFIG_BYTES`] (nor does
/// `/dev/zero` exhaust it); anything else is an error.
pub fn read_lossy(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    f.take(MAX_CONFIG_BYTES).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

impl HostLimits {
    /// This host's (a value that cannot be read is taken as large: a
    /// percentage of it is then not judged harmful).
    pub fn read() -> Self {
        let f = crate::cgroup_floors::Host::read();
        let read = |p: &str| read_lossy(Path::new(p)).unwrap_or_default();
        let words = |t: String| {
            t.split([',', ' ', '\n'])
                .filter(|w| !w.is_empty())
                .map(str::to_string)
                .collect()
        };
        let socket = Path::new(crate::systemd_bus::PRIVATE_SOCKET);
        let virtualization = crate::systemd_bus::manager_property(
            socket,
            std::time::Duration::from_secs(2),
            "Virtualization",
        )
        .ok()
        .and_then(|v| match v {
            crate::systemd_bus::Value::Str(s) => Some(s),
            _ => None,
        });
        // SAFETY: utsname is plain data; uname fills it.
        let mut u: libc::utsname = unsafe { std::mem::zeroed() };
        let machine = if unsafe { libc::uname(&mut u) } == 0 {
            unsafe { std::ffi::CStr::from_ptr(u.machine.as_ptr()) }
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };
        Self {
            mem_total: f.mem_total,
            tasks_max: f.tasks_max,
            cpus: crate::cgroup_floors::cpu_list(&read("/sys/devices/system/cpu/online")),
            virtualization,
            hostname: read("/proc/sys/kernel/hostname").trim().to_string(),
            machine_id: read("/etc/machine-id").trim().to_string(),
            cmdline: words(read("/proc/cmdline")),
            architecture: match machine.as_str() {
                "x86_64" => "x86-64".to_string(),
                "aarch64" => "arm64".to_string(),
                "i686" | "i586" | "i486" | "i386" => "x86".to_string(),
                other => other.to_string(),
            },
            lsms: words(read("/sys/kernel/security/lsm")),
            controllers: words(read("/sys/fs/cgroup/cgroup.controllers")),
        }
    }

    fn floors(&self) -> crate::cgroup_floors::Host {
        crate::cgroup_floors::Host {
            mem_total: self.mem_total,
            cpus: if self.cpus.is_empty() {
                u32::MAX
            } else {
                self.cpus.len() as u32
            },
            tasks_max: self.tasks_max,
        }
    }

    /// `true` when CPU list `v` leaves out an online CPU (an unknown host:
    /// not judged).
    fn narrower_cpus(&self, v: &str) -> bool {
        let set = crate::cgroup_floors::cpu_list(v);
        !self.cpus.is_empty() && !set.is_empty() && self.cpus.iter().any(|c| !set.contains(c))
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

/// The environment variables that change the agent: its own switches (a
/// prefix) and the dynamic loader's code injection (whole names). Lot 273d
/// (the review of #492): an allocator's or a runtime's tuning
/// (`MALLOC_ARENA_MAX`, `RUST_LOG`, `GLIBC_TUNABLES`) is not harmful — an
/// alert at most.
pub const DANGEROUS_ENV: &[&str] = &["NN_", "NORTHNARROW_"];
/// The loader's variables and (the last review of #497, RC1) those that
/// point a tool the agent runs elsewhere — the xtables modules, rpm's
/// configuration — or redirect systemd's notifications: harmful in any
/// drop-in that reaches our units, ours or the host's.
pub const DANGEROUS_ENV_NAMES: &[&str] = &[
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "XTABLES_LIBDIR",
    "IPTABLES_LIB_DIR",
    "RPM_CONFIGDIR",
    "NOTIFY_SOCKET",
];

/// `var` changes the agent.
pub fn dangerous_env(var: &str) -> bool {
    DANGEROUS_ENV.iter().any(|p| var.starts_with(p)) || DANGEROUS_ENV_NAMES.contains(&var)
}

/// What a directive does to our units.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Its value harms them — a limit below their floors, an idle class,
    /// another kill semantics… (`unit_dropin_harmful`; the agent's
    /// reloads withheld while it is on disk).
    Harmful,
    /// Lot 273d (the review of #492): a sandbox or capability setting that
    /// takes away what the agent uses — its next start fails or runs it
    /// blind (`unit_dropin_breaks_agent`, a warning; the reloads go on).
    BreaksAgent,
}

/// One directive of a drop-in, harmful to our units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Harm {
    pub path: PathBuf,
    pub directive: String,
    pub value: String,
    pub why: String,
    pub reach: Reach,
    pub kind: Kind,
}

impl Harm {
    /// One line for the journal and the signed drift.
    pub fn detail(&self) -> String {
        match self.kind {
            Kind::Harmful => format!(
                "{} sets {}={} for {}: {}; held for our units by the deny hooks and the floors \
                 at every registration; the drop-in is the host's (left in place)",
                self.path.display(),
                self.directive,
                self.value,
                self.reach.who(),
                self.why
            ),
            Kind::BreaksAgent => format!(
                "{} sets {}={} for every service: {}; the agent's next start breaks (the \
                 drop-in is the host's, left in place)",
                self.path.display(),
                self.directive,
                self.value,
                self.why
            ),
        }
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

/// The condition `key=value` evaluated as systemd would for our units (run
/// as root, on this host); `None` for one not evaluated here.
fn condition(key: &str, value: &str, host: &HostLimits) -> Option<bool> {
    let base = key
        .strip_prefix("Condition")
        .or_else(|| key.strip_prefix("Assert"))?;
    let v = value.trim().trim_start_matches('|');
    let (neg, p) = match v.strip_prefix('!') {
        Some(p) => (true, p),
        None => (false, v),
    };
    if p.is_empty() {
        // an empty assignment resets the conditions
        return Some(true);
    }
    let path = Path::new(p);
    let holds = match base {
        "Virtualization" => {
            let virt = host.virtualization.as_deref()?;
            let vm = [
                "qemu",
                "kvm",
                "amazon",
                "zvm",
                "vmware",
                "microsoft",
                "oracle",
                "powervm",
                "xen",
                "bochs",
                "uml",
                "parallels",
                "bhyve",
                "qnx",
                "acrn",
                "apple",
                "sre",
                "google",
            ];
            let container = [
                "openvz",
                "lxc",
                "lxc-libvirt",
                "systemd-nspawn",
                "docker",
                "podman",
                "rkt",
                "wsl",
                "proot",
                "pouch",
            ];
            match p {
                "yes" | "true" | "1" => !virt.is_empty(),
                "no" | "false" | "0" => virt.is_empty(),
                "vm" => vm.contains(&virt),
                "container" => container.contains(&virt),
                name => virt == name,
            }
        }
        "Host" => p == host.hostname || p == host.machine_id,
        "KernelCommandLine" => host
            .cmdline
            .iter()
            .any(|w| w == p || (!p.contains('=') && w.split('=').next() == Some(p))),
        "Architecture" => {
            p == host.architecture || (p == "native" && !host.architecture.is_empty())
        }
        "Security" => match p {
            "selinux" | "apparmor" | "smack" | "ima" | "tomoyo" | "landlock" | "bpf" => {
                host.lsms.iter().any(|l| l == p)
            }
            _ => return None,
        },
        "ControlGroupController" => p
            .split_whitespace()
            .all(|c| c == "v2" || host.controllers.iter().any(|x| x == c)),
        "User" => matches!(p, "root" | "0" | "@system"),
        "Group" => matches!(p, "root" | "0"),
        // root holds every capability
        "Capability" => true,
        "FirstBoot" => {
            let first = Path::new("/run/systemd/first-boot").exists();
            match p {
                "yes" | "true" => first,
                "no" | "false" => !first,
                _ => return None,
            }
        }
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
        // a CPU set covering every online CPU narrows nothing
        if file == "cpuset.cpus" && !host.narrower_cpus(&val) {
            return None;
        }
        for role in reach.roles() {
            if let Some(floor) = floor_on(*role, file, &host.floors()) {
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
        // lot 273d: on their merits; one not evaluated here is an alert only
        return match condition(key, v, host) {
            Some(false) => Some("the condition fails here: our units would not start".into()),
            Some(true) | None => None,
        };
    }
    // The rest applies to processes: a service drop-in only.
    if matches!(reach, Reach::Slices | Reach::OurSlice) {
        return None;
    }
    let our_oom = if reach == Reach::Watchdog { -900 } else { -500 };
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
        // lot 273d: narrower than the online CPUs only
        "CPUAffinity" if !v.is_empty() && host.narrower_cpus(v) => {
            Some(format!("CPUs {v}, fewer than the host's online ones"))
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
            .filter(|n| *n > our_oom)
            .map(|n| format!("OOM score {n}, ours is -500 (the agent) and -900 (the watchdog)")),
        "Restart" if reach != Reach::Agent => matches!(v, "no" | "on-success")
            .then(|| format!("Restart {v}: the watchdog's is always")),
        "Slice" => {
            (v != "northnarrow.slice").then(|| format!("another slice ({v}): our cgroups move"))
        }
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
            dangerous_env(var).then(|| format!("{var} set in our units' environment"))
        }),
        "EnvironmentFile" => {
            let p = v.trim_start_matches('-');
            // lot 311 (F4): read as bytes — a byte that is not UTF-8 (a
            // Latin-1 comment) hid the whole file and its LD_PRELOAD
            let text = read_lossy(Path::new(p)).unwrap_or_default();
            text.lines().find_map(|l| {
                let var = l
                    .trim()
                    .trim_start_matches("export ")
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim();
                dangerous_env(var)
                    .then(|| format!("{var} set in our units' environment (from {p})"))
            })
        }
        _ => None,
    }
}

/// The capabilities the agent's unit keeps (its `CapabilityBoundingSet=`).
const OUR_CAPS: &[&str] = &[
    "CAP_BPF",
    "CAP_PERFMON",
    "CAP_NET_ADMIN",
    "CAP_LINUX_IMMUTABLE",
    "CAP_SYS_PTRACE",
    "CAP_DAC_OVERRIDE",
    "CAP_KILL",
    "CAP_SETFCAP",
    "CAP_SETUID",
    "CAP_SETGID",
];

/// The system-call groups a deny list may hold without taking what the
/// agent uses (its own filter denies more).
const HARMLESS_DENY_GROUPS: &[&str] = &[
    "@obsolete",
    "@clock",
    "@cpu-emulation",
    "@swap",
    "@reboot",
    "@module",
    "@mount",
    "@raw-io",
    "@pkey",
];

/// Lot 273d (the review of #492): why `key=value`, in a service drop-in,
/// takes away what the agent uses (its next start fails, or it runs
/// blind); `None` when it does not. systemd merges these into the unit's
/// own: a `SystemCallFilter=` allow list after the agent's deny list is
/// read in the deny list's mode — its calls are denied to the agent.
pub fn breaks(key: &str, value: &str) -> Option<String> {
    let v = value.trim();
    let (invert, list) = match v.strip_prefix('~') {
        Some(l) => (true, l),
        None => (false, v),
    };
    let items: Vec<&str> = list.split_whitespace().collect();
    let yes = |x: &str| !matches!(x, "" | "no" | "false" | "0" | "off");
    match key {
        "SystemCallFilter" if v.is_empty() => None,
        "SystemCallFilter" if !invert => Some(
            "an allow list, merged into the agent's own deny list: its calls are denied to the \
             agent (bpf and perf_event_open among them for @system-service)"
                .into(),
        ),
        "SystemCallFilter" => items
            .iter()
            .find(|c| {
                matches!(**c, "bpf" | "perf_event_open")
                    || (c.starts_with('@') && !HARMLESS_DENY_GROUPS.contains(c))
            })
            .map(|c| format!("denies {c}, which the agent uses")),
        "CapabilityBoundingSet" if v.is_empty() => {
            Some("an empty bounding set: the agent keeps no capability".into())
        }
        "CapabilityBoundingSet" if invert => items
            .iter()
            .find(|c| OUR_CAPS.contains(c))
            .map(|c| format!("takes {c} from the agent's bounding set")),
        "ProtectControlGroups" if yes(v) => {
            Some("/sys/fs/cgroup read-only: the floors are not written".into())
        }
        "ProtectKernelTunables" if yes(v) => {
            Some("/sys read-only: the bpffs pins under /sys/fs/bpf".into())
        }
        "ProtectProc" if matches!(v, "invisible" | "noaccess" | "ptraceable") => {
            Some("the other processes' /proc hidden: the agent judges them there".into())
        }
        "ProcSubset" if v == "pid" => Some("/proc without its system files".into()),
        "PrivateNetwork" if yes(v) => Some("a network namespace of its own".into()),
        "PrivateUsers" if yes(v) => Some("a user namespace: no capability on the host".into()),
        "PrivatePIDs" if yes(v) => Some("a PID namespace of its own".into()),
        "RestrictAddressFamilies" if v == "none" => Some("no socket family".into()),
        "RestrictAddressFamilies" if !v.is_empty() => {
            let needed = ["AF_UNIX", "AF_NETLINK", "AF_INET", "AF_INET6"];
            if invert {
                items
                    .iter()
                    .find(|f| needed.contains(f))
                    .map(|f| format!("denies {f}, which the agent uses"))
            } else {
                needed
                    .iter()
                    .find(|f| !items.contains(f))
                    .map(|f| format!("an allow list without {f}, which the agent uses"))
            }
        }
        "IPAddressDeny"
            if items
                .iter()
                .any(|a| matches!(*a, "any" | "0.0.0.0/0" | "::/0")) =>
        {
            Some("every address denied to the agent".into())
        }
        _ => None,
    }
}

/// The keys whose assignments add to a list (an empty one resets it);
/// every other key's last assignment in a file is the one systemd keeps.
fn merges(key: &str) -> bool {
    key.starts_with("Exec")
        || key.starts_with("Condition")
        || key.starts_with("Assert")
        || matches!(
            key,
            "Environment"
                | "EnvironmentFile"
                | "BindPaths"
                | "BindReadOnlyPaths"
                | "ReadOnlyPaths"
                | "InaccessiblePaths"
                | "NoExecPaths"
                | "TemporaryFileSystem"
                | "SystemCallFilter"
                | "CapabilityBoundingSet"
                | "RestrictAddressFamilies"
                | "IODeviceWeight"
                | "IOReadBandwidthMax"
                | "IOWriteBandwidthMax"
                | "IOReadIOPSMax"
                | "IOWriteIOPSMax"
                | "IPAddressDeny"
        )
}

/// A file's directives as systemd keeps them: the last of a key that does
/// not merge, every one of a key that does (after its last reset), in
/// their order.
pub fn effective(directives: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in directives {
        if merges(&k) {
            if v.is_empty() {
                // the reset itself is judged (an empty ExecStart= loses
                // ours), what it reset is not
                out.retain(|(x, _)| *x != k);
            }
        } else {
            out.retain(|(x, _)| *x != k);
        }
        out.push((k, v));
    }
    out
}

/// The directives of a drop-in's text: `(key, value)`, comments and
/// section headers left out, continuation lines joined.
pub fn directives(text: &str) -> Vec<(String, String)> {
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
                // lot 311 (F4): read as bytes — a drop-in with one byte that
                // is not UTF-8 (a Latin-1 comment) was skipped whole, its
                // harmful directives unseen
                let Ok(text) = read_lossy(&path) else {
                    continue;
                };
                for (key, value) in effective(directives(&text)) {
                    let found = harms(*reach, &key, &value, host)
                        .map(|w| (w, Kind::Harmful))
                        .or_else(|| {
                            (*reach == Reach::Services)
                                .then(|| breaks(&key, &value))
                                .flatten()
                                .map(|w| (w, Kind::BreaksAgent))
                        });
                    if let Some((why, kind)) = found {
                        out.push(Harm {
                            path: path.clone(),
                            directive: key,
                            value,
                            why,
                            reach: *reach,
                            kind,
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

    fn host() -> HostLimits {
        HostLimits {
            mem_total: 16 << 30,
            tasks_max: 4_194_304,
            cpus: vec![0, 1, 2, 3],
            virtualization: Some("kvm".into()),
            hostname: "nn-lab".into(),
            cmdline: vec!["quiet".into(), "lsm=bpf".into()],
            architecture: "x86-64".into(),
            lsms: vec!["capability".into(), "bpf".into()],
            controllers: vec!["cpu".into(), "memory".into(), "pids".into()],
            ..Default::default()
        }
    }

    fn h(reach: Reach, kv: &str) -> Option<String> {
        let (k, v) = kv.split_once('=').unwrap();
        harms(reach, k, v, &host())
    }

    /// Lot 273d (the review of #492): the precision the first version
    /// lacked — an allocator's tuning, a CPU set covering every CPU, a
    /// condition that holds here, a small VM's slice settings.
    #[test]
    fn the_hosts_tuning_and_conditions_are_judged_on_their_merits() {
        for kv in [
            "Environment=MALLOC_ARENA_MAX=2",
            "Environment=RUST_LOG=info GLIBC_TUNABLES=glibc.malloc.tcache_count=0",
            "CPUAffinity=0-3",
            "AllowedCPUs=0,1,2,3",
            "ConditionVirtualization=kvm",
            "ConditionVirtualization=vm",
            "ConditionVirtualization=yes",
            "ConditionHost=nn-lab",
            "ConditionKernelCommandLine=lsm",
            "ConditionArchitecture=x86-64",
            "ConditionSecurity=bpf",
            "ConditionControlGroupController=cpu memory",
            "ConditionACPower=true",
            // lot 273d: the units' own slice
            "Slice=northnarrow.slice",
        ] {
            assert_eq!(h(Reach::Services, kv), None, "{kv}");
        }
        for kv in [
            "Environment=LD_AUDIT=/x.so",
            "CPUAffinity=0",
            "AllowedCPUs=0-1",
            "ConditionVirtualization=!kvm",
            "ConditionVirtualization=container",
            "ConditionHost=other",
            "ConditionKernelCommandLine=nn.off",
            "ConditionSecurity=selinux",
            "ConditionControlGroupController=io",
            "ConditionUser=nobody",
        ] {
            assert!(h(Reach::Services, kv).is_some(), "{kv}");
        }
        // a small VM: 1 GiB, 1 CPU
        let small = HostLimits {
            mem_total: 1 << 30,
            tasks_max: 32768,
            cpus: vec![0],
            ..Default::default()
        };
        for kv in ["MemoryHigh=80%", "CPUQuota=50%", "TasksMax=2048"] {
            let (k, v) = kv.split_once('=').unwrap();
            assert_eq!(harms(Reach::OurSlice, k, v, &small), None, "{kv}");
        }
        let (k, v) = ("MemoryMax", "256M");
        assert!(harms(Reach::OurSlice, k, v, &small).is_some());
    }

    /// Lot 273d: the sandbox and capability settings that take away what
    /// the agent uses are a separate warning; harmless ones are not.
    #[test]
    fn what_breaks_the_agent_is_told_apart() {
        let b = |kv: &str| {
            let (k, v) = kv.split_once('=').unwrap();
            breaks(k, v)
        };
        for kv in [
            "SystemCallFilter=@system-service",
            "SystemCallFilter=~bpf",
            "SystemCallFilter=~@privileged",
            "CapabilityBoundingSet=~CAP_BPF CAP_SYS_ADMIN",
            "CapabilityBoundingSet=",
            "ProtectControlGroups=yes",
            "ProtectKernelTunables=true",
            "ProtectProc=invisible",
            "ProcSubset=pid",
            "PrivateNetwork=yes",
            "PrivateUsers=yes",
            "RestrictAddressFamilies=AF_INET AF_INET6",
            "RestrictAddressFamilies=~AF_NETLINK",
            "IPAddressDeny=any",
        ] {
            assert!(b(kv).is_some(), "{kv}");
        }
        // an allow list is one, whatever it names (merged into the agent's
        // deny list, its calls are denied to the agent)
        assert!(b("SystemCallFilter=@system-service")
            .unwrap()
            .contains("an allow list"));
        assert!(b("SystemCallFilter=read write")
            .unwrap()
            .contains("an allow list"));
        for kv in [
            "SystemCallFilter=~@obsolete @swap",
            "SystemCallFilter=",
            "CapabilityBoundingSet=~CAP_SYS_BOOT",
            "CapabilityBoundingSet=CAP_NET_RAW",
            "ProtectControlGroups=no",
            "ProtectSystem=strict",
            "RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6",
            "IPAddressDeny=10.0.0.0/8",
        ] {
            assert_eq!(b(kv), None, "{kv}");
        }
    }

    /// Lot 273d: systemd keeps a key's last assignment in a file (a list's
    /// assignments add up, an empty one resets them).
    #[test]
    fn a_files_last_assignment_is_the_one_judged() {
        let e = effective(directives(
            "[Service]\nMemoryMax=4K\nMemoryMax=8G\nEnvironment=NN_X=1\nEnvironment=\nEnvironment=A=1\n",
        ));
        assert_eq!(
            e,
            vec![
                ("MemoryMax".to_string(), "8G".to_string()),
                ("Environment".to_string(), "".to_string()),
                ("Environment".to_string(), "A=1".to_string()),
            ]
        );
    }

    /// The review of #492 (C1): the host's legitimate configuration is
    /// not harmful to our units, and is never touched.
    #[test]
    fn the_hosts_own_configuration_is_not_harmful() {
        for kv in [
            "LimitNOFILE=1048576",
            "LimitNOFILE=65536:1048576",
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
            assert_eq!(h(Reach::OurSlice, kv), None, "{kv}");
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
        // a slice drop-in, judged against the slice's floors
        let sl = |kv| h(Reach::OurSlice, kv).unwrap_or_else(|| panic!("{kv} not harmful"));
        assert!(sl("MemoryMax=4K").contains("slice's floor"));
        assert!(
            sl("MemoryMax=600M").contains("slice's floor"),
            "above the agent's, below the slice's"
        );
        assert!(sl("TasksMax=16").contains("pids.max"));
        assert!(h(Reach::Slices, "CPUQuota=10%").is_some());
        // a process setting in a slice drop-in reaches no process
        assert_eq!(h(Reach::OurSlice, "Nice=19"), None);
    }

    #[test]
    fn the_drop_ins_are_read_and_left_where_they_are() {
        let root = tempfile::tempdir().unwrap();
        let svc = root.path().join("service.d");
        let sl = root.path().join("slice.d");
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
        let r = harmful(&[root.path()], &host());
        // the hardening filter breaks the agent (a warning), the 4K harms it
        assert_eq!(r.len(), 2, "{r:?}");
        assert_eq!(
            (r[0].path.as_path(), r[0].kind),
            (scf.as_path(), Kind::BreaksAgent)
        );
        assert!(r[0].detail().contains("the agent's next start breaks"));
        let r = &r[1..];
        assert_eq!(
            (r[0].path.as_path(), r[0].kind),
            (mem.as_path(), Kind::Harmful)
        );
        assert_eq!(
            (r[0].directive.as_str(), r[0].value.as_str()),
            ("MemoryMax", "4K")
        );
        assert!(r[0]
            .detail()
            .contains("for every slice, the units' northnarrow.slice among them"));
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

    /// Lot 311 (the mini-hunt of bug hunt 1.4's F4): a drop-in with one byte
    /// that is not UTF-8 (a Latin-1 comment) is still judged — on main its
    /// read failed and the whole file was skipped, its harmful directive
    /// unseen; an `EnvironmentFile=` with such a byte still shows its
    /// `LD_PRELOAD`.
    #[test]
    fn a_latin1_comment_does_not_hide_a_harmful_drop_in() {
        let root = tempfile::tempdir().unwrap();
        let svc = root.path().join("service.d");
        std::fs::create_dir_all(&svc).unwrap();
        let mem = svc.join("50-mem.conf");
        std::fs::write(&mem, b"# r\xe9glage\n[Service]\nMemoryMax=4K\n").unwrap();
        let r = harmful(&[root.path()], &host());
        assert_eq!(r.len(), 1, "{r:?}");
        assert_eq!(
            (r[0].path.as_path(), r[0].kind),
            (mem.as_path(), Kind::Harmful)
        );
        let env = root.path().join("env");
        std::fs::write(&env, b"# r\xe9glage\nLD_PRELOAD=/tmp/x.so\n").unwrap();
        let found = h(
            Reach::Services,
            &format!("EnvironmentFile={}", env.display()),
        );
        assert!(
            found.as_deref().is_some_and(|w| w.contains("LD_PRELOAD")),
            "{found:?}"
        );
    }

    /// Lot 311 (the review of #538, F9): a configuration file is read
    /// bounded and only when it is a regular file — a FIFO does not stall
    /// the judge, a huge file is cut at the bound, a directory is refused.
    #[test]
    fn a_configuration_read_is_bounded_and_never_blocks() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path and a mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let t0 = std::time::Instant::now();
        assert!(
            read_lossy(&fifo).is_err(),
            "a FIFO is not a configuration file"
        );
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "it did not block"
        );
        assert!(read_lossy(d.path()).is_err(), "a directory either");
        let big = d.path().join("big.conf");
        std::fs::write(&big, vec![b'#'; (MAX_CONFIG_BYTES + 10) as usize]).unwrap();
        assert_eq!(read_lossy(&big).unwrap().len() as u64, MAX_CONFIG_BYTES);
    }
}
