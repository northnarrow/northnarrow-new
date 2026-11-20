//! Lot 374: what a start of the agent or the watchdog checks of itself
//! before it takes its role, and what the surviving role reads of the
//! process that takes the other one.
//!
//! * [`LOADER_ENV`]: the dynamic loader's and the C library's variables —
//!   code, a library path or the allocator's behaviour given to a process
//!   before its `main` runs. Our units unset every one of them
//!   (`UnsetEnvironment=`, which systemd applies last, whatever the
//!   service manager's own environment holds), and so does the one
//!   transient unit the agent starts ([`systemd_run_unset`]).
//! * [`check_self`]: the start's own environment and the files it has
//!   mapped executable. A loader variable, or an executable mapping that
//!   is neither the binary itself nor one of the libraries the release
//!   links ([`EXPECTED_LIBS`], in a system library directory, root's and
//!   writable by nobody else), refuses the start; each binary signs the
//!   refusal its own way, before it takes its role.
//! * [`inspect`] and [`identity`]: the same facts of another process
//!   (`/proc/<pid>/environ`, `/proc/<pid>/maps`), and where it was
//!   started — its parent and its cgroup — read by the surviving role of
//!   the process that took the vacated one, and recorded by it.
//!
//! Only names are reported, never a value: a variable's value or a
//! library's contents are the operator's to read.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

/// The dynamic loader's variables (glibc's `ld.so`), the C library's that
/// load code or files, or change the allocator (glibc's `UNSECURE_ENVVARS`,
/// the list it drops for a set-id program, and the `MALLOC_` aliases of its
/// tunables). Unset by our units and refused at their start.
pub const LOADER_ENV: &[&str] = &[
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_ASSUME_KERNEL",
    "LD_BIND_NOT",
    "LD_BIND_NOW",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_ORIGIN_PATH",
    "LD_POINTER_GUARD",
    "LD_PREFER_MAP_32BIT_EXEC",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_SHOW_AUXV",
    "LD_TRACE_LOADED_OBJECTS",
    "LD_TRACE_PRELINKING",
    "LD_USE_LOAD_BIAS",
    "LD_VERBOSE",
    "LD_WARN",
    "GCONV_PATH",
    "GETCONF_DIR",
    "GLIBC_TUNABLES",
    "HOSTALIASES",
    "LOCALDOMAIN",
    "LOCPATH",
    "MALLOC_ARENA_MAX",
    "MALLOC_ARENA_TEST",
    "MALLOC_CHECK_",
    "MALLOC_MMAP_MAX_",
    "MALLOC_MMAP_THRESHOLD_",
    "MALLOC_PERTURB_",
    "MALLOC_TOP_PAD_",
    "MALLOC_TRACE",
    "MALLOC_TRIM_THRESHOLD_",
    "NIS_PATH",
    "NLSPATH",
    "RESOLV_HOST_CONF",
    "RES_OPTIONS",
    "TZDIR",
];

/// The shared libraries a release binary may need: the release's own gate
/// (`deploy/release/glibc-baseline.sh`, `ALLOWED_LIBS`, which every shipped
/// ELF file passes) — glibc's libraries, its loader and libgcc_s. The
/// xtask ratchet `start_check` keeps the two lists equal.
pub const EXPECTED_LIBS: &[&str] = &[
    "libc.so.6",
    "libm.so.6",
    "libgcc_s.so.1",
    "ld-linux-x86-64.so.2",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "libutil.so.1",
];

/// Where those libraries are installed (Debian's multiarch directories
/// under them, Fedora's `lib64`).
pub const LIB_DIRS: &[&str] = &["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"];

/// `name` is one of [`LOADER_ENV`].
pub fn is_loader_var(name: &[u8]) -> bool {
    LOADER_ENV.iter().any(|v| v.as_bytes() == name)
}

/// The names of the loader variables among `vars` (in [`LOADER_ENV`]'s
/// order, each once).
pub fn loader_vars<I, K>(vars: I) -> Vec<String>
where
    I: IntoIterator<Item = K>,
    K: AsRef<OsStr>,
{
    let names: Vec<K> = vars.into_iter().collect();
    LOADER_ENV
        .iter()
        .filter(|v| names.iter().any(|n| n.as_ref().as_bytes() == v.as_bytes()))
        .map(|v| v.to_string())
        .collect()
}

/// The loader variables of an environment block as `/proc/<pid>/environ`
/// gives it (`NAME=value` strings, each ended by a NUL).
pub fn loader_vars_in_environ(block: &[u8]) -> Vec<String> {
    loader_vars(
        block
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| OsStr::from_bytes(s.split(|b| *b == b'=').next().unwrap_or(s))),
    )
}

/// The value of our units' `UnsetEnvironment=` lines, together: every
/// [`LOADER_ENV`] name, space separated.
pub fn unset_environment() -> String {
    LOADER_ENV.join(" ")
}

/// The `systemd-run` argument that gives a transient unit the same
/// `UnsetEnvironment=` as our units.
pub fn systemd_run_unset() -> String {
    format!("--property=UnsetEnvironment={}", unset_environment())
}

/// One executable mapping of `/proc/<pid>/maps` that is neither the
/// process's binary nor an expected library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Foreign {
    /// The mapped file's path as the kernel shows it.
    pub path: String,
    /// Why it is not expected.
    pub why: &'static str,
}

/// How [`foreign_mappings`] judges a library mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Libs {
    /// A start, before any code of its own ran: only [`EXPECTED_LIBS`].
    Start,
    /// A process that has run: glibc's name-service modules too
    /// (`libnss_<service>.so.2`, which `getpwnam(3)` loads from the system
    /// directory `/etc/nsswitch.conf` names).
    Running,
}

/// What [`foreign_mappings`] needs to know of a mapped file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFacts {
    pub ino: u64,
    pub uid: u32,
    pub mode: u32,
}

/// How [`foreign_mappings`] names executable memory no file backs.
pub const ANONYMOUS_CODE: &str = "[anonymous executable memory]";

/// The re-check of #582 (N4): the files the judge itself has mapped
/// executable — `(device as maps shows it, inode)` — which its own start
/// judged ([`check_self`]). A library a package upgrade replaced on disk
/// stays mapped as "(deleted)" in every process started before it; one
/// the judge maps too is the very file the judge runs (a mapped inode is
/// never freed, so never reused), judged by that identity.
pub type OwnCode = Vec<(String, u64)>;

/// [`OwnCode`] of a `maps` text.
pub fn executable_files(maps: &str) -> OwnCode {
    let mut out: OwnCode = Vec::new();
    for line in maps.lines() {
        let mut f = line.splitn(6, ' ');
        let (Some(_), Some(perms), Some(_), Some(dev), Some(ino)) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let ino: u64 = ino.parse().unwrap_or(0);
        if perms.contains('x') && ino != 0 && !out.iter().any(|(d, i)| d == dev && *i == ino) {
            out.push((dev.to_string(), ino));
        }
    }
    out
}

/// The executable file mappings of a `/proc/<pid>/maps` text that are
/// neither the binary (`exe`: its path as `/proc/<pid>/exe` names it and
/// its inode) nor an expected library — and executable anonymous memory
/// ([`ANONYMOUS_CODE`], lot 374). An expected library is judged by what it
/// is, never by the name `maps` shows: the kernel names a mapping after the
/// file the loader's path resolved to, and a distribution may install a
/// library under a versioned name its expected name links to (RHEL's
/// `libgcc_s.so.1` → `libgcc_s-<gcc>-<date>.so.1`). So the mapped file, under
/// [`LIB_DIRS`], is one of [`EXPECTED_LIBS`] (or a name-service module,
/// [`Libs::Running`]) when that expected name in the same directory
/// resolves (symbolic links followed) to the mapped inode ([`alias_of`]);
/// the file at the mapped path ([`FileFacts`] by `facts`) is the one mapped
/// (its inode), root's and writable by nobody else. The kernel's pseudo
/// mappings (`[vdso]`, `[stack]`, `anon_inode:…`) and the ones that cannot
/// execute are not code of a file. One entry per path.
pub fn foreign_mappings(
    maps: &str,
    exe: (&str, u64),
    libs: Libs,
    facts: impl Fn(&str) -> Option<FileFacts>,
) -> Vec<Foreign> {
    judge_mappings(maps, exe, libs, facts, &[]).0
}

/// [`foreign_mappings`], and (the re-check of #582, N4) for a running
/// process ([`Libs::Running`]) a library a package upgrade replaced since
/// it was mapped ("(deleted)": an expected library's name in a system
/// library directory) judged by its identity, never as foreign on that
/// alone: the very file the judge runs (`own`, [`executable_files`]) is
/// expected; another is returned apart (the second list: replaced, its
/// identity not confirmed).
pub fn judge_mappings(
    maps: &str,
    exe: (&str, u64),
    libs: Libs,
    facts: impl Fn(&str) -> Option<FileFacts>,
    own: &[(String, u64)],
) -> (Vec<Foreign>, Vec<String>) {
    let mut out: Vec<Foreign> = Vec::new();
    let mut replaced: Vec<String> = Vec::new();
    for line in maps.lines() {
        // `start-end perms offset dev inode   path` — the path may hold
        // spaces (and " (deleted)").
        let mut f = line.splitn(6, ' ');
        let (Some(_range), Some(perms), Some(_off), Some(dev), Some(ino)) =
            (f.next(), f.next(), f.next(), f.next(), f.next())
        else {
            continue;
        };
        let path = f.next().unwrap_or("").trim_start();
        let ino: u64 = ino.parse().unwrap_or(0);
        if !perms.contains('x') {
            continue;
        }
        // Executable memory no file backs: code copied there, then its
        // file unmapped, would leave no path to judge. Neither a start nor
        // our daemons make any (the kernel's own pages are named: `[vdso]`);
        // a name a process gives its own (`[anon:…]`, `[anon_shmem:…]`,
        // `PR_SET_VMA_ANON_NAME`) is still anonymous memory.
        if ino == 0 && (path.is_empty() || path.starts_with("[anon")) {
            if !out.iter().any(|o| o.path == ANONYMOUS_CODE) {
                out.push(Foreign {
                    path: ANONYMOUS_CODE.to_string(),
                    why: "executable memory no file backs",
                });
            }
            continue;
        }
        if ino == 0 || !path.starts_with('/') {
            continue;
        }
        if out.iter().any(|o| o.path == path) {
            continue;
        }
        if path == exe.0 && ino == exe.1 {
            continue;
        }
        if libs == Libs::Running {
            if let Some(name) = upgraded_library(path) {
                if own.iter().any(|(d, i)| d == dev && *i == ino) {
                    continue;
                }
                if !replaced.iter().any(|r| r == name) {
                    replaced.push(name.to_string());
                }
                continue;
            }
        }
        if let Some(why) = library_refused(path, ino, libs, &facts) {
            out.push(Foreign {
                path: path.to_string(),
                why,
            });
        }
    }
    (out, replaced)
}

/// The re-check of #582 (N4): `path` as `maps` shows a library a package
/// upgrade replaced since it was mapped — " (deleted)" after the path of
/// an expected library's name (or a name-service module's) in a system
/// library directory — the path without the suffix; `None` otherwise (a
/// deleted file of another name or place stays foreign).
fn upgraded_library(path: &str) -> Option<&str> {
    let p = path.strip_suffix(" (deleted)")?;
    if !LIB_DIRS.iter().any(|d| p.starts_with(d)) || p.contains("/../") || p.contains("/./") {
        return None;
    }
    let name = p.rsplit_once('/')?.1;
    // the versioned file RHEL's `libgcc_s.so.1` links to
    // (`libgcc_s-<gcc>-<date>.so.1`) is the one other name
    let rhel_libgcc = name.starts_with("libgcc_s-") && name.ends_with(".so.1");
    (EXPECTED_LIBS.contains(&name) || rhel_libgcc || is_nss_module(name)).then_some(p)
}

/// Why the library mapped from `path` (inode `ino`) is not expected;
/// `None` when it is.
fn library_refused(
    path: &str,
    ino: u64,
    libs: Libs,
    facts: &impl Fn(&str) -> Option<FileFacts>,
) -> Option<&'static str> {
    if path.ends_with(" (deleted)") {
        return Some("a file deleted since it was mapped");
    }
    if !LIB_DIRS.iter().any(|d| path.starts_with(d))
        || path.contains("/../")
        || path.contains("/./")
    {
        return Some("not in a system library directory");
    }
    let Some(f) = facts(path) else {
        return Some("its file cannot be read");
    };
    if f.ino != ino {
        return Some("its path names another file now");
    }
    if f.uid != 0 || f.mode & 0o022 != 0 {
        return Some("not root's, or writable by another user");
    }
    // the review of #582 (F1): by identity, not by the name maps shows
    if alias_of(path, ino, libs, facts).is_none() {
        return Some("not a library the release links");
    }
    None
}

/// `name` is a glibc name-service module's (`libnss_<service>.so.2`).
fn is_nss_module(name: &str) -> bool {
    name.strip_prefix("libnss_")
        .and_then(|r| r.strip_suffix(".so.2"))
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

/// The review of #582 (F1): the expected library the file mapped from
/// `path` (inode `ino`) is — its own name when that is one of
/// [`EXPECTED_LIBS`] (or a name-service module's, [`Libs::Running`]),
/// else the expected name that, in the same directory, resolves (symbolic
/// links followed, `facts`) to that inode: what the loader opened by that
/// name. `None`: no expected name is that file.
pub fn alias_of(
    path: &str,
    ino: u64,
    libs: Libs,
    facts: &impl Fn(&str) -> Option<FileFacts>,
) -> Option<String> {
    let (dir, name) = path.rsplit_once('/')?;
    if EXPECTED_LIBS.contains(&name) || (libs == Libs::Running && is_nss_module(name)) {
        return Some(name.to_string());
    }
    EXPECTED_LIBS
        .iter()
        .find(|n| facts(&format!("{dir}/{n}")).is_some_and(|f| f.ino == ino))
        .map(|n| n.to_string())
}

/// [`FileFacts`] of the file at `path` (symbolic links followed, as the
/// loader opened it).
pub fn file_facts(path: &str) -> Option<FileFacts> {
    std::fs::metadata(path).ok().map(|m| FileFacts {
        ino: m.ino(),
        uid: m.uid(),
        mode: m.mode(),
    })
}

/// What a check found: the loader variables set and the foreign
/// executable mappings — or why it could not read them (never "clean").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Findings {
    pub loader_vars: Vec<String>,
    pub foreign: Vec<Foreign>,
    pub unreadable: Vec<String>,
    /// The re-check of #582 (N4): libraries replaced on disk since the
    /// process mapped them ([`judge_mappings`]), not the judge's own copy:
    /// their identity not confirmed. Not foreign on that alone.
    pub replaced: Vec<String>,
}

impl Findings {
    /// Nothing foreign found and everything read.
    pub fn clean(&self) -> bool {
        self.loader_vars.is_empty() && self.foreign.is_empty() && self.unreadable.is_empty()
    }

    /// [`Findings::clean`], and every library's identity confirmed (none
    /// [`Findings::replaced`]).
    pub fn confirmed(&self) -> bool {
        self.clean() && self.replaced.is_empty()
    }

    /// One line: what was found, names only.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.loader_vars.is_empty() {
            parts.push(format!("loader variables {}", self.loader_vars.join(",")));
        }
        if !self.foreign.is_empty() {
            let libs: Vec<String> = self
                .foreign
                .iter()
                .take(8)
                .map(|f| format!("{} ({})", f.path, f.why))
                .collect();
            parts.push(format!(
                "executable mappings not expected: {}",
                libs.join("; ")
            ));
        }
        if !self.unreadable.is_empty() {
            parts.push(format!("not read: {}", self.unreadable.join("; ")));
        }
        if !self.replaced.is_empty() {
            let libs: Vec<&str> = self.replaced.iter().take(8).map(String::as_str).collect();
            parts.push(format!(
                "libraries replaced on disk since they were mapped, not the judge's own copy (their \
                 identity not confirmed): {}",
                libs.join("; ")
            ));
        }
        if parts.is_empty() {
            "no loader variable, no executable mapping but the binary and the release's libraries"
                .to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// The largest `maps` or `environ` read (far above a daemon's).
const PROC_MAX: u64 = 4 << 20;

/// The start's own check: its environment ([`std::env::vars_os`]) and its
/// executable mappings ([`Libs::Start`]). Run before the process takes its
/// role, before any code of its own maps another file.
pub fn check_self() -> Findings {
    let vars: Vec<OsString> = std::env::vars_os().map(|(k, _)| k).collect();
    let mut found = Findings {
        loader_vars: loader_vars(vars),
        ..Findings::default()
    };
    mappings_into(&mut found, "/proc/self", Libs::Start);
    found
}

/// The same facts of process `pid`, read by another: its initial
/// environment (`/proc/<pid>/environ`, as it was given at its exec unless
/// the process rewrote it since) and its executable mappings
/// ([`Libs::Running`]).
pub fn inspect(pid: u32) -> Findings {
    let mut found = Findings::default();
    match crate::kernel_roots::read(format!("/proc/{pid}/environ"), PROC_MAX) {
        Ok(block) => found.loader_vars = loader_vars_in_environ(&block),
        Err(e) => found.unreadable.push(format!("environ: {e}")),
    }
    mappings_into(&mut found, &format!("/proc/{pid}"), Libs::Running);
    found
}

/// [`OwnCode`] of this process, read now (empty when unread: then no
/// replaced library is confirmed).
pub fn own_code() -> OwnCode {
    crate::kernel_roots::read("/proc/self/maps", PROC_MAX)
        .map(|b| executable_files(&String::from_utf8_lossy(&b)))
        .unwrap_or_default()
}

fn mappings_into(found: &mut Findings, proc_dir: &str, libs: Libs) {
    let exe = crate::kernel_roots::read_link(format!("{proc_dir}/exe"));
    let exe_ino = crate::kernel_roots::metadata(format!("{proc_dir}/exe")).map(|m| m.ino());
    let maps = crate::kernel_roots::read(format!("{proc_dir}/maps"), PROC_MAX);
    match (exe, exe_ino, maps) {
        (Ok(exe), Ok(ino), Ok(maps)) => {
            let text = String::from_utf8_lossy(&maps);
            let exe = exe.to_string_lossy();
            let own = if libs == Libs::Running {
                own_code()
            } else {
                Vec::new()
            };
            (found.foreign, found.replaced) =
                judge_mappings(&text, (&exe, ino), libs, file_facts, &own);
        }
        (Err(e), _, _) | (_, Err(e), _) => found.unreadable.push(format!("exe: {e}")),
        (_, _, Err(e)) => found.unreadable.push(format!("maps: {e}")),
    }
}

/// Where a process was started: its parent's tgid and its cgroup v2 path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Identity {
    pub ppid: Option<u32>,
    pub cgroup: Option<String>,
}

/// Our slice and units' names (one source with the eBPF programs' check of
/// the same cgroup, `common::wire`).
pub use common::wire::{AGENT_UNIT, OUR_SLICE, WATCHDOG_UNIT};

impl Identity {
    /// Started for the role of `unit` (one of ours): by PID 1, in that
    /// unit's own cgroup under [`OUR_SLICE`] at the hierarchy's root —
    /// the restart systemd makes of the unit, and nothing else.
    pub fn in_unit(&self, unit: &str) -> bool {
        self.ppid == Some(1)
            && self.cgroup.as_deref() == Some(format!("/{OUR_SLICE}/{unit}").as_str())
    }

    /// One line for a record.
    pub fn describe(&self) -> String {
        format!(
            "parent {}, cgroup {}",
            self.ppid
                .map_or_else(|| "unread".to_string(), |p| p.to_string()),
            self.cgroup.as_deref().unwrap_or("unread")
        )
    }
}

/// The parent field of a `/proc/<pid>/stat` text (after the command name,
/// which may hold spaces and parentheses: the last `)`).
pub fn stat_ppid(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// The start of a `/proc/<pid>/stat` text, in clock ticks since boot
/// (field 22).
pub fn stat_start_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// [`stat_start_ticks`] of process `pid`, read now: with its pid, what
/// names one process (a pid is reused, never with the same start).
pub fn start_ticks(pid: u32) -> Option<u64> {
    crate::kernel_roots::read_text(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| stat_start_ticks(&s))
}

/// The re-check of #582 (N4): process `pid`'s start in `CLOCK_BOOTTIME`
/// nanoseconds — its [`stat_start_ticks`] at the clock-tick rate
/// (`_SC_CLK_TCK`), the clock the kernel's liveness watch stamps a role's
/// exit with (`ROLE_EXITS`).
pub fn start_boot_ns(pid: u32) -> Option<u64> {
    // SAFETY: sysconf has no failure mode but -1 for an unknown name.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = u64::try_from(hz).ok().filter(|h| *h > 0)?;
    start_ticks(pid).map(|t| t.saturating_mul(1_000_000_000) / hz)
}

/// `CLOCK_BOOTTIME` now, in nanoseconds (the clock of [`start_boot_ns`]).
pub fn boot_ns_now() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a timespec to fill.
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// The re-check of #582 (N3): a process's start read from `/proc` is
/// rounded down to a clock tick; one that started less than this before a
/// moment may have started after it.
pub const START_SLACK_NS: u64 = 20_000_000;

/// The re-check of #582 (N3): process `pid` started before `at`
/// (`CLOCK_BOOTTIME` ns), beyond [`START_SLACK_NS`]; `false` when its start
/// is not read.
pub fn started_before(pid: u32, at: u64) -> bool {
    start_boot_ns(pid).is_some_and(|s| s.saturating_add(START_SLACK_NS) < at)
}

/// [`stat_start_ticks`] of this process, read now.
pub fn own_start_ticks() -> Option<u64> {
    crate::kernel_roots::read_text("/proc/self/stat")
        .ok()
        .and_then(|s| stat_start_ticks(&s))
}

/// [`Identity`] of process `pid`, read now.
pub fn identity(pid: u32) -> Identity {
    let ppid = crate::kernel_roots::read_text(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| stat_ppid(&s));
    let cgroup = crate::kernel_roots::read_text(format!("/proc/{pid}/cgroup"))
        .ok()
        .and_then(|t| crate::cgroup_guard::v2_path(&t).map(str::to_string));
    Identity { ppid, cgroup }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: (&str, u64) = ("/usr/local/bin/northnarrow-agent", 4242);

    fn sys(path: &str) -> Option<FileFacts> {
        let ino = match path {
            "/usr/lib/x86_64-linux-gnu/libc.so.6" => 10,
            "/usr/lib/x86_64-linux-gnu/libm.so.6" => 11,
            "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1" => 12,
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" => 13,
            "/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2" => 14,
            "/usr/lib/x86_64-linux-gnu/libevil.so" => 15,
            "/usr/lib/x86_64-linux-gnu/libz.so.1" => 16,
            "/lib64/libc.so.6" => 17,
            "/opt/lib/libc.so.6" => 18,
            "/usr/lib/x86_64-linux-gnu/../../../tmp/libc.so.6" => 19,
            "/usr/lib/./x86_64-linux-gnu/libc.so.6" => 20,
            _ => return None,
        };
        Some(FileFacts {
            ino,
            uid: 0,
            mode: 0o100644,
        })
    }

    fn line(perms: &str, ino: u64, path: &str) -> String {
        format!(
            "7f0000000000-7f0000001000 {perms} 00000000 fd:01 {ino}                      {path}\n"
        )
    }

    fn genuine() -> String {
        let mut m = String::new();
        m += &line("r--p", 4242, EXE.0);
        m += &line("r-xp", 4242, EXE.0);
        m += &line("rw-p", 0, "[heap]");
        m += &line("r--p", 10, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        m += &line("r-xp", 10, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        m += &line("r-xp", 11, "/usr/lib/x86_64-linux-gnu/libm.so.6");
        m += &line("r-xp", 12, "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1");
        m += &line("r-xp", 13, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
        m += &line("r-xp", 0, "[vdso]");
        m += &line("rw-s", 77, "anon_inode:bpf-map");
        m += &line("r--p", 99, "/etc/ld.so.cache");
        m += &line("rw-p", 0, "[stack]");
        m
    }

    #[test]
    fn a_genuine_start_maps_nothing_foreign() {
        assert!(foreign_mappings(&genuine(), EXE, Libs::Start, sys).is_empty());
    }

    #[test]
    fn a_preloaded_library_anywhere_is_foreign() {
        for path in [
            "/tmp/x.so",
            "/dev/shm/libc.so.6",
            "/usr/lib/x86_64-linux-gnu/libevil.so",
            "/usr/lib/x86_64-linux-gnu/libz.so.1",
            "/usr/lib/x86_64-linux-gnu/../../../tmp/libc.so.6",
            "/memfd:x (deleted)",
        ] {
            let maps = genuine() + &line("r-xp", 15, path);
            let found = foreign_mappings(&maps, EXE, Libs::Start, sys);
            assert_eq!(found.len(), 1, "{path}: {found:?}");
            assert_eq!(found[0].path, path);
        }
    }

    /// Lot 374: a library of an expected name — readable, root's, the same
    /// file at its path — is still foreign outside the system library
    /// directories, or through a `..` or `.` component (the kernel's own
    /// paths never hold one).
    #[test]
    fn an_expected_library_outside_the_system_directories_is_foreign() {
        for (path, ino) in [
            ("/opt/lib/libc.so.6", 18),
            ("/usr/lib/x86_64-linux-gnu/../../../tmp/libc.so.6", 19),
            ("/usr/lib/./x86_64-linux-gnu/libc.so.6", 20),
        ] {
            let maps = genuine() + &line("r-xp", ino, path);
            let f = foreign_mappings(&maps, EXE, Libs::Start, sys);
            assert_eq!(f.len(), 1, "{path}: {f:?}");
            assert_eq!(f[0].why, "not in a system library directory", "{path}");
        }
    }

    /// Lot 374: code copied into anonymous memory (its file unmapped
    /// after) is foreign; the kernel's named pages are not.
    #[test]
    fn executable_memory_no_file_backs_is_foreign() {
        let maps = genuine() + &line("r-xp", 0, "") + &line("rwxp", 0, "");
        let f = foreign_mappings(&maps, EXE, Libs::Start, sys);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].path, ANONYMOUS_CODE);
        let f = foreign_mappings(&maps, EXE, Libs::Running, sys);
        assert_eq!(f.len(), 1, "{f:?}");
        let named = genuine() + &line("r-xp", 0, "[anon:x]");
        assert_eq!(
            foreign_mappings(&named, EXE, Libs::Start, sys)[0].path,
            ANONYMOUS_CODE
        );
        let named = genuine() + &line("r-xp", 0, "[vsyscall]") + &line("rw-p", 0, "");
        assert!(foreign_mappings(&named, EXE, Libs::Start, sys).is_empty());
    }

    /// The facts of a host's library directory: `files` are `(path, inode)`
    /// of the real files, `links` `(link, target path)` resolved as `stat`
    /// follows them.
    fn host(
        files: &'static [(&'static str, u64)],
        links: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<FileFacts> {
        move |p: &str| {
            let real = links.iter().find(|(l, _)| *l == p).map_or(p, |(_, t)| *t);
            files
                .iter()
                .find(|(f, _)| *f == real)
                .map(|(_, ino)| FileFacts {
                    ino: *ino,
                    uid: 0,
                    mode: 0o100755,
                })
        }
    }

    fn maps_of(files: &[(&str, u64)]) -> String {
        let mut m = String::new();
        m += &line("r-xp", 4242, EXE.0);
        for (p, ino) in files {
            m += &line("r--p", *ino, p);
            m += &line("r-xp", *ino, p);
        }
        m += &line("r-xp", 0, "[vdso]");
        m
    }

    /// The review of #582 (F1): AlmaLinux / RHEL 9 installs libgcc_s under
    /// a versioned name its expected name links to, and the kernel names the
    /// mapping after the file: a genuine start there maps nothing foreign
    /// (it was refused at every start, the agent's and the watchdog's).
    #[test]
    fn a_genuine_alma_start_maps_its_versioned_libgcc_s_by_identity() {
        const FILES: &[(&str, u64)] = &[
            ("/usr/lib64/libc.so.6", 10),
            ("/usr/lib64/libm.so.6", 11),
            ("/usr/lib64/libgcc_s-11-20231218.so.1", 12),
            ("/usr/lib64/ld-linux-x86-64.so.2", 13),
        ];
        const LINKS: &[(&str, &str)] = &[
            (
                "/usr/lib64/libgcc_s.so.1",
                "/usr/lib64/libgcc_s-11-20231218.so.1",
            ),
            // merged /usr: /lib64 is a link to usr/lib64
            (
                "/lib64/libgcc_s.so.1",
                "/usr/lib64/libgcc_s-11-20231218.so.1",
            ),
        ];
        let facts = host(FILES, LINKS);
        for libs in [Libs::Start, Libs::Running] {
            let f = foreign_mappings(&maps_of(FILES), EXE, libs, &facts);
            assert!(
                f.is_empty(),
                "a genuine AlmaLinux 9 start is refused: {f:?}"
            );
        }
        assert_eq!(
            alias_of(
                "/usr/lib64/libgcc_s-11-20231218.so.1",
                12,
                Libs::Start,
                &facts
            )
            .as_deref(),
            Some("libgcc_s.so.1")
        );
    }

    /// The review of #582 (F1): the layouts of the supported distributions
    /// — Debian 12/13 and Ubuntu 22.04/24.04/26.04 (multiarch, merged /usr
    /// or not), Fedora/RHEL multilib (`/usr/lib64` for the 64-bit
    /// libraries, `/usr/lib` the 32-bit ones), a glibc before 2.34 (every
    /// library a versioned file its soname links to) — each a genuine start.
    #[test]
    fn every_supported_library_layout_is_a_genuine_start() {
        const DEB: &[(&str, u64)] = &[
            ("/usr/lib/x86_64-linux-gnu/libc.so.6", 10),
            ("/usr/lib/x86_64-linux-gnu/libm.so.6", 11),
            ("/usr/lib/x86_64-linux-gnu/libgcc_s.so.1", 12),
            ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", 13),
        ];
        const DEB_SPLIT: &[(&str, u64)] = &[
            ("/lib/x86_64-linux-gnu/libc.so.6", 10),
            ("/lib/x86_64-linux-gnu/libm.so.6", 11),
            ("/lib/x86_64-linux-gnu/libgcc_s.so.1", 12),
            ("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", 13),
        ];
        const FEDORA: &[(&str, u64)] = &[
            ("/usr/lib64/libc.so.6", 10),
            ("/usr/lib64/libm.so.6", 11),
            ("/usr/lib64/libgcc_s-14-20250110.so.1", 12),
            ("/usr/lib64/ld-linux-x86-64.so.2", 13),
            // the 32-bit multilib copies, never mapped by a 64-bit start
            ("/usr/lib/libc.so.6", 20),
            ("/usr/lib/libgcc_s-14-20250110.so.1", 22),
        ];
        const OLD_GLIBC: &[(&str, u64)] = &[
            ("/lib/x86_64-linux-gnu/libc-2.31.so", 10),
            ("/lib/x86_64-linux-gnu/libm-2.31.so", 11),
            ("/lib/x86_64-linux-gnu/libgcc_s.so.1", 12),
            ("/lib/x86_64-linux-gnu/ld-2.31.so", 13),
        ];
        const FEDORA_LINKS: &[(&str, &str)] = &[
            (
                "/usr/lib64/libgcc_s.so.1",
                "/usr/lib64/libgcc_s-14-20250110.so.1",
            ),
            (
                "/usr/lib/libgcc_s.so.1",
                "/usr/lib/libgcc_s-14-20250110.so.1",
            ),
        ];
        const OLD_LINKS: &[(&str, &str)] = &[
            (
                "/lib/x86_64-linux-gnu/libc.so.6",
                "/lib/x86_64-linux-gnu/libc-2.31.so",
            ),
            (
                "/lib/x86_64-linux-gnu/libm.so.6",
                "/lib/x86_64-linux-gnu/libm-2.31.so",
            ),
            (
                "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                "/lib/x86_64-linux-gnu/ld-2.31.so",
            ),
        ];
        for (name, files, links) in [
            ("debian/ubuntu merged /usr", DEB, &[][..]),
            ("debian split /usr", DEB_SPLIT, &[][..]),
            ("fedora/rhel multilib", FEDORA, FEDORA_LINKS),
            ("glibc before 2.34", OLD_GLIBC, OLD_LINKS),
        ] {
            let mapped: Vec<(&str, u64)> =
                files.iter().copied().filter(|(_, ino)| *ino < 20).collect();
            let f = foreign_mappings(&maps_of(&mapped), EXE, Libs::Start, host(files, links));
            assert!(f.is_empty(), "{name}: a genuine start is refused: {f:?}");
        }
    }

    /// The review of #582 (F1): identity, not a looser name rule — a file
    /// in a library directory that no expected name resolves to is still
    /// foreign, whatever it is called (a versioned look-alike, another
    /// library under the expected name's prefix, a copy of libc with its
    /// own inode), and so is the 32-bit multilib copy's name in the 64-bit
    /// directory when it is not the same file.
    #[test]
    fn a_file_no_expected_name_resolves_to_is_foreign() {
        const FILES: &[(&str, u64)] = &[
            ("/usr/lib64/libc.so.6", 10),
            ("/usr/lib64/libgcc_s-11-20231218.so.1", 12),
            ("/usr/lib64/libgcc_s-11-evil.so.1", 30),
            ("/usr/lib64/libc-copy.so.6", 31),
            ("/usr/lib64/libz.so.1", 32),
            ("/usr/lib64/sub/libgcc_s-11-20231218.so.1", 33),
        ];
        const LINKS: &[(&str, &str)] = &[(
            "/usr/lib64/libgcc_s.so.1",
            "/usr/lib64/libgcc_s-11-20231218.so.1",
        )];
        let facts = host(FILES, LINKS);
        for (path, ino) in [
            ("/usr/lib64/libgcc_s-11-evil.so.1", 30),
            ("/usr/lib64/libc-copy.so.6", 31),
            ("/usr/lib64/libz.so.1", 32),
            ("/usr/lib64/sub/libgcc_s-11-20231218.so.1", 33),
        ] {
            let maps = maps_of(&[("/usr/lib64/libc.so.6", 10)]) + &line("r-xp", ino, path);
            let f = foreign_mappings(&maps, EXE, Libs::Running, &facts);
            assert_eq!(f.len(), 1, "{path}: {f:?}");
            assert_eq!(f[0].why, "not a library the release links", "{path}");
            assert_eq!(alias_of(path, ino, Libs::Running, &facts), None, "{path}");
        }
        // the mapped file's own facts are still judged: a versioned file
        // replaced since it was mapped, or a user's
        let maps = maps_of(&[("/usr/lib64/libgcc_s-11-20231218.so.1", 99)]);
        assert_eq!(
            foreign_mappings(&maps, EXE, Libs::Start, &facts)[0].why,
            "its path names another file now"
        );
        let user = |p: &str| facts(p).map(|f| FileFacts { uid: 1000, ..f });
        let maps = maps_of(&[("/usr/lib64/libgcc_s-11-20231218.so.1", 12)]);
        assert_eq!(
            foreign_mappings(&maps, EXE, Libs::Start, user)[0].why,
            "not root's, or writable by another user"
        );
    }

    #[test]
    fn a_data_only_mapping_of_any_file_is_not_code() {
        let maps = genuine() + &line("r--p", 15, "/tmp/x.so") + &line("rw-p", 15, "/tmp/y");
        assert!(foreign_mappings(&maps, EXE, Libs::Start, sys).is_empty());
    }

    #[test]
    fn an_expected_name_is_judged_on_its_file() {
        // a different inode at the path: replaced since it was mapped
        let maps = genuine() + &line("r-xp", 999, "/lib64/libc.so.6");
        let f = foreign_mappings(&maps, EXE, Libs::Start, sys);
        assert_eq!(f[0].why, "its path names another file now");
        // a user's file
        let user = |p: &str| sys(p).map(|f| FileFacts { uid: 1000, ..f });
        let f = foreign_mappings(&genuine(), EXE, Libs::Start, user);
        assert!(f
            .iter()
            .all(|x| x.why == "not root's, or writable by another user"));
        assert_eq!(f.len(), 4);
        // group-writable
        let gw = |p: &str| {
            sys(p).map(|f| FileFacts {
                mode: 0o100664,
                ..f
            })
        };
        assert_eq!(foreign_mappings(&genuine(), EXE, Libs::Start, gw).len(), 4);
        // unreadable
        assert_eq!(
            foreign_mappings(&genuine(), EXE, Libs::Start, |_| None).len(),
            4
        );
        // deleted
        let maps = genuine() + &line("r-xp", 10, "/usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)");
        let f = foreign_mappings(&maps, EXE, Libs::Start, sys);
        assert_eq!(f[0].why, "a file deleted since it was mapped");
    }

    #[test]
    fn another_binary_than_the_process_s_own_is_foreign() {
        let maps = genuine() + &line("r-xp", 4243, "/usr/local/bin/northnarrow-watchdog");
        assert_eq!(foreign_mappings(&maps, EXE, Libs::Start, sys).len(), 1);
        // the binary's path with another inode
        let maps = genuine() + &line("r-xp", 1, EXE.0);
        assert_eq!(foreign_mappings(&maps, EXE, Libs::Start, sys).len(), 1);
    }

    #[test]
    fn name_service_modules_only_for_a_running_process() {
        let maps = genuine() + &line("r-xp", 14, "/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2");
        assert_eq!(foreign_mappings(&maps, EXE, Libs::Start, sys).len(), 1);
        assert!(foreign_mappings(&maps, EXE, Libs::Running, sys).is_empty());
        let maps = genuine() + &line("r-xp", 14, "/tmp/libnss_systemd.so.2");
        assert_eq!(foreign_mappings(&maps, EXE, Libs::Running, sys).len(), 1);
    }

    #[test]
    fn every_loader_variable_is_found_by_name_only() {
        for v in LOADER_ENV {
            assert_eq!(loader_vars([*v, "PATH", "LANG"]), vec![v.to_string()]);
            let block = format!("PATH=/usr/bin\0{v}=/tmp/x.so\0LANG=C\0");
            assert_eq!(
                loader_vars_in_environ(block.as_bytes()),
                vec![v.to_string()]
            );
        }
        // a value or a longer name is not the variable
        assert!(loader_vars(["LD_PRELOADX", "XLD_PRELOAD", "PATH"]).is_empty());
        assert!(loader_vars_in_environ(b"PATH=LD_PRELOAD=/tmp/x\0").is_empty());
        assert!(loader_vars_in_environ(b"").is_empty());
    }

    #[test]
    fn the_transient_unit_property_names_every_variable() {
        let p = systemd_run_unset();
        let v = p.strip_prefix("--property=UnsetEnvironment=").unwrap();
        assert_eq!(v.split(' ').collect::<Vec<_>>(), LOADER_ENV);
    }

    #[test]
    fn only_pid_1_in_the_unit_s_own_cgroup_is_its_restart() {
        let ok = Identity {
            ppid: Some(1),
            cgroup: Some("/northnarrow.slice/northnarrow-agent.service".into()),
        };
        assert!(ok.in_unit(AGENT_UNIT));
        assert!(!ok.in_unit(WATCHDOG_UNIT));
        for (ppid, cg) in [
            (Some(2), "/northnarrow.slice/northnarrow-agent.service"),
            (None, "/northnarrow.slice/northnarrow-agent.service"),
            (Some(1), "/system.slice/run-u12.service"),
            (Some(1), "/system.slice/northnarrow-agent.service"),
            (Some(1), "/northnarrow.slice/northnarrow-agent.service/sub"),
            (Some(1), "/x/northnarrow.slice/northnarrow-agent.service"),
        ] {
            let id = Identity {
                ppid,
                cgroup: Some(cg.into()),
            };
            assert!(!id.in_unit(AGENT_UNIT), "{id:?}");
        }
        assert!(!Identity {
            ppid: Some(1),
            cgroup: None
        }
        .in_unit(AGENT_UNIT));
    }

    #[test]
    fn the_parent_is_read_after_the_command_name() {
        assert_eq!(stat_ppid("42 (a) b) S 1 42 42 0"), Some(1));
        assert_eq!(stat_ppid("42 (northnarrow-age) S 977 42"), Some(977));
        assert_eq!(stat_ppid("42 (x"), None);
        let stat = "42 (a b) S 1 42 42 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 98765 1000 10";
        assert_eq!(stat_start_ticks(stat), Some(98765));
        assert_eq!(stat_start_ticks("42 (x) S 1"), None);
    }

    #[test]
    fn findings_say_what_they_found_and_never_clean_when_unread() {
        let f = Findings {
            unreadable: vec!["maps: denied".into()],
            ..Findings::default()
        };
        assert!(!f.clean());
        assert!(Findings::default().clean());
        let f = Findings {
            loader_vars: vec!["LD_PRELOAD".into()],
            foreign: vec![Foreign {
                path: "/tmp/x.so".into(),
                why: "not in a system library directory",
            }],
            unreadable: vec![],
            replaced: vec![],
        };
        let d = f.describe();
        assert!(d.contains("LD_PRELOAD") && d.contains("/tmp/x.so"), "{d}");
    }

    /// The re-check of #582 (N4): a library a package upgrade replaced
    /// since a running process mapped it ("(deleted)") is judged by its
    /// identity — the very file the judge maps (the same device and inode)
    /// is expected; another expected library's name, replaced, is apart
    /// (its identity not confirmed, never foreign on that alone); a
    /// deleted file of another name or place stays foreign, and a start
    /// ([`Libs::Start`]) judges every deleted file as before.
    #[test]
    fn a_library_replaced_since_it_was_mapped_is_judged_by_identity() {
        let maps = "\
7f00-7f10 r-xp 00000000 fd:01 4242   /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)
7f10-7f20 r-xp 00000000 fd:01 4343   /usr/lib/x86_64-linux-gnu/libgcc_s.so.1 (deleted)
7f20-7f30 r-xp 00000000 fd:01 4444   /usr/lib64/libgcc_s-11-20230605.so.1 (deleted)
7f30-7f40 r-xp 00000000 fd:01 4545   /tmp/evil.so (deleted)
7f40-7f50 r-xp 00000000 fd:01 4646   /usr/lib/x86_64-linux-gnu/libevil.so (deleted)
";
        let none = |_: &str| None;
        let own: OwnCode = vec![("fd:01".into(), 4242), ("fd:02".into(), 4343)];
        let (foreign, replaced) = judge_mappings(maps, ("/x", 1), Libs::Running, none, &own);
        // libc: the judge's own file (fd:01 4242); libgcc_s: the same inode
        // number on another device is not the judge's
        assert_eq!(
            replaced,
            [
                "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
                "/usr/lib64/libgcc_s-11-20230605.so.1"
            ]
        );
        let paths: Vec<&str> = foreign.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/tmp/evil.so (deleted)",
                "/usr/lib/x86_64-linux-gnu/libevil.so (deleted)"
            ]
        );
        assert!(foreign.iter().all(|f| f.why == "a file deleted since it was mapped"));
        // a start: every deleted file foreign, as before
        let (foreign, replaced) = judge_mappings(maps, ("/x", 1), Libs::Start, none, &own);
        assert_eq!(foreign.len(), 5);
        assert!(replaced.is_empty());
        // the judge's own code, read from its maps
        assert_eq!(
            executable_files(maps)[..2],
            [("fd:01".to_string(), 4242), ("fd:01".to_string(), 4343)]
        );
        let f = Findings {
            replaced,
            ..Findings::default()
        };
        assert!(f.clean() && f.confirmed());
        let f = Findings {
            replaced: vec!["/usr/lib/x86_64-linux-gnu/libgcc_s.so.1".into()],
            ..Findings::default()
        };
        assert!(f.clean(), "not foreign on that alone");
        assert!(!f.confirmed());
        assert!(f.describe().contains("identity not confirmed"), "{}", f.describe());
    }
}
