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

/// The executable file mappings of a `/proc/<pid>/maps` text that are
/// neither the binary (`exe`: its path as `/proc/<pid>/exe` names it and
/// its inode) nor an expected library: under [`LIB_DIRS`], its name in
/// [`EXPECTED_LIBS`] (or a name-service module, [`Libs::Running`]), the file
/// at that path ([`FileFacts`] by `facts`) the one mapped (its inode), root's
/// and writable by nobody else — and executable anonymous memory
/// ([`ANONYMOUS_CODE`], lot 374). The kernel's pseudo mappings (`[vdso]`,
/// `[stack]`, `anon_inode:…`) and the ones that cannot execute are not
/// code of a file. One entry per path.
pub fn foreign_mappings(
    maps: &str,
    exe: (&str, u64),
    libs: Libs,
    facts: impl Fn(&str) -> Option<FileFacts>,
) -> Vec<Foreign> {
    let mut out: Vec<Foreign> = Vec::new();
    for line in maps.lines() {
        // `start-end perms offset dev inode   path` — the path may hold
        // spaces (and " (deleted)").
        let mut f = line.splitn(6, ' ');
        let (Some(_range), Some(perms), Some(_off), Some(_dev), Some(ino)) =
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
        if let Some(why) = library_refused(path, ino, libs, &facts) {
            out.push(Foreign {
                path: path.to_string(),
                why,
            });
        }
    }
    out
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
    let name = path.rsplit('/').next().unwrap_or(path);
    let nss = libs == Libs::Running
        && name
            .strip_prefix("libnss_")
            .and_then(|r| r.strip_suffix(".so.2"))
            .is_some_and(|s| {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            });
    if !EXPECTED_LIBS.contains(&name) && !nss {
        return Some("not a library the release links");
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
    None
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
}

impl Findings {
    /// Nothing found and everything read.
    pub fn clean(&self) -> bool {
        self.loader_vars.is_empty() && self.foreign.is_empty() && self.unreadable.is_empty()
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

fn mappings_into(found: &mut Findings, proc_dir: &str, libs: Libs) {
    let exe = crate::kernel_roots::read_link(format!("{proc_dir}/exe"));
    let exe_ino = crate::kernel_roots::metadata(format!("{proc_dir}/exe")).map(|m| m.ino());
    let maps = crate::kernel_roots::read(format!("{proc_dir}/maps"), PROC_MAX);
    match (exe, exe_ino, maps) {
        (Ok(exe), Ok(ino), Ok(maps)) => {
            let text = String::from_utf8_lossy(&maps);
            let exe = exe.to_string_lossy();
            found.foreign = foreign_mappings(&text, (&exe, ino), libs, file_facts);
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
        };
        let d = f.describe();
        assert!(d.contains("LD_PRELOAD") && d.contains("/tmp/x.so"), "{d}");
    }
}
