//! Lot 279: the exec pump's reading of an exec of a kernel-module tool, AT
//! the exec — R011's facts ([`nn_core::decision::rules::kmod_exec_facts`]):
//!
//! - whether the file the kernel executed is the system's module tool: its
//!   device and inode (`exe`, from the LSM hook) against those of the one
//!   file `/usr/bin/kmod` resolves to (`/bin/kmod` where there is no
//!   `/usr/bin/kmod`), stat'ed now — the links the distribution installs
//!   (`/usr/sbin/modprobe` → `../bin/kmod`) execute that same file; a file
//!   of its own under a tool's name (`/usr/bin/modprobe`, where the
//!   distribution installs none) is not it (the re-review of #498, DC-5);
//!   `/usr/bin/kmod` and `/bin/kmod` two different files (not one file
//!   under both names, as a merged `/usr` shows it): neither is (the
//!   re-check of #498, N-3);
//! - whether the process's environment holds `MODPROBE_OPTIONS` (which kmod
//!   puts in front of its command line, and the sensor does not see) or one
//!   of the dynamic linker's `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`
//!   (code of the caller's choosing run in the tool: the re-review, DC-2):
//!   `/proc/<pid>/environ`, tied to the exec by a pidfd and the process's
//!   start. Read: refused (R011 kills) — whatever became of the process: it
//!   is evidence of what the exec asked for, not a false positive (the
//!   coordinator, 04/11). A RUNNING process whose environment could
//!   not be read, an environment over 1 MiB, an unknown start: refused. A
//!   process that had EXITED before its environment could be read — no
//!   process with its pid (`ESRCH`), its pid another process's (its start
//!   not the exec's: reaped, the pid reused), a zombie, past its exit with
//!   its memory gone, whatever was read then (a read cut by the exit is no
//!   whole environment: DC-1) — is said so ([`Environment::Exited`]): its
//!   kill would reach no one (the coordinator's decision of 04/11; R011
//!   records it, its environment not verified). A leader that exited while
//!   another thread of its process runs on (`pthread_exit`: a zombie
//!   without memory, its pidfd not exited) is no exit: the environment is
//!   read from a running thread's entry (`/proc/<pid>/task/<tid>/environ`)
//!   and judged — not read whole: refused (the re-check of #498, DC-A; the
//!   kill reaches the process); no thread seen with its memory while the
//!   kernel counts more than one (`Threads:`; threads that each make the
//!   next and exit slip between the listing and their stat): refused, never
//!   an exit (DC-B). An empty environment read
//!   from the running process is one: libxtables runs `modprobe` with none
//!   (`posix_spawn(…, argv, NULL)`; lot 279's lab, iptables-legacy on
//!   Ubuntu 24.04).
//!
//! **Best effort.** A `modprobe` that does its work and exits before the
//! exec pump reads its environment is judged on its command line alone,
//! and a burst of execs that slows the pump makes that likelier: a `-d` or
//! a path put in `MODPROBE_OPTIONS` is then R018's after the load, a `-C`
//! naming a configuration with an `install` command nobody's. A root parent
//! that traces the tool (`PTRACE_O_TRACEEXEC`) can rewrite its argv and
//! environment after this reading — root running code of its own, the
//! residual R011 never covered. Code injected into the tool (an
//! `LD_PRELOAD` the pump read too late, `/etc/ld.so.preload`, a tracer) can
//! also outlive it in a child it forked before exiting: the pump reads the
//! exited tool (recorded, [`Environment::Exited`]), and R011's kill — the
//! tool's process alone — would not reach that child, reparented out of
//! its tree (the re-check of #498, N-1).
//!
//! On the exec pump's thread, first, before the event goes on the bus, for
//! the execs whose `comm` is a module tool's only: a dozen `stat`s, one
//! pidfd, two small `/proc` reads (and its threads' entries when its
//! leader shows no memory). No configuration, index or module file is
//! read.

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use common::wire::exe::exe_flags;
use nn_core::decision::rules::kmod_exec_facts::{self, Environment, ExecFacts, KMOD_TOOLS};
use nn_core::posture::lineage::PACKAGE_MANAGER_EXES;
use nn_model::{Event, ExeIdentity};

use crate::anti_tamper::filesystem::stat_dev_to_kernel_dev;
use crate::response::proc_ref::{pidfd_exited, pidfd_open, started_at, stat_start_ticks};

/// The system's module tool under the host's root: the file `/usr/bin/kmod`
/// resolves to, or `/bin/kmod`'s where there is no `/usr/bin/kmod`; none
/// when both are there as two different files.
const KMOD_PATHS: &[&str] = &["usr/bin/kmod", "bin/kmod"];

/// The environment variables that refuse an exec of a module tool: kmod's
/// options in front of its command line, and the dynamic linker's code.
const REFUSED_VARS: &[&str] = &[
    "MODPROBE_OPTIONS",
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
];

/// The most of an environment read (a larger one is not read: killed).
const MAX_ENVIRON: u64 = 1 << 20;

/// The exec pump's step: the facts of `event` read and kept for R011, when
/// it is an exec of a module tool.
pub fn read_and_keep(event: &Event) {
    if let Some(facts) = facts(Path::new("/"), event) {
        kmod_exec_facts::keep(event, facts);
    }
}

/// What `event` (an exec) shows of its program and environment, when its
/// `comm` is a module tool's; `root`: the host's root (`/`; a fixture tree
/// in tests) the tools' paths are under.
pub fn facts(root: &Path, event: &Event) -> Option<ExecFacts> {
    facts_in(root, Path::new("/proc"), event)
}

/// [`facts`] with the processes read from `proc` (a fixture tree in tests).
fn facts_in(root: &Path, proc: &Path, event: &Event) -> Option<ExecFacts> {
    let Event::ProcessSpawn {
        pid,
        comm,
        start_ns,
        exe,
        ..
    } = event
    else {
        return None;
    };
    if !KMOD_TOOLS.contains(&comm.as_str()) {
        return None;
    }
    // the environment first: the process may be short-lived
    let environment = environment(proc, *pid, *start_ns);
    // lot 283b: and the lineage, while it is alive
    let package_manager = package_manager(proc, *pid);
    Some(ExecFacts {
        program: program(root, exe),
        environment,
        package_manager,
    })
}

/// Lot 283b: the nearest package manager proper in `pid`'s lineage — `pid`
/// itself, then its parents (`/proc/<pid>/stat`'s ppid), at most
/// [`LINEAGE_HOPS`] up — by what the kernel executed (`/proc/<pid>/exe`,
/// one of [`PACKAGE_MANAGER_EXES`]) and run by root (`/proc/<pid>/status`'
/// real uid): the package transaction's criterion, read at the exec while
/// the forks between the tool and the package manager are alive. `None`
/// when the walk finds none, or loses the chain (an ancestor gone).
pub fn package_manager(proc: &Path, pid: u32) -> Option<String> {
    let mut p = pid;
    for _ in 0..=LINEAGE_HOPS {
        if p <= 1 {
            return None;
        }
        let dir = proc.join(p.to_string());
        if let Ok(exe) = std::fs::read_link(dir.join("exe")) {
            let exe = exe.to_string_lossy().into_owned();
            if PACKAGE_MANAGER_EXES.contains(&exe.as_str()) && real_uid(&dir) == Some(0) {
                return Some(exe);
            }
        }
        p = ppid(&dir)?;
    }
    None
}

/// The most parents [`package_manager`] walks up (the lineage's own cap).
const LINEAGE_HOPS: usize = 32;

/// The parent of the process at `dir` (`stat`'s fourth field, after the
/// command name in parentheses, which may hold anything).
fn ppid(dir: &Path) -> Option<u32> {
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// The real uid of the process at `dir` (`status`' `Uid:` line).
fn real_uid(dir: &Path) -> Option<u32> {
    let status = std::fs::read_to_string(dir.join("status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// `Ok` when the file the kernel executed is the system's module tool
/// (device and inode).
fn program(root: &Path, exe: &ExeIdentity) -> Result<(), String> {
    if !exe.has(exe_flags::KNOWN) {
        return Err(
            "the kernel did not describe the file it executed (no LSM exec hook): it was not \
             checked to be the system's module tool"
                .to_string(),
        );
    }
    let kmod: Vec<_> = KMOD_PATHS
        .iter()
        .filter_map(|p| std::fs::metadata(root.join(p)).ok())
        .map(|m| (stat_dev_to_kernel_dev(m.dev()), m.ino()))
        .collect();
    // two files, not one under two names (a merged /usr): neither is the
    // system's (the re-check of #498, N-3)
    if kmod.windows(2).any(|two| two[0] != two[1]) {
        return Err(
            "/usr/bin/kmod and /bin/kmod are two different files: neither is taken for the \
             system's module tool"
                .to_string(),
        );
    }
    if kmod.first() == Some(&(exe.dev, exe.ino)) {
        Ok(())
    } else {
        Err(format!(
            "the file it executed (device {:#x}, inode {}) is not the system's module tool \
             (the file /usr/bin/kmod resolves to, stat'ed at the exec)",
            exe.dev, exe.ino
        ))
    }
}

/// What the environment of `pid`, the process that started at `start_ns`
/// (`CLOCK_MONOTONIC`, as the sensors report it), is to R011; `proc`:
/// procfs (`/proc`; a copy of an entry in a test).
fn environment(proc: &Path, pid: u32, start_ns: u64) -> Environment {
    if start_ns == 0 {
        return Environment::Refused(
            "its start is unknown: its environment cannot be tied to the exec".to_string(),
        );
    }
    let fd = match pidfd_open(pid) {
        // SAFETY: pidfd_open returned this fd to us; we own it.
        Ok(raw) => unsafe { OwnedFd::from_raw_fd(raw) },
        // no process has its pid: it had exited, and been reaped
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
            return Environment::Exited(format!("no process had its pid any more ({e})"))
        }
        Err(e) => {
            return Environment::Refused(format!(
                "its pidfd could not be opened ({e}): its environment was not read"
            ))
        }
    };
    // The pidfd holds the process: `/proc/<pid>` describes it while it runs
    // (checked after the reads — a pid is not reused before it is reaped).
    let stat = || std::fs::read_to_string(proc.join(format!("{pid}/stat"))).ok();
    match stat().as_deref().and_then(stat_start_ticks) {
        Some(ticks) if started_at(ticks, start_ns) => {}
        // the exec's process was reaped and its pid reused
        Some(_) => {
            return Environment::Exited(
                "its pid names another process now (its start is not the exec's)".to_string(),
            )
        }
        None if pidfd_exited(&fd) => {
            return Environment::Exited("it was reaped before its /proc entry was read".to_string())
        }
        None => return Environment::Refused("its /proc entry could not be read".to_string()),
    }
    let mut env = Vec::new();
    let read = read_environ(&proc.join(format!("{pid}/environ")), &mut env);
    // after the read: a process past its exit reads an empty environment
    // (its memory gone) before its pidfd says it exited
    let memory = stat().is_some_and(|stat| has_memory(&stat));
    if !memory {
        // its leader's memory gone: the process's exit, or its leader's
        // alone while another of its threads runs on (DC-A)
        if let Some(running) = running_thread(proc, pid, &fd) {
            return running;
        }
    }
    let gone = pidfd_exited(&fd) || !memory;
    judged(read, &env, gone)
}

/// `path` (an `environ`) read into `env`: at most [`MAX_ENVIRON`] + 1
/// bytes.
fn read_environ(path: &Path, env: &mut Vec<u8>) -> std::io::Result<()> {
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_ENVIRON + 1).read_to_end(env))
        .map(drop)
}

/// The re-check of #498, DC-A: the leader of `pid`'s thread group shows no
/// memory — a leader that left by `pthread_exit` is a zombie, its
/// environment empty or unreadable, while its process runs on in another
/// thread, its pidfd not exited (R011's kill reaches that process).
/// `None` when no thread of it runs: the process's own exit (DC-1) — its
/// pidfd exited, or none of its listed threads with its memory and the
/// kernel counting one thread (`Threads:`), its leader. Else the
/// environment read from the entry of a thread with that memory
/// (`/proc/<pid>/task/<tid>/environ`: the process's one memory), judged as
/// a running process's — refused when the threads cannot be listed or
/// counted while the process has not exited, when none is seen with its
/// memory while the kernel counts more than one (threads that come and go
/// slip between the listing and their stat: the re-check of #498, DC-B),
/// or when that environment cannot be read whole (the thread, or its
/// process, gone by the end of the read).
fn running_thread(proc: &Path, pid: u32, fd: &OwnedFd) -> Option<Environment> {
    let task = proc.join(format!("{pid}/task"));
    let threads = match std::fs::read_dir(&task) {
        Ok(threads) => threads,
        // reaped since: no thread of it runs
        Err(_) if pidfd_exited(fd) => return None,
        Err(e) => {
            return Some(Environment::Refused(format!(
                "its leader showed no memory and its threads could not be listed ({e})"
            )))
        }
    };
    let runs = |tid: &std::ffi::OsStr| {
        std::fs::read_to_string(task.join(tid).join("stat")).is_ok_and(|stat| has_memory(&stat))
    };
    let Some(tid) = threads
        .filter_map(Result::ok)
        .map(|thread| thread.file_name())
        .find(|tid| runs(tid))
    else {
        // none seen running: the process's exit, or threads that each made
        // the next and exited between the listing and their stat (DC-B)
        if pidfd_exited(fd) {
            return None;
        }
        return match thread_count(proc, pid) {
            Some(n) if n <= 1 => None,
            Some(n) => Some(Environment::Refused(format!(
                "its leader had exited and its process ran on ({n} threads), none of them seen \
                 with its memory: its environment not read"
            ))),
            None => Some(Environment::Refused(
                "its leader showed no memory and its threads could not be counted".to_string(),
            )),
        };
    };
    let mut env = Vec::new();
    let read = read_environ(&task.join(&tid).join("environ"), &mut env);
    // after the read: the thread still ran, its process had not exited
    let whole = runs(&tid) && !pidfd_exited(fd);
    let tid = tid.to_string_lossy();
    Some(match judged(read, &env, false) {
        Environment::Clean if !whole => Environment::Refused(format!(
            "its leader had exited, and its thread {tid} or its process exited as the thread's \
             environment was read: not read whole"
        )),
        Environment::Refused(why) => Environment::Refused(format!(
            "{why} (read from its thread {tid}: its leader had exited, the process ran on)"
        )),
        clean => clean,
    })
}

/// The threads the kernel counts in the process `pid` — its leader among
/// them while it is a zombie (`Threads:` of `/proc/<pid>/status`).
fn thread_count(proc: &Path, pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(proc.join(format!("{pid}/status"))).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|n| n.trim().parse().ok())
}

/// What an environment read (`read`'s outcome; `env`, at most
/// [`MAX_ENVIRON`] + 1 bytes) says, its process `gone` by the end of the
/// read (exited, or its memory gone) or not. A variable of [`REFUSED_VARS`]
/// read, or more than [`MAX_ENVIRON`] bytes, is a refusal whatever became
/// of the process; anything else read from a process gone is no whole
/// environment (a read the exit cut short ends without an error).
fn judged(read: std::io::Result<()>, env: &[u8], gone: bool) -> Environment {
    if let Err(e) = read {
        return if gone {
            Environment::Exited(format!("it exited as its environment was read ({e})"))
        } else {
            Environment::Refused(format!("its environment could not be read ({e})"))
        };
    }
    if env.len() as u64 > MAX_ENVIRON {
        return Environment::Refused(format!(
            "its environment is larger than {MAX_ENVIRON} bytes: not read whole"
        ));
    }
    for kv in env.split(|b| *b == 0) {
        let Some(eq) = kv.iter().position(|b| *b == b'=') else {
            continue;
        };
        let (name, value) = (&kv[..eq], &kv[eq + 1..]);
        if let Some(var) = REFUSED_VARS.iter().find(|v| v.as_bytes() == name) {
            return Environment::Refused(format!(
                "{var}='{}' in its environment: {}",
                String::from_utf8_lossy(value),
                if *var == "MODPROBE_OPTIONS" {
                    "kmod puts it in front of the command line, which the sensor does not see"
                } else {
                    "the dynamic linker runs code of the caller's choosing in the tool"
                }
            ));
        }
    }
    if gone {
        return Environment::Exited(if env.is_empty() {
            "it had exited (its memory gone) when its environment was read".to_string()
        } else {
            "it exited while its environment was read (what was read holds no refused \
             variable, and may be cut short)"
                .to_string()
        });
    }
    Environment::Clean
}

/// `/proc/<pid>/stat` (`stat`) shows a process with its memory: running
/// (not a zombie), its virtual size (field 23) not 0 — a process past
/// `exit_mm` shows 0.
fn has_memory(stat: &str) -> bool {
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    let mut fields = rest.split_whitespace();
    let state = fields.next().unwrap_or("Z");
    let vsize = fields.nth(19).and_then(|v| v.parse::<u64>().ok());
    !matches!(state, "Z" | "X" | "x") && vsize.is_some_and(|v| v > 0)
}

#[cfg(test)]
mod tests {

    /// Lot 283b: the package manager in the lineage, read from a `/proc`
    /// — the nearest, by its executable, run by root; a chain that breaks
    /// (a parent gone) or ends at init names none.
    #[test]
    fn the_package_manager_in_the_lineage_is_read_at_the_exec() {
        let tmp = tempfile::TempDir::new().unwrap();
        let proc = tmp.path();
        let mk = |pid: u32, ppid: u32, exe: &str, uid: u32| {
            let d = proc.join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(
                d.join("stat"),
                format!("{pid} (a (b) c) S {ppid} 1 1 0 -1 4194560 0 0\n"),
            )
            .unwrap();
            std::fs::write(
                d.join("status"),
                format!("Name:\tx\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            )
            .unwrap();
            std::os::unix::fs::symlink(exe, d.join("exe")).unwrap();
        };
        // apt-get (10) → dpkg (20) → postinst (30) → update-initramfs (40)
        // → mkinitramfs (50) → fork (60) → fork (70) → hooks/kmod (80)
        mk(10, 1, "/usr/bin/apt-get", 0);
        mk(20, 10, "/usr/bin/dpkg", 0);
        mk(30, 20, "/usr/bin/dash", 0);
        mk(40, 30, "/usr/bin/dash", 0);
        mk(50, 40, "/usr/bin/dash", 0);
        mk(60, 50, "/usr/bin/dash", 0);
        mk(70, 60, "/usr/bin/dash", 0);
        mk(80, 70, "/usr/bin/dash", 0);
        assert_eq!(package_manager(proc, 80).as_deref(), Some("/usr/bin/dpkg"));
        // a user's dpkg vouches for nothing; the walk goes on to apt-get
        mk(120, 10, "/usr/bin/dpkg", 1000);
        mk(130, 120, "/usr/bin/dash", 0);
        assert_eq!(
            package_manager(proc, 130).as_deref(),
            Some("/usr/bin/apt-get")
        );
        // a chain that breaks (its parent 999 gone), or ends at init
        mk(200, 999, "/usr/bin/dash", 0);
        assert_eq!(package_manager(proc, 200), None);
        mk(300, 1, "/usr/bin/bash", 0);
        mk(310, 300, "/usr/bin/kmod", 0);
        assert_eq!(package_manager(proc, 310), None);
        // a process named like a package manager is not one
        mk(400, 1, "/tmp/dpkg", 0);
        mk(410, 400, "/usr/bin/dash", 0);
        assert_eq!(package_manager(proc, 410), None);
        // the exec pump's facts of a module tool's exec carry it
        let hook = "/usr/share/initramfs-tools/hooks/kmod";
        let mut e = nn_core::decision::rules::testutil::spawn_exe("kmod", hook, hook, 0);
        if let Event::ProcessSpawn { pid, .. } = &mut e {
            *pid = 80;
        }
        let f = facts_in(Path::new("/"), proc, &e).expect("a module tool's exec");
        assert_eq!(f.package_manager.as_deref(), Some("/usr/bin/dpkg"));
    }

    use super::*;
    use std::process::{Child, Command, Stdio};

    use crate::response::proc_ref::proc_start_ns;

    /// `sleep 30` with exactly `env` as its environment.
    fn sleeper(env: &[(&str, &str)]) -> Child {
        let mut c = Command::new("sleep");
        c.arg("30").env_clear().stdout(Stdio::null());
        for (k, v) in env {
            c.env(k, v);
        }
        c.spawn().expect("spawn sleep")
    }

    /// Wait until `child` has executed `sleep` (its environment is then
    /// the new image's), and return its start.
    fn started(child: &Child) -> u64 {
        let pid = child.id();
        for _ in 0..200 {
            let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default();
            if exe.file_name().is_some_and(|n| n == "sleep") {
                return proc_start_ns(pid).expect("its start");
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("sleep never ran");
    }

    fn stop(mut child: Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    fn refused(e: Environment) -> String {
        match e {
            Environment::Refused(why) => why,
            other => panic!("not refused: {other:?}"),
        }
    }

    fn exited(e: Environment) -> String {
        match e {
            Environment::Exited(how) => how,
            other => panic!("not exited: {other:?}"),
        }
    }

    /// A child that has exited, not yet reaped (a zombie still holds its
    /// pid and start), and its start.
    fn zombie() -> (Child, u64) {
        let mut child = sleeper(&[("PATH", "/usr/bin")]);
        let start = started(&child);
        child.kill().unwrap();
        let pid = child.id();
        for _ in 0..200 {
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if state
                .rsplit_once(')')
                .is_some_and(|(_, r)| r.trim_start().starts_with('Z'))
            {
                return (child, start);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let _ = child.wait();
        panic!("never a zombie");
    }

    /// The stat of `pid` as read now, saying it runs (a zombie's says Z),
    /// its virtual size set to `vsize` when given.
    fn stat_running(pid: u32, vsize: Option<&str>) -> String {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let (head, rest) = stat.rsplit_once(')').unwrap();
        let mut fields: Vec<&str> = rest.split_whitespace().collect();
        if let Some(v) = vsize {
            fields[20] = v;
        }
        fields[0] = "S";
        format!("{head}) {}\n", fields.join(" "))
    }

    /// `status` of a process the kernel counts `threads` threads in.
    fn status_of(threads: u32) -> String {
        format!("Name:\tsleep\nState:\tS (sleeping)\nThreads:\t{threads}\nVmPeak:\t1 kB\n")
    }

    /// A copy of the `/proc` entry of `pid` (its stat as read now, the
    /// virtual size set to `vsize` when given; its one thread, its leader,
    /// listed with that stat and counted in its status) under a directory
    /// of its own, with `environ` an empty file or (`environ_dir`) a
    /// directory — which no read takes.
    fn proc_copy(pid: u32, vsize: Option<&str>, environ_dir: bool) -> tempfile::TempDir {
        let stat = stat_running(pid, vsize);
        let fake = tempfile::tempdir().unwrap();
        let entry = fake.path().join(pid.to_string());
        std::fs::create_dir_all(entry.join(format!("task/{pid}"))).unwrap();
        std::fs::write(entry.join("stat"), &stat).unwrap();
        std::fs::write(entry.join("status"), status_of(1)).unwrap();
        std::fs::write(entry.join(format!("task/{pid}/stat")), &stat).unwrap();
        if environ_dir {
            std::fs::create_dir_all(entry.join("environ")).unwrap();
        } else {
            std::fs::write(entry.join("environ"), b"").unwrap();
        }
        fake
    }

    /// The environment is read at the exec: `MODPROBE_OPTIONS` or a dynamic
    /// linker's variable named with its value; a clean one and an empty one
    /// (libxtables' modprobe) are clean; an unknown start refused; a process
    /// reaped, a pid now another process's, a zombie: exited.
    #[test]
    fn the_environment_is_read_from_the_exec_s_process() {
        let p = Path::new("/proc");
        let clean = sleeper(&[("PATH", "/usr/bin:/bin"), ("LANG", "C")]);
        let start = started(&clean);
        assert_eq!(environment(p, clean.id(), start), Environment::Clean);
        let later = start + 3_600_000_000_000;
        // its pid another process's: the exec's had been reaped
        assert!(exited(environment(p, clean.id(), later)).contains("another process now"));
        assert!(refused(environment(p, clean.id(), 0)).contains("start is unknown"));
        let pid = clean.id();
        stop(clean);
        assert!(exited(environment(p, pid, start)).contains("no process had its pid any more"));

        let set = sleeper(&[("PATH", "/usr/bin"), ("MODPROBE_OPTIONS", "-d /tmp/x")]);
        let why = refused(environment(p, set.id(), started(&set)));
        assert!(why.contains("MODPROBE_OPTIONS='-d /tmp/x'"), "{why}");
        stop(set);
        let empty_value = sleeper(&[("MODPROBE_OPTIONS", "")]);
        let why = refused(environment(p, empty_value.id(), started(&empty_value)));
        assert!(why.contains("MODPROBE_OPTIONS=''"), "{why}");
        stop(empty_value);
        // the dynamic linker's code (DC-2)
        let ld = sleeper(&[
            ("PATH", "/usr/bin"),
            ("LD_LIBRARY_PATH", "/nonexistent-nn-k279"),
        ]);
        let why = refused(environment(p, ld.id(), started(&ld)));
        assert!(
            why.contains("LD_LIBRARY_PATH='/nonexistent-nn-k279'"),
            "{why}"
        );
        stop(ld);
        // a name that only starts like it is another variable
        let other = sleeper(&[("MODPROBE_OPTIONS_X", "-d /tmp/x"), ("XLD_PRELOAD", "x")]);
        assert_eq!(
            environment(p, other.id(), started(&other)),
            Environment::Clean
        );
        stop(other);

        // none at all, as libxtables runs modprobe: read, nothing in it
        let empty = sleeper(&[]);
        assert_eq!(
            environment(p, empty.id(), started(&empty)),
            Environment::Clean
        );
        stop(empty);

        let (mut z, start) = zombie();
        exited(environment(p, z.id(), start));
        z.wait().unwrap();

        // larger than the bound: not read whole
        let big = "x".repeat(120_000);
        let vars: Vec<(String, &str)> = (0..9)
            .map(|i| (format!("NN_K279_BIG{i}"), big.as_str()))
            .collect();
        let env: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        let large = sleeper(&env);
        let why = refused(environment(p, large.id(), started(&large)));
        assert!(why.contains("larger than 1048576 bytes"), "{why}");
        stop(large);
    }

    /// The coordinator's three cases (04/11), on a copy of a real process's
    /// `/proc` entry beside its real pidfd: a RUNNING process whose
    /// environment cannot be read is refused; one that had EXITED (its
    /// pidfd says so, or its memory is gone — the window of an exit, where
    /// the pidfd does not say it yet) is said exited, whatever its entry
    /// still shows; an empty environment read from a running one is clean.
    /// (The pid that names another process: the test above.)
    #[test]
    fn a_running_process_s_unreadable_environment_is_refused_an_exited_one_s_is_not() {
        let child = sleeper(&[("PATH", "/usr/bin")]);
        let start = started(&child);
        let pid = child.id();
        // running, its memory there
        let fake = proc_copy(pid, None, true);
        let why = refused(environment(fake.path(), pid, start));
        assert!(why.contains("its environment could not be read"), "{why}");
        let fake = proc_copy(pid, None, false);
        assert_eq!(environment(fake.path(), pid, start), Environment::Clean);
        // the window of an exit: the pidfd not yet readable, the memory gone
        let fake = proc_copy(pid, Some("0"), false);
        let how = exited(environment(fake.path(), pid, start));
        assert!(how.contains("its memory gone"), "{how}");
        // a read the exit cut short: what was read is no whole environment
        let fake = proc_copy(pid, Some("0"), false);
        std::fs::write(
            fake.path().join(format!("{pid}/environ")),
            b"PATH=/usr/bin\0FILLER=xxxx",
        )
        .unwrap();
        let how = exited(environment(fake.path(), pid, start));
        assert!(how.contains("cut short"), "{how}");
        let fake = proc_copy(pid, Some("0"), true);
        let how = exited(environment(fake.path(), pid, start));
        assert!(
            how.contains("it exited as its environment was read"),
            "{how}"
        );
        stop(child);

        // exited (a zombie: its pidfd says so) while its entry, copied, still
        // shows a running process with its memory
        let (mut z, start) = zombie();
        let fake = proc_copy(z.id(), Some("1236992"), false);
        exited(environment(fake.path(), z.id(), start));
        let fake = proc_copy(z.id(), Some("1236992"), true);
        exited(environment(fake.path(), z.id(), start));
        // its entry gone: reaped before it was read
        let empty = tempfile::tempdir().unwrap();
        let how = exited(environment(empty.path(), z.id(), start));
        assert!(
            how.contains("reaped before its /proc entry was read"),
            "{how}"
        );
        z.wait().unwrap();
        // a running process whose entry cannot be read: refused
        let child = sleeper(&[("PATH", "/usr/bin")]);
        let why = refused(environment(empty.path(), child.id(), started(&child)));
        assert!(why.contains("its /proc entry could not be read"), "{why}");
        stop(child);
    }

    /// A process past `exit_mm` (its virtual size 0) or a zombie shows no
    /// memory; a running one does (a `(comm)` with spaces and parentheses
    /// read whole).
    #[test]
    fn a_process_without_its_memory_is_seen_so() {
        let fields = |state: &str, vsize: &str| {
            let mut f = vec!["1"; 20];
            f[0] = state;
            f.push(vsize);
            f.push("9");
            format!("4242 (mod probe) (x) {}", f.join(" "))
        };
        assert!(has_memory(&fields("R", "1236992")));
        assert!(has_memory(&fields("S", "1")));
        assert!(!has_memory(&fields("R", "0")));
        assert!(!has_memory(&fields("Z", "1236992")));
        assert!(!has_memory(&fields("X", "1236992")));
        assert!(!has_memory(&fields("R", "-")));
        assert!(!has_memory("4242 no parenthesis"));
        let own = std::fs::read_to_string("/proc/self/stat").unwrap();
        assert!(has_memory(&own));
    }

    /// A pidfd that cannot be opened on a running task (here a thread of
    /// this test, not a thread-group leader: `EINVAL`) is not "no process
    /// with its pid": refused, not taken for an exit.
    #[test]
    fn a_pidfd_refused_on_a_running_task_is_not_an_exit() {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            // SAFETY: gettid has no preconditions.
            tid_tx.send(unsafe { libc::gettid() } as u32).unwrap();
            let _ = done_rx.recv();
        });
        let tid = tid_rx.recv().unwrap();
        let why = refused(environment(Path::new("/proc"), tid, 1));
        assert!(why.contains("its pidfd could not be opened"), "{why}");
        done_tx.send(()).unwrap();
        thread.join().unwrap();
    }

    /// What was read is judged whole: a refused variable or more than
    /// 1 MiB refused whatever became of the process; anything else read
    /// from a process gone is no whole environment (exited, DC-1); an
    /// unread environment refused while the process runs, exited once it is
    /// gone; an empty one clean while it runs.
    #[test]
    fn what_was_read_is_judged() {
        let denied = || Err(std::io::Error::from_raw_os_error(libc::EACCES));
        assert_eq!(judged(Ok(()), b"", false), Environment::Clean);
        assert_eq!(judged(Ok(()), b"PATH=/bin\0", false), Environment::Clean);
        assert!(exited(judged(Ok(()), b"", true)).contains("memory gone"));
        // a read the exit cut short: no whole environment
        assert!(exited(judged(Ok(()), b"PATH=/bin\0FILLER=xxxx", true)).contains("cut short"));
        for gone in [false, true] {
            for (env, named) in [
                (
                    &b"PATH=/bin\0MODPROBE_OPTIONS=-C x\0"[..],
                    "MODPROBE_OPTIONS='-C x'",
                ),
                (b"LD_PRELOAD=/tmp/x.so\0", "LD_PRELOAD='/tmp/x.so'"),
                (b"A=1\0LD_AUDIT=/tmp/a.so", "LD_AUDIT='/tmp/a.so'"),
                (b"LD_LIBRARY_PATH=\0", "LD_LIBRARY_PATH=''"),
                // after an entry without '=', a value with one
                (
                    b"JUNK\0LD_PRELOAD=/tmp/a=b.so\0",
                    "LD_PRELOAD='/tmp/a=b.so'",
                ),
            ] {
                let why = refused(judged(Ok(()), env, gone));
                assert!(why.contains(named), "{named}: {why}");
                let because = if named.starts_with("MODPROBE_OPTIONS") {
                    "kmod puts it in front of the command line"
                } else {
                    "the dynamic linker runs code of the caller's choosing"
                };
                assert!(why.contains(because), "{named}: {why}");
            }
            let big = vec![b'x'; MAX_ENVIRON as usize + 1];
            assert!(refused(judged(Ok(()), &big, gone)).contains("larger than"));
        }
        // names that only look like them, a value that names one
        for env in [
            &b"LD_PRELOADX=1\0XLD_PRELOAD=1\0LD_LIBRARY=1\0"[..],
            b"A=LD_PRELOAD=/tmp/x.so\0",
            b"LD_PRELOAD\0",
        ] {
            assert_eq!(judged(Ok(()), env, false), Environment::Clean, "{env:?}");
        }
        let big = vec![b'x'; MAX_ENVIRON as usize];
        assert_eq!(judged(Ok(()), &big, false), Environment::Clean);
        assert!(refused(judged(denied(), b"", false)).contains("could not be read"));
        assert!(exited(judged(denied(), b"", true)).contains("exited as"));
    }

    /// Another user's process, which an unprivileged reader may not read
    /// (`/proc/1/environ`): said so (the agent, root with
    /// `CAP_SYS_PTRACE`, reads every one).
    #[test]
    fn an_environment_not_readable_is_said_so() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("run as root: /proc/1/environ is readable, nothing to show");
            return;
        }
        let start = proc_start_ns(1).expect("init's start");
        let why = refused(environment(Path::new("/proc"), 1, start));
        assert!(why.contains("could not be read"), "{why}");
    }

    /// The program is the system's tool by device and inode: the file
    /// `/usr/bin/kmod` resolves to (a link to it executes that file; `/bin`
    /// a link to `/usr/bin`, a merged `/usr`), not another file — a file of
    /// its own under a tool's name included (DC-5) — and not an exec the
    /// kernel did not describe; `/bin/kmod` where there is no
    /// `/usr/bin/kmod`; none when `/usr/bin/kmod` and `/bin/kmod` are two
    /// different files (N-3), one file under both names (a hard link) is.
    #[test]
    fn the_program_is_the_system_s_tool_by_device_and_inode() {
        let root = tempfile::tempdir().unwrap();
        let p = |rel: &str| root.path().join(rel);
        std::fs::create_dir_all(p("usr/bin")).unwrap();
        std::fs::create_dir_all(p("usr/sbin")).unwrap();
        // a merged /usr
        std::os::unix::fs::symlink("usr/bin", p("bin")).unwrap();
        std::fs::write(p("usr/bin/kmod"), b"\x7fELF kmod").unwrap();
        std::os::unix::fs::symlink("../bin/kmod", p("usr/sbin/modprobe")).unwrap();
        std::fs::write(p("usr/bin/copy"), b"\x7fELF kmod").unwrap();
        // where the distribution installs nothing: a file of its own
        std::fs::write(p("usr/bin/modprobe"), b"\x7fELF kmod").unwrap();
        let id = |rel: &str, known: bool| {
            let m = std::fs::metadata(p(rel)).unwrap();
            ExeIdentity {
                path: format!("/{rel}"),
                dev: stat_dev_to_kernel_dev(m.dev()),
                ino: m.ino(),
                flags: if known { exe_flags::KNOWN } else { 0 },
                ..Default::default()
            }
        };
        for tool in ["usr/bin/kmod", "usr/sbin/modprobe", "bin/kmod"] {
            assert_eq!(program(root.path(), &id(tool, true)), Ok(()), "{tool}");
        }
        for other in ["usr/bin/copy", "usr/bin/modprobe"] {
            let why = program(root.path(), &id(other, true)).unwrap_err();
            assert!(
                why.contains("is not the system's module tool"),
                "{other}: {why}"
            );
        }
        let why = program(root.path(), &id("usr/bin/kmod", false)).unwrap_err();
        assert!(why.contains("did not describe the file"), "{why}");
        // the stat's device in the kernel's encoding, not stat()'s
        let mut raw = id("usr/bin/kmod", true);
        raw.dev = std::fs::metadata(p("usr/bin/kmod")).unwrap().dev();
        if raw.dev != stat_dev_to_kernel_dev(raw.dev) {
            assert!(program(root.path(), &raw).is_err());
        }
        // no merged /usr, /bin/kmod a file of its own beside /usr/bin/kmod:
        // neither is the system's tool (N-3)
        std::fs::remove_file(p("bin")).unwrap();
        std::fs::create_dir_all(p("bin")).unwrap();
        std::fs::write(p("bin/kmod"), b"\x7fELF another kmod").unwrap();
        for either in ["usr/bin/kmod", "usr/sbin/modprobe", "bin/kmod"] {
            let why = program(root.path(), &id(either, true)).unwrap_err();
            assert!(why.contains("two different files"), "{either}: {why}");
        }
        // one file under both names: the system's tool
        std::fs::remove_file(p("bin/kmod")).unwrap();
        std::fs::hard_link(p("usr/bin/kmod"), p("bin/kmod")).unwrap();
        for tool in ["usr/bin/kmod", "bin/kmod"] {
            assert_eq!(program(root.path(), &id(tool, true)), Ok(()), "{tool}");
        }
        // no /usr/bin/kmod: /bin/kmod's file
        std::fs::remove_file(p("bin/kmod")).unwrap();
        std::fs::write(p("bin/kmod"), b"\x7fELF another kmod").unwrap();
        let bin_kmod = id("bin/kmod", true);
        std::fs::remove_file(p("usr/bin/kmod")).unwrap();
        assert_eq!(program(root.path(), &bin_kmod), Ok(()));
        // neither: nothing is the system's tool
        std::fs::remove_file(p("bin/kmod")).unwrap();
        assert!(program(root.path(), &bin_kmod).is_err());
    }

    /// Only an exec whose `comm` is a module tool's is read; its facts are
    /// kept for the decision by (pid, exec time).
    #[test]
    fn only_a_module_tool_s_exec_is_read_and_kept() {
        let child = sleeper(&[("PATH", "/usr/bin"), ("MODPROBE_OPTIONS", "-C /tmp/m.conf")]);
        let exec = |comm: &str| Event::ProcessSpawn {
            pid: child.id(),
            ppid: 1,
            uid: 0,
            gid: 0,
            comm: comm.into(),
            filename: "/sbin/modprobe".into(),
            timestamp_ns: 279_279,
            argv: vec!["modprobe".into(), "dummy".into()],
            parent_comm: "bash".into(),
            parent_start_ns: 0,
            start_ns: started(&child),
            parent_is_kthread: false,
            exe: ExeIdentity::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        };
        assert_eq!(facts(Path::new("/"), &exec("sleep")), None);
        let e = exec("modprobe");
        read_and_keep(&e);
        let kept = kmod_exec_facts::of(&e).expect("kept");
        assert!(
            matches!(&kept.environment, Environment::Refused(w) if w.contains("MODPROBE_OPTIONS='-C /tmp/m.conf'")),
            "{kept:?}"
        );
        assert!(kept.program.is_err(), "no exe described: {kept:?}");
        stop(child);
    }

    /// The re-check of #498, DC-A and DC-B, on a copy of a running process's
    /// entry (its leader without memory, its pidfd not exited) beside its
    /// real pidfd: a thread with the process's memory is read and judged — a
    /// variable refused, a clean environment clean, one that cannot be read
    /// refused; no thread seen with memory is the process's exit (DC-1) when
    /// the kernel counts one thread, refused when it counts more (DC-B) or
    /// the count cannot be read; threads that cannot be listed: refused
    /// while the process runs; either is its exit once its pidfd says so.
    #[test]
    fn a_leader_without_memory_is_judged_by_a_running_thread() {
        let child = sleeper(&[("PATH", "/usr/bin")]);
        let start = started(&child);
        let pid = child.id();
        let tid = pid + 1;
        // the copy, beside its leader a thread `tid` — with the process's
        // memory or (`vsize`) not, its environment `environ` or unreadable
        let with_thread = |vsize: Option<&str>, environ: Option<&[u8]>| {
            let fake = proc_copy(pid, Some("0"), false);
            std::fs::write(fake.path().join(format!("{pid}/status")), status_of(2)).unwrap();
            let thread = fake.path().join(format!("{pid}/task/{tid}"));
            std::fs::create_dir_all(&thread).unwrap();
            std::fs::write(thread.join("stat"), stat_running(pid, vsize)).unwrap();
            match environ {
                Some(env) => std::fs::write(thread.join("environ"), env).unwrap(),
                None => std::fs::create_dir_all(thread.join("environ")).unwrap(),
            }
            fake
        };
        let from_thread = format!("(read from its thread {tid}: its leader had exited");

        // its leader alone, without memory: its exit (DC-1)
        let fake = proc_copy(pid, Some("0"), false);
        assert!(exited(environment(fake.path(), pid, start)).contains("its memory gone"));
        // a thread runs on: its environment judged
        let fake = with_thread(None, Some(b"PATH=/usr/bin\0MODPROBE_OPTIONS=-d /tmp/x\0"));
        let why = refused(environment(fake.path(), pid, start));
        assert!(why.contains("MODPROBE_OPTIONS='-d /tmp/x'"), "{why}");
        assert!(why.contains(&from_thread), "{why}");
        let fake = with_thread(None, Some(b"LD_PRELOAD=/tmp/x.so\0"));
        let why = refused(environment(fake.path(), pid, start));
        assert!(why.contains("LD_PRELOAD='/tmp/x.so'"), "{why}");
        let fake = with_thread(None, Some(b"PATH=/usr/bin\0"));
        assert_eq!(environment(fake.path(), pid, start), Environment::Clean);
        let fake = with_thread(None, None);
        let why = refused(environment(fake.path(), pid, start));
        assert!(why.contains("its environment could not be read"), "{why}");
        assert!(why.contains(&from_thread), "{why}");
        // its thread seen without memory while the kernel counts two: the
        // process runs on, its environment not read (DC-B)
        let fake = with_thread(Some("0"), Some(b"LD_PRELOAD=/tmp/x.so\0"));
        let why = refused(environment(fake.path(), pid, start));
        assert!(
            why.contains("ran on (2 threads), none of them seen"),
            "{why}"
        );
        // the kernel counting one, its leader: the process's exit
        std::fs::write(fake.path().join(format!("{pid}/status")), status_of(1)).unwrap();
        assert!(exited(environment(fake.path(), pid, start)).contains("its memory gone"));
        // not counted while it runs: refused
        std::fs::remove_file(fake.path().join(format!("{pid}/status"))).unwrap();
        let why = refused(environment(fake.path(), pid, start));
        assert!(why.contains("its threads could not be counted"), "{why}");
        // its threads not listed while it runs: refused
        let fake = proc_copy(pid, Some("0"), false);
        std::fs::remove_dir_all(fake.path().join(format!("{pid}/task"))).unwrap();
        let why = refused(environment(fake.path(), pid, start));
        assert!(why.contains("its threads could not be listed"), "{why}");
        stop(child);

        // not listed, or two counted and none seen with memory, once its
        // pidfd says it exited (a zombie): its exit
        let (mut z, start) = zombie();
        let fake = proc_copy(z.id(), Some("0"), false);
        std::fs::write(fake.path().join(format!("{}/status", z.id())), status_of(2)).unwrap();
        assert!(exited(environment(fake.path(), z.id(), start)).contains("its memory gone"));
        std::fs::remove_dir_all(fake.path().join(format!("{}/task", z.id()))).unwrap();
        assert!(exited(environment(fake.path(), z.id(), start)).contains("its memory gone"));
        z.wait().unwrap();
    }

    /// DC-A: a running thread's environment read while that thread exits
    /// (its stat then without memory) or its process does (its pidfd then
    /// exited) is not read whole — refused, though what was read is clean.
    /// The thread's `environ` is a FIFO: its writer changes the thread's
    /// stat or kills the process after the read has opened it, before the
    /// read can end.
    #[test]
    fn a_running_thread_s_environment_cut_by_an_exit_is_refused() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        for process_exits in [false, true] {
            let mut child = sleeper(&[("PATH", "/usr/bin")]);
            let start = started(&child);
            let pid = child.id();
            let fake = proc_copy(pid, Some("0"), false);
            let thread = fake.path().join(format!("{pid}/task/{}", pid + 1));
            std::fs::create_dir_all(&thread).unwrap();
            let stat = thread.join("stat");
            std::fs::write(&stat, stat_running(pid, None)).unwrap();
            let fifo = thread.join("environ");
            let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: a valid C path; a new FIFO in our own tempdir.
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            let without_memory = stat_running(pid, Some("0"));
            let writer = std::thread::spawn(move || {
                // open once the read has (a FIFO's writer waits for a reader)
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let mut w = loop {
                    match std::fs::OpenOptions::new()
                        .write(true)
                        .custom_flags(libc::O_NONBLOCK)
                        .open(&fifo)
                    {
                        Ok(w) => break w,
                        Err(_) if std::time::Instant::now() < deadline => {
                            std::thread::sleep(std::time::Duration::from_millis(1))
                        }
                        Err(e) => panic!("the read never opened the thread's environ: {e}"),
                    }
                };
                w.write_all(b"PATH=/usr/bin\0").unwrap();
                if process_exits {
                    // SAFETY: a signal to our own child.
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                    for _ in 0..2000 {
                        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                            .unwrap_or_default();
                        if state
                            .rsplit_once(')')
                            .is_some_and(|(_, r)| r.trim_start().starts_with('Z'))
                        {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                } else {
                    std::fs::write(&stat, without_memory).unwrap();
                }
                // dropped: the read ends
            });
            let e = environment(fake.path(), pid, start);
            let written = writer.join();
            let _ = child.kill();
            let _ = child.wait();
            written.expect("the writer");
            let why = refused(e);
            assert!(
                why.contains("not read whole"),
                "process exits {process_exits}: {why}"
            );
        }
    }

    /// The helper of [`LeaderGone`], a no-op without `NN_K279_LEADER_EXITS`:
    /// run in a process of its own (this binary again, with the environment
    /// the test chose), it forks a process whose leader exits while its
    /// threads run on — `sleep`: one thread sleeps; `relay`: threads each
    /// make the next and exit (the re-check of #498, DC-B), for 30 s at most
    /// — prints that process's pid and waits for it.
    #[test]
    #[ignore = "a helper of LeaderGone: a no-op without NN_K279_LEADER_EXITS"]
    fn a_leader_exits_while_its_thread_runs_helper() {
        use std::sync::atomic::{AtomicI64, Ordering};
        let Some(mode) = std::env::var_os("NN_K279_LEADER_EXITS") else {
            return;
        };
        static RELAY_UNTIL: AtomicI64 = AtomicI64::new(0);
        type Start = extern "C" fn(*mut libc::c_void) -> *mut libc::c_void;
        /// A detached thread running `start`.
        ///
        /// # Safety
        /// `start` must be safe to run on a thread of its own.
        unsafe fn detached(start: Start) -> bool {
            // SAFETY: a zeroed attribute initialised before use, destroyed
            // after; the caller's `start`.
            unsafe {
                let mut attr: libc::pthread_attr_t = std::mem::zeroed();
                libc::pthread_attr_init(&mut attr);
                libc::pthread_attr_setdetachstate(&mut attr, libc::PTHREAD_CREATE_DETACHED);
                let mut thread: libc::pthread_t = 0;
                let made = libc::pthread_create(&mut thread, &attr, start, std::ptr::null_mut());
                libc::pthread_attr_destroy(&mut attr);
                made == 0
            }
        }
        extern "C" fn sleeps_on(_: *mut libc::c_void) -> *mut libc::c_void {
            // SAFETY: plain libc calls; `_exit` ends the process.
            unsafe {
                libc::sleep(60);
                libc::_exit(0)
            }
        }
        extern "C" fn relays(_: *mut libc::c_void) -> *mut libc::c_void {
            // SAFETY: plain libc calls; the next thread runs this function.
            unsafe {
                if libc::time(std::ptr::null_mut()) < RELAY_UNTIL.load(Ordering::Relaxed)
                    && !detached(relays)
                {
                    libc::_exit(3);
                }
            }
            std::ptr::null_mut()
        }
        let start: Start = if mode == "relay" { relays } else { sleeps_on };
        // SAFETY: the child (a copy of this thread alone) makes one thread
        // and ends its leader by the raw syscall — no unwinding, no atexit;
        // glibc's fork leaves its allocator and threads usable in the child.
        let leader = unsafe { libc::fork() };
        if leader == 0 {
            // SAFETY: as above.
            unsafe {
                RELAY_UNTIL.store(libc::time(std::ptr::null_mut()) + 30, Ordering::Relaxed);
                if !detached(start) {
                    libc::_exit(1);
                }
                // the leader alone exits: its process runs on
                libc::syscall(libc::SYS_exit, 0);
                libc::_exit(2)
            }
        }
        assert!(leader > 0, "fork: {}", std::io::Error::last_os_error());
        println!("NN_K279_LEADER {leader}");
        let mut status = 0;
        // SAFETY: waits for our own child.
        unsafe { libc::waitpid(leader, &mut status, 0) };
    }

    /// A process whose leader exited while its threads run on (`mode`, as
    /// [`a_leader_exits_while_its_thread_runs_helper`] takes it), its
    /// environment `env`; killed, with its helper, when dropped.
    struct LeaderGone {
        helper: Child,
        out: std::io::BufReader<std::process::ChildStdout>,
        pid: Option<u32>,
    }

    impl LeaderGone {
        fn spawn(env: &[(&str, &str)], mode: &str) -> Self {
            use std::io::BufRead;
            let mut helper = Command::new(std::env::current_exe().expect("this test binary"))
                .args([
                    "--exact",
                    "sensors::kmod_exec::tests::a_leader_exits_while_its_thread_runs_helper",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env_clear()
                .envs(env.iter().copied())
                .env("NN_K279_LEADER_EXITS", mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("run the helper");
            let mut out = std::io::BufReader::new(helper.stdout.take().unwrap());
            let mut line = String::new();
            let pid = loop {
                line.clear();
                if out.read_line(&mut line).unwrap_or(0) == 0 {
                    break None;
                }
                // after libtest's "test … ... " on the same line
                if let Some((_, pid)) = line.split_once("NN_K279_LEADER ") {
                    break pid.trim().parse::<u32>().ok();
                }
            };
            LeaderGone { helper, out, pid }
        }

        /// Its leader's stat once it is a zombie, the kernel counting at
        /// least `threads` threads (its leader among them).
        fn leader_gone(&self, threads: u64) -> Option<String> {
            let pid = self.pid?;
            for _ in 0..2000 {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                let zombie = stat
                    .rsplit_once(')')
                    .is_some_and(|(_, r)| r.trim_start().starts_with('Z'));
                if zombie && thread_count(Path::new("/proc"), pid).is_some_and(|n| n >= threads) {
                    return Some(stat);
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            None
        }
    }

    impl Drop for LeaderGone {
        fn drop(&mut self) {
            if let Some(pid) = self.pid {
                // SAFETY: a signal to the helper's child, the whole process
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
            let _ = std::io::Read::read_to_end(&mut self.out, &mut Vec::new());
            let _ = self.helper.kill();
            let _ = self.helper.wait();
        }
    }

    /// The re-check of #498, DC-A, its case `rr3` on a real process: a
    /// leader that exited (`pthread_exit`; here its raw `exit`) while
    /// another thread runs on — the leader a zombie without memory, its
    /// pidfd not exited — is no exit: `MODPROBE_OPTIONS` or `LD_PRELOAD` in
    /// its environment (read from the running thread) refused — R011's kill
    /// reaches the process —, a clean environment clean.
    #[test]
    fn a_leader_that_exited_while_its_thread_runs_has_not_exited() {
        for (var, value) in [
            ("MODPROBE_OPTIONS", "-d /tmp/x"),
            ("LD_PRELOAD", "/nonexistent-nn-k279/x.so"),
            ("PATH", "/usr/bin"),
        ] {
            let gone = LeaderGone::spawn(&[(var, value)], "sleep");
            let stat = gone
                .leader_gone(2)
                .expect("a zombie leader and a running thread");
            assert!(!has_memory(&stat), "the leader without memory: {stat}");
            let pid = gone.pid.unwrap();
            let e = environment(
                Path::new("/proc"),
                pid,
                proc_start_ns(pid).expect("its start"),
            );
            drop(gone);
            if var == "PATH" {
                assert_eq!(e, Environment::Clean);
            } else {
                let why = refused(e);
                assert!(why.contains(&format!("{var}='{value}'")), "{why}");
                assert!(why.contains("its leader had exited"), "{why}");
            }
        }
    }

    /// The re-check of #498, DC-B, its case `rr4` on a real process: its
    /// leader exited, its threads pass on a relay (each makes the next and
    /// exits) — the process runs on throughout, though a listing of its
    /// threads may see none of them with its memory. Read again and again
    /// for 3 s: never an exit, never clean (`MODPROBE_OPTIONS` and
    /// `LD_PRELOAD` in its environment).
    #[test]
    fn a_relay_of_threads_after_its_leader_exited_is_never_an_exit() {
        let gone = LeaderGone::spawn(
            &[
                ("MODPROBE_OPTIONS", "-d /tmp/x"),
                ("LD_PRELOAD", "/nonexistent-nn-k279/x.so"),
            ],
            "relay",
        );
        gone.leader_gone(2).expect("a zombie leader and its relay");
        let pid = gone.pid.unwrap();
        let start = proc_start_ns(pid).expect("its start");
        let (mut exited, mut refused, mut clean, mut first) = (0, 0, 0, None);
        let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < until {
            match environment(Path::new("/proc"), pid, start) {
                Environment::Exited(how) => {
                    exited += 1;
                    first.get_or_insert(how);
                }
                Environment::Refused(_) => refused += 1,
                Environment::Clean => clean += 1,
            }
        }
        // the relay still ran at the end: every read was of a live process
        let running = gone.leader_gone(2).is_some();
        drop(gone);
        assert!(running, "the relay ended early");
        assert_eq!(
            (exited, clean),
            (0, 0),
            "{refused} refused; the first exit: {first:?}"
        );
        assert!(refused > 0);
    }
}
