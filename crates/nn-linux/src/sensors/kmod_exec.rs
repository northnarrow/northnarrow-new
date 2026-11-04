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
//! - whether the process's environment holds `MODPROBE_OPTIONS` (which kmod
//!   puts in front of its command line, and the sensor does not see) or one
//!   of the dynamic linker's `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`
//!   (code of the caller's choosing run in the tool: the re-review, DC-2):
//!   `/proc/<pid>/environ`, tied to the exec by a pidfd and the process's
//!   start. Read: refused (R011 kills) — whatever became of the process: it
//!   is what the exec asked for. A RUNNING process whose environment could
//!   not be read, an environment over 1 MiB, an unknown start: refused. A
//!   process that had EXITED before its environment could be read — no
//!   process with its pid (`ESRCH`), its pid another process's (its start
//!   not the exec's: reaped, the pid reused), a zombie, past its exit with
//!   its memory gone, whatever was read then (a read cut by the exit is no
//!   whole environment: DC-1) — is said so ([`Environment::Exited`]): its
//!   kill would reach no one (the coordinator's decision of 04/11; R011
//!   records it, its environment not verified). An empty environment read
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
//! residual R011 never covered.
//!
//! On the exec pump's thread, first, before the event goes on the bus, for
//! the execs whose `comm` is a module tool's only: a dozen `stat`s, one
//! pidfd, two small `/proc` reads. No configuration, index or module file
//! is read.

use std::io::Read;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use common::wire::exe::exe_flags;
use nn_core::decision::rules::kmod_exec_facts::{self, Environment, ExecFacts, KMOD_TOOLS};
use nn_model::{Event, ExeIdentity};

use crate::anti_tamper::filesystem::stat_dev_to_kernel_dev;
use crate::response::proc_ref::{pidfd_exited, pidfd_open, started_at, stat_start_ticks};

/// The system's module tool under the host's root: the file `/usr/bin/kmod`
/// resolves to, or `/bin/kmod`'s where there is no `/usr/bin/kmod`.
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
    let environment = environment(Path::new("/proc"), *pid, *start_ns);
    Some(ExecFacts {
        program: program(root, exe),
        environment,
    })
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
    let kmod = KMOD_PATHS
        .iter()
        .find_map(|p| std::fs::metadata(root.join(p)).ok())
        .map(|m| (stat_dev_to_kernel_dev(m.dev()), m.ino()));
    if kmod == Some((exe.dev, exe.ino)) {
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
    let read = std::fs::File::open(proc.join(format!("{pid}/environ")))
        .and_then(|f| f.take(MAX_ENVIRON + 1).read_to_end(&mut env));
    // after the read: a process past its exit reads an empty environment
    // (its memory gone) before its pidfd says it exited
    let memory = stat().is_some_and(|stat| has_memory(&stat));
    let gone = pidfd_exited(&fd) || !memory;
    judged(read.map(drop), &env, gone)
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

    /// A copy of the `/proc` entry of `pid` (its stat as read now, the
    /// virtual size set to `vsize` when given) under a directory of its
    /// own, with `environ` an empty file or (`environ_dir`) a directory —
    /// which no read takes.
    fn proc_copy(pid: u32, vsize: Option<&str>, environ_dir: bool) -> tempfile::TempDir {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let (head, rest) = stat.rsplit_once(')').unwrap();
        let mut fields: Vec<&str> = rest.split_whitespace().collect();
        if let Some(v) = vsize {
            fields[20] = v;
        }
        // a zombie's stat says Z: the copy says it runs
        fields[0] = "S";
        let fake = tempfile::tempdir().unwrap();
        let entry = fake.path().join(pid.to_string());
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(
            entry.join("stat"),
            format!("{head}) {}\n", fields.join(" ")),
        )
        .unwrap();
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
    /// `/usr/bin/kmod` resolves to (a link to it executes that file), not
    /// another file — a file of its own under a tool's name included (DC-5)
    /// — and not an exec the kernel did not describe; `/bin/kmod` where
    /// there is no `/usr/bin/kmod`.
    #[test]
    fn the_program_is_the_system_s_tool_by_device_and_inode() {
        let root = tempfile::tempdir().unwrap();
        let p = |rel: &str| root.path().join(rel);
        std::fs::create_dir_all(p("usr/bin")).unwrap();
        std::fs::create_dir_all(p("usr/sbin")).unwrap();
        std::fs::create_dir_all(p("bin")).unwrap();
        std::fs::write(p("usr/bin/kmod"), b"\x7fELF kmod").unwrap();
        std::os::unix::fs::symlink("../bin/kmod", p("usr/sbin/modprobe")).unwrap();
        std::fs::write(p("usr/bin/copy"), b"\x7fELF kmod").unwrap();
        // where the distribution installs nothing: a file of its own
        std::fs::write(p("usr/bin/modprobe"), b"\x7fELF kmod").unwrap();
        std::fs::write(p("bin/kmod"), b"\x7fELF another kmod").unwrap();
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
        assert_eq!(program(root.path(), &id("usr/bin/kmod", true)), Ok(()));
        assert_eq!(program(root.path(), &id("usr/sbin/modprobe", true)), Ok(()));
        for other in ["usr/bin/copy", "usr/bin/modprobe", "bin/kmod"] {
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
        // no /usr/bin/kmod: /bin/kmod's file
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
}
