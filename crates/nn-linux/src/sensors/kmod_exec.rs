//! Lot 279: the exec pump's reading of an exec of a kernel-module tool, AT
//! the exec — R011's facts ([`nn_core::decision::rules::kmod_exec_facts`]):
//!
//! - whether the file the kernel executed is the system's module tool: its
//!   device and inode (`exe`, from the LSM hook) against those of the
//!   tools' paths (`/usr/bin/kmod`, `/usr/sbin/modprobe`, … followed to
//!   their file), stat'ed now;
//! - whether the process's environment holds `MODPROBE_OPTIONS`, which kmod
//!   puts in front of its command line and the sensor does not see:
//!   `/proc/<pid>/environ`, tied to the exec by a pidfd and the process's
//!   start. Gone before it was read, its pid another's, empty, unreadable:
//!   said so, and R011 kills (nothing told it apart).
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
use nn_core::decision::rules::kmod_exec_facts::{self, ExecFacts, KMOD_TOOLS};
use nn_model::{Event, ExeIdentity};

use crate::anti_tamper::filesystem::stat_dev_to_kernel_dev;
use crate::response::proc_ref::{pidfd_exited, pidfd_open, proc_start_ticks, started_at};

/// The system's module tools' paths under the host's root: kmod and the
/// links the distributions install to it (or tools of those names).
const TOOL_PATHS: &[&str] = &[
    "usr/bin/kmod",
    "bin/kmod",
    "usr/sbin/kmod",
    "sbin/kmod",
    "usr/sbin/modprobe",
    "sbin/modprobe",
    "usr/bin/modprobe",
    "bin/modprobe",
    "usr/sbin/insmod",
    "sbin/insmod",
    "usr/bin/insmod",
    "bin/insmod",
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
    let environment = environment(*pid, *start_ns);
    Some(ExecFacts {
        program: program(root, exe),
        environment,
    })
}

/// `Ok` when the file the kernel executed is one of the system's module
/// tools' (device and inode).
fn program(root: &Path, exe: &ExeIdentity) -> Result<(), String> {
    if !exe.has(exe_flags::KNOWN) {
        return Err(
            "the kernel did not describe the file it executed (no LSM exec hook): it was not \
             checked to be the system's module tool"
                .to_string(),
        );
    }
    let ours = TOOL_PATHS
        .iter()
        .filter_map(|p| std::fs::metadata(root.join(p)).ok())
        .any(|m| (stat_dev_to_kernel_dev(m.dev()), m.ino()) == (exe.dev, exe.ino));
    if ours {
        Ok(())
    } else {
        Err(format!(
            "the file it executed (device {:#x}, inode {}) is not the system's module tool \
             (/usr/bin/kmod, /usr/sbin/modprobe, /usr/sbin/insmod… as stat'ed at the exec)",
            exe.dev, exe.ino
        ))
    }
}

/// `Ok` when the environment of `pid`, the process that started at
/// `start_ns` (`CLOCK_MONOTONIC`, as the sensors report it), was read and
/// holds no `MODPROBE_OPTIONS`.
fn environment(pid: u32, start_ns: u64) -> Result<(), String> {
    if start_ns == 0 {
        return Err("its start is unknown: its environment cannot be tied to the exec".to_string());
    }
    let fd = match pidfd_open(pid) {
        // SAFETY: pidfd_open returned this fd to us; we own it.
        Ok(raw) => unsafe { OwnedFd::from_raw_fd(raw) },
        Err(e) => {
            return Err(format!(
                "it had exited before its environment was read ({e})"
            ))
        }
    };
    // The pidfd holds the process: `/proc/<pid>` describes it while it runs
    // (checked after the reads — a pid is not reused before it is reaped).
    match proc_start_ticks(pid) {
        Some(ticks) if started_at(ticks, start_ns) => {}
        Some(_) => {
            return Err("its pid names another process (its start is not the exec's)".to_string())
        }
        None => return Err("its /proc entry could not be read".to_string()),
    }
    let mut env = Vec::new();
    let read = std::fs::File::open(format!("/proc/{pid}/environ"))
        .and_then(|f| f.take(MAX_ENVIRON + 1).read_to_end(&mut env));
    if pidfd_exited(&fd) {
        return Err("it exited while its environment was read".to_string());
    }
    if let Err(e) = read {
        return Err(format!("its environment could not be read ({e})"));
    }
    if env.len() as u64 > MAX_ENVIRON {
        return Err(format!(
            "its environment is larger than {MAX_ENVIRON} bytes: not read whole"
        ));
    }
    if env.is_empty() {
        return Err(
            "its environment read empty (as a process past its exit reads): nothing tells it \
             from one that set MODPROBE_OPTIONS"
                .to_string(),
        );
    }
    if let Some(value) = env
        .split(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(b"MODPROBE_OPTIONS="))
    {
        return Err(format!(
            "MODPROBE_OPTIONS='{}' in its environment: kmod puts it in front of the command line, \
             which the sensor does not see",
            String::from_utf8_lossy(value)
        ));
    }
    Ok(())
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

    /// The environment is read at the exec: `MODPROBE_OPTIONS` named with
    /// its value, a clean one passes; a start that is not the exec's, an
    /// unknown start, a process gone or an empty environment do not.
    #[test]
    fn the_environment_is_read_from_the_exec_s_process() {
        let clean = sleeper(&[("PATH", "/usr/bin:/bin"), ("LANG", "C")]);
        let start = started(&clean);
        assert_eq!(environment(clean.id(), start), Ok(()));
        let later = start + 3_600_000_000_000;
        assert!(environment(clean.id(), later)
            .unwrap_err()
            .contains("another process"));
        assert!(environment(clean.id(), 0)
            .unwrap_err()
            .contains("start is unknown"));
        let pid = clean.id();
        stop(clean);
        assert!(environment(pid, start)
            .unwrap_err()
            .contains("before its environment was read"));

        let set = sleeper(&[("PATH", "/usr/bin"), ("MODPROBE_OPTIONS", "-d /tmp/x")]);
        let why = environment(set.id(), started(&set)).unwrap_err();
        assert!(why.contains("MODPROBE_OPTIONS='-d /tmp/x'"), "{why}");
        stop(set);
        let empty_value = sleeper(&[("MODPROBE_OPTIONS", "")]);
        let why = environment(empty_value.id(), started(&empty_value)).unwrap_err();
        assert!(why.contains("MODPROBE_OPTIONS=''"), "{why}");
        stop(empty_value);
        // a name that only starts like it is another variable
        let other = sleeper(&[("MODPROBE_OPTIONS_X", "-d /tmp/x")]);
        assert_eq!(environment(other.id(), started(&other)), Ok(()));
        stop(other);

        let empty = sleeper(&[]);
        let why = environment(empty.id(), started(&empty)).unwrap_err();
        assert!(why.contains("read empty"), "{why}");
        stop(empty);
    }

    /// The program is the system's tool by device and inode: the file a
    /// tool's path leads to (through its link), not another file — and not
    /// an exec the kernel did not describe.
    #[test]
    fn the_program_is_the_system_s_tool_by_device_and_inode() {
        let root = tempfile::tempdir().unwrap();
        let p = |rel: &str| root.path().join(rel);
        std::fs::create_dir_all(p("usr/bin")).unwrap();
        std::fs::create_dir_all(p("usr/sbin")).unwrap();
        std::fs::write(p("usr/bin/kmod"), b"\x7fELF kmod").unwrap();
        std::os::unix::fs::symlink("../bin/kmod", p("usr/sbin/modprobe")).unwrap();
        std::fs::write(p("usr/bin/copy"), b"\x7fELF kmod").unwrap();
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
        let why = program(root.path(), &id("usr/bin/copy", true)).unwrap_err();
        assert!(why.contains("is not the system's module tool"), "{why}");
        let why = program(root.path(), &id("usr/bin/kmod", false)).unwrap_err();
        assert!(why.contains("did not describe the file"), "{why}");
        // the stat's device in the kernel's encoding, not stat()'s
        let mut raw = id("usr/bin/kmod", true);
        raw.dev = std::fs::metadata(p("usr/bin/kmod")).unwrap().dev();
        if raw.dev != stat_dev_to_kernel_dev(raw.dev) {
            assert!(program(root.path(), &raw).is_err());
        }
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
        assert!(kept
            .environment
            .as_ref()
            .unwrap_err()
            .contains("MODPROBE_OPTIONS='-C /tmp/m.conf'"));
        assert!(kept.program.is_err(), "no exe described: {kept:?}");
        stop(child);
    }
}
