//! Lot 310 (the independent review of #539): what the exec pump reads of
//! an exec's process while it runs, for the rules that judge what a process
//! is (R004's fileless exec, the lineage's script identity). Each fact is a
//! userland bit of `common::wire::exe::exe_flags` (16 and up) on the event's
//! identity; the decision reads no `/proc` for them.
//!
//! - Tracepoint mode (no LSM identity): the image from `/proc/<pid>/exe` —
//!   its identity (the device in the kernel's form), unlinked (`DELETED`),
//!   a memfd (`MEMFD`), all marked `PROC_EXE`. R004 decides on them as in
//!   LSM mode; a process gone before the read keeps none (its path is
//!   judged).
//! - `ROOT_DIR`: the directory the image was executed from is root's and
//!   writable by no one else — no user could have unlinked it (R004's
//!   re-exec of a parent's own image). Read through `/proc/<pid>/exe`'s
//!   link, in the process's own view of the files (`/proc/<pid>/root`),
//!   only when that image is still the exec's own and the process runs in
//!   PID 1's mount namespace (the re-check of #539, N6: a user's namespace
//!   binds a root directory over its own; a container's process gets none).
//! - `ENV_LOADS`: an interpreter naming a script of a root-owned system tree
//!   (a client's or an installed program's identity), or naming nothing,
//!   whose environment loads the caller's code beside it (`PYTHONPATH`,
//!   `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`, `BASH_ENV` and their kin,
//!   [`LOADING_VARS`]; `NODE_OPTIONS` naming a loading option; `ENV`,
//!   `PYTHONSTARTUP` only for one naming nothing), or whose environment is
//!   larger than the pump reads (fail closed).
//! - `STDIN_PROGRAM`: an interpreter naming no program whose standard input
//!   is a file, a pipe or a socket (`bash < file`, `curl … | sh`): it runs
//!   its input.
//! - `ENV_READ`, `POSIXLY_CORRECT` (lot 316, the re-check of #548): an exec
//!   of systemctl or procps' `kill` (`impair::reads_posixly_correct`), its
//!   environment read whole while the exec's process ran — its start the
//!   exec's, its memory still there after the read (a process past its
//!   exit reads an empty environment) — and whether `POSIXLY_CORRECT` is
//!   set in it: which reading of its argv sends the signal (logrotate's
//!   `systemctl kill -s HUP rsyslog.service` is a SIGHUP without it, a
//!   SIGTERM with it). Not read: neither flag, and every reading is judged.
//!
//! Residual, said: a process may rewrite its own environment before the
//! pump reads it (milliseconds), as R011's environment read says; a pid
//! reused between the exec and the read gives another process's facts in
//! tracepoint mode; code an interpreter loads from the user's home with no
//! variable (python's user site `.pth` and `usercustomize`, zsh's
//! `~/.zshenv`) is not seen.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use common::wire::exe::{exe_flags, kernel_dev};
use nn_core::impair::reads_posixly_correct;
use nn_core::posture::lineage::{in_system_tree, ExecIdentity, Runs};
use nn_core::posture::script_args::{node_options_load, reads_a_program};
use nn_model::Event;

/// The environment variables that load code into an interpreter beside any
/// program it names: the review's list, and their kin (python's own
/// library, user site or bytecode cache moved, its standard input run after
/// the script; perl's older library variable; node's and ruby's module
/// paths; bash's exported functions and trace options, zsh's startup files
/// moved). `NODE_OPTIONS` is read apart, with the node reader's table
/// (`script_args::node_options_load`).
const LOADING_VARS: &[&str] = &[
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
    "PYTHONPYCACHEPREFIX",
    "NODE_PATH",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "GEM_HOME",
    "GEM_PATH",
    "BASH_ENV",
    "SHELLOPTS",
    "ZDOTDIR",
];

/// The prefixes of variables that load code the same way (bash's exported
/// functions, `BASH_FUNC_name%%`).
const LOADING_PREFIXES: &[&str] = &["BASH_FUNC_"];

/// The variables that load code only into an interpreter naming no program
/// (interactive): python's startup file, a POSIX shell's `ENV`, node's REPL
/// module. For a script they load nothing (the re-check of #539, N5: a
/// user's `PYTHONSTARTUP` must not take the `aws` client's identity away).
const INTERACTIVE_VARS: &[&str] = &["PYTHONSTARTUP", "ENV", "NODE_REPL_EXTERNAL_MODULE"];

/// The most of an environment read: a larger one is not read on, and its
/// identity is not known (the re-check of #539, N3: a `PYTHONPATH` past the
/// first MiB loaded its `sitecustomize` unseen).
const MAX_ENVIRON: u64 = 1 << 20;

/// The exec pump's step: `event`'s process read under `/proc`.
pub fn read(event: &mut Event) {
    read_under(Path::new("/proc"), event)
}

/// [`read`] with the processes under `proc_root` (a fixture tree in tests).
pub fn read_under(proc_root: &Path, event: &mut Event) {
    let Event::ProcessSpawn {
        pid,
        filename,
        argv,
        exe,
        start_ns,
        ..
    } = event
    else {
        return;
    };
    let dir = proc_root.join(pid.to_string());
    let image = dir.join("exe");
    let Ok(meta) = std::fs::metadata(&image) else {
        return;
    };
    let now = (kernel_dev(meta.dev()), meta.ino());
    let link = std::fs::read_link(&image).ok();
    // LSM mode: the image is still the exec's own (else the process
    // executed something else since, or is another one: no `ROOT_DIR`)
    let own = !exe.has(exe_flags::KNOWN) || now == (exe.dev, exe.ino);
    if !exe.has(exe_flags::KNOWN) {
        (exe.dev, exe.ino) = now;
        exe.flags |= exe_flags::PROC_EXE;
        if meta.nlink() == 0 {
            exe.flags |= exe_flags::DELETED;
        }
        if link
            .as_ref()
            .is_some_and(|l| l.to_string_lossy().starts_with("/memfd:"))
        {
            exe.flags |= exe_flags::MEMFD;
        }
    }
    // the re-check of #539 (N6): a process in another mount namespace
    // shows the files it chose (a user's bind mount over its own
    // directory): no `ROOT_DIR` for it
    let init_mounts = same_mount_namespace(proc_root, &dir);
    if let Some(path) = link
        .as_deref()
        .filter(|_| own && init_mounts)
        .map(|l| executed_path(l, meta.nlink() == 0))
    {
        let view = dir
            .join("root")
            .join(path.strip_prefix("/").unwrap_or(&path));
        if view.parent().is_some_and(dir_is_root_only) {
            exe.flags |= exe_flags::ROOT_DIR;
        }
    }
    // the facts below only take trust away: read whatever the image is
    let path = exe.path_or(filename).to_string();
    let id = ExecIdentity::of_exec(&path, argv);
    let names_a_system_script =
        matches!(&id.runs, Runs::Script(s) if s.starts_with('/') && in_system_tree(s));
    // an interpreter, or busybox running one of its shells (N9)
    let names_nothing = id.runs == Runs::Inline && reads_a_program(Path::new(&path), argv);
    if (names_a_system_script || names_nothing) && environ_loads(&dir, names_nothing) {
        exe.flags |= exe_flags::ENV_LOADS;
    }
    if names_nothing && stdin_is_a_program(&dir) {
        exe.flags |= exe_flags::STDIN_PROGRAM;
    }
    // lot 316 (the re-check of #548): the environment getopt reads
    if reads_posixly_correct(Path::new(&path), argv) {
        if let Some(set) = posixly_correct(&dir, *start_ns) {
            exe.flags |= exe_flags::ENV_READ;
            if set {
                exe.flags |= exe_flags::POSIXLY_CORRECT;
            }
        }
    }
}

/// Lot 316 (the re-check of #548): `POSIXLY_CORRECT` is set in the
/// environment of the process `dir` (`/proc/<pid>`), the exec's process
/// that started at `start_ns` — an entry named so, as glibc's `getenv`
/// finds it. `None` when it cannot be told: its start unknown or not the
/// exec's (the pid reused), its memory gone (it exited: a process past its
/// exit reads an empty environment), the read failed, or the environment
/// is larger than [`MAX_ENVIRON`]. Checked after the read: a pid is not
/// reused before its process is reaped, so the exec's process with its
/// memory then is the one whose environment was read, whole.
fn posixly_correct(dir: &Path, start_ns: u64) -> Option<bool> {
    use crate::response::proc_ref::{started_at, stat_start_ticks};
    use std::io::Read;
    if start_ns == 0 {
        return None;
    }
    let mut env = Vec::new();
    std::fs::File::open(dir.join("environ"))
        .and_then(|f| f.take(MAX_ENVIRON + 1).read_to_end(&mut env))
        .ok()?;
    // after the read: still the exec's process, still with its memory
    let stat = crate::state_read::read_state(dir.join("stat")).ok()?;
    let ticks = stat_start_ticks(&stat)?;
    if !started_at(ticks, start_ns)
        || !super::kmod_exec::has_memory(&stat)
        || env.len() as u64 > MAX_ENVIRON
    {
        return None;
    }
    Some(
        env.split(|b| *b == 0)
            .any(|var| var.starts_with(b"POSIXLY_CORRECT=")),
    )
}

/// The path an image was executed by, from its `exe` link's text: the
/// kernel's ` (deleted)` dropped when the image is unlinked.
fn executed_path(link: &Path, unlinked: bool) -> PathBuf {
    let text = link.to_string_lossy();
    match text.strip_suffix(" (deleted)") {
        Some(p) if unlinked => PathBuf::from(p),
        _ => link.to_path_buf(),
    }
}

/// `dir` is root's and writable by no one else.
fn dir_is_root_only(dir: &Path) -> bool {
    std::fs::metadata(dir).is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0)
}

/// The process's environment loads code into it: one of [`LOADING_VARS`]
/// (or [`LOADING_PREFIXES`]) set to a value that is not empty, one of
/// [`INTERACTIVE_VARS`] for an interpreter naming no program
/// (`interactive`), or `NODE_OPTIONS` naming a loading option. An
/// environment larger than [`MAX_ENVIRON`] loads, as far as the pump can
/// tell (fail closed); one that cannot be read says nothing (the process
/// is gone: its identity is the argv's).
fn environ_loads(dir: &Path, interactive: bool) -> bool {
    use std::io::Read;
    let Ok(f) = std::fs::File::open(dir.join("environ")) else {
        return false;
    };
    let mut env = Vec::new();
    if f.take(MAX_ENVIRON + 1).read_to_end(&mut env).is_err() {
        return false;
    }
    if env.len() as u64 > MAX_ENVIRON {
        return true;
    }
    let value = |var: &[u8], name: &str| -> Option<Vec<u8>> {
        var.strip_prefix(name.as_bytes())
            .and_then(|r| r.strip_prefix(b"="))
            .filter(|v| !v.is_empty())
            .map(<[u8]>::to_vec)
    };
    env.split(|b| *b == 0).any(|var| {
        LOADING_VARS.iter().any(|name| value(var, name).is_some())
            || LOADING_PREFIXES
                .iter()
                .any(|p| var.starts_with(p.as_bytes()))
            || (interactive
                && INTERACTIVE_VARS
                    .iter()
                    .any(|name| value(var, name).is_some()))
            || value(var, "NODE_OPTIONS")
                .is_some_and(|v| node_options_load(&String::from_utf8_lossy(&v)))
    })
}

/// The process runs in PID 1's mount namespace (`/proc/<pid>/ns/mnt` the
/// same as `/proc/1/ns/mnt`). Not readable: not known, so no.
fn same_mount_namespace(proc_root: &Path, dir: &Path) -> bool {
    let ns = |d: &Path| std::fs::read_link(d.join("ns/mnt")).ok();
    match (ns(dir), ns(&proc_root.join("1"))) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// The process's standard input is a file, a pipe or a socket: not a
/// terminal, not `/dev/null`, not closed.
fn stdin_is_a_program(dir: &Path) -> bool {
    let Ok(target) = std::fs::read_link(dir.join("fd/0")) else {
        return false;
    };
    let t = target.to_string_lossy();
    if t.starts_with("pipe:[") || t.starts_with("socket:[") {
        return true;
    }
    t.starts_with('/') && !t.starts_with("/dev/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn spawn(pid: u32, exe: nn_model::ExeIdentity, filename: &str, argv: &[&str]) -> Event {
        Event::ProcessSpawn {
            pid,
            ppid: 1,
            uid: 1000,
            gid: 1000,
            comm: "x".into(),
            filename: filename.into(),
            timestamp_ns: 1,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 1,
            parent_is_kthread: false,
            exe,
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        }
    }

    fn flags(e: &Event) -> (u32, u64, u64) {
        let Event::ProcessSpawn { exe, .. } = e else {
            unreachable!()
        };
        (exe.flags, exe.dev, exe.ino)
    }

    /// A fixture process: its `exe` a link to `image`, its environment and
    /// standard input as given.
    const INIT_NS: &str = "mnt:[4026531841]";

    /// `pid`'s mount namespace in the fixture (its `ns/mnt` link's text).
    fn mount_ns(root: &Path, pid: u32, ns: &str) {
        let d = root.join(pid.to_string()).join("ns");
        std::fs::create_dir_all(&d).unwrap();
        let _ = std::fs::remove_file(d.join("mnt"));
        symlink(ns, d.join("mnt")).unwrap();
    }

    fn proc_with(root: &Path, pid: u32, image: &Path, environ: &[&str], stdin: Option<&Path>) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(d.join("fd")).unwrap();
        symlink(image, d.join("exe")).unwrap();
        symlink("/", d.join("root")).unwrap();
        // PID 1's mount namespace, and the process in it
        mount_ns(root, 1, INIT_NS);
        mount_ns(root, pid, INIT_NS);
        let mut env = environ.join("\0").into_bytes();
        env.push(0);
        std::fs::write(d.join("environ"), env).unwrap();
        if let Some(s) = stdin {
            symlink(s, d.join("fd/0")).unwrap();
        }
    }

    /// Tracepoint mode: the image's identity from `/proc/<pid>/exe`, in the
    /// kernel's device form; the directory of a temporary file is not
    /// root's only, `/usr/bin`'s is.
    #[test]
    fn tracepoint_mode_reads_the_image_and_its_directory() {
        let proc = tempfile::tempdir().unwrap();
        let files = tempfile::tempdir().unwrap();
        let payload = files.path().join("payload");
        std::fs::write(&payload, b"x").unwrap();
        proc_with(proc.path(), 10, &payload, &[], None);
        let mut e = spawn(10, Default::default(), "/proc/self/fd/3", &["x"]);
        read_under(proc.path(), &mut e);
        let m = std::fs::metadata(&payload).unwrap();
        let (f, dev, ino) = flags(&e);
        assert_eq!((dev, ino), (kernel_dev(m.dev()), m.ino()));
        assert!(f & exe_flags::PROC_EXE != 0 && f & exe_flags::KNOWN == 0);
        assert!(f & (exe_flags::DELETED | exe_flags::MEMFD | exe_flags::ROOT_DIR) == 0);
        // a system binary: its directory is root's only
        proc_with(proc.path(), 11, Path::new("/usr/bin/env"), &[], None);
        let mut e = spawn(11, Default::default(), "/usr/bin/env", &["env"]);
        read_under(proc.path(), &mut e);
        assert!(flags(&e).0 & exe_flags::ROOT_DIR != 0);
        // gone: nothing read
        let mut e = spawn(12, Default::default(), "/proc/self/fd/3", &["x"]);
        read_under(proc.path(), &mut e);
        assert_eq!(flags(&e).0, 0);
    }

    /// LSM mode: a `ROOT_DIR` only when `/proc/<pid>/exe` is still the
    /// exec's image (its identity); the identity itself is the kernel's.
    #[test]
    fn lsm_mode_marks_the_directory_of_the_exec_s_own_image() {
        let proc = tempfile::tempdir().unwrap();
        proc_with(proc.path(), 20, Path::new("/usr/bin/env"), &[], None);
        let m = std::fs::metadata("/usr/bin/env").unwrap();
        let known = |dev, ino| nn_model::ExeIdentity {
            path: "/usr/bin/env".into(),
            dev,
            ino,
            flags: exe_flags::KNOWN,
            ..Default::default()
        };
        let mut e = spawn(
            20,
            known(kernel_dev(m.dev()), m.ino()),
            "/usr/bin/env",
            &["env"],
        );
        read_under(proc.path(), &mut e);
        assert!(flags(&e).0 & exe_flags::ROOT_DIR != 0);
        assert!(flags(&e).0 & exe_flags::PROC_EXE == 0);
        // another image now: no `ROOT_DIR`
        let mut e = spawn(20, known(1, 2), "/usr/bin/env", &["env"]);
        read_under(proc.path(), &mut e);
        assert_eq!(flags(&e).0, exe_flags::KNOWN);
        // …but what only takes trust away is still read
        proc_with(
            proc.path(),
            21,
            Path::new("/usr/bin/env"),
            &["PYTHONPATH=/tmp/p"],
            None,
        );
        let py = |dev, ino| nn_model::ExeIdentity {
            path: "/usr/bin/python3".into(),
            ..known(dev, ino)
        };
        let mut e = spawn(
            21,
            py(1, 2),
            "/usr/bin/python3",
            &["python3", "/usr/bin/aws"],
        );
        read_under(proc.path(), &mut e);
        assert_eq!(flags(&e).0, exe_flags::KNOWN | exe_flags::ENV_LOADS);
    }

    /// Tracepoint mode on a real process: an image unlinked after its exec
    /// is `DELETED` (its link count 0), with its identity.
    #[test]
    fn an_unlinked_image_is_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        // lot 344: the copy keeps the name `sleep` (uutils' multicall
        // coreutils — Ubuntu 26.04, the hosted runners — run no utility
        // named `payload`: the child exited at once)
        std::fs::create_dir(tmp.path().join("payload")).unwrap();
        let copy = tmp.path().join("payload").join("sleep");
        std::fs::copy("/bin/sleep", &copy).unwrap();
        // another test's fork may hold the copy's write descriptor until its
        // exec (the parallel harness): `ETXTBSY` for a moment
        let mut child = (0..200)
            .find_map(
                |_| match std::process::Command::new(&copy).arg("5").spawn() {
                    Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        None
                    }
                    other => Some(other.unwrap()),
                },
            )
            .expect("the copy runs");
        for _ in 0..500 {
            if std::fs::read_link(format!("/proc/{}/exe", child.id())).is_ok_and(|l| l == copy) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let id = std::fs::metadata(&copy).unwrap();
        let id = (kernel_dev(id.dev()), id.ino());
        std::fs::remove_file(&copy).unwrap();
        let mut e = spawn(child.id(), Default::default(), "/proc/self/fd/3", &["x"]);
        read_under(Path::new("/proc"), &mut e);
        let _ = child.kill();
        let _ = child.wait();
        let (f, dev, ino) = flags(&e);
        assert!(
            f & exe_flags::DELETED != 0 && f & exe_flags::PROC_EXE != 0,
            "{f:#x}"
        );
        assert_eq!((dev, ino), id);
    }

    /// `ROOT_DIR` is read in the process's own view of the files: a
    /// container's `/usr/bin` is its root's (`/proc/<pid>/root`), not the
    /// host's directory of the same name.
    #[test]
    fn the_directory_is_read_in_the_process_s_root() {
        let proc = tempfile::tempdir().unwrap();
        let container = tempfile::tempdir().unwrap();
        // the container's /usr/bin: writable by anyone (the host's is
        // root's only, [`tracepoint_mode_reads_the_image_and_its_directory`])
        let bin = container.path().join("usr/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o777))
            .unwrap();
        let d = proc.path().join("50");
        std::fs::create_dir_all(d.join("fd")).unwrap();
        // the image the agent's stat reads (any file); the link's text the
        // container's path
        symlink("/usr/bin/env", d.join("exe")).unwrap();
        symlink(container.path(), d.join("root")).unwrap();
        // (PID 1's mount namespace: what is read is the root's view)
        mount_ns(proc.path(), 1, INIT_NS);
        mount_ns(proc.path(), 50, INIT_NS);
        std::fs::write(d.join("environ"), b"\0").unwrap();
        let mut e = spawn(50, Default::default(), "/usr/bin/env", &["env"]);
        read_under(proc.path(), &mut e);
        assert_eq!(
            flags(&e).0 & exe_flags::ROOT_DIR,
            0,
            "the container's directory"
        );
    }

    /// An interpreter naming a system script, or nothing, with a loading
    /// variable set: `ENV_LOADS`; one naming a script of its own, or a
    /// variable left empty, nothing. A shell naming nothing whose standard
    /// input is a file or a pipe: `STDIN_PROGRAM`; a terminal or
    /// `/dev/null`: nothing.
    #[test]
    fn an_interpreter_s_environment_and_standard_input() {
        let proc = tempfile::tempdir().unwrap();
        let py = Path::new("/usr/bin/python3");
        // the fixture's image is any file there is (tracepoint mode: the
        // reading is the caller's path's, `filename`)
        let read =
            |pid: u32, filename: &Path, env: &[&str], stdin: Option<&Path>, argv: &[&str]| {
                proc_with(proc.path(), pid, Path::new("/usr/bin/env"), env, stdin);
                let mut e = spawn(pid, Default::default(), &filename.to_string_lossy(), argv);
                read_under(proc.path(), &mut e);
                flags(&e).0
            };
        let has = |f: u32, bit: u32| f & bit != 0;
        assert!(has(
            read(
                30,
                py,
                &["PYTHONPATH=/tmp/p"],
                None,
                &["python3", "/usr/bin/aws"]
            ),
            exe_flags::ENV_LOADS
        ));
        assert!(!has(
            read(31, py, &["PYTHONPATH="], None, &["python3", "/usr/bin/aws"]),
            exe_flags::ENV_LOADS
        ));
        assert!(!has(
            read(
                32,
                py,
                &["PYTHONPATH=/tmp/p"],
                None,
                &["python3", "/tmp/x.py"]
            ),
            exe_flags::ENV_LOADS
        ));
        assert!(has(
            read(
                33,
                Path::new("/usr/bin/node"),
                &["NODE_OPTIONS=--require /tmp/x.js"],
                None,
                &["node", "/usr/bin/aws"]
            ),
            exe_flags::ENV_LOADS
        ));
        let file = tempfile::NamedTempFile::new().unwrap();
        let bash = Path::new("/usr/bin/bash");
        assert!(has(
            read(40, bash, &[], Some(file.path()), &["bash"]),
            exe_flags::STDIN_PROGRAM
        ));
        assert!(has(
            read(41, bash, &[], Some(Path::new("pipe:[1234]")), &["bash"]),
            exe_flags::STDIN_PROGRAM
        ));
        assert!(!has(
            read(42, bash, &[], Some(Path::new("/dev/pts/0")), &["bash"]),
            exe_flags::STDIN_PROGRAM
        ));
        assert!(!has(
            read(43, bash, &[], Some(Path::new("/dev/null")), &["bash"]),
            exe_flags::STDIN_PROGRAM
        ));
        // a script named: its standard input is its own business
        assert!(!has(
            read(44, bash, &[], Some(file.path()), &["bash", "/tmp/s"]),
            exe_flags::STDIN_PROGRAM
        ));
        // the lineage reads the facts: Unknown and Code
        let mut e = spawn(
            30,
            Default::default(),
            "/usr/bin/python3",
            &["python3", "/usr/bin/aws"],
        );
        read_under(proc.path(), &mut e);
        let id = ExecIdentity::of_spawn(&e).unwrap();
        assert_eq!(id.runs, Runs::Unknown(Some("/usr/bin/aws".into())));
        assert!(!id.is_client(&["aws"]));
        let mut e = spawn(40, Default::default(), "/usr/bin/bash", &["bash"]);
        read_under(proc.path(), &mut e);
        assert_eq!(ExecIdentity::of_spawn(&e).unwrap().runs, Runs::Code);
    }

    /// The re-check of #539 (N6): a process in a mount namespace other than
    /// PID 1's gets no `ROOT_DIR` — a user's namespace binds a root-owned
    /// directory over the one its unlinked binary came from.
    #[test]
    fn another_mount_namespace_has_no_root_dir() {
        let proc = tempfile::tempdir().unwrap();
        proc_with(proc.path(), 60, Path::new("/usr/bin/env"), &[], None);
        let mut e = spawn(60, Default::default(), "/usr/bin/env", &["env"]);
        read_under(proc.path(), &mut e);
        assert!(flags(&e).0 & exe_flags::ROOT_DIR != 0, "PID 1's namespace");
        mount_ns(proc.path(), 60, "mnt:[4026532999]");
        let mut e = spawn(60, Default::default(), "/usr/bin/env", &["env"]);
        read_under(proc.path(), &mut e);
        assert_eq!(
            flags(&e).0 & exe_flags::ROOT_DIR,
            0,
            "a namespace of its own"
        );
        // PID 1's namespace not readable: not known, so none
        std::fs::remove_file(proc.path().join("1/ns/mnt")).unwrap();
        mount_ns(proc.path(), 60, INIT_NS);
        let mut e = spawn(60, Default::default(), "/usr/bin/env", &["env"]);
        read_under(proc.path(), &mut e);
        assert_eq!(flags(&e).0 & exe_flags::ROOT_DIR, 0, "not known");
    }

    /// The re-check of #539 (N3, N4, N5, N9): an environment past the read
    /// limit loads (fail closed); python's bytecode cache moved and bash's
    /// exported functions load; `PYTHONSTARTUP` and `ENV` load only into an
    /// interpreter naming nothing — a legitimate `aws` with a user's
    /// startup file keeps its identity; `NODE_OPTIONS` loads only with a
    /// loading option (`--max-old-space-size` does not); busybox's shell
    /// reads its standard input as any shell.
    #[test]
    fn the_environment_s_false_positives_and_its_size() {
        let proc = tempfile::tempdir().unwrap();
        let read = |pid: u32, exe: &str, env: &[&str], stdin: Option<&Path>, argv: &[&str]| {
            proc_with(proc.path(), pid, Path::new("/usr/bin/env"), env, stdin);
            let mut e = spawn(pid, Default::default(), exe, argv);
            read_under(proc.path(), &mut e);
            flags(&e).0
        };
        let loads = |f: u32| f & exe_flags::ENV_LOADS != 0;
        let py = "/usr/bin/python3";
        let aws = &["python3", "/usr/bin/aws"][..];
        // the legitimate client: no mark
        assert!(!loads(read(
            70,
            py,
            &["PYTHONSTARTUP=/home/u/.pythonrc"],
            None,
            aws
        )));
        assert!(!loads(read(
            71,
            "/usr/bin/node",
            &["NODE_OPTIONS=--max-old-space-size=4096"],
            None,
            &["node", "/usr/bin/x"]
        )));
        assert!(!loads(read(
            72,
            "/usr/bin/dash",
            &["ENV=/home/u/.shrc"],
            None,
            &["sh", "/usr/bin/x"]
        )));
        // interactive: the startup files load
        assert!(loads(read(
            73,
            py,
            &["PYTHONSTARTUP=/tmp/s.py"],
            None,
            &["python3"]
        )));
        assert!(loads(read(
            74,
            "/usr/bin/dash",
            &["ENV=/tmp/s"],
            None,
            &["sh"]
        )));
        // the loading options of NODE_OPTIONS, every spelling
        for (k, v) in [
            "NODE_OPTIONS=--require /tmp/x.js",
            "NODE_OPTIONS=--max-old-space-size=64 --import=data:text/javascript,x",
            "NODE_OPTIONS=-r/tmp/x.js",
            "NODE_OPTIONS=--test-reporter=/tmp/r.mjs",
            "NODE_OPTIONS=\"--experimental-loader\" /tmp/l.mjs",
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                loads(read(
                    90 + k as u32,
                    "/usr/bin/node",
                    &[v],
                    None,
                    &["node", "/usr/bin/x"]
                )),
                "{v}"
            );
        }
        // python's bytecode cache, bash's exported functions
        assert!(loads(read(
            76,
            py,
            &["PYTHONPYCACHEPREFIX=/tmp/c"],
            None,
            aws
        )));
        assert!(loads(read(
            77,
            "/usr/bin/bash",
            &["BASH_FUNC_aws%%=() { id; }"],
            None,
            &["bash", "/usr/bin/x"]
        )));
        // past the read limit: loads, whatever it holds
        let big = format!("X={}", "a".repeat(MAX_ENVIRON as usize));
        assert!(loads(read(78, py, &[&big], None, aws)));
        let fits = format!("X={}", "a".repeat(1000));
        assert!(!loads(read(79, py, &[&fits], None, aws)));
        // busybox's shell reading a pipe, and its environment
        let bb = "/bin/busybox";
        let f = read(80, bb, &[], Some(Path::new("pipe:[9]")), &["sh"]);
        assert!(f & exe_flags::STDIN_PROGRAM != 0);
        assert!(loads(read(81, bb, &["ENV=/tmp/s"], None, &["sh"])));
        // another applet reads no program
        let f = read(82, bb, &[], Some(Path::new("pipe:[9]")), &["wget", "x"]);
        assert_eq!(f & (exe_flags::STDIN_PROGRAM | exe_flags::ENV_LOADS), 0);
    }

    /// Lot 316 (the re-check of #548): systemctl's and procps' `kill`'s
    /// environment, read while the exec's process runs: `ENV_READ`, and
    /// `POSIXLY_CORRECT` when an entry is named so (any value, as `getenv`
    /// finds it). Neither flag when it cannot be told — the process a
    /// zombie or past its memory, another process on the pid (its start),
    /// the start unknown, no environment to read, one past the read limit
    /// — nor for a program whose reading it does not change.
    #[test]
    fn a_system_tool_s_getopt_environment() {
        let proc = tempfile::tempdir().unwrap();
        // SAFETY: sysconf reads a constant of the C library.
        let tick = 1_000_000_000 / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let ticks = 4_000u64;
        let read =
            |pid: u32, filename: &str, argv: &[&str], env: &[&str], stat: (&str, u64, u64)| {
                proc_with(proc.path(), pid, Path::new("/usr/bin/env"), env, None);
                let (state, start, vsize) = stat;
                std::fs::write(
                    proc.path().join(pid.to_string()).join("stat"),
                    format!(
                        "{pid} (x) {state} 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} \
                     {vsize} 0\n"
                    ),
                )
                .unwrap();
                let mut e = spawn(pid, Default::default(), filename, argv);
                if let Event::ProcessSpawn { start_ns, .. } = &mut e {
                    *start_ns = ticks * tick;
                }
                read_under(proc.path(), &mut e);
                flags(&e).0 & (exe_flags::ENV_READ | exe_flags::POSIXLY_CORRECT)
            };
        let sc = "/usr/bin/systemctl";
        let rotate = ["systemctl", "kill", "-s", "HUP", "rsyslog.service"];
        let ok = ("S", ticks, 4096);
        let (read_only, posix) = (
            exe_flags::ENV_READ,
            exe_flags::ENV_READ | exe_flags::POSIXLY_CORRECT,
        );
        assert_eq!(
            read(90, sc, &rotate, &["PATH=/usr/bin", "LANG=C"], ok),
            read_only
        );
        assert_eq!(read(91, sc, &rotate, &["POSIXLY_CORRECT=1"], ok), posix);
        assert_eq!(
            read(92, sc, &rotate, &["A=b", "POSIXLY_CORRECT="], ok),
            posix
        );
        // no `=`, or another name: getenv finds no POSIXLY_CORRECT
        assert_eq!(read(93, sc, &rotate, &["POSIXLY_CORRECT"], ok), read_only);
        assert_eq!(
            read(94, sc, &rotate, &["XPOSIXLY_CORRECT=1"], ok),
            read_only
        );
        // procps' kill by its path and by its argv[0]
        let kill = ["kill", "9", "-s", "HUP"];
        assert_eq!(
            read(95, "/usr/bin/kill", &kill, &["POSIXLY_CORRECT=y"], ok),
            posix
        );
        assert_eq!(read(96, "/bin/kill", &kill, &[], ok), read_only);
        // not told: a zombie, no memory, another start, no start, no
        // environment, one too large
        let p = &["POSIXLY_CORRECT=1"][..];
        assert_eq!(read(97, sc, &rotate, p, ("Z", ticks, 4096)), 0);
        assert_eq!(read(98, sc, &rotate, p, ("S", ticks, 0)), 0);
        assert_eq!(read(99, sc, &rotate, p, ("S", ticks + 360_000, 4096)), 0);
        // (a process of the boot's first tick: its start would pass for 0)
        read(100, sc, &rotate, p, ("S", 1, 4096));
        let mut e = spawn(100, Default::default(), sc, &rotate);
        if let Event::ProcessSpawn { start_ns, .. } = &mut e {
            *start_ns = 0;
        }
        read_under(proc.path(), &mut e);
        assert_eq!(flags(&e).0 & exe_flags::ENV_READ, 0);
        read(101, sc, &rotate, p, ok);
        std::fs::remove_file(proc.path().join("101/environ")).unwrap();
        let mut e = spawn(101, Default::default(), sc, &rotate);
        if let Event::ProcessSpawn { start_ns, .. } = &mut e {
            *start_ns = ticks * tick;
        }
        read_under(proc.path(), &mut e);
        assert_eq!(flags(&e).0 & exe_flags::ENV_READ, 0);
        let big = format!("X={}", "a".repeat(MAX_ENVIRON as usize));
        assert_eq!(read(102, sc, &rotate, &[&big], ok), 0);
        // a program whose reading it does not change
        assert_eq!(read(103, "/usr/bin/pkill", &["pkill", "x"], p, ok), 0);
        assert_eq!(read(104, "/usr/bin/bash", &["bash", "-c", "x"], p, ok), 0);
    }
}
