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
//!   link, in the process's own view of the files (`/proc/<pid>/root`: a
//!   container's directory, not the host's of the same name), and only
//!   when that image is still the exec's own.
//! - `ENV_LOADS`: an interpreter naming a script of a root-owned system tree
//!   (a client's or an installed program's identity), or naming nothing,
//!   whose environment loads the caller's code beside it (`PYTHONPATH`,
//!   `NODE_OPTIONS`, `PERL5OPT`, `PERL5LIB`, `RUBYOPT`, `RUBYLIB`,
//!   `BASH_ENV`, `ENV` and their kin, [`LOADING_VARS`]).
//! - `STDIN_PROGRAM`: an interpreter naming no program whose standard input
//!   is a file, a pipe or a socket (`bash < file`, `curl … | sh`): it runs
//!   its input.
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
use nn_core::posture::lineage::{in_system_tree, is_interpreter, ExecIdentity, Runs};
use nn_model::Event;

/// The environment variables that load code into an interpreter beside the
/// program it names: the review's list, and their kin (python's own
/// library or user site moved, its standard input run after the script or
/// a startup file before the prompt; perl's older library variable; node's
/// and ruby's module paths; zsh's startup files moved).
const LOADING_VARS: &[&str] = &[
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONUSERBASE",
    "PYTHONINSPECT",
    "PYTHONSTARTUP",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "PERL5LIB",
    "PERLLIB",
    "RUBYOPT",
    "RUBYLIB",
    "GEM_HOME",
    "GEM_PATH",
    "BASH_ENV",
    "ENV",
    "ZDOTDIR",
];

/// The most of an environment read.
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
    if let Some(path) = link
        .as_deref()
        .filter(|_| own)
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
    let names_nothing = id.runs == Runs::Inline && is_interpreter(Path::new(&path));
    if (names_a_system_script || names_nothing) && environ_loads(&dir) {
        exe.flags |= exe_flags::ENV_LOADS;
    }
    if names_nothing && stdin_is_a_program(&dir) {
        exe.flags |= exe_flags::STDIN_PROGRAM;
    }
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

/// The process's environment sets one of [`LOADING_VARS`] to a value that
/// is not empty. An environment that cannot be read whole says nothing.
fn environ_loads(dir: &Path) -> bool {
    use std::io::Read;
    let Ok(f) = std::fs::File::open(dir.join("environ")) else {
        return false;
    };
    let mut env = Vec::new();
    if f.take(MAX_ENVIRON).read_to_end(&mut env).is_err() {
        return false;
    }
    env.split(|b| *b == 0).any(|var| {
        LOADING_VARS.iter().any(|name| {
            var.strip_prefix(name.as_bytes())
                .and_then(|r| r.strip_prefix(b"="))
                .is_some_and(|v| !v.is_empty())
        })
    })
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
    fn proc_with(root: &Path, pid: u32, image: &Path, environ: &[&str], stdin: Option<&Path>) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(d.join("fd")).unwrap();
        symlink(image, d.join("exe")).unwrap();
        symlink("/", d.join("root")).unwrap();
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
}
