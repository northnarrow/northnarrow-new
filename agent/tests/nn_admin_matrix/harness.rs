//! One case of the matrix: the files it starts from, the command line, the
//! mock agent's script, and what the run gave — stdout, stderr, the exit
//! status, the files written and the requests the mock agent received.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::mock;
use crate::norm;

/// The nn-admin binary of this build: the agent package's shim, which
/// binds nn-admin to the agent's host (`AgentAdminHost`).
pub const BIN: &str = env!("CARGO_BIN_EXE_nn-admin");

/// A file the case starts with, in its own directory.
#[derive(Clone, Debug)]
pub enum Put {
    File(String, Vec<u8>, u32),
    Dir(String),
    Link(String, String),
}

impl Put {
    pub fn file(name: &str, content: impl AsRef<[u8]>, mode: u32) -> Self {
        Put::File(name.to_string(), content.as_ref().to_vec(), mode)
    }
}

/// Where a stream of nn-admin goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sink {
    /// Read by the test.
    Piped,
    /// A pipe whose read end is closed before nn-admin starts (lab PR 188).
    Closed,
}

/// What the case's output is normalised for, beyond the rules every case
/// gets (`norm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Special {
    None,
    /// `host-check` (table or JSON): the host's own checks.
    HostChecks,
    /// `status`'s table: its `host hardening` line.
    StatusHostLine,
}

#[derive(Clone, Debug)]
pub struct Case {
    /// The golden file it belongs to.
    pub area: &'static str,
    pub id: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub put: Vec<Put>,
    pub mock: Option<mock::Script>,
    pub stdout: Sink,
    pub stderr: Sink,
    pub special: Special,
    /// The case runs with nn-admin's default paths (`/etc/northnarrow`,
    /// `/run/northnarrow`, `/var/lib/northnarrow`): run only where none of
    /// them exists (`host_defaults_absent`).
    pub host_defaults: bool,
}

impl Case {
    pub fn new(area: &'static str, id: impl Into<String>, args: &[&str]) -> Self {
        Case {
            area,
            id: id.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            put: Vec::new(),
            mock: None,
            stdout: Sink::Piped,
            stderr: Sink::Piped,
            special: Special::None,
            host_defaults: false,
        }
    }

    pub fn args_owned(area: &'static str, id: impl Into<String>, args: Vec<String>) -> Self {
        let mut c = Case::new(area, id, &[]);
        c.args = args;
        c
    }

    pub fn with(mut self, put: impl IntoIterator<Item = Put>) -> Self {
        self.put.extend(put);
        self
    }

    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.env.push((k.to_string(), v.to_string()));
        self
    }

    pub fn mock(mut self, s: mock::Script) -> Self {
        self.mock = Some(s);
        self
    }

    pub fn stdout_closed(mut self) -> Self {
        self.stdout = Sink::Closed;
        self
    }

    pub fn stderr_closed(mut self) -> Self {
        self.stderr = Sink::Closed;
        self
    }

    pub fn special(mut self, s: Special) -> Self {
        self.special = s;
        self
    }

    pub fn host_defaults(mut self) -> Self {
        self.host_defaults = true;
        self
    }
}

/// A file's state in the case directory.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    File { mode: u32, bytes: Vec<u8> },
    Dir { mode: u32 },
    Link(String),
    Other,
}

/// What one run gave, rendered (normalised) for its golden file.
pub struct Outcome {
    pub text: String,
}

/// Lab PR 266b: the children this test starts, and the descriptors that
/// must be closed before a case's nn-admin runs, ordered by one lock.
///
/// A child holds a copy of every descriptor of this process from its fork
/// to its exec (`O_CLOEXEC` closes them only at the exec), and the matrix
/// starts nn-admin from several threads at once. The listening socket a
/// refused-connection case binds and closes, or the read end of the pipe a
/// closed-pipe case closes, could still be open in another thread's child,
/// between its fork and its exec, when the case's nn-admin connected or
/// wrote: the connect went into that socket's backlog and was reset when
/// the copy closed — "Connection reset by peer" instead of "Connection
/// refused", once in five `cargo xtask golden` runs (lot 265) — and a write
/// would have found a reader. Starting a child takes the lock shared, from
/// before its fork to after its exec (`Command::spawn` returns once the
/// child has exec'd); making and closing such a descriptor takes it
/// exclusive, so no child of this process is between its fork and its exec
/// while the descriptor exists. Other descriptors a child may copy (the
/// mock's listener while it serves, an accepted connection, the parent's
/// ends of the piped streams) only delay an end of file by that window;
/// they never change what nn-admin sees.
static FORKS: RwLock<()> = RwLock::new(());

/// Held while a child is started (fork to exec).
pub fn spawning() -> RwLockReadGuard<'static, ()> {
    FORKS.read().unwrap_or_else(|e| e.into_inner())
}

/// Held while a descriptor no child may copy is made and closed.
pub fn closing() -> RwLockWriteGuard<'static, ()> {
    FORKS.write().unwrap_or_else(|e| e.into_inner())
}

/// The paths nn-admin uses when no flag names another.
pub const HOST_DEFAULT_DIRS: [&str; 3] = [
    "/etc/northnarrow",
    "/run/northnarrow",
    "/var/lib/northnarrow",
];

/// None of nn-admin's default directories exists here: an installed agent's
/// files are never read, its socket never reached.
pub fn host_defaults_absent() -> bool {
    HOST_DEFAULT_DIRS
        .iter()
        .all(|d| std::fs::symlink_metadata(d).is_err())
}

fn snapshot(root: &Path) -> BTreeMap<String, Entry> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Entry>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            let ft = meta.file_type();
            let entry = if ft.is_symlink() {
                Entry::Link(
                    std::fs::read_link(&p)
                        .map(|t| t.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
            } else if ft.is_dir() {
                walk(root, &p, out);
                Entry::Dir {
                    mode: meta.mode() & 0o7777,
                }
            } else if ft.is_file() {
                Entry::File {
                    mode: meta.mode() & 0o7777,
                    bytes: std::fs::read(&p).unwrap_or_default(),
                }
            } else {
                Entry::Other
            };
            out.insert(rel, entry);
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn put_all(dir: &Path, put: &[Put]) {
    for p in put {
        match p {
            Put::File(name, bytes, mode) => {
                let path = dir.join(name);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).unwrap();
                }
                std::fs::write(&path, bytes).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(*mode)).unwrap();
            }
            Put::Dir(name) => std::fs::create_dir_all(dir.join(name)).unwrap(),
            Put::Link(name, target) => std::os::unix::fs::symlink(target, dir.join(name)).unwrap(),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A short directory per case (a Unix socket path holds 108 bytes).
static SEQ: AtomicUsize = AtomicUsize::new(0);

/// Run `case` in a directory of its own under `root`.
pub fn run(case: &Case, root: &Path) -> Outcome {
    let dir: PathBuf = root.join(format!("c{}", SEQ.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir(&dir).unwrap();
    put_all(&dir, &case.put);
    let before = snapshot(&dir);

    let started = now_secs();
    let mock = case
        .mock
        .as_ref()
        .map(|s| mock::start(&dir.join(mock::SOCKET), s.clone()));

    let mut cmd = Command::new(BIN);
    cmd.args(&case.args)
        .current_dir(&dir)
        .env_clear()
        .envs(case.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null());
    let sink = |s: Sink| -> Stdio {
        match s {
            Sink::Piped => Stdio::piped(),
            Sink::Closed => {
                let (reader, writer) = std::io::pipe().expect("pipe");
                drop(reader);
                Stdio::from(writer)
            }
        }
    };
    // A closed pipe's read end is closed before any child can copy it.
    let (stdout, stderr) = {
        let _closing = closing();
        (sink(case.stdout), sink(case.stderr))
    };
    cmd.stdout(stdout).stderr(stderr);
    let child = {
        let _spawning = spawning();
        cmd.spawn()
            .unwrap_or_else(|e| panic!("{}: spawning nn-admin: {e}", case.id))
    };
    let out = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("{}: waiting for nn-admin: {e}", case.id));
    let requests = mock.map(|m| m.finish());
    let ended = now_secs();
    let after = snapshot(&dir);

    let ctx = norm::Ctx::new(&dir, started, ended, case);
    let mut text = String::new();
    text.push_str(&format!("### {}\n", case.id));
    text.push_str(&format!("$ nn-admin{}\n", norm::shell_words(&case.args)));
    for (k, v) in &case.env {
        text.push_str(&format!("env {k}={v}\n"));
    }
    if case.stdout == Sink::Closed {
        text.push_str("stdout: a pipe closed before the start\n");
    }
    if case.stderr == Sink::Closed {
        text.push_str("stderr: a pipe closed before the start\n");
    }
    let exit = match out.status.code() {
        Some(c) => c.to_string(),
        None => {
            use std::os::unix::process::ExitStatusExt;
            format!("signal {}", out.status.signal().unwrap_or(0))
        }
    };
    let (stdout, stderr, exit) = ctx.special(case, &out.stdout, &out.stderr, exit);
    text.push_str(&format!("exit: {exit}\n"));
    if case.stdout == Sink::Piped {
        text.push_str("--- stdout\n");
        text.push_str(&norm::block(&ctx.text(&stdout)));
    }
    if case.stderr == Sink::Piped {
        text.push_str("--- stderr\n");
        text.push_str(&norm::block(&ctx.text(&stderr)));
    }
    let changes = file_changes(&ctx, &before, &after);
    if !changes.is_empty() {
        text.push_str("--- files\n");
        text.push_str(&changes);
    }
    if let Some(reqs) = requests {
        text.push_str("--- agent\n");
        if reqs.is_empty() {
            text.push_str("(no connection)\n");
        }
        for r in reqs {
            text.push_str(&ctx.text(r.as_bytes()));
            text.push('\n');
        }
    }
    text.push('\n');
    let _ = std::fs::remove_dir_all(&dir);
    Outcome { text }
}

fn file_changes(
    ctx: &norm::Ctx,
    before: &BTreeMap<String, Entry>,
    after: &BTreeMap<String, Entry>,
) -> String {
    let mut s = String::new();
    let skip = |name: &str| name == mock::SOCKET;
    for (name, e) in after {
        if skip(name) {
            continue;
        }
        let tag = match before.get(name) {
            None => "+",
            Some(b) if b == e => continue,
            Some(_) => "~",
        };
        match e {
            Entry::File { mode, bytes } => {
                s.push_str(&format!("{tag} {name} (file {mode:04o})\n"));
                s.push_str(&norm::block(&ctx.file_text(name, bytes)));
            }
            Entry::Dir { mode } => s.push_str(&format!("{tag} {name}/ (dir {mode:04o})\n")),
            Entry::Link(t) => s.push_str(&format!("{tag} {name} -> {}\n", ctx.text(t.as_bytes()))),
            Entry::Other => s.push_str(&format!("{tag} {name} (not a file)\n")),
        }
    }
    for name in before.keys() {
        if !after.contains_key(name) && !skip(name) {
            s.push_str(&format!("- {name}\n"));
        }
    }
    s
}
