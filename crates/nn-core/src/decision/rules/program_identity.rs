//! Lot 313 (external bug hunt, edition 1.4: BUG-85, N1, BUG-112, BUG-119):
//! the programs the rules judge — shells, interpreters, busybox — told by
//! what the kernel executed, never by a name alone; and the one place in
//! the rules that matches such a program by its name
//! (`xtask/tests/program_names.rs`).
//!
//! R020 read a shell from the basename of the executed file: `cp /bin/bash
//! ~/x` with its standard streams on a socket was no shell (N1), and busybox
//! was asked for its applet in `argv[0]` only, so `busybox sh`, `-sh` and
//! `-ash` were none either (BUG-85). Now [`shell_or_interpreter`] asks, in
//! order:
//!
//! 1. **the exec pump's content check** ([`keep_copy`]): for an exec whose
//!    standard streams (or its parent's) are an inet socket — R020's shapes
//!    — the pump compared the running image (`/proc/<pid>/exe`, the exec's
//!    own file by its device and inode) with every installed program of
//!    the same length, byte for byte (`nn_linux::program_images`): a copy of
//!    an installed shell under any name is that shell;
//! 2. **the installed programs' identities** ([`record_installed`]): the
//!    device and inode, in the kernel's form, of each shell `/etc/shells`
//!    lists (resolved), and of each shell, interpreter and busybox in the
//!    system's binary directories, recorded by the agent at its start and
//!    every minute — a hard link, a bind mount, a link the kernel resolved:
//!    the same file;
//! 3. **the executed file's name** ([`ProgramKind::of_name`]), as before:
//!    a shell built elsewhere (a container's image, a static build) is
//!    still recognised by its name. A name only ever adds a program, never
//!    exempts one.
//!
//! busybox runs the program its `argv` names, read as busybox reads it
//! (`crate::posture::script_args::busybox_program`, the interpreters'
//! reader's own): `argv[0]` less a login shell's `-`, and after `busybox`
//! itself the next argument.
//!
//! The system-tree exemptions of the rules (the trusted actor's record of
//! R011, R012, R013 and R017, R011's package transaction and initramfs
//! build, R006's distribution socat) are decided on the kernel's executed
//! file only ([`kernel_image`], [`exec_in_system_tree`]), never on the
//! caller's string (BUG-119): a string the kernel cut at 255 bytes named
//! `/usr/bin/./././…` and passed for `/usr/bin`.
//!
//! Not covered (said so): a shell that is not byte-identical to an
//! installed program (rebuilt, patched, downloaded) and named otherwise; a
//! copy checked only at an exec R020 looks at (its socket stdio).
//!
//! The core reads none of it (no file, no `/proc`): the pump reads and keeps
//! the facts here, per exec — (pid, the exec's time) — and the agent records
//! the installed programs.

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use nn_model::Event;
use parking_lot::RwLock;

/// Shells, by the name of their executed file (a version suffix allowed:
/// `ksh93`, `bash5.2`).
pub const SHELLS: &[&str] = &[
    "sh", "bash", "rbash", "dash", "ash", "zsh", "ksh", "mksh", "pdksh", "yash", "csh", "tcsh",
    "fish",
];

/// Interpreters a reverse shell is written in.
pub const INTERPRETERS: &[&str] = &[
    "python", "python2", "python3", "pypy", "pypy3", "perl", "ruby", "irb", "php", "lua", "luajit",
    "node", "nodejs", "deno", "tclsh", "wish", "expect", "pwsh",
];

/// busybox, by the name its executed file and its `argv[0]` start with
/// (`busybox`, `busybox.static`).
const BUSYBOX: &str = "busybox";

/// What a program is to the rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProgramKind {
    Shell,
    Interpreter,
    /// busybox: the program its `argv` names.
    Busybox,
}

impl ProgramKind {
    /// The kind a program's name gives — an executed file's basename, a word
    /// of a command line (its directories dropped): a shell or an
    /// interpreter of [`SHELLS`] or [`INTERPRETERS`], with a version suffix
    /// of digits and dots, or busybox.
    pub fn of_name(name: &str) -> Option<Self> {
        let base = base_of(name);
        if base.starts_with(BUSYBOX) {
            return Some(Self::Busybox);
        }
        if SHELLS.iter().any(|s| program_is(base, s)) {
            return Some(Self::Shell);
        }
        INTERPRETERS
            .iter()
            .any(|s| program_is(base, s))
            .then_some(Self::Interpreter)
    }
}

/// `base` is the program `name`, or `name` with a version suffix of digits
/// and dots (`php-fpm8.3`, `python3.12`).
pub(crate) fn program_is(base: &str, name: &str) -> bool {
    base.strip_prefix(name)
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// The last component of a path.
pub(crate) fn base_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A word of a command line names a shell (`/bin/sh`, `bash`): by name —
/// a command line holds names, no executed file.
pub fn names_a_shell(word: &str) -> bool {
    ProgramKind::of_name(word) == Some(ProgramKind::Shell)
}

/// A word of a command line names an interpreter (`python3`, `perl`).
pub fn names_an_interpreter(word: &str) -> bool {
    ProgramKind::of_name(word) == Some(ProgramKind::Interpreter)
}

/// A word of a command line names busybox.
pub fn names_busybox(word: &str) -> bool {
    ProgramKind::of_name(word) == Some(ProgramKind::Busybox)
}

/// Launchers a command line runs its program through (lot 313, BUG-112:
/// socat's `EXEC:/usr/bin/env sh`, `EXEC:setsid bash -i`): each with the
/// letters of its options that take a value (`-u NAME`), its long options
/// that do (`--unset NAME`; `--name=value` carries its own), and the
/// operands it reads before the program (`timeout`'s duration, `chrt`'s
/// priority, `taskset`'s mask).
const LAUNCHERS: &[(&str, &str, &[&str], usize)] = &[
    ("env", "uCP", &["unset", "chdir"], 0),
    ("setsid", "", &[], 0),
    ("nohup", "", &[], 0),
    ("stdbuf", "ioe", &["input", "output", "error"], 0),
    ("timeout", "ks", &["kill-after", "signal"], 1),
    ("nice", "n", &["adjustment"], 0),
    ("ionice", "cnp", &["class", "classdata", "pid"], 0),
    ("chrt", "", &[], 1),
    ("taskset", "", &[], 1),
    (
        "sudo",
        "ugCDhprtUT",
        &[
            "user",
            "group",
            "close-from",
            "chdir",
            "host",
            "prompt",
            "role",
            "type",
        ],
        0,
    ),
    ("doas", "uC", &[], 0),
];

/// Programs that start a shell of their own (`script -qc /bin/bash
/// /dev/null`; `script` alone runs `$SHELL`).
const STARTS_A_SHELL: &[&str] = &["script"];

/// Lot 313 (BUG-112): the command line `words` (its program first, as a
/// command line names it) runs a shell — its program, read past its
/// launchers ([`LAUNCHERS`]) and busybox (the program its next word
/// names), is a shell, a program that starts one, or an interpreter
/// running no script it names (inline code, its standard input, a REPL,
/// options the interpreters' one reader does not understand).
pub fn command_runs_a_shell(words: &[String]) -> bool {
    let mut at = 0;
    while let Some(word) = words.get(at) {
        let base = base_of(word);
        if names_busybox(base) {
            at += 1;
            continue;
        }
        let Some((_, letters, long, operands)) = LAUNCHERS.iter().find(|(n, ..)| *n == base) else {
            break;
        };
        at += 1;
        // its options, then its operands before the program
        while let Some(w) = words.get(at) {
            if w == "--" {
                at += 1;
                break;
            }
            if base == "env" && !w.starts_with('-') && w.contains('=') {
                at += 1;
                continue;
            }
            if let Some(name) = w.strip_prefix("--") {
                at += 1;
                if !name.contains('=') && long.contains(&name) {
                    at += 1;
                }
                continue;
            }
            if let Some(cluster) = w.strip_prefix('-').filter(|c| !c.is_empty()) {
                at += 1;
                // a letter that takes a value: the rest, else the next word
                if cluster
                    .find(|c| letters.contains(c))
                    .is_some_and(|i| i + 1 == cluster.len())
                {
                    at += 1;
                }
                continue;
            }
            break;
        }
        at += operands;
    }
    let Some(program) = words.get(at) else {
        return false;
    };
    if names_a_shell(program) || STARTS_A_SHELL.contains(&base_of(program)) {
        return true;
    }
    names_an_interpreter(program)
        && crate::posture::script_args::runs_of(std::path::Path::new(program), &words[at..])
            .script()
            .is_none()
}

/// The tool of `tools` an exec runs: by its `comm`, or by the kernel's
/// executed file's name (lot 313: a link to `/usr/bin/socat` under another
/// name runs socat; its `comm` is the link's), a version suffix of digits
/// and dots allowed on either (the lab, 12/11: Debian's and Ubuntu's socat
/// 1.8 installs `/usr/bin/socat1`, `/usr/bin/socat` a link to it).
pub fn tool_named<'a>(event: &Event, tools: &[&'a str]) -> Option<&'a str> {
    let Event::ProcessSpawn { comm, .. } = event else {
        return None;
    };
    let image = kernel_image(event).map(base_of);
    tools
        .iter()
        .find(|t| program_is(comm, t) || image.is_some_and(|i| program_is(i, t)))
        .copied()
}

/// One installed program: its identity as the exec sensor reports an
/// executed file (`st_dev` in the kernel's form, `MKDEV`, and `st_ino`), its
/// length and path (what a copy is compared with), and its kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledImage {
    pub id: (u64, u64),
    pub len: u64,
    pub path: String,
    pub kind: ProgramKind,
}

/// (pid, the exec's time): one exec.
type ExecKey = (u32, u64);

#[derive(Default)]
struct Known {
    /// The installed programs, oldest first (an upgrade adds an image and
    /// keeps the one it replaced: a process may still run it).
    installed: VecDeque<InstalledImage>,
    /// The execs the pump found to be a copy of an installed program.
    copies: HashMap<ExecKey, ProgramKind>,
    order: VecDeque<ExecKey>,
}

/// The installed programs the agent recorded, and the copies the exec pump
/// found: one host's.
static KNOWN: LazyLock<RwLock<Known>> = LazyLock::new(Default::default);

/// The installed images kept at most: every shell and interpreter of a
/// host, and the ones its upgrades replaced.
pub const INSTALLED_CAP: usize = 512;

/// The execs whose copy the pump found, kept at most (the oldest out).
pub const COPIES_CAP: usize = 1024;

impl Known {
    /// `image` recorded, at most `cap` kept (the oldest out); `true` when
    /// its identity is new.
    fn record(&mut self, image: InstalledImage, cap: usize) -> bool {
        if image.id == (0, 0) || self.installed.iter().any(|i| i.id == image.id) {
            return false;
        }
        if self.installed.len() >= cap {
            self.installed.pop_front();
        }
        self.installed.push_back(image);
        true
    }

    /// `kind` kept for the exec `key`, at most `cap` execs (the oldest out).
    fn keep(&mut self, key: ExecKey, kind: ProgramKind, cap: usize) {
        if self.copies.insert(key, kind).is_none() {
            self.order.push_back(key);
        }
        while self.order.len() > cap {
            if let Some(old) = self.order.pop_front() {
                self.copies.remove(&old);
            }
        }
    }
}

/// Record an installed program; `true` when its identity is new. `(0, 0)`
/// is no identity.
pub fn record_installed(image: InstalledImage) -> bool {
    KNOWN.write().record(image, INSTALLED_CAP)
}

/// The installed programs `len` bytes long (what the pump compares a
/// running image with).
pub fn installed_of_len(len: u64) -> Vec<InstalledImage> {
    KNOWN
        .read()
        .installed
        .iter()
        .filter(|i| i.len == len)
        .cloned()
        .collect()
}

/// The installed program whose identity is `id`.
pub fn installed_kind(id: (u64, u64)) -> Option<ProgramKind> {
    if id == (0, 0) {
        return None;
    }
    KNOWN
        .read()
        .installed
        .iter()
        .find(|i| i.id == id)
        .map(|i| i.kind)
}

fn exec_key(event: &Event) -> Option<ExecKey> {
    match event {
        Event::ProcessSpawn {
            pid, timestamp_ns, ..
        } => Some((*pid, *timestamp_ns)),
        _ => None,
    }
}

/// The exec pump's answer for `event`: its running image is a copy of an
/// installed program of `kind`.
pub fn keep_copy(event: &Event, kind: ProgramKind) {
    if let Some(key) = exec_key(event) {
        KNOWN.write().keep(key, kind, COPIES_CAP);
    }
}

/// What the pump found `event`'s image to be a copy of.
pub fn copy_of(event: &Event) -> Option<ProgramKind> {
    let key = exec_key(event)?;
    KNOWN.read().copies.get(&key).copied()
}

/// What the kernel executed for `event` (an exec), by identity: the pump's
/// content check, else the installed programs' device and inode (the LSM
/// hook's: a tracepoint exec carries none), else the executed file's name
/// (module docs).
pub fn image_kind(event: &Event) -> Option<ProgramKind> {
    let Event::ProcessSpawn { filename, exe, .. } = event else {
        return None;
    };
    if let Some(kind) = copy_of(event) {
        return Some(kind);
    }
    if exe.has(common::wire::exe::exe_flags::KNOWN) {
        if let Some(kind) = installed_kind((exe.dev, exe.ino)) {
            return Some(kind);
        }
    }
    ProgramKind::of_name(exe.path_or(filename))
}

/// The program an exec runs is a shell (`Some(true)`) or an interpreter
/// (`Some(false)`) — busybox's by the program its `argv` names; `None` for
/// anything else.
pub fn shell_or_interpreter(event: &Event) -> Option<bool> {
    let Event::ProcessSpawn { argv, .. } = event else {
        return None;
    };
    match image_kind(event)? {
        ProgramKind::Shell => Some(true),
        ProgramKind::Interpreter => Some(false),
        ProgramKind::Busybox => {
            let (program, _) = crate::posture::script_args::busybox_program(argv)?;
            crate::posture::script_args::BUSYBOX_SHELLS
                .contains(&program)
                .then_some(true)
        }
    }
}

/// The file the kernel executed for `event`, as the exec sensor placed it
/// (`ExeIdentity::path`: the LSM hook's path mapped to its mount point; in
/// tracepoint mode the exec pump's — `/proc/<pid>/exe`, or a whole absolute
/// string resolved lexically, external audit PROC-002/003) — `None` when it
/// is not known: never the caller's raw string, cut at 255 bytes or not
/// (BUG-119).
pub fn kernel_image(event: &Event) -> Option<&str> {
    let exe = match event {
        Event::ProcessSpawn { exe, .. } | Event::ExecCheck { exe, .. } => exe,
        _ => return None,
    };
    let path = exe.path_or("");
    (!path.is_empty()).then_some(path)
}

/// The executed file lies in a root-owned system tree
/// ([`crate::posture::lineage::in_system_tree`]), by the kernel's path
/// ([`kernel_image`]): a file whose place is not known is in none.
pub fn exec_in_system_tree(event: &Event) -> bool {
    kernel_image(event).is_some_and(crate::posture::lineage::in_system_tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn, spawn_exe};

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn with_argv(mut e: Event, a: &[&str]) -> Event {
        if let Event::ProcessSpawn { argv: v, .. } = &mut e {
            *v = argv(a);
        }
        e
    }

    fn with_id(mut e: Event, pid: u32, ts: u64, id: (u64, u64)) -> Event {
        if let Event::ProcessSpawn {
            pid: p,
            timestamp_ns,
            exe,
            ..
        } = &mut e
        {
            *p = pid;
            *timestamp_ns = ts;
            (exe.dev, exe.ino) = id;
        }
        e
    }

    #[test]
    fn names_give_a_kind() {
        for (n, k) in [
            ("/bin/sh", Some(ProgramKind::Shell)),
            ("bash", Some(ProgramKind::Shell)),
            ("ksh93", Some(ProgramKind::Shell)),
            ("python3.12", Some(ProgramKind::Interpreter)),
            ("/usr/bin/perl", Some(ProgramKind::Interpreter)),
            ("/bin/busybox", Some(ProgramKind::Busybox)),
            ("busybox.static", Some(ProgramKind::Busybox)),
            ("shellcheck", None),
            ("bashbug", None),
            ("x", None),
            ("", None),
        ] {
            assert_eq!(ProgramKind::of_name(n), k, "{n}");
        }
        assert!(names_a_shell("/usr/bin/zsh") && !names_a_shell("python3"));
        assert!(names_an_interpreter("ruby") && !names_an_interpreter("sh"));
        assert!(names_busybox("/bin/busybox") && !names_busybox("sh"));
    }

    /// The installed programs by their identity: a hard link or a bind
    /// mount of `/usr/bin/bash` under another name is bash; `(0, 0)` and a
    /// tracepoint exec (no identity from the hook) are none.
    #[test]
    fn an_installed_shell_is_known_by_its_identity_under_any_name() {
        let bash = (0x0fd0_0001, 313_001);
        assert!(record_installed(InstalledImage {
            id: bash,
            len: 1_446_024,
            path: "/usr/bin/bash".into(),
            kind: ProgramKind::Shell,
        }));
        assert!(!record_installed(InstalledImage {
            id: bash,
            len: 1,
            path: "/bin/bash".into(),
            kind: ProgramKind::Shell,
        }));
        assert!(!record_installed(InstalledImage {
            id: (0, 0),
            len: 1,
            path: "/x".into(),
            kind: ProgramKind::Shell,
        }));
        assert_eq!(installed_kind(bash), Some(ProgramKind::Shell));
        assert_eq!(installed_kind((0, 0)), None);
        assert!(installed_of_len(1_446_024).iter().any(|i| i.id == bash));
        let link = with_id(
            spawn_exe("x", "/home/u/x", "/home/u/x", 0),
            313_101,
            1,
            bash,
        );
        assert_eq!(image_kind(&link), Some(ProgramKind::Shell));
        assert_eq!(shell_or_interpreter(&link), Some(true));
        // the same numbers from a tracepoint exec: no identity from the hook
        let tp = with_id(spawn("x", "/home/u/x"), 313_102, 1, bash);
        assert_eq!(image_kind(&tp), None);
    }

    /// The pump's content check is per exec: another exec of the pid is
    /// not a copy.
    #[test]
    fn a_copy_is_kept_per_exec() {
        let e = with_id(
            spawn_exe("x", "/home/u/x", "/home/u/x", 0),
            313_201,
            7,
            (9, 9),
        );
        assert_eq!(image_kind(&e), None);
        keep_copy(&e, ProgramKind::Shell);
        assert_eq!(copy_of(&e), Some(ProgramKind::Shell));
        assert_eq!(shell_or_interpreter(&e), Some(true));
        let later = with_id(e.clone(), 313_201, 8, (9, 9));
        assert_eq!(copy_of(&later), None);
    }

    /// Both tables are bounded, the oldest out first (on a table of the
    /// test's own: the process's is shared by the tests).
    #[test]
    fn the_tables_are_bounded() {
        let mut k = Known::default();
        for i in 0..5u32 {
            k.keep((i, 1), ProgramKind::Shell, 3);
        }
        assert_eq!(k.copies.len(), 3);
        assert!(!k.copies.contains_key(&(0, 1)) && k.copies.contains_key(&(4, 1)));
        let image = |n: u64| InstalledImage {
            id: (1, n),
            len: n,
            path: format!("/usr/bin/sh{n}"),
            kind: ProgramKind::Shell,
        };
        for n in 1..=4 {
            assert!(k.record(image(n), 3));
        }
        assert!(!k.record(image(4), 3), "known");
        assert_eq!(k.installed.len(), 3);
        assert!(k.installed.iter().all(|i| i.id != (1, 1)), "the oldest out");
    }

    /// busybox runs the program its `argv` names, as busybox reads it.
    #[test]
    fn busybox_runs_the_shell_its_argv_names() {
        let bb = |a: &[&str]| {
            shell_or_interpreter(&with_argv(
                spawn_exe("busybox", "/bin/busybox", "/bin/busybox", 0),
                a,
            ))
        };
        for a in [
            &["sh", "-i"][..],
            &["-sh"],
            &["-ash"],
            &["/bin/sh"],
            &["busybox", "sh", "-i"],
            &["/bin/busybox", "sh"],
            &["busybox", "/bin/ash"],
            &["busybox.static", "sh"],
            &["busybox", "busybox", "hush"],
        ] {
            assert_eq!(bb(a), Some(true), "{a:?}");
        }
        for a in [
            &["busybox", "nc", "h", "1"][..],
            &["busybox", "cat"],
            &["busybox"],
            &["busybox", "--help", "sh"],
            &["busybox", "--list"],
            &["busybox", "-sh"],
            &["/x/-sh"],
            &["ls"],
        ] {
            assert_eq!(bb(a), None, "{a:?}");
        }
    }

    /// BUG-112: a command line's program, read past its launchers.
    #[test]
    fn a_command_line_s_program_is_read_past_its_launchers() {
        let runs = |c: &str| command_runs_a_shell(&argv(&c.split(' ').collect::<Vec<_>>()));
        for c in [
            "/bin/sh",
            "bash -li",
            "/usr/bin/env sh",
            "env -i PATH=/bin HOME=/ bash -i",
            "env -u HISTFILE -- /bin/bash",
            "/usr/bin/setsid bash -i",
            "setsid -w nohup zsh",
            "stdbuf -o0 -e 0 bash",
            "stdbuf --output L sh",
            "timeout 3600 bash",
            "timeout -k 5 -s KILL 60 sh -i",
            "nice -n 19 ionice -c 3 bash",
            "chrt -f 10 taskset 0x1 sh",
            "sudo -u root bash",
            "doas sh",
            "busybox sh",
            "/bin/busybox ash -i",
            "script -qc /bin/bash /dev/null",
            "python3 -c import",
            "python3",
            "perl -e exec",
            "ruby -rsocket -e x",
            "python3 -X frozen_modules=off -c x",
        ] {
            assert!(runs(c), "{c}");
        }
        for c in [
            "/usr/bin/id",
            "cat",
            "env",
            "env FOO=1",
            "timeout 5",
            "python3 /srv/app/main.py",
            "busybox cat",
            "nohup /usr/bin/tail -f /var/log/syslog",
            "",
        ] {
            assert!(!runs(c), "{c}");
        }
    }

    /// The tool an exec runs: by its `comm`, or the kernel's executed file.
    #[test]
    fn a_tool_is_named_by_its_comm_or_its_executed_file() {
        let tools = ["socat", "msfvenom"];
        let by_link = spawn_exe("x", "/home/u/x", "/usr/bin/socat", 0);
        assert_eq!(tool_named(&by_link, &tools), Some("socat"));
        assert_eq!(tool_named(&spawn("socat", "/x"), &tools), Some("socat"));
        assert_eq!(tool_named(&spawn("x", "/usr/bin/socat"), &tools), None);
        assert_eq!(
            tool_named(&spawn_exe("socatx", "/x", "/usr/bin/socatx", 0), &tools),
            None
        );
        // the lab (12/11): socat 1.8's file is `socat1`, `socat` a link
        let socat1 = spawn_exe("relay", "/home/u/relay", "/usr/bin/socat1", 0);
        assert_eq!(tool_named(&socat1, &tools), Some("socat"));
        assert_eq!(
            tool_named(
                &spawn_exe("socat1", "/usr/bin/socat1", "/usr/bin/socat1", 0),
                &tools
            ),
            Some("socat")
        );
        assert_eq!(
            tool_named(&spawn_exe("socat-x", "/x", "/usr/bin/socat-x", 0), &tools),
            None
        );
    }

    /// BUG-119's family (lot 313's mini-hunt): the lineage keeps the
    /// caller's string when the kernel's path is not known, and judged it
    /// with the same tree test — a cut `/usr/bin/./././…` was an installed
    /// program, a trusted writer's hop. A string with an empty, `.` or `..`
    /// segment is no canonical path: in no system tree.
    #[test]
    fn bug119_a_cut_string_is_no_installed_program_anywhere() {
        let cut = format!("/usr/bin/{}", "./".repeat(123));
        assert_eq!(cut.len(), 255);
        let id = crate::posture::lineage::ExecIdentity::of_exec(&cut, &argv(&["kmod"]));
        assert!(!id.is_installed_program(), "{cut}");
        assert!(!crate::posture::lineage::in_system_tree(&cut));
    }

    /// BUG-119: the kernel's place of the executed file only; the caller's
    /// string, cut or whole, places nothing.
    #[test]
    fn the_system_tree_is_the_kernel_s_executed_file() {
        let kernel = spawn_exe("kmod", "/tmp/x/kmod", "/usr/bin/kmod", 0);
        assert_eq!(kernel_image(&kernel), Some("/usr/bin/kmod"));
        assert!(exec_in_system_tree(&kernel));
        let copy = spawn_exe("kmod", "/usr/bin/kmod", "/tmp/x/kmod", 0);
        assert!(!exec_in_system_tree(&copy));
        let caller_only = spawn("kmod", "/usr/bin/kmod");
        assert_eq!(kernel_image(&caller_only), None);
        assert!(!exec_in_system_tree(&caller_only));
    }
}
