//! Lot 313 (external bug hunt, edition 1.4: BUG-85, N1): the host's shells,
//! interpreters and busybox by their identity, for R020
//! (`nn_core::decision::rules::program_identity`).
//!
//! - [`seed`], at the agent's start, and [`refresh`], every minute: each
//!   shell `/etc/shells` lists, and each file of the system's binary
//!   directories, resolved to the file it names, when that file is named as
//!   a shell, an interpreter or busybox — its device in the kernel's form
//!   (`MKDEV`, what the exec sensor reports: lot 310's finding), its inode,
//!   length and path. An upgrade gives a program a new inode: the minute's
//!   refresh records it, and the old one stays (a process may still run
//!   it).
//! - [`read_and_keep`], the exec pump's step: for an exec whose standard
//!   streams, or its parent's, are an inet socket (R020's shapes: rare) and
//!   whose file is no installed program by its identity, the running image
//!   (`/proc/<pid>/exe`, the exec's own file by its device and inode when
//!   the LSM hook gave them) is compared, byte for byte, with every
//!   installed program of its length; a copy is kept for the exec. `cp
//!   /bin/bash ~/x` is bash whatever its name (N1).
//!
//! A name only chooses which installed files are recorded; what an exec
//! runs is then told by the file, never by its name.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nn_core::decision::rules::module_provenance::same_content;
use nn_core::decision::rules::program_identity::{self, InstalledImage, ProgramKind};
use nn_model::Event;

/// The system's binary directories, where a distribution or an
/// administrator installs a shell or an interpreter (each writable by root
/// only).
pub const BIN_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"];

/// The files of a binary directory looked at, at most.
const MAX_DIR_ENTRIES: usize = 20_000;

/// The installed images compared with a running one, at most (an image's
/// length is shared by few files).
const MAX_COMPARED: usize = 8;

/// `path` (followed) as an installed program of `kind`.
fn image_of(path: &Path, kind: ProgramKind) -> Option<InstalledImage> {
    let real = std::fs::canonicalize(path).ok()?;
    let m = std::fs::metadata(&real).ok()?;
    if !m.is_file() {
        return None;
    }
    Some(InstalledImage {
        id: (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        ),
        len: m.len(),
        path: real.to_string_lossy().into_owned(),
        kind,
    })
}

/// The kind of an installed file, by the name of the file a path resolves
/// to (`/usr/bin/sh` → `dash`; `/bin/sh` on Alpine → `busybox`).
fn kind_of(path: &Path) -> Option<ProgramKind> {
    let real = std::fs::canonicalize(path).ok()?;
    ProgramKind::of_name(&real.to_string_lossy())
}

/// The installed programs under `root` (`/` on the host, a test's tree):
/// `/etc/shells`' and the binary directories'.
pub fn installed_under(root: &Path) -> Vec<InstalledImage> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(text) = std::fs::read(root.join("etc/shells")) {
        for line in String::from_utf8_lossy(&text).lines() {
            let line = line.trim();
            if line.starts_with('/') {
                paths.push(root.join(line.trim_start_matches('/')));
            }
        }
    }
    for dir in BIN_DIRS {
        let Ok(rd) = std::fs::read_dir(root.join(dir.trim_start_matches('/'))) else {
            continue;
        };
        // every entry, by the name of the file it resolves to: a link of
        // another name (`/usr/bin/pwsh-preview` → `/opt/…/pwsh`) is that file
        paths.extend(rd.flatten().take(MAX_DIR_ENTRIES).map(|e| e.path()));
    }
    let mut out: Vec<InstalledImage> = Vec::new();
    for p in paths {
        let Some(image) = kind_of(&p).and_then(|k| image_of(&p, k)) else {
            continue;
        };
        if !out.iter().any(|i| i.id == image.id) {
            out.push(image);
        }
    }
    out
}

/// Record the installed programs under `root`; how many were new.
pub fn refresh_under(root: &Path) -> usize {
    installed_under(root)
        .into_iter()
        .filter(|i| program_identity::record_installed(i.clone()))
        .count()
}

/// [`refresh_under`] the host's root: the agent's start and every minute.
pub fn refresh() -> usize {
    refresh_under(Path::new("/"))
}

/// [`refresh`], at the agent's start.
pub fn seed() -> usize {
    refresh()
}

/// The exec pump's step (module docs).
pub fn read_and_keep(event: &Event) {
    read_and_keep_at(event, Path::new("/proc"));
}

/// [`read_and_keep`] with `/proc` at `proc_root` (tests).
fn read_and_keep_at(event: &Event, proc_root: &Path) {
    let Event::ProcessSpawn {
        pid, exe, stdio, ..
    } = event
    else {
        return;
    };
    if !stdio.own.stdin_or_stdout_inet() && !stdio.parent.stdin_or_stdout_inet() {
        return;
    }
    let known = exe.has(common::wire::exe::exe_flags::KNOWN);
    if known && program_identity::installed_kind((exe.dev, exe.ino)).is_some() {
        return;
    }
    let running = proc_root.join(pid.to_string()).join("exe");
    let Ok(m) = std::fs::metadata(&running) else {
        return;
    };
    // the exec's own file, when the hook said which (a later exec of the
    // pid runs another)
    if known
        && (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        ) != (exe.dev, exe.ino)
    {
        return;
    }
    if let Some(kind) = copy_kind(&running, m.len()) {
        program_identity::keep_copy(event, kind);
    }
}

/// The kind of the installed program whose content `file` (`len` bytes)
/// holds.
fn copy_kind(file: &Path, len: u64) -> Option<ProgramKind> {
    program_identity::installed_of_len(len)
        .into_iter()
        .take(MAX_COMPARED)
        .find(|i| same_content(Path::new(&i.path), file, len))
        .map(|i| i.kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_model::{StdioSocket, StdioSockets};
    use std::os::unix::fs::symlink;

    fn put(root: &Path, path: &str, content: &[u8]) -> PathBuf {
        let f = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, content).unwrap();
        f
    }

    /// `/etc/shells` and the binary directories, resolved: a link is
    /// recorded as the file it names, once, by that file's name (a link
    /// named `zsh` to `ls` is no shell, one named `pwsh-preview` to `pwsh`
    /// an interpreter); a file named otherwise, or outside those
    /// directories and `/etc/shells`, is not.
    #[test]
    fn the_installed_shells_are_recorded_by_the_file_they_name() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let bash = put(r, "/usr/bin/bash", b"bash 5.2 image, 313");
        put(r, "/usr/bin/python3.12", b"python 3.12 image, 313");
        put(r, "/usr/bin/busybox", b"busybox image, 313");
        put(r, "/usr/bin/ls", b"ls image, 313");
        put(r, "/opt/zsh/bin/zsh", b"zsh image, 313");
        put(r, "/home/u/bash", b"bash in a home, 313");
        symlink(&bash, r.join("usr/bin/rbash")).unwrap();
        symlink("python3.12", r.join("usr/bin/python3")).unwrap();
        // a link of another name to an interpreter outside the directories
        let pwsh = put(r, "/opt/microsoft/powershell/7/pwsh", b"pwsh image, 313");
        symlink(&pwsh, r.join("usr/bin/pwsh-preview")).unwrap();
        // a link of a shell's name to a file of another
        symlink(r.join("usr/bin/ls"), r.join("usr/bin/zsh")).unwrap();
        put(
            r,
            "/etc/shells",
            b"# shells\n/bin/sh\n/usr/bin/bash\n/usr/bin/rbash\n/opt/zsh/bin/zsh\n\n",
        );
        // `/bin/sh` → busybox (Alpine)
        std::fs::create_dir_all(r.join("bin")).unwrap();
        symlink(r.join("usr/bin/busybox"), r.join("bin/sh")).unwrap();
        let mut got: Vec<(String, ProgramKind)> = installed_under(r)
            .into_iter()
            .map(|i| {
                let p = i
                    .path
                    .strip_prefix(&*r.to_string_lossy())
                    .unwrap()
                    .to_string();
                (p, i.kind)
            })
            .collect();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            got,
            vec![
                (
                    "/opt/microsoft/powershell/7/pwsh".to_string(),
                    ProgramKind::Interpreter
                ),
                ("/opt/zsh/bin/zsh".to_string(), ProgramKind::Shell),
                ("/usr/bin/bash".to_string(), ProgramKind::Shell),
                ("/usr/bin/busybox".to_string(), ProgramKind::Busybox),
                ("/usr/bin/python3.12".to_string(), ProgramKind::Interpreter),
            ]
        );
        // the device as the exec sensor reports it
        let m = std::fs::metadata(&bash).unwrap();
        let image = installed_under(r)
            .into_iter()
            .find(|i| i.path.ends_with("/usr/bin/bash"))
            .unwrap();
        assert_eq!(
            image.id,
            (
                crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
                m.ino()
            )
        );
        assert_eq!(image.len, m.len());
    }

    fn exec(pid: u32, ts: u64, own: StdioSocket) -> Event {
        let mut e = nn_core::decision::rules::testutil::spawn("x", "/home/u/x");
        if let Event::ProcessSpawn {
            pid: p,
            timestamp_ns,
            stdio,
            ..
        } = &mut e
        {
            *p = pid;
            *timestamp_ns = ts;
            *stdio = StdioSockets {
                own,
                parent: StdioSocket::default(),
            };
        }
        e
    }

    fn outbound() -> StdioSocket {
        StdioSocket {
            read: true,
            inet_fds: 0b011,
            outbound: true,
            proto: 6,
            peer: Some("127.0.0.1:4444".parse().unwrap()),
        }
    }

    /// N1: a copy of an installed shell, running with its stdio on a
    /// socket, is kept as that shell for its exec; the same file without a
    /// socket is not read, nor is a file of other content, nor the running
    /// image of a later exec of the pid (its device and inode another's).
    #[test]
    fn a_copy_of_an_installed_shell_is_that_shell() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let content = b"#!bash image of lot 313, n1 #1".repeat(1000);
        put(r, "/usr/bin/bash", &content);
        refresh_under(r);
        let copy = put(r, "/home/u/x", &content);
        let other = put(
            r,
            "/home/u/y",
            &b"#!bash image of lot 313, n1 #2".repeat(1000),
        );
        let proc_root = r.join("proc");
        for (pid, target) in [(31301, &copy), (31302, &other), (31303, &copy)] {
            std::fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            symlink(target, proc_root.join(pid.to_string()).join("exe")).unwrap();
        }
        let e = exec(31301, 1, outbound());
        read_and_keep_at(&e, &proc_root);
        assert_eq!(program_identity::copy_of(&e), Some(ProgramKind::Shell));
        let e = exec(31302, 1, outbound());
        read_and_keep_at(&e, &proc_root);
        assert_eq!(program_identity::copy_of(&e), None, "other content");
        let e = exec(31303, 1, StdioSocket::default());
        read_and_keep_at(&e, &proc_root);
        assert_eq!(program_identity::copy_of(&e), None, "no socket: not read");
        // the hook named another file than the one running now
        let mut e = exec(31303, 2, outbound());
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.flags = common::wire::exe::exe_flags::KNOWN;
            (exe.dev, exe.ino) = (1, 1);
        }
        read_and_keep_at(&e, &proc_root);
        assert_eq!(program_identity::copy_of(&e), None, "a later exec's image");
    }
}
