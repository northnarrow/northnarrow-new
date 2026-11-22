//! The dynamic loader's preload list (`/etc/ld.so.preload`) read as the
//! loader reads it, for the three that judge it: the watchdog's respawn
//! gate (lot 374: a list new or changed while the role is vacated holds the
//! successor's start), `nn-admin host-check` and `install.sh`'s preflight
//! (lot 377: a host whose list makes every program load a library cannot
//! run the agent — the start check of the agent and of the watchdog,
//! [`crate::start_check`], refuses an executable mapping of a library the
//! release does not link). `install.sh` keeps a shell copy of
//! [`preload_names`] and [`candidates`] (`preload_check`), tested on the
//! same cases.

use std::io::Read;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::Path;

/// The dynamic loader's preload list, read by every dynamically linked
/// start.
pub const PRELOAD_PATH: &str = "/etc/ld.so.preload";
/// The most of it read (far above any real list).
pub const PRELOAD_MAX: u64 = 64 << 10;

/// The list at `path` as the loader reads it (symbolic links followed),
/// never blocking on a FIFO: a regular file only, at most [`PRELOAD_MAX`]
/// bytes. `NotFound` when there is none; any other error when it cannot be
/// read as a list (a FIFO, a socket, a device, a directory, too large).
pub fn read_list(path: &Path) -> std::io::Result<Vec<u8>> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY)
        .open(path)?;
    let t = f.metadata()?.file_type();
    if !t.is_file() {
        let what = if t.is_fifo() {
            "a FIFO"
        } else if t.is_socket() {
            "a socket"
        } else if t.is_char_device() || t.is_block_device() {
            "a device"
        } else {
            "not a regular file"
        };
        return Err(std::io::Error::other(what));
    }
    let mut b = Vec::new();
    f.take(PRELOAD_MAX + 1).read_to_end(&mut b)?;
    if b.len() as u64 > PRELOAD_MAX {
        return Err(std::io::Error::other(format!(
            "larger than {PRELOAD_MAX} bytes"
        )));
    }
    Ok(b)
}

/// The re-check of #582 (N3): the names a preload list holds, as the
/// loader splits it (white space and `:`; `#` starts a comment to the end
/// of its line).
pub fn preload_names(text: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(text);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        for n in line.split(|c: char| c.is_ascii_whitespace() || c == ':') {
            if !n.is_empty() && !out.iter().any(|o| o == n) {
                out.push(n.to_string());
            }
        }
    }
    out
}

/// The directories the loader searches for a name without a `/` (the
/// default paths of the supported layouts: Debian's multiarch, Fedora's
/// `lib64`, merged `/usr` or not).
pub const SEARCH_DIRS: &[&str] = &[
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/lib",
    "/usr/lib",
];

/// The re-check of #582 (N3): every path the loader may load for preload
/// entry `name` — the path itself, its `$LIB` and `$PLATFORM` expansions
/// (each a supported layout's), or `name` in each of [`SEARCH_DIRS`].
pub fn candidates(name: &str) -> Vec<String> {
    let mut out = vec![name.to_string()];
    for (token, values) in [
        (
            "$LIB",
            &[
                "lib",
                "lib64",
                "lib/x86_64-linux-gnu",
                "usr/lib",
                "usr/lib64",
            ][..],
        ),
        (
            "${LIB}",
            &[
                "lib",
                "lib64",
                "lib/x86_64-linux-gnu",
                "usr/lib",
                "usr/lib64",
            ][..],
        ),
        ("$PLATFORM", &["x86_64", "haswell", "xeon_phi"][..]),
        ("${PLATFORM}", &["x86_64", "haswell", "xeon_phi"][..]),
    ] {
        out = out
            .into_iter()
            .flat_map(|p| {
                if p.contains(token) {
                    values.iter().map(|v| p.replace(token, v)).collect()
                } else {
                    vec![p]
                }
            })
            .collect();
    }
    if !name.contains('/') {
        out = SEARCH_DIRS.iter().map(|d| format!("{d}/{name}")).collect();
    }
    out.dedup();
    out
}

/// What a preload list makes every dynamically linked start load (lot 377).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No list.
    Absent,
    /// A list that loads nothing: `names` names (0: empty, or comments
    /// only), none of a file that exists.
    Inert { names: usize },
    /// The files that exist at the paths its names resolve to (each
    /// absolute, as the daemons' start resolves it from `/`).
    Loads(Vec<String>),
    /// Lot 385 (the review of #593): no file this caller saw, and a path a
    /// name resolves to whose `stat(2)` failed for another reason than its
    /// absence — `EACCES` in a directory this user cannot search
    /// (`nn-admin host-check` without root): what the list loads is not
    /// known to this caller. Each such path, with its error's kind.
    Unseen(Vec<(String, std::io::ErrorKind)>),
    /// A list that cannot be read as one (a FIFO, a device, too large, a
    /// read error): every start reads it, and nothing says what it loads.
    Unjudged(String),
}

/// [`Verdict`] of the list at `list` (an absolute path), its names
/// resolved below `root` (`/` on a host; a test's tree). A name's
/// candidate exists when `stat(2)` of it succeeds (symbolic links
/// followed) — present, whether or not the loader would accept the file;
/// it is absent only when the path walk ends at no entry (`ENOENT`) or at a
/// file where a directory should be (`ENOTDIR`), which ends it the same way
/// for every caller. Any other failure (`EACCES`: a directory this user
/// cannot search) is no absence: [`Verdict::Unseen`] unless a file was
/// found.
pub fn judge_in(root: &Path, list: &Path) -> Verdict {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let text = match read_list(&at(&list.to_string_lossy())) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Verdict::Absent,
        Err(e) => return Verdict::Unjudged(e.to_string()),
    };
    let names = preload_names(&text);
    let mut found: Vec<String> = Vec::new();
    let mut unseen: Vec<(String, std::io::ErrorKind)> = Vec::new();
    for n in &names {
        for c in candidates(n) {
            let c = if c.starts_with('/') {
                c
            } else {
                format!("/{c}")
            };
            if found.contains(&c) || unseen.iter().any(|(u, _)| *u == c) {
                continue;
            }
            match std::fs::metadata(at(&c)) {
                Ok(_) => found.push(c),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) => {}
                Err(e) => unseen.push((c, e.kind())),
            }
        }
    }
    if !found.is_empty() {
        Verdict::Loads(found)
    } else if !unseen.is_empty() {
        Verdict::Unseen(unseen)
    } else {
        Verdict::Inert { names: names.len() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tree with the libraries `libs` (empty files) and the list `text`
    /// at `/etc/ld.so.preload` (none: `None`).
    fn tree(libs: &[&str], text: Option<&[u8]>) -> tempfile::TempDir {
        let d = tempfile::tempdir().expect("tempdir");
        for l in libs {
            let p = d.path().join(l.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, b"").unwrap();
        }
        if let Some(t) = text {
            std::fs::create_dir_all(d.path().join("etc")).unwrap();
            std::fs::write(d.path().join("etc/ld.so.preload"), t).unwrap();
        }
        d
    }

    fn judge(d: &tempfile::TempDir) -> Verdict {
        judge_in(d.path(), Path::new(PRELOAD_PATH))
    }

    /// Lot 377 (named): a list that names a file that exists — by path,
    /// by a bare name in a system library directory, through `$LIB` or
    /// `${PLATFORM}`, after a `:` — loads it into every start; one that
    /// is absent, empty, comments only, or names no file that exists,
    /// loads nothing; one that cannot be read as a list is not judged.
    /// The same cases as install.sh's `preload_check`
    /// (`install_refuses_a_loadable_preload_list_and_notes_an_inert_one`).
    #[test]
    fn a_preload_list_is_judged_by_the_files_its_names_resolve_to() {
        let libs = [
            "/usr/lib/x86_64-linux-gnu/libnnlog.so",
            "/opt/v/lib64/libv.so",
            "/opt/v/x86_64/libp.so",
        ];
        assert_eq!(judge(&tree(&libs, None)), Verdict::Absent);
        for (text, names) in [
            (&b""[..], 0),
            (b"  \n\t\n", 0),
            (b"# /opt/v/lib64/libv.so\n", 0),
            (b"/nope/x.so  libmissing.so:/also/no.so\n", 3),
            (b"libv.so # not in a system directory\n", 1),
        ] {
            assert_eq!(
                judge(&tree(&libs, Some(text))),
                Verdict::Inert { names },
                "{}",
                String::from_utf8_lossy(text)
            );
        }
        for (text, want) in [
            (
                &b"libnnlog.so\n"[..],
                "/usr/lib/x86_64-linux-gnu/libnnlog.so",
            ),
            (b"/opt/v/$LIB/libv.so", "/opt/v/lib64/libv.so"),
            (b"/opt/v/${PLATFORM}/libp.so # c\n", "/opt/v/x86_64/libp.so"),
            (b"a.so:/opt/v/lib64/libv.so\n", "/opt/v/lib64/libv.so"),
            (b"opt/v/lib64/libv.so\n", "/opt/v/lib64/libv.so"),
        ] {
            assert_eq!(
                judge(&tree(&libs, Some(text))),
                Verdict::Loads(vec![want.to_string()]),
                "{}",
                String::from_utf8_lossy(text)
            );
        }
        // the mini-hunt's variants: CRLF lines, `${LIB}`, a list that is a
        // symbolic link to one (followed, as the loader opens it), a name
        // that is a dangling link (nothing loads)
        assert_eq!(
            judge(&tree(&libs, Some(b"libnnlog.so\r\n"))),
            Verdict::Loads(vec!["/usr/lib/x86_64-linux-gnu/libnnlog.so".to_string()])
        );
        assert_eq!(
            judge(&tree(&libs, Some(b"/opt/v/${LIB}/libv.so\n"))),
            Verdict::Loads(vec!["/opt/v/lib64/libv.so".to_string()])
        );
        let d = tree(&libs, None);
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        std::fs::write(d.path().join("vendor.list"), b"libnnlog.so\n").unwrap();
        std::os::unix::fs::symlink(
            d.path().join("vendor.list"),
            d.path().join("etc/ld.so.preload"),
        )
        .unwrap();
        assert!(matches!(judge(&d), Verdict::Loads(_)), "a linked list");
        let d = tree(&libs, Some(b"/opt/v/dangling.so\n"));
        std::os::unix::fs::symlink("/nonexistent/x.so", d.path().join("opt/v/dangling.so"))
            .unwrap();
        assert_eq!(judge(&d), Verdict::Inert { names: 1 }, "a dangling link");
        // a list that is no regular file, or too large: not judged
        let d = tree(&libs, None);
        std::fs::create_dir_all(d.path().join("etc/ld.so.preload")).unwrap();
        assert!(matches!(judge(&d), Verdict::Unjudged(_)), "a directory");
        let big = vec![b'a'; PRELOAD_MAX as usize + 1];
        assert!(
            matches!(judge(&tree(&libs, Some(&big))), Verdict::Unjudged(w) if w.contains("larger")),
            "too large"
        );
    }

    /// Lot 385 (the review of #593, named): a name whose file sits in a
    /// directory this user cannot search is no absent file. `nn-admin
    /// host-check` without root read such a list as loading nothing (`OK`)
    /// where root sees the library. By path, through `$LIB`, by a bare name
    /// in a system library directory, through a symbolic link: `Unseen`,
    /// never `Inert`; a file found by another name still `Loads`; a path
    /// through a regular file (`ENOTDIR`) is absent for every caller. (As
    /// root every directory is searched: the test needs another user.)
    #[test]
    fn a_name_this_user_cannot_look_at_is_unseen_not_absent() {
        use std::io::ErrorKind::PermissionDenied;
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipped: root searches every directory");
            return;
        }
        let libs = [
            "/secret/libhook.so",
            "/secret/lib64/libhook.so",
            "/usr/lib64/libhook2.so",
            "/usr/lib/x86_64-linux-gnu/libnnlog.so",
            "/opt/v/file",
        ];
        let d = tree(&libs, None);
        std::os::unix::fs::symlink(
            d.path().join("secret/libhook.so"),
            d.path().join("opt/v/link.so"),
        )
        .unwrap();
        let list = |text: &[u8]| {
            std::fs::create_dir_all(d.path().join("etc")).unwrap();
            std::fs::write(d.path().join("etc/ld.so.preload"), text).unwrap();
            judge(&d)
        };
        let shut = |mode: u32| {
            for dir in ["secret", "usr/lib64"] {
                std::fs::set_permissions(d.path().join(dir), std::fs::Permissions::from_mode(mode))
                    .unwrap();
            }
        };
        shut(0o000);
        let by_path = list(b"/secret/libhook.so\n");
        let by_lib = list(b"/secret/$LIB/libhook.so\n");
        let bare = list(b"libhook2.so\n");
        let linked = list(b"/opt/v/link.so\n");
        let also_found = list(b"/secret/libhook.so libnnlog.so\n");
        let not_a_dir = list(b"/opt/v/file/x.so\n");
        shut(0o755);
        let unseen = |p: &str| Verdict::Unseen(vec![(p.to_string(), PermissionDenied)]);
        assert_eq!(by_path, unseen("/secret/libhook.so"), "by path");
        assert!(
            matches!(&by_lib, Verdict::Unseen(p) if p.len() == 5
                && p.iter().all(|(c, k)| c.starts_with("/secret/") && *k == PermissionDenied)),
            "through $LIB: {by_lib:?}"
        );
        assert_eq!(bare, unseen("/usr/lib64/libhook2.so"), "a bare name");
        assert_eq!(linked, unseen("/opt/v/link.so"), "through a link");
        assert_eq!(
            also_found,
            Verdict::Loads(vec!["/usr/lib/x86_64-linux-gnu/libnnlog.so".to_string()]),
            "a file found by another name"
        );
        assert_eq!(not_a_dir, Verdict::Inert { names: 1 }, "ENOTDIR");
        // searchable again: what root sees
        assert_eq!(
            list(b"/secret/libhook.so\n"),
            Verdict::Loads(vec!["/secret/libhook.so".to_string()])
        );
    }

    /// A FIFO at the list's path is not opened for a writer: the read
    /// returns at once, as not a regular file.
    #[test]
    fn a_fifo_list_is_not_waited_on() {
        let d = tree(&[], None);
        std::fs::create_dir_all(d.path().join("etc")).unwrap();
        let p = d.path().join("etc/ld.so.preload");
        let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(judge(&d), Verdict::Unjudged(w) if w.contains("FIFO")));
    }
}
