//! Lot 310 (external bug hunt, edition 1.4: BUG-88): the one reader of "a
//! path through a link of `/proc`". It was lot 286's
//! `posture::triggers::through_proc_link` (the mass-write carve-out) beside
//! a narrower twin in R004 (`/proc/self/fd/N`, `/proc/<pid>/fd/N`,
//! `/dev/fd/N`), which `/proc/thread-self/fd/N`, `/proc/self/task/<tid>/fd/N`
//! and `/dev/stdin` passed. Both rules read it here now, and
//! `xtask/tests/proc_links.rs` keeps every other matching of such a path out
//! of the tree.
//!
//! What it reads is the caller's string (tracepoint mode, a path a file
//! event names): its spellings are unbounded — a relative path from a
//! `/proc/self` working directory, a symlink in a home directory — and only
//! the kernel's facts close them (R004 in LSM mode decides on the executed
//! file's own flags, not on this text).

/// Which link of a process's view a path goes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcLink {
    /// `/proc/<pid>[/task/<tid>]/cwd`, `root`: a directory of the process's
    /// view (the link itself or anything under it).
    View,
    /// `/proc/<pid>[/task/<tid>]/exe`: the image the process runs.
    Exe,
    /// An entry of `/proc/<pid>[/task/<tid>]/fd/` or `map_files/`, or
    /// `/dev/fd/<n>`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`: it reopens
    /// the file a descriptor (or a mapping) holds, linked or not.
    Descriptor,
}

/// Lot 286: the form of an unresolved `path` a prefix test may judge —
/// its `.` segments and repeated slashes folded — or `None` when it holds
/// a `..` segment. The kernel climbs a `..` from wherever the links before
/// it led, which the text does not show: `/proc/self/root/..` is `/` and
/// `/proc/self/cwd/../..` the cwd's grandparent, both folded to `/proc`
/// before (POS-004's fold judged them carved out); `/proc/net` is a link
/// to `self/net`, so `/proc/net/../root/…` reaches the process's root; a
/// sysfs link leads deeper or elsewhere in `/sys`, from where enough `..`
/// leave it.
pub(crate) fn lexical_form(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            s => parts.push(s),
        }
    }
    let joined = parts.join("/");
    Some(if path.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    })
}

/// The link a path (in [`lexical_form`]) goes through:
/// `/proc/<pid>[/task/<tid>]/` (or `self`, `thread-self`) then `cwd`, `root`
/// or `exe` (the link itself or anything under it), or an entry of `fd/` or
/// `map_files/` (each reopens the file it names); and (lot 286)
/// `/dev/fd/<n>`, `/dev/stdin`, `/dev/stdout`, `/dev/stderr`, links into
/// `/proc/self/fd/` that the `/dev/` prefix carved out. Any second segment
/// matches: no other entry of `/proc` holds such names, and a path that only
/// looks like one counts.
pub(crate) fn proc_link(path: &str) -> Option<ProcLink> {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let rest = match segs.as_slice() {
        ["dev", "fd", _, ..] | ["dev", "stdin" | "stdout" | "stderr", ..] => {
            return Some(ProcLink::Descriptor)
        }
        ["proc", _, "task", _, rest @ ..] | ["proc", _, rest @ ..] => rest,
        _ => return None,
    };
    match rest {
        ["cwd" | "root", ..] => Some(ProcLink::View),
        ["exe", ..] => Some(ProcLink::Exe),
        ["fd" | "map_files", _, ..] => Some(ProcLink::Descriptor),
        _ => None,
    }
}

/// A path (in [`lexical_form`]) through a link the kernel follows to a
/// process's view of the filesystem ([`proc_link`]).
pub(crate) fn through_proc_link(path: &str) -> bool {
    proc_link(path).is_some()
}

/// Lot 310 (BUG-88): an exec path, as the caller wrote it, that reopens a
/// descriptor ([`ProcLink::Descriptor`]): what fexecve(3) and its kin pass.
/// A `..` segment hides where the links lead ([`lexical_form`]): a path with
/// one that goes through `/proc` or `/dev` at all is taken for one
/// (`/proc/self/task/../fd/3` is `/proc/self/fd/3`).
pub(crate) fn reopens_a_descriptor(path: &str) -> bool {
    match lexical_form(path) {
        Some(p) => proc_link(&p) == Some(ProcLink::Descriptor),
        None => path.split('/').any(|s| matches!(s, "proc" | "dev")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_segments_fold_and_proc_links_are_doors() {
        assert_eq!(lexical_form("/home//u/./x").as_deref(), Some("/home/u/x"));
        assert_eq!(lexical_form("a/./b").as_deref(), Some("a/b"));
        // lot 286: a `..` is never folded (POS-004 folded both)
        assert_eq!(lexical_form("/proc/../home//u/./x"), None);
        assert_eq!(lexical_form("/a/b/../../.."), None);
        for (p, want) in [
            ("/proc/self/cwd/x", Some(ProcLink::View)),
            ("/proc/42/task/43/root/etc/x", Some(ProcLink::View)),
            ("/proc/self/cwd", Some(ProcLink::View)),
            ("/proc/self/exe", Some(ProcLink::Exe)),
            ("/proc/12/task/12/exe", Some(ProcLink::Exe)),
            ("/proc/thread-self/fd/3", Some(ProcLink::Descriptor)),
            ("/proc/self/task/4242/fd/3", Some(ProcLink::Descriptor)),
            ("/proc/4242/task/4242/fd/3", Some(ProcLink::Descriptor)),
            ("/proc/7/task/8/map_files/1-2", Some(ProcLink::Descriptor)),
            ("/dev/fd/4", Some(ProcLink::Descriptor)),
            ("/dev/stdout", Some(ProcLink::Descriptor)),
            ("/dev/stderr", Some(ProcLink::Descriptor)),
            ("/dev/stdin", Some(ProcLink::Descriptor)),
            ("/dev/fd", None),
            ("/dev/null", None),
            ("/proc/self/fd", None),
            ("/proc/self/task", None),
            ("/proc/sys/vm/x", None),
            ("/proc/self/oom_score_adj", None),
        ] {
            assert_eq!(proc_link(p), want, "{p}");
            assert_eq!(through_proc_link(p), want.is_some(), "{p}");
        }
    }

    /// BUG-88: every spelling of a descriptor the text can show — the
    /// per-thread names, a doubled slash, a `.` segment, `..` through
    /// `/proc` — and none that is a file of its own, the image or a view.
    #[test]
    fn a_descriptor_in_any_spelling_the_text_shows() {
        for p in [
            "/proc/self/fd/3",
            "/proc/4242/fd/3",
            "/proc/thread-self/fd/3",
            "/proc/self/task/4242/fd/3",
            "/proc/4242/task/4242/fd/3",
            "/proc//self/fd/3",
            "/proc/self/./fd/3",
            "/proc/self/task/../fd/3",
            "/proc/self/map_files/7f0000000000-7f0000001000",
            "/dev/fd/3",
            "/dev/stdin",
            "//dev//fd/0",
        ] {
            assert!(reopens_a_descriptor(p), "{p}");
        }
        for p in [
            "/usr/bin/ls",
            "/tmp/x",
            "/proc/self/exe",
            "/proc/self/cwd/payload",
            "/proc/self/root/usr/bin/ls",
            "/home/u/../x",
            "/dev/null",
        ] {
            assert!(!reopens_a_descriptor(p), "{p}");
        }
    }
}
