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

/// The link a path goes through: `/proc/<pid>[/task/<tid>]/` (or `self`,
/// `thread-self`) then `cwd`, `root` or `exe` (the link itself or anything
/// under it), or an entry of `fd/` or `map_files/` (each reopens the file it
/// names); and (lot 286) `/dev/fd/<n>`, `/dev/stdin`, `/dev/stdout`,
/// `/dev/stderr`, links into `/proc/self/fd/` that the `/dev/` prefix carved
/// out. Any second segment matches: no other entry of `/proc` holds such
/// names, and a path that only looks like one counts.
///
/// Lot 310 (the review of #539, finding 6): the path is folded first — `.`
/// and empty segments dropped, a `..` folded with the segment before it
/// (`/home/u/dev/../bin/tool` is `/home/u/bin/tool`, no link) — except a
/// `..` under `/proc/<x>/` or `/dev/<x>/`, where links lead elsewhere and
/// the kernel climbs from there (`/proc/self/task/../fd/3`, `/proc/net/..`):
/// where it leads is not known, and it counts as a descriptor. And
/// `/proc/<x>/root/` is the process's root: what follows is read again as
/// a path from it (`/proc/self/root/proc/self/fd/3` reopens descriptor 3).
pub(crate) fn proc_link(path: &str) -> Option<ProcLink> {
    match folded(path) {
        Some(segs) => link_of(&segs),
        None => Some(ProcLink::Descriptor),
    }
}

/// `path`'s segments folded as the text shows it ([`proc_link`]); `None`
/// for a `..` inside `/proc/<x>/` or `/dev/<x>/`. A relative path keeps its
/// segments (a leading `..` dropped: its directory is not known) and is
/// read as from the root.
fn folded(path: &str) -> Option<Vec<&str>> {
    let mut segs: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if segs.len() >= 2 && matches!(segs[0], "proc" | "dev") {
                    return None;
                }
                segs.pop();
            }
            s => segs.push(s),
        }
    }
    Some(segs)
}

/// The link of folded segments ([`proc_link`]).
fn link_of(segs: &[&str]) -> Option<ProcLink> {
    let rest = match segs {
        ["dev", "fd", _, ..] | ["dev", "stdin" | "stdout" | "stderr", ..] => {
            return Some(ProcLink::Descriptor)
        }
        ["proc", _, "task", _, rest @ ..] | ["proc", _, rest @ ..] => rest,
        _ => return None,
    };
    match rest {
        // the process's root: the rest is a path from it
        ["root", more @ ..] => link_of(more).or(Some(ProcLink::View)),
        ["cwd", ..] => Some(ProcLink::View),
        ["exe", ..] => Some(ProcLink::Exe),
        ["fd" | "map_files", _, ..] => Some(ProcLink::Descriptor),
        _ => None,
    }
}

/// A path through a link the kernel follows to a process's view of the
/// filesystem ([`proc_link`]).
pub(crate) fn through_proc_link(path: &str) -> bool {
    proc_link(path).is_some()
}

/// Lot 310 (BUG-88): an exec path, as the caller wrote it, that reopens a
/// descriptor ([`ProcLink::Descriptor`]): what fexecve(3) and its kin pass,
/// in every spelling the text shows ([`proc_link`]'s folding and its
/// `root/` chains).
pub(crate) fn reopens_a_descriptor(path: &str) -> bool {
    proc_link(path) == Some(ProcLink::Descriptor)
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

    /// The review of #539 (finding 6): a `..` outside a `/proc` or `/dev`
    /// link is folded — a source tree's `dev` directory is no descriptor
    /// (lot 310's first reader killed `execve("/home/u/dev/../bin/tool")`);
    /// one inside such a link is not known and counts; a process's `root`
    /// is read again from there.
    #[test]
    fn a_dot_dot_is_folded_outside_links_and_root_chains_are_followed() {
        for p in [
            "/home/u/dev/../bin/tool",
            "../dev/run.sh",
            "/opt/app/dev/../run.sh",
            "/home/u/proc/../bin/x",
            "/proc/../usr/bin/x",
            "/dev/../usr/bin/x",
            "dev/../bin/x",
        ] {
            assert_eq!(proc_link(p), None, "{p}");
            assert!(!reopens_a_descriptor(p), "{p}");
        }
        for p in [
            "/proc/self/root/proc/self/fd/3",
            "/proc/1/root/proc/self/fd/3",
            "/proc/self/root/dev/stdin",
            "/proc/self/root/proc/self/root/dev/fd/4",
            "/proc/self/task/../fd/3",
            "/proc/net/../fd/3",
            "/dev/fd/../fd/3",
            "/proc/self/cwd/../fd/3",
            // a `..` outside a link folds: the link is what is left
            "/tmp/../proc/self/fd/3",
            "/home/u/../../dev/fd/3",
        ] {
            assert!(reopens_a_descriptor(p), "{p}");
            assert!(through_proc_link(p), "{p}");
        }
        assert_eq!(
            proc_link("/proc/self/root/usr/bin/ls"),
            Some(ProcLink::View)
        );
        assert_eq!(
            proc_link("/proc/self/root/proc/self/exe"),
            Some(ProcLink::Exe)
        );
    }
}
