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
            return Some(ProcLink::Descriptor);
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

/// Lot 376 (the review of #583, F3): the descriptor of the caller's own
/// table an exec path reopens, spelled exactly as fexecve(3) and systemd's
/// `posix_spawn` of its executor spell it — `/proc/self/fd/N` or
/// `/dev/fd/N`, `N` decimal digits and nothing after. `None` for every other
/// spelling (a thread's, another pid's, a folded or relative one): an
/// exemption reads the forker's descriptor `N` only for these.
pub(crate) fn own_descriptor(path: &str) -> Option<u32> {
    let segs: Vec<&str> = path.split('/').collect();
    let n = match segs.as_slice() {
        ["", "proc", "self", "fd", n] | ["", "dev", "fd", n] => *n,
        _ => return None,
    };
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}

/// The review of #578 (N1): whose view a link of `/proc` opens — the
/// process that reads the name (`self`, `thread-self`), or a process by its
/// pid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Who<'a> {
    Own,
    OwnThread,
    Pid(&'a str),
}

/// The review of #578 (N1): the link a name of a process's view goes
/// through ([`ViewLink`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hop<'a> {
    Root,
    Cwd,
    Exe,
    Fd(&'a str),
    MapFiles(&'a str),
}

/// The review of #578 (N1): the first link of a process's view an absolute
/// name goes through — `/proc/<who>[/task/<tid>]/{root,cwd,exe}`,
/// `fd/<n>`, `map_files/<range>`, and `/dev/fd/<n>`, `/dev/std{in,out,err}`
/// (the reader's own descriptors) — and the rest of the name, read from
/// where it leads. What [`proc_link`] tells the kind of, with the parts the
/// exec pump opens in the process's own view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewLink<'a> {
    pub who: Who<'a>,
    pub task: Option<&'a str>,
    pub hop: Hop<'a>,
    pub rest: Vec<&'a str>,
}

/// [`ViewLink`] of `path` — absolute, `.` and empty segments dropped;
/// `None` with any `..` (the kernel climbs from wherever a link led) or
/// when it starts with no such link.
pub fn view_link(path: &str) -> Option<ViewLink<'_>> {
    if !path.starts_with('/') {
        return None;
    }
    let mut segs = Vec::new();
    for s in path.split('/') {
        match s {
            "" | "." => {}
            ".." => return None,
            s => segs.push(s),
        }
    }
    view_link_of(&segs)
}

fn view_link_of<'a>(segs: &[&'a str]) -> Option<ViewLink<'a>> {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let own_fd = |n: &'a str, rest: &[&'a str]| ViewLink {
        who: Who::Own,
        task: None,
        hop: Hop::Fd(n),
        rest: rest.to_vec(),
    };
    match segs {
        ["dev", "fd", n, rest @ ..] if digits(n) => Some(own_fd(n, rest)),
        ["dev", "stdin"] => Some(own_fd("0", &[])),
        ["dev", "stdout"] => Some(own_fd("1", &[])),
        ["dev", "stderr"] => Some(own_fd("2", &[])),
        ["proc", who, tail @ ..] => {
            let who = match *who {
                "self" => Who::Own,
                "thread-self" => Who::OwnThread,
                n if digits(n) => Who::Pid(n),
                _ => return None,
            };
            let (task, tail) = match tail {
                ["task", t, rest @ ..] if digits(t) && who != Who::OwnThread => (Some(*t), rest),
                _ => (None, tail),
            };
            let (hop, rest): (Hop<'a>, &[&'a str]) = match tail {
                ["root", rest @ ..] => (Hop::Root, rest),
                ["cwd", rest @ ..] => (Hop::Cwd, rest),
                ["exe"] => (Hop::Exe, &[]),
                ["fd", n, rest @ ..] if digits(n) => (Hop::Fd(n), rest),
                ["map_files", m] => (Hop::MapFiles(m), &[]),
                _ => return None,
            };
            Some(ViewLink {
                who,
                task,
                hop,
                rest: rest.to_vec(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 376 (the review of #583, F3): only the two spellings of the
    /// caller's own descriptor name one.
    #[test]
    fn own_descriptor_reads_only_the_two_exact_spellings() {
        assert_eq!(own_descriptor("/proc/self/fd/9"), Some(9));
        assert_eq!(own_descriptor("/dev/fd/12"), Some(12));
        for p in [
            "/proc/thread-self/fd/9",
            "/proc/self/task/1/fd/9",
            "/proc/1/fd/9",
            "/proc/self//fd/9",
            "/proc/self/fd/9/",
            "/proc/self/fd/9/x",
            "/proc/self/fd/",
            "/proc/self/fd/-1",
            "/proc/self/fd/9a",
            "/dev/stdin",
            "proc/self/fd/9",
            "/proc/self/fd/99999999999",
        ] {
            assert_eq!(own_descriptor(p), None, "{p}");
        }
    }

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

    /// The review of #578 (N1, named): the parts of a name through a link of
    /// a process's view, as the exec pump opens it — whose view, the link,
    /// the rest; none with a `..`, a relative name, or no link.
    #[test]
    fn a_view_link_s_parts_are_read_once() {
        let v = |p| view_link(p).map(|v| (v.who, v.task, v.hop, v.rest.join("/")));
        assert_eq!(
            v("/proc/self/root/tmp/x"),
            Some((Who::Own, None, Hop::Root, "tmp/x".into()))
        );
        assert_eq!(
            v("/proc/thread-self/cwd/./x"),
            Some((Who::OwnThread, None, Hop::Cwd, "x".into()))
        );
        assert_eq!(
            v("/proc/42/task/43/root//var/tmp/x"),
            Some((Who::Pid("42"), Some("43"), Hop::Root, "var/tmp/x".into()))
        );
        assert_eq!(
            v("/proc/self/fd/3"),
            Some((Who::Own, None, Hop::Fd("3"), String::new()))
        );
        assert_eq!(
            v("/dev/fd/4/sub"),
            Some((Who::Own, None, Hop::Fd("4"), "sub".into()))
        );
        assert_eq!(
            v("/dev/stdin"),
            Some((Who::Own, None, Hop::Fd("0"), String::new()))
        );
        assert_eq!(
            v("/proc/7/exe"),
            Some((Who::Pid("7"), None, Hop::Exe, String::new()))
        );
        assert_eq!(
            v("/proc/7/map_files/1-2"),
            Some((Who::Pid("7"), None, Hop::MapFiles("1-2"), String::new()))
        );
        for p in [
            "/proc/self/cwd/../x",
            "proc/self/cwd/x",
            "/proc/self/environ",
            "/proc/self/exe/x",
            "/proc/sys/vm/x",
            "/tmp/x",
            "/dev/null",
            "/proc/self/fd/x",
        ] {
            assert_eq!(v(p), None, "{p}");
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
