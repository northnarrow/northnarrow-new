//! The re-check 2 of #567, fix round 3 (the coordinator's decision): the
//! agent holds a descriptor of every link and program it pins.
//!
//! A link stays attached while one reference to it is left: its pin, or a
//! descriptor. The agent kept its deny links by their pins alone, so the
//! bpffs losing its last mount (an unmount of a subtree that takes
//! `/sys/fs/bpf` and every copy of it), or a pin removed or hidden,
//! detached the hook while the agent ran. Now every link and program the
//! agent pins goes through [`pin_link`], [`pin_fd`] or [`pin_prog`]
//! (`reattach_fresh*`, the start-in-cgroup tracker's, the liveness watch's,
//! the sysctl judge's, the module files' write history's), and a descriptor
//! of it is kept here for the process's life: attached while the agent
//! runs, whatever happens to its pin. The pin still carries it across the
//! agent's restart (the descriptors close with the process).
//!
//! The agent's own detach goes through [`crate::purge_stale_pin`], which
//! drops the descriptor held for that pin (or for the pins below that
//! directory) before the unlink: removing a pin still detaches what the
//! agent retires.
//!
//! [`vanished`] tells, for each object held, whether its pin still names
//! it (the inode it was pinned at, in the directory it was pinned in); the
//! integrity round signs a High for each one that does not, and [`repin`]
//! pins it again from the descriptor where its directory is still the one
//! it was pinned in — the next start finds it there.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{anyhow, bail, Context, Result};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::ProgramFd;
use tracing::warn;

/// What a held descriptor is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Link,
    Prog,
}

impl Kind {
    /// Its name in a record.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Link => "link",
            Kind::Prog => "program",
        }
    }

    /// The `/proc/self/fdinfo` field of its id.
    fn field(self) -> &'static str {
        match self {
            Kind::Link => "link_id:",
            Kind::Prog => "prog_id:",
        }
    }
}

/// The most objects held. The agent pins about fifty links and as many
/// programs (its soft `RLIMIT_NOFILE` is raised to the hard limit, at most
/// 65 536, at the start); past this one an object is kept by its pin
/// alone, and that is said.
pub const MAX_HELD: usize = 1024;

/// A device and inode.
pub type Key = (u64, u64);

/// One object held: where it was pinned, what it is, and the descriptor.
struct Held {
    path: PathBuf,
    kind: Kind,
    id: u32,
    /// The pin's inode once pinned, and its directory's.
    pin: Key,
    dir: Key,
    fd: Holder,
}

/// The descriptor: ours (re-pinnable), or — when ours could not be opened
/// from the pin — aya's, which holds the link as well but cannot be pinned
/// again (aya keeps a `PinnedLink`'s descriptor private).
enum Holder {
    Own(OwnedFd),
    Aya(#[allow(dead_code)] PinnedLink),
}

/// The objects held, for the process's life: the one eBPF object's pins
/// (one boot per process).
static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());

fn held() -> MutexGuard<'static, Vec<Held>> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Pin `link` at `path` and hold a descriptor of it: ours, opened from the
/// pin and checked to be the same link — aya's `PinnedLink` handed back (a
/// caller may keep that descriptor too). When ours cannot be opened, aya's
/// is the one held (`None`): attached while the agent runs, not re-pinnable.
pub fn pin_link(link: FdLink, path: &Path) -> Result<Option<PinnedLink>> {
    // an id unread is 0: aya's descriptor is the one held then
    let id = link.info().map(|i| i.id()).unwrap_or(0);
    let pinned = link
        .pin(path)
        .with_context(|| format!("pinning link {id} to {}", path.display()))?;
    match obj_get(path).and_then(|fd| {
        if id == 0 {
            bail!("the link's id unread");
        }
        same(fd, Kind::Link, id)
    }) {
        Ok(fd) => {
            keep(path, Kind::Link, id, Holder::Own(fd));
            Ok(Some(pinned))
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = format!("{e:#}"),
                "anti-tamper: the link's descriptor held is aya's (ours not opened from its pin): \
                 attached while the agent runs, not re-pinnable"
            );
            keep(path, Kind::Link, id, Holder::Aya(pinned));
            Ok(None)
        }
    }
}

/// Pin the link or program behind `fd` at `path` (`BPF_OBJ_PIN`) and hold
/// a copy of the descriptor.
pub fn pin_fd(kind: Kind, fd: BorrowedFd<'_>, path: &Path) -> Result<()> {
    obj_pin(fd, path)
        .with_context(|| format!("pinning a {} to {}", kind.name(), path.display()))?;
    // the pin made, holding is the second reference: a failure is said, the
    // object kept by its pin alone (as before)
    match fd
        .try_clone_to_owned()
        .map_err(anyhow::Error::from)
        .and_then(|own| Ok((id_of(own.as_fd(), kind)?, own)))
    {
        Ok((id, own)) => keep(path, kind, id, Holder::Own(own)),
        Err(e) => warn!(
            path = %path.display(),
            error = format!("{e:#}"),
            "anti-tamper: a pinned {} not held: kept by its pin alone",
            kind.name()
        ),
    }
    Ok(())
}

/// [`pin_fd`] for a program.
pub fn pin_prog(prog: &ProgramFd, path: &Path) -> Result<()> {
    pin_fd(Kind::Prog, prog.as_fd(), path)
}

/// Record a pinned object held: its pin's inode and its directory's.
fn keep(path: &Path, kind: Kind, id: u32, fd: Holder) {
    let (Ok(pin), Ok(dir)) = (
        key(path),
        key(path.parent().unwrap_or_else(|| Path::new("/"))),
    ) else {
        warn!(path = %path.display(), "anti-tamper: a pin unreadable just after pinning: not held");
        return;
    };
    let mut h = held();
    // the same path pinned again (an earlier object's pin was replaced
    // without the purge): the earlier one is no longer this pin's
    h.retain(|e| e.path != path);
    if h.len() >= MAX_HELD {
        warn!(
            path = %path.display(),
            max = MAX_HELD,
            "anti-tamper: too many objects held: this one is kept by its pin alone"
        );
        return;
    }
    h.push(Held {
        path: path.to_path_buf(),
        kind,
        id,
        pin,
        dir,
        fd,
    });
}

/// Drop the descriptors held for `path`, or for every pin below it when it
/// is a directory: the agent detaches them itself
/// ([`crate::purge_stale_pin`]). The number dropped.
pub fn release(path: &Path) -> usize {
    let mut h = held();
    let before = h.len();
    h.retain(|e| !e.path.starts_with(path));
    before - h.len()
}

/// The objects held now: their pin, kind and id.
pub fn held_now() -> Vec<(PathBuf, Kind, u32)> {
    held()
        .iter()
        .map(|e| (e.path.clone(), e.kind, e.id))
        .collect()
}

/// Why an object held no longer has its pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lost {
    /// Nothing at its path, its directory the one it was pinned in: a pin
    /// removed. It can be pinned again.
    Removed,
    /// Nothing at its path, and its directory gone or another one: the
    /// bpffs lost its mount, or one was laid over the directory.
    DirectoryGone,
    /// Another inode at its path (a pin replaced, or a mount over it).
    Replaced,
    /// Its path unreadable (the error).
    Unreadable(String),
}

impl Lost {
    /// Its words in a record.
    pub fn words(&self) -> String {
        match self {
            Lost::Removed => "its pin is gone".to_string(),
            Lost::DirectoryGone => {
                "its pin is gone with its directory (the bpffs unmounted, or a mount over it)"
                    .to_string()
            }
            Lost::Replaced => "its pin names another object".to_string(),
            Lost::Unreadable(e) => format!("its pin is unreadable ({e})"),
        }
    }
}

/// An object held whose pin no longer names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vanished {
    pub path: PathBuf,
    pub kind: Kind,
    pub id: u32,
    pub lost: Lost,
}

/// The objects held whose pin no longer names them.
pub fn vanished() -> Vec<Vanished> {
    let h = held();
    judge(
        h.iter()
            .map(|e| (e.path.as_path(), e.kind, e.id, e.pin, e.dir)),
        key,
    )
}

/// [`vanished`] over `entries` (`(path, kind, id, pin, dir)`), the inode of
/// a path read by `stat`.
pub fn judge<'a>(
    entries: impl Iterator<Item = (&'a Path, Kind, u32, Key, Key)>,
    stat: impl Fn(&Path) -> io::Result<Key>,
) -> Vec<Vanished> {
    let mut out = Vec::new();
    for (path, kind, id, pin, dir) in entries {
        let lost = match stat(path) {
            Ok(k) if k == pin => continue,
            Ok(_) => Lost::Replaced,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match stat(path.parent().unwrap_or_else(|| Path::new("/"))) {
                    Ok(d) if d == dir => Lost::Removed,
                    _ => Lost::DirectoryGone,
                }
            }
            Err(e) => Lost::Unreadable(e.kind().to_string()),
        };
        out.push(Vanished {
            path: path.to_path_buf(),
            kind,
            id,
            lost,
        });
    }
    out
}

/// Pin `v` again from its descriptor: only a [`Lost::Removed`] one, its
/// directory still the one it was pinned in (never into a directory laid
/// over it, nor a new bpffs). The pin's new inode is recorded.
pub fn repin(v: &Vanished) -> Result<()> {
    if v.lost != Lost::Removed {
        bail!("not pinned again: {}", v.lost.words());
    }
    let mut h = held();
    let Some(e) = h.iter_mut().find(|e| e.path == v.path && e.id == v.id) else {
        bail!("not pinned again: no longer held");
    };
    let Holder::Own(fd) = &e.fd else {
        bail!("not pinned again: its descriptor is aya's (not re-pinnable)");
    };
    let dir = key(e.path.parent().unwrap_or_else(|| Path::new("/")))
        .context("not pinned again: its directory unreadable")?;
    if dir != e.dir {
        bail!("not pinned again: its directory is another one now");
    }
    obj_pin(fd.as_fd(), &e.path).context("not pinned again: BPF_OBJ_PIN")?;
    e.pin = key(&e.path).context("pinned again, the new pin unreadable")?;
    Ok(())
}

/// The device and inode at `path`, a symbolic link not followed.
fn key(path: &Path) -> io::Result<Key> {
    crate::kernel_roots::symlink_metadata(path).map(|m| (m.dev(), m.ino()))
}

/// `fd` when it holds the `kind` object `id`.
fn same(fd: OwnedFd, kind: Kind, id: u32) -> Result<OwnedFd> {
    let got = id_of(fd.as_fd(), kind)?;
    if got != id {
        bail!("the pin names {} {got}, not {id}", kind.name());
    }
    Ok(fd)
}

/// The id of the `kind` object `fd` holds, from `/proc/self/fdinfo`.
fn id_of(fd: BorrowedFd<'_>, kind: Kind) -> Result<u32> {
    let text = crate::kernel_roots::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
        .context("reading its fdinfo")?;
    parse_id(&text, kind).ok_or_else(|| anyhow!("its fdinfo names no {}", kind.field()))
}

/// The `kind` id in an fdinfo text: `link_id` for a link, `prog_id` for a
/// program (a link prints its program's id too: a program's id is read only
/// from a text that names no link).
pub fn parse_id(text: &str, kind: Kind) -> Option<u32> {
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().parse::<u32>().ok())
    };
    match kind {
        Kind::Link => field("link_id:"),
        Kind::Prog if field("link_id:").is_some() => None,
        Kind::Prog => field("prog_id:"),
    }
}

/// `union bpf_attr` for `BPF_OBJ_PIN` and `BPF_OBJ_GET` (a shorter size
/// than the union is accepted: the rest is zero).
#[repr(C)]
struct ObjAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
}

fn sys_obj(cmd: u32, path: &Path, fd: u32) -> io::Result<i64> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let attr = ObjAttr {
        pathname: c.as_ptr() as u64,
        bpf_fd: fd,
        file_flags: 0,
    };
    // SAFETY: a plain syscall with a valid, fully initialised attr of its
    // exact size; `c` outlives the call.
    let r = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            &attr as *const ObjAttr as *const libc::c_void,
            std::mem::size_of::<ObjAttr>() as u32,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r)
}

/// `BPF_OBJ_PIN` of `fd` at `path`.
fn obj_pin(fd: BorrowedFd<'_>, path: &Path) -> io::Result<()> {
    sys_obj(common::bpf_cmd::BPF_OBJ_PIN, path, fd.as_raw_fd() as u32).map(drop)
}

/// `BPF_OBJ_GET` of the pin at `path`, the descriptor owned.
fn obj_get(path: &Path) -> Result<OwnedFd> {
    let fd = sys_obj(common::bpf_cmd::BPF_OBJ_GET, path, 0)
        .with_context(|| format!("BPF_OBJ_GET of {}", path.display()))?;
    // SAFETY: a fresh descriptor the kernel returned, owned here only.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn stat_of(m: HashMap<&'static str, Key>) -> impl Fn(&Path) -> io::Result<Key> {
        move |p: &Path| {
            m.get(p.to_str().unwrap())
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    const D: &str = "/sys/fs/bpf/northnarrow";
    const L: &str = "/sys/fs/bpf/northnarrow/link_task_kill";
    const P: &str = "/sys/fs/bpf/northnarrow/prog_task_kill";

    fn entries() -> Vec<(&'static Path, Kind, u32, Key, Key)> {
        vec![
            (Path::new(L), Kind::Link, 7, (40, 11), (40, 2)),
            (Path::new(P), Kind::Prog, 31, (40, 12), (40, 2)),
        ]
    }

    /// Named test (fix round 3 of #567): a pin as pinned is no finding.
    #[test]
    fn pins_as_pinned_are_not_vanished() {
        let s = stat_of(HashMap::from([(D, (40, 2)), (L, (40, 11)), (P, (40, 12))]));
        assert!(judge(entries().into_iter(), s).is_empty());
    }

    /// Named test: a pin removed (`rm` of `link_task_kill`) while the agent
    /// holds the link is told, re-pinnable; the other untouched.
    #[test]
    fn a_removed_pin_is_vanished_and_repinnable() {
        let s = stat_of(HashMap::from([(D, (40, 2)), (P, (40, 12))]));
        let v = judge(entries().into_iter(), s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].path, Path::new(L));
        assert_eq!((v[0].kind, v[0].id), (Kind::Link, 7));
        assert_eq!(v[0].lost, Lost::Removed);
    }

    /// Named test: the bpffs unmounted (nothing at the directory), or a new
    /// bpffs or a tmpfs over it (another inode at the directory): every pin
    /// gone with its directory — never re-pinned there.
    #[test]
    fn a_lost_directory_is_never_repinned_into() {
        for s in [
            stat_of(HashMap::new()),
            stat_of(HashMap::from([(D, (41, 2))])),
        ] {
            let v = judge(entries().into_iter(), s);
            assert_eq!(v.len(), 2);
            assert!(v.iter().all(|x| x.lost == Lost::DirectoryGone));
            for x in &v {
                let e = repin(x).unwrap_err().to_string();
                assert!(e.contains("not pinned again"), "{e}");
            }
        }
    }

    /// Named test: another inode at the pin's path (a pin replaced, or a
    /// file bound over it) is told as such.
    #[test]
    fn a_replaced_pin_is_vanished() {
        let s = stat_of(HashMap::from([(D, (40, 2)), (L, (40, 99)), (P, (40, 12))]));
        let v = judge(entries().into_iter(), s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].lost, Lost::Replaced);
        let e = repin(&v[0]).unwrap_err().to_string();
        assert!(e.contains("its pin names another object"), "{e}");
    }

    /// Named test: an unreadable pin is told with its error, not taken for
    /// one in place.
    #[test]
    fn an_unreadable_pin_is_vanished() {
        let s = |p: &Path| {
            if p == Path::new(L) {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else if p == Path::new(P) {
                Ok((40, 12))
            } else {
                Ok((40, 2))
            }
        };
        let v = judge(entries().into_iter(), s);
        assert_eq!(v.len(), 1);
        assert!(matches!(&v[0].lost, Lost::Unreadable(e) if e.contains("permission")));
    }

    /// Named test: the ids read from fdinfo — a link's own id (never its
    /// program's), a program's only from a text that names no link.
    #[test]
    fn fdinfo_ids_by_kind() {
        let link = "pos:\t0\nflags:\t02000000\nmnt_id:\t15\nino:\t1057\nlink_type:\ttracing\n\
                    link_id:\t7\nprog_tag:\tabc\nprog_id:\t31\nattach_type:\t27\n";
        let prog = "pos:\t0\nflags:\t02000002\nprog_type:\t29\nprog_jited:\t1\n\
                    prog_tag:\tabc\nmemlock:\t4096\nprog_id:\t31\n";
        assert_eq!(parse_id(link, Kind::Link), Some(7));
        assert_eq!(parse_id(link, Kind::Prog), None);
        assert_eq!(parse_id(prog, Kind::Prog), Some(31));
        assert_eq!(parse_id(prog, Kind::Link), None);
        assert_eq!(parse_id("pos:\t0\n", Kind::Prog), None);
    }

    /// The attr is the kernel's head of `union bpf_attr` for `BPF_OBJ_*`.
    #[test]
    fn obj_attr_is_the_kernels_head() {
        assert_eq!(std::mem::size_of::<ObjAttr>(), 16);
        assert_eq!(common::bpf_cmd::BPF_OBJ_PIN, 6);
        assert_eq!(common::bpf_cmd::BPF_OBJ_GET, 7);
    }

    /// Named test: a pin held again at the same path replaces the earlier
    /// entry (the earlier object is no longer that pin's); a removed pin is
    /// never pinned into a directory that is another one now.
    #[test]
    fn keep_replaces_the_same_path_and_repin_checks_the_directory() {
        let d = std::env::temp_dir().join(format!("nn-held-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let pin = d.join("link_x");
        std::fs::write(&pin, b"").unwrap();
        let null = || Holder::Own(std::fs::File::open("/dev/null").unwrap().into());
        keep(&pin, Kind::Link, 5, null());
        keep(&pin, Kind::Link, 6, null());
        let mine: Vec<u32> = held_now()
            .into_iter()
            .filter(|(p, ..)| *p == pin)
            .map(|(_, _, id)| id)
            .collect();
        assert_eq!(mine, vec![6]);
        {
            let mut h = held();
            let e = h.iter_mut().find(|e| e.path == pin).unwrap();
            e.dir = (0, 0);
        }
        std::fs::remove_file(&pin).unwrap();
        let v = Vanished {
            path: pin.clone(),
            kind: Kind::Link,
            id: 6,
            lost: Lost::Removed,
        };
        let e = repin(&v).unwrap_err().to_string();
        assert!(e.contains("its directory is another one now"), "{e}");
        assert!(!pin.exists());
        assert_eq!(release(&d), 1);
        let _ = std::fs::remove_dir(&d);
    }

    /// Named test: the agent's own purge drops the descriptors it holds for
    /// that pin, or below that directory — never a neighbour's (a held
    /// descriptor would keep a link the agent retires attached).
    #[test]
    fn release_drops_the_pin_and_those_below_only() {
        let fd = || Holder::Own(std::fs::File::open("/dev/null").unwrap().into());
        let base = Path::new("/nn-test-held");
        {
            let mut h = held();
            for (p, id) in [
                ("link_a", 1u32),
                ("prog_a", 2),
                ("sub/link_b", 3),
                ("link_ab", 4),
            ] {
                h.push(Held {
                    path: base.join(p),
                    kind: Kind::Link,
                    id,
                    pin: (0, id as u64),
                    dir: (0, 0),
                    fd: fd(),
                });
            }
        }
        let ours = |h: &[Held]| -> Vec<u32> {
            h.iter()
                .filter(|e| e.path.starts_with(base))
                .map(|e| e.id)
                .collect()
        };
        assert_eq!(release(&base.join("link_a")), 1);
        assert_eq!(ours(&held()), vec![2, 3, 4]);
        assert_eq!(release(&base.join("sub")), 1);
        assert_eq!(ours(&held()), vec![2, 4]);
        assert_eq!(release(&base.join("missing")), 0);
        assert_eq!(release(base), 2);
        assert!(ours(&held()).is_empty());
    }
}
