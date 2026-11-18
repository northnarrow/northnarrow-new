//! The review of #578 (lot 370's fix round 1): what the exec pump reads of
//! an exec of the dynamic loader while its process runs — for the staging
//! rules, which judge the program the loader runs as a direct exec of it
//! (`nn_core::decision::rules::loader_code`).
//!
//! - **N1, a file through a link of `/proc`.** `ld.so /proc/self/root/tmp/x`
//!   names `/tmp/x` only through the process's view: as text it is absolute,
//!   under no staging directory and no descriptor, and no rule judged it.
//!   Each such file the loader was given (`/proc/self/root/…`,
//!   `/proc/<pid>/cwd/…`, `/proc/thread-self/…`, `/proc/self/fd/N`,
//!   `/dev/fd/N`, `/dev/stdin` and their kin) is placed by the kernel's
//!   identity of the file the loader maps: its link opened in the process's
//!   own view — the kernel follows the link itself, the rest walked one name
//!   at a time, no symbolic link followed, every file system on the way
//!   judged ([`super::pump_reads`]) — and the file it reaches found among
//!   the files the process maps executable (`/proc/<pid>/maps`: the loader
//!   mapped it). Only for a process that shares PID 1's mount namespace and
//!   root (its `/proc` and `/dev/fd` are the host's), and only while it is
//!   the exec's process, still running the loader. A file not placed —
//!   another view, the process gone or not mapped yet, a link on the way —
//!   is judged by its text: a descriptor's link fileless (R004), any other
//!   name not placed (R001 records it).
//! - **P3, the loader that only lists.** Its environment read whole while
//!   the exec's process still ran (its start the exec's, its memory there
//!   after the read): `LD_TRACE_LOADED_OBJECTS` set — `ldd`'s trace mode —
//!   is [`exe_flags::LOADER_LISTS`]. Not read: not set.
//!
//! The loader maps its program a moment after the exec: a read that finds
//! it not mapped yet is made again, every 500 µs up to 5 ms, within 50 ms
//! of such waits a second for the whole host (past them: read once, not
//! placed, recorded).
//!
//! Residual, said: a process may change its own view (its directory, a
//! descriptor), what it maps and its environment in the moment before the
//! pump reads it; the file is then placed, and the trace mode read, by what
//! the read finds; a file the loader reaches through a symbolic link of the
//! process's view is not placed.

use std::collections::HashSet;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use antitamper_bpf::kernel_roots;
use common::wire::exe::exe_flags;
use nn_core::decision::rules::{self, program_identity};
use nn_model::Event;
use parking_lot::Mutex;

use super::pump_reads::Judge;

/// The most of a process's `maps` read (a loader's process maps a few
/// dozen files).
const MAX_MAPS: u64 = 1 << 20;

/// How many `/proc/<x>/root/` hops one name is read through at most.
const ROOT_HOPS: u8 = 8;

/// The wait between two reads of a loader's mappings (its program not
/// mapped yet), and how many reads more at most: 5 ms an exec.
const MAP_WAIT: Duration = Duration::from_micros(500);
const MAP_TRIES: u32 = 10;

/// The waits all loaders' reads may spend in a second, together: a flood of
/// loaders that never map their program slows the exec pump by this at
/// most; past it they are read once (not placed: recorded).
const MAP_WAITS_PER_SECOND: Duration = Duration::from_millis(50);

/// The second's waits spent ([`MAP_WAITS_PER_SECOND`]).
static MAP_WAITS: WaitBudget = WaitBudget::new();

/// A budget of waits a second.
struct WaitBudget(Mutex<Option<(Instant, Duration)>>);

impl WaitBudget {
    const fn new() -> Self {
        WaitBudget(Mutex::new(None))
    }

    /// `wait` taken from the second running at `now`, if it is left.
    fn take(&self, wait: Duration, now: Instant) -> bool {
        let mut s = self.0.lock();
        let (start, spent) = match *s {
            Some((t, n)) if now.duration_since(t) < Duration::from_secs(1) => (t, n),
            _ => (now, Duration::ZERO),
        };
        if spent + wait > MAP_WAITS_PER_SECOND {
            *s = Some((start, spent));
            return false;
        }
        *s = Some((start, spent + wait));
        true
    }
}

/// The exec pump's step: `event`'s process read under `proc_root`
/// (`/proc`) when it runs the dynamic loader — on the exec pumps' reader.
pub fn read_under(proc_root: &Path, event: &mut Event) {
    read_judged(proc_root, event, &Judge::host(), &|dir| {
        host_view(proc_root, dir)
    });
}

/// The process `dir` (`/proc/<pid>`) shares PID 1's mount namespace and
/// root: its `/proc` and `/dev/fd` are the host's.
fn host_view(proc_root: &Path, dir: &Path) -> bool {
    super::exec_facts::same_mount_namespace(proc_root, dir)
        && super::exec_facts::same_root(proc_root, dir)
}

/// [`read_under`], the file systems judged by `judge`, the process's view
/// told by `host_view` (tests).
fn read_judged(
    proc_root: &Path,
    event: &mut Event,
    judge: &Judge,
    host_view: &dyn Fn(&Path) -> bool,
) {
    if program_identity::loader_operand_at(event).is_none() {
        return;
    }
    let Event::ProcessSpawn {
        pid, start_ns, exe, ..
    } = &*event
    else {
        return;
    };
    let (pid, start_ns) = (*pid, *start_ns);
    let known = exe.has(exe_flags::KNOWN).then_some((exe.dev, exe.ino));
    let dir = proc_root.join(pid.to_string());
    // P3: ldd's trace mode, from the environment read whole
    if super::exec_facts::environ_has(&dir, start_ns, "LD_TRACE_LOADED_OBJECTS") == Some(true) {
        if let Event::ProcessSpawn { exe, .. } = event {
            exe.flags |= exe_flags::LOADER_LISTS;
        }
    }
    // N1: the files given through a link of /proc
    let texts: Vec<String> = rules::loader_code(event, false)
        .into_iter()
        .map(|(t, _)| t)
        .filter(|t| rules::through_proc_link(t))
        .map(str::to_string)
        .collect();
    if texts.is_empty() || !host_view(&dir) {
        return;
    }
    let placed: Vec<(String, Placed)> = texts
        .into_iter()
        .filter_map(|text| place(proc_root, pid, &text, judge).ok().map(|p| (text, p)))
        .collect();
    if placed.is_empty() {
        return;
    }
    // the loader maps its program a moment after the exec: a read before
    // that finds it not mapped yet — read again, a few times, within a
    // budget the whole host shares (past it: not placed, recorded)
    let wanted: Vec<(u64, u64)> = placed.iter().map(|(_, p)| (p.dev, p.ino)).collect();
    let Some(mapped) = read_until_mapped(|| executable_mappings(&dir), &wanted, &MAP_WAITS) else {
        return;
    };
    let files: Vec<program_identity::LoaderFile> = placed
        .into_iter()
        .filter(|(_, p)| mapped.contains(&(p.dev, p.ino)))
        .map(|(text, p)| program_identity::LoaderFile {
            text,
            path: p.path,
            memfd: p.memfd,
            deleted: p.deleted,
        })
        .collect();
    // after the reads: still the exec's process, still running the loader
    if !still_the_exec(&dir, start_ns, known) {
        return;
    }
    program_identity::keep_loader_files(event, files);
}

/// The process's executable mappings (`read`) once every `wanted` file is
/// among them — read again every [`MAP_WAIT`], at most [`MAP_TRIES`] times
/// more, each wait taken from `budget` — or the last read; `None` when a
/// read fails (the process gone).
fn read_until_mapped(
    mut read: impl FnMut() -> Option<HashSet<(u64, u64)>>,
    wanted: &[(u64, u64)],
    budget: &WaitBudget,
) -> Option<HashSet<(u64, u64)>> {
    let mut tries = 0;
    loop {
        let mapped = read()?;
        if wanted.iter().all(|w| mapped.contains(w))
            || tries >= MAP_TRIES
            || !budget.take(MAP_WAIT, Instant::now())
        {
            return Some(mapped);
        }
        tries += 1;
        std::thread::sleep(MAP_WAIT);
    }
}

/// The process `dir` is the exec's — started at `start_ns`, its memory
/// there — and runs the image the exec ran (`known`, the LSM hook's
/// identity, when it gave one).
fn still_the_exec(dir: &Path, start_ns: u64, known: Option<(u64, u64)>) -> bool {
    use crate::response::proc_ref::{started_at, stat_start_ticks};
    if start_ns == 0 {
        return false;
    }
    let Ok(stat) = crate::state_read::read_state(dir.join("stat")) else {
        return false;
    };
    let started = stat_start_ticks(&stat).is_some_and(|t| started_at(t, start_ns));
    let image = known.is_none_or(|id| {
        kernel_roots::link_target(&dir.join("exe")).is_ok_and(|(_, c)| (c.dev, c.ino) == id)
    });
    started && super::kmod_exec::has_memory(&stat) && image
}

/// A file placed by its link ([`place`]).
#[derive(Debug, PartialEq, Eq)]
struct Placed {
    /// Device (the kernel's encoding) and inode.
    dev: u64,
    ino: u64,
    /// The kernel's name of it, ` (deleted)` dropped.
    path: String,
    memfd: bool,
    deleted: bool,
}

/// The file `text` names for the process `pid` (a name through a link of
/// `/proc`, in that process's view): the link opened — the kernel follows
/// it — and the rest walked from where it leads, one name at a time, no
/// symbolic link followed, each file system judged; a regular file only.
fn place(proc_root: &Path, pid: u32, text: &str, judge: &Judge) -> io::Result<Placed> {
    let (link, rest) = base(proc_root, pid, text, 0)?;
    let judge = judge.of_process(&proc_root.join(pid.to_string()));
    let (f, c) = kernel_roots::link_target(&link)?;
    // a memfd is the kernel's own memory, on a mount no table shows: no
    // file system's daemon to ask (its link's text is procfs's)
    let memfd = rest.as_os_str().is_empty()
        && kernel_roots::read_link(&link).is_ok_and(|l| l.to_string_lossy().starts_with("/memfd:"));
    if !memfd && !judge.trusts(&c) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "on a file system the agent does not ask: not placed",
        ));
    }
    let (file, c) = if rest.as_os_str().is_empty() {
        (f, c)
    } else {
        if !c.is_dir() {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        let w = kernel_roots::walk_judged(&f, &link, &rest, false, &mut |c| judge.trusts(c))?;
        (w.file, w.cached)
    };
    if !c.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    let named = kernel_roots::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    let named = named.to_string_lossy();
    let deleted = c.nlink == 0;
    let path = match named.strip_suffix(" (deleted)") {
        Some(p) if deleted => p,
        _ => &named,
    };
    Ok(Placed {
        dev: c.dev,
        ino: c.ino,
        memfd: path.starts_with("/memfd:"),
        path: path.to_string(),
        deleted,
    })
}

/// `text`'s segments, `.` and empty ones dropped; `None` with a `..` (the
/// kernel climbs from wherever a link led) or a relative name (the loader's
/// directory is a link of its own: not a name the pump places).
fn folded(text: &str) -> Option<Vec<&str>> {
    if !text.starts_with('/') {
        return None;
    }
    let mut segs = Vec::new();
    for s in text.split('/') {
        match s {
            "" | "." => {}
            ".." => return None,
            s => segs.push(s),
        }
    }
    Some(segs)
}

/// The link a name starts from, under `proc_root`, and the rest of the name
/// read from where it leads ([`rules::view_link`], the one reading of such
/// a name): `self` and `thread-self` are the exec's process; a `root/`
/// whose process has PID 1's root is read again from there
/// (`/proc/self/root/proc/self/fd/3`); any other name from the process's
/// root.
fn base(proc_root: &Path, pid: u32, text: &str, hops: u8) -> io::Result<(PathBuf, PathBuf)> {
    use rules::{Hop, Who};
    let own = proc_root.join(pid.to_string());
    let Some(v) = rules::view_link(text) else {
        let segs = folded(text).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        return Ok((own.join("root"), segs.iter().collect()));
    };
    let dir = match v.who {
        Who::Own => own,
        Who::OwnThread => own.join("task").join(pid.to_string()),
        Who::Pid(n) => proc_root.join(n),
    };
    let dir = match v.task {
        Some(t) => dir.join("task").join(t),
        None => dir,
    };
    let rest: PathBuf = v.rest.iter().collect();
    Ok(match v.hop {
        Hop::Root => {
            let again = format!("/{}", v.rest.join("/"));
            if hops < ROOT_HOPS
                && rules::view_link(&again).is_some()
                && super::exec_facts::same_root(proc_root, &dir)
            {
                return base(proc_root, pid, &again, hops + 1);
            }
            (dir.join("root"), rest)
        }
        Hop::Cwd => (dir.join("cwd"), rest),
        Hop::Exe => (dir.join("exe"), PathBuf::new()),
        Hop::Fd(n) => (dir.join("fd").join(n), rest),
        Hop::MapFiles(m) => (dir.join("map_files").join(m), PathBuf::new()),
    })
}

/// The files the process `dir` maps executable — device (the kernel's
/// encoding) and inode — from its `maps`; `None` when it cannot be read.
fn executable_mappings(dir: &Path) -> Option<HashSet<(u64, u64)>> {
    use std::io::Read;
    let mut text = Vec::new();
    kernel_roots::open(dir.join("maps"), libc::O_RDONLY)
        .and_then(|f| f.take(MAX_MAPS).read_to_end(&mut text))
        .ok()?;
    Some(
        String::from_utf8_lossy(&text)
            .lines()
            .filter_map(executable_mapping)
            .collect(),
    )
}

/// One line of `maps` — `start-end perms offset major:minor inode path` —
/// when it maps a file executable: its device (major and minor in hex, as
/// the kernel prints them) in the kernel's encoding, and its inode.
fn executable_mapping(line: &str) -> Option<(u64, u64)> {
    let mut f = line.split_ascii_whitespace();
    let (_range, perms, _offset, dev, ino) =
        (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
    if !perms.contains('x') {
        return None;
    }
    let ino: u64 = ino.parse().ok().filter(|i| *i != 0)?;
    let (major, minor) = dev.split_once(':')?;
    let (major, minor) = (
        u64::from_str_radix(major, 16).ok()?,
        u64::from_str_radix(minor, 16).ok()?,
    );
    Some(((major << 20) | minor, ino))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::process::{Child, Command, Stdio};

    /// A `sleep` child in `cwd`, `stdin` its standard input.
    fn sleeper(cwd: &Path, stdin: Stdio) -> Child {
        Command::new("sleep")
            .arg("30")
            .current_dir(cwd)
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    /// A judge of this process's own mounts, read now (the host's tables
    /// change under the tests running beside).
    fn judge() -> Judge {
        Judge::of(&crate::mountinfo::read(Path::new("/proc/self/mountinfo")).unwrap())
    }

    fn id_of(p: &Path) -> (u64, u64) {
        let m = std::fs::metadata(p).unwrap();
        (common::wire::exe::kernel_dev(m.dev()), m.ino())
    }

    /// The review of #578 (N1, named): the files a loader is given through
    /// a link of `/proc` are placed in its process's own view — its
    /// directory, its root (numeric or `self`, `thread-self`, a `root/`
    /// read again), a descriptor (`/proc/self/fd/0`, `/dev/stdin`), a
    /// memfd — by the kernel's identity of the file; a `..`, a relative
    /// name or a symbolic link on the way are not placed.
    #[test]
    fn a_file_through_a_link_of_proc_is_placed_in_the_process_s_view() {
        let t = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(t.path()).unwrap();
        std::fs::write(dir.join("x"), b"\x7fELF payload").unwrap();
        std::os::unix::fs::symlink(dir.join("x"), dir.join("link")).unwrap();
        let x = dir.join("x");
        let mut child = sleeper(&dir, Stdio::from(std::fs::File::open(&x).unwrap()));
        let pid = child.id();
        let proc_root = Path::new("/proc");
        let judge = judge();
        let want = Placed {
            dev: id_of(&x).0,
            ino: id_of(&x).1,
            path: x.to_string_lossy().into_owned(),
            memfd: false,
            deleted: false,
        };
        let d = dir.to_string_lossy();
        for text in [
            "/proc/self/cwd/x".to_string(),
            format!("/proc/{pid}/cwd/x"),
            "/proc/thread-self/cwd/./x".to_string(),
            format!("/proc/self/root{d}/x"),
            format!("/proc/{pid}/task/{pid}/root{d}//x"),
            "/proc/self/fd/0".to_string(),
            "/dev/stdin".to_string(),
            "/dev/fd/0".to_string(),
        ] {
            assert_eq!(
                place(proc_root, pid, &text, &judge).as_ref().ok(),
                Some(&want),
                "{text}"
            );
        }
        for text in [
            "/proc/self/cwd/../x".to_string(),
            "x".to_string(),
            "/proc/self/cwd/link".to_string(),
            "/proc/self/environ".to_string(),
            "/proc/self/cwd".to_string(),
        ] {
            assert!(place(proc_root, pid, &text, &judge).is_err(), "{text}");
        }
        let _ = child.kill();
        let _ = child.wait();
        // a memfd on its standard input: fileless, by the kernel's name
        // SAFETY: a NUL-terminated name, no flags.
        let fd = unsafe { libc::memfd_create(c"nn-k370".as_ptr(), 0) };
        assert!(fd >= 0);
        // SAFETY: a fresh descriptor this test owns.
        let memfd = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
        let mut child = sleeper(&dir, Stdio::from(memfd));
        let p = place(proc_root, child.id(), "/proc/self/fd/0", &judge).expect("placed");
        assert!(p.memfd && p.path.starts_with("/memfd:nn-k370"), "{p:?}");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The review of #578 (N1, named): a file is the one the loader maps
    /// only when the process maps it executable — the process's own image
    /// is among its mappings, a file it only holds open is not.
    #[test]
    fn the_files_a_process_maps_executable_are_read_from_its_maps() {
        let t = tempfile::tempdir().unwrap();
        let held = t.path().join("held");
        std::fs::write(&held, b"data").unwrap();
        let mut child = sleeper(t.path(), Stdio::from(std::fs::File::open(&held).unwrap()));
        let dir = Path::new("/proc").join(child.id().to_string());
        let image = std::fs::canonicalize(dir.join("exe")).unwrap();
        // a moment for the exec to finish (the child maps its image)
        let mut mapped = None;
        for _ in 0..50 {
            mapped = executable_mappings(&dir);
            if mapped.as_ref().is_some_and(|m| m.contains(&id_of(&image))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mapped = mapped.expect("maps read");
        assert!(mapped.contains(&id_of(&image)), "{image:?} not mapped");
        assert!(!mapped.contains(&id_of(&held)));
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            executable_mapping("7f0000000000-7f0000001000 r-xp 00000000 fd:01 1234 /tmp/x"),
            Some(((0xfd << 20) | 1, 1234))
        );
        assert_eq!(
            executable_mapping("7f0000000000-7f0000001000 rw-p 00000000 fd:01 1234 /tmp/x"),
            None
        );
        assert_eq!(
            executable_mapping("7ffd0000-7ffd1000 r-xp 00000000 00:00 0 [vdso]"),
            None
        );
    }

    /// The review of #578 (N1, named): the pump's step on an exec of the
    /// loader — the files given through a link of `/proc` kept as placed
    /// when the process maps them (here the child's own image, named
    /// through its root), not when it only holds them open, and never for a
    /// process not in the host's view.
    #[test]
    fn the_pump_places_a_loader_s_files_the_process_maps() {
        let t = tempfile::tempdir().unwrap();
        let held = t.path().join("held");
        std::fs::write(&held, b"data").unwrap();
        let mut child = sleeper(t.path(), Stdio::from(std::fs::File::open(&held).unwrap()));
        let pid = child.id();
        let proc_root = Path::new("/proc");
        let dir = proc_root.join(pid.to_string());
        let image = std::fs::canonicalize(dir.join("exe")).unwrap();
        for _ in 0..50 {
            if executable_mappings(&dir).is_some_and(|m| m.contains(&id_of(&image))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let stat = crate::state_read::read_state(dir.join("stat")).unwrap();
        let ticks = crate::response::proc_ref::stat_start_ticks(&stat).unwrap();
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let start_ns = ticks * (1_000_000_000 / hz);
        let through_root = format!("/proc/self/root{}", image.to_string_lossy());
        // a library it preloads through a descriptor: held open, never mapped
        let mut e = rules::testutil::via_loader(&[
            "/lib64/ld-linux-x86-64.so.2",
            "--preload",
            "/proc/self/fd/0",
            &through_root,
        ]);
        if let Event::ProcessSpawn {
            pid: p,
            start_ns: s,
            timestamp_ns,
            exe,
            ..
        } = &mut e
        {
            (*p, *s, *timestamp_ns) = (pid, start_ns, 578_001);
            // the child runs its image, as the loader's process runs the loader
            (exe.dev, exe.ino) = id_of(&image);
        }
        read_judged(proc_root, &mut e, &judge(), &|_| true);
        let placed = program_identity::loader_file(&e, &through_root).expect("placed");
        assert_eq!(placed.path, image.to_string_lossy());
        assert!(!placed.memfd && !placed.deleted);
        // held open, not mapped: not the file the loader maps
        assert_eq!(program_identity::loader_file(&e, "/proc/self/fd/0"), None);
        // another view: nothing placed
        let mut other = e.clone();
        if let Event::ProcessSpawn { timestamp_ns, .. } = &mut other {
            *timestamp_ns = 578_002;
        }
        read_judged(proc_root, &mut other, &judge(), &|_| false);
        assert_eq!(program_identity::loader_file(&other, &through_root), None);
        // not the exec's process any more (another start): nothing kept
        let mut later = e.clone();
        if let Event::ProcessSpawn {
            timestamp_ns,
            start_ns,
            ..
        } = &mut later
        {
            (*timestamp_ns, *start_ns) = (578_003, start_ns.saturating_sub(60_000_000_000));
        }
        read_judged(proc_root, &mut later, &judge(), &|_| true);
        assert_eq!(program_identity::loader_file(&later, &through_root), None);
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The review of #578 (N1): the loader's mappings read again while its
    /// program is not mapped yet, within a budget of waits a second shared
    /// by the whole host — 50 ms of them, then none until the next second.
    #[test]
    fn the_waits_for_a_loader_s_mapping_are_bounded_a_second() {
        let b = WaitBudget::new();
        let t0 = Instant::now();
        let mut n = 0;
        while b.take(MAP_WAIT, t0) {
            n += 1;
        }
        assert_eq!(n, 100, "50 ms of 500 µs waits");
        assert!(!b.take(MAP_WAIT, t0 + Duration::from_millis(999)));
        assert!(b.take(MAP_WAIT, t0 + Duration::from_secs(1)));
    }

    /// The review of #578 (N1, named; the lab's first round: the pump read
    /// the loader's mappings before it had mapped its program, and placed
    /// nothing): the mappings are read again until the program is among
    /// them — at most ten times more, each wait taken from the second's
    /// budget; a process gone ends it; an exhausted budget reads once.
    #[test]
    fn a_loader_s_mappings_are_read_again_until_its_program_is_mapped() {
        let id = (7u64, 9u64);
        let mapped_at = |n: usize| {
            let mut calls = 0;
            move || {
                calls += 1;
                Some(if calls > n {
                    HashSet::from([id])
                } else {
                    HashSet::new()
                })
            }
        };
        let b = WaitBudget::new();
        assert_eq!(
            read_until_mapped(mapped_at(3), &[id], &b),
            Some(HashSet::from([id])),
            "mapped at the fourth read"
        );
        let mut reads = 0;
        let never = read_until_mapped(
            || {
                reads += 1;
                Some(HashSet::new())
            },
            &[id],
            &b,
        );
        assert_eq!(never, Some(HashSet::new()));
        assert_eq!(reads, MAP_TRIES as usize + 1);
        assert_eq!(read_until_mapped(|| None, &[id], &b), None);
        // the budget spent: one read
        let spent = WaitBudget::new();
        while spent.take(MAP_WAIT, Instant::now()) {}
        let mut reads = 0;
        read_until_mapped(
            || {
                reads += 1;
                Some(HashSet::new())
            },
            &[id],
            &spent,
        );
        assert_eq!(reads, 1);
    }

    /// The review of #578 (P3, named): `LD_TRACE_LOADED_OBJECTS` in the
    /// environment of an exec of the loader, read whole while its process
    /// ran, is its trace mode (`LOADER_LISTS`): any value, as the loader
    /// reads it. Not when it cannot be told — a zombie, another process on
    /// the pid — nor for another name, nor for an exec that is not the
    /// loader's.
    #[test]
    fn the_loader_s_trace_mode_is_read_from_its_environment() {
        let proc = tempfile::tempdir().unwrap();
        // SAFETY: sysconf has no preconditions.
        let tick = 1_000_000_000 / unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let ticks = 4_000u64;
        let read = |pid: u32, argv: &[&str], env: &[&str], state: &str, start: u64| {
            let d = proc.path().join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            let mut blob = Vec::new();
            for v in env {
                blob.extend_from_slice(v.as_bytes());
                blob.push(0);
            }
            std::fs::write(d.join("environ"), blob).unwrap();
            std::fs::write(
                d.join("stat"),
                format!(
                    "{pid} (x) {state} 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {start} \
                     4096 0\n"
                ),
            )
            .unwrap();
            let mut e = rules::testutil::via_loader(argv);
            if let Event::ProcessSpawn {
                pid: p,
                start_ns,
                timestamp_ns,
                ..
            } = &mut e
            {
                (*p, *start_ns, *timestamp_ns) = (pid, ticks * tick, u64::from(pid));
            }
            read_judged(proc.path(), &mut e, &judge(), &|_| false);
            let Event::ProcessSpawn { exe, .. } = &e else {
                unreachable!()
            };
            exe.has(exe_flags::LOADER_LISTS)
        };
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let x = &[ld, "/tmp/x"][..];
        assert!(read(
            51,
            x,
            &["A=b", "LD_TRACE_LOADED_OBJECTS=1"],
            "S",
            ticks
        ));
        assert!(read(52, x, &["LD_TRACE_LOADED_OBJECTS="], "R", ticks));
        assert!(!read(53, x, &["LD_TRACE_LOADED_OBJECTS"], "S", ticks));
        assert!(!read(54, x, &["XLD_TRACE_LOADED_OBJECTS=1"], "S", ticks));
        assert!(!read(55, x, &["LD_TRACE_LOADED_OBJECTS=1"], "Z", ticks));
        assert!(!read(
            56,
            x,
            &["LD_TRACE_LOADED_OBJECTS=1"],
            "S",
            ticks + 500
        ));
        // not the loader: its environment is not read for it
        let mut e = rules::testutil::spawn_full("cat", "/usr/bin/cat", 1000, &["cat"], "bash");
        if let Event::ProcessSpawn { pid, .. } = &mut e {
            *pid = 57;
        }
        let d = proc.path().join("57");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("environ"), b"LD_TRACE_LOADED_OBJECTS=1\0").unwrap();
        read_judged(proc.path(), &mut e, &judge(), &|_| false);
        let Event::ProcessSpawn { exe, .. } = &e else {
            unreachable!()
        };
        assert!(!exe.has(exe_flags::LOADER_LISTS));
    }
}
