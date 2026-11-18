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
//! - **The re-check (R1-1), what listing still runs.** glibc's loader loads
//!   and runs the libraries its program names for auditing (`DT_AUDIT`,
//!   `DT_DEPAUDIT`) in its list and trace modes too — the program's own
//!   constructor when it names itself. The program's dynamic section is
//!   read ([`super::elf_audit`]) from the file the loader maps (placed as
//!   below, found among the process's executable mappings), its status
//!   unchanged since the exec's process started (a write, a rename or a
//!   chmod of it since — a library rewriting the program it audits — is
//!   not read): one named is [`exe_flags::LOADER_AUDITS`]; none, with the
//!   environment read and holding no `LD_AUDIT`, is
//!   [`exe_flags::LOADER_NO_AUDIT`]. Not read: neither — the rules then
//!   record a listed program as one that may run, never as one that runs
//!   nothing.
//! - **The re-check (R1-2), a name through a symbolic link.** Any other
//!   name the loader was given — absolute, or relative to the process's
//!   directory — is walked the same way with its symbolic links followed
//!   as the kernel follows them (`/usr/tmp` is `../var/tmp` on the RHEL
//!   family), and kept by the kernel's name of the file the process maps:
//!   the rules judge it there beside the text's own reading.
//!
//! The loader maps its program a moment after the exec: a read that finds
//! it not mapped yet is made again, every 500 µs up to 5 ms, within a
//! budget of such waits a second ([`MapWaits`]): root's own 50 ms, which no
//! other uid spends, and 25 ms for each other account (a subordinate id
//! counted as its owner, as the reader's shares count it), 50 ms for all of
//! them together. Past them: read once, not placed, recorded.
//!
//! Residual, said: a process may change its own view (its directory, a
//! descriptor), what it maps and its environment in the moment before the
//! pump reads it; the file is then placed, and the trace mode read, by what
//! the read finds; a file the loader reaches through a symbolic link of the
//! process's view under a link of `/proc` is not placed. A program
//! rewritten in place in the instant after the pump's last look at its
//! status and before the loader reads its dynamic section is judged by
//! what the pump read.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
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

/// Root's waits a second ([`MapWaits`]), and all other accounts' together:
/// a flood of loaders that never map their program slows the exec pump by
/// at most these; past them they are read once (not placed: recorded).
const MAP_WAITS_PER_SECOND: Duration = Duration::from_millis(50);
/// The re-check of #578 (R1-3): one account's waits a second (not root's).
const MAP_WAITS_PER_ACCOUNT: Duration = Duration::from_millis(25);
/// The most accounts whose second is tracked at once; past it, an account
/// not tracked gets no wait (read once).
const MAP_WAIT_ACCOUNTS: usize = 4096;

/// The waits all loaders' reads spend ([`MapWaits`]).
static MAP_WAITS: LazyLock<MapWaits> = LazyLock::new(MapWaits::new);

/// A budget of waits a second.
struct WaitBudget {
    limit: Duration,
    spent: Mutex<Option<(Instant, Duration)>>,
}

impl WaitBudget {
    const fn new(limit: Duration) -> Self {
        WaitBudget {
            limit,
            spent: Mutex::new(None),
        }
    }

    /// `wait` taken from the second running at `now`, if it is left.
    fn take(&self, wait: Duration, now: Instant) -> bool {
        let mut s = self.spent.lock();
        let (start, spent) = match *s {
            Some((t, n)) if now.duration_since(t) < Duration::from_secs(1) => (t, n),
            _ => (now, Duration::ZERO),
        };
        if spent + wait > self.limit {
            *s = Some((start, spent));
            return false;
        }
        *s = Some((start, spent + wait));
        true
    }
}

/// The re-check of #578 (R1-3): the loaders' waits a second, per account as
/// the reader's shares are — root's own [`MAP_WAITS_PER_SECOND`], which no
/// other uid spends; every other account [`MAP_WAITS_PER_ACCOUNT`] of its
/// own, and all of them together [`MAP_WAITS_PER_SECOND`]. One host-wide
/// budget let any user spend root's waits, and every other user's.
struct MapWaits {
    root: WaitBudget,
    others: WaitBudget,
    each: Mutex<HashMap<u32, (Instant, Duration)>>,
}

impl MapWaits {
    fn new() -> Self {
        MapWaits {
            root: WaitBudget::new(MAP_WAITS_PER_SECOND),
            others: WaitBudget::new(MAP_WAITS_PER_SECOND),
            each: Mutex::new(HashMap::new()),
        }
    }

    /// `wait` taken for `account` (its uid's, [`super::pump_reads::account_of`];
    /// 0 is root) from the second running at `now`, if it is left.
    fn take(&self, account: u32, wait: Duration, now: Instant) -> bool {
        if account == 0 {
            return self.root.take(wait, now);
        }
        let second = Duration::from_secs(1);
        let mut each = self.each.lock();
        if each.len() >= MAP_WAIT_ACCOUNTS && !each.contains_key(&account) {
            each.retain(|_, (t, _)| now.duration_since(*t) < second);
            if each.len() >= MAP_WAIT_ACCOUNTS {
                return false;
            }
        }
        let (start, spent) = match each.get(&account) {
            Some((t, n)) if now.duration_since(*t) < second => (*t, *n),
            _ => (now, Duration::ZERO),
        };
        if spent + wait > MAP_WAITS_PER_ACCOUNT || !self.others.take(wait, now) {
            return false;
        }
        each.insert(account, (start, spent + wait));
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
        pid,
        uid,
        start_ns,
        exe,
        ..
    } = &*event
    else {
        return;
    };
    let (pid, start_ns) = (*pid, *start_ns);
    let account = super::pump_reads::account_of(*uid);
    let known = exe.has(exe_flags::KNOWN).then_some((exe.dev, exe.ino));
    let dir = proc_root.join(pid.to_string());
    // P3: ldd's trace mode; R1-1: an auditing library named by the
    // environment — from the environment read whole
    let env =
        super::exec_facts::environ_names(&dir, start_ns, &["LD_TRACE_LOADED_OBJECTS", "LD_AUDIT"]);
    if env.as_ref().is_some_and(|set| set[0]) {
        if let Event::ProcessSpawn { exe, .. } = event {
            exe.flags |= exe_flags::LOADER_LISTS;
        }
    }
    let env_audits = env.map(|set| set[1]);
    // N1, R1-2: every file the loader was given, its program first
    let texts: Vec<String> = rules::loader_code(event, false)
        .into_iter()
        .map(|(t, _)| t.to_string())
        .collect();
    let Some(program) = texts.first().cloned() else {
        return;
    };
    if !host_view(&dir) {
        return;
    }
    // (a relative name is opened for the program's dynamic section only:
    // never placed)
    let mut opened: Vec<(String, Placed, File)> = Vec::new();
    for text in texts {
        let relative = !text.starts_with('/');
        if (relative && text != program) || opened.iter().any(|(t, _, _)| *t == text) {
            continue;
        }
        if let Ok((f, p)) = open_placed(proc_root, pid, &text, judge, relative) {
            opened.push((text, p, f));
        }
    }
    if opened.is_empty() {
        return;
    }
    // the loader maps its program a moment after the exec: a read before
    // that finds it not mapped yet — read again, a few times, within the
    // account's budget (past it: not placed, recorded)
    let wanted: Vec<(u64, u64)> = opened.iter().map(|(_, p, _)| (p.dev, p.ino)).collect();
    let Some(mapped) = read_until_mapped(|| executable_mappings(&dir), &wanted, &mut || {
        MAP_WAITS.take(account, MAP_WAIT, Instant::now())
    }) else {
        return;
    };
    // R1-1: the program's auditing libraries, from the file the loader maps
    let audits = opened
        .iter()
        .find(|(t, p, _)| *t == program && mapped.contains(&(p.dev, p.ino)))
        .and_then(|(_, _, f)| names_an_auditor_since(f, start_ns));
    let files: Vec<program_identity::LoaderFile> = opened
        .into_iter()
        .filter(|(t, p, _)| t.starts_with('/') && mapped.contains(&(p.dev, p.ino)))
        .map(|(text, p, _)| program_identity::LoaderFile {
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
    if let Event::ProcessSpawn { exe, .. } = event {
        match (audits, env_audits) {
            (Some(true), _) => exe.flags |= exe_flags::LOADER_AUDITS,
            (Some(false), Some(false)) => exe.flags |= exe_flags::LOADER_NO_AUDIT,
            _ => {}
        }
    }
}

/// The re-check of #578 (R1-1): whether the program `f` (`O_PATH`, the file
/// the loader maps) names a library for auditing ([`super::elf_audit`]),
/// read from it opened again for reading — `None` when it cannot be read,
/// or when its status changed since the exec's process started
/// (`start_ns`, CLOCK_MONOTONIC), looked at after the read: a library that
/// rewrites the program it audits before the pump reads it.
fn names_an_auditor_since(f: &File, start_ns: u64) -> Option<bool> {
    use std::os::unix::fs::FileExt;
    if start_ns == 0 {
        return None;
    }
    let r = kernel_roots::reopen_fd(f, libc::O_RDONLY | libc::O_CLOEXEC).ok()?;
    let found = super::elf_audit::names_an_auditor(&mut |off, buf| r.read_at(buf, off))?;
    let ctime = status_changed_ns(&r)?;
    (!changed_after(ctime, monotonic_offset_ns()?, start_ns)).then_some(found)
}

/// How long before a process's start a status change still counts as
/// after it: the coarse clock the kernel stamps it with (a tick, 10 ms at
/// most) and the clocks' reads.
const CHANGE_SLACK_NS: i128 = 20_000_000;

/// The re-check of #578 (R1-1): a status change at `ctime_ns`
/// (CLOCK_REALTIME) is at or after `start_ns` (CLOCK_MONOTONIC), the
/// realtime clock being `offset_ns` ahead of the monotonic one — less
/// [`CHANGE_SLACK_NS`]: one in that slack counts as after.
fn changed_after(ctime_ns: i128, offset_ns: i128, start_ns: u64) -> bool {
    ctime_ns - offset_ns + CHANGE_SLACK_NS >= i128::from(start_ns)
}

/// The file's status change time (CLOCK_REALTIME, ns), from the kernel's
/// cache (`AT_STATX_DONT_SYNC`: no file system is asked).
fn status_changed_ns(f: &File) -> Option<i128> {
    // SAFETY: `statx` is plain old data, valid when zeroed.
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: the fd is live, the empty path NUL-terminated, `sx` writable.
    let rc = unsafe {
        libc::statx(
            f.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_STATX_DONT_SYNC,
            libc::STATX_CTIME,
            &mut sx,
        )
    };
    (rc == 0 && sx.stx_mask & libc::STATX_CTIME != 0)
        .then(|| i128::from(sx.stx_ctime.tv_sec) * 1_000_000_000 + i128::from(sx.stx_ctime.tv_nsec))
}

/// How far CLOCK_REALTIME is ahead of CLOCK_MONOTONIC now (ns).
fn monotonic_offset_ns() -> Option<i128> {
    let read = |clock| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is writable; the clocks always exist.
        (unsafe { libc::clock_gettime(clock, &mut ts) } == 0)
            .then(|| i128::from(ts.tv_sec) * 1_000_000_000 + i128::from(ts.tv_nsec))
    };
    Some(read(libc::CLOCK_REALTIME)? - read(libc::CLOCK_MONOTONIC)?)
}

/// The process's executable mappings (`read`) once every `wanted` file is
/// among them — read again every [`MAP_WAIT`], at most [`MAP_TRIES`] times
/// more, each wait taken by `take_wait` (the account's budget) — or the
/// last read; `None` when a read fails (the process gone).
fn read_until_mapped(
    mut read: impl FnMut() -> Option<HashSet<(u64, u64)>>,
    wanted: &[(u64, u64)],
    take_wait: &mut dyn FnMut() -> bool,
) -> Option<HashSet<(u64, u64)>> {
    let mut tries = 0;
    loop {
        let mapped = read()?;
        if wanted.iter().all(|w| mapped.contains(w)) || tries >= MAP_TRIES || !take_wait() {
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
/// The re-check of #578 (R1-2): any other absolute name is walked from the
/// process's root the same way, its symbolic links followed as the kernel
/// follows them (an absolute target from the root: the process has PID 1's,
/// [`host_view`]). (The pump's step opens it: [`open_placed`].)
#[cfg(test)]
fn place(proc_root: &Path, pid: u32, text: &str, judge: &Judge) -> io::Result<Placed> {
    open_placed(proc_root, pid, text, judge, false).map(|(_, p)| p)
}

/// [`place`], and the file (`O_PATH`) — with `relative`, a relative name
/// too, from the process's directory (the program whose dynamic section
/// the pump reads, R1-1: `ldd x` runs the loader on `./x`).
fn open_placed(
    proc_root: &Path,
    pid: u32,
    text: &str,
    judge: &Judge,
    relative: bool,
) -> io::Result<(File, Placed)> {
    let (link, rest) = base(proc_root, pid, text, 0, relative)?;
    let follow = !rules::through_proc_link(text);
    // a walk that follows links reads their text in the agent's view: one
    // into `/proc` (`/proc/self`, `/dev/fd`) would name the agent's own
    // process — never crossed
    let procfs = if follow {
        Some(
            kernel_roots::cached(&kernel_roots::open(
                proc_root,
                libc::O_PATH | libc::O_DIRECTORY,
            )?)?
            .dev,
        )
    } else {
        None
    };
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
        let w = kernel_roots::walk_judged(&f, &link, &rest, follow, &mut |c| {
            Some(c.dev) != procfs && judge.trusts(c)
        })?;
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
    let placed = Placed {
        dev: c.dev,
        ino: c.ino,
        memfd: path.starts_with("/memfd:"),
        path: path.to_string(),
        deleted,
    };
    Ok((file, placed))
}

/// `text`'s segments, `.` and empty ones dropped; `None` with a `..` (the
/// kernel climbs from wherever a link led) or, unless `relative`, a
/// relative name (the loader's directory is a link of its own: not a name
/// the pump places).
fn folded(text: &str, relative: bool) -> Option<Vec<&str>> {
    if !relative && !text.starts_with('/') {
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
/// (`/proc/self/root/proc/self/fd/3`); any other absolute name from the
/// process's root, and (`relative`) a relative one from its directory.
fn base(
    proc_root: &Path,
    pid: u32,
    text: &str,
    hops: u8,
    relative: bool,
) -> io::Result<(PathBuf, PathBuf)> {
    use rules::{Hop, Who};
    let own = proc_root.join(pid.to_string());
    let Some(v) = rules::view_link(text) else {
        let segs =
            folded(text, relative).ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let from = if text.starts_with('/') { "root" } else { "cwd" };
        return Ok((own.join(from), segs.iter().collect()));
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
                return base(proc_root, pid, &again, hops + 1, false);
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
    /// program is not mapped yet, within a budget of waits a second — 50 ms
    /// of them, then none until the next second.
    #[test]
    fn the_waits_for_a_loader_s_mapping_are_bounded_a_second() {
        let b = WaitBudget::new(MAP_WAITS_PER_SECOND);
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
        let b = WaitBudget::new(MAP_WAITS_PER_SECOND);
        let mut take = || b.take(MAP_WAIT, Instant::now());
        assert_eq!(
            read_until_mapped(mapped_at(3), &[id], &mut take),
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
            &mut take,
        );
        assert_eq!(never, Some(HashSet::new()));
        assert_eq!(reads, MAP_TRIES as usize + 1);
        assert_eq!(read_until_mapped(|| None, &[id], &mut take), None);
        // the budget spent: one read
        let spent = WaitBudget::new(MAP_WAITS_PER_SECOND);
        while spent.take(MAP_WAIT, Instant::now()) {}
        let mut reads = 0;
        read_until_mapped(
            || {
                reads += 1;
                Some(HashSet::new())
            },
            &[id],
            &mut || spent.take(MAP_WAIT, Instant::now()),
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

    /// The helper the next tests start as a child of their own: with
    /// `NN_K370_MAP` set (files joined by `:`), it maps each file readable
    /// and executable — as the loader maps its program — then waits for its
    /// standard input to close. A no-op without the variable.
    #[test]
    #[ignore = "a helper of the loader tests (NN_K370_MAP)"]
    fn map_and_wait_helper() {
        use std::io::Read;
        let Some(files) = std::env::var_os("NN_K370_MAP") else {
            return;
        };
        let mut kept = Vec::new();
        for f in std::env::split_paths(&files) {
            let file = std::fs::File::open(&f).expect("open a file to map");
            let len = file.metadata().unwrap().len() as usize;
            // SAFETY: a fresh private read-only mapping of an open file.
            let at = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(at, libc::MAP_FAILED, "mapped executable");
            kept.push(file);
        }
        let _ = std::io::stdin().read(&mut [0u8; 1]);
        drop(kept);
    }

    /// A child of this test binary mapping `files` executable
    /// ([`map_and_wait_helper`]), `env` added to its environment; its
    /// process's start (CLOCK_MONOTONIC) and image identity, once every file
    /// is among its mappings.
    fn mapper(files: &[&Path], env: &[(&str, &str)]) -> (Child, u64, (u64, u64)) {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--exact",
            "sensors::loader_files::tests::map_and_wait_helper",
            "--ignored",
            "--test-threads=1",
        ])
        .env("NN_K370_MAP", std::env::join_paths(files).unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn the mapping helper");
        let dir = Path::new("/proc").join(child.id().to_string());
        let wanted: Vec<_> = files.iter().map(|f| id_of(f)).collect();
        for _ in 0..250 {
            if executable_mappings(&dir).is_some_and(|m| wanted.iter().all(|w| m.contains(w))) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            executable_mappings(&dir).is_some_and(|m| wanted.iter().all(|w| m.contains(w))),
            "the helper maps its files"
        );
        let stat = crate::state_read::read_state(dir.join("stat")).unwrap();
        let ticks = crate::response::proc_ref::stat_start_ticks(&stat).unwrap();
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let image = std::fs::canonicalize(dir.join("exe")).unwrap();
        (child, ticks * (1_000_000_000 / hz), id_of(&image))
    }

    /// `argv` run through the loader by the process `pid` (started at
    /// `start_ns`, running the image `image`), exec `key`, read by the pump.
    fn pumped(argv: &[&str], pid: u32, start_ns: u64, image: (u64, u64), key: u64) -> Event {
        let mut e = rules::testutil::via_loader(argv);
        if let Event::ProcessSpawn {
            pid: p,
            start_ns: s,
            timestamp_ns,
            exe,
            ..
        } = &mut e
        {
            (*p, *s, *timestamp_ns) = (pid, start_ns, key);
            (exe.dev, exe.ino) = image;
        }
        read_judged(Path::new("/proc"), &mut e, &judge(), &|_| true);
        e
    }

    /// The pump's reading of the program's auditing libraries: `Some(true)`
    /// one named, `Some(false)` none, `None` not read.
    fn audit_read(e: &Event) -> Option<bool> {
        let Event::ProcessSpawn { exe, .. } = e else {
            unreachable!()
        };
        match (
            exe.has(exe_flags::LOADER_AUDITS),
            exe.has(exe_flags::LOADER_NO_AUDIT),
        ) {
            (true, false) => Some(true),
            (false, true) => Some(false),
            (false, false) => None,
            (true, true) => panic!("both flags"),
        }
    }

    /// A program image naming `audit` (a path, in its string table) under
    /// `tag` (`DT_AUDIT`, `DT_DEPAUDIT`), or no auditing library.
    fn program_naming(audit: Option<(i64, &str)>) -> Vec<u8> {
        use super::super::elf_audit::image::{build, dynamic};
        const DT_STRTAB: i64 = 5;
        const DT_STRSZ: i64 = 10;
        let mut strings = vec![0u8];
        let at = strings.len() as u64;
        if let Some((_, name)) = audit {
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let mut entries = vec![(DT_STRTAB, 0x300), (DT_STRSZ, strings.len() as u64)];
        if let Some((tag, _)) = audit {
            entries.push((tag, at));
        }
        entries.push((0, 0));
        let d = dynamic(2, false, &entries);
        let size = 0x400 + d.len() as u64;
        build(
            2,
            false,
            &[
                (1, 0, 0, size, size),
                (2, 0x400, 0x400, d.len() as u64, d.len() as u64),
            ],
            &[(0x300, strings), (0x400, d)],
        )
    }

    /// The re-check of #578 (R1-1, named; its probe: glibc 2.39 runs a
    /// listed program's auditing library, its own constructor when it names
    /// itself): the pump reads the program's dynamic section from the file
    /// the loader maps — a program naming itself for auditing, one naming
    /// another library (`DT_AUDIT`, `DT_DEPAUDIT`): `LOADER_AUDITS`; one
    /// naming none: `LOADER_NO_AUDIT`; one it cannot read (not ELF), or
    /// changed since its process started (a library rewriting the program
    /// it audits), or listed in an environment with `LD_AUDIT`: neither.
    /// On 6321c7b7 nothing was read: every listed program was Low.
    #[test]
    fn a_listed_program_s_auditing_libraries_are_read_from_the_file_it_maps() {
        use std::os::unix::fs::FileExt;
        let t = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(t.path()).unwrap();
        let path = |n: &str| dir.join(n);
        let self_audit = path("self.so");
        std::fs::write(
            &self_audit,
            program_naming(Some((
                super::super::elf_audit::DT_AUDIT,
                &self_audit.to_string_lossy(),
            ))),
        )
        .unwrap();
        let foreign = path("xa");
        std::fs::write(
            &foreign,
            program_naming(Some((super::super::elf_audit::DT_AUDIT, "/tmp/k370/a.so"))),
        )
        .unwrap();
        let dep = path("xd");
        std::fs::write(
            &dep,
            program_naming(Some((
                super::super::elf_audit::DT_DEPAUDIT,
                "/tmp/k370/a.so",
            ))),
        )
        .unwrap();
        let none = path("x");
        std::fs::write(&none, program_naming(None)).unwrap();
        let unreadable = path("script");
        std::fs::write(&unreadable, b"#!/bin/sh\necho not an ELF program\n").unwrap();
        let changed = path("changed");
        std::fs::write(&changed, program_naming(None)).unwrap();
        let unmapped = path("unmapped");
        std::fs::write(
            &unmapped,
            program_naming(Some((super::super::elf_audit::DT_AUDIT, "/x.so"))),
        )
        .unwrap();
        // the files older than the process by more than the clock's slack
        std::thread::sleep(Duration::from_millis(60));
        let all = [&self_audit, &foreign, &dep, &none, &unreadable, &changed];
        let all: Vec<&Path> = all.iter().map(|p| p.as_path()).collect();
        let (mut child, start_ns, image) = mapper(&all, &[]);
        let pid = child.id();
        // written since the process started: an auditing library rewriting
        // the program it audits, before the pump reads it
        std::fs::OpenOptions::new()
            .write(true)
            .open(&changed)
            .unwrap()
            .write_all_at(b"\x7fELF", 0)
            .unwrap();
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let read = |key: u64, file: &Path| {
            audit_read(&pumped(
                &[ld, "--list", &file.to_string_lossy()],
                pid,
                start_ns,
                image,
                key,
            ))
        };
        assert_eq!(
            read(578_101, &self_audit),
            Some(true),
            "a program naming itself"
        );
        assert_eq!(
            read(578_102, &foreign),
            Some(true),
            "a foreign auditing library"
        );
        assert_eq!(read(578_103, &dep), Some(true), "DT_DEPAUDIT");
        assert_eq!(read(578_104, &none), Some(false), "none");
        assert_eq!(read(578_105, &unreadable), None, "not ELF: not read");
        // a file the process does not map (older than it): not the loader's,
        // not read
        assert_eq!(read(578_109, &unmapped), None, "not mapped: not read");
        assert_eq!(
            read(578_106, &changed),
            None,
            "changed since the exec: not read"
        );
        // relative to the process's directory (`ldd x` runs the loader on
        // `./x`): read, never placed
        let _ = child.kill();
        let _ = child.wait();
        let mut in_dir = Command::new(std::env::current_exe().unwrap());
        in_dir
            .args([
                "--exact",
                "sensors::loader_files::tests::map_and_wait_helper",
                "--ignored",
            ])
            .env("NN_K370_MAP", &none)
            .current_dir(&dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let (mut child, start_ns, image) = {
            let c = in_dir.spawn().unwrap();
            let dir = Path::new("/proc").join(c.id().to_string());
            for _ in 0..250 {
                if executable_mappings(&dir).is_some_and(|m| m.contains(&id_of(&none))) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let stat = crate::state_read::read_state(dir.join("stat")).unwrap();
            let ticks = crate::response::proc_ref::stat_start_ticks(&stat).unwrap();
            // SAFETY: sysconf has no preconditions.
            let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
            let image = id_of(&std::fs::canonicalize(dir.join("exe")).unwrap());
            (c, ticks * (1_000_000_000 / hz), image)
        };
        let e = pumped(&[ld, "--list", "./x"], child.id(), start_ns, image, 578_107);
        assert_eq!(
            audit_read(&e),
            Some(false),
            "./x read in the process's directory"
        );
        assert_eq!(
            program_identity::loader_file(&e, "./x"),
            None,
            "a relative name is not placed"
        );
        let _ = child.kill();
        let _ = child.wait();
        // an environment naming an auditing library: never "none"
        let (mut child, start_ns, image) =
            mapper(&[&none], &[("LD_AUDIT", "/nonexistent/k370-audit.so")]);
        let e = pumped(
            &[ld, "--list", &none.to_string_lossy()],
            child.id(),
            start_ns,
            image,
            578_108,
        );
        assert_eq!(audit_read(&e), None, "LD_AUDIT in the environment");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The re-check of #578 (R1-1): a status change is "since the process
    /// started" with the coarse clock's slack — the clocks' offset applied.
    #[test]
    fn a_status_change_counts_from_the_process_s_start_with_a_slack() {
        let s = 1_000_000_000_000u64;
        let off = 5_000_000_000_000i128;
        let at = |mono: i128| mono + off;
        assert!(changed_after(at(i128::from(s)), off, s), "at the start");
        assert!(changed_after(at(i128::from(s) + 1), off, s), "after");
        assert!(
            changed_after(at(i128::from(s) - 19_000_000), off, s),
            "inside the slack"
        );
        assert!(
            !changed_after(at(i128::from(s) - 21_000_000), off, s),
            "before it"
        );
    }

    /// The re-check of #578 (R1-2, named): a loader operand that reaches a
    /// staging directory through a symbolic link of its text — the RHEL
    /// family's `/usr/tmp -> ../var/tmp` — is placed where the kernel finds
    /// the file the process maps (`…/var/tmp/x`), not by the text. A link
    /// into `/proc` (`/proc/self/…` would name the agent's own process) is
    /// never followed. On 6321c7b7 such a name was not placed (judged by
    /// its text, and silent).
    #[test]
    fn a_loader_operand_through_a_symbolic_link_is_placed_where_the_kernel_finds_it() {
        let t = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(t.path()).unwrap();
        std::fs::create_dir_all(dir.join("var/tmp")).unwrap();
        std::fs::create_dir_all(dir.join("usr")).unwrap();
        std::os::unix::fs::symlink("../var/tmp", dir.join("usr/tmp")).unwrap();
        let x = dir.join("var/tmp/x");
        std::fs::write(&x, program_naming(None)).unwrap();
        std::os::unix::fs::symlink("/proc/self/exe", dir.join("into-proc")).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let (mut child, start_ns, image) = mapper(&[&x], &[]);
        let ld = "/lib64/ld-linux-x86-64.so.2";
        let through = format!("{}/usr/tmp/x", dir.display());
        let e = pumped(&[ld, &through], child.id(), start_ns, image, 578_111);
        let placed = program_identity::loader_file(&e, &through).expect("placed");
        assert_eq!(
            placed.path,
            x.to_string_lossy(),
            "the kernel's name of the file"
        );
        assert!(!placed.memfd && !placed.deleted);
        let into = format!("{}/into-proc", dir.display());
        let e = pumped(&[ld, &into], child.id(), start_ns, image, 578_112);
        assert_eq!(
            program_identity::loader_file(&e, &into),
            None,
            "no link into /proc"
        );
        assert_eq!(
            place(Path::new("/proc"), child.id(), &into, &judge()).ok(),
            None,
            "not even opened"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The re-check of #578 (R1-3, named): the loaders' waits a second are
    /// root's own — no other uid spends them — and each other account's
    /// share (25 ms), all of them together 50 ms; a second later, again.
    /// On 6321c7b7 one budget for the host: any uid spent root's.
    #[test]
    fn the_loaders_waits_are_root_s_own_and_each_account_s_share() {
        let w = MapWaits::new();
        let t0 = Instant::now();
        let spend = |account: u32| {
            let mut n = 0;
            while w.take(account, MAP_WAIT, t0) {
                n += 1;
            }
            n
        };
        assert_eq!(spend(1000), 50, "an account's 25 ms");
        assert_eq!(spend(1000), 0, "spent");
        assert_eq!(spend(1001), 50, "another account's own");
        assert_eq!(spend(1002), 0, "the accounts' 50 ms together");
        assert_eq!(spend(0), 100, "root's 50 ms, its own");
        assert!(
            w.take(1002, MAP_WAIT, t0 + Duration::from_secs(1)),
            "a second later"
        );
        assert!(
            w.take(1000, MAP_WAIT, t0 + Duration::from_secs(1)),
            "a spent account's share again a second later"
        );
        // the accounts tracked at once are bounded: past them, a new one
        // waits not, until their second is over
        let w = MapWaits::new();
        for a in 1..=MAP_WAIT_ACCOUNTS as u32 {
            w.each.lock().insert(a, (t0, Duration::ZERO));
        }
        assert!(
            !w.take(1_000_000, MAP_WAIT, t0),
            "no room for a new account"
        );
        assert!(w.take(1, MAP_WAIT, t0), "a tracked one still waits");
        assert!(
            w.take(1_000_000, MAP_WAIT, t0 + Duration::from_secs(1)),
            "room again once their second is over"
        );
        assert!(
            super::super::pump_reads::account_of(1000) == 1000,
            "a uid below the subordinate ranges counts as its own account"
        );
    }
}
