//! Lot 366: what the exec pumps may read of a process's files, how long
//! they wait for it, and how the reads of one user are kept from holding
//! another's.
//!
//! The exec pump and the exec-check pump read, for each exec, the file the
//! process runs (`/proc/<pid>/exe`), its root, the directory it was run
//! from, an AppImage's image and daemon, a module tool's script and
//! library path. Any such read may wait on something the process's user
//! controls: a file system served from user space, or a lookup in a
//! directory. So:
//!
//! - **Never inline.** Every read the pumps need runs on the exec pumps'
//!   reader ([`bounded`], [`ExecReader`]) and is waited for at most a
//!   deadline; past it the pump goes on, the facts it did not get are
//!   judged as not verified — the flags that take trust away set, the ones
//!   that give it left out — and the condition is signed
//!   ([`UNANSWERED`], a degradation of the exec sensor while it lasts). No
//!   lock a pump takes is held while a read runs.
//! - **Fair between users.** A read is for the user of the exec's process:
//!   its uid, or — a subordinate id of `/etc/subuid` (a rootless
//!   container's) — the user that owns the id's range, as the agent's
//!   shares count it (`sensors::share_subuid`; the re-check of #573, N3).
//!   An id the published ranges give no known user — none published, an
//!   unreadable `/etc/subuid`, an owner `/etc/passwd` does not name, an id
//!   past every range — is the unattributed ids', one account together
//!   (the re-check 2 of #573, M1). One user's reads that did not answer
//!   hold at most one of the reader's helpers, all of its ids together — a
//!   second read for that user waits for the first (within its own
//!   deadline), or is refused at once while the first is held; the users
//!   together, the unattributed ids (one read held at most), the system's
//!   accounts together and root each have a share of their own, so no user
//!   can make root's facts unverifiable, nor another user's by any id it
//!   holds beside its own: the unattributed ids can hold only each other's
//!   reads. A share used up is signed once while it lasts ([`HELD`]). The
//!   pump's waits on reads that answered slowly add up per user: past a
//!   budget, a signed record names the user and that the pump was slowed —
//!   one record per user and window, its reads counted, signed again with
//!   its total when the window ends ([`SLOW`]).
//! - **Signed, always.** Each kind of the pumps' records has a budget of
//!   its own in the degradation registry
//!   ([`crate::boot::degradation::note_kept`]): the slow reads' records
//!   cannot crowd out the reads not waited for ([`UNANSWERED`]) or a share
//!   held ([`HELD`]), nor any other part's, and a record past its budget is
//!   still signed.
//! - **The kernel's identity, never the path's text.** Which file system a
//!   file is on is told by the mount the kernel reached it through (its
//!   mount id, from the kernel's cache: [`antitamper_bpf::kernel_roots::cached`])
//!   against the mount tables ([`Judge`]): a FUSE file system (`fuse`,
//!   `fuse.*`, `fuseblk`) is never asked; any other file system a table
//!   shows — local, or a network one root mounted — is read, on the reader.
//!   A mount no table shows is not read.
//! - **Nothing asked of a file system before it is judged.** A process's
//!   link (`exe`, `root`, `fd/<n>`) is followed alone and its target's
//!   identity read from the cache ([`kernel_roots::link_target`]); a path is
//!   walked one name at a time, each directory judged before a name is
//!   looked up in it ([`kernel_roots::walk_judged`]); a file is opened for
//!   reading only once judged ([`open_exe`]).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

use antitamper_bpf::kernel_roots::{self, Cached};
use parking_lot::{Condvar, Mutex};

use crate::mountinfo::MountTable;
use crate::state_read::{Condition, TimedReader};

/// The file systems the pumps never ask about a file: served by a daemon
/// in user space (FUSE, and its block form) — the daemon, not the kernel,
/// answers, when it cares to.
pub fn never_asked(fstype: &OsStr) -> bool {
    crate::mountinfo::is_fuse(fstype)
}

/// A mount of a table, by its id: its file system's device, and whether it
/// is [`never_asked`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    dev: u64,
    never: bool,
}

/// A mount table as the judge reads it: by mount id, and the file systems
/// it shows by device (whether one of their mounts is never asked).
#[derive(Debug, Default)]
struct Mounted {
    by_id: HashMap<u64, Entry>,
    by_dev: HashMap<u64, bool>,
}

fn mounted(table: &MountTable) -> Arc<Mounted> {
    let mut m = Mounted::default();
    for e in &table.entries {
        let never = never_asked(&e.fstype);
        // a mount id twice (no kernel's table): never asked if either is
        m.by_id
            .entry(e.id)
            .and_modify(|x| x.never |= never)
            .or_insert(Entry {
                dev: e.kernel_dev(),
                never,
            });
        *m.by_dev.entry(e.kernel_dev()).or_default() |= never;
    }
    Arc::new(m)
}

/// Whether the pumps may ask the file system of `c`, by `table` (a table
/// read just before: the AppImage tie's, PID 1's): [`Judge::of`].
pub fn trusted_in(table: &MountTable, c: &Cached) -> bool {
    Judge::of(table).trusts(c)
}

/// How often a mount table is read again after a change of the mounts.
const REFRESH_MIN: Duration = Duration::from_millis(250);

/// A mount table kept for the judge — read again after the kernel flags a
/// change (`POLLPRI` on the open table: the poll clears the flag, so a
/// change seen and not yet read stays `pending`), at most every
/// [`REFRESH_MIN`]. The review of #573 (F1): its lock is taken only to
/// look and to publish — never while the table is read.
#[derive(Debug)]
struct Mounts {
    mounted: Arc<Mounted>,
    loaded: Option<Instant>,
    pending: bool,
    /// A read of the table is under way (by another reader).
    reading: bool,
    watch: Option<Arc<File>>,
    source: PathBuf,
}

impl Mounts {
    fn new(source: &str) -> Self {
        Mounts {
            mounted: Arc::default(),
            loaded: None,
            pending: false,
            reading: false,
            watch: None,
            source: PathBuf::from(source),
        }
    }
}

/// Whether the kernel flagged a change of the mounts `watch` shows.
fn changed(watch: Option<&File>) -> bool {
    use std::os::fd::AsRawFd;
    let Some(w) = watch else {
        return true;
    };
    let mut p = libc::pollfd {
        fd: w.as_raw_fd(),
        events: libc::POLLPRI,
        revents: 0,
    };
    // SAFETY: one valid pollfd for a descriptor the caller keeps open; a
    // zero timeout never blocks.
    let n = unsafe { libc::poll(&mut p, 1, 0) };
    n > 0 && p.revents & (libc::POLLPRI | libc::POLLERR) != 0
}

/// A read of a table due: its source, and the watch already open.
struct Due {
    source: PathBuf,
    watch: Option<Arc<File>>,
}

/// Under `m`'s lock, memory only: whether the table is to be read now (it
/// changed, or was never read, and was not read within [`REFRESH_MIN`]);
/// the read is then this caller's.
fn mounts_due(m: &Mutex<Mounts>) -> Option<Due> {
    let mut g = m.lock();
    if changed(g.watch.as_deref()) {
        g.pending = true;
    }
    let due = g.loaded.is_none_or(|at| at.elapsed() >= REFRESH_MIN);
    if !(g.loaded.is_none() || g.pending) || !due || g.reading {
        return None;
    }
    g.reading = true;
    Some(Due {
        source: g.source.clone(),
        watch: g.watch.clone(),
    })
}

/// The table read — no lock held: its watch opened first when it is not
/// (a change after the poll below is flagged at the next one).
fn mounts_read(due: Due) -> (Option<Arc<File>>, io::Result<MountTable>) {
    let watch = due.watch.or_else(|| {
        kernel_roots::open(&due.source, libc::O_RDONLY)
            .ok()
            .map(Arc::new)
    });
    let _ = changed(watch.as_deref());
    (watch, crate::mountinfo::read(&due.source))
}

/// Under `m`'s lock, memory only: a read's table published — or, failed,
/// the last one read kept and the change not read (an anonymous device is
/// judged on none). Whether the read failed.
fn mounts_publish(
    m: &Mutex<Mounts>,
    watch: Option<Arc<File>>,
    read: Result<Arc<Mounted>, ()>,
) -> bool {
    let mut g = m.lock();
    g.reading = false;
    g.watch = watch;
    g.loaded = Some(Instant::now());
    match read {
        Ok(t) => {
            g.mounted = t;
            g.pending = false;
            false
        }
        Err(()) => {
            g.pending = true;
            true
        }
    }
}

/// Under `m`'s lock, memory only: the table now, and whether no change is
/// pending.
fn mounts_now(m: &Mutex<Mounts>) -> (Arc<Mounted>, bool) {
    let g = m.lock();
    (g.mounted.clone(), !g.pending)
}

/// `m`'s table for a judge: read again first when due ([`mounts_due`]) —
/// on the caller's thread, the exec pumps' reader, no lock held — then
/// taken; a table that cannot be read is signed by `read`
/// ([`crate::state_read::LastGood`]).
fn table_of(m: &Mutex<Mounts>, read: &Mutex<crate::state_read::LastGood>) -> (Arc<Mounted>, bool) {
    if let Some(due) = mounts_due(m) {
        let (watch, table) = mounts_read(due);
        let failed = match table {
            Ok(t) => {
                mounts_publish(m, watch, Ok(mounted(&t)));
                None
            }
            Err(e) => {
                mounts_publish(m, watch, Err(()));
                Some(e)
            }
        };
        last_good(read, failed.as_ref());
    }
    mounts_now(m)
}

/// A table's read signed (failed) or its condition ended.
fn last_good(read: &Mutex<crate::state_read::LastGood>, failed: Option<&io::Error>) {
    let mut g = read.lock();
    match failed {
        Some(e) => g.failed(e),
        None => g.ok(),
    }
}

/// PID 1's mounts.
static PID1: LazyLock<Mutex<Mounts>> =
    LazyLock::new(|| Mutex::new(Mounts::new("/proc/1/mountinfo")));
/// The agent's own mounts (its unit's namespace: a walk from its own `/`).
static OWN: LazyLock<Mutex<Mounts>> =
    LazyLock::new(|| Mutex::new(Mounts::new("/proc/self/mountinfo")));
/// PID 1's table read, or not (signed).
static PID1_READ: LazyLock<Mutex<crate::state_read::LastGood>> = LazyLock::new(|| {
    Mutex::new(crate::state_read::LastGood::new(
        "exec_pump_mounts",
        "PID 1's mount table",
    ))
});
/// The agent's own table read, or not (signed).
static OWN_READ: LazyLock<Mutex<crate::state_read::LastGood>> = LazyLock::new(|| {
    Mutex::new(crate::state_read::LastGood::new(
        "exec_pump_own_mounts",
        "the agent's own mount table",
    ))
});

/// The source while a file is left not verified because the mounts changed
/// and the tables were not read again yet.
pub const CHANGING: &str = "exec_pump_mounts_changing";

/// Signed while files are judged not verified for a change of the mounts
/// not read yet (one record per hold, however often the mounts change).
static STALE: LazyLock<Mutex<Condition>> =
    LazyLock::new(|| Mutex::new(Condition::deferred(CHANGING, Duration::from_secs(60), 1)));

/// Files judged not verified for a change of the mounts not read yet.
static JUDGED_STALE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Lot 366, the review of #573 (F2): whether the pumps may ask a file
/// system about a file, by the mount the kernel reached the file through
/// (`statx`'s mount id, from the kernel's cache) — never by its device: a
/// btrfs subvolume's files show a device of their own, which no table
/// shows.
///
/// - The mount is looked up by its id in PID 1's table, then in the
///   agent's own (its unit's namespace), then — for a walk through a
///   process's `/proc` entry ([`Judge::of_process`]) — in that process's
///   own table, read then.
/// - A mount of a [`never_asked`] type is not asked, whichever table shows
///   it.
/// - A mount only the process's own table shows (another mount namespace:
///   a container's) is asked only when its file system is one PID 1's or
///   the agent's table shows (a copy of a host's mount); one made in that
///   namespace (a user's own `tmpfs` or `overlay`) is not.
/// - A table with a change of the mounts not read yet (within
///   [`REFRESH_MIN`] of its last read) vouches only for a block device's
///   file system, the file's own device its mount's — a mount id or an
///   anonymous device is handed out again; such a file is judged not
///   verified, signed ([`CHANGING`]).
#[derive(Debug, Clone)]
pub struct Judge {
    tables: Vec<(Arc<Mounted>, bool)>,
    process: Option<PathBuf>,
    own: Arc<OnceLock<Option<Arc<Mounted>>>>,
}

impl Judge {
    /// The judge of the host's mounts now: PID 1's table and the agent's
    /// own, read again when they changed. Run on the exec pumps' reader.
    pub fn host() -> Judge {
        let tables = vec![table_of(&PID1, &PID1_READ), table_of(&OWN, &OWN_READ)];
        if tables.iter().all(|(_, fresh)| *fresh) {
            stale_ended();
        }
        Judge {
            tables,
            process: None,
            own: Arc::default(),
        }
    }

    /// A judge of `table` alone (read just before: an AppImage's tie, tests).
    pub fn of(table: &MountTable) -> Judge {
        Judge {
            tables: vec![(mounted(table), true)],
            process: None,
            own: Arc::default(),
        }
    }

    /// This judge for a walk through the process `proc_dir` (`/proc/<pid>`):
    /// a mount none of its tables shows is looked up in that process's own
    /// table (`proc_dir/mountinfo`), read once, on a first such mount.
    pub fn of_process(&self, proc_dir: &Path) -> Judge {
        Judge {
            tables: self.tables.clone(),
            process: Some(proc_dir.to_path_buf()),
            own: Arc::default(),
        }
    }

    /// The process's own table, read on the first call.
    fn process_table(&self) -> Option<&Mounted> {
        let dir = self.process.as_ref()?;
        self.own
            .get_or_init(|| {
                crate::mountinfo::read(&dir.join("mountinfo"))
                    .ok()
                    .map(|t| mounted(&t))
            })
            .as_deref()
    }

    /// The file system of `c` may be asked.
    pub fn trusts(&self, c: &Cached) -> bool {
        for (t, fresh) in &self.tables {
            if let Some(e) = t.by_id.get(&c.mnt_id) {
                return !e.never && (*fresh || stale_vouches(e, c));
            }
        }
        let stale = self.tables.iter().any(|(_, fresh)| !fresh);
        let Some(e) = self.process_table().and_then(|t| t.by_id.get(&c.mnt_id)) else {
            // a mount made since a table with a change not read yet
            if stale {
                stale_refused();
            }
            return false;
        };
        // another namespace's mount: of a file system the host's tables show
        // (a copy of a host's mount), never one made in that namespace
        let shown = |want_fresh: bool| {
            self.tables
                .iter()
                .any(|(t, fresh)| *fresh == want_fresh && t.by_dev.get(&e.dev) == Some(&false))
        };
        !e.never
            && (shown(true) || (shown(false) && stale_vouches(e, &Cached { dev: e.dev, ..*c })))
    }
}

/// A table with a change not read yet vouches for `e`, the mount of `c`:
/// a block device's file system, `c` on that very device — else `c` is
/// judged not verified, signed.
fn stale_vouches(e: &Entry, c: &Cached) -> bool {
    if e.dev == c.dev && c.dev >> 20 != 0 {
        return true;
    }
    stale_refused();
    false
}

/// The tables read since the mounts changed: the condition ended (after
/// its hold).
fn stale_ended() {
    STALE.lock().ended();
}

/// A file judged not verified for a change of the mounts not read yet:
/// counted and signed.
fn stale_refused() {
    JUDGED_STALE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    STALE.lock().holds(
        "the mounts changed and their tables were not read again yet: files on file systems \
         with an anonymous device (FUSE's kind; tmpfs, overlay, btrfs) are judged not verified \
         until they are"
            .to_string(),
    );
}

/// Lot 366: `rel` walked from the process's root (`proc_dir/root`: the
/// directory its `root` link names), every file system on the way judged
/// by `judge` for that process ([`Judge::of_process`],
/// [`kernel_roots::walk_judged`]; no symbolic link followed).
pub fn walk_in_root(
    proc_dir: &Path,
    rel: &Path,
    judge: &Judge,
) -> io::Result<kernel_roots::Walked> {
    let judge = judge.of_process(proc_dir);
    let (root, c) = kernel_roots::link_target(&proc_dir.join("root"))?;
    if !c.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    kernel_roots::walk_judged(&root, Path::new("/"), rel, false, &mut |c| judge.trusts(c))
}

/// Lot 366: `path` walked from the agent's own root, as [`walk_in_root`];
/// symbolic links followed when `follow` (each target walked and judged).
pub fn walk_host(
    root: &Path,
    path: &Path,
    follow: bool,
    judge: &Judge,
) -> io::Result<kernel_roots::Walked> {
    let r = kernel_roots::open(root, libc::O_PATH | libc::O_DIRECTORY)?;
    kernel_roots::walk_judged(&r, root, path, follow, &mut |c| judge.trusts(c))
}

/// Lot 366: the file a process's link names (`/proc/<pid>/exe`, `fd/<n>`)
/// opened with `flags` — its identity read from the kernel's cache first
/// and its file system judged for that process (`PermissionDenied` when
/// `judge` refuses it: not verified), then the same file opened again
/// through this thread's own descriptor ([`kernel_roots::reopen_fd`]:
/// compared, same mount and inode).
pub fn open_exe(link: &Path, flags: i32, judge: &Judge) -> io::Result<(File, Cached)> {
    let (f, c) = kernel_roots::link_target(link)?;
    let judge = match link.parent() {
        Some(dir) => judge.of_process(dir),
        None => judge.clone(),
    };
    if !judge.trusts(&c) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{}: on a file system the agent does not ask: not verified",
                link.display()
            ),
        ));
    }
    Ok((kernel_roots::reopen_fd(&f, flags)?, c))
}

/// How long a pump waits for one exec's reads.
pub const READ_DEADLINE: Duration = Duration::from_millis(500);
/// The degradation's source while reads are not waited for.
pub const UNANSWERED: &str = "exec_reads_unanswered";
/// The degradation's source while a share of the reader is held.
pub const HELD: &str = "exec_readers_held";
/// The degradation's source of a uid whose slow reads slowed the pump.
pub const SLOW: &str = "exec_reads_slow";

/// Who a read is for: root, the system's accounts, a user, or an id no
/// known user is given ([`Pool::Unattributed`]) — each with a share of the
/// reader's helpers of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Pool {
    Root,
    System,
    Users,
    /// The re-check 2 of #573 (M1): the ids of the users' range the reader
    /// cannot give one known user ([`subuid_account`] `None`): every id
    /// from 65536 up while no ranges are published, or while `/etc/subuid`
    /// cannot be read; an id of a range whose owner `/etc/passwd` does not
    /// name, of overlapping ranges or of a gap; an id past every range.
    /// All of them one account, one read at a time and one held at most:
    /// they can hold each other's reads, never an attributed user's, the
    /// system accounts' or root's.
    Unattributed,
}

/// The uids below it are the system's accounts (the distributions' first
/// user's, `login.defs`' `UID_MIN`).
pub const FIRST_USER_UID: u32 = 1000;

/// The re-check of #573 (N7): systemd's dynamic users (`DynamicUser=`) and
/// `nobody` (65534) are the system's accounts, though above
/// [`FIRST_USER_UID`].
const SYSTEM_HIGH: std::ops::RangeInclusive<u32> = 61_184..=65_535;
/// The part of [`SYSTEM_HIGH`] that is no account: the users' (`login.defs`'
/// `UID_MAX` is 60000; 65520–65533 belong to no one in particular).
const SYSTEM_HIGH_GAP: std::ops::RangeInclusive<u32> = 65_520..=65_533;

impl Pool {
    /// Every pool, in [`Self::index`]'s order.
    const ALL: [Pool; 4] = [Pool::Root, Pool::System, Pool::Users, Pool::Unattributed];

    /// The pool of `uid` by the uid alone ([`ExecReader::whose`] puts a
    /// users' id no known user is given in [`Pool::Unattributed`]).
    fn of(uid: u32) -> Pool {
        match uid {
            0 => Pool::Root,
            u if u < FIRST_USER_UID => Pool::System,
            u if SYSTEM_HIGH.contains(&u) && !SYSTEM_HIGH_GAP.contains(&u) => Pool::System,
            _ => Pool::Users,
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    /// The reads of the pool that may be held (unanswered past their
    /// deadline) at once.
    fn held_max(self) -> usize {
        match self {
            Pool::Root => 2,
            Pool::System | Pool::Users => 2,
            Pool::Unattributed => 1,
        }
    }

    fn words(self) -> &'static str {
        match self {
            Pool::Root => "root's",
            Pool::System => "the system accounts'",
            Pool::Users => "the users'",
            Pool::Unattributed => "the unattributed ids'",
        }
    }
}

/// How many reads may run on the reader at once: every share held, and
/// the pumps' own waits.
const READS_MAX: usize = 2 + 2 + 2 + 1 + 4;

/// Whose a read is: its pool, and in it the account it counts against — a
/// system account's uid, a user (the owner of a subordinate id's range:
/// [`subuid_account`]), or [`UNATTRIBUTED`] for every id of
/// [`Pool::Unattributed`]; root's reads are root's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Whose {
    pool: Pool,
    account: u32,
}

/// The reads under way: per account (root's aside), its one read (held or
/// not); per pool, how many are held.
#[derive(Debug, Default)]
struct Pools {
    busy: HashMap<Whose, bool>,
    held: [usize; 4],
}

/// Why a read was not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    /// The account's earlier read is held (did not answer by its deadline).
    UidHeld,
    /// The account's earlier read was still being read at this one's
    /// deadline.
    UidBusy,
    /// The pool's share is held.
    Share(Pool),
}

/// A read's place in its pool: waited for, held past its deadline, or done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flight {
    Waited,
    Held,
    Done,
}

/// A read admitted: its pool's account, settled once it is done.
#[derive(Debug)]
struct Ticket {
    whose: Whose,
    pool: Pool,
    flight: Mutex<Flight>,
    pools: Arc<Mutex<Pools>>,
    freed: Arc<Condvar>,
}

impl Ticket {
    /// The read answered, or never ran: its place given back.
    fn done(&self) {
        let mut f = self.flight.lock();
        let was = std::mem::replace(&mut *f, Flight::Done);
        if was == Flight::Done {
            return;
        }
        let mut p = self.pools.lock();
        if was == Flight::Held {
            p.held[self.pool.index()] -= 1;
        }
        if self.pool != Pool::Root {
            p.busy.remove(&self.whose);
        }
        drop(p);
        drop(f);
        self.freed.notify_all();
    }

    /// Its deadline passed, the read still running: held. Whether it is.
    fn passed(&self) -> bool {
        let mut f = self.flight.lock();
        if *f != Flight::Waited {
            return false;
        }
        *f = Flight::Held;
        let mut p = self.pools.lock();
        p.held[self.pool.index()] += 1;
        if self.pool != Pool::Root {
            p.busy.insert(self.whose, true);
        }
        true
    }
}

/// Settles its ticket when dropped: after the read, or with a read that
/// never ran.
struct Settle(Arc<Ticket>);

impl Drop for Settle {
    fn drop(&mut self) {
        self.0.done();
    }
}

/// A read that answered in this long or less did not slow the pump.
const SLOW_FLOOR: Duration = Duration::from_millis(25);
/// The window the slow reads add up in.
const SLOW_WINDOW: Duration = Duration::from_secs(60);
/// One user's slow reads past it within the window are signed.
const SLOW_BUDGET: Duration = Duration::from_secs(1);
/// Every user's slow reads together past it within the window are signed.
const SLOW_BUDGET_ALL: Duration = Duration::from_secs(5);
/// The users accounted at once: past it, the least slow is forgotten.
const ACCOUNTS_MAX: usize = 512;
/// The re-check of #573 (N2): the users with a record of their own at
/// once; past them, the record of every user's slow reads names them (it
/// is signed by then: each of them past [`SLOW_BUDGET`], together past
/// [`SLOW_BUDGET_ALL`]).
const SLOW_KEPT: usize = 4;
const _: () =
    assert!(SLOW_BUDGET.as_millis() * (SLOW_KEPT as u128 + 1) >= SLOW_BUDGET_ALL.as_millis());
/// The slow reads' budget of the degradation registry: the users' records
/// and every user's.
const SLOW_RECORDS: usize = SLOW_KEPT + 1;
/// The shares held: one record per pool at most.
const HELD_RECORDS: usize = Pool::ALL.len();

/// One user's (or every user's) slow reads in the current window.
#[derive(Debug, Clone)]
struct Account {
    since: Instant,
    waited: Duration,
    /// The slow reads counted.
    reads: u32,
    /// The uid of the latest (a user's own, or a subordinate id of its).
    last_uid: u32,
    /// The record signed in this window, and the wait it said.
    signed: Option<(String, Duration)>,
}

impl Account {
    fn new(now: Instant) -> Self {
        Account {
            since: now,
            waited: Duration::ZERO,
            reads: 0,
            last_uid: 0,
            signed: None,
        }
    }

    fn ended(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.since) >= SLOW_WINDOW
    }
}

/// The slow reads' accounts, by user.
#[derive(Debug)]
struct Slow {
    by_uid: HashMap<u32, Account>,
    all: Account,
    /// The earliest end of a window with a record: none ends before it.
    next_end: Option<Instant>,
}

impl Slow {
    fn new(now: Instant) -> Self {
        Slow {
            by_uid: HashMap::new(),
            all: Account::new(now),
            next_end: None,
        }
    }
}

/// Lot 366, the review of #573 (F4): the exec pumps' reader — #563's
/// bounded reader ([`TimedReader`]: its helpers reused, each read waited
/// for at most its deadline) with each read's uid's share: see the
/// module's "Fair between users".
pub struct ExecReader {
    reader: TimedReader,
    deadline: Duration,
    pools: Arc<Mutex<Pools>>,
    freed: Arc<Condvar>,
    slow: Mutex<Slow>,
    unanswered: Mutex<Condition>,
    held: [Mutex<Condition>; 4],
    /// The account a user's uid counts against ([`subuid_account`]):
    /// `None`, no known user's ([`Pool::Unattributed`]).
    owner: fn(u32) -> Option<u32>,
}

impl std::fmt::Debug for ExecReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecReader")
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}

impl ExecReader {
    /// A reader whose reads are waited for at most `deadline`, a uid
    /// counted as the owner of its subordinate range ([`subuid_account`]).
    pub fn new(deadline: Duration) -> Self {
        Self::with_owners(deadline, subuid_account)
    }

    /// [`Self::new`], a uid counted as the user `owner` says (`None`: no
    /// known user's).
    fn with_owners(deadline: Duration, owner: fn(u32) -> Option<u32>) -> Self {
        let held = || {
            Mutex::new(Condition::deferred(
                HELD,
                Duration::from_secs(60),
                HELD_RECORDS,
            ))
        };
        ExecReader {
            reader: TimedReader::new(deadline, READS_MAX),
            deadline,
            pools: Arc::default(),
            freed: Arc::default(),
            slow: Mutex::new(Slow::new(Instant::now())),
            unanswered: Mutex::new(Condition::deferred(UNANSWERED, Duration::from_secs(60), 1)),
            held: [held(), held(), held(), held()],
            owner,
        }
    }

    /// Whose a read of `uid`'s processes' files is: its pool (by the uid),
    /// and the account it counts against — a user's subordinate id, its
    /// owner's; an id of the users' range no known user is given, the
    /// unattributed ids' one account (the re-check 2 of #573, M1).
    fn whose(&self, uid: u32) -> Whose {
        match Pool::of(uid) {
            Pool::Users => match (self.owner)(uid) {
                Some(account) => Whose {
                    pool: Pool::Users,
                    account,
                },
                None => Whose {
                    pool: Pool::Unattributed,
                    account: UNATTRIBUTED,
                },
            },
            pool => Whose { pool, account: uid },
        }
    }

    /// `f` (reads of the files of a process of `uid`, `what` in words) run
    /// on a helper and waited for at most the deadline. `Err(why)` when it
    /// did not answer in time — the helper stays with it until it answers
    /// — or was refused at once (its uid's earlier read held, its pool's
    /// share held). Either is signed until reads answer again.
    pub fn run<T: Send + 'static>(
        &self,
        uid: u32,
        what: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, String> {
        let t0 = Instant::now();
        let until = t0 + self.deadline;
        let whose = self.whose(uid);
        let out = match self.admit(whose, until) {
            Ok(ticket) => self.read(ticket, what, until, f),
            Err(r) => Err(self.refused(uid, whose, what, r)),
        };
        self.waited(uid, whose, t0.elapsed(), Instant::now());
        match &out {
            Ok(_) => self.answered(),
            Err(why) => self.not_waited(what, why),
        }
        out
    }

    /// `f` on a helper as `ticket` admitted it, waited for until `until`.
    fn read<T: Send + 'static>(
        &self,
        ticket: Arc<Ticket>,
        what: &str,
        until: Instant,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, String> {
        let settle = Settle(Arc::clone(&ticket));
        let wait = until.saturating_duration_since(Instant::now());
        let got = self.reader.run_within(what, wait, move || {
            let v = f();
            drop(settle);
            v
        });
        if got.is_err() && ticket.passed() {
            self.held_now(ticket.pool);
        }
        got
    }

    /// Under the pools' lock (and waiting on it, at most until `until`, for
    /// the account's earlier read): the read admitted, or why not.
    fn admit(&self, whose: Whose, until: Instant) -> Result<Arc<Ticket>, Refused> {
        let pool = whose.pool;
        let mut p = self.pools.lock();
        loop {
            if p.held[pool.index()] >= pool.held_max() {
                return Err(Refused::Share(pool));
            }
            if pool == Pool::Root {
                break;
            }
            match p.busy.get(&whose) {
                None => break,
                Some(true) => return Err(Refused::UidHeld),
                Some(false) => {
                    if self.freed.wait_until(&mut p, until).timed_out() {
                        return Err(Refused::UidBusy);
                    }
                }
            }
        }
        if pool != Pool::Root {
            p.busy.insert(whose, false);
        }
        Ok(Arc::new(Ticket {
            whose,
            pool,
            flight: Mutex::new(Flight::Waited),
            pools: Arc::clone(&self.pools),
            freed: Arc::clone(&self.freed),
        }))
    }

    /// A refusal in words; a share held signed once while it lasts.
    fn refused(&self, uid: u32, whose: Whose, what: &str, r: Refused) -> String {
        let of = of_whom(uid, whose);
        match r {
            Refused::UidHeld => format!(
                "{what}: not read — an earlier read of the files of {of} processes has not \
                 answered"
            ),
            Refused::UidBusy => format!(
                "{what}: not read — an earlier read of the files of {of} processes was still \
                 running at the deadline"
            ),
            Refused::Share(pool) => {
                self.held_now(pool);
                format!(
                    "{what}: not read — {} share of the exec pumps' reader is held by reads \
                     that have not answered",
                    pool.words()
                )
            }
        }
    }

    /// `pool`'s share used up: signed once while it lasts.
    fn held_now(&self, pool: Pool) {
        let full = self.pools.lock().held[pool.index()] >= pool.held_max();
        if !full {
            return;
        }
        let mut c = self.held[pool.index()].lock();
        if !c.holding() {
            c.holds(format!(
                "{} share of the exec pumps' reader is held by reads of processes' files that \
                 have not answered: further reads of those processes are refused at once, their \
                 facts judged not verified",
                pool.words()
            ));
        }
    }

    /// A read answered: the conditions of the shares with room again, and
    /// of reads not waited for once none is held, ended (after their hold).
    fn answered(&self) {
        self.answered_at(Instant::now());
    }

    /// [`Self::answered`] at `now`.
    fn answered_at(&self, now: Instant) {
        let held = self.pools.lock().held;
        for pool in Pool::ALL {
            if held[pool.index()] < pool.held_max() {
                self.held[pool.index()].lock().ended_at(now);
            }
        }
        if held.iter().all(|n| *n == 0) {
            self.unanswered.lock().ended_at(now);
        }
    }

    /// A read not waited for: signed.
    fn not_waited(&self, what: &str, why: &str) {
        NOT_WAITED_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(read = what, why = %why, "exec pump: a read of a process's files was not waited for");
        self.unanswered.lock().holds(format!(
            "the exec pumps' reads of a process's files did not answer within {} ms, or were \
             refused while earlier ones had not: the facts they did not get are judged as not \
             verified",
            self.deadline.as_millis()
        ));
    }

    /// The pump waited `took` on a read of `uid`'s (counted as `whose`): a
    /// slow one added to its user's account, and to every user's — past a
    /// budget within the window, a signed record names the user and that
    /// the pump was slowed. The windows that ended are rolled over at any
    /// read: their records leave the status, signed again with their total
    /// when it grew (the re-check of #573, N2).
    fn waited(&self, uid: u32, whose: Whose, took: Duration, now: Instant) {
        let records = {
            let mut s = self.slow.lock();
            let mut out = slow_sweep(&mut s, now);
            if took > SLOW_FLOOR {
                out.extend(slow_add(&mut s, uid, whose.account, took, now));
            }
            out
        };
        for r in records {
            match r {
                SlowRecord::Sign(detail) => {
                    tracing::warn!(uid, detail = %detail, "exec pump slowed by slow reads");
                    crate::boot::degradation::note_kept(SLOW, &detail, SLOW_RECORDS);
                }
                SlowRecord::Retire(detail) => {
                    crate::boot::degradation::retire_kept(SLOW, &detail);
                }
                SlowRecord::Ended(detail) => {
                    crate::boot::degradation::sign_ended(SLOW, &detail);
                }
            }
        }
    }

    /// The reads unanswered now.
    pub fn unanswered(&self) -> usize {
        self.reader.unanswered()
    }

    /// The helpers free now.
    pub fn free_helpers(&self) -> usize {
        self.reader.free_helpers()
    }

    /// Whether reads not waited for are signed now ([`UNANSWERED`]).
    pub fn not_waited_now(&self) -> bool {
        self.unanswered.lock().holding()
    }

    /// Whether `uid`'s pool's share is signed held now ([`HELD`]).
    #[cfg(test)]
    fn held_signed(&self, uid: u32) -> bool {
        self.held[self.whose(uid).pool.index()].lock().holding()
    }

    /// The record signed for user `owner`'s slow reads in this window, if
    /// any.
    #[cfg(test)]
    fn slow_signed(&self, owner: u32) -> Option<String> {
        Some(self.slow.lock().by_uid.get(&owner)?.signed.clone()?.0)
    }
}

/// The re-check of #573 (N3): the account a user's uid counts against —
/// for a subordinate id of `/etc/subuid`, its range's owner's, as the
/// agent's shares count it ([`crate::sensors::share_subuid::account_of`]:
/// the ranges published at the agent's start and again when the file
/// changes; root's ranges one account of their own). No uid of the 16-bit
/// range — root's, a system account's, a user's own — is ever counted as
/// another's.
///
/// The re-check 2 of #573 (M1): `None` — no known user's, the
/// unattributed ids' account ([`Pool::Unattributed`]) — for an id from
/// 65536 up the ranges give no single known owner: the overflow row's (an
/// owner `/etc/passwd` does not name, overlapping ranges, a gap, every
/// such id while `/etc/subuid` cannot be read), an id past every range,
/// and every such id while no ranges are published. Counted as itself, it
/// was a second account of the user that holds it: with one read of its
/// own uid, it held the users' share.
fn subuid_account(uid: u32) -> Option<u32> {
    account_in(uid, crate::sensors::share_subuid::account_of)
}

/// [`subuid_account`] with the published ranges' answer `account_of`.
fn account_in(uid: u32, account_of: impl Fn(u32) -> Option<u32>) -> Option<u32> {
    use common::wire::execq::OVERFLOW_SHARE;
    if u64::from(uid) < crate::sensors::share_subuid::ACCOUNTS_END {
        return Some(uid);
    }
    account_of(uid).filter(|a| *a != OVERFLOW_SHARE)
}

/// The re-check of #578 (R1-3): the account `uid`'s waits count against —
/// itself below the users' subordinate ranges, a subordinate id's owner,
/// or one account for every id no known user is given — as the reader's
/// shares count it.
pub(crate) fn account_of(uid: u32) -> u32 {
    subuid_account(uid).unwrap_or(UNATTRIBUTED)
}

/// The account of every id of [`Pool::Unattributed`] (no uid: the
/// kernel's "no id", as the shares' overflow row).
const UNATTRIBUTED: u32 = common::wire::execq::OVERFLOW_SHARE;

/// An account of the users' share in words.
fn account_words(account: u32) -> String {
    use common::wire::execq::ROOT_SUBID_SHARE;
    match account {
        UNATTRIBUTED => "the unattributed ids (no known user's)".to_string(),
        ROOT_SUBID_SHARE => "root's subordinate ids".to_string(),
        n => format!("user {n}"),
    }
}

/// A uid's processes in words: `uid N's`, `user O's (uid N)` for a
/// subordinate id of O's, or the unattributed ids' ([`Pool::Unattributed`]).
fn of_whom(uid: u32, whose: Whose) -> String {
    match whose.pool {
        Pool::Unattributed => format!("the unattributed ids' (uid {uid}: no known user's)"),
        Pool::Users if whose.account != uid => {
            format!("{}'s (uid {uid})", account_words(whose.account))
        }
        _ => format!("uid {uid}'s"),
    }
}

/// A record of the slow reads: to sign (kept while its window lasts),
/// whose window ended (to retire), or a window's total once it ended
/// (signed, not kept).
#[derive(Debug, Clone, PartialEq, Eq)]
enum SlowRecord {
    Sign(String),
    Retire(String),
    Ended(String),
}

/// Every user's slow reads: how many users are past their own budget, and
/// the slowest.
type Every = (usize, Option<u32>);

/// A user's (or every user's: `owner` `None`, with `every`) record of `a`,
/// its window running (`end` false) or ended.
fn slow_detail(owner: Option<u32>, a: &Account, end: bool, every: Every) -> String {
    let (who, whose) = match owner {
        Some(o) => (
            account_words(o),
            format!(
                "the files of that user's processes (its own uid or its subordinate ids; the \
                 latest uid {})",
                a.last_uid
            ),
        ),
        None => (
            "every user".to_string(),
            format!(
                "processes' files ({} user(s) past their own budget, the most: {})",
                every.0,
                every.1.map_or_else(|| "-".to_string(), account_words)
            ),
        ),
    };
    let when = if end {
        "in the window that ended"
    } else {
        "within"
    };
    format!(
        "{who}: the exec pumps waited {} ms {when} {} s on {} slow read{} of {whose} — the \
         exec pump was slowed (the events behind it waited)",
        a.waited.as_millis(),
        SLOW_WINDOW.as_secs(),
        a.reads,
        if a.reads == 1 { "" } else { "s" },
    )
}

/// `a`'s window ended at `now`: its record retired — and signed again with
/// its total when it grew since — and the window begun again.
fn roll(
    owner: Option<u32>,
    a: &mut Account,
    now: Instant,
    every: Every,
    out: &mut Vec<SlowRecord>,
) {
    if !a.ended(now) {
        return;
    }
    if let Some((d, said)) = a.signed.take() {
        out.push(SlowRecord::Retire(d));
        if a.waited > said {
            out.push(SlowRecord::Ended(slow_detail(owner, a, true, every)));
        }
    }
    *a = Account::new(now);
}

/// The users past their own budget in this window, and the slowest.
fn every(s: &Slow) -> Every {
    (
        s.by_uid.values().filter(|a| a.waited > SLOW_BUDGET).count(),
        s.by_uid
            .iter()
            .max_by_key(|(_, a)| a.waited)
            .map(|(u, _)| *u),
    )
}

/// The re-check of #573 (N2): at any read, the windows with a record that
/// ended rolled over (memory only; at most once per window end) — a
/// record no longer stays in the status until its user is slow again.
fn slow_sweep(s: &mut Slow, now: Instant) -> Vec<SlowRecord> {
    let mut out = Vec::new();
    if s.next_end.is_none_or(|t| now < t) {
        return out;
    }
    let all = every(s);
    let mut next: Option<Instant> = None;
    for (owner, a) in s.by_uid.iter_mut() {
        if a.signed.is_some() {
            roll(Some(*owner), a, now, all, &mut out);
        }
        if a.signed.is_some() {
            let end = a.since + SLOW_WINDOW;
            next = Some(next.map_or(end, |n| n.min(end)));
        }
    }
    s.by_uid.retain(|_, a| a.reads > 0 && !a.ended(now));
    roll(None, &mut s.all, now, all, &mut out);
    if s.all.signed.is_some() {
        let end = s.all.since + SLOW_WINDOW;
        next = Some(next.map_or(end, |n| n.min(end)));
    }
    s.next_end = next;
    out
}

/// Room for one more user's account: the ones whose window ended dropped,
/// then the least slow not signed.
fn make_room(s: &mut Slow, now: Instant, out: &mut Vec<SlowRecord>) {
    if s.by_uid.len() < ACCOUNTS_MAX {
        return;
    }
    let all = every(s);
    for (owner, a) in s.by_uid.iter_mut() {
        roll(Some(*owner), a, now, all, out);
    }
    s.by_uid.retain(|_, a| a.reads > 0);
    if s.by_uid.len() >= ACCOUNTS_MAX {
        if let Some(least) = s
            .by_uid
            .iter()
            .filter(|(_, a)| a.signed.is_none())
            .min_by_key(|(_, a)| a.waited)
            .map(|(u, _)| *u)
        {
            s.by_uid.remove(&least);
        }
    }
}

/// The earliest window end with a record, `end` among them.
fn due(s: &mut Slow, end: Instant) {
    s.next_end = Some(s.next_end.map_or(end, |n| n.min(end)));
}

/// `took`, a wait on a read of `uid`'s (user `owner`'s), added to that
/// user's account and to every user's, in `s` (memory only): the records to
/// sign, and the ones whose window ended. One record per user and window
/// (the first [`SLOW_KEPT`] users past their budget; past them, every
/// user's names how many), its reads counted.
fn slow_add(s: &mut Slow, uid: u32, owner: u32, took: Duration, now: Instant) -> Vec<SlowRecord> {
    let mut out = Vec::new();
    if !s.by_uid.contains_key(&owner) {
        make_room(s, now, &mut out);
    }
    let all = every(s);
    let signed_now = s.by_uid.values().filter(|a| a.signed.is_some()).count();
    let a = s.by_uid.entry(owner).or_insert_with(|| Account::new(now));
    roll(Some(owner), a, now, all, &mut out);
    a.waited += took;
    a.reads = a.reads.saturating_add(1);
    a.last_uid = uid;
    let mut end = None;
    if a.waited > SLOW_BUDGET && a.signed.is_none() && signed_now < SLOW_KEPT {
        let d = slow_detail(Some(owner), a, false, (0, None));
        a.signed = Some((d.clone(), a.waited));
        end = Some(a.since + SLOW_WINDOW);
        out.push(SlowRecord::Sign(d));
    }
    if let Some(end) = end {
        due(s, end);
    }
    let all = every(s);
    roll(None, &mut s.all, now, all, &mut out);
    s.all.waited += took;
    s.all.reads = s.all.reads.saturating_add(1);
    s.all.last_uid = uid;
    if s.all.waited > SLOW_BUDGET_ALL && s.all.signed.is_none() {
        let d = slow_detail(None, &s.all, false, all);
        s.all.signed = Some((d.clone(), s.all.waited));
        let end = s.all.since + SLOW_WINDOW;
        due(s, end);
        out.push(SlowRecord::Sign(d));
    }
    out
}

/// The exec pumps' reader ([`ExecReader`], [`READ_DEADLINE`]).
pub static EXEC_READER: LazyLock<ExecReader> = LazyLock::new(|| ExecReader::new(READ_DEADLINE));

/// Reads not waited for since the start.
static NOT_WAITED_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Lot 366: `f` (an exec's reads, for a process of `uid`) run on the exec
/// pumps' reader ([`EXEC_READER`]) and waited for at most its deadline:
/// [`ExecReader::run`].
pub fn bounded<T: Send + 'static>(
    uid: u32,
    what: &str,
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    EXEC_READER.run(uid, what, f)
}

/// Lot 366: whether the condition "an exec's reads not waited for" stands
/// on the exec pumps' reader (signed, [`UNANSWERED`]).
pub fn not_waited() -> bool {
    EXEC_READER.not_waited_now()
}

/// Reads not waited for since the start, and files judged not verified
/// for a change of the mounts not read yet (both signed as they happen:
/// [`UNANSWERED`], [`CHANGING`]).
pub fn counts() -> (u64, u64) {
    (
        NOT_WAITED_COUNT.load(std::sync::atomic::Ordering::Relaxed),
        JUDGED_STALE.load(std::sync::atomic::Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::channel;

    /// A judge of the watched table `m` alone (tests).
    fn judge_of(m: &Mutex<Mounts>) -> Judge {
        let read = Mutex::new(crate::state_read::LastGood::new(
            "exec_pump_mounts_test",
            "a test's table",
        ));
        Judge {
            tables: vec![table_of(m, &read)],
            process: None,
            own: Arc::default(),
        }
    }

    /// A mount table's line: mount `id`, device `dev`, of `fstype`.
    fn line(id: u64, dev: u64, fstype: &str) -> String {
        format!(
            "{id} 1 {}:{} / /x{id} rw - {fstype} src rw\n",
            dev >> 20,
            dev & 0xfffff
        )
    }

    fn judge(text: &str) -> Judge {
        Judge::of(&crate::mountinfo::parse(text.as_bytes()))
    }

    fn here() -> Cached {
        let t = std::env::temp_dir();
        kernel_roots::cached(&File::open(t).unwrap()).unwrap()
    }

    /// Lot 366, the review of #573 (F3): a read that never answers holds a
    /// helper, never the caller: given up at the deadline and signed
    /// (`exec_reads_unanswered`, a degradation); another read meanwhile is
    /// answered by another helper, and the first serves again once its read
    /// answers — no helper made for it. Deterministic: a helper is free
    /// again before its answer is handed over.
    #[test]
    fn a_read_that_never_answers_holds_a_helper_not_the_pump() {
        let r = ExecReader::new(Duration::from_millis(200));
        let (release, wait) = channel::<()>();
        let before = counts().0;
        let t0 = Instant::now();
        let got = r.run(1000, "test", move || {
            let _ = wait.recv();
            1
        });
        let took = t0.elapsed();
        assert!(got.is_err());
        assert!(
            took >= Duration::from_millis(200) && took < Duration::from_secs(5),
            "{took:?}"
        );
        assert!(counts().0 > before && r.not_waited_now(), "signed");
        assert_eq!(r.unanswered(), 1);
        assert_eq!(r.run(1001, "test", || 2), Ok(2));
        release.send(()).unwrap();
        let t = Instant::now();
        while r.unanswered() != 0 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        while r.free_helpers() < 2 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(r.free_helpers(), 2, "both helpers free again");
        for n in 3..50 {
            assert_eq!(r.run(1000, "test", move || n), Ok(n));
            assert_eq!(r.free_helpers(), 2, "a free helper reused, none made");
            assert_eq!(r.unanswered(), 0, "none counted unanswered");
        }
    }

    /// Lot 366, the review of #573 (F4): the users' share of the reader
    /// held by reads that do not answer: the next user's read is refused at
    /// once — no wait, no thread made — and the share signed held once.
    #[test]
    fn a_share_held_refuses_at_once_and_is_signed_once() {
        let r = ExecReader::new(Duration::from_millis(50));
        let mut releases = Vec::new();
        let before = counts().0;
        for uid in [1000, 1001] {
            let (tx, rx) = channel::<()>();
            releases.push(tx);
            assert!(r
                .run(uid, "test", move || {
                    let _ = rx.recv();
                })
                .is_err());
        }
        assert!(r.held_signed(1002), "the users' share signed held");
        let t0 = Instant::now();
        assert!(r.run(1002, "test", || ()).is_err());
        assert!(r.run(1003, "test", || ()).is_err());
        assert!(t0.elapsed() < Duration::from_millis(50), "refused at once");
        assert_eq!(r.unanswered(), 2, "no read started for them");
        assert!(
            counts().0 >= before + 4 && r.not_waited_now(),
            "each signed"
        );
        assert_eq!(
            r.held[Pool::Users.index()].lock().reports(),
            1,
            "once per episode"
        );
        drop(releases);
    }

    /// Lot 366, the review of #573 (F4, the R011 case): one uid's reads
    /// that do not answer hold one helper — its next read refused at once —
    /// and the users together hold their share only: root's reads and a
    /// system account's are read as ever, however many users' reads are
    /// held. Fails where every read shares one bound (bad1b957: four held,
    /// root's module tool's facts refused).
    #[test]
    fn one_uid_cannot_starve_root_s_reads() {
        // each uid its own account (the subordinate ids' owners: below)
        let r = ExecReader::with_owners(Duration::from_millis(50), Some);
        let mut releases = Vec::new();
        let (tx, rx) = channel::<()>();
        releases.push(tx);
        assert!(r
            .run(1000, "test", move || {
                let _ = rx.recv();
            })
            .is_err());
        let t0 = Instant::now();
        let (tx, rx) = channel::<()>();
        releases.push(tx);
        assert!(
            r.run(1000, "test", move || {
                let _ = rx.recv();
            })
            .is_err(),
            "the uid's second read"
        );
        assert!(t0.elapsed() < Duration::from_millis(50), "refused at once");
        assert_eq!(r.unanswered(), 1, "one helper held by the uid");
        // more users' uids fill the users' share
        for uid in 100_000..100_010 {
            let (tx, rx) = channel::<()>();
            releases.push(tx);
            let _ = r.run(uid, "test", move || {
                let _ = rx.recv();
            });
        }
        assert_eq!(r.unanswered(), 2, "the users' share, no more");
        for _ in 0..20 {
            assert_eq!(r.run(0, "root", || 7), Ok(7), "root's read answered");
            assert_eq!(r.run(104, "system", || 8), Ok(8), "a system account's");
        }
        drop(releases);
    }

    /// Lot 366, the review of #573 (F4): a uid's second read while its
    /// first is still being read waits for it (within its own deadline) —
    /// the two pumps' reads of one user's files never run at once, so one
    /// uid's reads hold at most one helper — and is answered once the first
    /// is; root's run beside.
    #[test]
    fn a_uid_s_second_read_waits_for_its_first() {
        let r = Arc::new(ExecReader::new(Duration::from_millis(400)));
        let at_once = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let read = |at_once: Arc<AtomicUsize>, most: Arc<AtomicUsize>| {
            move || {
                let n = at_once.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(n, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(100));
                at_once.fetch_sub(1, Ordering::SeqCst);
                n
            }
        };
        let other = {
            let (r, f) = (
                Arc::clone(&r),
                read(Arc::clone(&at_once), Arc::clone(&most)),
            );
            std::thread::spawn(move || r.run(1000, "test", f))
        };
        std::thread::sleep(Duration::from_millis(20));
        let mine = r.run(1000, "test", read(Arc::clone(&at_once), Arc::clone(&most)));
        assert!(
            mine.is_ok() && other.join().unwrap().is_ok(),
            "both answered"
        );
        assert_eq!(most.load(Ordering::SeqCst), 1, "never at once");
        // root's reads are not one user's: beside each other
        let (r2, f) = (
            Arc::clone(&r),
            read(Arc::clone(&at_once), Arc::clone(&most)),
        );
        let other = std::thread::spawn(move || r2.run(0, "test", f));
        std::thread::sleep(Duration::from_millis(20));
        assert!(r
            .run(0, "test", read(Arc::clone(&at_once), Arc::clone(&most)))
            .is_ok());
        assert!(other.join().unwrap().is_ok());
        assert_eq!(most.load(Ordering::SeqCst), 2, "root's beside each other");
    }

    /// Lot 366, the review of #573 (F4): the pump's waits on reads that
    /// answered slowly add up per user: past the budget within the window a
    /// record names the user and that the pump was slowed — once in the
    /// window, its reads counted; when the window ends it is retired, and
    /// signed again with its total when that grew (the re-check of #573,
    /// N2); fast reads add nothing; every user's together past theirs is
    /// signed too, naming the slowest.
    #[test]
    fn the_slow_read_budget_is_signed_naming_the_uid() {
        let t0 = Instant::now();
        let mut s = Slow::new(t0);
        let slow = Duration::from_millis(400);
        assert!(slow_add(&mut s, 1234, 1234, slow, t0).is_empty());
        assert!(slow_add(&mut s, 1234, 1234, slow, t0).is_empty());
        let out = slow_add(&mut s, 1234, 1234, slow, t0);
        let [SlowRecord::Sign(d)] = out.as_slice() else {
            panic!("one record past the budget: {out:?}");
        };
        assert!(
            d.starts_with("user 1234:") && d.contains("slowed") && d.contains("3 slow read"),
            "{d}"
        );
        assert!(
            slow_add(&mut s, 1234, 1234, slow, t0).is_empty(),
            "once per window"
        );
        let later = t0 + SLOW_WINDOW;
        let out = slow_add(&mut s, 1234, 1234, slow, later);
        let [SlowRecord::Retire(gone), SlowRecord::Ended(total)] = out.as_slice() else {
            panic!("retired with its window, its total signed: {out:?}");
        };
        assert_eq!(gone, d, "retired with its window");
        assert!(
            total.starts_with("user 1234:")
                && total.contains("1600 ms in the window that ended")
                && total.contains("4 slow read"),
            "{total}"
        );
        // every user's together
        let mut s = Slow::new(t0);
        let mut all = None;
        for uid in 2000..2020 {
            for r in slow_add(&mut s, uid, uid, slow, t0) {
                if let SlowRecord::Sign(d) = r {
                    all = Some(d);
                }
            }
        }
        let all = all.expect("every user's past theirs");
        assert!(
            all.starts_with("every user:") && all.contains("slowed"),
            "{all}"
        );
        // through the reader: the waits it measured
        let r = ExecReader::new(Duration::from_secs(2));
        for _ in 0..3 {
            assert_eq!(
                r.run(4321, "test", || std::thread::sleep(Duration::from_millis(
                    400
                ))),
                Ok(())
            );
            assert_eq!(r.run(4322, "test", || ()), Ok(()));
        }
        assert!(r
            .slow_signed(4321)
            .is_some_and(|d| d.starts_with("user 4321:")));
        assert!(r.slow_signed(4322).is_none(), "fast reads add nothing");
    }

    /// The re-check of #573 (N2): a user's record leaves the status once its
    /// window ends, at any later read — not only when that user is slow
    /// again; one record per user, however many of its ids are slow, and
    /// at most [`SLOW_KEPT`] users' records at once (past them, every
    /// user's names how many).
    #[test]
    fn the_slow_records_are_one_per_user_and_bounded() {
        let t0 = Instant::now();
        let slow = Duration::from_millis(400);
        let mut s = Slow::new(t0);
        // one user's 70 subordinate ids, three slow reads each
        let mut signed = Vec::new();
        for uid in 100_000..100_070u32 {
            for _ in 0..3 {
                signed.extend(slow_add(&mut s, uid, 1000, slow, t0));
            }
        }
        let own: Vec<_> = signed
            .iter()
            .filter(|r| matches!(r, SlowRecord::Sign(d) if d.starts_with("user 1000:")))
            .collect();
        assert_eq!(own.len(), 1, "one record for the user: {signed:?}");
        assert_eq!(s.by_uid.len(), 1, "one account");
        // a quiet minute: a fast read of anyone's retires it, with its total
        let out = slow_sweep(&mut s, t0 + SLOW_WINDOW);
        assert!(
            out.iter()
                .any(|r| matches!(r, SlowRecord::Retire(d) if d.starts_with("user 1000:")))
                && out
                    .iter()
                    .any(|r| matches!(r, SlowRecord::Ended(d) if d.contains("210 slow read"))),
            "{out:?}"
        );
        assert!(s.by_uid.is_empty() && s.next_end.is_none());
        assert!(slow_sweep(&mut s, t0 + SLOW_WINDOW * 2).is_empty(), "once");
        // a user's record alone (every user's below its budget): retired too
        let mut s = Slow::new(t0);
        let mut own = None;
        for _ in 0..3 {
            for r in slow_add(&mut s, 1000, 1000, slow, t0) {
                if let SlowRecord::Sign(d) = r {
                    own = Some(d);
                }
            }
        }
        let own = own.expect("the user's record");
        assert!(s.all.signed.is_none(), "every user's not signed");
        assert!(
            slow_sweep(&mut s, t0 + SLOW_WINDOW / 2).is_empty(),
            "its window runs"
        );
        assert_eq!(
            slow_sweep(&mut s, t0 + SLOW_WINDOW),
            vec![SlowRecord::Retire(own)],
            "retired at its window's end"
        );
        // 70 users: at most SLOW_KEPT records of users, and every user's
        let mut s = Slow::new(t0);
        let mut signs = 0;
        let mut every = None;
        for owner in 2000..2070u32 {
            for _ in 0..3 {
                for r in slow_add(&mut s, owner, owner, slow, t0) {
                    if let SlowRecord::Sign(d) = r {
                        if d.starts_with("every user:") {
                            every = Some(d);
                        } else {
                            signs += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(signs, SLOW_KEPT, "the users' records bounded");
        let every = every.expect("every user's signed");
        assert!(every.contains("user(s) past their own budget"), "{every}");
    }

    /// The re-check of #573 (N2, the review's probe B): one user's
    /// subordinate ids — and as many users — slow, three slow reads each,
    /// then a minute later one more: the slow records stay within their own
    /// budget of the registry, and the reads not waited for and a share
    /// held are still kept and signed. Fails where the slow records filled
    /// the registry (a79a10b9: 63 of them kept, the share held neither kept
    /// nor signed).
    #[test]
    fn the_slow_records_never_crowd_out_the_exec_signals() {
        use crate::boot::degradation as deg;
        let _g = deg::TEST_LOCK.lock();
        deg::reset_for_tests();
        let _told = deg::KeptTold::new();
        // as many users as ids (each its own account): the most records
        let r = ExecReader::with_owners(READ_DEADLINE, Some);
        let now = Instant::now();
        for uid in 100_000..100_070u32 {
            for _ in 0..3 {
                r.waited(uid, r.whose(uid), Duration::from_millis(400), now);
            }
        }
        let later = now + Duration::from_secs(61);
        r.waited(200_000, r.whose(200_000), Duration::from_millis(400), later);
        let slow = deg::snapshot()
            .iter()
            .filter(|l| l.starts_with(SLOW))
            .count();
        assert!(slow <= SLOW_RECORDS, "{slow} slow records kept");
        // other parts' notes fill the shared room
        for i in 0..deg::MAX_KEPT {
            deg::note("k366_test_other", &format!("{i}"));
        }
        // the users' share held, and reads not waited for
        let fast = ExecReader::new(Duration::from_millis(50));
        let mut releases = Vec::new();
        for uid in [1000, 1001] {
            let (tx, rx) = channel::<()>();
            releases.push(tx);
            assert!(fast
                .run(uid, "test", move || {
                    let _ = rx.recv();
                })
                .is_err());
        }
        let lines = deg::snapshot();
        assert!(
            lines.iter().any(|l| l.starts_with(HELD))
                && lines.iter().any(|l| l.starts_with(UNANSWERED)),
            "kept for the status: {lines:#?}"
        );
        // and signed
        let dir = tempfile::tempdir().unwrap();
        let key = crate::audit::AgentSigningKey::load_or_bootstrap(&dir.path().join("agent.sig"))
            .unwrap();
        let log = Arc::new(Mutex::new(
            crate::audit::AuditLog::open(&dir.path().join("audit.log"), key, [7u8; 16]).unwrap(),
        ));
        deg::attach_audit_log(Some(log));
        let rows: Vec<serde_json::Value> = std::fs::read_to_string(dir.path().join("audit.log"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|v| v["extra"]["kind"] == "subsystem_degraded")
            .map(|v| v["extra"]["source"].clone())
            .collect();
        for source in [HELD, UNANSWERED] {
            assert!(rows.iter().any(|s| s == source), "{source} signed");
        }
        drop(releases);
        drop(_told);
        deg::reset_for_tests();
    }

    /// The re-check of #573 (N3, the review's probe A): one user's reads —
    /// its own uid's and its subordinate ids' (`/etc/subuid`'s range of
    /// that user) — that do not answer hold one read of the users' share,
    /// not the share: another user's reads are answered, and root's. Fails
    /// where a read counted by uid (a79a10b9: the user's uid and one of its
    /// subordinate ids held the share, every other user's reads refused).
    #[test]
    fn one_user_s_subordinate_ids_starve_no_other_user() {
        fn owners(uid: u32) -> Option<u32> {
            Some(if (100_000..165_536).contains(&uid) {
                1000
            } else {
                uid
            })
        }
        let r = ExecReader::with_owners(Duration::from_millis(100), owners);
        let mut rel = Vec::new();
        for uid in [1000u32, 100_000, 100_001, 165_535] {
            let (tx, rx) = channel::<()>();
            rel.push(tx);
            let _ = r.run(uid, "probe", move || {
                let _ = rx.recv();
            });
        }
        assert_eq!(r.unanswered(), 1, "one read held for the user, all its ids");
        let t0 = Instant::now();
        let refused = r.run(100_002, "probe", || 0);
        assert!(
            refused
                .as_ref()
                .is_err_and(|why| why.contains("user 1000's (uid 100002)")),
            "{refused:?}"
        );
        assert!(t0.elapsed() < Duration::from_millis(100), "refused at once");
        for _ in 0..10 {
            assert_eq!(r.run(1001, "probe", || 1), Ok(1), "another user's read");
            assert_eq!(r.run(0, "probe", || 2), Ok(2), "root's");
        }
        assert!(!r.held_signed(1001), "the users' share not held");
        drop(rel);
    }

    /// The re-check of #573 (N3): a subordinate id counts as the account the
    /// published ranges give it (its owner's; root's ranges'); no uid of the
    /// 16-bit range as another's, whatever the ranges say. The re-check 2
    /// of #573 (M1): an id of no single known owner (the overflow row's) and
    /// an id of no range are no known user's — the unattributed ids' one
    /// account, never an account of their own (on f7dd98ce: the overflow
    /// account and the id itself, each a second account of the user that
    /// held it).
    #[test]
    fn a_subordinate_id_counts_as_its_owner_never_an_account_s_uid() {
        use common::wire::execq::{OVERFLOW_SHARE, ROOT_SUBID_SHARE};
        fn ranges(uid: u32) -> Option<u32> {
            match uid {
                100_000..=165_535 => Some(1000),
                1_000_000..=1_999_999 => Some(ROOT_SUBID_SHARE),
                300_000..=300_009 => Some(OVERFLOW_SHARE),
                // a range that claims the accounts' own uids
                0..=99_999 => Some(1000),
                _ => None,
            }
        }
        fn owners(uid: u32) -> Option<u32> {
            account_in(uid, ranges)
        }
        assert_eq!(account_in(100_000, ranges), Some(1000));
        assert_eq!(account_in(165_535, ranges), Some(1000));
        assert_eq!(account_in(1_500_000, ranges), Some(ROOT_SUBID_SHARE));
        assert_eq!(account_in(300_005, ranges), None, "no single known owner");
        assert_eq!(account_in(200_000, ranges), None, "no range");
        for (uid, who) in [
            (0, "root"),
            (1, "a system account"),
            (999, "the last system account"),
            (1001, "a user"),
            (60_000, "the users' last"),
            (65_534, "nobody"),
            (65_535, "the 16-bit range's last"),
        ] {
            assert_eq!(account_in(uid, ranges), Some(uid), "{who}: never another's");
        }
        assert_eq!(account_in(65_536, ranges), Some(1000), "from the floor up");
        let r = ExecReader::with_owners(READ_DEADLINE, owners);
        assert_eq!(r.whose(100_001).account, 1000);
        assert_eq!(r.whose(1001).account, 1001);
        assert!(of_whom(1_500_000, r.whose(1_500_000)).starts_with("root's subordinate ids'"));
        for uid in [300_005, 200_000] {
            assert_eq!(
                r.whose(uid),
                Whose {
                    pool: Pool::Unattributed,
                    account: UNATTRIBUTED
                },
                "no known user's: the unattributed ids'"
            );
        }
        assert!(of_whom(200_000, r.whose(200_000)).starts_with("the unattributed ids'"));
        assert!(account_words(UNATTRIBUTED).starts_with("the unattributed ids"));
    }

    /// The re-check of #573 (N3): the agent's reader counts a uid by the
    /// ranges the agent publishes (`share_subuid`'s table, kept for it):
    /// a subordinate id as its owner's account, root's ranges as theirs;
    /// an id of no single known owner, past every range, or of any range
    /// while none are published, as no known user's (the re-check 2 of
    /// #573, M1: on f7dd98ce each was an account of the users' share).
    #[test]
    fn the_reader_counts_by_the_ranges_the_agent_publishes() {
        use crate::sensors::share_subuid as s;
        let _g = s::PUBLISHED_TEST_LOCK.lock();
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n";
        s::keep(&s::table(
            &s::ranges("alice:100000:65536\nroot:1000000:1000\n", passwd),
            s::TABLE_MAX,
        ));
        let r = ExecReader::new(READ_DEADLINE);
        assert_eq!(r.whose(100_005).account, 1000);
        assert_eq!(
            r.whose(1_000_005).account,
            common::wire::execq::ROOT_SUBID_SHARE
        );
        assert_eq!(r.whose(1000).account, 1000);
        assert_eq!(
            r.whose(500_000).pool,
            Pool::Unattributed,
            "a gap between ranges: no single known owner"
        );
        assert_eq!(
            r.whose(2_000_000).pool,
            Pool::Unattributed,
            "past every range"
        );
        s::keep(&s::Table::default());
        assert_eq!(r.whose(100_005).pool, Pool::Unattributed, "none published");
        assert_eq!(
            r.whose(1000).account,
            1000,
            "a user's own uid, whatever is published"
        );
    }

    /// A `/etc/passwd` that names root and alice (1000) alone.
    const PASSWD_TEXT: &str =
        "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n";

    /// The re-check 2 of #573 (M1), with the production reader and the
    /// ranges published as `t`: a read of the user's own uid `own` held, and
    /// one of `ids[0]`, an id `t` gives no known user — another user's
    /// reads, root's and a system account's are answered, the users' share
    /// not held: the id counts in the unattributed ids' share, one read
    /// held at most, so another unattributed id (`ids[1]`) is refused at
    /// once, the share signed held once while it lasts. The unattributed
    /// ids hold each other's reads, never an attributed user's. On f7dd98ce
    /// the id was a second account of the users' share: with the user's
    /// own, it held the share, every other user's reads refused (the
    /// review's probe A2).
    fn unattributed_ids_starve_no_attributed_user(
        t: &crate::sensors::share_subuid::Table,
        own: u32,
        ids: [u32; 2],
    ) {
        use crate::sensors::share_subuid as s;
        s::keep(t);
        let r = ExecReader::new(Duration::from_millis(100));
        for id in ids {
            assert_eq!(r.whose(id).pool, Pool::Unattributed, "no known user's");
        }
        let mut rel = Vec::new();
        for uid in [own, ids[0]] {
            let (tx, rx) = channel::<()>();
            rel.push(tx);
            let got = r.run(uid, "probe", move || {
                let _ = rx.recv();
            });
            assert!(got.is_err(), "held past its deadline");
        }
        assert_eq!(r.unanswered(), 2, "the user's read and the id's held");
        for _ in 0..10 {
            assert_eq!(r.run(1001, "probe", || 1), Ok(1), "another user's read");
            assert_eq!(r.run(0, "probe", || 2), Ok(2), "root's");
            assert_eq!(r.run(104, "probe", || 3), Ok(3), "a system account's");
        }
        assert!(!r.held_signed(1001), "the users' share not held");
        let t0 = Instant::now();
        for _ in 0..5 {
            let refused = r.run(ids[1], "probe", || 4);
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|why| why.contains("the unattributed ids' share")),
                "another unattributed id: refused, their share held"
            );
        }
        assert!(t0.elapsed() < Duration::from_millis(100), "refused at once");
        assert!(
            r.held_signed(ids[1]),
            "the unattributed ids' share signed held"
        );
        assert_eq!(
            r.held[Pool::Unattributed.index()].lock().reports(),
            1,
            "once per episode"
        );
        assert_eq!(r.unanswered(), 2, "no read started for them");
        // the held reads answer: the share's record ends (past its hold)
        drop(rel);
        let t = Instant::now();
        while r.unanswered() != 0 && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        r.answered_at(Instant::now() + Duration::from_secs(61));
        assert!(!r.held_signed(ids[1]), "ended once the share has room");
        s::keep(&s::Table::default());
    }

    /// M1, no ranges published (the file-open sensor on its tracepoint,
    /// before the first publish): every id from 65536 up is no known
    /// user's.
    #[test]
    fn unattributed_ids_none_published_starve_no_attributed_user() {
        use crate::sensors::share_subuid as s;
        let _g = s::PUBLISHED_TEST_LOCK.lock();
        unattributed_ids_starve_no_attributed_user(&s::Table::default(), 1000, [100_000, 165_535]);
    }

    /// M1, `/etc/subuid` unreadable: every id from 65536 up is the overflow
    /// row's — no known user's.
    #[test]
    fn unattributed_ids_subuid_unreadable_starve_no_attributed_user() {
        use crate::sensors::share_subuid as s;
        let _g = s::PUBLISHED_TEST_LOCK.lock();
        unattributed_ids_starve_no_attributed_user(&s::unreadable(), 1000, [100_000, 70_000]);
    }

    /// M1, a range whose owner `/etc/passwd` does not name (an sssd or
    /// LDAP user's, by name): its ids are the overflow row's — no known
    /// user's; the named user's ids stay its own.
    #[test]
    fn unattributed_ids_owner_not_in_passwd_starve_no_attributed_user() {
        use crate::sensors::share_subuid as s;
        let _g = s::PUBLISHED_TEST_LOCK.lock();
        let t = s::table(
            &s::ranges("alice:100000:65536\nldapuser:296608:65536\n", PASSWD_TEXT),
            s::TABLE_MAX,
        );
        unattributed_ids_starve_no_attributed_user(&t, 5000, [296_608, 300_000]);
        s::keep(&t);
        let r = ExecReader::new(READ_DEADLINE);
        assert_eq!(
            r.whose(100_005).account,
            1000,
            "a named owner's id: its own"
        );
        s::keep(&s::Table::default());
    }

    /// M1, an id past every range (a range added since the last publish, a
    /// transient one `/etc/subuid` does not list): no known user's.
    #[test]
    fn unattributed_ids_past_every_range_starve_no_attributed_user() {
        use crate::sensors::share_subuid as s;
        let _g = s::PUBLISHED_TEST_LOCK.lock();
        let t = s::table(
            &s::ranges("alice:100000:65536\nroot:1000000:1000\n", PASSWD_TEXT),
            s::TABLE_MAX,
        );
        unattributed_ids_starve_no_attributed_user(&t, 1000, [2_147_483_648, 2_000_000]);
    }

    /// The re-check of #573 (N7): systemd's dynamic users and `nobody` are
    /// the system's accounts, not the users'; the 16-bit gap above them and
    /// the ids past 65535 are the users'.
    #[test]
    fn dynamic_users_and_nobody_are_the_system_s() {
        for (uid, who) in [
            (1, "a system account"),
            (999, "the last system account"),
            (61_184, "the first dynamic user"),
            (63_000, "a dynamic user"),
            (65_519, "the last dynamic user"),
            (65_534, "nobody"),
            (65_535, "the 16-bit range's last"),
        ] {
            assert_eq!(Pool::of(uid), Pool::System, "{who}: the system's");
        }
        for (uid, who) in [
            (1000, "the first user"),
            (60_000, "the users' last"),
            (61_183, "below the dynamic users"),
            (65_520, "the gap's first"),
            (65_533, "the gap's last"),
            (65_536, "the first subordinate id"),
            (100_000, "a subordinate id"),
        ] {
            assert_eq!(Pool::of(uid), Pool::Users, "{who}: the users'");
        }
        assert_eq!(Pool::of(0), Pool::Root);
    }

    /// Lot 366: a mount made since the table was read: within
    /// [`REFRESH_MIN`] of the last read the table is not read again, and its
    /// mount is not trusted (signed); past it the table is read again and
    /// the new mount judged by its type; a FUSE mounted at once in its place
    /// — given its mount id, or its device, back — is not vouched for by the
    /// table read before. In a user and mount namespace of the test's own.
    #[test]
    fn a_mount_made_since_the_table_is_judged_only_once_read() {
        // the statics the child reads and signs through, made before the
        // fork (one being made at the fork would never be in the child)
        let _ = STALE.lock().holding();
        let _ = kernel_roots::views();
        let rc = crate::fuse_testing::in_userns(|| {
            let dir = std::env::temp_dir().join(format!("nn-k366-mounts-{}", std::process::id()));
            if std::fs::create_dir(&dir).is_err() {
                return 99;
            }
            let m = Mutex::new(Mounts::new("/proc/self/mountinfo"));
            let before = judge_of(&m);
            let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: NUL-terminated strings; a tmpfs of the test's own
            // namespace.
            if unsafe {
                libc::mount(
                    c"t".as_ptr(),
                    c.as_ptr(),
                    c"tmpfs".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            } != 0
            {
                return 99;
            }
            let id = kernel_roots::cached(&File::open(&dir).unwrap()).unwrap();
            let stale = counts().1;
            let rc = if before.trusts(&id) {
                1
            } else if judge_of(&m).trusts(&id) || counts().1 == stale {
                2
            } else {
                std::thread::sleep(REFRESH_MIN + Duration::from_millis(100));
                if judge_of(&m).trusts(&id) {
                    0
                } else {
                    3
                }
            };
            // SAFETY: as above.
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
            if rc != 0 {
                let _ = std::fs::remove_dir(&dir);
                return rc;
            }
            let rc = match crate::fuse_testing::smart_fuse_over(&dir, 0) {
                Some(fuse) => {
                    let root = std::os::unix::fs::OpenOptionsExt::custom_flags(
                        std::fs::OpenOptions::new().read(true),
                        libc::O_PATH | libc::O_DIRECTORY,
                    )
                    .open(&dir)
                    .unwrap();
                    let now = kernel_roots::cached(&root).unwrap();
                    let trusted = judge_of(&m).trusts(&now);
                    drop(root);
                    drop(fuse);
                    // SAFETY: as above.
                    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
                    if trusted {
                        4
                    } else {
                        0
                    }
                }
                None => 0,
            };
            let _ = std::fs::remove_dir(&dir);
            rc
        });
        if let Some(rc) = crate::fuse_testing::ran(rc) {
            assert_eq!(
                rc, 0,
                "1: trusted before its read, 2: stale (or not signed), 3: never read again, \
                 4: a FUSE vouched for"
            );
        }
    }

    /// Lot 366, the review of #573 (F2): the judge asks a file system by
    /// the mount the kernel reached the file through (its id), never by the
    /// file's device — not a FUSE one, not one no table shows.
    #[test]
    fn only_a_mount_the_table_shows_and_not_fuse_is_asked() {
        let c = here();
        assert!(judge(&line(c.mnt_id, c.dev, "ext4")).trusts(&c));
        for fstype in ["fuse", "fuse.sshfs", "fuseblk", "fuse.App.AppImage"] {
            assert!(
                !judge(&line(c.mnt_id, c.dev, fstype)).trusts(&c),
                "{fstype}"
            );
        }
        assert!(!judge("").trusts(&c), "no such mount");
        assert!(
            !judge(&line(c.mnt_id + 1, c.dev, "ext4")).trusts(&c),
            "another mount of the same device"
        );
        let two = format!(
            "{}{}",
            line(c.mnt_id + 1, c.dev, "fuse.x"),
            line(c.mnt_id, c.dev, "ext4")
        );
        assert!(judge(&two).trusts(&c), "its own mount decides");
        assert!(trusted_in(
            &crate::mountinfo::parse(line(c.mnt_id, c.dev, "ext4").as_bytes()),
            &c
        ));
        assert!(never_asked(OsStr::new("fuse.App.AppImage")));
        assert!(!never_asked(OsStr::new("ext4")) && !never_asked(OsStr::new("nfs4")));
    }

    /// Lot 366, the review of #573 (F2): a btrfs subvolume's file shows a
    /// device of its own (`statx`'s), which no table shows: judged by its
    /// mount (id), it is asked. Fails where the judge went by the device
    /// (bad1b957: every file of a btrfs root or home refused, every
    /// AppImage killed).
    #[test]
    fn a_btrfs_subvolume_s_file_is_judged_by_its_mount() {
        let c = here();
        let sb = 31;
        assert_ne!(c.dev, sb);
        assert!(judge(&line(c.mnt_id, sb, "btrfs")).trusts(&c));
        // a walk through a process of another namespace: its own table
        // shows the mount, PID 1's the file system
        let proc = tempfile::tempdir().unwrap();
        let other = c.mnt_id + 7000;
        std::fs::write(proc.path().join("mountinfo"), line(other, sb, "btrfs")).unwrap();
        let copy = Cached { mnt_id: other, ..c };
        let host = judge(&line(c.mnt_id, sb, "btrfs"));
        assert!(!host.trusts(&copy), "not the host's mount");
        assert!(host.of_process(proc.path()).trusts(&copy), "the process's");
        // a file system made in that namespace (no host table shows it)
        std::fs::write(proc.path().join("mountinfo"), line(other, 99, "tmpfs")).unwrap();
        assert!(!host.of_process(proc.path()).trusts(&copy), "made there");
    }

    /// Lot 366, the review of #573 (F2): a walk through a process's `/proc`
    /// entry (its root, its `exe`) is judged by that process's own table
    /// when no host table shows the mount (another mount namespace's: a
    /// container's) — asked when the host's tables show its file system,
    /// not when none is read.
    #[test]
    fn a_walk_through_a_process_judges_by_its_own_table() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir(t.path().join("d")).unwrap();
        std::fs::write(t.path().join("d/f"), b"x").unwrap();
        let c = kernel_roots::cached(&File::open(t.path()).unwrap()).unwrap();
        let proc = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(t.path(), proc.path().join("root")).unwrap();
        std::os::unix::fs::symlink(t.path().join("d/f"), proc.path().join("exe")).unwrap();
        // the host's tables: the file system, by another mount
        let host = judge(&line(c.mnt_id + 9000, c.dev, "ext4"));
        let exe = proc.path().join("exe");
        assert!(walk_in_root(proc.path(), Path::new("d/f"), &host).is_err());
        assert!(open_exe(&exe, libc::O_RDONLY, &host).is_err());
        std::fs::write(proc.path().join("mountinfo"), line(c.mnt_id, c.dev, "ext4")).unwrap();
        assert!(walk_in_root(proc.path(), Path::new("d/f"), &host).is_ok());
        assert!(open_exe(&exe, libc::O_RDONLY, &host).is_ok());
    }

    /// Lot 366, the review of #573 (F2): a network file system root mounted
    /// (NFS, CIFS) is read — on the exec pumps' reader, with its deadline:
    /// a home there keeps its AppImage's tie, and a server that does not
    /// answer holds a helper, never the pump.
    #[test]
    fn nfs_and_cifs_are_read_on_the_reader_with_its_deadline() {
        let c = here();
        for fstype in ["nfs", "nfs4", "cifs", "smb3"] {
            assert!(judge(&line(c.mnt_id, 50, fstype)).trusts(&c), "{fstype}");
        }
        let r = ExecReader::new(Duration::from_millis(100));
        let (tx, rx) = channel::<()>();
        let t0 = Instant::now();
        assert!(r
            .run(1000, "nfs", move || {
                let _ = rx.recv();
            })
            .is_err());
        assert!(t0.elapsed() < Duration::from_secs(2), "the deadline");
        assert!(r.not_waited_now(), "signed");
        drop(tx);
    }

    /// Lot 366: a table with a change of the mounts not read yet vouches
    /// only for a block device's file system, the file on that very device;
    /// any other file is judged not verified, counted and signed.
    #[test]
    fn a_stale_table_vouches_only_for_a_block_device() {
        let c = here();
        let stale = |text: &str| Judge {
            tables: vec![(mounted(&crate::mountinfo::parse(text.as_bytes())), false)],
            process: None,
            own: Arc::default(),
        };
        let block = Cached {
            dev: (8 << 20) | 1,
            ..c
        };
        assert!(stale(&line(c.mnt_id, block.dev, "ext4")).trusts(&block));
        let anon = Cached { dev: 40, ..c };
        let before = counts().1;
        assert!(
            !stale(&line(c.mnt_id, 40, "tmpfs")).trusts(&anon),
            "anonymous"
        );
        assert!(
            !stale(&line(c.mnt_id, 31, "btrfs")).trusts(&anon),
            "another device"
        );
        assert!(!stale("").trusts(&anon), "a mount made since");
        assert!(counts().1 >= before + 3, "counted");
        assert!(STALE.lock().holding(), "signed");
    }
}
