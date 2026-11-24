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
//!   /bin/bash ~/x` is bash whatever its name (N1). Lot 313 (the review of
//!   #549, F1): bounded, as it runs on the exec ring's one thread — an
//!   answer is remembered by the file's `(dev, ino, size, ctime)` (the same
//!   file is never read twice), a file is compared whole up to 4 MiB and by
//!   samples above (its first and last MiB and eight blocks between: at
//!   most ~2.5 MiB per pair, four pairs at most), and the compares share a
//!   budget of 64 MiB a second; past it an exec is not compared (counted:
//!   `status`'s `program_copy_skipped_total`), judged by its name as before.
//!   Under the dynamic loader (`ld.so /path/x`) the file compared is the
//!   loader's operand (F4).
//!
//! - Lot 347 ([`read_runtime_clone`], the same step): a memfd exec whose
//!   parent runs an installed OCI runtime or its manager (by the identity of
//!   its image, one `stat`) has its memfd — sealed against writing,
//!   shrinking and growing AT THE EXEC (the LSM program's record,
//!   `exe_flags::MEMFD_SEALED`: the review of #556, F1) — compared WHOLE,
//!   byte for byte, with the installed runtimes of its length (`runc`
//!   re-executes itself from such a copy, the CVE-2019-5736 defence); R004
//!   then judges the lineage. The runtimes are recorded with the shells, and
//!   again at such an exec (at most once a second: a runtime installed this
//!   minute), under a budget of their own: each uid's share, root's reserve
//!   ([`RUNTIME_BUDGET_PER_UID`], [`RUNTIME_ROOT_RESERVE`]: the review of
//!   #556, F2; the review of #585, F2: each uid's share a token bucket, up
//!   to [`RUNTIME_BURST_PER_UID`] at once, a rootless user's container
//!   starts in a loop); a clone past it is kept unverified, "not compared (budget)"
//!   (R004: root's recorded, never killed; any other uid's the Critical
//!   kill — the re-check of #556, N1: a user spends its own share).
//!   Lot 381: a copy whose process was gone before the read is read
//!   through a child of the exec's parent still running that very memfd
//!   ([`open_copy`]; the review of #588, F1: or through a thread of its own
//!   still running, its leader exited alone); none left, it is "not
//!   compared (gone)" — kept unverified with the runtime its parent runs
//!   only in runc 1.1's re-exec (the review of #588, F2), else nothing
//!   kept. Every such exec lands in exactly one counter
//!   ([`RuntimeCloneCounts`]), once ([`Settle`]: the review of #588, F3).
//!
//! A name only chooses which installed files are recorded; what an exec
//! runs is then told by the file, never by its name.

use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::sensors::pump_reads::Judge;
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
const MAX_COMPARED: usize = 4;

/// Lot 313 (F1): a file this long or shorter is compared whole.
const WHOLE_LEN: u64 = 4 << 20;
/// … a longer one by samples: its first and last `EDGE` bytes, and
/// `BLOCKS` blocks of `BLOCK` bytes evenly between.
const EDGE: u64 = 1 << 20;
const BLOCK: u64 = 64 << 10;
const BLOCKS: u64 = 8;
/// The bytes one uid's compares may read in a second (both files counted).
const BUDGET_PER_SECOND: u64 = 64 << 20;
/// … and every uid's together (the re-check 2 of #549, N1: a user with
/// many host uids — the subuids rootless podman maps — reads no more).
const GLOBAL_BUDGET_PER_SECOND: u64 = 128 << 20;
/// The answers remembered, by file, at most (the oldest out).
const MEMO_CAP: usize = 1024;
/// The uids whose budgets are kept at once (the least recently used out).
const UIDS_CAP: usize = 256;

/// Lot 313 (the re-check of #549, R2): where the distributions install the
/// dynamic loader — recorded with the shells, so a renamed copy of it is
/// the loader too.
const LOADER_PATHS: &[&str] = &[
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/ld-linux-aarch64.so.1",
    "/lib/ld-linux-armhf.so.3",
    "/lib/ld-linux.so.2",
    "/lib64/ld64.so.2",
    "/lib/ld64.so.1",
    "/lib/ld-musl-x86_64.so.1",
    "/lib/ld-musl-aarch64.so.1",
    "/usr/lib64/ld-linux-x86-64.so.2",
];

/// A file by what changes when its content can: `(dev, ino, size, ctime)`.
type FileKey = (u64, u64, u64, i64, i64);

/// The answers by file, and their order (the oldest first out).
type Memo = (HashMap<FileKey, Option<ProgramKind>>, VecDeque<FileKey>);

/// Lot 313 (F1): what bounds the content check — the answers it gave, by
/// file, and the bytes its compares read in the current second; its counts
/// for `status`.
pub struct Bounds {
    memo: Mutex<Memo>,
    spent: Mutex<Spent>,
    budget: u64,
    global_budget: u64,
    /// The review of #556 (F2): root's own budget, and the part of the
    /// global one the other uids together never spend (root's reserve).
    root_budget: u64,
    root_reserve: u64,
    /// The review of #585 (F2): a uid but root may read up to this much at
    /// once, its share paying it back at `budget` a second (a token bucket:
    /// a rootless user's container starts in a loop, their compares
    /// bunched); 0: no more than `budget` in any second, as before.
    burst: u64,
    compared: AtomicU64,
    skipped: AtomicU64,
    remembered: AtomicU64,
}

/// The bytes the compares read in the current second: each uid's (the
/// re-check of #549, R1: one user's flood spends only that user's) and all
/// of them (its re-check 2, N1).
#[derive(Default)]
struct Spent {
    /// uid → what it read.
    uids: HashMap<u32, UidSpent>,
    /// every uid's: (the second's start, the bytes read in it).
    all: Option<(Instant, u64)>,
}

/// One uid's reads ([`Spent::uids`]).
#[derive(Clone, Copy)]
struct UidSpent {
    /// Its second's start and the bytes it read in it.
    second: Instant,
    read: u64,
    /// Its last take.
    last: Instant,
    /// The review of #585 (F2): the bytes its burst owes ([`Bounds::burst`])
    /// as of `owed_at`, paid back at its share's rate.
    owed: u64,
    owed_at: Instant,
}

impl UidSpent {
    fn new(now: Instant) -> Self {
        Self {
            second: now,
            read: 0,
            last: now,
            owed: 0,
            owed_at: now,
        }
    }

    /// What its burst owes at `now`, `rate` bytes paid back a second.
    fn owed_at(&self, now: Instant, rate: u64) -> u64 {
        let paid = now.duration_since(self.owed_at).as_nanos() * u128::from(rate) / 1_000_000_000;
        self.owed
            .saturating_sub(u64::try_from(paid).unwrap_or(u64::MAX))
    }
}

impl Bounds {
    fn new(budget: u64, global_budget: u64) -> Self {
        Self::with_root_reserve(budget, global_budget, 0)
    }

    /// The review of #556 (F2): each uid but root spends `budget` a second,
    /// all of them together `global_budget - root_reserve`; root spends up
    /// to `global_budget` — no user's flood spends root's container starts.
    fn with_root_reserve(budget: u64, global_budget: u64, root_reserve: u64) -> Self {
        Self {
            memo: Mutex::new((HashMap::new(), VecDeque::new())),
            spent: Mutex::new(Spent::default()),
            budget,
            global_budget,
            root_budget: if root_reserve == 0 {
                budget
            } else {
                global_budget
            },
            root_reserve: root_reserve.min(global_budget),
            burst: 0,
            compared: AtomicU64::new(0),
            skipped: AtomicU64::new(0),
            remembered: AtomicU64::new(0),
        }
    }

    fn recall(&self, key: &FileKey) -> Option<Option<ProgramKind>> {
        self.memo.lock().0.get(key).copied()
    }

    fn remember(&self, key: FileKey, kind: Option<ProgramKind>) {
        let mut m = self.memo.lock();
        if m.0.insert(key, kind).is_none() {
            m.1.push_back(key);
        }
        while m.1.len() > MEMO_CAP {
            if let Some(old) = m.1.pop_front() {
                m.0.remove(&old);
            }
        }
    }

    /// `bytes` taken from `uid`'s budget and from every uid's for this
    /// second; `false` when they do not fit in either (nothing is taken).
    /// The review of #556 (F2): a uid but root fits in the global budget
    /// less root's reserve. The review of #585 (F2): with a burst, a uid but
    /// root fits while what its burst owes, with `bytes`, is no more than
    /// the burst — whatever it read this second (the global budget's second
    /// still bounds every uid's together).
    fn take(&self, uid: u32, bytes: u64, now: Instant) -> bool {
        let second = Duration::from_secs(1);
        let mut s = self.spent.lock();
        let all = match s.all {
            Some((t, n)) if now.duration_since(t) < second => (t, n),
            _ => (now, 0),
        };
        let (budget, global) = if uid == 0 {
            (self.root_budget, self.global_budget)
        } else {
            (self.budget, self.global_budget - self.root_reserve)
        };
        if all.1.saturating_add(bytes) > global {
            s.all = Some(all);
            return false;
        }
        if s.uids.len() >= UIDS_CAP && !s.uids.contains_key(&uid) {
            // the review of #585 (F2): a uid whose burst still owes is kept
            let rate = self.budget;
            s.uids
                .retain(|_, e| now.duration_since(e.second) < second || e.owed_at(now, rate) > 0);
            // never all of them at once (the re-check 2 of #549, N1: that
            // gave each uid its budget again): the least recently used out
            while s.uids.len() >= UIDS_CAP {
                let Some(oldest) = s
                    .uids
                    .iter()
                    .min_by_key(|(_, e)| e.last)
                    .map(|(uid, _)| *uid)
                else {
                    break;
                };
                s.uids.remove(&oldest);
            }
        }
        let bursts = uid != 0 && self.burst != 0;
        let e = s.uids.entry(uid).or_insert(UidSpent::new(now));
        if now.duration_since(e.second) >= second {
            (e.second, e.read) = (now, 0);
        }
        e.last = now;
        if bursts {
            let owed = e.owed_at(now, budget);
            if owed.saturating_add(bytes) > self.burst {
                return false;
            }
            (e.owed, e.owed_at) = (owed + bytes, now);
        } else if e.read.saturating_add(bytes) > budget {
            return false;
        }
        e.read += bytes;
        s.all = Some((all.0, all.1 + bytes));
        true
    }
}

impl Bounds {
    /// The review of #578 (N3): the uid that read the most in the second
    /// running at `now`, and how many bytes — who spent the budget.
    fn top_spender(&self, now: Instant) -> Option<(u32, u64)> {
        let second = Duration::from_secs(1);
        self.spent
            .lock()
            .uids
            .iter()
            .filter(|(_, e)| e.read > 0 && now.duration_since(e.second) < second)
            .max_by_key(|(uid, e)| (e.read, std::cmp::Reverse(**uid)))
            .map(|(uid, e)| (*uid, e.read))
    }
}

/// The content check's bounds: one exec pump, one host.
static BOUNDS: LazyLock<Bounds> =
    LazyLock::new(|| Bounds::new(BUDGET_PER_SECOND, GLOBAL_BUDGET_PER_SECOND));

/// Lot 313 (F1): the content check since the agent's start — running images
/// compared, execs not compared because the second's budget was spent, and
/// answers recalled without a read.
pub fn counts() -> (u64, u64, u64) {
    (
        BOUNDS.compared.load(Ordering::Relaxed),
        BOUNDS.skipped.load(Ordering::Relaxed),
        BOUNDS.remembered.load(Ordering::Relaxed),
    )
}

/// The bytes one comparison of two `len`-byte files reads (both files).
fn compare_cost(len: u64) -> u64 {
    2 * if len <= WHOLE_LEN {
        len
    } else {
        2 * EDGE + BLOCKS * BLOCK
    }
}

/// The ranges compared for a `len`-byte file: whole, or by samples.
fn compared_ranges(len: u64) -> Vec<(u64, u64)> {
    if len <= WHOLE_LEN {
        return vec![(0, len)];
    }
    let mut r = vec![(0, EDGE), (len - EDGE, EDGE)];
    let span = len - 2 * EDGE - BLOCK;
    for i in 0..BLOCKS {
        r.push((EDGE + span * i / (BLOCKS - 1), BLOCK));
    }
    r
}

/// `a` and the file at `b` hold the same bytes over [`compared_ranges`];
/// `b` is `len` bytes long.
fn same_sampled(a: &std::fs::File, b: &Path, len: u64) -> bool {
    same_over(a, b, len, None, &compared_ranges(len))
}

/// `a` and the file at `b` hold the same bytes over `ranges`; `b` is `len`
/// bytes long and, with `id`, the file of that identity (the kernel's
/// device form, its inode: lot 347, the image recorded, not one an upgrade
/// put at its path since).
fn same_over(
    a: &std::fs::File,
    b: &Path,
    len: u64,
    id: Option<(u64, u64)>,
    ranges: &[(u64, u64)],
) -> bool {
    // lot 353 (#563, the lab's FUSE over /proc): beneath the anchored root
    let Ok(fb) = antitamper_bpf::kernel_roots::open(b, libc::O_RDONLY) else {
        return false;
    };
    let Ok(mb) = fb.metadata() else {
        return false;
    };
    if !mb.is_file() || mb.len() != len {
        return false;
    }
    if id.is_some_and(|id| id != kernel_id(&mb)) {
        return false;
    }
    let mut ba = vec![0u8; 64 * 1024];
    let mut bb = vec![0u8; 64 * 1024];
    for &(from, n) in ranges {
        let mut at = from;
        while at < from + n {
            let k = (from + n - at).min(ba.len() as u64) as usize;
            if a.read_exact_at(&mut ba[..k], at).is_err()
                || fb.read_exact_at(&mut bb[..k], at).is_err()
                || ba[..k] != bb[..k]
            {
                return false;
            }
            at += k as u64;
        }
    }
    true
}

/// A file's identity as the exec sensor reports an executed file: its
/// device in the kernel's form (`MKDEV`), its inode.
fn kernel_id(m: &std::fs::Metadata) -> (u64, u64) {
    (
        crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        m.ino(),
    )
}

/// `path` (followed) as an installed program of `kind`, under `root`
/// (`/` on the host). The review of #556 (F7): an OCI runtime or manager
/// only when its file is one only root can change ([`root_only_path`]).
fn image_of(path: &Path, kind: ProgramKind, root: &Path) -> Option<InstalledImage> {
    let real = std::fs::canonicalize(path).ok()?;
    let m = antitamper_bpf::kernel_roots::metadata(&real).ok()?;
    if !m.is_file() {
        return None;
    }
    if kind.is_container_runtime() && !root_only_path(&real, root) {
        return None;
    }
    Some(InstalledImage {
        id: kernel_id(&m),
        len: m.len(),
        path: real.to_string_lossy().into_owned(),
        kind,
    })
}

/// The review of #556 (F7): `real` (a resolved file or directory) and every
/// directory above it up to `root` belong to `root`'s owner (root, on the host) and
/// are writable by no one else (no group or other write bit) — a file only
/// root can change or replace. A link in a binary directory to a file a
/// user can rewrite (`/usr/local/bin/runc` → `/home/u/runc`), or a
/// group-writable `/usr/local/bin` (Debian's old `staff`), records no
/// runtime or manager: its file anchors R004's identity and its compare.
/// The shells' records give no trust (a copy found to be a shell is judged
/// as one) and are not narrowed.
pub(crate) fn root_only_path(real: &Path, root: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    let Ok(owner) = antitamper_bpf::kernel_roots::metadata(&root).map(|m| m.uid()) else {
        return false;
    };
    real.starts_with(&root)
        && real
            .ancestors()
            .take_while(|a| a.starts_with(&root))
            .all(|a| {
                antitamper_bpf::kernel_roots::metadata(a)
                    .is_ok_and(|m| m.uid() == owner && m.mode() & 0o022 == 0)
            })
}

/// The kind of an installed file, by the name of the file a path resolves
/// to (`/usr/bin/sh` → `dash`; `/bin/sh` on Alpine → `busybox`; lot 347:
/// `/usr/sbin/runc` an OCI runtime, `/usr/bin/containerd-shim-runc-v2` its
/// manager).
fn kind_of(path: &Path) -> Option<ProgramKind> {
    let real = std::fs::canonicalize(path).ok()?;
    ProgramKind::of_installed_name(&real.to_string_lossy())
}

/// The installed programs under `root` (`/` on the host, a test's tree):
/// `/etc/shells`' and the binary directories'.
pub fn installed_under(root: &Path) -> Vec<InstalledImage> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(text) = antitamper_bpf::kernel_roots::read_all(root.join("etc/shells")) {
        for line in String::from_utf8_lossy(&text).lines() {
            let line = line.trim();
            if line.starts_with('/') {
                paths.push(root.join(line.trim_start_matches('/')));
            }
        }
    }
    // the dynamic loader (the re-check of #549, R2)
    paths.extend(
        LOADER_PATHS
            .iter()
            .map(|p| root.join(p.trim_start_matches('/'))),
    );
    // lot 347: podman's conmon where it is no binary directory's
    paths.extend(
        RUNTIME_EXTRA_PATHS
            .iter()
            .map(|p| root.join(p.trim_start_matches('/'))),
    );
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
        let Some(image) = kind_of(&p).and_then(|k| image_of(&p, k, root)) else {
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

/// The exec pump's step (module docs): lot 313's socket-stdio execs, and
/// (lot 347) a memfd exec's runtime clone ([`read_runtime_clone`]) —
/// counted and kept unless `settle` was taken by [`not_read`] already (the
/// review of #588, F3).
pub fn read_and_keep(event: &Event, settle: &Settle) {
    read_and_keep_at(event, Path::new("/proc"));
    read_runtime_clone(event, settle);
}

/// The review of #588 (F3): one exec's runtime compare settled once — by
/// the pump's step that read it ([`read_and_keep`]) or by [`not_read`]
/// when the pump stopped waiting for that step, whichever comes first; the
/// other then counts nothing and keeps nothing. A step that finished past
/// its deadline counted the exec a second time (`not_read` had counted it)
/// and kept a clone R004 had judged the exec without.
#[derive(Clone, Debug, Default)]
pub struct Settle(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl Settle {
    /// Whether this caller settles the exec: the first to ask.
    fn take(&self) -> bool {
        !self.0.swap(true, Ordering::AcqRel)
    }
}

/// Lot 366: whether [`read_and_keep`] reads anything of `event` — the
/// union of its steps' own gates, each the very test its step starts with:
/// an exec with its stdio, or its parent's, on an inet socket
/// ([`reads_socket_exec`]); lot 369: a memfd exec sealed at the exec
/// ([`reads_runtime_clone`]). Lot 366 gated the pump's hand-over on the
/// first alone, so runc 1.1's sealed clone of itself was never compared
/// again: R004 Critical at every container start on Debian 13 (the soak of
/// rc5). A step gated here by a test of its own drifts from it no more.
pub fn reads(event: &Event) -> bool {
    reads_socket_exec(event) || reads_runtime_clone(event)
}

/// Lot 313's step ([`read_and_keep_judged`]): an exec with its stdio, or
/// its parent's, on an inet socket.
fn reads_socket_exec(event: &Event) -> bool {
    matches!(event, Event::ProcessSpawn { stdio, .. }
        if stdio.own.stdin_or_stdout_inet() || stdio.parent.stdin_or_stdout_inet())
}

/// Lot 347's step ([`read_runtime_clone_with`]): a memfd exec the LSM
/// program described (`KNOWN`), sealed when the kernel executed it
/// (`MEMFD_SEALED`, the review of #556, F1), of a process and a parent
/// that are not the kernel's.
fn reads_runtime_clone(event: &Event) -> bool {
    use common::wire::exe::exe_flags::{KNOWN, MEMFD, MEMFD_SEALED};
    matches!(event, Event::ProcessSpawn { pid, ppid, exe, .. }
        if exe.has(KNOWN) && exe.has(MEMFD) && exe.has(MEMFD_SEALED) && *pid != 0 && *ppid != 0)
}

/// Lot 366: `event`'s reads were not waited for (a file system whose server
/// does not answer held them): an exec with its stdio on an inet socket is
/// kept unverified — R020 records it, as an image it could not open.
pub fn not_read(event: &mut Event, settle: &Settle) {
    // lot 369: a sealed memfd not compared keeps no clone — R004 judges it
    // fileless, as before — and is counted ([`runtime_clone_counts`])
    count_not_read(event, &RUNTIMES, settle);
    if let Event::ProcessSpawn { exe, .. } = &*event {
        let installed = exe.has(common::wire::exe::exe_flags::KNOWN)
            && program_identity::installed_kind((exe.dev, exe.ino)).is_some();
        if !installed && reads_socket_exec(event) {
            program_identity::keep_unverified(event);
        }
    }
}

/// [`not_read`]'s count in `checks`: a sealed memfd exec the pump did not
/// wait for — unless its step, finishing at the deadline, settled it first
/// (the review of #588, F3: its count and clone are the step's then).
fn count_not_read(event: &Event, checks: &RuntimeChecks, settle: &Settle) {
    if reads_runtime_clone(event) && settle.take() {
        checks.not_read.fetch_add(1, Ordering::Relaxed);
    }
}

/// [`read_and_keep`] with `/proc` at `proc_root` (tests).
fn read_and_keep_at(event: &Event, proc_root: &Path) {
    read_and_keep_with(event, proc_root, &BOUNDS);
}

/// Why a file could not be identified: the exec is then unverified.
#[derive(Debug, PartialEq, Eq)]
enum Unverified {
    /// It could not be opened or stat'ed (a user's FUSE mount without
    /// `allow_other`, a file gone).
    Unreadable,
    /// The file open is not the one the hook named (a later exec).
    Another,
    /// The uid's budget for this second is spent.
    Budget,
}

/// What the file `file` opened is (`None`: no installed program's copy),
/// bounded by `bounds` for `uid`; `expect`: the identity the hook gave.
/// Lot 366: the caller opens it only once its file system is judged one
/// the agent asks ([`crate::sensors::pump_reads`]): a user's FUSE file is
/// never opened through its daemon — unverified, R020 records it.
fn identify(
    file: std::io::Result<std::fs::File>,
    expect: Option<(u64, u64)>,
    uid: u32,
    bounds: &Bounds,
) -> Result<Option<ProgramKind>, Unverified> {
    let file = file.map_err(|_| Unverified::Unreadable)?;
    let m = file.metadata().map_err(|_| Unverified::Unreadable)?;
    let id = (
        crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        m.ino(),
    );
    if expect.is_some_and(|e| e != id) {
        return Err(Unverified::Another);
    }
    if let Some(kind) = program_identity::installed_kind_sized(id, m.len()) {
        return Ok(Some(kind));
    }
    let key = (id.0, id.1, m.len(), m.ctime(), m.ctime_nsec());
    if let Some(answer) = bounds.recall(&key) {
        bounds.remembered.fetch_add(1, Ordering::Relaxed);
        return Ok(answer);
    }
    // lot 347: no shell runs in a container runtime (R020's programs only)
    let candidates: Vec<InstalledImage> = program_identity::installed_of_len(m.len())
        .into_iter()
        .filter(|i| !i.kind.is_container_runtime())
        .take(MAX_COMPARED)
        .collect();
    if candidates.is_empty() {
        bounds.remember(key, None);
        return Ok(None);
    }
    let cost = compare_cost(m.len()) * candidates.len() as u64;
    if !bounds.take(uid, cost, Instant::now()) {
        bounds.skipped.fetch_add(1, Ordering::Relaxed);
        return Err(Unverified::Budget);
    }
    bounds.compared.fetch_add(1, Ordering::Relaxed);
    let kind = candidates
        .iter()
        .find(|i| same_sampled(&file, Path::new(&i.path), m.len()))
        .map(|i| i.kind);
    bounds.remember(key, kind);
    Ok(kind)
}

/// [`read_and_keep`] with `/proc` at `proc_root` and `bounds` (tests).
fn read_and_keep_with(event: &Event, proc_root: &Path, bounds: &Bounds) {
    read_and_keep_judged(
        event,
        proc_root,
        bounds,
        &crate::sensors::pump_reads::Judge::host(),
    );
}

/// Lot 366: the loader's operand `program` of the process `dir`
/// (`/proc/<pid>`): walked from the process's root (an absolute one) or its
/// working directory, one name at a time, every file system on the way
/// judged by `judge` (links followed, each judged where it leads; a `..`
/// refused), then opened — never a lookup through `root` or `cwd` by path
/// on a user's FUSE file system.
fn open_operand(dir: &Path, program: &str, judge: &Judge) -> std::io::Result<std::fs::File> {
    use antitamper_bpf::kernel_roots;
    let (link, rel) = match program.strip_prefix('/') {
        Some(abs) => ("root", abs),
        None => ("cwd", program),
    };
    let (from, c) = kernel_roots::link_target(&dir.join(link))?;
    if !c.is_dir() {
        return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    // the process's own mounts (a container's) judged by its own table
    let judge = judge.of_process(dir);
    let w = kernel_roots::walk_judged(&from, Path::new("/"), Path::new(rel), true, &mut |c| {
        judge.trusts(c)
    })?;
    kernel_roots::reopen_fd(&w.file, libc::O_RDONLY)
}

/// [`read_and_keep_with`], the file systems judged by `judge`.
fn read_and_keep_judged(event: &Event, proc_root: &Path, bounds: &Bounds, judge: &Judge) {
    if !reads_socket_exec(event) {
        return;
    }
    let Event::ProcessSpawn {
        pid,
        uid,
        filename,
        exe,
        argv,
        ..
    } = event
    else {
        return;
    };
    let dir = proc_root.join(pid.to_string());
    let known = exe.has(common::wire::exe::exe_flags::KNOWN);
    let installed = if known {
        program_identity::installed_kind((exe.dev, exe.ino))
    } else {
        None
    };
    let named_loader = ProgramKind::of_name(exe.path_or(filename)) == Some(ProgramKind::Loader);
    // the exec's own image: installed (the core knows it), the loader by its
    // name (its operand is what is compared), else compared
    let image = match installed {
        Some(kind) => Some(kind),
        None if named_loader => Some(ProgramKind::Loader),
        None => match identify(
            crate::sensors::pump_reads::open_exe(&dir.join("exe"), libc::O_RDONLY, judge)
                .map(|(f, _)| f),
            known.then_some((exe.dev, exe.ino)),
            *uid,
            bounds,
        ) {
            Ok(kind) => kind,
            // never silence (the re-check of #549, R1): R020 records it
            Err(_) => {
                program_identity::keep_unverified(event);
                return;
            }
        },
    };
    let loader = image == Some(ProgramKind::Loader);
    if !loader {
        if installed.is_none() {
            if let Some(kind) = image {
                program_identity::keep_copy(event, kind);
            }
        }
        return;
    }
    // the dynamic loader (by name, identity or content): its operand is the
    // program (the review of #549, F4; the re-check's R2), by the process's
    // root, or its working directory for a relative one
    let Some((program, _)) = nn_core::posture::script_args::loader_program(argv) else {
        return;
    };
    match identify(open_operand(&dir, program, judge), None, *uid, bounds) {
        Ok(Some(kind)) if kind != ProgramKind::Loader => program_identity::keep_copy(event, kind),
        // no copy: a loader known by its content is said so, the operand then
        // judged by its name
        Ok(_) => {
            if installed.is_none() && !named_loader {
                program_identity::keep_copy(event, ProgramKind::Loader);
            }
        }
        Err(_) => program_identity::keep_unverified(event),
    }
}

// ── Lot 347: an OCI runtime's copy of itself in a memfd (R004) ─────────

/// Lot 347: where a distribution installs a runtime's manager outside the
/// binary directories (podman's conmon on some).
const RUNTIME_EXTRA_PATHS: &[&str] = &["/usr/libexec/podman/conmon"];

/// Lot 347: the longest memfd compared with the runtimes (`runc` is 10–16
/// MiB, `crun` under 4).
const RUNTIME_MAX_LEN: u64 = 64 << 20;

/// Lot 347: the bytes the runtime compares may read in a second, both
/// files counted — a container start reads its runtime twice (~30 MiB for
/// runc 1.1): about seventeen starts a second, root's (the review of #556,
/// F2: every uid's, as it was, let one user's rootless loop spend root's
/// Docker starts). Past its share a clone is not compared: kept unverified;
/// R004 records root's (High) and never kills it, and kills any other
/// uid's (the re-check of #556, N1). Only an exec whose parent runs
/// an installed runtime or its manager reaches a compare.
const RUNTIME_BUDGET_PER_SECOND: u64 = 512 << 20;

/// The review of #556 (F2): each uid's share of it but root's — about two
/// runc 1.1 starts a second (a rootless Podman user's).
const RUNTIME_BUDGET_PER_UID: u64 = 64 << 20;

/// The review of #556 (F2): the part of it the uids but root together
/// never spend — root's container starts (Docker's, rootful Podman's) keep
/// at least this whatever the users run.
const RUNTIME_ROOT_RESERVE: u64 = 256 << 20;

/// The review of #585 (F2: the lab of lot 378 — thirty `podman run` in a
/// row by one rootless user, runc 1.1's 10 MiB copy compared about four
/// times a second, met its share eight times: eight Criticals "not
/// compared (budget)"): a uid but root may read four seconds of its share
/// at once, its share paying it back ([`Bounds::burst`]) — about twelve
/// runc 1.1 starts more than its rate. Spent, a copy is still not compared
/// (R004's Critical for a uid but root): no trust is added, a payload costs
/// only more to hide among compares.
const RUNTIME_BURST_PER_UID: u64 = 4 * RUNTIME_BUDGET_PER_UID;

/// Lot 347: the runtimes recorded again at a memfd exec at most this often
/// (a runtime installed since the minute's refresh: Docker's first
/// container right after its install).
const RUNTIME_REFRESH_EVERY: Duration = Duration::from_secs(1);

/// Lot 347: the seals a runtime's copy of itself carries — runc and crun
/// add these before they execute it: its bytes cannot change since.
const SEALED: libc::c_int = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW;

/// Lot 347: the runtime compares' bounds and the time of their last
/// refresh of the runtimes' records.
pub struct RuntimeChecks {
    bounds: Bounds,
    refreshed: Mutex<Option<Instant>>,
    /// Lot 369: the memfds kept as an installed runtime's clone, compared
    /// whole ([`runtime_clone_counts`]).
    kept: AtomicU64,
    /// Lot 369: the sealed memfd execs whose reads the pump did not wait
    /// for (no clone kept).
    not_read: AtomicU64,
    /// Lot 381: of `compared`, those read through another process running
    /// the copy (the exec's own gone: [`open_copy`]).
    through: AtomicU64,
    /// Lot 381: not compared, the copy gone before the read, kept
    /// unverified ([`CloneRead::Gone`]).
    gone: AtomicU64,
    /// The review of #588 (F4): not compared, nothing kept
    /// ([`CloneRead::Lost`]).
    lost: AtomicU64,
    /// Lot 381: no runtime's clone ([`CloneRead::NoRuntime`]).
    no_runtime: AtomicU64,
    /// The review of #578 (N3): each uid's last skip for the budget — an
    /// episode of its spent budget opens at a skip with none in the
    /// [`EPISODE_QUIET`] before ([`RuntimeChecks::opens_episode`]).
    episodes: Mutex<HashMap<u32, Instant>>,
}

/// The review of #578 (N3): a skip for the budget with none of the same
/// uid in this long before opens an episode — its record names who spent
/// the budget, once.
const EPISODE_QUIET: Duration = Duration::from_secs(60);

/// Lot 369: the runtime clones the exec pump judged since the agent's start
/// (`nn-admin status`): sealed memfds compared whole with an installed
/// runtime, those kept as its clone (R004's exemption), those not compared
/// for the budget (kept unverified), and those whose reads it did not wait
/// for (nothing kept). A container host where `kept` stays at zero while
/// containers start has lost the exemption (lot 366 lost it on Debian 13).
/// Lot 381: every sealed memfd exec the LSM program described is in
/// exactly one of `compared`, `unverified`, `gone`, `lost`, `no_runtime`
/// and `not_read`, once (the review of #588, F3: a read finishing past its
/// deadline counts nothing more) — rc11 judged one runc clone in 300
/// fileless outside every counter; `through` is the part of `compared`
/// read through another process running the copy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeCloneCounts {
    pub compared: u64,
    pub kept: u64,
    pub unverified: u64,
    pub not_read: u64,
    pub through: u64,
    pub gone: u64,
    pub lost: u64,
    pub no_runtime: u64,
}

/// Lot 369: [`RuntimeCloneCounts`] since the agent's start.
pub fn runtime_clone_counts() -> RuntimeCloneCounts {
    RUNTIMES.counts()
}

impl RuntimeChecks {
    /// Each uid's `per_uid`, root up to `global`, which the others together
    /// spend only less `root_reserve` (F2).
    fn new(per_uid: u64, global: u64, root_reserve: u64) -> Self {
        Self {
            bounds: Bounds::with_root_reserve(per_uid, global, root_reserve),
            refreshed: Mutex::new(None),
            kept: AtomicU64::new(0),
            not_read: AtomicU64::new(0),
            through: AtomicU64::new(0),
            gone: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            no_runtime: AtomicU64::new(0),
            episodes: Mutex::new(HashMap::new()),
        }
    }

    /// The review of #585 (F2): each uid but root may read up to `burst`
    /// at once, its share paying it back at its rate ([`Bounds::burst`]).
    fn with_burst(mut self, burst: u64) -> Self {
        self.bounds.burst = burst;
        self
    }

    /// The review of #578 (N3): `uid`'s skip at `now` opens an episode of
    /// its spent budget — none of its skips in the [`EPISODE_QUIET`] before
    /// (each skip is remembered, so a steady flood stays one episode). At
    /// most [`UIDS_CAP`] uids kept, the quiet ones first out.
    fn opens_episode(&self, uid: u32, now: Instant) -> bool {
        let mut e = self.episodes.lock();
        let opens = e
            .get(&uid)
            .is_none_or(|last| now.duration_since(*last) >= EPISODE_QUIET);
        if e.len() >= UIDS_CAP && !e.contains_key(&uid) {
            e.retain(|_, last| now.duration_since(*last) < EPISODE_QUIET);
            while e.len() >= UIDS_CAP {
                let Some(oldest) = e.iter().min_by_key(|(_, t)| **t).map(|(u, _)| *u) else {
                    break;
                };
                e.remove(&oldest);
            }
        }
        e.insert(uid, now);
        opens
    }

    fn counts(&self) -> RuntimeCloneCounts {
        RuntimeCloneCounts {
            compared: self.bounds.compared.load(Ordering::Relaxed),
            kept: self.kept.load(Ordering::Relaxed),
            unverified: self.bounds.skipped.load(Ordering::Relaxed),
            not_read: self.not_read.load(Ordering::Relaxed),
            through: self.through.load(Ordering::Relaxed),
            gone: self.gone.load(Ordering::Relaxed),
            lost: self.lost.load(Ordering::Relaxed),
            no_runtime: self.no_runtime.load(Ordering::Relaxed),
        }
    }

    /// Lot 381: `read`, one sealed memfd exec's outcome, counted — the one
    /// place the compare's counters move ([`CloneRead`]).
    fn count(&self, read: CloneRead) {
        let one = |c: &AtomicU64| {
            c.fetch_add(1, Ordering::Relaxed);
        };
        match read {
            CloneRead::Compared { kept, through } => {
                one(&self.bounds.compared);
                if kept {
                    one(&self.kept);
                }
                if through {
                    one(&self.through);
                }
            }
            CloneRead::Budget => one(&self.bounds.skipped),
            CloneRead::Gone => one(&self.gone),
            CloneRead::Lost => one(&self.lost),
            CloneRead::NoRuntime => one(&self.no_runtime),
        }
    }

    /// The runtimes under `root` recorded, unless done in the last
    /// [`RUNTIME_REFRESH_EVERY`].
    fn refresh(&self, root: &Path, now: Instant) {
        if !self.due(now) {
            return;
        }
        for image in installed_runtimes_under(root) {
            program_identity::record_installed(image);
        }
    }

    /// Whether a refresh is due at `now` (then it is this caller's) —
    /// memory only: the lock is never held while the runtimes are read.
    fn due(&self, now: Instant) -> bool {
        let mut at = self.refreshed.lock();
        if at.is_some_and(|t| now.duration_since(t) < RUNTIME_REFRESH_EVERY) {
            return false;
        }
        *at = Some(now);
        true
    }
}

static RUNTIMES: LazyLock<RuntimeChecks> = LazyLock::new(|| {
    RuntimeChecks::new(
        RUNTIME_BUDGET_PER_UID,
        RUNTIME_BUDGET_PER_SECOND,
        RUNTIME_ROOT_RESERVE,
    )
    .with_burst(RUNTIME_BURST_PER_UID)
});

/// Lot 347: the installed OCI runtimes and their managers under `root` —
/// each of their names in the binary directories (and
/// [`RUNTIME_EXTRA_PATHS`]), by the name of the file it resolves to: a
/// few `stat`s, no directory listed.
pub fn installed_runtimes_under(root: &Path) -> Vec<InstalledImage> {
    let names = program_identity::CONTAINER_RUNTIMES
        .iter()
        .chain(program_identity::RUNTIME_MANAGERS);
    let mut paths: Vec<PathBuf> = BIN_DIRS
        .iter()
        .flat_map(|d| {
            names
                .clone()
                .map(move |n| root.join(d.trim_start_matches('/')).join(n))
        })
        .collect();
    paths.extend(
        RUNTIME_EXTRA_PATHS
            .iter()
            .map(|p| root.join(p.trim_start_matches('/'))),
    );
    let mut out: Vec<InstalledImage> = Vec::new();
    for p in paths {
        let Some(image) = kind_of(&p)
            .filter(|k| k.is_container_runtime())
            .and_then(|k| image_of(&p, k, root))
        else {
            continue;
        };
        if !out.iter().any(|i| i.id == image.id) {
            out.push(image);
        }
    }
    out
}

/// Lot 348: the installed container runtimes and their managers recorded
/// again, at most once a second ([`RuntimeChecks::refresh`]) — the module
/// tool pump's step (`sensors::kmod_exec::facts`) before it keeps an exec's
/// facts: containerd's first start, right after `apt install docker.io`,
/// asks for its modules before the minute's refresh has recorded the
/// package's `containerd` (R011 kept its kill there, Debian 13: its
/// `LD_LIBRARY_PATH` judged without the manager's identity).
pub fn refresh_runtimes() {
    RUNTIMES.refresh(Path::new("/"), Instant::now());
}

/// Lot 347: the file `file` is sealed against writing, shrinking and
/// growing ([`SEALED`]): a memfd whose bytes no one can change any more.
fn sealed(file: &std::fs::File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: F_GET_SEALS reads the seals of an open descriptor this
    // function borrows; no memory is passed to the kernel.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    seals >= 0 && seals & SEALED == SEALED
}

/// Lot 347: the exec pump's step for a memfd exec (module docs) — the
/// running image kept as an installed runtime's clone when its parent runs
/// an installed runtime or its manager (by its image's identity), and the
/// memfd, the exec's own file by its device and inode, sealed AT THE EXEC
/// (the LSM program's `MEMFD_SEALED`: the review of #556, F1) and still,
/// is that runtime's image whole, byte for byte. Past the budget's share
/// (F2) such an exec is kept UNVERIFIED, with the installed runtime of its
/// length. Anything else keeps nothing: R004 judges a memfd exec fileless
/// without the clone. The review of #588 (F3): counted and kept only when
/// `settle` was not taken by [`not_read`] already.
pub fn read_runtime_clone(event: &Event, settle: &Settle) {
    read_runtime_clone_with(event, Path::new("/proc"), Path::new("/"), &RUNTIMES, settle);
}

/// [`read_runtime_clone`] with `/proc` at `proc_root`, the host's root at
/// `root` and `checks` (tests). Lot 381: every exec it reads is counted in
/// exactly one of [`RuntimeCloneCounts`] ([`RuntimeChecks::count`]) — the
/// outcome is what [`runtime_clone_read`] returns, never a bare `return`.
/// The review of #588 (F3): once — the count and the clone are this read's
/// only when it settles the exec ([`Settle`]); a read the pump stopped
/// waiting for was counted "not read in time" by [`not_read`], and R004
/// judged the exec without its clone: nothing more is counted or kept.
fn read_runtime_clone_with(
    event: &Event,
    proc_root: &Path,
    root: &Path,
    checks: &RuntimeChecks,
    settle: &Settle,
) {
    // the review of #556 (F1): sealed when the kernel executed it, by the
    // LSM program's read of its seals — sealed only when the pump reads it,
    // its bytes may have been rewritten after the exec (any holder of a
    // writable descriptor: the parent of an OCI hook run from
    // `/proc/<pid>/fd/N`)
    if !reads_runtime_clone(event) {
        return;
    }
    let (read, clone) = runtime_clone_read(event, proc_root, root, checks);
    if !settle.take() {
        return;
    }
    if let Some(clone) = clone {
        program_identity::keep_runtime_clone(event, clone);
    }
    checks.count(read);
}

/// Lot 381 (F6-6 of the pre-alpha's Phase 6b): what the runtime compare
/// made of one sealed memfd exec ([`reads_runtime_clone`]). On rc11 one
/// rootful runc clone in 300 (Debian 13, 200 containers started in a row)
/// was judged fileless, Critical, and counted nowhere: the pump read it
/// once its process had exited, and returned before any counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloneRead {
    /// Compared whole: `kept` as an installed runtime's clone (byte for
    /// byte its image), the copy read `through` another process running
    /// that very memfd — the exec's own gone before the read
    /// ([`open_copy`]).
    Compared { kept: bool, through: bool },
    /// Not compared: its uid's share of the compare budget spent this
    /// second (kept unverified, "not compared (budget)").
    Budget,
    /// Not compared: the copy gone before the read — every thread of the
    /// exec's process exited and none of its parent's children the pump
    /// read runs it — in runc 1.1's re-exec under an installed runtime
    /// ([`gone_unverified`]): kept unverified, "not compared (gone)".
    Gone,
    /// The review of #588 (F4): not compared, nothing kept (R004 judges it
    /// fileless): the copy gone in any other shape (runc 1.2's, an OCI
    /// hook's, under a manager), the parent gone too (no runtime to tell),
    /// the process running another file by the read, or a thread of it
    /// still running whose copy could not be read.
    Lost,
    /// No runtime's copy: its parent runs no installed runtime or manager,
    /// no installed runtime has its length, or it is no sealed file a
    /// runtime's size — nothing kept, R004 judges it fileless.
    NoRuntime,
}

/// [`read_runtime_clone_with`]'s step: the exec read and compared — what
/// came of it, and the clone to keep (the review of #588, F3: kept only by
/// the read that settles the exec).
fn runtime_clone_read(
    event: &Event,
    proc_root: &Path,
    root: &Path,
    checks: &RuntimeChecks,
) -> (CloneRead, Option<program_identity::RuntimeClone>) {
    let Event::ProcessSpawn {
        pid,
        ppid,
        uid,
        exe,
        ..
    } = event
    else {
        return (CloneRead::NoRuntime, None);
    };
    checks.refresh(root, Instant::now());
    // first the parent, one `stat` of its image: a runtime's or a manager's
    // lot 366: from the kernel's cache (a parent run from a user's FUSE
    // file system: its daemon is not asked)
    let image = |pid: u32| {
        antitamper_bpf::kernel_roots::link_target(&proc_root.join(pid.to_string()).join("exe"))
            .ok()
            .map(|(_, c)| (c.dev, c.ino))
    };
    // lot 381: a parent gone tells no runtime — not compared, counted
    let Some(parent) = image(*ppid) else {
        return (CloneRead::Lost, None);
    };
    let Some(parent_kind) = installed_at_its_path(parent) else {
        return (CloneRead::NoRuntime, None);
    };
    // the processes above the exec as they run now: the parent, and its
    // parent when it started no later (the pid not reused since), each an
    // installed runtime or manager's file at its path — R004's manager when
    // the lineage holds no exec of it (a fork that never executed: conmon's
    // monitor)
    let mut seen = vec![(*ppid, parent)];
    if let Some((grand, start)) = parent_and_start(proc_root, *ppid) {
        let older = parent_and_start(proc_root, grand).is_some_and(|(_, g)| g <= start);
        if let Some(id) =
            image(grand).filter(|id| older && grand > 1 && installed_at_its_path(*id).is_some())
        {
            seen.push((grand, id));
        }
    }
    // lot 353: through the `/proc` root the agent's start anchored; lot
    // 366: opened only once it is the file the kernel executed — a memfd
    // (the kernel's own memory, no file system's daemon to ask) — by its
    // cached identity, then again through this thread's descriptor; lot
    // 381: or through a process still running that very memfd
    let (file, m, through) = match open_copy(proc_root, *pid, *ppid, (exe.dev, exe.ino)) {
        Copy::Read { file, m, through } => (file, m, through),
        // the process runs another file now (it executed again, or its pid
        // is another process's): nothing kept, R004's fileless Critical as
        // before — a runtime's copy never re-executes; the review of #588
        // (F1): a thread of it still runs, its copy not read: not exited
        Copy::Replaced | Copy::Running => return (CloneRead::Lost, None),
        Copy::Exited => return gone_unverified(event, parent, parent_kind, seen),
    };
    if !m.is_file() || m.len() == 0 || m.len() > RUNTIME_MAX_LEN || !sealed(&file) {
        return (CloneRead::NoRuntime, None);
    }
    let candidates: Vec<InstalledImage> = program_identity::runtimes_of_len(m.len())
        .into_iter()
        .take(MAX_COMPARED)
        .collect();
    if candidates.is_empty() {
        return (CloneRead::NoRuntime, None);
    }
    let cost = 2 * m.len() * candidates.len() as u64;
    let now = Instant::now();
    if !checks.bounds.take(*uid, cost, now) {
        // lot 370 (F10-6): the budget spent is a signed event of its own —
        // the uid that spent it said (one line per uid, signed when new)
        crate::boot::degradation::report("runtime_copy_compare", &budget_spent_line(*uid));
        // the review of #578 (N3): the first skip of an episode names who
        // spent the budget — the uid whose share ran out and the second's
        // biggest spender — in R004's record, once per episode
        let episode = checks
            .opens_episode(*uid, now)
            .then(|| program_identity::BudgetEpisode {
                uid: *uid,
                top: checks.bounds.top_spender(now),
            });
        // the review of #556 (F2): every fact but the bytes holds (the
        // parent, the seal at the exec and now, an installed runtime's
        // length) — kept unverified, any program of that length (R004:
        // root's recorded High, never killed; any other uid's the Critical
        // kill — the review of #578, N3, reverting lot 370's F10-6)
        let clone = program_identity::RuntimeClone {
            image: candidates[0].id,
            seen,
            unverified: true,
            gone: false,
            episode,
        };
        return (CloneRead::Budget, Some(clone));
    }
    let whole = [(0, m.len())];
    let Some(found) = candidates
        .iter()
        .find(|i| same_over(&file, Path::new(&i.path), m.len(), Some(i.id), &whole))
    else {
        return (
            CloneRead::Compared {
                kept: false,
                through,
            },
            None,
        );
    };
    let clone = program_identity::RuntimeClone {
        image: found.id,
        seen,
        unverified: false,
        gone: false,
        episode: None,
    };
    (
        CloneRead::Compared {
            kept: true,
            through,
        },
        Some(clone),
    )
}

/// Lot 381: a copy whose process exited before the read (every thread of
/// it) and that none of its parent's children the pump read still runs.
/// Its length is not known (nothing left to `stat`), its seal is the LSM
/// program's at the exec: what holds is the parent's image and R004's
/// lineage. The review of #588 (F2): kept unverified with the runtime its
/// parent runs (R004: root's recorded High, never killed; any other uid's
/// the Critical kill, as past the budget) only in runc 1.1's re-exec — the
/// process executed again with no fork since its last exec
/// (`fork_parent` 0: `runc init` re-executing its copy) under an installed
/// runtime's process. runc 1.2's shape (`runc init` executing the copy
/// `runc create` made, its first exec since the fork) — every OCI hook a
/// runtime runs is such an exec — and a manager's parent (which runtime it
/// copied is not known) keep nothing: R004's fileless Critical.
fn gone_unverified(
    event: &Event,
    parent: (u64, u64),
    parent_kind: ProgramKind,
    seen: Vec<(u32, (u64, u64))>,
) -> (CloneRead, Option<program_identity::RuntimeClone>) {
    let reexec = matches!(event, Event::ProcessSpawn { exe, .. } if exe.fork_parent == 0);
    if parent_kind != ProgramKind::ContainerRuntime || !reexec {
        return (CloneRead::Lost, None);
    }
    let clone = program_identity::RuntimeClone {
        image: parent,
        seen,
        unverified: true,
        gone: true,
        episode: None,
    };
    (CloneRead::Gone, Some(clone))
}

/// Lot 381: where [`open_copy`] found the exec's memfd.
enum Copy {
    /// Opened read-only — `through` another process running that very
    /// inode (the exec's own gone).
    Read {
        file: std::fs::File,
        m: std::fs::Metadata,
        through: bool,
    },
    /// Every thread of the exec's process exited (no thread's `exe` read,
    /// each a zombie or gone: [`group_copy`]), and no process looked at
    /// runs the copy.
    Exited,
    /// The exec's process runs another file now, and no process looked at
    /// runs the copy.
    Replaced,
    /// The review of #588 (F1): a thread of the exec's process still runs
    /// (or more threads than are read), no thread's copy read, and no
    /// process looked at runs it: never told exited.
    Running,
}

/// Lot 381: the children of one thread read at most (a runtime's: its
/// `runc init` and that one's two clones); the review of #588 (F1): and
/// the threads of one process.
const HOLDERS_MAX: usize = 64;

/// Lot 381 (F6-6): the memfd `exe` (the kernel's identity of the file the
/// exec `pid` ran), opened read-only — through `/proc/<pid>/exe` while the
/// process runs it, else through a thread of it still running it (the
/// review of #588, F1: its leader exited alone — a plain `exit` of the
/// main thread — its other threads running on), else (`through`) through a
/// child of the exec's parent `ppid` still running that very inode. runc
/// 1.1's `runc init` re-executes its sealed copy, then forks its two stages
/// with `CLONE_PARENT` — children of `runc create`, running the copy until
/// the container's program starts — and exits: a pump a few milliseconds
/// late found it gone. The inode is the one executed (a memfd's inode lives
/// while a process maps it, and its number is not reused meanwhile), sealed
/// at the exec, so its bytes are the ones that ran.
fn open_copy(proc_root: &Path, pid: u32, ppid: u32, exe: (u64, u64)) -> Copy {
    let open = |link: &Path| -> Opened {
        let (link, id) = antitamper_bpf::kernel_roots::link_target(link).map_err(|_| false)?;
        if (id.dev, id.ino) != exe {
            return Err(true);
        }
        let file =
            antitamper_bpf::kernel_roots::reopen_fd(&link, libc::O_RDONLY).map_err(|_| false)?;
        let m = file.metadata().map_err(|_| false)?;
        if kernel_id(&m) != exe {
            return Err(true);
        }
        Ok((file, m))
    };
    let at = proc_root.join(pid.to_string());
    let own = match open(&at.join("exe")) {
        Ok((file, m)) => {
            return Copy::Read {
                file,
                m,
                through: false,
            };
        }
        Err(true) => Copy::Replaced,
        // the review of #588 (F1): its `exe` (its leader's) not read — the
        // process exited, or only its leader did
        Err(false) => match group_copy(&at, &open) {
            Group::Copy(file, m) => {
                return Copy::Read {
                    file,
                    m,
                    through: false,
                };
            }
            Group::Replaced => Copy::Replaced,
            Group::Running => Copy::Running,
            Group::Gone => Copy::Exited,
        },
    };
    let held = children_of(proc_root, ppid)
        .into_iter()
        .filter(|c| *c != pid)
        .find_map(|c| open(&proc_root.join(c.to_string()).join("exe")).ok());
    match held {
        Some((file, m)) => Copy::Read {
            file,
            m,
            through: true,
        },
        None => own,
    }
}

/// Lot 381: a process's link to the file it runs, opened read-only when it
/// is the copy; `Err(true)`: the link read, another file; `Err(false)`:
/// not read.
type Opened = Result<(std::fs::File, std::fs::Metadata), bool>;

/// The review of #588 (F1): what the threads of a process whose leader's
/// `exe` was not read run ([`group_copy`]).
enum Group {
    /// A thread runs the copy: opened read-only.
    Copy(std::fs::File, std::fs::Metadata),
    /// A thread runs another file.
    Replaced,
    /// A thread has not exited (or more threads than are read), its copy
    /// not read.
    Running,
    /// No thread runs: none listed (the process reaped), or each a zombie
    /// or gone and the leader counted alone (the re-check of #588, N1).
    Gone,
}

/// The review of #588 (F1): the copy read through a thread of the process
/// at `at` (`/proc/<pid>`) still running it (`task/<tid>/exe`, `open`), at
/// most [`HOLDERS_MAX`] threads. A leader that called `exit` (not
/// `exit_group`) is a zombie whose `exe` is not read while its other
/// threads run the payload: taken as exited, a foreign root memfd was kept
/// "not compared (gone)" — High, never killed. Gone only when no thread
/// listed has not exited ([`thread_runs`]) and the kernel counts the
/// leader alone ([`leader_alone`]: the re-check of #588, N1).
fn group_copy(at: &Path, open: &dyn Fn(&Path) -> Opened) -> Group {
    let task = at.join("task");
    let tids = match antitamper_bpf::kernel_roots::read_dir_max(&task, HOLDERS_MAX + 1) {
        Ok(tids) => tids,
        // the process reaped
        Err(e) if reaped(&e) => return Group::Gone,
        // the re-check of #588 (N2): any other failure (`EMFILE`, a
        // `readdir` error) on a group that may live: never told gone
        Err(_) => return Group::Running,
    };
    // a thread past the bound may run it: never told gone
    let mut running = tids.len() > HOLDERS_MAX;
    for tid in tids.iter().take(HOLDERS_MAX) {
        let thread = task.join(tid);
        match open(&thread.join("exe")) {
            Ok((file, m)) => return Group::Copy(file, m),
            Err(true) => return Group::Replaced,
            Err(false) => running |= thread_runs(&thread),
        }
    }
    // the re-check of #588 (N1): the listing is no snapshot — a thread made
    // after it, while the listed one exits before its read, is not seen
    // (1.7% of reads of such a group on 6.18): gone only when the kernel's
    // count of the group's threads (the leader's `num_threads`) is the
    // leader alone
    if running || !leader_alone(at) {
        Group::Running
    } else {
        Group::Gone
    }
}

/// The re-check of #588 (N1): the process at `at` (`/proc/<pid>`) counts
/// its leader alone, or none — `num_threads` of its `stat` (the kernel's
/// `signal->nr_threads`, one read) at most 1, or its `stat` gone (the
/// process reaped). Any other failure to read or parse it: not alone.
fn leader_alone(at: &Path) -> bool {
    match crate::state_read::read_state(at.join("stat")) {
        // after the name: the state is field 3, `num_threads` field 20
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| {
                let fields: Vec<&str> = rest.split_whitespace().collect();
                fields.get(17)?.parse::<u64>().ok()
            })
            .is_some_and(|n| n <= 1),
        Err(e) => reaped(&e),
    }
}

/// A read of a process's or a thread's `/proc` entry failed because it is
/// gone (reaped): `ENOENT`, `ESRCH`.
fn reaped(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ESRCH)
}

/// The review of #588 (F1): the thread at `thread` (`/proc/<pid>/task/<tid>`)
/// has not exited — its `stat` state no zombie's (`Z`) nor a dead task's
/// (`X`, `x`). Its `stat` not found (the thread reaped): exited; any other
/// failure to read or parse it: not told exited.
fn thread_runs(thread: &Path) -> bool {
    match crate::state_read::read_state(thread.join("stat")) {
        Ok(stat) => stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_none_or(|state| !matches!(state, "Z" | "X" | "x")),
        Err(e) => !reaped(&e),
    }
}

/// Lot 381: the children of `pid`'s threads (`/proc/<pid>/task/<tid>/children`,
/// procfs's own: the kernel lists them), at most [`HOLDERS_MAX`] from each.
fn children_of(proc_root: &Path, pid: u32) -> Vec<u32> {
    let task = proc_root.join(pid.to_string()).join("task");
    let Ok(threads) = antitamper_bpf::kernel_roots::read_dir_max(&task, HOLDERS_MAX) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for tid in threads {
        let Ok(text) = crate::state_read::read_state(task.join(&tid).join("children")) else {
            continue;
        };
        out.extend(
            text.split_whitespace()
                .filter_map(|c| c.parse::<u32>().ok())
                .take(HOLDERS_MAX),
        );
    }
    out
}

/// Lot 370 (F10-6): the signed line of a runtime copy not compared, uid
/// `uid`'s share of the compare budget spent.
pub fn budget_spent_line(uid: u32) -> String {
    format!(
        "uid {uid}: its share of the compare budget for a container runtime's sealed copy of \
         itself was spent — a sealed memfd of a runtime's length was not compared: R004 records \
         root's High (never killed) and kills any other uid's, the first of each episode naming \
         who spent the budget"
    )
}

/// Lot 347: the installed runtime or manager whose identity `id` is, when
/// the file at its recorded path is that inode still — an inode number a
/// removed runtime had, now another file's elsewhere, is not it.
fn installed_at_its_path(id: (u64, u64)) -> Option<ProgramKind> {
    let image = program_identity::installed_image(id)?;
    if !image.kind.is_container_runtime() {
        return None;
    }
    antitamper_bpf::kernel_roots::metadata(&image.path)
        .is_ok_and(|m| kernel_id(&m) == id)
        .then_some(image.kind)
}

/// Lot 347: `/proc/<pid>/stat`'s parent (field 4) and start (field 22),
/// read after the `(comm)` field.
fn parent_and_start(proc_root: &Path, pid: u32) -> Option<(u32, u64)> {
    let stat = crate::state_read::read_state(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let rest: Vec<&str> = stat.rsplit_once(')')?.1.split_whitespace().collect();
    Some((rest.get(1)?.parse().ok()?, rest.get(19)?.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 366, the review of #573 (F2): a loader's operand is walked from
    /// its process's root or working directory, each mount judged by that
    /// process's own table when no host table shows it (a container's
    /// mounts) — opened when the host's tables show its file system.
    #[test]
    fn a_loader_s_operand_is_judged_by_its_process_s_own_mounts() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join("prog"), b"x").unwrap();
        let c =
            antitamper_bpf::kernel_roots::cached(&std::fs::File::open(t.path()).unwrap()).unwrap();
        let proc = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(t.path(), proc.path().join("root")).unwrap();
        std::os::unix::fs::symlink(t.path(), proc.path().join("cwd")).unwrap();
        let line = |id: u64| {
            format!(
                "{id} 1 {}:{} / /x rw - ext4 src rw\n",
                c.dev >> 20,
                c.dev & 0xfffff
            )
        };
        let host = Judge::of(&crate::mountinfo::parse(line(c.mnt_id + 9000).as_bytes()));
        assert!(open_operand(proc.path(), "prog", &host).is_err());
        std::fs::write(proc.path().join("mountinfo"), line(c.mnt_id)).unwrap();
        assert!(
            open_operand(proc.path(), "prog", &host).is_ok(),
            "by its cwd"
        );
        assert!(
            open_operand(proc.path(), "/prog", &host).is_ok(),
            "by its root"
        );
    }

    use nn_model::{StdioSocket, StdioSockets};
    use std::os::unix::fs::symlink;

    /// `content` at `path` under `root`, the directories it makes 0755 and
    /// the file 0644 — as a distribution installs them, whatever the test's
    /// umask (0002 under a user unit): only root-only files are runtimes
    /// (the review of #556, F7).
    /// The exec pump's own runtime checks ([`RUNTIMES`]'s bounds), fresh.
    fn production_checks() -> RuntimeChecks {
        RuntimeChecks::new(
            RUNTIME_BUDGET_PER_UID,
            RUNTIME_BUDGET_PER_SECOND,
            RUNTIME_ROOT_RESERVE,
        )
        .with_burst(RUNTIME_BURST_PER_UID)
    }

    fn put(root: &Path, path: &str, content: &[u8]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let f = root.join(path.trim_start_matches('/'));
        let made: Vec<PathBuf> = f
            .ancestors()
            .skip(1)
            .take_while(|d| !d.exists())
            .map(Path::to_path_buf)
            .collect();
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        for d in made {
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(&f, content).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
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

    /// Lot 347: a memfd holding `content`, sealed with `seals`, as runc
    /// makes its copy.
    fn memfd(content: &[u8], seals: libc::c_int) -> std::fs::File {
        use std::io::Write;
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = std::ffi::CString::new("runc_cloned:/proc/self/exe").unwrap();
        // SAFETY: a name the call reads, no other memory; the descriptor
        // returned is owned by the File made of it at once.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
        assert!(fd >= 0, "memfd_create");
        // SAFETY: `fd` is a new descriptor no one else owns.
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.write_all(content).unwrap();
        if seals != 0 {
            // SAFETY: F_ADD_SEALS on the descriptor `f` owns; no memory.
            assert_eq!(
                unsafe { libc::fcntl(f.as_raw_fd(), libc::F_ADD_SEALS, seals) },
                0
            );
        }
        f
    }

    /// Lot 347: a memfd exec of `pid` under `ppid`, its file `f` (its
    /// identity as the LSM program reports it: sealed at the exec, F1).
    fn memfd_exec(pid: u32, ppid: u32, ts: u64, f: &std::fs::File) -> Event {
        let mut e = nn_core::decision::rules::testutil::spawn("memfd:runc_clon", "/dev/fd/6");
        let id = kernel_id(&f.metadata().unwrap());
        if let Event::ProcessSpawn {
            pid: p,
            ppid: pp,
            uid,
            timestamp_ns,
            exe,
            ..
        } = &mut e
        {
            (*p, *pp, *uid, *timestamp_ns) = (pid, ppid, 0, ts);
            exe.path = "/memfd:runc_cloned:/proc/self/exe".into();
            (exe.dev, exe.ino) = id;
            exe.flags = common::wire::exe::exe_flags::KNOWN
                | common::wire::exe::exe_flags::MEMFD
                | common::wire::exe::exe_flags::DELETED
                | common::wire::exe::exe_flags::MEMFD_SEALED;
        }
        e
    }

    /// Lot 347 (the alpha's container hosts): a memfd exec whose parent
    /// runs the installed runc (by its image's identity), sealed and WHOLE
    /// byte for byte the installed runc, is kept as runc's clone — by
    /// runc's identity. Unsealed, one byte other (even where lot 313's
    /// samples would not look), a parent running no runtime, a file that is
    /// not the exec's, a budget spent, a runtime installed since the last
    /// refresh (recorded at the exec): kept as nothing, or as the new one.
    #[test]
    fn a_sealed_memfd_copy_of_the_installed_runtime_is_its_clone() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        use std::os::fd::AsRawFd;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), t.path().join("proc"));
        // a runtime of 6 MiB: lot 313's samples would read 2.5 of them
        let mut image: Vec<u8> = (0..(6u32 << 20)).map(|i| (i % 251) as u8).collect();
        image[..4].copy_from_slice(b"runc");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let shim = put(
            &root,
            "/usr/bin/containerd-shim-runc-v2",
            b"shim image, 347",
        );
        let bash = put(&root, "/usr/bin/bash", b"bash image, 347");
        let runc_id = kernel_id(&std::fs::metadata(&runc).unwrap());
        let link = |pid: u32, to: &Path| {
            std::fs::create_dir_all(proc.join(pid.to_string())).unwrap();
            let _ = std::fs::remove_file(proc.join(pid.to_string()).join("exe"));
            symlink(to, proc.join(pid.to_string()).join("exe")).unwrap();
        };
        let fd_path = |f: &std::fs::File| PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd()));
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        // the clone compared (an uncompared one is no runtime's image)
        let run =
            |pid: u32, ppid: u32, parent: &Path, f: &std::fs::File, checks: &RuntimeChecks| {
                link(ppid, parent);
                link(pid, &fd_path(f));
                let e = memfd_exec(pid, ppid, 347, f);
                read_runtime_clone_with(&e, &proc, &root, checks, &Settle::default());
                runtime_clone_of(&e)
                    .filter(|c| !c.unverified)
                    .map(|c| c.image)
            };
        let all = SEALED | libc::F_SEAL_SEAL;
        // the runtime recorded at the exec (installed since the minute's
        // refresh), its clone found under it
        let clone = memfd(&image, all);
        assert_eq!(run(34_701, 34_700, &runc, &clone, &checks), Some(runc_id));
        // what the pump saw above the exec: the parent, and its parent when
        // it started no later (a pid reused since is younger: not kept)
        let stat = |pid: u32, ppid: u32, start: u64| {
            std::fs::write(
                proc.join(pid.to_string()).join("stat"),
                format!("{pid} (x y) S {ppid} 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0\n"),
            )
            .unwrap();
        };
        link(34_715, &shim);
        stat(34_700, 34_715, 200);
        stat(34_715, 1, 100);
        link(34_716, &fd_path(&clone));
        let e = memfd_exec(34_716, 34_700, 347, &clone);
        read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
        let shim_id = kernel_id(&std::fs::metadata(&shim).unwrap());
        assert_eq!(
            runtime_clone_of(&e).map(|c| c.seen),
            Some(vec![(34_700, runc_id), (34_715, shim_id)])
        );
        // the parent's parent running no installed runtime's or manager's
        // file at its path: not kept
        link(34_718, &bash);
        stat(34_700, 34_718, 200);
        stat(34_718, 1, 100);
        link(34_719, &fd_path(&clone));
        let e = memfd_exec(34_719, 34_700, 347, &clone);
        read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
        assert_eq!(
            runtime_clone_of(&e).map(|c| c.seen),
            Some(vec![(34_700, runc_id)])
        );
        stat(34_700, 34_715, 200);
        stat(34_715, 1, 300);
        link(34_717, &fd_path(&clone));
        let e = memfd_exec(34_717, 34_700, 347, &clone);
        read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
        assert_eq!(
            runtime_clone_of(&e).map(|c| c.seen),
            Some(vec![(34_700, runc_id)]),
            "a younger process at the parent's parent's pid"
        );
        std::fs::remove_file(proc.join("34700/stat")).unwrap();
        // under its manager too (crun's re-exec under conmon's shape)
        assert_eq!(run(34_702, 34_703, &shim, &clone, &checks), Some(runc_id));
        // CONTROLS — not sealed against writing
        let open = memfd(&image, libc::F_SEAL_SHRINK | libc::F_SEAL_GROW);
        assert_eq!(run(34_704, 34_700, &runc, &open, &checks), None);
        // one byte other, in the middle (no lot 313 sample there)
        let mut patched = image.clone();
        patched[3 << 20] ^= 0x90;
        assert_eq!(
            run(34_705, 34_700, &runc, &memfd(&patched, all), &checks),
            None
        );
        // a record of a removed runtime whose inode number the parent's
        // file has now (its path names no such file): not a runtime
        let bash_id = kernel_id(&std::fs::metadata(&bash).unwrap());
        program_identity::record_installed(InstalledImage {
            id: bash_id,
            len: 7_777_777,
            path: root
                .join("usr/sbin/runc-removed")
                .to_string_lossy()
                .into_owned(),
            kind: ProgramKind::ContainerRuntime,
        });
        // the parent runs no runtime
        assert_eq!(run(34_706, 34_707, &bash, &clone, &checks), None);
        // the file open is not the exec's (another memfd at the pid now)
        link(34_700, &runc);
        link(34_708, &fd_path(&clone));
        let mut other = memfd_exec(34_708, 34_700, 347, &clone);
        if let Event::ProcessSpawn { exe, .. } = &mut other {
            exe.ino ^= 1;
        }
        read_runtime_clone_with(&other, &proc, &root, &checks, &Settle::default());
        assert_eq!(runtime_clone_of(&other), None);
        // no identity from the LSM program (tracepoint mode): not compared
        let mut tp = memfd_exec(34_709, 34_700, 347, &clone);
        if let Event::ProcessSpawn { exe, .. } = &mut tp {
            exe.flags = common::wire::exe::exe_flags::MEMFD;
        }
        link(34_709, &fd_path(&clone));
        read_runtime_clone_with(&tp, &proc, &root, &checks, &Settle::default());
        assert_eq!(runtime_clone_of(&tp), None);
        // the budget spent: counted, not compared — kept unverified, with
        // the installed runtime of its length (the review of #556, F2)
        let poor = RuntimeChecks::new(1 << 20, 1 << 20, 0);
        assert_eq!(run(34_710, 34_700, &runc, &clone, &poor), None);
        assert_eq!(poor.bounds.skipped.load(Ordering::Relaxed), 1);
        let e = memfd_exec(34_710, 34_700, 347, &clone);
        assert_eq!(
            runtime_clone_of(&e).map(|c| (c.image, c.unverified)),
            Some((runc_id, true))
        );
        // … but only a copy every other fact holds for: not sealed, nothing
        let open = memfd(&image, libc::F_SEAL_SHRINK | libc::F_SEAL_GROW);
        link(34_724, &fd_path(&open));
        let e = memfd_exec(34_724, 34_700, 347, &open);
        read_runtime_clone_with(&e, &proc, &root, &poor, &Settle::default());
        assert_eq!(runtime_clone_of(&e), None);
        // the runtime upgraded: a new image at the path is the one compared
        // (the old inode's record names a file no longer there)
        // (the old image held open, as a process running it does: the new
        // file cannot take its inode)
        let _running = std::fs::File::open(&runc).unwrap();
        std::fs::remove_file(&runc).unwrap();
        let mut v2 = image.clone();
        v2[100] ^= 1;
        let runc2 = put(&root, "/usr/sbin/runc", &v2);
        let runc2_id = kernel_id(&std::fs::metadata(&runc2).unwrap());
        // before the new image is recorded (the second not over), the old
        // record names a file no longer at its path: its bytes are not the
        // new file's, whatever the new file holds
        let stale = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        *stale.refreshed.lock() = Some(Instant::now() + Duration::from_secs(3600));
        assert_eq!(run(34_714, 34_703, &shim, &memfd(&v2, all), &stale), None);
        let fresh = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        assert_eq!(
            run(34_711, 34_712, &runc2, &memfd(&v2, all), &fresh),
            Some(runc2_id)
        );
        assert_eq!(
            run(34_713, 34_712, &runc2, &clone, &fresh),
            None,
            "the old bytes"
        );
    }

    /// Lot 369 (the soak of rc5, Debian 13): runc 1.1's sealed clone of
    /// itself (`runc init`'s `fexecve` of `runc_cloned:/proc/self/exe`, its
    /// stdio no socket) is handed to the exec pump's runtime compare, and
    /// kept as the installed runc's clone: whatever `read_and_keep` keeps
    /// for an exec, `reads` hands it over. On 4f5f7aae the pump handed over
    /// only the execs with their stdio on an inet socket (lot 366): no clone
    /// was ever compared again, and R004 was Critical at every docker run,
    /// build and exec and every Podman run (fails there). The counters say
    /// so. Still nothing for an unsealed memfd, nor one the LSM program did
    /// not describe: R004 judges those fileless.
    #[test]
    fn runc_1_1_s_sealed_clone_is_handed_to_the_runtime_compare() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        use std::os::fd::AsRawFd;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), t.path().join("proc"));
        let mut image: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 241) as u8).collect();
        image[..4].copy_from_slice(b"r369");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let runc_id = kernel_id(&std::fs::metadata(&runc).unwrap());
        let link = |pid: u32, to: &Path| {
            std::fs::create_dir_all(proc.join(pid.to_string())).unwrap();
            let _ = std::fs::remove_file(proc.join(pid.to_string()).join("exe"));
            symlink(to, proc.join(pid.to_string()).join("exe")).unwrap();
        };
        let clone = memfd(&image, SEALED | libc::F_SEAL_SEAL);
        // `runc init` (the installed runc, run by `runc create`) re-executes
        // itself from its sealed copy: no socket anywhere in its stdio
        let e = memfd_exec(36_901, 36_900, 369, &clone);
        if let Event::ProcessSpawn { stdio, .. } = &e {
            assert!(!stdio.own.stdin_or_stdout_inet() && !stdio.parent.stdin_or_stdout_inet());
        }
        assert!(reads(&e), "the pump hands runc's sealed clone over");
        link(36_900, &runc);
        link(
            36_901,
            &PathBuf::from(format!("/proc/self/fd/{}", clone.as_raw_fd())),
        );
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
        assert_eq!(
            runtime_clone_of(&e).map(|c| (c.image, c.unverified)),
            Some((runc_id, false))
        );
        assert_eq!(
            checks.counts(),
            RuntimeCloneCounts {
                compared: 1,
                kept: 1,
                unverified: 0,
                not_read: 0,
                through: 0,
                gone: 0,
                lost: 0,
                no_runtime: 0,
            }
        );
        // CONTROLS: not sealed at the exec (an OCI hook's memfd), no identity
        // from the LSM program (tracepoint mode): not handed over
        let mut unsealed = memfd_exec(36_902, 36_900, 369, &clone);
        let mut tp = memfd_exec(36_903, 36_900, 369, &clone);
        if let (Event::ProcessSpawn { exe: a, .. }, Event::ProcessSpawn { exe: b, .. }) =
            (&mut unsealed, &mut tp)
        {
            a.flags &= !common::wire::exe::exe_flags::MEMFD_SEALED;
            b.flags &= !common::wire::exe::exe_flags::KNOWN;
        }
        assert!(!reads(&unsealed) && !reads(&tp));
        // its reads not waited for: nothing kept (R004 judges it fileless),
        // counted
        let before = runtime_clone_counts().not_read;
        let mut late = memfd_exec(36_904, 36_900, 369, &clone);
        not_read(&mut late, &Settle::default());
        assert_eq!(runtime_clone_of(&late), None);
        assert_eq!(runtime_clone_counts().not_read, before + 1);
        not_read(&mut unsealed, &Settle::default());
        assert_eq!(runtime_clone_counts().not_read, before + 1, "not a clone's");
        // a socket program's exec is still handed over (lot 313)
        let mut sock = nn_core::decision::rules::testutil::spawn("bash", "/tmp/bash");
        if let Event::ProcessSpawn { stdio, .. } = &mut sock {
            (stdio.own.read, stdio.own.inet_fds) = (true, 0b001);
        }
        assert!(reads(&sock));
    }

    /// Lot 381: a fake `/proc` for the runtime compare's tests — `exe`
    /// links and a thread's `children` (`/proc/<pid>/task/<tid>/children`).
    struct FakeProc(PathBuf);

    impl FakeProc {
        fn link(&self, pid: u32, to: &Path) {
            let d = self.0.join(pid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            let _ = std::fs::remove_file(d.join("exe"));
            symlink(to, d.join("exe")).unwrap();
        }

        fn children(&self, pid: u32, tid: u32, kids: &str) {
            let d = self.0.join(format!("{pid}/task/{tid}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("children"), kids).unwrap();
        }

        fn fd(f: &std::fs::File) -> PathBuf {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", f.as_raw_fd()))
        }
    }

    /// Lot 381 (F6-6 of the pre-alpha's Phase 6b, named): runc 1.1's
    /// `runc init` re-executes its sealed copy, forks its two stages with
    /// `CLONE_PARENT` (children of `runc create`, on whichever of its threads
    /// forked `runc init`) and exits. Under 200 rootful container starts in a
    /// row (Debian 13, rc11) the pump read one such clone in 300 once
    /// `runc init` was gone: it returned before any counter, kept nothing,
    /// and R004 judged the clone fileless, Critical (fails on 684b6d49:
    /// nothing kept). Now the copy is read through a child of `runc create`
    /// still running that very memfd — compared whole and kept, counted
    /// "through". A child running another memfd of the same bytes is not
    /// that copy: not compared, "gone", counted.
    #[test]
    fn a_runc_clone_gone_before_the_read_is_compared_through_a_child_still_running_it() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), FakeProc(t.path().join("proc")));
        // a length no other test's runtime has
        let mut image: Vec<u8> = (0..((1u32 << 20) + 381)).map(|i| (i % 239) as u8).collect();
        image[..4].copy_from_slice(b"r381");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let bash = put(&root, "/usr/bin/bash", b"bash image, 381");
        let runc_id = kernel_id(&std::fs::metadata(&runc).unwrap());
        let clone = memfd(&image, SEALED | libc::F_SEAL_SEAL);
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        // `runc create` runs the installed runc; `runc init` (38_001) is
        // gone; on one thread its sibling running bash, on another its two
        // stages — the first gone too, the second running the copy
        proc.link(38_000, &runc);
        proc.children(38_000, 38_000, "38001 38002\n");
        proc.children(38_000, 38_005, "38003 38004 ");
        proc.link(38_002, &bash);
        proc.link(38_004, &FakeProc::fd(&clone));
        let e = memfd_exec(38_001, 38_000, 381, &clone);
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(
            runtime_clone_of(&e).map(|c| (c.image, c.unverified)),
            Some((runc_id, false)),
            "compared through the stage still running the copy"
        );
        assert_eq!(
            checks.counts(),
            RuntimeCloneCounts {
                compared: 1,
                kept: 1,
                through: 1,
                ..Default::default()
            }
        );
        // CONTROL: the child runs another memfd of the very same bytes, not
        // the exec's inode — not read through it: not compared (gone), kept
        // unverified with the runtime its parent runs
        let twin = memfd(&image, SEALED | libc::F_SEAL_SEAL);
        proc.link(38_010, &runc);
        proc.children(38_010, 38_010, "38011 38014");
        proc.link(38_014, &FakeProc::fd(&twin));
        let e = memfd_exec(38_011, 38_010, 381, &clone);
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(
            runtime_clone_of(&e).map(|c| (c.image, c.unverified, c.gone)),
            Some((runc_id, true, true))
        );
        assert_eq!(
            checks.counts(),
            RuntimeCloneCounts {
                gone: 1,
                ..Default::default()
            }
        );
        // at most HOLDERS_MAX children read of one thread (the read's cost
        // bounded): a holder listed past them is not looked at
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        proc.link(38_030, &runc);
        let many: Vec<String> = (0..HOLDERS_MAX as u32)
            .map(|i| (39_000 + i).to_string())
            .collect();
        proc.children(38_030, 38_030, &format!("{} 38034", many.join(" ")));
        proc.link(38_034, &FakeProc::fd(&clone));
        let e = memfd_exec(38_031, 38_030, 381, &clone);
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(checks.counts().gone, 1, "the holder past the bound");
        // the exec's own process still running it: read there, not through
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        proc.link(38_021, &FakeProc::fd(&clone));
        proc.link(38_020, &runc);
        let e = memfd_exec(38_021, 38_020, 381, &clone);
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(
            checks.counts(),
            RuntimeCloneCounts {
                compared: 1,
                kept: 1,
                ..Default::default()
            }
        );
    }

    /// Lot 381 (F6-6, named): a sealed memfd exec whose copy no process
    /// runs any more by the pump's read is counted, never outside every
    /// counter (fails on 684b6d49: no count moved) — "gone", kept unverified
    /// with the runtime its parent runs, when the parent is an installed
    /// runtime and the exec runc 1.1's re-exec (R004: root's High, any other
    /// uid's the Critical kill); its parent gone too, its parent a manager
    /// (which runtime it copied is not known), or (the review of #588, F2)
    /// runc 1.2's shape — a first exec since the fork, every OCI hook's —
    /// nothing kept, counted "lost": R004's fileless Critical (kept "gone"
    /// at 51a0f11d).
    #[test]
    fn a_runtime_clone_with_nothing_left_running_it_is_counted_not_compared() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), FakeProc(t.path().join("proc")));
        let mut image: Vec<u8> = (0..((1u32 << 20) + 3810))
            .map(|i| (i % 233) as u8)
            .collect();
        image[..4].copy_from_slice(b"g381");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let shim = put(&root, "/usr/bin/conmon", b"conmon image, 381");
        let runc_id = kernel_id(&std::fs::metadata(&runc).unwrap());
        let clone = memfd(&image, SEALED | libc::F_SEAL_SEAL);
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        let before = checks.counts();
        // under `runc create`, nothing running the copy any more
        proc.link(38_100, &runc);
        let e = memfd_exec(38_101, 38_100, 381, &clone);
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_ne!(checks.counts(), before, "counted");
        let kept = runtime_clone_of(&e).expect("kept unverified");
        assert_eq!(
            (kept.image, kept.unverified, kept.gone, kept.seen),
            (runc_id, true, true, vec![(38_100, runc_id)])
        );
        // its parent gone too: no runtime to tell — nothing kept
        let e = memfd_exec(38_111, 38_110, 381, &clone);
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(runtime_clone_of(&e), None);
        // under a manager (crun's shape): which runtime it copied is not
        // known — nothing kept
        proc.link(38_120, &shim);
        let e = memfd_exec(38_121, 38_120, 381, &clone);
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(runtime_clone_of(&e), None);
        // the review of #588 (F2): runc 1.2's shape under `runc create` —
        // the exec's first since its fork (an OCI hook's too): nothing kept
        let mut e = memfd_exec(38_102, 38_100, 381, &clone);
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.fork_parent = 38_100;
        }
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(runtime_clone_of(&e), None, "runc 1.2's shape, gone");
        assert_eq!(
            checks.counts(),
            RuntimeCloneCounts {
                gone: 1,
                lost: 3,
                ..Default::default()
            }
        );
    }

    /// Lot 381 (the ratchet of F6-6): every sealed memfd exec the LSM
    /// program described lands in exactly one of the compare's counters —
    /// compared (kept or not, read through a child or not), not compared
    /// for the budget, gone, lost (the review of #588, F4), no runtime's,
    /// not read in time — whatever stops it; one the LSM program did not
    /// describe moves none (it is not read).
    #[test]
    fn every_sealed_memfd_exec_lands_in_exactly_one_runtime_counter() {
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), FakeProc(t.path().join("proc")));
        let mut image: Vec<u8> = (0..((1u32 << 20) + 3820))
            .map(|i| (i % 229) as u8)
            .collect();
        image[..4].copy_from_slice(b"e381");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let bash = put(&root, "/usr/bin/bash", b"bash image, 381 e");
        let sealed_copy = |bytes: &[u8]| memfd(bytes, SEALED | libc::F_SEAL_SEAL);
        let clone = sealed_copy(&image);
        let mut patched = image.clone();
        patched[1 << 19] ^= 1;
        let patched = sealed_copy(&patched);
        let short = sealed_copy(&image[..image.len() - 1]);
        let unsealed = memfd(&image, 0);
        // uid 1000's share too small for one compare; root's ample (its
        // reserve given: root's budget is the global one)
        let checks = RuntimeChecks::new(1 << 20, 1 << 30, 1 << 29);
        proc.link(38_200, &runc);
        proc.link(38_290, &bash);
        let as_uid = |mut e: Event, uid: u32| {
            if let Event::ProcessSpawn { uid: u, .. } = &mut e {
                *u = uid;
            }
            e
        };
        let mut n = 0u64;
        // the exec whose step the pump stopped waiting for
        const LATE: u32 = 38_212;
        // `ran`: the file the exec ran (its identity in the event);
        // `running`: what its `/proc/<pid>/exe` names now (none: gone)
        let mut run =
            |pid: u32, ppid: u32, ran: &std::fs::File, running: Option<&Path>, uid: u32| {
                if let Some(to) = running {
                    proc.link(pid, to);
                }
                let e = as_uid(memfd_exec(pid, ppid, 381, ran), uid);
                let before = checks.counts();
                // the review of #588 (F3): the pump's step and, past its
                // deadline, `not_read` — one count between them
                let settle = Settle::default();
                if pid == LATE {
                    count_not_read(&e, &checks, &settle);
                }
                read_runtime_clone_with(&e, &proc.0, &root, &checks, &settle);
                count_not_read(&e, &checks, &settle);
                let after = checks.counts();
                let moved = (after.compared - before.compared)
                    + (after.unverified - before.unverified)
                    + (after.gone - before.gone)
                    + (after.lost - before.lost)
                    + (after.no_runtime - before.no_runtime)
                    + (after.not_read - before.not_read);
                assert_eq!(moved, 1, "pid {pid}: {before:?} → {after:?}");
                n += 1;
            };
        let fd = FakeProc::fd;
        run(38_201, 38_200, &clone, Some(&fd(&clone)), 0); // compared, kept
        run(38_202, 38_200, &patched, Some(&fd(&patched)), 0); // compared, not kept
        run(38_203, 38_200, &clone, Some(&fd(&clone)), 1000); // its share spent
        run(38_204, 38_200, &clone, None, 0); // gone
        run(38_205, 38_299, &clone, Some(&fd(&clone)), 0); // its parent gone
        run(38_206, 38_290, &clone, Some(&fd(&clone)), 0); // under bash
        run(38_207, 38_200, &short, Some(&fd(&short)), 0); // no runtime's length
        run(38_208, 38_200, &unsealed, Some(&fd(&unsealed)), 0); // not sealed now
        // the mini-hunt: its pid running another file now (executed again,
        // or reused), and a zombie (its `/proc` entry, no `exe`)
        run(38_210, 38_200, &clone, Some(&bash), 0);
        std::fs::create_dir_all(proc.0.join("38211/task/38211")).unwrap();
        std::fs::write(
            proc.0.join("38211/task/38211/stat"),
            "38211 (runc:[1:CHILD]) Z 38200 1",
        )
        .unwrap();
        run(38_211, 38_200, &clone, None, 0);
        // the review of #588: not read in time (F3); its leader exited, a
        // thread running the copy (F1); a thread of it running, its copy
        // not read (F1)
        run(LATE, 38_200, &clone, Some(&fd(&clone)), 0);
        let thread = proc.0.join("38213/task/38214");
        std::fs::create_dir_all(&thread).unwrap();
        symlink(fd(&clone), thread.join("exe")).unwrap();
        run(38_213, 38_200, &clone, None, 0);
        let thread = proc.0.join("38215/task/38216");
        std::fs::create_dir_all(&thread).unwrap();
        std::fs::write(thread.join("stat"), "38216 (k381) S 38200 1").unwrap();
        run(38_215, 38_200, &clone, None, 0);
        let c = checks.counts();
        assert_eq!(
            c.compared + c.unverified + c.gone + c.lost + c.no_runtime + c.not_read,
            n
        );
        assert_eq!(
            (
                c.compared,
                c.kept,
                c.unverified,
                c.gone,
                c.lost,
                c.no_runtime,
                c.not_read
            ),
            (3, 2, 1, 2, 3, 3, 1)
        );
        // the pid running another file keeps nothing (R004's Critical);
        // the zombie's copy (every thread exited), its length not known, is
        // kept unverified: "not compared (gone)"; the late one keeps nothing
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let at = |pid: u32| runtime_clone_of(&memfd_exec(pid, 38_200, 381, &clone));
        assert_eq!(at(38_210), None);
        assert_eq!(
            at(38_211).map(|c| (c.unverified, c.gone)),
            Some((true, true))
        );
        assert_eq!(at(LATE), None, "kept past the deadline");
        assert_eq!(at(38_213).map(|c| c.unverified), Some(false));
        assert_eq!(at(38_215), None);
        // not described by the LSM program (tracepoint mode): not read
        let mut tp = memfd_exec(38_209, 38_200, 381, &clone);
        if let Event::ProcessSpawn { exe, .. } = &mut tp {
            exe.flags &= !common::wire::exe::exe_flags::KNOWN;
        }
        read_runtime_clone_with(&tp, &proc.0, &root, &checks, &Settle::default());
        assert_eq!(checks.counts(), c);
    }

    /// The review of #588 (F1, named): the exec's leader exited alone (a
    /// plain `exit` of its main thread, not `exit_group`) while another of
    /// its threads runs the payload — a zombie leader of a live thread
    /// group: `/proc/<pid>/exe` unreadable, `/proc/<pid>/task/<tid>/exe` the
    /// memfd, the process alive (a kill ends it). At 51a0f11d the pump took
    /// it as exited and kept a foreign root memfd "not compared (gone)" —
    /// R004 High, never killed. Now the copy is read through the live
    /// thread: a foreign memfd (of no runtime's length, or of its length
    /// with other bytes) keeps nothing — R004's fileless Critical with the
    /// kill — and runc's own copy is compared and kept. Exited only when no
    /// listed thread has not exited: a thread still running whose copy is
    /// not read, a thread past the bound, a thread whose state cannot be
    /// read — nothing kept, "lost".
    #[test]
    fn a_live_thread_group_whose_leader_exited_is_read_through_its_threads() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), FakeProc(t.path().join("proc")));
        let mut image: Vec<u8> = (0..((1u32 << 20) + 5880))
            .map(|i| (i % 227) as u8)
            .collect();
        image[..4].copy_from_slice(b"p588");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let runc_id = kernel_id(&std::fs::metadata(&runc).unwrap());
        let sealed_copy = |bytes: &[u8]| memfd(bytes, SEALED | libc::F_SEAL_SEAL);
        let foreign = sealed_copy(b"a foreign payload, not the runtime");
        let mut other = image.clone();
        other[1 << 19] ^= 1;
        let other = sealed_copy(&other);
        let clone = sealed_copy(&image);
        proc.link(58_800, &runc);
        // `tid` of `pid`: running `exe` (a link), or in `state` (no link)
        let thread = |pid: u32, tid: u32, exe: Option<&std::fs::File>, state: Option<&str>| {
            let d = proc.0.join(format!("{pid}/task/{tid}"));
            std::fs::create_dir_all(&d).unwrap();
            if let Some(f) = exe {
                symlink(FakeProc::fd(f), d.join("exe")).unwrap();
            }
            if let Some(s) = state {
                std::fs::write(d.join("stat"), format!("{tid} (k 588) {s} 58800 1")).unwrap();
            }
        };
        let read = |pid: u32, ran: &std::fs::File| {
            let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
            let e = memfd_exec(pid, 58_800, 588, ran);
            read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
            (
                runtime_clone_of(&e).map(|c| (c.image, c.unverified, c.gone)),
                checks.counts(),
            )
        };
        // the leader a zombie, a thread running a foreign memfd: nothing
        // kept (the review's probe)
        thread(58_801, 58_801, None, Some("Z"));
        thread(58_801, 58_802, Some(&foreign), None);
        assert_eq!(
            read(58_801, &foreign),
            (
                None,
                RuntimeCloneCounts {
                    no_runtime: 1,
                    ..Default::default()
                }
            ),
            "a running thread group's foreign memfd kept as a gone runtime copy"
        );
        // ... of the runtime's length, other bytes: compared, not kept
        thread(58_803, 58_803, None, Some("Z"));
        thread(58_803, 58_804, Some(&other), None);
        assert_eq!(
            read(58_803, &other),
            (
                None,
                RuntimeCloneCounts {
                    compared: 1,
                    ..Default::default()
                }
            )
        );
        // ... runc's own copy: compared whole, kept (its own process's)
        thread(58_805, 58_806, Some(&clone), None);
        assert_eq!(
            read(58_805, &clone),
            (
                Some((runc_id, false, false)),
                RuntimeCloneCounts {
                    compared: 1,
                    kept: 1,
                    ..Default::default()
                }
            )
        );
        let lost = RuntimeCloneCounts {
            lost: 1,
            ..Default::default()
        };
        // a thread still running, its copy not read: never "gone"
        thread(58_807, 58_807, None, Some("Z"));
        thread(58_808, 58_808, None, Some("Z"));
        thread(58_808, 58_809, None, Some("R"));
        assert_eq!(read(58_808, &clone), (None, lost));
        // a thread whose state is not read (not for its absence), or not
        // understood
        thread(58_810, 58_811, None, None);
        std::fs::create_dir_all(proc.0.join("58810/task/58811/stat")).unwrap();
        assert_eq!(read(58_810, &clone), (None, lost));
        thread(58_818, 58_819, None, None);
        std::fs::write(proc.0.join("58818/task/58819/stat"), "58819 no state").unwrap();
        assert_eq!(read(58_818, &clone), (None, lost));
        // a thread running another file (the process executed again):
        // nothing kept
        let bash = put(&root, "/usr/bin/bash", b"bash image, 588");
        thread(58_816, 58_816, None, Some("Z"));
        let d = proc.0.join("58816/task/58817");
        std::fs::create_dir_all(&d).unwrap();
        symlink(&bash, d.join("exe")).unwrap();
        assert_eq!(read(58_816, &clone), (None, lost));
        // more threads than are read, those read all exited
        for tid in 0..=HOLDERS_MAX as u32 {
            thread(58_812, 59_000 + tid, None, Some("Z"));
        }
        assert_eq!(read(58_812, &clone), (None, lost));
        // CONTROLS — every thread exited (the zombie leader, a thread dead,
        // one reaped as it was listed): gone, kept unverified (runc 1.1's
        // re-exec under runc)
        let gone = (
            Some((runc_id, true, true)),
            RuntimeCloneCounts {
                gone: 1,
                ..Default::default()
            },
        );
        assert_eq!(read(58_807, &clone), gone);
        thread(58_813, 58_813, None, Some("Z"));
        thread(58_813, 58_814, None, Some("X"));
        thread(58_813, 58_815, None, None);
        assert_eq!(read(58_813, &clone), gone);
    }

    /// The re-check of #588 (N1, N2; named): the threads' listing is no
    /// snapshot — a thread made after the `readdir` while the listed one
    /// exits before its read is not seen (1.7% of reads of such a group on
    /// 6.18, a live group taken as exited: "gone", root's High) — and a
    /// listing that fails for another reason than the process's absence
    /// (`EMFILE`, a `readdir` error) said nothing of the group either. At
    /// c0868bb9 both were "gone", kept unverified. Now gone only when the
    /// leader's `num_threads` (the kernel's count, one read) is 1 or its
    /// `stat` is gone; else nothing kept, "lost" (R004's fileless
    /// Critical).
    #[test]
    fn a_group_whose_listing_missed_a_live_thread_is_never_gone() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), FakeProc(t.path().join("proc")));
        let mut image: Vec<u8> = (0..((1u32 << 20) + 5884))
            .map(|i| (i % 211) as u8)
            .collect();
        image[..4].copy_from_slice(b"n588");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let runc_id = kernel_id(&std::fs::metadata(&runc).unwrap());
        let clone = memfd(&image, SEALED | libc::F_SEAL_SEAL);
        proc.link(58_840, &runc);
        // `pid`: its leader a listed zombie; its own `stat` (none: reaped)
        // counting `threads`
        let zombie = |pid: u32, threads: Option<&str>| {
            let d = proc.0.join(format!("{pid}/task/{pid}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("stat"), format!("{pid} (k 588) Z 58840 1")).unwrap();
            if let Some(n) = threads {
                // fields 3 to 19, then `num_threads` (field 20)
                let fields = format!("Z 58840 {} {n} 0 0", "0 ".repeat(15).trim_end());
                std::fs::write(
                    proc.0.join(format!("{pid}/stat")),
                    format!("{pid} (k 588) {fields}"),
                )
                .unwrap();
            }
        };
        let read = |pid: u32| {
            let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
            let e = memfd_exec(pid, 58_840, 588, &clone);
            read_runtime_clone_with(&e, &proc.0, &root, &checks, &Settle::default());
            (
                runtime_clone_of(&e).map(|c| (c.image, c.unverified, c.gone)),
                checks.counts(),
            )
        };
        let lost = (
            None,
            RuntimeCloneCounts {
                lost: 1,
                ..Default::default()
            },
        );
        // N1: every listed thread exited, the kernel counting two
        zombie(58_841, Some("2"));
        assert_eq!(read(58_841), lost, "a live thread the listing missed");
        // ... or a count not read as one
        zombie(58_842, Some("many"));
        assert_eq!(read(58_842), lost);
        // N2: the listing failed, not for the process's absence
        std::fs::create_dir_all(proc.0.join("58843")).unwrap();
        std::fs::write(proc.0.join("58843/task"), "not a directory").unwrap();
        assert_eq!(read(58_843), lost, "a listing error taken as gone");
        // CONTROLS: the leader alone (its zombie counted), or the process
        // reaped (no `stat`, no `task`): gone, kept unverified
        let gone = (
            Some((runc_id, true, true)),
            RuntimeCloneCounts {
                gone: 1,
                ..Default::default()
            },
        );
        zombie(58_844, Some("1"));
        assert_eq!(read(58_844), gone);
        zombie(58_845, None);
        assert_eq!(read(58_845), gone);
        assert_eq!(read(58_846), gone);
    }

    /// The review of #588 (F3, named): the pump stopped waiting for a
    /// runtime compare (its deadline passed: `not_read` counted the exec
    /// "not read in time", R004 judged it without a clone), and the compare
    /// finished later. At 51a0f11d it counted the exec a second time
    /// (compared) and kept a clone R004 had judged without. Now one count
    /// and one clone per exec, whichever of the step and `not_read` comes
    /// first ([`Settle`]); a step in time keeps its count and clone, and
    /// a `not_read` after it moves nothing.
    #[test]
    fn a_runtime_compare_past_its_deadline_counts_and_keeps_nothing_more() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), FakeProc(t.path().join("proc")));
        let mut image: Vec<u8> = (0..((1u32 << 20) + 5883))
            .map(|i| (i % 223) as u8)
            .collect();
        image[..4].copy_from_slice(b"d588");
        let runc = put(&root, "/usr/sbin/runc", &image);
        let clone = memfd(&image, SEALED | libc::F_SEAL_SEAL);
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        proc.link(58_830, &runc);
        proc.link(58_831, &FakeProc::fd(&clone));
        proc.link(58_832, &FakeProc::fd(&clone));
        // past the deadline: `not_read` first, the step's late answer after
        let late = memfd_exec(58_831, 58_830, 588, &clone);
        let settle = Settle::default();
        count_not_read(&late, &checks, &settle);
        read_runtime_clone_with(&late, &proc.0, &root, &checks, &settle);
        assert_eq!(
            checks.counts(),
            RuntimeCloneCounts {
                not_read: 1,
                ..Default::default()
            },
            "counted twice"
        );
        assert_eq!(runtime_clone_of(&late), None, "kept after R004 judged");
        // in time: the step's count and clone; a `not_read` after it, none
        let e = memfd_exec(58_832, 58_830, 588, &clone);
        let settle = Settle::default();
        read_runtime_clone_with(&e, &proc.0, &root, &checks, &settle);
        count_not_read(&e, &checks, &settle);
        assert_eq!(
            checks.counts(),
            RuntimeCloneCounts {
                not_read: 1,
                compared: 1,
                kept: 1,
                ..Default::default()
            }
        );
        assert!(runtime_clone_of(&e).is_some());
    }

    /// The review of #556 (F1, named): the memfd runc's OCI hook is executed
    /// from (`/proc/<A>/fd/N`) was open for writing at the exec; its holder
    /// then wrote runc's bytes into it and sealed it before the pump's read.
    /// Sealed and runc's whole when the pump reads it, but not sealed when
    /// the kernel executed it (no `MEMFD_SEALED` from the LSM program): no
    /// clone kept (fails on the lot's first head: it was kept as runc's).
    #[test]
    fn a_memfd_sealed_only_after_its_exec_is_no_runtime_clone() {
        use common::wire::exe::exe_flags::MEMFD_SEALED;
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        use std::io::{Seek, Write};
        use std::os::fd::AsRawFd;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), t.path().join("proc"));
        let image: Vec<u8> = (0..(1u32 << 20)).map(|i| (i % 241) as u8).collect();
        let runc = put(&root, "/usr/sbin/runc", &image);
        let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
        let link = |pid: u32, to: &Path| {
            std::fs::create_dir_all(proc.join(pid.to_string())).unwrap();
            symlink(to, proc.join(pid.to_string()).join("exe")).unwrap();
        };
        // executed unsealed, holding another program; then rewritten with
        // runc's bytes and sealed
        let mut hook = memfd(b"\x7fELF the hook's payload", 0);
        hook.set_len(0).unwrap();
        hook.rewind().unwrap();
        hook.write_all(&image).unwrap();
        // SAFETY: F_ADD_SEALS on the descriptor `hook` owns; no memory.
        assert_eq!(
            unsafe {
                libc::fcntl(
                    hook.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    SEALED | libc::F_SEAL_SEAL,
                )
            },
            0
        );
        assert!(sealed(&hook));
        link(35_600, &runc);
        link(
            35_601,
            &PathBuf::from(format!("/proc/self/fd/{}", hook.as_raw_fd())),
        );
        let mut e = memfd_exec(35_601, 35_600, 556, &hook);
        if let Event::ProcessSpawn { exe, .. } = &mut e {
            exe.flags &= !MEMFD_SEALED;
        }
        read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
        assert_eq!(runtime_clone_of(&e), None, "sealed after the exec");
        // the same file, the record sealed at the exec: runc's clone
        let e = memfd_exec(35_602, 35_600, 556, &hook);
        link(
            35_602,
            &PathBuf::from(format!("/proc/self/fd/{}", hook.as_raw_fd())),
        );
        read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
        assert_eq!(
            runtime_clone_of(&e).map(|c| (c.image, c.unverified)),
            Some((kernel_id(&std::fs::metadata(&runc).unwrap()), false))
        );
    }

    /// The re-check of #556 (N1; its probe): a user spends its OWN share
    /// (decoy hooks, genuine runc copies), then a sealed memfd of runc's
    /// LENGTH but other bytes (a padded payload, an OCI hook run from
    /// `/proc/<pid>/fd/N`) under runc is kept "not compared" — the fact R004
    /// judges by the uid: a uid but 0 keeps the Critical kill
    /// (`a_users_uncompared_memfd_past_its_own_share_stays_critical`).
    #[test]
    fn a_users_payload_of_runc_len_past_its_own_share_is_kept_not_compared() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        // lot 379: it reads the process's degradation registry, which the
        // tests that reset it do under this lock (a reset between the report
        // and the read below failed a gate run)
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), t.path().join("proc"));
        // a length no other test's runtime has: the installed runtimes are
        // one registry for the test binary (`runtimes_of_len`), and
        // `a_memfd_sealed_only_after_its_exec_is_no_runtime_clone`'s runc of
        // 1 MiB, recorded in parallel, was this one's first candidate (a
        // flake the gates met)
        let image: Vec<u8> = (0..((1u32 << 20) + 4093))
            .map(|i| (i % 241) as u8)
            .collect();
        let runc = put(&root, "/usr/sbin/runc", &image);
        let checks = production_checks();
        // the user's own decoys spend its share (the review of #585, F2: the
        // whole of its burst)
        assert!(
            checks
                .bounds
                .take(1000, RUNTIME_BURST_PER_UID, Instant::now())
        );
        let link = |pid: u32, to: &Path| {
            std::fs::create_dir_all(proc.join(pid.to_string())).unwrap();
            symlink(to, proc.join(pid.to_string()).join("exe")).unwrap();
        };
        let payload: Vec<u8> = image.iter().map(|b| b ^ 0x5a).collect();
        let hook = memfd(&payload, SEALED | libc::F_SEAL_SEAL);
        link(35_700, &runc);
        link(
            35_701,
            &PathBuf::from(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&hook)
            )),
        );
        let mut e = memfd_exec(35_701, 35_700, 556, &hook);
        if let Event::ProcessSpawn { uid, .. } = &mut e {
            *uid = 1000;
        }
        read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
        let runc_id = kernel_id(&std::fs::metadata(&runc).unwrap());
        assert_eq!(
            runtime_clone_of(&e).map(|c| (c.image, c.unverified)),
            Some((runc_id, true)),
            "kept not compared, never as runc's compared image"
        );
        assert_eq!(checks.bounds.skipped.load(Ordering::Relaxed), 1);
        // lot 370 (F10-6): the budget spent is signed, naming the uid
        assert!(
            crate::boot::degradation::entries()
                .iter()
                .any(|d| d.source == "runtime_copy_compare" && d.detail == budget_spent_line(1000))
        );
        // the review of #578 (N3): the episode's first skip names who spent
        // the budget — the user itself, its decoys' share
        assert_eq!(
            runtime_clone_of(&e).and_then(|c| c.episode),
            Some(program_identity::BudgetEpisode {
                uid: 1000,
                top: Some((1000, RUNTIME_BURST_PER_UID)),
            })
        );
        // the next skip of the same episode names nothing
        let hook2 = memfd(&payload, SEALED | libc::F_SEAL_SEAL);
        link(
            35_702,
            &PathBuf::from(format!(
                "/proc/self/fd/{}",
                std::os::fd::AsRawFd::as_raw_fd(&hook2)
            )),
        );
        let mut e2 = memfd_exec(35_702, 35_700, 557, &hook2);
        if let Event::ProcessSpawn { uid, .. } = &mut e2 {
            *uid = 1000;
        }
        read_runtime_clone_with(&e2, &proc, &root, &checks, &Settle::default());
        assert_eq!(
            runtime_clone_of(&e2).map(|c| (c.unverified, c.episode)),
            Some((true, None))
        );
    }

    /// The review of #578 (N3, named): a skip for the budget opens an
    /// episode only after a quiet minute of that uid's — a steady flood is
    /// one episode, one record naming who spent the budget — each uid its
    /// own; the biggest spender is the uid that read the most this second.
    #[test]
    fn a_spent_budget_is_one_episode_per_quiet_minute_and_names_its_spender() {
        let checks = production_checks();
        let t0 = Instant::now();
        assert!(checks.opens_episode(0, t0));
        assert!(!checks.opens_episode(0, t0 + Duration::from_secs(30)));
        // remembered at each skip: 59 s after the last one, still the same
        assert!(!checks.opens_episode(0, t0 + Duration::from_secs(89)));
        assert!(checks.opens_episode(0, t0 + Duration::from_secs(149)));
        assert!(checks.opens_episode(1000, t0 + Duration::from_secs(149)));
        // who read the most this second
        assert!(checks.bounds.take(1000, 40 << 20, t0));
        assert!(checks.bounds.take(0, 100 << 20, t0));
        assert!(checks.bounds.take(1001, 10 << 20, t0));
        assert_eq!(checks.bounds.top_spender(t0), Some((0, 100 << 20)));
        assert_eq!(
            checks.bounds.top_spender(t0 + Duration::from_secs(2)),
            None,
            "a second past: nobody spends"
        );
    }

    /// The review of #556 (F2, named; its probe): seventeen 30 MiB compares
    /// by one rootless user (runc 1.1's `runc init` clones in a loop) spent
    /// the budget of every uid — root's Docker start in the same second was
    /// not compared: R004's Critical and kill. Each uid but root has a share
    /// well below the global budget, and the uids but root together leave
    /// root a reserve: the user's third compare is refused, root's still
    /// fits, and a crowd of users cannot spend root's reserve (fails on the
    /// lot's first head: per-uid == global, nothing reserved).
    #[test]
    fn one_uid_cannot_spend_root_s_runtime_budget() {
        let c = production_checks();
        // the review of #585 (F2): the user's burst spent a second before
        // (its loop's first starts) — what its share paid back since is all
        // it has
        let t0 = Instant::now();
        assert!(c.bounds.take(1000, RUNTIME_BURST_PER_UID, t0));
        let now = t0 + Duration::from_secs(1);
        let start = 30 << 20;
        assert!(c.bounds.take(1000, start, now));
        assert!(c.bounds.take(1000, start, now));
        for _ in 0..15 {
            assert!(!c.bounds.take(1000, start, now), "one user's share");
        }
        assert!(c.bounds.take(0, start, now), "root's start compared");
        // many users: together never past the global budget less root's
        // reserve
        let mut users = 0u64;
        for uid in 2000..2100 {
            while c.bounds.take(uid, start, now) {
                users += start;
            }
        }
        assert!(
            2 * start + users <= RUNTIME_BUDGET_PER_SECOND - RUNTIME_ROOT_RESERVE,
            "{users}"
        );
        let mut root = start;
        while c.bounds.take(0, start, now) {
            root += start;
        }
        assert!(root >= RUNTIME_ROOT_RESERVE, "{root}");
        // the shares are well below the global budget, root's reserve eight
        // runc 1.1 starts
        const {
            assert!(RUNTIME_BUDGET_PER_UID * 4 <= RUNTIME_BUDGET_PER_SECOND - RUNTIME_ROOT_RESERVE);
            assert!(RUNTIME_ROOT_RESERVE >= 8 * (30 << 20));
            // the review of #585 (F2): a burst fits in one second of the
            // users' part of the global budget, never in root's reserve
            assert!(RUNTIME_BURST_PER_UID > RUNTIME_BUDGET_PER_UID);
            assert!(RUNTIME_BURST_PER_UID <= RUNTIME_BUDGET_PER_SECOND - RUNTIME_ROOT_RESERVE);
        }
        // the next second: the user's share again
        assert!(c.bounds.take(1000, start, now + Duration::from_secs(1)));
        // the pump's own checks are these
        let b = &RUNTIMES.bounds;
        assert_eq!(
            (
                b.budget,
                b.global_budget,
                b.root_budget,
                b.root_reserve,
                b.burst
            ),
            (
                RUNTIME_BUDGET_PER_UID,
                RUNTIME_BUDGET_PER_SECOND,
                RUNTIME_BUDGET_PER_SECOND,
                RUNTIME_ROOT_RESERVE,
                RUNTIME_BURST_PER_UID
            )
        );
        // lot 313's compares keep their own (no reserve: root a uid as any;
        // no burst)
        assert_eq!(
            (
                BOUNDS.budget,
                BOUNDS.root_budget,
                BOUNDS.root_reserve,
                BOUNDS.burst
            ),
            (BUDGET_PER_SECOND, BUDGET_PER_SECOND, 0, 0)
        );
    }

    /// The review of #585 (F2, named; the lab of lot 378 on Debian 13):
    /// thirty `podman run` in a row by one rootless user — runc 1.1.15's
    /// sealed copy of itself (10,683,064 bytes, compared against the
    /// installed runc: twice its length read) about every 0.27 s — met the
    /// share of a second eight times: eight copies not compared, R004's
    /// Critical. With the share a token bucket every one of them is
    /// compared, at that pace and at a faster host's (0.2 s); a sustained
    /// flood still runs out (the share's rate holds), and its debt is paid
    /// back at that rate only. Fails on 68d3e37b (eight refused).
    #[test]
    fn thirty_rootless_starts_in_a_row_are_all_compared_and_a_flood_still_runs_out() {
        let start: u64 = 2 * 10_683_064;
        for every_ms in [270, 200] {
            let c = production_checks();
            let t0 = Instant::now();
            let refused = (0..30u64)
                .filter(|i| {
                    !c.bounds
                        .take(1000, start, t0 + Duration::from_millis(i * every_ms))
                })
                .count();
            assert_eq!(refused, 0, "one start every {every_ms} ms");
        }
        // a flood: ten starts a second for ten seconds
        let c = production_checks();
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let granted = (0..100u64)
            .filter(|i| c.bounds.take(1000, start, at(i * 100)))
            .count() as u64;
        // no more than the burst and ten seconds of the share
        assert!(
            granted * start <= RUNTIME_BURST_PER_UID + 10 * RUNTIME_BUDGET_PER_UID,
            "{granted} granted"
        );
        assert!(granted < 100, "the flood runs out");
        // spent: paid back at the share's rate, never at once
        while c.bounds.take(1000, start, at(10_000)) {}
        assert!(!c.bounds.take(1000, start, at(10_000)), "spent");
        assert!(
            c.bounds.take(1000, start, at(10_340)),
            "a start's worth paid back in a third of a second"
        );
        assert!(
            !c.bounds.take(1000, 3 * start, at(10_680)),
            "never three starts' worth in a third more"
        );
        // root keeps its second's budget, no burst: its own share of the
        // global one, untouched by the user's
        let r = production_checks();
        assert!(r.bounds.take(0, RUNTIME_BUDGET_PER_SECOND, t0));
        assert!(!r.bounds.take(0, 1, t0), "root's second spent");
        assert!(r.bounds.take(0, 1, t0 + Duration::from_secs(1)));
    }

    /// The review of #585 (F2, named): a foreign sealed memfd of runc's
    /// length under an installed runtime stays the Critical one whatever
    /// the user's flood does — within its burst it is compared and kept as
    /// no clone (R004: fileless); past it, kept unverified (R004: "not
    /// compared (budget)", the kill for a uid but root). The burst adds no
    /// trust.
    #[test]
    fn a_foreign_memfd_under_a_flood_is_never_kept_as_runc_s_clone() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), t.path().join("proc"));
        // a length no other test's runtime has (one registry per binary)
        let image: Vec<u8> = (0..((1u32 << 20) + 5851))
            .map(|i| (i % 239) as u8)
            .collect();
        let runc = put(&root, "/usr/sbin/runc", &image);
        let checks = production_checks();
        let link = |pid: u32, to: &Path| {
            std::fs::create_dir_all(proc.join(pid.to_string())).unwrap();
            symlink(to, proc.join(pid.to_string()).join("exe")).unwrap();
        };
        link(35_850, &runc);
        let payload: Vec<u8> = image.iter().map(|b| b ^ 0x3c).collect();
        let exec = |pid: u32, ts: u64| {
            let hook = memfd(&payload, SEALED | libc::F_SEAL_SEAL);
            link(
                pid,
                &PathBuf::from(format!(
                    "/proc/self/fd/{}",
                    std::os::fd::AsRawFd::as_raw_fd(&hook)
                )),
            );
            let mut e = memfd_exec(pid, 35_850, ts, &hook);
            if let Event::ProcessSpawn { uid, .. } = &mut e {
                *uid = 1000;
            }
            read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
            (runtime_clone_of(&e).map(|c| c.unverified), hook)
        };
        // within the burst: compared, no clone kept
        assert_eq!(exec(35_851, 851).0, None, "compared: no clone");
        assert_eq!(checks.bounds.compared.load(Ordering::Relaxed), 1);
        // the user's flood spends the rest of its burst: kept unverified
        while checks.bounds.take(1000, 1 << 20, Instant::now()) {}
        assert_eq!(
            exec(35_852, 852).0,
            Some(true),
            "past the burst: not compared, unverified"
        );
        assert_eq!(checks.bounds.compared.load(Ordering::Relaxed), 1);
    }

    /// The review of #585 (F2): a full uid table keeps a uid whose burst
    /// still owes, whatever its second — clearing it would give it its burst
    /// again; a uid whose debt is paid and second is over leaves.
    #[test]
    fn a_full_uid_table_keeps_a_uid_whose_burst_owes() {
        let c = production_checks();
        let t0 = Instant::now();
        assert!(c.bounds.take(1000, RUNTIME_BURST_PER_UID, t0));
        // other uids, a byte each, fill the table a second later (the global
        // budget's next second; their debts paid back at once)
        for uid in 2000..(2000 + UIDS_CAP as u32 - 1) {
            assert!(c.bounds.take(uid, 1, t0 + Duration::from_secs(1)));
        }
        // a new uid 1.1 s after those: the paid-up uids leave, the owing one
        // stays
        let later = t0 + Duration::from_millis(2100);
        assert!(c.bounds.take(70_000, 1, later));
        assert!(
            !c.bounds.take(1000, RUNTIME_BURST_PER_UID * 3 / 4, later),
            "its burst still owes"
        );
    }

    /// The review of #556 (F7, named): a runtime or manager is recorded only
    /// when its resolved file and every directory above it are the owner's
    /// of the tree's root (root's on the host) and writable by no one else.
    /// A link to a file in a group-writable directory, a group- or
    /// world-writable file, a link out of the tree: no runtime (fails on the
    /// lot's first head: each was recorded by its name).
    #[test]
    fn a_runtime_file_a_user_can_rewrite_is_no_installed_runtime() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let r = t.path().join("root");
        let out = tempfile::tempdir().unwrap();
        let mode = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let kinds = |r: &Path| -> Vec<String> {
            installed_runtimes_under(r)
                .into_iter()
                .map(|i| {
                    Path::new(&i.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        };
        let runc = put(&r, "/usr/sbin/runc", b"runc image, 556 f7");
        put(&r, "/usr/bin/containerd", b"containerd image, 556 f7");
        // a group-writable directory's file, linked from a binary directory
        let staff = put(&r, "/usr/local/share/rt/crun", b"crun image, 556 f7");
        mode(staff.parent().unwrap(), 0o775);
        std::fs::create_dir_all(r.join("usr/local/bin")).unwrap();
        symlink(&staff, r.join("usr/local/bin/crun")).unwrap();
        // a world-writable file
        let conmon = put(&r, "/usr/bin/conmon", b"conmon image, 556 f7");
        mode(&conmon, 0o757);
        // a link out of the tree (a user's home on the host)
        let home = put(out.path(), "/podman", b"podman image, 556 f7");
        symlink(&home, r.join("usr/local/bin/podman")).unwrap();
        let mut found = kinds(&r);
        found.sort();
        assert_eq!(found, ["containerd", "runc"]);
        // the binary directory itself group-writable: nothing under it
        mode(runc.parent().unwrap(), 0o775);
        assert_eq!(kinds(&r), ["containerd"]);
        // the shells' records are not narrowed (no trust flows from them)
        let sh = put(&r, "/usr/sbin/sh", b"sh image, 556 f7");
        assert!(image_of(&sh, ProgramKind::Shell, &r).is_some());
    }

    /// The review of #556 (F7): the owner counts, not the modes alone — a
    /// file the test's user made, in directories only that user can write,
    /// is no root-only file under `/` (root's), and is one under its own
    /// tree (the user's). Skipped as root (root owns what it makes) and where
    /// a directory above the test's binary is writable by others (the modes
    /// alone would refuse it).
    #[test]
    fn a_file_of_another_owner_than_the_tree_s_root_is_not_root_only() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let t = tempfile::tempdir_in(exe.parent().unwrap()).unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = put(t.path(), "/usr/sbin/runc", b"runc image, 556 f7 owner");
        let real = std::fs::canonicalize(&f).unwrap();
        let modes_alone = real
            .ancestors()
            .all(|a| std::fs::metadata(a).is_ok_and(|m| m.mode() & 0o022 == 0));
        if !modes_alone {
            return;
        }
        assert!(
            !root_only_path(&real, Path::new("/")),
            "the user's file under root's /"
        );
        assert!(
            root_only_path(&real, t.path()),
            "under its own owner's tree"
        );
    }

    /// Lot 347: R020's compare looks at the shells, interpreters, busybox
    /// and the loader only — a copy of an installed runtime with its stdio
    /// on a socket is compared with none of them (no shell runs in it).
    #[test]
    fn r020_compares_no_runtime() {
        use nn_core::decision::rules::program_identity::{copy_of, record_installed};
        let t = tempfile::tempdir().unwrap();
        let (root, proc) = (t.path().join("root"), t.path().join("proc"));
        // lot 348: a length no other test's file has — this test's record,
        // its inode reused by the refresh test's 21-byte `ls` once this
        // tempdir went, named that file a runtime (a flake of the suite)
        let image: &[u8] = b"runc image of lot 347's r020 test";
        let runc = put(&root, "/usr/sbin/runc", image);
        let copy = put(&root, "/home/u/x", image);
        record_installed(InstalledImage {
            id: kernel_id(&std::fs::metadata(&runc).unwrap()),
            len: image.len() as u64,
            path: runc.to_string_lossy().into_owned(),
            kind: ProgramKind::ContainerRuntime,
        });
        std::fs::create_dir_all(proc.join("34720")).unwrap();
        symlink(&copy, proc.join("34720/exe")).unwrap();
        let e = exec(34_720, 347, outbound());
        read_and_keep_with(&e, &proc, &Bounds::new(1 << 20, 1 << 20));
        assert_eq!(copy_of(&e), None);
    }

    /// Lot 347: at a memfd exec the runtimes are recorded again (one
    /// installed since the minute's refresh), at most once a second; only
    /// the runtimes' and their managers' names, by the file they resolve to
    /// (a link named `runc` to another program records that program, if it
    /// is one), and podman's conmon outside the binary directories.
    #[test]
    fn the_runtimes_are_recorded_again_at_most_once_a_second() {
        use nn_core::decision::rules::program_identity::installed_kind_sized;
        // by identity and length: another test's file, removed, may have
        // left its inode number to one of these
        let installed_kind = |(id, len): ((u64, u64), u64)| installed_kind_sized(id, len);
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        // the tree's root as a host's, whatever the test's umask (F7)
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(r, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let id = |p: &Path| {
            let m = std::fs::metadata(p).unwrap();
            (kernel_id(&m), m.len())
        };
        let runc = put(r, "/usr/bin/runc", b"runc image, 347 refresh");
        let checks = RuntimeChecks::new(1 << 20, 1 << 20, 0);
        let now = Instant::now();
        checks.refresh(r, now);
        assert_eq!(
            installed_kind(id(&runc)),
            Some(ProgramKind::ContainerRuntime)
        );
        let crun = put(r, "/usr/bin/crun", b"crun image, 347 refresh");
        let conmon = put(
            r,
            "/usr/libexec/podman/conmon",
            b"conmon image, 347 refresh",
        );
        let ls = put(r, "/usr/bin/ls", b"ls image, 347 refresh");
        std::fs::create_dir_all(r.join("usr/sbin")).unwrap();
        symlink(&ls, r.join("usr/sbin/runc")).unwrap();
        checks.refresh(r, now + Duration::from_millis(900));
        assert_eq!(installed_kind(id(&crun)), None, "within the second");
        checks.refresh(r, now + Duration::from_millis(1100));
        assert_eq!(
            installed_kind(id(&crun)),
            Some(ProgramKind::ContainerRuntime)
        );
        assert_eq!(
            installed_kind(id(&conmon)),
            Some(ProgramKind::RuntimeManager)
        );
        assert_eq!(installed_kind(id(&ls)), None, "a link named runc to ls");
        // the runtimes are no shells for R020's compare
        assert!(
            ProgramKind::of_name("runc").is_none() && ProgramKind::of_name("dockerd").is_none()
        );
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

    /// Lot 313 (the review of #549, F1): an exec of a 64 MiB near-copy (its
    /// last byte off) of an installed interpreter, its stdio on a socket,
    /// costs the pump a bounded read — the samples, about 2.5 MiB a file —
    /// and the same file is not read again; the near-copy is no copy.
    #[test]
    fn a_64_mib_near_copy_cannot_stall_the_pump() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let n = 64usize << 20;
        let content: Vec<u8> = (0..n)
            .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[1])
            .collect();
        put(r, "/usr/local/bin/node", &content);
        refresh_under(r);
        let mut near = content;
        *near.last_mut().unwrap() ^= 1;
        let x = put(r, "/home/u/x", &near);
        let proc_root = r.join("proc");
        std::fs::create_dir_all(proc_root.join("31390")).unwrap();
        symlink(&x, proc_root.join("31390/exe")).unwrap();
        let e = exec(31390, 1, outbound());
        let bounds = Bounds::new(BUDGET_PER_SECOND, GLOBAL_BUDGET_PER_SECOND);
        let t0 = Instant::now();
        read_and_keep_with(&e, &proc_root, &bounds);
        let first = t0.elapsed();
        assert_eq!(program_identity::copy_of(&e), None, "one byte off: no copy");
        assert_eq!(bounds.compared.load(Ordering::Relaxed), 1);
        assert!(compare_cost(n as u64) <= 2 * (2 * EDGE + BLOCKS * BLOCK));
        assert!(
            compare_cost(n as u64) < 6 << 20,
            "{}",
            compare_cost(n as u64)
        );
        // the same file again: remembered, not read
        let e2 = exec(31390, 2, outbound());
        read_and_keep_with(&e2, &proc_root, &bounds);
        assert_eq!(bounds.compared.load(Ordering::Relaxed), 1);
        assert_eq!(bounds.remembered.load(Ordering::Relaxed), 1);
        // a whole 64 MiB compare would read 128 MiB; the samples, ~5 MiB
        assert!(first < Duration::from_secs(5), "{first:?}");
    }

    /// F1: the compares share a budget a second; past it an exec is not
    /// compared — counted — and judged by its name as before.
    #[test]
    fn past_the_budget_an_exec_is_counted_not_compared() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let n = (6usize << 20) + 251;
        let content: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        put(r, "/usr/bin/python3.12", &content);
        refresh_under(r);
        let proc_root = r.join("proc");
        let bounds = Bounds::new(3 * compare_cost(n as u64), u64::MAX);
        for i in 0..10u32 {
            let mut near = content.clone();
            near[n - 1] = i as u8 ^ 0xff;
            let x = put(r, &format!("/home/u/x{i}"), &near);
            let pid = 31_400 + i;
            std::fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            symlink(&x, proc_root.join(format!("{pid}/exe"))).unwrap();
            read_and_keep_with(&exec(pid, 1, outbound()), &proc_root, &bounds);
        }
        assert_eq!(bounds.compared.load(Ordering::Relaxed), 3);
        assert_eq!(bounds.skipped.load(Ordering::Relaxed), 7);
        // the coordinator's fail-safe: an exec not compared is marked
        // unverified for R020, never silently passed
        assert!(program_identity::unverified(&exec(31_409, 1, outbound())));
        assert!(!program_identity::unverified(&exec(31_400, 1, outbound())));
    }

    /// F1: above 4 MiB the samples cover the file's first and last MiB and
    /// eight blocks between — a file that matches an installed program there
    /// is that program (a copy patched elsewhere is still the shell: the
    /// check only ever adds one).
    #[test]
    fn a_large_file_is_compared_by_its_samples() {
        let len = 100u64 << 20;
        let r = compared_ranges(len);
        assert_eq!(r.len(), 2 + BLOCKS as usize);
        assert!(r.contains(&(0, EDGE)) && r.contains(&(len - EDGE, EDGE)));
        assert!(r.iter().all(|(from, n)| from + n <= len));
        assert_eq!(compared_ranges(WHOLE_LEN), vec![(0, WHOLE_LEN)]);
    }

    /// F4: under the dynamic loader the file compared is its operand (by
    /// the process's root, or its working directory for a relative one): a
    /// copy of bash run as `ld.so ~/x` is bash.
    #[test]
    fn under_the_dynamic_loader_its_operand_is_compared() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let content = b"#!bash image of lot 313, f4".repeat(1000);
        put(r, "/usr/bin/bash", &content);
        refresh_under(r);
        let proc_root = r.join("proc");
        put(&proc_root, "/31395/root/home/u/x", &content);
        put(&proc_root, "/31396/cwd/y", &content);
        let under_loader = |pid: u32, operand: &str| {
            let mut e = exec(pid, 1, outbound());
            if let Event::ProcessSpawn {
                exe,
                argv,
                filename,
                ..
            } = &mut e
            {
                exe.path = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2".into();
                *filename = "/lib64/ld-linux-x86-64.so.2".into();
                *argv = vec!["ld.so".into(), operand.into(), "-i".into()];
            }
            read_and_keep_at(&e, &proc_root);
            e
        };
        for (pid, operand) in [(31395u32, "/home/u/x"), (31396, "y")] {
            let e = under_loader(pid, operand);
            assert_eq!(
                program_identity::copy_of(&e),
                Some(ProgramKind::Shell),
                "{operand}"
            );
            assert!(!program_identity::unverified(&e), "{operand}");
        }
        // an operand the pump cannot open (a user's FUSE mount, a file gone):
        // unverified, never silently passed (the re-check of #549, R1/R2)
        let gone = under_loader(31397, "/home/u/gone");
        assert!(program_identity::unverified(&gone));
        assert_eq!(program_identity::copy_of(&gone), None);
    }

    /// The re-check of #549 (R1): one user's flood spends only that user's
    /// budget — another uid is still compared; and an exec whose image the
    /// pump cannot open (a user's FUSE mount without `allow_other`, a file
    /// gone) is unverified, never silently passed.
    #[test]
    fn the_budget_is_per_uid_and_an_unreadable_image_is_unverified() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let n = (6usize << 20) + 249;
        let content: Vec<u8> = (0..n).map(|i| (i % 249) as u8).collect();
        put(r, "/usr/bin/perl5.40", &content);
        refresh_under(r);
        let proc_root = r.join("proc");
        let bounds = Bounds::new(compare_cost(n as u64), u64::MAX);
        let as_uid = |pid: u32, uid: u32, tail: u8| {
            let mut near = content.clone();
            near[n - 1] = tail;
            let x = put(r, &format!("/home/u{uid}/x{pid}"), &near);
            std::fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            symlink(&x, proc_root.join(format!("{pid}/exe"))).unwrap();
            let mut e = exec(pid, 1, outbound());
            if let Event::ProcessSpawn { uid: u, .. } = &mut e {
                *u = uid;
            }
            read_and_keep_with(&e, &proc_root, &bounds);
            e
        };
        let a1 = as_uid(31_500, 1001, 1);
        let a2 = as_uid(31_501, 1001, 2);
        let b1 = as_uid(31_502, 1002, 3);
        assert!(!program_identity::unverified(&a1), "the first, compared");
        assert!(
            program_identity::unverified(&a2),
            "the same user's budget spent"
        );
        assert!(!program_identity::unverified(&b1), "another user: compared");
        assert_eq!(bounds.compared.load(Ordering::Relaxed), 2);
        assert_eq!(bounds.skipped.load(Ordering::Relaxed), 1);
        // no `exe` to open: unverified
        let gone = exec(31_503, 1, outbound());
        read_and_keep_with(&gone, &proc_root, &bounds);
        assert!(program_identity::unverified(&gone));
    }

    /// Lot 366: an exec's image a FUSE file system's that answers nothing:
    /// it is never opened through its daemon — unverified (R020 records
    /// it), at once (on 993795e0 the open waited on the daemon).
    #[test]
    fn an_image_on_a_fuse_that_answers_nothing_is_unverified_at_once() {
        let rc = crate::fuse_testing::answers_beside_a_held_fuse(|held| {
            let t = tempfile::tempdir().unwrap();
            let proc_root = t.path().join("proc");
            std::fs::create_dir_all(proc_root.join("31700")).unwrap();
            symlink(held, proc_root.join("31700/exe")).unwrap();
            let e = exec(31_700, 9, outbound());
            read_and_keep_with(&e, &proc_root, &Bounds::new(1 << 20, 1 << 20));
            program_identity::unverified(&e)
        });
        if let Some(rc) = rc {
            assert_eq!(rc, 0, "answered (0), not held (5) nor verified (1)");
        }
    }

    /// Lot 366: a sealed memfd's exec whose process runs another file by
    /// the pump's read (it executed again: here a FUSE file system's that
    /// answers nothing) is not opened — no clone, at once.
    #[test]
    fn a_memfd_exec_running_another_file_is_not_opened() {
        use nn_core::decision::rules::program_identity::runtime_clone_of;
        let rc = crate::fuse_testing::answers_beside_a_held_fuse(|held| {
            let t = tempfile::tempdir().unwrap();
            let (root, proc) = (t.path().join("root"), t.path().join("proc"));
            let mut image: Vec<u8> = (0..(1u32 << 16)).map(|i| (i % 251) as u8).collect();
            image[..4].copy_from_slice(b"runc");
            let runc = put(&root, "/usr/sbin/runc", &image);
            for (pid, to) in [(36_610u32, runc.as_path()), (36_611, held)] {
                std::fs::create_dir_all(proc.join(pid.to_string())).unwrap();
                symlink(to, proc.join(pid.to_string()).join("exe")).unwrap();
            }
            let clone = memfd(&image, SEALED | libc::F_SEAL_SEAL);
            let e = memfd_exec(36_611, 36_610, 366, &clone);
            let checks = RuntimeChecks::new(1 << 30, 1 << 30, 0);
            read_runtime_clone_with(&e, &proc, &root, &checks, &Settle::default());
            runtime_clone_of(&e).is_none()
        });
        if let Some(rc) = rc {
            assert_eq!(rc, 0, "answered (0), not held (5) nor a clone (1)");
        }
    }

    /// Lot 366: only an exec with its stdio (or its parent's) on an inet
    /// socket is read (and so handed to the pumps' reader).
    #[test]
    fn only_a_socket_program_s_exec_is_read() {
        assert!(reads(&exec(31_810, 13, outbound())));
        assert!(!reads(&exec(31_811, 14, StdioSocket::default())));
        let mut e = exec(31_812, 15, StdioSocket::default());
        if let Event::ProcessSpawn { stdio, .. } = &mut e {
            stdio.parent = outbound();
        }
        assert!(reads(&e), "the parent's");
    }

    /// Lot 366: an exec with its stdio on a socket whose reads were not
    /// waited for is unverified (R020 records it) — unless the kernel's
    /// identity is an installed program's; one with no socket keeps nothing.
    #[test]
    fn an_exec_not_read_in_time_is_unverified() {
        let mut e = exec(31_800, 11, outbound());
        not_read(&mut e, &Settle::default());
        assert!(program_identity::unverified(&e));
        let mut quiet = exec(31_801, 12, StdioSocket::default());
        not_read(&mut quiet, &Settle::default());
        assert!(!program_identity::unverified(&quiet));
    }

    /// Lot 366: an exec's image on a file system the judge refuses (a
    /// user's FUSE file system — its daemon would answer the open, or never
    /// — a network one, one PID 1's table does not show) is not opened:
    /// unverified (R020 records it), where the same image judged by the
    /// host's table is compared.
    #[test]
    fn an_image_on_a_file_system_the_agent_does_not_ask_is_unverified() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let content: Vec<u8> = (0..4462u32).map(|i| (i % 251) as u8).collect();
        put(r, "/usr/bin/perl5.41", &content);
        refresh_under(r);
        let proc_root = r.join("proc");
        let x = put(r, "/home/u/x", &content);
        std::fs::create_dir_all(proc_root.join("31600")).unwrap();
        symlink(&x, proc_root.join("31600/exe")).unwrap();
        let bounds = Bounds::new(1 << 20, 1 << 20);
        let none = Judge::of(&crate::mountinfo::parse(b""));
        let e = exec(31_600, 7, outbound());
        read_and_keep_judged(&e, &proc_root, &bounds, &none);
        assert!(program_identity::unverified(&e), "not opened: unverified");
        assert_eq!(bounds.compared.load(Ordering::Relaxed), 0);
        let e = exec(31_600, 8, outbound());
        read_and_keep_judged(&e, &proc_root, &bounds, &Judge::host());
        assert!(
            !program_identity::unverified(&e),
            "the host's table: compared"
        );
    }

    /// The re-check 2 of #549 (N1), the reviewer's probe: 300 uids (the
    /// subuids rootless podman maps) each asking for a whole budget, twice
    /// in one second, are granted the global budget in all — never 64 MiB
    /// each (the full uid table was cleared: 38,400 MiB in one second).
    #[test]
    fn many_uids_share_one_global_budget() {
        let b = Bounds::new(BUDGET_PER_SECOND, GLOBAL_BUDGET_PER_SECOND);
        let now = Instant::now();
        let take_all = |at: Instant| {
            (0..300u32)
                .filter(|uid| b.take(100_000 + uid, BUDGET_PER_SECOND, at))
                .count() as u64
        };
        let granted = take_all(now);
        let again = take_all(now + Duration::from_millis(500));
        assert!(
            (granted + again) * BUDGET_PER_SECOND <= GLOBAL_BUDGET_PER_SECOND,
            "{granted} then {again} uids granted 64 MiB in one second"
        );
        assert_eq!(granted, GLOBAL_BUDGET_PER_SECOND / BUDGET_PER_SECOND);
        assert_eq!(again, 0);
        // the next second: the global budget again, no more
        let next = take_all(now + Duration::from_millis(1500));
        assert_eq!(next, GLOBAL_BUDGET_PER_SECOND / BUDGET_PER_SECOND);
    }

    /// The re-check 2 of #549 (N1): a full uid table loses its least
    /// recently used uid, never every uid's spent budget.
    #[test]
    fn a_full_uid_table_evicts_one_never_clears() {
        let b = Bounds::new(1000, u64::MAX);
        let now = Instant::now();
        let at = |us: u64| now + Duration::from_micros(us);
        for uid in 0..UIDS_CAP as u32 {
            assert!(
                b.take(uid, 1000, at(uid.into())),
                "every uid of the table takes its first budget"
            );
        }
        // uid 0 asks again (refused): uid 1 is now the least recently used
        assert!(!b.take(0, 1, at(299)));
        assert!(b.take(70_000, 1000, at(300)), "a new uid, the table full");
        assert_eq!(b.spent.lock().uids.len(), UIDS_CAP);
        assert!(
            !b.spent.lock().uids.contains_key(&1),
            "the least recent out"
        );
        for uid in (0..UIDS_CAP as u32).filter(|uid| *uid != 1) {
            assert!(!b.take(uid, 1, at(400)), "a kept uid's budget stays spent");
        }
    }

    /// The re-check 2 of #549 (N1): past the global budget an exec of
    /// another uid is not compared — counted, and unverified, as past its
    /// own budget.
    #[test]
    fn past_the_global_budget_an_exec_is_unverified() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let n = (6usize << 20) + 241;
        let content: Vec<u8> = (0..n).map(|i| (i % 241) as u8).collect();
        put(r, "/usr/bin/perl5.42", &content);
        refresh_under(r);
        let proc_root = r.join("proc");
        let bounds = Bounds::new(u64::MAX, compare_cost(n as u64));
        let as_uid = |pid: u32, uid: u32, tail: u8| {
            let mut near = content.clone();
            near[n - 1] = tail;
            let x = put(r, &format!("/home/u{uid}/x{pid}"), &near);
            std::fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            symlink(&x, proc_root.join(format!("{pid}/exe"))).unwrap();
            let mut e = exec(pid, 1, outbound());
            if let Event::ProcessSpawn { uid: u, .. } = &mut e {
                *u = uid;
            }
            read_and_keep_with(&e, &proc_root, &bounds);
            e
        };
        let a = as_uid(31_600, 165_536, 1);
        let b = as_uid(31_601, 165_537, 2);
        assert!(!program_identity::unverified(&a), "the first, compared");
        assert!(program_identity::unverified(&b), "the global budget spent");
        assert_eq!(bounds.compared.load(Ordering::Relaxed), 1);
        assert_eq!(bounds.skipped.load(Ordering::Relaxed), 1);
    }

    /// The re-check of #549 (R2): the installed dynamic loader is recorded,
    /// and a renamed copy of it running bash is the loader — its operand
    /// (an installed bash, or a copy of bash) is what the exec runs.
    #[test]
    fn a_renamed_copy_of_the_loader_runs_its_operand() {
        let t = tempfile::tempdir().unwrap();
        let r = t.path();
        let loader = b"ld.so image of lot 313, r2".repeat(500);
        let bash = b"bash image of lot 313, r2".repeat(700);
        put(r, "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", &loader);
        std::fs::create_dir_all(r.join("lib64")).unwrap();
        symlink(
            r.join("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
            r.join("lib64/ld-linux-x86-64.so.2"),
        )
        .unwrap();
        put(r, "/usr/bin/bash", &bash);
        assert!(
            installed_under(r)
                .iter()
                .any(|i| i.kind == ProgramKind::Loader)
        );
        refresh_under(r);
        let proc_root = r.join("proc");
        let x = put(r, "/home/u/x", &loader);
        let y = put(&proc_root, "/31510/cwd/y", &bash);
        for (pid, operand) in [(31_510u32, "y"), (31_511, "/usr/bin/bash")] {
            std::fs::create_dir_all(proc_root.join(pid.to_string())).unwrap();
            symlink(&x, proc_root.join(format!("{pid}/exe"))).unwrap();
            if operand.starts_with('/') {
                put(&proc_root, &format!("/{pid}/root{operand}"), &bash);
            }
            let mut e = exec(pid, 1, outbound());
            if let Event::ProcessSpawn { argv, filename, .. } = &mut e {
                *filename = "/home/u/x".into();
                *argv = vec!["x".into(), operand.into(), "-i".into()];
            }
            read_and_keep_at(&e, &proc_root);
            assert_eq!(
                program_identity::copy_of(&e),
                Some(ProgramKind::Shell),
                "{operand}"
            );
            assert_eq!(program_identity::shell_or_interpreter(&e), Some(true));
        }
        let _ = y;
    }
}
