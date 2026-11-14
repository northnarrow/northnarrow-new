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
//!   #556, F2); a clone past it is kept unverified (R004: recorded, never
//!   killed).
//!
//! A name only chooses which installed files are recorded; what an exec
//! runs is then told by the file, never by its name.

use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

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
    compared: AtomicU64,
    skipped: AtomicU64,
    remembered: AtomicU64,
}

/// The bytes the compares read in the current second: each uid's (the
/// re-check of #549, R1: one user's flood spends only that user's) and all
/// of them (its re-check 2, N1).
#[derive(Default)]
struct Spent {
    /// uid → (its second's start, the bytes it read in it, its last take).
    uids: HashMap<u32, (Instant, u64, Instant)>,
    /// every uid's: (the second's start, the bytes read in it).
    all: Option<(Instant, u64)>,
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
    /// less root's reserve.
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
            s.uids
                .retain(|_, (t, _, _)| now.duration_since(*t) < second);
            // never all of them at once (the re-check 2 of #549, N1: that
            // gave each uid its budget again): the least recently used out
            while s.uids.len() >= UIDS_CAP {
                let Some(oldest) = s
                    .uids
                    .iter()
                    .min_by_key(|(_, (_, _, last))| *last)
                    .map(|(uid, _)| *uid)
                else {
                    break;
                };
                s.uids.remove(&oldest);
            }
        }
        let e = s.uids.entry(uid).or_insert((now, 0, now));
        if now.duration_since(e.0) >= second {
            (e.0, e.1) = (now, 0);
        }
        e.2 = now;
        if e.1.saturating_add(bytes) > budget {
            return false;
        }
        e.1 += bytes;
        s.all = Some((all.0, all.1 + bytes));
        true
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
    let Ok(fb) = std::fs::File::open(b) else {
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
    let m = std::fs::metadata(&real).ok()?;
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
    let Ok(owner) = std::fs::metadata(&root).map(|m| m.uid()) else {
        return false;
    };
    real.starts_with(&root)
        && real
            .ancestors()
            .take_while(|a| a.starts_with(&root))
            .all(|a| std::fs::metadata(a).is_ok_and(|m| m.uid() == owner && m.mode() & 0o022 == 0))
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
    if let Ok(text) = std::fs::read(root.join("etc/shells")) {
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
/// (lot 347) a memfd exec's runtime clone ([`read_runtime_clone`]).
pub fn read_and_keep(event: &Event) {
    read_and_keep_at(event, Path::new("/proc"));
    read_runtime_clone(event);
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

/// What the file at `path` is (`None`: no installed program's copy),
/// bounded by `bounds` for `uid`; `expect`: the identity the hook gave.
fn identify(
    path: &Path,
    expect: Option<(u64, u64)>,
    uid: u32,
    bounds: &Bounds,
) -> Result<Option<ProgramKind>, Unverified> {
    let file = std::fs::File::open(path).map_err(|_| Unverified::Unreadable)?;
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
    let Event::ProcessSpawn {
        pid,
        uid,
        filename,
        exe,
        argv,
        stdio,
        ..
    } = event
    else {
        return;
    };
    if !stdio.own.stdin_or_stdout_inet() && !stdio.parent.stdin_or_stdout_inet() {
        return;
    }
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
            &dir.join("exe"),
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
    let path = match program.strip_prefix('/') {
        Some(abs) => dir.join("root").join(abs),
        None => dir.join("cwd").join(program),
    };
    match identify(&path, None, *uid, bounds) {
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
/// Docker starts). Past its share a clone is not compared: kept unverified,
/// R004 records it (High) and never kills. Only an exec whose parent runs
/// an installed runtime or its manager reaches a compare.
const RUNTIME_BUDGET_PER_SECOND: u64 = 512 << 20;

/// The review of #556 (F2): each uid's share of it but root's — about two
/// runc 1.1 starts a second (a rootless Podman user's).
const RUNTIME_BUDGET_PER_UID: u64 = 64 << 20;

/// The review of #556 (F2): the part of it the uids but root together
/// never spend — root's container starts (Docker's, rootful Podman's) keep
/// at least this whatever the users run.
const RUNTIME_ROOT_RESERVE: u64 = 256 << 20;

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
}

impl RuntimeChecks {
    /// Each uid's `per_uid`, root up to `global`, which the others together
    /// spend only less `root_reserve` (F2).
    fn new(per_uid: u64, global: u64, root_reserve: u64) -> Self {
        Self {
            bounds: Bounds::with_root_reserve(per_uid, global, root_reserve),
            refreshed: Mutex::new(None),
        }
    }

    /// The runtimes under `root` recorded, unless done in the last
    /// [`RUNTIME_REFRESH_EVERY`].
    fn refresh(&self, root: &Path, now: Instant) {
        {
            let mut at = self.refreshed.lock();
            if at.is_some_and(|t| now.duration_since(t) < RUNTIME_REFRESH_EVERY) {
                return;
            }
            *at = Some(now);
        }
        for image in installed_runtimes_under(root) {
            program_identity::record_installed(image);
        }
    }
}

static RUNTIMES: LazyLock<RuntimeChecks> = LazyLock::new(|| {
    RuntimeChecks::new(
        RUNTIME_BUDGET_PER_UID,
        RUNTIME_BUDGET_PER_SECOND,
        RUNTIME_ROOT_RESERVE,
    )
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
/// without the clone.
pub fn read_runtime_clone(event: &Event) {
    read_runtime_clone_with(event, Path::new("/proc"), Path::new("/"), &RUNTIMES);
}

/// [`read_runtime_clone`] with `/proc` at `proc_root`, the host's root at
/// `root` and `checks` (tests).
fn read_runtime_clone_with(event: &Event, proc_root: &Path, root: &Path, checks: &RuntimeChecks) {
    use common::wire::exe::exe_flags::{KNOWN, MEMFD, MEMFD_SEALED};
    let Event::ProcessSpawn {
        pid,
        ppid,
        uid,
        exe,
        ..
    } = event
    else {
        return;
    };
    // the review of #556 (F1): sealed when the kernel executed it, by the
    // LSM program's read of its seals — sealed only when the pump reads it,
    // its bytes may have been rewritten after the exec (any holder of a
    // writable descriptor: the parent of an OCI hook run from
    // `/proc/<pid>/fd/N`)
    if !exe.has(KNOWN) || !exe.has(MEMFD) || !exe.has(MEMFD_SEALED) || *pid == 0 || *ppid == 0 {
        return;
    }
    checks.refresh(root, Instant::now());
    // first the parent, one `stat` of its image: a runtime's or a manager's
    let image = |pid: u32| {
        std::fs::metadata(proc_root.join(pid.to_string()).join("exe"))
            .ok()
            .map(|m| kernel_id(&m))
    };
    let Some(parent) = image(*ppid).filter(|id| installed_at_its_path(*id).is_some()) else {
        return;
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
    let Ok(file) = std::fs::File::open(proc_root.join(pid.to_string()).join("exe")) else {
        return;
    };
    let Ok(m) = file.metadata() else {
        return;
    };
    if kernel_id(&m) != (exe.dev, exe.ino)
        || !m.is_file()
        || m.len() == 0
        || m.len() > RUNTIME_MAX_LEN
        || !sealed(&file)
    {
        return;
    }
    let candidates: Vec<InstalledImage> = program_identity::runtimes_of_len(m.len())
        .into_iter()
        .take(MAX_COMPARED)
        .collect();
    if candidates.is_empty() {
        return;
    }
    let cost = 2 * m.len() * candidates.len() as u64;
    if !checks.bounds.take(*uid, cost, Instant::now()) {
        checks.bounds.skipped.fetch_add(1, Ordering::Relaxed);
        // the review of #556 (F2): every fact but the bytes holds — kept
        // unverified (R004 records it, never kills it)
        program_identity::keep_runtime_clone(
            event,
            program_identity::RuntimeClone {
                image: candidates[0].id,
                seen,
                unverified: true,
            },
        );
        return;
    }
    checks.bounds.compared.fetch_add(1, Ordering::Relaxed);
    let whole = [(0, m.len())];
    if let Some(found) = candidates
        .iter()
        .find(|i| same_over(&file, Path::new(&i.path), m.len(), Some(i.id), &whole))
    {
        program_identity::keep_runtime_clone(
            event,
            program_identity::RuntimeClone {
                image: found.id,
                seen,
                unverified: false,
            },
        );
    }
}

/// Lot 347: the installed runtime or manager whose identity `id` is, when
/// the file at its recorded path is that inode still — an inode number a
/// removed runtime had, now another file's elsewhere, is not it.
fn installed_at_its_path(id: (u64, u64)) -> Option<ProgramKind> {
    let image = program_identity::installed_image(id)?;
    if !image.kind.is_container_runtime() {
        return None;
    }
    std::fs::metadata(&image.path)
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
    use nn_model::{StdioSocket, StdioSockets};
    use std::os::unix::fs::symlink;

    /// `content` at `path` under `root`, the directories it makes 0755 and
    /// the file 0644 — as a distribution installs them, whatever the test's
    /// umask (0002 under a user unit): only root-only files are runtimes
    /// (the review of #556, F7).
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
                read_runtime_clone_with(&e, &proc, &root, checks);
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
        read_runtime_clone_with(&e, &proc, &root, &checks);
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
        read_runtime_clone_with(&e, &proc, &root, &checks);
        assert_eq!(
            runtime_clone_of(&e).map(|c| c.seen),
            Some(vec![(34_700, runc_id)])
        );
        stat(34_700, 34_715, 200);
        stat(34_715, 1, 300);
        link(34_717, &fd_path(&clone));
        let e = memfd_exec(34_717, 34_700, 347, &clone);
        read_runtime_clone_with(&e, &proc, &root, &checks);
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
        read_runtime_clone_with(&other, &proc, &root, &checks);
        assert_eq!(runtime_clone_of(&other), None);
        // no identity from the LSM program (tracepoint mode): not compared
        let mut tp = memfd_exec(34_709, 34_700, 347, &clone);
        if let Event::ProcessSpawn { exe, .. } = &mut tp {
            exe.flags = common::wire::exe::exe_flags::MEMFD;
        }
        link(34_709, &fd_path(&clone));
        read_runtime_clone_with(&tp, &proc, &root, &checks);
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
        read_runtime_clone_with(&e, &proc, &root, &poor);
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
        read_runtime_clone_with(&e, &proc, &root, &checks);
        assert_eq!(runtime_clone_of(&e), None, "sealed after the exec");
        // the same file, the record sealed at the exec: runc's clone
        let e = memfd_exec(35_602, 35_600, 556, &hook);
        link(
            35_602,
            &PathBuf::from(format!("/proc/self/fd/{}", hook.as_raw_fd())),
        );
        read_runtime_clone_with(&e, &proc, &root, &checks);
        assert_eq!(
            runtime_clone_of(&e).map(|c| (c.image, c.unverified)),
            Some((kernel_id(&std::fs::metadata(&runc).unwrap()), false))
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
        let c = RuntimeChecks::new(
            RUNTIME_BUDGET_PER_UID,
            RUNTIME_BUDGET_PER_SECOND,
            RUNTIME_ROOT_RESERVE,
        );
        let now = Instant::now();
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
        }
        // the next second: the user's share again
        assert!(c.bounds.take(1000, start, now + Duration::from_secs(1)));
        // the pump's own checks are these
        let b = &RUNTIMES.bounds;
        assert_eq!(
            (b.budget, b.global_budget, b.root_budget, b.root_reserve),
            (
                RUNTIME_BUDGET_PER_UID,
                RUNTIME_BUDGET_PER_SECOND,
                RUNTIME_BUDGET_PER_SECOND,
                RUNTIME_ROOT_RESERVE
            )
        );
        // lot 313's compares keep their own (no reserve: root a uid as any)
        assert_eq!(
            (BOUNDS.budget, BOUNDS.root_budget, BOUNDS.root_reserve),
            (BUDGET_PER_SECOND, BUDGET_PER_SECOND, 0)
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
        let runc = put(&root, "/usr/sbin/runc", b"runc image, 347, r020");
        let copy = put(&root, "/home/u/x", b"runc image, 347, r020");
        record_installed(InstalledImage {
            id: kernel_id(&std::fs::metadata(&runc).unwrap()),
            len: 21,
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
        assert!(installed_under(r)
            .iter()
            .any(|i| i.kind == ProgramKind::Loader));
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
