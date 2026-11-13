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
        Self {
            memo: Mutex::new((HashMap::new(), VecDeque::new())),
            spent: Mutex::new(Spent::default()),
            budget,
            global_budget,
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
    fn take(&self, uid: u32, bytes: u64, now: Instant) -> bool {
        let second = Duration::from_secs(1);
        let mut s = self.spent.lock();
        let all = match s.all {
            Some((t, n)) if now.duration_since(t) < second => (t, n),
            _ => (now, 0),
        };
        if all.1.saturating_add(bytes) > self.global_budget {
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
        if e.1.saturating_add(bytes) > self.budget {
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
    let Ok(fb) = std::fs::File::open(b) else {
        return false;
    };
    if !fb.metadata().is_ok_and(|m| m.is_file() && m.len() == len) {
        return false;
    }
    let mut ba = vec![0u8; 64 * 1024];
    let mut bb = vec![0u8; 64 * 1024];
    for (from, n) in compared_ranges(len) {
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

/// `path` (followed) as an installed program of `kind`.
fn image_of(path: &Path, kind: ProgramKind) -> Option<InstalledImage> {
    let real = std::fs::canonicalize(path).ok()?;
    let m = std::fs::metadata(&real).ok()?;
    if !m.is_file() {
        return None;
    }
    Some(InstalledImage {
        id: (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        ),
        len: m.len(),
        path: real.to_string_lossy().into_owned(),
        kind,
    })
}

/// The kind of an installed file, by the name of the file a path resolves
/// to (`/usr/bin/sh` → `dash`; `/bin/sh` on Alpine → `busybox`).
fn kind_of(path: &Path) -> Option<ProgramKind> {
    let real = std::fs::canonicalize(path).ok()?;
    ProgramKind::of_name(&real.to_string_lossy())
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
        let Some(image) = kind_of(&p).and_then(|k| image_of(&p, k)) else {
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

/// The exec pump's step (module docs).
pub fn read_and_keep(event: &Event) {
    read_and_keep_at(event, Path::new("/proc"));
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
    let candidates: Vec<InstalledImage> = program_identity::installed_of_len(m.len())
        .into_iter()
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

#[cfg(test)]
mod tests {
    use super::*;
    use nn_model::{StdioSocket, StdioSockets};
    use std::os::unix::fs::symlink;

    fn put(root: &Path, path: &str, content: &[u8]) -> PathBuf {
        let f = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, content).unwrap();
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
            assert!(b.take(uid, 1000, at(uid.into())), "uid {uid}");
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
            assert!(!b.take(uid, 1, at(400)), "uid {uid}'s budget kept spent");
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
