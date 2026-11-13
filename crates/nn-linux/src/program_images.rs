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
/// The bytes the compares may read in a second (both files counted).
const BUDGET_PER_SECOND: u64 = 64 << 20;
/// The answers remembered, by file, at most (the oldest out).
const MEMO_CAP: usize = 1024;

/// A file by what changes when its content can: `(dev, ino, size, ctime)`.
type FileKey = (u64, u64, u64, i64, i64);

/// The answers by file, and their order (the oldest first out).
type Memo = (HashMap<FileKey, Option<ProgramKind>>, VecDeque<FileKey>);

/// Lot 313 (F1): what bounds the content check — the answers it gave, by
/// file, and the bytes its compares read in the current second; its counts
/// for `status`.
pub struct Bounds {
    memo: Mutex<Memo>,
    spent: Mutex<(Option<Instant>, u64)>,
    budget: u64,
    compared: AtomicU64,
    skipped: AtomicU64,
    remembered: AtomicU64,
}

impl Bounds {
    fn new(budget: u64) -> Self {
        Self {
            memo: Mutex::new((HashMap::new(), VecDeque::new())),
            spent: Mutex::new((None, 0)),
            budget,
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

    /// `bytes` taken from this second's budget; `false` when they do not fit.
    fn take(&self, bytes: u64, now: Instant) -> bool {
        let mut s = self.spent.lock();
        if s.0
            .is_none_or(|t| now.duration_since(t) >= Duration::from_secs(1))
        {
            *s = (Some(now), 0);
        }
        if s.1 + bytes > self.budget {
            return false;
        }
        s.1 += bytes;
        true
    }
}

/// The content check's bounds: one exec pump, one host.
static BOUNDS: LazyLock<Bounds> = LazyLock::new(|| Bounds::new(BUDGET_PER_SECOND));

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

/// The file the exec runs: its running image, or under the dynamic loader
/// the loader's operand (relative to the process's working directory).
fn running_file(event: &Event, proc_root: &Path) -> Option<(PathBuf, bool)> {
    let Event::ProcessSpawn {
        pid,
        filename,
        exe,
        argv,
        ..
    } = event
    else {
        return None;
    };
    let dir = proc_root.join(pid.to_string());
    if let Some(program) =
        nn_core::posture::script_args::loader_operand(exe.path_or(filename), argv)
    {
        let path = match program.strip_prefix('/') {
            Some(abs) => dir.join("root").join(abs),
            None => dir.join("cwd").join(program),
        };
        return Some((path, true));
    }
    Some((dir.join("exe"), false))
}

/// [`read_and_keep`] with `/proc` at `proc_root` and `bounds` (tests).
fn read_and_keep_with(event: &Event, proc_root: &Path, bounds: &Bounds) {
    let Event::ProcessSpawn { exe, stdio, .. } = event else {
        return;
    };
    if !stdio.own.stdin_or_stdout_inet() && !stdio.parent.stdin_or_stdout_inet() {
        return;
    }
    let Some((path, operand)) = running_file(event, proc_root) else {
        return;
    };
    let known = exe.has(common::wire::exe::exe_flags::KNOWN) && !operand;
    if known && program_identity::installed_kind((exe.dev, exe.ino)).is_some() {
        return;
    }
    let Ok(file) = std::fs::File::open(&path) else {
        return;
    };
    let Ok(m) = file.metadata() else {
        return;
    };
    let id = (
        crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        m.ino(),
    );
    // the exec's own file, when the hook said which (a later exec of the
    // pid runs another)
    if known && id != (exe.dev, exe.ino) {
        return;
    }
    if operand {
        if let Some(kind) = program_identity::installed_kind(id) {
            program_identity::keep_copy(event, kind);
            return;
        }
    }
    let key = (id.0, id.1, m.len(), m.ctime(), m.ctime_nsec());
    if let Some(answer) = bounds.recall(&key) {
        bounds.remembered.fetch_add(1, Ordering::Relaxed);
        if let Some(kind) = answer {
            program_identity::keep_copy(event, kind);
        }
        return;
    }
    let candidates: Vec<InstalledImage> = program_identity::installed_of_len(m.len())
        .into_iter()
        .take(MAX_COMPARED)
        .collect();
    if candidates.is_empty() {
        bounds.remember(key, None);
        return;
    }
    let cost = compare_cost(m.len()) * candidates.len() as u64;
    if !bounds.take(cost, Instant::now()) {
        bounds.skipped.fetch_add(1, Ordering::Relaxed);
        // never silence: R020 records the exec, its identity unverified
        program_identity::keep_unverified(event);
        return;
    }
    bounds.compared.fetch_add(1, Ordering::Relaxed);
    let kind = candidates
        .iter()
        .find(|i| same_sampled(&file, Path::new(&i.path), m.len()))
        .map(|i| i.kind);
    bounds.remember(key, kind);
    if let Some(kind) = kind {
        program_identity::keep_copy(event, kind);
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
        let bounds = Bounds::new(BUDGET_PER_SECOND);
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
        let n = 6usize << 20;
        let content: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        put(r, "/usr/bin/python3.12", &content);
        refresh_under(r);
        let proc_root = r.join("proc");
        let bounds = Bounds::new(3 * compare_cost(n as u64));
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
        for (pid, operand) in [(31395u32, "/home/u/x"), (31396, "y")] {
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
            assert_eq!(
                program_identity::copy_of(&e),
                Some(ProgramKind::Shell),
                "{operand}"
            );
        }
    }
}
