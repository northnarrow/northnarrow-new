//! Lab PR 225: is what a burst left behind ciphertext? The entropy signal
//! of the ransomware combination.
//!
//! The sensors do not allow sampling at write-close for every file: the
//! only close hook (`file_free_security`) watches the FIM inodes, and a BPF
//! program cannot read a file's content. So the agent samples in userland,
//! when a burst record is read: the file the record names and the regular
//! files beside it that changed within the burst window (at most
//! [`SAMPLE_FILES_MAX`], scanning at most [`DIR_SCAN_MAX`] entries), a block
//! of [`BLOCK`] bytes at their start and, for a file of at least four
//! blocks, one in their middle (intermittent encryption leaves headers
//! alone). A block is **ciphertext-like** when its Shannon entropy is at
//! least [`HIGH_ENTROPY_BITS`] bits per byte and the file's start carries no
//! known container signature ([`known_container`]): compressed, media,
//! database, image, package and encrypted-container formats are high
//! entropy by design. The signal holds when at least
//! [`HIGH_FILES_MIN`] of the files sampled are.
//!
//! What cannot be measured is said: the originals are gone (overwritten or
//! renamed) when the record is read, so "over low-entropy originals" is
//! approximated by the absence of a format header, not compared with the
//! original's entropy. The files are read without following a link and
//! without blocking (`O_NOFOLLOW | O_NONBLOCK`), as the host sees them
//! (`/proc/1/root`), and nothing of their content is kept.
//!
//! R08b (lab PR 251): the signal's vocabulary — the bounds, [`Sample`],
//! [`Sampler`], the entropy measure and the container signatures — is
//! nn-core's (`nn_core::impact::entropy`, cut verbatim), as the tracker that
//! reads it moves there; here under its names. What stays is the agent's
//! sampler of the host's files ([`FsSampler`]: `O_NOFOLLOW | O_NONBLOCK`,
//! the owner and mode bits, `/proc/1/root`), which the agent's host hands
//! the tracker.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

pub use nn_core::impact::entropy::*;

/// The production sampler: the host's files.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsSampler;

/// The host's view of `p` (`/proc/1/root`), or `p` where it cannot be
/// reached (tests).
fn host_view(p: &Path) -> PathBuf {
    if std::fs::metadata("/proc/1/root/").is_ok() {
        crate::response::host_path(p)
    } else {
        p.to_path_buf()
    }
}

impl Sampler for FsSampler {
    fn sample(&self, path: &str, since: Duration) -> Sample {
        if !path.starts_with('/') {
            // An unplaced or cut path (`mnt[…]`, `…/`): nothing to open.
            return Sample::default();
        }
        crate::runtime::off_the_runtime(|| sample_dir(Path::new(path), since, &host_view))
    }

    fn sample_copies(&self, copy: &str, suffix: &str, since: Duration) -> Sample {
        if !copy.starts_with('/') {
            return Sample::default();
        }
        crate::runtime::off_the_runtime(|| {
            sample_copies_dir(Path::new(copy), suffix, None, since, &host_view)
        })
    }

    fn sample_copies_by(&self, copy: &str, suffix: &str, uid: u32, since: Duration) -> Sample {
        if !copy.starts_with('/') {
            return Sample::default();
        }
        crate::runtime::off_the_runtime(|| {
            sample_copies_dir(Path::new(copy), suffix, Some(uid), since, &host_view)
        })
    }
}

/// Modified at or after `cutoff` (`None`: never).
fn recent(meta: &std::fs::Metadata, cutoff: Option<SystemTime>) -> bool {
    match (cutoff, meta.modified()) {
        (Some(c), Ok(m)) => m >= c,
        _ => false,
    }
}

/// [`FsSampler`]'s work: `path` first, then its siblings changed within
/// `since`, each reached through `host`.
pub fn sample_dir(path: &Path, since: Duration, host: &dyn Fn(&Path) -> PathBuf) -> Sample {
    let cutoff = SystemTime::now().checked_sub(since);
    let mut files: Vec<(PathBuf, Option<u32>)> = vec![(path.to_path_buf(), None)];
    if let Some(dir) = path.parent() {
        if let Ok(entries) = std::fs::read_dir(host(dir)) {
            for e in entries.take(DIR_SCAN_MAX).flatten() {
                if files.len() >= SAMPLE_FILES_MAX * 2 {
                    break;
                }
                let name = dir.join(e.file_name());
                if name == path {
                    continue;
                }
                let Ok(meta) = e.metadata() else { continue };
                if meta.is_file() && meta.len() >= BLOCK as u64 && recent(&meta, cutoff) {
                    files.push((name, None));
                }
            }
        }
    }
    examine(files, host)
}

/// [`FsSampler::sample_copies`]'s work: `copy` first, then the other copies
/// of the copy-delete shape — regular files of at least a block, changed
/// within `since`, named `<original>.<suffix>` whose original is gone — in
/// `copy`'s directory and, while fewer than [`SAMPLE_FILES_MAX`] are found
/// there, in the directories below and beside it (an encryptor walking a
/// tree of small directories) but never across a world-writable sticky
/// directory (below `/tmp`, beside `/tmp/x`: other users' trees); at most
/// [`COPY_SCAN_MAX`] entries looked at in all, each reached through
/// `host`. In a shared directory itself (the copy in `/tmp`) a copy counts
/// only when `owner`, the uid the burst ran as, owns it — `copy` included
/// (lab PR 238); with `owner` unknown, none there does.
///
/// The originals that still wait their turn are never sampled: what sits
/// beside the copies says nothing about what the burst wrote. In the lab's
/// MS-23 copy-delete run (debian12) the unlink crossing came at the 20th
/// original, with 280 originals written a minute before beside 20 copies;
/// [`sample_dir`]'s pick of "siblings changed in the window" was mostly
/// those originals, one file of four sampled as ciphertext, and
/// NN-L-IMP-001 never fired.
pub fn sample_copies_dir(
    copy: &Path,
    suffix: &str,
    owner: Option<u32>,
    since: Duration,
    host: &dyn Fn(&Path) -> PathBuf,
) -> Sample {
    let mut files: Vec<(PathBuf, Option<u32>)> = Vec::new();
    // The copy the record names, as any other: in a shared directory
    // anyone may have left a file under that name.
    match copy.parent().map(|d| Owners::of(d, owner, host)) {
        Some(Owners::Nobody) => {}
        Some(Owners::Only(uid)) => files.push((copy.to_path_buf(), Some(uid))),
        Some(Owners::Any) | None => files.push((copy.to_path_buf(), None)),
    }
    let (Some(dir), false) = (copy.parent(), suffix.is_empty()) else {
        return examine(files, host);
    };
    let mut scan = CopyScan {
        skip: copy,
        dot_suffix: format!(".{suffix}"),
        cutoff: SystemTime::now().checked_sub(since),
        host,
        budget: COPY_SCAN_MAX,
        owner,
    };
    // Below it and beside it — never under the root (`/proc`, `/sys`,
    // `/dev` are no tree an encryptor walks), nor across a shared
    // directory ([`shared_dir`]): what lies below `/tmp` or beside
    // `/tmp/x` are other users' and other programs' trees.
    let mut below: Vec<PathBuf> = Vec::new();
    let below_wanted = dir.parent().is_some() && !shared_dir(dir, host);
    scan.dir(dir, &mut files, below_wanted.then_some(&mut below));
    if files.len() < SAMPLE_FILES_MAX {
        let mut beside: Vec<PathBuf> = Vec::new();
        if let Some(parent) = dir
            .parent()
            .filter(|p| p.parent().is_some() && !shared_dir(p, host))
        {
            scan.dir(parent, &mut files, Some(&mut beside));
        }
        for d in below
            .iter()
            .chain(beside.iter().filter(|d| d.as_path() != dir))
        {
            if files.len() >= SAMPLE_FILES_MAX || scan.budget == 0 {
                break;
            }
            if !shared_dir(d, host) {
                scan.dir(d, &mut files, None);
            }
        }
    }
    examine(files, host)
}

/// A world-writable directory with the sticky bit (`/tmp`, `/var/tmp`,
/// `/dev/shm`, `/run/lock`): the trees of unrelated users and programs
/// side by side, where anyone can leave files. Fresh copies of ciphertext
/// in another of its trees — same suffix, originals gone — say nothing of
/// the burst being judged (and can be planted to make a benign job look
/// like an encryptor), so the copy walk does not cross one. A
/// world-writable directory without the sticky bit is not one: a share's
/// tree (`0777`) is where an encryptor walks.
fn shared_dir(dir: &Path, host: &dyn Fn(&Path) -> PathBuf) -> bool {
    let shared = libc::S_ISVTX | libc::S_IWOTH;
    std::fs::metadata(host(dir)).is_ok_and(|m| m.is_dir() && m.mode() & shared == shared)
}

/// Whose copies count in a directory (lab PR 238).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Owners {
    /// An ordinary directory: whoever owns them (a share's tree included).
    Any,
    /// A shared directory ([`shared_dir`]): those of the uid the burst ran
    /// as. Another user's fresh copies of ciphertext there — or copies
    /// planted to have a benign job judged an encryptor — are not the
    /// burst's. An encryptor's copies are new files: its own.
    Only(u32),
    /// A shared directory, the burst's uid unknown: none.
    Nobody,
}

impl Owners {
    fn of(dir: &Path, owner: Option<u32>, host: &dyn Fn(&Path) -> PathBuf) -> Self {
        if !shared_dir(dir, host) {
            return Owners::Any;
        }
        match owner {
            Some(uid) => Owners::Only(uid),
            None => Owners::Nobody,
        }
    }
}

/// The walk of [`sample_copies_dir`].
struct CopyScan<'a> {
    skip: &'a Path,
    dot_suffix: String,
    cutoff: Option<SystemTime>,
    host: &'a dyn Fn(&Path) -> PathBuf,
    /// Entries left to look at.
    budget: usize,
    /// The uid the burst ran as, when known ([`Owners`]).
    owner: Option<u32>,
}

impl CopyScan<'_> {
    /// The copies in `dir` into `files` (up to twice [`SAMPLE_FILES_MAX`]:
    /// some may not be readable), each with the owner it must have to
    /// count ([`Owners`]), its subdirectories into `subdirs`.
    fn dir(
        &mut self,
        dir: &Path,
        files: &mut Vec<(PathBuf, Option<u32>)>,
        mut subdirs: Option<&mut Vec<PathBuf>>,
    ) {
        let only = match Owners::of(dir, self.owner, self.host) {
            Owners::Any => None,
            Owners::Only(uid) => Some(uid),
            // Nothing here counts (a shared directory's subdirectories are
            // not walked either).
            Owners::Nobody => return,
        };
        let Ok(entries) = std::fs::read_dir((self.host)(dir)) else {
            return;
        };
        for e in entries.flatten() {
            if self.budget == 0 || files.len() >= SAMPLE_FILES_MAX * 2 {
                break;
            }
            self.budget -= 1;
            // The entry's own type (no link followed; `d_type` where the
            // filesystem gives it, no `stat`).
            let Ok(kind) = e.file_type() else { continue };
            let name = dir.join(e.file_name());
            if kind.is_dir() {
                if let Some(s) = subdirs.as_deref_mut() {
                    s.push(name);
                }
                continue;
            }
            if !kind.is_file() || name == self.skip {
                continue;
            }
            let leaf = e.file_name();
            let Some(stem) = leaf
                .to_str()
                .and_then(|l| l.strip_suffix(self.dot_suffix.as_str()))
            else {
                continue;
            };
            if stem.is_empty() {
                continue;
            }
            let Ok(meta) = e.metadata() else { continue };
            if meta.len() < BLOCK as u64 || !recent(&meta, self.cutoff) {
                continue;
            }
            // Another owner's, in a shared directory: not looked at (nor
            // taking the place of one of the burst's). Checked again on
            // the file opened ([`classify`]).
            if only.is_some_and(|uid| meta.uid() != uid) {
                continue;
            }
            // Its original is gone: a copy still waiting for its deletion
            // (or a `.bak` kept beside its file) is not one.
            let gone = matches!(
                std::fs::symlink_metadata((self.host)(&dir.join(stem))),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound
            );
            if gone {
                files.push((name, only));
            }
        }
    }
}

/// Read up to [`SAMPLE_FILES_MAX`] of `files`, in order; a file paired with
/// a uid is read only when that uid owns it (lab PR 238).
fn examine(files: Vec<(PathBuf, Option<u32>)>, host: &dyn Fn(&Path) -> PathBuf) -> Sample {
    let mut out = Sample::default();
    for (f, owner) in files {
        if out.examined as usize >= SAMPLE_FILES_MAX {
            break;
        }
        match classify(&host(&f), owner) {
            Some(Kind::Ciphertext) => {
                out.examined += 1;
                out.high += 1;
            }
            Some(Kind::Container) => {
                out.examined += 1;
                out.containers += 1;
            }
            Some(Kind::Plain) => out.examined += 1,
            None => {}
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ciphertext,
    Container,
    Plain,
}

/// One file: `None` when it cannot be read, is no regular file of at
/// least a block, or is not `owner`'s (when given).
fn classify(path: &Path, owner: Option<u32>) -> Option<Kind> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.size() < BLOCK as u64 {
        return None;
    }
    if owner.is_some_and(|uid| meta.uid() != uid) {
        return None;
    }
    let mut head = vec![0u8; BLOCK];
    f.read_exact(&mut head).ok()?;
    if known_container(&head) {
        return Some(Kind::Container);
    }
    if entropy_bits(&head) >= HIGH_ENTROPY_BITS {
        return Some(Kind::Ciphertext);
    }
    if meta.size() >= 4 * BLOCK as u64 {
        use std::io::{Seek, SeekFrom};
        let mid = (meta.size() / 2) & !(BLOCK as u64 - 1);
        let mut block = vec![0u8; BLOCK];
        if f.seek(SeekFrom::Start(mid)).is_ok()
            && f.read_exact(&mut block).is_ok()
            && entropy_bits(&block) >= HIGH_ENTROPY_BITS
        {
            return Some(Kind::Ciphertext);
        }
    }
    Some(Kind::Plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test's own tree: `w` inside its own `TempDir`, so that what the
    /// copy sampler reads beside a copy in `w` (the `TempDir`) and below it
    /// is this test's alone — never the trees of the tests running beside
    /// it in the shared temporary directory, whose fresh `.locked` copies
    /// of ciphertext (originals gone) are what [`sample_copies_dir`] counts.
    fn sandbox() -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::TempDir::new().unwrap();
        let w = t.path().join("w");
        std::fs::create_dir(&w).unwrap();
        (t, w)
    }

    /// The uid this test runs as: the owner of the files it writes.
    fn me() -> u32 {
        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }

    fn random(n: usize, seed: u64) -> Vec<u8> {
        // xorshift: deterministic, uniform enough for an entropy test.
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// The file a burst names and its recently changed siblings: random
    /// bytes hold the signal, text, a gzip archive and small files do not.
    #[test]
    fn sample_dir_counts_ciphertext_like_siblings() {
        let (_t, d) = sandbox();
        let d = d.as_path();
        let host = |p: &Path| p.to_path_buf();
        let enc = |name: &str, seed: u64| {
            let mut b = random(3 * BLOCK, seed);
            b[0] = 0x42; // no signature by accident
            std::fs::write(d.join(name), b).unwrap();
        };
        enc("a.pdf.locked", 11);
        enc("b.docx.locked", 12);
        enc("c.xlsx.locked", 13);
        let s = sample_dir(&d.join("a.pdf.locked"), Duration::from_secs(60), &host);
        assert!(s.holds(), "{s:?}");
        assert_eq!(s.examined, 3);

        let (_t2, d2) = sandbox();
        let d2 = d2.as_path();
        let text = "plain report text, nothing encrypted here. ".repeat(300);
        std::fs::write(d2.join("r1.txt"), &text).unwrap();
        std::fs::write(d2.join("r2.txt"), &text).unwrap();
        let mut gz = random(2 * BLOCK, 9);
        gz[..2].copy_from_slice(b"\x1f\x8b");
        std::fs::write(d2.join("x.gz"), &gz).unwrap();
        std::fs::write(d2.join("small"), random(100, 2)).unwrap();
        let s = sample_dir(&d2.join("r1.txt"), Duration::from_secs(60), &host);
        assert!(!s.holds(), "{s:?}");
        assert_eq!((s.high, s.containers), (0, 1));
        // A link is not followed, a missing file is not counted.
        std::os::unix::fs::symlink(d.join("a.pdf.locked"), d2.join("link")).unwrap();
        let s = sample_dir(&d2.join("link"), Duration::from_secs(0), &host);
        assert_eq!(s.high, 0);
        assert_eq!(
            sample_dir(&d2.join("missing"), Duration::from_secs(0), &host),
            Sample::default()
        );
    }

    #[test]
    fn intermittent_encryption_is_seen_in_the_middle() {
        let (_t, w) = sandbox();
        let p = w.join("big.db");
        let mut b = "header text ".repeat(BLOCK).into_bytes();
        b.truncate(8 * BLOCK);
        let mid = 4 * BLOCK;
        b[mid..mid + BLOCK].copy_from_slice(&random(BLOCK, 21));
        std::fs::write(&p, &b).unwrap();
        assert_eq!(classify(&p, None), Some(Kind::Ciphertext));
        // lab PR 238: read only when the uid it is given owns it
        assert_eq!(classify(&p, Some(me())), Some(Kind::Ciphertext));
        assert_eq!(classify(&p, Some(me().wrapping_add(1))), None);
    }

    /// Lab MS-23 copy-delete: the copies are sampled — the files named
    /// `<original>.<suffix>` whose original is gone — never the plain
    /// originals beside them, however many and however fresh; a copy whose
    /// original is still there, a small one and one of another suffix are
    /// not copies of the burst.
    #[test]
    fn sample_copies_reads_the_copies_not_the_originals() {
        let (_t, d) = sandbox();
        let d = d.as_path();
        let host = |p: &Path| p.to_path_buf();
        let text = "plain report text, nothing encrypted here. ".repeat(300);
        let enc = |name: &str, seed: u64| {
            let mut b = random(2 * BLOCK, seed);
            b[0] = 0x42;
            std::fs::write(d.join(name), b).unwrap();
        };
        for i in 0..200 {
            std::fs::write(d.join(format!("r{i:03}.txt")), &text).unwrap();
        }
        // r900..r902 encrypted and deleted; r000 still there beside a
        // `.locked` of its own (this one plain: not read); a small copy;
        // a copy under another suffix.
        enc("r900.txt.locked", 1);
        enc("r901.txt.locked", 2);
        enc("r902.txt.locked", 3);
        std::fs::write(d.join("r000.txt.locked"), &text).unwrap();
        std::fs::write(d.join("r903.txt.locked"), random(100, 4)).unwrap();
        std::fs::write(d.join("r904.txt.bak"), &text).unwrap();
        let s = sample_copies_dir(
            &d.join("r902.txt.locked"),
            "locked",
            Some(me()),
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high), (3, 3), "{s:?}");
        assert!(s.holds());

        // Compressed copies (a rotation with compression) are containers.
        let (_t2, d2) = sandbox();
        let d2 = d2.as_path();
        for i in 0..6 {
            let mut gz = random(2 * BLOCK, 30 + i);
            gz[..2].copy_from_slice(b"\x1f\x8b");
            std::fs::write(d2.join(format!("app{i}.log.1.gz")), gz).unwrap();
        }
        let s = sample_copies_dir(
            &d2.join("app5.log.1.gz"),
            "gz",
            Some(me()),
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high, s.containers), (4, 0, 4), "{s:?}");
        // No suffix: the copy alone.
        let s = sample_copies_dir(
            &d.join("r902.txt.locked"),
            "",
            Some(me()),
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high), (1, 1));
    }

    /// One original per directory: the copies are looked for below the
    /// copy's directory and beside it, within the scan's bound.
    #[test]
    fn sample_copies_looks_below_and_beside_in_small_directories() {
        let (_t, w) = sandbox();
        let host = |p: &Path| p.to_path_buf();
        let top = w.join("home");
        for i in 0..6 {
            let d = top.join(format!("d{i}"));
            std::fs::create_dir_all(d.join("sub")).unwrap();
            let mut b = random(BLOCK, 50 + i);
            b[0] = 0x42;
            std::fs::write(d.join("a.odt.crypt"), &b).unwrap();
            if i == 0 {
                std::fs::write(d.join("sub/b.odt.crypt"), &b).unwrap();
            }
        }
        let s = sample_copies_dir(
            &top.join("d0/a.odt.crypt"),
            "crypt",
            Some(me()),
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high), (4, 4), "{s:?}");
        // Nothing beside or below: the copy alone, one file, no signal.
        let (_lone, l) = sandbox();
        let p = l.join("x/only.pdf.crypt");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut b = random(BLOCK, 60);
        b[0] = 0x42;
        std::fs::write(&p, &b).unwrap();
        let s = sample_copies_dir(&p, "crypt", Some(me()), Duration::from_secs(120), &host);
        assert_eq!((s.examined, s.high), (1, 1));
        assert!(!s.holds());
    }

    /// A world-writable sticky directory (`/tmp`, `/var/tmp`, `/dev/shm`)
    /// holds the trees of unrelated users and programs side by side: the
    /// copies are looked for neither beside it nor below it. Another tree's
    /// fresh copies of ciphertext there — same suffix, at least a block,
    /// originals gone — say nothing of this burst (and anyone can plant
    /// them). In an ordinary directory they count: the tree of small
    /// directories, and the CI failure of PR 427 (the copy sampler of a
    /// test in `/tmp/.tmpX` read another test's `.locked` copies beside
    /// it); a shared directory's own copies count as well.
    #[test]
    fn sample_copies_does_not_cross_a_shared_directory() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, w) = sandbox();
        let host = |p: &Path| p.to_path_buf();
        let since = Duration::from_secs(120);
        let text = "plain report text, nothing encrypted here. ".repeat(300);
        let enc = |p: PathBuf, seed: u64| {
            let mut b = random(2 * BLOCK, seed);
            b[0] = 0x42;
            std::fs::write(p, b).unwrap();
        };
        // `base/job/a.csv.part`: the burst's copy, plain, alone in its
        // directory; `base/<other>/x*.bin.part`: another tree's encrypted
        // copies, the shared directory being `base` or `base/<other>`.
        let tree = |base: &Path, other: &str, base_mode: u32, other_mode: u32| {
            std::fs::create_dir_all(base.join("job")).unwrap();
            std::fs::create_dir_all(base.join(other)).unwrap();
            std::fs::write(base.join("job/a.csv.part"), &text).unwrap();
            for i in 0..3 {
                enc(base.join(format!("{other}/x{i}.bin.part")), 70 + i);
            }
            let mode = |p: &Path, m: u32| {
                std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
            };
            mode(&base.join(other), other_mode);
            mode(base, base_mode);
            base.join("job/a.csv.part")
        };
        let other_tree = Sample {
            examined: 4,
            high: 3,
            containers: 0,
        };
        let alone = Sample {
            examined: 1,
            high: 0,
            containers: 0,
        };
        // Beside, in an ordinary directory: read.
        let copy = tree(&w.join("home"), "u2", 0o755, 0o755);
        assert_eq!(
            sample_copies_dir(&copy, "part", Some(me()), since, &host),
            other_tree
        );
        // Beside, in a shared directory: not read.
        let copy = tree(&w.join("tmp"), "u2", 0o1777, 0o700);
        assert_eq!(
            sample_copies_dir(&copy, "part", Some(me()), since, &host),
            alone
        );
        // A shared directory beside, in an ordinary one (`/var/tmp` from
        // `/var/x`): not read.
        let copy = tree(&w.join("var"), "tmp", 0o755, 0o1777);
        assert_eq!(
            sample_copies_dir(&copy, "part", Some(me()), since, &host),
            alone
        );
        // Below a shared directory (the copy in `/tmp` itself): not read;
        // its own copies are (the burst's uid's, lab PR 238: this test's).
        let shared = w.join("tmp");
        std::fs::write(shared.join("b.csv.part"), &text).unwrap();
        let copy = shared.join("b.csv.part");
        assert_eq!(
            sample_copies_dir(&copy, "part", Some(me()), since, &host),
            alone
        );
        enc(shared.join("c.pdf.part"), 80);
        enc(shared.join("d.pdf.part"), 81);
        let s = sample_copies_dir(&copy, "part", Some(me()), since, &host);
        assert_eq!((s.examined, s.high), (3, 2), "{s:?}");
        assert!(s.holds());
    }

    /// Lab PR 238: in a shared directory itself (the burst's copy in
    /// `/tmp`), only the copies of the uid the burst ran as count — the
    /// copy the record names included: anyone may have left a file under
    /// that name. Another uid's burst finds none of this test's copies
    /// there, and nothing counts when the uid is unknown. In an ordinary
    /// directory, a `0777` share included, the copies count whoever owns
    /// them.
    #[test]
    fn in_a_shared_directory_only_the_bursts_own_copies_count() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, w) = sandbox();
        let host = |p: &Path| p.to_path_buf();
        let since = Duration::from_secs(120);
        let other = me().wrapping_add(1);
        let enc = |p: PathBuf, seed: u64| {
            let mut b = random(2 * BLOCK, seed);
            b[0] = 0x42;
            std::fs::write(p, b).unwrap();
        };
        let three = |dir: &Path, mode: u32| {
            std::fs::create_dir_all(dir).unwrap();
            for (i, n) in ["a", "b", "c"].iter().enumerate() {
                enc(dir.join(format!("{n}.pdf.locked")), 90 + i as u64);
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode)).unwrap();
            dir.join("c.pdf.locked")
        };
        let all = Sample {
            examined: 3,
            high: 3,
            containers: 0,
        };
        // `/tmp`-like: this test's burst counts them; another uid's, none
        // (not even the copy its record names); an unknown uid, none.
        let copy = three(&w.join("tmp"), 0o1777);
        assert_eq!(
            sample_copies_dir(&copy, "locked", Some(me()), since, &host),
            all
        );
        assert!(sample_copies_dir(&copy, "locked", Some(me()), since, &host).holds());
        assert_eq!(
            sample_copies_dir(&copy, "locked", Some(other), since, &host),
            Sample::default()
        );
        assert_eq!(
            sample_copies_dir(&copy, "locked", None, since, &host),
            Sample::default()
        );
        // An ordinary directory and a share without the sticky bit (each
        // in a sandbox of its own: the walk looks beside): the copies
        // count whoever owns them.
        for (name, mode) in [("home", 0o755), ("share", 0o777)] {
            let (_t, w) = sandbox();
            let copy = three(&w.join(name), mode);
            for owner in [Some(other), None] {
                assert_eq!(
                    sample_copies_dir(&copy, "locked", owner, since, &host),
                    all,
                    "{name} {owner:?}"
                );
            }
        }
    }

    /// Lab PR 238, with copies of two owners side by side in a shared
    /// directory (root: `chown`): the burst's own copies are read, the
    /// other user's skipped — they neither count nor take the place of the
    /// burst's in the sample.
    #[test]
    #[ignore = "requires root (chown to another uid)"]
    fn in_a_shared_directory_another_users_copies_are_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, w) = sandbox();
        let host = |p: &Path| p.to_path_buf();
        let since = Duration::from_secs(120);
        let dir = w.join("tmp");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let nobody = 65_534;
        // eight of another user's copies of ciphertext, two of the burst's
        // (one plain): more of the other's than the sample takes
        for i in 0..8 {
            let p = dir.join(format!("o{i}.doc.locked"));
            let mut b = random(2 * BLOCK, 100 + i);
            b[0] = 0x42;
            std::fs::write(&p, b).unwrap();
            std::os::unix::fs::chown(&p, Some(nobody), Some(nobody)).unwrap();
        }
        let mut b = random(2 * BLOCK, 120);
        b[0] = 0x42;
        std::fs::write(dir.join("m0.doc.locked"), b).unwrap();
        let text = "plain report text, nothing encrypted here. ".repeat(300);
        std::fs::write(dir.join("m1.doc.locked"), &text).unwrap();
        let copy = dir.join("m1.doc.locked");
        let s = sample_copies_dir(&copy, "locked", Some(me()), since, &host);
        assert_eq!((s.examined, s.high), (2, 1), "{s:?}");
        assert!(!s.holds());
        // the other user's burst: its own eight (the named copy is not its)
        let named = dir.join("o0.doc.locked");
        let s = sample_copies_dir(&named, "locked", Some(nobody), since, &host);
        assert_eq!((s.examined, s.high), (4, 4), "{s:?}");
    }
}
